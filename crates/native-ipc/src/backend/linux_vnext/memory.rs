//! Linux 6.3+ least-authority memfd direction preparation.

use core::cell::Cell;
use core::marker::PhantomData;
use core::mem::{forget, zeroed};
use core::ptr::NonNull;
use core::sync::atomic::{Ordering, compiler_fence};
use std::io;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
#[cfg(test)]
use std::sync::{Arc, Mutex};

use crate::active::{ActiveReadOwner, ActiveWriteOwner};
use crate::backend::linux::QuiescentRegion;
use crate::batch::{ExpectedBatch, LocalRegionAuthority, TransferBatch};
use crate::memory::CleanupPolicy;
use crate::protocol::{
    ManifestEntry, NativeAuthorityProfile, NativeRegionSpec, PeerAccess, TransferManifest,
};
use crate::region::{GuardPolicy, RegionId, WriterEndpoint};
use crate::session::{AbsoluteDeadline, SessionLimits};

const MFD_NOEXEC_SEAL: libc::c_uint = 0x0008;
const F_SEAL_EXEC: libc::c_int = 0x0020;
const PREFIX_SEALS: libc::c_int = F_SEAL_EXEC | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK;
const FINAL_SEALS: libc::c_int = PREFIX_SEALS | libc::F_SEAL_FUTURE_WRITE | libc::F_SEAL_SEAL;
const TMPFS_MAGIC: libc::c_long = 0x0102_1994;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MemfdError {
    InvalidSize,
    InvalidBatch,
    UnsupportedDirection,
    DeadlineExpired,
    DeadlineMismatch,
    InvalidObject,
    WrongObject,
    WrongProvenance,
    ExecutableAuthorityUnsupported,
    GuardUnavailable,
    Native(i32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ObjectKey {
    device: u64,
    inode: u64,
    mapped_len: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TransferBinding {
    session_nonce: [u8; 32],
    transaction_id: u64,
    region_id: u128,
    incarnation: [u8; 16],
    ordinal: u16,
    manifest_digest: [u8; 32],
}

struct PrivateMemfd {
    fd: OwnedFd,
    mapping: Option<VmMapping>,
    logical_len: usize,
    not_sync: PhantomData<Cell<()>>,
}

struct CoordinatorWriterPrepared {
    fd: OwnedFd,
    mapping: VmMapping,
    reader_capability: OwnedFd,
    key: ObjectKey,
    not_sync: PhantomData<Cell<()>>,
}

struct ReceiverWriterPrepared {
    fd: OwnedFd,
    key: ObjectKey,
    binding: TransferBinding,
    not_sync: PhantomData<Cell<()>>,
}

struct ReceiverWriterCapabilitySent {
    fd: OwnedFd,
    key: ObjectKey,
    binding: TransferBinding,
    not_sync: PhantomData<Cell<()>>,
}

struct ImportedPeerWriter {
    fd: OwnedFd,
    mapping: VmMapping,
    key: ObjectKey,
    receipt_available: bool,
    sealed_verified: bool,
    binding: TransferBinding,
    not_sync: PhantomData<Cell<()>>,
}

struct PeerWriterImportedReceipt {
    key: ObjectKey,
    binding: TransferBinding,
    not_sync: PhantomData<Cell<()>>,
}

struct CoordinatorReaderPrepared {
    fd: OwnedFd,
    mapping: VmMapping,
    not_sync: PhantomData<Cell<()>>,
}

/// One owned view mapping. When `guarded` is true the interior view sits one
/// page inside an inaccessible anonymous reservation whose bands contain
/// in-process linear overruns; when false the reservation and the interior
/// are the exact same range.
struct VmMapping {
    base: NonNull<u8>,
    len: usize,
    clear_on_drop: bool,
    reservation_base: *mut libc::c_void,
    reservation_len: usize,
    guarded: bool,
}

/// Owns a successful `mmap` before the address has been validated and the
/// fallible mapping advice has completed.
struct PendingVmMapping {
    base: *mut libc::c_void,
    len: usize,
    clear_on_drop: bool,
    reservation_base: *mut libc::c_void,
    reservation_len: usize,
    guarded: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct LinuxActiveRegionSpec {
    pub(crate) id: RegionId,
    pub(crate) authority: LocalRegionAuthority,
    pub(crate) logical_len: usize,
    pub(crate) mapped_len: u64,
    pub(crate) guard_requested: GuardPolicy,
}

pub(crate) enum LinuxActiveRegionOwner {
    Reader {
        spec: LinuxActiveRegionSpec,
        owner: Box<dyn ActiveReadOwner>,
    },
    Writer {
        spec: LinuxActiveRegionSpec,
        owner: Box<dyn ActiveWriteOwner>,
    },
}

struct LinuxActiveReadMapping {
    mapping: Option<VmMapping>,
    _fd: OwnedFd,
    page_size: usize,
    #[cfg(test)]
    drop_observer: Option<Arc<Mutex<Vec<&'static str>>>>,
}

struct LinuxActiveWriteMapping {
    mapping: Option<VmMapping>,
    _fd: OwnedFd,
    page_size: usize,
    _not_sync: PhantomData<Cell<()>>,
    #[cfg(test)]
    drop_observer: Option<Arc<Mutex<Vec<&'static str>>>>,
}

pub(crate) struct LinuxCoordinatorWriterBatch {
    entries: Vec<LinuxCoordinatorWriterEntry>,
    deadline: AbsoluteDeadline,
    #[cfg(test)]
    drop_observer: Option<Arc<Mutex<Vec<&'static str>>>>,
    #[cfg(test)]
    revalidation_fault: bool,
}

pub(crate) struct LinuxReceiverWriterBatch {
    entries: Vec<LinuxReceiverWriterEntry>,
    deadline: AbsoluteDeadline,
    #[cfg(test)]
    drop_observer: Option<Arc<Mutex<Vec<&'static str>>>>,
    #[cfg(test)]
    seal_failure_at: Option<usize>,
    #[cfg(test)]
    advice_failure_at: Option<usize>,
}

/// Coordinator-owned canonical native preparation for one arbitrary mixed
/// direction batch. Each entry remains inside its direction-specific owner;
/// this wrapper exposes neither descriptors nor mappings as separable parts.
pub(crate) struct LinuxMixedDirectionBatch {
    entries: Vec<LinuxMixedDirectionEntry>,
    deadline: AbsoluteDeadline,
    #[cfg(test)]
    drop_observer: Option<Arc<Mutex<Vec<&'static str>>>>,
    #[cfg(test)]
    active_drop_observer: Option<Arc<Mutex<Vec<&'static str>>>>,
    #[cfg(test)]
    seal_failure_at: Option<usize>,
    #[cfg(test)]
    advice_failure_at: Option<usize>,
}

enum LinuxMixedDirectionEntry {
    CoordinatorWriter(LinuxCoordinatorWriterBatch),
    ReceiverWriter(LinuxReceiverWriterBatch),
}

pub(crate) struct LinuxExpectedCoordinatorWriterBatch {
    entries: Vec<LinuxExpectedCoordinatorWriterEntry>,
    total_logical: u64,
    total_mapped: u64,
    deadline: AbsoluteDeadline,
    #[cfg(test)]
    advice_failure_at: Option<usize>,
}

pub(crate) struct LinuxExpectedReceiverWriterBatch {
    entries: Vec<LinuxExpectedCoordinatorWriterEntry>,
    total_logical: u64,
    total_mapped: u64,
    deadline: AbsoluteDeadline,
    #[cfg(test)]
    advice_failure_at: Option<usize>,
}

pub(crate) struct LinuxExpectedMixedDirectionBatch {
    entries: Vec<LinuxExpectedMixedDirectionEntry>,
    total_logical: u64,
    total_mapped: u64,
    deadline: AbsoluteDeadline,
    #[cfg(test)]
    advice_failure_at: Option<usize>,
}

#[derive(Clone, Copy)]
struct LinuxExpectedCoordinatorWriterEntry {
    region_id: u128,
    logical_len: u64,
    mapped_len: u64,
}

#[derive(Clone, Copy)]
struct LinuxExpectedMixedDirectionEntry {
    region_id: u128,
    writer: WriterEndpoint,
    logical_len: u64,
    mapped_len: u64,
}

pub(crate) struct LinuxImportedCoordinatorWriterBatch {
    entries: Vec<LinuxImportedCoordinatorWriterEntry>,
    #[cfg(test)]
    drop_observer: Option<Arc<Mutex<Vec<&'static str>>>>,
}

pub(crate) struct LinuxImportedReceiverWriterBatch {
    entries: Vec<LinuxImportedReceiverWriterEntry>,
    sealed_verified: bool,
    #[cfg(test)]
    drop_observer: Option<Arc<Mutex<Vec<&'static str>>>>,
}

pub(crate) struct LinuxImportedMixedDirectionBatch {
    entries: Vec<LinuxImportedMixedDirectionEntry>,
    #[cfg(test)]
    sealed_verified: bool,
    #[cfg(test)]
    drop_observer: Option<Arc<Mutex<Vec<&'static str>>>>,
    #[cfg(test)]
    active_drop_observer: Option<Arc<Mutex<Vec<&'static str>>>>,
}

enum LinuxImportedMixedDirectionEntry {
    CoordinatorWriter(LinuxImportedCoordinatorWriterEntry),
    ReceiverWriter(LinuxImportedReceiverWriterEntry),
}

pub(crate) struct LinuxImportFailure {
    error: MemfdError,
    _partial: Vec<LinuxImportedCoordinatorWriterEntry>,
    _current_fd: Option<OwnedFd>,
    _current_mapping: Option<PendingVmMapping>,
    _remaining: std::vec::IntoIter<OwnedFd>,
    #[cfg(test)]
    drop_observer: Option<Arc<Mutex<Vec<&'static str>>>>,
}

pub(crate) struct LinuxReceiverWriterImportFailure {
    error: MemfdError,
    _partial: Vec<LinuxImportedReceiverWriterEntry>,
    _current_fd: Option<OwnedFd>,
    _current_mapping: Option<PendingVmMapping>,
    _remaining: std::vec::IntoIter<OwnedFd>,
    #[cfg(test)]
    drop_observer: Option<Arc<Mutex<Vec<&'static str>>>>,
}

pub(crate) struct LinuxMixedDirectionImportFailure {
    error: MemfdError,
    _partial: Vec<LinuxImportedMixedDirectionEntry>,
    _current_fd: Option<OwnedFd>,
    _current_mapping: Option<PendingVmMapping>,
    _remaining: std::vec::IntoIter<OwnedFd>,
    #[cfg(test)]
    drop_observer: Option<Arc<Mutex<Vec<&'static str>>>>,
}

impl core::fmt::Debug for LinuxImportFailure {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("LinuxImportFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

struct LinuxImportedCoordinatorWriterEntry {
    manifest: ManifestEntry,
    fd: OwnedFd,
    mapping: VmMapping,
    key: ObjectKey,
}

struct LinuxImportedReceiverWriterEntry {
    manifest: ManifestEntry,
    fd: OwnedFd,
    mapping: VmMapping,
    key: ObjectKey,
}

struct LinuxCoordinatorWriterEntry {
    native: NativeRegionSpec,
    prepared: CoordinatorWriterPrepared,
    guard_requested: GuardPolicy,
}

struct LinuxReceiverWriterEntry {
    native: NativeRegionSpec,
    fd: OwnedFd,
    key: ObjectKey,
    mapping: Option<VmMapping>,
    pending_mapping: Option<PendingVmMapping>,
    guard_requested: GuardPolicy,
    #[cfg(test)]
    capability_override: Option<OwnedFd>,
}

// SAFETY: VmMapping uniquely owns one local VM range. Moving that owner to a
// different thread neither duplicates the mapping nor creates Rust references.
unsafe impl Send for VmMapping {}

// SAFETY: PendingVmMapping uniquely owns one local VM range. Moving that owner
// neither duplicates the mapping nor creates Rust references to its address.
unsafe impl Send for PendingVmMapping {}

// SAFETY: this owner contains one immutable local mapping. Peer mutation is
// accessed only through the volatile byte boundary required by ActiveReader;
// no Rust reference is formed from the shared pointer.
unsafe impl Sync for LinuxActiveReadMapping {}

// SAFETY: each wrapper uniquely owns the exact mmap range and destroys it
// synchronously in VmMapping::drop. mmap returned page-aligned storage, and
// the retained descriptor does not duplicate local mapping ownership.
unsafe impl ActiveReadOwner for LinuxActiveReadMapping {
    fn as_ptr(&self) -> *const u8 {
        self.mapping().base.as_ptr().cast_const()
    }

    fn len(&self) -> usize {
        self.mapping().len
    }

    fn page_size(&self) -> usize {
        self.page_size
    }

    fn guard_installed(&self) -> bool {
        self.mapping().guarded
    }
}

// SAFETY: this wrapper uniquely owns the sole local writable mmap range. Its
// Cell marker keeps the capability non-Sync, and exclusive ActiveWriter access
// is required for every store operation.
unsafe impl ActiveWriteOwner for LinuxActiveWriteMapping {
    fn as_ptr(&self) -> *const u8 {
        self.mapping().base.as_ptr().cast_const()
    }

    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.mapping().base.as_ptr()
    }

    fn len(&self) -> usize {
        self.mapping().len
    }

    fn page_size(&self) -> usize {
        self.page_size
    }

    fn guard_installed(&self) -> bool {
        self.mapping().guarded
    }
}

impl LinuxActiveReadMapping {
    fn mapping(&self) -> &VmMapping {
        self.mapping
            .as_ref()
            .expect("active read mapping remains live until owner drop")
    }
}

impl LinuxActiveWriteMapping {
    fn mapping(&self) -> &VmMapping {
        self.mapping
            .as_ref()
            .expect("active write mapping remains live until owner drop")
    }
}

impl Drop for LinuxActiveReadMapping {
    fn drop(&mut self) {
        drop(self.mapping.take());
        #[cfg(test)]
        if let Some(observer) = &self.drop_observer {
            observer
                .lock()
                .expect("test active-drop observer mutex is not poisoned")
                .push("active-mapping-drop");
        }
    }
}

impl Drop for LinuxActiveWriteMapping {
    fn drop(&mut self) {
        drop(self.mapping.take());
        #[cfg(test)]
        if let Some(observer) = &self.drop_observer {
            observer
                .lock()
                .expect("test active-drop observer mutex is not poisoned")
                .push("active-mapping-drop");
        }
    }
}

impl TransferBinding {
    fn new(
        session_nonce: [u8; 32],
        transaction_id: u64,
        region_id: u128,
        incarnation: [u8; 16],
        ordinal: u16,
        manifest_digest: [u8; 32],
    ) -> Option<Self> {
        if session_nonce == [0; 32]
            || transaction_id == 0
            || region_id == 0
            || incarnation == [0; 16]
            || ordinal >= 16
            || manifest_digest == [0; 32]
        {
            return None;
        }
        Some(Self {
            session_nonce,
            transaction_id,
            region_id,
            incarnation,
            ordinal,
            manifest_digest,
        })
    }
}

impl PrivateMemfd {
    fn new(logical_len: usize) -> Result<Self, MemfdError> {
        let mapped_len = page_align(logical_len)?;
        // SAFETY: static name is NUL-terminated and flags are UAPI values.
        let raw = unsafe {
            libc::memfd_create(
                c"native-ipc-vnext".as_ptr(),
                libc::MFD_CLOEXEC | MFD_NOEXEC_SEAL,
            )
        };
        if raw < 0 {
            return Err(last_native());
        }
        // SAFETY: successful memfd_create returned a new owned fd.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        // SAFETY: descriptor is live and mapped_len narrowed to off_t below.
        if unsafe { libc::ftruncate(fd.as_raw_fd(), mapped_len as libc::off_t) } != 0 {
            return Err(last_native());
        }
        let mapping = VmMapping::map(
            fd.as_raw_fd(),
            mapped_len,
            libc::PROT_READ | libc::PROT_WRITE,
        )?;
        // SAFETY: the new mapping is private to this typestate and fully live.
        unsafe { core::ptr::write_bytes(mapping.base.as_ptr(), 0, mapped_len) };
        let key = validate_object(fd.as_raw_fd(), mapped_len, F_SEAL_EXEC)?;
        debug_assert_eq!(key.mapped_len, mapped_len);
        Ok(Self {
            fd,
            mapping: Some(mapping),
            logical_len,
            not_sync: PhantomData,
        })
    }

    fn from_quiescent(
        mut region: QuiescentRegion,
        cleanup: CleanupPolicy,
        deadline: AbsoluteDeadline,
        guard: bool,
    ) -> Result<Self, MemfdError> {
        check_deadline(deadline)?;
        let logical_len = region.logical_len();
        let mapped_len = region.len();
        let mapping = match VmMapping::map_with_clear(
            region.as_raw_fd_for_vnext(),
            mapped_len,
            libc::PROT_READ | libc::PROT_WRITE,
            cleanup == CleanupPolicy::ClearThenRelease,
            guard,
        ) {
            Ok(mapping) => mapping,
            Err(error) => {
                if cleanup == CleanupPolicy::ClearThenRelease {
                    for byte in region.as_bytes_mut() {
                        // SAFETY: the still-private quiescent mapping is live
                        // and exclusively borrowed for this clearing pass.
                        unsafe { core::ptr::write_volatile(byte, 0) };
                    }
                    compiler_fence(Ordering::SeqCst);
                }
                return Err(error);
            }
        };
        check_deadline(deadline)?;
        let (fd, original_logical_len, original_mapped_len) = region.into_vnext_unmapped_parts();
        debug_assert_eq!(logical_len, original_logical_len);
        debug_assert_eq!(mapped_len, original_mapped_len);
        let validation = validate_object(fd.as_raw_fd(), mapped_len, F_SEAL_EXEC);
        check_deadline(deadline)?;
        validation?;
        Ok(Self {
            fd,
            mapping: Some(mapping),
            logical_len,
            not_sync: PhantomData,
        })
    }

    fn initialize(&mut self, operation: impl FnOnce(&mut [u8])) {
        let mapping = self.mapping.as_mut().expect("private mapping is live");
        // SAFETY: private typestate and exclusive self provide unique bytes.
        let bytes =
            unsafe { core::slice::from_raw_parts_mut(mapping.base.as_ptr(), self.logical_len) };
        operation(bytes);
    }

    fn prepare_coordinator_writer(self) -> Result<CoordinatorWriterPrepared, MemfdError> {
        reject_unsupported_linux_nx()?;
        self.prepare_coordinator_writer_after_nx()
    }

    fn prepare_coordinator_writer_after_nx(
        mut self,
    ) -> Result<CoordinatorWriterPrepared, MemfdError> {
        add_seals(self.fd.as_raw_fd(), FINAL_SEALS & !F_SEAL_EXEC)?;
        let mapping = self.mapping.take().expect("private mapping is live");
        let key = validate_object(self.fd.as_raw_fd(), mapping.len, FINAL_SEALS)?;
        let reader_capability = duplicate(&self.fd)?;
        if validate_object(reader_capability.as_raw_fd(), mapping.len, FINAL_SEALS)? != key {
            return Err(MemfdError::WrongObject);
        }
        Ok(CoordinatorWriterPrepared {
            fd: self.fd,
            mapping,
            reader_capability,
            key,
            not_sync: PhantomData,
        })
    }

    fn prepare_coordinator_writer_for_batch(
        mut self,
        deadline: AbsoluteDeadline,
    ) -> Result<CoordinatorWriterPrepared, MemfdError> {
        check_deadline(deadline)?;
        add_seals(self.fd.as_raw_fd(), FINAL_SEALS & !F_SEAL_EXEC)?;
        check_deadline(deadline)?;
        let mapping = self.mapping.take().expect("private mapping is live");
        let key = validate_object(self.fd.as_raw_fd(), mapping.len, FINAL_SEALS)?;
        check_deadline(deadline)?;
        let reader_capability = duplicate(&self.fd)?;
        check_deadline(deadline)?;
        let exported = validate_object(reader_capability.as_raw_fd(), mapping.len, FINAL_SEALS)?;
        check_deadline(deadline)?;
        if exported != key {
            return Err(MemfdError::WrongObject);
        }
        Ok(CoordinatorWriterPrepared {
            fd: self.fd,
            mapping,
            reader_capability,
            key,
            not_sync: PhantomData,
        })
    }

    fn prepare_receiver_writer(
        self,
        binding: TransferBinding,
    ) -> Result<ReceiverWriterPrepared, MemfdError> {
        reject_unsupported_linux_nx()?;
        self.prepare_receiver_writer_after_nx(binding)
    }

    fn prepare_receiver_writer_after_nx(
        mut self,
        binding: TransferBinding,
    ) -> Result<ReceiverWriterPrepared, MemfdError> {
        add_seals(self.fd.as_raw_fd(), libc::F_SEAL_GROW | libc::F_SEAL_SHRINK)?;
        let mapped_len = self.mapping.as_ref().expect("private mapping is live").len;
        let key = validate_object(self.fd.as_raw_fd(), mapped_len, PREFIX_SEALS)?;
        // The trusted coordinator destroys its only writable view before any
        // receiver capability can be duplicated or escape.
        let mut mapping = self.mapping.take().expect("private mapping is live");
        mapping.clear_on_drop = false;
        mapping.unmap()?;
        Ok(ReceiverWriterPrepared {
            fd: self.fd,
            key,
            binding,
            not_sync: PhantomData,
        })
    }

    fn prepare_receiver_writer_for_batch(
        mut self,
        deadline: AbsoluteDeadline,
    ) -> Result<(OwnedFd, ObjectKey), MemfdError> {
        check_deadline(deadline)?;
        add_seals(self.fd.as_raw_fd(), libc::F_SEAL_GROW | libc::F_SEAL_SHRINK)?;
        check_deadline(deadline)?;
        let mapped_len = self.mapping.as_ref().expect("private mapping is live").len;
        let key = validate_object(self.fd.as_raw_fd(), mapped_len, PREFIX_SEALS)?;
        check_deadline(deadline)?;
        // No coordinator-owned writable mapping may survive capability escape.
        let mut mapping = self.mapping.take().expect("private mapping is live");
        mapping.clear_on_drop = false;
        mapping.unmap()?;
        check_deadline(deadline)?;
        if validate_object(self.fd.as_raw_fd(), mapped_len, PREFIX_SEALS)? != key {
            return Err(MemfdError::WrongObject);
        }
        check_deadline(deadline)?;
        Ok((self.fd, key))
    }
}

impl CoordinatorWriterPrepared {
    fn write_volatile(&mut self, offset: usize, value: u8) {
        assert!(offset < self.mapping.len);
        // SAFETY: this trusted endpoint retains the pre-seal writer mapping.
        unsafe { core::ptr::write_volatile(self.mapping.base.as_ptr().add(offset), value) };
    }

    fn reader_capability(&self) -> Result<OwnedFd, MemfdError> {
        duplicate(&self.reader_capability)
    }

    fn capability(&self) -> BorrowedFd<'_> {
        self.reader_capability.as_fd()
    }

    fn revalidate(&self, deadline: AbsoluteDeadline) -> Result<(), MemfdError> {
        check_deadline(deadline)?;
        let original = validate_object(self.fd.as_raw_fd(), self.mapping.len, FINAL_SEALS)?;
        check_deadline(deadline)?;
        let exported = validate_object(
            self.reader_capability.as_raw_fd(),
            self.mapping.len,
            FINAL_SEALS,
        )?;
        check_deadline(deadline)?;
        if original != self.key || exported != self.key {
            return Err(MemfdError::WrongObject);
        }
        Ok(())
    }
}

impl LinuxCoordinatorWriterBatch {
    pub(crate) fn prepare(
        batch: TransferBatch,
        authority_profile: NativeAuthorityProfile,
        deadline: AbsoluteDeadline,
    ) -> Result<Self, MemfdError> {
        check_deadline(deadline)?;
        if authority_profile != NativeAuthorityProfile::LinuxMdweV1 {
            return Err(MemfdError::WrongProvenance);
        }
        let mut pending = batch.into_pending().map_err(|_| MemfdError::InvalidBatch)?;
        pending
            .regions
            .sort_unstable_by_key(|region| region.spec().id);
        let mut entries = Vec::with_capacity(pending.regions.len());
        for region in pending.regions {
            check_deadline(deadline)?;
            let (request, spec, guard) = region.into_linux_transfer_parts();
            if spec.writer != WriterEndpoint::Coordinator {
                return Err(MemfdError::UnsupportedDirection);
            }
            let native = request
                .native_spec(spec.id.get())
                .ok_or(MemfdError::InvalidBatch)?;
            let (region, cleanup) = request.into_linux_quiescent();
            // This writable view is the coordinator's own active view after
            // commit, so it receives the region's requested guard policy.
            let prepared = PrivateMemfd::from_quiescent(
                region,
                cleanup,
                deadline,
                guard.requested != GuardPolicy::Disable,
            )?
            .prepare_coordinator_writer_for_batch(deadline)?;
            if guard.requested == GuardPolicy::Require && !prepared.mapping.guarded {
                return Err(MemfdError::GuardUnavailable);
            }
            entries.push(LinuxCoordinatorWriterEntry {
                native,
                prepared,
                guard_requested: guard.requested,
            });
        }
        check_deadline(deadline)?;
        Ok(Self {
            entries,
            deadline,
            #[cfg(test)]
            drop_observer: None,
            #[cfg(test)]
            revalidation_fault: false,
        })
    }

    pub(crate) fn manifest_entries(&self) -> Vec<ManifestEntry> {
        self.entries
            .iter()
            .map(|entry| ManifestEntry::from_native(entry.native, PeerAccess::ReadOnly))
            .collect()
    }

    pub(crate) fn capabilities(&self) -> Vec<BorrowedFd<'_>> {
        self.entries
            .iter()
            .map(|entry| entry.prepared.capability())
            .collect()
    }

    pub(crate) fn revalidate(&self) -> Result<(), MemfdError> {
        #[cfg(test)]
        if self.revalidation_fault {
            return Err(MemfdError::WrongObject);
        }
        check_deadline(self.deadline)?;
        self.entries.iter().try_for_each(|entry| {
            entry.prepared.revalidate(self.deadline)?;
            check_deadline(self.deadline)
        })
    }

    pub(crate) const fn deadline(&self) -> AbsoluteDeadline {
        self.deadline
    }

    #[cfg(test)]
    pub(crate) fn observe_drop_for_test(&mut self, observer: Arc<Mutex<Vec<&'static str>>>) {
        self.drop_observer = Some(observer);
    }

    #[cfg(test)]
    pub(crate) fn fail_revalidation_for_test(&mut self) {
        self.revalidation_fault = true;
    }

    #[cfg(test)]
    pub(crate) fn replace_export_with_invalid_file_for_test(&mut self, ordinal: usize) {
        self.entries[ordinal].prepared.reader_capability =
            std::fs::File::open("/dev/null").unwrap().into();
    }
}

impl LinuxReceiverWriterBatch {
    pub(crate) fn prepare(
        batch: TransferBatch,
        authority_profile: NativeAuthorityProfile,
        deadline: AbsoluteDeadline,
    ) -> Result<Self, MemfdError> {
        check_deadline(deadline)?;
        if authority_profile != NativeAuthorityProfile::LinuxMdweV1 {
            return Err(MemfdError::WrongProvenance);
        }
        let mut pending = batch.into_pending().map_err(|_| MemfdError::InvalidBatch)?;
        pending
            .regions
            .sort_unstable_by_key(|region| region.spec().id);
        let mut entries = Vec::with_capacity(pending.regions.len());
        for region in pending.regions {
            check_deadline(deadline)?;
            let (request, spec, guard) = region.into_linux_transfer_parts();
            if spec.writer != WriterEndpoint::Receiver {
                return Err(MemfdError::UnsupportedDirection);
            }
            let native = request
                .native_spec(spec.id.get())
                .ok_or(MemfdError::InvalidBatch)?;
            let (region, cleanup) = request.into_linux_quiescent();
            // This transitional writable view is destroyed before any
            // capability escapes; only the read-only view established at
            // seal time is active, so the policy applies there instead.
            let (fd, key) = PrivateMemfd::from_quiescent(region, cleanup, deadline, false)?
                .prepare_receiver_writer_for_batch(deadline)?;
            entries.push(LinuxReceiverWriterEntry {
                native,
                fd,
                key,
                mapping: None,
                pending_mapping: None,
                guard_requested: guard.requested,
                #[cfg(test)]
                capability_override: None,
            });
        }
        check_deadline(deadline)?;
        Ok(Self {
            entries,
            deadline,
            #[cfg(test)]
            drop_observer: None,
            #[cfg(test)]
            seal_failure_at: None,
            #[cfg(test)]
            advice_failure_at: None,
        })
    }

    pub(crate) fn manifest_entries(&self) -> Vec<ManifestEntry> {
        self.entries
            .iter()
            .map(|entry| ManifestEntry::from_native(entry.native, PeerAccess::SoleWriter))
            .collect()
    }

    pub(crate) fn capabilities(&self) -> Vec<BorrowedFd<'_>> {
        self.entries
            .iter()
            .map(|entry| {
                #[cfg(test)]
                if let Some(capability) = &entry.capability_override {
                    return capability.as_fd();
                }
                entry.fd.as_fd()
            })
            .collect()
    }

    pub(crate) const fn deadline(&self) -> AbsoluteDeadline {
        self.deadline
    }

    pub(crate) fn revalidate_prefix(&self) -> Result<(), MemfdError> {
        check_deadline(self.deadline)?;
        self.entries.iter().try_for_each(|entry| {
            if entry.mapping.is_some() || entry.pending_mapping.is_some() {
                return Err(MemfdError::WrongObject);
            }
            if validate_object(entry.fd.as_raw_fd(), entry.key.mapped_len, PREFIX_SEALS)?
                != entry.key
            {
                return Err(MemfdError::WrongObject);
            }
            check_deadline(self.deadline)
        })
    }

    pub(crate) fn seal_after_import(&mut self) -> Result<(), MemfdError> {
        let mut first_error = check_deadline(self.deadline).err();
        // Validate the complete prefix-sealed set before attenuation, but do
        // not let one failure prevent best-effort sealing of every escaped fd.
        for entry in &self.entries {
            let validation =
                validate_object(entry.fd.as_raw_fd(), entry.key.mapped_len, PREFIX_SEALS).and_then(
                    |key| {
                        if key == entry.key {
                            Ok(())
                        } else {
                            Err(MemfdError::WrongObject)
                        }
                    },
                );
            if first_error.is_none() {
                first_error = validation.err();
            }
        }

        // Attenuate the complete batch immediately after IMPORTED. Deadline or
        // per-entry failures are remembered, while remaining fds still receive
        // best-effort final seals before any unrelated mapping work begins.
        #[cfg(test)]
        let mut seal_ordinal = 0_usize;
        for entry in &mut self.entries {
            if first_error.is_none() {
                first_error = check_deadline(self.deadline).err();
            }
            #[cfg(test)]
            {
                seal_ordinal += 1;
                if self.seal_failure_at == Some(seal_ordinal) {
                    if first_error.is_none() {
                        first_error = Some(MemfdError::Native(libc::EIO));
                    }
                    continue;
                }
            }
            if let Err(error) = add_seals(
                entry.fd.as_raw_fd(),
                libc::F_SEAL_FUTURE_WRITE | libc::F_SEAL_SEAL,
            ) {
                if first_error.is_none() {
                    first_error = Some(error);
                }
                continue;
            }
            let validation =
                validate_object(entry.fd.as_raw_fd(), entry.key.mapped_len, FINAL_SEALS).and_then(
                    |key| {
                        if key == entry.key {
                            Ok(())
                        } else {
                            Err(MemfdError::WrongObject)
                        }
                    },
                );
            if first_error.is_none() {
                first_error = validation.err();
            }
        }
        if let Some(error) = first_error {
            return Err(error);
        }

        // Only a completely final-sealed batch may acquire coordinator RO
        // mappings. Any mapping/advice failure leaves every fd attenuated.
        #[cfg(test)]
        let mut advice_operation = 0_usize;
        for entry in &mut self.entries {
            check_deadline(self.deadline)?;
            // This read-only view is the coordinator's own active view after
            // commit, so it receives the region's requested guard policy.
            let pending = PendingVmMapping::map(
                entry.fd.as_raw_fd(),
                entry.key.mapped_len,
                libc::PROT_READ,
                false,
                entry.guard_requested != GuardPolicy::Disable,
            )?;
            if entry.guard_requested == GuardPolicy::Require && !pending.guarded {
                return Err(MemfdError::GuardUnavailable);
            }
            entry.pending_mapping = Some(pending);
            check_deadline(self.deadline)?;
            for advice in [libc::MADV_DONTDUMP, libc::MADV_DONTFORK] {
                #[cfg(test)]
                {
                    advice_operation += 1;
                    if self.advice_failure_at == Some(advice_operation) {
                        return Err(MemfdError::Native(libc::EIO));
                    }
                }
                entry
                    .pending_mapping
                    .as_ref()
                    .expect("pending mapping remains batch-owned")
                    .advise(advice)?;
                check_deadline(self.deadline)?;
            }
            let pending = entry
                .pending_mapping
                .take()
                .expect("validated pending mapping remains owned");
            entry.mapping = Some(match pending.into_mapping() {
                Ok(mapping) => mapping,
                Err((error, pending)) => {
                    entry.pending_mapping = Some(pending);
                    return Err(error);
                }
            });
        }
        check_deadline(self.deadline)
    }

    #[cfg(test)]
    pub(crate) fn observe_drop_for_test(&mut self, observer: Arc<Mutex<Vec<&'static str>>>) {
        self.drop_observer = Some(observer);
    }

    #[cfg(test)]
    pub(crate) fn fail_seal_at_for_test(&mut self, ordinal: usize) {
        assert!((1..=self.entries.len()).contains(&ordinal));
        self.seal_failure_at = Some(ordinal);
    }

    #[cfg(test)]
    pub(crate) fn fail_advice_at_for_test(&mut self, operation: usize) {
        assert!(operation > 0);
        self.advice_failure_at = Some(operation);
    }

    #[cfg(test)]
    pub(crate) fn replace_capability_with_invalid_file_for_test(&mut self, ordinal: usize) {
        self.entries[ordinal].capability_override =
            Some(std::fs::File::open("/dev/null").unwrap().into());
    }

    #[cfg(test)]
    pub(crate) fn read_for_test(&self, ordinal: usize, offset: usize) -> u8 {
        let mapping = self.entries[ordinal]
            .mapping
            .as_ref()
            .expect("coordinator read view follows final sealing");
        assert!(offset < self.entries[ordinal].native.logical_len as usize);
        // SAFETY: the final-sealed read-only mapping remains batch-owned.
        unsafe { core::ptr::read_volatile(mapping.base.as_ptr().add(offset)) }
    }

    #[cfg(test)]
    pub(crate) fn all_final_sealed_for_test(&self) -> bool {
        self.entries.iter().all(|entry| {
            validate_object(entry.fd.as_raw_fd(), entry.key.mapped_len, FINAL_SEALS)
                == Ok(entry.key)
        })
    }

    #[cfg(test)]
    pub(crate) fn seal_counts_for_test(&self) -> (usize, usize) {
        self.entries
            .iter()
            .fold((0, 0), |(prefix, final_sealed), entry| {
                // SAFETY: scalar seal query on a live batch-owned fd.
                match unsafe { libc::fcntl(entry.fd.as_raw_fd(), libc::F_GET_SEALS) } {
                    PREFIX_SEALS => (prefix + 1, final_sealed),
                    FINAL_SEALS => (prefix, final_sealed + 1),
                    seals => panic!("unexpected seal set {seals:#x}"),
                }
            })
    }
}

impl LinuxMixedDirectionBatch {
    pub(crate) fn prepare(
        batch: TransferBatch,
        authority_profile: NativeAuthorityProfile,
        deadline: AbsoluteDeadline,
    ) -> Result<Self, MemfdError> {
        Self::prepare_inner(batch, authority_profile, deadline, None)
    }

    fn prepare_inner(
        batch: TransferBatch,
        authority_profile: NativeAuthorityProfile,
        deadline: AbsoluteDeadline,
        failure_at: Option<usize>,
    ) -> Result<Self, MemfdError> {
        check_deadline(deadline)?;
        if authority_profile != NativeAuthorityProfile::LinuxMdweV1 {
            return Err(MemfdError::WrongProvenance);
        }
        let mut pending = batch.into_pending().map_err(|_| MemfdError::InvalidBatch)?;
        pending
            .regions
            .sort_unstable_by_key(|region| region.spec().id);
        let mut entries = Vec::with_capacity(pending.regions.len());
        #[cfg(test)]
        let mut prepare_ordinal = 0_usize;
        #[cfg(not(test))]
        let _ = failure_at;
        for region in pending.regions {
            check_deadline(deadline)?;
            #[cfg(test)]
            {
                prepare_ordinal += 1;
                if failure_at == Some(prepare_ordinal) {
                    return Err(MemfdError::Native(libc::EIO));
                }
            }
            let writer = region.spec().writer;
            let mapped_len =
                u64::try_from(region.mapped_len()).map_err(|_| MemfdError::InvalidSize)?;
            let mut single = TransferBatch::new(1, mapped_len, mapped_len)
                .map_err(|_| MemfdError::InvalidBatch)?;
            single.add(region).map_err(|_| MemfdError::InvalidBatch)?;
            let entry = match writer {
                WriterEndpoint::Coordinator => LinuxMixedDirectionEntry::CoordinatorWriter(
                    LinuxCoordinatorWriterBatch::prepare(single, authority_profile, deadline)?,
                ),
                WriterEndpoint::Receiver => LinuxMixedDirectionEntry::ReceiverWriter(
                    LinuxReceiverWriterBatch::prepare(single, authority_profile, deadline)?,
                ),
            };
            entries.push(entry);
        }
        check_deadline(deadline)?;
        Ok(Self {
            entries,
            deadline,
            #[cfg(test)]
            drop_observer: None,
            #[cfg(test)]
            active_drop_observer: None,
            #[cfg(test)]
            seal_failure_at: None,
            #[cfg(test)]
            advice_failure_at: None,
        })
    }

    pub(crate) fn manifest_entries(&self) -> Vec<ManifestEntry> {
        self.entries
            .iter()
            .flat_map(|entry| match entry {
                LinuxMixedDirectionEntry::CoordinatorWriter(batch) => batch.manifest_entries(),
                LinuxMixedDirectionEntry::ReceiverWriter(batch) => batch.manifest_entries(),
            })
            .collect()
    }

    pub(crate) fn reservation_lengths(&self) -> Vec<u64> {
        self.manifest_entries()
            .into_iter()
            .map(|entry| entry.mapped_len)
            .collect()
    }

    pub(crate) fn capabilities(&self) -> Vec<BorrowedFd<'_>> {
        self.entries
            .iter()
            .flat_map(|entry| match entry {
                LinuxMixedDirectionEntry::CoordinatorWriter(batch) => batch.capabilities(),
                LinuxMixedDirectionEntry::ReceiverWriter(batch) => batch.capabilities(),
            })
            .collect()
    }

    pub(crate) fn revalidate_before_send(&self) -> Result<(), MemfdError> {
        check_deadline(self.deadline)?;
        for entry in &self.entries {
            match entry {
                LinuxMixedDirectionEntry::CoordinatorWriter(batch) => batch.revalidate()?,
                LinuxMixedDirectionEntry::ReceiverWriter(batch) => batch.revalidate_prefix()?,
            }
            check_deadline(self.deadline)?;
        }
        Ok(())
    }

    pub(crate) fn requires_imported_sealed(&self) -> bool {
        self.entries
            .iter()
            .any(|entry| matches!(entry, LinuxMixedDirectionEntry::ReceiverWriter(_)))
    }

    pub(crate) fn seal_after_import(&mut self) -> Result<(), MemfdError> {
        let mut first_error = check_deadline(self.deadline).err();

        // Revalidate the complete mixed object set before attenuation. One bad
        // entry is remembered without preventing best-effort sealing of every
        // receiver-writer fd that has already escaped.
        for entry in &self.entries {
            let (fd, key, seals) = match entry {
                LinuxMixedDirectionEntry::CoordinatorWriter(batch) => {
                    let entry = &batch.entries[0];
                    (
                        entry.prepared.fd.as_raw_fd(),
                        entry.prepared.key,
                        FINAL_SEALS,
                    )
                }
                LinuxMixedDirectionEntry::ReceiverWriter(batch) => {
                    let entry = &batch.entries[0];
                    (entry.fd.as_raw_fd(), entry.key, PREFIX_SEALS)
                }
            };
            let validation = validate_object(fd, key.mapped_len, seals).and_then(|validated| {
                if validated == key {
                    Ok(())
                } else {
                    Err(MemfdError::WrongObject)
                }
            });
            if first_error.is_none() {
                first_error = validation.err();
            }
        }

        #[cfg(test)]
        let mut seal_ordinal = 0_usize;
        for entry in &mut self.entries {
            let LinuxMixedDirectionEntry::ReceiverWriter(batch) = entry else {
                continue;
            };
            for entry in &mut batch.entries {
                if first_error.is_none() {
                    first_error = check_deadline(self.deadline).err();
                }
                #[cfg(test)]
                {
                    seal_ordinal += 1;
                    if self.seal_failure_at == Some(seal_ordinal) {
                        if first_error.is_none() {
                            first_error = Some(MemfdError::Native(libc::EIO));
                        }
                        continue;
                    }
                }
                if let Err(error) = add_seals(
                    entry.fd.as_raw_fd(),
                    libc::F_SEAL_FUTURE_WRITE | libc::F_SEAL_SEAL,
                ) {
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                    continue;
                }
                let validation =
                    validate_object(entry.fd.as_raw_fd(), entry.key.mapped_len, FINAL_SEALS)
                        .and_then(|validated| {
                            if validated == entry.key {
                                Ok(())
                            } else {
                                Err(MemfdError::WrongObject)
                            }
                        });
                if first_error.is_none() {
                    first_error = validation.err();
                }
            }
        }
        if let Some(error) = first_error {
            return Err(error);
        }

        // All escaped writer fds are final-sealed before the first coordinator
        // read mapping is attempted.
        #[cfg(test)]
        let mut advice_operation = 0_usize;
        for entry in &mut self.entries {
            let LinuxMixedDirectionEntry::ReceiverWriter(batch) = entry else {
                continue;
            };
            for entry in &mut batch.entries {
                check_deadline(self.deadline)?;
                // This read-only view is the coordinator's own active view
                // after commit; it receives the region's requested policy.
                let pending = PendingVmMapping::map(
                    entry.fd.as_raw_fd(),
                    entry.key.mapped_len,
                    libc::PROT_READ,
                    false,
                    entry.guard_requested != GuardPolicy::Disable,
                )?;
                if entry.guard_requested == GuardPolicy::Require && !pending.guarded {
                    return Err(MemfdError::GuardUnavailable);
                }
                entry.pending_mapping = Some(pending);
                check_deadline(self.deadline)?;
                for advice in [libc::MADV_DONTDUMP, libc::MADV_DONTFORK] {
                    #[cfg(test)]
                    {
                        advice_operation += 1;
                        if self.advice_failure_at == Some(advice_operation) {
                            return Err(MemfdError::Native(libc::EIO));
                        }
                    }
                    entry
                        .pending_mapping
                        .as_ref()
                        .expect("pending mixed mapping remains batch-owned")
                        .advise(advice)?;
                    check_deadline(self.deadline)?;
                }
                let pending = entry
                    .pending_mapping
                    .take()
                    .expect("validated mixed mapping remains batch-owned");
                entry.mapping = Some(match pending.into_mapping() {
                    Ok(mapping) => mapping,
                    Err((error, pending)) => {
                        entry.pending_mapping = Some(pending);
                        return Err(error);
                    }
                });
            }
        }
        check_deadline(self.deadline)
    }

    pub(crate) const fn deadline(&self) -> AbsoluteDeadline {
        self.deadline
    }

    #[cfg(test)]
    pub(crate) fn prepare_with_failure_for_test(
        batch: TransferBatch,
        authority_profile: NativeAuthorityProfile,
        deadline: AbsoluteDeadline,
        failure_at: usize,
    ) -> Result<Self, MemfdError> {
        assert!((1..=16).contains(&failure_at));
        Self::prepare_inner(batch, authority_profile, deadline, Some(failure_at))
    }

    #[cfg(test)]
    pub(crate) fn observe_drop_for_test(&mut self, observer: Arc<Mutex<Vec<&'static str>>>) {
        self.drop_observer = Some(observer);
    }

    #[cfg(test)]
    pub(crate) fn observe_active_drop_for_test(&mut self, observer: Arc<Mutex<Vec<&'static str>>>) {
        self.active_drop_observer = Some(observer);
    }

    #[cfg(test)]
    pub(crate) fn fail_seal_at_for_test(&mut self, ordinal: usize) {
        assert!(ordinal > 0);
        self.seal_failure_at = Some(ordinal);
    }

    #[cfg(test)]
    pub(crate) fn fail_advice_at_for_test(&mut self, operation: usize) {
        assert!(operation > 0);
        self.advice_failure_at = Some(operation);
    }

    #[cfg(test)]
    pub(crate) fn all_final_sealed_for_test(&self) -> bool {
        self.entries.iter().all(|entry| match entry {
            LinuxMixedDirectionEntry::CoordinatorWriter(batch) => batch.revalidate().is_ok(),
            LinuxMixedDirectionEntry::ReceiverWriter(batch) => batch.all_final_sealed_for_test(),
        })
    }

    #[cfg(test)]
    pub(crate) fn seal_counts_for_test(&self) -> (usize, usize) {
        self.entries
            .iter()
            .fold((0, 0), |(prefix, final_sealed), entry| match entry {
                LinuxMixedDirectionEntry::CoordinatorWriter(_) => (prefix, final_sealed + 1),
                LinuxMixedDirectionEntry::ReceiverWriter(batch) => {
                    let (entry_prefix, entry_final) = batch.seal_counts_for_test();
                    (prefix + entry_prefix, final_sealed + entry_final)
                }
            })
    }

    #[cfg(test)]
    pub(crate) fn read_receiver_for_test(&self, ordinal: usize, offset: usize) -> u8 {
        let LinuxMixedDirectionEntry::ReceiverWriter(batch) = &self.entries[ordinal] else {
            panic!("test read requires a receiver-writer entry");
        };
        batch.read_for_test(0, offset)
    }
}

impl LinuxExpectedCoordinatorWriterBatch {
    pub(crate) fn prepare(
        expected: ExpectedBatch,
        limits: SessionLimits,
        deadline: AbsoluteDeadline,
    ) -> Result<Self, MemfdError> {
        check_deadline(deadline)?;
        if expected.len() > usize::from(limits.max_regions_per_batch)
            || expected.len() as u64 > u64::from(limits.max_active_regions)
            || expected.total_logical > limits.max_batch_bytes
        {
            return Err(MemfdError::InvalidBatch);
        }
        let mut total_mapped = 0_u64;
        let mut entries = Vec::with_capacity(expected.len());
        for region in expected.regions {
            check_deadline(deadline)?;
            if region.writer != WriterEndpoint::Coordinator {
                return Err(MemfdError::UnsupportedDirection);
            }
            let logical_len = u64::try_from(region.logical_len)
                .ok()
                .filter(|logical| *logical <= limits.max_region_bytes)
                .ok_or(MemfdError::InvalidBatch)?;
            let mapped_len = u64::try_from(page_align(region.logical_len)?)
                .map_err(|_| MemfdError::InvalidSize)?;
            total_mapped = total_mapped
                .checked_add(mapped_len)
                .filter(|total| {
                    *total <= limits.max_batch_bytes && *total <= limits.max_active_bytes
                })
                .ok_or(MemfdError::InvalidBatch)?;
            entries.push(LinuxExpectedCoordinatorWriterEntry {
                region_id: region.id.get(),
                logical_len,
                mapped_len,
            });
        }
        Ok(Self {
            entries,
            total_logical: expected.total_logical,
            total_mapped,
            deadline,
            #[cfg(test)]
            advice_failure_at: None,
        })
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(crate) const fn deadline(&self) -> AbsoluteDeadline {
        self.deadline
    }

    #[cfg(test)]
    pub(crate) fn fail_advice_at_for_test(&mut self, operation: usize) {
        assert!(operation > 0);
        self.advice_failure_at = Some(operation);
    }

    pub(crate) fn matches_manifest(&self, manifest: &TransferManifest) -> bool {
        manifest.entries().len() == self.entries.len()
            && manifest.total_logical() == self.total_logical
            && manifest.total_mapped() == self.total_mapped
            && self.entries.iter().zip(manifest.entries()).enumerate().all(
                |(ordinal, (expected, received))| {
                    received.region_id == expected.region_id
                        && received.writer == 0
                        && received.access == PeerAccess::ReadOnly
                        && received.logical_len == expected.logical_len
                        && received.mapped_len == expected.mapped_len
                        && received.ordinal as usize == ordinal
                },
            )
    }

    pub(crate) fn import(
        self,
        manifest: &TransferManifest,
        descriptors: Vec<OwnedFd>,
    ) -> Result<LinuxImportedCoordinatorWriterBatch, LinuxImportFailure> {
        let mut descriptors = descriptors.into_iter();
        let mut imported = Vec::with_capacity(self.entries.len());
        macro_rules! fail {
            ($error:expr, $current_fd:expr, $current_mapping:expr) => {
                return Err(LinuxImportFailure {
                    error: $error,
                    _partial: imported,
                    _current_fd: $current_fd,
                    _current_mapping: $current_mapping,
                    _remaining: descriptors,
                    #[cfg(test)]
                    drop_observer: None,
                })
            };
        }
        if let Err(error) = check_deadline(self.deadline) {
            fail!(error, None, None);
        }
        if descriptors.len() != self.entries.len() || !self.matches_manifest(manifest) {
            fail!(MemfdError::WrongProvenance, None, None);
        }
        #[cfg(test)]
        let mut advice_operation = 0_usize;
        for entry in manifest.entries().iter().copied() {
            let fd = descriptors
                .next()
                .expect("validated descriptor count matches manifest");
            if let Err(error) = check_deadline(self.deadline) {
                fail!(error, Some(fd), None);
            }
            let mapped_len = match usize::try_from(entry.mapped_len) {
                Ok(mapped_len) => mapped_len,
                Err(_) => fail!(MemfdError::InvalidSize, Some(fd), None),
            };
            let key = match validate_object(fd.as_raw_fd(), mapped_len, FINAL_SEALS) {
                Ok(key) => key,
                Err(error) => fail!(error, Some(fd), None),
            };
            if let Err(error) = check_deadline(self.deadline) {
                fail!(error, Some(fd), None);
            }
            // Imported views always take best-effort guard placement: the
            // wire manifest does not carry the creator's policy.
            let pending = match PendingVmMapping::map(
                fd.as_raw_fd(),
                mapped_len,
                libc::PROT_READ,
                false,
                true,
            ) {
                Ok(mapping) => mapping,
                Err(error) => fail!(error, Some(fd), None),
            };
            if let Err(error) = check_deadline(self.deadline) {
                fail!(error, Some(fd), Some(pending));
            }
            for advice in [libc::MADV_DONTDUMP, libc::MADV_DONTFORK] {
                #[cfg(test)]
                {
                    advice_operation += 1;
                    if self.advice_failure_at == Some(advice_operation) {
                        fail!(MemfdError::Native(libc::EIO), Some(fd), Some(pending));
                    }
                }
                if let Err(error) = pending.advise(advice) {
                    fail!(error, Some(fd), Some(pending));
                }
                if let Err(error) = check_deadline(self.deadline) {
                    fail!(error, Some(fd), Some(pending));
                }
            }
            let mapping = match pending.into_mapping() {
                Ok(mapping) => mapping,
                Err((error, pending)) => fail!(error, Some(fd), Some(pending)),
            };
            imported.push(LinuxImportedCoordinatorWriterEntry {
                manifest: entry,
                fd,
                mapping,
                key,
            });
            if let Err(error) = check_deadline(self.deadline) {
                fail!(error, None, None);
            }
            let retained = imported.last().expect("current import is retained");
            match validate_object(retained.fd.as_raw_fd(), mapped_len, FINAL_SEALS) {
                Ok(validated) if validated == key => {}
                Ok(_) => fail!(MemfdError::WrongObject, None, None),
                Err(error) => fail!(error, None, None),
            }
        }
        if let Err(error) = check_deadline(self.deadline) {
            fail!(error, None, None);
        }
        Ok(LinuxImportedCoordinatorWriterBatch {
            entries: imported,
            #[cfg(test)]
            drop_observer: None,
        })
    }
}

impl LinuxExpectedReceiverWriterBatch {
    pub(crate) fn prepare(
        expected: ExpectedBatch,
        limits: SessionLimits,
        deadline: AbsoluteDeadline,
    ) -> Result<Self, MemfdError> {
        check_deadline(deadline)?;
        if expected.len() > usize::from(limits.max_regions_per_batch)
            || expected.len() as u64 > u64::from(limits.max_active_regions)
            || expected.total_logical > limits.max_batch_bytes
        {
            return Err(MemfdError::InvalidBatch);
        }
        let mut total_mapped = 0_u64;
        let mut entries = Vec::with_capacity(expected.len());
        for region in expected.regions {
            check_deadline(deadline)?;
            if region.writer != WriterEndpoint::Receiver {
                return Err(MemfdError::UnsupportedDirection);
            }
            let logical_len = u64::try_from(region.logical_len)
                .ok()
                .filter(|logical| *logical <= limits.max_region_bytes)
                .ok_or(MemfdError::InvalidBatch)?;
            let mapped_len = u64::try_from(page_align(region.logical_len)?)
                .map_err(|_| MemfdError::InvalidSize)?;
            total_mapped = total_mapped
                .checked_add(mapped_len)
                .filter(|total| {
                    *total <= limits.max_batch_bytes && *total <= limits.max_active_bytes
                })
                .ok_or(MemfdError::InvalidBatch)?;
            entries.push(LinuxExpectedCoordinatorWriterEntry {
                region_id: region.id.get(),
                logical_len,
                mapped_len,
            });
        }
        Ok(Self {
            entries,
            total_logical: expected.total_logical,
            total_mapped,
            deadline,
            #[cfg(test)]
            advice_failure_at: None,
        })
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(crate) const fn deadline(&self) -> AbsoluteDeadline {
        self.deadline
    }

    #[cfg(test)]
    pub(crate) fn fail_advice_at_for_test(&mut self, operation: usize) {
        assert!(operation > 0);
        self.advice_failure_at = Some(operation);
    }

    pub(crate) fn matches_manifest(&self, manifest: &TransferManifest) -> bool {
        manifest.entries().len() == self.entries.len()
            && manifest.total_logical() == self.total_logical
            && manifest.total_mapped() == self.total_mapped
            && self.entries.iter().zip(manifest.entries()).enumerate().all(
                |(ordinal, (expected, received))| {
                    received.region_id == expected.region_id
                        && received.writer == 1
                        && received.access == PeerAccess::SoleWriter
                        && received.logical_len == expected.logical_len
                        && received.mapped_len == expected.mapped_len
                        && received.ordinal as usize == ordinal
                },
            )
    }

    pub(crate) fn import(
        self,
        manifest: &TransferManifest,
        descriptors: Vec<OwnedFd>,
    ) -> Result<LinuxImportedReceiverWriterBatch, LinuxReceiverWriterImportFailure> {
        let mut descriptors = descriptors.into_iter();
        let mut imported = Vec::with_capacity(self.entries.len());
        macro_rules! fail {
            ($error:expr, $current_fd:expr, $current_mapping:expr) => {
                return Err(LinuxReceiverWriterImportFailure {
                    error: $error,
                    _partial: imported,
                    _current_fd: $current_fd,
                    _current_mapping: $current_mapping,
                    _remaining: descriptors,
                    #[cfg(test)]
                    drop_observer: None,
                })
            };
        }
        if let Err(error) = check_deadline(self.deadline) {
            fail!(error, None, None);
        }
        if descriptors.len() != self.entries.len() || !self.matches_manifest(manifest) {
            fail!(MemfdError::WrongProvenance, None, None);
        }
        #[cfg(test)]
        let mut advice_operation = 0_usize;
        for entry in manifest.entries().iter().copied() {
            let fd = descriptors
                .next()
                .expect("validated descriptor count matches manifest");
            if let Err(error) = check_deadline(self.deadline) {
                fail!(error, Some(fd), None);
            }
            let mapped_len = match usize::try_from(entry.mapped_len) {
                Ok(mapped_len) => mapped_len,
                Err(_) => fail!(MemfdError::InvalidSize, Some(fd), None),
            };
            let key = match validate_object(fd.as_raw_fd(), mapped_len, PREFIX_SEALS) {
                Ok(key) => key,
                Err(error) => fail!(error, Some(fd), None),
            };
            if let Err(error) = check_deadline(self.deadline) {
                fail!(error, Some(fd), None);
            }
            // Imported views always take best-effort guard placement: the
            // wire manifest does not carry the creator's policy.
            let pending = match PendingVmMapping::map(
                fd.as_raw_fd(),
                mapped_len,
                libc::PROT_READ | libc::PROT_WRITE,
                false,
                true,
            ) {
                Ok(mapping) => mapping,
                Err(error) => fail!(error, Some(fd), None),
            };
            if let Err(error) = check_deadline(self.deadline) {
                fail!(error, Some(fd), Some(pending));
            }
            for advice in [libc::MADV_DONTDUMP, libc::MADV_DONTFORK] {
                #[cfg(test)]
                {
                    advice_operation += 1;
                    if self.advice_failure_at == Some(advice_operation) {
                        fail!(MemfdError::Native(libc::EIO), Some(fd), Some(pending));
                    }
                }
                if let Err(error) = pending.advise(advice) {
                    fail!(error, Some(fd), Some(pending));
                }
                if let Err(error) = check_deadline(self.deadline) {
                    fail!(error, Some(fd), Some(pending));
                }
            }
            let mapping = match pending.into_mapping() {
                Ok(mapping) => mapping,
                Err((error, pending)) => fail!(error, Some(fd), Some(pending)),
            };
            imported.push(LinuxImportedReceiverWriterEntry {
                manifest: entry,
                fd,
                mapping,
                key,
            });
            if let Err(error) = check_deadline(self.deadline) {
                fail!(error, None, None);
            }
            let retained = imported.last().expect("current import is retained");
            match validate_object(retained.fd.as_raw_fd(), mapped_len, PREFIX_SEALS) {
                Ok(validated) if validated == key => {}
                Ok(_) => fail!(MemfdError::WrongObject, None, None),
                Err(error) => fail!(error, None, None),
            }
        }
        if let Err(error) = check_deadline(self.deadline) {
            fail!(error, None, None);
        }
        Ok(LinuxImportedReceiverWriterBatch {
            entries: imported,
            sealed_verified: false,
            #[cfg(test)]
            drop_observer: None,
        })
    }
}

impl LinuxExpectedMixedDirectionBatch {
    pub(crate) fn prepare(
        expected: ExpectedBatch,
        limits: SessionLimits,
        deadline: AbsoluteDeadline,
    ) -> Result<Self, MemfdError> {
        check_deadline(deadline)?;
        if expected.len() > usize::from(limits.max_regions_per_batch)
            || expected.len() as u64 > u64::from(limits.max_active_regions)
            || expected.total_logical > limits.max_batch_bytes
        {
            return Err(MemfdError::InvalidBatch);
        }
        let mut total_mapped = 0_u64;
        let mut entries = Vec::with_capacity(expected.len());
        for region in expected.regions {
            check_deadline(deadline)?;
            let logical_len = u64::try_from(region.logical_len)
                .ok()
                .filter(|logical| *logical <= limits.max_region_bytes)
                .ok_or(MemfdError::InvalidBatch)?;
            let mapped_len = u64::try_from(page_align(region.logical_len)?)
                .map_err(|_| MemfdError::InvalidSize)?;
            total_mapped = total_mapped
                .checked_add(mapped_len)
                .filter(|total| {
                    *total <= limits.max_batch_bytes && *total <= limits.max_active_bytes
                })
                .ok_or(MemfdError::InvalidBatch)?;
            entries.push(LinuxExpectedMixedDirectionEntry {
                region_id: region.id.get(),
                writer: region.writer,
                logical_len,
                mapped_len,
            });
        }
        Ok(Self {
            entries,
            total_logical: expected.total_logical,
            total_mapped,
            deadline,
            #[cfg(test)]
            advice_failure_at: None,
        })
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn reservation_lengths(&self) -> Vec<u64> {
        self.entries.iter().map(|entry| entry.mapped_len).collect()
    }

    pub(crate) const fn deadline(&self) -> AbsoluteDeadline {
        self.deadline
    }

    pub(crate) fn requires_imported_sealed(&self) -> bool {
        self.entries
            .iter()
            .any(|entry| entry.writer == WriterEndpoint::Receiver)
    }

    pub(crate) fn matches_manifest(&self, manifest: &TransferManifest) -> bool {
        manifest.entries().len() == self.entries.len()
            && manifest.total_logical() == self.total_logical
            && manifest.total_mapped() == self.total_mapped
            && self.entries.iter().zip(manifest.entries()).enumerate().all(
                |(ordinal, (expected, received))| {
                    let (writer, access) = match expected.writer {
                        WriterEndpoint::Coordinator => (0, PeerAccess::ReadOnly),
                        WriterEndpoint::Receiver => (1, PeerAccess::SoleWriter),
                    };
                    received.region_id == expected.region_id
                        && received.writer == writer
                        && received.access == access
                        && received.logical_len == expected.logical_len
                        && received.mapped_len == expected.mapped_len
                        && received.ordinal as usize == ordinal
                },
            )
    }

    pub(crate) fn import(
        self,
        manifest: &TransferManifest,
        descriptors: Vec<OwnedFd>,
    ) -> Result<LinuxImportedMixedDirectionBatch, LinuxMixedDirectionImportFailure> {
        let mut descriptors = descriptors.into_iter();
        let mut imported: Vec<LinuxImportedMixedDirectionEntry> =
            Vec::with_capacity(self.entries.len());
        macro_rules! fail {
            ($error:expr, $current_fd:expr, $current_mapping:expr) => {
                return Err(LinuxMixedDirectionImportFailure {
                    error: $error,
                    _partial: imported,
                    _current_fd: $current_fd,
                    _current_mapping: $current_mapping,
                    _remaining: descriptors,
                    #[cfg(test)]
                    drop_observer: None,
                })
            };
        }
        if let Err(error) = check_deadline(self.deadline) {
            fail!(error, None, None);
        }
        if descriptors.len() != self.entries.len() || !self.matches_manifest(manifest) {
            fail!(MemfdError::WrongProvenance, None, None);
        }
        #[cfg(test)]
        let mut advice_operation = 0_usize;
        for (expected, entry) in self
            .entries
            .into_iter()
            .zip(manifest.entries().iter().copied())
        {
            let fd = descriptors
                .next()
                .expect("validated descriptor count matches manifest");
            if let Err(error) = check_deadline(self.deadline) {
                fail!(error, Some(fd), None);
            }
            let mapped_len = match usize::try_from(entry.mapped_len) {
                Ok(mapped_len) => mapped_len,
                Err(_) => fail!(MemfdError::InvalidSize, Some(fd), None),
            };
            let (seals, protection) = match expected.writer {
                WriterEndpoint::Coordinator => (FINAL_SEALS, libc::PROT_READ),
                WriterEndpoint::Receiver => (PREFIX_SEALS, libc::PROT_READ | libc::PROT_WRITE),
            };
            let key = match validate_object(fd.as_raw_fd(), mapped_len, seals) {
                Ok(key) => key,
                Err(error) => fail!(error, Some(fd), None),
            };
            if imported.iter().any(|retained| retained.key() == key) {
                fail!(MemfdError::WrongObject, Some(fd), None);
            }
            if let Err(error) = check_deadline(self.deadline) {
                fail!(error, Some(fd), None);
            }
            // Imported views always take best-effort guard placement: the
            // wire manifest does not carry the creator's policy.
            let pending =
                match PendingVmMapping::map(fd.as_raw_fd(), mapped_len, protection, false, true) {
                    Ok(mapping) => mapping,
                    Err(error) => fail!(error, Some(fd), None),
                };
            if let Err(error) = check_deadline(self.deadline) {
                fail!(error, Some(fd), Some(pending));
            }
            for advice in [libc::MADV_DONTDUMP, libc::MADV_DONTFORK] {
                #[cfg(test)]
                {
                    advice_operation += 1;
                    if self.advice_failure_at == Some(advice_operation) {
                        fail!(MemfdError::Native(libc::EIO), Some(fd), Some(pending));
                    }
                }
                if let Err(error) = pending.advise(advice) {
                    fail!(error, Some(fd), Some(pending));
                }
                if let Err(error) = check_deadline(self.deadline) {
                    fail!(error, Some(fd), Some(pending));
                }
            }
            let mapping = match pending.into_mapping() {
                Ok(mapping) => mapping,
                Err((error, pending)) => fail!(error, Some(fd), Some(pending)),
            };
            let retained = match expected.writer {
                WriterEndpoint::Coordinator => LinuxImportedMixedDirectionEntry::CoordinatorWriter(
                    LinuxImportedCoordinatorWriterEntry {
                        manifest: entry,
                        fd,
                        mapping,
                        key,
                    },
                ),
                WriterEndpoint::Receiver => LinuxImportedMixedDirectionEntry::ReceiverWriter(
                    LinuxImportedReceiverWriterEntry {
                        manifest: entry,
                        fd,
                        mapping,
                        key,
                    },
                ),
            };
            imported.push(retained);
            if let Err(error) = check_deadline(self.deadline) {
                fail!(error, None, None);
            }
            let retained = imported.last().expect("current import is retained");
            match retained.validate(seals) {
                Ok(()) => {}
                Err(error) => fail!(error, None, None),
            }
        }
        if let Err(error) = check_deadline(self.deadline) {
            fail!(error, None, None);
        }
        Ok(LinuxImportedMixedDirectionBatch {
            entries: imported,
            #[cfg(test)]
            sealed_verified: false,
            #[cfg(test)]
            drop_observer: None,
            #[cfg(test)]
            active_drop_observer: None,
        })
    }

    #[cfg(test)]
    pub(crate) fn fail_advice_at_for_test(&mut self, operation: usize) {
        assert!(operation > 0);
        self.advice_failure_at = Some(operation);
    }
}

impl LinuxImportedMixedDirectionEntry {
    fn key(&self) -> ObjectKey {
        match self {
            Self::CoordinatorWriter(entry) => entry.key,
            Self::ReceiverWriter(entry) => entry.key,
        }
    }

    fn validate(&self, seals: libc::c_int) -> Result<(), MemfdError> {
        let (fd, key) = match self {
            Self::CoordinatorWriter(entry) => (&entry.fd, entry.key),
            Self::ReceiverWriter(entry) => (&entry.fd, entry.key),
        };
        if validate_object(fd.as_raw_fd(), key.mapped_len, seals)? != key {
            return Err(MemfdError::WrongObject);
        }
        Ok(())
    }
}

impl LinuxImportFailure {
    pub(crate) const fn error(&self) -> MemfdError {
        self.error
    }

    #[cfg(test)]
    pub(crate) fn observe_drop_for_test(&mut self, observer: Arc<Mutex<Vec<&'static str>>>) {
        self.drop_observer = Some(observer);
    }
}

impl core::fmt::Debug for LinuxReceiverWriterImportFailure {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("LinuxReceiverWriterImportFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl core::fmt::Debug for LinuxMixedDirectionImportFailure {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("LinuxMixedDirectionImportFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl LinuxReceiverWriterImportFailure {
    pub(crate) const fn error(&self) -> MemfdError {
        self.error
    }

    #[cfg(test)]
    pub(crate) fn observe_drop_for_test(&mut self, observer: Arc<Mutex<Vec<&'static str>>>) {
        self.drop_observer = Some(observer);
    }
}

impl LinuxMixedDirectionImportFailure {
    pub(crate) const fn error(&self) -> MemfdError {
        self.error
    }

    #[cfg(test)]
    pub(crate) fn observe_drop_for_test(&mut self, observer: Arc<Mutex<Vec<&'static str>>>) {
        self.drop_observer = Some(observer);
    }
}

impl Drop for LinuxImportFailure {
    fn drop(&mut self) {
        #[cfg(test)]
        if let Some(observer) = &self.drop_observer {
            observer.lock().unwrap().push("failed-import-drop");
        }
    }
}

impl Drop for LinuxReceiverWriterImportFailure {
    fn drop(&mut self) {
        #[cfg(test)]
        if let Some(observer) = &self.drop_observer {
            observer.lock().unwrap().push("failed-receiver-import-drop");
        }
    }
}

impl Drop for LinuxMixedDirectionImportFailure {
    fn drop(&mut self) {
        #[cfg(test)]
        if let Some(observer) = &self.drop_observer {
            observer.lock().unwrap().push("failed-mixed-import-drop");
        }
    }
}

impl LinuxImportedCoordinatorWriterBatch {
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    pub(crate) fn read_for_test(&self, ordinal: usize, offset: usize) -> u8 {
        let entry = &self.entries[ordinal];
        assert!(offset < entry.manifest.logical_len as usize);
        // SAFETY: the imported mapping is live and read-only for this access.
        unsafe { core::ptr::read_volatile(entry.mapping.base.as_ptr().add(offset)) }
    }

    #[cfg(test)]
    pub(crate) fn descriptor_for_test(&self, ordinal: usize) -> BorrowedFd<'_> {
        self.entries[ordinal].fd.as_fd()
    }

    #[cfg(test)]
    pub(crate) fn object_key_for_test(&self, ordinal: usize) -> (u64, u64, usize) {
        let key = self.entries[ordinal].key;
        (key.device, key.inode, key.mapped_len)
    }

    #[cfg(test)]
    pub(crate) fn observe_drop_for_test(&mut self, observer: Arc<Mutex<Vec<&'static str>>>) {
        self.drop_observer = Some(observer);
    }
}

impl LinuxImportedReceiverWriterBatch {
    pub(crate) fn verify_final_seals(
        &mut self,
        deadline: AbsoluteDeadline,
    ) -> Result<(), MemfdError> {
        check_deadline(deadline)?;
        for entry in &self.entries {
            if validate_object(entry.fd.as_raw_fd(), entry.key.mapped_len, FINAL_SEALS)?
                != entry.key
            {
                return Err(MemfdError::WrongObject);
            }
            check_deadline(deadline)?;
        }
        self.sealed_verified = true;
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    pub(crate) fn write_for_test(&mut self, ordinal: usize, offset: usize, value: u8) {
        assert!(self.sealed_verified);
        let entry = &mut self.entries[ordinal];
        assert!(offset < entry.manifest.logical_len as usize);
        // SAFETY: this retained mapping was established writable before final
        // future-write sealing and is the receiver's sole-writer view.
        unsafe { core::ptr::write_volatile(entry.mapping.base.as_ptr().add(offset), value) };
    }

    #[cfg(test)]
    pub(crate) fn descriptor_for_test(&self, ordinal: usize) -> BorrowedFd<'_> {
        self.entries[ordinal].fd.as_fd()
    }

    #[cfg(test)]
    pub(crate) fn observe_drop_for_test(&mut self, observer: Arc<Mutex<Vec<&'static str>>>) {
        self.drop_observer = Some(observer);
    }
}

impl LinuxImportedMixedDirectionBatch {
    pub(crate) fn verify_final_seals(
        &mut self,
        deadline: AbsoluteDeadline,
    ) -> Result<(), MemfdError> {
        check_deadline(deadline)?;
        for entry in &self.entries {
            entry.validate(FINAL_SEALS)?;
            check_deadline(deadline)?;
        }
        #[cfg(test)]
        {
            self.sealed_verified = true;
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    #[cfg(test)]
    pub(crate) fn read_coordinator_for_test(&self, ordinal: usize, offset: usize) -> u8 {
        assert!(self.sealed_verified);
        let LinuxImportedMixedDirectionEntry::CoordinatorWriter(entry) = &self.entries[ordinal]
        else {
            panic!("test read requires a coordinator-writer entry");
        };
        assert!(offset < entry.manifest.logical_len as usize);
        // SAFETY: the final-sealed imported mapping remains mixed-batch-owned.
        unsafe { core::ptr::read_volatile(entry.mapping.base.as_ptr().add(offset)) }
    }

    #[cfg(test)]
    pub(crate) fn write_receiver_for_test(&mut self, ordinal: usize, offset: usize, value: u8) {
        assert!(self.sealed_verified);
        let LinuxImportedMixedDirectionEntry::ReceiverWriter(entry) = &mut self.entries[ordinal]
        else {
            panic!("test write requires a receiver-writer entry");
        };
        assert!(offset < entry.manifest.logical_len as usize);
        // SAFETY: this mapping was established writable before final sealing
        // and remains the receiver's transaction-owned sole-writer view.
        unsafe { core::ptr::write_volatile(entry.mapping.base.as_ptr().add(offset), value) };
    }

    #[cfg(test)]
    pub(crate) fn descriptor_for_test(&self, ordinal: usize) -> BorrowedFd<'_> {
        match &self.entries[ordinal] {
            LinuxImportedMixedDirectionEntry::CoordinatorWriter(entry) => entry.fd.as_fd(),
            LinuxImportedMixedDirectionEntry::ReceiverWriter(entry) => entry.fd.as_fd(),
        }
    }

    #[cfg(test)]
    pub(crate) fn observe_drop_for_test(&mut self, observer: Arc<Mutex<Vec<&'static str>>>) {
        self.drop_observer = Some(observer);
    }

    #[cfg(test)]
    pub(crate) fn observe_active_drop_for_test(&mut self, observer: Arc<Mutex<Vec<&'static str>>>) {
        self.active_drop_observer = Some(observer);
    }
}

impl LinuxActiveRegionOwner {
    pub(crate) const fn spec(&self) -> LinuxActiveRegionSpec {
        match self {
            Self::Reader { spec, .. } | Self::Writer { spec, .. } => *spec,
        }
    }
}

impl LinuxMixedDirectionBatch {
    pub(crate) fn activation_specs(&self) -> Result<Vec<LinuxActiveRegionSpec>, MemfdError> {
        check_deadline(self.deadline)?;
        let mut specs = Vec::with_capacity(self.entries.len());
        for entry in &self.entries {
            let spec = match entry {
                LinuxMixedDirectionEntry::CoordinatorWriter(batch) => {
                    if batch.entries.len() != 1 {
                        return Err(MemfdError::WrongProvenance);
                    }
                    let entry = &batch.entries[0];
                    entry.prepared.revalidate(self.deadline)?;
                    native_active_spec(
                        entry.native,
                        0,
                        LocalRegionAuthority::Writer,
                        &entry.prepared.mapping,
                        entry.guard_requested,
                    )?
                }
                LinuxMixedDirectionEntry::ReceiverWriter(batch) => {
                    if batch.entries.len() != 1 {
                        return Err(MemfdError::WrongProvenance);
                    }
                    let entry = &batch.entries[0];
                    if entry.pending_mapping.is_some()
                        || validate_object(entry.fd.as_raw_fd(), entry.key.mapped_len, FINAL_SEALS)?
                            != entry.key
                    {
                        return Err(MemfdError::WrongObject);
                    }
                    let mapping = entry.mapping.as_ref().ok_or(MemfdError::WrongObject)?;
                    native_active_spec(
                        entry.native,
                        1,
                        LocalRegionAuthority::Reader,
                        mapping,
                        entry.guard_requested,
                    )?
                }
            };
            specs.push(spec);
            check_deadline(self.deadline)?;
        }
        validate_active_specs(&specs)?;
        Ok(specs)
    }

    pub(crate) fn into_active_region_owners(
        mut self,
        page_size: usize,
    ) -> Vec<LinuxActiveRegionOwner> {
        #[cfg(test)]
        let drop_observer = self.active_drop_observer.clone();
        let entries = core::mem::take(&mut self.entries);
        let mut active = Vec::with_capacity(entries.len());
        for entry in entries {
            match entry {
                LinuxMixedDirectionEntry::CoordinatorWriter(mut batch) => {
                    let entries = core::mem::take(&mut batch.entries);
                    assert_eq!(entries.len(), 1, "activation preflight fixed the batch");
                    let entry = entries
                        .into_iter()
                        .next()
                        .expect("validated single coordinator-writer entry");
                    let CoordinatorWriterPrepared {
                        fd,
                        mapping,
                        reader_capability,
                        key: _,
                        not_sync: _,
                    } = entry.prepared;
                    drop(reader_capability);
                    let spec = native_active_spec(
                        entry.native,
                        0,
                        LocalRegionAuthority::Writer,
                        &mapping,
                        entry.guard_requested,
                    )
                    .expect("activation preflight validated coordinator-writer metadata");
                    active.push(LinuxActiveRegionOwner::Writer {
                        spec,
                        owner: Box::new(LinuxActiveWriteMapping {
                            mapping: Some(mapping),
                            _fd: fd,
                            page_size,
                            _not_sync: PhantomData,
                            #[cfg(test)]
                            drop_observer: drop_observer.clone(),
                        }),
                    });
                }
                LinuxMixedDirectionEntry::ReceiverWriter(mut batch) => {
                    let entries = core::mem::take(&mut batch.entries);
                    assert_eq!(entries.len(), 1, "activation preflight fixed the batch");
                    let mut entry = entries
                        .into_iter()
                        .next()
                        .expect("validated single receiver-writer entry");
                    assert!(
                        entry.pending_mapping.is_none(),
                        "activation preflight rejected a pending mapping"
                    );
                    let mapping = entry
                        .mapping
                        .take()
                        .expect("activation preflight retained the final mapping");
                    let spec = native_active_spec(
                        entry.native,
                        1,
                        LocalRegionAuthority::Reader,
                        &mapping,
                        entry.guard_requested,
                    )
                    .expect("activation preflight validated receiver-writer metadata");
                    active.push(LinuxActiveRegionOwner::Reader {
                        spec,
                        owner: Box::new(LinuxActiveReadMapping {
                            mapping: Some(mapping),
                            _fd: entry.fd,
                            page_size,
                            #[cfg(test)]
                            drop_observer: drop_observer.clone(),
                        }),
                    });
                }
            }
        }
        active
    }
}

impl LinuxImportedMixedDirectionBatch {
    pub(crate) fn activation_specs(
        &self,
        deadline: AbsoluteDeadline,
    ) -> Result<Vec<LinuxActiveRegionSpec>, MemfdError> {
        check_deadline(deadline)?;
        #[cfg(test)]
        if !self.sealed_verified {
            return Err(MemfdError::WrongObject);
        }
        let mut specs = Vec::with_capacity(self.entries.len());
        for (ordinal, entry) in self.entries.iter().enumerate() {
            entry.validate(FINAL_SEALS)?;
            let spec = match entry {
                LinuxImportedMixedDirectionEntry::CoordinatorWriter(entry) => {
                    if entry.manifest.ordinal as usize != ordinal
                        || entry.manifest.writer != 0
                        || entry.manifest.access != PeerAccess::ReadOnly
                    {
                        return Err(MemfdError::WrongProvenance);
                    }
                    manifest_active_spec(
                        entry.manifest,
                        LocalRegionAuthority::Reader,
                        &entry.mapping,
                    )?
                }
                LinuxImportedMixedDirectionEntry::ReceiverWriter(entry) => {
                    if entry.manifest.ordinal as usize != ordinal
                        || entry.manifest.writer != 1
                        || entry.manifest.access != PeerAccess::SoleWriter
                    {
                        return Err(MemfdError::WrongProvenance);
                    }
                    manifest_active_spec(
                        entry.manifest,
                        LocalRegionAuthority::Writer,
                        &entry.mapping,
                    )?
                }
            };
            specs.push(spec);
            check_deadline(deadline)?;
        }
        validate_active_specs(&specs)?;
        Ok(specs)
    }

    pub(crate) fn into_active_region_owners(
        mut self,
        page_size: usize,
    ) -> Vec<LinuxActiveRegionOwner> {
        #[cfg(test)]
        let drop_observer = self.active_drop_observer.clone();
        let entries = core::mem::take(&mut self.entries);
        let mut active = Vec::with_capacity(entries.len());
        for entry in entries {
            match entry {
                LinuxImportedMixedDirectionEntry::CoordinatorWriter(entry) => {
                    let spec = manifest_active_spec(
                        entry.manifest,
                        LocalRegionAuthority::Reader,
                        &entry.mapping,
                    )
                    .expect("activation preflight validated imported reader metadata");
                    active.push(LinuxActiveRegionOwner::Reader {
                        spec,
                        owner: Box::new(LinuxActiveReadMapping {
                            mapping: Some(entry.mapping),
                            _fd: entry.fd,
                            page_size,
                            #[cfg(test)]
                            drop_observer: drop_observer.clone(),
                        }),
                    });
                }
                LinuxImportedMixedDirectionEntry::ReceiverWriter(entry) => {
                    let spec = manifest_active_spec(
                        entry.manifest,
                        LocalRegionAuthority::Writer,
                        &entry.mapping,
                    )
                    .expect("activation preflight validated imported writer metadata");
                    active.push(LinuxActiveRegionOwner::Writer {
                        spec,
                        owner: Box::new(LinuxActiveWriteMapping {
                            mapping: Some(entry.mapping),
                            _fd: entry.fd,
                            page_size,
                            _not_sync: PhantomData,
                            #[cfg(test)]
                            drop_observer: drop_observer.clone(),
                        }),
                    });
                }
            }
        }
        active
    }
}

impl Drop for LinuxImportedCoordinatorWriterBatch {
    fn drop(&mut self) {
        #[cfg(test)]
        if let Some(observer) = &self.drop_observer {
            observer.lock().unwrap().push("imported-batch-drop");
        }
    }
}

impl Drop for LinuxImportedReceiverWriterBatch {
    fn drop(&mut self) {
        #[cfg(test)]
        if let Some(observer) = &self.drop_observer {
            observer
                .lock()
                .unwrap()
                .push("imported-receiver-batch-drop");
        }
    }
}

impl Drop for LinuxImportedMixedDirectionBatch {
    fn drop(&mut self) {
        #[cfg(test)]
        if let Some(observer) = &self.drop_observer {
            observer.lock().unwrap().push("imported-mixed-batch-drop");
        }
    }
}

impl Drop for LinuxCoordinatorWriterBatch {
    fn drop(&mut self) {
        #[cfg(test)]
        if let Some(observer) = &self.drop_observer {
            observer.lock().unwrap().push("native-batch-drop");
        }
    }
}

impl Drop for LinuxReceiverWriterBatch {
    fn drop(&mut self) {
        #[cfg(test)]
        if let Some(observer) = &self.drop_observer {
            observer.lock().unwrap().push("receiver-writer-batch-drop");
        }
    }
}

impl Drop for LinuxMixedDirectionBatch {
    fn drop(&mut self) {
        #[cfg(test)]
        if let Some(observer) = &self.drop_observer {
            observer.lock().unwrap().push("mixed-direction-batch-drop");
        }
    }
}

impl ReceiverWriterPrepared {
    fn export_writer(self) -> Result<(ReceiverWriterCapabilitySent, OwnedFd), MemfdError> {
        let capability = duplicate(&self.fd)?;
        Ok((
            ReceiverWriterCapabilitySent {
                fd: self.fd,
                key: self.key,
                binding: self.binding,
                not_sync: PhantomData,
            },
            capability,
        ))
    }
}

impl ReceiverWriterCapabilitySent {
    fn seal_after_import(
        self,
        receipt: PeerWriterImportedReceipt,
    ) -> Result<CoordinatorReaderPrepared, MemfdError> {
        if receipt.key != self.key {
            return Err(MemfdError::WrongObject);
        }
        if receipt.binding != self.binding {
            return Err(MemfdError::WrongProvenance);
        }
        validate_object(self.fd.as_raw_fd(), self.key.mapped_len, PREFIX_SEALS)?;
        add_seals(
            self.fd.as_raw_fd(),
            libc::F_SEAL_FUTURE_WRITE | libc::F_SEAL_SEAL,
        )?;
        validate_object(self.fd.as_raw_fd(), self.key.mapped_len, FINAL_SEALS)?;
        let mapping = VmMapping::map(self.fd.as_raw_fd(), self.key.mapped_len, libc::PROT_READ)?;
        Ok(CoordinatorReaderPrepared {
            fd: self.fd,
            mapping,
            not_sync: PhantomData,
        })
    }
}

impl ImportedPeerWriter {
    fn import(
        fd: OwnedFd,
        mapped_len: usize,
        binding: TransferBinding,
    ) -> Result<Self, MemfdError> {
        let key = validate_object(fd.as_raw_fd(), mapped_len, PREFIX_SEALS)?;
        let mapping = VmMapping::map(
            fd.as_raw_fd(),
            mapped_len,
            libc::PROT_READ | libc::PROT_WRITE,
        )?;
        Ok(Self {
            fd,
            mapping,
            key,
            receipt_available: true,
            sealed_verified: false,
            binding,
            not_sync: PhantomData,
        })
    }

    fn take_imported_receipt(&mut self) -> Option<PeerWriterImportedReceipt> {
        if self.receipt_available {
            self.receipt_available = false;
            Some(PeerWriterImportedReceipt {
                key: self.key,
                binding: self.binding,
                not_sync: PhantomData,
            })
        } else {
            None
        }
    }

    fn verify_sealed(&mut self) -> Result<(), MemfdError> {
        validate_object(self.fd.as_raw_fd(), self.mapping.len, FINAL_SEALS)?;
        self.sealed_verified = true;
        Ok(())
    }

    fn write_volatile(&mut self, offset: usize, value: u8) {
        assert!(self.sealed_verified && offset < self.mapping.len);
        // SAFETY: the receiver established this writable view before FUTURE_WRITE.
        unsafe { core::ptr::write_volatile(self.mapping.base.as_ptr().add(offset), value) };
    }
}

impl CoordinatorReaderPrepared {
    fn read_volatile(&self, offset: usize) -> u8 {
        assert!(offset < self.mapping.len);
        // SAFETY: the coordinator mapping is read-only and the address is live.
        unsafe { core::ptr::read_volatile(self.mapping.base.as_ptr().add(offset)) }
    }
}

impl VmMapping {
    fn map(fd: RawFd, len: usize, protection: libc::c_int) -> Result<Self, MemfdError> {
        Self::map_with_clear(fd, len, protection, false, true)
    }

    fn map_with_clear(
        fd: RawFd,
        len: usize,
        protection: libc::c_int,
        clear_on_drop: bool,
        guard: bool,
    ) -> Result<Self, MemfdError> {
        let pending = PendingVmMapping::map(fd, len, protection, clear_on_drop, guard)?;
        for advice in [libc::MADV_DONTDUMP, libc::MADV_DONTFORK] {
            pending.advise(advice)?;
        }
        pending.into_mapping().map_err(|(error, _mapping)| error)
    }

    fn unmap(self) -> Result<(), MemfdError> {
        // SAFETY: this value uniquely owns this exact local reservation, which
        // covers the interior view and, when guarded, both bands.
        if unsafe { libc::munmap(self.reservation_base, self.reservation_len) } != 0 {
            return Err(last_native());
        }
        // Successful munmap discharged the destructor's native obligation.
        forget(self);
        Ok(())
    }
}

impl PendingVmMapping {
    fn map(
        fd: RawFd,
        len: usize,
        protection: libc::c_int,
        clear_on_drop: bool,
        guard: bool,
    ) -> Result<Self, MemfdError> {
        if guard && let Some(guarded) = Self::map_guarded(fd, len, protection, clear_on_drop) {
            return Ok(guarded);
        }
        // SAFETY: arguments describe a checked shared memfd range.
        let base = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                len,
                protection,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        if base == libc::MAP_FAILED {
            return Err(last_native());
        }
        Ok(Self {
            base,
            len,
            clear_on_drop,
            reservation_base: base,
            reservation_len: len,
            guarded: false,
        })
    }

    /// Best-effort guarded placement: an inaccessible anonymous reservation of
    /// one page, the view, and one page, with the shared view carved into the
    /// middle by `MAP_FIXED`. Any failure returns `None` so the caller falls
    /// back to the plain unguarded path with its original error semantics.
    fn map_guarded(
        fd: RawFd,
        len: usize,
        protection: libc::c_int,
        clear_on_drop: bool,
    ) -> Option<Self> {
        let page = native_page_size().ok()?;
        if len == 0 || !len.is_multiple_of(page) {
            return None;
        }
        let total = len.checked_add(page.checked_mul(2)?)?;
        if total > isize::MAX as usize {
            return None;
        }
        // SAFETY: a fresh inaccessible anonymous reservation of checked length.
        let reservation = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                total,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
                -1,
                0,
            )
        };
        if reservation == libc::MAP_FAILED {
            return None;
        }
        // SAFETY: the carve target lies wholly inside the owned reservation,
        // one page in from each end, so `MAP_FIXED` replaces only owned pages.
        let interior = unsafe {
            libc::mmap(
                reservation.cast::<u8>().add(page).cast(),
                len,
                protection,
                libc::MAP_SHARED | libc::MAP_FIXED,
                fd,
                0,
            )
        };
        if interior == libc::MAP_FAILED {
            // SAFETY: the failed carve leaves the whole reservation owned here.
            let _ = unsafe { libc::munmap(reservation, total) };
            return None;
        }
        Some(Self {
            base: interior,
            len,
            clear_on_drop,
            reservation_base: reservation,
            reservation_len: total,
            guarded: true,
        })
    }

    fn advise(&self, advice: libc::c_int) -> Result<(), MemfdError> {
        // SAFETY: advice applies to the complete live interior view only,
        // never to the inaccessible bands around it.
        if unsafe { libc::madvise(self.base, self.len, advice) } != 0 {
            return Err(last_native());
        }
        Ok(())
    }

    fn into_mapping(self) -> Result<VmMapping, (MemfdError, Self)> {
        let Some(base) = NonNull::new(self.base.cast()) else {
            return Err((MemfdError::InvalidObject, self));
        };
        let mapping = VmMapping {
            base,
            len: self.len,
            clear_on_drop: self.clear_on_drop,
            reservation_base: self.reservation_base,
            reservation_len: self.reservation_len,
            guarded: self.guarded,
        };
        forget(self);
        Ok(mapping)
    }
}

fn reject_unsupported_linux_nx() -> Result<(), MemfdError> {
    Err(MemfdError::ExecutableAuthorityUnsupported)
}

impl Drop for VmMapping {
    fn drop(&mut self) {
        if self.clear_on_drop {
            for offset in 0..self.len {
                // SAFETY: this mapping is writable and uniquely owned by the
                // pending coordinator typestate until destruction. Clearing
                // touches only the interior view, never the bands.
                unsafe { core::ptr::write_volatile(self.base.as_ptr().add(offset), 0) };
            }
            compiler_fence(Ordering::SeqCst);
        }
        // SAFETY: this value uniquely owns this local reservation, which is
        // exactly the interior view when unguarded and additionally covers
        // both bands when guarded.
        let _ = unsafe { libc::munmap(self.reservation_base, self.reservation_len) };
    }
}

impl Drop for PendingVmMapping {
    fn drop(&mut self) {
        if self.clear_on_drop && !self.base.is_null() {
            // A null mapping is rejected before it can be used as a Rust byte
            // range. It remains owned for munmap, but must not be dereferenced.
            for offset in 0..self.len {
                // SAFETY: a non-null pending writable mapping covers this range.
                unsafe { core::ptr::write_volatile(self.base.cast::<u8>().add(offset), 0) };
            }
            compiler_fence(Ordering::SeqCst);
        }
        // SAFETY: this owner uniquely retains the successful mmap result,
        // including the address-zero case; the reservation covers the interior
        // view and, when guarded, both bands.
        let _ = unsafe { libc::munmap(self.reservation_base, self.reservation_len) };
    }
}

fn add_seals(fd: RawFd, seals: libc::c_int) -> Result<(), MemfdError> {
    // SAFETY: descriptor is live and seal mask contains Linux UAPI bits.
    if unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) } < 0 {
        return Err(last_native());
    }
    Ok(())
}

fn validate_object(
    fd: RawFd,
    mapped_len: usize,
    expected_seals: libc::c_int,
) -> Result<ObjectKey, MemfdError> {
    // SAFETY: output structures are valid for the live descriptor.
    let mut stat: libc::stat = unsafe { zeroed() };
    if unsafe { libc::fstat(fd, &mut stat) } != 0 {
        return Err(last_native());
    }
    // SAFETY: output structure is valid for the live descriptor.
    let mut statfs: libc::statfs = unsafe { zeroed() };
    if unsafe { libc::fstatfs(fd, &mut statfs) } != 0 {
        return Err(last_native());
    }
    // SAFETY: scalar fcntl queries have no pointer arguments.
    let seals = unsafe { libc::fcntl(fd, libc::F_GET_SEALS) };
    // SAFETY: scalar fcntl queries have no pointer arguments.
    let status = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if seals != expected_seals
        || status < 0
        || status & libc::O_ACCMODE != libc::O_RDWR
        || stat.st_size != mapped_len as libc::off_t
        || stat.st_nlink != 0
        || stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || stat.st_mode & 0o111 != 0
        || statfs.f_type != TMPFS_MAGIC
    {
        return Err(MemfdError::InvalidObject);
    }
    Ok(ObjectKey {
        device: stat.st_dev,
        inode: stat.st_ino,
        mapped_len,
    })
}

fn duplicate(fd: &OwnedFd) -> Result<OwnedFd, MemfdError> {
    // SAFETY: descriptor is live and F_DUPFD_CLOEXEC returns a new fd.
    let raw = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if raw < 0 {
        return Err(last_native());
    }
    // SAFETY: successful duplication returned a new owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

fn native_active_spec(
    native: NativeRegionSpec,
    expected_writer: u32,
    authority: LocalRegionAuthority,
    mapping: &VmMapping,
    guard_requested: GuardPolicy,
) -> Result<LinuxActiveRegionSpec, MemfdError> {
    if native.writer != expected_writer {
        return Err(MemfdError::WrongProvenance);
    }
    active_region_spec(
        native.region_id,
        authority,
        native.logical_len,
        native.mapped_len,
        mapping,
        guard_requested,
    )
}

fn manifest_active_spec(
    manifest: ManifestEntry,
    authority: LocalRegionAuthority,
    mapping: &VmMapping,
) -> Result<LinuxActiveRegionSpec, MemfdError> {
    // Imported regions apply best-effort guard placement: the wire manifest
    // does not carry the creator's requested policy.
    active_region_spec(
        manifest.region_id,
        authority,
        manifest.logical_len,
        manifest.mapped_len,
        mapping,
        GuardPolicy::BestEffort,
    )
}

fn active_region_spec(
    region_id: u128,
    authority: LocalRegionAuthority,
    logical_len: u64,
    mapped_len: u64,
    mapping: &VmMapping,
    guard_requested: GuardPolicy,
) -> Result<LinuxActiveRegionSpec, MemfdError> {
    let id = RegionId::new(region_id).ok_or(MemfdError::WrongProvenance)?;
    let logical_len = usize::try_from(logical_len).map_err(|_| MemfdError::InvalidSize)?;
    let native_mapped_len = usize::try_from(mapped_len).map_err(|_| MemfdError::InvalidSize)?;
    if logical_len == 0 || logical_len > native_mapped_len || mapping.len != native_mapped_len {
        return Err(MemfdError::WrongObject);
    }
    Ok(LinuxActiveRegionSpec {
        id,
        authority,
        logical_len,
        mapped_len,
        guard_requested,
    })
}

fn validate_active_specs(specs: &[LinuxActiveRegionSpec]) -> Result<(), MemfdError> {
    if specs.is_empty() || specs.len() > 16 || specs.windows(2).any(|pair| pair[0].id >= pair[1].id)
    {
        return Err(MemfdError::WrongProvenance);
    }
    Ok(())
}

pub(crate) fn native_page_size() -> Result<usize, MemfdError> {
    // SAFETY: sysconf has no pointer arguments.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    let page = usize::try_from(page)
        .ok()
        .filter(|page| page.is_power_of_two())
        .ok_or_else(last_native)?;
    Ok(page)
}

fn page_align(size: usize) -> Result<usize, MemfdError> {
    if size == 0 {
        return Err(MemfdError::InvalidSize);
    }
    let page = native_page_size()?;
    size.checked_add(page - 1)
        .map(|value| value & !(page - 1))
        .filter(|value| *value <= libc::off_t::MAX as usize && *value <= isize::MAX as usize)
        .ok_or(MemfdError::InvalidSize)
}

fn last_native() -> MemfdError {
    MemfdError::Native(io::Error::last_os_error().raw_os_error().unwrap_or(-1))
}

fn check_deadline(deadline: AbsoluteDeadline) -> Result<(), MemfdError> {
    if deadline.is_expired() {
        Err(MemfdError::DeadlineExpired)
    } else {
        Ok(())
    }
}

#[cfg(test)]
#[path = "memory_test.rs"]
mod tests;
