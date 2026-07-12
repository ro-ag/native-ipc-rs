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

use crate::backend::linux::QuiescentRegion;
use crate::batch::{ExpectedBatch, TransferBatch};
use crate::memory::CleanupPolicy;
use crate::protocol::{
    ManifestEntry, NativeAuthorityProfile, NativeRegionSpec, PeerAccess, TransferManifest,
};
use crate::region::WriterEndpoint;
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

struct VmMapping {
    base: NonNull<u8>,
    len: usize,
    clear_on_drop: bool,
}

/// Owns a successful `mmap` before the address has been validated and the
/// fallible mapping advice has completed.
struct PendingVmMapping {
    base: *mut libc::c_void,
    len: usize,
    clear_on_drop: bool,
}

pub(crate) struct LinuxCoordinatorWriterBatch {
    entries: Vec<LinuxCoordinatorWriterEntry>,
    deadline: AbsoluteDeadline,
    #[cfg(test)]
    drop_observer: Option<Arc<Mutex<Vec<&'static str>>>>,
    #[cfg(test)]
    revalidation_fault: bool,
}

pub(crate) struct LinuxExpectedCoordinatorWriterBatch {
    entries: Vec<LinuxExpectedCoordinatorWriterEntry>,
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

pub(crate) struct LinuxImportedCoordinatorWriterBatch {
    entries: Vec<LinuxImportedCoordinatorWriterEntry>,
    #[cfg(test)]
    drop_observer: Option<Arc<Mutex<Vec<&'static str>>>>,
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

struct LinuxCoordinatorWriterEntry {
    native: NativeRegionSpec,
    prepared: CoordinatorWriterPrepared,
}

// SAFETY: VmMapping uniquely owns one local VM range. Moving that owner to a
// different thread neither duplicates the mapping nor creates Rust references.
unsafe impl Send for VmMapping {}

// SAFETY: PendingVmMapping uniquely owns one local VM range. Moving that owner
// neither duplicates the mapping nor creates Rust references to its address.
unsafe impl Send for PendingVmMapping {}

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
    ) -> Result<Self, MemfdError> {
        check_deadline(deadline)?;
        let logical_len = region.logical_len();
        let mapped_len = region.len();
        let mapping = match VmMapping::map_with_clear(
            region.as_raw_fd_for_vnext(),
            mapped_len,
            libc::PROT_READ | libc::PROT_WRITE,
            cleanup == CleanupPolicy::ClearThenRelease,
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
            let (request, spec, _) = region.into_linux_transfer_parts();
            if spec.writer != WriterEndpoint::Coordinator {
                return Err(MemfdError::UnsupportedDirection);
            }
            let native = request
                .native_spec(spec.id.get())
                .ok_or(MemfdError::InvalidBatch)?;
            let (region, cleanup) = request.into_linux_quiescent();
            let prepared = PrivateMemfd::from_quiescent(region, cleanup, deadline)?
                .prepare_coordinator_writer_for_batch(deadline)?;
            entries.push(LinuxCoordinatorWriterEntry { native, prepared });
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
            let pending =
                match PendingVmMapping::map(fd.as_raw_fd(), mapped_len, libc::PROT_READ, false) {
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

impl LinuxImportFailure {
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

impl Drop for LinuxImportedCoordinatorWriterBatch {
    fn drop(&mut self) {
        #[cfg(test)]
        if let Some(observer) = &self.drop_observer {
            observer.lock().unwrap().push("imported-batch-drop");
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
        Self::map_with_clear(fd, len, protection, false)
    }

    fn map_with_clear(
        fd: RawFd,
        len: usize,
        protection: libc::c_int,
        clear_on_drop: bool,
    ) -> Result<Self, MemfdError> {
        let pending = PendingVmMapping::map(fd, len, protection, clear_on_drop)?;
        for advice in [libc::MADV_DONTDUMP, libc::MADV_DONTFORK] {
            pending.advise(advice)?;
        }
        pending.into_mapping().map_err(|(error, _mapping)| error)
    }

    fn unmap(self) -> Result<(), MemfdError> {
        // SAFETY: this value uniquely owns this exact local mapping.
        if unsafe { libc::munmap(self.base.as_ptr().cast(), self.len) } != 0 {
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
    ) -> Result<Self, MemfdError> {
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
        })
    }

    fn advise(&self, advice: libc::c_int) -> Result<(), MemfdError> {
        // SAFETY: this owner retains the complete live mapping for the call.
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
                // pending coordinator typestate until destruction.
                unsafe { core::ptr::write_volatile(self.base.as_ptr().add(offset), 0) };
            }
            compiler_fence(Ordering::SeqCst);
        }
        // SAFETY: this value uniquely owns this local mapping.
        let _ = unsafe { libc::munmap(self.base.as_ptr().cast(), self.len) };
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
        // including the address-zero case.
        let _ = unsafe { libc::munmap(self.base, self.len) };
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

fn page_align(size: usize) -> Result<usize, MemfdError> {
    if size == 0 {
        return Err(MemfdError::InvalidSize);
    }
    // SAFETY: sysconf has no pointer arguments.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page <= 0 {
        return Err(last_native());
    }
    let page = page as usize;
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
