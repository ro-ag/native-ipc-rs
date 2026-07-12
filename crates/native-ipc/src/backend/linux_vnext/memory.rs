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
use crate::batch::TransferBatch;
use crate::memory::CleanupPolicy;
use crate::protocol::{ManifestEntry, NativeAuthorityProfile, NativeRegionSpec, PeerAccess};
use crate::region::WriterEndpoint;
use crate::session::AbsoluteDeadline;

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

pub(crate) struct LinuxCoordinatorWriterBatch {
    entries: Vec<LinuxCoordinatorWriterEntry>,
    deadline: AbsoluteDeadline,
    #[cfg(test)]
    drop_observer: Option<Arc<Mutex<Vec<&'static str>>>>,
    #[cfg(test)]
    revalidation_fault: bool,
}

struct LinuxCoordinatorWriterEntry {
    native: NativeRegionSpec,
    prepared: CoordinatorWriterPrepared,
}

// SAFETY: VmMapping uniquely owns one local VM range. Moving that owner to a
// different thread neither duplicates the mapping nor creates Rust references.
unsafe impl Send for VmMapping {}

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
        // SAFETY: arguments describe a checked shared memfd range.
        let pointer = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                len,
                protection,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        if pointer == libc::MAP_FAILED {
            return Err(last_native());
        }
        let base = NonNull::new(pointer.cast()).ok_or(MemfdError::InvalidObject)?;
        let mapping = Self {
            base,
            len,
            clear_on_drop,
        };
        for advice in [libc::MADV_DONTDUMP, libc::MADV_DONTFORK] {
            // SAFETY: the complete mapping remains live for this call.
            if unsafe { libc::madvise(mapping.base.as_ptr().cast(), mapping.len, advice) } != 0 {
                return Err(last_native());
            }
        }
        Ok(mapping)
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
