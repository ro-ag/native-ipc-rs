//! Linux 6.3+ non-executable memfd direction preparation.

use core::cell::Cell;
use core::marker::PhantomData;
use core::mem::{forget, zeroed};
use core::ptr::NonNull;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

const MFD_NOEXEC_SEAL: libc::c_uint = 0x0008;
const F_SEAL_EXEC: libc::c_int = 0x0020;
const PREFIX_SEALS: libc::c_int = F_SEAL_EXEC | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK;
const FINAL_SEALS: libc::c_int = PREFIX_SEALS | libc::F_SEAL_FUTURE_WRITE | libc::F_SEAL_SEAL;
const TMPFS_MAGIC: libc::c_long = 0x0102_1994;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MemfdError {
    InvalidSize,
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

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NxProbeFacts {
    new_executable_mapping_denied: bool,
    existing_mapping_upgrade_denied: bool,
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

    #[cfg(test)]
    fn prepare_coordinator_writer_for_ordering_test(
        self,
    ) -> Result<CoordinatorWriterPrepared, MemfdError> {
        self.prepare_coordinator_writer_after_nx()
    }

    fn prepare_coordinator_writer_after_nx(
        mut self,
    ) -> Result<CoordinatorWriterPrepared, MemfdError> {
        add_seals(self.fd.as_raw_fd(), FINAL_SEALS & !F_SEAL_EXEC)?;
        let mapping = self.mapping.take().expect("private mapping is live");
        validate_object(self.fd.as_raw_fd(), mapping.len, FINAL_SEALS)?;
        let reader_capability = duplicate(&self.fd)?;
        Ok(CoordinatorWriterPrepared {
            fd: self.fd,
            mapping,
            reader_capability,
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

    #[cfg(test)]
    fn prepare_receiver_writer_for_ordering_test(
        self,
        binding: TransferBinding,
    ) -> Result<ReceiverWriterPrepared, MemfdError> {
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
        self.mapping
            .take()
            .expect("private mapping is live")
            .unmap()?;
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
        let mapping = Self { base, len };
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

#[cfg(test)]
fn probe_kernel_nx(fd: RawFd, mapping: &VmMapping) -> Result<NxProbeFacts, MemfdError> {
    // This function may run only in the isolated disposable helper below.
    // VmMapping owns any executable alias; process teardown is the final
    // containment backstop if explicit cleanup or restoration fails.
    let new_executable_mapping_denied =
        match VmMapping::map(fd, mapping.len, libc::PROT_READ | libc::PROT_EXEC) {
            Ok(executable) => {
                drop(executable);
                false
            }
            Err(MemfdError::Native(libc::EACCES)) | Err(MemfdError::Native(libc::EPERM)) => true,
            Err(error) => return Err(error),
        };

    // SAFETY: this mapping is still private; a successful protection probe is
    // restored to RW before facts or errors escape.
    let upgraded = unsafe {
        libc::mprotect(
            mapping.base.as_ptr().cast(),
            mapping.len,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
        )
    };
    let existing_mapping_upgrade_denied = upgraded != 0;
    if existing_mapping_upgrade_denied
        && !matches!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::EACCES) | Some(libc::EPERM)
        )
    {
        return Err(last_native());
    }
    if !existing_mapping_upgrade_denied {
        // SAFETY: same live range; restoration removes execute again.
        if unsafe {
            libc::mprotect(
                mapping.base.as_ptr().cast(),
                mapping.len,
                libc::PROT_READ | libc::PROT_WRITE,
            )
        } != 0
        {
            return Err(last_native());
        }
    }
    Ok(NxProbeFacts {
        new_executable_mapping_denied,
        existing_mapping_upgrade_denied,
    })
}

impl Drop for VmMapping {
    fn drop(&mut self) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::{assert_impl_all, assert_not_impl_any};
    use std::process::Command;

    assert_impl_all!(PrivateMemfd: Send);
    assert_not_impl_any!(PrivateMemfd: Sync, Clone);
    assert_impl_all!(CoordinatorWriterPrepared: Send);
    assert_not_impl_any!(CoordinatorWriterPrepared: Sync, Clone);
    assert_impl_all!(ReceiverWriterPrepared: Send);
    assert_not_impl_any!(ReceiverWriterPrepared: Sync, Clone);
    assert_impl_all!(ReceiverWriterCapabilitySent: Send);
    assert_not_impl_any!(ReceiverWriterCapabilitySent: Sync, Clone);
    assert_impl_all!(ImportedPeerWriter: Send);
    assert_not_impl_any!(ImportedPeerWriter: Sync, Clone);
    assert_impl_all!(PeerWriterImportedReceipt: Send);
    assert_not_impl_any!(PeerWriterImportedReceipt: Sync, Clone);
    assert_impl_all!(CoordinatorReaderPrepared: Send);
    assert_not_impl_any!(CoordinatorReaderPrepared: Sync, Clone);

    fn binding(seed: u8) -> TransferBinding {
        TransferBinding::new(
            [seed; 32],
            u64::from(seed),
            u128::from(seed),
            [seed; 16],
            u16::from(seed % 16),
            [seed.wrapping_add(1); 32],
        )
        .unwrap()
    }

    fn mapping_fails(fd: RawFd, protection: libc::c_int, len: usize) -> bool {
        // SAFETY: arguments describe the live memfd range under test.
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
            true
        } else {
            // SAFETY: successful mmap returned this exact live range.
            let _ = unsafe { libc::munmap(pointer, len) };
            false
        }
    }

    #[test]
    fn coordinator_writer_ordering_keeps_preseal_writer_and_exports_reader() {
        let mut private = PrivateMemfd::new(37).unwrap();
        private.initialize(|bytes| bytes[..4].copy_from_slice(b"NIPC"));
        let mut prepared = private
            .prepare_coordinator_writer_for_ordering_test()
            .unwrap();
        validate_object(prepared.fd.as_raw_fd(), prepared.mapping.len, FINAL_SEALS).unwrap();
        // SAFETY: descriptor is live and mode is a scalar probe.
        assert_eq!(unsafe { libc::fchmod(prepared.fd.as_raw_fd(), 0o700) }, -1);
        let reader_fd = prepared.reader_capability().unwrap();
        assert!(mapping_fails(
            reader_fd.as_raw_fd(),
            libc::PROT_READ | libc::PROT_WRITE,
            prepared.mapping.len
        ));
        let reader =
            VmMapping::map(reader_fd.as_raw_fd(), prepared.mapping.len, libc::PROT_READ).unwrap();
        prepared.write_volatile(3, b'X');
        // SAFETY: reader is a live read-only mapping and offset is in bounds.
        assert_eq!(
            unsafe { core::ptr::read_volatile(reader.base.as_ptr().add(3)) },
            b'X'
        );
        // SAFETY: page-rounded padding remains live and read-only.
        assert_eq!(
            unsafe { core::ptr::read_volatile(reader.base.as_ptr().add(reader.len - 1)) },
            0
        );
    }

    #[test]
    fn both_writer_directions_fail_closed_when_memfd_can_become_executable() {
        let coordinator = PrivateMemfd::new(73).unwrap();
        assert!(matches!(
            coordinator.prepare_coordinator_writer(),
            Err(MemfdError::ExecutableAuthorityUnsupported)
        ));
        let receiver = PrivateMemfd::new(73).unwrap();
        assert!(matches!(
            receiver.prepare_receiver_writer(binding(1)),
            Err(MemfdError::ExecutableAuthorityUnsupported)
        ));
    }

    #[test]
    #[ignore = "spawned alone as a disposable kernel-NX characterization helper"]
    fn isolated_kernel_nx_probe_helper() {
        let disposable = PrivateMemfd::new(73).unwrap();
        let facts = probe_kernel_nx(
            disposable.fd.as_raw_fd(),
            disposable.mapping.as_ref().unwrap(),
        )
        .unwrap();
        assert_eq!(
            facts,
            NxProbeFacts {
                new_executable_mapping_denied: false,
                existing_mapping_upgrade_denied: false,
            }
        );
    }

    #[test]
    fn isolated_process_confirms_kernel_nx_gap() {
        let executable = std::env::current_exe().unwrap();
        let status = Command::new(executable)
            .args([
                "--exact",
                "backend::linux_vnext::memory::tests::isolated_kernel_nx_probe_helper",
                "--ignored",
                "--nocapture",
            ])
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[test]
    fn receiver_writer_ordering_imports_then_seals_without_coordinator_writer() {
        let mut private = PrivateMemfd::new(73).unwrap();
        private.initialize(|bytes| bytes[0] = 7);
        let provenance = binding(1);
        let prepared = private
            .prepare_receiver_writer_for_ordering_test(provenance)
            .unwrap();
        let mapped_len = prepared.key.mapped_len;
        let (prepared, capability) = prepared.export_writer().unwrap();
        let mut peer = ImportedPeerWriter::import(capability, mapped_len, provenance).unwrap();
        let receipt = peer.take_imported_receipt().unwrap();
        assert!(peer.take_imported_receipt().is_none());
        let reader = prepared.seal_after_import(receipt).unwrap();
        peer.verify_sealed().unwrap();
        peer.write_volatile(0, 41);
        assert_eq!(reader.read_volatile(0), 41);
        assert_eq!(reader.read_volatile(mapped_len - 1), 0);
        // SAFETY: descriptor is live and mode is a scalar probe.
        assert_eq!(unsafe { libc::fchmod(reader.fd.as_raw_fd(), 0o700) }, -1);
        assert!(mapping_fails(
            reader.fd.as_raw_fd(),
            libc::PROT_READ | libc::PROT_WRITE,
            mapped_len
        ));
        // SAFETY: scalar syscall arguments describe a one-byte write probe.
        assert_eq!(
            unsafe { libc::pwrite(reader.fd.as_raw_fd(), b"x".as_ptr().cast(), 1, 0) },
            -1
        );
        // SAFETY: descriptor is live and the resize probe is scalar.
        assert_eq!(
            unsafe { libc::ftruncate(reader.fd.as_raw_fd(), (mapped_len * 2) as _) },
            -1
        );
    }

    #[test]
    fn imported_receipt_binds_full_provenance_even_for_the_same_object() {
        let expected = binding(2);
        let prepared = PrivateMemfd::new(1)
            .unwrap()
            .prepare_receiver_writer_for_ordering_test(expected)
            .unwrap();
        let mapped_len = prepared.key.mapped_len;
        let (prepared, capability) = prepared.export_writer().unwrap();
        let foreign_capability = duplicate(&capability).unwrap();
        let mut foreign_peer =
            ImportedPeerWriter::import(foreign_capability, mapped_len, binding(3)).unwrap();
        let foreign = foreign_peer.take_imported_receipt().unwrap();
        assert!(matches!(
            prepared.seal_after_import(foreign),
            Err(MemfdError::WrongProvenance)
        ));
    }
}
