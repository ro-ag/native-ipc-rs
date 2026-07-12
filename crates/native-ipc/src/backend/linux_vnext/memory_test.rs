use super::*;
use static_assertions::{assert_impl_all, assert_not_impl_any};
use std::process::Command;

const PR_SET_MDWE: libc::c_int = 65;
const PR_MDWE_REFUSE_EXEC_GAIN: libc::c_ulong = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NxProbeFacts {
    new_executable_mapping_denied: bool,
    existing_mapping_upgrade_denied: bool,
}

impl PrivateMemfd {
    fn prepare_coordinator_writer_for_ordering_test(
        self,
    ) -> Result<CoordinatorWriterPrepared, MemfdError> {
        self.prepare_coordinator_writer_after_nx()
    }

    fn prepare_receiver_writer_for_ordering_test(
        self,
        binding: TransferBinding,
    ) -> Result<ReceiverWriterPrepared, MemfdError> {
        self.prepare_receiver_writer_after_nx(binding)
    }
}

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

fn enable_irreversible_mdwe() -> Result<(), MemfdError> {
    // SAFETY: PR_SET_MDWE accepts this scalar mask and zero trailing arguments.
    if unsafe {
        libc::prctl(
            PR_SET_MDWE,
            PR_MDWE_REFUSE_EXEC_GAIN,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    } != 0
    {
        return Err(last_native());
    }
    Ok(())
}

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
#[ignore = "spawned alone as a disposable MDWE plus kernel-NX characterization helper"]
fn isolated_mdwe_kernel_nx_probe_helper() {
    let disposable = PrivateMemfd::new(73).unwrap();
    enable_irreversible_mdwe().unwrap();
    let facts = probe_kernel_nx(
        disposable.fd.as_raw_fd(),
        disposable.mapping.as_ref().unwrap(),
    )
    .unwrap();
    assert_eq!(
        facts,
        NxProbeFacts {
            new_executable_mapping_denied: false,
            existing_mapping_upgrade_denied: true,
        }
    );
}

#[test]
fn isolated_process_confirms_kernel_nx_gap() {
    let executable = std::env::current_exe().unwrap();
    for helper in [
        "backend::linux_vnext::memory::tests::isolated_kernel_nx_probe_helper",
        "backend::linux_vnext::memory::tests::isolated_mdwe_kernel_nx_probe_helper",
    ] {
        let status = Command::new(&executable)
            .args(["--exact", helper, "--ignored", "--nocapture"])
            .status()
            .unwrap();
        assert!(status.success(), "isolated NX helper failed: {helper}");
    }
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
