use super::super::{PacketCredentials, PacketError, ReceivedPacket, SeqPacketEndpoint};
use super::*;
use static_assertions::{assert_impl_all, assert_not_impl_any};
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, ExitStatus};
use std::time::{Duration, Instant};

const PR_SET_MDWE: libc::c_int = 65;
const PR_GET_MDWE: libc::c_int = 66;
const PR_MDWE_REFUSE_EXEC_GAIN: libc::c_ulong = 1;
const ENV_DELEGATE_FD: &str = "NATIVE_IPC_VNEXT_DELEGATE_FD";
const ENV_DELEGATE_LEN: &str = "NATIVE_IPC_VNEXT_DELEGATE_LEN";
const ENV_DELEGATE_PARENT_PID: &str = "NATIVE_IPC_VNEXT_DELEGATE_PARENT_PID";
const ENV_DELEGATE_PARENT_UID: &str = "NATIVE_IPC_VNEXT_DELEGATE_PARENT_UID";
const ENV_DELEGATE_PARENT_GID: &str = "NATIVE_IPC_VNEXT_DELEGATE_PARENT_GID";
const DELEGATE_WAIT_TIMEOUT: Duration = Duration::from_secs(25);
const RECEIVER_WAIT_TIMEOUT: Duration = Duration::from_secs(35);
const CHILD_POLL_INTERVAL: Duration = Duration::from_millis(5);

struct WatchedChild {
    child: Option<Child>,
}

impl WatchedChild {
    fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    fn id(&self) -> u32 {
        self.child.as_ref().expect("child already reaped").id()
    }

    fn wait_timeout(&mut self, timeout: Duration) -> io::Result<ExitStatus> {
        let deadline = Instant::now()
            .checked_add(timeout)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid child timeout"))?;
        loop {
            let status = self
                .child
                .as_mut()
                .expect("child already reaped")
                .try_wait()?;
            if let Some(status) = status {
                self.child.take();
                return Ok(status);
            }
            if Instant::now() >= deadline {
                let child = self.child.take().expect("child already reaped");
                let pid = child.id();
                Self::terminate_and_reap(child);
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("helper process {pid} exceeded {timeout:?}"),
                ));
            }
            std::thread::sleep(CHILD_POLL_INTERVAL);
        }
    }

    fn terminate_and_reap(mut child: Child) {
        match child.try_wait() {
            Ok(Some(_)) => {}
            Ok(None) | Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
}

impl Drop for WatchedChild {
    fn drop(&mut self) {
        if let Some(child) = self.child.take() {
            Self::terminate_and_reap(child);
        }
    }
}

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

fn current_mdwe() -> Result<libc::c_ulong, MemfdError> {
    // SAFETY: PR_GET_MDWE accepts four zero trailing arguments.
    let value = unsafe {
        libc::prctl(
            PR_GET_MDWE,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    };
    if value < 0 {
        Err(last_native())
    } else {
        Ok(value as libc::c_ulong)
    }
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

fn current_seals(fd: RawFd) -> libc::c_int {
    // SAFETY: descriptor is live and F_GET_SEALS has no pointer argument.
    let seals = unsafe { libc::fcntl(fd, libc::F_GET_SEALS) };
    assert!(seals >= 0);
    seals
}

fn assert_resize_allowed(fd: RawFd, mapped_len: usize) {
    // SAFETY: descriptor is live and both lengths fit off_t by construction.
    assert_eq!(
        unsafe { libc::ftruncate(fd, (mapped_len * 2) as libc::off_t) },
        0
    );
    // SAFETY: restores the exact mapped object length before preparation.
    assert_eq!(unsafe { libc::ftruncate(fd, mapped_len as libc::off_t) }, 0);
}

fn assert_resize_denied(fd: RawFd, mapped_len: usize) {
    for length in [mapped_len / 2, mapped_len * 2] {
        // SAFETY: descriptor is live and each length fits off_t by construction.
        assert_eq!(unsafe { libc::ftruncate(fd, length as libc::off_t) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
    }
}

fn local_credentials() -> PacketCredentials {
    PacketCredentials {
        pid: std::process::id(),
        // SAFETY: scalar identity syscalls have no preconditions.
        uid: unsafe { libc::geteuid() },
        // SAFETY: scalar identity syscalls have no preconditions.
        gid: unsafe { libc::getegid() },
    }
}

fn receive_packet_until(
    endpoint: &mut SeqPacketEndpoint,
    expected_len: usize,
    peer: PacketCredentials,
    descriptors: usize,
) -> ReceivedPacket {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match endpoint.receive(expected_len, peer, descriptors) {
            Ok(packet) => return packet,
            Err(PacketError::WouldBlock | PacketError::Interrupted)
                if Instant::now() < deadline =>
            {
                std::thread::yield_now();
            }
            Err(error) => panic!("packet receive failed: {error:?}"),
        }
    }
}

fn send_packet_until(endpoint: &mut SeqPacketEndpoint, bytes: &[u8], descriptors: &[RawFd]) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match endpoint.send(bytes, descriptors) {
            Ok(()) => return,
            Err(PacketError::WouldBlock | PacketError::Interrupted)
                if Instant::now() < deadline =>
            {
                std::thread::yield_now();
            }
            Err(error) => panic!("packet send failed: {error:?}"),
        }
    }
}

#[test]
fn coordinator_writer_ordering_keeps_preseal_writer_and_exports_reader() {
    let mut private = PrivateMemfd::new(37).unwrap();
    let mapped_len = private.mapping.as_ref().unwrap().len;
    assert_eq!(current_seals(private.fd.as_raw_fd()), F_SEAL_EXEC);
    assert_resize_allowed(private.fd.as_raw_fd(), mapped_len);
    assert!(!mapping_fails(
        private.fd.as_raw_fd(),
        libc::PROT_READ | libc::PROT_WRITE,
        mapped_len
    ));
    private.initialize(|bytes| bytes[..4].copy_from_slice(b"NIPC"));
    let mut prepared = private
        .prepare_coordinator_writer_for_ordering_test()
        .unwrap();
    validate_object(prepared.fd.as_raw_fd(), prepared.mapping.len, FINAL_SEALS).unwrap();
    assert_eq!(current_seals(prepared.fd.as_raw_fd()), FINAL_SEALS);
    assert_resize_denied(prepared.fd.as_raw_fd(), prepared.mapping.len);
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
#[ignore = "spawned as the pre-existing non-MDWE receiver-writer delegate"]
fn preexisting_non_mdwe_receiver_writer_delegate_helper() {
    assert_eq!(current_mdwe().unwrap(), 0);
    let raw: RawFd = std::env::var(ENV_DELEGATE_FD).unwrap().parse().unwrap();
    let mapped_len: usize = std::env::var(ENV_DELEGATE_LEN).unwrap().parse().unwrap();
    let parent = PacketCredentials {
        pid: std::env::var(ENV_DELEGATE_PARENT_PID)
            .unwrap()
            .parse()
            .unwrap(),
        uid: std::env::var(ENV_DELEGATE_PARENT_UID)
            .unwrap()
            .parse()
            .unwrap(),
        gid: std::env::var(ENV_DELEGATE_PARENT_GID)
            .unwrap()
            .parse()
            .unwrap(),
    };
    // SAFETY: the spawning helper transferred this uniquely owned endpoint.
    let mut endpoint = unsafe { SeqPacketEndpoint::from_inherited(raw) }.unwrap();
    let packet = receive_packet_until(&mut endpoint, 6, parent, 1);
    assert_eq!(packet.bytes, b"writer");
    let mut descriptors = packet.descriptors;
    let writer = descriptors.pop().unwrap();
    assert!(descriptors.is_empty());
    assert_eq!(current_seals(writer.as_raw_fd()), PREFIX_SEALS);
    let mapping = VmMapping::map(
        writer.as_raw_fd(),
        mapped_len,
        libc::PROT_READ | libc::PROT_WRITE,
    )
    .unwrap();
    // SAFETY: this disposable delegate owns the retained writer mapping.
    unsafe { core::ptr::write_volatile(mapping.base.as_ptr(), 0x29) };
    send_packet_until(&mut endpoint, b"imported", &[]);

    let packet = receive_packet_until(&mut endpoint, 6, parent, 0);
    assert_eq!(packet.bytes, b"sealed");
    assert_eq!(current_seals(writer.as_raw_fd()), FINAL_SEALS);
    assert!(mapping_fails(
        writer.as_raw_fd(),
        libc::PROT_READ | libc::PROT_WRITE,
        mapped_len
    ));

    // This mapping belongs only to a disposable characterization object. The
    // test proves the accepted outside-tree upgrade with mprotect, restores RW,
    // and deliberately never branches to or executes any mapped byte.
    assert_eq!(
        // SAFETY: the exact retained mapping remains live for this probe.
        unsafe {
            libc::mprotect(
                mapping.base.as_ptr().cast(),
                mapping.len,
                libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
            )
        },
        0
    );
    assert_eq!(
        // SAFETY: restoring RW removes execute before this helper reports success.
        unsafe {
            libc::mprotect(
                mapping.base.as_ptr().cast(),
                mapping.len,
                libc::PROT_READ | libc::PROT_WRITE,
            )
        },
        0
    );
    // SAFETY: restored RW mapping remains live and in bounds.
    unsafe { core::ptr::write_volatile(mapping.base.as_ptr(), 0x5a) };
    send_packet_until(&mut endpoint, b"upgraded", &[]);
}

#[test]
#[ignore = "spawned alone as the MDWE-enabled simulated receiver"]
fn isolated_mdwe_receiver_delegates_preseal_writer_outside_tree_helper() {
    assert_eq!(current_mdwe().unwrap(), 0);
    let mut private = PrivateMemfd::new(73).unwrap();
    private.initialize(|bytes| bytes[0] = 7);
    let provenance = binding(9);
    let prepared = private
        .prepare_receiver_writer_for_ordering_test(provenance)
        .unwrap();
    let mapped_len = prepared.key.mapped_len;
    assert_eq!(current_seals(prepared.fd.as_raw_fd()), PREFIX_SEALS);

    let (mut endpoint, child_endpoint) = SeqPacketEndpoint::pair().unwrap();
    let source = child_endpoint.fd.as_raw_fd();
    let parent = local_credentials();
    let executable = std::env::current_exe().unwrap();
    let mut command = Command::new(executable);
    command
        .args([
            "--exact",
            "backend::linux_vnext::memory::tests::preexisting_non_mdwe_receiver_writer_delegate_helper",
            "--ignored",
            "--nocapture",
        ])
        .env(ENV_DELEGATE_FD, source.to_string())
        .env(ENV_DELEGATE_LEN, mapped_len.to_string())
        .env(ENV_DELEGATE_PARENT_PID, parent.pid.to_string())
        .env(ENV_DELEGATE_PARENT_UID, parent.uid.to_string())
        .env(ENV_DELEGATE_PARENT_GID, parent.gid.to_string());
    let expected_parent_pid = parent.pid as libc::pid_t;
    // SAFETY: only raw Linux syscalls run between fork and exec.
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(source, libc::F_SETFD, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::getppid() != expected_parent_pid {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "receiver exited before delegate exec",
                ));
            }
            Ok(())
        });
    }
    // Spawn before MDWE installation: this is a pre-existing process outside
    // the subsequently MDWE-inheriting receiver tree.
    let mut delegate = WatchedChild::new(command.spawn().unwrap());
    let delegate_credentials = PacketCredentials {
        pid: delegate.id(),
        uid: parent.uid,
        gid: parent.gid,
    };
    drop(child_endpoint);

    // This process now simulates the malicious MDWE-enabled receiver and sends
    // its pre-seal writer capability to that non-inheriting delegate.
    enable_irreversible_mdwe().unwrap();
    assert_eq!(current_mdwe().unwrap(), PR_MDWE_REFUSE_EXEC_GAIN);
    let (sent, capability) = prepared.export_writer().unwrap();
    send_packet_until(&mut endpoint, b"writer", &[capability.as_raw_fd()]);
    drop(capability);
    let unauthenticated_import_ack =
        receive_packet_until(&mut endpoint, 8, delegate_credentials, 0);
    assert_eq!(unauthenticated_import_ack.bytes, b"imported");

    // This characterization covers kernel seal and process-topology behavior,
    // not an authenticated IMPORTED protocol exchange. Synthesize the private
    // typestate receipt only after the delegate's unauthenticated test signal.
    let synthetic_unauthenticated_receipt = PeerWriterImportedReceipt {
        key: sent.key,
        binding: sent.binding,
        not_sync: core::marker::PhantomData,
    };
    let reader = sent
        .seal_after_import(synthetic_unauthenticated_receipt)
        .unwrap();
    assert_eq!(current_seals(reader.fd.as_raw_fd()), FINAL_SEALS);
    send_packet_until(&mut endpoint, b"sealed", &[]);
    let packet = receive_packet_until(&mut endpoint, 8, delegate_credentials, 0);
    assert_eq!(packet.bytes, b"upgraded");
    assert_eq!(reader.read_volatile(0), 0x5a);
    assert!(
        delegate
            .wait_timeout(DELEGATE_WAIT_TIMEOUT)
            .unwrap()
            .success()
    );
}

#[test]
fn receiver_writer_preseal_delegate_outside_mdwe_tree_retains_upgradeable_writer() {
    let executable = std::env::current_exe().unwrap();
    let mut command = Command::new(executable);
    command.args([
        "--exact",
        "backend::linux_vnext::memory::tests::isolated_mdwe_receiver_delegates_preseal_writer_outside_tree_helper",
        "--ignored",
        "--nocapture",
    ]);
    let mut receiver = WatchedChild::new(command.spawn().unwrap());
    let status = receiver.wait_timeout(RECEIVER_WAIT_TIMEOUT).unwrap();
    assert!(status.success());
}

#[test]
fn receiver_writer_ordering_imports_then_seals_without_coordinator_writer() {
    let mut private = PrivateMemfd::new(73).unwrap();
    let initial_len = private.mapping.as_ref().unwrap().len;
    assert_eq!(current_seals(private.fd.as_raw_fd()), F_SEAL_EXEC);
    assert_resize_allowed(private.fd.as_raw_fd(), initial_len);
    assert!(!mapping_fails(
        private.fd.as_raw_fd(),
        libc::PROT_READ | libc::PROT_WRITE,
        initial_len
    ));
    private.initialize(|bytes| bytes[0] = 7);
    let provenance = binding(1);
    let prepared = private
        .prepare_receiver_writer_for_ordering_test(provenance)
        .unwrap();
    let mapped_len = prepared.key.mapped_len;
    assert_eq!(current_seals(prepared.fd.as_raw_fd()), PREFIX_SEALS);
    assert_resize_denied(prepared.fd.as_raw_fd(), mapped_len);
    assert!(!mapping_fails(
        prepared.fd.as_raw_fd(),
        libc::PROT_READ | libc::PROT_WRITE,
        mapped_len
    ));
    let (prepared, capability) = prepared.export_writer().unwrap();
    assert_eq!(current_seals(prepared.fd.as_raw_fd()), PREFIX_SEALS);
    assert_eq!(current_seals(capability.as_raw_fd()), PREFIX_SEALS);
    assert_resize_denied(capability.as_raw_fd(), mapped_len);
    assert!(!mapping_fails(
        capability.as_raw_fd(),
        libc::PROT_READ | libc::PROT_WRITE,
        mapped_len
    ));
    let mut peer = ImportedPeerWriter::import(capability, mapped_len, provenance).unwrap();
    assert_eq!(current_seals(peer.fd.as_raw_fd()), PREFIX_SEALS);
    assert_resize_denied(peer.fd.as_raw_fd(), mapped_len);
    assert!(!mapping_fails(
        peer.fd.as_raw_fd(),
        libc::PROT_READ | libc::PROT_WRITE,
        mapped_len
    ));
    let receipt = peer.take_imported_receipt().unwrap();
    assert!(peer.take_imported_receipt().is_none());
    assert_eq!(current_seals(peer.fd.as_raw_fd()), PREFIX_SEALS);
    assert!(!mapping_fails(
        peer.fd.as_raw_fd(),
        libc::PROT_READ | libc::PROT_WRITE,
        mapped_len
    ));
    let reader = prepared.seal_after_import(receipt).unwrap();
    assert_eq!(current_seals(reader.fd.as_raw_fd()), FINAL_SEALS);
    assert_resize_denied(reader.fd.as_raw_fd(), mapped_len);
    peer.verify_sealed().unwrap();
    assert_eq!(current_seals(peer.fd.as_raw_fd()), FINAL_SEALS);
    assert!(mapping_fails(
        peer.fd.as_raw_fd(),
        libc::PROT_READ | libc::PROT_WRITE,
        mapped_len
    ));
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
    assert!(matches!(
        add_seals(reader.fd.as_raw_fd(), libc::F_SEAL_WRITE),
        Err(MemfdError::Native(libc::EPERM))
    ));
    assert_eq!(current_seals(reader.fd.as_raw_fd()), FINAL_SEALS);
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
