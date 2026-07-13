use super::super::{PacketCredentials, PacketError, ReceivedPacket, SeqPacketEndpoint};
use super::*;
use crate::batch::{ExpectedBatch, ExpectedRegion};
use crate::protocol::{CAPABILITY_MAGIC, TransferManifest};
use crate::region::{PrivateRegion, RegionId, RegionOptions, RegionSpec};
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
assert_impl_all!(LinuxCoordinatorWriterBatch: Send);
assert_not_impl_any!(LinuxCoordinatorWriterBatch: Sync, Clone);
assert_impl_all!(LinuxReceiverWriterBatch: Send);
assert_not_impl_any!(LinuxReceiverWriterBatch: Sync, Clone);
assert_impl_all!(LinuxMixedDirectionBatch: Send);
assert_not_impl_any!(LinuxMixedDirectionBatch: Sync, Clone);
assert_impl_all!(LinuxExpectedCoordinatorWriterBatch: Send);
assert_not_impl_any!(LinuxExpectedCoordinatorWriterBatch: Clone);
assert_impl_all!(LinuxExpectedReceiverWriterBatch: Send);
assert_not_impl_any!(LinuxExpectedReceiverWriterBatch: Clone);
assert_impl_all!(LinuxExpectedMixedDirectionBatch: Send);
assert_not_impl_any!(LinuxExpectedMixedDirectionBatch: Clone);
assert_impl_all!(LinuxImportedCoordinatorWriterBatch: Send);
assert_not_impl_any!(LinuxImportedCoordinatorWriterBatch: Sync, Clone);
assert_impl_all!(LinuxImportedReceiverWriterBatch: Send);
assert_not_impl_any!(LinuxImportedReceiverWriterBatch: Sync, Clone);
assert_impl_all!(LinuxImportedMixedDirectionBatch: Send);
assert_not_impl_any!(LinuxImportedMixedDirectionBatch: Sync, Clone);
assert_impl_all!(LinuxMixedDirectionImportFailure: Send);
assert_not_impl_any!(LinuxMixedDirectionImportFailure: Sync, Clone);

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

fn portable_batch(regions: &[(u128, WriterEndpoint, usize)]) -> TransferBatch {
    let mut batch = TransferBatch::new(16, 16 * 1024 * 1024, 16 * 1024 * 1024).unwrap();
    for &(id, writer, logical_len) in regions {
        let mut region = PrivateRegion::allocate(RegionOptions::fixed(logical_len)).unwrap();
        region.initialize(|bytes| bytes.fill(id as u8));
        batch
            .add(
                region
                    .prepare(RegionSpec {
                        id: RegionId::new(id).unwrap(),
                        writer,
                    })
                    .unwrap(),
            )
            .unwrap();
    }
    batch
}

fn expected_batch(regions: &[(u128, WriterEndpoint, usize)]) -> ExpectedBatch {
    ExpectedBatch::try_from_specs(
        regions
            .iter()
            .map(|&(id, writer, logical_len)| ExpectedRegion {
                id: RegionId::new(id).unwrap(),
                writer,
                logical_len,
            })
            .collect(),
    )
    .unwrap()
}

fn duplicate_mixed_descriptors(batch: &LinuxMixedDirectionBatch) -> Vec<OwnedFd> {
    batch
        .entries
        .iter()
        .map(|entry| match entry {
            LinuxMixedDirectionEntry::CoordinatorWriter(batch) => {
                duplicate(&batch.entries[0].prepared.reader_capability).unwrap()
            }
            LinuxMixedDirectionEntry::ReceiverWriter(batch) => {
                duplicate(&batch.entries[0].fd).unwrap()
            }
        })
        .collect()
}

fn batch_deadline() -> AbsoluteDeadline {
    AbsoluteDeadline::after(Duration::from_secs(5)).unwrap()
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
    // SAFETY: the callback performs only scalar syscalls and constructs errors
    // directly from errno values, without formatted or allocated messages.
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(source, libc::F_SETFD, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::getppid() != expected_parent_pid {
                return Err(io::Error::from_raw_os_error(libc::EPIPE));
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

#[test]
fn coordinator_writer_batches_prepare_canonical_exact_objects_for_one_to_sixteen() {
    for count in [1, 2, 4, 16] {
        let regions: Vec<_> = (1..=count)
            .rev()
            .map(|id| (id as u128, WriterEndpoint::Coordinator, id * 17))
            .collect();
        let deadline = batch_deadline();
        let batch = LinuxCoordinatorWriterBatch::prepare(
            portable_batch(&regions),
            NativeAuthorityProfile::LinuxMdweV1,
            deadline,
        )
        .unwrap();
        assert_eq!(batch.deadline(), deadline);
        assert_eq!(batch.entries.len(), count);
        assert_eq!(batch.capabilities().len(), count);
        batch.revalidate().unwrap();

        let manifest = TransferManifest::new_with_authority(
            [0x71; 32],
            10,
            11,
            1,
            NativeAuthorityProfile::LinuxMdweV1,
            batch.manifest_entries(),
        )
        .unwrap();
        let frame = manifest.encode(CAPABILITY_MAGIC);
        for (ordinal, entry) in batch.entries.iter().enumerate() {
            let start = 96 + ordinal * 64;
            assert_eq!(
                u128::from_le_bytes(frame[start..start + 16].try_into().unwrap()),
                entry.native.region_id
            );
            assert_eq!(&frame[start + 16..start + 32], &entry.native.incarnation);
            assert_eq!(
                u64::from_le_bytes(frame[start + 32..start + 40].try_into().unwrap()),
                entry.native.logical_len
            );
            assert_eq!(
                u64::from_le_bytes(frame[start + 40..start + 48].try_into().unwrap()),
                entry.native.mapped_len
            );
            assert_eq!(
                u16::from_le_bytes(frame[start + 56..start + 58].try_into().unwrap()) as usize,
                ordinal
            );
            assert_eq!(current_seals(entry.prepared.fd.as_raw_fd()), FINAL_SEALS);
            assert_eq!(
                current_seals(entry.prepared.reader_capability.as_raw_fd()),
                FINAL_SEALS
            );
            assert!(mapping_fails(
                entry.prepared.reader_capability.as_raw_fd(),
                libc::PROT_READ | libc::PROT_WRITE,
                entry.prepared.mapping.len
            ));
            // SAFETY: the retained coordinator mapping is live for the complete
            // logical range and no mutable access overlaps this observation.
            let initialized = unsafe {
                core::slice::from_raw_parts(
                    entry.prepared.mapping.base.as_ptr(),
                    usize::try_from(entry.native.logical_len).unwrap(),
                )
            };
            assert!(
                initialized
                    .iter()
                    .all(|byte| *byte == entry.native.region_id as u8)
            );
        }
    }
}

#[test]
fn mixed_direction_batches_prepare_one_to_sixteen_in_canonical_capability_order() {
    for count in [1, 2, 4, 16] {
        let regions: Vec<_> = (1..=count)
            .rev()
            .map(|id| {
                let writer = if id % 2 == 0 {
                    WriterEndpoint::Coordinator
                } else {
                    WriterEndpoint::Receiver
                };
                (id as u128, writer, id * 17)
            })
            .collect();
        let deadline = batch_deadline();
        let mut batch = LinuxMixedDirectionBatch::prepare(
            portable_batch(&regions),
            NativeAuthorityProfile::LinuxMdweV1,
            deadline,
        )
        .unwrap();
        assert_eq!(batch.deadline(), deadline);
        assert_eq!(batch.entries.len(), count);
        batch.revalidate_before_send().unwrap();
        let capabilities = batch.capabilities();
        assert_eq!(capabilities.len(), count);

        let manifest = TransferManifest::new_with_authority(
            [0x73; 32],
            10,
            11,
            1,
            NativeAuthorityProfile::LinuxMdweV1,
            batch.manifest_entries(),
        )
        .unwrap();
        for (ordinal, ((manifest, native), capability)) in manifest
            .entries()
            .iter()
            .zip(&batch.entries)
            .zip(&capabilities)
            .enumerate()
        {
            assert_eq!(manifest.region_id, (ordinal + 1) as u128);
            assert_eq!(manifest.ordinal as usize, ordinal);
            match native {
                LinuxMixedDirectionEntry::CoordinatorWriter(batch) => {
                    let entry = &batch.entries[0];
                    assert_eq!(manifest.writer, 0);
                    assert_eq!(manifest.access, PeerAccess::ReadOnly);
                    assert_eq!(manifest.region_id, entry.native.region_id);
                    assert_eq!(
                        validate_object(
                            capability.as_raw_fd(),
                            entry.prepared.key.mapped_len,
                            FINAL_SEALS,
                        ),
                        Ok(entry.prepared.key)
                    );
                    assert_eq!(
                        current_seals(entry.prepared.reader_capability.as_raw_fd()),
                        FINAL_SEALS
                    );
                    assert!(mapping_fails(
                        entry.prepared.reader_capability.as_raw_fd(),
                        libc::PROT_READ | libc::PROT_WRITE,
                        entry.prepared.mapping.len
                    ));
                    for offset in 0..manifest.logical_len as usize {
                        // SAFETY: the retained coordinator mapping is live for
                        // the complete initialized logical range.
                        assert_eq!(
                            unsafe {
                                core::ptr::read_volatile(
                                    entry.prepared.mapping.base.as_ptr().add(offset),
                                )
                            },
                            manifest.region_id as u8
                        );
                    }
                }
                LinuxMixedDirectionEntry::ReceiverWriter(batch) => {
                    let entry = &batch.entries[0];
                    assert_eq!(manifest.writer, 1);
                    assert_eq!(manifest.access, PeerAccess::SoleWriter);
                    assert_eq!(manifest.region_id, entry.native.region_id);
                    assert_eq!(
                        validate_object(capability.as_raw_fd(), entry.key.mapped_len, PREFIX_SEALS,),
                        Ok(entry.key)
                    );
                    assert_eq!(current_seals(entry.fd.as_raw_fd()), PREFIX_SEALS);
                    assert!(entry.mapping.is_none());
                    assert!(entry.pending_mapping.is_none());
                    let reader =
                        VmMapping::map(entry.fd.as_raw_fd(), entry.key.mapped_len, libc::PROT_READ)
                            .unwrap();
                    for offset in 0..manifest.logical_len as usize {
                        // SAFETY: the test-only read mapping covers the exact
                        // initialized logical range and is not writable.
                        assert_eq!(
                            unsafe { core::ptr::read_volatile(reader.base.as_ptr().add(offset)) },
                            manifest.region_id as u8
                        );
                    }
                }
            }
        }
        drop(capabilities);
        let events = Arc::new(Mutex::new(Vec::new()));
        batch.observe_drop_for_test(events.clone());
        drop(batch);
        assert_eq!(
            events.lock().unwrap().as_slice(),
            &["mixed-direction-batch-drop"]
        );
    }
}

#[test]
fn mixed_direction_revalidation_rejects_a_retained_coordinator_writable_view() {
    let mut batch = LinuxMixedDirectionBatch::prepare(
        portable_batch(&[
            (1, WriterEndpoint::Coordinator, 17),
            (2, WriterEndpoint::Receiver, 34),
        ]),
        NativeAuthorityProfile::LinuxMdweV1,
        batch_deadline(),
    )
    .unwrap();
    let LinuxMixedDirectionEntry::ReceiverWriter(receiver) = &mut batch.entries[1] else {
        panic!("canonical second entry is receiver-writer");
    };
    let entry = &mut receiver.entries[0];
    entry.pending_mapping = Some(
        PendingVmMapping::map(
            entry.fd.as_raw_fd(),
            entry.key.mapped_len,
            libc::PROT_READ | libc::PROT_WRITE,
            false,
        )
        .unwrap(),
    );
    assert_eq!(batch.revalidate_before_send(), Err(MemfdError::WrongObject));
}

#[test]
fn mixed_receiver_import_owns_one_canonical_pending_batch_for_one_to_sixteen() {
    for count in [1, 2, 4, 16] {
        let regions: Vec<_> = (1..=count)
            .rev()
            .map(|id| {
                let writer = if id % 2 == 0 {
                    WriterEndpoint::Coordinator
                } else {
                    WriterEndpoint::Receiver
                };
                (id as u128, writer, id * 17)
            })
            .collect();
        let deadline = batch_deadline();
        let coordinator = LinuxMixedDirectionBatch::prepare(
            portable_batch(&regions),
            NativeAuthorityProfile::LinuxMdweV1,
            deadline,
        )
        .unwrap();
        let manifest = TransferManifest::new_with_authority(
            [0x74; 32],
            10,
            11,
            1,
            NativeAuthorityProfile::LinuxMdweV1,
            coordinator.manifest_entries(),
        )
        .unwrap();
        let expected = LinuxExpectedMixedDirectionBatch::prepare(
            expected_batch(&regions),
            SessionLimits::default(),
            deadline,
        )
        .unwrap();
        assert_eq!(expected.len(), count);
        assert_eq!(expected.deadline(), deadline);
        assert!(expected.matches_manifest(&manifest));
        let descriptors = duplicate_mixed_descriptors(&coordinator);
        let mut imported = expected.import(&manifest, descriptors).unwrap();
        assert_eq!(imported.len(), count);

        for (ordinal, entry) in imported.entries.iter_mut().enumerate() {
            let id = ordinal + 1;
            match entry {
                LinuxImportedMixedDirectionEntry::CoordinatorWriter(entry) => {
                    assert_eq!(entry.manifest.region_id, id as u128);
                    assert_eq!(current_seals(entry.fd.as_raw_fd()), FINAL_SEALS);
                    assert!(mapping_fails(
                        entry.fd.as_raw_fd(),
                        libc::PROT_READ | libc::PROT_WRITE,
                        entry.key.mapped_len
                    ));
                    for offset in 0..entry.manifest.logical_len as usize {
                        // SAFETY: this private imported mapping is live and
                        // read-only for its complete logical range.
                        assert_eq!(
                            unsafe {
                                core::ptr::read_volatile(entry.mapping.base.as_ptr().add(offset))
                            },
                            id as u8
                        );
                    }
                }
                LinuxImportedMixedDirectionEntry::ReceiverWriter(entry) => {
                    assert_eq!(entry.manifest.region_id, id as u128);
                    assert_eq!(current_seals(entry.fd.as_raw_fd()), PREFIX_SEALS);
                    for offset in 0..entry.manifest.logical_len as usize {
                        // SAFETY: this private pending mapping was established
                        // RW before future-write sealing and remains owner-bound.
                        assert_eq!(
                            unsafe {
                                core::ptr::read_volatile(entry.mapping.base.as_ptr().add(offset))
                            },
                            id as u8
                        );
                    }
                    // SAFETY: test-only mutation remains inside the pending
                    // owner and does not expose runtime authority.
                    unsafe { core::ptr::write_volatile(entry.mapping.base.as_ptr(), 0xa5) };
                    // SAFETY: same live mapping and byte as the preceding write.
                    assert_eq!(
                        unsafe { core::ptr::read_volatile(entry.mapping.base.as_ptr()) },
                        0xa5
                    );
                }
            }
        }
        let events = Arc::new(Mutex::new(Vec::new()));
        imported.observe_drop_for_test(events.clone());
        drop(imported);
        assert_eq!(
            events.lock().unwrap().as_slice(),
            &["imported-mixed-batch-drop"]
        );
        drop(coordinator);
    }
}

#[test]
fn mixed_receiver_expectation_rejects_aggregate_limits_and_wrong_manifest() {
    let regions = [
        (1, WriterEndpoint::Coordinator, 4096),
        (2, WriterEndpoint::Receiver, 4096),
    ];
    for limits in [
        SessionLimits {
            max_regions_per_batch: 1,
            ..SessionLimits::default()
        },
        SessionLimits {
            max_active_regions: 1,
            ..SessionLimits::default()
        },
        SessionLimits {
            max_region_bytes: 4095,
            ..SessionLimits::default()
        },
        SessionLimits {
            max_region_bytes: 4096,
            max_batch_bytes: 8191,
            ..SessionLimits::default()
        },
    ] {
        assert!(matches!(
            LinuxExpectedMixedDirectionBatch::prepare(
                expected_batch(&regions),
                limits,
                batch_deadline(),
            ),
            Err(MemfdError::InvalidBatch)
        ));
    }

    let page = page_align(1).unwrap() as u64;
    let page_rounded = [
        (1, WriterEndpoint::Coordinator, 1),
        (2, WriterEndpoint::Receiver, 1),
    ];
    assert!(matches!(
        LinuxExpectedMixedDirectionBatch::prepare(
            expected_batch(&page_rounded),
            SessionLimits {
                max_region_bytes: 1,
                max_batch_bytes: page,
                max_active_bytes: page * 2,
                ..SessionLimits::default()
            },
            batch_deadline(),
        ),
        Err(MemfdError::InvalidBatch)
    ));
    assert!(matches!(
        LinuxExpectedMixedDirectionBatch::prepare(
            expected_batch(&page_rounded),
            SessionLimits {
                max_region_bytes: 1,
                max_batch_bytes: page * 2,
                max_active_bytes: page,
                ..SessionLimits::default()
            },
            batch_deadline(),
        ),
        Err(MemfdError::InvalidBatch)
    ));

    let deadline = batch_deadline();
    let coordinator = LinuxMixedDirectionBatch::prepare(
        portable_batch(&regions),
        NativeAuthorityProfile::LinuxMdweV1,
        deadline,
    )
    .unwrap();
    let manifest = TransferManifest::new_with_authority(
        [0x75; 32],
        10,
        11,
        1,
        NativeAuthorityProfile::LinuxMdweV1,
        coordinator.manifest_entries(),
    )
    .unwrap();
    let expected = LinuxExpectedMixedDirectionBatch::prepare(
        expected_batch(&[
            (1, WriterEndpoint::Receiver, 4096),
            (2, WriterEndpoint::Coordinator, 4096),
        ]),
        SessionLimits::default(),
        deadline,
    )
    .unwrap();
    assert!(!expected.matches_manifest(&manifest));
    let events = Arc::new(Mutex::new(Vec::new()));
    let mut failure = match expected.import(&manifest, duplicate_mixed_descriptors(&coordinator)) {
        Err(failure) => failure,
        Ok(_) => panic!("wrong mixed manifest was accepted"),
    };
    assert_eq!(failure.error(), MemfdError::WrongProvenance);
    failure.observe_drop_for_test(events.clone());
    drop(failure);
    assert_eq!(
        events.lock().unwrap().as_slice(),
        &["failed-mixed-import-drop"]
    );

    let duplicate_regions = [
        (1, WriterEndpoint::Coordinator, 4096),
        (2, WriterEndpoint::Coordinator, 4096),
    ];
    let coordinator = LinuxMixedDirectionBatch::prepare(
        portable_batch(&duplicate_regions),
        NativeAuthorityProfile::LinuxMdweV1,
        deadline,
    )
    .unwrap();
    let manifest = TransferManifest::new_with_authority(
        [0x79; 32],
        10,
        11,
        1,
        NativeAuthorityProfile::LinuxMdweV1,
        coordinator.manifest_entries(),
    )
    .unwrap();
    let expected = LinuxExpectedMixedDirectionBatch::prepare(
        expected_batch(&duplicate_regions),
        SessionLimits::default(),
        deadline,
    )
    .unwrap();
    let mut descriptors = duplicate_mixed_descriptors(&coordinator);
    descriptors[1] = duplicate(&descriptors[0]).unwrap();
    let failure = match expected.import(&manifest, descriptors) {
        Err(failure) => failure,
        Ok(_) => panic!("duplicate mixed object was accepted"),
    };
    assert_eq!(failure.error(), MemfdError::WrongObject);

    let expired = AbsoluteDeadline::after(Duration::from_millis(1)).unwrap();
    while !expired.is_expired() {
        core::hint::spin_loop();
    }
    assert!(matches!(
        LinuxExpectedMixedDirectionBatch::prepare(
            expected_batch(&duplicate_regions),
            SessionLimits::default(),
            expired,
        ),
        Err(MemfdError::DeadlineExpired)
    ));

    let short = AbsoluteDeadline::after(Duration::from_millis(100)).unwrap();
    let expected = LinuxExpectedMixedDirectionBatch::prepare(
        expected_batch(&duplicate_regions),
        SessionLimits::default(),
        short,
    )
    .unwrap();
    let descriptors = duplicate_mixed_descriptors(&coordinator);
    while !short.is_expired() {
        core::hint::spin_loop();
    }
    let failure = match expected.import(&manifest, descriptors) {
        Err(failure) => failure,
        Ok(_) => panic!("expired mixed import was accepted"),
    };
    assert_eq!(failure.error(), MemfdError::DeadlineExpired);
}

#[test]
#[ignore = "spawned alone by mixed_receiver_import_nth_failure_restores_resources"]
fn isolated_mixed_receiver_import_nth_failure_helper() {
    let baseline = process_resource_baseline();
    let regions: Vec<_> = (1..=16)
        .rev()
        .map(|id| {
            let writer = if id % 2 == 0 {
                WriterEndpoint::Coordinator
            } else {
                WriterEndpoint::Receiver
            };
            (id as u128, writer, id * 17)
        })
        .collect();
    for invalid in [1, 2, 4, 16] {
        let deadline = batch_deadline();
        let coordinator = LinuxMixedDirectionBatch::prepare(
            portable_batch(&regions),
            NativeAuthorityProfile::LinuxMdweV1,
            deadline,
        )
        .unwrap();
        let manifest = TransferManifest::new_with_authority(
            [0x76; 32],
            10,
            11,
            1,
            NativeAuthorityProfile::LinuxMdweV1,
            coordinator.manifest_entries(),
        )
        .unwrap();
        let expected = LinuxExpectedMixedDirectionBatch::prepare(
            expected_batch(&regions),
            SessionLimits::default(),
            deadline,
        )
        .unwrap();
        let mut descriptors = duplicate_mixed_descriptors(&coordinator);
        descriptors[invalid - 1] = std::fs::File::open("/dev/null").unwrap().into();
        let failure = match expected.import(&manifest, descriptors) {
            Err(failure) => failure,
            Ok(_) => panic!("invalid mixed descriptor was accepted"),
        };
        assert_eq!(failure.error(), MemfdError::InvalidObject);
        drop(failure);
        drop(coordinator);
        assert_eq!(process_resource_baseline(), baseline, "invalid {invalid}");
    }

    for operation in [1, 17, 32] {
        let deadline = batch_deadline();
        let coordinator = LinuxMixedDirectionBatch::prepare(
            portable_batch(&regions),
            NativeAuthorityProfile::LinuxMdweV1,
            deadline,
        )
        .unwrap();
        let manifest = TransferManifest::new_with_authority(
            [0x77; 32],
            10,
            11,
            1,
            NativeAuthorityProfile::LinuxMdweV1,
            coordinator.manifest_entries(),
        )
        .unwrap();
        let mut expected = LinuxExpectedMixedDirectionBatch::prepare(
            expected_batch(&regions),
            SessionLimits::default(),
            deadline,
        )
        .unwrap();
        expected.fail_advice_at_for_test(operation);
        let failure = match expected.import(&manifest, duplicate_mixed_descriptors(&coordinator)) {
            Err(failure) => failure,
            Ok(_) => panic!("injected mixed import advice failure was ignored"),
        };
        assert_eq!(failure.error(), MemfdError::Native(libc::EIO));
        drop(failure);
        drop(coordinator);
        assert_eq!(
            process_resource_baseline(),
            baseline,
            "advice operation {operation}"
        );
    }

    let deadline = batch_deadline();
    let coordinator = LinuxMixedDirectionBatch::prepare(
        portable_batch(&regions),
        NativeAuthorityProfile::LinuxMdweV1,
        deadline,
    )
    .unwrap();
    let manifest = TransferManifest::new_with_authority(
        [0x78; 32],
        10,
        11,
        1,
        NativeAuthorityProfile::LinuxMdweV1,
        coordinator.manifest_entries(),
    )
    .unwrap();
    let expected = LinuxExpectedMixedDirectionBatch::prepare(
        expected_batch(&regions),
        SessionLimits::default(),
        deadline,
    )
    .unwrap();
    let imported = expected
        .import(&manifest, duplicate_mixed_descriptors(&coordinator))
        .unwrap();
    drop(imported);
    drop(coordinator);
    assert_eq!(process_resource_baseline(), baseline);
}

#[test]
fn mixed_receiver_import_nth_failure_restores_resources() {
    let status = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "backend::linux_vnext::memory::tests::isolated_mixed_receiver_import_nth_failure_helper",
            "--ignored",
            "--nocapture",
        ])
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
#[ignore = "spawned alone by mixed_direction_batch_nth_failure_restores_resources"]
fn isolated_mixed_direction_batch_nth_failure_helper() {
    let baseline = process_resource_baseline();
    let regions: Vec<_> = (1..=16)
        .rev()
        .map(|id| {
            let writer = if id % 2 == 0 {
                WriterEndpoint::Coordinator
            } else {
                WriterEndpoint::Receiver
            };
            (id as u128, writer, id * 17)
        })
        .collect();
    for failure in [1, 2, 4, 16] {
        assert!(matches!(
            LinuxMixedDirectionBatch::prepare_with_failure_for_test(
                portable_batch(&regions),
                NativeAuthorityProfile::LinuxMdweV1,
                batch_deadline(),
                failure,
            ),
            Err(MemfdError::Native(libc::EIO))
        ));
        assert_eq!(process_resource_baseline(), baseline, "failure {failure}");
    }

    let prepared = LinuxMixedDirectionBatch::prepare(
        portable_batch(&regions),
        NativeAuthorityProfile::LinuxMdweV1,
        batch_deadline(),
    )
    .unwrap();
    drop(prepared);
    assert_eq!(process_resource_baseline(), baseline);
}

#[test]
fn mixed_direction_batch_nth_failure_restores_resources() {
    let status = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "backend::linux_vnext::memory::tests::isolated_mixed_direction_batch_nth_failure_helper",
            "--ignored",
            "--nocapture",
        ])
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
fn mixed_direction_batch_rejects_profile_and_expiry_before_native_preparation() {
    assert!(matches!(
        LinuxMixedDirectionBatch::prepare(
            portable_batch(&[
                (1, WriterEndpoint::Coordinator, 1),
                (2, WriterEndpoint::Receiver, 1),
            ]),
            NativeAuthorityProfile::Legacy,
            batch_deadline(),
        ),
        Err(MemfdError::WrongProvenance)
    ));

    let expired = AbsoluteDeadline::after(Duration::from_millis(1)).unwrap();
    while !expired.is_expired() {
        core::hint::spin_loop();
    }
    assert!(matches!(
        LinuxMixedDirectionBatch::prepare(
            portable_batch(&[
                (1, WriterEndpoint::Coordinator, 1),
                (2, WriterEndpoint::Receiver, 1),
            ]),
            NativeAuthorityProfile::LinuxMdweV1,
            expired,
        ),
        Err(MemfdError::DeadlineExpired)
    ));
}

#[test]
fn coordinator_writer_batch_rejects_profile_direction_and_object_substitution() {
    assert!(matches!(
        LinuxCoordinatorWriterBatch::prepare(
            portable_batch(&[(1, WriterEndpoint::Coordinator, 1)]),
            NativeAuthorityProfile::Legacy,
            batch_deadline(),
        ),
        Err(MemfdError::WrongProvenance)
    ));
    assert!(matches!(
        LinuxCoordinatorWriterBatch::prepare(
            portable_batch(&[(1, WriterEndpoint::Receiver, 1)]),
            NativeAuthorityProfile::LinuxMdweV1,
            batch_deadline(),
        ),
        Err(MemfdError::UnsupportedDirection)
    ));

    let mut batch = LinuxCoordinatorWriterBatch::prepare(
        portable_batch(&[
            (1, WriterEndpoint::Coordinator, 1),
            (2, WriterEndpoint::Coordinator, 1),
        ]),
        NativeAuthorityProfile::LinuxMdweV1,
        batch_deadline(),
    )
    .unwrap();
    batch.entries[0].prepared.reader_capability =
        duplicate(&batch.entries[1].prepared.reader_capability).unwrap();
    assert_eq!(batch.revalidate(), Err(MemfdError::WrongObject));
}

#[test]
fn receiver_expectation_rejects_direction_limits_and_expired_deadline_locally() {
    let limits = SessionLimits {
        max_regions_per_batch: 2,
        max_region_bytes: 4096,
        max_batch_bytes: 8192,
        ..SessionLimits::default()
    };
    assert!(matches!(
        LinuxExpectedCoordinatorWriterBatch::prepare(
            expected_batch(&[(1, WriterEndpoint::Receiver, 1)]),
            limits,
            batch_deadline(),
        ),
        Err(MemfdError::UnsupportedDirection)
    ));
    assert!(matches!(
        LinuxExpectedCoordinatorWriterBatch::prepare(
            expected_batch(&[(1, WriterEndpoint::Coordinator, 4097)]),
            limits,
            batch_deadline(),
        ),
        Err(MemfdError::InvalidBatch)
    ));
    assert!(matches!(
        LinuxExpectedCoordinatorWriterBatch::prepare(
            expected_batch(&[
                (1, WriterEndpoint::Coordinator, 1),
                (2, WriterEndpoint::Coordinator, 1),
            ]),
            SessionLimits {
                max_active_regions: 1,
                ..limits
            },
            batch_deadline(),
        ),
        Err(MemfdError::InvalidBatch)
    ));
    assert!(matches!(
        LinuxExpectedCoordinatorWriterBatch::prepare(
            expected_batch(&[(1, WriterEndpoint::Coordinator, 1)]),
            SessionLimits {
                max_active_bytes: 4095,
                ..limits
            },
            batch_deadline(),
        ),
        Err(MemfdError::InvalidBatch)
    ));
    let expired = AbsoluteDeadline::after(Duration::from_millis(1)).unwrap();
    while !expired.is_expired() {
        core::hint::spin_loop();
    }
    assert!(matches!(
        LinuxExpectedCoordinatorWriterBatch::prepare(
            expected_batch(&[(1, WriterEndpoint::Coordinator, 1)]),
            limits,
            expired,
        ),
        Err(MemfdError::DeadlineExpired)
    ));
}

#[test]
fn receiver_imports_exact_final_sealed_objects_and_rejects_ordinal_substitution() {
    let regions = [
        (1, WriterEndpoint::Coordinator, 17),
        (2, WriterEndpoint::Coordinator, 8193),
    ];
    let deadline = batch_deadline();
    let coordinator = LinuxCoordinatorWriterBatch::prepare(
        portable_batch(&regions),
        NativeAuthorityProfile::LinuxMdweV1,
        deadline,
    )
    .unwrap();
    let manifest = TransferManifest::new_with_authority(
        [0x61; 32],
        10,
        11,
        1,
        NativeAuthorityProfile::LinuxMdweV1,
        coordinator.manifest_entries(),
    )
    .unwrap();
    let expected = LinuxExpectedCoordinatorWriterBatch::prepare(
        expected_batch(&regions),
        SessionLimits::default(),
        deadline,
    )
    .unwrap();
    assert!(expected.matches_manifest(&manifest));
    let descriptors = coordinator
        .entries
        .iter()
        .map(|entry| duplicate(&entry.prepared.reader_capability).unwrap())
        .collect();
    let imported = expected.import(&manifest, descriptors).unwrap();
    assert_eq!(imported.len(), 2);
    for (ordinal, (id, _, logical_len)) in regions.into_iter().enumerate() {
        for offset in 0..logical_len {
            assert_eq!(imported.read_for_test(ordinal, offset), id as u8);
        }
        let (_, _, mapped_len) = imported.object_key_for_test(ordinal);
        assert!(mapping_fails(
            imported.descriptor_for_test(ordinal).as_raw_fd(),
            libc::PROT_READ | libc::PROT_WRITE,
            mapped_len,
        ));
    }

    let expected = LinuxExpectedCoordinatorWriterBatch::prepare(
        expected_batch(&regions),
        SessionLimits::default(),
        deadline,
    )
    .unwrap();
    let descriptors = coordinator
        .entries
        .iter()
        .rev()
        .map(|entry| duplicate(&entry.prepared.reader_capability).unwrap())
        .collect();
    assert!(matches!(
        expected.import(&manifest, descriptors),
        Err(failure) if failure.error() == MemfdError::InvalidObject
    ));
}

#[test]
fn receiver_writer_batches_import_before_final_sealing_for_one_to_sixteen() {
    for count in [1, 2, 4, 16] {
        let regions: Vec<_> = (1..=count)
            .rev()
            .map(|id| (id as u128, WriterEndpoint::Receiver, id * 17))
            .collect();
        let deadline = batch_deadline();
        let mut coordinator = LinuxReceiverWriterBatch::prepare(
            portable_batch(&regions),
            NativeAuthorityProfile::LinuxMdweV1,
            deadline,
        )
        .unwrap();
        coordinator.revalidate_prefix().unwrap();
        let manifest = TransferManifest::new_with_authority(
            [0x71; 32],
            10,
            11,
            1,
            NativeAuthorityProfile::LinuxMdweV1,
            coordinator.manifest_entries(),
        )
        .unwrap();
        let canonical: Vec<_> = (1..=count)
            .map(|id| (id as u128, WriterEndpoint::Receiver, id * 17))
            .collect();
        let expected = LinuxExpectedReceiverWriterBatch::prepare(
            expected_batch(&canonical),
            SessionLimits::default(),
            deadline,
        )
        .unwrap();
        assert!(expected.matches_manifest(&manifest));
        let descriptors = coordinator
            .entries
            .iter()
            .map(|entry| duplicate(&entry.fd).unwrap())
            .collect();
        let mut imported = expected.import(&manifest, descriptors).unwrap();
        assert_eq!(imported.len(), count);
        for entry in &coordinator.entries {
            assert_eq!(current_seals(entry.fd.as_raw_fd()), PREFIX_SEALS);
            assert!(!mapping_fails(
                entry.fd.as_raw_fd(),
                libc::PROT_READ | libc::PROT_WRITE,
                entry.key.mapped_len,
            ));
        }

        coordinator.seal_after_import().unwrap();
        imported.verify_final_seals(deadline).unwrap();
        for ordinal in 0..count {
            let logical_len = (ordinal + 1) * 17;
            assert_eq!(
                current_seals(imported.descriptor_for_test(ordinal).as_raw_fd()),
                FINAL_SEALS
            );
            assert!(mapping_fails(
                imported.descriptor_for_test(ordinal).as_raw_fd(),
                libc::PROT_READ | libc::PROT_WRITE,
                coordinator.entries[ordinal].key.mapped_len,
            ));
            for offset in 0..logical_len {
                imported.write_for_test(ordinal, offset, (ordinal + 1) as u8);
                assert_eq!(
                    coordinator.read_for_test(ordinal, offset),
                    (ordinal + 1) as u8
                );
            }
        }
    }
}

#[test]
fn receiver_writer_expectation_and_preparation_reject_wrong_direction_locally() {
    let deadline = batch_deadline();
    assert!(matches!(
        LinuxReceiverWriterBatch::prepare(
            portable_batch(&[(1, WriterEndpoint::Coordinator, 17)]),
            NativeAuthorityProfile::LinuxMdweV1,
            deadline,
        ),
        Err(MemfdError::UnsupportedDirection)
    ));
    assert!(matches!(
        LinuxExpectedReceiverWriterBatch::prepare(
            expected_batch(&[(1, WriterEndpoint::Coordinator, 17)]),
            SessionLimits::default(),
            deadline,
        ),
        Err(MemfdError::UnsupportedDirection)
    ));
}

#[test]
#[ignore = "spawned alone by coordinator_writer_batch_rejects_expired_deadline_before_native_conversion"]
fn isolated_coordinator_writer_batch_rejects_expired_deadline_before_native_conversion() {
    let baseline = process_resource_baseline();
    let expired = AbsoluteDeadline::after(Duration::from_millis(1)).unwrap();
    while !expired.is_expired() {
        core::hint::spin_loop();
    }
    assert!(matches!(
        LinuxCoordinatorWriterBatch::prepare(
            portable_batch(&[(1, WriterEndpoint::Coordinator, 1)]),
            NativeAuthorityProfile::LinuxMdweV1,
            expired,
        ),
        Err(MemfdError::DeadlineExpired)
    ));
    assert_eq!(process_resource_baseline(), baseline);
}

#[test]
fn coordinator_writer_batch_rejects_expired_deadline_before_native_conversion() {
    let status = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "backend::linux_vnext::memory::tests::isolated_coordinator_writer_batch_rejects_expired_deadline_before_native_conversion",
            "--ignored",
            "--nocapture",
        ])
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
fn coordinator_writer_batch_drop_clears_pending_shared_bytes() {
    let batch = LinuxCoordinatorWriterBatch::prepare(
        portable_batch(&[(1, WriterEndpoint::Coordinator, 73)]),
        NativeAuthorityProfile::LinuxMdweV1,
        batch_deadline(),
    )
    .unwrap();
    let mapped_len = batch.entries[0].prepared.mapping.len;
    let retained = duplicate(&batch.entries[0].prepared.reader_capability).unwrap();
    drop(batch);

    let cleared = VmMapping::map(retained.as_raw_fd(), mapped_len, libc::PROT_READ).unwrap();
    for offset in 0..mapped_len {
        // SAFETY: the retained read-only mapping covers this complete range.
        assert_eq!(
            unsafe { core::ptr::read_volatile(cleared.base.as_ptr().add(offset)) },
            0
        );
    }
}

fn process_resource_baseline() -> (usize, usize) {
    let fds = std::fs::read_dir("/proc/self/fd").unwrap().count();
    let maps = std::fs::read_to_string("/proc/self/maps")
        .unwrap()
        .lines()
        // Sanitizer runtimes may lazily add unrelated process mappings. This
        // baseline is specifically responsible for vNext memfd VM ownership.
        .filter(|line| line.contains("native-ipc-vnext"))
        .count();
    (fds, maps)
}

#[test]
#[ignore = "spawned alone by coordinator_writer_batch_nth_failure_restores_resources"]
fn isolated_coordinator_writer_batch_nth_failure_helper() {
    let baseline = process_resource_baseline();
    for failure in [1, 2, 4, 16] {
        let regions: Vec<_> = (1..=16)
            .map(|id| {
                let writer = if id == failure {
                    WriterEndpoint::Receiver
                } else {
                    WriterEndpoint::Coordinator
                };
                (id as u128, writer, id * 17)
            })
            .collect();
        assert!(matches!(
            LinuxCoordinatorWriterBatch::prepare(
                portable_batch(&regions),
                NativeAuthorityProfile::LinuxMdweV1,
                batch_deadline(),
            ),
            Err(MemfdError::UnsupportedDirection)
        ));
        assert_eq!(process_resource_baseline(), baseline, "failure {failure}");
    }
}

#[test]
fn coordinator_writer_batch_nth_failure_restores_resources() {
    let status = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "backend::linux_vnext::memory::tests::isolated_coordinator_writer_batch_nth_failure_helper",
            "--ignored",
            "--nocapture",
        ])
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
#[ignore = "spawned alone by receiver_import_nth_failure_restores_resources"]
fn isolated_receiver_import_nth_failure_helper() {
    let regions: Vec<_> = (1..=16)
        .map(|id| (id as u128, WriterEndpoint::Coordinator, id * 17))
        .collect();
    let deadline = batch_deadline();
    let coordinator = LinuxCoordinatorWriterBatch::prepare(
        portable_batch(&regions),
        NativeAuthorityProfile::LinuxMdweV1,
        deadline,
    )
    .unwrap();
    let manifest = TransferManifest::new_with_authority(
        [0x62; 32],
        10,
        11,
        1,
        NativeAuthorityProfile::LinuxMdweV1,
        coordinator.manifest_entries(),
    )
    .unwrap();
    let baseline = process_resource_baseline();
    for failure in [1, 2, 4, 16] {
        let expected = LinuxExpectedCoordinatorWriterBatch::prepare(
            expected_batch(&regions),
            SessionLimits::default(),
            deadline,
        )
        .unwrap();
        let mut descriptors: Vec<OwnedFd> = coordinator
            .entries
            .iter()
            .map(|entry| duplicate(&entry.prepared.reader_capability).unwrap())
            .collect();
        descriptors[failure - 1] = std::fs::File::open("/dev/null").unwrap().into();
        assert!(matches!(
            expected.import(&manifest, descriptors),
            Err(failure) if failure.error() == MemfdError::InvalidObject
        ));
        assert_eq!(process_resource_baseline(), baseline, "failure {failure}");
    }
}

#[test]
fn receiver_import_nth_failure_restores_resources() {
    let status = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "backend::linux_vnext::memory::tests::isolated_receiver_import_nth_failure_helper",
            "--ignored",
            "--nocapture",
        ])
        .status()
        .unwrap();
    assert!(status.success());
}
