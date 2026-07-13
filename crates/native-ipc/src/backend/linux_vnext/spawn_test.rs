use super::super::memory::{
    LinuxCoordinatorWriterBatch, LinuxMixedDirectionBatch, LinuxReceiverWriterBatch, MemfdError,
};
use super::*;
use crate::backend::accepted_control::{
    AcceptedControlError, LinuxActivationError, LinuxCapabilityBatchError,
    LinuxCoordinatorCommittedMixedDirectionBatch, LinuxCoordinatorMixedDirectionTransaction,
    LinuxReceiverCommittedMixedDirectionBatch, LinuxReceiverMixedDirectionTransaction,
};
use crate::batch::{ExpectedBatch, ExpectedRegion, TransferBatch};
use crate::control::{ControlError, ControlFrame, ControlState};
use crate::protocol::{ManifestEntry, NativeRegionSpec, PeerAccess, TransferManifest};
use crate::region::{PrivateRegion, RegionId, RegionOptions, RegionSpec, WriterEndpoint};
use static_assertions::{assert_impl_all, assert_not_impl_any};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

const PR_GET_MDWE: libc::c_int = 66;

assert_impl_all!(UnauthenticatedLinuxSpawn: Send);
assert_not_impl_any!(UnauthenticatedLinuxSpawn: Sync, Clone);
assert_impl_all!(NegotiatingLinuxSpawn: Send);
assert_not_impl_any!(NegotiatingLinuxSpawn: Sync, Clone);
assert_impl_all!(ReceiverNegotiatingState: Send);
assert_not_impl_any!(ReceiverNegotiatingState: Sync, Clone);
assert_impl_all!(AcceptedLinuxSpawn: Send);
assert_not_impl_any!(AcceptedLinuxSpawn: Sync, Clone);
assert_impl_all!(AcceptedLinuxReceiver: Send);
assert_not_impl_any!(AcceptedLinuxReceiver: Sync, Clone);
assert_impl_all!(ReceiverDecisionPending: Send);
assert_not_impl_any!(ReceiverDecisionPending: Sync, Clone);
assert_impl_all!(RejectedLinuxReceiver: Send);
assert_not_impl_any!(RejectedLinuxReceiver: Sync, Clone);
assert_impl_all!(CoordinatorAcceptedEvidenceOwner: Send);
assert_not_impl_any!(CoordinatorAcceptedEvidenceOwner: Sync, Clone);
assert_impl_all!(ReceiverAcceptedEvidenceOwner: Send);
assert_not_impl_any!(ReceiverAcceptedEvidenceOwner: Sync, Clone);
assert_impl_all!(CoordinatorLinuxControlTransport: Send, AuthenticatedZeroRightsTransport, CoordinatorCapabilityTransport, OwnedChildLifecycle);
assert_not_impl_any!(CoordinatorLinuxControlTransport: Sync, Clone, ReceiverCapabilityTransport);
assert_impl_all!(ReceiverLinuxControlTransport: Send, AuthenticatedZeroRightsTransport, ReceiverCapabilityTransport);
assert_not_impl_any!(ReceiverLinuxControlTransport: Sync, Clone, CoordinatorCapabilityTransport, OwnedChildLifecycle);
assert_impl_all!(CoordinatorAcceptedControl: Send);
assert_not_impl_any!(CoordinatorAcceptedControl: Sync, Clone);
assert_impl_all!(ReceiverAcceptedControl: Send);
assert_not_impl_any!(ReceiverAcceptedControl: Sync, Clone);
assert_impl_all!(LinuxCoordinatorMixedDirectionTransaction<'static>: Send);
assert_not_impl_any!(LinuxCoordinatorMixedDirectionTransaction<'static>: Sync, Clone);
assert_impl_all!(LinuxReceiverMixedDirectionTransaction<'static>: Send);
assert_not_impl_any!(LinuxReceiverMixedDirectionTransaction<'static>: Sync, Clone);
assert_impl_all!(LinuxCoordinatorCommittedMixedDirectionBatch: Send);
assert_not_impl_any!(LinuxCoordinatorCommittedMixedDirectionBatch: Sync, Clone);
assert_impl_all!(LinuxReceiverCommittedMixedDirectionBatch: Send);
assert_not_impl_any!(LinuxReceiverCommittedMixedDirectionBatch: Sync, Clone);

const APPLICATION_CONTROL_KIND: u32 = 0x8000_0047;

fn deadline() -> AbsoluteDeadline {
    AbsoluteDeadline::after(Duration::from_secs(5)).unwrap()
}

fn mixed_direction_mapped_bytes(count: usize) -> u64 {
    // SAFETY: sysconf has no pointer arguments.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    assert!(page > 0);
    let page = page as usize;
    (1..=count)
        .map(|id| (id * 17).div_ceil(page) * page)
        .map(|bytes| bytes as u64)
        .sum()
}

fn helper_arguments() -> Vec<OsString> {
    [
        "native-ipc-spawn-helper",
        "--exact",
        "backend::linux_vnext::spawn::tests::spawn_helper",
        "--ignored",
        "--nocapture",
    ]
    .into_iter()
    .map(OsString::from)
    .collect()
}

fn hello_offer(payload_len: usize) -> LinuxHelloOffer {
    LinuxHelloOffer {
        supported_features: FeatureBits([3, 0]),
        required_features: FeatureBits::default(),
        limits: SessionLimits {
            max_bootstrap_payload_bytes: MAX_LINUX_HELLO_PAYLOAD as u32,
            ..SessionLimits::default()
        },
        application_payload: (0..payload_len).map(|index| index as u8).collect(),
    }
}

fn native_capability_frame(transaction: u64, count: usize) -> CapabilityFrame {
    let entries = (1..=count)
        .map(|ordinal| {
            let native =
                NativeRegionSpec::new(ordinal as u128, [ordinal as u8; 16], 1, 1, 4096).unwrap();
            ManifestEntry::from_native(native, PeerAccess::ReadOnly)
        })
        .collect();
    let manifest = TransferManifest::new([0x41; 32], 10, 11, transaction, entries).unwrap();
    CapabilityFrame::from_manifest(&manifest)
}

fn portable_coordinator_writer_batch(count: usize) -> TransferBatch {
    let mut batch = TransferBatch::new(16, 1024 * 1024).unwrap();
    for id in (1..=count).rev() {
        let mut region = PrivateRegion::allocate(RegionOptions::fixed(id * 17)).unwrap();
        region.initialize(|bytes| bytes.fill(id as u8));
        batch
            .add(
                region
                    .prepare(RegionSpec {
                        id: RegionId::new(id as u128).unwrap(),
                        writer: WriterEndpoint::Coordinator,
                    })
                    .unwrap(),
            )
            .unwrap();
    }
    batch
}

fn portable_receiver_writer_batch(count: usize) -> TransferBatch {
    let mut batch = TransferBatch::new(16, 1024 * 1024).unwrap();
    for id in (1..=count).rev() {
        let mut region = PrivateRegion::allocate(RegionOptions::fixed(id * 17)).unwrap();
        region.initialize(|bytes| bytes.fill(0));
        batch
            .add(
                region
                    .prepare(RegionSpec {
                        id: RegionId::new(id as u128).unwrap(),
                        writer: WriterEndpoint::Receiver,
                    })
                    .unwrap(),
            )
            .unwrap();
    }
    batch
}

fn portable_mixed_direction_batch(count: usize) -> TransferBatch {
    let mut batch = TransferBatch::new(16, 1024 * 1024).unwrap();
    for id in (1..=count).rev() {
        let mut region = PrivateRegion::allocate(RegionOptions::fixed(id * 17)).unwrap();
        region.initialize(|bytes| bytes.fill(id as u8));
        batch
            .add(
                region
                    .prepare(RegionSpec {
                        id: RegionId::new(id as u128).unwrap(),
                        writer: if id % 2 == 0 {
                            WriterEndpoint::Receiver
                        } else {
                            WriterEndpoint::Coordinator
                        },
                    })
                    .unwrap(),
            )
            .unwrap();
    }
    batch
}

fn expected_coordinator_writer_batch(count: usize) -> ExpectedBatch {
    expected_coordinator_writer_batch_with_first_delta(count, 0)
}

fn expected_receiver_writer_batch(count: usize) -> ExpectedBatch {
    ExpectedBatch::try_from_specs(
        (1..=count)
            .rev()
            .map(|id| ExpectedRegion {
                id: RegionId::new(id as u128).unwrap(),
                writer: WriterEndpoint::Receiver,
                logical_len: id * 17,
            })
            .collect(),
    )
    .unwrap()
}

fn expected_mixed_direction_batch(count: usize) -> ExpectedBatch {
    expected_mixed_direction_batch_with_first_delta(count, 0)
}

fn expected_mixed_direction_batch_with_first_delta(
    count: usize,
    first_delta: usize,
) -> ExpectedBatch {
    ExpectedBatch::try_from_specs(
        (1..=count)
            .rev()
            .map(|id| ExpectedRegion {
                id: RegionId::new(id as u128).unwrap(),
                writer: if id % 2 == 0 {
                    WriterEndpoint::Receiver
                } else {
                    WriterEndpoint::Coordinator
                },
                logical_len: id * 17 + usize::from(id == 1) * first_delta,
            })
            .collect(),
    )
    .unwrap()
}

fn expected_coordinator_writer_batch_with_first_delta(
    count: usize,
    first_delta: usize,
) -> ExpectedBatch {
    ExpectedBatch::try_from_specs(
        (1..=count)
            .rev()
            .map(|id| ExpectedRegion {
                id: RegionId::new(id as u128).unwrap(),
                writer: WriterEndpoint::Coordinator,
                logical_len: id * 17 + usize::from(id == 1) * first_delta,
            })
            .collect(),
    )
    .unwrap()
}

fn local_packet_credentials() -> PacketCredentials {
    PacketCredentials {
        pid: std::process::id(),
        // SAFETY: scalar credential queries have no pointer arguments.
        uid: unsafe { libc::getuid() },
        // SAFETY: scalar credential queries have no pointer arguments.
        gid: unsafe { libc::getgid() },
    }
}

#[test]
fn linux_control_limit_is_capped_before_both_hellos_and_transcript() {
    assert_eq!(
        crate::control::control_wire_len(MAX_LINUX_CONTROL_PAYLOAD as usize),
        Some(MAX_ZERO_RIGHTS_PACKET_BYTES)
    );

    let lower = MAX_LINUX_CONTROL_PAYLOAD - 1;
    let mut lower_offer = hello_offer(0);
    lower_offer.limits.max_control_payload_bytes = lower;
    assert_eq!(
        validate_linux_offer(lower_offer)
            .unwrap()
            .limits
            .max_control_payload_bytes,
        lower
    );

    for offered in [
        SessionLimits::default().max_control_payload_bytes,
        crate::session::HARD_MAX_CONTROL_PAYLOAD_BYTES,
    ] {
        let mut offer = hello_offer(0);
        offer.limits.max_control_payload_bytes = offered;
        assert_eq!(
            validate_linux_offer(offer)
                .unwrap()
                .limits
                .max_control_payload_bytes,
            MAX_LINUX_CONTROL_PAYLOAD
        );
    }

    let mut zero = hello_offer(0);
    zero.limits.max_control_payload_bytes = 0;
    assert!(matches!(
        validate_linux_offer(zero),
        Err(LinuxSpawnError::NativeNegotiation(
            NegotiationError::ZeroLimit
        ))
    ));

    let atomics = discover_atomic_capabilities().unwrap();
    let nonce = [0x61; NONCE_LEN];
    let coordinator_offer = validate_linux_offer(hello_offer(0)).unwrap();
    let receiver_offer = validate_linux_offer(hello_offer(0)).unwrap();
    let coordinator =
        make_hello(SenderRole::Coordinator, nonce, coordinator_offer, atomics).unwrap();
    let receiver = make_hello(SenderRole::Receiver, nonce, receiver_offer, atomics).unwrap();
    assert_eq!(
        coordinator.limits.max_control_payload_bytes,
        MAX_LINUX_CONTROL_PAYLOAD
    );
    assert_eq!(
        receiver.limits.max_control_payload_bytes,
        MAX_LINUX_CONTROL_PAYLOAD
    );
    let mut transcript =
        NegotiatedTranscript::from_hellos(HelloPair::new(coordinator, receiver), atomics).unwrap();
    let challenge = DecisionChallenge::from_os_csprng([0x62; 16]).unwrap();
    let coordinator_accept = transcript.coordinator_accept(challenge).unwrap();
    transcript
        .validate_accept(coordinator_accept, SenderRole::Coordinator)
        .unwrap();
    let receiver_accept = transcript.receiver_accept().unwrap();
    transcript
        .validate_accept(receiver_accept, SenderRole::Receiver)
        .unwrap();
    assert_eq!(
        transcript
            .take_accepted_facts()
            .unwrap()
            .effective_limits()
            .max_control_payload_bytes,
        MAX_LINUX_CONTROL_PAYLOAD
    );
}

#[test]
#[ignore = "spawned alone by accepted_capability_record_transport_is_exact_bounded_and_owns_installed_fds"]
fn isolated_accepted_capability_record_transport_is_exact_bounded_and_owns_installed_fds() {
    let credentials = local_packet_credentials();
    let file = std::fs::File::open("/dev/null").unwrap();

    for count in [1, 2, 16] {
        let frame = native_capability_frame(count as u64, count);
        let (mut sender, mut receiver) = SeqPacketEndpoint::pair().unwrap();
        let raw = vec![file.as_raw_fd(); count];
        let mut sender_poisoned = false;
        send_accepted_capability_record(
            &mut sender,
            None,
            &mut sender_poisoned,
            &frame,
            &raw,
            deadline(),
        )
        .unwrap();
        let before_receive = open_fd_count();
        let mut receiver_poisoned = false;
        let received = receive_accepted_capability_record(
            &mut receiver,
            None,
            credentials,
            &mut receiver_poisoned,
            &frame,
            deadline(),
        )
        .unwrap();
        assert_eq!(received.len(), count);
        assert_eq!(open_fd_count(), before_receive + count);
        for descriptor in &received.descriptors {
            // SAFETY: descriptor is live and F_GETFD has no pointer argument.
            assert_ne!(
                unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
                0
            );
        }
        drop(received);
        assert_eq!(open_fd_count(), before_receive);
    }

    let expected = native_capability_frame(21, 1);
    for count in [0, 2, 16] {
        let (mut sender, mut receiver) = SeqPacketEndpoint::pair().unwrap();
        sender
            .send(expected.as_bytes(), &vec![file.as_raw_fd(); count])
            .unwrap();
        let before_receive = open_fd_count();
        let mut poisoned = false;
        assert!(matches!(
            receive_accepted_capability_record(
                &mut receiver,
                None,
                credentials,
                &mut poisoned,
                &expected,
                deadline(),
            ),
            Err(SessionTransportError::MalformedRecord)
        ));
        assert_eq!(open_fd_count(), before_receive);
    }

    for hostile in [
        native_capability_frame(22, 1).as_bytes().to_vec(),
        b"NIPCAPP1".to_vec(),
    ] {
        let (mut sender, mut receiver) = SeqPacketEndpoint::pair().unwrap();
        sender.send(&hostile, &[file.as_raw_fd()]).unwrap();
        let before_receive = open_fd_count();
        let mut poisoned = false;
        assert!(matches!(
            receive_accepted_capability_record(
                &mut receiver,
                None,
                credentials,
                &mut poisoned,
                &expected,
                deadline(),
            ),
            Err(SessionTransportError::MalformedRecord)
        ));
        assert_eq!(open_fd_count(), before_receive);
    }

    let (mut sender, mut receiver) = SeqPacketEndpoint::pair().unwrap();
    sender
        .send(expected.as_bytes(), &[file.as_raw_fd()])
        .unwrap();
    let wrong = PacketCredentials {
        pid: credentials.pid.saturating_add(1),
        ..credentials
    };
    let before_receive = open_fd_count();
    let mut poisoned = false;
    assert!(matches!(
        receive_accepted_capability_record(
            &mut receiver,
            None,
            wrong,
            &mut poisoned,
            &expected,
            deadline(),
        ),
        Err(SessionTransportError::IdentityMismatch)
    ));
    assert_eq!(open_fd_count(), before_receive);
}

#[test]
fn accepted_capability_record_transport_is_exact_bounded_and_owns_installed_fds() {
    run_isolated(
        "backend::linux_vnext::spawn::tests::isolated_accepted_capability_record_transport_is_exact_bounded_and_owns_installed_fds",
    );
}

fn open_fd_count() -> usize {
    std::fs::read_dir("/proc/self/fd").unwrap().count()
}

fn open_task_count() -> usize {
    std::fs::read_dir("/proc/self/task").unwrap().count()
}

fn open_vnext_map_count() -> usize {
    std::fs::read_to_string("/proc/self/maps")
        .unwrap()
        .lines()
        .filter(|line| line.contains("native-ipc-vnext"))
        .count()
}

fn wait_for_baseline(fds: usize, tasks: usize, child_pid: libc::pid_t, deadline: AbsoluteDeadline) {
    loop {
        let children = std::fs::read_to_string("/proc/thread-self/children").unwrap();
        let child_absent = !children
            .split_ascii_whitespace()
            .any(|value| value.parse::<libc::pid_t>() == Ok(child_pid));
        if open_fd_count() == fds && open_task_count() == tasks && child_absent {
            break;
        }
        assert!(
            !deadline.is_expired(),
            "spawn resources did not return to baseline"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    // SAFETY: WNOHANG cannot block. ECHILD proves this exact clone-time PID has
    // no zombie or other waitable direct-child status left in this process.
    assert_eq!(
        unsafe { libc::waitpid(child_pid, core::ptr::null_mut(), libc::WNOHANG) },
        -1
    );
    assert_eq!(
        io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
}

fn assert_immediate_child_and_fd_cleanup(
    fds: usize,
    tasks: usize,
    child_pid: libc::pid_t,
    task_deadline: AbsoluteDeadline,
) {
    let children = std::fs::read_to_string("/proc/thread-self/children").unwrap();
    assert!(
        !children
            .split_ascii_whitespace()
            .any(|value| value.parse::<libc::pid_t>() == Ok(child_pid)),
        "evidence-construction error returned before the exact child was reaped"
    );
    assert_eq!(open_fd_count(), fds);
    // SAFETY: WNOHANG cannot block. ECHILD proves the failure path consumed
    // every waitable status for this exact clone-time child before returning.
    assert_eq!(
        unsafe { libc::waitpid(child_pid, core::ptr::null_mut(), libc::WNOHANG) },
        -1
    );
    assert_eq!(
        io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
    // The detached reaper publishes exact child completion before its own
    // thread can cease to exist. Its transient task is not child authority;
    // wait only to isolate the next fixture after the child/ECHILD/fd facts
    // above have already proved synchronous malicious-child cleanup.
    while open_task_count() != tasks {
        assert!(
            !task_deadline.is_expired(),
            "exact-child reaper task did not exit"
        );
        std::thread::yield_now();
    }
}

fn spawn(
    fault: SpawnFault,
    operation_deadline: AbsoluteDeadline,
) -> Result<UnauthenticatedLinuxSpawn, LinuxSpawnError> {
    spawn_unauthenticated_with_fault(
        &std::env::current_exe().unwrap(),
        &helper_arguments(),
        &[],
        fault,
        operation_deadline,
    )
}

#[test]
#[ignore = "exec target used only by private atomic spawn tests"]
fn spawn_helper() {
    let raw: RawFd = std::env::var("NATIVE_IPC_VNEXT_BOOTSTRAP_FD")
        .unwrap()
        .parse()
        .unwrap();
    if let Ok(encoded) = std::env::var("NATIVE_IPC_VNEXT_POST_REEXEC_DECISION") {
        // SAFETY: the re-exec helper uniquely owns the intentionally inherited fd.
        let mut endpoint = unsafe { SeqPacketEndpoint::from_inherited(raw) }.unwrap();
        let bytes = decode_hex(&encoded);
        send_socket_before(&mut endpoint, &bytes, deadline()).unwrap();
        loop {
            // SAFETY: exact coordinator cleanup terminates this helper.
            unsafe { libc::pause() };
        }
    }
    // Check inherited state before any operation that could open/reuse an fd.
    for closed in std::env::var("NATIVE_IPC_VNEXT_EXPECT_CLOSED")
        .unwrap()
        .split(',')
    {
        let mut parts = closed.split(':');
        let fd = parts.next().unwrap().parse::<RawFd>().unwrap();
        let expected_device = parts.next().unwrap().parse::<u64>().unwrap();
        let expected_inode = parts.next().unwrap().parse::<u64>().unwrap();
        assert!(parts.next().is_none());
        // The ELF loader may reuse a closed numeric slot. It must never still
        // identify the original held image, pipe, or socket object.
        // SAFETY: status is complete writable output for this scalar fd query.
        let mut status: libc::stat = unsafe { core::mem::zeroed() };
        let result = unsafe { libc::fstat(fd, &mut status) };
        if result == 0 {
            assert_ne!(
                (status.st_dev, status.st_ino),
                (expected_device, expected_inode)
            );
        } else {
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
        }
    }
    // SAFETY: the trusted raw child intentionally cleared CLOEXEC on only this slot.
    assert_eq!(unsafe { libc::fcntl(raw, libc::F_GETFD) }, 0);
    let mut socket_type = 0_i32;
    let mut length = core::mem::size_of::<i32>() as libc::socklen_t;
    // SAFETY: output and its exact length remain valid for getsockopt.
    assert_eq!(
        unsafe {
            libc::getsockopt(
                raw,
                libc::SOL_SOCKET,
                libc::SO_TYPE,
                (&mut socket_type as *mut i32).cast(),
                &mut length,
            )
        },
        0
    );
    assert_eq!(socket_type, libc::SOCK_SEQPACKET);
    // SAFETY: scalar MDWE and identity queries have no pointer arguments.
    assert_eq!(
        unsafe { libc::prctl(PR_GET_MDWE, 0, 0, 0, 0) } as libc::c_ulong,
        PR_MDWE_REFUSE_EXEC_GAIN
    );
    let pid = unsafe { libc::getpid() };
    assert_eq!(unsafe { libc::getsid(0) }, pid);
    assert_eq!(unsafe { libc::getpgrp() }, pid);
    if let Ok(mode) = std::env::var("NATIVE_IPC_VNEXT_TEST_HELLO_LIFECYCLE") {
        consume_coordinator_then(raw, &mode);
    }
    if let Ok(mode) = std::env::var("NATIVE_IPC_VNEXT_TEST_MALICIOUS_HELLO") {
        send_malicious_receiver_hello(raw, &mode);
        loop {
            // SAFETY: exact-child cleanup terminates the disposable helper.
            unsafe { libc::pause() };
        }
    }
    if let Ok(receiver_payload_len) = std::env::var("NATIVE_IPC_VNEXT_TEST_HELLO") {
        let receiver_payload_len = receiver_payload_len.parse::<usize>().unwrap();
        let expected_coordinator_len = std::env::var("NATIVE_IPC_VNEXT_TEST_COORDINATOR_LEN")
            .unwrap()
            .parse::<usize>()
            .unwrap();
        let mut receiver_offer = hello_offer(receiver_payload_len);
        if let Ok(limit) = std::env::var("NATIVE_IPC_VNEXT_CONTROL_LIMIT") {
            receiver_offer.limits.max_control_payload_bytes = limit.parse().unwrap();
        }
        let state = receive_inherited_hello(raw, receiver_offer, deadline())
            .expect("receiver HELLO exchange");
        assert_eq!(
            state._peer_application_payload.len(),
            expected_coordinator_len
        );
        if let Ok(mode) = std::env::var("NATIVE_IPC_VNEXT_TEST_MALICIOUS_DECISION") {
            send_malicious_receiver_decision(state, &mode);
        } else if let Ok(decision) = std::env::var("NATIVE_IPC_VNEXT_TEST_DECISION") {
            let decision = match decision.as_str() {
                "accept" => ApplicationDecision::Accept,
                "reject" => ApplicationDecision::Reject(NonZeroU32::new(19).unwrap()),
                _ => panic!("unknown application decision"),
            };
            let pending = match state
                .await_coordinator_decision()
                .expect("coordinator decision")
            {
                CoordinatorDecisionOutcome::Pending(pending) => *pending,
                CoordinatorDecisionOutcome::Rejected { state, .. } => {
                    let _state = state;
                    loop {
                        // SAFETY: coordinator clean rejection terminates this helper.
                        unsafe { libc::pause() };
                    }
                }
            };
            match pending.decide(decision).expect("receiver decision") {
                DecisionOutcome::Accepted(accepted) => {
                    let evidence = accepted.into_evidence().unwrap();
                    let facts = evidence.facts();
                    // SAFETY: scalar process/credential queries have no pointers.
                    assert_eq!(facts.parent_pid(), unsafe { libc::getppid() } as u32);
                    // SAFETY: scalar process/credential queries have no pointers.
                    assert_eq!(facts.child_pid(), unsafe { libc::getpid() } as u32);
                    // SAFETY: scalar process/credential queries have no pointers.
                    assert_eq!(facts.parent_uid(), unsafe { libc::getuid() });
                    // SAFETY: scalar process/credential queries have no pointers.
                    assert_eq!(facts.parent_gid(), unsafe { libc::getgid() });
                    // SAFETY: scalar process/credential queries have no pointers.
                    assert_eq!(facts.child_uid(), unsafe { libc::getuid() });
                    // SAFETY: scalar process/credential queries have no pointers.
                    assert_eq!(facts.child_gid(), unsafe { libc::getgid() });
                    assert_ne!(facts.nonce(), [0; NONCE_LEN]);
                    if let Ok(mode) = std::env::var("NATIVE_IPC_VNEXT_CONTROL_MODE") {
                        run_accepted_control_receiver(evidence, &mode);
                    }
                    let _evidence = evidence;
                    loop {
                        // SAFETY: keep evidence state alive until coordinator cleanup.
                        unsafe { libc::pause() };
                    }
                }
                DecisionOutcome::Rejected { .. } => loop {
                    // SAFETY: coordinator clean rejection terminates this helper.
                    unsafe { libc::pause() };
                },
            }
        } else {
            loop {
                // SAFETY: keep the negotiating state and exact endpoint alive until
                // coordinator pidfd cleanup terminates this disposable helper.
                unsafe { libc::pause() };
            }
        }
    }
    loop {
        // SAFETY: pause blocks this disposable helper until exact pidfd cleanup.
        unsafe { libc::pause() };
    }
}

fn run_accepted_control_receiver(mut evidence: ReceiverAcceptedEvidenceOwner, mode: &str) -> ! {
    let parameters = evidence
        .evidence
        .session_parameters(NativeAuthorityProfile::LinuxMdweV1);
    let nonce = parameters.facts().nonce();
    let maximum = parameters.limits().max_control_payload_bytes;
    let raw_frame = |payload_len: usize| {
        let mut state = ControlState::new(nonce, payload_len.max(1) as u32).unwrap();
        let frame = ControlFrame {
            kind: APPLICATION_CONTROL_KIND,
            payload: vec![0x5a; payload_len],
        };
        let mut bytes = vec![0; state.encoded_len(&frame).unwrap()];
        state.encode_into(&frame, &mut bytes).unwrap();
        bytes
    };
    match mode {
        "echo" => {
            let expected = std::env::var("NATIVE_IPC_VNEXT_CONTROL_COORDINATOR_LEN")
                .unwrap()
                .parse::<usize>()
                .unwrap();
            let response = std::env::var("NATIVE_IPC_VNEXT_CONTROL_RECEIVER_LEN")
                .unwrap()
                .parse::<usize>()
                .unwrap();
            let mut control = evidence.into_control().unwrap();
            control
                .send(
                    &ControlFrame {
                        kind: APPLICATION_CONTROL_KIND,
                        payload: b"ready".to_vec(),
                    },
                    deadline(),
                )
                .unwrap();
            let received = control.receive(deadline()).unwrap();
            assert_eq!(received.kind, APPLICATION_CONTROL_KIND);
            assert_eq!(received.payload, vec![0x41; expected]);
            control
                .send(
                    &ControlFrame {
                        kind: APPLICATION_CONTROL_KIND,
                        payload: vec![0x52; response],
                    },
                    deadline(),
                )
                .unwrap();
            loop {
                let _control = &control;
                // SAFETY: coordinator exact-child cleanup terminates this helper.
                unsafe { libc::pause() };
            }
        }
        "coordinator-writer-batch"
        | "coordinator-writer-batch-wrong-logical"
        | "coordinator-writer-batch-invalid-object"
        | "coordinator-writer-batch-advice-failure" => {
            let count = std::env::var("NATIVE_IPC_VNEXT_CONTROL_RECEIVER_LEN")
                .unwrap()
                .parse::<usize>()
                .unwrap();
            let expected = expected_coordinator_writer_batch_with_first_delta(
                count,
                usize::from(mode.ends_with("wrong-logical")),
            );
            let events = Arc::new(Mutex::new(Vec::new()));
            let mut control = evidence.into_control().unwrap();
            control.observe_linux_receiver_poison_for_test(events.clone());
            control
                .send(
                    &ControlFrame {
                        kind: APPLICATION_CONTROL_KIND,
                        payload: b"ready".to_vec(),
                    },
                    deadline(),
                )
                .unwrap();
            let mut transaction = control
                .begin_linux_expected_coordinator_writer_batch(expected, deadline())
                .unwrap();
            transaction.observe_import_drop_for_test(events.clone());
            if mode.ends_with("advice-failure") {
                let failure = std::env::var("NATIVE_IPC_VNEXT_CONTROL_COORDINATOR_LEN")
                    .unwrap()
                    .parse::<usize>()
                    .unwrap();
                transaction.fail_import_advice_at_for_test(failure);
            }
            let received = transaction.receive();
            if mode.ends_with("wrong-logical") {
                assert!(matches!(
                    received,
                    Err(LinuxCapabilityBatchError::Control(
                        AcceptedControlError::Control(ControlError::NonCanonical)
                    ))
                ));
                drop(transaction);
                drop(control);
                std::process::exit(0);
            }
            if mode.ends_with("invalid-object") {
                assert!(matches!(
                    received,
                    Err(LinuxCapabilityBatchError::Memory(MemfdError::InvalidObject))
                ));
                assert_eq!(
                    events.lock().unwrap().as_slice(),
                    &["poison", "failed-import-drop"]
                );
                drop(transaction);
                assert_eq!(
                    control.send(
                        &ControlFrame {
                            kind: APPLICATION_CONTROL_KIND,
                            payload: Vec::new(),
                        },
                        deadline(),
                    ),
                    Err(AcceptedControlError::Control(ControlError::Poisoned))
                );
                drop(control);
                std::process::exit(0);
            }
            if mode.ends_with("advice-failure") {
                assert!(matches!(
                    received,
                    Err(LinuxCapabilityBatchError::Memory(MemfdError::Native(
                        libc::EIO
                    )))
                ));
                assert_eq!(
                    events.lock().unwrap().as_slice(),
                    &["poison", "failed-import-drop"]
                );
                drop(transaction);
                assert_eq!(
                    control.send(
                        &ControlFrame {
                            kind: APPLICATION_CONTROL_KIND,
                            payload: Vec::new(),
                        },
                        deadline(),
                    ),
                    Err(AcceptedControlError::Control(ControlError::Poisoned))
                );
                drop(control);
                std::process::exit(0);
            }
            received.unwrap();
            let imported = transaction.imported_for_test();
            assert_eq!(imported.len(), count);
            let final_seals = 0x20
                | libc::F_SEAL_GROW
                | libc::F_SEAL_SHRINK
                | libc::F_SEAL_FUTURE_WRITE
                | libc::F_SEAL_SEAL;
            for ordinal in 0..count {
                let descriptor = imported.descriptor_for_test(ordinal);
                let region_id = ordinal + 1;
                // SAFETY: scalar fcntl query on a live received descriptor.
                assert_eq!(
                    unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GET_SEALS) },
                    final_seals
                );
                for offset in 0..region_id * 17 {
                    assert_eq!(imported.read_for_test(ordinal, offset), region_id as u8);
                }
                let (_, _, len) = imported.object_key_for_test(ordinal);
                // SAFETY: final future-write seals must reject this mapping.
                let writer = unsafe {
                    libc::mmap(
                        core::ptr::null_mut(),
                        len,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_SHARED,
                        descriptor.as_raw_fd(),
                        0,
                    )
                };
                assert_eq!(writer, libc::MAP_FAILED);
            }
            drop(transaction);
            assert_eq!(
                events.lock().unwrap().as_slice(),
                &["poison", "imported-batch-drop"]
            );
            assert_eq!(
                control.send(
                    &ControlFrame {
                        kind: APPLICATION_CONTROL_KIND,
                        payload: Vec::new(),
                    },
                    deadline(),
                ),
                Err(AcceptedControlError::Control(ControlError::Poisoned))
            );
            drop(control);
            std::process::exit(0);
        }
        "receiver-writer-batch"
        | "receiver-writer-seal-failure"
        | "receiver-writer-imported-application"
        | "receiver-writer-sealed-substitution"
        | "receiver-writer-imported-silence"
        | "receiver-writer-imported-rights"
        | "receiver-writer-imported-truncated"
        | "receiver-writer-imported-wrong-credentials"
        | "receiver-writer-invalid-object"
        | "receiver-writer-import-advice-failure"
        | "receiver-writer-coordinator-advice-failure"
        | "receiver-writer-final-seal-missing"
        | "receiver-writer-stale-imported"
        | "receiver-writer-duplicate-imported"
        | "receiver-writer-duplicate-sealed"
        | "receiver-writer-continuous-wrong-imported" => {
            let count = std::env::var("NATIVE_IPC_VNEXT_CONTROL_RECEIVER_LEN")
                .unwrap()
                .parse::<usize>()
                .unwrap();
            let events = Arc::new(Mutex::new(Vec::new()));
            let mut control = evidence.into_control().unwrap();
            control.observe_linux_receiver_poison_for_test(events.clone());
            control
                .send(
                    &ControlFrame {
                        kind: APPLICATION_CONTROL_KIND,
                        payload: b"ready".to_vec(),
                    },
                    deadline(),
                )
                .unwrap();
            let operation_deadline = if mode.ends_with("silence") {
                AbsoluteDeadline::after(Duration::from_millis(150)).unwrap()
            } else {
                deadline()
            };
            let mut transaction = control
                .begin_linux_expected_receiver_writer_batch(
                    expected_receiver_writer_batch(count),
                    operation_deadline,
                )
                .unwrap();
            transaction.observe_import_drop_for_test(events.clone());
            if mode.ends_with("imported-application") {
                transaction.substitute_imported_with_application_for_test();
            }
            if mode.ends_with("silence") {
                transaction.suppress_imported_for_test();
            }
            if mode.ends_with("rights") {
                let rights = std::env::var("NATIVE_IPC_VNEXT_CONTROL_COORDINATOR_LEN")
                    .unwrap()
                    .parse::<usize>()
                    .unwrap();
                transaction.inject_imported_rights_for_test(rights);
            }
            if mode.ends_with("truncated") {
                transaction.truncate_imported_for_test();
            }
            if mode.ends_with("wrong-credentials") {
                transaction.use_wrong_imported_credentials_for_test();
            }
            if mode.ends_with("import-advice-failure") {
                let operation = std::env::var("NATIVE_IPC_VNEXT_CONTROL_COORDINATOR_LEN")
                    .unwrap()
                    .parse::<usize>()
                    .unwrap();
                transaction.fail_receiver_advice_at_for_test(operation);
            }
            if mode.ends_with("stale-imported") {
                transaction.stale_imported_for_test();
            }
            if mode.ends_with("duplicate-imported") {
                transaction.duplicate_imported_for_test();
            }
            if mode.ends_with("continuous-wrong-imported") {
                transaction.continuous_wrong_imported_for_test();
            }
            if mode.ends_with("duplicate-sealed") {
                transaction.expect_duplicate_sealed_replay_for_test();
            }
            let prepared = transaction.prepare();
            if mode.ends_with("invalid-object") {
                assert_eq!(
                    prepared,
                    Err(LinuxCapabilityBatchError::Memory(MemfdError::InvalidObject))
                );
                drop(transaction);
                assert_eq!(
                    events.lock().unwrap().as_slice(),
                    &["poison", "failed-receiver-import-drop"]
                );
                drop(control);
                std::process::exit(0);
            } else if mode.ends_with("import-advice-failure") {
                assert_eq!(
                    prepared,
                    Err(LinuxCapabilityBatchError::Memory(MemfdError::Native(
                        libc::EIO
                    )))
                );
                drop(transaction);
                assert_eq!(
                    events.lock().unwrap().as_slice(),
                    &["poison", "failed-receiver-import-drop"]
                );
                drop(control);
                std::process::exit(0);
            } else if mode.ends_with("final-seal-missing") {
                assert_eq!(
                    prepared,
                    Err(LinuxCapabilityBatchError::Memory(MemfdError::InvalidObject))
                );
                drop(transaction);
                assert_eq!(
                    events.lock().unwrap().as_slice(),
                    &["poison", "imported-receiver-batch-drop"]
                );
                drop(control);
                std::process::exit(0);
            } else if mode.ends_with("sealed-substitution") {
                assert!(matches!(
                    prepared,
                    Err(LinuxCapabilityBatchError::Control(
                        AcceptedControlError::Control(ControlError::NonCanonical)
                    ))
                ));
            } else if mode.ends_with("duplicate-sealed") {
                assert_eq!(
                    prepared,
                    Err(LinuxCapabilityBatchError::Control(
                        AcceptedControlError::Control(ControlError::ReplayOrReorder)
                    ))
                );
            } else if !matches!(
                mode,
                "receiver-writer-batch" | "receiver-writer-duplicate-imported"
            ) {
                assert!(matches!(
                    prepared,
                    Err(LinuxCapabilityBatchError::Control(
                        AcceptedControlError::Transport(
                            SessionTransportError::PeerExited
                                | SessionTransportError::Native
                                | SessionTransportError::DeadlineExpired
                        )
                    ))
                ));
            }
            if !matches!(
                mode,
                "receiver-writer-batch" | "receiver-writer-duplicate-imported"
            ) {
                drop(transaction);
                assert_eq!(
                    events.lock().unwrap().as_slice(),
                    &["poison", "imported-receiver-batch-drop"]
                );
                drop(control);
                std::process::exit(0);
            }
            prepared.unwrap();
            let imported = transaction.imported_for_test();
            assert_eq!(imported.len(), count);
            let final_seals = 0x20
                | libc::F_SEAL_GROW
                | libc::F_SEAL_SHRINK
                | libc::F_SEAL_FUTURE_WRITE
                | libc::F_SEAL_SEAL;
            for ordinal in 0..count {
                let descriptor = imported.descriptor_for_test(ordinal);
                // SAFETY: scalar seal query on a live transaction-owned fd.
                assert_eq!(
                    unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GET_SEALS) },
                    final_seals
                );
                for offset in 0..(ordinal + 1) * 17 {
                    imported.write_for_test(ordinal, offset, (ordinal + 1) as u8);
                }
            }
            drop(transaction);
            assert_eq!(
                events.lock().unwrap().as_slice(),
                &["poison", "imported-receiver-batch-drop"]
            );
            drop(control);
            std::process::exit(0);
        }
        "mixed-direction-batch"
        | "mixed-direction-seal-failure"
        | "mixed-direction-import-advice-failure"
        | "mixed-direction-coordinator-advice-failure"
        | "mixed-direction-final-seal-missing"
        | "mixed-direction-imported-rights"
        | "mixed-direction-imported-wrong-credentials"
        | "mixed-direction-stale-imported"
        | "mixed-direction-wrong-logical"
        | "mixed-direction-ready-application"
        | "mixed-direction-ready-substitution"
        | "mixed-direction-ready-truncated"
        | "mixed-direction-ready-duplicate"
        | "mixed-direction-commit-application"
        | "mixed-direction-commit-substitution"
        | "mixed-direction-commit-truncated"
        | "mixed-direction-commit-duplicate"
        | "mixed-direction-coordinator-activation-failure"
        | "mixed-direction-receiver-activation-failure" => {
            let count = std::env::var("NATIVE_IPC_VNEXT_CONTROL_RECEIVER_LEN")
                .unwrap()
                .parse::<usize>()
                .unwrap();
            let events = Arc::new(Mutex::new(Vec::new()));
            let active_drops = Arc::new(Mutex::new(Vec::new()));
            let mut control = evidence.into_control().unwrap();
            if mode == "mixed-direction-receiver-activation-failure" {
                control.observe_linux_receiver_poison_for_test(active_drops.clone());
            } else {
                control.observe_linux_receiver_poison_for_test(events.clone());
            }
            control.observe_active_lease_drop_for_test(active_drops.clone());
            control
                .send(
                    &ControlFrame {
                        kind: APPLICATION_CONTROL_KIND,
                        payload: b"ready".to_vec(),
                    },
                    deadline(),
                )
                .unwrap();
            let session_fds = open_fd_count();
            let session_tasks = open_task_count();
            let session_maps = open_vnext_map_count();
            let operation_deadline = deadline();
            let mut transaction = control
                .begin_linux_expected_mixed_direction_batch(
                    expected_mixed_direction_batch_with_first_delta(
                        count,
                        usize::from(mode.ends_with("wrong-logical")),
                    ),
                    operation_deadline,
                )
                .unwrap();
            transaction.observe_import_drop_for_test(events.clone());
            if mode.ends_with("rights") {
                let rights = std::env::var("NATIVE_IPC_VNEXT_CONTROL_COORDINATOR_LEN")
                    .unwrap()
                    .parse::<usize>()
                    .unwrap();
                transaction.inject_imported_rights_for_test(rights);
            }
            if mode.ends_with("wrong-credentials") {
                transaction.use_wrong_imported_credentials_for_test();
            }
            if mode.ends_with("import-advice-failure") {
                let operation = std::env::var("NATIVE_IPC_VNEXT_CONTROL_COORDINATOR_LEN")
                    .unwrap()
                    .parse::<usize>()
                    .unwrap();
                transaction.fail_receiver_advice_at_for_test(operation);
            }
            if mode.ends_with("stale-imported") {
                transaction.stale_imported_for_test();
            }
            match mode {
                "mixed-direction-ready-application" => {
                    transaction.interleave_application_ready_for_test();
                }
                "mixed-direction-ready-substitution" => {
                    transaction.substitute_ready_manifest_for_test();
                }
                "mixed-direction-ready-truncated" => {
                    transaction.truncate_ready_for_test();
                }
                "mixed-direction-ready-duplicate" => {
                    transaction.duplicate_ready_for_test();
                }
                "mixed-direction-commit-application"
                | "mixed-direction-commit-substitution"
                | "mixed-direction-commit-truncated" => {
                    transaction.acknowledge_commit_rejection_for_test();
                }
                _ => {}
            }
            let prepared = transaction.prepare();
            if mode.ends_with("wrong-logical") {
                assert_eq!(
                    prepared,
                    Err(LinuxCapabilityBatchError::Control(
                        AcceptedControlError::Control(ControlError::NonCanonical)
                    ))
                );
                drop(transaction);
                assert_eq!(events.lock().unwrap().as_slice(), &["poison"]);
                drop(control);
                std::process::exit(0);
            }
            if mode.ends_with("import-advice-failure") {
                assert_eq!(
                    prepared,
                    Err(LinuxCapabilityBatchError::Memory(MemfdError::Native(
                        libc::EIO
                    )))
                );
                drop(transaction);
                assert_eq!(
                    events.lock().unwrap().as_slice(),
                    &["poison", "failed-mixed-import-drop"]
                );
                drop(control);
                std::process::exit(0);
            }
            if mode.ends_with("final-seal-missing") {
                assert_eq!(
                    prepared,
                    Err(LinuxCapabilityBatchError::Memory(MemfdError::InvalidObject))
                );
                drop(transaction);
                assert_eq!(
                    events.lock().unwrap().as_slice(),
                    &["poison", "imported-mixed-batch-drop"]
                );
                drop(control);
                std::process::exit(0);
            }
            if mode.ends_with("seal-failure")
                || mode.ends_with("coordinator-advice-failure")
                || mode.ends_with("rights")
                || mode.ends_with("wrong-credentials")
                || mode.ends_with("stale-imported")
            {
                assert!(matches!(
                    prepared,
                    Err(LinuxCapabilityBatchError::Control(
                        AcceptedControlError::Transport(
                            SessionTransportError::PeerExited | SessionTransportError::Native
                        )
                    ))
                ));
                drop(transaction);
                assert_eq!(
                    events.lock().unwrap().as_slice(),
                    &["poison", "imported-mixed-batch-drop"]
                );
                drop(control);
                std::process::exit(0);
            }
            prepared.unwrap();
            transaction.observe_active_drop_for_test(active_drops.clone());
            if mode == "mixed-direction-receiver-activation-failure" {
                let failure = std::env::var("NATIVE_IPC_VNEXT_CONTROL_COORDINATOR_LEN")
                    .unwrap()
                    .parse::<usize>()
                    .unwrap();
                transaction.fail_activation_at_for_test(failure);
            }
            if mode.ends_with("duplicate") {
                let committed = transaction.commit().unwrap();
                if mode == "mixed-direction-commit-duplicate" {
                    assert_eq!(
                        control.receive(deadline()),
                        Err(AcceptedControlError::Control(ControlError::BadMagic))
                    );
                    assert_eq!(events.lock().unwrap().as_slice(), &["poison"]);
                } else {
                    assert!(events.lock().unwrap().is_empty());
                }
                drop(committed);
                let expected_events: &[&str] = if mode == "mixed-direction-commit-duplicate" {
                    &["poison", "imported-mixed-batch-drop"]
                } else {
                    &["imported-mixed-batch-drop"]
                };
                assert_eq!(events.lock().unwrap().as_slice(), expected_events);
                drop(control);
                std::process::exit(0);
            }
            if mode.starts_with("mixed-direction-ready-")
                || mode.starts_with("mixed-direction-commit-")
            {
                assert!(matches!(
                    transaction.commit(),
                    Err(LinuxCapabilityBatchError::Control(
                        AcceptedControlError::Control(error)
                    ))
                    if error == ControlError::NonCanonical
                ));
                assert_eq!(
                    events.lock().unwrap().as_slice(),
                    &["poison", "imported-mixed-batch-drop"]
                );
                loop {
                    let _control = &control;
                    // SAFETY: coordinator exact-child cleanup terminates this helper.
                    unsafe { libc::pause() };
                }
            }
            let committed = transaction.commit().unwrap();
            if mode == "mixed-direction-receiver-activation-failure" {
                assert_eq!(
                    control
                        .activate_linux_receiver_mixed_direction_batch(committed)
                        .err(),
                    Some(LinuxActivationError::Memory(MemfdError::Native(libc::EIO)))
                );
                assert_eq!(
                    control.receive(deadline()),
                    Err(AcceptedControlError::Control(ControlError::Poisoned))
                );
                let released = control.active_lease_facts_for_test();
                assert_eq!((released.regions, released.bytes), (0, 0));
                let drops = active_drops.lock().unwrap();
                assert_eq!(drops.first(), Some(&"poison"));
                assert_eq!(
                    drops
                        .iter()
                        .filter(|event| **event == "active-mapping-drop")
                        .count(),
                    count
                );
                assert_eq!(
                    drops
                        .iter()
                        .filter(|event| **event == "active-lease-drop")
                        .count(),
                    count
                );
                assert_eq!(
                    events.lock().unwrap().as_slice(),
                    &["imported-mixed-batch-drop"]
                );
                assert_eq!(open_fd_count(), session_fds);
                assert_eq!(open_task_count(), session_tasks);
                assert_eq!(open_vnext_map_count(), session_maps);
                drop(control);
                std::process::exit(0);
            }
            let mut active = control
                .activate_linux_receiver_mixed_direction_batch(committed)
                .unwrap();
            assert_eq!(active.len(), count);
            let charged = control.active_lease_facts_for_test();
            assert_eq!(charged.regions, count as u32);
            assert_eq!(charged.bytes, mixed_direction_mapped_bytes(count));
            let mut readers = Vec::new();
            let mut writers = Vec::new();
            for region_id in 1..=count {
                let id = RegionId::new(region_id as u128).unwrap();
                if region_id % 2 == 0 {
                    let mut writer = active.take_writer(id).unwrap();
                    writer.fill(0..writer.len(), region_id as u8).unwrap();
                    writers.push(writer);
                } else {
                    let reader = active.take_reader(id).unwrap();
                    let mut bytes = vec![0; reader.len()];
                    reader.read_into(0, &mut bytes).unwrap();
                    assert!(bytes.iter().all(|byte| *byte == region_id as u8));
                    readers.push(reader);
                }
            }
            assert!(active.is_empty());
            assert_eq!(
                events.lock().unwrap().as_slice(),
                &["imported-mixed-batch-drop"]
            );
            if mode == "mixed-direction-coordinator-activation-failure" {
                drop(readers);
                drop(writers);
                let released = control.active_lease_facts_for_test();
                assert_eq!((released.regions, released.bytes), (0, 0));
                let drops = active_drops.lock().unwrap();
                assert_eq!(drops.len(), count * 2);
                for pair in drops.chunks_exact(2) {
                    assert_eq!(pair, &["active-mapping-drop", "active-lease-drop"]);
                }
                drop(control);
                std::process::exit(0);
            }
            control
                .send(
                    &ControlFrame {
                        kind: APPLICATION_CONTROL_KIND,
                        payload: b"committed".to_vec(),
                    },
                    deadline(),
                )
                .unwrap();
            assert_eq!(control.receive(deadline()).unwrap().payload, b"continue");
            control
                .send(
                    &ControlFrame {
                        kind: APPLICATION_CONTROL_KIND,
                        payload: Vec::new(),
                    },
                    deadline(),
                )
                .unwrap();
            drop(readers);
            drop(writers);
            let released = control.active_lease_facts_for_test();
            assert_eq!((released.regions, released.bytes), (0, 0));
            let drops = active_drops.lock().unwrap();
            assert_eq!(drops.len(), count * 2);
            for pair in drops.chunks_exact(2) {
                assert_eq!(pair, &["active-mapping-drop", "active-lease-drop"]);
            }
            assert_eq!(
                events.lock().unwrap().as_slice(),
                &["imported-mixed-batch-drop"]
            );
            loop {
                let _control = &control;
                // SAFETY: coordinator exact-child cleanup terminates this helper.
                unsafe { libc::pause() };
            }
        }
        "coordinator-writer-batch-local-reject" => {
            let mut control = evidence.into_control().unwrap();
            let expected = ExpectedBatch::try_from_specs(vec![ExpectedRegion {
                id: RegionId::new(1).unwrap(),
                writer: WriterEndpoint::Receiver,
                logical_len: 17,
            }])
            .unwrap();
            assert!(matches!(
                control.begin_linux_expected_coordinator_writer_batch(expected, deadline()),
                Err(LinuxCapabilityBatchError::Memory(
                    MemfdError::UnsupportedDirection
                ))
            ));
            control
                .send(
                    &ControlFrame {
                        kind: APPLICATION_CONTROL_KIND,
                        payload: b"local-rejected".to_vec(),
                    },
                    deadline(),
                )
                .unwrap();
            loop {
                let _control = &control;
                // SAFETY: coordinator exact-child cleanup terminates this helper.
                unsafe { libc::pause() };
            }
        }
        "rights" => {
            let bytes = raw_frame(1);
            // SAFETY: successful open returns one uniquely owned descriptor.
            let raw =
                unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
            assert!(raw >= 0);
            // SAFETY: successful open returned one uniquely owned descriptor.
            let descriptor = unsafe { OwnedFd::from_raw_fd(raw) };
            evidence
                .endpoint
                .send(&bytes, &[descriptor.as_raw_fd()])
                .unwrap();
        }
        "truncated" => {
            evidence.endpoint.send_zero_rights(b"NIPCAPP1").unwrap();
        }
        "oversize" => {
            assert_eq!(maximum, 8);
            evidence.endpoint.send_zero_rights(&raw_frame(9)).unwrap();
        }
        "replay" => {
            let bytes = raw_frame(1);
            evidence.endpoint.send_zero_rights(&bytes).unwrap();
            evidence.endpoint.send_zero_rights(&bytes).unwrap();
        }
        "wrong-credentials" => {
            let bytes = raw_frame(1);
            // SAFETY: fork creates a disposable malicious delegate with a
            // distinct kernel PID but the inherited authenticated endpoint.
            let child = unsafe { libc::fork() };
            assert!(child >= 0);
            if child == 0 {
                let _ = evidence.endpoint.send_zero_rights(&bytes);
                // SAFETY: disposable delegate exits without Rust teardown.
                unsafe { libc::_exit(0) }
            }
            let mut status = 0;
            // SAFETY: this helper owns the exact disposable delegate child.
            assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        }
        "silent" => {}
        "exit" => {
            let mut control = evidence.into_control().unwrap();
            let _ = control.receive(deadline()).unwrap();
            // SAFETY: coordinator retains exact lifecycle cleanup authority.
            unsafe { libc::_exit(0) }
        }
        _ => panic!("unknown accepted control mode"),
    }
    loop {
        // SAFETY: coordinator exact-child cleanup terminates this helper.
        unsafe { libc::pause() };
    }
}

fn send_malicious_receiver_decision(mut state: ReceiverNegotiatingState, mode: &str) -> ! {
    let fake_challenge = DecisionChallenge::from_os_csprng([0x5a; 16]).unwrap();
    let frame = if mode == "prequeued-accept" || mode == "prequeued-reject" {
        let coordinator = state.transcript.coordinator_accept(fake_challenge).unwrap();
        state
            .transcript
            .validate_accept(coordinator, SenderRole::Coordinator)
            .unwrap();
        if mode == "prequeued-accept" {
            NegotiationFrame::Accept(state.transcript.receiver_accept().unwrap())
        } else {
            NegotiationFrame::Reject(
                state
                    .transcript
                    .receiver_reject(NonZeroU32::new(23).unwrap())
                    .unwrap(),
            )
        }
    } else if mode == "duplicate-hello" || mode == "malformed-flood" {
        let atomics = discover_atomic_capabilities().unwrap();
        let hello = make_hello(SenderRole::Receiver, state.nonce, hello_offer(1), atomics).unwrap();
        let mut bytes = encode_hello(&hello).unwrap();
        if mode == "malformed-flood" {
            bytes.truncate(HEADER_LEN - 1);
        }
        send_socket_before(&mut state.endpoint, &bytes, state.deadline).unwrap();
        if mode == "malformed-flood" {
            let _ = send_socket_before(&mut state.endpoint, &bytes, state.deadline);
        }
        loop {
            // SAFETY: exact coordinator cleanup terminates this helper.
            unsafe { libc::pause() };
        }
    } else {
        let packet =
            receive_socket_before(&mut state.endpoint, state.peer, state.deadline).unwrap();
        let coordinator = match decode_frame(
            &packet.bytes,
            SenderRole::Coordinator,
            state.nonce,
            MAX_LINUX_HELLO_PAYLOAD as u32,
        )
        .unwrap()
        {
            NegotiationFrame::Accept(accept) => accept,
            _ => panic!("expected Coordinator ACCEPT"),
        };
        state
            .transcript
            .validate_accept(coordinator, SenderRole::Coordinator)
            .unwrap();
        if mode == "decision-silent" {
            loop {
                // SAFETY: exact coordinator cleanup terminates this helper.
                unsafe { libc::pause() };
            }
        }
        if mode == "decision-exit" {
            // SAFETY: disposable child exits after exact Coordinator ACCEPT.
            unsafe { libc::_exit(0) }
        }
        if mode.starts_with("reject-") {
            NegotiationFrame::Reject(
                state
                    .transcript
                    .receiver_reject(NonZeroU32::new(29).unwrap())
                    .unwrap(),
            )
        } else {
            NegotiationFrame::Accept(state.transcript.receiver_accept().unwrap())
        }
    };
    let mut bytes = encode_negotiation_frame(&frame).unwrap();
    if mode == "reexec" {
        let path = std::env::var_os("NATIVE_IPC_VNEXT_TEST_REEXEC_PATH").unwrap();
        let raw = state.endpoint.fd.as_raw_fd();
        // SAFETY: clearing CLOEXEC intentionally transfers this exact endpoint
        // through the controlled re-exec test boundary.
        assert_eq!(unsafe { libc::fcntl(raw, libc::F_SETFD, 0) }, 0);
        let error = std::process::Command::new(path)
            .args(&helper_arguments()[1..])
            .env("NATIVE_IPC_VNEXT_BOOTSTRAP_FD", raw.to_string())
            .env("NATIVE_IPC_VNEXT_POST_REEXEC_DECISION", encode_hex(&bytes))
            .exec();
        panic!("controlled re-exec failed: {error}");
    }
    match mode {
        "prequeued-accept" | "prequeued-reject" => {}
        "wrong-role" => bytes[14] = SenderRole::Coordinator as u8,
        "wrong-nonce" => bytes[32] ^= 1,
        "wrong-challenge" => bytes[80] ^= 1,
        "zero-challenge" => bytes[80..96].fill(0),
        "wrong-features" => bytes[64] ^= 1,
        "wrong-limit-regions" => bytes[96] ^= 1,
        "wrong-limit-active" => bytes[100] ^= 1,
        "wrong-limit-region-bytes" => bytes[104] ^= 1,
        "wrong-limit-batch-bytes" => bytes[112] ^= 1,
        "wrong-limit-active-bytes" => bytes[120] ^= 1,
        "wrong-limit-transactions" => bytes[128] ^= 1,
        "wrong-limit-bootstrap" => bytes[136] ^= 1,
        "wrong-limit-control" => bytes[140] ^= 1,
        "wrong-atomics" => bytes[144] ^= 1,
        "wrong-target" => bytes[160] ^= 1,
        "wrong-digest" => bytes[166] ^= 1,
        "reserved" => bytes[198] = 1,
        "truncated" => bytes.truncate(HEADER_LEN - 1),
        "reject-wrong-role" => bytes[14] = SenderRole::Coordinator as u8,
        "reject-wrong-nonce" => bytes[32] ^= 1,
        "reject-wrong-challenge" => bytes[80] ^= 1,
        "reject-zero-reason" => bytes[28..32].fill(0),
        "reject-reserved" => bytes[198] = 1,
        "rights" | "reject-rights" => {
            // SAFETY: successful open returns one uniquely owned test descriptor.
            let raw =
                unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
            assert!(raw >= 0);
            // SAFETY: the successful open descriptor is uniquely owned.
            let descriptor = unsafe { OwnedFd::from_raw_fd(raw) };
            state
                .endpoint
                .send(&bytes, &[descriptor.as_raw_fd()])
                .unwrap();
            loop {
                // SAFETY: exact coordinator cleanup terminates this helper.
                unsafe { libc::pause() };
            }
        }
        _ => panic!("unknown malicious decision mode"),
    }
    send_socket_before(&mut state.endpoint, &bytes, state.deadline).unwrap();
    loop {
        // SAFETY: exact coordinator cleanup terminates this helper.
        unsafe { libc::pause() };
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0xf) as usize] as char);
    }
    encoded
}

fn decode_hex(encoded: &str) -> Vec<u8> {
    assert_eq!(encoded.len() % 2, 0);
    encoded
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |value: u8| match value {
                b'0'..=b'9' => value - b'0',
                b'a'..=b'f' => value - b'a' + 10,
                b'A'..=b'F' => value - b'A' + 10,
                _ => panic!("invalid test hex"),
            };
            (digit(pair[0]) << 4) | digit(pair[1])
        })
        .collect()
}

fn decision_environment(
    coordinator_len: usize,
    receiver_len: usize,
    receiver_decision: &str,
) -> Vec<(OsString, OsString)> {
    [
        ("NATIVE_IPC_VNEXT_TEST_HELLO", receiver_len.to_string()),
        (
            "NATIVE_IPC_VNEXT_TEST_COORDINATOR_LEN",
            coordinator_len.to_string(),
        ),
        (
            "NATIVE_IPC_VNEXT_TEST_DECISION",
            receiver_decision.to_owned(),
        ),
    ]
    .into_iter()
    .map(|(key, value)| (OsString::from(key), OsString::from(value)))
    .collect()
}

fn control_environment(
    mode: &str,
    coordinator_len: usize,
    receiver_len: usize,
    control_limit: u32,
) -> Vec<(OsString, OsString)> {
    let mut environment = decision_environment(0, 0, "accept");
    environment.extend([
        (
            OsString::from("NATIVE_IPC_VNEXT_CONTROL_MODE"),
            OsString::from(mode),
        ),
        (
            OsString::from("NATIVE_IPC_VNEXT_CONTROL_COORDINATOR_LEN"),
            OsString::from(coordinator_len.to_string()),
        ),
        (
            OsString::from("NATIVE_IPC_VNEXT_CONTROL_RECEIVER_LEN"),
            OsString::from(receiver_len.to_string()),
        ),
        (
            OsString::from("NATIVE_IPC_VNEXT_CONTROL_LIMIT"),
            OsString::from(control_limit.to_string()),
        ),
    ]);
    environment
}

fn accepted_control(
    mode: &str,
    coordinator_len: usize,
    receiver_len: usize,
    control_limit: u32,
) -> (CoordinatorAcceptedControl, libc::pid_t) {
    let mut offer = hello_offer(0);
    offer.limits.max_control_payload_bytes = control_limit;
    let owner = spawn_negotiating(
        &std::env::current_exe().unwrap(),
        &helper_arguments(),
        &control_environment(mode, coordinator_len, receiver_len, control_limit),
        offer,
        deadline(),
    )
    .unwrap();
    let pid = owner.pid();
    let accepted = match owner.decide(ApplicationDecision::Accept).unwrap() {
        DecisionOutcome::Accepted(accepted) => accepted,
        DecisionOutcome::Rejected { .. } => panic!("accepted control negotiation rejected"),
    };
    let evidence = accepted.into_evidence().unwrap();
    (evidence.into_control().unwrap(), pid)
}

#[test]
#[ignore = "spawned alone by accepted_native_control_is_bounded_authenticated_and_role_scoped"]
fn isolated_accepted_native_control_is_bounded_authenticated_and_role_scoped() {
    let before_fds = open_fd_count();
    let before_tasks = open_task_count();

    for length in [0, MAX_LINUX_CONTROL_PAYLOAD as usize] {
        let (mut control, pid) =
            accepted_control("echo", length, length, MAX_LINUX_CONTROL_PAYLOAD);
        assert_eq!(control.try_poll_peer().unwrap(), PeerState::Running);
        assert_eq!(control.receive(deadline()).unwrap().payload, b"ready");
        control
            .send(
                &ControlFrame {
                    kind: APPLICATION_CONTROL_KIND,
                    payload: vec![0x41; length],
                },
                deadline(),
            )
            .unwrap();
        let received = control.receive(deadline()).unwrap();
        assert_eq!(received.kind, APPLICATION_CONTROL_KIND);
        assert_eq!(received.payload, vec![0x52; length]);
        control.terminate_and_reap(deadline()).unwrap();
        drop(control);
        wait_for_baseline(before_fds, before_tasks, pid, deadline());
    }

    for mode in ["rights", "truncated", "oversize", "wrong-credentials"] {
        let limit = if mode == "oversize" {
            8
        } else {
            MAX_LINUX_CONTROL_PAYLOAD
        };
        let (mut control, pid) = accepted_control(mode, 0, 0, limit);
        assert!(control.receive(deadline()).is_err(), "mode {mode}");
        assert_eq!(
            control.receive(deadline()),
            Err(AcceptedControlError::Control(ControlError::Poisoned)),
            "mode {mode} did not poison persistently"
        );
        control.terminate_and_reap(deadline()).unwrap();
        drop(control);
        wait_for_baseline(before_fds, before_tasks, pid, deadline());
    }

    let (mut replay, pid) = accepted_control("replay", 0, 0, MAX_LINUX_CONTROL_PAYLOAD);
    assert_eq!(replay.receive(deadline()).unwrap().payload, vec![0x5a]);
    assert_eq!(
        replay.receive(deadline()),
        Err(AcceptedControlError::Control(ControlError::ReplayOrReorder))
    );
    replay.terminate_and_reap(deadline()).unwrap();
    drop(replay);
    wait_for_baseline(before_fds, before_tasks, pid, deadline());

    let (mut silent, pid) = accepted_control("silent", 0, 0, MAX_LINUX_CONTROL_PAYLOAD);
    let short_deadline = AbsoluteDeadline::after(Duration::from_millis(20)).unwrap();
    assert_eq!(
        silent.receive(short_deadline),
        Err(AcceptedControlError::Transport(
            SessionTransportError::DeadlineExpired
        ))
    );
    silent.terminate_and_reap(deadline()).unwrap();
    drop(silent);
    wait_for_baseline(before_fds, before_tasks, pid, deadline());

    let (mut exited, pid) = accepted_control("exit", 0, 0, MAX_LINUX_CONTROL_PAYLOAD);
    exited
        .send(
            &ControlFrame {
                kind: APPLICATION_CONTROL_KIND,
                payload: Vec::new(),
            },
            deadline(),
        )
        .unwrap();
    let observation_deadline = deadline();
    loop {
        if exited.try_poll_peer().unwrap() == PeerState::ExitedUnknown {
            break;
        }
        assert!(!observation_deadline.is_expired());
        std::thread::yield_now();
    }
    exited.terminate_and_reap(deadline()).unwrap();
    drop(exited);
    wait_for_baseline(before_fds, before_tasks, pid, deadline());
}

#[test]
fn accepted_native_control_is_bounded_authenticated_and_role_scoped() {
    run_isolated(
        "backend::linux_vnext::spawn::tests::isolated_accepted_native_control_is_bounded_authenticated_and_role_scoped",
    );
}

#[test]
#[ignore = "spawned alone by coordinator_writer_batches_share_the_accepted_owner"]
fn isolated_coordinator_writer_batches_share_the_accepted_owner() {
    let before_fds = open_fd_count();
    let before_tasks = open_task_count();

    let (mut mismatch, pid) = accepted_control("echo", 0, 0, MAX_LINUX_CONTROL_PAYLOAD);
    assert_eq!(mismatch.receive(deadline()).unwrap().payload, b"ready");
    let original_deadline = deadline();
    let prepared = LinuxCoordinatorWriterBatch::prepare(
        portable_coordinator_writer_batch(1),
        mismatch.authority_profile(),
        original_deadline,
    )
    .unwrap();
    let replacement_deadline = AbsoluteDeadline::after(Duration::from_secs(4)).unwrap();
    assert!(matches!(
        mismatch.begin_linux_coordinator_writer_batch(prepared, replacement_deadline),
        Err(LinuxCapabilityBatchError::Memory(
            MemfdError::DeadlineMismatch
        ))
    ));
    mismatch
        .send(
            &ControlFrame {
                kind: APPLICATION_CONTROL_KIND,
                payload: Vec::new(),
            },
            original_deadline,
        )
        .unwrap();
    assert!(
        mismatch
            .receive(original_deadline)
            .unwrap()
            .payload
            .is_empty()
    );
    mismatch.terminate_and_reap(deadline()).unwrap();
    drop(mismatch);
    wait_for_baseline(before_fds, before_tasks, pid, deadline());

    for count in [1, 2, 4, 16] {
        let (mut control, pid) = accepted_control(
            "coordinator-writer-batch",
            0,
            count,
            MAX_LINUX_CONTROL_PAYLOAD,
        );
        assert_eq!(control.receive(deadline()).unwrap().payload, b"ready");
        let operation_deadline = deadline();
        let prepared = LinuxCoordinatorWriterBatch::prepare(
            portable_coordinator_writer_batch(count),
            control.authority_profile(),
            operation_deadline,
        )
        .unwrap();
        {
            let mut transaction = control
                .begin_linux_coordinator_writer_batch(prepared, operation_deadline)
                .unwrap();
            transaction.send().unwrap();
        }
        assert_eq!(
            control.send(
                &ControlFrame {
                    kind: APPLICATION_CONTROL_KIND,
                    payload: Vec::new(),
                },
                deadline(),
            ),
            Err(AcceptedControlError::Control(ControlError::Poisoned))
        );
        control.terminate_and_reap(deadline()).unwrap();
        drop(control);
        wait_for_baseline(before_fds, before_tasks, pid, deadline());
    }

    let (mut mismatch, pid) = accepted_control(
        "coordinator-writer-batch-wrong-logical",
        0,
        2,
        MAX_LINUX_CONTROL_PAYLOAD,
    );
    assert_eq!(mismatch.receive(deadline()).unwrap().payload, b"ready");
    let operation_deadline = deadline();
    let prepared = LinuxCoordinatorWriterBatch::prepare(
        portable_coordinator_writer_batch(2),
        mismatch.authority_profile(),
        operation_deadline,
    )
    .unwrap();
    {
        let mut transaction = mismatch
            .begin_linux_coordinator_writer_batch(prepared, operation_deadline)
            .unwrap();
        transaction.send().unwrap();
    }
    mismatch.terminate_and_reap(deadline()).unwrap();
    drop(mismatch);
    wait_for_baseline(before_fds, before_tasks, pid, deadline());

    for failure in [1, 2, 4, 16] {
        let (mut invalid, pid) = accepted_control(
            "coordinator-writer-batch-invalid-object",
            failure,
            16,
            MAX_LINUX_CONTROL_PAYLOAD,
        );
        assert_eq!(invalid.receive(deadline()).unwrap().payload, b"ready");
        let operation_deadline = deadline();
        let mut prepared = LinuxCoordinatorWriterBatch::prepare(
            portable_coordinator_writer_batch(16),
            invalid.authority_profile(),
            operation_deadline,
        )
        .unwrap();
        prepared.replace_export_with_invalid_file_for_test(failure - 1);
        {
            let mut transaction = invalid
                .begin_linux_coordinator_writer_batch(prepared, operation_deadline)
                .unwrap();
            transaction.send_without_revalidation_for_test().unwrap();
        }
        invalid.terminate_and_reap(deadline()).unwrap();
        drop(invalid);
        wait_for_baseline(before_fds, before_tasks, pid, deadline());
    }

    for failure in [1, 17, 32] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let (mut control, pid) = accepted_control(
            "receiver-writer-import-advice-failure",
            failure,
            16,
            MAX_LINUX_CONTROL_PAYLOAD,
        );
        assert_eq!(control.receive(deadline()).unwrap().payload, b"ready");
        control.observe_linux_poison_for_test(events.clone());
        let operation_deadline = deadline();
        let mut prepared = LinuxReceiverWriterBatch::prepare(
            portable_receiver_writer_batch(16),
            control.authority_profile(),
            operation_deadline,
        )
        .unwrap();
        prepared.observe_drop_for_test(events.clone());
        {
            let mut transaction = control
                .begin_linux_receiver_writer_batch(prepared, operation_deadline)
                .unwrap();
            assert!(matches!(
                transaction.prepare(),
                Err(LinuxCapabilityBatchError::Control(
                    AcceptedControlError::Transport(
                        SessionTransportError::PeerExited | SessionTransportError::Native
                    )
                ))
            ));
        }
        assert_eq!(
            events.lock().unwrap().as_slice(),
            &["poison", "receiver-writer-batch-drop"]
        );
        control.terminate_and_reap(deadline()).unwrap();
        drop(control);
        wait_for_baseline(before_fds, before_tasks, pid, deadline());
    }

    for failure in [1, 17, 32] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let (mut control, pid) = accepted_control(
            "receiver-writer-coordinator-advice-failure",
            failure,
            16,
            MAX_LINUX_CONTROL_PAYLOAD,
        );
        assert_eq!(control.receive(deadline()).unwrap().payload, b"ready");
        control.observe_linux_poison_for_test(events.clone());
        let operation_deadline = deadline();
        let mut prepared = LinuxReceiverWriterBatch::prepare(
            portable_receiver_writer_batch(16),
            control.authority_profile(),
            operation_deadline,
        )
        .unwrap();
        prepared.observe_drop_for_test(events.clone());
        {
            let mut transaction = control
                .begin_linux_receiver_writer_batch(prepared, operation_deadline)
                .unwrap();
            transaction.fail_coordinator_advice_at_for_test(failure);
            assert_eq!(
                transaction.prepare(),
                Err(LinuxCapabilityBatchError::Memory(MemfdError::Native(
                    libc::EIO
                )))
            );
            assert!(transaction.all_final_sealed_for_test());
        }
        assert_eq!(
            events.lock().unwrap().as_slice(),
            &["poison", "receiver-writer-batch-drop"]
        );
        control.terminate_and_reap(deadline()).unwrap();
        drop(control);
        wait_for_baseline(before_fds, before_tasks, pid, deadline());
    }

    for failure in [1, 17, 32] {
        let (mut faulted, pid) = accepted_control(
            "coordinator-writer-batch-advice-failure",
            failure,
            16,
            MAX_LINUX_CONTROL_PAYLOAD,
        );
        assert_eq!(faulted.receive(deadline()).unwrap().payload, b"ready");
        let operation_deadline = deadline();
        let prepared = LinuxCoordinatorWriterBatch::prepare(
            portable_coordinator_writer_batch(16),
            faulted.authority_profile(),
            operation_deadline,
        )
        .unwrap();
        {
            let mut transaction = faulted
                .begin_linux_coordinator_writer_batch(prepared, operation_deadline)
                .unwrap();
            transaction.send().unwrap();
        }
        faulted.terminate_and_reap(deadline()).unwrap();
        drop(faulted);
        wait_for_baseline(before_fds, before_tasks, pid, deadline());
    }

    let (mut local_reject, pid) = accepted_control(
        "coordinator-writer-batch-local-reject",
        0,
        0,
        MAX_LINUX_CONTROL_PAYLOAD,
    );
    assert_eq!(
        local_reject.receive(deadline()).unwrap().payload,
        b"local-rejected"
    );
    local_reject
        .send(
            &ControlFrame {
                kind: APPLICATION_CONTROL_KIND,
                payload: Vec::new(),
            },
            deadline(),
        )
        .unwrap();
    local_reject.terminate_and_reap(deadline()).unwrap();
    drop(local_reject);
    wait_for_baseline(before_fds, before_tasks, pid, deadline());
}

#[test]
fn coordinator_writer_batches_share_the_accepted_owner() {
    run_isolated(
        "backend::linux_vnext::spawn::tests::isolated_coordinator_writer_batches_share_the_accepted_owner",
    );
}

#[test]
#[ignore = "spawned alone by receiver_writer_batches_complete_imported_sealed_pending"]
fn isolated_receiver_writer_batches_complete_imported_sealed_pending() {
    let before_fds = open_fd_count();
    let before_tasks = open_task_count();
    let before_maps = open_vnext_map_count();

    for count in [1, 2, 4, 16] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let (mut control, pid) =
            accepted_control("receiver-writer-batch", 0, count, MAX_LINUX_CONTROL_PAYLOAD);
        assert_eq!(control.receive(deadline()).unwrap().payload, b"ready");
        control.observe_linux_poison_for_test(events.clone());
        let operation_deadline = deadline();
        let mut prepared = LinuxReceiverWriterBatch::prepare(
            portable_receiver_writer_batch(count),
            control.authority_profile(),
            operation_deadline,
        )
        .unwrap();
        prepared.observe_drop_for_test(events.clone());
        {
            let mut transaction = control
                .begin_linux_receiver_writer_batch(prepared, operation_deadline)
                .unwrap();
            transaction.prepare().unwrap();
            loop {
                let complete = (0..count).all(|ordinal| {
                    (0..(ordinal + 1) * 17).all(|offset| {
                        transaction.batch_for_test().read_for_test(ordinal, offset)
                            == (ordinal + 1) as u8
                    })
                });
                if complete {
                    break;
                }
                assert!(!operation_deadline.is_expired());
                std::thread::yield_now();
            }
            assert_eq!(
                transaction.prepare(),
                Err(LinuxCapabilityBatchError::Control(
                    AcceptedControlError::Control(ControlError::ReplayOrReorder)
                ))
            );
        }
        assert_eq!(
            events.lock().unwrap().as_slice(),
            &["poison", "receiver-writer-batch-drop"]
        );
        assert_eq!(
            control.send(
                &ControlFrame {
                    kind: APPLICATION_CONTROL_KIND,
                    payload: Vec::new(),
                },
                deadline(),
            ),
            Err(AcceptedControlError::Control(ControlError::Poisoned))
        );
        control.terminate_and_reap(deadline()).unwrap();
        drop(control);
        wait_for_baseline(before_fds, before_tasks, pid, deadline());
    }

    for failure in [1, 2, 4, 16] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let (mut control, pid) = accepted_control(
            "receiver-writer-invalid-object",
            failure,
            16,
            MAX_LINUX_CONTROL_PAYLOAD,
        );
        assert_eq!(control.receive(deadline()).unwrap().payload, b"ready");
        control.observe_linux_poison_for_test(events.clone());
        let operation_deadline = deadline();
        let mut prepared = LinuxReceiverWriterBatch::prepare(
            portable_receiver_writer_batch(16),
            control.authority_profile(),
            operation_deadline,
        )
        .unwrap();
        prepared.observe_drop_for_test(events.clone());
        {
            let mut transaction = control
                .begin_linux_receiver_writer_batch(prepared, operation_deadline)
                .unwrap();
            transaction.replace_capability_with_invalid_file_for_test(failure - 1);
            assert!(matches!(
                transaction.prepare(),
                Err(LinuxCapabilityBatchError::Control(
                    AcceptedControlError::Transport(
                        SessionTransportError::PeerExited | SessionTransportError::Native
                    )
                ))
            ));
        }
        assert_eq!(
            events.lock().unwrap().as_slice(),
            &["poison", "receiver-writer-batch-drop"]
        );
        control.terminate_and_reap(deadline()).unwrap();
        drop(control);
        wait_for_baseline(before_fds, before_tasks, pid, deadline());
    }

    for failure in [1, 2, 4, 16] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let (mut control, pid) = accepted_control(
            "receiver-writer-seal-failure",
            failure,
            16,
            MAX_LINUX_CONTROL_PAYLOAD,
        );
        assert_eq!(control.receive(deadline()).unwrap().payload, b"ready");
        control.observe_linux_poison_for_test(events.clone());
        let operation_deadline = deadline();
        let mut prepared = LinuxReceiverWriterBatch::prepare(
            portable_receiver_writer_batch(16),
            control.authority_profile(),
            operation_deadline,
        )
        .unwrap();
        prepared.observe_drop_for_test(events.clone());
        {
            let mut transaction = control
                .begin_linux_receiver_writer_batch(prepared, operation_deadline)
                .unwrap();
            transaction.fail_seal_at_for_test(failure);
            assert_eq!(
                transaction.prepare(),
                Err(LinuxCapabilityBatchError::Memory(MemfdError::Native(
                    libc::EIO
                )))
            );
            assert_eq!(transaction.seal_counts_for_test(), (1, 15));
        }
        assert_eq!(
            events.lock().unwrap().as_slice(),
            &["poison", "receiver-writer-batch-drop"]
        );
        control.terminate_and_reap(deadline()).unwrap();
        drop(control);
        wait_for_baseline(before_fds, before_tasks, pid, deadline());
    }

    for mode in [
        "receiver-writer-imported-application",
        "receiver-writer-imported-truncated",
        "receiver-writer-stale-imported",
        "receiver-writer-duplicate-imported",
        "receiver-writer-sealed-substitution",
        "receiver-writer-duplicate-sealed",
        "receiver-writer-final-seal-missing",
        "receiver-writer-continuous-wrong-imported",
        "receiver-writer-imported-silence",
    ] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let (mut control, pid) = accepted_control(mode, 0, 1, MAX_LINUX_CONTROL_PAYLOAD);
        assert_eq!(control.receive(deadline()).unwrap().payload, b"ready");
        control.observe_linux_poison_for_test(events.clone());
        let operation_deadline = if mode.ends_with("silence") {
            AbsoluteDeadline::after(Duration::from_millis(150)).unwrap()
        } else {
            deadline()
        };
        let mut prepared = LinuxReceiverWriterBatch::prepare(
            portable_receiver_writer_batch(1),
            control.authority_profile(),
            operation_deadline,
        )
        .unwrap();
        prepared.observe_drop_for_test(events.clone());
        {
            let mut transaction = control
                .begin_linux_receiver_writer_batch(prepared, operation_deadline)
                .unwrap();
            if mode.ends_with("sealed-substitution") {
                transaction.substitute_sealed_for_test();
                transaction.prepare().unwrap();
            } else if mode.ends_with("duplicate-sealed") {
                transaction.duplicate_sealed_for_test();
                transaction.prepare().unwrap();
            } else if mode.ends_with("final-seal-missing") {
                transaction.skip_final_sealing_for_test();
                transaction.prepare().unwrap();
            } else if mode.ends_with("duplicate-imported") {
                transaction.prepare().unwrap();
            } else if mode.ends_with("silence") {
                assert_eq!(
                    transaction.prepare(),
                    Err(LinuxCapabilityBatchError::Control(
                        AcceptedControlError::Transport(SessionTransportError::DeadlineExpired)
                    ))
                );
            } else {
                assert_eq!(
                    transaction.prepare(),
                    Err(LinuxCapabilityBatchError::Control(
                        AcceptedControlError::Control(ControlError::NonCanonical)
                    ))
                );
                if mode.ends_with("continuous-wrong-imported") {
                    assert!(!operation_deadline.is_expired());
                }
            }
        }
        assert_eq!(
            events.lock().unwrap().as_slice(),
            &["poison", "receiver-writer-batch-drop"]
        );
        assert_eq!(
            control.send(
                &ControlFrame {
                    kind: APPLICATION_CONTROL_KIND,
                    payload: Vec::new(),
                },
                deadline(),
            ),
            Err(AcceptedControlError::Control(ControlError::Poisoned))
        );
        control.terminate_and_reap(deadline()).unwrap();
        drop(control);
        wait_for_baseline(before_fds, before_tasks, pid, deadline());
    }

    for rights in [1, 2, 16] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let (mut control, pid) = accepted_control(
            "receiver-writer-imported-rights",
            rights,
            1,
            MAX_LINUX_CONTROL_PAYLOAD,
        );
        assert_eq!(control.receive(deadline()).unwrap().payload, b"ready");
        control.observe_linux_poison_for_test(events.clone());
        let operation_deadline = deadline();
        let mut prepared = LinuxReceiverWriterBatch::prepare(
            portable_receiver_writer_batch(1),
            control.authority_profile(),
            operation_deadline,
        )
        .unwrap();
        prepared.observe_drop_for_test(events.clone());
        {
            let mut transaction = control
                .begin_linux_receiver_writer_batch(prepared, operation_deadline)
                .unwrap();
            assert_eq!(
                transaction.prepare(),
                Err(LinuxCapabilityBatchError::Control(
                    AcceptedControlError::Transport(SessionTransportError::MalformedRecord)
                ))
            );
        }
        assert_eq!(
            events.lock().unwrap().as_slice(),
            &["poison", "receiver-writer-batch-drop"]
        );
        control.terminate_and_reap(deadline()).unwrap();
        drop(control);
        wait_for_baseline(before_fds, before_tasks, pid, deadline());
    }

    let events = Arc::new(Mutex::new(Vec::new()));
    let (mut control, pid) = accepted_control(
        "receiver-writer-imported-wrong-credentials",
        0,
        1,
        MAX_LINUX_CONTROL_PAYLOAD,
    );
    assert_eq!(control.receive(deadline()).unwrap().payload, b"ready");
    control.observe_linux_poison_for_test(events.clone());
    let operation_deadline = deadline();
    let mut prepared = LinuxReceiverWriterBatch::prepare(
        portable_receiver_writer_batch(1),
        control.authority_profile(),
        operation_deadline,
    )
    .unwrap();
    prepared.observe_drop_for_test(events.clone());
    {
        let mut transaction = control
            .begin_linux_receiver_writer_batch(prepared, operation_deadline)
            .unwrap();
        assert_eq!(
            transaction.prepare(),
            Err(LinuxCapabilityBatchError::Control(
                AcceptedControlError::Transport(SessionTransportError::IdentityMismatch)
            ))
        );
    }
    assert_eq!(
        events.lock().unwrap().as_slice(),
        &["poison", "receiver-writer-batch-drop"]
    );
    control.terminate_and_reap(deadline()).unwrap();
    drop(control);
    wait_for_baseline(before_fds, before_tasks, pid, deadline());
    assert_eq!(open_vnext_map_count(), before_maps);
}

#[test]
fn receiver_writer_batches_complete_imported_sealed_pending() {
    run_isolated(
        "backend::linux_vnext::spawn::tests::isolated_receiver_writer_batches_complete_imported_sealed_pending",
    );
}

#[test]
#[ignore = "spawned alone by mixed_direction_batches_share_the_accepted_owner"]
fn isolated_mixed_direction_batches_share_the_accepted_owner() {
    let before_fds = open_fd_count();
    let before_tasks = open_task_count();
    let before_maps = open_vnext_map_count();

    let (mut mismatch, pid) = accepted_control("echo", 0, 0, MAX_LINUX_CONTROL_PAYLOAD);
    assert_eq!(mismatch.receive(deadline()).unwrap().payload, b"ready");
    let original_deadline = deadline();
    let prepared = LinuxMixedDirectionBatch::prepare(
        portable_mixed_direction_batch(2),
        mismatch.authority_profile(),
        original_deadline,
    )
    .unwrap();
    let replacement_deadline = deadline();
    assert!(matches!(
        mismatch.begin_linux_mixed_direction_batch(prepared, replacement_deadline),
        Err(LinuxCapabilityBatchError::Memory(
            MemfdError::DeadlineMismatch
        ))
    ));
    mismatch
        .send(
            &ControlFrame {
                kind: APPLICATION_CONTROL_KIND,
                payload: Vec::new(),
            },
            original_deadline,
        )
        .unwrap();
    assert!(
        mismatch
            .receive(original_deadline)
            .unwrap()
            .payload
            .is_empty()
    );
    mismatch.terminate_and_reap(deadline()).unwrap();
    drop(mismatch);
    wait_for_baseline(before_fds, before_tasks, pid, deadline());

    for count in [1, 2, 4, 16] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let active_drops = Arc::new(Mutex::new(Vec::new()));
        let (mut control, pid) =
            accepted_control("mixed-direction-batch", 0, count, MAX_LINUX_CONTROL_PAYLOAD);
        assert_eq!(control.receive(deadline()).unwrap().payload, b"ready");
        control.observe_linux_poison_for_test(events.clone());
        control.observe_active_lease_drop_for_test(active_drops.clone());
        let operation_deadline = deadline();
        let mut prepared = LinuxMixedDirectionBatch::prepare(
            portable_mixed_direction_batch(count),
            control.authority_profile(),
            operation_deadline,
        )
        .unwrap();
        prepared.observe_drop_for_test(events.clone());
        prepared.observe_active_drop_for_test(active_drops.clone());
        {
            let mut transaction = control
                .begin_linux_mixed_direction_batch(prepared, operation_deadline)
                .unwrap();
            transaction.prepare().unwrap();
            let committed = transaction.commit().unwrap();
            let mut active = control
                .activate_linux_coordinator_mixed_direction_batch(committed)
                .unwrap();
            assert_eq!(active.len(), count);
            let charged = control.active_lease_facts_for_test();
            assert_eq!(charged.regions, count as u32);
            assert_eq!(charged.bytes, mixed_direction_mapped_bytes(count));
            let mut readers = Vec::new();
            let mut writers = Vec::new();
            for region_id in 1..=count {
                let id = RegionId::new(region_id as u128).unwrap();
                if region_id % 2 == 0 {
                    let reader = active.take_reader(id).unwrap();
                    let mut bytes = vec![0; reader.len()];
                    loop {
                        reader.read_into(0, &mut bytes).unwrap();
                        if bytes.iter().all(|byte| *byte == region_id as u8) {
                            break;
                        }
                        assert!(!operation_deadline.is_expired());
                        std::thread::yield_now();
                    }
                    readers.push(reader);
                } else {
                    let mut writer = active.take_writer(id).unwrap();
                    writer.fill(0..writer.len(), region_id as u8).unwrap();
                    writers.push(writer);
                }
            }
            assert!(active.is_empty());
            assert_eq!(control.receive(deadline()).unwrap().payload, b"committed");
            control
                .send(
                    &ControlFrame {
                        kind: APPLICATION_CONTROL_KIND,
                        payload: b"continue".to_vec(),
                    },
                    deadline(),
                )
                .unwrap();
            assert!(control.receive(deadline()).unwrap().payload.is_empty());
            assert_eq!(
                events.lock().unwrap().as_slice(),
                &["mixed-direction-batch-drop"]
            );
            drop(readers);
            drop(writers);
            let released = control.active_lease_facts_for_test();
            assert_eq!((released.regions, released.bytes), (0, 0));
            let drops = active_drops.lock().unwrap();
            assert_eq!(drops.len(), count * 2);
            for pair in drops.chunks_exact(2) {
                assert_eq!(pair, &["active-mapping-drop", "active-lease-drop"]);
            }
        }
        control.terminate_and_reap(deadline()).unwrap();
        drop(control);
        wait_for_baseline(before_fds, before_tasks, pid, deadline());
    }

    let events = Arc::new(Mutex::new(Vec::new()));
    let (mut control, pid) = accepted_control(
        "mixed-direction-wrong-logical",
        0,
        2,
        MAX_LINUX_CONTROL_PAYLOAD,
    );
    assert_eq!(control.receive(deadline()).unwrap().payload, b"ready");
    control.observe_linux_poison_for_test(events.clone());
    let operation_deadline = deadline();
    let mut prepared = LinuxMixedDirectionBatch::prepare(
        portable_mixed_direction_batch(2),
        control.authority_profile(),
        operation_deadline,
    )
    .unwrap();
    prepared.observe_drop_for_test(events.clone());
    {
        let mut transaction = control
            .begin_linux_mixed_direction_batch(prepared, operation_deadline)
            .unwrap();
        assert!(matches!(
            transaction.prepare(),
            Err(LinuxCapabilityBatchError::Control(
                AcceptedControlError::Transport(
                    SessionTransportError::PeerExited | SessionTransportError::Native
                )
            ))
        ));
    }
    assert_eq!(
        events.lock().unwrap().as_slice(),
        &["poison", "mixed-direction-batch-drop"]
    );
    control.terminate_and_reap(deadline()).unwrap();
    drop(control);
    wait_for_baseline(before_fds, before_tasks, pid, deadline());

    for failure in [1, 17, 32] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let (mut control, pid) = accepted_control(
            "mixed-direction-import-advice-failure",
            failure,
            16,
            MAX_LINUX_CONTROL_PAYLOAD,
        );
        assert_eq!(control.receive(deadline()).unwrap().payload, b"ready");
        control.observe_linux_poison_for_test(events.clone());
        let operation_deadline = deadline();
        let mut prepared = LinuxMixedDirectionBatch::prepare(
            portable_mixed_direction_batch(16),
            control.authority_profile(),
            operation_deadline,
        )
        .unwrap();
        prepared.observe_drop_for_test(events.clone());
        {
            let mut transaction = control
                .begin_linux_mixed_direction_batch(prepared, operation_deadline)
                .unwrap();
            assert!(matches!(
                transaction.prepare(),
                Err(LinuxCapabilityBatchError::Control(
                    AcceptedControlError::Transport(
                        SessionTransportError::PeerExited | SessionTransportError::Native
                    )
                ))
            ));
        }
        assert_eq!(
            events.lock().unwrap().as_slice(),
            &["poison", "mixed-direction-batch-drop"]
        );
        control.terminate_and_reap(deadline()).unwrap();
        drop(control);
        wait_for_baseline(before_fds, before_tasks, pid, deadline());
    }

    for failure in [1, 9, 16] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let (mut control, pid) = accepted_control(
            "mixed-direction-coordinator-advice-failure",
            failure,
            16,
            MAX_LINUX_CONTROL_PAYLOAD,
        );
        assert_eq!(control.receive(deadline()).unwrap().payload, b"ready");
        control.observe_linux_poison_for_test(events.clone());
        let operation_deadline = deadline();
        let mut prepared = LinuxMixedDirectionBatch::prepare(
            portable_mixed_direction_batch(16),
            control.authority_profile(),
            operation_deadline,
        )
        .unwrap();
        prepared.observe_drop_for_test(events.clone());
        {
            let mut transaction = control
                .begin_linux_mixed_direction_batch(prepared, operation_deadline)
                .unwrap();
            transaction.fail_coordinator_advice_at_for_test(failure);
            assert_eq!(
                transaction.prepare(),
                Err(LinuxCapabilityBatchError::Memory(MemfdError::Native(
                    libc::EIO
                )))
            );
            assert!(transaction.all_final_sealed_for_test());
        }
        assert_eq!(
            events.lock().unwrap().as_slice(),
            &["poison", "mixed-direction-batch-drop"]
        );
        control.terminate_and_reap(deadline()).unwrap();
        drop(control);
        wait_for_baseline(before_fds, before_tasks, pid, deadline());
    }

    for failure in [1, 4, 8] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let (mut control, pid) = accepted_control(
            "mixed-direction-seal-failure",
            failure,
            16,
            MAX_LINUX_CONTROL_PAYLOAD,
        );
        assert_eq!(control.receive(deadline()).unwrap().payload, b"ready");
        control.observe_linux_poison_for_test(events.clone());
        let operation_deadline = deadline();
        let mut prepared = LinuxMixedDirectionBatch::prepare(
            portable_mixed_direction_batch(16),
            control.authority_profile(),
            operation_deadline,
        )
        .unwrap();
        prepared.observe_drop_for_test(events.clone());
        {
            let mut transaction = control
                .begin_linux_mixed_direction_batch(prepared, operation_deadline)
                .unwrap();
            transaction.fail_seal_at_for_test(failure);
            assert_eq!(
                transaction.prepare(),
                Err(LinuxCapabilityBatchError::Memory(MemfdError::Native(
                    libc::EIO
                )))
            );
            assert_eq!(transaction.seal_counts_for_test(), (1, 15));
        }
        assert_eq!(
            events.lock().unwrap().as_slice(),
            &["poison", "mixed-direction-batch-drop"]
        );
        control.terminate_and_reap(deadline()).unwrap();
        drop(control);
        wait_for_baseline(before_fds, before_tasks, pid, deadline());
    }

    let events = Arc::new(Mutex::new(Vec::new()));
    let (mut control, pid) = accepted_control(
        "mixed-direction-final-seal-missing",
        0,
        2,
        MAX_LINUX_CONTROL_PAYLOAD,
    );
    assert_eq!(control.receive(deadline()).unwrap().payload, b"ready");
    control.observe_linux_poison_for_test(events.clone());
    let operation_deadline = deadline();
    let mut prepared = LinuxMixedDirectionBatch::prepare(
        portable_mixed_direction_batch(2),
        control.authority_profile(),
        operation_deadline,
    )
    .unwrap();
    prepared.observe_drop_for_test(events.clone());
    {
        let mut transaction = control
            .begin_linux_mixed_direction_batch(prepared, operation_deadline)
            .unwrap();
        transaction.skip_final_sealing_for_test();
        transaction.prepare().unwrap();
        assert_eq!(transaction.seal_counts_for_test(), (1, 1));
    }
    assert_eq!(
        events.lock().unwrap().as_slice(),
        &["poison", "mixed-direction-batch-drop"]
    );
    control.terminate_and_reap(deadline()).unwrap();
    drop(control);
    wait_for_baseline(before_fds, before_tasks, pid, deadline());

    let events = Arc::new(Mutex::new(Vec::new()));
    let (mut control, pid) = accepted_control(
        "mixed-direction-stale-imported",
        0,
        2,
        MAX_LINUX_CONTROL_PAYLOAD,
    );
    assert_eq!(control.receive(deadline()).unwrap().payload, b"ready");
    control.observe_linux_poison_for_test(events.clone());
    let operation_deadline = deadline();
    let mut prepared = LinuxMixedDirectionBatch::prepare(
        portable_mixed_direction_batch(2),
        control.authority_profile(),
        operation_deadline,
    )
    .unwrap();
    prepared.observe_drop_for_test(events.clone());
    {
        let mut transaction = control
            .begin_linux_mixed_direction_batch(prepared, operation_deadline)
            .unwrap();
        assert_eq!(
            transaction.prepare(),
            Err(LinuxCapabilityBatchError::Control(
                AcceptedControlError::Control(ControlError::NonCanonical)
            ))
        );
    }
    assert_eq!(
        events.lock().unwrap().as_slice(),
        &["poison", "mixed-direction-batch-drop"]
    );
    control.terminate_and_reap(deadline()).unwrap();
    drop(control);
    wait_for_baseline(before_fds, before_tasks, pid, deadline());

    for rights in [1, 16] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let (mut control, pid) = accepted_control(
            "mixed-direction-imported-rights",
            rights,
            2,
            MAX_LINUX_CONTROL_PAYLOAD,
        );
        assert_eq!(control.receive(deadline()).unwrap().payload, b"ready");
        control.observe_linux_poison_for_test(events.clone());
        let operation_deadline = deadline();
        let mut prepared = LinuxMixedDirectionBatch::prepare(
            portable_mixed_direction_batch(2),
            control.authority_profile(),
            operation_deadline,
        )
        .unwrap();
        prepared.observe_drop_for_test(events.clone());
        {
            let mut transaction = control
                .begin_linux_mixed_direction_batch(prepared, operation_deadline)
                .unwrap();
            assert_eq!(
                transaction.prepare(),
                Err(LinuxCapabilityBatchError::Control(
                    AcceptedControlError::Transport(SessionTransportError::MalformedRecord)
                ))
            );
        }
        assert_eq!(
            events.lock().unwrap().as_slice(),
            &["poison", "mixed-direction-batch-drop"]
        );
        control.terminate_and_reap(deadline()).unwrap();
        drop(control);
        wait_for_baseline(before_fds, before_tasks, pid, deadline());
    }

    let events = Arc::new(Mutex::new(Vec::new()));
    let (mut control, pid) = accepted_control(
        "mixed-direction-imported-wrong-credentials",
        0,
        2,
        MAX_LINUX_CONTROL_PAYLOAD,
    );
    assert_eq!(control.receive(deadline()).unwrap().payload, b"ready");
    control.observe_linux_poison_for_test(events.clone());
    let operation_deadline = deadline();
    let mut prepared = LinuxMixedDirectionBatch::prepare(
        portable_mixed_direction_batch(2),
        control.authority_profile(),
        operation_deadline,
    )
    .unwrap();
    prepared.observe_drop_for_test(events.clone());
    {
        let mut transaction = control
            .begin_linux_mixed_direction_batch(prepared, operation_deadline)
            .unwrap();
        assert_eq!(
            transaction.prepare(),
            Err(LinuxCapabilityBatchError::Control(
                AcceptedControlError::Transport(SessionTransportError::IdentityMismatch)
            ))
        );
    }
    assert_eq!(
        events.lock().unwrap().as_slice(),
        &["poison", "mixed-direction-batch-drop"]
    );
    control.terminate_and_reap(deadline()).unwrap();
    drop(control);
    wait_for_baseline(before_fds, before_tasks, pid, deadline());
    assert_eq!(open_vnext_map_count(), before_maps);
}

#[test]
fn mixed_direction_batches_share_the_accepted_owner() {
    run_isolated(
        "backend::linux_vnext::spawn::tests::isolated_mixed_direction_batches_share_the_accepted_owner",
    );
}

#[test]
#[ignore = "spawned alone by mixed_direction_activation_failures_are_atomic_and_terminal"]
fn isolated_mixed_direction_activation_failures_are_atomic_and_terminal() {
    let before_fds = open_fd_count();
    let before_tasks = open_task_count();
    let before_maps = open_vnext_map_count();
    const COUNT: usize = 16;

    for failure in [1, 8, 16] {
        let cleanup_events = Arc::new(Mutex::new(Vec::new()));
        let active_events = Arc::new(Mutex::new(Vec::new()));
        let (mut control, pid) = accepted_control(
            "mixed-direction-coordinator-activation-failure",
            failure,
            COUNT,
            MAX_LINUX_CONTROL_PAYLOAD,
        );
        assert_eq!(control.receive(deadline()).unwrap().payload, b"ready");
        let session_fds = open_fd_count();
        let session_tasks = open_task_count();
        let session_maps = open_vnext_map_count();
        control.observe_linux_poison_for_test(active_events.clone());
        control.observe_active_lease_drop_for_test(active_events.clone());
        let operation_deadline = deadline();
        let mut prepared = LinuxMixedDirectionBatch::prepare(
            portable_mixed_direction_batch(COUNT),
            control.authority_profile(),
            operation_deadline,
        )
        .unwrap();
        prepared.observe_drop_for_test(cleanup_events.clone());
        prepared.observe_active_drop_for_test(active_events.clone());
        let mut transaction = control
            .begin_linux_mixed_direction_batch(prepared, operation_deadline)
            .unwrap();
        transaction.fail_activation_at_for_test(failure);
        transaction.prepare().unwrap();
        let committed = transaction.commit().unwrap();
        assert_eq!(
            control
                .activate_linux_coordinator_mixed_direction_batch(committed)
                .err(),
            Some(LinuxActivationError::Memory(MemfdError::Native(libc::EIO)))
        );
        assert_eq!(
            control.receive(deadline()),
            Err(AcceptedControlError::Control(ControlError::Poisoned))
        );
        let released = control.active_lease_facts_for_test();
        assert_eq!((released.regions, released.bytes), (0, 0));
        let active_events = active_events.lock().unwrap();
        assert_eq!(active_events.first(), Some(&"poison"));
        assert_eq!(
            active_events
                .iter()
                .filter(|event| **event == "active-mapping-drop")
                .count(),
            COUNT
        );
        assert_eq!(
            active_events
                .iter()
                .filter(|event| **event == "active-lease-drop")
                .count(),
            COUNT
        );
        let mut mappings = 0_usize;
        let mut leases = 0_usize;
        for event in active_events.iter().skip(1) {
            match *event {
                "active-mapping-drop" => mappings += 1,
                "active-lease-drop" => leases += 1,
                other => panic!("unexpected activation drop event {other}"),
            }
            assert!(leases <= mappings, "lease released before its mapping");
        }
        drop(active_events);
        assert_eq!(
            cleanup_events.lock().unwrap().as_slice(),
            &["mixed-direction-batch-drop"]
        );
        assert_eq!(open_fd_count(), session_fds);
        assert_eq!(open_task_count(), session_tasks);
        assert_eq!(open_vnext_map_count(), session_maps);
        control.terminate_and_reap(deadline()).unwrap();
        drop(control);
        wait_for_baseline(before_fds, before_tasks, pid, deadline());
        assert_eq!(open_vnext_map_count(), before_maps);
    }

    for failure in [1, 8, 16] {
        let (mut control, pid) = accepted_control(
            "mixed-direction-receiver-activation-failure",
            failure,
            COUNT,
            MAX_LINUX_CONTROL_PAYLOAD,
        );
        assert_eq!(control.receive(deadline()).unwrap().payload, b"ready");
        let session_fds = open_fd_count();
        let session_maps = open_vnext_map_count();
        let operation_deadline = deadline();
        let prepared = LinuxMixedDirectionBatch::prepare(
            portable_mixed_direction_batch(COUNT),
            control.authority_profile(),
            operation_deadline,
        )
        .unwrap();
        let mut transaction = control
            .begin_linux_mixed_direction_batch(prepared, operation_deadline)
            .unwrap();
        transaction.prepare().unwrap();
        let committed = transaction.commit().unwrap();
        let active = control
            .activate_linux_coordinator_mixed_direction_batch(committed)
            .unwrap();
        assert_eq!(active.len(), COUNT);
        drop(active);
        let released = control.active_lease_facts_for_test();
        assert_eq!((released.regions, released.bytes), (0, 0));
        assert_eq!(open_fd_count(), session_fds);
        assert_eq!(open_vnext_map_count(), session_maps);
        control
            .wait_for_linux_peer_success_for_test(deadline())
            .unwrap();
        drop(control);
        wait_for_baseline(before_fds, before_tasks, pid, deadline());
        assert_eq!(open_vnext_map_count(), before_maps);
    }
}

#[test]
fn mixed_direction_activation_failures_are_atomic_and_terminal() {
    run_isolated(
        "backend::linux_vnext::spawn::tests::isolated_mixed_direction_activation_failures_are_atomic_and_terminal",
    );
}

#[test]
#[ignore = "spawned alone by mixed_direction_ready_commit_rejects_hostile_barriers"]
fn isolated_mixed_direction_ready_commit_rejects_hostile_barriers() {
    let before_fds = open_fd_count();
    let before_tasks = open_task_count();
    let before_maps = open_vnext_map_count();

    for mode in [
        "mixed-direction-ready-application",
        "mixed-direction-ready-substitution",
        "mixed-direction-ready-truncated",
        "mixed-direction-ready-duplicate",
        "mixed-direction-commit-application",
        "mixed-direction-commit-substitution",
        "mixed-direction-commit-truncated",
        "mixed-direction-commit-duplicate",
    ] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let (mut control, pid) = accepted_control(mode, 0, 2, MAX_LINUX_CONTROL_PAYLOAD);
        assert_eq!(control.receive(deadline()).unwrap().payload, b"ready");
        control.observe_linux_poison_for_test(events.clone());
        let operation_deadline = deadline();
        let mut prepared = LinuxMixedDirectionBatch::prepare(
            portable_mixed_direction_batch(2),
            control.authority_profile(),
            operation_deadline,
        )
        .unwrap();
        prepared.observe_drop_for_test(events.clone());
        let mut transaction = control
            .begin_linux_mixed_direction_batch(prepared, operation_deadline)
            .unwrap();
        match mode {
            "mixed-direction-commit-application" => {
                transaction.interleave_application_commit_for_test();
            }
            "mixed-direction-commit-substitution" => {
                transaction.substitute_commit_manifest_for_test();
            }
            "mixed-direction-commit-truncated" => {
                transaction.truncate_commit_for_test();
            }
            "mixed-direction-commit-duplicate" => {
                transaction.duplicate_commit_for_test();
            }
            _ => {}
        }
        transaction.prepare().unwrap();
        let duplicate = mode.ends_with("duplicate");
        if duplicate {
            let committed = transaction.commit().unwrap();
            if mode == "mixed-direction-ready-duplicate" {
                assert_eq!(
                    control.receive(deadline()),
                    Err(AcceptedControlError::Control(ControlError::BadMagic))
                );
                assert_eq!(events.lock().unwrap().as_slice(), &["poison"]);
            } else {
                assert!(events.lock().unwrap().is_empty());
            }
            control
                .wait_for_linux_peer_success_for_test(deadline())
                .unwrap();
            drop(committed);
            let expected_events: &[&str] = if mode == "mixed-direction-ready-duplicate" {
                &["poison", "mixed-direction-batch-drop"]
            } else {
                &["mixed-direction-batch-drop"]
            };
            assert_eq!(events.lock().unwrap().as_slice(), expected_events);
        } else {
            assert!(matches!(
                transaction.commit(),
                Err(LinuxCapabilityBatchError::Control(
                    AcceptedControlError::Control(ControlError::NonCanonical)
                ))
            ));
            assert_eq!(
                events.lock().unwrap().as_slice(),
                &["poison", "mixed-direction-batch-drop"]
            );
            assert_eq!(
                control.send(
                    &ControlFrame {
                        kind: APPLICATION_CONTROL_KIND,
                        payload: Vec::new(),
                    },
                    deadline(),
                ),
                Err(AcceptedControlError::Control(ControlError::Poisoned))
            );
            control.terminate_and_reap(deadline()).unwrap();
        }
        drop(control);
        wait_for_baseline(before_fds, before_tasks, pid, deadline());
        assert_eq!(open_vnext_map_count(), before_maps, "mode {mode}");
    }
}

#[test]
fn mixed_direction_ready_commit_rejects_hostile_barriers() {
    run_isolated(
        "backend::linux_vnext::spawn::tests::isolated_mixed_direction_ready_commit_rejects_hostile_barriers",
    );
}

#[test]
#[ignore = "spawned alone by coordinator_writer_batch_poison_precedes_native_cleanup"]
fn isolated_coordinator_writer_batch_poison_precedes_native_cleanup() {
    let before_fds = open_fd_count();
    let before_tasks = open_task_count();

    for revalidation_failure in [false, true] {
        let events = Arc::new(Mutex::new(Vec::new()));
        let (mut control, pid) = accepted_control("echo", 0, 0, MAX_LINUX_CONTROL_PAYLOAD);
        assert_eq!(control.receive(deadline()).unwrap().payload, b"ready");
        control.observe_linux_poison_for_test(events.clone());
        let operation_deadline = deadline();
        let mut prepared = LinuxCoordinatorWriterBatch::prepare(
            portable_coordinator_writer_batch(2),
            control.authority_profile(),
            operation_deadline,
        )
        .unwrap();
        prepared.observe_drop_for_test(events.clone());
        if revalidation_failure {
            prepared.fail_revalidation_for_test();
        }
        {
            let mut transaction = control
                .begin_linux_coordinator_writer_batch(prepared, operation_deadline)
                .unwrap();
            if revalidation_failure {
                assert_eq!(
                    transaction.send(),
                    Err(LinuxCapabilityBatchError::Memory(MemfdError::WrongObject))
                );
            }
        }
        assert_eq!(
            events.lock().unwrap().as_slice(),
            &["poison", "native-batch-drop"]
        );
        assert_eq!(
            control.send(
                &ControlFrame {
                    kind: APPLICATION_CONTROL_KIND,
                    payload: Vec::new(),
                },
                deadline(),
            ),
            Err(AcceptedControlError::Control(ControlError::Poisoned))
        );
        control.terminate_and_reap(deadline()).unwrap();
        drop(control);
        wait_for_baseline(before_fds, before_tasks, pid, deadline());
    }
}

#[test]
fn coordinator_writer_batch_poison_precedes_native_cleanup() {
    run_isolated(
        "backend::linux_vnext::spawn::tests::isolated_coordinator_writer_batch_poison_precedes_native_cleanup",
    );
}

#[test]
fn receiver_control_observes_socket_hup_without_inventing_exit_status() {
    let (peer, receiver) = SeqPacketEndpoint::pair().unwrap();
    assert_eq!(
        observe_accepted_control_peer(receiver.fd.as_raw_fd(), None).unwrap(),
        PeerState::Running
    );
    drop(peer);
    assert_eq!(
        observe_accepted_control_peer(receiver.fd.as_raw_fd(), None).unwrap(),
        PeerState::ExitedUnknown
    );
}

#[test]
#[ignore = "spawned alone by bilateral_decisions_and_rejections_restore_baselines"]
fn isolated_bilateral_decisions_and_rejections_restore_baselines() {
    let before_fds = open_fd_count();
    let before_tasks = open_task_count();
    let executable = std::env::current_exe().unwrap();
    let arguments = helper_arguments();

    for payload_len in [0, 1, MAX_LINUX_HELLO_PAYLOAD] {
        let owner = spawn_negotiating(
            &executable,
            &arguments,
            &decision_environment(payload_len, payload_len, "accept"),
            hello_offer(payload_len),
            deadline(),
        )
        .unwrap();
        let pid = owner.pid();
        let accepted = match owner.decide(ApplicationDecision::Accept).unwrap() {
            DecisionOutcome::Accepted(accepted) => accepted,
            DecisionOutcome::Rejected { .. } => panic!("bilateral ACCEPT rejected"),
        };
        assert_eq!(accepted.pid(), pid);
        let evidence = accepted.into_evidence().unwrap();
        assert_eq!(evidence.pid(), pid);
        let facts = evidence.facts();
        assert_eq!(facts.parent_pid(), std::process::id());
        assert_eq!(facts.child_pid(), pid as u32);
        // SAFETY: scalar credential queries have no pointer arguments.
        assert_eq!(facts.parent_uid(), unsafe { libc::getuid() });
        // SAFETY: scalar credential queries have no pointer arguments.
        assert_eq!(facts.parent_gid(), unsafe { libc::getgid() });
        // SAFETY: scalar credential queries have no pointer arguments.
        assert_eq!(facts.child_uid(), unsafe { libc::getuid() });
        // SAFETY: scalar credential queries have no pointer arguments.
        assert_eq!(facts.child_gid(), unsafe { libc::getgid() });
        assert_ne!(facts.nonce(), [0; NONCE_LEN]);
        evidence.terminate_and_reap(deadline());
        wait_for_baseline(before_fds, before_tasks, pid, deadline());
    }

    let owner = spawn_negotiating(
        &executable,
        &arguments,
        &decision_environment(1, 1, "accept"),
        hello_offer(1),
        deadline(),
    )
    .unwrap();
    let pid = owner.pid();
    let mut accepted = match owner.decide(ApplicationDecision::Accept).unwrap() {
        DecisionOutcome::Accepted(accepted) => accepted,
        DecisionOutcome::Rejected { .. } => panic!("bilateral ACCEPT rejected"),
    };
    accepted.nonce = [0; NONCE_LEN];
    assert_eq!(
        accepted.into_evidence().err().unwrap(),
        LinuxSpawnError::InvalidInput
    );
    assert_immediate_child_and_fd_cleanup(before_fds, before_tasks, pid, deadline());

    let coordinator_reject = spawn_negotiating(
        &executable,
        &arguments,
        &decision_environment(1, 1, "accept"),
        hello_offer(1),
        deadline(),
    )
    .unwrap();
    let pid = coordinator_reject.pid();
    assert!(matches!(
        coordinator_reject
            .decide(ApplicationDecision::Reject(NonZeroU32::new(17).unwrap()))
            .unwrap(),
        DecisionOutcome::Rejected {
            by: SenderRole::Coordinator,
            reason,
            ..
        } if reason.get() == 17
    ));
    wait_for_baseline(before_fds, before_tasks, pid, deadline());

    let receiver_reject = spawn_negotiating(
        &executable,
        &arguments,
        &decision_environment(1, 1, "reject"),
        hello_offer(1),
        deadline(),
    )
    .unwrap();
    let pid = receiver_reject.pid();
    assert!(matches!(
        receiver_reject
            .decide(ApplicationDecision::Accept)
            .unwrap(),
        DecisionOutcome::Rejected {
            by: SenderRole::Receiver,
            reason,
            ..
        } if reason.get() == 19
    ));
    wait_for_baseline(before_fds, before_tasks, pid, deadline());
}

#[test]
fn bilateral_decisions_and_rejections_restore_baselines() {
    run_isolated(
        "backend::linux_vnext::spawn::tests::isolated_bilateral_decisions_and_rejections_restore_baselines",
    );
}

#[test]
#[ignore = "spawned alone by challenged_decision_mutations_restore_baselines"]
fn isolated_challenged_decision_mutations_restore_baselines() {
    let before_fds = open_fd_count();
    let before_tasks = open_task_count();
    for mode in [
        "prequeued-accept",
        "prequeued-reject",
        "duplicate-hello",
        "malformed-flood",
        "wrong-role",
        "wrong-nonce",
        "wrong-challenge",
        "zero-challenge",
        "wrong-features",
        "wrong-limit-regions",
        "wrong-limit-active",
        "wrong-limit-region-bytes",
        "wrong-limit-batch-bytes",
        "wrong-limit-active-bytes",
        "wrong-limit-transactions",
        "wrong-limit-bootstrap",
        "wrong-limit-control",
        "wrong-atomics",
        "wrong-target",
        "wrong-digest",
        "reserved",
        "truncated",
        "rights",
        "reject-wrong-role",
        "reject-wrong-nonce",
        "reject-wrong-challenge",
        "reject-zero-reason",
        "reject-reserved",
        "reject-rights",
    ] {
        let mut environment = decision_environment(1, 1, "accept");
        environment.push((
            OsString::from("NATIVE_IPC_VNEXT_TEST_MALICIOUS_DECISION"),
            OsString::from(mode),
        ));
        let owner = spawn_negotiating(
            &std::env::current_exe().unwrap(),
            &helper_arguments(),
            &environment,
            hello_offer(1),
            deadline(),
        )
        .unwrap();
        let pid = owner.pid();
        assert!(
            owner.decide(ApplicationDecision::Accept).is_err(),
            "malicious decision accepted: {mode}"
        );
        wait_for_baseline(before_fds, before_tasks, pid, deadline());
    }
}

#[test]
fn challenged_decision_mutations_restore_baselines() {
    run_isolated(
        "backend::linux_vnext::spawn::tests::isolated_challenged_decision_mutations_restore_baselines",
    );
}

#[test]
#[ignore = "spawned alone by decision_entropy_and_stored_deadline_restore_baselines"]
fn isolated_decision_entropy_and_stored_deadline_restore_baselines() {
    let before_fds = open_fd_count();
    let before_tasks = open_task_count();
    let executable = std::env::current_exe().unwrap();
    let arguments = helper_arguments();

    for decision in [
        ApplicationDecision::Accept,
        ApplicationDecision::Reject(NonZeroU32::new(31).unwrap()),
    ] {
        for fault in [
            EntropyFault::WouldBlock,
            EntropyFault::Short,
            EntropyFault::AllZero,
        ] {
            let owner = spawn_negotiating(
                &executable,
                &arguments,
                &decision_environment(1, 1, "accept"),
                hello_offer(1),
                deadline(),
            )
            .unwrap();
            let pid = owner.pid();
            assert_eq!(
                owner
                    .decide_with_entropy_fault(decision, fault)
                    .err()
                    .unwrap(),
                LinuxSpawnError::EntropyUnavailable
            );
            wait_for_baseline(before_fds, before_tasks, pid, deadline());
        }
    }

    let owner = spawn_negotiating(
        &executable,
        &arguments,
        &decision_environment(1, 1, "accept"),
        hello_offer(1),
        deadline(),
    )
    .unwrap();
    let pid = owner.pid();
    let accepted = match owner
        .decide_with_entropy_fault(ApplicationDecision::Accept, EntropyFault::Interrupted)
        .unwrap()
    {
        DecisionOutcome::Accepted(accepted) => accepted,
        DecisionOutcome::Rejected { .. } => panic!("interrupted challenge rejected"),
    };
    accepted.terminate_and_reap(deadline());
    wait_for_baseline(before_fds, before_tasks, pid, deadline());

    let short = AbsoluteDeadline::after(Duration::from_secs(2)).unwrap();
    let owner = spawn_negotiating(
        &executable,
        &arguments,
        &decision_environment(1, 1, "accept"),
        hello_offer(1),
        short,
    )
    .unwrap();
    let pid = owner.pid();
    while !short.is_expired() {
        std::thread::yield_now();
    }
    assert_eq!(
        owner.decide(ApplicationDecision::Accept).err().unwrap(),
        LinuxSpawnError::DeadlineExpired
    );
    wait_for_baseline(before_fds, before_tasks, pid, deadline());
}

#[test]
fn decision_entropy_and_stored_deadline_restore_baselines() {
    run_isolated(
        "backend::linux_vnext::spawn::tests::isolated_decision_entropy_and_stored_deadline_restore_baselines",
    );
}

#[test]
#[ignore = "spawned alone by reexec_between_hello_and_accept_never_becomes_accepted"]
fn isolated_reexec_between_hello_and_accept_never_becomes_accepted() {
    let before_fds = open_fd_count();
    let before_tasks = open_task_count();
    let directory =
        std::env::temp_dir().join(format!("native-ipc-decision-reexec-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir(&directory).unwrap();
    let replacement = directory.join("replacement-helper");
    std::fs::copy(std::env::current_exe().unwrap(), &replacement).unwrap();
    std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o700)).unwrap();

    let mut environment = decision_environment(1, 1, "accept");
    environment.extend([
        (
            OsString::from("NATIVE_IPC_VNEXT_TEST_MALICIOUS_DECISION"),
            OsString::from("reexec"),
        ),
        (
            OsString::from("NATIVE_IPC_VNEXT_TEST_REEXEC_PATH"),
            replacement.as_os_str().to_owned(),
        ),
    ]);
    let owner = spawn_negotiating(
        &std::env::current_exe().unwrap(),
        &helper_arguments(),
        &environment,
        hello_offer(1),
        deadline(),
    )
    .unwrap();
    let pid = owner.pid();
    assert_eq!(
        owner.decide(ApplicationDecision::Accept).err().unwrap(),
        LinuxSpawnError::WrongExecutable
    );
    wait_for_baseline(before_fds, before_tasks, pid, deadline());
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn reexec_between_hello_and_accept_never_becomes_accepted() {
    run_isolated(
        "backend::linux_vnext::spawn::tests::isolated_reexec_between_hello_and_accept_never_becomes_accepted",
    );
}

#[test]
#[ignore = "spawned alone by decision_silence_and_exit_restore_exact_baselines"]
fn isolated_decision_silence_and_exit_restore_exact_baselines() {
    let before_fds = open_fd_count();
    let before_tasks = open_task_count();
    let executable = std::env::current_exe().unwrap();
    let arguments = helper_arguments();

    let mut silent_environment = decision_environment(1, 1, "accept");
    silent_environment.push((
        OsString::from("NATIVE_IPC_VNEXT_TEST_MALICIOUS_DECISION"),
        OsString::from("decision-silent"),
    ));
    let operation_deadline = AbsoluteDeadline::after(Duration::from_millis(250)).unwrap();
    let started = std::time::Instant::now();
    let owner = spawn_negotiating(
        &executable,
        &arguments,
        &silent_environment,
        hello_offer(1),
        operation_deadline,
    )
    .unwrap();
    let pid = owner.pid();
    assert_eq!(
        owner.decide(ApplicationDecision::Accept).err().unwrap(),
        LinuxSpawnError::Packet(PacketError::DeadlineExpired)
    );
    assert!(started.elapsed() < Duration::from_secs(2));
    wait_for_baseline(before_fds, before_tasks, pid, deadline());

    let mut exit_environment = decision_environment(1, 1, "accept");
    exit_environment.push((
        OsString::from("NATIVE_IPC_VNEXT_TEST_MALICIOUS_DECISION"),
        OsString::from("decision-exit"),
    ));
    let owner = spawn_negotiating(
        &executable,
        &arguments,
        &exit_environment,
        hello_offer(1),
        deadline(),
    )
    .unwrap();
    let pid = owner.pid();
    let started = std::time::Instant::now();
    assert_eq!(
        owner.decide(ApplicationDecision::Accept).err().unwrap(),
        LinuxSpawnError::Packet(PacketError::PeerExited)
    );
    assert!(started.elapsed() < Duration::from_secs(2));
    wait_for_baseline(before_fds, before_tasks, pid, deadline());
}

#[test]
fn decision_silence_and_exit_restore_exact_baselines() {
    run_isolated(
        "backend::linux_vnext::spawn::tests::isolated_decision_silence_and_exit_restore_exact_baselines",
    );
}

fn consume_coordinator_then(raw: RawFd, mode: &str) -> ! {
    // SAFETY: the helper uniquely owns the inherited bootstrap descriptor.
    let mut endpoint = unsafe { SeqPacketEndpoint::from_inherited(raw) }.unwrap();
    let expected_parent = PacketCredentials {
        // SAFETY: scalar process and credential queries have no pointers.
        pid: unsafe { libc::getppid() } as u32,
        // SAFETY: automatic SCM_CREDENTIALS reports the real UID.
        uid: unsafe { libc::getuid() },
        // SAFETY: automatic SCM_CREDENTIALS reports the real GID.
        gid: unsafe { libc::getgid() },
    };
    let packet = receive_socket_before(&mut endpoint, expected_parent, deadline()).unwrap();
    let nonce = authenticated_nonce(&packet.bytes).unwrap();
    assert!(matches!(
        decode_frame(
            &packet.bytes,
            SenderRole::Coordinator,
            nonce,
            MAX_LINUX_HELLO_PAYLOAD as u32,
        )
        .unwrap(),
        NegotiationFrame::Hello(_)
    ));
    match mode {
        "silent" => loop {
            // SAFETY: exact-child cleanup terminates this disposable helper.
            unsafe { libc::pause() };
        },
        "exit" => {
            // SAFETY: this disposable helper must exit without Rust teardown so
            // the coordinator observes exact pidfd/socket terminal readiness.
            unsafe { libc::_exit(0) }
        }
        _ => panic!("unknown HELLO lifecycle mode"),
    }
}

fn send_malicious_receiver_hello(raw: RawFd, mode: &str) {
    // SAFETY: the helper uniquely owns the inherited bootstrap descriptor.
    let mut endpoint = unsafe { SeqPacketEndpoint::from_inherited(raw) }.unwrap();
    let expected_parent = PacketCredentials {
        pid: unsafe { libc::getppid() } as u32,
        uid: unsafe { libc::getuid() },
        gid: unsafe { libc::getgid() },
    };
    let packet = receive_socket_before(&mut endpoint, expected_parent, deadline()).unwrap();
    let nonce = authenticated_nonce(&packet.bytes).unwrap();
    let atomics = discover_atomic_capabilities().unwrap();
    let receiver = make_hello(SenderRole::Receiver, nonce, hello_offer(1), atomics).unwrap();
    let mut encoded = encode_hello(&receiver).unwrap();
    match mode {
        "wrong-role" => encoded[14] = SenderRole::Coordinator as u8,
        "wrong-nonce" => encoded[32] ^= 0x80,
        "wrong-target" => encoded[160..162].copy_from_slice(&2_u16.to_le_bytes()),
        "wrong-atomics" => encoded[152..156].copy_from_slice(&8192_u32.to_le_bytes()),
        "zero-limit" => encoded[96..98].fill(0),
        "reserved" => encoded[198] = 1,
        "truncated" => encoded.truncate(HEADER_LEN - 1),
        "rights" => {
            let descriptor = unsafe {
                OwnedFd::from_raw_fd(libc::open(
                    c"/dev/null".as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC,
                ))
            };
            endpoint.send(&encoded, &[descriptor.as_raw_fd()]).unwrap();
            return;
        }
        _ => panic!("unknown malicious HELLO mode"),
    }
    send_socket_before(&mut endpoint, &encoded, deadline()).unwrap();
}

#[test]
#[ignore = "spawned alone by canonical_two_sided_hello_native_boundaries"]
fn isolated_canonical_two_sided_hello_native_boundaries() {
    let before_fds = open_fd_count();
    let before_tasks = open_task_count();
    let mut nonces = Vec::new();
    for (coordinator_len, receiver_len) in [
        (0, 0),
        (1, 1),
        (MAX_LINUX_HELLO_PAYLOAD, MAX_LINUX_HELLO_PAYLOAD),
    ] {
        let environment = [
            (
                OsString::from("NATIVE_IPC_VNEXT_TEST_HELLO"),
                OsString::from(receiver_len.to_string()),
            ),
            (
                OsString::from("NATIVE_IPC_VNEXT_TEST_COORDINATOR_LEN"),
                OsString::from(coordinator_len.to_string()),
            ),
        ];
        let owner = spawn_negotiating(
            &std::env::current_exe().unwrap(),
            &helper_arguments(),
            &environment,
            hello_offer(coordinator_len),
            deadline(),
        )
        .unwrap();
        assert_ne!(owner.nonce, [0; NONCE_LEN]);
        assert_eq!(owner._peer_application_payload.len(), receiver_len);
        assert!(!nonces.contains(&owner.nonce));
        nonces.push(owner.nonce);
        let pid = owner.pid();
        owner.terminate_and_reap(deadline());
        wait_for_baseline(before_fds, before_tasks, pid, deadline());
    }
}

#[test]
fn canonical_two_sided_hello_native_boundaries() {
    run_isolated(
        "backend::linux_vnext::spawn::tests::isolated_canonical_two_sided_hello_native_boundaries",
    );
}

#[test]
#[ignore = "spawned alone by hello_payload_feature_and_entropy_fail_before_clone"]
fn isolated_hello_payload_feature_and_entropy_fail_before_clone() {
    let before_fds = open_fd_count();
    let before_tasks = open_task_count();
    let before_children = std::fs::read_to_string("/proc/thread-self/children").unwrap();
    let executable = std::env::current_exe().unwrap();
    LAST_SPAWN_PID.with(|slot| slot.set(0));
    assert_eq!(
        spawn_negotiating(
            &executable,
            &helper_arguments(),
            &[],
            hello_offer(MAX_LINUX_HELLO_PAYLOAD + 1),
            deadline(),
        )
        .err()
        .unwrap(),
        LinuxSpawnError::InvalidInput
    );
    assert_eq!(LAST_SPAWN_PID.with(|slot| slot.get()), 0);

    let mut invalid_features = hello_offer(0);
    invalid_features.required_features = FeatureBits([1 << 63, 0]);
    assert_eq!(
        spawn_negotiating(
            &executable,
            &helper_arguments(),
            &[],
            invalid_features,
            deadline(),
        )
        .err()
        .unwrap(),
        LinuxSpawnError::Negotiation(NegotiationWireError::RequiredFeatureNotSupported)
    );
    assert_eq!(LAST_SPAWN_PID.with(|slot| slot.get()), 0);

    for (fault, expected) in [
        (
            EntropyFault::WouldBlock,
            LinuxSpawnError::EntropyUnavailable,
        ),
        (EntropyFault::Short, LinuxSpawnError::EntropyUnavailable),
        (EntropyFault::AllZero, LinuxSpawnError::EntropyUnavailable),
    ] {
        assert_eq!(
            spawn_negotiating_with_fault(
                &executable,
                &helper_arguments(),
                &[],
                hello_offer(0),
                SpawnFault::None,
                fault,
                deadline(),
            )
            .err()
            .unwrap(),
            expected
        );
        assert_eq!(LAST_SPAWN_PID.with(|slot| slot.get()), 0);
    }
    assert_ne!(
        generate_nonce(deadline(), EntropyFault::Interrupted).unwrap(),
        [0; NONCE_LEN]
    );
    assert_eq!(open_fd_count(), before_fds);
    assert_eq!(open_task_count(), before_tasks);
    assert_eq!(
        std::fs::read_to_string("/proc/thread-self/children").unwrap(),
        before_children
    );
}

#[test]
fn hello_payload_feature_and_entropy_fail_before_clone() {
    run_isolated(
        "backend::linux_vnext::spawn::tests::isolated_hello_payload_feature_and_entropy_fail_before_clone",
    );
}

#[test]
fn credential_changing_executable_modes_fail_before_clone() {
    let directory =
        std::env::temp_dir().join(format!("native-ipc-credential-mode-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir(&directory).unwrap();
    for mode in [0o4700, 0o2700] {
        let path = directory.join(format!("helper-{mode:o}"));
        std::fs::copy(std::env::current_exe().unwrap(), &path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        LAST_SPAWN_PID.with(|slot| slot.set(0));
        assert_eq!(
            spawn_unauthenticated(&path, &helper_arguments(), &[], deadline())
                .err()
                .unwrap(),
            LinuxSpawnError::InvalidInput
        );
        assert_eq!(LAST_SPAWN_PID.with(|slot| slot.get()), 0);
    }
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
#[ignore = "root-only disposable SCM_CREDENTIALS real-ID characterization"]
fn isolated_scm_credentials_bind_real_ids_when_effective_ids_differ() {
    // Hosted non-root runners cannot create this identity split. Native root
    // Docker and equivalent disposable hosts exercise both HELLO directions.
    if unsafe { libc::geteuid() } != 0 || unsafe { libc::getegid() } != 0 {
        return;
    }
    // Preserve effective and saved root while changing only the real IDs.
    // SAFETY: this ignored test runs alone in a disposable subprocess.
    assert_eq!(unsafe { libc::setresgid(65534, 0, 0) }, 0);
    // SAFETY: this ignored test runs alone in a disposable subprocess.
    assert_eq!(unsafe { libc::setresuid(65534, 0, 0) }, 0);
    assert_ne!(unsafe { libc::getuid() }, unsafe { libc::geteuid() });
    assert_ne!(unsafe { libc::getgid() }, unsafe { libc::getegid() });

    let owner = spawn_negotiating(
        &std::env::current_exe().unwrap(),
        &helper_arguments(),
        &[
            (
                OsString::from("NATIVE_IPC_VNEXT_TEST_HELLO"),
                OsString::from("1"),
            ),
            (
                OsString::from("NATIVE_IPC_VNEXT_TEST_COORDINATOR_LEN"),
                OsString::from("1"),
            ),
        ],
        hello_offer(1),
        deadline(),
    )
    .unwrap();
    owner.terminate_and_reap(deadline());

    // SAFETY: effective/saved root remains available in this disposable test.
    assert_eq!(unsafe { libc::setresuid(0, 0, 0) }, 0);
    // SAFETY: effective/saved root remains available in this disposable test.
    assert_eq!(unsafe { libc::setresgid(0, 0, 0) }, 0);
}

#[test]
fn scm_credentials_bind_real_ids_when_effective_ids_differ() {
    run_isolated(
        "backend::linux_vnext::spawn::tests::isolated_scm_credentials_bind_real_ids_when_effective_ids_differ",
    );
}

#[test]
#[ignore = "spawned alone by malformed_receiver_hello_poisoning_restores_baseline"]
fn isolated_malformed_receiver_hello_poisoning_restores_baseline() {
    let before_fds = open_fd_count();
    let before_tasks = open_task_count();
    for mode in [
        "wrong-role",
        "wrong-nonce",
        "wrong-target",
        "wrong-atomics",
        "zero-limit",
        "reserved",
        "truncated",
        "rights",
    ] {
        let result = spawn_negotiating(
            &std::env::current_exe().unwrap(),
            &helper_arguments(),
            &[(
                OsString::from("NATIVE_IPC_VNEXT_TEST_MALICIOUS_HELLO"),
                OsString::from(mode),
            )],
            hello_offer(1),
            deadline(),
        );
        assert!(result.is_err(), "malicious HELLO accepted: {mode}");
        let pid = LAST_SPAWN_PID.with(|slot| slot.get());
        assert!(pid > 0);
        wait_for_baseline(before_fds, before_tasks, pid, deadline());
    }
}

#[test]
fn malformed_receiver_hello_poisoning_restores_baseline() {
    run_isolated(
        "backend::linux_vnext::spawn::tests::isolated_malformed_receiver_hello_poisoning_restores_baseline",
    );
}

#[test]
#[ignore = "spawned alone by hello_deadline_and_peer_exit_restore_exact_baselines"]
fn isolated_hello_deadline_and_peer_exit_restore_exact_baselines() {
    let before_fds = open_fd_count();
    let before_tasks = open_task_count();
    let executable = std::env::current_exe().unwrap();
    let arguments = helper_arguments();

    let operation_deadline = AbsoluteDeadline::after(Duration::from_millis(250)).unwrap();
    let started = std::time::Instant::now();
    let silent = spawn_negotiating(
        &executable,
        &arguments,
        &[(
            OsString::from("NATIVE_IPC_VNEXT_TEST_HELLO_LIFECYCLE"),
            OsString::from("silent"),
        )],
        hello_offer(1),
        operation_deadline,
    )
    .err()
    .unwrap();
    let elapsed = started.elapsed();
    assert_eq!(
        silent,
        LinuxSpawnError::Packet(PacketError::DeadlineExpired)
    );
    assert!(elapsed >= Duration::from_millis(100));
    assert!(elapsed < Duration::from_secs(2));
    let silent_pid = LAST_SPAWN_PID.with(|slot| slot.get());
    wait_for_baseline(before_fds, before_tasks, silent_pid, deadline());

    let started = std::time::Instant::now();
    let exited = spawn_negotiating(
        &executable,
        &arguments,
        &[(
            OsString::from("NATIVE_IPC_VNEXT_TEST_HELLO_LIFECYCLE"),
            OsString::from("exit"),
        )],
        hello_offer(1),
        deadline(),
    )
    .err()
    .unwrap();
    assert_eq!(exited, LinuxSpawnError::Packet(PacketError::PeerExited));
    assert!(started.elapsed() < Duration::from_secs(2));
    let exited_pid = LAST_SPAWN_PID.with(|slot| slot.get());
    wait_for_baseline(before_fds, before_tasks, exited_pid, deadline());
}

#[test]
fn hello_deadline_and_peer_exit_restore_exact_baselines() {
    run_isolated(
        "backend::linux_vnext::spawn::tests::isolated_hello_deadline_and_peer_exit_restore_exact_baselines",
    );
}

#[test]
fn input_validation_precedes_clone() {
    let executable = std::env::current_exe().unwrap();
    let arguments = helper_arguments();
    assert_eq!(
        spawn_unauthenticated(
            &executable,
            &arguments,
            &[(
                OsString::from("NATIVE_IPC_VNEXT_BOOTSTRAP_FD"),
                OsString::from("9")
            )],
            deadline(),
        )
        .err()
        .unwrap(),
        LinuxSpawnError::InvalidInput
    );
    assert_eq!(
        spawn_unauthenticated(
            &executable,
            &[OsString::from_vec(b"bad\0argument".to_vec())],
            &[],
            deadline(),
        )
        .err()
        .unwrap(),
        LinuxSpawnError::InvalidInput
    );
    assert_eq!(
        spawn_unauthenticated(
            &executable,
            &arguments,
            &[(
                OsString::from_vec(b"BAD\0KEY".to_vec()),
                OsString::from("x")
            )],
            deadline(),
        )
        .err()
        .unwrap(),
        LinuxSpawnError::InvalidInput
    );
}

#[test]
#[ignore = "spawned alone by atomic_spawn_success_and_failures_restore_baseline"]
fn isolated_atomic_spawn_success_and_failures_restore_baseline() {
    let before_fds = open_fd_count();
    let before_tasks = open_task_count();

    let owner = spawn(SpawnFault::None, deadline()).unwrap();
    let pid = owner.pid();
    assert!(pid > 0);
    owner.terminate_and_reap(deadline());
    wait_for_baseline(before_fds, before_tasks, pid, deadline());

    for (fault, expected) in [
        (
            SpawnFault::CloseRange,
            LinuxSpawnError::Child {
                stage: 1,
                errno: libc::EPERM,
            },
        ),
        (
            SpawnFault::BootstrapFd,
            LinuxSpawnError::Child {
                stage: 2,
                errno: libc::EPERM,
            },
        ),
        (
            SpawnFault::SetSid,
            LinuxSpawnError::Child {
                stage: 3,
                errno: libc::EPERM,
            },
        ),
        (
            SpawnFault::Mdwe,
            LinuxSpawnError::Child {
                stage: 4,
                errno: libc::EPERM,
            },
        ),
        (
            SpawnFault::Exec,
            LinuxSpawnError::Child {
                stage: 5,
                errno: libc::ENOENT,
            },
        ),
        (SpawnFault::Partial, LinuxSpawnError::MalformedChildError),
        (SpawnFault::Malformed, LinuxSpawnError::MalformedChildError),
    ] {
        assert_eq!(spawn(fault, deadline()).err().unwrap(), expected);
        let pid = LAST_SPAWN_PID.with(|slot| slot.get());
        assert!(pid > 0);
        wait_for_baseline(before_fds, before_tasks, pid, deadline());
    }

    // A silent child can disappear from /proc before pidfd readiness becomes
    // observable, or readiness can win first. Both are exact fail-closed
    // terminal observations of the same owned child.
    for _ in 0..16 {
        assert!(matches!(
            spawn(SpawnFault::SilentExit, deadline()).err().unwrap(),
            LinuxSpawnError::ExitedBeforeConfirmation | LinuxSpawnError::WrongExecutable
        ));
        let pid = LAST_SPAWN_PID.with(|slot| slot.get());
        assert!(pid > 0);
        wait_for_baseline(before_fds, before_tasks, pid, deadline());
    }

    let short = AbsoluteDeadline::after(Duration::from_millis(2)).unwrap();
    assert_eq!(
        spawn(SpawnFault::Stall, short).err().unwrap(),
        LinuxSpawnError::DeadlineExpired
    );
    let pid = LAST_SPAWN_PID.with(|slot| slot.get());
    wait_for_baseline(before_fds, before_tasks, pid, deadline());

    for cycle in 0..24 {
        let owner = spawn(SpawnFault::None, deadline()).unwrap();
        let pid = owner.pid();
        if cycle % 3 == 0 {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                let _owner = owner;
                panic!("spawn owner unwind");
            }));
            assert!(result.is_err());
        } else {
            drop(owner);
        }
        wait_for_baseline(before_fds, before_tasks, pid, deadline());
    }
}

#[test]
fn atomic_spawn_success_and_failures_restore_baseline() {
    run_isolated(
        "backend::linux_vnext::spawn::tests::isolated_atomic_spawn_success_and_failures_restore_baseline",
    );
}

#[test]
#[ignore = "spawned alone by held_path_replacement_and_occupied_fds_do_not_change_identity_or_slot"]
fn isolated_held_path_replacement_and_occupied_fds_do_not_change_identity_or_slot() {
    let before_fds = open_fd_count();
    let before_tasks = open_task_count();
    let directory = std::env::temp_dir().join(format!("native-ipc-spawn-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("helper");
    std::fs::copy(std::env::current_exe().unwrap(), &path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();

    let occupied: Vec<OwnedFd> = (0..48)
        .map(|_| {
            let raw =
                unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
            assert!(raw >= 0);
            unsafe { OwnedFd::from_raw_fd(raw) }
        })
        .collect();
    let held = HeldExecutable::open(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    std::fs::copy("/bin/sh", &path).unwrap();
    let owner = spawn_held_with_fault(held, &helper_arguments(), &[], SpawnFault::None, deadline())
        .unwrap();
    let pid = owner.pid();
    owner.terminate_and_reap(deadline());
    drop(occupied);
    std::fs::remove_dir_all(directory).unwrap();
    wait_for_baseline(before_fds, before_tasks, pid, deadline());
}

#[test]
fn held_path_replacement_and_occupied_fds_do_not_change_identity_or_slot() {
    run_isolated(
        "backend::linux_vnext::spawn::tests::isolated_held_path_replacement_and_occupied_fds_do_not_change_identity_or_slot",
    );
}

fn run_isolated(test: &str) {
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test, "--ignored", "--nocapture"])
        .status()
        .unwrap();
    assert!(status.success(), "isolated spawn test failed: {test}");
}
