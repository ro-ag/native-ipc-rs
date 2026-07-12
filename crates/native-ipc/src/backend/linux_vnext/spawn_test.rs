use super::*;
use static_assertions::{assert_impl_all, assert_not_impl_any};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
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

fn deadline() -> AbsoluteDeadline {
    AbsoluteDeadline::after(Duration::from_secs(5)).unwrap()
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

fn open_fd_count() -> usize {
    std::fs::read_dir("/proc/self/fd").unwrap().count()
}

fn open_task_count() -> usize {
    std::fs::read_dir("/proc/self/task").unwrap().count()
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
        let state = receive_inherited_hello(raw, hello_offer(receiver_payload_len), deadline())
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
