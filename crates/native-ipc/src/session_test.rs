use super::*;
use static_assertions::{assert_impl_all, assert_not_impl_any};

assert_impl_all!(Session<Coordinator, Negotiating>: Send);
assert_not_impl_any!(Session<Coordinator, Negotiating>: Sync, Clone);
assert_impl_all!(Session<Receiver, Negotiating>: Send);
assert_not_impl_any!(Session<Receiver, Negotiating>: Sync, Clone);
assert_impl_all!(Session<Coordinator, Ready>: Send);
assert_not_impl_any!(Session<Coordinator, Ready>: Sync, Clone);
assert_impl_all!(Session<Receiver, Ready>: Send);
assert_not_impl_any!(Session<Receiver, Ready>: Sync, Clone);
assert_impl_all!(ReceiverBootstrap: Send);
assert_not_impl_any!(ReceiverBootstrap: Sync, Clone, Copy);

#[test]
fn public_session_backend_status_is_first_class_and_target_exact() {
    assert_eq!(backend_status(), BackendStatus::Available);
}

#[test]
fn public_session_inputs_are_explicit_bounded_and_role_typed() {
    let command = SessionCommand::new("/absolute/helper")
        .arg("--mode")
        .env("KEY", "first")
        .env("KEY", "replacement");
    assert_eq!(command.executable, PathBuf::from("/absolute/helper"));
    assert_eq!(command.arguments.len(), 2);
    assert_eq!(command.environment.len(), 1);
    assert_eq!(command.environment[0].1, OsString::from("replacement"));

    let deadline = AbsoluteDeadline::after(Duration::from_secs(1)).unwrap();
    let options = SessionOptions::new(deadline, ExecutableIdentityPolicy::ExactOpenedFile)
        .with_limits(SessionLimits::default())
        .with_application_payload(b"opaque".to_vec())
        .require_atomic_u32()
        .require_atomic_u64();
    assert_eq!(options.deadline, deadline);
    assert_eq!(options.application_payload, b"opaque");
    assert!(options.require_atomic_u32 && options.require_atomic_u64);

    assert_eq!(RejectionReason::APPLICATION_DECLINED.get(), 1);
    assert_eq!(RejectionReason::INCOMPATIBLE_APPLICATION_PROTOCOL.get(), 2);
    assert_eq!(RejectionReason::APPLICATION_POLICY.get(), 3);
    assert!(RejectionReason::application_specific(0x7fff_ffff).is_none());
    assert_eq!(
        RejectionReason::application_specific(0x8000_0042)
            .unwrap()
            .get(),
        0x8000_0042
    );

    #[cfg(target_os = "linux")]
    {
        assert!(
            SessionCommand::new("/absolute/helper")
                .env("NATIVE_IPC_VNEXT_BOOTSTRAP_FD", "7")
                .has_reserved_environment()
        );
        assert!(
            SessionCommand::new("/absolute/helper")
                .env("NATIVE_IPC_VNEXT_PUBLIC_BOOTSTRAP", "1")
                .has_reserved_environment()
        );
        assert_eq!(
            RejectionReason::from_wire(NonZeroU32::new(3).unwrap()),
            Some(RejectionReason::APPLICATION_POLICY)
        );
        assert_eq!(
            RejectionReason::from_wire(NonZeroU32::new(4).unwrap()),
            None
        );
        assert_eq!(
            RejectionReason::from_wire(NonZeroU32::new(0x8000_0042).unwrap()),
            RejectionReason::application_specific(0x8000_0042)
        );
    }
}

#[cfg(target_os = "macos")]
#[test]
fn macos_public_spawn_is_wired_and_no_longer_fails_closed() {
    let command = SessionCommand::new(std::env::current_exe().unwrap())
        .env("NATIVE_IPC_MACH_NONCE", "forged");
    let options = SessionOptions::new(
        AbsoluteDeadline::after(Duration::from_secs(1)).unwrap(),
        ExecutableIdentityPolicy::ExactOpenedFile,
    );
    let failure = CoordinatorSession::<Negotiating>::spawn(command, options)
        .err()
        .unwrap();
    assert_ne!(failure.reason(), SessionError::BackendUnavailable);
    assert_eq!(failure.reason(), SessionError::InvalidInput);
    assert_eq!(
        failure.transaction_state(),
        SessionTransactionState::NotEstablished
    );
    assert!(!failure.is_poisoned());
    assert!(failure.cleanup().is_none());
}

#[cfg(target_os = "macos")]
#[test]
fn macos_public_pre_spawn_failure_is_not_misreported_as_negotiating() {
    let failure = CoordinatorSession::<Negotiating>::spawn(
        SessionCommand::new("relative-helper"),
        SessionOptions::new(
            AbsoluteDeadline::after(Duration::from_secs(1)).unwrap(),
            ExecutableIdentityPolicy::ExactOpenedFile,
        ),
    )
    .err()
    .unwrap();
    assert_eq!(failure.reason(), SessionError::InvalidInput);
    assert_eq!(
        failure.transaction_state(),
        SessionTransactionState::NotEstablished
    );
    assert!(!failure.is_poisoned());
}

#[test]
fn limits_are_finite_validated_and_negotiated_by_minimum() {
    let local = SessionLimits::default();
    local.validate().unwrap();
    let peer = SessionLimits {
        max_regions_per_batch: 4,
        max_region_bytes: local.max_region_bytes / 2,
        max_batch_bytes: local.max_batch_bytes / 2,
        max_active_regions: local.max_active_regions / 2,
        max_active_bytes: local.max_active_bytes / 2,
        max_transactions: local.max_transactions / 2,
        max_bootstrap_payload_bytes: local.max_bootstrap_payload_bytes / 2,
        max_control_payload_bytes: local.max_control_payload_bytes / 2,
    };
    let effective = SessionLimits::negotiate(local, peer).unwrap();
    assert_eq!(effective, peer);

    let zeroes = [
        SessionLimits {
            max_regions_per_batch: 0,
            ..local
        },
        SessionLimits {
            max_region_bytes: 0,
            ..local
        },
        SessionLimits {
            max_batch_bytes: 0,
            ..local
        },
        SessionLimits {
            max_active_regions: 0,
            ..local
        },
        SessionLimits {
            max_active_bytes: 0,
            ..local
        },
        SessionLimits {
            max_transactions: 0,
            ..local
        },
        SessionLimits {
            max_bootstrap_payload_bytes: 0,
            ..local
        },
        SessionLimits {
            max_control_payload_bytes: 0,
            ..local
        },
    ];
    for zero in zeroes {
        assert_eq!(zero.validate(), Err(NegotiationError::ZeroLimit));
    }

    let exact_maxima = SessionLimits {
        max_regions_per_batch: HARD_MAX_REGIONS_PER_BATCH,
        max_region_bytes: HARD_MAX_REGION_BYTES,
        max_batch_bytes: HARD_MAX_BATCH_BYTES,
        max_active_regions: HARD_MAX_ACTIVE_REGIONS,
        max_active_bytes: HARD_MAX_ACTIVE_BYTES,
        max_transactions: HARD_MAX_TRANSACTIONS,
        max_bootstrap_payload_bytes: HARD_MAX_BOOTSTRAP_PAYLOAD_BYTES,
        max_control_payload_bytes: HARD_MAX_CONTROL_PAYLOAD_BYTES,
    };
    assert_eq!(exact_maxima.validate(), Ok(exact_maxima));

    let oversized = [
        SessionLimits {
            max_regions_per_batch: HARD_MAX_REGIONS_PER_BATCH + 1,
            ..local
        },
        SessionLimits {
            max_region_bytes: HARD_MAX_REGION_BYTES + 1,
            ..local
        },
        SessionLimits {
            max_batch_bytes: HARD_MAX_BATCH_BYTES + 1,
            ..local
        },
        SessionLimits {
            max_active_regions: HARD_MAX_ACTIVE_REGIONS + 1,
            ..local
        },
        SessionLimits {
            max_active_bytes: HARD_MAX_ACTIVE_BYTES + 1,
            ..local
        },
        SessionLimits {
            max_transactions: HARD_MAX_TRANSACTIONS + 1,
            ..local
        },
        SessionLimits {
            max_bootstrap_payload_bytes: HARD_MAX_BOOTSTRAP_PAYLOAD_BYTES + 1,
            ..local
        },
        SessionLimits {
            max_control_payload_bytes: HARD_MAX_CONTROL_PAYLOAD_BYTES + 1,
            ..local
        },
    ];
    for oversized in oversized {
        assert_eq!(
            oversized.validate(),
            Err(NegotiationError::AboveHardMaximum)
        );
    }

    let native_narrowing = SessionLimits {
        max_region_bytes: u64::from(u32::MAX) + 1,
        ..local
    };
    assert_eq!(
        native_narrowing.validate_for_native_max(u64::from(u32::MAX)),
        Err(NegotiationError::NativeSizeNarrowing)
    );
}

#[test]
fn atomic_facts_and_absolute_deadline_fail_closed() {
    let atomics = AtomicCapabilities::from_verified_native(4096, 128, true, true)
        .unwrap()
        .require(true, true)
        .unwrap();
    assert!(atomics.atomic_u32_lock_free() && atomics.atomic_u64_lock_free());
    assert_eq!(atomics.page_alignment(), 4096);
    assert_eq!(atomics.cache_line_alignment(), 128);
    assert_eq!(
        AtomicCapabilities::from_verified_native(1, 64, true, true),
        Err(NegotiationError::AtomicUnsupported)
    );
    assert_eq!(
        AtomicCapabilities::from_verified_native(4096, 64, false, true)
            .unwrap()
            .require(true, false),
        Err(NegotiationError::AtomicUnsupported)
    );
    assert!(matches!(
        AbsoluteDeadline::after(Duration::ZERO),
        Err(NegotiationError::InvalidDeadline)
    ));
    let deadline = AbsoluteDeadline::after(Duration::from_secs(1)).unwrap();
    assert!(!deadline.is_expired());
    assert!(deadline.remaining() <= Duration::from_secs(1));

    let fixed = AbsoluteDeadline::after(Duration::from_millis(2)).unwrap();
    let mut previous = fixed.remaining();
    while !fixed.is_expired() {
        let remaining = fixed.remaining();
        assert!(remaining <= previous);
        previous = remaining;
        core::hint::spin_loop();
    }
    assert!(fixed.is_expired());
    assert_eq!(fixed.remaining(), Duration::ZERO);
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
#[test]
fn public_typestate_negotiates_controls_and_reports_exact_exit() {
    let executable = std::env::current_exe().unwrap();
    let command = SessionCommand::new(&executable)
        .arg0("native-ipc-public-helper")
        .arg("--exact")
        .arg("session::tests::public_receiver_helper")
        .arg("--ignored")
        .arg("--nocapture");
    let options = SessionOptions::new(
        AbsoluteDeadline::after(Duration::from_secs(120)).unwrap(),
        ExecutableIdentityPolicy::ExactOpenedFile,
    )
    .with_application_payload(b"public-coordinator".to_vec())
    .require_atomic_u32()
    .require_atomic_u64();
    let negotiating = CoordinatorSession::<Negotiating>::spawn(command, options).unwrap();
    assert_eq!(negotiating.peer_application_payload(), b"public-receiver");
    let mut ready = match negotiating.decide(NegotiationDecision::Accept).unwrap() {
        NegotiationOutcome::Accepted(ready) => ready,
        NegotiationOutcome::Rejected { .. } => panic!("valid public helper rejected"),
    };
    assert!(ready.atomic_capabilities().atomic_u32_lock_free());
    assert!(ready.atomic_capabilities().atomic_u64_lock_free());
    assert_eq!(ready.state(), SessionState::Ready);
    let oversized = vec![0; ready.negotiated_limits().max_control_payload_bytes as usize + 1];
    let failure = ready
        .send_control(
            0x8000_0040,
            &oversized,
            AbsoluteDeadline::after(Duration::from_secs(120)).unwrap(),
        )
        .unwrap_err();
    assert_eq!(
        failure.reason(),
        SessionError::Control(ControlError::PayloadTooLarge)
    );
    assert!(!failure.is_poisoned());
    assert_eq!(ready.state(), SessionState::Ready);
    let frame = ready
        .receive_control(AbsoluteDeadline::after(Duration::from_secs(120)).unwrap())
        .unwrap();
    assert_eq!(
        (frame.kind, frame.payload.as_slice()),
        (0x8000_0041, b"from-receiver".as_slice())
    );
    ready
        .send_control(
            0x8000_0042,
            b"from-coordinator",
            AbsoluteDeadline::after(Duration::from_secs(120)).unwrap(),
        )
        .unwrap();
    let cleanup = ready.wait_for_exit(AbsoluteDeadline::after(Duration::from_secs(120)).unwrap());
    assert_eq!(cleanup.direct_child(), Some(ChildExitStatus::Exited(0)));
    #[cfg(target_os = "macos")]
    assert_eq!(
        cleanup.descendants(),
        DescendantCleanupStatus::FreshGroupUnverified
    );
    #[cfg(target_os = "windows")]
    assert_eq!(
        cleanup.descendants(),
        DescendantCleanupStatus::ContainedProcessTreeComplete
    );
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
#[test]
#[ignore = "spawned alone by the public typestate integration test"]
fn public_receiver_helper() {
    let bootstrap = __take_receiver_bootstrap().unwrap();
    assert!(__take_receiver_bootstrap().is_err());
    let options = SessionOptions::new(
        AbsoluteDeadline::after(Duration::from_secs(120)).unwrap(),
        ExecutableIdentityPolicy::ExactOpenedFile,
    )
    .with_application_payload(b"public-receiver".to_vec())
    .require_atomic_u32()
    .require_atomic_u64();
    let negotiating = ReceiverSession::<Negotiating>::from_bootstrap(bootstrap, options).unwrap();
    // The one-shot bootstrap designation must not survive into this receiver's
    // descendants. The public marker and every target-specific bootstrap value
    // are scrubbed by the time construction completes.
    assert!(std::env::var_os("NATIVE_IPC_VNEXT_PUBLIC_BOOTSTRAP").is_none());
    #[cfg(target_os = "macos")]
    {
        assert!(std::env::var_os("NATIVE_IPC_MACH_NONCE").is_none());
        assert!(std::env::var_os("NATIVE_IPC_PARENT_PID").is_none());
    }
    assert_eq!(
        negotiating.peer_application_payload(),
        b"public-coordinator"
    );
    let mut ready = match negotiating
        .decide_after_coordinator(|_| NegotiationDecision::Accept)
        .unwrap()
    {
        NegotiationOutcome::Accepted(ready) => ready,
        NegotiationOutcome::Rejected { .. } => panic!("coordinator rejected valid helper"),
    };
    ready
        .send_control(
            0x8000_0041,
            b"from-receiver",
            AbsoluteDeadline::after(Duration::from_secs(120)).unwrap(),
        )
        .unwrap();
    let frame = ready
        .receive_control(AbsoluteDeadline::after(Duration::from_secs(120)).unwrap())
        .unwrap();
    assert_eq!(
        (frame.kind, frame.payload.as_slice()),
        (0x8000_0042, b"from-coordinator".as_slice())
    );
    assert!(matches!(ready.try_close(), ReceiverCloseOutcome::Closed));
}

#[cfg(target_os = "macos")]
#[test]
fn macos_public_unknown_rejection_preserves_cleanup_facts() {
    let executable = std::env::current_exe().unwrap();
    let command = SessionCommand::new(&executable)
        .arg0("native-ipc-macos-unknown-reject-helper")
        .arg("--exact")
        .arg("session::tests::macos_public_unknown_reject_helper")
        .arg("--ignored")
        .arg("--nocapture");
    let options = SessionOptions::new(
        AbsoluteDeadline::after(Duration::from_secs(120)).unwrap(),
        ExecutableIdentityPolicy::ExactOpenedFile,
    );
    let negotiating = CoordinatorSession::<Negotiating>::spawn(command, options).unwrap();
    let failure = negotiating
        .decide(NegotiationDecision::Accept)
        .err()
        .unwrap();
    assert_eq!(failure.reason(), SessionError::MalformedPeer);
    assert!(failure.is_poisoned());
    assert!(
        failure
            .cleanup()
            .is_some_and(ChildCleanupFacts::direct_child_complete)
    );
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "spawned alone by the unknown-rejection cleanup test"]
fn macos_public_unknown_reject_helper() {
    let negotiating =
        crate::backend::macos::vnext_session::MacReceiverNegotiatingSession::from_environment(
            SessionLimits::default(),
            Vec::new(),
            false,
            false,
            AbsoluteDeadline::after(Duration::from_secs(120)).unwrap(),
        )
        .unwrap();
    let outcome = negotiating
        .decide_after_coordinator(|_| Some(NonZeroU32::new(4).unwrap()))
        .unwrap();
    assert!(matches!(
        outcome,
        crate::backend::macos::vnext_session::MacNegotiationOutcome::Rejected { .. }
    ));
}

#[cfg(target_os = "macos")]
#[test]
fn macos_public_abort_uses_exact_audit_token_and_closes_inherited_fds() {
    use std::os::fd::AsRawFd;

    unsafe extern "C" {
        fn fcntl(fd: i32, command: i32, ...) -> i32;
    }
    const F_SETFD: i32 = 2;

    let inherited = std::fs::File::open(std::env::current_exe().unwrap()).unwrap();
    let inherited_fd = inherited.as_raw_fd();
    // SAFETY: the descriptor is owned and live; clearing CLOEXEC deliberately
    // creates a hostile inheritance candidate for POSIX_SPAWN_CLOEXEC_DEFAULT.
    assert_eq!(unsafe { fcntl(inherited_fd, F_SETFD, 0) }, 0);
    let executable = std::env::current_exe().unwrap();
    let command = SessionCommand::new(&executable)
        .arg0("native-ipc-macos-abort-helper")
        .arg("--exact")
        .arg("session::tests::macos_public_abort_helper")
        .arg("--ignored")
        .arg("--nocapture")
        .env("NATIVE_IPC_TEST_INHERITED_FD", inherited_fd.to_string());
    let options = SessionOptions::new(
        AbsoluteDeadline::after(Duration::from_secs(120)).unwrap(),
        ExecutableIdentityPolicy::ExactOpenedFile,
    );
    let negotiating = CoordinatorSession::<Negotiating>::spawn(command, options).unwrap();
    let ready = match negotiating.decide(NegotiationDecision::Accept).unwrap() {
        NegotiationOutcome::Accepted(ready) => ready,
        NegotiationOutcome::Rejected { .. } => panic!("abort helper rejected negotiation"),
    };
    let outcome = ready.abort(AbsoluteDeadline::after(Duration::from_secs(120)).unwrap());
    assert!(outcome.failure().is_none());
    assert!(matches!(
        outcome.cleanup().direct_child(),
        Some(ChildExitStatus::Signaled { .. })
    ));
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "spawned alone by the exact-audit-token abort test"]
fn macos_public_abort_helper() {
    unsafe extern "C" {
        fn fcntl(fd: i32, command: i32, ...) -> i32;
    }
    const F_GETFD: i32 = 1;

    let inherited_fd: i32 = std::env::var("NATIVE_IPC_TEST_INHERITED_FD")
        .unwrap()
        .parse()
        .unwrap();
    // SAFETY: probing an integer descriptor number is defined; -1 proves it
    // was not inherited into this exact child.
    assert_eq!(unsafe { fcntl(inherited_fd, F_GETFD) }, -1);
    let bootstrap = __take_receiver_bootstrap().unwrap();
    let options = SessionOptions::new(
        AbsoluteDeadline::after(Duration::from_secs(120)).unwrap(),
        ExecutableIdentityPolicy::ExactOpenedFile,
    );
    let negotiating = ReceiverSession::<Negotiating>::from_bootstrap(bootstrap, options).unwrap();
    let _ready = match negotiating
        .decide_after_coordinator(|_| NegotiationDecision::Accept)
        .unwrap()
    {
        NegotiationOutcome::Accepted(ready) => ready,
        NegotiationOutcome::Rejected { .. } => panic!("coordinator rejected abort helper"),
    };
    std::thread::sleep(Duration::from_secs(300));
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn public_native_batch(count: usize) -> (TransferBatch, ExpectedBatch) {
    use crate::batch::{ExpectedBatch, ExpectedRegion};
    use crate::region::{PrivateRegion, RegionId, RegionOptions, RegionSpec, WriterEndpoint};

    let mut batch = TransferBatch::new(16, 1 << 20, 16 << 20).unwrap();
    let mut expected = Vec::with_capacity(count);
    for index in (0..count).rev() {
        let id = RegionId::new((index + 1) as u128).unwrap();
        let writer = if index % 2 == 0 {
            WriterEndpoint::Coordinator
        } else {
            WriterEndpoint::Receiver
        };
        let logical_len = 31 + index;
        let mut region = PrivateRegion::allocate(RegionOptions::fixed(logical_len)).unwrap();
        region.initialize(|bytes| {
            bytes.fill(0);
            bytes[0] = (index + 1) as u8;
        });
        batch
            .add(region.prepare(RegionSpec { id, writer }).unwrap())
            .unwrap();
        expected.push(ExpectedRegion::new(id, writer, logical_len));
    }
    (batch, ExpectedBatch::try_from_regions(expected).unwrap())
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
#[test]
fn public_ready_activates_one_mixed_batch_atomically() {
    use crate::region::RegionId;

    let executable = std::env::current_exe().unwrap();
    let command = SessionCommand::new(&executable)
        .arg0("native-ipc-public-batch-helper")
        .arg("--exact")
        .arg("session::tests::public_batch_receiver_helper")
        .arg("--ignored")
        .arg("--nocapture");
    let options = SessionOptions::new(
        AbsoluteDeadline::after(Duration::from_secs(120)).unwrap(),
        ExecutableIdentityPolicy::ExactOpenedFile,
    );
    let negotiating = CoordinatorSession::<Negotiating>::spawn(command, options).unwrap();
    let mut ready = match negotiating.decide(NegotiationDecision::Accept).unwrap() {
        NegotiationOutcome::Accepted(ready) => ready,
        NegotiationOutcome::Rejected { .. } => panic!("valid batch helper rejected"),
    };
    let (batch, _) = public_native_batch(4);
    let mut active = ready
        .transfer_batch(
            batch,
            AbsoluteDeadline::after(Duration::from_secs(120)).unwrap(),
        )
        .unwrap();
    assert_eq!(active.len(), 4);
    for ordinal in (0..4).step_by(2) {
        active
            .take_writer(RegionId::new((ordinal + 1) as u128).unwrap())
            .unwrap()
            .write_from(1, &[0xa0 + ordinal as u8])
            .unwrap();
    }
    ready
        .send_control(
            0x8000_0051,
            b"inspect",
            AbsoluteDeadline::after(Duration::from_secs(120)).unwrap(),
        )
        .unwrap();
    let acknowledgement = ready
        .receive_control(AbsoluteDeadline::after(Duration::from_secs(120)).unwrap())
        .unwrap();
    assert_eq!(acknowledgement.kind, 0x8000_0052);
    for ordinal in (1..4).step_by(2) {
        let reader = active
            .take_reader(RegionId::new((ordinal + 1) as u128).unwrap())
            .unwrap();
        let mut byte = [0];
        reader.read_into(1, &mut byte).unwrap();
        assert_eq!(byte, [0xc0 + ordinal as u8]);
    }
    assert!(active.is_empty());
    assert!(ready.active_leases().is_empty());
    let cleanup = ready.wait_for_exit(AbsoluteDeadline::after(Duration::from_secs(120)).unwrap());
    assert_eq!(cleanup.direct_child(), Some(ChildExitStatus::Exited(0)));
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
#[test]
#[ignore = "spawned alone by the public mixed-batch integration test"]
fn public_batch_receiver_helper() {
    use crate::region::RegionId;

    let bootstrap = __take_receiver_bootstrap().unwrap();
    let options = SessionOptions::new(
        AbsoluteDeadline::after(Duration::from_secs(120)).unwrap(),
        ExecutableIdentityPolicy::ExactOpenedFile,
    );
    let negotiating = ReceiverSession::<Negotiating>::from_bootstrap(bootstrap, options).unwrap();
    let mut ready = match negotiating
        .decide_after_coordinator(|_| NegotiationDecision::Accept)
        .unwrap()
    {
        NegotiationOutcome::Accepted(ready) => ready,
        NegotiationOutcome::Rejected { .. } => panic!("coordinator rejected batch helper"),
    };
    let (_, expected) = public_native_batch(4);
    let mut active = ready
        .receive_batch(
            expected,
            AbsoluteDeadline::after(Duration::from_secs(120)).unwrap(),
        )
        .unwrap();
    assert_eq!(active.len(), 4);
    let notification = ready
        .receive_control(AbsoluteDeadline::after(Duration::from_secs(120)).unwrap())
        .unwrap();
    assert_eq!(notification.kind, 0x8000_0051);
    for ordinal in 0..4 {
        let id = RegionId::new((ordinal + 1) as u128).unwrap();
        if ordinal % 2 == 0 {
            let reader = active.take_reader(id).unwrap();
            let mut bytes = [0; 2];
            reader.read_into(0, &mut bytes).unwrap();
            assert_eq!(bytes, [(ordinal + 1) as u8, 0xa0 + ordinal as u8]);
        } else {
            active
                .take_writer(id)
                .unwrap()
                .write_from(1, &[0xc0 + ordinal as u8])
                .unwrap();
        }
    }
    assert!(active.is_empty());
    assert!(ready.active_leases().is_empty());
    ready
        .send_control(
            0x8000_0052,
            b"done",
            AbsoluteDeadline::after(Duration::from_secs(120)).unwrap(),
        )
        .unwrap();
    assert!(matches!(ready.try_close(), ReceiverCloseOutcome::Closed));
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
fn one_active_region_options() -> SessionOptions {
    SessionOptions::new(
        AbsoluteDeadline::after(Duration::from_secs(120)).unwrap(),
        ExecutableIdentityPolicy::ExactOpenedFile,
    )
    .with_limits(SessionLimits {
        max_active_regions: 1,
        max_active_bytes: 1 << 20,
        ..SessionLimits::default()
    })
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
#[test]
fn public_capacity_rejection_keeps_both_sessions_synchronized() {
    let executable = std::env::current_exe().unwrap();
    let command = SessionCommand::new(&executable)
        .arg0("native-ipc-capacity-helper")
        .arg("--exact")
        .arg("session::tests::public_capacity_receiver_helper")
        .arg("--ignored")
        .arg("--nocapture");
    let negotiating =
        CoordinatorSession::<Negotiating>::spawn(command, one_active_region_options()).unwrap();
    let mut ready = match negotiating.decide(NegotiationDecision::Accept).unwrap() {
        NegotiationOutcome::Accepted(ready) => ready,
        NegotiationOutcome::Rejected { .. } => panic!("valid capacity helper rejected"),
    };
    let (first, _) = public_native_batch(1);
    let active = ready
        .transfer_batch(
            first,
            AbsoluteDeadline::after(Duration::from_secs(120)).unwrap(),
        )
        .unwrap();
    drop(active);
    ready
        .send_control(
            0x8000_0061,
            b"second",
            AbsoluteDeadline::after(Duration::from_secs(120)).unwrap(),
        )
        .unwrap();
    let (second, _) = public_native_batch(1);
    let failure = match ready.transfer_batch(
        second,
        AbsoluteDeadline::after(Duration::from_secs(120)).unwrap(),
    ) {
        Ok(_) => panic!("receiver capacity rejection unexpectedly activated"),
        Err(failure) => failure,
    };
    assert_eq!(failure.reason(), SessionError::ActiveLimit);
    assert!(!failure.is_poisoned());
    assert_eq!(ready.state(), SessionState::Ready);
    ready
        .send_control(
            0x8000_0062,
            b"still-synchronized",
            AbsoluteDeadline::after(Duration::from_secs(120)).unwrap(),
        )
        .unwrap();
    let acknowledgement = ready
        .receive_control(AbsoluteDeadline::after(Duration::from_secs(120)).unwrap())
        .unwrap();
    assert_eq!(acknowledgement.kind, 0x8000_0063);
    let cleanup = ready.wait_for_exit(AbsoluteDeadline::after(Duration::from_secs(120)).unwrap());
    assert_eq!(cleanup.direct_child(), Some(ChildExitStatus::Exited(0)));
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
#[test]
#[ignore = "spawned alone by the public capacity-preflight test"]
fn public_capacity_receiver_helper() {
    let bootstrap = __take_receiver_bootstrap().unwrap();
    let negotiating =
        ReceiverSession::<Negotiating>::from_bootstrap(bootstrap, one_active_region_options())
            .unwrap();
    let mut ready = match negotiating
        .decide_after_coordinator(|_| NegotiationDecision::Accept)
        .unwrap()
    {
        NegotiationOutcome::Accepted(ready) => ready,
        NegotiationOutcome::Rejected { .. } => panic!("coordinator rejected capacity helper"),
    };
    let (_, first) = public_native_batch(1);
    let active = ready
        .receive_batch(
            first,
            AbsoluteDeadline::after(Duration::from_secs(120)).unwrap(),
        )
        .unwrap();
    let notification = ready
        .receive_control(AbsoluteDeadline::after(Duration::from_secs(120)).unwrap())
        .unwrap();
    assert_eq!(notification.kind, 0x8000_0061);
    let (_, second) = public_native_batch(1);
    let failure = match ready.receive_batch(
        second,
        AbsoluteDeadline::after(Duration::from_secs(120)).unwrap(),
    ) {
        Ok(_) => panic!("over-limit receiver unexpectedly activated"),
        Err(failure) => failure,
    };
    assert_eq!(failure.reason(), SessionError::ActiveLimit);
    assert!(!failure.is_poisoned());
    assert_eq!(ready.state(), SessionState::Ready);
    drop(active);
    let synchronized = ready
        .receive_control(AbsoluteDeadline::after(Duration::from_secs(120)).unwrap())
        .unwrap();
    assert_eq!(synchronized.kind, 0x8000_0062);
    ready
        .send_control(
            0x8000_0063,
            b"confirmed",
            AbsoluteDeadline::after(Duration::from_secs(120)).unwrap(),
        )
        .unwrap();
    assert!(matches!(ready.try_close(), ReceiverCloseOutcome::Closed));
}
