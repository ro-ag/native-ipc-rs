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
