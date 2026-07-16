use std::time::{Duration, Instant};

use super::*;

fn plan() -> BrokerLaunchPlan {
    BrokerLaunchPlan {
        deadline: SupervisorDeadline::from_instant(Instant::now() + Duration::from_secs(5))
            .unwrap(),
        connection_generation: 7,
        sequence: 1,
        effective_uid: 501,
        effective_gid: 20,
        session: [1; 32],
        audit_identity: [2; 32],
        code_identity: [3; 32],
        target_identity: [4; 32],
        client_nonce: [5; 32],
        service_nonce: [6; 32],
        policy_id: b"org.example.private-policy".to_vec(),
        installed_executable: b"/example/NativeIPC.app/Contents/Helpers/receiver".to_vec(),
        arguments: vec![b"receiver".to_vec(), b"--mode=test".to_vec()],
        environment: vec![TargetEnvironmentEntry::new(b"LANG".to_vec(), b"C".to_vec()).unwrap()],
    }
}

#[test]
fn exact_plan_round_trips_canonically() {
    let plan = plan();
    let encoded = plan.encode().unwrap();
    let received = ReceivedBrokerLaunchPlan::decode(&encoded).unwrap();
    assert_eq!(received.deadline.wire(), plan.deadline);
    // SAFETY: this codec-only test models exact-parent provenance for the
    // identical complete frame it just encoded locally.
    let acknowledged = unsafe { received.acknowledge_exact_parent() };
    // SAFETY: this test models the sole exact gate START after the ACK above.
    let bound = unsafe { acknowledged.activate() };
    assert_eq!(bound.deadline().wire(), plan.deadline);
    assert_eq!(bound.into_plan(), plan);
}

#[test]
fn exact_parent_alone_mints_canonical_authority_free_launcher_data() {
    let original = plan();
    let encoded = original.encode().unwrap();
    let received = ReceivedBrokerLaunchPlan::decode(&encoded).unwrap();
    // SAFETY: this codec-only test models exact FD4 ACK and FD3 START.
    let exact = unsafe { received.acknowledge_exact_parent().activate() };
    let deadline = exact.deadline();
    let launcher_frame = exact.launcher_frame().unwrap();
    assert_ne!(launcher_frame, encoded);
    for secret in [
        &[1; 32][..],
        &[2; 32][..],
        &[3; 32][..],
        &[4; 32][..],
        &[5; 32][..],
        &[6; 32][..],
        b"org.example.private-policy",
    ] {
        assert!(
            !launcher_frame
                .windows(secret.len())
                .any(|value| value == secret)
        );
    }
    let prefix: &[u8; LAUNCHER_PLAN_PREFIX_BYTES] = launcher_frame[..LAUNCHER_PLAN_PREFIX_BYTES]
        .try_into()
        .unwrap();
    let parsed = parse_launcher_plan_prefix(prefix, launcher_frame.len()).unwrap();
    assert_eq!(parsed.deadline.wire(), deadline.wire());
    let parts = ReceivedLauncherExecPlan::decode_with_deadline(&launcher_frame, parsed.deadline)
        .unwrap()
        .into_parts();
    assert_eq!(parts.deadline.wire(), original.deadline);
    assert_eq!(parts.effective_uid, original.effective_uid);
    assert_eq!(parts.effective_gid, original.effective_gid);
    assert_eq!(parts.installed_executable, original.installed_executable);
    assert_eq!(parts.arguments, original.arguments);
    assert_eq!(parts.environment, original.environment);
}

#[test]
fn launcher_data_rejects_every_truncation_extension_and_deadline_substitution() {
    let broker = plan();
    let encoded = LauncherExecPlan::from_broker(&broker).encode().unwrap();
    let prefix: &[u8; LAUNCHER_PLAN_PREFIX_BYTES] =
        encoded[..LAUNCHER_PLAN_PREFIX_BYTES].try_into().unwrap();
    let parsed = parse_launcher_plan_prefix(prefix, encoded.len()).unwrap();
    for length in 0..encoded.len() {
        assert!(
            ReceivedLauncherExecPlan::decode_with_deadline(&encoded[..length], parsed.deadline)
                .is_err()
        );
    }
    let mut extended = encoded.clone();
    extended.push(0);
    assert!(ReceivedLauncherExecPlan::decode_with_deadline(&extended, parsed.deadline).is_err());

    let mut substituted = encoded;
    put_u64(
        &mut substituted,
        16,
        broker.deadline.wire_value().checked_add(1).unwrap(),
    );
    assert_eq!(
        ReceivedLauncherExecPlan::decode_with_deadline(&substituted, parsed.deadline).err(),
        Some(SupervisorWireError::ReplayOrSubstitution)
    );
}

#[test]
fn every_truncation_and_extension_is_rejected() {
    let encoded = plan().encode().unwrap();
    for length in 0..encoded.len() {
        assert!(ReceivedBrokerLaunchPlan::decode(&encoded[..length]).is_err());
    }
    let mut extended = encoded;
    extended.push(0);
    assert!(ReceivedBrokerLaunchPlan::decode(&extended).is_err());
}

#[test]
fn header_identity_and_reserved_mutations_fail_closed() {
    let encoded = plan().encode().unwrap();
    for offset in [0, 8, 10, 12, 32, 252] {
        let mut mutated = encoded.clone();
        mutated[offset] ^= 0xff;
        assert!(
            ReceivedBrokerLaunchPlan::decode(&mutated).is_err(),
            "offset {offset}"
        );
    }
    let exact = ReceivedBrokerLaunchPlan::decode(&encoded).unwrap().plan;
    for offset in [24, 40, 44, 48, 80, 112, 144, 176, 208] {
        let mut mutated = encoded.clone();
        mutated[offset] ^= 0xff;
        assert_ne!(
            ReceivedBrokerLaunchPlan::decode(&mutated).unwrap().plan,
            exact
        );
    }
    for range in [48..80, 80..112, 112..144, 144..176, 176..208, 208..240] {
        let mut zeroed = encoded.clone();
        zeroed[range].fill(0);
        assert!(ReceivedBrokerLaunchPlan::decode(&zeroed).is_err());
    }
}

#[test]
fn duplicate_environment_and_oversized_plan_reject() {
    let mut duplicate = plan();
    duplicate
        .environment
        .push(TargetEnvironmentEntry::new(b"LANG".to_vec(), b"C".to_vec()).unwrap());
    assert_eq!(
        duplicate.encode(),
        Err(SupervisorWireError::InvalidTargetInput)
    );

    let mut oversized = plan();
    oversized.arguments = (0..(MAX_ARGUMENTS - 1)).map(|_| vec![b'x'; 4096]).collect();
    assert_eq!(oversized.encode(), Err(SupervisorWireError::LimitExceeded));
}

#[test]
fn exact_policy_expanded_limits_round_trip_and_hostile_counts_reject_before_allocation() {
    let mut exact_arguments = plan();
    exact_arguments.arguments = (0..MAX_ARGUMENTS).map(|_| vec![b'x']).collect();
    let encoded = exact_arguments.encode().unwrap();
    assert_eq!(
        ReceivedBrokerLaunchPlan::decode(&encoded).unwrap().plan,
        exact_arguments
    );

    for (offset, value) in [
        (240, u32::try_from(MAX_POLICY_ID_BYTES + 1).unwrap()),
        (244, u32::try_from(MAX_COMPONENT_BYTES + 1).unwrap()),
    ] {
        let mut hostile = plan().encode().unwrap();
        put_u32(&mut hostile, offset, value);
        assert_eq!(
            ReceivedBrokerLaunchPlan::decode(&hostile).err(),
            Some(SupervisorWireError::LimitExceeded)
        );
    }
    for (offset, value) in [
        (248, u16::try_from(MAX_ARGUMENTS + 1).unwrap()),
        (250, u16::try_from(MAX_ENVIRONMENT + 1).unwrap()),
    ] {
        let mut hostile = plan().encode().unwrap();
        put_u16(&mut hostile, offset, value);
        assert_eq!(
            ReceivedBrokerLaunchPlan::decode(&hostile).err(),
            Some(SupervisorWireError::LimitExceeded)
        );
    }
    let mut zero_arguments = plan().encode().unwrap();
    put_u16(&mut zero_arguments, 248, 0);
    assert_eq!(
        ReceivedBrokerLaunchPlan::decode(&zero_arguments).err(),
        Some(SupervisorWireError::LimitExceeded)
    );
}

#[test]
fn receive_rejects_expired_and_extended_deadline_authority() {
    let mut expired = plan();
    expired.deadline = SupervisorDeadline::from_wire(1);
    assert_eq!(
        ReceivedBrokerLaunchPlan::decode(&expired.encode().unwrap()).err(),
        Some(SupervisorWireError::LimitExceeded)
    );

    let mut extended = plan();
    extended.deadline = SupervisorDeadline::from_wire(u64::MAX);
    assert_eq!(
        ReceivedBrokerLaunchPlan::decode(&extended.encode().unwrap()).err(),
        Some(SupervisorWireError::LimitExceeded)
    );
}

#[test]
fn fixed_prefix_binds_outer_length_and_deadline_before_payload_read() {
    let exact = plan();
    let encoded = exact.encode().unwrap();
    let prefix: &[u8; BROKER_PLAN_PREFIX_BYTES] =
        encoded[..BROKER_PLAN_PREFIX_BYTES].try_into().unwrap();
    let parsed = parse_broker_plan_prefix(prefix, encoded.len()).unwrap();
    assert_eq!(parsed.frame_len, encoded.len());
    assert_eq!(
        parsed.deadline.wire().wire_value(),
        exact.deadline.wire_value()
    );
    assert!(parse_broker_plan_prefix(prefix, encoded.len() + 1).is_err());

    let mut expired = *prefix;
    put_u64(&mut expired, 16, 1);
    assert_eq!(
        parse_broker_plan_prefix(&expired, encoded.len()).err(),
        Some(SupervisorWireError::LimitExceeded)
    );
}
