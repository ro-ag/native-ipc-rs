use super::*;
use static_assertions::assert_not_impl_any;

assert_not_impl_any!(HelloFrame: Clone);
assert_not_impl_any!(HelloPair: Clone);
assert_not_impl_any!(NegotiatedTranscript: Clone);

const NONCE: [u8; 32] = [0x5a; 32];

fn atomics() -> AtomicOffer {
    AtomicOffer::from_local(
        AtomicCapabilities::from_verified_native(4096, 128, true, true).unwrap(),
    )
    .unwrap()
}

fn hello(payload: &[u8]) -> NegotiationFrame {
    NegotiationFrame::Hello(HelloFrame {
        role: SenderRole::Coordinator,
        nonce: NONCE,
        supported_features: FeatureBits([0x11, 0x22]),
        required_features: FeatureBits([0x01, 0x02]),
        limits: SessionLimits::default(),
        atomics: atomics(),
        target: TargetFacts::current(),
        application_payload: payload.to_vec(),
    })
}

fn duplicate_hello(frame: &HelloFrame) -> HelloFrame {
    HelloFrame {
        role: frame.role,
        nonce: frame.nonce,
        supported_features: frame.supported_features,
        required_features: frame.required_features,
        limits: frame.limits,
        atomics: frame.atomics,
        target: frame.target,
        application_payload: frame.application_payload.clone(),
    }
}

fn negotiate(
    coordinator: &HelloFrame,
    receiver: &HelloFrame,
    verified: AtomicCapabilities,
) -> Result<NegotiatedTranscript, NegotiationWireError> {
    NegotiatedTranscript::from_hellos(
        HelloPair::new(duplicate_hello(coordinator), duplicate_hello(receiver)),
        verified,
    )
}

fn encoded(frame: &NegotiationFrame) -> Vec<u8> {
    let mut bytes = vec![0; frame.encoded_len().unwrap()];
    let len = frame.encode_into(&mut bytes).unwrap();
    assert_eq!(len, bytes.len());
    bytes
}

#[test]
fn hello_is_fixed_little_endian_bounded_and_round_trips_opaque_payload() {
    let bytes = encoded(&hello(b"opaque"));
    assert_eq!(&bytes[..8], &MAGIC);
    assert_eq!(get_u16(&bytes, 8), WIRE_MAJOR);
    assert_eq!(get_u16(&bytes, 10), WIRE_MINOR);
    assert_eq!(get_u16(&bytes, 12), KIND_HELLO);
    assert_eq!(bytes[14], SenderRole::Coordinator as u8);
    assert_eq!(get_u32(&bytes, 16), HEADER_LEN as u32);
    assert_eq!(get_u32(&bytes, 20) as usize, HEADER_LEN + 6);
    assert_eq!(get_u32(&bytes, 24), 6);
    assert_eq!(&bytes[32..64], &NONCE);
    assert_eq!(get_u64(&bytes, 64), 0x11);
    assert_eq!(get_u64(&bytes, 72), 0x22);
    assert_eq!(&bytes[HEADER_LEN..], b"opaque");
    assert_eq!(
        decode_frame(
            &bytes,
            SenderRole::Coordinator,
            NONCE,
            HARD_MAX_BOOTSTRAP_PAYLOAD_BYTES,
        )
        .unwrap(),
        hello(b"opaque")
    );

    assert!(matches!(
        hello(&[0; 2]).encode_into(&mut [0; HEADER_LEN + 1]),
        Err(NegotiationWireError::DestinationTooSmall)
    ));
    assert!(matches!(
        decode_frame(&bytes, SenderRole::Coordinator, NONCE, 5),
        Err(NegotiationWireError::PayloadTooLarge)
    ));
    assert_eq!(
        validate_payload_len(
            HARD_MAX_BOOTSTRAP_PAYLOAD_BYTES,
            HARD_MAX_BOOTSTRAP_PAYLOAD_BYTES,
        ),
        Ok(())
    );
    assert_eq!(
        validate_payload_len(
            HARD_MAX_BOOTSTRAP_PAYLOAD_BYTES + 1,
            HARD_MAX_BOOTSTRAP_PAYLOAD_BYTES + 1,
        ),
        Err(NegotiationWireError::PayloadTooLarge)
    );

    let empty = encoded(&hello(b""));
    assert!(matches!(
        decode_frame(&empty, SenderRole::Coordinator, NONCE, 0),
        Ok(NegotiationFrame::Hello(HelloFrame {
            application_payload,
            ..
        })) if application_payload.is_empty()
    ));
}

#[test]
fn accept_and_reject_are_payload_free_exact_decisions() {
    let accept = NegotiationFrame::Accept(AcceptFrame {
        role: SenderRole::Receiver,
        nonce: NONCE,
        selected_features: FeatureBits([1, 2]),
        effective_limits: SessionLimits::default(),
        atomics: atomics(),
        target: TargetFacts::current(),
        hello_digest: [7; 32],
    });
    let accept_bytes = encoded(&accept);
    assert_eq!(accept_bytes.len(), HEADER_LEN);
    assert_eq!(
        decode_frame(
            &accept_bytes,
            SenderRole::Receiver,
            NONCE,
            HARD_MAX_BOOTSTRAP_PAYLOAD_BYTES,
        )
        .unwrap(),
        accept
    );

    let reject = NegotiationFrame::Reject(RejectFrame {
        role: SenderRole::Receiver,
        nonce: NONCE,
        reason: 7,
    });
    let reject_bytes = encoded(&reject);
    assert_eq!(get_u32(&reject_bytes, 28), 7);
    assert_eq!(
        decode_frame(
            &reject_bytes,
            SenderRole::Receiver,
            NONCE,
            HARD_MAX_BOOTSTRAP_PAYLOAD_BYTES,
        )
        .unwrap(),
        reject
    );

    let zero_reason = NegotiationFrame::Reject(RejectFrame {
        role: SenderRole::Receiver,
        nonce: NONCE,
        reason: 0,
    });
    assert_eq!(
        zero_reason.encode_into(&mut [0; HEADER_LEN]),
        Err(NegotiationWireError::BadRejectReason)
    );
}

#[test]
fn hostile_header_and_every_truncation_fail_before_payload_copy() {
    let bytes = encoded(&hello(b"payload"));
    for len in 0..bytes.len() {
        let error = decode_frame(
            &bytes[..len],
            SenderRole::Coordinator,
            NONCE,
            HARD_MAX_BOOTSTRAP_PAYLOAD_BYTES,
        )
        .unwrap_err();
        if len < HEADER_LEN {
            assert_eq!(error, NegotiationWireError::Truncated, "length {len}");
        } else {
            assert_eq!(error, NegotiationWireError::NonCanonical, "length {len}");
        }
    }

    let mutations: &[(usize, NegotiationWireError)] = &[
        (0, NegotiationWireError::BadMagic),
        (8, NegotiationWireError::BadVersion),
        (12, NegotiationWireError::BadKind),
        (14, NegotiationWireError::BadRole),
        (15, NegotiationWireError::NonCanonical),
        (16, NegotiationWireError::NonCanonical),
        (20, NegotiationWireError::NonCanonical),
        (24, NegotiationWireError::NonCanonical),
        (28, NegotiationWireError::NonCanonical),
        (32, NegotiationWireError::NonceMismatch),
        (98, NegotiationWireError::NonCanonical),
        (144, NegotiationWireError::BadAtomicFacts),
        (164, NegotiationWireError::BadTarget),
        (166, NegotiationWireError::NonCanonical),
        (191, NegotiationWireError::NonCanonical),
    ];
    for &(offset, error) in mutations {
        let mut bad = bytes.clone();
        bad[offset] ^= 0x80;
        assert_eq!(
            decode_frame(
                &bad,
                SenderRole::Coordinator,
                NONCE,
                HARD_MAX_BOOTSTRAP_PAYLOAD_BYTES,
            ),
            Err(error),
            "offset {offset}"
        );
    }
    for offset in 166..HEADER_LEN {
        let mut bad = bytes.clone();
        bad[offset] = 1;
        assert_eq!(
            decode_frame(
                &bad,
                SenderRole::Coordinator,
                NONCE,
                HARD_MAX_BOOTSTRAP_PAYLOAD_BYTES,
            ),
            Err(NegotiationWireError::NonCanonical),
            "reserved offset {offset}"
        );
    }
    assert_eq!(
        decode_frame(
            &bytes,
            SenderRole::Receiver,
            NONCE,
            HARD_MAX_BOOTSTRAP_PAYLOAD_BYTES,
        ),
        Err(NegotiationWireError::BadRole)
    );
    assert_eq!(
        decode_frame(
            &bytes,
            SenderRole::Coordinator,
            [1; 32],
            HARD_MAX_BOOTSTRAP_PAYLOAD_BYTES,
        ),
        Err(NegotiationWireError::NonceMismatch)
    );
}

#[test]
fn feature_atomic_limit_and_payload_invariants_fail_closed() {
    let mut invalid_feature = match hello(b"") {
        NegotiationFrame::Hello(frame) => frame,
        _ => unreachable!(),
    };
    invalid_feature.required_features = FeatureBits([1 << 63, 0]);
    assert_eq!(
        NegotiationFrame::Hello(invalid_feature).encode_into(&mut [0; HEADER_LEN]),
        Err(NegotiationWireError::RequiredFeatureNotSupported)
    );

    let mut invalid_limit = match hello(b"") {
        NegotiationFrame::Hello(frame) => frame,
        _ => unreachable!(),
    };
    invalid_limit.limits.max_transactions = 0;
    assert_eq!(
        NegotiationFrame::Hello(invalid_limit).encode_into(&mut [0; HEADER_LEN]),
        Err(NegotiationWireError::BadLimits)
    );

    let mut payload_over_offer = match hello(b"xx") {
        NegotiationFrame::Hello(frame) => frame,
        _ => unreachable!(),
    };
    payload_over_offer.limits.max_bootstrap_payload_bytes = 1;
    assert_eq!(
        NegotiationFrame::Hello(duplicate_hello(&payload_over_offer)).encoded_len(),
        Err(NegotiationWireError::PayloadTooLarge)
    );
    assert_eq!(
        NegotiationFrame::Hello(payload_over_offer).encode_into(&mut [0; HEADER_LEN + 2]),
        Err(NegotiationWireError::PayloadTooLarge)
    );

    let mut bad_atomic = encoded(&hello(b""));
    put_u16(&mut bad_atomic, 148, 3);
    assert_eq!(
        decode_frame(
            &bad_atomic,
            SenderRole::Coordinator,
            NONCE,
            HARD_MAX_BOOTSTRAP_PAYLOAD_BYTES,
        ),
        Err(NegotiationWireError::BadAtomicFacts)
    );
}

#[test]
fn exact_two_hello_transcript_binds_both_accept_decisions() {
    let verified = AtomicCapabilities::from_verified_native(4096, 128, true, true).unwrap();
    let mut coordinator = match hello(b"coordinator") {
        NegotiationFrame::Hello(frame) => frame,
        _ => unreachable!(),
    };
    coordinator.supported_features = FeatureBits([3, 1 << 40]);
    coordinator.required_features = FeatureBits([1, 0]);
    let mut receiver = duplicate_hello(&coordinator);
    receiver.role = SenderRole::Receiver;
    receiver.application_payload = b"receiver".to_vec();
    receiver.supported_features = FeatureBits([3, 0]);
    receiver.required_features = FeatureBits([2, 0]);
    receiver.limits.max_regions_per_batch = 4;

    let mut transcript = negotiate(&coordinator, &receiver, verified).unwrap();
    let coordinator_accept = transcript.expected_accept(SenderRole::Coordinator);
    let receiver_accept = transcript.expected_accept(SenderRole::Receiver);
    assert_ne!(receiver_accept.hello_digest, [0; 32]);
    assert_eq!(coordinator_accept.selected_features, FeatureBits([3, 0]));
    assert_eq!(coordinator_accept.effective_limits.max_regions_per_batch, 4);
    let mut out_of_order = negotiate(&coordinator, &receiver, verified).unwrap();
    assert_eq!(
        out_of_order.validate_accept(receiver_accept, SenderRole::Receiver),
        Err(NegotiationWireError::DecisionReplayOrOrder)
    );

    let mut substitutions = Vec::new();
    let mut wrong = receiver_accept;
    wrong.selected_features.0[0] ^= 1;
    substitutions.push(wrong);
    let mut wrong = receiver_accept;
    wrong.effective_limits.max_transactions -= 1;
    substitutions.push(wrong);
    let mut wrong = receiver_accept;
    wrong.atomics.u64_lock_free = false;
    substitutions.push(wrong);
    let mut wrong = receiver_accept;
    wrong.target.architecture = if wrong.target.architecture == 1 { 2 } else { 1 };
    substitutions.push(wrong);
    let mut wrong = receiver_accept;
    wrong.nonce[0] ^= 1;
    substitutions.push(wrong);
    let mut wrong = receiver_accept;
    wrong.hello_digest[0] ^= 1;
    substitutions.push(wrong);
    for wrong in substitutions {
        let mut substitution_transcript = negotiate(&coordinator, &receiver, verified).unwrap();
        substitution_transcript
            .validate_accept(coordinator_accept, SenderRole::Coordinator)
            .unwrap();
        assert_eq!(
            substitution_transcript.validate_accept(wrong, SenderRole::Receiver),
            Err(NegotiationWireError::EffectiveMismatch)
        );
    }
    let mut wrong_role = negotiate(&coordinator, &receiver, verified).unwrap();
    assert_eq!(
        wrong_role.validate_accept(receiver_accept, SenderRole::Coordinator),
        Err(NegotiationWireError::EffectiveMismatch)
    );

    transcript
        .validate_accept(coordinator_accept, SenderRole::Coordinator)
        .unwrap();
    transcript
        .validate_accept(receiver_accept, SenderRole::Receiver)
        .unwrap();

    let mut replay = negotiate(&coordinator, &receiver, verified).unwrap();
    replay
        .validate_accept(coordinator_accept, SenderRole::Coordinator)
        .unwrap();
    assert_eq!(
        replay.validate_accept(coordinator_accept, SenderRole::Coordinator),
        Err(NegotiationWireError::DecisionReplayOrOrder)
    );
    let mut changed_payload = duplicate_hello(&receiver);
    changed_payload.application_payload.push(b'!');
    let changed = negotiate(&coordinator, &changed_payload, verified).unwrap();
    assert_ne!(
        changed.expected_accept(SenderRole::Receiver).hello_digest,
        receiver_accept.hello_digest
    );

    let mut unknown_required = duplicate_hello(&receiver);
    unknown_required.supported_features.0[1] = 1;
    unknown_required.required_features.0[1] = 1;
    assert_eq!(
        negotiate(&coordinator, &unknown_required, verified),
        Err(NegotiationWireError::RequiredFeatureNotSupported)
    );

    let mut false_required_atomic = duplicate_hello(&receiver);
    false_required_atomic.atomics.u64_lock_free = false;
    assert_eq!(
        negotiate(&coordinator, &false_required_atomic, verified),
        Err(NegotiationWireError::RequiredFeatureNotSupported)
    );

    let mut optional_coordinator = duplicate_hello(&coordinator);
    optional_coordinator.required_features = FeatureBits::default();
    let mut optional_receiver = duplicate_hello(&receiver);
    optional_receiver.required_features = FeatureBits::default();
    optional_receiver.atomics.u64_lock_free = false;
    let optional = negotiate(&optional_coordinator, &optional_receiver, verified).unwrap();
    assert_eq!(
        optional
            .expected_accept(SenderRole::Coordinator)
            .selected_features,
        FeatureBits([1, 0])
    );

    let mut wrong_target = receiver;
    wrong_target.target.os = if wrong_target.target.os == 1 { 2 } else { 1 };
    assert_eq!(
        negotiate(&coordinator, &wrong_target, verified),
        Err(NegotiationWireError::TargetMismatch)
    );
}

#[test]
fn hello_digest_has_a_platform_independent_golden_vector() {
    let fixed_target = TargetFacts {
        os: 1,
        architecture: 1,
        pointer_width: 64,
        endian: 1,
    };
    let fixed_atomics = AtomicOffer {
        u32_lock_free: true,
        u64_lock_free: true,
        u32_alignment: 4,
        u64_alignment: 8,
        page_alignment: 4096,
        cache_line_alignment: 128,
    };
    let mut coordinator = match hello(b"coordinator") {
        NegotiationFrame::Hello(frame) => frame,
        _ => unreachable!(),
    };
    coordinator.supported_features = FeatureBits([3, 1 << 40]);
    coordinator.required_features = FeatureBits([1, 0]);
    coordinator.target = fixed_target;
    coordinator.atomics = fixed_atomics;
    let mut receiver = duplicate_hello(&coordinator);
    receiver.role = SenderRole::Receiver;
    receiver.application_payload = b"receiver".to_vec();
    receiver.supported_features = FeatureBits([3, 0]);
    receiver.required_features = FeatureBits([2, 0]);
    receiver.limits.max_regions_per_batch = 4;
    let hello_digest = canonical_hello_digest(&coordinator, &receiver);

    assert_eq!(
        hello_digest,
        [
            165, 94, 237, 164, 126, 159, 1, 36, 189, 159, 155, 103, 94, 123, 53, 111, 220, 114,
            205, 225, 115, 255, 125, 98, 172, 215, 161, 88, 25, 185, 49, 42,
        ]
    );
}
