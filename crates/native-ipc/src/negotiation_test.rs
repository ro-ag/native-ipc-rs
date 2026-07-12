use super::*;
use static_assertions::assert_not_impl_any;

assert_not_impl_any!(HelloFrame: Clone);
assert_not_impl_any!(HelloPair: Clone);
assert_not_impl_any!(NegotiatedTranscript: Clone);

const NONCE: [u8; 32] = [0x5a; 32];
const CHALLENGE_BYTES: [u8; 16] = [0xa5; 16];

fn challenge() -> DecisionChallenge {
    DecisionChallenge::from_os_csprng(CHALLENGE_BYTES).unwrap()
}

fn reason(value: u32) -> NonZeroU32 {
    NonZeroU32::new(value).unwrap()
}

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
        decision_challenge: challenge(),
    });
    let accept_bytes = encoded(&accept);
    assert_eq!(accept_bytes.len(), HEADER_LEN);
    assert_eq!(&accept_bytes[80..96], &CHALLENGE_BYTES);
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
        reason: reason(7),
        decision_challenge: challenge(),
    });
    let reject_bytes = encoded(&reject);
    assert_eq!(get_u32(&reject_bytes, 28), 7);
    assert_eq!(&reject_bytes[80..96], &CHALLENGE_BYTES);
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

    let mut zero_reason = reject_bytes.clone();
    zero_reason[28..32].fill(0);
    assert_eq!(
        decode_frame(
            &zero_reason,
            SenderRole::Receiver,
            NONCE,
            HARD_MAX_BOOTSTRAP_PAYLOAD_BYTES,
        ),
        Err(NegotiationWireError::BadRejectReason)
    );

    assert_eq!(
        DecisionChallenge::from_os_csprng([0; 16]),
        Err(NegotiationWireError::BadDecisionChallenge)
    );
    for mut zero_challenge in [accept_bytes, reject_bytes] {
        zero_challenge[80..96].fill(0);
        assert_eq!(
            decode_frame(
                &zero_challenge,
                SenderRole::decode(zero_challenge[14]).unwrap(),
                NONCE,
                HARD_MAX_BOOTSTRAP_PAYLOAD_BYTES,
            ),
            Err(NegotiationWireError::BadDecisionChallenge)
        );
    }
}

#[test]
fn accept_and_reject_have_exact_platform_independent_wire_goldens() {
    let fixed_atomics = AtomicOffer {
        u32_lock_free: true,
        u64_lock_free: true,
        u32_alignment: 4,
        u64_alignment: 8,
        page_alignment: 4096,
        cache_line_alignment: 128,
    };
    let fixed_target = TargetFacts {
        os: 1,
        architecture: 1,
        pointer_width: 64,
        endian: 1,
    };
    let accept = encoded(&NegotiationFrame::Accept(AcceptFrame {
        role: SenderRole::Coordinator,
        nonce: NONCE,
        selected_features: FeatureBits([1, 2]),
        effective_limits: SessionLimits::default(),
        atomics: fixed_atomics,
        target: fixed_target,
        hello_digest: [7; 32],
        decision_challenge: challenge(),
    }));
    let reject = encoded(&NegotiationFrame::Reject(RejectFrame {
        role: SenderRole::Receiver,
        nonce: NONCE,
        reason: reason(7),
        decision_challenge: challenge(),
    }));

    assert_eq!(
        <[u8; 32]>::from(Sha256::digest(&accept)),
        [
            0xab, 0x8d, 0x8c, 0xbc, 0x2f, 0x18, 0xfc, 0x90, 0x0b, 0xe1, 0x8c, 0x83, 0x9a, 0x1e,
            0x43, 0x58, 0xa8, 0xf2, 0x7a, 0x4d, 0x2e, 0xfa, 0xa2, 0x30, 0x9a, 0x8e, 0x85, 0x2f,
            0x0b, 0xac, 0xb6, 0xfe,
        ]
    );
    assert_eq!(
        <[u8; 32]>::from(Sha256::digest(&reject)),
        [
            0x1d, 0xeb, 0x42, 0x80, 0x73, 0xdc, 0xfa, 0x23, 0x0c, 0x50, 0x11, 0x1c, 0x13, 0x9b,
            0xeb, 0x1d, 0xd5, 0x49, 0xc4, 0x15, 0xae, 0x11, 0xfc, 0x6e, 0x79, 0x71, 0x11, 0x1e,
            0xba, 0x82, 0x9c, 0xf1,
        ]
    );
}

#[test]
fn decision_frames_reject_every_truncation_reserved_byte_role_and_extra_byte() {
    let frames = [
        encoded(&NegotiationFrame::Accept(AcceptFrame {
            role: SenderRole::Coordinator,
            nonce: NONCE,
            selected_features: FeatureBits([1, 0]),
            effective_limits: SessionLimits::default(),
            atomics: atomics(),
            target: TargetFacts::current(),
            hello_digest: [7; 32],
            decision_challenge: challenge(),
        })),
        encoded(&NegotiationFrame::Reject(RejectFrame {
            role: SenderRole::Coordinator,
            nonce: NONCE,
            reason: reason(7),
            decision_challenge: challenge(),
        })),
    ];
    for bytes in &frames {
        for len in 0..HEADER_LEN {
            assert_eq!(
                decode_frame(
                    &bytes[..len],
                    SenderRole::Coordinator,
                    NONCE,
                    HARD_MAX_BOOTSTRAP_PAYLOAD_BYTES,
                ),
                Err(NegotiationWireError::Truncated),
                "kind {} length {len}",
                get_u16(bytes, 12)
            );
        }
        let mut extra = bytes.clone();
        extra.push(0);
        assert_eq!(
            decode_frame(
                &extra,
                SenderRole::Coordinator,
                NONCE,
                HARD_MAX_BOOTSTRAP_PAYLOAD_BYTES,
            ),
            Err(NegotiationWireError::NonCanonical)
        );
        assert_eq!(
            decode_frame(
                bytes,
                SenderRole::Receiver,
                NONCE,
                HARD_MAX_BOOTSTRAP_PAYLOAD_BYTES,
            ),
            Err(NegotiationWireError::BadRole)
        );
    }

    let accept = &frames[0];
    for offset in [15, 28, 29, 30, 31, 98, 99]
        .into_iter()
        .chain(198..HEADER_LEN)
    {
        let mut bad = accept.clone();
        bad[offset] = 1;
        assert_eq!(
            decode_frame(
                &bad,
                SenderRole::Coordinator,
                NONCE,
                HARD_MAX_BOOTSTRAP_PAYLOAD_BYTES,
            ),
            Err(NegotiationWireError::NonCanonical),
            "ACCEPT reserved offset {offset}"
        );
    }
    let reject = &frames[1];
    for offset in [15]
        .into_iter()
        .chain(64..80)
        .chain(96..198)
        .chain(198..HEADER_LEN)
    {
        let mut bad = reject.clone();
        bad[offset] = 1;
        assert_eq!(
            decode_frame(
                &bad,
                SenderRole::Coordinator,
                NONCE,
                HARD_MAX_BOOTSTRAP_PAYLOAD_BYTES,
            ),
            Err(NegotiationWireError::NonCanonical),
            "REJECT reserved offset {offset}"
        );
    }
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
    let coordinator_accept = transcript.coordinator_accept(challenge()).unwrap();
    assert_eq!(transcript.decision_challenge(), None);
    assert_eq!(
        transcript.receiver_accept(),
        Err(NegotiationWireError::DecisionReplayOrOrder)
    );
    transcript
        .validate_accept(coordinator_accept, SenderRole::Coordinator)
        .unwrap();
    assert_eq!(transcript.decision_challenge(), Some(challenge()));
    let receiver_accept = transcript.receiver_accept().unwrap();
    assert_ne!(receiver_accept.hello_digest, [0; 32]);
    assert_eq!(coordinator_accept.selected_features, FeatureBits([3, 0]));
    assert_eq!(coordinator_accept.effective_limits.max_regions_per_batch, 4);
    let mut out_of_order = negotiate(&coordinator, &receiver, verified).unwrap();
    assert_eq!(
        out_of_order.receiver_accept(),
        Err(NegotiationWireError::DecisionReplayOrOrder)
    );
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
        let coordinator_accept = substitution_transcript
            .coordinator_accept(challenge())
            .unwrap();
        substitution_transcript
            .validate_accept(coordinator_accept, SenderRole::Coordinator)
            .unwrap();
        assert_eq!(
            substitution_transcript.validate_accept(wrong, SenderRole::Receiver),
            Err(NegotiationWireError::EffectiveMismatch)
        );
    }
    let mut wrong_challenge_transcript = negotiate(&coordinator, &receiver, verified).unwrap();
    let coordinator_accept = wrong_challenge_transcript
        .coordinator_accept(challenge())
        .unwrap();
    wrong_challenge_transcript
        .validate_accept(coordinator_accept, SenderRole::Coordinator)
        .unwrap();
    let mut wrong_challenge = wrong_challenge_transcript.receiver_accept().unwrap();
    wrong_challenge.decision_challenge = DecisionChallenge::from_os_csprng([0x3c; 16]).unwrap();
    assert_eq!(
        wrong_challenge_transcript.validate_accept(wrong_challenge, SenderRole::Receiver),
        Err(NegotiationWireError::DecisionChallengeMismatch)
    );
    assert_eq!(
        wrong_challenge_transcript.receiver_accept(),
        Err(NegotiationWireError::DecisionReplayOrOrder)
    );
    let mut wrong_role = negotiate(&coordinator, &receiver, verified).unwrap();
    assert_eq!(
        wrong_role.validate_accept(receiver_accept, SenderRole::Coordinator),
        Err(NegotiationWireError::EffectiveMismatch)
    );

    transcript
        .validate_accept(receiver_accept, SenderRole::Receiver)
        .unwrap();
    assert_eq!(transcript.decision_challenge(), Some(challenge()));

    let mut replay = negotiate(&coordinator, &receiver, verified).unwrap();
    let coordinator_accept = replay.coordinator_accept(challenge()).unwrap();
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
        changed
            .coordinator_accept(challenge())
            .unwrap()
            .hello_digest,
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
            .coordinator_accept(challenge())
            .unwrap()
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
fn reject_constructors_are_challenge_bound_ordered_and_terminal() {
    let verified = AtomicCapabilities::from_verified_native(4096, 128, true, true).unwrap();
    let mut coordinator = match hello(b"") {
        NegotiationFrame::Hello(frame) => frame,
        _ => unreachable!(),
    };
    coordinator.supported_features = FeatureBits([3, 0]);
    coordinator.required_features = FeatureBits::default();
    let mut receiver = duplicate_hello(&coordinator);
    receiver.role = SenderRole::Receiver;
    let new_transcript = || negotiate(&coordinator, &receiver, verified).unwrap();

    let mut coordinator_rejects = new_transcript();
    let reject = coordinator_rejects
        .coordinator_reject(challenge(), reason(9))
        .unwrap();
    assert_eq!(reject.role, SenderRole::Coordinator);
    assert_eq!(reject.decision_challenge, challenge());
    assert_eq!(reject.reason, reason(9));
    assert_eq!(coordinator_rejects.decision_challenge(), None);
    assert_eq!(
        coordinator_rejects.coordinator_accept(challenge()),
        Err(NegotiationWireError::DecisionReplayOrOrder)
    );
    let mut coordinator_reject_peer = new_transcript();
    assert_eq!(
        coordinator_reject_peer.validate_reject(reject, SenderRole::Coordinator),
        Ok(reason(9))
    );
    assert_eq!(
        coordinator_reject_peer.validate_reject(reject, SenderRole::Coordinator),
        Err(NegotiationWireError::DecisionReplayOrOrder)
    );
    assert_eq!(
        coordinator_reject_peer.coordinator_accept(challenge()),
        Err(NegotiationWireError::DecisionReplayOrOrder)
    );

    let mut receiver_rejects = new_transcript();
    assert_eq!(
        receiver_rejects.receiver_reject(reason(11)),
        Err(NegotiationWireError::DecisionReplayOrOrder)
    );

    let mut coordinator_side = new_transcript();
    let mut receiver_side = new_transcript();
    let coordinator_accept = coordinator_side.coordinator_accept(challenge()).unwrap();
    coordinator_side
        .validate_accept(coordinator_accept, SenderRole::Coordinator)
        .unwrap();
    receiver_side
        .validate_accept(coordinator_accept, SenderRole::Coordinator)
        .unwrap();
    let reject = receiver_side.receiver_reject(reason(11)).unwrap();
    assert_eq!(reject.role, SenderRole::Receiver);
    assert_eq!(reject.decision_challenge, challenge());
    assert_eq!(reject.reason, reason(11));
    assert_eq!(receiver_side.decision_challenge(), Some(challenge()));
    assert_eq!(
        receiver_side.receiver_reject(reason(11)),
        Err(NegotiationWireError::DecisionReplayOrOrder)
    );
    assert_eq!(
        coordinator_side.validate_reject(reject, SenderRole::Receiver),
        Ok(reason(11))
    );
    assert_eq!(
        coordinator_side.validate_reject(reject, SenderRole::Receiver),
        Err(NegotiationWireError::DecisionReplayOrOrder)
    );

    let prequeued = RejectFrame {
        role: SenderRole::Receiver,
        nonce: NONCE,
        reason: reason(11),
        decision_challenge: challenge(),
    };
    let mut prequeued_peer = new_transcript();
    assert_eq!(
        prequeued_peer.validate_reject(prequeued, SenderRole::Receiver),
        Err(NegotiationWireError::DecisionReplayOrOrder)
    );
    assert_eq!(
        prequeued_peer.coordinator_accept(challenge()),
        Err(NegotiationWireError::DecisionReplayOrOrder)
    );

    let mut wrong_challenge = reject;
    wrong_challenge.decision_challenge = DecisionChallenge::from_os_csprng([0x3c; 16]).unwrap();
    let mut wrong_challenge_peer = new_transcript();
    let coordinator_accept = wrong_challenge_peer
        .coordinator_accept(challenge())
        .unwrap();
    wrong_challenge_peer
        .validate_accept(coordinator_accept, SenderRole::Coordinator)
        .unwrap();
    assert_eq!(
        wrong_challenge_peer.validate_reject(wrong_challenge, SenderRole::Receiver),
        Err(NegotiationWireError::DecisionChallengeMismatch)
    );
    assert_eq!(
        wrong_challenge_peer.validate_reject(reject, SenderRole::Receiver),
        Err(NegotiationWireError::DecisionReplayOrOrder)
    );

    let mut wrong_role = reject;
    wrong_role.role = SenderRole::Coordinator;
    let mut wrong_role_peer = new_transcript();
    let coordinator_accept = wrong_role_peer.coordinator_accept(challenge()).unwrap();
    wrong_role_peer
        .validate_accept(coordinator_accept, SenderRole::Coordinator)
        .unwrap();
    assert_eq!(
        wrong_role_peer.validate_reject(wrong_role, SenderRole::Receiver),
        Err(NegotiationWireError::EffectiveMismatch)
    );
    assert_eq!(
        wrong_role_peer.validate_reject(reject, SenderRole::Receiver),
        Err(NegotiationWireError::DecisionReplayOrOrder)
    );

    let mut wrong_nonce = reject;
    wrong_nonce.nonce[0] ^= 1;
    let mut wrong_nonce_peer = new_transcript();
    let coordinator_accept = wrong_nonce_peer.coordinator_accept(challenge()).unwrap();
    wrong_nonce_peer
        .validate_accept(coordinator_accept, SenderRole::Coordinator)
        .unwrap();
    assert_eq!(
        wrong_nonce_peer.validate_reject(wrong_nonce, SenderRole::Receiver),
        Err(NegotiationWireError::EffectiveMismatch)
    );
    assert_eq!(
        wrong_nonce_peer.validate_reject(reject, SenderRole::Receiver),
        Err(NegotiationWireError::DecisionReplayOrOrder)
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
