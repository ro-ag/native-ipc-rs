use super::*;
use crate::negotiation::{
    AtomicOffer, DecisionChallenge, FeatureBits, HelloFrame, HelloPair, NegotiatedTranscript,
    SenderRole, TargetFacts,
};
use crate::session::{AtomicCapabilities, SessionLimits};
use static_assertions::{assert_impl_all, assert_not_impl_any};

assert_not_impl_any!(CoordinatorChildChannelReceipt: Clone);
assert_not_impl_any!(CoordinatorChildImageReceipt: Clone);
assert_not_impl_any!(CoordinatorAcceptedEvidence: Clone);
assert_not_impl_any!(CoordinatorAcceptedEvidence: Sync);
assert_impl_all!(CoordinatorAcceptedEvidence: Send);
assert_not_impl_any!(ReceiverSpawnerEvidence: Clone, Sync);
assert_impl_all!(ReceiverSpawnerEvidence: Send);

fn accepted_transcript(nonce: [u8; 32]) -> AcceptedTranscriptFacts {
    let atomics = AtomicCapabilities::from_verified_native(4096, 128, true, true).unwrap();
    let offer = AtomicOffer::from_local(atomics).unwrap();
    let hello = |role| HelloFrame {
        role,
        nonce,
        supported_features: FeatureBits([3, 0]),
        required_features: FeatureBits::default(),
        limits: SessionLimits::default(),
        atomics: offer,
        target: TargetFacts::current(),
        application_payload: Vec::new(),
    };
    let mut transcript = NegotiatedTranscript::from_hellos(
        HelloPair::new(hello(SenderRole::Coordinator), hello(SenderRole::Receiver)),
        atomics,
    )
    .unwrap();
    let challenge = DecisionChallenge::from_os_csprng([9; 16]).unwrap();
    let coordinator = transcript.coordinator_accept(challenge).unwrap();
    transcript
        .validate_accept(coordinator, SenderRole::Coordinator)
        .unwrap();
    let receiver = transcript.receiver_accept().unwrap();
    transcript
        .validate_accept(receiver, SenderRole::Receiver)
        .unwrap();
    transcript.take_accepted_facts().unwrap()
}

fn facts(child_pid: u32, nonce: [u8; 32]) -> SpawnIdentityFacts {
    SpawnIdentityFacts::new(10, child_pid, 1000, 1000, 1000, 1000, nonce).unwrap()
}

#[test]
fn coordinator_evidence_requires_exact_channel_image_and_transcript_identity() {
    let nonce = [7; 32];
    // SAFETY: this unit test models completed coordinator channel verification.
    let channel = unsafe { CoordinatorChildChannelReceipt::from_verified_native(facts(11, nonce)) };
    // SAFETY: this unit test models a substituted child-image proof.
    let wrong_image =
        unsafe { CoordinatorChildImageReceipt::from_verified_native(facts(12, nonce)) };
    assert!(matches!(
        CoordinatorAcceptedEvidence::combine(channel, wrong_image, accepted_transcript(nonce)),
        Err(SessionTransportError::IdentityMismatch)
    ));

    // SAFETY: these unit-test receipts intentionally mismatch the transcript nonce.
    let channel = unsafe { CoordinatorChildChannelReceipt::from_verified_native(facts(11, nonce)) };
    // SAFETY: these unit-test receipts intentionally mismatch the transcript nonce.
    let image = unsafe { CoordinatorChildImageReceipt::from_verified_native(facts(11, nonce)) };
    assert!(matches!(
        CoordinatorAcceptedEvidence::combine(channel, image, accepted_transcript([8; 32])),
        Err(SessionTransportError::IdentityMismatch)
    ));

    // SAFETY: this unit test models exact matching coordinator proofs.
    let channel = unsafe { CoordinatorChildChannelReceipt::from_verified_native(facts(11, nonce)) };
    // SAFETY: this unit test models exact matching coordinator proofs.
    let image = unsafe { CoordinatorChildImageReceipt::from_verified_native(facts(11, nonce)) };
    let accepted =
        CoordinatorAcceptedEvidence::combine(channel, image, accepted_transcript(nonce)).unwrap();
    assert_eq!(accepted.facts(), facts(11, nonce));

    assert!(SpawnIdentityFacts::new(0, 11, 0, 0, 0, 0, nonce).is_none());
    assert!(SpawnIdentityFacts::new(10, 10, 0, 0, 0, 0, nonce).is_none());
    assert!(SpawnIdentityFacts::new(10, 11, 0, 0, 0, 0, [0; 32]).is_none());
}

#[test]
fn receiver_evidence_is_role_scoped_and_nonce_bound() {
    let nonce = [7; 32];
    let identity = facts(11, nonce);
    // SAFETY: this unit test models receiver-side spawner/channel verification.
    let receiver = unsafe {
        ReceiverSpawnerEvidence::from_verified_native(identity, accepted_transcript(nonce))
    }
    .unwrap();
    assert_eq!(receiver.facts, identity);

    // SAFETY: the mismatch is intentional and must fail before evidence exists.
    let mismatch = unsafe {
        ReceiverSpawnerEvidence::from_verified_native(identity, accepted_transcript([8; 32]))
    };
    assert!(matches!(
        mismatch,
        Err(SessionTransportError::IdentityMismatch)
    ));
}
