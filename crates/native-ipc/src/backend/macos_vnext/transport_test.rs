use super::vnext_transport::{
    CoordinatorMacControlTransport, MacReceivedCapabilities, ReceiverMacControlTransport,
};
use super::{bootstrap, set_vnext_drop_observer_for_test};
use crate::backend::{
    AuthenticatedZeroRightsTransport, CoordinatorAcceptedEvidence, CoordinatorCapabilityTransport,
    CoordinatorChildChannelReceipt, CoordinatorChildImageReceipt, OwnedChildLifecycle, PeerState,
    ReceiverCapabilityTransport, ReceiverSpawnerEvidence, SessionTransportError,
    SpawnIdentityFacts,
};
use crate::negotiation::{
    AcceptedTranscriptFacts, AtomicOffer, DecisionChallenge, FeatureBits, HelloFrame, HelloPair,
    NegotiatedTranscript, SenderRole, TargetFacts,
};
use crate::protocol::{
    CapabilityFrame, ManifestEntry, NativeAuthorityProfile, NativeRegionSpec, PeerAccess,
    TransferManifest,
};
use crate::session::{AbsoluteDeadline, AtomicCapabilities, SessionLimits};
use static_assertions::{assert_impl_all, assert_not_impl_any};
use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

assert_impl_all!(
    CoordinatorMacControlTransport:
        Send,
        AuthenticatedZeroRightsTransport,
        CoordinatorCapabilityTransport,
        OwnedChildLifecycle
);
assert_not_impl_any!(
    CoordinatorMacControlTransport: Sync, Clone, ReceiverCapabilityTransport
);
assert_impl_all!(
    ReceiverMacControlTransport:
        Send,
        AuthenticatedZeroRightsTransport,
        ReceiverCapabilityTransport
);
assert_not_impl_any!(
    ReceiverMacControlTransport: Sync, Clone, CoordinatorCapabilityTransport, OwnedChildLifecycle
);
assert_impl_all!(MacReceivedCapabilities: Send);
assert_not_impl_any!(MacReceivedCapabilities: Sync);
assert_not_impl_any!(MacReceivedCapabilities: Clone);

fn deadline() -> AbsoluteDeadline {
    AbsoluteDeadline::after(Duration::from_secs(20)).unwrap()
}

fn accepted_transcript(nonce: [u8; 32]) -> AcceptedTranscriptFacts {
    let atomics = AtomicCapabilities::from_verified_native(
        super::page_size().expect("native page size"),
        128,
        true,
        true,
    )
    .expect("native macOS atomic facts");
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
    let challenge = DecisionChallenge::from_os_csprng([11; 16]).unwrap();
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

fn coordinator_transport(channel: bootstrap::ParentChannel) -> CoordinatorMacControlTransport {
    let nonce = channel.vnext_nonce();
    let facts =
        SpawnIdentityFacts::new(std::process::id(), channel.peer_pid(), 0, 0, 0, 0, nonce).unwrap();
    // SAFETY: this native integration fixture has completed exact audit-token
    // authentication for the retained channel and models the image proof that
    // public macOS composition will retain in task #42.
    let channel_receipt = unsafe { CoordinatorChildChannelReceipt::from_verified_native(facts) };
    // SAFETY: this test-only receipt models the matching held-image proof; the
    // production image owner remains intentionally unreachable until task #42.
    let image_receipt = unsafe { CoordinatorChildImageReceipt::from_verified_native(facts) };
    let evidence = CoordinatorAcceptedEvidence::combine(
        channel_receipt,
        image_receipt,
        accepted_transcript(nonce),
    )
    .unwrap();
    let transport = CoordinatorMacControlTransport::from_accepted(channel, evidence).unwrap();
    assert_eq!(
        transport.session_parameters().authority_profile(),
        NativeAuthorityProfile::MacMachV1
    );
    transport
}

fn coordinator_evidence(facts: SpawnIdentityFacts) -> CoordinatorAcceptedEvidence {
    // SAFETY: callers of this test helper state which modeled native facts are
    // intentional; production cannot call these private unsafe constructors.
    let channel_receipt = unsafe { CoordinatorChildChannelReceipt::from_verified_native(facts) };
    // SAFETY: this test helper models the matching held-image receipt.
    let image_receipt = unsafe { CoordinatorChildImageReceipt::from_verified_native(facts) };
    CoordinatorAcceptedEvidence::combine(
        channel_receipt,
        image_receipt,
        accepted_transcript(facts.nonce()),
    )
    .unwrap()
}

fn receiver_transport(channel: bootstrap::ChildChannel) -> ReceiverMacControlTransport {
    let nonce = channel.vnext_nonce();
    let facts = SpawnIdentityFacts::new(
        channel.vnext_parent_pid(),
        std::process::id(),
        0,
        0,
        0,
        0,
        nonce,
    )
    .unwrap();
    // SAFETY: the child obtained the exact injected port, validated its parent
    // audit PID, and retains the nonce-bound accepted transcript in this test.
    let evidence =
        unsafe { ReceiverSpawnerEvidence::from_verified_native(facts, accepted_transcript(nonce)) }
            .unwrap();
    let transport = ReceiverMacControlTransport::from_accepted(channel, evidence).unwrap();
    assert_eq!(
        transport.session_parameters().authority_profile(),
        NativeAuthorityProfile::MacMachV1
    );
    transport
}

fn spawn_helper(test: &str) -> bootstrap::ParentChannel {
    let executable = std::env::current_exe().unwrap();
    let path = CString::new(executable.as_os_str().as_bytes()).unwrap();
    let arguments = [
        CString::new("--exact").unwrap(),
        CString::new(test).unwrap(),
        CString::new("--ignored").unwrap(),
        CString::new("--nocapture").unwrap(),
    ];
    bootstrap::SpawnedHelper::spawn(&path, &arguments)
        .unwrap()
        .authenticate()
        .unwrap()
}

fn wait_for_exit(transport: &mut CoordinatorMacControlTransport) {
    for _ in 0..10_000 {
        if transport.try_poll_peer().unwrap() == PeerState::ExitedUnknown {
            return;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    panic!("helper did not exit");
}

#[test]
fn accepted_evidence_must_match_the_exact_authenticated_channel() {
    let channel = spawn_helper("backend::macos::bootstrap::tests::spawned_helper_entry");
    let wrong_nonce = [0x7b; 32];
    assert_ne!(channel.vnext_nonce(), wrong_nonce);
    let wrong_facts = SpawnIdentityFacts::new(
        std::process::id(),
        channel.peer_pid(),
        0,
        0,
        0,
        0,
        wrong_nonce,
    )
    .unwrap();
    assert!(matches!(
        CoordinatorMacControlTransport::from_accepted(channel, coordinator_evidence(wrong_facts)),
        Err(SessionTransportError::IdentityMismatch)
    ));
}

#[test]
fn only_coordinator_can_terminate_and_reap_the_exact_child() {
    let channel = spawn_helper("backend::macos::bootstrap::tests::spawned_helper_entry");
    let mut transport = coordinator_transport(channel);
    transport.terminate_and_reap(deadline()).unwrap();
    assert_eq!(
        transport.try_poll_peer(),
        Err(SessionTransportError::Native(None))
    );
}

#[test]
fn cleanup_timeout_hands_reaping_off_without_blocking_drop() {
    let channel = spawn_helper("backend::macos::bootstrap::tests::spawned_helper_entry");
    let mut transport = coordinator_transport(channel);
    transport.delay_reap_for_test(100);
    let short = AbsoluteDeadline::after(Duration::from_millis(1)).unwrap();
    assert_eq!(
        transport.terminate_and_reap(short),
        Err(SessionTransportError::DeadlineExpired)
    );
    let before_drop = Instant::now();
    drop(transport);
    assert!(before_drop.elapsed() < Duration::from_millis(25));
    // Leave enough time for the detached exact-child worker to consume the
    // delayed wait and reap before the test process exits.
    std::thread::sleep(Duration::from_millis(125));
}

#[test]
fn exact_child_reaper_retries_wait_interruptions_until_cleanup_completes() {
    let channel = spawn_helper("backend::macos::bootstrap::tests::spawned_helper_entry");
    let mut transport = coordinator_transport(channel);
    transport.interrupt_reap_wait_for_test(32);
    transport.terminate_and_reap(deadline()).unwrap();
    assert_eq!(
        transport.try_poll_peer(),
        Err(SessionTransportError::Native(None))
    );
}

#[test]
fn accepted_zero_rights_transport_is_bounded_duplex_and_terminally_poisoned() {
    let channel =
        spawn_helper("backend::macos::vnext_transport_test::accepted_zero_rights_transport_helper");
    let mut transport = coordinator_transport(channel);
    let maximum = vec![0x5a; bootstrap::MAX_VNEXT_RECORD_BYTES];
    assert_eq!(
        transport.send_record(&[], deadline()),
        Err(SessionTransportError::RecordTooLarge)
    );
    assert_eq!(
        transport.receive_record(0, deadline()),
        Err(SessionTransportError::RecordTooLarge)
    );
    transport.send_record(b"parent-one", deadline()).unwrap();
    transport.send_record(&maximum, deadline()).unwrap();
    assert_eq!(
        transport.receive_record(1, deadline()).unwrap(),
        b"c".to_vec()
    );
    assert_eq!(
        transport
            .receive_record(bootstrap::MAX_VNEXT_RECORD_BYTES, deadline())
            .unwrap(),
        maximum
    );
    wait_for_exit(&mut transport);

    transport.poison();
    assert_eq!(
        transport.send_record(b"after-poison", deadline()),
        Err(SessionTransportError::Native(None))
    );
}

#[test]
#[ignore = "spawned only by the accepted macOS transport integration test"]
fn accepted_zero_rights_transport_helper() {
    let channel = bootstrap::ChildChannel::connect_from_environment().unwrap();
    let mut transport = receiver_transport(channel);
    assert_eq!(
        transport.receive_record(10, deadline()).unwrap(),
        b"parent-one"
    );
    assert_eq!(
        transport
            .receive_record(bootstrap::MAX_VNEXT_RECORD_BYTES, deadline())
            .unwrap(),
        vec![0x5a; bootstrap::MAX_VNEXT_RECORD_BYTES]
    );
    transport.send_record(b"c", deadline()).unwrap();
    transport
        .send_record(&vec![0x5a; bootstrap::MAX_VNEXT_RECORD_BYTES], deadline())
        .unwrap();
}

#[test]
fn same_alignment_bucket_oversize_record_is_rejected_and_poisoned() {
    let channel =
        spawn_helper("backend::macos::vnext_transport_test::same_alignment_bucket_oversize_helper");
    let mut transport = coordinator_transport(channel);
    assert_eq!(
        transport.receive_record(1, deadline()),
        Err(SessionTransportError::MalformedRecord)
    );
    assert_eq!(
        transport.receive_record(1, deadline()),
        Err(SessionTransportError::Native(None))
    );
}

#[test]
#[ignore = "spawned only by the accepted macOS bounded-record test"]
fn same_alignment_bucket_oversize_helper() {
    let channel = bootstrap::ChildChannel::connect_from_environment().unwrap();
    let mut transport = receiver_transport(channel);
    transport.send_record(b"xy", deadline()).unwrap();
}

fn capability_frame(
    nonce: [u8; 32],
    parent_pid: u32,
    child_pid: u32,
    transaction_id: u64,
    count: usize,
) -> CapabilityFrame {
    let entries = (0..count)
        .map(|ordinal| {
            let native = NativeRegionSpec::new(
                (ordinal + 1) as u128,
                [(ordinal + 1) as u8; 16],
                1,
                1,
                super::page_size().expect("native page size"),
            )
            .unwrap();
            ManifestEntry::from_native(native, PeerAccess::ReadOnly)
        })
        .collect();
    let manifest = TransferManifest::new_with_authority(
        nonce,
        parent_pid,
        child_pid,
        transaction_id,
        NativeAuthorityProfile::MacMachV1,
        entries,
    )
    .unwrap();
    CapabilityFrame::from_manifest(&manifest)
}

#[test]
fn accepted_capability_transport_moves_exact_1_2_4_16_owned_rights() {
    let channel =
        spawn_helper("backend::macos::vnext_transport_test::accepted_capability_transport_helper");
    let nonce = channel.vnext_nonce();
    let child_pid = channel.peer_pid();
    let mut transport = coordinator_transport(channel);
    for (index, count) in [1, 2, 4, 16].into_iter().enumerate() {
        let frame = capability_frame(
            nonce,
            std::process::id(),
            child_pid,
            (index + 1) as u64,
            count,
        );
        let ports = (0..count)
            .map(|_| bootstrap::TestSendRight::allocate().unwrap())
            .collect::<Vec<_>>();
        let names = ports
            .iter()
            .map(bootstrap::TestSendRight::name)
            .collect::<Vec<_>>();
        transport.send_record(frame.as_bytes(), deadline()).unwrap();
        transport
            .send_capability_record(&frame, &names, deadline())
            .unwrap();
        assert_eq!(
            transport.receive_record(1, deadline()).unwrap(),
            vec![count as u8]
        );
    }
    wait_for_exit(&mut transport);
}

#[test]
#[ignore = "spawned only by the accepted macOS capability integration test"]
fn accepted_capability_transport_helper() {
    let channel = bootstrap::ChildChannel::connect_from_environment().unwrap();
    let mut transport = receiver_transport(channel);
    for count in [1, 2, 4, 16] {
        let bytes = transport
            .receive_record(crate::protocol::CONTROL_FRAME_LEN, deadline())
            .unwrap();
        let (frame, _) = CapabilityFrame::decode(&bytes).unwrap();
        assert_eq!(frame.capability_count(), count);
        let received = transport
            .receive_capability_record(&frame, deadline())
            .unwrap();
        assert_eq!(received.len(), count);
        drop(received.into_rights());
        transport.send_record(&[count as u8], deadline()).unwrap();
    }
}

#[test]
fn substituted_capability_frame_drops_every_installed_right_and_poisons() {
    let channel =
        spawn_helper("backend::macos::vnext_transport_test::substituted_capability_frame_helper");
    let nonce = channel.vnext_nonce();
    let child_pid = channel.peer_pid();
    let mut transport = coordinator_transport(channel);
    let expected = capability_frame(nonce, std::process::id(), child_pid, 1, 1);
    let substituted = capability_frame(nonce, std::process::id(), child_pid, 2, 1);
    let port = bootstrap::TestSendRight::allocate().unwrap();
    transport
        .send_record(expected.as_bytes(), deadline())
        .unwrap();
    transport
        .send_capability_record(&substituted, &[port.name()], deadline())
        .unwrap();
    wait_for_exit(&mut transport);
}

#[test]
#[ignore = "spawned only by the accepted macOS substitution test"]
fn substituted_capability_frame_helper() {
    let channel = bootstrap::ChildChannel::connect_from_environment().unwrap();
    let mut transport = receiver_transport(channel);
    let bytes = transport
        .receive_record(crate::protocol::CONTROL_FRAME_LEN, deadline())
        .unwrap();
    let (expected, _) = CapabilityFrame::decode(&bytes).unwrap();
    let drops = Arc::new(Mutex::new(Vec::new()));
    set_vnext_drop_observer_for_test(Some(drops.clone()));
    assert!(matches!(
        transport.receive_capability_record(&expected, deadline()),
        Err(SessionTransportError::MalformedRecord)
    ));
    assert!(matches!(
        transport.receive_capability_record(&expected, deadline()),
        Err(SessionTransportError::Native(None))
    ));
    set_vnext_drop_observer_for_test(None);
    assert_eq!(
        drops
            .lock()
            .unwrap()
            .iter()
            .filter(|event| **event == "send-right")
            .count(),
        1
    );
}

#[test]
fn zero_rights_receive_rejects_and_drops_injected_capabilities() {
    let mut channel =
        spawn_helper("backend::macos::vnext_transport_test::zero_rights_injection_helper");
    let port = bootstrap::TestSendRight::allocate().unwrap();
    channel
        .send_vnext_zero_with_rights_for_test(b"injected", &[port.name()], deadline())
        .unwrap();
    let mut transport = coordinator_transport(channel);
    wait_for_exit(&mut transport);
}

#[test]
#[ignore = "spawned only by the accepted macOS injection integration test"]
fn zero_rights_injection_helper() {
    let channel = bootstrap::ChildChannel::connect_from_environment().unwrap();
    let mut transport = receiver_transport(channel);
    let drops = Arc::new(Mutex::new(Vec::new()));
    set_vnext_drop_observer_for_test(Some(drops.clone()));
    assert_eq!(
        transport.receive_record(8, deadline()),
        Err(SessionTransportError::MalformedRecord)
    );
    set_vnext_drop_observer_for_test(None);
    assert_eq!(
        drops
            .lock()
            .unwrap()
            .iter()
            .filter(|event| **event == "send-right")
            .count(),
        1
    );
}
