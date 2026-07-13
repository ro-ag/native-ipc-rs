use super::vnext_memory::{WindowsExpectedMixedDirectionBatch, WindowsMixedDirectionBatch};
use super::vnext_transport::{
    CoordinatorWindowsControlTransport, ReceiverWindowsControlTransport,
    WindowsReceivedCapabilities,
};
use super::{ChildChannel, ChildSession, MAX_VNEXT_RECORD_BYTES, connect_spawned_helper};
use crate::backend::{
    AuthenticatedZeroRightsTransport, CoordinatorAcceptedEvidence, CoordinatorCapabilityTransport,
    CoordinatorChildChannelReceipt, CoordinatorChildImageReceipt, OwnedChildLifecycle, PeerState,
    ReceiverCapabilityTransport, ReceiverSpawnerEvidence, SessionTransportError,
    SpawnIdentityFacts,
};
use crate::batch::{ExpectedBatch, ExpectedRegion, TransferBatch};
use crate::negotiation::{
    AcceptedTranscriptFacts, AtomicOffer, DecisionChallenge, FeatureBits, HelloFrame, HelloPair,
    NegotiatedTranscript, SenderRole, TargetFacts,
};
use crate::protocol::{
    CONTROL_FRAME_LEN, CapabilityFrame, NativeAuthorityProfile, TransferManifest,
};
use crate::region::{PrivateRegion, RegionId, RegionOptions, RegionSpec, WriterEndpoint};
use crate::session::{AbsoluteDeadline, AtomicCapabilities, SessionLimits};
use static_assertions::{assert_impl_all, assert_not_impl_any};
use std::ffi::OsString;
use std::mem::zeroed;
use std::time::Duration;
use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
use windows_sys::Win32::System::Threading::GetCurrentProcessId;

assert_impl_all!(
    CoordinatorWindowsControlTransport:
        Send,
        AuthenticatedZeroRightsTransport,
        CoordinatorCapabilityTransport,
        OwnedChildLifecycle
);
assert_not_impl_any!(
    CoordinatorWindowsControlTransport: Sync, Clone, ReceiverCapabilityTransport
);
assert_impl_all!(
    ReceiverWindowsControlTransport:
        Send,
        AuthenticatedZeroRightsTransport,
        ReceiverCapabilityTransport
);
assert_not_impl_any!(
    ReceiverWindowsControlTransport: Sync, Clone, CoordinatorCapabilityTransport, OwnedChildLifecycle
);
assert_impl_all!(WindowsReceivedCapabilities: Send);
assert_not_impl_any!(WindowsReceivedCapabilities: Sync, Clone);

fn deadline() -> AbsoluteDeadline {
    AbsoluteDeadline::after(Duration::from_secs(20)).unwrap()
}

fn page_size() -> usize {
    let mut information: SYSTEM_INFO = unsafe { zeroed() };
    unsafe { GetSystemInfo(&mut information) };
    information.dwPageSize as usize
}

fn accepted_transcript(nonce: [u8; 32]) -> AcceptedTranscriptFacts {
    let atomics = AtomicCapabilities::from_verified_native(page_size(), 64, true, true).unwrap();
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
    let coordinator = transcript
        .coordinator_accept(DecisionChallenge::from_os_csprng([11; 16]).unwrap())
        .unwrap();
    transcript
        .validate_accept(coordinator, SenderRole::Coordinator)
        .unwrap();
    let receiver = transcript.receiver_accept().unwrap();
    transcript
        .validate_accept(receiver, SenderRole::Receiver)
        .unwrap();
    transcript.take_accepted_facts().unwrap()
}

fn coordinator_evidence(
    parent_pid: u32,
    child_pid: u32,
    nonce: [u8; 32],
) -> CoordinatorAcceptedEvidence {
    let facts = SpawnIdentityFacts::new(parent_pid, child_pid, 0, 0, 0, 0, nonce).unwrap();
    // SAFETY: the native fixture completed PID authentication and retains the
    // exact process/Job owner; the image receipt models later composition.
    let channel = unsafe { CoordinatorChildChannelReceipt::from_verified_native(facts) };
    // SAFETY: this test receipt is paired with the same held process facts.
    let image = unsafe { CoordinatorChildImageReceipt::from_verified_native(facts) };
    CoordinatorAcceptedEvidence::combine(channel, image, accepted_transcript(nonce)).unwrap()
}

fn receiver_evidence(parent_pid: u32, child_pid: u32, nonce: [u8; 32]) -> ReceiverSpawnerEvidence {
    let facts = SpawnIdentityFacts::new(parent_pid, child_pid, 0, 0, 0, 0, nonce).unwrap();
    // SAFETY: connect_spawned_helper validated the exact named-pipe server PID
    // and nonce before this role-scoped evidence is created.
    unsafe { ReceiverSpawnerEvidence::from_verified_native(facts, accepted_transcript(nonce)) }
        .unwrap()
}

fn coordinator_transport(session: ChildSession) -> CoordinatorWindowsControlTransport {
    let parent = unsafe { GetCurrentProcessId() };
    let child = session.pid();
    let nonce = session.vnext_nonce();
    let transport = CoordinatorWindowsControlTransport::from_accepted(
        session,
        coordinator_evidence(parent, child, nonce),
    )
    .unwrap();
    assert_eq!(
        transport.session_parameters().authority_profile(),
        NativeAuthorityProfile::WindowsSectionsV1
    );
    transport
}

fn receiver_transport(channel: ChildChannel) -> ReceiverWindowsControlTransport {
    let parent = channel.parent_pid();
    let nonce = channel.vnext_nonce();
    let child = unsafe { GetCurrentProcessId() };
    let transport = ReceiverWindowsControlTransport::from_accepted(
        channel,
        receiver_evidence(parent, child, nonce),
    )
    .unwrap();
    assert_eq!(
        transport.session_parameters().authority_profile(),
        NativeAuthorityProfile::WindowsSectionsV1
    );
    transport
}

fn spawn_helper(test: &str) -> ChildSession {
    let executable = std::env::current_exe().unwrap();
    let arguments = [
        OsString::from("--exact"),
        OsString::from(test),
        OsString::from("--ignored"),
        OsString::from("--nocapture"),
    ];
    ChildSession::spawn(&executable, &arguments).unwrap()
}

fn wait_and_reap(transport: &mut CoordinatorWindowsControlTransport) {
    for _ in 0..20_000 {
        if transport.try_poll_peer().unwrap() == PeerState::ExitedUnknown {
            transport.terminate_and_reap(deadline()).unwrap();
            return;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    panic!("Windows helper did not exit");
}

fn build_batch(count: usize) -> (TransferBatch, ExpectedBatch) {
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
        let region = PrivateRegion::allocate(RegionOptions::fixed(logical_len)).unwrap();
        batch
            .add(region.prepare(RegionSpec { id, writer }).unwrap())
            .unwrap();
        expected.push(ExpectedRegion::new(id, writer, logical_len));
    }
    (batch, ExpectedBatch::try_from_regions(expected).unwrap())
}

#[test]
fn accepted_message_records_preserve_boundaries_and_maximum() {
    let session =
        spawn_helper("backend::windows::vnext_transport_test::accepted_message_record_helper");
    let mut transport = coordinator_transport(session);
    transport.send_record(&[0x41], deadline()).unwrap();
    transport
        .send_record(&vec![0x5a; MAX_VNEXT_RECORD_BYTES], deadline())
        .unwrap();
    assert_eq!(transport.receive_record(1, deadline()).unwrap(), [0x7e]);
    wait_and_reap(&mut transport);
}

#[test]
fn caller_deadline_poison_is_persistent() {
    let session = spawn_helper("backend::windows::vnext_transport_test::stalled_record_helper");
    let mut transport = coordinator_transport(session);
    let short = AbsoluteDeadline::after(Duration::from_millis(5)).unwrap();
    assert_eq!(
        transport.receive_record(1, short),
        Err(SessionTransportError::DeadlineExpired)
    );
    assert_eq!(
        transport.receive_record(1, deadline()),
        Err(SessionTransportError::Native(None))
    );
    transport.terminate_and_reap(deadline()).unwrap();
}

#[test]
fn accepted_evidence_must_match_exact_pipe_and_process() {
    let session = spawn_helper("backend::windows::vnext_transport_test::stalled_record_helper");
    let parent = unsafe { GetCurrentProcessId() };
    let child = session.pid();
    let mut wrong_nonce = session.vnext_nonce();
    wrong_nonce[0] ^= 0xff;
    assert!(matches!(
        CoordinatorWindowsControlTransport::from_accepted(
            session,
            coordinator_evidence(parent, child, wrong_nonce)
        ),
        Err(SessionTransportError::IdentityMismatch)
    ));
}

#[test]
fn accepted_capability_records_move_exact_mixed_1_2_4_16_handles() {
    for count in [1, 2, 4, 16] {
        let session = spawn_helper(
            "backend::windows::vnext_transport_test::accepted_capability_record_helper",
        );
        let parent = unsafe { GetCurrentProcessId() };
        let child = session.pid();
        let nonce = session.vnext_nonce();
        let (batch, _) = build_batch(count);
        let prepared = WindowsMixedDirectionBatch::prepare(
            batch,
            NativeAuthorityProfile::WindowsSectionsV1,
            deadline(),
        )
        .unwrap();
        let manifest = TransferManifest::new_with_authority(
            nonce,
            parent,
            child,
            count as u64,
            NativeAuthorityProfile::WindowsSectionsV1,
            prepared.manifest_entries(),
        )
        .unwrap();
        let frame = CapabilityFrame::from_manifest(&manifest);
        let mut transport = coordinator_transport(session);
        transport.send_record(frame.as_bytes(), deadline()).unwrap();
        transport
            .send_capability_record(&frame, &prepared, deadline())
            .unwrap();
        assert_eq!(
            transport.receive_record(1, deadline()).unwrap(),
            [count as u8]
        );
        wait_and_reap(&mut transport);
    }
}

#[test]
#[ignore = "spawned only by the accepted Windows record integration test"]
fn accepted_message_record_helper() {
    let channel = connect_spawned_helper().unwrap();
    let mut transport = receiver_transport(channel);
    assert_eq!(transport.receive_record(1, deadline()).unwrap(), [0x41]);
    assert_eq!(
        transport
            .receive_record(MAX_VNEXT_RECORD_BYTES, deadline())
            .unwrap(),
        vec![0x5a; MAX_VNEXT_RECORD_BYTES]
    );
    transport.send_record(&[0x7e], deadline()).unwrap();
}

#[test]
#[ignore = "spawned only by the caller-deadline Windows transport test"]
fn stalled_record_helper() {
    let channel = connect_spawned_helper().unwrap();
    let _transport = receiver_transport(channel);
    std::thread::sleep(Duration::from_secs(1));
}

#[test]
#[ignore = "spawned only by the accepted Windows capability integration test"]
fn accepted_capability_record_helper() {
    let channel = connect_spawned_helper().unwrap();
    let mut transport = receiver_transport(channel);
    let frame_bytes = transport
        .receive_record(CONTROL_FRAME_LEN, deadline())
        .unwrap();
    let (frame, manifest) = CapabilityFrame::decode(&frame_bytes).unwrap();
    let received = transport
        .receive_capability_record(&frame, deadline())
        .unwrap();
    let expected = ExpectedBatch::try_from_regions(
        manifest
            .entries()
            .iter()
            .map(|entry| {
                ExpectedRegion::new(
                    RegionId::new(entry.region_id).unwrap(),
                    if entry.writer == 0 {
                        WriterEndpoint::Coordinator
                    } else {
                        WriterEndpoint::Receiver
                    },
                    usize::try_from(entry.logical_len).unwrap(),
                )
            })
            .collect::<Vec<_>>(),
    )
    .unwrap();
    let expected =
        WindowsExpectedMixedDirectionBatch::new(expected, SessionLimits::default(), deadline())
            .unwrap();
    let imported = expected.import(&manifest, received.into_handles()).unwrap();
    assert_eq!(
        imported.activation_specs(deadline()).unwrap().len(),
        frame.capability_count()
    );
    transport
        .send_record(&[frame.capability_count() as u8], deadline())
        .unwrap();
}
