use super::vnext_memory::{
    WindowsExpectedMixedDirectionBatch, WindowsMixedDirectionBatch, live_handles_for_test,
};
use super::vnext_transport::{
    CoordinatorWindowsControlTransport, ReceiverWindowsControlTransport,
    WindowsReceivedCapabilities, adopt_capability_record, set_post_io_delay_for_test,
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
use std::process::Command;
use std::time::Duration;
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_INVALID_HANDLE, GetHandleInformation, GetLastError, HANDLE,
    HANDLE_FLAG_INHERIT, HANDLE_FLAG_PROTECT_FROM_CLOSE, SetHandleInformation, WAIT_OBJECT_0,
};
use windows_sys::Win32::Storage::FileSystem::SYNCHRONIZE;
use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcessId, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, WaitForSingleObject,
};

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

pub(super) fn deadline() -> AbsoluteDeadline {
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

pub(super) fn coordinator_transport(session: ChildSession) -> CoordinatorWindowsControlTransport {
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

pub(super) fn receiver_transport(channel: ChildChannel) -> ReceiverWindowsControlTransport {
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

pub(super) fn spawn_helper(test: &str) -> ChildSession {
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
    transport.wait_for_child_exit_for_test(deadline()).unwrap();
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
    assert_eq!(transport.receive_record(1, deadline()).unwrap(), [0x7d]);
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
fn pipe_backpressure_retries_zero_byte_writes_under_one_deadline() {
    let session =
        spawn_helper("backend::windows::vnext_transport_test::delayed_record_reader_helper");
    let mut transport = coordinator_transport(session);
    transport
        .send_record(&vec![0x4c; MAX_VNEXT_RECORD_BYTES], deadline())
        .unwrap();
    transport.send_record(&[0x6b], deadline()).unwrap();
    assert_eq!(transport.receive_record(1, deadline()).unwrap(), [0x6c]);
    wait_and_reap(&mut transport);
}

#[test]
fn successful_native_io_is_rechecked_after_the_syscall() {
    let session = spawn_helper("backend::windows::vnext_transport_test::stalled_record_helper");
    let mut writer = coordinator_transport(session);
    set_post_io_delay_for_test(10);
    let short = AbsoluteDeadline::after(Duration::from_millis(1)).unwrap();
    assert_eq!(
        writer.send_record(&[0x31], short),
        Err(SessionTransportError::DeadlineExpired)
    );
    set_post_io_delay_for_test(0);
    writer.terminate_and_reap(deadline()).unwrap();

    let session =
        spawn_helper("backend::windows::vnext_transport_test::one_record_then_stall_helper");
    let mut reader = coordinator_transport(session);
    std::thread::sleep(Duration::from_millis(10));
    set_post_io_delay_for_test(10);
    let short = AbsoluteDeadline::after(Duration::from_millis(1)).unwrap();
    assert_eq!(
        reader.receive_record(1, short),
        Err(SessionTransportError::DeadlineExpired)
    );
    set_post_io_delay_for_test(0);
    reader.terminate_and_reap(deadline()).unwrap();
}

#[test]
fn expired_capability_receive_adopts_then_closes_every_installed_handle() {
    let session =
        spawn_helper("backend::windows::vnext_transport_test::expired_capability_receive_helper");
    let parent = unsafe { GetCurrentProcessId() };
    let child = session.pid();
    let nonce = session.vnext_nonce();
    let (batch, _) = build_batch(4);
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
        1,
        NativeAuthorityProfile::WindowsSectionsV1,
        prepared.manifest_entries(),
    )
    .unwrap();
    let frame = CapabilityFrame::from_manifest(&manifest);
    let mut transport = coordinator_transport(session);
    transport.send_record(frame.as_bytes(), deadline()).unwrap();
    assert_eq!(transport.receive_record(1, deadline()).unwrap(), [0x61]);
    transport
        .send_capability_record(&frame, &prepared, deadline())
        .unwrap();
    wait_and_reap(&mut transport);
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

    let session = spawn_helper("backend::windows::vnext_transport_test::stalled_record_helper");
    let child = session.pid();
    let nonce = session.vnext_nonce();
    assert!(matches!(
        CoordinatorWindowsControlTransport::from_accepted(
            session,
            coordinator_evidence(parent.wrapping_add(1), child, nonce)
        ),
        Err(SessionTransportError::IdentityMismatch)
    ));

    let session = spawn_helper("backend::windows::vnext_transport_test::stalled_record_helper");
    let child = session.pid();
    let nonce = session.vnext_nonce();
    assert!(matches!(
        CoordinatorWindowsControlTransport::from_accepted(
            session,
            coordinator_evidence(parent, child.wrapping_add(1), nonce)
        ),
        Err(SessionTransportError::IdentityMismatch)
    ));

    spawn_helper("backend::windows::vnext_transport_test::receiver_parent_pid_mismatch_helper")
        .wait()
        .unwrap();
    spawn_helper("backend::windows::vnext_transport_test::receiver_child_pid_mismatch_helper")
        .wait()
        .unwrap();
}

#[test]
fn rejected_middle_handle_still_adopts_and_closes_the_complete_record() {
    let (batch, _) = build_batch(3);
    let prepared = WindowsMixedDirectionBatch::prepare(
        batch,
        NativeAuthorityProfile::WindowsSectionsV1,
        deadline(),
    )
    .unwrap();
    let parent = unsafe { GetCurrentProcessId() };
    let manifest = TransferManifest::new_with_authority(
        [9; 32],
        parent,
        parent.wrapping_add(1),
        1,
        NativeAuthorityProfile::WindowsSectionsV1,
        prepared.manifest_entries(),
    )
    .unwrap();
    let frame = CapabilityFrame::from_manifest(&manifest);
    let raw = (0..3)
        .map(|ordinal| prepared.duplicate_raw_capability_for_test(ordinal).unwrap())
        .collect::<Vec<_>>();
    let mask = HANDLE_FLAG_INHERIT | HANDLE_FLAG_PROTECT_FROM_CLOSE;
    assert_ne!(
        unsafe { SetHandleInformation(raw[1] as HANDLE, mask, HANDLE_FLAG_PROTECT_FROM_CLOSE,) },
        0
    );
    let baseline = live_handles_for_test();
    let mut record = frame.as_bytes().to_vec();
    for handle in &raw {
        record.extend_from_slice(&(*handle as u64).to_le_bytes());
    }
    assert!(matches!(
        adopt_capability_record(record, &frame),
        Err(SessionTransportError::MalformedRecord)
    ));
    assert_eq!(live_handles_for_test(), baseline);
    for handle in raw {
        let mut flags = 0;
        assert_eq!(
            unsafe { GetHandleInformation(handle as HANDLE, &mut flags) },
            0
        );
        assert_eq!(unsafe { GetLastError() }, ERROR_INVALID_HANDLE);
    }
}

#[test]
fn lifecycle_terminates_the_whole_job_after_the_direct_child_exits() {
    let session =
        spawn_helper("backend::windows::vnext_transport_test::outliving_descendant_helper");
    let mut transport = coordinator_transport(session);
    let bytes = transport.receive_record(4, deadline()).unwrap();
    let descendant_pid = u32::from_le_bytes(bytes.try_into().unwrap());
    let descendant = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE,
            0,
            descendant_pid,
        )
    };
    assert!(!descendant.is_null());
    for _ in 0..20_000 {
        if transport.try_poll_peer().unwrap() == PeerState::ExitedUnknown {
            transport.terminate_and_reap(deadline()).unwrap();
            for _ in 0..20_000 {
                if unsafe { WaitForSingleObject(descendant, 0) } == WAIT_OBJECT_0 {
                    assert_ne!(unsafe { CloseHandle(descendant) }, 0);
                    return;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            let _ = unsafe { CloseHandle(descendant) };
            panic!("Job descendant did not finish termination");
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    let _ = unsafe { CloseHandle(descendant) };
    panic!("direct Windows helper did not exit");
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
    transport.send_record(&[0x7d], deadline()).unwrap();
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
#[ignore = "spawned only by the backpressure Windows transport test"]
fn delayed_record_reader_helper() {
    let channel = connect_spawned_helper().unwrap();
    let mut transport = receiver_transport(channel);
    std::thread::sleep(Duration::from_millis(50));
    assert_eq!(
        transport
            .receive_record(MAX_VNEXT_RECORD_BYTES, deadline())
            .unwrap(),
        vec![0x4c; MAX_VNEXT_RECORD_BYTES]
    );
    assert_eq!(transport.receive_record(1, deadline()).unwrap(), [0x6b]);
    transport.send_record(&[0x6c], deadline()).unwrap();
}

#[test]
#[ignore = "spawned only by the post-I/O deadline test"]
fn one_record_then_stall_helper() {
    let channel = connect_spawned_helper().unwrap();
    let mut transport = receiver_transport(channel);
    transport.send_record(&[0x32], deadline()).unwrap();
    std::thread::sleep(Duration::from_secs(1));
}

#[test]
#[ignore = "spawned only by the post-I/O capability deadline test"]
fn expired_capability_receive_helper() {
    let channel = connect_spawned_helper().unwrap();
    let mut transport = receiver_transport(channel);
    let frame_bytes = transport
        .receive_record(CONTROL_FRAME_LEN, deadline())
        .unwrap();
    let (frame, _) = CapabilityFrame::decode(&frame_bytes).unwrap();
    transport.send_record(&[0x61], deadline()).unwrap();
    std::thread::sleep(Duration::from_millis(20));
    let baseline = live_handles_for_test();
    set_post_io_delay_for_test(10);
    let short = AbsoluteDeadline::after(Duration::from_millis(1)).unwrap();
    assert!(matches!(
        transport.receive_capability_record(&frame, short),
        Err(SessionTransportError::DeadlineExpired)
    ));
    set_post_io_delay_for_test(0);
    assert_eq!(live_handles_for_test(), baseline);
}

#[test]
#[ignore = "spawned only by the receiver parent-PID mismatch test"]
fn receiver_parent_pid_mismatch_helper() {
    let channel = connect_spawned_helper().unwrap();
    let parent = channel.parent_pid();
    let child = unsafe { GetCurrentProcessId() };
    let nonce = channel.vnext_nonce();
    assert!(matches!(
        ReceiverWindowsControlTransport::from_accepted(
            channel,
            receiver_evidence(parent.wrapping_add(1), child, nonce)
        ),
        Err(SessionTransportError::IdentityMismatch)
    ));
}

#[test]
#[ignore = "spawned only by the receiver child-PID mismatch test"]
fn receiver_child_pid_mismatch_helper() {
    let channel = connect_spawned_helper().unwrap();
    let parent = channel.parent_pid();
    let child = unsafe { GetCurrentProcessId() };
    let nonce = channel.vnext_nonce();
    assert!(matches!(
        ReceiverWindowsControlTransport::from_accepted(
            channel,
            receiver_evidence(parent, child.wrapping_add(1), nonce)
        ),
        Err(SessionTransportError::IdentityMismatch)
    ));
}

#[test]
#[ignore = "spawned only by the whole-Job lifecycle test"]
#[allow(clippy::zombie_processes)]
fn outliving_descendant_helper() {
    let channel = connect_spawned_helper().unwrap();
    let mut transport = receiver_transport(channel);
    let executable = std::env::current_exe().unwrap();
    // This fixture intentionally exits without waiting so the descendant is
    // the only active Job member when the coordinator invokes lifecycle cleanup.
    let descendant = Command::new(executable)
        .args([
            "--exact",
            "backend::windows::vnext_transport_test::job_descendant_helper",
            "--ignored",
            "--nocapture",
        ])
        .spawn()
        .unwrap();
    transport
        .send_record(&descendant.id().to_le_bytes(), deadline())
        .unwrap();
}

#[test]
#[ignore = "spawned only as an outliving Job descendant"]
fn job_descendant_helper() {
    std::thread::sleep(Duration::from_secs(30));
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
