use super::accepted_control::{AcceptedControlDispatcher, AcceptedControlError};
use super::*;
use crate::control::{CONTROL_HEADER_LEN, ControlError, ControlFrame, ControlState};
use crate::protocol::{
    CapabilityFrame, ManifestEntry, NativeRegionSpec, PeerAccess, TransferManifest,
};
use static_assertions::{assert_impl_all, assert_not_impl_any};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const NONCE: [u8; 32] = [0x31; 32];
const MAXIMUM: u32 = 8;
const APPLICATION_KIND_MIN: u32 = 0x8000_0000;

assert_impl_all!(AcceptedControlDispatcher<MockTransport>: Send);
assert_not_impl_any!(AcceptedControlDispatcher<MockTransport>: Sync, Clone);

#[derive(Default)]
struct MockFacts {
    incoming: VecDeque<Vec<u8>>,
    sent: Vec<Vec<u8>>,
    send_calls: usize,
    receive_calls: usize,
    poll_calls: usize,
    poison_calls: usize,
    send_error: Option<SessionTransportError>,
    receive_error: Option<SessionTransportError>,
    poll_error: Option<SessionTransportError>,
    peer: Option<PeerState>,
    return_oversized_success: bool,
    poisoned: bool,
    capability_incoming: VecDeque<MockCapabilityRecord>,
    capability_sent: Vec<(Vec<u8>, usize)>,
    capability_send_calls: usize,
    capability_receive_calls: usize,
    capability_error_on_call: Option<usize>,
    capability_deadline: Option<AbsoluteDeadline>,
}

struct MockCapabilityRecord {
    bytes: Vec<u8>,
    count: usize,
    drops: Arc<AtomicUsize>,
}

struct MockReceivedCapabilities {
    count: usize,
    drops: Arc<AtomicUsize>,
}

impl Drop for MockReceivedCapabilities {
    fn drop(&mut self) {
        self.drops.fetch_add(self.count, Ordering::SeqCst);
    }
}

#[derive(Clone, Default)]
struct MockHandle(Arc<Mutex<MockFacts>>);

struct MockTransport(MockHandle);

impl sealed::Sealed for MockTransport {}

impl AuthenticatedZeroRightsTransport for MockTransport {
    fn send_record(
        &mut self,
        bytes: &[u8],
        _deadline: AbsoluteDeadline,
    ) -> Result<(), SessionTransportError> {
        let mut facts = self.0.0.lock().unwrap();
        if facts.poisoned {
            return Err(SessionTransportError::Native);
        }
        facts.send_calls += 1;
        if let Some(error) = facts.send_error.take() {
            return Err(error);
        }
        facts.sent.push(bytes.to_vec());
        Ok(())
    }

    fn receive_record(
        &mut self,
        maximum: usize,
        _deadline: AbsoluteDeadline,
    ) -> Result<Vec<u8>, SessionTransportError> {
        let mut facts = self.0.0.lock().unwrap();
        if facts.poisoned {
            return Err(SessionTransportError::Native);
        }
        facts.receive_calls += 1;
        if let Some(error) = facts.receive_error.take() {
            return Err(error);
        }
        let bytes = facts
            .incoming
            .pop_front()
            .ok_or(SessionTransportError::PeerExited)?;
        if bytes.len() > maximum && !facts.return_oversized_success {
            return Err(SessionTransportError::RecordTooLarge);
        }
        Ok(bytes)
    }

    fn try_poll_peer(&mut self) -> Result<PeerState, SessionTransportError> {
        let mut facts = self.0.0.lock().unwrap();
        if facts.poisoned {
            return Err(SessionTransportError::Native);
        }
        facts.poll_calls += 1;
        if let Some(error) = facts.poll_error.take() {
            return Err(error);
        }
        Ok(facts.peer.unwrap_or(PeerState::Running))
    }

    fn poison(&mut self) {
        let mut facts = self.0.0.lock().unwrap();
        facts.poison_calls += 1;
        facts.poisoned = true;
    }
}

impl CoordinatorCapabilityTransport for MockTransport {
    type Capabilities<'a> = usize;

    fn send_capability_record(
        &mut self,
        frame: &CapabilityFrame,
        capabilities: Self::Capabilities<'_>,
        deadline: AbsoluteDeadline,
    ) -> Result<(), SessionTransportError> {
        let mut facts = self.0.0.lock().unwrap();
        facts.capability_send_calls += 1;
        facts.capability_deadline = Some(deadline);
        if facts.capability_error_on_call == Some(facts.capability_send_calls) {
            return Err(SessionTransportError::Native);
        }
        if capabilities != frame.capability_count() {
            return Err(SessionTransportError::MalformedRecord);
        }
        facts
            .capability_sent
            .push((frame.as_bytes().to_vec(), capabilities));
        Ok(())
    }
}

impl ReceiverCapabilityTransport for MockTransport {
    type ReceivedCapabilities = MockReceivedCapabilities;

    fn receive_capability_record(
        &mut self,
        expected: &CapabilityFrame,
        deadline: AbsoluteDeadline,
    ) -> Result<Self::ReceivedCapabilities, SessionTransportError> {
        let mut facts = self.0.0.lock().unwrap();
        facts.capability_receive_calls += 1;
        facts.capability_deadline = Some(deadline);
        if facts.capability_error_on_call == Some(facts.capability_receive_calls) {
            return Err(SessionTransportError::Native);
        }
        let record = facts
            .capability_incoming
            .pop_front()
            .ok_or(SessionTransportError::PeerExited)?;
        if record.bytes.as_slice() != expected.as_bytes()
            || record.count != expected.capability_count()
        {
            record.drops.fetch_add(record.count, Ordering::SeqCst);
            return Err(SessionTransportError::MalformedRecord);
        }
        Ok(MockReceivedCapabilities {
            count: record.count,
            drops: record.drops,
        })
    }
}

fn deadline() -> AbsoluteDeadline {
    AbsoluteDeadline::after(Duration::from_secs(1)).unwrap()
}

fn frame(kind_offset: u32, payload: &[u8]) -> ControlFrame {
    ControlFrame {
        kind: APPLICATION_KIND_MIN + kind_offset,
        payload: payload.to_vec(),
    }
}

fn dispatcher(maximum: u32) -> (AcceptedControlDispatcher<MockTransport>, MockHandle) {
    let handle = MockHandle::default();
    let dispatcher = AcceptedControlDispatcher::new(MockTransport(handle.clone()), NONCE, maximum)
        .ok()
        .unwrap();
    (dispatcher, handle)
}

fn encode(nonce: [u8; 32], maximum: u32, frame: &ControlFrame) -> Vec<u8> {
    let mut state = ControlState::new(nonce, maximum).unwrap();
    let mut bytes = vec![0; state.encoded_len(frame).unwrap()];
    state.encode_into(frame, &mut bytes).unwrap();
    bytes
}

fn capability_frame(nonce: [u8; 32], transaction: u64, count: usize) -> CapabilityFrame {
    let entries = (1..=count)
        .map(|ordinal| {
            let region = ordinal as u128;
            let native = NativeRegionSpec::new(region, [ordinal as u8; 16], 1, 1, 4096).unwrap();
            ManifestEntry::from_native(native, PeerAccess::ReadOnly)
        })
        .collect();
    let manifest = TransferManifest::new(nonce, 10, 11, transaction, entries).unwrap();
    CapabilityFrame::from_manifest(&manifest)
}

fn enqueue_capability(handle: &MockHandle, bytes: Vec<u8>, count: usize, drops: Arc<AtomicUsize>) {
    handle
        .0
        .lock()
        .unwrap()
        .capability_incoming
        .push_back(MockCapabilityRecord {
            bytes,
            count,
            drops,
        });
}

fn enqueue(handle: &MockHandle, bytes: Vec<u8>) {
    handle.0.lock().unwrap().incoming.push_back(bytes);
}

fn transfer(from: &MockHandle, to: &MockHandle) {
    let bytes = from.0.lock().unwrap().sent.remove(0);
    enqueue(to, bytes);
}

fn assert_poisoned_without_more_io(
    dispatcher: &mut AcceptedControlDispatcher<MockTransport>,
    handle: &MockHandle,
) {
    let before = {
        let facts = handle.0.lock().unwrap();
        (facts.send_calls, facts.receive_calls, facts.poll_calls)
    };
    assert_eq!(
        dispatcher.receive(deadline()),
        Err(AcceptedControlError::Control(ControlError::Poisoned))
    );
    assert_eq!(
        dispatcher.send(&frame(0, b""), deadline()),
        Err(AcceptedControlError::Control(ControlError::Poisoned))
    );
    assert_eq!(
        dispatcher.try_poll_peer(),
        Err(AcceptedControlError::Control(ControlError::Poisoned))
    );
    let facts = handle.0.lock().unwrap();
    assert!(facts.poisoned);
    assert_eq!(
        (facts.send_calls, facts.receive_calls, facts.poll_calls),
        before
    );
}

#[test]
fn empty_and_exact_maximum_records_sequence_in_both_directions() {
    let (mut a, a_handle) = dispatcher(MAXIMUM);
    let (mut b, b_handle) = dispatcher(MAXIMUM);

    a.send(&frame(0, b""), deadline()).unwrap();
    transfer(&a_handle, &b_handle);
    assert_eq!(b.receive(deadline()).unwrap(), frame(0, b""));

    b.send(&frame(1, b"12345678"), deadline()).unwrap();
    transfer(&b_handle, &a_handle);
    assert_eq!(a.receive(deadline()).unwrap(), frame(1, b"12345678"));

    a.send(&frame(2, b"a"), deadline()).unwrap();
    b.send(&frame(3, b"b"), deadline()).unwrap();
    transfer(&a_handle, &b_handle);
    transfer(&b_handle, &a_handle);
    assert_eq!(a.receive(deadline()).unwrap(), frame(3, b"b"));
    assert_eq!(b.receive(deadline()).unwrap(), frame(2, b"a"));
}

#[test]
fn local_reserved_and_oversized_frames_are_recoverable_without_io() {
    let (mut dispatcher, handle) = dispatcher(MAXIMUM);
    let reserved = ControlFrame {
        kind: APPLICATION_KIND_MIN - 1,
        payload: Vec::new(),
    };
    assert_eq!(
        dispatcher.send(&reserved, deadline()),
        Err(AcceptedControlError::Control(ControlError::ReservedKind))
    );
    assert_eq!(
        dispatcher.send(&frame(0, b"123456789"), deadline()),
        Err(AcceptedControlError::Control(ControlError::PayloadTooLarge))
    );
    assert_eq!(handle.0.lock().unwrap().send_calls, 0);
    dispatcher.send(&frame(0, b"ok"), deadline()).unwrap();
    assert_eq!(handle.0.lock().unwrap().send_calls, 1);
}

#[test]
fn capability_transaction_is_inseparable_terminal_and_blocks_application_control() {
    let native = capability_frame(NONCE, 1, 1);
    let (mut coordinator, handle) = dispatcher(MAXIMUM);
    let original_deadline = deadline();
    {
        let mut transaction = coordinator
            .begin_capability_transaction(original_deadline)
            .unwrap();
        transaction.send(&native, 1).unwrap();
    }
    let facts = handle.0.lock().unwrap();
    assert_eq!(facts.capability_send_calls, 1);
    assert_eq!(facts.capability_deadline, Some(original_deadline));
    assert_eq!(facts.send_calls, 0);
    drop(facts);
    assert_poisoned_without_more_io(&mut coordinator, &handle);

    let (mut receiver, handle) = dispatcher(MAXIMUM);
    let application = encode(NONCE, MAXIMUM, &frame(0, b"app"));
    let drops = Arc::new(AtomicUsize::new(0));
    enqueue_capability(&handle, application, 1, drops.clone());
    {
        let mut transaction = receiver.await_capability_transaction(deadline()).unwrap();
        assert_eq!(
            transaction.receive(&native).map(|_| ()),
            Err(AcceptedControlError::Transport(
                SessionTransportError::MalformedRecord
            ))
        );
    }
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_eq!(handle.0.lock().unwrap().receive_calls, 0);
    assert_poisoned_without_more_io(&mut receiver, &handle);
}

#[test]
fn received_capabilities_stay_transaction_owned_for_one_two_and_sixteen_rights() {
    for count in [1, 2, 16] {
        let native = capability_frame(NONCE, count as u64, count);
        let (mut receiver, handle) = dispatcher(MAXIMUM);
        let drops = Arc::new(AtomicUsize::new(0));
        enqueue_capability(&handle, native.as_bytes().to_vec(), count, drops.clone());
        {
            let mut transaction = receiver.await_capability_transaction(deadline()).unwrap();
            let capabilities = transaction.receive(&native).unwrap();
            assert_eq!(capabilities.count, count);
            assert_eq!(drops.load(Ordering::SeqCst), 0);
        }
        assert_eq!(drops.load(Ordering::SeqCst), count);
        assert_poisoned_without_more_io(&mut receiver, &handle);
    }
}

#[test]
fn wrong_rights_replay_substitution_and_first_operation_failure_poison_once() {
    let expected = capability_frame(NONCE, 7, 1);
    for actual_count in [0, 2, 16] {
        let (mut coordinator, handle) = dispatcher(MAXIMUM);
        {
            let mut transaction = coordinator
                .begin_capability_transaction(deadline())
                .unwrap();
            assert!(transaction.send(&expected, actual_count).is_err());
        }
        assert_eq!(handle.0.lock().unwrap().capability_send_calls, 1);
        assert_poisoned_without_more_io(&mut coordinator, &handle);
    }

    for actual_count in [0, 2, 16] {
        let (mut receiver, handle) = dispatcher(MAXIMUM);
        let drops = Arc::new(AtomicUsize::new(0));
        enqueue_capability(
            &handle,
            expected.as_bytes().to_vec(),
            actual_count,
            drops.clone(),
        );
        {
            let mut transaction = receiver.await_capability_transaction(deadline()).unwrap();
            assert!(transaction.receive(&expected).is_err());
        }
        assert_eq!(drops.load(Ordering::SeqCst), actual_count);
        assert_poisoned_without_more_io(&mut receiver, &handle);
    }

    for substituted in [
        capability_frame([0x32; 32], 7, 1),
        capability_frame(NONCE, 8, 1),
        capability_frame(NONCE, 7, 2),
    ] {
        let (mut receiver, handle) = dispatcher(MAXIMUM);
        let drops = Arc::new(AtomicUsize::new(0));
        enqueue_capability(&handle, substituted.as_bytes().to_vec(), 1, drops.clone());
        {
            let mut transaction = receiver.await_capability_transaction(deadline()).unwrap();
            assert!(transaction.receive(&expected).is_err());
        }
        assert_eq!(drops.load(Ordering::SeqCst), 1);
        assert_poisoned_without_more_io(&mut receiver, &handle);
    }

    let (mut coordinator, handle) = dispatcher(MAXIMUM);
    handle.0.lock().unwrap().capability_error_on_call = Some(1);
    {
        let mut transaction = coordinator
            .begin_capability_transaction(deadline())
            .unwrap();
        assert_eq!(
            transaction.send(&expected, 1),
            Err(AcceptedControlError::Transport(
                SessionTransportError::Native
            ))
        );
    }
    assert_eq!(handle.0.lock().unwrap().capability_send_calls, 1);
    assert_poisoned_without_more_io(&mut coordinator, &handle);
}

#[test]
fn same_guard_capability_replay_never_performs_a_second_native_operation() {
    let expected = capability_frame(NONCE, 10, 1);
    let (mut coordinator, handle) = dispatcher(MAXIMUM);
    {
        let mut transaction = coordinator
            .begin_capability_transaction(deadline())
            .unwrap();
        transaction.send(&expected, 1).unwrap();
        assert_eq!(
            transaction.send(&expected, 1),
            Err(AcceptedControlError::Control(ControlError::ReplayOrReorder))
        );
    }
    assert_eq!(handle.0.lock().unwrap().capability_send_calls, 1);
    assert_poisoned_without_more_io(&mut coordinator, &handle);

    let (mut receiver, handle) = dispatcher(MAXIMUM);
    let installed_drops = Arc::new(AtomicUsize::new(0));
    let queued_drops = Arc::new(AtomicUsize::new(0));
    enqueue_capability(
        &handle,
        expected.as_bytes().to_vec(),
        1,
        installed_drops.clone(),
    );
    enqueue_capability(
        &handle,
        expected.as_bytes().to_vec(),
        1,
        queued_drops.clone(),
    );
    {
        let mut transaction = receiver.await_capability_transaction(deadline()).unwrap();
        assert_eq!(transaction.receive(&expected).unwrap().count, 1);
        assert_eq!(
            transaction.receive(&expected).map(|_| ()),
            Err(AcceptedControlError::Control(ControlError::ReplayOrReorder))
        );
        assert_eq!(installed_drops.load(Ordering::SeqCst), 0);
    }
    let facts = handle.0.lock().unwrap();
    assert_eq!(facts.capability_receive_calls, 1);
    assert_eq!(facts.capability_incoming.len(), 1);
    drop(facts);
    assert_eq!(installed_drops.load(Ordering::SeqCst), 1);
    assert_eq!(queued_drops.load(Ordering::SeqCst), 0);
    assert_poisoned_without_more_io(&mut receiver, &handle);
}

#[test]
fn hostile_continuous_transaction_traffic_cannot_retry_or_replace_the_deadline() {
    let expected = capability_frame(NONCE, 9, 1);
    let (mut receiver, handle) = dispatcher(MAXIMUM);
    let drops = Arc::new(AtomicUsize::new(0));
    for _ in 0..64 {
        enqueue_capability(
            &handle,
            encode(NONCE, MAXIMUM, &frame(0, b"hostile")),
            1,
            drops.clone(),
        );
    }
    let original_deadline = deadline();
    {
        let mut transaction = receiver
            .await_capability_transaction(original_deadline)
            .unwrap();
        assert!(transaction.receive(&expected).is_err());
    }
    let facts = handle.0.lock().unwrap();
    assert_eq!(facts.capability_receive_calls, 1);
    assert_eq!(facts.capability_deadline, Some(original_deadline));
    assert_eq!(facts.capability_incoming.len(), 63);
    drop(facts);
    assert_eq!(drops.load(Ordering::SeqCst), 1);
    assert_poisoned_without_more_io(&mut receiver, &handle);
}

#[test]
fn post_encode_send_error_poisons_state_and_transport() {
    let (mut dispatcher, handle) = dispatcher(MAXIMUM);
    handle.0.lock().unwrap().send_error = Some(SessionTransportError::DeadlineExpired);
    assert_eq!(
        dispatcher.send(&frame(0, b"encoded"), deadline()),
        Err(AcceptedControlError::Transport(
            SessionTransportError::DeadlineExpired
        ))
    );
    assert_eq!(handle.0.lock().unwrap().poison_calls, 1);
    assert_poisoned_without_more_io(&mut dispatcher, &handle);
}

#[test]
fn hostile_control_records_poison_persistently() {
    let canonical = encode(NONCE, MAXIMUM + 1, &frame(0, b"payload"));
    let mut cases = Vec::new();
    for magic in [*b"NIPCHEL1", *b"NIPCCAP1", *b"NIPCFD\0\0"] {
        let mut bytes = canonical.clone();
        bytes[..8].copy_from_slice(&magic);
        cases.push(bytes);
    }
    let mut wrong_nonce = canonical.clone();
    wrong_nonce[32] ^= 1;
    cases.push(wrong_nonce);
    for length in 0..canonical.len() {
        cases.push(canonical[..length].to_vec());
    }
    let mut extra = canonical.clone();
    extra.push(0);
    cases.push(extra);
    let mut replay = canonical.clone();
    replay[64..72].copy_from_slice(&0_u64.to_le_bytes());
    cases.push(replay);
    let mut future = canonical.clone();
    future[64..72].copy_from_slice(&2_u64.to_le_bytes());
    cases.push(future);

    for bytes in cases {
        let (mut dispatcher, handle) = dispatcher(MAXIMUM);
        enqueue(&handle, bytes);
        assert!(dispatcher.receive(deadline()).is_err());
        assert_poisoned_without_more_io(&mut dispatcher, &handle);
    }

    let (mut replay_dispatcher, handle) = dispatcher(MAXIMUM);
    enqueue(&handle, canonical.clone());
    enqueue(&handle, canonical);
    assert_eq!(
        replay_dispatcher.receive(deadline()).unwrap(),
        frame(0, b"payload")
    );
    assert_eq!(
        replay_dispatcher.receive(deadline()),
        Err(AcceptedControlError::Control(ControlError::ReplayOrReorder))
    );
    assert_poisoned_without_more_io(&mut replay_dispatcher, &handle);

    let (mut dispatcher, handle) = dispatcher(MAXIMUM);
    enqueue(&handle, encode(NONCE, MAXIMUM + 1, &frame(0, b"123456789")));
    assert_eq!(
        dispatcher.receive(deadline()),
        Err(AcceptedControlError::Transport(
            SessionTransportError::RecordTooLarge
        ))
    );
    assert_poisoned_without_more_io(&mut dispatcher, &handle);
}

#[test]
fn ambiguous_receive_error_poisons_without_retry() {
    let (mut dispatcher, handle) = dispatcher(MAXIMUM);
    handle.0.lock().unwrap().receive_error = Some(SessionTransportError::Native);
    assert_eq!(
        dispatcher.receive(deadline()),
        Err(AcceptedControlError::Transport(
            SessionTransportError::Native
        ))
    );
    assert_eq!(handle.0.lock().unwrap().receive_calls, 1);
    assert_poisoned_without_more_io(&mut dispatcher, &handle);
}

#[test]
fn queued_valid_application_record_is_not_drained_on_construction() {
    let handle = MockHandle::default();
    enqueue(&handle, encode(NONCE, MAXIMUM, &frame(0, b"queued")));
    let mut dispatcher =
        AcceptedControlDispatcher::new(MockTransport(handle.clone()), NONCE, MAXIMUM)
            .ok()
            .unwrap();
    assert_eq!(handle.0.lock().unwrap().receive_calls, 0);
    assert_eq!(dispatcher.receive(deadline()).unwrap(), frame(0, b"queued"));
}

#[test]
fn peer_observation_never_claims_an_exit_code() {
    let (mut dispatcher, handle) = dispatcher(MAXIMUM);
    handle.0.lock().unwrap().peer = Some(PeerState::ExitedUnknown);
    assert_eq!(
        dispatcher.try_poll_peer().unwrap(),
        PeerState::ExitedUnknown
    );
}

#[test]
fn peer_poll_error_poisons_without_a_second_observation() {
    let (mut dispatcher, handle) = dispatcher(MAXIMUM);
    handle.0.lock().unwrap().poll_error = Some(SessionTransportError::Native);
    assert_eq!(
        dispatcher.try_poll_peer(),
        Err(AcceptedControlError::Transport(
            SessionTransportError::Native
        ))
    );
    assert_eq!(handle.0.lock().unwrap().poll_calls, 1);
    assert_poisoned_without_more_io(&mut dispatcher, &handle);
}

#[test]
fn canonical_record_bound_is_header_plus_negotiated_payload() {
    let (_, handle) = dispatcher(MAXIMUM);
    enqueue(&handle, vec![0; CONTROL_HEADER_LEN + MAXIMUM as usize + 1]);
    handle.0.lock().unwrap().return_oversized_success = true;
    let mut dispatcher =
        AcceptedControlDispatcher::new(MockTransport(handle.clone()), NONCE, MAXIMUM)
            .ok()
            .unwrap();
    assert_eq!(
        dispatcher.receive(deadline()),
        Err(AcceptedControlError::Transport(
            SessionTransportError::RecordTooLarge
        ))
    );
    assert_poisoned_without_more_io(&mut dispatcher, &handle);
}

#[test]
fn receive_reuses_the_single_bounded_record_allocation_for_payload() {
    let (mut dispatcher, handle) = dispatcher(MAXIMUM);
    let mut wire = encode(NONCE, MAXIMUM, &frame(0, b"payload"));
    wire.reserve_exact(19);
    let allocation = wire.as_ptr() as usize;
    let capacity = wire.capacity();
    enqueue(&handle, wire);
    let received = dispatcher.receive(deadline()).unwrap();
    assert_eq!(received, frame(0, b"payload"));
    assert_eq!(received.payload.as_ptr() as usize, allocation);
    assert_eq!(received.payload.capacity(), capacity);
}
