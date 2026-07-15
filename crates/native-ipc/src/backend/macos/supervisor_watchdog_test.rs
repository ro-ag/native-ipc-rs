use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use static_assertions::assert_not_impl_any;

use super::*;
use crate::backend::macos::supervisor::{
    ConnectionGeneration, FreshServiceNonce, SupervisorConnection,
};

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

assert_not_impl_any!(FreshSessionId: Clone, Copy);
assert_not_impl_any!(ExactBroker<FakeBroker>: Clone, Copy);
assert_not_impl_any!(TraceEstablished: Clone, Copy);
assert_not_impl_any!(ReadySessionProof: Clone, Copy);
assert_not_impl_any!(PendingReadyDelivery<FakeBroker>: Clone, Copy);
assert_not_impl_any!(ReapedBroker: Clone, Copy);
assert_not_impl_any!(RegisteredLaunch<TestLaunch>: Clone, Copy);
assert_not_impl_any!(RegisteredLaunchPermit<'static, TestLaunch, FakeBroker>: Clone, Copy);
assert_not_impl_any!(RegisteredLaunchCommitGuard<'static, FakeBroker>: Clone, Copy);
assert_not_impl_any!(PendingRegisteredSession<TestLaunch, FakeBroker>: Clone, Copy);

#[derive(Debug, Default, Eq, PartialEq)]
struct FakeState {
    activation_attempts: usize,
    attempts: usize,
    emergency_attempts: usize,
    completed: bool,
    reasons: Vec<TerminationReason>,
    emergency_reasons: Vec<Option<TerminationReason>>,
}

struct FakeBroker {
    state: Arc<Mutex<FakeState>>,
    failures_remaining: usize,
    activation_fails: bool,
}

struct TestLaunch {
    connection: ConnectionIdentity,
    deadline: Instant,
}

struct ReportDropProbe {
    broker_state: Arc<Mutex<FakeState>>,
    drops: Arc<Mutex<usize>>,
}

impl Drop for ReportDropProbe {
    fn drop(&mut self) {
        assert!(
            self.broker_state.lock().unwrap().completed,
            "report state dropped before exact broker reap"
        );
        *self.drops.lock().unwrap() += 1;
    }
}

impl RegisteredLaunchEffect for TestLaunch {
    fn connection_identity(&self) -> ConnectionIdentity {
        self.connection
    }

    fn deadline(&self) -> Instant {
        self.deadline
    }
}

// SAFETY: the fake models exact authority. Success mints a reaped proof;
// failure leaves the same modeled authority; emergency cleanup always succeeds.
unsafe impl ExactBrokerAuthority for FakeBroker {
    type Failure = &'static str;

    fn activate_after_registration(&mut self) -> Result<(), Self::Failure> {
        self.state.lock().unwrap().activation_attempts += 1;
        if self.activation_fails {
            Err("activation")
        } else {
            Ok(())
        }
    }

    fn terminate_and_reap(
        &mut self,
        reason: TerminationReason,
    ) -> Result<ReapedBroker, Self::Failure> {
        let mut state = self.state.lock().unwrap();
        state.attempts += 1;
        state.reasons.push(reason);
        if self.failures_remaining != 0 {
            self.failures_remaining -= 1;
            return Err("retry");
        }
        state.completed = true;
        // SAFETY: this branch models successful exact broker reap.
        Ok(unsafe { ReapedBroker::from_exact_reap() })
    }

    fn emergency_terminate_and_reap(&mut self, reason: Option<TerminationReason>) -> ReapedBroker {
        let mut state = self.state.lock().unwrap();
        state.emergency_attempts += 1;
        state.emergency_reasons.push(reason);
        state.completed = true;
        // SAFETY: the fake emergency path models successful exact broker reap.
        unsafe { ReapedBroker::from_exact_reap() }
    }
}

#[derive(Clone, Copy)]
enum TestSendOutcome {
    Success,
    Error,
    Panic,
}

#[derive(Default)]
struct TestSendObservation {
    calls: usize,
    handle: Option<SessionHandle>,
    connection: Option<ConnectionIdentity>,
    deadline: Option<Instant>,
}

struct TestReadySend {
    outcome: TestSendOutcome,
    observation: Arc<Mutex<TestSendObservation>>,
}

fn test_ready_send(outcome: TestSendOutcome) -> (TestReadySend, Arc<Mutex<TestSendObservation>>) {
    let observation = Arc::new(Mutex::new(TestSendObservation::default()));
    (
        TestReadySend {
            outcome,
            observation: Arc::clone(&observation),
        },
        observation,
    )
}

// SAFETY: this fixed test sender performs no allocation or callback in
// send_once. It records one immediate invocation and returns its preselected
// outcome without waiting or retrying.
unsafe impl NonblockingReadySend for TestReadySend {
    type Error = &'static str;

    fn cleanup_reason(_error: &Self::Error) -> TerminationReason {
        TerminationReason::SpawnResultUndeliverable
    }

    fn send_once(
        self,
        handle: SessionHandle,
        connection: ConnectionIdentity,
        deadline: Instant,
    ) -> Result<(), Self::Error> {
        let mut observation = self
            .observation
            .try_lock()
            .expect("single-threaded test observation must never block");
        observation.calls += 1;
        observation.handle = Some(handle);
        observation.connection = Some(connection);
        observation.deadline = Some(deadline);
        drop(observation);
        match self.outcome {
            TestSendOutcome::Success => Ok(()),
            TestSendOutcome::Error => Err("send"),
            TestSendOutcome::Panic => panic!("injected fixed send panic"),
        }
    }
}

fn unique_value() -> u64 {
    NEXT_ID.fetch_add(1, Ordering::Relaxed)
}

fn connection() -> ConnectionIdentity {
    let value = unique_value().checked_add(100).unwrap();
    let mut nonce = [0x55; 32];
    nonce[..8].copy_from_slice(&value.to_le_bytes());
    // SAFETY: the monotonic test value is unique and nonzero.
    let generation = unsafe { ConnectionGeneration::from_unique_service_value(value).unwrap() };
    // SAFETY: each test connection receives a distinct modeled CSPRNG nonce.
    let nonce = unsafe { FreshServiceNonce::from_fresh_random(nonce).unwrap() };
    SupervisorConnection::new(generation, nonce).connection_identity()
}

fn session() -> FreshSessionId {
    let value = unique_value();
    let mut bytes = [0x66; 32];
    bytes[..8].copy_from_slice(&value.to_le_bytes());
    // SAFETY: the monotonic test value makes this modeled session ID unique.
    unsafe { FreshSessionId::from_fresh_random(bytes).unwrap() }
}

fn broker(failures_remaining: usize) -> (ExactBroker<FakeBroker>, Arc<Mutex<FakeState>>) {
    let state = Arc::new(Mutex::new(FakeState::default()));
    let authority = FakeBroker {
        state: Arc::clone(&state),
        failures_remaining,
        activation_fails: false,
    };
    // SAFETY: tests model one exact unreaped broker child owner.
    let broker = unsafe { ExactBroker::from_unreaped_direct_child(authority) };
    (broker, state)
}

trait WatchdogTableTestExt<Authority: ExactBrokerAuthority> {
    fn register_test<Launch: RegisteredLaunchEffect>(
        &mut self,
        session: FreshSessionId,
        launch: Launch,
        broker: ExactBroker<Authority>,
    ) -> Result<RegisteredSession<Launch>, WatchdogStateError>;

    fn register_armed_test<Launch: RegisteredLaunchEffect>(
        &mut self,
        session: FreshSessionId,
        launch: Launch,
        broker: ExactBroker<Authority>,
    ) -> Result<PendingRegisteredSession<Launch, Authority>, WatchdogStateError>;
}

impl<Authority: ExactBrokerAuthority> WatchdogTableTestExt<Authority> for WatchdogTable<Authority> {
    fn register_test<Launch: RegisteredLaunchEffect>(
        &mut self,
        session: FreshSessionId,
        launch: Launch,
        broker: ExactBroker<Authority>,
    ) -> Result<RegisteredSession<Launch>, WatchdogStateError> {
        // SAFETY: every test call models one atomic spawn result and supplies
        // its paired launch and exact broker in the same expression.
        let spawned =
            unsafe { AtomicallySpawnedBroker::from_test_atomic_spawn(session, launch, broker) };
        self.register(spawned)
    }

    fn register_armed_test<Launch: RegisteredLaunchEffect>(
        &mut self,
        session: FreshSessionId,
        launch: Launch,
        broker: ExactBroker<Authority>,
    ) -> Result<PendingRegisteredSession<Launch, Authority>, WatchdogStateError> {
        // SAFETY: the test call models one atomic spawn result and supplies its
        // paired launch and exact broker in the same expression.
        let spawned =
            unsafe { AtomicallySpawnedBroker::from_test_atomic_spawn(session, launch, broker) };
        self.register_armed(spawned)
    }
}

fn future_deadline() -> Instant {
    Instant::now() + Duration::from_secs(60)
}

fn near_future_deadline() -> Instant {
    Instant::now() + Duration::from_secs(1)
}

fn wait_past(deadline: Instant) {
    std::thread::sleep(
        deadline
            .saturating_duration_since(Instant::now())
            .saturating_add(Duration::from_millis(1)),
    );
    assert!(Instant::now() >= deadline);
}

fn launch(connection: ConnectionIdentity, deadline: Instant) -> TestLaunch {
    TestLaunch {
        connection,
        deadline,
    }
}

fn trace_proof(handle: SessionHandle, connection: ConnectionIdentity) -> TraceEstablished {
    // SAFETY: tests model the broker consuming both trusted-launcher stops.
    unsafe { TraceEstablished::from_broker_handshake(handle, connection) }
}

#[test]
fn unexpected_stop_is_terminal_and_success_tombstones_the_session() {
    let owner = connection();
    let mut table = WatchdogTable::new();
    let (broker, state) = broker(0);
    let handle = table
        .register_test(session(), launch(owner, future_deadline()), broker)
        .unwrap()
        .handle();
    let _ready = table.mark_traced(trace_proof(handle, owner)).unwrap();
    assert_eq!(table.terminate_for_unexpected_stop(handle).unwrap(), Ok(()));
    assert_eq!(
        state.lock().unwrap().reasons,
        vec![TerminationReason::UnexpectedBrokerStop]
    );
    assert_eq!(state.lock().unwrap().emergency_attempts, 0);
    assert!(!table.contains_live(handle));
    assert!(table.contains_tombstone(handle));
    assert_eq!(
        table.terminate_for_unexpected_stop(handle),
        Err(WatchdogStateError::UnknownSession)
    );
}

#[test]
fn pending_launch_obligation_does_not_block_unrelated_session_cleanup() {
    let first_owner = connection();
    let second_owner = connection();
    let mut table = WatchdogTable::new();
    let (first_broker, first_state) = broker(0);
    let first = table
        .register_armed_test(
            session(),
            launch(first_owner, future_deadline()),
            first_broker,
        )
        .unwrap();
    let first_handle = first.handle();
    let (second_broker, second_state) = broker(0);
    let second_handle = table
        .register_test(
            session(),
            launch(second_owner, future_deadline()),
            second_broker,
        )
        .unwrap()
        .handle();

    assert_eq!(
        table.terminate_for_unexpected_stop(second_handle),
        Ok(Ok(()))
    );
    assert_eq!(second_state.lock().unwrap().attempts, 1);
    assert_eq!(first_state.lock().unwrap().attempts, 0);
    assert_eq!(first_state.lock().unwrap().emergency_attempts, 0);
    assert!(table.contains_live(first_handle));

    drop(first);
    assert_eq!(first_state.lock().unwrap().emergency_attempts, 1);
    assert_eq!(
        table.terminate_for_client_request(first_handle, first_owner),
        Err(WatchdogStateError::UnknownSession)
    );
}

#[test]
fn table_cleanup_and_drop_cannot_double_clean_retained_session_obligation() {
    let owner = connection();
    let mut table = WatchdogTable::new();
    let (broker, state) = broker(0);
    let pending = table
        .register_armed_test(session(), launch(owner, future_deadline()), broker)
        .unwrap();
    let handle = pending.handle();
    assert_eq!(
        table.terminate_for_client_request(handle, owner),
        Ok(Ok(()))
    );
    assert_eq!(state.lock().unwrap().attempts, 1);
    drop(pending);
    assert_eq!(state.lock().unwrap().attempts, 1);
    assert_eq!(state.lock().unwrap().emergency_attempts, 0);
}

#[test]
fn table_drop_exactly_cleans_even_with_retained_session_obligation() {
    let owner = connection();
    let mut table = WatchdogTable::new();
    let (broker, state) = broker(0);
    let pending = table
        .register_armed_test(session(), launch(owner, future_deadline()), broker)
        .unwrap();
    drop(table);
    assert_eq!(state.lock().unwrap().emergency_attempts, 1);
    drop(pending);
    assert_eq!(state.lock().unwrap().emergency_attempts, 1);
}

#[test]
fn active_launch_permit_does_not_block_table_cleanup() {
    let owner = connection();
    let mut table = WatchdogTable::new();
    let (broker, state) = broker(0);
    let pending = table
        .register_armed_test(session(), launch(owner, future_deadline()), broker)
        .unwrap();
    let permit = pending.launch_permit().unwrap();

    drop(table);
    assert_eq!(state.lock().unwrap().emergency_attempts, 1);
    assert_eq!(
        permit.commit_guard().err(),
        Some(WatchdogStateError::UnknownSession)
    );
    drop(permit);
    drop(pending);
    assert_eq!(state.lock().unwrap().emergency_attempts, 1);
}

#[test]
fn expired_launch_permit_exactly_cleans_before_returning_error() {
    let owner = connection();
    let mut table = WatchdogTable::new();
    let (broker, state) = broker(0);
    let deadline = near_future_deadline();
    let pending = table
        .register_armed_test(session(), launch(owner, deadline), broker)
        .unwrap();
    let handle = pending.handle();
    wait_past(deadline);

    assert!(matches!(
        pending.launch_permit(),
        Err(WatchdogStateError::DeadlineExpired)
    ));
    let locked = state.lock().unwrap();
    assert_eq!(locked.emergency_attempts, 1);
    assert_eq!(
        locked.emergency_reasons,
        vec![Some(TerminationReason::DeadlineExpired)]
    );
    drop(locked);
    assert!(table.contains_tombstone(handle));
    drop(pending);
    assert_eq!(state.lock().unwrap().emergency_attempts, 1);
}

#[test]
fn registered_report_expiry_preserves_deadline_reason_and_reaps_before_drop() {
    let owner = connection();
    let mut table = WatchdogTable::new();
    let (broker, state) = broker(0);
    let drops = Arc::new(Mutex::new(0));
    let deadline = Instant::now() + Duration::from_millis(20);
    let report = ReportDropProbe {
        broker_state: Arc::clone(&state),
        drops: Arc::clone(&drops),
    };
    // SAFETY: this test atomically pairs the modeled exact broker, launch,
    // session, and report receipt in one construction.
    let spawned = unsafe {
        AtomicallySpawnedBroker::from_test_atomic_spawn_with_report(
            session(),
            launch(owner, deadline),
            broker,
            report,
        )
    };
    let mut pending = table.register_armed(spawned).unwrap();
    wait_past(deadline);

    assert!(matches!(
        pending.report_mut(),
        Err(WatchdogStateError::DeadlineExpired)
    ));
    drop(pending);

    let state = state.lock().unwrap();
    assert_eq!(state.emergency_attempts, 1);
    assert_eq!(
        state.emergency_reasons,
        vec![Some(TerminationReason::DeadlineExpired)]
    );
    drop(state);
    assert_eq!(*drops.lock().unwrap(), 1);
}

#[test]
fn armed_obligation_emergency_cleanup_preserves_first_terminal_reason() {
    let owner = connection();
    let mut table = WatchdogTable::new();
    let (broker, state) = broker(1);
    let pending = table
        .register_armed_test(session(), launch(owner, future_deadline()), broker)
        .unwrap();
    let handle = pending.handle();

    assert_eq!(
        table.terminate_for_client_request(handle, owner),
        Ok(Err("retry"))
    );
    drop(pending);
    let state = state.lock().unwrap();
    assert_eq!(state.reasons, vec![TerminationReason::ClientRequested]);
    assert_eq!(state.emergency_attempts, 1);
    assert_eq!(
        state.emergency_reasons,
        vec![Some(TerminationReason::ClientRequested)]
    );
}

#[test]
fn undelivered_ready_proof_exactly_cleans_or_retains_first_reason() {
    for failures in [0, 1] {
        let owner = connection();
        let mut table = WatchdogTable::new();
        let (broker, state) = broker(failures);
        let handle = table
            .register_test(session(), launch(owner, future_deadline()), broker)
            .unwrap()
            .handle();
        let ready = table.mark_traced(trace_proof(handle, owner)).unwrap();
        let result = table.terminate_undelivered_ready(ready).unwrap();
        if failures == 0 {
            assert_eq!(result, Ok(()));
            assert!(!table.contains_live(handle));
            assert!(table.contains_tombstone(handle));
        } else {
            assert_eq!(result, Err("retry"));
            assert!(table.contains_live(handle));
            assert_eq!(
                table.terminate_for_protocol_violation(handle).unwrap(),
                Ok(())
            );
        }
        let state = state.lock().unwrap();
        assert!(
            state
                .reasons
                .iter()
                .all(|reason| *reason == TerminationReason::SpawnResultUndeliverable)
        );
        assert_eq!(state.emergency_attempts, 0);
    }
}

#[test]
fn ready_delivery_success_disarms_and_keeps_the_exact_session_live() {
    let owner = connection();
    let mut table = WatchdogTable::new();
    let (broker, state) = broker(0);
    let handle = table
        .register_test(session(), launch(owner, future_deadline()), broker)
        .unwrap()
        .handle();
    let delivery = table
        .mark_traced_for_delivery(trace_proof(handle, owner))
        .unwrap();
    let (send, observation) = test_ready_send(TestSendOutcome::Success);
    assert_eq!(delivery.deliver(send), Ok(Ok(())));
    let observation = observation.lock().unwrap();
    assert_eq!(observation.calls, 1);
    assert_eq!(observation.handle, Some(handle));
    assert_eq!(observation.connection, Some(owner));
    assert!(
        observation
            .deadline
            .is_some_and(|value| value > Instant::now())
    );
    drop(observation);
    assert!(table.contains_live(handle));
    assert!(!table.contains_tombstone(handle));
    assert_eq!(state.lock().unwrap().attempts, 0);
    assert_eq!(
        table.terminate_for_client_request(handle, owner).unwrap(),
        Ok(())
    );
}

#[test]
fn ready_delivery_drop_and_send_error_clean_only_the_bound_session() {
    for drop_without_send in [false, true] {
        let owner = connection();
        let mut table = WatchdogTable::new();
        let (bound_broker, bound_state) = broker(0);
        let (other_broker, other_state) = broker(0);
        let bound = table
            .register_test(session(), launch(owner, future_deadline()), bound_broker)
            .unwrap()
            .handle();
        let other = table
            .register_test(session(), launch(owner, future_deadline()), other_broker)
            .unwrap()
            .handle();
        let delivery = table
            .mark_traced_for_delivery(trace_proof(bound, owner))
            .unwrap();
        if drop_without_send {
            drop(delivery);
        } else {
            let (send, observation) = test_ready_send(TestSendOutcome::Error);
            assert_eq!(delivery.deliver(send), Ok(Err("send")));
            assert_eq!(observation.lock().unwrap().calls, 1);
        }
        assert!(!table.contains_live(bound));
        assert!(table.contains_tombstone(bound));
        assert!(table.contains_live(other));
        assert_eq!(bound_state.lock().unwrap().attempts, 0);
        assert_eq!(bound_state.lock().unwrap().emergency_attempts, 1);
        assert_eq!(other_state.lock().unwrap().attempts, 0);
        assert_eq!(
            table.terminate_for_client_request(other, owner).unwrap(),
            Ok(())
        );
    }
}

#[test]
fn ready_delivery_panic_and_drop_use_exact_emergency_cleanup() {
    for panic_in_send in [false, true] {
        let owner = connection();
        let mut table = WatchdogTable::new();
        let (broker, state) = broker(1);
        let handle = table
            .register_test(session(), launch(owner, future_deadline()), broker)
            .unwrap()
            .handle();
        let delivery = table
            .mark_traced_for_delivery(trace_proof(handle, owner))
            .unwrap();
        if panic_in_send {
            let (send, observation) = test_ready_send(TestSendOutcome::Panic);
            let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = delivery.deliver(send);
            }));
            assert!(unwind.is_err());
            assert_eq!(observation.lock().unwrap().calls, 1);
        } else {
            drop(delivery);
        }
        assert!(!table.contains_live(handle));
        assert!(table.contains_tombstone(handle));
        let state = state.lock().unwrap();
        assert_eq!(state.attempts, 0);
        assert_eq!(state.emergency_attempts, 1);
        assert!(state.completed);
    }
}

#[test]
fn ready_delivery_rechecks_deadline_before_invoking_send() {
    let owner = connection();
    let mut table = WatchdogTable::new();
    let (broker, state) = broker(0);
    let deadline = future_deadline();
    let handle = table
        .register_test(session(), launch(owner, deadline), broker)
        .unwrap()
        .handle();
    let delivery = table
        .mark_traced_for_delivery(trace_proof(handle, owner))
        .unwrap();
    let (send, observation) = test_ready_send(TestSendOutcome::Success);
    assert_eq!(
        delivery.deliver_at(deadline, send),
        Err(WatchdogStateError::DeadlineExpired)
    );
    assert_eq!(observation.lock().unwrap().calls, 0);
    assert!(!table.contains_live(handle));
    assert!(table.contains_tombstone(handle));
    assert_eq!(
        state.lock().unwrap().emergency_reasons,
        vec![Some(TerminationReason::DeadlineExpired)]
    );
}

#[test]
fn expired_trace_transition_mints_no_ready_and_exactly_cleans_or_retains() {
    for failures in [0, 1] {
        let owner = connection();
        let mut table = WatchdogTable::new();
        let (broker, state) = broker(failures);
        let deadline = near_future_deadline();
        let handle = table
            .register_test(session(), launch(owner, deadline), broker)
            .unwrap()
            .handle();
        wait_past(deadline);
        assert!(matches!(
            table.mark_traced(trace_proof(handle, owner)),
            Err(WatchdogStateError::DeadlineExpired)
        ));
        if failures == 0 {
            assert!(!table.contains_live(handle));
            assert!(table.contains_tombstone(handle));
        } else {
            assert!(table.contains_live(handle));
            assert_eq!(
                table.terminate_for_protocol_violation(handle).unwrap(),
                Ok(())
            );
        }
        let state = state.lock().unwrap();
        assert!(
            state
                .reasons
                .iter()
                .all(|reason| *reason == TerminationReason::DeadlineExpired)
        );
    }
}

#[test]
fn failed_cleanup_retains_exact_authority_and_all_terminal_causes_retry() {
    let owner = connection();
    let mut table = WatchdogTable::new();
    let (broker, state) = broker(1);
    let deadline = near_future_deadline();
    let handle = table
        .register_test(session(), launch(owner, deadline), broker)
        .unwrap()
        .handle();
    wait_past(deadline);
    assert_eq!(table.terminate_for_deadline(handle).unwrap(), Err("retry"));
    assert!(table.contains_live(handle));
    assert_eq!(
        table.terminate_for_protocol_violation(handle).unwrap(),
        Ok(())
    );
    let state = state.lock().unwrap();
    assert_eq!(state.attempts, 2);
    assert_eq!(
        state.reasons,
        vec![
            TerminationReason::DeadlineExpired,
            TerminationReason::DeadlineExpired
        ]
    );
    assert_eq!(state.emergency_attempts, 0);
}

#[test]
fn deadline_cleanup_cannot_begin_before_registered_deadline() {
    let owner = connection();
    let mut table = WatchdogTable::new();
    let (broker, state) = broker(0);
    let deadline = future_deadline();
    let handle = table
        .register_test(session(), launch(owner, deadline), broker)
        .unwrap()
        .handle();
    assert_eq!(
        table.terminate_for_deadline(handle),
        Err(WatchdogStateError::InvalidTransition)
    );
    assert_eq!(state.lock().unwrap().attempts, 0);
    assert_eq!(
        table.terminate_for_client_request(handle, owner).unwrap(),
        Ok(())
    );
}

#[test]
fn wrong_connection_never_receives_or_invokes_authority() {
    let owner = connection();
    let stranger = connection();
    let mut table = WatchdogTable::new();
    let (broker, state) = broker(0);
    let handle = table
        .register_test(session(), launch(owner, future_deadline()), broker)
        .unwrap()
        .handle();
    assert_eq!(
        table.terminate_for_client_request(handle, stranger),
        Err(WatchdogStateError::WrongConnection)
    );
    assert_eq!(state.lock().unwrap().attempts, 0);
    assert_eq!(
        table.terminate_for_client_request(handle, owner).unwrap(),
        Ok(())
    );
}

#[test]
fn trace_transition_requires_typed_proof_and_is_single_use() {
    let owner = connection();
    let stranger = connection();
    let mut table = WatchdogTable::new();
    let (broker, _state) = broker(0);
    let handle = table
        .register_test(session(), launch(owner, future_deadline()), broker)
        .unwrap()
        .handle();
    assert!(matches!(
        table.mark_traced(trace_proof(handle, stranger)),
        Err(WatchdogStateError::WrongConnection)
    ));
    let ready = table.mark_traced(trace_proof(handle, owner)).unwrap();
    assert_eq!(ready.handle(), handle);
    assert_eq!(ready.connection(), owner);
    assert!(matches!(
        table.mark_traced(trace_proof(handle, owner)),
        Err(WatchdogStateError::InvalidTransition)
    ));
    assert_eq!(
        table
            .terminate_for_client_disconnect(handle, owner)
            .unwrap(),
        Ok(())
    );
}

#[test]
fn trace_proof_cannot_be_substituted_between_sessions() {
    let owner = connection();
    let mut table = WatchdogTable::new();
    let (first, _first_state) = broker(0);
    let (second, _second_state) = broker(0);
    let first_handle = table
        .register_test(session(), launch(owner, future_deadline()), first)
        .unwrap()
        .handle();
    let second_handle = table
        .register_test(session(), launch(owner, future_deadline()), second)
        .unwrap()
        .handle();

    let first_ready = table.mark_traced(trace_proof(first_handle, owner)).unwrap();
    assert_eq!(
        table.terminate_undelivered_ready(first_ready).unwrap(),
        Ok(())
    );
    assert!(!table.contains_live(first_handle));
    assert!(table.contains_live(second_handle));
    // Cleaning proof A cannot transition or invoke session B. Session B
    // remains Starting and therefore still accepts only its own bound proof.
    let _second_ready = table
        .mark_traced(trace_proof(second_handle, owner))
        .unwrap();
}

#[test]
fn registration_failure_emergency_cleans_the_unstored_authority() {
    let owner = connection();
    let mut table = WatchdogTable::new();
    for _ in 0..MAX_LIVE_SESSIONS {
        let (broker, _state) = broker(0);
        table
            .register_test(session(), launch(owner, future_deadline()), broker)
            .unwrap();
    }
    let (rejected, rejected_state) = broker(0);
    assert!(matches!(
        table.register_test(session(), launch(owner, future_deadline()), rejected),
        Err(WatchdogStateError::CapacityExceeded)
    ));
    let rejected_state = rejected_state.lock().unwrap();
    assert!(rejected_state.completed);
    assert_eq!(rejected_state.emergency_attempts, 1);
}

#[test]
fn broker_activation_occurs_after_registration_and_failure_exactly_cleans() {
    let owner = connection();
    let mut table = WatchdogTable::new();
    let state = Arc::new(Mutex::new(FakeState::default()));
    let authority = FakeBroker {
        state: Arc::clone(&state),
        failures_remaining: 0,
        activation_fails: true,
    };
    // SAFETY: the fake models one exact dormant unreaped broker child.
    let broker = unsafe { ExactBroker::from_unreaped_direct_child(authority) };
    let fresh = session();
    let handle = fresh.handle();
    assert!(matches!(
        table.register_test(fresh, launch(owner, future_deadline()), broker),
        Err(WatchdogStateError::BrokerActivationFailed)
    ));
    let state = state.lock().unwrap();
    assert_eq!(state.activation_attempts, 1);
    assert_eq!(state.emergency_attempts, 1);
    assert_eq!(
        state.emergency_reasons,
        vec![Some(TerminationReason::LaunchAbandoned)]
    );
    drop(state);
    assert!(table.contains_tombstone(handle));
}

#[test]
fn expired_registration_exactly_cleans_without_releasing_broker_gate() {
    let owner = connection();
    let mut table = WatchdogTable::new();
    let (broker, state) = broker(0);
    assert!(matches!(
        table.register_test(session(), launch(owner, Instant::now()), broker),
        Err(WatchdogStateError::DeadlineExpired)
    ));
    let state = state.lock().unwrap();
    assert_eq!(state.activation_attempts, 0);
    assert_eq!(state.emergency_attempts, 1);
    assert_eq!(
        state.emergency_reasons,
        vec![Some(TerminationReason::DeadlineExpired)]
    );
}

#[test]
fn dropping_live_table_emergency_cleans_every_exact_broker() {
    let owner = connection();
    let mut table = WatchdogTable::new();
    let (first, first_state) = broker(0);
    let (second, second_state) = broker(0);
    table
        .register_test(session(), launch(owner, future_deadline()), first)
        .unwrap();
    table
        .register_test(session(), launch(owner, future_deadline()), second)
        .unwrap();
    drop(table);
    for state in [first_state, second_state] {
        let state = state.lock().unwrap();
        assert!(state.completed);
        assert_eq!(state.emergency_attempts, 1);
    }
}

#[test]
fn zero_session_identifier_is_rejected() {
    // SAFETY: this test intentionally supplies a rejected freshness value.
    assert_eq!(
        unsafe { FreshSessionId::from_fresh_random([0; 32]) },
        Err(WatchdogStateError::UnknownSession)
    );
}
