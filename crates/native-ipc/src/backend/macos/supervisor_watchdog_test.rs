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
assert_not_impl_any!(ReapedBroker: Clone, Copy);
assert_not_impl_any!(RegisteredLaunch<TestLaunch>: Clone, Copy);

#[derive(Debug, Default, Eq, PartialEq)]
struct FakeState {
    attempts: usize,
    emergency_attempts: usize,
    completed: bool,
    reasons: Vec<TerminationReason>,
}

struct FakeBroker {
    state: Arc<Mutex<FakeState>>,
    failures_remaining: usize,
}

struct TestLaunch {
    connection: ConnectionIdentity,
    deadline: Instant,
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

    fn emergency_terminate_and_reap(&mut self) -> ReapedBroker {
        let mut state = self.state.lock().unwrap();
        state.emergency_attempts += 1;
        state.completed = true;
        // SAFETY: the fake emergency path models successful exact broker reap.
        unsafe { ReapedBroker::from_exact_reap() }
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
    };
    // SAFETY: tests model one exact unreaped broker child owner.
    let broker = unsafe { ExactBroker::from_unreaped_direct_child(authority) };
    (broker, state)
}

fn future_deadline() -> Instant {
    Instant::now() + Duration::from_secs(60)
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
        .register(session(), launch(owner, future_deadline()), broker)
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
fn undelivered_ready_proof_exactly_cleans_or_retains_first_reason() {
    for failures in [0, 1] {
        let owner = connection();
        let mut table = WatchdogTable::new();
        let (broker, state) = broker(failures);
        let handle = table
            .register(session(), launch(owner, future_deadline()), broker)
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
fn expired_trace_transition_mints_no_ready_and_exactly_cleans_or_retains() {
    for failures in [0, 1] {
        let owner = connection();
        let mut table = WatchdogTable::new();
        let (broker, state) = broker(failures);
        let handle = table
            .register(
                session(),
                launch(owner, Instant::now() - Duration::from_secs(1)),
                broker,
            )
            .unwrap()
            .handle();
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
    let deadline = Instant::now() - Duration::from_secs(1);
    let handle = table
        .register(session(), launch(owner, deadline), broker)
        .unwrap()
        .handle();
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
        .register(session(), launch(owner, deadline), broker)
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
        .register(session(), launch(owner, future_deadline()), broker)
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
        .register(session(), launch(owner, future_deadline()), broker)
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
        .register(session(), launch(owner, future_deadline()), first)
        .unwrap()
        .handle();
    let second_handle = table
        .register(session(), launch(owner, future_deadline()), second)
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
            .register(session(), launch(owner, future_deadline()), broker)
            .unwrap();
    }
    let (rejected, rejected_state) = broker(0);
    assert!(matches!(
        table.register(session(), launch(owner, future_deadline()), rejected),
        Err(WatchdogStateError::CapacityExceeded)
    ));
    let rejected_state = rejected_state.lock().unwrap();
    assert!(rejected_state.completed);
    assert_eq!(rejected_state.emergency_attempts, 1);
}

#[test]
fn dropping_live_table_emergency_cleans_every_exact_broker() {
    let owner = connection();
    let mut table = WatchdogTable::new();
    let (first, first_state) = broker(0);
    let (second, second_state) = broker(0);
    table
        .register(session(), launch(owner, future_deadline()), first)
        .unwrap();
    table
        .register(session(), launch(owner, future_deadline()), second)
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
