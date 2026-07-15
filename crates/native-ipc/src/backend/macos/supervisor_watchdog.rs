//! Opaque-session watchdog state independent of numeric process identifiers.

use std::collections::{HashMap, HashSet};
use std::time::Instant;

use super::supervisor::{ConnectionIdentity, ValidatedSpawn};

const MAX_LIVE_SESSIONS: usize = 64;
const MAX_SESSIONS_PER_SERVICE_GENERATION: usize = 4096;

/// Failure while changing watchdog-owned exact-broker lifecycle state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WatchdogStateError {
    /// The service-generation session budget is exhausted.
    CapacityExceeded,
    /// The opaque session is unknown or was already tombstoned.
    UnknownSession,
    /// Another authenticated client connection owns the session.
    WrongConnection,
    /// The requested transition is not valid from the current state.
    InvalidTransition,
    /// The registered launch authority expired before readiness commitment.
    DeadlineExpired,
}

/// Fresh service-generated session identifier, consumed on registration.
#[derive(Debug, Eq, PartialEq)]
pub(super) struct FreshSessionId([u8; 32]);

impl FreshSessionId {
    /// # Safety
    ///
    /// `value` must come from the OS CSPRNG and must never have been used by
    /// this service generation.
    pub(super) unsafe fn from_fresh_random(value: [u8; 32]) -> Result<Self, WatchdogStateError> {
        if value == [0; 32] {
            Err(WatchdogStateError::UnknownSession)
        } else {
            Ok(Self(value))
        }
    }
}

/// Opaque client-visible handle with no PID, task port, or signal authority.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) struct SessionHandle([u8; 32]);

impl SessionHandle {
    pub(super) const fn bytes(self) -> [u8; 32] {
        self.0
    }
}

/// Linear launch authority issued only after watchdog registration succeeds.
pub(super) struct RegisteredLaunch<Launch> {
    handle: SessionHandle,
    connection: ConnectionIdentity,
    deadline: Instant,
    launch: Launch,
}

impl<Launch> RegisteredLaunch<Launch> {
    pub(super) const fn handle(&self) -> SessionHandle {
        self.handle
    }

    pub(super) const fn connection(&self) -> ConnectionIdentity {
        self.connection
    }

    pub(super) const fn deadline(&self) -> Instant {
        self.deadline
    }

    pub(super) fn into_parts(self) -> (SessionHandle, ConnectionIdentity, Instant, Launch) {
        (self.handle, self.connection, self.deadline, self.launch)
    }
}

/// Registration result separating the copyable client handle from launch authority.
pub(super) struct RegisteredSession<Launch> {
    handle: SessionHandle,
    launch: RegisteredLaunch<Launch>,
}

impl<Launch> RegisteredSession<Launch> {
    pub(super) const fn handle(&self) -> SessionHandle {
        self.handle
    }

    pub(super) fn into_launch(self) -> RegisteredLaunch<Launch> {
        self.launch
    }
}

/// Effect data consumed at the same transition that registers exact cleanup.
pub(super) trait RegisteredLaunchEffect {
    fn connection_identity(&self) -> ConnectionIdentity;
    fn deadline(&self) -> Instant;
}

impl RegisteredLaunchEffect for ValidatedSpawn {
    fn connection_identity(&self) -> ConnectionIdentity {
        self.connection_identity()
    }

    fn deadline(&self) -> Instant {
        self.deadline()
    }
}

/// Linear service-local owner for one exact unreaped broker child.
pub(super) struct ExactBroker<Authority: ExactBrokerAuthority> {
    authority: Authority,
    armed: bool,
}

impl<Authority: ExactBrokerAuthority> ExactBroker<Authority> {
    /// # Safety
    ///
    /// `authority` must retain the exact unreaped direct-child relationship
    /// and be usable only by the watchdog's serialized waiter domain.
    pub(super) const unsafe fn from_unreaped_direct_child(authority: Authority) -> Self {
        Self {
            authority,
            armed: true,
        }
    }

    fn mark_reaped(&mut self, _proof: ReapedBroker) {
        self.armed = false;
    }
}

impl<Authority: ExactBrokerAuthority> Drop for ExactBroker<Authority> {
    fn drop(&mut self) {
        if self.armed {
            let proof = self.authority.emergency_terminate_and_reap();
            self.mark_reaped(proof);
        }
    }
}

/// Exact cleanup behavior required of a platform broker authority owner.
///
/// # Safety
///
/// Implementations must return `Ok` only after the exact broker is reaped.
/// An `Err` must leave the same exact unreaped authority retained for retry.
/// Emergency cleanup must not return until exact reap completes; if that is
/// impossible it must terminate the watchdog process rather than abandon the
/// live authority.
pub(super) unsafe trait ExactBrokerAuthority {
    type Failure;

    fn terminate_and_reap(
        &mut self,
        reason: TerminationReason,
    ) -> Result<ReapedBroker, Self::Failure>;

    fn emergency_terminate_and_reap(&mut self) -> ReapedBroker;
}

/// Proof that the exact broker child reached the reaped terminal state.
pub(super) struct ReapedBroker(());

impl ReapedBroker {
    /// # Safety
    ///
    /// The exact broker owned by the calling authority must already be reaped.
    pub(super) const unsafe fn from_exact_reap() -> Self {
        Self(())
    }
}

/// Proof that the broker consumed the trace proof stop and exec trap.
pub(super) struct TraceEstablished {
    handle: SessionHandle,
    connection: ConnectionIdentity,
}

/// Linear proof that one registered session completed both trusted-launcher
/// stops and may become the input to a future authenticated Ready reply.
#[must_use = "a ready proof must be delivered or exact-cleaned"]
pub(super) struct ReadySessionProof {
    handle: SessionHandle,
    connection: ConnectionIdentity,
}

impl ReadySessionProof {
    pub(super) const fn handle(&self) -> SessionHandle {
        self.handle
    }

    pub(super) const fn connection(&self) -> ConnectionIdentity {
        self.connection
    }
}

impl TraceEstablished {
    /// # Safety
    ///
    /// The sole broker waiter must have established tracing and consumed both
    /// trusted-launcher stops for `handle` under `connection`.
    pub(super) const unsafe fn from_broker_handshake(
        handle: SessionHandle,
        connection: ConnectionIdentity,
    ) -> Self {
        Self { handle, connection }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BrokerPhase {
    Starting,
    Traced,
    TerminationRequired(TerminationReason),
}

/// Internal reason for exact broker teardown; never decoded from a signal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TerminationReason {
    /// The authenticated client connection was invalidated.
    ClientDisconnected,
    /// The immutable service-local deadline expired.
    DeadlineExpired,
    /// The authenticated client requested semantic session termination.
    ClientRequested,
    /// The sole waiter observed an unexpected broker stop.
    UnexpectedBrokerStop,
    /// A protocol violation made continuation unsafe.
    ProtocolViolation,
    /// The kernel did not accept the opaque Ready reply for delivery.
    SpawnResultUndeliverable,
}

struct WatchdogEntry<Authority: ExactBrokerAuthority> {
    connection: ConnectionIdentity,
    deadline: Instant,
    broker: ExactBroker<Authority>,
    phase: BrokerPhase,
}

/// Service-generation table retaining exact broker owners through cleanup.
pub(super) struct WatchdogTable<Authority: ExactBrokerAuthority> {
    live: HashMap<SessionHandle, WatchdogEntry<Authority>>,
    tombstones: HashSet<SessionHandle>,
}

impl<Authority: ExactBrokerAuthority> WatchdogTable<Authority> {
    pub(super) fn new() -> Self {
        Self {
            live: HashMap::new(),
            tombstones: HashSet::new(),
        }
    }

    /// Registers authority before a broker or untrusted target may run.
    pub(super) fn register<Launch: RegisteredLaunchEffect>(
        &mut self,
        session: FreshSessionId,
        launch: Launch,
        broker: ExactBroker<Authority>,
    ) -> Result<RegisteredSession<Launch>, WatchdogStateError> {
        if self.live.len() >= MAX_LIVE_SESSIONS
            || self.live.len().saturating_add(self.tombstones.len())
                >= MAX_SESSIONS_PER_SERVICE_GENERATION
        {
            return Err(WatchdogStateError::CapacityExceeded);
        }
        let handle = SessionHandle(session.0);
        let connection = launch.connection_identity();
        let deadline = launch.deadline();
        if self.live.contains_key(&handle) || self.tombstones.contains(&handle) {
            return Err(WatchdogStateError::UnknownSession);
        }
        self.live.insert(
            handle,
            WatchdogEntry {
                connection,
                deadline,
                broker,
                phase: BrokerPhase::Starting,
            },
        );
        Ok(RegisteredSession {
            handle,
            launch: RegisteredLaunch {
                handle,
                connection,
                deadline,
                launch,
            },
        })
    }

    /// Records that the broker established the exact trace relationship.
    pub(super) fn mark_traced(
        &mut self,
        proof: TraceEstablished,
    ) -> Result<ReadySessionProof, WatchdogStateError> {
        let expired = {
            let entry = self.client_entry_mut(proof.handle, proof.connection)?;
            if entry.phase != BrokerPhase::Starting {
                return Err(WatchdogStateError::InvalidTransition);
            }
            if Instant::now() >= entry.deadline {
                true
            } else {
                entry.phase = BrokerPhase::Traced;
                false
            }
        };
        if expired {
            // Whether cleanup completes or remains pending, the table retains
            // the exact terminal state and first reason. No Ready proof exists.
            let _ = self.terminate_internal(proof.handle, TerminationReason::DeadlineExpired);
            return Err(WatchdogStateError::DeadlineExpired);
        }
        Ok(ReadySessionProof {
            handle: proof.handle,
            connection: proof.connection,
        })
    }

    /// Consumes an undelivered readiness proof into exact cleanup. A failed
    /// cleanup attempt leaves the same broker authority and first terminal
    /// reason retained in the table for service-loop retry.
    pub(super) fn terminate_undelivered_ready(
        &mut self,
        proof: ReadySessionProof,
    ) -> Result<Result<(), Authority::Failure>, WatchdogStateError> {
        let entry = self.client_entry_mut(proof.handle, proof.connection)?;
        if entry.phase != BrokerPhase::Traced {
            return Err(WatchdogStateError::InvalidTransition);
        }
        self.terminate_internal(proof.handle, TerminationReason::SpawnResultUndeliverable)
    }

    pub(super) fn terminate_for_client_disconnect(
        &mut self,
        handle: SessionHandle,
        connection: ConnectionIdentity,
    ) -> Result<Result<(), Authority::Failure>, WatchdogStateError> {
        self.terminate_for_client(handle, connection, TerminationReason::ClientDisconnected)
    }

    pub(super) fn terminate_for_client_request(
        &mut self,
        handle: SessionHandle,
        connection: ConnectionIdentity,
    ) -> Result<Result<(), Authority::Failure>, WatchdogStateError> {
        self.terminate_for_client(handle, connection, TerminationReason::ClientRequested)
    }

    pub(super) fn terminate_for_deadline(
        &mut self,
        handle: SessionHandle,
    ) -> Result<Result<(), Authority::Failure>, WatchdogStateError> {
        let entry = self
            .live
            .get(&handle)
            .ok_or(WatchdogStateError::UnknownSession)?;
        if Instant::now() < entry.deadline {
            return Err(WatchdogStateError::InvalidTransition);
        }
        self.terminate_internal(handle, TerminationReason::DeadlineExpired)
    }

    /// Makes every unexpected broker stop terminal under the held exact owner.
    pub(super) fn terminate_for_unexpected_stop(
        &mut self,
        handle: SessionHandle,
    ) -> Result<Result<(), Authority::Failure>, WatchdogStateError> {
        self.terminate_internal(handle, TerminationReason::UnexpectedBrokerStop)
    }

    pub(super) fn terminate_for_protocol_violation(
        &mut self,
        handle: SessionHandle,
    ) -> Result<Result<(), Authority::Failure>, WatchdogStateError> {
        self.terminate_internal(handle, TerminationReason::ProtocolViolation)
    }

    fn terminate_for_client(
        &mut self,
        handle: SessionHandle,
        connection: ConnectionIdentity,
        reason: TerminationReason,
    ) -> Result<Result<(), Authority::Failure>, WatchdogStateError> {
        self.client_entry_mut(handle, connection)?;
        self.terminate_internal(handle, reason)
    }

    fn terminate_internal(
        &mut self,
        handle: SessionHandle,
        reason: TerminationReason,
    ) -> Result<Result<(), Authority::Failure>, WatchdogStateError> {
        let result = {
            let entry = self
                .live
                .get_mut(&handle)
                .ok_or(WatchdogStateError::UnknownSession)?;
            let effective_reason = match entry.phase {
                BrokerPhase::Starting | BrokerPhase::Traced => {
                    entry.phase = BrokerPhase::TerminationRequired(reason);
                    reason
                }
                BrokerPhase::TerminationRequired(existing) => existing,
            };
            entry.broker.authority.terminate_and_reap(effective_reason)
        };
        if let Ok(proof) = result {
            let mut removed = self
                .live
                .remove(&handle)
                .expect("live entry existed for successful exact cleanup");
            removed.broker.mark_reaped(proof);
            self.tombstones.insert(handle);
            Ok(Ok(()))
        } else {
            Ok(result.map(|_| ()))
        }
    }

    fn client_entry_mut(
        &mut self,
        handle: SessionHandle,
        connection: ConnectionIdentity,
    ) -> Result<&mut WatchdogEntry<Authority>, WatchdogStateError> {
        let entry = self
            .live
            .get_mut(&handle)
            .ok_or(WatchdogStateError::UnknownSession)?;
        if entry.connection != connection {
            return Err(WatchdogStateError::WrongConnection);
        }
        Ok(entry)
    }

    #[cfg(test)]
    fn contains_live(&self, handle: SessionHandle) -> bool {
        self.live.contains_key(&handle)
    }

    #[cfg(test)]
    fn contains_tombstone(&self, handle: SessionHandle) -> bool {
        self.tombstones.contains(&handle)
    }
}

#[cfg(test)]
#[path = "supervisor_watchdog_test.rs"]
mod tests;
