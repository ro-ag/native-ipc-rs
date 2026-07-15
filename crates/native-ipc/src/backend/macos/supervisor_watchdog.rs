//! Opaque-session watchdog state independent of numeric process identifiers.

use std::cell::{Ref, RefCell};
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
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
    /// The exact broker could not be released after registration completed.
    BrokerActivationFailed,
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

    pub(super) const fn handle(&self) -> SessionHandle {
        SessionHandle(self.0)
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
struct RegisteredLaunch<Launch> {
    handle: SessionHandle,
    connection: ConnectionIdentity,
    deadline: Instant,
    launch: Launch,
}

/// One broker spawn result whose session, launch effect, and exact child
/// authority were minted by the same atomic spawning operation.
///
/// There is deliberately no general production constructor: the future
/// clean-exec spawner must create this value internally at the point where it
/// obtains the exact unreaped child authority. This prevents callers from
/// pairing one authenticated launch with another request's broker.
pub(super) struct AtomicallySpawnedBroker<Launch, Authority: ExactBrokerAuthority> {
    session: FreshSessionId,
    launch: Launch,
    broker: ExactBroker<Authority>,
}

impl<Launch, Authority: ExactBrokerAuthority> AtomicallySpawnedBroker<Launch, Authority> {
    #[cfg(test)]
    pub(super) unsafe fn from_test_atomic_spawn(
        session: FreshSessionId,
        launch: Launch,
        broker: ExactBroker<Authority>,
    ) -> Self {
        Self {
            session,
            launch,
            broker,
        }
    }

    fn into_parts(self) -> (FreshSessionId, Launch, ExactBroker<Authority>) {
        (self.session, self.launch, self.broker)
    }
}

impl
    AtomicallySpawnedBroker<
        ValidatedSpawn,
        super::supervisor::auth_adapter::broker_spawn::DirectChildBrokerAuthority,
    >
{
    pub(super) fn from_fixed_image_spawn(
        spawned: super::supervisor::auth_adapter::broker_spawn::FixedImageBrokerSpawn,
    ) -> Self {
        let (session, launch, broker) = spawned.into_parts();
        Self {
            session,
            launch,
            broker,
        }
    }
}

impl<Launch> RegisteredLaunch<Launch> {
    const fn handle(&self) -> SessionHandle {
        self.handle
    }

    const fn connection(&self) -> ConnectionIdentity {
        self.connection
    }

    const fn deadline(&self) -> Instant {
        self.deadline
    }
}

/// Registration result separating the copyable client handle from launch authority.
struct RegisteredSession<Launch> {
    handle: SessionHandle,
    launch: RegisteredLaunch<Launch>,
}

impl<Launch> RegisteredSession<Launch> {
    const fn handle(&self) -> SessionHandle {
        self.handle
    }

    fn into_launch(self) -> RegisteredLaunch<Launch> {
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

    #[cfg(test)]
    pub(super) fn authority_mut_for_test(&mut self) -> &mut Authority {
        &mut self.authority
    }

    #[cfg(test)]
    pub(super) fn mark_reaped_for_test(&mut self, proof: ReapedBroker) {
        self.mark_reaped(proof);
    }
}

impl<Authority: ExactBrokerAuthority> Drop for ExactBroker<Authority> {
    fn drop(&mut self) {
        if self.armed {
            let proof = self.authority.emergency_terminate_and_reap(None);
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

    /// Releases a broker that was created dormant only after its exact owner
    /// is present in the watchdog table.
    ///
    /// This must perform at most one nonblocking kernel operation, must not
    /// invoke caller code, and on error must retain the same exact unreaped
    /// authority for emergency cleanup.
    fn activate_after_registration(&mut self) -> Result<(), Self::Failure>;

    fn terminate_and_reap(
        &mut self,
        reason: TerminationReason,
    ) -> Result<ReapedBroker, Self::Failure>;

    fn emergency_terminate_and_reap(&mut self, reason: Option<TerminationReason>) -> ReapedBroker;
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

/// Armed delivery boundary retaining one session-specific exact entry.
///
/// The guard remains armed until one send effect succeeds. Any error, panic,
/// expiry, or ordinary drop exact-cleans only the proof-bound broker before
/// control can escape.
#[must_use = "Ready delivery must succeed or exact-clean the bound broker"]
pub(super) struct PendingReadyDelivery<Authority: ExactBrokerAuthority> {
    entry: Rc<RefCell<WatchdogEntry<Authority>>>,
    proof: Option<ReadySessionProof>,
    cleanup_reason: TerminationReason,
}

/// One prepared bounded nonblocking Ready send effect.
///
/// # Safety
///
/// Implementations must complete all allocation, encoding, and validation
/// before this value is supplied. `send_once` must perform at most one
/// nonblocking kernel send over the exact retained reply authority, must not
/// invoke caller code or wait for queue capacity, and must recheck the supplied
/// original deadline immediately before that send. The userspace clock check
/// and kernel entry are not an atomic kernel deadline operation.
pub(super) unsafe trait NonblockingReadySend {
    type Error;

    fn cleanup_reason(error: &Self::Error) -> TerminationReason;

    fn send_once(
        self,
        handle: SessionHandle,
        connection: ConnectionIdentity,
        deadline: Instant,
    ) -> Result<(), Self::Error>;
}

impl<Authority: ExactBrokerAuthority> PendingReadyDelivery<Authority> {
    pub(super) fn deliver<Send: NonblockingReadySend>(
        self,
        send: Send,
    ) -> Result<Result<(), Send::Error>, WatchdogStateError> {
        self.deliver_at(Instant::now(), send)
    }

    fn deliver_at<Send: NonblockingReadySend>(
        mut self,
        now: Instant,
        send: Send,
    ) -> Result<Result<(), Send::Error>, WatchdogStateError> {
        let proof = self.proof.as_ref().expect("armed Ready proof");
        let entry = self
            .entry
            .try_borrow()
            .unwrap_or_else(|_| std::process::abort());
        if entry.handle != proof.handle || entry.connection != proof.connection {
            std::process::abort();
        }
        match entry.phase {
            BrokerPhase::Reaped(_) => return Err(WatchdogStateError::UnknownSession),
            BrokerPhase::Reaping(_) => std::process::abort(),
            BrokerPhase::Starting | BrokerPhase::Traced | BrokerPhase::TerminationRequired(_) => {}
        }
        if entry.phase != BrokerPhase::Traced {
            return Err(WatchdogStateError::InvalidTransition);
        }
        if now >= entry.deadline {
            self.cleanup_reason = TerminationReason::DeadlineExpired;
            return Err(WatchdogStateError::DeadlineExpired);
        }
        let deadline = entry.deadline;
        drop(entry);
        match send.send_once(proof.handle, proof.connection, deadline) {
            Ok(()) => {
                self.proof.take();
                Ok(Ok(()))
            }
            Err(error) => {
                self.cleanup_reason = Send::cleanup_reason(&error);
                Ok(Err(error))
            }
        }
    }
}

impl<Authority: ExactBrokerAuthority> Drop for PendingReadyDelivery<Authority> {
    fn drop(&mut self) {
        if let Some(proof) = self.proof.take() {
            emergency_terminate_entry(
                &self.entry,
                proof.handle,
                proof.connection,
                self.cleanup_reason,
            );
        }
    }
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
    pub(super) const fn handle(&self) -> SessionHandle {
        self.handle
    }

    pub(super) const fn connection(&self) -> ConnectionIdentity {
        self.connection
    }

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
    Reaping(TerminationReason),
    Reaped(TerminationReason),
}

/// Internal reason for exact broker teardown; never decoded from a signal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum TerminationReason {
    /// Trusted launch or trace setup was abandoned before Ready commitment.
    LaunchAbandoned,
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
    handle: SessionHandle,
    connection: ConnectionIdentity,
    deadline: Instant,
    broker: Option<ExactBroker<Authority>>,
    phase: BrokerPhase,
}

/// Service-generation table retaining exact broker owners through cleanup.
pub(super) struct WatchdogTable<Authority: ExactBrokerAuthority> {
    live: HashMap<SessionHandle, Rc<RefCell<WatchdogEntry<Authority>>>>,
    tombstones: HashSet<SessionHandle>,
}

/// Armed ownership of one registered session while its trusted launch and
/// trace handshake are incomplete.
///
/// The session-specific obligation permits unrelated lifecycle entries to keep
/// progressing while preventing this exact launch from escaping cleanup. Every
/// abandonment path emergency exact-cleans the bound broker.
#[must_use = "a registered spawn must reach Ready or exact-clean its broker"]
pub(super) struct PendingRegisteredSession<Launch, Authority: ExactBrokerAuthority> {
    entry: Rc<RefCell<WatchdogEntry<Authority>>>,
    handle: SessionHandle,
    connection: ConnectionIdentity,
    launch: Option<RegisteredLaunch<Launch>>,
    trace: Option<TraceEstablished>,
    cleanup_reason: TerminationReason,
    armed: bool,
}

/// Borrowed launch effect view branded by the live registered-session lease.
/// No method returns the owned effect, so it cannot survive lease cleanup.
pub(super) struct RegisteredLaunchPermit<'lease, Launch, Authority: ExactBrokerAuthority> {
    entry: Rc<RefCell<WatchdogEntry<Authority>>>,
    launch: &'lease RegisteredLaunch<Launch>,
}

/// Short-lived final launch commitment held only across the no-callback
/// irreversible launcher mutation and exec operation.
#[must_use = "the launch commitment must remain live through irreversible exec"]
pub(super) struct RegisteredLaunchCommitGuard<'permit, Authority: ExactBrokerAuthority> {
    _entry: Ref<'permit, WatchdogEntry<Authority>>,
}

impl<Launch, Authority: ExactBrokerAuthority> RegisteredLaunchPermit<'_, Launch, Authority> {
    pub(super) const fn handle(&self) -> SessionHandle {
        self.launch.handle()
    }

    pub(super) const fn connection(&self) -> ConnectionIdentity {
        self.launch.connection()
    }

    pub(super) const fn deadline(&self) -> Instant {
        self.launch.deadline()
    }

    pub(super) const fn launch(&self) -> &Launch {
        &self.launch.launch
    }

    /// Revalidates the exact live registration immediately before the
    /// no-callback irreversible launcher operation and pins only this entry for
    /// that operation's duration.
    pub(super) fn commit_guard(
        &self,
    ) -> Result<RegisteredLaunchCommitGuard<'_, Authority>, WatchdogStateError> {
        let entry = self
            .entry
            .try_borrow()
            .unwrap_or_else(|_| std::process::abort());
        if entry.handle != self.launch.handle || entry.connection != self.launch.connection {
            std::process::abort();
        }
        match entry.phase {
            BrokerPhase::Starting => {}
            BrokerPhase::Reaped(_) => return Err(WatchdogStateError::UnknownSession),
            BrokerPhase::Reaping(_) => std::process::abort(),
            BrokerPhase::Traced | BrokerPhase::TerminationRequired(_) => {
                return Err(WatchdogStateError::InvalidTransition);
            }
        }
        if Instant::now() >= entry.deadline {
            drop(entry);
            emergency_terminate_entry(
                &self.entry,
                self.launch.handle,
                self.launch.connection,
                TerminationReason::DeadlineExpired,
            );
            return Err(WatchdogStateError::DeadlineExpired);
        }
        Ok(RegisteredLaunchCommitGuard { _entry: entry })
    }
}

impl<Launch, Authority: ExactBrokerAuthority> PendingRegisteredSession<Launch, Authority> {
    pub(super) const fn handle(&self) -> SessionHandle {
        self.handle
    }

    pub(super) const fn connection(&self) -> ConnectionIdentity {
        self.connection
    }

    pub(super) fn launch_permit(
        &self,
    ) -> Result<RegisteredLaunchPermit<'_, Launch, Authority>, WatchdogStateError> {
        let entry = self
            .entry
            .try_borrow()
            .unwrap_or_else(|_| std::process::abort());
        if entry.handle != self.handle || entry.connection != self.connection {
            std::process::abort();
        }
        if entry.phase != BrokerPhase::Starting {
            return Err(WatchdogStateError::InvalidTransition);
        }
        if Instant::now() >= entry.deadline {
            drop(entry);
            emergency_terminate_entry(
                &self.entry,
                self.handle,
                self.connection,
                TerminationReason::DeadlineExpired,
            );
            return Err(WatchdogStateError::DeadlineExpired);
        }
        let launch = self
            .launch
            .as_ref()
            .ok_or(WatchdogStateError::InvalidTransition)?;
        Ok(RegisteredLaunchPermit {
            entry: Rc::clone(&self.entry),
            launch,
        })
    }

    pub(super) fn mark_protocol_violation(&mut self) {
        self.cleanup_reason = TerminationReason::ProtocolViolation;
    }

    pub(super) fn bind_trace(&mut self, trace: TraceEstablished) -> Result<(), TraceEstablished> {
        if self.trace.is_some()
            || trace.handle != self.handle
            || trace.connection != self.connection
        {
            return Err(trace);
        }
        self.trace = Some(trace);
        Ok(())
    }

    pub(super) fn mark_traced_for_delivery(
        mut self,
    ) -> Result<PendingReadyDelivery<Authority>, WatchdogStateError> {
        let Some(trace) = self.trace.take() else {
            self.mark_protocol_violation();
            return Err(WatchdogStateError::InvalidTransition);
        };
        self.armed = false;
        transition_registered_for_delivery(Rc::clone(&self.entry), trace)
    }
}

impl<Launch, Authority: ExactBrokerAuthority> Drop for PendingRegisteredSession<Launch, Authority> {
    fn drop(&mut self) {
        if self.armed {
            emergency_terminate_entry(
                &self.entry,
                self.handle,
                self.connection,
                self.cleanup_reason,
            );
            self.armed = false;
        }
    }
}

fn transition_registered_for_delivery<Authority: ExactBrokerAuthority>(
    entry: Rc<RefCell<WatchdogEntry<Authority>>>,
    proof: TraceEstablished,
) -> Result<PendingReadyDelivery<Authority>, WatchdogStateError> {
    let transition_error = {
        let mut entry_ref = entry
            .try_borrow_mut()
            .unwrap_or_else(|_| std::process::abort());
        if entry_ref.handle != proof.handle || entry_ref.connection != proof.connection {
            std::process::abort();
        }
        if entry_ref.phase != BrokerPhase::Starting {
            Some(WatchdogStateError::InvalidTransition)
        } else if Instant::now() >= entry_ref.deadline {
            Some(WatchdogStateError::DeadlineExpired)
        } else {
            entry_ref.phase = BrokerPhase::Traced;
            None
        }
    };
    if let Some(error) = transition_error {
        emergency_terminate_entry(
            &entry,
            proof.handle,
            proof.connection,
            if error == WatchdogStateError::DeadlineExpired {
                TerminationReason::DeadlineExpired
            } else {
                TerminationReason::ProtocolViolation
            },
        );
        return Err(error);
    }
    Ok(PendingReadyDelivery {
        entry,
        proof: Some(ReadySessionProof {
            handle: proof.handle,
            connection: proof.connection,
        }),
        cleanup_reason: TerminationReason::SpawnResultUndeliverable,
    })
}

fn emergency_terminate_entry<Authority: ExactBrokerAuthority>(
    entry: &Rc<RefCell<WatchdogEntry<Authority>>>,
    handle: SessionHandle,
    connection: ConnectionIdentity,
    reason: TerminationReason,
) {
    let (mut broker, effective_reason) = {
        let mut entry = entry
            .try_borrow_mut()
            .unwrap_or_else(|_| std::process::abort());
        if entry.handle != handle || entry.connection != connection {
            std::process::abort();
        }
        let effective_reason = match entry.phase {
            BrokerPhase::Reaped(_) => return,
            BrokerPhase::Reaping(_) => std::process::abort(),
            BrokerPhase::Starting | BrokerPhase::Traced => reason,
            BrokerPhase::TerminationRequired(existing) => existing,
        };
        entry.phase = BrokerPhase::Reaping(effective_reason);
        (
            entry.broker.take().unwrap_or_else(|| std::process::abort()),
            effective_reason,
        )
    };
    let proof = broker
        .authority
        .emergency_terminate_and_reap(Some(effective_reason));
    broker.mark_reaped(proof);
    let mut entry = entry
        .try_borrow_mut()
        .unwrap_or_else(|_| std::process::abort());
    if entry.phase != BrokerPhase::Reaping(effective_reason) || entry.broker.is_some() {
        std::process::abort();
    }
    entry.phase = BrokerPhase::Reaped(effective_reason);
}

impl<Authority: ExactBrokerAuthority> WatchdogTable<Authority> {
    pub(super) fn new() -> Self {
        Self {
            live: HashMap::new(),
            tombstones: HashSet::new(),
        }
    }

    /// Registers authority before a broker or untrusted target may run.
    fn register<Launch: RegisteredLaunchEffect>(
        &mut self,
        spawned: AtomicallySpawnedBroker<Launch, Authority>,
    ) -> Result<RegisteredSession<Launch>, WatchdogStateError> {
        self.sweep_reaped();
        let (session, launch, broker) = spawned.into_parts();
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
            Rc::new(RefCell::new(WatchdogEntry {
                handle,
                connection,
                deadline,
                broker: Some(broker),
                phase: BrokerPhase::Starting,
            })),
        );
        if Instant::now() >= deadline {
            let entry = Rc::clone(
                self.live
                    .get(&handle)
                    .expect("expired registration retains the exact session entry"),
            );
            emergency_terminate_entry(
                &entry,
                handle,
                connection,
                TerminationReason::DeadlineExpired,
            );
            self.sweep_reaped();
            return Err(WatchdogStateError::DeadlineExpired);
        }
        let activation = self
            .live
            .get(&handle)
            .expect("registration inserted the exact session entry")
            .try_borrow_mut()
            .unwrap_or_else(|_| std::process::abort())
            .broker
            .as_mut()
            .unwrap_or_else(|| std::process::abort())
            .authority
            .activate_after_registration();
        if activation.is_err() {
            let entry = Rc::clone(
                self.live
                    .get(&handle)
                    .expect("failed activation retains the exact session entry"),
            );
            emergency_terminate_entry(
                &entry,
                handle,
                connection,
                TerminationReason::LaunchAbandoned,
            );
            self.sweep_reaped();
            return Err(WatchdogStateError::BrokerActivationFailed);
        }
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

    pub(super) fn register_armed<Launch: RegisteredLaunchEffect>(
        &mut self,
        spawned: AtomicallySpawnedBroker<Launch, Authority>,
    ) -> Result<PendingRegisteredSession<Launch, Authority>, WatchdogStateError> {
        let registered = self.register(spawned)?;
        let handle = registered.handle();
        let launch = registered.into_launch();
        let connection = launch.connection();
        let entry = Rc::clone(
            self.live
                .get(&handle)
                .expect("registration inserted the exact session entry"),
        );
        Ok(PendingRegisteredSession {
            entry,
            handle,
            connection,
            launch: Some(launch),
            trace: None,
            cleanup_reason: TerminationReason::LaunchAbandoned,
            armed: true,
        })
    }

    /// Records that the broker established the exact trace relationship.
    fn mark_traced(
        &mut self,
        proof: TraceEstablished,
    ) -> Result<ReadySessionProof, WatchdogStateError> {
        let entry = self.client_entry(proof.handle, proof.connection)?;
        let expired = {
            let mut entry = entry
                .try_borrow_mut()
                .unwrap_or_else(|_| std::process::abort());
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

    /// Atomically transitions the exact trace proof into an armed delivery
    /// guard. A deadline failure returns only after any retryable retained
    /// terminal authority has been emergency exact-reaped.
    pub(super) fn mark_traced_for_delivery(
        &mut self,
        proof: TraceEstablished,
    ) -> Result<PendingReadyDelivery<Authority>, WatchdogStateError> {
        let entry = self.client_entry(proof.handle, proof.connection)?;
        transition_registered_for_delivery(entry, proof)
    }

    /// Consumes an undelivered readiness proof into exact cleanup. A failed
    /// cleanup attempt leaves the same broker authority and first terminal
    /// reason retained in the table for service-loop retry.
    pub(super) fn terminate_undelivered_ready(
        &mut self,
        proof: ReadySessionProof,
    ) -> Result<Result<(), Authority::Failure>, WatchdogStateError> {
        let entry = self.client_entry(proof.handle, proof.connection)?;
        if entry
            .try_borrow()
            .unwrap_or_else(|_| std::process::abort())
            .phase
            != BrokerPhase::Traced
        {
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
        self.sweep_reaped();
        let entry = self
            .live
            .get(&handle)
            .ok_or(WatchdogStateError::UnknownSession)?;
        if Instant::now()
            < entry
                .try_borrow()
                .unwrap_or_else(|_| std::process::abort())
                .deadline
        {
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
        self.client_entry(handle, connection)?;
        self.terminate_internal(handle, reason)
    }

    fn terminate_internal(
        &mut self,
        handle: SessionHandle,
        reason: TerminationReason,
    ) -> Result<Result<(), Authority::Failure>, WatchdogStateError> {
        self.sweep_reaped();
        let entry = Rc::clone(
            self.live
                .get(&handle)
                .ok_or(WatchdogStateError::UnknownSession)?,
        );
        let (mut broker, effective_reason) = {
            let mut entry = entry
                .try_borrow_mut()
                .unwrap_or_else(|_| std::process::abort());
            let effective_reason = match entry.phase {
                BrokerPhase::Starting | BrokerPhase::Traced => reason,
                BrokerPhase::TerminationRequired(existing) => existing,
                BrokerPhase::Reaping(_) => std::process::abort(),
                BrokerPhase::Reaped(_) => return Err(WatchdogStateError::UnknownSession),
            };
            entry.phase = BrokerPhase::Reaping(effective_reason);
            let broker = entry.broker.take().unwrap_or_else(|| std::process::abort());
            (broker, effective_reason)
        };
        let result = broker.authority.terminate_and_reap(effective_reason);
        let result = match result {
            Ok(proof) => {
                broker.mark_reaped(proof);
                let mut entry = entry
                    .try_borrow_mut()
                    .unwrap_or_else(|_| std::process::abort());
                if entry.phase != BrokerPhase::Reaping(effective_reason) || entry.broker.is_some() {
                    std::process::abort();
                }
                entry.phase = BrokerPhase::Reaped(effective_reason);
                Ok(())
            }
            Err(error) => {
                let mut entry = entry
                    .try_borrow_mut()
                    .unwrap_or_else(|_| std::process::abort());
                if entry.phase != BrokerPhase::Reaping(effective_reason) || entry.broker.is_some() {
                    std::process::abort();
                }
                entry.phase = BrokerPhase::TerminationRequired(effective_reason);
                entry.broker = Some(broker);
                Err(error)
            }
        };
        if result.is_ok() {
            self.sweep_reaped();
        }
        Ok(result)
    }

    fn emergency_terminate_registered(
        &mut self,
        handle: SessionHandle,
        connection: ConnectionIdentity,
        reason: TerminationReason,
    ) {
        let Ok(entry) = self.client_entry(handle, connection) else {
            std::process::abort();
        };
        emergency_terminate_entry(&entry, handle, connection, reason);
        self.sweep_reaped();
    }

    fn client_entry(
        &mut self,
        handle: SessionHandle,
        connection: ConnectionIdentity,
    ) -> Result<Rc<RefCell<WatchdogEntry<Authority>>>, WatchdogStateError> {
        self.sweep_reaped();
        let entry = Rc::clone(
            self.live
                .get(&handle)
                .ok_or(WatchdogStateError::UnknownSession)?,
        );
        let entry_connection = entry
            .try_borrow()
            .unwrap_or_else(|_| std::process::abort())
            .connection;
        if entry_connection != connection {
            return Err(WatchdogStateError::WrongConnection);
        }
        Ok(entry)
    }

    fn sweep_reaped(&mut self) {
        let reaped: Vec<_> = self
            .live
            .iter()
            .filter_map(|(handle, entry)| {
                let phase = entry
                    .try_borrow()
                    .unwrap_or_else(|_| std::process::abort())
                    .phase;
                match phase {
                    BrokerPhase::Reaped(_) => Some(*handle),
                    BrokerPhase::Reaping(_) => std::process::abort(),
                    BrokerPhase::Starting
                    | BrokerPhase::Traced
                    | BrokerPhase::TerminationRequired(_) => None,
                }
            })
            .collect();
        for handle in reaped {
            if !self.tombstones.insert(handle) {
                std::process::abort();
            }
            self.live
                .remove(&handle)
                .unwrap_or_else(|| std::process::abort());
        }
    }

    #[cfg(test)]
    fn contains_live(&self, handle: SessionHandle) -> bool {
        self.live.get(&handle).is_some_and(|entry| {
            matches!(
                entry
                    .try_borrow()
                    .unwrap_or_else(|_| std::process::abort())
                    .phase,
                BrokerPhase::Starting | BrokerPhase::Traced | BrokerPhase::TerminationRequired(_)
            )
        })
    }

    #[cfg(test)]
    fn contains_tombstone(&self, handle: SessionHandle) -> bool {
        self.tombstones.contains(&handle)
            || self.live.get(&handle).is_some_and(|entry| {
                matches!(
                    entry
                        .try_borrow()
                        .unwrap_or_else(|_| std::process::abort())
                        .phase,
                    BrokerPhase::Reaped(_)
                )
            })
    }
}

impl<Authority: ExactBrokerAuthority> Drop for WatchdogTable<Authority> {
    fn drop(&mut self) {
        for entry in self.live.values() {
            let (handle, connection, phase) = {
                let entry = entry.try_borrow().unwrap_or_else(|_| std::process::abort());
                (entry.handle, entry.connection, entry.phase)
            };
            match phase {
                BrokerPhase::Reaped(_) => {}
                BrokerPhase::Reaping(_) => std::process::abort(),
                BrokerPhase::Starting
                | BrokerPhase::Traced
                | BrokerPhase::TerminationRequired(_) => emergency_terminate_entry(
                    entry,
                    handle,
                    connection,
                    TerminationReason::ProtocolViolation,
                ),
            }
        }
    }
}

#[cfg(test)]
#[path = "supervisor_watchdog_test.rs"]
mod tests;
