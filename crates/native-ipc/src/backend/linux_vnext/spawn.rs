//! Private, pre-authentication Linux exact-child spawn owner.

use core::cell::Cell;
use core::marker::PhantomData;
use std::ffi::{CString, OsString};
use std::io;
use std::num::NonZeroU32;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
#[cfg(test)]
use std::sync::{Arc, Mutex};

use crate::backend::accepted_control::{
    AcceptedControlDispatcher, AcceptedControlError, LinuxActivationError, LinuxBatchBeginError,
    LinuxCapabilityBatchError,
};
use crate::backend::{
    AuthenticatedZeroRightsTransport, CoordinatorAcceptedEvidence, CoordinatorCapabilityTransport,
    CoordinatorChildChannelReceipt, CoordinatorChildImageReceipt, OwnedChildLifecycle, PeerState,
    ReceiverCapabilityTransport, ReceiverSpawnerEvidence, SessionTransportError,
    SpawnIdentityFacts, sealed,
};
use crate::batch::{ActiveRegionSet, BatchError, ExpectedBatch, TransferBatch};
use crate::control::{CONTROL_HEADER_LEN, ControlError, ControlFrame};
use crate::liveness::ResourceError;
use crate::negotiation::{
    AtomicOffer, DecisionChallenge, FeatureBits, HEADER_LEN, HelloFrame, HelloPair,
    NegotiatedTranscript, NegotiationFrame, NegotiationWireError, SenderRole, TargetFacts,
    decode_frame,
};
use crate::protocol::{
    CONTROL_FRAME_LEN, CapabilityFrame, CoordinatorCapacityStatus, NativeAuthorityProfile,
};
use crate::session::{
    AbsoluteDeadline, ActiveLeaseFacts, AtomicCapabilities, ChildCleanupFacts, ChildExitStatus,
    DescendantCleanupStatus, NegotiationError, PeerStatus, ProtocolVersion, SessionCommand,
    SessionLimits, SessionOptions, SessionState,
};

use super::memory::{LinuxMixedDirectionBatch, MemfdError};
use super::process::{
    DescendantCleanup, ExactChildCleanup, ExactChildExit, ExactChildLifecycle, HeldExecutable,
    PreparedExactChildLifecycle,
};
use super::{
    MAX_ZERO_RIGHTS_PACKET_BYTES, PacketCredentials, PacketError, SeqPacketEndpoint,
    discover_atomic_capabilities,
};

const CLONE_PIDFD: u64 = 0x0000_1000;
const CLOSE_RANGE_CLOEXEC: libc::c_uint = 1 << 2;
const PR_SET_MDWE: libc::c_int = 65;
const PR_MDWE_REFUSE_EXEC_GAIN: libc::c_ulong = 1;
const EXEC_ERROR_LEN: usize = 8;
const NONCE_LEN: usize = 32;
const MAX_LINUX_HELLO_PAYLOAD: usize = MAX_ZERO_RIGHTS_PACKET_BYTES - HEADER_LEN;
const MAX_LINUX_CONTROL_PAYLOAD: u32 = (MAX_ZERO_RIGHTS_PACKET_BYTES - CONTROL_HEADER_LEN) as u32;
const BOOTSTRAP_ENV: &[u8] = b"NATIVE_IPC_VNEXT_BOOTSTRAP_FD";
const PUBLIC_BOOTSTRAP_ENV: &str = "NATIVE_IPC_VNEXT_PUBLIC_BOOTSTRAP";
#[cfg(test)]
std::thread_local! {
    static LAST_SPAWN_PID: Cell<libc::pid_t> = const { Cell::new(0) };
}

#[repr(C)]
#[derive(Default)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

#[repr(C)]
struct RawChildError {
    stage: u32,
    errno: i32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LinuxSpawnError {
    InvalidInput,
    DeadlineExpired,
    MalformedChildError,
    Child { stage: u32, errno: i32 },
    ExitedBeforeConfirmation,
    WrongExecutable,
    EntropyUnavailable,
    Packet(PacketError),
    Negotiation(NegotiationWireError),
    NativeNegotiation(NegotiationError),
    Native(i32),
}

#[derive(Debug)]
struct LinuxCoordinatorSpawnFailure {
    error: LinuxSpawnError,
    cleanup: Option<ExactChildCleanup>,
    state: LinuxCoordinatorFailureState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LinuxCoordinatorFailureState {
    NotEstablished,
    Spawned,
    Negotiating,
}

#[cfg(test)]
impl PartialEq<LinuxSpawnError> for LinuxCoordinatorSpawnFailure {
    fn eq(&self, other: &LinuxSpawnError) -> bool {
        self.error == *other
    }
}

impl LinuxCoordinatorSpawnFailure {
    const fn before_child(error: LinuxSpawnError) -> Self {
        Self {
            error,
            cleanup: None,
            state: LinuxCoordinatorFailureState::NotEstablished,
        }
    }

    const fn after_spawn(error: LinuxSpawnError, cleanup: ExactChildCleanup) -> Self {
        Self {
            error,
            cleanup: Some(cleanup),
            state: LinuxCoordinatorFailureState::Spawned,
        }
    }

    const fn during_negotiation(error: LinuxSpawnError, cleanup: ExactChildCleanup) -> Self {
        Self {
            error,
            cleanup: Some(cleanup),
            state: LinuxCoordinatorFailureState::Negotiating,
        }
    }
}

#[derive(Clone, Copy)]
enum SpawnFault {
    None,
    CloseRange,
    BootstrapFd,
    SetSid,
    Mdwe,
    Exec,
    Partial,
    Malformed,
    Stall,
    SilentExit,
}

/// Exact child and anonymous bootstrap topology before any peer authentication.
///
/// This owner deliberately has no transport, descriptor-transfer, receipt,
/// session, negotiation, or memory-authority methods.
struct UnauthenticatedLinuxSpawn {
    lifecycle: Option<ExactChildLifecycle>,
    endpoint: SeqPacketEndpoint,
    executable: HeldExecutable,
    not_sync: PhantomData<Cell<()>>,
}

struct LinuxHelloOffer {
    supported_features: FeatureBits,
    required_features: FeatureBits,
    limits: SessionLimits,
    application_payload: Vec<u8>,
}

/// Two canonical HELLO records bound to the exact child, but not accepted.
///
/// This private owner intentionally exposes no endpoint, descriptor, receipt,
/// session, control, batch, or memory-authority operation.
struct NegotiatingLinuxSpawn {
    lifecycle: Option<ExactChildLifecycle>,
    endpoint: SeqPacketEndpoint,
    executable: HeldExecutable,
    transcript: NegotiatedTranscript,
    nonce: [u8; NONCE_LEN],
    deadline: AbsoluteDeadline,
    _peer_application_payload: Vec<u8>,
    not_sync: PhantomData<Cell<()>>,
}

struct ReceiverNegotiatingState {
    endpoint: SeqPacketEndpoint,
    transcript: NegotiatedTranscript,
    nonce: [u8; NONCE_LEN],
    peer: PacketCredentials,
    local: PacketCredentials,
    deadline: AbsoluteDeadline,
    _peer_application_payload: Vec<u8>,
    not_sync: PhantomData<Cell<()>>,
}

struct AcceptedLinuxSpawn {
    lifecycle: Option<ExactChildLifecycle>,
    endpoint: SeqPacketEndpoint,
    executable: HeldExecutable,
    transcript: NegotiatedTranscript,
    nonce: [u8; NONCE_LEN],
    child: PacketCredentials,
    deadline: AbsoluteDeadline,
    not_sync: PhantomData<Cell<()>>,
}

struct AcceptedLinuxReceiver {
    endpoint: SeqPacketEndpoint,
    transcript: NegotiatedTranscript,
    nonce: [u8; NONCE_LEN],
    parent: PacketCredentials,
    child: PacketCredentials,
    not_sync: PhantomData<Cell<()>>,
}

struct CoordinatorAcceptedEvidenceOwner {
    lifecycle: Option<ExactChildLifecycle>,
    endpoint: SeqPacketEndpoint,
    executable: HeldExecutable,
    evidence: CoordinatorAcceptedEvidence,
    deadline: AbsoluteDeadline,
    not_sync: PhantomData<Cell<()>>,
}

struct ReceiverAcceptedEvidenceOwner {
    endpoint: SeqPacketEndpoint,
    evidence: ReceiverSpawnerEvidence,
    not_sync: PhantomData<Cell<()>>,
}

pub(crate) struct CoordinatorLinuxControlTransport {
    lifecycle: Option<ExactChildLifecycle>,
    endpoint: SeqPacketEndpoint,
    _executable: HeldExecutable,
    _evidence: CoordinatorAcceptedEvidence,
    peer: PacketCredentials,
    poisoned: bool,
    #[cfg(test)]
    poison_observer: Option<Arc<Mutex<Vec<&'static str>>>>,
    not_sync: PhantomData<Cell<()>>,
}

pub(crate) struct ReceiverLinuxControlTransport {
    endpoint: SeqPacketEndpoint,
    _evidence: ReceiverSpawnerEvidence,
    peer: PacketCredentials,
    poisoned: bool,
    #[cfg(test)]
    poison_observer: Option<Arc<Mutex<Vec<&'static str>>>>,
    not_sync: PhantomData<Cell<()>>,
}

pub(crate) struct LinuxReceivedCapabilities {
    descriptors: Vec<OwnedFd>,
}

pub(crate) struct LinuxReceivedCapabilityRecord {
    pub(crate) frame: Vec<u8>,
    pub(crate) descriptors: Vec<OwnedFd>,
}

impl LinuxReceivedCapabilities {
    const fn len(&self) -> usize {
        self.descriptors.len()
    }
}

type CoordinatorAcceptedControl = AcceptedControlDispatcher<CoordinatorLinuxControlTransport>;
type ReceiverAcceptedControl = AcceptedControlDispatcher<ReceiverLinuxControlTransport>;

pub(crate) struct LinuxCoordinatorNegotiatingSession(NegotiatingLinuxSpawn);
pub(crate) struct LinuxReceiverNegotiatingSession(ReceiverNegotiatingState);
pub(crate) struct LinuxCoordinatorReadySession(CoordinatorAcceptedControl);
pub(crate) struct LinuxReceiverReadySession(ReceiverAcceptedControl);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LinuxNegotiationRole {
    Coordinator,
    Receiver,
}

pub(crate) enum LinuxNegotiationOutcome<T> {
    Accepted(T),
    Rejected {
        by: LinuxNegotiationRole,
        reason: NonZeroU32,
        cleanup: Option<ChildCleanupFacts>,
    },
}

pub(crate) struct LinuxCoordinatorSessionFailure {
    pub(crate) error: LinuxPublicSessionError,
    pub(crate) cleanup: Option<ChildCleanupFacts>,
    pub(crate) state: LinuxCoordinatorFailureState,
    pub(crate) poisoned: bool,
}

pub(crate) struct LinuxPublicReadyFailure {
    pub(crate) error: LinuxPublicSessionError,
    pub(crate) transaction_open_on_failure: bool,
}

impl LinuxPublicReadyFailure {
    fn before_transaction(error: LinuxPublicSessionError) -> Self {
        Self {
            error,
            transaction_open_on_failure: false,
        }
    }

    fn after_transaction(error: LinuxPublicSessionError) -> Self {
        Self {
            error,
            transaction_open_on_failure: true,
        }
    }

    fn ready_after_transaction(error: LinuxPublicSessionError) -> Self {
        Self {
            error,
            transaction_open_on_failure: false,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LinuxPublicSessionError {
    InvalidInput,
    DeadlineExpired,
    PeerExited,
    IdentityMismatch,
    MalformedPeer,
    Ambiguous,
    NegotiationFailed,
    NativeNegotiation(NegotiationError),
    Control(ControlError),
    Batch(BatchError),
    ActiveLimit,
    PeerPreparationFailed,
    ActivationFailed(Option<i32>),
    Poisoned,
    Native(Option<i32>),
}

struct ReceiverDecisionPending {
    endpoint: SeqPacketEndpoint,
    transcript: NegotiatedTranscript,
    deadline: AbsoluteDeadline,
    nonce: [u8; NONCE_LEN],
    parent: PacketCredentials,
    child: PacketCredentials,
    not_sync: PhantomData<Cell<()>>,
}

struct RejectedLinuxReceiver {
    _endpoint: SeqPacketEndpoint,
    not_sync: PhantomData<Cell<()>>,
}

enum CoordinatorDecisionOutcome {
    Pending(Box<ReceiverDecisionPending>),
    Rejected {
        reason: NonZeroU32,
        state: RejectedLinuxReceiver,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ApplicationDecision {
    Accept,
    Reject(NonZeroU32),
}

#[derive(Debug)]
enum DecisionOutcome<T, R = ()> {
    Accepted(T),
    Rejected {
        by: SenderRole,
        reason: NonZeroU32,
        state: R,
    },
}

#[derive(Clone, Copy)]
enum EntropyFault {
    None,
    #[cfg(test)]
    Interrupted,
    #[cfg(test)]
    WouldBlock,
    #[cfg(test)]
    Short,
    #[cfg(test)]
    AllZero,
}

impl UnauthenticatedLinuxSpawn {
    fn pid(&self) -> libc::pid_t {
        self.lifecycle.as_ref().expect("live spawn owner").pid()
    }

    fn pidfd(&self) -> RawFd {
        self.lifecycle.as_ref().expect("live spawn owner").pidfd()
    }

    fn terminate_and_reap(mut self, deadline: AbsoluteDeadline) -> ExactChildCleanup {
        self.lifecycle
            .take()
            .expect("live negotiating owner retains exact child lifecycle")
            .terminate_and_reap(deadline)
    }
}

impl NegotiatingLinuxSpawn {
    fn pid(&self) -> libc::pid_t {
        self.lifecycle
            .as_ref()
            .expect("live negotiating owner")
            .pid()
    }

    fn pidfd(&self) -> RawFd {
        self.lifecycle
            .as_ref()
            .expect("live negotiating owner")
            .pidfd()
    }

    fn terminate_and_reap(mut self, deadline: AbsoluteDeadline) -> ExactChildCleanup {
        self.lifecycle
            .take()
            .expect("live negotiating owner retains exact child lifecycle")
            .terminate_and_reap(deadline)
    }

    fn decide(
        self,
        decision: ApplicationDecision,
    ) -> Result<
        DecisionOutcome<AcceptedLinuxSpawn, ExactChildCleanup>,
        (LinuxSpawnError, ExactChildCleanup),
    > {
        self.decide_with_entropy_fault(decision, EntropyFault::None)
    }

    fn decide_with_entropy_fault(
        mut self,
        decision: ApplicationDecision,
        entropy_fault: EntropyFault,
    ) -> Result<
        DecisionOutcome<AcceptedLinuxSpawn, ExactChildCleanup>,
        (LinuxSpawnError, ExactChildCleanup),
    > {
        let deadline = self.deadline;
        let result = (|| {
            let challenge = generate_decision_challenge(deadline, entropy_fault)?;
            match decision {
                ApplicationDecision::Reject(reason) => {
                    let reject = self
                        .transcript
                        .coordinator_reject(challenge, reason)
                        .map_err(LinuxSpawnError::Negotiation)?;
                    let frame = NegotiationFrame::Reject(reject);
                    let encoded = encode_negotiation_frame(&frame)?;
                    send_negotiating_spawn(&mut self, &encoded)?;
                    return Ok(DecisionOutcome::Rejected {
                        by: SenderRole::Coordinator,
                        reason,
                        state: (),
                    });
                }
                ApplicationDecision::Accept => {
                    let accept = self
                        .transcript
                        .coordinator_accept(challenge)
                        .map_err(LinuxSpawnError::Negotiation)?;
                    self.transcript
                        .validate_accept(accept, SenderRole::Coordinator)
                        .map_err(LinuxSpawnError::Negotiation)?;
                    let encoded = encode_negotiation_frame(&NegotiationFrame::Accept(accept))?;
                    send_negotiating_spawn(&mut self, &encoded)?;
                }
            }

            let expected_peer = exact_child_credentials(&self)?;
            let pidfd = self.pidfd();
            let packet = receive_with_exact_child_fields(
                &mut self.endpoint,
                pidfd,
                expected_peer,
                deadline,
            )?;
            match decode_frame(
                &packet.bytes,
                SenderRole::Receiver,
                self.nonce,
                MAX_LINUX_HELLO_PAYLOAD as u32,
            )
            .map_err(LinuxSpawnError::Negotiation)?
            {
                NegotiationFrame::Accept(accept) => {
                    self.transcript
                        .validate_accept(accept, SenderRole::Receiver)
                        .map_err(LinuxSpawnError::Negotiation)?;
                }
                NegotiationFrame::Reject(reject) => {
                    let reason = self
                        .transcript
                        .validate_reject(reject, SenderRole::Receiver)
                        .map_err(LinuxSpawnError::Negotiation)?;
                    return Ok(DecisionOutcome::Rejected {
                        by: SenderRole::Receiver,
                        reason,
                        state: (),
                    });
                }
                NegotiationFrame::Hello(_) => {
                    return Err(LinuxSpawnError::Negotiation(NegotiationWireError::BadKind));
                }
            }
            ensure_live(self.pidfd(), deadline)?;
            if !self.executable.matches_process_image(self.pid()) {
                return Err(LinuxSpawnError::WrongExecutable);
            }
            ensure_live(self.pidfd(), deadline)?;
            let child = exact_child_credentials(&self)?;
            Ok(DecisionOutcome::Accepted(child))
        })();
        match result {
            Ok(DecisionOutcome::Accepted(child)) => {
                Ok(DecisionOutcome::Accepted(AcceptedLinuxSpawn {
                    lifecycle: self.lifecycle.take(),
                    endpoint: self.endpoint,
                    executable: self.executable,
                    transcript: self.transcript,
                    nonce: self.nonce,
                    child,
                    deadline,
                    not_sync: PhantomData,
                }))
            }
            Ok(DecisionOutcome::Rejected {
                by,
                reason,
                state: (),
            }) => {
                let cleanup = self.terminate_and_reap(deadline);
                Ok(DecisionOutcome::Rejected {
                    by,
                    reason,
                    state: cleanup,
                })
            }
            Err(error) => {
                let cleanup = self.terminate_and_reap(deadline);
                Err((error, cleanup))
            }
        }
    }
}

impl ReceiverNegotiatingState {
    fn await_coordinator_decision(mut self) -> Result<CoordinatorDecisionOutcome, LinuxSpawnError> {
        let packet = receive_socket_before(&mut self.endpoint, self.peer, self.deadline)?;
        match decode_frame(
            &packet.bytes,
            SenderRole::Coordinator,
            self.nonce,
            MAX_LINUX_HELLO_PAYLOAD as u32,
        )
        .map_err(LinuxSpawnError::Negotiation)?
        {
            NegotiationFrame::Accept(accept) => {
                self.transcript
                    .validate_accept(accept, SenderRole::Coordinator)
                    .map_err(LinuxSpawnError::Negotiation)?;
            }
            NegotiationFrame::Reject(reject) => {
                let reason = self
                    .transcript
                    .validate_reject(reject, SenderRole::Coordinator)
                    .map_err(LinuxSpawnError::Negotiation)?;
                return Ok(CoordinatorDecisionOutcome::Rejected {
                    reason,
                    state: RejectedLinuxReceiver {
                        _endpoint: self.endpoint,
                        not_sync: PhantomData,
                    },
                });
            }
            NegotiationFrame::Hello(_) => {
                return Err(LinuxSpawnError::Negotiation(NegotiationWireError::BadKind));
            }
        }
        Ok(CoordinatorDecisionOutcome::Pending(Box::new(
            ReceiverDecisionPending {
                endpoint: self.endpoint,
                transcript: self.transcript,
                deadline: self.deadline,
                nonce: self.nonce,
                parent: self.peer,
                child: self.local,
                not_sync: PhantomData,
            },
        )))
    }
}

impl ReceiverDecisionPending {
    fn decide(
        mut self,
        decision: ApplicationDecision,
    ) -> Result<DecisionOutcome<AcceptedLinuxReceiver, RejectedLinuxReceiver>, LinuxSpawnError>
    {
        match decision {
            ApplicationDecision::Reject(reason) => {
                let reject = self
                    .transcript
                    .receiver_reject(reason)
                    .map_err(LinuxSpawnError::Negotiation)?;
                let frame = NegotiationFrame::Reject(reject);
                let encoded = encode_negotiation_frame(&frame)?;
                send_socket_before(&mut self.endpoint, &encoded, self.deadline)?;
                Ok(DecisionOutcome::Rejected {
                    by: SenderRole::Receiver,
                    reason,
                    state: RejectedLinuxReceiver {
                        _endpoint: self.endpoint,
                        not_sync: PhantomData,
                    },
                })
            }
            ApplicationDecision::Accept => {
                let accept = self
                    .transcript
                    .receiver_accept()
                    .map_err(LinuxSpawnError::Negotiation)?;
                self.transcript
                    .validate_accept(accept, SenderRole::Receiver)
                    .map_err(LinuxSpawnError::Negotiation)?;
                let encoded = encode_negotiation_frame(&NegotiationFrame::Accept(accept))?;
                send_socket_before(&mut self.endpoint, &encoded, self.deadline)?;
                Ok(DecisionOutcome::Accepted(AcceptedLinuxReceiver {
                    endpoint: self.endpoint,
                    transcript: self.transcript,
                    nonce: self.nonce,
                    parent: self.parent,
                    child: self.child,
                    not_sync: PhantomData,
                }))
            }
        }
    }
}

impl AcceptedLinuxSpawn {
    fn pid(&self) -> libc::pid_t {
        self.lifecycle.as_ref().expect("live accepted owner").pid()
    }

    fn terminate_and_reap(mut self, deadline: AbsoluteDeadline) -> ExactChildCleanup {
        self.lifecycle
            .take()
            .expect("live accepted owner retains exact child lifecycle")
            .terminate_and_reap(deadline)
    }

    fn into_evidence(
        mut self,
    ) -> Result<CoordinatorAcceptedEvidenceOwner, (LinuxSpawnError, ExactChildCleanup)> {
        let evidence = (|| {
            let transcript = self
                .transcript
                .take_accepted_facts()
                .map_err(LinuxSpawnError::Negotiation)?;
            // SAFETY: scalar identity queries have no pointer arguments.
            let parent_pid = unsafe { libc::getpid() } as u32;
            // SAFETY: scalar identity queries have no pointer arguments.
            let parent_uid = unsafe { libc::getuid() };
            // SAFETY: scalar identity queries have no pointer arguments.
            let parent_gid = unsafe { libc::getgid() };
            let facts = SpawnIdentityFacts::new(
                parent_pid,
                self.child.pid,
                parent_uid,
                parent_gid,
                self.child.uid,
                self.child.gid,
                self.nonce,
            )
            .ok_or(LinuxSpawnError::InvalidInput)?;
            // SAFETY: this owner retains the exact accepted child socket and its
            // per-message credentials for these facts.
            let channel = unsafe { CoordinatorChildChannelReceipt::from_verified_native(facts) };
            // SAFETY: this owner retains the held image and sole clone-time pidfd
            // that passed the final live/image/live sandwich for these facts.
            let image = unsafe { CoordinatorChildImageReceipt::from_verified_native(facts) };
            CoordinatorAcceptedEvidence::combine(channel, image, transcript)
                .map_err(|_| LinuxSpawnError::InvalidInput)
        })();
        let evidence = match evidence {
            Ok(evidence) => evidence,
            Err(error) => {
                let deadline = self.deadline;
                let cleanup = self.terminate_and_reap(deadline);
                return Err((error, cleanup));
            }
        };
        Ok(CoordinatorAcceptedEvidenceOwner {
            lifecycle: self.lifecycle.take(),
            endpoint: self.endpoint,
            executable: self.executable,
            evidence,
            deadline: self.deadline,
            not_sync: PhantomData,
        })
    }
}

impl AcceptedLinuxReceiver {
    fn into_evidence(mut self) -> Result<ReceiverAcceptedEvidenceOwner, LinuxSpawnError> {
        let transcript = self
            .transcript
            .take_accepted_facts()
            .map_err(LinuxSpawnError::Negotiation)?;
        let facts = SpawnIdentityFacts::new(
            self.parent.pid,
            self.child.pid,
            self.parent.uid,
            self.parent.gid,
            self.child.uid,
            self.child.gid,
            self.nonce,
        )
        .ok_or(LinuxSpawnError::InvalidInput)?;
        // SAFETY: these facts were captured from the validated inherited
        // parent packet and local child identity during the exact HELLO flow.
        let evidence = unsafe { ReceiverSpawnerEvidence::from_verified_native(facts, transcript) }
            .map_err(|_| LinuxSpawnError::InvalidInput)?;
        Ok(ReceiverAcceptedEvidenceOwner {
            endpoint: self.endpoint,
            evidence,
            not_sync: PhantomData,
        })
    }
}

impl CoordinatorAcceptedEvidenceOwner {
    fn pid(&self) -> libc::pid_t {
        self.lifecycle.as_ref().expect("live evidence owner").pid()
    }

    fn facts(&self) -> SpawnIdentityFacts {
        self.evidence.facts()
    }

    #[cfg(test)]
    fn terminate_and_reap(mut self, deadline: AbsoluteDeadline) -> ExactChildCleanup {
        self.lifecycle
            .take()
            .expect("live evidence owner retains exact child lifecycle")
            .terminate_and_reap(deadline)
    }

    fn into_control(
        self,
    ) -> Result<CoordinatorAcceptedControl, (LinuxSpawnError, ChildCleanupFacts)> {
        let facts = self.evidence.facts();
        let parameters = self
            .evidence
            .session_parameters(NativeAuthorityProfile::LinuxMdweV1);
        let transport = CoordinatorLinuxControlTransport {
            lifecycle: self.lifecycle,
            endpoint: self.endpoint,
            _executable: self.executable,
            _evidence: self.evidence,
            peer: PacketCredentials {
                pid: facts.child_pid(),
                uid: facts.child_uid(),
                gid: facts.child_gid(),
            },
            poisoned: false,
            #[cfg(test)]
            poison_observer: None,
            not_sync: PhantomData,
        };
        match AcceptedControlDispatcher::new(transport, parameters) {
            Ok(dispatcher) => Ok(dispatcher),
            Err(mut transport) => {
                let cleanup = transport.terminate_and_reap_facts(self.deadline);
                Err((LinuxSpawnError::InvalidInput, cleanup))
            }
        }
    }
}

impl ReceiverAcceptedEvidenceOwner {
    fn facts(&self) -> SpawnIdentityFacts {
        self.evidence.facts()
    }

    fn into_control(self) -> Result<ReceiverAcceptedControl, LinuxSpawnError> {
        let facts = self.evidence.facts();
        let parameters = self
            .evidence
            .session_parameters(NativeAuthorityProfile::LinuxMdweV1);
        let transport = ReceiverLinuxControlTransport {
            endpoint: self.endpoint,
            _evidence: self.evidence,
            peer: PacketCredentials {
                pid: facts.parent_pid(),
                uid: facts.parent_uid(),
                gid: facts.parent_gid(),
            },
            poisoned: false,
            #[cfg(test)]
            poison_observer: None,
            not_sync: PhantomData,
        };
        AcceptedControlDispatcher::new(transport, parameters)
            .map_err(|_| LinuxSpawnError::InvalidInput)
    }
}

impl LinuxCoordinatorNegotiatingSession {
    pub(crate) fn spawn(
        command: &SessionCommand,
        options: &SessionOptions,
    ) -> Result<Self, LinuxCoordinatorSessionFailure> {
        let offer = public_linux_offer(
            options.limits(),
            options.application_payload().to_vec(),
            options.requires_atomic_u32(),
            options.requires_atomic_u64(),
        );
        let mut public_environment = command.environment().to_vec();
        public_environment.push((OsString::from(PUBLIC_BOOTSTRAP_ENV), OsString::from("1")));
        spawn_negotiating(
            command.executable(),
            command.arguments(),
            &public_environment,
            offer,
            options.deadline(),
        )
        .map(Self)
        .map_err(|failure| LinuxCoordinatorSessionFailure {
            error: map_public_spawn_error(failure.error),
            cleanup: failure.cleanup.map(map_child_cleanup),
            state: failure.state,
            poisoned: failure.cleanup.is_some(),
        })
    }

    pub(crate) fn peer_application_payload(&self) -> &[u8] {
        &self.0._peer_application_payload
    }

    pub(crate) fn decide(
        self,
        rejection: Option<NonZeroU32>,
    ) -> Result<LinuxNegotiationOutcome<LinuxCoordinatorReadySession>, LinuxCoordinatorSessionFailure>
    {
        let decision = rejection.map_or(ApplicationDecision::Accept, ApplicationDecision::Reject);
        match self.0.decide(decision).map_err(|(error, cleanup)| {
            LinuxCoordinatorSessionFailure {
                error: map_public_spawn_error(error),
                cleanup: Some(map_child_cleanup(cleanup)),
                state: LinuxCoordinatorFailureState::Negotiating,
                poisoned: true,
            }
        })? {
            DecisionOutcome::Accepted(accepted) => {
                let evidence = accepted.into_evidence().map_err(|(error, cleanup)| {
                    LinuxCoordinatorSessionFailure {
                        error: map_public_spawn_error(error),
                        cleanup: Some(map_child_cleanup(cleanup)),
                        state: LinuxCoordinatorFailureState::Negotiating,
                        poisoned: true,
                    }
                })?;
                let control = evidence.into_control().map_err(|(error, cleanup)| {
                    LinuxCoordinatorSessionFailure {
                        error: map_public_spawn_error(error),
                        cleanup: Some(cleanup),
                        state: LinuxCoordinatorFailureState::Negotiating,
                        poisoned: true,
                    }
                })?;
                Ok(LinuxNegotiationOutcome::Accepted(
                    LinuxCoordinatorReadySession(control),
                ))
            }
            DecisionOutcome::Rejected {
                by,
                reason,
                state: cleanup,
            } => Ok(LinuxNegotiationOutcome::Rejected {
                by: map_negotiation_role(by),
                reason,
                cleanup: Some(map_child_cleanup(cleanup)),
            }),
        }
    }
}

impl LinuxReceiverNegotiatingSession {
    pub(crate) fn from_inherited_bootstrap(
        inherited: OwnedFd,
        limits: SessionLimits,
        application_payload: Vec<u8>,
        require_atomic_u32: bool,
        require_atomic_u64: bool,
        deadline: AbsoluteDeadline,
    ) -> Result<Self, LinuxPublicSessionError> {
        let offer = public_linux_offer(
            limits,
            application_payload,
            require_atomic_u32,
            require_atomic_u64,
        );
        receive_inherited_hello_owned(inherited, offer, deadline)
            .map(Self)
            .map_err(map_public_spawn_error)
    }

    pub(crate) fn peer_application_payload(&self) -> &[u8] {
        &self.0._peer_application_payload
    }

    pub(crate) fn decide_after_coordinator(
        self,
        decide: impl FnOnce(&[u8]) -> Option<NonZeroU32>,
    ) -> Result<LinuxNegotiationOutcome<LinuxReceiverReadySession>, LinuxPublicSessionError> {
        let mut state = self.0;
        let peer_application_payload = core::mem::take(&mut state._peer_application_payload);
        match state
            .await_coordinator_decision()
            .map_err(map_public_spawn_error)?
        {
            CoordinatorDecisionOutcome::Rejected { reason, .. } => {
                Ok(LinuxNegotiationOutcome::Rejected {
                    by: LinuxNegotiationRole::Coordinator,
                    reason,
                    cleanup: None,
                })
            }
            CoordinatorDecisionOutcome::Pending(pending) => {
                let decision = decide(&peer_application_payload)
                    .map_or(ApplicationDecision::Accept, ApplicationDecision::Reject);
                match pending.decide(decision).map_err(map_public_spawn_error)? {
                    DecisionOutcome::Accepted(accepted) => {
                        let evidence = accepted.into_evidence().map_err(map_public_spawn_error)?;
                        let control = evidence.into_control().map_err(map_public_spawn_error)?;
                        Ok(LinuxNegotiationOutcome::Accepted(
                            LinuxReceiverReadySession(control),
                        ))
                    }
                    DecisionOutcome::Rejected { by, reason, .. } => {
                        Ok(LinuxNegotiationOutcome::Rejected {
                            by: map_negotiation_role(by),
                            reason,
                            cleanup: None,
                        })
                    }
                }
            }
        }
    }
}

impl LinuxCoordinatorReadySession {
    pub(crate) const fn limits(&self) -> SessionLimits {
        self.0.limits()
    }

    pub(crate) const fn atomics(&self) -> AtomicCapabilities {
        self.0.atomics()
    }

    pub(crate) const fn protocol_version(&self) -> ProtocolVersion {
        self.0.protocol_version()
    }

    pub(crate) fn state(&self) -> SessionState {
        self.0.session_state()
    }

    pub(crate) fn active_leases(&self) -> ActiveLeaseFacts {
        self.0.active_lease_facts()
    }

    pub(crate) fn poll_peer(&mut self) -> Result<PeerStatus, LinuxPublicSessionError> {
        self.0
            .try_poll_peer()
            .map(|state| match state {
                PeerState::Running => PeerStatus::Connected,
                PeerState::ExitedUnknown => PeerStatus::Disconnected,
            })
            .map_err(map_public_control_error)
    }

    pub(crate) fn wait_for_exit(&mut self, deadline: AbsoluteDeadline) -> ChildCleanupFacts {
        self.0.wait_for_linux_child(deadline)
    }

    pub(crate) fn close_resources(&mut self) -> Result<(), LinuxPublicSessionError> {
        self.0
            .try_close_resources()
            .map_err(map_close_resource_error)
    }

    pub(crate) fn abort(&mut self, deadline: AbsoluteDeadline) -> ChildCleanupFacts {
        self.0.abort_linux_child(deadline)
    }

    #[cfg(test)]
    pub(crate) fn fail_next_cleanup_signal_for_test(&self, code: i32) {
        self.0.fail_next_linux_cleanup_signal_for_test(code);
    }

    pub(crate) fn send_control(
        &mut self,
        kind: u32,
        payload: &[u8],
        deadline: AbsoluteDeadline,
    ) -> Result<(), LinuxPublicSessionError> {
        self.0
            .send_parts(kind, payload, deadline)
            .map_err(map_public_control_error)
    }

    pub(crate) fn receive_control(
        &mut self,
        deadline: AbsoluteDeadline,
    ) -> Result<ControlFrame, LinuxPublicSessionError> {
        self.0.receive(deadline).map_err(map_public_control_error)
    }

    pub(crate) fn transfer_batch(
        &mut self,
        batch: TransferBatch,
        deadline: AbsoluteDeadline,
    ) -> Result<ActiveRegionSet, LinuxPublicReadyFailure> {
        if deadline.is_expired() {
            return Err(LinuxPublicReadyFailure::before_transaction(
                LinuxPublicSessionError::DeadlineExpired,
            ));
        }
        let frame = self
            .0
            .begin_public_linux_transfer_capacity(&batch, deadline)
            .map_err(map_public_batch_transaction_error)
            .map_err(LinuxPublicReadyFailure::before_transaction)?;
        let reservations = self.0.reserve_linux_transfer_batch(&batch);
        let preparation = reservations.as_ref().ok().map(|_| {
            LinuxMixedDirectionBatch::prepare(batch, self.0.authority_profile(), deadline)
        });
        let local_status = if reservations.is_err() {
            CoordinatorCapacityStatus::ActiveLimit
        } else if preparation
            .as_ref()
            .is_some_and(|prepared| prepared.is_err())
        {
            CoordinatorCapacityStatus::PreparationFailed
        } else {
            CoordinatorCapacityStatus::Ready
        };
        let peer_ready = self
            .0
            .exchange_public_linux_transfer_capacity(&frame, local_status, deadline)
            .map_err(map_public_batch_transaction_error)
            .map_err(LinuxPublicReadyFailure::after_transaction)?;
        let reservations = reservations
            .map_err(|_| LinuxPublicSessionError::ActiveLimit)
            .map_err(LinuxPublicReadyFailure::ready_after_transaction)?;
        let prepared = preparation
            .expect("successful reservation attempts native preparation")
            .map_err(map_public_local_memory_error)
            .map_err(LinuxPublicReadyFailure::ready_after_transaction)?;
        if !peer_ready {
            return Err(LinuxPublicReadyFailure::ready_after_transaction(
                LinuxPublicSessionError::ActiveLimit,
            ));
        }
        let mut transaction = self
            .0
            .begin_public_linux_mixed_direction_batch_preflighted(
                prepared,
                reservations,
                frame,
                deadline,
            )
            .map_err(map_public_batch_transaction_error)
            .map_err(LinuxPublicReadyFailure::after_transaction)?;
        transaction
            .prepare()
            .map_err(map_public_batch_transaction_error)
            .map_err(LinuxPublicReadyFailure::after_transaction)?;
        let committed = transaction
            .commit()
            .map_err(map_public_batch_transaction_error)
            .map_err(LinuxPublicReadyFailure::after_transaction)?;
        self.0
            .activate_linux_coordinator_mixed_direction_batch(committed)
            .map_err(map_public_activation_error)
            .map_err(LinuxPublicReadyFailure::after_transaction)
    }
}

impl LinuxReceiverReadySession {
    pub(crate) const fn limits(&self) -> SessionLimits {
        self.0.limits()
    }

    pub(crate) const fn atomics(&self) -> AtomicCapabilities {
        self.0.atomics()
    }

    pub(crate) const fn protocol_version(&self) -> ProtocolVersion {
        self.0.protocol_version()
    }

    pub(crate) fn state(&self) -> SessionState {
        self.0.session_state()
    }

    pub(crate) fn active_leases(&self) -> ActiveLeaseFacts {
        self.0.active_lease_facts()
    }

    pub(crate) fn poll_peer(&mut self) -> Result<PeerStatus, LinuxPublicSessionError> {
        self.0
            .try_poll_peer()
            .map(|state| match state {
                PeerState::Running => PeerStatus::Connected,
                PeerState::ExitedUnknown => PeerStatus::Disconnected,
            })
            .map_err(map_public_control_error)
    }

    pub(crate) fn wait_for_exit(
        &mut self,
        deadline: AbsoluteDeadline,
    ) -> Result<PeerStatus, LinuxPublicSessionError> {
        self.0
            .wait_for_linux_peer_exit(deadline)
            .map(|state| match state {
                PeerState::Running => PeerStatus::Connected,
                PeerState::ExitedUnknown => PeerStatus::Disconnected,
            })
            .map_err(map_public_transport_error)
    }

    pub(crate) fn close_resources(&mut self) -> Result<(), LinuxPublicSessionError> {
        self.0
            .try_close_resources()
            .map_err(map_close_resource_error)
    }

    pub(crate) fn abort(&mut self) {
        self.0.poison_session();
    }

    pub(crate) fn send_control(
        &mut self,
        kind: u32,
        payload: &[u8],
        deadline: AbsoluteDeadline,
    ) -> Result<(), LinuxPublicSessionError> {
        self.0
            .send_parts(kind, payload, deadline)
            .map_err(map_public_control_error)
    }

    pub(crate) fn receive_control(
        &mut self,
        deadline: AbsoluteDeadline,
    ) -> Result<ControlFrame, LinuxPublicSessionError> {
        self.0.receive(deadline).map_err(map_public_control_error)
    }

    pub(crate) fn receive_batch(
        &mut self,
        expected: ExpectedBatch,
        deadline: AbsoluteDeadline,
    ) -> Result<ActiveRegionSet, LinuxPublicReadyFailure> {
        let mut transaction = self
            .0
            .begin_public_linux_expected_mixed_direction_batch(expected, deadline)
            .map_err(
                |LinuxBatchBeginError {
                     error,
                     transaction_open_on_failure,
                 }| LinuxPublicReadyFailure {
                    error: map_public_receiver_begin_error(error),
                    transaction_open_on_failure,
                },
            )?;
        transaction
            .prepare()
            .map_err(map_public_receiver_transaction_error)
            .map_err(LinuxPublicReadyFailure::after_transaction)?;
        let committed = transaction
            .commit()
            .map_err(map_public_receiver_transaction_error)
            .map_err(LinuxPublicReadyFailure::after_transaction)?;
        self.0
            .activate_linux_receiver_mixed_direction_batch(committed)
            .map_err(map_public_activation_error)
            .map_err(LinuxPublicReadyFailure::after_transaction)
    }
}

fn public_linux_offer(
    limits: SessionLimits,
    application_payload: Vec<u8>,
    require_atomic_u32: bool,
    require_atomic_u64: bool,
) -> LinuxHelloOffer {
    let required = u64::from(require_atomic_u32) | (u64::from(require_atomic_u64) << 1);
    LinuxHelloOffer {
        supported_features: FeatureBits([3, 0]),
        required_features: FeatureBits([required, 0]),
        limits,
        application_payload,
    }
}

fn map_negotiation_role(role: SenderRole) -> LinuxNegotiationRole {
    match role {
        SenderRole::Coordinator => LinuxNegotiationRole::Coordinator,
        SenderRole::Receiver => LinuxNegotiationRole::Receiver,
    }
}

fn map_public_spawn_error(error: LinuxSpawnError) -> LinuxPublicSessionError {
    match error {
        LinuxSpawnError::InvalidInput => LinuxPublicSessionError::InvalidInput,
        LinuxSpawnError::DeadlineExpired => LinuxPublicSessionError::DeadlineExpired,
        LinuxSpawnError::ExitedBeforeConfirmation => LinuxPublicSessionError::PeerExited,
        LinuxSpawnError::WrongExecutable => LinuxPublicSessionError::IdentityMismatch,
        LinuxSpawnError::Negotiation(_) => LinuxPublicSessionError::NegotiationFailed,
        LinuxSpawnError::NativeNegotiation(error) => {
            LinuxPublicSessionError::NativeNegotiation(error)
        }
        LinuxSpawnError::Packet(error) => match error {
            PacketError::DeadlineExpired => LinuxPublicSessionError::DeadlineExpired,
            PacketError::PeerExited => LinuxPublicSessionError::PeerExited,
            PacketError::WrongPeer => LinuxPublicSessionError::IdentityMismatch,
            PacketError::Poisoned => LinuxPublicSessionError::Poisoned,
            PacketError::AmbiguousAfterSend | PacketError::AmbiguousAfterReceive => {
                LinuxPublicSessionError::Ambiguous
            }
            PacketError::Native(code) => LinuxPublicSessionError::Native(Some(code)),
            _ => LinuxPublicSessionError::MalformedPeer,
        },
        LinuxSpawnError::MalformedChildError => LinuxPublicSessionError::MalformedPeer,
        LinuxSpawnError::Child { errno, .. } => LinuxPublicSessionError::Native(Some(errno)),
        LinuxSpawnError::Native(code) => LinuxPublicSessionError::Native(Some(code)),
        LinuxSpawnError::EntropyUnavailable => LinuxPublicSessionError::Native(None),
    }
}

fn map_public_control_error(error: AcceptedControlError) -> LinuxPublicSessionError {
    match error {
        AcceptedControlError::Control(error) => LinuxPublicSessionError::Control(error),
        AcceptedControlError::Transport(error) => map_public_transport_error(error),
    }
}

fn map_public_local_memory_error(error: MemfdError) -> LinuxPublicSessionError {
    match error {
        MemfdError::DeadlineExpired => LinuxPublicSessionError::DeadlineExpired,
        MemfdError::InvalidSize
        | MemfdError::InvalidBatch
        | MemfdError::UnsupportedDirection
        | MemfdError::DeadlineMismatch => LinuxPublicSessionError::InvalidInput,
        MemfdError::InvalidObject
        | MemfdError::WrongObject
        | MemfdError::WrongProvenance
        | MemfdError::ExecutableAuthorityUnsupported => LinuxPublicSessionError::Native(None),
        MemfdError::Native(code) => LinuxPublicSessionError::Native(Some(code)),
    }
}

fn map_public_batch_transaction_error(error: LinuxCapabilityBatchError) -> LinuxPublicSessionError {
    match error {
        LinuxCapabilityBatchError::Memory(error) => map_public_local_memory_error(error),
        LinuxCapabilityBatchError::Control(error) => map_public_control_error(error),
        LinuxCapabilityBatchError::Resource(_) => LinuxPublicSessionError::ActiveLimit,
        LinuxCapabilityBatchError::ActiveLimit => LinuxPublicSessionError::ActiveLimit,
        LinuxCapabilityBatchError::PeerPreparationFailed => {
            LinuxPublicSessionError::PeerPreparationFailed
        }
    }
}

fn map_public_receiver_begin_error(error: LinuxCapabilityBatchError) -> LinuxPublicSessionError {
    match error {
        LinuxCapabilityBatchError::Memory(error) => map_public_local_memory_error(error),
        LinuxCapabilityBatchError::Control(error) => map_public_control_error(error),
        LinuxCapabilityBatchError::Resource(_) => LinuxPublicSessionError::ActiveLimit,
        LinuxCapabilityBatchError::ActiveLimit => LinuxPublicSessionError::ActiveLimit,
        LinuxCapabilityBatchError::PeerPreparationFailed => {
            LinuxPublicSessionError::PeerPreparationFailed
        }
    }
}

fn map_public_receiver_transaction_error(
    error: LinuxCapabilityBatchError,
) -> LinuxPublicSessionError {
    match error {
        LinuxCapabilityBatchError::Memory(error) => match error {
            MemfdError::DeadlineExpired => LinuxPublicSessionError::DeadlineExpired,
            MemfdError::InvalidSize
            | MemfdError::InvalidBatch
            | MemfdError::UnsupportedDirection
            | MemfdError::DeadlineMismatch
            | MemfdError::InvalidObject
            | MemfdError::WrongObject
            | MemfdError::WrongProvenance
            | MemfdError::ExecutableAuthorityUnsupported => LinuxPublicSessionError::MalformedPeer,
            MemfdError::Native(code) => LinuxPublicSessionError::Native(Some(code)),
        },
        LinuxCapabilityBatchError::Control(error) => map_public_control_error(error),
        LinuxCapabilityBatchError::Resource(_) => LinuxPublicSessionError::ActiveLimit,
        LinuxCapabilityBatchError::ActiveLimit => LinuxPublicSessionError::ActiveLimit,
        LinuxCapabilityBatchError::PeerPreparationFailed => {
            LinuxPublicSessionError::PeerPreparationFailed
        }
    }
}

fn map_public_activation_error(error: LinuxActivationError) -> LinuxPublicSessionError {
    match error {
        LinuxActivationError::Batch(error) => LinuxPublicSessionError::Batch(error),
        LinuxActivationError::Memory(MemfdError::Native(code)) => {
            LinuxPublicSessionError::ActivationFailed(Some(code))
        }
        LinuxActivationError::WrongSession
        | LinuxActivationError::Memory(_)
        | LinuxActivationError::Active(_) => LinuxPublicSessionError::ActivationFailed(None),
    }
}

fn map_close_resource_error(error: ResourceError) -> LinuxPublicSessionError {
    match error {
        ResourceError::ActiveLeases(_) | ResourceError::ActiveLimit => {
            LinuxPublicSessionError::ActiveLimit
        }
        ResourceError::Poisoned | ResourceError::Closed => LinuxPublicSessionError::Poisoned,
        ResourceError::InvalidLimits | ResourceError::MappedLengthMismatch { .. } => {
            LinuxPublicSessionError::Native(None)
        }
    }
}

fn map_public_transport_error(error: SessionTransportError) -> LinuxPublicSessionError {
    match error {
        SessionTransportError::DeadlineExpired => LinuxPublicSessionError::DeadlineExpired,
        SessionTransportError::PeerExited => LinuxPublicSessionError::PeerExited,
        SessionTransportError::MalformedRecord | SessionTransportError::RecordTooLarge => {
            LinuxPublicSessionError::MalformedPeer
        }
        SessionTransportError::IdentityMismatch => LinuxPublicSessionError::IdentityMismatch,
        SessionTransportError::Ambiguous => LinuxPublicSessionError::Ambiguous,
        SessionTransportError::Native(code) => LinuxPublicSessionError::Native(code),
    }
}

impl sealed::Sealed for CoordinatorLinuxControlTransport {}
impl sealed::Sealed for ReceiverLinuxControlTransport {}

impl AuthenticatedZeroRightsTransport for CoordinatorLinuxControlTransport {
    fn send_record(
        &mut self,
        bytes: &[u8],
        deadline: AbsoluteDeadline,
    ) -> Result<(), SessionTransportError> {
        let pidfd = self
            .lifecycle
            .as_ref()
            .ok_or(SessionTransportError::PeerExited)?
            .pidfd();
        send_accepted_control_record(
            &mut self.endpoint,
            Some(pidfd),
            &mut self.poisoned,
            bytes,
            deadline,
        )
    }

    fn receive_record(
        &mut self,
        maximum: usize,
        deadline: AbsoluteDeadline,
    ) -> Result<Vec<u8>, SessionTransportError> {
        let pidfd = self
            .lifecycle
            .as_ref()
            .ok_or(SessionTransportError::PeerExited)?
            .pidfd();
        receive_accepted_control_record(
            &mut self.endpoint,
            Some(pidfd),
            self.peer,
            &mut self.poisoned,
            maximum,
            deadline,
        )
    }

    fn try_poll_peer(&mut self) -> Result<PeerState, SessionTransportError> {
        if self.poisoned {
            return Err(SessionTransportError::Native(None));
        }
        let pidfd = self
            .lifecycle
            .as_ref()
            .ok_or(SessionTransportError::PeerExited)?
            .pidfd();
        observe_accepted_control_peer(self.endpoint.fd.as_raw_fd(), Some(pidfd))
    }

    fn poison(&mut self) {
        self.poisoned = true;
        #[cfg(test)]
        if let Some(observer) = &self.poison_observer {
            observer.lock().unwrap().push("poison");
        }
    }
}

impl CoordinatorLinuxControlTransport {
    pub(crate) fn wait_and_reap_facts(&mut self, deadline: AbsoluteDeadline) -> ChildCleanupFacts {
        let Some(lifecycle) = self.lifecycle.as_ref() else {
            return ChildCleanupFacts::new(
                Some(ChildExitStatus::AlreadyReaped),
                DescendantCleanupStatus::NotEstablished,
                None,
            );
        };
        map_child_cleanup(lifecycle.wait_and_reap(deadline))
    }

    pub(crate) fn terminate_and_reap_facts(
        &mut self,
        deadline: AbsoluteDeadline,
    ) -> ChildCleanupFacts {
        self.poisoned = true;
        let Some(lifecycle) = self.lifecycle.take() else {
            return ChildCleanupFacts::new(
                Some(ChildExitStatus::AlreadyReaped),
                DescendantCleanupStatus::NotEstablished,
                None,
            );
        };
        map_child_cleanup(lifecycle.terminate_and_reap(deadline))
    }

    #[cfg(test)]
    pub(crate) fn fail_next_cleanup_signal_for_test(&self, code: i32) {
        self.lifecycle
            .as_ref()
            .expect("live coordinator transport retains exact child lifecycle")
            .fail_next_signal_for_test(code);
    }

    #[cfg(test)]
    pub(crate) fn observe_poison_for_test(&mut self, observer: Arc<Mutex<Vec<&'static str>>>) {
        self.poison_observer = Some(observer);
    }

    #[cfg(test)]
    pub(crate) fn wait_and_reap_clean_for_test(
        &mut self,
        deadline: AbsoluteDeadline,
    ) -> Result<(), SessionTransportError> {
        self.poisoned = true;
        let lifecycle = self
            .lifecycle
            .take()
            .ok_or(SessionTransportError::PeerExited)?;
        let cleanup = lifecycle.wait_and_reap(deadline);
        if cleanup.direct_child_succeeded() {
            Ok(())
        } else if let Some(code) = cleanup.last_native_error() {
            Err(SessionTransportError::Native(Some(code)))
        } else {
            Err(SessionTransportError::DeadlineExpired)
        }
    }
}

fn map_child_cleanup(cleanup: ExactChildCleanup) -> ChildCleanupFacts {
    let direct_child = cleanup.direct_child().map(|exit| match exit {
        ExactChildExit::Exited(code) => ChildExitStatus::Exited(code),
        ExactChildExit::Signaled {
            signal,
            dumped_core,
        } => ChildExitStatus::Signaled {
            signal,
            dumped_core,
        },
        ExactChildExit::AlreadyReaped => ChildExitStatus::AlreadyReaped,
    });
    let descendants = match cleanup.descendants() {
        DescendantCleanup::NotEstablished => DescendantCleanupStatus::NotEstablished,
        DescendantCleanup::FreshGroupUnverified => DescendantCleanupStatus::FreshGroupUnverified,
        DescendantCleanup::FreshGroupTerminated => DescendantCleanupStatus::FreshGroupTerminated,
    };
    ChildCleanupFacts::new(direct_child, descendants, cleanup.last_native_error())
}

impl OwnedChildLifecycle for CoordinatorLinuxControlTransport {
    fn terminate_and_reap(
        &mut self,
        deadline: AbsoluteDeadline,
    ) -> Result<(), SessionTransportError> {
        self.poisoned = true;
        let lifecycle = self
            .lifecycle
            .take()
            .ok_or(SessionTransportError::PeerExited)?;
        let cleanup = lifecycle.terminate_and_reap(deadline);
        if cleanup.direct_child_complete() {
            Ok(())
        } else if let Some(code) = cleanup.last_native_error() {
            Err(SessionTransportError::Native(Some(code)))
        } else {
            Err(SessionTransportError::DeadlineExpired)
        }
    }
}

impl CoordinatorCapabilityTransport for CoordinatorLinuxControlTransport {
    type Capabilities<'a> = &'a [BorrowedFd<'a>];

    fn send_capability_record(
        &mut self,
        frame: &CapabilityFrame,
        capabilities: Self::Capabilities<'_>,
        deadline: AbsoluteDeadline,
    ) -> Result<(), SessionTransportError> {
        let pidfd = self
            .lifecycle
            .as_ref()
            .ok_or(SessionTransportError::PeerExited)?
            .pidfd();
        let mut raw = [-1; super::MAX_PACKET_FDS];
        if capabilities.len() != frame.capability_count() || capabilities.len() > raw.len() {
            return Err(SessionTransportError::MalformedRecord);
        }
        for (destination, capability) in raw.iter_mut().zip(capabilities) {
            *destination = capability.as_raw_fd();
        }
        send_accepted_capability_record(
            &mut self.endpoint,
            Some(pidfd),
            &mut self.poisoned,
            frame,
            &raw[..capabilities.len()],
            deadline,
        )
    }
}

impl AuthenticatedZeroRightsTransport for ReceiverLinuxControlTransport {
    fn send_record(
        &mut self,
        bytes: &[u8],
        deadline: AbsoluteDeadline,
    ) -> Result<(), SessionTransportError> {
        send_accepted_control_record(
            &mut self.endpoint,
            None,
            &mut self.poisoned,
            bytes,
            deadline,
        )
    }

    fn receive_record(
        &mut self,
        maximum: usize,
        deadline: AbsoluteDeadline,
    ) -> Result<Vec<u8>, SessionTransportError> {
        receive_accepted_control_record(
            &mut self.endpoint,
            None,
            self.peer,
            &mut self.poisoned,
            maximum,
            deadline,
        )
    }

    fn try_poll_peer(&mut self) -> Result<PeerState, SessionTransportError> {
        if self.poisoned {
            return Err(SessionTransportError::Native(None));
        }
        observe_accepted_control_peer(self.endpoint.fd.as_raw_fd(), None)
    }

    fn poison(&mut self) {
        self.poisoned = true;
        #[cfg(test)]
        if let Some(observer) = &self.poison_observer {
            observer.lock().unwrap().push("poison");
        }
    }
}

impl ReceiverCapabilityTransport for ReceiverLinuxControlTransport {
    type ReceivedCapabilities = LinuxReceivedCapabilities;

    fn receive_capability_record(
        &mut self,
        expected: &CapabilityFrame,
        deadline: AbsoluteDeadline,
    ) -> Result<Self::ReceivedCapabilities, SessionTransportError> {
        receive_accepted_capability_record(
            &mut self.endpoint,
            None,
            self.peer,
            &mut self.poisoned,
            expected,
            deadline,
        )
    }
}

impl ReceiverLinuxControlTransport {
    pub(crate) fn wait_for_peer_exit(
        &mut self,
        deadline: AbsoluteDeadline,
    ) -> Result<PeerState, SessionTransportError> {
        if self.poisoned {
            return Err(SessionTransportError::Native(None));
        }
        loop {
            let remaining = deadline.remaining();
            if remaining.is_zero() {
                return Err(SessionTransportError::DeadlineExpired);
            }
            let timeout = remaining
                .as_nanos()
                .div_ceil(1_000_000)
                .min(i32::MAX as u128) as libc::c_int;
            let mut event = libc::pollfd {
                fd: self.endpoint.fd.as_raw_fd(),
                events: 0,
                revents: 0,
            };
            // SAFETY: event is one initialized descriptor for bounded poll.
            let result = unsafe { libc::poll(&mut event, 1, timeout) };
            if result < 0 {
                if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(SessionTransportError::Native(
                    io::Error::last_os_error().raw_os_error(),
                ));
            }
            if deadline.is_expired() || result == 0 {
                return Err(SessionTransportError::DeadlineExpired);
            }
            if event.revents & libc::POLLNVAL != 0 {
                return Err(SessionTransportError::Native(Some(libc::EBADF)));
            }
            if event.revents & (libc::POLLERR | libc::POLLHUP) != 0 {
                return Ok(PeerState::ExitedUnknown);
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn observe_poison_for_test(&mut self, observer: Arc<Mutex<Vec<&'static str>>>) {
        self.poison_observer = Some(observer);
    }

    pub(crate) fn receive_candidate_capability_record(
        &mut self,
        expected_descriptors: usize,
        deadline: AbsoluteDeadline,
    ) -> Result<LinuxReceivedCapabilityRecord, SessionTransportError> {
        receive_candidate_capability_record(
            &mut self.endpoint,
            None,
            self.peer,
            &mut self.poisoned,
            expected_descriptors,
            deadline,
        )
    }

    #[cfg(test)]
    pub(crate) fn send_record_with_rights_for_test(
        &mut self,
        bytes: &[u8],
        rights: &[RawFd],
        deadline: AbsoluteDeadline,
    ) -> Result<(), SessionTransportError> {
        if self.poisoned || rights.is_empty() || rights.len() > super::MAX_PACKET_FDS {
            return Err(SessionTransportError::MalformedRecord);
        }
        loop {
            if deadline.is_expired() {
                return Err(SessionTransportError::DeadlineExpired);
            }
            match self.endpoint.send(bytes, rights) {
                Ok(()) => {
                    if deadline.is_expired() {
                        self.poisoned = true;
                        return Err(SessionTransportError::DeadlineExpired);
                    }
                    return Ok(());
                }
                Err(PacketError::Interrupted) => continue,
                Err(PacketError::WouldBlock) => poll_accepted_control(
                    self.endpoint.fd.as_raw_fd(),
                    None,
                    libc::POLLOUT,
                    deadline,
                )?,
                Err(error) => return Err(map_packet_transport_error(error)),
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn send_record_from_fork_for_test(
        &mut self,
        bytes: &[u8],
    ) -> Result<(), SessionTransportError> {
        // SAFETY: the disposable child performs one async-signal-safe sendmsg
        // through the inherited endpoint and exits without Rust teardown.
        let child = unsafe { libc::fork() };
        if child < 0 {
            return Err(SessionTransportError::Native(
                io::Error::last_os_error().raw_os_error(),
            ));
        }
        if child == 0 {
            let status = i32::from(self.endpoint.send_zero_rights(bytes).is_err());
            // SAFETY: this is the disposable post-fork child.
            unsafe { libc::_exit(status) }
        }
        let mut status = 0;
        loop {
            // SAFETY: this process owns the exact disposable child.
            let waited = unsafe { libc::waitpid(child, &mut status, 0) };
            if waited == child {
                break;
            }
            if waited < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return Err(SessionTransportError::Native(
                io::Error::last_os_error().raw_os_error(),
            ));
        }
        if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
            Ok(())
        } else {
            Err(SessionTransportError::Native(None))
        }
    }
}

fn send_accepted_control_record(
    endpoint: &mut SeqPacketEndpoint,
    peer_pidfd: Option<RawFd>,
    poisoned: &mut bool,
    bytes: &[u8],
    deadline: AbsoluteDeadline,
) -> Result<(), SessionTransportError> {
    if *poisoned {
        return Err(SessionTransportError::Native(None));
    }
    if bytes.is_empty() || bytes.len() > MAX_ZERO_RIGHTS_PACKET_BYTES {
        return Err(SessionTransportError::RecordTooLarge);
    }
    loop {
        if let Some(pidfd) = peer_pidfd {
            super::ensure_running(pidfd, deadline).map_err(map_packet_transport_error)?;
        } else if deadline.is_expired() {
            return Err(SessionTransportError::DeadlineExpired);
        }
        match endpoint.send_zero_rights(bytes) {
            Ok(()) => {
                if deadline.is_expired() {
                    *poisoned = true;
                    return Err(SessionTransportError::DeadlineExpired);
                }
                return Ok(());
            }
            Err(PacketError::Interrupted) => continue,
            Err(PacketError::WouldBlock) => {
                poll_accepted_control(
                    endpoint.fd.as_raw_fd(),
                    peer_pidfd,
                    libc::POLLOUT,
                    deadline,
                )?;
            }
            Err(error) => return Err(map_packet_transport_error(error)),
        }
    }
}

fn receive_accepted_control_record(
    endpoint: &mut SeqPacketEndpoint,
    peer_pidfd: Option<RawFd>,
    peer: PacketCredentials,
    poisoned: &mut bool,
    maximum: usize,
    deadline: AbsoluteDeadline,
) -> Result<Vec<u8>, SessionTransportError> {
    if *poisoned {
        return Err(SessionTransportError::Native(None));
    }
    if maximum == 0 || maximum > MAX_ZERO_RIGHTS_PACKET_BYTES {
        return Err(SessionTransportError::RecordTooLarge);
    }
    loop {
        if deadline.is_expired() {
            return Err(SessionTransportError::DeadlineExpired);
        }
        match endpoint.receive_zero_rights_bounded(maximum, peer) {
            Ok(packet) => {
                if deadline.is_expired() {
                    *poisoned = true;
                    return Err(SessionTransportError::DeadlineExpired);
                }
                debug_assert!(packet.descriptors.is_empty());
                debug_assert_eq!(packet.credentials, peer);
                return Ok(packet.bytes);
            }
            Err(PacketError::Interrupted) => continue,
            Err(PacketError::WouldBlock) => {
                poll_accepted_control(endpoint.fd.as_raw_fd(), peer_pidfd, libc::POLLIN, deadline)?;
            }
            Err(error) => return Err(map_packet_transport_error(error)),
        }
    }
}

fn send_accepted_capability_record(
    endpoint: &mut SeqPacketEndpoint,
    peer_pidfd: Option<RawFd>,
    poisoned: &mut bool,
    frame: &CapabilityFrame,
    capabilities: &[RawFd],
    deadline: AbsoluteDeadline,
) -> Result<(), SessionTransportError> {
    if *poisoned {
        return Err(SessionTransportError::Native(None));
    }
    if capabilities.is_empty()
        || capabilities.len() > super::MAX_PACKET_FDS
        || capabilities.iter().any(|descriptor| *descriptor < 0)
    {
        return Err(SessionTransportError::MalformedRecord);
    }
    loop {
        if let Some(pidfd) = peer_pidfd {
            super::ensure_running(pidfd, deadline).map_err(map_packet_transport_error)?;
        } else if deadline.is_expired() {
            return Err(SessionTransportError::DeadlineExpired);
        }
        match endpoint.send(frame.as_bytes(), capabilities) {
            Ok(()) => {
                if deadline.is_expired() {
                    *poisoned = true;
                    return Err(SessionTransportError::DeadlineExpired);
                }
                return Ok(());
            }
            Err(PacketError::Interrupted) => continue,
            Err(PacketError::WouldBlock) => {
                poll_accepted_control(
                    endpoint.fd.as_raw_fd(),
                    peer_pidfd,
                    libc::POLLOUT,
                    deadline,
                )?;
            }
            Err(error) => return Err(map_packet_transport_error(error)),
        }
    }
}

fn receive_accepted_capability_record(
    endpoint: &mut SeqPacketEndpoint,
    peer_pidfd: Option<RawFd>,
    peer: PacketCredentials,
    poisoned: &mut bool,
    expected: &CapabilityFrame,
    deadline: AbsoluteDeadline,
) -> Result<LinuxReceivedCapabilities, SessionTransportError> {
    let record = receive_candidate_capability_record(
        endpoint,
        peer_pidfd,
        peer,
        poisoned,
        expected.capability_count(),
        deadline,
    )?;
    if record.frame.as_slice() != expected.as_bytes() {
        return Err(SessionTransportError::MalformedRecord);
    }
    Ok(LinuxReceivedCapabilities {
        descriptors: record.descriptors,
    })
}

fn receive_candidate_capability_record(
    endpoint: &mut SeqPacketEndpoint,
    peer_pidfd: Option<RawFd>,
    peer: PacketCredentials,
    poisoned: &mut bool,
    expected_descriptors: usize,
    deadline: AbsoluteDeadline,
) -> Result<LinuxReceivedCapabilityRecord, SessionTransportError> {
    if *poisoned {
        return Err(SessionTransportError::Native(None));
    }
    if !(1..=super::MAX_PACKET_FDS).contains(&expected_descriptors) {
        return Err(SessionTransportError::MalformedRecord);
    }
    loop {
        if deadline.is_expired() {
            return Err(SessionTransportError::DeadlineExpired);
        }
        match endpoint.receive(CONTROL_FRAME_LEN, peer, expected_descriptors) {
            Ok(packet) => {
                if deadline.is_expired() {
                    *poisoned = true;
                    return Err(SessionTransportError::DeadlineExpired);
                }
                debug_assert_eq!(packet.credentials, peer);
                debug_assert_eq!(packet.descriptors.len(), expected_descriptors);
                return Ok(LinuxReceivedCapabilityRecord {
                    frame: packet.bytes,
                    descriptors: packet.descriptors,
                });
            }
            Err(PacketError::Interrupted) => continue,
            Err(PacketError::WouldBlock) => {
                poll_accepted_control(endpoint.fd.as_raw_fd(), peer_pidfd, libc::POLLIN, deadline)?;
            }
            Err(error) => return Err(map_packet_transport_error(error)),
        }
    }
}

fn poll_accepted_control(
    socket: RawFd,
    peer_pidfd: Option<RawFd>,
    requested: libc::c_short,
    deadline: AbsoluteDeadline,
) -> Result<(), SessionTransportError> {
    match peer_pidfd {
        Some(pidfd) => super::poll_until(socket, pidfd, requested, deadline)
            .map_err(map_packet_transport_error),
        None => poll_socket(socket, requested, deadline).map_err(map_spawn_transport_error),
    }
}

fn observe_accepted_control_peer(
    socket: RawFd,
    peer_pidfd: Option<RawFd>,
) -> Result<PeerState, SessionTransportError> {
    observe_accepted_control_peer_with(socket, peer_pidfd, |descriptors, count, timeout| {
        // SAFETY: the caller supplies `count` initialized writable pollfd entries.
        let result = unsafe { libc::poll(descriptors, count, timeout) };
        if result < 0 {
            Err(io::Error::last_os_error().raw_os_error().unwrap_or(-1))
        } else {
            Ok(result)
        }
    })
}

fn observe_accepted_control_peer_with(
    socket: RawFd,
    peer_pidfd: Option<RawFd>,
    mut poll_once: impl FnMut(*mut libc::pollfd, libc::nfds_t, libc::c_int) -> Result<libc::c_int, i32>,
) -> Result<PeerState, SessionTransportError> {
    let mut descriptors = [
        libc::pollfd {
            fd: socket,
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: peer_pidfd.unwrap_or(-1),
            events: libc::POLLIN,
            revents: 0,
        },
    ];
    let count = if peer_pidfd.is_some() { 2 } else { 1 };
    match poll_once(descriptors.as_mut_ptr(), count, 0) {
        Ok(_) => {}
        Err(libc::EINTR) => return Ok(PeerState::Running),
        Err(code) => return Err(SessionTransportError::Native(Some(code))),
    }
    if descriptors[0].revents & libc::POLLNVAL != 0 {
        return Err(SessionTransportError::Native(Some(libc::EBADF)));
    }
    if descriptors[0].revents & (libc::POLLERR | libc::POLLHUP) != 0
        || (peer_pidfd.is_some() && descriptors[1].revents != 0)
    {
        return Ok(PeerState::ExitedUnknown);
    }
    Ok(PeerState::Running)
}

fn map_packet_transport_error(error: PacketError) -> SessionTransportError {
    match error {
        PacketError::DeadlineExpired => SessionTransportError::DeadlineExpired,
        PacketError::PeerExited => SessionTransportError::PeerExited,
        PacketError::WrongPeer => SessionTransportError::IdentityMismatch,
        PacketError::RecordTooLarge => SessionTransportError::RecordTooLarge,
        PacketError::InvalidInput
        | PacketError::Truncated
        | PacketError::MalformedAncillary
        | PacketError::WrongDescriptorCount => SessionTransportError::MalformedRecord,
        PacketError::AmbiguousAfterSend | PacketError::AmbiguousAfterReceive => {
            SessionTransportError::Ambiguous
        }
        PacketError::WouldBlock | PacketError::Interrupted | PacketError::Poisoned => {
            SessionTransportError::Native(None)
        }
        PacketError::Native(code) => SessionTransportError::Native(Some(code)),
    }
}

fn map_spawn_transport_error(error: LinuxSpawnError) -> SessionTransportError {
    match error {
        LinuxSpawnError::DeadlineExpired => SessionTransportError::DeadlineExpired,
        LinuxSpawnError::ExitedBeforeConfirmation => SessionTransportError::PeerExited,
        LinuxSpawnError::Packet(error) => map_packet_transport_error(error),
        LinuxSpawnError::Child { errno, .. } | LinuxSpawnError::Native(errno) => {
            SessionTransportError::Native(Some(errno))
        }
        _ => SessionTransportError::Native(None),
    }
}

fn exact_child_credentials(
    owner: &NegotiatingLinuxSpawn,
) -> Result<PacketCredentials, LinuxSpawnError> {
    Ok(PacketCredentials {
        pid: u32::try_from(owner.pid()).map_err(|_| LinuxSpawnError::InvalidInput)?,
        // SAFETY: automatic SCM_CREDENTIALS carries real IDs.
        uid: unsafe { libc::getuid() },
        // SAFETY: automatic SCM_CREDENTIALS carries real IDs.
        gid: unsafe { libc::getgid() },
    })
}

fn send_negotiating_spawn(
    owner: &mut NegotiatingLinuxSpawn,
    bytes: &[u8],
) -> Result<(), LinuxSpawnError> {
    let pidfd = owner.pidfd();
    send_with_exact_child_fields(&mut owner.endpoint, pidfd, bytes, owner.deadline)
}

fn spawn_negotiating(
    executable: &Path,
    arguments: &[OsString],
    environment: &[(OsString, OsString)],
    offer: LinuxHelloOffer,
    deadline: AbsoluteDeadline,
) -> Result<NegotiatingLinuxSpawn, LinuxCoordinatorSpawnFailure> {
    let offer = validate_linux_offer(offer).map_err(LinuxCoordinatorSpawnFailure::before_child)?;
    let atomics = discover_atomic_capabilities()
        .map_err(LinuxSpawnError::NativeNegotiation)
        .map_err(LinuxCoordinatorSpawnFailure::before_child)?;
    let nonce = generate_nonce(deadline, EntropyFault::None)
        .map_err(LinuxCoordinatorSpawnFailure::before_child)?;
    let owner = spawn_unauthenticated_diagnostic(
        executable,
        arguments,
        environment,
        SpawnFault::None,
        deadline,
    )?;
    exchange_coordinator_hello_diagnostic(owner, offer, atomics, nonce, deadline)
}

fn spawn_negotiating_with_fault(
    executable: &Path,
    arguments: &[OsString],
    environment: &[(OsString, OsString)],
    offer: LinuxHelloOffer,
    spawn_fault: SpawnFault,
    entropy_fault: EntropyFault,
    deadline: AbsoluteDeadline,
) -> Result<NegotiatingLinuxSpawn, LinuxSpawnError> {
    let offer = validate_linux_offer(offer)?;
    let atomics = discover_atomic_capabilities().map_err(LinuxSpawnError::NativeNegotiation)?;
    let nonce = generate_nonce(deadline, entropy_fault)?;
    let owner = spawn_unauthenticated_with_fault(
        executable,
        arguments,
        environment,
        spawn_fault,
        deadline,
    )?;
    exchange_coordinator_hello(owner, offer, atomics, nonce, deadline)
}

fn spawn_unauthenticated_diagnostic(
    executable: &Path,
    arguments: &[OsString],
    environment: &[(OsString, OsString)],
    fault: SpawnFault,
    deadline: AbsoluteDeadline,
) -> Result<UnauthenticatedLinuxSpawn, LinuxCoordinatorSpawnFailure> {
    if deadline.is_expired() || arguments.is_empty() {
        return Err(LinuxCoordinatorSpawnFailure::before_child(
            if deadline.is_expired() {
                LinuxSpawnError::DeadlineExpired
            } else {
                LinuxSpawnError::InvalidInput
            },
        ));
    }
    let held = HeldExecutable::open(executable)
        .map_err(|_| LinuxCoordinatorSpawnFailure::before_child(LinuxSpawnError::InvalidInput))?;
    reject_credential_changing_mode(&held).map_err(LinuxCoordinatorSpawnFailure::before_child)?;
    spawn_held_with_fault_diagnostic(held, arguments, environment, fault, deadline)
}

fn exchange_coordinator_hello_diagnostic(
    mut owner: UnauthenticatedLinuxSpawn,
    offer: LinuxHelloOffer,
    atomics: crate::session::AtomicCapabilities,
    nonce: [u8; NONCE_LEN],
    deadline: AbsoluteDeadline,
) -> Result<NegotiatingLinuxSpawn, LinuxCoordinatorSpawnFailure> {
    let result = (|| {
        let coordinator = make_hello(SenderRole::Coordinator, nonce, offer, atomics)?;
        let encoded = encode_hello(&coordinator)?;
        send_with_exact_child(&mut owner, &encoded, deadline)?;
        let expected_peer = PacketCredentials {
            pid: u32::try_from(owner.pid()).map_err(|_| LinuxSpawnError::InvalidInput)?,
            // SAFETY: scalar credential queries have no pointer arguments.
            uid: unsafe { libc::getuid() },
            // SAFETY: scalar credential queries have no pointer arguments.
            gid: unsafe { libc::getgid() },
        };
        let packet = receive_with_exact_child(&mut owner, expected_peer, deadline)?;
        let receiver = match decode_frame(
            &packet.bytes,
            SenderRole::Receiver,
            nonce,
            MAX_LINUX_HELLO_PAYLOAD as u32,
        )
        .map_err(LinuxSpawnError::Negotiation)?
        {
            NegotiationFrame::Hello(frame) => frame,
            NegotiationFrame::Accept(_) | NegotiationFrame::Reject(_) => {
                return Err(LinuxSpawnError::Negotiation(NegotiationWireError::BadKind));
            }
        };
        let peer_application_payload = receiver.application_payload.clone();
        let transcript =
            NegotiatedTranscript::from_hellos(HelloPair::new(coordinator, receiver), atomics)
                .map_err(LinuxSpawnError::Negotiation)?;
        Ok((transcript, peer_application_payload))
    })();
    let (transcript, peer_application_payload) = match result {
        Ok(value) => value,
        Err(error) => {
            let cleanup = owner.terminate_and_reap(deadline);
            return Err(LinuxCoordinatorSpawnFailure::during_negotiation(
                error, cleanup,
            ));
        }
    };
    Ok(NegotiatingLinuxSpawn {
        lifecycle: owner.lifecycle.take(),
        endpoint: owner.endpoint,
        executable: owner.executable,
        transcript,
        nonce,
        deadline,
        _peer_application_payload: peer_application_payload,
        not_sync: PhantomData,
    })
}

fn exchange_coordinator_hello(
    mut owner: UnauthenticatedLinuxSpawn,
    offer: LinuxHelloOffer,
    atomics: crate::session::AtomicCapabilities,
    nonce: [u8; NONCE_LEN],
    deadline: AbsoluteDeadline,
) -> Result<NegotiatingLinuxSpawn, LinuxSpawnError> {
    let coordinator = make_hello(SenderRole::Coordinator, nonce, offer, atomics)?;
    let encoded = encode_hello(&coordinator)?;
    let result = (|| {
        send_with_exact_child(&mut owner, &encoded, deadline)?;
        let expected_peer = PacketCredentials {
            pid: u32::try_from(owner.pid()).map_err(|_| LinuxSpawnError::InvalidInput)?,
            // Automatic SCM_CREDENTIALS carries real IDs. Credential-changing
            // executable modes are rejected before clone.
            // SAFETY: scalar credential queries have no pointer arguments.
            uid: unsafe { libc::getuid() },
            // SAFETY: scalar credential queries have no pointer arguments.
            gid: unsafe { libc::getgid() },
        };
        let packet = receive_with_exact_child(&mut owner, expected_peer, deadline)?;
        let receiver = match decode_frame(
            &packet.bytes,
            SenderRole::Receiver,
            nonce,
            MAX_LINUX_HELLO_PAYLOAD as u32,
        )
        .map_err(LinuxSpawnError::Negotiation)?
        {
            NegotiationFrame::Hello(frame) => frame,
            NegotiationFrame::Accept(_) | NegotiationFrame::Reject(_) => {
                return Err(LinuxSpawnError::Negotiation(NegotiationWireError::BadKind));
            }
        };
        let peer_application_payload = receiver.application_payload.clone();
        let transcript =
            NegotiatedTranscript::from_hellos(HelloPair::new(coordinator, receiver), atomics)
                .map_err(LinuxSpawnError::Negotiation)?;
        Ok((transcript, peer_application_payload))
    })();
    let (transcript, peer_application_payload) = match result {
        Ok(value) => value,
        Err(error) => {
            owner.terminate_and_reap(deadline);
            return Err(error);
        }
    };
    Ok(NegotiatingLinuxSpawn {
        lifecycle: owner.lifecycle.take(),
        endpoint: owner.endpoint,
        executable: owner.executable,
        transcript,
        nonce,
        deadline,
        _peer_application_payload: peer_application_payload,
        not_sync: PhantomData,
    })
}

fn receive_inherited_hello(
    inherited: RawFd,
    offer: LinuxHelloOffer,
    deadline: AbsoluteDeadline,
) -> Result<ReceiverNegotiatingState, LinuxSpawnError> {
    // SAFETY: private callers transfer the unique inherited endpoint.
    let inherited = unsafe { OwnedFd::from_raw_fd(inherited) };
    receive_inherited_hello_owned(inherited, offer, deadline)
}

fn receive_inherited_hello_owned(
    inherited: OwnedFd,
    offer: LinuxHelloOffer,
    deadline: AbsoluteDeadline,
) -> Result<ReceiverNegotiatingState, LinuxSpawnError> {
    let offer = validate_linux_offer(offer)?;
    let atomics = discover_atomic_capabilities().map_err(LinuxSpawnError::NativeNegotiation)?;
    let mut endpoint =
        SeqPacketEndpoint::from_inherited_owned(inherited).map_err(LinuxSpawnError::Packet)?;
    // Capture the directional sender identity after exec. A reparenting race
    // fails closed because the received kernel credential must match exactly.
    let expected_parent = PacketCredentials {
        // SAFETY: scalar process/credential queries have no pointer arguments.
        pid: unsafe { libc::getppid() } as u32,
        // SAFETY: scalar credential query has no pointer arguments.
        uid: unsafe { libc::getuid() },
        // SAFETY: scalar credential query has no pointer arguments.
        gid: unsafe { libc::getgid() },
    };
    let local_child = PacketCredentials {
        // SAFETY: scalar process/credential queries have no pointer arguments.
        pid: unsafe { libc::getpid() } as u32,
        // SAFETY: automatic SCM_CREDENTIALS carries real IDs.
        uid: unsafe { libc::getuid() },
        // SAFETY: automatic SCM_CREDENTIALS carries real IDs.
        gid: unsafe { libc::getgid() },
    };
    let packet = receive_socket_before(&mut endpoint, expected_parent, deadline)?;
    let nonce = authenticated_nonce(&packet.bytes)?;
    let coordinator = match decode_frame(
        &packet.bytes,
        SenderRole::Coordinator,
        nonce,
        MAX_LINUX_HELLO_PAYLOAD as u32,
    )
    .map_err(LinuxSpawnError::Negotiation)?
    {
        NegotiationFrame::Hello(frame) => frame,
        NegotiationFrame::Accept(_) | NegotiationFrame::Reject(_) => {
            return Err(LinuxSpawnError::Negotiation(NegotiationWireError::BadKind));
        }
    };
    let peer_application_payload = coordinator.application_payload.clone();
    let receiver = make_hello(SenderRole::Receiver, nonce, offer, atomics)?;
    let encoded = encode_hello(&receiver)?;
    send_socket_before(&mut endpoint, &encoded, deadline)?;
    let transcript =
        NegotiatedTranscript::from_hellos(HelloPair::new(coordinator, receiver), atomics)
            .map_err(LinuxSpawnError::Negotiation)?;
    Ok(ReceiverNegotiatingState {
        endpoint,
        transcript,
        nonce,
        peer: expected_parent,
        local: local_child,
        deadline,
        _peer_application_payload: peer_application_payload,
        not_sync: PhantomData,
    })
}

fn spawn_unauthenticated(
    executable: &Path,
    arguments: &[OsString],
    environment: &[(OsString, OsString)],
    deadline: AbsoluteDeadline,
) -> Result<UnauthenticatedLinuxSpawn, LinuxSpawnError> {
    spawn_unauthenticated_with_fault(
        executable,
        arguments,
        environment,
        SpawnFault::None,
        deadline,
    )
}

fn spawn_unauthenticated_with_fault(
    executable: &Path,
    arguments: &[OsString],
    environment: &[(OsString, OsString)],
    fault: SpawnFault,
    deadline: AbsoluteDeadline,
) -> Result<UnauthenticatedLinuxSpawn, LinuxSpawnError> {
    if deadline.is_expired() || arguments.is_empty() {
        return Err(if deadline.is_expired() {
            LinuxSpawnError::DeadlineExpired
        } else {
            LinuxSpawnError::InvalidInput
        });
    }
    let held = HeldExecutable::open(executable).map_err(|_| LinuxSpawnError::InvalidInput)?;
    reject_credential_changing_mode(&held)?;
    spawn_held_with_fault(held, arguments, environment, fault, deadline)
}

fn spawn_held_with_fault(
    held: HeldExecutable,
    arguments: &[OsString],
    environment: &[(OsString, OsString)],
    fault: SpawnFault,
    deadline: AbsoluteDeadline,
) -> Result<UnauthenticatedLinuxSpawn, LinuxSpawnError> {
    spawn_held_with_fault_diagnostic(held, arguments, environment, fault, deadline)
        .map_err(|failure| failure.error)
}

fn spawn_held_with_fault_diagnostic(
    held: HeldExecutable,
    arguments: &[OsString],
    environment: &[(OsString, OsString)],
    fault: SpawnFault,
    deadline: AbsoluteDeadline,
) -> Result<UnauthenticatedLinuxSpawn, LinuxCoordinatorSpawnFailure> {
    let prepared_lifecycle = PreparedExactChildLifecycle::new()
        .map_err(|_| LinuxSpawnError::Native(-1))
        .map_err(LinuxCoordinatorSpawnFailure::before_child)?;
    let (parent_endpoint, child_endpoint) = SeqPacketEndpoint::pair()
        .map_err(packet_native)
        .map_err(LinuxCoordinatorSpawnFailure::before_child)?;

    // A new descriptor chosen by the kernel cannot collide with the held image,
    // socketpair, error pipe, or any caller-owned descriptor.
    let inherited_raw =
        unsafe { libc::fcntl(child_endpoint.fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if inherited_raw < 0 {
        return Err(LinuxCoordinatorSpawnFailure::before_child(last_native()));
    }
    // SAFETY: F_DUPFD_CLOEXEC returned a new uniquely owned descriptor.
    let inherited = unsafe { OwnedFd::from_raw_fd(inherited_raw) };

    let mut pipe = [-1; 2];
    // SAFETY: output has room for exactly two descriptors.
    if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } != 0 {
        return Err(LinuxCoordinatorSpawnFailure::before_child(last_native()));
    }
    // SAFETY: successful pipe2 returned two distinct owned descriptors.
    let reader = unsafe { OwnedFd::from_raw_fd(pipe[0]) };
    // SAFETY: successful pipe2 returned two distinct owned descriptors.
    let writer = unsafe { OwnedFd::from_raw_fd(pipe[1]) };
    let reader_raw = reader.as_raw_fd();
    let writer_raw = writer.as_raw_fd();
    let held_raw = held.raw_fd();
    let argv = encode_arguments(arguments).map_err(LinuxCoordinatorSpawnFailure::before_child)?;
    let env = encode_environment(environment, inherited_raw)
        .map_err(LinuxCoordinatorSpawnFailure::before_child)?;
    #[cfg(test)]
    let env = {
        let mut env = env;
        let closed = [
            held_raw,
            reader_raw,
            writer_raw,
            parent_endpoint.fd.as_raw_fd(),
            child_endpoint.fd.as_raw_fd(),
        ]
        .into_iter()
        .map(|fd| {
            let (device, inode) = descriptor_identity(fd);
            format!("{fd}:{device}:{inode}")
        })
        .collect::<Vec<_>>()
        .join(",");
        env.push(
            CString::new(format!("NATIVE_IPC_VNEXT_EXPECT_CLOSED={closed}"))
                .expect("trusted test environment"),
        );
        env
    };
    let mut argv_ptrs: Vec<*const libc::c_char> = argv.iter().map(|v| v.as_ptr()).collect();
    argv_ptrs.push(core::ptr::null());
    let mut env_ptrs: Vec<*const libc::c_char> = env.iter().map(|v| v.as_ptr()).collect();
    env_ptrs.push(core::ptr::null());
    let argv_raw = argv_ptrs.as_ptr();
    let env_raw = env_ptrs.as_ptr();
    let fault_code = fault as u8;

    // Argument/environment preparation and native acquisition must not turn an
    // already-expired operation into process creation.
    if deadline.is_expired() {
        return Err(LinuxCoordinatorSpawnFailure::before_child(
            LinuxSpawnError::DeadlineExpired,
        ));
    }

    let mut raw_pidfd = -1;
    // A zero exit signal keeps this child out of every default process-global
    // wait: `wait`/`waitpid(-1)`/`waitid(P_ALL)` without `__WALL` never select
    // it, and an ignored or `SA_NOCLDWAIT` SIGCHLD disposition cannot
    // auto-reap it. The unreaped zombie therefore durably pins its PID and
    // fresh process-group identity until the sole pidfd waiter consumes it,
    // which is what makes the bounded group termination before that reap
    // race-resistant.
    let clone_arguments = CloneArgs {
        flags: CLONE_PIDFD,
        pidfd: (&mut raw_pidfd as *mut libc::c_int) as u64,
        exit_signal: 0,
        ..CloneArgs::default()
    };
    // SAFETY: fork-like clone3 receives a complete zero-extended clone_args.
    let pid = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            &clone_arguments,
            core::mem::size_of::<CloneArgs>(),
        ) as libc::pid_t
    };
    if pid == 0 {
        // Child audit: only raw close/close_range/fcntl/setsid/prctl/execveat,
        // write/errno/_exit operations use parent-prebuilt pointers and fds.
        unsafe {
            libc::close(reader_raw);
            if libc::syscall(
                libc::SYS_close_range,
                0_u32,
                libc::c_uint::MAX,
                CLOSE_RANGE_CLOEXEC,
            ) != 0
                || fault_code == SpawnFault::CloseRange as u8
            {
                let errno = if fault_code == SpawnFault::CloseRange as u8 {
                    libc::EPERM
                } else {
                    *libc::__errno_location()
                };
                child_error(writer_raw, 1, errno);
            }
            if fault_code == SpawnFault::Partial as u8 {
                let record = RawChildError {
                    stage: 2_u32.to_le(),
                    errno: libc::EPERM.to_le(),
                };
                libc::write(writer_raw, (&record as *const RawChildError).cast(), 3);
                libc::_exit(121);
            }
            if fault_code == SpawnFault::Malformed as u8 {
                child_error(writer_raw, 99, libc::EINVAL);
            }
            if fault_code == SpawnFault::Stall as u8 {
                loop {
                    libc::pause();
                }
            }
            if fault_code == SpawnFault::SilentExit as u8 {
                libc::_exit(122);
            }
            if fault_code == SpawnFault::BootstrapFd as u8
                || libc::fcntl(inherited_raw, libc::F_SETFD, 0) != 0
            {
                child_error(writer_raw, 2, libc::EPERM);
            }
            if fault_code == SpawnFault::SetSid as u8 {
                child_error(writer_raw, 3, libc::EPERM);
            }
            if libc::setsid() < 0 {
                child_error(writer_raw, 3, *libc::__errno_location());
            }
            if fault_code == SpawnFault::Mdwe as u8 {
                child_error(writer_raw, 4, libc::EPERM);
            }
            if libc::prctl(
                PR_SET_MDWE,
                PR_MDWE_REFUSE_EXEC_GAIN,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
            ) != 0
            {
                child_error(writer_raw, 4, *libc::__errno_location());
            }
            if fault_code == SpawnFault::Exec as u8 {
                child_error(writer_raw, 5, libc::ENOENT);
            }
            libc::syscall(
                libc::SYS_execveat,
                held_raw,
                c"".as_ptr(),
                argv_raw,
                env_raw,
                libc::AT_EMPTY_PATH,
            );
            child_error(writer_raw, 5, *libc::__errno_location());
        }
    }
    if pid < 0 || raw_pidfd < 0 {
        return Err(LinuxCoordinatorSpawnFailure::before_child(last_native()));
    }
    #[cfg(test)]
    LAST_SPAWN_PID.with(|slot| slot.set(pid));
    // SAFETY: CLONE_PIDFD atomically installed this sole descriptor.
    let pidfd = unsafe { OwnedFd::from_raw_fd(raw_pidfd) };
    let lifecycle = prepared_lifecycle
        .arm(pid, pidfd)
        .map_err(|_| LinuxSpawnError::Native(-1))
        .map_err(LinuxCoordinatorSpawnFailure::before_child)?;
    drop(writer);
    drop(inherited);
    drop(child_endpoint);
    let mut owner = UnauthenticatedLinuxSpawn {
        lifecycle: Some(lifecycle),
        endpoint: parent_endpoint,
        executable: held,
        not_sync: PhantomData,
    };

    let result = await_exec_result(&reader, &mut owner, deadline);
    if let Err(error) = result {
        let cleanup = owner.terminate_and_reap(deadline);
        return Err(LinuxCoordinatorSpawnFailure::after_spawn(error, cleanup));
    }
    Ok(owner)
}

fn await_exec_result(
    reader: &OwnedFd,
    owner: &mut UnauthenticatedLinuxSpawn,
    deadline: AbsoluteDeadline,
) -> Result<(), LinuxSpawnError> {
    let mut record = [0_u8; EXEC_ERROR_LEN];
    let mut received = 0_usize;
    loop {
        // SAFETY: remaining record storage is writable and bounded.
        let read = unsafe {
            libc::read(
                reader.as_raw_fd(),
                record[received..].as_mut_ptr().cast(),
                record.len() - received,
            )
        };
        if read > 0 {
            received += read as usize;
            if received == EXEC_ERROR_LEN {
                let stage = u32::from_le_bytes(record[..4].try_into().expect("fixed range"));
                let errno = i32::from_le_bytes(record[4..].try_into().expect("fixed range"));
                if !(1..=5).contains(&stage) || errno <= 0 {
                    return Err(LinuxSpawnError::MalformedChildError);
                }
                if stage >= 4 {
                    owner
                        .lifecycle
                        .as_ref()
                        .expect("live spawn owner")
                        .establish_fresh_session();
                }
                return Err(LinuxSpawnError::Child { stage, errno });
            }
            continue;
        }
        if read == 0 {
            if received != 0 {
                return Err(LinuxSpawnError::MalformedChildError);
            }
            owner
                .lifecycle
                .as_ref()
                .expect("live spawn owner")
                .establish_fresh_session();
            ensure_live(owner.pidfd(), deadline)?;
            if !owner.executable.matches_process_image(owner.pid()) {
                return Err(LinuxSpawnError::WrongExecutable);
            }
            ensure_live(owner.pidfd(), deadline)?;
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            if deadline.is_expired() {
                return Err(LinuxSpawnError::DeadlineExpired);
            }
            continue;
        }
        if error.kind() != io::ErrorKind::WouldBlock {
            return Err(LinuxSpawnError::Native(error.raw_os_error().unwrap_or(-1)));
        }
        poll_exec(reader.as_raw_fd(), owner.pidfd(), deadline)?;
    }
}

fn reject_credential_changing_mode(held: &HeldExecutable) -> Result<(), LinuxSpawnError> {
    // SAFETY: status is complete writable output for the live held image.
    let mut status: libc::stat = unsafe { core::mem::zeroed() };
    // SAFETY: fstat only reads metadata for the live descriptor.
    if unsafe { libc::fstat(held.raw_fd(), &mut status) } != 0 {
        return Err(last_native());
    }
    if status.st_mode & (libc::S_ISUID | libc::S_ISGID) != 0 {
        return Err(LinuxSpawnError::InvalidInput);
    }
    Ok(())
}

fn validate_linux_offer(mut offer: LinuxHelloOffer) -> Result<LinuxHelloOffer, LinuxSpawnError> {
    if !offer
        .required_features
        .is_subset_of(offer.supported_features)
    {
        return Err(LinuxSpawnError::Negotiation(
            NegotiationWireError::RequiredFeatureNotSupported,
        ));
    }
    offer.limits.max_control_payload_bytes = offer
        .limits
        .max_control_payload_bytes
        .min(MAX_LINUX_CONTROL_PAYLOAD);
    offer
        .limits
        .validate()
        .map_err(LinuxSpawnError::NativeNegotiation)?;
    if offer.application_payload.len() > MAX_LINUX_HELLO_PAYLOAD {
        return Err(LinuxSpawnError::InvalidInput);
    }
    offer.limits.max_bootstrap_payload_bytes = offer
        .limits
        .max_bootstrap_payload_bytes
        .min(MAX_LINUX_HELLO_PAYLOAD as u32);
    if offer.application_payload.len() > offer.limits.max_bootstrap_payload_bytes as usize {
        return Err(LinuxSpawnError::InvalidInput);
    }
    Ok(offer)
}

fn make_hello(
    role: SenderRole,
    nonce: [u8; NONCE_LEN],
    offer: LinuxHelloOffer,
    atomics: crate::session::AtomicCapabilities,
) -> Result<HelloFrame, LinuxSpawnError> {
    Ok(HelloFrame {
        role,
        nonce,
        supported_features: offer.supported_features,
        required_features: offer.required_features,
        limits: offer.limits,
        atomics: AtomicOffer::from_local(atomics).map_err(LinuxSpawnError::Negotiation)?,
        target: TargetFacts::current(),
        application_payload: offer.application_payload,
    })
}

fn encode_hello(hello: &HelloFrame) -> Result<Vec<u8>, LinuxSpawnError> {
    let frame = NegotiationFrame::Hello(HelloFrame {
        role: hello.role,
        nonce: hello.nonce,
        supported_features: hello.supported_features,
        required_features: hello.required_features,
        limits: hello.limits,
        atomics: hello.atomics,
        target: hello.target,
        application_payload: hello.application_payload.clone(),
    });
    let length = frame.encoded_len().map_err(LinuxSpawnError::Negotiation)?;
    if length > MAX_ZERO_RIGHTS_PACKET_BYTES {
        return Err(LinuxSpawnError::InvalidInput);
    }
    let mut encoded = vec![0; length];
    frame
        .encode_into(&mut encoded)
        .map_err(LinuxSpawnError::Negotiation)?;
    Ok(encoded)
}

fn encode_negotiation_frame(frame: &NegotiationFrame) -> Result<Vec<u8>, LinuxSpawnError> {
    let length = frame.encoded_len().map_err(LinuxSpawnError::Negotiation)?;
    if length > MAX_ZERO_RIGHTS_PACKET_BYTES {
        return Err(LinuxSpawnError::InvalidInput);
    }
    let mut encoded = vec![0; length];
    frame
        .encode_into(&mut encoded)
        .map_err(LinuxSpawnError::Negotiation)?;
    Ok(encoded)
}

fn authenticated_nonce(bytes: &[u8]) -> Result<[u8; NONCE_LEN], LinuxSpawnError> {
    if bytes.len() < HEADER_LEN {
        return Err(LinuxSpawnError::Negotiation(
            NegotiationWireError::Truncated,
        ));
    }
    let nonce = bytes[32..64].try_into().expect("checked fixed nonce range");
    if nonce == [0; NONCE_LEN] {
        return Err(LinuxSpawnError::Negotiation(
            NegotiationWireError::NonceMismatch,
        ));
    }
    Ok(nonce)
}

fn generate_nonce(
    deadline: AbsoluteDeadline,
    fault: EntropyFault,
) -> Result<[u8; NONCE_LEN], LinuxSpawnError> {
    generate_entropy(deadline, fault)
}

fn generate_decision_challenge(
    deadline: AbsoluteDeadline,
    fault: EntropyFault,
) -> Result<DecisionChallenge, LinuxSpawnError> {
    DecisionChallenge::from_os_csprng(generate_entropy(deadline, fault)?)
        .map_err(LinuxSpawnError::Negotiation)
}

fn generate_entropy<const LENGTH: usize>(
    deadline: AbsoluteDeadline,
    fault: EntropyFault,
) -> Result<[u8; LENGTH], LinuxSpawnError> {
    let mut bytes = [0_u8; LENGTH];
    #[cfg(test)]
    let mut interrupted_once = false;
    #[cfg(not(test))]
    let _ = fault;
    loop {
        if deadline.is_expired() {
            return Err(LinuxSpawnError::DeadlineExpired);
        }
        #[cfg(test)]
        let result = match fault {
            EntropyFault::Interrupted if !interrupted_once => {
                interrupted_once = true;
                continue;
            }
            EntropyFault::Interrupted => unsafe {
                libc::syscall(
                    libc::SYS_getrandom,
                    bytes.as_mut_ptr(),
                    bytes.len(),
                    libc::GRND_NONBLOCK,
                )
            },
            EntropyFault::WouldBlock => -1,
            EntropyFault::Short => (LENGTH - 1) as libc::c_long,
            EntropyFault::AllZero => LENGTH as libc::c_long,
            EntropyFault::None => unsafe {
                libc::syscall(
                    libc::SYS_getrandom,
                    bytes.as_mut_ptr(),
                    bytes.len(),
                    libc::GRND_NONBLOCK,
                )
            },
        };
        #[cfg(not(test))]
        let result = unsafe {
            libc::syscall(
                libc::SYS_getrandom,
                bytes.as_mut_ptr(),
                bytes.len(),
                libc::GRND_NONBLOCK,
            )
        };
        #[cfg(test)]
        if matches!(fault, EntropyFault::WouldBlock) {
            return Err(LinuxSpawnError::EntropyUnavailable);
        }
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(LinuxSpawnError::EntropyUnavailable);
        }
        if result as usize != LENGTH || bytes == [0; LENGTH] {
            return Err(LinuxSpawnError::EntropyUnavailable);
        }
        return Ok(bytes);
    }
}

fn send_with_exact_child(
    owner: &mut UnauthenticatedLinuxSpawn,
    bytes: &[u8],
    deadline: AbsoluteDeadline,
) -> Result<(), LinuxSpawnError> {
    let pidfd = owner.pidfd();
    send_with_exact_child_fields(&mut owner.endpoint, pidfd, bytes, deadline)
}

fn send_with_exact_child_fields(
    endpoint: &mut SeqPacketEndpoint,
    pidfd: RawFd,
    bytes: &[u8],
    deadline: AbsoluteDeadline,
) -> Result<(), LinuxSpawnError> {
    loop {
        super::ensure_running(pidfd, deadline).map_err(LinuxSpawnError::Packet)?;
        match endpoint.send_zero_rights(bytes) {
            Ok(()) => {
                if deadline.is_expired() {
                    return Err(LinuxSpawnError::Packet(PacketError::AmbiguousAfterSend));
                }
                return Ok(());
            }
            Err(PacketError::Interrupted) => continue,
            Err(PacketError::WouldBlock) => {
                super::poll_until(endpoint.fd.as_raw_fd(), pidfd, libc::POLLOUT, deadline)
                    .map_err(LinuxSpawnError::Packet)?
            }
            Err(error) => return Err(LinuxSpawnError::Packet(error)),
        }
    }
}

fn receive_with_exact_child(
    owner: &mut UnauthenticatedLinuxSpawn,
    expected_peer: PacketCredentials,
    deadline: AbsoluteDeadline,
) -> Result<super::ReceivedPacket, LinuxSpawnError> {
    let pidfd = owner.pidfd();
    receive_with_exact_child_fields(&mut owner.endpoint, pidfd, expected_peer, deadline)
}

fn receive_with_exact_child_fields(
    endpoint: &mut SeqPacketEndpoint,
    pidfd: RawFd,
    expected_peer: PacketCredentials,
    deadline: AbsoluteDeadline,
) -> Result<super::ReceivedPacket, LinuxSpawnError> {
    loop {
        if deadline.is_expired() {
            return Err(LinuxSpawnError::DeadlineExpired);
        }
        match endpoint.receive_zero_rights(expected_peer) {
            Ok(packet) => {
                if deadline.is_expired() {
                    return Err(LinuxSpawnError::Packet(PacketError::AmbiguousAfterReceive));
                }
                return Ok(packet);
            }
            Err(PacketError::Interrupted) => continue,
            Err(PacketError::WouldBlock) => {
                super::poll_until(endpoint.fd.as_raw_fd(), pidfd, libc::POLLIN, deadline)
                    .map_err(LinuxSpawnError::Packet)?
            }
            Err(error) => return Err(LinuxSpawnError::Packet(error)),
        }
    }
}

fn send_socket_before(
    endpoint: &mut SeqPacketEndpoint,
    bytes: &[u8],
    deadline: AbsoluteDeadline,
) -> Result<(), LinuxSpawnError> {
    loop {
        if deadline.is_expired() {
            return Err(LinuxSpawnError::DeadlineExpired);
        }
        match endpoint.send_zero_rights(bytes) {
            Ok(()) => {
                if deadline.is_expired() {
                    return Err(LinuxSpawnError::Packet(PacketError::AmbiguousAfterSend));
                }
                return Ok(());
            }
            Err(PacketError::Interrupted) => continue,
            Err(PacketError::WouldBlock) => {
                poll_socket(endpoint.fd.as_raw_fd(), libc::POLLOUT, deadline)?;
            }
            Err(error) => return Err(LinuxSpawnError::Packet(error)),
        }
    }
}

fn receive_socket_before(
    endpoint: &mut SeqPacketEndpoint,
    expected_peer: PacketCredentials,
    deadline: AbsoluteDeadline,
) -> Result<super::ReceivedPacket, LinuxSpawnError> {
    loop {
        if deadline.is_expired() {
            return Err(LinuxSpawnError::DeadlineExpired);
        }
        match endpoint.receive_zero_rights(expected_peer) {
            Ok(packet) => {
                if deadline.is_expired() {
                    return Err(LinuxSpawnError::Packet(PacketError::AmbiguousAfterReceive));
                }
                return Ok(packet);
            }
            Err(PacketError::Interrupted) => continue,
            Err(PacketError::WouldBlock) => {
                poll_socket(endpoint.fd.as_raw_fd(), libc::POLLIN, deadline)?;
            }
            Err(error) => return Err(LinuxSpawnError::Packet(error)),
        }
    }
}

fn poll_socket(
    socket: RawFd,
    requested: libc::c_short,
    deadline: AbsoluteDeadline,
) -> Result<(), LinuxSpawnError> {
    loop {
        let remaining = deadline.remaining();
        if remaining.is_zero() {
            return Err(LinuxSpawnError::DeadlineExpired);
        }
        let timeout = remaining
            .as_nanos()
            .div_ceil(1_000_000)
            .min(i32::MAX as u128) as libc::c_int;
        let mut event = libc::pollfd {
            fd: socket,
            events: requested,
            revents: 0,
        };
        // SAFETY: event is one initialized descriptor for bounded poll.
        let result = unsafe { libc::poll(&mut event, 1, timeout) };
        if result < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(last_native());
        }
        if deadline.is_expired() {
            return Err(LinuxSpawnError::DeadlineExpired);
        }
        let readable = requested & libc::POLLIN != 0 && event.revents & libc::POLLIN != 0;
        if readable {
            return Ok(());
        }
        if event.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Err(LinuxSpawnError::Packet(PacketError::PeerExited));
        }
        if event.revents & requested != 0 {
            return Ok(());
        }
    }
}

fn ensure_live(pidfd: RawFd, deadline: AbsoluteDeadline) -> Result<(), LinuxSpawnError> {
    loop {
        if deadline.is_expired() {
            return Err(LinuxSpawnError::DeadlineExpired);
        }
        let mut event = libc::pollfd {
            fd: pidfd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: event is one live poll descriptor.
        let result = unsafe { libc::poll(&mut event, 1, 0) };
        if result < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(last_native());
        }
        if result != 0 || event.revents != 0 {
            return Err(LinuxSpawnError::ExitedBeforeConfirmation);
        }
        return Ok(());
    }
}

fn poll_exec(
    reader: RawFd,
    pidfd: RawFd,
    deadline: AbsoluteDeadline,
) -> Result<(), LinuxSpawnError> {
    loop {
        let remaining = deadline.remaining();
        if remaining.is_zero() {
            return Err(LinuxSpawnError::DeadlineExpired);
        }
        let timeout = remaining
            .as_nanos()
            .div_ceil(1_000_000)
            .min(i32::MAX as u128) as libc::c_int;
        let mut events = [
            libc::pollfd {
                fd: reader,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: pidfd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: both initialized entries remain live for the bounded poll.
        let result = unsafe { libc::poll(events.as_mut_ptr(), 2, timeout) };
        if result < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(last_native());
        }
        if deadline.is_expired() {
            return Err(LinuxSpawnError::DeadlineExpired);
        }
        if events[0].revents != 0 {
            return Ok(());
        }
        if events[1].revents != 0 {
            return Err(LinuxSpawnError::ExitedBeforeConfirmation);
        }
    }
}

fn encode_arguments(arguments: &[OsString]) -> Result<Vec<CString>, LinuxSpawnError> {
    arguments
        .iter()
        .map(|value| {
            CString::new(value.as_os_str().as_bytes()).map_err(|_| LinuxSpawnError::InvalidInput)
        })
        .collect()
}

fn encode_environment(
    environment: &[(OsString, OsString)],
    inherited_fd: RawFd,
) -> Result<Vec<CString>, LinuxSpawnError> {
    let mut encoded = Vec::with_capacity(environment.len() + 1);
    for (key, value) in environment {
        let key = key.as_os_str().as_bytes();
        let value = value.as_os_str().as_bytes();
        if key.is_empty()
            || key.contains(&0)
            || key.contains(&b'=')
            || key == BOOTSTRAP_ENV
            || value.contains(&0)
        {
            return Err(LinuxSpawnError::InvalidInput);
        }
        let mut entry = Vec::with_capacity(key.len() + value.len() + 1);
        entry.extend_from_slice(key);
        entry.push(b'=');
        entry.extend_from_slice(value);
        encoded.push(CString::new(entry).map_err(|_| LinuxSpawnError::InvalidInput)?);
    }
    encoded.push(
        CString::new(format!(
            "{}={inherited_fd}",
            core::str::from_utf8(BOOTSTRAP_ENV).expect("ASCII key")
        ))
        .expect("trusted bootstrap environment"),
    );
    Ok(encoded)
}

unsafe fn child_error(fd: RawFd, stage: u32, errno: i32) -> ! {
    let record = RawChildError {
        stage: stage.to_le(),
        errno: errno.to_le(),
    };
    let mut written = 0_usize;
    let mut interrupts = 0_u8;
    while written < EXEC_ERROR_LEN && interrupts < 16 {
        // SAFETY: the fixed stack record remains live for this bounded write.
        let result = unsafe {
            libc::write(
                fd,
                (&record as *const RawChildError)
                    .cast::<u8>()
                    .add(written)
                    .cast(),
                EXEC_ERROR_LEN - written,
            )
        };
        if result > 0 {
            written += result as usize;
        } else if result < 0 && unsafe { *libc::__errno_location() } == libc::EINTR {
            interrupts += 1;
        } else {
            break;
        }
    }
    // SAFETY: the raw child cannot unwind or run Rust destructors.
    unsafe { libc::_exit(120) }
}

fn packet_native(error: super::PacketError) -> LinuxSpawnError {
    match error {
        super::PacketError::Native(code) => LinuxSpawnError::Native(code),
        _ => LinuxSpawnError::Native(-1),
    }
}

fn last_native() -> LinuxSpawnError {
    LinuxSpawnError::Native(io::Error::last_os_error().raw_os_error().unwrap_or(-1))
}

#[cfg(test)]
fn descriptor_identity(fd: RawFd) -> (u64, u64) {
    // SAFETY: status is complete writable output for this live descriptor.
    let mut status: libc::stat = unsafe { core::mem::zeroed() };
    // SAFETY: fstat reads metadata for the live descriptor only.
    assert_eq!(unsafe { libc::fstat(fd, &mut status) }, 0);
    (status.st_dev, status.st_ino)
}

#[cfg(test)]
#[path = "spawn_test.rs"]
mod tests;
