//! Private, pre-authentication Linux exact-child spawn owner.

use core::cell::Cell;
use core::marker::PhantomData;
use std::ffi::{CString, OsString};
use std::io;
use std::num::NonZeroU32;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use crate::backend::{
    CoordinatorAcceptedEvidence, CoordinatorChildChannelReceipt, CoordinatorChildImageReceipt,
    ReceiverSpawnerEvidence, SpawnIdentityFacts,
};
use crate::control::CONTROL_HEADER_LEN;
use crate::negotiation::{
    AtomicOffer, DecisionChallenge, FeatureBits, HEADER_LEN, HelloFrame, HelloPair,
    NegotiatedTranscript, NegotiationFrame, NegotiationWireError, SenderRole, TargetFacts,
    decode_frame,
};
use crate::session::{AbsoluteDeadline, NegotiationError, SessionLimits};

use super::process::{ExactChildLifecycle, HeldExecutable, PreparedExactChildLifecycle};
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
    _endpoint: SeqPacketEndpoint,
    _executable: HeldExecutable,
    _evidence: CoordinatorAcceptedEvidence,
    not_sync: PhantomData<Cell<()>>,
}

struct ReceiverAcceptedEvidenceOwner {
    _endpoint: SeqPacketEndpoint,
    _evidence: ReceiverSpawnerEvidence,
    not_sync: PhantomData<Cell<()>>,
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

    fn terminate_and_reap(mut self, deadline: AbsoluteDeadline) {
        if let Some(lifecycle) = self.lifecycle.take() {
            let _ = lifecycle.terminate_and_reap(deadline);
        }
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

    fn terminate_and_reap(mut self, deadline: AbsoluteDeadline) {
        if let Some(lifecycle) = self.lifecycle.take() {
            let _ = lifecycle.terminate_and_reap(deadline);
        }
    }

    fn decide(
        self,
        decision: ApplicationDecision,
    ) -> Result<DecisionOutcome<AcceptedLinuxSpawn>, LinuxSpawnError> {
        self.decide_with_entropy_fault(decision, EntropyFault::None)
    }

    fn decide_with_entropy_fault(
        mut self,
        decision: ApplicationDecision,
        entropy_fault: EntropyFault,
    ) -> Result<DecisionOutcome<AcceptedLinuxSpawn>, LinuxSpawnError> {
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
                self.terminate_and_reap(deadline);
                Ok(DecisionOutcome::Rejected {
                    by,
                    reason,
                    state: (),
                })
            }
            Err(error) => {
                self.terminate_and_reap(deadline);
                Err(error)
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

    fn terminate_and_reap(mut self, deadline: AbsoluteDeadline) {
        if let Some(lifecycle) = self.lifecycle.take() {
            let _ = lifecycle.terminate_and_reap(deadline);
        }
    }

    fn into_evidence(mut self) -> Result<CoordinatorAcceptedEvidenceOwner, LinuxSpawnError> {
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
                self.terminate_and_reap(deadline);
                return Err(error);
            }
        };
        Ok(CoordinatorAcceptedEvidenceOwner {
            lifecycle: self.lifecycle.take(),
            _endpoint: self.endpoint,
            _executable: self.executable,
            _evidence: evidence,
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
            _endpoint: self.endpoint,
            _evidence: evidence,
            not_sync: PhantomData,
        })
    }
}

impl CoordinatorAcceptedEvidenceOwner {
    fn pid(&self) -> libc::pid_t {
        self.lifecycle.as_ref().expect("live evidence owner").pid()
    }

    fn facts(&self) -> SpawnIdentityFacts {
        self._evidence.facts()
    }

    fn terminate_and_reap(mut self, deadline: AbsoluteDeadline) {
        if let Some(lifecycle) = self.lifecycle.take() {
            let _ = lifecycle.terminate_and_reap(deadline);
        }
    }
}

impl ReceiverAcceptedEvidenceOwner {
    fn facts(&self) -> SpawnIdentityFacts {
        self._evidence.facts()
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
) -> Result<NegotiatingLinuxSpawn, LinuxSpawnError> {
    spawn_negotiating_with_fault(
        executable,
        arguments,
        environment,
        offer,
        SpawnFault::None,
        EntropyFault::None,
        deadline,
    )
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
    let offer = validate_linux_offer(offer)?;
    let atomics = discover_atomic_capabilities().map_err(LinuxSpawnError::NativeNegotiation)?;
    // SAFETY: this entry consumes the unique inherited bootstrap descriptor.
    let mut endpoint =
        unsafe { SeqPacketEndpoint::from_inherited(inherited) }.map_err(LinuxSpawnError::Packet)?;
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
    let prepared_lifecycle =
        PreparedExactChildLifecycle::new().map_err(|_| LinuxSpawnError::Native(-1))?;
    let (parent_endpoint, child_endpoint) = SeqPacketEndpoint::pair().map_err(packet_native)?;

    // A new descriptor chosen by the kernel cannot collide with the held image,
    // socketpair, error pipe, or any caller-owned descriptor.
    let inherited_raw =
        unsafe { libc::fcntl(child_endpoint.fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if inherited_raw < 0 {
        return Err(last_native());
    }
    // SAFETY: F_DUPFD_CLOEXEC returned a new uniquely owned descriptor.
    let inherited = unsafe { OwnedFd::from_raw_fd(inherited_raw) };

    let mut pipe = [-1; 2];
    // SAFETY: output has room for exactly two descriptors.
    if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } != 0 {
        return Err(last_native());
    }
    // SAFETY: successful pipe2 returned two distinct owned descriptors.
    let reader = unsafe { OwnedFd::from_raw_fd(pipe[0]) };
    // SAFETY: successful pipe2 returned two distinct owned descriptors.
    let writer = unsafe { OwnedFd::from_raw_fd(pipe[1]) };
    let reader_raw = reader.as_raw_fd();
    let writer_raw = writer.as_raw_fd();
    let held_raw = held.raw_fd();
    let argv = encode_arguments(arguments)?;
    let env = encode_environment(environment, inherited_raw)?;
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
        return Err(LinuxSpawnError::DeadlineExpired);
    }

    let mut raw_pidfd = -1;
    let clone_arguments = CloneArgs {
        flags: CLONE_PIDFD,
        pidfd: (&mut raw_pidfd as *mut libc::c_int) as u64,
        exit_signal: libc::SIGCHLD as u64,
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
        return Err(last_native());
    }
    #[cfg(test)]
    LAST_SPAWN_PID.with(|slot| slot.set(pid));
    // SAFETY: CLONE_PIDFD atomically installed this sole descriptor.
    let pidfd = unsafe { OwnedFd::from_raw_fd(raw_pidfd) };
    let lifecycle = prepared_lifecycle
        .arm(pid, pidfd)
        .map_err(|_| LinuxSpawnError::Native(-1))?;
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
        owner.terminate_and_reap(deadline);
        return Err(error);
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
        super::ensure_running(pidfd, deadline).map_err(LinuxSpawnError::Packet)?;
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
