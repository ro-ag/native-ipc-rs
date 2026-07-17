//! Public Windows exact-child negotiation and Ready-session owners.

use core::cell::Cell;
use core::marker::PhantomData;
use std::num::NonZeroU32;

use super::vnext_memory::{WindowsBatchError, WindowsMixedDirectionBatch};
use super::vnext_transport::{
    CoordinatorWindowsControlTransport, ReceiverWindowsControlTransport, read_message,
    write_message,
};
use super::{
    ChildChannel, ChildSession, ChildSpawnFailure, MAX_VNEXT_RECORD_BYTES, WindowsError,
    public_command_strings_are_valid, session_nonce,
};
use crate::backend::accepted_control::{
    AcceptedControlDispatcher, AcceptedControlError, WindowsActivationError,
    WindowsCapabilityBatchError,
};
use crate::backend::{
    CoordinatorAcceptedEvidence, CoordinatorChildChannelReceipt, CoordinatorChildImageReceipt,
    ReceiverSpawnerEvidence, SessionTransportError, SpawnIdentityFacts,
};
use crate::batch::{ActiveRegionSet, BatchError, ExpectedBatch, TransferBatch};
use crate::control::{CONTROL_HEADER_LEN, ControlError, ControlFrame};
use crate::liveness::ResourceError;
use crate::negotiation::{
    AtomicOffer, DecisionChallenge, FeatureBits, HEADER_LEN, HelloFrame, HelloPair,
    NegotiatedTranscript, NegotiationFrame, NegotiationWireError, SenderRole, TargetFacts,
    decode_frame,
};
use crate::protocol::{CoordinatorCapacityStatus, NativeAuthorityProfile};
use crate::session::{
    AbsoluteDeadline, ActiveLeaseFacts, AtomicCapabilities, ChildCleanupFacts, ChildExitStatus,
    DescendantCleanupStatus, NegotiationError, PeerStatus, ProtocolVersion, SessionCommand,
    SessionLimits, SessionOptions, SessionState,
};

const NONCE_LEN: usize = 32;
const MAX_WINDOWS_HELLO_PAYLOAD: usize = MAX_VNEXT_RECORD_BYTES - HEADER_LEN;
const MAX_WINDOWS_CONTROL_PAYLOAD: u32 = (MAX_VNEXT_RECORD_BYTES - CONTROL_HEADER_LEN) as u32;

#[derive(Debug)]
pub(crate) enum WindowsPublicSessionError {
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
    ActivationFailed,
    Poisoned,
    Native(Option<i32>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WindowsCoordinatorFailureState {
    NotEstablished,
    Spawned,
    Negotiating,
}

#[derive(Debug)]
pub(crate) struct WindowsCoordinatorSessionFailure {
    pub(crate) error: WindowsPublicSessionError,
    pub(crate) cleanup: Option<ChildCleanupFacts>,
    pub(crate) state: WindowsCoordinatorFailureState,
    pub(crate) poisoned: bool,
}

impl WindowsCoordinatorSessionFailure {
    fn before_child(error: WindowsPublicSessionError) -> Self {
        Self {
            error,
            cleanup: None,
            state: WindowsCoordinatorFailureState::NotEstablished,
            poisoned: false,
        }
    }

    fn after_child(
        error: WindowsPublicSessionError,
        state: WindowsCoordinatorFailureState,
    ) -> Self {
        Self {
            error,
            cleanup: Some(incomplete_cleanup()),
            state,
            poisoned: true,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WindowsNegotiationRole {
    Coordinator,
    Receiver,
}

pub(crate) enum WindowsNegotiationOutcome<T> {
    Accepted(T),
    Rejected {
        by: WindowsNegotiationRole,
        reason: NonZeroU32,
        cleanup: Option<ChildCleanupFacts>,
    },
}

struct WindowsHelloOffer {
    supported_features: FeatureBits,
    required_features: FeatureBits,
    limits: SessionLimits,
    application_payload: Vec<u8>,
}

pub(crate) struct WindowsCoordinatorNegotiatingSession {
    session: Option<ChildSession>,
    transcript: NegotiatedTranscript,
    nonce: [u8; NONCE_LEN],
    deadline: AbsoluteDeadline,
    peer_application_payload: Vec<u8>,
    not_sync: PhantomData<Cell<()>>,
}

pub(crate) struct WindowsReceiverNegotiatingSession {
    channel: ChildChannel,
    transcript: NegotiatedTranscript,
    nonce: [u8; NONCE_LEN],
    deadline: AbsoluteDeadline,
    peer_application_payload: Vec<u8>,
    not_sync: PhantomData<Cell<()>>,
}

pub(crate) struct WindowsCoordinatorReadySession {
    dispatcher: AcceptedControlDispatcher<CoordinatorWindowsControlTransport>,
}

pub(crate) struct WindowsReceiverReadySession {
    dispatcher: AcceptedControlDispatcher<ReceiverWindowsControlTransport>,
}

impl WindowsCoordinatorNegotiatingSession {
    pub(crate) fn spawn(
        command: &SessionCommand,
        options: &SessionOptions,
    ) -> Result<Self, WindowsCoordinatorSessionFailure> {
        if options.deadline().is_expired()
            || command.arguments().is_empty()
            || !command.executable().is_absolute()
            || !public_command_strings_are_valid(
                command.executable(),
                command.arguments(),
                command.environment(),
            )
        {
            return Err(WindowsCoordinatorSessionFailure::before_child(
                WindowsPublicSessionError::InvalidInput,
            ));
        }
        let offer =
            public_offer(options).map_err(WindowsCoordinatorSessionFailure::before_child)?;
        let atomics = discover_atomic_capabilities()
            .map_err(WindowsCoordinatorSessionFailure::before_child)?;
        let session = ChildSession::spawn_until(
            command.executable(),
            command.arguments(),
            command.environment(),
            options.deadline(),
        )
        .map_err(|failure: ChildSpawnFailure| {
            let error = map_windows_error(failure.error);
            if failure.child_was_created {
                WindowsCoordinatorSessionFailure::after_child(
                    error,
                    WindowsCoordinatorFailureState::Spawned,
                )
            } else {
                WindowsCoordinatorSessionFailure::before_child(error)
            }
        })?;
        let nonce = session.vnext_nonce();
        let coordinator =
            make_hello(SenderRole::Coordinator, nonce, offer, atomics).map_err(|error| {
                WindowsCoordinatorSessionFailure::after_child(
                    error,
                    WindowsCoordinatorFailureState::Spawned,
                )
            })?;
        write_message(
            session.pipe.0,
            &encode_frame(&NegotiationFrame::Hello(clone_hello(&coordinator))).map_err(
                |error| {
                    WindowsCoordinatorSessionFailure::after_child(
                        error,
                        WindowsCoordinatorFailureState::Negotiating,
                    )
                },
            )?,
            options.deadline(),
            Some(session.process.0),
        )
        .map_err(|error| {
            WindowsCoordinatorSessionFailure::after_child(
                map_transport_error(error),
                WindowsCoordinatorFailureState::Negotiating,
            )
        })?;
        let bytes = read_message(
            session.pipe.0,
            MAX_VNEXT_RECORD_BYTES,
            options.deadline(),
            Some(session.process.0),
        )
        .map_err(|error| {
            WindowsCoordinatorSessionFailure::after_child(
                map_transport_error(error),
                WindowsCoordinatorFailureState::Negotiating,
            )
        })?;
        let receiver = match decode_frame(
            &bytes,
            SenderRole::Receiver,
            nonce,
            MAX_WINDOWS_HELLO_PAYLOAD as u32,
        )
        .map_err(|error| {
            WindowsCoordinatorSessionFailure::after_child(
                map_negotiation_error(error),
                WindowsCoordinatorFailureState::Negotiating,
            )
        })? {
            NegotiationFrame::Hello(frame) => frame,
            NegotiationFrame::Accept(_) | NegotiationFrame::Reject(_) => {
                return Err(WindowsCoordinatorSessionFailure::after_child(
                    WindowsPublicSessionError::MalformedPeer,
                    WindowsCoordinatorFailureState::Negotiating,
                ));
            }
        };
        let peer_application_payload = receiver.application_payload.clone();
        let transcript =
            NegotiatedTranscript::from_hellos(HelloPair::new(coordinator, receiver), atomics)
                .map_err(|error| {
                    WindowsCoordinatorSessionFailure::after_child(
                        map_negotiation_error(error),
                        WindowsCoordinatorFailureState::Negotiating,
                    )
                })?;
        Ok(Self {
            session: Some(session),
            transcript,
            nonce,
            deadline: options.deadline(),
            peer_application_payload,
            not_sync: PhantomData,
        })
    }

    pub(crate) fn peer_application_payload(&self) -> &[u8] {
        &self.peer_application_payload
    }

    pub(crate) fn decide(
        mut self,
        rejection: Option<NonZeroU32>,
    ) -> Result<
        WindowsNegotiationOutcome<WindowsCoordinatorReadySession>,
        WindowsCoordinatorSessionFailure,
    > {
        let mut session = self
            .session
            .take()
            .expect("negotiating owner retains child");
        let challenge = decision_challenge().map_err(|error| {
            WindowsCoordinatorSessionFailure::after_child(
                error,
                WindowsCoordinatorFailureState::Negotiating,
            )
        })?;
        if let Some(reason) = rejection {
            let reject = self
                .transcript
                .coordinator_reject(challenge, reason)
                .map_err(|error| {
                    WindowsCoordinatorSessionFailure::after_child(
                        map_negotiation_error(error),
                        WindowsCoordinatorFailureState::Negotiating,
                    )
                })?;
            write_message(
                session.pipe.0,
                &encode_frame(&NegotiationFrame::Reject(reject)).map_err(|error| {
                    WindowsCoordinatorSessionFailure::after_child(
                        error,
                        WindowsCoordinatorFailureState::Negotiating,
                    )
                })?,
                self.deadline,
                Some(session.process.0),
            )
            .map_err(|error| {
                WindowsCoordinatorSessionFailure::after_child(
                    map_transport_error(error),
                    WindowsCoordinatorFailureState::Negotiating,
                )
            })?;
            session.abort_child();
            return Ok(WindowsNegotiationOutcome::Rejected {
                by: WindowsNegotiationRole::Coordinator,
                reason,
                cleanup: Some(terminated_cleanup()),
            });
        }
        let accept = self
            .transcript
            .coordinator_accept(challenge)
            .map_err(|error| {
                WindowsCoordinatorSessionFailure::after_child(
                    map_negotiation_error(error),
                    WindowsCoordinatorFailureState::Negotiating,
                )
            })?;
        self.transcript
            .validate_accept(accept, SenderRole::Coordinator)
            .map_err(|error| {
                WindowsCoordinatorSessionFailure::after_child(
                    map_negotiation_error(error),
                    WindowsCoordinatorFailureState::Negotiating,
                )
            })?;
        write_message(
            session.pipe.0,
            &encode_frame(&NegotiationFrame::Accept(accept)).map_err(|error| {
                WindowsCoordinatorSessionFailure::after_child(
                    error,
                    WindowsCoordinatorFailureState::Negotiating,
                )
            })?,
            self.deadline,
            Some(session.process.0),
        )
        .map_err(|error| {
            WindowsCoordinatorSessionFailure::after_child(
                map_transport_error(error),
                WindowsCoordinatorFailureState::Negotiating,
            )
        })?;
        let bytes = read_message(
            session.pipe.0,
            MAX_VNEXT_RECORD_BYTES,
            self.deadline,
            Some(session.process.0),
        )
        .map_err(|error| {
            WindowsCoordinatorSessionFailure::after_child(
                map_transport_error(error),
                WindowsCoordinatorFailureState::Negotiating,
            )
        })?;
        match decode_frame(
            &bytes,
            SenderRole::Receiver,
            self.nonce,
            MAX_WINDOWS_HELLO_PAYLOAD as u32,
        )
        .map_err(|error| {
            WindowsCoordinatorSessionFailure::after_child(
                map_negotiation_error(error),
                WindowsCoordinatorFailureState::Negotiating,
            )
        })? {
            NegotiationFrame::Accept(peer) => self
                .transcript
                .validate_accept(peer, SenderRole::Receiver)
                .map_err(|error| {
                    WindowsCoordinatorSessionFailure::after_child(
                        map_negotiation_error(error),
                        WindowsCoordinatorFailureState::Negotiating,
                    )
                })?,
            NegotiationFrame::Reject(peer) => {
                let reason = self
                    .transcript
                    .validate_reject(peer, SenderRole::Receiver)
                    .map_err(|error| {
                        WindowsCoordinatorSessionFailure::after_child(
                            map_negotiation_error(error),
                            WindowsCoordinatorFailureState::Negotiating,
                        )
                    })?;
                session.abort_child();
                return Ok(WindowsNegotiationOutcome::Rejected {
                    by: WindowsNegotiationRole::Receiver,
                    reason,
                    cleanup: Some(terminated_cleanup()),
                });
            }
            NegotiationFrame::Hello(_) => {
                return Err(WindowsCoordinatorSessionFailure::after_child(
                    WindowsPublicSessionError::MalformedPeer,
                    WindowsCoordinatorFailureState::Negotiating,
                ));
            }
        }
        let transcript = self.transcript.take_accepted_facts().map_err(|error| {
            WindowsCoordinatorSessionFailure::after_child(
                map_negotiation_error(error),
                WindowsCoordinatorFailureState::Negotiating,
            )
        })?;
        let facts =
            SpawnIdentityFacts::new(std::process::id(), session.pid(), 0, 0, 0, 0, self.nonce)
                .ok_or_else(|| {
                    WindowsCoordinatorSessionFailure::after_child(
                        WindowsPublicSessionError::IdentityMismatch,
                        WindowsCoordinatorFailureState::Negotiating,
                    )
                })?;
        // SAFETY: ChildSession owns the PID-authenticated pipe, exact process,
        // suspended-before-Job spawn, bootstrap nonce, and selected image path.
        let channel = unsafe { CoordinatorChildChannelReceipt::from_verified_native(facts) };
        // SAFETY: CreateProcessW selected the exact absolute application while
        // the process and kill-on-close Job remain owned by ChildSession.
        let image = unsafe { CoordinatorChildImageReceipt::from_verified_native(facts) };
        let evidence =
            CoordinatorAcceptedEvidence::combine(channel, image, transcript).map_err(|error| {
                WindowsCoordinatorSessionFailure::after_child(
                    map_transport_error(error),
                    WindowsCoordinatorFailureState::Negotiating,
                )
            })?;
        let parameters = evidence.session_parameters(NativeAuthorityProfile::WindowsSectionsV1);
        let transport = CoordinatorWindowsControlTransport::from_accepted(session, evidence)
            .map_err(|error| {
                WindowsCoordinatorSessionFailure::after_child(
                    map_transport_error(error),
                    WindowsCoordinatorFailureState::Negotiating,
                )
            })?;
        let dispatcher = AcceptedControlDispatcher::new(transport, parameters).map_err(|_| {
            WindowsCoordinatorSessionFailure::after_child(
                WindowsPublicSessionError::InvalidInput,
                WindowsCoordinatorFailureState::Negotiating,
            )
        })?;
        Ok(WindowsNegotiationOutcome::Accepted(
            WindowsCoordinatorReadySession { dispatcher },
        ))
    }
}

impl WindowsReceiverNegotiatingSession {
    pub(crate) fn from_environment(
        options: &SessionOptions,
    ) -> Result<Self, WindowsPublicSessionError> {
        let channel =
            super::connect_spawned_helper_until(options.deadline()).map_err(map_windows_error)?;
        let offer = public_offer(options)?;
        let atomics = discover_atomic_capabilities()?;
        let nonce = channel.vnext_nonce();
        let bytes = read_message(
            channel.pipe.0,
            MAX_VNEXT_RECORD_BYTES,
            options.deadline(),
            None,
        )
        .map_err(map_transport_error)?;
        let coordinator = match decode_frame(
            &bytes,
            SenderRole::Coordinator,
            nonce,
            MAX_WINDOWS_HELLO_PAYLOAD as u32,
        )
        .map_err(map_negotiation_error)?
        {
            NegotiationFrame::Hello(frame) => frame,
            NegotiationFrame::Accept(_) | NegotiationFrame::Reject(_) => {
                return Err(WindowsPublicSessionError::MalformedPeer);
            }
        };
        let peer_application_payload = coordinator.application_payload.clone();
        let receiver = make_hello(SenderRole::Receiver, nonce, offer, atomics)?;
        write_message(
            channel.pipe.0,
            &encode_frame(&NegotiationFrame::Hello(clone_hello(&receiver)))?,
            options.deadline(),
            None,
        )
        .map_err(map_transport_error)?;
        let transcript =
            NegotiatedTranscript::from_hellos(HelloPair::new(coordinator, receiver), atomics)
                .map_err(map_negotiation_error)?;
        Ok(Self {
            channel,
            transcript,
            nonce,
            deadline: options.deadline(),
            peer_application_payload,
            not_sync: PhantomData,
        })
    }

    pub(crate) fn peer_application_payload(&self) -> &[u8] {
        &self.peer_application_payload
    }

    pub(crate) fn decide_after_coordinator(
        mut self,
        decide: impl FnOnce(&[u8]) -> Option<NonZeroU32>,
    ) -> Result<WindowsNegotiationOutcome<WindowsReceiverReadySession>, WindowsPublicSessionError>
    {
        let bytes = read_message(
            self.channel.pipe.0,
            MAX_VNEXT_RECORD_BYTES,
            self.deadline,
            None,
        )
        .map_err(map_transport_error)?;
        match decode_frame(
            &bytes,
            SenderRole::Coordinator,
            self.nonce,
            MAX_WINDOWS_HELLO_PAYLOAD as u32,
        )
        .map_err(map_negotiation_error)?
        {
            NegotiationFrame::Accept(peer) => self
                .transcript
                .validate_accept(peer, SenderRole::Coordinator)
                .map_err(map_negotiation_error)?,
            NegotiationFrame::Reject(peer) => {
                let reason = self
                    .transcript
                    .validate_reject(peer, SenderRole::Coordinator)
                    .map_err(map_negotiation_error)?;
                return Ok(WindowsNegotiationOutcome::Rejected {
                    by: WindowsNegotiationRole::Coordinator,
                    reason,
                    cleanup: None,
                });
            }
            NegotiationFrame::Hello(_) => return Err(WindowsPublicSessionError::MalformedPeer),
        }
        if let Some(reason) = decide(&self.peer_application_payload) {
            let reject = self
                .transcript
                .receiver_reject(reason)
                .map_err(map_negotiation_error)?;
            write_message(
                self.channel.pipe.0,
                &encode_frame(&NegotiationFrame::Reject(reject))?,
                self.deadline,
                None,
            )
            .map_err(map_transport_error)?;
            return Ok(WindowsNegotiationOutcome::Rejected {
                by: WindowsNegotiationRole::Receiver,
                reason,
                cleanup: None,
            });
        }
        let accept = self
            .transcript
            .receiver_accept()
            .map_err(map_negotiation_error)?;
        self.transcript
            .validate_accept(accept, SenderRole::Receiver)
            .map_err(map_negotiation_error)?;
        write_message(
            self.channel.pipe.0,
            &encode_frame(&NegotiationFrame::Accept(accept))?,
            self.deadline,
            None,
        )
        .map_err(map_transport_error)?;
        let transcript = self
            .transcript
            .take_accepted_facts()
            .map_err(map_negotiation_error)?;
        let facts = SpawnIdentityFacts::new(
            self.channel.parent_pid(),
            std::process::id(),
            0,
            0,
            0,
            0,
            self.nonce,
        )
        .ok_or(WindowsPublicSessionError::IdentityMismatch)?;
        // SAFETY: bootstrap authenticated the exact named-pipe server PID and nonce.
        let evidence = unsafe { ReceiverSpawnerEvidence::from_verified_native(facts, transcript) }
            .map_err(map_transport_error)?;
        let parameters = evidence.session_parameters(NativeAuthorityProfile::WindowsSectionsV1);
        let transport = ReceiverWindowsControlTransport::from_accepted(self.channel, evidence)
            .map_err(map_transport_error)?;
        let dispatcher = AcceptedControlDispatcher::new(transport, parameters)
            .map_err(|_| WindowsPublicSessionError::InvalidInput)?;
        Ok(WindowsNegotiationOutcome::Accepted(
            WindowsReceiverReadySession { dispatcher },
        ))
    }
}

macro_rules! ready_facts {
    ($type:ty) => {
        impl $type {
            pub(crate) const fn limits(&self) -> SessionLimits {
                self.dispatcher.limits()
            }
            pub(crate) const fn atomics(&self) -> AtomicCapabilities {
                self.dispatcher.atomics()
            }
            pub(crate) const fn protocol_version(&self) -> ProtocolVersion {
                self.dispatcher.protocol_version()
            }
            pub(crate) fn state(&self) -> SessionState {
                self.dispatcher.session_state()
            }
            pub(crate) fn active_leases(&self) -> ActiveLeaseFacts {
                self.dispatcher.active_lease_facts()
            }
            pub(crate) fn poll_peer(&mut self) -> Result<PeerStatus, WindowsPublicSessionError> {
                self.dispatcher
                    .try_poll_peer()
                    .map(peer_status)
                    .map_err(map_control_error)
            }
            pub(crate) fn close_resources(&mut self) -> Result<(), WindowsPublicSessionError> {
                self.dispatcher
                    .try_close_resources()
                    .map_err(map_resource_error)
            }
            pub(crate) fn send_control(
                &mut self,
                kind: u32,
                payload: &[u8],
                deadline: AbsoluteDeadline,
            ) -> Result<(), WindowsPublicSessionError> {
                self.dispatcher
                    .send_parts(kind, payload, deadline)
                    .map_err(map_control_error)
            }
            pub(crate) fn receive_control(
                &mut self,
                deadline: AbsoluteDeadline,
            ) -> Result<ControlFrame, WindowsPublicSessionError> {
                self.dispatcher.receive(deadline).map_err(map_control_error)
            }
        }
    };
}
ready_facts!(WindowsCoordinatorReadySession);
ready_facts!(WindowsReceiverReadySession);

impl WindowsCoordinatorReadySession {
    pub(crate) fn wait_for_exit(&mut self, deadline: AbsoluteDeadline) -> ChildCleanupFacts {
        match self.dispatcher.wait_for_windows_child(deadline) {
            Ok(code) => ChildCleanupFacts::new(
                Some(ChildExitStatus::Exited(code as i32)),
                DescendantCleanupStatus::ContainedProcessTreeComplete,
                None,
            ),
            Err(error) => cleanup_from_transport(error),
        }
    }
    pub(crate) fn abort(&mut self, deadline: AbsoluteDeadline) -> ChildCleanupFacts {
        match self.dispatcher.terminate_and_reap(deadline) {
            Ok(()) => terminated_cleanup(),
            Err(error) => cleanup_from_transport(error),
        }
    }
    pub(crate) fn transfer_batch(
        &mut self,
        batch: TransferBatch,
        deadline: AbsoluteDeadline,
    ) -> Result<ActiveRegionSet, WindowsPublicSessionError> {
        if deadline.is_expired() {
            return Err(WindowsPublicSessionError::DeadlineExpired);
        }
        let frame = self
            .dispatcher
            .begin_public_windows_transfer_capacity(&batch, deadline)
            .map_err(map_batch_error)?;
        let reservations = self.dispatcher.reserve_windows_transfer_batch(&batch);
        let preparation = if reservations.is_ok() {
            Some(WindowsMixedDirectionBatch::prepare(
                batch,
                self.dispatcher.authority_profile(),
                deadline,
            ))
        } else {
            drop(batch);
            None
        };
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
            .dispatcher
            .exchange_public_windows_transfer_capacity(&frame, local_status, deadline)
            .map_err(map_batch_error)?;
        let reservations = reservations.map_err(|_| WindowsPublicSessionError::ActiveLimit)?;
        let prepared = preparation
            .expect("successful reservation attempts native preparation")
            .map_err(map_memory_error)?;
        if !peer_ready {
            return Err(WindowsPublicSessionError::ActiveLimit);
        }
        let mut transaction = self
            .dispatcher
            .begin_public_windows_mixed_direction_batch_preflighted(
                prepared,
                reservations,
                frame,
                deadline,
            )
            .map_err(map_batch_error)?;
        transaction.prepare().map_err(map_batch_error)?;
        let committed = transaction.commit().map_err(map_batch_error)?;
        self.dispatcher
            .activate_windows_coordinator_mixed_direction_batch(committed)
            .map_err(map_activation_error)
    }
}

impl WindowsReceiverReadySession {
    pub(crate) fn wait_for_exit(
        &mut self,
        deadline: AbsoluteDeadline,
    ) -> Result<PeerStatus, WindowsPublicSessionError> {
        loop {
            match self.poll_peer()? {
                PeerStatus::Disconnected => return Ok(PeerStatus::Disconnected),
                PeerStatus::Connected if deadline.is_expired() => {
                    return Err(WindowsPublicSessionError::DeadlineExpired);
                }
                PeerStatus::Connected => std::thread::sleep(
                    core::time::Duration::from_millis(1).min(deadline.remaining()),
                ),
            }
        }
    }
    pub(crate) fn abort(&mut self) {
        self.dispatcher.poison_session();
    }
    pub(crate) fn receive_batch(
        &mut self,
        expected: ExpectedBatch,
        deadline: AbsoluteDeadline,
    ) -> Result<ActiveRegionSet, WindowsPublicSessionError> {
        if deadline.is_expired() {
            return Err(WindowsPublicSessionError::DeadlineExpired);
        }
        let mut transaction = self
            .dispatcher
            .begin_public_windows_expected_mixed_direction_batch(expected, deadline)
            .map_err(map_batch_error)?;
        transaction.prepare().map_err(map_batch_error)?;
        let committed = transaction.commit().map_err(map_batch_error)?;
        self.dispatcher
            .activate_windows_receiver_mixed_direction_batch(committed)
            .map_err(map_activation_error)
    }
}

fn public_offer(options: &SessionOptions) -> Result<WindowsHelloOffer, WindowsPublicSessionError> {
    validate_offer(WindowsHelloOffer {
        supported_features: FeatureBits([3, 0]),
        required_features: FeatureBits([
            u64::from(options.requires_atomic_u32())
                | (u64::from(options.requires_atomic_u64()) << 1),
            0,
        ]),
        limits: options.limits(),
        application_payload: options.application_payload().to_vec(),
    })
}

fn validate_offer(
    mut offer: WindowsHelloOffer,
) -> Result<WindowsHelloOffer, WindowsPublicSessionError> {
    if offer.application_payload.len() > MAX_WINDOWS_HELLO_PAYLOAD {
        return Err(WindowsPublicSessionError::InvalidInput);
    }
    offer.limits.max_bootstrap_payload_bytes = offer
        .limits
        .max_bootstrap_payload_bytes
        .min(MAX_WINDOWS_HELLO_PAYLOAD as u32);
    offer.limits.max_control_payload_bytes = offer
        .limits
        .max_control_payload_bytes
        .min(MAX_WINDOWS_CONTROL_PAYLOAD);
    offer
        .limits
        .validate()
        .map_err(WindowsPublicSessionError::NativeNegotiation)?;
    if offer.application_payload.len() > offer.limits.max_bootstrap_payload_bytes as usize {
        return Err(WindowsPublicSessionError::InvalidInput);
    }
    Ok(offer)
}

fn make_hello(
    role: SenderRole,
    nonce: [u8; NONCE_LEN],
    offer: WindowsHelloOffer,
    atomics: AtomicCapabilities,
) -> Result<HelloFrame, WindowsPublicSessionError> {
    Ok(HelloFrame {
        role,
        nonce,
        supported_features: offer.supported_features,
        required_features: offer.required_features,
        limits: offer.limits,
        atomics: AtomicOffer::from_local(atomics).map_err(map_negotiation_error)?,
        target: TargetFacts::current(),
        application_payload: offer.application_payload,
    })
}

fn clone_hello(hello: &HelloFrame) -> HelloFrame {
    HelloFrame {
        role: hello.role,
        nonce: hello.nonce,
        supported_features: hello.supported_features,
        required_features: hello.required_features,
        limits: hello.limits,
        atomics: hello.atomics,
        target: hello.target,
        application_payload: hello.application_payload.clone(),
    }
}

fn encode_frame(frame: &NegotiationFrame) -> Result<Vec<u8>, WindowsPublicSessionError> {
    let len = frame.encoded_len().map_err(map_negotiation_error)?;
    if len > MAX_VNEXT_RECORD_BYTES {
        return Err(WindowsPublicSessionError::InvalidInput);
    }
    let mut bytes = vec![0; len];
    frame
        .encode_into(&mut bytes)
        .map_err(map_negotiation_error)?;
    Ok(bytes)
}

fn decision_challenge() -> Result<DecisionChallenge, WindowsPublicSessionError> {
    let nonce = session_nonce().map_err(map_windows_error)?;
    DecisionChallenge::from_os_csprng(nonce[..16].try_into().expect("fixed challenge"))
        .map_err(map_negotiation_error)
}

fn discover_atomic_capabilities() -> Result<AtomicCapabilities, WindowsPublicSessionError> {
    AtomicCapabilities::from_verified_native(
        super::page_align(1).map_err(map_windows_error)?,
        64,
        cfg!(target_has_atomic = "32"),
        cfg!(target_has_atomic = "64"),
    )
    .map_err(WindowsPublicSessionError::NativeNegotiation)
}

fn map_windows_error(error: WindowsError) -> WindowsPublicSessionError {
    match error {
        WindowsError::TimedOut(_) => WindowsPublicSessionError::DeadlineExpired,
        WindowsError::ChildExit(_) => WindowsPublicSessionError::PeerExited,
        WindowsError::WrongPeer => WindowsPublicSessionError::IdentityMismatch,
        WindowsError::InvalidBootstrap
        | WindowsError::ForeignPending
        | WindowsError::InvalidHandle => WindowsPublicSessionError::MalformedPeer,
        WindowsError::Os { code, .. } => WindowsPublicSessionError::Native(Some(code as i32)),
        WindowsError::InvalidSize(_)
        | WindowsError::Layout(_)
        | WindowsError::Binding(_)
        | WindowsError::CapabilityAlreadyTransferred => WindowsPublicSessionError::InvalidInput,
    }
}

fn map_transport_error(error: SessionTransportError) -> WindowsPublicSessionError {
    match error {
        SessionTransportError::DeadlineExpired => WindowsPublicSessionError::DeadlineExpired,
        SessionTransportError::PeerExited => WindowsPublicSessionError::PeerExited,
        SessionTransportError::IdentityMismatch => WindowsPublicSessionError::IdentityMismatch,
        SessionTransportError::Ambiguous => WindowsPublicSessionError::Ambiguous,
        SessionTransportError::MalformedRecord | SessionTransportError::RecordTooLarge => {
            WindowsPublicSessionError::MalformedPeer
        }
        SessionTransportError::Native(code) => WindowsPublicSessionError::Native(code),
    }
}
fn map_negotiation_error(_: NegotiationWireError) -> WindowsPublicSessionError {
    WindowsPublicSessionError::NegotiationFailed
}
fn peer_status(state: crate::backend::PeerState) -> PeerStatus {
    match state {
        crate::backend::PeerState::Running => PeerStatus::Connected,
        crate::backend::PeerState::ExitedUnknown => PeerStatus::Disconnected,
    }
}
fn map_control_error(error: AcceptedControlError) -> WindowsPublicSessionError {
    match error {
        AcceptedControlError::Control(ControlError::Poisoned) => {
            WindowsPublicSessionError::Poisoned
        }
        AcceptedControlError::Control(error) => WindowsPublicSessionError::Control(error),
        AcceptedControlError::Transport(error) => map_transport_error(error),
    }
}
fn map_memory_error(error: WindowsBatchError) -> WindowsPublicSessionError {
    match error {
        WindowsBatchError::DeadlineExpired => WindowsPublicSessionError::DeadlineExpired,
        WindowsBatchError::InvalidBatch
        | WindowsBatchError::InvalidSize
        | WindowsBatchError::WrongProvenance => WindowsPublicSessionError::InvalidInput,
        WindowsBatchError::WrongObject | WindowsBatchError::WrongAccess => {
            WindowsPublicSessionError::MalformedPeer
        }
        WindowsBatchError::Native(error) => map_windows_error(error),
    }
}
fn map_batch_error(error: WindowsCapabilityBatchError) -> WindowsPublicSessionError {
    match error {
        WindowsCapabilityBatchError::Memory(error) => map_memory_error(error),
        WindowsCapabilityBatchError::Control(error) => map_control_error(error),
        WindowsCapabilityBatchError::Resource(_) | WindowsCapabilityBatchError::ActiveLimit => {
            WindowsPublicSessionError::ActiveLimit
        }
        WindowsCapabilityBatchError::PeerPreparationFailed => {
            WindowsPublicSessionError::PeerPreparationFailed
        }
    }
}
fn map_activation_error(error: WindowsActivationError) -> WindowsPublicSessionError {
    match error {
        WindowsActivationError::Batch(error) => WindowsPublicSessionError::Batch(error),
        WindowsActivationError::WrongSession
        | WindowsActivationError::Memory(_)
        | WindowsActivationError::Active(_) => WindowsPublicSessionError::ActivationFailed,
    }
}
fn map_resource_error(error: ResourceError) -> WindowsPublicSessionError {
    match error {
        ResourceError::ActiveLeases(_) | ResourceError::ActiveLimit => {
            WindowsPublicSessionError::ActiveLimit
        }
        ResourceError::Poisoned | ResourceError::Closed => WindowsPublicSessionError::Poisoned,
        ResourceError::InvalidLimits | ResourceError::MappedLengthMismatch { .. } => {
            WindowsPublicSessionError::Native(None)
        }
    }
}

fn incomplete_cleanup() -> ChildCleanupFacts {
    ChildCleanupFacts::new(
        None,
        DescendantCleanupStatus::OwnedContainmentUnverified,
        None,
    )
}
fn terminated_cleanup() -> ChildCleanupFacts {
    ChildCleanupFacts::new(
        Some(ChildExitStatus::Exited(127)),
        DescendantCleanupStatus::ContainedProcessTreeComplete,
        None,
    )
}
fn cleanup_from_transport(error: SessionTransportError) -> ChildCleanupFacts {
    let code = match error {
        SessionTransportError::Native(code) => code,
        _ => None,
    };
    ChildCleanupFacts::new(
        None,
        DescendantCleanupStatus::OwnedContainmentUnverified,
        code,
    )
}
