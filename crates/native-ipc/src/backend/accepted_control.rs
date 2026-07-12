use super::{
    AuthenticatedZeroRightsTransport, CoordinatorCapabilityTransport, OwnedChildLifecycle,
    PeerState, ReceiverCapabilityTransport, SessionTransportError,
};
use crate::control::{ControlError, ControlFrame, ControlState, control_wire_len};
use crate::protocol::CapabilityFrame;
use crate::session::AbsoluteDeadline;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AcceptedControlError {
    Control(ControlError),
    Transport(SessionTransportError),
}

/// Private application-control dispatcher after authenticated bilateral ACCEPT.
///
/// It owns the protocol sequence state and the authenticated zero-rights record
/// transport. It deliberately exposes neither one as separable native parts.
pub(crate) struct AcceptedControlDispatcher<T> {
    transport: T,
    state: ControlState,
    maximum_wire_len: usize,
}

/// Coordinator-owned open native transaction on the accepted session owner.
///
/// G1b deliberately has no completion operation. Until the complete native
/// preparation plus READY/COMMIT reducer exists, dropping this value poisons
/// the inseparable session owner.
pub(crate) struct CoordinatorCapabilityTransaction<'a, T: CoordinatorCapabilityTransport> {
    dispatcher: &'a mut AcceptedControlDispatcher<T>,
    deadline: AbsoluteDeadline,
    attempted: bool,
    already_poisoned: bool,
}

/// Receiver-owned open native transaction and its immediately owned imports.
///
/// Installed capabilities cannot leave this guard in G1b. A later complete
/// import state machine may consume them without exposing the accepted native
/// endpoint or independent pending tokens.
pub(crate) struct ReceiverCapabilityTransaction<'a, T: ReceiverCapabilityTransport> {
    dispatcher: &'a mut AcceptedControlDispatcher<T>,
    deadline: AbsoluteDeadline,
    received: Option<T::ReceivedCapabilities>,
    attempted: bool,
    already_poisoned: bool,
}

impl<T: AuthenticatedZeroRightsTransport> AcceptedControlDispatcher<T> {
    pub(crate) fn new(transport: T, nonce: [u8; 32], maximum_payload: u32) -> Result<Self, T> {
        let Some(maximum_wire_len) = usize::try_from(maximum_payload)
            .ok()
            .and_then(control_wire_len)
        else {
            return Err(transport);
        };
        let Some(state) = ControlState::new(nonce, maximum_payload) else {
            return Err(transport);
        };
        Ok(Self {
            transport,
            state,
            maximum_wire_len,
        })
    }

    pub(crate) fn send(
        &mut self,
        frame: &ControlFrame,
        deadline: AbsoluteDeadline,
    ) -> Result<(), AcceptedControlError> {
        if self.state.is_poisoned() {
            return Err(AcceptedControlError::Control(ControlError::Poisoned));
        }
        let wire_len = match self.state.encoded_len(frame) {
            Ok(wire_len) => wire_len,
            Err(error @ (ControlError::TransactionConflict | ControlError::SequenceExhausted)) => {
                self.poison_both();
                return Err(AcceptedControlError::Control(error));
            }
            Err(error) => return Err(AcceptedControlError::Control(error)),
        };
        let mut wire = Vec::new();
        wire.try_reserve_exact(wire_len)
            .map_err(|_| AcceptedControlError::Control(ControlError::AllocationFailed))?;
        wire.resize(wire_len, 0);
        if let Err(error) = self.state.encode_into(frame, &mut wire) {
            if self.state.is_poisoned() {
                self.transport.poison();
            }
            return Err(AcceptedControlError::Control(error));
        }
        if let Err(error) = self.transport.send_record(&wire, deadline) {
            self.poison_both();
            return Err(AcceptedControlError::Transport(error));
        }
        Ok(())
    }

    pub(crate) fn receive(
        &mut self,
        deadline: AbsoluteDeadline,
    ) -> Result<ControlFrame, AcceptedControlError> {
        if self.state.is_poisoned() {
            return Err(AcceptedControlError::Control(ControlError::Poisoned));
        }
        if self.state.is_transaction_open() {
            self.poison_both();
            return Err(AcceptedControlError::Control(
                ControlError::TransactionConflict,
            ));
        }
        let wire = match self
            .transport
            .receive_record(self.maximum_wire_len, deadline)
        {
            Ok(wire) if wire.len() <= self.maximum_wire_len => wire,
            Ok(_) => {
                self.poison_both();
                return Err(AcceptedControlError::Transport(
                    SessionTransportError::RecordTooLarge,
                ));
            }
            Err(error) => {
                self.poison_both();
                return Err(AcceptedControlError::Transport(error));
            }
        };
        match self.state.decode_owned(wire) {
            Ok(frame) => Ok(frame),
            Err(error) => {
                self.poison_both();
                Err(AcceptedControlError::Control(error))
            }
        }
    }

    pub(crate) fn try_poll_peer(&mut self) -> Result<PeerState, AcceptedControlError> {
        if self.state.is_poisoned() {
            return Err(AcceptedControlError::Control(ControlError::Poisoned));
        }
        match self.transport.try_poll_peer() {
            Ok(state) => Ok(state),
            Err(error) => {
                self.poison_both();
                Err(AcceptedControlError::Transport(error))
            }
        }
    }

    fn poison_both(&mut self) {
        self.state.poison();
        self.transport.poison();
    }
}

impl<T: CoordinatorCapabilityTransport> AcceptedControlDispatcher<T> {
    pub(crate) fn begin_capability_transaction(
        &mut self,
        deadline: AbsoluteDeadline,
    ) -> Result<CoordinatorCapabilityTransaction<'_, T>, AcceptedControlError> {
        self.begin_native_transaction(deadline)?;
        Ok(CoordinatorCapabilityTransaction {
            dispatcher: self,
            deadline,
            attempted: false,
            already_poisoned: false,
        })
    }
}

impl<T: ReceiverCapabilityTransport> AcceptedControlDispatcher<T> {
    /// Awaits a coordinator-initiated native transaction without sending any
    /// receiver-originated start record.
    pub(crate) fn await_capability_transaction(
        &mut self,
        deadline: AbsoluteDeadline,
    ) -> Result<ReceiverCapabilityTransaction<'_, T>, AcceptedControlError> {
        self.begin_native_transaction(deadline)?;
        Ok(ReceiverCapabilityTransaction {
            dispatcher: self,
            deadline,
            received: None,
            attempted: false,
            already_poisoned: false,
        })
    }
}

impl<T: AuthenticatedZeroRightsTransport> AcceptedControlDispatcher<T> {
    fn begin_native_transaction(
        &mut self,
        deadline: AbsoluteDeadline,
    ) -> Result<(), AcceptedControlError> {
        if deadline.is_expired() {
            return Err(AcceptedControlError::Transport(
                SessionTransportError::DeadlineExpired,
            ));
        }
        match self.state.begin_transaction() {
            Ok(()) => Ok(()),
            Err(error) => {
                if self.state.is_poisoned() {
                    self.transport.poison();
                }
                Err(AcceptedControlError::Control(error))
            }
        }
    }
}

impl<T: CoordinatorCapabilityTransport> CoordinatorCapabilityTransaction<'_, T> {
    pub(crate) fn send(
        &mut self,
        frame: &CapabilityFrame,
        capabilities: T::Capabilities<'_>,
    ) -> Result<(), AcceptedControlError> {
        if self.attempted {
            self.poison();
            return Err(AcceptedControlError::Control(ControlError::ReplayOrReorder));
        }
        self.attempted = true;
        if let Err(error) =
            self.dispatcher
                .transport
                .send_capability_record(frame, capabilities, self.deadline)
        {
            self.poison();
            return Err(AcceptedControlError::Transport(error));
        }
        Ok(())
    }

    fn poison(&mut self) {
        if !self.already_poisoned {
            self.dispatcher.poison_both();
            self.already_poisoned = true;
        }
    }
}

impl<T: CoordinatorCapabilityTransport> Drop for CoordinatorCapabilityTransaction<'_, T> {
    fn drop(&mut self) {
        self.poison();
    }
}

impl<T: ReceiverCapabilityTransport> ReceiverCapabilityTransaction<'_, T> {
    pub(crate) fn receive(
        &mut self,
        expected: &CapabilityFrame,
    ) -> Result<&T::ReceivedCapabilities, AcceptedControlError> {
        if self.attempted {
            self.poison();
            return Err(AcceptedControlError::Control(ControlError::ReplayOrReorder));
        }
        self.attempted = true;
        let received = match self
            .dispatcher
            .transport
            .receive_capability_record(expected, self.deadline)
        {
            Ok(received) => received,
            Err(error) => {
                self.poison();
                return Err(AcceptedControlError::Transport(error));
            }
        };
        self.received = Some(received);
        Ok(self
            .received
            .as_ref()
            .expect("successful receive retains transaction-owned capabilities"))
    }

    fn poison(&mut self) {
        if !self.already_poisoned {
            self.dispatcher.poison_both();
            self.already_poisoned = true;
        }
    }
}

impl<T: ReceiverCapabilityTransport> Drop for ReceiverCapabilityTransaction<'_, T> {
    fn drop(&mut self) {
        self.poison();
    }
}

impl<T: AuthenticatedZeroRightsTransport + OwnedChildLifecycle> AcceptedControlDispatcher<T> {
    pub(crate) fn terminate_and_reap(
        &mut self,
        deadline: AbsoluteDeadline,
    ) -> Result<(), SessionTransportError> {
        self.transport.poison();
        self.state.poison();
        self.transport.terminate_and_reap(deadline)
    }
}
