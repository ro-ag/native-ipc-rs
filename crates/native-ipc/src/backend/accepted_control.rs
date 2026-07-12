use super::{AuthenticatedZeroRightsTransport, PeerState, SessionTransportError};
use crate::control::{ControlError, ControlFrame, ControlState, control_wire_len};
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

impl<T: AuthenticatedZeroRightsTransport> AcceptedControlDispatcher<T> {
    pub(crate) fn new(transport: T, nonce: [u8; 32], maximum_payload: u32) -> Option<Self> {
        let maximum_wire_len = control_wire_len(usize::try_from(maximum_payload).ok()?)?;
        Some(Self {
            transport,
            state: ControlState::new(nonce, maximum_payload)?,
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

    pub(crate) fn begin_transaction(&mut self) -> Result<(), AcceptedControlError> {
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

    pub(crate) fn end_transaction(&mut self) -> Result<(), AcceptedControlError> {
        match self.state.end_transaction() {
            Ok(()) => Ok(()),
            Err(error) => {
                if self.state.is_poisoned() {
                    self.transport.poison();
                }
                Err(AcceptedControlError::Control(error))
            }
        }
    }

    fn poison_both(&mut self) {
        self.state.poison();
        self.transport.poison();
    }
}
