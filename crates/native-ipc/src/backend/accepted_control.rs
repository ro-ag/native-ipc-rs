use super::{
    AcceptedSessionParameters, AuthenticatedZeroRightsTransport, CoordinatorCapabilityTransport,
    OwnedChildLifecycle, PeerState, ReceiverCapabilityTransport, SessionTransportError,
};
use crate::control::{ControlError, ControlFrame, ControlState, control_wire_len};
use crate::protocol::{CapabilityFrame, ManifestEntry, TransferManifest};
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
    parameters: AcceptedSessionParameters,
    next_transaction: u64,
}

/// Coordinator-owned open native transaction on the accepted session owner.
///
/// G1b deliberately has no completion operation. Until the complete native
/// preparation plus READY/COMMIT reducer exists, dropping this value poisons
/// the inseparable session owner.
pub(crate) struct CoordinatorCapabilityTransaction<'a, T: CoordinatorCapabilityTransport> {
    dispatcher: &'a mut AcceptedControlDispatcher<T>,
    frame: CapabilityFrame,
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
    frame: CapabilityFrame,
    deadline: AbsoluteDeadline,
    received: Option<T::ReceivedCapabilities>,
    attempted: bool,
    already_poisoned: bool,
}

impl<T: AuthenticatedZeroRightsTransport> AcceptedControlDispatcher<T> {
    pub(crate) fn new(transport: T, parameters: AcceptedSessionParameters) -> Result<Self, T> {
        let facts = parameters.facts();
        let limits = parameters.limits();
        let nonce = facts.nonce();
        let maximum_payload = limits.max_control_payload_bytes;
        if limits.validate().is_err() || !parameters.authority_profile().is_vnext() {
            return Err(transport);
        }
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
            parameters,
            next_transaction: 1,
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
        entries: Vec<ManifestEntry>,
        deadline: AbsoluteDeadline,
    ) -> Result<CoordinatorCapabilityTransaction<'_, T>, AcceptedControlError> {
        let frame = self.begin_native_transaction(entries, deadline)?;
        Ok(CoordinatorCapabilityTransaction {
            dispatcher: self,
            frame,
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
        expected_entries: Vec<ManifestEntry>,
        deadline: AbsoluteDeadline,
    ) -> Result<ReceiverCapabilityTransaction<'_, T>, AcceptedControlError> {
        let frame = self.begin_native_transaction(expected_entries, deadline)?;
        Ok(ReceiverCapabilityTransaction {
            dispatcher: self,
            frame,
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
        entries: Vec<ManifestEntry>,
        deadline: AbsoluteDeadline,
    ) -> Result<CapabilityFrame, AcceptedControlError> {
        if self.state.is_poisoned() {
            return Err(AcceptedControlError::Control(ControlError::Poisoned));
        }
        if deadline.is_expired() {
            return Err(AcceptedControlError::Transport(
                SessionTransportError::DeadlineExpired,
            ));
        }
        let limits = self.parameters.limits();
        if self.next_transaction > limits.max_transactions {
            self.poison_both();
            return Err(AcceptedControlError::Control(
                ControlError::SequenceExhausted,
            ));
        }
        let facts = self.parameters.facts();
        let Some(manifest) = TransferManifest::new_with_authority(
            facts.nonce(),
            facts.parent_pid(),
            facts.child_pid(),
            self.next_transaction,
            self.parameters.authority_profile(),
            entries,
        ) else {
            return Err(AcceptedControlError::Control(ControlError::NonCanonical));
        };
        if !manifest.fits_limits(limits) {
            return Err(AcceptedControlError::Control(ControlError::PayloadTooLarge));
        }
        match self.state.begin_transaction() {
            Ok(()) => {}
            Err(error) => {
                if self.state.is_poisoned() {
                    self.transport.poison();
                }
                return Err(AcceptedControlError::Control(error));
            }
        }
        self.next_transaction = self
            .next_transaction
            .checked_add(1)
            .expect("negotiated transaction maximum cannot approach u64 overflow");
        Ok(CapabilityFrame::from_manifest(&manifest))
    }
}

impl<T: CoordinatorCapabilityTransport> CoordinatorCapabilityTransaction<'_, T> {
    pub(crate) fn send(
        &mut self,
        capabilities: T::Capabilities<'_>,
    ) -> Result<(), AcceptedControlError> {
        if self.attempted {
            self.poison();
            return Err(AcceptedControlError::Control(ControlError::ReplayOrReorder));
        }
        self.attempted = true;
        if let Err(error) = self.dispatcher.transport.send_capability_record(
            &self.frame,
            capabilities,
            self.deadline,
        ) {
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

    #[cfg(test)]
    pub(crate) fn complete_for_test(mut self) {
        assert!(
            self.attempted,
            "test completion requires one capability send"
        );
        self.dispatcher
            .state
            .end_transaction()
            .expect("test completion follows one open transaction");
        self.already_poisoned = true;
    }
}

impl<T: CoordinatorCapabilityTransport> Drop for CoordinatorCapabilityTransaction<'_, T> {
    fn drop(&mut self) {
        self.poison();
    }
}

impl<T: ReceiverCapabilityTransport> ReceiverCapabilityTransaction<'_, T> {
    pub(crate) fn receive(&mut self) -> Result<&T::ReceivedCapabilities, AcceptedControlError> {
        if self.attempted {
            self.poison();
            return Err(AcceptedControlError::Control(ControlError::ReplayOrReorder));
        }
        self.attempted = true;
        let received = match self
            .dispatcher
            .transport
            .receive_capability_record(&self.frame, self.deadline)
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
