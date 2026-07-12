use super::{
    AcceptedSessionParameters, AuthenticatedZeroRightsTransport, CoordinatorCapabilityTransport,
    OwnedChildLifecycle, PeerState, ReceiverCapabilityTransport, SessionTransportError,
};
#[cfg(target_os = "linux")]
use crate::batch::ExpectedBatch;
#[cfg(test)]
use crate::batch::{PendingBatch, TransferBatch};
use crate::control::{ControlError, ControlFrame, ControlState, control_wire_len};
use crate::protocol::{CapabilityFrame, ManifestEntry, TransferManifest};
use crate::session::AbsoluteDeadline;

#[cfg(target_os = "linux")]
use super::linux_vnext::{
    memory::{
        LinuxCoordinatorWriterBatch, LinuxExpectedCoordinatorWriterBatch,
        LinuxImportedCoordinatorWriterBatch, MemfdError,
    },
    spawn::{CoordinatorLinuxControlTransport, ReceiverLinuxControlTransport},
};

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

/// Coordinator transaction that inseparably retains every portable prepared
/// region whose metadata formed the native capability frame.
#[cfg(test)]
pub(crate) struct CoordinatorPreparedBatchTransaction<'a, T: CoordinatorCapabilityTransport> {
    transaction: CoordinatorCapabilityTransaction<'a, T>,
    _batch: PendingBatch,
}

#[cfg(target_os = "linux")]
pub(crate) struct LinuxCoordinatorWriterTransaction<'a> {
    transaction: CoordinatorCapabilityTransaction<'a, CoordinatorLinuxControlTransport>,
    _batch: LinuxCoordinatorWriterBatch,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LinuxCapabilityBatchError {
    Memory(MemfdError),
    Control(AcceptedControlError),
}

/// Receiver-owned open native transaction and its immediately owned imports.
///
/// Installed capabilities cannot leave this guard in G1b. A later complete
/// import state machine may consume them without exposing the accepted native
/// endpoint or independent pending tokens.
#[cfg(test)]
pub(crate) struct ReceiverCapabilityTransaction<'a, T: ReceiverCapabilityTransport> {
    dispatcher: &'a mut AcceptedControlDispatcher<T>,
    frame: CapabilityFrame,
    deadline: AbsoluteDeadline,
    received: Option<T::ReceivedCapabilities>,
    attempted: bool,
    already_poisoned: bool,
}

#[cfg(target_os = "linux")]
pub(crate) struct LinuxReceiverCoordinatorWriterTransaction<'a> {
    dispatcher: &'a mut AcceptedControlDispatcher<ReceiverLinuxControlTransport>,
    expected: Option<LinuxExpectedCoordinatorWriterBatch>,
    imported: Option<LinuxImportedCoordinatorWriterBatch>,
    deadline: AbsoluteDeadline,
    transaction_id: u64,
    attempted: bool,
    already_poisoned: bool,
    #[cfg(test)]
    import_drop_observer: Option<std::sync::Arc<std::sync::Mutex<Vec<&'static str>>>>,
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

    pub(crate) const fn authority_profile(&self) -> crate::protocol::NativeAuthorityProfile {
        self.parameters.authority_profile()
    }

    fn poison_both(&mut self) {
        self.state.poison();
        self.transport.poison();
    }
}

impl<T: CoordinatorCapabilityTransport> AcceptedControlDispatcher<T> {
    #[cfg(test)]
    pub(crate) fn begin_prepared_batch(
        &mut self,
        batch: TransferBatch,
        deadline: AbsoluteDeadline,
    ) -> Result<CoordinatorPreparedBatchTransaction<'_, T>, AcceptedControlError> {
        let pending = batch
            .into_pending()
            .map_err(|_| AcceptedControlError::Control(ControlError::NonCanonical))?;
        let entries = pending
            .manifest_entries()
            .ok_or(AcceptedControlError::Control(ControlError::NonCanonical))?;
        let frame = self.begin_native_transaction(entries, deadline)?;
        Ok(CoordinatorPreparedBatchTransaction {
            transaction: CoordinatorCapabilityTransaction {
                dispatcher: self,
                frame,
                deadline,
                attempted: false,
                already_poisoned: false,
            },
            _batch: pending,
        })
    }

    #[cfg(test)]
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

#[cfg(test)]
impl<T: CoordinatorCapabilityTransport> CoordinatorPreparedBatchTransaction<'_, T> {
    pub(crate) fn send(
        &mut self,
        capabilities: T::Capabilities<'_>,
    ) -> Result<(), AcceptedControlError> {
        self.transaction.send(capabilities)
    }

    #[cfg(test)]
    pub(crate) fn complete_for_test(self) {
        self.transaction.complete_for_test();
    }
}

#[cfg(target_os = "linux")]
impl AcceptedControlDispatcher<CoordinatorLinuxControlTransport> {
    #[cfg(test)]
    pub(crate) fn observe_linux_poison_for_test(
        &mut self,
        observer: std::sync::Arc<std::sync::Mutex<Vec<&'static str>>>,
    ) {
        self.transport.observe_poison_for_test(observer);
    }

    pub(crate) fn begin_linux_coordinator_writer_batch(
        &mut self,
        batch: LinuxCoordinatorWriterBatch,
        deadline: AbsoluteDeadline,
    ) -> Result<LinuxCoordinatorWriterTransaction<'_>, LinuxCapabilityBatchError> {
        if self.parameters.authority_profile()
            != crate::protocol::NativeAuthorityProfile::LinuxMdweV1
        {
            return Err(LinuxCapabilityBatchError::Memory(
                MemfdError::WrongProvenance,
            ));
        }
        if batch.deadline() != deadline {
            return Err(LinuxCapabilityBatchError::Memory(
                MemfdError::DeadlineMismatch,
            ));
        }
        let frame = self
            .begin_native_transaction(batch.manifest_entries(), deadline)
            .map_err(LinuxCapabilityBatchError::Control)?;
        Ok(LinuxCoordinatorWriterTransaction {
            transaction: CoordinatorCapabilityTransaction {
                dispatcher: self,
                frame,
                deadline,
                attempted: false,
                already_poisoned: false,
            },
            _batch: batch,
        })
    }
}

#[cfg(target_os = "linux")]
impl AcceptedControlDispatcher<ReceiverLinuxControlTransport> {
    #[cfg(test)]
    pub(crate) fn observe_linux_receiver_poison_for_test(
        &mut self,
        observer: std::sync::Arc<std::sync::Mutex<Vec<&'static str>>>,
    ) {
        self.transport.observe_poison_for_test(observer);
    }

    pub(crate) fn begin_linux_expected_coordinator_writer_batch(
        &mut self,
        expected: ExpectedBatch,
        deadline: AbsoluteDeadline,
    ) -> Result<LinuxReceiverCoordinatorWriterTransaction<'_>, LinuxCapabilityBatchError> {
        if self.parameters.authority_profile()
            != crate::protocol::NativeAuthorityProfile::LinuxMdweV1
        {
            return Err(LinuxCapabilityBatchError::Memory(
                MemfdError::WrongProvenance,
            ));
        }
        let expected = LinuxExpectedCoordinatorWriterBatch::prepare(
            expected,
            self.parameters.limits(),
            deadline,
        )
        .map_err(LinuxCapabilityBatchError::Memory)?;
        let transaction_id = self
            .enter_native_transaction(deadline)
            .map_err(LinuxCapabilityBatchError::Control)?;
        Ok(LinuxReceiverCoordinatorWriterTransaction {
            dispatcher: self,
            expected: Some(expected),
            imported: None,
            deadline,
            transaction_id,
            attempted: false,
            already_poisoned: false,
            #[cfg(test)]
            import_drop_observer: None,
        })
    }
}

#[cfg(target_os = "linux")]
impl LinuxCoordinatorWriterTransaction<'_> {
    pub(crate) fn send(&mut self) -> Result<(), LinuxCapabilityBatchError> {
        if let Err(error) = self._batch.revalidate() {
            self.transaction.poison();
            return Err(LinuxCapabilityBatchError::Memory(error));
        }
        let capabilities = self._batch.capabilities();
        self.transaction
            .send(&capabilities)
            .map_err(LinuxCapabilityBatchError::Control)
    }

    #[cfg(test)]
    pub(crate) fn send_without_revalidation_for_test(
        &mut self,
    ) -> Result<(), LinuxCapabilityBatchError> {
        let capabilities = self._batch.capabilities();
        self.transaction
            .send(&capabilities)
            .map_err(LinuxCapabilityBatchError::Control)
    }
}

#[cfg(target_os = "linux")]
impl LinuxReceiverCoordinatorWriterTransaction<'_> {
    pub(crate) fn receive(&mut self) -> Result<(), LinuxCapabilityBatchError> {
        if self.attempted {
            self.poison();
            return Err(LinuxCapabilityBatchError::Control(
                AcceptedControlError::Control(ControlError::ReplayOrReorder),
            ));
        }
        self.attempted = true;
        let expected = self
            .expected
            .as_ref()
            .expect("receiver expectation remains transaction-owned");
        debug_assert_eq!(expected.deadline(), self.deadline);
        let record = match self
            .dispatcher
            .transport
            .receive_candidate_capability_record(expected.len(), self.deadline)
        {
            Ok(record) => record,
            Err(error) => {
                self.poison();
                return Err(LinuxCapabilityBatchError::Control(
                    AcceptedControlError::Transport(error),
                ));
            }
        };
        let Some((_, manifest)) = CapabilityFrame::decode(&record.frame) else {
            self.poison();
            return Err(LinuxCapabilityBatchError::Control(
                AcceptedControlError::Control(ControlError::NonCanonical),
            ));
        };
        if !linux_received_manifest_matches(
            self.dispatcher.parameters,
            self.transaction_id,
            expected,
            &manifest,
        ) {
            self.poison();
            return Err(LinuxCapabilityBatchError::Control(
                AcceptedControlError::Control(ControlError::NonCanonical),
            ));
        }
        let expected = self
            .expected
            .take()
            .expect("validated expectation is consumed once");
        let imported = match expected.import(&manifest, record.descriptors) {
            Ok(imported) => imported,
            Err(failure) => {
                #[cfg(test)]
                let mut failure = failure;
                let error = failure.error();
                #[cfg(test)]
                if let Some(observer) = &self.import_drop_observer {
                    failure.observe_drop_for_test(observer.clone());
                }
                self.poison();
                drop(failure);
                return Err(LinuxCapabilityBatchError::Memory(error));
            }
        };
        #[cfg(test)]
        let imported = {
            let mut imported = imported;
            if let Some(observer) = &self.import_drop_observer {
                imported.observe_drop_for_test(observer.clone());
            }
            imported
        };
        self.imported = Some(imported);
        Ok(())
    }

    fn poison(&mut self) {
        if !self.already_poisoned {
            self.dispatcher.poison_both();
            self.already_poisoned = true;
        }
    }

    #[cfg(test)]
    pub(crate) fn imported_for_test(&self) -> &LinuxImportedCoordinatorWriterBatch {
        self.imported
            .as_ref()
            .expect("test observation follows successful import")
    }

    #[cfg(test)]
    pub(crate) fn observe_import_drop_for_test(
        &mut self,
        observer: std::sync::Arc<std::sync::Mutex<Vec<&'static str>>>,
    ) {
        self.import_drop_observer = Some(observer);
    }

    #[cfg(test)]
    pub(crate) fn fail_import_advice_at_for_test(&mut self, operation: usize) {
        self.expected
            .as_mut()
            .expect("test fault precedes the only receive attempt")
            .fail_advice_at_for_test(operation);
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_received_manifest_matches(
    parameters: AcceptedSessionParameters,
    transaction_id: u64,
    expected: &LinuxExpectedCoordinatorWriterBatch,
    manifest: &TransferManifest,
) -> bool {
    let facts = parameters.facts();
    manifest.nonce == facts.nonce()
        && manifest.parent_pid == facts.parent_pid()
        && manifest.child_pid == facts.child_pid()
        && manifest.transfer_id == transaction_id
        && manifest.authority_profile() == parameters.authority_profile()
        && manifest.fits_limits(parameters.limits())
        && expected.matches_manifest(manifest)
}

#[cfg(target_os = "linux")]
impl Drop for LinuxReceiverCoordinatorWriterTransaction<'_> {
    fn drop(&mut self) {
        self.poison();
    }
}

impl<T: ReceiverCapabilityTransport> AcceptedControlDispatcher<T> {
    /// Awaits a coordinator-initiated native transaction without sending any
    /// receiver-originated start record.
    #[cfg(test)]
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
        let transaction_id = self.enter_native_transaction(deadline)?;
        debug_assert_eq!(transaction_id, manifest.transfer_id);
        Ok(CapabilityFrame::from_manifest(&manifest))
    }

    fn enter_native_transaction(
        &mut self,
        deadline: AbsoluteDeadline,
    ) -> Result<u64, AcceptedControlError> {
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
        match self.state.begin_transaction() {
            Ok(()) => {}
            Err(error) => {
                if self.state.is_poisoned() {
                    self.transport.poison();
                }
                return Err(AcceptedControlError::Control(error));
            }
        }
        let transaction_id = self.next_transaction;
        self.next_transaction = self
            .next_transaction
            .checked_add(1)
            .expect("negotiated transaction maximum cannot approach u64 overflow");
        Ok(transaction_id)
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

#[cfg(test)]
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

#[cfg(test)]
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
