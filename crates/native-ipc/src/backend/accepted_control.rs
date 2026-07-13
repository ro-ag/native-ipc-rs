use super::{
    AcceptedSessionParameters, AuthenticatedZeroRightsTransport, CoordinatorCapabilityTransport,
    OwnedChildLifecycle, PeerState, ReceiverCapabilityTransport, SessionTransportError,
};
#[cfg(target_os = "linux")]
use crate::active::{ActivationError, ActiveReader, ActiveWriter};
#[cfg(target_os = "linux")]
use crate::batch::{
    ActiveRegionSet, BatchError, CommittedRegion, ExpectedBatch, LocalRegionAuthority,
};
#[cfg(test)]
use crate::batch::{PendingBatch, TransferBatch};
use crate::control::{ControlError, ControlFrame, ControlState, control_wire_len};
use crate::liveness::ResourceOwner;
use crate::protocol::{CapabilityFrame, ManifestEntry, PreparationFrame, TransferManifest};
#[cfg(target_os = "linux")]
use crate::protocol::{CompletionFrame, CompletionFrameKind, PreparationFrameKind};
use crate::session::AbsoluteDeadline;
#[cfg(all(target_os = "linux", test))]
use std::os::fd::AsRawFd;

#[cfg(all(target_os = "linux", test))]
const DUPLICATE_SEALED_BARRIER: &[u8; 8] = b"NIPCTST1";
#[cfg(all(target_os = "linux", test))]
const COMPLETION_REJECTED_BARRIER: &[u8; 8] = b"NIPCTST2";

#[cfg(all(target_os = "linux", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CompletionFault {
    None,
    InterleavedApplication,
    SubstitutedManifest,
    Truncated,
    Duplicate,
}

#[cfg(target_os = "linux")]
use super::linux_vnext::{
    memory::{
        LinuxActiveRegionOwner, LinuxActiveRegionSpec, LinuxCoordinatorWriterBatch,
        LinuxExpectedCoordinatorWriterBatch, LinuxExpectedMixedDirectionBatch,
        LinuxExpectedReceiverWriterBatch, LinuxImportedCoordinatorWriterBatch,
        LinuxImportedMixedDirectionBatch, LinuxImportedReceiverWriterBatch,
        LinuxMixedDirectionBatch, LinuxReceiverWriterBatch, MemfdError,
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
    resources: ResourceOwner,
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
pub(crate) struct LinuxCoordinatorReceiverWriterTransaction<'a> {
    transaction: CoordinatorCapabilityTransaction<'a, CoordinatorLinuxControlTransport>,
    batch: LinuxReceiverWriterBatch,
    attempted: bool,
    #[cfg(test)]
    sealed_frame_fault: bool,
    #[cfg(test)]
    skip_sealing: bool,
    #[cfg(test)]
    duplicate_sealed: bool,
}

#[cfg(target_os = "linux")]
pub(crate) struct LinuxCoordinatorMixedDirectionTransaction<'a> {
    transaction: CoordinatorCapabilityTransaction<'a, CoordinatorLinuxControlTransport>,
    batch: LinuxMixedDirectionBatch,
    attempted: bool,
    #[cfg(test)]
    skip_sealing: bool,
    #[cfg(test)]
    commit_fault: CompletionFault,
}

/// Full-manifest COMMIT has completed, but no runtime mapping authority has
/// been activated or charged to the accepted session yet.
#[cfg(target_os = "linux")]
pub(crate) struct LinuxCoordinatorCommittedMixedDirectionBatch {
    batch: LinuxMixedDirectionBatch,
    parameters: AcceptedSessionParameters,
    deadline: AbsoluteDeadline,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LinuxCapabilityBatchError {
    Memory(MemfdError),
    Control(AcceptedControlError),
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LinuxActivationError {
    WrongSession,
    Memory(MemfdError),
    Active(ActivationError),
    Batch(BatchError),
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

#[cfg(target_os = "linux")]
pub(crate) struct LinuxReceiverWriterTransaction<'a> {
    dispatcher: &'a mut AcceptedControlDispatcher<ReceiverLinuxControlTransport>,
    expected: Option<LinuxExpectedReceiverWriterBatch>,
    imported: Option<LinuxImportedReceiverWriterBatch>,
    deadline: AbsoluteDeadline,
    transaction_id: u64,
    attempted: bool,
    already_poisoned: bool,
    #[cfg(test)]
    import_drop_observer: Option<std::sync::Arc<std::sync::Mutex<Vec<&'static str>>>>,
    #[cfg(test)]
    imported_application_fault: bool,
    #[cfg(test)]
    suppress_imported: bool,
    #[cfg(test)]
    imported_rights_fault: Option<usize>,
    #[cfg(test)]
    truncate_imported: bool,
    #[cfg(test)]
    imported_wrong_credentials: bool,
    #[cfg(test)]
    stale_imported: bool,
    #[cfg(test)]
    duplicate_imported: bool,
    #[cfg(test)]
    continuous_wrong_imported: bool,
    #[cfg(test)]
    expect_duplicate_sealed: bool,
}

#[cfg(target_os = "linux")]
pub(crate) struct LinuxReceiverMixedDirectionTransaction<'a> {
    dispatcher: &'a mut AcceptedControlDispatcher<ReceiverLinuxControlTransport>,
    expected: Option<LinuxExpectedMixedDirectionBatch>,
    imported: Option<LinuxImportedMixedDirectionBatch>,
    frame: Option<CapabilityFrame>,
    deadline: AbsoluteDeadline,
    transaction_id: u64,
    attempted: bool,
    already_poisoned: bool,
    #[cfg(test)]
    import_drop_observer: Option<std::sync::Arc<std::sync::Mutex<Vec<&'static str>>>>,
    #[cfg(test)]
    imported_rights_fault: Option<usize>,
    #[cfg(test)]
    imported_wrong_credentials: bool,
    #[cfg(test)]
    stale_imported: bool,
    #[cfg(test)]
    ready_fault: CompletionFault,
    #[cfg(test)]
    acknowledge_commit_rejection: bool,
}

/// Exact COMMIT has been received, but the imported mappings remain opaque
/// pending ownership until session-charged activation succeeds atomically.
#[cfg(target_os = "linux")]
pub(crate) struct LinuxReceiverCommittedMixedDirectionBatch {
    batch: LinuxImportedMixedDirectionBatch,
    parameters: AcceptedSessionParameters,
    deadline: AbsoluteDeadline,
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
        let Ok(resources) = ResourceOwner::new(limits) else {
            return Err(transport);
        };
        Ok(Self {
            transport,
            state,
            maximum_wire_len,
            parameters,
            next_transaction: 1,
            resources,
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

    #[cfg(test)]
    pub(crate) fn active_lease_facts_for_test(&self) -> crate::liveness::ActiveLeaseFacts {
        self.resources.active_lease_facts()
    }

    fn poison_both(&mut self) {
        self.state.poison();
        self.transport.poison();
        self.resources.poison();
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

    #[cfg(test)]
    pub(crate) fn wait_for_linux_peer_success_for_test(
        &mut self,
        deadline: AbsoluteDeadline,
    ) -> Result<(), SessionTransportError> {
        self.state.poison();
        self.transport.wait_and_reap_clean_for_test(deadline)
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

    pub(crate) fn begin_linux_receiver_writer_batch(
        &mut self,
        batch: LinuxReceiverWriterBatch,
        deadline: AbsoluteDeadline,
    ) -> Result<LinuxCoordinatorReceiverWriterTransaction<'_>, LinuxCapabilityBatchError> {
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
        Ok(LinuxCoordinatorReceiverWriterTransaction {
            transaction: CoordinatorCapabilityTransaction {
                dispatcher: self,
                frame,
                deadline,
                attempted: false,
                already_poisoned: false,
            },
            batch,
            attempted: false,
            #[cfg(test)]
            sealed_frame_fault: false,
            #[cfg(test)]
            skip_sealing: false,
            #[cfg(test)]
            duplicate_sealed: false,
        })
    }

    pub(crate) fn begin_linux_mixed_direction_batch(
        &mut self,
        batch: LinuxMixedDirectionBatch,
        deadline: AbsoluteDeadline,
    ) -> Result<LinuxCoordinatorMixedDirectionTransaction<'_>, LinuxCapabilityBatchError> {
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
        Ok(LinuxCoordinatorMixedDirectionTransaction {
            transaction: CoordinatorCapabilityTransaction {
                dispatcher: self,
                frame,
                deadline,
                attempted: false,
                already_poisoned: false,
            },
            batch,
            attempted: false,
            #[cfg(test)]
            skip_sealing: false,
            #[cfg(test)]
            commit_fault: CompletionFault::None,
        })
    }

    pub(crate) fn activate_linux_coordinator_mixed_direction_batch(
        &mut self,
        committed: LinuxCoordinatorCommittedMixedDirectionBatch,
    ) -> Result<ActiveRegionSet, LinuxActivationError> {
        let LinuxCoordinatorCommittedMixedDirectionBatch {
            batch,
            parameters,
            deadline,
        } = committed;
        let result = (|| {
            if parameters != self.parameters || batch.deadline() != deadline {
                return Err(LinuxActivationError::WrongSession);
            }
            let specs = batch
                .activation_specs()
                .map_err(LinuxActivationError::Memory)?;
            activate_linux_regions(&mut self.resources, specs, || {
                batch.into_active_region_owners()
            })
        })();
        if result.is_err() {
            self.poison_both();
        }
        result
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

    pub(crate) fn activate_linux_receiver_mixed_direction_batch(
        &mut self,
        committed: LinuxReceiverCommittedMixedDirectionBatch,
    ) -> Result<ActiveRegionSet, LinuxActivationError> {
        let LinuxReceiverCommittedMixedDirectionBatch {
            batch,
            parameters,
            deadline,
        } = committed;
        let result = (|| {
            if parameters != self.parameters {
                return Err(LinuxActivationError::WrongSession);
            }
            let specs = batch
                .activation_specs(deadline)
                .map_err(LinuxActivationError::Memory)?;
            activate_linux_regions(&mut self.resources, specs, || {
                batch.into_active_region_owners()
            })
        })();
        if result.is_err() {
            self.poison_both();
        }
        result
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

    pub(crate) fn begin_linux_expected_receiver_writer_batch(
        &mut self,
        expected: ExpectedBatch,
        deadline: AbsoluteDeadline,
    ) -> Result<LinuxReceiverWriterTransaction<'_>, LinuxCapabilityBatchError> {
        if self.parameters.authority_profile()
            != crate::protocol::NativeAuthorityProfile::LinuxMdweV1
        {
            return Err(LinuxCapabilityBatchError::Memory(
                MemfdError::WrongProvenance,
            ));
        }
        let expected =
            LinuxExpectedReceiverWriterBatch::prepare(expected, self.parameters.limits(), deadline)
                .map_err(LinuxCapabilityBatchError::Memory)?;
        let transaction_id = self
            .enter_native_transaction(deadline)
            .map_err(LinuxCapabilityBatchError::Control)?;
        Ok(LinuxReceiverWriterTransaction {
            dispatcher: self,
            expected: Some(expected),
            imported: None,
            deadline,
            transaction_id,
            attempted: false,
            already_poisoned: false,
            #[cfg(test)]
            import_drop_observer: None,
            #[cfg(test)]
            imported_application_fault: false,
            #[cfg(test)]
            suppress_imported: false,
            #[cfg(test)]
            imported_rights_fault: None,
            #[cfg(test)]
            truncate_imported: false,
            #[cfg(test)]
            imported_wrong_credentials: false,
            #[cfg(test)]
            stale_imported: false,
            #[cfg(test)]
            duplicate_imported: false,
            #[cfg(test)]
            continuous_wrong_imported: false,
            #[cfg(test)]
            expect_duplicate_sealed: false,
        })
    }

    pub(crate) fn begin_linux_expected_mixed_direction_batch(
        &mut self,
        expected: ExpectedBatch,
        deadline: AbsoluteDeadline,
    ) -> Result<LinuxReceiverMixedDirectionTransaction<'_>, LinuxCapabilityBatchError> {
        if self.parameters.authority_profile()
            != crate::protocol::NativeAuthorityProfile::LinuxMdweV1
        {
            return Err(LinuxCapabilityBatchError::Memory(
                MemfdError::WrongProvenance,
            ));
        }
        let expected =
            LinuxExpectedMixedDirectionBatch::prepare(expected, self.parameters.limits(), deadline)
                .map_err(LinuxCapabilityBatchError::Memory)?;
        let transaction_id = self
            .enter_native_transaction(deadline)
            .map_err(LinuxCapabilityBatchError::Control)?;
        Ok(LinuxReceiverMixedDirectionTransaction {
            dispatcher: self,
            expected: Some(expected),
            imported: None,
            frame: None,
            deadline,
            transaction_id,
            attempted: false,
            already_poisoned: false,
            #[cfg(test)]
            import_drop_observer: None,
            #[cfg(test)]
            imported_rights_fault: None,
            #[cfg(test)]
            imported_wrong_credentials: false,
            #[cfg(test)]
            stale_imported: false,
            #[cfg(test)]
            ready_fault: CompletionFault::None,
            #[cfg(test)]
            acknowledge_commit_rejection: false,
        })
    }
}

#[cfg(target_os = "linux")]
fn activate_linux_regions(
    resources: &mut ResourceOwner,
    specs: Vec<LinuxActiveRegionSpec>,
    owners: impl FnOnce() -> Result<Vec<LinuxActiveRegionOwner>, MemfdError>,
) -> Result<ActiveRegionSet, LinuxActivationError> {
    let expected = specs
        .iter()
        .map(|spec| (spec.id, spec.authority))
        .collect::<Vec<(crate::region::RegionId, LocalRegionAuthority)>>();
    let mut reservations = Vec::with_capacity(specs.len());
    for spec in &specs {
        reservations.push(
            resources
                .reserve(spec.mapped_len)
                .map_err(ActivationError::Resource)
                .map_err(LinuxActivationError::Active)?,
        );
    }
    let owners = owners().map_err(LinuxActivationError::Memory)?;
    if owners.len() != specs.len() {
        return Err(LinuxActivationError::Memory(MemfdError::WrongProvenance));
    }
    let mut active = Vec::with_capacity(specs.len());
    for ((expected_spec, owner), reservation) in specs.into_iter().zip(owners).zip(reservations) {
        if owner.spec() != expected_spec {
            return Err(LinuxActivationError::Memory(MemfdError::WrongProvenance));
        }
        let region = match (expected_spec.authority, owner) {
            (LocalRegionAuthority::Reader, LinuxActiveRegionOwner::Reader { owner, .. }) => {
                CommittedRegion::Reader(
                    ActiveReader::new_leased(owner, expected_spec.logical_len, reservation)
                        .map_err(LinuxActivationError::Active)?,
                )
            }
            (LocalRegionAuthority::Writer, LinuxActiveRegionOwner::Writer { owner, .. }) => {
                CommittedRegion::Writer(
                    ActiveWriter::new_leased(owner, expected_spec.logical_len, reservation)
                        .map_err(LinuxActivationError::Active)?,
                )
            }
            _ => return Err(LinuxActivationError::Memory(MemfdError::WrongProvenance)),
        };
        active.push((expected_spec.id, region));
    }
    ActiveRegionSet::from_local_committed(expected, active).map_err(LinuxActivationError::Batch)
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
impl LinuxCoordinatorReceiverWriterTransaction<'_> {
    pub(crate) fn prepare(&mut self) -> Result<(), LinuxCapabilityBatchError> {
        if self.attempted {
            self.transaction.poison();
            return Err(LinuxCapabilityBatchError::Control(
                AcceptedControlError::Control(ControlError::ReplayOrReorder),
            ));
        }
        self.attempted = true;
        if let Err(error) = self.batch.revalidate_prefix() {
            self.transaction.poison();
            return Err(LinuxCapabilityBatchError::Memory(error));
        }
        let capabilities = self.batch.capabilities();
        self.transaction
            .send(&capabilities)
            .map_err(LinuxCapabilityBatchError::Control)?;
        let imported = self
            .transaction
            .frame
            .preparation_frame(PreparationFrameKind::Imported);
        self.transaction
            .receive_preparation(&imported)
            .map_err(LinuxCapabilityBatchError::Control)?;
        #[cfg(test)]
        let should_seal = !self.skip_sealing;
        #[cfg(not(test))]
        let should_seal = true;
        if should_seal && let Err(error) = self.batch.seal_after_import() {
            self.transaction.poison();
            return Err(LinuxCapabilityBatchError::Memory(error));
        }
        let sealed = self
            .transaction
            .frame
            .preparation_frame(PreparationFrameKind::Sealed);
        #[cfg(test)]
        if self.sealed_frame_fault {
            let mut substituted = *sealed.as_bytes();
            substituted[16] ^= 1;
            return self
                .transaction
                .send_preparation_bytes(&substituted)
                .map_err(LinuxCapabilityBatchError::Control);
        }
        self.transaction
            .send_preparation(&sealed)
            .map_err(LinuxCapabilityBatchError::Control)?;
        #[cfg(test)]
        if self.duplicate_sealed {
            self.transaction
                .send_preparation(&sealed)
                .map_err(LinuxCapabilityBatchError::Control)?;
            self.transaction
                .send_preparation_bytes(DUPLICATE_SEALED_BARRIER)
                .map_err(LinuxCapabilityBatchError::Control)?;
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn batch_for_test(&self) -> &LinuxReceiverWriterBatch {
        &self.batch
    }

    #[cfg(test)]
    pub(crate) fn fail_seal_at_for_test(&mut self, ordinal: usize) {
        self.batch.fail_seal_at_for_test(ordinal);
    }

    #[cfg(test)]
    pub(crate) fn fail_coordinator_advice_at_for_test(&mut self, operation: usize) {
        self.batch.fail_advice_at_for_test(operation);
    }

    #[cfg(test)]
    pub(crate) fn all_final_sealed_for_test(&self) -> bool {
        self.batch.all_final_sealed_for_test()
    }

    #[cfg(test)]
    pub(crate) fn seal_counts_for_test(&self) -> (usize, usize) {
        self.batch.seal_counts_for_test()
    }

    #[cfg(test)]
    pub(crate) fn substitute_sealed_for_test(&mut self) {
        self.sealed_frame_fault = true;
    }

    #[cfg(test)]
    pub(crate) fn skip_final_sealing_for_test(&mut self) {
        self.skip_sealing = true;
    }

    #[cfg(test)]
    pub(crate) fn duplicate_sealed_for_test(&mut self) {
        self.duplicate_sealed = true;
    }

    #[cfg(test)]
    pub(crate) fn replace_capability_with_invalid_file_for_test(&mut self, ordinal: usize) {
        self.batch
            .replace_capability_with_invalid_file_for_test(ordinal);
    }
}

#[cfg(target_os = "linux")]
impl LinuxCoordinatorMixedDirectionTransaction<'_> {
    pub(crate) fn prepare(&mut self) -> Result<(), LinuxCapabilityBatchError> {
        if self.attempted {
            self.transaction.poison();
            return Err(LinuxCapabilityBatchError::Control(
                AcceptedControlError::Control(ControlError::ReplayOrReorder),
            ));
        }
        self.attempted = true;
        if let Err(error) = self.batch.revalidate_before_send() {
            self.transaction.poison();
            return Err(LinuxCapabilityBatchError::Memory(error));
        }
        let requires_imported_sealed = self.batch.requires_imported_sealed();
        let capabilities = self.batch.capabilities();
        self.transaction
            .send(&capabilities)
            .map_err(LinuxCapabilityBatchError::Control)?;
        if requires_imported_sealed {
            let imported = self
                .transaction
                .frame
                .preparation_frame(PreparationFrameKind::Imported);
            self.transaction
                .receive_preparation(&imported)
                .map_err(LinuxCapabilityBatchError::Control)?;
            #[cfg(test)]
            let should_seal = !self.skip_sealing;
            #[cfg(not(test))]
            let should_seal = true;
            if should_seal && let Err(error) = self.batch.seal_after_import() {
                self.transaction.poison();
                return Err(LinuxCapabilityBatchError::Memory(error));
            }
            let sealed = self
                .transaction
                .frame
                .preparation_frame(PreparationFrameKind::Sealed);
            self.transaction
                .send_preparation(&sealed)
                .map_err(LinuxCapabilityBatchError::Control)?;
        }
        Ok(())
    }

    /// Completes the single full-manifest READY/COMMIT barrier and returns an
    /// opaque committed owner. Runtime access remains unavailable until a
    /// later activation step charges every mapping to the session ledger.
    pub(crate) fn commit(
        mut self,
    ) -> Result<LinuxCoordinatorCommittedMixedDirectionBatch, LinuxCapabilityBatchError> {
        if !self.attempted {
            self.transaction.poison();
            return Err(LinuxCapabilityBatchError::Control(
                AcceptedControlError::Control(ControlError::ReplayOrReorder),
            ));
        }
        let ready = self
            .transaction
            .frame
            .completion_frame(CompletionFrameKind::Ready);
        self.transaction
            .receive_completion(&ready)
            .map_err(LinuxCapabilityBatchError::Control)?;
        let commit = self
            .transaction
            .frame
            .completion_frame(CompletionFrameKind::Commit);
        #[cfg(test)]
        if self.commit_fault == CompletionFault::Duplicate {
            self.transaction
                .send_completion(&commit)
                .and_then(|()| self.transaction.send_completion(&commit))
                .map_err(LinuxCapabilityBatchError::Control)?;
            self.transaction
                .finish()
                .map_err(LinuxCapabilityBatchError::Control)?;
            return Ok(LinuxCoordinatorCommittedMixedDirectionBatch {
                batch: self.batch,
                parameters: self.transaction.dispatcher.parameters,
                deadline: self.transaction.deadline,
            });
        }
        #[cfg(test)]
        if self.commit_fault != CompletionFault::None {
            let mut bytes = *commit.as_bytes();
            let error = match self.commit_fault {
                CompletionFault::None | CompletionFault::Duplicate => unreachable!(),
                CompletionFault::InterleavedApplication => {
                    bytes[..8].copy_from_slice(b"NIPCAPP1");
                    self.transaction.send_preparation_bytes(&bytes)
                }
                CompletionFault::SubstitutedManifest => {
                    bytes[56] ^= 1;
                    self.transaction.send_preparation_bytes(&bytes)
                }
                CompletionFault::Truncated => self
                    .transaction
                    .send_preparation_bytes(&bytes[..bytes.len() - 1]),
            };
            error.map_err(LinuxCapabilityBatchError::Control)?;
            let rejection = match self
                .transaction
                .dispatcher
                .transport
                .receive_record(COMPLETION_REJECTED_BARRIER.len(), self.transaction.deadline)
            {
                Ok(rejection) => rejection,
                Err(error) => {
                    self.transaction.poison();
                    return Err(LinuxCapabilityBatchError::Control(
                        AcceptedControlError::Transport(error),
                    ));
                }
            };
            if rejection != COMPLETION_REJECTED_BARRIER {
                self.transaction.poison();
                return Err(LinuxCapabilityBatchError::Control(
                    AcceptedControlError::Control(ControlError::NonCanonical),
                ));
            }
            self.transaction.poison();
            return Err(LinuxCapabilityBatchError::Control(
                AcceptedControlError::Control(ControlError::NonCanonical),
            ));
        }
        self.transaction
            .send_completion(&commit)
            .map_err(LinuxCapabilityBatchError::Control)?;
        self.transaction
            .finish()
            .map_err(LinuxCapabilityBatchError::Control)?;
        Ok(LinuxCoordinatorCommittedMixedDirectionBatch {
            batch: self.batch,
            parameters: self.transaction.dispatcher.parameters,
            deadline: self.transaction.deadline,
        })
    }

    #[cfg(test)]
    pub(crate) fn batch_for_test(&self) -> &LinuxMixedDirectionBatch {
        &self.batch
    }

    #[cfg(test)]
    pub(crate) fn fail_seal_at_for_test(&mut self, ordinal: usize) {
        self.batch.fail_seal_at_for_test(ordinal);
    }

    #[cfg(test)]
    pub(crate) fn fail_coordinator_advice_at_for_test(&mut self, operation: usize) {
        self.batch.fail_advice_at_for_test(operation);
    }

    #[cfg(test)]
    pub(crate) fn all_final_sealed_for_test(&self) -> bool {
        self.batch.all_final_sealed_for_test()
    }

    #[cfg(test)]
    pub(crate) fn seal_counts_for_test(&self) -> (usize, usize) {
        self.batch.seal_counts_for_test()
    }

    #[cfg(test)]
    pub(crate) fn skip_final_sealing_for_test(&mut self) {
        self.skip_sealing = true;
    }

    #[cfg(test)]
    pub(crate) fn interleave_application_commit_for_test(&mut self) {
        self.commit_fault = CompletionFault::InterleavedApplication;
    }

    #[cfg(test)]
    pub(crate) fn substitute_commit_manifest_for_test(&mut self) {
        self.commit_fault = CompletionFault::SubstitutedManifest;
    }

    #[cfg(test)]
    pub(crate) fn truncate_commit_for_test(&mut self) {
        self.commit_fault = CompletionFault::Truncated;
    }

    #[cfg(test)]
    pub(crate) fn duplicate_commit_for_test(&mut self) {
        self.commit_fault = CompletionFault::Duplicate;
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
impl LinuxReceiverWriterTransaction<'_> {
    pub(crate) fn prepare(&mut self) -> Result<(), LinuxCapabilityBatchError> {
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
        let Some((frame, manifest)) = CapabilityFrame::decode(&record.frame) else {
            self.poison();
            return Err(LinuxCapabilityBatchError::Control(
                AcceptedControlError::Control(ControlError::NonCanonical),
            ));
        };
        if !linux_received_receiver_writer_manifest_matches(
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
        let mut imported = {
            let mut imported = imported;
            if let Some(observer) = &self.import_drop_observer {
                imported.observe_drop_for_test(observer.clone());
            }
            imported
        };
        #[cfg(not(test))]
        let mut imported = imported;
        let imported_frame = frame.preparation_frame(PreparationFrameKind::Imported);
        #[cfg(test)]
        let imported_bytes = if self.imported_application_fault {
            let mut substituted = *imported_frame.as_bytes();
            substituted[..8].copy_from_slice(b"NIPCAPP1");
            substituted
        } else if self.stale_imported {
            let mut substituted = *imported_frame.as_bytes();
            substituted[56] ^= 1;
            substituted
        } else {
            *imported_frame.as_bytes()
        };
        #[cfg(not(test))]
        let imported_bytes = *imported_frame.as_bytes();
        #[cfg(test)]
        let should_send_imported = !self.suppress_imported;
        #[cfg(test)]
        let imported_send = if !should_send_imported {
            Ok(())
        } else if self.continuous_wrong_imported {
            let mut wrong = imported_bytes;
            wrong[..8].copy_from_slice(b"NIPCAPP1");
            loop {
                if self.deadline.is_expired() {
                    break Err(SessionTransportError::DeadlineExpired);
                }
                if let Err(error) = self.dispatcher.transport.send_record(&wrong, self.deadline) {
                    break Err(error);
                }
            }
        } else if self.imported_wrong_credentials {
            self.dispatcher
                .transport
                .send_record_from_fork_for_test(&imported_bytes)
        } else if let Some(count) = self.imported_rights_fault {
            let descriptor = imported.descriptor_for_test(0).as_raw_fd();
            self.dispatcher.transport.send_record_with_rights_for_test(
                &imported_bytes,
                &vec![descriptor; count],
                self.deadline,
            )
        } else {
            let bytes = if self.truncate_imported {
                &imported_bytes[..imported_bytes.len() - 1]
            } else {
                &imported_bytes
            };
            self.dispatcher.transport.send_record(bytes, self.deadline)
        };
        #[cfg(not(test))]
        let imported_send = self
            .dispatcher
            .transport
            .send_record(&imported_bytes, self.deadline);
        if let Err(error) = imported_send {
            self.poison();
            return Err(LinuxCapabilityBatchError::Control(
                AcceptedControlError::Transport(error),
            ));
        }
        #[cfg(test)]
        if self.duplicate_imported
            && let Err(error) = self
                .dispatcher
                .transport
                .send_record(&imported_bytes, self.deadline)
        {
            self.poison();
            return Err(LinuxCapabilityBatchError::Control(
                AcceptedControlError::Transport(error),
            ));
        }
        let sealed_frame = frame.preparation_frame(PreparationFrameKind::Sealed);
        let sealed = match self
            .dispatcher
            .transport
            .receive_record(sealed_frame.as_bytes().len(), self.deadline)
        {
            Ok(sealed) => sealed,
            Err(error) => {
                self.poison();
                return Err(LinuxCapabilityBatchError::Control(
                    AcceptedControlError::Transport(error),
                ));
            }
        };
        if !sealed_frame.matches(&sealed) {
            self.poison();
            return Err(LinuxCapabilityBatchError::Control(
                AcceptedControlError::Control(ControlError::NonCanonical),
            ));
        }
        if let Err(error) = imported.verify_final_seals(self.deadline) {
            self.poison();
            return Err(LinuxCapabilityBatchError::Memory(error));
        }
        #[cfg(test)]
        if self.expect_duplicate_sealed {
            let replay = match self
                .dispatcher
                .transport
                .receive_record(sealed_frame.as_bytes().len(), self.deadline)
            {
                Ok(replay) => replay,
                Err(error) => {
                    self.poison();
                    return Err(LinuxCapabilityBatchError::Control(
                        AcceptedControlError::Transport(error),
                    ));
                }
            };
            if !sealed_frame.matches(&replay) {
                self.poison();
                return Err(LinuxCapabilityBatchError::Control(
                    AcceptedControlError::Control(ControlError::NonCanonical),
                ));
            }
            let barrier = match self
                .dispatcher
                .transport
                .receive_record(DUPLICATE_SEALED_BARRIER.len(), self.deadline)
            {
                Ok(barrier) => barrier,
                Err(error) => {
                    self.poison();
                    return Err(LinuxCapabilityBatchError::Control(
                        AcceptedControlError::Transport(error),
                    ));
                }
            };
            if barrier.as_slice() != DUPLICATE_SEALED_BARRIER {
                self.poison();
                return Err(LinuxCapabilityBatchError::Control(
                    AcceptedControlError::Control(ControlError::NonCanonical),
                ));
            }
            self.poison();
            return Err(LinuxCapabilityBatchError::Control(
                AcceptedControlError::Control(ControlError::ReplayOrReorder),
            ));
        }
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
    pub(crate) fn imported_for_test(&mut self) -> &mut LinuxImportedReceiverWriterBatch {
        self.imported
            .as_mut()
            .expect("test observation follows successful sealed preparation")
    }

    #[cfg(test)]
    pub(crate) fn observe_import_drop_for_test(
        &mut self,
        observer: std::sync::Arc<std::sync::Mutex<Vec<&'static str>>>,
    ) {
        self.import_drop_observer = Some(observer);
    }

    #[cfg(test)]
    pub(crate) fn substitute_imported_with_application_for_test(&mut self) {
        self.imported_application_fault = true;
    }

    #[cfg(test)]
    pub(crate) fn suppress_imported_for_test(&mut self) {
        self.suppress_imported = true;
    }

    #[cfg(test)]
    pub(crate) fn inject_imported_rights_for_test(&mut self, count: usize) {
        assert!((1..=16).contains(&count));
        self.imported_rights_fault = Some(count);
    }

    #[cfg(test)]
    pub(crate) fn truncate_imported_for_test(&mut self) {
        self.truncate_imported = true;
    }

    #[cfg(test)]
    pub(crate) fn use_wrong_imported_credentials_for_test(&mut self) {
        self.imported_wrong_credentials = true;
    }

    #[cfg(test)]
    pub(crate) fn fail_receiver_advice_at_for_test(&mut self, operation: usize) {
        self.expected
            .as_mut()
            .expect("test fault precedes the only preparation attempt")
            .fail_advice_at_for_test(operation);
    }

    #[cfg(test)]
    pub(crate) fn stale_imported_for_test(&mut self) {
        self.stale_imported = true;
    }

    #[cfg(test)]
    pub(crate) fn duplicate_imported_for_test(&mut self) {
        self.duplicate_imported = true;
    }

    #[cfg(test)]
    pub(crate) fn continuous_wrong_imported_for_test(&mut self) {
        self.continuous_wrong_imported = true;
    }

    #[cfg(test)]
    pub(crate) fn expect_duplicate_sealed_replay_for_test(&mut self) {
        self.expect_duplicate_sealed = true;
    }
}

#[cfg(target_os = "linux")]
impl LinuxReceiverMixedDirectionTransaction<'_> {
    pub(crate) fn prepare(&mut self) -> Result<(), LinuxCapabilityBatchError> {
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
            .expect("mixed receiver expectation remains transaction-owned");
        debug_assert_eq!(expected.deadline(), self.deadline);
        let requires_imported_sealed = expected.requires_imported_sealed();
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
        let Some((frame, manifest)) = CapabilityFrame::decode(&record.frame) else {
            self.poison();
            return Err(LinuxCapabilityBatchError::Control(
                AcceptedControlError::Control(ControlError::NonCanonical),
            ));
        };
        if !linux_received_mixed_manifest_matches(
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
            .expect("validated mixed expectation is consumed once");
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
        let mut imported = {
            let mut imported = imported;
            if let Some(observer) = &self.import_drop_observer {
                imported.observe_drop_for_test(observer.clone());
            }
            imported
        };
        #[cfg(not(test))]
        let mut imported = imported;
        if requires_imported_sealed {
            let imported_frame = frame.preparation_frame(PreparationFrameKind::Imported);
            #[cfg(test)]
            let imported_bytes = if self.stale_imported {
                let mut substituted = *imported_frame.as_bytes();
                substituted[56] ^= 1;
                substituted
            } else {
                *imported_frame.as_bytes()
            };
            #[cfg(not(test))]
            let imported_bytes = *imported_frame.as_bytes();
            #[cfg(test)]
            let imported_send = if self.imported_wrong_credentials {
                self.dispatcher
                    .transport
                    .send_record_from_fork_for_test(&imported_bytes)
            } else if let Some(count) = self.imported_rights_fault {
                let descriptor = imported.descriptor_for_test(0).as_raw_fd();
                self.dispatcher.transport.send_record_with_rights_for_test(
                    &imported_bytes,
                    &vec![descriptor; count],
                    self.deadline,
                )
            } else {
                self.dispatcher
                    .transport
                    .send_record(&imported_bytes, self.deadline)
            };
            #[cfg(not(test))]
            let imported_send = self
                .dispatcher
                .transport
                .send_record(&imported_bytes, self.deadline);
            if let Err(error) = imported_send {
                self.poison();
                return Err(LinuxCapabilityBatchError::Control(
                    AcceptedControlError::Transport(error),
                ));
            }
            let sealed_frame = frame.preparation_frame(PreparationFrameKind::Sealed);
            let sealed = match self
                .dispatcher
                .transport
                .receive_record(sealed_frame.as_bytes().len(), self.deadline)
            {
                Ok(sealed) => sealed,
                Err(error) => {
                    self.poison();
                    return Err(LinuxCapabilityBatchError::Control(
                        AcceptedControlError::Transport(error),
                    ));
                }
            };
            if !sealed_frame.matches(&sealed) {
                self.poison();
                return Err(LinuxCapabilityBatchError::Control(
                    AcceptedControlError::Control(ControlError::NonCanonical),
                ));
            }
        }
        if let Err(error) = imported.verify_final_seals(self.deadline) {
            self.poison();
            return Err(LinuxCapabilityBatchError::Memory(error));
        }
        self.imported = Some(imported);
        self.frame = Some(frame);
        Ok(())
    }

    /// Sends full-manifest READY, accepts only the exact matching COMMIT, and
    /// returns opaque committed pending ownership without runtime exposure.
    pub(crate) fn commit(
        mut self,
    ) -> Result<LinuxReceiverCommittedMixedDirectionBatch, LinuxCapabilityBatchError> {
        if !self.attempted || self.imported.is_none() || self.frame.is_none() {
            self.poison();
            return Err(LinuxCapabilityBatchError::Control(
                AcceptedControlError::Control(ControlError::ReplayOrReorder),
            ));
        }
        let frame = self
            .frame
            .as_ref()
            .expect("successful preparation retains the canonical frame");
        let ready = frame.completion_frame(CompletionFrameKind::Ready);
        let commit = frame.completion_frame(CompletionFrameKind::Commit);
        #[cfg(test)]
        if self.ready_fault == CompletionFault::Duplicate {
            self.dispatcher
                .transport
                .send_record(ready.as_bytes(), self.deadline)
                .and_then(|()| {
                    self.dispatcher
                        .transport
                        .send_record(ready.as_bytes(), self.deadline)
                })
                .map_err(|error| {
                    self.poison();
                    LinuxCapabilityBatchError::Control(AcceptedControlError::Transport(error))
                })?;
        }
        #[cfg(test)]
        if self.ready_fault != CompletionFault::None
            && self.ready_fault != CompletionFault::Duplicate
        {
            let mut bytes = *ready.as_bytes();
            let send = match self.ready_fault {
                CompletionFault::None | CompletionFault::Duplicate => unreachable!(),
                CompletionFault::InterleavedApplication => {
                    bytes[..8].copy_from_slice(b"NIPCAPP1");
                    self.dispatcher.transport.send_record(&bytes, self.deadline)
                }
                CompletionFault::SubstitutedManifest => {
                    bytes[56] ^= 1;
                    self.dispatcher.transport.send_record(&bytes, self.deadline)
                }
                CompletionFault::Truncated => self
                    .dispatcher
                    .transport
                    .send_record(&bytes[..bytes.len() - 1], self.deadline),
            };
            if let Err(error) = send {
                self.poison();
                return Err(LinuxCapabilityBatchError::Control(
                    AcceptedControlError::Transport(error),
                ));
            }
            self.poison();
            return Err(LinuxCapabilityBatchError::Control(
                AcceptedControlError::Control(ControlError::NonCanonical),
            ));
        }
        #[cfg(test)]
        let ready_already_sent = self.ready_fault == CompletionFault::Duplicate;
        #[cfg(not(test))]
        let ready_already_sent = false;
        if !ready_already_sent
            && let Err(error) = self
                .dispatcher
                .transport
                .send_record(ready.as_bytes(), self.deadline)
        {
            self.poison();
            return Err(LinuxCapabilityBatchError::Control(
                AcceptedControlError::Transport(error),
            ));
        }
        let committed = match self
            .dispatcher
            .transport
            .receive_record(commit.as_bytes().len(), self.deadline)
        {
            Ok(committed) => committed,
            Err(error) => {
                self.poison();
                return Err(LinuxCapabilityBatchError::Control(
                    AcceptedControlError::Transport(error),
                ));
            }
        };
        if !commit.matches(&committed) {
            #[cfg(test)]
            if self.acknowledge_commit_rejection
                && let Err(error) = self
                    .dispatcher
                    .transport
                    .send_record(COMPLETION_REJECTED_BARRIER, self.deadline)
            {
                self.poison();
                return Err(LinuxCapabilityBatchError::Control(
                    AcceptedControlError::Transport(error),
                ));
            }
            self.poison();
            return Err(LinuxCapabilityBatchError::Control(
                AcceptedControlError::Control(ControlError::NonCanonical),
            ));
        }
        if let Err(error) = self.dispatcher.state.end_transaction() {
            self.poison();
            return Err(LinuxCapabilityBatchError::Control(
                AcceptedControlError::Control(error),
            ));
        }
        self.already_poisoned = true;
        let batch = self
            .imported
            .take()
            .expect("exact COMMIT releases the retained imported batch once");
        Ok(LinuxReceiverCommittedMixedDirectionBatch {
            batch,
            parameters: self.dispatcher.parameters,
            deadline: self.deadline,
        })
    }

    fn poison(&mut self) {
        if !self.already_poisoned {
            self.dispatcher.poison_both();
            self.already_poisoned = true;
        }
    }

    #[cfg(test)]
    pub(crate) fn imported_for_test(&mut self) -> &mut LinuxImportedMixedDirectionBatch {
        self.imported
            .as_mut()
            .expect("test observation follows successful mixed preparation")
    }

    #[cfg(test)]
    pub(crate) fn observe_import_drop_for_test(
        &mut self,
        observer: std::sync::Arc<std::sync::Mutex<Vec<&'static str>>>,
    ) {
        self.import_drop_observer = Some(observer);
    }

    #[cfg(test)]
    pub(crate) fn fail_receiver_advice_at_for_test(&mut self, operation: usize) {
        self.expected
            .as_mut()
            .expect("test fault precedes the only mixed preparation attempt")
            .fail_advice_at_for_test(operation);
    }

    #[cfg(test)]
    pub(crate) fn inject_imported_rights_for_test(&mut self, count: usize) {
        assert!((1..=16).contains(&count));
        self.imported_rights_fault = Some(count);
    }

    #[cfg(test)]
    pub(crate) fn use_wrong_imported_credentials_for_test(&mut self) {
        self.imported_wrong_credentials = true;
    }

    #[cfg(test)]
    pub(crate) fn stale_imported_for_test(&mut self) {
        self.stale_imported = true;
    }

    #[cfg(test)]
    pub(crate) fn interleave_application_ready_for_test(&mut self) {
        self.ready_fault = CompletionFault::InterleavedApplication;
    }

    #[cfg(test)]
    pub(crate) fn substitute_ready_manifest_for_test(&mut self) {
        self.ready_fault = CompletionFault::SubstitutedManifest;
    }

    #[cfg(test)]
    pub(crate) fn truncate_ready_for_test(&mut self) {
        self.ready_fault = CompletionFault::Truncated;
    }

    #[cfg(test)]
    pub(crate) fn duplicate_ready_for_test(&mut self) {
        self.ready_fault = CompletionFault::Duplicate;
    }

    #[cfg(test)]
    pub(crate) fn acknowledge_commit_rejection_for_test(&mut self) {
        self.acknowledge_commit_rejection = true;
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
fn linux_received_receiver_writer_manifest_matches(
    parameters: AcceptedSessionParameters,
    transaction_id: u64,
    expected: &LinuxExpectedReceiverWriterBatch,
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
fn linux_received_mixed_manifest_matches(
    parameters: AcceptedSessionParameters,
    transaction_id: u64,
    expected: &LinuxExpectedMixedDirectionBatch,
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

#[cfg(target_os = "linux")]
impl Drop for LinuxReceiverWriterTransaction<'_> {
    fn drop(&mut self) {
        self.poison();
    }
}

#[cfg(target_os = "linux")]
impl Drop for LinuxReceiverMixedDirectionTransaction<'_> {
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

    fn receive_preparation(
        &mut self,
        expected: &PreparationFrame,
    ) -> Result<(), AcceptedControlError> {
        let bytes = match self
            .dispatcher
            .transport
            .receive_record(expected.as_bytes().len(), self.deadline)
        {
            Ok(bytes) => bytes,
            Err(error) => {
                self.poison();
                return Err(AcceptedControlError::Transport(error));
            }
        };
        if !expected.matches(&bytes) {
            self.poison();
            return Err(AcceptedControlError::Control(ControlError::NonCanonical));
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    fn receive_completion(
        &mut self,
        expected: &CompletionFrame,
    ) -> Result<(), AcceptedControlError> {
        let bytes = match self
            .dispatcher
            .transport
            .receive_record(expected.as_bytes().len(), self.deadline)
        {
            Ok(bytes) => bytes,
            Err(error) => {
                self.poison();
                return Err(AcceptedControlError::Transport(error));
            }
        };
        if !expected.matches(&bytes) {
            self.poison();
            return Err(AcceptedControlError::Control(ControlError::NonCanonical));
        }
        Ok(())
    }

    fn send_preparation(&mut self, frame: &PreparationFrame) -> Result<(), AcceptedControlError> {
        self.send_preparation_bytes(frame.as_bytes())
    }

    #[cfg(target_os = "linux")]
    fn send_completion(&mut self, frame: &CompletionFrame) -> Result<(), AcceptedControlError> {
        self.send_preparation_bytes(frame.as_bytes())
    }

    fn send_preparation_bytes(&mut self, bytes: &[u8]) -> Result<(), AcceptedControlError> {
        if let Err(error) = self.dispatcher.transport.send_record(bytes, self.deadline) {
            self.poison();
            return Err(AcceptedControlError::Transport(error));
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<(), AcceptedControlError> {
        if !self.attempted {
            self.poison();
            return Err(AcceptedControlError::Control(ControlError::ReplayOrReorder));
        }
        if let Err(error) = self.dispatcher.state.end_transaction() {
            self.poison();
            return Err(AcceptedControlError::Control(error));
        }
        self.already_poisoned = true;
        Ok(())
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
