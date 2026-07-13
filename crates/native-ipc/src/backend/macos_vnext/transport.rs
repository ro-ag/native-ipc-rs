//! Accepted macOS Mach record and capability transports.
//!
//! These private owners deliberately hide the concrete Mach implementation
//! behind the backend-wide transport traits. A future signed-XPC adapter can
//! implement the same traits without changing any public session type.

use core::cell::Cell;
use core::marker::PhantomData;

use super::MachPort;
use super::bootstrap::{ChildChannel, MacChildLifecycle, ParentChannel, SendRight};
use crate::backend::{
    AuthenticatedZeroRightsTransport, CoordinatorAcceptedEvidence, CoordinatorCapabilityTransport,
    OwnedChildLifecycle, PeerState, ReceiverCapabilityTransport, ReceiverSpawnerEvidence,
    SessionTransportError, sealed,
};
use crate::protocol::{CONTROL_FRAME_LEN, CapabilityFrame, NativeAuthorityProfile};
use crate::session::AbsoluteDeadline;
use crate::session::ChildCleanupFacts;

/// Coordinator-only accepted Mach transport retaining exact-child lifecycle.
pub(crate) struct CoordinatorMacControlTransport {
    channel: ParentChannel,
    lifecycle: MacChildLifecycle,
    _evidence: CoordinatorAcceptedEvidence,
    poisoned: bool,
    not_sync: PhantomData<Cell<()>>,
}

/// Receiver-only accepted Mach transport with no child lifecycle authority.
pub(crate) struct ReceiverMacControlTransport {
    channel: ChildChannel,
    _evidence: ReceiverSpawnerEvidence,
    poisoned: bool,
    #[cfg(test)]
    poison_observer: Option<std::sync::Arc<std::sync::Mutex<Vec<&'static str>>>>,
    not_sync: PhantomData<Cell<()>>,
}

/// Immediately owned Mach send rights installed by one capability record.
pub(crate) struct MacReceivedCapabilities {
    rights: Vec<SendRight>,
    not_sync: PhantomData<Cell<()>>,
}

pub(crate) struct MacReceivedCapabilityRecord {
    pub(crate) frame: Vec<u8>,
    pub(crate) rights: Vec<SendRight>,
}

impl MacReceivedCapabilities {
    pub(crate) fn len(&self) -> usize {
        self.rights.len()
    }

    pub(crate) fn into_rights(self) -> Vec<SendRight> {
        self.rights
    }
}

impl CoordinatorMacControlTransport {
    #[cfg(test)]
    pub(crate) fn from_accepted_for_wait_test(
        mut channel: ParentChannel,
        evidence: CoordinatorAcceptedEvidence,
    ) -> Result<Self, SessionTransportError> {
        let lifecycle = channel.take_vnext_lifecycle()?;
        Self::from_accepted_with_lifecycle(channel, lifecycle, evidence)
    }

    pub(super) fn from_accepted_with_lifecycle(
        channel: ParentChannel,
        lifecycle: MacChildLifecycle,
        evidence: CoordinatorAcceptedEvidence,
    ) -> Result<Self, SessionTransportError> {
        let facts = evidence.facts();
        if facts.parent_pid() != std::process::id()
            || facts.child_pid() != channel.peer_pid()
            || lifecycle.pid() != channel.peer_pid()
            || facts.nonce() != channel.vnext_nonce()
        {
            return Err(SessionTransportError::IdentityMismatch);
        }
        Ok(Self {
            channel,
            lifecycle,
            _evidence: evidence,
            poisoned: false,
            not_sync: PhantomData,
        })
    }

    pub(crate) fn session_parameters(&self) -> crate::backend::AcceptedSessionParameters {
        self._evidence
            .session_parameters(NativeAuthorityProfile::MacMachV1)
    }

    pub(crate) fn wait_and_reap_facts(&self, deadline: AbsoluteDeadline) -> ChildCleanupFacts {
        self.lifecycle.wait_and_reap_facts(deadline)
    }

    pub(crate) fn terminate_and_reap_facts(
        &mut self,
        deadline: AbsoluteDeadline,
    ) -> ChildCleanupFacts {
        self.poisoned = true;
        self.lifecycle.terminate_and_reap_facts(deadline)
    }

    #[cfg(test)]
    pub(crate) fn delay_reap_for_test(&self, milliseconds: u64) {
        self.lifecycle.delay_reap_for_test(milliseconds);
    }

    #[cfg(test)]
    pub(crate) fn interrupt_reap_wait_for_test(&self, count: u64) {
        self.lifecycle.interrupt_wait_for_test(count);
    }

    #[cfg(test)]
    pub(crate) fn wait_for_child_exit_for_test(
        &self,
        deadline: AbsoluteDeadline,
    ) -> Result<(), SessionTransportError> {
        loop {
            match self.lifecycle.try_poll()? {
                PeerState::ExitedUnknown if self.lifecycle.exited_successfully_for_test() => {
                    return Ok(());
                }
                PeerState::ExitedUnknown => return Err(SessionTransportError::Native(None)),
                PeerState::Running if deadline.is_expired() => {
                    return Err(SessionTransportError::DeadlineExpired);
                }
                PeerState::Running => std::thread::sleep(
                    core::time::Duration::from_millis(1).min(deadline.remaining()),
                ),
            }
        }
    }

    fn ensure_live(&self) -> Result<(), SessionTransportError> {
        if self.poisoned {
            Err(SessionTransportError::Native(None))
        } else {
            Ok(())
        }
    }

    fn terminal<T>(
        &mut self,
        result: Result<T, SessionTransportError>,
    ) -> Result<T, SessionTransportError> {
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
}

impl ReceiverMacControlTransport {
    pub(crate) fn from_accepted(
        channel: ChildChannel,
        evidence: ReceiverSpawnerEvidence,
    ) -> Result<Self, SessionTransportError> {
        let facts = evidence.facts();
        if facts.child_pid() != std::process::id()
            || facts.parent_pid() != channel.vnext_parent_pid()
            || facts.nonce() != channel.vnext_nonce()
        {
            return Err(SessionTransportError::IdentityMismatch);
        }
        Ok(Self {
            channel,
            _evidence: evidence,
            poisoned: false,
            #[cfg(test)]
            poison_observer: None,
            not_sync: PhantomData,
        })
    }

    pub(crate) fn session_parameters(&self) -> crate::backend::AcceptedSessionParameters {
        self._evidence
            .session_parameters(NativeAuthorityProfile::MacMachV1)
    }

    #[cfg(test)]
    pub(crate) fn observe_poison_for_test(
        &mut self,
        observer: std::sync::Arc<std::sync::Mutex<Vec<&'static str>>>,
    ) {
        self.poison_observer = Some(observer);
    }

    fn ensure_live(&self) -> Result<(), SessionTransportError> {
        if self.poisoned {
            Err(SessionTransportError::Native(None))
        } else {
            Ok(())
        }
    }

    fn terminal<T>(
        &mut self,
        result: Result<T, SessionTransportError>,
    ) -> Result<T, SessionTransportError> {
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    pub(crate) fn receive_candidate_capability_record(
        &mut self,
        expected_count: usize,
        deadline: AbsoluteDeadline,
    ) -> Result<MacReceivedCapabilityRecord, SessionTransportError> {
        self.ensure_live()?;
        if !(1..=16).contains(&expected_count) {
            return Err(SessionTransportError::MalformedRecord);
        }
        let result = self
            .channel
            .receive_vnext_capabilities(CONTROL_FRAME_LEN, deadline)
            .and_then(|record| {
                if record.rights.len() != expected_count {
                    return Err(SessionTransportError::MalformedRecord);
                }
                Ok(MacReceivedCapabilityRecord {
                    frame: record.bytes,
                    rights: record.rights,
                })
            });
        self.terminal(result)
    }
}

impl sealed::Sealed for CoordinatorMacControlTransport {}
impl sealed::Sealed for ReceiverMacControlTransport {}

impl AuthenticatedZeroRightsTransport for CoordinatorMacControlTransport {
    fn send_record(
        &mut self,
        bytes: &[u8],
        deadline: AbsoluteDeadline,
    ) -> Result<(), SessionTransportError> {
        self.ensure_live()?;
        if bytes.is_empty() || bytes.len() > super::bootstrap::MAX_VNEXT_RECORD_BYTES {
            return Err(SessionTransportError::RecordTooLarge);
        }
        let result = self.channel.send_vnext_zero_rights(bytes, deadline);
        self.terminal(result)
    }

    fn receive_record(
        &mut self,
        maximum: usize,
        deadline: AbsoluteDeadline,
    ) -> Result<Vec<u8>, SessionTransportError> {
        self.ensure_live()?;
        if maximum == 0 {
            return Err(SessionTransportError::RecordTooLarge);
        }
        let result = self.channel.receive_vnext_zero_rights(
            maximum.min(super::bootstrap::MAX_VNEXT_RECORD_BYTES),
            deadline,
        );
        self.terminal(result)
    }

    fn try_poll_peer(&mut self) -> Result<PeerState, SessionTransportError> {
        self.ensure_live()?;
        let result = self.lifecycle.try_poll();
        self.terminal(result)
    }

    fn poison(&mut self) {
        self.poisoned = true;
    }
}

impl AuthenticatedZeroRightsTransport for ReceiverMacControlTransport {
    fn send_record(
        &mut self,
        bytes: &[u8],
        deadline: AbsoluteDeadline,
    ) -> Result<(), SessionTransportError> {
        self.ensure_live()?;
        if bytes.is_empty() || bytes.len() > super::bootstrap::MAX_VNEXT_RECORD_BYTES {
            return Err(SessionTransportError::RecordTooLarge);
        }
        let result = self.channel.send_vnext_zero_rights(bytes, deadline);
        self.terminal(result)
    }

    fn receive_record(
        &mut self,
        maximum: usize,
        deadline: AbsoluteDeadline,
    ) -> Result<Vec<u8>, SessionTransportError> {
        self.ensure_live()?;
        if maximum == 0 {
            return Err(SessionTransportError::RecordTooLarge);
        }
        let result = self.channel.receive_vnext_zero_rights(
            maximum.min(super::bootstrap::MAX_VNEXT_RECORD_BYTES),
            deadline,
        );
        self.terminal(result)
    }

    fn try_poll_peer(&mut self) -> Result<PeerState, SessionTransportError> {
        self.ensure_live()?;
        let result = self.channel.try_poll_vnext_peer();
        self.terminal(result)
    }

    fn poison(&mut self) {
        self.poisoned = true;
        #[cfg(test)]
        if let Some(observer) = self.poison_observer.as_ref() {
            observer.lock().unwrap().push("poison");
        }
    }
}

impl CoordinatorCapabilityTransport for CoordinatorMacControlTransport {
    type Capabilities<'a> = &'a [MachPort];

    fn send_capability_record(
        &mut self,
        frame: &CapabilityFrame,
        capabilities: Self::Capabilities<'_>,
        deadline: AbsoluteDeadline,
    ) -> Result<(), SessionTransportError> {
        self.ensure_live()?;
        if capabilities.len() != frame.capability_count() || !(1..=16).contains(&capabilities.len())
        {
            return Err(SessionTransportError::MalformedRecord);
        }
        let result = self
            .channel
            .send_vnext_capabilities(frame.as_bytes(), capabilities, deadline);
        self.terminal(result)
    }
}

impl ReceiverCapabilityTransport for ReceiverMacControlTransport {
    type ReceivedCapabilities = MacReceivedCapabilities;

    fn receive_capability_record(
        &mut self,
        expected: &CapabilityFrame,
        deadline: AbsoluteDeadline,
    ) -> Result<Self::ReceivedCapabilities, SessionTransportError> {
        self.ensure_live()?;
        if !(1..=16).contains(&expected.capability_count()) {
            return Err(SessionTransportError::MalformedRecord);
        }
        let record =
            self.receive_candidate_capability_record(expected.capability_count(), deadline)?;
        if record.frame.as_slice() != expected.as_bytes() {
            self.poisoned = true;
            return Err(SessionTransportError::MalformedRecord);
        }
        Ok(MacReceivedCapabilities {
            rights: record.rights,
            not_sync: PhantomData,
        })
    }
}

impl OwnedChildLifecycle for CoordinatorMacControlTransport {
    fn terminate_and_reap(
        &mut self,
        deadline: AbsoluteDeadline,
    ) -> Result<(), SessionTransportError> {
        self.poisoned = true;
        self.lifecycle.terminate_and_reap(deadline)
    }
}
