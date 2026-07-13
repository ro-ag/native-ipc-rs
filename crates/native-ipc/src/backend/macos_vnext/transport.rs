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
    not_sync: PhantomData<Cell<()>>,
}

/// Immediately owned Mach send rights installed by one capability record.
pub(crate) struct MacReceivedCapabilities {
    rights: Vec<SendRight>,
    not_sync: PhantomData<Cell<()>>,
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
    pub(crate) fn from_accepted(
        mut channel: ParentChannel,
        evidence: CoordinatorAcceptedEvidence,
    ) -> Result<Self, SessionTransportError> {
        let facts = evidence.facts();
        if facts.parent_pid() != std::process::id()
            || facts.child_pid() != channel.peer_pid()
            || facts.nonce() != channel.vnext_nonce()
        {
            return Err(SessionTransportError::IdentityMismatch);
        }
        let lifecycle = channel.take_vnext_lifecycle()?;
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

    #[cfg(test)]
    pub(crate) fn delay_reap_for_test(&self, milliseconds: u64) {
        self.lifecycle.delay_reap_for_test(milliseconds);
    }

    #[cfg(test)]
    pub(crate) fn interrupt_reap_wait_for_test(&self, count: u64) {
        self.lifecycle.interrupt_wait_for_test(count);
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
            not_sync: PhantomData,
        })
    }

    pub(crate) fn session_parameters(&self) -> crate::backend::AcceptedSessionParameters {
        self._evidence
            .session_parameters(NativeAuthorityProfile::MacMachV1)
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
        if maximum == 0 || maximum > super::bootstrap::MAX_VNEXT_RECORD_BYTES {
            return Err(SessionTransportError::RecordTooLarge);
        }
        let result = self.channel.receive_vnext_zero_rights(maximum, deadline);
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
        if maximum == 0 || maximum > super::bootstrap::MAX_VNEXT_RECORD_BYTES {
            return Err(SessionTransportError::RecordTooLarge);
        }
        let result = self.channel.receive_vnext_zero_rights(maximum, deadline);
        self.terminal(result)
    }

    fn try_poll_peer(&mut self) -> Result<PeerState, SessionTransportError> {
        self.ensure_live()?;
        let result = self.channel.try_poll_vnext_peer();
        self.terminal(result)
    }

    fn poison(&mut self) {
        self.poisoned = true;
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
        let result = self
            .channel
            .receive_vnext_capabilities(CONTROL_FRAME_LEN, deadline)
            .and_then(|record| {
                if record.bytes.as_slice() != expected.as_bytes()
                    || record.rights.len() != expected.capability_count()
                {
                    return Err(SessionTransportError::MalformedRecord);
                }
                Ok(MacReceivedCapabilities {
                    rights: record.rights,
                    not_sync: PhantomData,
                })
            });
        self.terminal(result)
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
