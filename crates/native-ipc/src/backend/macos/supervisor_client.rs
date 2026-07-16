//! One-shot client state for the future same-user supervisor transport.

use super::supervisor::{
    DecodedSpawnResult, OpaqueSessionHandle, SpawnRequest, SupervisorWireError,
    decode_service_hello, decode_spawn_result, encode_client_hello, encode_spawn_request,
};

/// Client-lifetime-unique identity for one transport connection.
#[derive(Debug, Eq, PartialEq)]
pub(super) struct ClientConnectionGeneration(u64);

impl ClientConnectionGeneration {
    /// # Safety
    ///
    /// `value` must be nonzero and never reused by this client process.
    pub(super) const unsafe fn from_unique_client_value(
        value: u64,
    ) -> Result<Self, SupervisorWireError> {
        if value == 0 {
            Err(SupervisorWireError::ReplayOrSubstitution)
        } else {
            Ok(Self(value))
        }
    }

    const fn into_identity(self) -> ClientConnectionIdentity {
        ClientConnectionIdentity(self.0)
    }
}

/// Copyable identity derived from one consumed client connection generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ClientConnectionIdentity(u64);

/// Fresh unpredictable client nonce used by exactly one connection.
#[derive(Debug, Eq, PartialEq)]
pub(super) struct FreshClientNonce([u8; 32]);

impl FreshClientNonce {
    /// # Safety
    ///
    /// `value` must come from the OS CSPRNG and must not be reused by this
    /// client process.
    pub(super) unsafe fn from_fresh_random(value: [u8; 32]) -> Result<Self, SupervisorWireError> {
        if value == [0; 32] {
            Err(SupervisorWireError::ReplayOrSubstitution)
        } else {
            Ok(Self(value))
        }
    }
}

/// Service identity facts authenticated from one exact received reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct VerifiedServicePeer {
    connection_identity: ClientConnectionIdentity,
    code_identity: [u8; 32],
}

impl VerifiedServicePeer {
    /// Constructs facts only after the transport adapter verifies the dynamic
    /// code identity of the exact received service reply.
    ///
    /// # Safety
    ///
    /// `connection_identity` and `code_identity` must describe the same exact
    /// received message later wrapped in [`VerifiedServiceMessage`].
    unsafe fn from_authenticated_service_message(
        connection_identity: ClientConnectionIdentity,
        code_identity: [u8; 32],
    ) -> Result<Self, SupervisorWireError> {
        if code_identity == [0; 32] {
            return Err(SupervisorWireError::PeerMismatch);
        }
        Ok(Self {
            connection_identity,
            code_identity,
        })
    }

    #[cfg(test)]
    pub(super) unsafe fn from_test_authenticated_service_message(
        connection_identity: ClientConnectionIdentity,
        code_identity: [u8; 32],
    ) -> Result<Self, SupervisorWireError> {
        // SAFETY: this test-only seam models the fused Mach/Security boundary
        // and supplies all facts from one synthetic exact reply.
        unsafe { Self::from_authenticated_service_message(connection_identity, code_identity) }
    }
}

/// Reply bytes already authenticated as coming from the installed service.
pub(super) struct VerifiedServiceMessage<'a> {
    peer: VerifiedServicePeer,
    bytes: &'a [u8],
}

impl<'a> VerifiedServiceMessage<'a> {
    /// # Safety
    ///
    /// `peer` must have been derived from the same received transport message
    /// that supplied `bytes`.
    unsafe fn from_authenticated_service_message(
        peer: VerifiedServicePeer,
        bytes: &'a [u8],
    ) -> Self {
        Self { peer, bytes }
    }

    #[cfg(test)]
    pub(super) unsafe fn from_test_authenticated_service_message(
        peer: VerifiedServicePeer,
        bytes: &'a [u8],
    ) -> Self {
        // SAFETY: this test-only seam binds the synthetic exact-reply peer to
        // these exact modeled receive bytes.
        unsafe { Self::from_authenticated_service_message(peer, bytes) }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ClientState {
    Fresh,
    AwaitingServiceHello,
    Authenticated {
        generation: u64,
        service_nonce: [u8; 32],
    },
    AwaitingSpawnResult {
        generation: u64,
        service_nonce: [u8; 32],
    },
    Active {
        handle: OpaqueSessionHandle,
    },
    TerminalFailure,
    Poisoned,
}

/// Authentication-before-effects client for one supervisor connection.
pub(super) struct SupervisorClient {
    connection_identity: ClientConnectionIdentity,
    expected_service_code_identity: [u8; 32],
    client_nonce: [u8; 32],
    state: ClientState,
}

impl SupervisorClient {
    pub(super) fn new(
        generation: ClientConnectionGeneration,
        nonce: FreshClientNonce,
        expected_service_code_identity: [u8; 32],
    ) -> Result<Self, SupervisorWireError> {
        if expected_service_code_identity == [0; 32] {
            return Err(SupervisorWireError::PeerMismatch);
        }
        Ok(Self {
            connection_identity: generation.into_identity(),
            expected_service_code_identity,
            client_nonce: nonce.0,
            state: ClientState::Fresh,
        })
    }

    pub(super) const fn connection_identity(&self) -> ClientConnectionIdentity {
        self.connection_identity
    }

    /// Emits this connection's authentication-only hello exactly once.
    pub(super) fn take_client_hello(&mut self) -> Result<Vec<u8>, SupervisorWireError> {
        if self.state != ClientState::Fresh {
            self.state = ClientState::Poisoned;
            return Err(SupervisorWireError::StateViolation);
        }
        self.state = ClientState::Poisoned;
        let hello = encode_client_hello(self.client_nonce)?;
        self.state = ClientState::AwaitingServiceHello;
        Ok(hello)
    }

    /// Authenticates the exact service reply and binds its freshness facts.
    pub(super) fn receive_service_hello(
        &mut self,
        message: VerifiedServiceMessage<'_>,
    ) -> Result<(), SupervisorWireError> {
        if self.state != ClientState::AwaitingServiceHello {
            self.state = ClientState::Poisoned;
            return Err(SupervisorWireError::StateViolation);
        }
        self.state = ClientState::Poisoned;
        if message.peer.connection_identity != self.connection_identity
            || message.peer.code_identity != self.expected_service_code_identity
        {
            return Err(SupervisorWireError::PeerMismatch);
        }
        let hello = decode_service_hello(message.bytes, self.client_nonce)?;
        self.state = ClientState::Authenticated {
            generation: hello.generation(),
            service_nonce: hello.service_nonce(),
        };
        Ok(())
    }

    /// Emits one effect-bearing request using only authenticated server facts.
    pub(super) fn encode_spawn(
        &mut self,
        request: SpawnRequest,
    ) -> Result<Vec<u8>, SupervisorWireError> {
        let (generation, service_nonce) = match self.state {
            ClientState::Authenticated {
                generation,
                service_nonce,
            } => (generation, service_nonce),
            ClientState::Fresh | ClientState::AwaitingServiceHello => {
                self.state = ClientState::Poisoned;
                return Err(SupervisorWireError::AuthenticationRequired);
            }
            ClientState::AwaitingSpawnResult { .. }
            | ClientState::Active { .. }
            | ClientState::TerminalFailure
            | ClientState::Poisoned => {
                self.state = ClientState::Poisoned;
                return Err(SupervisorWireError::StateViolation);
            }
        };
        self.state = ClientState::Poisoned;
        let encoded = encode_spawn_request(&request, generation, self.client_nonce, service_nonce)?;
        self.state = ClientState::AwaitingSpawnResult {
            generation,
            service_nonce,
        };
        Ok(encoded)
    }

    /// Authenticates the exact sequence-one service reply. A ready result
    /// carries only an opaque handle; failures are terminal and coarse.
    pub(super) fn receive_spawn_result(
        &mut self,
        message: VerifiedServiceMessage<'_>,
    ) -> Result<DecodedSpawnResult, SupervisorWireError> {
        let (generation, service_nonce) = match self.state {
            ClientState::AwaitingSpawnResult {
                generation,
                service_nonce,
            } => (generation, service_nonce),
            ClientState::Fresh
            | ClientState::AwaitingServiceHello
            | ClientState::Authenticated { .. } => {
                self.state = ClientState::Poisoned;
                return Err(SupervisorWireError::AuthenticationRequired);
            }
            ClientState::Active { .. } | ClientState::TerminalFailure | ClientState::Poisoned => {
                self.state = ClientState::Poisoned;
                return Err(SupervisorWireError::StateViolation);
            }
        };
        self.state = ClientState::Poisoned;
        if message.peer.connection_identity != self.connection_identity
            || message.peer.code_identity != self.expected_service_code_identity
        {
            return Err(SupervisorWireError::PeerMismatch);
        }
        let result =
            decode_spawn_result(message.bytes, generation, self.client_nonce, service_nonce)?;
        self.state = match result {
            DecodedSpawnResult::Ready(handle) => ClientState::Active { handle },
            DecodedSpawnResult::Rejected(_) => ClientState::TerminalFailure,
        };
        Ok(result)
    }

    pub(super) const fn session_handle(&self) -> Option<OpaqueSessionHandle> {
        match self.state {
            ClientState::Active { handle } => Some(handle),
            _ => None,
        }
    }

    pub(super) const fn is_poisoned(&self) -> bool {
        matches!(self.state, ClientState::Poisoned)
    }
}

#[cfg(test)]
#[path = "supervisor_client_test.rs"]
mod tests;
