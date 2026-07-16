use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use static_assertions::assert_not_impl_any;

use super::*;
use crate::backend::macos::supervisor::{
    ConnectionGeneration, DecodedSpawnResult, FreshServiceNonce, SpawnFailure, SpawnRequest,
    SupervisorConnection, TargetEnvironmentEntry, VerifiedMessage, VerifiedPeer,
    encode_test_spawn_result,
};

const CLIENT_CODE_IDENTITY: [u8; 32] = [0x33; 32];
const CLIENT_AUDIT_IDENTITY: [u8; 32] = [0x44; 32];
const SERVICE_CODE_IDENTITY: [u8; 32] = [0x55; 32];
static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(10_000);

assert_not_impl_any!(ClientConnectionGeneration: Clone, Copy);
assert_not_impl_any!(FreshClientNonce: Clone, Copy);

struct Pair {
    client: SupervisorClient,
    service: SupervisorConnection,
    client_peer: VerifiedPeer,
    service_peer: VerifiedServicePeer,
    service_generation: u64,
    client_nonce: [u8; 32],
    service_nonce: [u8; 32],
}

impl Pair {
    fn new() -> Self {
        let unique = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let mut client_nonce = [0x11; 32];
        client_nonce[..8].copy_from_slice(&unique.to_le_bytes());
        let mut service_nonce = [0x22; 32];
        service_nonce[..8].copy_from_slice(&unique.to_le_bytes());

        // SAFETY: the monotonic fixture counter provides distinct nonzero values.
        let service_generation = unsafe {
            ConnectionGeneration::from_unique_service_value(unique.checked_add(1).unwrap()).unwrap()
        };
        // SAFETY: this fixture nonce is distinct and nonzero.
        let service_fresh = unsafe { FreshServiceNonce::from_fresh_random(service_nonce).unwrap() };
        let service = SupervisorConnection::new(service_generation, service_fresh);
        // SAFETY: tests model exact-message authentication for this connection.
        let client_peer = unsafe {
            VerifiedPeer::from_test_authenticated_message(
                service.connection_identity(),
                CLIENT_AUDIT_IDENTITY,
                501,
                20,
                CLIENT_CODE_IDENTITY,
            )
            .unwrap()
        };

        // SAFETY: the monotonic fixture counter provides distinct nonzero values.
        let client_generation = unsafe {
            ClientConnectionGeneration::from_unique_client_value(unique.checked_add(2).unwrap())
                .unwrap()
        };
        // SAFETY: this fixture nonce is distinct and nonzero.
        let client_fresh = unsafe { FreshClientNonce::from_fresh_random(client_nonce).unwrap() };
        let client =
            SupervisorClient::new(client_generation, client_fresh, SERVICE_CODE_IDENTITY).unwrap();
        // SAFETY: tests model exact-message service authentication for this connection.
        let service_peer = unsafe {
            VerifiedServicePeer::from_test_authenticated_service_message(
                client.connection_identity(),
                SERVICE_CODE_IDENTITY,
            )
            .unwrap()
        };
        let service_generation = service.connection_identity().get();
        Self {
            client,
            service,
            client_peer,
            service_peer,
            service_generation,
            client_nonce,
            service_nonce,
        }
    }

    fn service_message<'a>(&self, bytes: &'a [u8]) -> VerifiedServiceMessage<'a> {
        // SAFETY: tests bind these bytes to this pair's modeled exact service peer.
        unsafe {
            VerifiedServiceMessage::from_test_authenticated_service_message(
                self.service_peer,
                bytes,
            )
        }
    }

    fn authenticate(&mut self) {
        let request = self.client.take_client_hello().unwrap();
        // SAFETY: tests bind these bytes to this pair's modeled exact client peer.
        let message =
            unsafe { VerifiedMessage::from_test_authenticated_message(self.client_peer, &request) };
        let reply = self.service.receive_client_hello(message).unwrap();
        let reply_message = self.service_message(&reply);
        self.client.receive_service_hello(reply_message).unwrap();
    }

    fn spawn_result(&self, result: Result<[u8; 32], SpawnFailure>) -> Vec<u8> {
        encode_test_spawn_result(
            result,
            self.service_generation,
            self.client_nonce,
            self.service_nonce,
        )
        .unwrap()
    }
}

fn request() -> SpawnRequest {
    SpawnRequest::new(
        crate::backend::macos::supervisor::SupervisorDeadline::from_instant(
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap(),
        b"com.example.receiver".to_vec(),
        vec![b"--mode=test".to_vec()],
        vec![TargetEnvironmentEntry::new(b"LANG".to_vec(), b"C".to_vec()).unwrap()],
    )
    .unwrap()
}

fn service_reply(pair: &mut Pair) -> Vec<u8> {
    let hello = pair.client.take_client_hello().unwrap();
    // SAFETY: tests bind these bytes to this pair's modeled exact client peer.
    let message =
        unsafe { VerifiedMessage::from_test_authenticated_message(pair.client_peer, &hello) };
    pair.service.receive_client_hello(message).unwrap()
}

fn awaiting_spawn_result_pair() -> Pair {
    let mut pair = Pair::new();
    pair.authenticate();
    pair.client.encode_spawn(request()).unwrap();
    pair
}

#[test]
fn exact_service_reply_authenticates_one_spawn_for_the_server() {
    let mut pair = Pair::new();
    pair.authenticate();
    let spawn = pair.client.encode_spawn(request()).unwrap();
    // SAFETY: tests bind these bytes to this pair's modeled exact client peer.
    let message =
        unsafe { VerifiedMessage::from_test_authenticated_message(pair.client_peer, &spawn) };
    assert!(pair.service.receive_spawn(message).is_ok());

    assert_eq!(
        pair.client.encode_spawn(request()),
        Err(SupervisorWireError::StateViolation)
    );
    assert!(pair.client.is_poisoned());
}

#[test]
fn authenticated_spawn_result_yields_only_an_opaque_handle() {
    let mut pair = Pair::new();
    pair.authenticate();
    pair.client.encode_spawn(request()).unwrap();
    let handle = [0x77; 32];
    let reply = pair.spawn_result(Ok(handle));
    let message = pair.service_message(&reply);
    let result = pair.client.receive_spawn_result(message).unwrap();
    assert!(matches!(result, DecodedSpawnResult::Ready(_)));
    assert_eq!(pair.client.session_handle().unwrap().bytes(), handle);
    assert_eq!(
        pair.client.encode_spawn(request()),
        Err(SupervisorWireError::StateViolation)
    );
}

#[test]
fn coarse_spawn_rejection_is_terminal_and_has_no_handle() {
    for failure in [
        SpawnFailure::Denied,
        SpawnFailure::Busy,
        SpawnFailure::DeadlineExpired,
        SpawnFailure::LaunchFailed,
    ] {
        let mut pair = Pair::new();
        pair.authenticate();
        pair.client.encode_spawn(request()).unwrap();
        let reply = pair.spawn_result(Err(failure));
        let message = pair.service_message(&reply);
        assert_eq!(
            pair.client.receive_spawn_result(message),
            Ok(DecodedSpawnResult::Rejected(failure))
        );
        assert_eq!(pair.client.session_handle(), None);
        let replay = pair.service_message(&reply);
        assert_eq!(
            pair.client.receive_spawn_result(replay),
            Err(SupervisorWireError::StateViolation)
        );
    }
}

#[test]
fn spawn_result_canonicality_and_freshness_fail_closed() {
    let template = Pair::new();
    let canonical = template.spawn_result(Ok([0x88; 32]));
    for length in 0..canonical.len() {
        let mut pair = Pair::new();
        pair.authenticate();
        pair.client.encode_spawn(request()).unwrap();
        let own = pair.spawn_result(Ok([0x88; 32]));
        let peer = pair.service_peer;
        // SAFETY: the test binds this truncation to the exact modeled reply.
        let message = unsafe {
            VerifiedServiceMessage::from_test_authenticated_service_message(peer, &own[..length])
        };
        assert!(pair.client.receive_spawn_result(message).is_err());
        assert!(pair.client.is_poisoned());
    }

    for offset in [10, 16, 24, 32, 64, 96, 98, 100] {
        let mut pair = Pair::new();
        pair.authenticate();
        pair.client.encode_spawn(request()).unwrap();
        let mut reply = pair.spawn_result(Ok([0x88; 32]));
        reply[offset] ^= 1;
        let peer = pair.service_peer;
        // SAFETY: the test binds this mutation to the exact modeled reply.
        let message = unsafe {
            VerifiedServiceMessage::from_test_authenticated_service_message(peer, &reply)
        };
        assert!(pair.client.receive_spawn_result(message).is_err());
        assert!(pair.client.is_poisoned());
    }

    let mut pair = Pair::new();
    pair.authenticate();
    pair.client.encode_spawn(request()).unwrap();
    let mut zero_handle = pair.spawn_result(Ok([0x88; 32]));
    zero_handle[104..136].fill(0);
    let peer = pair.service_peer;
    // SAFETY: the test binds this malformed handle to the exact modeled reply.
    let message = unsafe {
        VerifiedServiceMessage::from_test_authenticated_service_message(peer, &zero_handle)
    };
    assert_eq!(
        pair.client.receive_spawn_result(message),
        Err(SupervisorWireError::Malformed)
    );
}

#[test]
fn spawn_result_wrong_service_and_every_semantic_shape_fail_closed() {
    let mut pair = awaiting_spawn_result_pair();
    let reply = pair.spawn_result(Ok([0x91; 32]));
    let other = Pair::new();
    let wrong_connection = VerifiedServicePeer {
        connection_identity: other.client.connection_identity(),
        code_identity: SERVICE_CODE_IDENTITY,
    };
    // SAFETY: intentionally model a reply from the wrong exact connection.
    let message = unsafe {
        VerifiedServiceMessage::from_test_authenticated_service_message(wrong_connection, &reply)
    };
    assert_eq!(
        pair.client.receive_spawn_result(message),
        Err(SupervisorWireError::PeerMismatch)
    );
    assert!(pair.client.is_poisoned());
    assert_eq!(pair.client.session_handle(), None);

    let mut pair = awaiting_spawn_result_pair();
    let reply = pair.spawn_result(Ok([0x92; 32]));
    let wrong_identity = VerifiedServicePeer {
        connection_identity: pair.client.connection_identity(),
        code_identity: [0x99; 32],
    };
    // SAFETY: intentionally model a reply from the wrong signed service.
    let message = unsafe {
        VerifiedServiceMessage::from_test_authenticated_service_message(wrong_identity, &reply)
    };
    assert_eq!(
        pair.client.receive_spawn_result(message),
        Err(SupervisorWireError::PeerMismatch)
    );

    for mutation in 0..8 {
        let mut pair = awaiting_spawn_result_pair();
        let mut reply = if mutation == 1 || mutation == 2 {
            pair.spawn_result(Err(SpawnFailure::Denied))
        } else {
            pair.spawn_result(Ok([0x93; 32]))
        };
        match mutation {
            0 => reply[98] = 1,          // Ready detail must be zero.
            1 => reply[104] = 1,         // Rejected handle must be zero.
            2 => reply[98..100].fill(0), // Rejected detail must be known/nonzero.
            3 => reply[96..98].copy_from_slice(&3_u16.to_le_bytes()),
            4..=7 => reply[100 + mutation - 4] = 1,
            _ => unreachable!(),
        }
        let peer = pair.service_peer;
        // SAFETY: bind each noncanonical shape to the exact modeled service.
        let message = unsafe {
            VerifiedServiceMessage::from_test_authenticated_service_message(peer, &reply)
        };
        assert_eq!(
            pair.client.receive_spawn_result(message),
            Err(SupervisorWireError::Malformed)
        );
        assert!(pair.client.is_poisoned());
        assert_eq!(pair.client.session_handle(), None);
    }

    let mut pair = awaiting_spawn_result_pair();
    let mut extended = pair.spawn_result(Ok([0x94; 32]));
    extended.push(0);
    let peer = pair.service_peer;
    // SAFETY: bind the extension to the exact modeled service reply.
    let message =
        unsafe { VerifiedServiceMessage::from_test_authenticated_service_message(peer, &extended) };
    assert_eq!(
        pair.client.receive_spawn_result(message),
        Err(SupervisorWireError::Malformed)
    );

    let mut pair = Pair::new();
    let premature = pair.spawn_result(Ok([0x95; 32]));
    let message = pair.service_message(&premature);
    assert_eq!(
        pair.client.receive_spawn_result(message),
        Err(SupervisorWireError::AuthenticationRequired)
    );
    assert!(pair.client.is_poisoned());
}

#[test]
fn reply_truncation_and_freshness_mutation_poison_the_client() {
    let mut template = Pair::new();
    let reply = service_reply(&mut template);
    for length in 0..reply.len() {
        let mut pair = Pair::new();
        let own_reply = service_reply(&mut pair);
        let peer = pair.service_peer;
        // SAFETY: tests bind this truncation to the pair's modeled exact service peer.
        let message = unsafe {
            VerifiedServiceMessage::from_test_authenticated_service_message(
                peer,
                &own_reply[..length],
            )
        };
        assert!(pair.client.receive_service_hello(message).is_err());
        assert!(pair.client.is_poisoned());
    }

    for offset in [10, 24, 32] {
        let mut pair = Pair::new();
        let mut own_reply = service_reply(&mut pair);
        own_reply[offset] ^= 0xff;
        let peer = pair.service_peer;
        // SAFETY: tests bind the mutation to the pair's modeled exact service peer.
        let message = unsafe {
            VerifiedServiceMessage::from_test_authenticated_service_message(peer, &own_reply)
        };
        assert!(pair.client.receive_service_hello(message).is_err());
        assert!(pair.client.is_poisoned());
    }

    for range in [16..24, 64..96] {
        let mut pair = Pair::new();
        let mut own_reply = service_reply(&mut pair);
        own_reply[range].fill(0);
        let peer = pair.service_peer;
        // SAFETY: tests bind the malformed freshness fact to the exact reply.
        let message = unsafe {
            VerifiedServiceMessage::from_test_authenticated_service_message(peer, &own_reply)
        };
        assert!(pair.client.receive_service_hello(message).is_err());
        assert!(pair.client.is_poisoned());
    }

    let mut pair = Pair::new();
    let mut own_reply = service_reply(&mut pair);
    own_reply.copy_within(32..64, 64);
    let peer = pair.service_peer;
    // SAFETY: tests bind the nonce-reuse mutation to the exact reply.
    let message = unsafe {
        VerifiedServiceMessage::from_test_authenticated_service_message(peer, &own_reply)
    };
    assert!(pair.client.receive_service_hello(message).is_err());
}

#[test]
fn wrong_connection_or_service_identity_never_authenticates() {
    let mut pair = Pair::new();
    let reply = service_reply(&mut pair);
    let other = Pair::new();
    let wrong_connection = VerifiedServicePeer {
        connection_identity: other.client.connection_identity(),
        code_identity: SERVICE_CODE_IDENTITY,
    };
    // SAFETY: this intentionally models a reply from the wrong connection.
    let message = unsafe {
        VerifiedServiceMessage::from_test_authenticated_service_message(wrong_connection, &reply)
    };
    assert_eq!(
        pair.client.receive_service_hello(message),
        Err(SupervisorWireError::PeerMismatch)
    );

    let mut pair = Pair::new();
    let reply = service_reply(&mut pair);
    let wrong_identity = VerifiedServicePeer {
        connection_identity: pair.client.connection_identity(),
        code_identity: [0x99; 32],
    };
    // SAFETY: this intentionally models a reply with the wrong code identity.
    let message = unsafe {
        VerifiedServiceMessage::from_test_authenticated_service_message(wrong_identity, &reply)
    };
    assert_eq!(
        pair.client.receive_service_hello(message),
        Err(SupervisorWireError::PeerMismatch)
    );
}

#[test]
fn client_protocol_is_ordered_and_fresh_values_are_linear() {
    let mut pair = Pair::new();
    assert_eq!(
        pair.client.encode_spawn(request()),
        Err(SupervisorWireError::AuthenticationRequired)
    );
    assert!(pair.client.is_poisoned());

    let mut pair = Pair::new();
    assert!(pair.client.take_client_hello().is_ok());
    assert_eq!(
        pair.client.take_client_hello(),
        Err(SupervisorWireError::StateViolation)
    );

    // SAFETY: these intentionally supply rejected non-fresh values.
    assert_eq!(
        unsafe { ClientConnectionGeneration::from_unique_client_value(0) },
        Err(SupervisorWireError::ReplayOrSubstitution)
    );
    // SAFETY: these intentionally supply rejected non-fresh values.
    assert_eq!(
        unsafe { FreshClientNonce::from_fresh_random([0; 32]) },
        Err(SupervisorWireError::ReplayOrSubstitution)
    );
}
