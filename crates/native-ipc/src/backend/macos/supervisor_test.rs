use std::sync::atomic::{AtomicU64, Ordering};

use static_assertions::assert_not_impl_any;

use super::*;

const CLIENT_NONCE: [u8; 32] = [0x11; 32];
const CLIENT_AUDIT_IDENTITY: [u8; 32] = [0x22; 32];
const CLIENT_IDENTITY: [u8; 32] = [0x33; 32];
const TARGET_IDENTITY: [u8; 32] = [0x44; 32];
static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(1);

assert_not_impl_any!(ConnectionGeneration: Clone, Copy);
assert_not_impl_any!(FreshServiceNonce: Clone, Copy);
assert_not_impl_any!(AuthenticatedSpawnRequest: Clone, Copy);
assert_not_impl_any!(ValidatedSpawn: Clone, Copy);

struct Fixture {
    generation: u64,
    service_nonce: [u8; 32],
    peer: VerifiedPeer,
    connection: SupervisorConnection,
}

impl Fixture {
    fn new() -> Self {
        let unique = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        assert_ne!(unique, 0);
        let generation_value = unique.checked_add(100).unwrap();
        let mut nonce = [0x22; 32];
        nonce[..8].copy_from_slice(&unique.to_le_bytes());
        // SAFETY: the monotonic test counter supplies a unique nonzero value.
        let generation =
            unsafe { ConnectionGeneration::from_unique_service_value(generation_value).unwrap() };
        // SAFETY: each fixture derives a distinct nonzero modeled CSPRNG value.
        let fresh_nonce = unsafe { FreshServiceNonce::from_fresh_random(nonce).unwrap() };
        let connection = SupervisorConnection::new(generation, fresh_nonce);
        // SAFETY: tests model exact-message code-identity checking for this
        // fixture's one connection identity.
        let peer = unsafe {
            VerifiedPeer::from_test_authenticated_message(
                connection.connection_identity(),
                CLIENT_AUDIT_IDENTITY,
                501,
                20,
                CLIENT_IDENTITY,
            )
            .unwrap()
        };
        Self {
            generation: generation_value,
            service_nonce: nonce,
            peer,
            connection,
        }
    }

    fn authenticate(&mut self) {
        let hello = encode_client_hello(CLIENT_NONCE).unwrap();
        let reply = self
            .connection
            .receive_client_hello(message(self.peer, &hello))
            .unwrap();
        let reply_header = decode_header(&reply).unwrap();
        assert_eq!(reply_header.kind, RecordKind::ServiceHello);
        assert_eq!(reply_header.generation, self.generation);
        assert_eq!(reply_header.client_nonce, CLIENT_NONCE);
        assert_eq!(reply_header.service_nonce, self.service_nonce);
    }

    fn spawn_wire(&self, request: &SpawnRequest) -> Vec<u8> {
        encode_spawn_request(request, self.generation, CLIENT_NONCE, self.service_nonce).unwrap()
    }
}

fn message(peer: VerifiedPeer, bytes: &[u8]) -> VerifiedMessage<'_> {
    // SAFETY: each test binds these bytes to the supplied modeled peer.
    unsafe { VerifiedMessage::from_test_authenticated_message(peer, bytes) }
}

fn deadline_after(duration: Duration) -> SupervisorDeadline {
    SupervisorDeadline::from_instant(Instant::now() + duration).unwrap()
}

fn request() -> SpawnRequest {
    SpawnRequest::new(
        deadline_after(Duration::from_secs(5)),
        b"com.example.receiver".to_vec(),
        vec![b"--mode=test".to_vec()],
        vec![TargetEnvironmentEntry::new(b"LANG".to_vec(), b"C".to_vec()).unwrap()],
    )
    .unwrap()
}

fn policy_definition() -> TargetPolicyDefinition {
    TargetPolicyDefinition::new(
        b"com.example.receiver".to_vec(),
        CLIENT_IDENTITY,
        TARGET_IDENTITY,
        b"/example/NativeIPC.app/Contents/Helpers/receiver".to_vec(),
        b"receiver".to_vec(),
        4,
        vec![b"LANG".to_vec()],
    )
    .unwrap()
}

fn catalog() -> InstalledPolicyCatalog {
    // SAFETY: tests model one immutable deployer-owned installed policy resource.
    unsafe { InstalledPolicyCatalog::from_verified_installation(vec![policy_definition()]) }
        .unwrap()
}

#[test]
fn authentication_and_installed_policy_precede_the_single_effect_request() {
    let mut unauthenticated = Fixture::new();
    let spawn = unauthenticated.spawn_wire(&request());
    assert_eq!(
        unauthenticated
            .connection
            .receive_spawn(message(unauthenticated.peer, &spawn)),
        Err(SupervisorWireError::AuthenticationRequired)
    );
    assert!(unauthenticated.connection.is_poisoned());

    let mut authenticated = Fixture::new();
    authenticated.authenticate();
    let requested_deadline = Instant::now() + Duration::from_secs(5);
    let requested_wire_deadline = SupervisorDeadline::from_instant(requested_deadline).unwrap();
    let bounded_request = SpawnRequest::new(
        requested_wire_deadline,
        b"com.example.receiver".to_vec(),
        vec![b"--mode=test".to_vec()],
        vec![TargetEnvironmentEntry::new(b"LANG".to_vec(), b"C".to_vec()).unwrap()],
    )
    .unwrap();
    let spawn = authenticated.spawn_wire(&bounded_request);
    let admitted = authenticated
        .connection
        .receive_spawn(message(authenticated.peer, &spawn))
        .unwrap()
        .validate(&catalog())
        .unwrap();
    let after_admission = Instant::now();
    assert_eq!(admitted.peer(), authenticated.peer);
    assert_eq!(admitted.wire_deadline(), requested_wire_deadline);
    assert!(admitted.deadline() > after_admission);
    assert!(admitted.deadline() <= requested_deadline);
    assert_eq!(admitted.policy_id(), b"com.example.receiver");
    assert_eq!(admitted.target_identity(), TARGET_IDENTITY);
    assert_eq!(
        admitted.arguments(),
        &[b"receiver".to_vec(), b"--mode=test".to_vec()]
    );
    assert_eq!(admitted.environment()[0].key(), b"LANG");
    assert_eq!(admitted.environment()[0].value(), b"C");
    assert_eq!(
        admitted.launcher_parts_for_permit().deadline.wire(),
        requested_wire_deadline
    );

    assert_eq!(
        authenticated
            .connection
            .receive_spawn(message(authenticated.peer, &spawn)),
        Err(SupervisorWireError::StateViolation)
    );
    assert!(authenticated.connection.is_poisoned());
}

#[test]
fn transport_delay_never_restarts_or_extends_the_absolute_deadline() {
    let mut fixture = Fixture::new();
    fixture.authenticate();
    let requested_deadline = Instant::now() + Duration::from_millis(40);
    let bounded_request = SpawnRequest::new(
        SupervisorDeadline::from_instant(requested_deadline).unwrap(),
        b"com.example.receiver".to_vec(),
        vec![],
        vec![],
    )
    .unwrap();
    let spawn = fixture.spawn_wire(&bounded_request);
    std::thread::sleep(Duration::from_millis(10));
    let admitted = fixture
        .connection
        .receive_spawn(message(fixture.peer, &spawn))
        .unwrap();
    assert!(admitted.deadline.local() <= requested_deadline);
    assert!(admitted.deadline.local() > Instant::now());

    let mut expired = Fixture::new();
    expired.authenticate();
    let mut expired_wire = expired.spawn_wire(&request());
    expired_wire[HEADER_LEN..HEADER_LEN + 8].copy_from_slice(
        &monotonic_now_nanos()
            .unwrap()
            .saturating_sub(1)
            .to_le_bytes(),
    );
    assert_eq!(
        expired
            .connection
            .receive_spawn(message(expired.peer, &expired_wire)),
        Err(SupervisorWireError::LimitExceeded)
    );
    assert!(expired.connection.is_poisoned());

    let mut too_far = Fixture::new();
    too_far.authenticate();
    let mut future_wire = too_far.spawn_wire(&request());
    let maximum_nanos = u64::try_from(MAX_SUPERVISOR_DEADLINE.as_nanos()).unwrap();
    let future = monotonic_now_nanos()
        .unwrap()
        .checked_add(maximum_nanos)
        .and_then(|value| value.checked_add(1_000_000_000))
        .unwrap();
    future_wire[HEADER_LEN..HEADER_LEN + 8].copy_from_slice(&future.to_le_bytes());
    assert_eq!(
        too_far
            .connection
            .receive_spawn(message(too_far.peer, &future_wire)),
        Err(SupervisorWireError::LimitExceeded)
    );
    assert!(too_far.connection.is_poisoned());
}

#[test]
fn wire_deadline_selects_rust_instants_darwin_uptime_clock() {
    // Rust's Darwin std::time implementation selects CLOCK_UPTIME_RAW (8).
    // Keep the transcribed public Darwin ABI value explicit without a
    // scheduler-sensitive elapsed-time comparison.
    assert_eq!(CLOCK_UPTIME_RAW, 8);
    assert!(monotonic_now_nanos().unwrap() > 0);
}

#[test]
fn every_hello_truncation_extra_byte_and_peer_substitution_poison() {
    let hello = encode_client_hello(CLIENT_NONCE).unwrap();
    for length in 0..hello.len() {
        let mut fixture = Fixture::new();
        assert!(
            fixture
                .connection
                .receive_client_hello(message(fixture.peer, &hello[..length]))
                .is_err()
        );
        assert!(fixture.connection.is_poisoned());
    }

    let mut extra = hello.clone();
    extra.push(0);
    let mut fixture = Fixture::new();
    assert!(
        fixture
            .connection
            .receive_client_hello(message(fixture.peer, &extra))
            .is_err()
    );

    let mut fixture = Fixture::new();
    let other = Fixture::new();
    assert_eq!(
        fixture
            .connection
            .receive_client_hello(message(other.peer, &hello)),
        Err(SupervisorWireError::PeerMismatch)
    );
}

#[test]
fn wrong_generation_nonces_and_sequence_cannot_poison_a_live_connection() {
    for offset in [16, 24, 32, 64] {
        let mut fixture = Fixture::new();
        fixture.authenticate();
        let mut mutated = fixture.spawn_wire(&request());
        mutated[offset] ^= 0xff;
        assert_eq!(
            fixture
                .connection
                .receive_spawn(message(fixture.peer, &mutated)),
            Err(SupervisorWireError::ReplayOrSubstitution)
        );
        assert!(!fixture.connection.is_poisoned());
        let exact = fixture.spawn_wire(&request());
        assert!(
            fixture
                .connection
                .receive_spawn(message(fixture.peer, &exact))
                .is_ok()
        );
    }
}

#[test]
fn complete_audit_token_change_cannot_cross_the_authenticated_connection() {
    let mut fixture = Fixture::new();
    fixture.authenticate();
    // SAFETY: this deliberately models a second exact message whose complete
    // audit token changed while all snapshot-like facts remained identical.
    let changed_audit = unsafe {
        VerifiedPeer::from_test_authenticated_message(
            fixture.connection.connection_identity(),
            [0x99; 32],
            501,
            20,
            CLIENT_IDENTITY,
        )
        .unwrap()
    };
    let spawn = fixture.spawn_wire(&request());
    assert_eq!(
        fixture
            .connection
            .receive_spawn(message(changed_audit, &spawn)),
        Err(SupervisorWireError::PeerMismatch)
    );
    assert!(!fixture.connection.is_poisoned());
    assert!(
        fixture
            .connection
            .receive_spawn(message(fixture.peer, &spawn))
            .is_ok()
    );
}

#[test]
fn policy_identifier_cannot_be_a_path_or_implicit_target() {
    for policy in [
        b"".as_slice(),
        b".",
        b"..",
        b"../target",
        b"/tmp/target",
        b"a/b",
    ] {
        assert_eq!(
            SpawnRequest::new(
                deadline_after(Duration::from_secs(1)),
                policy.to_vec(),
                vec![],
                vec![],
            ),
            Err(SupervisorWireError::InvalidPolicy)
        );
    }
}

#[test]
fn loader_private_and_routing_environment_are_rejected() {
    for key in [
        b"DYLD_INSERT_LIBRARIES".as_slice(),
        b"LD_LIBRARY_PATH",
        b"__XPC_FOO",
        b"XPC_SERVICE_NAME",
        b"NATIVE_IPC_MACH_NONCE",
        b"lowercase",
        b"BAD=KEY",
    ] {
        assert_eq!(
            TargetEnvironmentEntry::new(key.to_vec(), b"value".to_vec()),
            Err(SupervisorWireError::InvalidTargetInput)
        );
    }
    assert_eq!(
        TargetEnvironmentEntry::new(b"LANG".to_vec(), b"bad\0value".to_vec()),
        Err(SupervisorWireError::InvalidTargetInput)
    );
}

#[test]
fn spawn_payload_is_exact_bounded_and_rejects_reserved_or_trailing_bytes() {
    let template = Fixture::new();
    let canonical = template.spawn_wire(&request());
    for length in HEADER_LEN..canonical.len() {
        let mut truncated = canonical[..length].to_vec();
        let payload_len = u32::try_from(length - HEADER_LEN).unwrap();
        truncated[12..16].copy_from_slice(&payload_len.to_le_bytes());
        let mut fixture = Fixture::new();
        fixture.authenticate();
        // Rebind the structurally truncated payload to this fresh connection.
        truncated[16..24].copy_from_slice(&fixture.generation.to_le_bytes());
        truncated[64..96].copy_from_slice(&fixture.service_nonce);
        assert!(
            fixture
                .connection
                .receive_spawn(message(fixture.peer, &truncated))
                .is_err()
        );
    }

    let mut fixture = Fixture::new();
    fixture.authenticate();
    let mut reserved = fixture.spawn_wire(&request());
    reserved[HEADER_LEN + 14] = 1;
    assert!(
        fixture
            .connection
            .receive_spawn(message(fixture.peer, &reserved))
            .is_err()
    );

    let mut fixture = Fixture::new();
    fixture.authenticate();
    let mut trailing = fixture.spawn_wire(&request());
    trailing.push(0);
    let payload_len = u32::try_from(trailing.len() - HEADER_LEN).unwrap();
    trailing[12..16].copy_from_slice(&payload_len.to_le_bytes());
    assert_eq!(
        fixture
            .connection
            .receive_spawn(message(fixture.peer, &trailing)),
        Err(SupervisorWireError::Malformed)
    );
}

#[test]
fn root_sentinel_zero_identity_and_unbounded_inputs_are_unrepresentable() {
    let fixture = Fixture::new();
    for (audit, uid, gid, identity) in [
        ([0; 32], 501, 20, [1; 32]),
        ([1; 32], 0, 20, [1; 32]),
        ([1; 32], 501, 0, [1; 32]),
        ([1; 32], u32::MAX, 20, [1; 32]),
        ([1; 32], 501, u32::MAX, [1; 32]),
        ([1; 32], 501, 20, [0; 32]),
    ] {
        // SAFETY: this test intentionally supplies rejected modeled audit facts.
        assert_eq!(
            unsafe {
                VerifiedPeer::from_test_authenticated_message(
                    fixture.connection.connection_identity(),
                    audit,
                    uid,
                    gid,
                    identity,
                )
            },
            Err(SupervisorWireError::PeerMismatch)
        );
    }
    // SAFETY: these tests intentionally supply rejected freshness values.
    assert_eq!(
        unsafe { ConnectionGeneration::from_unique_service_value(0) },
        Err(SupervisorWireError::ReplayOrSubstitution)
    );
    // SAFETY: these tests intentionally supply rejected freshness values.
    assert_eq!(
        unsafe { FreshServiceNonce::from_fresh_random([0; 32]) },
        Err(SupervisorWireError::ReplayOrSubstitution)
    );

    assert_eq!(
        SupervisorDeadline::from_instant(
            Instant::now() + MAX_SUPERVISOR_DEADLINE + Duration::from_secs(1)
        ),
        Err(SupervisorWireError::LimitExceeded)
    );
    assert_eq!(
        SupervisorDeadline::from_instant(Instant::now()),
        Err(SupervisorWireError::LimitExceeded)
    );
    assert_eq!(
        SpawnRequest::new(
            deadline_after(Duration::from_secs(1)),
            b"policy".to_vec(),
            vec![Vec::new(); MAX_ARGUMENTS],
            vec![]
        ),
        Err(SupervisorWireError::LimitExceeded)
    );
    assert_eq!(
        SpawnRequest::new(
            deadline_after(Duration::from_secs(1)),
            b"policy".to_vec(),
            vec![vec![b'a'; MAX_COMPONENT_BYTES + 1]],
            vec![]
        ),
        Err(SupervisorWireError::InvalidTargetInput)
    );
}

#[test]
fn installed_catalog_is_unique_and_enforces_client_argv_and_environment() {
    let duplicate = vec![policy_definition(), policy_definition()];
    // SAFETY: tests model a malformed installed catalog to prove rejection.
    assert!(unsafe { InstalledPolicyCatalog::from_verified_installation(duplicate) }.is_err());

    let cases = [
        (
            SpawnRequest::new(
                deadline_after(Duration::from_secs(1)),
                b"com.example.other".to_vec(),
                vec![],
                vec![],
            )
            .unwrap(),
            SupervisorWireError::InvalidPolicy,
        ),
        (
            SpawnRequest::new(
                deadline_after(Duration::from_secs(1)),
                b"com.example.receiver".to_vec(),
                vec![],
                vec![TargetEnvironmentEntry::new(b"HOME".to_vec(), b"/tmp".to_vec()).unwrap()],
            )
            .unwrap(),
            SupervisorWireError::InvalidTargetInput,
        ),
        (
            SpawnRequest::new(
                deadline_after(Duration::from_secs(1)),
                b"com.example.receiver".to_vec(),
                vec![],
                vec![
                    TargetEnvironmentEntry::new(b"LANG".to_vec(), b"C".to_vec()).unwrap(),
                    TargetEnvironmentEntry::new(b"LANG".to_vec(), b"POSIX".to_vec()).unwrap(),
                ],
            )
            .unwrap(),
            SupervisorWireError::InvalidTargetInput,
        ),
        (
            SpawnRequest::new(
                deadline_after(Duration::from_secs(1)),
                b"com.example.receiver".to_vec(),
                vec![Vec::new(); 5],
                vec![],
            )
            .unwrap(),
            SupervisorWireError::InvalidTargetInput,
        ),
    ];
    for (request, expected) in cases {
        let mut fixture = Fixture::new();
        fixture.authenticate();
        let wire = fixture.spawn_wire(&request);
        assert_eq!(
            fixture
                .connection
                .receive_spawn(message(fixture.peer, &wire))
                .unwrap()
                .validate(&catalog()),
            Err(expected)
        );
    }

    let wrong_client_definition = TargetPolicyDefinition::new(
        b"com.example.receiver".to_vec(),
        [0x99; 32],
        TARGET_IDENTITY,
        b"/example/NativeIPC.app/Contents/Helpers/receiver".to_vec(),
        b"receiver".to_vec(),
        4,
        vec![b"LANG".to_vec()],
    )
    .unwrap();
    // SAFETY: tests model a second immutable installed policy resource.
    let wrong_client_catalog = unsafe {
        InstalledPolicyCatalog::from_verified_installation(vec![wrong_client_definition])
    }
    .unwrap();
    let mut fixture = Fixture::new();
    fixture.authenticate();
    let wire = fixture.spawn_wire(&request());
    assert_eq!(
        fixture
            .connection
            .receive_spawn(message(fixture.peer, &wire))
            .unwrap()
            .validate(&wrong_client_catalog),
        Err(SupervisorWireError::PeerMismatch)
    );
}
