//! Bounded, effect-ordered wire contract for the future same-user supervisor.
//!
//! This module deliberately contains no Mach transport, process, filesystem,
//! or signal operations. Platform adapters must authenticate each received
//! Mach message's audit trailer before constructing [`VerifiedMessage`], and
//! only a successfully validated
//! [`ValidatedSpawn`] may reach the fixed-policy launcher path.

use std::collections::HashSet;
use std::ffi::{CStr, CString, c_int, c_long};
use std::time::{Duration, Instant};

const MAGIC: [u8; 8] = *b"NIPCSUP1";
const VERSION: u16 = 1;
const HEADER_LEN: usize = 96;
const SPAWN_PREFIX_LEN: usize = 16;
const SPAWN_RESULT_LEN: usize = 40;
// Rust's Darwin `Instant` uses CLOCK_UPTIME_RAW, which is also the
// nanosecond-converted `mach_absolute_time` clock used for kernel deadlines.
const CLOCK_UPTIME_RAW: c_int = 8;

pub(super) const MAX_SUPERVISOR_RECORD_BYTES: usize = 64 * 1024;
pub(super) const MAX_POLICY_ID_BYTES: usize = 128;
pub(super) const MAX_ARGUMENTS: usize = 64;
pub(super) const MAX_ENVIRONMENT: usize = 64;
pub(super) const MAX_COMPONENT_BYTES: usize = 4096;
pub(super) const MAX_SUPERVISOR_DEADLINE: Duration = Duration::from_secs(30);

/// Copies one deployer-owned absolute helper path into an installation-bound
/// value. Request data never reaches this boundary.
pub(in crate::backend::macos::supervisor) fn deployer_helper_path(path: &CStr) -> Option<CString> {
    is_deployer_helper_path(path).then(|| path.to_owned())
}

pub(in crate::backend::macos::supervisor) fn is_deployer_helper_path(path: &CStr) -> bool {
    let bytes = path.to_bytes();
    bytes.len() > 1 && bytes.first() == Some(&b'/')
}

#[repr(C)]
struct TimeSpec {
    tv_sec: c_long,
    tv_nsec: c_long,
}

unsafe extern "C" {
    fn clock_gettime(clock_id: c_int, time: *mut TimeSpec) -> c_int;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
enum RecordKind {
    ClientHello = 1,
    ServiceHello = 2,
    Spawn = 3,
    SpawnResult = 4,
}

impl RecordKind {
    fn decode(value: u16) -> Result<Self, SupervisorWireError> {
        match value {
            1 => Ok(Self::ClientHello),
            2 => Ok(Self::ServiceHello),
            3 => Ok(Self::Spawn),
            4 => Ok(Self::SpawnResult),
            _ => Err(SupervisorWireError::Malformed),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Header {
    kind: RecordKind,
    payload_len: usize,
    generation: u64,
    sequence: u64,
    client_nonce: [u8; 32],
    service_nonce: [u8; 32],
}

/// Failure while validating the bounded same-user supervisor protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SupervisorWireError {
    /// The message was truncated, noncanonical, or used an unknown kind.
    Malformed,
    /// The message exceeded a protocol bound.
    LimitExceeded,
    /// An effect-bearing message arrived before mutual authentication.
    AuthenticationRequired,
    /// The message came from another authenticated connection identity.
    PeerMismatch,
    /// A nonce, connection generation, or sequence did not match.
    ReplayOrSubstitution,
    /// A caller-controlled target policy identifier was not canonical.
    InvalidPolicy,
    /// An argv or environment component was invalid or privilege-bearing.
    InvalidTargetInput,
    /// This connection already consumed its one permitted spawn request.
    StateViolation,
    /// The shared monotonic clock could not supply a trustworthy timestamp.
    ClockUnavailable,
}

/// Absolute deadline on the system-wide monotonic clock shared by processes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SupervisorDeadline(u64);

impl SupervisorDeadline {
    /// Converts a caller deadline once, conservatively, before transport.
    pub(super) fn from_instant(deadline: Instant) -> Result<Self, SupervisorWireError> {
        // Capture the shared clock first so time spent sampling `Instant` can
        // only shorten, never extend, the transmitted authority window.
        let monotonic_now = monotonic_now_nanos()?;
        let local_now = Instant::now();
        let remaining = deadline
            .checked_duration_since(local_now)
            .ok_or(SupervisorWireError::LimitExceeded)?;
        if remaining.is_zero() || remaining > MAX_SUPERVISOR_DEADLINE {
            return Err(SupervisorWireError::LimitExceeded);
        }
        let remaining_nanos =
            u64::try_from(remaining.as_nanos()).map_err(|_| SupervisorWireError::LimitExceeded)?;
        monotonic_now
            .checked_add(remaining_nanos)
            .map(Self)
            .ok_or(SupervisorWireError::LimitExceeded)
    }

    fn from_wire(value: u64) -> Self {
        Self(value)
    }

    /// Returns the earlier authority boundary without sampling either clock.
    pub(super) const fn earlier(self, other: Self) -> Self {
        if self.0 <= other.0 { self } else { other }
    }

    fn to_local_instant(self) -> Result<Instant, SupervisorWireError> {
        // Capture `Instant` first so time spent sampling the shared clock can
        // only shorten, never extend, the local authority window.
        let local_now = Instant::now();
        let monotonic_now = monotonic_now_nanos()?;
        let remaining_nanos = self
            .0
            .checked_sub(monotonic_now)
            .ok_or(SupervisorWireError::LimitExceeded)?;
        let remaining = Duration::from_nanos(remaining_nanos);
        if remaining.is_zero() || remaining > MAX_SUPERVISOR_DEADLINE {
            return Err(SupervisorWireError::LimitExceeded);
        }
        local_now
            .checked_add(remaining)
            .ok_or(SupervisorWireError::LimitExceeded)
    }

    const fn wire_value(self) -> u64 {
        self.0
    }
}

mod deadline_binding {
    use super::{Instant, SupervisorDeadline, SupervisorWireError};

    /// Inseparable original wire deadline and its conservative local view.
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    pub(in crate::backend::macos) struct SupervisorDeadlineBinding {
        wire: SupervisorDeadline,
        local: Instant,
    }

    impl SupervisorDeadlineBinding {
        pub(in crate::backend::macos) fn from_wire(
            wire: SupervisorDeadline,
        ) -> Result<Self, SupervisorWireError> {
            Ok(Self {
                wire,
                local: wire.to_local_instant()?,
            })
        }

        pub(in crate::backend::macos) const fn wire(self) -> SupervisorDeadline {
            self.wire
        }

        pub(in crate::backend::macos) const fn local(self) -> Instant {
            self.local
        }

        #[cfg(test)]
        pub(in crate::backend::macos) fn from_test_instant(
            deadline: Instant,
        ) -> Result<Self, SupervisorWireError> {
            Self::from_wire(SupervisorDeadline::from_instant(deadline)?)
        }
    }
}

pub(super) use deadline_binding::SupervisorDeadlineBinding;

fn monotonic_now_nanos() -> Result<u64, SupervisorWireError> {
    let mut time = TimeSpec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: `time` is a valid writable `timespec`, and CLOCK_UPTIME_RAW is
    // the public Darwin clock shared by processes and Rust's `Instant`.
    if unsafe { clock_gettime(CLOCK_UPTIME_RAW, &raw mut time) } != 0
        || time.tv_sec < 0
        || !(0..1_000_000_000).contains(&time.tv_nsec)
    {
        return Err(SupervisorWireError::ClockUnavailable);
    }
    let seconds = u64::try_from(time.tv_sec).map_err(|_| SupervisorWireError::ClockUnavailable)?;
    let nanoseconds =
        u64::try_from(time.tv_nsec).map_err(|_| SupervisorWireError::ClockUnavailable)?;
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or(SupervisorWireError::ClockUnavailable)
}

/// Service-lifetime-unique identity for one accepted transport connection.
#[derive(Debug, Eq, PartialEq)]
pub(super) struct ConnectionGeneration(u64);

impl ConnectionGeneration {
    /// # Safety
    ///
    /// `value` must be nonzero and never reused during this service instance.
    pub(super) const unsafe fn from_unique_service_value(
        value: u64,
    ) -> Result<Self, SupervisorWireError> {
        if value == 0 {
            Err(SupervisorWireError::ReplayOrSubstitution)
        } else {
            Ok(Self(value))
        }
    }

    const fn into_identity(self) -> ConnectionIdentity {
        ConnectionIdentity(self.0)
    }
}

/// Copyable identity derived by consuming one fresh connection generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ConnectionIdentity(u64);

impl ConnectionIdentity {
    pub(super) const fn get(self) -> u64 {
        self.0
    }
}

/// Opaque client-visible session identifier carrying no process authority.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct OpaqueSessionHandle([u8; 32]);

impl OpaqueSessionHandle {
    pub(super) const fn bytes(self) -> [u8; 32] {
        self.0
    }
}

impl std::fmt::Debug for OpaqueSessionHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("OpaqueSessionHandle(..)")
    }
}

/// Coarse spawn failure that reveals no PID, signal, path, or native status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub(super) enum SpawnFailure {
    Denied = 1,
    Busy = 2,
    DeadlineExpired = 3,
    LaunchFailed = 4,
}

impl SpawnFailure {
    fn decode(value: u16) -> Result<Self, SupervisorWireError> {
        match value {
            1 => Ok(Self::Denied),
            2 => Ok(Self::Busy),
            3 => Ok(Self::DeadlineExpired),
            4 => Ok(Self::LaunchFailed),
            _ => Err(SupervisorWireError::Malformed),
        }
    }
}

/// Canonical authenticated result of one spawn request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DecodedSpawnResult {
    Ready(OpaqueSessionHandle),
    Rejected(SpawnFailure),
}

/// Fresh unpredictable service nonce used by exactly one connection.
#[derive(Debug, Eq, PartialEq)]
pub(super) struct FreshServiceNonce([u8; 32]);

impl FreshServiceNonce {
    /// # Safety
    ///
    /// `value` must come from the OS CSPRNG and must not be reused by this
    /// service instance.
    pub(super) unsafe fn from_fresh_random(value: [u8; 32]) -> Result<Self, SupervisorWireError> {
        if value == [0; 32] {
            Err(SupervisorWireError::ReplayOrSubstitution)
        } else {
            Ok(Self(value))
        }
    }

    pub(super) const fn get(&self) -> [u8; 32] {
        self.0
    }
}

/// Code and credential facts derived from one exact Mach audit trailer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct VerifiedPeer {
    connection_identity: ConnectionIdentity,
    audit_identity: [u8; 32],
    effective_uid: u32,
    effective_gid: u32,
    code_identity: [u8; 32],
}

impl VerifiedPeer {
    /// Constructs facts only after the platform adapter has verified the
    /// audit-token-derived dynamic code against its installed requirement.
    ///
    /// # Safety
    ///
    /// `code_identity`, UID, and GID must derive from the same exact received
    /// Mach message's kernel audit trailer. Code must be validated through
    /// `kSecGuestAttributeAudit`; UID and GID must be decoded from that same
    /// token, not a connection-time snapshot. `connection_identity` must be
    /// fresh service state created after an authenticated hello, or the exact
    /// existing generation selected from an authenticated spawn envelope.
    /// The adapter must also establish that the UID is an authorized non-system
    /// client identity under the installed product policy.
    unsafe fn from_authenticated_message_audit_token(
        connection_identity: ConnectionIdentity,
        audit_identity: [u8; 32],
        effective_uid: u32,
        effective_gid: u32,
        code_identity: [u8; 32],
    ) -> Result<Self, SupervisorWireError> {
        if audit_identity == [0; 32]
            || effective_uid == 0
            || effective_gid == 0
            || effective_uid == u32::MAX
            || effective_gid == u32::MAX
            || code_identity == [0; 32]
        {
            return Err(SupervisorWireError::PeerMismatch);
        }
        Ok(Self {
            connection_identity,
            audit_identity,
            effective_uid,
            effective_gid,
            code_identity,
        })
    }

    #[cfg(test)]
    pub(super) unsafe fn from_test_authenticated_message(
        connection_identity: ConnectionIdentity,
        audit_identity: [u8; 32],
        effective_uid: u32,
        effective_gid: u32,
        code_identity: [u8; 32],
    ) -> Result<Self, SupervisorWireError> {
        // SAFETY: this test-only seam models the fused Mach/Security boundary
        // and supplies all facts from one synthetic exact message.
        unsafe {
            Self::from_authenticated_message_audit_token(
                connection_identity,
                audit_identity,
                effective_uid,
                effective_gid,
                code_identity,
            )
        }
    }

    pub(super) const fn connection_generation(self) -> u64 {
        self.connection_identity.get()
    }

    pub(super) const fn connection_identity(self) -> ConnectionIdentity {
        self.connection_identity
    }

    pub(super) const fn effective_uid(self) -> u32 {
        self.effective_uid
    }

    pub(super) const fn effective_gid(self) -> u32 {
        self.effective_gid
    }
}

/// Bytes whose exact Mach message audit trailer has passed authentication.
pub(super) struct VerifiedMessage<'a> {
    peer: VerifiedPeer,
    bytes: &'a [u8],
}

impl<'a> VerifiedMessage<'a> {
    /// Wraps bytes after the platform adapter authenticates that exact received
    /// Mach message, rather than a PID or earlier connection snapshot.
    ///
    /// # Safety
    ///
    /// `peer` must have been derived from the same received Mach message that
    /// supplied `bytes`.
    unsafe fn from_authenticated_message_audit_token(peer: VerifiedPeer, bytes: &'a [u8]) -> Self {
        Self { peer, bytes }
    }

    #[cfg(test)]
    pub(super) unsafe fn from_test_authenticated_message(
        peer: VerifiedPeer,
        bytes: &'a [u8],
    ) -> Self {
        // SAFETY: this test-only seam binds the synthetic exact-message peer
        // to these exact modeled receive bytes.
        unsafe { Self::from_authenticated_message_audit_token(peer, bytes) }
    }
}

/// One environment entry delivered only after the launcher drops privilege.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct TargetEnvironmentEntry {
    key: Vec<u8>,
    value: Vec<u8>,
}

impl TargetEnvironmentEntry {
    pub(super) fn new(key: Vec<u8>, value: Vec<u8>) -> Result<Self, SupervisorWireError> {
        validate_environment_key(&key)?;
        validate_component(&value)?;
        Ok(Self { key, value })
    }

    pub(super) fn key(&self) -> &[u8] {
        &self.key
    }

    pub(super) fn value(&self) -> &[u8] {
        &self.value
    }
}

/// Canonical target request containing no executable path or process authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct SpawnRequest {
    deadline: SupervisorDeadline,
    policy_id: Vec<u8>,
    arguments: Vec<Vec<u8>>,
    environment: Vec<TargetEnvironmentEntry>,
}

impl SpawnRequest {
    pub(super) fn new(
        deadline: SupervisorDeadline,
        policy_id: Vec<u8>,
        arguments: Vec<Vec<u8>>,
        environment: Vec<TargetEnvironmentEntry>,
    ) -> Result<Self, SupervisorWireError> {
        validate_policy_id(&policy_id)?;
        if arguments.len() >= MAX_ARGUMENTS || environment.len() > MAX_ENVIRONMENT {
            return Err(SupervisorWireError::LimitExceeded);
        }
        for argument in &arguments {
            validate_component(argument)?;
        }
        Ok(Self {
            deadline,
            policy_id,
            arguments,
            environment,
        })
    }

    pub(super) const fn deadline(&self) -> SupervisorDeadline {
        self.deadline
    }

    pub(super) fn policy_id(&self) -> &[u8] {
        &self.policy_id
    }

    pub(super) fn arguments(&self) -> &[Vec<u8>] {
        &self.arguments
    }

    pub(super) fn environment(&self) -> &[TargetEnvironmentEntry] {
        &self.environment
    }
}

/// Authenticated request that still has no authority to select or launch code.
#[derive(Debug, Eq, PartialEq)]
pub(super) struct AuthenticatedSpawnRequest {
    peer: VerifiedPeer,
    deadline: SupervisorDeadlineBinding,
    request: SpawnRequest,
}

impl AuthenticatedSpawnRequest {
    /// Resolves caller input through the immutable installed target catalog.
    pub(super) fn validate(
        self,
        catalog: &InstalledPolicyCatalog,
    ) -> Result<ValidatedSpawn, SupervisorWireError> {
        let policy = catalog
            .resolve(&self.request.policy_id)
            .ok_or(SupervisorWireError::InvalidPolicy)?;
        policy.validate(self)
    }
}

/// Non-authoritative policy data awaiting installed-catalog verification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct TargetPolicyDefinition {
    policy_id: Vec<u8>,
    authorized_client_code_identity: [u8; 32],
    target_identity: [u8; 32],
    installed_executable: Vec<u8>,
    argument0: Vec<u8>,
    maximum_additional_arguments: usize,
    allowed_environment_keys: Vec<Vec<u8>>,
}

impl TargetPolicyDefinition {
    /// `target_identity` must be the nonzero code identity compiled into the
    /// fixed auth worker that evaluates this target's designated requirement.
    /// It is installed policy, never request-selected data.
    pub(super) fn new(
        policy_id: Vec<u8>,
        authorized_client_code_identity: [u8; 32],
        target_identity: [u8; 32],
        installed_executable: Vec<u8>,
        argument0: Vec<u8>,
        maximum_additional_arguments: usize,
        mut allowed_environment_keys: Vec<Vec<u8>>,
    ) -> Result<Self, SupervisorWireError> {
        validate_policy_id(&policy_id)?;
        validate_installed_executable(&installed_executable)?;
        validate_component(&argument0)?;
        if authorized_client_code_identity == [0; 32]
            || target_identity == [0; 32]
            || argument0.is_empty()
            || maximum_additional_arguments >= MAX_ARGUMENTS
            || allowed_environment_keys.len() > MAX_ENVIRONMENT
        {
            return Err(SupervisorWireError::InvalidPolicy);
        }
        for key in &allowed_environment_keys {
            validate_environment_key(key)?;
        }
        allowed_environment_keys.sort_unstable();
        if allowed_environment_keys
            .windows(2)
            .any(|pair| pair[0] == pair[1])
        {
            return Err(SupervisorWireError::InvalidPolicy);
        }
        Ok(Self {
            policy_id,
            authorized_client_code_identity,
            target_identity,
            installed_executable,
            argument0,
            maximum_additional_arguments,
            allowed_environment_keys,
        })
    }
}

/// Immutable deployer-owned catalog that uniquely maps IDs to installed targets.
pub(super) struct InstalledPolicyCatalog {
    policies: Vec<InstalledTargetPolicy>,
}

impl InstalledPolicyCatalog {
    /// Builds the effect-authorizing catalog after verifying its signed,
    /// deployer-owned installation source.
    ///
    /// # Safety
    ///
    /// `definitions` must come from the authenticated immutable installed
    /// policy resource for this exact signed service generation. Every target
    /// path and identity must name the same deployer-owned, replacement-resistant
    /// installed image that the trusted launcher will pass directly to
    /// `execve`; no caller-writable path component or symlink is permitted.
    pub(super) unsafe fn from_verified_installation(
        mut definitions: Vec<TargetPolicyDefinition>,
    ) -> Result<Self, SupervisorWireError> {
        if definitions.is_empty() {
            return Err(SupervisorWireError::InvalidPolicy);
        }
        definitions.sort_unstable_by(|left, right| left.policy_id.cmp(&right.policy_id));
        if definitions
            .windows(2)
            .any(|pair| pair[0].policy_id == pair[1].policy_id)
        {
            return Err(SupervisorWireError::InvalidPolicy);
        }
        Ok(Self {
            policies: definitions
                .into_iter()
                .map(InstalledTargetPolicy::from_definition)
                .collect(),
        })
    }

    fn resolve(&self, policy_id: &[u8]) -> Option<&InstalledTargetPolicy> {
        self.policies
            .binary_search_by(|candidate| candidate.policy_id.as_slice().cmp(policy_id))
            .ok()
            .map(|index| &self.policies[index])
    }
}

/// Root-owned policy mapping one authenticated client to one installed target.
struct InstalledTargetPolicy {
    policy_id: Vec<u8>,
    authorized_client_code_identity: [u8; 32],
    target_identity: [u8; 32],
    installed_executable: Vec<u8>,
    argument0: Vec<u8>,
    maximum_additional_arguments: usize,
    allowed_environment_keys: Vec<Vec<u8>>,
}

impl InstalledTargetPolicy {
    fn from_definition(definition: TargetPolicyDefinition) -> Self {
        Self {
            policy_id: definition.policy_id,
            authorized_client_code_identity: definition.authorized_client_code_identity,
            target_identity: definition.target_identity,
            installed_executable: definition.installed_executable,
            argument0: definition.argument0,
            maximum_additional_arguments: definition.maximum_additional_arguments,
            allowed_environment_keys: definition.allowed_environment_keys,
        }
    }

    fn validate(
        &self,
        authenticated: AuthenticatedSpawnRequest,
    ) -> Result<ValidatedSpawn, SupervisorWireError> {
        if authenticated.request.policy_id != self.policy_id {
            return Err(SupervisorWireError::InvalidPolicy);
        }
        if authenticated.peer.code_identity != self.authorized_client_code_identity {
            return Err(SupervisorWireError::PeerMismatch);
        }
        if authenticated.request.arguments.len() > self.maximum_additional_arguments {
            return Err(SupervisorWireError::InvalidTargetInput);
        }
        let mut seen_environment = HashSet::with_capacity(authenticated.request.environment.len());
        for entry in &authenticated.request.environment {
            if self
                .allowed_environment_keys
                .binary_search_by(|candidate| candidate.as_slice().cmp(entry.key()))
                .is_err()
                || !seen_environment.insert(entry.key())
            {
                return Err(SupervisorWireError::InvalidTargetInput);
            }
        }
        let mut arguments = Vec::with_capacity(authenticated.request.arguments.len() + 1);
        arguments.push(self.argument0.clone());
        arguments.extend(authenticated.request.arguments);
        Ok(ValidatedSpawn {
            peer: authenticated.peer,
            deadline: authenticated.deadline,
            policy_id: self.policy_id.clone(),
            target_identity: self.target_identity,
            installed_executable: self.installed_executable.clone(),
            arguments,
            environment: authenticated.request.environment,
        })
    }
}

/// Effect-capable request admitted by an immutable installed target policy.
#[derive(Debug, Eq, PartialEq)]
pub(super) struct ValidatedSpawn {
    peer: VerifiedPeer,
    deadline: SupervisorDeadlineBinding,
    policy_id: Vec<u8>,
    target_identity: [u8; 32],
    installed_executable: Vec<u8>,
    arguments: Vec<Vec<u8>>,
    environment: Vec<TargetEnvironmentEntry>,
}

impl ValidatedSpawn {
    pub(super) const fn peer(&self) -> VerifiedPeer {
        self.peer
    }

    pub(super) const fn connection_identity(&self) -> ConnectionIdentity {
        self.peer.connection_identity()
    }

    pub(super) const fn deadline(&self) -> Instant {
        self.deadline.local()
    }

    /// Original absolute CLOCK_UPTIME_RAW boundary suitable for exact
    /// cross-exec serialization without reconstructing or extending it.
    pub(super) const fn wire_deadline(&self) -> SupervisorDeadline {
        self.deadline.wire()
    }

    pub(super) fn policy_id(&self) -> &[u8] {
        &self.policy_id
    }

    pub(super) const fn target_identity(&self) -> [u8; 32] {
        self.target_identity
    }

    /// Copies prepared policy data only for a lifetime-branded registered
    /// launch permit. The copied bytes carry no launch authority by themselves.
    pub(super) fn launcher_parts_for_permit(&self) -> LauncherSpawnParts {
        LauncherSpawnParts {
            peer: self.peer,
            deadline: self.deadline,
            policy_id: self.policy_id.clone(),
            target_identity: self.target_identity,
            installed_executable: self.installed_executable.clone(),
            arguments: self.arguments.clone(),
            environment: self.environment.clone(),
        }
    }

    pub(super) fn arguments(&self) -> &[Vec<u8>] {
        &self.arguments
    }

    pub(super) fn environment(&self) -> &[TargetEnvironmentEntry] {
        &self.environment
    }
}

/// Linear installed-policy launch data consumed only by the trusted launcher.
pub(super) struct LauncherSpawnParts {
    pub(super) peer: VerifiedPeer,
    pub(super) deadline: SupervisorDeadlineBinding,
    pub(super) policy_id: Vec<u8>,
    pub(super) target_identity: [u8; 32],
    pub(super) installed_executable: Vec<u8>,
    pub(super) arguments: Vec<Vec<u8>>,
    pub(super) environment: Vec<TargetEnvironmentEntry>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConnectionState {
    AwaitingHello,
    Authenticated {
        client_nonce: [u8; 32],
        peer: VerifiedPeer,
    },
    SpawnConsumed,
    Poisoned,
}

/// Authentication-before-effects state for one transport connection generation.
pub(super) struct SupervisorConnection {
    connection_identity: ConnectionIdentity,
    service_nonce: FreshServiceNonce,
    state: ConnectionState,
}

impl SupervisorConnection {
    pub(super) const fn new(
        generation: ConnectionGeneration,
        service_nonce: FreshServiceNonce,
    ) -> Self {
        Self {
            connection_identity: generation.into_identity(),
            service_nonce,
            state: ConnectionState::AwaitingHello,
        }
    }

    pub(super) const fn connection_identity(&self) -> ConnectionIdentity {
        self.connection_identity
    }

    /// Accepts the authentication-only hello and returns the nonce-bound reply.
    pub(super) fn receive_client_hello(
        &mut self,
        message: VerifiedMessage<'_>,
    ) -> Result<Vec<u8>, SupervisorWireError> {
        if self.state != ConnectionState::AwaitingHello {
            self.state = ConnectionState::Poisoned;
            return Err(SupervisorWireError::StateViolation);
        }
        self.state = ConnectionState::Poisoned;
        self.verify_connection(message.peer)?;
        let header = decode_header(message.bytes)?;
        if header.kind != RecordKind::ClientHello
            || header.payload_len != 0
            || header.generation != 0
            || header.sequence != 0
            || header.client_nonce == [0; 32]
            || header.service_nonce != [0; 32]
            || header.client_nonce == self.service_nonce.get()
        {
            return Err(SupervisorWireError::AuthenticationRequired);
        }
        self.state = ConnectionState::Authenticated {
            client_nonce: header.client_nonce,
            peer: message.peer,
        };
        encode_record(
            Header {
                kind: RecordKind::ServiceHello,
                payload_len: 0,
                generation: self.connection_identity.get(),
                sequence: 0,
                client_nonce: header.client_nonce,
                service_nonce: self.service_nonce.get(),
            },
            &[],
        )
    }

    /// Consumes this connection's single bounded effect-bearing request.
    pub(super) fn receive_spawn(
        &mut self,
        message: VerifiedMessage<'_>,
    ) -> Result<AuthenticatedSpawnRequest, SupervisorWireError> {
        let (client_nonce, peer) = match self.state {
            ConnectionState::AwaitingHello => {
                self.state = ConnectionState::Poisoned;
                return Err(SupervisorWireError::AuthenticationRequired);
            }
            ConnectionState::Authenticated { client_nonce, peer } => (client_nonce, peer),
            ConnectionState::SpawnConsumed | ConnectionState::Poisoned => {
                self.state = ConnectionState::Poisoned;
                return Err(SupervisorWireError::StateViolation);
            }
        };
        if message.peer != peer {
            return Err(SupervisorWireError::PeerMismatch);
        }
        let header = decode_header(message.bytes)?;
        if header.kind != RecordKind::Spawn
            || header.generation != self.connection_identity.get()
            || header.sequence != 1
            || header.client_nonce != client_nonce
            || header.service_nonce != self.service_nonce.get()
        {
            return Err(SupervisorWireError::ReplayOrSubstitution);
        }
        // Only the exact peer with both connection nonces may commit a state
        // transition. Globally routed wrong-peer/wrong-nonce traffic leaves
        // the selected live connection untouched.
        self.state = ConnectionState::Poisoned;
        let request = decode_spawn_payload(&message.bytes[HEADER_LEN..])?;
        let deadline = SupervisorDeadlineBinding::from_wire(request.deadline)?;
        self.state = ConnectionState::SpawnConsumed;
        Ok(AuthenticatedSpawnRequest {
            peer,
            deadline,
            request,
        })
    }

    pub(super) const fn is_poisoned(&self) -> bool {
        matches!(self.state, ConnectionState::Poisoned)
    }

    fn verify_connection(&self, peer: VerifiedPeer) -> Result<(), SupervisorWireError> {
        if peer.connection_identity == self.connection_identity {
            Ok(())
        } else {
            Err(SupervisorWireError::PeerMismatch)
        }
    }
}

pub(super) fn encode_client_hello(client_nonce: [u8; 32]) -> Result<Vec<u8>, SupervisorWireError> {
    if client_nonce == [0; 32] {
        return Err(SupervisorWireError::ReplayOrSubstitution);
    }
    encode_record(
        Header {
            kind: RecordKind::ClientHello,
            payload_len: 0,
            generation: 0,
            sequence: 0,
            client_nonce,
            service_nonce: [0; 32],
        },
        &[],
    )
}

/// Freshness facts accepted from one authentication-only service reply.
pub(super) struct ServiceHelloFacts {
    generation: u64,
    service_nonce: [u8; 32],
}

impl ServiceHelloFacts {
    pub(super) const fn generation(&self) -> u64 {
        self.generation
    }

    pub(super) const fn service_nonce(&self) -> [u8; 32] {
        self.service_nonce
    }
}

/// Validates a service reply against the nonce from this exact client hello.
pub(super) fn decode_service_hello(
    bytes: &[u8],
    expected_client_nonce: [u8; 32],
) -> Result<ServiceHelloFacts, SupervisorWireError> {
    if expected_client_nonce == [0; 32] {
        return Err(SupervisorWireError::ReplayOrSubstitution);
    }
    let header = decode_header(bytes)?;
    if header.kind != RecordKind::ServiceHello
        || header.payload_len != 0
        || header.generation == 0
        || header.sequence != 0
        || header.client_nonce != expected_client_nonce
        || header.service_nonce == [0; 32]
        || header.service_nonce == expected_client_nonce
    {
        return Err(SupervisorWireError::ReplayOrSubstitution);
    }
    Ok(ServiceHelloFacts {
        generation: header.generation,
        service_nonce: header.service_nonce,
    })
}

pub(super) fn encode_spawn_request(
    request: &SpawnRequest,
    generation: u64,
    client_nonce: [u8; 32],
    service_nonce: [u8; 32],
) -> Result<Vec<u8>, SupervisorWireError> {
    if generation == 0 || client_nonce == [0; 32] || service_nonce == [0; 32] {
        return Err(SupervisorWireError::ReplayOrSubstitution);
    }
    let payload = encode_spawn_payload(request)?;
    encode_record(
        Header {
            kind: RecordKind::Spawn,
            payload_len: payload.len(),
            generation,
            sequence: 1,
            client_nonce,
            service_nonce,
        },
        &payload,
    )
}

/// Validates the exact authenticated reply to sequence-one spawn.
pub(super) fn decode_spawn_result(
    bytes: &[u8],
    generation: u64,
    client_nonce: [u8; 32],
    service_nonce: [u8; 32],
) -> Result<DecodedSpawnResult, SupervisorWireError> {
    if generation == 0 || client_nonce == [0; 32] || service_nonce == [0; 32] {
        return Err(SupervisorWireError::ReplayOrSubstitution);
    }
    let header = decode_header(bytes)?;
    if header.kind != RecordKind::SpawnResult
        || header.payload_len != SPAWN_RESULT_LEN
        || header.generation != generation
        || header.sequence != 1
        || header.client_nonce != client_nonce
        || header.service_nonce != service_nonce
    {
        return Err(SupervisorWireError::ReplayOrSubstitution);
    }
    let payload = &bytes[HEADER_LEN..];
    let outcome = u16_at(payload, 0)?;
    let detail = u16_at(payload, 2)?;
    if u32_at(payload, 4)? != 0 {
        return Err(SupervisorWireError::Malformed);
    }
    let handle = array_at::<32>(payload, 8)?;
    match outcome {
        1 if detail == 0 && handle != [0; 32] => {
            Ok(DecodedSpawnResult::Ready(OpaqueSessionHandle(handle)))
        }
        2 if handle == [0; 32] => Ok(DecodedSpawnResult::Rejected(SpawnFailure::decode(detail)?)),
        1 | 2 => Err(SupervisorWireError::Malformed),
        _ => Err(SupervisorWireError::Malformed),
    }
}

fn encode_spawn_result(
    result: Result<[u8; 32], SpawnFailure>,
    generation: u64,
    client_nonce: [u8; 32],
    service_nonce: [u8; 32],
) -> Result<Vec<u8>, SupervisorWireError> {
    if generation == 0 || client_nonce == [0; 32] || service_nonce == [0; 32] {
        return Err(SupervisorWireError::ReplayOrSubstitution);
    }
    let (outcome, detail, handle) = match result {
        Ok(handle) if handle != [0; 32] => (1_u16, 0_u16, handle),
        Ok(_) => return Err(SupervisorWireError::Malformed),
        Err(failure) => (2, failure as u16, [0; 32]),
    };
    let mut payload = Vec::with_capacity(SPAWN_RESULT_LEN);
    payload.extend_from_slice(&outcome.to_le_bytes());
    payload.extend_from_slice(&detail.to_le_bytes());
    payload.extend_from_slice(&0_u32.to_le_bytes());
    payload.extend_from_slice(&handle);
    encode_record(
        Header {
            kind: RecordKind::SpawnResult,
            payload_len: payload.len(),
            generation,
            sequence: 1,
            client_nonce,
            service_nonce,
        },
        &payload,
    )
}

fn encode_ready_spawn_result(
    handle: [u8; 32],
    generation: u64,
    client_nonce: [u8; 32],
    service_nonce: [u8; 32],
) -> Result<Vec<u8>, SupervisorWireError> {
    encode_spawn_result(Ok(handle), generation, client_nonce, service_nonce)
}

#[cfg(test)]
pub(super) fn encode_test_spawn_result(
    result: Result<[u8; 32], SpawnFailure>,
    generation: u64,
    client_nonce: [u8; 32],
    service_nonce: [u8; 32],
) -> Result<Vec<u8>, SupervisorWireError> {
    encode_spawn_result(result, generation, client_nonce, service_nonce)
}

fn encode_record(header: Header, payload: &[u8]) -> Result<Vec<u8>, SupervisorWireError> {
    if header.payload_len != payload.len()
        || HEADER_LEN.saturating_add(payload.len()) > MAX_SUPERVISOR_RECORD_BYTES
    {
        return Err(SupervisorWireError::LimitExceeded);
    }
    let payload_len =
        u32::try_from(payload.len()).map_err(|_| SupervisorWireError::LimitExceeded)?;
    let mut bytes = Vec::with_capacity(HEADER_LEN + payload.len());
    bytes.extend_from_slice(&MAGIC);
    bytes.extend_from_slice(&VERSION.to_le_bytes());
    bytes.extend_from_slice(&(header.kind as u16).to_le_bytes());
    bytes.extend_from_slice(&payload_len.to_le_bytes());
    bytes.extend_from_slice(&header.generation.to_le_bytes());
    bytes.extend_from_slice(&header.sequence.to_le_bytes());
    bytes.extend_from_slice(&header.client_nonce);
    bytes.extend_from_slice(&header.service_nonce);
    debug_assert_eq!(bytes.len(), HEADER_LEN);
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

fn decode_header(bytes: &[u8]) -> Result<Header, SupervisorWireError> {
    if bytes.len() < HEADER_LEN || bytes.len() > MAX_SUPERVISOR_RECORD_BYTES {
        return Err(SupervisorWireError::Malformed);
    }
    if bytes[..8] != MAGIC || u16_at(bytes, 8)? != VERSION {
        return Err(SupervisorWireError::Malformed);
    }
    let payload_len =
        usize::try_from(u32_at(bytes, 12)?).map_err(|_| SupervisorWireError::LimitExceeded)?;
    if HEADER_LEN.checked_add(payload_len) != Some(bytes.len()) {
        return Err(SupervisorWireError::Malformed);
    }
    Ok(Header {
        kind: RecordKind::decode(u16_at(bytes, 10)?)?,
        payload_len,
        generation: u64_at(bytes, 16)?,
        sequence: u64_at(bytes, 24)?,
        client_nonce: array_at(bytes, 32)?,
        service_nonce: array_at(bytes, 64)?,
    })
}

fn encode_spawn_payload(request: &SpawnRequest) -> Result<Vec<u8>, SupervisorWireError> {
    let policy_len =
        u16::try_from(request.policy_id.len()).map_err(|_| SupervisorWireError::LimitExceeded)?;
    let argument_count =
        u16::try_from(request.arguments.len()).map_err(|_| SupervisorWireError::LimitExceeded)?;
    let environment_count =
        u16::try_from(request.environment.len()).map_err(|_| SupervisorWireError::LimitExceeded)?;
    let mut payload = Vec::new();
    payload.extend_from_slice(&request.deadline.wire_value().to_le_bytes());
    payload.extend_from_slice(&policy_len.to_le_bytes());
    payload.extend_from_slice(&argument_count.to_le_bytes());
    payload.extend_from_slice(&environment_count.to_le_bytes());
    payload.extend_from_slice(&0_u16.to_le_bytes());
    payload.extend_from_slice(&request.policy_id);
    for argument in &request.arguments {
        push_component(&mut payload, argument)?;
    }
    for entry in &request.environment {
        push_component(&mut payload, &entry.key)?;
        push_component(&mut payload, &entry.value)?;
    }
    if HEADER_LEN.saturating_add(payload.len()) > MAX_SUPERVISOR_RECORD_BYTES {
        return Err(SupervisorWireError::LimitExceeded);
    }
    Ok(payload)
}

fn decode_spawn_payload(payload: &[u8]) -> Result<SpawnRequest, SupervisorWireError> {
    if payload.len() < SPAWN_PREFIX_LEN {
        return Err(SupervisorWireError::Malformed);
    }
    let deadline = SupervisorDeadline::from_wire(u64_at(payload, 0)?);
    let policy_len = usize::from(u16_at(payload, 8)?);
    let argument_count = usize::from(u16_at(payload, 10)?);
    let environment_count = usize::from(u16_at(payload, 12)?);
    if u16_at(payload, 14)? != 0
        || policy_len > MAX_POLICY_ID_BYTES
        || argument_count > MAX_ARGUMENTS
        || environment_count > MAX_ENVIRONMENT
    {
        return Err(SupervisorWireError::LimitExceeded);
    }
    let mut cursor = PayloadCursor::new(&payload[SPAWN_PREFIX_LEN..]);
    let policy_id = cursor.take(policy_len)?.to_vec();
    let mut arguments = Vec::with_capacity(argument_count);
    for _ in 0..argument_count {
        arguments.push(cursor.component()?.to_vec());
    }
    let mut environment = Vec::with_capacity(environment_count);
    for _ in 0..environment_count {
        environment.push(TargetEnvironmentEntry::new(
            cursor.component()?.to_vec(),
            cursor.component()?.to_vec(),
        )?);
    }
    if !cursor.is_empty() {
        return Err(SupervisorWireError::Malformed);
    }
    SpawnRequest::new(deadline, policy_id, arguments, environment)
}

struct PayloadCursor<'a> {
    remaining: &'a [u8],
}

impl<'a> PayloadCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn take(&mut self, count: usize) -> Result<&'a [u8], SupervisorWireError> {
        if count > self.remaining.len() {
            return Err(SupervisorWireError::Malformed);
        }
        let (value, remaining) = self.remaining.split_at(count);
        self.remaining = remaining;
        Ok(value)
    }

    fn component(&mut self) -> Result<&'a [u8], SupervisorWireError> {
        let length_bytes = self.take(2)?;
        let length = usize::from(u16::from_le_bytes(
            length_bytes
                .try_into()
                .map_err(|_| SupervisorWireError::Malformed)?,
        ));
        if length > MAX_COMPONENT_BYTES {
            return Err(SupervisorWireError::LimitExceeded);
        }
        self.take(length)
    }

    const fn is_empty(&self) -> bool {
        self.remaining.is_empty()
    }
}

fn push_component(payload: &mut Vec<u8>, component: &[u8]) -> Result<(), SupervisorWireError> {
    let length = u16::try_from(component.len()).map_err(|_| SupervisorWireError::LimitExceeded)?;
    payload.extend_from_slice(&length.to_le_bytes());
    payload.extend_from_slice(component);
    Ok(())
}

fn validate_policy_id(policy_id: &[u8]) -> Result<(), SupervisorWireError> {
    if policy_id.is_empty()
        || policy_id.len() > MAX_POLICY_ID_BYTES
        || policy_id == b"."
        || policy_id == b".."
        || !policy_id
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(SupervisorWireError::InvalidPolicy);
    }
    Ok(())
}

fn validate_installed_executable(path: &[u8]) -> Result<(), SupervisorWireError> {
    if path.is_empty()
        || path.len() > MAX_COMPONENT_BYTES
        || path[0] != b'/'
        || path.contains(&0)
        || path
            .split(|byte| *byte == b'/')
            .skip(1)
            .any(|component| component.is_empty() || component == b"." || component == b"..")
    {
        return Err(SupervisorWireError::InvalidPolicy);
    }
    Ok(())
}

fn validate_component(component: &[u8]) -> Result<(), SupervisorWireError> {
    if component.len() > MAX_COMPONENT_BYTES || component.contains(&0) {
        return Err(SupervisorWireError::InvalidTargetInput);
    }
    Ok(())
}

fn validate_environment_key(key: &[u8]) -> Result<(), SupervisorWireError> {
    const FORBIDDEN_PREFIXES: [&[u8]; 5] = [b"DYLD_", b"LD_", b"__XPC_", b"XPC_", b"NATIVE_IPC_"];
    if key.is_empty()
        || key.len() > MAX_COMPONENT_BYTES
        || !key
            .iter()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || *byte == b'_')
        || FORBIDDEN_PREFIXES
            .iter()
            .any(|prefix| key.starts_with(prefix))
    {
        return Err(SupervisorWireError::InvalidTargetInput);
    }
    Ok(())
}

fn u16_at(bytes: &[u8], offset: usize) -> Result<u16, SupervisorWireError> {
    let end = offset
        .checked_add(2)
        .ok_or(SupervisorWireError::Malformed)?;
    Ok(u16::from_le_bytes(
        bytes
            .get(offset..end)
            .ok_or(SupervisorWireError::Malformed)?
            .try_into()
            .map_err(|_| SupervisorWireError::Malformed)?,
    ))
}

fn u32_at(bytes: &[u8], offset: usize) -> Result<u32, SupervisorWireError> {
    let end = offset
        .checked_add(4)
        .ok_or(SupervisorWireError::Malformed)?;
    Ok(u32::from_le_bytes(
        bytes
            .get(offset..end)
            .ok_or(SupervisorWireError::Malformed)?
            .try_into()
            .map_err(|_| SupervisorWireError::Malformed)?,
    ))
}

fn u64_at(bytes: &[u8], offset: usize) -> Result<u64, SupervisorWireError> {
    let end = offset
        .checked_add(8)
        .ok_or(SupervisorWireError::Malformed)?;
    Ok(u64::from_le_bytes(
        bytes
            .get(offset..end)
            .ok_or(SupervisorWireError::Malformed)?
            .try_into()
            .map_err(|_| SupervisorWireError::Malformed)?,
    ))
}

fn array_at<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], SupervisorWireError> {
    let end = offset
        .checked_add(N)
        .ok_or(SupervisorWireError::Malformed)?;
    bytes
        .get(offset..end)
        .ok_or(SupervisorWireError::Malformed)?
        .try_into()
        .map_err(|_| SupervisorWireError::Malformed)
}

#[path = "supervisor_auth_adapter.rs"]
pub(super) mod auth_adapter;

#[path = "supervisor_broker_entry.rs"]
pub(super) mod broker_entry;

#[path = "supervisor_launcher_entry.rs"]
pub(super) mod launcher_entry;

#[path = "supervisor_spawn_primitives.rs"]
mod spawn_primitives;

#[cfg(test)]
#[path = "supervisor_test.rs"]
mod tests;
