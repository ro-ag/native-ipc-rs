//! Canonical cross-exec broker launch-plan frame.

use std::collections::HashSet;
#[cfg(test)]
use std::time::Instant;

use sha2::{Digest, Sha256};

use super::super::{
    MAX_ARGUMENTS, MAX_COMPONENT_BYTES, MAX_ENVIRONMENT, MAX_POLICY_ID_BYTES, SupervisorDeadline,
    SupervisorDeadlineBinding, SupervisorWireError, TargetEnvironmentEntry, validate_component,
    validate_environment_key, validate_installed_executable, validate_policy_id,
};
use super::broker_report::BrokerTraceReportBinding;
use super::{PendingSpawnReply, SessionAssignedSpawn};

const MAGIC: [u8; 8] = *b"NIPCBP01";
const VERSION: u16 = 1;
const HEADER_BYTES: usize = 256;
const LAUNCHER_MAGIC: [u8; 8] = *b"NIPCLP01";
const LAUNCHER_VERSION: u16 = 1;
const LAUNCHER_HEADER_BYTES: usize = 40;
pub(in crate::backend::macos::supervisor) const LAUNCHER_PLAN_PREFIX_BYTES: usize = 24;
pub(in crate::backend::macos::supervisor) const MAX_BROKER_PLAN_BYTES: usize = 80 * 1024;
pub(in crate::backend::macos::supervisor) const BROKER_PLAN_PREFIX_BYTES: usize = 24;
pub(in crate::backend::macos::supervisor) const BROKER_ACK_BYTES: usize = 40;
const ACK_MAGIC: [u8; 8] = *b"NIPCBPA1";
const ACK_DOMAIN: &[u8] = b"native-ipc-macos-broker-plan-ack-v1";

/// Canonical authority-free data staged to one exact dormant broker.
#[derive(Debug, Eq, PartialEq)]
pub(super) struct BrokerLaunchPlan {
    deadline: SupervisorDeadline,
    connection_generation: u64,
    sequence: u64,
    effective_uid: u32,
    effective_gid: u32,
    session: [u8; 32],
    audit_identity: [u8; 32],
    code_identity: [u8; 32],
    target_identity: [u8; 32],
    client_nonce: [u8; 32],
    service_nonce: [u8; 32],
    policy_id: Vec<u8>,
    installed_executable: Vec<u8>,
    arguments: Vec<Vec<u8>>,
    environment: Vec<TargetEnvironmentEntry>,
}

/// Complete authenticated reply/session state plus its immutable staged frame.
#[must_use = "a staged broker spawn retains the exact reply and launch state"]
pub(super) struct StagedBrokerSpawn {
    pending: PendingSpawnReply<SessionAssignedSpawn>,
    frame: Vec<u8>,
}

/// Staging failure that retains the complete unspawned operation.
#[must_use = "a failed staging operation retains its exact reply authority"]
pub(super) struct BrokerPlanStageError {
    pending: PendingSpawnReply<SessionAssignedSpawn>,
    error: SupervisorWireError,
}

/// Structurally valid but still non-authoritative bytes received by a broker.
pub(in crate::backend::macos::supervisor) struct ReceivedBrokerLaunchPlan {
    plan: BrokerLaunchPlan,
    deadline: SupervisorDeadlineBinding,
    digest: [u8; 32],
}

/// Exact-parent FD4 plan whose complete-frame ACK was written before START.
/// This remains authority-free until consumed with the later FD3 activation.
pub(in crate::backend::macos::supervisor) struct AcknowledgedBrokerLaunchPlan {
    plan: BrokerLaunchPlan,
    deadline: SupervisorDeadlineBinding,
    digest: [u8; 32],
}

/// Plan whose acknowledged FD4 staging was followed by exact FD3 activation.
pub(in crate::backend::macos::supervisor) struct ExactParentBrokerLaunchPlan {
    plan: BrokerLaunchPlan,
    deadline: SupervisorDeadlineBinding,
    digest: [u8; 32],
}

/// Authority-free target data decoded by the fixed trusted launcher.
///
/// This type carries no trace, session, Ready, report, or termination proof.
/// Only the broker's retained [`ExactParentBrokerLaunchPlan`] remains
/// authoritative across launcher identity proof and the later exec trap.
pub(in crate::backend::macos::supervisor) struct ReceivedLauncherExecPlan {
    plan: LauncherExecPlan,
    deadline: SupervisorDeadlineBinding,
}

/// Minimal cross-exec launcher data, deliberately disjoint from broker
/// authentication, session, report, and termination state.
struct LauncherExecPlan {
    deadline: SupervisorDeadline,
    effective_uid: u32,
    effective_gid: u32,
    installed_executable: Vec<u8>,
    arguments: Vec<Vec<u8>>,
    environment: Vec<TargetEnvironmentEntry>,
}

/// Owned target inputs prepared from one canonical launcher frame.
pub(in crate::backend::macos::supervisor) struct LauncherExecParts {
    pub(in crate::backend::macos::supervisor) deadline: SupervisorDeadlineBinding,
    pub(in crate::backend::macos::supervisor) effective_uid: u32,
    pub(in crate::backend::macos::supervisor) effective_gid: u32,
    pub(in crate::backend::macos::supervisor) installed_executable: Vec<u8>,
    pub(in crate::backend::macos::supervisor) arguments: Vec<Vec<u8>>,
    pub(in crate::backend::macos::supervisor) environment: Vec<TargetEnvironmentEntry>,
}

pub(in crate::backend::macos::supervisor) struct BrokerPlanPrefix {
    pub(in crate::backend::macos::supervisor) frame_len: usize,
    pub(in crate::backend::macos::supervisor) deadline: SupervisorDeadlineBinding,
}

impl PendingSpawnReply<SessionAssignedSpawn> {
    /// Consumes the complete authenticated/session-assigned operation into its
    /// canonical authority-free frame before any broker child can be created.
    pub(super) fn stage_broker_plan(self) -> Result<StagedBrokerSpawn, Box<BrokerPlanStageError>> {
        let freshness = self.freshness;
        let session = self.output.session.handle();
        let spawn = &self.output.spawn;
        if freshness.generation != freshness.connection.get()
            || freshness.connection != spawn.connection_identity()
            || freshness.sequence != 1
            || freshness.client_nonce == [0; 32]
            || freshness.service_nonce == [0; 32]
            || freshness.client_nonce == freshness.service_nonce
            || self.bound_session != Some(session)
        {
            return Err(Box::new(BrokerPlanStageError {
                pending: self,
                error: SupervisorWireError::ReplayOrSubstitution,
            }));
        }
        let peer = spawn.peer;
        let plan = BrokerLaunchPlan {
            deadline: spawn.wire_deadline(),
            connection_generation: freshness.generation,
            sequence: freshness.sequence,
            effective_uid: peer.effective_uid,
            effective_gid: peer.effective_gid,
            session: session.bytes(),
            audit_identity: peer.audit_identity,
            code_identity: peer.code_identity,
            target_identity: spawn.target_identity,
            client_nonce: freshness.client_nonce,
            service_nonce: freshness.service_nonce,
            policy_id: spawn.policy_id.clone(),
            installed_executable: spawn.installed_executable.clone(),
            arguments: spawn.arguments.clone(),
            environment: spawn.environment.clone(),
        };
        match plan.encode() {
            Ok(frame) => Ok(StagedBrokerSpawn {
                pending: self,
                frame,
            }),
            Err(error) => Err(Box::new(BrokerPlanStageError {
                pending: self,
                error,
            })),
        }
    }
}

impl StagedBrokerSpawn {
    pub(super) fn frame(&self) -> &[u8] {
        &self.frame
    }

    pub(super) fn spawn_installed_broker(
        self,
        image: &super::broker_spawn::InstalledBrokerImage,
        wait_domain: &mut super::DedicatedChildWaitDomain,
    ) -> Result<
        super::broker_spawn::PendingFixedImageBroker,
        Box<PendingSpawnReply<super::broker_spawn::BrokerSpawnError>>,
    > {
        super::broker_spawn::spawn_staged_broker(self, image, wait_domain)
    }

    pub(in crate::backend::macos::supervisor::auth_adapter) fn into_spawn_parts(
        self,
    ) -> (PendingSpawnReply<SessionAssignedSpawn>, Vec<u8>) {
        (self.pending, self.frame)
    }
}

impl BrokerPlanStageError {
    pub(super) fn into_parts(
        self,
    ) -> (PendingSpawnReply<SessionAssignedSpawn>, SupervisorWireError) {
        (self.pending, self.error)
    }
}

impl ReceivedBrokerLaunchPlan {
    /// Parses authority-free bytes and conservatively binds the original
    /// CLOCK_UPTIME_RAW deadline at broker receipt time.
    pub(in crate::backend::macos::supervisor) fn decode(
        bytes: &[u8],
    ) -> Result<Self, SupervisorWireError> {
        let prefix: &[u8; BROKER_PLAN_PREFIX_BYTES] = bytes
            .get(..BROKER_PLAN_PREFIX_BYTES)
            .ok_or(SupervisorWireError::Malformed)?
            .try_into()
            .map_err(|_| SupervisorWireError::Malformed)?;
        let parsed = parse_broker_plan_prefix(prefix, bytes.len())?;
        Self::decode_with_deadline(bytes, parsed.deadline)
    }

    pub(in crate::backend::macos::supervisor) fn decode_with_deadline(
        bytes: &[u8],
        deadline: SupervisorDeadlineBinding,
    ) -> Result<Self, SupervisorWireError> {
        let plan = BrokerLaunchPlan::decode_untrusted(bytes)?;
        if plan.deadline != deadline.wire() {
            return Err(SupervisorWireError::ReplayOrSubstitution);
        }
        Ok(Self {
            plan,
            deadline,
            digest: broker_plan_digest(bytes),
        })
    }

    pub(in crate::backend::macos::supervisor) const fn deadline(
        &self,
    ) -> SupervisorDeadlineBinding {
        self.deadline
    }

    /// Records that the complete-frame ACK was written on the exact inherited
    /// FD4 channel. The resulting data still cannot authorize launch.
    ///
    /// # Safety
    ///
    /// These exact bytes must have arrived on fixed FD4 from this process's
    /// exact parent, and the complete ACK returned by [`broker_plan_ack`] must
    /// have been written before this transition.
    pub(in crate::backend::macos::supervisor) unsafe fn acknowledge_exact_parent(
        self,
    ) -> AcknowledgedBrokerLaunchPlan {
        AcknowledgedBrokerLaunchPlan {
            plan: self.plan,
            deadline: self.deadline,
            digest: self.digest,
        }
    }
}

impl AcknowledgedBrokerLaunchPlan {
    pub(in crate::backend::macos::supervisor) const fn deadline(
        &self,
    ) -> SupervisorDeadlineBinding {
        self.deadline
    }

    /// # Safety
    ///
    /// The caller must consume this value together with the exact FD3 gate's
    /// sole START observation, after ACK completion and with no extra gate byte.
    pub(in crate::backend::macos::supervisor) unsafe fn activate(
        self,
    ) -> ExactParentBrokerLaunchPlan {
        ExactParentBrokerLaunchPlan {
            plan: self.plan,
            deadline: self.deadline,
            digest: self.digest,
        }
    }
}

impl ExactParentBrokerLaunchPlan {
    pub(in crate::backend::macos::supervisor) const fn deadline(
        &self,
    ) -> SupervisorDeadlineBinding {
        self.deadline
    }

    pub(in crate::backend::macos::supervisor) const fn effective_uid(&self) -> u32 {
        self.plan.effective_uid
    }

    pub(in crate::backend::macos::supervisor) const fn effective_gid(&self) -> u32 {
        self.plan.effective_gid
    }

    pub(in crate::backend::macos::supervisor) fn installed_executable(&self) -> &[u8] {
        &self.plan.installed_executable
    }

    #[cfg(test)]
    pub(in crate::backend::macos::supervisor) fn for_launcher_test(
        deadline: Instant,
        effective_uid: u32,
        effective_gid: u32,
        installed_executable: Vec<u8>,
    ) -> Self {
        Self::for_launcher_test_with_arguments(
            deadline,
            effective_uid,
            effective_gid,
            installed_executable,
            vec![b"launcher-fixture".to_vec()],
        )
    }

    /// Like [`Self::for_launcher_test`] but with caller-chosen argv, so a
    /// lifecycle fixture can name a real system target such as `/bin/sleep`.
    #[cfg(test)]
    pub(in crate::backend::macos::supervisor) fn for_launcher_test_with_arguments(
        deadline: Instant,
        effective_uid: u32,
        effective_gid: u32,
        installed_executable: Vec<u8>,
        arguments: Vec<Vec<u8>>,
    ) -> Self {
        let deadline = SupervisorDeadlineBinding::from_test_instant(deadline).unwrap();
        Self {
            plan: BrokerLaunchPlan {
                deadline: deadline.wire(),
                connection_generation: 1,
                sequence: 1,
                effective_uid,
                effective_gid,
                session: [1; 32],
                audit_identity: [2; 32],
                code_identity: [3; 32],
                target_identity: [4; 32],
                client_nonce: [5; 32],
                service_nonce: [6; 32],
                policy_id: b"test.launcher".to_vec(),
                installed_executable,
                arguments,
                environment: Vec::new(),
            },
            deadline,
            digest: [7; 32],
        }
    }

    pub(super) fn into_plan(self) -> BrokerLaunchPlan {
        self.plan
    }

    pub(in crate::backend::macos::supervisor) fn trace_report_binding(
        &self,
    ) -> BrokerTraceReportBinding {
        self.plan.trace_report_binding(self.digest)
    }

    /// Re-encodes the already validated exact-parent plan for the fixed
    /// launcher's authority-free post-trace transport.
    pub(in crate::backend::macos::supervisor) fn launcher_frame(
        &self,
    ) -> Result<Vec<u8>, SupervisorWireError> {
        LauncherExecPlan::from_broker(&self.plan).encode()
    }
}

impl ReceivedLauncherExecPlan {
    /// Decodes one exact canonical frame against the deadline retained from
    /// its previously parsed fixed prefix, without minting launch authority.
    pub(in crate::backend::macos::supervisor) fn decode_with_deadline(
        bytes: &[u8],
        deadline: SupervisorDeadlineBinding,
    ) -> Result<Self, SupervisorWireError> {
        let plan = LauncherExecPlan::decode_untrusted(bytes)?;
        if plan.deadline != deadline.wire() {
            return Err(SupervisorWireError::ReplayOrSubstitution);
        }
        Ok(Self { plan, deadline })
    }

    pub(in crate::backend::macos::supervisor) fn into_parts(self) -> LauncherExecParts {
        LauncherExecParts {
            deadline: self.deadline,
            effective_uid: self.plan.effective_uid,
            effective_gid: self.plan.effective_gid,
            installed_executable: self.plan.installed_executable,
            arguments: self.plan.arguments,
            environment: self.plan.environment,
        }
    }
}

pub(in crate::backend::macos::supervisor) fn parse_launcher_plan_prefix(
    prefix: &[u8; LAUNCHER_PLAN_PREFIX_BYTES],
    outer_len: usize,
) -> Result<BrokerPlanPrefix, SupervisorWireError> {
    if !(LAUNCHER_HEADER_BYTES..=MAX_BROKER_PLAN_BYTES).contains(&outer_len)
        || prefix[..8] != LAUNCHER_MAGIC
        || get_u16(prefix, 8) != Some(LAUNCHER_VERSION)
        || prefix[10..12] != [0; 2]
        || get_u32(prefix, 12) != u32::try_from(outer_len).ok()
    {
        return Err(SupervisorWireError::Malformed);
    }
    let deadline = SupervisorDeadlineBinding::from_wire(SupervisorDeadline::from_wire(
        get_u64(prefix, 16).ok_or(SupervisorWireError::Malformed)?,
    ))?;
    Ok(BrokerPlanPrefix {
        frame_len: outer_len,
        deadline,
    })
}

pub(in crate::backend::macos::supervisor) fn parse_broker_plan_prefix(
    prefix: &[u8; BROKER_PLAN_PREFIX_BYTES],
    outer_len: usize,
) -> Result<BrokerPlanPrefix, SupervisorWireError> {
    if !(HEADER_BYTES..=MAX_BROKER_PLAN_BYTES).contains(&outer_len)
        || prefix[..8] != MAGIC
        || get_u16(prefix, 8) != Some(VERSION)
        || prefix[10..12] != [0; 2]
        || get_u32(prefix, 12) != u32::try_from(outer_len).ok()
    {
        return Err(SupervisorWireError::Malformed);
    }
    let deadline = SupervisorDeadlineBinding::from_wire(SupervisorDeadline::from_wire(
        get_u64(prefix, 16).ok_or(SupervisorWireError::Malformed)?,
    ))?;
    Ok(BrokerPlanPrefix {
        frame_len: outer_len,
        deadline,
    })
}

pub(in crate::backend::macos::supervisor) fn broker_plan_ack(
    frame: &[u8],
) -> [u8; BROKER_ACK_BYTES] {
    let mut ack = [0_u8; BROKER_ACK_BYTES];
    ack[..8].copy_from_slice(&ACK_MAGIC);
    ack[8..].copy_from_slice(&broker_plan_digest(frame));
    ack
}

pub(in crate::backend::macos::supervisor) fn broker_plan_digest(frame: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(ACK_DOMAIN);
    hasher.update(frame);
    hasher.finalize().into()
}

pub(super) fn trace_report_binding_from_frame(
    frame: &[u8],
) -> Result<BrokerTraceReportBinding, SupervisorWireError> {
    let plan = BrokerLaunchPlan::decode_untrusted(frame)?;
    Ok(plan.trace_report_binding(broker_plan_digest(frame)))
}

impl BrokerLaunchPlan {
    fn trace_report_binding(&self, plan_digest: [u8; 32]) -> BrokerTraceReportBinding {
        BrokerTraceReportBinding::new(
            self.deadline,
            self.connection_generation,
            self.sequence,
            self.effective_uid,
            self.effective_gid,
            self.session,
            self.client_nonce,
            self.service_nonce,
            self.target_identity,
            plan_digest,
        )
    }

    fn encode(&self) -> Result<Vec<u8>, SupervisorWireError> {
        self.validate()?;
        let mut bytes = vec![0_u8; HEADER_BYTES];
        bytes[..8].copy_from_slice(&MAGIC);
        put_u16(&mut bytes, 8, VERSION);
        put_u64(&mut bytes, 16, self.deadline.wire_value());
        put_u64(&mut bytes, 24, self.connection_generation);
        put_u64(&mut bytes, 32, self.sequence);
        put_u32(&mut bytes, 40, self.effective_uid);
        put_u32(&mut bytes, 44, self.effective_gid);
        bytes[48..80].copy_from_slice(&self.session);
        bytes[80..112].copy_from_slice(&self.audit_identity);
        bytes[112..144].copy_from_slice(&self.code_identity);
        bytes[144..176].copy_from_slice(&self.target_identity);
        bytes[176..208].copy_from_slice(&self.client_nonce);
        bytes[208..240].copy_from_slice(&self.service_nonce);
        put_u32(&mut bytes, 240, u32_len(&self.policy_id)?);
        put_u32(&mut bytes, 244, u32_len(&self.installed_executable)?);
        put_u16(&mut bytes, 248, u16_len(&self.arguments)?);
        put_u16(&mut bytes, 250, u16_len(&self.environment)?);
        bytes.extend_from_slice(&self.policy_id);
        bytes.extend_from_slice(&self.installed_executable);
        for argument in &self.arguments {
            append_component(&mut bytes, argument)?;
        }
        for entry in &self.environment {
            append_component(&mut bytes, entry.key())?;
            append_component(&mut bytes, entry.value())?;
        }
        if bytes.len() > MAX_BROKER_PLAN_BYTES {
            return Err(SupervisorWireError::LimitExceeded);
        }
        let length = u32_len(&bytes)?;
        put_u32(&mut bytes, 12, length);
        Ok(bytes)
    }

    fn decode_untrusted(bytes: &[u8]) -> Result<Self, SupervisorWireError> {
        if bytes.len() < HEADER_BYTES
            || bytes.len() > MAX_BROKER_PLAN_BYTES
            || bytes[..8] != MAGIC
            || get_u16(bytes, 8) != Some(VERSION)
            || bytes[10..12] != [0; 2]
            || get_u32(bytes, 12) != u32::try_from(bytes.len()).ok()
            || bytes[252..256] != [0; 4]
        {
            return Err(SupervisorWireError::Malformed);
        }
        let policy_len = usize_at(bytes, 240)?;
        let executable_len = usize_at(bytes, 244)?;
        let argument_count =
            usize::from(get_u16(bytes, 248).ok_or(SupervisorWireError::Malformed)?);
        let environment_count =
            usize::from(get_u16(bytes, 250).ok_or(SupervisorWireError::Malformed)?);
        if policy_len > MAX_POLICY_ID_BYTES
            || executable_len > MAX_COMPONENT_BYTES
            || argument_count == 0
            || argument_count > MAX_ARGUMENTS
            || environment_count > MAX_ENVIRONMENT
        {
            return Err(SupervisorWireError::LimitExceeded);
        }
        let mut cursor = HEADER_BYTES;
        let policy_id = take_exact(bytes, &mut cursor, policy_len)?.to_vec();
        let installed_executable = take_exact(bytes, &mut cursor, executable_len)?.to_vec();
        let mut arguments = Vec::with_capacity(argument_count);
        for _ in 0..argument_count {
            arguments.push(take_component(bytes, &mut cursor)?);
        }
        let mut environment = Vec::with_capacity(environment_count);
        for _ in 0..environment_count {
            environment.push(TargetEnvironmentEntry::new(
                take_component(bytes, &mut cursor)?,
                take_component(bytes, &mut cursor)?,
            )?);
        }
        if cursor != bytes.len() {
            return Err(SupervisorWireError::Malformed);
        }
        let plan = Self {
            deadline: SupervisorDeadline::from_wire(
                get_u64(bytes, 16).ok_or(SupervisorWireError::Malformed)?,
            ),
            connection_generation: get_u64(bytes, 24).ok_or(SupervisorWireError::Malformed)?,
            sequence: get_u64(bytes, 32).ok_or(SupervisorWireError::Malformed)?,
            effective_uid: get_u32(bytes, 40).ok_or(SupervisorWireError::Malformed)?,
            effective_gid: get_u32(bytes, 44).ok_or(SupervisorWireError::Malformed)?,
            session: array_at(bytes, 48)?,
            audit_identity: array_at(bytes, 80)?,
            code_identity: array_at(bytes, 112)?,
            target_identity: array_at(bytes, 144)?,
            client_nonce: array_at(bytes, 176)?,
            service_nonce: array_at(bytes, 208)?,
            policy_id,
            installed_executable,
            arguments,
            environment,
        };
        plan.validate()?;
        Ok(plan)
    }

    fn validate(&self) -> Result<(), SupervisorWireError> {
        if self.deadline.wire_value() == 0
            || self.connection_generation == 0
            || self.sequence != 1
            || self.effective_uid == 0
            || self.effective_uid == u32::MAX
            || self.effective_gid == 0
            || self.effective_gid == u32::MAX
            || [
                self.session,
                self.audit_identity,
                self.code_identity,
                self.target_identity,
                self.client_nonce,
                self.service_nonce,
            ]
            .contains(&[0; 32])
            || self.client_nonce == self.service_nonce
            || self.arguments.is_empty()
            || self.arguments.len() > MAX_ARGUMENTS
            || self.environment.len() > MAX_ENVIRONMENT
        {
            return Err(SupervisorWireError::Malformed);
        }
        validate_policy_id(&self.policy_id)?;
        validate_installed_executable(&self.installed_executable)?;
        for argument in &self.arguments {
            validate_component(argument)?;
        }
        let mut keys = HashSet::with_capacity(self.environment.len());
        for entry in &self.environment {
            validate_environment_key(entry.key())?;
            validate_component(entry.value())?;
            if !keys.insert(entry.key()) {
                return Err(SupervisorWireError::InvalidTargetInput);
            }
        }
        Ok(())
    }
}

impl LauncherExecPlan {
    fn from_broker(plan: &BrokerLaunchPlan) -> Self {
        Self {
            deadline: plan.deadline,
            effective_uid: plan.effective_uid,
            effective_gid: plan.effective_gid,
            installed_executable: plan.installed_executable.clone(),
            arguments: plan.arguments.clone(),
            environment: plan.environment.clone(),
        }
    }

    fn encode(&self) -> Result<Vec<u8>, SupervisorWireError> {
        self.validate()?;
        let mut bytes = vec![0_u8; LAUNCHER_HEADER_BYTES];
        bytes[..8].copy_from_slice(&LAUNCHER_MAGIC);
        put_u16(&mut bytes, 8, LAUNCHER_VERSION);
        put_u64(&mut bytes, 16, self.deadline.wire_value());
        put_u32(&mut bytes, 24, self.effective_uid);
        put_u32(&mut bytes, 28, self.effective_gid);
        put_u32(&mut bytes, 32, u32_len(&self.installed_executable)?);
        put_u16(&mut bytes, 36, u16_len(&self.arguments)?);
        put_u16(&mut bytes, 38, u16_len(&self.environment)?);
        bytes.extend_from_slice(&self.installed_executable);
        for argument in &self.arguments {
            append_component(&mut bytes, argument)?;
        }
        for entry in &self.environment {
            append_component(&mut bytes, entry.key())?;
            append_component(&mut bytes, entry.value())?;
        }
        if bytes.len() > MAX_BROKER_PLAN_BYTES {
            return Err(SupervisorWireError::LimitExceeded);
        }
        let length = u32_len(&bytes)?;
        put_u32(&mut bytes, 12, length);
        Ok(bytes)
    }

    fn decode_untrusted(bytes: &[u8]) -> Result<Self, SupervisorWireError> {
        if bytes.len() < LAUNCHER_HEADER_BYTES
            || bytes.len() > MAX_BROKER_PLAN_BYTES
            || bytes[..8] != LAUNCHER_MAGIC
            || get_u16(bytes, 8) != Some(LAUNCHER_VERSION)
            || bytes[10..12] != [0; 2]
            || get_u32(bytes, 12) != u32::try_from(bytes.len()).ok()
        {
            return Err(SupervisorWireError::Malformed);
        }
        let executable_len = usize_at(bytes, 32)?;
        let argument_count = usize::from(get_u16(bytes, 36).ok_or(SupervisorWireError::Malformed)?);
        let environment_count =
            usize::from(get_u16(bytes, 38).ok_or(SupervisorWireError::Malformed)?);
        if executable_len > MAX_COMPONENT_BYTES
            || argument_count == 0
            || argument_count > MAX_ARGUMENTS
            || environment_count > MAX_ENVIRONMENT
        {
            return Err(SupervisorWireError::LimitExceeded);
        }
        let mut cursor = LAUNCHER_HEADER_BYTES;
        let installed_executable = take_exact(bytes, &mut cursor, executable_len)?.to_vec();
        let mut arguments = Vec::with_capacity(argument_count);
        for _ in 0..argument_count {
            arguments.push(take_component(bytes, &mut cursor)?);
        }
        let mut environment = Vec::with_capacity(environment_count);
        for _ in 0..environment_count {
            environment.push(TargetEnvironmentEntry::new(
                take_component(bytes, &mut cursor)?,
                take_component(bytes, &mut cursor)?,
            )?);
        }
        if cursor != bytes.len() {
            return Err(SupervisorWireError::Malformed);
        }
        let plan = Self {
            deadline: SupervisorDeadline::from_wire(
                get_u64(bytes, 16).ok_or(SupervisorWireError::Malformed)?,
            ),
            effective_uid: get_u32(bytes, 24).ok_or(SupervisorWireError::Malformed)?,
            effective_gid: get_u32(bytes, 28).ok_or(SupervisorWireError::Malformed)?,
            installed_executable,
            arguments,
            environment,
        };
        plan.validate()?;
        Ok(plan)
    }

    fn validate(&self) -> Result<(), SupervisorWireError> {
        if self.deadline.wire_value() == 0
            || self.effective_uid == 0
            || self.effective_uid == u32::MAX
            || self.effective_gid == 0
            || self.effective_gid == u32::MAX
            || self.arguments.is_empty()
            || self.arguments.len() > MAX_ARGUMENTS
            || self.environment.len() > MAX_ENVIRONMENT
        {
            return Err(SupervisorWireError::Malformed);
        }
        validate_installed_executable(&self.installed_executable)?;
        for argument in &self.arguments {
            validate_component(argument)?;
        }
        let mut keys = HashSet::with_capacity(self.environment.len());
        for entry in &self.environment {
            validate_environment_key(entry.key())?;
            validate_component(entry.value())?;
            if !keys.insert(entry.key()) {
                return Err(SupervisorWireError::InvalidTargetInput);
            }
        }
        Ok(())
    }
}

fn append_component(bytes: &mut Vec<u8>, component: &[u8]) -> Result<(), SupervisorWireError> {
    bytes.extend_from_slice(&u32_len(component)?.to_le_bytes());
    bytes.extend_from_slice(component);
    Ok(())
}

fn take_component(bytes: &[u8], cursor: &mut usize) -> Result<Vec<u8>, SupervisorWireError> {
    let length_bytes = take_exact(bytes, cursor, 4)?;
    let length = usize::try_from(u32::from_le_bytes(length_bytes.try_into().unwrap()))
        .map_err(|_| SupervisorWireError::LimitExceeded)?;
    Ok(take_exact(bytes, cursor, length)?.to_vec())
}

fn take_exact<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    length: usize,
) -> Result<&'a [u8], SupervisorWireError> {
    let end = cursor
        .checked_add(length)
        .ok_or(SupervisorWireError::LimitExceeded)?;
    let value = bytes
        .get(*cursor..end)
        .ok_or(SupervisorWireError::Malformed)?;
    *cursor = end;
    Ok(value)
}

fn usize_at(bytes: &[u8], offset: usize) -> Result<usize, SupervisorWireError> {
    usize::try_from(get_u32(bytes, offset).ok_or(SupervisorWireError::Malformed)?)
        .map_err(|_| SupervisorWireError::LimitExceeded)
}

fn u32_len(value: &[u8]) -> Result<u32, SupervisorWireError> {
    u32::try_from(value.len()).map_err(|_| SupervisorWireError::LimitExceeded)
}

fn u16_len<T>(value: &[T]) -> Result<u16, SupervisorWireError> {
    u16::try_from(value.len()).map_err(|_| SupervisorWireError::LimitExceeded)
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
fn get_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}
fn get_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}
fn get_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    Some(u64::from_le_bytes(
        bytes.get(offset..offset + 8)?.try_into().ok()?,
    ))
}
fn array_at<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], SupervisorWireError> {
    bytes
        .get(offset..offset + N)
        .and_then(|value| value.try_into().ok())
        .ok_or(SupervisorWireError::Malformed)
}

#[cfg(test)]
#[path = "supervisor_broker_plan_test.rs"]
mod tests;
