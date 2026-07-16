//! Cross-target compilation fixture for the complete consumer type surface.

use native_ipc::active::{AccessError, ActiveReader, ActiveWriter, PrefaultResult};
use native_ipc::batch::{
    ActiveRegionSet, BatchError, ExpectedBatch, ExpectedRegion, TransferBatch,
};
use native_ipc::control::{APPLICATION_CONTROL_KIND_MIN, ControlError, ControlFrame};
use native_ipc::memory::{
    AuthorityMechanism, CleanupPolicy, GrowthPolicy, MemoryAccess, MemoryError, NativeArchitecture,
    NativeMemoryCapabilities, NativePlatform, NativeRegion, NativeShareRequest, PermissionPlan,
    RegionOptions as MemoryRegionOptions, RegionState, RegionStatus, SealPolicy, WriterOwner,
    native_memory_capabilities,
};
use native_ipc::region::{
    GuardCapability, GuardPolicy, PreparedRegion, PrivateRegion, RegionError, RegionId,
    RegionOptions as TransferRegionOptions, RegionSpec, WriterEndpoint,
};
use native_ipc::session::{
    AbsoluteDeadline, ActiveLeaseFacts, AtomicCapabilities, BackendStatus, ChildCleanupFacts,
    ChildExitStatus, Coordinator, CoordinatorAbortOutcome, CoordinatorCloseOutcome,
    CoordinatorSession, DescendantCleanupStatus, ExecutableIdentityPolicy, HARD_MAX_ACTIVE_BYTES,
    HARD_MAX_ACTIVE_REGIONS, HARD_MAX_BATCH_BYTES, HARD_MAX_BOOTSTRAP_PAYLOAD_BYTES,
    HARD_MAX_CONTROL_PAYLOAD_BYTES, HARD_MAX_REGION_BYTES, HARD_MAX_REGIONS_PER_BATCH,
    HARD_MAX_TRANSACTIONS, LeaseFactsConsistency, Negotiating, NegotiationDecision,
    NegotiationError, NegotiationOutcome, PeerStatus, ProtocolVersion, Ready, Receiver,
    ReceiverBootstrap, ReceiverCloseOutcome, ReceiverSession, RejectionReason, Session,
    SessionCommand, SessionEndpoint, SessionError, SessionFailure, SessionLimits, SessionOperation,
    SessionOptions, SessionState, SessionTransactionState, backend_status,
};

fn assert_public_type<T: 'static>() {}

#[test]
fn consumer_type_surface_is_available_on_every_supported_target() {
    assert_public_type::<AccessError>();
    assert_public_type::<ActiveReader>();
    assert_public_type::<ActiveWriter>();
    assert_public_type::<PrefaultResult>();
    assert_public_type::<ActiveRegionSet>();
    assert_public_type::<BatchError>();
    assert_public_type::<ExpectedBatch>();
    assert_public_type::<ExpectedRegion>();
    assert_public_type::<TransferBatch>();
    assert_public_type::<ControlError>();
    assert_public_type::<ControlFrame>();
    assert_public_type::<AuthorityMechanism>();
    assert_public_type::<CleanupPolicy>();
    assert_public_type::<GrowthPolicy>();
    assert_public_type::<MemoryAccess>();
    assert_public_type::<MemoryError>();
    assert_public_type::<NativeArchitecture>();
    assert_public_type::<NativeMemoryCapabilities>();
    assert_public_type::<NativePlatform>();
    assert_public_type::<NativeRegion>();
    assert_public_type::<NativeShareRequest>();
    assert_public_type::<PermissionPlan>();
    assert_public_type::<MemoryRegionOptions>();
    assert_public_type::<RegionState>();
    assert_public_type::<RegionStatus>();
    assert_public_type::<SealPolicy>();
    assert_public_type::<WriterOwner>();
    assert_public_type::<GuardCapability>();
    assert_public_type::<GuardPolicy>();
    assert_public_type::<PreparedRegion>();
    assert_public_type::<PrivateRegion>();
    assert_public_type::<RegionError>();
    assert_public_type::<RegionId>();
    assert_public_type::<TransferRegionOptions>();
    assert_public_type::<RegionSpec>();
    assert_public_type::<WriterEndpoint>();
    assert_public_type::<AbsoluteDeadline>();
    assert_public_type::<ActiveLeaseFacts>();
    assert_public_type::<AtomicCapabilities>();
    assert_public_type::<BackendStatus>();
    assert_public_type::<ChildCleanupFacts>();
    assert_public_type::<ChildExitStatus>();
    assert_public_type::<Coordinator>();
    assert_public_type::<CoordinatorAbortOutcome>();
    assert_public_type::<CoordinatorCloseOutcome>();
    assert_public_type::<CoordinatorSession<Negotiating>>();
    assert_public_type::<DescendantCleanupStatus>();
    assert_public_type::<ExecutableIdentityPolicy>();
    assert_public_type::<LeaseFactsConsistency>();
    assert_public_type::<Negotiating>();
    assert_public_type::<NegotiationDecision>();
    assert_public_type::<NegotiationError>();
    assert_public_type::<NegotiationOutcome<CoordinatorSession<Ready>>>();
    assert_public_type::<PeerStatus>();
    assert_public_type::<ProtocolVersion>();
    assert_public_type::<Ready>();
    assert_public_type::<Receiver>();
    assert_public_type::<ReceiverBootstrap>();
    assert_public_type::<ReceiverCloseOutcome>();
    assert_public_type::<ReceiverSession<Negotiating>>();
    assert_public_type::<RejectionReason>();
    assert_public_type::<Session<Coordinator, Ready>>();
    assert_public_type::<SessionCommand>();
    assert_public_type::<SessionEndpoint>();
    assert_public_type::<SessionError>();
    assert_public_type::<SessionFailure>();
    assert_public_type::<SessionLimits>();
    assert_public_type::<SessionOperation>();
    assert_public_type::<SessionOptions>();
    assert_public_type::<SessionState>();
    assert_public_type::<SessionTransactionState>();

    let _: fn() -> NativeMemoryCapabilities = native_memory_capabilities;
    let _: fn() -> BackendStatus = backend_status;
    let _ = (
        APPLICATION_CONTROL_KIND_MIN,
        HARD_MAX_REGIONS_PER_BATCH,
        HARD_MAX_REGION_BYTES,
        HARD_MAX_BATCH_BYTES,
        HARD_MAX_ACTIVE_REGIONS,
        HARD_MAX_ACTIVE_BYTES,
        HARD_MAX_TRANSACTIONS,
        HARD_MAX_BOOTSTRAP_PAYLOAD_BYTES,
        HARD_MAX_CONTROL_PAYLOAD_BYTES,
    );
}
