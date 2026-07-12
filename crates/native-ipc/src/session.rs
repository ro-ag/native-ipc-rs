//! Platform-neutral session negotiation facts.

use std::time::{Duration, Instant};

/// Hard protocol maximum for one atomic transfer batch.
pub const HARD_MAX_REGIONS_PER_BATCH: u16 = 16;
/// Hard maximum for the opaque HELLO application payload.
pub const HARD_MAX_BOOTSTRAP_PAYLOAD_BYTES: u32 = 16 * 1024 * 1024;
/// Hard maximum for one opaque application-control payload.
pub const HARD_MAX_CONTROL_PAYLOAD_BYTES: u32 = 16 * 1024 * 1024;
/// Hard maximum logical size of one region.
pub const HARD_MAX_REGION_BYTES: u64 = 1 << 40;
/// Hard maximum aggregate bytes in one transaction.
pub const HARD_MAX_BATCH_BYTES: u64 = 1 << 42;
/// Hard maximum simultaneously charged region mappings.
pub const HARD_MAX_ACTIVE_REGIONS: u32 = 1 << 20;
/// Hard maximum simultaneously charged mapping bytes.
pub const HARD_MAX_ACTIVE_BYTES: u64 = 1 << 44;
/// Hard maximum transactions in one fresh session.
pub const HARD_MAX_TRANSACTIONS: u64 = 1 << 48;

/// Finite resource limits offered and negotiated by both endpoints.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionLimits {
    /// Maximum entries in one batch; hard maximum sixteen.
    pub max_regions_per_batch: u16,
    /// Maximum logical bytes in one region.
    pub max_region_bytes: u64,
    /// Maximum aggregate logical/mapped bytes in one batch.
    pub max_batch_bytes: u64,
    /// Maximum charged active region mappings.
    pub max_active_regions: u32,
    /// Maximum charged active mapping bytes.
    pub max_active_bytes: u64,
    /// Maximum monotonically increasing transactions.
    pub max_transactions: u64,
    /// Maximum opaque HELLO application payload bytes.
    pub max_bootstrap_payload_bytes: u32,
    /// Maximum opaque application-control payload bytes.
    pub max_control_payload_bytes: u32,
}

impl Default for SessionLimits {
    fn default() -> Self {
        Self {
            max_regions_per_batch: 16,
            max_region_bytes: 256 * 1024 * 1024,
            max_batch_bytes: 1024 * 1024 * 1024,
            max_active_regions: 4096,
            max_active_bytes: 8 * 1024 * 1024 * 1024,
            max_transactions: 1 << 32,
            max_bootstrap_payload_bytes: 1024 * 1024,
            max_control_payload_bytes: 1024 * 1024,
        }
    }
}

/// Invalid local or peer negotiation offer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NegotiationError {
    /// A numeric limit is zero.
    ZeroLimit,
    /// A numeric limit exceeds its field-specific hard maximum.
    AboveHardMaximum,
    /// A byte limit cannot narrow to this target's `usize`.
    NativeSizeNarrowing,
    /// Required lock-free atomic width is not available.
    AtomicUnsupported,
    /// A monotonic deadline cannot be represented.
    InvalidDeadline,
}

impl core::fmt::Display for NegotiationError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "session negotiation failed: {self:?}")
    }
}

impl std::error::Error for NegotiationError {}

impl SessionLimits {
    /// Validates every field before allocation or native import.
    pub fn validate(self) -> Result<Self, NegotiationError> {
        self.validate_for_native_max(usize::MAX as u64)
    }

    fn validate_for_native_max(self, native_usize_max: u64) -> Result<Self, NegotiationError> {
        if self.max_regions_per_batch == 0
            || self.max_region_bytes == 0
            || self.max_batch_bytes == 0
            || self.max_active_regions == 0
            || self.max_active_bytes == 0
            || self.max_transactions == 0
            || self.max_bootstrap_payload_bytes == 0
            || self.max_control_payload_bytes == 0
        {
            return Err(NegotiationError::ZeroLimit);
        }
        if self.max_regions_per_batch > HARD_MAX_REGIONS_PER_BATCH
            || self.max_region_bytes > HARD_MAX_REGION_BYTES
            || self.max_batch_bytes > HARD_MAX_BATCH_BYTES
            || self.max_active_regions > HARD_MAX_ACTIVE_REGIONS
            || self.max_active_bytes > HARD_MAX_ACTIVE_BYTES
            || self.max_transactions > HARD_MAX_TRANSACTIONS
            || self.max_bootstrap_payload_bytes > HARD_MAX_BOOTSTRAP_PAYLOAD_BYTES
            || self.max_control_payload_bytes > HARD_MAX_CONTROL_PAYLOAD_BYTES
        {
            return Err(NegotiationError::AboveHardMaximum);
        }
        if self.max_region_bytes > native_usize_max
            || self.max_batch_bytes > native_usize_max
            || self.max_active_bytes > native_usize_max
            || u64::from(self.max_bootstrap_payload_bytes) > native_usize_max
            || u64::from(self.max_control_payload_bytes) > native_usize_max
        {
            return Err(NegotiationError::NativeSizeNarrowing);
        }
        Ok(self)
    }

    /// Computes checked effective minima after validating both offers.
    pub fn negotiate(local: Self, peer: Self) -> Result<Self, NegotiationError> {
        let local = local.validate()?;
        let peer = peer.validate()?;
        Self {
            max_regions_per_batch: local.max_regions_per_batch.min(peer.max_regions_per_batch),
            max_region_bytes: local.max_region_bytes.min(peer.max_region_bytes),
            max_batch_bytes: local.max_batch_bytes.min(peer.max_batch_bytes),
            max_active_regions: local.max_active_regions.min(peer.max_active_regions),
            max_active_bytes: local.max_active_bytes.min(peer.max_active_bytes),
            max_transactions: local.max_transactions.min(peer.max_transactions),
            max_bootstrap_payload_bytes: local
                .max_bootstrap_payload_bytes
                .min(peer.max_bootstrap_payload_bytes),
            max_control_payload_bytes: local
                .max_control_payload_bytes
                .min(peer.max_control_payload_bytes),
        }
        .validate()
    }
}

/// Cross-process atomic and layout alignment facts for the selected target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AtomicCapabilities {
    atomic_u32_lock_free: bool,
    atomic_u32_alignment: usize,
    atomic_u64_lock_free: bool,
    atomic_u64_alignment: usize,
    page_alignment: usize,
    cache_line_alignment: usize,
}

impl AtomicCapabilities {
    /// Constructs facts only after private native discovery has established
    /// lock freedom and runtime page/cache-line alignment.
    #[allow(dead_code, reason = "wired into native HELLO discovery in phase 4b")]
    pub(crate) fn from_verified_native(
        page_alignment: usize,
        cache_line_alignment: usize,
        atomic_u32_lock_free: bool,
        atomic_u64_lock_free: bool,
    ) -> Result<Self, NegotiationError> {
        let atomic_u32_alignment = core::mem::align_of::<core::sync::atomic::AtomicU32>();
        let atomic_u64_alignment = core::mem::align_of::<core::sync::atomic::AtomicU64>();
        if !page_alignment.is_power_of_two()
            || !cache_line_alignment.is_power_of_two()
            || page_alignment < atomic_u32_alignment.max(atomic_u64_alignment)
            || cache_line_alignment < atomic_u32_alignment.max(atomic_u64_alignment)
        {
            return Err(NegotiationError::AtomicUnsupported);
        }
        Ok(Self {
            atomic_u32_lock_free,
            atomic_u32_alignment,
            atomic_u64_lock_free,
            atomic_u64_alignment,
            page_alignment,
            cache_line_alignment,
        })
    }

    /// Whether private target discovery established lock-free 32-bit atomics.
    pub fn atomic_u32_lock_free(self) -> bool {
        self.atomic_u32_lock_free
    }

    /// Required alignment for an atomic 32-bit value.
    pub fn atomic_u32_alignment(self) -> usize {
        self.atomic_u32_alignment
    }

    /// Whether private target discovery established lock-free 64-bit atomics.
    pub fn atomic_u64_lock_free(self) -> bool {
        self.atomic_u64_lock_free
    }

    /// Required alignment for an atomic 64-bit value.
    pub fn atomic_u64_alignment(self) -> usize {
        self.atomic_u64_alignment
    }

    /// Runtime native page alignment.
    pub fn page_alignment(self) -> usize {
        self.page_alignment
    }

    /// Runtime native cache-line alignment used by application layouts.
    pub fn cache_line_alignment(self) -> usize {
        self.cache_line_alignment
    }

    /// Rejects negotiation if required widths are unavailable.
    #[allow(dead_code, reason = "wired into native HELLO negotiation in phase 4b")]
    pub(crate) fn require(
        self,
        u32_required: bool,
        u64_required: bool,
    ) -> Result<Self, NegotiationError> {
        if (u32_required && !self.atomic_u32_lock_free)
            || (u64_required && !self.atomic_u64_lock_free)
        {
            return Err(NegotiationError::AtomicUnsupported);
        }
        Ok(self)
    }
}

/// One monotonic absolute deadline shared by a complete operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AbsoluteDeadline(Instant);

impl AbsoluteDeadline {
    /// Derives a deadline once at operation entry.
    pub fn after(duration: Duration) -> Result<Self, NegotiationError> {
        if duration.is_zero() {
            return Err(NegotiationError::InvalidDeadline);
        }
        Instant::now()
            .checked_add(duration)
            .map(Self)
            .ok_or(NegotiationError::InvalidDeadline)
    }

    /// Returns the remaining duration, or zero after expiry.
    pub fn remaining(self) -> Duration {
        self.0.saturating_duration_since(Instant::now())
    }

    /// Whether the absolute deadline has expired.
    pub fn is_expired(self) -> bool {
        self.remaining().is_zero()
    }
}

const _: () = assert!(cfg!(target_has_atomic = "32"));
const _: () = assert!(cfg!(target_has_atomic = "64"));

#[cfg(test)]
#[path = "session_test.rs"]
mod tests;
