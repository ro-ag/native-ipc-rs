//! Common lifecycle and policy interface for the best native shared-memory backend.

use core::fmt;
use core::sync::atomic::{Ordering, compiler_fence};

/// Native backend selected for the compilation target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativePlatform {
    /// Linux sealed anonymous `memfd` mappings.
    Linux,
    /// macOS Mach VM memory-entry mappings.
    MacOs,
    /// Windows unnamed paging-file section mappings.
    Windows,
}

/// Processor architecture selected for the native backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeArchitecture {
    /// 64-bit Arm (Rust `aarch64`) architecture.
    Arm64,
    /// 64-bit x86 (Rust `x86_64`) architecture.
    Amd64,
}

/// Kernel mechanism that freezes shared-memory authority before transfer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityMechanism {
    /// Linux descriptor seals plus a read-only imported mapping.
    DescriptorSeals,
    /// Mach memory-entry maximum protections.
    MaximumPortRights,
    /// Windows exact-rights duplicated section handles.
    ExactHandleRights,
}

/// Cross-platform capabilities of the selected native backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeMemoryCapabilities {
    platform: NativePlatform,
    architecture: NativeArchitecture,
    authority: AuthorityMechanism,
}

impl NativeMemoryCapabilities {
    /// Selected operating-system backend.
    pub const fn platform(self) -> NativePlatform {
        self.platform
    }

    /// Selected processor architecture.
    pub const fn architecture(self) -> NativeArchitecture {
        self.architecture
    }

    /// Native mechanism used to freeze or attenuate authority.
    pub const fn authority_mechanism(self) -> AuthorityMechanism {
        self.authority
    }

    /// Whether a private region can grow by allocating a replacement mapping.
    pub const fn supports_replacement_growth(self) -> bool {
        true
    }

    /// Whether a shared mapping can grow in place.
    pub const fn supports_in_place_growth(self) -> bool {
        false
    }

    /// Whether permission changes are accepted after sharing.
    pub const fn supports_post_share_permission_changes(self) -> bool {
        false
    }

    /// Whether dropping all owners automatically releases the anonymous object.
    pub const fn releases_on_drop(self) -> bool {
        true
    }
}

/// Reports the native memory behavior selected for this target.
pub const fn native_memory_capabilities() -> NativeMemoryCapabilities {
    NativeMemoryCapabilities {
        platform: native_platform(),
        architecture: native_architecture(),
        authority: authority_mechanism(),
    }
}

/// Endpoint that will retain the sole writable mapping after transfer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriterOwner {
    /// The process creating and transferring the region remains the writer.
    Creator,
    /// The authenticated peer becomes the sole writer.
    Peer,
}

/// Planned access for one endpoint after the sharing transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MemoryAccess {
    /// Mapping may load but cannot store.
    ReadOnly,
    /// Mapping is the sole store-capable view.
    ReadWrite,
}

/// Exact creator/peer access requested for the future sharing transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PermissionPlan {
    writer: WriterOwner,
}

impl PermissionPlan {
    /// Creates the only supported permission plan: one writer and one reader.
    pub const fn new(writer: WriterOwner) -> Self {
        Self { writer }
    }

    /// Endpoint selected as sole writer.
    pub const fn writer(self) -> WriterOwner {
        self.writer
    }

    /// Creator's access after authenticated transfer.
    pub const fn creator_access(self) -> MemoryAccess {
        match self.writer {
            WriterOwner::Creator => MemoryAccess::ReadWrite,
            WriterOwner::Peer => MemoryAccess::ReadOnly,
        }
    }

    /// Peer's access after authenticated transfer.
    pub const fn peer_access(self) -> MemoryAccess {
        match self.writer {
            WriterOwner::Creator => MemoryAccess::ReadOnly,
            WriterOwner::Peer => MemoryAccess::ReadWrite,
        }
    }

    /// Whether a mapping created by the library requests execute authority.
    ///
    /// This does not describe every alias a malicious native-capability holder
    /// may create under the documented target-specific authority limits.
    pub const fn library_view_executable(self) -> bool {
        false
    }
}

/// Capacity policy while a region is still private and quiescent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GrowthPolicy {
    /// Mapping size is fixed at allocation.
    Fixed,
    /// Growth replaces the private mapping up to an inclusive logical limit.
    ReplaceBeforeShare {
        /// Maximum logical byte length.
        maximum_len: usize,
    },
}

/// Cleanup policy applied while the common wrapper still owns the region.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CleanupPolicy {
    /// Release the anonymous native object without an explicit clearing pass.
    ReleaseOnDrop,
    /// Clear the complete mapping before releasing it.
    ClearThenRelease,
}

/// Mandatory authority-sealing policy for shared regions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SealPolicy {
    /// Seal or attenuate native authority during the consuming share transition.
    RequiredOnShare,
}

/// Immutable configuration for one native shared-memory region.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegionOptions {
    logical_len: usize,
    growth: GrowthPolicy,
    cleanup: CleanupPolicy,
    permissions: PermissionPlan,
    seal: SealPolicy,
}

impl RegionOptions {
    /// Creates a fixed-size region with clear-on-drop cleanup.
    pub const fn fixed(logical_len: usize, writer: WriterOwner) -> Self {
        Self {
            logical_len,
            growth: GrowthPolicy::Fixed,
            cleanup: CleanupPolicy::ClearThenRelease,
            permissions: PermissionPlan::new(writer),
            seal: SealPolicy::RequiredOnShare,
        }
    }

    /// Creates a private growable region with clear-on-drop cleanup.
    ///
    /// Growth allocates a replacement mapping. It is never available after
    /// the region is consumed for native sharing.
    pub const fn growable(logical_len: usize, maximum_len: usize, writer: WriterOwner) -> Self {
        Self {
            logical_len,
            growth: GrowthPolicy::ReplaceBeforeShare { maximum_len },
            cleanup: CleanupPolicy::ClearThenRelease,
            permissions: PermissionPlan::new(writer),
            seal: SealPolicy::RequiredOnShare,
        }
    }

    /// Overrides cleanup behavior before the native sharing transition.
    pub const fn with_cleanup(mut self, cleanup: CleanupPolicy) -> Self {
        self.cleanup = cleanup;
        self
    }

    /// Initial logical bytes requested by the caller.
    pub const fn logical_len(self) -> usize {
        self.logical_len
    }

    /// Private growth policy.
    pub const fn growth(self) -> GrowthPolicy {
        self.growth
    }

    /// Pre-transfer cleanup policy.
    pub const fn cleanup(self) -> CleanupPolicy {
        self.cleanup
    }

    /// Required one-writer permission plan.
    pub const fn permissions(self) -> PermissionPlan {
        self.permissions
    }

    /// Mandatory native authority-sealing behavior.
    pub const fn seal(self) -> SealPolicy {
        self.seal
    }

    /// Inclusive logical capacity limit.
    pub const fn maximum_len(self) -> usize {
        match self.growth {
            GrowthPolicy::Fixed => self.logical_len,
            GrowthPolicy::ReplaceBeforeShare { maximum_len } => maximum_len,
        }
    }
}

/// Current common lifecycle state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegionState {
    /// Region is private, writable, unshared, and not yet authority-sealed.
    Quiescent,
}

/// Snapshot of a managed region's portable state and policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegionStatus {
    /// Current lifecycle state.
    pub state: RegionState,
    /// Logical application-visible length.
    pub logical_len: usize,
    /// Native page-rounded mapping length.
    pub mapped_len: usize,
    /// Maximum pre-share logical length.
    pub maximum_len: usize,
    /// Whether another pre-share growth operation is possible.
    pub can_grow: bool,
    /// Future creator/peer permission assignment.
    pub permissions: PermissionPlan,
    /// Cleanup behavior while managed by this wrapper.
    pub cleanup: CleanupPolicy,
    /// Mandatory seal applied by the consuming native share transition.
    pub seal: SealPolicy,
}

/// Portable allocation, policy, or lifecycle failure.
#[derive(Debug)]
pub enum MemoryError {
    /// Shared-memory regions cannot be empty.
    ZeroLength,
    /// Configured maximum is smaller than the initial logical length.
    MaximumBelowInitial {
        /// Initial requested logical length.
        initial: usize,
        /// Configured maximum logical length.
        maximum: usize,
    },
    /// Fixed-size policy rejects growth.
    FixedSize,
    /// Shrinking would silently discard user-owned bytes.
    ShrinkUnsupported {
        /// Current logical length.
        current: usize,
        /// Requested smaller logical length.
        requested: usize,
    },
    /// Requested growth exceeds the configured limit.
    MaximumExceeded {
        /// Requested logical length.
        requested: usize,
        /// Configured maximum logical length.
        maximum: usize,
    },
    /// Selected native backend rejected the bounded operation.
    Platform {
        /// Portable operation category.
        operation: &'static str,
    },
    /// The operating-system CSPRNG could not mint object freshness.
    RandomnessUnavailable,
}

impl fmt::Display for MemoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "native shared-memory operation failed: {self:?}")
    }
}

impl std::error::Error for MemoryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

#[cfg(target_os = "linux")]
impl From<crate::backend::linux::LinuxError> for MemoryError {
    fn from(_: crate::backend::linux::LinuxError) -> Self {
        Self::Platform {
            operation: "allocate",
        }
    }
}

#[cfg(target_os = "macos")]
impl From<crate::backend::macos::MachError> for MemoryError {
    fn from(_: crate::backend::macos::MachError) -> Self {
        Self::Platform {
            operation: "allocate",
        }
    }
}

#[cfg(target_os = "windows")]
impl From<crate::backend::windows::WindowsError> for MemoryError {
    fn from(_: crate::backend::windows::WindowsError) -> Self {
        Self::Platform {
            operation: "allocate",
        }
    }
}

/// Common owner of the best private native shared-memory object on this target.
///
/// It exposes logical initialization bytes only through a closure. Consuming
/// [`NativeRegion::prepare_for_sharing`] hands the region to the existing
/// authenticated platform transfer typestate, which applies real native seals
/// and exact permissions. Growth and arbitrary permission changes are no longer
/// possible after that transition.
pub struct NativeRegion {
    inner: Option<PlatformQuiescentRegion>,
    logical_len: usize,
    options: RegionOptions,
}

impl NativeRegion {
    /// Allocates a zeroed anonymous region with a non-executable library view.
    ///
    /// Delegated native authority follows the documented target policy; on
    /// Linux, a malicious memfd holder may create a separate executable alias.
    pub fn allocate(options: RegionOptions) -> Result<Self, MemoryError> {
        validate_options(options)?;
        let inner = PlatformQuiescentRegion::new(options.logical_len())?;
        Ok(Self {
            inner: Some(inner),
            logical_len: options.logical_len(),
            options,
        })
    }

    /// Returns the immutable allocation and authority policy.
    pub const fn options(&self) -> RegionOptions {
        self.options
    }

    /// Returns a portable status snapshot.
    pub fn status(&self) -> RegionStatus {
        let maximum_len = self.options.maximum_len();
        RegionStatus {
            state: RegionState::Quiescent,
            logical_len: self.logical_len,
            mapped_len: self.inner().len(),
            maximum_len,
            can_grow: matches!(
                self.options.growth(),
                GrowthPolicy::ReplaceBeforeShare { .. }
            ) && self.logical_len < maximum_len,
            permissions: self.options.permissions(),
            cleanup: self.options.cleanup(),
            seal: self.options.seal(),
        }
    }

    /// Runs one initialization operation over logical bytes only.
    ///
    /// Page-rounded padding remains zero and inaccessible through this common
    /// method. No capability has escaped while the closure runs.
    pub fn initialize<R>(&mut self, operation: impl FnOnce(&mut [u8]) -> R) -> R {
        let logical_len = self.logical_len;
        operation(&mut self.inner_mut().as_bytes_mut()[..logical_len])
    }

    /// Clears the complete page-rounded mapping and retains it for reuse.
    ///
    /// Every byte, including native page padding, is overwritten through the
    /// live mapping before this method returns.
    pub fn clear(&mut self) {
        clear_mapping(self.inner_mut());
    }

    /// Grows by replacing the still-private mapping and preserving logical bytes.
    pub fn grow(&mut self, requested: usize) -> Result<(), MemoryError> {
        if requested == 0 {
            return Err(MemoryError::ZeroLength);
        }
        if requested < self.logical_len {
            return Err(MemoryError::ShrinkUnsupported {
                current: self.logical_len,
                requested,
            });
        }
        if requested == self.logical_len {
            return Ok(());
        }
        let maximum = match self.options.growth() {
            GrowthPolicy::Fixed => return Err(MemoryError::FixedSize),
            GrowthPolicy::ReplaceBeforeShare { maximum_len } => maximum_len,
        };
        if requested > maximum {
            return Err(MemoryError::MaximumExceeded { requested, maximum });
        }

        let mut replacement = PlatformQuiescentRegion::new(requested)?;
        replacement.as_bytes_mut()[..self.logical_len]
            .copy_from_slice(&self.inner().as_bytes()[..self.logical_len]);
        let mut previous = self
            .inner
            .replace(replacement)
            .expect("managed region always owns its mapping");
        if self.options.cleanup() == CleanupPolicy::ClearThenRelease {
            clear_mapping(&mut previous);
        }
        self.logical_len = requested;
        Ok(())
    }

    /// Explicitly clears according to policy and releases the anonymous object.
    pub fn close(mut self) {
        self.release();
    }

    /// Overwrites the complete mapping, then explicitly releases it.
    ///
    /// This ignores [`CleanupPolicy`] and always performs the clearing pass.
    /// It cannot erase copies previously made by a process, the kernel, or a
    /// device. The region must still be quiescent and exclusively owned here;
    /// shared regions are destroyed by their transferred lifecycle owner.
    pub fn destroy(mut self) {
        if let Some(inner) = self.inner.as_mut() {
            clear_mapping(inner);
        }
        drop(self.inner.take());
    }

    /// Freezes initialization/growth and creates an opaque native share request.
    ///
    /// The private owner is consumed and cannot be reused after preparation.
    ///
    /// ```compile_fail
    /// use native_ipc::memory::{NativeRegion, RegionOptions, WriterOwner};
    /// let mut region = NativeRegion::allocate(RegionOptions::fixed(
    ///     32,
    ///     WriterOwner::Creator,
    /// )).unwrap();
    /// let _prepared = region.prepare_for_sharing().unwrap();
    /// region.clear();
    /// ```
    pub fn prepare_for_sharing(mut self) -> Result<NativeShareRequest, MemoryError> {
        let incarnation =
            crate::backend::mint_incarnation().map_err(|()| MemoryError::RandomnessUnavailable)?;
        Ok(NativeShareRequest {
            inner: self.inner.take(),
            incarnation,
            logical_len: self.logical_len,
            permissions: self.options.permissions(),
            seal: self.options.seal(),
            cleanup: self.options.cleanup(),
        })
    }

    pub(crate) fn prepare_with_writer(
        mut self,
        writer: WriterOwner,
    ) -> Result<NativeShareRequest, MemoryError> {
        self.options.permissions = PermissionPlan::new(writer);
        self.prepare_for_sharing()
    }

    fn inner(&self) -> &PlatformQuiescentRegion {
        self.inner
            .as_ref()
            .expect("managed region always owns its mapping")
    }

    fn inner_mut(&mut self) -> &mut PlatformQuiescentRegion {
        self.inner
            .as_mut()
            .expect("managed region always owns its mapping")
    }

    fn release(&mut self) {
        if let Some(inner) = self.inner.as_mut()
            && self.options.cleanup() == CleanupPolicy::ClearThenRelease
        {
            clear_mapping(inner);
        }
        drop(self.inner.take());
    }
}

/// Consuming boundary between common memory management and native transfer.
///
/// This type exposes no bytes, native parts, or growth operation. It keeps the
/// requested one-writer permission plan attached until a platform-neutral
/// transfer batch consumes it.
///
/// ```compile_fail
/// use native_ipc::memory::{NativeRegion, RegionOptions, WriterOwner};
/// let region = NativeRegion::allocate(RegionOptions::fixed(
///     32,
///     WriterOwner::Creator,
/// )).unwrap();
/// let mut prepared = region.prepare_for_sharing().unwrap();
/// prepared.initialize(|bytes| bytes.fill(0));
/// ```
pub struct NativeShareRequest {
    inner: Option<PlatformQuiescentRegion>,
    #[allow(dead_code)]
    incarnation: [u8; 16],
    logical_len: usize,
    permissions: PermissionPlan,
    seal: SealPolicy,
    cleanup: CleanupPolicy,
}

impl NativeShareRequest {
    /// Required creator/peer access assignment.
    pub const fn permissions(&self) -> PermissionPlan {
        self.permissions
    }

    /// Mandatory native authority-sealing policy.
    pub const fn seal_policy(&self) -> SealPolicy {
        self.seal
    }

    /// Complete native page-rounded mapping length.
    pub fn mapped_len(&self) -> usize {
        self.inner
            .as_ref()
            .expect("share request always owns its mapping")
            .len()
    }

    #[allow(dead_code)]
    pub(crate) const fn logical_len(&self) -> usize {
        self.logical_len
    }

    #[allow(dead_code)]
    pub(crate) const fn incarnation(&self) -> [u8; 16] {
        self.incarnation
    }

    #[allow(dead_code)]
    pub(crate) fn native_spec(&self, region_id: u128) -> Option<crate::protocol::NativeRegionSpec> {
        crate::protocol::NativeRegionSpec::new(
            region_id,
            self.incarnation,
            self.permissions.writer() as u32,
            self.logical_len,
            self.mapped_len(),
        )
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn into_linux_quiescent(
        mut self,
    ) -> (crate::backend::linux::QuiescentRegion, CleanupPolicy) {
        let inner = self
            .inner
            .take()
            .expect("share request always owns its mapping");
        (inner, self.cleanup)
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn into_macos_quiescent(
        mut self,
    ) -> (crate::backend::macos::QuiescentRegion, CleanupPolicy) {
        let inner = self
            .inner
            .take()
            .expect("share request always owns its mapping");
        (inner, self.cleanup)
    }

    /// Clears and releases a prepared request without sharing it.
    pub fn destroy(mut self) {
        if let Some(inner) = self.inner.as_mut() {
            clear_mapping(inner);
        }
        drop(self.inner.take());
    }

    fn release(&mut self) {
        if let Some(inner) = self.inner.as_mut()
            && self.cleanup == CleanupPolicy::ClearThenRelease
        {
            clear_mapping(inner);
        }
        drop(self.inner.take());
    }
}

impl Drop for NativeShareRequest {
    fn drop(&mut self) {
        self.release();
    }
}

fn clear_mapping(region: &mut PlatformQuiescentRegion) {
    for byte in region.as_bytes_mut() {
        // SAFETY: the quiescent typestate uniquely owns the complete live
        // mapping, and each byte pointer is valid for one volatile store.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

impl Drop for NativeRegion {
    fn drop(&mut self) {
        self.release();
    }
}

fn validate_options(options: RegionOptions) -> Result<(), MemoryError> {
    if options.logical_len() == 0 {
        return Err(MemoryError::ZeroLength);
    }
    let maximum = options.maximum_len();
    if maximum < options.logical_len() {
        return Err(MemoryError::MaximumBelowInitial {
            initial: options.logical_len(),
            maximum,
        });
    }
    Ok(())
}

#[cfg(target_os = "linux")]
/// Native quiescent region selected on Linux.
pub(crate) type PlatformQuiescentRegion = crate::backend::linux::QuiescentRegion;
#[cfg(target_os = "macos")]
/// Native quiescent region selected on macOS.
pub(crate) type PlatformQuiescentRegion = crate::backend::macos::QuiescentRegion;

#[cfg(target_os = "windows")]
/// Native quiescent region selected on Windows.
pub(crate) type PlatformQuiescentRegion = crate::backend::windows::QuiescentRegion;
#[cfg(target_os = "linux")]
const fn native_platform() -> NativePlatform {
    NativePlatform::Linux
}
#[cfg(target_os = "macos")]
const fn native_platform() -> NativePlatform {
    NativePlatform::MacOs
}
#[cfg(target_os = "windows")]
const fn native_platform() -> NativePlatform {
    NativePlatform::Windows
}

#[cfg(target_arch = "aarch64")]
const fn native_architecture() -> NativeArchitecture {
    NativeArchitecture::Arm64
}

#[cfg(target_arch = "x86_64")]
const fn native_architecture() -> NativeArchitecture {
    NativeArchitecture::Amd64
}

#[cfg(target_os = "linux")]
const fn authority_mechanism() -> AuthorityMechanism {
    AuthorityMechanism::DescriptorSeals
}
#[cfg(target_os = "macos")]
const fn authority_mechanism() -> AuthorityMechanism {
    AuthorityMechanism::MaximumPortRights
}
#[cfg(target_os = "windows")]
const fn authority_mechanism() -> AuthorityMechanism {
    AuthorityMechanism::ExactHandleRights
}

#[cfg(test)]
#[path = "memory_test.rs"]
mod tests;
