//! Platform-neutral private and prepared shared-memory regions.

use core::cell::Cell;
use core::fmt;
use core::marker::PhantomData;

use crate::memory;

/// Caller-selected opaque region identity.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RegionId(u128);

impl RegionId {
    /// Constructs a nonzero opaque identity.
    pub const fn new(value: u128) -> Option<Self> {
        if value == 0 { None } else { Some(Self(value)) }
    }

    /// Returns the caller-selected numeric value.
    pub const fn get(self) -> u128 {
        self.0
    }
}

/// Endpoint with store authority after commit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriterEndpoint {
    /// The spawning coordinator writes and the receiver reads.
    Coordinator,
    /// The spawned receiver writes and the coordinator reads.
    Receiver,
}

/// Identity and writer direction attached during consuming preparation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegionSpec {
    /// Opaque identity, unique within a batch.
    pub id: RegionId,
    /// Coordinator-relative writer direction.
    pub writer: WriterEndpoint,
}

/// Requested guard-page behavior around a payload mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GuardPolicy {
    /// Install guards where reliable placement is available.
    BestEffort,
    /// Fail preparation unless guards can be installed.
    Require,
    /// Do not request guard pages.
    Disable,
}

/// Guard-page request and the backend result established during preparation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GuardCapability {
    /// Policy requested by the caller.
    pub requested: GuardPolicy,
    /// Whether inaccessible guard pages were actually installed.
    pub installed: bool,
}

/// Immutable private allocation policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegionOptions {
    logical_len: usize,
    maximum_len: usize,
    guard: GuardPolicy,
}

impl RegionOptions {
    /// Creates a fixed-length private region.
    pub const fn fixed(logical_len: usize) -> Self {
        Self {
            logical_len,
            maximum_len: logical_len,
            guard: GuardPolicy::BestEffort,
        }
    }

    /// Sets the inclusive replacement-growth limit before preparation.
    pub const fn with_max_bytes(mut self, maximum_len: usize) -> Self {
        self.maximum_len = maximum_len;
        self
    }

    /// Selects guard-page behavior.
    pub const fn with_guard_policy(mut self, guard: GuardPolicy) -> Self {
        self.guard = guard;
        self
    }
}

/// Portable private allocation or preparation failure.
#[derive(Debug)]
pub enum RegionError {
    /// Portable or native allocation/preparation failed.
    Memory(memory::MemoryError),
    /// Required reliable guard-page placement is not implemented.
    GuardUnavailable,
}

impl fmt::Display for RegionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Memory(error) => error.fmt(formatter),
            Self::GuardUnavailable => formatter.write_str("required guard pages are unavailable"),
        }
    }
}

impl std::error::Error for RegionError {}

impl From<memory::MemoryError> for RegionError {
    fn from(value: memory::MemoryError) -> Self {
        Self::Memory(value)
    }
}

/// Unique writable region before any native capability escapes.
pub struct PrivateRegion {
    inner: memory::NativeRegion,
    guard: GuardPolicy,
    _not_sync: PhantomData<Cell<()>>,
}

// SAFETY: the value uniquely owns its mapping and exposes mutation only through
// `&mut self`; moving that ownership between threads does not create aliases.
unsafe impl Send for PrivateRegion {}

impl PrivateRegion {
    /// Allocates zeroed anonymous memory with a non-executable library view.
    ///
    /// Delegated native authority follows the documented target policy; on
    /// Linux, a malicious memfd holder may create a separate executable alias.
    pub fn allocate(options: RegionOptions) -> Result<Self, RegionError> {
        if options.guard == GuardPolicy::Require {
            return Err(RegionError::GuardUnavailable);
        }
        let native = if options.maximum_len == options.logical_len {
            memory::RegionOptions::fixed(options.logical_len, memory::WriterOwner::Creator)
        } else {
            memory::RegionOptions::growable(
                options.logical_len,
                options.maximum_len,
                memory::WriterOwner::Creator,
            )
        };
        Ok(Self {
            inner: memory::NativeRegion::allocate(native)?,
            guard: options.guard,
            _not_sync: PhantomData,
        })
    }

    /// Runs scoped initialization over logical bytes only.
    pub fn initialize<R>(&mut self, operation: impl FnOnce(&mut [u8]) -> R) -> R {
        self.inner.initialize(operation)
    }

    /// Consumes private ownership and attaches opaque transfer metadata.
    pub fn prepare(self, spec: RegionSpec) -> Result<PreparedRegion, RegionError> {
        let writer = match spec.writer {
            WriterEndpoint::Coordinator => memory::WriterOwner::Creator,
            WriterEndpoint::Receiver => memory::WriterOwner::Peer,
        };
        let request = self.inner.prepare_with_writer(writer)?;
        Ok(PreparedRegion {
            request,
            spec,
            guard: GuardCapability {
                requested: self.guard,
                installed: false,
            },
            #[cfg(test)]
            drop_observer: PreparedDropObserver(None),
            _not_sync: PhantomData,
        })
    }
}

/// Opaque prepared native object awaiting ownership by one transfer batch.
///
/// This state has no payload access, cloning, or raw native-parts operation.
///
/// ```compile_fail
/// use native_ipc::region::PreparedRegion;
/// fn access(pending: &PreparedRegion) { let _ = pending.read_into(0, &mut []); }
/// ```
pub struct PreparedRegion {
    #[cfg(test)]
    drop_observer: PreparedDropObserver,
    #[allow(dead_code)]
    pub(crate) request: memory::NativeShareRequest,
    #[allow(dead_code)]
    pub(crate) spec: RegionSpec,
    #[allow(dead_code)]
    pub(crate) guard: GuardCapability,
    _not_sync: PhantomData<Cell<()>>,
}

#[cfg(test)]
struct PreparedDropObserver(Option<std::sync::Arc<std::sync::Mutex<Vec<&'static str>>>>);

#[cfg(test)]
impl Drop for PreparedDropObserver {
    fn drop(&mut self) {
        if let Some(events) = &self.0 {
            events.lock().unwrap().push("prepared-drop");
        }
    }
}

// SAFETY: preparation retains unique ownership and exposes no shared access.
unsafe impl Send for PreparedRegion {}

impl PreparedRegion {
    /// Reports requested and actually installed guard-page behavior.
    pub const fn guard_capability(&self) -> GuardCapability {
        self.guard
    }

    pub(crate) const fn spec(&self) -> RegionSpec {
        self.spec
    }

    #[allow(dead_code)]
    pub(crate) fn logical_len(&self) -> usize {
        self.request.logical_len()
    }

    #[allow(dead_code)]
    pub(crate) fn mapped_len(&self) -> usize {
        self.request.mapped_len()
    }

    #[cfg(test)]
    pub(crate) fn observe_drop(
        mut self,
        events: std::sync::Arc<std::sync::Mutex<Vec<&'static str>>>,
    ) -> Self {
        self.drop_observer.0 = Some(events);
        self
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn into_linux_transfer_parts(
        self,
    ) -> (memory::NativeShareRequest, RegionSpec, GuardCapability) {
        let Self {
            #[cfg(test)]
                drop_observer: _,
            request,
            spec,
            guard,
            _not_sync: _,
        } = self;
        (request, spec, guard)
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn into_macos_transfer_parts(
        self,
    ) -> (memory::NativeShareRequest, RegionSpec, GuardCapability) {
        let Self {
            #[cfg(test)]
                drop_observer: _,
            request,
            spec,
            guard,
            _not_sync: _,
        } = self;
        (request, spec, guard)
    }

    #[cfg(target_os = "windows")]
    pub(crate) fn into_windows_transfer_parts(
        self,
    ) -> (memory::NativeShareRequest, RegionSpec, GuardCapability) {
        let Self {
            #[cfg(test)]
                drop_observer: _,
            request,
            spec,
            guard,
            _not_sync: _,
        } = self;
        (request, spec, guard)
    }
}

#[cfg(test)]
#[path = "region_test.rs"]
mod tests;
