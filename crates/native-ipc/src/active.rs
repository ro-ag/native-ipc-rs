//! Runtime mappings exposed only after complete batch commit.

use core::cell::Cell;
use core::fmt;
use core::marker::PhantomData;
use core::ops::Range;

use crate::liveness::{LivenessState, RegionLease, ResourceError};

/// Checked active-memory access failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessError {
    /// Offset plus byte count overflowed or exceeded the logical payload.
    OutOfBounds,
    /// The supplied range begins after its end.
    InvalidRange,
}

impl fmt::Display for AccessError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "active-region access failed: {self:?}")
    }
}

impl std::error::Error for AccessError {}

/// Bounded result of an explicit off-thread prefault operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PrefaultResult {
    /// Requested logical byte count.
    pub requested_bytes: usize,
    /// Number of distinct covered page locations touched.
    pub pages_touched: usize,
}

unsafe extern "C" {
    fn native_ipc_0_4_0_vnext_v1_external_read(
        source: *const u8,
        destination: *mut u8,
        length: usize,
    );
    fn native_ipc_0_4_0_vnext_v1_external_write(
        destination: *mut u8,
        source: *const u8,
        length: usize,
    );
    fn native_ipc_0_4_0_vnext_v1_external_fill(destination: *mut u8, value: u8, length: usize);
    fn native_ipc_0_4_0_vnext_v1_external_touch_read(address: *const u8);
    fn native_ipc_0_4_0_vnext_v1_external_touch_write(address: *mut u8);
}

/// Private lifetime/permission witness for a stable read-only active mapping.
///
/// # Safety
///
/// The pointer must remain readable and initialized for `len` bytes until the
/// owner is dropped. This value must uniquely own the exact local VM mapping
/// described by that pointer and `len`: it may not delegate lifetime to an
/// `Arc`, duplicate mapping owner, or other value that can retain the local
/// mapping after this owner is dropped. Its non-panicking destructor must
/// synchronously destroy that exact local mapping before returning. These
/// local-ownership obligations do not revoke or shorten the peer's separately
/// authorized mapping. Peer mutation may occur concurrently; no Rust reference
/// may be formed from the pointer. The pointer must be aligned to the stable,
/// nonzero `page_size`; pointer, length, and page size must not change.
pub(crate) unsafe trait ActiveReadOwner: Send + Sync {
    fn as_ptr(&self) -> *const u8;
    fn len(&self) -> usize;
    fn page_size(&self) -> usize;
    #[allow(dead_code)]
    fn liveness_state(&self) -> Option<LivenessState> {
        None
    }
}

/// Private lifetime/permission witness for the sole stable writable mapping.
///
/// # Safety
///
/// In addition to [`ActiveReadOwner`], the current endpoint must have native
/// store authority for the complete range and no safe local writer alias.
/// `as_mut_ptr()` must be stable, writable for `len` bytes, aligned to
/// `page_size`, and identify the exact same base/range as `as_ptr()`. This
/// value has the same unique exact-local-mapping ownership, synchronous unmap,
/// and non-panicking destructor obligations as [`ActiveReadOwner`].
pub(crate) unsafe trait ActiveWriteOwner: Send {
    fn as_ptr(&self) -> *const u8;
    fn as_mut_ptr(&mut self) -> *mut u8;
    fn len(&self) -> usize;
    fn page_size(&self) -> usize;
    #[allow(dead_code)]
    fn liveness_state(&self) -> Option<LivenessState> {
        None
    }
}

/// Stable read-only mapping of peer-writable hostile bytes.
///
/// Active mappings are uniquely owned and cannot be cloned.
///
/// ```compile_fail
/// use native_ipc::active::ActiveReader;
/// fn duplicate(reader: ActiveReader) { let _ = reader.clone(); }
/// ```
#[cfg_attr(
    not(feature = "raw-pointer"),
    doc = "```compile_fail\nuse native_ipc::active::ActiveReader;\nfn pointer(reader: &ActiveReader) { let _ = unsafe { reader.as_ptr() }; }\n```"
)]
pub struct ActiveReader {
    owner: Box<dyn ActiveReadOwner>,
    logical_len: usize,
}

#[allow(dead_code)]
struct LeasedReadOwner {
    owner: Option<Box<dyn ActiveReadOwner>>,
    lease: Option<RegionLease>,
}

#[allow(dead_code)]
struct LeasedWriteOwner {
    owner: Option<Box<dyn ActiveWriteOwner>>,
    lease: Option<RegionLease>,
}

pub(crate) struct LeaseReservation {
    lease: Option<RegionLease>,
    not_sync: PhantomData<Cell<()>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) enum ActivationError {
    Access(AccessError),
    Resource(ResourceError),
    MappingLengthOverflow,
}

impl ActiveReader {
    fn from_owner(
        owner: Box<dyn ActiveReadOwner>,
        logical_len: usize,
    ) -> Result<Self, AccessError> {
        if logical_len == 0
            || logical_len > ActiveReadOwner::len(&*owner)
            || owner.page_size() == 0
            || !(owner.as_ptr() as usize).is_multiple_of(owner.page_size())
        {
            return Err(AccessError::OutOfBounds);
        }
        Ok(Self { owner, logical_len })
    }

    #[cfg(test)]
    pub(crate) fn new_unleased_for_test(
        owner: Box<dyn ActiveReadOwner>,
        logical_len: usize,
    ) -> Result<Self, AccessError> {
        Self::from_owner(owner, logical_len)
    }

    #[allow(dead_code)]
    pub(crate) fn new_leased(
        owner: Box<dyn ActiveReadOwner>,
        logical_len: usize,
        reservation: LeaseReservation,
    ) -> Result<Self, ActivationError> {
        let mut active = Self::from_owner(owner, logical_len).map_err(ActivationError::Access)?;
        let mapped_len = u64::try_from(active.owner.len())
            .map_err(|_| ActivationError::MappingLengthOverflow)?;
        let lease = reservation
            .complete(mapped_len)
            .map_err(ActivationError::Resource)?;
        active.owner = Box::new(LeasedReadOwner {
            owner: Some(active.owner),
            lease: Some(lease),
        });
        Ok(active)
    }

    #[allow(dead_code)]
    pub(crate) fn liveness_state(&self) -> Option<LivenessState> {
        self.owner.liveness_state()
    }

    /// Logical application-visible byte length.
    pub const fn len(&self) -> usize {
        self.logical_len
    }

    /// Whether the logical payload is empty (always false for valid regions).
    pub const fn is_empty(&self) -> bool {
        self.logical_len == 0
    }

    /// Copies hostile externally mutable bytes into caller-owned storage.
    ///
    /// The copy is byte-volatile and may be torn or internally inconsistent.
    /// It provides memory safety and bounds checking, not payload integrity.
    pub fn read_into(&self, offset: usize, destination: &mut [u8]) -> Result<(), AccessError> {
        checked_end(offset, destination.len(), self.logical_len)?;
        // SAFETY: the owner witness and checked range keep source bytes live;
        // the C boundary performs volatile-qualified loads into caller-owned bytes.
        unsafe {
            native_ipc_0_4_0_vnext_v1_external_read(
                self.owner.as_ptr().add(offset),
                destination.as_mut_ptr(),
                destination.len(),
            );
        }
        Ok(())
    }

    /// Touches one byte per covered page off-thread.
    pub fn prefault(&self, range: Range<usize>) -> Result<PrefaultResult, AccessError> {
        prefault_read(
            self.owner.as_ptr(),
            self.owner.page_size(),
            self.logical_len,
            range,
        )
    }

    /// Returns the stable payload address without transferring ownership.
    ///
    /// # Safety
    ///
    /// The caller must remain within `len`, preserve the mapping lifetime,
    /// never create references invalidated by peer mutation, accept torn bytes,
    /// and supply all alignment, synchronization, atomic-ordering, and
    /// application-data validation required by its layout.
    #[cfg(feature = "raw-pointer")]
    pub unsafe fn as_ptr(&self) -> *const u8 {
        self.owner.as_ptr()
    }
}

/// Stable sole-writer mapping. It is movable between threads but deliberately
/// not shareable between threads.
///
/// ```compile_fail
/// use native_ipc::active::ActiveWriter;
/// fn assert_sync<T: Sync>() {}
/// assert_sync::<ActiveWriter>();
/// ```
pub struct ActiveWriter {
    owner: Box<dyn ActiveWriteOwner>,
    logical_len: usize,
    _not_sync: PhantomData<Cell<()>>,
}

impl ActiveWriter {
    fn from_owner(
        mut owner: Box<dyn ActiveWriteOwner>,
        logical_len: usize,
    ) -> Result<Self, AccessError> {
        if logical_len == 0
            || logical_len > ActiveWriteOwner::len(&*owner)
            || owner.page_size() == 0
            || !(owner.as_ptr() as usize).is_multiple_of(owner.page_size())
            || owner.as_ptr() != owner.as_mut_ptr().cast_const()
        {
            return Err(AccessError::OutOfBounds);
        }
        Ok(Self {
            owner,
            logical_len,
            _not_sync: PhantomData,
        })
    }

    #[cfg(test)]
    pub(crate) fn new_unleased_for_test(
        owner: Box<dyn ActiveWriteOwner>,
        logical_len: usize,
    ) -> Result<Self, AccessError> {
        Self::from_owner(owner, logical_len)
    }

    #[allow(dead_code)]
    pub(crate) fn new_leased(
        owner: Box<dyn ActiveWriteOwner>,
        logical_len: usize,
        reservation: LeaseReservation,
    ) -> Result<Self, ActivationError> {
        let mut active = Self::from_owner(owner, logical_len).map_err(ActivationError::Access)?;
        let mapped_len = u64::try_from(active.owner.len())
            .map_err(|_| ActivationError::MappingLengthOverflow)?;
        let lease = reservation
            .complete(mapped_len)
            .map_err(ActivationError::Resource)?;
        active.owner = Box::new(LeasedWriteOwner {
            owner: Some(active.owner),
            lease: Some(lease),
        });
        Ok(active)
    }

    #[allow(dead_code)]
    pub(crate) fn liveness_state(&self) -> Option<LivenessState> {
        self.owner.liveness_state()
    }

    /// Logical application-visible byte length.
    pub const fn len(&self) -> usize {
        self.logical_len
    }

    /// Whether the logical payload is empty (always false for valid regions).
    pub const fn is_empty(&self) -> bool {
        self.logical_len == 0
    }

    /// Copies caller bytes into the sole writable mapping.
    pub fn write_from(&mut self, offset: usize, source: &[u8]) -> Result<(), AccessError> {
        checked_end(offset, source.len(), self.logical_len)?;
        // SAFETY: exclusive self and the owner witness supply sole store
        // authority; checked_end proves both complete ranges.
        unsafe {
            native_ipc_0_4_0_vnext_v1_external_write(
                self.owner.as_mut_ptr().add(offset),
                source.as_ptr(),
                source.len(),
            );
        }
        Ok(())
    }

    /// Fills a checked logical range with one byte value.
    pub fn fill(&mut self, range: Range<usize>, value: u8) -> Result<(), AccessError> {
        validate_range(&range, self.logical_len)?;
        let length = range.end - range.start;
        // SAFETY: range validation and the exclusive native writer witness
        // establish the same obligations as write_from.
        unsafe {
            native_ipc_0_4_0_vnext_v1_external_fill(
                self.owner.as_mut_ptr().add(range.start),
                value,
                length,
            );
        }
        Ok(())
    }

    /// Touches one byte per covered page off-thread without changing contents.
    pub fn prefault(&mut self, range: Range<usize>) -> Result<PrefaultResult, AccessError> {
        let result = prefault_read(
            self.owner.as_ptr(),
            self.owner.page_size(),
            self.logical_len,
            range.clone(),
        )?;
        if !range.is_empty() {
            let base = self.owner.as_mut_ptr();
            let mut offset = range.start;
            loop {
                // SAFETY: prefault_read validated the range; exclusive self and
                // the owner witness permit a same-value volatile store.
                unsafe { native_ipc_0_4_0_vnext_v1_external_touch_write(base.add(offset)) };
                let page = (offset / self.owner.page_size())
                    .checked_add(1)
                    .ok_or(AccessError::OutOfBounds)?;
                let next = page
                    .checked_mul(self.owner.page_size())
                    .ok_or(AccessError::OutOfBounds)?;
                if next >= range.end {
                    break;
                }
                offset = next;
            }
        }
        Ok(result)
    }

    /// Returns the stable readable payload address.
    ///
    /// # Safety
    ///
    /// The caller must uphold the bounds, lifetime, aliasing, synchronization,
    /// atomic-ordering, and peer-mutation obligations in [`ActiveReader::as_ptr`].
    #[cfg(feature = "raw-pointer")]
    pub unsafe fn as_ptr(&self) -> *const u8 {
        self.owner.as_ptr()
    }

    /// Returns the stable writable payload address without transferring ownership.
    ///
    /// # Safety
    ///
    /// The caller must uphold bounds, alignment, initialization, lifetime,
    /// aliasing, synchronization, atomic ordering, and peer-access obligations.
    #[cfg(feature = "raw-pointer")]
    pub unsafe fn as_mut_ptr(&mut self) -> *mut u8 {
        self.owner.as_mut_ptr()
    }
}

unsafe impl ActiveReadOwner for LeasedReadOwner {
    fn as_ptr(&self) -> *const u8 {
        self.owner().as_ptr()
    }

    fn len(&self) -> usize {
        self.owner().len()
    }

    fn page_size(&self) -> usize {
        self.owner().page_size()
    }

    fn liveness_state(&self) -> Option<LivenessState> {
        Some(self.lease().state())
    }
}

unsafe impl ActiveWriteOwner for LeasedWriteOwner {
    fn as_ptr(&self) -> *const u8 {
        self.owner().as_ptr()
    }

    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.owner_mut().as_mut_ptr()
    }

    fn len(&self) -> usize {
        self.owner().len()
    }

    fn page_size(&self) -> usize {
        self.owner().page_size()
    }

    fn liveness_state(&self) -> Option<LivenessState> {
        Some(self.lease().state())
    }
}

#[allow(dead_code)]
impl LeasedReadOwner {
    fn owner(&self) -> &dyn ActiveReadOwner {
        &**self.owner.as_ref().expect("mapping precedes lease drop")
    }

    fn lease(&self) -> &RegionLease {
        self.lease.as_ref().expect("lease follows mapping drop")
    }
}

#[allow(dead_code)]
impl LeasedWriteOwner {
    fn owner(&self) -> &dyn ActiveWriteOwner {
        &**self.owner.as_ref().expect("mapping precedes lease drop")
    }

    fn owner_mut(&mut self) -> &mut dyn ActiveWriteOwner {
        &mut **self.owner.as_mut().expect("mapping precedes lease drop")
    }

    fn lease(&self) -> &RegionLease {
        self.lease.as_ref().expect("lease follows mapping drop")
    }
}

impl Drop for LeasedReadOwner {
    fn drop(&mut self) {
        let lease_guard = self.lease.take();
        drop(self.owner.take());
        drop(lease_guard);
    }
}

impl Drop for LeasedWriteOwner {
    fn drop(&mut self) {
        let lease_guard = self.lease.take();
        drop(self.owner.take());
        drop(lease_guard);
    }
}

impl LeaseReservation {
    pub(super) fn new(lease: RegionLease) -> Self {
        Self {
            lease: Some(lease),
            not_sync: PhantomData,
        }
    }

    fn complete(mut self, actual_mapped_len: u64) -> Result<RegionLease, ResourceError> {
        let lease = self
            .lease
            .as_ref()
            .expect("reservation retains its charge until completion or drop");
        if lease.bytes() != actual_mapped_len {
            return Err(ResourceError::MappedLengthMismatch {
                reserved: lease.bytes(),
                actual: actual_mapped_len,
            });
        }
        match lease.state() {
            LivenessState::Active => {}
            LivenessState::Poisoned => return Err(ResourceError::Poisoned),
            LivenessState::Closed => return Err(ResourceError::Closed),
        }
        Ok(self
            .lease
            .take()
            .expect("validated reservation still owns its charge"))
    }

    #[cfg(test)]
    pub(super) fn complete_for_test(
        self,
        actual_mapped_len: u64,
    ) -> Result<RegionLease, ResourceError> {
        self.complete(actual_mapped_len)
    }
}

fn checked_end(offset: usize, length: usize, limit: usize) -> Result<usize, AccessError> {
    let end = offset.checked_add(length).ok_or(AccessError::OutOfBounds)?;
    if end > limit {
        return Err(AccessError::OutOfBounds);
    }
    Ok(end)
}

fn validate_range(range: &Range<usize>, limit: usize) -> Result<(), AccessError> {
    if range.start > range.end {
        return Err(AccessError::InvalidRange);
    }
    checked_end(range.start, range.end - range.start, limit)?;
    Ok(())
}

fn prefault_read(
    base: *const u8,
    page_size: usize,
    logical_len: usize,
    range: Range<usize>,
) -> Result<PrefaultResult, AccessError> {
    validate_range(&range, logical_len)?;
    let requested_bytes = range.end - range.start;
    if requested_bytes == 0 {
        return Ok(PrefaultResult {
            requested_bytes: 0,
            pages_touched: 0,
        });
    }
    let mut touches = 0;
    let mut offset = range.start;
    loop {
        // SAFETY: the validated range is within the owner mapping; the C
        // boundary performs one volatile-qualified read.
        unsafe { native_ipc_0_4_0_vnext_v1_external_touch_read(base.add(offset)) };
        touches += 1;
        let next_page = (offset / page_size)
            .checked_add(1)
            .ok_or(AccessError::OutOfBounds)?;
        let next = next_page
            .checked_mul(page_size)
            .ok_or(AccessError::OutOfBounds)?;
        if next >= range.end {
            break;
        }
        offset = next;
    }
    Ok(PrefaultResult {
        requested_bytes,
        pages_touched: touches,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::liveness::{LivenessState, ResourceError, ResourceOwner};
    use crate::session::SessionLimits;
    use std::sync::{Arc, Barrier};

    fn assert_send<T: Send>() {}
    fn assert_send_sync<T: Send + Sync>() {}

    struct ReaderOwner(Box<[u8]>);
    // SAFETY: boxed bytes have a stable initialized address for the owner lifetime.
    unsafe impl ActiveReadOwner for ReaderOwner {
        fn as_ptr(&self) -> *const u8 {
            self.0.as_ptr()
        }
        fn len(&self) -> usize {
            self.0.len()
        }
        fn page_size(&self) -> usize {
            1
        }
    }

    struct WriterOwner(Box<[u8]>);
    // SAFETY: the test transfers unique boxed-byte ownership into ActiveWriter.
    unsafe impl ActiveWriteOwner for WriterOwner {
        fn as_ptr(&self) -> *const u8 {
            self.0.as_ptr()
        }
        fn as_mut_ptr(&mut self) -> *mut u8 {
            self.0.as_mut_ptr()
        }
        fn len(&self) -> usize {
            self.0.len()
        }
        fn page_size(&self) -> usize {
            1
        }
    }

    struct BlockingReaderOwner {
        bytes: Box<[u8]>,
        started: Arc<Barrier>,
        release: Arc<Barrier>,
    }

    unsafe impl ActiveReadOwner for BlockingReaderOwner {
        fn as_ptr(&self) -> *const u8 {
            self.bytes.as_ptr()
        }

        fn len(&self) -> usize {
            self.bytes.len()
        }

        fn page_size(&self) -> usize {
            1
        }
    }

    impl Drop for BlockingReaderOwner {
        fn drop(&mut self) {
            self.started.wait();
            self.release.wait();
        }
    }

    struct DropFlagReaderOwner {
        bytes: Box<[u8]>,
        dropped: Arc<core::sync::atomic::AtomicBool>,
    }

    struct PanickingReaderOwner(Box<[u8]>);

    unsafe impl ActiveReadOwner for DropFlagReaderOwner {
        fn as_ptr(&self) -> *const u8 {
            self.bytes.as_ptr()
        }

        fn len(&self) -> usize {
            self.bytes.len()
        }

        fn page_size(&self) -> usize {
            1
        }
    }

    impl Drop for DropFlagReaderOwner {
        fn drop(&mut self) {
            self.dropped
                .store(true, core::sync::atomic::Ordering::Release);
        }
    }

    unsafe impl ActiveReadOwner for PanickingReaderOwner {
        fn as_ptr(&self) -> *const u8 {
            self.0.as_ptr()
        }

        fn len(&self) -> usize {
            self.0.len()
        }

        fn page_size(&self) -> usize {
            1
        }
    }

    impl Drop for PanickingReaderOwner {
        fn drop(&mut self) {
            panic!("deliberate private-owner contract violation");
        }
    }

    fn lease_limits() -> SessionLimits {
        SessionLimits {
            max_active_regions: 2,
            max_active_bytes: 16,
            ..SessionLimits::default()
        }
    }

    #[test]
    fn checked_volatile_access_and_prefault_are_bounded() {
        assert_send_sync::<ActiveReader>();
        assert_send::<ActiveWriter>();
        let reader = ActiveReader::new_unleased_for_test(
            Box::new(ReaderOwner(vec![1, 2, 3, 4, 5].into())),
            5,
        )
        .unwrap();
        let mut output = [0; 3];
        reader.read_into(1, &mut output).unwrap();
        assert_eq!(output, [2, 3, 4]);
        assert_eq!(
            reader.read_into(4, &mut output),
            Err(AccessError::OutOfBounds)
        );
        assert_eq!(reader.prefault(0..5).unwrap().pages_touched, 5);
        assert_eq!(reader.prefault(3..5).unwrap().pages_touched, 2);

        let mut writer =
            ActiveWriter::new_unleased_for_test(Box::new(WriterOwner(vec![0; 5].into())), 5)
                .unwrap();
        writer.write_from(1, &[7, 8]).unwrap();
        writer.fill(3..5, 9).unwrap();
        assert_eq!(writer.prefault(0..5).unwrap().pages_touched, 5);
        assert_eq!(writer.fill(4..6, 1), Err(AccessError::OutOfBounds));

        #[cfg(feature = "raw-pointer")]
        unsafe {
            assert!(!reader.as_ptr().is_null());
            assert!(!writer.as_ptr().is_null());
            assert!(!writer.as_mut_ptr().is_null());
        }
    }

    #[test]
    fn active_mapping_retains_shared_liveness_until_mapping_drop_finishes() {
        let mut resources = ResourceOwner::new(lease_limits()).unwrap();
        let started = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let reader = ActiveReader::new_leased(
            Box::new(BlockingReaderOwner {
                bytes: vec![0; 4].into(),
                started: Arc::clone(&started),
                release: Arc::clone(&release),
            }),
            4,
            resources.reserve(4).unwrap(),
        )
        .unwrap();
        assert_eq!(reader.liveness_state(), Some(LivenessState::Active));
        resources.poison();
        assert_eq!(reader.liveness_state(), Some(LivenessState::Poisoned));

        let drop_thread = std::thread::spawn(move || drop(reader));
        started.wait();
        assert!(matches!(
            resources.try_close(),
            Err(ResourceError::ActiveLeases(_))
        ));
        release.wait();
        drop_thread.join().unwrap();
        resources.try_close().unwrap();
    }

    #[test]
    fn rejected_mapping_is_destroyed_and_its_charge_rolls_back() {
        use core::sync::atomic::{AtomicBool, Ordering};

        let mut resources = ResourceOwner::new(lease_limits()).unwrap();
        let dropped = Arc::new(AtomicBool::new(false));
        let result = ActiveReader::new_leased(
            Box::new(DropFlagReaderOwner {
                bytes: vec![0; 3].into(),
                dropped: Arc::clone(&dropped),
            }),
            3,
            resources.reserve(4).unwrap(),
        );
        assert!(matches!(
            result,
            Err(ActivationError::Resource(
                ResourceError::MappedLengthMismatch {
                    reserved: 4,
                    actual: 3
                }
            ))
        ));
        assert!(dropped.load(Ordering::Acquire));
        assert_eq!(resources.active_lease_facts().regions, 0);
    }

    #[test]
    fn active_writer_retains_the_same_exact_resource_lease() {
        let mut resources = ResourceOwner::new(lease_limits()).unwrap();
        let mut writer = ActiveWriter::new_leased(
            Box::new(WriterOwner(vec![0; 5].into())),
            5,
            resources.reserve(5).unwrap(),
        )
        .unwrap();
        assert_eq!(writer.liveness_state(), Some(LivenessState::Active));
        writer.write_from(0, &[1, 2, 3, 4, 5]).unwrap();
        assert_eq!(resources.active_lease_facts().regions, 1);
        drop(writer);
        assert_eq!(resources.active_lease_facts().regions, 0);
    }

    #[test]
    fn owner_destructor_panic_cannot_leak_the_resource_charge() {
        let mut resources = ResourceOwner::new(lease_limits()).unwrap();
        let reader = ActiveReader::new_leased(
            Box::new(PanickingReaderOwner(vec![0; 4].into())),
            4,
            resources.reserve(4).unwrap(),
        )
        .unwrap();
        let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(reader)));
        assert!(panic.is_err());
        assert_eq!(resources.active_lease_facts().regions, 0);
        resources.try_close().unwrap();
    }
}
