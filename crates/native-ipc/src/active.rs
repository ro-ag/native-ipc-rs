//! Runtime mappings exposed only after complete batch commit.

use core::cell::Cell;
use core::fmt;
use core::marker::PhantomData;
use core::ops::Range;

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
/// owner is dropped. Peer mutation may occur concurrently; no Rust reference
/// may be formed from the pointer. The pointer must be aligned to the stable,
/// nonzero `page_size`; pointer, length, and page size must not change.
pub(crate) unsafe trait ActiveReadOwner: Send + Sync {
    fn as_ptr(&self) -> *const u8;
    fn len(&self) -> usize;
    fn page_size(&self) -> usize;
}

/// Private lifetime/permission witness for the sole stable writable mapping.
///
/// # Safety
///
/// In addition to [`ActiveReadOwner`], the current endpoint must have native
/// store authority for the complete range and no safe local writer alias.
/// `as_mut_ptr()` must be stable, writable for `len` bytes, aligned to
/// `page_size`, and identify the exact same base/range as `as_ptr()`.
pub(crate) unsafe trait ActiveWriteOwner: Send {
    fn as_ptr(&self) -> *const u8;
    fn as_mut_ptr(&mut self) -> *mut u8;
    fn len(&self) -> usize;
    fn page_size(&self) -> usize;
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

impl ActiveReader {
    #[allow(dead_code)]
    pub(crate) fn new(
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
    #[allow(dead_code)]
    pub(crate) fn new(
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

    #[test]
    fn checked_volatile_access_and_prefault_are_bounded() {
        assert_send_sync::<ActiveReader>();
        assert_send::<ActiveWriter>();
        let reader =
            ActiveReader::new(Box::new(ReaderOwner(vec![1, 2, 3, 4, 5].into())), 5).unwrap();
        let mut output = [0; 3];
        reader.read_into(1, &mut output).unwrap();
        assert_eq!(output, [2, 3, 4]);
        assert_eq!(
            reader.read_into(4, &mut output),
            Err(AccessError::OutOfBounds)
        );
        assert_eq!(reader.prefault(0..5).unwrap().pages_touched, 5);
        assert_eq!(reader.prefault(3..5).unwrap().pages_touched, 2);

        let mut writer = ActiveWriter::new(Box::new(WriterOwner(vec![0; 5].into())), 5).unwrap();
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
}
