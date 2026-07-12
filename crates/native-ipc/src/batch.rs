//! One-owner transfer transactions and keyed post-commit regions.

use std::collections::BTreeMap;

use crate::active::{ActiveReader, ActiveWriter};
use crate::region::{PreparedRegion, RegionId, WriterEndpoint};

/// Portable batch construction or active-set lookup failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BatchError {
    /// Negotiated batch limits are zero or exceed hard maxima.
    InvalidLimits,
    /// A batch must contain at least one region.
    Empty,
    /// Region count exceeds the negotiated limit or hard maximum of sixteen.
    TooManyRegions,
    /// A region ID occurs more than once in the transaction.
    DuplicateRegionId(RegionId),
    /// Checked aggregate logical or mapped bytes overflowed or exceeded limits.
    BatchBytesExceeded,
    /// The keyed active set does not contain this ID.
    UnknownRegion(RegionId),
    /// The requested runtime authority does not match the committed direction.
    WrongDirection(RegionId),
    /// Committed mappings do not exactly match pending IDs and directions.
    CommitMismatch,
}

impl core::fmt::Display for BatchError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "region batch operation failed: {self:?}")
    }
}

impl std::error::Error for BatchError {}

/// Consuming owner of every prepared object in one transfer transaction.
pub struct TransferBatch {
    regions: Vec<PreparedRegion>,
    max_regions: usize,
    max_batch_bytes: u64,
    total_logical: u64,
    total_mapped: u64,
}

impl TransferBatch {
    #[allow(dead_code)]
    pub(crate) fn new(max_regions: u16, max_batch_bytes: u64) -> Result<Self, BatchError> {
        let max_regions = usize::from(max_regions);
        if max_regions == 0 || max_regions > 16 {
            return Err(BatchError::TooManyRegions);
        }
        if max_batch_bytes == 0 {
            return Err(BatchError::InvalidLimits);
        }
        Ok(Self {
            regions: Vec::new(),
            max_regions,
            max_batch_bytes,
            total_logical: 0,
            total_mapped: 0,
        })
    }

    /// Consumes one prepared region into this transaction.
    pub fn add(&mut self, region: PreparedRegion) -> Result<(), BatchError> {
        if self.regions.len() == self.max_regions {
            return Err(BatchError::TooManyRegions);
        }
        let id = region.spec().id;
        if self.regions.iter().any(|existing| existing.spec().id == id) {
            return Err(BatchError::DuplicateRegionId(id));
        }
        let logical =
            u64::try_from(region.logical_len()).map_err(|_| BatchError::BatchBytesExceeded)?;
        let mapped =
            u64::try_from(region.mapped_len()).map_err(|_| BatchError::BatchBytesExceeded)?;
        let total_logical = self
            .total_logical
            .checked_add(logical)
            .ok_or(BatchError::BatchBytesExceeded)?;
        let total_mapped = self
            .total_mapped
            .checked_add(mapped)
            .ok_or(BatchError::BatchBytesExceeded)?;
        if total_logical > self.max_batch_bytes || total_mapped > self.max_batch_bytes {
            return Err(BatchError::BatchBytesExceeded);
        }
        self.total_logical = total_logical;
        self.total_mapped = total_mapped;
        self.regions.push(region);
        Ok(())
    }

    /// Current number of transaction-owned regions.
    pub fn len(&self) -> usize {
        self.regions.len()
    }

    /// Whether no region has been added yet.
    pub fn is_empty(&self) -> bool {
        self.regions.is_empty()
    }

    #[allow(dead_code)]
    pub(crate) fn into_pending(self) -> Result<PendingBatch, BatchError> {
        if self.regions.is_empty() {
            return Err(BatchError::Empty);
        }
        Ok(PendingBatch {
            regions: self.regions,
            total_logical: self.total_logical,
            total_mapped: self.total_mapped,
        })
    }
}

/// Complete transaction state after local validation and before COMMIT.
#[allow(dead_code)]
pub(crate) struct PendingBatch {
    pub(crate) regions: Vec<PreparedRegion>,
    pub(crate) total_logical: u64,
    pub(crate) total_mapped: u64,
}

#[allow(dead_code)]
pub(crate) enum CommittedRegion {
    Reader(ActiveReader),
    Writer(ActiveWriter),
}

/// Keyed complete runtime set returned only after batch COMMIT.
pub struct ActiveRegionSet {
    regions: BTreeMap<RegionId, CommittedRegion>,
}

impl ActiveRegionSet {
    #[allow(dead_code)]
    pub(crate) fn from_committed(
        pending: PendingBatch,
        regions: impl IntoIterator<Item = (RegionId, CommittedRegion)>,
    ) -> Result<Self, BatchError> {
        let mut keyed = BTreeMap::new();
        for (id, region) in regions {
            if keyed.insert(id, region).is_some() {
                return Err(BatchError::DuplicateRegionId(id));
            }
        }
        if keyed.len() != pending.regions.len() || keyed.len() > 16 {
            return Err(BatchError::CommitMismatch);
        }
        for expected in &pending.regions {
            let id = expected.spec().id;
            match (expected.spec().writer, keyed.get(&id)) {
                (WriterEndpoint::Coordinator, Some(CommittedRegion::Writer(_)))
                | (WriterEndpoint::Receiver, Some(CommittedRegion::Reader(_))) => {}
                _ => return Err(BatchError::CommitMismatch),
            }
        }
        drop(pending);
        Ok(Self { regions: keyed })
    }

    /// Number of active regions still retained by this set.
    pub fn len(&self) -> usize {
        self.regions.len()
    }

    /// Whether every region has been removed.
    pub fn is_empty(&self) -> bool {
        self.regions.is_empty()
    }

    /// Removes the coordinator-writer mapping for `id`.
    pub fn take_writer(&mut self, id: RegionId) -> Result<ActiveWriter, BatchError> {
        match self.regions.get(&id) {
            None => return Err(BatchError::UnknownRegion(id)),
            Some(CommittedRegion::Reader(_)) => return Err(BatchError::WrongDirection(id)),
            Some(CommittedRegion::Writer(_)) => {}
        }
        match self.regions.remove(&id) {
            Some(CommittedRegion::Writer(writer)) => Ok(writer),
            Some(CommittedRegion::Reader(_)) => Err(BatchError::WrongDirection(id)),
            None => Err(BatchError::UnknownRegion(id)),
        }
    }

    /// Removes the coordinator-reader mapping for `id`.
    pub fn take_reader(&mut self, id: RegionId) -> Result<ActiveReader, BatchError> {
        match self.regions.get(&id) {
            None => return Err(BatchError::UnknownRegion(id)),
            Some(CommittedRegion::Writer(_)) => return Err(BatchError::WrongDirection(id)),
            Some(CommittedRegion::Reader(_)) => {}
        }
        match self.regions.remove(&id) {
            Some(CommittedRegion::Reader(reader)) => Ok(reader),
            Some(CommittedRegion::Writer(_)) => Err(BatchError::WrongDirection(id)),
            None => Err(BatchError::UnknownRegion(id)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::active::{ActiveReadOwner, ActiveWriteOwner};
    use crate::region::{PrivateRegion, RegionOptions, RegionSpec, WriterEndpoint};
    use static_assertions::{assert_impl_all, assert_not_impl_any};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    assert_impl_all!(TransferBatch: Send);
    assert_not_impl_any!(TransferBatch: Sync, Clone);
    assert_impl_all!(ActiveRegionSet: Send);
    assert_not_impl_any!(ActiveRegionSet: Sync, Clone);

    fn prepared(id: u128, writer: WriterEndpoint, bytes: usize) -> PreparedRegion {
        PrivateRegion::allocate(RegionOptions::fixed(bytes))
            .unwrap()
            .prepare(RegionSpec {
                id: RegionId::new(id).unwrap(),
                writer,
            })
            .unwrap()
    }

    struct ReadOwner(Box<[u8]>);
    // SAFETY: test bytes have stable initialized storage for the owner lifetime.
    unsafe impl ActiveReadOwner for ReadOwner {
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

    struct WriteOwner(Box<[u8]>);
    // SAFETY: test bytes are uniquely owned and stable for the owner lifetime.
    unsafe impl ActiveWriteOwner for WriteOwner {
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

    struct CountingReadOwner {
        bytes: Box<[u8]>,
        drops: Arc<AtomicUsize>,
    }

    impl Drop for CountingReadOwner {
        fn drop(&mut self) {
            self.drops.fetch_add(1, Ordering::Relaxed);
        }
    }

    // SAFETY: boxed test bytes are stable and initialized; the atomic counter
    // is independent of the exposed mapping range.
    unsafe impl ActiveReadOwner for CountingReadOwner {
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

    fn reader(bytes: usize) -> ActiveReader {
        ActiveReader::new(Box::new(ReadOwner(vec![0; bytes].into())), bytes).unwrap()
    }

    fn writer(bytes: usize) -> ActiveWriter {
        ActiveWriter::new(Box::new(WriteOwner(vec![0; bytes].into())), bytes).unwrap()
    }

    fn counting_reader(drops: &Arc<AtomicUsize>) -> ActiveReader {
        ActiveReader::new(
            Box::new(CountingReadOwner {
                bytes: vec![0; 8].into(),
                drops: Arc::clone(drops),
            }),
            8,
        )
        .unwrap()
    }

    #[test]
    fn transaction_owns_mixed_regions_and_rejects_limits_and_duplicates() {
        let mut batch = TransferBatch::new(16, 1 << 20).unwrap();
        for (id, writer) in [
            (1, WriterEndpoint::Coordinator),
            (2, WriterEndpoint::Receiver),
            (3, WriterEndpoint::Coordinator),
            (4, WriterEndpoint::Receiver),
        ] {
            batch.add(prepared(id, writer, id as usize * 17)).unwrap();
        }
        assert_eq!(batch.len(), 4);
        assert_eq!(
            batch.add(prepared(4, WriterEndpoint::Coordinator, 8)),
            Err(BatchError::DuplicateRegionId(RegionId::new(4).unwrap()))
        );
        let pending = batch.into_pending().unwrap();
        assert_eq!(pending.regions.len(), 4);
        assert!(pending.total_logical > 0);
        assert!(pending.total_mapped >= pending.total_logical);
    }

    #[test]
    fn zero_and_seventeen_region_batches_fail_closed() {
        assert!(matches!(
            TransferBatch::new(0, 1),
            Err(BatchError::TooManyRegions)
        ));
        assert!(matches!(
            TransferBatch::new(17, 1),
            Err(BatchError::TooManyRegions)
        ));
        assert!(matches!(
            TransferBatch::new(16, 1024).unwrap().into_pending(),
            Err(BatchError::Empty)
        ));
        let mut batch = TransferBatch::new(16, 1 << 20).unwrap();
        for id in 1..=16 {
            batch
                .add(prepared(id, WriterEndpoint::Coordinator, 1))
                .unwrap();
        }
        assert_eq!(
            batch.add(prepared(17, WriterEndpoint::Receiver, 1)),
            Err(BatchError::TooManyRegions)
        );
    }

    #[test]
    fn committed_set_requires_exact_ids_and_directions_and_preserves_wrong_take() {
        let writer_id = RegionId::new(1).unwrap();
        let reader_id = RegionId::new(2).unwrap();
        let mut batch = TransferBatch::new(16, 1 << 20).unwrap();
        batch
            .add(prepared(1, WriterEndpoint::Coordinator, 8))
            .unwrap();
        batch.add(prepared(2, WriterEndpoint::Receiver, 8)).unwrap();
        let pending = batch.into_pending().unwrap();
        let mut active = ActiveRegionSet::from_committed(
            pending,
            [
                (writer_id, CommittedRegion::Writer(writer(8))),
                (reader_id, CommittedRegion::Reader(reader(8))),
            ],
        )
        .unwrap();
        assert!(matches!(
            active.take_reader(writer_id),
            Err(BatchError::WrongDirection(id)) if id == writer_id
        ));
        assert_eq!(active.len(), 2);
        active.take_writer(writer_id).unwrap();
        active.take_reader(reader_id).unwrap();
        assert!(active.is_empty());

        let mut mismatch = TransferBatch::new(16, 1 << 20).unwrap();
        mismatch
            .add(prepared(3, WriterEndpoint::Receiver, 8))
            .unwrap();
        assert!(matches!(
            ActiveRegionSet::from_committed(
                mismatch.into_pending().unwrap(),
                [(
                    RegionId::new(3).unwrap(),
                    CommittedRegion::Writer(writer(8))
                )],
            ),
            Err(BatchError::CommitMismatch)
        ));
    }

    #[test]
    fn aggregate_byte_limit_rejects_without_mutating_existing_transaction() {
        let first = prepared(1, WriterEndpoint::Coordinator, 1);
        let exact_one_mapping = first.mapped_len() as u64;
        let mut batch = TransferBatch::new(16, exact_one_mapping).unwrap();
        batch.add(first).unwrap();
        assert_eq!(batch.len(), 1);
        assert_eq!(
            batch.add(prepared(2, WriterEndpoint::Receiver, 1)),
            Err(BatchError::BatchBytesExceeded)
        );
        assert_eq!(batch.len(), 1);
    }

    #[test]
    fn commit_mismatch_drops_all_supplied_mappings() {
        let expected_id = RegionId::new(1).unwrap();
        let foreign_id = RegionId::new(2).unwrap();

        let pending = {
            let mut batch = TransferBatch::new(16, 1 << 20).unwrap();
            batch.add(prepared(1, WriterEndpoint::Receiver, 8)).unwrap();
            batch.into_pending().unwrap()
        };
        let missing_drops = Arc::new(AtomicUsize::new(0));
        assert!(matches!(
            ActiveRegionSet::from_committed(pending, std::iter::empty()),
            Err(BatchError::CommitMismatch)
        ));
        assert_eq!(missing_drops.load(Ordering::Relaxed), 0);

        let pending = {
            let mut batch = TransferBatch::new(16, 1 << 20).unwrap();
            batch.add(prepared(1, WriterEndpoint::Receiver, 8)).unwrap();
            batch.into_pending().unwrap()
        };
        let excess_drops = Arc::new(AtomicUsize::new(0));
        assert!(matches!(
            ActiveRegionSet::from_committed(
                pending,
                [
                    (
                        expected_id,
                        CommittedRegion::Reader(counting_reader(&excess_drops))
                    ),
                    (
                        foreign_id,
                        CommittedRegion::Reader(counting_reader(&excess_drops))
                    ),
                ],
            ),
            Err(BatchError::CommitMismatch)
        ));
        assert_eq!(excess_drops.load(Ordering::Relaxed), 2);

        let pending = {
            let mut batch = TransferBatch::new(16, 1 << 20).unwrap();
            batch.add(prepared(1, WriterEndpoint::Receiver, 8)).unwrap();
            batch.into_pending().unwrap()
        };
        let duplicate_drops = Arc::new(AtomicUsize::new(0));
        assert!(matches!(
            ActiveRegionSet::from_committed(
                pending,
                [
                    (expected_id, CommittedRegion::Reader(counting_reader(&duplicate_drops))),
                    (expected_id, CommittedRegion::Reader(counting_reader(&duplicate_drops))),
                ],
            ),
            Err(BatchError::DuplicateRegionId(id)) if id == expected_id
        ));
        assert_eq!(duplicate_drops.load(Ordering::Relaxed), 2);
    }
}
