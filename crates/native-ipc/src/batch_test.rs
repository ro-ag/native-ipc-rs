use super::*;
use crate::active::{ActiveReadOwner, ActiveWriteOwner};
use crate::region::{PrivateRegion, RegionOptions, RegionSpec, WriterEndpoint};
use static_assertions::{assert_impl_all, assert_not_impl_any};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

assert_impl_all!(TransferBatch: Send);
assert_not_impl_any!(TransferBatch: Sync, Clone);
assert_impl_all!(ExpectedBatch: Send);
assert_not_impl_any!(ExpectedBatch: Clone);
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

fn expected(id: u128, writer: WriterEndpoint, logical_len: usize) -> ExpectedRegion {
    ExpectedRegion {
        id: RegionId::new(id).unwrap(),
        writer,
        logical_len,
    }
}

#[test]
fn expected_batch_is_complete_canonical_metadata_before_receipt() {
    let batch = ExpectedBatch::try_from_specs(vec![
        expected(4, WriterEndpoint::Receiver, 17),
        expected(1, WriterEndpoint::Coordinator, 3),
        expected(2, WriterEndpoint::Coordinator, 5),
    ])
    .unwrap();
    assert_eq!(batch.len(), 3);
    assert_eq!(batch.total_logical, 25);
    assert_eq!(
        batch
            .regions
            .iter()
            .map(|region| region.id.get())
            .collect::<Vec<_>>(),
        vec![1, 2, 4]
    );
    assert_eq!(batch.regions[2].writer, WriterEndpoint::Receiver);
}

#[test]
fn expected_batch_rejects_empty_zero_duplicate_and_seventeen() {
    assert!(matches!(
        ExpectedBatch::try_from_specs(Vec::new()),
        Err(BatchError::Empty)
    ));
    assert!(matches!(
        ExpectedBatch::try_from_specs(vec![expected(1, WriterEndpoint::Coordinator, 0)]),
        Err(BatchError::InvalidRegionLength)
    ));
    assert!(matches!(
        ExpectedBatch::try_from_specs(vec![
            expected(1, WriterEndpoint::Coordinator, 1),
            expected(1, WriterEndpoint::Receiver, 1),
        ]),
        Err(BatchError::DuplicateRegionId(id)) if id == RegionId::new(1).unwrap()
    ));
    assert!(matches!(
        ExpectedBatch::try_from_specs(
            (1..=17)
                .map(|id| expected(id, WriterEndpoint::Coordinator, 1))
                .collect()
        ),
        Err(BatchError::TooManyRegions)
    ));
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
    ActiveReader::new_unleased_for_test(Box::new(ReadOwner(vec![0; bytes].into())), bytes).unwrap()
}

fn writer(bytes: usize) -> ActiveWriter {
    ActiveWriter::new_unleased_for_test(Box::new(WriteOwner(vec![0; bytes].into())), bytes).unwrap()
}

fn counting_reader(drops: &Arc<AtomicUsize>) -> ActiveReader {
    ActiveReader::new_unleased_for_test(
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
    let mut batch = TransferBatch::new(16, 1 << 20, 1 << 20).unwrap();
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
fn per_region_limit_applies_to_logical_not_page_rounded_length() {
    let mut batch = TransferBatch::new(16, 17, 1 << 20).unwrap();
    batch
        .add(prepared(1, WriterEndpoint::Coordinator, 17))
        .unwrap();
    assert_eq!(
        batch.add(prepared(2, WriterEndpoint::Receiver, 18)),
        Err(BatchError::InvalidRegionLength)
    );
}

#[test]
fn zero_and_seventeen_region_batches_fail_closed() {
    assert!(matches!(
        TransferBatch::new(0, 1, 1),
        Err(BatchError::TooManyRegions)
    ));
    assert!(matches!(
        TransferBatch::new(17, 1, 1),
        Err(BatchError::TooManyRegions)
    ));
    assert!(matches!(
        TransferBatch::new(16, 1024, 1024).unwrap().into_pending(),
        Err(BatchError::Empty)
    ));
    let mut batch = TransferBatch::new(16, 1 << 20, 1 << 20).unwrap();
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
    let mut batch = TransferBatch::new(16, 1 << 20, 1 << 20).unwrap();
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

    let mut mismatch = TransferBatch::new(16, 1 << 20, 1 << 20).unwrap();
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
    let mut batch = TransferBatch::new(16, exact_one_mapping, exact_one_mapping).unwrap();
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
        let mut batch = TransferBatch::new(16, 1 << 20, 1 << 20).unwrap();
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
        let mut batch = TransferBatch::new(16, 1 << 20, 1 << 20).unwrap();
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
        let mut batch = TransferBatch::new(16, 1 << 20, 1 << 20).unwrap();
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
