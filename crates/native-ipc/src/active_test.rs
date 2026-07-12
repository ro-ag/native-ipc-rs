use super::*;
use crate::liveness::{LivenessState, ResourceError, ResourceOwner};
use crate::session::SessionLimits;
use std::sync::{Arc, Barrier};

impl ActiveReader {
    pub(crate) fn new_unleased_for_test(
        owner: Box<dyn ActiveReadOwner>,
        logical_len: usize,
    ) -> Result<Self, AccessError> {
        Self::from_owner(owner, logical_len)
    }
}

impl ActiveWriter {
    pub(crate) fn new_unleased_for_test(
        owner: Box<dyn ActiveWriteOwner>,
        logical_len: usize,
    ) -> Result<Self, AccessError> {
        Self::from_owner(owner, logical_len)
    }
}

impl LeaseReservation {
    pub(crate) fn complete_for_test(
        self,
        actual_mapped_len: u64,
    ) -> Result<RegionLease, ResourceError> {
        self.complete(actual_mapped_len)
    }
}

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
    let reader =
        ActiveReader::new_unleased_for_test(Box::new(ReaderOwner(vec![1, 2, 3, 4, 5].into())), 5)
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
        ActiveWriter::new_unleased_for_test(Box::new(WriterOwner(vec![0; 5].into())), 5).unwrap();
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
