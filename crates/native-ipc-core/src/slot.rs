//! Generation-bound, role-bound slot and acknowledgement capabilities.

use core::cell::{Cell, UnsafeCell};
use core::fmt;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering, fence};

use crate::layout::{AcknowledgementRoute, RoleId};

#[cfg(not(target_has_atomic = "64"))]
compile_error!("native-ipc-core requires lock-free 64-bit atomic support");

/// Bytes occupied by one cache-line-aligned slot metadata record.
pub const SLOT_HEADER_SIZE: u64 = 64;
/// Bytes occupied by one cache-line-aligned acknowledgement cell.
pub const ACKNOWLEDGEMENT_CELL_SIZE: u64 = 64;

/// Writer-owned atomic publication metadata for one fixed-capacity slot.
///
/// This type is an in-memory concurrency record, not a serializable Rust wire
/// layout. A region layout fixes its offsets and requires 64-bit atomics.
#[repr(C, align(64))]
#[derive(Debug)]
pub struct SlotMetadata {
    generation: AtomicU64,
    payload_len: AtomicU32,
    reserved_word: UnsafeCell<u32>,
    published_sequence: AtomicU64,
    reserved: UnsafeCell<[u8; 40]>,
}

impl SlotMetadata {
    /// Creates unpublished metadata in quiescent, process-local storage.
    pub const fn new(generation: u64) -> Self {
        Self {
            generation: AtomicU64::new(generation),
            payload_len: AtomicU32::new(0),
            reserved_word: UnsafeCell::new(0),
            published_sequence: AtomicU64::new(0),
            reserved: UnsafeCell::new([0; 40]),
        }
    }

    /// Reinitializes metadata before any peer can access the mapping.
    ///
    /// # Safety
    ///
    /// No peer process or concurrent thread may access this slot until the
    /// initialization and all associated payload initialization complete.
    pub unsafe fn initialize(&mut self, generation: u64) -> Result<(), SlotError> {
        if generation == 0 {
            return Err(SlotError::ZeroGeneration);
        }
        *self.generation.get_mut() = generation;
        *self.payload_len.get_mut() = 0;
        // SAFETY: `&mut self` and the function contract exclude all aliases.
        unsafe { *self.reserved_word.get() = 0 };
        *self.published_sequence.get_mut() = 0;
        // SAFETY: `&mut self` and the function contract exclude all aliases.
        unsafe { *self.reserved.get() = [0; 40] };
        Ok(())
    }
}

// SAFETY: live fields are accessed only through atomics. `UnsafeCell` makes
// peer mutation of padding explicit; protocol code never reads that padding
// after quiescent validation. Peers must use compatible aligned atomics for
// atomic fields.
unsafe impl Sync for SlotMetadata {}

/// A single writer-owned atomic acknowledgement sequence.
#[repr(C, align(64))]
pub struct AcknowledgementCell {
    sequence: AtomicU64,
    reserved: UnsafeCell<[u8; 56]>,
}

impl AcknowledgementCell {
    /// Creates a zero/unpublished cell in quiescent storage.
    pub const fn new() -> Self {
        Self {
            sequence: AtomicU64::new(0),
            reserved: UnsafeCell::new([0; 56]),
        }
    }

    /// Reinitializes this cell before peer access.
    ///
    /// # Safety
    ///
    /// No peer process or concurrent thread may access this cell.
    pub unsafe fn initialize(&mut self) {
        *self.sequence.get_mut() = 0;
        // SAFETY: `&mut self` and the function contract exclude all aliases.
        unsafe { *self.reserved.get() = [0; 56] };
    }
}

// SAFETY: `sequence` is atomic and externally mutable padding is never read
// after quiescent validation.
unsafe impl Sync for AcknowledgementCell {}

impl Default for AcknowledgementCell {
    fn default() -> Self {
        Self::new()
    }
}

/// Immutable facts for a slot in a validated writable mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WriterSlotBinding(SlotBinding);

impl WriterSlotBinding {
    pub(crate) const fn validated(
        role: RoleId,
        generation: u64,
        payload_capacity: u32,
        slot_index: u32,
        slot_count: u32,
        acknowledgement_owner: RoleId,
        acknowledgement_cell_index: u32,
    ) -> Self {
        Self(SlotBinding {
            role,
            generation,
            payload_capacity,
            slot_index,
            slot_count,
            acknowledgement_owner: Some(acknowledgement_owner),
            acknowledgement_cell_index: Some(acknowledgement_cell_index),
        })
    }
}

/// Immutable facts for a slot in a validated read-only mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReaderSlotBinding(SlotBinding);

impl ReaderSlotBinding {
    pub(crate) const fn validated(
        role: RoleId,
        generation: u64,
        payload_capacity: u32,
        slot_index: u32,
        slot_count: u32,
    ) -> Self {
        Self(SlotBinding {
            role,
            generation,
            payload_capacity,
            slot_index,
            slot_count,
            acknowledgement_owner: None,
            acknowledgement_cell_index: None,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SlotBinding {
    role: RoleId,
    generation: u64,
    payload_capacity: u32,
    slot_index: u32,
    slot_count: u32,
    acknowledgement_owner: Option<RoleId>,
    acknowledgement_cell_index: Option<u32>,
}

/// Sole-writer capability bound to a validated writable mapping.
pub struct WriterSlot<'a> {
    header: &'a SlotMetadata,
    binding: SlotBinding,
    _not_sync: PhantomData<Cell<()>>,
}

impl<'a> WriterSlot<'a> {
    /// Binds atomic metadata reached through the sole writer's mapping.
    ///
    /// # Safety
    ///
    /// `header` must reside at the checked slot offset represented by
    /// `binding`. This process must be the only holder of a writable mapping,
    /// and the mapping must remain live for `'a`. No other writer capability
    /// may be bound for this slot while this value exists.
    pub unsafe fn bind(
        header: &'a SlotMetadata,
        binding: WriterSlotBinding,
    ) -> Result<Self, SlotError> {
        validate_bound_generation(header, binding.0.generation)?;
        Ok(Self {
            header,
            binding: binding.0,
            _not_sync: PhantomData,
        })
    }

    /// Checks sequence/slot/reuse invariants before payload mutation begins.
    pub fn prepare_publish(
        &mut self,
        sequence: u64,
        acknowledgement: Option<AcknowledgementObservation>,
    ) -> Result<PublishReservation<'_>, SlotError> {
        validate_bound_generation(self.header, self.binding.generation)?;
        validate_sequence_slot(self.binding, sequence)?;
        let current = self.header.published_sequence.load(Ordering::Relaxed);
        if current == 0 {
            let expected = u64::from(self.binding.slot_index) + 1;
            if sequence != expected {
                return Err(SlotError::UnexpectedFirstSequence {
                    expected,
                    actual: sequence,
                });
            }
        } else {
            let expected = current
                .checked_add(u64::from(self.binding.slot_count))
                .ok_or(SlotError::SequenceWrap)?;
            if sequence != expected {
                return Err(SlotError::UnexpectedNextSequence {
                    expected,
                    actual: sequence,
                });
            }
            let acknowledgement =
                acknowledgement.ok_or(SlotError::MissingAcknowledgement { sequence: current })?;
            if acknowledgement.target != self.binding.role {
                return Err(SlotError::WrongAcknowledgementTarget);
            }
            if acknowledgement.owner != self.binding.acknowledgement_owner.unwrap() {
                return Err(SlotError::WrongAcknowledgementOwner);
            }
            if acknowledgement.slot_index != self.binding.slot_index {
                return Err(SlotError::WrongAcknowledgementSlot);
            }
            if acknowledgement.cell_index != self.binding.acknowledgement_cell_index.unwrap() {
                return Err(SlotError::WrongAcknowledgementCell);
            }
            if acknowledgement.generation != self.binding.generation {
                return Err(SlotError::StaleAcknowledgementGeneration);
            }
            if acknowledgement.sequence < current {
                return Err(SlotError::LaggingAcknowledgement {
                    expected: current,
                    actual: acknowledgement.sequence,
                });
            }
            if acknowledgement.sequence > current {
                return Err(SlotError::FutureAcknowledgement {
                    expected: current,
                    actual: acknowledgement.sequence,
                });
            }
        }
        Ok(PublishReservation {
            header: self.header,
            sequence,
            capacity: self.binding.payload_capacity,
            _exclusive: PhantomData,
        })
    }
}

/// Acquire-only capability bound to a validated read-only mapping.
pub struct ReaderSlot<'a> {
    header: &'a SlotMetadata,
    binding: SlotBinding,
}

impl<'a> ReaderSlot<'a> {
    /// Binds atomic metadata reached through a read-only native mapping.
    ///
    /// # Safety
    ///
    /// `header` must reside at the checked slot offset represented by
    /// `binding`, be readable for `'a`, and must not be reached through a
    /// writable mapping in this process.
    pub unsafe fn bind(
        header: &'a SlotMetadata,
        binding: ReaderSlotBinding,
    ) -> Result<Self, SlotError> {
        validate_bound_generation(header, binding.0.generation)?;
        Ok(Self {
            header,
            binding: binding.0,
        })
    }

    /// Acquires and validates publication metadata before an owned payload copy.
    pub fn observe(&self, expected_sequence: u64) -> Result<SlotObservation, SlotError> {
        validate_sequence_slot(self.binding, expected_sequence)?;
        let sequence = self.header.published_sequence.load(Ordering::Acquire);
        if sequence != expected_sequence {
            return Err(SlotError::StaleSequence {
                expected: expected_sequence,
                actual: sequence,
            });
        }
        validate_bound_generation(self.header, self.binding.generation)?;
        let payload_len = self.header.payload_len.load(Ordering::Relaxed);
        if payload_len > self.binding.payload_capacity {
            return Err(SlotError::PayloadTooLarge {
                length: payload_len,
                capacity: self.binding.payload_capacity,
            });
        }
        Ok(SlotObservation {
            role: self.binding.role,
            slot_index: self.binding.slot_index,
            generation: self.binding.generation,
            sequence,
            payload_len,
        })
    }

    /// Rechecks metadata stability after copying hostile bytes to owned storage.
    ///
    /// This detects metadata changes, not payload integrity. A malicious writer
    /// can mutate bytes without changing metadata; callers must parse every
    /// owned payload copy as hostile input.
    pub fn recheck(&self, observation: SlotObservation) -> Result<(), SlotError> {
        if observation.role != self.binding.role {
            return Err(SlotError::WrongObservationRole);
        }
        if observation.generation != self.binding.generation {
            return Err(SlotError::StaleGeneration {
                expected: self.binding.generation,
                actual: observation.generation,
            });
        }
        // Keep preceding payload reads before the final metadata loads on
        // weakly ordered hardware.
        fence(Ordering::SeqCst);
        let sequence = self.header.published_sequence.load(Ordering::Acquire);
        if sequence != observation.sequence {
            return Err(SlotError::StaleSequence {
                expected: observation.sequence,
                actual: sequence,
            });
        }
        validate_bound_generation(self.header, observation.generation)?;
        let payload_len = self.header.payload_len.load(Ordering::Relaxed);
        if payload_len != observation.payload_len {
            return Err(SlotError::ChangedPayloadLength {
                expected: observation.payload_len,
                actual: payload_len,
            });
        }
        Ok(())
    }
}

/// Permission to publish metadata after the caller has written the payload.
#[must_use = "payload bytes remain unpublished until publish is called"]
#[derive(Debug)]
pub struct PublishReservation<'a> {
    header: &'a SlotMetadata,
    sequence: u64,
    capacity: u32,
    _exclusive: PhantomData<&'a mut ()>,
}

impl PublishReservation<'_> {
    /// Stores length, then Release-publishes the nonzero sequence.
    pub fn publish(self, payload_len: u32) -> Result<(), SlotError> {
        if payload_len > self.capacity {
            return Err(SlotError::PayloadTooLarge {
                length: payload_len,
                capacity: self.capacity,
            });
        }
        self.header
            .payload_len
            .store(payload_len, Ordering::Relaxed);
        self.header
            .published_sequence
            .store(self.sequence, Ordering::Release);
        Ok(())
    }
}

/// Owned identity observed before copying a slot payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SlotObservation {
    role: RoleId,
    slot_index: u32,
    generation: u64,
    sequence: u64,
    payload_len: u32,
}

impl SlotObservation {
    /// Returns the producer region role.
    pub const fn role(self) -> RoleId {
        self.role
    }
    /// Returns the exact observed slot index.
    pub const fn slot_index(self) -> u32 {
        self.slot_index
    }
    /// Returns the connection generation.
    pub const fn generation(self) -> u64 {
        self.generation
    }
    /// Returns the published sequence.
    pub const fn sequence(self) -> u64 {
        self.sequence
    }
    /// Returns the validated payload length.
    pub const fn payload_len(self) -> u32 {
        self.payload_len
    }
}

/// Immutable route metadata for a writable acknowledgement mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcknowledgementWriterBinding(AcknowledgementBinding);

impl AcknowledgementWriterBinding {
    pub(crate) const fn validated(route: AcknowledgementRoute, generation: u64) -> Self {
        Self(AcknowledgementBinding {
            owner: route.owner(),
            target: route.target(),
            slot_index: route.slot_index(),
            cell_index: route.cell_index(),
            generation,
        })
    }
}

/// Immutable route metadata for a read-only acknowledgement mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcknowledgementReaderBinding(AcknowledgementBinding);

impl AcknowledgementReaderBinding {
    pub(crate) const fn validated(route: AcknowledgementRoute, generation: u64) -> Self {
        Self(AcknowledgementBinding {
            owner: route.owner(),
            target: route.target(),
            slot_index: route.slot_index(),
            cell_index: route.cell_index(),
            generation,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AcknowledgementBinding {
    owner: RoleId,
    target: RoleId,
    slot_index: u32,
    cell_index: u32,
    generation: u64,
}

/// Release-store capability for a cell in a writable mapping.
pub struct AcknowledgementWriter<'a> {
    cell: &'a AcknowledgementCell,
    binding: AcknowledgementBinding,
    _not_sync: PhantomData<Cell<()>>,
}

impl<'a> AcknowledgementWriter<'a> {
    /// Binds a cell reached through its owner's writable mapping.
    ///
    /// # Safety
    ///
    /// `cell` must be the checked route cell described by `binding`; this
    /// process must be the only writer of its containing mapping. No other
    /// writer capability may be bound for this route while this value exists.
    pub unsafe fn bind(
        cell: &'a AcknowledgementCell,
        binding: AcknowledgementWriterBinding,
    ) -> Self {
        Self {
            cell,
            binding: binding.0,
            _not_sync: PhantomData,
        }
    }

    /// Acknowledges an exact observed slot identity with Release ordering.
    pub fn acknowledge(
        &mut self,
        observation: SlotObservation,
    ) -> Result<(), AcknowledgementError> {
        if observation.role != self.binding.target {
            return Err(AcknowledgementError::WrongTarget);
        }
        if observation.generation != self.binding.generation {
            return Err(AcknowledgementError::StaleGeneration);
        }
        if observation.slot_index != self.binding.slot_index {
            return Err(AcknowledgementError::WrongSlot);
        }
        if observation.sequence == 0 {
            return Err(AcknowledgementError::UnpublishedSequence);
        }
        let current = self.cell.sequence.load(Ordering::Relaxed);
        if observation.sequence < current {
            return Err(AcknowledgementError::NonMonotonic {
                current,
                next: observation.sequence,
            });
        }
        if observation.sequence == current {
            return Ok(());
        }
        self.cell
            .sequence
            .store(observation.sequence, Ordering::Release);
        Ok(())
    }
}

/// Acquire-only capability for a cell in a read-only mapping.
pub struct AcknowledgementReader<'a> {
    cell: &'a AcknowledgementCell,
    binding: AcknowledgementBinding,
}

impl<'a> AcknowledgementReader<'a> {
    /// Binds a cell reached through a read-only mapping.
    ///
    /// # Safety
    ///
    /// `cell` must be the checked route cell described by `binding` and must
    /// remain readable for `'a`; this API must not be bound from a writable
    /// alias in the current process.
    pub unsafe fn bind(
        cell: &'a AcknowledgementCell,
        binding: AcknowledgementReaderBinding,
    ) -> Self {
        Self {
            cell,
            binding: binding.0,
        }
    }

    /// Acquire-observes the exact route identity and current sequence.
    pub fn observe(&self) -> AcknowledgementObservation {
        AcknowledgementObservation {
            owner: self.binding.owner,
            target: self.binding.target,
            generation: self.binding.generation,
            slot_index: self.binding.slot_index,
            cell_index: self.binding.cell_index,
            sequence: self.cell.sequence.load(Ordering::Acquire),
        }
    }
}

/// Owned acknowledgement identity passed to a slot writer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcknowledgementObservation {
    owner: RoleId,
    target: RoleId,
    generation: u64,
    slot_index: u32,
    cell_index: u32,
    sequence: u64,
}

impl AcknowledgementObservation {
    /// Returns the role that owns the acknowledgement mapping.
    pub const fn owner(self) -> RoleId {
        self.owner
    }
    /// Returns the acknowledged producer role.
    pub const fn target(self) -> RoleId {
        self.target
    }
    /// Returns the acknowledged generation.
    pub const fn generation(self) -> u64 {
        self.generation
    }
    /// Returns the acknowledged producer slot.
    pub const fn slot_index(self) -> u32 {
        self.slot_index
    }
    /// Returns the exact acknowledgement cell.
    pub const fn cell_index(self) -> u32 {
        self.cell_index
    }
    /// Returns the acknowledged sequence.
    pub const fn sequence(self) -> u64 {
        self.sequence
    }
}

/// Bounded slot validation failures.
#[allow(missing_docs)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SlotError {
    /// Generation zero is reserved.
    ZeroGeneration,
    /// Sequence zero is unpublished.
    UnpublishedSequence,
    /// Bound generation differs from shared metadata.
    StaleGeneration { expected: u64, actual: u64 },
    /// Sequence would wrap.
    SequenceWrap,
    /// Sequence points at a different ring slot.
    WrongSlot { expected: u32, actual: u32 },
    /// First use of a slot had a noncanonical sequence.
    UnexpectedFirstSequence { expected: u64, actual: u64 },
    /// Reuse was not exactly one ring rotation later.
    UnexpectedNextSequence { expected: u64, actual: u64 },
    /// Reuse lacked an acknowledgement.
    MissingAcknowledgement { sequence: u64 },
    /// Acknowledgement targets another producer role.
    WrongAcknowledgementTarget,
    /// Acknowledgement came from another routed owner.
    WrongAcknowledgementOwner,
    /// Acknowledgement belongs to another producer slot.
    WrongAcknowledgementSlot,
    /// Acknowledgement came from another cell.
    WrongAcknowledgementCell,
    /// Acknowledgement came from another generation.
    StaleAcknowledgementGeneration,
    /// Acknowledgement lags the exact prior publication.
    LaggingAcknowledgement { expected: u64, actual: u64 },
    /// Acknowledgement attempts to pre-authorize future reuse.
    FutureAcknowledgement { expected: u64, actual: u64 },
    /// Observed sequence differs from expectation.
    StaleSequence { expected: u64, actual: u64 },
    /// Peer-declared payload exceeds fixed capacity.
    PayloadTooLarge { length: u32, capacity: u32 },
    /// Payload length changed during the copy window.
    ChangedPayloadLength { expected: u32, actual: u32 },
    /// Observation belongs to another role.
    WrongObservationRole,
}

/// Bounded acknowledgement failures.
#[allow(missing_docs)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcknowledgementError {
    /// Slot observation targets another route.
    WrongTarget,
    /// Slot observation belongs to another generation.
    StaleGeneration,
    /// Slot observation belongs to another routed slot.
    WrongSlot,
    /// Sequence zero is unpublished.
    UnpublishedSequence,
    /// Acknowledgement moved backwards.
    NonMonotonic { current: u64, next: u64 },
}

impl fmt::Display for SlotError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "slot operation failed: {self:?}")
    }
}
impl fmt::Display for AcknowledgementError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "acknowledgement failed: {self:?}")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SlotError {}
#[cfg(feature = "std")]
impl std::error::Error for AcknowledgementError {}

fn validate_bound_generation(header: &SlotMetadata, expected: u64) -> Result<(), SlotError> {
    if expected == 0 {
        return Err(SlotError::ZeroGeneration);
    }
    let actual = header.generation.load(Ordering::Relaxed);
    if actual == expected {
        Ok(())
    } else {
        Err(SlotError::StaleGeneration { expected, actual })
    }
}

fn validate_sequence_slot(binding: SlotBinding, sequence: u64) -> Result<(), SlotError> {
    if sequence == 0 {
        return Err(SlotError::UnpublishedSequence);
    }
    let expected = ((sequence - 1) % u64::from(binding.slot_count)) as u32;
    if binding.slot_index == expected {
        Ok(())
    } else {
        Err(SlotError::WrongSlot {
            expected,
            actual: binding.slot_index,
        })
    }
}

const _: () = assert!(core::mem::size_of::<SlotMetadata>() == SLOT_HEADER_SIZE as usize);
const _: () = assert!(core::mem::align_of::<SlotMetadata>() == 64);
const _: () = assert!(core::mem::offset_of!(SlotMetadata, generation) == 0);
const _: () = assert!(core::mem::offset_of!(SlotMetadata, payload_len) == 8);
const _: () = assert!(core::mem::offset_of!(SlotMetadata, reserved_word) == 12);
const _: () = assert!(core::mem::offset_of!(SlotMetadata, published_sequence) == 16);
const _: () = assert!(core::mem::offset_of!(SlotMetadata, reserved) == 24);
const _: () = assert!(core::mem::size_of::<AcknowledgementCell>() == 64);
const _: () = assert!(core::mem::align_of::<AcknowledgementCell>() == 64);
const _: () = assert!(core::mem::offset_of!(AcknowledgementCell, sequence) == 0);
const _: () = assert!(core::mem::offset_of!(AcknowledgementCell, reserved) == 8);

#[cfg(test)]
mod tests {
    use super::*;

    const PRODUCER: RoleId = RoleId::new(1).unwrap();
    const ACK_OWNER: RoleId = RoleId::new(2).unwrap();
    const GENERATION: u64 = 9;

    fn writer_binding(slot: u32) -> WriterSlotBinding {
        WriterSlotBinding::validated(PRODUCER, GENERATION, 8, slot, 2, ACK_OWNER, slot)
    }

    const fn route(slot: u32) -> AcknowledgementRoute {
        AcknowledgementRoute::validated(ACK_OWNER, PRODUCER, slot, slot)
    }

    fn reader_binding(slot: u32) -> ReaderSlotBinding {
        ReaderSlotBinding::validated(PRODUCER, GENERATION, 8, slot, 2)
    }

    fn observation(sequence: u64) -> SlotObservation {
        SlotObservation {
            role: PRODUCER,
            slot_index: if sequence == 0 {
                0
            } else {
                ((sequence - 1) % 2) as u32
            },
            generation: GENERATION,
            sequence,
            payload_len: 4,
        }
    }

    #[test]
    fn writer_release_publishes_and_reader_acquires() {
        let header = SlotMetadata::new(GENERATION);
        {
            // SAFETY: local test storage has one simulated writer capability.
            let mut writer = unsafe { WriterSlot::bind(&header, writer_binding(0)) }.unwrap();
            writer.prepare_publish(1, None).unwrap().publish(4).unwrap();
        }
        // SAFETY: writer capability was dropped and test performs no mutation.
        let reader = unsafe { ReaderSlot::bind(&header, reader_binding(0)) }.unwrap();
        let observed = reader.observe(1).unwrap();
        assert_eq!(observed, observation(1));
        reader.recheck(observed).unwrap();
    }

    #[test]
    fn reuse_requires_exact_target_generation_and_prior_sequence() {
        let header = SlotMetadata::new(GENERATION);
        // SAFETY: local test storage has one writer capability and no aliases.
        let mut writer = unsafe { WriterSlot::bind(&header, writer_binding(0)) }.unwrap();
        writer.prepare_publish(1, None).unwrap().publish(4).unwrap();
        assert_eq!(
            writer.prepare_publish(3, None).unwrap_err(),
            SlotError::MissingAcknowledgement { sequence: 1 }
        );

        let exact = AcknowledgementObservation {
            owner: ACK_OWNER,
            target: PRODUCER,
            generation: GENERATION,
            slot_index: 0,
            cell_index: 0,
            sequence: 1,
        };
        writer
            .prepare_publish(3, Some(exact))
            .unwrap()
            .publish(2)
            .unwrap();

        let lagging = AcknowledgementObservation {
            sequence: 0,
            ..exact
        };
        assert!(matches!(
            writer.prepare_publish(5, Some(lagging)),
            Err(SlotError::LaggingAcknowledgement { .. })
        ));
        let future = AcknowledgementObservation {
            sequence: 4,
            ..exact
        };
        assert!(matches!(
            writer.prepare_publish(5, Some(future)),
            Err(SlotError::FutureAcknowledgement { .. })
        ));
        let wrong_target = AcknowledgementObservation {
            target: ACK_OWNER,
            sequence: 3,
            ..exact
        };
        assert_eq!(
            writer.prepare_publish(5, Some(wrong_target)).unwrap_err(),
            SlotError::WrongAcknowledgementTarget
        );
        let wrong_owner = AcknowledgementObservation {
            owner: PRODUCER,
            sequence: 3,
            ..exact
        };
        assert_eq!(
            writer.prepare_publish(5, Some(wrong_owner)).unwrap_err(),
            SlotError::WrongAcknowledgementOwner
        );
        let stale = AcknowledgementObservation {
            generation: GENERATION - 1,
            sequence: 3,
            ..exact
        };
        assert_eq!(
            writer.prepare_publish(5, Some(stale)).unwrap_err(),
            SlotError::StaleAcknowledgementGeneration
        );
    }

    #[test]
    fn acknowledgement_capabilities_are_split_and_monotonic() {
        let cell = AcknowledgementCell::new();
        let writer_binding = AcknowledgementWriterBinding::validated(route(0), GENERATION);
        {
            // SAFETY: local test storage has one simulated acknowledgement writer.
            let mut writer = unsafe { AcknowledgementWriter::bind(&cell, writer_binding) };
            writer.acknowledge(observation(1)).unwrap();
            writer.acknowledge(observation(1)).unwrap();
            writer.acknowledge(observation(3)).unwrap();
            assert_eq!(
                writer.acknowledge(observation(1)).unwrap_err(),
                AcknowledgementError::NonMonotonic {
                    current: 3,
                    next: 1
                }
            );
            assert!(matches!(
                writer.acknowledge(observation(0)),
                Err(AcknowledgementError::UnpublishedSequence)
            ));
        }
        let reader_binding = AcknowledgementReaderBinding::validated(route(0), GENERATION);
        // SAFETY: simulated writer was dropped; storage is immutable here.
        let reader = unsafe { AcknowledgementReader::bind(&cell, reader_binding) };
        let observed = reader.observe();
        assert_eq!(observed.owner(), ACK_OWNER);
        assert_eq!(observed.target(), PRODUCER);
        assert_eq!(observed.generation(), GENERATION);
        assert_eq!(observed.sequence(), 3);

        let mut terminal = AcknowledgementCell::new();
        *terminal.sequence.get_mut() = u64::MAX;
        let mut writer = unsafe {
            AcknowledgementWriter::bind(
                &terminal,
                AcknowledgementWriterBinding::validated(route(0), GENERATION),
            )
        };
        let maximum = SlotObservation {
            sequence: u64::MAX,
            slot_index: 0,
            ..observation(1)
        };
        writer.acknowledge(maximum).unwrap();
    }

    #[test]
    fn two_slot_routes_complete_multiple_rotations() {
        let headers = [SlotMetadata::new(GENERATION), SlotMetadata::new(GENERATION)];
        let cells = [AcknowledgementCell::new(), AcknowledgementCell::new()];
        let mut acknowledgements = [None, None];

        for sequence in 1..=6 {
            let slot = ((sequence - 1) % 2) as usize;
            let mut writer =
                unsafe { WriterSlot::bind(&headers[slot], writer_binding(slot as u32)) }.unwrap();
            writer
                .prepare_publish(sequence, acknowledgements[slot])
                .unwrap()
                .publish(4)
                .unwrap();
            let reader =
                unsafe { ReaderSlot::bind(&headers[slot], reader_binding(slot as u32)) }.unwrap();
            let observed = reader.observe(sequence).unwrap();
            reader.recheck(observed).unwrap();
            let binding = AcknowledgementWriterBinding::validated(route(slot as u32), GENERATION);
            let mut acknowledgement_writer =
                unsafe { AcknowledgementWriter::bind(&cells[slot], binding) };
            acknowledgement_writer.acknowledge(observed).unwrap();
            let binding = AcknowledgementReaderBinding::validated(route(slot as u32), GENERATION);
            let acknowledgement_reader =
                unsafe { AcknowledgementReader::bind(&cells[slot], binding) };
            acknowledgements[slot] = Some(acknowledgement_reader.observe());
        }

        let mut slot_zero = unsafe { WriterSlot::bind(&headers[0], writer_binding(0)) }.unwrap();
        let wrong_cell = AcknowledgementObservation {
            cell_index: 1,
            sequence: 5,
            ..acknowledgements[0].unwrap()
        };
        assert_eq!(
            slot_zero.prepare_publish(7, Some(wrong_cell)).unwrap_err(),
            SlotError::WrongAcknowledgementCell
        );
        let wrong_slot = AcknowledgementObservation {
            slot_index: 1,
            cell_index: 0,
            sequence: 5,
            ..acknowledgements[0].unwrap()
        };
        assert_eq!(
            slot_zero.prepare_publish(7, Some(wrong_slot)).unwrap_err(),
            SlotError::WrongAcknowledgementSlot
        );
    }

    #[test]
    fn production_interleaving_model_accepts_only_exact_prior_ack() {
        for current in [1_u64, 3, 5] {
            for acknowledged in 0..=current + 1 {
                let mut header = SlotMetadata::new(GENERATION);
                *header.published_sequence.get_mut() = current;
                let mut writer = unsafe { WriterSlot::bind(&header, writer_binding(0)) }.unwrap();
                let result = writer.prepare_publish(
                    current + 2,
                    Some(AcknowledgementObservation {
                        owner: ACK_OWNER,
                        target: PRODUCER,
                        generation: GENERATION,
                        slot_index: 0,
                        cell_index: 0,
                        sequence: acknowledged,
                    }),
                );
                assert_eq!(result.is_ok(), acknowledged == current);
            }
        }
    }

    #[test]
    fn recheck_detects_length_change_but_does_not_claim_payload_integrity() {
        let header = SlotMetadata::new(GENERATION);
        {
            let mut writer = unsafe { WriterSlot::bind(&header, writer_binding(0)) }.unwrap();
            writer.prepare_publish(1, None).unwrap().publish(4).unwrap();
        }
        let reader = unsafe { ReaderSlot::bind(&header, reader_binding(0)) }.unwrap();
        let observed = reader.observe(1).unwrap();
        header.payload_len.store(5, Ordering::Relaxed);
        assert_eq!(
            reader.recheck(observed).unwrap_err(),
            SlotError::ChangedPayloadLength {
                expected: 4,
                actual: 5
            }
        );
    }

    #[test]
    fn rejects_wrong_slot_zero_sequence_oversize_and_wrap() {
        let header = SlotMetadata::new(GENERATION);
        // SAFETY: local test storage has one writer capability.
        let mut writer = unsafe { WriterSlot::bind(&header, writer_binding(1)) }.unwrap();
        assert_eq!(
            writer.prepare_publish(0, None).unwrap_err(),
            SlotError::UnpublishedSequence
        );
        assert!(matches!(
            writer.prepare_publish(1, None),
            Err(SlotError::WrongSlot { .. })
        ));
        assert!(matches!(
            writer.prepare_publish(2, None).unwrap().publish(9),
            Err(SlotError::PayloadTooLarge { .. })
        ));

        let mut wrapped = SlotMetadata::new(GENERATION);
        *wrapped.published_sequence.get_mut() = u64::MAX;
        // SAFETY: separate local storage has one writer capability.
        let mut writer = unsafe { WriterSlot::bind(&wrapped, writer_binding(0)) }.unwrap();
        assert_eq!(
            writer
                .prepare_publish(
                    u64::MAX,
                    Some(AcknowledgementObservation {
                        owner: ACK_OWNER,
                        target: PRODUCER,
                        generation: GENERATION,
                        slot_index: 0,
                        cell_index: 0,
                        sequence: u64::MAX,
                    })
                )
                .unwrap_err(),
            SlotError::SequenceWrap
        );
    }
}
