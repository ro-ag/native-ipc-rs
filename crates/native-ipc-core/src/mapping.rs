//! Audited conversion from native mapping witnesses to atomic capabilities.

use alloc::vec::Vec;
use core::fmt;
use core::mem::{align_of, size_of};
use core::ptr::NonNull;

use crate::layout::{LayoutError, RegionSetLayout, RoleId, ValidatedRegionLayout};
use crate::slot::{
    AcknowledgementCell, AcknowledgementObservation, AcknowledgementReader, AcknowledgementWriter,
    ReaderSlot, SlotError, SlotMetadata, WriterSlot,
};

/// Native read-only mapping witness consumed by the audited binding boundary.
///
/// # Safety
///
/// The base and length must describe one live, initialized allocation for the
/// witness lifetime. It must be OS-enforced read-only locally, cover exactly
/// the bytes used to create the supplied `ValidatedRegionLayout`, and remain
/// mapped while a bound region owns the witness.
pub unsafe trait ReadOnlyMapping {
    /// Mapping base with allocation provenance.
    fn base(&self) -> NonNull<u8>;
    /// Exact native capability size.
    fn len(&self) -> usize;
    /// Returns whether the capability is empty (valid witnesses are not).
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Native sole-writer mapping witness consumed by the audited binding boundary.
///
/// # Safety
///
/// In addition to the allocation requirements of `ReadOnlyMapping`, this must
/// be the only writable mapping for the region and safe code must be unable to
/// duplicate the witness or recover a second writer while it is owned here.
pub unsafe trait SoleWriterMapping {
    /// Mapping base with allocation provenance.
    fn base(&self) -> NonNull<u8>;
    /// Exact native capability size.
    fn len(&self) -> usize;
    /// Returns whether the capability is empty (valid witnesses are not).
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Failure to bind a validated layout to its native mapping witness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BindingError {
    /// Native capability size differs from the validated range.
    MappingSizeMismatch {
        /// Size validated while the mapping was quiescent.
        expected: usize,
        /// Size reported by the platform witness.
        actual: usize,
    },
    /// Checked record address is not aligned for its atomic representation.
    MisalignedRecord,
    /// Validated layout rejected the selected route or index.
    Layout(LayoutError),
    /// Shared metadata no longer matches its validated generation.
    Slot(SlotError),
    /// Owned payload snapshot allocation failed.
    AllocationFailed,
    /// Caller payload length cannot be represented by the fixed protocol field.
    PayloadLengthOverflow,
    /// Validated mapping does not belong to the supplied composed topology.
    TopologyMismatch,
    /// Composed topology has no exact route for the requested target slot.
    MissingRoute {
        /// Producer role requested from the bound topology.
        target: RoleId,
        /// Producer slot requested from the bound topology.
        slot: u32,
    },
}

impl fmt::Display for BindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "mapping binding failed: {self:?}")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for BindingError {}

impl From<LayoutError> for BindingError {
    fn from(value: LayoutError) -> Self {
        Self::Layout(value)
    }
}

impl From<SlotError> for BindingError {
    fn from(value: SlotError) -> Self {
        Self::Slot(value)
    }
}

/// Mapping-lifetime owner that can mint acquire-only capabilities.
pub struct ReaderRegion<M> {
    mapping: M,
    layout: ValidatedRegionLayout,
    topology: RegionSetLayout,
}

impl<M: ReadOnlyMapping> ReaderRegion<M> {
    /// Consumes a platform-minted read-only witness.
    pub fn new(
        mapping: M,
        layout: ValidatedRegionLayout,
        topology: RegionSetLayout,
    ) -> Result<Self, BindingError> {
        validate_mapping_size(mapping.len(), &layout)?;
        validate_topology(&layout, &topology)?;
        Ok(Self {
            mapping,
            layout,
            topology,
        })
    }

    /// Binds one checked slot without exposing shared bytes.
    pub fn slot(&self, slot: u32) -> Result<ReaderSlot<'_>, BindingError> {
        let binding = self.layout.reader_slot_binding(slot)?;
        let range = self.layout.slot_range(slot)?;
        let header = record::<SlotMetadata, _>(
            &self.mapping,
            self.mapping.base(),
            range.start,
            range.len(),
        )?;
        // SAFETY: the witness contract supplies provenance, lifetime, exact
        // validation, and local read-only permission; `record` checked bounds/alignment.
        Ok(unsafe { ReaderSlot::bind(header, binding) }?)
    }

    /// Copies one bounded hostile payload and rechecks its publication metadata.
    ///
    /// Same-sequence malicious mutation can still produce torn bytes; the
    /// returned owned buffer must be decoded as hostile input.
    pub fn copy_payload(&self, slot: u32, expected_sequence: u64) -> Result<Vec<u8>, BindingError> {
        let observation = self.slot(slot)?.observe(expected_sequence)?;
        let range = self
            .layout
            .slot_payload_range(slot, observation.payload_len())?;
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(range.len())
            .map_err(|_| BindingError::AllocationFailed)?;
        // SAFETY: the read-only witness keeps this validated range mapped and
        // readable; the reserved owned destination is disjoint shared memory.
        unsafe {
            owned.set_len(range.len());
            core::ptr::copy_nonoverlapping(
                self.mapping.base().as_ptr().add(range.start),
                owned.as_mut_ptr(),
                range.len(),
            );
        }
        self.slot(slot)?.recheck(observation)?;
        Ok(owned)
    }

    /// Binds one checked acknowledgement route without exposing shared bytes.
    pub fn acknowledgement(
        &self,
        target: RoleId,
        slot: u32,
    ) -> Result<AcknowledgementReader<'_>, BindingError> {
        let route = self
            .topology
            .acknowledgement_route(target, slot)
            .ok_or(BindingError::MissingRoute { target, slot })?;
        let binding = self.layout.acknowledgement_reader_binding(route)?;
        let range = self.layout.acknowledgement_range(route.cell_index())?;
        let cell = record::<AcknowledgementCell, _>(
            &self.mapping,
            self.mapping.base(),
            range.start,
            range.len(),
        )?;
        // SAFETY: same witness and checked-record proof as `slot`.
        Ok(unsafe { AcknowledgementReader::bind(cell, binding) })
    }
}

/// Mapping-lifetime owner that prevents duplicate safe writer binding.
pub struct WriterRegion<M> {
    mapping: M,
    layout: ValidatedRegionLayout,
    topology: RegionSetLayout,
}

impl<M: SoleWriterMapping> WriterRegion<M> {
    /// Consumes a platform-minted unique writer witness.
    pub fn new(
        mapping: M,
        layout: ValidatedRegionLayout,
        topology: RegionSetLayout,
    ) -> Result<Self, BindingError> {
        validate_mapping_size(mapping.len(), &layout)?;
        validate_topology(&layout, &topology)?;
        Ok(Self {
            mapping,
            layout,
            topology,
        })
    }

    /// Exclusively binds one checked producer slot.
    pub fn slot(&mut self, slot: u32) -> Result<WriterSlot<'_>, BindingError> {
        let target = self.layout.role();
        let route = self
            .topology
            .acknowledgement_route(target, slot)
            .ok_or(BindingError::MissingRoute { target, slot })?;
        let binding = self.layout.writer_slot_binding(route)?;
        let range = self.layout.slot_range(route.slot_index())?;
        let header = record::<SlotMetadata, _>(
            &self.mapping,
            self.mapping.base(),
            range.start,
            range.len(),
        )?;
        // SAFETY: consuming the unique witness and borrowing `self` mutably
        // prevent a second safe writer capability while this borrow is live.
        Ok(unsafe { WriterSlot::bind(header, binding) }?)
    }

    /// Copies an owned caller payload into a checked slot and publishes it.
    pub fn publish(
        &mut self,
        slot: u32,
        sequence: u64,
        acknowledgement: Option<AcknowledgementObservation>,
        payload: &[u8],
    ) -> Result<(), BindingError> {
        let payload_len =
            u32::try_from(payload.len()).map_err(|_| BindingError::PayloadLengthOverflow)?;
        let range = self.layout.slot_payload_range(slot, payload_len)?;
        let base = self.mapping.base();
        let mut bound_slot = self.slot(slot)?;
        let reservation = bound_slot.prepare_publish(sequence, acknowledgement)?;
        // SAFETY: the unique writer witness and `&mut self` exclude other
        // writers; the checked payload range is disjoint from slot metadata.
        unsafe {
            core::ptr::copy_nonoverlapping(
                payload.as_ptr(),
                base.as_ptr().add(range.start),
                payload.len(),
            );
        }
        reservation.publish(payload_len)?;
        Ok(())
    }

    /// Exclusively binds one checked acknowledgement cell.
    pub fn acknowledgement(
        &mut self,
        target: RoleId,
        slot: u32,
    ) -> Result<AcknowledgementWriter<'_>, BindingError> {
        let route = self
            .topology
            .acknowledgement_route(target, slot)
            .ok_or(BindingError::MissingRoute { target, slot })?;
        let binding = self.layout.acknowledgement_writer_binding(route)?;
        let range = self.layout.acknowledgement_range(route.cell_index())?;
        let cell = record::<AcknowledgementCell, _>(
            &self.mapping,
            self.mapping.base(),
            range.start,
            range.len(),
        )?;
        // SAFETY: same unique witness and exclusive-borrow proof as `slot`.
        Ok(unsafe { AcknowledgementWriter::bind(cell, binding) })
    }
}

fn validate_mapping_size(
    actual: usize,
    layout: &ValidatedRegionLayout,
) -> Result<(), BindingError> {
    if actual == layout.mapping_size() {
        Ok(())
    } else {
        Err(BindingError::MappingSizeMismatch {
            expected: layout.mapping_size(),
            actual,
        })
    }
}

fn validate_topology(
    layout: &ValidatedRegionLayout,
    topology: &RegionSetLayout,
) -> Result<(), BindingError> {
    if layout.matches_topology(topology) {
        Ok(())
    } else {
        Err(BindingError::TopologyMismatch)
    }
}

fn record<T, M>(
    _owner: &M,
    base: NonNull<u8>,
    offset: usize,
    available: usize,
) -> Result<&T, BindingError> {
    if available < size_of::<T>() {
        return Err(BindingError::Layout(LayoutError::RangeOutOfBounds));
    }
    // SAFETY: offset was checked against the validated mapping; the witness
    // retains the allocation and provenance. The returned lifetime is narrowed
    // immediately by the caller to its borrow of the owning region.
    let pointer = unsafe { base.as_ptr().add(offset) }.cast::<T>();
    if !(pointer as usize).is_multiple_of(align_of::<T>()) {
        return Err(BindingError::MisalignedRecord);
    }
    // SAFETY: validation established initialization and `T`'s field offsets;
    // alignment and complete record bounds were checked above.
    Ok(unsafe { &*pointer })
}

#[cfg(test)]
#[path = "mapping_test.rs"]
mod tests;
