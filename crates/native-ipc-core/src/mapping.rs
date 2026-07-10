//! Audited conversion from native mapping witnesses to atomic capabilities.

use core::fmt;
use core::mem::{align_of, size_of};
use core::ptr::NonNull;

use crate::layout::{LayoutError, RegionSetLayout, RoleId, ValidatedRegionLayout};
use crate::slot::{
    AcknowledgementCell, AcknowledgementReader, AcknowledgementWriter, ReaderSlot, SlotError,
    SlotMetadata, WriterSlot,
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
mod tests {
    use super::*;
    use crate::layout::{
        AcknowledgementRouteSpec, Endpoint, LayoutLimits, RegionSetLayout, RegionSpec, RoleId,
        ValidationExpectations,
    };
    use std::alloc::{Layout, alloc_zeroed, dealloc};

    struct Allocation {
        base: NonNull<u8>,
        len: usize,
    }

    impl Allocation {
        fn new(len: usize) -> Self {
            let layout = Layout::from_size_align(len, 64).unwrap();
            let base = NonNull::new(unsafe { alloc_zeroed(layout) }).unwrap();
            Self { base, len }
        }
        fn bytes_mut(&mut self) -> &mut [u8] {
            unsafe { core::slice::from_raw_parts_mut(self.base.as_ptr(), self.len) }
        }
        fn bytes(&self) -> &[u8] {
            unsafe { core::slice::from_raw_parts(self.base.as_ptr(), self.len) }
        }
    }
    impl Drop for Allocation {
        fn drop(&mut self) {
            unsafe {
                dealloc(
                    self.base.as_ptr(),
                    Layout::from_size_align(self.len, 64).unwrap(),
                )
            }
        }
    }

    struct ReaderWitness<'a>(&'a Allocation);
    struct WriterWitness<'a>(&'a mut Allocation);
    unsafe impl ReadOnlyMapping for ReaderWitness<'_> {
        fn base(&self) -> NonNull<u8> {
            self.0.base
        }
        fn len(&self) -> usize {
            self.0.len
        }
    }
    unsafe impl SoleWriterMapping for WriterWitness<'_> {
        fn base(&self) -> NonNull<u8> {
            self.0.base
        }
        fn len(&self) -> usize {
            self.0.len
        }
    }

    #[test]
    fn initialize_validate_bind_publish_recheck_and_acknowledge() {
        let producer = RoleId::new(1).unwrap();
        let acknowledger = RoleId::new(2).unwrap();
        let specs = [
            RegionSpec {
                role: producer,
                writer: Endpoint::Initiator,
                slot_count: 1,
                payload_bytes: 16,
                acknowledgement_count: 1,
            },
            RegionSpec {
                role: acknowledger,
                writer: Endpoint::Responder,
                slot_count: 1,
                payload_bytes: 16,
                acknowledgement_count: 1,
            },
        ];
        let route_specs = [
            AcknowledgementRouteSpec {
                owner: acknowledger,
                target: producer,
                slot_index: 0,
                cell_index: 0,
            },
            AcknowledgementRouteSpec {
                owner: producer,
                target: acknowledger,
                slot_index: 0,
                cell_index: 0,
            },
        ];
        let limits = LayoutLimits {
            maximum_mapping_size: 4096,
            maximum_slot_count: 2,
            maximum_acknowledgement_count: 2,
            maximum_payload_bytes: 64,
        };
        let set = RegionSetLayout::calculate([7; 32], 9, &specs, &route_specs, limits).unwrap();
        let producer_layout = set.region(producer).unwrap();
        let mut producer_memory = Allocation::new(producer_layout.total_size() as usize);
        producer_layout
            .encode_into(producer_memory.bytes_mut())
            .unwrap();
        let producer_validated = unsafe {
            ValidatedRegionLayout::validate(
                producer_memory.bytes(),
                ValidationExpectations {
                    schema_id: [7; 32],
                    generation: 9,
                    role: producer,
                    writer: Endpoint::Initiator,
                    maximum_mapping_size: 4096,
                },
                &set,
            )
        }
        .unwrap();

        let ack_layout = set.region(acknowledger).unwrap();
        let mut ack_memory = Allocation::new(ack_layout.total_size() as usize);
        ack_layout.encode_into(ack_memory.bytes_mut()).unwrap();
        let ack_validated = unsafe {
            ValidatedRegionLayout::validate(
                ack_memory.bytes(),
                ValidationExpectations {
                    schema_id: [7; 32],
                    generation: 9,
                    role: acknowledger,
                    writer: Endpoint::Responder,
                    maximum_mapping_size: 4096,
                },
                &set,
            )
        }
        .unwrap();

        {
            let mut writer = WriterRegion::new(
                WriterWitness(&mut producer_memory),
                producer_validated.clone(),
                set.clone(),
            )
            .unwrap();
            writer
                .slot(0)
                .unwrap()
                .prepare_publish(1, None)
                .unwrap()
                .publish(4)
                .unwrap();
        }
        let reader = ReaderRegion::new(
            ReaderWitness(&producer_memory),
            producer_validated,
            set.clone(),
        )
        .unwrap();
        let observation = reader.slot(0).unwrap().observe(1).unwrap();
        reader.slot(0).unwrap().recheck(observation).unwrap();

        {
            let mut ack_writer = WriterRegion::new(
                WriterWitness(&mut ack_memory),
                ack_validated.clone(),
                set.clone(),
            )
            .unwrap();
            ack_writer
                .acknowledgement(producer, 0)
                .unwrap()
                .acknowledge(observation)
                .unwrap();
        }
        let ack_reader = ReaderRegion::new(ReaderWitness(&ack_memory), ack_validated, set).unwrap();
        let acknowledged = ack_reader.acknowledgement(producer, 0).unwrap().observe();
        assert_eq!(acknowledged.sequence(), 1);
        assert_eq!(acknowledged.slot_index(), 0);
        assert_eq!(acknowledged.cell_index(), 0);
    }
}
