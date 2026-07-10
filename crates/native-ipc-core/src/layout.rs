//! Checked construction and validation of independent directional regions.

use alloc::vec::Vec;
use core::fmt;
use core::ops::Range;

use crate::codec::{VERSION_MAJOR, VERSION_MINOR};
use crate::slot::{
    ACKNOWLEDGEMENT_CELL_SIZE, AcknowledgementReaderBinding, AcknowledgementWriterBinding,
    ReaderSlotBinding, SLOT_HEADER_SIZE, WriterSlotBinding,
};

/// Cache-line granularity used for concurrently accessed records.
pub const CACHE_LINE: u64 = 64;
/// Region signature stored in every mapping header.
pub const REGION_MAGIC: [u8; 8] = *b"NIPCREG\0";
/// Manually encoded region header size.
pub const REGION_HEADER_SIZE: u64 = 128;

/// A validated, nonzero numeric region role.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RoleId(u32);

impl RoleId {
    /// Creates a role, rejecting the reserved zero value.
    pub const fn new(value: u32) -> Option<Self> {
        if value == 0 { None } else { Some(Self(value)) }
    }

    /// Returns the fixed-width wire value.
    pub const fn get(self) -> u32 {
        self.0
    }
}

/// One of the two authenticated endpoints of a connection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Endpoint {
    /// Endpoint that initiated the connection.
    Initiator = 1,
    /// Endpoint accepted or inherited the connection.
    Responder = 2,
}

impl Endpoint {
    const fn from_raw(raw: u32) -> Option<Self> {
        match raw {
            1 => Some(Self::Initiator),
            2 => Some(Self::Responder),
            _ => None,
        }
    }
}

/// Actual permissions of the mapping through which validation occurred.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MappingPermissions {
    /// Peer-owned mapping: acquire-only APIs may be bound.
    ReadOnly,
    /// Locally owned mapping: release-store APIs may be bound.
    ReadWrite,
}

/// Capacity of one independently permissioned region.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RegionSpec {
    /// Numeric role unique within the connection.
    pub role: RoleId,
    /// Sole endpoint allowed to write this region.
    pub writer: Endpoint,
    /// Number of fixed-capacity ring slots.
    pub slot_count: u32,
    /// Maximum opaque payload bytes in each slot.
    pub payload_bytes: u32,
    /// Number of independently routed acknowledgement cells.
    pub acknowledgement_count: u32,
}

/// Bounds applied while calculating or validating a region.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LayoutLimits {
    /// Maximum complete mapping size.
    pub maximum_mapping_size: u64,
    /// Maximum slots in one region.
    pub maximum_slot_count: u32,
    /// Maximum acknowledgement cells in one region.
    pub maximum_acknowledgement_count: u32,
    /// Maximum opaque bytes in one slot.
    pub maximum_payload_bytes: u32,
}

/// Checked layouts for caller-configured independent directional regions.
#[derive(Clone, Debug)]
pub struct RegionSetLayout {
    regions: Vec<RegionLayout>,
}

impl RegionSetLayout {
    /// Calculates layouts and rejects empty or duplicate role sets.
    pub fn calculate(
        schema_id: [u8; 32],
        generation: u64,
        specs: &[RegionSpec],
        limits: LayoutLimits,
    ) -> Result<Self, LayoutError> {
        if generation == 0 {
            return Err(LayoutError::ZeroGeneration);
        }
        if specs.is_empty() {
            return Err(LayoutError::EmptyRegionSet);
        }
        let mut regions = Vec::new();
        regions
            .try_reserve_exact(specs.len())
            .map_err(|_| LayoutError::AllocationFailed)?;
        for (index, spec) in specs.iter().copied().enumerate() {
            if specs[..index].iter().any(|prior| prior.role == spec.role) {
                return Err(LayoutError::DuplicateRole(spec.role));
            }
            regions.push(RegionLayout::calculate(
                schema_id, generation, spec, limits,
            )?);
        }
        Ok(Self { regions })
    }

    /// Returns all independent layouts.
    pub fn regions(&self) -> &[RegionLayout] {
        &self.regions
    }

    /// Finds a layout by validated numeric role.
    pub fn region(&self, role: RoleId) -> Option<&RegionLayout> {
        self.regions.iter().find(|region| region.role() == role)
    }
}

/// Layout of one independent, single-writer mapping.
#[derive(Clone, Debug)]
pub struct RegionLayout {
    header: RegionHeader,
}

impl RegionLayout {
    fn calculate(
        schema_id: [u8; 32],
        generation: u64,
        spec: RegionSpec,
        limits: LayoutLimits,
    ) -> Result<Self, LayoutError> {
        validate_counts(spec, limits)?;
        let acknowledgement_offset = REGION_HEADER_SIZE;
        let acknowledgement_len = u64::from(spec.acknowledgement_count)
            .checked_mul(ACKNOWLEDGEMENT_CELL_SIZE)
            .ok_or(LayoutError::Overflow)?;
        let slots_offset = align_up(
            acknowledgement_offset
                .checked_add(acknowledgement_len)
                .ok_or(LayoutError::Overflow)?,
            CACHE_LINE,
        )?;
        let slot_stride = align_up(
            SLOT_HEADER_SIZE
                .checked_add(u64::from(spec.payload_bytes))
                .ok_or(LayoutError::Overflow)?,
            CACHE_LINE,
        )?;
        let slots_len = slot_stride
            .checked_mul(u64::from(spec.slot_count))
            .ok_or(LayoutError::Overflow)?;
        let total_size = slots_offset
            .checked_add(slots_len)
            .ok_or(LayoutError::Overflow)?;
        if slot_stride > u64::from(u32::MAX)
            || total_size > limits.maximum_mapping_size
            || total_size > usize::MAX as u64
        {
            return Err(LayoutError::LimitExceeded);
        }
        Ok(Self {
            header: RegionHeader {
                total_size,
                schema_id,
                generation,
                role: spec.role.get(),
                writer: spec.writer as u32,
                acknowledgement_offset,
                acknowledgement_count: spec.acknowledgement_count,
                acknowledgement_stride: ACKNOWLEDGEMENT_CELL_SIZE as u32,
                slots_offset,
                slot_count: spec.slot_count,
                slot_stride: slot_stride as u32,
                payload_capacity: spec.payload_bytes,
            },
        })
    }

    /// Returns the region role.
    pub const fn role(&self) -> RoleId {
        RoleId(self.header.role)
    }

    /// Returns the sole writer endpoint.
    pub const fn writer(&self) -> Endpoint {
        match Endpoint::from_raw(self.header.writer) {
            Some(writer) => writer,
            None => unreachable!(),
        }
    }

    /// Returns the exact mapping size.
    pub const fn total_size(&self) -> u64 {
        self.header.total_size
    }

    /// Returns the fixed slot count.
    pub const fn slot_count(&self) -> u32 {
        self.header.slot_count
    }

    /// Returns the per-slot payload capacity.
    pub const fn payload_capacity(&self) -> u32 {
        self.header.payload_capacity
    }

    /// Initializes a quiescent mapping with a manually encoded header and zero metadata.
    pub fn encode_into(&self, destination: &mut [u8]) -> Result<(), LayoutError> {
        let total = usize::try_from(self.header.total_size).map_err(|_| LayoutError::Overflow)?;
        if destination.len() < total {
            return Err(LayoutError::MappingTooSmall {
                required: self.header.total_size,
                actual: destination.len() as u64,
            });
        }
        destination[..total].fill(0);
        encode_header(
            &self.header,
            &mut destination[..REGION_HEADER_SIZE as usize],
        );
        for slot in 0..self.header.slot_count {
            let start = self.header.slots_offset as usize
                + slot as usize * self.header.slot_stride as usize;
            put_u64(destination, start, self.header.generation);
        }
        Ok(())
    }
}

/// Expected identity and actual OS permissions for mapping validation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValidationExpectations {
    /// Exact protocol schema.
    pub schema_id: [u8; 32],
    /// Exact nonzero connection generation.
    pub generation: u64,
    /// Expected numeric role.
    pub role: RoleId,
    /// Expected sole writer endpoint.
    pub writer: Endpoint,
    /// Maximum accepted complete mapping size.
    pub maximum_mapping_size: u64,
    /// Permissions of the native mapping used for runtime access.
    pub permissions: MappingPermissions,
}

/// Owned metadata and checked ranges copied from one validated mapping.
///
/// This type never retains or returns a slice into cross-process storage.
#[derive(Clone, Debug)]
pub struct ValidatedRegionLayout {
    header: RegionHeader,
    acknowledgements: Range<usize>,
    slots: Range<usize>,
    permissions: MappingPermissions,
}

impl ValidatedRegionLayout {
    /// Validates a mapping while it is quiescent and before peer mutation begins.
    ///
    /// # Safety
    ///
    /// No process may mutate `bytes` for the duration of this call. The caller
    /// must also truthfully supply the native mapping's permissions.
    pub unsafe fn validate(
        bytes: &[u8],
        expected: ValidationExpectations,
    ) -> Result<Self, LayoutError> {
        if expected.generation == 0 {
            return Err(LayoutError::ZeroGeneration);
        }
        if bytes.len() < REGION_HEADER_SIZE as usize {
            return Err(LayoutError::MappingTooSmall {
                required: REGION_HEADER_SIZE,
                actual: bytes.len() as u64,
            });
        }
        validate_header_encoding(&bytes[..REGION_HEADER_SIZE as usize])?;
        let header = decode_header(&bytes[..REGION_HEADER_SIZE as usize]);
        validate_header(&header, bytes.len(), expected)?;
        let acknowledgements_end = header
            .acknowledgement_offset
            .checked_add(
                u64::from(header.acknowledgement_count)
                    .checked_mul(u64::from(header.acknowledgement_stride))
                    .ok_or(LayoutError::Overflow)?,
            )
            .ok_or(LayoutError::Overflow)?;
        let acknowledgements = checked_range(
            header.acknowledgement_offset,
            acknowledgements_end,
            header.total_size,
            bytes.len(),
        )?;
        if bytes[acknowledgements.clone()]
            .iter()
            .any(|byte| *byte != 0)
        {
            return Err(LayoutError::AcknowledgementNotZero);
        }
        let minimum_stride = align_up(
            SLOT_HEADER_SIZE
                .checked_add(u64::from(header.payload_capacity))
                .ok_or(LayoutError::Overflow)?,
            CACHE_LINE,
        )?;
        if u64::from(header.slot_stride) != minimum_stride {
            return Err(LayoutError::BadSlotStride);
        }
        let slots_end = header
            .slots_offset
            .checked_add(
                u64::from(header.slot_stride)
                    .checked_mul(u64::from(header.slot_count))
                    .ok_or(LayoutError::Overflow)?,
            )
            .ok_or(LayoutError::Overflow)?;
        if slots_end != header.total_size {
            return Err(LayoutError::BadTotalSize);
        }
        let slots = checked_range(
            header.slots_offset,
            slots_end,
            header.total_size,
            bytes.len(),
        )?;
        for slot in 0..header.slot_count {
            let start = slots.start + slot as usize * header.slot_stride as usize;
            if get_u64(bytes, start) != header.generation
                || bytes[start + 8..start + SLOT_HEADER_SIZE as usize]
                    .iter()
                    .any(|byte| *byte != 0)
            {
                return Err(LayoutError::SlotMetadataNotInitialized);
            }
        }
        Ok(Self {
            header,
            acknowledgements,
            slots,
            permissions: expected.permissions,
        })
    }

    /// Returns the validated role.
    pub const fn role(&self) -> RoleId {
        RoleId(self.header.role)
    }

    /// Returns the validated generation.
    pub const fn generation(&self) -> u64 {
        self.header.generation
    }

    /// Returns the actual native mapping permission represented by this metadata.
    pub const fn permissions(&self) -> MappingPermissions {
        self.permissions
    }

    /// Returns a checked complete slot range without granting memory access.
    pub fn slot_range(&self, slot: u32) -> Result<Range<usize>, LayoutError> {
        if slot >= self.header.slot_count {
            return Err(LayoutError::SlotOutOfBounds {
                slot,
                count: self.header.slot_count,
            });
        }
        let start = self
            .slots
            .start
            .checked_add(slot as usize * self.header.slot_stride as usize)
            .ok_or(LayoutError::Overflow)?;
        let end = start
            .checked_add(self.header.slot_stride as usize)
            .ok_or(LayoutError::Overflow)?;
        Ok(start..end)
    }

    /// Binds metadata for a sole writer. Read-only mappings cannot call this successfully.
    pub fn writer_slot_binding(
        &self,
        slot: u32,
        acknowledgement_owner: RoleId,
    ) -> Result<WriterSlotBinding, LayoutError> {
        if self.permissions != MappingPermissions::ReadWrite {
            return Err(LayoutError::WrongMappingPermission);
        }
        self.slot_range(slot)?;
        Ok(WriterSlotBinding::validated(
            self.role(),
            self.generation(),
            self.header.payload_capacity,
            slot,
            self.header.slot_count,
            acknowledgement_owner,
        ))
    }

    /// Binds metadata for an acquire-only reader. Writable mappings are not treated as readers.
    pub fn reader_slot_binding(&self, slot: u32) -> Result<ReaderSlotBinding, LayoutError> {
        if self.permissions != MappingPermissions::ReadOnly {
            return Err(LayoutError::WrongMappingPermission);
        }
        self.slot_range(slot)?;
        Ok(ReaderSlotBinding::validated(
            self.role(),
            self.generation(),
            self.header.payload_capacity,
            slot,
            self.header.slot_count,
        ))
    }

    /// Returns a checked acknowledgement cell range without granting access.
    pub fn acknowledgement_range(&self, index: u32) -> Result<Range<usize>, LayoutError> {
        if index >= self.header.acknowledgement_count {
            return Err(LayoutError::AcknowledgementOutOfBounds {
                index,
                count: self.header.acknowledgement_count,
            });
        }
        let start = self
            .acknowledgements
            .start
            .checked_add(index as usize * self.header.acknowledgement_stride as usize)
            .ok_or(LayoutError::Overflow)?;
        let end = start
            .checked_add(self.header.acknowledgement_stride as usize)
            .ok_or(LayoutError::Overflow)?;
        Ok(start..end)
    }

    /// Binds a store-capable acknowledgement route only for a writable mapping.
    pub fn acknowledgement_writer_binding(
        &self,
        index: u32,
        target: RoleId,
    ) -> Result<AcknowledgementWriterBinding, LayoutError> {
        if self.permissions != MappingPermissions::ReadWrite {
            return Err(LayoutError::WrongMappingPermission);
        }
        self.acknowledgement_range(index)?;
        Ok(AcknowledgementWriterBinding::validated(
            self.role(),
            target,
            self.generation(),
        ))
    }

    /// Binds an acquire-only acknowledgement route only for a read-only mapping.
    pub fn acknowledgement_reader_binding(
        &self,
        index: u32,
        target: RoleId,
    ) -> Result<AcknowledgementReaderBinding, LayoutError> {
        if self.permissions != MappingPermissions::ReadOnly {
            return Err(LayoutError::WrongMappingPermission);
        }
        self.acknowledgement_range(index)?;
        Ok(AcknowledgementReaderBinding::validated(
            self.role(),
            target,
            self.generation(),
        ))
    }
}

#[derive(Clone, Copy, Debug)]
struct RegionHeader {
    total_size: u64,
    schema_id: [u8; 32],
    generation: u64,
    role: u32,
    writer: u32,
    acknowledgement_offset: u64,
    acknowledgement_count: u32,
    acknowledgement_stride: u32,
    slots_offset: u64,
    slot_count: u32,
    slot_stride: u32,
    payload_capacity: u32,
}

/// Bounded region layout validation failures.
#[allow(missing_docs)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LayoutError {
    /// Checked arithmetic overflowed.
    Overflow,
    /// Allocation of owned layout metadata failed.
    AllocationFailed,
    /// Generation zero is reserved.
    ZeroGeneration,
    /// No independent regions were configured.
    EmptyRegionSet,
    /// A numeric role appeared more than once.
    DuplicateRole(RoleId),
    /// Slot, payload, acknowledgement, or total-size limit was exceeded.
    LimitExceeded,
    /// Region has no slots or zero-capacity slots.
    EmptySlots,
    /// Mapping cannot contain the declared region.
    MappingTooSmall { required: u64, actual: u64 },
    /// Region signature is invalid.
    BadMagic,
    /// Region wire revision is unsupported.
    BadVersion { major: u16, minor: u16 },
    /// Encoded header size is noncanonical.
    BadHeaderSize(u32),
    /// Schema identity differs.
    SchemaMismatch,
    /// Generation differs.
    StaleGeneration { expected: u64, actual: u64 },
    /// Role differs.
    UnexpectedRole { expected: RoleId, actual: u32 },
    /// Writer endpoint differs or is invalid.
    UnexpectedWriter,
    /// Reserved bytes or flags are nonzero.
    ReservedFieldSet,
    /// Total size is invalid.
    BadTotalSize,
    /// Acknowledgement layout is invalid.
    BadAcknowledgementLayout,
    /// Acknowledgement storage was not zero before transfer.
    AcknowledgementNotZero,
    /// Slot layout is invalid.
    BadSlotLayout,
    /// Quiescent slot generation or unpublished metadata is invalid.
    SlotMetadataNotInitialized,
    /// Slot stride is invalid.
    BadSlotStride,
    /// A checked range escapes the mapping.
    RangeOutOfBounds,
    /// Slot index is outside the negotiated count.
    SlotOutOfBounds { slot: u32, count: u32 },
    /// Acknowledgement index is outside the negotiated count.
    AcknowledgementOutOfBounds { index: u32, count: u32 },
    /// Capability direction does not match native mapping permissions.
    WrongMappingPermission,
}

impl fmt::Display for LayoutError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "region layout failed validation: {self:?}")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for LayoutError {}

fn validate_counts(spec: RegionSpec, limits: LayoutLimits) -> Result<(), LayoutError> {
    if spec.slot_count == 0 || spec.payload_bytes == 0 {
        return Err(LayoutError::EmptySlots);
    }
    if spec.slot_count > limits.maximum_slot_count
        || spec.payload_bytes > limits.maximum_payload_bytes
        || spec.acknowledgement_count > limits.maximum_acknowledgement_count
    {
        return Err(LayoutError::LimitExceeded);
    }
    Ok(())
}

fn validate_header(
    header: &RegionHeader,
    mapped_len: usize,
    expected: ValidationExpectations,
) -> Result<(), LayoutError> {
    if header.schema_id != expected.schema_id {
        return Err(LayoutError::SchemaMismatch);
    }
    if header.generation != expected.generation {
        return Err(LayoutError::StaleGeneration {
            expected: expected.generation,
            actual: header.generation,
        });
    }
    if header.role != expected.role.get() {
        return Err(LayoutError::UnexpectedRole {
            expected: expected.role,
            actual: header.role,
        });
    }
    if Endpoint::from_raw(header.writer) != Some(expected.writer) {
        return Err(LayoutError::UnexpectedWriter);
    }
    if header.total_size > mapped_len as u64
        || header.total_size > expected.maximum_mapping_size
        || header.total_size > usize::MAX as u64
    {
        return Err(LayoutError::BadTotalSize);
    }
    if header.acknowledgement_offset != REGION_HEADER_SIZE
        || header.acknowledgement_stride != ACKNOWLEDGEMENT_CELL_SIZE as u32
    {
        return Err(LayoutError::BadAcknowledgementLayout);
    }
    let acknowledgement_len = u64::from(header.acknowledgement_count)
        .checked_mul(u64::from(header.acknowledgement_stride))
        .ok_or(LayoutError::Overflow)?;
    let expected_slots_offset = align_up(
        header
            .acknowledgement_offset
            .checked_add(acknowledgement_len)
            .ok_or(LayoutError::Overflow)?,
        CACHE_LINE,
    )?;
    if header.slots_offset != expected_slots_offset
        || !header.slots_offset.is_multiple_of(CACHE_LINE)
    {
        return Err(LayoutError::BadSlotLayout);
    }
    if header.slot_count == 0 || header.payload_capacity == 0 {
        return Err(LayoutError::EmptySlots);
    }
    Ok(())
}

fn validate_header_encoding(bytes: &[u8]) -> Result<(), LayoutError> {
    if bytes[0..8] != REGION_MAGIC {
        return Err(LayoutError::BadMagic);
    }
    let major = get_u16(bytes, 8);
    let minor = get_u16(bytes, 10);
    if major != VERSION_MAJOR || minor != VERSION_MINOR {
        return Err(LayoutError::BadVersion { major, minor });
    }
    let header_size = get_u32(bytes, 12);
    if header_size != REGION_HEADER_SIZE as u32 {
        return Err(LayoutError::BadHeaderSize(header_size));
    }
    if get_u32(bytes, 108) != 0 || bytes[112..128].iter().any(|byte| *byte != 0) {
        return Err(LayoutError::ReservedFieldSet);
    }
    Ok(())
}

fn encode_header(header: &RegionHeader, bytes: &mut [u8]) {
    bytes[0..8].copy_from_slice(&REGION_MAGIC);
    put_u16(bytes, 8, VERSION_MAJOR);
    put_u16(bytes, 10, VERSION_MINOR);
    put_u32(bytes, 12, REGION_HEADER_SIZE as u32);
    put_u64(bytes, 16, header.total_size);
    bytes[24..56].copy_from_slice(&header.schema_id);
    put_u64(bytes, 56, header.generation);
    put_u32(bytes, 64, header.role);
    put_u32(bytes, 68, header.writer);
    put_u64(bytes, 72, header.acknowledgement_offset);
    put_u32(bytes, 80, header.acknowledgement_count);
    put_u32(bytes, 84, header.acknowledgement_stride);
    put_u64(bytes, 88, header.slots_offset);
    put_u32(bytes, 96, header.slot_count);
    put_u32(bytes, 100, header.slot_stride);
    put_u32(bytes, 104, header.payload_capacity);
    put_u32(bytes, 108, 0);
    bytes[112..128].fill(0);
}

fn decode_header(bytes: &[u8]) -> RegionHeader {
    let mut schema_id = [0; 32];
    schema_id.copy_from_slice(&bytes[24..56]);
    RegionHeader {
        total_size: get_u64(bytes, 16),
        schema_id,
        generation: get_u64(bytes, 56),
        role: get_u32(bytes, 64),
        writer: get_u32(bytes, 68),
        acknowledgement_offset: get_u64(bytes, 72),
        acknowledgement_count: get_u32(bytes, 80),
        acknowledgement_stride: get_u32(bytes, 84),
        slots_offset: get_u64(bytes, 88),
        slot_count: get_u32(bytes, 96),
        slot_stride: get_u32(bytes, 100),
        payload_capacity: get_u32(bytes, 104),
    }
}

fn checked_range(
    start: u64,
    end: u64,
    total: u64,
    mapped_len: usize,
) -> Result<Range<usize>, LayoutError> {
    if start > end || end > total || end > mapped_len as u64 || end > usize::MAX as u64 {
        return Err(LayoutError::RangeOutOfBounds);
    }
    Ok(start as usize..end as usize)
}

fn align_up(value: u64, alignment: u64) -> Result<u64, LayoutError> {
    value
        .checked_add(alignment - 1)
        .map(|sum| sum & !(alignment - 1))
        .ok_or(LayoutError::Overflow)
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}
fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}
fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
fn get_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("fixed checked range"),
    )
}
fn get_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(
        bytes[offset..offset + 2]
            .try_into()
            .expect("fixed checked range"),
    )
}
fn get_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("fixed checked range"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const SCHEMA: [u8; 32] = [0x5a; 32];
    const GENERATION: u64 = 11;
    const ROLE_A: RoleId = RoleId::new(1).unwrap();
    const ROLE_B: RoleId = RoleId::new(2).unwrap();

    fn limits() -> LayoutLimits {
        LayoutLimits {
            maximum_mapping_size: 1 << 20,
            maximum_slot_count: 32,
            maximum_acknowledgement_count: 8,
            maximum_payload_bytes: 4096,
        }
    }

    fn specs() -> [RegionSpec; 2] {
        [
            RegionSpec {
                role: ROLE_A,
                writer: Endpoint::Initiator,
                slot_count: 2,
                payload_bytes: 128,
                acknowledgement_count: 0,
            },
            RegionSpec {
                role: ROLE_B,
                writer: Endpoint::Responder,
                slot_count: 4,
                payload_bytes: 64,
                acknowledgement_count: 2,
            },
        ]
    }

    fn encoded(role: RoleId) -> (RegionLayout, Vec<u8>) {
        let set = RegionSetLayout::calculate(SCHEMA, GENERATION, &specs(), limits()).unwrap();
        let layout = set.region(role).unwrap().clone();
        let mut bytes = vec![0; layout.total_size() as usize];
        layout.encode_into(&mut bytes).unwrap();
        (layout, bytes)
    }

    fn expected(
        role: RoleId,
        writer: Endpoint,
        size: u64,
        permissions: MappingPermissions,
    ) -> ValidationExpectations {
        ValidationExpectations {
            schema_id: SCHEMA,
            generation: GENERATION,
            role,
            writer,
            maximum_mapping_size: size,
            permissions,
        }
    }

    #[test]
    fn configurable_regions_have_checked_independent_layouts() {
        let set = RegionSetLayout::calculate(SCHEMA, GENERATION, &specs(), limits()).unwrap();
        assert_eq!(set.regions().len(), 2);
        assert_ne!(
            set.region(ROLE_A).unwrap().total_size(),
            set.region(ROLE_B).unwrap().total_size()
        );
        let (layout, bytes) = encoded(ROLE_B);
        // SAFETY: owned vector is quiescent and its simulated permission is exact.
        let validated = unsafe {
            ValidatedRegionLayout::validate(
                &bytes,
                expected(
                    ROLE_B,
                    Endpoint::Responder,
                    layout.total_size(),
                    MappingPermissions::ReadOnly,
                ),
            )
        }
        .unwrap();
        assert_eq!(validated.role(), ROLE_B);
        assert_eq!(validated.slot_range(3).unwrap().len(), 128);
        assert_eq!(validated.acknowledgement_range(1).unwrap().len(), 64);
        assert!(validated.reader_slot_binding(0).is_ok());
        assert_eq!(
            validated.writer_slot_binding(0, ROLE_A).unwrap_err(),
            LayoutError::WrongMappingPermission
        );
        assert!(validated.acknowledgement_reader_binding(0, ROLE_A).is_ok());
    }

    #[test]
    fn writable_layout_cannot_mint_reader_or_ack_reader_capabilities() {
        let (layout, bytes) = encoded(ROLE_B);
        // SAFETY: owned vector is quiescent and permission is simulated exactly.
        let validated = unsafe {
            ValidatedRegionLayout::validate(
                &bytes,
                expected(
                    ROLE_B,
                    Endpoint::Responder,
                    layout.total_size(),
                    MappingPermissions::ReadWrite,
                ),
            )
        }
        .unwrap();
        assert!(validated.writer_slot_binding(0, ROLE_A).is_ok());
        assert_eq!(
            validated.reader_slot_binding(0).unwrap_err(),
            LayoutError::WrongMappingPermission
        );
        assert!(validated.acknowledgement_writer_binding(0, ROLE_A).is_ok());
        assert_eq!(
            validated
                .acknowledgement_reader_binding(0, ROLE_A)
                .unwrap_err(),
            LayoutError::WrongMappingPermission
        );
    }

    #[test]
    fn malformed_headers_offsets_slots_and_limits_fail_closed() {
        let (layout, original) = encoded(ROLE_B);
        let expectation = expected(
            ROLE_B,
            Endpoint::Responder,
            layout.total_size(),
            MappingPermissions::ReadOnly,
        );
        for offset in [
            0_usize, 8, 12, 16, 24, 56, 64, 68, 72, 84, 88, 100, 108, 112,
        ] {
            let mut bytes = original.clone();
            bytes[offset] ^= 1;
            // SAFETY: mutation occurs before validation and no peer exists.
            assert!(unsafe { ValidatedRegionLayout::validate(&bytes, expectation) }.is_err());
        }
        let slot_start = get_u64(&original, 88) as usize;
        let mut bytes = original;
        bytes[slot_start + 16] = 1;
        // SAFETY: mutation occurs before validation and no peer exists.
        assert_eq!(
            unsafe { ValidatedRegionLayout::validate(&bytes, expectation) }.unwrap_err(),
            LayoutError::SlotMetadataNotInitialized
        );
    }

    #[test]
    fn rejects_zero_generation_duplicate_roles_and_excess_capacity() {
        assert_eq!(
            RegionSetLayout::calculate(SCHEMA, 0, &specs(), limits()).unwrap_err(),
            LayoutError::ZeroGeneration
        );
        let duplicate = [specs()[0], specs()[0]];
        assert_eq!(
            RegionSetLayout::calculate(SCHEMA, 1, &duplicate, limits()).unwrap_err(),
            LayoutError::DuplicateRole(ROLE_A)
        );
        let mut too_large = specs();
        too_large[0].slot_count = 33;
        assert_eq!(
            RegionSetLayout::calculate(SCHEMA, 1, &too_large, limits()).unwrap_err(),
            LayoutError::LimitExceeded
        );

        let (layout, bytes) = encoded(ROLE_A);
        let zero_generation = ValidationExpectations {
            generation: 0,
            ..expected(
                ROLE_A,
                Endpoint::Initiator,
                layout.total_size(),
                MappingPermissions::ReadOnly,
            )
        };
        // SAFETY: owned vector is quiescent; the hostile expectation is deliberate.
        assert_eq!(
            unsafe { ValidatedRegionLayout::validate(&bytes, zero_generation) }.unwrap_err(),
            LayoutError::ZeroGeneration
        );
    }
}
