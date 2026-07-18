use super::*;
use crate::layout::{
    AcknowledgementRouteSpec, Endpoint, LayoutLimits, RegionSetLayout, RegionSpec, RoleId,
    ValidationExpectations,
};
use std::alloc::{Layout, alloc_zeroed, dealloc};

#[derive(Debug)]
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

#[derive(Debug)]
struct ReaderWitness<'a>(&'a Allocation);
#[derive(Debug)]
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
        writer.publish(0, 1, None, b"ping").unwrap();
    }
    let reader = ReaderRegion::new(
        ReaderWitness(&producer_memory),
        producer_validated,
        set.clone(),
    )
    .unwrap();
    let observation = reader.slot(0).unwrap().observe(1).unwrap();
    reader.slot(0).unwrap().recheck(observation).unwrap();
    assert_eq!(reader.copy_payload(0, 1).unwrap(), b"ping");

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

const SLOT: u32 = 0;
const SEQUENCE: u64 = 1;
const PAYLOAD: &[u8] = b"ping";

/// Builds the two-role producer/acknowledger topology used by the fixtures
/// below, mirroring the shape composed inline in the test above.
fn build_topology(schema_id: [u8; 32], generation: u64) -> RegionSetLayout {
    let producer = RoleId::new(1).unwrap();
    let acknowledger = RoleId::new(2).unwrap();
    let specs = [
        RegionSpec {
            role: producer,
            writer: Endpoint::Initiator,
            slot_count: 1,
            payload_bytes: 64,
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
    RegionSetLayout::calculate(schema_id, generation, &specs, &route_specs, limits).unwrap()
}

/// Owned memory, validated layout, and topology for the producer role, with
/// `payload` already published at [`SLOT`]/[`SEQUENCE`].
struct ProducerFixture {
    memory: Allocation,
    layout: ValidatedRegionLayout,
    topology: RegionSetLayout,
}

fn build_producer_fixture(schema_id: [u8; 32], generation: u64, payload: &[u8]) -> ProducerFixture {
    let producer = RoleId::new(1).unwrap();
    let set = build_topology(schema_id, generation);
    let producer_layout = set.region(producer).unwrap();
    let mut producer_memory = Allocation::new(producer_layout.total_size() as usize);
    producer_layout
        .encode_into(producer_memory.bytes_mut())
        .unwrap();
    let producer_validated = unsafe {
        ValidatedRegionLayout::validate(
            producer_memory.bytes(),
            ValidationExpectations {
                schema_id,
                generation,
                role: producer,
                writer: Endpoint::Initiator,
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
        writer.publish(SLOT, SEQUENCE, None, payload).unwrap();
    }

    ProducerFixture {
        memory: producer_memory,
        layout: producer_validated,
        topology: set,
    }
}

#[test]
fn copy_payload_into_returns_payload_length_without_allocating() {
    let fixture = build_producer_fixture([7; 32], 9, PAYLOAD);
    let reader = ReaderRegion::new(
        ReaderWitness(&fixture.memory),
        fixture.layout.clone(),
        fixture.topology.clone(),
    )
    .unwrap();
    let mut destination = [0_u8; 64];
    let copied = reader
        .copy_payload_into(SLOT, SEQUENCE, &mut destination)
        .unwrap();
    assert_eq!(copied, PAYLOAD.len());
    assert_eq!(&destination[..copied], PAYLOAD);
}

#[test]
fn copy_payload_into_rejects_short_destination() {
    let fixture = build_producer_fixture([7; 32], 9, PAYLOAD);
    let reader = ReaderRegion::new(
        ReaderWitness(&fixture.memory),
        fixture.layout.clone(),
        fixture.topology.clone(),
    )
    .unwrap();
    let mut destination = [0_u8; 1]; // shorter than the published payload
    let error = reader
        .copy_payload_into(SLOT, SEQUENCE, &mut destination)
        .unwrap_err();
    assert!(matches!(
        error,
        BindingError::DestinationTooSmall { required, provided }
            if required == PAYLOAD.len() && provided == 1
    ));
}

#[test]
fn copy_payload_into_matches_copy_payload_bytes() {
    let fixture = build_producer_fixture([7; 32], 9, PAYLOAD);
    let reader = ReaderRegion::new(
        ReaderWitness(&fixture.memory),
        fixture.layout.clone(),
        fixture.topology.clone(),
    )
    .unwrap();
    let owned = reader.copy_payload(SLOT, SEQUENCE).unwrap();
    let mut destination = vec![0_u8; owned.len() + 8];
    let copied = reader
        .copy_payload_into(SLOT, SEQUENCE, &mut destination)
        .unwrap();
    assert_eq!(&destination[..copied], owned.as_slice());
}

#[test]
fn reader_region_into_mapping_returns_witness() {
    let fixture = build_producer_fixture([7; 32], 9, PAYLOAD);
    let reader = ReaderRegion::new(
        ReaderWitness(&fixture.memory),
        fixture.layout.clone(),
        fixture.topology.clone(),
    )
    .unwrap();
    let mapping = reader.into_mapping();
    // Rebind proves the witness is intact.
    let rebound =
        ReaderRegion::new(mapping, fixture.layout.clone(), fixture.topology.clone()).unwrap();
    let _ = rebound.slot(SLOT).unwrap();
}

#[test]
fn writer_region_into_mapping_returns_witness() {
    let mut fixture = build_producer_fixture([7; 32], 9, PAYLOAD);
    let writer = WriterRegion::new(
        WriterWitness(&mut fixture.memory),
        fixture.layout.clone(),
        fixture.topology.clone(),
    )
    .unwrap();
    let mapping = writer.into_mapping();
    let rebound =
        WriterRegion::new(mapping, fixture.layout.clone(), fixture.topology.clone()).unwrap();
    drop(rebound);
}

#[test]
fn reader_region_new_returns_witness_on_rejected_bind() {
    let fixture = build_producer_fixture([7; 32], 9, PAYLOAD);
    // A topology validated against a different schema does not match the
    // already-validated producer layout, so the bind is rejected.
    let mismatched_topology = build_topology([9; 32], 9);
    let (witness, error) = match ReaderRegion::new(
        ReaderWitness(&fixture.memory),
        fixture.layout.clone(),
        mismatched_topology,
    ) {
        Ok(_) => panic!("expected the mismatched topology bind to be rejected"),
        Err(pair) => pair,
    };
    assert!(matches!(error, BindingError::TopologyMismatch));
    // The rejected bind returns the witness intact; rebinding with the
    // correct topology proves it is still usable.
    let rebound =
        ReaderRegion::new(witness, fixture.layout.clone(), fixture.topology.clone()).unwrap();
    let _ = rebound.slot(SLOT).unwrap();
}

#[test]
fn writer_region_new_returns_witness_on_rejected_bind() {
    let mut fixture = build_producer_fixture([7; 32], 9, PAYLOAD);
    let mismatched_topology = build_topology([9; 32], 9);
    let (witness, error) = match WriterRegion::new(
        WriterWitness(&mut fixture.memory),
        fixture.layout.clone(),
        mismatched_topology,
    ) {
        Ok(_) => panic!("expected the mismatched topology bind to be rejected"),
        Err(pair) => pair,
    };
    assert!(matches!(error, BindingError::TopologyMismatch));
    // The rejected bind returns the witness intact; rebinding with the
    // correct topology and binding the producer slot proves it is still
    // usable.
    let mut rebound =
        WriterRegion::new(witness, fixture.layout.clone(), fixture.topology.clone()).unwrap();
    let _ = rebound.slot(SLOT).unwrap();
}
