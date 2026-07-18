use super::*;
use native_ipc_core::layout::{
    AcknowledgementRouteSpec, Endpoint, LayoutLimits, RegionSetLayout, RegionSpec, RoleId,
};
use std::mem::size_of;

impl Mapping {
    fn map_entry<Access: CapabilityAccess>(
        task: MachPort,
        mapped_len: usize,
        entry: &MemoryEntry<Access>,
    ) -> Result<Self, MachError> {
        Self::map_port(task, mapped_len, entry.name, Access::PROTECTION)
    }
}

struct TestWriterWitness<'a>(&'a mut Mapping);
struct TestReaderWitness<'a>(&'a Mapping);

// SAFETY: test witnesses borrow live Mach mappings for their full bound
// lifetime; the writer mapping is unique and peer entries are read-only.
unsafe impl SoleWriterMapping for TestWriterWitness<'_> {
    fn base(&self) -> NonNull<u8> {
        self.0.address
    }
    fn len(&self) -> usize {
        self.0.mapped_len
    }
}

// SAFETY: test reader mappings are created from read-only memory entries
// and remain borrowed for their full bound lifetime.
unsafe impl ReadOnlyMapping for TestReaderWitness<'_> {
    fn base(&self) -> NonNull<u8> {
        self.0.address
    }
    fn len(&self) -> usize {
        self.0.mapped_len
    }
}

#[test]
fn read_only_capability_rejects_writable_mapping() {
    let owner = QuiescentRegion::new(37).unwrap();
    let capability_len = owner.len();
    let runtime = owner.into_local_writer(capability_len).unwrap();
    let mut address = 0;
    let protection = VM_PROT_READ | VM_PROT_WRITE;
    // SAFETY: deliberately bypasses typed API to probe kernel enforcement.
    let result = unsafe {
        mach_vm_map(
            runtime.mapping.task,
            &mut address,
            runtime.mapping.mapped_len as MachVmSize,
            0,
            VM_FLAGS_ANYWHERE,
            runtime.peer_entry.name,
            0,
            0,
            protection,
            protection,
            VM_INHERIT_NONE,
        )
    };
    if result == KERN_SUCCESS {
        deallocate_mapping(runtime.mapping.task, address, runtime.mapping.mapped_len);
    }
    assert_ne!(result, KERN_SUCCESS);
}

#[test]
fn executable_protection_upgrade_is_rejected() {
    let owner = QuiescentRegion::new(37).unwrap();
    let capability_len = owner.len();
    let runtime = owner.into_local_writer(capability_len).unwrap();
    // SAFETY: deliberately requests execute to probe the clamped maximum.
    let result = unsafe {
        mach_vm_protect(
            runtime.mapping.task,
            runtime.mapping.address(),
            runtime.mapping.mapped_len as MachVmSize,
            0,
            VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE,
        )
    };
    assert_ne!(result, KERN_SUCCESS);
}

#[test]
fn remote_writer_downgrades_local_mapping_before_escape() {
    let mut owner = QuiescentRegion::new(19).unwrap();
    owner.as_bytes_mut()[0] = 7;
    let capability_len = owner.len();
    let mut runtime = owner.into_remote_writer(capability_len).unwrap();
    assert!(
        runtime
            .mapping
            .protect(VM_PROT_READ | VM_PROT_WRITE, false)
            .is_err()
    );
    let mut peer = Mapping::map_entry(
        runtime.mapping.task,
        runtime.mapping.mapped_len,
        &runtime.peer_entry,
    )
    .unwrap();
    // SAFETY: peer test mapping is the sole writer while quiescent.
    let peer_bytes = unsafe { peer.bytes_mut(19) };
    peer_bytes[3..8].copy_from_slice(b"world");
    drop(peer);
    // SAFETY: peer mapping is gone; immutable test snapshot is quiescent.
    assert_eq!(&unsafe { runtime.mapping.bytes(19) }[3..8], b"world");
}

#[test]
fn local_writer_peer_observes_quiescent_initialization() {
    let mut owner = QuiescentRegion::new(37).unwrap();
    owner.as_bytes_mut()[..5].copy_from_slice(b"hello");
    let capability_len = owner.len();
    let runtime = owner.into_local_writer(capability_len).unwrap();
    let peer = Mapping::map_entry(
        runtime.mapping.task,
        runtime.mapping.mapped_len,
        &runtime.peer_entry,
    )
    .unwrap();
    // SAFETY: local writer is quiescent during immutable test snapshot.
    assert_eq!(&unsafe { peer.bytes(37) }[..5], b"hello");
}

#[test]
fn rejects_bad_sizes_and_matches_sdk_scalars() {
    assert_eq!(QuiescentRegion::new(0).unwrap_err(), MachError::ZeroSize);
    assert_eq!(
        page_align(usize::MAX, 4096).unwrap_err(),
        MachError::SizeOverflow {
            requested: usize::MAX
        }
    );
    assert_eq!(size_of::<MachPort>(), 4);
    assert_eq!(size_of::<MachVmAddress>(), 8);
    assert_eq!(ReadOnlyCapability::PROTECTION, VM_PROT_READ);
    assert_eq!(
        ReadWriteCapability::PROTECTION,
        VM_PROT_READ | VM_PROT_WRITE
    );
}

#[test]
fn page_capability_padding_is_explicit_validated_and_bound() {
    let producer = RoleId::new(1).unwrap();
    let peer = RoleId::new(2).unwrap();
    let specs = [
        RegionSpec {
            role: producer,
            writer: Endpoint::Initiator,
            slot_count: 1,
            payload_bytes: 16,
            acknowledgement_count: 1,
        },
        RegionSpec {
            role: peer,
            writer: Endpoint::Responder,
            slot_count: 1,
            payload_bytes: 16,
            acknowledgement_count: 1,
        },
    ];
    let routes = [
        AcknowledgementRouteSpec {
            owner: peer,
            target: producer,
            slot_index: 0,
            cell_index: 0,
        },
        AcknowledgementRouteSpec {
            owner: producer,
            target: peer,
            slot_index: 0,
            cell_index: 0,
        },
    ];
    let set = RegionSetLayout::calculate(
        [3; 32],
        7,
        &specs,
        &routes,
        LayoutLimits {
            maximum_mapping_size: 1 << 20,
            maximum_slot_count: 2,
            maximum_acknowledgement_count: 2,
            maximum_payload_bytes: 64,
        },
    )
    .unwrap();
    let layout = set.region(producer).unwrap();
    let mut owner = QuiescentRegion::new(layout.total_size() as usize).unwrap();
    assert!(owner.len() >= owner.logical_len());
    assert!(owner.len().is_multiple_of(page_size().unwrap()));
    layout.encode_into(owner.as_bytes_mut()).unwrap();
    let expected = ValidationExpectations {
        schema_id: [3; 32],
        generation: 7,
        role: producer,
        writer: Endpoint::Initiator,
        maximum_mapping_size: owner.len() as u64,
    };
    let mut bound = owner
        .into_bound_local_writer(expected, set.clone())
        .unwrap();
    bound
        .slot(0)
        .unwrap()
        .prepare_publish(1, None)
        .unwrap()
        .publish(4)
        .unwrap();

    let mut hostile = QuiescentRegion::new(layout.total_size() as usize).unwrap();
    layout.encode_into(hostile.as_bytes_mut()).unwrap();
    let last = hostile.len() - 1;
    hostile.as_bytes_mut()[last] = 1;
    let expected = ValidationExpectations {
        schema_id: [3; 32],
        generation: 7,
        role: producer,
        writer: Endpoint::Initiator,
        maximum_mapping_size: hostile.len() as u64,
    };
    assert!(matches!(
        hostile.into_bound_local_writer(expected, set),
        Err(MacBindingError::Layout(
            LayoutError::CapabilityPaddingNotZero
        ))
    ));
}

#[test]
fn mach_mapping_completes_core_publish_observe_and_ack_path() {
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
    let routes = [
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
    let topology = RegionSetLayout::calculate(
        [9; 32],
        11,
        &specs,
        &routes,
        LayoutLimits {
            maximum_mapping_size: 1 << 20,
            maximum_slot_count: 2,
            maximum_acknowledgement_count: 2,
            maximum_payload_bytes: 64,
        },
    )
    .unwrap();

    let producer_layout = topology.region(producer).unwrap();
    let mut producer_owner = QuiescentRegion::new(producer_layout.total_size() as usize).unwrap();
    producer_layout
        .encode_into(producer_owner.as_bytes_mut())
        .unwrap();
    let producer_expected = ValidationExpectations {
        schema_id: [9; 32],
        generation: 11,
        role: producer,
        writer: Endpoint::Initiator,
        maximum_mapping_size: producer_owner.len() as u64,
    };
    let producer_validated = unsafe {
        ValidatedRegionLayout::validate(producer_owner.as_bytes(), producer_expected, &topology)
    }
    .unwrap();
    let producer_len = producer_owner.len();
    let mut producer_runtime = producer_owner.into_local_writer(producer_len).unwrap();
    let producer_peer = Mapping::map_entry(
        producer_runtime.mapping.task,
        producer_runtime.mapping.mapped_len,
        &producer_runtime.peer_entry,
    )
    .unwrap();

    let ack_layout = topology.region(acknowledger).unwrap();
    let mut ack_owner = QuiescentRegion::new(ack_layout.total_size() as usize).unwrap();
    ack_layout.encode_into(ack_owner.as_bytes_mut()).unwrap();
    let ack_expected = ValidationExpectations {
        schema_id: [9; 32],
        generation: 11,
        role: acknowledger,
        writer: Endpoint::Responder,
        maximum_mapping_size: ack_owner.len() as u64,
    };
    let ack_validated =
        unsafe { ValidatedRegionLayout::validate(ack_owner.as_bytes(), ack_expected, &topology) }
            .unwrap();
    let ack_len = ack_owner.len();
    let mut ack_runtime = ack_owner.into_local_writer(ack_len).unwrap();
    let ack_peer = Mapping::map_entry(
        ack_runtime.mapping.task,
        ack_runtime.mapping.mapped_len,
        &ack_runtime.peer_entry,
    )
    .unwrap();

    {
        let mut writer = WriterRegion::new(
            TestWriterWitness(&mut producer_runtime.mapping),
            producer_validated.clone(),
            topology.clone(),
        )
        .map_err(|(_, error)| error)
        .unwrap();
        writer.publish(0, 1, None, b"mach").unwrap();
    }
    let reader = ReaderRegion::new(
        TestReaderWitness(&producer_peer),
        producer_validated,
        topology.clone(),
    )
    .map_err(|(_, error)| error)
    .unwrap();
    let observation = reader.slot(0).unwrap().observe(1).unwrap();
    reader.slot(0).unwrap().recheck(observation).unwrap();
    assert_eq!(reader.copy_payload(0, 1).unwrap(), b"mach");

    {
        let mut writer = WriterRegion::new(
            TestWriterWitness(&mut ack_runtime.mapping),
            ack_validated.clone(),
            topology.clone(),
        )
        .map_err(|(_, error)| error)
        .unwrap();
        writer
            .acknowledgement(producer, 0)
            .unwrap()
            .acknowledge(observation)
            .unwrap();
    }
    let reader = ReaderRegion::new(TestReaderWitness(&ack_peer), ack_validated, topology)
        .map_err(|(_, error)| error)
        .unwrap();
    let acknowledged = reader.acknowledgement(producer, 0).unwrap().observe();
    assert_eq!(acknowledged.sequence(), 1);
    assert_eq!(acknowledged.slot_index(), 0);
    assert_eq!(acknowledged.cell_index(), 0);
}
