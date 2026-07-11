#![no_main]

use libfuzzer_sys::fuzz_target;
use native_ipc_core::layout::{
    AcknowledgementRouteSpec, Endpoint, LayoutLimits, RegionSetLayout, RegionSpec, RoleId,
    ValidatedRegionLayout, ValidationExpectations,
};

fuzz_target!(|data: &[u8]| {
    if data.len() > 16 * 1024 {
        return;
    }
    let producer = RoleId::new(1).unwrap();
    let acknowledger = RoleId::new(2).unwrap();
    let specs = [
        RegionSpec { role: producer, writer: Endpoint::Initiator, slot_count: 2, payload_bytes: 64, acknowledgement_count: 2 },
        RegionSpec { role: acknowledger, writer: Endpoint::Responder, slot_count: 2, payload_bytes: 64, acknowledgement_count: 2 },
    ];
    let routes = [
        AcknowledgementRouteSpec { owner: acknowledger, target: producer, slot_index: 0, cell_index: 0 },
        AcknowledgementRouteSpec { owner: acknowledger, target: producer, slot_index: 1, cell_index: 1 },
        AcknowledgementRouteSpec { owner: producer, target: acknowledger, slot_index: 0, cell_index: 0 },
        AcknowledgementRouteSpec { owner: producer, target: acknowledger, slot_index: 1, cell_index: 1 },
    ];
    let topology = RegionSetLayout::calculate(
        [0x46; 32], 7, &specs, &routes,
        LayoutLimits { maximum_mapping_size: 16 * 1024, maximum_slot_count: 4, maximum_acknowledgement_count: 4, maximum_payload_bytes: 128 },
    ).unwrap();
    let expected = ValidationExpectations {
        schema_id: [0x46; 32], generation: 7, role: producer,
        writer: Endpoint::Initiator, maximum_mapping_size: 16 * 1024,
    };
    // SAFETY: libFuzzer owns `data` and cannot mutate it during this call.
    let _ = unsafe { ValidatedRegionLayout::validate(data, expected, &topology) };

    let region = topology.region(producer).unwrap();
    let mut structured = vec![0; region.total_size() as usize];
    region.encode_into(&mut structured).unwrap();
    for mutation in data.chunks_exact(3).take(256) {
        let index = u16::from_le_bytes([mutation[0], mutation[1]]) as usize % structured.len();
        structured[index] = mutation[2];
    }
    // SAFETY: the owned structured buffer is quiescent for this call.
    let _ = unsafe { ValidatedRegionLayout::validate(&structured, expected, &topology) };
});
