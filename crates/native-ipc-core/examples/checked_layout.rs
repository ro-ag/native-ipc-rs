//! Composes two bounded single-writer regions and their acknowledgement routes.

use native_ipc_core::layout::{
    AcknowledgementRouteSpec, Endpoint, LayoutLimits, RegionSetLayout, RegionSpec, RoleId,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let requests = RoleId::new(1).expect("nonzero role");
    let responses = RoleId::new(2).expect("nonzero role");
    let regions = [
        RegionSpec {
            role: requests,
            writer: Endpoint::Initiator,
            slot_count: 1,
            payload_bytes: 256,
            acknowledgement_count: 1,
        },
        RegionSpec {
            role: responses,
            writer: Endpoint::Responder,
            slot_count: 1,
            payload_bytes: 256,
            acknowledgement_count: 1,
        },
    ];
    let routes = [
        AcknowledgementRouteSpec {
            owner: responses,
            target: requests,
            slot_index: 0,
            cell_index: 0,
        },
        AcknowledgementRouteSpec {
            owner: requests,
            target: responses,
            slot_index: 0,
            cell_index: 0,
        },
    ];
    let limits = LayoutLimits {
        maximum_mapping_size: 64 * 1024,
        maximum_slot_count: 8,
        maximum_acknowledgement_count: 8,
        maximum_payload_bytes: 4096,
    };

    let topology = RegionSetLayout::calculate([0x52; 32], 1, &regions, &routes, limits)?;
    for region in topology.regions() {
        println!(
            "role={} writer={:?} mapping={} bytes",
            region.role().get(),
            region.writer(),
            region.total_size()
        );
    }
    Ok(())
}
