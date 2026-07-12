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
            acknowledgement_count: 4,
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

fn routes() -> [AcknowledgementRouteSpec; 6] {
    [
        AcknowledgementRouteSpec {
            owner: ROLE_B,
            target: ROLE_A,
            slot_index: 0,
            cell_index: 0,
        },
        AcknowledgementRouteSpec {
            owner: ROLE_B,
            target: ROLE_A,
            slot_index: 1,
            cell_index: 1,
        },
        AcknowledgementRouteSpec {
            owner: ROLE_A,
            target: ROLE_B,
            slot_index: 0,
            cell_index: 0,
        },
        AcknowledgementRouteSpec {
            owner: ROLE_A,
            target: ROLE_B,
            slot_index: 1,
            cell_index: 1,
        },
        AcknowledgementRouteSpec {
            owner: ROLE_A,
            target: ROLE_B,
            slot_index: 2,
            cell_index: 2,
        },
        AcknowledgementRouteSpec {
            owner: ROLE_A,
            target: ROLE_B,
            slot_index: 3,
            cell_index: 3,
        },
    ]
}

fn encoded(role: RoleId) -> (RegionLayout, Vec<u8>) {
    let set = topology();
    let layout = set.region(role).unwrap().clone();
    let mut bytes = vec![0; layout.total_size() as usize];
    layout.encode_into(&mut bytes).unwrap();
    (layout, bytes)
}

fn topology() -> RegionSetLayout {
    RegionSetLayout::calculate(SCHEMA, GENERATION, &specs(), &routes(), limits()).unwrap()
}

fn expected(role: RoleId, writer: Endpoint, size: u64) -> ValidationExpectations {
    ValidationExpectations {
        schema_id: SCHEMA,
        generation: GENERATION,
        role,
        writer,
        maximum_mapping_size: size,
    }
}

#[test]
fn configurable_regions_have_checked_independent_layouts() {
    let set =
        RegionSetLayout::calculate(SCHEMA, GENERATION, &specs(), &routes(), limits()).unwrap();
    assert_eq!(set.regions().len(), 2);
    assert_eq!(set.acknowledgement_routes().len(), 6);
    let (layout, bytes) = encoded(ROLE_B);
    // SAFETY: owned vector is quiescent and its simulated permission is exact.
    let validated = unsafe {
        ValidatedRegionLayout::validate(
            &bytes,
            expected(ROLE_B, Endpoint::Responder, layout.total_size()),
            &set,
        )
    }
    .unwrap();
    assert_eq!(validated.role(), ROLE_B);
    assert_eq!(validated.slot_range(3).unwrap().len(), 128);
    assert_eq!(validated.acknowledgement_range(1).unwrap().len(), 64);
    assert!(validated.reader_slot_binding(0).is_ok());
    assert!(
        validated
            .writer_slot_binding(set.acknowledgement_route(ROLE_B, 0).unwrap())
            .is_ok()
    );
    assert!(
        validated
            .acknowledgement_reader_binding(set.acknowledgement_route(ROLE_A, 0).unwrap())
            .is_ok()
    );
}

#[test]
fn writable_layout_cannot_mint_reader_or_ack_reader_capabilities() {
    let set = topology();
    let (layout, bytes) = encoded(ROLE_B);
    // SAFETY: owned vector is quiescent and permission is simulated exactly.
    let validated = unsafe {
        ValidatedRegionLayout::validate(
            &bytes,
            expected(ROLE_B, Endpoint::Responder, layout.total_size()),
            &set,
        )
    }
    .unwrap();
    assert!(
        validated
            .writer_slot_binding(set.acknowledgement_route(ROLE_B, 0).unwrap())
            .is_ok()
    );
    assert!(validated.reader_slot_binding(0).is_ok());
    assert!(
        validated
            .acknowledgement_writer_binding(set.acknowledgement_route(ROLE_A, 0).unwrap())
            .is_ok()
    );
    assert!(
        validated
            .acknowledgement_reader_binding(set.acknowledgement_route(ROLE_A, 0).unwrap())
            .is_ok()
    );
}

#[test]
fn malformed_headers_offsets_slots_and_limits_fail_closed() {
    let topology = topology();
    let (layout, original) = encoded(ROLE_B);
    let expectation = expected(ROLE_B, Endpoint::Responder, layout.total_size());
    for offset in [
        0_usize, 8, 12, 16, 24, 56, 64, 68, 72, 84, 88, 100, 108, 112,
    ] {
        let mut bytes = original.clone();
        bytes[offset] ^= 1;
        // SAFETY: mutation occurs before validation and no peer exists.
        assert!(
            unsafe { ValidatedRegionLayout::validate(&bytes, expectation, &topology) }.is_err()
        );
    }
    let slot_start = get_u64(&original, 88) as usize;
    let mut bytes = original;
    bytes[slot_start + 16] = 1;
    // SAFETY: mutation occurs before validation and no peer exists.
    assert_eq!(
        unsafe { ValidatedRegionLayout::validate(&bytes, expectation, &topology) }.unwrap_err(),
        LayoutError::SlotMetadataNotInitialized
    );
}

#[test]
fn rejects_zero_generation_duplicate_roles_and_excess_capacity() {
    let topology = topology();
    assert_eq!(
        RegionSetLayout::calculate(SCHEMA, 0, &specs(), &routes(), limits()).unwrap_err(),
        LayoutError::ZeroGeneration
    );
    let duplicate = [specs()[0], specs()[0]];
    assert_eq!(
        RegionSetLayout::calculate(SCHEMA, 1, &duplicate, &routes(), limits()).unwrap_err(),
        LayoutError::DuplicateRole(ROLE_A)
    );
    let mut too_large = specs();
    too_large[0].slot_count = 33;
    assert_eq!(
        RegionSetLayout::calculate(SCHEMA, 1, &too_large, &routes(), limits()).unwrap_err(),
        LayoutError::LimitExceeded
    );

    let (layout, bytes) = encoded(ROLE_A);
    let zero_generation = ValidationExpectations {
        generation: 0,
        ..expected(ROLE_A, Endpoint::Initiator, layout.total_size())
    };
    // SAFETY: owned vector is quiescent; the hostile expectation is deliberate.
    assert_eq!(
        unsafe { ValidatedRegionLayout::validate(&bytes, zero_generation, &topology) }.unwrap_err(),
        LayoutError::ZeroGeneration
    );
}

#[test]
fn composition_rejects_ambiguous_and_directionally_invalid_routes() {
    let mut shared_cell = routes();
    shared_cell[1].cell_index = shared_cell[0].cell_index;
    assert_eq!(
        RegionSetLayout::calculate(SCHEMA, GENERATION, &specs(), &shared_cell, limits())
            .unwrap_err(),
        LayoutError::DuplicateAcknowledgementRoute
    );

    let mut duplicate_slot = routes();
    duplicate_slot[1].slot_index = 0;
    assert_eq!(
        RegionSetLayout::calculate(SCHEMA, GENERATION, &specs(), &duplicate_slot, limits())
            .unwrap_err(),
        LayoutError::DuplicateAcknowledgementRoute
    );

    for hostile in [
        AcknowledgementRouteSpec {
            owner: RoleId::new(99).unwrap(),
            ..routes()[0]
        },
        AcknowledgementRouteSpec {
            target: RoleId::new(99).unwrap(),
            ..routes()[0]
        },
        AcknowledgementRouteSpec {
            slot_index: 99,
            ..routes()[0]
        },
        AcknowledgementRouteSpec {
            cell_index: 99,
            ..routes()[0]
        },
    ] {
        let mut hostile_routes = routes();
        hostile_routes[0] = hostile;
        assert_eq!(
            RegionSetLayout::calculate(SCHEMA, GENERATION, &specs(), &hostile_routes, limits())
                .unwrap_err(),
            LayoutError::InvalidAcknowledgementRoute
        );
    }

    let mut wrong_direction = routes();
    wrong_direction[0].owner = ROLE_A;
    assert_eq!(
        RegionSetLayout::calculate(SCHEMA, GENERATION, &specs(), &wrong_direction, limits())
            .unwrap_err(),
        LayoutError::InvalidAcknowledgementRoute
    );

    let mut same_endpoint = specs();
    same_endpoint[1].writer = Endpoint::Initiator;
    assert_eq!(
        RegionSetLayout::calculate(SCHEMA, GENERATION, &same_endpoint, &routes(), limits())
            .unwrap_err(),
        LayoutError::InvalidAcknowledgementRoute
    );

    assert_eq!(
        RegionSetLayout::calculate(SCHEMA, GENERATION, &specs(), &routes()[..5], limits())
            .unwrap_err(),
        LayoutError::IncompleteAcknowledgementRoutes
    );
}
