use super::*;
use crate::active::{ActiveReadOwner, ActiveWriteOwner};
use crate::core::layout::{
    AcknowledgementRouteSpec, Endpoint, LayoutLimits, RegionSpec, RoleId, ValidationExpectations,
};
use std::alloc::{Layout, alloc_zeroed, dealloc};

const SCHEMA_ID: [u8; 32] = [7; 32];
const GENERATION: u64 = 9;
const SLOT_INDEX: u32 = 0;
const SEQUENCE: u64 = 1;
const PAYLOAD: &[u8] = b"ping-payload";

/// 64-byte-aligned backing store shared between the writer and reader owners in
/// a round-trip, mirroring the single shared object both endpoints map. It is
/// declared before any active value in each test so it drops last, keeping the
/// non-owning owner views valid for the whole test.
struct Backing {
    base: NonNull<u8>,
    len: usize,
}

impl Backing {
    fn new(len: usize) -> Self {
        let layout = Layout::from_size_align(len, 64).unwrap();
        // SAFETY: `len` is nonzero for every layout used here.
        let base = NonNull::new(unsafe { alloc_zeroed(layout) }).unwrap();
        Self { base, len }
    }

    fn bytes(&self) -> &[u8] {
        // SAFETY: the allocation is initialized to zero and covers `len` bytes.
        unsafe { core::slice::from_raw_parts(self.base.as_ptr(), self.len) }
    }

    fn bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: `&mut self` proves exclusive access to the whole allocation.
        unsafe { core::slice::from_raw_parts_mut(self.base.as_ptr(), self.len) }
    }
}

impl Drop for Backing {
    fn drop(&mut self) {
        // SAFETY: reconstructs the exact layout the allocation was made with.
        unsafe {
            dealloc(
                self.base.as_ptr(),
                Layout::from_size_align(self.len, 64).unwrap(),
            );
        }
    }
}

/// Non-owning read view into a `Backing` the test keeps alive past this owner.
struct BackingReadOwner {
    base: NonNull<u8>,
    len: usize,
}

// SAFETY: the test's `Backing` outlives every active value built from this
// owner, and the base is only ever touched through the checked volatile
// boundary, never as an aliased reference.
unsafe impl Send for BackingReadOwner {}
unsafe impl Sync for BackingReadOwner {}

// SAFETY: `base` is a stable 64-byte-aligned initialized allocation of `len`
// bytes that the test guarantees stays mapped for this owner's lifetime.
unsafe impl ActiveReadOwner for BackingReadOwner {
    fn as_ptr(&self) -> *const u8 {
        self.base.as_ptr()
    }
    fn len(&self) -> usize {
        self.len
    }
    fn page_size(&self) -> usize {
        64
    }
}

/// Non-owning sole-writer view into the same `Backing`.
struct BackingWriteOwner {
    base: NonNull<u8>,
    len: usize,
}

// SAFETY: as `BackingReadOwner`; the sole writable view is never aliased.
unsafe impl Send for BackingWriteOwner {}

// SAFETY: `base`/`len` describe the same stable aligned allocation, and
// `as_ptr`/`as_mut_ptr` return the identical base as required by the writer
// owner contract.
unsafe impl ActiveWriteOwner for BackingWriteOwner {
    fn as_ptr(&self) -> *const u8 {
        self.base.as_ptr()
    }
    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.base.as_ptr()
    }
    fn len(&self) -> usize {
        self.len
    }
    fn page_size(&self) -> usize {
        64
    }
}

/// Builds the two-role producer/acknowledger topology, mirroring the core
/// mapping harness so the producer region can publish and be observed.
fn build_topology() -> RegionSetLayout {
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
    RegionSetLayout::calculate(SCHEMA_ID, GENERATION, &specs, &route_specs, limits).unwrap()
}

fn producer_role() -> RoleId {
    RoleId::new(1).unwrap()
}

fn producer_total(topology: &RegionSetLayout) -> usize {
    topology.region(producer_role()).unwrap().total_size() as usize
}

/// Encodes the quiescent producer region into `backing` and returns its
/// validated layout. The layout is validated over the active mapping's logical
/// bytes, so its `mapping_size` equals the length the active value reports.
fn validate_producer(backing: &mut Backing, topology: &RegionSetLayout) -> ValidatedRegionLayout {
    topology
        .region(producer_role())
        .unwrap()
        .encode_into(backing.bytes_mut())
        .unwrap();
    // SAFETY: the backing is quiescent and unshared during validation.
    unsafe {
        ValidatedRegionLayout::validate(
            backing.bytes(),
            ValidationExpectations {
                schema_id: SCHEMA_ID,
                generation: GENERATION,
                role: producer_role(),
                writer: Endpoint::Initiator,
                maximum_mapping_size: 4096,
            },
            topology,
        )
    }
    .unwrap()
}

fn read_owner(backing: &Backing, len: usize) -> Box<BackingReadOwner> {
    Box::new(BackingReadOwner {
        base: backing.base,
        len,
    })
}

fn write_owner(backing: &Backing, len: usize) -> Box<BackingWriteOwner> {
    Box::new(BackingWriteOwner {
        base: backing.base,
        len,
    })
}

/// Publishes `PAYLOAD` at `SLOT_INDEX`/`SEQUENCE` through the writer bind path.
fn publish_via_write_bind(
    backing: &Backing,
    total: usize,
    layout: &ValidatedRegionLayout,
    topology: &RegionSetLayout,
) {
    let writer = ActiveWriter::new_unleased_for_test(write_owner(backing, total), total).unwrap();
    let mut region = writer.bind(layout.clone(), topology.clone()).unwrap();
    region.publish(SLOT_INDEX, SEQUENCE, None, PAYLOAD).unwrap();
}

#[test]
fn witnesses_carry_expected_thread_markers() {
    fn assert_send<T: Send>() {}
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<BoundReadMapping>();
    assert_send::<BoundWriteMapping>();
}

#[test]
fn bound_read_round_trip_copies_published_payload() {
    let topology = build_topology();
    let total = producer_total(&topology);
    let mut backing = Backing::new(total);
    let layout = validate_producer(&mut backing, &topology);

    publish_via_write_bind(&backing, total, &layout, &topology);

    let reader = ActiveReader::new_unleased_for_test(read_owner(&backing, total), total).unwrap();
    let bound = reader.bind(layout, topology).unwrap();
    let mut destination = [0_u8; 64];
    let copied = bound
        .copy_payload_into(SLOT_INDEX, SEQUENCE, &mut destination)
        .unwrap();
    assert_eq!(copied, PAYLOAD.len());
    assert_eq!(&destination[..copied], PAYLOAD);
}

#[test]
fn bound_write_publishes_payload_observed_by_bound_read() {
    let topology = build_topology();
    let total = producer_total(&topology);
    let mut backing = Backing::new(total);
    let layout = validate_producer(&mut backing, &topology);

    // Write side: bind, publish, and recover the writer through the witness.
    let writer = ActiveWriter::new_unleased_for_test(write_owner(&backing, total), total).unwrap();
    let mut region = writer.bind(layout.clone(), topology.clone()).unwrap();
    region.publish(SLOT_INDEX, SEQUENCE, None, PAYLOAD).unwrap();
    let recovered = region.into_mapping().into_active();
    assert_eq!(recovered.len(), total);
    drop(recovered);

    // Read side observes the published bytes with an allocating copy.
    let reader = ActiveReader::new_unleased_for_test(read_owner(&backing, total), total).unwrap();
    let bound = reader.bind(layout, topology).unwrap();
    let observed = bound.copy_payload(SLOT_INDEX, SEQUENCE).unwrap();
    assert_eq!(observed, PAYLOAD);
}

#[test]
fn rejected_read_bind_returns_recoverable_reader() {
    let topology = build_topology();
    let total = producer_total(&topology);
    let mut backing = Backing::new(total);
    let layout = validate_producer(&mut backing, &topology); // mapping_size == total

    // Mint a reader whose logical length differs from the validated layout's
    // mapping size, modelling a layout minted for a different mapping length.
    let short_len = total - 64;
    let reader =
        ActiveReader::new_unleased_for_test(read_owner(&backing, total), short_len).unwrap();
    let rejected = match reader.bind(layout, topology) {
        Ok(_) => panic!("expected the length-mismatched bind to be rejected"),
        Err(rejected) => rejected,
    };
    assert!(matches!(
        rejected.error,
        BindingError::MappingSizeMismatch { expected, actual }
            if expected == total && actual == short_len
    ));

    // The same reader comes back intact and still reads its logical bytes.
    let recovered = rejected.into_inner();
    assert_eq!(recovered.len(), short_len);
    let mut destination = [0_u8; 4];
    recovered.read_into(0, &mut destination).unwrap();
}

#[test]
fn bound_read_into_mapping_into_active_returns_usable_reader() {
    let topology = build_topology();
    let total = producer_total(&topology);
    let mut backing = Backing::new(total);
    let layout = validate_producer(&mut backing, &topology);

    publish_via_write_bind(&backing, total, &layout, &topology);

    let reader = ActiveReader::new_unleased_for_test(read_owner(&backing, total), total).unwrap();
    let bound = reader.bind(layout.clone(), topology.clone()).unwrap();
    // Release the binding and recover the active reader unchanged.
    let recovered = bound.into_mapping().into_active();
    assert_eq!(recovered.len(), total);

    // The recovered reader is still usable through a fresh bind.
    let rebound = recovered.bind(layout, topology).unwrap();
    let mut destination = [0_u8; 64];
    let copied = rebound
        .copy_payload_into(SLOT_INDEX, SEQUENCE, &mut destination)
        .unwrap();
    assert_eq!(&destination[..copied], PAYLOAD);
}

#[test]
fn bound_write_into_mapping_into_active_returns_usable_writer() {
    let topology = build_topology();
    let total = producer_total(&topology);
    let mut backing = Backing::new(total);
    let layout = validate_producer(&mut backing, &topology);

    let writer = ActiveWriter::new_unleased_for_test(write_owner(&backing, total), total).unwrap();
    let region = writer.bind(layout.clone(), topology.clone()).unwrap();
    let recovered = region.into_mapping().into_active();
    assert_eq!(recovered.len(), total);

    // The recovered writer still publishes through a fresh bind.
    let mut rebound = recovered.bind(layout, topology).unwrap();
    rebound
        .publish(SLOT_INDEX, SEQUENCE, None, PAYLOAD)
        .unwrap();
}
