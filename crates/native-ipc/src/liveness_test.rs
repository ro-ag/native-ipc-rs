use super::*;
use static_assertions::{assert_impl_all, assert_not_impl_any};

assert_impl_all!(ResourceOwner: Send);
assert_not_impl_any!(ResourceOwner: Sync, Clone);
assert_impl_all!(RegionLease: Send, Sync);
assert_not_impl_any!(RegionLease: Clone);
assert_impl_all!(LeaseReservation: Send);
assert_not_impl_any!(LeaseReservation: Sync, Clone);

fn limits() -> SessionLimits {
    SessionLimits {
        max_active_regions: 2,
        max_active_bytes: 10,
        ..SessionLimits::default()
    }
}

#[test]
fn leases_charge_exact_limits_and_block_recoverable_close() {
    let mut owner = ResourceOwner::new(limits()).unwrap();
    let rollback = owner.reserve(1).unwrap();
    drop(rollback);
    assert_eq!(owner.active_lease_facts().regions, 0);
    let first = owner.reserve(4).unwrap().complete_for_test(4).unwrap();
    let second = owner.reserve(6).unwrap().complete_for_test(6).unwrap();
    assert!(matches!(owner.reserve(1), Err(ResourceError::ActiveLimit)));
    assert_eq!(
        owner.try_close(),
        Err(ResourceError::ActiveLeases(ActiveLeaseFacts {
            regions: 2,
            bytes: 10,
            consistency: LeaseFactsConsistency::ApproximateDuringConcurrentDrop,
        }))
    );
    drop(first);
    assert_eq!(
        owner.active_lease_facts(),
        ActiveLeaseFacts {
            regions: 1,
            bytes: 6,
            consistency: LeaseFactsConsistency::ApproximateDuringConcurrentDrop,
        }
    );
    drop(second);
    owner.try_close().unwrap();
    assert_eq!(owner.state(), LivenessState::Closed);
    assert!(matches!(owner.reserve(1), Err(ResourceError::Closed)));
}

#[test]
fn poison_is_shared_with_live_regions_and_close_waits_for_drop() {
    let mut owner = ResourceOwner::new(limits()).unwrap();
    let lease = owner.reserve(5).unwrap().complete_for_test(5).unwrap();
    owner.poison();
    assert_eq!(owner.state(), LivenessState::Poisoned);
    assert_eq!(lease.state(), LivenessState::Poisoned);
    assert!(matches!(owner.reserve(1), Err(ResourceError::Poisoned)));
    assert!(matches!(
        owner.try_close(),
        Err(ResourceError::ActiveLeases(_))
    ));
    drop(lease);
    owner.try_close().unwrap();
    assert_eq!(owner.state(), LivenessState::Closed);
}

#[test]
fn dropping_control_owner_marks_surviving_region_hostile() {
    let lease = {
        let mut owner = ResourceOwner::new(limits()).unwrap();
        owner.reserve(1).unwrap().complete_for_test(1).unwrap()
    };
    assert_eq!(lease.state(), LivenessState::Poisoned);
    drop(lease);

    let mut invalid = limits();
    invalid.max_active_regions = 0;
    assert!(matches!(
        ResourceOwner::new(invalid),
        Err(ResourceError::InvalidLimits)
    ));
}

#[test]
fn concurrent_mapping_drops_never_permit_premature_close() {
    use std::sync::{Arc, Barrier};

    let mut owner = ResourceOwner::new(limits()).unwrap();
    let first = owner.reserve(4).unwrap().complete_for_test(4).unwrap();
    let second = owner.reserve(6).unwrap().complete_for_test(6).unwrap();
    let barrier = Arc::new(Barrier::new(3));
    let first_barrier = Arc::clone(&barrier);
    let first_drop = std::thread::spawn(move || {
        first_barrier.wait();
        drop(first);
    });
    let second_barrier = Arc::clone(&barrier);
    let second_drop = std::thread::spawn(move || {
        second_barrier.wait();
        drop(second);
    });
    assert!(matches!(
        owner.try_close(),
        Err(ResourceError::ActiveLeases(_))
    ));
    barrier.wait();
    first_drop.join().unwrap();
    second_drop.join().unwrap();
    assert_eq!(
        owner.active_lease_facts(),
        ActiveLeaseFacts {
            regions: 0,
            bytes: 0,
            consistency: LeaseFactsConsistency::Exact,
        }
    );
    owner.try_close().unwrap();
}

#[test]
fn completion_rechecks_exact_mapping_length_and_liveness() {
    let mut owner = ResourceOwner::new(limits()).unwrap();
    let mismatch = owner.reserve(4).unwrap().complete_for_test(3);
    assert!(matches!(
        mismatch,
        Err(ResourceError::MappedLengthMismatch {
            reserved: 4,
            actual: 3
        })
    ));
    assert_eq!(owner.active_lease_facts().regions, 0);

    let reservation = owner.reserve(4).unwrap();
    owner.poison();
    assert!(matches!(
        reservation.complete_for_test(4),
        Err(ResourceError::Poisoned)
    ));
    assert_eq!(owner.active_lease_facts().regions, 0);
}
