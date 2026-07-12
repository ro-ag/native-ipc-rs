use crate::active::LeaseReservation;
use crate::session::SessionLimits;
use core::cell::Cell;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

const ACTIVE: u8 = 0;
const POISONED: u8 = 1;
const CLOSED: u8 = 2;

pub(crate) struct ResourceOwner {
    shared: Arc<SharedResources>,
    not_sync: PhantomData<Cell<()>>,
}

struct SharedResources {
    state: AtomicU8,
    active_regions: AtomicU32,
    active_bytes: AtomicU64,
    maximum_regions: u32,
    maximum_bytes: u64,
}

pub(crate) struct RegionLease {
    shared: Arc<SharedResources>,
    bytes: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LivenessState {
    Active,
    Poisoned,
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ActiveLeaseFacts {
    pub(crate) regions: u32,
    pub(crate) bytes: u64,
    pub(crate) consistency: LeaseFactsConsistency,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LeaseFactsConsistency {
    Exact,
    ApproximateDuringConcurrentDrop,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResourceError {
    InvalidLimits,
    Poisoned,
    Closed,
    ActiveLimit,
    MappedLengthMismatch { reserved: u64, actual: u64 },
    ActiveLeases(ActiveLeaseFacts),
}

impl ResourceOwner {
    pub(crate) fn new(limits: SessionLimits) -> Result<Self, ResourceError> {
        let limits = limits
            .validate()
            .map_err(|_| ResourceError::InvalidLimits)?;
        Ok(Self {
            shared: Arc::new(SharedResources {
                state: AtomicU8::new(ACTIVE),
                active_regions: AtomicU32::new(0),
                active_bytes: AtomicU64::new(0),
                maximum_regions: limits.max_active_regions,
                maximum_bytes: limits.max_active_bytes,
            }),
            not_sync: PhantomData,
        })
    }

    pub(crate) fn reserve(&mut self, bytes: u64) -> Result<LeaseReservation, ResourceError> {
        if bytes == 0 || bytes > self.shared.maximum_bytes {
            return Err(ResourceError::ActiveLimit);
        }
        self.ensure_active()?;
        self.shared
            .active_regions
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |regions| {
                (regions < self.shared.maximum_regions).then_some(regions + 1)
            })
            .map_err(|_| ResourceError::ActiveLimit)?;
        if self
            .shared
            .active_bytes
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current
                    .checked_add(bytes)
                    .filter(|next| *next <= self.shared.maximum_bytes)
            })
            .is_err()
        {
            self.shared.active_regions.fetch_sub(1, Ordering::AcqRel);
            return Err(ResourceError::ActiveLimit);
        }
        if let Err(error) = self.ensure_active() {
            self.shared.active_bytes.fetch_sub(bytes, Ordering::AcqRel);
            self.shared.active_regions.fetch_sub(1, Ordering::AcqRel);
            return Err(error);
        }
        Ok(LeaseReservation::new(RegionLease {
            shared: Arc::clone(&self.shared),
            bytes,
        }))
    }

    pub(crate) fn poison(&mut self) {
        let _ = self.shared.state.compare_exchange(
            ACTIVE,
            POISONED,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    pub(crate) fn try_close(&mut self) -> Result<(), ResourceError> {
        let facts = self.active_lease_facts();
        if facts.regions != 0 || facts.bytes != 0 {
            return Err(ResourceError::ActiveLeases(facts));
        }
        loop {
            let current = self.shared.state.load(Ordering::Acquire);
            if current == CLOSED {
                return Err(ResourceError::Closed);
            }
            if self
                .shared
                .state
                .compare_exchange(current, CLOSED, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Ok(());
            }
        }
    }

    pub(crate) fn state(&self) -> LivenessState {
        decode_state(self.shared.state.load(Ordering::Acquire))
    }

    pub(crate) fn active_lease_facts(&self) -> ActiveLeaseFacts {
        let regions = self.shared.active_regions.load(Ordering::Acquire);
        let bytes = self.shared.active_bytes.load(Ordering::Acquire);
        ActiveLeaseFacts {
            regions,
            bytes,
            consistency: if regions == 0 && bytes == 0 {
                LeaseFactsConsistency::Exact
            } else {
                LeaseFactsConsistency::ApproximateDuringConcurrentDrop
            },
        }
    }

    fn ensure_active(&self) -> Result<(), ResourceError> {
        match self.state() {
            LivenessState::Active => Ok(()),
            LivenessState::Poisoned => Err(ResourceError::Poisoned),
            LivenessState::Closed => Err(ResourceError::Closed),
        }
    }
}

impl Drop for ResourceOwner {
    fn drop(&mut self) {
        self.poison();
    }
}

impl RegionLease {
    pub(crate) const fn bytes(&self) -> u64 {
        self.bytes
    }

    pub(crate) fn state(&self) -> LivenessState {
        decode_state(self.shared.state.load(Ordering::Acquire))
    }
}

impl Drop for RegionLease {
    fn drop(&mut self) {
        let previous_bytes = self
            .shared
            .active_bytes
            .fetch_sub(self.bytes, Ordering::AcqRel);
        debug_assert!(previous_bytes >= self.bytes);
        let previous_regions = self.shared.active_regions.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous_regions >= 1);
    }
}

fn decode_state(state: u8) -> LivenessState {
    match state {
        ACTIVE => LivenessState::Active,
        POISONED => LivenessState::Poisoned,
        CLOSED => LivenessState::Closed,
        _ => unreachable!("private liveness state is canonical"),
    }
}

#[cfg(test)]
mod tests {
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
}
