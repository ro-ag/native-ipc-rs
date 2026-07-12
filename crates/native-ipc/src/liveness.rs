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
#[path = "liveness_test.rs"]
mod tests;
