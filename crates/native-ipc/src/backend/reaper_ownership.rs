//! Model-checkable ownership state for detached child reapers.

#[cfg(all(test, loom))]
use loom::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
#[cfg(not(all(test, loom)))]
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};

struct ReaperOwnershipState {
    external_owners: AtomicUsize,
    terminate: AtomicBool,
}

/// A non-owning-count handle through which the worker observes cancellation.
pub(super) struct ReaperTermination {
    shared: Arc<ReaperOwnershipState>,
}

impl ReaperTermination {
    pub(super) fn request(&self) {
        self.shared.terminate.store(true, Ordering::Release);
    }

    pub(super) fn requested(&self) -> bool {
        self.shared.terminate.load(Ordering::Acquire)
    }
}

/// One external lifecycle owner of a detached reaper.
///
/// The explicit owner count deliberately excludes the worker's termination
/// handle. An `Arc::strong_count` snapshot cannot identify the last external
/// owner when owners are dropped concurrently: both drops may observe the
/// earlier count before either `Arc` field is destroyed.
pub(super) struct ReaperOwnership {
    shared: Arc<ReaperOwnershipState>,
    active: bool,
}

impl ReaperOwnership {
    pub(super) fn new() -> Self {
        Self {
            shared: Arc::new(ReaperOwnershipState {
                external_owners: AtomicUsize::new(1),
                terminate: AtomicBool::new(false),
            }),
            active: true,
        }
    }

    pub(super) fn termination(&self) -> ReaperTermination {
        ReaperTermination {
            shared: Arc::clone(&self.shared),
        }
    }

    /// Releases this owner, returning whether it latched termination.
    pub(super) fn release(&mut self) -> bool {
        if !self.active {
            return false;
        }
        // Disable the destructor before checking the invariant so an
        // invariant panic cannot recurse through a second release attempt.
        self.active = false;
        let previous = self
            .shared
            .external_owners
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_sub(1)
            })
            .unwrap_or_else(|current| panic!("lifecycle owner count underflowed from {current}"));
        if previous == 1 {
            self.shared.terminate.store(true, Ordering::Release);
            true
        } else {
            false
        }
    }
}

impl Clone for ReaperOwnership {
    fn clone(&self) -> Self {
        assert!(self.active, "cannot clone a released lifecycle owner");
        self.shared
            .external_owners
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1)
            })
            .unwrap_or_else(|current| panic!("lifecycle owner count overflowed from {current}"));
        Self {
            shared: Arc::clone(&self.shared),
            active: true,
        }
    }
}

impl Drop for ReaperOwnership {
    fn drop(&mut self) {
        let _ = self.release();
    }
}
