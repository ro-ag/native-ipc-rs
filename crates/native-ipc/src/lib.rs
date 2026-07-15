#![doc = include_str!("../README.md")]

#[cfg(not(any(
    all(
        target_os = "linux",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ),
    all(
        target_os = "windows",
        any(target_arch = "aarch64", target_arch = "x86_64")
    ),
    all(target_os = "macos", target_arch = "aarch64")
)))]
compile_error!("native-ipc supports Linux and Windows on aarch64/x86_64, and macOS on aarch64");

/// Platform-neutral wire, layout, and sequencing primitives.
pub use native_ipc_core as core;

/// Checked allocation-free runtime access after batch commit.
pub mod active;
#[allow(dead_code)]
/// Atomic transfer-batch construction, expectations, and committed active sets.
pub mod batch;
/// Common native shared-memory allocation, policy, and cleanup interface.
pub mod memory;
/// Platform-neutral consuming region ownership states.
pub mod region;
/// Finite session limits, target capabilities, and absolute deadlines.
pub mod session;

mod backend;
/// Bounded opaque application-control records and validation errors.
pub mod control;
#[allow(dead_code)]
mod liveness;
#[allow(dead_code)]
mod negotiation;
mod protocol;

/// Runs the fixed macOS broker gate executable boundary without callbacks.
///
/// This hidden artifact entry performs no launch effect: it validates the
/// fixed process vector and FIFO reader, waits for one start byte, then retains
/// the reader until service-death EOF. It exists only so a separately compiled
/// minimal broker executable can enter reviewed crate-private gate code.
///
/// # Safety
///
/// This must run in the just-execed dedicated broker before threads, children,
/// policy, or effect-bearing endpoints. The exact fixed spawner must
/// exclusively transfer descriptor 3 and the installed process vector; no
/// Rust value may already own that descriptor. Read-only fixture dispatch over
/// `argv[0]` is permitted before entry.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[doc(hidden)]
pub unsafe fn __private_macos_broker_gate_main() -> ! {
    // SAFETY: the caller supplies the complete fixed process-entry contract.
    unsafe { backend::macos::run_fixed_broker_gate_process() }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(dead_code)]
pub(crate) enum BackendStatus {
    Available,
    Incomplete(&'static str),
}
