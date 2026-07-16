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
/// fixed process vector, FIFO reader, and control stream; receives and
/// acknowledges one canonical launch plan, waits for one start byte, then
/// retains the reader until service-death EOF. It exists only so a separately
/// compiled minimal broker executable can enter reviewed crate-private code.
///
/// # Safety
///
/// This must run in the just-execed dedicated broker before threads, children,
/// policy, or effect-bearing endpoints. The exact fixed spawner must
/// exclusively transfer descriptors 3 and 4 and the installed process vector;
/// no Rust value may already own either descriptor. `installed_path` must be an
/// absolute compile-time constant in the deployer's broker artifact and must
/// not derive from request data. Read-only fixture dispatch over `argv[0]` is
/// permitted before entry.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[doc(hidden)]
pub unsafe fn __private_macos_broker_gate_main(installed_path: &std::ffi::CStr) -> ! {
    // SAFETY: the caller supplies the complete fixed process-entry contract.
    unsafe { backend::macos::run_fixed_broker_gate_process(installed_path) }
}

/// Runs the complete fixed macOS broker launcher lifecycle without callbacks.
///
/// This hidden artifact entry stages and activates the exact parent plan,
/// pre-creates its fixed clean-exec authentication worker, spawns the fixed
/// launcher, delivers the plan, verifies the target at its exec trap, reports
/// the held trace state, and resumes only after the Ready-bound reverse commit.
/// Public macOS construction uses the direct-spawn session path and does not
/// call this entry.
///
/// # Safety
///
/// This must run in the just-execed dedicated broker before threads, children,
/// policy, or effect-bearing endpoints. The exact fixed spawner must
/// exclusively transfer descriptors 3 through 5 and the installed process
/// vector. Each path must be an absolute compile-time constant in the
/// deployer's broker artifact, must not derive from request data, and must name
/// the exact replacement-resistant signed image verified by the installation.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[doc(hidden)]
pub unsafe fn __private_macos_broker_main(
    installed_path: &std::ffi::CStr,
    launcher_path: &std::ffi::CStr,
    auth_worker_path: &std::ffi::CStr,
) -> ! {
    // SAFETY: the caller supplies the complete fixed process-entry contract.
    unsafe {
        backend::macos::run_fixed_broker_process(installed_path, launcher_path, auth_worker_path)
    }
}

/// Runs the fixed macOS trusted-launcher boundary without callbacks.
///
/// The launcher exists because the target is foreign code that cannot trace
/// itself. This image designates the broker as its tracer, stops for identity
/// proof, contains itself, then becomes the target. It needs no privilege and
/// refuses to run as root.
///
/// # Safety
///
/// This must run in the just-execed launcher before threads, children, or
/// effect-bearing endpoints exist. The fixed spawner must exclusively transfer
/// descriptor 3 (broker death) and descriptor 4 (plan) plus the installed
/// process vector; no Rust value may already own either descriptor.
/// `installed_path` must be an absolute compile-time constant in the deployer's
/// launcher artifact and must not derive from request data.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[doc(hidden)]
pub unsafe fn __private_macos_launcher_main(installed_path: &std::ffi::CStr) -> ! {
    // SAFETY: the caller supplies the complete fixed process-entry contract.
    unsafe { backend::macos::run_fixed_launcher_process(installed_path) }
}

/// Runs the fixed macOS clean-exec authentication-worker boundary.
///
/// This hidden artifact entry validates one exact inherited request, performs
/// the installed fixed Security requirement check against its audit token,
/// emits one canonical result, and exits. It exists only for a separately
/// compiled minimal signed worker executable.
///
/// # Safety
///
/// This must run in the just-execed dedicated worker before threads or
/// Security.framework initialization. `installed_path`, `requirement`, and
/// `code_identity` must be compile-time installed-policy constants in that
/// artifact; `installed_path` must be absolute. None may derive from request
/// data. The exact spawner must exclusively transfer descriptors 3 and 4 plus
/// the fixed vector.
#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
#[doc(hidden)]
pub unsafe fn __private_macos_auth_worker_main(
    installed_path: &std::ffi::CStr,
    requirement: &std::ffi::CStr,
    code_identity: [u8; 32],
) -> ! {
    // SAFETY: the caller supplies the complete fixed process-entry contract.
    unsafe {
        backend::macos::run_fixed_auth_worker_process(installed_path, requirement, code_identity)
    }
}
