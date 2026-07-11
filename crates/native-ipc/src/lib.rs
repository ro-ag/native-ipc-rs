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
/// Native operating-system capability implementations.
pub use native_ipc_platform as platform;

/// Common native shared-memory allocation, policy, and cleanup interface.
pub mod memory;
