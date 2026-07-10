#![doc = include_str!("../../../README.md")]

/// Platform-neutral wire, layout, and sequencing primitives.
pub use native_ipc_core as core;
/// Native operating-system capability implementations.
pub use native_ipc_platform as platform;
