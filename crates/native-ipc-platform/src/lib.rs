//! Platform capability and mapping implementations.
//!
//! macOS, Linux, and Windows adapters implement private authenticated bootstrap,
//! least-authority shared-memory transfer, and owned helper lifecycles.

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
compile_error!(
    "native-ipc-platform supports Linux and Windows on aarch64/x86_64, and macOS on aarch64"
);

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "windows")]
pub mod windows;

/// Status of an operating-system transport backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendStatus {
    /// The backend enforces its documented capability policy.
    Available,
    /// The backend is deliberately unavailable rather than offering weaker behavior.
    Incomplete(&'static str),
}

mod protocol;
