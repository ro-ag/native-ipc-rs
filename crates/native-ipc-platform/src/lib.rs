//! Platform capability and mapping implementations.
//!
//! Only the macOS Mach VM typestate is implemented in this initial slice.
//! Linux and Windows expose explicit fail-closed status values.

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
