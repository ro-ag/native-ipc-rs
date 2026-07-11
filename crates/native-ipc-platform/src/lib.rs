//! Platform capability and mapping implementations.
//!
//! macOS, Linux, and Windows adapters implement private authenticated bootstrap,
//! least-authority shared-memory transfer, and owned helper lifecycles.

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
