//! Linux transport policy placeholder.

use crate::BackendStatus;

/// Reports that sealed-memfd capability transfer is not yet implemented.
pub const fn status() -> BackendStatus {
    BackendStatus::Incomplete(
        "sealed memfd, SCM_RIGHTS, SO_PEERCRED, and pidfd support is not implemented",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_fails_closed_until_permission_enforcement_exists() {
        assert!(matches!(status(), BackendStatus::Incomplete(_)));
    }
}
