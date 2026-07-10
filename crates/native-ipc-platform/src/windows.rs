//! Windows transport policy placeholder.

use crate::BackendStatus;

/// Reports that Windows section and private-pipe support is not yet implemented.
pub const fn status() -> BackendStatus {
    BackendStatus::Incomplete(
        "least-rights sections, private named pipes, and Job Objects are not implemented",
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
