# Changelog

All notable changes are documented here. This project follows Semantic
Versioning once a stable API is released.

## [Unreleased]

## [0.1.0] - 2026-07-10

### Added

- Initial four-crate workspace.
- Generic fixed-width message envelope and explicit payload codec traits.
- Checked configurable region/slot layouts and bounded validation errors.
- Role-, generation-, capacity-, index-, count-, and permission-bound slot
  reader/writer capabilities.
- Split acknowledgement capabilities with exact ring-reuse validation.
- macOS Mach quiescent/local-writer/remote-writer typestates and live
  permission-escalation tests.
- Linux sealed-memory capability transfer with kernel peer credentials, pidfds,
  and an owned cross-process helper lifecycle.
- Windows exact-rights unnamed-section duplication over a private PID-checked
  named pipe with suspended Job containment and a real helper fixture.
- Authenticated private Mach bootstrap, audit-token PID checks, memory-entry
  transfer/import, READY barriers, and bidirectional helper-process coverage.
- Composition-validated one-cell-per-slot acknowledgement routes.
- Audited mapping-to-atomic binding with platform permission witnesses,
  peer-mutable padding, and compile-time field offsets.
- Fenced generation/sequence/length snapshot rechecks with an explicit
  no-payload-integrity guarantee.
- Explicit macOS page-rounded capability sizes and zero-padding validation.
- No-default-feature CI tests, core Miri, bounded hostile corpora, and a full
  common-core binding lifecycle test.
- Coverage-guided envelope/layout fuzz targets run for bounded time in CI.

[Unreleased]: https://github.com/ro-ag/native-ipc-rs/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/ro-ag/native-ipc-rs/releases/tag/v0.1.0
