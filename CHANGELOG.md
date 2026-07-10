# Changelog

All notable changes are documented here. This project follows Semantic
Versioning once a stable API is released.

## [Unreleased]

### Added

- Initial four-crate workspace.
- Generic fixed-width message envelope and explicit payload codec traits.
- Checked configurable region/slot layouts and bounded validation errors.
- Role-, generation-, capacity-, index-, count-, and permission-bound slot
  reader/writer capabilities.
- Split acknowledgement capabilities with exact ring-reuse validation.
- macOS Mach quiescent/local-writer/remote-writer typestates and live
  permission-escalation tests.
- Explicit incomplete Linux and Windows backends.
- Composition-validated one-cell-per-slot acknowledgement routes.
- Audited mapping-to-atomic binding with platform permission witnesses,
  peer-mutable padding, and compile-time field offsets.
- Fenced generation/sequence/length snapshot rechecks with an explicit
  no-payload-integrity guarantee.
- Explicit macOS page-rounded capability sizes and zero-padding validation.
- No-default-feature CI tests, core Miri, bounded hostile corpora, and a full
  common-core binding lifecycle test.
