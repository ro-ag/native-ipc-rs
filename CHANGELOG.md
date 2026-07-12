# Changelog

All notable changes are documented here. This project follows Semantic
Versioning once a stable API is released.

## [Unreleased]

### Security

- Define the strongest achievable Linux shared-memory authority contract:
  `MFD_NOEXEC_SEAL`, complete seal ordering, non-executable library views, and
  inherited irreversible MDWE are mandatory. Native AMD64/Arm64 evidence shows
  Linux still permits a malicious delegated peer to create RX aliases. During
  receiver-writer setup, an fd delegated outside the MDWE-inheriting process
  tree may also retain RW and later gain execute. This residual authority is
  explicit rather than overstated as object-level NX.
- Add a private trusted pre-exec hook that installs exact inherited MDWE and
  propagates setup failure before exec. It deliberately mints no witness;
  memory preparation remains gated until exact-image, authenticated-channel,
  pidfd, and bounded-cleanup ownership are combined.

### Changed

- **Breaking:** rename `PermissionPlan::executable()` to
  `library_view_executable()`. The old name incorrectly suggested a guarantee
  about every alias a malicious native-capability holder could create.

## [0.4.0] - 2026-07-11

### Changed

- **Breaking:** Windows `import_reader` and `import_writer` are now
  `ChildChannel` methods instead of free functions, and `MacBindingError` /
  `WindowsError` gained the `ForeignPending` variant. Code calling the free
  functions or matching those enums exhaustively must update.

### Fixed

- Bind every pending transfer and import value to its originating channel and
  transfer transaction. `commit_transfers` and `commit_imports` on macOS and
  Windows now fail closed with a `ForeignPending` error before READY/COMMIT
  when any pending value came from another channel or an earlier transaction,
  and the mismatched transaction is poisoned. Windows imports moved from free
  functions to `ChildChannel::import_reader`/`ChildChannel::import_writer` so
  the binding is unforgeable.
- Return Linux `ChildSession::spawn` bootstrap resources to baseline on every
  failure path: a construction guard now removes the private bootstrap
  directory and kills and reaps the helper on pre-accept, timeout, peer
  credential, and channel construction failures.
- Stop the macOS null-address allocation branch from speculatively
  deallocating the page-zero range, and release the parent's extra bootstrap
  send-right reference even when `posix_spawn` fails.

### Documentation

- State the consolidation goal explicitly across the README, crate landing
  pages, and architecture doc: one safe library over the three non-portable
  native mechanisms for sealed, least-authority anonymous shared memory —
  `memfd_create` and file seals are Linux-only, macOS uses Mach memory-entry
  rights, and Windows uses exact-rights duplicated section handles.

## [0.3.0] - 2026-07-11

### Fixed

- Make native capability bootstrap a canonical `CAPABILITY -> READY -> COMMIT`
  transaction. Runtime reader and writer regions remain hidden until both peers
  validate the exact versioned manifest and COMMIT succeeds.
- Make Linux `SCM_RIGHTS` stream framing tolerate short reads and immediately
  own every installed descriptor so malformed transfers cannot leak file
  descriptors.

### Documentation

- Add crates.io landing pages, runnable examples, complete public error-field
  documentation, and cross-target READY/COMMIT API guidance for every crate.

## [0.2.0] - 2026-07-10

### Added

- Add a common cross-platform native memory lifecycle API with fixed or bounded
  pre-share growth, one-writer permission plans, reusable clearing, explicit
  clear-and-destroy, backend capability reporting, and mandatory sealing on
  transfer.
- Support and continuously test ARM64 and AMD64 native backends on Linux and
  Windows, with macOS intentionally supported on ARM64 only.
- Run the full Linux AMD64 workspace and native lifecycle suite under
  AddressSanitizer with leak and stack-use-after-return detection.
- Assert exact Linux failure modes for size overflow, unsealed capabilities,
  peer mismatch, oversized payloads, writable remapping, descriptor writes,
  and sealed-region growth or shrink attempts.

### Documentation

- Add architecture and memory-access diagrams, runnable codec/layout examples,
  status badges, and GitHub community contribution templates.

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

[Unreleased]: https://github.com/ro-ag/native-ipc-rs/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/ro-ag/native-ipc-rs/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/ro-ag/native-ipc-rs/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ro-ag/native-ipc-rs/releases/tag/v0.1.0
