# Changelog

All notable changes are documented here. This project follows Semantic
Versioning once a stable API is released.

## [Unreleased]

### Security

- Bind two-sided ACCEPT/REJECT ordering to a fresh nonzero 128-bit coordinator
  decision challenge. Receiver ACCEPT or REJECT must echo the exact challenge,
  preventing a malicious receiver from prequeuing a deterministic decision
  before the coordinator decides. Zero and legacy challenge-free decisions are
  rejected with no downgrade decoder; the challenge is causality evidence, not
  a MAC, secret, receipt, or authority grant.
- Define the strongest achievable Linux shared-memory authority contract:
  `MFD_NOEXEC_SEAL`, complete seal ordering, non-executable library views, and
  inherited irreversible MDWE are mandatory. Native AMD64/Arm64 evidence shows
  Linux still permits a malicious delegated peer to create RX aliases. During
  receiver-writer setup, an fd delegated outside the MDWE-inheriting process
  tree may also retain RW and later gain execute. This residual authority is
  explicit rather than overstated as object-level NX.
- Add an executable-only ELF preinitializer and `receiver_main!` entry macro.
  The preinitializer validates fresh-session MDWE and an inherited nonblocking
  `SOCK_SEQPACKET`, scrubs its reserved environment, installs CLOEXEC, and
  publishes one ownership-bearing `ReceiverBootstrap` before ordinary Rust
  application code. The public receiver session consumes that token exactly
  once; malformed or forged startup state closes the designated descriptor.
- Add private Linux executable evidence that opens an absolute native ELF with
  `openat2` symlink/magic-link rejection, retains its inode, opens the child's
  pidfd, executes through the held CLOEXEC descriptor, and compares
  `/proc/PID/exe` before any image receipt can be minted.
- Compose arbitrary mixed-direction Linux batches inside the authenticated
  accepted-session owner. The full batch is imported and manifest-bound before
  one best-effort attenuation pass final-seals every escaped receiver-writer fd;
  coordinator read mapping begins only after complete attenuation, and every
  failure poisons before transaction-owned fds and mappings are destroyed.
- Complete the Linux mixed-batch transaction with exact full-manifest
  READY/COMMIT records and compose it into public role/state-typed sessions.
  `Session<Ready>` exposes bounded opaque control and atomic mixed transfers;
  runtime mappings escape only as a complete keyed set after full reservation.
  Activation failure poisons before native cleanup, exposes no partial set,
  rolls back every charge, and preserves mapping-before-lease destruction.
- Add checked opaque active-reader/writer access, explicit off-thread prefault,
  lease-aware recoverable close, terminal abort invalidation, and bounded
  `SessionFailure` diagnostics carrying operation/stage/reason, optional errno,
  poison and endpoint facts, and coordinator child-cleanup evidence. The public
  session composition remains target-specific until Windows parity lands.
- Add a private, public-API-shaped macOS Arm64 composition prototype with a held
  stable-path image check, fresh-session `posix_spawn`, audit-PID-authenticated private
  Mach bootstrap, canonical HELLO and challenged decisions, symmetric capacity
  preflight, bounded control, mixed READY/COMMIT activation, one-shot
  `receiver_main!`, and exact direct-child wait diagnostics. Public macOS
  spawn/bootstrap remain fail-closed pending pre-bootstrap exact termination.
- Record a preinstalled signed launchd/XPC service as a necessary macOS
  lifecycle candidate, together with its authentication, privilege, serialized
  reap, and native evidence obligations. The investigation also proves that
  the service alone is insufficient across supervisor crash, so the
  architecture and public macOS path remain blocked.
- Pin the macOS helper's complete kernel audit token at private bootstrap
  authentication and require every later vNext record to carry the identical
  token. A helper `exec` keeps the numeric PID but changes the audit PID
  version, so post-exec records now fail closed with an identity mismatch
  instead of passing the PID-only trailer check. The receiver symmetrically
  pins the coordinator token at its first authenticated record.
- Record the primary-source public-API impossibility evidence for
  crash-surviving exact macOS containment in
  `docs/macos-supervisor-boundary.md`: no documented public mechanism binds a
  reuse-proof process identity to a termination primitive, launchd cleanup is
  process-group scoped and `setsid`-escapable, and no public sandbox
  entitlement denies fork. Public macOS composition remains fail-closed.

### Fixed

- Fix a macOS private-prototype negotiation race where a receiver that sent
  its validated ACCEPT and exited before the coordinator's live-image recheck
  poisoned the completed negotiation with `PeerExited`. The queued bilateral
  decision now wins: a failed live-image lookup is honored only after the
  sole-waiter lifecycle confirms the exact child's reap, live re-exec still
  fails closed as an identity mismatch, and only an `ESRCH` process lookup is
  reported as peer exit.

### Changed

- **Breaking:** rename `PermissionPlan::executable()` to
  `library_view_executable()`. The old name incorrectly suggested a guarantee
  about every alias a malicious native-capability holder could create.
- Retire the excluded duplicate `native-ipc-platform` source package after its
  backends moved behind the `native-ipc` facade. The published 0.4 artifact and
  `v0.4.0` source tag remain available. Future releases contain the normative
  three-crate graph and publish it in dependency order.
- Retire the obsolete Linux filesystem-bootstrap, stream-framed single-region
  transfer backend after confirming it had no production consumer. Preserve
  the quiescent memfd allocator shared by the public memory facade and private
  vNext preparation, and make that retained module reject dead code locally.

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
