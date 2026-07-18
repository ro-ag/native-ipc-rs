# Changelog

All notable changes are documented here. This project follows Semantic
Versioning once a stable API is released.

## [Unreleased]

### Added

- Inaccessible guard bands around every vnext active view mapping on Linux
  (`PROT_NONE` reservation carve), macOS (Mach fixed-overwrite placement
  inside a protected reservation), and Windows (reserved placeholders around
  a `MapViewOfFile3` view), with honest reporting:
  `ActiveReader::guard_capability` and `ActiveWriter::guard_capability`
  return the requested policy and whether bands actually installed. The
  creating endpoint honors the region's `GuardPolicy` (`Require` fails batch
  preparation or commit when a band cannot install; `Disable` skips bands);
  the receiving endpoint always applies best-effort placement because the
  wire manifest is unchanged. Bands contain in-process linear overruns past
  a view; they do not constrain the peer's address space or hostile
  native-capability aliases.

- `binding` module: safe audited conversion from committed active mappings to
  core read/write capabilities (`ActiveReader::bind`, `ActiveWriter::bind`,
  recoverable `BindRejected`, reversible witnesses). Downstream no longer
  needs the `raw-pointer` feature or a hand-written unsafe adapter to run the
  audited core protocol over session-transferred regions.
- `core::mapping::ReaderRegion::copy_payload_into` copies one observed hostile
  payload into caller-owned storage with the same observe → volatile copy →
  metadata recheck discipline as `copy_payload`, performing no allocation, for
  consumers that cannot allocate on their read path. Short destinations report
  the new `BindingError::DestinationTooSmall` without touching shared bytes.
- `core::mapping::{ReaderRegion, WriterRegion}::into_mapping` release a
  binding and return the owned mapping witness.

### Changed

- Docs: retitle the crate README's vNext session section from "Unreleased" to
  "Experimental" and correct the workspace and crate READMEs to reflect that
  guard bands ship on every vnext active view mapping (reported through
  `ActiveReader`/`ActiveWriter::guard_capability`), that native Windows Arm64
  and Linux Arm64 full-suite evidence now exists, and that `region.rs`'s
  `with_guard_policy` doc uses "guard-band" rather than the stale
  "guard-page" wording.
- `PrivateRegion::allocate` accepts `GuardPolicy::Require` instead of
  rejecting it with `GuardUnavailable`: guard bands install at view-mapping
  time, so a `Require` region now fails at batch preparation or commit when
  bands cannot install. `PreparedRegion::guard_capability` keeps reporting
  `installed: false` and documents that the active reporters carry the
  post-commit outcome.
- `core::mapping::{ReaderRegion, WriterRegion}::new` return the rejected
  mapping witness alongside the binding error, so callers recover the
  consumed witness instead of losing it.
- Unify the cross-platform public-API failure semantics recorded as known
  limitations in 0.5.0. Every target now rejects the same reserved bootstrap
  environment union before any backend work; an expired coordinator
  `wait_for_exit` deadline with a live child no longer poisons the Windows
  session; a nonexistent executable path reports the kernel error on every
  target; an absent receiver bootstrap designation reports invalid input at
  `NotEstablished` instead of claiming a malformed peer; waiting on a
  poisoned session reports `Poisoned` uniformly; and Windows termination
  facts carry the exact exit code the kernel recorded instead of a fabricated
  `Exited(127)`. Native evidence: full suites green on macOS Arm64, Linux
  ARM64, and Windows ARM64.

## [0.5.0] - 2026-07-17

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
  session composition remains target-specific while macOS stays fail-closed.
- Compose the public Windows `Negotiating` and `Ready` session surface over the
  exact-PID named-pipe transport, held executable identity, kill-on-close Job,
  full-manifest mixed reducer, bilateral capacity recovery, bounded control,
  active mappings, and exact whole-Job exit/abort diagnostics. The downstream
  `receiver_main!` path and extracted release-order crates now run the same
  all-feature and no-default Windows AMD64 corpus as the source workspace.
- Add a private, public-API-shaped macOS Arm64 composition prototype with a held
  stable-path image check, fresh-session `posix_spawn`, audit-PID-authenticated private
  Mach bootstrap, canonical HELLO and challenged decisions, symmetric capacity
  preflight, bounded control, mixed READY/COMMIT activation, one-shot
  `receiver_main!`, and exact direct-child wait diagnostics. Public macOS
  spawn/bootstrap remain fail-closed pending public crash-surviving exact
  containment.
- Start the private macOS helper suspended, capture a task-name right and
  `TASK_AUDIT_TOKEN` before resume, and use the existing private audit-token
  signal SPI to terminate a silent direct child without numeric-PID fallback.
  Native probes show that ordinary `exec` invalidates the task-name right,
  supervisor crash drops the authority, and a `setsid` descendant survives;
  therefore this narrows the blocker but does not enable public macOS.
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
- Narrow that negative result with a backend-private trusted-launcher gate.
  The launcher authenticates its broker, proves cooperative tracing with an
  explicit stop, installs hard `RLIMIT_NPROC=1`, and execs through the trace
  trap before target code. Native tests prove post-exec fork denial, exact
  stopped `PT_KILL`, and kernel tracee cleanup when the broker exits. A mutex
  waiter gate prevents the background reaper from consuming handshake stops.
- Record the remaining macOS authority blocker: a same-UID hostile tracee can
  `SIGSTOP` its broker indefinitely, while the launchd bootstrap namespace
  restored for libxpc permits delegated work outside the rlimit. Keep public
  macOS fail-closed pending a packaged signed launcher and independently
  privileged, authenticated, non-deputy service/watchdog.
- Add backend-private source models for that future deployment boundary: an
  authentication-only nonce exchange followed by one bounded installed-policy
  spawn request; opaque connection-bound watchdog handles retaining linear
  exact broker/reap authority across cleanup retries; and an abort-on-failure
  launcher transition that clears supplementary groups, permanently drops real,
  effective, and saved UID/GID to the authenticated nonroot client, then installs
  hard and soft `RLIMIT_NPROC=1`. These models remain unreachable from public
  macOS and are not signed-service, installed-launcher, or root-native evidence.
- Bind the modeled supervisor request to an absolute Darwin
  `CLOCK_UPTIME_RAW` deadline rather than restarting a relative timeout after
  transport. Add a one-shot client authentication typestate that accepts
  service generation/nonces only from an exact-message-authenticated reply.
  Keep exact UID/GID authentication on a raw Mach audit trailer because public
  XPC exposes only connection-time credential snapshots.
- Retain the complete exact-message audit token in the authenticated supervisor
  peer so an exec, PID-version change, or credential transition cannot cross
  from the authentication hello into the spawn request. Restrict the unsafe
  peer/message constructors to the future fused Mach receiver; only test-only
  synthetic seams remain visible elsewhere.
- Add the backend-private canonical raw Mach receiver and fixed worker pipe
  codecs. Malformed, complex, and oversized messages release returned rights;
  accepted requests retain one linear send-once reply. Authentication and exact
  worker reap now precede hello/spawn routing, and wrong-peer/wrong-nonce traffic
  cannot poison another live connection. This does not enable public macOS or
  supply the installed privileged service and clean-exec Security workers.
- Replace the modeled authentication-worker receipt with an actual linear
  one-shot pipe capability. Submission is one atomic fixed frame; completion
  requires exactly one fixed result plus EOF; every I/O, deadline, abnormal
  exit, and exact-reap-pending outcome preserves the slot/generation needed for
  exact cancellation or retry. Add a sole-waiter direct-child authority whose
  unreaped zombie relation pins the PID, fails stop on `ECHILD`, and authorizes
  a result only after normal status-zero reap.
- Add a receive-only authenticated macOS spawn-result shape. The client waits
  for exact service identity, generation, both nonces, and sequence one before
  accepting either a redacted opaque handle or one of four coarse failures.
  No production success encoder exists until watchdog readiness proof and
  retained reply-right integration are implemented.
- Bind every accepted spawn's decoded connection generation, sequence, and both
  nonces to its linear Mach send-once reply through later success/error mapping.
  Add a one-shot main-thread child-wait-domain prerequisite checker that rejects
  threaded startup, nondefault SIGCHLD, and automatic reaping, then installs a
  canonical blocked SIGCHLD policy. It intentionally cannot construct a
  production child until the clean-exec spawner owns the atomic spawn-to-armed
  transition.
- Make watchdog readiness a linear proof minted only by the registered
  unexpired `Starting` to exact-traced transition. An expired transition mints
  no proof and enters exact deadline cleanup. If a future Ready reply is not
  deliverable, consuming that proof records a distinct terminal reason and
  exactly reaps or retains the same broker authority for retry.
- Separate raw-Mach receive polling from the authentication authority window.
  Client Hello uses a fixed service authentication cap; Spawn uses the earlier
  of that cap and its exact original wire deadline. Normalize only Darwin's
  verified zero message-alignment bytes before digesting the logical record;
  inconsistent/nonzero padding rejects before worker assignment and destroys
  the retained send-once reply.
- Fuse the accepted spawn reply with a session assigned before broker creation,
  one atomic launch-plus-exact-broker result, and a session-specific armed
  watchdog obligation. Require that broker to remain dormant until the table
  contains its exact owner; only then may one nonblocking, non-callback
  activation release its fixed start gate. Activation failure exact-reaps and
  tombstones before returning. Its revocable launch permit holds no long-lived table
  borrow, so same-session and unrelated cleanup remain operable while it is
  pending. A short final guard revalidates the live registration immediately
  across the no-callback credential-drop/exec transition; copied launch bytes
  cannot commit after reap. The
  obligation survives trace validation, then moves
  into a zero-timeout prepared Mach Ready send. Substitution, abandonment,
  freshness/deadline failure, and recoverable send failure exact-clean the
  bound broker before returning; indeterminate send status exact-cleans before
  fail-stop. This is backend-private source/native evidence and does not supply
  the installed privileged service or enable public macOS sessions.
- Characterize the public raw-Mach deployment path with ignored C/CMake probes:
  launchd `bootstrap_check_in`/`bootstrap_look_up` delivers exact bidirectional
  audit trailers, and Security accepts exactly 32 native audit-token bytes for
  `kSecGuestAttributeAudit` while rejecting length and token mutations. These
  mechanism probes do not replace signed/root packaged evidence.
- Exercise the same raw-Mach boundary with a local Developer ID Application
  identity: a hardened-runtime per-user launchd service validates the exact
  request audit token against one fixed client designated requirement, accepts
  only the matching client, rejects same-signer/wrong-identifier and ad-hoc
  images, and observes unsigned or post-signature-mutated clients killed before
  authorization. This is local signed mechanism evidence, not a privileged
  installed-service or downstream distribution claim.
- Add a backend-private fused authentication-adapter state model. One retained
  exact Mach frame is bound to a fixed one-job worker through a domain-separated
  digest, complete audit token, credentials, connection/generation, linear
  private-endpoint receipt, and original absolute deadline. No result can mint
  supervisor peer authority until a bounded nonblocking observation returns an
  exact worker-reap proof; mismatched, late, wedged, or cancelled workers retain
  exact cleanup authority and a slot cannot be replaced until reap. Live replay
  state and the strictly increasing worker-generation allocator are bounded.
- Extend the ignored Security probe across `exec`: a token captured from image A
  is rejected after the same PID execs image B. Rework lookup helpers as clean
  exec workers after stress exposed that calling Security.framework in a child
  forked after framework initialization is not a safe worker topology.
- Add a repeated nested-tracer native proof for watchdog recovery: the target
  stops its broker, the outer tracer uses `PT_KILL` on that exact stopped
  broker and reaps it, and XNU removes the broker's exact tracee without a
  numeric-PID reacquisition. This is kernel-mechanism evidence, not signed/root
  deployment evidence.
- Adopt the standing decision that public macOS stays fail-closed instead of
  re-scoping the contract to a weaker documented containment class or
  depending on private interfaces. Enabling it now requires proof of the
  privileged watchdog, permanent nonroot target identity, hostile-stop
  recovery, and an explicit delegated-XPC ownership boundary.
- Record packaged-crate conformance: the three release-order `cargo package`
  artifacts rebuild from extracted sources and pass the all-feature and
  no-default workspace suites natively on physical Apple Silicon. Reconcile
  the traceability progress ledger (hosted macOS reducer evidence, blocked-by-
  decision 6d state) and the README/architecture/feasibility macOS status
  text with the standing fail-closed decision.

### Added

- Prove the section 10 real-time contract dynamically on the public macOS
  active path. A dedicated `tests/rt` binary carries its own counting global
  allocator and task-level syscall/context-switch/fault deltas: after an
  explicit prefault, a 10,000-iteration `write_from`/`read_into`/`fill` hot
  window makes exactly zero measured-thread allocator entries and cannot
  contain a per-operation syscall, wait, or fault; prefault reports exact
  touched coverage and observes faults on freshly imported mappings without
  promising residency; every access after abrupt peer death returns bounded
  success or `SessionInactive`, before and after the exact reap; and one full
  session close plus one fresh replacement session execute without a single
  allocator entry on the measured active thread. Deliberate allocation and
  unix/Mach syscall tripwires prove each instrument detects the violation it
  guards against.

### Fixed

- Replace the macOS detached-reaper's `Arc::strong_count` last-owner heuristic
  with an explicit atomic external-owner count. A Loom model now exhaustively
  verifies that concurrent final owner drops cannot lose the latched termination
  request; this in-process check does not model kernel reaping or CI timing.
- Fix a macOS private-prototype negotiation race where a receiver that sent
  its validated ACCEPT and exited before the coordinator's live-image recheck
  poisoned the completed negotiation with `PeerExited`. The queued bilateral
  decision now wins: a failed live-image lookup is honored only after the
  sole-waiter lifecycle confirms the exact child's reap, live re-exec still
  fails closed as an identity mismatch, and only an `ESRCH` process lookup is
  reported as peer exit.
- Scrub the inherited bootstrap environment in the public macOS receiver so a
  receiver's descendants no longer inherit the live Mach nonce, parent PID, or
  one-shot public-bootstrap marker, matching the Linux pre-init and Windows
  connect scrubs.
- Stabilize the macOS CI job: widen a transport-delay fixture deadline that
  flaked on slow shared runners, and run the macOS test legs single-threaded so
  concurrent ptrace lifecycle fixtures cannot race on `wait()` and hang the job.

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
- Enable public macOS Arm64 session construction. `session::backend_status()`
  now reports `Available` on every supported target, and `Session::spawn` /
  `Session::from_bootstrap` compose the audit-token/nonce-authenticated
  direct-spawn path with exact own-child termination and reaping. The same
  cross-platform public session conformance corpus runs green on macOS. The
  hardened ptrace/sandbox launcher remains backend-private machinery for
  deployer-built helper artifacts; no installed, signed, notarized, or
  packaged-release evidence is claimed, and descendant cleanup stays
  `FreshGroupUnverified`.

### Known limitations

- The post-enable cross-platform parity review recorded a set of Windows/Linux
  public-API diagnostic divergences (failure-state shapes, poison timing,
  spawn-error tuples, and one fabricated Windows `Exited(127)` cleanup fact
  reported without querying the real exit code). These do not affect memory
  safety or protocol security and are tracked for a dedicated cross-platform
  parity pass. The library remains experimental per the vNext specification
  §16; public API shapes may still change between 0.x releases.

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

[Unreleased]: https://github.com/ro-ag/native-ipc-rs/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/ro-ag/native-ipc-rs/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/ro-ag/native-ipc-rs/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/ro-ag/native-ipc-rs/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/ro-ag/native-ipc-rs/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/ro-ag/native-ipc-rs/releases/tag/v0.1.0
