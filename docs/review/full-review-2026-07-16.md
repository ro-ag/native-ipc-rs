# Full pre-release adversarial review — 2026-07-16

Review target: `71201704a19c32f08bc2271ac79c58e826ea901c`

This is point-in-time source-review evidence for the current `main` head. It is
not release evidence for a future release-candidate commit. The review covered
all of `native-ipc-core`, the portable facade, the enabled macOS path, the
invariant-bearing Linux and Windows paths, the normative specification
sections 3–12, every traceability row, public documentation, and the production
unsafe-site inventory.

## Outcome

**Release verdict: blocked.** The exact target commit has a green ten-job hosted
CI run, and the complete local macOS gate passes, but three P1 contract gaps
remain:

1. the safe core payload copy uses an ordinary Rust memory copy for bytes that
   its contract permits another process to change concurrently;
2. the public macOS launch checks a pathname before and after launch but does
   not prove that the already-opened file is the file that was started; and
3. the normative section 9 ordinary-descendant cleanup requirement is not
   implemented on either Unix backend and is explicitly reported as
   unverified.

The first item has a small source fix. The other two require an architectural
decision: provide the stronger native mechanism, fail the affected public
construction closed, or deliberately revise the normative contract. A passing
test matrix cannot substitute for that decision.

## Findings

### P1 — safe core payload copy does not use the defined external-memory boundary

Locations:

- `crates/native-ipc-core/src/mapping.rs:141-165`
- `docs/native-ipc-vnext-spec.md:319-329`
- `crates/native-ipc/src/active.rs:199-214`
- `crates/native-ipc/src/external_memory.c:9-17`

`ReaderRegion::copy_payload` documents that a peer may change the payload while
the copy is in progress, but it calls `core::ptr::copy_nonoverlapping`. That is
an ordinary Rust copy. The normative contract requires volatile byte access or
an audited external-language boundary for this exact situation, and the public
active API already uses such a boundary.

Concrete failure: a safe caller reads a published slot while the peer changes
payload bytes without changing the metadata. The API says the result may be
torn but memory-safe; the implementation instead performs ordinary reads that
do not establish the documented external-memory behavior. Current Miri tests
do not model a second process changing the mapping, so their success does not
exercise this case.

Required resolution: replace the ordinary copy with the crate's documented
volatile-byte boundary and retain the metadata recheck. Add a regression that
keeps this adapter from returning to an ordinary bulk copy.

### P1 — public macOS launch does not bind the opened file to the started image

Locations:

- `crates/native-ipc/src/backend/macos_vnext/session.rs:155-197`
- `crates/native-ipc/src/backend/macos_vnext/session.rs:258-300`
- `crates/native-ipc/src/backend/macos_vnext/session.rs:488-561`
- `crates/native-ipc/src/session.rs:611-621`
- `docs/native-ipc-vnext-spec.md:381-392`
- `docs/architecture.md:471-476`

`HeldExecutable` opens and retains the configured file, but `posix_spawn` is
given the pathname. The later checks ask macOS for a process pathname, reopen
that pathname, and compare file metadata. The public API documentation and
architecture document correctly admit that this is neither file-descriptor
execution nor replacement denial.

Concrete failure: a normal installer or updater changes the configured file
between the initial open and the pathname-based spawn, then restores or moves
files again before a recheck. The code can compare the retained file with the
current pathname, but it has no proof that the process was created from that
retained file. This conflicts with the section 6.1 stable-image requirement and
with broader documentation that says the library binds every launch to the
configured exact executable identity.

Required resolution: use a mechanism that authenticates the actual running
image against the retained identity, or keep public macOS construction
unavailable. Do not describe the existing pathname comparison as exact opened-
file execution.

### P1 — section 9 ordinary-descendant cleanup is intentionally absent on Unix

Locations:

- `docs/native-ipc-vnext-spec.md:839-846`
- `crates/native-ipc/src/backend/linux_vnext/process.rs:287-295`
- `crates/native-ipc/src/backend/linux_vnext/process.rs:471-475`
- `crates/native-ipc/src/backend/macos/bootstrap.rs:1005-1030`
- `docs/vnext-traceability.md:131`
- `docs/vnext-feasibility.md:1147-1151`

The specification requires bounded process-group termination for ordinary
Linux/macOS descendants. Both implementations deliberately retain only exact
direct-child authority and report `FreshGroupUnverified`. The feasibility and
traceability documents already explain why a numeric process-group operation
is not considered safe under the project's broad-waiter model.

Concrete failure: the application-owned runner starts an ordinary child and
the session is then aborted. The direct runner is terminated and reaped, while
the ordinary child can remain. This is not merely missing evidence; it is a
known difference between normative behavior and implementation.

Required resolution: select a stronger retained containment mechanism, or make
an explicit normative change with corresponding public documentation. Adding a
numeric process-group operation without resolving the recorded identity race
would not be an acceptable fix.

### P2 — Windows command strings can be silently shortened at an embedded NUL

Locations:

- `crates/native-ipc/src/session.rs:624-667`
- `crates/native-ipc/src/backend/windows.rs:1340-1370`
- `crates/native-ipc/src/backend/windows.rs:1387-1396`
- `crates/native-ipc/src/backend/windows_vnext/session.rs:145-167`

The public command API calls its executable and arguments exact. The Unix
backends reject interior NUL bytes while creating C strings. The Windows path
encodes `OsStr` values directly into NUL-terminated UTF-16 without first
rejecting an interior zero unit.

Concrete failure: a Windows caller constructs an `OsString` containing a zero
UTF-16 unit. The operating-system call observes only the prefix, so the child
receives a different executable path or argument list than the caller supplied.

Recommended fix before the RC: validate the executable and every argument in
the Windows public layer before any native acquisition, return `InvalidInput`,
and add a Windows-native regression.

### P2 — Windows pre-spawn failures are reported as if a child was created

Locations:

- `crates/native-ipc/src/backend/windows_vnext/session.rs:162-172`
- `crates/native-ipc/src/backend/windows.rs:664-731`
- `crates/native-ipc/src/backend/windows.rs:1399-1443`

Every error returned by `ChildSession::spawn_until` is converted to the
`Spawned` failure state with poison and incomplete cleanup. That function can
fail while opening the executable, creating the pipe or Job, validating the
explicit environment, or preparing the command line, all before
`CreateProcessW` succeeds.

Concrete failure: a caller supplies a missing executable or an invalid Windows
environment key. No child exists, but diagnostics say the transaction reached
`Spawned`, mark it poisoned, and attach incomplete child cleanup facts. This
breaks the bounded failure-state semantics that callers use to decide whether
an external effect occurred.

Recommended fix before the RC: return a staged Windows spawn error that records
whether process creation succeeded, and map only post-creation failures to
`Spawned`.

### P2 — native tests contain wall-clock correctness assertions

Representative locations:

- `crates/native-ipc/src/backend/macos_vnext/transport_test.rs:217-231`
- `crates/native-ipc/src/backend/macos/bootstrap_test.rs:1328-1339`
- `crates/native-ipc/src/backend/macos_vnext/session_test.rs:160-173`
- `crates/native-ipc/src/backend/linux_vnext_test.rs:645-652`
- `crates/native-ipc/src/backend/linux_vnext/process_test.rs:1633-1647`
- `crates/native-ipc/src/backend/linux_vnext/spawn_test.rs:3842-3878`

The inventory found 31 assertions that compare `Instant::now()` or elapsed
time with a threshold. Some are bounded polling guards, but several use host
speed as the correctness oracle. Issue 14 already records a sibling macOS
shared-runner failure, and issue 13 records the equivalent Linux sanitizer
class.

Concrete failure: a correct test fails on a slow or oversubscribed runner, or a
broken implementation passes because the threshold is generous. The clearest
examples assert that drop completed within 25 ms or that a protocol exchange
took at least 90 ms.

Recommended fix before the RC: retain deadlines only as harness escape bounds;
assert deterministic events, state transitions, or injected-hook observations
instead of elapsed duration. The RT suite already follows the right model by
printing latency as evidence without asserting it.

### P2 — traceability names an old commit as the current conformance head

Locations:

- `docs/vnext-traceability.md:38`
- `docs/vnext-traceability.md:68`
- `docs/vnext-traceability.md:151-166`

The ledger still calls `220479d` the current conformance head and describes the
RT instrumentation as incomplete. The reviewed head is
`71201704a19c32f08bc2271ac79c58e826ea901c`; its ten-job CI run
[`29552943953`](https://github.com/ro-ag/native-ipc-rs/actions/runs/29552943953)
is green, and the RT suite is present. Historical rows may keep historical
SHAs, but the current-head and current-status statements must not.

Concrete failure: a release reviewer following only the ledger reaches the
wrong conclusion about which source was exercised and which requirements
remain unimplemented.

Recommended fix before the RC: update only current-status cells and the current
evidence summary; preserve historical checkpoint records.

### P3 — `TransferBatch::add` destroys the supplied prepared region on local error

Location: `crates/native-ipc/src/batch.rs:162-193`

The method consumes `PreparedRegion` but returns only `BatchError`. A duplicate
ID, count limit, or byte-limit mistake therefore drops an already-prepared
native object and gives the caller no way to correct the batch.

Concrete user cost: preparing a large set and accidentally adding one duplicate
requires rebuilding that region instead of recovering it from the local
validation error.

Pre-1.0 recommendation: return the region with the error, for example
`Result<(), (BatchError, PreparedRegion)>`, or offer a consuming builder that
returns both owners on failure. Migration cost is small but source-breaking.
Per the review brief, this proposal is report-only.

## Follow-up correction status

After the report was written, the straightforward findings were corrected on
the review branch:

- the core payload adapter now performs volatile byte reads and retains its
  metadata recheck;
- Windows validates command and environment strings before launch and now
  distinguishes failures before process creation from failures after it;
- native timing tests assert protocol results, cleanup facts, or observed
  background reaping instead of elapsed host speed; deadlines remain only as
  bounded test escape paths; and
- current traceability rows now cite the reviewed commit and CI run while
  preserving historical checkpoint rows.

The full local gate, Miri, and Linux/Windows cross-target compilation pass with
those corrections. The macOS opened-file launch guarantee and the Unix
ordinary-descendant cleanup guarantee remained unresolved P1 blockers at the
time of this review. The P3 batch API proposal remains report-only.

Resolution follow-up (2026-07-17): both remaining P1 findings were resolved by
stronger retained mechanisms with no normative specification change. The macOS
launch now binds the started image to the retained descriptor by comparing the
kernel's audit-token-bound code-directory hash against hashes computed from
the held file, and both Unix backends perform bounded ordinary-descendant
group termination under the unreaped direct child's kernel-witnessed identity
pin. Decisions, evidence, and rows `p1-16`/`p1-17` are recorded in
[`../vnext-traceability.md`](../vnext-traceability.md).

## Six-pass disposition

### 1. Logic and correctness

Checked arithmetic, manifest canonicalization, transaction poisoning, active
lease accounting, mapping-before-lease destruction, direct-child wait owners,
and native capability cleanup were reviewed against their failure paths. No
additional P1/P2 arithmetic, replay, partial-activation, or double-owner defect
was confirmed. The Windows failure-stage issue above is the remaining concrete
diagnostic error.

### 2. Semantics versus specification

Sections 3–8 and 10–11 have implementation and test coverage for the portable
API, finite limits, one-writer authority, no library-created executable view,
typestates, challenged negotiation, bounded control, full-manifest atomic
batches, checked active access, and RT negative instrumentation. The three P1s
above are direct section 5.4, 6.1, and 9 differences. Section 12 remains a
release matrix rather than a satisfied source property.

No traceability row was accepted solely because it said “green” or “verified.”
Historical run references were treated as historical. The current-head ledger
error is listed above; remaining rows generally underclaim incomplete release
evidence rather than claiming evidence that does not exist.

### 3. Unsafe and FFI safety

The production unsafe inventory was grouped by ownership conversion, mapped-
memory access, native ABI call, dynamic symbol, and Send/Sync proof, then checked
at call sites. The C external-memory signatures match their Rust declarations;
the active API uses volatile-qualified byte loops; native handles are moved into
single owners after successful acquisition; and the reviewed Send/Sync proofs
match the exposed mutation model. The core ordinary copy is the one confirmed
unsafe-boundary defect.

Miri passes all 16 portable-core tests, but it cannot represent concurrent
mutation from another process and therefore does not clear that defect.

### 4. Documentation

Rustdoc builds with warnings denied. The documents are unusually candid about
the macOS pathname limitation and Unix descendant limitation, but broader
“exact executable identity” language conflicts with the macOS admission, and
the normative section 9 requirement conflicts with both feasibility and code.
Those claim problems are covered by the P1s. The traceability current-head
entry is stale as described above.

### 5. Ergonomics

The public typestate flow prevents pre-ACCEPT transfer, partial activation, and
silent close with active leases. Error records are bounded and expose useful
operation/state/cleanup facts. The two pre-1.0 changes worth considering are
recoverable `TransferBatch::add` errors and staged Windows spawn diagnostics.
At the reviewed target commit neither was implemented; the follow-up branch now
stages Windows spawn failures accurately, while the batch API proposal remains
report-only.

### 6. Rust idiom and test quality

Strict Clippy and rustfmt are green. Target-gated modules type-check for all four
non-host Rust targets through Zig-assisted C compilation, and the hosted matrix
runs them natively. No silently uncompiled production target branch was found.
The main test-quality defect is wall-clock assertion use. Test-only ignored
helpers are explicitly named and invoked by exact parent tests; no swallowed
helper failure was confirmed in the reviewed paths.

## Specification §12 disposition

| Section | Review disposition at `71201704a19c32f08bc2271ac79c58e826ea901c` |
| --- | --- |
| 12.1 Type/API and core | Broad compile-fail/unit/property coverage and exact-head Miri are green; the external-memory scenario is not modeled and has a P1 source defect. |
| 12.2 Batch/replay | Broad portable and native 1/2/4/16, rejection, mutation, replay, and no-partial-activation coverage is green. Exact release-candidate evidence does not yet exist. |
| 12.3 Negotiation/control | Challenged decisions, limits, ordering, malformed input, deadlines, and bounded opaque control are covered across native jobs. |
| 12.4 Authentication/timing | Exact child/channel tests are broad. macOS exact opened-file identity and Unix ordinary-descendant cleanup remain P1 gaps; timing tests also contain P2 wall-clock oracles. |
| 12.5 Native permission/framing | The five native target jobs are green on the reviewed SHA. This is source-head evidence, not final packaged release evidence. |
| 12.6 Failure injection/leaks | Nth-failure and repeated native cleanup tests exist, including 10,000-cycle macOS memory-owner stress. The complete scheduled exact-release stress matrix remains unverified. |
| 12.7 Real-time negatives | The macOS public active path has allocator/task-event instrumentation and non-asserted latency evidence. Cross-target exact-release RT evidence remains incomplete. |
| 12.8 Release jobs | Ten hosted source jobs are green on the reviewed SHA, and this independent review exists. P1 findings are unresolved; extracted-package, named physical-host, scheduled stress, and exact future RC evidence are not complete. |

## Specification §16 release readiness

vNext is not ready for an RC cut. The exact reviewed source has strong native
CI evidence, but §16 cannot be satisfied while safe shared-memory copying,
macOS image identity, and the section 9 normative cleanup contract diverge from
the implementation. The current public API must continue to be described as
experimental. No release, tag, or publish action is authorized by this review.

## Validation evidence

Local macOS Arm64 results:

- `cargo fmt --all -- --check` — pass
- `cargo clippy --workspace --all-features --all-targets --locked -- -D warnings` — pass
- `cargo test --workspace --all-features --all-targets --locked -- --test-threads=1` — pass
- `cargo test --workspace --no-default-features --all-targets --locked -- --test-threads=1` — pass
- `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked` — pass
- `cargo deny check` — pass
- `git diff --check` — pass
- nightly Miri, `native-ipc-core --lib` — 16 passed
- Zig-assisted all-feature `cargo check --all-targets` for Linux AMD64/Arm64
  and Windows AMD64/Arm64 — pass

Hosted exact-head evidence:

- [CI run 29552943953](https://github.com/ro-ag/native-ipc-rs/actions/runs/29552943953)
  — all ten jobs passed for
  `71201704a19c32f08bc2271ac79c58e826ea901c`, including native Linux
  AMD64/Arm64, macOS Arm64, Windows AMD64/Arm64, quality, ASan, cargo-deny,
  Miri, and fuzz smoke.
