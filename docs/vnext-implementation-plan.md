# vNext dependency-ordered implementation plan

Every phase begins with failing tests (or adds them in the same reviewable
change when a compile-fail fixture cannot compile independently), runs
proportional validation, receives an independent adversarial diff review, fixes
all findings before the next invariant, and updates
[`vnext-traceability.md`](vnext-traceability.md). Commits stay small and never
include unrelated working-tree files.

## Phase 0 — prove native feasibility and resolve claims

Invariant: every native mechanism has an implementable least-authority state
machine, and impossible revocation/containment claims are explicitly excluded.

Deliverables: [`vnext-feasibility.md`](vnext-feasibility.md), primary-source
evidence, focused native probes for NX memfds/seal order/credentials/Mach
maximum rights/Windows duplicate teardown, and target evidence placeholders.
Validation: document link checks plus native probes where runners exist.

## Phase 1 — final crate graph and private backend facade

Invariant: the publishable graph is acyclic (`native-ipc -> native-ipc-core`;
testkit -> both), the generic native manifest is independent of core layout
semantics, and no public platform orchestration crate/API remains in vNext.

Tests: Cargo metadata/packaging graph, public API checks, forbidden vocabulary,
unsupported-target compile-fail. Validation: fmt, check, Clippy, docs, package
dry-runs on the host.

## Phase 2 — consuming platform-neutral region typestates

Invariant: private, prepared, pending, reader, and writer ownership/Send/Sync
properties are enforced by types; ordinary safe `into_platform_parts` is gone.

Tests: trybuild compile-fail suite, boundary property tests, allocation/padding/
guard policy native tests. Validation: portable tests, Miri, host native suite.

## Phase 3 — transaction-owned arbitrary batch

Invariant: one `TransferBatch` owns 1..=16 mixed-direction prepared regions and
returns a keyed `ActiveRegionSet` only as a complete committed set.

Tests: 0/1/2/4/16/17 counts, all direction mixes, duplicate/zero IDs, failure at
first/middle/final entry, cross-session/transaction provenance compile/runtime
tests. Validation: unit/property/Miri plus host integration.

## Phase 4 — exact-child session, negotiation, control, and deadlines

Invariant: an authenticated exact child completes HELLO/ACCEPT before batches;
opaque duplex control and every setup operation obey one absolute deadline;
atomic/alignment capabilities and finite effective limits are transcript-bound.

Tests: identity replacement/wrong process, negotiation downgrade/overflow,
application accept/reject, control short-I/O/conflict, hostile traffic through
deadline, exit at every state, lease-aware close/abort/reconnect. Validation:
portable corpus and host process integration.

## Phase 5 — Linux GNU AMD64/Arm64 backend

Invariant: Linux 6.3+ uses NX memfds, exact peer-writer seal preparation,
credentialed `SOCK_SEQPACKET` ancillary framing, pidfds, and contained owned
child cleanup with no fd leaks.

Tests: every seal/preparation state, 0/1/2/N `SCM_RIGHTS`, every truncation and
ancillary mutation, exact credentials, resize/write/execute denial, hostile
deadline and Nth-operation faults. Validation: native AMD64 and Arm64 only;
cross-build results stay unverified.

## Phase 6 — macOS Arm64 backend

Invariant: exact-length Mach entries carry only complementary non-executable
rights, bootstrap validates full audit trailers/exact child identity, and every
port/right/mapping/child is ledgered exactly once behind a replaceable private
control trait.

Tests: every header/descriptor/trailer mutation, extra installed rights, audit
PID, maximum-protection upgrade rejection, process lifecycle and Nth faults.
Validation: native macOS Arm64; Intel macOS compile-fail.

## Phase 7 — Windows AMD64/Arm64 backend

Invariant: unnamed sections, exact access duplication, suspended pre-Job spawn,
private one-instance pipe authentication, remote duplicate ledger, cancellation,
and Job teardown implement the common batch/session contract.

Tests: exact rights/object/size/ordinal, partial/`ERROR_MORE_DATA`/cancelled pipe,
wrong endpoint PID, resume-state duplicate failures, Job tree teardown, Nth
faults and handle baseline. Validation: native AMD64 and Arm64 only.

## Phase 8 — poisoning, cleanup ledgers, and failure injection

Invariant: every acquisition immediately registers an inverse; ambiguous state
poisons; cleanup continues after errors and reports bounded exact incomplete
facts without unsafe retry.

Tests: fail every Nth forward and cleanup call on every backend success path,
panic/drop permutations, concurrent sessions, simulated terminal-close errors.
Validation: portable model plus all available native targets.

## Phase 9 — complete conformance, leak, and real-time gates

Invariant: permission, framing, replay, timing, compile-fail, leak-cycle, and
real-time negative guarantees have positive and negative evidence.

Tests: complete spec corpus, allocator/syscall/lock instrumentation, prefault,
peer-death nonblocking access, 10,000-cycle scheduled stress, fuzz/property
smoke, Miri, ASan. Validation: all five native target jobs; unavailable runners
block release.

## Phase 10 — migration, packaging, and exact-release gates

Invariant: docs/examples expose only the platform-neutral vNext contract,
migration covers 1/2/4/16-region flows, packaged crates reproduce all relevant
tests, and the exact release commit has green native evidence and final review.

Validation: Rust 1.97 and current stable; fmt; strict Clippy; all-feature,
all-target, no-default, warning-free rustdoc; Miri; fuzz/property; hostile/fault/
leak/RT suites; extracted packaged-crate native retests; benchmark artifacts;
independent exact-SHA adversarial review. Publishing/tagging remains a separate
explicit action and is forbidden while traceability has any unverified row.
