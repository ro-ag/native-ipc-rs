# Full repository review — 2026-07-15

> Point-in-time review evidence from 2026-07-15, before the macOS public
> enablement decision (2026-07-16). Statements below about macOS being
> `BackendUnavailable` describe the reviewed head, not the current state;
> [`macos-supervisor-boundary.md`](../macos-supervisor-boundary.md) is the
> current authority.

Scope: task 55 on Plan 8b. Reviewed the public vNext surface, Linux, macOS, and
Windows backends, integration/threat-model documentation, traceability, and the
macOS fixed broker/launcher spawn, entry, and FD4 delivery path through branch
head `c5c908b`.

This is source-review evidence, not release evidence. Public macOS session
construction remains `BackendUnavailable`.

## Outcome

No unresolved critical or high source finding was identified in the reviewed
change. Two macOS implementation gaps were fixed:

1. Shared Darwin spawn attributes now include `POSIX_SPAWN_SETSID`; a native
   regression proves each supervisor child is both session and process-group
   leader, then exact-reaps it to `ECHILD`.
2. The fixed launcher now marks FD3 and FD4 `FD_CLOEXEC` before irreversible
   containment. Explicit close remains defense in depth, so an unusual close
   failure cannot leak the death or plan descriptor through target exec.

The review does **not** claim race-resistant Unix process-group termination.
The code retains exact direct-child authority and never reconstructs it from a
numeric PID after `ECHILD`. Ordinary-descendant group cleanup remains deferred:
the specification §9 requirement conflicts with the repository's already
measured PGID-reuse/broad-waiter threat model unless a stronger retained
containment primitive or normative amendment is selected. Public macOS is
fail-closed, and Linux documents the same limitation.

## Independent review disposition

Three independent read-only passes examined the branch:

- **Architecture:** found integration and macOS-boundary prose that conflated
  bulk shared memory with the bootstrap/control channel, application signing
  policy with library guarantees, portable type shape with runtime backend
  availability, and an obsolete privileged/root macOS proposal with the
  selected same-user design. The integration model, README files, architecture,
  protocol-decision, feasibility, threat-model, and supervisor-boundary docs
  now state the current boundary and mark older exploration as non-normative.
- **Darwin ABI/lifecycle:** found the missing fresh-session spawn flag. The
  shared `posix_spawn` attributes and native exact-child test now cover it.
- **Adversarial entry/FD review:** found that FD3/FD4 close results were ignored
  after containment. Both descriptors are now made close-on-exec before that
  point, with a regression test for the fail-closed flag.

## Integration-model audit

The end-to-end model is internally consistent after correction:

- the Host and Child Runner are application-owned executables in separate
  processes;
- untrusted plug-in/model/library code runs inside the disposable Child Runner,
  rather than being supplied as an arbitrary executable;
- shared memory is the bulk-data path, while one bounded authenticated channel
  carries bootstrap, negotiation, capability, control, and lifecycle records;
- the application owns signing, packaging, notarization, and optional
  filesystem/network/service policy;
- Linux uses per-record `SCM_CREDENTIALS` bound to clone-time exact-child
  identity, not cached `SO_PEERCRED` as post-exec proof;
- Windows owns the suspended exact image and non-breakaway kill-on-close Job;
- the private macOS source is same-user and unprivileged, uses fixed
  deployer-compiled helper paths, cooperative tracing, inherited SBPL and
  `RLIMIT_NPROC`, and exact direct-child reap; and
- no root, `sudo`, set-ID transition, root-owned helper path, task-port wire
  authority, or request-selected arbitrary-exec/signal deputy is part of the
  selected macOS model.

A separate malicious same-user process that already exists outside the
Host/Runner relationship remains outside this integration contract. The docs
do not translate that exclusion into a claim of host secrecy or general
filesystem/network sandboxing.

## Security and claim corrections

- The opt-in Developer ID matrix proves designated-requirement acceptance and
  rejection cases, but post-signing mutation detection is page-demanded. A
  mutation of a mapped executable page was killed before authorization; a
  mutation in an unfaulted debug/`__LINKEDIT` page could still run and validate.
  Documentation now states this limit and leaves installed-file replacement and
  mutation resistance to deployment policy.
- The standalone C proof uses the narrower `(deny signal)` profile. Launchd
  lookup/registration denial belongs to the separate Rust launcher profile and
  is no longer attributed to that C proof.
- The public memory/transport vocabulary and base-manifest independence now
  have checked-in regression tests and corresponding R3.1/R3.2 traceability.
- Dead-code and test-seam inventory counts were refreshed to 63 explicit
  `dead_code` allowances and 573 syntactic `cfg(test)` occurrences.
- Merged Linux and Windows checkpoints are no longer described as draft or
  uncommitted working-tree state.

## Specification §12 disposition

| Section | Current disposition | Deferred work / reason |
| --- | --- | --- |
| 12.1 Type/API and portable core | Partially satisfied by compile-fail docs, portable property/unit corpus, warning-free docs gates, and source tests including R3.1/R3.2. | Exact-release Miri/property/fuzz and complete enumerated compile-fail evidence remain release-gated. |
| 12.2 Batch/replay corpus | Broad 1/2/4/16, rejected limits, mixed direction, substitution, replay, truncation, mutation, Nth-failure, and no-partial-activation corpora exist across the portable reducer and native backends. | A checked exact-release trace proving every enumerated mutation on all applicable native targets remains outstanding. Public macOS cannot supply session evidence while fail-closed. |
| 12.3 Negotiation/control | Public Linux and Windows plus private macOS corpora cover challenged decisions, limits, opaque bounded control, ordering, malformed input, deadlines, EOF, and transaction exclusion. | Exact-release all-target rerun and public macOS composition remain deferred. |
| 12.4 Authentication/timing | Linux per-record credentials/pidfd, Windows pipe PID/Job, and private macOS audit-token/trace/deadline paths have hostile and lifecycle coverage. | Installed macOS artifacts, public macOS sessions, complete parent-drop/state matrix, physical release targets, and the unresolved §9 ordinary-descendant requirement remain deferred. |
| 12.5 Native permission/framing | Linux, private macOS, and Windows native suites cover direction/access, object substitution, framing, rights/handles, and cleanup baselines in substantial depth. | Five exact-release native targets, complete per-direction enumerated proof, and public macOS evidence remain outstanding. |
| 12.6 Failure injection/leaks | Nth-operation seams and exact/incomplete cleanup ledgers exist across backends; cleanup failures avoid ambiguous retry. | Required 10,000-cycle scheduled stress and complete exact-release resource baselines are not established. |
| 12.7 Real-time negatives | Runtime APIs are structured for checked, allocation-free access. | Allocator/syscall/lock instrumentation, prefault evidence, and named-machine bounds remain unverified. |
| 12.8 Release jobs | Source-tree local gates are run for this task. Historical native and package checkpoints remain recorded. | No exact release commit exists; five-target native, packaged, Miri, fuzz, hostile, and repeated leak-stress release jobs remain unverified. |

## Specification §16 disposition

vNext is not done. Items 1–2 have public Linux/Windows composition and portable
application-neutral coverage, but public macOS remains deliberately unavailable.
Items 3–6 and 10 require exact-release native, baseline/stress, RT, and packaged
evidence that does not yet exist. Item 7 is improved by this claim audit. Item 8
cannot be evaluated for a nonexistent exact release commit. Item 9 is satisfied
for this review only by fixing the medium source findings and explicitly
retaining the §9/descendant and release-evidence deferrals.

The repository must continue to describe vNext as experimental foundation work,
not a complete secure isolation transport.
