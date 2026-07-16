# macOS exact-lifecycle supervisor boundary

Status: backend-private same-user launcher lifecycle implemented and natively
tested; public macOS session construction remains `BackendUnavailable` pending
the explicit Plan 8b enable-or-defer decision and installed-artifact evidence.
The common `session::backend_status()` query therefore reports
`BackendStatus::Unavailable` on macOS Arm64.

This document is subordinate to
[`integration-model.md`](integration-model.md) and the normative
[`native-ipc-vnext-spec.md`](native-ipc-vnext-spec.md). It describes the current
unprivileged design. Earlier root-owned, credential-dropping, independently
privileged service proposals were rejected and are not part of the product
model.

## Scope and trust boundary

The supported integration has two application-owned executables:

1. a trusted Host; and
2. a small disposable Child Runner that the application builds and deploys.

Untrusted plug-in, model, or library code runs in-process inside the Child
Runner. `native-ipc` is not an arbitrary-program sandbox. A separate malicious
same-user process that already exists outside this host/runner relationship is a
different authority principal and is outside the integration contract.

The macOS lifecycle is same-user and unprivileged throughout:

- no root, `sudo`, set-ID transition, or root-owned installation path;
- no task-control port transfer or retention;
- no caller-selected broker, launcher, or authentication-worker path;
- no numeric PID as wire authority after exact child ownership is lost; and
- no public enablement inferred from backend-private source evidence.

Applications own signing, packaging, notarization, filesystem/network sandbox,
and capability-profile policy. The library owns the exact child lifecycle,
bounded authenticated framing, native rights, deadlines, and cleanup facts.

## Process topology

```text
Host (same user)
  └─ fixed Broker (our code, exact direct child of its launcher/owner)
       └─ fixed trusted Launcher (our code, exact unreaped tracee)
            └─ exec -> signed Child Runner (our code)
                         └─ loads untrusted library in-process
```

The launcher exists because the final runner cannot establish `PT_TRACE_ME`
before its own first instruction. The fixed launcher authenticates the intended
broker, establishes the trace relationship, applies inherited containment, and
then becomes the runner through `execve`. The broker consumes the exec trap
before the runner's first instruction.

## Implemented source boundary

The backend-private implementation now composes the following source path:

1. Deployer-compiled absolute paths select the broker, launcher, and clean-exec
   authentication worker. Request bytes cannot select or change those paths.
2. One shared Darwin `posix_spawn` primitive layer owns fresh-session creation,
   canonical signal defaults, the empty signal mask,
   `POSIX_SPAWN_CLOEXEC_DEFAULT`, descriptor actions, special-port setup, raw
   `c_int` error propagation, and the no-stranded-child destructor rule. Each
   supervisor child starts as its own session and process-group leader rather
   than inheriting the embedding application's job-control group.
3. One permanent main-thread, never-threaded child-wait domain creates the
   non-atomic Darwin pipes and immediately converts every successful spawn into
   exact direct-child authority. It rejects incompatible `SIGCHLD`, broad-waiter,
   and already-threaded initialization states.
4. The fixed broker process pre-creates its clean-exec authentication worker,
   spawns the launcher, proves the initial stop, delivers the canonical plan,
   waits for the exec trap, verifies the exact target identity, reports the held
   trace state, resumes only after Ready commits, and reaps the target exactly.
5. While failure is still reportable, the launcher marks FD3 and FD4
   close-on-exec. It then installs the inherited SBPL profile and hard
   `RLIMIT_NPROC=1`, closes those staging descriptors as defense in depth, and
   immediately calls `execve`. A rare explicit-close failure therefore cannot
   leak either descriptor into the target.
6. Public `Session::spawn` and `Session::from_bootstrap` on macOS still return
   `BackendUnavailable`; none of these private owners can be reached through the
   ordinary safe session API.

Security.framework and CoreFoundation are never statically linked into the
shared library/test image. The fixed authentication worker loads both frameworks
with `dlopen` inside its clean-exec process, applies its deployer-compiled
designated requirement to the exact audit token, writes one bounded result, and
must exit successfully and be reaped before verified identity exists.

## Fixed descriptor protocol

The broker/launcher path uses three fixed channels with no native authority in
their byte values:

- **FD 3 — death/start gate.** The broker observes service/owner death through
  EOF and accepts exactly one activation byte at the staged boundary. The
  launcher inherits only the death-reader shape and probes it at every
  effect-bearing transition.
- **FD 4 — canonical plan and digest acknowledgement.** The broker receives one
  bounded plan under the original absolute deadline, requires exact EOF, and
  acknowledges the complete domain-separated digest. The launcher reads its
  exact execution plan only after the initial stop is proven.
- **FD 5 — trace report and Ready-bound resume.** The held exec-trap owner alone
  can emit one exact report plus EOF. Successful Ready delivery commits one
  resume byte plus EOF; failure emits no resume and exact-cleans first.

The production spawn fixture enters through the actual launcher file actions and
attributes. It verifies exact argv/environment, `/dev/null` descriptors 0–2,
read-only anonymous FIFO readers only at FD 3 and FD 4, exclusion of an
intentionally inheritable sentinel, and exact initial-stop cleanup through
`ECHILD`.

## Exact lifecycle argument

The proof depends on exact unreaped-direct-child ownership, not on the numeric
PID alone:

- `PT_TRACE_ME` followed by `SIGSTOP` establishes a proof stop that only the
  exact parent/tracer may consume.
- Successful `PT_CONTINUE` upgrades the initial stop to proven traced authority.
- `exec` changes the audit PID version but preserves the trace relationship; the
  broker requires that version change, matching real/effective credentials, the
  expected installed path, and the clean-exec signature result before reporting.
- While the direct child is live or an unreaped zombie, its PID cannot be reused.
  Running termination first stops it, then uses parent-only `PT_KILL`, and reaps
  to `ECHILD`.
- Darwin may report a traced terminal status twice when tracer and parent are the
  same process. `drain_exact_child` therefore continues until `ECHILD`; the first
  terminal status alone is not ownership release.
- `ECHILD` before the expected exact reap is authority loss. Cleanup aborts and
  never falls back to a numeric signal.
- Tracer exit makes XNU kill the exact tracee, covering broker crash for the
  direct runner relationship.

After Ready, natural exit or signal death is also drained to `ECHILD`. A later
unexpected trace stop, gate failure, or owner death exact-cleans before returning
a PID-free terminal outcome.

## Inherited containment and its limit

Before target exec the launcher installs this load-bearing policy:

```text
(version 1)
(allow default)
(deny signal)
(deny mach-lookup)
(deny mach-register)
```

Together with hard `RLIMIT_NPROC=1`, native tests show that the runner cannot:

- create a direct child with `fork` or `posix_spawn`;
- signal the broker or another process while retaining self-signalling;
- look up or register launchd Mach services before or after exec; or
- relax the inherited profile with a second `sandbox_init`.

This is empirical mechanism evidence, not a supported Apple API contract:
`sandbox_init` is deprecated and SBPL is undocumented. The profile constrains
the exact runner process, not every process already running as the same user. A
separate malicious same-user sibling can still attack a same-user broker, but
that sibling is outside the signed-runner integration model. Any future deployer
service allowlist replaces blanket denial with explicit delegated authority that
must be documented and tested.

Fresh session/process-group creation isolates supervisor children from the
embedding application's inherited job-control signals. It is not a retained,
race-resistant process-group handle. Cleanup therefore claims the exact direct
child only; ordinary descendants remain unverified. The launcher profile and
hard process limit are the measured no-delegation/no-fork boundary for the
runner, not a generic process-group cleanup promise.

## Signature evidence and mutation caveat

The opt-in Developer ID matrix runs only when
`NATIVE_IPC_TEST_SIGN_IDENTITY` names a Developer ID Application identity. It
proves that the exact designated requirement accepts the intended hardened
runtime image and rejects same-signer/wrong-identifier and ad-hoc images.

Post-signing mutation has a measured limit. Mutating a mapped executable page,
including the `LC_MAIN` entry instruction, causes the kernel to kill the image
before authorization. Mutating an unfaulted debug/`__LINKEDIT` page did not stop
the image and still allowed `SecCodeCheckValidity` to succeed. Documentation
therefore must not claim that every post-signing file mutation is detected
before authorization; the installed artifact must also be protected against
replacement and mutation by deployment policy.

## What is not established

Current source/native tests do not prove:

- separately installed minimal broker, launcher, or authentication-worker
  artifacts;
- code signing, bundle placement, hardened runtime, notarization, or
  replacement resistance for deployer-supplied helper paths;
- a complete filesystem/network/service capability allowlist;
- constructor/dyld behavior of the eventual minimal signed helpers;
- public `Session<Negotiating>`/`Session<Ready>` composition on macOS;
- 10,000-cycle installed lifecycle/port baselines; or
- exact-release packaged and physical-host conformance.

Source work alone is not installed, signed, packaged, public-enable, or release
evidence.

## Required evidence before public enablement

If the user selects the Plan 8b enable option, the implementation must still
provide and verify:

- separately built minimal broker, launcher, and clean-exec worker artifacts at
  deployer-supplied absolute paths;
- positive and negative signing/identity cases, including the mapped-page
  mutation caveat above;
- packaged hardened-runtime execution through the real Host integration;
- immutable inherited SBPL/capability policy before target exec;
- launchd lookup/registration denial and explicit accounting for every allowed
  delegated service;
- hostile constructor, early exit, silence, wrong-image, wrong-worker, FD
  substitution, truncation, replay, deadline, client/owner death, broker crash,
  and every Nth lifecycle/right failure;
- exact VM/port/process baselines, Darwin double-terminal-status handling, and
  10,000-cycle stress; and
- the applicable specification §12 matrix on the exact candidate commit and
  packaged artifacts.

## Public decision boundary

Plan 8b task #57 was deliberately user-gated between:

- **Option A:** keep public macOS fail-closed and document the source mechanism
  as experimental/private; or
- **Option B:** complete the installed evidence above and wire the already
  reviewed private lifecycle into public sessions.

**Decision (user, 2026-07-16): Option B**, under the lib-in-signed-host
integration model — the library launches only deployer-signed code, verified at
the exec trap against the deployer's designated requirement through the
process-unique audit token (PID + pidversion), and terminates exactly its own
unreaped direct child, never any other process.

The decision authorizes the enable path; it does not enable anything by
itself. Until Option B's installed evidence above is complete, public macOS
remains `BackendUnavailable`. No agent may infer enablement from the existence
of private source code or from this decision record.
