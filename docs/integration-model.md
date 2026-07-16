# Integration model and scope

This document states what `native-ipc` is for, how a consumer is expected to
integrate it, and — precisely — what security guarantee it does and does not
make. It is the canonical scope statement; where an older document disagrees,
this one wins.

## Two layers

`native-ipc` has two layers, at two different stages of maturity.

1. **Shared-memory core (shipping).** Least-authority, pointer-free, sealed
   shared memory with a single allocation/preparation API across every supported
   platform: private regions, direction-specific reader/writer capabilities,
   and a bounded wire/layout codec. The unreleased vNext session layer adds
   authenticated capability transfer; it is publicly composed on Linux and
   Windows, while public macOS session construction remains fail-closed.

2. **Lifecycle supervisor (vNext design, not yet public on macOS).** The spawn,
   identity-verification, containment, and exact-termination machinery for a
   child process. On Linux and Windows this rides the platform's own primitives
   (pidfd + owned cleanup; suspended spawn + kill-on-close Job). On macOS it is
   an unprivileged ptrace/sandbox design that is **not enabled** — the public
   macOS backend is currently `BackendUnavailable` by decision. The model below
   describes the design and its scope, not a shipping macOS promise.

## The integration model

`native-ipc` is used to build **both ends** of a connection. It is not a tool
for running an unknown program safely.

```
 Host  [your code]   ⟷   shared memory (native-ipc)   ⟷   Child Runner  [your code]
 (your main app)          the validated choke point          (disposable, contained)
        │                                                            │
   separate process ───────────────────────────────────────── separate process
                                                                     │
                                                              dlopen │
                                                                     ▼
                                                            plugin / model / lib
                                                               (untrusted)
```

- The **Host** is your application. It is a separate process and is protected by
  the process boundary.
- The **Child Runner** is also your code: a small program you write and sign
  whose job is to load and drive one untrusted artifact — a VST3 plugin, a model
  runner, a third-party C library — as an in-process shared object.
- **Shared memory** is the only bulk application-data channel between them. The
  library also owns one bounded authenticated bootstrap/control channel for
  negotiation, capability transfer, and non-real-time lifecycle messages. The
  untrusted artifact operates on only the regions and opaque control payloads
  the Host grants, and the Host validates everything that comes back. These are
  the security choke points the whole library exists to provide.

**The contract:** `native-ipc` launches only code you control — a program you
wrote, or a runner that loads plugins as shared objects. Untrusted third-party
logic only ever runs as an **in-process library inside that runner**, never as a
standalone process the library was handed. The application owns signing and
deployment policy. The library binds an owned launch to the configured exact
executable identity, and the private macOS design additionally applies a
deployer-compiled signing requirement at the exec trap. Using the API to run an
arbitrary, unknown, standalone program is outside the contract.

## What the guarantee is

Within that contract, for a Child Runner:

- **It is the configured executable.** Linux executes a held opened image;
  Windows retains replacement-denying file identity and verifies the suspended
  image; the private macOS launcher compares stable image identity and, when
  configured, validates the exec-trap audit token against the deployer's signing
  requirement. Signing itself remains application deployment policy.
- **Its native authority is bounded.** The library grants only the authenticated
  regions and control frames described by the vNext contract. Process-tree
  containment is target-specific: Windows owns a non-breakaway kill-on-close
  Job; Linux owns an exact direct child in a fresh session but does not promise
  cleanup of hostile escaped descendants; the private macOS design empirically
  denies fork/spawn, outbound signals, and launchd lookup/registration through
  inherited rlimit/SBPL policy. Filesystem and network confinement is optional
  application policy, not a cross-platform library guarantee.
- **Its direct-child lifecycle is exact while authority remains available.**
  The coordinator retains a race-resistant exact-child owner, observes exit,
  terminates when required, and reaps without reconstructing authority from a
  PID. An uninterruptible kernel wait or terminal cleanup failure may prevent
  immediate completion; the API then retains ownership and reports bounded
  incomplete cleanup facts rather than claiming success.
- **No elevated privilege is part of this model.** The supported construction
  and the private macOS design are same-user and unprivileged; root, `sudo`,
  set-ID helpers, and root-owned installation paths are excluded.

The untrusted plugin runs *in-process* in the runner, so it can corrupt or crash
its own runner. The runner is disposable and the Host is a separate process,
but this is not a claim that the OS hides every Host resource from the runner.
The application must avoid placing Host secrets in granted regions/control
payloads and must configure any desired filesystem, network, or platform sandbox.

## What the guarantee is not

- **It is not a sandbox for an arbitrary untrusted process.** Containing a
  separate, adversarial, same-user process without a task port is not achievable
  under public macOS APIs (an extensively researched result). This library does
  not attempt it; it manages the lifecycle of *your* code and confines untrusted
  logic to an in-process library instead.
- **It does not defend against a malicious same-user *principal*** — an attacker
  who already runs their own separate process as your user. A malicious plugin
  shipped as a library does not by itself grant that; an attacker who already has
  independent code execution as your user is outside scope.
- **macOS `launchd` delegation.** The fixed launcher profile denies Mach service
  lookup and registration before the runner image executes, closing the blanket
  delegation path in the backend-private design. A future deployer capability
  profile may replace that blanket denial only with an explicit service
  allowlist; each allowlisted service is delegated authority that the deployment
  must account for. Public macOS remains disabled until its separate enablement
  decision and installed-artifact evidence are complete.
- **macOS mechanism caveat.** The unprivileged containment relies on
  `sandbox_init` (deprecated) and SBPL (undocumented). It is an empirical property
  of the current OS, verified by measurement, not a supported API contract.

## Cross-platform consistency

The **consumer type surface is intended to be identical on every supported
platform.** The
`memory`, `session`, `region`, `batch`, `control`, and `active` modules expose
the same types and the same security contract everywhere; the per-platform
kernel mechanism is an implementation detail confined to a private backend and
summarized in the supported-targets table in the README. A consumer writes to
one API and one contract; only the underlying primitive changes:

| Concern | Linux | macOS | Windows |
| --- | --- | --- | --- |
| Shared memory | sealed anonymous `memfd` + `SCM_RIGHTS` | Mach memory-entry send rights | least-rights unnamed section handles |
| Peer identity | per-record `SCM_CREDENTIALS` bound to the exact child | Mach audit-token PID (+ deployer signing policy in the private launcher) | both named-pipe endpoint PIDs |
| Runner lifecycle | `pidfd` + owned helper cleanup | ptrace exec-trap + sandbox + exact reap (design; not yet public) | suspended spawn + kill-on-close Job |

The common promise is exact configured-image bootstrap, bounded IPC authority,
and honest direct-child cleanup facts without elevated privilege. Descendant and
sandbox strength remains the target-specific contract stated above.

The consumer-facing public API carries **no `#[cfg(target_os)]` items**: the
`memory`, `session`, `region`, `batch`, `control`, and `active` modules present
byte-for-byte the same types on every target. The only platform-specific public
surface is a small set of `#[doc(hidden)]` macOS entry points
(`__private_macos_*`) used solely when a deployer compiles the macOS helper
executables; they are not part of the consumer API and do not appear in the
rendered docs.

## Reference proofs

The mechanism is demonstrated end to end, unprivileged, in
[`docs/proofs/nipc_proof.c`](proofs/nipc_proof.c) (a standalone C proof: spawn,
identity + certificate check, exec trap, containment, exact reap) and in the
in-tree Rust test `real_launcher_entry_proves_identity_contains_the_target_and_reaps_exactly`,
which drives the real launcher entry through the same sequence. Both run with no
root and prove the *mechanism*; neither claims an installed, notarized,
production deployment.
