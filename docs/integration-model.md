# Integration model and scope

This document states what `native-ipc` is for, how a consumer is expected to
integrate it, and — precisely — what security guarantee it does and does not
make. It is the canonical scope statement; where an older document disagrees,
this one wins.

## Two layers

`native-ipc` has two layers, at two different stages of maturity.

1. **Shared-memory core (shipping).** Least-authority, pointer-free, sealed
   shared memory with a single API across every supported platform: private
   regions, direction-specific reader/writer capabilities, a bounded wire/layout
   codec, and authenticated capability transfer. This is the published building
   block and it is the same public surface on Linux, macOS, and Windows.

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
- **Shared memory** is the only channel between them. The untrusted artifact
  never touches the Host directly; it only ever operates on the region the Host
  grants, and the Host validates everything that comes back. This is the
  security choke point the whole library exists to provide.

**The contract:** `native-ipc` launches only code you control — a program you
wrote, or a runner that loads plugins as shared objects. Untrusted third-party
logic only ever runs as an **in-process library inside a signed runner**, never
as a standalone process the library was handed. Using it to run an arbitrary,
unknown, standalone program is outside the contract, and the guarantees below do
not apply to that use.

## What the guarantee is

Within that contract, for a Child Runner:

- **It is your code, cryptographically.** The runner image is verified before it
  is released — by exact process identity, and (where signing is configured) by
  its code signature checked at the exec boundary against your designated
  requirement. A swapped-on-disk image does not run; it is rejected and killed.
- **It is contained.** The runner (and any in-process plugin) cannot escape to a
  new process (a hard process limit denies `fork`/spawn), cannot signal or attack
  the Host or supervisor, and — where a capability profile is configured — cannot
  reach the filesystem or network beyond an allowlisted working set.
- **Its lifecycle is exact.** The supervisor owns the runner as an exact,
  unreaped direct child. It can terminate it deterministically at any point and
  reaps it fully — no leaked process, no zombie — including an uncooperative or
  hung runner that ignores a graceful request.
- **No elevated privilege is required.** None of this needs, uses, or wants root.
  The design is same-user and unprivileged throughout.

The untrusted plugin runs *in-process* in the runner, so it can corrupt or crash
its own runner. That is contained, not an escape: the runner is disposable, holds
no Host secrets, and is exact-killed and replaced. The Host is a separate process
and is not reachable from the plugin.

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

The **public API is identical on every supported platform.** The
`memory`, `session`, `region`, `batch`, `control`, and `active` modules expose
the same types and the same security contract everywhere; the per-platform
kernel mechanism is an implementation detail confined to a private backend and
summarized in the supported-targets table in the README. A consumer writes to
one API and one contract; only the underlying primitive changes:

| Concern | Linux | macOS | Windows |
| --- | --- | --- | --- |
| Shared memory | sealed anonymous `memfd` + `SCM_RIGHTS` | Mach memory-entry send rights | least-rights unnamed section handles |
| Peer identity | `SO_PEERCRED` | Mach audit-token PID (+ optional code signature) | both named-pipe endpoint PIDs |
| Runner lifecycle | `pidfd` + owned helper cleanup | ptrace exec-trap + sandbox + exact reap (design; not yet public) | suspended spawn + kill-on-close Job |

The lifecycle guarantee — verified-your-code runner, contained, exactly reaped,
no root — is the same conceptual promise on each platform; each reaches it with
its own native primitive.

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
