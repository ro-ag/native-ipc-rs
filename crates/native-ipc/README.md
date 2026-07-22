# native-ipc

`native-ipc` is the public facade for the `native-ipc-rs` workspace: one safe
API for least-authority shared memory across Linux, macOS, and Windows. There
is no portable OS primitive for sealed anonymous shared memory — `memfd_create`
exists only on Linux, macOS uses Mach memory-entry rights, and Windows uses
exact-rights section handles — so this crate consolidates the three native
mechanisms behind a single interface and security contract. Native backends
remain private implementation details. The facade re-exports:

- `native-ipc-core` for pointer-free codecs, checked shared-memory layouts,
  sequencing, and audited reader/writer bindings.

Supported targets are Linux and Windows on ARM64 or AMD64, and macOS on ARM64:
`aarch64-unknown-linux-gnu`, `x86_64-unknown-linux-gnu`,
`aarch64-pc-windows-msvc`, `x86_64-pc-windows-msvc`, and
`aarch64-apple-darwin`. Other OS/architecture combinations fail compilation
instead of selecting an unaudited fallback.

The consumer declarations are identical for a fixed feature set on all five
targets. The stable-core versus experimental-vNext boundary and complete module
inventory are documented in the repository's
[public API surface](https://github.com/ro-ag/native-ipc-rs/blob/main/docs/public-api.md).

The `native_ipc::memory` module provides one allocation and lifecycle API for
the best native object on the current target — sealed `memfd` on Linux, Mach
VM memory entries on macOS, and unnamed sections on Windows — so application
code never branches on the operating system. Regions may be fixed
or replacement-growable before sharing, can be cleared for reuse, and can be
explicitly destroyed with a complete clearing pass.

## Example

```rust
use native_ipc::memory::{NativeRegion, RegionOptions, WriterOwner};

let mut region = NativeRegion::allocate(RegionOptions::fixed(
    4096,
    WriterOwner::Creator,
))?;
region.initialize(|bytes| bytes[..4].copy_from_slice(b"NIPC"));
let request = region.prepare_for_sharing()?;
assert!(request.mapped_len() >= 4096);
# Ok::<(), native_ipc::memory::MemoryError>(())
```

Run the complete portable lifecycle example with:

```sh
cargo run -p native-ipc --example common_memory
```

## Experimental vNext session API

Since 0.5.0 the Linux, macOS Arm64, and Windows vNext compositions ship as an
experimental surface: per the vNext specification §16, its shapes may still
change between 0.x releases. It is exposed through role- and
state-typed `CoordinatorSession<Negotiating>` and
`ReceiverSession<Negotiating>` owners. `receiver_main!` adopts the inherited
bootstrap exactly once before ordinary receiver code, bilateral application
decisions yield `Session<Ready>`, and only Ready owners may exchange bounded
opaque control records or complete an atomic mixed-direction transfer batch.
Committed batches yield keyed `ActiveReader` and `ActiveWriter` mappings with
checked copy/fill/prefault operations and no safe slice or native-handle escape.

Ready-session failures carry a bounded `SessionFailure` record: operation,
transaction stage, portable reason, optional native code, poison state, peer
endpoint observation, and coordinator child-cleanup facts where available.
Graceful close returns the live session when active leases or child cleanup
still need attention; explicit abort invalidates retained mappings and preserves
bounded cleanup diagnostics.

macOS Arm64 publicly composes the same Negotiating/Ready typestate surface:
public spawn opens and holds the configured executable, spawns it directly,
authenticates the exact child over an audit-token/nonce Mach channel inherited
through a dedicated task registered port, preserves the child's ordinary
launchd bootstrap port, re-verifies the spawned image, and owns exact
direct-child termination, reaping, and bounded cleanup facts. Separately, its
backend-private trusted launcher
authenticates the broker, enters cooperative `ptrace`, proves the relationship
with a stopped handshake, installs hard `RLIMIT_NPROC=1`, and execs through the
kernel's pre-first-instruction trap. Exact stopped `PT_KILL`, tracer-death kill,
and post-exec fork denial pass native tests. The inherited SBPL profile also
denies outbound signals and launchd Mach lookup/registration before and after
target exec. The hidden fixed broker caller composes launcher spawn, FD 4 plan
delivery, clean-exec signature verification, FD 5 trace reporting/Ready-bound
resume, and exact target reap through one child wait domain. That launcher
machinery is for deployer-built helper artifacts and is not part of the public
constructor path; its artifacts are not installed, signed, packaged,
notarized, or proven replacement-resistant, and no deployer capability
allowlist is complete. Consumers can query the common, const availability API
before constructing a session, or handle the construction result directly:

```rust
use native_ipc::session::{BackendStatus, SessionError, backend_status};

match backend_status() {
    BackendStatus::Available => { /* construct the role-typed session */ }
    BackendStatus::Unavailable => { /* use a supported fallback */ }
}

# let construction_result: Result<(), SessionError> = Ok(());
if let Err(SessionError::BackendUnavailable) = construction_result {
    // Reserved for a supported target whose adapter is not composed; no
    // currently supported target reaches this arm.
}
```

The declarations do not vary by target: Linux, macOS Arm64, and Windows all
report `Available`; `Unavailable` remains reserved for targets whose adapter
is not composed. This query concerns only the vNext session layer; the
published native-memory API is available everywhere regardless.
Windows publicly composes the same Negotiating/Ready typestate surface over its
unnamed-section memory owner, PID-authenticated message transport, held image,
whole-Job lifecycle, full-manifest reducer, bilateral capacity recovery, and
post-COMMIT active ledger. Native Windows AMD64 source-tree and extracted-package
all-feature/no-default suites pass at the recorded checkpoint. Native Windows
Arm64 and Linux Arm64 full-suite runs also pass with zero failures, recorded
at both the 0.5.0 parity checkpoint and the guard-band head. Exact-release
packaged conformance and the installed/signed macOS helper (launcher)
architecture remain pending. The existing cross-platform native-memory
lifecycle API remains available independently.

Payload bytes received through shared memory remain hostile input. Readers copy
them into owned storage and recheck bounded metadata, but the library does not
claim integrity against a malicious same-sequence writer.

See the [repository README](https://github.com/ro-ag/native-ipc-rs#readme),
[architecture](https://github.com/ro-ag/native-ipc-rs/blob/main/docs/architecture.md),
and [threat model](https://github.com/ro-ag/native-ipc-rs/blob/main/docs/threat-model.md)
for the complete security contract.

Licensed under MIT or Apache-2.0 at your option.
