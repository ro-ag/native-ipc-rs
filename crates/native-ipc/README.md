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
targets. The published-0.4 versus unreleased-vNext boundary and complete module
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

## Unreleased vNext session API

The current source tree exposes the Linux and Windows vNext compositions through role- and
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

The macOS Arm64 prototype reaches the same private reducer but remains
fail-closed at public spawn/bootstrap. Its backend-private trusted launcher
authenticates the broker, enters cooperative `ptrace`, proves the relationship
with a stopped handshake, installs hard `RLIMIT_NPROC=1`, and execs through the
kernel's pre-first-instruction trap. Exact stopped `PT_KILL`, tracer-death kill,
and post-exec fork denial pass native tests. The inherited SBPL profile also
denies outbound signals and launchd Mach lookup/registration before and after
target exec. The hidden fixed broker caller composes launcher spawn, FD 4 plan
delivery, clean-exec signature verification, FD 5 trace reporting/Ready-bound
resume, and exact target reap through one child wait domain. These are
source/native mechanism results only: deployer-supplied broker, launcher, and
worker artifacts are not installed, signed, packaged, notarized, or proven
replacement-resistant; no deployer capability allowlist is complete; and public
enablement remains a separate user decision. Public macOS therefore remains
`BackendUnavailable`. Consumers can query this common, const API before
constructing a session, or handle the construction result directly:

```rust
use native_ipc::session::{BackendStatus, SessionError, backend_status};

match backend_status() {
    BackendStatus::Available => { /* construct the role-typed session */ }
    BackendStatus::Unavailable => { /* use a supported fallback */ }
}

# let construction_result: Result<(), SessionError> = Ok(());
if let Err(SessionError::BackendUnavailable) = construction_result {
    // The target's public session composition is intentionally fail-closed.
}
```

The declarations do not vary by target: Linux and Windows report `Available`,
while macOS Arm64 reports `Unavailable`. This query concerns only the vNext
session layer; the published native-memory API remains available on macOS.
Windows publicly composes the same Negotiating/Ready typestate surface over its
unnamed-section memory owner, PID-authenticated message transport, held image,
whole-Job lifecycle, full-manifest reducer, bilateral capacity recovery, and
post-COMMIT active ledger. Native Windows AMD64 source-tree and extracted-package
all-feature/no-default suites pass at the recorded checkpoint. Native Windows
Arm64 runtime, exact-release packaged conformance, the macOS lifecycle
architecture, and release evidence remain pending. The existing cross-platform
native-memory lifecycle API remains available independently.

Payload bytes received through shared memory remain hostile input. Readers copy
them into owned storage and recheck bounded metadata, but the library does not
claim integrity against a malicious same-sequence writer.

See the [repository README](https://github.com/ro-ag/native-ipc-rs#readme),
[architecture](https://github.com/ro-ag/native-ipc-rs/blob/main/docs/architecture.md),
and [threat model](https://github.com/ro-ag/native-ipc-rs/blob/main/docs/threat-model.md)
for the complete security contract.

Licensed under MIT or Apache-2.0 at your option.
