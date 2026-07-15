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

The current source tree exposes the Linux vNext composition through role- and
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
and post-exec fork denial pass native tests. The remaining authority boundary
is not solved: same-UID target code can `SIGSTOP` the broker indefinitely. A
nested-tracer native test proves an outer watchdog can exactly kill/reap that
stopped broker and trigger exact tracer-exit cleanup of its target, but not the
required production privilege separation. The launchd bootstrap namespace
restored for libxpc permits delegated work outside the rlimit. Public
composition therefore still requires an
independently privileged authenticated service/watchdog and remains blocked.
Backend-private source models constrain that future boundary to a verified
installed policy, a bounded absolute-deadline nonce/generation-bound request, opaque watchdog
handles retaining linear exact cleanup authority, and a permanent nonroot
UID/GID/group drop. A fused source-only authentication adapter further binds
the retained exact message/token to a fixed one-job worker and linear private
reply receipt, then requires typed exact worker reap before peer authority can
exist; no API falls back to signaling a reconstructed PID. They are not a
packaged or installed service and do not
constitute root, signing, installed-service, or public-session evidence.
Windows publicly composes the same Negotiating/Ready typestate surface over its
unnamed-section memory owner, PID-authenticated message transport, held image,
whole-Job lifecycle, full-manifest reducer, bilateral capacity recovery, and
post-COMMIT active ledger. Native Windows AMD64 source-tree and extracted-package
all-feature/no-default suites pass in the recorded working tree. Native Windows
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
