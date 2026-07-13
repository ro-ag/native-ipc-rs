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
fail-closed at public spawn/bootstrap because direct spawn cannot exactly kill a
child silent before its first audit-bearing Mach message without forbidden task
authority. A preinstalled signed launchd/XPC service is a necessary candidate,
but it does not preserve exact authority across service crash without another
OS-enforced containment mechanism; that architecture remains blocked.
Windows is likewise fail-closed with `BackendUnavailable`, but its private
unnamed-section memory owner, PID-authenticated message transport, whole-Job
lifecycle, full-manifest reducer, and post-COMMIT active ledger now pass the
native Windows AMD64/Arm64 source-tree corpus. Public Windows session
composition, the macOS lifecycle architecture, exact-release packaged
conformance, and release evidence remain pending. The existing cross-platform
native-memory lifecycle API remains available independently.

Payload bytes received through shared memory remain hostile input. Readers copy
them into owned storage and recheck bounded metadata, but the library does not
claim integrity against a malicious same-sequence writer.

See the [repository README](https://github.com/ro-ag/native-ipc-rs#readme),
[architecture](https://github.com/ro-ag/native-ipc-rs/blob/main/docs/architecture.md),
and [threat model](https://github.com/ro-ag/native-ipc-rs/blob/main/docs/threat-model.md)
for the complete security contract.

Licensed under MIT or Apache-2.0 at your option.
