# native-ipc-rs

`native-ipc-rs` is a security-oriented Rust foundation for bounded,
pointer-free IPC over least-authority native shared-memory capabilities. It
separates a domain-neutral wire/layout core from operating-system capability
enforcement. It is not yet a complete process transport.

The workspace contains:

- `native-ipc`: public facade;
- `native-ipc-core`: explicit codecs, checked layouts, publication sequencing,
  and capability bindings;
- `native-ipc-platform`: native mappings and capability policy; and
- `native-ipc-testkit`: golden-vector and adversarial conformance helpers.

## Security invariants

- Wire data is manually encoded little-endian fixed-width fields. Rust object
  layouts, pointers, references, `usize`, native handles, and implicit
  serialization formats never cross the boundary.
- Every message and region is bound to a 256-bit schema, a nonzero generation,
  numeric roles, fixed capacity, and checked relative ranges.
- Each mapping has exactly one writer. A peer reader receives only a read-only
  native capability; no shared page is writable by both processes.
- Writers publish a nonzero sequence with Release ordering. Readers Acquire,
  validate, copy to owned memory, and recheck without modifying producer data.
- Ring reuse requires an acknowledgement with the exact target, generation,
  and prior sequence. Missing, stale, lagging, future, wrong-target, and wrapped
  acknowledgements fail closed.
- Store-capable slot and acknowledgement types can be created only from
  layouts validated as writable. Read-only layouts grant acquire-only types.
- Runtime mappings never expose ordinary Rust slices. Slice access exists only
  in a consuming, pre-transfer quiescent macOS typestate.
- Shared mappings are never executable and are never globally named.

These properties reduce shared-memory authority; they do not sandbox a peer
process. Process launch, identity authentication, sandboxing, and application
policy remain the embedding application's responsibility.

## Current status

Implemented in `0.1.0`:

- generic message envelopes and explicit codec traits with allocation/record
  limits;
- checked configurable directional region and slot layouts;
- role/generation/capacity/index/count/permission-bound reader and writer
  capabilities;
- split acknowledgement reader/writer capabilities and exact reuse checks;
- macOS Mach VM quiescent/local-writer/remote-writer typestates, including live
  kernel tests for read-only and non-executable maximum permissions;
- portable golden vectors and adversarial validation fixtures; and
- explicit fail-closed Linux and Windows backend status.

Incomplete:

- transfer of Mach memory-entry send rights and authenticated bootstrap;
- Linux sealed `memfd`, `SCM_RIGHTS`, `SO_PEERCRED`, and `pidfd` transport;
- Windows least-rights unnamed sections, private named pipes, and kill-on-close
  Job Objects;
- cross-process helper lifecycle, peer authentication, guard pages, fuzzing,
  and production cleanup orchestration.

Until those items are complete, this repository must not be described as a
production-ready isolation transport.

## Non-goals

- mapping arbitrary Rust values or native object graphs between processes;
- VST3, COM, audio plug-in, or other application-domain semantics;
- Serde, bincode, postcard, or ABI-dependent foundational wire layouts;
- network or cross-machine transport;
- globally discoverable shared-memory names or System V IPC;
- executable shared mappings; and
- claiming that process separation alone is a security sandbox.

## Toolchain and validation

The MSRV is Rust 1.97 with edition 2024. Before submitting a change, run:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-features --all-targets -- -D warnings
cargo test --workspace --all-features --all-targets
cargo check --workspace --no-default-features --all-targets
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps
cargo deny check
git diff --check
```

The project is dual-licensed under [MIT](LICENSE-MIT) or
[Apache-2.0](LICENSE-APACHE), at your option.
