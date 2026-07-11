# native-ipc-rs

[![CI](https://github.com/ro-ag/native-ipc-rs/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/ro-ag/native-ipc-rs/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/native-ipc.svg)](https://crates.io/crates/native-ipc)
[![docs.rs](https://docs.rs/native-ipc/badge.svg)](https://docs.rs/native-ipc)
[![license](https://img.shields.io/crates/l/native-ipc.svg)](LICENSE-MIT)
[![MSRV](https://img.shields.io/badge/MSRV-1.97-blue.svg)](rust-toolchain.toml)
[![platforms](https://img.shields.io/badge/platforms-Linux%20%26%20Windows%20ARM64%2FAMD64%20%7C%20macOS%20ARM64-informational.svg)](#supported-targets)

`native-ipc-rs` is a security-oriented Rust foundation for bounded,
pointer-free IPC over least-authority native shared-memory capabilities. It
separates a domain-neutral wire/layout core from operating-system capability
enforcement. It is not yet a complete process transport.

## Why this repository exists

Shared memory is fast, but a conventional wrapper can accidentally turn an
untrusted process into a holder of writable aliases, native handles with excess
rights, or Rust references whose invariants another process can violate.
Serialization alone does not solve capability transfer, mapping permissions,
peer identity, process cleanup, or replay across restarts.

This repository separates those concerns:

- a pointer-free core manually encodes fixed-width wire/layout data and checks
  every hostile length, offset, role, generation, sequence, and resource bound;
- native adapters ask each kernel for least-authority mappings and authenticate
  the exact helper process before transferring them; and
- safe runtime APIs expose owned payload copies and typed reader/writer
  capabilities instead of shared Rust slices.

```mermaid
flowchart LR
    subgraph A["Process A"]
        AA["Application"] --> AC["Bounded codec"]
        AC --> AW["Sole writer"]
        AR["Read-only reader"] --> AO["Owned hostile bytes"]
        ACTL["Bootstrap endpoint"]
    end

    subgraph K["Kernel-enforced capabilities"]
        RAB["Region A → B"]
        RBA["Region B → A"]
        AUTH["Private authenticated control channel"]
    end

    subgraph B["Process B"]
        BA["Application"] --> BC["Bounded codec"]
        BC --> BW["Sole writer"]
        BR["Read-only reader"] --> BO["Owned hostile bytes"]
        BCTL["Bootstrap endpoint"]
    end

    AW -->|"RW only in A"| RAB
    RAB -->|"RO in B"| BR
    BW -->|"RW only in B"| RBA
    RBA -->|"RO in A"| AR
    ACTL <-->|"identity, capabilities, READY"| AUTH
    AUTH <-->|"identity, capabilities, READY"| BCTL
```

The workspace contains:

- `native-ipc`: public facade;
- `native-ipc-core`: explicit codecs, checked layouts, publication sequencing,
  and capability bindings;
- `native-ipc-platform`: native mappings and capability policy; and
- `native-ipc-testkit`: golden-vector and adversarial conformance helpers.

## How memory is accessed

Ordinary byte slices exist only while a new mapping is private and quiescent.
The creator writes the canonical layout, validates the complete page-rounded
range, chooses the sole writer, and asks the OS to attenuate the peer's rights.
After authenticated transfer and import, both sides signal `READY`; runtime APIs
then operate through mapping-owned capabilities without returning shared
references.

```mermaid
sequenceDiagram
    participant C as Creator
    participant OS as Native kernel
    participant P as Authenticated peer
    participant R as Shared region

    C->>OS: Allocate zeroed, non-executable region
    OS-->>C: Exclusive quiescent mapping
    C->>R: Encode canonical header, slots, and routes
    C->>C: Validate full mapping and padding
    C->>OS: Create exact RO or sole-RW peer capability
    OS-->>P: Transfer capability over private channel
    P->>P: Import with exact access and validate again
    P-->>C: READY
    C->>R: Copy payload, then Release-publish sequence
    P->>R: Acquire sequence and checked length
    P->>P: Copy payload into owned storage
    P->>R: Fence and recheck generation/sequence/length
    P->>R: Publish exact acknowledgement for reuse
```

The recheck bounds memory access and detects metadata changes. It does not make
a malicious writer's payload trustworthy: same-sequence mutation may still
produce a torn owned copy, so protocol decoding must remain hostile-input safe.

## Common memory interface

`native_ipc::memory::NativeRegion` selects the strongest supported anonymous
shared-memory object at compile time. Applications describe intent rather than
calling Mach, Unix, or Win32 APIs directly:

```rust
use native_ipc::memory::{
    CleanupPolicy, NativeRegion, RegionOptions, WriterOwner,
};

# fn demo() -> Result<(), native_ipc::memory::MemoryError> {
let options = RegionOptions::growable(
    64 * 1024,             // initial logical bytes
    1024 * 1024,           // maximum before sharing
    WriterOwner::Creator,  // peer receives read-only access
)
.with_cleanup(CleanupPolicy::ClearThenRelease);

let mut region = NativeRegion::allocate(options)?;
region.initialize(|bytes| bytes[..4].copy_from_slice(b"NIPC"));
region.grow(128 * 1024)?; // replaces the still-private mapping
region.clear();           // zero all mapped bytes and keep it reusable
region.destroy();         // zero all mapped bytes, then release explicitly
# Ok(())
# }
```

| Operation | State | Guarantee |
| --- | --- | --- |
| `RegionOptions::fixed` | Before allocation | Mapping cannot grow |
| `RegionOptions::growable` | Private only | Replacement growth up to an explicit maximum |
| `initialize` | Quiescent | Closure sees logical bytes; padding remains hidden and zero |
| `clear` | Quiescent | Volatile-zero the complete mapping and retain it for reuse |
| `destroy` | Quiescent | Volatile-zero, fence, unmap, and close the anonymous object |
| `prepare_for_sharing` | Consuming transition | Remove byte/growth access and retain the seal/permission plan |

Sealing is deliberately not an optional Boolean. `SealPolicy::RequiredOnShare`
is fixed by the safe interface. The consuming platform transition applies
`memfd` seals, Mach maximum rights, or exact Windows handle rights according to
the selected backend. Size, writer ownership, and permissions cannot change
after sharing.

## Examples

Add the public facade with:

```sh
cargo add native-ipc
```

Runnable core examples demonstrate the two pieces applications configure
before native capability transfer:

```sh
cargo run -p native-ipc-core --example bounded_codec
cargo run -p native-ipc-core --example checked_layout
cargo run -p native-ipc-platform --example quiescent_region
cargo run -p native-ipc --example common_memory
```

- [`bounded_codec.rs`](crates/native-ipc-core/examples/bounded_codec.rs) defines
  a manual little-endian protocol, encodes an envelope, and decodes it under
  explicit message/payload/allocation limits.
- [`checked_layout.rs`](crates/native-ipc-core/examples/checked_layout.rs)
  composes two directional, single-writer regions with exact acknowledgement
  routes and bounded capacities.
- [`quiescent_region.rs`](crates/native-ipc-platform/examples/quiescent_region.rs)
  allocates the current OS's zeroed native capability and demonstrates that
  mutable slices exist only before the consuming transfer transition.
- [`common_memory.rs`](crates/native-ipc/examples/common_memory.rs) uses the
  portable fixed/grow/clear/destroy lifecycle without selecting an OS backend.

## Security invariants

- Wire data is manually encoded little-endian fixed-width fields. Rust object
  layouts, pointers, references, `usize`, native handles, and implicit
  serialization formats never cross the boundary.
- Every message and region is bound to a 256-bit schema, a nonzero generation,
  numeric roles, fixed capacity, and checked relative ranges.
- Each mapping has exactly one writer. A peer reader receives only a read-only
  native capability; no shared page is writable by both processes.
- Writers publish with Release ordering. Readers Acquire, copy hostile bytes to
  owned memory, fence, and recheck generation, sequence, and length. This does
  not prove payload integrity or detect malicious same-sequence mutation.
- Ring reuse requires a unique per-slot route with exact owner, target, slot,
  cell, generation, and prior sequence. Equal re-acknowledgement is
  intentionally idempotent for retransmission.
- Store capabilities require a consumed platform sole-writer witness;
  OS-enforced read-only witnesses grant only acquire capabilities.
- Runtime mappings never expose ordinary Rust slices. Slice access exists only
  in consuming, pre-transfer quiescent platform typestates.

## Current status

Implemented in `0.1.0`:

- generic message envelopes and explicit codec traits with allocation/record
  limits;
- checked configurable directional region and slot layouts;
- role/generation/capacity/index/count/permission-bound reader and writer
  capabilities;
- split acknowledgement reader/writer capabilities and exact reuse checks;
- macOS Mach VM quiescent/local-writer/remote-writer typestates, including live
  permission probes, authenticated bootstrap, memory-entry transfer/import, and
  a bidirectional helper-process fixture;
- Linux sealed `memfd`, exact `SCM_RIGHTS`, `SO_PEERCRED`, `pidfd`, and owned
  helper lifecycle;
- Windows least-rights unnamed sections, exact-PID private named pipes,
  suspended Job-contained helpers, and cross-process handle import;
- portable golden vectors, deterministic adversarial fixtures, Miri, and
  bounded coverage-guided fuzz targets.

### Platform capabilities

#### Supported targets

| Platform | Architecture | Rust target | Shared-memory capability | Peer authentication | Lifecycle containment |
| --- | --- | --- | --- | --- | --- |
| Linux | AMD64 | `x86_64-unknown-linux-gnu` | Sealed anonymous `memfd` + exact `SCM_RIGHTS` | `SO_PEERCRED` | `pidfd` + owned helper cleanup |
| Linux | ARM64 | `aarch64-unknown-linux-gnu` | Sealed anonymous `memfd` + exact `SCM_RIGHTS` | `SO_PEERCRED` | `pidfd` + owned helper cleanup |
| macOS | ARM64 | `aarch64-apple-darwin` | Mach memory-entry send rights | Mach audit-token PID | private bootstrap port + reap |
| Windows | AMD64 | `x86_64-pc-windows-msvc` | Least-rights unnamed section handles | both named-pipe endpoint PIDs | suspended spawn + kill-on-close Job |
| Windows | ARM64 | `aarch64-pc-windows-msvc` | Least-rights unnamed section handles | both named-pipe endpoint PIDs | suspended spawn + kill-on-close Job |

The public facade and native platform crate fail compilation on other target
combinations. The platform-neutral `native-ipc-core` crate remains usable
wherever its documented 64-bit atomic requirement is met. CI runs the full
workspace and native permission/helper-process tests on all five targets; no
Intel macOS support is claimed. Linux AMD64 additionally runs every workspace
and native lifecycle test under AddressSanitizer. Leak detection and
stack-use-after-return detection are enabled, and the standard library is
rebuilt with instrumentation so the check covers allocation boundaries beyond
this workspace's crates.

Still intentionally outside `0.1.x` are a high-level negotiation/supervisor
API, payload authenticity or encryption, automatic guard-page policy, and a
stable `1.0` compatibility promise. The current crates are low-level building
blocks for applications that explicitly own protocol negotiation, resource
budgets, compatibility policy, and guard-page decisions.

## Toolchain and validation

The MSRV is Rust 1.97 with edition 2024. Before submitting a change, run:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-features --all-targets -- -D warnings
cargo test --workspace --all-features --all-targets
cargo test --workspace --no-default-features --all-targets --locked
cargo check --workspace --no-default-features --all-targets
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps
cargo deny check
git diff --check
```

The Linux AMD64 sanitizer job uses nightly Rust because sanitizers and
instrumented standard-library builds are not stable compiler features:

```sh
ASAN_OPTIONS="detect_leaks=1:detect_stack_use_after_return=1:halt_on_error=1" \
RUSTFLAGS="-Zsanitizer=address -Cforce-frame-pointers=yes" \
RUSTDOCFLAGS="-Zsanitizer=address -Cforce-frame-pointers=yes" \
cargo +nightly test -Zbuild-std --workspace --all-features --all-targets \
  --locked --target x86_64-unknown-linux-gnu
```

The project is dual-licensed under [MIT](LICENSE-MIT) or
[Apache-2.0](LICENSE-APACHE), at your option.
