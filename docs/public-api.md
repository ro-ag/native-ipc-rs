# Public Rust API surface

This document records the consumer-facing Rust surface at the current vNext
source head and separates already-published 0.4 API from unreleased vNext API.
It is an API inventory, not a 1.0 compatibility promise.

## Cross-target invariant

For a fixed Cargo feature set, the public declarations in `memory`, `session`,
`region`, `batch`, `control`, and `active` are the same on every supported
target. A consumer does not select an OS module or use `cfg(target_os)` to name
a type or method. Backend selection changes private representation and runtime
behavior, not the consumer-visible Rust signatures.

This is a Rust source-compatibility contract. It does not promise a stable C
ABI, stable type layout, equal `size_of` values, or interchangeable serialized
Rust values. Public types do not use `repr(C)` unless a separate documented FFI
contract says so.

The invariant is enforced in two complementary ways:

- `protocol::tests::consumer_modules_have_no_target_gated_public_items` rejects
  a `target_os` or `target_arch` gate on a public item in any of the six
  consumer modules; and
- `tests/public_consumer_surface.rs` names the complete public type inventory
  from one unchanged downstream source file. The existing five-target CI
  matrix compiles that file on Linux GNU AMD64/Arm64, macOS Arm64, and Windows
  AMD64/Arm64.

Feature gates remain allowed when they express an explicit, cross-platform
Cargo feature. Today only the unsafe raw pointer methods are gated by the
`raw-pointer` feature.

## Maturity boundary

| Surface | Status at this source head | Compatibility statement |
| --- | --- | --- |
| `native_ipc::core` re-export | Published in 0.4 | Existing pre-1.0 surface; normal semver rules apply. |
| `native_ipc::memory` | Published in 0.4 | Existing pre-1.0 allocation/lifecycle surface; normal semver rules apply. |
| `native_ipc::{region,batch,control,active,session}` | Unreleased vNext | Experimental source API. Names and details may change until the vNext contract and release gates are complete. |
| `native_ipc::receiver_main!` | Unreleased vNext | Experimental helper-entry macro coupled to the vNext session bootstrap contract. |
| `raw-pointer` methods | Unreleased vNext advanced API | Feature-gated unsafe escape; never part of the ordinary safe API. |
| `#[doc(hidden)]` entry hooks | Deployment/test plumbing | Not consumer API and no compatibility promise. |

The `native-ipc-platform` re-export present in the published 0.4 facade is
superseded at this vNext source head. Backend orchestration now lives in private
facade modules. The published 0.4 crate and `v0.4.0` tag remain the reference
for that older API; this source tree does not pretend the already-published
artifact can be changed retroactively.

## Consumer module inventory

| Module | Public surface | Role |
| --- | --- | --- |
| `memory` | `NativeRegion`, `NativeShareRequest`, `RegionOptions`, `RegionStatus`, `RegionState`, `MemoryError`, `NativeMemoryCapabilities`, `NativePlatform`, `NativeArchitecture`, `AuthorityMechanism`, `WriterOwner`, `MemoryAccess`, `PermissionPlan`, `GrowthPolicy`, `CleanupPolicy`, `SealPolicy`, `native_memory_capabilities` | Published 0.4 private-memory allocation, policy, pre-share preparation, and cleanup. |
| `region` | `RegionId`, `WriterEndpoint`, `RegionSpec`, `RegionOptions`, `GuardPolicy`, `GuardCapability`, `RegionError`, `PrivateRegion`, `PreparedRegion` | vNext consuming, opaque region typestates. |
| `batch` | `TransferBatch`, `ExpectedRegion`, `ExpectedBatch`, `ActiveRegionSet`, `BatchError` | vNext bounded 1..=16 mixed-direction transaction and committed keyed result. |
| `control` | `ControlFrame`, `ControlError`, `APPLICATION_CONTROL_KIND_MIN` | vNext bounded opaque application-control record. |
| `active` | `ActiveReader`, `ActiveWriter`, `AccessError`, `PrefaultResult` | vNext checked runtime copy/fill/prefault access; raw pointers only with the explicit feature. |
| `session` | role/state markers and `Session<Role, State>` aliases; bootstrap/command/options/limits/deadline; negotiation/control/batch operations; lifecycle, failure, peer, exit, cleanup, atomic, and lease facts | vNext authenticated exact-child session, negotiation, transfer, control, and lifecycle ownership. |

The two `RegionOptions` types are intentionally distinct during the migration:
`memory::RegionOptions` belongs to the published 0.4 private-memory lifecycle;
`region::RegionOptions` configures a vNext consuming region. Consumers should
import them through their module paths or explicit aliases.

## Runtime availability

The Rust signatures are identical, but a target may honestly report that a
runtime composition is unavailable:

| Target | Published `memory` API | vNext public session construction |
| --- | --- | --- |
| Linux GNU AMD64/Arm64 | Available | Publicly composed. |
| Windows AMD64/Arm64 | Available | Publicly composed. |
| macOS Arm64 | Available | `CoordinatorSession::<Negotiating>::spawn` returns `SessionError::BackendUnavailable`; public bootstrap/session composition remains fail-closed. |

The backend-unavailable result is behavior of the common API, not a missing
macOS declaration. Plan 8b task 58 owns any further first-class availability
query or reporting shape. This inventory neither chooses nor authorizes the
separate macOS enablement decision.

## Non-consumer hooks

`session::__receiver_bootstrap_preinit` and
`session::__take_receiver_bootstrap` are `#[doc(hidden)]` implementation hooks
used by `receiver_main!`. Their signatures exist on every supported target;
the ELF preinitializer is deliberately a no-op off Linux. The crate-root
`__private_macos_*` functions are target-gated hidden entry points for
separately compiled deployer helper artifacts. They are outside the six
consumer modules, omitted from rendered documentation, unsafe to invoke except
under their exact process-entry contracts, and carry no consumer compatibility
promise.

The supported-target table and target-specific kernel authority limits remain
in the [repository README](../README.md#supported-targets). The normative
ownership properties are in sections 3 and 5 of the
[vNext specification](native-ipc-vnext-spec.md).
