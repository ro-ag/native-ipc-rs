# Consolidated meta-review

- **Date:** 2026-07-10
- **Repository revision reviewed:** `c370712`
- **Scope:** Nine reports in `docs/review/`, checked against the current Rust
  sources, tests, documentation, and CI configuration
- **Purpose:** Review the reviews, remove duplicates and false positives, and
  produce one prioritized set of accepted findings

## Verdict

The reports correctly recognize a careful foundation with no demonstrated
safe-code memory-safety vulnerability in the code that is currently usable.
They also identify one concrete protocol-configuration defect and several
soundness boundaries that must be closed before the unfinished cross-process
transport becomes usable.

The most important current finding is acknowledgement routing: exact per-slot
reuse cannot make progress when multiple ring slots share one monotonic
acknowledgement cell. The API accepts that configuration and does not document
the required one-cell-per-slot subsequences.

The remaining high-priority items are integration blockers, not present
exploits: there is no audited mapping-to-atomic bridge, mapping permission is an
unsafe caller assertion rather than a platform witness, and the documented
snapshot recheck is not payload integrity against a writer that mutates bytes
without changing its sequence.

Severity in this document means:

- **P1:** resolve before the next cross-process transport slice builds on it;
- **P2:** real design, verification, or documentation debt;
- **P3:** useful cleanup that does not block the next slice.

## Review-set quality

The nine reports must not be treated as nine independent votes.

| Report | Assessment |
| --- | --- |
| Claude Fable 5 | High-value deep pass. It uniquely explains the reader-side fence requirement and clearly demonstrates the acknowledgement topology failure. Its `WrongSlot` and null-address deallocation findings are rejected below. |
| Claude Sonnet 4.5 | High-value pass on the unsafe integration boundary. Several P1 labels describe future misuse after an integration layer exists, rather than current safe-code vulnerabilities. |
| Composer | Useful concise inventory, but closely overlaps Grok in structure, wording, and findings. It adds little independent evidence. |
| Gemini 3.1 Pro | Broad but imprecise. It treats a missing byte-to-atomic cast as though the repository already performs that cast, and its links are absolute `file://` paths. |
| Gemini 3.5 Flash | Near-duplicate of Gemini 3.1 Pro with mostly editorial differences. It should not increase confidence by repetition. |
| GLM 5.2 | Detailed and useful for coverage gaps. Its concern about the relaxed `payload_len` load is technically incorrect under the existing Release/Acquire publication edge. |
| Grok 4.5 | Useful concise inventory, but substantially overlaps Composer and does not find the acknowledgement topology defect. |
| Kimi K2 | Not reliable for defect discovery. The report claims no vulnerabilities and awards perfect security, code, documentation, and testing scores while also acknowledging absent platform transports and integration tests. |
| Opus 4.8 | Strongest prior synthesis. It correctly rejects the relaxed-load and fixed-slice panic claims, calibrates conditional risks, and includes the acknowledgement topology defect. It does not fully develop the reader-side fence issue. |

## Accepted findings

### [P1] Exact acknowledgements require a per-slot route, but the layout accepts shared cells

Locations:

- [`slot.rs:182`](../../crates/native-ipc-core/src/slot.rs#L182)
- [`slot.rs:433`](../../crates/native-ipc-core/src/slot.rs#L433)
- [`layout.rs:67`](../../crates/native-ipc-core/src/layout.rs#L67)
- [`architecture.md:66`](../architecture.md#L66)

`WriterSlot::prepare_publish` requires the acknowledgement sequence to equal
that slot's prior publication exactly. `AcknowledgementWriter` only permits a
cell to move forward. With two slots sharing one cell, acknowledgements advance
from sequence 1 to 2; slot 0 then requires 1 for reuse and receives 2, which is
rejected as future. The ring wedges after its first rotation.

This is a current logic/configuration defect: `RegionSpec` permits arbitrary
slot and acknowledgement counts, bindings do not pair a slot with a cell, and
the routing requirement is undocumented.

Required resolution:

1. Model the acknowledgement route as `(owner role, target role, slot index)`.
2. Require a distinct monotonic sequence cell for every slot subsequence, or
   design a different acknowledgement representation that can acknowledge the
   complete ring without losing exactness.
3. Validate the topology when composing regions.
4. Add a two-slot test covering at least two complete rotations.

### [P1] The core-to-platform binding boundary is missing

Locations:

- [`layout.rs:381`](../../crates/native-ipc-core/src/layout.rs#L381)
- [`slot.rs:169`](../../crates/native-ipc-core/src/slot.rs#L169)
- [`slot.rs:623`](../../crates/native-ipc-core/src/slot.rs#L623)
- [`native-ipc/src/lib.rs`](../../crates/native-ipc/src/lib.rs)

The layout returns checked byte ranges, while slot APIs require references to
aligned `SlotMetadata` and `AcknowledgementCell` records. No workspace API
performs that conversion. An embedder would need to repeat the provenance,
alignment, lifetime, initialization, aliasing, and permission proof.

The byte initializer and the `#[repr(C)]` atomic record also define field
offsets independently. Existing assertions cover only size and alignment.

Required resolution before exposing runtime mappings:

1. Add `offset_of!` assertions for every accessed atomic field.
2. Centralize record construction/binding in one audited integration layer.
3. Make that layer own the mapping lifetime and prevent duplicate writer binds.
4. Add a core-to-platform integration test that initializes, validates, binds,
   publishes, observes, rechecks, and acknowledges one mapping.

### [P1] Mapping direction needs a platform-minted witness

Locations:

- [`layout.rs:252`](../../crates/native-ipc-core/src/layout.rs#L252)
- [`layout.rs:285`](../../crates/native-ipc-core/src/layout.rs#L285)
- [`layout.rs:400`](../../crates/native-ipc-core/src/layout.rs#L400)

`ValidationExpectations.permissions` is a plain caller-provided enum. The
unsafe contract requires it to describe the native mapping truthfully, but the
platform crate does not produce a witness that core consumes. This is not a
safe-code escalation today: lying already violates an unsafe precondition, and
the OS still enforces its actual mapping rights. It is nevertheless the wrong
boundary for the future safe facade.

Required resolution: platform mapping typestates should mint non-forgeable
read-only/read-write witnesses, and the audited bridge should consume those
witnesses when creating reader or writer bindings.

### [P1] Snapshot semantics and memory ordering must be decided before payload copies exist

Locations:

- [`slot.rs:267`](../../crates/native-ipc-core/src/slot.rs#L267)
- [`slot.rs:293`](../../crates/native-ipc-core/src/slot.rs#L293)
- [`threat-model.md:48`](../threat-model.md#L48)

The current repository exposes no runtime payload-copy API, so there is no
present torn-copy implementation to exploit. The documented design is still
stronger than the metadata API:

- rechecking generation and sequence cannot detect a writer that changes
  payload bytes while leaving the sequence unchanged;
- an Acquire load at the end of a future copy does not by itself keep earlier
  payload reads from moving after that load on weakly ordered hardware;
- `payload_len` is not included in the recheck observation.

Before adding payload access, choose and document the contract. If arbitrary
writer mutation is in scope, use an odd/even seqlock state, integrity tag, or
another mechanism that detects in-progress and same-sequence mutation. The
copy path also needs a fence or equivalent ordering primitive before its final
metadata loads and should recheck the observed length.

The existing relaxed `payload_len` load in `observe` is not itself a bug. The
writer's relaxed length store occurs before its Release sequence store, and the
reader performs the length load after the matching Acquire sequence load.

### [P1] Every byte in a peer-writable shared record needs an explicit mutation model

Locations:

- [`slot.rs:24`](../../crates/native-ipc-core/src/slot.rs#L24)
- [`slot.rs:65`](../../crates/native-ipc-core/src/slot.rs#L65)

`SlotMetadata` and `AcknowledgementCell` contain atomic fields plus plain
reserved bytes. Legitimate code initializes reserved bytes before transfer and
never changes them, so the current single-process tests have no race. A hostile
remote writer can nevertheless modify any writable byte while the reader holds
`&SlotMetadata` or `&AcknowledgementCell`. Plain fields behind a shared
reference do not express that external mutation model.

Before cross-process binding, either make all peer-writable bytes interior
mutable/atomic or make the bridge prove and enforce that reserved bytes cannot
be changed for the lifetime of the reference. The former is easier to audit.

### [P2] macOS exposes page-rounded slack beyond the logical length

Locations:

- [`macos.rs:122`](https://github.com/ro-ag/native-ipc-rs/blob/v0.4.0/crates/native-ipc-platform/src/macos.rs#L122)
- [`macos.rs:157`](https://github.com/ro-ag/native-ipc-rs/blob/v0.4.0/crates/native-ipc-platform/src/macos.rs#L157)

Mach allocation and memory entries cover the page-rounded `mapped_len`, while
the typestate exposes a smaller logical `len`. The slack is zero-initialized,
but the peer capability still covers it. This conflicts with the architecture
statement that mappings cover no more than the negotiated size.

Resolve this by negotiating page-rounded region sizes as the actual capability
size and validating the padding, or by proving that a narrower memory entry is
enforceable on supported macOS versions.

### [P2] Acknowledgement roles are not validated as connection topology

Locations:

- [`layout.rs:400`](../../crates/native-ipc-core/src/layout.rs#L400)
- [`layout.rs:454`](../../crates/native-ipc-core/src/layout.rs#L454)

Binding methods accept arbitrary nonzero owner and target roles. They do not
prove that both roles exist in the region set, are owned by opposite endpoints,
or correspond to the selected acknowledgement cell. Runtime identity checks
fail closed for accidental mismatches, but topology errors should be rejected
when bindings are minted.

This belongs in the same region-composition API that fixes the per-slot route
problem.

### [P2] Verification does not yet match the unsafe/concurrent domain

Locations:

- [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml)
- [`native-ipc-testkit/src/lib.rs`](../../crates/native-ipc-testkit/src/lib.rs)

The existing CI baseline is strong: pinned actions, minimal permissions,
strict Clippy, warning-free docs, locked builds, three OSes, native macOS
permission probes, and dependency policy. The accepted gaps are:

- no Miri job for core unsafe contracts;
- no Loom or equivalent model for publication/acknowledgement interleavings;
- no fuzz target for envelope and layout hostile bytes;
- no core-to-platform or cross-process integration test;
- no multi-slot acknowledgement-rotation test;
- no `cargo test --no-default-features` job;
- README asks for `git diff --check`, but CI does not run it; and
- testkit's public description is broader than its two codec helpers.

Linux and Windows jobs currently verify compilation and explicit fail-closed
status, not transport parity. The project documentation already says those
backends are incomplete, so this is a coverage limitation rather than a false
implementation claim.

## Partially accepted observations

These are useful constraints but not independent current defects.

- **Duplicate writer binding:** possible only through unsafe APIs that already
  require uniqueness. The future safe bridge should consume a unique mapping
  token so the obligation cannot leak to embedders.
- **Hand-transcribed Mach FFI:** a legitimate maintenance risk, partially
  mitigated by scalar/constant tests. An SDK cross-check is worthwhile as the
  FFI surface grows.
- **Thin facade:** intentional for the first foundation slice. It becomes a
  problem only if the public crate remains a re-export after runtime binding
  and session APIs are added.
- **Idempotent acknowledgement:** accepting the same sequence twice is safe
  and can support retransmission. Document whether acknowledgements are
  idempotent; do not change behavior without deciding that protocol contract.
- **Version/changelog/docs.rs metadata:** release-process cleanup, not
  correctness. Cut a dated changelog entry and verify links when publishing.
- **Exact minor-version matching:** safe and fail-closed, but the word
  "additive" in `VERSION_MINOR` documentation is misleading until a compatible
  minor acceptance rule exists.

## Rejected or overstated claims

### Relaxed `payload_len` load is an ordering bug

Rejected. The Release store of `published_sequence` follows the relaxed length
store, and the reader loads length after acquiring that exact sequence. The
synchronizes-with edge orders the length correctly for a conforming writer.
Same-sequence mutation is the separate snapshot-integrity issue above.

### Fixed-range codec helpers expose a hostile-input panic

Rejected. `decode_envelope` receives an exact 72-byte subslice only after the
outer length check. The internal conversions use fixed offsets within that
slice. Their `expect` calls could panic only after an internal invariant is
broken by a code change, not from current hostile input.

### `WrongSlot { expected, actual }` fields are reversed

Rejected. The sequence determines the expected ring slot; the binding supplies
the actual slot being used. The current field assignment follows that model and
matches the function's comparison.

### `align_up` mishandles caller-provided non-power-of-two alignment

Rejected as a current issue. `align_up` is private and every call passes the
constant 64, which is a power of two. A debug assertion could document the
invariant but no public input reaches it.

### `RegionLayout::writer()` is a hostile-input panic path

Rejected. `RegionLayout` is constructed only by checked calculation with a
known endpoint. Hostile decoded headers produce `ValidatedRegionLayout`, not
`RegionLayout`, and do not reach this accessor.

### Null-address cleanup deallocates memory that was not allocated

Rejected. If Mach allocation reports success with address zero, that exact
range is the allocation being rejected by Rust's `NonNull` requirement.
Deallocating it is the correct cleanup operation.

### Encoder output must obey local decoder `Limits`

Rejected as a defect. Decoder limits are local resource policy. An encoder may
need negotiated peer limits for interoperability, but applying the local
decoder's policy is not inherently correct.

### Perfect scores and "no vulnerabilities"

Rejected as unsupported. The Kimi report does not engage with the missing
bridge, acknowledgement topology, snapshot semantics, or absent integration
tests. Its perfect scores conflict with its own statement that the repository
is not production-ready.

## Canonical priority order

1. Fix and test acknowledgement cell-to-slot routing.
2. Decide the hostile-writer snapshot contract; align documentation, ordering,
   length rechecks, and integrity mechanism with that decision.
3. Make every peer-writable shared-record byte compatible with external
   mutation.
4. Build the core-to-platform bridge with field-offset assertions, unique
   ownership, and platform-minted permission witnesses.
5. Make page-rounded capability sizes part of the negotiated layout contract.
6. Add Miri, concurrency modeling, fuzzing, and real cross-process fixtures.
7. Address low-risk API and release-documentation cleanup before 0.1.0 is
   published.

## Open design decisions

- Is same-sequence payload mutation by the sole writer within the supported
  threat model, or is the writer required to follow the publication protocol?
- Is the acknowledgement representation permanently one cell per ring slot,
  or should it become a bounded per-slot sequence array owned by a control
  region?
- Which crate owns the safe integration boundary: the facade or platform?
- Does the MSRV intentionally track the newest stable Rust release?
