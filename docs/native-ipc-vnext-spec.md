# Native IPC vNext normative specification

**Status:** proposed normative contract

**Target:** first post-`0.4.0` release satisfying every mandatory gate

**MSRV:** Rust 1.97

**Targets:** Linux GNU AMD64/Arm64, macOS Arm64, Windows AMD64/Arm64

This document defines what `native-ipc` must provide before it is used as the
shared-memory foundation for process-isolated VST3 execution. The library
remains application-neutral: VST3 is an acceptance consumer, not part of its
types, wire protocol, or public vocabulary.

The deliverable is one safe, opaque, platform-neutral native shared-memory API.
A caller can authenticate a peer, prepare an arbitrary mixed-direction group
of regions, transfer it in one transaction, and receive runtime mappings only
after the complete group commits.

This specification supersedes older documentation where it describes the
current fixed one- or two-region helpers as an already-public generic batch.

## 1. Requirement language and completion standard

**MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** are normative in
the RFC 2119 sense.

An implementation is complete only when code, public documentation, and tests
agree. A prose-only property is not a supported guarantee. A mock-only test is
not evidence of a native security guarantee.

## 2. Required outcome

The ordinary safe API MUST provide:

1. anonymous, zeroed native shared memory whose library-created views exclude
   execute and whose delegated authority is attenuated to the strongest
   supported kernel mechanism, subject only to the explicit Linux residual
   authority in section 8.2;
2. quiescent initialization before any capability escapes;
3. a consuming local-writer or peer-writer choice for each region;
4. opaque application-neutral region handles;
5. authenticated library-owned exact-child bootstrap;
6. a bounded heterogeneous batch of 1 through 16 regions;
7. arbitrary writer directions inside one batch;
8. one canonical manifest and READY/COMMIT barrier for the whole batch;
9. all-or-nothing runtime visibility at each endpoint;
10. checked allocation-free runtime copies and an explicit unsafe pointer
    escape hatch for application atomics and real-time layouts;
11. peer lifecycle observation, poisoning, termination, reaping, and cleanup;
12. identical public API and runtime semantics on every supported platform,
    with target-specific kernel authority limits stated explicitly;
13. bounded authenticated application-control framing for negotiation and
    non-real-time lifecycle messages; and
14. native adversarial tests for every claimed security property.

Normal users MUST NOT import an OS-specific module, branch on `target_os`, or
manipulate an fd, Mach port, address, Windows handle, socket path, or pipe name.

## 3. Scope boundary

### 3.1 What the library owns

- allocation, mapping, page rounding, pre-share growth, and cleanup;
- logical length versus mapped/capability length;
- native read/write authority, non-executable library views, and exact
  target-specific residual execute authority;
- peer authentication, session freshness, and absolute deadlines;
- capability framing, batching, provenance, READY, and COMMIT;
- limits for sessions, regions, batches, control frames, and native objects;
- safe byte-copy operations and narrowly documented unsafe access;
- authenticated bounded application-control framing without interpretation;
- peer exit observation and owned-child cleanup;
- bounded structured transport errors; and
- mock/fault-injection infrastructure and native conformance suites.

### 3.2 What applications own

- region meanings and application schemas;
- codecs, record kinds, flags, build identity, and compatibility negotiation;
- generations, sequences, rings, acknowledgements, and scheduling;
- audio, events, parameters, commands, status, or other layouts;
- synchronization and validation of all peer-written application data;
- payload/protocol/DSP fault interpretation, silence, restart, and state replay;
- sandbox, signing, and deployment policy; and
- integrity or confidentiality beyond native least authority.

### 3.3 Forbidden coupling

The public memory/transport layers MUST NOT contain VST3, audio, bus, sample,
event, parameter, plug-in, slot, ring, or fixed-four-region types.

The base native transfer manifest MUST NOT depend on `native-ipc-core` layout
roles, schema parsing, or acknowledgement types. `native-ipc-core` MAY remain
an optional application-layout adapter above active regions.

### 3.4 Required crate graph

The final Cargo dependency direction is acyclic; `A -> B` means package A
depends on package B:

```text
native-ipc -> native-ipc-core
native-ipc-testkit -> native-ipc
native-ipc-testkit -> native-ipc-core
```

The backend implementation moves into private modules of the published facade;
this avoids an impossible cross-crate private trait and lets the facade remain
publishable without depending on an unpublished path crate. No vNext
`native-ipc-platform` orchestration crate is published or re-exported. The old
0.4 package is documented as superseded and remains available from crates.io
and the `v0.4.0` source tag; published artifacts cannot be retroactively
removed. Raw interop remains feature-gated unsafe API.

## 4. Security model and honest claims

### 4.1 Attacker

The baseline security orientation is asymmetric: the library-owned spawning
coordinator is the trusted safe-Rust principal, and the spawned receiver may be
buggy or malicious. The receiver controls all bytes it may
write, message timing/order/fragmentation, capability delegation, descendants,
exit, and silence. It may race the trusted process. Authentication establishes
bootstrap identity; it never makes peer data trustworthy.

Receiver-side safe APIs remain memory-safe against a malformed coordinator, but
cannot prove that a malicious capability creator discarded hidden writable
aliases on Linux, macOS, or Windows. Symmetric distrust requires a separate
trusted broker that creates/attenuates objects for both endpoints and is outside
the baseline.

The kernel, the library build, and trusted-process safe Rust caller are trusted.
Incorrect use of an explicitly unsafe API is outside the safe-code guarantee.

### 4.2 Mandatory guarantees

For safe callers, a hostile peer MUST NOT cause:

- trusted-process undefined behavior or out-of-bounds access;
- unchecked slice construction from peer values;
- writable aliasing contrary to the documented authority model;
- use-after-free, double-close, double-unmap, or double-reap;
- executable mappings in the trusted process or reader write authority;
- stale, replayed, substituted, or foreign transactions becoming active;
- partial exposure of an uncommitted batch;
- hostile traffic extending an operation beyond its deadline; or
- resource leaks on covered failure paths.

Exactly one endpoint MUST have library-managed store authority per region. The
other endpoint MUST receive kernel-enforced read-only authority. The library
MUST NOT create an executable shared-memory view. macOS and Windows delegated
capabilities MUST exclude execute through kernel-enforced maximum rights. On
Linux, the direction-specific section 8.2 residual authority applies. It
includes peer RX aliases and, for receiver-writer setup, an unrelated
non-MDWE-tree delegate retaining then upgrading a pre-seal RW view. These
kernel limits MUST be documented and MUST NOT be described as kernel-enforced
object-level NX.

Here “endpoint” means the coordinator or receiver authority principal, not one
OS mapping or PID; an authorized receiver may duplicate/delegate only the same
bounded authority. The sole-writer proof is guaranteed to the trusted
coordinator under the asymmetric baseline above.

### 4.3 Claims the library MUST NOT make

The library does not provide payload integrity against the authorized writer,
confidentiality from an authorized reader, revocation after capability
delivery, confinement of a delivered capability to one PID, erasure of peer
copies, rollback of irreversible kernel transitions, or distributed crash
atomicity.

Native capabilities are delegatable. A malicious peer and its delegates are
one trust principal. Delegation MUST NOT increase delivered authority.

On Linux, delivered authority expressly includes the direction-specific limits
in section 8.2. MDWE is process authority, not memfd-object authority: it
constrains the spawned receiver and inheriting descendants, but does not travel
with an fd delegated outside that MDWE-inheriting process tree. Every such
delegate remains part of the same malicious receiver authority principal. No
stronger confinement or revocation is claimed.

“Sealed” means size/authority attenuation defined by the backend. It does not
mean immutable, encrypted, revocable, or safe from the authorized writer.

### 4.4 Meaning of atomic batch

Atomic means **API visibility atomicity**:

- no endpoint obtains an active runtime region before commit;
- successful commit returns the complete region set; and
- failure returns no active region from the transaction.

A process can die between protocol messages. Ambiguous terminal states poison
the session and require fresh resources. This is not rollback.

Native authority may already have reached the peer while safe runtime wrappers
remain pending. After any capability escapes, failure destroys trusted local
pending objects, poisons the session, and normally terminates the owned child;
it does not prove the peer never observed or delegated that pending authority.

## 5. Public type and ownership model

Exact names may change, but these ownership properties are normative.

### 5.1 Generic identities and limits

```rust
pub struct RegionId(u128);

pub enum WriterEndpoint { Coordinator, Receiver }

pub struct SessionLimits {
    pub max_regions_per_batch: u16,
    pub max_region_bytes: u64,
    pub max_batch_bytes: u64,
    pub max_active_regions: u32,
    pub max_active_bytes: u64,
    pub max_transactions: u64,
    pub max_bootstrap_payload_bytes: u32,
    pub max_control_payload_bytes: u32,
}
```

`RegionId` is caller-selected opaque metadata, not a schema or role enum. Zero
MUST be invalid. Duplicate IDs in a batch MUST fail. The library MUST also
mint an unguessable object incarnation so reusing an ID cannot authenticate an
older native object.

Incarnation is library-owned transcript freshness for a coordinator-created
object, not a portable kernel object identifier and not proof against a
malicious coordinator substituting another valid object. The receiver verifies
native authority, size, transaction, and ordinal; the baseline trusted
coordinator orientation supplies object-origin trust.

Limits MUST have finite secure defaults. Counts, logical sizes, page-rounded
sizes, totals, and frame lengths MUST be checked before allocation/import.
Active mappings remain charged to their originating session limits until the
mapping is dropped, even after removal from `ActiveRegionSet`. Starting a batch
that could exceed active/session totals fails before capability receipt.

### 5.2 Consuming region typestates

```text
PrivateRegion
  -> PreparedRegion<CoordinatorWriter> -> PendingBatch -> ActiveWriter
  -> PreparedRegion<ReceiverWriter>    -> PendingBatch -> ActiveReader
```

The peer receives complementary authority.

`PrivateRegion` MUST be uniquely owned, writable, anonymous, and non-`Clone`.
Only it may expose scoped initialization bytes. It MAY support fixed allocation
or bounded replacement growth before preparation.

Preparation MUST consume the private region. Once native preparation begins,
failure may not return a reusable private region because sealing/protection can
be irreversible. Failed inputs are consumed and destroyed.

Prepared and pending values MUST be non-`Clone`, non-`Copy`, and unable to
access runtime payload. Dropping them closes/unmaps all owned state.

Active readers/writers own stable mapping lifetimes. Safe code MUST NOT derive
writer authority from a reader or duplicate a sole writer.

`ActiveWriter` is non-`Clone`, `Send`, and `!Sync`; mutation requires exclusive
access. `ActiveReader` is non-`Clone`, `Send`, and `Sync`; concurrent trusted
threads may take independent hostile snapshots. Private/prepared/pending
values and unsplit session/control objects are `Send + !Sync`. Split control
sender/receiver objects, if provided, are `Send + !Sync` per direction.

### 5.3 Allocation and preparation API shape

```rust
let mut region = PrivateRegion::allocate(
    RegionOptions::fixed(logical_len).with_max_bytes(limit),
)?;
region.initialize(|bytes| initialize_layout(bytes))?;
let prepared = region.prepare(RegionSpec {
    id,
    writer: WriterEndpoint::Coordinator,
})?;
```

Allocation MUST reject zero length/overflow, be page-aligned and zeroed, and
create no executable library mapping. Logical length and mapped length remain
distinct. Page padding MUST be zero before transfer and inaccessible through
safe runtime APIs.

`RegionOptions` includes `GuardPolicy::{BestEffort, Require, Disable}`. Where
native placement permits reliable guard pages, inaccessible pages surround the
payload mapping. `Require` fails closed when unavailable; `BestEffort` reports
the installed result through region capabilities.

Growth exists only before preparation. Clearing is best-effort local clearing;
documentation MUST NOT imply erasure of kernel copies or peer mappings.

The initialization closure is scoped and non-escaping. Panic leaves ownership
valid and publishes nothing.

### 5.4 Runtime access

The safe baseline MUST offer equivalent checked operations:

```rust
impl ActiveReader {
    pub fn len(&self) -> usize;
    pub fn read_into(&self, offset: usize, dst: &mut [u8]) -> Result<(), AccessError>;
}

impl ActiveWriter {
    pub fn len(&self) -> usize;
    pub fn write_from(&mut self, offset: usize, src: &[u8]) -> Result<(), AccessError>;
    pub fn fill(&mut self, range: Range<usize>, value: u8) -> Result<(), AccessError>;
}
```

After activation/prefault, these MUST be checked, allocation-free, syscall-free,
lock-free, wait-free with respect to library primitives, non-logging, and
non-panicking for peer input.

The implementation MUST document and review the Rust memory-model boundary for
memory concurrently mutated by another process. Safe copies MUST use a defined
external-memory primitive (for example volatile byte operations or an audited
platform FFI copy boundary), never ordinary shared references whose validity
assumes no concurrent mutation. A read may be torn or internally inconsistent;
it returns owned hostile bytes and provides memory safety, not snapshot
integrity. Native tests supplement but do not replace this soundness argument.

Safe runtime APIs MUST NOT return persistent shared `&[u8]`, `&mut [u8]`, `&T`,
or `&mut T`. Validated aligned atomic helpers MAY be added.

Real-time users require direct addresses. An advanced feature MUST provide an
explicit unsafe escape equivalent to:

```rust
impl ActiveReader {
    unsafe fn as_ptr(&self) -> *const u8;
}

impl ActiveWriter {
    unsafe fn as_ptr(&self) -> *const u8;
    unsafe fn as_mut_ptr(&mut self) -> *mut u8;
}
```

Its contract MUST state bounds, alignment, initialization, lifetime, aliasing,
synchronization, atomic ordering, and peer-mutation obligations. The pointer
never transfers mapping ownership.

The library MUST provide an explicit off-thread `prefault`/`touch` operation
covering the requested logical range and returning a bounded result. Touching
reduces setup faults but cannot guarantee pages will never fault later unless
an optional native memory-locking policy succeeds. The real-time guarantee is
that the library's active access path contains no explicit syscall, not that
the kernel can never service a page fault.

### 5.5 Generic native handle

The typed region object is the generic native handle; its backend is opaque.
Raw fd/Mach-port/Windows-handle import/export MAY exist only behind an advanced
feature, MUST be unsafe and ownership-explicit, and is not the ordinary API.

There MUST be no fallback to regular files, globally named POSIX SHM, or System
V SHM.

## 6. Session and process lifecycle

### 6.1 Safe exact-child baseline

```rust
let parent: CoordinatorSession<Negotiating> =
    Session::spawn(command, SessionOptions { deadline, limits, .. })?;

// Inside the exact spawned helper:
let child: ReceiverSession<Negotiating> =
    Session::from_inherited_bootstrap(SessionOptions::default())?;
```

Spawn MUST use an already-resolved executable path and authenticate the exact
created process. The library MUST retain a race-resistant kernel lifecycle
handle where available.

`SessionOptions` MUST include an expected `ExecutableIdentityPolicy`. The
library opens/identifies the artifact before launch, prevents replacement where
the OS permits, binds the launched image back to that identity after spawn, and
optionally verifies an application-provided digest/signature. PID or pathname
text alone is insufficient. Identity mismatch terminates the child before
negotiation. Linux SHOULD execute the held artifact with `execveat`/equivalent;
macOS/Windows MUST compare stable file/image identity before and after spawn and
hold replacement-denying rights where available.

Existing-service attachment is not in the initial safe baseline. A later API
requires an authenticated invitation/rendezvous stronger than a PID.

Only the spawning coordinator initiates native region batches in the baseline.
`WriterEndpoint::{Coordinator, Receiver}` therefore has one stable meaning in
both processes rather than changing with the caller's perspective. The receiver
validates/imports offered objects but cannot initiate a competing transaction.
Application control frames remain duplex. A future symmetric-offer protocol is
a separate versioned feature, not an implicit extension of this state machine.

### 6.2 Session state and API

```text
Created -> Spawned -> Authenticated -> Negotiating -> Ready
Ready -> TransactionOpen -> Ready
Ready -> Closing -> Closed
any nonterminal state -> Poisoned -> Closed
```

Only one transaction may be open on a channel. Mutating control APIs require
exclusive access. Coordinator/receiver sessions and transactions are
`Send + !Sync`.

The platform-neutral API exposes peer diagnostics, exit observation, bounded
wait, explicit close, owned-child terminate/reap, session state, protocol
version, and negotiated limits.

`try_close(self)` returns `Result<Closed, CloseBlocked<Self>>` or an equivalent
recoverable shape when active leases remain; it never consumes/strands the live
control owner because mappings are outstanding. A separate close MAY consume
the session and all regions together. Explicit abort is the only operation
allowed to orphan mappings. Final close attempts all cleanup and returns the
first error plus bounded cleanup facts. Drop is idempotent, panic-safe, best
effort, and unsuitable for a real-time thread when it may block.

### 6.3 Library and application negotiation

After authentication and before region transfer, endpoints MUST complete a
versioned `HELLO -> ACCEPT|REJECT` exchange. Library HELLO binds protocol
version, supported features, local limits, target facts, atomic capabilities,
and session nonce. Effective numeric limits are the checked minima; zero,
unsupported required features, incompatible major versions, narrowing/overflow
to native `usize`, and values above field-specific hard maxima fail closed.
Only `max_regions_per_batch` has hard maximum 16; byte, active-object,
transaction, and control limits have separately documented maxima. Effective
limits and feature selection are bound into later transaction transcripts.

HELLO also carries one bounded opaque application payload so applications can
negotiate build/schema/target/features/capacities. The library bounds it before
allocation and never interprets it. Application code explicitly accepts or
rejects. Empty payloads are valid.

After both HELLOs, the coordinator's application decision MUST carry a fresh,
nonzero 128-bit decision challenge generated by the OS CSPRNG. A coordinator
`ACCEPT` carries the challenge and the receiver's later `ACCEPT` or `REJECT`
MUST echo it exactly. A coordinator `REJECT` is terminal and requires no
receiver decision. This ordering prevents a malicious receiver from prequeuing
a deterministic decision that will validate after seeing only the HELLOs: one
online attempt to guess the fresh value succeeds with probability at most
2^-128. Zero, wrong, replayed, substituted, or out-of-order challenges fail
closed and poison the live negotiation.

The challenge proves only successful decision causality. It is not peer
authentication, a session nonce, a receipt, a secret after delivery, or a
cryptographic MAC, and it grants no native or memory authority. The receiver's
application decision remains explicit after it observes the coordinator
`ACCEPT`. Challenge entropy and the complete decision exchange use the original
negotiation absolute deadline. Entropy failure, timeout, partial transmission,
or ambiguity after a decision begins fails closed and poisons the session; it
MUST NOT retry with a new challenge or a new deadline.

The typestate is `Session<Negotiating> -> Session<Ready>`; no transfer batch or
ordinary control message is permitted before both endpoints accept.

### 6.4 Authenticated application control channel

After negotiation, the session MUST carry bounded opaque duplex frames for
non-real-time lifecycle, request/response, offline work, fault, and heartbeat
messages. The library owns fixed-width framing, size limits, absolute deadlines,
short-I/O behavior, and session association but never interprets kind/payload.

The shape is equivalent to `send_control(kind, bytes, deadline)` and
`receive_control(deadline) -> ControlFrame`. A split sender/receiver MAY allow
full duplex, with exactly one serialized writer/reader per direction. Native
capability and application frame kinds are disjoint. Application frames cannot
interleave with an open transfer transaction. Oversize, malformed, stale, or
transaction-conflicting frames poison the session.

Control calls may allocate only within negotiated bounds and may block only to
their absolute deadline. They are forbidden on real-time threads.

### 6.5 Atomic and alignment capabilities

The library MUST expose `AtomicCapabilities` with lock-free cross-process
support and required alignment for at least 32-bit and 64-bit atomics, plus
page/cache-line alignment facts needed by application layouts. Required but
unsupported atomics reject negotiation before transfer. Claimed targets have
compile-time assertions and native publication/observation tests.

### 6.6 Active lifetime and close

Active regions retain an internal session resource lease but not permission to
open transactions or control the child. They MAY outlive the public `Session`
handle without dangling mappings. `Session::try_close` MUST return ownership of
the live session inside a bounded `ActiveLeases` outcome unless all active
regions are supplied/closed; it MUST not silently kill a peer still serving
live regions. An explicit consuming
`abort(self)` invalidates control, kills an owned child, and marks retained
regions orphaned/hostile, but cannot revoke their native mappings.

The session and all active regions share a local atomic liveness/poison flag.
`poll_peer` and bounded monitor APIs update it after kernel exit observation;
there is an unavoidable detection race and no promise of instantaneous
invalidation. Safe memory operations MAY check it without blocking and return
`PeerExited`, while real-time users may poll/swap generations off-thread and
use explicitly documented unchecked active access until quiescence.

### 6.7 Freshness and reconnect

Each session uses a fresh OS-CSPRNG 256-bit nonce. Transactions use monotonically
increasing nonzero IDs; exhaustion poisons the session and wrapping is forbidden.
Nonces/incarnations provide freshness and collision/replay separation; they are
not the sole authentication mechanism and are not assumed secret after spawn.

Reconnect creates a new process, nonce, channel, objects, incarnations, and
transaction sequence. No prior pending/active object may reactivate.

Peer exit prevents new transactions. Applications must stop using hostile-
writer regions; delivered native authority cannot be reliably revoked.

## 7. Arbitrary atomic transfer batch

### 7.1 Capacity and public shape

One transaction MUST support 1..=16 regions and any writer-direction mixture.
The API is keyed rather than a fixed tuple:

```rust
let mut batch = session.begin_batch(deadline)?;
batch.add(input)?;
batch.add(output)?;
batch.add(commands)?;
batch.add(status)?;
let active: ActiveRegionSet = batch.commit()?;

let input = active.take_writer(input_id)?;
let output = active.take_reader(output_id)?;
```

The receiver API is equivalent to:

```rust
let expected = ExpectedBatch::try_from_specs([
    ExpectedRegion {
        id: input_id,
        writer: WriterEndpoint::Coordinator,
        logical_len,
    },
    // ... the same coordinator-relative metadata on both endpoints
])?;
let pending = session.receive_batch(expected, deadline)?;
let active: ActiveRegionSet = pending.commit()?;
```

`ExpectedBatch` is fully constructed before capability receipt. The receiver
checks negotiated count and aggregate limits before allocating/mapping, then
checks exact IDs, complementary access, logical/mapped lengths, flags, object
identity, and capability ordinals before READY. Missing, unexpected, duplicate,
oversized, undersized, or wrong-access entries reject the whole transaction.
Rejection consumes pending objects, poisons after any capability escaped, and
returns no runtime set.

### 7.2 Transaction ownership

One transaction object owns every pending mapping, capability, remote-cleanup
record, manifest entry, and provenance fact. Callers MUST NOT assemble
independent pending tokens.

Pending transactions cannot access payload, clone, or commit twice. Rejection
closes every pending object and returns no partial `ActiveRegionSet`. Ambiguous
framing/remote state poisons the complete session.

### 7.3 Canonical application-neutral manifest

The manifest is manually encoded, fixed-width, bounded, versioned, and binds:

- magic, version, frame kind, flags, and exact frame length;
- random session nonce and kernel-authenticated endpoint identities;
- nonzero transaction ID, entry count, and total logical/mapped bytes;
- for each entry in canonical `RegionId` order:
  - region ID and library-minted object incarnation;
  - writer endpoint/complementary access;
  - logical and mapped/capability lengths;
  - capability ordinal and the library-view non-execute flag; and
- session-wide trusted platform authority facts, including Linux pre-exec MDWE
  and the direction-specific residual limitations;
- zero reserved bytes.

It MUST NOT contain pointers, `usize`, raw native handle values, `repr(Rust)`
enums, application schemas, or padding-dependent structures.

Capability order is bound to canonical entry order. Object identity, size,
access, and ordinal validation MUST reject reordered/substituted objects.

### 7.4 Transcript and visibility

```text
CAPABILITY(full canonical manifest + exact native capabilities)
[backend preparation subprotocol, when required]
READY(exact full-manifest transcript)
COMMIT(exact full-manifest transcript)
```

All capabilities are imported, permission/length checked, and matched against
the exact expected batch before READY. The coordinator exposes local runtime
only after exact READY and successful COMMIT transmission. The receiver exposes
runtime only after exact COMMIT.

A later `COMMITTED` response MAY improve diagnostics but does not remove crash
ambiguity. READY/COMMIT MUST cover the full manifest, not only an ID.

The backend preparation subprotocol is bounded and manifest-bound; it cannot
expose runtime mappings. It exists for kernels where final authority
attenuation depends on the peer first establishing its designated mapping.
Every preparation frame uses the same session/transaction provenance, and any
failure poisons the transaction before READY.

### 7.5 Provenance

Pending state is privately bound to the in-process session identity, wire nonce,
authenticated peer, transaction ID, full manifest, and native object set.
Safe code cannot mint or alter provenance.

Session-A state fails on session B even with identical visible metadata.
Transaction-1 state fails on transaction 2. Replayed READY/COMMIT fails.

### 7.6 Absolute deadlines

Every setup/transfer derives one monotonic absolute deadline for the complete
operation. Check it before/after every potentially blocking action and after
every rejected connection/frame/message. Continuous wrong-peer or malformed
traffic MUST NOT extend the deadline. Partial ambiguous transmission poisons
the session and is never retried as fresh.

Native I/O/waits MUST be nonblocking and pollable, use a kernel timeout, or be
cancellable with the remaining absolute duration; checking only after an
unbounded blocking call is nonconforming. Every loop recomputes remaining time.
If process creation itself cannot be safely cancelled, the documented hard
deadline begins immediately after successful spawn; a late/failed spawn result
is still owned and cleaned before return.

## 8. Native backend contract

### 8.1 Common

Each acquired resource enters RAII immediately. Backends never create an
executable shared-memory view and verify their complete backend-specific
authority state: Linux object type/fd mode/seals plus MDWE and characterization
probes, Mach entry and current/maximum VM rights, or Windows section
protection/duplicated access/view rights. They disable
inheritance except the intentional bootstrap endpoint, freeze size/authority,
preserve stable active addresses, hide padding, and fail rather than select a
weaker fallback.

### 8.2 Linux GNU AMD64/Arm64

Target baseline: Linux kernel 6.3+ and glibc 2.31+, verified before release.
Kernel 6.3 is required for `MFD_NOEXEC_SEAL` and irreversible MDWE. See the kernel's
[`MFD_NOEXEC_SEAL` design](https://www.kernel.org/doc/html/latest/userspace-api/mfd_noexec.html).

**Accepted kernel limit (2026-07-11):** native AMD64/Arm64 probes show that an
`MFD_NOEXEC_SEAL` object with `F_SEAL_EXEC` still permits executable VM views.
Irreversible `PR_SET_MDWE(PR_MDWE_REFUSE_EXEC_GAIN)` rejects an executable
upgrade of an existing writable view but still permits a separate shared RX
alias while the writable alias remains live. Therefore Linux cannot provide
object-level NX against a malicious delegated peer. The library MUST expose
this limit accurately, MUST NOT claim parity with Mach/Windows maximum execute
rights, and MUST retain every stronger protection below.

Before the initial authenticated receiver exec, the trusted library-owned
pre-exec path MUST install exactly `PR_MDWE_REFUSE_EXEC_GAIN` without
`PR_MDWE_NO_INHERIT`; failure MUST propagate through the trusted spawn/exec
error path, abort spawn, and clean up. Capability transfer MUST NOT begin unless
that path and exact-image exec succeed. Security relies on kernel inheritance
and irreversibility, not a receiver assertion. This protection prevents a
receiver from converting an existing non-executable mapping into an executable
mapping or creating one mapping that is simultaneously writable and
executable. It does not prevent dual RW/RX aliases of the same memfd and MUST
NOT be documented as doing so. Controlled native helpers MUST verify
`PR_GET_MDWE` after exec and in descendants.

The residual authority is direction-specific. A coordinator-writer capability
escapes only after future-write sealing, so the receiver principal and its
delegates can create RX aliases but cannot regain store authority. A
receiver-writer fd necessarily escapes before `F_SEAL_FUTURE_WRITE`; the
receiver may delegate it to an unrelated non-MDWE process, which may establish
an RW view before `IMPORTED` and later upgrade that retained view to executable.
That possible RWX view is part of the accepted receiver-principal authority and
does not create a second authority principal with store rights. The library
MUST document it, MUST keep the transfer window bounded by one absolute
deadline, and MUST complete future-write sealing immediately after the exact
manifest-bound import receipt.

Memory uses `memfd_create(MFD_CLOEXEC | MFD_NOEXEC_SEAL)`, checked `ftruncate`,
and verifies the implied `F_SEAL_EXEC` plus `F_SEAL_GROW | F_SEAL_SHRINK |
F_SEAL_FUTURE_WRITE | F_SEAL_SEAL` in a correct order. Reader capabilities are
descriptors whose verified seals prohibit new writable mappings; they need not
have an `O_RDONLY` open-file mode. Views use `PROT_READ` or
`PROT_READ | PROT_WRITE`, never `PROT_EXEC`. Unsupported flags/seals fail closed.

For peer-writer regions, temporary write-capable transfer MAY establish the
peer writer before future-write sealing. Both sides remain pending until the
seal is installed/reverified and the local side retains no writable mapping.
The exact per-entry order is:

1. initialize while private;
2. install/verify `F_SEAL_EXEC | F_SEAL_GROW | F_SEAL_SHRINK`;
3. permanently remove coordinator writable views for **receiver-writer entries
   only** (coordinator-writer mappings remain intentionally writable);
4. transfer the still-future-write-unsealed receiver-writer fd;
5. receiver creates its writer view and sends manifest-bound `IMPORTED`;
6. coordinator installs/verifies `F_SEAL_FUTURE_WRITE | F_SEAL_SEAL`;
7. coordinator sends manifest-bound `SEALED`, receiver re-reads all seals, then
   the complete batch proceeds through READY and COMMIT.

There is never a library-owned coordinator writable view for a receiver-writer
entry after its capability escapes. `IMPORTED`/`SEALED` are pending preparation,
not partial activation or replacements for the single batch READY/COMMIT.

Bootstrap MUST use an inherited anonymous `AF_UNIX SOCK_SEQPACKET` socket pair,
not a filesystem path. One bounded protocol frame occupies one packet. Only the
exact child endpoint is intentionally inherited. A future stream fallback needs
a separate specified/tested credential-and-rights association protocol.

Cached socket-pair `SO_PEERCRED` MUST NOT be used as post-exec child proof. The
child sends nonce-bound bootstrap/control packets with kernel-supplied
per-message credentials via `SO_PASSCRED`/`SCM_CREDENTIALS`; every packet is
checked against the exact expected sender PID/UID/GID for its direction. The
coordinator checks child-originated packets against the exact spawned PID and
retained pidfd; the receiver checks coordinator-originated packets against the
expected spawning coordinator identity. Tests MUST assert actual credentials
in both directions on the selected pre-spawn socketpair topology.

Every received packet requires exactly one `SCM_CREDENTIALS` record and, for a
capability packet, exactly one expected `SCM_RIGHTS` record with exact fd count.
Use `MSG_CMSG_CLOEXEC`, immediate RAII ownership, and reject packet/frame length
mismatch, truncation, malformed/extra ancillary data, wrong level/type,
`EINTR`, or EOF. Close every installed fd on every error.

Retain a `pidfd`, prevent PID-reuse confusion, and terminate/reap the exact
owned helper after ambiguous failure.

If path bootstrap temporarily remains during migration, create the directory
atomically as `0700` and check deadlines under continuous wrong-peer connects.
It is not the target design.

### 8.3 macOS Arm64

Intel macOS is unsupported and MUST fail compilation.

Use anonymous Mach VM and exact-length memory entries. Reader entries are
read-only; only the sole writer receives write-capable non-executable authority.
Downgrade local mapping permanently before peer-writer activation. Exclude
execute from current/maximum protection and prove upgrade rejection natively.

Never transfer task ports. Track/deallocate every right exactly once, including
rights installed by malformed messages.

Bootstrap uses an injected private Mach port, fresh nonce, and full audit
trailer. Validate message ID, complex bit, size, descriptor count/type/
disposition, trailer, audit token, and exact spawned PID. Parent owns helper
termination/reaping and port cleanup.

The internal control abstraction MUST be replaceable by a signed XPC adapter
without changing public session/region APIs. `PeerIdentityPolicy` includes the
expected resolved executable identity and an optional code-signing requirement;
when configured and available, validation fails closed. Direct private spawn is
the baseline and registers no service. The library itself never registers a
global Mach service.

A conforming public XPC adapter MUST connect to a preinstalled, signed,
`launchd`-advertised private service; spawning a broker from the client merely
recurses into the same pre-bootstrap lifecycle problem and is not conforming.
Before any spawn effect, client and service MUST complete an
authentication-only nonce handshake, derive dynamic code identity from the
received messages, and check it against installed requirements. The same-user
nonprivileged service MUST install an opaque non-PID lifecycle entry before the
helper runs, serialize signal selection with reap-and-tombstone, accept no
numeric PID as wire authority, reject helper audit-token PID-version changes,
and never transfer a task port. It MUST additionally use an OS-enforced exact
containment mechanism that survives service crash and cannot be escaped by the
helper. No documented public macOS primitive satisfying that last condition is
currently known, so this signed-XPC crash-surviving adapter architecture
remains unimplemented. Public macOS sessions are enabled (2026-07-16) over the
simpler audit-token-authenticated direct-spawn baseline, which does not claim
service-crash-surviving containment. The analysis and native evidence gate are
specified in [`macos-supervisor-boundary.md`](macos-supervisor-boundary.md).

### 8.4 Windows AMD64/Arm64

Use unnamed non-executable paging-file sections with explicit private security.
Disable inheritance; spawn exact child suspended; assign kill-on-close Job
before resume; duplicate exact required mapping rights; never use
`DUPLICATE_SAME_ACCESS`; validate section type/length/access; and ledger every
remote duplicate until the transaction is unambiguous. The remote ledger is
diagnostic/containment state, not authority to close an untrusted numeric handle:
on ambiguous failure terminate the owned Job/process and let kernel teardown
release remote handles. Never remotely close a numeric value after child resume.

The pipe is local-only, one-instance (`FILE_FLAG_FIRST_PIPE_INSTANCE`), random,
protected by an explicit minimal logon-SID DACL, and uses
`PIPE_REJECT_REMOTE_CLIENTS`. Its high-entropy name is routing metadata, not an
authentication secret. Endpoint PID APIs authenticate the exact child; wrong
clients are disconnected/retried only within the original absolute deadline.

Handle partial pipe I/O, `ERROR_MORE_DATA`, cancellation, breakage, exit, and
absolute deadlines. Numeric handles are not identity: object type, access,
size, ordinal, and provenance must match.

Windows Arm64 is runtime-supported only after native conformance execution;
cross-compilation is insufficient.

## 9. Errors, poisoning, and cleanup

Errors are bounded records containing operation, transaction state, portable
reason, optional native code, poison status, peer exit/termination, and cleanup
outcome. They retain no unbounded peer string/payload.

Poison after malformed/stale/foreign frames, partial capability transfer,
transaction timeout, mid-transaction peer exit, native mismatch after receipt,
READY/COMMIT failure, or ID exhaustion. Pure local validation before anything
escapes MAY leave the session idle.

Every successful acquisition immediately registers its inverse. Cover failure
during allocation, resize, mapping, protection, seal, channel creation, spawn,
auth, duplicate, send, receive, import, validation, READY, COMMIT, close, kill,
and wait. Cleanup continues after cleanup errors; Drop never panics.

With functioning cleanup primitives, forward/acquisition failure MUST restore
the exact baseline. Safely retryable cleanup interruption is retried only while
identity remains unambiguous and within deadline. If the kernel reports an
ambiguous/non-retryable cleanup failure, continue other cleanup, avoid a retry
that could target a reused resource, report the exact incomplete ledger, and do
not claim baseline restoration.

Owned-child mode launches the Linux/macOS child in a fresh process group/session,
performs bounded group termination for ordinary descendants, and reaps the exact
direct child. Windows Job containment owns its process tree. The baseline cannot
promise cleanup of malicious Unix descendants that escape the group or receive
delegated authority; optional cgroup/sandbox containment may strengthen this.
A bounded termination/reap attempt may still be defeated by an uninterruptible
kernel wait; that case retains cleanup ownership and reports exact incomplete
ledger facts rather than claiming successful bounded reap.
A future external-peer mode never kills a process it does not own.

## 10. Real-time contract

Setup, mapping, transfer, monitoring, and destruction are not real-time.

After activation and explicit prefault/touch, bounded runtime memory operations
perform no allocation/free, syscall/IPC, lock/wait/yield, logging/formatting,
panic, hidden retry, or background-progress dependency. Work is bounded by the
caller byte count. Peer death cannot make memory access block. Replacement and
cleanup occur off-thread with fresh resources.

Instrumentation and benchmarks MUST prove these negative properties. The
library does not prescribe an audio pipeline.

## 11. Generic four-region acceptance profile

This is an acceptance example, not library API:

| Example meaning | Writer endpoint | Coordinator result |
| --- | --- | --- |
| audio/event input | coordinator | `ActiveWriter` |
| audio/event output | receiver | `ActiveReader` |
| command | coordinator | `ActiveWriter` |
| status | receiver | `ActiveReader` |

The profile passes only when all four differently sized regions activate in
one transaction; peer authority is complementary; none is visible early; one
READY/COMMIT covers all; injected failure at first/middle/final entry exposes
none; every reader rejects native writes, macOS/Windows reject execute, and
Linux denies permission upgrades inside the MDWE-inheriting tree while
positively characterizing the complete direction-specific section 8.2
residual; runtime access has no
allocation/syscall/wait; and peer crash cannot block access/monitor cleanup.

The library and fixture contain no VST3 symbol or plug-in ABI structure.

## 12. Mandatory verification matrix

### 12.1 Type/API and portable core

Compile-fail tests prove private reuse after preparation, pending payload
access, reader mutation, writer duplication, double commit, concurrent channel
transactions, provenance construction, fallback on unsupported targets, and
intended `Send`/`Sync` traits.

Miri covers portable unsafe/typestate code. Property tests cover checked
arithmetic at zero, page boundaries, configured maxima, and near integer
limits. Fuzzers cover every parser without panic/unbounded allocation.

### 12.2 Batch/replay corpus

Test 1, 2, 4, 16, and rejected 17-region batches; all-local, all-peer, and
mixed directions. Across sessions A/B and transactions 1/2 test capability,
pending, READY, and COMMIT substitution; stale/future/duplicate transaction
IDs; zero transaction ID and exhaustion; zero/duplicate region IDs; a safe-API
object from session A substituted into B; reordered/omitted/duplicated/excess
entries; every manifest field/reserved byte;
wrong length/access/ordinal/incarnation/peer/nonce/version/count/total; and
first/middle/final failure with no active object.

Cover every fixed-frame truncation point and deterministic byte mutations.
Mutate/replay `IMPORTED`/`SEALED` and fail every Linux peer-writer preparation
substep. Verify no runtime object escapes and future writable mappings fail.

### 12.3 Negotiation and control corpus

Test HELLO version incompatibility, unknown required features, zero/oversized
limits, effective-minimum calculation, integer narrowing, feature downgrade,
nonce/limit transcript binding, application accept/reject, and batch-before-
accept rejection. Test opaque control kinds/payloads, maximum and maximum+1
lengths, duplex ordering, short I/O, timeout, EOF, malformed frames, stale
session data, control-during-transaction rejection, and bounded allocation.

### 12.4 Authentication/timing corpus

Test wrong process first, continuous wrong traffic through deadline, child exit
at every state, PID reuse attempts, parallel sessions, inherited-capability
inventory, parent drop at every state, silence/junk/fragmentation/reject storms,
socketpair per-message credential identity, and reconnect with zero stale
acceptance. Test `close` with active leases, explicit abort, active mappings
outliving the public session handle, liveness detection races, and quota release
only when active mappings drop.

### 12.5 Native permission/framing corpus

For every platform/direction, subprocess tests prove reader read, reader store
failure, designated writer success,
opposite endpoint denial, post-prepare resize denial, wrong object rejection,
zero padding, safe padding inaccessibility, guard-page faults when required,
and accurate best-effort guard capability reporting.

Linux additionally tests each missing seal and `SCM_RIGHTS` with 0/1/2/N fds,
multiple messages, wrong level/type, invalid cmsg lengths/alignment,
`MSG_TRUNC`, `MSG_CTRUNC`, partial frame, and fd baseline. Attempt resize and
new writable mappings between every peer-writer preparation state; assert size
is frozen before escape and no coordinator writable view exists for a
receiver-writer entry after transfer.
Linux also proves inherited MDWE, denial of RW-to-executable upgrades and
single-view RWX mappings within the MDWE-inheriting process tree, and the
documented success of a separate RX alias. For receiver-writer entries it also
proves that an unrelated non-MDWE delegate can retain a pre-seal RW view and
later upgrade it. Positive residual-authority probes MUST run only in
disposable helpers and MUST NOT make a production payload executable.
Native failure tests MUST prove that injected or real `PR_SET_MDWE` failure
prevents exec and capability transfer and restores fd/child/resource baselines;
the exact spawned image observes exactly `PR_MDWE_REFUSE_EXEC_GAIN`; fork and
exec descendants retain it; clearing MDWE or adding `PR_MDWE_NO_INHERIT` fails;
and no receiver-supplied MDWE claim can authorize capability transfer.

macOS additionally tests every header/descriptor/trailer size, audit token,
complex bit, count/type/disposition, extra installed rights, and port baseline.

Windows additionally tests wrong/stale objects, exact rights, partial messages,
`ERROR_MORE_DATA`, cancellation, Job teardown, and handle baseline.

### 12.6 Failure injection and leaks

Route native operations through a test-only fault boundary. Fail the Nth call
for every N across success paths, including cleanup. Forward failures with
functioning cleanup MUST restore baseline fds/maps/filesystem/pidfds/children
on Linux, VM/ports/children on macOS, and handles/views/pipes/Jobs/process trees
on Windows. Injected terminal cleanup failures instead assert continued cleanup,
no unsafe ambiguous retry, and an exact incomplete-ledger result; they cannot
require the kernel resource whose close was forced to fail to reach baseline.

Test panic unwind, drop-order permutations, and concurrent sessions. Repeat
normal close, crash, timeout, forward failures, and cleanup failures with a
functioning backstop for at least 10,000 cycles in stress/scheduled CI. Run
terminal-cleanup-failure cases against simulated handles or bounded individual
native tests; exclude intentionally unclosed real resources from leak-cycle
claims. No monotonic growth is acceptable in cases that require baseline.

### 12.7 Real-time negative tests

Allocator count is zero; deliberate syscall tracing is zero; lock/wait
instrumentation is zero; prefault reports touched coverage and observed faults
without promising permanent residency; cost is bounded; peer death does not
block; replacement occurs off-thread.

### 12.8 Release jobs

The exact release commit and packaged crates pass native execution on all five
targets, Rust 1.97/current stable, fmt, strict Clippy, all-feature/all-target
tests, no-default checks, warning-free rustdoc, Miri, fuzz/property smoke,
hostile-helper/fault suites, and repeated leak stress.

Cross-compilation proves buildability only. Every normative guarantee maps to
at least one positive and one negative test in a checked-in traceability table.
An independent adversarial review audits the exact release commit.

## 13. Performance and diagnostics

Benchmark allocation, preparation, mapping, batch transfer, commit, close, and
active access separately. Report p50/p95/p99/p99.9 where meaningful with
platform, architecture, region count/bytes, and profile. Retain raw CI artifacts
and derive thresholds from named-machine baselines.

Diagnostics are bounded, off-thread, and never expose reusable secrets or raw
capability values.

## 14. Migration from 0.4.0

This is an intentional breaking pre-1.0 correction.

Preserve accurate concepts: region options/page rounding, pre-share growth,
local clearing semantics, native capability reporting, optional checked core
layouts/codecs, target matrix, and Rust 1.97.

Replace/deprecate ordinary safe `NativeShareRequest::into_platform_parts`,
OS-specific orchestration, Linux single-region transactions, macOS/Windows
fixed tuples, caller-composable pending tokens, and application schema/layout
fields in the base native manifest.

Rename `PermissionPlan::executable()` to
`PermissionPlan::library_view_executable()`. The result describes mappings
created by the library, not every alias a malicious delegated-capability holder
can create under the target-specific authority contract.

Publish migration examples for 1, 2, 4, and 16 regions, mixed directions,
bootstrap, exact receive validation, poison handling, and explicit close.
Compatibility features MUST NOT weaken new guarantees or appear in vNext
conformance examples.

## 15. Optional hardening and non-goals

Not baseline unless claimed: `mlock`, dump exclusion, huge pages, NUMA,
seccomp/App Sandbox/AppContainer, cgroups and containment beyond the mandatory
fresh Unix process group, arbitrary services/brokers, encryption/MAC,
crash-resilient application protocols, telemetry, and raw-handle
interoperability.

Optional features fail explicitly when unavailable and never weaken default
authority, authentication, deadlines, or cleanup.

## 16. Definition of done

vNext is done only when:

1. allocation through batch activation/cleanup is platform-neutral;
2. the generic four-region profile passes without application types;
3. every native target executes conformance tests;
4. every MUST has positive and negative traceability tests;
5. fault/resource-cycle gates return to baseline;
6. real-time negative properties are instrumented and pass;
7. docs accurately limit sealing, integrity, revocation, atomicity, and
   platform execute-authority claims;
8. exact-release adversarial review has no unresolved critical/high issue;
9. medium findings are fixed or explicitly accepted with rationale; and
10. packaged crates are retested before publication.

Until all ten hold, describe the library as experimental foundation work, not
as a complete secure VST3 isolation transport.
