# Architecture

## Boundaries

`native-ipc-core` treats every byte originating across a process boundary as
hostile. It owns protocol-neutral encoding, resource limits, region arithmetic,
atomic publication state, and the facts needed to bind capabilities. It knows
nothing about native handles or application message meanings.

`native-ipc-platform` turns OS objects into least-authority mapping witnesses.
The negotiated capability size includes page rounding; bytes outside the
logical layout are zeroed and validated. Native code never creates executable
shared-memory views and fails closed on weaker-than-documented rights. macOS
and Windows exclude execute from maximum rights. Linux combines noexec memfds,
seals, and inherited irreversible MDWE, while explicitly retaining the kernel's
direction-specific limits: peer RX aliases and a receiver-writer fd delegate
outside the MDWE tree retaining then upgrading a pre-seal RW view.

Core owns the audited conversion from checked ranges and consumed platform
witnesses to atomic slot and acknowledgement capabilities.

## Wire envelope

Every message starts with a 72-byte, manually encoded little-endian envelope:

| Offset | Width | Field |
| ---: | ---: | --- |
| 0 | 4 | magic |
| 4 | 2 | major version |
| 6 | 2 | minor version |
| 8 | 4 | numeric kind |
| 12 | 4 | numeric flags |
| 16 | 4 | payload length |
| 20 | 4 | envelope length |
| 24 | 8 | generation |
| 32 | 8 | sequence |
| 40 | 32 | schema identity |

The generic layer validates the exact schema, nonzero identities, canonical
complete length, and message/payload limits before invoking a protocol decoder.
A protocol decoder must additionally validate its kind/flags, record count,
aggregate allocation, and every relative offset/length before constructing an
owned message.

## Independent regions

Each caller-defined numeric role gets a separate mapping with one designated
writer endpoint. A 128-byte immutable header is followed by zero or more
64-byte acknowledgement cells and fixed-stride slots. All arithmetic uses
checked addition/multiplication and all concurrently accessed records are
64-byte aligned.

Validation copies immutable header facts into owned metadata, checks zero
capability padding, and returns numeric ranges without retaining a slice.
Permission is represented by unsafe platform witness implementations, not a
caller-provided enum. The bridge consumes the witness, owns its lifetime, and
checks size, alignment, initialization, generation, and route identity.

## Publication and reuse

Sequence zero means unpublished. For sequence `S` and `N` slots, the only legal
slot is `(S - 1) mod N`. First publication in slot `i` is `i + 1`; later reuse
is exactly the prior sequence plus `N`. Overflow is terminal.

The sole writer mutates opaque payload bytes through a native mapping-specific
mechanism, stores payload length, and Release-publishes the sequence. The reader
Acquire-loads the sequence, validates generation and length, copies the payload
into owned storage, fences, then rechecks generation, sequence, and length.
This detects metadata changes only. Same-sequence malicious mutation can yield
a torn or inconsistent copy, which must always be parsed as hostile input.

Before reuse, a writer must observe the cell uniquely routed to that slot from
an opposite-endpoint region. Owner, target, slot, cell, generation, and prior
sequence must be exact; greater values remain rejected as future. Equal
re-acknowledgement is intentionally idempotent.

## Native policy

No OS-portable primitive provides sealed, least-authority anonymous shared
memory, so every backend implements the same capability policy with its own
kernel's native mechanism:

- macOS uses explicit page-rounded capability lengths and typed memory-entry rights. Only the
  quiescent state exposes slices. Consuming transitions choose a local writer
  with a read-only peer entry or a remote writer with a read-write peer entry
  after permanently downgrading the local mapping. Current and maximum
  permissions exclude execute.
- Linux uses sealed anonymous `memfd` objects, inherited irreversible MDWE,
  exact private `SCM_RIGHTS` transfer, `SO_PEERCRED`, `pidfd`, and parent-owned
  helper cleanup. Inside the MDWE-inheriting process tree, MDWE blocks
  permission upgrades and a single RWX view. The kernel still permits RX
  aliases; for receiver-writer setup, an unrelated process receiving the fd
  before future-write sealing can retain RW and later upgrade it. Every such
  delegate remains part of the malicious receiver authority principal.
- Windows uses unnamed sections with least-rights duplicated handles,
  per-launch private PID-checked named pipes, suspended process creation, and
  kill-on-close Job Objects.
- All three backends use consuming authenticated READY/COMMIT barriers after
  the peer imports and validates the complete page-rounded capability. Runtime
  reader/writer bindings remain withheld until the barrier completes.

Each bootstrap transaction carries a manually encoded, fixed-width,
little-endian manifest. It binds the control version, nonzero session nonce,
kernel-authenticated parent and child PIDs, monotonically increasing transfer
ID, canonical role ordering, schema, generation, writer endpoint, peer access,
and exact page-rounded capability length. A bounded batch supports up to 16
directional regions; one READY and one COMMIT activate the whole batch. The
current macOS and Windows two-direction helpers are convenience adapters over
that generic batch transcript.

Control channels require exclusive mutable access for capability transfer and
barrier transitions. This prevents two transactions from interleaving frames;
any malformed, stale, timed-out, or ambiguous transition poisons the session
and keeps all pending runtime wrappers private.

The private Linux G1c checkpoint keeps accepted application-control and native
capability traffic in one `AcceptedControlDispatcher`. Sealed role-specific
transport traits let only the coordinator send the first canonical capability
record while the receiver can only await it. A transaction guard borrows that
owner, stores the caller's one absolute deadline, and owns every installed fd.
The dispatcher retains the immutable accepted nonce, authenticated parent and
child identities, and negotiated limits; it alone mints monotonically
increasing transaction IDs and the canonical capability frame. Callers provide
only candidate manifest entries and cannot substitute accepted provenance or a
wire frame. Local manifest validation occurs before transaction entry and does
not consume an ID, while negotiated transaction exhaustion poisons the owner.
The guard never yields the socket, pidfd, executable, evidence, or descriptors.
Until the manifest-bound import/seal and READY/COMMIT reducer exists, it has no
production completion operation and its destruction persistently poisons the
session. This is a terminal provenance/transport ownership checkpoint, not an
active batch.

The private Linux G1d checkpoint also binds one exact native-authority profile
into the canonical capability transcript. Only the role-scoped accepted Linux
evidence owners select `LinuxMdweV1`; ordinary transaction callers cannot
provide or replace it. The profile records inherited irreversible MDWE,
non-executable library views, and the accepted Linux RX-alias and pre-seal
receiver-writer delegation limitations. The accepted dispatcher rejects the
legacy zero profile before native I/O, and exact frame comparison rejects peer
profile substitution. This session policy fact is not proof that any individual
memfd has completed import, final sealing, mapping, READY, or COMMIT.

The private Linux G1e coordinator entry point consumes one complete portable
`TransferBatch`. It derives every manifest entry from the transaction-owned
`PreparedRegion` metadata and retains all prepared regions beside the native
transaction guard; the raw-entry coordinator constructor exists only in tests.
Empty batches fail before transaction entry or ID consumption, and abandoned
guards poison before their retained batch is destroyed. The internal send step
receives a separately prepared native capability collection only in tests; the
production Linux entry point is superseded by G1f. G1e alone does not prove
descriptor-to-object identity or constitute the complete Linux prepared-memory
adapter.

Linux G1f-a converts a retained all-coordinator-writer `TransferBatch` into one
private native batch before any capability escapes. Conversion preserves the
initialized memfd contents, canonicalizes by `RegionId`, installs and verifies
`F_SEAL_EXEC | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_FUTURE_WRITE |
F_SEAL_SEAL`, and retains both the original coordinator writer mapping and one
same-object exported descriptor per canonical ordinal. The original and export
are revalidated against the same device/inode/length key immediately before
send. Pending drop clears the complete shared mapping according to
`ClearThenRelease` before closing it. Receiver-writer entries fail locally in
this slice; their IMPORTED/SEALED ordering remains separate work.

Linux G1f-b moves that native batch into a wrapper whose first field is the
accepted-owner transaction guard and whose second field is the complete native
batch. Thus abandonment or send failure poisons the inseparable session before
any pending mapping or fd is destroyed. Preparation, transaction entry,
pre-send revalidation, and native send carry one exactly equal caller-derived
absolute deadline; replacement deadlines fail before transaction entry. The
wrapper constructs the borrowed fd slice from its own canonical batch and never
accepts caller-provided descriptors or exposes the endpoint. There is still no
production completion operation, receiver native import, or READY/COMMIT.
Independent review found and closed both production substitution paths through
the older raw-entry and prepared-batch test scaffolds. Linux-specific event
tests also prove transport poison precedes native-batch cleanup on abandonment
and injected pre-send revalidation failure.

Linux G1g adds the complementary terminal receiver owner for
coordinator-writer batches. A private application-neutral `ExpectedBatch` is
canonical and complete before receipt but contains no coordinator-minted
incarnation or native authority. The accepted receiver alone enters the
transaction, performs one exact credential-bound receive for the expected fd
count, decodes the fixed capability frame, and matches accepted session facts,
transaction ID, authority profile, negotiated batch and fresh-session active
limits, IDs, writer/access direction, logical/page-rounded lengths, ordinals,
flags, and totals. It then verifies final seals and anonymous-object properties,
creates only read-only mappings, and retains every fd/mapping inside the
terminal transaction. Failed import ownership retains partial mappings and all
remaining installed fds until after session poison. G1g does not yet charge an
ongoing active-resource ledger, activate mappings, support receiver-writer
entries, or implement IMPORTED/SEALED/READY/COMMIT or public receiver APIs.

Linux G1h adds the receiver-writer-only preparation subprotocol without
activating a batch. The coordinator consumes and canonicalizes the complete
portable batch, installs and verifies execute/grow/shrink seals, and destroys
every coordinator writable mapping before its accepted owner can send the
capabilities. The receiver validates the exact expected batch under prefix
seals, creates all RW mappings, and sends `NIPCIMP1` carrying the exact full
manifest with zero rights. Only the accepted coordinator owner can consume that
receipt; it immediately installs and verifies future-write plus final seals,
continuing best-effort attenuation across every remaining escaped fd if one
seal step fails. Only after the complete batch is final-sealed does it create
read-only pending mappings and send exact zero-rights `NIPCSEA1`. The
receiver revalidates every final seal before retaining the still-pending batch.
Both preparation frames are derived internally from the transaction's canonical
capability frame, use the same caller deadline, and cannot be replaced with
application control. Every success and failure remains terminal and poisons on
guard destruction. G1h does not combine writer directions, end the transaction,
charge ongoing active leases, expose mappings, or implement batch READY/COMMIT
or public APIs.

Linux G1i-a introduces the private native owner needed before mixed accepted
transfer. `LinuxMixedDirectionBatch` consumes one complete portable batch,
canonicalizes it by region ID, and retains every entry inside its existing
direction-specific native owner. Its only production observations are the
canonical manifest entries, one borrowed capability view in that same order,
the original absolute deadline, and whole-batch pre-send revalidation. It does
not extract an fd or mapping, send on accepted control, perform IMPORTED/SEALED,
or expose pending/runtime authority. The later mixed accepted reducer must
consume this owner and preserve full-batch attenuation before mapping work.

## Unsafe-code policy

Unsafe is restricted to native ABI calls, construction of quiescent byte
slices, and binding atomics reached through independently validated native
mappings. Every unsafe operation states its aliasing, lifetime, permission, and
quiescence obligations. Runtime safe APIs do not expose shared byte slices.
Miri covers platform-neutral core; native Mach FFI is excluded because the
interpreter cannot execute those kernel operations.
