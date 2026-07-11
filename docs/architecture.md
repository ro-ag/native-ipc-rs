# Architecture

## Boundaries

`native-ipc-core` treats every byte originating across a process boundary as
hostile. It owns protocol-neutral encoding, resource limits, region arithmetic,
atomic publication state, and the facts needed to bind capabilities. It knows
nothing about native handles or application message meanings.

`native-ipc-platform` turns OS objects into least-authority mapping witnesses.
The negotiated capability size includes page rounding; bytes outside the
logical layout are zeroed and validated. Native code excludes execute from
current and maximum protection and fails closed on weaker rights.

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
- Linux uses sealed anonymous `memfd` objects, exact private `SCM_RIGHTS`
  transfer, `SO_PEERCRED`, `pidfd`, and parent-owned helper cleanup.
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

## Unsafe-code policy

Unsafe is restricted to native ABI calls, construction of quiescent byte
slices, and binding atomics reached through independently validated native
mappings. Every unsafe operation states its aliasing, lifetime, permission, and
quiescence obligations. Runtime safe APIs do not expose shared byte slices.
Miri covers platform-neutral core; native Mach FFI is excluded because the
interpreter cannot execute those kernel operations.
