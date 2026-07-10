# Architecture

## Boundaries

`native-ipc-core` treats every byte originating across a process boundary as
hostile. It owns protocol-neutral encoding, resource limits, region arithmetic,
atomic publication state, and the facts needed to bind capabilities. It knows
nothing about native handles or application message meanings.

`native-ipc-platform` turns OS objects into least-authority mappings. Native
code must validate the actual permission of a received capability, map no more
than the negotiated size, exclude execute from current and maximum protection,
and fail closed when the OS cannot enforce the requested rights.

The facade reexports both boundaries without inventing a combined mapping API.

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

Validation copies immutable header facts into owned Rust metadata. It returns
checked numeric ranges but never retains or returns a shared slice. Native
mapping permission is part of the validated binding: a read-write mapping can
mint writer/store bindings, and a read-only mapping can mint reader/load
bindings. These types are intentionally not interchangeable.

## Publication and reuse

Sequence zero means unpublished. For sequence `S` and `N` slots, the only legal
slot is `(S - 1) mod N`. First publication in slot `i` is `i + 1`; later reuse
is exactly the prior sequence plus `N`. Overflow is terminal.

The sole writer mutates opaque payload bytes through a native mapping-specific
mechanism, stores payload length, and Release-publishes the sequence. The reader
Acquire-loads the sequence, validates generation and length, copies the payload
into owned storage, then Acquire-rechecks generation and sequence. The reader
never claims, releases, or otherwise writes producer-owned metadata.

Before a writer can reuse a slot, it must observe an acknowledgement from an
opposite-direction mapping. Target role, generation, and prior sequence must be
exact. Greater-than comparisons are insufficient because they permit malicious
pre-acknowledgement and ABA reuse.

## Native policy

- macOS uses Mach VM allocation and typed memory-entry rights. Only the
  quiescent state exposes slices. Consuming transitions choose a local writer
  with a read-only peer entry or a remote writer with a read-write peer entry
  after permanently downgrading the local mapping. Current and maximum
  permissions exclude execute.
- Linux will use sealed anonymous `memfd` objects, private `SCM_RIGHTS`
  transfer, `SO_PEERCRED`, and `pidfd`. It currently returns incomplete.
- Windows will use unnamed sections with least-rights duplicated handles,
  per-launch private named pipes, and kill-on-close Job Objects. It currently
  returns incomplete.

No backend may substitute a globally named object, System V IPC, executable
mapping, or cooperative-only permission convention.

## Unsafe-code policy

Unsafe is restricted to native ABI calls, construction of quiescent byte
slices, and binding atomics reached through independently validated native
mappings. Every unsafe operation states its aliasing, lifetime, permission, and
quiescence obligations. Runtime safe APIs do not expose shared byte slices.
