# vNext protocol decisions

This file records wire choices intentionally left open by
[`native-ipc-vnext-spec.md`](native-ipc-vnext-spec.md). The normative security
and ownership requirements remain unchanged.

## Negotiation ordering

The authenticated channel uses this fixed two-sided sequence:

1. coordinator `HELLO`;
2. receiver `HELLO`;
3. coordinator `ACCEPT` or `REJECT`; and
4. receiver `ACCEPT` or `REJECT`.

Each application sees the peer's bounded opaque HELLO payload before making
its decision. Only the final exact `ACCEPT` transitions to ready. A malformed,
stale, substituted, out-of-order, partial, or timed-out frame poisons the
session once transport exists; a canonical application `REJECT` is a clean
negotiation outcome.

## Wire registry

- Negotiation magic is `NIPCHEL1`, with a 224-byte fixed little-endian header.
- Wire version 1.0 accepts exactly major 1, minor 0. A future compatible minor
  requires an explicit compatibility table before the decoder accepts it.
- Frame kinds are HELLO 1, ACCEPT 2, and REJECT 3.
- Sender roles are coordinator 1 and receiver 2.
- Target OS codes are Linux 1, macOS 2, and Windows 3.
- Target architecture codes are AMD64 1 and Arm64 2. Pointer width is 64 and
  endian code 1 is little-endian on every supported target.
- Library feature bits 0 and 1 require lock-free cross-process 32-bit and
  64-bit atomics respectively. The registry is 128 bits. Unknown optional bits
  are ignored; unknown required bits reject negotiation.
- Rejection reason zero is invalid. Named nonzero reason assignments will be
  fixed before the public session API is exposed.

The selected feature set is the known intersection of both supported sets and
verified effective capabilities. It must include both required sets. Numeric
limits are exact checked minima. ACCEPT repeats the selected features,
effective limits, effective atomic/alignment facts, target, role, and session
nonce, plus a domain-separated SHA-256 digest of both canonical HELLO records
(including their opaque payloads). It is compared to the immutable result of
both HELLO frames. Decision validation is ordered and one-shot per role.

The SHA-256 preimage is exactly the following concatenation, with no implicit
padding or separators:

1. ASCII `native-ipc-vnext-hello-transcript-v1`;
2. the canonical coordinator HELLO record below; and
3. the canonical receiver HELLO record below.

Each canonical record contains these fields in order. Every integer is
little-endian: magic `[u8; 8]`; wire major `u16`; wire minor `u16`; HELLO kind
`u16`; sender role `u8`; nonce `[u8; 32]`; two supported-feature `u64` words;
two required-feature `u64` words; maximum regions `u16`; maximum active regions
`u32`; maximum region, batch, active, and transaction values as four `u64`s;
bootstrap and control payload maxima as two `u32`s; atomic flags `u32`; u32 and
u64 atomic alignments as two `u16`s; page and cache-line alignments as two
`u32`s; target OS and architecture as two `u16`s; pointer width `u8`; endian
code `u8`; application payload length `u32`; and exactly that many payload
bytes. Atomic flag bits 0 and 1 mean lock-free u32 and u64 respectively.

Header length, derived frame length, zero result, fixed flags, reserved bytes,
and the ACCEPT digest field are excluded. They are fixed, derived, or required
zero by the canonical wire decoder. The unit-test golden vector for the fixed
coordinator/receiver fixture is
`39dddcd2f78ad36ebd7ab2f45061f98457300f99b51683a92a3d78fae5f8d746`.

Page, cache-line, and atomic alignments reported by either endpoint must equal
the locally discovered native facts. Lock-free support is the logical AND of
the verified local fact and both offers. Native publication/observation tests
remain mandatory release evidence; wire agreement alone is not proof.

## Field-specific hard maxima

The public constants in `session` define the implementation's finite maxima:
16 regions, 1 TiB per region, 4 TiB per batch, 1,048,576 active regions,
16 TiB active bytes, 2^48 transactions, and independent 16 MiB bootstrap and
application-control payload maxima. These bounds are checked before native
import or allocation and may only change with a reviewed wire/API revision.
