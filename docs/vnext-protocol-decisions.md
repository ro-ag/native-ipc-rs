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
its decision. The coordinator decision carries a fresh nonzero 128-bit
OS-CSPRNG challenge. After coordinator `ACCEPT`, the receiver makes its own
explicit application decision and its `ACCEPT` or `REJECT` echoes that challenge
exactly. Coordinator `REJECT` is terminal. Only the final exact `ACCEPT`
transitions to ready. A malformed, stale, substituted, out-of-order, partial,
or timed-out frame poisons the session once transport exists; a canonical
application `REJECT` is a clean negotiation outcome.

The challenge prevents a malicious receiver from prequeuing a deterministic
decision before the coordinator decides. It is neither authentication, the
session nonce, a receipt, a MAC, nor a secret after delivery. A single online
guess succeeds with probability 2^-128. Entropy/deadline failure after the
decision begins poisons without retrying or replacing the original deadline.

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
- ACCEPT and REJECT bytes 80..96 carry the decision challenge. The all-zero
  value is invalid. For HELLO, those bytes retain their original meaning as the
  two required-feature `u64` words.

The selected feature set is the known intersection of both supported sets and
verified effective capabilities. It must include both required sets. Numeric
limits are exact checked minima. ACCEPT repeats the selected features,
effective limits, effective atomic/alignment facts, target, role, and session
nonce, plus a domain-separated SHA-256 digest of both canonical HELLO records
(including their opaque payloads), and the decision challenge. It is compared
to the immutable result of both HELLO frames. The first exact coordinator
ACCEPT stores its challenge; the receiver decision must echo it. Decision
validation is ordered and one-shot per role. REJECT carries the session nonce,
nonzero reason, and decision challenge; its other decision-body bytes are zero.
Canonical REJECT decoding alone is not an authorized decision: the
transcript-owned reducer must additionally validate role, nonce, reason,
challenge, and current decision order before terminating negotiation.

This is a deliberate incompatible correction to an unpublished and unfrozen
pre-public wire 1.0 draft. Header length remains 224, wire number remains 1.0,
and the HELLO payload ceiling is unchanged. There is no legacy zero-challenge
decoder, dual decoder, downgrade path, or compatibility mode.

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
the decision challenge, and the ACCEPT digest field are excluded. They are
fixed, derived, decision-time input, or validated elsewhere by the canonical
wire decoder. The unit-test golden vector for the fixed
coordinator/receiver fixture is
`a55eeda47e9f0124bd9f9b675e7b356fdc72cde173ff7d62acd7a15819b9312a`.

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

## Native authority profile

Bytes 76..80 of the fixed native transfer header are a little-endian `u32`
authority-profile code. Zero is retained only for the landed pre-vNext native
helpers. The private accepted vNext dispatcher rejects zero before native I/O.

Profile 1 is `LinuxMdweV1`: the trusted pre-exec path installed inherited
irreversible `PR_MDWE_REFUSE_EXEC_GAIN`; library mappings never request
execute; the documented fresh RX-alias limitation remains; and a
receiver-writer may delegate its pre-final-seal fd outside the MDWE tree and
retain an upgradeable RW mapping. This is a session policy and residual-limit
profile, not evidence that any particular object has completed import, final
sealing, mapping, READY, or COMMIT. The complete fixed frame, including this
profile, is compared exactly on receive.

New target profiles require a reviewed wire decision. Reserved bytes outside
defined fields remain zero.

## Linux preparation frame kinds

Linux receiver-writer preparation uses `NIPCIMP1` for `IMPORTED` and `NIPCSEA1`
for `SEALED`. Each is the same fixed-size canonical full-manifest encoding as
`NIPCCAP1`, with only the eight-byte magic/frame-kind changed by library-owned
construction. Both carry zero rights, exact directional credentials, and no
application payload. Callers cannot construct them, and neither frame ends a
transaction or grants READY, COMMIT, activation, or runtime authority.

## Application control framing

Application control uses magic `NIPCAPP1`, exact wire version 1.0, and a
72-byte little-endian fixed header: magic `[u8; 8]`; major and minor `u16`;
header length `u32`; complete frame length `u32`; payload length `u32`; kind
`u32`; zero flags `u32`; session nonce `[u8; 32]`; and per-direction sequence
`u64`. The opaque payload follows immediately. Application kinds occupy
`0x8000_0000..=u32::MAX`; lower values remain disjoint native protocol kinds.

The record transport independently bounds or preallocates the complete record
from the negotiated native maximum before reading it. The private decoder then
validates the fixed header, negotiated/hard payload bound, nonce, and exact next
sequence before payload exposure or any second allocation derived from peer
fields. On Linux, `SOCK_SEQPACKET` consumes the record with one bounded
`recvmsg`, never `MSG_PEEK`, and adopts then closes injected ancillary rights
before rejection. A borrow-bound pending-receive guard poisons on every
unsuccessful finish or Drop. Successful exact payload finalization reuses that
single owned record allocation and advances the receive sequence once. Send
and receive sequences are independent; exhaustion, replay/reorder, malformed
peer input, partial receive, and transaction conflict are terminal. The Linux
public API exposes this transport only from an authenticated `Session<Ready>`.
The blocked macOS Arm64 prototype uses the same canonical wire records over an
audit-PID/nonce-authenticated private Mach port and retains exact-child wait
ownership plus the held image through prototype Ready; public construction
remains fail-closed pending pre-bootstrap exact termination. Windows publicly
composes the canonical records over its exact-PID named pipe, held suspended
image, and kill-on-close Job. Its Negotiating/Ready owners expose only the same
portable control, mixed-batch, active-mapping, and lifecycle surface as Linux.

## macOS supervisor lifecycle candidate

Any viable public macOS construction needs a preinstalled signed launchd/XPC
service, not a broker spawned by the client library. An authentication-only
nonce exchange and explicit code-requirement checks precede the spawn-bearing
request, which carries bounded command/image/nonce/deadline policy. Lifecycle
commands carry only a fresh opaque session identifier; numeric helper PIDs and
task ports are never wire authority. The service serializes signal selection
with reap-and-tombstone and compares the complete helper audit execution
identity on every Mach record. The candidate is insufficient across service
crash because the parent wait authority and in-memory table disappear; no
documented public crash-surviving exact containment primitive has been
identified. Public macOS remains architecture-blocked and fail-closed; see
[`macos-supervisor-boundary.md`](macos-supervisor-boundary.md).
