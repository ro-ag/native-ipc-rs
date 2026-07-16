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
composes this path (Option B enabled 2026-07-16 after the cross-platform
public session conformance corpus ran green on macOS; see
[`macos-supervisor-boundary.md`](macos-supervisor-boundary.md)). The
backend-private trusted-launcher path authenticates its broker, establishes
cooperative tracing before untrusted exec, proves the relationship with a
stopped handshake, lowers hard `RLIMIT_NPROC` to one, denies Mach lookup and
registration in an inherited profile, and crosses exec through the kernel's
trace trap before target code. This gives exact direct-child termination, fork
denial, and launchd delegation denial while the broker runs, and XNU kills the
tracee if the broker exits. The launcher path remains backend-private
deployer machinery with no installed-artifact proof; a separate malicious
same-user principal also remains outside the integration model. Windows publicly
composes the canonical records over its exact-PID named pipe, held suspended
image, and kill-on-close Job. Its Negotiating/Ready owners expose only the same
portable control, mixed-batch, active-mapping, and lifecycle surface as Linux.

## macOS supervisor lifecycle decision

The selected source design is same-user and unprivileged. Fixed
deployer-compiled broker, launcher, and clean-exec worker paths are never
selected by requests. Every supervisor child starts in a fresh session with
canonical signals and close-on-exec defaults. The launcher establishes
cooperative tracing, marks staging descriptors close-on-exec before irreversible
containment, installs the inherited SBPL/`RLIMIT_NPROC` boundary, and immediately
execs the configured application-owned runner. Security.framework is loaded
only in the disposable worker. No root, set-ID transition, root-owned catalog,
privileged launchd watchdog, or arbitrary-exec/signal deputy is part of the
model.

Public macOS sessions are enabled (2026-07-16) over the direct-spawn path;
the launcher machinery here stays backend-private. Exact direct-child
termination/reap is implemented; ordinary-descendant group cleanup remains
unverified and is not inferred from a fresh session. Signing, packaging,
notarization, and optional capability policy belong to the embedding
application. See [`macos-supervisor-boundary.md`](macos-supervisor-boundary.md)
for the current protocol and evidence boundary.

### Superseded design exploration

The text below preserves the earlier privileged-service exploration as design
history only. It is non-normative and is not the selected implementation.

Any viable public macOS construction needs a preinstalled, independently
privileged signed launchd service/watchdog, not a same-UID broker spawned by
the client library. An authentication-only
nonce exchange and explicit code-requirement checks precede the spawn-bearing
request, which carries only a bounded installed-policy identifier, additional
arguments, allowlisted environment values, freshness facts, and one absolute
deadline. The immutable signed/root-owned catalog selects the executable,
argv0, code requirements, and target identity. Lifecycle
commands carry only a fresh opaque session identifier; numeric helper PIDs and
task ports are never wire authority. The service serializes signal selection
with reap-and-tombstone and compares the complete helper audit execution
identity on every Mach record. The candidate is insufficient across service
deployment because a same-UID target can stop the broker indefinitely. The
trace relationship now supplies exact broker-exit cleanup, and a nested-tracer
native test proves an independent watchdog's exact stopped-broker recovery, but
the privileged service boundary is not implemented. The backend-private
protocol model now admits only one bounded, absolute-deadline,
exact-message-authenticated installed-policy launch bound to fresh
client/service nonces, a connection generation, and a sequence. A one-shot
client authenticates the service reply before emitting that effect; exact
UID/GID facts require a raw Mach audit trailer, not public XPC snapshots.
The permanent watchdog must also keep Security.framework off its lifecycle
loop. Each dynamic guest check runs in one of a fixed number of disposable
worker processes over a private capability channel. The fixed job and result
bind the exact 32-byte audit token, digest of the exact retained bytes, live-job
ID, worker generation, and the original absolute deadline. Client-selected
connection generations are excluded from pre-authentication jobs and capacity.
A
linear non-serializable receipt binds completion to the assigned private reply
endpoint. That receipt now owns the actual nonblocking result FD: the parent
submits one atomic 152-byte frame, closes the sole request writer, and accepts
only one exact 200-byte result followed by EOF. Every pending/error token keeps
the exact slot and generation for cancellation or reap retry. Late, replayed,
mismatched, saturated, or wrong-worker results fail
closed; authority is minted only after bounded nonblocking observation returns
a typed normal-status-zero exact-worker-reap proof. A sole-waiter direct-child
owner may signal the numeric PID only while a live child or unreaped zombie pins
it; `ECHILD` fails stop without fallback. A wedged worker retains exact unreaped-child
authority and is exactly terminated and reaped before replacement; no
replacement restarts the deadline. Live replay state is bounded, and strictly
increasing worker generations make a retired endpoint unreachable even if a
random job ID coincidentally repeats. Only immutable installed requirements may
be cached, never dynamic validation across tokens or messages. The
backend-private raw receiver now authenticates before routing: a canonical hello
may create fresh connection state only after full validation, while a spawn
exposes its generation only after validation and exact worker reap. Wrong-peer
or wrong-nonce traffic cannot poison the selected live connection.
The client then remains in `AwaitingSpawnResult` until an exact authenticated
sequence-one reply carries either a nonzero opaque handle or one of four coarse
failures. The wire contains no PID, signal, path, task port, audit token, errno,
or OSStatus. This is receive-only: production success emission remains absent
until it can consume watchdog trace/readiness proof while retaining the exact
Mach reply right.
The watchdog-side proof is now a linear value minted only by the unexpired
registered Starting-to-Traced transition. Expiry enters exact deadline cleanup
and mints no proof. An undeliverable proof consumes into a distinct
cleanup reason; exact-reap failure keeps the same table entry and first reason
for retry. This still supplies no production Ready encoder: the next boundary
must keep the proof and exact authenticated send-once right inseparable through
send and cleanup. The accepted spawn wrapper now preserves the exact decoded
generation, sequence, client nonce, and service nonce with that linear reply
right through both successful and failed transformations. It still cannot emit
Ready or substitute for the armed watchdog cleanup guard required at send time.
The auth-worker source also has a one-shot, main-thread-only child wait-domain
initializer that rejects an already-threaded process, custom/ignored SIGCHLD,
and `SA_NOCLDWAIT`, installs canonical default zombie semantics, and blocks
SIGCHLD before service threads inherit their masks. The fixed source spawner
owns the entire successful `posix_spawn` to armed exact-worker transition
without a fallible PID-only gap, and its clean-exec entry retains result FD4
through success or rejection until `_exit`. The separately packaged, signed,
same-user worker and complete service-wide waiter policy remain absent.
The watchdog model exposes only connection-bound opaque handles and retains
linear exact broker authority through a typed reap proof. The launcher-only
transition binds the exact traced session and validated installed target to
group/credential drop and immediate exec. These are source constraints, not a
signed or installed service. The source production boundary exposes no
arbitrary signaling or execution deputy and forbids blanket launchd lookup and
registration before target exec. An installed deployment must prove that
immutable profile, survive client/broker stops, and account explicitly for any
future service allowlist. Public macOS sessions compose over the direct-spawn
path (enabled 2026-07-16); this launcher boundary remains backend-private and
installed-artifact proof is deployment responsibility. See
[`macos-supervisor-boundary.md`](macos-supervisor-boundary.md).
