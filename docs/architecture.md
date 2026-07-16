# Architecture

## Boundaries

`native-ipc-core` treats every byte originating across a process boundary as
hostile. It owns protocol-neutral encoding, resource limits, region arithmetic,
atomic publication state, and the facts needed to bind capabilities. It knows
nothing about native handles or application message meanings.

Private native backends inside `native-ipc` turn OS objects into
least-authority mapping witnesses. The negotiated capability size includes
page rounding; bytes outside the logical layout are zeroed and validated.
Native code never creates executable shared-memory views and fails closed on
weaker-than-documented rights. macOS and Windows exclude execute from maximum
rights. Linux combines noexec memfds, seals, and inherited irreversible MDWE,
while explicitly retaining the kernel's direction-specific limits: peer RX
aliases and a receiver-writer fd delegate outside the MDWE tree retaining then
upgrading a pre-seal RW view.

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
  exact private `SCM_RIGHTS` transfer, per-record `SCM_CREDENTIALS`, a
  clone-time `pidfd`, and parent-owned helper cleanup. Cached `SO_PEERCRED` is
  not used as post-exec proof. Inside the MDWE-inheriting process tree, MDWE blocks
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

Linux G1i-b adds the matching private receiver-side native pending owner, still
without accepted-session integration. One pre-receipt mixed expectation checks
the complete negotiated count, logical-byte, mapped-byte, and active-resource
limits before any descriptor is accepted. Import immediately owns the complete
descriptor vector, validates canonical direction/access/length/ordinal shape,
rejects duplicate native objects, and creates a read-only pending mapping for
coordinator-writer entries or a writable pending mapping for receiver-writer
entries. Every partial fd and mapping remains in either the successful mixed
owner or one consuming failure owner. Neither exposes payload/runtime methods;
the later accepted reducer must consume them under its stored deadline.

The dependency-ordered Linux cleanup after G1i-b retired the superseded
filesystem-bootstrap, stream-framed, single-region transfer implementation.
The public memory facade and vNext still share the legacy-named
`QuiescentRegion` allocation primitive; that module now contains only the
anonymous memfd allocation/mapping owner and its vNext handoff. Its
`deny(dead_code)` boundary prevents a second unused Linux transport from
accumulating. The complete suppression and test-seam classification is recorded
in [`dead-code-audit.md`](dead-code-audit.md). This cleanup adds no mixed
accepted reducer, READY/COMMIT, activation, or public session authority.

Linux G1j consumes both mixed native owners into the role-scoped accepted
dispatcher. The coordinator alone mints and sends one canonical capability
frame; the receiver alone fixes the complete expectation, imports every fd,
and returns the exact full-manifest `IMPORTED` receipt. The coordinator then
revalidates the complete mixed object set and final-seals every receiver-writer
fd in one best-effort attenuation pass before attempting any new read mapping.
Only a completely attenuated batch can produce exact `SEALED`; the receiver
revalidates final seals for every direction before retaining the pending mixed
owner. Both sides use the same stored absolute deadline and keep transport,
manifest, fds, mappings, and accepted evidence inseparable. Failure or guard
destruction poisons before native cleanup. This is still a terminal private
checkpoint: it does not end the transaction, send READY/COMMIT, charge active
leases, or expose pending/runtime/public authority.

Linux G1k completes the private transaction with one exact full-manifest
READY/COMMIT barrier. Both completion records are domain-separated from
application control and from each other, use the transaction's stored absolute
deadline, carry no rights, and are derived only from the retained canonical
capability frame. Exact READY ends receiver preparation; exact COMMIT ends the
coordinator transaction and releases a committed owner on each endpoint.
Manifest substitution, truncation, application interleaving, and queued
duplicate replay poison persistently while the pending native owner still
retains cleanup authority. This remains a private Linux barrier, not a public
`Session<Ready>` or cross-platform completion claim.

Linux G1l binds one session-wide `ResourceOwner` into each accepted dispatcher
and activates the committed mixed batch all-or-nothing. Activation revalidates
the complete native batch, reserves every page-rounded byte before consuming
any mapping, and constructs endpoint-local `ActiveReader` or `ActiveWriter`
owners according to the negotiated writer direction. Runtime authority escapes
only as a complete keyed `ActiveRegionSet`; every active charge remains until
its native mapping is destroyed, with mapping drop ordered before lease
release. First/middle/final injected activation failures on either endpoint
poison before native mappings and leases unwind, expose no active set, restore
exact fd/map/task and ledger baselines, and leave later control persistently
poisoned. This is private Linux source-tree and hosted-run evidence only; public
composition, macOS/Windows reducers, physical Arm64, packaged-crate, and
release evidence remain outstanding.

Linux G1m composes those private owners into the safe public session surface.
An executable-side ELF preinitializer validates, scrubs, marks close-on-exec,
and reserves the inherited bootstrap before Rust application code; the
`receiver_main!` macro transfers that one-shot authority into
`ReceiverSession<Negotiating>`. The coordinator holds the exact executable and
direct-child lifecycle throughout HELLO, challenged bilateral decisions, Ready
control, batch activation, close, and abort. Public batch entry points accept
only portable prepared/expected owners and return only keyed opaque active
mappings. Capacity rejection is a clean bilateral return to Ready; ambiguous or
malformed in-flight operations poison before pending native cleanup. Active
mappings retain atomic session liveness, so abort makes later safe access fail
without revoking the peer's independently authorized mapping.

Windows composes the same public typestate and portable ownership surface over
its target-specific proof. The coordinator holds an absolute regular image
with replacement-denying sharing, compares the suspended process image's stable
file identity before resume, assigns the exact child to a kill-on-close Job,
and authenticates both named-pipe endpoint PIDs plus the nonce. Accepted owners
then run the canonical challenged negotiation, bounded control, bilateral
capacity preflight, complete IMPORTED/SEALED/READY/COMMIT mixed reducer, and
all-or-nothing activation. Normal wait reports the exact exit code only after
the process is signaled and the Job is empty; abort terminates the contained
tree and retains incomplete containment facts on failure.

Public failures retain a bounded `SessionFailure` describing the operation,
transaction stage, portable reason, optional errno, poison state, endpoint
observation, and coordinator child cleanup where applicable. Socket closure is
reported only as endpoint disconnection; exact direct-child exit is claimed
only after coordinator reap. Graceful close returns its owner when leases or
cleanup remain pending, and terminal abort reports any incomplete exact-child
cleanup.

### Current macOS lifecycle boundary

Public macOS session construction composes the audit-token-authenticated
direct-spawn path (enabled 2026-07-16). Separately, the backend-private
source implements a same-user, unprivileged fixed broker/launcher path: shared
`posix_spawn` preparation creates each supervisor child in a fresh session,
the launcher establishes `PT_TRACE_ME`, the broker verifies the initial stop
and exec trap, and the launcher installs an inherited `(deny signal)`,
`(deny mach-lookup)`, `(deny mach-register)` profile plus hard
`RLIMIT_NPROC=1` before it becomes the application-owned runner. FD3/FD4 are
made close-on-exec while failure remains reportable and then explicitly closed
before target exec. Security.framework is loaded dynamically only in a
disposable clean-exec authentication worker.

This design uses no root, set-ID transition, root-owned path, privileged
service, or request-selected executable. Applications own signing, packaging,
notarization, and any additional filesystem/network policy. Exact direct-child
termination/reap is implemented; race-resistant ordinary-descendant group
termination is not claimed. A separate malicious same-user process is outside
the host/runner integration model. The authoritative current description and
enablement gate are in
[`macos-supervisor-boundary.md`](macos-supervisor-boundary.md).

### Historical macOS prototype record

The remainder of this macOS subsection records earlier feasibility milestones
and rejected designs. It is non-normative: references below to privileged
watchdogs, root installation, credential dropping, or restored launchd access
do not describe the current architecture and confer no implementation or
release claim.

The macOS 6d direct-spawn composition is now the public typestate surface;
public macOS spawn/bootstrap compose it (enabled 2026-07-16). Direct
spawn now starts suspended and, in private prototype code, captures a task-name
right plus `TASK_AUDIT_TOKEN` before resume. Private
`proc_signal_with_audittoken` therefore exactly terminates a silent direct
child. The newer backend-private trusted-launcher path continues beyond that
execution-scoped SPI: it authenticates its broker by full audit token and PPID,
calls `PT_TRACE_ME`, completes an explicit stopped handshake, installs hard
`RLIMIT_NPROC=1`, and execs under the kernel's trace trap. The broker consumes
the exec `SIGTRAP` before target code, and later termination uses stop plus
`PT_KILL` while the unreaped direct child pins its PID. XNU also kills the exact
tracee if its tracer exits. A waiter mutex gives the handshake exclusive
ownership of both trace stops so the background reaper cannot consume them.

This remains a private proof, not a public lifecycle solution. Native
adversarial evidence shows same-UID target code can send unmaskable `SIGSTOP`
to its broker and indefinitely suspend deadline/death cleanup. A nested-tracer
test now proves that an outer watchdog can exact-`PT_KILL`/reap that stopped
broker and trigger exact tracer-exit cleanup of its target, but the production
privilege boundary is still absent. The launcher
must also restore the ordinary launchd bootstrap port before target exec for
libxpc initialization, so delegated XPC work is not governed by the target's
rlimit. Cooperative tracing relaxes code-signing enforcement for the
participating processes and therefore belongs in a minimal boundary. A
conforming design now requires an independently privileged authenticated
service/watchdog that the target cannot stop, with the target permanently
dropped to a nonroot client identity and no confused-deputy signaling or
arbitrary-exec surface. Backend-private source models now make the proposed
boundary narrower: the service accepts one bounded absolute-deadline
connection/nonces/sequence-bound installed-policy launch, a one-shot client
authenticates the service reply, the watchdog exposes only opaque handles while
retaining exact broker authority until a typed reap proof, and the launcher
clears supplementary groups before permanently dropping real/effective/saved
UID/GID and installing `RLIMIT_NPROC=1`. Exact credentials require a raw Mach
audit trailer rather than public XPC's connection-time UID/GID snapshots. Those
exact-message credentials still require Security.framework dynamic-code
validation, but the permanent watchdog lifecycle loop must never call that
framework, the filesystem, or the installed catalog. It dispatches a fixed
bounded audit-token/frame/generation/deadline job to one of a fixed number of
disposable authentication-worker processes. A result has effect only if it
echoes every binding before the original deadline. Saturation rejects
   immediately; a wedged worker is exactly killed and reaped before replacement;
   late or replayed output is discarded. The source implementation now owns the
   parent pipe ends linearly, submits one atomic fixed frame, requires exactly one
   result plus EOF, and retains the exact slot/generation across every pending or
   failure outcome. Its sole-waiter direct-child owner uses the unreaped child or
   zombie to pin the PID, fails stop on `ECHILD`, and accepts a result only after
   normal status-zero reap. Only immutable compiled requirements may
be cached, never a dynamic guest result across tokens or messages. The
backend-private fused adapter implements the raw Mach receive half and models
the remaining clean-exec side as pre-created one-job workers,
linear private-endpoint reply receipts, domain-separated exact-frame digests,
strictly increasing worker generations, live-only replay state, and bounded
nonblocking reap progress. It cannot mint a verified peer until typed exact
worker reap. The receiver uses exact audit trailers and logical receive limits,
destroys malformed/complex/oversized input, retains a linear send-once reply,
   and routes connection state only after authentication and reap. The client-side
   spawn result is likewise receive-only and reveals only an opaque handle or a
   coarse failure after exact reply authentication; there is intentionally no
   production success encoder yet. The watchdog now mints a noncopyable Ready
   proof only after the unexpired registered broker consumes both trace stops;
   an expired transition enters exact deadline cleanup without a proof; an
   undeliverable proof exact-cleans or retains the same broker and reason for
   retry. The authenticated spawn request now retains its exact decoded
   generation, sequence, and both nonces with the linear Mach reply through
   success and error transformations, but the Ready proof and reply right are
   not fused yet. Before broker creation, only that complete reply plus its
   assigned opaque session can mint the canonical bounded broker plan. The
   authority-free frame preserves the original `CLOCK_UPTIME_RAW` deadline,
   full exact-message peer identities, freshness, installed-policy target,
   argv, and environment. Broker receipt parses into a distinct untrusted type,
   conservatively rejects an expired or extended deadline, and still requires
   proof of the exact inherited parent channel plus complete-frame EOF/ACK and
   the later sole FD 3 START before any broker-consumable type exists. The
   source FD 4 stream transport uses gate-first polling, exact outer/inner
   lengths, one conservative deadline binding, sender write-half close, digest
   ACK, and a deadline-bounded dormant FD 3/FD 4 transition. A separate fixed
   FD 5 stream is minted with the same exact broker spawn and remains sealed
   through watchdog registration. It accepts only one fixed report plus EOF
   before the original deadline, binds the complete plan digest, session,
   connection generation, sequence, nonces, target, and credentials, and alone
   can construct the production `TraceEstablished` proof. Missing, extended,
   late, or substituted reports exact-clean the registered broker. The same
   socket's reverse endpoint then moves linearly with the authenticated proof
   through the armed Ready guard. A failed Ready send emits no resume byte and
   exact-cleans first; only a successful Ready send commits one fixed RESUME
   byte and closes the endpoint, after which no second deadline veto can create
   a Ready-but-never-resumed session. The broker requires exact byte plus EOF
   and one final FD 3 death probe before resumed authority. The broker
   source broker-local waiter now retains the exact active plan, gate, report
   endpoint, and original deadline across a sole-waiter child typestate. It
   distinguishes an unproven initial stop from successful ptrace continuation
   and requires changed audit PID version, complete real/effective credential
   equality, and exact installed `proc_pidpath` at the exec trap. That token now
   alone emits FD 5, retains the stopped target through Ready-bound RESUME+EOF,
   rechecks service liveness at the continuation boundary, and resumes once
   without a post-report broker clock veto; every rejection exact-cleans. The
   watchdog enters `ReadyCommitted` only after Ready and reverse commit both
   succeed, so stale deadline work cannot kill the committed session; all
   non-deadline terminal causes remain valid. Resumed authority enters a
   gate-first exact-wait loop without a post-Ready clock veto. Natural exit or
   signal death consumes the exact reap before returning a PID-free outcome;
   any later traced stop, service EOF, or invalid gate byte exact-cleans, with
   a post-wait gate probe preserving service-death priority. The fixed launcher
   spawner/entry remains to be implemented. A one-shot non-sendable
   child-wait-domain initializer checks
   main-thread/single-threaded startup, canonicalizes default SIGCHLD zombie
   semantics, and blocks SIGCHLD for inheriting service threads. The fixed
   source spawner now creates private one-job pipes, installs only FD 3/FD 4,
   and converts a positive `posix_spawn` result directly into exact direct-child
   authority before any fallible work. Its separate clean-exec entry validates
   the fixed vector and descriptors, dynamically loads Security.framework only
   inside that worker, authenticates the exact audit token, writes one atomic
   result, and retains the result writer until process exit. Native tests compose
   that spawner, real entry, Security validation, pool routing, and exact reap
   while proving the enclosing test/service image has no static Security or
   CoreFoundation dependency. The worker is still not separately packaged,
   signed, root-installed, or verified as replacement-resistant; the spawner is
   not wired to Mach transport or a complete process-wide waiter policy, and no
   positive installed-root evidence exists. The negative result for unprivileged same-UID
constructions, the primary-source evidence, and the enable decision history
are recorded in
[`macos-supervisor-boundary.md`](macos-supervisor-boundary.md). In the
post-authentication prototype the
coordinator retains an opened regular non-setid
executable and compares its stable path identity with `proc_pidpath` after
authentication and again through ACCEPT. This is not fd-exec, immutable
running-vnode proof, or replacement denial. Spawn launches the helper in a
fresh POSIX session with close-on-exec default and transfers wait ownership to
a durable nonblocking reaper before the deadline-bound Mach bootstrap receive.
The private channel validates exact audit PID and nonce;
only canonical bilateral HELLO and challenged ACCEPT mint role-scoped evidence.
Prototype Ready control and mixed transfers reuse the common dispatcher, including a
bilateral capacity preflight that returns both endpoints cleanly to Ready on an
asymmetric active limit. Direct-child status is reported only after the sole
waiter reaps it; descendant cleanup is `FreshGroupUnverified` because macOS has
no retained race-resistant process-group handle in the public session path.
The private traced-launcher proof prevents direct fork/spawn by the nonroot
target but is not wired into public sessions until its privileged broker and
delegation boundary exist. The macOS lifecycle
boundary, native Windows Arm64 runtime, physical Arm64 and exact-release
packaged evidence, exact-tip hosted CI, and release evidence remain
outstanding; local Windows AMD64 source and extracted-package verification are
green.

## Unsafe-code policy

Unsafe is restricted to native ABI calls, construction of quiescent byte
slices, and binding atomics reached through independently validated native
mappings. Every unsafe operation states its aliasing, lifetime, permission, and
quiescence obligations. Runtime safe APIs do not expose shared byte slices.
Miri covers platform-neutral core; native Mach FFI is excluded because the
interpreter cannot execute those kernel operations.
