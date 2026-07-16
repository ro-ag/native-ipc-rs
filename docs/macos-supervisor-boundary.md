# macOS exact-lifecycle supervisor boundary

> **Scope correction (2026-07-15).** Parts of this document below predate the
> current design and describe a *privileged, root-owned, credential-dropping*
> supervisor. That design was removed. The supervisor is now **same-user and
> unprivileged** — no root, no `setuid`, no root-owned install — and its purpose
> is **lifecycle correctness** (verified-your-code child, contained, exactly
> reaped, no zombie), not privilege separation. Untrusted code is confined to an
> in-process library inside a signed child runner rather than run as a separate
> process. The "hostile same-UID helper can stop its broker" and "privileged
> service required" framing below applies only to the abandoned goal of
> containing an *arbitrary adversarial process*; that is explicitly out of scope.
> For the authoritative scope and threat model, see
> [`docs/integration-model.md`](integration-model.md). Public macOS remains
> `BackendUnavailable` by decision.

Status: backend-private traced-launcher core implemented; privileged deployment
boundary unresolved. A cooperative `ptrace` launcher plus hard
`RLIMIT_NPROC=1` now closes the first-target-instruction, post-exec identity,
direct-fork, exact-stop/kill, and tracer-crash gaps in native tests. It does not
yet satisfy the hostile-helper contract: same-UID target code can stop its
broker indefinitely, and restored launchd/XPC delegation is outside the
rlimit. Backend-private source models now constrain the future service protocol,
watchdog ownership state, client authentication state, launcher
credential/exec transition, and the broker's fixed start/death gate, but they
are not Mach-service or executable artifacts. No privileged service, signed launcher
artifact, bundle, entitlement, installation fixture, or public macOS session
adapter is implemented. Public macOS spawn/bootstrap remain fail-closed.

A dedicated primary-source investigation (2026-07-13, recorded in project
tracking) examined every then-known direct-kill candidate and produced the
negative result later narrowed by the traced-launcher composition. The still
applicable findings are recorded in
[Residual public-API evidence](#residual-public-api-evidence) below.
Native follow-up on 2026-07-14 first narrowed one premise: suspended spawn can
retain a task-name right and read `TASK_AUDIT_TOKEN` before the child runs.
Combined with private `proc_signal_with_audittoken`, that closes only the silent
direct-child gap. Further source and native work found a stronger composition
using public process primitives: a trusted launcher authenticates its broker,
enters `PT_TRACE_ME`, performs a stopped proof handshake, lowers hard and soft
`RLIMIT_NPROC` to one, and crosses exec through the kernel's trace trap before
target code. Broker stop/`PT_KILL` and broker exit both act on the exact tracee.
The backend-private implementation and adversarial corpus now exercise this
chain.

The source model now also contains the production-shaped broker creation
boundary that was previously missing. An installation-only value copies one
absolute broker path supplied as a compile-time constant by the deployer's
helper artifact, fixes `argv` with matching `argv[0]`, and prepares a canonical
environment before exact-path `posix_spawn`. The launcher and clean-exec auth
worker use the same deployer-supplied path contract. Relative configuration and
entry-vector substitution fail closed; no request field selects any helper
path. The child receives only one collision-normalized start/death pipe reader. Darwin
`POSIX_SPAWN_CLOEXEC_DEFAULT`, `POSIX_SPAWN_SETSIGDEF`, and
`POSIX_SPAWN_SETSIGMASK` close unrelated descriptors, restore explicit signal
defaults, and install an empty child mask without changing the parent mask.
Because Darwin has no atomic CLOEXEC pipe constructor, the dedicated service
must remain permanently single-threaded: immediately before every pipe/spawn
transition the linear wait-domain token rechecks the main thread and Darwin's
sticky never-threaded state, along with canonical blocked `SIGCHLD`. This
excludes a concurrent fork/exec from inheriting either briefly unmarked pipe
end. Any future service child creation must consume the same exclusive domain;
becoming threaded permanently rejects later broker spawns.
The service retains the nonblocking, no-`SIGPIPE` writer, inserts the complete
reply/session/validated-launch/exact-child owner into the watchdog table, and
then writes one start byte. It keeps the writer after activation so service
death produces EOF. Cleanup closes the gate, exact-waits before any signal,
never treats `ESRCH` as reap proof, aborts on `ECHILD` without numeric fallback,
and mints terminal proof only from exact `waitpid` reap.

The matching source entry boundary accepts only the fixed absolute `argv[0]`,
broker mode, and exact `--gate-fd=3`, `--control-fd=4`, and `--trace-fd=5`
vector. It adopts a read-only FIFO reader at FD 3 plus two bidirectional Unix
streams, sets `FD_CLOEXEC`, gate-first stages and digest-ACKs one canonical
deadline-bound plan on FD 4, then blocks until exactly START byte `1`. It
distinguishes service EOF before activation, immediately after START, and
during the active lifetime; a wrong, repeated, or later gate byte is terminal.
FD 5 is a separate one-shot trace-report channel sealed into the same atomic
broker spawn and watchdog registration. The service accepts only one fixed
report plus EOF before the original deadline with exact plan digest,
session/connection/sequence/nonces/credentials/target bindings. Missing,
extended, late, or substituted output exact-cleans the registered broker. The
authenticated reverse endpoint remains linear through Ready delivery: failed
Ready sends emit no RESUME and exact-clean before endpoint drop; successful
Ready is the final commit point and is followed by one fixed reverse byte plus
EOF without a second clock veto. The broker admits resumed authority only after
that exact frame and a final FD 3 service-death probe. The
resulting active gate and report receipt expose no request-selected launch,
path, PID, signal, task, or filesystem authority. START and report bytes alone
cannot launch a target. The source broker-local waiter now consumes an exact
direct child together with the complete active plan/gate/report bundle, keeps
the initial `SIGSTOP` unproven until `PT_CONTINUE` succeeds, and accepts the
exec trap only after the audit PID version changes, real/effective IDs match,
and `proc_pidpath` equals the installed plan path. Untraced, substituted-image,
unexpected-stop, service-death, and deadline paths exact-clean. Only that held
token can now emit the canonical FD 5 report; it retains the stopped target
through exact RESUME+EOF, rechecks FD 3 immediately at the effect boundary,
and then continues exactly once without a second broker-side deadline veto.
The service receiver and armed Ready guard remain the sole deadline authority
after report EOF. Only successful Ready plus reverse commit moves the watchdog
to `ReadyCommitted`; stale deadline work cannot retroactively terminate that
phase, while client loss, protocol failure, unexpected stop, and service table
drop remain exact-clean effects. The resumed target then enters a gate-first
sole-waiter loop with no post-Ready clock veto. Exact natural exit or signal
death is reaped before a PID-free outcome is returned; any later traced stop
is terminal and exact-cleaned. Service EOF or a bad gate byte wins through a
final post-wait probe: a still-live or stopped target exact-cleans, while an
already reaped target only changes the terminal classification. The fixed
launcher spawner and entry exist as source mechanisms, but no production
service caller or separately installed launcher artifact exists yet.

A native pre-main fixture now enters through the production
`LauncherSpawnResources` file actions and attributes rather than reconstructing
them in test code. Inside the spawned image it verifies the exact fixed argv,
three-entry canonical environment, `/dev/null` descriptors 0 through 2,
read-only anonymous FIFO readers at FD 3
and FD 4 with `FD_CLOEXEC` cleared only for those destinations, and no open
descriptor above FD 4. The parent deliberately retains an inheritable sentinel
descriptor, so the fixture also proves `POSIX_SPAWN_CLOEXEC_DEFAULT` excludes
unrelated broker authority. It inspects `TASK_BOOTSTRAP_PORT` and rejects a
receive right, but deliberately accepts either the requested dead name or the
known live send-right residual: current Darwin restores a live launchd
bootstrap right, so this fixture does not claim launchd is unreachable. That
delegation gap remains issue #9 and keeps public macOS fail-closed.

This remains source and native mechanism evidence. The test image is a fixed
local shell used to characterize pipe, spawn, and direct-child semantics; it
does not prove that the eventual signed broker's dyld/constructor path reaches
only trusted gate code. The gate-entry tests use both libtest subprocesses and
a separately compiled harnessless fixture that invokes the hidden no-callback
entry runner with the exact process vector and FD 3. The fixture still links
the library test build and is not a minimal signed/package artifact or pre-main
constructor audit. These tests also cannot distinguish an anonymous pipe from
a named FIFO using public descriptor metadata; FIFO shape and START are
explicitly non-authoritative until an exact-child/session/control-plan binding
is authenticated. Nor do they prove that any deployer-supplied production path
is installed, signed, packaged, or replacement-resistant. The
packaged executable and clean-exec launcher artifact,
installed service loop,
permanent credential drop, real client-death authority, and launchd/XPC
delegation policy remain unresolved. Public macOS therefore remains
fail-closed.

Standing decision (2026-07-13): the project keeps public macOS fail-closed
rather than re-scoping the contract to a documented weaker containment class
or depending on private libproc/proc_info interfaces. The exactness
requirement is not negotiable for this backend. This position is revisited
only when an independently privileged service/watchdog can host the proven
trace core without becoming an arbitrary-exec or signaling deputy, permanently
drops the launcher/target to the authenticated nonroot client identity, and
resolves launchd/XPC delegation ownership. Until then R8.6/6d remains
architecture-blocked by decision.

## Decision

Any viable production macOS session adapter requires an authority that exists
before untrusted code runs and which the target cannot stop. The current
candidate is a preinstalled, signed, independently privileged
`launchd`-advertised service/watchdog hosting a minimal broker. A same-UID
broker that the library starts with `posix_spawn` is insufficient: although
cooperative tracing survives exec and broker exit kills the exact tracee, the
tracee can send its same-UID broker unmaskable `SIGSTOP` and suspend all live
cleanup. The client must connect to an already authenticated service authority
outside the target's signal permission domain.

The privileged service must permanently drop the launcher/target to the
authenticated client's nonroot real UID before untrusted exec while keeping
the broker at an identity the target cannot signal. It must accept only a held,
policy-authorized executable and bounded canonical arguments/environment; it
cannot expose arbitrary privileged spawn, signal, task-port, or filesystem
operations. A watchdog above a stopped or crashed broker must terminate the
broker, relying on XNU's tracer-exit rule to kill the exact tracee. Restart must
not reconstruct authority from a PID. The design must also resolve the launchd
bootstrap namespace restored for libxpc: delegated XPC work must either be
prevented or explicitly excluded from the owned-principal claim.

This is a deployment boundary, not a new public session or region API. The
backend reads the service name and designated code requirement from
`NativeIPCSupervisorMachService` and
`NativeIPCSupervisorCodeRequirement` in the signed main-bundle metadata. It
does not accept either value from an environment variable or session caller.
Missing metadata or a
missing, unavailable, unsigned, wrongly signed, or misconfigured service fails
closed with `BackendUnavailable` or a bounded native construction failure. The
direct-spawn prototype remains private test machinery and is never an automatic
fallback.

The current source-only boundary accepts an authentication-only first frame and
then one bounded spawn request tied to the exact verified Mach audit trailer,
fresh client/service nonces, a unique connection generation, and a monotonic
sequence. The authenticated peer retains the complete 32-byte token, so any
exec/PID-version/credential transition between hello and spawn changes peer
identity even when snapshot-like fields still match. The token is identity
evidence only, never termination authority. A one-shot client state accepts those service facts only from an
exact-message-authenticated reply. The request carries one absolute Darwin
`CLOCK_UPTIME_RAW` deadline, the same clock basis as Rust `Instant`, so transport
delay cannot restart its budget. It resolves only an immutable installed policy;
callers cannot select an executable path or request PID, signal, task, or
filesystem effects. The
watchdog model registers a fresh opaque session handle before execution and
retains linear exact broker authority until an implementation returns a typed
reap proof. All terminal causes converge on exact terminate-and-reap cleanup,
and a failed attempt retains the same authority for retry. The launcher
transition consumes the exact trace-established session and validated installed
target, prepares the complete `execve` request before mutation, clears
supplementary groups, permanently changes real/effective/saved UID and GID to
the authenticated nonroot client, proves root cannot be regained, lowers hard
and soft `RLIMIT_NPROC` to one, and immediately execs; any failure after the
first mutation aborts. A nested-tracer native test further proves that an outer
watchdog can consume a broker proof stop, recover after the hostile target stops
that broker, exact-`PT_KILL`/reap it, and rely on tracer exit to remove the exact
target. These are source and same-UID kernel-mechanism invariants only. They do
not prove a root launch, signed installation, UID separation, or delegation
policy.

Public XPC can authenticate dynamic code from an exact message, but its public
credential accessors expose connection-time UID/GID snapshots. That is weaker
than this contract's exact-message credential continuity. The candidate runtime
transport is therefore a launchd-advertised raw Mach service: the kernel's Mach
audit trailer supplies the exact message token, BSM decoding supplies UID/GID,
and Security validates dynamic code from the same audit token. No private
`xpc_dictionary_get_audit_token` dependency is permitted. XPC peer PIDs and all
other numeric PIDs remain diagnostic only, never lifecycle capabilities.

Ignored native probes confirm the mechanism boundary without claiming
deployment completion. The initial certificate-free corpus proves that a
transient per-user launchd Mach service
delivers exact audit trailers in both directions and cleans up by exact label;
Security accepts a 32-byte native audit token for `kSecGuestAttributeAudit`,
validates the ad-hoc code's designated requirement, and rejects a one-byte
token mutation plus 31/33-byte values. A separately bounded stale-token probe
reaped the subject first and then received `kPOSIXErrorESRCH` in all five runs.
Another probe retained image A's token while the same live PID execed image B;
100 clean-worker repetitions rejected the pre-exec token with
`errSecCSNoSuchCode`. An earlier fork-without-exec lookup worker intermittently
crashed after the parent initialized Security.framework, reinforcing that
workers must be pre-created safely or enter through a clean exec image rather
than call the framework in a post-initialization fork child. A separate local
Developer ID Application matrix signs distinct hardened-runtime service and
client Mach-O images. From the request's kernel audit trailer, the per-user
launchd service accepts the exact client designated requirement, rejects a
same-Team-ID image with the wrong identifier and an ad-hoc image with the right
identifier (`errSecCSReqFailed`), while unsigned and post-signing-mutated
clients are killed before authorization. Twenty repeated matrices covered 100
client launches, and 100 signed exact-token/exec repetitions also passed; no
probe process, launchd job, plist, or log survived.
That negative result is characterization, not a liveness guarantee:
Security.framework does not provide a cancellable, caller-deadline-bound lookup,
so the production watchdog must isolate every dynamic guest lookup in a
disposable worker process. These probes do not prove a privileged LaunchDaemon,
root/nonroot separation, an immutable production requirement, downstream
deployment, or notarization.

Primary platform references:

- [Mach message audit trailers](https://developer.apple.com/documentation/kernel/mach_msg_audit_trailer_t)
- [Audit-token Security guest attribute](https://developer.apple.com/documentation/security/ksecguestattributeaudit)
- [XPC peer PID reuse warning](https://developer.apple.com/documentation/xpc/xpc_connection_get_pid%28_%3A%29)
- [Code identity from the audit token attached to an XPC message](https://developer.apple.com/documentation/security/seccodecreatewithxpcmessage%28_%3A_%3A_%3A%29)
- [launchd on-demand ownership](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html)
- [setsid process-group escape semantics](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/setsid.2.html)

## Why direct spawn cannot satisfy the contract

The coordinator process cannot make the following race safe using only the
public direct-spawn primitives available to this crate:

1. `posix_spawn` returns a numeric PID.
2. The child exits, is consumed by process-global `SIGCHLD` auto-reap or an
   unrelated waiter, and its PID becomes reusable.
3. The library signals that numeric PID while attempting deadline cleanup.

The library cannot take exclusive ownership of process-global signal
disposition or every waiter in its host application. `waitpid(WNOHANG)`,
`proc_pidpath`, a process-group ID, or `kqueue` exit observation cannot turn the
later numeric signal into an exact capability. `POSIX_SPAWN_START_SUSPENDED`
does permit a narrower private construction: while the fresh child cannot run,
the parent captures a task-name right, reads its `TASK_AUDIT_TOKEN`, commits the
lifecycle owner, and resumes or kills that exact execution with private
`proc_signal_with_audittoken`. Native tests prove silent-before-bootstrap
direct-child cleanup for that prototype.

That construction is not a public solution. The token-addressed signal is
private SPI; the token names only one execution; and a real `exec` invalidated
both the old token and retained task-name right in the native probe. The rights
also disappear when the spawning process crashes, and exact direct-child
termination does not contain a descendant that calls `setsid`. A task-control
port could provide stronger live-process authority, but the normative contract
forbids transferring or retaining it.

A trusted cooperative launcher improves this substantially without a task
port. It receives the broker's complete audit token and real launchd bootstrap
right over the authenticated private Mach channel, restores that bootstrap
right, captures and compares the broker's task-name audit token and PPID, calls
`PT_TRACE_ME`, revalidates, sends a ready marker, and raises `SIGSTOP`. The
broker proves it owns the trace relationship by consuming and continuing that
stop. The launcher installs hard and soft `RLIMIT_NPROC=1`, sends a second
marker, and immediately execs. The broker consumes the exec `SIGTRAP` before
the target's first instruction and continues it.

While the broker runs, exact termination is `SIGSTOP` followed by parent-only
`waitpid(WUNTRACED)` and `PT_KILL`; the sole unreaped-child relationship pins
the PID throughout. If the broker exits, XNU kills and reaps its tracee. The
hard nonroot process limit survives exec and native tests show direct fork and
`posix_spawn` fail with `EAGAIN`. The backend uses a mutex waiter gate so its
background reaper cannot consume either handshake stop.

This still cannot be enabled from a same-UID library-spawned broker. Native
adversarial testing proves the target can stop that broker indefinitely with
`SIGSTOP`, suspending deadline and death-pipe handling. An outer authority can
kill the stopped broker, after which XNU kills the exact tracee, so the safe
recovery primitive exists but must live in an independently privileged
watchdog. In addition, restoring launchd bootstrap is required to keep libxpc
from hanging before `main` and permits delegated XPC work outside the rlimit;
cooperative tracing also invokes XNU code-signing debug relaxation. These are
the remaining deployment and principal-boundary blockers.

## Minimum candidate contract

Before the privileged authority and delegation gaps can be resolved, a raw
Mach-service candidate must satisfy all of these conditions:

1. The service is bundled or installed as a signed launchd job with a
   private Mach service. No global library-created Mach service is registered.
2. Authentication precedes every spawn or lifecycle effect. The client first
   sends a bounded authentication-only message containing a protocol version
   and fresh nonce, but no command, image, environment, or authority. The
   service requests an audit trailer and decodes UID/GID from that exact kernel
   token. The permanent watchdog's lifecycle loop performs no Security.framework
   call, filesystem lookup, or installed-catalog lookup. Instead it copies one
   fixed, bounded job containing the complete 32-byte token, exact retained-wire
   frame digest, worker generation, one live-job identifier, and original
   absolute `CLOCK_UPTIME_RAW` deadline into one of a fixed number of
   pre-created, one-job authentication-worker processes. A non-serializable
   linear receipt binds the exact private reply endpoint to that job. Only that
   worker resolves the
   dynamic code through
   `SecCodeCopyGuestWithAttributes(kSecGuestAttributeAudit)` and checks it with
   `SecCodeCheckValidity` against an immutable installed client requirement.
   Its bounded result must echo every binding exactly and arrive before the
   original deadline. No client-supplied connection generation enters this
   pre-authentication job or its capacity accounting. The permanent authority
   uses only bounded nonblocking
   reap progress; the result cannot mint peer authority until a typed exact
   worker-reap proof exists. A late, replayed, mismatched, or wrong-generation
   result retires the worker without creating or selecting connection state.
   Saturation rejects immediately rather than
   queueing. A wedged worker retains exact unreaped-child authority and is
   exactly terminated and reaped before replacement, without restarting the
   caller deadline. Slot identity plus a strictly increasing worker generation
   makes old endpoints/results unreachable without an unbounded tombstone set.
   The current source now makes the private endpoint literal rather than
   documentary: the pool moves one `OwnedFd` request writer and result reader
   into the dispatched linear token, writes the 152-byte job atomically, closes
   the request writer, and accepts exactly 200 result bytes plus EOF. EINTR yields
   immediately, EAGAIN retains the receipt, and every I/O/deadline/reap-pending
   outcome carries the exact worker slot/generation for cancellation or retry.
   Its sole waiter signals only while the direct child or unreaped zombie pins
   the PID; `ECHILD` aborts without signaling, and only normal exit status zero
   can authorize the result.
   The service then returns both the client
   nonce and a fresh service nonce. The client performs the symmetric
   audit-token code check on that exact reply against the requirement pinned in
   its signed bundle. Only then may the service accept a spawn request bound to
   both nonces and that connection generation. No numeric PID is used as
   identity or authority, and dynamic guest validation is never cached across
   messages or audit tokens.

The raw Mach boundary has an additional receive-shape obligation. Darwin does
not provide a descriptor-free receive option: a hostile complex message can
transfer rights into the service namespace before validation. The adapter must
reject complex input, immediately call `mach_msg_destroy` on the complete
received shape, and prove that no transferred right is inspected, retained, or
forwarded. In particular it never deliberately requests, transfers, or uses a
task-control port. If the normative prohibition is interpreted to forbid even
this attacker-forced transient insertion before destruction, raw Mach cannot
satisfy that stronger reading and the public backend must remain fail-closed.
The backend-private receiver now proves the implementable portion: exact audit
trailer extraction, exact logical receive limits, immediate complex/malformed
destruction, oversized-head progress without `MACH_RCV_LARGE`, and linear
send-once reply ownership. It routes hello/spawn state only after validation and
   exact worker reap. A receive-only spawn-result decoder also authenticates
   exact service freshness before revealing only an opaque handle or coarse
   failure. The source model now assigns the fresh opaque session before broker
   creation, accepts only one atomic launch-plus-exact-broker result, and keeps
   an armed session-specific watchdog obligation through launch transfer, trace
   binding, Ready encoding, and the exact send-once reply. Drop, substitution,
   deadline, encoding, and recoverable-send paths emergency exact-reap the
   bound broker before returning; an indeterminate Mach send exact-cleans and
   then fail-stops. A successful zero-timeout send commits the authenticated
   reverse FD 5 RESUME; only successful RESUME disarms the Ready guard. Reverse
   failure exact-cleans before dropping the retained endpoint. The obligation
   does not borrow the whole table, so an unrelated
   session can still be terminated while one launch is pending; table shutdown
   also exact-cleans entries retained by outstanding obligations. Broker
   authority must arrive dormant: the exact entry is inserted first, then one
   nonblocking/no-callback activation releases the future fixed start gate;
   activation failure exact-reaps and tombstones before returning. A revocable
   launch permit exposes no owned launch authority and holds no long-lived
   table borrow, so same-session cleanup can reap it. Immediately before the
   no-callback credential-drop/exec transition, a short guard revalidates and
   pins the exact live registration; copied preparation bytes cannot commit
   after cleanup.
   Native tests exercise real Mach Ready delivery and invalid-destination
   cleanup. Raw ingress uses separate service receive and authentication caps;
   Spawn authentication is bounded by the earlier of the fixed cap and the
   original absolute wire deadline. Darwin's required inline-message alignment
   is stripped only when every padding byte is zero, leaving the exact logical
   record for the worker digest and later decoding. The deadline is rechecked immediately before the send, but that
   userspace check and kernel entry are not one atomic kernel deadline action.
   This remains source/native mechanism evidence, not an installed privileged
   service, packaged broker/control loop, or separately packaged, signed, and
   root-installed clean-exec Security-worker artifact. The fixed source entry
   and spawner exist but are not installation evidence.
3. The service/watchdog is independently privileged so target code running as
   the client cannot signal-stop it. Privilege is retained only by the minimal
   broker/watchdog; the launcher permanently drops real/effective/saved IDs to
   the authenticated nonroot client identity before untrusted exec. It launches
   only a held, installed-policy-authorized non-setid image, constructs
   environment variables from a fixed allowlist, and rejects loader injection
   and privilege-bearing variables. A privileged daemon accepting arbitrary
   caller-selected executable or signal policy is nonconforming.
4. The service accepts only a fixed, bounded canonical request containing an
   installed policy ID, bounded additional argv/allowlisted environment values,
   the authenticated connection freshness facts, and one caller deadline. The
   immutable signed/root-owned catalog—not the caller—selects the executable,
   argv0, held-image/code identity, client requirement, and target identity. It
   accepts no caller path, PID, signal, task, filesystem operation, or signing
   policy as authority.
5. Before the helper can run, the service creates a fresh unguessable session
   identifier, installs the complete lifecycle entry and watchdog relationship,
   creates the private Mach bootstrap endpoint, and establishes the broker as
   the sole helper waiter/tracer.
6. The service keeps normal child-wait semantics: it does not use `SIGCHLD`
   auto-reap, has no broad competing waiter, and does not remove the lifecycle
   entry until the exact child is reaped. An exited-but-unreaped child pins its
   PID. One per-entry serialization domain covers both (a) signal selection and
   the signal syscall and (b) the reaping `waitpid` call and immediate
   signal-authority tombstone. The waiter holds that domain through reap and
   tombstoning, so no concurrent path can observe a reaped entry as signalable.
   The source-only auth-worker boundary now rejects non-main or already-threaded
   initialization, nondefault SIGCHLD, and `SA_NOCLDWAIT`, then installs
   canonical default disposition and blocks SIGCHLD for subsequently inherited
   thread masks. The token is one-shot and non-sendable, but it cannot prove
   absence of future broad waiters. The fixed source spawner creates the private
   one-job pipes and owns the whole `posix_spawn`
   success-to-armed-direct-child-authority sequence. The paired clean-exec entry
   validates the fixed process ABI and dynamically loads Security.framework
   only inside the worker; native composition reaches exact status-zero reap
   without statically linking Security/CoreFoundation into the surrounding
   binary. This is not yet deployable sole-waiter evidence: the worker is not a
   separately signed, root-installed, replacement-resistant artifact, the
   service does not verify its immutable policy constants, and a complete
   process-wide no-competing-waiter policy is not wired or proven.
7. The signed trusted launcher authenticates its broker, establishes
   `PT_TRACE_ME` with an explicit stopped handshake, drops to the nonroot client
   identity, installs hard `RLIMIT_NPROC=1`, and execs only after the lifecycle
   table, disconnect hook, held image, endpoint, nonce, and watchdog are
   committed. The broker consumes the exec trap before target code runs.
8. Client requests refer only to the opaque session identifier. The service
   resolves a signal under the live lifecycle entry; no wire command accepts a
   numeric helper PID, process-group ID, task port, or Mach task name.
9. Cancellation, deadline expiry, malformed traffic, client disconnect, broker
   stop/crash, and ambiguous transfer all request termination. A live broker
   uses stop/`PT_KILL`/reap; the independent watchdog kills a stopped/crashed
   broker and relies on the kernel tracer-exit cascade for the exact tracee. A
   terminal reply is sent only after observed cleanup or carries explicit
   incomplete native facts. Session identifiers are never reused.
10. The first helper Mach message binds its complete audit token, not only its
   PID. Every later helper message must carry the same execution identity.
   A changed PID version or image is terminal and asks the supervisor to clean
   up through the parent-owned lifecycle entry, which remains valid across
   helper `exec`.
11. The service transfers only the specific bootstrap/control and memory-entry
    rights required by the canonical protocol. It never transfers a task port,
    and every installed or malformed right has immediate RAII ownership.
12. Service invalidation is reported distinctly from helper exit. A live
    service cleans every session associated with a disconnected client. Native
    evidence must prove client death, broker stop, broker crash, and service
    restart behavior without reconstructing authority from a PID. Delegated
    launchd/XPC processes must be forbidden or explicitly outside the lifecycle
    principal and capability-revocation claim.
13. The service name, signing requirement, entitlements, bundle placement, and
    launchd configuration are release inputs checked by packaging and native
    conformance; crates.io source packaging alone is not sufficient evidence.

## Conditional exactness of the traced-launcher core

Let one broker lifecycle entry own `(session_id, tracee_pid, child_wait,
bootstrap_endpoint, image, nonce, client_generation)` and let an independent
watchdog own the broker.

- Before the launcher resumes, the entry and watchdog relationship exist, so
  there is no running untrusted target without a cleanup owner.
- The launcher's full-token/PPID checks and explicit `PT_TRACE_ME`/`SIGSTOP`
  proof establish the intended parent as the kernel tracer before untrusted
  exec. A mutex waiter gate gives the broker exclusive ownership of that stop
  and the later exec trap.
- `exec` changes the execution token but preserves the trace relationship. XNU
  stops the new image before its first target instruction. The broker consumes
  that trap and only then permits target execution.
- While the direct child is unreaped, a live tracee owns the PID and a naturally
  exited tracee pins it as a zombie. Stop plus parent-only `PT_KILL` therefore
  cannot target a replacement. Broker exit makes XNU kill the exact tracee.
- Hard `RLIMIT_NPROC=1` is installed before exec and cannot be raised by the
  nonroot target; native fork/spawn attempts fail with `EAGAIN`.
- The terminal transition removes the opaque session entry only after observed
  cleanup. A replayed identifier has no authority and fails closed.

These statements are implemented and natively tested for the backend-private
core. They do not prove the deployment boundary. A same-UID tracee can stop its
broker indefinitely, so an independent privileged watchdog must remain outside
the target's signal permission domain and kill a stopped broker. The launcher
must permanently drop to the authenticated nonroot client identity, and the
service must prove it is not a confused deputy. Restored launchd/XPC bootstrap
also creates delegation outside the direct tracee/rlimit principal. Until those
properties are implemented and tested, this is a conditional core proof rather
than public-session evidence.

## Residual public-API evidence

The earlier direct-kill investigation decomposed the requirement into an exact
reuse-proof termination identity, crash survival, and escape-proof
containment. Its individual observations remain relevant, but the traced-child
relationship composes around two earlier assumptions: parent-only `PT_KILL`
provides exact action without a kill-by-unique-ID API, and tracer exit makes the
kernel kill the tracee. The remaining failure is independent authority against
a hostile same-UID tracee plus delegated work outside that relationship:

1. **No public reuse-proof kill identity.** The kernel keeps a never-reused
   64-bit process identity (`p_uniqueid`, with `p_idversion` for exec
   generations), but the retrieval flavor `PROC_PIDUNIQIDENTIFIERINFO` (17)
   lives only in the private header `bsd/sys/proc_info_private.h`; the shipped
   SDK's `sys/proc_info.h` omits the structure and its flavor numbering skips
   17–18. No kill/terminate-by-unique-id or compare-and-kill primitive exists
   on any terminate path. `proc_terminate` in `libproc.h` addresses a bare
   reusable `pid_t` and that header self-describes its contents as private
   interfaces subject to change. `kill(2)` and every launchd kill are PID- or
   process-group-addressed; the PID space is small (`PID_MAX` 99999, wraps to
   100), so verify-then-kill by numeric PID remains a documented TOCTOU
   vulnerability class. The audit token (`audit_token_t`, whose `val[7]` is the
   PID version) is Apple's sanctioned fix for PID races. The private prototype
   can obtain it before resume by calling public Mach entry points
   `task_name_for_pid` and `task_info(TASK_AUDIT_TOKEN)`, but no public signal
   primitive accepts that identity. The token-addressed signal it uses while
   its coordinator lives (`proc_signal_with_audittoken`) sits behind the
   private-interface disclaimer in `libproc.h`. Native testing also found that
   an ordinary `exec` invalidates the retained task-name right, and a restarted
   supervisor cannot reconstruct the original token from a numeric PID, so the
   construction closes neither the public nor crash path.
2. **Process-group cleanup remains inexact, but tracer-exit cleanup is exact.**
   launchd (PID 1) survives a supervisor crash, and bundle-embedded XPC
   services are launched, restarted, and killed by launchd rather than the
   client. `launchd.plist(5)`
   documents job-death cleanup as process-group scoped ("kills any remaining
   processes with the same process group ID as the job",
   `AbandonProcessGroup`), with no per-descendant or unique-identifier
   tracking; a helper that calls `setsid(2)` or `setpgid(2)` definitionally
   leaves the kill set, and Apple guidance (TN2083 era) historically
   recommended exactly that call to survive job death. Cooperative tracing
   supplies a different exact edge: XNU kills a live tracee when its tracer
   exits. An independent watchdog can therefore kill a stopped broker and let
   the kernel terminate that broker's exact tracee; native tests prove the
   kernel edge. Its source ownership state is modeled, but no privileged
   watchdog process is implemented or installed.
3. **No complete public principal containment.** App Sandbox confinement survives
   `exec` (a differently-sandboxed image traps at profile-set time) and a
   spawned child of a sandboxed process inherits the static sandbox without
   needing its own entitlement, but sandboxed processes may `fork`/`posix_spawn`
   freely: the public entitlement surface restricts resources (files, network,
   hardware, personal data), not process creation, and no supported profile
   denies fork. Custom SBPL no-fork profiles exist only behind the deprecated
   `sandbox_init(3)`/`sandbox-exec` interfaces. Observation mechanisms do not
   close the gap: `kqueue` `EVFILT_PROC` attaches by numeric PID, the kqueue
   cannot be transferred or inherited (kernel excludes `DTYPE_KQUEUE` from
   `SCM_RIGHTS` internalization), watches die with the watcher, and
   `NOTE_TRACK` fork-following has been unsupported since macOS 10.5; Endpoint
   Security's `ES_EVENT_TYPE_NOTIFY_EXIT` is public SDK surface but requires
   the restricted `com.apple.developer.endpoint-security.client` entitlement
   plus root and is notify-only. Among Mach task-port flavors, `task_terminate`
   accepts only the full control port (MIG conversion rejects read, inspect,
   and name ports), so no lesser flavor provides termination either.

Consequently the earlier blanket impossibility statement is narrowed: public
`ptrace` and rlimit mechanisms provide an exact no-task-port direct-child core,
including broker-crash cleanup, but a same-UID deployment is not live against
hostile `SIGSTOP`, and restored launchd/XPC delegation is not contained by the
rlimit. R8.6 and 6d remain architecture-blocked until the independent
privileged service/watchdog and delegation policy are implemented and proven;
the public macOS composition remains fail-closed.

Additional primary references for this section:

- [XPC services lifecycle under launchd](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html)
- [App Sandbox inheritance and spawn behavior (Apple DTS)](https://developer.apple.com/forums/thread/747499)
- [Resolving App Sandbox inheritance problems (Apple DTS)](https://developer.apple.com/forums/thread/706390)
- [App Sandbox entitlement surface](https://developer.apple.com/documentation/xcode/configuring-the-macos-app-sandbox)
- [Endpoint Security exit notification](https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_exit)
- `launchd.plist(5)`, `kqueue(2)`, `setsid(2)` man pages; xnu
  `bsd/sys/proc_info_private.h`, `bsd/kern/kern_prot.c`
  (`set_security_token_task_internal`), `osfmk/mach/task.defs`
  (`task_terminate`), `osfmk/kern/task.c` (`task_name_for_pid`),
  `osfmk/kern/task_info.c` (`TASK_AUDIT_TOKEN`), and
  `bsd/kern/kern_descrip.c` (`fg_sendable`).

## Required native evidence before enabling public macOS

- signed positive service and wrong/unsigned/re-signed service rejection;
- absent service, launch failure, connection interruption, invalidation, and
  restart under the original absolute deadline;
- silent helper before bootstrap, helper exit before reply, and helper `exec`
  before and after authentication;
- packaged signed launcher/broker tracing under hardened runtime, including the
  code-signing relaxation boundary and exec trap before target instructions;
- permanent launcher/target UID drop, target attempts to signal-stop the
  broker/watchdog, and watchdog recovery of a deliberately stopped broker;
- hard-limit fork/`posix_spawn` denial before and after exec, root exclusion,
  and launchd/XPC delegation characterization;
- process-global hostile `SIGCHLD` settings in the client, demonstrating that
  only the service parent owns child waiting;
- 0/1/2/16 and extra Mach rights, every XPC/Mach truncation and type mutation,
  replayed/unknown session IDs, wrong client, wrong service, and wrong helper
  audit token/PID version;
- first/middle/final spawn, table insertion, endpoint transfer, resume, signal,
  wait, reap, and reply failures with exact VM/port/process baselines;
- client crash/disconnect, broker stop/crash, and service/watchdog crash
  characterization without claiming cleanup that cannot be observed;
- exact tracer-exit cleanup across watchdog recovery and service restart,
  without reconstructing signal authority from a numeric PID;
- 10,000-cycle native Apple Silicon lifecycle/port baseline, strict warning
  freedom, packaged application/XPC-service verification, and exact hosted plus
  release-host evidence.

Until the privileged service/watchdog, signed launcher packaging, delegation
policy, and those tests exist, R8.6 and 6d remain architecture-blocked, and the
public macOS facade remains fail-closed.
