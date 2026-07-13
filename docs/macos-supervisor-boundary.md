# macOS exact-lifecycle supervisor boundary

Status: candidate boundary and negative result. A preinstalled signed XPC
service solves the direct client's pre-bootstrap gap only while that service
remains alive; it does not by itself preserve exact lifecycle authority across
a service crash. No XPC service, bundle, entitlement, signing requirement, or
public macOS session adapter is implemented by this document. The architecture
milestone and public macOS spawn/bootstrap remain blocked.

A dedicated primary-source investigation (2026-07-13, recorded in project
tracking) examined every public candidate for the crash-surviving gap and
confirmed the negative result. The findings are recorded in
[Public-API impossibility evidence](#public-api-impossibility-evidence) below.

## Decision

Any viable production macOS session adapter requires an authority that exists
before untrusted code runs. The current candidate is a preinstalled, signed,
`launchd`-advertised XPC service. A broker that the library starts with
`posix_spawn` is not sufficient: it merely moves the same silent-before-first-
message cleanup problem from the untrusted helper to the broker. The client
must connect to a service already represented by a launchd-owned Mach service;
it must not create the supervisor process itself.

That service is necessary but not sufficient. If it crashes, its in-memory
session table and parent-only wait authority disappear, and its children are
reparented. A restarted service cannot reconstruct an exact capability from a
PID or session identifier. Public macOS therefore cannot be enabled until a
documented OS-enforced containment mechanism survives the service crash,
cannot be escaped by the helper, and gives a surviving trusted authority exact
termination and reap responsibility.

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

Apple documents that a named XPC Mach service must be advertised in a
`launchd.plist`, that the connection is one-to-one, and that service launch is
on demand. Apple also explicitly warns that the PID returned for an XPC peer
can become stale and be reused. Therefore neither the service connection PID
nor a helper PID is a lifecycle capability.

Primary platform references:

- [XPC Mach-service connection](https://developer.apple.com/documentation/xpc/xpc_connection_create_mach_service%28_%3A_%3A_%3A%29)
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
`proc_pidpath`, a process-group ID, `kqueue` exit observation, or
`POSIX_SPAWN_START_SUSPENDED` can narrow windows but cannot turn the later
numeric signal into an exact capability. A task port would do so, but the
normative contract forbids transferring or retaining task-port authority.

An audit token is exact for one execution because it includes a PID version,
but it arrives only with the first audit-bearing message. It therefore cannot
clean up a child that stays silent before bootstrap. A later `exec` changes the
PID version, so a retained token also cannot terminate the new execution.

A library-spawned supervisor has the same unsolved first step. Trusting it to
send a prompt first message is not a bounded cleanup proof. Only a connection
to an independently installed, authenticated service avoids spawning an
unowned process before the lifecycle boundary exists.

## Minimum candidate contract

Even before the crash-surviving containment gap can be resolved, an XPC
candidate must satisfy all of these conditions:

1. The service is bundled or installed as a signed launchd/XPC job with a
   private Mach service. No global library-created Mach service is registered.
2. Authentication precedes every spawn or lifecycle effect. The client first
   sends a bounded authentication-only message containing a protocol version
   and fresh nonce, but no command, image, environment, or authority. The
   service derives the sender's dynamic code with
   `SecCodeCreateWithXPCMessage`, checks it with `SecCodeCheckValidity` against
   an installed client requirement, and returns both the client nonce and a
   fresh service nonce. The client performs the same two calls on that reply
   against the requirement pinned in its signed bundle. Only then may the
   service accept a spawn request bound to both nonces and that XPC connection
   generation. A numeric `xpc_connection_get_pid` result is diagnostic only.
3. The service is a nonprivileged same-user agent/service: its effective user
   and group match the authenticated client, and it has no root, set-ID, or
   entitlement capability that would make it a confused deputy. It launches
   only a held, policy-authorized non-setid image, applies the requested
   identity/signing rule, constructs environment variables from a fixed
   allowlist, and rejects loader-injection and other privilege-bearing
   variables. A privileged launch daemon accepting arbitrary executable policy
   is nonconforming.
4. The service accepts only a fixed, bounded canonical request containing the
   command, explicit argv/environment, held-image facts, nonce, caller deadline,
   and requested identity/signing policy. It accepts no caller PID as authority.
5. Before the helper can run, the service creates a fresh unguessable session
   identifier, installs the complete lifecycle entry, creates the private Mach
   bootstrap endpoint, and establishes itself as the sole helper waiter.
6. The service keeps normal child-wait semantics: it does not use `SIGCHLD`
   auto-reap, has no broad competing waiter, and does not remove the lifecycle
   entry until the exact child is reaped. An exited-but-unreaped child pins its
   PID. One per-entry serialization domain covers both (a) signal selection and
   the signal syscall and (b) the reaping `waitpid` call and immediate
   signal-authority tombstone. The waiter holds that domain through reap and
   tombstoning, so no concurrent path can observe a reaped entry as signalable.
7. Spawn starts suspended or otherwise cannot run untrusted code until the
   lifecycle table, cleanup-on-client-disconnect hook, held image, endpoint,
   and nonce are committed. Resume is a single audited transition.
8. Client requests refer only to the opaque session identifier. The service
   resolves a signal under the live lifecycle entry; no wire command accepts a
   numeric helper PID, process-group ID, task port, or Mach task name.
9. Cancellation, deadline expiry, malformed traffic, client disconnect, and
   ambiguous transfer all request termination and exact wait/reap. A terminal
   reply is sent only after reap or carries explicit incomplete native cleanup
   facts. Session identifiers are never reused.
10. The first helper Mach message binds its complete audit token, not only its
   PID. Every later helper message must carry the same execution identity.
   A changed PID version or image is terminal and asks the supervisor to clean
   up through the parent-owned lifecycle entry, which remains valid across
   helper `exec`.
11. The service transfers only the specific bootstrap/control and memory-entry
    rights required by the canonical protocol. It never transfers a task port,
    and every installed or malformed right has immediate RAII ownership.
12. Service invalidation is reported distinctly from helper exit. A live
    service cleans every session associated with a disconnected client. A
    service crash is not exact cleanup: the candidate remains nonconforming
    until separate OS-enforced containment survives that crash, prevents helper
    escape, and performs exact termination and reap under a surviving authority.
13. The service name, signing requirement, entitlements, bundle placement, and
    launchd configuration are release inputs checked by packaging and native
    conformance; crates.io source packaging alone is not sufficient evidence.

## Conditional exactness while the service lives

Let one supervisor lifecycle entry own `(session_id, child_pid, child_wait,
bootstrap_endpoint, image, nonce, client_generation)`.

- Before resume, the entry exists and the XPC disconnect cleanup hook owns it,
  so there is no running untrusted helper without a cleanup owner.
- While the child is running, `child_pid` identifies that child. If it exits,
  the supervisor's exclusive unreaped wait state prevents PID reuse. Signal
  selection and the signal syscall run in the same per-entry serialization
  domain. The terminal waiter holds that domain across the reaping `waitpid`
  and conversion to a nonsignalable tombstone before any concurrent operation
  can proceed. Therefore no path can signal a later process through the entry.
- `exec` changes the helper execution identity but not the parent/child wait
  entry. Full audit-token comparison rejects the new execution on the control
  channel, while supervisor termination remains exact because it is based on
  the pinned child entry rather than the stale audit token.
- The terminal transition removes the entry only after exact wait/reap. A
  replayed session identifier then has no authority and fails closed.
- The client authenticates the supervisor from the audit token attached to an
  XPC message and never treats an XPC PID as authority. Thus launch-on-demand or
  service restart cannot silently substitute a differently signed supervisor.

These steps establish the ordinary and concurrent path only while the service
lives. They do not establish the required crash path. On service crash, the
helper is reparented and the table and wait relationship are lost. The
installed `launchd.plist(5)` documentation says launchd kills remaining
processes with the job's process-group ID, but that is not sufficient for this
hostile-helper model: a non-group-leader helper can call `setsid` to create a
new session and process group, and the current direct-spawn contract already
does so. No documented public SDK capability found in this investigation both
survives the parent crash and provides exact, non-task-port helper authority.
Consequently this is a narrowed conditional argument, not a complete boundary
proof or an implementation claim.

## Public-API impossibility evidence

The crash-surviving requirement decomposes into three properties that must
hold simultaneously: an exact reuse-proof identity bound to the termination
primitive, a termination authority that survives the supervisor crash, and an
escape-proof containment set. On current macOS (Apple Silicon, shipped SDK),
each property fails independently under public APIs:

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
   PID version) is Apple's sanctioned fix for PID races, but it is an
   IPC-sender identity available only from a live message or connection. The
   token-addressed signal that this crate's private prototype uses while its
   coordinator lives (`proc_signal_with_audittoken`) sits behind the same
   private-interface disclaimer as the rest of `libproc.h`, and a token cannot
   be reconstructed by a restarted supervisor holding only a numeric PID, so
   neither closes the crash path.
2. **The only crash-surviving authority cleans up inexactly.** launchd (PID 1)
   is by construction the only termination authority that survives a
   supervisor crash, and bundle-embedded XPC services are launched, restarted,
   and killed by launchd rather than the client. But `launchd.plist(5)`
   documents job-death cleanup as process-group scoped ("kills any remaining
   processes with the same process group ID as the job",
   `AbandonProcessGroup`), with no per-descendant or unique-identifier
   tracking; a helper that calls `setsid(2)` or `setpgid(2)` definitionally
   leaves the kill set, and Apple guidance (TN2083 era) historically
   recommended exactly that call to survive job death. Termination of an XPC
   service when its *client* crashes is not documented as a guarantee; only
   the reverse direction (service crash observed as connection invalidation)
   is.
3. **No public escape-proof containment.** App Sandbox confinement survives
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

Consequently no composition of documented public mechanisms satisfies
"OS-enforced, crash-surviving, exact containment without task ports". The
strongest supported approximation — launchd-owned XPC service lifecycle plus
inherited sandbox confinement plus `EVFILT_PROC`/Endpoint Security exit
observation plus post-hoc identity verification — is crash-surviving and
observable but not exact: it can neither atomically close the verify-then-kill
race nor prevent process-group escape. R8.6 and 6d therefore remain
architecture-blocked and the public macOS composition remains fail-closed
until Apple ships a public exact-identity termination or containment
primitive.

Additional primary references for this section:

- [XPC services lifecycle under launchd](https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingXPCServices.html)
- [App Sandbox inheritance and spawn behavior (Apple DTS)](https://developer.apple.com/forums/thread/747499)
- [Resolving App Sandbox inheritance problems (Apple DTS)](https://developer.apple.com/forums/thread/706390)
- [App Sandbox entitlement surface](https://developer.apple.com/documentation/xcode/configuring-the-macos-app-sandbox)
- [Endpoint Security exit notification](https://developer.apple.com/documentation/endpointsecurity/es_event_type_notify_exit)
- `launchd.plist(5)`, `kqueue(2)`, `setsid(2)` man pages; xnu
  `bsd/sys/proc_info_private.h`, `bsd/kern/kern_prot.c`
  (`set_security_token_task_internal`), `osfmk/mach/task.defs`
  (`task_terminate`), `bsd/kern/kern_descrip.c` (`fg_sendable`).

## Required native evidence before enabling public macOS

- signed positive service and wrong/unsigned/re-signed service rejection;
- absent service, launch failure, connection interruption, invalidation, and
  restart under the original absolute deadline;
- silent helper before bootstrap, helper exit before reply, and helper `exec`
  before and after authentication;
- process-global hostile `SIGCHLD` settings in the client, demonstrating that
  only the service parent owns child waiting;
- 0/1/2/16 and extra Mach rights, every XPC/Mach truncation and type mutation,
  replayed/unknown session IDs, wrong client, wrong service, and wrong helper
  audit token/PID version;
- first/middle/final spawn, table insertion, endpoint transfer, resume, signal,
  wait, reap, and reply failures with exact VM/port/process baselines;
- client crash/disconnect and service crash characterization without claiming
  cleanup that cannot be observed;
- service-crash containment that is OS-enforced, exact, survives restart, and
  cannot be escaped with `setsid`, `setpgid`, `fork`, or `exec`;
- 10,000-cycle native Apple Silicon lifecycle/port baseline, strict warning
  freedom, packaged application/XPC-service verification, and exact hosted plus
  release-host evidence.

Until a crash-surviving containment design and those tests exist, R8.6 and 6d
remain architecture-blocked, and the public macOS facade remains fail-closed.
