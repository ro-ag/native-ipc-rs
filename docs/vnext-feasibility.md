# vNext phase-0 native feasibility record

This record resolves mechanism questions before implementation. It separates
safe-code ownership, kernel authority, authenticated-peer assumptions, and
claims that cannot be made. Native proof still requires execution on every
release target; this document is design evidence, not native conformance.

## Linux 6.3+ execute mitigation — accepted direction-specific limit

`memfd_create(MFD_CLOEXEC | MFD_NOEXEC_SEAL)` creates the memfd with executable
mode bits clear, installs `F_SEAL_EXEC`, and implies `MFD_ALLOW_SEALING`. Native
AMD64 and Arm64 execution in [Actions 29179189298](https://github.com/ro-ag/native-ipc-rs/actions/runs/29179189298)
confirmed that the seal rejects executable mode changes. The GitHub run proved
that an already-existing writable mapping can still gain `PROT_EXEC` through
`mprotect` after all required seals are installed. An initial Linux Arm64
Docker-VM characterization suggested that a brand-new `PROT_EXEC` mapping also
succeeds. Exact native AMD64 and Arm64 execution in
[Actions 29179590235](https://github.com/ro-ag/native-ipc-rs/actions/runs/29179590235)
then confirmed that fresh shared RX alias while irreversible MDWE was active;
MDWE denied only the existing RW-to-RWX upgrade. The mode/seal policy, even
combined with MDWE, therefore does not provide object-level maximum VM
protection against dual RW/RX aliases.

Those results define the strongest feasible vNext contract for both directions.
A peer reader can create a new executable view of a coordinator-writer object.
For a receiver-writer object, irreversible MDWE prevents mappings in the
receiver's inheriting process tree from gaining execute, but the receiver can
create a distinct RX alias while retaining RW. It can also delegate the
pre-future-write-seal fd to an unrelated non-MDWE process, which can retain an
RW view and later upgrade it. Every delegate remains part of the malicious
receiver authority principal, so this does not grant store authority to the
coordinator or a second principal. Safe-code ownership remains sufficient for
the trusted coordinator's access discipline. `F_SEAL_EXEC` plus MDWE is not a
maximum-VM-protection mechanism analogous to Mach memory-entry maximum rights.

Disposable isolated helper processes characterize both kernel paths, with
process teardown as their cleanup backstop. Production never probes or makes a
real payload executable. The trusted pre-exec path must install inherited
irreversible MDWE and propagate failure before capability transfer; security
relies on kernel inheritance and irreversibility, not a malicious receiver's
assertion. Preparation remains fail-closed until that process fact is
structurally bound to the session. The accepted residual authority is precise:
library views exclude execute and memfd mode cannot gain execute; MDWE-tree
mappings cannot gain execute or become RWX; RX aliases remain possible; and an
unrelated receiver-writer delegate may retain then upgrade a pre-seal RW view.
At source-tree commit `e904e35`, a bare-metal AMD64 test created that unrelated
delegate before enabling MDWE in the parent, transferred the real pre-seal fd
with `SCM_RIGHTS`, retained the delegate's RW mapping through final sealing,
then demonstrated RW-to-RWX upgrade and immediately restored RW without
executing payload bytes. This is characterization of the accepted limit, not
an authenticated import or permission receipt.

The private pre-exec hook installs the exact inherited mask and propagates
setup failure through `Command`'s exec-error path. Controlled helpers verify
exact post-exec state, irreversibility, and fork-plus-exec inheritance. The hook
mints no witness and is not accepted by memory preparation; it must first be
integrated with exact-image/authenticated-channel receipts and the retained
exact-child lifecycle for the same session. A private deadline-bounded cleanup
owner now exists, but it is intentionally not composed with an authenticated
channel or memory preparation.
The hook checkpoint passed both native Linux architectures and ASan in
[Actions 29180257562](https://github.com/ro-ag/native-ipc-rs/actions/runs/29180257562).

Primary sources:
<https://www.kernel.org/doc/html/latest/userspace-api/mfd_noexec.html> and
<https://man7.org/linux/man-pages/man2/pr_set_mdwe.2const.html>

## Linux peer-writer seal order

The future-write ordering is feasible as a bounded preparation subprotocol
under the accepted authority boundary. Size and execute seals precede
escape. For receiver-writer entries the coordinator destroys its writable
view, transfers the still-future-write-unsealed fd, waits for exact
manifest-bound `IMPORTED`, installs `F_SEAL_FUTURE_WRITE | F_SEAL_SEAL`, sends
`SEALED`, and requires receiver seal revalidation before batch READY. Existing
writable mappings survive `F_SEAL_FUTURE_WRITE`, while new writable mappings
are denied; this is why the receiver must map before that seal and why no
coordinator writable mapping may survive capability escape.

Kernel authority proves no new writable mappings after sealing. Safe-code
ownership proves the trusted coordinator destroyed its old writer. The
receiver may duplicate/delegate its already-authorized writer, but all such
delegates are the same receiver authority principal. Revocation is impossible
after delegation and is not claimed.

Primary sources: Linux `fcntl(2)`/`memfd_create(2)` man-pages and the kernel
memfd no-exec design above.

## Linux socketpair child credentials

Feasible with inherited `AF_UNIX SOCK_SEQPACKET`, `SO_PASSCRED`, and exactly
one `SCM_CREDENTIALS` record on every received packet. Cached `SO_PEERCRED` on
a socketpair made before spawn describes the creator topology and is not
post-exec child proof. Per-message credentials must match the retained pidfd
and expected child PID/UID/GID. `MSG_CMSG_CLOEXEC`, exact ancillary validation,
and immediate `OwnedFd` registration are required for every installed fd.

Authentication binds packets to the exact directional sender at send time:
child-originated packets match the spawned child and retained pidfd, while
coordinator-originated packets match the expected spawning coordinator. It
does not prevent the authenticated malicious receiver from delegating a
capability after receipt. The original draft's requirement that every packet
match the spawned child was impossible for child-received parent packets and
has been corrected in the normative spec.

Variable-length zero-rights bootstrap records use one datagram and a
conservative Linux-native ceiling of 64 KiB, not the generic 16 MiB hard
maximum. Socket construction requests and verifies send/receive buffers large
enough for that ceiling or fails closed. Receive performs one bounded
`recvmsg`, never `MSG_PEEK`, validates exact per-message credentials, adopts
then closes any injected rights, and rejects zero length, oversize truncation,
control truncation, malformed ancillary data, or wrong credentials. The fixed
capability-frame path retains its existing smaller exact-size/fd-count limit.

Linux atomic-capability discovery derives 32/64-bit lock freedom only from the
compiler's `target_has_atomic` facts and compile-time supported-target gates.
It reads page size and L1 data-cache-line size from `sysconf`, checks positive
`usize` narrowing, power-of-two shape, and atomic alignment, then constructs
the platform-neutral `AtomicCapabilities` through its private verified-native
constructor. Missing, zero, overflowing, non-power-of-two, or under-aligned
facts fail closed. This private discovery does not yet mint a HELLO, session,
receipt, or memory-authority witness.

An isolated native probe places cache-line-aligned `AtomicU32` and `AtomicU64`
publication/acknowledgement pairs in anonymous `MAP_SHARED` memory. Parent and
raw fork child prove Release/Acquire observation in both directions. After
fork, the child uses only compiler-proven lock-free atomics, spin hints, raw
syscalls, and `_exit`; parent-death `SIGKILL` is installed as its failure
backstop. A separate exact-pidfd watchdog bounds the disposable probe process
and reaps it exactly. The successful publication path checks runtime facts,
exact inner-child reap/ECHILD, and fd/map/child baselines. Forced parent-death
cleanup of the reparented inner child is not claimed as exact-reap evidence and
remains excluded from the baseline claim. At exact commit `d3ee93b`, all ten
hosted jobs are green in
[Actions 29197989720](https://github.com/ro-ag/native-ipc-rs/actions/runs/29197989720),
including native Linux AMD64/Arm64 and ASan. The hosted Linux Arm64 result is
VM characterization, not physical Arm64 release evidence.

At source-tree commit `e904e35`, the parser additionally adopts every complete
nonnegative descriptor word in every structurally reachable `SCM_RIGHTS`
record before reporting malformed payload, truncation, wrong credentials, or
wrong descriptor count. A complete descriptor followed by trailing
non-descriptor bytes is therefore closed on rejection rather than leaked. This
does not claim recovery of descriptors hidden behind an untraversable kernel
control header.

Primary sources: Linux `unix(7)`, `recvmsg(2)`, and `pidfd_open(2)` man-pages.

### Linux executable-identity implementation constraint

Adversarial implementation probes ruled out a split `canonicalize` then `open`,
an unreserved fixed inherited descriptor number, sleep-based post-exec
observation, and best-effort `kill`/blocking `wait` cleanup. The conforming
implementation must:

- accept an already-resolved absolute native ELF path and acquire it with one
  `openat2` resolution that rejects symlink and magic-link components;
- validate the held inode against the caller's identity policy and execute that
  held artifact, then compare `/proc/PID/exe` device/inode while the child is
  held in a nonce-bound inherited bootstrap handshake;
- dynamically allocate a collision-free inherited descriptor and clear `FD_CLOEXEC` only
  in the child between fork and exec;
- open and retain the pidfd immediately; recompute/check the one absolute
  deadline before every blocking I/O, process poll, and retry; and poll the
  pidfd rather than spin or use blocking wait; and
- transfer every incompletely reaped child and pidfd into a durable reaper or
  containment owner that survives returned errors and Drop.

The private `HeldExecutable`/`VerifiedExecutable` scaffold now implements the
absolute native-ELF `openat2` policy, held device/inode, pidfd retention, and
post-spawn `/proc/PID/exe` comparison. It rejects relative paths,
symlink/magic-link resolution, nonfiles, non-executables, non-ELF artifacts,
foreign-class/machine ELF, wrong spawned images, and already-reaped children.
Native tests execute through the held descriptor after replacing its original
path and prove that CLOEXEC removes the descriptor in the new image. The
scaffold alone does not establish role-asymmetric coordinator child-image
evidence; that requires the inherited bootstrap, authenticated channel, and
bounded process owner described below.
The deterministic held-exec checkpoint passed native Linux AMD64/Arm64, ASan,
and all auxiliary gates in
[Actions 29180802767](https://github.com/ro-ag/native-ipc-rs/actions/runs/29180802767).

The existing `Command::spawn` followed by `pidfd_open(PID)` is not sufficient
for the final boundary: process-global `SIGCHLD=SIG_IGN`, `SA_NOCLDWAIT`, or a
concurrent broad waiter can reap the child and permit PID reuse before
`pidfd_open`. A private test-only feasibility probe therefore uses the Linux
`clone3` v2-sized `clone_args` UAPI (zero extensions) with fork-like flags, `CLONE_PIDFD`, and
`SIGCHLD`. The kernel writes the pidfd in the same clone operation. In an
isolated process with `SIGCHLD=SIG_IGN`, the probe proves the pidfd reports the
returned child while live and remains readable after automatic reap.
Post-reap diagnostics vary by kernel and timing: signal zero may still succeed
or fail with `ESRCH`, and fdinfo may retain the clone-time PID or report `-1`.
None of those diagnostic forms is treated as continued process authority; the
authoritative post-reap assertion is that `waitpid` reports `ECHILD`. Docker
Arm64 required an unconfined seccomp profile because its default profile
returned synthetic `ENOSYS`. Exact native AMD64/Arm64, ASan, and auxiliary CI
passed in [Actions 29181676361](https://github.com/ro-ag/native-ipc-rs/actions/runs/29181676361).
This probe does not exec, install MDWE, own cleanup, or mint a receipt.
Production work must build the preallocated async-signal-safe
MDWE/exec/error-pipe path around this atomic primitive.

A second private, test-only scaffold now exercises that next path without
making it constructible by production code. The parent prebuilds the held-fd
path, bounded argv/envp pointer arrays, and nonblocking CLOEXEC error pipe;
fork-like `clone3(CLONE_PIDFD)` atomically returns the sole pidfd. The raw child
closes the parent pipe end, applies `close_range(CLOSE_RANGE_CLOEXEC)`, installs
exact MDWE, and `execve`s the held native ELF. Failures write one fixed-width
stage/errno record with a bounded EINTR loop and `_exit`; zero-byte CLOEXEC EOF
is only provisional exec-transition evidence. The scaffold fails closed when
pidfd already reports death, then requires the live exact held image and a
deterministic post-exec checkpoint. Future production use must additionally
bind authenticated HELLO. Parent parsing uses the error pipe plus pidfd and one
absolute deadline. Isolated tests cover silent pre-exec death, held-path
replacement, post-exec MDWE and held-fd
CLOEXEC, injected MDWE/exec errors, partial/malformed records, deadline expiry,
pidfd readiness, and fd/process baselines. The exact execution path remains
private and mints no image, channel, session, or memory authority.

An adjacent private `PreparedExactChildLifecycle`/`ExactChildLifecycle` now
provides durable ownership for that sole clone-time pidfd. Its cleanup worker
is created before clone; `Drop` only stores an atomic termination request and
unparks the worker. Explicit wait and terminate operations share one absolute
deadline. The worker uses `pidfd_send_signal`, pidfd polling, and
`waitid(P_PIDFD)`, treats process-global auto-reap or a broad waiter as
`AlreadyReaped`, and reports a terminal cleanup fault once before parking
forever while retaining the exact pidfd. It neither blocks in Drop nor retries
a permanent fault. Isolated tests cover live/stalled Drop, cancellation,
exact-child SIGKILL/reap, incomplete explicit cleanup followed by durable
cleanup, `SIGCHLD=SIG_IGN`, `SA_NOCLDWAIT`, a broad waiter, and persistent
signal/poll/reap failures.

The private atomic-exec checkpoint now calls `setsid` in the trusted raw child
before MDWE and held-image exec. Success creates a fresh session and process
group whose SID and PGID equal the clone-time child PID. The lifecycle records
that fact only after the trusted exec-error protocol proves the child passed
`setsid`; it still mints no receipt. Cleanup never submits a numeric PGID
signal. Linux has no pidfd-equivalent process-group handle and no atomic
"validate this pidfd leader, then signal its group" operation. Even after
`waitid(P_PIDFD, ... | WNOWAIT)` reports `CLD_STOPPED`, a malicious same-UID
delegate can send `SIGCONT` or `SIGKILL`; the leader can exit and a broad waiter
can reap it before `kill(-pgid)` executes. The number may then identify an
unrelated group. The lifecycle therefore reports a fresh but unverified group
and uses only pidfd operations for exact direct-child termination/reap.

Native-style disposable tests prove post-exec SID/PGID identity, `setsid`
failure, nonblocking Drop, exact cleanup after broad/automatic reap, and the
intentional survival of both an ordinary group descendant and a malicious
descendant that creates a new session. Test-only pidfds provide their
disposable-helper cleanup backstop. Race-resistant descendant teardown is a
kernel impossibility under the stated malicious-receiver and broad-waiter model
without stronger trusted containment such as a broker-controlled cgroup or PID
namespace. A task in an uninterruptible kernel wait can also prevent bounded
successful direct-child reap; the durable worker retains the exact pidfd and
the bounded result remains incomplete. This checkpoint is currently
Docker-characterized and requires native AMD64/Arm64 execution.
Bootstrap-fd collision policy, authenticated HELLO composition, and physical
Arm64 release evidence also remain required.

The next private production checkpoint composes the held native ELF, a
pre-created durable lifecycle worker, the sole clone-time
`clone3(CLONE_PIDFD)` pidfd, and the parent half of an anonymous
`SOCK_SEQPACKET` pair in one `UnauthenticatedLinuxSpawn`. The kernel dynamically
chooses a collision-free duplicate of the child endpoint. The raw child marks
the complete descriptor table CLOEXEC, clears CLOEXEC only on that bootstrap
slot, calls `setsid`, installs exact irreversible MDWE, and executes the held
descriptor with `execveat(AT_EMPTY_PATH)`. A fixed CLOEXEC nonblocking error
pipe reports close-range, bootstrap-fd, `setsid`, MDWE, and exec failures. The
parent immediately arms the durable pidfd owner and uses the error pipe, pidfd,
held inode, and one caller-derived absolute deadline to reject malformed,
partial, silent, stalled, exited, or wrong-image outcomes. Error-pipe EOF is
only provisional exec evidence; exact image and live pidfd checks must also
succeed.

This owner is deliberately unreachable and pre-authentication. It exposes no
packet send, fd transfer, receipt, session, HELLO, negotiation, or memory
authority. Drop requests exact pidfd cleanup through the pre-created worker;
the fresh group remains explicitly unverified as described above. Local Rust
1.97 Arm64 unconfined-Docker tests cover occupied fd slots, held-path
replacement, exactly one inherited bootstrap socket, closure of the held,
pipe, and original pair descriptors, every fixed error stage, malformed and
partial records, silence, deadline expiry, repeated Drop, panic, and
fd/task/child baselines. This composition is included in the Phase 5i-D hosted
exact-target evidence below; physical Arm64 release evidence remains required.

Phase 5i-D consumes that owner through one
`spawn_negotiating` entry so the caller cannot replace the absolute deadline
between image confirmation and HELLO. The coordinator generates one nonzero
32-byte nonce with nonblocking `getrandom`, sends exactly one canonical
Coordinator HELLO, then accepts exactly one Receiver HELLO only after the
packet primitive verifies zero rights and kernel per-message credentials for
the exact clone PID and real UID/GID while the sole lifecycle pidfd remains
live. The receiver validates the coordinator's directional real UID/GID and
parent PID before using the authenticated record's nonce, independently
discovers native atomic facts, echoes the nonce, and reduces the same canonical
two-HELLO transcript. Executables carrying set-user-ID or set-group-ID mode
bits are rejected before clone. Locally decidable invalid feature relations,
limits, payloads, and entropy failures also reject before clone.

Linux's one-datagram ceiling makes the exact opaque application payload limit
65,312 bytes (`64 KiB - 224-byte HELLO header`). Unconfined Rust 1.97 Arm64
Docker exercises empty, one-byte, and exact-limit payloads in both directions;
wrong role, nonce, target, atomic facts, limits, reserved bytes, truncation,
and injected `SCM_RIGHTS` all fail and restore exact direct-child/resource
baselines. A root-only disposable test splits real IDs 65534 from effective
IDs 0 and proves that automatic `SCM_CREDENTIALS` binds real IDs in both HELLO
directions. Default Docker seccomp masks `clone3` as `ENOSYS`; this evidence
therefore requires privileged, seccomp-unconfined execution and remains VM/
emulation characterization rather than native release evidence.

The resulting private `NegotiatingLinuxSpawn` is `Send`, non-`Sync`, and
non-`Clone`. It exposes no endpoint, raw descriptor, ACCEPT/READY state,
receipt, session, control, batch, or memory authority. Duplicate/flood/replay
records cannot mint authority at this HELLO-only typestate and still require
explicit native coverage at the later ACCEPT/poison transition.

Local Phase 5i-E consumes both negotiating owners through challenged bilateral
application decisions while retaining the original bootstrap deadline. After
the coordinator application chooses ACCEPT or REJECT, the coordinator obtains
a fresh nonzero 128-bit `DecisionChallenge` from nonblocking `getrandom` under
that stored deadline. Coordinator ACCEPT binds the challenge to the complete
HELLO digest and effective facts. Only a receiver that first validates that
Coordinator ACCEPT obtains a non-cloneable `ReceiverDecisionPending`; its
application then explicitly chooses ACCEPT or REJECT, and the exact response
echoes the challenge. Coordinator REJECT is clean and terminal without a
receiver reply. Receiver REJECT is likewise terminal after the challenged
Coordinator ACCEPT. Entropy failure, malformed/foreign decisions, wrong or
zero challenges, stale ordering, rights injection, deadline ambiguity, or
peer exit fail closed and exact-clean the owned child.

The challenge resolves a protocol-causality contradiction found during the
implementation audit: without an unpredictable value delivered only in the
Coordinator decision, a malicious receiver could prequeue the deterministic
Receiver ACCEPT derived from the two HELLOs. A nonblocking queue probe could
not close the race. The challenged transcript makes prequeued Receiver ACCEPT
or REJECT fail with exact challenge mismatch instead of pretending that socket
arrival order proves causality.

Only bilateral exact ACCEPT yields private `AcceptedLinuxSpawn` and
`AcceptedLinuxReceiver`. These names intentionally do not claim the public
normative `Ready` state. They expose no receipt, endpoint/raw descriptor,
public session, control, transfer batch, mapping, or memory authority. Before
the coordinator accepted owner is constructed, live pidfd / held-image match /
live pidfd is rechecked under the stored deadline. A controlled copied-inode
re-exec between HELLO and ACCEPT is rejected. This is exact authenticated
launch/bootstrap-principal evidence, not immutable ongoing image attestation;
a malicious receiver may later re-exec or delegate already received authority.

Local Rust 1.97 privileged, seccomp-unconfined Arm64 Docker covers ACCEPT with
empty/one/exact-65,312-byte HELLO payloads, both clean Reject paths, fresh
challenge entropy faults and EINTR, application delay through the original
deadline, prequeued decisions, every effective-field/challenge mutation,
malformed flood, duplicate HELLO, SCM_RIGHTS, silence, exit, re-exec, and exact
fd/task/child/ECHILD baselines. Full all-feature and no-default workspace
tests/doctests plus strict Clippy pass locally. This remains emulated/VM
characterization only and is not native-host or release proof.

The Phase 5i-E protocol implementation commit is `2801b47`, but exact native
evidence belongs to final evidence SHA
`b768979ce74be7a2063914cf9b27e17deb520d6f`. All ten jobs are green in
[Actions 29201467797](https://github.com/ro-ag/native-ipc-rs/actions/runs/29201467797),
including Rust 1.97 native Linux AMD64/Arm64 all-feature, no-default, and native
permission tests; Linux AMD64 ASan; macOS Arm64 and Windows AMD64/Arm64 checks;
and Miri, fuzz, dependency/policy, and quality gates. The final SHA includes
the mapping-specific ASan oracle correction `a6df424` and the
pidfd-before-completion publication correction at `b768979`.

Two intermediate failures are explicitly not evidence. Run
[29201058759](https://github.com/ro-ag/native-ipc-rs/actions/runs/29201058759)
at `2801b47` failed the ASan job because a process-global VMA-count test oracle
observed sanitizer-lazy mappings rather than an owned mapping leak. Run
[29201262157](https://github.com/ro-ag/native-ipc-rs/actions/runs/29201262157)
at `a6df424` exposed a transient native AMD64 pidfd publication race. Both are
superseded by the all-green final SHA above. A duplicate decision queued after
a valid final ACCEPT remains for the future common accepted-state dispatcher
to reject and is not overclaimed here. Packaged-crate conformance, physical
user-owned Arm64 hardware, public Ready/session/receipt authority, and whole
vNext release completion remain unverified.

Phase 5i-F consumes those bilateral Accepted states into private,
role-asymmetric evidence owners. Coordinator-only evidence inseparably retains
the exact clone-time lifecycle pidfd, held child image, accepted seqpacket
endpoint and terminal transcript, and nonce-bound parent/child real UID/GID
identity facts. Receiver-only evidence retains the authenticated spawning
parent endpoint, terminal transcript, and corresponding identity facts; it
explicitly carries no coordinator-owned child-image or pidfd proof. Neither
role can extract raw native parts. Both owners are `Send`, non-`Sync`, and
non-`Clone`.

Accepted transcript facts are one-shot and require exact bilateral ACCEPT.
Unaccepted, coordinator-only, rejected, poisoned, and replayed transcripts
persistently return the terminal ordering error and cannot later yield facts.
The tested invalid-evidence path, while the stored original deadline remains
live, terminates and reaps the exact child before returning, with immediate
child absence, fd baseline, and `ECHILD` evidence. If that deadline expires or
native cleanup becomes terminal-incomplete, the durable worker instead retains
the exact pidfd/child cleanup authority and reports incomplete facts. After a
successful completion is published, the test separately waits within its own
bound for the now-authority-free detached reaper task to retire; this is not a
hard scheduler bound on every call.

Exact implementation commit `a63a06ea34fdb2389abe1791bc636741b3018e15`
is green across all ten jobs in
[Actions 29202485515](https://github.com/ro-ag/native-ipc-rs/actions/runs/29202485515):
Rust 1.97 native Linux AMD64/Arm64 all-feature, no-default, and native tests;
Linux AMD64 ASan; macOS Arm64 and Windows AMD64/Arm64 general jobs; and Miri,
fuzz, policy, and quality. The non-Linux jobs do not verify a macOS or Windows
Phase 5i-F implementation. Local privileged, seccomp-unconfined Arm64 Docker
all-feature/no-default runs and 25 focused repetitions are characterization
only, not native-host or physical Arm64 evidence. The adversarial audit removed
the stale symmetric generic receipt and ended with no P1/P2/P3.

This evidence SHA is a private Linux mechanism checkpoint, not a release
candidate. Phase 5i-F exposes no public `Ready`, session, control, fd transfer,
batch, mapping, or memory authority. It proves no symmetric sole-writer or
image property, immutable ongoing image attestation, or revocation of already
delegated authority. Physical user-owned Arm64, macOS/Windows Phase 5i-F,
packaged-crate conformance, whole-vNext completion, and release completion all
remain unverified.

Phase 5i-G0 adds a private, role-neutral `AcceptedControlDispatcher` scaffold.
It inseparably owns the portable accepted control sequence, transaction state,
zero-rights record transport, and persistent poison state. Receive asks the
transport for one independently bounded complete record, validates the fixed
72-byte header before payload exposure or any second allocation derived from
peer fields, and reuses that owned record allocation for the returned payload.
Send and receive sequences remain independent. Transaction interleaving,
ambiguous post-encode or receive I/O, hostile framing, an oversized successful
transport return, and peer-poll errors poison both layers without retry.

Linux now caps each local HELLO offer before either canonical HELLO or the
accepted transcript is constructed. Its maximum application-control payload is
65,464 bytes: the verified 65,536-byte single-packet ceiling minus the 72-byte
application-control header. Lower nonzero offers remain unchanged and zero
still fails closed. This is the truthful negotiated transport limit rather than
the portable 16 MiB field hard maximum. It does not change the one bounded
`recvmsg`, no-`MSG_PEEK`, adopt-then-close-ancillary design required of the
future Linux adapter.

Exact implementation commit `9eae30f6f2e1a6083459fd6e34bec537387540e0`
is green across all ten jobs in
[Actions 29203533427](https://github.com/ro-ag/native-ipc-rs/actions/runs/29203533427),
including native hosted Linux AMD64/Arm64 and ASan plus the non-Linux and
auxiliary gates. The hosted Linux Arm64 job is an Azure VM/native runner, not
physical user-owned Arm64 evidence. Local macOS Rust 1.97 all-feature/no-default
tests, doctests, and strict Clippy are green. Privileged, seccomp-unconfined
Arm64 Docker passes the corresponding proportional gates but remains
emulation/characterization only; it is not a native-host, physical Arm64, or
release proof. This checkpoint does not wire either Linux accepted evidence
owner to a native application-control adapter, transfer `SCM_RIGHTS`, or expose
a public `Ready`, session, or control API. It creates no batch, mapping, or
memory authority. Packaged-crate, physical Arm64, exact-release-commit, and
whole-vNext release evidence remain unverified.

Phase 5i-G1a consumes the role-scoped Accepted Linux evidence owners into
private native application-control owners. The coordinator transport alone
inseparably owns the singular clone-time lifecycle pidfd, held executable,
accepted evidence, seqpacket endpoint, and `OwnedChildLifecycle`. The receiver
transport owns only authenticated spawning-parent evidence and its endpoint.
It has no parent pidfd, image, or exit-code proof; it observes socket HUP and
reports only `ExitedUnknown`.

Every application-control record uses the original caller-supplied absolute
deadline and requires exact directional `SCM_CREDENTIALS`. It permits zero
`SCM_RIGHTS`; every injected installed fd is nevertheless adopted and closed
before rejection. Receive remains one independently bounded `recvmsg` with no
`MSG_PEEK`, using the negotiated 65,464-byte payload maximum and reusing the
owned record allocation after validation. A valid record queued before
dispatcher construction remains queued. Hostile framing, credentials, rights,
replay, oversize, silence, and ambiguous I/O persistently poison the control
owner.

Linux `SOCK_SEQPACKET` distinguishes a live zero-length record from EOF only
after the empty record has been consumed: a live empty record is malformed,
while actual socket HUP is peer exit. Failure of that post-consumption
diagnostic poll, including `EINTR`, is terminal so the caller never retries a
second `recvmsg` and silently consumes the next queued record.

Exact implementation commit `a26e1df71fccf44540a174a4994cd421668b5700`
is green across all ten jobs in
[Actions 29204483739](https://github.com/ro-ag/native-ipc-rs/actions/runs/29204483739),
including native hosted Linux AMD64/Arm64 and ASan plus non-Linux and auxiliary
gates. The hosted Linux Arm64 result is not physical user-owned Arm64 evidence.
Local macOS Rust 1.97 gates are green. Privileged, seccomp-unconfined Arm64
Docker full and focused runs pass as characterization only, not native-host,
physical Arm64, or release evidence. Independent final review reports no
issue. This remains private G1a: it exposes no public `Ready`, session, or
control API and transfers no native batch `SCM_RIGHTS`. It creates no
transaction, mapping, or memory authority; cannot revoke a delegated endpoint;
and supplies no receiver-side exact parent pidfd, image, or exit-code proof.
Physical Arm64, packaged-crate, exact-release, and whole-vNext evidence remain
unverified.

Phase 5i-G1b extends that same private `AcceptedControlDispatcher` owner with
one dependency-ordered capability transport checkpoint. It does not extract or
duplicate the accepted endpoint. Sealed role-specific traits let only the
coordinator begin and send the first capability record; the receiver can only
await and receive it. The transaction guard mutably borrows the dispatcher,
stores the caller-derived absolute deadline once, and passes that same value to
the native operation without accepting a replacement deadline.

The capability record is constructed only from the canonical transfer manifest
with exact `NIPCCAP1` magic. Its manifest entry count is the required installed
fd count, so callers cannot independently select a different expected count.
Linux sends 1..=16 borrowed fds on the already-owned accepted seqpacket and
receives with one exact-size `recvmsg`, exact directional credentials, exact fd
count, and exact full-frame comparison. Every installed fd is immediately an
`OwnedFd`; successful imports stay inside the receiver transaction guard, while
wrong credentials, 0/2/N rights for a one-entry manifest, truncation,
application-frame interleaving, nonce/transaction/manifest substitution, I/O
failure, replay, or guard destruction closes them and persistently poisons the
inseparable session owner.

G1b intentionally provides no transaction completion operation. It therefore
cannot resume ordinary application control after capability escape and makes no
READY, COMMIT, activation, mapping, or public `Session<Ready>` claim. Remaining
work includes transaction ID allocation/limit charging, the complete 1..=16
prepared-memory adapter, receiver expected-batch validation and import,
receiver-writer IMPORTED/SEALED preparation, exact full-manifest READY/COMMIT,
activation/lease integration, and public session/control APIs.

Local macOS Rust 1.97 all-feature tests and strict Clippy pass. Privileged,
seccomp-unconfined Rust 1.97 Arm64 Docker passes the focused native capability
transport and portable accepted-owner corpus. Docker remains emulation/
container characterization only, not native-host, physical Arm64, packaged,
release, or whole-vNext evidence. Exact implementation commit
`c34e904f2451907a3f35c7b17cf79636c19187aa` is green across all ten jobs in
[Actions 29205870709](https://github.com/ro-ag/native-ipc-rs/actions/runs/29205870709),
including hosted native Linux AMD64/Arm64 and ASan plus non-Linux and auxiliary
gates. Independent review found one P3 missing same-guard replay test; the added
coordinator/receiver regression proves one native operation, retained duplicate
input, transaction-owned fd cleanup, and persistent poison. Focused re-review
reports no remaining P1/P2/P3.

Phase 5i-G1c moves capability-frame provenance and transaction allocation into
the inseparable accepted-session owner. Both role-scoped Accepted evidence
owners now transfer the exact authenticated parent/child identities, accepted
nonce, and effective negotiated limits into `AcceptedControlDispatcher`.
Callers supply only proposed manifest entries. The dispatcher validates and
canonicalizes them, enforces negotiated entry, per-region logical, aggregate
logical, aggregate mapped, and transaction limits, then mints the nonzero
monotonic transaction ID and exact capability frame internally. It never
accepts a caller-built frame or caller-selected nonce, PID pair, or transaction
ID.

Pure local invalid-manifest, limit, and already-expired-deadline failures occur
before transaction entry, native I/O, or ID consumption. Transaction-limit
exhaustion is terminal and poisons the accepted owner. Once a transaction is
entered, the G1b rules remain unchanged: one caller-derived absolute deadline,
coordinator-only initiation, ordinary-control exclusion, exact directional
credentials, immediate ownership of installed fds, and persistent poisoning on
failure or guard destruction.

Adjacent tests cover exact evidence propagation, internally minted identity
and transaction IDs, nonce/PID/transaction/count substitution, monotonic
allocation and exhaustion, duplicate entries, count/per-logical-region and
aggregate logical/mapped limits, expired-deadline non-consumption, and
preservation of the G1b replay,
interleaving, rights-count, deadline, cleanup, and poisoning corpus. Local
macOS Rust 1.97 formatting, strict Clippy, all-feature, and no-default-feature
tests pass. Privileged seccomp-unconfined Rust 1.97 Arm64 Docker passes the same
proportional gates but remains container/emulation characterization only.

Exact implementation commit `bd4e2789cdcf218e5569529003f975e4c7c41e1b`
is green across all ten jobs in
[Actions 29206612933](https://github.com/ro-ag/native-ipc-rs/actions/runs/29206612933),
including hosted native Linux AMD64/Arm64, ASan, non-Linux targets, and every
auxiliary gate. Independent review found one P2 where the initial limit check
incorrectly applied the negotiated per-region logical-byte maximum to the
page-rounded mapped length. The correction applies that limit only to logical
bytes, keeps aggregate mapped bytes under `max_batch_bytes`, and adds the exact
4,095-logical/4,096-mapped boundary regression. Final re-review reports no
remaining P1/P2/P3.

G1c adds no production transaction completion path and makes no IMPORTED,
SEALED, READY, COMMIT, activation, mapping, or public `Session<Ready>` claim.
The complete prepared-memory/expected-batch adapter, import and native object
validation, receiver-writer preparation, full-manifest barriers, runtime
activation, public APIs, native-host/physical Arm64, packaged-crate, release,
and whole-vNext evidence remain outstanding.

Phase 5i-G1d fills the remaining session-wide native-authority field in the
canonical capability transcript before memory preparation. The profile value
`LinuxMdweV1` means the trusted pre-exec path installed inherited irreversible
`PR_MDWE_REFUSE_EXEC_GAIN`, library-created views never request execute, fresh
RX aliases remain possible, and a receiver-writer may delegate its pre-seal fd
outside the MDWE tree and retain an upgradeable RW view. Those limitations are
part of the accepted Linux authority contract, not stronger protection claims.

Only the role-scoped accepted Linux evidence owners attach this profile while
they consume into the inseparable dispatcher. Batch/transaction callers cannot
select it. The dispatcher rejects the legacy zero profile before native I/O and
mints the profile into bytes 76..80 of every canonical capability frame.
Exact-frame validation therefore rejects profile replay or substitution along
with every other session and transaction field. Landed pre-vNext helpers retain
the zero compatibility profile and their existing wire bytes.

G1d remains a policy/provenance checkpoint. It does not validate any individual
memfd, prove final seals, create mappings, implement IMPORTED/SEALED, or add a
production completion/READY/COMMIT path. Exact implementation commit
`a48a051abbce0414fbe6bf00d26888ceba3e6f2b` is green across all ten jobs in
[Actions 29207032792](https://github.com/ro-ag/native-ipc-rs/actions/runs/29207032792).
Local macOS Rust 1.97 and privileged seccomp-unconfined Arm64 Docker full gates
pass; Docker remains container/emulation characterization only. Independent
adversarial review reports no P1/P2/P3.

Phase 5i-G1e removes caller-supplied coordinator manifest entries from the
production transaction boundary. The coordinator now consumes one complete
portable `TransferBatch`, derives region ID, library-minted incarnation,
writer direction, complementary peer access, logical length, and mapped length
from its owned `PreparedRegion` values, and passes those derived entries to the
G1c/G1d canonical manifest minting path. The open native transaction retains
the resulting `PendingBatch`; callers cannot extract a region or independent
pending token while the guard is live.

The adjacent corpus covers 1/2/4/16 batches, reverse input order, mixed writer
directions, canonical IDs/access ordinals, empty-batch rejection before native
I/O or transaction-ID consumption, and continued transaction ownership through
the existing terminal guard. The former raw-entry coordinator constructor is
test-only so hostile frame/limit cases can still exercise the portable reducer.

G1e deliberately stops before native memory conversion. Its separately supplied
backend capability collection is now test-only; the production Linux G1f
adapter prepares each owned region, binds each exact fd/object/seal state to its
canonical entry and ordinal, and retains local pending mappings. Receiver
`ExpectedBatch`, native
import validation, IMPORTED/SEALED, READY/COMMIT, activation, and public APIs
also remain unimplemented. Exact implementation/review/hosted evidence is
recorded separately below. The G1e implementation commit is
`c8c9558ac714d0e34014c34f939034294a868632`, green across all ten jobs in
[Actions 29207363955](https://github.com/ro-ag/native-ipc-rs/actions/runs/29207363955).
Local macOS Rust 1.97 and privileged seccomp-unconfined Arm64 Docker full gates
pass; Docker remains container/emulation characterization only. Independent
review found one P3 evidence gap: the initial corpus did not observe retained
resource destruction or assert every derived entry field. A minimal test-only
drop observer now proves transport poison precedes every prepared-region
destruction on both abandonment and send failure, and the 1/2/4/16 corpus
asserts exact incarnation, lengths, writer, access, and ordinal. Focused
re-review reports no remaining P1/P2/P3.

Phase 5i-G1f-a implements the first real prepared-memory batch adapter for the
coordinator-writer direction. It consumes an all-coordinator-writer portable
`TransferBatch`, sorts owned regions by `RegionId`, preserves exact initialized
bytes while replacing the portable mapping owner, installs the complete final
memfd seal set, duplicates one export descriptor, and proves the original and
export resolve to the same anonymous tmpfs object key and mapped length. The
adapter owns every mapping/fd and derives manifest entries and capability order
from the same vector.

One caller-derived `AbsoluteDeadline` is stored in the prepared native batch.
Preparation checks it before and after native conversion, sealing, validation,
duplication, and each entry; pre-send revalidation checks the same stored value.
G1f-b refuses a different transaction deadline and the accepted native send
uses that same value. Expiry and deadline substitution occur before capability
escape. Pending `ClearThenRelease` destruction clears the shared bytes through
the retained writer mapping before unmapping/closing; failure at first, middle,
or final preparation entry restores isolated fd/map baselines.

Phase 5i-G1f-b then moves the prepared native batch into the accepted Linux
coordinator transaction. The wrapper derives the exact frame entries and fd
slice from its owned canonical batch, revalidates every object immediately
before the one native send, and keeps the accepted socket, pidfd, image,
evidence, prepared mappings, original fds, and export fds inseparable. A real
exact-child test transfers 1/2/4/16 initialized regions over the already
accepted seqpacket, checks exact credentials/frame/rights through the existing
transport, verifies final seals and read-only peer mappings, rejects new writer
mappings, exercises deadline substitution without poisoning, and restores
fd/task/child baselines. Dropping the still-terminal transaction persistently
poisons ordinary control.

G1f supports coordinator-writer batches only. Receiver-writer preparation still
requires transaction/full-manifest binding, peer native import and object
validation, IMPORTED, final coordinator sealing, SEALED, and receiver seal
revalidation. A production receiver `ExpectedBatch`, complete mixed-direction
adapter, READY/COMMIT, activation, and public APIs remain unimplemented. Exact
implementation `f94c93f7273fb7a9f33779c1a9aba90817e0b2a4` plus the scoped
mapping-baseline correction `1c8a3ad4bcde2c5d555d31a96949d51bb19f55f1`
are green across all ten jobs in
[Actions 29210607343](https://github.com/ro-ag/native-ipc-rs/actions/runs/29210607343).
The accepted-send implementation
`4e8231bbeadb1d38ca2525b9baf78df9c3526026` is green across all ten jobs in
[Actions 29210656133](https://github.com/ro-ag/native-ipc-rs/actions/runs/29210656133).
Local macOS Rust 1.97 and privileged seccomp-unconfined Arm64 Docker full gates
pass; Docker remains container/emulation characterization only. Independent
review found two P2 production substitution paths through the earlier raw and
prepared test scaffolds; both are now `cfg(test)`. Two P3 evidence gaps were
also fixed by checking every initialized logical byte and directly observing
poison before native cleanup on abandonment and revalidation failure. Final
re-review reports no P1/P2/P3.

Phase 5i-G1g implements the first production receiver expectation and native
import path for the coordinator-writer-only slice. `ExpectedBatch` is built and
canonicalized before capability receipt from caller-known ID, writer direction,
and logical length only. The accepted receiver preflights negotiated count,
per-region, aggregate, and fresh-session active count/page-rounded byte limits
before transaction entry. It then receives one exact fd count under the same
absolute deadline, decodes the canonical fixed frame, and binds every accepted
session, transaction, profile, limit, entry, access, length, ordinal, flag, and
total field before importing.

Each imported fd is immediately owned, verified as the exact final-sealed
anonymous object shape, and mapped read-only. The terminal receiver transaction
retains the complete imported set and exposes no raw frame, fd, mapping, or
runtime region. Import failure returns an owning failure candidate containing
all partial mappings plus the current and remaining installed fds; the accepted
owner poisons first and only then destroys that candidate. Exact-child tests
cover 1/2/4/16 success, expected logical substitution, local unsupported
direction rejection, and invalid native objects at ordinals 1/2/4/16 with
poison-before-cleanup and fd/map/child baselines. Injected post-`mmap` advisory
failures at operations 1/17/32 additionally prove first/middle/final pending
mapping ownership and poison-before-release ordering. The dependency commit
`9b00e6813abdb81ecb4352c60647fc0b569a6c42` and accepted-import implementation
`9e81e3f47d883aa9f9c18767fb6aecfdf3c2a481` are green across all ten hosted
jobs in [Actions 29211825345](https://github.com/ro-ag/native-ipc-rs/actions/runs/29211825345).
Local macOS Rust 1.97 and privileged seccomp-unconfined Rust 1.97 Arm64 Docker
full gates pass; Docker remains container/emulation characterization only.
Independent adversarial review corrected active-limit preflight and all
pre-poison partial-import ownership gaps, including fallible advice and a legal
address-zero `mmap`; final re-review reports no P1/P2/P3.

G1g remains a terminal import checkpoint. It does not implement an ongoing
active-resource charge/lease, receiver-writer preparation, IMPORTED/SEALED,
READY/COMMIT, activation, public `ExpectedBatch`/session APIs, or release proof.

Phase 5i-G1h implements the bounded Linux receiver-writer preparation ordering
for homogeneous 1..=16-region batches inside the same accepted-session owner.
Before capability escape the coordinator retains only prefix-sealed memfds and
has destroyed every local writable mapping. The receiver verifies exact
pre-receipt expectations and prefix seals, establishes every RW mapping, and
sends an internally derived exact-full-manifest `NIPCIMP1` record with zero
rights. The coordinator accepts only that exact credential-bound receipt,
immediately installs `F_SEAL_FUTURE_WRITE | F_SEAL_SEAL` across the complete
batch, continuing best-effort attenuation of remaining fds after an individual
seal error. Only a completely final-sealed batch proceeds to read-only pending
mappings and internally derived `NIPCSEA1`. The receiver revalidates final
seals before its terminal pending owner can be observed even by tests.

The adjacent corpus covers full-byte 1/2/4/16 transfer, new writable-map denial
after final sealing, exact receipt kind/transcript substitution, application
frame interleaving, wrong directional credentials, injected 1/2/16 rights,
every IMPORTED/SEALED truncation, silence under one absolute deadline, replay
of the terminal prepare operation plus stale/duplicate IMPORTED and duplicate
SEALED wire records, continuous wrong-kind traffic, invalid objects at ordinals
1/2/4/16, Nth final-seal failure at 1/2/4/16, first/middle/final receiver and
coordinator post-`mmap` advisory failures, receiver final-seal revalidation
failure, persistent poison, poison-before-native-cleanup, and fd/map/child/task
baselines. Exact implementation `3914dc18d6e3efcefdbc2f28487563932cb06703`
is green in all ten hosted jobs in
[Actions 29213561283](https://github.com/ro-ag/native-ipc-rs/actions/runs/29213561283),
including native Linux AMD64/Arm64 and Linux AMD64 ASan. The independent final
adversarial review reports no P1/P2/P3.

G1h is not READY or COMMIT. It supports receiver-writer-only batches in this
checkpoint; mixed-direction composition, the single full-batch READY/COMMIT
reducer, active resource leases, runtime exposure, public session/control APIs,
physical Arm64, packaged-crate, release, and whole-vNext evidence remain
outstanding.

Phase 5i-G1i-a adds only the private coordinator-side native preparation owner
required for a later arbitrary mixed-direction accepted transaction. One
`LinuxMixedDirectionBatch` consumes 1..=16 portable entries, sorts them by
`RegionId`, retains each coordinator-writer or receiver-writer entry inside its
already reviewed direction-specific memfd owner, and produces one matching
canonical capability order. Pre-send revalidation checks final seals for
coordinator-writer entries and prefix seals plus absent coordinator writable
views for receiver-writer entries under the original deadline. No raw fd,
mapping, per-entry pending token, or replacement deadline escapes.

Adjacent Arm64 Linux characterization covers 1/2/4/16 reverse-input batches,
alternating directions, exact initialized bytes, exact per-direction seals and
peer access, canonical ordinals/capability order, non-`Clone`/non-`Sync`
ownership, local profile/expiry rejection, retained coordinator-mapping
rejection, first/middle/final synthetic preparation failure, owner destruction,
and exact fd/vNext-map baselines. Exact implementation
`ba13372623dff7a29bd6be1e95f6fdee3c2676c0` is green in all ten hosted jobs in
[Actions 29213948297](https://github.com/ro-ag/native-ipc-rs/actions/runs/29213948297),
including native Linux AMD64/Arm64 and Linux AMD64 ASan. The independent final
adversarial review reports no P1/P2/P3.

G1i-a deliberately performs no accepted capability send or peer import. The
mixed receiver expectation/import owner, complete-batch IMPORTED/SEALED
attenuation, READY/COMMIT, active leases, runtime/public APIs, and release
evidence remain outstanding.

Phase 5i-G1i-b adds the private receiver expectation and import half for one
mixed-direction native batch. The expectation is complete before descriptor
receipt and rejects negotiated count, region, aggregate logical/mapped, and
active limits locally. Import consumes all installed descriptors at once,
checks the exact full manifest shape and capability ordinal order, validates
direction-specific final or prefix seals, rejects duplicate native objects,
and establishes only pending RO coordinator-writer or RW receiver-writer
mappings. Success and every partial-failure path retain all fds and mappings in
one non-`Clone`, non-`Sync` owner until destruction.

Adjacent Arm64 Linux characterization covers exact 1/2/4/16 alternating mixed
imports and initialized bytes, full-limit and wrong-direction expectation
rejection, duplicate/wrong native objects, first/middle/final invalid-object
failure, first/middle/final post-`mmap` advice failure, failure-owner drop order,
stored-deadline expiry, and exact fd/vNext-map baselines after success and
failure. The independent final adversarial review reports no P1/P2/P3. Exact
implementation SHA and hosted CI are pending.

G1i-b has no accepted send/receive path and exposes no pending payload or
runtime authority. Exact credentials/rights framing, full-batch attenuation,
IMPORTED/SEALED, READY/COMMIT, active leases, public APIs, and release evidence
remain with the later inseparable accepted reducer.

The first exact hosted tip, `2f21c59`, is not completion evidence: run
[29198888250](https://github.com/ro-ag/native-ipc-rs/actions/runs/29198888250)
failed only its Linux AMD64 ASan job because the containment test harness
published an escaped descendant PID before that child completed `setsid`; the
test observed the child's old session rather than waiting for the intended
kernel transition. Exact commit `0ae24f9` corrects that scheduling race with one
bounded `AbsoluteDeadline` wait for the exact descendant's session while
retaining its pidfd and the final exact SID assertion. All ten hosted jobs,
including native Linux AMD64/Arm64 and ASan, are green in
[Actions 29199137594](https://github.com/ro-ag/native-ipc-rs/actions/runs/29199137594).
Those non-root hosted runners prove the normal bidirectional credential path;
the privileged real-ID/effective-ID split remains Arm64 seccomp-unconfined
Docker characterization only. The hosted Linux Arm64 result is VM
characterization, not physical Arm64 release evidence. ACCEPT/READY, public
session and receipt composition, fd/control/batch/memory authority, physical
Arm64, exact release-commit, and packaged-crate evidence remain unverified; no
release claim follows from Docker or this hosted mechanism checkpoint.

The exact variable-packet correction commit `ad4ca15` is green across all ten
hosted jobs, including native Linux AMD64/Arm64 and ASan, in
[Actions 29197506559](https://github.com/ro-ag/native-ipc-rs/actions/runs/29197506559).
The earlier failed run `29197362446` is not evidence.

The exact atomic-capability discovery commit `d3ee93b` is green across all ten
hosted jobs, including native Linux AMD64/Arm64 and ASan, in
[Actions 29197989720](https://github.com/ro-ag/native-ipc-rs/actions/runs/29197989720).
The hosted Linux Arm64 result is VM characterization, not physical Arm64
release evidence.

The exact pre-authentication spawn-owner commit `81832fd` is green across all
ten hosted jobs in
[Actions 29197002887](https://github.com/ro-ag/native-ipc-rs/actions/runs/29197002887).

The preceding exact-child and fresh-session scaffold passed hosted native Linux
AMD64/Arm64 and Linux AMD64 ASan at exact commit `861c139` in
[Actions 29196282000](https://github.com/ro-ag/native-ipc-rs/actions/runs/29196282000).
That is exact mechanism evidence for the containment/baseline tip, not native
evidence for the later uncommitted spawn composition and not physical Arm64
release evidence. An earlier extended scaffold passed at
commit `cd38c26` in CI run
[`29182825256`](https://github.com/ro-ag/native-ipc-rs/actions/runs/29182825256).
That evidence validates this private mechanism checkpoint only; it does not
remove the authenticated HELLO or bootstrap-fd blockers. The durable lifecycle
extension and a focused direct-host syscall trace passed on bare-metal AMD64 at
source-tree commit `e904e35`; the full workflow is
[Actions 29186489332](https://github.com/ro-ag/native-ipc-rs/actions/runs/29186489332),
where all jobs passed and both hosted Linux runners identified themselves as
Azure VMs. That hosted execution is characterization rather than physical
Arm64 release evidence.

The durable owner removes the leak-prone exact direct-child cleanup blocker in
isolation. The fresh-session checkpoint characterizes grouping but cannot
provide race-resistant descendant teardown. At this checkpoint, the Linux
image owner alone could not establish later role-scoped coordinator
child-channel, child-image, and accepted-transcript evidence; that also
required the collision-safe pre-authentication owner, authenticated nonce-bound
HELLO, exact per-message credentials, and bilateral acceptance for the same
child. Even that private evidence does not construct the public safe session;
PID/path checks or a standalone private probe are not substitutes.

Primary sources: Linux man-pages for [`openat2(2)`](https://man7.org/linux/man-pages/man2/openat2.2.html),
[`fcntl(2)`](https://man7.org/linux/man-pages/man2/fcntl.2.html),
[`execveat(2)`](https://man7.org/linux/man-pages/man2/execveat.2.html),
[`proc_pid_exe(5)`](https://man7.org/linux/man-pages/man5/proc_pid_exe.5.html),
[`pidfd_open(2)`](https://man7.org/linux/man-pages/man2/pidfd_open.2.html), and
[`poll(2)`](https://man7.org/linux/man-pages/man2/poll.2.html).

## Windows remote duplicate cleanup

Feasible only with the spec's containment interpretation. `DuplicateHandle`
creates a handle value valid in the target process. Before resume, local setup
may safely unwind the suspended child. After resume, numeric remote handles
are not stable object identities and must never be closed by replaying a
ledgered number into `DUPLICATE_CLOSE_SOURCE`. On ambiguous failure the owner
terminates the kill-on-close Job/process and lets kernel process teardown close
remote handles. The ledger records what may remain until teardown; it is not a
revocation primitive.

Primary sources: <https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-duplicatehandle>
and <https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects>.

## Concurrent peer-memory copy soundness

The selected design is one narrowly audited unsafe external-memory boundary.
Active safe APIs validate owned logical ranges in Rust and call a tiny C FFI
module whose source/destination mapping pointers are volatile-qualified. They
never form an ordinary persistent Rust shared slice/reference over active
memory and return reads only into caller-owned bytes. Volatile is not
synchronization and does not make a coherent snapshot. That is acceptable for
memory safety because every `u8` bit pattern is valid, owned range/lifetime are
checked independently, and the API promises torn hostile bytes rather than
integrity. Writer methods require exclusive `&mut self`; the complementary
kernel capability is read-only. The 0.4 core's ordinary `copy_nonoverlapping`
path is not used for vNext active peer-mutated memory.

Primary semantics: <https://doc.rust-lang.org/core/ptr/fn.read_volatile.html>
and <https://doc.rust-lang.org/core/ptr/fn.write_volatile.html>.

This remains a memory-safety argument, not a kernel snapshot guarantee. The
concrete boundary and its pointer lifetime/alignment contracts have independent
diff review and local tests; R5.13 remains release-unverified until native
hostile mutation, Miri-covered portable range code, and exact-target
conformance pass.

## Process containment

- Linux: fresh session/process-group creation and exact direct-child pidfd
  cleanup are feasible. Race-resistant numeric group termination is not:
  same-UID delegates plus broad/automatic reaping can invalidate and reuse the
  PGID between any leader check and `kill(-pgid)`. Ordinary and escaped
  descendants therefore remain unverified without stronger trusted cgroup,
  broker, or namespace containment.
- macOS: fresh group/session feasibility remains separate native work; Linux's
  pidfd evidence does not establish a race-resistant macOS group handle.
- Windows: feasible by creating the child suspended, assigning it to an
  unnamed kill-on-close Job before resume, rejecting setup if assignment or
  required Job policy fails, and retaining process/thread/Job handles in RAII.
  Job containment is kernel authority for processes that remain in the Job;
  configuration must not permit breakaway.

No platform may claim that process containment revokes a capability already
delegated outside the contained principal.

## Contradiction audit and resolutions

Two prose contradictions were corrected without weakening a MUST: packet
credentials now match the exact directional sender rather than always the
child, and the optional-hardening section now distinguishes the mandatory
fresh Unix process group from stronger optional containment. The remaining
apparent tensions resolve as follows:

1. “Exactly one endpoint” names an authority principal, not one PID or mapping;
   bounded same-authority duplication is compatible with the asymmetric model.
2. Batch atomicity is runtime API visibility, not rollback of kernel
   capability delivery. Ambiguous post-escape failures poison and contain.
3. `F_SEAL_FUTURE_WRITE` is compatible with an already-created designated
   writer mapping; it forbids future writer mappings rather than revoking the
   existing one. `F_SEAL_EXEC` alone does not stop executable upgrade;
   inherited irreversible MDWE closes that path inside its process tree but
   not dual RW/RX aliases or the outside-tree receiver-writer delegation case.
4. Windows remote cleanup is containment/process teardown, not unsafe numeric
   remote-handle closure after resume.
5. Linux process-group creation does not make numeric PGID termination
   race-resistant. The section 9 MUST for bounded ordinary-descendant group
   termination conflicts with the malicious-receiver plus broad-waiter model
   unless stronger trusted containment is added. The private checkpoint fails
   closed by omitting numeric group signals and blocks release pending a
   normative amendment or mandatory stronger containment.
6. A bounded termination/reap attempt does not guarantee successful bounded
   reap when a task is stuck in an uninterruptible kernel wait; the cleanup
   ledger retains ownership and reports this exact incomplete state.

The memory-authority mechanism design is feasible under the explicit Linux
kernel limit above. Phase 0's execute-authority contradiction is resolved, but
the newly proven Linux process-group identity contradiction blocks release
pending a normative amendment or mandatory stronger containment. Exact
five-target implementation evidence also remains outstanding.
