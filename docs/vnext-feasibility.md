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
remains excluded from the baseline claim. Local Arm64 Docker evidence is
characterization pending native AMD64/Arm64 execution.

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
scaffold does not mint an `ImageIdentityReceipt`; that still requires the
inherited bootstrap, authenticated channel, and bounded process owner below.
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
fd/task/child baselines. Native exact-target evidence for this new composition
is still required.

The exact variable-packet correction commit `ad4ca15` is green across all ten
hosted jobs, including native Linux AMD64/Arm64 and ASan, in
[Actions 29197506559](https://github.com/ro-ag/native-ipc-rs/actions/runs/29197506559).
The earlier failed run `29197362446` is not evidence. This exact run does not
cover the later uncommitted atomic-capability discovery.

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
provide race-resistant descendant teardown. Linux
image identity still cannot mint the final authenticated-endpoint receipt until
the new collision-safe pre-authentication owner completes authenticated
nonce-bound HELLO and exact per-message packet credentials for the same child.
This still blocks the safe session constructor;
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
