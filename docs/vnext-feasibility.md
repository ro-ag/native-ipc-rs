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

Until that durable lifecycle owner exists, Linux image identity cannot mint the
final authenticated-endpoint receipt. This blocks the safe session constructor;
PID/path checks or a leak-prone probe are not substitutes.

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

- Linux and macOS: feasible for the exact direct child and ordinary
  descendants using a fresh session/process group, bounded group termination,
  a race-resistant direct-child lifecycle handle where available, and exact
  direct-child reap. A malicious descendant may escape the group or retain a
  delegated capability; baseline cleanup cannot prevent or revoke that.
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
5. Unix process-group cleanup covers the direct child and ordinary descendants
   but cannot contain an actively escaping malicious descendant; the spec
   already forbids making the stronger claim.
6. A bounded termination/reap attempt does not guarantee successful bounded
   reap when a task is stuck in an uninterruptible kernel wait; the cleanup
   ledger retains ownership and reports this exact incomplete state.

The mechanism design is feasible under the explicit Linux kernel limit above.
Phase 0's execute-authority contradiction is resolved normatively; release
remains blocked on implementation and exact five-target evidence.
