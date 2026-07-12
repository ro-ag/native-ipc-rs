# vNext phase-0 native feasibility record

This record resolves mechanism questions before implementation. It separates
safe-code ownership, kernel authority, authenticated-peer assumptions, and
claims that cannot be made. Native proof still requires execution on every
release target; this document is design evidence, not native conformance.

## Linux 6.3+ non-executable memfds

Feasible with `memfd_create(MFD_CLOEXEC | MFD_NOEXEC_SEAL)`. Linux documents
that `MFD_NOEXEC_SEAL` creates the memfd non-executable, installs
`F_SEAL_EXEC`, and implies `MFD_ALLOW_SEALING`. The implementation must reject
`EINVAL`/missing flags rather than fall back. It must verify object type, mode,
seals, and negative executable-map/protection probes. The current 0.4 backend
uses only `MFD_ALLOW_SEALING`, so it is not vNext evidence.

Primary source: <https://www.kernel.org/doc/html/latest/userspace-api/mfd_noexec.html>

## Linux peer-writer seal order

Feasible as a bounded preparation subprotocol. Size and execute seals precede
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
   existing one.
4. Windows remote cleanup is containment/process teardown, not unsafe numeric
   remote-handle closure after resume.
5. Unix process-group cleanup covers the direct child and ordinary descendants
   but cannot contain an actively escaping malicious descendant; the spec
   already forbids making the stronger claim.
6. A bounded termination/reap attempt does not guarantee successful bounded
   reap when a task is stuck in an uninterruptible kernel wait; the cleanup
   ledger retains ownership and reports this exact incomplete state.

The mechanisms have a provisional paper-feasible design. Phase 0 remains open
until focused native probes and independent review validate the chosen
external-memory boundary and available host mechanisms. Release evidence also
remains blocked pending the complete implementation and native execution on all
five targets.
