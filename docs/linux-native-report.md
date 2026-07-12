# Linux native handoff report

This report closes the source-tree work requested by
[`linux-agent.md`](linux-agent.md). It is an implementation checkpoint, not a
vNext release-conformance record. The release ledger in
[`vnext-traceability.md`](vnext-traceability.md) remains blocked until the
public session and batch state machine exists and every release target has
exact-release native evidence.

## Scope and revision

- Date: 2026-07-12
- Baseline: `origin/codex/native-ipc-vnext` at `09a1500`
- Linux branch: `codex/linux-native-debug`
- Exact production implementation commit: `e904e35d7a507eda560e22aea7b9b4bd8d8d47c8`
- Initial continuous wrong-peer test commit: `46f428fd6ac05c9867c3d556e8cc01ed18db5e1d`
- Corrected real-listener test commit: `09c0601` (local integration branch;
  physical-host rerun pending)
- Exact corrected evidence tip: `98b71637dc64af699199c3864f21c620838783e2`
- Implementation workflow: [Actions 29186489332](https://github.com/ro-ag/native-ipc-rs/actions/runs/29186489332)
- First evidence workflow: [Actions 29186964531](https://github.com/ro-ag/native-ipc-rs/actions/runs/29186964531)
- Corrected evidence workflow: [Actions 29187052061](https://github.com/ro-ag/native-ipc-rs/actions/runs/29187052061)
- Commit policy: every branch commit has the sole author and committer
  `Rodrigo Agurto <roagto@gmail.com>` and no commit-message trailers.

The implementation remains private and unreachable from the safe public API.
It deliberately mints no image, channel, session, receipt, or memory authority.

## Native host

The direct host was physical AMD64 hardware, not a VM, WSL, or container. The
full gates and stress runs were completed from a Nix flake environment directly
on that host. After Codex was restarted inside its managed sandbox, the focused
trace and later evidence tests and suites were explicitly executed outside that
sandbox on the same physical host. Managed-sandbox results are not counted as
native evidence.

| Fact | Value |
| --- | --- |
| Kernel | Linux 6.12.93, NixOS build, `x86_64` |
| Distribution | NixOS 25.11 (Xantusia), build `25.11.12484.b6018f87da91` |
| C library | glibc 2.40 |
| Rust | `rustc 1.97.0 (2d8144b78 2026-07-07)`, LLVM 22.1.6 |
| Cargo | 1.97.0 |
| CPU | Intel Core Ultra 9 285K, 24 cores |
| Virtualization | `systemd-detect-virt`, `--container`, and `--vm`: `none` |
| Init/root | PID 1 is systemd; ext4 root on `/dev/nvme1n1p2`; cgroup `/init.scope` |

AMD64 execution establishes only AMD64 source-tree behavior. Cross-compilation
and GitHub-hosted Arm64 execution do not replace physical Arm64 release
evidence under the handoff rules.

## Changes made

1. Test-only modules were moved out of production source files into adjacent
   `*_test.rs` files. Exact Rust test paths and target `cfg` behavior were
   preserved.
2. A reproducible Rust 1.97 Nix flake supplies the Linux debugging tools and
   evaluates for both supported Linux architectures.
3. CI records Linux kernel, architecture, libc, toolchain, virtualization,
   root-mount, exact SHA, and worktree facts before tests.
4. The legacy filesystem bootstrap listener now creates its directory
   atomically at mode `0700`, restores exact mode under restrictive umasks, and
   checks the original absolute deadline before every accept attempt and after
   credential inspection. This is regression hardening for the legacy path,
   not evidence for the vNext anonymous inherited `SOCK_SEQPACKET` bootstrap.
5. The ancillary parser adopts every complete nonnegative descriptor word in a
   reachable `SCM_RIGHTS` record before reporting truncation, malformed data,
   wrong credentials, or wrong descriptor count. Complete descriptor words
   followed by non-descriptor trailing bytes are owned and then rejected.
6. The memory corpus now characterizes the required Linux seal sequence and a
   receiver-writer fd delegated before `F_SEAL_FUTURE_WRITE` to a process
   outside the MDWE tree. The imported acknowledgement and receipt in that
   test are explicitly synthetic and unauthenticated.
7. A private exact-child lifecycle owner receives the clone-time pidfd from
   `clone3(CLONE_PIDFD)`. A cleanup worker is created before clone. `Drop` only
   stores an atomic termination request and unparks that worker; it does not
   wait or block. Explicit wait/terminate operations use one absolute deadline.
   The worker uses `pidfd_send_signal`, `poll`, and `waitid(P_PIDFD)`, and
   handles `SIGCHLD=SIG_IGN`, `SA_NOCLDWAIT`, and broad waiter races. A terminal
   cleanup fault is reported once and then parks a durable owner holding the
   exact pidfd instead of retrying or spinning.

## Implementation commits

The following single-author commits were pushed to
`origin/codex/linux-native-debug`:

| Commit | Purpose |
| --- | --- |
| `0fb8637` | Add the reproducible Linux Nix shell |
| `b57fac2` | Remove FHS assumptions from Linux fixtures |
| `10682b0` | Move unit tests into adjacent files |
| `8121c21` | Record Linux host facts in CI |
| `474d093` | Bound private bootstrap acceptance |
| `64ead09` | Own descriptors in malformed ancillary data |
| `5d4142f` | Characterize pre-seal delegation outside MDWE |
| `e904e35` | Add durable exact-child lifecycle ownership |
| `46f428f` | Sustain wrong-peer pressure through the original deadline |
| `98b7163` | Wait for the complete child-list baseline |

## Direct-host validation

The following gates passed with a clean worktree at `e904e35`:

```sh
nix develop --command cargo fmt --all -- --check
git diff --check
nix run nixpkgs#actionlint -- .github/workflows/ci.yml
nix flake check --all-systems
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo clippy --manifest-path crates/native-ipc-platform/Cargo.toml --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-targets --all-features --locked -- --test-threads=1
cargo test --workspace --all-targets --no-default-features --locked -- --test-threads=1
cargo test --manifest-path crates/native-ipc-platform/Cargo.toml --all-targets --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps
```

Results:

- workspace all-feature and no-default test passes each reported 73 passing
  `native-ipc` tests with 25 process-helper tests ignored, 16 passing core
  tests, and 3 passing testkit integration tests;
- standalone `native-ipc-platform` reported 12 passed and 4 helper tests
  ignored;
- warning-free rustdoc and strict Clippy passed;
- all-feature and no-default cross-checks passed for Linux Arm64 at the final
  implementation tip; the macOS Arm64 and Windows AMD64/Arm64 checks passed
  immediately before the final Linux-`cfg`-only fixes, and final-tree native
  hosted jobs later passed for all three targets; and
- cross-checks were treated as compilation evidence only.

Commit `46f428f` attempted to add continuous wrong-peer pressure and was run
directly on the physical host:

```sh
cargo test -p native-ipc --all-features \
  backend::linux::tests::continuous_wrong_peer_accepts_cannot_extend_original_deadline \
  -- --exact --test-threads=1 --nocapture
```

The test passed in 0.10 seconds, but later independent review found that it
cloned one pre-existing stream and exercised callbacks rather than native
`accept(2)`, distinct connections, and per-connection credentials. That result
is therefore withdrawn as native hostile-listener evidence.

Local integration commit `09c0601` replaces it with a real nonblocking Unix
listener and an isolated hostile child that continuously creates distinct
credential-bearing connections through the original deadline. It proves that
no accept callback begins after expiry. The replacement passed ten consecutive
Linux Arm64 seccomp-unconfined Docker runs and strict Clippy. Docker is only
characterization; a direct physical Linux rerun and exact-tip hosted CI remain
pending.

The first hosted evidence run then exposed a test-only auto-reap observation
race: fd and task counts had reached baseline before one immediate
`/proc/thread-self/children` sample reflected the already-automatic reap.
Commit `98b7163` made child-list absence part of the same existing bounded
baseline wait. The corrected no-default lifecycle test passed 25 consecutive
runs directly on the physical host:

```sh
cargo test -p native-ipc --no-default-features \
  backend::linux_vnext::process::tests::exact_child_lifecycle_handles_sigchld_auto_reap \
  -- --exact --test-threads=1
```

The full all-feature and no-default workspace suites were then rerun directly
on the physical host at `98b7163`; both passed with the same 73/25, 16, and 3
workspace counts recorded above.

Native stress at production implementation revision `e904e35` passed:

- 50 repetitions of the lifecycle parent test, including normal and isolated
  terminal-fault cases;
- 50 earlier lifecycle repetitions comprising 1,050 exact-child cleanup
  cycles, plus 100 automatic-reap cases across both signal dispositions;
- 25 repetitions each of automatic reap, outside-MDWE pre-seal delegation,
  ancillary cleanup, and deadline/interruption cases; and
- stable fd, task, child-process, zombie, mapping, and test-directory
  baselines after normal completion.

One stale `0700` bootstrap directory was observed after an intentionally
interrupted parallel test run. No process or fd owned it, and it was removed
explicitly. Normal and stress completion did not reproduce that artifact.

## Native evidence by focus

| Focus | Direct AMD64 evidence | Classification |
| --- | --- | --- |
| Atomic process identity | `clone3(CLONE_PIDFD)` returned the child and exact pidfd in one syscall; the handle remained authoritative across auto-reap conditions. No numeric PID reopening is used by the private owner. | Implemented private mechanism |
| Held executable | `openat2` rejects symlinks/magic links and holds the exact native ELF inode; replacement of the original path does not replace the executed image; the inherited held-fd slot is closed across exec. | Implemented private mechanism |
| MDWE | Exact `PR_MDWE_REFUSE_EXEC_GAIN` is set before exec, observed after exec and by descendants, and cannot be cleared or weakened. Injected setup failure exits before exec. | Implemented private mechanism |
| memfd seals | Exact `F_SEAL_EXEC`, size seals, future-write seal, and final seal states were checked. Existing RW survives future-write sealing; new write mappings and later seals fail as required. | Kernel behavior characterized; production remains fail-closed |
| Outside-tree delegation | A helper created before parent MDWE imported the pre-seal fd, retained RW after final sealing, upgraded it to RWX, restored RW immediately, and never executed payload bytes. | Accepted Linux kernel/authority limit |
| Ancillary ownership | Exact 0/1/2/16-fd packets and malformed, truncated, duplicate, empty, negative, wrong-level/type, short/long, wrong-peer, wrong-count, and trailing-byte records restored fd baselines. | Code defect fixed |
| Absolute deadlines | Wrong packets terminate immediately. Continuous EINTR, silence, saturated output, child exit, late send/receive, and already-expired accept paths cannot restart the deadline. The corrected real-listener hostile-child test at local `09c0601` passed Docker characterization, but direct physical-host evidence is pending. | Code defect fixed; real-listener native evidence pending |
| Nonblocking Drop | Live and stalled exact-child owners returned from `Drop` after an atomic request/unpark; the durable worker killed and reaped the exact child. | Implemented private mechanism |
| Reaping and PID reuse | Cleanup uses the clone-time pidfd for signal, readiness, and `waitid(P_PIDFD)`. Auto-reap and a concurrent broad waiter become `AlreadyReaped`, never a numeric-PID retry. | Implemented private mechanism |
| Terminal cleanup faults | Persistent signal/poll/reap faults report terminal `Incomplete` once, retain the pidfd forever in an isolated process, and do not hot-loop. | Code defect fixed; process containment remains required |
| Signal dispositions | Isolated `SIGCHLD=SIG_IGN` and `SA_NOCLDWAIT` tests passed and restored process-global state by process exit. | Implemented private mechanism |
| Resource cycles | Normal, retryable/forward injected failure, cancellation, and stress paths restored fd/task/child/zombie/mapping/directory baselines. Persistent terminal cleanup faults intentionally retain the exact pidfd until the isolated process-exit backstop and are excluded from baseline-restoration claims. | Source-tree evidence only |
| Descendant containment | Exact direct-child cleanup is implemented. A fresh process group and authenticated production owner are not yet composed; malicious descendants may escape a Unix group or retain delegated capabilities. | Release blocker and kernel limit |

## Syscall, proc, and log evidence

A focused direct-host trace exited successfully:

```sh
strace -ff -qq -o /tmp/native-ipc-e904e35-atomic.strace \
  -e trace=clone3,openat2,close_range,prctl,execve,execveat,pidfd_send_signal,waitid,poll,ppoll,kill,wait4 \
  cargo test -p native-ipc --all-features \
  backend::linux_vnext::process::tests::atomic_clone_exec_state_machine_is_bounded \
  -- --exact --test-threads=1 --nocapture
```

It recorded 24 `clone3`, 8 `openat2`, 8 `close_range`, 18 `prctl`, 6
`execve`, 3 `pidfd_send_signal`, 14 `waitid`, and 23 `poll` calls. Relevant
records include successful `clone3({flags=CLONE_PIDFD, ...} => {pidfd=[...]})`,
`close_range(..., CLOSE_RANGE_CLOEXEC)`, `PR_SET_MDWE`, post-exec
`PR_GET_MDWE`, held-image `openat2`, exact-pidfd signaling, and
`waitid(P_PIDFD, ...)`.

A broader process-module trace completed all 7 selected tests. After Cargo
reported success, the tracer did not exit promptly and was terminated. The
corpus includes an isolated fixture that deliberately retains a parked
terminal cleanup owner, but the cause of the tracer delay was not established;
this run is not used as the clean trace. Before termination it recorded 433
`clone3`, 46 `openat2`, 34 `close_range`, 512 `prctl`, 232 `execve`, 30
`pidfd_send_signal`, 117 `waitid`, and 185 `poll` calls. Its records include
successful exact-child `SIGKILL` followed by `CLD_KILLED`, `ECHILD` under
automatic reap, stopped-child checkpoints, and the injected terminal owner.
The test result itself was 7 passed, 0 failed, and 10 helper-only tests ignored.

`/proc/PID/exe`, `/proc/self/fd`, `/proc/self/task`, child-state snapshots, and
fdinfo were used by the test corpus for image, descriptor, thread, process,
and zombie baselines. The host journal showed no seccomp denial, native-ipc
fault, segfault, memfd, pidfd, clone3, or MDWE kernel message during the exact
test window.

## GitHub characterization

The full workflow for `e904e35` completed successfully in
[Actions 29186489332](https://github.com/ro-ag/native-ipc-rs/actions/runs/29186489332).
All 10 jobs passed: strict quality, dependency/license policy, Miri, fuzz
smoke, Linux AMD64 ASan, macOS Arm64, Windows AMD64/Arm64, and Linux
AMD64/Arm64 all-feature and no-default tests.

The first evidence workflow at `46f428f`,
[Actions 29186964531](https://github.com/ro-ag/native-ipc-rs/actions/runs/29186964531),
passed the then-current callback-based wrong-peer test in both feature modes
and passed 9 of 10 jobs. That test is no longer counted as native
hostile-listener evidence.
The no-default test step in its Linux AMD64 job exposed the immediate
child-list sampling race described above. The corrected evidence tip
`98b7163` passed all 10 jobs in
[Actions 29187052061](https://github.com/ro-ag/native-ipc-rs/actions/runs/29187052061).

Both Linux jobs in the implementation workflow were Azure virtual machines
according to
`systemd-detect-virt`:

| Runner | Recorded facts | Classification |
| --- | --- | --- |
| Linux AMD64 | Ubuntu 24.04.4, kernel `6.17.0-1018-azure`, x86_64, glibc 2.39, root `/dev/nvme0n1p1` ext4; virt/container/vm = `microsoft`/`none`/`microsoft` | GitHub-hosted VM characterization |
| Linux Arm64 | Ubuntu 24.04.4, kernel `6.17.0-1018-azure`, aarch64, glibc 2.39, root `/dev/sda1` ext4; virt/container/vm = `microsoft`/`none`/`microsoft` | GitHub-hosted VM characterization |

The hosted Arm64 job proves that the tests execute successfully on the Arm64
architecture and kernel ABI in that VM. Under `linux-agent.md`, it is not a
substitute for physical Arm64 release evidence.

## Remaining blockers

The Linux source-tree handoff is not the vNext product implementation. These
items remain release-blocking:

- compose the exact child, held executable, collision-free inherited
  bootstrap fd, anonymous authenticated packet channel, nonce-bound HELLO, and
  lifecycle owner into one production session state machine;
- bind exact packet credentials, image identity, MDWE state, target facts, and
  negotiated transcript into an inseparable receipt before any authority can
  escape;
- implement the manifest-bound 1..=16 mixed-direction memory batch,
  authenticated `IMPORTED`/`SEALED`/READY/COMMIT sequence, poisoning, and
  public activation/close semantics;
- create and own the mandatory fresh process group and characterize ordinary
  descendant cleanup without claiming containment of an actively escaping
  malicious descendant;
- run exact-release physical Arm64 Linux conformance, fault/leak, and real-time
  suites; and
- exercise deterministic PID-reuse pressure and an uninterruptible `D`-state
  cleanup case where the host can do so safely. The current exact pidfd design
  avoids numeric-PID reuse authority, while a `D`-state child can still make
  bounded successful reap impossible and must remain reported incomplete.

The older public `backend/linux.rs` path still performs a separate
`SO_PEERCRED` observation followed by `pidfd_open` and has blocking cleanup in
`Drop`. That legacy behavior was not silently rewritten in this handoff. The
private vNext path demonstrates the replacement mechanisms but is not yet
connected to the public session API.
