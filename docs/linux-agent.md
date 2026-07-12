# Native Linux agent handoff

Tell the Codex agent on the Linux machine:

> Read `docs/linux-agent.md` completely and execute it.

## Mission

Take ownership of native Linux verification and troubleshooting for
`ro-ag/native-ipc-rs`. Native host execution is evidence; Docker and virtual
machines are characterization aids only.

Use `codex/native-ipc-vnext` as the baseline, but create a separate branch such
as `codex/linux-native-debug` before editing. Do not commit directly to the
baseline branch, merge, tag, publish, or weaken a normative requirement.

The 2026-07-12 execution record for this handoff is
[`linux-native-report.md`](linux-native-report.md). It records the exact
implementation SHA, direct-host evidence, hosted-runner classification, pushed
commits, fixed defects, accepted kernel limits, and remaining release blockers.

## Required reading

Before acting, read completely:

1. `docs/native-ipc-vnext-spec.md`
2. The architecture, changelog, and public-API sections inside that normative
   specification
3. `docs/architecture.md`
4. `docs/threat-model.md`
5. `docs/vnext-implementation-plan.md`
6. `docs/vnext-protocol-decisions.md`
7. `docs/vnext-feasibility.md`
8. `docs/vnext-traceability.md`
9. All Linux backend code, Linux tests, CI configuration, and open Linux issues

The vNext specification is normative and wins over conflicting older code or
prose. Preserve the asymmetric threat model: the spawning coordinator is
trusted safe Rust, while the spawned receiver may be malicious. Distinguish
safe-code ownership, kernel-enforced authority, authenticated-peer
assumptions, and guarantees the kernel cannot provide.

## Record the native environment

Before testing, save the output of:

```sh
uname -a
uname -m
cat /etc/os-release
rustc --version --verbose
cargo --version
git rev-parse HEAD
git status --short
systemd-detect-virt || true
```

The supported Rust toolchain is Rust 1.97 with edition 2024. The Linux NX
contract requires Linux 6.3 or newer. State explicitly whether the host is bare
metal, a VM, WSL, or a container. AMD64 execution proves AMD64 only; it does not
replace native Arm64 CI.

## Native focus

Run directly on the Linux host and investigate failures involving:

- `clone3(CLONE_PIDFD)` and exact pidfd identity;
- held-inode ELF execution and image replacement resistance;
- pre-exec MDWE installation and inheritance;
- `MFD_NOEXEC_SEAL` and exact memfd seal ordering;
- `SCM_RIGHTS` short reads and ownership of every installed fd;
- absolute deadlines under continuous hostile traffic;
- nonblocking `Drop`, exact-child termination, durable reaping, and PID reuse;
- `SIGCHLD=SIG_IGN` and `SA_NOCLDWAIT` behavior;
- fd, thread, process, zombie, directory, and mapping leak cycles; and
- process containment and descendant cleanup limits.

Use `strace`, `/proc`, kernel logs, and targeted fault injection when useful.
Do not infer native permission or lifecycle guarantees from cross-compilation
or Docker results.

## Validation

Start with:

```sh
cargo fmt --all -- --check
git diff --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features -- --test-threads=1
cargo test --workspace --no-default-features -- --test-threads=1
```

Then repeat the relevant lifecycle, permission, failure-injection, and leak
tests enough times to expose timing-sensitive failures. Use the repository CI
commands when they are stricter than this baseline.

## Editing rules

- Add a failing test before or with each fix.
- Keep changes Linux-specific and reviewable.
- Do not modify macOS or Windows behavior to accommodate a Linux result.
- Do not expose raw fds or weaken the opaque shared-memory handle API.
- Do not enable receipt, session, or memory authority from partial evidence.
- Preserve unrelated and untracked files.
- Use small conventional commits with no `Co-authored-by` trailer.
- Push fixes only to the separate Linux branch.

## Report back

Report:

- host and kernel facts;
- exact tested commit and commands;
- passing and failing native evidence;
- `strace` or `/proc` evidence relevant to each failure;
- whether the result is a code defect, environmental restriction, or kernel
  limit;
- commits pushed to the Linux branch; and
- remaining unverified targets or release blockers.

Never claim completion from a happy path, unit tests alone, Docker, or
cross-compilation. If a native guarantee cannot be established, leave the
target unverified and release-blocking rather than weakening the contract.
