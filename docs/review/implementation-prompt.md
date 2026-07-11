# Implementation prompt

Copy the text below into a new Codex chat.

```text
Take ownership of the next hardening slice for this repository:

- Local repository: /Users/rodox/dev/rs/native-ipc-rs
- GitHub repository: https://github.com/ro-ag/native-ipc-rs
- Default branch: main
- Rust edition: 2024
- Toolchain/MSRV: Rust 1.97
- License: MIT OR Apache-2.0

The repository may contain untracked review documents under `docs/review/`.
They are intentional user work. Preserve them and include the canonical review
artifacts in this branch; do not delete, overwrite, or regenerate the original
model reports.

Git rules
=========

1. Inspect `git status`, remotes, and recent history first.
2. Start from the current local `main` and create a new branch named
   `fix/consolidated-review-findings`. If it already exists, do not overwrite
   it; inspect it and choose a clearly related unused branch name.
3. Never add `Co-authored-by` or any other co-author trailer to commits.
4. Make intentional, concise commits grouped by invariant or subsystem.
5. Do not merge the branch. Do not push or open a pull request unless the user
   explicitly asks during the session.

Primary sources of truth
========================

- `docs/review/consolidated-2026-07-10.md`
- `docs/review/README.md`
- `docs/architecture.md`
- `docs/threat-model.md`
- `README.md`

Read the consolidated review completely before editing. Use the individual
reports only as supporting evidence. The consolidated report's disposition
overrides individual reports.

Use several concise independent reviewers because the protocol spans distinct
risk domains:

- one reviewer for ring and acknowledgement state-machine correctness;
- one reviewer for unsafe code, Rust aliasing, mapping permissions, and Mach
  capability lifetimes; and
- one reviewer for adversarial tests, Miri/Loom/fuzz feasibility, CI, and
  documentation consistency.

Keep implementation ownership in the main chat. Reconcile claims against code
rather than counting votes. Before handoff, run a final independent review of
every unsafe block and every cross-process aliasing invariant.

Goal
====

Resolve every accepted P1 and P2 finding in the consolidated review, or leave a
specific evidence-backed deferral only when work belongs to an explicitly
incomplete native backend. Do not stop after writing a plan. Implement and
validate the largest coherent safe slice that closes common-core and macOS
issues without pretending Linux or Windows transports exist.

Required work
=============

1. Make acknowledgement routing correct for multi-slot rings.

   - Model a route with exact owner role, target role, slot index, and
     acknowledgement cell index, or an equivalently strong type.
   - Make ambiguous shared-cell configurations impossible through safe APIs, or
     reject them during region composition.
   - Validate that roles exist, are directionally valid, and match the selected
     slot and cell.
   - Preserve exact target, generation, and prior-sequence checks. Do not weaken
     future-ack rejection to `>=` merely to make tests pass.
   - Add a two-slot test covering at least two complete rotations, plus
     wrong-cell, wrong-slot, wrong-owner, stale, lagging, future, and wrap cases.

2. Define honest snapshot semantics before adding runtime payload access.

   - Treat every copied payload byte as hostile, including torn or
     same-sequence mutation by a malicious writer.
   - Do not claim that generation/sequence recheck proves payload integrity.
   - Add the ordering primitive needed to keep future payload reads before the
     final metadata recheck on weakly ordered hardware.
   - Include the observed payload length in the post-copy recheck contract.
   - If choosing an odd/even seqlock or stronger mechanism, document exactly
     which malicious-writer behaviors it detects and add adversarial tests.
   - Do not add cryptography both peers can trivially forge and call it
     integrity.
   - Align the threat model, architecture, README, and rustdoc with the exact
     guarantee implemented.

3. Make the shared-record representation sound for external mutation.

   - Every byte a peer may write needs an explicit interior-mutation model.
     Plain reserved fields must not remain frozen behind long-lived shared
     references if a remote writer can modify them.
   - Preserve the 64-byte size/alignment contract unless intentionally making a
     versioned wire change.
   - Add compile-time `size_of`, `align_of`, and `offset_of` assertions for all
     fields accessed through the byte initializer or validator.
   - Document why each shared record is `Sync` if a manual implementation is
     required.

4. Build one audited core-to-platform binding boundary.

   - Centralize conversion from a validated mapping and checked ranges to slot
     and acknowledgement capabilities. Embedders must not repeat raw casts.
   - Prove base provenance, size, alignment, initialization, generation, role,
     slot/cell index, mapping lifetime, and absence of conflicting writable
     aliases.
   - Prevent duplicate writer binding through safe APIs by consuming a unique
     mapping/ownership token or an equivalently strong mechanism.
   - Runtime APIs must continue to avoid ordinary Rust slices into memory a
     peer can mutate.

5. Replace caller-asserted permissions with platform-minted witnesses.

   - Reader bindings must originate from native read-only mapping witnesses;
     writer bindings must originate from sole-writer mapping witnesses.
   - A plain public enum must not stand in for OS-enforced rights at the safe
     integration boundary.
   - Keep low-level escape hatches unsafe and document permission, lifetime,
     provenance, and aliasing preconditions.
   - On macOS, preserve the consuming quiescent/local-writer/remote-writer
     typestate and live kernel tests for read-only and execute protections.

6. Reconcile logical length and native capability size.

   - Make page rounding an explicit negotiated and validated part of the macOS
     mapping contract, or prove a narrower memory-entry capability is enforced.
   - Validate and zero all padding covered by a peer capability.
   - Do not expose unvalidated slack as an undocumented channel.

7. Strengthen verification and the testkit.

   - Add reusable hostile layout, slot, acknowledgement, and mapping fixtures to
     `native-ipc-testkit`; its public description must match its real scope.
   - Add a core-to-platform integration test for the complete
     initialize→validate→bind→publish→observe→recheck→acknowledge path.
   - Add `cargo test --workspace --no-default-features --all-targets --locked`
     and `git diff --check` to CI.
   - Add a practical Miri job for platform-neutral core if current nightly
     supports it. Document precise exclusions for unsupported native paths.
   - Add a Loom model or dependency-free equivalent for publication and
     acknowledgement interleavings, without letting the model diverge from
     production semantics.
   - Add fuzz targets or deterministic adversarial corpora for envelope and
     layout decoding with explicit resource limits.

8. Resolve accepted documentation and API cleanup in touched areas.

   - State whether acknowledgements are intentionally idempotent. Keep or reject
     equal-sequence re-acknowledgement based on that explicit contract.
   - Make minor-version documentation match exact-equality behavior, or
     implement and test the intended compatible-minor rule.
   - Update architecture, threat model, README status, changelog, and public
     rustdoc as guarantees change.
   - Keep Linux and Windows explicitly incomplete and fail closed. Do not add
     false stubs to make the platform matrix appear complete.

Non-findings
============

Do not spend the session fixing these rejected claims unless new evidence
changes the analysis:

- the relaxed `payload_len` load after the matching Acquire sequence load is
  ordered by the writer's Release publication;
- fixed-range codec helper `expect` calls are not reachable from current
  hostile input;
- `WrongSlot { expected, actual }` uses the correct interpretation;
- private `align_up` receives a fixed power-of-two alignment;
- `RegionLayout::writer()` is not reachable from hostile decoded headers;
- deallocating a successful Mach allocation at address zero is correct cleanup;
  and
- encoder output need not obey the local decoder's resource policy.

Validation gate
===============

Run all applicable checks before handoff:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-features --all-targets --locked -- -D warnings
cargo test --workspace --all-features --all-targets --locked
cargo test --workspace --no-default-features --all-targets --locked
cargo check --workspace --no-default-features --all-targets --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
cargo deny check
git diff --check
```

Also run native permission tests on macOS and compile-check Linux and Windows
target surfaces. Run any new Miri, Loom, fuzz-corpus, or integration checks
introduced by the branch. Do not weaken or skip a failing check to obtain green
output.

Handoff requirements
====================

End with:

- branch name and commit IDs;
- accepted findings fixed, with code and test references;
- findings deliberately deferred and the exact blocker;
- local validation results;
- unsafe/aliasing review outcome;
- incomplete platform work stated explicitly; and
- the next recommended implementation slice.

Do not claim completion merely because the code compiles. The branch is ready
only when the implemented guarantees, adversarial tests, and documentation all
agree.
```
