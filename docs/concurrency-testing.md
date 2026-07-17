# Concurrency testing recommendation

## Decision

Adopt Loom narrowly for small, syscall-free synchronization seams. Do not try
to run the native reapers or transports themselves under a model checker.

The first model covers the macOS lifecycle's external-owner drop to detached-
reaper termination latch. The previous implementation inferred the final
external owner from `Arc::strong_count`. Rust documents that another thread can
change that count between observation and action; two concurrent final drops
can both observe the earlier count and both decline to terminate. The
production path now uses a separate atomic external-owner count, and Loom
exhaustively checks the same owner token's `Clone`/`Drop` orderings and the
termination publication. The current private call sites ordinarily create and
destroy their temporary clones on one thread, so this is a latent
synchronization defect, not an explanation for a known CI failure.

Loom 0.7.2 is the best fit for this bounded model. It permutes executions under
its C11 memory model and supports the atomics needed here. Shuttle 0.9.1 is
newer and better suited to larger state machines because it offers randomized,
PCT, replay, and bounded DFS schedulers, but a passing randomized run is not a
proof and Shuttle still requires replacing `std` synchronization imports. For
this two-owner state, Shuttle's scalability does not offset Loom's exhaustive
result. Cargo-nextest retry or stress modes only rerun the host scheduler; they
do not enumerate this ordering and should not turn flaky success into a green
correctness claim.

Primary tool documentation:

- [Loom 0.7.2](https://docs.rs/loom/0.7.2/loom/) describes exhaustive
  permutation testing, the required synchronization shims, and its incomplete
  weak-memory coverage.
- [Shuttle 0.9.1](https://docs.rs/shuttle/0.9.1/shuttle/) documents its
  soundness/scalability trade-off and deterministic schedule replay.
- [Miri's data-race detector](https://doc.rust-lang.org/nightly/nightly-rustc/miri/concurrency/data_race/)
  detects races in executions it interprets, but does not replace schedule
  enumeration.
- [cargo-nextest retries](https://nexte.st/docs/features/retries/) document
  rerun and flaky-result behavior rather than model checking.

## Coverage boundary

The Loom test adds deterministic interleaving coverage that the existing CI
does not provide. Miri currently interprets only `native-ipc-core`'s platform-
neutral unsafe contracts. AddressSanitizer runs the native crate and catches
instrumented memory errors and leaks, but it does not systematically enumerate
logical synchronization orderings.

Loom cannot model the kernel behaviors behind the recent CI flakes: a returned
thread lingering in `/proc/self/task`, socket close-to-`poll` HUP propagation,
`waitpid`/pidfd reaping, or ptrace teardown. Those invariants must retain their
bounded retry-with-deadline checks. Deadlines remain escape bounds, never
elapsed-time correctness assertions. The constrained macOS CI leg must also
retain `CARGO_BUILD_JOBS=1`.

Broader reaper coverage would require separating every syscall result from the
Linux and macOS `Mutex`/`Condvar`/atomic state transitions and routing all
thread operations through model-aware shims. That refactor is not justified by
one model: the crate is syscall-heavy, accepted-control and negotiation state
is currently uniquely borrowed, and the existing kernel-facing tests remain
necessary. Isolate another small pure synchronization seam only when it changes
or when a concrete in-process ordering risk is found.

Run the adopted model with:

```sh
RUSTFLAGS="--cfg loom" cargo test -p native-ipc --lib --locked \
  backend::reaper_ownership_tests::concurrent_final_owner_drops_latch_reaper_termination \
  -- --exact
```

Do not broaden that cfg-Loom invocation to the crate's ordinary tests. The
shared helper intentionally switches to Loom primitives only for test builds,
and those primitives must execute inside a `loom::model` closure. CI additionally
checks the libtest summary so a stale or misspelled filter cannot pass after
running zero models.
