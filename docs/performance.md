# Performance measurement

Performance changes in this repository use optimized artifacts and preserve the
same security, deadline, and resource-bound contracts as functional tests.
Wall-clock results are evidence, not correctness assertions.

## Workload matrix

| Workload | Inputs | Metrics | Command |
| --- | --- | --- | --- |
| Active shared-memory access | 64 KiB regions, 4 KiB read/write/fill chunks, 10,000 iterations after prefault | allocator events, faults, syscalls, context switches, p50/p95/p99 | `cargo test --release -p native-ipc --test rt -- --nocapture` |
| Core acknowledgement-route lookup | 4,096 routes, 100,000 worst-position lookups | elapsed time and lookup throughput | `cargo test --release -p native-ipc-core layout::tests::large_topology_route_lookup_benchmark -- --exact --ignored --nocapture` |
| Control framing | empty, typical, and maximum negotiated payloads | bytes written, allocations, p50/p95/p99 round-trip latency | platform session benchmark required; the codec regression tests currently prove only canonical wire equivalence |
| Batch transfer | 1, 2, 4, and 16 mixed-direction regions at small and maximum aggregate sizes | preparation/transfer/commit p50/p95/p99, allocations, peak RSS | run the platform-native public session corpus; a dedicated repeated timing harness is still required |
| Mapping lifecycle | 4 KiB, 1 MiB, 64 MiB, and maximum supported mappings | allocation/map/prepare/close latency, faults, peak RSS | run on each native target; cross-compilation is not runtime evidence |

Record the exact revision, OS, architecture, CPU, Rust version, profile, input
sizes, repetition count, median, spread, peak RSS, and allocation/fault/syscall
counters with every result. Linux and Windows claims require native runners;
cross-compilation proves buildability only.

## Current named-machine baseline

Revision `e9b30533390d28a2bdc854fdaffa984f2dd7a9e5` plus the performance branch was
measured on an Apple M4 Max running macOS 26.5.2 with Rust 1.97.0.

- The active-path test reported zero measured allocator entries and zero faults
  over 10,000 iterations of 4 KiB write/read/fill after prefault. Observed 4 KiB
  read/write medians were approximately 0.54–0.71 microseconds across runs.
- Before the route index, 100,000 lookups over 4,096 routes took 113.358 ms.
  With the bounded sorted index they took 2.50–2.63 ms, approximately 43–45
  times faster for this large-ring workload.

No CPU sampling profile is claimed for the short active test window. Xcode's
`xctrace` is unavailable on the named machine; a longer-lived workload is
required before `/usr/bin/sample` can provide useful attribution.

## Native guest validation

The exact performance-branch working tree was copied to local guest storage
and validated with Rust 1.97.0 in Parallels Desktop. These runs exercise the
platform transports but do not claim bare-metal latency:

- Ubuntu 24.04.3 LTS ARM64 on virtualized Apple Silicon passed formatting,
  Clippy with warnings denied, serialized all-feature and no-default-feature
  release workspace tests, and the Linux public-session corpus. The main
  library result was 184 passed and 56 ignored in both feature modes. The route
  workload completed in 2.909 ms.
- Windows 11 Pro 10.0.26200 ARM64 on virtualized Apple Silicon passed the same
  gates and the Windows named-pipe/public-session corpus. The main library
  result was 138 passed and 22 ignored in both feature modes. The route workload
  completed in 2.689 ms.

The guest `rt` target contains only its allocator tripwire outside macOS, so it
does not provide Linux or Windows active-path latency evidence. Dedicated
platform timing harnesses remain necessary for control, batch, and mapping
lifecycle latency distributions.
