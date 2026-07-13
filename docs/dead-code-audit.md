# Dead-code and test-seam audit

This inventory records the cleanup boundary after public Linux G1m and the
blocked macOS 6d prototype. It is not vNext completion evidence. Linux composes
the safe public session/control surface. macOS privately composes READY/COMMIT,
all-or-nothing activation, and the active-resource ledger, but public
spawn/bootstrap remain fail-closed pending exact pre-bootstrap termination; the
equivalent Windows reducer and public session remain unavailable.

## Dead-code suppression inventory

There are 60 explicit `dead_code` allowances after the legacy Linux retirement.
The table accounts for every site; counts include `cfg_attr` allowances that
exist only on targets where the corresponding private implementation is not
yet reachable.

| File | Sites | Classification | Retained reason |
| --- | ---: | --- | --- |
| `protocol.rs` | 17 | unfinished reducer and target-specific | Canonical capability, IMPORTED/SEALED, authority-profile, access, totals, entry, and exact-frame machinery is consumed by private Linux and macOS reducers but remains unreachable or intentionally unused on Windows until its accepted reducer exists. The legacy-profile manifest constructor remains compiled for unfinished target composition and tests. |
| `active.rs` | 11 | target activation composition | Leased reader/writer owners, reservations, activation failures, liveness observations, and ordered mapping-before-lease destruction are consumed by the public Linux and private macOS-prototype all-or-nothing activation boundaries but remain unreachable from the unfinished Windows reducer. |
| `region.rs` | 5 | unfinished batch composition | Prepared native request/spec/guard fields and logical/mapped accessors cross into the private batch/native preparation owners; they are not obsolete pending accepted-session composition on every target. |
| `batch.rs` | 5 | target READY/COMMIT composition | Transfer construction, pending ownership, committed direction variants, and keyed active-set construction are consumed by the public Linux reducer and private macOS prototype but remain withheld from unfinished Windows composition. |
| `lib.rs` | 4 | unfinished private modules | `batch`, `control`, `liveness`, and `negotiation` remain private until full composition. |
| `backend/mod.rs` | 3 | unfinished role evidence and target-specific | The backend-wide allowance covers unreachable role-scoped evidence and accepted transport traits; target-only compilation retains the macOS and `linux_vnext` module allowances. The retained legacy-free Linux allocator overrides the blanket with `deny(dead_code)`. |
| `memory.rs` | 4 | unfinished native batch composition | Incarnation, logical length, and native manifest derivation are consumed by the Linux private batch adapter and will be required by the other target adapters. |
| `session.rs` | 9 | unfinished target negotiation composition | Verified atomic discovery and required-width validation remain private HELLO inputs; blocked macOS public-session variants preserve the reviewed prototype while production spawn/bootstrap fail closed pending exact pre-bootstrap termination. |
| `backend/macos.rs` | 2 | target-specific landed backend | The consuming local/remote writer owners are used by the macOS transfer path; the broad struct allowances currently cover target-only fields and should be narrowed only with native macOS warning checks. |

### Obsolete Linux code removed

The retired `backend/linux.rs` path had no production consumer outside its own
module and adjacent tests. It comprised the filesystem bootstrap directory,
`UnixListener`/`UnixStream` authentication, cached `SO_PEERCRED` plus
post-construction `pidfd_open`, single-region descriptor framing,
`NIPCFD`/READY/COMMIT exchange, legacy reader/writer mapping witnesses, and
blocking child cleanup. The private vNext path already owns the replacement
anonymous `SOCK_SEQPACKET`, per-record credentials, clone-time pidfd, exact
child/image lifecycle, and canonical batch framing.

The following legacy Linux primitives remain live and were not removed:

- `QuiescentRegion::new`, `len`, `logical_len`, `as_bytes`, and `as_bytes_mut`
  implement the public `memory::NativeRegion` allocation and initialization
  facade;
- `as_raw_fd_for_vnext` and `into_vnext_unmapped_parts` transfer that same
  private allocation into `linux_vnext::memory::PrivateMemfd`; and
- `Mapping`, page rounding, native advice, and `LinuxError` retain the exact
  allocation/mapping ownership needed by both consumers.

No legacy Linux transfer, bootstrap, reader/writer witness, or native test
remains without a production consumer. The retained module uses
`deny(dead_code)` so a new unconsumed Linux item fails compilation.

## `cfg(test)` seam inventory

The production tree contains 426 `cfg(test)` gates: 23 are adjacent
`*_test.rs` module wiring and 403 are deliberate production seams. The latter
are concentrated as follows.

| Production file | Non-wiring seams | Purpose |
| --- | ---: | --- |
| `backend/accepted_control.rs` | 179 | Exact record mutation/truncation/rights/credential/replay/interleaving faults plus Linux/macOS mixed READY/COMMIT, capacity preflight, activation, accepted-owner, and poison-before-resource-drop observations. |
| `backend/linux_vnext/memory.rs` | 121 | Exact Nth preparation/seal/advice/activation failures, native-object substitution, full-mixed-batch attenuation, mapping/drop observations, and fd/map baselines. |
| `backend/linux_vnext/spawn.rs` | 27 | Entropy, inherited-fd, credential, send/receive, poison, and exact-child publication faults. |
| `backend/linux_vnext/process.rs` | 15 | Signal, poll, wait/reap, auto-reap, and terminal-cleanup fault injection. |
| `backend/macos/bootstrap.rs` | 16 | Mach send/receive shape and deadline faults, right-drop observations, exact-child wait interruption/delay, lifecycle extraction, and native helper behavior. |
| `backend/macos.rs` | 5 | Mapping/right creation and protection-failure observations for adjacent native memory tests. |
| `liveness.rs` | 7 | Session-ledger observations, exact charge accounting, and mapping-before-lease destruction evidence. |
| `region.rs` | 7 | Prepared-owner destruction ordering observations. |
| `backend/macos_vnext/memory.rs` | 7 | Nth native preparation/import/activation failures and exact Mach mapping/right-drop observations. |
| `backend/macos_vnext/transport.rs` | 8 | Accepted channel fault injection, lifecycle test construction, and right/record boundary observations. |
| `backend/linux_vnext.rs` | 5 | Packet/descriptor boundary faults and native transport observations. |
| `control.rs` | 4 | Bounded allocation and exact control-state test observations. |
| `backend/windows.rs` | 1 | Bounded test timeout for native child/pipe cases. |
| `backend/macos_vnext/session.rs` | 1 | Native child-exit authority assertion used by the production session integration test. |

These seams are not consolidated in this cleanup. Their locations select the
exact native operation or ownership transition under test; moving them behind
a coarser shared switch could change first/middle/final operation numbering,
production ordering, or poison-before-drop evidence. Any later consolidation
must preserve the same production branch, Nth-operation index, and resource
baseline assertions on every supported native target.
