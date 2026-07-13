# Dead-code and test-seam audit

This inventory records the cleanup boundary after private Linux G1l and macOS
6c. It is not vNext completion evidence. Linux and macOS now privately compose
READY/COMMIT, all-or-nothing activation, and the active-resource ledger;
public macOS session/control APIs and the equivalent Windows reducer remain
unavailable.

## Dead-code suppression inventory

There are 53 explicit `dead_code` allowances after the legacy Linux retirement.
The table accounts for every site; counts include `cfg_attr` allowances that
exist only on targets where the corresponding private implementation is not
yet reachable.

| File | Sites | Classification | Retained reason |
| --- | ---: | --- | --- |
| `protocol.rs` | 15 | unfinished reducer and target-specific | Canonical capability, IMPORTED/SEALED, authority-profile, access, totals, entry, and exact-frame machinery is consumed by private Linux and macOS reducers but remains unreachable or intentionally unused on Windows until its accepted reducer exists. The legacy-profile manifest constructor remains compiled for unfinished target composition and tests. |
| `active.rs` | 11 | private activation composition | Leased reader/writer owners, reservations, activation failures, liveness observations, and ordered mapping-before-lease destruction are consumed by the private Linux and macOS all-or-nothing activation boundaries but remain unreachable from the public macOS API and Windows reducer. |
| `region.rs` | 5 | unfinished batch composition | Prepared native request/spec/guard fields and logical/mapped accessors cross into the private batch/native preparation owners; they are not obsolete pending accepted-session composition on every target. |
| `batch.rs` | 5 | private READY/COMMIT composition | Transfer construction, pending ownership, committed direction variants, and keyed active-set construction are consumed by the private Linux and macOS reducers but remain withheld from public macOS and Windows composition. |
| `lib.rs` | 5 | four unfinished private modules; one obsolete status scaffold | `batch`, `control`, `liveness`, and `negotiation` remain private until full composition. `BackendStatus` and `windows::status` have no production consumer and are a later target-scoped cleanup candidate. |
| `backend/mod.rs` | 4 | unfinished role evidence and target-specific | The backend-wide allowance covers unreachable role-scoped evidence and accepted transport traits; the macOS, Windows, and `linux_vnext` module allowances cover target-only compilation. The retained legacy-free Linux allocator overrides the blanket with `deny(dead_code)`. |
| `memory.rs` | 4 | unfinished native batch composition | Incarnation, logical length, and native manifest derivation are consumed by the Linux private batch adapter and will be required by the other target adapters. |
| `session.rs` | 2 | unfinished native negotiation composition | Verified atomic discovery and required-width validation are private HELLO inputs; Linux uses them, while public Ready construction and other target adapters remain incomplete. |
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

The production tree contains 342 `cfg(test)` gates: 19 are adjacent
`*_test.rs` module wiring and 323 are deliberate production seams. The latter
are concentrated as follows.

| Production file | Non-wiring seams | Purpose |
| --- | ---: | --- |
| `backend/accepted_control.rs` | 146 | Exact record mutation/truncation/rights/credential/replay/interleaving faults plus mixed READY/COMMIT, activation, accepted-owner, and poison-before-resource-drop observations. |
| `backend/linux_vnext/memory.rs` | 121 | Exact Nth preparation/seal/advice/activation failures, native-object substitution, full-mixed-batch attenuation, mapping/drop observations, and fd/map baselines. |
| `backend/linux_vnext/spawn.rs` | 22 | Entropy, inherited-fd, credential, send/receive, poison, and exact-child publication faults. |
| `backend/linux_vnext/process.rs` | 14 | Signal, poll, wait/reap, auto-reap, and terminal-cleanup fault injection. |
| `liveness.rs` | 7 | Session-ledger observations, exact charge accounting, and mapping-before-lease destruction evidence. |
| `region.rs` | 6 | Prepared-owner destruction ordering observations. |
| `backend/linux_vnext.rs` | 5 | Packet/descriptor boundary faults and native transport observations. |
| `backend/macos/bootstrap.rs` | 1 | Native bootstrap test behavior. |
| `backend/windows.rs` | 1 | Bounded test timeout for native child/pipe cases. |

These seams are not consolidated in this cleanup. Their locations select the
exact native operation or ownership transition under test; moving them behind
a coarser shared switch could change first/middle/final operation numbering,
production ordering, or poison-before-drop evidence. Any later consolidation
must preserve the same production branch, Nth-operation index, and resource
baseline assertions on every supported native target.
