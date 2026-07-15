# Dead-code and test-seam audit

This inventory records the cleanup boundary after public Linux G1m, public
Windows composition, and the blocked macOS 6d prototype. It is not vNext
completion evidence. Linux and Windows compose the safe public session/control
surface. macOS privately composes READY/COMMIT, all-or-nothing activation, and
the active-resource ledger, but public spawn/bootstrap remain fail-closed
pending an independently privileged containment authority. The private
bootstrap now also carries the cooperative trace handshake, hard no-fork
limit, exec trap, and exact ptrace lifecycle used by its native proof corpus.

## Dead-code suppression inventory

There are 60 explicit `dead_code` allowances after the legacy Linux retirement.
The table accounts for every site; counts include `cfg_attr` allowances that
exist only on targets where the corresponding private implementation is not
yet reachable.

| File | Sites | Classification | Retained reason |
| --- | ---: | --- | --- |
| `protocol.rs` | 17 | unfinished public composition and target-specific | Canonical capability, IMPORTED/SEALED, READY/COMMIT, authority-profile, access, totals, entry, and exact-frame machinery is consumed by the Linux public and macOS/Windows private reducers. The legacy-profile manifest constructor remains compiled for unfinished target composition and tests. |
| `active.rs` | 11 | target activation composition | Leased reader/writer owners, reservations, activation failures, liveness observations, and ordered mapping-before-lease destruction are consumed by the public Linux/Windows and private macOS all-or-nothing activation boundaries. |
| `region.rs` | 5 | unfinished batch composition | Prepared native request/spec/guard fields and logical/mapped accessors cross into the private batch/native preparation owners; they are not obsolete pending accepted-session composition on every target. |
| `batch.rs` | 5 | target READY/COMMIT composition | Transfer construction, pending ownership, committed direction variants, and keyed active-set construction are consumed by the public Linux/Windows reducers and private macOS reducer. |
| `lib.rs` | 4 | unfinished private modules | `batch`, `control`, `liveness`, and `negotiation` remain private until full composition. |
| `backend/mod.rs` | 3 | unfinished role evidence and target-specific | The backend-wide allowance covers unreachable role-scoped evidence and accepted transport traits; target-only compilation retains the macOS and `linux_vnext` module allowances. The retained legacy-free Linux allocator overrides the blanket with `deny(dead_code)`. |
| `memory.rs` | 4 | unfinished native batch composition | Incarnation, logical length, and native manifest derivation are consumed by the Linux private batch adapter and will be required by the other target adapters. |
| `session.rs` | 9 | unfinished target negotiation composition | Verified atomic discovery and required-width validation remain private HELLO inputs; Linux and Windows consume the public variants, while blocked macOS variants preserve the reviewed prototype and production spawn/bootstrap fail closed pending public crash-surviving exact containment. |
| `backend/macos.rs` | 2 | target-specific landed backend | The consuming local/remote writer owners are used by the macOS transfer path; the broad struct allowances currently cover target-only fields and should be narrowed only with native macOS warning checks. |
| `backend/macos/supervisor.rs` | module-private | future signed-service boundary | Bounded authentication/spawn framing, absolute Darwin deadline, exact-Mach-audit peer facts, freshness types, and immutable installed-policy resolution intentionally remain unreachable until the privileged raw Mach adapter exists. |
| `backend/macos/supervisor_auth_adapter.rs` | module-private | future fused Mach/Security boundary | The source-native raw receiver enforces canonical audit trailers, bounded malformed/complex/oversize cleanup, linear send-once replies, and authentication-before-routing. Fixed-capacity one-job workers bind retained exact-message bytes/token/credentials/deadline to actual one-shot pipe FDs and typed exact clean reap. The direct-child owner signals only under a sole-waiter unreaped-child relation and fails stop after authority loss. Accepted spawn freshness remains bound to the request's send-once reply through later transformations. A one-shot non-sendable startup token verifies main-thread, pre-thread, default-zombie SIGCHLD prerequisites and blocks SIGCHLD. The fixed source spawner owns pipe creation, file actions, `posix_spawn`, and the immediate positive-PID-to-armed-authority transition; the fixed clean-exec entry validates FD 3/FD 4, dynamically loads Security.framework only in the worker, authenticates one exact audit token, and retains FD 4 through exit. A native composition test reaches the real entry and exact reap without statically linking Security/CoreFoundation into the surrounding binary. It exposes no request-selected PID, signal, task, path, requirement string, or filesystem deputy and remains unreachable until an installed service supplies a separately packaged, signed, root-owned worker, verifies the fixed image and policy constants, and establishes the complete process-wide waiter policy. |
| `backend/macos/supervisor_broker_spawn.rs` | module-private | future fixed installed broker creation | The installation-only exact-path spawner prepares fixed vectors and canonical signals, collision-normalizes the start/death, plan/ACK, and trace-report channels, immediately arms direct-child authority after positive spawn, and keeps the exact report receipt sealed with that atomic spawn through watchdog registration. Registration precedes one nonblocking activation byte. Exact wait precedes every signal; `ECHILD` fails stop without numeric fallback. It is not installation or signing evidence. |
| `backend/macos/supervisor_broker_plan.rs` | module-private | future broker staging channel | Only the complete authenticated reply plus assigned session can mint the bounded canonical authority-free launch frame. The frame binds the original wire deadline, freshness, full peer identities, opaque session, installed policy target, argv, and environment; hostile counts reject before allocation. Received bytes remain a distinct non-authoritative type, reuse the one conservative deadline binding, and become broker-consumable only after exact-parent FD4 EOF/complete-frame ACK followed by FD3 START. |
| `backend/macos/supervisor_broker_report.rs` | module-private | future trace-proof return channel | A fixed 224-byte report binds the original deadline, connection/sequence, opaque session, client credentials/nonces, target identity, and domain-separated complete-plan digest. The nonblocking service receipt requires exact bytes plus EOF from the FD 5 endpoint sealed into the same atomic broker spawn; only exact registered-session binding can construct production `TraceEstablished`. Missing, malformed, extended, late, or substituted output exact-cleans. The test emitter models consumed stops; the native broker-local launcher still must supply them. |
| `backend/macos/supervisor_broker_entry.rs` | module-private | future packaged broker entry | The fixed process adopts a read-only FIFO at FD 3 plus bidirectional Unix streams at FD 4 and FD 5. It gate-first receives one deadline-bounded length-exact plan, requires write EOF, returns a digest ACK, then accepts one START before the same deadline while retaining service-death EOF. An unsafe post-two-stop transition may emit one canonical FD 5 report while continuing to prioritize service death. Wrong/repeated/early bytes, extensions, descriptor substitution, and expiry fail closed. The packaged executable and native launcher/effect loop remain required. |
| `backend/macos/supervisor_client.rs` | module-private | future signed-service client | One-shot client authentication binds the installed service's exact-message identity, fresh reply facts, and single spawn effect. Its receive-only spawn result accepts only an authenticated opaque handle or coarse failure; no production ready encoder or public session consumes it yet. |
| `backend/macos/supervisor_watchdog.rs` | module-private | future privileged watchdog | Opaque session state and linear exact broker/reap proofs model cleanup ownership without exposing PID/signal/task authority. A generic sealed report receipt now survives atomic spawn and registration, closes before exact cleanup, and can bind trace state only through the authenticated FD 5 token; no launchd service consumes it yet. |
| `backend/macos/supervisor_launcher.rs` | module-private | future packaged launcher | The trace/session/target-bound irreversible ID drop and immediate-exec transition may run only in the separately packaged single-threaded launcher; the library process must never call it. |

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
| `backend/macos/bootstrap.rs` | 39 | Mach send/receive shape and deadline faults, right-drop observations, exact-child wait interruption/delay, suspended task/audit and proc-identity characterization, task-identity-token exec behavior, cooperative trace/exec/crash/stop paths, hard no-fork limits, trusted-launcher handshake, exact ptrace lifecycle, and native helper behavior. |
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
