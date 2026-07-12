# vNext normative traceability matrix

This matrix is the release ledger for the normative requirements in
[`native-ipc-vnext-spec.md`](native-ipc-vnext-spec.md). A test name beginning
with `planned::` does not exist yet and is not evidence. Native evidence is
recorded only for execution on the named OS/architecture; compilation and
cross-compilation never change a target from `unverified` to `verified`.

Evidence states: `planned`, `implemented`, `verified`, `unverified`, `blocked`,
and `n/a`.
The exact release commit SHA and CI run URL must replace every `planned` or
`unverified` cell before release.

Target abbreviations: `Lx` = Linux GNU AMD64/Arm64, `Ma` = macOS Arm64,
`Wx` = Windows AMD64/Arm64, and `All` = all five native targets.

| ID | Normative MUST / MUST NOT | Owning module or document | Positive test/evidence | Negative test/evidence | Native target evidence |
| --- | --- | --- | --- | --- | --- |
| R2.1 | Safe allocation is anonymous, zeroed, and non-executable. | `native-ipc::region`, private `backend::*` | `planned::native::allocation_zero_nx` | `planned::native::execute_upgrade_rejected` | All unverified |
| R2.2 | Initialization is quiescent before capability escape. | `native-ipc::region` typestates | `planned::ui::private_initialize` | `planned::ui::prepared_has_no_payload` | portable planned; All unverified |
| R2.3 | Writer direction is a consuming per-region choice. | `native-ipc::region` | `planned::api::both_writer_directions` | `planned::ui::private_reuse_after_prepare` | All unverified |
| R2.4 | Region handles are opaque and application-neutral. | facade public API | `planned::api::opaque_region_handle` | `planned::api::no_native_or_app_types` | portable planned |
| R2.5 | Bootstrap authenticates the library-owned exact child. | `session`, private `backend::*::process` | `planned::native::exact_child_auth` | `planned::native::wrong_child_rejected` | All unverified |
| R2.6 | A heterogeneous batch contains 1 through 16 regions. | `batch` | `planned::batch::counts_1_2_4_16` | `planned::batch::counts_0_17_rejected` | All unverified |
| R2.7 | A batch permits arbitrary writer-direction mixtures. | `batch` | `planned::batch::all_direction_profiles` | `planned::batch::wrong_direction_rejected` | All unverified |
| R2.8 | One canonical manifest and READY/COMMIT covers the complete batch. | `wire::manifest`, `batch` | `planned::batch::one_barrier_full_transcript` | `planned::batch::partial_or_mutated_transcript` | All unverified |
| R2.9 | Runtime visibility is all-or-nothing at both endpoints. | `batch::PendingBatch`, `active` | `planned::batch::complete_activation` | `planned::batch::nth_failure_exposes_none` | All unverified |
| R2.10 | Runtime copies are checked/allocation-free and pointer access is explicitly unsafe. | `active`, feature `raw-pointer` | `planned::rt::checked_copy_contract` | `planned::ui::safe_pointer_unavailable` | All unverified |
| R2.11 | Session owns exit observation, poison, termination, reap, and cleanup. | `session`, `cleanup` | `planned::lifecycle::owned_child_close` | `planned::lifecycle::exit_each_state` | All unverified |
| R2.12 | Public semantics are identical across supported platforms. | facade API plus backend conformance | `planned::api::target_surface` | `planned::ci::unsupported_target_compile_fail` | All unverified |
| R2.13 | Application control is bounded, authenticated, and non-real-time. | `control` | `planned::control::bounded_duplex` | `planned::control::oversize_stale_conflict` | All unverified |
| R2.14 | Every claimed security property has native adversarial tests. | `tests/native`, CI | exact-release conformance jobs | release gate rejects missing native result | All unverified |
| R2.15 | Ordinary users do not import OS modules or manipulate native names/handles. | facade exports; feature `raw-handle` | `planned::api::platform_neutral_flow` | `planned::ui::native_parts_not_safe` | portable planned |
| R3.1 | Public memory/transport contains no forbidden application/fixed-four vocabulary. | facade API and docs | `planned::api::application_neutral` | `planned::lint::forbidden_vocabulary` | portable planned |
| R3.2 | Base manifest is independent of core layouts/schemas/acks. | `wire::manifest`; Cargo graph | `planned::wire::generic_manifest` | `planned::graph::manifest_has_no_core_dependency` | portable planned |
| R4.1 | Hostile peer cannot trigger trusted UB/OOB. | `active`, all parsers/backends | Miri + native hostile corpus | truncation/arithmetic/mutation corpus | All unverified |
| R4.2 | Hostile peer cannot create undocumented writable aliasing. | region typestates; backend permission checks | `planned::native::designated_writer_succeeds` | `planned::native::reader_store_and_map_fail` | All unverified |
| R4.3 | Hostile peer cannot trigger use-after-free/double cleanup/reap. | RAII `cleanup::Ledger` | `planned::fault::drop_permutations` | `planned::fault::nth_cleanup_failure` | All unverified |
| R4.4 | Hostile peer cannot obtain executable memory or reader write authority. | private backends | `planned::native::reader_read` | `planned::native::write_exec_upgrade_fail` | All unverified |
| R4.5 | Stale/replayed/substituted/foreign transactions never activate. | `wire::Provenance`, `batch` | `planned::replay::fresh_transaction` | `planned::replay::session_and_tx_substitution` | All unverified |
| R4.6 | Uncommitted batches never expose partial runtime regions. | `PendingBatch` | `planned::batch::activation_after_commit` | `planned::batch::failure_first_middle_last` | All unverified |
| R4.7 | Hostile traffic cannot extend an absolute deadline. | `deadline`, transport loops | `planned::timing::operation_within_deadline` | `planned::timing::continuous_wrong_traffic` | All unverified |
| R4.8 | Covered failure paths do not leak resources. | `cleanup::Ledger`, fault boundary | `planned::leak::success_baseline` | `planned::fault::all_nth_operations` | All unverified |
| R4.9 | Exactly one endpoint has library-managed store authority; the other is kernel-read-only; neither has execute. | typestates and private backends | mixed-direction native permission suite | opposite endpoint write/exec probes | All unverified |
| R4.10 | Delegation cannot increase the bounded native authority delivered. | backend attenuated capability | exact-right duplicate/import succeeds | duplicate/map with excess rights rejected | All unverified |
| R4.11 | Documentation makes no payload-integrity claim against the authorized writer. | threat model, active API docs | torn-hostile-byte contract review | forbidden-claim scan for integrity/seqlock/checksum claims | docs planned |
| R4.12 | Documentation makes no confidentiality claim against an authorized reader. | threat model, region API docs | authority-scope review | forbidden-claim scan for confidentiality claims | docs planned |
| R4.13 | Documentation makes no revocation claim after capability delivery. | threat model, abort/cleanup docs | explicit non-revocation examples | forbidden-claim scan for revoke/erase claims | docs planned |
| R4.14 | Documentation makes no one-PID confinement or peer-copy erasure claim. | threat model, process docs | authority-principal/delegation review | forbidden-claim scan for PID confinement/erasure | docs planned |
| R4.15 | Documentation makes no rollback or distributed crash-atomicity claim. | batch atomicity and poisoning docs | API-visibility atomicity review | forbidden-claim scan for rollback/crash atomicity | docs planned |
| R5.1 | `RegionId(0)` and duplicate IDs fail; each object gets an unguessable incarnation. | `identity`, `batch`, CSPRNG | `planned::identity::fresh_incarnations` | `planned::identity::zero_duplicate_id` | portable + All unverified |
| R5.2 | Limits have finite secure defaults and every count/size/total/frame is checked before allocation/import. | `limits`, `checked`, parsers | boundary property tests | zero/overflow/above-hard-max corpus | portable planned; All unverified |
| R5.3 | Active leases remain charged until mapping drop. | `session::Lease` | `planned::limits::release_on_drop` | `planned::limits::removed_set_still_charged` | portable planned |
| R5.4 | `PrivateRegion` is unique, writable, anonymous, non-`Clone`, and only exposes scoped initialization. | `region::PrivateRegion` | `planned::api::scoped_initialize` | compile-fail clone/escape tests | portable planned; All unverified |
| R5.5 | Preparation consumes private state; failed preparation consumes and destroys it. | `region::prepare` | `planned::region::prepare_consumes` | faulted prepare + compile-fail reuse | All unverified |
| R5.6 | Prepared/pending values are non-Clone/non-Copy and payload-inaccessible; Drop closes all state. | typestates, cleanup | trait assertions + drop baseline | compile-fail clone/access + injected drop | All unverified |
| R5.7 | Safe code cannot derive writer authority from a reader or duplicate a sole writer. | `active` | intended Send/Sync assertions | compile-fail mutation/clone/sync | portable planned |
| R5.8 | Allocation rejects zero/overflow, rounds to pages, zeros payload/padding, and excludes execute. | `region`, backend allocation | page-boundary properties + zero checks | zero/overflow + execute probe | All unverified |
| R5.9 | Page padding is zero before transfer and inaccessible to safe runtime calls. | `region`, `active` | `planned::native::zero_padding` | safe OOB access rejection | All unverified |
| R5.10 | Clearing docs do not claim erasure of kernel/peer copies. | API docs, threat model | documentation review | forbidden-claim scan | docs planned |
| R5.11 | Safe active access provides checked read/write/fill equivalents. | `active` | offset/range success corpus | OOB/overflow/access-direction corpus | portable planned; All unverified |
| R5.12 | After activation/prefault access is allocation/syscall/lock/wait/log/panic free and bounded. | `active`, RT instrumentation | `planned::rt::negative_instrumentation` | hostile bytes/peer death during access | All unverified |
| R5.13 | External-memory soundness boundary is documented/reviewed; safe copies use volatile or audited FFI, not ordinary shared references. | `active::external_memory` safety module | Miri boundary tests + independent review | source lint rejects ordinary copy/shared slice | portable planned; All unverified |
| R5.14 | Safe runtime APIs return no persistent slices or typed references. | facade public API | API surface test | compile-fail slice/reference acquisition | portable planned |
| R5.15 | Advanced pointer access exists only as unsafe API with full bounds/alignment/init/lifetime/alias/sync/atomic/peer contract. | feature `raw-pointer`, docs | `planned::api::unsafe_pointer_feature` | unavailable without feature + compile-fail safe call | portable planned |
| R5.16 | Explicit off-thread prefault/touch reports bounded coverage without promising permanent residency. | `active::prefault` | coverage/fault observation | invalid range/required lock unavailable | All unverified |
| R5.17 | Raw native import/export is feature-gated unsafe and ownership-explicit. | feature `raw-handle` | feature API tests | default-build compile-fail/safe-call fail | All unverified |
| R5.18 | No regular-file, named POSIX SHM, or System V fallback exists. | backend selection | native object-type checks | unsupported mechanism fails closed | All unverified |
| R6.1 | Spawn uses a resolved executable, authenticates exact process, and retains race-resistant lifecycle handle. | `session::spawn`, backend process | exact child/image identity | replacement/wrong PID/image tests | All unverified |
| R6.2 | `SessionOptions` requires an expected executable identity policy on every platform. | `session::identity` | policy-required exact-image spawn | missing/mismatched policy rejection | All unverified |
| R6.3 | macOS/Windows compare stable image identity before/after spawn and hold replacement-denying rights where available. | private process backends | stable identity match | path replacement/image mismatch | Ma/Wx unverified |
| R6.4 | HELLO then ACCEPT/REJECT completes before transfer. | private `negotiation` codec/transcript + future session typestate | two opaque-payload HELLOs and exact ordered decisions | all truncations, version/role/nonce/reserved/limit/atomic/target/feature/digest substitutions, replay/order, reject | portable codec/transcript implemented; authenticated transport and public ready gating unverified |
| R6.5 | Session carries bounded opaque authenticated duplex control frames. | `control` | max-size duplex ordering | max+1/malformed/stale/transaction conflict | All unverified |
| R6.6 | `AtomicCapabilities` reports lock-free cross-process 32/64-bit atomics and alignments. | `session::AtomicCapabilities` + private native discovery | private construction/alignment validation; native publish/observe planned | forged public construction impossible; invalid alignment/required unsupported reject | portable representation implemented; native facts/evidence unverified |
| R6.7 | `try_close` returns live ownership while leases exist and does not silently kill a serving peer. | `session::try_close` | close after lease drop | close-blocked retains session/peer | All unverified |
| R7.1 | One consuming transaction supports 1..=16 arbitrary mixed directions. | `batch::TransferBatch` | 1/2/4/16 direction corpus | 0/17/wrong-direction corpus | All unverified |
| R7.2 | Callers cannot assemble independent pending tokens; transaction owns all pending/provenance/cleanup state. | private `batch::Transaction` | transaction-owned success | compile-fail provenance/pending construction | portable planned |
| R7.3 | Manifest contains no pointer/usize/raw handle/repr-Rust/application schema/padding structures. | `wire::manifest` manual codec | golden fixed-width vectors | forbidden field/reserved-byte mutations | portable planned |
| R7.4 | Object identity, size, access, and ordinal reject reorder/substitution. | backend import + manifest validator | canonical order import | reordered/substituted/wrong metadata corpus | All unverified |
| R7.5 | READY/COMMIT binds the exact full manifest. | `wire::transcript`, `batch` | exact transcript barrier | every-field mutation/replay | All unverified |
| R7.6 | Continuous malformed/wrong-peer traffic cannot extend deadline; partial ambiguous transmission poisons. | `session::AbsoluteDeadline`, transports | one fixed deadline has monotonic remaining time | zero duration and repeated-work expiry; transport reject storm/partial frame timeout planned | portable deadline value implemented; transports unverified |
| R7.7 | Native I/O/waits are nonblocking/pollable/cancellable and recompute remaining absolute time. | backend transport loops | near-deadline success | silence/junk/fragment/exit storms | All unverified |
| R8.1 | Linux bootstrap is inherited anonymous `AF_UNIX SOCK_SEQPACKET`, not a filesystem path. | `backend::linux::channel` | socket type/inherited-fd inventory | filesystem bootstrap absent + extra inheritance | Lx unverified |
| R8.2 | Linux does not use cached pre-spawn `SO_PEERCRED`; each packet has exact post-exec credentials checked against pidfd/PID/UID/GID. | `backend::linux::channel` | per-message credentials | missing/extra/wrong credentials + topology test | Lx unverified |
| R8.3 | Linux uses `MFD_NOEXEC_SEAL` and exact size/execute/grow/shrink/future-write/seal ordering for both writer directions. | `backend::linux::region` | seal-state native probes | every missing seal, resize, new write/execute map rejected | Lx unverified |
| R8.4 | Linux receives exact ancillary records and immediately owns every installed fd, including all malformed/error paths. | `backend::linux::channel` | exact N-fd packet import | 0/1/2/N, malformed/extra/truncated cmsg and fd-baseline corpus | Lx unverified |
| R8.5 | Intel macOS fails compilation. | facade target gate | Arm64 check | x86_64-apple-darwin compile-fail | CI planned |
| R8.6 | macOS control abstraction is replaceable by signed XPC adapter without public API change. | private `backend::macos::ControlTransport` | alternate mock transport conformance | no backend type leaks publicly | Ma unverified |
| R8.7 | macOS entries/mappings exclude execute, enforce complementary maximum rights, and ledger every installed right exactly once. | `backend::macos::{region,channel}` | reader/writer/cleanup native probes | write/execute upgrade, malformed extra-right, port-baseline corpus | Ma unverified |
| R8.8 | Windows uses exact non-inheritable duplicate access and never `DUPLICATE_SAME_ACCESS`. | `backend::windows::region` | exact reader/writer access probes | excess/wrong access import rejection | Wx unverified |
| R8.9 | Windows ledgers remote duplicates but never closes an untrusted numeric remote handle after resume; ambiguity tears down the owned Job/process. | `backend::windows::{batch,process}` | contained successful close | handle reuse/partial duplicate/ambiguous failure Job teardown | Wx unverified |
| R8.10 | Windows private pipe has explicit minimal logon-SID DACL, one-instance/local-only policy, exact endpoint PID, cancellation, and absolute deadlines. | `backend::windows::channel` | authenticated bounded framing | wrong PID/remote/second client/partial/timeout/cancel corpus | Wx unverified |
| R9.1 | Functioning cleanup after acquisition failure restores exact baseline. | `cleanup::Ledger`, fault injection | baseline success | fail every Nth operation/cleanup continuation | All unverified |
| R10.1 | Instrumentation and benchmarks prove real-time negative properties. | `tests/rt`, benchmarks, CI artifacts | allocator/syscall/lock counters zero | deliberate instrumentation tripwires | All unverified |
| R12.1 | Functioning cleanup restores native fd/map/path/pidfd/child, VM/port/child, or handle/view/pipe/Job/tree baseline. | backend cleanup suites | 10,000-cycle stable baseline | Nth forward/cleanup failure suite | All unverified |
| R14.1 | Compatibility features neither weaken vNext nor appear in conformance examples. | migration feature policy/docs | migration examples use vNext | API/docs scan for legacy escape use | portable planned |
| R16.1 | Every normative MUST has both positive and negative traceability. | this file + CI trace checker | `planned::trace::all_requirements_linked` | missing/stale test/evidence link rejects release | release blocked |

## Implementation progress (not release evidence)

| Phase | Invariant | Local evidence | Independent review | State |
| --- | --- | --- | --- | --- |
| 0 | Feasibility, claim boundaries, MUST inventory, and ordered plan | macOS Arm64 0.4 baseline plus primary-source mechanism review | no unresolved finding | implemented; native vNext probes unverified |
| 1 | Private facade backends, required crate direction, application-neutral manifest, no safe native-parts escape | host fmt, strict Clippy, all-feature/no-default tests, compile-fail docs, warning-free rustdoc, four cross-target checks, retained 0.4 package tests | no unresolved finding after three review rounds | implemented locally; exact native targets unverified |
| 2a | Public private/prepared ownership states and guarded runtime access boundary | exact commit `61d11f6`: all five native jobs, strict quality, Miri, ASan, fuzz, and policy green in [Actions 29175446059](https://github.com/ro-ag/native-ipc-rs/actions/runs/29175446059) | no unresolved finding after pedantic unsafe review | implemented; native activation remains batch-gated and full vNext conformance unverified |
| 3a | Private transaction-owned mixed-region and exact keyed-set scaffold | host count/direction/duplicate/aggregate/exact-commit/drop and Send/Sync tests | no unresolved finding after three review rounds | internal only; public session commit deliberately blocked on native state machine |
| 4a | Finite checked limits, unforgeable target-capability representation, and one reusable monotonic absolute deadline | exact commit `068e508`: all five native jobs, strict quality, Miri, ASan, fuzz, and policy green in [Actions 29175823735](https://github.com/ro-ag/native-ipc-rs/actions/runs/29175823735); limit/capability/deadline host corpus | no unresolved finding after two review rounds | portable foundation only; native atomic fact discovery/publication and hostile transport timing remain unverified |
| 4b | Canonical two-sided HELLO/ACCEPT/REJECT wire and payload-bound one-shot negotiated transcript | exact fix commit `8920f36`: all five native jobs and auxiliary gates green in [Actions 29176564979](https://github.com/ro-ag/native-ipc-rs/actions/runs/29176564979); dependency policy; platform-independent golden SHA-256 vector; opaque empty/bounded payload, full-frame truncation, every reserved byte, feature/minimum/atomic/target/digest/substitution/replay/order corpus | no unresolved finding after four codec rounds plus one readiness-boundary review | private portable codec only; authenticated exact-child transport, poisoning, public ready typestate, and later transaction binding remain unverified |

## Native release evidence ledger

| Target | Exact release SHA | Source-tree conformance | Packaged-crate conformance | Leak/fault/RT suites | Status |
| --- | --- | --- | --- | --- | --- |
| Linux GNU AMD64, kernel 6.3+, glibc 2.31+ | — | — | — | — | unverified |
| Linux GNU Arm64, kernel 6.3+, glibc 2.31+ | — | — | — | — | unverified |
| macOS Arm64 | — | — | — | — | unverified |
| Windows AMD64 | — | — | — | — | unverified |
| Windows Arm64 | — | — | — | — | unverified |

The existing green 0.4.0 CI run predates vNext and is not evidence for this
matrix. Release remains blocked while any row or target is planned, blocked,
or unverified.
