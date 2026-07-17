//! Section 12.7 real-time negative instrumentation over the public active path.
//!
//! This binary carries its own counting global allocator so the measurement
//! never perturbs the library or the other test binaries. It proves the R10.1
//! negative properties dynamically:
//!
//! - allocator entries on the measured thread are exactly zero across the hot
//!   window (`write_from`/`read_into`/`fill` after an explicit prefault);
//! - task-level syscall, context-switch, and fault counters stay below one
//!   event per hot iteration, so a per-operation syscall, wait, or fault is
//!   impossible while unrelated background activity cannot fail the test;
//! - deliberate tripwires prove each instrument detects the violation it
//!   guards against, per the R10.1 negative-evidence column;
//! - prefault reports touched coverage, and on a freshly imported mapping the
//!   task fault counter observes at least one fault per touched page, without
//!   asserting any permanent residency;
//! - peer death cannot block access: every call after an abrupt peer exit
//!   returns a bounded `Ok` or `SessionInactive`, before and after the reap;
//! - session cleanup and replacement run without a single allocator entry on
//!   the measured active thread.
//!
//! An uncontended lock leaves no dynamic trace and also cannot block; a
//! contended lock or any wait surfaces in the syscall and context-switch
//! counters, which is the observable half of the "lock/wait instrumentation
//! is zero" requirement. Latency percentiles are printed as evidence without
//! wall-clock assertions because shared CI runners are timing-noisy.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::{Mutex, MutexGuard, PoisonError};

/// Forwards every operation to the system allocator unchanged while counting
/// entries made on threads that enabled their local gate.
struct CountingSystemAllocator;

thread_local! {
    static ALLOCATOR_GATE: Cell<bool> = const { Cell::new(false) };
    static ALLOCATOR_EVENTS: Cell<u64> = const { Cell::new(0) };
}

/// Records one allocator entry on gated threads. The const-initialized
/// `Cell` thread-locals allocate nothing and register no destructor, so this
/// is safe to enter from inside the global allocator at any thread lifetime
/// stage; `try_with` tolerates access after thread-local teardown.
fn record_allocator_event() {
    let _ = ALLOCATOR_GATE.try_with(|gate| {
        if gate.get() {
            let _ = ALLOCATOR_EVENTS.try_with(|events| events.set(events.get() + 1));
        }
    });
}

unsafe impl GlobalAlloc for CountingSystemAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record_allocator_event();
        // SAFETY: the caller's `GlobalAlloc` obligations are forwarded unchanged.
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        record_allocator_event();
        // SAFETY: the caller's `GlobalAlloc` obligations are forwarded unchanged.
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record_allocator_event();
        // SAFETY: the caller's `GlobalAlloc` obligations are forwarded unchanged.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        record_allocator_event();
        // SAFETY: the caller's `GlobalAlloc` obligations are forwarded unchanged.
        unsafe { System.realloc(pointer, layout, new_size) }
    }
}

#[global_allocator]
static COUNTING_ALLOCATOR: CountingSystemAllocator = CountingSystemAllocator;

/// Runs `body` with this thread's allocator gate enabled and returns its value
/// together with the exact number of allocator entries the thread made.
fn allocator_events_during<T>(body: impl FnOnce() -> T) -> (T, u64) {
    ALLOCATOR_EVENTS.with(|events| events.set(0));
    ALLOCATOR_GATE.with(|gate| gate.set(true));
    let value = body();
    ALLOCATOR_GATE.with(|gate| gate.set(false));
    (value, ALLOCATOR_EVENTS.with(Cell::get))
}

/// Serializes the counter-window tests so one test's task-wide activity can
/// never leak into another test's measurement window.
static COUNTER_WINDOW: Mutex<()> = Mutex::new(());

fn counter_window_guard() -> MutexGuard<'static, ()> {
    COUNTER_WINDOW
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
}

#[test]
fn counting_allocator_tripwire_detects_deliberate_allocation() {
    let _window = counter_window_guard();
    let ((), silent) = allocator_events_during(|| {
        std::hint::black_box(0_u64);
    });
    assert_eq!(
        silent, 0,
        "the allocator instrument must stay silent over pure arithmetic"
    );
    let (deliberate, caught) = allocator_events_during(|| std::hint::black_box(vec![0_u8; 4096]));
    assert!(
        caught >= 1,
        "the allocator instrument must catch a deliberate heap allocation"
    );
    drop(deliberate);
}

#[cfg(target_os = "macos")]
mod macos_public_rt {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, Instant};

    use native_ipc::active::{AccessError, ActiveReader, ActiveWriter};
    use native_ipc::batch::{ExpectedBatch, ExpectedRegion, TransferBatch};
    use native_ipc::region::{PrivateRegion, RegionId, RegionOptions, RegionSpec, WriterEndpoint};
    use native_ipc::session::{
        __take_receiver_bootstrap, AbsoluteDeadline, ChildExitStatus, CoordinatorSession,
        ExecutableIdentityPolicy, Negotiating, NegotiationDecision, NegotiationOutcome, Ready,
        ReceiverCloseOutcome, ReceiverSession, SessionCommand, SessionOptions,
    };

    use super::{allocator_events_during, counter_window_guard};

    /// Task-wide event counters from `task_info(TASK_EVENTS_INFO)`.
    #[repr(C)]
    #[derive(Clone, Copy, Debug, Default)]
    struct TaskEventsInfo {
        faults: i32,
        pageins: i32,
        cow_faults: i32,
        messages_sent: i32,
        messages_received: i32,
        syscalls_mach: i32,
        syscalls_unix: i32,
        csw: i32,
    }

    /// Signed differences between two task event snapshots.
    #[derive(Clone, Copy, Debug)]
    struct TaskEventsDelta {
        faults: i64,
        syscalls_mach: i64,
        syscalls_unix: i64,
        csw: i64,
    }

    impl TaskEventsInfo {
        fn delta_since(self, earlier: Self) -> TaskEventsDelta {
            TaskEventsDelta {
                faults: i64::from(self.faults.wrapping_sub(earlier.faults)),
                syscalls_mach: i64::from(self.syscalls_mach.wrapping_sub(earlier.syscalls_mach)),
                syscalls_unix: i64::from(self.syscalls_unix.wrapping_sub(earlier.syscalls_unix)),
                csw: i64::from(self.csw.wrapping_sub(earlier.csw)),
            }
        }
    }

    const TASK_EVENTS_INFO_FLAVOR: u32 = 2;
    const KERN_SUCCESS: i32 = 0;

    unsafe extern "C" {
        static mach_task_self_: u32;
        fn task_info(
            target_task: u32,
            flavor: u32,
            task_info_out: *mut i32,
            task_info_out_count: *mut u32,
        ) -> i32;
        fn getpagesize() -> core::ffi::c_int;
        fn read(descriptor: i32, buffer: *mut core::ffi::c_void, length: usize) -> isize;
    }

    /// Reads the current task-wide event counters; itself a Mach IPC entry,
    /// which the Mach tripwire below relies on.
    fn task_events_snapshot() -> TaskEventsInfo {
        let mut info = TaskEventsInfo::default();
        let expected_count = u32::try_from(size_of::<TaskEventsInfo>() / size_of::<i32>()).unwrap();
        let mut count = expected_count;
        // SAFETY: self-inspection of the current task with an exactly sized
        // TASK_EVENTS_INFO output buffer; the in/out count is passed in full
        // and re-validated after the call so a short kernel reply cannot
        // leave silently zeroed counter fields.
        let outcome = unsafe {
            task_info(
                mach_task_self_,
                TASK_EVENTS_INFO_FLAVOR,
                (&raw mut info).cast::<i32>(),
                &raw mut count,
            )
        };
        assert_eq!(outcome, KERN_SUCCESS, "task_info(TASK_EVENTS_INFO) failed");
        assert_eq!(
            count, expected_count,
            "task_info(TASK_EVENTS_INFO) returned a short counter reply"
        );
        info
    }

    fn page_size() -> usize {
        // SAFETY: `getpagesize` reads a process constant and cannot fail.
        usize::try_from(unsafe { getpagesize() }).unwrap()
    }

    const REGION_BYTES: usize = 64 * 1024;
    const CHUNK_BYTES: usize = 4096;
    const HOT_ITERATIONS: usize = 10_000;
    const COORDINATOR_WRITER_REGION: u128 = 1;
    const RECEIVER_WRITER_REGION: u128 = 2;
    const RT_HELPER_READY: u32 = 0x8000_0071;
    const RT_DONE: u32 = 0x8000_0072;
    const RT_MARKER: &[u8] = b"rt-marker-0071";

    fn deadline() -> AbsoluteDeadline {
        AbsoluteDeadline::after(Duration::from_secs(120)).unwrap()
    }

    fn session_options() -> SessionOptions {
        SessionOptions::new(deadline(), ExecutableIdentityPolicy::ExactOpenedFile)
    }

    /// The two-region measurement layout: region 1 is coordinator-written
    /// and region 2 is receiver-written, both multi-page.
    const RT_REGIONS: [(u128, WriterEndpoint); 2] = [
        (COORDINATOR_WRITER_REGION, WriterEndpoint::Coordinator),
        (RECEIVER_WRITER_REGION, WriterEndpoint::Receiver),
    ];

    /// Receiver-side description of the measurement batch.
    fn rt_expected_batch() -> ExpectedBatch {
        let expected = RT_REGIONS
            .into_iter()
            .map(|(id, writer)| {
                ExpectedRegion::new(RegionId::new(id).unwrap(), writer, REGION_BYTES)
            })
            .collect();
        ExpectedBatch::try_from_regions(expected).unwrap()
    }

    /// Coordinator-side construction of the measurement batch.
    fn rt_transfer_batch(ready: &CoordinatorSession<Ready>) -> TransferBatch {
        let mut batch = ready.new_transfer_batch().unwrap();
        for (id, writer) in RT_REGIONS {
            let id = RegionId::new(id).unwrap();
            let mut region = PrivateRegion::allocate(RegionOptions::fixed(REGION_BYTES)).unwrap();
            region.initialize(|bytes| {
                bytes.fill(0);
                bytes[..RT_MARKER.len()].copy_from_slice(RT_MARKER);
            });
            batch
                .add(region.prepare(RegionSpec { id, writer }).unwrap())
                .unwrap();
        }
        batch
    }

    fn spawn_ready(helper: &str, label: &str) -> CoordinatorSession<Ready> {
        let executable = std::env::current_exe().unwrap();
        let command = SessionCommand::new(&executable)
            .arg0(label)
            .arg("--exact")
            .arg(helper)
            .arg("--ignored")
            .arg("--nocapture");
        let negotiating =
            CoordinatorSession::<Negotiating>::spawn(command, session_options()).unwrap();
        match negotiating.decide(NegotiationDecision::Accept).unwrap() {
            NegotiationOutcome::Accepted(ready) => ready,
            NegotiationOutcome::Rejected { .. } => panic!("rt helper rejected negotiation"),
        }
    }

    /// Drives one complete transfer and returns the coordinator-side actives.
    fn transfer_actives(ready: &mut CoordinatorSession<Ready>) -> (ActiveWriter, ActiveReader) {
        let batch = rt_transfer_batch(ready);
        let mut active = ready.transfer_batch(batch, deadline()).unwrap();
        let writer = active
            .take_writer(RegionId::new(COORDINATOR_WRITER_REGION).unwrap())
            .unwrap();
        let reader = active
            .take_reader(RegionId::new(RECEIVER_WRITER_REGION).unwrap())
            .unwrap();
        assert!(active.is_empty());
        (writer, reader)
    }

    #[test]
    fn task_event_counters_tripwire_detects_deliberate_syscalls() {
        let _window = counter_window_guard();
        const TRIPWIRE_CALLS: usize = 10_000;
        let before = task_events_snapshot();
        for _ in 0..TRIPWIRE_CALLS {
            // SAFETY: reading zero bytes from an invalid descriptor touches no
            // memory and deterministically fails with EBADF after one syscall.
            let outcome = unsafe { read(-1, core::ptr::null_mut(), 0) };
            assert_eq!(outcome, -1);
        }
        let unix_delta = task_events_snapshot().delta_since(before);
        assert!(
            unix_delta.syscalls_unix >= i64::try_from(TRIPWIRE_CALLS).unwrap(),
            "the unix syscall counter must catch {TRIPWIRE_CALLS} deliberate syscalls, saw {unix_delta:?}"
        );
        const MACH_CALLS: usize = 1_000;
        let before = task_events_snapshot();
        for _ in 0..MACH_CALLS {
            let _ = task_events_snapshot();
        }
        let mach_delta = task_events_snapshot().delta_since(before);
        assert!(
            mach_delta.syscalls_mach >= i64::try_from(MACH_CALLS).unwrap(),
            "the Mach syscall counter must catch {MACH_CALLS} deliberate Mach IPC entries, saw {mach_delta:?}"
        );
    }

    #[test]
    fn public_active_hot_path_is_allocation_and_syscall_free_after_prefault() {
        let _window = counter_window_guard();
        let mut ready = spawn_ready(
            "macos_public_rt::rt_receiver_helper",
            "native-ipc-rt-hot-helper",
        );
        let (mut writer, reader) = transfer_actives(&mut ready);
        let helper_ready = ready.receive_control(deadline()).unwrap();
        assert_eq!(helper_ready.kind(), RT_HELPER_READY);

        // Prefault reports exact touched coverage over the full logical range.
        let pages = REGION_BYTES.div_ceil(page_size());
        let writer_prefault = writer.prefault(0..REGION_BYTES).unwrap();
        assert_eq!(writer_prefault.requested_bytes, REGION_BYTES);
        assert_eq!(writer_prefault.pages_touched, pages);
        let reader_prefault = reader.prefault(0..REGION_BYTES).unwrap();
        assert_eq!(reader_prefault.requested_bytes, REGION_BYTES);
        assert_eq!(reader_prefault.pages_touched, pages);

        // The receiver's marker proves live shared bytes flow before measuring.
        let mut marker = [0_u8; RT_MARKER.len()];
        reader.read_into(0, &mut marker).unwrap();
        assert_eq!(marker, RT_MARKER);

        let mut inbound = [0_u8; CHUNK_BYTES];
        let outbound = [0x5a_u8; CHUNK_BYTES];
        let chunks = REGION_BYTES / CHUNK_BYTES;
        let before = task_events_snapshot();
        let ((), allocations) = allocator_events_during(|| {
            for index in 0..HOT_ITERATIONS {
                let offset = (index % chunks) * CHUNK_BYTES;
                writer.write_from(offset, &outbound).unwrap();
                reader.read_into(offset, &mut inbound).unwrap();
                writer
                    .fill(offset..offset + CHUNK_BYTES, index.to_le_bytes()[0])
                    .unwrap();
                std::hint::black_box(&mut inbound);
            }
        });
        let hot = task_events_snapshot().delta_since(before);
        assert_eq!(
            allocations, 0,
            "the hot path made allocator entries after prefault"
        );
        let budget = i64::try_from(HOT_ITERATIONS).unwrap();
        assert!(
            hot.syscalls_unix < budget,
            "hot window exceeded the unix syscall budget of one per iteration: {hot:?}"
        );
        assert!(
            hot.syscalls_mach < budget,
            "hot window exceeded the Mach IPC budget of one per iteration: {hot:?}"
        );
        assert!(
            hot.csw < budget,
            "hot window exceeded the context-switch budget of one per iteration: {hot:?}"
        );
        assert!(
            hot.faults < budget,
            "hot window exceeded the post-prefault fault budget of one per iteration: {hot:?}"
        );
        println!(
            "rt-evidence hot window: {HOT_ITERATIONS} iterations x 3 operations, \
             allocator entries 0, task deltas {hot:?}"
        );

        // Latency evidence only: shared CI runners forbid wall-clock asserts.
        const SAMPLES: usize = 1_000;
        let mut write_samples = Vec::with_capacity(SAMPLES);
        let mut read_samples = Vec::with_capacity(SAMPLES);
        for index in 0..SAMPLES {
            let offset = (index % chunks) * CHUNK_BYTES;
            let start = Instant::now();
            writer.write_from(offset, &outbound).unwrap();
            write_samples.push(start.elapsed());
            let start = Instant::now();
            reader.read_into(offset, &mut inbound).unwrap();
            read_samples.push(start.elapsed());
        }
        write_samples.sort_unstable();
        read_samples.sort_unstable();
        println!(
            "rt-evidence write_from {CHUNK_BYTES}B p50={:?} p95={:?} p99={:?}",
            write_samples[SAMPLES / 2],
            write_samples[SAMPLES * 95 / 100],
            write_samples[SAMPLES * 99 / 100],
        );
        println!(
            "rt-evidence read_into {CHUNK_BYTES}B p50={:?} p95={:?} p99={:?}",
            read_samples[SAMPLES / 2],
            read_samples[SAMPLES * 95 / 100],
            read_samples[SAMPLES * 99 / 100],
        );

        drop(writer);
        drop(reader);
        ready.send_control(RT_DONE, b"done", deadline()).unwrap();
        let cleanup = ready.wait_for_exit(deadline());
        assert_eq!(cleanup.direct_child(), Some(ChildExitStatus::Exited(0)));
    }

    #[test]
    #[ignore = "spawned alone by the rt coordinator tests"]
    fn rt_receiver_helper() {
        let bootstrap = __take_receiver_bootstrap().unwrap();
        let negotiating =
            ReceiverSession::<Negotiating>::from_bootstrap(bootstrap, session_options()).unwrap();
        let mut ready = match negotiating
            .decide_after_coordinator(|_| NegotiationDecision::Accept)
            .unwrap()
        {
            NegotiationOutcome::Accepted(ready) => ready,
            NegotiationOutcome::Rejected { .. } => panic!("coordinator rejected rt helper"),
        };
        let expected = rt_expected_batch();
        let mut active = ready.receive_batch(expected, deadline()).unwrap();
        let mut writer = active
            .take_writer(RegionId::new(RECEIVER_WRITER_REGION).unwrap())
            .unwrap();
        let reader = active
            .take_reader(RegionId::new(COORDINATOR_WRITER_REGION).unwrap())
            .unwrap();

        // Both mappings were imported fresh in this process, so prefaulting
        // them must observe at least one fault per touched page while
        // reporting exact coverage. No residency promise is asserted.
        let pages = REGION_BYTES.div_ceil(page_size());
        let before = task_events_snapshot();
        let writer_prefault = writer.prefault(0..REGION_BYTES).unwrap();
        let writer_faults = task_events_snapshot().delta_since(before);
        assert_eq!(writer_prefault.requested_bytes, REGION_BYTES);
        assert_eq!(writer_prefault.pages_touched, pages);
        assert!(
            writer_faults.faults >= i64::try_from(pages).unwrap(),
            "prefaulting a fresh imported writable mapping must observe faults: {writer_faults:?}"
        );
        let before = task_events_snapshot();
        let reader_prefault = reader.prefault(0..REGION_BYTES).unwrap();
        let reader_faults = task_events_snapshot().delta_since(before);
        assert_eq!(reader_prefault.requested_bytes, REGION_BYTES);
        assert_eq!(reader_prefault.pages_touched, pages);
        assert!(
            reader_faults.faults >= i64::try_from(pages).unwrap(),
            "prefaulting a fresh imported readable mapping must observe faults: {reader_faults:?}"
        );

        // The coordinator's initializer marker proves live imported bytes.
        let mut marker = [0_u8; RT_MARKER.len()];
        reader.read_into(0, &mut marker).unwrap();
        assert_eq!(marker, RT_MARKER);

        // The receiver endpoint's own hot window is allocation-free too.
        let mut inbound = [0_u8; CHUNK_BYTES];
        let outbound = [0x3c_u8; CHUNK_BYTES];
        let ((), allocations) = allocator_events_during(|| {
            for index in 0..1_000 {
                let offset = (index % (REGION_BYTES / CHUNK_BYTES)) * CHUNK_BYTES;
                writer.write_from(offset, &outbound).unwrap();
                reader.read_into(offset, &mut inbound).unwrap();
            }
        });
        assert_eq!(
            allocations, 0,
            "the receiver hot path made allocator entries after prefault"
        );

        writer.write_from(0, RT_MARKER).unwrap();
        ready
            .send_control(RT_HELPER_READY, b"prefaulted", deadline())
            .unwrap();
        let done = ready.receive_control(deadline()).unwrap();
        assert_eq!(done.kind(), RT_DONE);
        drop(writer);
        drop(reader);
        drop(active);
        assert!(matches!(ready.try_close(), ReceiverCloseOutcome::Closed));
    }

    #[test]
    fn peer_death_cannot_block_public_active_access() {
        let _window = counter_window_guard();
        let mut ready = spawn_ready(
            "macos_public_rt::rt_peer_death_helper",
            "native-ipc-rt-peer-death-helper",
        );
        let (mut writer, reader) = transfer_actives(&mut ready);
        let helper_ready = ready.receive_control(deadline()).unwrap();
        assert_eq!(helper_ready.kind(), RT_HELPER_READY);

        // The helper exits abruptly after that control frame without dropping
        // its actives or closing its session. Whether each access below lands
        // before or after the library notices the death, it must return a
        // bounded Ok or SessionInactive; completing the loop is the proof
        // that no access blocked. No timing assumption is made.
        let mut byte = [0_u8; 1];
        let mut succeeded: u32 = 0;
        let mut inactive: u32 = 0;
        const DEATH_PROBES: u32 = 1_000;
        let ((), allocations) = allocator_events_during(|| {
            for index in 0..DEATH_PROBES {
                match writer.write_from(0, &[index.to_le_bytes()[0]]) {
                    Ok(()) => succeeded += 1,
                    Err(AccessError::SessionInactive) => inactive += 1,
                    Err(other) => panic!("unbounded peer-death write outcome: {other:?}"),
                }
                match reader.read_into(0, &mut byte) {
                    Ok(()) => succeeded += 1,
                    Err(AccessError::SessionInactive) => inactive += 1,
                    Err(other) => panic!("unbounded peer-death read outcome: {other:?}"),
                }
            }
        });
        assert_eq!(succeeded + inactive, DEATH_PROBES * 2);
        assert_eq!(
            allocations, 0,
            "peer death introduced allocator entries on the access path"
        );

        // After the exact reap the same invariant holds: bounded, non-blocking.
        let cleanup = ready.wait_for_exit(deadline());
        assert_eq!(cleanup.direct_child(), Some(ChildExitStatus::Exited(0)));
        let mut reaped_succeeded: u32 = 0;
        let mut reaped_inactive: u32 = 0;
        for _ in 0..100 {
            match writer.write_from(0, &[0]) {
                Ok(()) => reaped_succeeded += 1,
                Err(AccessError::SessionInactive) => reaped_inactive += 1,
                Err(other) => panic!("unbounded post-reap write outcome: {other:?}"),
            }
            match reader.read_into(0, &mut byte) {
                Ok(()) => reaped_succeeded += 1,
                Err(AccessError::SessionInactive) => reaped_inactive += 1,
                Err(other) => panic!("unbounded post-reap read outcome: {other:?}"),
            }
        }
        assert_eq!(reaped_succeeded + reaped_inactive, 200);
        println!(
            "rt-evidence peer death: pre-reap ok={succeeded} inactive={inactive}, \
             post-reap ok={reaped_succeeded} inactive={reaped_inactive}"
        );
    }

    #[test]
    #[ignore = "spawned alone by the peer-death coordinator test"]
    fn rt_peer_death_helper() {
        let bootstrap = __take_receiver_bootstrap().unwrap();
        let negotiating =
            ReceiverSession::<Negotiating>::from_bootstrap(bootstrap, session_options()).unwrap();
        let mut ready = match negotiating
            .decide_after_coordinator(|_| NegotiationDecision::Accept)
            .unwrap()
        {
            NegotiationOutcome::Accepted(ready) => ready,
            NegotiationOutcome::Rejected { .. } => panic!("coordinator rejected death helper"),
        };
        let expected = rt_expected_batch();
        let active = ready.receive_batch(expected, deadline()).unwrap();
        assert_eq!(active.len(), 2);
        ready
            .send_control(RT_HELPER_READY, b"exiting-abruptly", deadline())
            .unwrap();
        // Exit without dropping the actives or closing the session: no
        // destructor runs, so the peer observes an abrupt death with live
        // mappings, the case section 10 requires to never block the survivor.
        std::process::exit(0);
    }

    #[test]
    fn replacement_and_cleanup_stay_off_the_measured_active_thread() {
        let _window = counter_window_guard();
        // Session A feeds the measured thread for the whole test.
        let mut session_a = spawn_ready(
            "macos_public_rt::rt_receiver_helper",
            "native-ipc-rt-session-a-helper",
        );
        let (mut writer_a, _reader_a) = transfer_actives(&mut session_a);
        let ready_a = session_a.receive_control(deadline()).unwrap();
        assert_eq!(ready_a.kind(), RT_HELPER_READY);
        writer_a.prefault(0..REGION_BYTES).unwrap();

        let stop = Arc::new(AtomicBool::new(false));
        let stop_signal = Arc::clone(&stop);
        let measured = std::thread::spawn(move || {
            let outbound = [0x7e_u8; CHUNK_BYTES];
            let (operations, allocations) = allocator_events_during(|| {
                let mut operations: u64 = 0;
                while !stop_signal.load(Ordering::Relaxed) {
                    writer_a.write_from(0, &outbound).unwrap();
                    operations += 1;
                }
                operations
            });
            (operations, allocations)
        });

        // While the measured thread runs, a complete session B lifecycle
        // (cleanup) and a fresh session C (replacement) happen elsewhere.
        let mut session_b = spawn_ready(
            "macos_public_rt::rt_receiver_helper",
            "native-ipc-rt-session-b-helper",
        );
        let (writer_b, reader_b) = transfer_actives(&mut session_b);
        let ready_b = session_b.receive_control(deadline()).unwrap();
        assert_eq!(ready_b.kind(), RT_HELPER_READY);
        drop(writer_b);
        drop(reader_b);
        session_b
            .send_control(RT_DONE, b"done", deadline())
            .unwrap();
        let cleanup_b = session_b.wait_for_exit(deadline());
        assert_eq!(cleanup_b.direct_child(), Some(ChildExitStatus::Exited(0)));

        let mut session_c = spawn_ready(
            "macos_public_rt::rt_receiver_helper",
            "native-ipc-rt-session-c-helper",
        );
        let (writer_c, reader_c) = transfer_actives(&mut session_c);
        let ready_c = session_c.receive_control(deadline()).unwrap();
        assert_eq!(ready_c.kind(), RT_HELPER_READY);
        drop(writer_c);
        drop(reader_c);
        session_c
            .send_control(RT_DONE, b"done", deadline())
            .unwrap();
        let cleanup_c = session_c.wait_for_exit(deadline());
        assert_eq!(cleanup_c.direct_child(), Some(ChildExitStatus::Exited(0)));

        stop.store(true, Ordering::Relaxed);
        let (operations, allocations) = measured.join().unwrap();
        assert!(operations > 0, "the measured thread never progressed");
        assert_eq!(
            allocations, 0,
            "session cleanup or replacement executed allocator entries on the measured thread"
        );
        println!(
            "rt-evidence off-thread replacement: {operations} uninterrupted operations, \
             allocator entries 0 while one session closed and one fresh session replaced it"
        );

        session_a
            .send_control(RT_DONE, b"done", deadline())
            .unwrap();
        let cleanup_a = session_a.wait_for_exit(deadline());
        assert_eq!(cleanup_a.direct_child(), Some(ChildExitStatus::Exited(0)));
    }
}
