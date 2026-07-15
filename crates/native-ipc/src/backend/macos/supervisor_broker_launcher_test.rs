use std::ffi::{CStr, c_char, c_int};
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use static_assertions::assert_not_impl_any;

use super::*;

const FIXTURE_ENV: &[u8] = b"NATIVE_IPC_TEST_EXACT_BROKER_LAUNCHER\0";
const VALID_EXEC: &[u8] = b"valid-exec";
const POST_EXEC: &[u8] = b"post-exec";
const TARGET_STOP: &[u8] = b"target-stop";
const POST_EXEC_STOP: &[u8] = b"post-exec-stop";
const TARGET_DELAY: &[u8] = b"target-delay";
const POST_EXEC_DELAY: &[u8] = b"post-exec-delay";
const TARGET_SIGKILL: &[u8] = b"target-sigkill";
const POST_EXEC_SIGKILL: &[u8] = b"post-exec-sigkill";
const FAKE_TRAP: &[u8] = b"fake-trap";
const UNEXPECTED_STOP: &[u8] = b"unexpected-stop";
const UNTRACED_STOP: &[u8] = b"untraced-stop";
const SUBSTITUTE_EXEC: &[u8] = b"substitute-exec";
const EXACT_TEST: &str =
    "backend::macos::supervisor::broker_entry::broker_launcher::tests::fixture_target";
const PT_TRACE_ME: c_int = 0;
const ENOENT: c_int = 2;

unsafe extern "C" {
    fn _exit(status: c_int) -> !;
    fn getenv(name: *const c_char) -> *mut c_char;
    fn getegid() -> u32;
    fn getgid() -> u32;
    fn geteuid() -> u32;
    fn getuid() -> u32;
    fn pipe(descriptors: *mut c_int) -> c_int;
    fn raise(signal: c_int) -> c_int;
    fn setenv(name: *const c_char, value: *const c_char, overwrite: c_int) -> c_int;
}

assert_not_impl_any!(SpawnedLauncher: Clone, Copy, Send, Sync);
assert_not_impl_any!(InitialStopObserved: Clone, Copy, Send, Sync);
assert_not_impl_any!(AwaitingExecTrap: Clone, Copy, Send, Sync);
assert_not_impl_any!(ExecTrapHeld: Clone, Copy, Send, Sync);

#[test]
fn installed_launcher_vectors_and_same_user_identity_are_fixed() {
    // SAFETY: this source-level vector test does not claim the fixed image is
    // installed or verified; it inspects only the installation-bound values.
    let image = unsafe { InstalledLauncherImage::from_verified_installation() }.unwrap();
    let argv = image.argv();
    let environment = image.environment();
    let argv = argv[..argv.len() - 1]
        .iter()
        .map(|value| unsafe { CStr::from_ptr(value.cast_const()) }.to_bytes())
        .collect::<Vec<_>>();
    let environment = environment[..environment.len() - 1]
        .iter()
        .map(|value| unsafe { CStr::from_ptr(value.cast_const()) }.to_bytes())
        .collect::<Vec<_>>();
    assert_eq!(
        argv,
        [
            INSTALLED_LAUNCHER_PATH.as_bytes(),
            INSTALLED_LAUNCHER_MODE.as_bytes(),
            INSTALLED_LAUNCHER_DEATH_ARGUMENT.as_bytes(),
            INSTALLED_LAUNCHER_PLAN_ARGUMENT.as_bytes(),
        ]
    );
    assert_eq!(
        environment,
        [&b"PATH=/usr/bin:/bin"[..], &b"LANG=C"[..], &b"LC_ALL=C"[..],]
    );
    // The launcher must present this unprivileged supervisor's own identity.
    // No request value contributes, and root is never expected or required.
    let identity = image.fixed_identity();
    // SAFETY: credential getters have no preconditions.
    unsafe {
        assert_eq!(identity.real_uid, getuid());
        assert_eq!(identity.effective_uid, geteuid());
        assert_eq!(identity.real_gid, getgid());
        assert_eq!(identity.effective_gid, getegid());
    }
    assert_eq!(identity.executable, INSTALLED_LAUNCHER_PATH.as_bytes());
}

#[test]
fn launcher_identity_never_expects_or_requires_root() {
    // A supervisor that expected root here would reject its own launcher, and
    // a design that required it would need an install this project refuses.
    // SAFETY: credential getters have no preconditions.
    let running_as_root = unsafe { geteuid() == 0 };
    assert!(
        !running_as_root,
        "the unprivileged supervisor's tests must not run as root",
    );
    // SAFETY: source-level vector construction only; see above.
    let image = unsafe { InstalledLauncherImage::from_verified_installation() }.unwrap();
    let identity = image.fixed_identity();
    assert_ne!(identity.real_uid, 0);
    assert_ne!(identity.effective_uid, 0);
}

/// Complete broker-side state for the fixed launcher spawn boundary, with no
/// child of its own. The spawn under test is the only process creator here.
struct SpawnBoundary {
    active: Option<ActiveBrokerProcess>,
    gate_writer: Option<OwnedFd>,
    _trace_peer: UnixStream,
}

impl SpawnBoundary {
    fn new(deadline: Instant) -> Self {
        let mut descriptors = [-1; 2];
        // SAFETY: descriptors has storage for both pipe descriptors.
        assert_eq!(unsafe { pipe(descriptors.as_mut_ptr()) }, 0);
        // SAFETY: the successful pipe returned two distinct owned descriptors.
        let gate_reader = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
        // SAFETY: the successful pipe returned two distinct owned descriptors.
        let gate_writer = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
        let expected_executable = std::env::current_exe()
            .unwrap()
            .as_os_str()
            .as_bytes()
            .to_vec();
        // SAFETY: credential getters have no preconditions.
        let plan = super::super::super::auth_adapter::broker_plan::ExactParentBrokerLaunchPlan::for_launcher_test(
            deadline,
            unsafe { geteuid() },
            unsafe { getegid() },
            expected_executable,
        );
        let (trace, trace_peer) = UnixStream::pair().unwrap();
        trace.set_nonblocking(true).unwrap();
        Self {
            active: Some(ActiveBrokerProcess {
                gate: ActiveBrokerGate {
                    reader: gate_reader,
                },
                plan,
                trace,
            }),
            gate_writer: Some(gate_writer),
            _trace_peer: trace_peer,
        }
    }

    fn take_active(&mut self) -> ActiveBrokerProcess {
        self.active.take().unwrap()
    }

    fn close_gate(&mut self) {
        drop(self.gate_writer.take());
    }

    fn poison_gate(&mut self) {
        let writer = self.gate_writer.as_ref().unwrap().try_clone().unwrap();
        std::fs::File::from(writer).write_all(&[1]).unwrap();
    }
}

/// One anonymous pipe whose ends are owned by the caller.
fn test_pipe() -> (OwnedFd, OwnedFd) {
    let mut descriptors = [-1; 2];
    // SAFETY: descriptors has storage for both pipe descriptors.
    assert_eq!(unsafe { pipe(descriptors.as_mut_ptr()) }, 0);
    // SAFETY: the successful pipe returned two distinct owned descriptors.
    let reader = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
    // SAFETY: the successful pipe returned two distinct owned descriptors.
    let writer = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
    (reader, writer)
}

/// Source-level vectors only. No test claims the fixed image is installed,
/// root-owned, signed, or verified.
fn uninstalled_fixed_image() -> InstalledLauncherImage {
    // SAFETY: this inspects installation-bound values and deliberately drives
    // the spawn against an absent path; it asserts no installation evidence.
    unsafe { InstalledLauncherImage::from_verified_installation() }.unwrap()
}

#[test]
fn uninstalled_fixed_launcher_image_fails_only_at_the_exact_spawn() {
    assert!(
        !std::path::Path::new(INSTALLED_LAUNCHER_PATH).exists(),
        "this boundary test is only meaningful while the fixed image is absent",
    );
    let mut boundary = SpawnBoundary::new(Instant::now() + Duration::from_secs(5));
    let (active, failure) =
        spawn_fixed_launcher(boundary.take_active(), &uninstalled_fixed_image())
            .err()
            .expect("an absent fixed launcher image cannot spawn")
            .into_parts();
    // Every pipe, descriptor relocation, file action, spawn attribute, dead-end
    // bootstrap name, expected identity, and the canonical frame were prepared
    // successfully; only the absent fixed path failed. Darwin forks before it
    // execs, so a transient child does exist, but posix_spawn never writes the
    // pid, SIGKILLs it, and reparents it to initproc for reaping. This broker
    // therefore has no child to own, and every wait here remains pid-specific.
    assert_eq!(failure, LauncherSpawnFailure::Spawn(ENOENT));
    // The failure returned the complete exact broker authority rather than
    // dropping it, so the broker can still report and clean up exactly.
    drop(active);
    boundary.close_gate();
}

#[test]
fn service_death_preempts_the_fixed_launcher_spawn() {
    let mut boundary = SpawnBoundary::new(Instant::now() + Duration::from_secs(5));
    boundary.close_gate();
    let (_active, failure) =
        spawn_fixed_launcher(boundary.take_active(), &uninstalled_fixed_image())
            .err()
            .expect("service death must preempt the spawn")
            .into_parts();
    // Service loss outranks creating a privileged child. This must never reach
    // posix_spawn, so it cannot report the absent image instead.
    assert_eq!(failure, LauncherSpawnFailure::ServiceGone);
}

#[test]
fn expired_deadline_preempts_the_fixed_launcher_spawn() {
    let mut boundary = SpawnBoundary::new(Instant::now() + Duration::from_millis(1));
    std::thread::sleep(Duration::from_millis(2));
    let (_active, failure) =
        spawn_fixed_launcher(boundary.take_active(), &uninstalled_fixed_image())
            .err()
            .expect("an expired deadline must preempt the spawn")
            .into_parts();
    // The original absolute deadline is checked while no child exists, so an
    // expired request can never create one.
    assert_eq!(failure, LauncherSpawnFailure::DeadlineExpired);
    boundary.close_gate();
}

#[test]
fn a_gate_byte_preempts_the_fixed_launcher_spawn() {
    let mut boundary = SpawnBoundary::new(Instant::now() + Duration::from_secs(5));
    boundary.poison_gate();
    let (_active, failure) =
        spawn_fixed_launcher(boundary.take_active(), &uninstalled_fixed_image())
            .err()
            .expect("a noncanonical gate byte must preempt the spawn")
            .into_parts();
    // Only EOF is canonical on the gate. A byte is a protocol failure and must
    // not be mistaken for a live service that may spawn a launcher.
    assert_eq!(failure, LauncherSpawnFailure::InvalidGate);
    boundary.close_gate();
}

#[used]
#[unsafe(link_section = "__DATA,__mod_init_func")]
static EXACT_LAUNCHER_HOOK: extern "C" fn() = exact_launcher_hook;

extern "C" fn exact_launcher_hook() {
    // SAFETY: getenv reads one static NUL-terminated name before main. The
    // returned pointer, when nonnull, remains valid until this process exits.
    let mode = unsafe { getenv(FIXTURE_ENV.as_ptr().cast()) };
    if mode.is_null() {
        return;
    }
    // SAFETY: getenv returned one NUL-terminated environment value.
    let mode = unsafe { CStr::from_ptr(mode) }.to_bytes();
    if mode == POST_EXEC
        || mode == POST_EXEC_STOP
        || mode == POST_EXEC_DELAY
        || mode == POST_EXEC_SIGKILL
    {
        return;
    }
    if mode != VALID_EXEC
        && mode != FAKE_TRAP
        && mode != UNEXPECTED_STOP
        && mode != UNTRACED_STOP
        && mode != SUBSTITUTE_EXEC
        && mode != TARGET_STOP
        && mode != TARGET_DELAY
        && mode != TARGET_SIGKILL
    {
        // SAFETY: an isolated malformed fixture must not enter libtest.
        unsafe { _exit(91) }
    }

    if mode == UNTRACED_STOP {
        // SAFETY: this deliberately supplies the expected signal without
        // PT_TRACE_ME. The parent must not classify it as traced authority.
        if unsafe { raise(SIGSTOP) } != 0 {
            // SAFETY: the isolated fixture cannot continue safely.
            unsafe { _exit(100) }
        }
        // SAFETY: the parent should exact-kill this stopped direct child.
        unsafe { _exit(101) }
    }

    // SAFETY: this isolated direct child designates its actual parent as the
    // sole tracer, then creates the launcher's canonical initial stop.
    if unsafe { ptrace(PT_TRACE_ME, 0, std::ptr::null_mut(), 0) } != 0
        || unsafe { raise(SIGSTOP) } != 0
    {
        // SAFETY: fixture setup failed before Rust runtime entry.
        unsafe { _exit(92) }
    }

    if mode == FAKE_TRAP {
        // SAFETY: this deliberately counterfeits the expected signal without
        // crossing exec; the parent must reject the unchanged PID version.
        if unsafe { raise(SIGTRAP) } != 0 {
            // SAFETY: the isolated fixture cannot continue safely.
            unsafe { _exit(93) }
        }
        // SAFETY: the parent should kill this tracee while it remains stopped.
        unsafe { _exit(94) }
    }
    if mode == UNEXPECTED_STOP {
        // SAFETY: this deliberately supplies a noncanonical second stop; the
        // exact waiter must reject it and retain cleanup authority.
        if unsafe { raise(SIGSTOP) } != 0 {
            // SAFETY: the isolated fixture cannot continue safely.
            unsafe { _exit(98) }
        }
        // SAFETY: the parent should kill this tracee at the unexpected stop.
        unsafe { _exit(99) }
    }

    let substitute_exec = mode == SUBSTITUTE_EXEC;

    // SAFETY: both arguments are static NUL-terminated strings. Marking the
    // next image prevents this initializer from tracing a second time.
    let post_exec = if mode == TARGET_STOP {
        c"post-exec-stop"
    } else if mode == TARGET_DELAY {
        c"post-exec-delay"
    } else if mode == TARGET_SIGKILL {
        c"post-exec-sigkill"
    } else {
        c"post-exec"
    };
    if unsafe { setenv(FIXTURE_ENV.as_ptr().cast(), post_exec.as_ptr(), 1) } != 0 {
        // SAFETY: the fixture cannot establish its one-exec invariant.
        unsafe { _exit(95) }
    }
    let executable = if substitute_exec {
        std::path::PathBuf::from("/usr/bin/true")
    } else {
        match std::env::current_exe() {
            Ok(executable) => executable,
            // SAFETY: fixture discovery failed before the intended exec.
            Err(_) => unsafe { _exit(96) },
        }
    };
    let error = Command::new(executable)
        .arg("--exact")
        .arg(EXACT_TEST)
        .arg("--ignored")
        .arg("--nocapture")
        .exec();
    let _ = error;
    // SAFETY: exec returned, so the fixture cannot satisfy the protocol.
    unsafe { _exit(97) }
}

struct Fixture {
    child: Child,
    gate: Option<ActiveBrokerGate>,
    gate_writer: Option<OwnedFd>,
    trace_peer: Option<UnixStream>,
    launcher_readers: Option<(OwnedFd, OwnedFd)>,
}

impl Fixture {
    fn spawn(mode: &str) -> Self {
        let mut descriptors = [-1; 2];
        // SAFETY: descriptors has storage for both pipe descriptors.
        assert_eq!(unsafe { pipe(descriptors.as_mut_ptr()) }, 0);
        // SAFETY: successful pipe returned two distinct owned descriptors.
        let gate_reader = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
        // SAFETY: successful pipe returned two distinct owned descriptors.
        let gate_writer = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
        // SAFETY: both live fixture descriptors must disappear from the execed
        // child so only this parent retains service-liveness authority.
        assert_eq!(
            unsafe {
                super::super::fcntl(
                    gate_reader.as_raw_fd(),
                    super::super::F_SETFD,
                    super::super::FD_CLOEXEC,
                )
            },
            0
        );
        // SAFETY: same live-descriptor close-on-exec operation as above.
        assert_eq!(
            unsafe {
                super::super::fcntl(
                    gate_writer.as_raw_fd(),
                    super::super::F_SETFD,
                    super::super::FD_CLOEXEC,
                )
            },
            0
        );
        let child = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg(EXACT_TEST)
            .arg("--ignored")
            .arg("--nocapture")
            .env(
                std::str::from_utf8(&FIXTURE_ENV[..FIXTURE_ENV.len() - 1]).unwrap(),
                mode,
            )
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        Self {
            child,
            gate: Some(ActiveBrokerGate {
                reader: gate_reader,
            }),
            gate_writer: Some(gate_writer),
            trace_peer: None,
            launcher_readers: None,
        }
    }

    fn spawned_launcher(&mut self, deadline: Instant) -> SpawnedLauncher {
        let expected_executable = std::env::current_exe()
            .unwrap()
            .as_os_str()
            .as_bytes()
            .to_vec();
        self.spawned_launcher_with_identity(deadline, expected_executable, None)
    }

    fn spawned_launcher_with_identity(
        &mut self,
        deadline: Instant,
        expected_launcher_executable: Vec<u8>,
        expected_effective_uid: Option<u32>,
    ) -> SpawnedLauncher {
        let pid = c_int::try_from(self.child.id()).unwrap();
        let gate = self.gate.take().unwrap();
        let expected_executable = std::env::current_exe()
            .unwrap()
            .as_os_str()
            .as_bytes()
            .to_vec();
        // SAFETY: credential getters have no preconditions.
        let plan = super::super::super::auth_adapter::broker_plan::ExactParentBrokerLaunchPlan::for_launcher_test(
            deadline,
            unsafe { geteuid() },
            unsafe { getegid() },
            expected_executable,
        );
        let (trace, trace_peer) = UnixStream::pair().unwrap();
        trace.set_nonblocking(true).unwrap();
        self.trace_peer = Some(trace_peer);
        let active = ActiveBrokerProcess { gate, plan, trace };
        // SAFETY: credential getters have no preconditions.
        let expected_launcher = FixedLauncherIdentity::for_test(
            unsafe { getuid() },
            expected_effective_uid.unwrap_or_else(|| unsafe { geteuid() }),
            unsafe { getgid() },
            unsafe { getegid() },
            expected_launcher_executable,
        );
        // Real retained ends, so the fixture arms the production channel shape
        // and exercises the release-before-signal cleanup ordering. The reader
        // ends stay live here, standing in for the child that would hold them.
        let (death_reader, death_writer) = test_pipe();
        let (plan_reader, plan_writer) = test_pipe();
        self.launcher_readers = Some((death_reader, plan_reader));
        let channels = RetainedLauncherChannels::for_test(plan_writer, death_writer);
        // SAFETY: Command just returned this positive direct-child PID, and
        // this fixture never performs another wait on its Child handle. The
        // active process owns the immutable production-shaped plan binding;
        // the test identity names the exact fixed fixture image and IDs.
        unsafe { SpawnedLauncher::from_positive_spawn(pid, active, expected_launcher, channels) }
            .unwrap()
    }

    fn deadline(&self) -> Instant {
        Instant::now() + Duration::from_secs(5)
    }

    fn close_gate(&mut self) {
        drop(self.gate_writer.take());
    }

    fn held_exec(&mut self) -> (c_int, ExecTrapHeld) {
        self.held_exec_until(self.deadline())
    }

    fn held_exec_until(&mut self, deadline: Instant) -> (c_int, ExecTrapHeld) {
        let pid = c_int::try_from(self.child.id()).unwrap();
        let initial = self.spawned_launcher(deadline).wait_initial_stop().unwrap();
        let running = initial.prove_trace_and_continue_to_exec().unwrap();
        (pid, running.wait_exec_trap().unwrap())
    }

    fn drain_report(&mut self) -> UnixStream {
        let mut service = self.trace_peer.take().unwrap();
        let mut report =
            [0_u8; super::super::super::auth_adapter::broker_report::BROKER_TRACE_REPORT_BYTES];
        service.read_exact(&mut report).unwrap();
        assert_eq!(&report[..8], b"NIPCBTR1");
        let mut extension = [0_u8; 1];
        assert_eq!(service.read(&mut extension).unwrap(), 0);
        service
    }
}

#[test]
fn real_exec_changes_audit_pid_version_at_exact_trap() {
    let mut fixture = Fixture::spawn("valid-exec");
    let pid = c_int::try_from(fixture.child.id()).unwrap();
    let deadline = fixture.deadline();
    let initial = fixture
        .spawned_launcher(deadline)
        .wait_initial_stop()
        .unwrap();
    let running = initial.prove_trace_and_continue_to_exec().unwrap();
    let held = running.wait_exec_trap().unwrap();
    assert_eq!(held.exact_pid_for_test(), pid);
    drop(held);
    fixture.close_gate();
}

#[test]
fn same_image_sigtrap_cannot_counterfeit_exec_transition() {
    let mut fixture = Fixture::spawn("fake-trap");
    let deadline = fixture.deadline();
    let initial = fixture
        .spawned_launcher(deadline)
        .wait_initial_stop()
        .unwrap();
    let running = initial.prove_trace_and_continue_to_exec().unwrap();
    let result = running.wait_exec_trap();
    assert!(matches!(result, Err(LauncherWaitError::IdentityTransition)));
    fixture.close_gate();
}

#[test]
fn unexpected_second_stop_is_rejected_and_exact_cleaned() {
    let mut fixture = Fixture::spawn("unexpected-stop");
    let deadline = fixture.deadline();
    let initial = fixture
        .spawned_launcher(deadline)
        .wait_initial_stop()
        .unwrap();
    let running = initial.prove_trace_and_continue_to_exec().unwrap();
    let result = running.wait_exec_trap();
    assert!(matches!(result, Err(LauncherWaitError::UnexpectedStatus)));
    fixture.close_gate();
}

#[test]
fn service_death_preempts_initial_stop_authority() {
    let mut fixture = Fixture::spawn("valid-exec");
    fixture.close_gate();
    let deadline = fixture.deadline();
    assert!(matches!(
        fixture.spawned_launcher(deadline).wait_initial_stop(),
        Err(LauncherWaitError::ServiceGone)
    ));
}

#[test]
fn expired_deadline_preempts_initial_stop_authority() {
    let mut fixture = Fixture::spawn("valid-exec");
    let launcher = fixture.spawned_launcher(Instant::now() + Duration::from_millis(1));
    std::thread::sleep(Duration::from_millis(2));
    assert!(matches!(
        launcher.wait_initial_stop(),
        Err(LauncherWaitError::DeadlineExpired)
    ));
    fixture.close_gate();
}

#[test]
fn untraced_initial_sigstop_cannot_mint_ptrace_authority() {
    let mut fixture = Fixture::spawn("untraced-stop");
    let deadline = fixture.deadline();
    let initial = fixture
        .spawned_launcher(deadline)
        .wait_initial_stop()
        .unwrap();
    assert!(matches!(
        initial.prove_trace_and_continue_to_exec(),
        Err(LauncherWaitError::Native(_))
    ));
    fixture.close_gate();
}

#[test]
fn wrong_initial_launcher_image_never_reaches_ptrace_continue() {
    let mut fixture = Fixture::spawn("valid-exec");
    let deadline = fixture.deadline();
    assert!(matches!(
        fixture
            .spawned_launcher_with_identity(deadline, b"/usr/bin/false".to_vec(), None)
            .wait_initial_stop(),
        Err(LauncherWaitError::IdentityTransition)
    ));
    fixture.close_gate();
}

#[test]
fn wrong_initial_launcher_credentials_never_reach_ptrace_continue() {
    let mut fixture = Fixture::spawn("valid-exec");
    let deadline = fixture.deadline();
    let expected_executable = std::env::current_exe()
        .unwrap()
        .as_os_str()
        .as_bytes()
        .to_vec();
    // SAFETY: credential getter has no preconditions.
    let wrong_uid = unsafe { geteuid() }.wrapping_add(1);
    assert!(matches!(
        fixture
            .spawned_launcher_with_identity(deadline, expected_executable, Some(wrong_uid))
            .wait_initial_stop(),
        Err(LauncherWaitError::IdentityTransition)
    ));
    fixture.close_gate();
}

#[test]
fn different_exec_image_cannot_mint_bound_identity() {
    let mut fixture = Fixture::spawn("substitute-exec");
    let deadline = fixture.deadline();
    let initial = fixture
        .spawned_launcher(deadline)
        .wait_initial_stop()
        .unwrap();
    let running = initial.prove_trace_and_continue_to_exec().unwrap();
    assert!(matches!(
        running.wait_exec_trap(),
        Err(LauncherWaitError::IdentityTransition)
    ));
    fixture.close_gate();
}

#[test]
fn held_exec_reports_waits_for_ready_and_resumes_exactly_once() {
    let mut fixture = Fixture::spawn("valid-exec");
    let (pid, held) = fixture.held_exec();
    let reported = held.report_trace_stops().unwrap().unwrap();

    let mut service = fixture.drain_report();
    service
        .write_all(&super::super::super::auth_adapter::broker_report::BROKER_RESUME_BYTE)
        .unwrap();
    service.shutdown(Shutdown::Write).unwrap();

    let committed = reported.wait_for_ready_commit().unwrap().unwrap();
    let resumed = committed.resume_target().unwrap();
    assert_eq!(resumed.exact_pid_for_test(), pid);
    drop(resumed);
    fixture.close_gate();
}

#[test]
fn service_death_before_report_exactly_cleans_held_target() {
    let mut fixture = Fixture::spawn("valid-exec");
    let (_, held) = fixture.held_exec();
    fixture.close_gate();
    // The production service is permanently single-threaded while spawning,
    // but libtest concurrently execs unrelated helpers that can transiently
    // inherit this fixture's pipe writer before their CLOEXEC boundary.
    held.wait_for_gate_eof_for_test();
    match held.report_trace_stops() {
        Ok(Err(BrokerGateExit::ServiceGone)) => {}
        Ok(Err(exit)) => panic!("unexpected gate exit: {exit:?}"),
        Ok(Ok(_)) => panic!("service death minted reported authority"),
        Err(error) => panic!("service death returned protocol error: {error:?}"),
    }
}

#[test]
fn malformed_or_extended_resume_exactly_cleans_reported_target() {
    for resume in [[9_u8].as_slice(), [1_u8, 2].as_slice()] {
        let mut fixture = Fixture::spawn("valid-exec");
        let (_, held) = fixture.held_exec();
        let reported = held.report_trace_stops().unwrap().unwrap();
        let mut service = fixture.drain_report();
        service.write_all(resume).unwrap();
        service.shutdown(Shutdown::Write).unwrap();
        assert!(matches!(
            reported.wait_for_ready_commit(),
            Err(BrokerEntryError::Plan(SupervisorWireError::Malformed))
        ));
        fixture.close_gate();
    }
}

#[test]
fn service_death_after_commit_preempts_delayed_resume() {
    let mut fixture = Fixture::spawn("valid-exec");
    let (_, held) = fixture.held_exec();
    let reported = held.report_trace_stops().unwrap().unwrap();
    let mut service = fixture.drain_report();
    service
        .write_all(&super::super::super::auth_adapter::broker_report::BROKER_RESUME_BYTE)
        .unwrap();
    service.shutdown(Shutdown::Write).unwrap();
    let committed = reported.wait_for_ready_commit().unwrap().unwrap();
    fixture.close_gate();
    committed.wait_for_gate_eof_for_test();
    assert!(matches!(
        committed.resume_target(),
        Err(LauncherWaitError::ServiceGone)
    ));
}

#[test]
fn ready_resume_commit_has_no_broker_side_deadline_veto() {
    let mut fixture = Fixture::spawn("valid-exec");
    let deadline = Instant::now() + Duration::from_millis(250);
    let (_, held) = fixture.held_exec_until(deadline);
    let reported = held.report_trace_stops().unwrap().unwrap();
    let mut service = fixture.drain_report();
    std::thread::sleep(Duration::from_millis(300));
    service
        .write_all(&super::super::super::auth_adapter::broker_report::BROKER_RESUME_BYTE)
        .unwrap();
    service.shutdown(Shutdown::Write).unwrap();
    let committed = reported.wait_for_ready_commit().unwrap().unwrap();
    let resumed = committed.resume_target().unwrap();
    drop(resumed);
    fixture.close_gate();
}

#[test]
fn resumed_target_natural_exit_is_exactly_reaped() {
    let mut fixture = Fixture::spawn("valid-exec");
    let (_, held) = fixture.held_exec();
    let reported = held.report_trace_stops().unwrap().unwrap();
    let mut service = fixture.drain_report();
    service
        .write_all(&super::super::super::auth_adapter::broker_report::BROKER_RESUME_BYTE)
        .unwrap();
    service.shutdown(Shutdown::Write).unwrap();
    let resumed = reported
        .wait_for_ready_commit()
        .unwrap()
        .unwrap()
        .resume_target()
        .unwrap();
    assert_eq!(resumed.wait_for_exit(), Ok(ExactTargetExit::Exited(101)));
    fixture.close_gate();
}

#[test]
fn post_ready_sigkill_is_a_terminal_traced_stop_and_exactly_cleaned() {
    let mut fixture = Fixture::spawn("target-sigkill");
    let (_, held) = fixture.held_exec();
    let reported = held.report_trace_stops().unwrap().unwrap();
    let mut service = fixture.drain_report();
    service
        .write_all(&super::super::super::auth_adapter::broker_report::BROKER_RESUME_BYTE)
        .unwrap();
    service.shutdown(Shutdown::Write).unwrap();
    let resumed = reported
        .wait_for_ready_commit()
        .unwrap()
        .unwrap()
        .resume_target()
        .unwrap();
    assert_eq!(
        resumed.wait_for_exit(),
        Err(LauncherWaitError::UnexpectedStatus)
    );
    fixture.close_gate();
}

#[test]
fn terminal_status_decoder_distinguishes_exit_and_signal() {
    assert_eq!(
        exact_target_exit(23 << 8),
        Some(ExactTargetExit::Exited(23))
    );
    assert_eq!(
        exact_target_exit(SIGKILL),
        Some(ExactTargetExit::Signaled(SIGKILL))
    );
    assert_eq!(exact_target_exit((SIGSTOP << 8) | 0x7f), None);
}

#[test]
fn service_death_after_terminal_wait_wins_classification() {
    let mut fixture = Fixture::spawn("valid-exec");
    let (_, held) = fixture.held_exec();
    let reported = held.report_trace_stops().unwrap().unwrap();
    let mut service = fixture.drain_report();
    service
        .write_all(&super::super::super::auth_adapter::broker_report::BROKER_RESUME_BYTE)
        .unwrap();
    service.shutdown(Shutdown::Write).unwrap();
    let resumed = reported
        .wait_for_ready_commit()
        .unwrap()
        .unwrap()
        .resume_target()
        .unwrap();
    let gate_writer = fixture.gate_writer.take().unwrap();
    assert_eq!(
        resumed.wait_for_exit_with_post_wait_for_test(move |gate| {
            drop(gate_writer);
            wait_for_gate_eof(gate);
        }),
        Err(LauncherWaitError::ServiceGone)
    );
}

#[test]
fn service_death_after_stop_wait_wins_and_exactly_cleans() {
    let mut fixture = Fixture::spawn("target-stop");
    let (_, held) = fixture.held_exec();
    let reported = held.report_trace_stops().unwrap().unwrap();
    let mut service = fixture.drain_report();
    service
        .write_all(&super::super::super::auth_adapter::broker_report::BROKER_RESUME_BYTE)
        .unwrap();
    service.shutdown(Shutdown::Write).unwrap();
    let resumed = reported
        .wait_for_ready_commit()
        .unwrap()
        .unwrap()
        .resume_target()
        .unwrap();
    let gate_writer = fixture.gate_writer.take().unwrap();
    assert_eq!(
        resumed.wait_for_exit_with_post_wait_for_test(move |gate| {
            drop(gate_writer);
            wait_for_gate_eof(gate);
        }),
        Err(LauncherWaitError::ServiceGone)
    );
}

#[test]
fn service_death_while_target_runs_preempts_exit_and_exactly_cleans() {
    let mut fixture = Fixture::spawn("valid-exec");
    let (_, held) = fixture.held_exec();
    let reported = held.report_trace_stops().unwrap().unwrap();
    let mut service = fixture.drain_report();
    service
        .write_all(&super::super::super::auth_adapter::broker_report::BROKER_RESUME_BYTE)
        .unwrap();
    service.shutdown(Shutdown::Write).unwrap();
    let resumed = reported
        .wait_for_ready_commit()
        .unwrap()
        .unwrap()
        .resume_target()
        .unwrap();
    fixture.close_gate();
    // The production broker is single-threaded, while unrelated libtest
    // helpers can transiently retain a CLOEXEC writer until their exec edge.
    resumed.wait_for_gate_eof_for_test();
    assert_eq!(resumed.wait_for_exit(), Err(LauncherWaitError::ServiceGone));
}

#[test]
fn service_death_after_waiting_begins_still_wins_and_exactly_cleans() {
    let mut fixture = Fixture::spawn("target-delay");
    let (_, held) = fixture.held_exec();
    let reported = held.report_trace_stops().unwrap().unwrap();
    let mut service = fixture.drain_report();
    service
        .write_all(&super::super::super::auth_adapter::broker_report::BROKER_RESUME_BYTE)
        .unwrap();
    service.shutdown(Shutdown::Write).unwrap();
    let resumed = reported
        .wait_for_ready_commit()
        .unwrap()
        .unwrap()
        .resume_target()
        .unwrap();
    let gate_writer = fixture.gate_writer.take().unwrap();
    let closer = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(20));
        drop(gate_writer);
    });
    assert_eq!(resumed.wait_for_exit(), Err(LauncherWaitError::ServiceGone));
    closer.join().unwrap();
}

#[test]
fn post_ready_target_stop_is_terminal_and_exactly_cleaned() {
    let mut fixture = Fixture::spawn("target-stop");
    let (_, held) = fixture.held_exec();
    let reported = held.report_trace_stops().unwrap().unwrap();
    let mut service = fixture.drain_report();
    service
        .write_all(&super::super::super::auth_adapter::broker_report::BROKER_RESUME_BYTE)
        .unwrap();
    service.shutdown(Shutdown::Write).unwrap();
    let resumed = reported
        .wait_for_ready_commit()
        .unwrap()
        .unwrap()
        .resume_target()
        .unwrap();
    assert_eq!(
        resumed.wait_for_exit(),
        Err(LauncherWaitError::UnexpectedStatus)
    );
    fixture.close_gate();
}

#[test]
#[ignore = "exec target for the exact broker-launcher native fixture"]
fn fixture_target() {
    // SAFETY: getenv reads the one fixed fixture variable in the isolated
    // post-exec target process.
    let mode = unsafe { getenv(FIXTURE_ENV.as_ptr().cast()) };
    if !mode.is_null()
        // SAFETY: the nonnull environment pointer is NUL-terminated.
        && unsafe { CStr::from_ptr(mode) }.to_bytes() == POST_EXEC_STOP
    {
        // SAFETY: this deliberately creates a traced post-Ready stop so the
        // broker's running-target waiter must exact-clean it.
        assert_eq!(unsafe { raise(SIGSTOP) }, 0);
    }
    if !mode.is_null()
        // SAFETY: the nonnull environment pointer is NUL-terminated.
        && unsafe { CStr::from_ptr(mode) }.to_bytes() == POST_EXEC_DELAY
    {
        std::thread::sleep(Duration::from_millis(500));
    }
    if !mode.is_null()
        // SAFETY: the nonnull environment pointer is NUL-terminated.
        && unsafe { CStr::from_ptr(mode) }.to_bytes() == POST_EXEC_SIGKILL
    {
        // SAFETY: the isolated fixture intentionally terminates itself.
        assert_eq!(unsafe { raise(SIGKILL) }, 0);
    }
    panic!("the exact launcher waiter should kill this image at its exec trap");
}

fn wait_for_gate_eof(gate: &ActiveBrokerGate) {
    loop {
        match probe_gate(gate) {
            Err(LauncherWaitError::ServiceGone) => return,
            Ok(()) => poll_gate_slice(gate).unwrap(),
            Err(error) => panic!("unexpected gate probe failure: {error:?}"),
        }
    }
}
