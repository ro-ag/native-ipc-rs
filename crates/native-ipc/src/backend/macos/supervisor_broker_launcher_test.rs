use std::ffi::{CStr, c_char, c_int};
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
const FAKE_TRAP: &[u8] = b"fake-trap";
const UNEXPECTED_STOP: &[u8] = b"unexpected-stop";
const UNTRACED_STOP: &[u8] = b"untraced-stop";
const SUBSTITUTE_EXEC: &[u8] = b"substitute-exec";
const EXACT_TEST: &str =
    "backend::macos::supervisor::broker_entry::broker_launcher::tests::fixture_target";
const PT_TRACE_ME: c_int = 0;

unsafe extern "C" {
    fn _exit(status: c_int) -> !;
    fn getenv(name: *const c_char) -> *mut c_char;
    fn getegid() -> u32;
    fn geteuid() -> u32;
    fn pipe(descriptors: *mut c_int) -> c_int;
    fn raise(signal: c_int) -> c_int;
    fn setenv(name: *const c_char, value: *const c_char, overwrite: c_int) -> c_int;
}

assert_not_impl_any!(SpawnedLauncher: Clone, Copy, Send, Sync);
assert_not_impl_any!(InitialStopObserved: Clone, Copy, Send, Sync);
assert_not_impl_any!(AwaitingExecTrap: Clone, Copy, Send, Sync);
assert_not_impl_any!(ExecTrapHeld: Clone, Copy, Send, Sync);

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
    if mode == POST_EXEC {
        return;
    }
    if mode != VALID_EXEC
        && mode != FAKE_TRAP
        && mode != UNEXPECTED_STOP
        && mode != UNTRACED_STOP
        && mode != SUBSTITUTE_EXEC
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
    if unsafe { setenv(FIXTURE_ENV.as_ptr().cast(), c"post-exec".as_ptr(), 1) } != 0 {
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
        }
    }

    fn spawned_launcher(&mut self, deadline: Instant) -> SpawnedLauncher {
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
        drop(trace_peer);
        let active = ActiveBrokerProcess { gate, plan, trace };
        // SAFETY: Command just returned this positive direct-child PID, and
        // this fixture never performs another wait on its Child handle. The
        // active process owns the immutable production-shaped plan binding.
        unsafe { SpawnedLauncher::from_positive_spawn(pid, active) }.unwrap()
    }

    fn deadline(&self) -> Instant {
        Instant::now() + Duration::from_secs(5)
    }

    fn close_gate(&mut self) {
        drop(self.gate_writer.take());
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
#[ignore = "exec target for the exact broker-launcher native fixture"]
fn fixture_target() {
    panic!("the exact launcher waiter should kill this image at its exec trap");
}
