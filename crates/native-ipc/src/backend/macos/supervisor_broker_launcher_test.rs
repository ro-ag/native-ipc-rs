use std::ffi::{CStr, CString, c_char, c_int};
use std::fs;
use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::thread::JoinHandle;
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
const DEPLOYER_LAUNCHER_PATH: &CStr =
    c"/example/NativeIPC.app/Contents/Helpers/native-ipc-launcher";
const PRODUCTION_BROKER_FIXTURE_SUFFIX: &[u8] = b".native-ipc-production-broker-fixture";
const PT_TRACE_ME: c_int = 0;
const ENOENT: c_int = 2;
const ECHILD: c_int = 10;
const WNOHANG: c_int = 1;
const F_DUPFD: c_int = 0;
const F_GETFD: c_int = 1;
const F_SETFD: c_int = 2;
const O_ACCMODE: c_int = 3;
const FD_CLOEXEC: c_int = 1;
const MACH_PORT_TYPE_SEND: u32 = 1 << 16;
const MACH_PORT_TYPE_RECEIVE: u32 = 1 << 17;
const MACH_PORT_TYPE_DEAD_NAME: u32 = 1 << 20;

unsafe extern "C" {
    fn _exit(status: c_int) -> !;
    fn getdtablesize() -> c_int;
    fn getenv(name: *const c_char) -> *mut c_char;
    fn getegid() -> u32;
    fn getgid() -> u32;
    fn geteuid() -> u32;
    fn getuid() -> u32;
    fn mach_port_type(task: u32, name: u32, port_type: *mut u32) -> c_int;
    fn pipe(descriptors: *mut c_int) -> c_int;
    fn raise(signal: c_int) -> c_int;
    fn setenv(name: *const c_char, value: *const c_char, overwrite: c_int) -> c_int;
    fn task_get_special_port(task: u32, which: c_int, port: *mut u32) -> c_int;
}

assert_not_impl_any!(SpawnedLauncher: Clone, Copy, Send, Sync);
assert_not_impl_any!(InitialStopObserved: Clone, Copy, Send, Sync);
assert_not_impl_any!(AwaitingExecTrap: Clone, Copy, Send, Sync);
assert_not_impl_any!(ExecTrapHeld: Clone, Copy, Send, Sync);
assert_not_impl_any!(SignatureVerifiedExecTrap: Clone, Copy, Send, Sync);

struct FakeSignatureWorkerAuthority;

unsafe impl super::super::super::auth_adapter::ExactAuthWorkerAuthority
    for FakeSignatureWorkerAuthority
{
    type Failure = ();

    fn try_reap_after_result(
        &mut self,
    ) -> Result<Option<super::super::super::auth_adapter::ReapedAuthWorker>, Self::Failure> {
        Ok(Some(
            super::super::super::auth_adapter::ReapedAuthWorker::from_test_clean_exit(),
        ))
    }

    fn try_terminate_and_reap(
        &mut self,
    ) -> Result<Option<super::super::super::auth_adapter::ReapedAuthWorker>, Self::Failure> {
        Ok(Some(
            super::super::super::auth_adapter::ReapedAuthWorker::from_test_clean_exit(),
        ))
    }

    fn emergency_terminate_and_reap(
        &mut self,
    ) -> super::super::super::auth_adapter::ReapedAuthWorker {
        super::super::super::auth_adapter::ReapedAuthWorker::from_test_clean_exit()
    }
}

fn signature_job_id(byte: u8) -> super::super::super::auth_adapter::FreshAuthJobId {
    // SAFETY: each test uses one fresh nonzero value for its one-job pool.
    unsafe {
        super::super::super::auth_adapter::FreshAuthJobId::from_fresh_random([byte; 32]).unwrap()
    }
}

fn signature_worker_pool(
    code_identity: [u8; 32],
    expected_audit_identity: [u8; 32],
) -> (
    super::super::super::auth_adapter::AuthWorkerPool<FakeSignatureWorkerAuthority>,
    JoinHandle<()>,
) {
    use super::super::super::auth_adapter::{
        AuthWorkerEndpoint, AuthWorkerJob, AuthWorkerPool, ExactAuthWorker,
        FreshAuthWorkerGeneration,
    };

    let (request_reader, request_writer) = test_pipe();
    let (result_reader, result_writer) = test_pipe();
    super::set_nonblocking(request_writer.as_raw_fd(), true).unwrap();
    super::set_nonblocking(result_reader.as_raw_fd(), true).unwrap();
    // SAFETY: the request writer is a live pipe descriptor retained by the
    // parent endpoint; Darwin applies this setting without consuming it.
    assert_eq!(
        unsafe { fcntl(request_writer.as_raw_fd(), F_SETNOSIGPIPE, 1) },
        0
    );
    // SAFETY: these are the sole parent ends for one fresh private worker.
    let endpoint =
        unsafe { AuthWorkerEndpoint::from_private_parent_pipe_ends(request_writer, result_reader) };
    // SAFETY: this fake models one exact unreaped worker owned by the pool.
    let worker =
        unsafe { ExactAuthWorker::from_test_unreaped_direct_child(FakeSignatureWorkerAuthority) };
    // SAFETY: this generation is nonzero and unique within this one-worker pool.
    let generation = unsafe { FreshAuthWorkerGeneration::from_unique_service_value(1).unwrap() };
    let pool =
        AuthWorkerPool::from_test_precreated_workers(vec![(generation, worker, endpoint)]).unwrap();
    let worker_thread = std::thread::spawn(move || {
        let mut request = Vec::new();
        std::fs::File::from(request_reader)
            .read_to_end(&mut request)
            .unwrap();
        let job = AuthWorkerJob::decode_pipe_frame(&request).unwrap();
        assert_eq!(job.audit_identity(), expected_audit_identity);
        let result = job.encode_test_result(code_identity);
        std::fs::File::from(result_writer)
            .write_all(&result)
            .unwrap();
    });
    (pool, worker_thread)
}

#[test]
fn installed_launcher_vectors_and_same_user_identity_are_fixed() {
    // SAFETY: this source-level vector test does not claim the fixed image is
    // installed or verified; it inspects only the installation-bound values.
    let image =
        unsafe { InstalledLauncherImage::from_verified_installation(DEPLOYER_LAUNCHER_PATH) }
            .unwrap();
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
            DEPLOYER_LAUNCHER_PATH.to_bytes(),
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
    assert_eq!(identity.executable, DEPLOYER_LAUNCHER_PATH.to_bytes());
    // SAFETY: the invalid test value is rejected before any child can exist.
    assert!(matches!(
        unsafe { InstalledLauncherImage::from_verified_installation(c"relative-launcher") },
        Err(LauncherSpawnFailure::InvalidFixedImage)
    ));
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
    let image =
        unsafe { InstalledLauncherImage::from_verified_installation(DEPLOYER_LAUNCHER_PATH) }
            .unwrap();
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
/// signed, installed, or verified.
fn uninstalled_fixed_image() -> InstalledLauncherImage {
    // SAFETY: this inspects installation-bound values and deliberately drives
    // the spawn against an absent path; it asserts no installation evidence.
    unsafe { InstalledLauncherImage::from_verified_installation(DEPLOYER_LAUNCHER_PATH) }.unwrap()
}

#[test]
fn uninstalled_fixed_launcher_image_fails_only_at_the_exact_spawn() {
    assert!(
        !std::path::Path::new(std::ffi::OsStr::from_bytes(
            DEPLOYER_LAUNCHER_PATH.to_bytes()
        ))
        .exists(),
        "this boundary test is only meaningful while the fixed image is absent",
    );
    let mut boundary = SpawnBoundary::new(Instant::now() + Duration::from_secs(5));
    let (active, failure) = spawn_fixed_launcher(
        boundary.take_active(),
        &uninstalled_fixed_image(),
        &mut DedicatedChildWaitDomain::for_spawn_test(),
    )
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
fn production_spawn_installs_exact_launcher_fd_topology_and_characterizes_bootstrap() {
    let executable = std::env::current_exe().unwrap();
    let installed_path = CString::new(executable.as_os_str().as_bytes()).unwrap();
    // SAFETY: this fixture treats the absolute current test image as the one
    // deployer-verified launcher solely to exercise production spawn actions
    // and attributes. It establishes no installation or signing evidence.
    let image =
        unsafe { InstalledLauncherImage::from_verified_installation(&installed_path) }.unwrap();
    let mut boundary = SpawnBoundary::new(Instant::now() + Duration::from_secs(5));
    let sentinel = fs::File::open("/dev/null").unwrap();
    // SAFETY: duplicate one live broker descriptor above the fixed child ABI,
    // then deliberately clear CLOEXEC. The production spawn's
    // POSIX_SPAWN_CLOEXEC_DEFAULT attribute must still exclude it.
    let inherited_sentinel = unsafe { fcntl(sentinel.as_raw_fd(), F_DUPFD, 100) };
    assert!(inherited_sentinel >= 100);
    // SAFETY: the new descriptor is live and F_SETFD accepts zero flags.
    assert_eq!(unsafe { fcntl(inherited_sentinel, F_SETFD, 0) }, 0);
    // SAFETY: the successful F_DUPFD result is a fresh owned descriptor.
    let inherited_sentinel = unsafe { OwnedFd::from_raw_fd(inherited_sentinel) };

    let spawned = match spawn_fixed_launcher(
        boundary.take_active(),
        &image,
        &mut DedicatedChildWaitDomain::for_spawn_test(),
    ) {
        Ok(spawned) => spawned,
        Err(error) => {
            let (_active, failure) = error.into_parts();
            panic!("production-shaped launcher fixture failed to spawn: {failure:?}")
        }
    };
    let initial = spawned.wait_initial_stop().unwrap();

    // Dropping the exact stopped direct-child owner kills and drains through
    // ECHILD. No numeric PID is retained or reconstructed after this point.
    drop(initial);
    drop(inherited_sentinel);
    boundary.close_gate();
}

#[test]
fn service_death_preempts_the_fixed_launcher_spawn() {
    let mut boundary = SpawnBoundary::new(Instant::now() + Duration::from_secs(5));
    boundary.close_gate();
    let (_active, failure) = spawn_fixed_launcher(
        boundary.take_active(),
        &uninstalled_fixed_image(),
        &mut DedicatedChildWaitDomain::for_spawn_test(),
    )
    .err()
    .expect("service death must preempt the spawn")
    .into_parts();
    // Service loss outranks creating a child. This must never reach
    // posix_spawn, so it cannot report the absent image instead.
    assert_eq!(failure, LauncherSpawnFailure::ServiceGone);
}

#[test]
fn expired_deadline_preempts_the_fixed_launcher_spawn() {
    let mut boundary = SpawnBoundary::new(Instant::now() + Duration::from_millis(1));
    std::thread::sleep(Duration::from_millis(2));
    let (_active, failure) = spawn_fixed_launcher(
        boundary.take_active(),
        &uninstalled_fixed_image(),
        &mut DedicatedChildWaitDomain::for_spawn_test(),
    )
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
    let (_active, failure) = spawn_fixed_launcher(
        boundary.take_active(),
        &uninstalled_fixed_image(),
        &mut DedicatedChildWaitDomain::for_spawn_test(),
    )
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
    let mut arguments = std::env::args_os();
    let argument0 = arguments.next();
    let launcher_mode = arguments
        .next()
        .is_some_and(|argument| argument.as_bytes() == INSTALLED_LAUNCHER_MODE.as_bytes());
    if launcher_mode && production_spawn_has_canonical_environment() {
        if let Some(argument0) = argument0
            && argument0
                .as_bytes()
                .ends_with(PRODUCTION_BROKER_FIXTURE_SUFFIX)
        {
            let installed = CString::new(argument0.as_bytes()).unwrap_or_else(|_| {
                // SAFETY: the isolated fixture cannot satisfy the entry ABI.
                unsafe { _exit(105) }
            });
            // SAFETY: the production-broker sibling fixture installed this
            // exact path/vector and the sole FD3/FD4 ownership before exec.
            unsafe { super::super::super::launcher_entry::run_fixed_launcher_process(&installed) }
        }
        production_spawn_containment_hook();
    }

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

fn production_spawn_containment_hook() -> ! {
    if !production_spawn_has_exact_arguments()
        || !production_spawn_has_canonical_environment()
        || !production_spawn_has_null_stdio()
        || !production_spawn_has_exact_descriptors()
        || !production_spawn_has_bounded_bootstrap_right()
    {
        // SAFETY: the isolated fixture must not enter libtest after observing
        // a production launcher-spawn contract violation.
        unsafe { _exit(102) }
    }

    // The parent uses the production initial-stop path as the fixture's one
    // success receipt. If it observes this stop, every check above ran inside
    // the exact image created by LauncherSpawnResources.
    // SAFETY: this isolated fixture designates its actual parent as tracer and
    // then produces the launcher's canonical initial stop.
    if unsafe { ptrace(PT_TRACE_ME, 0, std::ptr::null_mut(), 0) } != 0
        || unsafe { raise(SIGSTOP) } != 0
    {
        // SAFETY: the fixture cannot continue safely without exact tracing.
        unsafe { _exit(103) }
    }
    // SAFETY: the parent exact-kills this stopped fixture; resumption is a
    // protocol failure rather than permission to enter libtest.
    unsafe { _exit(104) }
}

fn production_spawn_has_canonical_environment() -> bool {
    let mut environment = std::env::vars_os()
        .map(|(key, value)| (key.as_bytes().to_vec(), value.as_bytes().to_vec()))
        .collect::<Vec<_>>();
    environment.sort_unstable();
    environment
        == [
            (b"LANG".to_vec(), b"C".to_vec()),
            (b"LC_ALL".to_vec(), b"C".to_vec()),
            (b"PATH".to_vec(), b"/usr/bin:/bin".to_vec()),
        ]
}

fn production_spawn_has_exact_arguments() -> bool {
    let arguments = std::env::args_os()
        .map(|argument| argument.as_bytes().to_vec())
        .collect::<Vec<_>>();
    arguments.len() == 4
        && arguments[0].first() == Some(&b'/')
        && arguments[1] == INSTALLED_LAUNCHER_MODE.as_bytes()
        && arguments[2] == INSTALLED_LAUNCHER_DEATH_ARGUMENT.as_bytes()
        && arguments[3] == INSTALLED_LAUNCHER_PLAN_ARGUMENT.as_bytes()
}

fn production_spawn_has_null_stdio() -> bool {
    let Ok(null) = fs::metadata("/dev/null") else {
        return false;
    };
    (0..=2).all(|descriptor| {
        let Ok(metadata) = fs::metadata(format!("/dev/fd/{descriptor}")) else {
            return false;
        };
        metadata.file_type().is_char_device()
            && metadata.dev() == null.dev()
            && metadata.ino() == null.ino()
            && metadata.rdev() == null.rdev()
    })
}

fn production_spawn_has_exact_descriptors() -> bool {
    for descriptor in [LAUNCHER_DEATH_FD, LAUNCHER_PLAN_FD] {
        // SAFETY: these are read-only descriptor queries on fixed nonnegative
        // numbers; the fixture owns no Rust value for either child descriptor.
        let descriptor_flags = unsafe { fcntl(descriptor, F_GETFD) };
        let status_flags = unsafe { fcntl(descriptor, F_GETFL) };
        let Ok(metadata) = fs::metadata(format!("/dev/fd/{descriptor}")) else {
            return false;
        };
        if descriptor_flags < 0
            || descriptor_flags & FD_CLOEXEC != 0
            || status_flags < 0
            || status_flags & O_ACCMODE != 0
            || !metadata.file_type().is_fifo()
        {
            return false;
        }
    }

    // SAFETY: getdtablesize is a read-only process limit query.
    let descriptor_limit = unsafe { getdtablesize() };
    descriptor_limit > LAUNCHER_PLAN_FD
        && (0..descriptor_limit).all(|descriptor| {
            // SAFETY: F_GETFD only observes whether this numeric slot is live.
            let is_open = unsafe { fcntl(descriptor, F_GETFD) } >= 0;
            is_open == (0..=LAUNCHER_PLAN_FD).contains(&descriptor)
        })
}

fn production_spawn_has_bounded_bootstrap_right() -> bool {
    let task = crate::backend::macos::current_task();
    let mut bootstrap = 0;
    // SAFETY: bootstrap points to writable storage for one copied special-port
    // right in this isolated child.
    if unsafe { task_get_special_port(task, TASK_BOOTSTRAP_PORT, &raw mut bootstrap) } != 0
        || bootstrap == 0
    {
        return false;
    }
    if bootstrap == MACH_PORT_DEAD {
        return true;
    }

    let mut port_type = 0;
    // SAFETY: bootstrap is live in this task and port_type is writable.
    let result = unsafe { mach_port_type(task, bootstrap, &raw mut port_type) };
    crate::backend::macos::deallocate_port(task, bootstrap);
    result == 0
        && port_type & MACH_PORT_TYPE_RECEIVE == 0
        && port_type & (MACH_PORT_TYPE_SEND | MACH_PORT_TYPE_DEAD_NAME) != 0
}

struct Fixture {
    child: Child,
    gate: Option<ActiveBrokerGate>,
    gate_writer: Option<OwnedFd>,
    trace_peer: Option<UnixStream>,
    launcher_readers: Option<(OwnedFd, OwnedFd)>,
    plan_frame: Vec<u8>,
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
            plan_frame: Vec::new(),
        }
    }

    /// Takes the plan-pipe reader end, which the fixture holds in place of the
    /// child, so a test can read back exactly what the broker delivered.
    fn take_plan_reader(&mut self) -> OwnedFd {
        let (death_reader, plan_reader) = self.launcher_readers.take().unwrap();
        self.launcher_readers = Some((death_reader, test_pipe().0));
        plan_reader
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
        // ends stay live here, standing in for the child that would hold them,
        // so plan delivery can be read back and verified byte for byte.
        let (death_reader, death_writer) = test_pipe();
        let (plan_reader, plan_writer) = test_pipe();
        self.launcher_readers = Some((death_reader, plan_reader));
        let channels =
            RetainedLauncherChannels::for_test(plan_writer, death_writer, self.plan_frame.clone());
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

    fn held_exec(&mut self) -> (c_int, SignatureVerifiedExecTrap) {
        self.held_exec_until(self.deadline())
    }

    fn held_exec_until(&mut self, deadline: Instant) -> (c_int, SignatureVerifiedExecTrap) {
        let (pid, held) = self.held_exec_unverified_until(deadline);
        // SAFETY: legacy launcher lifecycle tests isolate properties after the
        // new signature boundary. Dedicated tests above exercise the real
        // auth-worker accept/reject transition.
        (pid, unsafe { held.assume_signature_verified_for_test() })
    }

    fn held_exec_unverified(&mut self) -> (c_int, ExecTrapHeld) {
        self.held_exec_unverified_until(self.deadline())
    }

    fn held_exec_unverified_until(&mut self, deadline: Instant) -> (c_int, ExecTrapHeld) {
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
fn exec_trap_signature_gate_accepts_the_installed_target_identity() {
    let mut fixture = Fixture::spawn("valid-exec");
    let (pid, held) = fixture.held_exec_unverified();
    let expected_audit_identity = held._after_exec.audit_identity();
    let (mut pool, worker) = signature_worker_pool([4; 32], expected_audit_identity);

    let verified = held
        .verify_signature(&mut pool, signature_job_id(0x71))
        .unwrap();

    assert_eq!(verified.exact_pid_for_test(), pid);
    worker.join().unwrap();
    drop(verified);
    assert_no_reapable_status(pid);
    fixture.close_gate();
}

#[test]
fn exec_trap_signature_gate_rejects_zero_or_substituted_identity_and_exact_cleans() {
    for (job_byte, code_identity) in [(0x72, [0; 32]), (0x73, [9; 32])] {
        let mut fixture = Fixture::spawn("valid-exec");
        let (pid, held) = fixture.held_exec_unverified();
        let expected_audit_identity = held._after_exec.audit_identity();
        let (mut pool, worker) = signature_worker_pool(code_identity, expected_audit_identity);

        assert!(matches!(
            held.verify_signature(&mut pool, signature_job_id(job_byte)),
            Err(LauncherSignatureError::Auth(
                super::super::super::auth_adapter::AuthAdapterError::AuthenticationRejected
            ))
        ));

        worker.join().unwrap();
        assert_no_reapable_status(pid);
        fixture.close_gate();
    }
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
fn deliver_plan_writes_the_exact_frame_on_fd4_then_closes_for_eof() {
    let mut fixture = Fixture::spawn("valid-exec");
    // Larger than Darwin's pipe buffer, so a background reader must drain it
    // and the broker's nonblocking write actually exercises its poll path. The
    // pattern is distinctive so a byte-exact round trip is meaningful.
    let frame: Vec<u8> = (0..131_072_u32).map(|index| (index % 251) as u8).collect();
    fixture.plan_frame = frame.clone();

    let deadline = fixture.deadline();
    let launcher = fixture.spawned_launcher(deadline);
    let reader = fixture.take_plan_reader();
    // Drain the plan pipe from a second thread, as the launcher child would.
    let expected_len = frame.len();
    let drain = std::thread::spawn(move || {
        let mut received = Vec::new();
        let mut file = std::fs::File::from(reader);
        file.read_to_end(&mut received).unwrap();
        received
    });

    let initial = launcher.wait_initial_stop().unwrap();
    let mut awaiting = initial.prove_trace_and_continue_to_exec().unwrap();
    awaiting.deliver_plan().unwrap();

    let received = drain.join().unwrap();
    assert_eq!(received.len(), expected_len, "delivered length must match");
    assert_eq!(received, frame, "delivered bytes must match exactly");
    // read_to_end returned, so the writer was closed: the launcher's required
    // EOF terminator was produced.
    drop(awaiting);
    fixture.close_gate();
}

#[test]
fn deliver_plan_is_preempted_by_service_death() {
    let mut fixture = Fixture::spawn("valid-exec");
    fixture.plan_frame = vec![0x5a; 64];
    let deadline = fixture.deadline();
    let launcher = fixture.spawned_launcher(deadline);
    let _reader = fixture.take_plan_reader();
    let initial = launcher.wait_initial_stop().unwrap();
    let mut awaiting = initial.prove_trace_and_continue_to_exec().unwrap();
    // Service loss outranks handing a launcher the plan it would act on.
    fixture.close_gate();
    assert!(matches!(
        awaiting.deliver_plan(),
        Err(LauncherWaitError::ServiceGone),
    ));
}

#[test]
fn dropping_an_exact_launcher_drains_it_leaving_no_zombie() {
    // Darwin hands a traced child's terminal status to its tracer AND to its
    // parent, which are the same process here, so one exact wait observes the
    // death without consuming the child. Cleanup must drain the duplicate or a
    // zombie survives for the broker's whole life. No other test asserts
    // ECHILD, which is why this went unseen.
    let mut fixture = Fixture::spawn("valid-exec");
    let deadline = fixture.deadline();
    let (pid, held) = fixture.held_exec_until(deadline);
    drop(held);
    assert_no_reapable_status(pid);
    fixture.close_gate();
}

/// The exact child must be gone from the kernel, not merely observed dead.
fn assert_no_reapable_status(pid: c_int) {
    let mut status = 0;
    // SAFETY: status is writable and this fixture is the sole waiter for pid.
    let result = unsafe { waitpid(pid, &raw mut status, WNOHANG | WUNTRACED) };
    let error = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    assert!(
        result < 0 && error == ECHILD,
        "exact child {pid} still had a reapable status: waitpid returned \
         {result} (status 0x{status:04x}, errno {error}), so it is a zombie",
    );
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
