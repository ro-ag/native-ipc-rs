use std::ffi::{CStr, c_char};
use std::fs::File;
use std::io::Write;
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};
use std::rc::Rc;
use std::thread;
use std::time::{Duration, Instant};

use super::*;
use crate::backend::macos::supervisor::auth_adapter::tests::{
    accepted_spawn_reply, installed_catalog,
};
use crate::backend::macos::supervisor_watchdog::{SessionHandle, WatchdogTable};

const EXIT_AFTER_START: &str = "IFS= read -r -n 1 <&3 || exit 71; exit 0";
const HOLD_UNTIL_EOF: &str = "IFS= read -r -n 1 <&3 || exit 71; IFS= read -r -n 1 <&3; exit 0";
const EXIT_IMMEDIATELY: &str = "exit 7";
const CHECK_FD_TOPOLOGY: &str =
    "IFS= read -r -n 1 <&3 || exit 71; if true <&100 2>/dev/null; then sleep 30; else exit 0; fi";
const PREMAIN_WAIT_DOMAIN_ENV: &[u8] = b"NATIVE_IPC_TEST_PREMAIN_WAIT_DOMAIN\0";

unsafe extern "C" {
    fn _exit(status: c_int) -> !;
    fn close(fd: c_int) -> c_int;
    fn dup2(source: c_int, destination: c_int) -> c_int;
    fn getenv(name: *const c_char) -> *mut c_char;
}

#[used]
#[unsafe(link_section = "__DATA,__mod_init_func")]
static PREMAIN_WAIT_DOMAIN_HOOK: extern "C" fn() = premain_wait_domain_hook;

extern "C" fn premain_wait_domain_hook() {
    // SAFETY: getenv reads one static NUL-terminated name before main. The
    // returned pointer, when nonnull, remains valid for this process lifetime.
    let mode = unsafe { getenv(PREMAIN_WAIT_DOMAIN_ENV.as_ptr().cast()) };
    if mode.is_null() {
        return;
    }
    // SAFETY: getenv returned one NUL-terminated environment value.
    let mode = unsafe { CStr::from_ptr(mode) }.to_bytes();
    if mode == b"ignored" || mode == b"no-cld-wait" {
        let action = super::super::DarwinSigaction {
            handler: usize::from(mode == b"ignored"),
            mask: 0,
            flags: if mode == b"no-cld-wait" {
                super::super::SA_NOCLDWAIT
            } else {
                0
            },
        };
        // SAFETY: the hook runs before main and supplies Darwin's public
        // sigaction layout while no other thread can observe the mutation.
        if unsafe {
            super::super::sigaction(
                super::super::SIGCHLD,
                &raw const action,
                std::ptr::null_mut(),
            )
        } != 0
        {
            // SAFETY: the pre-main harness cannot unwind through dyld.
            unsafe { _exit(90) }
        }
    }

    // SAFETY: this Mach-O initializer runs on the process main thread before
    // libtest or any other thread/child initialization.
    let established = unsafe { DedicatedChildWaitDomain::establish_at_service_startup() };
    let success = match mode {
        b"default" => match established {
            Ok(mut domain) => {
                let image = test_image(EXIT_AFTER_START);
                match spawn_fixed_image(&image, &mut domain) {
                    Ok(mut broker) => {
                        if broker
                            .authority_mut_for_test()
                            .activate_after_registration()
                            .is_err()
                        {
                            false
                        } else {
                            match broker
                                .authority_mut_for_test()
                                .terminate_and_reap(TerminationReason::ClientRequested)
                            {
                                Ok(proof) => {
                                    broker.mark_reaped_for_test(proof);
                                    true
                                }
                                Err(_) => false,
                            }
                        }
                    }
                    Err(_) => false,
                }
            }
            Err(_) => false,
        },
        b"ignored" => matches!(
            established,
            Err(super::super::ChildWaitDomainError::NonDefaultSigchld)
        ),
        b"no-cld-wait" => matches!(
            established,
            Err(super::super::ChildWaitDomainError::AutoReapEnabled)
        ),
        _ => false,
    };
    // SAFETY: exit without entering libtest; every successful default-path
    // broker was exact-reaped above, and hostile startup created no child.
    unsafe { _exit(if success { 0 } else { 91 }) }
}

fn test_image(script: &'static str) -> InstalledBrokerImage {
    InstalledBrokerImage {
        path: fixed_cstring("/bin/sh").unwrap(),
        mode: fixed_cstring("-c").unwrap(),
        gate_argument: fixed_cstring(script).unwrap(),
        environment_path: fixed_cstring(CANONICAL_PATH).unwrap(),
        environment_lang: fixed_cstring(CANONICAL_LANG).unwrap(),
        environment_locale: fixed_cstring(CANONICAL_LOCALE).unwrap(),
    }
}

fn test_wait_domain() -> DedicatedChildWaitDomain {
    DedicatedChildWaitDomain {
        _not_send_or_sync: std::marker::PhantomData::<Rc<()>>,
        bypass_spawn_recheck: true,
    }
}

fn assigned_pending(
    generation: u64,
    session_byte: u8,
) -> (
    PendingSpawnReply<SessionAssignedSpawn>,
    super::super::super::ConnectionIdentity,
    SessionHandle,
) {
    let (pending, owner) = accepted_spawn_reply(generation);
    let pending = pending
        .validate(&installed_catalog())
        .unwrap_or_else(|_| panic!("installed test policy rejected authenticated spawn"));
    let mut session_id = [session_byte; 32];
    session_id[..8].copy_from_slice(&generation.to_le_bytes());
    // SAFETY: this nonzero test session is unique in its local watchdog table.
    let session = unsafe { FreshSessionId::from_fresh_random(session_id).unwrap() };
    let handle = session.handle();
    (pending.assign_session(session), owner, handle)
}

fn pid(broker: &mut ExactBroker<DirectChildBrokerAuthority>) -> c_int {
    broker.authority_mut_for_test().pid
}

fn poll_exact_reap(authority: &mut DirectChildBrokerAuthority) -> ReapedBroker {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match authority.observe_exact_reap(WNOHANG) {
            Ok(Some(proof)) => return proof,
            Ok(None) | Err(BrokerSpawnError::Wait(EINTR)) => {
                assert!(
                    Instant::now() < deadline,
                    "broker did not exit before deadline"
                );
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) => panic!("exact wait failed: {error:?}"),
        }
    }
}

fn assert_exactly_reaped(pid: c_int) {
    let mut status = 0;
    // SAFETY: the exact authority must already have consumed this child.
    assert_eq!(unsafe { waitpid(pid, &raw mut status, WNOHANG) }, -1);
    assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(ECHILD));
}

#[test]
fn installed_image_vectors_are_fixed_and_canonical() {
    // SAFETY: this source-only test checks only the fixed in-memory vectors;
    // it does not claim the hard-coded path is installed, signed, or verified.
    let image = unsafe { InstalledBrokerImage::from_verified_installation() }.unwrap();
    let argv = image.argv();
    assert_eq!(image.path.to_bytes(), INSTALLED_BROKER_PATH.as_bytes());
    assert_eq!(argv[0], image.path.as_ptr().cast_mut());
    assert_eq!(image.mode.to_bytes(), INSTALLED_BROKER_MODE.as_bytes());
    assert_eq!(
        image.gate_argument.to_bytes(),
        INSTALLED_GATE_ARGUMENT.as_bytes()
    );
    assert!(argv[3].is_null());
    assert!(image.environment()[3].is_null());
}

#[test]
fn premain_wait_domain_accepts_default_and_rejects_hostile_sigchld() {
    for mode in ["default", "ignored", "no-cld-wait"] {
        let status = Command::new(std::env::current_exe().unwrap())
            .env("NATIVE_IPC_TEST_PREMAIN_WAIT_DOMAIN", mode)
            .status()
            .unwrap();
        assert!(status.success(), "pre-main wait-domain mode {mode} failed");
    }
}

#[test]
fn fixed_broker_cannot_cross_gate_before_activation() {
    let mut domain = test_wait_domain();
    let mut broker = spawn_fixed_image(&test_image(EXIT_AFTER_START), &mut domain).unwrap();
    thread::sleep(Duration::from_millis(20));
    assert!(matches!(
        broker.authority_mut_for_test().observe_exact_reap(WNOHANG),
        Ok(None)
    ));

    broker
        .authority_mut_for_test()
        .activate_after_registration()
        .unwrap();
    let proof = poll_exact_reap(broker.authority_mut_for_test());
    let child = pid(&mut broker);
    broker.mark_reaped_for_test(proof);
    drop(broker);
    assert_exactly_reaped(child);
}

#[test]
fn watchdog_registration_releases_only_each_exact_pending_broker() {
    let (first, _first_owner, _first_handle) = assigned_pending(4101, 0xa1);
    let (second, _second_owner, _second_handle) = assigned_pending(4102, 0xa2);
    let mut domain = test_wait_domain();
    let first = first
        .spawn_installed_broker(&test_image(EXIT_AFTER_START), &mut domain)
        .unwrap_or_else(|_| panic!("first fixed-image spawn failed"));
    let second = second
        .spawn_installed_broker(&test_image(EXIT_AFTER_START), &mut domain)
        .unwrap_or_else(|_| panic!("second fixed-image spawn failed"));

    // Both children have executed the fixed image but must still be blocked on
    // their distinct gates. A premature release would make later activation
    // fail with EPIPE after the short-lived test image exits.
    thread::sleep(Duration::from_millis(20));
    let mut table = WatchdogTable::new();
    let first = first
        .register_watchdog(&mut table)
        .unwrap_or_else(|_| panic!("first watchdog registration failed"));
    drop(first);
    thread::sleep(Duration::from_millis(20));
    let second = second
        .register_watchdog(&mut table)
        .unwrap_or_else(|_| panic!("second watchdog registration failed"));
    drop(second);
}

#[test]
fn dormant_abandonment_closes_gate_and_exactly_reaps() {
    let mut domain = test_wait_domain();
    let mut broker = spawn_fixed_image(&test_image(HOLD_UNTIL_EOF), &mut domain).unwrap();
    let child = pid(&mut broker);
    drop(broker);
    assert_exactly_reaped(child);
}

#[test]
fn active_termination_closes_gate_kills_and_exactly_reaps() {
    let mut domain = test_wait_domain();
    let mut broker = spawn_fixed_image(&test_image(HOLD_UNTIL_EOF), &mut domain).unwrap();
    let child = pid(&mut broker);
    broker
        .authority_mut_for_test()
        .activate_after_registration()
        .unwrap();
    let proof = broker
        .authority_mut_for_test()
        .terminate_and_reap(TerminationReason::ClientRequested)
        .unwrap();
    broker.mark_reaped_for_test(proof);
    drop(broker);
    assert_exactly_reaped(child);
}

#[test]
fn service_death_eof_exits_without_numeric_termination() {
    let mut domain = test_wait_domain();
    let mut broker = spawn_fixed_image(&test_image(HOLD_UNTIL_EOF), &mut domain).unwrap();
    let child = pid(&mut broker);
    broker
        .authority_mut_for_test()
        .activate_after_registration()
        .unwrap();
    broker.authority_mut_for_test().close_gate();
    let proof = poll_exact_reap(broker.authority_mut_for_test());
    broker.mark_reaped_for_test(proof);
    drop(broker);
    assert_exactly_reaped(child);
}

#[test]
fn abrupt_service_exit_closes_gate_while_exec_sibling_lives() {
    const MARKER: &str = "NATIVE_IPC_TEST_ABRUPT_BROKER_SERVICE_EXIT";
    const PREFIX: &str = "NATIVE_IPC_BROKER_SERVICE_PIDS ";
    if std::env::var_os(MARKER).is_some() {
        let mut domain = test_wait_domain();
        let mut broker = spawn_fixed_image(&test_image(HOLD_UNTIL_EOF), &mut domain).unwrap();
        let broker_pid = pid(&mut broker);
        broker
            .authority_mut_for_test()
            .activate_after_registration()
            .unwrap();
        let sibling = Command::new("/bin/sleep")
            .arg("1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        println!("{PREFIX}{broker_pid} {}", sibling.id());
        std::io::stdout().flush().unwrap();
        std::mem::forget(sibling);
        std::mem::forget(broker);
        // SAFETY: model abrupt installed-service death without Rust destructors.
        unsafe { _exit(0) }
    }

    let output = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("backend::macos::supervisor::auth_adapter::broker_spawn::tests::abrupt_service_exit_closes_gate_while_exec_sibling_lives")
        .arg("--nocapture")
        .env(MARKER, "1")
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    let line = stdout
        .lines()
        .find(|line| line.starts_with(PREFIX))
        .expect("service subprocess did not report child identities");
    let mut fields = line[PREFIX.len()..].split_whitespace();
    let broker_pid: c_int = fields.next().unwrap().parse().unwrap();
    let sibling_pid: c_int = fields.next().unwrap().parse().unwrap();
    assert!(fields.next().is_none());

    // SAFETY: signal zero is observational. The exec sibling must remain live
    // while the broker independently exits from service-death EOF.
    assert_eq!(unsafe { kill(sibling_pid, 0) }, 0);
    let broker_deadline = Instant::now() + Duration::from_millis(750);
    loop {
        // SAFETY: observational existence check only.
        if unsafe { kill(broker_pid, 0) } != 0 {
            assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(ESRCH));
            break;
        }
        assert!(
            Instant::now() < broker_deadline,
            "broker retained a gate writer"
        );
        assert_eq!(unsafe { kill(sibling_pid, 0) }, 0);
        thread::sleep(Duration::from_millis(5));
    }
    let sibling_deadline = Instant::now() + Duration::from_secs(2);
    while unsafe { kill(sibling_pid, 0) } == 0 {
        assert!(
            Instant::now() < sibling_deadline,
            "exec sibling survived its bound"
        );
        thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn immediate_exit_retains_zombie_pid_pin_until_exact_reap() {
    let mut domain = test_wait_domain();
    let mut broker = spawn_fixed_image(&test_image(EXIT_IMMEDIATELY), &mut domain).unwrap();
    let child = pid(&mut broker);
    thread::sleep(Duration::from_millis(20));
    // SAFETY: signal zero is a read-only existence check. An unreaped zombie
    // remains present and pins its PID until the exact wait below.
    assert_eq!(unsafe { kill(child, 0) }, 0);
    for _ in 0..32 {
        let mut churn = Command::new("/usr/bin/true").spawn().unwrap();
        assert_ne!(c_int::try_from(churn.id()).unwrap(), child);
        assert!(churn.wait().unwrap().success());
    }
    let proof = poll_exact_reap(broker.authority_mut_for_test());
    broker.mark_reaped_for_test(proof);
    drop(broker);
    assert_exactly_reaped(child);
}

#[test]
fn spawn_failure_mints_no_direct_child_authority() {
    let image = InstalledBrokerImage {
        path: fixed_cstring("/Library/PrivilegedHelperTools/.native-ipc-missing-broker").unwrap(),
        mode: fixed_cstring(INSTALLED_BROKER_MODE).unwrap(),
        gate_argument: fixed_cstring(INSTALLED_GATE_ARGUMENT).unwrap(),
        environment_path: fixed_cstring(CANONICAL_PATH).unwrap(),
        environment_lang: fixed_cstring(CANONICAL_LANG).unwrap(),
        environment_locale: fixed_cstring(CANONICAL_LOCALE).unwrap(),
    };
    assert!(matches!(
        spawn_fixed_image(&image, &mut test_wait_domain()),
        Err(BrokerSpawnError::Spawn(_))
    ));
}

#[test]
fn spawn_failure_preserves_exact_reply_and_bound_session_error_path() {
    let (pending, _owner, handle) = assigned_pending(4103, 0xa3);
    let mut domain = test_wait_domain();
    let missing = InstalledBrokerImage {
        path: fixed_cstring("/Library/PrivilegedHelperTools/.native-ipc-missing-broker").unwrap(),
        mode: fixed_cstring(INSTALLED_BROKER_MODE).unwrap(),
        gate_argument: fixed_cstring(INSTALLED_GATE_ARGUMENT).unwrap(),
        environment_path: fixed_cstring(CANONICAL_PATH).unwrap(),
        environment_lang: fixed_cstring(CANONICAL_LANG).unwrap(),
        environment_locale: fixed_cstring(CANONICAL_LOCALE).unwrap(),
    };
    let error = match pending.spawn_installed_broker(&missing, &mut domain) {
        Ok(_) => panic!("missing fixed image minted child authority"),
        Err(error) => error,
    };
    let (_reply, _freshness, bound_session, error) = error.into_parts();
    assert_eq!(bound_session, Some(handle));
    assert!(matches!(error, BrokerSpawnError::Spawn(_)));
}

#[test]
fn gate_pipe_sources_are_collision_safe_cloexec_and_nonblocking() {
    const F_GETFD: c_int = 1;
    let (reader, writer) = create_gate_pipe().unwrap();
    assert!(reader.as_raw_fd() >= STABLE_FD_MINIMUM);
    assert!(writer.as_raw_fd() >= STABLE_FD_MINIMUM);
    assert_ne!(reader.as_raw_fd(), writer.as_raw_fd());
    // SAFETY: both descriptors are live and the queries have no side effects.
    assert_ne!(
        unsafe { fcntl(reader.as_raw_fd(), F_GETFD) } & FD_CLOEXEC,
        0
    );
    // SAFETY: same live descriptor query.
    assert_ne!(
        unsafe { fcntl(writer.as_raw_fd(), F_GETFD) } & FD_CLOEXEC,
        0
    );
    // SAFETY: same live descriptor query.
    assert_ne!(
        unsafe { fcntl(writer.as_raw_fd(), F_GETFL) } & O_NONBLOCK,
        0
    );
}

#[test]
fn fixed_gate_fd_collision_and_child_inheritance_are_exact() {
    const MARKER: &str = "NATIVE_IPC_TEST_BROKER_FD_TOPOLOGY";
    if std::env::var_os(MARKER).is_some() {
        let sentinel = File::open("/dev/null").unwrap();
        // SAFETY: install one deliberately inheritable non-gate sentinel at a
        // fixed high fd, then free fd 3 so pipe creation exercises collision.
        assert_eq!(unsafe { dup2(sentinel.as_raw_fd(), 100) }, 100);
        assert_eq!(unsafe { fcntl(100, F_SETFD, 0) }, 0);
        drop(sentinel);
        let _ = unsafe { close(BROKER_GATE_FD) };
        let mut domain = test_wait_domain();
        let mut broker = spawn_fixed_image(&test_image(CHECK_FD_TOPOLOGY), &mut domain).unwrap();
        broker
            .authority_mut_for_test()
            .activate_after_registration()
            .unwrap();
        let proof = poll_exact_reap(broker.authority_mut_for_test());
        broker.mark_reaped_for_test(proof);
        return;
    }

    let status = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("backend::macos::supervisor::auth_adapter::broker_spawn::tests::fixed_gate_fd_collision_and_child_inheritance_are_exact")
        .arg("--nocapture")
        .env(MARKER, "1")
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
fn stolen_wait_fails_stop_before_any_numeric_signal() {
    const CHILD_MARKER: &str = "NATIVE_IPC_TEST_BROKER_ECHILD_ABORT";
    if std::env::var_os(CHILD_MARKER).is_some() {
        let mut domain = test_wait_domain();
        let mut broker = spawn_fixed_image(&test_image(EXIT_IMMEDIATELY), &mut domain).unwrap();
        let child = pid(&mut broker);
        let mut status = 0;
        loop {
            // SAFETY: intentionally steal the exact wait relation so armed
            // cleanup must discover ECHILD and abort before calling kill.
            let result = unsafe { waitpid(child, &raw mut status, 0) };
            if result == child {
                break;
            }
            assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(EINTR));
        }
        drop(broker);
        panic!("ECHILD must fail-stop before returning");
    }

    let status = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("backend::macos::supervisor::auth_adapter::broker_spawn::tests::stolen_wait_fails_stop_before_any_numeric_signal")
        .arg("--nocapture")
        .env(CHILD_MARKER, "1")
        .status()
        .unwrap();
    assert_eq!(status.signal(), Some(6));
}

#[test]
fn repeated_cleanup_never_affects_unrelated_child() {
    let mut sentinel = Command::new("/bin/sleep").arg("30").spawn().unwrap();
    let sentinel_pid = c_int::try_from(sentinel.id()).unwrap();
    for _ in 0..50 {
        let mut domain = test_wait_domain();
        let mut broker = spawn_fixed_image(&test_image(EXIT_AFTER_START), &mut domain).unwrap();
        broker
            .authority_mut_for_test()
            .activate_after_registration()
            .unwrap();
        let proof = broker
            .authority_mut_for_test()
            .terminate_and_reap(TerminationReason::ClientRequested)
            .unwrap();
        broker.mark_reaped_for_test(proof);
        drop(broker);
        // SAFETY: signal zero cannot mutate the unrelated sentinel.
        assert_eq!(unsafe { kill(sentinel_pid, 0) }, 0);
    }
    sentinel.kill().unwrap();
    let status = sentinel.wait().unwrap();
    assert_eq!(status.signal(), Some(SIGKILL));
}
