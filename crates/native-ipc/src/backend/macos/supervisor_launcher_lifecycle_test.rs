//! End-to-end Rust lifecycle proof, mirroring `docs/proofs/nipc_proof.c` but
//! driving the *real* Rust launcher entry rather than a hand-written mimic.
//!
//! The test binary is re-spawned as the launcher role, which runs
//! [`super::run_fixed_launcher_process`] verbatim. The broker role drives it
//! with the same public syscalls the C proof used: it proves the exact stopped
//! launcher's identity (audit token — exact PID, our own non-root uid — and the
//! code signature when a Developer ID identity is supplied), delivers the real
//! plan on FD4, observes the exec trap before the target runs, then terminates
//! the target exactly by its pinned PID and reaps until no zombie remains.
//!
//! The target is a minimal system binary rather than this test binary, and the
//! target's attack-resistance is proven separately (the C proof and the sandbox
//! unit test); this test's contribution is that the *real Rust entry* performs
//! the identity proof, plan delivery, exec trap, and exact reap end to end.
//!
//! Nothing here needs root. Bring your own certificate: set
//! `NATIVE_IPC_TEST_SIGN_IDENTITY` to add the signature check, or leave it unset
//! and the identity is proven by audit token alone.

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::io::Write;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use super::super::auth_adapter::broker_plan::ExactParentBrokerLaunchPlan;
use super::super::broker_entry::broker_launcher::{
    INSTALLED_LAUNCHER_DEATH_ARGUMENT, INSTALLED_LAUNCHER_MODE, INSTALLED_LAUNCHER_PLAN_ARGUMENT,
};

const IDENTITY_ENV: &str = "NATIVE_IPC_TEST_SIGN_IDENTITY";
const SUBJECT_IDENTIFIER: &str = "com.ro-ag.native-ipc.lifecycle-subject";
const DEPLOYER_LAUNCHER_PATH: &CStr =
    c"/example/NativeIPC.app/Contents/Helpers/native-ipc-launcher";

/// A real system binary is the target, not the test binary. Re-exec'ing the
/// heavy Rust/libtest runtime under the launcher's `(deny signal)` sandbox and
/// `RLIMIT_NPROC=1` fails during startup; a minimal image runs cleanly, exactly
/// as the C proof's target did. The target's job here is only to exist so the
/// broker can prove exact termination — attack resistance is proven separately
/// by the C proof and the sandbox unit test.
const TARGET_EXECUTABLE: &str = "/bin/sleep";
const TARGET_ARGUMENT: &str = "3600";

const DEATH_FD: c_int = 3;
const PLAN_FD: c_int = 4;

const PT_CONTINUE: c_int = 7;
const PT_KILL: c_int = 8;
const SIGKILL: c_int = 9;
const SIGSTOP: c_int = 17;
const SIGTRAP: c_int = 5;
const WUNTRACED: c_int = 2;
const WNOHANG: c_int = 1;
const ECHILD: c_int = 10;
const EINTR: c_int = 4;
const TASK_AUDIT_TOKEN: c_int = 15;

unsafe extern "C" {
    static mach_task_self_: u32;
    fn close(fd: c_int) -> c_int;
    fn dup2(source: c_int, destination: c_int) -> c_int;
    fn fcntl(fd: c_int, command: c_int, ...) -> c_int;
    fn getegid() -> u32;
    fn geteuid() -> u32;
    fn kill(pid: c_int, signal: c_int) -> c_int;
    fn pipe(fds: *mut c_int) -> c_int;
    fn ptrace(request: c_int, pid: c_int, address: *mut c_void, data: c_int) -> c_int;
    fn task_info(task: u32, flavor: c_int, info: *mut c_int, count: *mut u32) -> c_int;
    fn task_name_for_pid(task: u32, pid: c_int, port: *mut u32) -> c_int;
    fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int;
    fn _exit(status: c_int) -> !;
}

/// Before-main dispatcher. The launcher role must never enter libtest.
#[used]
#[unsafe(link_section = "__DATA,__mod_init_func")]
static LIFECYCLE_HOOK: extern "C" fn() = lifecycle_hook;

extern "C" fn lifecycle_hook() {
    let is_launcher = std::env::args_os()
        .next()
        .is_some_and(|value| value.as_bytes() == DEPLOYER_LAUNCHER_PATH.to_bytes());
    if is_launcher {
        // SAFETY: the broker role spawns this child with the exact fixed vector
        // and sole ownership of descriptors 3 and 4, satisfying the entry
        // contract. This is the real production launcher entry.
        unsafe { super::run_fixed_launcher_process(DEPLOYER_LAUNCHER_PATH) }
    }
    // Any other invocation is the ordinary libtest process; fall through.
}

/// Audit token of an exact stopped child: eight words via `TASK_AUDIT_TOKEN`.
fn audit_token(pid: c_int) -> Option<[u32; 8]> {
    let mut name = 0_u32;
    // SAFETY: name is writable; the caller owns this exact stopped child.
    if unsafe { task_name_for_pid(mach_task_self_, pid, &raw mut name) } != 0 {
        return None;
    }
    let mut values = [0_u32; 8];
    let mut count = 8_u32;
    // SAFETY: TASK_AUDIT_TOKEN writes exactly eight words into this storage.
    let result = unsafe {
        task_info(
            name,
            TASK_AUDIT_TOKEN,
            values.as_mut_ptr().cast(),
            &raw mut count,
        )
    };
    (result == 0 && count == 8).then_some(values)
}

fn token_pid(token: &[u32; 8]) -> c_int {
    token[5] as c_int
}
fn token_euid(token: &[u32; 8]) -> u32 {
    token[1]
}
fn token_pidversion(token: &[u32; 8]) -> u32 {
    token[7]
}

fn wait_for_stop(pid: c_int, expected_signal: c_int) {
    loop {
        let mut status = 0;
        // SAFETY: the broker is the sole waiter for this exact traced child.
        let result = unsafe { waitpid(pid, &raw mut status, WUNTRACED) };
        if result < 0 {
            if last_errno() == EINTR {
                continue;
            }
            panic!("waitpid failed while awaiting signal {expected_signal}");
        }
        assert_eq!(result, pid, "an unexpected child was reaped");
        assert!(
            is_stopped(status),
            "child did not stop; it exited with code {} (status {status:#06x})",
            (status >> 8) & 0xff,
        );
        assert_eq!(
            stop_signal(status),
            expected_signal,
            "child stopped on the wrong signal"
        );
        return;
    }
}

fn is_stopped(status: c_int) -> bool {
    status & 0xff == 0x7f
}
fn stop_signal(status: c_int) -> c_int {
    (status >> 8) & 0xff
}
fn terminal_is_signal(status: c_int) -> bool {
    let low = status & 0x7f;
    low != 0 && low != 0x7f
}

/// Reaps until the kernel reports the relation is gone, exactly as the fixed
/// drain does. Darwin double-reports a traced child's terminal status when the
/// tracer is also the parent, so the first terminal status is not the end.
fn drain_to_echild(pid: c_int) -> c_int {
    let mut terminal = 0;
    loop {
        let mut status = 0;
        // SAFETY: sole waiter for this exact child, whose death it has caused.
        let result = unsafe { waitpid(pid, &raw mut status, WUNTRACED) };
        if result == pid {
            if is_stopped(status) {
                // SAFETY: a tracee reports stops while dying; keep ending it.
                unsafe { ptrace(PT_KILL, pid, std::ptr::null_mut(), 0) };
                continue;
            }
            terminal = status;
            continue;
        }
        if result < 0 {
            let error = last_errno();
            if error == EINTR {
                continue;
            }
            if error == ECHILD {
                return terminal;
            }
        }
        panic!("waitpid returned an impossible result while draining {pid}");
    }
}

fn continue_tracee(pid: c_int) {
    // SAFETY: the broker holds this exact tracee at a stop; address 1 continues
    // at the current program counter on Darwin.
    let result = unsafe {
        ptrace(
            PT_CONTINUE,
            pid,
            std::ptr::without_provenance_mut::<c_void>(1),
            0,
        )
    };
    assert_eq!(result, 0, "PT_CONTINUE failed (errno {})", last_errno());
}

fn signing_identity() -> Option<String> {
    std::env::var(IDENTITY_ENV)
        .ok()
        .filter(|value| !value.is_empty())
}

fn team_of(identity: &str) -> String {
    identity
        .rsplit_once('(')
        .and_then(|(_, rest)| rest.split_once(')'))
        .map(|(team, _)| team.to_owned())
        .unwrap_or_else(|| panic!("no team OU in identity {identity:?}"))
}

/// A copy of this test binary, optionally Developer ID signed, used as both the
/// launcher image and the target it execs.
fn subject_image(identity: Option<&str>) -> std::path::PathBuf {
    let path = std::env::temp_dir().join("native-ipc-lifecycle-subject");
    let _ = std::fs::remove_file(&path);
    std::fs::copy(std::env::current_exe().unwrap(), &path).unwrap();
    if let Some(identity) = identity {
        let status = Command::new("/usr/bin/codesign")
            .args([
                "--force",
                "--options",
                "runtime",
                "--identifier",
                SUBJECT_IDENTIFIER,
                "--sign",
            ])
            .arg(identity)
            .arg(&path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success(), "codesign of the lifecycle subject failed");
    }
    path
}

type CfType = *const c_void;
type CfDataCreateFn = unsafe extern "C" fn(*const c_void, *const u8, isize) -> CfType;
type CfDictionaryCreateFn = unsafe extern "C" fn(
    *const c_void,
    *const *const c_void,
    *const *const c_void,
    isize,
    *const c_void,
    *const c_void,
) -> CfType;
type CfStringCreateFn = unsafe extern "C" fn(*const c_void, *const c_char, u32) -> CfType;
type CfReleaseFn = unsafe extern "C" fn(CfType);
type SecCopyGuestFn = unsafe extern "C" fn(CfType, CfType, u32, *mut CfType) -> i32;
type SecRequirementFn = unsafe extern "C" fn(CfType, u32, *mut CfType) -> i32;
type SecCheckValidityFn = unsafe extern "C" fn(CfType, u32, CfType) -> i32;

unsafe extern "C" {
    fn dlopen(path: *const c_char, mode: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}

/// Requires the live guest at the exact audit token to satisfy the requirement.
///
/// Security.framework is loaded with `dlopen` at call time rather than linked
/// statically. A static `#[link]` would run the framework's initializers in the
/// shared test binary for *every* test, which perturbs the Mach/bootstrap
/// environment the suspended-spawn and ptrace fixtures depend on and kills their
/// helper children. Loading on demand, only when a certificate is supplied,
/// keeps every other test's process image exactly as it was.
fn signature_satisfies(token: &[u32; 8], requirement: &str) -> Result<(), i32> {
    // SAFETY: fixed NUL-terminated system framework paths; RTLD_NOW|RTLD_LOCAL.
    let core = unsafe {
        dlopen(
            c"/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation".as_ptr(),
            0x2 | 0x4,
        )
    };
    // SAFETY: same fixed system framework path and eager local binding.
    let security = unsafe {
        dlopen(
            c"/System/Library/Frameworks/Security.framework/Security".as_ptr(),
            0x2 | 0x4,
        )
    };
    assert!(
        !core.is_null() && !security.is_null(),
        "loading Security.framework failed"
    );

    // SAFETY: every symbol below is the public SDK declaration for these fixed
    // framework versions, resolved from the just-loaded handles.
    unsafe {
        let sym = |handle: *mut c_void, name: &CStr| {
            let symbol = dlsym(handle, name.as_ptr());
            assert!(!symbol.is_null(), "missing framework symbol {name:?}");
            symbol
        };
        let cf_data_create: CfDataCreateFn = std::mem::transmute(sym(core, c"CFDataCreate"));
        let cf_dict_create: CfDictionaryCreateFn =
            std::mem::transmute(sym(core, c"CFDictionaryCreate"));
        let cf_string_create: CfStringCreateFn =
            std::mem::transmute(sym(core, c"CFStringCreateWithCString"));
        let cf_release: CfReleaseFn = std::mem::transmute(sym(core, c"CFRelease"));
        let key_callbacks = sym(core, c"kCFTypeDictionaryKeyCallBacks");
        let value_callbacks = sym(core, c"kCFTypeDictionaryValueCallBacks");
        let copy_guest: SecCopyGuestFn =
            std::mem::transmute(sym(security, c"SecCodeCopyGuestWithAttributes"));
        let create_requirement: SecRequirementFn =
            std::mem::transmute(sym(security, c"SecRequirementCreateWithString"));
        let check_validity: SecCheckValidityFn =
            std::mem::transmute(sym(security, c"SecCodeCheckValidity"));
        // The audit-guest key is an exported CFStringRef; dlsym yields the
        // address of that pointer, which is read to get the value.
        let audit_key = sym(security, c"kSecGuestAttributeAudit")
            .cast::<CfType>()
            .read();

        let data = cf_data_create(std::ptr::null(), token.as_ptr().cast(), 32);
        let keys = [audit_key];
        let values = [data];
        let attrs = cf_dict_create(
            std::ptr::null(),
            keys.as_ptr(),
            values.as_ptr(),
            1,
            key_callbacks,
            value_callbacks,
        );
        let mut guest: CfType = std::ptr::null();
        let status = copy_guest(std::ptr::null(), attrs, 0, &raw mut guest);
        cf_release(attrs);
        cf_release(data);
        if status != 0 {
            return Err(status);
        }

        let text = CString::new(requirement).unwrap();
        let cf_text = cf_string_create(std::ptr::null(), text.as_ptr(), 0x0800_0100);
        let mut req: CfType = std::ptr::null();
        let status = create_requirement(cf_text, 0, &raw mut req);
        cf_release(cf_text);
        if status != 0 {
            cf_release(guest);
            return Err(status);
        }

        let status = check_validity(guest, 0, req);
        cf_release(req);
        cf_release(guest);
        if status == 0 { Ok(()) } else { Err(status) }
    }
}

fn last_errno() -> c_int {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

/// Returns (reader, writer) for one anonymous pipe, both owned by the caller
/// and both close-on-exec.
///
/// CLOEXEC is essential: the launcher is spawned by fork+exec, so it inherits
/// every broker-held pipe end. If the broker's plan writer survived into the
/// launcher, the plan pipe would never reach EOF and the launcher would block
/// forever awaiting the frame terminator. Marking both ends here means the
/// inherited copies close on exec, and only the descriptors the child
/// deliberately `dup2`s onto 3/4/5 (which clears their CLOEXEC) survive.
fn pipe_pair() -> (OwnedFd, OwnedFd) {
    const F_SETFD: c_int = 2;
    const FD_CLOEXEC: c_int = 1;
    let mut fds = [-1; 2];
    // SAFETY: fds has storage for both descriptors.
    assert_eq!(unsafe { pipe(fds.as_mut_ptr()) }, 0, "pipe failed");
    for fd in fds {
        // SAFETY: fd is a live descriptor and F_SETFD accepts FD_CLOEXEC.
        assert_eq!(
            unsafe { fcntl(fd, F_SETFD, FD_CLOEXEC) },
            0,
            "set CLOEXEC failed"
        );
    }
    // SAFETY: the successful pipe returned two distinct owned descriptors.
    let reader = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    // SAFETY: the successful pipe returned two distinct owned descriptors.
    let writer = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    (reader, writer)
}

#[test]
// The spawned launcher is reaped through the exact ptrace/waitpid path, not the
// std Child handle, so std's own wait() is never called on it.
#[allow(clippy::zombie_processes)]
fn real_launcher_entry_proves_identity_contains_the_target_and_reaps_exactly() {
    // SAFETY: credential getters have no preconditions.
    let running_as_root = unsafe { geteuid() == 0 };
    assert!(
        !running_as_root,
        "the unprivileged lifecycle test must not run as root"
    );

    let identity = signing_identity();
    let subject = subject_image(identity.as_deref());
    let requirement = identity.as_ref().map(|identity| {
        format!(
            "anchor apple generic and identifier \"{SUBJECT_IDENTIFIER}\" \
             and certificate leaf[subject.OU] = \"{}\"",
            team_of(identity),
        )
    });

    // The real plan the launcher reads on FD4: it names a minimal system target
    // and carries our own credentials, since the launcher never changes
    // identity.
    let deadline = Instant::now() + Duration::from_secs(20);
    // SAFETY: credential getters have no preconditions.
    let plan = ExactParentBrokerLaunchPlan::for_launcher_test_with_arguments(
        deadline,
        unsafe { geteuid() },
        unsafe { getegid() },
        TARGET_EXECUTABLE.as_bytes().to_vec(),
        vec![b"sleep".to_vec(), TARGET_ARGUMENT.as_bytes().to_vec()],
    );
    let frame = plan
        .launcher_frame()
        .expect("the launcher frame must encode");

    let (death_reader, death_writer) = pipe_pair();
    let (plan_reader, plan_writer) = pipe_pair();

    let death_child_fd = death_reader.as_raw_fd();
    let plan_child_fd = plan_reader.as_raw_fd();
    let mut command = Command::new(&subject);
    command
        .arg0(std::ffi::OsStr::from_bytes(
            DEPLOYER_LAUNCHER_PATH.to_bytes(),
        ))
        .arg(INSTALLED_LAUNCHER_MODE)
        .arg(INSTALLED_LAUNCHER_DEATH_ARGUMENT)
        .arg(INSTALLED_LAUNCHER_PLAN_ARGUMENT)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    // SAFETY: only async-signal-safe fcntl/dup2/close before exec, installing
    // the fixed descriptors the launcher expects (3 death, 4 plan). Sources are
    // relocated above the destination range first (F_DUPFD, 10) so a pipe fd
    // that lands on 3/4 cannot clobber a source before it is placed, and the
    // temporaries are closed so only 3/4 survive exec.
    const F_DUPFD: c_int = 0;
    unsafe {
        command.pre_exec(move || {
            let d = fcntl(death_child_fd, F_DUPFD, 10);
            let p = fcntl(plan_child_fd, F_DUPFD, 10);
            if d < 10 || p < 10 {
                return Err(std::io::Error::last_os_error());
            }
            let placed = dup2(d, DEATH_FD) == DEATH_FD && dup2(p, PLAN_FD) == PLAN_FD;
            close(d);
            close(p);
            if placed {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    }
    let child = command.spawn().expect("spawning the real launcher failed");
    let pid = c_int::try_from(child.id()).unwrap();
    // The broker keeps its own ends: the death writer (its drop is the broker's
    // death signal) and the plan writer (FD4 delivery). The child owns the peers.
    drop(death_reader);
    drop(plan_reader);
    let mut plan_writer = std::fs::File::from(plan_writer);

    // 1. Identity, proven while the launcher is stopped and before it runs.
    wait_for_stop(pid, SIGSTOP);
    let before = audit_token(pid).expect("captured the stopped launcher's audit token");
    assert_eq!(token_pid(&before), pid, "audit token names this exact PID");
    // SAFETY: credential getters have no preconditions.
    assert_eq!(
        token_euid(&before),
        unsafe { geteuid() },
        "launcher carries our uid"
    );
    assert_ne!(token_euid(&before), 0, "launcher is not root");
    if let Some(requirement) = &requirement {
        signature_satisfies(&before, requirement)
            .expect("the stopped launcher must satisfy the designated requirement");
    }

    // 2. Continue, deliver the real plan on FD4, and observe the exec trap. The
    // frame carries its own length in its fixed header, so no outer length
    // prefix is written; closing the writer is the EOF terminator the launcher
    // requires.
    continue_tracee(pid);
    plan_writer.write_all(&frame).unwrap();
    drop(plan_writer);

    wait_for_stop(pid, SIGTRAP);
    let after = audit_token(pid).expect("captured the post-exec audit token");
    assert_eq!(token_pid(&after), pid, "same exact PID across exec");
    assert_ne!(
        token_pidversion(&after),
        token_pidversion(&before),
        "PID version must change, proving a real exec and not a counterfeit trap",
    );

    // 3. Continue the contained target, then terminate it exactly by its pinned
    // PID and reap until no zombie remains. The unreaped direct-child relation
    // pins the PID, so it cannot have been reused by anyone else.
    continue_tracee(pid);
    // SAFETY: the exact unreaped child pins this PID; it cannot be reused.
    assert_eq!(
        unsafe { kill(pid, SIGKILL) },
        0,
        "the exact child is signalled by PID"
    );
    let terminal = drain_to_echild(pid);
    assert!(
        terminal_is_signal(terminal),
        "target died by our exact signal"
    );
    // SAFETY: after ECHILD the relation is gone; a further wait must confirm it.
    let leftover = unsafe { waitpid(pid, std::ptr::null_mut(), WNOHANG) };
    assert!(
        leftover < 0 && last_errno() == ECHILD,
        "a zombie remained after cleanup"
    );

    drop(death_writer);
    let _ = std::fs::remove_file(&subject);
}
