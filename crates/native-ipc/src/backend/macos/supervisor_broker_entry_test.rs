use std::ffi::{CStr, CString, OsStr, OsString, c_int, c_long};
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::Shutdown;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::os::unix::process::CommandExt;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

use static_assertions::assert_not_impl_any;

use super::*;

const HELPER_ENV: &str = "NATIVE_IPC_TEST_BROKER_GATE_ENTRY";
const EXACT_TEST: &str =
    "backend::macos::supervisor::broker_entry::tests::fixed_gate_entry_subprocess";
const DEPLOYER_BROKER_PATH: &CStr = c"/example/NativeIPC.app/Contents/Helpers/native-ipc-broker";
const PRODUCTION_BROKER_FIXTURE_SUFFIX: &str = ".native-ipc-production-broker-fixture";
const PRODUCTION_CODE_IDENTITY: [u8; 32] = [0x5a; 32];
const BROKER_TRACE_REPORT_BYTES: usize = 224;
const F_DUPFD_CLOEXEC: c_int = 67;

#[repr(C)]
struct TimeSpec {
    tv_sec: c_long,
    tv_nsec: c_long,
}

unsafe extern "C" {
    fn clock_gettime(clock_id: c_int, time: *mut TimeSpec) -> c_int;
    fn close(fd: c_int) -> c_int;
    fn dup2(source: c_int, destination: c_int) -> c_int;
    fn getegid() -> u32;
    fn getdtablesize() -> c_int;
    fn geteuid() -> u32;
    fn pipe(descriptors: *mut c_int) -> c_int;
}

assert_not_impl_any!(DormantBrokerGate: Clone, Copy);
assert_not_impl_any!(ActiveBrokerGate: Clone, Copy);

#[used]
#[unsafe(link_section = "__DATA,__mod_init_func")]
static PRODUCTION_BROKER_PROCESS_HOOK: extern "C" fn() = production_broker_process_hook;

extern "C" fn production_broker_process_hook() {
    let mut arguments = std::env::args_os();
    let Some(argument0) = arguments.next() else {
        return;
    };
    if !argument0
        .as_bytes()
        .ends_with(PRODUCTION_BROKER_FIXTURE_SUFFIX.as_bytes())
    {
        return;
    }
    let Some(mode) = arguments.next() else {
        return;
    };
    let installed = CString::new(argument0.as_bytes()).unwrap_or_else(|_| {
        // SAFETY: the isolated fixture cannot satisfy any fixed entry ABI.
        unsafe { super::_exit(106) }
    });
    match mode.as_bytes() {
        b"--supervisor-broker" => {
            // SAFETY: the sibling fixture installed the exact broker vector,
            // descriptors 3 through 5, and one copied absolute helper image.
            unsafe { super::run_fixed_broker_process(&installed, &installed, &installed) }
        }
        b"--supervisor-auth-worker" => {
            // SAFETY: the production broker installed the exact fixed worker
            // vector and sole FD3/FD4 ends. `always` is test-only; production
            // artifacts compile their designated signing requirement here.
            unsafe {
                super::super::auth_adapter::auth_worker_entry::run_fixed_auth_worker_process(
                    &installed,
                    c"always",
                    PRODUCTION_CODE_IDENTITY,
                )
            }
        }
        _ => {}
    }
}

#[test]
fn post_report_gate_eof_wins_before_reported_authority() {
    let mut descriptors = [-1; 2];
    // SAFETY: descriptors has storage for the two pipe descriptors.
    assert_eq!(unsafe { pipe(descriptors.as_mut_ptr()) }, 0);
    // SAFETY: successful pipe returned two distinct owned descriptors.
    let reader = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
    // SAFETY: successful pipe returned two distinct owned descriptors.
    let writer = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
    set_nonblocking(reader.as_raw_fd(), true).unwrap();
    let (trace, _service) = UnixStream::pair().unwrap();

    drop(writer);
    assert_eq!(
        finish_trace_report_before_authority(&trace, reader.as_raw_fd()),
        Ok(Some(BrokerGateExit::ServiceGone))
    );
}

#[test]
fn post_resume_eof_gate_eof_wins_before_resumed_authority() {
    let mut descriptors = [-1; 2];
    // SAFETY: descriptors has storage for the two pipe descriptors.
    assert_eq!(unsafe { pipe(descriptors.as_mut_ptr()) }, 0);
    // SAFETY: successful pipe returned two distinct owned descriptors.
    let reader = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
    // SAFETY: successful pipe returned two distinct owned descriptors.
    let writer = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
    set_nonblocking(reader.as_raw_fd(), true).unwrap();

    drop(writer);
    assert_eq!(
        final_resume_gate_probe(reader.as_raw_fd()),
        Ok(Some(BrokerGateExit::ServiceGone))
    );
}

fn spawn_helper(mode: &str) -> Child {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .arg("--exact")
        .arg(EXACT_TEST)
        .arg("--nocapture")
        .env(HELPER_ENV, mode)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: this closure runs after fork and before exec. It performs only
    // async-signal-safe dup2, making the command's private stdin pipe reader
    // available at the fixed broker descriptor.
    unsafe {
        command.pre_exec(|| {
            if dup2(0, BROKER_GATE_FD) == BROKER_GATE_FD {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    }
    command.spawn().unwrap()
}

fn finish(mut child: Child) -> std::process::Output {
    drop(child.stdin.take());
    child.wait_with_output().unwrap()
}

struct FixtureImage(std::path::PathBuf);

impl Drop for FixtureImage {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

struct ProductionBroker {
    child: Child,
    control: UnixStream,
    trace: UnixStream,
    _image: FixtureImage,
}

fn production_fixture_image(tag: &str) -> FixtureImage {
    let path = std::env::temp_dir().join(format!(
        "native-ipc-{tag}-{}{}",
        std::process::id(),
        PRODUCTION_BROKER_FIXTURE_SUFFIX,
    ));
    let _ = std::fs::remove_file(&path);
    std::fs::copy(std::env::current_exe().unwrap(), &path).unwrap();
    FixtureImage(std::fs::canonicalize(path).unwrap())
}

fn spawn_production_broker(tag: &str) -> ProductionBroker {
    let image = production_fixture_image(tag);
    let (control, child_control) = UnixStream::pair().unwrap();
    let (trace, child_trace) = UnixStream::pair().unwrap();
    // SAFETY: both live child ends are collision-safely duplicated above the
    // fixed ABI; successful results are fresh owned descriptors.
    let control_fd = unsafe { fcntl(child_control.as_raw_fd(), F_DUPFD_CLOEXEC, 10) };
    assert!(control_fd >= 10);
    // SAFETY: successful fcntl returned one fresh owned descriptor.
    let control_fd = unsafe { OwnedFd::from_raw_fd(control_fd) };
    // SAFETY: same exact duplication for the trace channel.
    let trace_fd = unsafe { fcntl(child_trace.as_raw_fd(), F_DUPFD_CLOEXEC, 10) };
    assert!(trace_fd >= 10);
    // SAFETY: successful fcntl returned one fresh owned descriptor.
    let trace_fd = unsafe { OwnedFd::from_raw_fd(trace_fd) };
    let child_control_fd = control_fd.as_raw_fd();
    let child_trace_fd = trace_fd.as_raw_fd();
    // SAFETY: read-only process limit query before the child is created.
    let descriptor_limit = unsafe { getdtablesize() };
    assert!(descriptor_limit > BROKER_TRACE_FD);

    let mut command = Command::new(&image.0);
    command
        .arg0(&image.0)
        .arg(INSTALLED_BROKER_MODE)
        .arg(INSTALLED_GATE_ARGUMENT)
        .arg(INSTALLED_CONTROL_ARGUMENT)
        .arg(INSTALLED_TRACE_ARGUMENT)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    // SAFETY: the isolated just-forked child performs only async-signal-safe
    // dup2 calls before exec and transfers fixed FD3/FD4/FD5 ownership.
    unsafe {
        command.pre_exec(move || {
            if dup2(0, BROKER_GATE_FD) == BROKER_GATE_FD
                && dup2(child_control_fd, BROKER_CONTROL_FD) == BROKER_CONTROL_FD
                && dup2(child_trace_fd, BROKER_TRACE_FD) == BROKER_TRACE_FD
            {
                // SAFETY: fixed descriptors 0 through 5 are now complete;
                // close is async-signal-safe and prevents cross-test ownership
                // of any other live pipe in this inherited descriptor table.
                for fd in (BROKER_TRACE_FD + 1)..descriptor_limit {
                    let _ = close(fd);
                }
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    }
    let child = command.spawn().unwrap();
    drop(control_fd);
    drop(trace_fd);
    drop(child_control);
    drop(child_trace);
    ProductionBroker {
        child,
        control,
        trace,
        _image: image,
    }
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn production_plan_frame(target_identity: [u8; 32]) -> Vec<u8> {
    const TARGET: &[u8] = b"/usr/bin/true";
    const ARGUMENT: &[u8] = b"true";
    const POLICY: &[u8] = b"test.production-caller";
    let mut now = TimeSpec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: now is writable and CLOCK_UPTIME_RAW is Darwin clock 8.
    assert_eq!(unsafe { clock_gettime(8, &raw mut now) }, 0);
    let deadline = u64::try_from(now.tv_sec).unwrap() * 1_000_000_000
        + u64::try_from(now.tv_nsec).unwrap()
        + 20_000_000_000;
    // SAFETY: credential getters have no preconditions and the fixed broker
    // and target must remain same-user and unprivileged.
    let effective_uid = unsafe { geteuid() };
    // SAFETY: same current-process credential snapshot.
    let effective_gid = unsafe { getegid() };
    assert_ne!(
        effective_uid, 0,
        "the macOS broker fixture must not run as root"
    );
    assert_ne!(
        effective_gid, 0,
        "the macOS broker fixture needs a nonroot group"
    );

    let mut bytes = vec![0_u8; 256];
    bytes[..8].copy_from_slice(b"NIPCBP01");
    put_u16(&mut bytes, 8, 1);
    put_u64(&mut bytes, 16, deadline);
    put_u64(&mut bytes, 24, 1);
    put_u64(&mut bytes, 32, 1);
    put_u32(&mut bytes, 40, effective_uid);
    put_u32(&mut bytes, 44, effective_gid);
    for (range, value) in [
        (48..80, 1),
        (80..112, 2),
        (112..144, 3),
        (176..208, 5),
        (208..240, 6),
    ] {
        bytes[range].fill(value);
    }
    bytes[144..176].copy_from_slice(&target_identity);
    put_u32(&mut bytes, 240, u32::try_from(POLICY.len()).unwrap());
    put_u32(&mut bytes, 244, u32::try_from(TARGET.len()).unwrap());
    put_u16(&mut bytes, 248, 1);
    bytes.extend_from_slice(POLICY);
    bytes.extend_from_slice(TARGET);
    bytes.extend_from_slice(&u32::try_from(ARGUMENT.len()).unwrap().to_le_bytes());
    bytes.extend_from_slice(ARGUMENT);
    let frame_len = u32::try_from(bytes.len()).unwrap();
    put_u32(&mut bytes, 12, frame_len);
    bytes
}

fn stage_production_plan(broker: &mut ProductionBroker, frame: &[u8]) -> [u8; 40] {
    broker
        .control
        .write_all(&u32::try_from(frame.len()).unwrap().to_le_bytes())
        .unwrap();
    broker.control.write_all(frame).unwrap();
    broker.control.shutdown(Shutdown::Write).unwrap();
    let mut ack = [0_u8; 40];
    broker.control.read_exact(&mut ack).unwrap();
    assert_eq!(&ack[..8], b"NIPCBPA1");
    ack
}

fn wait_with_gate_live(broker: &mut ProductionBroker) -> (std::process::ExitStatus, Vec<u8>) {
    let status = broker.child.wait().unwrap();
    let mut stderr = Vec::new();
    broker
        .child
        .stderr
        .as_mut()
        .unwrap()
        .read_to_end(&mut stderr)
        .unwrap();
    drop(broker.child.stdin.take());
    (status, stderr)
}

#[test]
fn production_broker_caller_drives_launcher_plan_signature_report_resume_and_exact_exit() {
    let mut broker = spawn_production_broker("accept");
    let frame = production_plan_frame(PRODUCTION_CODE_IDENTITY);
    let ack = stage_production_plan(&mut broker, &frame);
    broker
        .child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(&START_BYTE)
        .unwrap();

    let mut report = [0_u8; BROKER_TRACE_REPORT_BYTES];
    if let Err(error) = broker.trace.read_exact(&mut report) {
        let (status, stderr) = wait_with_gate_live(&mut broker);
        panic!(
            "broker closed trace before report: {error:?}, status {status:?}, stderr {stderr:?}"
        );
    }
    let mut extra = [0_u8; 1];
    assert_eq!(broker.trace.read(&mut extra).unwrap(), 0);
    assert_eq!(&report[..8], b"NIPCBTR1");
    assert_eq!(u16::from_le_bytes(report[10..12].try_into().unwrap()), 2);
    assert_eq!(&report[144..176], &PRODUCTION_CODE_IDENTITY);
    assert_eq!(&report[176..208], &ack[8..]);

    broker.trace.write_all(&[1]).unwrap();
    broker.trace.shutdown(Shutdown::Write).unwrap();
    let (status, stderr) = wait_with_gate_live(&mut broker);
    assert!(status.success(), "broker status {status:?}: {stderr:?}");
}

#[test]
fn production_broker_caller_rejects_substituted_worker_identity_before_report_or_resume() {
    let mut broker = spawn_production_broker("reject");
    let frame = production_plan_frame([0x6b; 32]);
    stage_production_plan(&mut broker, &frame);
    broker
        .child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(&START_BYTE)
        .unwrap();

    let mut report = Vec::new();
    broker.trace.read_to_end(&mut report).unwrap();
    let (status, stderr) = wait_with_gate_live(&mut broker);
    assert_eq!(status.code(), Some(67), "broker stderr: {stderr:?}");
    assert!(report.is_empty(), "rejected target emitted trace authority");
}

#[test]
fn fixed_arguments_accept_only_the_installed_vector() {
    let exact = [
        OsStr::from_bytes(DEPLOYER_BROKER_PATH.to_bytes()),
        OsStr::new(INSTALLED_BROKER_MODE),
        OsStr::new(INSTALLED_GATE_ARGUMENT),
        OsStr::new(INSTALLED_CONTROL_ARGUMENT),
        OsStr::new(INSTALLED_TRACE_ARGUMENT),
    ];
    assert_eq!(
        validate_fixed_arguments(DEPLOYER_BROKER_PATH, exact),
        Ok(())
    );

    let mutations = [
        vec![
            OsString::from("relative-broker"),
            OsString::from(INSTALLED_BROKER_MODE),
            OsString::from(INSTALLED_GATE_ARGUMENT),
            OsString::from(INSTALLED_CONTROL_ARGUMENT),
            OsString::from(INSTALLED_TRACE_ARGUMENT),
        ],
        vec![
            OsString::from(OsStr::from_bytes(DEPLOYER_BROKER_PATH.to_bytes())),
            OsString::from("--other-mode"),
            OsString::from(INSTALLED_GATE_ARGUMENT),
            OsString::from(INSTALLED_CONTROL_ARGUMENT),
            OsString::from(INSTALLED_TRACE_ARGUMENT),
        ],
        vec![
            OsString::from(OsStr::from_bytes(DEPLOYER_BROKER_PATH.to_bytes())),
            OsString::from(INSTALLED_BROKER_MODE),
            OsString::from("--gate-fd=4"),
            OsString::from(INSTALLED_CONTROL_ARGUMENT),
            OsString::from(INSTALLED_TRACE_ARGUMENT),
        ],
        vec![
            OsString::from(OsStr::from_bytes(DEPLOYER_BROKER_PATH.to_bytes())),
            OsString::from(INSTALLED_BROKER_MODE),
            OsString::from(INSTALLED_GATE_ARGUMENT),
            OsString::from(INSTALLED_CONTROL_ARGUMENT),
        ],
        vec![
            OsString::from(OsStr::from_bytes(DEPLOYER_BROKER_PATH.to_bytes())),
            OsString::from(INSTALLED_BROKER_MODE),
            OsString::from(INSTALLED_GATE_ARGUMENT),
            OsString::from(INSTALLED_CONTROL_ARGUMENT),
            OsString::from(INSTALLED_TRACE_ARGUMENT),
            OsString::from("extra"),
        ],
    ];
    for mutation in mutations {
        assert_eq!(
            validate_fixed_arguments(DEPLOYER_BROKER_PATH, mutation),
            Err(BrokerEntryError::InvalidArguments)
        );
    }

    let substituted_path = [
        OsStr::new("/other/NativeIPC.app/Contents/Helpers/native-ipc-broker"),
        OsStr::new(INSTALLED_BROKER_MODE),
        OsStr::new(INSTALLED_GATE_ARGUMENT),
        OsStr::new(INSTALLED_CONTROL_ARGUMENT),
        OsStr::new(INSTALLED_TRACE_ARGUMENT),
    ];
    assert_eq!(
        validate_fixed_arguments(DEPLOYER_BROKER_PATH, substituted_path),
        Err(BrokerEntryError::InvalidArguments)
    );

    let relative_configuration = [
        OsStr::new("relative-broker"),
        OsStr::new(INSTALLED_BROKER_MODE),
        OsStr::new(INSTALLED_GATE_ARGUMENT),
        OsStr::new(INSTALLED_CONTROL_ARGUMENT),
        OsStr::new(INSTALLED_TRACE_ARGUMENT),
    ];
    assert_eq!(
        validate_fixed_arguments(c"relative-broker", relative_configuration),
        Err(BrokerEntryError::InvalidArguments)
    );
}

#[test]
fn fixed_gate_entry_subprocess() {
    let Ok(mode) = std::env::var(HELPER_ENV) else {
        return;
    };
    if mode == "regular-file" {
        let null = File::open("/dev/null").unwrap();
        // SAFETY: replace the inherited test gate with a live read-only regular
        // file, then transfer descriptor 3 to the entrypoint exactly once.
        assert_eq!(
            unsafe { dup2(null.as_raw_fd(), BROKER_GATE_FD) },
            BROKER_GATE_FD
        );
    }

    // SAFETY: the subprocess pre-exec hook installed one private descriptor 3
    // with no Rust owner. This helper calls no broker operation before adoption.
    let dormant = unsafe { DormantBrokerGate::adopt_fixed_gate() };
    if mode == "regular-file" {
        assert!(matches!(dormant, Err(BrokerEntryError::InvalidGate)));
        return;
    }
    let dormant = dormant.unwrap();
    match dormant.wait_for_activation() {
        Ok(Err(BrokerGateExit::ServiceGoneBeforeActivation)) => {
            assert_eq!(mode, "eof-before-start");
        }
        Ok(Err(BrokerGateExit::ServiceGone)) => {
            assert_eq!(mode, "start-then-eof");
        }
        Ok(Ok(active)) => {
            assert_eq!(mode, "active");
            // SAFETY: the live adopted descriptor accepts this read-only flag
            // query and must have been made close-on-exec by the entrypoint.
            assert_ne!(
                unsafe { fcntl(active.descriptor(), F_GETFD) } & FD_CLOEXEC,
                0
            );
            println!("NATIVE_IPC_GATE_ACTIVE");
            std::io::stdout().flush().unwrap();
            assert_eq!(
                active.wait_for_service_death(),
                Ok(BrokerGateExit::ServiceGone)
            );
        }
        Err(BrokerEntryError::InvalidActivation) => {
            assert!(mode == "wrong-byte" || mode == "multiple-bytes");
        }
        other => panic!("unexpected gate result for {mode}: {other:?}"),
    }
}

#[test]
fn eof_before_start_performs_no_activation() {
    let child = spawn_helper("eof-before-start");
    let output = finish(child);
    assert!(output.status.success(), "{:?}", output.stderr);
    assert!(
        !String::from_utf8(output.stdout)
            .unwrap()
            .contains("NATIVE_IPC_GATE_ACTIVE")
    );
}

#[test]
fn wrong_and_multiple_activation_bytes_fail_closed() {
    for (mode, bytes) in [("wrong-byte", vec![0xff]), ("multiple-bytes", vec![1, 1])] {
        let mut child = spawn_helper(mode);
        child.stdin.as_mut().unwrap().write_all(&bytes).unwrap();
        let output = finish(child);
        assert!(output.status.success(), "{mode}: {:?}", output.stderr);
        assert!(
            !String::from_utf8(output.stdout)
                .unwrap()
                .contains("NATIVE_IPC_GATE_ACTIVE")
        );
    }
}

#[test]
fn start_then_immediate_service_death_never_returns_active_authority() {
    let mut child = spawn_helper("start-then-eof");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(&START_BYTE)
        .unwrap();
    let output = finish(child);
    assert!(output.status.success(), "{:?}", output.stderr);
    assert!(
        !String::from_utf8(output.stdout)
            .unwrap()
            .contains("NATIVE_IPC_GATE_ACTIVE")
    );
}

#[test]
fn exact_start_activates_once_and_retains_service_death_reader() {
    let mut child = spawn_helper("active");
    thread::sleep(Duration::from_millis(20));
    assert!(child.try_wait().unwrap().is_none());
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(&START_BYTE)
        .unwrap();
    thread::sleep(Duration::from_millis(20));
    assert!(child.try_wait().unwrap().is_none());
    let output = finish(child);
    assert!(output.status.success(), "{:?}", output.stderr);
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .contains("NATIVE_IPC_GATE_ACTIVE")
    );
}

#[test]
fn regular_file_cannot_substitute_for_the_gate_pipe() {
    let child = spawn_helper("regular-file");
    let output = finish(child);
    assert!(output.status.success(), "{:?}", output.stderr);
}

#[test]
fn service_data_after_activation_is_terminal_protocol_failure() {
    const EXTRA_MODE: &str = "active-extra";
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .arg("--exact")
        .arg(EXACT_TEST)
        .arg("--nocapture")
        .env(HELPER_ENV, "active")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: same isolated fixed-fd installation as spawn_helper.
    unsafe {
        command.pre_exec(|| {
            if dup2(0, BROKER_GATE_FD) == BROKER_GATE_FD {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    }
    let mut child = command.spawn().unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(&START_BYTE)
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let (sender, receiver) = std::sync::mpsc::channel();
    let reader = thread::spawn(move || {
        let mut sender = Some(sender);
        for line in BufReader::new(stdout).lines() {
            let line = line.unwrap();
            if line == "NATIVE_IPC_GATE_ACTIVE"
                && let Some(sender) = sender.take()
            {
                sender.send(line).unwrap();
            }
        }
        if let Some(sender) = sender {
            sender.send(String::new()).unwrap();
        }
    });
    assert_eq!(
        receiver.recv_timeout(Duration::from_secs(2)).unwrap(),
        "NATIVE_IPC_GATE_ACTIVE"
    );
    child.stdin.as_mut().unwrap().write_all(&[2]).unwrap();
    drop(child.stdin.take());
    let status = child.wait().unwrap();
    reader.join().unwrap();
    assert!(!status.success(), "{EXTRA_MODE} unexpectedly succeeded");
}

#[test]
fn closed_descriptor_is_rejected_without_ownership_construction() {
    const CLOSED_ENV: &str = "NATIVE_IPC_TEST_BROKER_GATE_CLOSED";
    if std::env::var_os(CLOSED_ENV).is_some() {
        // SAFETY: deliberately close the fixed descriptor before adoption.
        let _ = unsafe { close(BROKER_GATE_FD) };
        // SAFETY: the constructor validates liveness before FromRawFd.
        assert!(matches!(
            unsafe { DormantBrokerGate::adopt_fixed_gate() },
            Err(BrokerEntryError::InvalidGate)
        ));
        return;
    }
    let status = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("backend::macos::supervisor::broker_entry::tests::closed_descriptor_is_rejected_without_ownership_construction")
        .arg("--nocapture")
        .env(CLOSED_ENV, "1")
        .status()
        .unwrap();
    assert!(status.success());
}
