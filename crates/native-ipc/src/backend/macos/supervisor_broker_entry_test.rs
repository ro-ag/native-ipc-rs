use std::ffi::{CStr, OsStr, OsString, c_int};
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
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

unsafe extern "C" {
    fn close(fd: c_int) -> c_int;
    fn dup2(source: c_int, destination: c_int) -> c_int;
    fn pipe(descriptors: *mut c_int) -> c_int;
}

assert_not_impl_any!(DormantBrokerGate: Clone, Copy);
assert_not_impl_any!(ActiveBrokerGate: Clone, Copy);

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
