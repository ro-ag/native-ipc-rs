//! Harnessless executable proof for the fixed macOS broker gate entry.

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod macos {
    use std::ffi::{c_int, c_long};
    use std::io::{Read, Write};
    use std::net::Shutdown;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command, Stdio};
    use std::thread;
    use std::time::Duration;

    const INSTALLED_PATH: &str = "/Library/PrivilegedHelperTools/com.ro-ag.native-ipc.broker";
    const MODE: &str = "--supervisor-broker";
    const GATE: &str = "--gate-fd=3";
    const CONTROL: &str = "--control-fd=4";
    const TRACE: &str = "--trace-fd=5";

    #[repr(C)]
    struct TimeSpec {
        tv_sec: c_long,
        tv_nsec: c_long,
    }

    unsafe extern "C" {
        fn dup2(source: i32, destination: i32) -> i32;
        fn clock_gettime(clock_id: c_int, time: *mut TimeSpec) -> c_int;
        fn fcntl(fd: c_int, command: c_int, ...) -> c_int;
    }

    struct Spawned {
        child: Child,
        control: UnixStream,
        _trace: UnixStream,
    }

    fn is_fixed_child_invocation() -> bool {
        std::env::args_os()
            .next()
            .is_some_and(|argument| argument.as_bytes() == INSTALLED_PATH.as_bytes())
    }

    fn spawn(mode: &str, gate: &str, control_argument: &str) -> Spawned {
        let (control, child_control) = UnixStream::pair().unwrap();
        let (trace, child_trace) = UnixStream::pair().unwrap();
        // SAFETY: F_DUPFD_CLOEXEC=67 returns one fresh owned descriptor above
        // the fixed ABI range so dup2 always clears close-on-exec on FD4.
        let stable = unsafe { fcntl(child_control.as_raw_fd(), 67, 10) };
        assert!(stable >= 10);
        // SAFETY: successful fcntl returned a fresh descriptor.
        let stable = unsafe { OwnedFd::from_raw_fd(stable) };
        let child_control_fd = stable.as_raw_fd();
        // SAFETY: same collision-safe duplication for fixed trace FD5.
        let stable_trace = unsafe { fcntl(child_trace.as_raw_fd(), 67, 10) };
        assert!(stable_trace >= 10);
        // SAFETY: successful fcntl returned a fresh descriptor.
        let stable_trace = unsafe { OwnedFd::from_raw_fd(stable_trace) };
        let child_trace_fd = stable_trace.as_raw_fd();
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .arg0(INSTALLED_PATH)
            .arg(mode)
            .arg(gate)
            .arg(control_argument)
            .arg(TRACE)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // SAFETY: the isolated child performs only async-signal-safe dup2
        // before exec, installing its private stdin pipe reader at fixed FD 3.
        unsafe {
            command.pre_exec(move || {
                if dup2(0, 3) == 3 && dup2(child_control_fd, 4) == 4 && dup2(child_trace_fd, 5) == 5
                {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error())
                }
            });
        }
        let child = command.spawn().unwrap();
        drop(stable);
        drop(stable_trace);
        drop(child_control);
        drop(child_trace);
        Spawned {
            child,
            control,
            _trace: trace,
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

    fn plan_frame() -> Vec<u8> {
        let policy = b"com.example.receiver";
        let executable = b"/Library/PrivilegedHelperTools/com.example.receiver";
        let argument = b"receiver";
        let mut bytes = vec![0_u8; 256];
        bytes[..8].copy_from_slice(b"NIPCBP01");
        put_u16(&mut bytes, 8, 1);
        let mut now = TimeSpec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: now is writable and CLOCK_UPTIME_RAW is Darwin clock 8.
        assert_eq!(unsafe { clock_gettime(8, &raw mut now) }, 0);
        let deadline = u64::try_from(now.tv_sec).unwrap() * 1_000_000_000
            + u64::try_from(now.tv_nsec).unwrap()
            + 5_000_000_000;
        put_u64(&mut bytes, 16, deadline);
        put_u64(&mut bytes, 24, 1);
        put_u64(&mut bytes, 32, 1);
        put_u32(&mut bytes, 40, 501);
        put_u32(&mut bytes, 44, 20);
        for (range, value) in [
            (48..80, 1),
            (80..112, 2),
            (112..144, 3),
            (144..176, 4),
            (176..208, 5),
            (208..240, 6),
        ] {
            bytes[range].fill(value);
        }
        put_u32(&mut bytes, 240, u32::try_from(policy.len()).unwrap());
        put_u32(&mut bytes, 244, u32::try_from(executable.len()).unwrap());
        put_u16(&mut bytes, 248, 1);
        bytes.extend_from_slice(policy);
        bytes.extend_from_slice(executable);
        bytes.extend_from_slice(&u32::try_from(argument.len()).unwrap().to_le_bytes());
        bytes.extend_from_slice(argument);
        let length = u32::try_from(bytes.len()).unwrap();
        put_u32(&mut bytes, 12, length);
        bytes
    }

    fn stage(spawned: &mut Spawned) {
        let frame = plan_frame();
        spawned
            .control
            .write_all(&u32::try_from(frame.len()).unwrap().to_le_bytes())
            .unwrap();
        spawned.control.write_all(&frame).unwrap();
        spawned.control.shutdown(Shutdown::Write).unwrap();
        let mut ack = [0_u8; 40];
        spawned.control.read_exact(&mut ack).unwrap();
        assert_eq!(&ack[..8], b"NIPCBPA1");
    }

    fn send_unacknowledged_frame(spawned: &mut Spawned, extra: &[u8]) {
        let frame = plan_frame();
        let _ = spawned
            .control
            .write_all(&u32::try_from(frame.len()).unwrap().to_le_bytes());
        let _ = spawned.control.write_all(&frame);
        let _ = spawned.control.write_all(extra);
        let _ = spawned.control.shutdown(Shutdown::Write);
    }

    pub fn main() {
        if is_fixed_child_invocation() {
            // SAFETY: the fixture's pre-exec hook transferred sole FD 3
            // ownership and arg0/args reproduce the installed process vector.
            unsafe { native_ipc::__private_macos_broker_gate_main() }
        }

        let mut active = spawn(MODE, GATE, CONTROL);
        stage(&mut active);
        thread::sleep(Duration::from_millis(20));
        assert!(active.child.try_wait().unwrap().is_none());
        active
            .child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(&[1])
            .unwrap();
        thread::sleep(Duration::from_millis(20));
        assert!(active.child.try_wait().unwrap().is_none());
        drop(active.child.stdin.take());
        assert!(active.child.wait().unwrap().success());

        let mut wrong_arguments = spawn("--wrong-mode", GATE, CONTROL);
        drop(wrong_arguments.child.stdin.take());
        assert_eq!(wrong_arguments.child.wait().unwrap().code(), Some(64));

        let mut wrong_activation = spawn(MODE, GATE, CONTROL);
        stage(&mut wrong_activation);
        wrong_activation
            .child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(&[0xff])
            .unwrap();
        drop(wrong_activation.child.stdin.take());
        assert_eq!(wrong_activation.child.wait().unwrap().code(), Some(65));

        let mut early_start = spawn(MODE, GATE, CONTROL);
        early_start
            .child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(&[1])
            .unwrap();
        send_unacknowledged_frame(&mut early_start, &[]);
        drop(early_start.child.stdin.take());
        assert_eq!(early_start.child.wait().unwrap().code(), Some(65));
        let mut unexpected_ack = Vec::new();
        early_start
            .control
            .read_to_end(&mut unexpected_ack)
            .unwrap();
        assert!(unexpected_ack.is_empty());

        let mut extended = spawn(MODE, GATE, CONTROL);
        send_unacknowledged_frame(&mut extended, &[0xff]);
        let gate_writer = extended.child.stdin.take().unwrap();
        assert_eq!(extended.child.wait().unwrap().code(), Some(65));
        drop(gate_writer);
        let mut unexpected_ack = Vec::new();
        extended.control.read_to_end(&mut unexpected_ack).unwrap();
        assert!(unexpected_ack.is_empty());
    }
}

fn main() {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    macos::main();
}
