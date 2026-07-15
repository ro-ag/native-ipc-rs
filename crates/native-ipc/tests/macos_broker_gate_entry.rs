//! Harnessless executable proof for the fixed macOS broker gate entry.

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod macos {
    use std::io::Write;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command, Stdio};
    use std::thread;
    use std::time::Duration;

    const INSTALLED_PATH: &str = "/Library/PrivilegedHelperTools/com.ro-ag.native-ipc.broker";
    const MODE: &str = "--supervisor-broker";
    const GATE: &str = "--gate-fd=3";

    unsafe extern "C" {
        fn dup2(source: i32, destination: i32) -> i32;
    }

    fn is_fixed_child_invocation() -> bool {
        std::env::args_os()
            .next()
            .is_some_and(|argument| argument.as_bytes() == INSTALLED_PATH.as_bytes())
    }

    fn spawn(mode: &str, gate: &str) -> Child {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .arg0(INSTALLED_PATH)
            .arg(mode)
            .arg(gate)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // SAFETY: the isolated child performs only async-signal-safe dup2
        // before exec, installing its private stdin pipe reader at fixed FD 3.
        unsafe {
            command.pre_exec(|| {
                if dup2(0, 3) == 3 {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error())
                }
            });
        }
        command.spawn().unwrap()
    }

    pub fn main() {
        if is_fixed_child_invocation() {
            // SAFETY: the fixture's pre-exec hook transferred sole FD 3
            // ownership and arg0/args reproduce the installed process vector.
            unsafe { native_ipc::__private_macos_broker_gate_main() }
        }

        let mut active = spawn(MODE, GATE);
        thread::sleep(Duration::from_millis(20));
        assert!(active.try_wait().unwrap().is_none());
        active.stdin.as_mut().unwrap().write_all(&[1]).unwrap();
        thread::sleep(Duration::from_millis(20));
        assert!(active.try_wait().unwrap().is_none());
        drop(active.stdin.take());
        assert!(active.wait().unwrap().success());

        let mut wrong_arguments = spawn("--wrong-mode", GATE);
        drop(wrong_arguments.stdin.take());
        assert_eq!(wrong_arguments.wait().unwrap().code(), Some(64));

        let mut wrong_activation = spawn(MODE, GATE);
        wrong_activation
            .stdin
            .as_mut()
            .unwrap()
            .write_all(&[0xff])
            .unwrap();
        drop(wrong_activation.stdin.take());
        assert_eq!(wrong_activation.wait().unwrap().code(), Some(65));
    }
}

fn main() {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    macos::main();
}
