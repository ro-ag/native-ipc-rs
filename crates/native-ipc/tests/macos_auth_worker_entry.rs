//! Harnessless executable proof for the fixed macOS authentication-worker entry.

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod macos {
    use std::ffi::{c_int, c_long};
    use std::io::{Read, Write};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::process::CommandExt;
    use std::process::{Child, Command, Stdio};

    const INSTALLED_PATH: &str = "/Library/PrivilegedHelperTools/com.ro-ag.native-ipc.auth-worker";
    const MODE: &str = "--supervisor-auth-worker";
    const REQUEST: &str = "--request-fd=3";
    const RESULT: &str = "--result-fd=4";
    const JOB_BYTES: usize = 152;
    const RESULT_BYTES: usize = 200;
    const CODE_IDENTITY: [u8; 32] = [0x5a; 32];

    #[repr(C)]
    struct TimeSpec {
        tv_sec: c_long,
        tv_nsec: c_long,
    }

    unsafe extern "C" {
        static mach_task_self_: u32;
        fn clock_gettime(clock_id: c_int, time: *mut TimeSpec) -> c_int;
        fn dup2(source: c_int, destination: c_int) -> c_int;
        fn getegid() -> u32;
        fn geteuid() -> u32;
        fn task_info(task: u32, flavor: c_int, info: *mut c_int, count: *mut u32) -> c_int;
    }

    fn is_fixed_child_invocation() -> bool {
        std::env::args_os()
            .next()
            .is_some_and(|argument| argument.as_bytes() == INSTALLED_PATH.as_bytes())
    }

    fn spawn(mode: &str, request: &str, result: &str) -> Child {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .arg0(INSTALLED_PATH)
            .arg(mode)
            .arg(request)
            .arg(result)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        // SAFETY: the isolated child performs only async-signal-safe dup2
        // before exec, installing its request/result pipes at fixed FD3/FD4.
        unsafe {
            command.pre_exec(|| {
                if dup2(0, 3) == 3 && dup2(1, 4) == 4 {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error())
                }
            });
        }
        command.spawn().unwrap()
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

    fn audit_token() -> [u8; 32] {
        let mut values = [0_u32; 8];
        let mut count = 8;
        // SAFETY: the current task is live and values/count are writable for
        // TASK_AUDIT_TOKEN's exact eight natural_t words.
        assert_eq!(
            unsafe {
                task_info(
                    mach_task_self_,
                    15,
                    values.as_mut_ptr().cast(),
                    &raw mut count,
                )
            },
            0
        );
        assert_eq!(count, 8);
        let mut bytes = [0_u8; 32];
        for (destination, value) in bytes.chunks_exact_mut(4).zip(values) {
            destination.copy_from_slice(&value.to_ne_bytes());
        }
        bytes
    }

    fn deadline_after(seconds: u64) -> u64 {
        let mut now = TimeSpec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: now is writable and CLOCK_UPTIME_RAW is Darwin clock 8.
        assert_eq!(unsafe { clock_gettime(8, &raw mut now) }, 0);
        u64::try_from(now.tv_sec).unwrap() * 1_000_000_000
            + u64::try_from(now.tv_nsec).unwrap()
            + seconds * 1_000_000_000
    }

    fn job(deadline: u64) -> [u8; JOB_BYTES] {
        let mut bytes = [0_u8; JOB_BYTES];
        bytes[..8].copy_from_slice(b"NIPCAWJ1");
        put_u16(&mut bytes, 8, 1);
        put_u32(&mut bytes, 12, JOB_BYTES as u32);
        bytes[16] = 0;
        put_u64(&mut bytes, 24, 1);
        bytes[32..64].fill(0x11);
        bytes[72..104].copy_from_slice(&audit_token());
        // SAFETY: credential getters have no preconditions and describe this
        // same live task whose audit token was copied above.
        put_u32(&mut bytes, 104, unsafe { geteuid() });
        // SAFETY: same exact process credential snapshot.
        put_u32(&mut bytes, 108, unsafe { getegid() });
        bytes[112..144].fill(0x22);
        put_u64(&mut bytes, 144, deadline);
        bytes
    }

    fn run_job(bytes: &[u8]) -> (std::process::ExitStatus, Vec<u8>) {
        let mut child = spawn(MODE, REQUEST, RESULT);
        child.stdin.as_mut().unwrap().write_all(bytes).unwrap();
        drop(child.stdin.take());
        let mut result = Vec::new();
        child
            .stdout
            .as_mut()
            .unwrap()
            .read_to_end(&mut result)
            .unwrap();
        (child.wait().unwrap(), result)
    }

    fn assert_no_static_security_framework_dependency() {
        let output = Command::new("/usr/bin/otool")
            .arg("-L")
            .arg(std::env::current_exe().unwrap())
            .output()
            .unwrap();
        assert!(output.status.success());
        let load_commands = String::from_utf8(output.stdout).unwrap();
        assert!(!load_commands.contains("Security.framework"));
        assert!(!load_commands.contains("CoreFoundation.framework"));
    }

    pub fn main() {
        if is_fixed_child_invocation() {
            // SAFETY: `always` and CODE_IDENTITY are compiled fixture
            // constants; the pre-exec hook transferred sole FD3/FD4 ownership.
            unsafe { native_ipc::__private_macos_auth_worker_main(c"always", CODE_IDENTITY) }
        }

        assert_no_static_security_framework_dependency();

        let (status, result) = run_job(&job(deadline_after(5)));
        assert!(
            status.success(),
            "worker status {status:?}, result {result:?}"
        );
        assert_eq!(result.len(), RESULT_BYTES);
        assert_eq!(&result[..8], b"NIPCAWR1");
        assert_eq!(u16::from_le_bytes(result[10..12].try_into().unwrap()), 1);
        assert_eq!(&result[168..200], &CODE_IDENTITY);

        let valid = job(deadline_after(5));
        let (status, result) = run_job(&valid[..valid.len() - 1]);
        assert!(!status.success());
        assert!(result.is_empty());

        let mut extended = job(deadline_after(5)).to_vec();
        extended.push(0xff);
        let (status, result) = run_job(&extended);
        assert!(!status.success());
        assert!(result.is_empty());

        let (status, result) = run_job(&job(1));
        assert!(!status.success());
        assert!(result.is_empty());

        let mut wrong = spawn("--wrong-mode", REQUEST, RESULT);
        drop(wrong.stdin.take());
        let mut result = Vec::new();
        wrong
            .stdout
            .as_mut()
            .unwrap()
            .read_to_end(&mut result)
            .unwrap();
        assert!(!wrong.wait().unwrap().success());
        assert!(result.is_empty());
    }
}

fn main() {
    #[cfg(all(target_os = "macos", target_arch = "aarch64"))]
    macos::main();
}
