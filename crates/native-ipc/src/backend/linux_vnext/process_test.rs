use super::*;
use static_assertions::{assert_impl_all, assert_not_impl_any};
use std::io::Write;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::session::AbsoluteDeadline;

const ENV_DESCENDANT: &str = "NATIVE_IPC_MDWE_DESCENDANT";
const ENV_HELD_EXECUTABLE_FD: &str = "NATIVE_IPC_HELD_EXECUTABLE_FD";
const ENV_HELD_EXECUTABLE_KEY: &str = "NATIVE_IPC_HELD_EXECUTABLE_KEY";
const ENV_IDENTITY_HANDSHAKE_FD: &str = "NATIVE_IPC_IDENTITY_HANDSHAKE_FD";
const ENV_CONTAINMENT_MODE: &str = "NATIVE_IPC_CONTAINMENT_MODE";
const ENV_DESCENDANT_PID_FILE: &str = "NATIVE_IPC_DESCENDANT_PID_FILE";
const PR_GET_MDWE: libc::c_int = 66;
const PR_MDWE_NO_INHERIT: libc::c_ulong = 2;
const CLONE_PIDFD: u64 = 0x0000_1000;
const CLOSE_RANGE_CLOEXEC: libc::c_uint = 1 << 2;
const EXEC_ERROR_LEN: usize = 8;
const REPLACEMENT_IMAGE: &str = "/bin/sh";
static FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

fn get_mdwe() -> Result<libc::c_ulong, SpawnPolicyError> {
    // SAFETY: PR_GET_MDWE has scalar zero trailing arguments.
    let mask = unsafe {
        libc::prctl(
            PR_GET_MDWE,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    };
    if mask < 0 {
        return Err(native_error(io::Error::last_os_error()));
    }
    Ok(mask as libc::c_ulong)
}

#[repr(C)]
#[derive(Default)]
struct CloneArgs {
    flags: u64,
    pidfd: u64,
    child_tid: u64,
    parent_tid: u64,
    exit_signal: u64,
    stack: u64,
    stack_size: u64,
    tls: u64,
    set_tid: u64,
    set_tid_size: u64,
    cgroup: u64,
}

#[derive(Clone, Copy)]
enum AtomicExecFault {
    None,
    SetSid,
    Mdwe,
    Exec,
    Partial,
    Malformed,
    Stall,
    SilentExit,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AtomicExecError {
    Deadline,
    Malformed,
    Child { stage: u32, errno: i32 },
    Native(i32),
    ExitedBeforeConfirmation,
}

#[repr(C)]
struct RawChildError {
    stage: u32,
    errno: i32,
}

struct AtomicExecChild {
    lifecycle: ExactChildLifecycle,
    held: HeldExecutable,
}

static_assertions::assert_impl_all!(AtomicExecChild: Send);
static_assertions::assert_not_impl_any!(AtomicExecChild: Sync, Clone);
static_assertions::assert_impl_all!(ExactChildLifecycle: Send);
static_assertions::assert_not_impl_any!(ExactChildLifecycle: Sync, Clone);

assert_impl_all!(HeldExecutable: Send);
assert_not_impl_any!(HeldExecutable: Sync, Clone);
assert_impl_all!(VerifiedExecutable: Send);
assert_not_impl_any!(VerifiedExecutable: Sync, Clone);

struct TestChild {
    child: Option<Child>,
    process_group: bool,
}

struct ExecutableFixture {
    directory: std::path::PathBuf,
    file: std::path::PathBuf,
}

struct IdentityHandshake {
    parent: OwnedFd,
    child: Option<OwnedFd>,
}

impl TestChild {
    fn spawn(command: &mut Command, process_group: bool) -> Self {
        if process_group {
            command.process_group(0);
        }
        Self {
            child: Some(command.spawn().unwrap()),
            process_group,
        }
    }

    fn child_mut(&mut self) -> &mut Child {
        self.child.as_mut().expect("test child is live")
    }

    fn wait_success(mut self) {
        let child = self.child.as_mut().expect("test child is live");
        let pid = child.id();
        // Keep the exited leader unreaped so its PID/process-group identity
        // cannot be reused before every controlled descendant is killed.
        // SAFETY: siginfo storage is valid and this waits for the owned PID.
        let mut information: libc::siginfo_t = unsafe { core::mem::zeroed() };
        if unsafe {
            libc::waitid(
                libc::P_PID,
                pid,
                &mut information,
                libc::WEXITED | libc::WNOWAIT,
            )
        } != 0
        {
            panic!(
                "controlled child waitid failed: {}",
                io::Error::last_os_error()
            );
        }
        if self.process_group {
            // SAFETY: the unreaped leader still owns this process-group ID.
            let _ = unsafe { libc::kill(-(pid as libc::pid_t), libc::SIGKILL) };
        }
        let result = child.wait();
        let status = match result {
            Ok(status) => status,
            Err(error) => panic!("controlled child wait failed: {error}"),
        };
        self.child.take();
        assert!(status.success());
    }
}

impl Drop for TestChild {
    fn drop(&mut self) {
        if let Some(child) = self.child.as_mut() {
            if self.process_group {
                // SAFETY: the controlled child created its own process group.
                let _ = unsafe { libc::kill(-(child.id() as libc::pid_t), libc::SIGKILL) };
            } else {
                let _ = child.kill();
            }
            let _ = child.wait();
        }
    }
}

impl ExecutableFixture {
    fn new(bytes: &[u8]) -> Self {
        let sequence = FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let directory = std::env::temp_dir().join(format!(
            "native-ipc-vnext-elf-{}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir(&directory).unwrap();
        let file = directory.join("image");
        let mut output = std::fs::File::create(&file).unwrap();
        output.write_all(bytes).unwrap();
        output
            .set_permissions(std::fs::Permissions::from_mode(0o700))
            .unwrap();
        Self { directory, file }
    }

    fn copy_from(source: &Path) -> Self {
        let fixture = Self::new(&[]);
        std::fs::copy(source, &fixture.file).unwrap();
        fixture
    }
}

impl IdentityHandshake {
    fn configure(command: &mut Command) -> Self {
        let mut pair = [-1; 2];
        // SAFETY: output has room for two descriptors and flags are valid.
        assert_eq!(
            unsafe {
                libc::socketpair(
                    libc::AF_UNIX,
                    libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC,
                    0,
                    pair.as_mut_ptr(),
                )
            },
            0
        );
        // SAFETY: successful socketpair returned two owned descriptors.
        let parent = unsafe { OwnedFd::from_raw_fd(pair[0]) };
        // SAFETY: successful socketpair returned two owned descriptors.
        let child = unsafe { OwnedFd::from_raw_fd(pair[1]) };
        let inherited = child.as_raw_fd();
        command.env(ENV_IDENTITY_HANDSHAKE_FD, inherited.to_string());
        // SAFETY: the closure performs only one scalar fcntl before exec.
        unsafe {
            command.pre_exec(move || {
                if libc::fcntl(inherited, libc::F_SETFD, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        Self {
            parent,
            child: Some(child),
        }
    }

    fn child_spawned(&mut self) {
        self.child.take();
    }

    fn wait_ready(&self) {
        let mut ready = libc::pollfd {
            fd: self.parent.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: one pollfd remains live for this bounded controlled wait.
        assert_eq!(unsafe { libc::poll(&mut ready, 1, 5_000) }, 1);
        assert_ne!(ready.revents & libc::POLLIN, 0);
        let mut byte = 0_u8;
        // SAFETY: one-byte output is live and controlled helper sends once.
        assert_eq!(
            unsafe { libc::recv(self.parent.as_raw_fd(), (&mut byte as *mut u8).cast(), 1, 0) },
            1
        );
        assert_eq!(byte, b'R');
    }

    fn release(&self) {
        // SAFETY: one-byte input is live and controlled helper receives once.
        assert_eq!(
            unsafe {
                libc::send(
                    self.parent.as_raw_fd(),
                    (&b'G' as *const u8).cast(),
                    1,
                    libc::MSG_NOSIGNAL,
                )
            },
            1
        );
    }
}

impl Drop for ExecutableFixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

fn native_elf_header() -> [u8; ELF_HEADER_LEN] {
    let mut header = [0_u8; ELF_HEADER_LEN];
    header[..4].copy_from_slice(b"\x7fELF");
    header[4] = 2;
    header[5] = 1;
    header[6] = 1;
    header[16..18].copy_from_slice(&2_u16.to_le_bytes());
    header[18..20].copy_from_slice(&NATIVE_ELF_MACHINE.to_le_bytes());
    header[20..24].copy_from_slice(&1_u32.to_le_bytes());
    header[52..54].copy_from_slice(&(ELF_HEADER_LEN as u16).to_le_bytes());
    header
}

fn configure_held_cloexec_probe(command: &mut Command, held: &HeldExecutable) {
    let raw = held.fd.as_raw_fd();
    // SAFETY: scalar query of the live held descriptor.
    let flags = unsafe { libc::fcntl(raw, libc::F_GETFD) };
    assert!(flags >= 0 && flags & libc::FD_CLOEXEC != 0);
    command.env(ENV_HELD_EXECUTABLE_FD, raw.to_string()).env(
        ENV_HELD_EXECUTABLE_KEY,
        format!("{}:{}", held.key.device, held.key.inode),
    );
}

fn assert_held_description_closed() {
    let Some(raw) = std::env::var_os(ENV_HELD_EXECUTABLE_FD) else {
        return;
    };
    let raw: RawFd = raw.to_string_lossy().parse().unwrap();
    let expected = std::env::var(ENV_HELD_EXECUTABLE_KEY).unwrap();
    let (device, inode) = expected.split_once(':').unwrap();
    let expected = ExecutableKey {
        device: device.parse().unwrap(),
        inode: inode.parse().unwrap(),
    };
    // Numeric fd slots may be reused by the loader. Either EBADF or a
    // different object proves the held executable description was closed.
    // SAFETY: scalar query intentionally probes this inherited slot.
    if unsafe { libc::fcntl(raw, libc::F_GETFD) } >= 0 {
        assert_ne!(file_key(raw).unwrap().0, expected);
    } else {
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
    }
}

fn identity_helper_handshake() {
    let Some(raw) = std::env::var_os(ENV_IDENTITY_HANDSHAKE_FD) else {
        return;
    };
    let raw: RawFd = raw.to_string_lossy().parse().unwrap();
    // SAFETY: the trusted test pre-exec path transferred sole ownership.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    // SAFETY: controlled one-byte READY send.
    assert_eq!(
        unsafe { libc::send(fd.as_raw_fd(), (&b'R' as *const u8).cast(), 1, 0) },
        1
    );
    let mut release = 0_u8;
    // SAFETY: controlled one-byte release receive.
    assert_eq!(
        unsafe { libc::recv(fd.as_raw_fd(), (&mut release as *mut u8).cast(), 1, 0,) },
        1
    );
    assert_eq!(release, b'G');
}

fn open_fd_count() -> usize {
    std::fs::read_dir("/proc/self/fd").unwrap().count()
}

fn open_task_count() -> usize {
    std::fs::read_dir("/proc/self/task").unwrap().count()
}

fn assert_drop_returns(child: AtomicExecChild) {
    let (finished, observed) = std::sync::mpsc::sync_channel(0);
    let dropper = std::thread::spawn(move || {
        drop(child);
        let _ = finished.send(());
    });
    observed
        .recv_timeout(Duration::from_millis(500))
        .expect("exact-child Drop waited for process cleanup");
    dropper.join().unwrap();
}

fn assert_complete_direct(cleanup: ExactChildCleanup, expected: ExactChildExit) {
    assert_eq!(cleanup.direct_child, Some(expected));
    assert_eq!(cleanup.last_native_error, None);
}

fn assert_incomplete_direct(cleanup: ExactChildCleanup, expected_error: Option<i32>) {
    assert_eq!(cleanup.direct_child, None);
    assert_eq!(cleanup.last_native_error, expected_error);
}

fn wait_for_child_baseline(
    expected_fds: usize,
    expected_tasks: usize,
    pid: libc::pid_t,
    deadline: AbsoluteDeadline,
) {
    loop {
        let children = std::fs::read_to_string("/proc/thread-self/children").unwrap();
        let child_is_absent = !children
            .split_ascii_whitespace()
            .any(|child| child.parse::<libc::pid_t>() == Ok(pid));
        if open_fd_count() == expected_fds && open_task_count() == expected_tasks && child_is_absent
        {
            break;
        }
        assert!(!deadline.is_expired(), "child cleanup missed its baseline");
        std::thread::sleep(Duration::from_millis(1));
    }

    // SAFETY: the worker has dropped its pidfd and exited. ECHILD now proves
    // no waitable status or zombie remains for this direct-child PID.
    assert_eq!(
        unsafe { libc::waitpid(pid, core::ptr::null_mut(), libc::WNOHANG) },
        -1
    );
    assert_eq!(
        io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
}

fn pidfd_reported_pid(pidfd: RawFd) -> i64 {
    let contents = std::fs::read_to_string(format!("/proc/self/fdinfo/{pidfd}")).unwrap();
    contents
        .lines()
        .find_map(|line| line.strip_prefix("Pid:\t"))
        .unwrap()
        .parse()
        .unwrap()
}

unsafe fn child_write_error_and_exit(fd: RawFd, stage: u32, errno: i32) -> ! {
    let record = RawChildError {
        stage: stage.to_le(),
        errno: errno.to_le(),
    };
    let mut written = 0_usize;
    let mut interrupts = 0_u8;
    while written < EXEC_ERROR_LEN && interrupts < 16 {
        // SAFETY: the fixed stack record remains live; fd is the inherited
        // error-pipe writer and each length is bounded by the record.
        let result = unsafe {
            libc::write(
                fd,
                (&record as *const RawChildError)
                    .cast::<u8>()
                    .add(written)
                    .cast(),
                EXEC_ERROR_LEN - written,
            )
        };
        if result > 0 {
            written += result as usize;
        } else if result < 0 && unsafe { *libc::__errno_location() } == libc::EINTR {
            interrupts += 1;
        } else {
            break;
        }
    }
    // SAFETY: raw child path never runs Rust destructors.
    unsafe { libc::_exit(120) }
}

fn atomic_clone_exec_for_test(
    held: HeldExecutable,
    arguments: &[std::ffi::CString],
    environment: &[std::ffi::CString],
    fault: AtomicExecFault,
    deadline: AbsoluteDeadline,
) -> Result<AtomicExecChild, (AtomicExecError, AtomicExecChild)> {
    let held_path =
        std::ffi::CString::new(format!("/proc/self/fd/{}", held.fd.as_raw_fd())).unwrap();
    let invalid_path = c"/native-ipc-vnext-intentional-missing-image";
    let mut argv: Vec<*const libc::c_char> = arguments.iter().map(|value| value.as_ptr()).collect();
    argv.push(core::ptr::null());
    let mut envp: Vec<*const libc::c_char> =
        environment.iter().map(|value| value.as_ptr()).collect();
    envp.push(core::ptr::null());
    let argv_raw = argv.as_ptr();
    let envp_raw = envp.as_ptr();
    let held_path_raw = held_path.as_ptr();
    let invalid_path_raw = invalid_path.as_ptr();
    let fault_code = match fault {
        AtomicExecFault::None => 0_u8,
        AtomicExecFault::SetSid => 1,
        AtomicExecFault::Mdwe => 2,
        AtomicExecFault::Exec => 3,
        AtomicExecFault::Partial => 4,
        AtomicExecFault::Malformed => 5,
        AtomicExecFault::Stall => 6,
        AtomicExecFault::SilentExit => 7,
    };

    let mut pipe = [-1; 2];
    // SAFETY: output has room for two descriptors.
    if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } != 0 {
        panic!("atomic exec error pipe failed");
    }
    // SAFETY: successful pipe2 returned two unique descriptors.
    let reader = unsafe { OwnedFd::from_raw_fd(pipe[0]) };
    // SAFETY: successful pipe2 returned two unique descriptors.
    let writer = unsafe { OwnedFd::from_raw_fd(pipe[1]) };
    let reader_raw = reader.as_raw_fd();
    let writer_raw = writer.as_raw_fd();
    let prepared_lifecycle = PreparedExactChildLifecycle::new().unwrap();

    let mut raw_pidfd = -1;
    let clone_arguments = CloneArgs {
        flags: CLONE_PIDFD,
        pidfd: (&mut raw_pidfd as *mut libc::c_int) as u64,
        exit_signal: libc::SIGCHLD as u64,
        ..CloneArgs::default()
    };
    // SAFETY: fork-like clone3 with an 88-byte zero-extended clone_args.
    let pid = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            &clone_arguments,
            core::mem::size_of::<CloneArgs>(),
        ) as libc::pid_t
    };
    if pid == 0 {
        // Child audit: only scalar/byte arithmetic and raw close, prctl,
        // execve, write, errno-location, and _exit calls occur after clone.
        // SAFETY: all pointers and fds were completely prebuilt in parent.
        unsafe {
            libc::close(reader_raw);
            if libc::syscall(
                libc::SYS_close_range,
                3_u32,
                libc::c_uint::MAX,
                CLOSE_RANGE_CLOEXEC,
            ) != 0
            {
                child_write_error_and_exit(writer_raw, 0, *libc::__errno_location());
            }
            if fault_code == 4 {
                let record = RawChildError {
                    stage: 1_u32.to_le(),
                    errno: libc::EPERM.to_le(),
                };
                libc::write(writer_raw, (&record as *const RawChildError).cast(), 3);
                libc::_exit(121);
            }
            if fault_code == 5 {
                child_write_error_and_exit(writer_raw, 99, libc::EINVAL);
            }
            if fault_code == 6 {
                loop {
                    libc::pause();
                }
            }
            if fault_code == 7 {
                libc::_exit(122);
            }
            if fault_code == 1 {
                child_write_error_and_exit(writer_raw, 1, libc::EPERM);
            }
            if libc::setsid() < 0 {
                child_write_error_and_exit(writer_raw, 1, *libc::__errno_location());
            }
            if fault_code == 2 {
                child_write_error_and_exit(writer_raw, 2, libc::EPERM);
            }
            if libc::prctl(
                PR_SET_MDWE,
                PR_MDWE_REFUSE_EXEC_GAIN,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
            ) != 0
            {
                child_write_error_and_exit(writer_raw, 2, *libc::__errno_location());
            }
            let path = if fault_code == 3 {
                invalid_path_raw
            } else {
                held_path_raw
            };
            libc::execve(path, argv_raw, envp_raw);
            child_write_error_and_exit(writer_raw, 3, *libc::__errno_location());
        }
    }
    assert!(pid > 0, "clone3 failed: {}", io::Error::last_os_error());
    assert!(raw_pidfd >= 0);
    // SAFETY: successful CLONE_PIDFD atomically installed this descriptor.
    let pidfd = unsafe { OwnedFd::from_raw_fd(raw_pidfd) };
    let lifecycle = prepared_lifecycle.arm(pid, pidfd).unwrap();
    drop(writer);
    let child = AtomicExecChild { lifecycle, held };

    let mut record = [0_u8; EXEC_ERROR_LEN];
    let mut received = 0_usize;
    loop {
        // SAFETY: remaining record storage is writable and bounded.
        let read = unsafe {
            libc::read(
                reader.as_raw_fd(),
                record[received..].as_mut_ptr().cast(),
                record.len() - received,
            )
        };
        if read > 0 {
            received += read as usize;
            if received == record.len() {
                let stage = u32::from_le_bytes(record[..4].try_into().unwrap());
                let errno = i32::from_le_bytes(record[4..].try_into().unwrap());
                if !matches!(stage, 0..=3) || errno <= 0 {
                    return Err((AtomicExecError::Malformed, child));
                }
                if stage >= 2 {
                    child.lifecycle.establish_fresh_session();
                }
                return Err((AtomicExecError::Child { stage, errno }, child));
            }
            continue;
        }
        if read == 0 {
            return if received == 0 {
                child.lifecycle.establish_fresh_session();
                let mut event = libc::pollfd {
                    fd: child.pidfd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                // SAFETY: one pollfd remains live for this nonblocking check.
                let observed = unsafe { libc::poll(&mut event, 1, 0) };
                if observed < 0 {
                    Err((AtomicExecError::Native(-1), child))
                } else if observed > 0 || !child.held_image_matches() {
                    Err((AtomicExecError::ExitedBeforeConfirmation, child))
                } else if let Err(error) = child.await_post_exec_checkpoint(deadline) {
                    Err((error, child))
                } else {
                    Ok(child)
                }
            } else {
                Err((AtomicExecError::Malformed, child))
            };
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            if deadline.is_expired() {
                return Err((AtomicExecError::Deadline, child));
            }
            continue;
        }
        if error.kind() != io::ErrorKind::WouldBlock {
            return Err((
                AtomicExecError::Native(error.raw_os_error().unwrap_or(-1)),
                child,
            ));
        }
        if deadline.is_expired() {
            return Err((AtomicExecError::Deadline, child));
        }
        let timeout = deadline
            .remaining()
            .as_nanos()
            .div_ceil(1_000_000)
            .min(i32::MAX as u128) as libc::c_int;
        let mut events = [
            libc::pollfd {
                fd: reader.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: child.pidfd(),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: both pollfd entries remain live for this bounded call.
        let polled = unsafe { libc::poll(events.as_mut_ptr(), 2, timeout) };
        if polled < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return Err((AtomicExecError::Native(-1), child));
        }
        if deadline.is_expired() {
            return Err((AtomicExecError::Deadline, child));
        }
    }
}

impl AtomicExecChild {
    fn pid(&self) -> libc::pid_t {
        self.lifecycle.pid()
    }

    fn pidfd(&self) -> RawFd {
        self.lifecycle.pidfd()
    }

    fn inject_signal_interrupts(&self, count: u32) {
        self.lifecycle
            .shared
            .signal_interrupts
            .store(count, Ordering::Release);
    }

    fn inject_signal_failure(&self, code: i32) {
        self.lifecycle
            .shared
            .signal_failure
            .store(code, Ordering::Release);
    }

    fn inject_poll_failure(&self, code: i32) {
        self.lifecycle
            .shared
            .poll_failure
            .store(code, Ordering::Release);
    }

    fn inject_reap_failure(&self, code: i32) {
        self.lifecycle
            .shared
            .reap_failure
            .store(code, Ordering::Release);
    }

    fn held_image_matches(&self) -> bool {
        let path = std::ffi::CString::new(format!("/proc/{}/exe", self.pid())).unwrap();
        // SAFETY: path is NUL-terminated and flags need no mode.
        let raw = unsafe { libc::open(path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if raw < 0 {
            return false;
        }
        // SAFETY: successful open returned one owned descriptor.
        let actual = unsafe { OwnedFd::from_raw_fd(raw) };
        matches!(file_key(actual.as_raw_fd()), Ok((key, _)) if key == self.held.key)
    }

    fn await_post_exec_checkpoint(
        &self,
        deadline: AbsoluteDeadline,
    ) -> Result<(), AtomicExecError> {
        loop {
            // SAFETY: zero is valid initialization for waitid output.
            let mut information: libc::siginfo_t = unsafe { core::mem::zeroed() };
            // SAFETY: pidfd is live; WNOHANG and WNOWAIT cannot block or reap.
            let result = unsafe {
                libc::waitid(
                    libc::P_PIDFD,
                    self.pidfd() as libc::id_t,
                    &mut information,
                    libc::WSTOPPED | libc::WEXITED | libc::WNOWAIT | libc::WNOHANG,
                )
            };
            if result != 0 {
                return Err(AtomicExecError::Native(
                    io::Error::last_os_error().raw_os_error().unwrap_or(-1),
                ));
            }
            if information.si_code == libc::CLD_STOPPED {
                // SAFETY: CLD_STOPPED initializes the SIGCHLD status member.
                return if unsafe { information.si_status() } == libc::SIGSTOP {
                    Ok(())
                } else {
                    Err(AtomicExecError::Malformed)
                };
            }
            if matches!(
                information.si_code,
                libc::CLD_EXITED | libc::CLD_KILLED | libc::CLD_DUMPED
            ) {
                return Err(AtomicExecError::ExitedBeforeConfirmation);
            }
            if deadline.is_expired() {
                return Err(AtomicExecError::Deadline);
            }
            std::thread::park_timeout(deadline.remaining().min(Duration::from_millis(1)));
        }
    }

    fn resume(&self) {
        // SAFETY: pidfd is the exact atomic identity handle.
        assert_eq!(
            unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    self.pidfd(),
                    libc::SIGCONT,
                    core::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            },
            0
        );
    }

    fn wait_and_reap(self, deadline: AbsoluteDeadline) -> ExactChildCleanup {
        let Self { lifecycle, held: _ } = self;
        lifecycle.wait_and_reap(deadline)
    }

    fn terminate_and_reap(self, deadline: AbsoluteDeadline) -> ExactChildCleanup {
        let Self { lifecycle, held: _ } = self;
        lifecycle.terminate_and_reap(deadline)
    }
}

fn set_mdwe(mask: libc::c_ulong) -> libc::c_int {
    // SAFETY: PR_SET_MDWE accepts scalar masks and zero trailing arguments.
    unsafe {
        libc::prctl(
            PR_SET_MDWE,
            mask,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
            0 as libc::c_ulong,
        )
    }
}

#[test]
#[ignore = "spawned as the exact post-exec MDWE helper and descendant"]
fn exact_image_mdwe_helper() {
    assert_held_description_closed();
    assert_eq!(get_mdwe().unwrap(), PR_MDWE_REFUSE_EXEC_GAIN);
    identity_helper_handshake();
    assert_ne!(set_mdwe(0), 0, "irreversible MDWE unexpectedly cleared");
    assert_eq!(get_mdwe().unwrap(), PR_MDWE_REFUSE_EXEC_GAIN);
    assert_ne!(
        set_mdwe(PR_MDWE_REFUSE_EXEC_GAIN | PR_MDWE_NO_INHERIT),
        0,
        "NO_INHERIT unexpectedly weakened descendant policy"
    );
    assert_eq!(get_mdwe().unwrap(), PR_MDWE_REFUSE_EXEC_GAIN);

    if std::env::var_os(ENV_DESCENDANT).is_none() {
        let executable = std::env::current_exe().unwrap();
        let status = Command::new(executable)
            .args([
                "--exact",
                "backend::linux_vnext::process::tests::exact_image_mdwe_helper",
                "--ignored",
                "--nocapture",
            ])
            .env(ENV_DESCENDANT, "1")
            .env_remove(ENV_HELD_EXECUTABLE_FD)
            .env_remove(ENV_HELD_EXECUTABLE_KEY)
            .env_remove(ENV_IDENTITY_HANDSHAKE_FD)
            .status()
            .unwrap();
        assert!(status.success());
    }
}

#[test]
#[ignore = "spawned alone by identity_and_mdwe_evidence_restore_baselines"]
fn isolated_identity_and_mdwe_evidence_helper() {
    let before = open_fd_count();
    let executable = std::env::current_exe().unwrap();
    let held = HeldExecutable::open(&executable).unwrap();
    let mut command = held.command();
    command
        .args([
            "--exact",
            "backend::linux_vnext::process::tests::exact_image_mdwe_helper",
            "--ignored",
            "--nocapture",
        ])
        .env_remove(ENV_DESCENDANT);
    configure_held_cloexec_probe(&mut command, &held);
    let mut handshake = IdentityHandshake::configure(&mut command);
    install_mdwe_preexec(&mut command);
    let mut child = TestChild::spawn(&mut command, true);
    handshake.child_spawned();
    handshake.wait_ready();
    let child_pid = child.child_mut().id();
    let verified = held.verify_child(child.child_mut()).unwrap();
    assert_eq!(verified.child_pid(), child_pid);
    assert!(verified.pidfd() >= 0);
    assert_ne!(verified.key().inode, 0);
    handshake.release();
    child.wait_success();
    drop(verified);
    drop(handshake);
    assert_eq!(open_fd_count(), before);

    let before = open_fd_count();
    let executable = std::env::current_exe().unwrap();
    let fixture = ExecutableFixture::copy_from(&executable);
    let held = HeldExecutable::open(&fixture.file).unwrap();
    std::fs::remove_file(&fixture.file).unwrap();
    std::fs::copy(REPLACEMENT_IMAGE, &fixture.file).unwrap();
    let mut command = held.command();
    command
        .args([
            "--exact",
            "backend::linux_vnext::process::tests::exact_image_mdwe_helper",
            "--ignored",
            "--nocapture",
        ])
        .env(ENV_DESCENDANT, "1");
    configure_held_cloexec_probe(&mut command, &held);
    let mut handshake = IdentityHandshake::configure(&mut command);
    install_mdwe_preexec(&mut command);
    let mut child = TestChild::spawn(&mut command, true);
    handshake.child_spawned();
    handshake.wait_ready();
    let verified = held.verify_child(child.child_mut()).unwrap();
    handshake.release();
    child.wait_success();
    drop(verified);
    drop(handshake);
    drop(fixture);
    assert_eq!(open_fd_count(), before);

    let before = open_fd_count();
    let executable = std::env::current_exe().unwrap();
    let held = HeldExecutable::open(&executable).unwrap();
    let wrong = ExecutableFixture::copy_from(&executable);
    let mut command = Command::new(&wrong.file);
    command
        .args([
            "--exact",
            "backend::linux_vnext::process::tests::exact_image_mdwe_helper",
            "--ignored",
            "--nocapture",
        ])
        .env(ENV_DESCENDANT, "1");
    configure_held_cloexec_probe(&mut command, &held);
    let mut handshake = IdentityHandshake::configure(&mut command);
    install_mdwe_preexec(&mut command);
    let mut child = TestChild::spawn(&mut command, true);
    handshake.child_spawned();
    handshake.wait_ready();
    assert!(matches!(
        held.verify_child(child.child_mut()),
        Err(SpawnPolicyError::WrongExecutable)
    ));
    handshake.release();
    drop(child);
    drop(handshake);
    drop(wrong);
    assert_eq!(open_fd_count(), before);

    let executable = std::env::current_exe().unwrap();
    let held = HeldExecutable::open(&executable).unwrap();
    let mut exited = Command::new(&executable)
        .args(["--exact", "native-ipc-intentionally-missing-test"])
        .spawn()
        .unwrap();
    assert!(exited.wait().unwrap().success());
    assert!(matches!(
        held.verify_child(&mut exited),
        Err(SpawnPolicyError::ExitedBeforeVerification)
    ));
}

#[test]
fn identity_and_mdwe_evidence_restore_baselines() {
    let executable = std::env::current_exe().unwrap();
    let mut command = Command::new(executable);
    command.args([
        "--exact",
        "backend::linux_vnext::process::tests::isolated_identity_and_mdwe_evidence_helper",
        "--ignored",
        "--nocapture",
    ]);
    TestChild::spawn(&mut command, true).wait_success();
}

#[test]
fn executable_policy_rejects_relative_nonfiles_and_nonexecutables() {
    assert!(matches!(
        HeldExecutable::open(Path::new("relative")),
        Err(SpawnPolicyError::InvalidExecutable)
    ));
    assert!(matches!(
        HeldExecutable::open(Path::new("/dev/null")),
        Err(SpawnPolicyError::InvalidExecutable)
    ));
    assert!(matches!(
        HeldExecutable::open(Path::new("/")),
        Err(SpawnPolicyError::InvalidExecutable)
    ));
    assert!(matches!(
        HeldExecutable::open(Path::new("/proc/self/exe")),
        Err(SpawnPolicyError::Native(libc::ELOOP))
    ));

    let non_elf = ExecutableFixture::new(b"#!/bin/false\n");
    assert!(matches!(
        HeldExecutable::open(&non_elf.file),
        Err(SpawnPolicyError::InvalidExecutable)
    ));
    let link = non_elf.directory.join("link");
    symlink(&non_elf.file, &link).unwrap();
    assert!(matches!(
        HeldExecutable::open(&link),
        Err(SpawnPolicyError::Native(libc::ELOOP))
    ));

    let truncated = ExecutableFixture::new(b"\x7fELF");
    assert!(matches!(
        HeldExecutable::open(&truncated.file),
        Err(SpawnPolicyError::InvalidExecutable)
    ));
    let mut wrong_class = native_elf_header();
    wrong_class[4] = 1;
    let wrong_class = ExecutableFixture::new(&wrong_class);
    assert!(matches!(
        HeldExecutable::open(&wrong_class.file),
        Err(SpawnPolicyError::InvalidExecutable)
    ));
    let mut wrong_machine = native_elf_header();
    wrong_machine[18..20].copy_from_slice(&0_u16.to_le_bytes());
    let wrong_machine = ExecutableFixture::new(&wrong_machine);
    assert!(matches!(
        HeldExecutable::open(&wrong_machine.file),
        Err(SpawnPolicyError::InvalidExecutable)
    ));
}

#[test]
#[ignore = "spawned alone by preexec_failure_restores_descriptor_and_child_baseline"]
fn isolated_preexec_failure_helper() {
    let before = open_fd_count();
    let executable = std::env::current_exe().unwrap();
    let mut command = Command::new(executable);
    command.args([
        "--exact",
        "backend::linux_vnext::process::tests::exact_image_mdwe_helper",
        "--ignored",
    ]);
    install_mdwe_preexec_inner(&mut command, true);
    assert!(matches!(
        command.spawn().map_err(native_error),
        Err(SpawnPolicyError::Native(libc::EPERM))
    ));
    assert_eq!(open_fd_count(), before);
    // SAFETY: this isolated helper owns no other child; ECHILD proves the
    // failed pre-exec child was reaped by Command's spawn-error path.
    assert_eq!(
        unsafe { libc::waitpid(-1, core::ptr::null_mut(), libc::WNOHANG) },
        -1
    );
    assert_eq!(
        io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
}

#[test]
fn preexec_failure_restores_descriptor_and_child_baseline() {
    let executable = std::env::current_exe().unwrap();
    let status = Command::new(executable)
        .args([
            "--exact",
            "backend::linux_vnext::process::tests::isolated_preexec_failure_helper",
            "--ignored",
            "--nocapture",
        ])
        .status()
        .unwrap();
    assert!(status.success());
}

fn atomic_exec_arguments() -> Vec<std::ffi::CString> {
    [
        "native-ipc-atomic-exec-helper",
        "--exact",
        "backend::linux_vnext::process::tests::atomic_exec_mdwe_helper",
        "--ignored",
        "--nocapture",
    ]
    .into_iter()
    .map(|value| std::ffi::CString::new(value).unwrap())
    .collect()
}

fn atomic_exec_environment(held: &HeldExecutable) -> Vec<std::ffi::CString> {
    vec![
        std::ffi::CString::new(format!("{ENV_HELD_EXECUTABLE_FD}={}", held.fd.as_raw_fd()))
            .unwrap(),
        std::ffi::CString::new(format!(
            "{ENV_HELD_EXECUTABLE_KEY}={}:{}",
            held.key.device, held.key.inode
        ))
        .unwrap(),
    ]
}

#[test]
#[ignore = "executed only by the atomic clone3+MDWE+held-exec scaffold"]
fn atomic_exec_mdwe_helper() {
    assert_held_description_closed();
    assert_eq!(get_mdwe().unwrap(), PR_MDWE_REFUSE_EXEC_GAIN);
    // SAFETY: these scalar identity queries cannot mutate process state.
    let pid = unsafe { libc::getpid() };
    // SAFETY: zero selects the calling process.
    assert_eq!(unsafe { libc::getsid(0) }, pid);
    // SAFETY: getpgrp has no arguments and returns the calling process group.
    assert_eq!(unsafe { libc::getpgrp() }, pid);

    if let Some(mode) = std::env::var_os(ENV_CONTAINMENT_MODE) {
        let escape = mode == "escape";
        // SAFETY: the controlled post-exec helper forks before other threads
        // exist. The descendant uses only raw process syscalls afterward.
        let descendant = unsafe { libc::fork() };
        assert!(descendant >= 0);
        if descendant == 0 {
            if escape {
                // SAFETY: the fork child is not a process-group leader.
                if unsafe { libc::setsid() } < 0 {
                    // SAFETY: the fork child cannot safely unwind Rust state.
                    unsafe { libc::_exit(123) };
                }
            }
            loop {
                // SAFETY: pause is a cancellable wait until test cleanup.
                unsafe { libc::pause() };
            }
        }
        let pid_file = std::env::var_os(ENV_DESCENDANT_PID_FILE).unwrap();
        std::fs::write(pid_file, descendant.to_string()).unwrap();
    }
    // Deterministic post-exec checkpoint: parent verifies the held image,
    // observes this stop, then resumes us to return success.
    // SAFETY: SIGSTOP has no handler and cannot be ignored.
    assert_eq!(unsafe { libc::raise(libc::SIGSTOP) }, 0);
}

#[test]
#[ignore = "spawned alone by atomic_clone_exec_state_machine_is_bounded"]
fn isolated_atomic_clone_exec_state_machine_helper() {
    let before = open_fd_count();
    let executable = std::env::current_exe().unwrap();
    let deadline = || AbsoluteDeadline::after(Duration::from_secs(5)).unwrap();

    let held = HeldExecutable::open(&executable).unwrap();
    let environment = atomic_exec_environment(&held);
    let child = atomic_clone_exec_for_test(
        held,
        &atomic_exec_arguments(),
        &environment,
        AtomicExecFault::None,
        deadline(),
    )
    .unwrap_or_else(|(error, child)| {
        let _ = child.terminate_and_reap(deadline());
        panic!("held exec failed: {error:?}")
    });
    assert_eq!(pidfd_reported_pid(child.pidfd()), i64::from(child.pid()));
    child.resume();
    let status = child.wait_and_reap(deadline());
    assert_complete_direct(status, ExactChildExit::Exited(0));

    let fixture = ExecutableFixture::copy_from(&executable);
    let held = HeldExecutable::open(&fixture.file).unwrap();
    std::fs::remove_file(&fixture.file).unwrap();
    std::fs::copy(REPLACEMENT_IMAGE, &fixture.file).unwrap();
    let environment = atomic_exec_environment(&held);
    let child = atomic_clone_exec_for_test(
        held,
        &atomic_exec_arguments(),
        &environment,
        AtomicExecFault::None,
        deadline(),
    )
    .unwrap_or_else(|(error, child)| {
        let _ = child.terminate_and_reap(deadline());
        panic!("replacement-resistant exec failed: {error:?}")
    });
    child.resume();
    let status = child.wait_and_reap(deadline());
    assert_complete_direct(status, ExactChildExit::Exited(0));
    drop(fixture);

    for (fault, expected) in [
        (
            AtomicExecFault::SetSid,
            AtomicExecError::Child {
                stage: 1,
                errno: libc::EPERM,
            },
        ),
        (
            AtomicExecFault::Mdwe,
            AtomicExecError::Child {
                stage: 2,
                errno: libc::EPERM,
            },
        ),
        (
            AtomicExecFault::Exec,
            AtomicExecError::Child {
                stage: 3,
                errno: libc::ENOENT,
            },
        ),
        (AtomicExecFault::Partial, AtomicExecError::Malformed),
        (AtomicExecFault::Malformed, AtomicExecError::Malformed),
        (
            AtomicExecFault::SilentExit,
            AtomicExecError::ExitedBeforeConfirmation,
        ),
    ] {
        let held = HeldExecutable::open(&executable).unwrap();
        let environment = atomic_exec_environment(&held);
        let (error, child) = match atomic_clone_exec_for_test(
            held,
            &atomic_exec_arguments(),
            &environment,
            fault,
            deadline(),
        ) {
            Ok(child) => {
                let _ = child.terminate_and_reap(deadline());
                panic!("injected child failure unexpectedly execed")
            }
            Err(failure) => failure,
        };
        assert_eq!(error, expected);
        let status = child.wait_and_reap(deadline());
        assert!(matches!(
            status.direct_child,
            Some(ExactChildExit::Exited(_))
        ));
    }

    let held = HeldExecutable::open(&executable).unwrap();
    let environment = atomic_exec_environment(&held);
    let short = AbsoluteDeadline::after(Duration::from_millis(2)).unwrap();
    let (error, child) = match atomic_clone_exec_for_test(
        held,
        &atomic_exec_arguments(),
        &environment,
        AtomicExecFault::Stall,
        short,
    ) {
        Ok(child) => {
            let _ = child.terminate_and_reap(deadline());
            panic!("stalled child bypassed deadline")
        }
        Err(failure) => failure,
    };
    assert_eq!(error, AtomicExecError::Deadline);
    let status = child.terminate_and_reap(deadline());
    assert_complete_direct(
        status,
        ExactChildExit::Signaled {
            signal: libc::SIGKILL,
            dumped_core: false,
        },
    );

    assert_eq!(open_fd_count(), before);
}

#[test]
fn atomic_clone_exec_state_machine_is_bounded() {
    let executable = std::env::current_exe().unwrap();
    let status = Command::new(executable)
        .args([
            "--exact",
            "backend::linux_vnext::process::tests::isolated_atomic_clone_exec_state_machine_helper",
            "--ignored",
            "--nocapture",
        ])
        .status()
        .unwrap();
    assert!(status.success());
}

fn lifecycle_child(deadline: AbsoluteDeadline) -> AtomicExecChild {
    let executable = std::env::current_exe().unwrap();
    let held = HeldExecutable::open(&executable).unwrap();
    let environment = atomic_exec_environment(&held);
    atomic_clone_exec_for_test(
        held,
        &atomic_exec_arguments(),
        &environment,
        AtomicExecFault::None,
        deadline,
    )
    .unwrap_or_else(|(error, child)| {
        drop(child);
        panic!("lifecycle child failed before its checkpoint: {error:?}")
    })
}

fn containment_child(
    mode: &str,
    deadline: AbsoluteDeadline,
) -> (AtomicExecChild, libc::pid_t, OwnedFd, std::path::PathBuf) {
    let executable = std::env::current_exe().unwrap();
    let held = HeldExecutable::open(&executable).unwrap();
    let sequence = FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let pid_file = std::env::temp_dir().join(format!(
        "native-ipc-vnext-descendant-{}-{sequence}",
        std::process::id()
    ));
    let mut environment = atomic_exec_environment(&held);
    environment.push(std::ffi::CString::new(format!("{ENV_CONTAINMENT_MODE}={mode}")).unwrap());
    environment.push(
        std::ffi::CString::new(format!("{ENV_DESCENDANT_PID_FILE}={}", pid_file.display()))
            .unwrap(),
    );
    let child = atomic_clone_exec_for_test(
        held,
        &atomic_exec_arguments(),
        &environment,
        AtomicExecFault::None,
        deadline,
    )
    .unwrap_or_else(|(error, child)| {
        drop(child);
        panic!("containment child failed before its checkpoint: {error:?}")
    });
    let descendant: libc::pid_t = std::fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let descendant_pidfd = open_pidfd(descendant.try_into().unwrap()).unwrap();
    (child, descendant, descendant_pidfd, pid_file)
}

fn wait_for_pidfd_ready(pidfd: RawFd, deadline: AbsoluteDeadline) {
    loop {
        let mut event = libc::pollfd {
            fd: pidfd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: the sole pollfd remains live for this nonblocking query.
        let result = unsafe { libc::poll(&mut event, 1, 0) };
        assert!(result >= 0);
        if result > 0 {
            return;
        }
        assert!(!deadline.is_expired(), "descendant did not terminate");
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn wait_for_descendant_session(descendant: libc::pid_t, pidfd: RawFd, deadline: AbsoluteDeadline) {
    loop {
        // SAFETY: getsid accepts any scalar PID. This controlled descendant
        // remains owned by its live parent while the caller retains its pidfd.
        let session = unsafe { libc::getsid(descendant) };
        if session == descendant {
            return;
        }
        if session == -1 {
            panic!(
                "getsid failed before escaped descendant entered its session: {}",
                io::Error::last_os_error()
            );
        }

        let mut event = libc::pollfd {
            fd: pidfd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: the sole pollfd remains live for this nonblocking exit check.
        let result = unsafe { libc::poll(&mut event, 1, 0) };
        if result == -1 {
            panic!(
                "pidfd poll failed while awaiting escaped descendant session: {}",
                io::Error::last_os_error()
            );
        }
        if result > 0 {
            if event.revents & libc::POLLIN != 0 {
                panic!("escaped descendant exited before entering its own session");
            }
            panic!(
                "unexpected pidfd poll events while awaiting escaped descendant session: {:#x}",
                event.revents
            );
        }
        assert!(
            !deadline.is_expired(),
            "escaped descendant did not enter its own session before the deadline; last SID was {session}"
        );
        std::thread::yield_now();
    }
}

#[test]
#[ignore = "spawned alone by fresh_session_containment_is_precise"]
fn isolated_fresh_session_containment_helper() {
    let before_fds = open_fd_count();
    let before_tasks = open_task_count();
    let deadline = || AbsoluteDeadline::after(Duration::from_secs(5)).unwrap();

    // The ordinary descendant inherits the fresh group. Exact-child cleanup
    // terminates the kernel-verified group while the unreaped direct child
    // still pins its numeric identity, so the ordinary descendant must die
    // without any test-side signal. The kernel exit event on its pidfd is the
    // deterministic observation; the deadline is only a harness escape bound.
    let (ordinary, descendant, descendant_pidfd, pid_file) =
        containment_child("ordinary", deadline());
    assert_eq!(
        // SAFETY: the controlled descendant is live at this checkpoint.
        unsafe { libc::getpgid(descendant) },
        ordinary.pid()
    );
    let cleanup = ordinary.terminate_and_reap(deadline());
    assert!(matches!(
        cleanup.direct_child,
        Some(ExactChildExit::Signaled {
            signal: libc::SIGKILL,
            ..
        })
    ));
    assert_eq!(cleanup.descendants, DescendantCleanup::FreshGroupTerminated);
    wait_for_pidfd_ready(descendant_pidfd.as_raw_fd(), deadline());
    drop(descendant_pidfd);
    std::fs::remove_file(pid_file).unwrap();

    // A malicious descendant can leave the fresh session. The witnessed group
    // termination is still performed and reported, but it must not touch the
    // escaped process; a test-only pidfd is the disposable-helper cleanup
    // backstop.
    let (escaping, descendant, descendant_pidfd, pid_file) =
        containment_child("escape", deadline());
    wait_for_descendant_session(descendant, descendant_pidfd.as_raw_fd(), deadline());
    assert_eq!(
        // SAFETY: the controlled escaped descendant is live.
        unsafe { libc::getsid(descendant) },
        descendant
    );
    let cleanup = escaping.terminate_and_reap(deadline());
    assert!(matches!(
        cleanup.direct_child,
        Some(ExactChildExit::Signaled {
            signal: libc::SIGKILL,
            ..
        })
    ));
    assert_eq!(cleanup.descendants, DescendantCleanup::FreshGroupTerminated);
    let mut event = libc::pollfd {
        fd: descendant_pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: the pidfd remains live for this nonblocking escape check.
    assert_eq!(unsafe { libc::poll(&mut event, 1, 0) }, 0);
    signal_exact_child(descendant_pidfd.as_raw_fd(), libc::SIGKILL).unwrap();
    wait_for_pidfd_ready(descendant_pidfd.as_raw_fd(), deadline());
    drop(descendant_pidfd);
    std::fs::remove_file(pid_file).unwrap();

    assert_eq!(open_fd_count(), before_fds);
    assert_eq!(open_task_count(), before_tasks);
}

#[test]
fn fresh_session_containment_is_precise() {
    let executable = std::env::current_exe().unwrap();
    let status = Command::new(executable)
        .args([
            "--exact",
            "backend::linux_vnext::process::tests::isolated_fresh_session_containment_helper",
            "--ignored",
            "--nocapture",
        ])
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
#[ignore = "spawned alone by exact_child_lifecycle_drop_and_reap_are_bounded"]
fn isolated_exact_child_lifecycle_drop_and_reap_helper() {
    let expected_fds = open_fd_count();
    let expected_tasks = open_task_count();
    let deadline = || AbsoluteDeadline::after(Duration::from_secs(5)).unwrap();

    drop(PreparedExactChildLifecycle::new().unwrap());
    let cancellation_deadline = deadline();
    while open_fd_count() != expected_fds || open_task_count() != expected_tasks {
        assert!(
            !cancellation_deadline.is_expired(),
            "unarmed lifecycle worker did not exit"
        );
        std::thread::sleep(Duration::from_millis(1));
    }

    // Registration is the only fallible lifecycle setup and must complete
    // before clone. Injecting its failure proves that no child can exist when
    // the coordinator cannot first establish a durable cleanup worker.
    let registration = PreparedExactChildLifecycle::new_with_worker(|_| {
        Err(io::Error::from_raw_os_error(libc::EAGAIN))
    });
    assert!(matches!(
        registration,
        Err(SpawnPolicyError::Native(libc::EAGAIN))
    ));
    assert_eq!(open_fd_count(), expected_fds);
    assert_eq!(open_task_count(), expected_tasks);
    // SAFETY: this isolated helper has not cloned a child yet; WNOHANG cannot
    // block and ECHILD proves registration failure acquired no child.
    assert_eq!(
        unsafe { libc::waitpid(-1, core::ptr::null_mut(), libc::WNOHANG) },
        -1
    );
    assert_eq!(
        io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );

    let child = lifecycle_child(deadline());
    let pid = child.pid();
    assert_eq!(pidfd_reported_pid(child.pidfd()), i64::from(pid));
    assert_drop_returns(child);
    wait_for_child_baseline(expected_fds, expected_tasks, pid, deadline());

    let child = lifecycle_child(deadline());
    let pid = child.pid();
    let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _owned_until_unwind = child;
        panic!("injected lifecycle owner panic");
    }));
    assert!(unwind.is_err());
    wait_for_child_baseline(expected_fds, expected_tasks, pid, deadline());

    const CONCURRENT_DROPS: usize = 16;
    let mut children = Vec::with_capacity(CONCURRENT_DROPS);
    let mut pids = Vec::with_capacity(CONCURRENT_DROPS);
    for _ in 0..CONCURRENT_DROPS {
        let child = lifecycle_child(deadline());
        pids.push(child.pid());
        children.push(child);
    }
    let start = std::sync::Arc::new(std::sync::Barrier::new(CONCURRENT_DROPS + 1));
    let droppers: Vec<_> = children
        .into_iter()
        .map(|child| {
            let start = std::sync::Arc::clone(&start);
            std::thread::spawn(move || {
                start.wait();
                drop(child);
            })
        })
        .collect();
    start.wait();
    for dropper in droppers {
        dropper.join().unwrap();
    }
    for pid in pids {
        wait_for_child_baseline(expected_fds, expected_tasks, pid, deadline());
    }

    let executable = std::env::current_exe().unwrap();
    let held = HeldExecutable::open(&executable).unwrap();
    let environment = atomic_exec_environment(&held);
    let short = AbsoluteDeadline::after(Duration::from_millis(2)).unwrap();
    let (error, stalled) = match atomic_clone_exec_for_test(
        held,
        &atomic_exec_arguments(),
        &environment,
        AtomicExecFault::Stall,
        short,
    ) {
        Ok(child) => {
            drop(child);
            panic!("pre-exec stall unexpectedly reached exec")
        }
        Err(failure) => failure,
    };
    assert_eq!(error, AtomicExecError::Deadline);
    let stalled_pid = stalled.pid();
    assert_drop_returns(stalled);
    wait_for_child_baseline(expected_fds, expected_tasks, stalled_pid, deadline());

    let child = lifecycle_child(deadline());
    let pid = child.pid();
    assert_eq!(pidfd_reported_pid(child.pidfd()), i64::from(pid));
    child.inject_signal_interrupts(3);
    let cleanup = child.terminate_and_reap(deadline());
    assert_complete_direct(
        cleanup,
        ExactChildExit::Signaled {
            signal: libc::SIGKILL,
            dumped_core: false,
        },
    );
    wait_for_child_baseline(expected_fds, expected_tasks, pid, deadline());

    let child = lifecycle_child(deadline());
    let pid = child.pid();
    let broad_waiter = std::thread::spawn(|| {
        let mut status = 0;
        // SAFETY: this isolated helper owns exactly one direct child, and the
        // lifecycle worker remains idle until after this broad wait completes.
        let waited = unsafe { libc::waitpid(-1, &mut status, 0) };
        (waited, status)
    });
    child.resume();
    let (waited, status) = broad_waiter.join().unwrap();
    assert_eq!(waited, pid);
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 0);
    let cleanup = child.wait_and_reap(deadline());
    assert_complete_direct(cleanup, ExactChildExit::AlreadyReaped);
    assert_eq!(cleanup.descendants, DescendantCleanup::FreshGroupUnverified);
    wait_for_child_baseline(expected_fds, expected_tasks, pid, deadline());

    let child = lifecycle_child(deadline());
    let pid = child.pid();
    child.inject_signal_interrupts(3);
    let short = AbsoluteDeadline::after(Duration::from_millis(2)).unwrap();
    assert_incomplete_direct(child.terminate_and_reap(short), None);
    // Consuming explicit cleanup has returned, but its pre-established worker
    // still owns the atomic pidfd and eventually exhausts retryable EINTR.
    wait_for_child_baseline(expected_fds, expected_tasks, pid, deadline());

    for cycle in 0..32 {
        let child = lifecycle_child(deadline());
        let pid = child.pid();
        if cycle % 2 == 0 {
            assert_drop_returns(child);
        } else {
            assert_complete_direct(
                child.terminate_and_reap(deadline()),
                ExactChildExit::Signaled {
                    signal: libc::SIGKILL,
                    dumped_core: false,
                },
            );
        }
        wait_for_child_baseline(expected_fds, expected_tasks, pid, deadline());
    }
}

#[test]
#[ignore = "spawned alone by exact_child_lifecycle_drop_and_reap_are_bounded"]
fn isolated_exact_child_terminal_cleanup_failure_helper() {
    let deadline = || AbsoluteDeadline::after(Duration::from_secs(5)).unwrap();

    let child = lifecycle_child(deadline());
    child.inject_signal_failure(libc::EIO);
    assert_incomplete_direct(child.terminate_and_reap(deadline()), Some(libc::EIO));

    let child = lifecycle_child(deadline());
    child.inject_poll_failure(libc::EIO);
    assert_incomplete_direct(child.terminate_and_reap(deadline()), Some(libc::EIO));

    let child = lifecycle_child(deadline());
    child.inject_reap_failure(libc::EIO);
    assert_incomplete_direct(child.terminate_and_reap(deadline()), Some(libc::EIO));

    // These workers deliberately retain their exact pidfds until this isolated
    // process exits. Process teardown is the backstop for simulated terminal
    // failures, which are excluded from baseline-restoration claims.
}

#[test]
fn exact_child_lifecycle_drop_and_reap_are_bounded() {
    let executable = std::env::current_exe().unwrap();
    for helper in [
        "backend::linux_vnext::process::tests::isolated_exact_child_lifecycle_drop_and_reap_helper",
        "backend::linux_vnext::process::tests::isolated_exact_child_terminal_cleanup_failure_helper",
    ] {
        let status = Command::new(&executable)
            .args(["--exact", helper, "--ignored", "--nocapture"])
            .status()
            .unwrap();
        assert!(
            status.success(),
            "isolated lifecycle helper failed: {helper}"
        );
    }
}

fn install_sigchld_disposition(handler: libc::sighandler_t, flags: libc::c_int) {
    // SAFETY: zeroed sigaction is fully initialized before installation.
    let mut action: libc::sigaction = unsafe { core::mem::zeroed() };
    action.sa_sigaction = handler;
    action.sa_flags = flags;
    // SAFETY: mask storage and action are initialized for SIGCHLD.
    assert_eq!(unsafe { libc::sigemptyset(&mut action.sa_mask) }, 0);
    // SAFETY: these helpers run alone in disposable subprocesses.
    assert_eq!(
        unsafe { libc::sigaction(libc::SIGCHLD, &action, core::ptr::null_mut()) },
        0
    );
}

fn exercise_automatic_reap_disposition() {
    let expected_fds = open_fd_count();
    let expected_tasks = open_task_count();
    let deadline = || AbsoluteDeadline::after(Duration::from_secs(5)).unwrap();
    let child = lifecycle_child(deadline());
    let pid = child.pid();
    assert_eq!(pidfd_reported_pid(child.pidfd()), i64::from(pid));
    child.resume();
    let cleanup = child.wait_and_reap(deadline());
    assert_complete_direct(cleanup, ExactChildExit::AlreadyReaped);
    assert_eq!(cleanup.descendants, DescendantCleanup::FreshGroupUnverified);
    wait_for_child_baseline(expected_fds, expected_tasks, pid, deadline());
}

#[test]
#[ignore = "spawned alone by exact_child_lifecycle_handles_sigchld_auto_reap"]
fn isolated_exact_child_lifecycle_sigchld_ignored_helper() {
    install_sigchld_disposition(libc::SIG_IGN, 0);
    exercise_automatic_reap_disposition();
}

#[test]
#[ignore = "spawned alone by exact_child_lifecycle_handles_sigchld_auto_reap"]
fn isolated_exact_child_lifecycle_no_cldwait_helper() {
    install_sigchld_disposition(libc::SIG_DFL, libc::SA_NOCLDWAIT);
    exercise_automatic_reap_disposition();
}

#[test]
fn exact_child_lifecycle_handles_sigchld_auto_reap() {
    let executable = std::env::current_exe().unwrap();
    for helper in [
        "backend::linux_vnext::process::tests::isolated_exact_child_lifecycle_sigchld_ignored_helper",
        "backend::linux_vnext::process::tests::isolated_exact_child_lifecycle_no_cldwait_helper",
    ] {
        let status = Command::new(&executable)
            .args(["--exact", helper, "--ignored", "--nocapture"])
            .status()
            .unwrap();
        assert!(
            status.success(),
            "isolated disposition helper failed: {helper}"
        );
    }
}

#[test]
#[ignore = "spawned alone by clone3_pidfd_survives_ignored_sigchld"]
fn isolated_clone3_pidfd_sigchld_ignored_helper() {
    let before = open_fd_count();

    // This helper is an isolated process, so changing process-global child
    // disposition cannot race any unrelated library user.
    // SAFETY: zeroed sigaction is completed before the syscall.
    let mut action: libc::sigaction = unsafe { core::mem::zeroed() };
    action.sa_sigaction = libc::SIG_IGN;
    // SAFETY: mask storage and action are initialized for SIGCHLD.
    assert_eq!(unsafe { libc::sigemptyset(&mut action.sa_mask) }, 0);
    // SAFETY: installs SIG_IGN in this isolated feasibility helper only.
    assert_eq!(
        unsafe { libc::sigaction(libc::SIGCHLD, &action, core::ptr::null_mut()) },
        0
    );

    let mut pipe = [-1; 2];
    // SAFETY: output has room for two descriptors.
    assert_eq!(
        unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC) },
        0
    );
    // SAFETY: successful pipe2 returned two uniquely owned descriptors.
    let read_end = unsafe { OwnedFd::from_raw_fd(pipe[0]) };
    // SAFETY: successful pipe2 returned two uniquely owned descriptors.
    let write_end = unsafe { OwnedFd::from_raw_fd(pipe[1]) };
    let read_raw = read_end.as_raw_fd();
    let write_raw = write_end.as_raw_fd();

    let mut raw_pidfd: libc::c_int = -1;
    let arguments = CloneArgs {
        flags: CLONE_PIDFD,
        pidfd: (&mut raw_pidfd as *mut libc::c_int) as u64,
        exit_signal: libc::SIGCHLD as u64,
        ..CloneArgs::default()
    };
    // SAFETY: clone_args uses the Linux v2 size (11 u64 fields, 88 bytes)
    // with every extension zero; zero stack/stack_size requests fork-like
    // address-space separation.
    let result = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            &arguments,
            core::mem::size_of::<CloneArgs>(),
        ) as libc::pid_t
    };
    if result == 0 {
        // Child: raw async-signal-safe syscalls only. No Rust destructors,
        // allocation, locks, formatting, panic, or unwinding may run.
        // SAFETY: descriptors were inherited and scalar arguments are valid.
        unsafe {
            libc::close(write_raw);
            let mut release = 0_u8;
            loop {
                let read = libc::read(read_raw, (&mut release as *mut u8).cast(), 1);
                if read == 1 {
                    libc::_exit(if release == b'G' { 37 } else { 111 });
                }
                if read < 0 && *libc::__errno_location() == libc::EINTR {
                    continue;
                }
                libc::_exit(112);
            }
        }
    }
    assert!(result > 0, "clone3 failed: {}", io::Error::last_os_error());
    assert!(raw_pidfd >= 0);
    // SAFETY: successful CLONE_PIDFD atomically installed one owned pidfd.
    let pidfd = unsafe { OwnedFd::from_raw_fd(raw_pidfd) };
    drop(read_end);

    assert_eq!(pidfd_reported_pid(pidfd.as_raw_fd()), i64::from(result));
    // SAFETY: signal zero performs an existence/permission check only.
    assert_eq!(
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                pidfd.as_raw_fd(),
                0,
                core::ptr::null::<libc::siginfo_t>(),
                0,
            )
        },
        0
    );
    // SAFETY: one-byte input is live; the child is blocked on this pipe.
    assert_eq!(
        unsafe { libc::write(write_end.as_raw_fd(), (&b'G' as *const u8).cast(), 1,) },
        1
    );
    drop(write_end);

    let mut event = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: one pollfd remains live for this bounded wait.
    assert_eq!(unsafe { libc::poll(&mut event, 1, 5_000) }, 1);
    assert_ne!(event.revents & libc::POLLIN, 0);
    // SIGCHLD=SIG_IGN auto-reaped the child, but the atomic pidfd remains
    // readable. Kernels vary between retaining the clone-time PID in
    // fdinfo and reporting -1 after reap; signal-zero may likewise still
    // succeed transiently or fail with ESRCH.
    // SAFETY: numeric PID is used only to prove there is no waitable child.
    assert_eq!(
        unsafe { libc::waitpid(result, core::ptr::null_mut(), libc::WNOHANG) },
        -1
    );
    assert_eq!(
        io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
    // SAFETY: signal zero performs an existence/permission check only.
    let signal_zero = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd.as_raw_fd(),
            0,
            core::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    assert!(
        signal_zero == 0
            || (signal_zero == -1
                && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH))
    );
    let reported_pid = pidfd_reported_pid(pidfd.as_raw_fd());
    assert!(reported_pid == -1 || reported_pid == i64::from(result));
    drop(pidfd);
    assert_eq!(open_fd_count(), before);
}

#[test]
fn clone3_pidfd_survives_ignored_sigchld() {
    let executable = std::env::current_exe().unwrap();
    let status = Command::new(executable)
        .args([
            "--exact",
            "backend::linux_vnext::process::tests::isolated_clone3_pidfd_sigchld_ignored_helper",
            "--ignored",
            "--nocapture",
        ])
        .status()
        .unwrap();
    assert!(status.success());
}

#[test]
#[ignore = "spawned alone by zero_exit_signal_zombie_pin_survives_hostile_reaping"]
fn isolated_zero_exit_signal_zombie_pin_helper() {
    let deadline = AbsoluteDeadline::after(Duration::from_secs(10)).unwrap();

    // The production spawn premise under one roof: an ignored SIGCHLD
    // disposition, a concurrent process-global broad waiter, and hostile
    // numeric signals must all fail to release a zero-exit-signal child's
    // identity pin before the sole pidfd owner consumes its status.
    install_sigchld_disposition(libc::SIG_IGN, 0);

    let mut lifecycle_pipe = [-1; 2];
    // SAFETY: output has room for two descriptors.
    assert_eq!(
        unsafe {
            libc::pipe2(
                lifecycle_pipe.as_mut_ptr(),
                libc::O_CLOEXEC | libc::O_NONBLOCK,
            )
        },
        0
    );
    // SAFETY: successful pipe2 returned two uniquely owned descriptors.
    let grandchild_alive = unsafe { OwnedFd::from_raw_fd(lifecycle_pipe[0]) };
    // SAFETY: successful pipe2 returned two uniquely owned descriptors.
    let grandchild_writer = unsafe { OwnedFd::from_raw_fd(lifecycle_pipe[1]) };
    let alive_raw = grandchild_alive.as_raw_fd();
    let writer_raw = grandchild_writer.as_raw_fd();

    let mut raw_pidfd: libc::c_int = -1;
    let arguments = CloneArgs {
        flags: CLONE_PIDFD,
        pidfd: (&mut raw_pidfd as *mut libc::c_int) as u64,
        exit_signal: 0,
        ..CloneArgs::default()
    };
    // SAFETY: fork-like clone3 with an 88-byte zero-extended clone_args.
    let child = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            &arguments,
            core::mem::size_of::<CloneArgs>(),
        ) as libc::pid_t
    };
    if child == 0 {
        // Child: raw async-signal-safe syscalls only. It becomes a fresh
        // session leader, plants one ordinary grandchild that holds the
        // inherited pipe writer open forever, then exits so its zombie is the
        // only thing pinning the fresh group identity.
        // SAFETY: descriptors were inherited and scalar arguments are valid.
        unsafe {
            libc::close(alive_raw);
            if libc::setsid() < 0 {
                libc::_exit(101);
            }
            let grandchild = libc::fork();
            if grandchild < 0 {
                libc::_exit(102);
            }
            if grandchild == 0 {
                loop {
                    libc::pause();
                }
            }
            libc::close(writer_raw);
            libc::_exit(0);
        }
    }
    assert!(child > 0, "clone3 failed: {}", io::Error::last_os_error());
    assert!(raw_pidfd >= 0);
    // SAFETY: successful CLONE_PIDFD atomically installed one owned pidfd.
    let pidfd = unsafe { OwnedFd::from_raw_fd(raw_pidfd) };
    drop(grandchild_writer);

    // A broad waiter races the child's exit from the start and must never
    // select a zero-exit-signal child; it observes ECHILD once no other
    // waitable children exist.
    let broad_waiter = std::thread::spawn(|| {
        let mut status = 0;
        // SAFETY: status output is valid; this isolated helper owns exactly
        // one direct child, which carries no exit signal.
        let waited = unsafe { libc::waitpid(-1, &mut status, 0) };
        (waited, io::Error::last_os_error().raw_os_error())
    });
    let (waited, errno) = broad_waiter.join().unwrap();
    assert_eq!(waited, -1);
    assert_eq!(errno, Some(libc::ECHILD));

    // The child has exited by now or shortly after; the pidfd exit event is
    // the deterministic observation and the deadline only an escape bound.
    wait_for_pidfd_ready(pidfd.as_raw_fd(), deadline);

    // Ignored SIGCHLD did not auto-reap: the zombie still answers queued-exit
    // and group-identity queries.
    let pinned = zombie_pinned_child(pidfd.as_raw_fd()).expect("zombie must stay queued");
    assert_eq!(pinned, child);
    // SAFETY: scalar identity queries about the pinned zombie leader.
    assert_eq!(unsafe { libc::getpgid(child) }, child);
    // SAFETY: scalar identity queries about the pinned zombie leader.
    assert_eq!(unsafe { libc::getsid(child) }, child);

    // Hostile numeric signals cannot dislodge a zombie's identity pin.
    // SAFETY: SIGKILL/SIGCONT to an owned zombie mutate nothing.
    unsafe {
        let _ = libc::kill(child, libc::SIGKILL);
        let _ = libc::kill(child, libc::SIGCONT);
    }
    assert_eq!(zombie_pinned_child(pidfd.as_raw_fd()), Some(child));

    // Group termination under the pin reaches the planted ordinary
    // grandchild: the inherited pipe writer closes only when it dies.
    // SAFETY: the pinned zombie leader proves the numeric group identity.
    assert_eq!(unsafe { libc::killpg(child, libc::SIGKILL) }, 0);
    let mut byte = 0_u8;
    loop {
        // SAFETY: one-byte output buffer is live for this nonblocking read.
        let read = unsafe {
            libc::read(
                grandchild_alive.as_raw_fd(),
                (&mut byte as *mut u8).cast(),
                1,
            )
        };
        if read == 0 {
            break;
        }
        let errno = io::Error::last_os_error().raw_os_error();
        assert!(
            read < 0 && matches!(errno, Some(libc::EINTR | libc::EAGAIN)),
            "unexpected grandchild pipe state: read {read}, errno {errno:?}"
        );
        assert!(
            !deadline.is_expired(),
            "ordinary grandchild survived group termination"
        );
        std::thread::sleep(Duration::from_millis(1));
    }

    // The pin held across the group signal and only the sole owner's __WALL
    // reap releases it.
    assert_eq!(zombie_pinned_child(pidfd.as_raw_fd()), Some(child));
    match reap_exact_child(pidfd.as_raw_fd()) {
        Ok(Some(ExactChildExit::Exited(0))) => {}
        other => panic!("exact reap failed after pinned group termination: {other:?}"),
    }
}

#[test]
fn zero_exit_signal_zombie_pin_survives_hostile_reaping() {
    let executable = std::env::current_exe().unwrap();
    let status = Command::new(executable)
        .args([
            "--exact",
            "backend::linux_vnext::process::tests::isolated_zero_exit_signal_zombie_pin_helper",
            "--ignored",
            "--nocapture",
        ])
        .status()
        .unwrap();
    assert!(status.success());
}
