//! Private, pre-authentication Linux exact-child spawn owner.

use core::cell::Cell;
use core::marker::PhantomData;
use std::ffi::{CString, OsString};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use crate::session::AbsoluteDeadline;

use super::SeqPacketEndpoint;
use super::process::{ExactChildLifecycle, HeldExecutable, PreparedExactChildLifecycle};

const CLONE_PIDFD: u64 = 0x0000_1000;
const CLOSE_RANGE_CLOEXEC: libc::c_uint = 1 << 2;
const PR_SET_MDWE: libc::c_int = 65;
const PR_MDWE_REFUSE_EXEC_GAIN: libc::c_ulong = 1;
const EXEC_ERROR_LEN: usize = 8;
const BOOTSTRAP_ENV: &[u8] = b"NATIVE_IPC_VNEXT_BOOTSTRAP_FD";
#[cfg(test)]
std::thread_local! {
    static LAST_SPAWN_PID: Cell<libc::pid_t> = const { Cell::new(0) };
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

#[repr(C)]
struct RawChildError {
    stage: u32,
    errno: i32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LinuxSpawnError {
    InvalidInput,
    DeadlineExpired,
    MalformedChildError,
    Child { stage: u32, errno: i32 },
    ExitedBeforeConfirmation,
    WrongExecutable,
    Native(i32),
}

#[derive(Clone, Copy)]
enum SpawnFault {
    None,
    CloseRange,
    BootstrapFd,
    SetSid,
    Mdwe,
    Exec,
    Partial,
    Malformed,
    Stall,
    SilentExit,
}

/// Exact child and anonymous bootstrap topology before any peer authentication.
///
/// This owner deliberately has no transport, descriptor-transfer, receipt,
/// session, negotiation, or memory-authority methods.
struct UnauthenticatedLinuxSpawn {
    lifecycle: Option<ExactChildLifecycle>,
    _endpoint: SeqPacketEndpoint,
    _executable: HeldExecutable,
    not_sync: PhantomData<Cell<()>>,
}

impl UnauthenticatedLinuxSpawn {
    fn pid(&self) -> libc::pid_t {
        self.lifecycle.as_ref().expect("live spawn owner").pid()
    }

    fn pidfd(&self) -> RawFd {
        self.lifecycle.as_ref().expect("live spawn owner").pidfd()
    }

    fn terminate_and_reap(mut self, deadline: AbsoluteDeadline) {
        if let Some(lifecycle) = self.lifecycle.take() {
            let _ = lifecycle.terminate_and_reap(deadline);
        }
    }
}

fn spawn_unauthenticated(
    executable: &Path,
    arguments: &[OsString],
    environment: &[(OsString, OsString)],
    deadline: AbsoluteDeadline,
) -> Result<UnauthenticatedLinuxSpawn, LinuxSpawnError> {
    spawn_unauthenticated_with_fault(
        executable,
        arguments,
        environment,
        SpawnFault::None,
        deadline,
    )
}

fn spawn_unauthenticated_with_fault(
    executable: &Path,
    arguments: &[OsString],
    environment: &[(OsString, OsString)],
    fault: SpawnFault,
    deadline: AbsoluteDeadline,
) -> Result<UnauthenticatedLinuxSpawn, LinuxSpawnError> {
    if deadline.is_expired() || arguments.is_empty() {
        return Err(if deadline.is_expired() {
            LinuxSpawnError::DeadlineExpired
        } else {
            LinuxSpawnError::InvalidInput
        });
    }
    let held = HeldExecutable::open(executable).map_err(|_| LinuxSpawnError::InvalidInput)?;
    spawn_held_with_fault(held, arguments, environment, fault, deadline)
}

fn spawn_held_with_fault(
    held: HeldExecutable,
    arguments: &[OsString],
    environment: &[(OsString, OsString)],
    fault: SpawnFault,
    deadline: AbsoluteDeadline,
) -> Result<UnauthenticatedLinuxSpawn, LinuxSpawnError> {
    let prepared_lifecycle =
        PreparedExactChildLifecycle::new().map_err(|_| LinuxSpawnError::Native(-1))?;
    let (parent_endpoint, child_endpoint) = SeqPacketEndpoint::pair().map_err(packet_native)?;

    // A new descriptor chosen by the kernel cannot collide with the held image,
    // socketpair, error pipe, or any caller-owned descriptor.
    let inherited_raw =
        unsafe { libc::fcntl(child_endpoint.fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
    if inherited_raw < 0 {
        return Err(last_native());
    }
    // SAFETY: F_DUPFD_CLOEXEC returned a new uniquely owned descriptor.
    let inherited = unsafe { OwnedFd::from_raw_fd(inherited_raw) };

    let mut pipe = [-1; 2];
    // SAFETY: output has room for exactly two descriptors.
    if unsafe { libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) } != 0 {
        return Err(last_native());
    }
    // SAFETY: successful pipe2 returned two distinct owned descriptors.
    let reader = unsafe { OwnedFd::from_raw_fd(pipe[0]) };
    // SAFETY: successful pipe2 returned two distinct owned descriptors.
    let writer = unsafe { OwnedFd::from_raw_fd(pipe[1]) };
    let reader_raw = reader.as_raw_fd();
    let writer_raw = writer.as_raw_fd();
    let held_raw = held.raw_fd();
    let argv = encode_arguments(arguments)?;
    let env = encode_environment(environment, inherited_raw)?;
    #[cfg(test)]
    let env = {
        let mut env = env;
        let closed = [
            held_raw,
            reader_raw,
            writer_raw,
            parent_endpoint.fd.as_raw_fd(),
            child_endpoint.fd.as_raw_fd(),
        ]
        .into_iter()
        .map(|fd| {
            let (device, inode) = descriptor_identity(fd);
            format!("{fd}:{device}:{inode}")
        })
        .collect::<Vec<_>>()
        .join(",");
        env.push(
            CString::new(format!("NATIVE_IPC_VNEXT_EXPECT_CLOSED={closed}"))
                .expect("trusted test environment"),
        );
        env
    };
    let mut argv_ptrs: Vec<*const libc::c_char> = argv.iter().map(|v| v.as_ptr()).collect();
    argv_ptrs.push(core::ptr::null());
    let mut env_ptrs: Vec<*const libc::c_char> = env.iter().map(|v| v.as_ptr()).collect();
    env_ptrs.push(core::ptr::null());
    let argv_raw = argv_ptrs.as_ptr();
    let env_raw = env_ptrs.as_ptr();
    let fault_code = fault as u8;

    // Argument/environment preparation and native acquisition must not turn an
    // already-expired operation into process creation.
    if deadline.is_expired() {
        return Err(LinuxSpawnError::DeadlineExpired);
    }

    let mut raw_pidfd = -1;
    let clone_arguments = CloneArgs {
        flags: CLONE_PIDFD,
        pidfd: (&mut raw_pidfd as *mut libc::c_int) as u64,
        exit_signal: libc::SIGCHLD as u64,
        ..CloneArgs::default()
    };
    // SAFETY: fork-like clone3 receives a complete zero-extended clone_args.
    let pid = unsafe {
        libc::syscall(
            libc::SYS_clone3,
            &clone_arguments,
            core::mem::size_of::<CloneArgs>(),
        ) as libc::pid_t
    };
    if pid == 0 {
        // Child audit: only raw close/close_range/fcntl/setsid/prctl/execveat,
        // write/errno/_exit operations use parent-prebuilt pointers and fds.
        unsafe {
            libc::close(reader_raw);
            if libc::syscall(
                libc::SYS_close_range,
                0_u32,
                libc::c_uint::MAX,
                CLOSE_RANGE_CLOEXEC,
            ) != 0
                || fault_code == SpawnFault::CloseRange as u8
            {
                let errno = if fault_code == SpawnFault::CloseRange as u8 {
                    libc::EPERM
                } else {
                    *libc::__errno_location()
                };
                child_error(writer_raw, 1, errno);
            }
            if fault_code == SpawnFault::Partial as u8 {
                let record = RawChildError {
                    stage: 2_u32.to_le(),
                    errno: libc::EPERM.to_le(),
                };
                libc::write(writer_raw, (&record as *const RawChildError).cast(), 3);
                libc::_exit(121);
            }
            if fault_code == SpawnFault::Malformed as u8 {
                child_error(writer_raw, 99, libc::EINVAL);
            }
            if fault_code == SpawnFault::Stall as u8 {
                loop {
                    libc::pause();
                }
            }
            if fault_code == SpawnFault::SilentExit as u8 {
                libc::_exit(122);
            }
            if fault_code == SpawnFault::BootstrapFd as u8
                || libc::fcntl(inherited_raw, libc::F_SETFD, 0) != 0
            {
                child_error(writer_raw, 2, libc::EPERM);
            }
            if fault_code == SpawnFault::SetSid as u8 {
                child_error(writer_raw, 3, libc::EPERM);
            }
            if libc::setsid() < 0 {
                child_error(writer_raw, 3, *libc::__errno_location());
            }
            if fault_code == SpawnFault::Mdwe as u8 {
                child_error(writer_raw, 4, libc::EPERM);
            }
            if libc::prctl(
                PR_SET_MDWE,
                PR_MDWE_REFUSE_EXEC_GAIN,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
            ) != 0
            {
                child_error(writer_raw, 4, *libc::__errno_location());
            }
            if fault_code == SpawnFault::Exec as u8 {
                child_error(writer_raw, 5, libc::ENOENT);
            }
            libc::syscall(
                libc::SYS_execveat,
                held_raw,
                c"".as_ptr(),
                argv_raw,
                env_raw,
                libc::AT_EMPTY_PATH,
            );
            child_error(writer_raw, 5, *libc::__errno_location());
        }
    }
    if pid < 0 || raw_pidfd < 0 {
        return Err(last_native());
    }
    #[cfg(test)]
    LAST_SPAWN_PID.with(|slot| slot.set(pid));
    // SAFETY: CLONE_PIDFD atomically installed this sole descriptor.
    let pidfd = unsafe { OwnedFd::from_raw_fd(raw_pidfd) };
    let lifecycle = prepared_lifecycle
        .arm(pid, pidfd)
        .map_err(|_| LinuxSpawnError::Native(-1))?;
    drop(writer);
    drop(inherited);
    drop(child_endpoint);
    let mut owner = UnauthenticatedLinuxSpawn {
        lifecycle: Some(lifecycle),
        _endpoint: parent_endpoint,
        _executable: held,
        not_sync: PhantomData,
    };

    let result = await_exec_result(&reader, &mut owner, deadline);
    if let Err(error) = result {
        owner.terminate_and_reap(deadline);
        return Err(error);
    }
    Ok(owner)
}

fn await_exec_result(
    reader: &OwnedFd,
    owner: &mut UnauthenticatedLinuxSpawn,
    deadline: AbsoluteDeadline,
) -> Result<(), LinuxSpawnError> {
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
            if received == EXEC_ERROR_LEN {
                let stage = u32::from_le_bytes(record[..4].try_into().expect("fixed range"));
                let errno = i32::from_le_bytes(record[4..].try_into().expect("fixed range"));
                if !(1..=5).contains(&stage) || errno <= 0 {
                    return Err(LinuxSpawnError::MalformedChildError);
                }
                if stage >= 4 {
                    owner
                        .lifecycle
                        .as_ref()
                        .expect("live spawn owner")
                        .establish_fresh_session();
                }
                return Err(LinuxSpawnError::Child { stage, errno });
            }
            continue;
        }
        if read == 0 {
            if received != 0 {
                return Err(LinuxSpawnError::MalformedChildError);
            }
            owner
                .lifecycle
                .as_ref()
                .expect("live spawn owner")
                .establish_fresh_session();
            ensure_live(owner.pidfd(), deadline)?;
            if !owner._executable.matches_process_image(owner.pid()) {
                return Err(LinuxSpawnError::WrongExecutable);
            }
            ensure_live(owner.pidfd(), deadline)?;
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            if deadline.is_expired() {
                return Err(LinuxSpawnError::DeadlineExpired);
            }
            continue;
        }
        if error.kind() != io::ErrorKind::WouldBlock {
            return Err(LinuxSpawnError::Native(error.raw_os_error().unwrap_or(-1)));
        }
        poll_exec(reader.as_raw_fd(), owner.pidfd(), deadline)?;
    }
}

fn ensure_live(pidfd: RawFd, deadline: AbsoluteDeadline) -> Result<(), LinuxSpawnError> {
    loop {
        if deadline.is_expired() {
            return Err(LinuxSpawnError::DeadlineExpired);
        }
        let mut event = libc::pollfd {
            fd: pidfd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: event is one live poll descriptor.
        let result = unsafe { libc::poll(&mut event, 1, 0) };
        if result < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(last_native());
        }
        if result != 0 || event.revents != 0 {
            return Err(LinuxSpawnError::ExitedBeforeConfirmation);
        }
        return Ok(());
    }
}

fn poll_exec(
    reader: RawFd,
    pidfd: RawFd,
    deadline: AbsoluteDeadline,
) -> Result<(), LinuxSpawnError> {
    loop {
        let remaining = deadline.remaining();
        if remaining.is_zero() {
            return Err(LinuxSpawnError::DeadlineExpired);
        }
        let timeout = remaining
            .as_nanos()
            .div_ceil(1_000_000)
            .min(i32::MAX as u128) as libc::c_int;
        let mut events = [
            libc::pollfd {
                fd: reader,
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: pidfd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: both initialized entries remain live for the bounded poll.
        let result = unsafe { libc::poll(events.as_mut_ptr(), 2, timeout) };
        if result < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(last_native());
        }
        if deadline.is_expired() {
            return Err(LinuxSpawnError::DeadlineExpired);
        }
        if events[0].revents != 0 {
            return Ok(());
        }
        if events[1].revents != 0 {
            return Err(LinuxSpawnError::ExitedBeforeConfirmation);
        }
    }
}

fn encode_arguments(arguments: &[OsString]) -> Result<Vec<CString>, LinuxSpawnError> {
    arguments
        .iter()
        .map(|value| {
            CString::new(value.as_os_str().as_bytes()).map_err(|_| LinuxSpawnError::InvalidInput)
        })
        .collect()
}

fn encode_environment(
    environment: &[(OsString, OsString)],
    inherited_fd: RawFd,
) -> Result<Vec<CString>, LinuxSpawnError> {
    let mut encoded = Vec::with_capacity(environment.len() + 1);
    for (key, value) in environment {
        let key = key.as_os_str().as_bytes();
        let value = value.as_os_str().as_bytes();
        if key.is_empty()
            || key.contains(&0)
            || key.contains(&b'=')
            || key == BOOTSTRAP_ENV
            || value.contains(&0)
        {
            return Err(LinuxSpawnError::InvalidInput);
        }
        let mut entry = Vec::with_capacity(key.len() + value.len() + 1);
        entry.extend_from_slice(key);
        entry.push(b'=');
        entry.extend_from_slice(value);
        encoded.push(CString::new(entry).map_err(|_| LinuxSpawnError::InvalidInput)?);
    }
    encoded.push(
        CString::new(format!(
            "{}={inherited_fd}",
            core::str::from_utf8(BOOTSTRAP_ENV).expect("ASCII key")
        ))
        .expect("trusted bootstrap environment"),
    );
    Ok(encoded)
}

unsafe fn child_error(fd: RawFd, stage: u32, errno: i32) -> ! {
    let record = RawChildError {
        stage: stage.to_le(),
        errno: errno.to_le(),
    };
    let mut written = 0_usize;
    let mut interrupts = 0_u8;
    while written < EXEC_ERROR_LEN && interrupts < 16 {
        // SAFETY: the fixed stack record remains live for this bounded write.
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
    // SAFETY: the raw child cannot unwind or run Rust destructors.
    unsafe { libc::_exit(120) }
}

fn packet_native(error: super::PacketError) -> LinuxSpawnError {
    match error {
        super::PacketError::Native(code) => LinuxSpawnError::Native(code),
        _ => LinuxSpawnError::Native(-1),
    }
}

fn last_native() -> LinuxSpawnError {
    LinuxSpawnError::Native(io::Error::last_os_error().raw_os_error().unwrap_or(-1))
}

#[cfg(test)]
fn descriptor_identity(fd: RawFd) -> (u64, u64) {
    // SAFETY: status is complete writable output for this live descriptor.
    let mut status: libc::stat = unsafe { core::mem::zeroed() };
    // SAFETY: fstat reads metadata for the live descriptor only.
    assert_eq!(unsafe { libc::fstat(fd, &mut status) }, 0);
    (status.st_dev, status.st_ino)
}

#[cfg(test)]
#[path = "spawn_test.rs"]
mod tests;
