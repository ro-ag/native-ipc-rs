//! Trusted Linux receiver pre-exec policy.

use core::cell::Cell;
use core::marker::PhantomData;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command};

const PR_SET_MDWE: libc::c_int = 65;
const PR_MDWE_REFUSE_EXEC_GAIN: libc::c_ulong = 1;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const ELF_HEADER_LEN: usize = 64;
#[cfg(target_arch = "x86_64")]
const NATIVE_ELF_MACHINE: u16 = 62;
#[cfg(target_arch = "aarch64")]
const NATIVE_ELF_MACHINE: u16 = 183;

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SpawnPolicyError {
    InvalidExecutable,
    WrongExecutable,
    ExitedBeforeVerification,
    Native(i32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExecutableKey {
    device: u64,
    inode: u64,
}

struct HeldExecutable {
    fd: OwnedFd,
    key: ExecutableKey,
    not_sync: PhantomData<Cell<()>>,
}

/// Race-resistant exact-image evidence that still owns both the original
/// executable artifact and the spawned-but-unreaped child's pidfd.
struct VerifiedExecutable {
    executable: HeldExecutable,
    pidfd: OwnedFd,
    child_pid: u32,
}

impl HeldExecutable {
    fn open(path: &Path) -> Result<Self, SpawnPolicyError> {
        if !path.is_absolute() {
            return Err(SpawnPolicyError::InvalidExecutable);
        }
        let path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
            .map_err(|_| SpawnPolicyError::InvalidExecutable)?;
        let how = OpenHow {
            flags: (libc::O_PATH | libc::O_CLOEXEC) as u64,
            mode: 0,
            resolve: RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
        };
        // SAFETY: path and complete open_how storage remain live for openat2.
        let raw = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                libc::AT_FDCWD,
                path.as_ptr(),
                &how,
                core::mem::size_of::<OpenHow>(),
            ) as RawFd
        };
        if raw < 0 {
            return Err(native_error(io::Error::last_os_error()));
        }
        // SAFETY: successful open returned a new owned descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let (key, mode) = file_key(fd.as_raw_fd())?;
        if mode & libc::S_IFMT != libc::S_IFREG || mode & 0o111 == 0 {
            return Err(SpawnPolicyError::InvalidExecutable);
        }
        validate_native_elf(fd.as_raw_fd())?;
        Ok(Self {
            fd,
            key,
            not_sync: PhantomData,
        })
    }

    fn verify_child(self, child: &mut Child) -> Result<VerifiedExecutable, SpawnPolicyError> {
        if child.try_wait().map_err(native_error)?.is_some() {
            return Err(SpawnPolicyError::ExitedBeforeVerification);
        }
        let child_pid = child.id();
        let pidfd = open_pidfd(child_pid)?;
        let proc_path = std::ffi::CString::new(format!("/proc/{child_pid}/exe"))
            .map_err(|_| SpawnPolicyError::InvalidExecutable)?;
        // SAFETY: path is NUL-terminated and flags have no variadic mode.
        let raw = unsafe { libc::open(proc_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if raw < 0 {
            return Err(native_error(io::Error::last_os_error()));
        }
        // SAFETY: successful open returned a new owned descriptor.
        let actual = unsafe { OwnedFd::from_raw_fd(raw) };
        let (actual_key, _) = file_key(actual.as_raw_fd())?;
        if actual_key != self.key {
            return Err(SpawnPolicyError::WrongExecutable);
        }
        Ok(VerifiedExecutable {
            executable: self,
            pidfd,
            child_pid,
        })
    }

    fn command(&self) -> Command {
        Command::new(format!("/proc/self/fd/{}", self.fd.as_raw_fd()))
    }
}

impl VerifiedExecutable {
    fn child_pid(&self) -> u32 {
        self.child_pid
    }

    fn key(&self) -> ExecutableKey {
        self.executable.key
    }

    fn pidfd(&self) -> RawFd {
        self.pidfd.as_raw_fd()
    }
}

/// Installs the mandatory policy hook without minting authentication evidence.
///
/// A later process owner must combine successful spawn, exact-image identity,
/// authenticated channel state, pidfd lifetime, and bounded cleanup before it
/// may mint a session authority witness. This helper alone proves none of them.
fn install_mdwe_preexec(command: &mut Command) {
    install_mdwe_preexec_inner(command, false);
}

fn install_mdwe_preexec_inner(command: &mut Command, inject_failure: bool) {
    // SAFETY: the closure performs only scalar `prctl` plus inline OS-error
    // construction between fork and exec. Command's exec-error pipe propagates
    // any failure without returning an unowned Child to the coordinator.
    unsafe {
        command.pre_exec(move || {
            if inject_failure {
                return Err(io::Error::from_raw_os_error(libc::EPERM));
            }
            if libc::prctl(
                PR_SET_MDWE,
                PR_MDWE_REFUSE_EXEC_GAIN,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
                0 as libc::c_ulong,
            ) != 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

fn native_error(error: io::Error) -> SpawnPolicyError {
    SpawnPolicyError::Native(error.raw_os_error().unwrap_or(-1))
}

fn file_key(fd: RawFd) -> Result<(ExecutableKey, libc::mode_t), SpawnPolicyError> {
    // SAFETY: output is valid for this live descriptor.
    let mut status: libc::stat = unsafe { core::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut status) } != 0 {
        return Err(native_error(io::Error::last_os_error()));
    }
    Ok((
        ExecutableKey {
            device: status.st_dev,
            inode: status.st_ino,
        },
        status.st_mode,
    ))
}

fn validate_native_elf(fd: RawFd) -> Result<(), SpawnPolicyError> {
    let proc_path = std::ffi::CString::new(format!("/proc/self/fd/{fd}"))
        .map_err(|_| SpawnPolicyError::InvalidExecutable)?;
    // SAFETY: this internal proc path names the already-held exact inode.
    let readable = unsafe { libc::open(proc_path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if readable < 0 {
        return Err(native_error(io::Error::last_os_error()));
    }
    // SAFETY: successful open returned a new owned descriptor.
    let readable = unsafe { OwnedFd::from_raw_fd(readable) };
    let mut header = [0_u8; ELF_HEADER_LEN];
    // SAFETY: output points to bounded writable storage and offset zero is valid.
    let read = unsafe {
        libc::pread(
            readable.as_raw_fd(),
            header.as_mut_ptr().cast(),
            header.len(),
            0,
        )
    };
    let object_type = u16::from_le_bytes([header[16], header[17]]);
    let machine = u16::from_le_bytes([header[18], header[19]]);
    let version = u32::from_le_bytes([header[20], header[21], header[22], header[23]]);
    let header_size = u16::from_le_bytes([header[52], header[53]]);
    if read != ELF_HEADER_LEN as isize
        || header[..4] != *b"\x7fELF"
        || header[4] != 2
        || header[5] != 1
        || header[6] != 1
        || !matches!(object_type, 2 | 3)
        || machine != NATIVE_ELF_MACHINE
        || version != 1
        || usize::from(header_size) != ELF_HEADER_LEN
    {
        return Err(SpawnPolicyError::InvalidExecutable);
    }
    Ok(())
}

fn open_pidfd(pid: u32) -> Result<OwnedFd, SpawnPolicyError> {
    // SAFETY: scalar syscall arguments request a new CLOEXEC pidfd.
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) as RawFd };
    if raw < 0 {
        return Err(native_error(io::Error::last_os_error()));
    }
    // SAFETY: successful pidfd_open returned a new owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

#[cfg(test)]
#[path = "process_test.rs"]
mod tests;
