//! Trusted Linux receiver pre-exec policy.

use core::cell::Cell;
use core::marker::PhantomData;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command};

const PR_SET_MDWE: libc::c_int = 65;
const PR_GET_MDWE: libc::c_int = 66;
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

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::{assert_impl_all, assert_not_impl_any};
    use std::io::Write;
    use std::os::unix::fs::{PermissionsExt, symlink};
    use std::sync::atomic::{AtomicU64, Ordering};

    const ENV_DESCENDANT: &str = "NATIVE_IPC_MDWE_DESCENDANT";
    const PR_MDWE_NO_INHERIT: libc::c_ulong = 2;
    static FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(1);

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

    fn open_fd_count() -> usize {
        std::fs::read_dir("/proc/self/fd").unwrap().count()
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
        assert_eq!(get_mdwe().unwrap(), PR_MDWE_REFUSE_EXEC_GAIN);
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
        let mut command = Command::new(executable);
        command
            .args([
                "--exact",
                "backend::linux_vnext::process::tests::exact_image_mdwe_helper",
                "--ignored",
                "--nocapture",
            ])
            .env_remove(ENV_DESCENDANT);
        install_mdwe_preexec(&mut command);
        let mut child = TestChild::spawn(&mut command, true);
        let child_pid = child.child_mut().id();
        let verified = held.verify_child(child.child_mut()).unwrap();
        assert_eq!(verified.child_pid(), child_pid);
        assert!(verified.pidfd() >= 0);
        assert_ne!(verified.key().inode, 0);
        child.wait_success();
        drop(verified);
        assert_eq!(open_fd_count(), before);

        let before = open_fd_count();
        let executable = std::env::current_exe().unwrap();
        let held = HeldExecutable::open(&executable).unwrap();
        let mut command = Command::new("/bin/sleep");
        command.arg("30");
        let mut child = TestChild::spawn(&mut command, true);
        assert!(matches!(
            held.verify_child(child.child_mut()),
            Err(SpawnPolicyError::WrongExecutable)
        ));
        drop(child);
        assert_eq!(open_fd_count(), before);

        let executable = std::env::current_exe().unwrap();
        let held = HeldExecutable::open(&executable).unwrap();
        let mut exited = Command::new("/bin/true").spawn().unwrap();
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
}
