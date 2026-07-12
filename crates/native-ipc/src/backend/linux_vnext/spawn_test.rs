use super::*;
use static_assertions::{assert_impl_all, assert_not_impl_any};
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::PermissionsExt;
use std::time::Duration;

const PR_GET_MDWE: libc::c_int = 66;

assert_impl_all!(UnauthenticatedLinuxSpawn: Send);
assert_not_impl_any!(UnauthenticatedLinuxSpawn: Sync, Clone);

fn deadline() -> AbsoluteDeadline {
    AbsoluteDeadline::after(Duration::from_secs(5)).unwrap()
}

fn helper_arguments() -> Vec<OsString> {
    [
        "native-ipc-spawn-helper",
        "--exact",
        "backend::linux_vnext::spawn::tests::spawn_helper",
        "--ignored",
        "--nocapture",
    ]
    .into_iter()
    .map(OsString::from)
    .collect()
}

fn open_fd_count() -> usize {
    std::fs::read_dir("/proc/self/fd").unwrap().count()
}

fn open_task_count() -> usize {
    std::fs::read_dir("/proc/self/task").unwrap().count()
}

fn wait_for_baseline(fds: usize, tasks: usize, child_pid: libc::pid_t, deadline: AbsoluteDeadline) {
    loop {
        let children = std::fs::read_to_string("/proc/thread-self/children").unwrap();
        let child_absent = !children
            .split_ascii_whitespace()
            .any(|value| value.parse::<libc::pid_t>() == Ok(child_pid));
        if open_fd_count() == fds && open_task_count() == tasks && child_absent {
            break;
        }
        assert!(
            !deadline.is_expired(),
            "spawn resources did not return to baseline"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    // SAFETY: WNOHANG cannot block. ECHILD proves this exact clone-time PID has
    // no zombie or other waitable direct-child status left in this process.
    assert_eq!(
        unsafe { libc::waitpid(child_pid, core::ptr::null_mut(), libc::WNOHANG) },
        -1
    );
    assert_eq!(
        io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
}

fn spawn(
    fault: SpawnFault,
    operation_deadline: AbsoluteDeadline,
) -> Result<UnauthenticatedLinuxSpawn, LinuxSpawnError> {
    spawn_unauthenticated_with_fault(
        &std::env::current_exe().unwrap(),
        &helper_arguments(),
        &[],
        fault,
        operation_deadline,
    )
}

#[test]
#[ignore = "exec target used only by private atomic spawn tests"]
fn spawn_helper() {
    let raw: RawFd = std::env::var("NATIVE_IPC_VNEXT_BOOTSTRAP_FD")
        .unwrap()
        .parse()
        .unwrap();
    // Check inherited state before any operation that could open/reuse an fd.
    for closed in std::env::var("NATIVE_IPC_VNEXT_EXPECT_CLOSED")
        .unwrap()
        .split(',')
    {
        let mut parts = closed.split(':');
        let fd = parts.next().unwrap().parse::<RawFd>().unwrap();
        let expected_device = parts.next().unwrap().parse::<u64>().unwrap();
        let expected_inode = parts.next().unwrap().parse::<u64>().unwrap();
        assert!(parts.next().is_none());
        // The ELF loader may reuse a closed numeric slot. It must never still
        // identify the original held image, pipe, or socket object.
        // SAFETY: status is complete writable output for this scalar fd query.
        let mut status: libc::stat = unsafe { core::mem::zeroed() };
        let result = unsafe { libc::fstat(fd, &mut status) };
        if result == 0 {
            assert_ne!(
                (status.st_dev, status.st_ino),
                (expected_device, expected_inode)
            );
        } else {
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
        }
    }
    // SAFETY: the trusted raw child intentionally cleared CLOEXEC on only this slot.
    assert_eq!(unsafe { libc::fcntl(raw, libc::F_GETFD) }, 0);
    let mut socket_type = 0_i32;
    let mut length = core::mem::size_of::<i32>() as libc::socklen_t;
    // SAFETY: output and its exact length remain valid for getsockopt.
    assert_eq!(
        unsafe {
            libc::getsockopt(
                raw,
                libc::SOL_SOCKET,
                libc::SO_TYPE,
                (&mut socket_type as *mut i32).cast(),
                &mut length,
            )
        },
        0
    );
    assert_eq!(socket_type, libc::SOCK_SEQPACKET);
    // SAFETY: scalar MDWE and identity queries have no pointer arguments.
    assert_eq!(
        unsafe { libc::prctl(PR_GET_MDWE, 0, 0, 0, 0) } as libc::c_ulong,
        PR_MDWE_REFUSE_EXEC_GAIN
    );
    let pid = unsafe { libc::getpid() };
    assert_eq!(unsafe { libc::getsid(0) }, pid);
    assert_eq!(unsafe { libc::getpgrp() }, pid);
    loop {
        // SAFETY: pause blocks this disposable helper until exact pidfd cleanup.
        unsafe { libc::pause() };
    }
}

#[test]
fn input_validation_precedes_clone() {
    let executable = std::env::current_exe().unwrap();
    let arguments = helper_arguments();
    assert_eq!(
        spawn_unauthenticated(
            &executable,
            &arguments,
            &[(
                OsString::from("NATIVE_IPC_VNEXT_BOOTSTRAP_FD"),
                OsString::from("9")
            )],
            deadline(),
        )
        .err()
        .unwrap(),
        LinuxSpawnError::InvalidInput
    );
    assert_eq!(
        spawn_unauthenticated(
            &executable,
            &[OsString::from_vec(b"bad\0argument".to_vec())],
            &[],
            deadline(),
        )
        .err()
        .unwrap(),
        LinuxSpawnError::InvalidInput
    );
    assert_eq!(
        spawn_unauthenticated(
            &executable,
            &arguments,
            &[(
                OsString::from_vec(b"BAD\0KEY".to_vec()),
                OsString::from("x")
            )],
            deadline(),
        )
        .err()
        .unwrap(),
        LinuxSpawnError::InvalidInput
    );
}

#[test]
#[ignore = "spawned alone by atomic_spawn_success_and_failures_restore_baseline"]
fn isolated_atomic_spawn_success_and_failures_restore_baseline() {
    let before_fds = open_fd_count();
    let before_tasks = open_task_count();

    let owner = spawn(SpawnFault::None, deadline()).unwrap();
    let pid = owner.pid();
    assert!(pid > 0);
    owner.terminate_and_reap(deadline());
    wait_for_baseline(before_fds, before_tasks, pid, deadline());

    for (fault, expected) in [
        (
            SpawnFault::CloseRange,
            LinuxSpawnError::Child {
                stage: 1,
                errno: libc::EPERM,
            },
        ),
        (
            SpawnFault::BootstrapFd,
            LinuxSpawnError::Child {
                stage: 2,
                errno: libc::EPERM,
            },
        ),
        (
            SpawnFault::SetSid,
            LinuxSpawnError::Child {
                stage: 3,
                errno: libc::EPERM,
            },
        ),
        (
            SpawnFault::Mdwe,
            LinuxSpawnError::Child {
                stage: 4,
                errno: libc::EPERM,
            },
        ),
        (
            SpawnFault::Exec,
            LinuxSpawnError::Child {
                stage: 5,
                errno: libc::ENOENT,
            },
        ),
        (SpawnFault::Partial, LinuxSpawnError::MalformedChildError),
        (SpawnFault::Malformed, LinuxSpawnError::MalformedChildError),
    ] {
        assert_eq!(spawn(fault, deadline()).err().unwrap(), expected);
        let pid = LAST_SPAWN_PID.with(|slot| slot.get());
        assert!(pid > 0);
        wait_for_baseline(before_fds, before_tasks, pid, deadline());
    }

    // A silent child can disappear from /proc before pidfd readiness becomes
    // observable, or readiness can win first. Both are exact fail-closed
    // terminal observations of the same owned child.
    for _ in 0..16 {
        assert!(matches!(
            spawn(SpawnFault::SilentExit, deadline()).err().unwrap(),
            LinuxSpawnError::ExitedBeforeConfirmation | LinuxSpawnError::WrongExecutable
        ));
        let pid = LAST_SPAWN_PID.with(|slot| slot.get());
        assert!(pid > 0);
        wait_for_baseline(before_fds, before_tasks, pid, deadline());
    }

    let short = AbsoluteDeadline::after(Duration::from_millis(2)).unwrap();
    assert_eq!(
        spawn(SpawnFault::Stall, short).err().unwrap(),
        LinuxSpawnError::DeadlineExpired
    );
    let pid = LAST_SPAWN_PID.with(|slot| slot.get());
    wait_for_baseline(before_fds, before_tasks, pid, deadline());

    for cycle in 0..24 {
        let owner = spawn(SpawnFault::None, deadline()).unwrap();
        let pid = owner.pid();
        if cycle % 3 == 0 {
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
                let _owner = owner;
                panic!("spawn owner unwind");
            }));
            assert!(result.is_err());
        } else {
            drop(owner);
        }
        wait_for_baseline(before_fds, before_tasks, pid, deadline());
    }
}

#[test]
fn atomic_spawn_success_and_failures_restore_baseline() {
    run_isolated(
        "backend::linux_vnext::spawn::tests::isolated_atomic_spawn_success_and_failures_restore_baseline",
    );
}

#[test]
#[ignore = "spawned alone by held_path_replacement_and_occupied_fds_do_not_change_identity_or_slot"]
fn isolated_held_path_replacement_and_occupied_fds_do_not_change_identity_or_slot() {
    let before_fds = open_fd_count();
    let before_tasks = open_task_count();
    let directory = std::env::temp_dir().join(format!("native-ipc-spawn-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("helper");
    std::fs::copy(std::env::current_exe().unwrap(), &path).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();

    let occupied: Vec<OwnedFd> = (0..48)
        .map(|_| {
            let raw =
                unsafe { libc::open(c"/dev/null".as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
            assert!(raw >= 0);
            unsafe { OwnedFd::from_raw_fd(raw) }
        })
        .collect();
    let held = HeldExecutable::open(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    std::fs::copy("/bin/sh", &path).unwrap();
    let owner = spawn_held_with_fault(held, &helper_arguments(), &[], SpawnFault::None, deadline())
        .unwrap();
    let pid = owner.pid();
    owner.terminate_and_reap(deadline());
    drop(occupied);
    std::fs::remove_dir_all(directory).unwrap();
    wait_for_baseline(before_fds, before_tasks, pid, deadline());
}

#[test]
fn held_path_replacement_and_occupied_fds_do_not_change_identity_or_slot() {
    run_isolated(
        "backend::linux_vnext::spawn::tests::isolated_held_path_replacement_and_occupied_fds_do_not_change_identity_or_slot",
    );
}

fn run_isolated(test: &str) {
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test, "--ignored", "--nocapture"])
        .status()
        .unwrap();
    assert!(status.success(), "isolated spawn test failed: {test}");
}
