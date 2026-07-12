//! Trusted Linux receiver pre-exec policy.

use std::io;
use std::os::unix::process::CommandExt;
use std::process::Command;

const PR_SET_MDWE: libc::c_int = 65;
const PR_GET_MDWE: libc::c_int = 66;
const PR_MDWE_REFUSE_EXEC_GAIN: libc::c_ulong = 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SpawnPolicyError {
    Native(i32),
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

    const ENV_DESCENDANT: &str = "NATIVE_IPC_MDWE_DESCENDANT";
    const PR_MDWE_NO_INHERIT: libc::c_ulong = 2;

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
    fn trusted_preexec_mdwe_is_exact_irreversible_and_inherited() {
        let executable = std::env::current_exe().unwrap();
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
        let mut child = command.spawn().unwrap();
        assert!(child.wait().unwrap().success());
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
