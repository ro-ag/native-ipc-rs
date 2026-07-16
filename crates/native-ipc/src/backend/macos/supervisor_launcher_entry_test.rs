use super::*;

const DEPLOYER_LAUNCHER_PATH: &std::ffi::CStr =
    c"/example/NativeIPC.app/Contents/Helpers/native-ipc-launcher";
const LAUNCHD_LOOKUP_PROBE: &str =
    "backend::macos::supervisor::launcher_entry::tests::launchd_lookup_probe_helper";
const LAUNCHD_LOOKUP_PROBE_ENV: &str = "NATIVE_IPC_LAUNCHD_LOOKUP_PROBE";
const LOOKUP_ALLOWED_EXIT: i32 = 78;
const LOOKUP_DENIED_EXIT: i32 = 79;
const TASK_BOOTSTRAP_PORT: c_int = 4;

unsafe extern "C" {
    static mach_task_self_: u32;
    fn bootstrap_look_up(
        bootstrap_port: u32,
        service_name: *const c_char,
        service_port: *mut u32,
    ) -> c_int;
    fn mach_port_deallocate(task: u32, name: u32) -> c_int;
    fn task_get_special_port(task: u32, which: c_int, port: *mut u32) -> c_int;
}

#[test]
fn fixed_arguments_accept_only_the_installed_launcher_vector() {
    let good = [
        DEPLOYER_LAUNCHER_PATH.to_str().unwrap(),
        INSTALLED_LAUNCHER_MODE,
        INSTALLED_LAUNCHER_DEATH_ARGUMENT,
        INSTALLED_LAUNCHER_PLAN_ARGUMENT,
    ];
    assert_eq!(
        validate_fixed_arguments(DEPLOYER_LAUNCHER_PATH, good),
        Ok(())
    );

    // No request value may reach this vector, so every deviation is refused
    // rather than interpreted.
    let cases: [&[&str]; 6] = [
        &[],
        &[DEPLOYER_LAUNCHER_PATH.to_str().unwrap()],
        &[
            "/usr/bin/true",
            INSTALLED_LAUNCHER_MODE,
            INSTALLED_LAUNCHER_DEATH_ARGUMENT,
            INSTALLED_LAUNCHER_PLAN_ARGUMENT,
        ],
        &[
            DEPLOYER_LAUNCHER_PATH.to_str().unwrap(),
            "--other-mode",
            INSTALLED_LAUNCHER_DEATH_ARGUMENT,
            INSTALLED_LAUNCHER_PLAN_ARGUMENT,
        ],
        &[
            DEPLOYER_LAUNCHER_PATH.to_str().unwrap(),
            INSTALLED_LAUNCHER_MODE,
            "--broker-death-fd=9",
            INSTALLED_LAUNCHER_PLAN_ARGUMENT,
        ],
        &[
            DEPLOYER_LAUNCHER_PATH.to_str().unwrap(),
            INSTALLED_LAUNCHER_MODE,
            INSTALLED_LAUNCHER_DEATH_ARGUMENT,
            INSTALLED_LAUNCHER_PLAN_ARGUMENT,
            "--extra",
        ],
    ];
    for case in cases {
        assert_eq!(
            validate_fixed_arguments(DEPLOYER_LAUNCHER_PATH, case.iter().copied()),
            Err(LauncherEntryError::InvalidArguments),
            "vector {case:?} must be refused",
        );
    }
    assert_eq!(
        validate_fixed_arguments(
            c"relative-launcher",
            [
                "relative-launcher",
                INSTALLED_LAUNCHER_MODE,
                INSTALLED_LAUNCHER_DEATH_ARGUMENT,
                INSTALLED_LAUNCHER_PLAN_ARGUMENT,
            ],
        ),
        Err(LauncherEntryError::InvalidArguments),
    );
}

#[test]
fn broker_death_is_the_only_clean_launcher_exit() {
    // A launcher that loses its broker has nothing left to be exact about and
    // must exit cleanly. Every other refusal is a distinct nonzero status so a
    // fixture can tell them apart, and none may collide.
    assert_eq!(LauncherEntryError::BrokerGone.status(), 0);
    let refusals = [
        LauncherEntryError::InvalidArguments,
        LauncherEntryError::InvalidDescriptor,
        LauncherEntryError::TraceRefused,
        LauncherEntryError::Plan,
        LauncherEntryError::IdentityMismatch,
        LauncherEntryError::InvalidTarget,
        LauncherEntryError::ContainmentRefused,
    ];
    let mut seen = std::collections::HashSet::new();
    for refusal in refusals {
        let status = refusal.status();
        assert_ne!(status, 0, "{refusal:?} must not look like a clean exit");
        assert!(seen.insert(status), "{refusal:?} reuses status {status}");
    }
}

#[test]
fn the_sandbox_profile_denies_signals_launchd_and_survives_exec() {
    // The load-bearing containment claim: without it a target can SIGSTOP the
    // broker and suspend all cleanup, which is the sole reason this design once
    // required a privileged watchdog. Applying the profile to this process
    // would poison the whole test binary, so it is exercised in throwaway
    // children that report through their exit status.
    let mut victim = std::process::Command::new("/bin/sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let victim_pid = i32::try_from(victim.id()).unwrap();

    let attack = format!("kill -STOP {victim_pid} 2>/dev/null && exit 9; exit 7");
    let contained = std::process::Command::new("/usr/bin/sandbox-exec")
        .arg("-p")
        .arg(LAUNCHER_SANDBOX_PROFILE)
        .arg("/bin/sh")
        .arg("-c")
        .arg(&attack)
        .status()
        .unwrap();
    // 7 means the signal was refused; 9 means the attack landed.
    assert_eq!(
        contained.code(),
        Some(7),
        "the launcher profile must deny outbound signals",
    );

    // A stopped victim would mean the profile let the attack through.
    let state = std::process::Command::new("/bin/ps")
        .args(["-o", "state=", "-p"])
        .arg(victim_pid.to_string())
        .output()
        .unwrap();
    let state = String::from_utf8_lossy(&state.stdout).trim().to_owned();
    assert!(
        !state.starts_with('T'),
        "victim was stopped, so the profile did not contain the attack: {state:?}",
    );

    // Self-signalling must still work or real targets break: raise, abort, and
    // pthread_kill all depend on it.
    let self_signal = std::process::Command::new("/usr/bin/sandbox-exec")
        .arg("-p")
        .arg(LAUNCHER_SANDBOX_PROFILE)
        .arg("/bin/sh")
        .arg("-c")
        .arg("kill -0 $$ && exit 7; exit 9")
        .status()
        .unwrap();
    assert_eq!(
        self_signal.code(),
        Some(7),
        "the profile must not break self-signalling",
    );

    // The containment must survive exec, because the launcher applies it and
    // then becomes the target through execve.
    let after_exec = std::process::Command::new("/usr/bin/sandbox-exec")
        .arg("-p")
        .arg(LAUNCHER_SANDBOX_PROFILE)
        .arg("/bin/sh")
        .arg("-c")
        .arg(format!("exec /bin/sh -c '{attack}'"))
        .status()
        .unwrap();
    assert_eq!(
        after_exec.code(),
        Some(7),
        "the profile must still deny signals after exec",
    );

    // Establish that the measured launchd service is reachable without the
    // profile, then prove the same exact lookup is denied inside the profile.
    let current_exe = std::env::current_exe().unwrap();
    let baseline = launchd_probe(&current_exe).status().unwrap();
    assert_eq!(
        baseline.code(),
        Some(LOOKUP_ALLOWED_EXIT),
        "the launchd probe service must be reachable for this measurement",
    );
    let contained_lookup = launchd_probe_via_sandbox(&current_exe).status().unwrap();
    assert_eq!(
        contained_lookup.code(),
        Some(LOOKUP_DENIED_EXIT),
        "the inherited profile must deny launchd Mach lookup",
    );

    victim.kill().unwrap();
    victim.wait().unwrap();
}

fn launchd_probe(current_exe: &std::path::Path) -> std::process::Command {
    let mut command = std::process::Command::new(current_exe);
    command
        .args(["--ignored", "--exact", LAUNCHD_LOOKUP_PROBE])
        .env(LAUNCHD_LOOKUP_PROBE_ENV, "1");
    command
}

fn launchd_probe_via_sandbox(current_exe: &std::path::Path) -> std::process::Command {
    let mut command = std::process::Command::new("/usr/bin/sandbox-exec");
    command
        .arg("-p")
        .arg(LAUNCHER_SANDBOX_PROFILE)
        .arg(current_exe)
        .args(["--ignored", "--exact", LAUNCHD_LOOKUP_PROBE])
        .env(LAUNCHD_LOOKUP_PROBE_ENV, "1");
    command
}

#[test]
#[ignore = "spawned alone by the launcher sandbox launchd-lookup measurement"]
fn launchd_lookup_probe_helper() {
    if std::env::var_os(LAUNCHD_LOOKUP_PROBE_ENV).is_none() {
        return;
    }
    // SAFETY: the task-self getter and special-port query have public Darwin
    // ABI; all out-parameters are writable for one port name.
    let task = unsafe { mach_task_self_ };
    let mut bootstrap = 0_u32;
    let special = unsafe { task_get_special_port(task, TASK_BOOTSTRAP_PORT, &raw mut bootstrap) };
    if special != 0 || bootstrap == 0 {
        std::process::exit(LOOKUP_DENIED_EXIT);
    }

    let mut service = 0_u32;
    // This is the same stable service used by the original issue-9
    // measurement. The parent first proves it exists without the profile.
    let lookup = unsafe {
        bootstrap_look_up(
            bootstrap,
            c"com.apple.system.notification_center".as_ptr(),
            &raw mut service,
        )
    };
    if service != 0 {
        // SAFETY: a successful lookup returned one send-right reference.
        let _ = unsafe { mach_port_deallocate(task, service) };
    }
    // SAFETY: task_get_special_port returned one send-right reference.
    let _ = unsafe { mach_port_deallocate(task, bootstrap) };
    std::process::exit(if lookup == 0 {
        LOOKUP_ALLOWED_EXIT
    } else {
        LOOKUP_DENIED_EXIT
    });
}

#[test]
fn the_launcher_never_expects_or_accepts_root() {
    // Root is exempt from RLIMIT_NPROC, so a root launcher cannot honour the
    // containment this entry promises. Root is refused, never required.
    // SAFETY: credential getters have no preconditions.
    let (uid, gid) = unsafe { (geteuid(), getegid()) };
    assert_ne!(
        uid, 0,
        "the unprivileged entry's tests must not run as root"
    );

    assert_eq!(verify_own_identity(&target_for_test(uid, gid)), Ok(()));

    // A plan naming anyone else is refused: this launcher never changes
    // credentials, so a mismatch means it is not the process the plan is for.
    for (other_uid, other_gid) in [(uid + 1, gid), (uid, gid + 1), (0, gid), (uid, 0)] {
        assert_eq!(
            verify_own_identity(&target_for_test(other_uid, other_gid)),
            Err(LauncherEntryError::IdentityMismatch),
            "a plan for uid {other_uid} gid {other_gid} must be refused",
        );
    }
}

fn target_for_test(effective_uid: u32, effective_gid: u32) -> PreparedTarget {
    PreparedTarget {
        effective_uid,
        effective_gid,
        executable: CString::new("/usr/bin/true").unwrap(),
        _arguments: Vec::new(),
        _environment: Vec::new(),
        argument_pointers: vec![std::ptr::null()],
        environment_pointers: vec![std::ptr::null()],
    }
}

#[test]
fn a_malformed_plan_prefix_is_refused_before_any_allocation() {
    // The frame length arrives inside the untrusted frame, so it is bounded
    // against the fixed prefix before a byte is allocated for the rest.
    let mut prefix = [0_u8; LAUNCHER_PLAN_PREFIX_BYTES];
    prefix[..8].copy_from_slice(b"NIPCLP01");
    prefix[8..10].copy_from_slice(&1_u16.to_le_bytes());

    let mut oversized = prefix;
    oversized[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(
        parse_launcher_plan_prefix_bytes(&oversized),
        Err(LauncherEntryError::Plan),
        "a frame larger than the fixed bound must be refused",
    );

    let mut truncated = prefix;
    truncated[12..16].copy_from_slice(&1_u32.to_le_bytes());
    assert_eq!(
        parse_launcher_plan_prefix_bytes(&truncated),
        Err(LauncherEntryError::Plan),
        "a frame shorter than its own prefix must be refused",
    );

    let mut wrong_magic = prefix;
    wrong_magic[..8].copy_from_slice(b"NIPCBP01");
    wrong_magic[12..16].copy_from_slice(&64_u32.to_le_bytes());
    assert_eq!(
        parse_launcher_plan_prefix_bytes(&wrong_magic),
        Err(LauncherEntryError::Plan),
        "the broker's own plan magic must not be accepted here",
    );
}
