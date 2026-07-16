use super::*;

#[test]
fn fixed_arguments_accept_only_the_installed_launcher_vector() {
    let good = [
        INSTALLED_LAUNCHER_PATH,
        INSTALLED_LAUNCHER_MODE,
        INSTALLED_LAUNCHER_DEATH_ARGUMENT,
        INSTALLED_LAUNCHER_PLAN_ARGUMENT,
    ];
    assert_eq!(validate_fixed_arguments(good), Ok(()));

    // No request value may reach this vector, so every deviation is refused
    // rather than interpreted.
    let cases: [&[&str]; 6] = [
        &[],
        &[INSTALLED_LAUNCHER_PATH],
        &[
            "/usr/bin/true",
            INSTALLED_LAUNCHER_MODE,
            INSTALLED_LAUNCHER_DEATH_ARGUMENT,
            INSTALLED_LAUNCHER_PLAN_ARGUMENT,
        ],
        &[
            INSTALLED_LAUNCHER_PATH,
            "--other-mode",
            INSTALLED_LAUNCHER_DEATH_ARGUMENT,
            INSTALLED_LAUNCHER_PLAN_ARGUMENT,
        ],
        &[
            INSTALLED_LAUNCHER_PATH,
            INSTALLED_LAUNCHER_MODE,
            "--broker-death-fd=9",
            INSTALLED_LAUNCHER_PLAN_ARGUMENT,
        ],
        &[
            INSTALLED_LAUNCHER_PATH,
            INSTALLED_LAUNCHER_MODE,
            INSTALLED_LAUNCHER_DEATH_ARGUMENT,
            INSTALLED_LAUNCHER_PLAN_ARGUMENT,
            "--extra",
        ],
    ];
    for case in cases {
        assert_eq!(
            validate_fixed_arguments(case.iter().copied()),
            Err(LauncherEntryError::InvalidArguments),
            "vector {case:?} must be refused",
        );
    }
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
fn the_sandbox_profile_denies_signals_and_survives_exec() {
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

    victim.kill().unwrap();
    victim.wait().unwrap();
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
