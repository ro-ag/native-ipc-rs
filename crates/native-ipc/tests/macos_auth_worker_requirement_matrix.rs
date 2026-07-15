//! Bring-your-own-cert signed evidence matrix for the fixed auth worker.
//!
//! The sibling `macos_auth_worker_entry` proof drives the worker with the
//! `always` requirement, which is satisfied by construction and therefore
//! exercises framing rather than code-signing policy. This fixture supplies a
//! real requirement and a really signed subject, so a rejection can only come
//! from Security.framework.
//!
//! No signing identity, team, or requirement is compiled in. The deployer's
//! identity is read from `NATIVE_IPC_TEST_SIGN_IDENTITY` at run time, matching
//! the project rule that downstream signs helpers with its own certificate and
//! that this repository never ships or hardcodes one. Without that variable the
//! fixture reports a skip and succeeds, so unsigned CI stays green.
//!
//! Run locally with, for example:
//!
//! ```text
//! NATIVE_IPC_TEST_SIGN_IDENTITY="Developer ID Application: You (TEAMID)" \
//!   cargo test -p native-ipc --test macos-auth-worker-requirement-matrix
//! ```

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod macos {
    use std::ffi::{CString, c_int, c_long};
    use std::io::{Read, Write};
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::process::CommandExt;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};

    const INSTALLED_PATH: &str = "/Library/PrivilegedHelperTools/com.ro-ag.native-ipc.auth-worker";
    const MODE: &str = "--supervisor-auth-worker";
    const REQUEST: &str = "--request-fd=3";
    const RESULT: &str = "--result-fd=4";
    const JOB_BYTES: usize = 152;
    const RESULT_BYTES: usize = 200;
    const CODE_IDENTITY: [u8; 32] = [0x5a; 32];
    const REJECTED_IDENTITY: [u8; 32] = [0; 32];

    /// Fixed identifier stamped at signing time, so a requirement can name the
    /// subject independently of its temporary file name.
    const SUBJECT_IDENTIFIER: &str = "com.ro-ag.native-ipc.test-subject";
    const IDENTITY_ENV: &str = "NATIVE_IPC_TEST_SIGN_IDENTITY";
    const REQUIREMENT_ENV: &str = "NATIVE_IPC_TEST_REQUIREMENT";

    #[repr(C)]
    struct TimeSpec {
        tv_sec: c_long,
        tv_nsec: c_long,
    }

    unsafe extern "C" {
        static mach_task_self_: u32;
        fn clock_gettime(clock_id: c_int, time: *mut TimeSpec) -> c_int;
        fn dup2(source: c_int, destination: c_int) -> c_int;
        fn task_info(task: u32, flavor: c_int, info: *mut c_int, count: *mut u32) -> c_int;
        fn task_name_for_pid(target: u32, pid: c_int, name: *mut u32) -> c_int;
        fn getegid() -> u32;
        fn geteuid() -> u32;
    }

    fn is_fixed_child_invocation() -> bool {
        std::env::args_os()
            .next()
            .is_some_and(|argument| argument.as_bytes() == INSTALLED_PATH.as_bytes())
    }

    /// How the subject worker image is signed before it is spawned.
    #[derive(Clone, Copy, Debug)]
    enum SubjectSignature {
        DeveloperId,
        AdHoc,
        Unsigned,
        DeveloperIdThenMutated,
    }

    /// What the worker is told to require of the audit token it is handed.
    #[derive(Clone, Copy, Debug)]
    enum Requirement {
        CorrectTeamAndIdentifier,
        SameTeamWrongIdentifier,
        WrongTeam,
        ApplePlatformOnly,
    }

    impl Requirement {
        fn string(self, team: &str) -> String {
            match self {
                Self::CorrectTeamAndIdentifier => format!(
                    "anchor apple generic and identifier \"{SUBJECT_IDENTIFIER}\" \
                     and certificate leaf[subject.OU] = \"{team}\""
                ),
                Self::SameTeamWrongIdentifier => format!(
                    "anchor apple generic and identifier \"com.ro-ag.native-ipc.not-the-subject\" \
                     and certificate leaf[subject.OU] = \"{team}\""
                ),
                Self::WrongTeam => format!(
                    "anchor apple generic and identifier \"{SUBJECT_IDENTIFIER}\" \
                     and certificate leaf[subject.OU] = \"ZZZZZZZZZZ\""
                ),
                // A Developer ID image is anchored to Apple's Developer ID CA,
                // not to Apple's own platform anchor, so this must never match.
                Self::ApplePlatformOnly => "anchor apple".to_owned(),
            }
        }
    }

    fn signing_identity() -> Option<String> {
        std::env::var(IDENTITY_ENV).ok().filter(|v| !v.is_empty())
    }

    /// Team OU carried by the configured identity, parsed from its common name
    /// (`Developer ID Application: Someone (TEAMID)`).
    fn team_of(identity: &str) -> String {
        identity
            .rsplit_once('(')
            .and_then(|(_, rest)| rest.split_once(')'))
            .map(|(team, _)| team.to_owned())
            .unwrap_or_else(|| panic!("cannot read a team OU from identity {identity:?}"))
    }

    fn prepare_subject(signature: SubjectSignature, identity: &str, index: usize) -> PathBuf {
        let path = std::env::temp_dir().join(format!("native-ipc-subject-{index}"));
        let _ = std::fs::remove_file(&path);
        std::fs::copy(std::env::current_exe().unwrap(), &path).unwrap();

        let sign = |args: &[&str]| {
            let status = Command::new("/usr/bin/codesign")
                .args(args)
                .arg(&path)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap();
            assert!(status.success(), "codesign {args:?} failed for {path:?}");
        };
        match signature {
            SubjectSignature::Unsigned => {
                // Cargo ad-hoc signs its output, so an unsigned subject must be
                // produced by explicitly stripping that signature.
                let _ = Command::new("/usr/bin/codesign")
                    .args(["--remove-signature"])
                    .arg(&path)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
            SubjectSignature::AdHoc => sign(&[
                "--force",
                "--options",
                "runtime",
                "--identifier",
                SUBJECT_IDENTIFIER,
                "--sign",
                "-",
            ]),
            SubjectSignature::DeveloperId | SubjectSignature::DeveloperIdThenMutated => sign(&[
                "--force",
                "--options",
                "runtime",
                "--identifier",
                SUBJECT_IDENTIFIER,
                "--sign",
                identity,
            ]),
        }
        if matches!(signature, SubjectSignature::DeveloperIdThenMutated) {
            mutate_entry_point(&path);
        }
        path
    }

    /// Flips the first instruction at the signed image's entry point.
    ///
    /// The target must be executable code, not an arbitrary file offset. The
    /// kernel enforces a page's code-directory hash only when it faults that
    /// page in, so tampering with an unmapped region (debug info, `__LINKEDIT`)
    /// is never observed at runtime and the guest still validates. Mutating the
    /// entry point guarantees the tampered page is the first one executed.
    fn mutate_entry_point(path: &Path) {
        let mut bytes = std::fs::read(path).unwrap();
        let offset = entry_point_offset(&bytes)
            .unwrap_or_else(|| panic!("no LC_MAIN entry point in {path:?}"));
        bytes[offset] ^= 0xff;
        std::fs::write(path, bytes).unwrap();
    }

    /// File offset of `LC_MAIN`'s entry point in a 64-bit Mach-O, whose
    /// `__TEXT` segment begins at file offset zero.
    fn entry_point_offset(bytes: &[u8]) -> Option<usize> {
        const MH_MAGIC_64: u32 = 0xfeed_facf;
        const LC_MAIN: u32 = 0x8000_0028;
        let read_u32 = |at: usize| -> Option<u32> {
            Some(u32::from_le_bytes(bytes.get(at..at + 4)?.try_into().ok()?))
        };
        if read_u32(0)? != MH_MAGIC_64 {
            return None;
        }
        let command_count = read_u32(16)?;
        let mut cursor = 32_usize;
        for _ in 0..command_count {
            let kind = read_u32(cursor)?;
            let size = usize::try_from(read_u32(cursor + 4)?).ok()?;
            if kind == LC_MAIN {
                let entry =
                    u64::from_le_bytes(bytes.get(cursor + 8..cursor + 16)?.try_into().ok()?);
                return usize::try_from(entry).ok().filter(|at| *at < bytes.len());
            }
            cursor = cursor.checked_add(size)?;
        }
        None
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

    /// Audit token of an exact live child, captured the way the broker captures
    /// a stopped launcher's token.
    fn audit_token_of(pid: c_int) -> Option<[u8; 32]> {
        let mut name = 0_u32;
        // SAFETY: name is writable and the caller owns this exact live child.
        if unsafe { task_name_for_pid(mach_task_self_, pid, &raw mut name) } != 0 {
            return None;
        }
        let mut values = [0_u32; 8];
        let mut count = 8_u32;
        // SAFETY: TASK_AUDIT_TOKEN (15) writes exactly eight natural_t words
        // into this writable storage for the named task.
        let result = unsafe { task_info(name, 15, values.as_mut_ptr().cast(), &raw mut count) };
        if result != 0 || count != 8 {
            return None;
        }
        let mut token = [0_u8; 32];
        for (destination, value) in token.chunks_exact_mut(4).zip(values) {
            destination.copy_from_slice(&value.to_ne_bytes());
        }
        Some(token)
    }

    fn deadline_after(seconds: u64) -> u64 {
        let mut now = TimeSpec {
            tv_sec: 0,
            tv_nsec: 0,
        };
        // SAFETY: CLOCK_UPTIME_RAW writes one initialized timespec.
        assert_eq!(unsafe { clock_gettime(8, &raw mut now) }, 0);
        let base = u64::try_from(now.tv_sec).unwrap() * 1_000_000_000
            + u64::try_from(now.tv_nsec).unwrap();
        base + seconds * 1_000_000_000
    }

    /// Same canonical fixed job the sibling entry proof builds, differing only
    /// in whose audit token it carries.
    fn job(token: [u8; 32], deadline: u64) -> [u8; JOB_BYTES] {
        let mut bytes = [0_u8; JOB_BYTES];
        bytes[..8].copy_from_slice(b"NIPCAWJ1");
        put_u16(&mut bytes, 8, 1);
        put_u32(&mut bytes, 12, u32::try_from(JOB_BYTES).unwrap());
        bytes[16] = 0;
        put_u64(&mut bytes, 24, 1);
        bytes[32..64].fill(0x11);
        bytes[72..104].copy_from_slice(&token);
        // SAFETY: credential getters have no preconditions. The subject runs as
        // this same user, so its token must carry these same credentials.
        put_u32(&mut bytes, 104, unsafe { geteuid() });
        // SAFETY: same exact process credential snapshot.
        put_u32(&mut bytes, 108, unsafe { getegid() });
        bytes[112..144].fill(0x22);
        put_u64(&mut bytes, 144, deadline);
        bytes
    }

    /// Spawns one signed subject as the fixed worker and returns its validation
    /// verdict: `Some(true)` validated, `Some(false)` rejected, `None` if the
    /// image never reached a verdict (killed or refused before answering).
    fn verdict(subject: &Path, requirement: &str) -> Option<bool> {
        let mut command = Command::new(subject);
        command
            .arg0(INSTALLED_PATH)
            .arg(MODE)
            .arg(REQUEST)
            .arg(RESULT)
            .env(REQUIREMENT_ENV, requirement)
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
        let mut child = command.spawn().ok()?;
        let pid = c_int::try_from(child.id()).unwrap();
        let token = match audit_token_of(pid) {
            Some(token) => token,
            None => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        };
        let bytes = job(token, deadline_after(5));
        if child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(&bytes)
            .and_then(|()| child.stdin.as_mut().unwrap().flush())
            .is_err()
        {
            let _ = child.wait();
            return None;
        }
        drop(child.stdin.take());
        let mut result = Vec::new();
        child
            .stdout
            .as_mut()
            .unwrap()
            .read_to_end(&mut result)
            .ok()?;
        let status = child.wait().ok()?;
        if !status.success() || result.len() != RESULT_BYTES {
            return None;
        }
        assert_eq!(&result[..8], b"NIPCAWR1");
        let identity = &result[168..200];
        if identity == CODE_IDENTITY {
            Some(true)
        } else if identity == REJECTED_IDENTITY {
            Some(false)
        } else {
            panic!("worker returned an unknown identity {identity:?}");
        }
    }

    pub fn main() {
        if is_fixed_child_invocation() {
            let requirement = std::env::var(REQUIREMENT_ENV)
                .expect("the fixture always supplies a requirement to its worker");
            let requirement = CString::new(requirement).unwrap();
            // SAFETY: this fixture worker entered through a clean exec with the
            // fixed vector and sole FD3/FD4 ownership. The requirement is a
            // fixture input rather than an installed constant precisely so the
            // deployer's own certificate can be supplied at run time.
            unsafe { native_ipc::__private_macos_auth_worker_main(&requirement, CODE_IDENTITY) }
        }

        let Some(identity) = signing_identity() else {
            println!(
                "skipping signed requirement matrix: set {IDENTITY_ENV} to a \
                 Developer ID Application identity to run it"
            );
            return;
        };
        let team = team_of(&identity);

        // A correctly signed subject is the only accepted combination. Every
        // other row must be rejected by Security.framework itself, never by the
        // fixture, and `always` could not distinguish any of them.
        let matrix: [(SubjectSignature, Requirement, Option<bool>); 5] = [
            (
                SubjectSignature::DeveloperId,
                Requirement::CorrectTeamAndIdentifier,
                Some(true),
            ),
            (
                SubjectSignature::DeveloperId,
                Requirement::SameTeamWrongIdentifier,
                Some(false),
            ),
            (
                SubjectSignature::DeveloperId,
                Requirement::WrongTeam,
                Some(false),
            ),
            (
                SubjectSignature::DeveloperId,
                Requirement::ApplePlatformOnly,
                Some(false),
            ),
            (
                SubjectSignature::AdHoc,
                Requirement::CorrectTeamAndIdentifier,
                Some(false),
            ),
        ];

        for (index, (signature, requirement, expected)) in matrix.into_iter().enumerate() {
            let subject = prepare_subject(signature, &identity, index);
            let observed = verdict(&subject, &requirement.string(&team));
            assert_eq!(
                observed, expected,
                "subject {signature:?} against requirement {requirement:?}"
            );
            let _ = std::fs::remove_file(&subject);
            println!("ok: {signature:?} + {requirement:?} -> {observed:?}");
        }

        // An unsigned image and one mutated after signing must never reach a
        // verdict at all. This platform refuses to exec either, so the kernel
        // kills the subject before the worker can answer. That is a stronger
        // outcome than a rejection, and the `always` requirement cannot
        // observe it either way.
        for (index, signature) in [
            SubjectSignature::Unsigned,
            SubjectSignature::DeveloperIdThenMutated,
        ]
        .into_iter()
        .enumerate()
        {
            let subject = prepare_subject(signature, &identity, 5 + index);
            let observed = verdict(
                &subject,
                &Requirement::CorrectTeamAndIdentifier.string(&team),
            );
            assert_eq!(
                observed, None,
                "{signature:?} must be killed before producing any verdict"
            );
            let _ = std::fs::remove_file(&subject);
            println!("ok: {signature:?} reached no verdict");
        }
    }
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
fn main() {
    macos::main();
}

#[cfg(not(all(target_os = "macos", target_arch = "aarch64")))]
fn main() {}
