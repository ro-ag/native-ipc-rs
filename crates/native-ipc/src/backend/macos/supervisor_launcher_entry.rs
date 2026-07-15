//! Fixed no-callback entry for the trusted launcher image.
//!
//! The launcher exists for one reason: the target is foreign code that cannot
//! `PT_TRACE_ME` itself. This image is ours, so it designates the broker as its
//! tracer, stops itself for identity proof, contains itself, and only then
//! becomes the target through `execve`. The exec trap the broker observes is
//! therefore taken before the target's first instruction.
//!
//! Nothing here is privileged. The launcher never gains, drops, or changes
//! credentials; it runs as the same unprivileged user as the broker and
//! verifies that it does. Containment is applied by lowering this process
//! before the target inherits it, never by raising anyone.
//!
//! # Ordering
//!
//! Every step is ordered against one rule: the broker must be able to end this
//! process exactly, at any point, and the target must never run un-contained.
//!
//! 1. `PT_TRACE_ME`, then `SIGSTOP`. The broker proves this exact stopped PID,
//!    path, and credentials before it continues us. FD4 is not read first: the
//!    broker delivers the plan only after that proof, so a launcher that
//!    blocked on FD4 could never be identified.
//! 2. Decode the plan, and prepare every exec input, while still fully
//!    reversible. No allocation or fallible call may follow containment.
//! 3. Contain: sandbox, then `RLIMIT_NPROC`. Both survive `execve`.
//! 4. Close FD3 and FD4, then `execve` immediately. `dup2` cleared their
//!    close-on-exec flags and `POSIX_SPAWN_CLOEXEC_DEFAULT` covered only the
//!    broker's spawn, so without this the target would inherit the
//!    broker-death pipe and any undelivered plan bytes.
//!
//! FD3 carries no data; its only signal is EOF, meaning the broker died. It is
//! probed at every step where a decision follows. Broker death also closes the
//! FD4 writer, so a blocking plan read cannot hang past it.

use std::convert::Infallible;
use std::ffi::{CString, c_char, c_int, c_void};

use super::auth_adapter::broker_plan::{
    LAUNCHER_PLAN_PREFIX_BYTES, LauncherExecParts, MAX_BROKER_PLAN_BYTES, ReceivedLauncherExecPlan,
    parse_launcher_plan_prefix,
};
use super::broker_entry::broker_launcher::{
    INSTALLED_LAUNCHER_DEATH_ARGUMENT, INSTALLED_LAUNCHER_MODE, INSTALLED_LAUNCHER_PATH,
    INSTALLED_LAUNCHER_PLAN_ARGUMENT, LAUNCHER_DEATH_FD, LAUNCHER_PLAN_FD,
};

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;

const PT_TRACE_ME: c_int = 0;
const SIGSTOP: c_int = 17;
const RLIMIT_NPROC: c_int = 7;
const F_GETFD: c_int = 1;
const F_GETFL: c_int = 3;
const F_SETFL: c_int = 4;
const O_NONBLOCK: c_int = 0x0000_0004;
const EINTR: c_int = 4;
const EAGAIN: c_int = 35;

/// Containment the target inherits, applied before it can run.
///
/// `(deny signal)` is the load-bearing rule for the cooperative tier. Without
/// it a target can send the broker an unmaskable `SIGSTOP` and suspend every
/// deadline and death-pipe check. Native measurement on this platform: from
/// inside this profile, outbound signals are denied with `EPERM`, the profile
/// cannot be relaxed by a second `sandbox_init` or by `execve`, and
/// self-signalling (`raise`, `abort`, `pthread_kill`) still works so targets
/// do not break.
///
/// This binds the exact contained process, not the user. It does not make the
/// broker safe from a *malicious* same-user principal: a sibling process the
/// broker never sandboxed can still `SIGSTOP` it, and adversarial review found
/// `launchd` reachable from inside this profile, so a delegated helper escapes
/// both this rule and `RLIMIT_NPROC`. Those attacks are out of scope for this
/// lifecycle boundary; defending against them would need the privileged
/// watchdog this design deliberately does not require. The guarantee here is
/// that an *uncooperative* target cannot stop the process that must reap it.
///
/// The mechanism is also not a durable contract: `sandbox_init` is deprecated
/// and SBPL is undocumented, so this is an empirical property of the current
/// OS, not a supported API boundary.
const LAUNCHER_SANDBOX_PROFILE: &str = "(version 1)\n(allow default)\n(deny signal)\n";

/// One process. Set only after the sandbox, and never as root, because Darwin
/// exempts root from this limit entirely.
const LAUNCHER_PROCESS_LIMIT: ResourceLimit = ResourceLimit {
    current: 1,
    maximum: 1,
};

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ResourceLimit {
    current: u64,
    maximum: u64,
}

unsafe extern "C" {
    fn _exit(status: c_int) -> !;
    fn close(fd: c_int) -> c_int;
    fn execve(
        path: *const c_char,
        arguments: *const *const c_char,
        environment: *const *const c_char,
    ) -> c_int;
    fn fcntl(fd: c_int, command: c_int, ...) -> c_int;
    fn getegid() -> u32;
    fn geteuid() -> u32;
    fn getrlimit(resource: c_int, limit: *mut ResourceLimit) -> c_int;
    fn ptrace(request: c_int, pid: c_int, address: *mut c_void, data: c_int) -> c_int;
    fn raise(signal: c_int) -> c_int;
    fn read(fd: c_int, buffer: *mut u8, count: usize) -> isize;
    fn sandbox_init(profile: *const c_char, flags: u64, errorbuf: *mut *mut c_char) -> c_int;
    fn setrlimit(resource: c_int, limit: *const ResourceLimit) -> c_int;
}

/// Why a launcher refused to become its target. Every value means no target
/// instruction ever ran.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LauncherEntryError {
    /// The process vector was not the one the fixed spawner installs.
    InvalidArguments,
    /// Fixed descriptor 3 or 4 was absent.
    InvalidDescriptor,
    /// The broker disappeared before the target could be committed to.
    BrokerGone,
    /// `PT_TRACE_ME` or the initial stop failed.
    TraceRefused,
    /// The plan pipe carried a malformed, oversized, or truncated frame.
    Plan,
    /// The plan named credentials this launcher does not have.
    IdentityMismatch,
    /// Target inputs could not be converted to one exact exec request.
    InvalidTarget,
    /// Containment could not be established.
    ContainmentRefused,
}

impl LauncherEntryError {
    /// Distinct nonzero statuses, so a fixture can tell refusals apart.
    const fn status(self) -> c_int {
        match self {
            Self::InvalidArguments => 64,
            Self::InvalidDescriptor => 65,
            // Broker death is the one clean, expected exit.
            Self::BrokerGone => 0,
            Self::TraceRefused => 66,
            Self::Plan => 67,
            Self::IdentityMismatch => 68,
            Self::InvalidTarget => 69,
            Self::ContainmentRefused => 70,
        }
    }
}

/// Runs the fixed launcher and never returns.
///
/// # Safety
///
/// This must be called directly by the separately packaged launcher image,
/// before threads, callbacks, or any effect-bearing endpoint exist. Its exact
/// process vector, fixed descriptor 3 (broker death) and descriptor 4 (plan)
/// must come from this library's launcher spawner, and no other Rust value may
/// own either descriptor.
pub(in crate::backend::macos) unsafe fn run_fixed_launcher_process() -> ! {
    // SAFETY: the caller promises the complete fixed process-entry contract.
    let status = match unsafe { run_launcher() } {
        Ok(infallible) => match infallible {},
        Err(error) => error.status(),
    };
    // SAFETY: a refusing launcher has no authority-bearing cleanup beyond
    // descriptor close, which the kernel performs. Avoid arbitrary
    // process-global exit callbacks after the terminal decision.
    unsafe { _exit(status) }
}

unsafe fn run_launcher() -> Result<Infallible, LauncherEntryError> {
    validate_fixed_arguments(std::env::args_os())?;
    // SAFETY: read-only liveness queries before either fixed descriptor is
    // used; the entry contract transfers sole ownership of both.
    unsafe {
        require_live(LAUNCHER_DEATH_FD)?;
        require_live(LAUNCHER_PLAN_FD)?;
        adopt_death_pipe()?;
    }

    // Establish the broker's trace authority before anything else can run, so
    // there is no window in which this image is alive but unowned.
    probe_broker_death()?;
    // SAFETY: this designates the exact parent as sole tracer for this process.
    if unsafe { ptrace(PT_TRACE_ME, 0, std::ptr::null_mut(), 0) } != 0 {
        return Err(LauncherEntryError::TraceRefused);
    }
    probe_broker_death()?;
    // The broker proves this exact stopped PID, path, and credentials here,
    // and only continues us once it has. It delivers the plan afterwards.
    // SAFETY: raising the canonical initial stop on this process.
    if unsafe { raise(SIGSTOP) } != 0 {
        return Err(LauncherEntryError::TraceRefused);
    }
    // The broker may have died while we were stopped.
    probe_broker_death()?;

    let parts = read_exact_plan()?;
    let prepared = PreparedTarget::from_plan(parts)?;
    verify_own_identity(&prepared)?;

    // Everything fallible is done. From here the process is only lowered.
    probe_broker_death()?;
    // SAFETY: the fixed profile is a live NUL-terminated string, and this
    // single-threaded image has no callbacks that could observe the change.
    unsafe { apply_containment() }?;

    // Last look before the target exists. After this the broker's exec trap
    // and exact child authority are the only controls that remain.
    probe_broker_death()?;
    // SAFETY: both fixed descriptors are owned by this process and must not
    // survive into the target, which would otherwise inherit the broker-death
    // pipe and any plan bytes this launcher did not consume.
    unsafe {
        close(LAUNCHER_DEATH_FD);
        close(LAUNCHER_PLAN_FD);
    }

    // SAFETY: every C string and pointer array is owned by `prepared`, which
    // remains live across this call.
    let _ = unsafe {
        execve(
            prepared.executable.as_ptr(),
            prepared.argument_pointers.as_ptr(),
            prepared.environment_pointers.as_ptr(),
        )
    };
    // exec returned, so this image is contained but did not become the target.
    // It cannot report and must not continue in a half-committed state.
    std::process::abort();
}

/// Owned target inputs, fully converted before any irreversible step.
struct PreparedTarget {
    effective_uid: u32,
    effective_gid: u32,
    executable: CString,
    _arguments: Vec<CString>,
    _environment: Vec<CString>,
    argument_pointers: Vec<*const c_char>,
    environment_pointers: Vec<*const c_char>,
}

impl PreparedTarget {
    fn from_plan(parts: LauncherExecParts) -> Result<Self, LauncherEntryError> {
        let executable = CString::new(parts.installed_executable)
            .map_err(|_| LauncherEntryError::InvalidTarget)?;
        let arguments = parts
            .arguments
            .into_iter()
            .map(CString::new)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| LauncherEntryError::InvalidTarget)?;
        if arguments.is_empty() {
            return Err(LauncherEntryError::InvalidTarget);
        }
        let environment = parts
            .environment
            .into_iter()
            .map(|entry| {
                let mut bytes = entry.key().to_vec();
                bytes.push(b'=');
                bytes.extend_from_slice(entry.value());
                CString::new(bytes)
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| LauncherEntryError::InvalidTarget)?;
        let mut argument_pointers = arguments
            .iter()
            .map(|value| value.as_ptr())
            .collect::<Vec<_>>();
        argument_pointers.push(std::ptr::null());
        let mut environment_pointers = environment
            .iter()
            .map(|value| value.as_ptr())
            .collect::<Vec<_>>();
        environment_pointers.push(std::ptr::null());
        Ok(Self {
            effective_uid: parts.effective_uid,
            effective_gid: parts.effective_gid,
            _arguments: arguments,
            _environment: environment,
            executable,
            argument_pointers,
            environment_pointers,
        })
    }
}

/// Requires that this launcher already is the identity the plan names.
///
/// This supervisor is unprivileged and same-user, so there is nothing to drop:
/// the check exists to prove the launcher never needed to change credentials
/// and is not running as someone else. Root is a refusal, not a requirement —
/// a root launcher would be exempt from `RLIMIT_NPROC` and would mean the
/// deployer installed this image in a way this design does not support.
fn verify_own_identity(prepared: &PreparedTarget) -> Result<(), LauncherEntryError> {
    // SAFETY: credential getters have no preconditions.
    let (uid, gid) = unsafe { (geteuid(), getegid()) };
    if uid == 0 || gid == 0 || uid != prepared.effective_uid || gid != prepared.effective_gid {
        return Err(LauncherEntryError::IdentityMismatch);
    }
    Ok(())
}

/// Lowers this process so the target inherits containment it cannot undo.
unsafe fn apply_containment() -> Result<(), LauncherEntryError> {
    let profile = CString::new(LAUNCHER_SANDBOX_PROFILE)
        .map_err(|_| LauncherEntryError::ContainmentRefused)?;
    let mut error: *mut c_char = std::ptr::null_mut();
    // SAFETY: the profile is a live NUL-terminated SBPL string and `error` is
    // writable storage for one optional message.
    if unsafe { sandbox_init(profile.as_ptr(), 0, &raw mut error) } != 0 {
        return Err(LauncherEntryError::ContainmentRefused);
    }

    // Only meaningful once the process is nonroot, which verify_own_identity
    // already required. Darwin exempts root from this limit.
    let limit = LAUNCHER_PROCESS_LIMIT;
    // SAFETY: the limit is one initialized rlimit value.
    if unsafe { setrlimit(RLIMIT_NPROC, &raw const limit) } != 0 {
        return Err(LauncherEntryError::ContainmentRefused);
    }
    let mut observed = ResourceLimit {
        current: 0,
        maximum: 0,
    };
    // SAFETY: `observed` is valid writable storage for one rlimit value.
    if unsafe { getrlimit(RLIMIT_NPROC, &raw mut observed) } != 0
        || observed != LAUNCHER_PROCESS_LIMIT
    {
        return Err(LauncherEntryError::ContainmentRefused);
    }
    Ok(())
}

/// Reads the one canonical plan frame, bounded by its own fixed prefix.
///
/// Broker death closes the plan writer too, so a blocking read reaches EOF
/// rather than hanging past the broker that authorized this launch.
fn read_exact_plan() -> Result<LauncherExecParts, LauncherEntryError> {
    let mut prefix = [0_u8; LAUNCHER_PLAN_PREFIX_BYTES];
    read_exact(LAUNCHER_PLAN_FD, &mut prefix)?;
    // The frame length is not trusted: it is validated against the fixed
    // prefix's own bounds before a single byte is allocated for the rest.
    let parsed = parse_launcher_plan_prefix_bytes(&prefix)?;
    let mut frame = vec![0_u8; parsed];
    frame[..LAUNCHER_PLAN_PREFIX_BYTES].copy_from_slice(&prefix);
    read_exact(LAUNCHER_PLAN_FD, &mut frame[LAUNCHER_PLAN_PREFIX_BYTES..])?;
    require_plan_eof()?;

    let prefix_binding = parse_launcher_plan_prefix(&prefix, parsed)
        .map_err(|_| LauncherEntryError::Plan)?
        .deadline;
    let received = ReceivedLauncherExecPlan::decode_with_deadline(&frame, prefix_binding)
        .map_err(|_| LauncherEntryError::Plan)?;
    Ok(received.into_parts())
}

fn parse_launcher_plan_prefix_bytes(
    prefix: &[u8; LAUNCHER_PLAN_PREFIX_BYTES],
) -> Result<usize, LauncherEntryError> {
    let length = u32::from_le_bytes(prefix[12..16].try_into().unwrap_or([0; 4]));
    let length = usize::try_from(length).map_err(|_| LauncherEntryError::Plan)?;
    if !(LAUNCHER_PLAN_PREFIX_BYTES..=MAX_BROKER_PLAN_BYTES).contains(&length) {
        return Err(LauncherEntryError::Plan);
    }
    parse_launcher_plan_prefix(prefix, length).map_err(|_| LauncherEntryError::Plan)?;
    Ok(length)
}

fn require_plan_eof() -> Result<(), LauncherEntryError> {
    let mut extra = [0_u8; 1];
    loop {
        // SAFETY: extra is writable for one byte and FD4 is live.
        let count = unsafe { read(LAUNCHER_PLAN_FD, extra.as_mut_ptr(), 1) };
        if count == 0 {
            return Ok(());
        }
        if count > 0 {
            return Err(LauncherEntryError::Plan);
        }
        if last_errno() != EINTR {
            return Err(LauncherEntryError::Plan);
        }
    }
}

fn read_exact(fd: c_int, mut bytes: &mut [u8]) -> Result<(), LauncherEntryError> {
    while !bytes.is_empty() {
        // SAFETY: bytes is writable for its own length and fd is live.
        let count = unsafe { read(fd, bytes.as_mut_ptr(), bytes.len()) };
        if count == 0 {
            // The broker closed the plan writer without completing the frame.
            return Err(LauncherEntryError::BrokerGone);
        }
        if count < 0 {
            if last_errno() == EINTR {
                continue;
            }
            return Err(LauncherEntryError::Plan);
        }
        let count = usize::try_from(count).map_err(|_| LauncherEntryError::Plan)?;
        bytes = bytes.get_mut(count..).ok_or(LauncherEntryError::Plan)?;
    }
    Ok(())
}

/// EOF on FD3 is the broker's death. Any byte is a protocol failure: the
/// broker never writes this pipe.
///
/// This requires FD3 to be nonblocking, which [`adopt_death_pipe`] establishes.
/// The broker only makes its own writer nonblocking, and a pipe's two ends have
/// independent file descriptions, so a blocking reader here would park forever
/// on the healthy case: a live broker that correctly never writes.
fn probe_broker_death() -> Result<(), LauncherEntryError> {
    let mut byte = 0_u8;
    loop {
        // SAFETY: byte is writable for one byte and FD3 is live.
        let count = unsafe { read(LAUNCHER_DEATH_FD, &raw mut byte, 1) };
        if count == 0 {
            return Err(LauncherEntryError::BrokerGone);
        }
        if count > 0 {
            return Err(LauncherEntryError::InvalidDescriptor);
        }
        return match last_errno() {
            EINTR => continue,
            // Live and silent is the only healthy state for a data-free pipe.
            EAGAIN => Ok(()),
            _ => Err(LauncherEntryError::InvalidDescriptor),
        };
    }
}

/// Makes the broker-death pipe probeable without blocking.
unsafe fn adopt_death_pipe() -> Result<(), LauncherEntryError> {
    // SAFETY: F_GETFL is a read-only query on the live fixed descriptor.
    let flags = unsafe { fcntl(LAUNCHER_DEATH_FD, F_GETFL) };
    if flags < 0 {
        return Err(LauncherEntryError::InvalidDescriptor);
    }
    // SAFETY: the value preserves every unrelated status flag.
    if unsafe { fcntl(LAUNCHER_DEATH_FD, F_SETFL, flags | O_NONBLOCK) } != 0 {
        return Err(LauncherEntryError::InvalidDescriptor);
    }
    Ok(())
}

unsafe fn require_live(fd: c_int) -> Result<(), LauncherEntryError> {
    // SAFETY: F_GETFD is a read-only descriptor query.
    if unsafe { fcntl(fd, F_GETFD) } < 0 {
        return Err(LauncherEntryError::InvalidDescriptor);
    }
    Ok(())
}

fn validate_fixed_arguments(
    arguments: impl IntoIterator<Item = impl AsRef<OsStr>>,
) -> Result<(), LauncherEntryError> {
    let mut arguments = arguments.into_iter();
    let expected = [
        INSTALLED_LAUNCHER_PATH.as_bytes(),
        INSTALLED_LAUNCHER_MODE.as_bytes(),
        INSTALLED_LAUNCHER_DEATH_ARGUMENT.as_bytes(),
        INSTALLED_LAUNCHER_PLAN_ARGUMENT.as_bytes(),
    ];
    for expected in expected {
        let Some(argument) = arguments.next() else {
            return Err(LauncherEntryError::InvalidArguments);
        };
        if argument.as_ref().as_bytes() != expected {
            return Err(LauncherEntryError::InvalidArguments);
        }
    }
    if arguments.next().is_some() {
        return Err(LauncherEntryError::InvalidArguments);
    }
    Ok(())
}

fn last_errno() -> c_int {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

#[cfg(test)]
#[path = "supervisor_launcher_entry_test.rs"]
mod tests;

#[cfg(all(test, target_arch = "aarch64"))]
#[path = "supervisor_launcher_lifecycle_test.rs"]
mod lifecycle_tests;
