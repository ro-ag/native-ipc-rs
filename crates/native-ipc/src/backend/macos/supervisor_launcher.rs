//! Session-bound irreversible transition for the future signed launcher.

use std::convert::Infallible;
use std::ffi::{CString, c_char, c_int};

use super::supervisor::{ConnectionIdentity, LauncherSpawnParts, ValidatedSpawn, VerifiedPeer};
use super::supervisor_watchdog::{ExactBrokerAuthority, RegisteredLaunchPermit, SessionHandle};

const RLIMIT_NPROC: c_int = 7;

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ResourceLimit {
    current: u64,
    maximum: u64,
}

unsafe extern "C" {
    fn getuid() -> u32;
    fn geteuid() -> u32;
    fn getgid() -> u32;
    fn getegid() -> u32;
    fn getgroups(count: c_int, groups: *mut u32) -> c_int;
    fn setgroups(count: c_int, groups: *const u32) -> c_int;
    fn setgid(gid: u32) -> c_int;
    fn setegid(gid: u32) -> c_int;
    fn setuid(uid: u32) -> c_int;
    fn seteuid(uid: u32) -> c_int;
    fn getrlimit(resource: c_int, limit: *mut ResourceLimit) -> c_int;
    fn setrlimit(resource: c_int, limit: *const ResourceLimit) -> c_int;
    fn execve(
        path: *const c_char,
        arguments: *const *const c_char,
        environment: *const *const c_char,
    ) -> c_int;
}

/// Pre-mutation launcher validation failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum CredentialDropError {
    /// UID or GID was root, an unchanged-ID sentinel, or otherwise unusable.
    InvalidClientIdentity,
    /// Installed policy data could not be converted to one exact exec request.
    InvalidPreparedTarget,
    /// The original admitted absolute deadline elapsed before mutation.
    DeadlineExpired,
    /// The watchdog registration was terminated before launch commitment.
    RegistrationRevoked,
    /// The fixed launcher did not begin with real/effective root authority.
    LauncherNotRoot,
}

/// Proof that the broker consumed this session's initial `PT_TRACE_ME` stop.
pub(super) struct LauncherTraceEstablished<'lease, Authority: ExactBrokerAuthority> {
    registration: RegisteredLaunchPermit<'lease, ValidatedSpawn, Authority>,
}

impl<'lease, Authority: ExactBrokerAuthority> LauncherTraceEstablished<'lease, Authority> {
    /// # Safety
    ///
    /// The sole broker waiter for the registered launch must have
    /// consumed the trusted launcher's initial trace-proof stop. The launcher
    /// must still be that exact stopped/resumed tracee and must not have execed.
    pub(super) const unsafe fn from_broker_trace_stop(
        registration: RegisteredLaunchPermit<'lease, ValidatedSpawn, Authority>,
    ) -> Self {
        Self { registration }
    }

    /// Prepares target bytes while retaining the permit lifetime as authority.
    pub(super) fn into_launch(self) -> TraceBoundValidatedSpawn<'lease, Authority> {
        let handle = self.registration.handle();
        let connection = self.registration.connection();
        let deadline = self.registration.deadline();
        let spawn = self.registration.launch().launcher_parts_for_permit();
        TraceBoundValidatedSpawn {
            handle,
            connection,
            deadline,
            spawn,
            registration: self.registration,
        }
    }
}

/// One exact registered session ready for drop-and-immediate-exec.
pub(super) struct TraceBoundValidatedSpawn<'lease, Authority: ExactBrokerAuthority> {
    handle: SessionHandle,
    connection: ConnectionIdentity,
    deadline: std::time::Instant,
    spawn: LauncherSpawnParts,
    registration: RegisteredLaunchPermit<'lease, ValidatedSpawn, Authority>,
}

/// Permanently drops credentials and immediately execs the exact installed image.
///
/// All fallible request conversion and the root preflight happen before the
/// first process mutation. Once mutation begins, any failure—including an
/// `execve` return—aborts the launcher. No callback or returned credential proof
/// permits target-controlled work between the drop and exec.
///
/// # Safety
///
/// `launch` must refer to the separately packaged, single-threaded launcher in
/// its exact registered watchdog session. The installed catalog that produced
/// it must guarantee a root-owned replacement-resistant executable path and
/// matching code identity. `PT_TRACE_ME` must remain active so Darwin ignores
/// any set-user-ID/set-group-ID bits at exec and stops the target before its
/// first instruction.
pub(super) unsafe fn permanently_drop_and_exec<Authority: ExactBrokerAuthority>(
    launch: TraceBoundValidatedSpawn<'_, Authority>,
) -> Result<Infallible, CredentialDropError> {
    let TraceBoundValidatedSpawn {
        handle,
        connection,
        deadline,
        spawn,
        registration,
    } = launch;
    let prepared = PreparedExec::from_validated(spawn)?;
    let identity = AuthenticatedClientIdentity::from_verified_peer(prepared.peer)?;
    preflight_deadline(deadline)?;
    preflight_root()?;

    // Revalidate the exact live registration only after all fallible
    // preparation. The returned short borrow stays live across the no-callback
    // irreversible transition, so copied request bytes cannot authorize a
    // launch after the watchdog has reaped this session.
    let _commit = registration.commit_guard().map_err(|error| match error {
        super::supervisor_watchdog::WatchdogStateError::DeadlineExpired => {
            CredentialDropError::DeadlineExpired
        }
        super::supervisor_watchdog::WatchdogStateError::CapacityExceeded
        | super::supervisor_watchdog::WatchdogStateError::UnknownSession
        | super::supervisor_watchdog::WatchdogStateError::WrongConnection
        | super::supervisor_watchdog::WatchdogStateError::InvalidTransition
        | super::supervisor_watchdog::WatchdogStateError::BrokerActivationFailed => {
            CredentialDropError::RegistrationRevoked
        }
    })?;

    // Keep the exact session binding live across the irreversible transition.
    let _exact_session = (
        handle,
        connection,
        deadline,
        prepared.policy_id,
        prepared.target_identity,
    );
    // SAFETY: the function contract restricts this to the single-threaded
    // privileged launcher after all fallible preparation and root preflight.
    unsafe { drop_client_identity(identity) };

    // SAFETY: every C string and pointer array is owned by `prepared`, which
    // remains live. Returning from exec is an invariant failure and aborts.
    let result = unsafe {
        execve(
            prepared.executable.as_ptr(),
            prepared.argument_pointers.as_ptr(),
            prepared.environment_pointers.as_ptr(),
        )
    };
    let _ = result;
    std::process::abort();
}

struct AuthenticatedClientIdentity {
    uid: u32,
    gid: u32,
}

impl AuthenticatedClientIdentity {
    fn from_verified_peer(peer: VerifiedPeer) -> Result<Self, CredentialDropError> {
        let uid = peer.effective_uid();
        let gid = peer.effective_gid();
        if uid == 0 || gid == 0 || uid == u32::MAX || gid == u32::MAX {
            Err(CredentialDropError::InvalidClientIdentity)
        } else {
            Ok(Self { uid, gid })
        }
    }
}

struct PreparedExec {
    peer: VerifiedPeer,
    policy_id: Vec<u8>,
    target_identity: [u8; 32],
    executable: CString,
    arguments: Vec<CString>,
    environment: Vec<CString>,
    argument_pointers: Vec<*const c_char>,
    environment_pointers: Vec<*const c_char>,
}

impl PreparedExec {
    fn from_validated(spawn: LauncherSpawnParts) -> Result<Self, CredentialDropError> {
        let executable = CString::new(spawn.installed_executable)
            .map_err(|_| CredentialDropError::InvalidPreparedTarget)?;
        let arguments = spawn
            .arguments
            .into_iter()
            .map(CString::new)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| CredentialDropError::InvalidPreparedTarget)?;
        if arguments.is_empty() {
            return Err(CredentialDropError::InvalidPreparedTarget);
        }
        let environment = spawn
            .environment
            .into_iter()
            .map(|entry| {
                let mut bytes = entry.key().to_vec();
                bytes.push(b'=');
                bytes.extend_from_slice(entry.value());
                CString::new(bytes)
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| CredentialDropError::InvalidPreparedTarget)?;
        let mut argument_pointers = arguments
            .iter()
            .map(|argument| argument.as_ptr())
            .collect::<Vec<_>>();
        argument_pointers.push(std::ptr::null());
        let mut environment_pointers = environment
            .iter()
            .map(|entry| entry.as_ptr())
            .collect::<Vec<_>>();
        environment_pointers.push(std::ptr::null());
        Ok(Self {
            peer: spawn.peer,
            policy_id: spawn.policy_id,
            target_identity: spawn.target_identity,
            executable,
            arguments,
            environment,
            argument_pointers,
            environment_pointers,
        })
    }
}

fn preflight_root() -> Result<(), CredentialDropError> {
    // SAFETY: credential getters have no preconditions.
    let starts_as_root =
        unsafe { getuid() == 0 && geteuid() == 0 && getgid() == 0 && getegid() == 0 };
    if starts_as_root {
        Ok(())
    } else {
        Err(CredentialDropError::LauncherNotRoot)
    }
}

fn preflight_deadline(deadline: std::time::Instant) -> Result<(), CredentialDropError> {
    if std::time::Instant::now() >= deadline {
        Err(CredentialDropError::DeadlineExpired)
    } else {
        Ok(())
    }
}

unsafe fn drop_client_identity(identity: AuthenticatedClientIdentity) {
    // From this point onward, returning would risk continuing from a partially
    // mutated privileged state. Every failure therefore terminates the image.
    // SAFETY: a zero group count requires no group-array storage.
    abort_unless(unsafe { setgroups(0, std::ptr::null()) } == 0);
    // SAFETY: root setgid sets real, effective, and saved group IDs on Darwin.
    abort_unless(unsafe { setgid(identity.gid) } == 0);
    // SAFETY: root setuid sets real, effective, and saved user IDs on Darwin.
    abort_unless(unsafe { setuid(identity.uid) } == 0);

    // SAFETY: identity and group getters have valid scalar/null arguments.
    abort_unless(unsafe {
        getuid() == identity.uid
            && geteuid() == identity.uid
            && getgid() == identity.gid
            && getegid() == identity.gid
            && getgroups(0, std::ptr::null_mut()) == 0
    });

    // Any retained root real/effective/saved ID would permit at least one of
    // these operations. Every attempt must fail and leave all IDs unchanged.
    // SAFETY: scalar IDs are valid inputs; the expected result is denial.
    abort_unless(unsafe { seteuid(0) } != 0);
    // SAFETY: scalar IDs are valid inputs; the expected result is denial.
    abort_unless(unsafe { setuid(0) } != 0);
    // SAFETY: scalar IDs are valid inputs; the expected result is denial.
    abort_unless(unsafe { setegid(0) } != 0);
    // SAFETY: scalar IDs are valid inputs; the expected result is denial.
    abort_unless(unsafe { setgid(0) } != 0);
    // SAFETY: getters verify the failed regain attempts changed no identity.
    abort_unless(unsafe {
        getuid() == identity.uid
            && geteuid() == identity.uid
            && getgid() == identity.gid
            && getegid() == identity.gid
    });

    let limit = ResourceLimit {
        current: 1,
        maximum: 1,
    };
    // SAFETY: install the irreversible limit only after the real UID is
    // nonroot, so Darwin's root exemption cannot bypass it.
    abort_unless(unsafe { setrlimit(RLIMIT_NPROC, &limit) } == 0);
    let mut observed = ResourceLimit {
        current: 0,
        maximum: 0,
    };
    // SAFETY: `observed` is valid writable storage for one rlimit value.
    abort_unless(unsafe { getrlimit(RLIMIT_NPROC, &mut observed) } == 0);
    abort_unless(observed == limit);
}

fn abort_unless(condition: bool) {
    if !condition {
        std::process::abort();
    }
}

#[cfg(test)]
#[path = "supervisor_launcher_test.rs"]
mod tests;
