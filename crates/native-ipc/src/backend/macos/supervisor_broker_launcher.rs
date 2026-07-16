//! Exact broker-local authority for the trusted launcher's two ptrace stops.
//!
//! This supervisor is unprivileged and same-user throughout. Nothing here
//! needs or wants elevated rights: owning an exact direct child, tracing it,
//! holding it at an exec trap, and reaping it are all ordinary operations on
//! one's own children. The launcher exists solely because the target is
//! foreign code that cannot `PT_TRACE_ME` itself — it is our image, which
//! traces itself and then execs the target, giving the broker an exec trap
//! before the target's first instruction. It never changes credentials.
//!
//! What this boundary provides is lifecycle correctness — no leaked process,
//! no zombie, exact termination of an uncooperative target — not privilege
//! separation. A hostile process running as the same user is out of scope.
//!
//! # Fixed launcher channel contract
//!
//! `--broker-death-fd=3` and `--plan-fd=4` are compiled into the installed
//! argument vector, so the launcher entry must honour this ordering exactly:
//!
//! 1. The launcher performs `PT_TRACE_ME` and `raise(SIGSTOP)` **before**
//!    reading FD4. The broker proves the stopped launcher's exact PID, path,
//!    and complete root identity while it is stopped, and only then delivers
//!    the plan. A launcher that blocked on FD4 first could never be identified,
//!    and `wait_initial_stop` never writes FD4, so it would spin to the
//!    deadline.
//! 2. The broker therefore delivers the frame after identity proof, and the
//!    launcher's FD4 read is the first thing it does once continued.
//!
//! This also keeps delivery clear of Darwin's 64 KiB pipe buffer as a
//! correctness dependency: the broker writes FD4 only while the launcher is
//! running and draining it, multiplexed against service death and the exact
//! child state, so a frame larger than the buffer cannot deadlock either side.
//!
//! FD3 carries no data. Its only signal is EOF, which means the broker died.

use std::ffi::{CString, c_char, c_int, c_void};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::rc::Rc;
use std::time::Instant;

use super::super::SupervisorWireError;
use super::super::auth_adapter::broker_report::{BROKER_RESUME_BYTE, encode_broker_trace_report};
use super::{
    ActiveBrokerGate, ActiveBrokerProcess, BrokerEntryError, BrokerGateExit, EAGAIN, EINTR,
    F_GETFL, F_SETFL, O_NONBLOCK, ensure_deadline_live, fcntl,
    finish_trace_report_before_authority, last_errno, read_resume_commit,
    require_resume_commit_eof, set_nonblocking, write_control_while_dormant,
};
use crate::backend::macos::bootstrap::{TaskAuditIdentity, capture_task_audit_identity};

const SIGKILL: c_int = 9;
const SIGSTOP: c_int = 17;
const SIGTRAP: c_int = 5;
const PT_CONTINUE: c_int = 7;
const PT_KILL: c_int = 8;
const WNOHANG: c_int = 1;
const WUNTRACED: c_int = 2;
const ESRCH: c_int = 3;
const ECHILD: c_int = 10;
const POLLIN: i16 = 0x0001;
const POLLOUT: i16 = 0x0004;
const EPIPE: c_int = 32;

pub(in crate::backend::macos::supervisor) const INSTALLED_LAUNCHER_PATH: &str =
    "/Library/PrivilegedHelperTools/com.ro-ag.native-ipc.launcher";
pub(in crate::backend::macos::supervisor) const INSTALLED_LAUNCHER_MODE: &str =
    "--supervisor-launcher";
pub(in crate::backend::macos::supervisor) const INSTALLED_LAUNCHER_DEATH_ARGUMENT: &str =
    "--broker-death-fd=3";
pub(in crate::backend::macos::supervisor) const INSTALLED_LAUNCHER_PLAN_ARGUMENT: &str =
    "--plan-fd=4";
const CANONICAL_PATH: &str = "PATH=/usr/bin:/bin";
const CANONICAL_LANG: &str = "LANG=C";
const CANONICAL_LOCALE: &str = "LC_ALL=C";
const NULL_DEVICE: &str = "/dev/null";

/// Fixed launcher descriptors. Both numbers are also compiled into the
/// installed image's argument vector, so no request value can move a channel.
pub(in crate::backend::macos::supervisor) const LAUNCHER_DEATH_FD: c_int = 3;
pub(in crate::backend::macos::supervisor) const LAUNCHER_PLAN_FD: c_int = 4;
const LAUNCHER_STDIO_FDS: [c_int; 3] = [0, 1, 2];
/// Keeps every broker-retained end clear of the fixed child descriptors, so no
/// `dup2` destination can collide with a still-live parent descriptor.
const STABLE_FD_MINIMUM: c_int = 10;

const F_DUPFD_CLOEXEC: c_int = 67;
const F_SETNOSIGPIPE: c_int = 73;
const O_RDWR: c_int = 2;

const POSIX_SPAWN_SETSIGDEF: i16 = 0x0004;
const POSIX_SPAWN_SETSIGMASK: i16 = 0x0008;
const POSIX_SPAWN_CLOEXEC_DEFAULT: i16 = 0x4000;
const TASK_BOOTSTRAP_PORT: c_int = 4;
/// `MACH_PORT_DEAD`. XNU gates the spawn port action's copyin on
/// `MACH_PORT_VALID`, so this name is stored verbatim rather than copied in.
const MACH_PORT_DEAD: u32 = !0;

type PosixSpawnAttr = *mut c_void;
type PosixSpawnFileActions = *mut c_void;

#[repr(C)]
struct PollFd {
    fd: c_int,
    events: i16,
    revents: i16,
}

unsafe extern "C" {
    fn getegid() -> u32;
    fn geteuid() -> u32;
    fn getgid() -> u32;
    fn getuid() -> u32;
    fn kill(pid: c_int, signal: c_int) -> c_int;
    fn pipe(descriptors: *mut c_int) -> c_int;
    fn poll(descriptors: *mut PollFd, count: u32, timeout_ms: c_int) -> c_int;
    fn posix_spawn(
        pid: *mut c_int,
        path: *const c_char,
        file_actions: *const PosixSpawnFileActions,
        attributes: *const PosixSpawnAttr,
        argv: *const *mut c_char,
        environment: *const *mut c_char,
    ) -> c_int;
    fn posix_spawn_file_actions_addclose(actions: *mut PosixSpawnFileActions, fd: c_int) -> c_int;
    fn posix_spawn_file_actions_adddup2(
        actions: *mut PosixSpawnFileActions,
        source: c_int,
        destination: c_int,
    ) -> c_int;
    fn posix_spawn_file_actions_addopen(
        actions: *mut PosixSpawnFileActions,
        fd: c_int,
        path: *const c_char,
        flags: c_int,
        mode: u16,
    ) -> c_int;
    fn posix_spawn_file_actions_destroy(actions: *mut PosixSpawnFileActions) -> c_int;
    fn posix_spawn_file_actions_init(actions: *mut PosixSpawnFileActions) -> c_int;
    fn posix_spawnattr_destroy(attributes: *mut PosixSpawnAttr) -> c_int;
    fn posix_spawnattr_init(attributes: *mut PosixSpawnAttr) -> c_int;
    fn posix_spawnattr_setflags(attributes: *mut PosixSpawnAttr, flags: i16) -> c_int;
    fn posix_spawnattr_setsigdefault(attributes: *mut PosixSpawnAttr, signals: *const u32)
    -> c_int;
    fn posix_spawnattr_setsigmask(attributes: *mut PosixSpawnAttr, signals: *const u32) -> c_int;
    fn posix_spawnattr_setspecialport_np(
        attributes: *mut PosixSpawnAttr,
        port: u32,
        which: c_int,
    ) -> c_int;
    fn ptrace(request: c_int, pid: c_int, address: *mut c_void, data: c_int) -> c_int;
    fn read(fd: c_int, buffer: *mut u8, count: usize) -> isize;
    fn sigdelset(set: *mut u32, signal: c_int) -> c_int;
    fn sigemptyset(set: *mut u32) -> c_int;
    fn sigfillset(set: *mut u32) -> c_int;
    fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int;
    fn write(fd: c_int, buffer: *const u8, count: usize) -> isize;
}

/// Preparation or exact-spawn failure before launcher authority is minted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LauncherSpawnFailure {
    /// A fixed installation vector was not a valid C string.
    InvalidFixedImage,
    /// The exact-parent plan could not be re-encoded for the launcher.
    Plan(SupervisorWireError),
    /// The original absolute deadline elapsed before the spawn.
    DeadlineExpired,
    /// The service writer disappeared before the spawn.
    ServiceGone,
    /// The service gate carried a byte where only EOF is canonical.
    InvalidGate,
    /// A fixed channel pipe failed with this Darwin error number.
    Pipe(c_int),
    /// A descriptor operation failed with this Darwin error number.
    Descriptor(c_int),
    /// A spawn file action failed with this error number.
    FileActions(c_int),
    /// A spawn attribute failed with this error number.
    Attributes(c_int),
    /// `posix_spawn` itself failed with this error number.
    Spawn(c_int),
}

/// Failed launcher spawn that retains the complete exact broker authority.
#[must_use = "a failed launcher spawn retains exact broker authority"]
pub(super) struct LauncherSpawnError {
    active: ActiveBrokerProcess,
    failure: LauncherSpawnFailure,
}

impl LauncherSpawnError {
    pub(super) fn into_parts(self) -> (ActiveBrokerProcess, LauncherSpawnFailure) {
        (self.active, self.failure)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum LauncherWaitError {
    InvalidPid,
    ServiceGone,
    InvalidGate,
    DeadlineExpired,
    UnexpectedStatus,
    IdentityTransition,
    Native(c_int),
}

/// Installation-only fixed launcher image and canonical clean-exec vectors.
///
/// No request data selects its path, arguments, environment, credentials, PID,
/// signal, or descriptors. Construction alone does not claim installed-image
/// verification; that obligation remains with the privileged runtime.
pub(super) struct InstalledLauncherImage {
    path: CString,
    mode: CString,
    death_argument: CString,
    plan_argument: CString,
    environment_path: CString,
    environment_lang: CString,
    environment_locale: CString,
    null_device: CString,
}

impl InstalledLauncherImage {
    /// # Safety
    ///
    /// The installed supervisor must first verify the fixed path is the
    /// immutable root-owned signed launcher image for this service.
    pub(super) unsafe fn from_verified_installation() -> Result<Self, LauncherSpawnFailure> {
        Ok(Self {
            path: fixed_launcher_cstring(INSTALLED_LAUNCHER_PATH)?,
            mode: fixed_launcher_cstring(INSTALLED_LAUNCHER_MODE)?,
            death_argument: fixed_launcher_cstring(INSTALLED_LAUNCHER_DEATH_ARGUMENT)?,
            plan_argument: fixed_launcher_cstring(INSTALLED_LAUNCHER_PLAN_ARGUMENT)?,
            environment_path: fixed_launcher_cstring(CANONICAL_PATH)?,
            environment_lang: fixed_launcher_cstring(CANONICAL_LANG)?,
            environment_locale: fixed_launcher_cstring(CANONICAL_LOCALE)?,
            null_device: fixed_launcher_cstring(NULL_DEVICE)?,
        })
    }

    fn argv(&self) -> [*mut c_char; 5] {
        [
            self.path.as_ptr().cast_mut(),
            self.mode.as_ptr().cast_mut(),
            self.death_argument.as_ptr().cast_mut(),
            self.plan_argument.as_ptr().cast_mut(),
            std::ptr::null_mut(),
        ]
    }

    fn environment(&self) -> [*mut c_char; 4] {
        [
            self.environment_path.as_ptr().cast_mut(),
            self.environment_lang.as_ptr().cast_mut(),
            self.environment_locale.as_ptr().cast_mut(),
            std::ptr::null_mut(),
        ]
    }

    /// Credentials the launcher must already carry at its initial stop.
    ///
    /// This supervisor is unprivileged and same-user, so the launcher is an
    /// ordinary direct child that must present exactly this process's own
    /// identity. It never gains or drops privilege: an image whose credentials
    /// differ here changed identity across exec (a set-user-ID or set-group-ID
    /// binary) and is therefore not the image the deployer installed.
    fn fixed_identity(&self) -> FixedLauncherIdentity {
        // SAFETY: credential getters have no preconditions.
        unsafe {
            FixedLauncherIdentity {
                real_uid: getuid(),
                effective_uid: geteuid(),
                real_gid: getgid(),
                effective_gid: getegid(),
                executable: self.path.as_bytes().to_vec(),
            }
        }
    }
}

fn fixed_launcher_cstring(value: &'static str) -> Result<CString, LauncherSpawnFailure> {
    CString::new(value).map_err(|_| LauncherSpawnFailure::InvalidFixedImage)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExactPhase {
    AwaitingInitialStop,
    UnprovenInitialStop,
    AwaitingExecTrap,
    ObservedTracedStop,
    ExecTrapHeld,
    RunningTarget,
    Reaped,
}

struct ExactLauncher {
    pid: c_int,
    phase: ExactPhase,
    active: ActiveBrokerProcess,
    expected_launcher: FixedLauncherIdentity,
    channels: Option<RetainedLauncherChannels>,
    _thread_confined: std::marker::PhantomData<Rc<()>>,
}

/// Broker-retained ends of the fixed launcher channels.
///
/// Closing `death_writer` is the launcher's only broker-death signal, so exact
/// cleanup drops it before any signal: a launcher blocked on its own FD3 probe
/// then wakes and self-terminates even if the kill races. Dropping the private
/// bootstrap port destroys the launcher's inherited namespace rather than
/// reconnecting it to `launchd`.
/// Field order is release order: dropping this value closes the plan writer
/// first, then the death writer.
pub(super) struct RetainedLauncherChannels {
    /// `None` once the one canonical frame is delivered and FD4 is closed.
    plan: Option<LauncherPlanDelivery>,
    /// The launcher's only broker-death signal; live for its whole life.
    death_writer: OwnedFd,
}

/// The one canonical launcher frame and the exact writer that delivers it.
struct LauncherPlanDelivery {
    writer: OwnedFd,
    frame: Vec<u8>,
}

impl RetainedLauncherChannels {
    /// Fixture shape carrying real ends for a child the test spawned itself.
    #[cfg(test)]
    pub(super) fn for_test(plan_writer: OwnedFd, death_writer: OwnedFd, frame: Vec<u8>) -> Self {
        Self {
            plan: Some(LauncherPlanDelivery {
                writer: plan_writer,
                frame,
            }),
            death_writer,
        }
    }
}

/// Installation-bound identity of the only launcher image the broker may
/// trace. Its fields are private so request data cannot construct it.
pub(super) struct FixedLauncherIdentity {
    real_uid: u32,
    effective_uid: u32,
    real_gid: u32,
    effective_gid: u32,
    executable: Vec<u8>,
}

impl FixedLauncherIdentity {
    #[cfg(test)]
    fn for_test(
        real_uid: u32,
        effective_uid: u32,
        real_gid: u32,
        effective_gid: u32,
        executable: Vec<u8>,
    ) -> Self {
        Self {
            real_uid,
            effective_uid,
            real_gid,
            effective_gid,
            executable,
        }
    }
}

/// Exact unreaped direct child immediately after a positive fixed-image spawn.
#[must_use = "the exact launcher must reach exec trap or be exact-cleaned"]
pub(super) struct SpawnedLauncher {
    inner: Option<ExactLauncher>,
}

/// The sole production transition that creates a trusted launcher child.
///
/// Every allocation, C string, pipe, descriptor relocation, file action, spawn
/// attribute, private bootstrap port, expected identity, and the canonical
/// launcher frame is prepared before `posix_spawn`, so no preparation failure
/// can ever strand a live child. A positive PID is then wrapped in exact
/// unreaped direct-child ownership with no intervening fallible call,
/// allocation, or callback.
pub(super) fn spawn_fixed_launcher(
    active: ActiveBrokerProcess,
    image: &InstalledLauncherImage,
) -> Result<SpawnedLauncher, Box<LauncherSpawnError>> {
    PreparedLauncherSpawn::prepare(active, image)?.spawn_and_arm()
}

/// Complete pre-spawn state for exactly one launcher child.
///
/// It owns the exact broker authority and borrows the one image it was
/// prepared against, so the identity the broker will verify and the vectors it
/// will actually spawn cannot come from two different images or plans.
struct PreparedLauncherSpawn<'image> {
    image: &'image InstalledLauncherImage,
    active: ActiveBrokerProcess,
    resources: LauncherSpawnResources,
}

/// Every fallible resource one launcher child needs, all already acquired.
struct LauncherSpawnResources {
    actions: FileActionsGuard,
    attributes: SpawnAttributesGuard,
    death_reader: OwnedFd,
    plan_reader: OwnedFd,
    channels: RetainedLauncherChannels,
    expected_launcher: FixedLauncherIdentity,
}

impl<'image> PreparedLauncherSpawn<'image> {
    fn prepare(
        active: ActiveBrokerProcess,
        image: &'image InstalledLauncherImage,
    ) -> Result<Self, Box<LauncherSpawnError>> {
        match LauncherSpawnResources::acquire(&active, image) {
            Ok(resources) => Ok(Self {
                image,
                active,
                resources,
            }),
            Err(failure) => Err(Box::new(LauncherSpawnError { active, failure })),
        }
    }
}

impl LauncherSpawnResources {
    fn acquire(
        active: &ActiveBrokerProcess,
        image: &InstalledLauncherImage,
    ) -> Result<Self, LauncherSpawnFailure> {
        let frame = active
            .plan
            .launcher_frame()
            .map_err(LauncherSpawnFailure::Plan)?;
        let expected_launcher = image.fixed_identity();
        let (death_reader, death_writer) = create_launcher_pipe()?;
        let (plan_reader, plan_writer) = create_launcher_pipe()?;
        // The broker never writes the death pipe and must outlive a launcher
        // that dies mid-frame, so neither retained writer may raise SIGPIPE.
        set_no_sigpipe(death_writer.as_raw_fd())?;
        set_no_sigpipe(plan_writer.as_raw_fd())?;
        // Plan delivery is multiplexed against service death and exact child
        // state, so it must never block on a launcher that stopped reading.
        set_writer_nonblocking(plan_writer.as_raw_fd())?;

        let mut actions = FileActionsGuard::new()?;
        // Canonical stdio: the launcher inherits no terminal. Together with
        // CLOEXEC_DEFAULT below, the launcher receives exactly fds 0-4 and no
        // channel back to the broker or service. This covers the launcher
        // only: dup2 clears FD_CLOEXEC on its destination and CLOEXEC_DEFAULT
        // is scoped to this spawn, so fds 3 and 4 survive the launcher's own
        // exec. The launcher entry must close both before execing the target.
        for fd in LAUNCHER_STDIO_FDS {
            actions.add_open_null(fd, &image.null_device)?;
        }
        actions.add_dup2(death_reader.as_raw_fd(), LAUNCHER_DEATH_FD)?;
        actions.add_dup2(plan_reader.as_raw_fd(), LAUNCHER_PLAN_FD)?;
        // The relocated ends are already close-on-exec, but file actions run
        // before exec, so every parent-retained end is closed explicitly.
        for fd in [
            death_reader.as_raw_fd(),
            death_writer.as_raw_fd(),
            plan_reader.as_raw_fd(),
            plan_writer.as_raw_fd(),
        ] {
            actions.add_close(fd)?;
        }

        let mut attributes = SpawnAttributesGuard::new()?;
        attributes.configure_canonical_signals()?;
        attributes.configure_dead_end_bootstrap()?;

        Ok(Self {
            actions,
            attributes,
            death_reader,
            plan_reader,
            channels: RetainedLauncherChannels {
                plan: Some(LauncherPlanDelivery {
                    writer: plan_writer,
                    frame,
                }),
                death_writer,
            },
            expected_launcher,
        })
    }
}

impl PreparedLauncherSpawn<'_> {
    fn spawn_and_arm(self) -> Result<SpawnedLauncher, Box<LauncherSpawnError>> {
        let Self {
            image,
            active,
            resources:
                LauncherSpawnResources {
                    actions,
                    attributes,
                    death_reader,
                    plan_reader,
                    channels,
                    expected_launcher,
                },
        } = self;
        // Last veto while no child exists. Service death and the original
        // absolute deadline both outrank creating a new privileged process.
        if let Err(failure) = ensure_spawn_admissible(&active) {
            return Err(Box::new(LauncherSpawnError { active, failure }));
        }

        let argv = image.argv();
        let environment = image.environment();
        let mut pid = 0;
        // SAFETY: every C string, pointer array, file action, spawn attribute,
        // bootstrap right, and pipe end was completely prepared above and
        // remains live for the duration of this call.
        let result = unsafe {
            posix_spawn(
                &raw mut pid,
                image.path.as_ptr(),
                &raw const actions.0,
                &raw const attributes.0,
                argv.as_ptr(),
                environment.as_ptr(),
            )
        };
        if result != 0 {
            return Err(Box::new(LauncherSpawnError {
                active,
                failure: LauncherSpawnFailure::Spawn(result),
            }));
        }
        if pid <= 0 {
            std::process::abort();
        }

        // No allocation, fallible operation, or callback may occur between the
        // successful positive spawn and this single ownership transition.
        // SAFETY: posix_spawn just returned this positive direct-child PID to
        // the broker's sole wait domain, `active` is the exact plan that
        // authorized it, and `channels` are the ends created for this child.
        let launcher = unsafe { SpawnedLauncher::arm(pid, active, expected_launcher, channels) };

        // The child's ends and the prepared C objects may be destroyed only
        // after the exact launcher authority is armed.
        drop(death_reader);
        drop(plan_reader);
        drop(actions);
        drop(attributes);
        Ok(launcher)
    }
}

fn ensure_spawn_admissible(active: &ActiveBrokerProcess) -> Result<(), LauncherSpawnFailure> {
    set_gate_nonblocking(&active.gate).map_err(spawn_gate_failure)?;
    let verdict =
        probe_gate(&active.gate).and_then(|()| ensure_deadline(active.plan.deadline().local()));
    // The blocking contract belongs to ActiveBrokerProcess, which is minted
    // with a blocking gate. A failed spawn hands that authority back, and its
    // wait_for_service_death retries only EINTR, so leaving O_NONBLOCK set
    // would turn a later clean service-death wait into an EAGAIN error exit.
    let restored = set_gate_blocking(&active.gate);
    verdict.map_err(spawn_gate_failure)?;
    restored
}

fn set_gate_blocking(gate: &ActiveBrokerGate) -> Result<(), LauncherSpawnFailure> {
    set_nonblocking(gate.reader.as_raw_fd(), false).map_err(|error| match error {
        BrokerEntryError::Descriptor(error) => LauncherSpawnFailure::Descriptor(error),
        // set_nonblocking reports no other failure for a live descriptor.
        _ => std::process::abort(),
    })
}

fn spawn_gate_failure(error: LauncherWaitError) -> LauncherSpawnFailure {
    match error {
        LauncherWaitError::ServiceGone => LauncherSpawnFailure::ServiceGone,
        LauncherWaitError::InvalidGate => LauncherSpawnFailure::InvalidGate,
        LauncherWaitError::DeadlineExpired => LauncherSpawnFailure::DeadlineExpired,
        LauncherWaitError::Native(error) => LauncherSpawnFailure::Descriptor(error),
        // The gate and clock checks above cannot produce a child-state verdict.
        LauncherWaitError::InvalidPid
        | LauncherWaitError::UnexpectedStatus
        | LauncherWaitError::IdentityTransition => std::process::abort(),
    }
}

fn create_launcher_pipe() -> Result<(OwnedFd, OwnedFd), LauncherSpawnFailure> {
    let mut descriptors = [-1; 2];
    // SAFETY: descriptors points to two writable integers.
    if unsafe { pipe(descriptors.as_mut_ptr()) } != 0 {
        return Err(LauncherSpawnFailure::Pipe(last_errno()));
    }
    // SAFETY: the successful pipe returned two distinct owned descriptors.
    let reader = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
    // SAFETY: the successful pipe returned two distinct owned descriptors.
    let writer = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
    // Darwin has no pipe2, so relocate both ends clear of the fixed child
    // descriptors and make them close-on-exec in one operation. The original
    // ends close when this scope ends.
    let reader = duplicate_cloexec(reader.as_raw_fd())?;
    let writer = duplicate_cloexec(writer.as_raw_fd())?;
    Ok((reader, writer))
}

fn duplicate_cloexec(fd: c_int) -> Result<OwnedFd, LauncherSpawnFailure> {
    // SAFETY: fd is live and F_DUPFD_CLOEXEC returns a new owned descriptor at
    // or above the requested minimum.
    let duplicate = unsafe { fcntl(fd, F_DUPFD_CLOEXEC, STABLE_FD_MINIMUM) };
    if duplicate < 0 {
        return Err(LauncherSpawnFailure::Descriptor(last_errno()));
    }
    // SAFETY: the successful fcntl returned one fresh owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(duplicate) })
}

fn set_no_sigpipe(fd: c_int) -> Result<(), LauncherSpawnFailure> {
    // SAFETY: fd is live and Darwin's F_SETNOSIGPIPE takes a scalar flag.
    if unsafe { fcntl(fd, F_SETNOSIGPIPE, 1) } == 0 {
        Ok(())
    } else {
        Err(LauncherSpawnFailure::Descriptor(last_errno()))
    }
}

fn set_writer_nonblocking(fd: c_int) -> Result<(), LauncherSpawnFailure> {
    // SAFETY: fd is live and F_GETFL is a read-only descriptor query.
    let flags = unsafe { fcntl(fd, F_GETFL) };
    if flags < 0 {
        return Err(LauncherSpawnFailure::Descriptor(last_errno()));
    }
    // SAFETY: fd is live and the value preserves unrelated status flags.
    if unsafe { fcntl(fd, F_SETFL, flags | O_NONBLOCK) } == 0 {
        Ok(())
    } else {
        Err(LauncherSpawnFailure::Descriptor(last_errno()))
    }
}

struct FileActionsGuard(PosixSpawnFileActions);

impl FileActionsGuard {
    fn new() -> Result<Self, LauncherSpawnFailure> {
        let mut actions = std::ptr::null_mut();
        // SAFETY: actions points to writable opaque storage.
        let result = unsafe { posix_spawn_file_actions_init(&raw mut actions) };
        if result == 0 {
            Ok(Self(actions))
        } else {
            Err(LauncherSpawnFailure::FileActions(result))
        }
    }

    fn add_open_null(&mut self, fd: c_int, path: &CString) -> Result<(), LauncherSpawnFailure> {
        // SAFETY: actions is initialized, fd is nonnegative, and path is the
        // installed image's live fixed device C string.
        spawn_file_action_result(unsafe {
            posix_spawn_file_actions_addopen(&raw mut self.0, fd, path.as_ptr(), O_RDWR, 0)
        })
    }

    fn add_dup2(&mut self, source: c_int, destination: c_int) -> Result<(), LauncherSpawnFailure> {
        // SAFETY: actions is initialized and both descriptors are nonnegative.
        spawn_file_action_result(unsafe {
            posix_spawn_file_actions_adddup2(&raw mut self.0, source, destination)
        })
    }

    fn add_close(&mut self, fd: c_int) -> Result<(), LauncherSpawnFailure> {
        // SAFETY: actions is initialized and fd is nonnegative.
        spawn_file_action_result(unsafe { posix_spawn_file_actions_addclose(&raw mut self.0, fd) })
    }
}

impl Drop for FileActionsGuard {
    fn drop(&mut self) {
        // These guards are destroyed only after a successful spawn has already
        // armed the exact launcher, and abort() would skip ExactLauncher::drop
        // and orphan a live root child. Destroy can only fail on storage this
        // type never constructs, so the no-stranded-child law outranks a
        // fail-stop here and the result is deliberately ignored.
        // SAFETY: initialized actions are destroyed exactly once.
        let _ = unsafe { posix_spawn_file_actions_destroy(&raw mut self.0) };
    }
}

fn spawn_file_action_result(result: c_int) -> Result<(), LauncherSpawnFailure> {
    if result == 0 {
        Ok(())
    } else {
        Err(LauncherSpawnFailure::FileActions(result))
    }
}

struct SpawnAttributesGuard(PosixSpawnAttr);

impl SpawnAttributesGuard {
    fn new() -> Result<Self, LauncherSpawnFailure> {
        let mut attributes = std::ptr::null_mut();
        // SAFETY: attributes points to writable opaque storage.
        let result = unsafe { posix_spawnattr_init(&raw mut attributes) };
        if result == 0 {
            Ok(Self(attributes))
        } else {
            Err(LauncherSpawnFailure::Attributes(result))
        }
    }

    fn configure_canonical_signals(&mut self) -> Result<(), LauncherSpawnFailure> {
        let mut defaults = 0_u32;
        let mut mask = 0_u32;
        // SAFETY: both values are Darwin sigset_t storage. SIGKILL and SIGSTOP
        // cannot be caught or reset, so they are removed from the default set.
        if unsafe { sigfillset(&raw mut defaults) } != 0
            || unsafe { sigdelset(&raw mut defaults, SIGKILL) } != 0
            || unsafe { sigdelset(&raw mut defaults, SIGSTOP) } != 0
            || unsafe { sigemptyset(&raw mut mask) } != 0
        {
            return Err(LauncherSpawnFailure::Attributes(last_errno()));
        }
        // SAFETY: initialized attributes and signal sets remain live.
        let result = unsafe { posix_spawnattr_setsigdefault(&raw mut self.0, &raw const defaults) };
        if result != 0 {
            return Err(LauncherSpawnFailure::Attributes(result));
        }
        // SAFETY: initialized attributes and empty signal mask remain live.
        let result = unsafe { posix_spawnattr_setsigmask(&raw mut self.0, &raw const mask) };
        if result != 0 {
            return Err(LauncherSpawnFailure::Attributes(result));
        }
        // SAFETY: flags are public Darwin posix_spawn flags. No suspended-spawn
        // or containment-claiming session flag is used; the launcher stops
        // itself under PT_TRACE_ME instead.
        let result = unsafe {
            posix_spawnattr_setflags(
                &raw mut self.0,
                POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(LauncherSpawnFailure::Attributes(result))
        }
    }

    /// Sets the child's `TASK_BOOTSTRAP_PORT` special port to a dead name.
    ///
    /// The intent is to deny the launcher and its target any `launchd` service
    /// lookup. It is not sufficient on its own: adversarial measurement on the
    /// current OS shows a child spawned this way still obtains a live bootstrap
    /// port and reaches `launchd`, so this only removes the *inherited* port and
    /// does not close the delegation path. Cutting off `launchd` is an open
    /// problem tracked for the adversarial tier, not something this call proves.
    ///
    /// A dead name is used rather than a live port the broker owns but never
    /// services: a never-drained receive right would let the child's first
    /// bootstrap message queue and then block it forever in `mach_msg`, which
    /// `ResumedTarget::wait_for_exit` could not preempt because Ready delivery
    /// is the final deadline commit. A dead name owns no resource to retain.
    fn configure_dead_end_bootstrap(&mut self) -> Result<(), LauncherSpawnFailure> {
        // SAFETY: initialized attributes and a name the kernel stores verbatim.
        let result = unsafe {
            posix_spawnattr_setspecialport_np(&raw mut self.0, MACH_PORT_DEAD, TASK_BOOTSTRAP_PORT)
        };
        if result == 0 {
            Ok(())
        } else {
            Err(LauncherSpawnFailure::Attributes(result))
        }
    }
}

impl Drop for SpawnAttributesGuard {
    fn drop(&mut self) {
        // Ignored for the same reason as FileActionsGuard::drop: this runs
        // after the exact launcher is armed, and abort() would strand it.
        // SAFETY: initialized attributes are destroyed exactly once.
        let _ = unsafe { posix_spawnattr_destroy(&raw mut self.0) };
    }
}

/// Exact launcher held at the expected initial stop, before ptrace is proven.
#[must_use = "the observed initial stop must prove ptrace or exact-clean"]
pub(super) struct InitialStopObserved {
    inner: Option<ExactLauncher>,
    before_exec: TaskAuditIdentity,
}

/// Exact traced launcher running only toward its immediate target `execve`.
#[must_use = "the running traced launcher must reach exec trap or exact-clean"]
pub(super) struct AwaitingExecTrap {
    inner: Option<ExactLauncher>,
    before_exec: TaskAuditIdentity,
}

/// Sole production-shaped proof of a real exec transition held at `SIGTRAP`.
#[must_use = "the exec-trap-held launcher must report, resume, or exact-clean"]
pub(super) struct ExecTrapHeld {
    inner: Option<ExactLauncher>,
    _after_exec: TaskAuditIdentity,
}

/// Exact exec-trap authority after its canonical FD5 report reached service.
#[must_use = "the reported target must receive Ready-bound resume or exact-clean"]
pub(super) struct ReportedExecTrapHeld {
    inner: Option<ExactLauncher>,
}

/// Exact exec-trap authority after the canonical Ready-bound RESUME commit.
#[must_use = "the committed target must resume exactly once or exact-clean"]
pub(super) struct ReadyCommittedExecTrap {
    inner: Option<ExactLauncher>,
}

/// Exact traced target running only after successful Ready delivery.
#[must_use = "the running target must retain broker cleanup authority"]
pub(super) struct ResumedTarget {
    inner: Option<ExactLauncher>,
}

/// Exact natural exit observed by the sole broker waiter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ExactTargetExit {
    Exited(u8),
    Signaled(c_int),
}

impl SpawnedLauncher {
    /// The sole transition that mints exact unreaped direct-child authority.
    ///
    /// # Safety
    ///
    /// `pid` must be the strictly positive result of this active broker's
    /// just-finished launcher spawn, no other waiter may observe the child,
    /// `active` must be the exact plan that authorized it, and `channels` must
    /// be the broker ends created for that same child.
    unsafe fn arm(
        pid: c_int,
        active: ActiveBrokerProcess,
        expected_launcher: FixedLauncherIdentity,
        channels: RetainedLauncherChannels,
    ) -> Self {
        if pid <= 0 {
            std::process::abort();
        }
        Self {
            inner: Some(ExactLauncher {
                pid,
                phase: ExactPhase::AwaitingInitialStop,
                active,
                expected_launcher,
                channels: Some(channels),
                _thread_confined: std::marker::PhantomData,
            }),
        }
    }

    /// # Safety
    ///
    /// Same contract as [`SpawnedLauncher::arm`]. Production launchers are
    /// armed only inside [`spawn_fixed_launcher`]; this exists so fixtures can
    /// arm a child they spawned themselves, with real retained channels.
    #[cfg(test)]
    pub(super) unsafe fn from_positive_spawn(
        pid: c_int,
        active: ActiveBrokerProcess,
        expected_launcher: FixedLauncherIdentity,
        channels: RetainedLauncherChannels,
    ) -> Result<Self, LauncherWaitError> {
        if pid <= 0 {
            return Err(LauncherWaitError::InvalidPid);
        }
        // SAFETY: the caller carries the same contract forward, and the pid
        // sign was just checked so `arm` cannot abort on it.
        Ok(unsafe { Self::arm(pid, active, expected_launcher, channels) })
    }

    pub(super) fn wait_initial_stop(mut self) -> Result<InitialStopObserved, LauncherWaitError> {
        let mut inner = self.inner.take().unwrap_or_else(|| std::process::abort());
        set_gate_nonblocking(inner.gate())?;
        wait_for_exact_stop(&mut inner, SIGSTOP)?;
        probe_gate(inner.gate())?;
        ensure_deadline(inner.deadline())?;
        let before_exec = capture_task_audit_identity(inner.pid)
            .map_err(|_| LauncherWaitError::IdentityTransition)?;
        probe_gate(inner.gate())?;
        ensure_deadline(inner.deadline())?;
        if !before_exec.proves_exact_process_image(
            inner.pid,
            inner.expected_launcher.real_uid,
            inner.expected_launcher.effective_uid,
            inner.expected_launcher.real_gid,
            inner.expected_launcher.effective_gid,
            &inner.expected_launcher.executable,
        ) {
            return Err(LauncherWaitError::IdentityTransition);
        }
        Ok(InitialStopObserved {
            inner: Some(inner),
            before_exec,
        })
    }
}

impl InitialStopObserved {
    pub(super) fn prove_trace_and_continue_to_exec(
        mut self,
    ) -> Result<AwaitingExecTrap, LauncherWaitError> {
        let mut inner = self.inner.take().unwrap_or_else(|| std::process::abort());
        probe_gate(inner.gate())?;
        ensure_deadline(inner.deadline())?;
        // SAFETY: this owner observed the exact tracee at its initial stop;
        // Darwin address 1 continues at the current program counter.
        if unsafe {
            ptrace(
                PT_CONTINUE,
                inner.pid,
                std::ptr::without_provenance_mut::<c_void>(1),
                0,
            )
        } != 0
        {
            return Err(LauncherWaitError::Native(last_errno()));
        }
        inner.phase = ExactPhase::AwaitingExecTrap;
        probe_gate(inner.gate())?;
        ensure_deadline(inner.deadline())?;
        Ok(AwaitingExecTrap {
            inner: Some(inner),
            before_exec: self.before_exec,
        })
    }
}

impl AwaitingExecTrap {
    /// Delivers the one canonical launcher frame on fixed FD4.
    ///
    /// This runs only after the initial stop proved the exact launcher, and
    /// only while it is continued and draining FD4. Delivery is therefore
    /// nonblocking and multiplexed against the three authorities that outrank
    /// it: service death, the original absolute deadline, and the exact child's
    /// own state. A launcher that died mid-frame surfaces as `EPIPE` rather
    /// than as a broker that blocks forever, because both retained writers were
    /// created with `F_SETNOSIGPIPE`.
    ///
    /// Because the broker writes only while the launcher is running, a frame
    /// larger than Darwin's pipe buffer cannot deadlock either side.
    pub(super) fn deliver_plan(&mut self) -> Result<(), LauncherWaitError> {
        let inner = self.inner.as_mut().unwrap_or_else(|| std::process::abort());
        // The plan is delivered exactly once; production always arms with one.
        let Some(LauncherPlanDelivery { writer, frame }) =
            inner.channels.as_mut().and_then(|held| held.plan.take())
        else {
            std::process::abort();
        };
        let deadline = inner.deadline();
        let mut written = 0_usize;
        while written < frame.len() {
            // Service loss and the original deadline both outrank handing a
            // launcher the plan it would act on.
            probe_gate(&inner.active.gate)?;
            ensure_deadline(deadline)?;
            let remaining = &frame[written..];
            // SAFETY: the slice is live for its own length and the retained
            // nonblocking writer is this launcher's exact plan channel.
            let result = unsafe { write(writer.as_raw_fd(), remaining.as_ptr(), remaining.len()) };
            if result > 0 {
                written += usize::try_from(result).unwrap_or_else(|_| std::process::abort());
                continue;
            }
            if result == 0 {
                return Err(LauncherWaitError::UnexpectedStatus);
            }
            match last_errno() {
                EINTR => {}
                EAGAIN => poll_plan_slice(&inner.active.gate, writer.as_raw_fd())?,
                // The launcher closed its plan reader or died mid-frame.
                EPIPE => return Err(LauncherWaitError::UnexpectedStatus),
                error => return Err(LauncherWaitError::Native(error)),
            }
        }
        // Closing the writer is the frame's terminator: the launcher requires
        // EOF, so a truncated or extended frame cannot be mistaken for this one.
        drop(writer);
        probe_gate(&inner.active.gate)?;
        ensure_deadline(deadline)
    }

    pub(super) fn wait_exec_trap(mut self) -> Result<ExecTrapHeld, LauncherWaitError> {
        let mut inner = self.inner.take().unwrap_or_else(|| std::process::abort());
        wait_for_exact_stop(&mut inner, SIGTRAP)?;
        inner.phase = ExactPhase::ExecTrapHeld;
        probe_gate(inner.gate())?;
        ensure_deadline(inner.deadline())?;
        let after_exec = capture_task_audit_identity(inner.pid)
            .map_err(|_| LauncherWaitError::IdentityTransition)?;
        if !after_exec.proves_exec_transition_from(
            &self.before_exec,
            inner.pid,
            inner.expected_euid(),
            inner.expected_egid(),
            inner.expected_executable(),
        ) {
            return Err(LauncherWaitError::IdentityTransition);
        }
        probe_gate(inner.gate())?;
        ensure_deadline(inner.deadline())?;
        Ok(ExecTrapHeld {
            inner: Some(inner),
            _after_exec: after_exec,
        })
    }
}

impl ExecTrapHeld {
    pub(super) fn report_trace_stops(
        mut self,
    ) -> Result<Result<ReportedExecTrapHeld, BrokerGateExit>, BrokerEntryError> {
        let mut inner = self.inner.take().unwrap_or_else(|| std::process::abort());
        let deadline = inner.deadline();
        ensure_deadline_live(Some(deadline))?;
        let bytes = encode_broker_trace_report(inner.active.plan.trace_report_binding())
            .map_err(|error| BrokerEntryError::Plan(error.into()))?;
        let gate_fd = inner.active.gate.reader.as_raw_fd();
        set_nonblocking(gate_fd, true)?;
        if write_control_while_dormant(&mut inner.active.trace, gate_fd, &bytes, deadline)?
            .is_some()
        {
            return Ok(Err(BrokerGateExit::ServiceGone));
        }
        if let Some(exit) = finish_trace_report_before_authority(&inner.active.trace, gate_fd)? {
            return Ok(Err(exit));
        }
        Ok(Ok(ReportedExecTrapHeld { inner: Some(inner) }))
    }

    #[cfg(test)]
    fn exact_pid_for_test(&self) -> c_int {
        self.inner
            .as_ref()
            .unwrap_or_else(|| std::process::abort())
            .pid
    }

    #[cfg(test)]
    fn wait_for_gate_eof_for_test(&self) {
        let inner = self.inner.as_ref().unwrap_or_else(|| std::process::abort());
        loop {
            match probe_gate(inner.gate()) {
                Err(LauncherWaitError::ServiceGone) => return,
                Ok(()) => poll_gate_slice(inner.gate()).unwrap(),
                Err(error) => panic!("unexpected gate probe failure: {error:?}"),
            }
        }
    }
}

impl ReportedExecTrapHeld {
    pub(super) fn wait_for_ready_commit(
        mut self,
    ) -> Result<Result<ReadyCommittedExecTrap, BrokerGateExit>, BrokerEntryError> {
        let mut inner = self.inner.take().unwrap_or_else(|| std::process::abort());
        let gate_fd = inner.active.gate.reader.as_raw_fd();
        let mut resume = [0_u8; 1];
        if read_resume_commit(&mut inner.active.trace, gate_fd, &mut resume)?.is_some() {
            return Ok(Err(BrokerGateExit::ServiceGone));
        }
        if resume != BROKER_RESUME_BYTE {
            return Err(BrokerEntryError::Plan(SupervisorWireError::Malformed));
        }
        if require_resume_commit_eof(&mut inner.active.trace, gate_fd)?.is_some() {
            return Ok(Err(BrokerGateExit::ServiceGone));
        }
        Ok(Ok(ReadyCommittedExecTrap { inner: Some(inner) }))
    }
}

impl ReadyCommittedExecTrap {
    pub(super) fn resume_target(mut self) -> Result<ResumedTarget, LauncherWaitError> {
        let mut inner = self.inner.take().unwrap_or_else(|| std::process::abort());
        // The commit token is freely delayable, so service liveness must be
        // sampled at the effect boundary rather than only when it was minted.
        probe_gate(inner.gate())?;
        // Successful Ready delivery is the final deadline commit. This exact
        // continuation therefore performs no second clock veto.
        // SAFETY: the retained sole waiter holds the exact target at its
        // verified exec trap; Darwin address 1 resumes at the current PC.
        if unsafe {
            ptrace(
                PT_CONTINUE,
                inner.pid,
                std::ptr::without_provenance_mut::<c_void>(1),
                0,
            )
        } != 0
        {
            return Err(LauncherWaitError::Native(last_errno()));
        }
        inner.phase = ExactPhase::RunningTarget;
        Ok(ResumedTarget { inner: Some(inner) })
    }

    #[cfg(test)]
    fn wait_for_gate_eof_for_test(&self) {
        let inner = self.inner.as_ref().unwrap_or_else(|| std::process::abort());
        loop {
            match probe_gate(inner.gate()) {
                Err(LauncherWaitError::ServiceGone) => return,
                Ok(()) => poll_gate_slice(inner.gate()).unwrap(),
                Err(error) => panic!("unexpected gate probe failure: {error:?}"),
            }
        }
    }
}

impl ResumedTarget {
    pub(super) fn wait_for_exit(self) -> Result<ExactTargetExit, LauncherWaitError> {
        self.wait_for_exit_with_post_wait(|_| {})
    }

    fn wait_for_exit_with_post_wait<Barrier>(
        mut self,
        barrier: Barrier,
    ) -> Result<ExactTargetExit, LauncherWaitError>
    where
        Barrier: FnOnce(&ActiveBrokerGate),
    {
        let mut inner = self.inner.take().unwrap_or_else(|| std::process::abort());
        let mut barrier = Some(barrier);
        loop {
            // Service loss wins over a simultaneously observable target exit.
            // Dropping the retained exact authority then performs exact cleanup.
            probe_gate(inner.gate())?;
            let mut status = 0;
            // SAFETY: the broker remains the sole waiter for this exact,
            // unreaped direct child after the Ready-bound continuation.
            let result = unsafe { waitpid(inner.pid, &raw mut status, WNOHANG | WUNTRACED) };
            if result == inner.pid {
                if traced_stop_signal(status).is_some() {
                    inner.phase = ExactPhase::ObservedTracedStop;
                    barrier.take().unwrap_or_else(|| std::process::abort())(inner.gate());
                    probe_gate(inner.gate())?;
                    return Err(LauncherWaitError::UnexpectedStatus);
                }
                inner.phase = ExactPhase::Reaped;
                // The facts come from this first terminal status; the child is
                // only consumed once the duplicate report is drained too.
                drain_exact_child(inner.pid);
                barrier.take().unwrap_or_else(|| std::process::abort())(inner.gate());
                probe_gate(inner.gate())?;
                return exact_target_exit(status).ok_or(LauncherWaitError::UnexpectedStatus);
            }
            if result < 0 {
                let error = last_errno();
                if error == EINTR {
                    continue;
                }
                if error == ECHILD {
                    std::process::abort();
                }
                return Err(LauncherWaitError::Native(error));
            }
            if result > 0 {
                std::process::abort();
            }
            poll_gate_slice(inner.gate())?;
        }
    }

    #[cfg(test)]
    fn wait_for_exit_with_post_wait_for_test<Barrier>(
        self,
        barrier: Barrier,
    ) -> Result<ExactTargetExit, LauncherWaitError>
    where
        Barrier: FnOnce(&ActiveBrokerGate),
    {
        self.wait_for_exit_with_post_wait(barrier)
    }

    #[cfg(test)]
    fn exact_pid_for_test(&self) -> c_int {
        self.inner
            .as_ref()
            .unwrap_or_else(|| std::process::abort())
            .pid
    }

    #[cfg(test)]
    fn wait_for_gate_eof_for_test(&self) {
        let inner = self.inner.as_ref().unwrap_or_else(|| std::process::abort());
        loop {
            match probe_gate(inner.gate()) {
                Err(LauncherWaitError::ServiceGone) => return,
                Ok(()) => poll_gate_slice(inner.gate()).unwrap(),
                Err(error) => panic!("unexpected gate probe failure: {error:?}"),
            }
        }
    }
}

impl ExactLauncher {
    fn gate(&self) -> &ActiveBrokerGate {
        &self.active.gate
    }

    fn deadline(&self) -> Instant {
        self.active.plan.deadline().local()
    }

    fn expected_euid(&self) -> u32 {
        self.active.plan.effective_uid()
    }

    fn expected_egid(&self) -> u32 {
        self.active.plan.effective_gid()
    }

    fn expected_executable(&self) -> &[u8] {
        self.active.plan.installed_executable()
    }
}

fn wait_for_exact_stop(
    inner: &mut ExactLauncher,
    expected_signal: c_int,
) -> Result<(), LauncherWaitError> {
    loop {
        probe_gate(inner.gate())?;
        ensure_deadline(inner.deadline())?;
        let mut status = 0;
        // SAFETY: this broker is the sole waiter for the exact unreaped child.
        let result = unsafe { waitpid(inner.pid, &mut status, WNOHANG | WUNTRACED) };
        if result == inner.pid {
            match traced_stop_signal(status) {
                Some(signal) => {
                    inner.phase = match inner.phase {
                        ExactPhase::AwaitingInitialStop => ExactPhase::UnprovenInitialStop,
                        ExactPhase::AwaitingExecTrap => ExactPhase::ObservedTracedStop,
                        _ => std::process::abort(),
                    };
                    if signal == expected_signal {
                        return Ok(());
                    }
                    return Err(LauncherWaitError::UnexpectedStatus);
                }
                None => {
                    // The launcher died instead of stopping. Marking it Reaped
                    // stops Drop from cleaning up, so the duplicate terminal
                    // report must be drained here or the child outlives us.
                    inner.phase = ExactPhase::Reaped;
                    drain_exact_child(inner.pid);
                    return Err(LauncherWaitError::UnexpectedStatus);
                }
            }
        }
        if result < 0 {
            let error = last_errno();
            if error == EINTR {
                continue;
            }
            if error == ECHILD {
                std::process::abort();
            }
            return Err(LauncherWaitError::Native(error));
        }
        poll_gate_slice(inner.gate())?;
    }
}

fn set_gate_nonblocking(gate: &ActiveBrokerGate) -> Result<(), LauncherWaitError> {
    let fd = gate.reader.as_raw_fd();
    // SAFETY: the exact gate reader is live for both descriptor operations.
    let flags = unsafe { fcntl(fd, F_GETFL) };
    if flags < 0 || unsafe { fcntl(fd, F_SETFL, flags | O_NONBLOCK) } != 0 {
        return Err(LauncherWaitError::Native(last_errno()));
    }
    Ok(())
}

fn probe_gate(gate: &ActiveBrokerGate) -> Result<(), LauncherWaitError> {
    let mut byte = 0_u8;
    loop {
        // SAFETY: byte is writable and the exact gate reader remains live.
        let result = unsafe { read(gate.reader.as_raw_fd(), &mut byte, 1) };
        if result == 0 {
            return Err(LauncherWaitError::ServiceGone);
        }
        if result == 1 {
            return Err(LauncherWaitError::InvalidGate);
        }
        let error = last_errno();
        if error == EINTR {
            continue;
        }
        if error == EAGAIN {
            return Ok(());
        }
        return Err(LauncherWaitError::Native(error));
    }
}

/// Waits for the plan writer to accept more bytes, or for the service to die.
///
/// The gate is polled alongside the writer so a service that disappears while
/// a launcher stops reading cannot leave delivery parked on a full pipe.
fn poll_plan_slice(gate: &ActiveBrokerGate, writer: c_int) -> Result<(), LauncherWaitError> {
    let mut descriptors = [
        PollFd {
            fd: gate.reader.as_raw_fd(),
            events: POLLIN,
            revents: 0,
        },
        PollFd {
            fd: writer,
            events: POLLOUT,
            revents: 0,
        },
    ];
    // SAFETY: descriptors contains two initialized writable pollfd values.
    let result = unsafe { poll(descriptors.as_mut_ptr(), 2, 1) };
    if result < 0 {
        let error = last_errno();
        if error != EINTR {
            return Err(LauncherWaitError::Native(error));
        }
    }
    Ok(())
}

fn poll_gate_slice(gate: &ActiveBrokerGate) -> Result<(), LauncherWaitError> {
    let mut descriptor = PollFd {
        fd: gate.reader.as_raw_fd(),
        events: POLLIN,
        revents: 0,
    };
    // SAFETY: descriptor is one initialized writable pollfd.
    let result = unsafe { poll(&raw mut descriptor, 1, 1) };
    if result < 0 {
        let error = last_errno();
        if error != EINTR {
            return Err(LauncherWaitError::Native(error));
        }
    }
    Ok(())
}

fn ensure_deadline(deadline: Instant) -> Result<(), LauncherWaitError> {
    if Instant::now() >= deadline {
        Err(LauncherWaitError::DeadlineExpired)
    } else {
        Ok(())
    }
}

fn traced_stop_signal(status: c_int) -> Option<c_int> {
    (status & 0xff == 0x7f).then_some((status >> 8) & 0xff)
}

fn exact_target_exit(status: c_int) -> Option<ExactTargetExit> {
    let terminal = status & 0x7f;
    if terminal == 0 {
        Some(ExactTargetExit::Exited(((status >> 8) & 0xff) as u8))
    } else if terminal != 0x7f {
        Some(ExactTargetExit::Signaled(terminal))
    } else {
        None
    }
}

impl Drop for ExactLauncher {
    fn drop(&mut self) {
        // Release every retained end before signalling. A launcher parked on
        // its own FD3 broker-death probe then wakes and self-terminates even if
        // the signal races, and its bootstrap namespace dies rather than
        // outliving the broker that vouched for it.
        drop(self.channels.take());
        if self.phase == ExactPhase::Reaped {
            return;
        }
        match self.phase {
            ExactPhase::AwaitingInitialStop => exact_signal(self.pid, SIGKILL),
            ExactPhase::UnprovenInitialStop => exact_unproven_stop_kill(self.pid),
            ExactPhase::AwaitingExecTrap | ExactPhase::RunningTarget => {
                exact_signal(self.pid, SIGSTOP)
            }
            ExactPhase::ObservedTracedStop | ExactPhase::ExecTrapHeld => {
                exact_ptrace_kill(self.pid)
            }
            ExactPhase::Reaped => return,
        }
        // Drains every status, including Darwin's duplicate terminal report, so
        // no exact child can outlive the authority that owned it.
        drain_exact_child(self.pid);
        self.phase = ExactPhase::Reaped;
    }
}

/// Consumes every remaining status for this exact child, until the kernel
/// reports the relation is gone.
///
/// Darwin hands a traced child's terminal status to its tracer *and* to its
/// parent, which are the same process here, so one exact wait observes the
/// death but does not consume the child. Measured on both paths: a natural
/// exit reports `0x0300` twice, and a `SIGKILL` reports `0x0009` twice after
/// its traced stop; only the following wait yields `ECHILD`. Stopping at the
/// first terminal status therefore leaves a zombie for the broker's whole
/// lifetime, which is precisely what this boundary exists to prevent.
///
/// `ECHILD` is the expected end here, unlike before a death is observed, where
/// it would mean exact authority was lost and must abort.
fn drain_exact_child(pid: c_int) {
    loop {
        let mut status = 0;
        // SAFETY: this owner is the sole waiter for the exact unreaped child,
        // whose death it has already observed.
        let result = unsafe { waitpid(pid, &raw mut status, WUNTRACED) };
        if result == pid {
            // A tracee can still report stops while dying; keep ending it.
            if traced_stop_signal(status).is_some() {
                exact_ptrace_kill(pid);
            }
            continue;
        }
        if result < 0 {
            let error = last_errno();
            if error == EINTR {
                continue;
            }
            if error == ECHILD {
                return;
            }
        }
        std::process::abort();
    }
}

fn exact_signal(pid: c_int, signal: c_int) {
    // SAFETY: exact unreaped direct-child authority pins this numeric PID.
    if unsafe { kill(pid, signal) } != 0 && last_errno() != ESRCH {
        std::process::abort();
    }
}

fn exact_ptrace_kill(pid: c_int) {
    // SAFETY: the exact direct child is a ptrace tracee held at a stop.
    if unsafe { ptrace(PT_KILL, pid, std::ptr::null_mut(), 0) } != 0 && last_errno() != ESRCH {
        std::process::abort();
    }
}

fn exact_unproven_stop_kill(pid: c_int) {
    // A SIGSTOP observation alone does not prove PT_TRACE_ME. Prefer the
    // tracee-only kill so a real tracee cannot remain held forever, then fall
    // back to the exact direct-child signal when the stop was untraced.
    // SAFETY: exact unreaped direct-child authority pins this numeric PID.
    if unsafe { ptrace(PT_KILL, pid, std::ptr::null_mut(), 0) } == 0 {
        return;
    }
    // Any ptrace error is ambiguous in this deliberately unproven phase;
    // ESRCH is not reap proof. Exact direct-child ownership makes the signal
    // fallback PID-safe, and an already-dead child simply returns ESRCH.
    exact_signal(pid, SIGKILL);
}

#[cfg(test)]
#[path = "supervisor_broker_launcher_test.rs"]
mod tests;
