//! Fixed-image broker spawn and exact direct-child lifecycle authority.

use std::ffi::{CString, c_char, c_int, c_void};
use std::marker::PhantomData;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::rc::Rc;

use super::super::super::supervisor_watchdog::{
    AtomicallySpawnedBroker, ExactBroker, ExactBrokerAuthority, FreshSessionId, ReapedBroker,
    TerminationReason,
};
use super::super::ValidatedSpawn;
use super::{DedicatedChildWaitDomain, PendingSpawnReply, SessionAssignedSpawn};

type PosixSpawnAttr = *mut c_void;
type PosixSpawnFileActions = *mut c_void;

const INSTALLED_BROKER_PATH: &str = "/Library/PrivilegedHelperTools/com.ro-ag.native-ipc.broker";
const INSTALLED_BROKER_MODE: &str = "--supervisor-broker";
const INSTALLED_GATE_ARGUMENT: &str = "--gate-fd=3";
const CANONICAL_PATH: &str = "PATH=/usr/bin:/bin";
const CANONICAL_LANG: &str = "LANG=C";
const CANONICAL_LOCALE: &str = "LC_ALL=C";

const BROKER_GATE_FD: c_int = 3;
const STABLE_FD_MINIMUM: c_int = 10;
const START_BYTE: [u8; 1] = [1];

const POSIX_SPAWN_SETSIGDEF: i16 = 0x0004;
const POSIX_SPAWN_SETSIGMASK: i16 = 0x0008;
const POSIX_SPAWN_CLOEXEC_DEFAULT: i16 = 0x4000;

const F_GETFL: c_int = 3;
const F_SETFL: c_int = 4;
const F_SETFD: c_int = 2;
const F_DUPFD_CLOEXEC: c_int = 67;
const F_SETNOSIGPIPE: c_int = 73;
const FD_CLOEXEC: c_int = 1;
const O_NONBLOCK: c_int = 0x0000_0004;

const ECHILD: c_int = 10;
const EINTR: c_int = 4;
const ESRCH: c_int = 3;
const SIGKILL: c_int = 9;
const SIGSTOP: c_int = 17;
const WNOHANG: c_int = 1;

unsafe extern "C" {
    fn fcntl(fd: c_int, command: c_int, ...) -> c_int;
    fn kill(pid: c_int, signal: c_int) -> c_int;
    fn pipe(descriptors: *mut c_int) -> c_int;
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
    fn posix_spawn_file_actions_destroy(actions: *mut PosixSpawnFileActions) -> c_int;
    fn posix_spawn_file_actions_init(actions: *mut PosixSpawnFileActions) -> c_int;
    fn posix_spawnattr_destroy(attributes: *mut PosixSpawnAttr) -> c_int;
    fn posix_spawnattr_init(attributes: *mut PosixSpawnAttr) -> c_int;
    fn posix_spawnattr_setflags(attributes: *mut PosixSpawnAttr, flags: i16) -> c_int;
    fn posix_spawnattr_setsigdefault(attributes: *mut PosixSpawnAttr, signals: *const u32)
    -> c_int;
    fn posix_spawnattr_setsigmask(attributes: *mut PosixSpawnAttr, signals: *const u32) -> c_int;
    fn sigdelset(set: *mut u32, signal: c_int) -> c_int;
    fn sigemptyset(set: *mut u32) -> c_int;
    fn sigfillset(set: *mut u32) -> c_int;
    fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int;
    fn write(fd: c_int, buffer: *const u8, count: usize) -> isize;
}

/// Preparation or exact-spawn failure before child authority is minted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::backend::macos) enum BrokerSpawnError {
    InvalidFixedImage,
    Pipe(c_int),
    Descriptor(c_int),
    FileActions(c_int),
    Attributes(c_int),
    Spawn(c_int),
    Wait(c_int),
    Signal(c_int),
    Activation(c_int),
    InvalidTransition,
    InvalidWaitDomain,
}

/// Installation-only fixed broker image and its canonical process vectors.
///
/// This value contains no request-selected path, PID, signal, filesystem
/// operation, requirement, or descriptor. The installed runtime must verify
/// the root-owned replacement-resistant signed image before constructing it.
pub(in crate::backend::macos::supervisor) struct InstalledBrokerImage {
    path: CString,
    mode: CString,
    gate_argument: CString,
    environment_path: CString,
    environment_lang: CString,
    environment_locale: CString,
}

impl InstalledBrokerImage {
    /// # Safety
    ///
    /// The caller must be the installed supervisor after it has verified the
    /// fixed path as the immutable root-owned signed broker image. This source
    /// boundary does not itself claim installed, root, signing, or packaging
    /// evidence.
    pub(in crate::backend::macos::supervisor) unsafe fn from_verified_installation()
    -> Result<Self, BrokerSpawnError> {
        Ok(Self {
            path: fixed_cstring(INSTALLED_BROKER_PATH)?,
            mode: fixed_cstring(INSTALLED_BROKER_MODE)?,
            gate_argument: fixed_cstring(INSTALLED_GATE_ARGUMENT)?,
            environment_path: fixed_cstring(CANONICAL_PATH)?,
            environment_lang: fixed_cstring(CANONICAL_LANG)?,
            environment_locale: fixed_cstring(CANONICAL_LOCALE)?,
        })
    }

    fn argv(&self) -> [*mut c_char; 4] {
        [
            self.path.as_ptr().cast_mut(),
            self.mode.as_ptr().cast_mut(),
            self.gate_argument.as_ptr().cast_mut(),
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
}

fn fixed_cstring(value: &'static str) -> Result<CString, BrokerSpawnError> {
    CString::new(value).map_err(|_| BrokerSpawnError::InvalidFixedImage)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DirectChildState {
    Dormant,
    Active,
    TerminationSent,
    Reaped,
    AuthorityLost,
}

/// Exact sole-waiter authority for one fixed-image direct broker child.
///
/// The PID is usable only while the unreaped direct-child relation pins it.
/// No audit token, start time, PID version, task port, or reconstructible
/// numeric identity can replace that relation.
pub(in crate::backend::macos) struct DirectChildBrokerAuthority {
    pid: c_int,
    gate_writer: Option<OwnedFd>,
    state: DirectChildState,
    _wait_domain: PhantomData<Rc<()>>,
}

impl DirectChildBrokerAuthority {
    fn close_gate(&mut self) {
        drop(self.gate_writer.take());
    }

    fn observe_exact_reap(
        &mut self,
        options: c_int,
    ) -> Result<Option<ReapedBroker>, BrokerSpawnError> {
        if matches!(
            self.state,
            DirectChildState::Reaped | DirectChildState::AuthorityLost
        ) {
            std::process::abort();
        }
        let mut status = 0;
        // SAFETY: this authority is the service's sole waiter for exactly pid.
        let result = unsafe { waitpid(self.pid, &raw mut status, options) };
        if result == self.pid {
            self.state = DirectChildState::Reaped;
            // SAFETY: the successful exact wait above consumed this child.
            return Ok(Some(unsafe { ReapedBroker::from_exact_reap() }));
        }
        if result == 0 {
            return Ok(None);
        }
        let error = last_error(ECHILD);
        if error == ECHILD {
            self.state = DirectChildState::AuthorityLost;
            // Never attempt a numeric fallback once the kernel relation is lost.
            std::process::abort();
        }
        Err(BrokerSpawnError::Wait(error))
    }

    fn signal_exact_child(&mut self) -> Result<(), BrokerSpawnError> {
        if matches!(
            self.state,
            DirectChildState::Reaped | DirectChildState::AuthorityLost
        ) {
            std::process::abort();
        }
        if self.state == DirectChildState::TerminationSent {
            return Ok(());
        }
        // SAFETY: an unreaped direct child or zombie pins this numeric PID.
        if unsafe { kill(self.pid, SIGKILL) } == 0 {
            self.state = DirectChildState::TerminationSent;
            return Ok(());
        }
        let error = last_error(ESRCH);
        if error == ESRCH {
            // ESRCH is not reap proof; exact waitpid must retire the authority.
            self.state = DirectChildState::TerminationSent;
            Ok(())
        } else {
            Err(BrokerSpawnError::Signal(error))
        }
    }

    fn terminate_and_wait(&mut self) -> Result<ReapedBroker, BrokerSpawnError> {
        self.close_gate();
        loop {
            match self.observe_exact_reap(WNOHANG) {
                Ok(Some(proof)) => return Ok(proof),
                Ok(None) => break,
                Err(BrokerSpawnError::Wait(EINTR)) => continue,
                Err(error) => return Err(error),
            }
        }
        self.signal_exact_child()?;
        loop {
            match self.observe_exact_reap(0) {
                Ok(Some(proof)) => return Ok(proof),
                Ok(None) => std::process::abort(),
                Err(BrokerSpawnError::Wait(EINTR)) => continue,
                Err(error) => return Err(error),
            }
        }
    }

    fn emergency_terminate_and_wait(&mut self) -> ReapedBroker {
        match self.terminate_and_wait() {
            Ok(proof) => proof,
            Err(_) => std::process::abort(),
        }
    }
}

// SAFETY: this implementation uses only the exact unreaped direct-child
// relation. ECHILD aborts at discovery, ESRCH still requires exact waitpid,
// and every termination path closes the retained start/death gate first.
unsafe impl ExactBrokerAuthority for DirectChildBrokerAuthority {
    type Failure = BrokerSpawnError;

    fn activate_after_registration(&mut self) -> Result<(), Self::Failure> {
        if self.state != DirectChildState::Dormant {
            return Err(BrokerSpawnError::InvalidTransition);
        }
        let writer = self
            .gate_writer
            .as_ref()
            .unwrap_or_else(|| std::process::abort());
        // SAFETY: the fixed one-byte buffer and live nonblocking writer are valid.
        let result = unsafe { write(writer.as_raw_fd(), START_BYTE.as_ptr(), START_BYTE.len()) };
        if result == 1 {
            self.state = DirectChildState::Active;
            Ok(())
        } else if result < 0 {
            Err(BrokerSpawnError::Activation(last_error(ECHILD)))
        } else {
            Err(BrokerSpawnError::Activation(ECHILD))
        }
    }

    fn terminate_and_reap(
        &mut self,
        _reason: TerminationReason,
    ) -> Result<ReapedBroker, Self::Failure> {
        self.terminate_and_wait()
    }

    fn emergency_terminate_and_reap(&mut self, _reason: Option<TerminationReason>) -> ReapedBroker {
        self.emergency_terminate_and_wait()
    }
}

/// Sealed provenance bundle created only by the fixed-image spawn transition.
pub(in crate::backend::macos) struct FixedImageBrokerSpawn {
    session: FreshSessionId,
    launch: ValidatedSpawn,
    broker: ExactBroker<DirectChildBrokerAuthority>,
}

impl FixedImageBrokerSpawn {
    pub(in crate::backend::macos) fn into_parts(
        self,
    ) -> (
        FreshSessionId,
        ValidatedSpawn,
        ExactBroker<DirectChildBrokerAuthority>,
    ) {
        (self.session, self.launch, self.broker)
    }
}

impl PendingSpawnReply<SessionAssignedSpawn> {
    /// Atomically consumes the complete reply/session/validated-launch value
    /// into one fixed-image child and its exact authority. A spawn error keeps
    /// the original reply freshness and bound opaque session on the error path.
    /// The exclusive wait-domain borrow also serializes Darwin's non-atomic
    /// pipe creation/CLOEXEC preparation against every service-owned spawn.
    pub(in crate::backend::macos::supervisor) fn spawn_installed_broker(
        self,
        image: &InstalledBrokerImage,
        _wait_domain: &mut DedicatedChildWaitDomain,
    ) -> Result<
        PendingSpawnReply<AtomicallySpawnedBroker<ValidatedSpawn, DirectChildBrokerAuthority>>,
        Box<PendingSpawnReply<BrokerSpawnError>>,
    > {
        let Self {
            reply,
            freshness,
            bound_session,
            output,
        } = self;
        let broker = match spawn_fixed_image(image, _wait_domain) {
            Ok(broker) => broker,
            Err(output) => {
                return Err(Box::new(PendingSpawnReply {
                    reply,
                    freshness,
                    bound_session,
                    output,
                }));
            }
        };
        let spawned = FixedImageBrokerSpawn {
            session: output.session,
            launch: output.spawn,
            broker,
        };
        Ok(PendingSpawnReply {
            reply,
            freshness,
            bound_session,
            output: AtomicallySpawnedBroker::from_fixed_image_spawn(spawned),
        })
    }
}

fn spawn_fixed_image(
    image: &InstalledBrokerImage,
    wait_domain: &mut DedicatedChildWaitDomain,
) -> Result<ExactBroker<DirectChildBrokerAuthority>, BrokerSpawnError> {
    wait_domain
        .verify_single_threaded_spawn()
        .map_err(|_| BrokerSpawnError::InvalidWaitDomain)?;
    let (gate_reader, gate_writer) = create_gate_pipe()?;
    let mut actions = FileActionsGuard::new()?;
    actions.add_dup2(gate_reader.as_raw_fd(), BROKER_GATE_FD)?;
    actions.add_close(gate_reader.as_raw_fd())?;
    actions.add_close(gate_writer.as_raw_fd())?;

    let mut attributes = SpawnAttributesGuard::new()?;
    attributes.configure_canonical_signals()?;

    let argv = image.argv();
    let environment = image.environment();
    let mut pid = 0;
    // SAFETY: all CString storage, pointer arrays, file actions, attributes,
    // and pipe topology were completely prepared and remain live for the call.
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
        return Err(BrokerSpawnError::Spawn(result));
    }
    if pid <= 0 {
        std::process::abort();
    }

    // No allocation, callback, or fallible operation may occur between the
    // successful positive spawn and these two armed ownership transitions.
    let authority = DirectChildBrokerAuthority {
        pid,
        gate_writer: Some(gate_writer),
        state: DirectChildState::Dormant,
        _wait_domain: PhantomData,
    };
    // SAFETY: the just-created authority owns the positive direct child and
    // the dedicated service wait domain is the sole waiter.
    let broker = unsafe { ExactBroker::from_unreaped_direct_child(authority) };

    // The parent's reader and the prepared C objects may be destroyed only
    // after the exact child authority is armed.
    drop(gate_reader);
    Ok(broker)
}

fn create_gate_pipe() -> Result<(OwnedFd, OwnedFd), BrokerSpawnError> {
    let mut descriptors = [-1; 2];
    // SAFETY: descriptors points to two writable integers.
    if unsafe { pipe(descriptors.as_mut_ptr()) } != 0 {
        return Err(BrokerSpawnError::Pipe(last_error(ECHILD)));
    }
    // SAFETY: successful pipe returned two distinct owned descriptors.
    let reader = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
    // SAFETY: successful pipe returned two distinct owned descriptors.
    let writer = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
    set_cloexec(reader.as_raw_fd())?;
    set_cloexec(writer.as_raw_fd())?;
    let reader = duplicate_cloexec(reader.as_raw_fd())?;
    let writer = duplicate_cloexec(writer.as_raw_fd())?;
    set_nonblocking(writer.as_raw_fd())?;
    // Darwin's F_SETNOSIGPIPE keeps a dead broker from terminating the service.
    if unsafe { fcntl(writer.as_raw_fd(), F_SETNOSIGPIPE, 1) } != 0 {
        return Err(BrokerSpawnError::Descriptor(last_error(ECHILD)));
    }
    Ok((reader, writer))
}

fn duplicate_cloexec(fd: c_int) -> Result<OwnedFd, BrokerSpawnError> {
    // SAFETY: fd is live and F_DUPFD_CLOEXEC returns a new owned descriptor.
    let duplicate = unsafe { fcntl(fd, F_DUPFD_CLOEXEC, STABLE_FD_MINIMUM) };
    if duplicate < 0 {
        return Err(BrokerSpawnError::Descriptor(last_error(ECHILD)));
    }
    // SAFETY: the successful fcntl returned a fresh descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(duplicate) })
}

fn set_cloexec(fd: c_int) -> Result<(), BrokerSpawnError> {
    // SAFETY: fd is live and F_SETFD accepts the scalar FD_CLOEXEC flag.
    if unsafe { fcntl(fd, F_SETFD, FD_CLOEXEC) } == 0 {
        Ok(())
    } else {
        Err(BrokerSpawnError::Descriptor(last_error(ECHILD)))
    }
}

fn set_nonblocking(fd: c_int) -> Result<(), BrokerSpawnError> {
    // SAFETY: fd is live and F_GETFL has no variadic argument.
    let flags = unsafe { fcntl(fd, F_GETFL) };
    if flags < 0 {
        return Err(BrokerSpawnError::Descriptor(last_error(ECHILD)));
    }
    // SAFETY: fd is live and F_SETFL accepts the returned status flags.
    if unsafe { fcntl(fd, F_SETFL, flags | O_NONBLOCK) } == 0 {
        Ok(())
    } else {
        Err(BrokerSpawnError::Descriptor(last_error(ECHILD)))
    }
}

struct FileActionsGuard(PosixSpawnFileActions);

impl FileActionsGuard {
    fn new() -> Result<Self, BrokerSpawnError> {
        let mut actions = std::ptr::null_mut();
        // SAFETY: actions points to writable opaque storage.
        let result = unsafe { posix_spawn_file_actions_init(&raw mut actions) };
        if result == 0 {
            Ok(Self(actions))
        } else {
            Err(BrokerSpawnError::FileActions(result))
        }
    }

    fn add_dup2(&mut self, source: c_int, destination: c_int) -> Result<(), BrokerSpawnError> {
        // SAFETY: actions is initialized and both descriptors are nonnegative.
        spawn_file_action_result(unsafe {
            posix_spawn_file_actions_adddup2(&raw mut self.0, source, destination)
        })
    }

    fn add_close(&mut self, fd: c_int) -> Result<(), BrokerSpawnError> {
        // SAFETY: actions is initialized and fd is nonnegative.
        spawn_file_action_result(unsafe { posix_spawn_file_actions_addclose(&raw mut self.0, fd) })
    }
}

impl Drop for FileActionsGuard {
    fn drop(&mut self) {
        // SAFETY: initialized actions are destroyed exactly once.
        if unsafe { posix_spawn_file_actions_destroy(&raw mut self.0) } != 0 {
            std::process::abort();
        }
    }
}

fn spawn_file_action_result(result: c_int) -> Result<(), BrokerSpawnError> {
    if result == 0 {
        Ok(())
    } else {
        Err(BrokerSpawnError::FileActions(result))
    }
}

struct SpawnAttributesGuard(PosixSpawnAttr);

impl SpawnAttributesGuard {
    fn new() -> Result<Self, BrokerSpawnError> {
        let mut attributes = std::ptr::null_mut();
        // SAFETY: attributes points to writable opaque storage.
        let result = unsafe { posix_spawnattr_init(&raw mut attributes) };
        if result == 0 {
            Ok(Self(attributes))
        } else {
            Err(BrokerSpawnError::Attributes(result))
        }
    }

    fn configure_canonical_signals(&mut self) -> Result<(), BrokerSpawnError> {
        let mut defaults = 0_u32;
        let mut mask = 0_u32;
        // SAFETY: both values are Darwin sigset_t storage. SIGKILL and SIGSTOP
        // cannot be caught or reset, so they are removed from the default set.
        if unsafe { sigfillset(&raw mut defaults) } != 0
            || unsafe { sigdelset(&raw mut defaults, SIGKILL) } != 0
            || unsafe { sigdelset(&raw mut defaults, SIGSTOP) } != 0
            || unsafe { sigemptyset(&raw mut mask) } != 0
        {
            return Err(BrokerSpawnError::Attributes(last_error(ECHILD)));
        }
        // SAFETY: initialized attributes and signal sets remain live.
        let result = unsafe { posix_spawnattr_setsigdefault(&raw mut self.0, &raw const defaults) };
        if result != 0 {
            return Err(BrokerSpawnError::Attributes(result));
        }
        // SAFETY: initialized attributes and empty signal mask remain live.
        let result = unsafe { posix_spawnattr_setsigmask(&raw mut self.0, &raw const mask) };
        if result != 0 {
            return Err(BrokerSpawnError::Attributes(result));
        }
        // SAFETY: flags are public Darwin posix_spawn flags. No suspended-spawn
        // or containment-claiming session flag is used.
        let result = unsafe {
            posix_spawnattr_setflags(
                &raw mut self.0,
                POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK,
            )
        };
        if result == 0 {
            Ok(())
        } else {
            Err(BrokerSpawnError::Attributes(result))
        }
    }
}

impl Drop for SpawnAttributesGuard {
    fn drop(&mut self) {
        // SAFETY: initialized attributes are destroyed exactly once.
        if unsafe { posix_spawnattr_destroy(&raw mut self.0) } != 0 {
            std::process::abort();
        }
    }
}

fn last_error(fallback: c_int) -> c_int {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(fallback)
}

#[cfg(test)]
#[path = "supervisor_broker_spawn_test.rs"]
mod tests;
