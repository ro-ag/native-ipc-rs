//! Fixed-image clean-exec authentication-worker spawn boundary.

use std::ffi::{CStr, CString, c_char, c_int};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use super::{
    AuthAdapterError, AuthWorkerEndpoint, AuthWorkerPool, DedicatedChildWaitDomain,
    DirectChildAuthWorkerAuthority, DirectChildAuthWorkerError, DirectChildState, ExactAuthWorker,
    FreshAuthWorkerGeneration,
};
use crate::backend::macos::supervisor::deployer_helper_path;
use crate::backend::macos::supervisor::spawn_primitives::{
    SpawnAttributes, SpawnFileActions, spawn,
};

pub(super) const INSTALLED_AUTH_WORKER_MODE: &str = "--supervisor-auth-worker";
pub(super) const INSTALLED_AUTH_WORKER_REQUEST_ARGUMENT: &str = "--request-fd=3";
pub(super) const INSTALLED_AUTH_WORKER_RESULT_ARGUMENT: &str = "--result-fd=4";
const CANONICAL_PATH: &str = "PATH=/usr/bin:/bin";
const CANONICAL_LANG: &str = "LANG=C";
const CANONICAL_LOCALE: &str = "LC_ALL=C";

pub(super) const AUTH_WORKER_REQUEST_FD: c_int = 3;
pub(super) const AUTH_WORKER_RESULT_FD: c_int = 4;
const STABLE_FD_MINIMUM: c_int = 10;

const F_SETFL: c_int = 4;
const F_SETFD: c_int = 2;
const F_DUPFD_CLOEXEC: c_int = 67;
const F_SETNOSIGPIPE: c_int = 73;
const FD_CLOEXEC: c_int = 1;
const O_NONBLOCK: c_int = 0x0000_0004;
const O_RDONLY: c_int = 0;
const O_WRONLY: c_int = 1;
const ECHILD: c_int = 10;
const DEV_NULL: &CStr = c"/dev/null";

unsafe extern "C" {
    fn fcntl(fd: c_int, command: c_int, ...) -> c_int;
    fn pipe(descriptors: *mut c_int) -> c_int;
}

/// Failure before one exact clean-exec worker bundle is armed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::backend::macos::supervisor) enum AuthWorkerSpawnError {
    /// The verified installation vector could not be represented exactly.
    InvalidFixedImage,
    /// The permanent service wait-domain invariant no longer held.
    InvalidWaitDomain,
    /// A one-job pipe could not be created.
    Pipe(c_int),
    /// A private descriptor could not be configured or normalized.
    Descriptor(c_int),
    /// Fixed child descriptor actions could not be prepared.
    FileActions(c_int),
    /// Canonical child signal attributes could not be prepared.
    Attributes(c_int),
    /// The fixed-image spawn failed.
    Spawn(c_int),
}

/// Installation-only fixed authentication-worker image and process vectors.
///
/// The worker path, mode, descriptors, and environment are never selected by
/// a request. The installed runtime must verify the deployer-supplied signed
/// image before constructing this value.
pub(in crate::backend::macos::supervisor) struct InstalledAuthWorkerImage {
    spawn_path: CString,
    argument0: CString,
    mode: CString,
    request_argument: CString,
    result_argument: CString,
    environment_path: CString,
    environment_lang: CString,
    environment_locale: CString,
}

impl InstalledAuthWorkerImage {
    /// Constructs the fixed vector after external installation verification.
    ///
    /// # Safety
    ///
    /// `path` must be an absolute compile-time constant supplied by the
    /// deployer's helper artifact, not request data. The caller must have
    /// verified that exact path as a replacement-resistant signed clean-exec
    /// worker for this service.
    pub(in crate::backend::macos::supervisor) unsafe fn from_verified_installation(
        path: &CStr,
    ) -> Result<Self, AuthWorkerSpawnError> {
        let spawn_path =
            deployer_helper_path(path).ok_or(AuthWorkerSpawnError::InvalidFixedImage)?;
        Ok(Self {
            argument0: spawn_path.clone(),
            spawn_path,
            mode: fixed_cstring(INSTALLED_AUTH_WORKER_MODE)?,
            request_argument: fixed_cstring(INSTALLED_AUTH_WORKER_REQUEST_ARGUMENT)?,
            result_argument: fixed_cstring(INSTALLED_AUTH_WORKER_RESULT_ARGUMENT)?,
            environment_path: fixed_cstring(CANONICAL_PATH)?,
            environment_lang: fixed_cstring(CANONICAL_LANG)?,
            environment_locale: fixed_cstring(CANONICAL_LOCALE)?,
        })
    }

    fn argv(&self) -> [*mut c_char; 5] {
        [
            self.argument0.as_ptr().cast_mut(),
            self.mode.as_ptr().cast_mut(),
            self.request_argument.as_ptr().cast_mut(),
            self.result_argument.as_ptr().cast_mut(),
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

/// One freshly spawned worker inseparably carrying its generation, exact child
/// authority, and the matching private parent pipe ends.
#[must_use = "a spawned authentication worker must enter its exact pool slot"]
pub(in crate::backend::macos::supervisor) struct SpawnedAuthWorker {
    generation: FreshAuthWorkerGeneration,
    worker: ExactAuthWorker<DirectChildAuthWorkerAuthority>,
    endpoint: AuthWorkerEndpoint,
}

impl SpawnedAuthWorker {
    fn into_parts(
        self,
    ) -> (
        FreshAuthWorkerGeneration,
        ExactAuthWorker<DirectChildAuthWorkerAuthority>,
        AuthWorkerEndpoint,
    ) {
        (self.generation, self.worker, self.endpoint)
    }
}

impl AuthWorkerPool<DirectChildAuthWorkerAuthority> {
    /// Builds the fixed-capacity pool only from complete spawned bundles.
    pub(in crate::backend::macos::supervisor) fn from_spawned_workers(
        workers: Vec<SpawnedAuthWorker>,
    ) -> Result<Self, AuthAdapterError<DirectChildAuthWorkerError>> {
        Self::from_precreated_workers(
            workers
                .into_iter()
                .map(SpawnedAuthWorker::into_parts)
                .collect(),
        )
    }

    /// Installs one complete freshly spawned replacement only into an exactly
    /// retired slot. A live or reused generation is rejected by the pool.
    pub(super) fn install_spawned_replacement(
        &mut self,
        slot_index: u8,
        spawned: SpawnedAuthWorker,
    ) -> Result<super::AuthWorkerIdentity, AuthAdapterError<DirectChildAuthWorkerError>> {
        let (generation, worker, endpoint) = spawned.into_parts();
        self.install_replacement(slot_index, generation, worker, endpoint)
    }
}

/// Spawns one exact fixed-image clean-exec authentication worker.
///
/// No fallible work or callback occurs between a positive `posix_spawn`
/// result and the armed exact direct-child owner.
pub(in crate::backend::macos::supervisor) fn spawn_installed_auth_worker(
    image: &InstalledAuthWorkerImage,
    generation: FreshAuthWorkerGeneration,
    wait_domain: &mut DedicatedChildWaitDomain,
) -> Result<SpawnedAuthWorker, AuthWorkerSpawnError> {
    wait_domain
        .verify_single_threaded_spawn()
        .map_err(|_| AuthWorkerSpawnError::InvalidWaitDomain)?;
    let (request_reader, request_writer) = create_pipe_pair()?;
    let (result_reader, result_writer) = create_pipe_pair()?;
    set_nonblocking(request_writer.as_raw_fd())?;
    set_nonblocking(result_reader.as_raw_fd())?;
    set_nosigpipe(request_writer.as_raw_fd())?;

    let mut actions = SpawnFileActions::new().map_err(AuthWorkerSpawnError::FileActions)?;
    actions
        .add_open(0, DEV_NULL, O_RDONLY, 0)
        .map_err(AuthWorkerSpawnError::FileActions)?;
    actions
        .add_open(1, DEV_NULL, O_WRONLY, 0)
        .map_err(AuthWorkerSpawnError::FileActions)?;
    actions
        .add_open(2, DEV_NULL, O_WRONLY, 0)
        .map_err(AuthWorkerSpawnError::FileActions)?;
    actions
        .add_dup2(request_reader.as_raw_fd(), AUTH_WORKER_REQUEST_FD)
        .map_err(AuthWorkerSpawnError::FileActions)?;
    actions
        .add_dup2(result_writer.as_raw_fd(), AUTH_WORKER_RESULT_FD)
        .map_err(AuthWorkerSpawnError::FileActions)?;
    for descriptor in [
        request_reader.as_raw_fd(),
        request_writer.as_raw_fd(),
        result_reader.as_raw_fd(),
        result_writer.as_raw_fd(),
    ] {
        actions
            .add_close(descriptor)
            .map_err(AuthWorkerSpawnError::FileActions)?;
    }
    let mut attributes = SpawnAttributes::new().map_err(AuthWorkerSpawnError::Attributes)?;
    attributes
        .configure_canonical_signals()
        .map_err(AuthWorkerSpawnError::Attributes)?;

    wait_domain
        .verify_single_threaded_spawn()
        .map_err(|_| AuthWorkerSpawnError::InvalidWaitDomain)?;
    let argv = image.argv();
    let environment = image.environment();
    // SAFETY: all CString storage, pointer arrays, actions, and attributes are
    // complete and remain live for the fixed exact-path spawn.
    let pid = unsafe {
        spawn(
            image.spawn_path.as_c_str(),
            &actions,
            &attributes,
            &argv,
            &environment,
        )
    }
    .map_err(AuthWorkerSpawnError::Spawn)?;
    if pid <= 0 {
        std::process::abort();
    }

    // No allocation, callback, or fallible operation is permitted between the
    // positive child result and these exact ownership transitions.
    let authority = DirectChildAuthWorkerAuthority {
        pid,
        state: DirectChildState::Unreaped,
    };
    // SAFETY: the successful exact-path spawn returned this positive direct
    // child, and the dedicated service domain is its sole waiter.
    let worker = unsafe { ExactAuthWorker::from_unreaped_direct_child(authority) };
    // SAFETY: these are the sole parent ends paired to the exact child ends
    // installed above. Both are nonblocking, CLOEXEC, and request has NOSIGPIPE.
    let endpoint =
        unsafe { AuthWorkerEndpoint::from_private_parent_pipe_ends(request_writer, result_reader) };
    drop(request_reader);
    drop(result_writer);
    Ok(SpawnedAuthWorker {
        generation,
        worker,
        endpoint,
    })
}

fn fixed_cstring(value: &'static str) -> Result<CString, AuthWorkerSpawnError> {
    CString::new(value).map_err(|_| AuthWorkerSpawnError::InvalidFixedImage)
}

fn create_pipe_pair() -> Result<(OwnedFd, OwnedFd), AuthWorkerSpawnError> {
    let mut descriptors = [-1; 2];
    // SAFETY: descriptors points to writable storage for exactly two fds.
    if unsafe { pipe(descriptors.as_mut_ptr()) } != 0 {
        return Err(AuthWorkerSpawnError::Pipe(last_errno()));
    }
    // SAFETY: a successful pipe call returned two distinct owned descriptors.
    let reader = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
    // SAFETY: same successful pipe call returned the writer.
    let writer = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
    set_cloexec(reader.as_raw_fd())?;
    set_cloexec(writer.as_raw_fd())?;
    Ok((
        duplicate_cloexec(reader.as_raw_fd())?,
        duplicate_cloexec(writer.as_raw_fd())?,
    ))
}

fn duplicate_cloexec(fd: c_int) -> Result<OwnedFd, AuthWorkerSpawnError> {
    // SAFETY: fd is live; successful F_DUPFD_CLOEXEC returns a new owned fd.
    let duplicate = unsafe { fcntl(fd, F_DUPFD_CLOEXEC, STABLE_FD_MINIMUM) };
    if duplicate < 0 {
        Err(AuthWorkerSpawnError::Descriptor(last_errno()))
    } else {
        // SAFETY: the successful duplication transferred one new owned fd.
        Ok(unsafe { OwnedFd::from_raw_fd(duplicate) })
    }
}

fn set_cloexec(fd: c_int) -> Result<(), AuthWorkerSpawnError> {
    // SAFETY: fd is live and accepts the close-on-exec descriptor flag.
    if unsafe { fcntl(fd, F_SETFD, FD_CLOEXEC) } == 0 {
        Ok(())
    } else {
        Err(AuthWorkerSpawnError::Descriptor(last_errno()))
    }
}

fn set_nonblocking(fd: c_int) -> Result<(), AuthWorkerSpawnError> {
    // SAFETY: these fresh private pipe ends accept the nonblocking status flag.
    if unsafe { fcntl(fd, F_SETFL, O_NONBLOCK) } == 0 {
        Ok(())
    } else {
        Err(AuthWorkerSpawnError::Descriptor(last_errno()))
    }
}

fn set_nosigpipe(fd: c_int) -> Result<(), AuthWorkerSpawnError> {
    // SAFETY: Darwin pipe descriptors accept F_SETNOSIGPIPE.
    if unsafe { fcntl(fd, F_SETNOSIGPIPE, 1) } == 0 {
        Ok(())
    } else {
        Err(AuthWorkerSpawnError::Descriptor(last_errno()))
    }
}

fn last_errno() -> c_int {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(ECHILD)
}

#[cfg(test)]
#[path = "supervisor_auth_worker_spawn_test.rs"]
mod tests;
