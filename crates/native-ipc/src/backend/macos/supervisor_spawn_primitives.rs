//! Shared Darwin `posix_spawn` preparation primitives.
//!
//! The broker, authentication worker, and launcher use one implementation for
//! canonical signal state and fixed descriptor actions. Native errors remain
//! raw `c_int` values here so each authority boundary maps them into its own
//! error type without duplicating the Darwin ABI.

use std::ffi::{CStr, c_char, c_int, c_void};

type PosixSpawnAttr = *mut c_void;
type PosixSpawnFileActions = *mut c_void;

const POSIX_SPAWN_SETSIGDEF: i16 = 0x0004;
const POSIX_SPAWN_SETSIGMASK: i16 = 0x0008;
const POSIX_SPAWN_CLOEXEC_DEFAULT: i16 = 0x4000;
const SIGKILL: c_int = 9;
const SIGSTOP: c_int = 17;
const ECHILD: c_int = 10;

unsafe extern "C" {
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
    fn sigdelset(set: *mut u32, signal: c_int) -> c_int;
    fn sigemptyset(set: *mut u32) -> c_int;
    fn sigfillset(set: *mut u32) -> c_int;
}

/// Initialized fixed descriptor actions for one spawn.
pub(super) struct SpawnFileActions(PosixSpawnFileActions);

impl SpawnFileActions {
    pub(super) fn new() -> Result<Self, c_int> {
        let mut actions = std::ptr::null_mut();
        // SAFETY: `actions` is writable opaque file-action storage.
        result(unsafe { posix_spawn_file_actions_init(&raw mut actions) })?;
        Ok(Self(actions))
    }

    pub(super) fn add_close(&mut self, fd: c_int) -> Result<(), c_int> {
        // SAFETY: this owns initialized actions and `fd` is validated by libc.
        result(unsafe { posix_spawn_file_actions_addclose(&raw mut self.0, fd) })
    }

    pub(super) fn add_dup2(&mut self, source: c_int, destination: c_int) -> Result<(), c_int> {
        // SAFETY: this owns initialized actions and libc validates both fds.
        result(unsafe { posix_spawn_file_actions_adddup2(&raw mut self.0, source, destination) })
    }

    pub(super) fn add_open(
        &mut self,
        fd: c_int,
        path: &CStr,
        flags: c_int,
        mode: u16,
    ) -> Result<(), c_int> {
        // SAFETY: this owns initialized actions and `path` is NUL-terminated.
        result(unsafe {
            posix_spawn_file_actions_addopen(&raw mut self.0, fd, path.as_ptr(), flags, mode)
        })
    }
}

impl Drop for SpawnFileActions {
    fn drop(&mut self) {
        // Once `posix_spawn` succeeds, the caller must arm exact child
        // authority before these values can drop. A destructor failure must
        // never abort and strand that child, so it cannot replace the primary
        // spawn/authority outcome. All fallible preparation calls above return
        // their native error explicitly.
        // SAFETY: this guard destroys its initialized storage exactly once.
        let _ = unsafe { posix_spawn_file_actions_destroy(&raw mut self.0) };
    }
}

/// Initialized canonical spawn attributes shared by every supervisor child.
pub(super) struct SpawnAttributes(PosixSpawnAttr);

impl SpawnAttributes {
    pub(super) fn new() -> Result<Self, c_int> {
        let mut attributes = std::ptr::null_mut();
        // SAFETY: `attributes` is writable opaque attribute storage.
        result(unsafe { posix_spawnattr_init(&raw mut attributes) })?;
        Ok(Self(attributes))
    }

    pub(super) fn configure_canonical_signals(&mut self) -> Result<(), c_int> {
        let mut defaults = 0_u32;
        let mut mask = 0_u32;
        // SAFETY: both values are writable Darwin `sigset_t` storage. SIGKILL
        // and SIGSTOP cannot be caught or reset and are excluded from defaults.
        if unsafe { sigfillset(&raw mut defaults) } != 0
            || unsafe { sigdelset(&raw mut defaults, SIGKILL) } != 0
            || unsafe { sigdelset(&raw mut defaults, SIGSTOP) } != 0
            || unsafe { sigemptyset(&raw mut mask) } != 0
        {
            return Err(last_errno());
        }
        // SAFETY: initialized attributes and both live signal sets.
        result(unsafe { posix_spawnattr_setsigdefault(&raw mut self.0, &raw const defaults) })?;
        // SAFETY: initialized attributes and the live empty mask.
        result(unsafe { posix_spawnattr_setsigmask(&raw mut self.0, &raw const mask) })?;
        // SAFETY: initialized attributes and public Darwin spawn flags.
        result(unsafe {
            posix_spawnattr_setflags(
                &raw mut self.0,
                POSIX_SPAWN_CLOEXEC_DEFAULT | POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETSIGMASK,
            )
        })
    }

    pub(super) fn set_special_port(&mut self, port: u32, which: c_int) -> Result<(), c_int> {
        // SAFETY: initialized attributes; Darwin validates the port action.
        result(unsafe { posix_spawnattr_setspecialport_np(&raw mut self.0, port, which) })
    }
}

impl Drop for SpawnAttributes {
    fn drop(&mut self) {
        // Same no-stranded-child rule as `SpawnFileActions::drop`.
        // SAFETY: this guard destroys its initialized storage exactly once.
        let _ = unsafe { posix_spawnattr_destroy(&raw mut self.0) };
    }
}

/// Performs one fully prepared fixed-image spawn and returns the raw child PID.
///
/// # Safety
///
/// Every pointer in `argv` and `environment` must remain live for the call,
/// both arrays must be NUL-terminated, and the caller must arm exact direct-
/// child authority immediately after a successful positive PID.
pub(super) unsafe fn spawn(
    path: &CStr,
    actions: &SpawnFileActions,
    attributes: &SpawnAttributes,
    argv: &[*mut c_char],
    environment: &[*mut c_char],
) -> Result<c_int, c_int> {
    let mut pid = 0;
    // SAFETY: the caller supplies the complete `posix_spawn` pointer contract.
    let code = unsafe {
        posix_spawn(
            &raw mut pid,
            path.as_ptr(),
            &raw const actions.0,
            &raw const attributes.0,
            argv.as_ptr(),
            environment.as_ptr(),
        )
    };
    result(code)?;
    Ok(pid)
}

fn result(code: c_int) -> Result<(), c_int> {
    if code == 0 { Ok(()) } else { Err(code) }
}

fn last_errno() -> c_int {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(ECHILD)
}

#[cfg(test)]
#[path = "supervisor_spawn_primitives_test.rs"]
mod tests;
