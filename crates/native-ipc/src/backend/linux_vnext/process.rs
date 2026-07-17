//! Trusted Linux receiver pre-exec policy.

use core::cell::Cell;
use core::marker::PhantomData;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, Command};
#[cfg(test)]
use std::sync::atomic::AtomicU32;
use std::sync::atomic::{AtomicBool, AtomicI32, AtomicU8, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::Thread;
use std::time::Duration;

use crate::session::AbsoluteDeadline;

const PR_SET_MDWE: libc::c_int = 65;
const PR_MDWE_REFUSE_EXEC_GAIN: libc::c_ulong = 1;
const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const ELF_HEADER_LEN: usize = 64;
#[cfg(target_arch = "x86_64")]
const NATIVE_ELF_MACHINE: u16 = 62;
#[cfg(target_arch = "aarch64")]
const NATIVE_ELF_MACHINE: u16 = 183;

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SpawnPolicyError {
    InvalidExecutable,
    WrongExecutable,
    ExitedBeforeVerification,
    Native(i32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ExecutableKey {
    device: u64,
    inode: u64,
}

pub(super) struct HeldExecutable {
    fd: OwnedFd,
    key: ExecutableKey,
    not_sync: PhantomData<Cell<()>>,
}

/// Race-resistant exact-image evidence that still owns both the original
/// executable artifact and the spawned-but-unreaped child's pidfd.
struct VerifiedExecutable {
    executable: HeldExecutable,
    pidfd: OwnedFd,
    child_pid: u32,
}

impl HeldExecutable {
    pub(super) fn open(path: &Path) -> Result<Self, SpawnPolicyError> {
        if !path.is_absolute() {
            return Err(SpawnPolicyError::InvalidExecutable);
        }
        let path = std::ffi::CString::new(path.as_os_str().as_encoded_bytes())
            .map_err(|_| SpawnPolicyError::InvalidExecutable)?;
        let how = OpenHow {
            flags: (libc::O_PATH | libc::O_CLOEXEC) as u64,
            mode: 0,
            resolve: RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
        };
        // SAFETY: path and complete open_how storage remain live for openat2.
        let raw = unsafe {
            libc::syscall(
                libc::SYS_openat2,
                libc::AT_FDCWD,
                path.as_ptr(),
                &how,
                core::mem::size_of::<OpenHow>(),
            ) as RawFd
        };
        if raw < 0 {
            return Err(native_error(io::Error::last_os_error()));
        }
        // SAFETY: successful open returned a new owned descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        let (key, mode) = file_key(fd.as_raw_fd())?;
        if mode & libc::S_IFMT != libc::S_IFREG || mode & 0o111 == 0 {
            return Err(SpawnPolicyError::InvalidExecutable);
        }
        validate_native_elf(fd.as_raw_fd())?;
        Ok(Self {
            fd,
            key,
            not_sync: PhantomData,
        })
    }

    fn verify_child(self, child: &mut Child) -> Result<VerifiedExecutable, SpawnPolicyError> {
        if child.try_wait().map_err(native_error)?.is_some() {
            return Err(SpawnPolicyError::ExitedBeforeVerification);
        }
        let child_pid = child.id();
        let pidfd = open_pidfd(child_pid)?;
        let proc_path = std::ffi::CString::new(format!("/proc/{child_pid}/exe"))
            .map_err(|_| SpawnPolicyError::InvalidExecutable)?;
        // SAFETY: path is NUL-terminated and flags have no variadic mode.
        let raw = unsafe { libc::open(proc_path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if raw < 0 {
            return Err(native_error(io::Error::last_os_error()));
        }
        // SAFETY: successful open returned a new owned descriptor.
        let actual = unsafe { OwnedFd::from_raw_fd(raw) };
        let (actual_key, _) = file_key(actual.as_raw_fd())?;
        if actual_key != self.key {
            return Err(SpawnPolicyError::WrongExecutable);
        }
        Ok(VerifiedExecutable {
            executable: self,
            pidfd,
            child_pid,
        })
    }

    fn command(&self) -> Command {
        Command::new(format!("/proc/self/fd/{}", self.fd.as_raw_fd()))
    }

    pub(super) fn raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }

    pub(super) fn matches_process_image(&self, pid: libc::pid_t) -> bool {
        if pid <= 0 {
            return false;
        }
        let Ok(path) = std::ffi::CString::new(format!("/proc/{pid}/exe")) else {
            return false;
        };
        // SAFETY: path is NUL-terminated and these flags have no mode argument.
        let raw = unsafe { libc::open(path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if raw < 0 {
            return false;
        }
        // SAFETY: successful open returned one uniquely owned descriptor.
        let actual = unsafe { OwnedFd::from_raw_fd(raw) };
        matches!(file_key(actual.as_raw_fd()), Ok((key, _)) if key == self.key)
    }
}

impl VerifiedExecutable {
    fn child_pid(&self) -> u32 {
        self.child_pid
    }

    fn key(&self) -> ExecutableKey {
        self.executable.key
    }

    fn pidfd(&self) -> RawFd {
        self.pidfd.as_raw_fd()
    }
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

fn file_key(fd: RawFd) -> Result<(ExecutableKey, libc::mode_t), SpawnPolicyError> {
    // SAFETY: output is valid for this live descriptor.
    let mut status: libc::stat = unsafe { core::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut status) } != 0 {
        return Err(native_error(io::Error::last_os_error()));
    }
    Ok((
        ExecutableKey {
            device: status.st_dev,
            inode: status.st_ino,
        },
        status.st_mode,
    ))
}

fn validate_native_elf(fd: RawFd) -> Result<(), SpawnPolicyError> {
    let proc_path = std::ffi::CString::new(format!("/proc/self/fd/{fd}"))
        .map_err(|_| SpawnPolicyError::InvalidExecutable)?;
    // SAFETY: this internal proc path names the already-held exact inode.
    let readable = unsafe { libc::open(proc_path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if readable < 0 {
        return Err(native_error(io::Error::last_os_error()));
    }
    // SAFETY: successful open returned a new owned descriptor.
    let readable = unsafe { OwnedFd::from_raw_fd(readable) };
    let mut header = [0_u8; ELF_HEADER_LEN];
    // SAFETY: output points to bounded writable storage and offset zero is valid.
    let read = unsafe {
        libc::pread(
            readable.as_raw_fd(),
            header.as_mut_ptr().cast(),
            header.len(),
            0,
        )
    };
    let object_type = u16::from_le_bytes([header[16], header[17]]);
    let machine = u16::from_le_bytes([header[18], header[19]]);
    let version = u32::from_le_bytes([header[20], header[21], header[22], header[23]]);
    let header_size = u16::from_le_bytes([header[52], header[53]]);
    if read != ELF_HEADER_LEN as isize
        || header[..4] != *b"\x7fELF"
        || header[4] != 2
        || header[5] != 1
        || header[6] != 1
        || !matches!(object_type, 2 | 3)
        || machine != NATIVE_ELF_MACHINE
        || version != 1
        || usize::from(header_size) != ELF_HEADER_LEN
    {
        return Err(SpawnPolicyError::InvalidExecutable);
    }
    Ok(())
}

fn open_pidfd(pid: u32) -> Result<OwnedFd, SpawnPolicyError> {
    // SAFETY: scalar syscall arguments request a new CLOEXEC pidfd.
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) as RawFd };
    if raw < 0 {
        return Err(native_error(io::Error::last_os_error()));
    }
    // SAFETY: successful pidfd_open returned a new owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

const LIFECYCLE_IDLE: u8 = 0;
const LIFECYCLE_WAIT: u8 = 1;
const LIFECYCLE_TERMINATE: u8 = 2;
const REAPER_POLL_INTERVAL: Duration = Duration::from_millis(10);

/// Exact direct-child exit observed and consumed through the atomic pidfd.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ExactChildExit {
    Exited(i32),
    Signaled {
        signal: i32,
        dumped_core: bool,
    },
    /// Process-global child disposition or another waiter consumed the status.
    AlreadyReaped,
}

/// Bounded facts about the fresh Unix process group owned with the child.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DescendantCleanup {
    /// The child never reached the trusted post-`setsid` checkpoint.
    NotEstablished,
    /// A fresh session/group exists, but bounded group termination could not
    /// be performed under a kernel-witnessed direct-child identity pin.
    FreshGroupUnverified,
    /// SIGKILL was delivered to the kernel-verified fresh process group while
    /// the unreaped direct child pinned its identity, and the pin was
    /// re-observed after the signal.
    FreshGroupTerminated,
}

/// Bounded explicit cleanup result. An incomplete direct-child result leaves
/// the dedicated worker holding the same atomic pidfd until kernel cleanup
/// becomes possible.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ExactChildCleanup {
    direct_child: Option<ExactChildExit>,
    descendants: DescendantCleanup,
    last_native_error: Option<i32>,
}

impl ExactChildCleanup {
    pub(super) const fn direct_child_complete(self) -> bool {
        self.direct_child.is_some()
    }

    pub(super) const fn last_native_error(self) -> Option<i32> {
        self.last_native_error
    }

    pub(super) const fn direct_child(self) -> Option<ExactChildExit> {
        self.direct_child
    }

    pub(super) const fn descendants(self) -> DescendantCleanup {
        self.descendants
    }

    #[cfg(test)]
    pub(super) const fn direct_child_succeeded(self) -> bool {
        matches!(self.direct_child, Some(ExactChildExit::Exited(0)))
    }
}

struct ReapTask {
    pidfd: Arc<OwnedFd>,
}

struct LifecycleShared {
    task: Mutex<Option<ReapTask>>,
    task_ready: Condvar,
    request: AtomicU8,
    finished: AtomicBool,
    last_native_error: AtomicI32,
    completion: Mutex<Option<ExactChildExit>>,
    completion_ready: Condvar,
    cancel_unarmed: AtomicBool,
    terminal_incomplete: AtomicBool,
    fresh_session: AtomicBool,
    descendant_cleanup: Mutex<DescendantCleanup>,
    #[cfg(test)]
    signal_interrupts: AtomicU32,
    #[cfg(test)]
    signal_failure: AtomicI32,
    #[cfg(test)]
    poll_failure: AtomicI32,
    #[cfg(test)]
    reap_failure: AtomicI32,
}

/// Worker prepared before acquiring a child, so every successful clone can
/// transfer its pidfd into an already-durable cleanup owner without spawning
/// or waiting from `Drop`.
pub(super) struct PreparedExactChildLifecycle {
    shared: Arc<LifecycleShared>,
    worker: Thread,
    armed: bool,
}

/// Private exact-child owner. This is deliberately not a receipt and cannot
/// construct authenticated channel, session, or memory authority.
pub(super) struct ExactChildLifecycle {
    pidfd: Arc<OwnedFd>,
    pid: libc::pid_t,
    shared: Arc<LifecycleShared>,
    worker: Thread,
    not_sync: PhantomData<Cell<()>>,
}

impl PreparedExactChildLifecycle {
    pub(super) fn new() -> Result<Self, SpawnPolicyError> {
        Self::new_with_worker(|worker_shared| {
            let worker = std::thread::Builder::new()
                .name("native-ipc-child-reaper".into())
                .spawn(move || exact_child_reaper(worker_shared))?;
            let worker_thread = worker.thread().clone();
            drop(worker);
            Ok(worker_thread)
        })
    }

    fn new_with_worker(
        spawn_worker: impl FnOnce(Arc<LifecycleShared>) -> io::Result<Thread>,
    ) -> Result<Self, SpawnPolicyError> {
        let shared = Arc::new(LifecycleShared {
            task: Mutex::new(None),
            task_ready: Condvar::new(),
            request: AtomicU8::new(LIFECYCLE_IDLE),
            finished: AtomicBool::new(false),
            last_native_error: AtomicI32::new(0),
            completion: Mutex::new(None),
            completion_ready: Condvar::new(),
            cancel_unarmed: AtomicBool::new(false),
            terminal_incomplete: AtomicBool::new(false),
            fresh_session: AtomicBool::new(false),
            descendant_cleanup: Mutex::new(DescendantCleanup::NotEstablished),
            #[cfg(test)]
            signal_interrupts: AtomicU32::new(0),
            #[cfg(test)]
            signal_failure: AtomicI32::new(0),
            #[cfg(test)]
            poll_failure: AtomicI32::new(0),
            #[cfg(test)]
            reap_failure: AtomicI32::new(0),
        });
        let worker = spawn_worker(Arc::clone(&shared)).map_err(native_error)?;
        Ok(Self {
            shared,
            worker,
            armed: false,
        })
    }

    pub(super) fn arm(
        mut self,
        pid: libc::pid_t,
        pidfd: OwnedFd,
    ) -> Result<ExactChildLifecycle, SpawnPolicyError> {
        let pidfd = Arc::new(pidfd);
        *lock_unpoisoned(&self.shared.task) = Some(ReapTask {
            pidfd: Arc::clone(&pidfd),
        });
        self.armed = true;
        self.shared.task_ready.notify_one();
        self.worker.unpark();
        if pid <= 0 {
            self.shared
                .request
                .store(LIFECYCLE_TERMINATE, Ordering::Release);
            self.worker.unpark();
            return Err(SpawnPolicyError::Native(libc::EINVAL));
        }
        Ok(ExactChildLifecycle {
            pidfd,
            pid,
            shared: Arc::clone(&self.shared),
            worker: self.worker.clone(),
            not_sync: PhantomData,
        })
    }
}

impl Drop for PreparedExactChildLifecycle {
    fn drop(&mut self) {
        if !self.armed {
            // Hold the predicate mutex while cancelling and notifying so the
            // worker cannot miss the transition between its check and wait.
            let task = lock_unpoisoned(&self.shared.task);
            self.shared.cancel_unarmed.store(true, Ordering::Release);
            self.shared.task_ready.notify_one();
            drop(task);
            self.worker.unpark();
        }
    }
}

impl ExactChildLifecycle {
    pub(super) fn pid(&self) -> libc::pid_t {
        self.pid
    }

    pub(super) fn pidfd(&self) -> RawFd {
        self.pidfd.as_raw_fd()
    }

    /// Records the trusted child-side `setsid` checkpoint. This is containment
    /// state only and cannot mint image, channel, session, or memory authority.
    pub(super) fn establish_fresh_session(&self) {
        self.shared.fresh_session.store(true, Ordering::Release);
        *lock_unpoisoned(&self.shared.descendant_cleanup) = DescendantCleanup::FreshGroupUnverified;
    }

    pub(super) fn wait_and_reap(&self, deadline: AbsoluteDeadline) -> ExactChildCleanup {
        self.request(LIFECYCLE_WAIT);
        self.wait_for_completion(deadline)
    }

    pub(super) fn terminate_and_reap(&self, deadline: AbsoluteDeadline) -> ExactChildCleanup {
        self.request(LIFECYCLE_TERMINATE);
        self.wait_for_completion(deadline)
    }

    #[cfg(test)]
    pub(super) fn fail_next_signal_for_test(&self, code: i32) {
        self.shared.signal_failure.store(code, Ordering::Release);
    }

    fn request(&self, request: u8) {
        self.shared.request.fetch_max(request, Ordering::AcqRel);
        self.worker.unpark();
    }

    fn wait_for_completion(&self, deadline: AbsoluteDeadline) -> ExactChildCleanup {
        let mut completion = lock_unpoisoned(&self.shared.completion);
        loop {
            if let Some(exit) = *completion {
                return ExactChildCleanup {
                    direct_child: Some(exit),
                    descendants: *lock_unpoisoned(&self.shared.descendant_cleanup),
                    last_native_error: None,
                };
            }
            if self.shared.terminal_incomplete.load(Ordering::Acquire) {
                let code = self.shared.last_native_error.load(Ordering::Acquire);
                return ExactChildCleanup {
                    direct_child: None,
                    descendants: *lock_unpoisoned(&self.shared.descendant_cleanup),
                    last_native_error: (code != 0).then_some(code),
                };
            }
            let remaining = deadline.remaining();
            if remaining.is_zero() {
                let code = self.shared.last_native_error.load(Ordering::Acquire);
                return ExactChildCleanup {
                    direct_child: None,
                    descendants: *lock_unpoisoned(&self.shared.descendant_cleanup),
                    last_native_error: (code != 0).then_some(code),
                };
            }
            completion = match self
                .shared
                .completion_ready
                .wait_timeout(completion, remaining)
            {
                Ok((guard, _)) => guard,
                Err(poisoned) => poisoned.into_inner().0,
            };
        }
    }
}

impl Drop for ExactChildLifecycle {
    fn drop(&mut self) {
        if !self.shared.finished.load(Ordering::Acquire) {
            self.request(LIFECYCLE_TERMINATE);
        }
    }
}

fn exact_child_reaper(shared: Arc<LifecycleShared>) {
    let task = {
        let mut task = lock_unpoisoned(&shared.task);
        loop {
            if let Some(task) = task.take() {
                break task;
            }
            if shared.cancel_unarmed.load(Ordering::Acquire) {
                return;
            }
            task = match shared.task_ready.wait(task) {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
        }
    };

    let mut signal_attempted = false;
    let mut descendant_cleanup_attempted = false;
    let mut group_termination_attempted = false;
    loop {
        let request = shared.request.load(Ordering::Acquire);
        if request == LIFECYCLE_IDLE {
            std::thread::park();
            continue;
        }
        if request == LIFECYCLE_TERMINATE && !descendant_cleanup_attempted {
            let cleanup = descendant_cleanup_limit(&shared);
            *lock_unpoisoned(&shared.descendant_cleanup) = cleanup;
            descendant_cleanup_attempted = true;
        }
        if request == LIFECYCLE_TERMINATE && !signal_attempted {
            match signal_exact_child_with_faults(task.pidfd.as_raw_fd(), libc::SIGKILL, &shared) {
                Ok(()) | Err(libc::ESRCH) => signal_attempted = true,
                Err(libc::EINTR) => {
                    std::thread::park_timeout(REAPER_POLL_INTERVAL);
                    continue;
                }
                Err(code) => retain_incomplete_cleanup(&shared, code),
            }
        }

        let mut event = libc::pollfd {
            fd: task.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        #[cfg(test)]
        let injected_poll_failure = shared.poll_failure.swap(0, Ordering::AcqRel);
        #[cfg(not(test))]
        let injected_poll_failure = 0;
        let polled = if injected_poll_failure != 0 {
            -1
        } else {
            // SAFETY: the sole pollfd and its pidfd remain live for this bounded poll.
            unsafe {
                libc::poll(
                    &mut event,
                    1,
                    REAPER_POLL_INTERVAL.as_millis() as libc::c_int,
                )
            }
        };
        if polled < 0 {
            let code = if injected_poll_failure != 0 {
                injected_poll_failure
            } else {
                io::Error::last_os_error().raw_os_error().unwrap_or(-1)
            };
            if code == libc::EINTR {
                std::thread::park_timeout(REAPER_POLL_INTERVAL);
                continue;
            }
            retain_incomplete_cleanup(&shared, code);
        }
        if polled == 0
            || event.revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) == 0
        {
            continue;
        }
        if !descendant_cleanup_attempted {
            let cleanup = descendant_cleanup_limit(&shared);
            *lock_unpoisoned(&shared.descendant_cleanup) = cleanup;
            descendant_cleanup_attempted = true;
        }
        if !group_termination_attempted {
            group_termination_attempted = true;
            terminate_descendant_group_before_reap(&shared, task.pidfd.as_raw_fd());
        }
        #[cfg(test)]
        let injected_reap_failure = shared.reap_failure.swap(0, Ordering::AcqRel);
        #[cfg(not(test))]
        let injected_reap_failure = 0;
        let reaped = if injected_reap_failure != 0 {
            Err(injected_reap_failure)
        } else {
            reap_exact_child(task.pidfd.as_raw_fd())
        };
        match reaped {
            Ok(Some(exit)) => {
                // Release the worker's exact pidfd before publishing completion.
                // The waiting owner may return as soon as it observes the
                // notification, so retaining this task until thread return would
                // make successful cleanup transiently leave one descriptor open.
                drop(task);
                *lock_unpoisoned(&shared.completion) = Some(exit);
                shared.finished.store(true, Ordering::Release);
                shared.completion_ready.notify_all();
                return;
            }
            Ok(None) => std::thread::park_timeout(REAPER_POLL_INTERVAL),
            Err(code) => retain_incomplete_cleanup(&shared, code),
        }
    }
}

fn descendant_cleanup_limit(shared: &LifecycleShared) -> DescendantCleanup {
    if shared.fresh_session.load(Ordering::Acquire) {
        DescendantCleanup::FreshGroupUnverified
    } else {
        DescendantCleanup::NotEstablished
    }
}

/// Bounded ordinary-descendant termination under the direct child's identity
/// pin, immediately before this sole waiter consumes the exit status.
///
/// The child was cloned with no exit signal, so no default process-global
/// wait and no ignored-SIGCHLD auto-reap can consume it: the unreaped zombie
/// durably pins its PID and therefore the numeric identity of the fresh
/// process group it leads. Every step is kernel-verified under that pin, and
/// the successful outcome is recorded only after the pin is observed again,
/// which proves it held across the group signal because the pin can end only
/// through this worker's own reap.
fn terminate_descendant_group_before_reap(shared: &LifecycleShared, pidfd: RawFd) {
    if !shared.fresh_session.load(Ordering::Acquire) {
        return;
    }
    let Some(pid) = zombie_pinned_child(pidfd) else {
        return;
    };
    // SAFETY: scalar queries about the pinned PID with no memory arguments.
    let fresh_group_leader = unsafe { libc::getpgid(pid) == pid && libc::getsid(pid) == pid };
    if !fresh_group_leader {
        return;
    }
    // SAFETY: the pinned zombie leader proves this numeric group is still the
    // fresh session created for the exact child; SIGKILL to it cannot reach
    // any process outside that owned session.
    if unsafe { libc::killpg(pid, libc::SIGKILL) } != 0 {
        return;
    }
    if zombie_pinned_child(pidfd) == Some(pid) {
        *lock_unpoisoned(&shared.descendant_cleanup) = DescendantCleanup::FreshGroupTerminated;
    }
}

/// Exact child PID while its exit status remains queued for this pidfd owner.
fn zombie_pinned_child(pidfd: RawFd) -> Option<libc::pid_t> {
    loop {
        // SAFETY: zero is valid initialization for waitid output.
        let mut information: libc::siginfo_t = unsafe { core::mem::zeroed() };
        // SAFETY: P_PIDFD binds the query to this exact owned child; WNOWAIT
        // leaves the status queued so the PID stays pinned; __WALL is
        // mandatory because the child carries no exit signal.
        let result = unsafe {
            libc::waitid(
                libc::P_PIDFD,
                pidfd as libc::id_t,
                &mut information,
                libc::WEXITED | libc::WNOHANG | libc::WNOWAIT | libc::__WALL,
            )
        };
        if result != 0 {
            if io::Error::last_os_error().raw_os_error() == Some(libc::EINTR) {
                continue;
            }
            return None;
        }
        // SAFETY: waitid initialized the exit fields it reports.
        let pid = unsafe { information.si_pid() };
        if pid <= 0 {
            return None;
        }
        return Some(pid);
    }
}

fn retain_incomplete_cleanup(shared: &LifecycleShared, code: i32) -> ! {
    let completion = lock_unpoisoned(&shared.completion);
    shared.last_native_error.store(code, Ordering::Release);
    shared.terminal_incomplete.store(true, Ordering::Release);
    shared.completion_ready.notify_all();
    drop(completion);
    // The worker deliberately keeps its ReapTask and exact pidfd on its stack.
    // A non-retryable failure cannot be retried safely and must not spin.
    loop {
        std::thread::park();
    }
}

fn signal_exact_child_with_faults(
    pidfd: RawFd,
    signal: libc::c_int,
    shared: &LifecycleShared,
) -> Result<(), i32> {
    #[cfg(not(test))]
    let _ = shared;
    #[cfg(test)]
    {
        let failure = shared.signal_failure.swap(0, Ordering::AcqRel);
        if failure != 0 {
            return Err(failure);
        }
    }
    #[cfg(test)]
    if shared
        .signal_interrupts
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
            remaining.checked_sub(1)
        })
        .is_ok()
    {
        return Err(libc::EINTR);
    }
    signal_exact_child(pidfd, signal)
}

fn signal_exact_child(pidfd: RawFd, signal: libc::c_int) -> Result<(), i32> {
    // SAFETY: pidfd is held live by the lifecycle and scalar signal arguments
    // target only the exact kernel process object represented by that pidfd.
    let result = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd,
            signal,
            core::ptr::null::<libc::siginfo_t>(),
            0,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error().raw_os_error().unwrap_or(-1))
    }
}

fn reap_exact_child(pidfd: RawFd) -> Result<Option<ExactChildExit>, i32> {
    // SAFETY: zero is valid initialization for waitid output.
    let mut information: libc::siginfo_t = unsafe { core::mem::zeroed() };
    // SAFETY: P_PIDFD binds the wait to this exact owned child; WNOHANG prevents
    // an unexpected kernel wait even after pidfd readiness was observed, and
    // __WALL is mandatory because the child carries no exit signal.
    let result = unsafe {
        libc::waitid(
            libc::P_PIDFD,
            pidfd as libc::id_t,
            &mut information,
            libc::WEXITED | libc::WNOHANG | libc::__WALL,
        )
    };
    if result != 0 {
        let code = io::Error::last_os_error().raw_os_error().unwrap_or(-1);
        return if code == libc::ECHILD {
            Ok(Some(ExactChildExit::AlreadyReaped))
        } else if code == libc::EINTR {
            Ok(None)
        } else {
            Err(code)
        };
    }
    let status = unsafe { information.si_status() };
    match information.si_code {
        libc::CLD_EXITED => Ok(Some(ExactChildExit::Exited(status))),
        libc::CLD_KILLED => Ok(Some(ExactChildExit::Signaled {
            signal: status,
            dumped_core: false,
        })),
        libc::CLD_DUMPED => Ok(Some(ExactChildExit::Signaled {
            signal: status,
            dumped_core: true,
        })),
        _ => Ok(None),
    }
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
#[path = "process_test.rs"]
mod tests;
