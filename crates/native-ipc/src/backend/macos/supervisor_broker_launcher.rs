//! Exact broker-local authority for the trusted launcher's two ptrace stops.

use std::ffi::{CString, c_char, c_int, c_void};
use std::os::fd::AsRawFd;
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

pub(super) const INSTALLED_LAUNCHER_PATH: &str =
    "/Library/PrivilegedHelperTools/com.ro-ag.native-ipc.launcher";
pub(super) const INSTALLED_LAUNCHER_MODE: &str = "--supervisor-launcher";
pub(super) const INSTALLED_LAUNCHER_DEATH_ARGUMENT: &str = "--broker-death-fd=3";
pub(super) const INSTALLED_LAUNCHER_PLAN_ARGUMENT: &str = "--plan-fd=4";
const CANONICAL_PATH: &str = "PATH=/usr/bin:/bin";
const CANONICAL_LANG: &str = "LANG=C";
const CANONICAL_LOCALE: &str = "LC_ALL=C";

#[repr(C)]
struct PollFd {
    fd: c_int,
    events: i16,
    revents: i16,
}

unsafe extern "C" {
    fn kill(pid: c_int, signal: c_int) -> c_int;
    fn poll(descriptors: *mut PollFd, count: u32, timeout_ms: c_int) -> c_int;
    fn ptrace(request: c_int, pid: c_int, address: *mut c_void, data: c_int) -> c_int;
    fn read(fd: c_int, buffer: *mut u8, count: usize) -> isize;
    fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int;
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
}

impl InstalledLauncherImage {
    /// # Safety
    ///
    /// The installed supervisor must first verify the fixed path is the
    /// immutable root-owned signed launcher image for this service.
    pub(super) unsafe fn from_verified_installation() -> Result<Self, LauncherWaitError> {
        Ok(Self {
            path: fixed_launcher_cstring(INSTALLED_LAUNCHER_PATH)?,
            mode: fixed_launcher_cstring(INSTALLED_LAUNCHER_MODE)?,
            death_argument: fixed_launcher_cstring(INSTALLED_LAUNCHER_DEATH_ARGUMENT)?,
            plan_argument: fixed_launcher_cstring(INSTALLED_LAUNCHER_PLAN_ARGUMENT)?,
            environment_path: fixed_launcher_cstring(CANONICAL_PATH)?,
            environment_lang: fixed_launcher_cstring(CANONICAL_LANG)?,
            environment_locale: fixed_launcher_cstring(CANONICAL_LOCALE)?,
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

    fn fixed_identity(&self) -> FixedLauncherIdentity {
        FixedLauncherIdentity {
            real_uid: 0,
            effective_uid: 0,
            real_gid: 0,
            effective_gid: 0,
            executable: self.path.as_bytes().to_vec(),
        }
    }
}

fn fixed_launcher_cstring(value: &'static str) -> Result<CString, LauncherWaitError> {
    CString::new(value).map_err(|_| LauncherWaitError::IdentityTransition)
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
    _thread_confined: std::marker::PhantomData<Rc<()>>,
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
    /// # Safety
    ///
    /// `pid` must be the strictly positive result of this active broker's
    /// just-finished fixed-image launcher spawn. No other waiter may observe
    /// the child, and `active` must be the exact plan that authorized it.
    pub(super) unsafe fn from_positive_spawn(
        pid: c_int,
        active: ActiveBrokerProcess,
        expected_launcher: FixedLauncherIdentity,
    ) -> Result<Self, LauncherWaitError> {
        if pid <= 0 {
            return Err(LauncherWaitError::InvalidPid);
        }
        Ok(Self {
            inner: Some(ExactLauncher {
                pid,
                phase: ExactPhase::AwaitingInitialStop,
                active,
                expected_launcher,
                _thread_confined: std::marker::PhantomData,
            }),
        })
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
                    inner.phase = ExactPhase::Reaped;
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
        loop {
            let mut status = 0;
            // SAFETY: this value retains sole exact unreaped-child authority.
            let result = unsafe { waitpid(self.pid, &mut status, WUNTRACED) };
            if result == self.pid {
                if traced_stop_signal(status).is_some() {
                    exact_ptrace_kill(self.pid);
                    continue;
                }
                self.phase = ExactPhase::Reaped;
                return;
            }
            if result < 0 && last_errno() == EINTR {
                continue;
            }
            std::process::abort();
        }
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
