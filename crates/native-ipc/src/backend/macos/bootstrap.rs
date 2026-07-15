//! Private Mach bootstrap channel with audit-token process authentication.

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::fmt;
use std::mem::{size_of, size_of_val, zeroed};
#[cfg(test)]
use std::sync::atomic::AtomicU64;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use super::{KERN_SUCCESS, MachPort, current_task, deallocate_port};
use crate::backend::{PeerState, SessionTransportError};
use crate::protocol::{
    CONTROL_FRAME_LEN, ManifestEntry, NativeRegionSpec, PeerAccess, TransferManifest,
    TransferProvenance, mint_channel_id,
};
use crate::session::{
    AbsoluteDeadline, ChildCleanupFacts, ChildExitStatus, DescendantCleanupStatus,
};
type MachMsgReturn = c_int;
type PosixSpawnAttr = *mut c_void;
type PosixSpawnFileActions = *mut c_void;

const MACH_PORT_NULL: MachPort = 0;
const MACH_PORT_RIGHT_RECEIVE: c_int = 1;
const MACH_PORT_RIGHT_SEND: c_int = 0;
const MACH_PORT_TYPE_SEND: u32 = 0x0001_0000;
const MACH_PORT_TYPE_DEAD_NAME: u32 = 0x0010_0000;
const MACH_MSG_TYPE_COPY_SEND: u8 = 19;
const MACH_MSG_TYPE_MAKE_SEND: u8 = 20;
const MACH_MSG_TYPE_PORT_SEND: u8 = 17;
const MACH_MSG_PORT_DESCRIPTOR: u8 = 0;
const MACH_MSGH_BITS_COMPLEX: u32 = 0x8000_0000;
const MACH_SEND_MSG: u32 = 0x0000_0001;
const MACH_RCV_MSG: u32 = 0x0000_0002;
const MACH_SEND_TIMEOUT: u32 = 0x0000_0010;
const MACH_RCV_TIMEOUT: u32 = 0x0000_0100;
const MACH_RCV_TRAILER_AUDIT: u32 = 3 << 24;
const MACH_RCV_TOO_LARGE: c_int = 0x1000_4004;
const MACH_SEND_TIMED_OUT: c_int = 0x1000_0004;
const MACH_RCV_TIMED_OUT: c_int = 0x1000_4003;
const MACH_SEND_INTERRUPTED: c_int = 0x1000_0007;
const MACH_RCV_INTERRUPTED: c_int = 0x1000_4005;
const TASK_BOOTSTRAP_PORT: c_int = 4;
const MESSAGE_ID: c_int = 0x4e49_5043;
const VNEXT_MESSAGE_ID: c_int = 0x4e49_5044;
const MESSAGE_MAGIC: [u8; 8] = *b"NIPCMACH";
const VNEXT_MESSAGE_MAGIC: [u8; 8] = *b"NIPCVNXT";
const CAPABILITY_MAGIC: [u8; 8] = *b"NIPCCAP1";
const READY_MAGIC: [u8; 8] = *b"NIPCRDY1";
const COMMIT_MAGIC: [u8; 8] = *b"NIPCCMT1";
const ENV_NONCE: &str = "NATIVE_IPC_MACH_NONCE";
const ENV_PARENT_PID: &str = "NATIVE_IPC_PARENT_PID";
const TIMEOUT_MS: u32 = 10_000;
pub(super) const MAX_VNEXT_RECORD_BYTES: usize = 64 * 1024;
const MAX_VNEXT_CAPABILITIES: usize = 16;
const WNOHANG: c_int = 1;
const WUNTRACED: c_int = 2;
const ESRCH: c_int = 3;
const SIGSTOP: c_int = 17;
const SIGCONT: c_int = 19;
const PT_TRACE_ME: c_int = 0;
const PT_CONTINUE: c_int = 7;
const PT_KILL: c_int = 8;
const RLIMIT_NPROC: c_int = 7;
const TASK_AUDIT_TOKEN: c_int = 15;
const TASK_AUDIT_TOKEN_COUNT: u32 = 8;
const POSIX_SPAWN_START_SUSPENDED: i16 = 0x0080;
const POSIX_SPAWN_SETSID: i16 = 0x0400;
const POSIX_SPAWN_CLOEXEC_DEFAULT: i16 = 0x4000;
const PROC_PIDPATHINFO_MAXSIZE: usize = 4096;

unsafe extern "C" {
    fn mach_port_allocate(task: MachPort, right: c_int, name: *mut MachPort) -> c_int;
    fn mach_port_insert_right(
        task: MachPort,
        name: MachPort,
        poly: MachPort,
        poly_poly: c_int,
    ) -> c_int;
    fn mach_port_mod_refs(task: MachPort, name: MachPort, right: c_int, delta: c_int) -> c_int;
    fn mach_port_type(task: MachPort, name: MachPort, port_type: *mut u32) -> c_int;
    fn mach_msg(
        message: *mut MachMsgHeader,
        option: u32,
        send_size: u32,
        receive_limit: u32,
        receive_name: MachPort,
        timeout: u32,
        notify: MachPort,
    ) -> MachMsgReturn;
    fn mach_msg_destroy(message: *mut MachMsgHeader);
    fn proc_signal_with_audittoken(token: *mut AuditToken, signal: c_int) -> c_int;
    fn getppid() -> Pid;
    fn ptrace(request: c_int, pid: Pid, address: *mut c_void, data: c_int) -> c_int;
    fn raise(signal: c_int) -> c_int;
    fn setrlimit(resource: c_int, limit: *const ResourceLimit) -> c_int;
    fn task_name_for_pid(task: MachPort, pid: Pid, name: *mut MachPort) -> c_int;
    fn task_info(task: MachPort, flavor: c_int, information: *mut c_int, count: *mut u32) -> c_int;
    fn task_get_special_port(task: MachPort, which: c_int, port: *mut MachPort) -> c_int;
    fn task_set_special_port(task: MachPort, which: c_int, port: MachPort) -> c_int;
    fn posix_spawnattr_init(attributes: *mut PosixSpawnAttr) -> c_int;
    fn posix_spawnattr_destroy(attributes: *mut PosixSpawnAttr) -> c_int;
    fn posix_spawnattr_setspecialport_np(
        attributes: *mut PosixSpawnAttr,
        port: MachPort,
        which: c_int,
    ) -> c_int;
    fn posix_spawnattr_setflags(attributes: *mut PosixSpawnAttr, flags: i16) -> c_int;
    fn posix_spawn(
        pid: *mut Pid,
        path: *const c_char,
        file_actions: *const PosixSpawnFileActions,
        attributes: *const PosixSpawnAttr,
        argv: *const *mut c_char,
        envp: *const *mut c_char,
    ) -> c_int;
    fn kill(pid: Pid, signal: c_int) -> c_int;
    fn waitpid(pid: Pid, status: *mut c_int, options: c_int) -> Pid;
}

#[link(name = "proc")]
unsafe extern "C" {
    fn proc_pidpath(pid: c_int, buffer: *mut c_void, buffer_size: u32) -> c_int;
}

#[link(name = "bsm")]
unsafe extern "C" {
    fn audit_token_to_pid(token: AuditToken) -> Pid;
}

type Pid = c_int;

#[repr(C)]
#[derive(Clone, Copy)]
struct MachMsgHeader {
    bits: u32,
    size: u32,
    remote_port: MachPort,
    local_port: MachPort,
    voucher_port: MachPort,
    id: c_int,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct MachMsgBody {
    descriptor_count: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct MachMsgPortDescriptor {
    name: MachPort,
    pad1: u32,
    pad2: u16,
    disposition: u8,
    descriptor_type: u8,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AuditToken {
    values: [u32; 8],
}

#[repr(C)]
struct ResourceLimit {
    current: u64,
    maximum: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct AuditTrailer {
    trailer_type: u32,
    trailer_size: u32,
    sequence: u32,
    sender_security: [u32; 2],
    audit: AuditToken,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct VnextEnvelope {
    magic: [u8; 8],
    nonce: [u8; 32],
    kind: u32,
    payload_len: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VnextRecordKind {
    ZeroRights = 1,
    Capabilities = 2,
}

pub(super) struct VnextCapabilityRecord {
    pub(super) bytes: Vec<u8>,
    pub(super) rights: Vec<SendRight>,
}

#[repr(C)]
struct PortMessage {
    header: MachMsgHeader,
    body: MachMsgBody,
    descriptor: MachMsgPortDescriptor,
    magic: [u8; 8],
    nonce: [u8; 32],
    transcript: [u8; CONTROL_FRAME_LEN],
}

#[repr(C)]
struct ReceiveBuffer {
    message: PortMessage,
    trailer: AuditTrailer,
}

/// Mach bootstrap or authenticated port-transfer failure.
#[derive(Debug)]
pub enum BootstrapError {
    /// A bounded Mach operation failed.
    Mach {
        /// Bounded Mach operation.
        operation: &'static str,
        /// Kernel return code.
        code: c_int,
    },
    /// `posix_spawn` setup or launch failed.
    Spawn(c_int),
    /// Received message shape, nonce, or descriptor was noncanonical.
    InvalidMessage,
    /// Kernel audit trailer identified another process.
    WrongPeer {
        /// Held spawned or parent PID.
        expected: u32,
        /// PID from the kernel audit trailer.
        actual: u32,
    },
    /// Spawn environment was missing or malformed.
    InvalidEnvironment,
    /// The caller-derived absolute deadline expired.
    DeadlineExpired,
    /// A send completed at the deadline boundary with ambiguous peer state.
    Ambiguous,
    /// Exact child authority could not be retained, so no numeric signal was sent.
    ExactAuthorityUnavailable {
        /// Native capture error when one was available.
        native_error: Option<c_int>,
    },
}

impl fmt::Display for BootstrapError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Mach bootstrap failed: {self:?}")
    }
}
impl std::error::Error for BootstrapError {}

/// Received send right owned by this process.
pub struct SendRight(MachPort);
impl SendRight {
    /// Raw port name for native mapping APIs inside this crate.
    pub(super) const fn name(&self) -> MachPort {
        self.0
    }

    #[cfg(test)]
    pub(super) fn copy_existing(name: MachPort) -> Result<Self, BootstrapError> {
        if name == MACH_PORT_NULL {
            return Err(BootstrapError::InvalidMessage);
        }
        // SAFETY: the caller supplies a live send-right name in the current
        // task; incrementing its user-reference count creates one owned copy.
        mach("mach_port_mod_refs(send,+1)", unsafe {
            mach_port_mod_refs(current_task(), name, MACH_PORT_RIGHT_SEND, 1)
        })?;
        Ok(Self(name))
    }
}
impl Drop for SendRight {
    fn drop(&mut self) {
        deallocate_port(current_task(), self.0);
        #[cfg(test)]
        super::observe_vnext_drop_for_test("send-right");
    }
}

#[cfg(test)]
pub(super) struct TestSendRight {
    _receive: ReceiveRight,
    send: SendRight,
}

#[cfg(test)]
impl TestSendRight {
    pub(super) fn allocate() -> Result<Self, BootstrapError> {
        let receive = ReceiveRight::allocate()?;
        receive.make_send()?;
        let send = SendRight(receive.0);
        Ok(Self {
            _receive: receive,
            send,
        })
    }

    pub(super) const fn name(&self) -> MachPort {
        self.send.0
    }
}

struct ReceiveRight(MachPort);
impl ReceiveRight {
    fn allocate() -> Result<Self, BootstrapError> {
        let mut name = MACH_PORT_NULL;
        // SAFETY: output pointer is valid for the current task.
        let result =
            unsafe { mach_port_allocate(current_task(), MACH_PORT_RIGHT_RECEIVE, &mut name) };
        mach("mach_port_allocate", result)?;
        if name == MACH_PORT_NULL {
            return Err(BootstrapError::InvalidMessage);
        }
        Ok(Self(name))
    }
    fn make_send(&self) -> Result<(), BootstrapError> {
        // SAFETY: this object owns the receive right from which MAKE_SEND is valid.
        mach("mach_port_insert_right", unsafe {
            mach_port_insert_right(
                current_task(),
                self.0,
                self.0,
                MACH_MSG_TYPE_MAKE_SEND.into(),
            )
        })
    }
}
impl Drop for ReceiveRight {
    fn drop(&mut self) {
        // SAFETY: this object uniquely owns one receive-right reference.
        let _ = unsafe { mach_port_mod_refs(current_task(), self.0, MACH_PORT_RIGHT_RECEIVE, -1) };
    }
}

/// Low-privilege kernel identity for one exact Mach task.
///
/// Unlike a task-control port this right cannot suspend, mutate, or terminate
/// the task. It lets the suspended-spawn path obtain an execution-scoped audit
/// token before the child runs. Native testing shows that an ordinary `exec`
/// invalidates this right, so it is not a cross-exec lifecycle capability.
struct TaskNameRight(MachPort);

/// Kernel audit identity sampled while an exact direct child is ptrace-stopped.
pub(super) struct TaskAuditIdentity {
    audit: AuditToken,
    executable: Vec<u8>,
}

impl TaskAuditIdentity {
    /// Requires the same exact PID, the expected post-drop credentials, and a
    /// changed PID version. Darwin changes the audit PID version on `exec`.
    pub(super) fn proves_exec_transition_from(
        &self,
        before: &Self,
        pid: c_int,
        expected_euid: u32,
        expected_egid: u32,
        expected_executable: &[u8],
    ) -> bool {
        let Ok(expected_pid) = u32::try_from(pid) else {
            return false;
        };
        before.audit.values[5] == expected_pid
            && self.audit.values[5] == expected_pid
            && before.audit.values[7] != self.audit.values[7]
            && self.audit.values[1] == expected_euid
            && self.audit.values[2] == expected_egid
            && self.audit.values[3] == expected_euid
            && self.audit.values[4] == expected_egid
            && self.executable == expected_executable
    }
}

/// Captures only an execution-scoped task-name identity, never task control.
/// The caller must independently pin `pid` against reuse while this runs.
pub(super) fn capture_task_audit_identity(pid: c_int) -> Result<TaskAuditIdentity, BootstrapError> {
    let (_right, audit) = TaskNameRight::capture(pid)?;
    let mut path = [0_u8; PROC_PIDPATHINFO_MAXSIZE];
    // SAFETY: exact stopped-child authority pins pid while proc_pidpath writes
    // at most the supplied live buffer. libproc returns a NUL-terminated path.
    let result = unsafe {
        proc_pidpath(
            pid,
            path.as_mut_ptr().cast(),
            u32::try_from(path.len()).unwrap_or(u32::MAX),
        )
    };
    if result <= 0 {
        return Err(BootstrapError::InvalidMessage);
    }
    let executable = CStr::from_bytes_until_nul(&path)
        .map_err(|_| BootstrapError::InvalidMessage)?
        .to_bytes()
        .to_vec();
    if executable.is_empty() {
        return Err(BootstrapError::InvalidMessage);
    }
    Ok(TaskAuditIdentity { audit, executable })
}

impl TaskNameRight {
    fn capture_suspended(pid: Pid) -> Result<(Self, AuditToken), BootstrapError> {
        Self::capture(pid)
    }

    fn capture(pid: Pid) -> Result<(Self, AuditToken), BootstrapError> {
        let mut name = MACH_PORT_NULL;
        // SAFETY: the output pointer is valid. Callers that require a proof
        // against PID reuse must independently establish that the process
        // cannot exit during this numeric lookup; the production spawn path
        // does so by keeping the fresh child suspended.
        mach("task_name_for_pid", unsafe {
            task_name_for_pid(current_task(), pid, &mut name)
        })?;
        if name == MACH_PORT_NULL {
            return Err(BootstrapError::InvalidMessage);
        }
        let right = Self(name);
        let audit = right.audit_token()?;
        // SAFETY: `audit` came from TASK_AUDIT_TOKEN for this exact task.
        let actual = unsafe { audit_token_to_pid(audit) };
        if actual != pid {
            return Err(BootstrapError::WrongPeer {
                expected: pid as u32,
                actual: actual as u32,
            });
        }
        Ok((right, audit))
    }

    fn audit_token(&self) -> Result<AuditToken, BootstrapError> {
        let mut audit = AuditToken { values: [0; 8] };
        let mut count = TASK_AUDIT_TOKEN_COUNT;
        // SAFETY: TASK_AUDIT_TOKEN writes exactly `count` natural words into
        // the aligned audit-token storage, and this object owns a live task-
        // name send right accepted by `task_info` for this flavor.
        mach("task_info(TASK_AUDIT_TOKEN)", unsafe {
            task_info(
                self.0,
                TASK_AUDIT_TOKEN,
                audit.values.as_mut_ptr().cast(),
                &mut count,
            )
        })?;
        if count != TASK_AUDIT_TOKEN_COUNT {
            return Err(BootstrapError::InvalidMessage);
        }
        Ok(audit)
    }
}

impl Drop for TaskNameRight {
    fn drop(&mut self) {
        deallocate_port(current_task(), self.0);
    }
}

/// Parent-owned exact helper and authenticated bidirectional Mach channel.
pub struct SpawnedHelper {
    pid: Pid,
    nonce: [u8; 32],
    receive: Option<ReceiveRight>,
    lifecycle: Option<MacChildLifecycle>,
}

impl SpawnedHelper {
    /// Spawns an absolute helper path with a private bootstrap send right.
    pub fn spawn(path: &CString, arguments: &[CString]) -> Result<Self, BootstrapError> {
        let environment = std::env::vars_os()
            .filter(|(key, _)| key != ENV_NONCE && key != ENV_PARENT_PID)
            .filter_map(|(key, value)| {
                CString::new(format!(
                    "{}={}",
                    key.to_string_lossy(),
                    value.to_string_lossy()
                ))
                .ok()
            })
            .collect();
        Self::spawn_inner(path, arguments, environment, false, false)
    }

    pub(super) fn spawn_explicit(
        path: &CString,
        arguments: &[CString],
        environment: &[CString],
    ) -> Result<Self, BootstrapError> {
        Self::spawn_inner(path, arguments, environment.to_vec(), true, true)
    }

    fn spawn_inner(
        path: &CString,
        arguments: &[CString],
        mut environment: Vec<CString>,
        fresh_session: bool,
        arguments_include_arg0: bool,
    ) -> Result<Self, BootstrapError> {
        let nonce = random_nonce()?;
        let receive = ReceiveRight::allocate()?;
        receive.make_send()?;
        let mut attributes: PosixSpawnAttr = std::ptr::null_mut();
        // SAFETY: attribute output pointer is valid.
        spawn_result(unsafe { posix_spawnattr_init(&mut attributes) })?;
        struct AttributeGuard(PosixSpawnAttr);
        impl Drop for AttributeGuard {
            fn drop(&mut self) {
                // SAFETY: initialized posix_spawn attributes are destroyed once.
                let _ = unsafe { posix_spawnattr_destroy(&mut self.0) };
            }
        }
        let mut guard = AttributeGuard(attributes);
        // SAFETY: attributes are initialized and receive port has a live send right.
        spawn_result(unsafe {
            posix_spawnattr_setspecialport_np(&mut guard.0, receive.0, TASK_BOOTSTRAP_PORT)
        })?;
        if fresh_session {
            // SAFETY: attributes are initialized and the flag is defined by
            // the macOS SDK to create a fresh session for the spawned child.
            spawn_result(unsafe {
                posix_spawnattr_setflags(
                    &mut guard.0,
                    POSIX_SPAWN_START_SUSPENDED | POSIX_SPAWN_SETSID | POSIX_SPAWN_CLOEXEC_DEFAULT,
                )
            })?;
        }

        let mut argv_storage =
            Vec::with_capacity(arguments.len() + usize::from(!arguments_include_arg0));
        if !arguments_include_arg0 {
            argv_storage.push(path.clone());
        }
        argv_storage.extend(arguments.iter().cloned());
        let mut argv: Vec<*mut c_char> = argv_storage
            .iter_mut()
            .map(|argument| argument.as_ptr().cast_mut())
            .collect();
        argv.push(std::ptr::null_mut());

        let nonce_value = hex(&nonce);
        let parent_pid = std::process::id().to_string();
        environment.push(CString::new(format!("{ENV_NONCE}={nonce_value}")).expect("hex env"));
        environment.push(CString::new(format!("{ENV_PARENT_PID}={parent_pid}")).expect("pid env"));
        let mut envp: Vec<*mut c_char> = environment
            .iter_mut()
            .map(|entry| entry.as_ptr().cast_mut())
            .collect();
        envp.push(std::ptr::null_mut());
        let lifecycle = fresh_session
            .then(MacChildLifecycle::prepare)
            .transpose()
            .map_err(bootstrap_lifecycle_error)?;
        let mut pid = 0;
        // SAFETY: path/argv/envp and initialized attributes remain live for the call.
        let result = unsafe {
            posix_spawn(
                &mut pid,
                path.as_ptr(),
                std::ptr::null(),
                &guard.0,
                argv.as_ptr(),
                envp.as_ptr(),
            )
        };
        // Drop the parent's extra send reference on every outcome before the
        // launch result is inspected; the receive right remains owned.
        deallocate_port(current_task(), receive.0);
        spawn_result(result)?;
        if let Some(owner) = &lifecycle {
            let (task_name, mut audit_token) = match TaskNameRight::capture_suspended(pid) {
                Ok(identity) => identity,
                Err(error) => {
                    // A hostile process-global SIGCHLD policy or broad waiter
                    // can consume an externally killed child and release its
                    // PID before this branch runs. Once exact task authority
                    // acquisition fails, never fall back to a numeric signal.
                    // Perform no PID-addressed action at all: after auto-reap,
                    // even waitpid could consume a different concurrently
                    // spawned direct child that reused the numeric PID. An
                    // unobservable suspended child therefore remains an
                    // explicit incomplete-cleanup failure of this private
                    // prototype rather than a risk to another child.
                    owner.request_termination();
                    return Err(BootstrapError::ExactAuthorityUnavailable {
                        native_error: bootstrap_native_error(&error),
                    });
                }
            };
            owner.install_task_identity(task_name, audit_token);
            owner.activate(pid);
            // Resume the exact captured execution rather than addressing the
            // reusable PID with a numeric SIGCONT.
            if let Err(error) = signal_with_audit_token(&mut audit_token, SIGCONT) {
                owner.request_termination();
                return Err(BootstrapError::Spawn(error));
            }
        }
        Ok(Self {
            pid,
            nonce,
            receive: Some(receive),
            lifecycle,
        })
    }

    /// Receives the helper's control port and authenticates its audit PID.
    pub fn authenticate(self) -> Result<ParentChannel, BootstrapError> {
        self.authenticate_inner(None)
    }

    pub(super) fn authenticate_vnext_until(
        mut self,
        deadline: AbsoluteDeadline,
    ) -> Result<(ParentChannel, MacChildLifecycle), (BootstrapError, ChildCleanupFacts)> {
        let Some(receive) = self.receive.take() else {
            let cleanup = self.cleanup_vnext_until(deadline);
            return Err((BootstrapError::InvalidMessage, cleanup));
        };
        let Some(lifecycle) = self.lifecycle.take() else {
            drop(receive);
            let cleanup = self.cleanup_vnext_until(deadline);
            return Err((BootstrapError::InvalidMessage, cleanup));
        };
        let peer_pid = self.pid as u32;
        self.pid = 0;
        let (child_send, child_audit) = match receive_port_with_audit(
            &receive,
            &self.nonce,
            peer_pid,
            &[0; CONTROL_FRAME_LEN],
            Some(deadline),
        ) {
            Ok(received) => received,
            Err(error) => {
                drop(receive);
                return Err((error, lifecycle.terminate_and_reap_facts(deadline)));
            }
        };
        if let Err(error) = lifecycle.install_authenticated_audit_token(child_audit) {
            drop(child_send);
            drop(receive);
            return Err((
                bootstrap_lifecycle_error(error),
                lifecycle.terminate_and_reap_facts(deadline),
            ));
        }
        let channel = ParentChannel {
            peer_send: child_send,
            _receive: receive,
            nonce: self.nonce,
            peer_pid,
            peer_audit: Some(child_audit),
            reaped: true,
            pending_entries: Vec::new(),
            channel_id: mint_channel_id(),
            next_transfer_id: 1,
            poisoned: false,
        };
        Ok((channel, lifecycle))
    }

    pub(super) fn cleanup_vnext_until(mut self, deadline: AbsoluteDeadline) -> ChildCleanupFacts {
        self.receive.take();
        self.pid = 0;
        self.lifecycle.take().map_or_else(
            || ChildCleanupFacts::new(None, DescendantCleanupStatus::FreshGroupUnverified, None),
            |lifecycle| lifecycle.terminate_and_reap_facts(deadline),
        )
    }

    fn authenticate_inner(
        mut self,
        deadline: Option<AbsoluteDeadline>,
    ) -> Result<ParentChannel, BootstrapError> {
        let receive = self.receive.take().ok_or(BootstrapError::InvalidMessage)?;
        let child_send = match receive_port(
            &receive,
            &self.nonce,
            self.pid as u32,
            &[0; CONTROL_FRAME_LEN],
            deadline,
        ) {
            Ok(right) => right,
            Err(error) => {
                terminate_and_reap(self.pid);
                self.pid = 0;
                return Err(error);
            }
        };
        let channel = ParentChannel {
            peer_send: child_send,
            _receive: receive,
            nonce: self.nonce,
            peer_pid: self.pid as u32,
            peer_audit: None,
            reaped: false,
            pending_entries: Vec::new(),
            channel_id: mint_channel_id(),
            next_transfer_id: 1,
            poisoned: false,
        };
        self.pid = 0;
        Ok(channel)
    }

    /// Spawned process ID held unreaped by the caller's lifecycle policy.
    pub const fn pid(&self) -> u32 {
        self.pid as u32
    }
}

impl Drop for SpawnedHelper {
    fn drop(&mut self) {
        if self.lifecycle.is_none() && self.pid > 0 {
            terminate_and_reap(self.pid);
        }
    }
}

impl Drop for ParentChannel {
    fn drop(&mut self) {
        if !self.reaped {
            terminate_and_reap(self.peer_pid as Pid);
        }
    }
}

/// Parent side of an authenticated bidirectional port-transfer channel.
pub struct ParentChannel {
    peer_send: SendRight,
    _receive: ReceiveRight,
    nonce: [u8; 32],
    peer_pid: u32,
    peer_audit: Option<AuditToken>,
    reaped: bool,
    pending_entries: Vec<ManifestEntry>,
    channel_id: u64,
    next_transfer_id: u64,
    poisoned: bool,
}

struct MacChildLifecycleState {
    reaped: bool,
    last_error: Option<i32>,
    exit_status: Option<i32>,
    task_name: Option<TaskNameRight>,
    audit_token: Option<AuditToken>,
}

struct MacChildLifecycleShared {
    pid: AtomicI32,
    terminate: AtomicBool,
    traced: AtomicBool,
    reaper_gate: Mutex<()>,
    state: Mutex<MacChildLifecycleState>,
    changed: Condvar,
    #[cfg(test)]
    reap_delay_ms: AtomicU64,
    #[cfg(test)]
    wait_interrupts: AtomicU64,
}

/// Durable exact-child owner whose destructor never waits on the caller.
pub(super) struct MacChildLifecycle {
    shared: Arc<MacChildLifecycleShared>,
}

impl MacChildLifecycle {
    fn prepare() -> Result<Self, SessionTransportError> {
        let shared = Arc::new(MacChildLifecycleShared {
            pid: AtomicI32::new(0),
            terminate: AtomicBool::new(false),
            traced: AtomicBool::new(false),
            reaper_gate: Mutex::new(()),
            state: Mutex::new(MacChildLifecycleState {
                reaped: false,
                last_error: None,
                exit_status: None,
                task_name: None,
                audit_token: None,
            }),
            changed: Condvar::new(),
            #[cfg(test)]
            reap_delay_ms: AtomicU64::new(0),
            #[cfg(test)]
            wait_interrupts: AtomicU64::new(0),
        });
        let worker_shared = Arc::clone(&shared);
        std::thread::Builder::new()
            .name("native-ipc-macos-child-reaper".into())
            .spawn(move || mac_child_reaper(worker_shared))
            .map_err(|error| SessionTransportError::Native(error.raw_os_error()))?;
        Ok(Self { shared })
    }

    fn start(pid: Pid) -> Result<Self, SessionTransportError> {
        let lifecycle = Self::prepare()?;
        lifecycle.activate(pid);
        Ok(lifecycle)
    }

    fn activate(&self, pid: Pid) {
        debug_assert!(pid > 0);
        let previous = self.shared.pid.swap(pid, Ordering::AcqRel);
        debug_assert_eq!(previous, 0);
        self.shared.changed.notify_all();
    }

    pub(super) fn pid(&self) -> u32 {
        self.shared.pid.load(Ordering::Acquire) as u32
    }

    fn install_task_identity(&self, task_name: TaskNameRight, audit_token: AuditToken) {
        let mut state = lock_lifecycle(&self.shared.state);
        debug_assert!(state.task_name.is_none());
        debug_assert!(state.audit_token.is_none());
        state.task_name = Some(task_name);
        state.audit_token = Some(audit_token);
        self.shared.changed.notify_all();
    }

    fn install_authenticated_audit_token(
        &self,
        audit_token: AuditToken,
    ) -> Result<(), SessionTransportError> {
        let mut state = lock_lifecycle(&self.shared.state);
        if let Some(task_name) = &state.task_name {
            let current = task_name
                .audit_token()
                .map_err(bootstrap_lifecycle_transport_error)?;
            if current != audit_token {
                return Err(SessionTransportError::IdentityMismatch);
            }
        }
        state.audit_token = Some(audit_token);
        self.shared.changed.notify_all();
        Ok(())
    }

    fn mark_traced(&self) {
        self.shared.traced.store(true, Ordering::Release);
        self.shared.changed.notify_all();
    }

    fn pause_reaping(&self) -> MacReapingPause<'_> {
        MacReapingPause {
            _guard: match self.shared.reaper_gate.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            },
        }
    }

    #[cfg(test)]
    fn current_task_audit_token_for_test(&self) -> Result<AuditToken, BootstrapError> {
        let state = lock_lifecycle(&self.shared.state);
        state
            .task_name
            .as_ref()
            .ok_or(BootstrapError::InvalidMessage)?
            .audit_token()
    }

    pub(super) fn try_poll(&self) -> Result<PeerState, SessionTransportError> {
        let state = lock_lifecycle(&self.shared.state);
        if state.reaped {
            Ok(PeerState::ExitedUnknown)
        } else if let Some(error) = state.last_error {
            Err(SessionTransportError::Native(Some(error)))
        } else {
            Ok(PeerState::Running)
        }
    }

    pub(super) fn exited_successfully_for_test(&self) -> bool {
        lock_lifecycle(&self.shared.state).exit_status == Some(0)
    }

    pub(super) fn wait_and_reap_status(
        &self,
        deadline: AbsoluteDeadline,
    ) -> Result<i32, SessionTransportError> {
        self.wait_for_status(deadline, false)
    }

    pub(super) fn wait_and_reap_facts(&self, deadline: AbsoluteDeadline) -> ChildCleanupFacts {
        mac_child_cleanup_facts(self.wait_and_reap_status(deadline))
    }

    pub(super) fn terminate_and_reap_status(
        &self,
        deadline: AbsoluteDeadline,
    ) -> Result<i32, SessionTransportError> {
        self.wait_for_status(deadline, true)
    }

    pub(super) fn terminate_and_reap_facts(&self, deadline: AbsoluteDeadline) -> ChildCleanupFacts {
        mac_child_cleanup_facts(self.terminate_and_reap_status(deadline))
    }

    pub(super) fn terminate_and_reap(
        &self,
        deadline: AbsoluteDeadline,
    ) -> Result<(), SessionTransportError> {
        self.terminate_and_reap_status(deadline).map(|_| ())
    }

    fn wait_for_status(
        &self,
        deadline: AbsoluteDeadline,
        terminate: bool,
    ) -> Result<i32, SessionTransportError> {
        if terminate {
            self.request_termination();
        }
        let mut state = lock_lifecycle(&self.shared.state);
        loop {
            if state.reaped {
                return state.exit_status.ok_or(SessionTransportError::Native(None));
            }
            if let Some(error) = state.last_error
                && error != ESRCH
            {
                return Err(SessionTransportError::Native(Some(error)));
            }
            let remaining = deadline.remaining();
            if remaining.is_zero() {
                return Err(match state.last_error {
                    Some(error) => SessionTransportError::Native(Some(error)),
                    None => SessionTransportError::DeadlineExpired,
                });
            }
            state = match self.shared.changed.wait_timeout(state, remaining) {
                Ok((state, _)) => state,
                Err(poisoned) => poisoned.into_inner().0,
            };
        }
    }

    fn request_termination(&self) {
        self.shared.terminate.store(true, Ordering::Release);
        self.shared.changed.notify_all();
    }

    #[cfg(test)]
    pub(super) fn delay_reap_for_test(&self, milliseconds: u64) {
        self.shared
            .reap_delay_ms
            .store(milliseconds, Ordering::Release);
    }

    #[cfg(test)]
    pub(super) fn interrupt_wait_for_test(&self, count: u64) {
        self.shared.wait_interrupts.store(count, Ordering::Release);
    }
}

struct MacReapingPause<'a> {
    _guard: std::sync::MutexGuard<'a, ()>,
}

fn mac_child_cleanup_facts(result: Result<i32, SessionTransportError>) -> ChildCleanupFacts {
    let descendants = DescendantCleanupStatus::FreshGroupUnverified;
    match result {
        Ok(status) if status & 0x7f == 0 => ChildCleanupFacts::new(
            Some(ChildExitStatus::Exited((status >> 8) & 0xff)),
            descendants,
            None,
        ),
        Ok(status) if status & 0x7f != 0x7f => ChildCleanupFacts::new(
            Some(ChildExitStatus::Signaled {
                signal: status & 0x7f,
                dumped_core: status & 0x80 != 0,
            }),
            descendants,
            None,
        ),
        Ok(_) => ChildCleanupFacts::new(None, descendants, None),
        Err(SessionTransportError::Native(code)) => ChildCleanupFacts::new(None, descendants, code),
        Err(
            SessionTransportError::DeadlineExpired
            | SessionTransportError::PeerExited
            | SessionTransportError::MalformedRecord
            | SessionTransportError::RecordTooLarge
            | SessionTransportError::IdentityMismatch
            | SessionTransportError::Ambiguous,
        ) => ChildCleanupFacts::new(None, descendants, None),
    }
}

impl Drop for MacChildLifecycle {
    fn drop(&mut self) {
        // The worker retains one Arc until exact wait completion. Request
        // cancellation/cleanup when this is the final external owner.
        if Arc::strong_count(&self.shared) <= 2 {
            self.request_termination();
        }
    }
}

impl Clone for MacChildLifecycle {
    fn clone(&self) -> Self {
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl ParentChannel {
    pub(super) const fn vnext_nonce(&self) -> [u8; 32] {
        self.nonce
    }

    pub(super) fn send_vnext_zero_rights(
        &mut self,
        bytes: &[u8],
        deadline: AbsoluteDeadline,
    ) -> Result<(), SessionTransportError> {
        send_vnext_message(
            self.peer_send.0,
            &self.nonce,
            VnextRecordKind::ZeroRights,
            bytes,
            &[],
            deadline,
        )
    }

    pub(super) fn receive_vnext_zero_rights(
        &mut self,
        maximum: usize,
        deadline: AbsoluteDeadline,
    ) -> Result<Vec<u8>, SessionTransportError> {
        let record = receive_vnext_message(
            &self._receive,
            &self.nonce,
            self.peer_pid,
            self.peer_audit.as_ref(),
            maximum,
            deadline,
        )?;
        if record.kind != VnextRecordKind::ZeroRights || !record.rights.is_empty() {
            return Err(SessionTransportError::MalformedRecord);
        }
        Ok(record.bytes)
    }

    pub(super) fn send_vnext_capabilities(
        &mut self,
        bytes: &[u8],
        rights: &[MachPort],
        deadline: AbsoluteDeadline,
    ) -> Result<(), SessionTransportError> {
        send_vnext_message(
            self.peer_send.0,
            &self.nonce,
            VnextRecordKind::Capabilities,
            bytes,
            rights,
            deadline,
        )
    }

    #[cfg(test)]
    pub(super) fn send_vnext_zero_with_rights_for_test(
        &mut self,
        bytes: &[u8],
        rights: &[MachPort],
        deadline: AbsoluteDeadline,
    ) -> Result<(), SessionTransportError> {
        send_vnext_message_inner(
            self.peer_send.0,
            &self.nonce,
            VnextRecordKind::ZeroRights,
            bytes,
            rights,
            deadline,
            true,
        )
    }

    pub(super) fn receive_vnext_capabilities(
        &mut self,
        maximum: usize,
        deadline: AbsoluteDeadline,
    ) -> Result<VnextCapabilityRecord, SessionTransportError> {
        let record = receive_vnext_message(
            &self._receive,
            &self.nonce,
            self.peer_pid,
            self.peer_audit.as_ref(),
            maximum,
            deadline,
        )?;
        if record.kind != VnextRecordKind::Capabilities || record.rights.is_empty() {
            return Err(SessionTransportError::MalformedRecord);
        }
        Ok(VnextCapabilityRecord {
            bytes: record.bytes,
            rights: record.rights,
        })
    }

    /// Completes the broker half of the cooperative traced-launcher gate.
    ///
    /// The child must call [`ChildChannel::prepare_traced_target_exec`] and
    /// exec the target immediately after that method returns.
    pub(super) fn start_traced_launcher(
        &mut self,
        lifecycle: &MacChildLifecycle,
        deadline: AbsoluteDeadline,
    ) -> Result<(), SessionTransportError> {
        let pid = self.peer_pid as Pid;
        if lifecycle.pid() != self.peer_pid {
            return Err(SessionTransportError::IdentityMismatch);
        }
        // Darwin reports traced stops to waitpid even without WUNTRACED. Keep
        // the background sole waiter from consuming either handshake stop.
        let _reaping_pause = lifecycle.pause_reaping();

        let (_self_task, self_audit) = TaskNameRight::capture(std::process::id() as Pid)
            .map_err(bootstrap_lifecycle_transport_error)?;
        let mut launchd_bootstrap = MACH_PORT_NULL;
        // SAFETY: output storage is valid for one copied send right.
        let result = unsafe {
            task_get_special_port(current_task(), TASK_BOOTSTRAP_PORT, &mut launchd_bootstrap)
        };
        if result != KERN_SUCCESS || launchd_bootstrap == MACH_PORT_NULL {
            return Err(SessionTransportError::Native(Some(result)));
        }
        let launchd_bootstrap = SendRight(launchd_bootstrap);
        self.send_vnext_capabilities(
            &encode_audit_token(self_audit),
            &[launchd_bootstrap.0],
            deadline,
        )?;

        if self.receive_vnext_zero_rights(1, deadline)? != [1] {
            return Err(SessionTransportError::MalformedRecord);
        }
        let status = wait_for_traced_stop_until(pid, deadline)?;
        if traced_stop_signal(status) != Some(SIGSTOP) {
            return Err(SessionTransportError::IdentityMismatch);
        }
        lifecycle.mark_traced();
        ptrace_continue(pid)?;

        if self.receive_vnext_zero_rights(1, deadline)? != [2] {
            return Err(SessionTransportError::MalformedRecord);
        }
        let status = wait_for_traced_stop_until(pid, deadline)?;
        if traced_stop_signal(status) != Some(5) {
            return Err(SessionTransportError::IdentityMismatch);
        }
        ptrace_continue(pid)
    }

    #[cfg(test)]
    pub(super) fn take_vnext_lifecycle(
        &mut self,
    ) -> Result<MacChildLifecycle, SessionTransportError> {
        if self.reaped {
            return Err(SessionTransportError::PeerExited);
        }
        let lifecycle = MacChildLifecycle::start(self.peer_pid as Pid)?;
        // The durable worker is now the sole waiter and exact-child cleanup
        // owner. Suppress the legacy blocking ParentChannel destructor.
        self.reaped = true;
        Ok(lifecycle)
    }

    /// Sends one port right to the authenticated helper.
    pub(super) fn send(
        &mut self,
        port: MachPort,
        native: NativeRegionSpec,
        access: PeerAccess,
    ) -> Result<(), BootstrapError> {
        let result = (|| {
            let entry = ManifestEntry::from_native(native, access);
            let transcript = self.single_manifest(entry)?.encode(CAPABILITY_MAGIC);
            send_port(
                self.peer_send.0,
                port,
                MACH_MSG_TYPE_COPY_SEND,
                &self.nonce,
                &transcript,
                None,
            )?;
            self.pending_entries.push(entry);
            Ok(())
        })();
        if result.is_err() {
            self.poison();
        }
        result
    }
    /// Kernel-authenticated helper PID.
    pub const fn peer_pid(&self) -> u32 {
        self.peer_pid
    }
    /// Waits for authenticated READY and acknowledges it with COMMIT.
    pub(super) fn ready_and_commit(&mut self) -> Result<(), BootstrapError> {
        let result = (|| {
            let manifest = self.batch_manifest()?;
            drop(receive_port(
                &self._receive,
                &self.nonce,
                self.peer_pid,
                &manifest.encode(READY_MAGIC),
                None,
            )?);
            #[cfg(test)]
            std::thread::sleep(std::time::Duration::from_millis(50));
            let marker = ReceiveRight::allocate()?;
            send_port(
                self.peer_send.0,
                marker.0,
                MACH_MSG_TYPE_MAKE_SEND,
                &self.nonce,
                &manifest.encode(COMMIT_MAGIC),
                None,
            )?;
            self.pending_entries.clear();
            self.next_transfer_id = self
                .next_transfer_id
                .checked_add(1)
                .ok_or(BootstrapError::InvalidMessage)?;
            Ok(())
        })();
        if result.is_err() {
            self.poison();
        }
        result
    }
    /// Waits for normal helper exit and consumes the child cleanup ledger.
    pub fn wait(mut self) -> Result<(), BootstrapError> {
        let mut status = 0;
        // SAFETY: PID is the held unreaped child and output pointer is valid.
        let result = unsafe { waitpid(self.peer_pid as Pid, &mut status, 0) };
        self.reaped = result == self.peer_pid as Pid;
        if self.reaped && status == 0 {
            Ok(())
        } else {
            Err(BootstrapError::Spawn(status))
        }
    }

    fn single_manifest(&self, entry: ManifestEntry) -> Result<TransferManifest, BootstrapError> {
        TransferManifest::new(
            self.nonce,
            std::process::id(),
            self.peer_pid,
            self.next_transfer_id,
            vec![entry],
        )
        .ok_or(BootstrapError::InvalidMessage)
    }

    fn batch_manifest(&self) -> Result<TransferManifest, BootstrapError> {
        if self.poisoned {
            return Err(BootstrapError::InvalidMessage);
        }
        TransferManifest::new(
            self.nonce,
            std::process::id(),
            self.peer_pid,
            self.next_transfer_id,
            self.pending_entries.clone(),
        )
        .ok_or(BootstrapError::InvalidMessage)
    }

    fn poison(&mut self) {
        self.poisoned = true;
        if !self.reaped {
            terminate_and_reap(self.peer_pid as Pid);
            self.reaped = true;
        }
    }

    pub(super) fn poison_transaction(&mut self) {
        self.poison();
    }

    /// Provenance stamp binding pending values to the open transaction.
    pub(super) const fn pending_provenance(&self) -> TransferProvenance {
        TransferProvenance::new(self.channel_id, self.next_transfer_id)
    }
}

/// Child side obtained from its injected special bootstrap port.
pub struct ChildChannel {
    _parent_send: SendRight,
    receive: ReceiveRight,
    nonce: [u8; 32],
    parent_pid: u32,
    parent_audit: Option<AuditToken>,
    pending_entries: Vec<ManifestEntry>,
    channel_id: u64,
    next_transfer_id: u64,
    poisoned: bool,
}

impl ChildChannel {
    /// Connects using the injected special port and authenticated environment.
    pub fn connect_from_environment() -> Result<Self, BootstrapError> {
        Self::connect_from_environment_inner(None)
    }

    pub(super) fn connect_from_environment_until(
        deadline: AbsoluteDeadline,
    ) -> Result<Self, BootstrapError> {
        Self::connect_from_environment_inner(Some(deadline))
    }

    fn connect_from_environment_inner(
        deadline: Option<AbsoluteDeadline>,
    ) -> Result<Self, BootstrapError> {
        let nonce = parse_nonce(
            &std::env::var(ENV_NONCE).map_err(|_| BootstrapError::InvalidEnvironment)?,
        )?;
        let parent_pid = std::env::var(ENV_PARENT_PID)
            .map_err(|_| BootstrapError::InvalidEnvironment)?
            .parse()
            .map_err(|_| BootstrapError::InvalidEnvironment)?;
        let mut parent = MACH_PORT_NULL;
        // SAFETY: output pointer is valid for the current task.
        mach("task_get_special_port", unsafe {
            task_get_special_port(current_task(), TASK_BOOTSTRAP_PORT, &mut parent)
        })?;
        if parent == MACH_PORT_NULL {
            return Err(BootstrapError::InvalidEnvironment);
        }
        let receive = ReceiveRight::allocate()?;
        send_port(
            parent,
            receive.0,
            MACH_MSG_TYPE_MAKE_SEND,
            &nonce,
            &[0; CONTROL_FRAME_LEN],
            deadline,
        )?;
        Ok(Self {
            _parent_send: SendRight(parent),
            receive,
            nonce,
            parent_pid,
            parent_audit: None,
            pending_entries: Vec::new(),
            channel_id: mint_channel_id(),
            next_transfer_id: 1,
            poisoned: false,
        })
    }

    pub(super) const fn vnext_nonce(&self) -> [u8; 32] {
        self.nonce
    }

    pub(super) const fn vnext_parent_pid(&self) -> u32 {
        self.parent_pid
    }

    pub(super) fn send_vnext_zero_rights(
        &mut self,
        bytes: &[u8],
        deadline: AbsoluteDeadline,
    ) -> Result<(), SessionTransportError> {
        send_vnext_message(
            self._parent_send.0,
            &self.nonce,
            VnextRecordKind::ZeroRights,
            bytes,
            &[],
            deadline,
        )
    }

    pub(super) fn receive_vnext_zero_rights(
        &mut self,
        maximum: usize,
        deadline: AbsoluteDeadline,
    ) -> Result<Vec<u8>, SessionTransportError> {
        let record = receive_vnext_message(
            &self.receive,
            &self.nonce,
            self.parent_pid,
            self.parent_audit.as_ref(),
            maximum,
            deadline,
        )?;
        // Pin the coordinator execution identity at the first authenticated
        // record; every later record must carry the identical complete token.
        self.parent_audit.get_or_insert(record.audit);
        if record.kind != VnextRecordKind::ZeroRights || !record.rights.is_empty() {
            return Err(SessionTransportError::MalformedRecord);
        }
        Ok(record.bytes)
    }

    pub(super) fn send_vnext_capabilities(
        &mut self,
        bytes: &[u8],
        rights: &[MachPort],
        deadline: AbsoluteDeadline,
    ) -> Result<(), SessionTransportError> {
        send_vnext_message(
            self._parent_send.0,
            &self.nonce,
            VnextRecordKind::Capabilities,
            bytes,
            rights,
            deadline,
        )
    }

    pub(super) fn receive_vnext_capabilities(
        &mut self,
        maximum: usize,
        deadline: AbsoluteDeadline,
    ) -> Result<VnextCapabilityRecord, SessionTransportError> {
        let record = receive_vnext_message(
            &self.receive,
            &self.nonce,
            self.parent_pid,
            self.parent_audit.as_ref(),
            maximum,
            deadline,
        )?;
        // Pin the coordinator execution identity at the first authenticated
        // record; every later record must carry the identical complete token.
        self.parent_audit.get_or_insert(record.audit);
        if record.kind != VnextRecordKind::Capabilities || record.rights.is_empty() {
            return Err(SessionTransportError::MalformedRecord);
        }
        Ok(VnextCapabilityRecord {
            bytes: record.bytes,
            rights: record.rights,
        })
    }

    /// Establishes cooperative tracing and an irreversible no-descendants
    /// limit before a trusted launcher execs untrusted target code.
    pub(super) fn prepare_traced_target_exec(
        &mut self,
        deadline: AbsoluteDeadline,
    ) -> Result<(), SessionTransportError> {
        let bootstrap = self.receive_vnext_capabilities(32, deadline)?;
        if bootstrap.bytes.len() != 32 || bootstrap.rights.len() != 1 {
            return Err(SessionTransportError::MalformedRecord);
        }
        let expected_parent_audit = decode_audit_token(&bootstrap.bytes)?;
        // SAFETY: the authenticated broker transferred one live send right to
        // its launchd bootstrap namespace. The MIG call copies that send right
        // into this task's special-port slot before target exec.
        let result = unsafe {
            task_set_special_port(current_task(), TASK_BOOTSTRAP_PORT, bootstrap.rights[0].0)
        };
        if result != KERN_SUCCESS {
            return Err(SessionTransportError::Native(Some(result)));
        }

        let parent_pid = self.parent_pid as Pid;
        let (parent_task, parent_audit) =
            TaskNameRight::capture(parent_pid).map_err(bootstrap_lifecycle_transport_error)?;
        if parent_audit != expected_parent_audit {
            return Err(SessionTransportError::IdentityMismatch);
        }
        // SAFETY: getppid has no preconditions.
        if unsafe { getppid() } != parent_pid {
            return Err(SessionTransportError::IdentityMismatch);
        }
        // SAFETY: the trusted launcher voluntarily binds tracing to its exact
        // current parent. XNU rechecks reparenting while establishing it.
        if unsafe { ptrace(PT_TRACE_ME, 0, std::ptr::null_mut(), 0) } != 0 {
            return Err(last_native_error());
        }
        if parent_task
            .audit_token()
            .map_err(bootstrap_lifecycle_transport_error)?
            != parent_audit
        {
            return Err(SessionTransportError::IdentityMismatch);
        }
        // SAFETY: getppid has no preconditions.
        if unsafe { getppid() } != parent_pid {
            return Err(SessionTransportError::IdentityMismatch);
        }

        self.send_vnext_zero_rights(&[1], deadline)?;
        // SAFETY: this creates a traced stop that only the intended broker can
        // observe and continue, proving the relationship before target exec.
        if unsafe { raise(SIGSTOP) } != 0 {
            return Err(last_native_error());
        }
        if parent_task
            .audit_token()
            .map_err(bootstrap_lifecycle_transport_error)?
            != parent_audit
        {
            return Err(SessionTransportError::IdentityMismatch);
        }

        let limit = ResourceLimit {
            current: 1,
            maximum: 1,
        };
        // SAFETY: install an irreversible hard per-UID process limit before
        // target exec. Non-root code cannot raise it again.
        if unsafe { setrlimit(RLIMIT_NPROC, &limit) } != 0 {
            return Err(last_native_error());
        }
        self.send_vnext_zero_rights(&[2], deadline)
    }

    pub(super) fn try_poll_vnext_peer(&self) -> Result<PeerState, SessionTransportError> {
        port_peer_state(self._parent_send.0)
    }
    /// Receives one port right from the authenticated parent.
    pub(super) fn receive(
        &mut self,
        native: NativeRegionSpec,
        access: PeerAccess,
    ) -> Result<SendRight, BootstrapError> {
        let result = (|| {
            let entry = ManifestEntry::from_native(native, access);
            let transcript = self.single_manifest(entry)?.encode(CAPABILITY_MAGIC);
            let right = receive_port(
                &self.receive,
                &self.nonce,
                self.parent_pid,
                &transcript,
                None,
            )?;
            self.pending_entries.push(entry);
            Ok(right)
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
    /// Signals validation and waits for the creator's COMMIT acknowledgement.
    pub(super) fn ready_and_wait_commit(&mut self) -> Result<(), BootstrapError> {
        let result = (|| {
            let manifest = self.batch_manifest()?;
            let marker = ReceiveRight::allocate()?;
            send_port(
                self._parent_send.0,
                marker.0,
                MACH_MSG_TYPE_MAKE_SEND,
                &self.nonce,
                &manifest.encode(READY_MAGIC),
                None,
            )?;
            drop(receive_port(
                &self.receive,
                &self.nonce,
                self.parent_pid,
                &manifest.encode(COMMIT_MAGIC),
                None,
            )?);
            self.pending_entries.clear();
            self.next_transfer_id = self
                .next_transfer_id
                .checked_add(1)
                .ok_or(BootstrapError::InvalidMessage)?;
            Ok(())
        })();
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }

    fn single_manifest(&self, entry: ManifestEntry) -> Result<TransferManifest, BootstrapError> {
        TransferManifest::new(
            self.nonce,
            self.parent_pid,
            std::process::id(),
            self.next_transfer_id,
            vec![entry],
        )
        .ok_or(BootstrapError::InvalidMessage)
    }

    fn batch_manifest(&self) -> Result<TransferManifest, BootstrapError> {
        if self.poisoned {
            return Err(BootstrapError::InvalidMessage);
        }
        TransferManifest::new(
            self.nonce,
            self.parent_pid,
            std::process::id(),
            self.next_transfer_id,
            self.pending_entries.clone(),
        )
        .ok_or(BootstrapError::InvalidMessage)
    }

    pub(super) fn poison_transaction(&mut self) {
        self.poisoned = true;
    }

    /// Provenance stamp binding pending values to the open transaction.
    pub(super) const fn pending_provenance(&self) -> TransferProvenance {
        TransferProvenance::new(self.channel_id, self.next_transfer_id)
    }
}

fn send_port(
    remote: MachPort,
    port: MachPort,
    disposition: u8,
    nonce: &[u8; 32],
    transcript: &[u8; CONTROL_FRAME_LEN],
    deadline: Option<AbsoluteDeadline>,
) -> Result<(), BootstrapError> {
    let mut message = PortMessage {
        header: MachMsgHeader {
            bits: MACH_MSGH_BITS_COMPLEX | u32::from(MACH_MSG_TYPE_COPY_SEND),
            size: size_of::<PortMessage>() as u32,
            remote_port: remote,
            local_port: MACH_PORT_NULL,
            voucher_port: MACH_PORT_NULL,
            id: MESSAGE_ID,
        },
        body: MachMsgBody {
            descriptor_count: 1,
        },
        descriptor: MachMsgPortDescriptor {
            name: port,
            pad1: 0,
            pad2: 0,
            disposition,
            descriptor_type: MACH_MSG_PORT_DESCRIPTOR,
        },
        magic: MESSAGE_MAGIC,
        nonce: *nonce,
        transcript: *transcript,
    };
    loop {
        let timeout = bootstrap_timeout(deadline)?;
        // SAFETY: complete initialized message buffer is live for bounded send.
        let result = unsafe {
            mach_msg(
                &mut message.header,
                MACH_SEND_MSG | MACH_SEND_TIMEOUT,
                size_of::<PortMessage>() as u32,
                0,
                MACH_PORT_NULL,
                timeout,
                MACH_PORT_NULL,
            )
        };
        match result {
            KERN_SUCCESS => break,
            MACH_SEND_INTERRUPTED if deadline.is_some() => continue,
            MACH_SEND_TIMED_OUT if deadline.is_some_and(|value| !value.is_expired()) => continue,
            MACH_SEND_TIMED_OUT => return Err(BootstrapError::DeadlineExpired),
            code => {
                return Err(BootstrapError::Mach {
                    operation: "mach_msg(send)",
                    code,
                });
            }
        }
    }
    if deadline.is_some_and(|value| value.is_expired()) {
        return Err(BootstrapError::Ambiguous);
    }
    Ok(())
}

fn receive_port(
    receive: &ReceiveRight,
    nonce: &[u8; 32],
    expected_pid: u32,
    expected_transcript: &[u8; CONTROL_FRAME_LEN],
    deadline: Option<AbsoluteDeadline>,
) -> Result<SendRight, BootstrapError> {
    receive_port_with_audit(receive, nonce, expected_pid, expected_transcript, deadline)
        .map(|(right, _)| right)
}

fn receive_port_with_audit(
    receive: &ReceiveRight,
    nonce: &[u8; 32],
    expected_pid: u32,
    expected_transcript: &[u8; CONTROL_FRAME_LEN],
    deadline: Option<AbsoluteDeadline>,
) -> Result<(SendRight, AuditToken), BootstrapError> {
    // SAFETY: zero is valid initialization for receive buffer/out descriptor.
    let mut buffer: ReceiveBuffer = unsafe { zeroed() };
    loop {
        let timeout = bootstrap_timeout(deadline)?;
        // SAFETY: receive buffer is sized for message plus requested audit trailer.
        let result = unsafe {
            mach_msg(
                &mut buffer.message.header,
                MACH_RCV_MSG | MACH_RCV_TIMEOUT | MACH_RCV_TRAILER_AUDIT,
                0,
                size_of::<ReceiveBuffer>() as u32,
                receive.0,
                timeout,
                MACH_PORT_NULL,
            )
        };
        match result {
            KERN_SUCCESS => break,
            MACH_RCV_INTERRUPTED if deadline.is_some() => continue,
            MACH_RCV_TIMED_OUT if deadline.is_some_and(|value| !value.is_expired()) => continue,
            MACH_RCV_TIMED_OUT => return Err(BootstrapError::DeadlineExpired),
            code => {
                return Err(BootstrapError::Mach {
                    operation: "mach_msg(receive)",
                    code,
                });
            }
        }
    }
    if deadline.is_some_and(|value| value.is_expired()) {
        destroy_legacy_received_if_complex(&mut buffer);
        return Err(BootstrapError::DeadlineExpired);
    }
    let expected_bits = MACH_MSGH_BITS_COMPLEX | (u32::from(MACH_MSG_TYPE_PORT_SEND) << 8);
    let complex = buffer.message.header.bits & MACH_MSGH_BITS_COMPLEX != 0;
    if buffer.message.header.bits != expected_bits
        || buffer.message.header.size as usize != size_of::<PortMessage>()
        || buffer.message.header.remote_port != MACH_PORT_NULL
        || buffer.message.header.local_port != receive.0
        || buffer.message.header.voucher_port != MACH_PORT_NULL
        || buffer.message.header.id != MESSAGE_ID
        || buffer.message.body.descriptor_count != 1
        || buffer.message.descriptor.descriptor_type != MACH_MSG_PORT_DESCRIPTOR
        || buffer.message.descriptor.disposition != MACH_MSG_TYPE_PORT_SEND
        || buffer.message.descriptor.pad1 != 0
        || buffer.message.descriptor.pad2 != 0
        || buffer.message.magic != MESSAGE_MAGIC
        || buffer.message.nonce != *nonce
        || buffer.message.transcript != *expected_transcript
        || buffer.message.descriptor.name == MACH_PORT_NULL
        || buffer.trailer.trailer_type != 0
        || buffer.trailer.trailer_size as usize != size_of::<AuditTrailer>()
    {
        if complex {
            // SAFETY: the kernel delivered a complex message into this live buffer;
            // libSystem destroys every delivered descriptor according to its type.
            unsafe { mach_msg_destroy(&mut buffer.message.header) };
        }
        return Err(BootstrapError::InvalidMessage);
    }
    // SAFETY: kernel supplied a complete audit trailer of the checked size.
    let actual = unsafe { audit_token_to_pid(buffer.trailer.audit) } as u32;
    if actual != expected_pid {
        // SAFETY: the exact checked complex message is still wholly owned by
        // this receive buffer; destroy every delivered right on rejection.
        unsafe { mach_msg_destroy(&mut buffer.message.header) };
        return Err(BootstrapError::WrongPeer {
            expected: expected_pid,
            actual,
        });
    }
    Ok((
        SendRight(buffer.message.descriptor.name),
        buffer.trailer.audit,
    ))
}

struct ReceivedVnextRecord {
    kind: VnextRecordKind,
    bytes: Vec<u8>,
    rights: Vec<SendRight>,
    audit: AuditToken,
}

fn send_vnext_message(
    remote: MachPort,
    nonce: &[u8; 32],
    kind: VnextRecordKind,
    payload: &[u8],
    rights: &[MachPort],
    deadline: AbsoluteDeadline,
) -> Result<(), SessionTransportError> {
    send_vnext_message_inner(remote, nonce, kind, payload, rights, deadline, false)
}

fn send_vnext_message_inner(
    remote: MachPort,
    nonce: &[u8; 32],
    kind: VnextRecordKind,
    payload: &[u8],
    rights: &[MachPort],
    deadline: AbsoluteDeadline,
    allow_kind_rights_mismatch_for_test: bool,
) -> Result<(), SessionTransportError> {
    if payload.is_empty() || payload.len() > MAX_VNEXT_RECORD_BYTES {
        return Err(SessionTransportError::RecordTooLarge);
    }
    let capability_record = kind == VnextRecordKind::Capabilities;
    if (!allow_kind_rights_mismatch_for_test && capability_record != !rights.is_empty())
        || rights.len() > MAX_VNEXT_CAPABILITIES
        || rights.contains(&MACH_PORT_NULL)
    {
        return Err(SessionTransportError::MalformedRecord);
    }
    let descriptor_bytes = rights
        .len()
        .checked_mul(size_of::<MachMsgPortDescriptor>())
        .ok_or(SessionTransportError::RecordTooLarge)?;
    let body_bytes = if rights.is_empty() {
        0
    } else {
        size_of::<MachMsgBody>()
    };
    let unrounded = size_of::<MachMsgHeader>()
        .checked_add(body_bytes)
        .and_then(|size| size.checked_add(descriptor_bytes))
        .and_then(|size| size.checked_add(size_of::<VnextEnvelope>()))
        .and_then(|size| size.checked_add(payload.len()))
        .ok_or(SessionTransportError::RecordTooLarge)?;
    let message_size = round_message(unrounded).ok_or(SessionTransportError::RecordTooLarge)?;
    let words = message_size.div_ceil(size_of::<u64>());
    let mut storage = vec![0_u64; words];
    let bytes = slice_as_bytes_mut(&mut storage);
    let header = MachMsgHeader {
        bits: u32::from(MACH_MSG_TYPE_COPY_SEND)
            | if rights.is_empty() {
                0
            } else {
                MACH_MSGH_BITS_COMPLEX
            },
        size: u32::try_from(message_size).map_err(|_| SessionTransportError::RecordTooLarge)?,
        remote_port: remote,
        local_port: MACH_PORT_NULL,
        voucher_port: MACH_PORT_NULL,
        id: VNEXT_MESSAGE_ID,
    };
    write_value(bytes, 0, header);
    let mut offset = size_of::<MachMsgHeader>();
    if !rights.is_empty() {
        write_value(
            bytes,
            offset,
            MachMsgBody {
                descriptor_count: rights.len() as u32,
            },
        );
        offset += size_of::<MachMsgBody>();
        for right in rights {
            write_value(
                bytes,
                offset,
                MachMsgPortDescriptor {
                    name: *right,
                    pad1: 0,
                    pad2: 0,
                    disposition: MACH_MSG_TYPE_COPY_SEND,
                    descriptor_type: MACH_MSG_PORT_DESCRIPTOR,
                },
            );
            offset += size_of::<MachMsgPortDescriptor>();
        }
    }
    write_value(
        bytes,
        offset,
        VnextEnvelope {
            magic: VNEXT_MESSAGE_MAGIC,
            nonce: *nonce,
            kind: kind as u32,
            payload_len: payload.len() as u32,
        },
    );
    offset += size_of::<VnextEnvelope>();
    bytes[offset..offset + payload.len()].copy_from_slice(payload);

    loop {
        let timeout = deadline_timeout(deadline)?;
        // SAFETY: storage is naturally aligned and contains one fully
        // initialized bounded inline Mach message for the duration of the call.
        let result = unsafe {
            mach_msg(
                bytes.as_mut_ptr().cast(),
                MACH_SEND_MSG | MACH_SEND_TIMEOUT,
                message_size as u32,
                0,
                MACH_PORT_NULL,
                timeout,
                MACH_PORT_NULL,
            )
        };
        match result {
            KERN_SUCCESS => break,
            MACH_SEND_INTERRUPTED => continue,
            MACH_SEND_TIMED_OUT if !deadline.is_expired() => continue,
            MACH_SEND_TIMED_OUT => return Err(SessionTransportError::DeadlineExpired),
            other => return Err(SessionTransportError::Native(Some(other))),
        }
    }
    if deadline.is_expired() {
        return Err(SessionTransportError::Ambiguous);
    }
    Ok(())
}

fn receive_vnext_message(
    receive: &ReceiveRight,
    nonce: &[u8; 32],
    expected_pid: u32,
    expected_audit: Option<&AuditToken>,
    maximum: usize,
    deadline: AbsoluteDeadline,
) -> Result<ReceivedVnextRecord, SessionTransportError> {
    if maximum == 0 || maximum > MAX_VNEXT_RECORD_BYTES {
        return Err(SessionTransportError::RecordTooLarge);
    }
    let maximum_message = size_of::<MachMsgHeader>()
        + size_of::<MachMsgBody>()
        + MAX_VNEXT_CAPABILITIES * size_of::<MachMsgPortDescriptor>()
        + size_of::<VnextEnvelope>()
        + maximum;
    let receive_bytes = round_message(maximum_message)
        .and_then(|size| size.checked_add(size_of::<AuditTrailer>()))
        .ok_or(SessionTransportError::RecordTooLarge)?;
    let words = receive_bytes.div_ceil(size_of::<u64>());
    let mut storage = vec![0_u64; words];
    let bytes = slice_as_bytes_mut(&mut storage);
    loop {
        bytes.fill(0);
        let timeout = deadline_timeout(deadline)?;
        // SAFETY: storage is naturally aligned, zero initialized, and sized for
        // the bounded message plus the requested full audit trailer.
        let result = unsafe {
            mach_msg(
                bytes.as_mut_ptr().cast(),
                MACH_RCV_MSG | MACH_RCV_TIMEOUT | MACH_RCV_TRAILER_AUDIT,
                0,
                u32::try_from(receive_bytes).map_err(|_| SessionTransportError::RecordTooLarge)?,
                receive.0,
                timeout,
                MACH_PORT_NULL,
            )
        };
        match result {
            KERN_SUCCESS => break,
            MACH_RCV_INTERRUPTED => continue,
            MACH_RCV_TIMED_OUT if !deadline.is_expired() => continue,
            MACH_RCV_TIMED_OUT => return Err(SessionTransportError::DeadlineExpired),
            MACH_RCV_TOO_LARGE => return Err(SessionTransportError::RecordTooLarge),
            other => return Err(SessionTransportError::Native(Some(other))),
        }
    }
    if deadline.is_expired() {
        destroy_received_if_complex(bytes);
        return Err(SessionTransportError::DeadlineExpired);
    }
    parse_vnext_message(
        bytes,
        receive.0,
        nonce,
        expected_pid,
        expected_audit,
        maximum,
    )
}

fn parse_vnext_message(
    bytes: &mut [u8],
    expected_receive: MachPort,
    nonce: &[u8; 32],
    expected_pid: u32,
    expected_audit: Option<&AuditToken>,
    maximum: usize,
) -> Result<ReceivedVnextRecord, SessionTransportError> {
    let header =
        read_value::<MachMsgHeader>(bytes, 0).ok_or(SessionTransportError::MalformedRecord)?;
    let complex = header.bits & MACH_MSGH_BITS_COMPLEX != 0;
    let message_size = header.size as usize;
    let trailer_offset =
        round_message(message_size).ok_or(SessionTransportError::MalformedRecord)?;
    let trailer = read_value::<AuditTrailer>(bytes, trailer_offset);
    let mut offset = size_of::<MachMsgHeader>();
    let descriptor_count = if complex {
        let Some(body) = read_value::<MachMsgBody>(bytes, offset) else {
            destroy_received_if_complex(bytes);
            return Err(SessionTransportError::MalformedRecord);
        };
        offset += size_of::<MachMsgBody>();
        body.descriptor_count as usize
    } else {
        0
    };
    let descriptor_bytes = descriptor_count.checked_mul(size_of::<MachMsgPortDescriptor>());
    let envelope_offset = descriptor_bytes.and_then(|size| offset.checked_add(size));
    let envelope = envelope_offset.and_then(|at| read_value::<VnextEnvelope>(bytes, at));
    let expected_bits =
        u32::from(MACH_MSG_TYPE_PORT_SEND) << 8 | if complex { MACH_MSGH_BITS_COMPLEX } else { 0 };
    let canonical_shape = header.bits == expected_bits
        && header.remote_port == MACH_PORT_NULL
        && header.local_port == expected_receive
        && header.voucher_port == MACH_PORT_NULL
        && header.id == VNEXT_MESSAGE_ID
        && descriptor_count <= MAX_VNEXT_CAPABILITIES
        && complex == (descriptor_count != 0)
        && trailer.is_some_and(|value| {
            value.trailer_type == 0 && value.trailer_size as usize == size_of::<AuditTrailer>()
        })
        && envelope
            .is_some_and(|value| value.magic == VNEXT_MESSAGE_MAGIC && value.nonce == *nonce);
    if !canonical_shape {
        destroy_received_if_complex(bytes);
        return Err(SessionTransportError::MalformedRecord);
    }
    let trailer = trailer.expect("checked trailer");
    // SAFETY: the checked complete audit trailer was supplied by the kernel.
    let actual_pid = unsafe { audit_token_to_pid(trailer.audit) } as u32;
    if actual_pid != expected_pid {
        destroy_received_if_complex(bytes);
        return Err(SessionTransportError::IdentityMismatch);
    }
    // When the channel pinned the peer's authentication-time audit token,
    // every later record must carry the identical complete token. A helper
    // `exec` keeps the PID but changes the PID version, so this rejects any
    // record sent by a different execution of the same process.
    if expected_audit.is_some_and(|expected| trailer.audit != *expected) {
        destroy_received_if_complex(bytes);
        return Err(SessionTransportError::IdentityMismatch);
    }
    let envelope = envelope.expect("checked envelope");
    let kind = match envelope.kind {
        1 => VnextRecordKind::ZeroRights,
        2 => VnextRecordKind::Capabilities,
        _ => {
            destroy_received_if_complex(bytes);
            return Err(SessionTransportError::MalformedRecord);
        }
    };
    let payload_len = envelope.payload_len as usize;
    if payload_len == 0 || payload_len > maximum || payload_len > MAX_VNEXT_RECORD_BYTES {
        destroy_received_if_complex(bytes);
        return Err(SessionTransportError::MalformedRecord);
    }
    let payload_offset = envelope_offset
        .and_then(|at| at.checked_add(size_of::<VnextEnvelope>()))
        .ok_or(SessionTransportError::MalformedRecord)?;
    let unrounded = payload_offset
        .checked_add(payload_len)
        .ok_or(SessionTransportError::MalformedRecord)?;
    let canonical_size = round_message(unrounded).ok_or(SessionTransportError::MalformedRecord)?;
    if message_size != canonical_size
        || trailer_offset + size_of::<AuditTrailer>() > bytes.len()
        || unrounded > bytes.len()
        || bytes[unrounded..message_size].iter().any(|byte| *byte != 0)
    {
        destroy_received_if_complex(bytes);
        return Err(SessionTransportError::MalformedRecord);
    }
    let mut right_names = Vec::with_capacity(descriptor_count);
    let mut descriptor_offset = size_of::<MachMsgHeader>() + size_of::<MachMsgBody>();
    for _ in 0..descriptor_count {
        let Some(descriptor) = read_value::<MachMsgPortDescriptor>(bytes, descriptor_offset) else {
            destroy_received_if_complex(bytes);
            return Err(SessionTransportError::MalformedRecord);
        };
        if descriptor.descriptor_type != MACH_MSG_PORT_DESCRIPTOR
            || descriptor.disposition != MACH_MSG_TYPE_PORT_SEND
            || descriptor.name == MACH_PORT_NULL
            || descriptor.pad1 != 0
            || descriptor.pad2 != 0
        {
            destroy_received_if_complex(bytes);
            return Err(SessionTransportError::MalformedRecord);
        }
        right_names.push(descriptor.name);
        descriptor_offset += size_of::<MachMsgPortDescriptor>();
    }
    let rights = right_names.into_iter().map(SendRight).collect();
    Ok(ReceivedVnextRecord {
        kind,
        bytes: bytes[payload_offset..unrounded].to_vec(),
        rights,
        audit: trailer.audit,
    })
}

fn destroy_received_if_complex(bytes: &mut [u8]) {
    let Some(header) = read_value::<MachMsgHeader>(bytes, 0) else {
        return;
    };
    if header.bits & MACH_MSGH_BITS_COMPLEX != 0 {
        // SAFETY: the kernel delivered this complex message into the live
        // aligned buffer; libSystem owns the descriptor-shape destruction ABI.
        unsafe { mach_msg_destroy(bytes.as_mut_ptr().cast()) };
    }
}

fn read_value<T: Copy>(bytes: &[u8], offset: usize) -> Option<T> {
    let end = offset.checked_add(size_of::<T>())?;
    (end <= bytes.len()).then(|| {
        // SAFETY: the byte range is in bounds; unaligned reads support every
        // field offset used by the packed Mach wire representation.
        unsafe { bytes.as_ptr().add(offset).cast::<T>().read_unaligned() }
    })
}

fn write_value<T: Copy>(bytes: &mut [u8], offset: usize, value: T) {
    debug_assert!(offset + size_of::<T>() <= bytes.len());
    // SAFETY: callers reserve the complete in-bounds byte range; unaligned
    // writes support every descriptor offset.
    unsafe {
        bytes
            .as_mut_ptr()
            .add(offset)
            .cast::<T>()
            .write_unaligned(value)
    };
}

fn slice_as_bytes_mut(words: &mut [u64]) -> &mut [u8] {
    // SAFETY: a u64 slice is contiguous initialized storage; byte access spans
    // exactly the same allocation and preserves its natural alignment.
    unsafe { core::slice::from_raw_parts_mut(words.as_mut_ptr().cast(), size_of_val(words)) }
}

fn round_message(size: usize) -> Option<usize> {
    size.checked_add(size_of::<u32>() - 1)
        .map(|value| value & !(size_of::<u32>() - 1))
}

fn deadline_timeout(deadline: AbsoluteDeadline) -> Result<u32, SessionTransportError> {
    let remaining = deadline.remaining();
    if remaining.is_zero() {
        return Err(SessionTransportError::DeadlineExpired);
    }
    Ok(remaining
        .as_nanos()
        .div_ceil(1_000_000)
        .min(u32::MAX as u128) as u32)
}

fn bootstrap_timeout(deadline: Option<AbsoluteDeadline>) -> Result<u32, BootstrapError> {
    let Some(deadline) = deadline else {
        return Ok(TIMEOUT_MS);
    };
    let remaining = deadline.remaining();
    if remaining.is_zero() {
        return Err(BootstrapError::DeadlineExpired);
    }
    Ok(remaining
        .as_nanos()
        .div_ceil(1_000_000)
        .min(u32::MAX as u128) as u32)
}

fn bootstrap_lifecycle_error(error: SessionTransportError) -> BootstrapError {
    match error {
        SessionTransportError::DeadlineExpired => BootstrapError::DeadlineExpired,
        SessionTransportError::IdentityMismatch => BootstrapError::InvalidMessage,
        SessionTransportError::Native(Some(code)) => BootstrapError::Spawn(code),
        SessionTransportError::PeerExited
        | SessionTransportError::MalformedRecord
        | SessionTransportError::RecordTooLarge
        | SessionTransportError::Ambiguous
        | SessionTransportError::Native(None) => BootstrapError::InvalidMessage,
    }
}

fn bootstrap_lifecycle_transport_error(error: BootstrapError) -> SessionTransportError {
    match error {
        BootstrapError::Mach { code, .. } | BootstrapError::Spawn(code) => {
            SessionTransportError::Native(Some(code))
        }
        BootstrapError::WrongPeer { .. } => SessionTransportError::IdentityMismatch,
        BootstrapError::DeadlineExpired => SessionTransportError::DeadlineExpired,
        BootstrapError::Ambiguous => SessionTransportError::Ambiguous,
        BootstrapError::ExactAuthorityUnavailable { native_error } => {
            SessionTransportError::Native(native_error)
        }
        BootstrapError::InvalidMessage | BootstrapError::InvalidEnvironment => {
            SessionTransportError::MalformedRecord
        }
    }
}

fn destroy_legacy_received_if_complex(buffer: &mut ReceiveBuffer) {
    if buffer.message.header.bits & MACH_MSGH_BITS_COMPLEX != 0 {
        // SAFETY: the kernel delivered a complex message into this live buffer.
        unsafe { mach_msg_destroy(&mut buffer.message.header) };
    }
}

fn lock_lifecycle(
    state: &Mutex<MacChildLifecycleState>,
) -> std::sync::MutexGuard<'_, MacChildLifecycleState> {
    match state.lock() {
        Ok(state) => state,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn encode_audit_token(token: AuditToken) -> [u8; 32] {
    let mut encoded = [0_u8; 32];
    for (destination, value) in encoded.chunks_exact_mut(4).zip(token.values) {
        destination.copy_from_slice(&value.to_ne_bytes());
    }
    encoded
}

fn decode_audit_token(encoded: &[u8]) -> Result<AuditToken, SessionTransportError> {
    if encoded.len() != 32 {
        return Err(SessionTransportError::MalformedRecord);
    }
    let mut values = [0_u32; 8];
    for (destination, source) in values.iter_mut().zip(encoded.chunks_exact(4)) {
        *destination = u32::from_ne_bytes(
            source
                .try_into()
                .map_err(|_| SessionTransportError::MalformedRecord)?,
        );
    }
    Ok(AuditToken { values })
}

fn last_native_error() -> SessionTransportError {
    SessionTransportError::Native(std::io::Error::last_os_error().raw_os_error())
}

fn traced_stop_signal(status: c_int) -> Option<c_int> {
    (status & 0xff == 0x7f).then_some((status >> 8) & 0xff)
}

fn wait_for_traced_stop_until(
    pid: Pid,
    deadline: AbsoluteDeadline,
) -> Result<c_int, SessionTransportError> {
    loop {
        let mut status = 0;
        // SAFETY: the caller is the exact parent/tracer and output is valid.
        let result = unsafe { waitpid(pid, &mut status, WNOHANG | WUNTRACED) };
        if result == pid {
            if traced_stop_signal(status).is_some() {
                return Ok(status);
            }
            return Err(SessionTransportError::PeerExited);
        }
        if result < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(SessionTransportError::Native(error.raw_os_error()));
        }
        if deadline.remaining().is_zero() {
            return Err(SessionTransportError::DeadlineExpired);
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn ptrace_continue(pid: Pid) -> Result<(), SessionTransportError> {
    // SAFETY: address 1 is Darwin's sentinel for continuing at the current
    // program counter; the caller already observed this exact tracee stopped.
    if unsafe {
        ptrace(
            PT_CONTINUE,
            pid,
            std::ptr::without_provenance_mut::<c_void>(1),
            0,
        )
    } == 0
    {
        Ok(())
    } else {
        Err(last_native_error())
    }
}

fn signal_with_audit_token(token: &mut AuditToken, signal: c_int) -> Result<(), i32> {
    // SAFETY: the token was supplied by the kernel for the exact task-name
    // right retained by this lifecycle owner.
    let result = unsafe { proc_signal_with_audittoken(token, signal) };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(result))
    }
}

fn mac_child_reaper(shared: Arc<MacChildLifecycleShared>) {
    let mut termination_attempted = false;
    let mut pending_signal_error = None;
    loop {
        let pid = shared.pid.load(Ordering::Acquire);
        if pid == 0 {
            if shared.terminate.load(Ordering::Acquire) {
                return;
            }
            let state = lock_lifecycle(&shared.state);
            let _ = match shared.changed.wait_timeout(state, Duration::from_millis(1)) {
                Ok(result) => result,
                Err(poisoned) => poisoned.into_inner(),
            };
            continue;
        }

        // Serialize every lifecycle signal/wait decision with the launch
        // handshake. A concurrent termination request must not inject a stop
        // between the launcher's proof SIGSTOP and its exec SIGTRAP.
        let reaper_gate = match shared.reaper_gate.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };

        if shared.terminate.load(Ordering::Acquire) && !termination_attempted {
            if shared.traced.load(Ordering::Acquire) {
                termination_attempted = true;
                // The sole waiter has not reaped this direct child, so a live
                // child owns this PID and an exited child remains a PID-pinning
                // zombie. The numeric stop therefore cannot hit a replacement.
                // SAFETY: pid is this worker's exact unreaped traced child.
                if unsafe { kill(pid, SIGSTOP) } != 0 {
                    let error = std::io::Error::last_os_error()
                        .raw_os_error()
                        .unwrap_or(ESRCH);
                    if error != ESRCH {
                        pending_signal_error = Some(error);
                    }
                }
            } else {
                let audit_token = lock_lifecycle(&shared.state).audit_token;
                if let Some(mut audit_token) = audit_token {
                    termination_attempted = true;
                    if let Err(error) = signal_with_audit_token(&mut audit_token, 9) {
                        // A post-capture `exec` changes the audit-token PID version.
                        // The private exact-signal SPI then returns ESRCH while the
                        // direct child may still be alive; retain that incomplete
                        // cleanup fact rather than falling back to its numeric PID.
                        pending_signal_error = Some(error);
                    }
                }
            }
        }

        #[cfg(test)]
        {
            let delay = shared.reap_delay_ms.swap(0, Ordering::AcqRel);
            if delay != 0 {
                std::thread::sleep(Duration::from_millis(delay));
            }
        }

        #[cfg(test)]
        if shared
            .wait_interrupts
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            continue;
        }

        let mut status = 0;
        // SAFETY: this worker is the sole waiter for the exact spawned PID.
        let wait_options = if termination_attempted && shared.traced.load(Ordering::Acquire) {
            WNOHANG | WUNTRACED
        } else {
            WNOHANG
        };
        // The traced-launcher handshake holds this gate while it consumes the
        // initial SIGSTOP and exec SIGTRAP. Excluding the background waiter is
        // mandatory because Darwin reports trace stops to a direct parent even
        // when its waitpid call omitted WUNTRACED.
        // SAFETY: this worker is the sole background waiter for the exact
        // spawned PID, and the handshake gate excludes its only peer.
        let result = unsafe { waitpid(pid, &mut status, wait_options) };
        if result == pid {
            if traced_stop_signal(status).is_some() {
                // SAFETY: XNU accepts PT_KILL only from this tracee's exact
                // tracer while the tracee is stopped.
                if unsafe { ptrace(PT_KILL, pid, std::ptr::null_mut(), 0) } != 0 {
                    pending_signal_error = Some(
                        std::io::Error::last_os_error()
                            .raw_os_error()
                            .unwrap_or(ESRCH),
                    );
                }
                continue;
            }
            let mut state = lock_lifecycle(&shared.state);
            state.reaped = true;
            state.exit_status = Some(status);
            shared.changed.notify_all();
            return;
        }
        if result < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            let mut state = lock_lifecycle(&shared.state);
            state.last_error = error.raw_os_error();
            shared.changed.notify_all();
            return;
        }

        if let Some(error) = pending_signal_error.take() {
            let mut state = lock_lifecycle(&shared.state);
            state.last_error = Some(error);
            shared.changed.notify_all();
        }

        drop(reaper_gate);
        let state = lock_lifecycle(&shared.state);
        let _ = match shared.changed.wait_timeout(state, Duration::from_millis(1)) {
            Ok(result) => result,
            Err(poisoned) => poisoned.into_inner(),
        };
    }
}

fn port_peer_state(name: MachPort) -> Result<PeerState, SessionTransportError> {
    let mut port_type = 0;
    // SAFETY: output points to one writable type value and name is retained by
    // the authenticated endpoint owner.
    let result = unsafe { mach_port_type(current_task(), name, &mut port_type) };
    if result != KERN_SUCCESS {
        return Err(SessionTransportError::Native(Some(result)));
    }
    if port_type & MACH_PORT_TYPE_DEAD_NAME != 0 {
        Ok(PeerState::ExitedUnknown)
    } else if port_type & MACH_PORT_TYPE_SEND != 0 {
        Ok(PeerState::Running)
    } else {
        Err(SessionTransportError::Native(None))
    }
}

pub(super) fn random_nonce() -> Result<[u8; 32], BootstrapError> {
    let mut nonce = [0_u8; 32];
    // arc4random_buf is provided by libSystem and has no failure mode.
    unsafe extern "C" {
        fn arc4random_buf(buffer: *mut c_void, length: usize);
    }
    // SAFETY: output buffer is valid for its complete length.
    unsafe { arc4random_buf(nonce.as_mut_ptr().cast(), nonce.len()) };
    if nonce == [0; 32] {
        Err(BootstrapError::InvalidEnvironment)
    } else {
        Ok(nonce)
    }
}

fn mach(operation: &'static str, code: c_int) -> Result<(), BootstrapError> {
    if code == KERN_SUCCESS {
        Ok(())
    } else {
        Err(BootstrapError::Mach { operation, code })
    }
}
fn spawn_result(code: c_int) -> Result<(), BootstrapError> {
    if code == 0 {
        Ok(())
    } else {
        Err(BootstrapError::Spawn(code))
    }
}

const fn bootstrap_native_error(error: &BootstrapError) -> Option<c_int> {
    match error {
        BootstrapError::Mach { code, .. } | BootstrapError::Spawn(code) => Some(*code),
        BootstrapError::ExactAuthorityUnavailable { native_error } => *native_error,
        BootstrapError::InvalidMessage
        | BootstrapError::WrongPeer { .. }
        | BootstrapError::InvalidEnvironment
        | BootstrapError::DeadlineExpired
        | BootstrapError::Ambiguous => None,
    }
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}
fn parse_nonce(encoded: &str) -> Result<[u8; 32], BootstrapError> {
    if encoded.len() != 64 {
        return Err(BootstrapError::InvalidEnvironment);
    }
    let mut nonce = [0; 32];
    for (output, pair) in nonce.iter_mut().zip(encoded.as_bytes().chunks_exact(2)) {
        let pair = std::str::from_utf8(pair).map_err(|_| BootstrapError::InvalidEnvironment)?;
        *output = u8::from_str_radix(pair, 16).map_err(|_| BootstrapError::InvalidEnvironment)?;
    }
    Ok(nonce)
}

fn terminate_and_reap(pid: Pid) {
    if pid <= 0 {
        return;
    }
    // SAFETY: SIGKILL cannot be ignored and PID is the held spawned child.
    let _ = unsafe { kill(pid, 9) };
    let mut status = 0;
    // SAFETY: status pointer is valid; held child is reaped at most once here.
    let _ = unsafe { waitpid(pid, &mut status, 0) };
}

const _: () = assert!(size_of::<MachMsgHeader>() == 24);
const _: () = assert!(size_of::<MachMsgPortDescriptor>() == 12);
const _: () = assert!(size_of::<AuditTrailer>() == 52);

#[cfg(test)]
#[path = "bootstrap_test.rs"]
mod tests;
