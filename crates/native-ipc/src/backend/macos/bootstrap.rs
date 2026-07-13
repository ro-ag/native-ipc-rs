//! Private Mach bootstrap channel with audit-token process authentication.

use std::ffi::{CString, c_char, c_int, c_void};
use std::fmt;
use std::mem::{size_of, size_of_val, zeroed};
#[cfg(test)]
use std::sync::atomic::AtomicU64;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use super::{KERN_SUCCESS, MachPort, current_task, deallocate_port};
use crate::backend::{PeerState, SessionTransportError};
use crate::protocol::{
    CONTROL_FRAME_LEN, ManifestEntry, NativeRegionSpec, PeerAccess, TransferManifest,
    TransferProvenance, mint_channel_id,
};
use crate::session::AbsoluteDeadline;
type MachMsgReturn = c_int;
type PosixSpawnAttr = *mut c_void;

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
    fn task_get_special_port(task: MachPort, which: c_int, port: *mut MachPort) -> c_int;
    fn posix_spawnattr_init(attributes: *mut PosixSpawnAttr) -> c_int;
    fn posix_spawnattr_destroy(attributes: *mut PosixSpawnAttr) -> c_int;
    fn posix_spawnattr_setspecialport_np(
        attributes: *mut PosixSpawnAttr,
        port: MachPort,
        which: c_int,
    ) -> c_int;
    fn posix_spawn(
        pid: *mut Pid,
        path: *const c_char,
        file_actions: *const c_void,
        attributes: *const PosixSpawnAttr,
        argv: *const *mut c_char,
        envp: *const *mut c_char,
    ) -> c_int;
    fn kill(pid: Pid, signal: c_int) -> c_int;
    fn waitpid(pid: Pid, status: *mut c_int, options: c_int) -> Pid;
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
#[derive(Clone, Copy)]
struct AuditToken {
    values: [u32; 8],
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

/// Parent-owned exact helper and authenticated bidirectional Mach channel.
pub struct SpawnedHelper {
    pid: Pid,
    nonce: [u8; 32],
    receive: Option<ReceiveRight>,
}

impl SpawnedHelper {
    /// Spawns an absolute helper path with a private bootstrap send right.
    pub fn spawn(path: &CString, arguments: &[CString]) -> Result<Self, BootstrapError> {
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

        let mut argv_storage = Vec::with_capacity(arguments.len() + 1);
        argv_storage.push(path.clone());
        argv_storage.extend(arguments.iter().cloned());
        let mut argv: Vec<*mut c_char> = argv_storage
            .iter_mut()
            .map(|argument| argument.as_ptr().cast_mut())
            .collect();
        argv.push(std::ptr::null_mut());

        let nonce_value = hex(&nonce);
        let parent_pid = std::process::id().to_string();
        let mut environment: Vec<CString> = std::env::vars_os()
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
        environment.push(CString::new(format!("{ENV_NONCE}={nonce_value}")).expect("hex env"));
        environment.push(CString::new(format!("{ENV_PARENT_PID}={parent_pid}")).expect("pid env"));
        let mut envp: Vec<*mut c_char> = environment
            .iter_mut()
            .map(|entry| entry.as_ptr().cast_mut())
            .collect();
        envp.push(std::ptr::null_mut());
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
        Ok(Self {
            pid,
            nonce,
            receive: Some(receive),
        })
    }

    /// Receives the helper's control port and authenticates its audit PID.
    pub fn authenticate(mut self) -> Result<ParentChannel, BootstrapError> {
        let receive = self.receive.take().ok_or(BootstrapError::InvalidMessage)?;
        let child_send = match receive_port(
            &receive,
            &self.nonce,
            self.pid as u32,
            &[0; CONTROL_FRAME_LEN],
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
        if self.pid > 0 {
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
    reaped: bool,
    pending_entries: Vec<ManifestEntry>,
    channel_id: u64,
    next_transfer_id: u64,
    poisoned: bool,
}

struct MacChildLifecycleState {
    reaped: bool,
    last_error: Option<i32>,
    #[cfg(test)]
    exit_status: Option<i32>,
}

struct MacChildLifecycleShared {
    pid: Pid,
    terminate: AtomicBool,
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
    fn start(pid: Pid) -> Result<Self, SessionTransportError> {
        let shared = Arc::new(MacChildLifecycleShared {
            pid,
            terminate: AtomicBool::new(false),
            state: Mutex::new(MacChildLifecycleState {
                reaped: false,
                last_error: None,
                #[cfg(test)]
                exit_status: None,
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

    #[cfg(test)]
    pub(super) fn exited_successfully_for_test(&self) -> bool {
        lock_lifecycle(&self.shared.state).exit_status == Some(0)
    }

    pub(super) fn terminate_and_reap(
        &self,
        deadline: AbsoluteDeadline,
    ) -> Result<(), SessionTransportError> {
        self.request_termination();
        let mut state = lock_lifecycle(&self.shared.state);
        loop {
            if state.reaped {
                return Ok(());
            }
            if let Some(error) = state.last_error {
                return Err(SessionTransportError::Native(Some(error)));
            }
            let remaining = deadline.remaining();
            if remaining.is_zero() {
                return Err(SessionTransportError::DeadlineExpired);
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

impl Drop for MacChildLifecycle {
    fn drop(&mut self) {
        self.request_termination();
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
    pending_entries: Vec<ManifestEntry>,
    channel_id: u64,
    next_transfer_id: u64,
    poisoned: bool,
}

impl ChildChannel {
    /// Connects using the injected special port and authenticated environment.
    pub fn connect_from_environment() -> Result<Self, BootstrapError> {
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
        )?;
        Ok(Self {
            _parent_send: SendRight(parent),
            receive,
            nonce,
            parent_pid,
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
            let right = receive_port(&self.receive, &self.nonce, self.parent_pid, &transcript)?;
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
            )?;
            drop(receive_port(
                &self.receive,
                &self.nonce,
                self.parent_pid,
                &manifest.encode(COMMIT_MAGIC),
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
    // SAFETY: complete initialized message buffer is live for bounded send.
    mach("mach_msg(send)", unsafe {
        mach_msg(
            &mut message.header,
            MACH_SEND_MSG | MACH_SEND_TIMEOUT,
            size_of::<PortMessage>() as u32,
            0,
            MACH_PORT_NULL,
            TIMEOUT_MS,
            MACH_PORT_NULL,
        )
    })
}

fn receive_port(
    receive: &ReceiveRight,
    nonce: &[u8; 32],
    expected_pid: u32,
    expected_transcript: &[u8; CONTROL_FRAME_LEN],
) -> Result<SendRight, BootstrapError> {
    // SAFETY: zero is valid initialization for receive buffer/out descriptor.
    let mut buffer: ReceiveBuffer = unsafe { zeroed() };
    // SAFETY: receive buffer is sized for message plus requested audit trailer.
    mach("mach_msg(receive)", unsafe {
        mach_msg(
            &mut buffer.message.header,
            MACH_RCV_MSG | MACH_RCV_TIMEOUT | MACH_RCV_TRAILER_AUDIT,
            0,
            size_of::<ReceiveBuffer>() as u32,
            receive.0,
            TIMEOUT_MS,
            MACH_PORT_NULL,
        )
    })?;
    let complex = buffer.message.header.bits & MACH_MSGH_BITS_COMPLEX != 0;
    if buffer.message.header.size as usize != size_of::<PortMessage>()
        || !complex
        || buffer.message.header.id != MESSAGE_ID
        || buffer.message.body.descriptor_count != 1
        || buffer.message.descriptor.descriptor_type != MACH_MSG_PORT_DESCRIPTOR
        || buffer.message.descriptor.disposition != MACH_MSG_TYPE_PORT_SEND
        || buffer.message.magic != MESSAGE_MAGIC
        || buffer.message.nonce != *nonce
        || buffer.message.transcript != *expected_transcript
        || buffer.message.descriptor.name == MACH_PORT_NULL
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
        deallocate_port(current_task(), buffer.message.descriptor.name);
        return Err(BootstrapError::WrongPeer {
            expected: expected_pid,
            actual,
        });
    }
    Ok(SendRight(buffer.message.descriptor.name))
}

struct ReceivedVnextRecord {
    kind: VnextRecordKind,
    bytes: Vec<u8>,
    rights: Vec<SendRight>,
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
    parse_vnext_message(bytes, receive.0, nonce, expected_pid, maximum)
}

fn parse_vnext_message(
    bytes: &mut [u8],
    expected_receive: MachPort,
    nonce: &[u8; 32],
    expected_pid: u32,
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

fn lock_lifecycle(
    state: &Mutex<MacChildLifecycleState>,
) -> std::sync::MutexGuard<'_, MacChildLifecycleState> {
    match state.lock() {
        Ok(state) => state,
        Err(poisoned) => poisoned.into_inner(),
    }
}

fn mac_child_reaper(shared: Arc<MacChildLifecycleShared>) {
    let mut signal_attempted = false;
    loop {
        if shared.terminate.load(Ordering::Acquire) && !signal_attempted {
            signal_attempted = true;
            // SAFETY: this worker is the durable owner of the exact spawned PID.
            let result = unsafe { kill(shared.pid, 9) };
            if result != 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() != Some(3) {
                    let mut state = lock_lifecycle(&shared.state);
                    state.last_error = error.raw_os_error();
                    shared.changed.notify_all();
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
        let result = unsafe { waitpid(shared.pid, &mut status, WNOHANG) };
        if result == shared.pid {
            let mut state = lock_lifecycle(&shared.state);
            state.reaped = true;
            #[cfg(test)]
            {
                state.exit_status = Some(status);
            }
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

fn random_nonce() -> Result<[u8; 32], BootstrapError> {
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
