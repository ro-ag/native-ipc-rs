//! Private Mach bootstrap channel with audit-token process authentication.

use std::ffi::{CString, c_char, c_int, c_void};
use std::fmt;
use std::mem::{size_of, zeroed};

use super::{KERN_SUCCESS, MachPort, current_task, deallocate_port};
use crate::protocol::{
    CONTROL_FRAME_LEN, ManifestEntry, NativeRegionSpec, PeerAccess, TransferManifest,
    TransferProvenance, mint_channel_id,
};
type MachMsgReturn = c_int;
type PosixSpawnAttr = *mut c_void;

const MACH_PORT_NULL: MachPort = 0;
const MACH_PORT_RIGHT_RECEIVE: c_int = 1;
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
const TASK_BOOTSTRAP_PORT: c_int = 4;
const MESSAGE_ID: c_int = 0x4e49_5043;
const MESSAGE_MAGIC: [u8; 8] = *b"NIPCMACH";
const CAPABILITY_MAGIC: [u8; 8] = *b"NIPCCAP1";
const READY_MAGIC: [u8; 8] = *b"NIPCRDY1";
const COMMIT_MAGIC: [u8; 8] = *b"NIPCCMT1";
const ENV_NONCE: &str = "NATIVE_IPC_MACH_NONCE";
const ENV_PARENT_PID: &str = "NATIVE_IPC_PARENT_PID";
const TIMEOUT_MS: u32 = 10_000;

unsafe extern "C" {
    fn mach_port_allocate(task: MachPort, right: c_int, name: *mut MachPort) -> c_int;
    fn mach_port_insert_right(
        task: MachPort,
        name: MachPort,
        poly: MachPort,
        poly_poly: c_int,
    ) -> c_int;
    fn mach_port_mod_refs(task: MachPort, name: MachPort, right: c_int, delta: c_int) -> c_int;
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
}
impl Drop for SendRight {
    fn drop(&mut self) {
        deallocate_port(current_task(), self.0);
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

impl ParentChannel {
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
