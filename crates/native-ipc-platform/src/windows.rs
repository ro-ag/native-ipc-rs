//! Windows unnamed-section mappings, pipe identity, and Job containment.

use std::ffi::{OsStr, OsString};
use std::fmt;
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr::NonNull;
use std::time::{Duration, Instant};

use native_ipc_core::layout::{RegionSetLayout, ValidatedRegionLayout, ValidationExpectations};
use native_ipc_core::mapping::{
    BindingError, ReadOnlyMapping, ReaderRegion, SoleWriterMapping, WriterRegion,
};
use windows_sys::Win32::Foundation::{
    CloseHandle, DuplicateHandle, ERROR_NO_DATA, ERROR_PIPE_CONNECTED, ERROR_PIPE_LISTENING,
    GENERIC_READ, GENERIC_WRITE, GetLastError, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
    WAIT_TIMEOUT,
};
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, OPEN_EXISTING, PIPE_ACCESS_DUPLEX, ReadFile,
    WriteFile,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
    SetInformationJobObject,
};
use windows_sys::Win32::System::Memory::{
    CreateFileMappingW, FILE_MAP_READ, FILE_MAP_WRITE, MEMORY_MAPPED_VIEW_ADDRESS, MapViewOfFile,
    PAGE_READWRITE, SEC_COMMIT, UnmapViewOfFile,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, GetNamedPipeServerProcessId,
    PIPE_NOWAIT, PIPE_READMODE_MESSAGE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_MESSAGE,
    SetNamedPipeHandleState,
};
use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
use windows_sys::Win32::System::Threading::{
    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessW, GetCurrentProcess,
    GetCurrentProcessId, GetExitCodeProcess, PROCESS_INFORMATION, ResumeThread, STARTUPINFOW,
    TerminateProcess, WaitForSingleObject,
};

use crate::BackendStatus;
use crate::protocol::{CONTROL_FRAME_LEN, ManifestEntry, PeerAccess, TransferManifest};

/// Windows section, bootstrap, lifecycle, or binding failure.
#[derive(Debug)]
pub enum WindowsError {
    /// Win32 API failed with a captured `GetLastError` value.
    Os {
        /// Bounded Win32 operation name.
        operation: &'static str,
        /// Captured `GetLastError` value.
        code: u32,
    },
    /// Mapping size is zero or cannot be page-rounded.
    InvalidSize(usize),
    /// Named-pipe peer PID differs from the held expected process.
    WrongPeer,
    /// Received or duplicated handle is invalid for this process.
    InvalidHandle,
    /// Quiescent layout validation failed.
    Layout(native_ipc_core::layout::LayoutError),
    /// Audited core binding failed.
    Binding(BindingError),
    /// Bootstrap environment or authenticated handshake was malformed.
    InvalidBootstrap,
    /// A sole-writer capability was already duplicated from this preparation.
    CapabilityAlreadyTransferred,
    /// A bounded bootstrap or lifecycle operation reached its deadline.
    TimedOut(&'static str),
    /// The exact helper exited unsuccessfully.
    ChildExit(u32),
}

impl fmt::Display for WindowsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Windows transport failed: {self:?}")
    }
}
impl std::error::Error for WindowsError {}
impl From<native_ipc_core::layout::LayoutError> for WindowsError {
    fn from(value: native_ipc_core::layout::LayoutError) -> Self {
        Self::Layout(value)
    }
}
impl From<BindingError> for WindowsError {
    fn from(value: BindingError) -> Self {
        Self::Binding(value)
    }
}

/// Generates a nonzero 256-bit bootstrap nonce from the system RNG.
pub fn session_nonce() -> Result<[u8; 32], WindowsError> {
    let mut nonce = [0_u8; 32];
    // SAFETY: output buffer is valid; null algorithm selects system-preferred RNG.
    let status = unsafe {
        BCryptGenRandom(
            std::ptr::null_mut(),
            nonce.as_mut_ptr(),
            nonce.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status < 0 || nonce == [0; 32] {
        Err(last_os("BCryptGenRandom"))
    } else {
        Ok(nonce)
    }
}

/// Verifies the connected client of a private named-pipe server instance.
///
/// # Safety
///
/// `pipe` must be a live connected named-pipe server handle owned by the caller.
pub unsafe fn authenticate_pipe_client(
    pipe: HANDLE,
    expected_pid: u32,
) -> Result<(), WindowsError> {
    let mut actual = 0;
    // SAFETY: caller supplies a live pipe and output pointer is valid.
    if unsafe { GetNamedPipeClientProcessId(pipe, &mut actual) } == 0 {
        return Err(last_os("GetNamedPipeClientProcessId"));
    }
    if actual == expected_pid {
        Ok(())
    } else {
        Err(WindowsError::WrongPeer)
    }
}

/// Verifies the connected server of a private named-pipe client instance.
///
/// # Safety
///
/// `pipe` must be a live connected named-pipe client handle owned by the caller.
pub unsafe fn authenticate_pipe_server(
    pipe: HANDLE,
    expected_pid: u32,
) -> Result<(), WindowsError> {
    let mut actual = 0;
    // SAFETY: caller supplies a live pipe and output pointer is valid.
    if unsafe { GetNamedPipeServerProcessId(pipe, &mut actual) } == 0 {
        return Err(last_os("GetNamedPipeServerProcessId"));
    }
    if actual == expected_pid {
        Ok(())
    } else {
        Err(WindowsError::WrongPeer)
    }
}

/// Quiescent unnamed paging-file section and exclusive initialization view.
pub struct QuiescentRegion {
    section: OwnedHandle,
    view: View,
    logical_len: usize,
}

impl QuiescentRegion {
    /// Allocates a page-rounded unnamed, non-executable section.
    pub fn new(logical_len: usize) -> Result<Self, WindowsError> {
        let len = page_align(logical_len)?;
        let size = len as u64;
        // SAFETY: paging-file sentinel, null security/name, and checked size are valid.
        let section = unsafe {
            CreateFileMappingW(
                INVALID_HANDLE_VALUE,
                std::ptr::null(),
                PAGE_READWRITE | SEC_COMMIT,
                (size >> 32) as u32,
                size as u32,
                std::ptr::null(),
            )
        };
        let section = OwnedHandle::new(section)?;
        let view = View::map(section.0, len, FILE_MAP_WRITE)?;
        // SAFETY: newly created unnamed section view is exclusive and writable.
        unsafe { std::slice::from_raw_parts_mut(view.base.as_ptr(), len) }.fill(0);
        Ok(Self {
            section,
            view,
            logical_len,
        })
    }
    /// Exact page-rounded capability size.
    pub const fn len(&self) -> usize {
        self.view.len
    }
    /// Returns whether the capability is empty (always false for valid values).
    pub const fn is_empty(&self) -> bool {
        false
    }
    /// Requested logical layout length.
    pub const fn logical_len(&self) -> usize {
        self.logical_len
    }
    /// Full quiescent initialization range.
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: no duplicated handle or second view exists in this typestate.
        unsafe { std::slice::from_raw_parts(self.view.base.as_ptr(), self.view.len) }
    }
    /// Mutable full quiescent initialization range.
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: `&mut self` and typestate provide exclusivity.
        unsafe { std::slice::from_raw_parts_mut(self.view.base.as_ptr(), self.view.len) }
    }

    /// Validates a future local-writer region before attenuated duplication.
    pub fn prepare_local_writer(
        self,
        expected: ValidationExpectations,
        topology: RegionSetLayout,
    ) -> Result<PreparedLocalWriter, WindowsError> {
        // SAFETY: section is quiescent and complete capability range is borrowed.
        let layout =
            unsafe { ValidatedRegionLayout::validate(self.as_bytes(), expected, &topology) }?;
        let len = self.view.len;
        let entry = ManifestEntry::validated(expected, len, PeerAccess::ReadOnly)
            .ok_or(WindowsError::InvalidBootstrap)?;
        Ok(PreparedLocalWriter {
            section: self.section,
            runtime: WriterRegion::new(WindowsWriterMapping { view: self.view }, layout, topology)?,
            entry,
            len,
            reader_duplicated: false,
        })
    }

    /// Validates a future remote-writer region before remapping local read-only.
    pub fn prepare_remote_writer(
        self,
        expected: ValidationExpectations,
        topology: RegionSetLayout,
    ) -> Result<PreparedRemoteWriter, WindowsError> {
        // SAFETY: section is quiescent and complete capability range is borrowed.
        let layout =
            unsafe { ValidatedRegionLayout::validate(self.as_bytes(), expected, &topology) }?;
        let len = self.view.len;
        drop(self.view);
        let view = View::map(self.section.0, len, FILE_MAP_READ)?;
        let entry = ManifestEntry::validated(expected, len, PeerAccess::SoleWriter)
            .ok_or(WindowsError::InvalidBootstrap)?;
        Ok(PreparedRemoteWriter {
            section: self.section,
            runtime: ReaderRegion::new(WindowsReaderMapping { view }, layout, topology)?,
            entry,
            len,
            writer_duplicated: false,
        })
    }
}

/// Target-process handle value produced by exact-rights duplication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteHandle(pub usize);

/// Local unique writer awaiting a read-only peer handle and READY barrier.
///
/// ```compile_fail
/// use native_ipc_platform::windows::PreparedLocalWriter;
/// fn publish_early(mut pending: PreparedLocalWriter) {
///     pending.publish(0, 1, None, b"too early").unwrap();
/// }
/// ```
pub struct PreparedLocalWriter {
    section: OwnedHandle,
    runtime: WriterRegion<WindowsWriterMapping>,
    entry: ManifestEntry,
    len: usize,
    reader_duplicated: bool,
}
impl PreparedLocalWriter {
    /// Duplicates exactly `FILE_MAP_READ` into a held authenticated target process.
    ///
    /// # Safety
    ///
    /// `target_process` must be the held live process authenticated by the pipe.
    unsafe fn duplicate_reader_to(
        &mut self,
        target_process: HANDLE,
    ) -> Result<RemoteHandle, WindowsError> {
        if self.reader_duplicated {
            return Err(WindowsError::CapabilityAlreadyTransferred);
        }
        let handle = duplicate_to(self.section.0, target_process, FILE_MAP_READ)?;
        self.reader_duplicated = true;
        Ok(handle)
    }
}

/// Local read-only view awaiting the sole remote-writer handle and READY barrier.
pub struct PreparedRemoteWriter {
    section: OwnedHandle,
    runtime: ReaderRegion<WindowsReaderMapping>,
    entry: ManifestEntry,
    len: usize,
    writer_duplicated: bool,
}
impl PreparedRemoteWriter {
    /// Duplicates exactly one `FILE_MAP_WRITE` handle into a held authenticated target.
    ///
    /// # Safety
    ///
    /// `target_process` must be the held live process authenticated by the pipe.
    unsafe fn duplicate_writer_to(
        &mut self,
        target_process: HANDLE,
    ) -> Result<RemoteHandle, WindowsError> {
        if self.writer_duplicated {
            return Err(WindowsError::CapabilityAlreadyTransferred);
        }
        let handle = duplicate_to(self.section.0, target_process, FILE_MAP_WRITE)?;
        self.writer_duplicated = true;
        Ok(handle)
    }
}

/// Validated imported reader withheld until the creator acknowledges READY.
///
/// ```compile_fail
/// use native_ipc_platform::windows::PendingImportedReader;
/// fn read_early(pending: PendingImportedReader) {
///     let _ = pending.copy_payload(0, 1);
/// }
/// ```
pub struct PendingImportedReader {
    runtime: ReaderRegion<WindowsReaderMapping>,
    entry: ManifestEntry,
}

/// Validated imported writer withheld until the creator acknowledges READY.
pub struct PendingImportedWriter {
    runtime: WriterRegion<WindowsWriterMapping>,
    entry: ManifestEntry,
}

/// Imports a duplicated section handle using an exact desired mapping access.
///
/// # Safety
///
/// `handle` must have arrived over the authenticated bootstrap, be owned by this
/// process, have exactly the manifest rights, and not have been previously closed.
pub unsafe fn import_reader(
    handle: usize,
    len: usize,
    expected: ValidationExpectations,
    topology: RegionSetLayout,
) -> Result<PendingImportedReader, WindowsError> {
    let section = OwnedHandle::new(handle as HANDLE)?;
    let view = View::map(section.0, len, FILE_MAP_READ)?;
    // SAFETY: READY protocol keeps view quiescent; access is read-only.
    let bytes = unsafe { std::slice::from_raw_parts(view.base.as_ptr(), len) };
    let layout = unsafe { ValidatedRegionLayout::validate(bytes, expected, &topology) }?;
    let entry = ManifestEntry::validated(expected, len, PeerAccess::ReadOnly)
        .ok_or(WindowsError::InvalidBootstrap)?;
    drop(section);
    Ok(PendingImportedReader {
        runtime: ReaderRegion::new(WindowsReaderMapping { view }, layout, topology)?,
        entry,
    })
}

/// Imports the sole duplicated writer handle.
///
/// # Safety
///
/// Same authenticated ownership requirements as [`import_reader`], plus the
/// manifest/creator must guarantee no other writable handle or view exists.
pub unsafe fn import_writer(
    handle: usize,
    len: usize,
    expected: ValidationExpectations,
    topology: RegionSetLayout,
) -> Result<PendingImportedWriter, WindowsError> {
    let section = OwnedHandle::new(handle as HANDLE)?;
    let view = View::map(section.0, len, FILE_MAP_WRITE)?;
    // SAFETY: READY protocol keeps the sole writer quiescent during validation.
    let bytes = unsafe { std::slice::from_raw_parts(view.base.as_ptr(), len) };
    let layout = unsafe { ValidatedRegionLayout::validate(bytes, expected, &topology) }?;
    let entry = ManifestEntry::validated(expected, len, PeerAccess::SoleWriter)
        .ok_or(WindowsError::InvalidBootstrap)?;
    drop(section);
    Ok(PendingImportedWriter {
        runtime: WriterRegion::new(WindowsWriterMapping { view }, layout, topology)?,
        entry,
    })
}

/// Kill-on-last-handle Job Object used to contain an exact spawned helper tree.
pub struct ChildJob(OwnedHandle);
impl ChildJob {
    /// Creates an unnamed non-inheritable kill-on-close job.
    pub fn new() -> Result<Self, WindowsError> {
        // SAFETY: null security/name create an unnamed non-inheritable job.
        let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        let handle = OwnedHandle::new(handle)?;
        let mut information: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
        information.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: buffer type/size match the requested information class.
        if unsafe {
            SetInformationJobObject(
                handle.0,
                JobObjectExtendedLimitInformation,
                (&information as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        } == 0
        {
            return Err(last_os("SetInformationJobObject"));
        }
        Ok(Self(handle))
    }
    /// Assigns a still-suspended exact child before any untrusted code runs.
    ///
    /// # Safety
    ///
    /// `process` must be the live suspended child handle returned by CreateProcess.
    pub unsafe fn assign_suspended(&self, process: HANDLE) -> Result<(), WindowsError> {
        // SAFETY: caller proves process handle/lifecycle; job handle is live.
        if unsafe { AssignProcessToJobObject(self.0.0, process) } == 0 {
            Err(last_os("AssignProcessToJobObject"))
        } else {
            Ok(())
        }
    }
}

const PIPE_ENV: &str = "NATIVE_IPC_WINDOWS_PIPE";
const NONCE_ENV: &str = "NATIVE_IPC_WINDOWS_NONCE";
const PARENT_ENV: &str = "NATIVE_IPC_PARENT_PID";
const BOOTSTRAP_MAGIC: [u8; 8] = *b"NIPCWIN1";
const AUTH_MAGIC: [u8; 8] = *b"NIPCAUT1";
const READY_MAGIC: [u8; 8] = *b"NIPCRDY1";
const COMMIT_MAGIC: [u8; 8] = *b"NIPCCMT1";
const CAPABILITY_MAGIC: [u8; 8] = *b"NIPCCAP1";
#[cfg(not(test))]
const WAIT_MS: u32 = 10_000;
#[cfg(test)]
const WAIT_MS: u32 = 1_000;

#[repr(C)]
#[derive(Clone, Copy)]
struct BootstrapFrame {
    magic: [u8; 8],
    nonce: [u8; 32],
    parent_pid: u32,
    child_pid: u32,
}

const CAPABILITY_FRAME_LEN: usize = 40 + CONTROL_FRAME_LEN;

fn encode_capability_frame(
    reader: RemoteHandle,
    reader_len: usize,
    writer: RemoteHandle,
    writer_len: usize,
    transcript: &[u8; CONTROL_FRAME_LEN],
) -> Result<[u8; CAPABILITY_FRAME_LEN], WindowsError> {
    let mut frame = [0_u8; CAPABILITY_FRAME_LEN];
    frame[..8].copy_from_slice(&CAPABILITY_MAGIC);
    frame[8..16].copy_from_slice(
        &u64::try_from(reader.0)
            .map_err(|_| WindowsError::InvalidBootstrap)?
            .to_le_bytes(),
    );
    frame[16..24].copy_from_slice(
        &u64::try_from(writer.0)
            .map_err(|_| WindowsError::InvalidBootstrap)?
            .to_le_bytes(),
    );
    frame[24..32].copy_from_slice(
        &u64::try_from(reader_len)
            .map_err(|_| WindowsError::InvalidBootstrap)?
            .to_le_bytes(),
    );
    frame[32..40].copy_from_slice(
        &u64::try_from(writer_len)
            .map_err(|_| WindowsError::InvalidBootstrap)?
            .to_le_bytes(),
    );
    frame[40..].copy_from_slice(transcript);
    Ok(frame)
}

/// Parent-owned exact helper, private pipe, process handle, and kill-on-close job.
pub struct ChildSession {
    pipe: OwnedHandle,
    process: OwnedHandle,
    _job: ChildJob,
    pid: u32,
    nonce: [u8; 32],
    reaped: bool,
    next_transfer_id: u64,
    pending_manifest: Option<TransferManifest>,
}

impl ChildSession {
    /// Creates a one-instance local pipe and launches the helper suspended.
    pub fn spawn(path: &Path, arguments: &[OsString]) -> Result<Self, WindowsError> {
        let nonce = session_nonce()?;
        let name = format!(r"\\.\pipe\native-ipc-{}", hex(&nonce));
        let pipe_name = wide_null(OsStr::new(&name));
        // SAFETY: name is terminated; null security creates a non-inheritable handle.
        let pipe = unsafe {
            CreateNamedPipeW(
                pipe_name.as_ptr(),
                PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
                PIPE_TYPE_MESSAGE
                    | PIPE_READMODE_MESSAGE
                    | PIPE_NOWAIT
                    | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                4096,
                4096,
                WAIT_MS,
                std::ptr::null(),
            )
        };
        let pipe = OwnedHandle::new(pipe)?;
        let job = ChildJob::new()?;

        let application = wide_null(path.as_os_str());
        let mut command = command_line(path.as_os_str(), arguments);
        let parent_pid = unsafe { GetCurrentProcessId() };
        let environment = environment_block(&[
            (PIPE_ENV, name),
            (NONCE_ENV, hex(&nonce)),
            (PARENT_ENV, parent_pid.to_string()),
        ]);
        let mut startup: STARTUPINFOW = unsafe { zeroed() };
        startup.cb = size_of::<STARTUPINFOW>() as u32;
        let mut information: PROCESS_INFORMATION = unsafe { zeroed() };
        // SAFETY: all UTF-16 buffers and output structures remain live; no handles inherit.
        if unsafe {
            CreateProcessW(
                application.as_ptr(),
                command.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                0,
                CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT,
                environment.as_ptr().cast(),
                std::ptr::null(),
                &startup,
                &mut information,
            )
        } == 0
        {
            return Err(last_os("CreateProcessW"));
        }
        let process = OwnedHandle::new(information.hProcess)?;
        let thread = OwnedHandle::new(information.hThread)?;
        // SAFETY: CreateProcessW returned this exact child still suspended.
        if let Err(error) = unsafe { job.assign_suspended(process.0) } {
            // SAFETY: exact held child is still suspended.
            let _ = unsafe { TerminateProcess(process.0, 127) };
            return Err(error);
        }
        // SAFETY: thread is the exact suspended primary thread.
        if unsafe { ResumeThread(thread.0) } == u32::MAX {
            let error = last_os("ResumeThread");
            let _ = unsafe { TerminateProcess(process.0, 127) };
            return Err(error);
        }
        drop(thread);
        connect_pipe(pipe.0, process.0)?;
        // SAFETY: the server pipe is connected and the expected PID is held live.
        unsafe { authenticate_pipe_client(pipe.0, information.dwProcessId)? };
        let hello = BootstrapFrame {
            magic: BOOTSTRAP_MAGIC,
            nonce,
            parent_pid,
            child_pid: information.dwProcessId,
        };
        write_frame(pipe.0, &hello)?;
        let ready = read_frame(pipe.0)?;
        if ready.magic != AUTH_MAGIC
            || ready.nonce != nonce
            || ready.parent_pid != parent_pid
            || ready.child_pid != information.dwProcessId
        {
            let _ = unsafe { TerminateProcess(process.0, 127) };
            return Err(WindowsError::InvalidBootstrap);
        }
        Ok(Self {
            pipe,
            process,
            _job: job,
            pid: information.dwProcessId,
            nonce,
            reaped: false,
            next_transfer_id: 1,
            pending_manifest: None,
        })
    }

    /// Exact live process handle used only for attenuated handle duplication.
    pub const fn process_handle(&self) -> HANDLE {
        self.process.0
    }
    /// Kernel-created child process ID authenticated on the private pipe.
    pub const fn pid(&self) -> u32 {
        self.pid
    }
    /// Sends the two exact-rights handle values and their complete mapped lengths.
    fn send_capabilities(
        &mut self,
        reader_handle: RemoteHandle,
        reader: &PreparedLocalWriter,
        writer_handle: RemoteHandle,
        remote_writer: &PreparedRemoteWriter,
    ) -> Result<(), WindowsError> {
        if self.pending_manifest.is_some() {
            return Err(WindowsError::InvalidBootstrap);
        }
        let manifest = TransferManifest::new(
            self.nonce,
            unsafe { GetCurrentProcessId() },
            self.pid,
            self.next_transfer_id,
            vec![reader.entry, remote_writer.entry],
        )
        .ok_or(WindowsError::InvalidBootstrap)?;
        let frame = encode_capability_frame(
            reader_handle,
            reader.len,
            writer_handle,
            remote_writer.len,
            &manifest.encode(CAPABILITY_MAGIC),
        )?;
        write_pod(self.pipe.0, &frame)?;
        self.pending_manifest = Some(manifest);
        Ok(())
    }
    /// Consumes prepared mappings after authenticated READY and sends COMMIT.
    ///
    /// This method owns capability duplication, the remote-handle cleanup
    /// ledger, exact manifest transfer, READY validation, and COMMIT. It returns
    /// `(local_writer, local_reader)` only after successful COMMIT.
    ///
    /// # Errors
    ///
    /// Returns an error for duplication, pipe, transcript, timeout, or process
    /// failures. Ambiguous failure terminates and reaps the exact held child.
    ///
    /// ```compile_fail
    /// use native_ipc_platform::windows::{
    ///     ChildSession, PreparedLocalWriter, PreparedRemoteWriter,
    /// };
    /// fn commit_twice(
    ///     session: &mut ChildSession,
    ///     writer: PreparedLocalWriter,
    ///     reader: PreparedRemoteWriter,
    /// ) {
    ///     let _ = session.commit_transfers(writer, reader);
    ///     let _ = session.commit_transfers(writer, reader);
    /// }
    /// ```
    pub fn commit_transfers(
        &mut self,
        writer: PreparedLocalWriter,
        reader: PreparedRemoteWriter,
    ) -> Result<
        (
            WriterRegion<WindowsWriterMapping>,
            ReaderRegion<WindowsReaderMapping>,
        ),
        WindowsError,
    > {
        let result = self.commit_transfers_inner(writer, reader);
        if result.is_err() {
            self.abort_child();
        }
        result
    }

    fn commit_transfers_inner(
        &mut self,
        mut writer: PreparedLocalWriter,
        mut reader: PreparedRemoteWriter,
    ) -> Result<
        (
            WriterRegion<WindowsWriterMapping>,
            ReaderRegion<WindowsReaderMapping>,
        ),
        WindowsError,
    > {
        // SAFETY: this session owns the exact authenticated live child handle.
        let reader_handle = unsafe { writer.duplicate_reader_to(self.process.0)? };
        // SAFETY: same held child; the preparation enforces one writer duplicate.
        let writer_handle = unsafe { reader.duplicate_writer_to(self.process.0)? };
        self.send_capabilities(reader_handle, &writer, writer_handle, &reader)?;
        let manifest = self
            .pending_manifest
            .as_ref()
            .ok_or(WindowsError::InvalidBootstrap)?;
        let ready: [u8; CONTROL_FRAME_LEN] = read_pod(self.pipe.0)?;
        if !manifest.matches_frame(READY_MAGIC, &ready) {
            return Err(WindowsError::InvalidBootstrap);
        }
        write_pod(self.pipe.0, &manifest.encode(COMMIT_MAGIC))?;
        drop(writer.section);
        drop(reader.section);
        self.pending_manifest = None;
        self.next_transfer_id = self
            .next_transfer_id
            .checked_add(1)
            .ok_or(WindowsError::InvalidBootstrap)?;
        Ok((writer.runtime, reader.runtime))
    }

    fn abort_child(&mut self) {
        if !self.reaped {
            // SAFETY: this session owns the exact authenticated child handle.
            let _ = unsafe { TerminateProcess(self.process.0, 127) };
            // SAFETY: same held process; bounded wait completes cleanup.
            let _ = unsafe { WaitForSingleObject(self.process.0, WAIT_MS) };
            self.reaped = true;
        }
    }
    /// Waits for a normal helper exit after protocol completion.
    pub fn wait(mut self) -> Result<(), WindowsError> {
        // SAFETY: process is held live for this session.
        match unsafe { WaitForSingleObject(self.process.0, WAIT_MS) } {
            WAIT_OBJECT_0 => {
                let mut code = 0;
                // SAFETY: held process is signaled and output pointer is valid.
                if unsafe { GetExitCodeProcess(self.process.0, &mut code) } == 0 {
                    return Err(last_os("GetExitCodeProcess"));
                }
                if code != 0 {
                    return Err(WindowsError::ChildExit(code));
                }
            }
            WAIT_TIMEOUT => return Err(WindowsError::TimedOut("helper exit")),
            _ => return Err(last_os("WaitForSingleObject")),
        }
        self.reaped = true;
        Ok(())
    }
}

impl Drop for ChildSession {
    fn drop(&mut self) {
        if !self.reaped {
            // SAFETY: exact held child; job close remains the backstop for descendants.
            let _ = unsafe { TerminateProcess(self.process.0, 127) };
            let _ = unsafe { WaitForSingleObject(self.process.0, WAIT_MS) };
        }
    }
}

/// Connects a spawned helper from its authenticated bootstrap environment.
pub fn connect_spawned_helper() -> Result<ChildChannel, WindowsError> {
    let name = std::env::var_os(PIPE_ENV).ok_or(WindowsError::InvalidBootstrap)?;
    let nonce =
        parse_nonce(&std::env::var(NONCE_ENV).map_err(|_| WindowsError::InvalidBootstrap)?)?;
    let parent_pid = std::env::var(PARENT_ENV)
        .map_err(|_| WindowsError::InvalidBootstrap)?
        .parse::<u32>()
        .map_err(|_| WindowsError::InvalidBootstrap)?;
    let name = wide_null(&name);
    // SAFETY: terminated name; no sharing or inheritance and existing pipe only.
    let pipe = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };
    let pipe = OwnedHandle::new(pipe)?;
    let mode = PIPE_READMODE_MESSAGE | PIPE_NOWAIT;
    // SAFETY: connected client pipe and mode pointer are valid.
    if unsafe { SetNamedPipeHandleState(pipe.0, &mode, std::ptr::null(), std::ptr::null()) } == 0 {
        return Err(last_os("SetNamedPipeHandleState"));
    }
    // SAFETY: connected pipe client and exact expected parent from spawn environment.
    unsafe { authenticate_pipe_server(pipe.0, parent_pid)? };
    let hello = read_frame(pipe.0)?;
    let child_pid = unsafe { GetCurrentProcessId() };
    if hello.magic != BOOTSTRAP_MAGIC
        || hello.nonce != nonce
        || hello.parent_pid != parent_pid
        || hello.child_pid != child_pid
    {
        return Err(WindowsError::InvalidBootstrap);
    }
    write_frame(
        pipe.0,
        &BootstrapFrame {
            magic: AUTH_MAGIC,
            ..hello
        },
    )?;
    Ok(ChildChannel {
        pipe,
        parent_pid,
        nonce,
        next_transfer_id: 1,
        pending_transcript: None,
    })
}

/// Authenticated child endpoint retained for the lifetime of imported capabilities.
pub struct ChildChannel {
    pipe: OwnedHandle,
    parent_pid: u32,
    nonce: [u8; 32],
    next_transfer_id: u64,
    pending_transcript: Option<[u8; CONTROL_FRAME_LEN]>,
}
impl ChildChannel {
    /// Held authenticated parent PID.
    pub const fn parent_pid(&self) -> u32 {
        self.parent_pid
    }
    /// Raw pipe handle for a bounded manifest protocol owned by the caller.
    pub const fn pipe_handle(&self) -> HANDLE {
        self.pipe.0
    }
    /// Receives exact-rights handle values only after pipe PID authentication.
    ///
    /// The tuple is `(reader_handle, reader_len, writer_handle, writer_len)`.
    /// Lengths are exact page-rounded capability sizes. Handles remain pending
    /// and must be imported and passed to [`Self::commit_imports`].
    ///
    /// # Errors
    ///
    /// Returns an error for duplicate receipt, timeout, truncated or oversized
    /// frames, invalid fixed-width values, or a malformed capability envelope.
    pub fn receive_capabilities(
        &mut self,
    ) -> Result<(RemoteHandle, usize, RemoteHandle, usize), WindowsError> {
        if self.pending_transcript.is_some() {
            return Err(WindowsError::InvalidBootstrap);
        }
        let frame: [u8; CAPABILITY_FRAME_LEN] = read_pod(self.pipe.0)?;
        if frame[..8] != CAPABILITY_MAGIC {
            return Err(WindowsError::InvalidBootstrap);
        }
        let reader_handle = usize::try_from(u64::from_le_bytes(
            frame[8..16].try_into().expect("fixed range"),
        ))
        .map_err(|_| WindowsError::InvalidBootstrap)?;
        let writer_handle = usize::try_from(u64::from_le_bytes(
            frame[16..24].try_into().expect("fixed range"),
        ))
        .map_err(|_| WindowsError::InvalidBootstrap)?;
        let reader_len = usize::try_from(u64::from_le_bytes(
            frame[24..32].try_into().expect("fixed range"),
        ))
        .map_err(|_| WindowsError::InvalidBootstrap)?;
        let writer_len = usize::try_from(u64::from_le_bytes(
            frame[32..40].try_into().expect("fixed range"),
        ))
        .map_err(|_| WindowsError::InvalidBootstrap)?;
        if reader_handle == 0 || writer_handle == 0 || reader_len == 0 || writer_len == 0 {
            return Err(WindowsError::InvalidBootstrap);
        }
        let mut transcript = [0; CONTROL_FRAME_LEN];
        transcript.copy_from_slice(&frame[40..]);
        self.pending_transcript = Some(transcript);
        Ok((
            RemoteHandle(reader_handle),
            reader_len,
            RemoteHandle(writer_handle),
            writer_len,
        ))
    }
    /// Signals validation, waits for COMMIT, then exposes imported capabilities.
    ///
    /// Returns `(imported_reader, imported_writer)` in manifest order.
    ///
    /// # Errors
    ///
    /// Returns an error if the imported entries do not match the capability
    /// transcript, READY cannot be sent, or COMMIT is malformed or stale.
    pub fn commit_imports(
        &mut self,
        reader: PendingImportedReader,
        writer: PendingImportedWriter,
    ) -> Result<
        (
            ReaderRegion<WindowsReaderMapping>,
            WriterRegion<WindowsWriterMapping>,
        ),
        WindowsError,
    > {
        let manifest = TransferManifest::new(
            self.nonce,
            self.parent_pid,
            unsafe { GetCurrentProcessId() },
            self.next_transfer_id,
            vec![reader.entry, writer.entry],
        )
        .ok_or(WindowsError::InvalidBootstrap)?;
        let transcript = self
            .pending_transcript
            .as_ref()
            .ok_or(WindowsError::InvalidBootstrap)?;
        if !manifest.matches_frame(CAPABILITY_MAGIC, transcript) {
            return Err(WindowsError::InvalidBootstrap);
        }
        write_pod(self.pipe.0, &manifest.encode(READY_MAGIC))?;
        let commit: [u8; CONTROL_FRAME_LEN] = read_pod(self.pipe.0)?;
        if !manifest.matches_frame(COMMIT_MAGIC, &commit) {
            return Err(WindowsError::InvalidBootstrap);
        }
        self.pending_transcript = None;
        self.next_transfer_id = self
            .next_transfer_id
            .checked_add(1)
            .ok_or(WindowsError::InvalidBootstrap)?;
        Ok((reader.runtime, writer.runtime))
    }
}

/// Platform-minted unique writable unnamed-section view.
pub struct WindowsWriterMapping {
    view: View,
}
// SAFETY: constructors consume the full creator handle and retain the sole RW view.
unsafe impl SoleWriterMapping for WindowsWriterMapping {
    fn base(&self) -> NonNull<u8> {
        self.view.base
    }
    fn len(&self) -> usize {
        self.view.len
    }
}
/// Platform-minted read-only unnamed-section view.
pub struct WindowsReaderMapping {
    view: View,
}
// SAFETY: constructors map only FILE_MAP_READ and retain the view lifetime.
unsafe impl ReadOnlyMapping for WindowsReaderMapping {
    fn base(&self) -> NonNull<u8> {
        self.view.base
    }
    fn len(&self) -> usize {
        self.view.len
    }
}

struct OwnedHandle(HANDLE);
impl OwnedHandle {
    fn new(handle: HANDLE) -> Result<Self, WindowsError> {
        if handle.is_null() || handle == INVALID_HANDLE_VALUE {
            Err(WindowsError::InvalidHandle)
        } else {
            Ok(Self(handle))
        }
    }
}
impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: this value uniquely owns a real non-pseudo handle.
        let _ = unsafe { CloseHandle(self.0) };
    }
}

struct View {
    base: NonNull<u8>,
    len: usize,
}
impl View {
    fn map(section: HANDLE, len: usize, access: u32) -> Result<Self, WindowsError> {
        // SAFETY: section handle is live; access/offset/length are checked.
        let address = unsafe { MapViewOfFile(section, access, 0, 0, len) };
        let base = NonNull::new(address.Value.cast()).ok_or_else(|| last_os("MapViewOfFile"))?;
        Ok(Self { base, len })
    }
}
impl Drop for View {
    fn drop(&mut self) {
        // SAFETY: this object uniquely owns the mapped view.
        let _ = unsafe {
            UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS {
                Value: self.base.as_ptr().cast(),
            })
        };
    }
}

fn duplicate_to(source: HANDLE, target: HANDLE, access: u32) -> Result<RemoteHandle, WindowsError> {
    let mut remote: HANDLE = std::ptr::null_mut();
    // SAFETY: source/current/target handles are live; no SAME_ACCESS option is used.
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            source,
            target,
            &mut remote,
            access,
            0,
            0,
        )
    } == 0
    {
        return Err(last_os("DuplicateHandle"));
    }
    if remote.is_null() {
        Err(WindowsError::InvalidHandle)
    } else {
        Ok(RemoteHandle(remote as usize))
    }
}

fn page_align(size: usize) -> Result<usize, WindowsError> {
    if size == 0 {
        return Err(WindowsError::InvalidSize(size));
    }
    let mut information: SYSTEM_INFO = unsafe { zeroed() };
    // SAFETY: output pointer is valid.
    unsafe { GetSystemInfo(&mut information) };
    let page = information.dwPageSize as usize;
    if page == 0 || !page.is_power_of_two() {
        return Err(WindowsError::InvalidSize(size));
    }
    size.checked_add(page - 1)
        .map(|value| value & !(page - 1))
        .filter(|value| *value <= isize::MAX as usize)
        .ok_or(WindowsError::InvalidSize(size))
}

fn wide_null(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

fn quote_argument(value: &OsStr, output: &mut Vec<u16>) {
    let units: Vec<u16> = value.encode_wide().collect();
    let needs_quotes = units.is_empty()
        || units
            .iter()
            .any(|unit| *unit == b' ' as u16 || *unit == b'\t' as u16);
    if !needs_quotes {
        output.extend(units);
        return;
    }
    output.push(b'"' as u16);
    let mut slashes = 0;
    for unit in units {
        if unit == b'\\' as u16 {
            slashes += 1;
        } else if unit == b'"' as u16 {
            output.extend(std::iter::repeat_n(b'\\' as u16, slashes * 2 + 1));
            output.push(unit);
            slashes = 0;
        } else {
            output.extend(std::iter::repeat_n(b'\\' as u16, slashes));
            output.push(unit);
            slashes = 0;
        }
    }
    output.extend(std::iter::repeat_n(b'\\' as u16, slashes * 2));
    output.push(b'"' as u16);
}

fn command_line(path: &OsStr, arguments: &[OsString]) -> Vec<u16> {
    let mut result = Vec::new();
    quote_argument(path, &mut result);
    for argument in arguments {
        result.push(b' ' as u16);
        quote_argument(argument, &mut result);
    }
    result.push(0);
    result
}

fn environment_block(overrides: &[(&str, String)]) -> Vec<u16> {
    let mut values: Vec<(OsString, OsString)> = std::env::vars_os()
        .filter(|(key, _)| {
            !overrides
                .iter()
                .any(|(name, _)| key.to_string_lossy().eq_ignore_ascii_case(name))
        })
        .collect();
    values.extend(
        overrides
            .iter()
            .map(|(key, value)| (OsString::from(key), OsString::from(value))),
    );
    values.sort_by(|left, right| {
        left.0
            .to_string_lossy()
            .to_ascii_lowercase()
            .cmp(&right.0.to_string_lossy().to_ascii_lowercase())
    });
    let mut block = Vec::new();
    for (key, value) in values {
        block.extend(key.encode_wide());
        block.push(b'=' as u16);
        block.extend(value.encode_wide());
        block.push(0);
    }
    block.push(0);
    block
}

fn pod_bytes<T>(value: &T) -> &[u8] {
    // SAFETY: callers use repr(C), fully initialized integer-only protocol records.
    unsafe { std::slice::from_raw_parts((value as *const T).cast(), size_of::<T>()) }
}

fn write_frame(pipe: HANDLE, frame: &BootstrapFrame) -> Result<(), WindowsError> {
    write_pod(pipe, frame)
}

fn write_pod<T>(pipe: HANDLE, value: &T) -> Result<(), WindowsError> {
    let bytes = pod_bytes(value);
    let deadline = Instant::now() + Duration::from_millis(WAIT_MS.into());
    loop {
        let mut written = 0;
        // SAFETY: pipe is live, bytes are valid, and nonblocking operation is synchronous.
        if unsafe {
            WriteFile(
                pipe,
                bytes.as_ptr(),
                bytes.len() as u32,
                &mut written,
                std::ptr::null_mut(),
            )
        } != 0
        {
            return if written as usize == bytes.len() {
                Ok(())
            } else {
                Err(WindowsError::InvalidBootstrap)
            };
        }
        let code = unsafe { GetLastError() };
        if code != ERROR_NO_DATA && code != ERROR_PIPE_LISTENING {
            return Err(WindowsError::Os {
                operation: "WriteFile",
                code,
            });
        }
        wait_retry(deadline, "pipe write")?;
    }
}

fn read_frame(pipe: HANDLE) -> Result<BootstrapFrame, WindowsError> {
    read_pod(pipe)
}

fn read_pod<T>(pipe: HANDLE) -> Result<T, WindowsError> {
    let deadline = Instant::now() + Duration::from_millis(WAIT_MS.into());
    loop {
        let mut value: T = unsafe { zeroed() };
        let mut read = 0;
        // SAFETY: frame output range is valid and nonblocking operation is synchronous.
        if unsafe {
            ReadFile(
                pipe,
                (&mut value as *mut T).cast(),
                size_of::<T>() as u32,
                &mut read,
                std::ptr::null_mut(),
            )
        } != 0
        {
            return if read as usize == size_of::<T>() {
                Ok(value)
            } else {
                Err(WindowsError::InvalidBootstrap)
            };
        }
        let code = unsafe { GetLastError() };
        if code != ERROR_NO_DATA && code != ERROR_PIPE_LISTENING {
            return Err(WindowsError::Os {
                operation: "ReadFile",
                code,
            });
        }
        wait_retry(deadline, "pipe read")?;
    }
}

fn connect_pipe(pipe: HANDLE, process: HANDLE) -> Result<(), WindowsError> {
    let deadline = Instant::now() + Duration::from_millis(WAIT_MS.into());
    loop {
        // SAFETY: server pipe is nonblocking and no OVERLAPPED operation is requested.
        if unsafe { ConnectNamedPipe(pipe, std::ptr::null_mut()) } != 0 {
            return Ok(());
        }
        let code = unsafe { GetLastError() };
        if code == ERROR_PIPE_CONNECTED {
            return Ok(());
        }
        if code != ERROR_PIPE_LISTENING && code != ERROR_NO_DATA {
            return Err(WindowsError::Os {
                operation: "ConnectNamedPipe",
                code,
            });
        }
        // SAFETY: exact child process handle is held throughout bootstrap.
        if unsafe { WaitForSingleObject(process, 0) } == WAIT_OBJECT_0 {
            let mut exit = 0;
            // SAFETY: process is signaled and output is valid.
            if unsafe { GetExitCodeProcess(process, &mut exit) } != 0 {
                return Err(WindowsError::ChildExit(exit));
            }
            return Err(last_os("GetExitCodeProcess"));
        }
        wait_retry(deadline, "pipe connect")?;
    }
}

fn wait_retry(deadline: Instant, operation: &'static str) -> Result<(), WindowsError> {
    if Instant::now() >= deadline {
        Err(WindowsError::TimedOut(operation))
    } else {
        std::thread::sleep(Duration::from_millis(1));
        Ok(())
    }
}

fn hex(bytes: &[u8; 32]) -> String {
    let mut output = String::with_capacity(64);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("String writes are infallible");
    }
    output
}

fn parse_nonce(value: &str) -> Result<[u8; 32], WindowsError> {
    if value.len() != 64 {
        return Err(WindowsError::InvalidBootstrap);
    }
    let mut nonce = [0; 32];
    for (index, output) in nonce.iter_mut().enumerate() {
        *output = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| WindowsError::InvalidBootstrap)?;
    }
    if nonce == [0; 32] {
        return Err(WindowsError::InvalidBootstrap);
    }
    Ok(nonce)
}

fn last_os(operation: &'static str) -> WindowsError {
    // SAFETY: GetLastError has no preconditions.
    WindowsError::Os {
        operation,
        code: unsafe { GetLastError() },
    }
}

/// Reports the native backend's enforced capability policy.
pub const fn status() -> BackendStatus {
    BackendStatus::Available
}

#[cfg(test)]
mod tests {
    use super::*;
    use native_ipc_core::layout::{
        AcknowledgementRouteSpec, Endpoint, LayoutLimits, RegionSpec, RoleId,
    };
    use std::time::Duration;
    use windows_sys::Win32::System::Memory::{PAGE_EXECUTE_READWRITE, VirtualProtect};

    fn topology() -> (RegionSetLayout, RoleId, RoleId) {
        let producer = RoleId::new(1).unwrap();
        let peer = RoleId::new(2).unwrap();
        let specs = [
            RegionSpec {
                role: producer,
                writer: Endpoint::Initiator,
                slot_count: 1,
                payload_bytes: 32,
                acknowledgement_count: 1,
            },
            RegionSpec {
                role: peer,
                writer: Endpoint::Responder,
                slot_count: 1,
                payload_bytes: 32,
                acknowledgement_count: 1,
            },
        ];
        let routes = [
            AcknowledgementRouteSpec {
                owner: peer,
                target: producer,
                slot_index: 0,
                cell_index: 0,
            },
            AcknowledgementRouteSpec {
                owner: producer,
                target: peer,
                slot_index: 0,
                cell_index: 0,
            },
        ];
        let topology = RegionSetLayout::calculate(
            [7; 32],
            23,
            &specs,
            &routes,
            LayoutLimits {
                maximum_mapping_size: 1 << 20,
                maximum_slot_count: 2,
                maximum_acknowledgement_count: 2,
                maximum_payload_bytes: 64,
            },
        )
        .unwrap();
        (topology, producer, peer)
    }

    fn expected(topology: &RegionSetLayout, role: RoleId, len: usize) -> ValidationExpectations {
        let region = topology.region(role).unwrap();
        ValidationExpectations {
            schema_id: [7; 32],
            generation: 23,
            role,
            writer: region.writer(),
            maximum_mapping_size: len as u64,
        }
    }

    #[test]
    fn nonce_is_nonzero_and_job_is_constructible() {
        assert_ne!(session_nonce().unwrap(), [0; 32]);
        let _job = ChildJob::new().unwrap();
    }

    #[test]
    fn unnamed_section_is_page_rounded_and_zeroed() {
        let region = QuiescentRegion::new(37).unwrap();
        assert!(region.len() >= 37);
        assert!(region.as_bytes().iter().all(|byte| *byte == 0));
        let mut prior = 0;
        // SAFETY: the complete live view and protection output are valid.
        assert_eq!(
            unsafe {
                VirtualProtect(
                    region.view.base.as_ptr().cast(),
                    region.len(),
                    PAGE_EXECUTE_READWRITE,
                    &mut prior,
                )
            },
            0
        );
    }

    #[test]
    fn read_only_duplicate_rejects_writable_mapping() {
        let region = QuiescentRegion::new(4096).unwrap();
        let duplicate = duplicate_to(
            region.section.0,
            unsafe { GetCurrentProcess() },
            FILE_MAP_READ,
        )
        .unwrap();
        let duplicate = OwnedHandle::new(duplicate.0 as HANDLE).unwrap();
        // SAFETY: exact read-only section handle is live; the denied result is not owned.
        let denied = unsafe { MapViewOfFile(duplicate.0, FILE_MAP_WRITE, 0, 0, region.len()) };
        assert!(denied.Value.is_null());
    }

    #[test]
    fn spawned_helper_is_pid_authenticated_and_job_owned() {
        let (topology, producer, peer) = topology();
        let producer_layout = topology.region(producer).unwrap();
        let mut producer_region =
            QuiescentRegion::new(producer_layout.total_size() as usize).unwrap();
        producer_layout
            .encode_into(producer_region.as_bytes_mut())
            .unwrap();
        let producer_expected = expected(&topology, producer, producer_region.len());
        let prepared_producer = producer_region
            .prepare_local_writer(producer_expected, topology.clone())
            .unwrap();
        let peer_layout = topology.region(peer).unwrap();
        let mut peer_region = QuiescentRegion::new(peer_layout.total_size() as usize).unwrap();
        peer_layout.encode_into(peer_region.as_bytes_mut()).unwrap();
        let peer_expected = expected(&topology, peer, peer_region.len());
        let prepared_peer = peer_region
            .prepare_remote_writer(peer_expected, topology.clone())
            .unwrap();
        let executable = std::env::current_exe().unwrap();
        let arguments = [
            OsString::from("--exact"),
            OsString::from("windows::tests::spawned_helper_entry"),
            OsString::from("--ignored"),
            OsString::from("--nocapture"),
        ];
        let mut child = ChildSession::spawn(&executable, &arguments).unwrap();
        assert_ne!(child.pid(), unsafe { GetCurrentProcessId() });
        let (mut writer, reader) = child
            .commit_transfers(prepared_producer, prepared_peer)
            .unwrap();
        writer
            .publish(0, 1, None, b"cross-process-windows")
            .unwrap();
        for _ in 0..10_000 {
            if let Ok(payload) = reader.copy_payload(0, 1) {
                assert_eq!(payload, b"child-windows-writer");
                child.wait().unwrap();
                return;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        panic!("child never published payload");
    }

    #[test]
    fn helper_exit_before_connect_is_bounded() {
        let executable = std::env::current_exe().unwrap();
        let arguments = [
            OsString::from("--exact"),
            OsString::from("windows::tests::exit_before_connect_entry"),
            OsString::from("--ignored"),
        ];
        let result = ChildSession::spawn(&executable, &arguments);
        assert!(matches!(
            result,
            Err(WindowsError::ChildExit(0) | WindowsError::Os { .. })
        ));
    }

    #[test]
    fn helper_stall_before_auth_is_bounded() {
        let executable = std::env::current_exe().unwrap();
        let arguments = [
            OsString::from("--exact"),
            OsString::from("windows::tests::stall_before_auth_entry"),
            OsString::from("--ignored"),
        ];
        let result = ChildSession::spawn(&executable, &arguments);
        assert!(matches!(result, Err(WindowsError::TimedOut("pipe read"))));
    }

    #[test]
    #[ignore = "spawned only by the exact lifecycle test"]
    fn spawned_helper_entry() {
        let (topology, producer, peer) = topology();
        let mut channel = connect_spawned_helper().unwrap();
        assert_ne!(channel.parent_pid(), unsafe { GetCurrentProcessId() });
        let (reader_handle, reader_len, writer_handle, writer_len) =
            channel.receive_capabilities().unwrap();
        // SAFETY: exact handles arrived from authenticated parent on private pipe.
        let reader = unsafe {
            import_reader(
                reader_handle.0,
                reader_len,
                expected(&topology, producer, reader_len),
                topology.clone(),
            )
            .unwrap()
        };
        // SAFETY: manifest designates this exact handle as the sole writer.
        let writer = unsafe {
            import_writer(
                writer_handle.0,
                writer_len,
                expected(&topology, peer, writer_len),
                topology,
            )
            .unwrap()
        };
        let (reader, mut writer) = channel.commit_imports(reader, writer).unwrap();
        for _ in 0..10_000 {
            if let Ok(payload) = reader.copy_payload(0, 1) {
                assert_eq!(payload, b"cross-process-windows");
                writer.publish(0, 1, None, b"child-windows-writer").unwrap();
                return;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        panic!("parent never published payload");
    }

    #[test]
    #[ignore = "spawned only by the exit-before-connect lifecycle test"]
    fn exit_before_connect_entry() {}

    #[test]
    #[ignore = "spawned only by the stalled-auth lifecycle test"]
    fn stall_before_auth_entry() {
        let name = wide_null(&std::env::var_os(PIPE_ENV).unwrap());
        // SAFETY: terminated private pipe name and existing-only open are valid.
        let pipe = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                std::ptr::null(),
                OPEN_EXISTING,
                0,
                std::ptr::null_mut(),
            )
        };
        let _pipe = OwnedHandle::new(pipe).unwrap();
        std::thread::sleep(Duration::from_secs(5));
    }
}
