//! Windows unnamed-section mappings, pipe identity, and Job containment.

use std::fmt;
use std::mem::{size_of, zeroed};
use std::ptr::NonNull;

use native_ipc_core::layout::{RegionSetLayout, ValidatedRegionLayout, ValidationExpectations};
use native_ipc_core::mapping::{
    BindingError, ReadOnlyMapping, ReaderRegion, SoleWriterMapping, WriterRegion,
};
use windows_sys::Win32::Foundation::{
    CloseHandle, DuplicateHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
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
use windows_sys::Win32::System::Pipes::{GetNamedPipeClientProcessId, GetNamedPipeServerProcessId};
use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

use crate::BackendStatus;

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
        Ok(PreparedLocalWriter {
            section: self.section,
            view: self.view,
            layout,
            topology,
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
        Ok(PreparedRemoteWriter {
            section: self.section,
            view,
            layout,
            topology,
        })
    }
}

/// Target-process handle value produced by exact-rights duplication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemoteHandle(pub usize);

/// Local unique writer awaiting a read-only peer handle and READY barrier.
pub struct PreparedLocalWriter {
    section: OwnedHandle,
    view: View,
    layout: ValidatedRegionLayout,
    topology: RegionSetLayout,
}
impl PreparedLocalWriter {
    /// Duplicates exactly `FILE_MAP_READ` into a held authenticated target process.
    ///
    /// # Safety
    ///
    /// `target_process` must be the held live process authenticated by the pipe.
    pub unsafe fn duplicate_reader_to(
        &self,
        target_process: HANDLE,
    ) -> Result<RemoteHandle, WindowsError> {
        duplicate_to(self.section.0, target_process, FILE_MAP_READ)
    }
    /// Closes the full section handle and commits the sole local writer.
    pub fn bind(self) -> Result<WriterRegion<WindowsWriterMapping>, WindowsError> {
        drop(self.section);
        Ok(WriterRegion::new(
            WindowsWriterMapping { view: self.view },
            self.layout,
            self.topology,
        )?)
    }
}

/// Local read-only view awaiting the sole remote-writer handle and READY barrier.
pub struct PreparedRemoteWriter {
    section: OwnedHandle,
    view: View,
    layout: ValidatedRegionLayout,
    topology: RegionSetLayout,
}
impl PreparedRemoteWriter {
    /// Duplicates exactly `FILE_MAP_WRITE` into a held authenticated target process.
    ///
    /// # Safety
    ///
    /// `target_process` must be the held live process authenticated by the pipe.
    pub unsafe fn duplicate_writer_to(
        &self,
        target_process: HANDLE,
    ) -> Result<RemoteHandle, WindowsError> {
        duplicate_to(self.section.0, target_process, FILE_MAP_WRITE)
    }
    /// Closes the full section handle and commits the local read-only witness.
    pub fn bind_reader(self) -> Result<ReaderRegion<WindowsReaderMapping>, WindowsError> {
        drop(self.section);
        Ok(ReaderRegion::new(
            WindowsReaderMapping { view: self.view },
            self.layout,
            self.topology,
        )?)
    }
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
) -> Result<ReaderRegion<WindowsReaderMapping>, WindowsError> {
    let section = OwnedHandle::new(handle as HANDLE)?;
    let view = View::map(section.0, len, FILE_MAP_READ)?;
    // SAFETY: READY protocol keeps view quiescent; access is read-only.
    let bytes = unsafe { std::slice::from_raw_parts(view.base.as_ptr(), len) };
    let layout = unsafe { ValidatedRegionLayout::validate(bytes, expected, &topology) }?;
    drop(section);
    Ok(ReaderRegion::new(
        WindowsReaderMapping { view },
        layout,
        topology,
    )?)
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
) -> Result<WriterRegion<WindowsWriterMapping>, WindowsError> {
    let section = OwnedHandle::new(handle as HANDLE)?;
    let view = View::map(section.0, len, FILE_MAP_WRITE)?;
    // SAFETY: READY protocol keeps the sole writer quiescent during validation.
    let bytes = unsafe { std::slice::from_raw_parts(view.base.as_ptr(), len) };
    let layout = unsafe { ValidatedRegionLayout::validate(bytes, expected, &topology) }?;
    drop(section);
    Ok(WriterRegion::new(
        WindowsWriterMapping { view },
        layout,
        topology,
    )?)
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

fn last_os(operation: &'static str) -> WindowsError {
    // SAFETY: GetLastError has no preconditions.
    WindowsError::Os {
        operation,
        code: unsafe { GetLastError() },
    }
}

/// Remains fail-closed until native Windows permission/lifecycle CI passes.
pub const fn status() -> BackendStatus {
    BackendStatus::Incomplete("Windows backend awaits native permission and lifecycle validation")
}

#[cfg(test)]
mod tests {
    use super::*;

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
    }
}
