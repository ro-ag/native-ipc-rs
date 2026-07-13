//! Private Windows vNext mixed-direction section ownership.

use core::cell::Cell;
use core::marker::PhantomData;
use core::mem::{size_of, zeroed};
use core::ptr::NonNull;

#[cfg(test)]
use core::sync::atomic::{AtomicUsize, Ordering};
#[cfg(test)]
use std::sync::Arc;

use windows_sys::Wdk::Foundation::{NtQueryObject, ObjectBasicInformation};
use windows_sys::Win32::Foundation::{
    CompareObjectHandles, GetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT,
    HANDLE_FLAG_PROTECT_FROM_CLOSE, SetHandleInformation,
};
use windows_sys::Win32::System::Memory::{
    FILE_MAP_READ, FILE_MAP_WRITE, MEM_COMMIT, MEM_MAPPED, MEMORY_BASIC_INFORMATION, MapViewOfFile,
    MemoryRegionInfo, PAGE_READONLY, PAGE_READWRITE, QueryVirtualMemoryInformation, VirtualQuery,
    WIN32_MEMORY_REGION_INFORMATION,
};
use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
use windows_sys::Win32::System::Threading::GetCurrentProcess;
use windows_sys::Win32::System::WindowsProgramming::PUBLIC_OBJECT_BASIC_INFORMATION;

#[cfg(test)]
use super::duplicate_to;
use super::{OwnedHandle, QuiescentRegion, View, page_align};
use crate::active::{ActiveReadOwner, ActiveWriteOwner};
use crate::batch::{ExpectedBatch, LocalRegionAuthority, TransferBatch};
use crate::protocol::{
    ManifestEntry, NativeAuthorityProfile, NativeRegionSpec, PeerAccess, TransferManifest,
};
use crate::region::{RegionId, WriterEndpoint};
use crate::session::{AbsoluteDeadline, SessionLimits};

const OBJECT_NAME_INFORMATION: i32 = 1;
const OBJECT_TYPE_INFORMATION: i32 = 2;
const MEMORY_REGION_MAPPED_PAGE_FILE: u32 = 1 << 3;

/// Windows mixed-batch construction or import failure.
#[derive(Debug)]
pub(crate) enum WindowsBatchError {
    InvalidBatch,
    InvalidSize,
    DeadlineExpired,
    WrongProvenance,
    WrongObject,
    WrongAccess,
    Native(super::WindowsError),
}

impl From<super::WindowsError> for WindowsBatchError {
    fn from(error: super::WindowsError) -> Self {
        Self::Native(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct WindowsActiveRegionSpec {
    pub(crate) id: RegionId,
    pub(crate) logical_len: usize,
    pub(crate) mapped_len: usize,
    pub(crate) authority: LocalRegionAuthority,
}

pub(crate) enum WindowsActiveRegionOwner {
    Reader {
        spec: WindowsActiveRegionSpec,
        owner: Box<dyn ActiveReadOwner>,
    },
    Writer {
        spec: WindowsActiveRegionSpec,
        owner: Box<dyn ActiveWriteOwner>,
    },
}

impl WindowsActiveRegionOwner {
    pub(crate) const fn spec(&self) -> WindowsActiveRegionSpec {
        match self {
            Self::Reader { spec, .. } | Self::Writer { spec, .. } => *spec,
        }
    }

    pub(crate) fn into_reader(self) -> Option<Box<dyn ActiveReadOwner>> {
        match self {
            Self::Reader { owner, .. } => Some(owner),
            Self::Writer { .. } => None,
        }
    }

    pub(crate) fn into_writer(self) -> Option<Box<dyn ActiveWriteOwner>> {
        match self {
            Self::Writer { owner, .. } => Some(owner),
            Self::Reader { .. } => None,
        }
    }
}

struct SectionView(Option<View>, #[cfg(test)] Arc<AtomicUsize>);

struct SectionHandle(Option<OwnedHandle>, #[cfg(test)] Arc<AtomicUsize>);

impl SectionHandle {
    fn new(handle: OwnedHandle) -> Self {
        #[cfg(test)]
        let live = LIVE_VNEXT_HANDLES.with(Arc::clone);
        #[cfg(test)]
        live.fetch_add(1, Ordering::Relaxed);
        Self(
            Some(handle),
            #[cfg(test)]
            live,
        )
    }

    fn raw(&self) -> HANDLE {
        self.0.as_ref().expect("live section handle").0
    }
}

impl Drop for SectionHandle {
    fn drop(&mut self) {
        let _released = self.0.take().is_none_or(|handle| handle.close().is_ok());
        #[cfg(test)]
        if _released {
            let previous = self.1.fetch_sub(1, Ordering::Relaxed);
            assert!(previous > 0, "live Windows handle accounting underflow");
        }
    }
}

impl SectionView {
    fn new(view: View) -> Self {
        #[cfg(test)]
        let live = LIVE_VNEXT_VIEWS.with(Arc::clone);
        #[cfg(test)]
        live.fetch_add(1, Ordering::Relaxed);
        Self(
            Some(view),
            #[cfg(test)]
            live,
        )
    }

    fn base(&self) -> NonNull<u8> {
        self.0.as_ref().expect("live section view").base
    }

    fn len(&self) -> usize {
        self.0.as_ref().expect("live section view").len
    }
}

#[cfg(test)]
thread_local! {
    static LIVE_VNEXT_VIEWS: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
    static LIVE_VNEXT_HANDLES: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));
}

#[cfg(test)]
pub(crate) fn live_views_for_test() -> usize {
    LIVE_VNEXT_VIEWS.with(|live| live.load(Ordering::Relaxed))
}

#[cfg(test)]
pub(crate) fn live_handles_for_test() -> usize {
    LIVE_VNEXT_HANDLES.with(|live| live.load(Ordering::Relaxed))
}

impl Drop for SectionView {
    fn drop(&mut self) {
        let _released = self.0.take().is_none_or(|view| view.unmap().is_ok());
        #[cfg(test)]
        if _released {
            let previous = self.1.fetch_sub(1, Ordering::Relaxed);
            assert!(previous > 0, "live Windows view accounting underflow");
        }
    }
}

struct ActiveReadMapping {
    view: SectionView,
    page_size: usize,
}

struct ActiveWriteMapping {
    view: SectionView,
    page_size: usize,
    _not_sync: PhantomData<Cell<()>>,
}

// SAFETY: the wrapper owns one immutable local mapping. Peer mutation is
// observed only through ActiveReader's volatile-copy boundary.
unsafe impl Send for ActiveReadMapping {}
// SAFETY: immutable access is synchronized by the shared-memory protocol.
unsafe impl Sync for ActiveReadMapping {}

// SAFETY: the wrapper uniquely owns its view and may transfer that ownership.
unsafe impl Send for ActiveWriteMapping {}

// SAFETY: each wrapper uniquely owns and synchronously destroys its exact view.
unsafe impl ActiveReadOwner for ActiveReadMapping {
    fn as_ptr(&self) -> *const u8 {
        self.view.base().as_ptr().cast_const()
    }

    fn len(&self) -> usize {
        self.view.len()
    }

    fn page_size(&self) -> usize {
        self.page_size
    }
}

// SAFETY: this wrapper uniquely owns the endpoint's writable local view. The
// Cell marker keeps it non-Sync and mutation requires `&mut`.
unsafe impl ActiveWriteOwner for ActiveWriteMapping {
    fn as_ptr(&self) -> *const u8 {
        self.view.base().as_ptr().cast_const()
    }

    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.view.base().as_ptr()
    }

    fn len(&self) -> usize {
        self.view.len()
    }

    fn page_size(&self) -> usize {
        self.page_size
    }
}

struct CoordinatorWriterEntry {
    native: NativeRegionSpec,
    section: SectionHandle,
    mapping: SectionView,
}

struct ReceiverWriterEntry {
    native: NativeRegionSpec,
    section: SectionHandle,
    mapping: SectionView,
}

enum PreparedEntry {
    CoordinatorWriter(CoordinatorWriterEntry),
    ReceiverWriter(ReceiverWriterEntry),
}

impl PreparedEntry {
    fn section(&self) -> HANDLE {
        match self {
            Self::CoordinatorWriter(entry) => entry.section.raw(),
            Self::ReceiverWriter(entry) => entry.section.raw(),
        }
    }

    const fn peer_access(&self) -> u32 {
        match self {
            Self::CoordinatorWriter(_) => FILE_MAP_READ,
            Self::ReceiverWriter(_) => FILE_MAP_WRITE,
        }
    }
}

/// Coordinator-owned canonical native batch before handle duplication.
pub(crate) struct WindowsMixedDirectionBatch {
    entries: Vec<PreparedEntry>,
    deadline: AbsoluteDeadline,
}

impl WindowsMixedDirectionBatch {
    pub(crate) fn prepare(
        batch: TransferBatch,
        authority_profile: NativeAuthorityProfile,
        deadline: AbsoluteDeadline,
    ) -> Result<Self, WindowsBatchError> {
        Self::prepare_inner(batch, authority_profile, deadline, None)
    }

    fn prepare_inner(
        batch: TransferBatch,
        authority_profile: NativeAuthorityProfile,
        deadline: AbsoluteDeadline,
        failure_at: Option<usize>,
    ) -> Result<Self, WindowsBatchError> {
        check_deadline(deadline)?;
        if authority_profile != NativeAuthorityProfile::WindowsSectionsV1 {
            return Err(WindowsBatchError::WrongProvenance);
        }
        let mut pending = batch
            .into_pending()
            .map_err(|_| WindowsBatchError::InvalidBatch)?;
        pending
            .regions
            .sort_unstable_by_key(|region| region.spec().id);
        let mut entries = Vec::with_capacity(pending.regions.len());
        for (ordinal, region) in pending.regions.into_iter().enumerate() {
            check_deadline(deadline)?;
            let (request, spec, _) = region.into_windows_transfer_parts();
            let native = request
                .native_spec(spec.id.get())
                .ok_or(WindowsBatchError::InvalidBatch)?;
            let mapped_len = request.mapped_len();
            let (region, _cleanup) = request.into_windows_quiescent();
            let QuiescentRegion {
                section,
                view,
                logical_len: _,
            } = region;
            let section = SectionHandle::new(section);
            let entry = match spec.writer {
                WriterEndpoint::Coordinator => {
                    PreparedEntry::CoordinatorWriter(CoordinatorWriterEntry {
                        native,
                        section,
                        mapping: SectionView::new(view),
                    })
                }
                WriterEndpoint::Receiver => {
                    drop(view);
                    let mapping =
                        SectionView::new(View::map(section.raw(), mapped_len, FILE_MAP_READ)?);
                    PreparedEntry::ReceiverWriter(ReceiverWriterEntry {
                        native,
                        section,
                        mapping,
                    })
                }
            };
            if failure_at == Some(ordinal + 1) {
                drop(entry);
                return Err(WindowsBatchError::WrongObject);
            }
            entries.push(entry);
        }
        check_deadline(deadline)?;
        validate_prepared_entries(&entries, deadline)?;
        Ok(Self { entries, deadline })
    }

    pub(crate) fn manifest_entries(&self) -> Vec<ManifestEntry> {
        self.entries
            .iter()
            .map(|entry| match entry {
                PreparedEntry::CoordinatorWriter(entry) => {
                    ManifestEntry::from_native(entry.native, PeerAccess::ReadOnly)
                }
                PreparedEntry::ReceiverWriter(entry) => {
                    ManifestEntry::from_native(entry.native, PeerAccess::SoleWriter)
                }
            })
            .collect()
    }

    pub(crate) fn reservation_lengths(&self) -> Vec<u64> {
        self.manifest_entries()
            .into_iter()
            .map(|entry| entry.mapped_len)
            .collect()
    }

    pub(crate) const fn deadline(&self) -> AbsoluteDeadline {
        self.deadline
    }

    pub(crate) fn revalidate_before_send(&self) -> Result<(), WindowsBatchError> {
        check_deadline(self.deadline)?;
        validate_prepared_entries(&self.entries, self.deadline)
    }

    pub(crate) fn capability_sources(&self) -> Result<Vec<(HANDLE, u32)>, WindowsBatchError> {
        self.revalidate_before_send()?;
        Ok(self
            .entries
            .iter()
            .map(|entry| (entry.section(), entry.peer_access()))
            .collect())
    }

    pub(crate) fn activation_specs(
        &self,
    ) -> Result<Vec<WindowsActiveRegionSpec>, WindowsBatchError> {
        self.revalidate_before_send()?;
        let specs = self
            .entries
            .iter()
            .map(|entry| match entry {
                PreparedEntry::CoordinatorWriter(entry) => {
                    active_spec(entry.native, LocalRegionAuthority::Writer, &entry.mapping)
                }
                PreparedEntry::ReceiverWriter(entry) => {
                    active_spec(entry.native, LocalRegionAuthority::Reader, &entry.mapping)
                }
            })
            .collect::<Result<Vec<_>, _>>()?;
        validate_active_specs(&specs)?;
        Ok(specs)
    }

    pub(crate) fn into_active_region_owners(self) -> Vec<WindowsActiveRegionOwner> {
        let page_size = native_page_size().expect("activation preflight validated page size");
        self.entries
            .into_iter()
            .map(|entry| match entry {
                PreparedEntry::CoordinatorWriter(entry) => {
                    let spec =
                        active_spec(entry.native, LocalRegionAuthority::Writer, &entry.mapping)
                            .expect("activation preflight validated writer mapping");
                    drop(entry.section);
                    WindowsActiveRegionOwner::Writer {
                        spec,
                        owner: Box::new(ActiveWriteMapping {
                            view: entry.mapping,
                            page_size,
                            _not_sync: PhantomData,
                        }),
                    }
                }
                PreparedEntry::ReceiverWriter(entry) => {
                    let spec =
                        active_spec(entry.native, LocalRegionAuthority::Reader, &entry.mapping)
                            .expect("activation preflight validated reader mapping");
                    drop(entry.section);
                    WindowsActiveRegionOwner::Reader {
                        spec,
                        owner: Box::new(ActiveReadMapping {
                            view: entry.mapping,
                            page_size,
                        }),
                    }
                }
            })
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn prepare_with_failure_for_test(
        batch: TransferBatch,
        failure_at: usize,
        deadline: AbsoluteDeadline,
    ) -> Result<Self, WindowsBatchError> {
        Self::prepare_inner(
            batch,
            NativeAuthorityProfile::WindowsSectionsV1,
            deadline,
            Some(failure_at),
        )
    }

    #[cfg(test)]
    pub(crate) fn copied_capabilities_for_test(
        &self,
    ) -> Result<Vec<WindowsReceivedHandle>, WindowsBatchError> {
        self.entries
            .iter()
            .map(|entry| {
                let remote = duplicate_to(
                    entry.section(),
                    unsafe { GetCurrentProcess() },
                    entry.peer_access(),
                )?;
                // SAFETY: DuplicateHandle installed this exact value in the
                // current test process and ownership transfers immediately.
                unsafe { WindowsReceivedHandle::from_raw(remote.0) }
            })
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn duplicate_capability_for_test(
        &self,
        ordinal: usize,
    ) -> Result<WindowsReceivedHandle, WindowsBatchError> {
        let entry = self
            .entries
            .get(ordinal)
            .ok_or(WindowsBatchError::InvalidBatch)?;
        let remote = duplicate_to(
            entry.section(),
            unsafe { GetCurrentProcess() },
            entry.peer_access(),
        )?;
        // SAFETY: the handle was just installed in this process.
        unsafe { WindowsReceivedHandle::from_raw(remote.0) }
    }

    #[cfg(test)]
    pub(crate) fn duplicate_raw_capability_for_test(
        &self,
        ordinal: usize,
    ) -> Result<usize, WindowsBatchError> {
        let entry = self
            .entries
            .get(ordinal)
            .ok_or(WindowsBatchError::InvalidBatch)?;
        Ok(duplicate_to(
            entry.section(),
            unsafe { GetCurrentProcess() },
            entry.peer_access(),
        )?
        .0)
    }

    #[cfg(test)]
    pub(crate) fn write_coordinator_for_test(&mut self, ordinal: usize, offset: usize, value: u8) {
        let PreparedEntry::CoordinatorWriter(entry) = &mut self.entries[ordinal] else {
            panic!("test write requires a coordinator-writer entry");
        };
        assert!(offset < entry.native.logical_len as usize);
        // SAFETY: the batch is quiescent and owns the only writable local view.
        unsafe { core::ptr::write_volatile(entry.mapping.base().as_ptr().add(offset), value) };
    }

    #[cfg(test)]
    pub(crate) fn read_receiver_for_test(&self, ordinal: usize, offset: usize) -> u8 {
        let PreparedEntry::ReceiverWriter(entry) = &self.entries[ordinal] else {
            panic!("test read requires a receiver-writer entry");
        };
        assert!(offset < entry.native.logical_len as usize);
        // SAFETY: this exact local mapping is read-only and batch-owned.
        unsafe { core::ptr::read_volatile(entry.mapping.base().as_ptr().add(offset)) }
    }
}

/// Immediately owned handle installed in the receiving process.
pub(crate) struct WindowsReceivedHandle(SectionHandle);

// SAFETY: this value uniquely owns one process-local handle and transfers only
// that ownership; all use and destruction remains serialized by `&mut self` or
// consuming operations.
unsafe impl Send for WindowsReceivedHandle {}

impl WindowsReceivedHandle {
    /// # Safety
    ///
    /// `handle` must be a newly installed, non-pseudo handle owned by this
    /// process and must not have any other Rust owner.
    pub(crate) unsafe fn from_raw(handle: usize) -> Result<Self, WindowsBatchError> {
        let handle = SectionHandle::new(OwnedHandle::new(handle as HANDLE)?);
        let flags = match handle_flags(handle.raw()) {
            Ok(flags) => flags,
            Err(error) => {
                clear_handle_flags(handle.raw())?;
                return Err(error);
            }
        };
        if flags != 0 {
            clear_handle_flags(handle.raw())?;
            return Err(WindowsBatchError::WrongAccess);
        }
        Ok(Self(handle))
    }

    fn raw(&self) -> HANDLE {
        self.0.raw()
    }

    #[cfg(test)]
    pub(crate) fn set_flags_for_test(&self, flags: u32) -> bool {
        let mask = HANDLE_FLAG_INHERIT | HANDLE_FLAG_PROTECT_FROM_CLOSE;
        // SAFETY: the test owner keeps the handle live for this call.
        unsafe { SetHandleInformation(self.raw(), mask, flags) != 0 }
    }
}

#[derive(Clone, Copy)]
struct ExpectedEntry {
    id: RegionId,
    writer: WriterEndpoint,
    logical_len: usize,
    mapped_len: usize,
}

/// Receiver-owned canonical expectation fixed before any handle arrives.
pub(crate) struct WindowsExpectedMixedDirectionBatch {
    entries: Vec<ExpectedEntry>,
    total_logical: u64,
    total_mapped: u64,
    deadline: AbsoluteDeadline,
}

impl WindowsExpectedMixedDirectionBatch {
    pub(crate) fn new(
        expected: ExpectedBatch,
        limits: SessionLimits,
        deadline: AbsoluteDeadline,
    ) -> Result<Self, WindowsBatchError> {
        check_deadline(deadline)?;
        limits
            .validate()
            .map_err(|_| WindowsBatchError::InvalidBatch)?;
        if expected.regions.len() > usize::from(limits.max_regions_per_batch)
            || expected.regions.len() as u64 > u64::from(limits.max_active_regions)
            || expected.total_logical > limits.max_batch_bytes
        {
            return Err(WindowsBatchError::InvalidBatch);
        }
        let mut total_mapped = 0_u64;
        let mut entries = Vec::with_capacity(expected.regions.len());
        for region in expected.regions {
            if u64::try_from(region.logical_len).map_err(|_| WindowsBatchError::InvalidSize)?
                > limits.max_region_bytes
            {
                return Err(WindowsBatchError::InvalidSize);
            }
            let mapped_len = page_align(region.logical_len)?;
            total_mapped = total_mapped
                .checked_add(u64::try_from(mapped_len).map_err(|_| WindowsBatchError::InvalidSize)?)
                .ok_or(WindowsBatchError::InvalidSize)?;
            entries.push(ExpectedEntry {
                id: region.id,
                writer: region.writer,
                logical_len: region.logical_len,
                mapped_len,
            });
        }
        if total_mapped > limits.max_batch_bytes || total_mapped > limits.max_active_bytes {
            return Err(WindowsBatchError::InvalidSize);
        }
        Ok(Self {
            entries,
            total_logical: expected.total_logical,
            total_mapped,
            deadline,
        })
    }

    pub(crate) fn matches_manifest(&self, manifest: &TransferManifest) -> bool {
        manifest.authority_profile() == NativeAuthorityProfile::WindowsSectionsV1
            && manifest.entries().len() == self.entries.len()
            && manifest.total_logical() == self.total_logical
            && manifest.total_mapped() == self.total_mapped
            && self.entries.iter().zip(manifest.entries()).enumerate().all(
                |(ordinal, (expected, received))| {
                    let (writer, access) = match expected.writer {
                        WriterEndpoint::Coordinator => (0, PeerAccess::ReadOnly),
                        WriterEndpoint::Receiver => (1, PeerAccess::SoleWriter),
                    };
                    received.region_id == expected.id.get()
                        && received.writer == writer
                        && received.access == access
                        && received.logical_len == expected.logical_len as u64
                        && received.mapped_len == expected.mapped_len as u64
                        && received.ordinal as usize == ordinal
                },
            )
    }

    pub(crate) const fn len(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn reservation_lengths(&self) -> Vec<u64> {
        self.entries
            .iter()
            .map(|entry| entry.mapped_len as u64)
            .collect()
    }

    pub(crate) fn import(
        self,
        manifest: &TransferManifest,
        handles: Vec<WindowsReceivedHandle>,
    ) -> Result<WindowsImportedMixedDirectionBatch, WindowsBatchError> {
        self.import_inner(manifest, handles, None)
    }

    fn import_inner(
        self,
        manifest: &TransferManifest,
        handles: Vec<WindowsReceivedHandle>,
        failure_at: Option<usize>,
    ) -> Result<WindowsImportedMixedDirectionBatch, WindowsBatchError> {
        check_deadline(self.deadline)?;
        if handles.len() != self.entries.len() || !self.matches_manifest(manifest) {
            return Err(WindowsBatchError::WrongProvenance);
        }
        let mut imported = Vec::with_capacity(handles.len());
        for (ordinal, ((expected, manifest_entry), handle)) in self
            .entries
            .into_iter()
            .zip(manifest.entries().iter().copied())
            .zip(handles)
            .enumerate()
        {
            check_deadline(self.deadline)?;
            if imported
                .iter()
                .any(|entry: &ImportedEntry| same_object(entry.handle(), handle.raw()))
            {
                return Err(WindowsBatchError::WrongObject);
            }
            let access = match expected.writer {
                WriterEndpoint::Coordinator => FILE_MAP_READ,
                WriterEndpoint::Receiver => FILE_MAP_WRITE,
            };
            let mapping = map_exact_unnamed_section(handle.raw(), expected.mapped_len, access)?;
            if failure_at == Some(ordinal + 1) {
                drop(mapping);
                drop(handle);
                return Err(WindowsBatchError::WrongObject);
            }
            imported.push(match expected.writer {
                WriterEndpoint::Coordinator => ImportedEntry::CoordinatorWriter {
                    manifest: manifest_entry,
                    section: handle,
                    mapping,
                },
                WriterEndpoint::Receiver => ImportedEntry::ReceiverWriter {
                    manifest: manifest_entry,
                    section: handle,
                    mapping,
                },
            });
        }
        check_deadline(self.deadline)?;
        let batch = WindowsImportedMixedDirectionBatch { entries: imported };
        batch.activation_specs(self.deadline)?;
        Ok(batch)
    }

    #[cfg(test)]
    pub(crate) fn import_with_failure_for_test(
        self,
        manifest: &TransferManifest,
        handles: Vec<WindowsReceivedHandle>,
        failure_at: usize,
    ) -> Result<WindowsImportedMixedDirectionBatch, WindowsBatchError> {
        self.import_inner(manifest, handles, Some(failure_at))
    }
}

enum ImportedEntry {
    CoordinatorWriter {
        manifest: ManifestEntry,
        section: WindowsReceivedHandle,
        mapping: SectionView,
    },
    ReceiverWriter {
        manifest: ManifestEntry,
        section: WindowsReceivedHandle,
        mapping: SectionView,
    },
}

impl ImportedEntry {
    fn handle(&self) -> HANDLE {
        match self {
            Self::CoordinatorWriter { section, .. } | Self::ReceiverWriter { section, .. } => {
                section.raw()
            }
        }
    }
}

/// Receiver-owned imported mappings withheld until full-batch commit.
pub(crate) struct WindowsImportedMixedDirectionBatch {
    entries: Vec<ImportedEntry>,
}

impl WindowsImportedMixedDirectionBatch {
    pub(crate) fn activation_specs(
        &self,
        deadline: AbsoluteDeadline,
    ) -> Result<Vec<WindowsActiveRegionSpec>, WindowsBatchError> {
        check_deadline(deadline)?;
        let mut specs = Vec::with_capacity(self.entries.len());
        for (ordinal, entry) in self.entries.iter().enumerate() {
            check_deadline(deadline)?;
            let spec = match entry {
                ImportedEntry::CoordinatorWriter {
                    manifest, mapping, ..
                } => {
                    validate_imported_manifest(*manifest, ordinal, 0, PeerAccess::ReadOnly)?;
                    active_spec_from_manifest(*manifest, LocalRegionAuthority::Reader, mapping)
                }
                ImportedEntry::ReceiverWriter {
                    manifest, mapping, ..
                } => {
                    validate_imported_manifest(*manifest, ordinal, 1, PeerAccess::SoleWriter)?;
                    active_spec_from_manifest(*manifest, LocalRegionAuthority::Writer, mapping)
                }
            }?;
            specs.push(spec);
        }
        check_deadline(deadline)?;
        validate_active_specs(&specs)?;
        Ok(specs)
    }

    pub(crate) fn into_active_region_owners(self) -> Vec<WindowsActiveRegionOwner> {
        let page_size = native_page_size().expect("activation preflight validated page size");
        self.entries
            .into_iter()
            .map(|entry| match entry {
                ImportedEntry::CoordinatorWriter {
                    manifest,
                    section,
                    mapping,
                } => {
                    let spec =
                        active_spec_from_manifest(manifest, LocalRegionAuthority::Reader, &mapping)
                            .expect("activation preflight validated imported reader");
                    drop(section);
                    WindowsActiveRegionOwner::Reader {
                        spec,
                        owner: Box::new(ActiveReadMapping {
                            view: mapping,
                            page_size,
                        }),
                    }
                }
                ImportedEntry::ReceiverWriter {
                    manifest,
                    section,
                    mapping,
                } => {
                    let spec =
                        active_spec_from_manifest(manifest, LocalRegionAuthority::Writer, &mapping)
                            .expect("activation preflight validated imported writer");
                    drop(section);
                    WindowsActiveRegionOwner::Writer {
                        spec,
                        owner: Box::new(ActiveWriteMapping {
                            view: mapping,
                            page_size,
                            _not_sync: PhantomData,
                        }),
                    }
                }
            })
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn read_coordinator_for_test(&self, ordinal: usize, offset: usize) -> u8 {
        let ImportedEntry::CoordinatorWriter {
            manifest, mapping, ..
        } = &self.entries[ordinal]
        else {
            panic!("test read requires an imported coordinator-writer entry");
        };
        assert!(offset < manifest.logical_len as usize);
        // SAFETY: the imported read-only mapping remains batch-owned.
        unsafe { core::ptr::read_volatile(mapping.base().as_ptr().add(offset)) }
    }

    #[cfg(test)]
    pub(crate) fn write_receiver_for_test(&mut self, ordinal: usize, offset: usize, value: u8) {
        let ImportedEntry::ReceiverWriter {
            manifest, mapping, ..
        } = &mut self.entries[ordinal]
        else {
            panic!("test write requires an imported receiver-writer entry");
        };
        assert!(offset < manifest.logical_len as usize);
        // SAFETY: the imported mapping is the receiver's only writable view.
        unsafe { core::ptr::write_volatile(mapping.base().as_ptr().add(offset), value) };
    }
}

fn validate_prepared_entries(
    entries: &[PreparedEntry],
    deadline: AbsoluteDeadline,
) -> Result<(), WindowsBatchError> {
    if entries.is_empty() || entries.len() > 16 {
        return Err(WindowsBatchError::InvalidBatch);
    }
    let mut previous = None;
    for (ordinal, entry) in entries.iter().enumerate() {
        check_deadline(deadline)?;
        let (native, mapping) = match entry {
            PreparedEntry::CoordinatorWriter(entry) => (entry.native, &entry.mapping),
            PreparedEntry::ReceiverWriter(entry) => (entry.native, &entry.mapping),
        };
        let id = RegionId::new(native.region_id).ok_or(WindowsBatchError::WrongProvenance)?;
        if previous.is_some_and(|previous| previous >= id)
            || native.logical_len == 0
            || native.logical_len > native.mapped_len
            || native.mapped_len != mapping.len() as u64
            || entries[..ordinal]
                .iter()
                .any(|prior| same_object(prior.section(), entry.section()))
        {
            return Err(WindowsBatchError::WrongProvenance);
        }
        previous = Some(id);
    }
    check_deadline(deadline)
}

fn map_exact_unnamed_section(
    handle: HANDLE,
    mapped_len: usize,
    access: u32,
) -> Result<SectionView, WindowsBatchError> {
    if mapped_len == 0 || granted_access(handle)? != access {
        return Err(WindowsBatchError::WrongAccess);
    }
    if handle_flags(handle)? != 0 {
        clear_handle_flags(handle)?;
        return Err(WindowsBatchError::WrongAccess);
    }
    if object_type(handle)? != "Section" || !object_is_unnamed(handle)? {
        return Err(WindowsBatchError::WrongObject);
    }
    // SAFETY: the installed handle is owned and access was checked exactly;
    // zero maps the full section so its true extent can be validated.
    let address = unsafe { MapViewOfFile(handle, access, 0, 0, 0) };
    let base = NonNull::new(address.Value.cast()).ok_or(WindowsBatchError::WrongObject)?;
    let view = SectionView::new(View {
        base,
        len: mapped_len,
    });
    let expected_protection = if access == FILE_MAP_READ {
        PAGE_READONLY
    } else {
        PAGE_READWRITE
    };
    let mut region: WIN32_MEMORY_REGION_INFORMATION = unsafe { zeroed() };
    let mut returned = 0_usize;
    // SAFETY: current-process pseudo-handle, mapped base, output, and output
    // length match the public allocation-level information class.
    if unsafe {
        QueryVirtualMemoryInformation(
            GetCurrentProcess(),
            base.as_ptr().cast_const().cast(),
            MemoryRegionInfo,
            (&mut region as *mut WIN32_MEMORY_REGION_INFORMATION).cast(),
            size_of::<WIN32_MEMORY_REGION_INFORMATION>(),
            &mut returned,
        )
    } == 0
        || returned != size_of::<WIN32_MEMORY_REGION_INFORMATION>()
    {
        return Err(WindowsBatchError::WrongObject);
    }
    // windows-sys exposes the C bitfield as its generated backing word. The
    // documented bit order makes bit 3 MappedPageFile; exact equality also
    // rejects data/image/physical/direct/private and reserved classifications.
    let region_flags = unsafe { region.Anonymous.Anonymous._bitfield };
    if region.AllocationBase != base.as_ptr().cast()
        || region.AllocationProtect != expected_protection
        || region.RegionSize != mapped_len
        || region_flags != MEMORY_REGION_MAPPED_PAGE_FILE
    {
        return Err(WindowsBatchError::WrongObject);
    }
    let mut information: MEMORY_BASIC_INFORMATION = unsafe { zeroed() };
    // SAFETY: the mapped base and output structure are valid.
    if unsafe {
        VirtualQuery(
            base.as_ptr().cast_const().cast(),
            &mut information,
            size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    } != size_of::<MEMORY_BASIC_INFORMATION>()
    {
        return Err(WindowsBatchError::WrongObject);
    }
    if information.BaseAddress != base.as_ptr().cast()
        || information.AllocationBase != base.as_ptr().cast()
        || information.RegionSize != mapped_len
        || information.State != MEM_COMMIT
        || information.Type != MEM_MAPPED
        || information.Protect != expected_protection
        || information.AllocationProtect != expected_protection
    {
        return Err(WindowsBatchError::WrongObject);
    }
    Ok(view)
}

fn handle_flags(handle: HANDLE) -> Result<u32, WindowsBatchError> {
    let mut flags = 0_u32;
    // SAFETY: the handle is live and the output pointer is valid.
    if unsafe { GetHandleInformation(handle, &mut flags) } == 0 {
        Err(WindowsBatchError::WrongObject)
    } else {
        Ok(flags)
    }
}

fn clear_handle_flags(handle: HANDLE) -> Result<(), WindowsBatchError> {
    let mask = HANDLE_FLAG_INHERIT | HANDLE_FLAG_PROTECT_FROM_CLOSE;
    // SAFETY: the newly installed handle is live and still exclusively owned.
    if unsafe { SetHandleInformation(handle, mask, 0) } == 0 {
        Err(WindowsBatchError::WrongObject)
    } else {
        Ok(())
    }
}

fn granted_access(handle: HANDLE) -> Result<u32, WindowsBatchError> {
    let mut information = PUBLIC_OBJECT_BASIC_INFORMATION::default();
    let mut returned = 0;
    // SAFETY: handle is live and the class/output size match the documented
    // public basic-information record.
    let status = unsafe {
        NtQueryObject(
            handle,
            ObjectBasicInformation,
            (&mut information as *mut PUBLIC_OBJECT_BASIC_INFORMATION).cast(),
            size_of::<PUBLIC_OBJECT_BASIC_INFORMATION>() as u32,
            &mut returned,
        )
    };
    if status < 0 || returned < size_of::<PUBLIC_OBJECT_BASIC_INFORMATION>() as u32 {
        Err(WindowsBatchError::WrongObject)
    } else {
        Ok(information.GrantedAccess)
    }
}

fn object_type(handle: HANDLE) -> Result<String, WindowsBatchError> {
    query_object_unicode(handle, OBJECT_TYPE_INFORMATION)
}

fn object_is_unnamed(handle: HANDLE) -> Result<bool, WindowsBatchError> {
    Ok(query_object_unicode(handle, OBJECT_NAME_INFORMATION)?.is_empty())
}

fn query_object_unicode(handle: HANDLE, class: i32) -> Result<String, WindowsBatchError> {
    let mut required = 0_u32;
    // SAFETY: this sizing call supplies no output buffer.
    let _ = unsafe { NtQueryObject(handle, class, core::ptr::null_mut(), 0, &mut required) };
    if required < size_of::<windows_sys::Win32::Foundation::UNICODE_STRING>() as u32 {
        return Err(WindowsBatchError::WrongObject);
    }
    let words = usize::try_from(required)
        .ok()
        .and_then(|bytes| bytes.checked_add(size_of::<usize>() - 1))
        .map(|bytes| bytes / size_of::<usize>())
        .ok_or(WindowsBatchError::InvalidSize)?;
    let mut storage = vec![0_usize; words];
    let mut returned = 0_u32;
    // SAFETY: aligned storage is at least the requested byte length.
    let status = unsafe {
        NtQueryObject(
            handle,
            class,
            storage.as_mut_ptr().cast(),
            required,
            &mut returned,
        )
    };
    if status < 0 || returned > required {
        return Err(WindowsBatchError::WrongObject);
    }
    // Both name and type information start with one UNICODE_STRING.
    let value = unsafe {
        &*(storage
            .as_ptr()
            .cast::<windows_sys::Win32::Foundation::UNICODE_STRING>())
    };
    if value.Length == 0 {
        return Ok(String::new());
    }
    if value.Buffer.is_null() || value.Length % 2 != 0 {
        return Err(WindowsBatchError::WrongObject);
    }
    let start = value.Buffer as usize;
    let storage_start = storage.as_ptr() as usize;
    let storage_end = storage_start
        .checked_add(storage.len() * size_of::<usize>())
        .ok_or(WindowsBatchError::InvalidSize)?;
    let byte_len = usize::from(value.Length);
    if start < storage_start
        || start
            .checked_add(byte_len)
            .is_none_or(|end| end > storage_end)
    {
        return Err(WindowsBatchError::WrongObject);
    }
    // SAFETY: range and UTF-16 alignment/length were validated above.
    let units = unsafe { core::slice::from_raw_parts(value.Buffer, byte_len / 2) };
    String::from_utf16(units).map_err(|_| WindowsBatchError::WrongObject)
}

fn same_object(left: HANDLE, right: HANDLE) -> bool {
    // SAFETY: both handles are live for the duration of the comparison.
    unsafe { CompareObjectHandles(left, right) != 0 }
}

fn active_spec(
    native: NativeRegionSpec,
    authority: LocalRegionAuthority,
    mapping: &SectionView,
) -> Result<WindowsActiveRegionSpec, WindowsBatchError> {
    let id = RegionId::new(native.region_id).ok_or(WindowsBatchError::WrongProvenance)?;
    let logical_len =
        usize::try_from(native.logical_len).map_err(|_| WindowsBatchError::InvalidSize)?;
    let mapped_len =
        usize::try_from(native.mapped_len).map_err(|_| WindowsBatchError::InvalidSize)?;
    if logical_len == 0 || logical_len > mapped_len || mapped_len != mapping.len() {
        return Err(WindowsBatchError::WrongProvenance);
    }
    Ok(WindowsActiveRegionSpec {
        id,
        logical_len,
        mapped_len,
        authority,
    })
}

fn active_spec_from_manifest(
    manifest: ManifestEntry,
    authority: LocalRegionAuthority,
    mapping: &SectionView,
) -> Result<WindowsActiveRegionSpec, WindowsBatchError> {
    let native = NativeRegionSpec::new(
        manifest.region_id,
        manifest.incarnation,
        manifest.writer,
        usize::try_from(manifest.logical_len).map_err(|_| WindowsBatchError::InvalidSize)?,
        usize::try_from(manifest.mapped_len).map_err(|_| WindowsBatchError::InvalidSize)?,
    )
    .ok_or(WindowsBatchError::WrongProvenance)?;
    active_spec(native, authority, mapping)
}

fn validate_imported_manifest(
    manifest: ManifestEntry,
    ordinal: usize,
    writer: u32,
    access: PeerAccess,
) -> Result<(), WindowsBatchError> {
    if manifest.ordinal as usize != ordinal
        || manifest.writer != writer
        || manifest.access != access
    {
        return Err(WindowsBatchError::WrongProvenance);
    }
    Ok(())
}

fn validate_active_specs(specs: &[WindowsActiveRegionSpec]) -> Result<(), WindowsBatchError> {
    if specs.is_empty() || specs.len() > 16 {
        return Err(WindowsBatchError::InvalidBatch);
    }
    if specs.windows(2).any(|pair| pair[0].id >= pair[1].id)
        || specs
            .iter()
            .any(|spec| spec.logical_len == 0 || spec.logical_len > spec.mapped_len)
    {
        return Err(WindowsBatchError::WrongProvenance);
    }
    Ok(())
}

fn native_page_size() -> Result<usize, WindowsBatchError> {
    let mut information: SYSTEM_INFO = unsafe { zeroed() };
    // SAFETY: output pointer is valid.
    unsafe { GetSystemInfo(&mut information) };
    let page = information.dwPageSize as usize;
    if page == 0 || !page.is_power_of_two() {
        Err(WindowsBatchError::InvalidSize)
    } else {
        Ok(page)
    }
}

fn check_deadline(deadline: AbsoluteDeadline) -> Result<(), WindowsBatchError> {
    if deadline.is_expired() {
        Err(WindowsBatchError::DeadlineExpired)
    } else {
        Ok(())
    }
}
