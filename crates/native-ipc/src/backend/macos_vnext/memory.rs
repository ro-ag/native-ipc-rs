//! Private macOS vNext mixed-direction memory ownership.

use core::cell::Cell;
use core::marker::PhantomData;

use super::{
    LocalWriterRegion, Mapping, MemoryEntry, ReadOnlyCapability, ReadWriteCapability,
    RemoteWriterRegion, VM_FLAGS_ANYWHERE, VM_INHERIT_NONE, VM_PROT_EXECUTE, VM_PROT_READ,
    VM_PROT_WRITE, bootstrap, current_task, deallocate_mapping, mach_vm_map, page_align, page_size,
};
use crate::active::{ActiveReadOwner, ActiveWriteOwner};
use crate::batch::{ExpectedBatch, LocalRegionAuthority, TransferBatch};
use crate::protocol::{
    ManifestEntry, NativeAuthorityProfile, NativeRegionSpec, PeerAccess, TransferManifest,
};
use crate::region::{RegionId, WriterEndpoint};
use crate::session::{AbsoluteDeadline, SessionLimits};

const KERN_INVALID_ARGUMENT: super::KernReturn = 4;
const KERN_INVALID_RIGHT: super::KernReturn = 17;

/// Native macOS mixed-batch construction or import failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MacBatchError {
    InvalidBatch,
    InvalidSize,
    DeadlineExpired,
    WrongProvenance,
    WrongObject,
    Mach(super::MachError),
}

impl From<super::MachError> for MacBatchError {
    fn from(error: super::MachError) -> Self {
        Self::Mach(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MacActiveRegionSpec {
    pub(crate) id: RegionId,
    pub(crate) logical_len: usize,
    pub(crate) mapped_len: usize,
    pub(crate) authority: LocalRegionAuthority,
}

pub(crate) enum MacActiveRegionOwner {
    Reader {
        spec: MacActiveRegionSpec,
        owner: Box<dyn ActiveReadOwner>,
    },
    Writer {
        spec: MacActiveRegionSpec,
        owner: Box<dyn ActiveWriteOwner>,
    },
}

impl MacActiveRegionOwner {
    pub(crate) const fn spec(&self) -> MacActiveRegionSpec {
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

struct MacActiveReadMapping {
    mapping: Mapping,
    page_size: usize,
}

struct MacActiveWriteMapping {
    mapping: Mapping,
    page_size: usize,
    _not_sync: PhantomData<Cell<()>>,
}

// SAFETY: the wrapper owns one immutable local mapping. Peer mutation is
// observed only through ActiveReader's volatile-copy boundary.
unsafe impl Sync for MacActiveReadMapping {}

// SAFETY: each wrapper uniquely owns and synchronously destroys its exact Mach
// mapping. The stored page size is stable and was queried from the kernel.
unsafe impl ActiveReadOwner for MacActiveReadMapping {
    fn as_ptr(&self) -> *const u8 {
        self.mapping.address.as_ptr().cast_const()
    }

    fn len(&self) -> usize {
        self.mapping.mapped_len
    }

    fn page_size(&self) -> usize {
        self.page_size
    }
}

// SAFETY: this wrapper uniquely owns the endpoint's only writable local view.
// Its Cell marker keeps the capability non-Sync and mutation requires `&mut`.
unsafe impl ActiveWriteOwner for MacActiveWriteMapping {
    fn as_ptr(&self) -> *const u8 {
        self.mapping.address.as_ptr().cast_const()
    }

    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.mapping.address.as_ptr()
    }

    fn len(&self) -> usize {
        self.mapping.mapped_len
    }

    fn page_size(&self) -> usize {
        self.page_size
    }
}

struct CoordinatorWriterEntry {
    native: NativeRegionSpec,
    mapping: Mapping,
    peer_entry: MemoryEntry<ReadOnlyCapability>,
}

struct ReceiverWriterEntry {
    native: NativeRegionSpec,
    mapping: Mapping,
    peer_entry: MemoryEntry<ReadWriteCapability>,
}

enum PreparedEntry {
    CoordinatorWriter(CoordinatorWriterEntry),
    ReceiverWriter(ReceiverWriterEntry),
}

/// Coordinator-owned canonical native batch before capability transfer.
pub(crate) struct MacMixedDirectionBatch {
    entries: Vec<PreparedEntry>,
    deadline: AbsoluteDeadline,
}

impl MacMixedDirectionBatch {
    pub(crate) fn prepare(
        batch: TransferBatch,
        authority_profile: NativeAuthorityProfile,
        deadline: AbsoluteDeadline,
    ) -> Result<Self, MacBatchError> {
        Self::prepare_inner(batch, authority_profile, deadline, None)
    }

    fn prepare_inner(
        batch: TransferBatch,
        authority_profile: NativeAuthorityProfile,
        deadline: AbsoluteDeadline,
        failure_at: Option<usize>,
    ) -> Result<Self, MacBatchError> {
        check_deadline(deadline)?;
        if authority_profile != NativeAuthorityProfile::MacMachV1 {
            return Err(MacBatchError::WrongProvenance);
        }
        let mut pending = batch
            .into_pending()
            .map_err(|_| MacBatchError::InvalidBatch)?;
        pending
            .regions
            .sort_unstable_by_key(|region| region.spec().id);
        let mut entries = Vec::with_capacity(pending.regions.len());
        for (ordinal, region) in pending.regions.into_iter().enumerate() {
            check_deadline(deadline)?;
            let (request, spec, _) = region.into_macos_transfer_parts();
            let native = request
                .native_spec(spec.id.get())
                .ok_or(MacBatchError::InvalidBatch)?;
            let mapped_len = request.mapped_len();
            let (region, _cleanup) = request.into_macos_quiescent();
            let entry = match spec.writer {
                WriterEndpoint::Coordinator => {
                    let LocalWriterRegion {
                        mapping,
                        peer_entry,
                        len: _,
                    } = region.into_local_writer(mapped_len)?;
                    PreparedEntry::CoordinatorWriter(CoordinatorWriterEntry {
                        native,
                        mapping,
                        peer_entry,
                    })
                }
                WriterEndpoint::Receiver => {
                    let RemoteWriterRegion {
                        mapping,
                        peer_entry,
                        len: _,
                    } = region.into_remote_writer(mapped_len)?;
                    PreparedEntry::ReceiverWriter(ReceiverWriterEntry {
                        native,
                        mapping,
                        peer_entry,
                    })
                }
            };
            if failure_at == Some(ordinal + 1) {
                drop(entry);
                return Err(MacBatchError::WrongObject);
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

    pub(crate) fn capability_names(&self) -> Vec<super::MachPort> {
        self.entries
            .iter()
            .map(|entry| match entry {
                PreparedEntry::CoordinatorWriter(entry) => entry.peer_entry.name,
                PreparedEntry::ReceiverWriter(entry) => entry.peer_entry.name,
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

    pub(crate) fn revalidate_before_send(&self) -> Result<(), MacBatchError> {
        check_deadline(self.deadline)?;
        validate_prepared_entries(&self.entries, self.deadline)
    }

    pub(crate) fn activation_specs(&self) -> Result<Vec<MacActiveRegionSpec>, MacBatchError> {
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

    pub(crate) fn into_active_region_owners(self) -> Vec<MacActiveRegionOwner> {
        let native_page_size = page_size().expect("activation preflight validated page size");
        self.entries
            .into_iter()
            .map(|entry| match entry {
                PreparedEntry::CoordinatorWriter(entry) => {
                    let spec =
                        active_spec(entry.native, LocalRegionAuthority::Writer, &entry.mapping)
                            .expect("activation preflight validated coordinator mapping");
                    drop(entry.peer_entry);
                    MacActiveRegionOwner::Writer {
                        spec,
                        owner: Box::new(MacActiveWriteMapping {
                            mapping: entry.mapping,
                            page_size: native_page_size,
                            _not_sync: PhantomData,
                        }),
                    }
                }
                PreparedEntry::ReceiverWriter(entry) => {
                    let spec =
                        active_spec(entry.native, LocalRegionAuthority::Reader, &entry.mapping)
                            .expect("activation preflight validated receiver-writer mapping");
                    drop(entry.peer_entry);
                    MacActiveRegionOwner::Reader {
                        spec,
                        owner: Box::new(MacActiveReadMapping {
                            mapping: entry.mapping,
                            page_size: native_page_size,
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
    ) -> Result<Self, MacBatchError> {
        Self::prepare_inner(
            batch,
            NativeAuthorityProfile::MacMachV1,
            deadline,
            Some(failure_at),
        )
    }

    #[cfg(test)]
    pub(crate) fn copied_capabilities_for_test(
        &self,
    ) -> Result<Vec<bootstrap::SendRight>, bootstrap::BootstrapError> {
        self.capability_names()
            .into_iter()
            .map(bootstrap::SendRight::copy_existing)
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn write_coordinator_for_test(&mut self, ordinal: usize, offset: usize, value: u8) {
        let PreparedEntry::CoordinatorWriter(entry) = &mut self.entries[ordinal] else {
            panic!("test write requires a coordinator-writer entry");
        };
        assert!(offset < entry.native.logical_len as usize);
        // SAFETY: the batch is quiescent and owns the only writable local view.
        unsafe { core::ptr::write_volatile(entry.mapping.address.as_ptr().add(offset), value) };
    }

    #[cfg(test)]
    pub(crate) fn read_receiver_for_test(&self, ordinal: usize, offset: usize) -> u8 {
        let PreparedEntry::ReceiverWriter(entry) = &self.entries[ordinal] else {
            panic!("test read requires a receiver-writer entry");
        };
        assert!(offset < entry.native.logical_len as usize);
        // SAFETY: the exact local read-only mapping remains batch-owned.
        unsafe { core::ptr::read_volatile(entry.mapping.address.as_ptr().add(offset)) }
    }
}

#[derive(Clone, Copy)]
struct ExpectedEntry {
    id: RegionId,
    writer: WriterEndpoint,
    logical_len: usize,
    mapped_len: usize,
}

/// Receiver-owned canonical expectation fixed before any Mach right arrives.
pub(crate) struct MacExpectedMixedDirectionBatch {
    entries: Vec<ExpectedEntry>,
    total_logical: u64,
    total_mapped: u64,
    deadline: AbsoluteDeadline,
}

impl MacExpectedMixedDirectionBatch {
    pub(crate) fn new(
        expected: ExpectedBatch,
        limits: SessionLimits,
        deadline: AbsoluteDeadline,
    ) -> Result<Self, MacBatchError> {
        check_deadline(deadline)?;
        limits.validate().map_err(|_| MacBatchError::InvalidBatch)?;
        if expected.regions.len() > usize::from(limits.max_regions_per_batch)
            || expected.regions.len() as u64 > u64::from(limits.max_active_regions)
            || expected.total_logical > limits.max_batch_bytes
        {
            return Err(MacBatchError::InvalidBatch);
        }
        let native_page_size = page_size()?;
        let mut total_mapped = 0_u64;
        let mut entries = Vec::with_capacity(expected.regions.len());
        for region in expected.regions {
            if u64::try_from(region.logical_len).map_err(|_| MacBatchError::InvalidSize)?
                > limits.max_region_bytes
            {
                return Err(MacBatchError::InvalidSize);
            }
            let mapped_len = page_align(region.logical_len, native_page_size)?;
            total_mapped = total_mapped
                .checked_add(u64::try_from(mapped_len).map_err(|_| MacBatchError::InvalidSize)?)
                .ok_or(MacBatchError::InvalidSize)?;
            entries.push(ExpectedEntry {
                id: region.id,
                writer: region.writer,
                logical_len: region.logical_len,
                mapped_len,
            });
        }
        if total_mapped > limits.max_batch_bytes || total_mapped > limits.max_active_bytes {
            return Err(MacBatchError::InvalidSize);
        }
        Ok(Self {
            entries,
            total_logical: expected.total_logical,
            total_mapped,
            deadline,
        })
    }

    pub(crate) fn matches_manifest(&self, manifest: &TransferManifest) -> bool {
        manifest.authority_profile() == NativeAuthorityProfile::MacMachV1
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
        rights: Vec<bootstrap::SendRight>,
    ) -> Result<MacImportedMixedDirectionBatch, MacBatchError> {
        self.import_inner(manifest, rights, None)
    }

    fn import_inner(
        self,
        manifest: &TransferManifest,
        rights: Vec<bootstrap::SendRight>,
        failure_at: Option<usize>,
    ) -> Result<MacImportedMixedDirectionBatch, MacBatchError> {
        check_deadline(self.deadline)?;
        if rights.len() != self.entries.len() || !self.matches_manifest(manifest) {
            return Err(MacBatchError::WrongProvenance);
        }
        let mut seen_names = Vec::with_capacity(rights.len());
        let mut imported = Vec::with_capacity(rights.len());
        for (ordinal, ((expected, manifest_entry), right)) in self
            .entries
            .into_iter()
            .zip(manifest.entries().iter().copied())
            .zip(rights)
            .enumerate()
        {
            check_deadline(self.deadline)?;
            let name = right.name();
            if name == 0 || seen_names.contains(&name) {
                return Err(MacBatchError::WrongObject);
            }
            seen_names.push(name);
            let protection = match expected.writer {
                WriterEndpoint::Coordinator => VM_PROT_READ,
                WriterEndpoint::Receiver => VM_PROT_READ | VM_PROT_WRITE,
            };
            let mapping = map_exact_memory_entry(
                name,
                expected.mapped_len,
                protection,
                expected.writer == WriterEndpoint::Coordinator,
            )?;
            drop(right);
            if failure_at == Some(ordinal + 1) {
                drop(mapping);
                return Err(MacBatchError::WrongObject);
            }
            imported.push(match expected.writer {
                WriterEndpoint::Coordinator => ImportedEntry::CoordinatorWriter {
                    manifest: manifest_entry,
                    mapping,
                },
                WriterEndpoint::Receiver => ImportedEntry::ReceiverWriter {
                    manifest: manifest_entry,
                    mapping,
                },
            });
        }
        check_deadline(self.deadline)?;
        let batch = MacImportedMixedDirectionBatch { entries: imported };
        batch.activation_specs(self.deadline)?;
        Ok(batch)
    }

    #[cfg(test)]
    pub(crate) fn import_with_failure_for_test(
        self,
        manifest: &TransferManifest,
        rights: Vec<bootstrap::SendRight>,
        failure_at: usize,
    ) -> Result<MacImportedMixedDirectionBatch, MacBatchError> {
        self.import_inner(manifest, rights, Some(failure_at))
    }
}

enum ImportedEntry {
    CoordinatorWriter {
        manifest: ManifestEntry,
        mapping: Mapping,
    },
    ReceiverWriter {
        manifest: ManifestEntry,
        mapping: Mapping,
    },
}

/// Receiver-owned imported mappings withheld until full-batch commit.
pub(crate) struct MacImportedMixedDirectionBatch {
    entries: Vec<ImportedEntry>,
}

impl MacImportedMixedDirectionBatch {
    pub(crate) fn activation_specs(
        &self,
        deadline: AbsoluteDeadline,
    ) -> Result<Vec<MacActiveRegionSpec>, MacBatchError> {
        check_deadline(deadline)?;
        let mut specs = Vec::with_capacity(self.entries.len());
        for (ordinal, entry) in self.entries.iter().enumerate() {
            check_deadline(deadline)?;
            let spec = match entry {
                ImportedEntry::CoordinatorWriter { manifest, mapping } => {
                    validate_imported_manifest(*manifest, ordinal, 0, PeerAccess::ReadOnly)?;
                    active_spec_from_manifest(*manifest, LocalRegionAuthority::Reader, mapping)
                }
                ImportedEntry::ReceiverWriter { manifest, mapping } => {
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

    pub(crate) fn into_active_region_owners(self) -> Vec<MacActiveRegionOwner> {
        let native_page_size = page_size().expect("activation preflight validated page size");
        self.entries
            .into_iter()
            .map(|entry| match entry {
                ImportedEntry::CoordinatorWriter { manifest, mapping } => {
                    let spec =
                        active_spec_from_manifest(manifest, LocalRegionAuthority::Reader, &mapping)
                            .expect("activation preflight validated imported reader");
                    MacActiveRegionOwner::Reader {
                        spec,
                        owner: Box::new(MacActiveReadMapping {
                            mapping,
                            page_size: native_page_size,
                        }),
                    }
                }
                ImportedEntry::ReceiverWriter { manifest, mapping } => {
                    let spec =
                        active_spec_from_manifest(manifest, LocalRegionAuthority::Writer, &mapping)
                            .expect("activation preflight validated imported writer");
                    MacActiveRegionOwner::Writer {
                        spec,
                        owner: Box::new(MacActiveWriteMapping {
                            mapping,
                            page_size: native_page_size,
                            _not_sync: PhantomData,
                        }),
                    }
                }
            })
            .collect()
    }

    #[cfg(test)]
    pub(crate) fn read_coordinator_for_test(&self, ordinal: usize, offset: usize) -> u8 {
        let ImportedEntry::CoordinatorWriter { manifest, mapping } = &self.entries[ordinal] else {
            panic!("test read requires an imported coordinator-writer entry");
        };
        assert!(offset < manifest.logical_len as usize);
        // SAFETY: the imported read-only mapping remains batch-owned.
        unsafe { core::ptr::read_volatile(mapping.address.as_ptr().add(offset)) }
    }

    #[cfg(test)]
    pub(crate) fn write_receiver_for_test(&mut self, ordinal: usize, offset: usize, value: u8) {
        let ImportedEntry::ReceiverWriter { manifest, mapping } = &mut self.entries[ordinal] else {
            panic!("test write requires an imported receiver-writer entry");
        };
        assert!(offset < manifest.logical_len as usize);
        // SAFETY: the imported mapping is the receiver's only writable view.
        unsafe { core::ptr::write_volatile(mapping.address.as_ptr().add(offset), value) };
    }
}

fn validate_prepared_entries(
    entries: &[PreparedEntry],
    deadline: AbsoluteDeadline,
) -> Result<(), MacBatchError> {
    if entries.is_empty() || entries.len() > 16 {
        return Err(MacBatchError::InvalidBatch);
    }
    let mut previous = None;
    let mut names = Vec::with_capacity(entries.len());
    for entry in entries {
        check_deadline(deadline)?;
        let (native, mapping, name) = match entry {
            PreparedEntry::CoordinatorWriter(entry) => {
                (entry.native, &entry.mapping, entry.peer_entry.name)
            }
            PreparedEntry::ReceiverWriter(entry) => {
                (entry.native, &entry.mapping, entry.peer_entry.name)
            }
        };
        let id = RegionId::new(native.region_id).ok_or(MacBatchError::WrongProvenance)?;
        if previous.is_some_and(|previous| previous >= id)
            || name == 0
            || names.contains(&name)
            || native.logical_len == 0
            || native.logical_len > native.mapped_len
            || native.mapped_len != mapping.mapped_len as u64
        {
            return Err(MacBatchError::WrongProvenance);
        }
        previous = Some(id);
        names.push(name);
    }
    check_deadline(deadline)?;
    Ok(())
}

fn map_exact_memory_entry(
    name: super::MachPort,
    mapped_len: usize,
    protection: super::VmProt,
    require_read_only: bool,
) -> Result<Mapping, MacBatchError> {
    if require_read_only {
        match Mapping::map_port(
            current_task(),
            mapped_len,
            name,
            VM_PROT_READ | VM_PROT_WRITE,
        ) {
            Ok(excess) => {
                drop(excess);
                return Err(MacBatchError::WrongObject);
            }
            Err(super::MachError::Kernel {
                code: KERN_INVALID_RIGHT,
                ..
            }) => {}
            Err(error) => return Err(MacBatchError::Mach(error)),
        }
    }
    if mapping_allowed(name, mapped_len, protection | VM_PROT_EXECUTE)? {
        return Err(MacBatchError::WrongObject);
    }
    let larger_len = mapped_len
        .checked_add(page_size()?)
        .ok_or(MacBatchError::InvalidSize)?;
    match Mapping::map_port(current_task(), larger_len, name, protection) {
        Ok(larger) => {
            drop(larger);
            return Err(MacBatchError::WrongObject);
        }
        Err(super::MachError::Kernel {
            code: KERN_INVALID_ARGUMENT,
            ..
        }) => {}
        Err(error) => return Err(MacBatchError::Mach(error)),
    }
    Mapping::map_port(current_task(), mapped_len, name, protection).map_err(Into::into)
}

fn mapping_allowed(
    name: super::MachPort,
    mapped_len: usize,
    protection: super::VmProt,
) -> Result<bool, MacBatchError> {
    let mut address = 0;
    // SAFETY: this is a negative authority probe into a fresh anywhere mapping.
    // A successful mapping is synchronously deallocated before the result is
    // returned, and no pointer or authority escapes this function.
    let result = unsafe {
        mach_vm_map(
            current_task(),
            &mut address,
            mapped_len as super::MachVmSize,
            0,
            VM_FLAGS_ANYWHERE,
            name,
            0,
            0,
            protection,
            protection,
            VM_INHERIT_NONE,
        )
    };
    if result == super::KERN_SUCCESS {
        deallocate_mapping(current_task(), address, mapped_len);
        Ok(true)
    } else if result == KERN_INVALID_RIGHT {
        Ok(false)
    } else {
        Err(MacBatchError::Mach(super::MachError::Kernel {
            operation: "mach_vm_map(authority probe)",
            code: result,
        }))
    }
}

fn active_spec(
    native: NativeRegionSpec,
    authority: LocalRegionAuthority,
    mapping: &Mapping,
) -> Result<MacActiveRegionSpec, MacBatchError> {
    let id = RegionId::new(native.region_id).ok_or(MacBatchError::WrongProvenance)?;
    let logical_len =
        usize::try_from(native.logical_len).map_err(|_| MacBatchError::InvalidSize)?;
    let mapped_len = usize::try_from(native.mapped_len).map_err(|_| MacBatchError::InvalidSize)?;
    if logical_len == 0 || logical_len > mapped_len || mapped_len != mapping.mapped_len {
        return Err(MacBatchError::WrongProvenance);
    }
    Ok(MacActiveRegionSpec {
        id,
        logical_len,
        mapped_len,
        authority,
    })
}

fn active_spec_from_manifest(
    manifest: ManifestEntry,
    authority: LocalRegionAuthority,
    mapping: &Mapping,
) -> Result<MacActiveRegionSpec, MacBatchError> {
    let native = NativeRegionSpec::new(
        manifest.region_id,
        manifest.incarnation,
        manifest.writer,
        usize::try_from(manifest.logical_len).map_err(|_| MacBatchError::InvalidSize)?,
        usize::try_from(manifest.mapped_len).map_err(|_| MacBatchError::InvalidSize)?,
    )
    .ok_or(MacBatchError::WrongProvenance)?;
    active_spec(native, authority, mapping)
}

fn validate_imported_manifest(
    manifest: ManifestEntry,
    ordinal: usize,
    writer: u32,
    access: PeerAccess,
) -> Result<(), MacBatchError> {
    if manifest.ordinal as usize != ordinal
        || manifest.writer != writer
        || manifest.access != access
    {
        return Err(MacBatchError::WrongProvenance);
    }
    Ok(())
}

fn validate_active_specs(specs: &[MacActiveRegionSpec]) -> Result<(), MacBatchError> {
    if specs.is_empty() || specs.len() > 16 {
        return Err(MacBatchError::InvalidBatch);
    }
    if specs.windows(2).any(|pair| pair[0].id >= pair[1].id)
        || specs
            .iter()
            .any(|spec| spec.logical_len == 0 || spec.logical_len > spec.mapped_len)
    {
        return Err(MacBatchError::WrongProvenance);
    }
    Ok(())
}

fn check_deadline(deadline: AbsoluteDeadline) -> Result<(), MacBatchError> {
    if deadline.is_expired() {
        Err(MacBatchError::DeadlineExpired)
    } else {
        Ok(())
    }
}
