//! Mach memory-entry backed shared regions.
//!
//! The ABI declarations and constants are transcribed from the macOS SDK's
//! Mach VM headers. Runtime typestates intentionally expose no byte slices.

use std::ffi::c_int;
use std::fmt;
use std::marker::PhantomData;
use std::ptr::NonNull;

use crate::protocol::{NativeRegionSpec, PeerAccess, TransferProvenance};
use native_ipc_core::layout::{
    LayoutError, RegionSetLayout, ValidatedRegionLayout, ValidationExpectations,
};
use native_ipc_core::mapping::{
    BindingError, ReadOnlyMapping, ReaderRegion, SoleWriterMapping, WriterRegion,
};

pub mod bootstrap;

type KernReturn = c_int;
type MachPort = u32;
type MachVmAddress = u64;
type MachVmSize = u64;
type MemoryObjectOffset = u64;
type MemoryObjectSize = u64;
type VmInherit = u32;
type VmProt = c_int;

const KERN_SUCCESS: KernReturn = 0;
const MACH_PORT_NULL: MachPort = 0;
const VM_FLAGS_ANYWHERE: c_int = 1;
const VM_PROT_READ: VmProt = 1;
const VM_PROT_WRITE: VmProt = 2;
const VM_PROT_EXECUTE: VmProt = 4;
const MAP_MEM_VM_SHARE: VmProt = 0x0040_0000;
const VM_INHERIT_NONE: VmInherit = 2;

unsafe extern "C" {
    static mach_task_self_: MachPort;

    fn getpagesize() -> c_int;
    fn mach_vm_allocate(
        target: MachPort,
        address: *mut MachVmAddress,
        size: MachVmSize,
        flags: c_int,
    ) -> KernReturn;
    fn mach_vm_deallocate(target: MachPort, address: MachVmAddress, size: MachVmSize)
    -> KernReturn;
    fn mach_vm_protect(
        target_task: MachPort,
        address: MachVmAddress,
        size: MachVmSize,
        set_maximum: c_int,
        new_protection: VmProt,
    ) -> KernReturn;
    fn mach_make_memory_entry_64(
        target_task: MachPort,
        size: *mut MemoryObjectSize,
        offset: MemoryObjectOffset,
        permission: VmProt,
        object_handle: *mut MachPort,
        parent_entry: MachPort,
    ) -> KernReturn;
    fn mach_vm_map(
        target_task: MachPort,
        address: *mut MachVmAddress,
        size: MachVmSize,
        mask: MachVmAddress,
        flags: c_int,
        object: MachPort,
        offset: MemoryObjectOffset,
        copy: c_int,
        current_protection: VmProt,
        maximum_protection: VmProt,
        inheritance: VmInherit,
    ) -> KernReturn;
    fn mach_port_deallocate(task: MachPort, name: MachPort) -> KernReturn;
}

/// Failure to create or restrict a Mach shared-memory capability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MachError {
    /// Shared regions cannot be empty.
    ZeroSize,
    /// Requested size cannot be page-aligned.
    SizeOverflow {
        /// Logical byte length that could not be page-aligned.
        requested: usize,
    },
    /// Transition size differs from the quiescent region.
    InvalidViewSize {
        /// Requested capability view length.
        requested: usize,
        /// Exact page-rounded region length.
        region: usize,
    },
    /// Kernel reported an invalid page size.
    InvalidPageSize(c_int),
    /// Successful allocation returned an unusable address.
    InvalidAddress(MachVmAddress),
    /// Successful memory-entry creation returned a null capability.
    NullMemoryEntry,
    /// Kernel changed an already aligned entry size.
    UnexpectedEntrySize {
        /// Requested page-rounded memory-entry size.
        expected: usize,
        /// Size returned by the Mach kernel.
        actual: u64,
    },
    /// Mach kernel call failed.
    Kernel {
        /// Operation name from this bounded implementation.
        operation: &'static str,
        /// Kernel status code.
        code: KernReturn,
    },
}

/// Failure while validating and binding a Mach mapping to the common core.
#[derive(Debug)]
pub enum MacBindingError {
    /// Quiescent bytes failed hostile layout validation.
    Layout(LayoutError),
    /// Mach typestate transition failed.
    Mach(MachError),
    /// Audited mapping-to-record binding failed.
    Binding(BindingError),
    /// Authenticated bootstrap or Mach port transfer failed.
    Bootstrap(bootstrap::BootstrapError),
    /// A pending value came from another channel or transfer transaction.
    ForeignPending,
}

impl fmt::Display for MacBindingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Mach/core binding failed: {self:?}")
    }
}

impl std::error::Error for MacBindingError {}
impl From<LayoutError> for MacBindingError {
    fn from(value: LayoutError) -> Self {
        Self::Layout(value)
    }
}
impl From<MachError> for MacBindingError {
    fn from(value: MachError) -> Self {
        Self::Mach(value)
    }
}
impl From<BindingError> for MacBindingError {
    fn from(value: BindingError) -> Self {
        Self::Binding(value)
    }
}
impl From<bootstrap::BootstrapError> for MacBindingError {
    fn from(value: bootstrap::BootstrapError) -> Self {
        Self::Bootstrap(value)
    }
}

impl fmt::Display for MachError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Mach shared memory operation failed: {self:?}")
    }
}

impl std::error::Error for MachError {}

/// Quiescent, pre-transfer owner of a zero-initialized Mach mapping.
///
/// This is the only typestate that exposes ordinary byte slices. Consuming it
/// chooses the one writer direction and permanently removes those accessors.
#[derive(Debug)]
pub struct QuiescentRegion {
    mapping: Mapping,
    logical_len: usize,
}

impl QuiescentRegion {
    /// Allocates a non-executable, zero-initialized Mach VM region.
    pub fn new(len: usize) -> Result<Self, MachError> {
        let page_size = page_size()?;
        let mapped_len = page_align(len, page_size)?;
        let task = current_task();
        let mut mapping = Mapping::allocate(task, mapped_len)?;
        // SAFETY: newly allocated mapping has no aliases or capabilities.
        unsafe { mapping.bytes_mut(mapped_len) }.fill(0);
        mapping.protect(VM_PROT_READ | VM_PROT_WRITE, false)?;
        mapping.protect(VM_PROT_READ | VM_PROT_WRITE, true)?;
        Ok(Self {
            mapping,
            logical_len: len,
        })
    }

    /// Returns the negotiated page-rounded capability length.
    pub const fn len(&self) -> usize {
        self.mapping.mapped_len
    }

    /// Returns the requested logical layout length within the capability.
    pub const fn logical_len(&self) -> usize {
        self.logical_len
    }

    /// Returns whether the logical region is empty (always false for a valid value).
    pub const fn is_empty(&self) -> bool {
        false
    }

    /// Borrows quiescent initialization bytes.
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: quiescent state has no peer capability or second mapping.
        unsafe { self.mapping.bytes(self.mapping.mapped_len) }
    }

    /// Mutably borrows quiescent initialization bytes.
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: quiescent state plus `&mut self` provides exclusive access.
        unsafe { self.mapping.bytes_mut(self.mapping.mapped_len) }
    }

    /// Selects this process as sole writer and creates one read-only peer entry.
    pub fn into_local_writer(self, expected_len: usize) -> Result<LocalWriterRegion, MachError> {
        self.validate_transition_size(expected_len)?;
        let peer_entry = MemoryEntry::<ReadOnlyCapability>::new(self.mapping.task, &self.mapping)?;
        Ok(LocalWriterRegion {
            mapping: self.mapping,
            peer_entry,
            len: expected_len,
        })
    }

    /// Selects the peer as sole writer and permanently downgrades this mapping.
    pub fn into_remote_writer(
        mut self,
        expected_len: usize,
    ) -> Result<RemoteWriterRegion, MachError> {
        self.validate_transition_size(expected_len)?;
        let peer_entry = MemoryEntry::<ReadWriteCapability>::new(self.mapping.task, &self.mapping)?;
        self.mapping.protect(VM_PROT_READ, false)?;
        self.mapping.protect(VM_PROT_READ, true)?;
        Ok(RemoteWriterRegion {
            mapping: self.mapping,
            peer_entry,
            len: expected_len,
        })
    }

    fn validate_transition_size(&self, expected_len: usize) -> Result<(), MachError> {
        if expected_len == self.mapping.mapped_len && expected_len != 0 {
            Ok(())
        } else {
            Err(MachError::InvalidViewSize {
                requested: expected_len,
                region: self.mapping.mapped_len,
            })
        }
    }

    /// Validates the complete padded capability, then consumes it as the sole writer.
    pub fn into_bound_local_writer(
        self,
        expected: ValidationExpectations,
        topology: RegionSetLayout,
    ) -> Result<WriterRegion<MacWriterMapping>, MacBindingError> {
        // SAFETY: quiescent typestate excludes peer aliases and validation sees
        // the exact page-rounded capability range that will be transferred.
        let layout =
            unsafe { ValidatedRegionLayout::validate(self.as_bytes(), expected, &topology) }?;
        let capability_len = self.len();
        let region = self.into_local_writer(capability_len)?;
        Ok(WriterRegion::new(
            MacWriterMapping { region },
            layout,
            topology,
        )?)
    }

    /// Validates the complete padded capability, then downgrades it to read-only.
    pub fn into_bound_remote_writer(
        self,
        expected: ValidationExpectations,
        topology: RegionSetLayout,
    ) -> Result<ReaderRegion<MacReaderMapping>, MacBindingError> {
        // SAFETY: same quiescent exact-capability proof as the local-writer path.
        let layout =
            unsafe { ValidatedRegionLayout::validate(self.as_bytes(), expected, &topology) }?;
        let capability_len = self.len();
        let region = self.into_remote_writer(capability_len)?;
        Ok(ReaderRegion::new(
            MacReaderMapping { region },
            layout,
            topology,
        )?)
    }

    /// Validates, transfers a read-only entry, and commits the local writer.
    ///
    /// The returned pending value has no payload API. Pass it as part of the
    /// exact batch to [`bootstrap::ParentChannel::commit_transfers`].
    ///
    /// # Errors
    ///
    /// Returns an error if layout validation, Mach permission attenuation,
    /// runtime binding, or authenticated capability transfer fails. Failure
    /// poisons the active parent transaction.
    pub fn transfer_local_writer(
        self,
        native: NativeRegionSpec,
        expected: ValidationExpectations,
        topology: RegionSetLayout,
        channel: &mut bootstrap::ParentChannel,
    ) -> Result<PendingTransferredWriter, MacBindingError> {
        let result = (|| {
            // SAFETY: quiescent state covers the exact transferred capability.
            let layout =
                unsafe { ValidatedRegionLayout::validate(self.as_bytes(), expected, &topology) }?;
            let capability_len = self.len();
            let region = self.into_local_writer(capability_len)?;
            let LocalWriterRegion {
                mapping,
                peer_entry,
                len: _,
            } = region;
            let runtime =
                WriterRegion::new(TransferredWriterMapping { mapping }, layout, topology)?;
            channel.send(peer_entry.name, native, PeerAccess::ReadOnly)?;
            drop(peer_entry);
            Ok(PendingTransferredWriter {
                runtime,
                provenance: channel.pending_provenance(),
            })
        })();
        if result.is_err() {
            channel.poison_transaction();
        }
        result
    }

    /// Validates, transfers the sole writer entry, and commits local read-only access.
    ///
    /// The local reader and peer writer remain pending until the batch commits.
    ///
    /// # Errors
    ///
    /// Returns an error if validation, permanent local protection downgrade,
    /// runtime binding, or authenticated capability transfer fails.
    pub fn transfer_remote_writer(
        self,
        native: NativeRegionSpec,
        expected: ValidationExpectations,
        topology: RegionSetLayout,
        channel: &mut bootstrap::ParentChannel,
    ) -> Result<PendingTransferredReader, MacBindingError> {
        let result = (|| {
            // SAFETY: quiescent state covers the exact transferred capability.
            let layout =
                unsafe { ValidatedRegionLayout::validate(self.as_bytes(), expected, &topology) }?;
            let capability_len = self.len();
            let region = self.into_remote_writer(capability_len)?;
            let RemoteWriterRegion {
                mapping,
                peer_entry,
                len: _,
            } = region;
            let runtime =
                ReaderRegion::new(TransferredReaderMapping { mapping }, layout, topology)?;
            channel.send(peer_entry.name, native, PeerAccess::SoleWriter)?;
            drop(peer_entry);
            Ok(PendingTransferredReader {
                runtime,
                provenance: channel.pending_provenance(),
            })
        })();
        if result.is_err() {
            channel.poison_transaction();
        }
        result
    }
}

/// Local writer withheld until the authenticated peer validates every import.
pub struct PendingTransferredWriter {
    runtime: WriterRegion<TransferredWriterMapping>,
    provenance: TransferProvenance,
}

/// Local reader withheld until the authenticated peer validates every import.
pub struct PendingTransferredReader {
    runtime: ReaderRegion<TransferredReaderMapping>,
    provenance: TransferProvenance,
}

/// Imported reader withheld until READY is acknowledged with COMMIT.
pub struct PendingImportedReader {
    runtime: ReaderRegion<ImportedReaderMapping>,
    provenance: TransferProvenance,
}

/// Imported writer withheld until READY is acknowledged with COMMIT.
pub struct PendingImportedWriter {
    runtime: WriterRegion<ImportedWriterMapping>,
    provenance: TransferProvenance,
}

/// Parent-side writer mapping after its read-only entry was transferred.
pub struct TransferredWriterMapping {
    mapping: Mapping,
}
// SAFETY: the only transferred right is kernel-clamped read-only; local mapping is unique RW.
unsafe impl SoleWriterMapping for TransferredWriterMapping {
    fn base(&self) -> NonNull<u8> {
        self.mapping.address
    }
    fn len(&self) -> usize {
        self.mapping.mapped_len
    }
}

/// Parent-side read-only mapping after the sole writer entry was transferred.
pub struct TransferredReaderMapping {
    mapping: Mapping,
}
// SAFETY: local current/maximum protection was permanently downgraded before transfer.
unsafe impl ReadOnlyMapping for TransferredReaderMapping {
    fn base(&self) -> NonNull<u8> {
        self.mapping.address
    }
    fn len(&self) -> usize {
        self.mapping.mapped_len
    }
}

/// Imported child-side read-only mapping.
pub struct ImportedReaderMapping {
    mapping: Mapping,
}
// SAFETY: mapping is created with current/maximum read-only protection.
unsafe impl ReadOnlyMapping for ImportedReaderMapping {
    fn base(&self) -> NonNull<u8> {
        self.mapping.address
    }
    fn len(&self) -> usize {
        self.mapping.mapped_len
    }
}

/// Imported child-side sole-writer mapping.
pub struct ImportedWriterMapping {
    mapping: Mapping,
}
// SAFETY: authenticated parent creates exactly one RW entry for this role.
unsafe impl SoleWriterMapping for ImportedWriterMapping {
    fn base(&self) -> NonNull<u8> {
        self.mapping.address
    }
    fn len(&self) -> usize {
        self.mapping.mapped_len
    }
}

impl bootstrap::ChildChannel {
    /// Receives and binds a read-only memory entry while the parent is quiescent.
    ///
    /// `len` is the exact page-rounded entry length. The result is a hidden
    /// runtime wrapper that becomes accessible only through [`Self::commit_imports`].
    ///
    /// # Errors
    ///
    /// Returns an error for transcript mismatch, mapping failure, layout
    /// rejection, or runtime binding failure and poisons the transaction.
    pub fn receive_reader(
        &mut self,
        len: usize,
        native: NativeRegionSpec,
        expected: ValidationExpectations,
        topology: RegionSetLayout,
    ) -> Result<PendingImportedReader, MacBindingError> {
        let result = (|| {
            let right = self.receive(native, PeerAccess::ReadOnly)?;
            let mapping = Mapping::map_port(current_task(), len, right.name(), VM_PROT_READ)?;
            // SAFETY: authenticated transfer remains quiescent until this call returns.
            let bytes = unsafe { mapping.bytes(len) };
            let layout = unsafe { ValidatedRegionLayout::validate(bytes, expected, &topology) }?;
            drop(right);
            Ok(PendingImportedReader {
                runtime: ReaderRegion::new(ImportedReaderMapping { mapping }, layout, topology)?,
                provenance: self.pending_provenance(),
            })
        })();
        if result.is_err() {
            self.poison_transaction();
        }
        result
    }

    /// Receives and binds the sole writable memory entry while quiescent.
    ///
    /// # Errors
    ///
    /// Returns an error for transcript mismatch, mapping failure, layout
    /// rejection, or runtime binding failure and poisons the transaction.
    pub fn receive_writer(
        &mut self,
        len: usize,
        native: NativeRegionSpec,
        expected: ValidationExpectations,
        topology: RegionSetLayout,
    ) -> Result<PendingImportedWriter, MacBindingError> {
        let result = (|| {
            let right = self.receive(native, PeerAccess::SoleWriter)?;
            let mapping = Mapping::map_port(
                current_task(),
                len,
                right.name(),
                VM_PROT_READ | VM_PROT_WRITE,
            )?;
            // SAFETY: authenticated transfer remains quiescent until this call returns.
            let bytes = unsafe { mapping.bytes(len) };
            let layout = unsafe { ValidatedRegionLayout::validate(bytes, expected, &topology) }?;
            drop(right);
            Ok(PendingImportedWriter {
                runtime: WriterRegion::new(ImportedWriterMapping { mapping }, layout, topology)?,
                provenance: self.pending_provenance(),
            })
        })();
        if result.is_err() {
            self.poison_transaction();
        }
        result
    }
}

impl bootstrap::ParentChannel {
    /// Consumes a complete two-region transfer, waits for peer validation, then
    /// sends COMMIT before exposing either local runtime capability.
    ///
    /// # Errors
    ///
    /// Returns an error if either pending value belongs to another channel or
    /// transfer transaction, if READY does not match the exact canonical batch,
    /// or if COMMIT cannot be sent unambiguously. The helper is terminated on
    /// failure.
    pub fn commit_transfers(
        &mut self,
        writer: PendingTransferredWriter,
        reader: PendingTransferredReader,
    ) -> Result<
        (
            WriterRegion<TransferredWriterMapping>,
            ReaderRegion<TransferredReaderMapping>,
        ),
        MacBindingError,
    > {
        let expected = self.pending_provenance();
        if writer.provenance != expected || reader.provenance != expected {
            self.poison_transaction();
            return Err(MacBindingError::ForeignPending);
        }
        self.ready_and_commit()?;
        Ok((writer.runtime, reader.runtime))
    }
}

impl bootstrap::ChildChannel {
    /// Signals validation, waits for creator COMMIT, and only then exposes the
    /// imported reader and sole-writer runtime capabilities.
    ///
    /// # Errors
    ///
    /// Returns an error if either pending value belongs to another channel or
    /// transfer transaction, if READY cannot be sent, or if the received COMMIT
    /// does not match the complete canonical batch.
    pub fn commit_imports(
        &mut self,
        reader: PendingImportedReader,
        writer: PendingImportedWriter,
    ) -> Result<
        (
            ReaderRegion<ImportedReaderMapping>,
            WriterRegion<ImportedWriterMapping>,
        ),
        MacBindingError,
    > {
        let expected = self.pending_provenance();
        if reader.provenance != expected || writer.provenance != expected {
            self.poison_transaction();
            return Err(MacBindingError::ForeignPending);
        }
        self.ready_and_wait_commit()?;
        Ok((reader.runtime, writer.runtime))
    }
}

/// Platform-minted sole-writer witness for the audited core bridge.
pub struct MacWriterMapping {
    region: LocalWriterRegion,
}

// SAFETY: `LocalWriterRegion` is consuming, owns the mapping lifetime, and its
// peer memory entry is kernel-clamped read-only.
unsafe impl SoleWriterMapping for MacWriterMapping {
    fn base(&self) -> NonNull<u8> {
        self.region.mapping.address
    }
    fn len(&self) -> usize {
        self.region.mapping.mapped_len
    }
}

/// Platform-minted local read-only witness for the audited core bridge.
pub struct MacReaderMapping {
    region: RemoteWriterRegion,
}

// SAFETY: `RemoteWriterRegion` permanently sets current and maximum local
// protection to read-only before construction and owns the mapping lifetime.
unsafe impl ReadOnlyMapping for MacReaderMapping {
    fn base(&self) -> NonNull<u8> {
        self.region.mapping.address
    }
    fn len(&self) -> usize {
        self.region.mapping.mapped_len
    }
}

/// Runtime region written locally and represented to the peer by a read-only entry.
///
/// The runtime state exposes identity only, not ordinary shared-memory slices.
#[derive(Debug)]
#[allow(dead_code)]
pub struct LocalWriterRegion {
    mapping: Mapping,
    peer_entry: MemoryEntry<ReadOnlyCapability>,
    len: usize,
}

impl LocalWriterRegion {
    /// Returns the logical region length without granting memory access.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns whether the logical region is empty.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Runtime region written remotely with a permanently read-only local mapping.
///
/// The runtime state exposes identity only, not ordinary shared-memory slices.
#[derive(Debug)]
#[allow(dead_code)]
pub struct RemoteWriterRegion {
    mapping: Mapping,
    peer_entry: MemoryEntry<ReadWriteCapability>,
    len: usize,
}

impl RemoteWriterRegion {
    /// Returns the logical region length without granting memory access.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns whether the logical region is empty.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }
}

#[derive(Debug)]
struct Mapping {
    task: MachPort,
    address: NonNull<u8>,
    mapped_len: usize,
}

// SAFETY: `Mapping` uniquely owns one Mach VM range. Moving that owner between
// threads neither duplicates the mapping nor creates Rust references to it.
unsafe impl Send for Mapping {}

impl Mapping {
    fn allocate(task: MachPort, mapped_len: usize) -> Result<Self, MachError> {
        let mut address = 0;
        // SAFETY: output pointer is valid and size was checked/page-aligned.
        let result = unsafe {
            mach_vm_allocate(
                task,
                &mut address,
                mapped_len as MachVmSize,
                VM_FLAGS_ANYWHERE,
            )
        };
        check_kernel("mach_vm_allocate", result)?;
        Self::from_allocated(task, address, mapped_len)
    }

    fn map_port(
        task: MachPort,
        mapped_len: usize,
        port: MachPort,
        protection: VmProt,
    ) -> Result<Self, MachError> {
        debug_assert_eq!(protection & VM_PROT_EXECUTE, 0);
        let mut address = 0;
        // SAFETY: entry is live; current/maximum protections exclude execute.
        let result = unsafe {
            mach_vm_map(
                task,
                &mut address,
                mapped_len as MachVmSize,
                0,
                VM_FLAGS_ANYWHERE,
                port,
                0,
                0,
                protection,
                protection,
                VM_INHERIT_NONE,
            )
        };
        check_kernel("mach_vm_map", result)?;
        Self::from_allocated(task, address, mapped_len)
    }

    fn protect(&mut self, protection: VmProt, set_maximum: bool) -> Result<(), MachError> {
        debug_assert_eq!(protection & VM_PROT_EXECUTE, 0);
        // SAFETY: mapping is live and no reference exists during transition.
        let result = unsafe {
            mach_vm_protect(
                self.task,
                self.address(),
                self.mapped_len as MachVmSize,
                c_int::from(set_maximum),
                protection,
            )
        };
        check_kernel("mach_vm_protect", result)
    }

    fn from_allocated(
        task: MachPort,
        address: MachVmAddress,
        mapped_len: usize,
    ) -> Result<Self, MachError> {
        let address_usize = match usize::try_from(address) {
            Ok(value) => value,
            Err(_) => {
                deallocate_mapping(task, address, mapped_len);
                return Err(MachError::InvalidAddress(address));
            }
        };
        let Some(address) = NonNull::new(address_usize as *mut u8) else {
            // VM_FLAGS_ANYWHERE never returns address zero; refuse the value
            // without speculatively deallocating the page-zero range this code
            // did not allocate.
            return Err(MachError::InvalidAddress(0));
        };
        Ok(Self {
            task,
            address,
            mapped_len,
        })
    }

    fn address(&self) -> MachVmAddress {
        self.address.as_ptr() as usize as MachVmAddress
    }

    unsafe fn bytes(&self, len: usize) -> &[u8] {
        assert!(len <= self.mapped_len && len <= isize::MAX as usize);
        // SAFETY: caller proves this address retains provenance from the live
        // Mach allocation, the range is initialized/readable for the returned
        // borrow, and neither process mutates it for that borrow's lifetime.
        unsafe { std::slice::from_raw_parts(self.address.as_ptr(), len) }
    }

    unsafe fn bytes_mut(&mut self, len: usize) -> &mut [u8] {
        assert!(len <= self.mapped_len && len <= isize::MAX as usize);
        // SAFETY: caller proves this address retains provenance from the live
        // Mach allocation and that the initialized/writable range has no local
        // or remote aliases for the returned exclusive borrow's lifetime.
        unsafe { std::slice::from_raw_parts_mut(self.address.as_ptr(), len) }
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        deallocate_mapping(self.task, self.address(), self.mapped_len);
        #[cfg(test)]
        observe_vnext_drop_for_test("mapping");
    }
}

#[derive(Debug)]
struct ReadOnlyCapability;
#[derive(Debug)]
struct ReadWriteCapability;

trait CapabilityAccess {
    const PROTECTION: VmProt;
}

impl CapabilityAccess for ReadOnlyCapability {
    const PROTECTION: VmProt = VM_PROT_READ;
}
impl CapabilityAccess for ReadWriteCapability {
    const PROTECTION: VmProt = VM_PROT_READ | VM_PROT_WRITE;
}

#[derive(Debug)]
struct MemoryEntry<Access> {
    task: MachPort,
    name: MachPort,
    _access: PhantomData<fn() -> Access>,
}

impl<Access: CapabilityAccess> MemoryEntry<Access> {
    fn new(task: MachPort, mapping: &Mapping) -> Result<Self, MachError> {
        let mut entry_size = mapping.mapped_len as MemoryObjectSize;
        let mut name = MACH_PORT_NULL;
        let permission = Access::PROTECTION | MAP_MEM_VM_SHARE;
        debug_assert_eq!(permission & VM_PROT_EXECUTE, 0);
        // SAFETY: out-pointers are valid; source is a live current-task mapping.
        let result = unsafe {
            mach_make_memory_entry_64(
                task,
                &mut entry_size,
                mapping.address(),
                permission,
                &mut name,
                MACH_PORT_NULL,
            )
        };
        if result != KERN_SUCCESS {
            if name != MACH_PORT_NULL {
                deallocate_port(task, name);
            }
            return Err(MachError::Kernel {
                operation: "mach_make_memory_entry_64",
                code: result,
            });
        }
        if name == MACH_PORT_NULL {
            return Err(MachError::NullMemoryEntry);
        }
        let entry = Self {
            task,
            name,
            _access: PhantomData,
        };
        if entry_size != mapping.mapped_len as MemoryObjectSize {
            return Err(MachError::UnexpectedEntrySize {
                expected: mapping.mapped_len,
                actual: entry_size,
            });
        }
        Ok(entry)
    }
}

impl<Access> Drop for MemoryEntry<Access> {
    fn drop(&mut self) {
        deallocate_port(self.task, self.name);
        #[cfg(test)]
        observe_vnext_drop_for_test("memory-entry");
    }
}

fn current_task() -> MachPort {
    // SAFETY: libSystem initializes this process-global task port name.
    unsafe { mach_task_self_ }
}

fn page_size() -> Result<usize, MachError> {
    // SAFETY: `getpagesize` has no caller obligations.
    let size = unsafe { getpagesize() };
    let Ok(converted) = usize::try_from(size) else {
        return Err(MachError::InvalidPageSize(size));
    };
    if converted == 0 || !converted.is_power_of_two() {
        return Err(MachError::InvalidPageSize(size));
    }
    Ok(converted)
}

fn page_align(size: usize, page_size: usize) -> Result<usize, MachError> {
    if size == 0 {
        return Err(MachError::ZeroSize);
    }
    let aligned = size
        .checked_add(page_size - 1)
        .map(|value| value & !(page_size - 1))
        .ok_or(MachError::SizeOverflow { requested: size })?;
    if aligned > isize::MAX as usize {
        return Err(MachError::SizeOverflow { requested: size });
    }
    Ok(aligned)
}

fn check_kernel(operation: &'static str, code: KernReturn) -> Result<(), MachError> {
    if code == KERN_SUCCESS {
        Ok(())
    } else {
        Err(MachError::Kernel { operation, code })
    }
}

fn deallocate_mapping(task: MachPort, address: MachVmAddress, mapped_len: usize) {
    // SAFETY: callers pass a mapping returned by Mach for this task.
    let _ = unsafe { mach_vm_deallocate(task, address, mapped_len as MachVmSize) };
}

fn deallocate_port(task: MachPort, name: MachPort) {
    // SAFETY: callers pass a live memory-entry send right in this task.
    let _ = unsafe { mach_port_deallocate(task, name) };
}

#[cfg(test)]
thread_local! {
    static VNEXT_DROP_OBSERVER: std::cell::RefCell<
        Option<std::sync::Arc<std::sync::Mutex<Vec<&'static str>>>>
    > = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn set_vnext_drop_observer_for_test(
    observer: Option<std::sync::Arc<std::sync::Mutex<Vec<&'static str>>>>,
) {
    VNEXT_DROP_OBSERVER.with(|slot| *slot.borrow_mut() = observer);
}

#[cfg(test)]
fn observe_vnext_drop_for_test(label: &'static str) {
    VNEXT_DROP_OBSERVER.with(|slot| {
        if let Some(observer) = slot.borrow().as_ref() {
            observer.lock().unwrap().push(label);
        }
    });
}

#[path = "macos_vnext/memory.rs"]
pub(crate) mod vnext_memory;

#[path = "macos_vnext/transport.rs"]
pub(crate) mod vnext_transport;

#[cfg(test)]
#[path = "macos_vnext/memory_test.rs"]
mod vnext_memory_test;

#[cfg(test)]
#[path = "macos_vnext/transport_test.rs"]
mod vnext_transport_test;

#[cfg(test)]
#[path = "macos_vnext/reducer_test.rs"]
mod vnext_reducer_test;

#[cfg(test)]
#[path = "macos_test.rs"]
mod tests;
