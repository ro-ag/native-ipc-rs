//! Mach memory-entry backed shared regions.
//!
//! The ABI declarations and constants are transcribed from the macOS SDK's
//! Mach VM headers. Runtime typestates intentionally expose no byte slices.

use std::ffi::c_int;
use std::fmt;
use std::marker::PhantomData;
use std::ptr::NonNull;

type KernReturn = c_int;
type MachPort = u32;
type MachVmAddress = u64;
type MachVmSize = u64;
type MemoryObjectOffset = u64;
type MemoryObjectSize = u64;
#[cfg(test)]
type VmInherit = u32;
type VmProt = c_int;

const KERN_SUCCESS: KernReturn = 0;
const MACH_PORT_NULL: MachPort = 0;
const VM_FLAGS_ANYWHERE: c_int = 1;
const VM_PROT_READ: VmProt = 1;
const VM_PROT_WRITE: VmProt = 2;
const VM_PROT_EXECUTE: VmProt = 4;
const MAP_MEM_VM_SHARE: VmProt = 0x0040_0000;
#[cfg(test)]
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
    #[cfg(test)]
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
#[allow(missing_docs)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MachError {
    /// Shared regions cannot be empty.
    ZeroSize,
    /// Requested size cannot be page-aligned.
    SizeOverflow { requested: usize },
    /// Transition size differs from the quiescent region.
    InvalidViewSize { requested: usize, region: usize },
    /// Kernel reported an invalid page size.
    InvalidPageSize(c_int),
    /// Successful allocation returned an unusable address.
    InvalidAddress(MachVmAddress),
    /// Successful memory-entry creation returned a null capability.
    NullMemoryEntry,
    /// Kernel changed an already aligned entry size.
    UnexpectedEntrySize { expected: usize, actual: u64 },
    /// Mach kernel call failed.
    Kernel {
        /// Operation name from this bounded implementation.
        operation: &'static str,
        /// Kernel status code.
        code: KernReturn,
    },
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
    len: usize,
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
        Ok(Self { mapping, len })
    }

    /// Returns the logical, unpadded length.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Returns whether the logical region is empty (always false for a valid value).
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Borrows quiescent initialization bytes.
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: quiescent state has no peer capability or second mapping.
        unsafe { self.mapping.bytes(self.len) }
    }

    /// Mutably borrows quiescent initialization bytes.
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: quiescent state plus `&mut self` provides exclusive access.
        unsafe { self.mapping.bytes_mut(self.len) }
    }

    /// Selects this process as sole writer and creates one read-only peer entry.
    pub fn into_local_writer(self, expected_len: usize) -> Result<LocalWriterRegion, MachError> {
        self.validate_transition_size(expected_len)?;
        let peer_entry = MemoryEntry::<ReadOnlyCapability>::new(self.mapping.task, &self.mapping)?;
        Ok(LocalWriterRegion {
            mapping: self.mapping,
            peer_entry,
            len: self.len,
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
            len: self.len,
        })
    }

    fn validate_transition_size(&self, expected_len: usize) -> Result<(), MachError> {
        if expected_len == self.len && expected_len != 0 {
            Ok(())
        } else {
            Err(MachError::InvalidViewSize {
                requested: expected_len,
                region: self.len,
            })
        }
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

    #[cfg(test)]
    fn map_entry<Access: CapabilityAccess>(
        task: MachPort,
        mapped_len: usize,
        entry: &MemoryEntry<Access>,
    ) -> Result<Self, MachError> {
        let protection = Access::PROTECTION;
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
                entry.name,
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
            deallocate_mapping(task, 0, mapped_len);
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
mod tests {
    use super::*;
    use std::mem::size_of;

    #[test]
    fn read_only_capability_rejects_writable_mapping() {
        let owner = QuiescentRegion::new(37).unwrap();
        let runtime = owner.into_local_writer(37).unwrap();
        let mut address = 0;
        let protection = VM_PROT_READ | VM_PROT_WRITE;
        // SAFETY: deliberately bypasses typed API to probe kernel enforcement.
        let result = unsafe {
            mach_vm_map(
                runtime.mapping.task,
                &mut address,
                runtime.mapping.mapped_len as MachVmSize,
                0,
                VM_FLAGS_ANYWHERE,
                runtime.peer_entry.name,
                0,
                0,
                protection,
                protection,
                VM_INHERIT_NONE,
            )
        };
        if result == KERN_SUCCESS {
            deallocate_mapping(runtime.mapping.task, address, runtime.mapping.mapped_len);
        }
        assert_ne!(result, KERN_SUCCESS);
    }

    #[test]
    fn executable_protection_upgrade_is_rejected() {
        let owner = QuiescentRegion::new(37).unwrap();
        let runtime = owner.into_local_writer(37).unwrap();
        // SAFETY: deliberately requests execute to probe the clamped maximum.
        let result = unsafe {
            mach_vm_protect(
                runtime.mapping.task,
                runtime.mapping.address(),
                runtime.mapping.mapped_len as MachVmSize,
                0,
                VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE,
            )
        };
        assert_ne!(result, KERN_SUCCESS);
    }

    #[test]
    fn remote_writer_downgrades_local_mapping_before_escape() {
        let mut owner = QuiescentRegion::new(19).unwrap();
        owner.as_bytes_mut()[0] = 7;
        let mut runtime = owner.into_remote_writer(19).unwrap();
        assert!(
            runtime
                .mapping
                .protect(VM_PROT_READ | VM_PROT_WRITE, false)
                .is_err()
        );
        let mut peer = Mapping::map_entry(
            runtime.mapping.task,
            runtime.mapping.mapped_len,
            &runtime.peer_entry,
        )
        .unwrap();
        // SAFETY: peer test mapping is the sole writer while quiescent.
        let peer_bytes = unsafe { peer.bytes_mut(19) };
        peer_bytes[3..8].copy_from_slice(b"world");
        drop(peer);
        // SAFETY: peer mapping is gone; immutable test snapshot is quiescent.
        assert_eq!(&unsafe { runtime.mapping.bytes(19) }[3..8], b"world");
    }

    #[test]
    fn local_writer_peer_observes_quiescent_initialization() {
        let mut owner = QuiescentRegion::new(37).unwrap();
        owner.as_bytes_mut()[..5].copy_from_slice(b"hello");
        let runtime = owner.into_local_writer(37).unwrap();
        let peer = Mapping::map_entry(
            runtime.mapping.task,
            runtime.mapping.mapped_len,
            &runtime.peer_entry,
        )
        .unwrap();
        // SAFETY: local writer is quiescent during immutable test snapshot.
        assert_eq!(&unsafe { peer.bytes(37) }[..5], b"hello");
    }

    #[test]
    fn rejects_bad_sizes_and_matches_sdk_scalars() {
        assert_eq!(QuiescentRegion::new(0).unwrap_err(), MachError::ZeroSize);
        assert_eq!(
            page_align(usize::MAX, 4096).unwrap_err(),
            MachError::SizeOverflow {
                requested: usize::MAX
            }
        );
        assert_eq!(size_of::<MachPort>(), 4);
        assert_eq!(size_of::<MachVmAddress>(), 8);
        assert_eq!(ReadOnlyCapability::PROTECTION, VM_PROT_READ);
        assert_eq!(
            ReadWriteCapability::PROTECTION,
            VM_PROT_READ | VM_PROT_WRITE
        );
    }
}
