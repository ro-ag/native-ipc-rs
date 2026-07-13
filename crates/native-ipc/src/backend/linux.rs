//! Linux quiescent sealed-memfd allocation shared by the public facade and vNext.

use std::fmt;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::ptr::NonNull;

// Linux UAPI values introduced in 6.3; libc versions predating the headers do
// not expose them even though the running kernel supports the ABI.
const MFD_NOEXEC_SEAL: libc::c_uint = 0x0008;

/// Linux private-memory allocation failure.
#[derive(Debug)]
pub enum LinuxError {
    /// A native syscall failed with the captured errno.
    Os {
        /// Bounded syscall name.
        operation: &'static str,
        /// Captured platform errno.
        code: i32,
    },
    /// Requested mapping size is zero or cannot be page-rounded.
    InvalidSize(usize),
    /// The kernel returned a mapping address Rust cannot represent safely.
    InvalidCapability,
}

impl fmt::Display for LinuxError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Os { operation, code } => {
                write!(formatter, "Linux {operation} failed with errno {code}")
            }
            Self::InvalidSize(size) => write!(formatter, "invalid Linux mapping size {size}"),
            Self::InvalidCapability => {
                formatter.write_str("Linux returned an unrepresentable mapping")
            }
        }
    }
}

impl std::error::Error for LinuxError {}

/// Quiescent owner of an anonymous, page-rounded, writable memfd mapping.
pub struct QuiescentRegion {
    fd: OwnedFd,
    mapping: Mapping,
    logical_len: usize,
}

impl QuiescentRegion {
    /// Allocates and zeroes an anonymous sealable memfd mapping.
    pub fn new(logical_len: usize) -> Result<Self, LinuxError> {
        let len = page_align(logical_len)?;
        // SAFETY: static name is NUL-terminated and flags are valid.
        let raw = unsafe {
            libc::memfd_create(c"native-ipc".as_ptr(), libc::MFD_CLOEXEC | MFD_NOEXEC_SEAL)
        };
        if raw < 0 {
            return Err(last_os("memfd_create"));
        }
        // SAFETY: successful syscall returned a new owned descriptor.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        // SAFETY: descriptor is live and length was checked.
        if unsafe { libc::ftruncate(fd.as_raw_fd(), len as libc::off_t) } != 0 {
            return Err(last_os("ftruncate"));
        }
        let mapping = Mapping::map(fd.as_raw_fd(), len)?;
        // SAFETY: the new mapping is exclusive and live for the complete range.
        unsafe { std::ptr::write_bytes(mapping.base.as_ptr(), 0, len) };
        mapping.advise()?;
        Ok(Self {
            fd,
            mapping,
            logical_len,
        })
    }

    /// Exact page-rounded capability length.
    pub const fn len(&self) -> usize {
        self.mapping.len
    }

    /// Requested logical layout length.
    pub const fn logical_len(&self) -> usize {
        self.logical_len
    }

    /// Quiescent initialization bytes covering the full capability.
    pub fn as_bytes(&self) -> &[u8] {
        // SAFETY: this typestate has no exported fd or peer mapping.
        unsafe { std::slice::from_raw_parts(self.mapping.base.as_ptr(), self.mapping.len) }
    }

    /// Mutable quiescent initialization bytes covering the full capability.
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        // SAFETY: `&mut self` and quiescent typestate provide exclusivity.
        unsafe { std::slice::from_raw_parts_mut(self.mapping.base.as_ptr(), self.mapping.len) }
    }

    pub(crate) fn into_vnext_unmapped_parts(self) -> (OwnedFd, usize, usize) {
        let Self {
            fd,
            mapping,
            logical_len,
        } = self;
        let mapped_len = mapping.len;
        drop(mapping);
        (fd, logical_len, mapped_len)
    }

    pub(crate) fn as_raw_fd_for_vnext(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

struct Mapping {
    base: NonNull<u8>,
    len: usize,
}

impl Mapping {
    fn map(fd: RawFd, len: usize) -> Result<Self, LinuxError> {
        // SAFETY: arguments describe a checked file-backed shared mapping.
        let pointer = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        if pointer == libc::MAP_FAILED {
            return Err(last_os("mmap"));
        }
        let Some(base) = NonNull::new(pointer.cast()) else {
            // Rust slices cannot represent a live nonempty mapping at address
            // zero, so release it immediately before failing closed.
            // SAFETY: mmap succeeded for this exact range.
            let _ = unsafe { libc::munmap(pointer, len) };
            return Err(LinuxError::InvalidCapability);
        };
        Ok(Self { base, len })
    }

    fn advise(&self) -> Result<(), LinuxError> {
        for advice in [libc::MADV_DONTDUMP, libc::MADV_DONTFORK] {
            // SAFETY: mapping range is live for the complete call.
            if unsafe { libc::madvise(self.base.as_ptr().cast(), self.len, advice) } != 0 {
                return Err(last_os("madvise"));
            }
        }
        Ok(())
    }
}

impl Drop for Mapping {
    fn drop(&mut self) {
        // SAFETY: this object uniquely owns the live mapping.
        let _ = unsafe { libc::munmap(self.base.as_ptr().cast(), self.len) };
    }
}

fn page_align(size: usize) -> Result<usize, LinuxError> {
    if size == 0 {
        return Err(LinuxError::InvalidSize(size));
    }
    // SAFETY: sysconf has no pointer arguments.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page <= 0 {
        return Err(last_os("sysconf(_SC_PAGESIZE)"));
    }
    let page = page as usize;
    size.checked_add(page - 1)
        .map(|value| value & !(page - 1))
        .filter(|value| *value <= isize::MAX as usize)
        .ok_or(LinuxError::InvalidSize(size))
}

fn last_os(operation: &'static str) -> LinuxError {
    LinuxError::Os {
        operation,
        code: io::Error::last_os_error().raw_os_error().unwrap_or(-1),
    }
}

#[cfg(test)]
#[path = "linux_test.rs"]
mod tests;
