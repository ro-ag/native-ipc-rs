use super::*;

const F_SEAL_EXEC: libc::c_int = 0x0020;

#[test]
fn invalid_sizes_fail_exactly() {
    assert!(matches!(
        QuiescentRegion::new(0),
        Err(LinuxError::InvalidSize(0))
    ));
    assert!(matches!(
        QuiescentRegion::new(usize::MAX),
        Err(LinuxError::InvalidSize(usize::MAX))
    ));
}

#[test]
fn quiescent_region_is_zeroed_page_rounded_and_vnext_ready() {
    let logical_len = 37;
    let mut region = QuiescentRegion::new(logical_len).unwrap();
    let mapped_len = region.len();
    // SAFETY: sysconf has no pointer arguments.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;

    assert_eq!(region.logical_len(), logical_len);
    assert_eq!(mapped_len % page, 0);
    assert!(mapped_len >= logical_len);
    assert!(region.as_bytes().iter().all(|byte| *byte == 0));
    region.as_bytes_mut()[..4].copy_from_slice(b"NIPC");

    // SAFETY: the descriptor is live and both commands take scalar arguments.
    let descriptor_flags = unsafe { libc::fcntl(region.as_raw_fd_for_vnext(), libc::F_GETFD) };
    // SAFETY: the descriptor is live and this command takes no pointer argument.
    let seals = unsafe { libc::fcntl(region.as_raw_fd_for_vnext(), libc::F_GET_SEALS) };
    assert_ne!(descriptor_flags & libc::FD_CLOEXEC, 0);
    assert_ne!(seals & F_SEAL_EXEC, 0);

    let (fd, original_logical_len, original_mapped_len) = region.into_vnext_unmapped_parts();
    assert_eq!(original_logical_len, logical_len);
    assert_eq!(original_mapped_len, mapped_len);
    // SAFETY: status is complete writable output for the live descriptor.
    let mut status: libc::stat = unsafe { core::mem::zeroed() };
    assert_eq!(unsafe { libc::fstat(fd.as_raw_fd(), &mut status) }, 0);
    assert_eq!(status.st_size, mapped_len as libc::off_t);
}
