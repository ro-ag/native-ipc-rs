//! Private native backend implementations.

#[cfg(target_os = "linux")]
#[allow(dead_code)]
pub(crate) mod linux;
#[cfg(target_os = "macos")]
#[allow(dead_code)]
pub(crate) mod macos;
#[cfg(target_os = "windows")]
#[allow(dead_code)]
pub(crate) mod windows;

#[cfg(target_os = "linux")]
pub(crate) fn mint_incarnation() -> Result<[u8; 16], ()> {
    let mut bytes = [0_u8; 16];
    let mut filled = 0;
    while filled < bytes.len() {
        // SAFETY: the remaining byte slice is writable for the supplied length.
        let result = unsafe {
            libc::getrandom(bytes[filled..].as_mut_ptr().cast(), bytes.len() - filled, 0)
        };
        if result < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(());
        }
        if result == 0 {
            return Err(());
        }
        filled += usize::try_from(result).map_err(|_| ())?;
    }
    (bytes != [0; 16]).then_some(bytes).ok_or(())
}

#[cfg(target_os = "macos")]
pub(crate) fn mint_incarnation() -> Result<[u8; 16], ()> {
    unsafe extern "C" {
        fn arc4random_buf(buffer: *mut core::ffi::c_void, length: usize);
    }
    let mut bytes = [0_u8; 16];
    // SAFETY: `bytes` is writable for exactly its length; arc4random_buf has no
    // failure return and fills caller-owned storage.
    unsafe { arc4random_buf(bytes.as_mut_ptr().cast(), bytes.len()) };
    (bytes != [0; 16]).then_some(bytes).ok_or(())
}

#[cfg(target_os = "windows")]
pub(crate) fn mint_incarnation() -> Result<[u8; 16], ()> {
    use windows_sys::Win32::Security::Cryptography::{
        BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
    };
    let mut bytes = [0_u8; 16];
    // SAFETY: the system-preferred RNG accepts a null algorithm handle and the
    // output buffer is writable for exactly the supplied length.
    let status = unsafe {
        BCryptGenRandom(
            core::ptr::null_mut(),
            bytes.as_mut_ptr(),
            bytes.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status != 0 || bytes == [0; 16] {
        return Err(());
    }
    Ok(bytes)
}
