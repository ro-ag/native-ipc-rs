//! Fixed no-callback entry for one clean-exec Security authentication worker.

use std::ffi::{CStr, OsStr, c_char, c_int, c_void};
use std::fs::File;
use std::io::Read;
use std::mem::ManuallyDrop;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileTypeExt;

use super::auth_worker_spawn::{
    AUTH_WORKER_REQUEST_FD, AUTH_WORKER_RESULT_FD, INSTALLED_AUTH_WORKER_MODE,
    INSTALLED_AUTH_WORKER_PATH, INSTALLED_AUTH_WORKER_REQUEST_ARGUMENT,
    INSTALLED_AUTH_WORKER_RESULT_ARGUMENT,
};
use super::{AUTH_WORKER_JOB_BYTES, AuditToken, AuthWorkerJob, AuthWorkerResult};
use crate::backend::macos::supervisor::SupervisorDeadline;

const F_GETFD: c_int = 1;
const F_SETFD: c_int = 2;
const F_GETFL: c_int = 3;
const FD_CLOEXEC: c_int = 1;
const O_ACCMODE: c_int = 3;
const O_RDONLY: c_int = 0;
const O_WRONLY: c_int = 1;
const EINTR: c_int = 4;
const CF_STRING_ENCODING_UTF8: u32 = 0x0800_0100;
const SEC_SUCCESS: c_int = 0;
const RTLD_NOW: c_int = 0x2;
const RTLD_LOCAL: c_int = 0x4;

type CfType = *const c_void;
type CfDataCreateFn = unsafe extern "C" fn(CfType, *const u8, isize) -> CfType;
type CfDictionaryCreateFn = unsafe extern "C" fn(
    CfType,
    *const CfType,
    *const CfType,
    isize,
    *const c_void,
    *const c_void,
) -> CfType;
type CfReleaseFn = unsafe extern "C" fn(CfType);
type CfStringCreateWithCStringFn = unsafe extern "C" fn(CfType, *const c_char, u32) -> CfType;
type SecCodeCheckValidityFn = unsafe extern "C" fn(CfType, u32, CfType) -> c_int;
type SecCodeCopyGuestWithAttributesFn =
    unsafe extern "C" fn(CfType, CfType, u32, *mut CfType) -> c_int;
type SecRequirementCreateWithStringFn = unsafe extern "C" fn(CfType, u32, *mut CfType) -> c_int;

unsafe extern "C" {
    fn _exit(status: c_int) -> !;
    fn chdir(path: *const c_char) -> c_int;
    fn dlclose(handle: *mut c_void) -> c_int;
    fn dlopen(path: *const c_char, mode: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
    fn fcntl(fd: c_int, command: c_int, ...) -> c_int;
    fn write(fd: c_int, bytes: *const u8, length: usize) -> isize;
    fn umask(mask: u16) -> u16;
}

/// Runs one fixed clean-exec Security worker and never returns.
///
/// # Safety
///
/// This must be called directly by the separately packaged worker before
/// threads, callbacks, or Security.framework initialization. `requirement`
/// and `code_identity` must be compile-time constants in that signed artifact;
/// the requirement must be the immutable installed client requirement and the
/// nonzero identity must be the exact value installed in the service catalog.
/// The fixed spawner must exclusively transfer the request FIFO reader at FD3
/// and result FIFO writer at FD4 with the exact process vector.
pub(in crate::backend::macos) unsafe fn run_fixed_auth_worker_process(
    requirement: &CStr,
    code_identity: [u8; 32],
) -> ! {
    let status = match prepare_worker(code_identity) {
        Ok((mut request, result)) => {
            let outcome = run_worker(requirement, code_identity, &mut request, &result);
            // `result` deliberately has no close-on-drop path. It remains owned
            // in this never-returning scope even when `run_worker` rejects after
            // adopting FD4, so only process exit can produce result EOF.
            outcome.err().unwrap_or(0)
        }
        Err(status) => status,
    };
    // SAFETY: a one-job worker performs no user-space exit cleanup. A result
    // writer adopted above remains process-owned through this exact exit.
    unsafe { _exit(status.max(0)) }
}

fn prepare_worker(code_identity: [u8; 32]) -> Result<(File, ExitOwnedResultFd), c_int> {
    validate_fixed_arguments(std::env::args_os())?;
    if code_identity == [0; 32] {
        return Err(71);
    }
    let request = File::from(adopt_fixed_pipe(AUTH_WORKER_REQUEST_FD, O_RDONLY)?);
    let result = ExitOwnedResultFd::new(adopt_fixed_pipe(AUTH_WORKER_RESULT_FD, O_WRONLY)?);
    Ok((request, result))
}

fn run_worker(
    requirement: &CStr,
    code_identity: [u8; 32],
    request: &mut File,
    result: &ExitOwnedResultFd,
) -> Result<(), c_int> {
    // SAFETY: the path is one fixed NUL-terminated absolute directory and the
    // worker performs no caller-selected filesystem operation.
    if unsafe { chdir(c"/".as_ptr()) } != 0 {
        return Err(72);
    }
    // SAFETY: this process is a clean-exec single-threaded worker.
    let _ = unsafe { umask(0o077) };

    let mut bytes = [0_u8; AUTH_WORKER_JOB_BYTES];
    request.read_exact(&mut bytes).map_err(|_| 73)?;
    let mut extra = [0_u8; 1];
    if request.read(&mut extra).map_err(|_| 74)? != 0 {
        return Err(75);
    }
    let job = AuthWorkerJob::decode_pipe_frame(&bytes).map_err(|_| 76)?;
    ensure_deadline(job.deadline())?;
    let token = decode_audit_token(job.audit_identity());
    // SAFETY: the token was decoded from the canonical fixed job, and the BSM
    // functions accept one native audit_token_t by value.
    let uid = unsafe { super::audit_token_to_euid(token) };
    // SAFETY: same exact native token.
    let gid = unsafe { super::audit_token_to_egid(token) };
    if uid != job.effective_uid() || gid != job.effective_gid() {
        return Err(77);
    }
    let validated = security_validates(requirement, &job.audit_identity())?;
    ensure_deadline(job.deadline())?;
    let result_identity = if validated { code_identity } else { [0; 32] };
    // SAFETY: this worker just performed the only fixed Security validation on
    // the exact job audit token and will write only to its private result pipe.
    let response = unsafe { AuthWorkerResult::from_security_validation(job, result_identity) }
        .encode_pipe_frame()
        .map_err(|_| 78)?;
    write_one_frame(result.as_raw_fd(), &response)?;
    Ok(())
}

/// Result-pipe ownership that is released only by process teardown.
///
/// The fixed entry always ends in `_exit`; suppressing Rust drop here prevents
/// any post-adoption rejection from closing FD4 during error unwinding first.
struct ExitOwnedResultFd(ManuallyDrop<OwnedFd>);

impl ExitOwnedResultFd {
    fn new(descriptor: OwnedFd) -> Self {
        Self(ManuallyDrop::new(descriptor))
    }

    fn as_raw_fd(&self) -> c_int {
        self.0.as_raw_fd()
    }
}

fn validate_fixed_arguments(
    arguments: impl IntoIterator<Item = impl AsRef<OsStr>>,
) -> Result<(), c_int> {
    let actual = arguments
        .into_iter()
        .map(|argument| argument.as_ref().as_bytes().to_vec())
        .collect::<Vec<_>>();
    let expected = [
        INSTALLED_AUTH_WORKER_PATH.as_bytes(),
        INSTALLED_AUTH_WORKER_MODE.as_bytes(),
        INSTALLED_AUTH_WORKER_REQUEST_ARGUMENT.as_bytes(),
        INSTALLED_AUTH_WORKER_RESULT_ARGUMENT.as_bytes(),
    ];
    if actual.len() == expected.len()
        && actual
            .iter()
            .zip(expected)
            .all(|(actual, expected)| actual.as_slice() == expected)
    {
        Ok(())
    } else {
        Err(79)
    }
}

fn adopt_fixed_pipe(fd: c_int, access: c_int) -> Result<OwnedFd, c_int> {
    // SAFETY: F_GETFD is a read-only liveness query before ownership transfer.
    if unsafe { fcntl(fd, F_GETFD) } < 0 {
        return Err(80);
    }
    // SAFETY: the fixed process contract transfers sole ownership now.
    let owned = unsafe { OwnedFd::from_raw_fd(fd) };
    let file = File::from(owned);
    let metadata = file.metadata().map_err(|_| 81)?;
    if !metadata.file_type().is_fifo() {
        return Err(82);
    }
    // SAFETY: F_GETFL is a read-only query on the live descriptor.
    let flags = unsafe { fcntl(file.as_raw_fd(), F_GETFL) };
    if flags < 0 || flags & O_ACCMODE != access {
        return Err(83);
    }
    // SAFETY: transfer the still-live descriptor directly into OwnedFd.
    let owned = unsafe { OwnedFd::from_raw_fd(file.into_raw_fd()) };
    // SAFETY: the live fixed descriptor accepts close-on-exec.
    if unsafe { fcntl(owned.as_raw_fd(), F_SETFD, FD_CLOEXEC) } != 0 {
        return Err(84);
    }
    Ok(owned)
}

fn ensure_deadline(deadline: u64) -> Result<(), c_int> {
    SupervisorDeadline::from_wire(deadline)
        .to_local_instant()
        .map(|_| ())
        .map_err(|_| 85)
}

fn decode_audit_token(bytes: [u8; 32]) -> AuditToken {
    let mut values = [0_u32; 8];
    for (value, bytes) in values.iter_mut().zip(bytes.chunks_exact(4)) {
        *value = u32::from_ne_bytes(bytes.try_into().expect("exact chunk"));
    }
    AuditToken { values }
}

fn security_validates(requirement: &CStr, audit: &[u8; 32]) -> Result<bool, c_int> {
    // Loading happens only inside this clean-exec worker. Keeping framework
    // symbols out of the crate's static link prevents the permanent service
    // and unrelated helper binaries from initializing Security.framework.
    let frameworks = Frameworks::load()?;
    let requirement = FixedRequirement::new(requirement, &frameworks)?;
    // SAFETY: the exact 32 bytes remain live for CFDataCreate's copy.
    let data = unsafe {
        (frameworks.cf_data_create)(
            frameworks.allocator,
            audit.as_ptr(),
            isize::try_from(audit.len()).expect("audit token fits CFIndex"),
        )
    };
    let data = CfOwner::new(data, frameworks.cf_release).ok_or(86)?;
    let keys = [frameworks.audit_attribute];
    let values = [data.get()];
    // SAFETY: the one-element arrays and standard callbacks remain live; Core
    // Foundation retains/copies their contents into the dictionary.
    let attributes = unsafe {
        (frameworks.cf_dictionary_create)(
            frameworks.allocator,
            keys.as_ptr(),
            values.as_ptr(),
            1,
            frameworks.dictionary_key_callbacks,
            frameworks.dictionary_value_callbacks,
        )
    };
    let attributes = CfOwner::new(attributes, frameworks.cf_release).ok_or(87)?;
    let mut code = std::ptr::null();
    // SAFETY: output storage is valid; attributes contains only the exact audit
    // token, and no caller-controlled flag or host code is supplied.
    let lookup = unsafe {
        (frameworks.sec_code_copy_guest)(std::ptr::null(), attributes.get(), 0, &raw mut code)
    };
    let Some(code) = CfOwner::new(code, frameworks.cf_release) else {
        return Ok(false);
    };
    if lookup != SEC_SUCCESS {
        return Ok(false);
    }
    // SAFETY: code and requirement are live Security objects created above.
    Ok(
        unsafe { (frameworks.sec_code_check_validity)(code.get(), 0, requirement.get()) }
            == SEC_SUCCESS,
    )
}

struct FixedRequirement(CfOwner);

impl FixedRequirement {
    fn new(requirement: &CStr, frameworks: &Frameworks) -> Result<Self, c_int> {
        // SAFETY: requirement is one live NUL-terminated fixed artifact string.
        let text = unsafe {
            (frameworks.cf_string_create)(
                frameworks.allocator,
                requirement.as_ptr(),
                CF_STRING_ENCODING_UTF8,
            )
        };
        let text = CfOwner::new(text, frameworks.cf_release).ok_or(88)?;
        let mut parsed = std::ptr::null();
        // SAFETY: output storage and the fixed CF string are live.
        let status = unsafe { (frameworks.sec_requirement_create)(text.get(), 0, &raw mut parsed) };
        if status != SEC_SUCCESS {
            return Err(89);
        }
        CfOwner::new(parsed, frameworks.cf_release)
            .map(Self)
            .ok_or(90)
    }

    fn get(&self) -> CfType {
        self.0.get()
    }
}

struct Frameworks {
    core_foundation: *mut c_void,
    security: *mut c_void,
    allocator: CfType,
    dictionary_key_callbacks: *const c_void,
    dictionary_value_callbacks: *const c_void,
    audit_attribute: CfType,
    cf_data_create: CfDataCreateFn,
    cf_dictionary_create: CfDictionaryCreateFn,
    cf_release: CfReleaseFn,
    cf_string_create: CfStringCreateWithCStringFn,
    sec_code_check_validity: SecCodeCheckValidityFn,
    sec_code_copy_guest: SecCodeCopyGuestWithAttributesFn,
    sec_requirement_create: SecRequirementCreateWithStringFn,
}

impl Frameworks {
    fn load() -> Result<Self, c_int> {
        // SAFETY: both paths are fixed NUL-terminated system framework images.
        let core_foundation = unsafe {
            dlopen(
                c"/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation".as_ptr(),
                RTLD_NOW | RTLD_LOCAL,
            )
        };
        if core_foundation.is_null() {
            return Err(93);
        }
        // SAFETY: fixed system framework path and local eager binding.
        let security = unsafe {
            dlopen(
                c"/System/Library/Frameworks/Security.framework/Security".as_ptr(),
                RTLD_NOW | RTLD_LOCAL,
            )
        };
        if security.is_null() {
            // SAFETY: the first dlopen succeeded and owns this handle.
            let _ = unsafe { dlclose(core_foundation) };
            return Err(94);
        }
        // SAFETY: every symbol name and function signature below is the public
        // macOS SDK declaration for these fixed framework versions.
        unsafe { Self::from_handles(core_foundation, security) }
    }

    unsafe fn from_handles(
        core_foundation: *mut c_void,
        security: *mut c_void,
    ) -> Result<Self, c_int> {
        let loaded = (|| {
            let allocator_symbol = load_symbol(core_foundation, c"kCFAllocatorDefault")?;
            let audit_symbol = load_symbol(security, c"kSecGuestAttributeAudit")?;
            // SAFETY: these two public symbols are exported pointer-valued
            // constants; dlsym returns the address of their storage.
            let allocator = unsafe { allocator_symbol.cast::<CfType>().read() };
            // SAFETY: same pointer-valued constant rule for the Security key.
            let audit_attribute = unsafe { audit_symbol.cast::<CfType>().read() };
            // kCFAllocatorDefault is intentionally the null allocator value;
            // only the exported Security attribute key must be nonnull.
            if audit_attribute.is_null() {
                return Err(95);
            }
            Ok(Self {
                core_foundation,
                security,
                allocator,
                dictionary_key_callbacks: load_symbol(
                    core_foundation,
                    c"kCFTypeDictionaryKeyCallBacks",
                )?
                .cast_const(),
                dictionary_value_callbacks: load_symbol(
                    core_foundation,
                    c"kCFTypeDictionaryValueCallBacks",
                )?
                .cast_const(),
                audit_attribute,
                // SAFETY: each public symbol has the explicitly transcribed
                // SDK function signature named by its alias.
                cf_data_create: unsafe {
                    std::mem::transmute::<*mut c_void, CfDataCreateFn>(load_symbol(
                        core_foundation,
                        c"CFDataCreate",
                    )?)
                },
                // SAFETY: exact public SDK signature.
                cf_dictionary_create: unsafe {
                    std::mem::transmute::<*mut c_void, CfDictionaryCreateFn>(load_symbol(
                        core_foundation,
                        c"CFDictionaryCreate",
                    )?)
                },
                // SAFETY: exact public SDK signature.
                cf_release: unsafe {
                    std::mem::transmute::<*mut c_void, CfReleaseFn>(load_symbol(
                        core_foundation,
                        c"CFRelease",
                    )?)
                },
                // SAFETY: exact public SDK signature.
                cf_string_create: unsafe {
                    std::mem::transmute::<*mut c_void, CfStringCreateWithCStringFn>(load_symbol(
                        core_foundation,
                        c"CFStringCreateWithCString",
                    )?)
                },
                // SAFETY: exact public SDK signature.
                sec_code_check_validity: unsafe {
                    std::mem::transmute::<*mut c_void, SecCodeCheckValidityFn>(load_symbol(
                        security,
                        c"SecCodeCheckValidity",
                    )?)
                },
                // SAFETY: exact public SDK signature.
                sec_code_copy_guest: unsafe {
                    std::mem::transmute::<*mut c_void, SecCodeCopyGuestWithAttributesFn>(
                        load_symbol(security, c"SecCodeCopyGuestWithAttributes")?,
                    )
                },
                // SAFETY: exact public SDK signature.
                sec_requirement_create: unsafe {
                    std::mem::transmute::<*mut c_void, SecRequirementCreateWithStringFn>(
                        load_symbol(security, c"SecRequirementCreateWithString")?,
                    )
                },
            })
        })();
        if loaded.is_err() {
            // SAFETY: both handles were successfully opened and no CF object
            // escaped from this failed symbol-loading path.
            let _ = unsafe { dlclose(security) };
            // SAFETY: same for the Core Foundation handle.
            let _ = unsafe { dlclose(core_foundation) };
        }
        loaded
    }
}

impl Drop for Frameworks {
    fn drop(&mut self) {
        // All CF/Security owners are declared after this API value and drop
        // before it, so both framework handles may now be released.
        // SAFETY: this object owns both successful dlopen handles.
        let _ = unsafe { dlclose(self.security) };
        // SAFETY: same for Core Foundation.
        let _ = unsafe { dlclose(self.core_foundation) };
    }
}

fn load_symbol(handle: *mut c_void, name: &CStr) -> Result<*mut c_void, c_int> {
    // SAFETY: handle is one live framework and name is NUL-terminated.
    let symbol = unsafe { dlsym(handle, name.as_ptr()) };
    if symbol.is_null() {
        Err(96)
    } else {
        Ok(symbol)
    }
}

struct CfOwner {
    value: CfType,
    release: CfReleaseFn,
}

impl CfOwner {
    fn new(value: CfType, release: CfReleaseFn) -> Option<Self> {
        (!value.is_null()).then_some(Self { value, release })
    }

    const fn get(&self) -> CfType {
        self.value
    }
}

impl Drop for CfOwner {
    fn drop(&mut self) {
        // SAFETY: this owner holds one nonnull Core Foundation object reference.
        unsafe { (self.release)(self.value) };
    }
}

fn write_one_frame(fd: c_int, bytes: &[u8]) -> Result<(), c_int> {
    loop {
        // SAFETY: fd is the sole blocking result writer and the fixed frame is
        // no larger than Darwin PIPE_BUF, so a successful write is atomic.
        let written = unsafe { write(fd, bytes.as_ptr(), bytes.len()) };
        if written == isize::try_from(bytes.len()).expect("result frame fits isize") {
            return Ok(());
        }
        if written >= 0 {
            return Err(91);
        }
        if last_errno() != EINTR {
            return Err(92);
        }
    }
}

fn last_errno() -> c_int {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(1)
}

#[cfg(test)]
#[path = "supervisor_auth_worker_entry_test.rs"]
mod tests;
