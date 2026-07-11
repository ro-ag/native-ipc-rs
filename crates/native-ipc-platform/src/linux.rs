//! Linux sealed-memfd mappings and authenticated descriptor transfer.

use std::ffi::OsStr;
use std::fmt;
use std::io;
use std::mem::{size_of, zeroed};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixListener;
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::ptr::NonNull;
use std::time::{Duration, Instant};

use native_ipc_core::layout::{RegionSetLayout, ValidatedRegionLayout, ValidationExpectations};
use native_ipc_core::mapping::{
    BindingError, ReadOnlyMapping, ReaderRegion, SoleWriterMapping, WriterRegion,
};

use crate::BackendStatus;

const REQUIRED_SEALS: libc::c_int =
    libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_FUTURE_WRITE | libc::F_SEAL_SEAL;
const FRAME_MAGIC: [u8; 8] = *b"NIPCFD\0\0";
const FRAME_LEN: usize = 48;
const TMPFS_MAGIC: libc::c_long = 0x0102_1994;
const ENV_SOCKET: &str = "NATIVE_IPC_LINUX_SOCKET";
const ENV_NONCE: &str = "NATIVE_IPC_SESSION_NONCE";
const ENV_PARENT_PID: &str = "NATIVE_IPC_PARENT_PID";

/// Linux mapping, descriptor-transfer, or peer-authentication failure.
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
    /// Received peer credentials differ from the expected live process.
    WrongPeer,
    /// Descriptor transfer frame was truncated, malformed, or stale.
    InvalidFrame,
    /// Received descriptor count or ancillary type was not exactly one SCM_RIGHTS fd.
    InvalidAncillaryData,
    /// Received capability lacks the exact anonymous sealed-shmem policy.
    InvalidCapability,
    /// Private bootstrap path, environment, or child process setup failed.
    Bootstrap,
    /// Quiescent core layout validation failed.
    Layout(native_ipc_core::layout::LayoutError),
    /// Audited core binding failed.
    Binding(BindingError),
}

/// Owned exact child process, authenticated control channel, and cleanup ledger.
pub struct ChildSession {
    child: Child,
    channel: AuthenticatedChannel,
    bootstrap_dir: PathBuf,
}

impl ChildSession {
    /// Spawns an exact helper executable and authenticates its post-exec connection.
    pub fn spawn(program: &OsStr, arguments: &[&OsStr]) -> Result<Self, LinuxError> {
        let mut nonce = [0_u8; 32];
        // SAFETY: output buffer is valid and flags zero request blocking system RNG.
        if unsafe { libc::getrandom(nonce.as_mut_ptr().cast(), nonce.len(), 0) }
            != nonce.len() as isize
        {
            return Err(last_os("getrandom"));
        }
        let suffix = hex(&nonce[..16]);
        let bootstrap_dir = std::env::temp_dir().join(format!("native-ipc-{suffix}"));
        std::fs::create_dir(&bootstrap_dir).map_err(|_| LinuxError::Bootstrap)?;
        std::fs::set_permissions(&bootstrap_dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|_| LinuxError::Bootstrap)?;
        let socket_path = bootstrap_dir.join("control.sock");
        let listener = UnixListener::bind(&socket_path).map_err(|_| LinuxError::Bootstrap)?;
        std::fs::set_permissions(&socket_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|_| LinuxError::Bootstrap)?;
        listener
            .set_nonblocking(true)
            .map_err(|_| LinuxError::Bootstrap)?;

        let mut command = Command::new(program);
        command
            .args(arguments)
            .env(ENV_SOCKET, &socket_path)
            .env(ENV_NONCE, hex(&nonce))
            .env(ENV_PARENT_PID, std::process::id().to_string());
        let mut child = command.spawn().map_err(|_| LinuxError::Bootstrap)?;
        let expected = PeerCredentials {
            pid: child.id(),
            // SAFETY: scalar identity syscalls have no preconditions.
            uid: unsafe { libc::geteuid() },
            // SAFETY: scalar identity syscalls have no preconditions.
            gid: unsafe { libc::getegid() },
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        let stream = loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    if peer_credentials(&stream)? == expected {
                        break stream;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Err(LinuxError::Bootstrap);
                    }
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => return Err(LinuxError::Bootstrap),
            }
        };
        let channel = AuthenticatedChannel::new(stream, expected, nonce)?;
        Ok(Self {
            child,
            channel,
            bootstrap_dir,
        })
    }

    /// Authenticated capability-transfer channel.
    pub const fn channel(&self) -> &AuthenticatedChannel {
        &self.channel
    }

    /// Child process identifier held live and unreaped by this session.
    pub fn child_id(&self) -> u32 {
        self.child.id()
    }

    /// Requests termination and reaps the owned child.
    pub fn terminate(mut self) -> Result<(), LinuxError> {
        self.child.kill().map_err(|_| LinuxError::Bootstrap)?;
        self.child.wait().map_err(|_| LinuxError::Bootstrap)?;
        Ok(())
    }
}

impl Drop for ChildSession {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.bootstrap_dir);
    }
}

/// Connects the spawned helper using inherited freshness and expected-parent data.
pub fn connect_spawned_helper() -> Result<AuthenticatedChannel, LinuxError> {
    let path = std::env::var_os(ENV_SOCKET).ok_or(LinuxError::Bootstrap)?;
    let nonce = parse_nonce(&std::env::var(ENV_NONCE).map_err(|_| LinuxError::Bootstrap)?)?;
    let parent_pid = std::env::var(ENV_PARENT_PID)
        .map_err(|_| LinuxError::Bootstrap)?
        .parse()
        .map_err(|_| LinuxError::Bootstrap)?;
    let stream = UnixStream::connect(path).map_err(|_| LinuxError::Bootstrap)?;
    let expected = PeerCredentials {
        pid: parent_pid,
        // SAFETY: scalar identity syscalls have no preconditions.
        uid: unsafe { libc::geteuid() },
        // SAFETY: scalar identity syscalls have no preconditions.
        gid: unsafe { libc::getegid() },
    };
    AuthenticatedChannel::new(stream, expected, nonce)
}

impl fmt::Display for LinuxError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "Linux transport failed: {self:?}")
    }
}

impl std::error::Error for LinuxError {}
impl From<native_ipc_core::layout::LayoutError> for LinuxError {
    fn from(value: native_ipc_core::layout::LayoutError) -> Self {
        Self::Layout(value)
    }
}
impl From<BindingError> for LinuxError {
    fn from(value: BindingError) -> Self {
        Self::Binding(value)
    }
}

/// Kernel-authenticated Unix peer identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerCredentials {
    /// Process ID captured by the kernel at connection time.
    pub pid: u32,
    /// Effective user identity.
    pub uid: u32,
    /// Effective group identity.
    pub gid: u32,
}

/// Authenticated private control channel with a pollable peer-lifecycle handle.
pub struct AuthenticatedChannel {
    stream: UnixStream,
    nonce: [u8; 32],
    peer: PeerCredentials,
    pidfd: OwnedFd,
}

impl AuthenticatedChannel {
    /// Authenticates an already-private post-exec Unix connection.
    pub fn new(
        stream: UnixStream,
        expected: PeerCredentials,
        nonce: [u8; 32],
    ) -> Result<Self, LinuxError> {
        let peer = peer_credentials(&stream)?;
        if peer != expected || nonce == [0; 32] {
            return Err(LinuxError::WrongPeer);
        }
        let pidfd = pidfd_open(peer.pid)?;
        Ok(Self {
            stream,
            nonce,
            peer,
            pidfd,
        })
    }

    /// Returns the kernel-authenticated peer credentials.
    pub const fn peer(&self) -> PeerCredentials {
        self.peer
    }

    /// Returns whether the peer pidfd currently reports exit without blocking.
    pub fn peer_exited(&self) -> Result<bool, LinuxError> {
        let mut poll = libc::pollfd {
            fd: self.pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `poll` points to one initialized entry for the call.
        let result = unsafe { libc::poll(&mut poll, 1, 0) };
        if result < 0 {
            return Err(last_os("poll(pidfd)"));
        }
        Ok(result == 1 && poll.revents != 0)
    }

    /// Sends one sealed reader capability with the session nonce and exact size.
    pub fn send(&self, capability: &ExportedReaderCapability) -> Result<(), LinuxError> {
        send_fd(
            &self.stream,
            &self.nonce,
            capability.len,
            capability.fd.as_raw_fd(),
        )
    }

    /// Receives, validates, maps, and binds one read-only capability.
    pub fn receive_reader(
        &self,
        expected_len: usize,
        expected: ValidationExpectations,
        topology: RegionSetLayout,
    ) -> Result<ReaderRegion<LinuxReaderMapping>, LinuxError> {
        let fd = receive_fd(&self.stream, &self.nonce, expected_len)?;
        LinuxReaderMapping::import(fd, expected_len, expected, topology)
    }
}

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
        let name = c"native-ipc";
        // SAFETY: static name is NUL-terminated and flags are valid.
        let raw = unsafe {
            libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING)
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
        let mapping = Mapping::map(fd.as_raw_fd(), len, libc::PROT_READ | libc::PROT_WRITE)?;
        // SAFETY: new mapping is exclusive and completely initialized by zero fill.
        unsafe { std::slice::from_raw_parts_mut(mapping.base.as_ptr(), len) }.fill(0);
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
    /// Returns whether the capability is empty (always false for valid values).
    pub const fn is_empty(&self) -> bool {
        false
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

    /// Validates, seals, and prepares the sole writer plus export capability.
    pub fn prepare_writer(
        self,
        expected: ValidationExpectations,
        topology: RegionSetLayout,
    ) -> Result<PreparedWriter, LinuxError> {
        // SAFETY: no descriptor or mapping has escaped this quiescent owner.
        let layout =
            unsafe { ValidatedRegionLayout::validate(self.as_bytes(), expected, &topology) }?;
        // SAFETY: descriptor is live and seal mask is valid.
        if unsafe { libc::fcntl(self.fd.as_raw_fd(), libc::F_ADD_SEALS, REQUIRED_SEALS) } < 0 {
            return Err(last_os("fcntl(F_ADD_SEALS)"));
        }
        validate_fd(self.fd.as_raw_fd(), self.mapping.len)?;
        Ok(PreparedWriter {
            mapping: LinuxWriterMapping {
                fd: self.fd,
                mapping: self.mapping,
            },
            layout,
            topology,
        })
    }
}

/// Sealed sole-writer mapping awaiting export/commit.
pub struct PreparedWriter {
    mapping: LinuxWriterMapping,
    layout: ValidatedRegionLayout,
    topology: RegionSetLayout,
}

impl PreparedWriter {
    /// Duplicates a sealed descriptor that can create only future read-only mappings.
    pub fn export_reader(&self) -> Result<ExportedReaderCapability, LinuxError> {
        // SAFETY: fcntl duplicates the live descriptor with close-on-exec.
        let raw = unsafe { libc::fcntl(self.mapping.fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        if raw < 0 {
            return Err(last_os("fcntl(F_DUPFD_CLOEXEC)"));
        }
        Ok(ExportedReaderCapability {
            // SAFETY: successful fcntl returned a new owned descriptor.
            fd: unsafe { OwnedFd::from_raw_fd(raw) },
            len: self.mapping.mapping.len,
        })
    }

    /// Commits the unique local writer into the audited core bridge.
    pub fn bind(self) -> Result<WriterRegion<LinuxWriterMapping>, LinuxError> {
        Ok(WriterRegion::new(self.mapping, self.layout, self.topology)?)
    }
}

/// Sealed descriptor intended for one authenticated reader transfer.
pub struct ExportedReaderCapability {
    fd: OwnedFd,
    len: usize,
}

/// Platform-minted sole-writer witness retaining the memfd and mapping lifetime.
pub struct LinuxWriterMapping {
    fd: OwnedFd,
    mapping: Mapping,
}
// SAFETY: construction requires an exclusive pre-seal mapping; FUTURE_WRITE
// prevents all later writable mappings and write-like fd operations.
unsafe impl SoleWriterMapping for LinuxWriterMapping {
    fn base(&self) -> NonNull<u8> {
        self.mapping.base
    }
    fn len(&self) -> usize {
        self.mapping.len
    }
}

/// Platform-minted read-only witness retaining the received fd and mapping.
pub struct LinuxReaderMapping {
    _fd: OwnedFd,
    mapping: Mapping,
}
// SAFETY: import maps only PROT_READ after exact anonymous-seal validation.
unsafe impl ReadOnlyMapping for LinuxReaderMapping {
    fn base(&self) -> NonNull<u8> {
        self.mapping.base
    }
    fn len(&self) -> usize {
        self.mapping.len
    }
}

impl LinuxReaderMapping {
    fn import(
        fd: OwnedFd,
        len: usize,
        expected: ValidationExpectations,
        topology: RegionSetLayout,
    ) -> Result<ReaderRegion<Self>, LinuxError> {
        validate_fd(fd.as_raw_fd(), len)?;
        let mapping = Mapping::map(fd.as_raw_fd(), len, libc::PROT_READ)?;
        mapping.advise()?;
        // SAFETY: READY/COMMIT protocol keeps the writer quiescent during import.
        let bytes = unsafe { std::slice::from_raw_parts(mapping.base.as_ptr(), len) };
        let layout = unsafe { ValidatedRegionLayout::validate(bytes, expected, &topology) }?;
        Ok(ReaderRegion::new(
            Self { _fd: fd, mapping },
            layout,
            topology,
        )?)
    }
}

struct Mapping {
    base: NonNull<u8>,
    len: usize,
}
impl Mapping {
    fn map(fd: RawFd, len: usize, protection: libc::c_int) -> Result<Self, LinuxError> {
        // SAFETY: arguments describe a checked file-backed shared mapping.
        let pointer = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                len,
                protection,
                libc::MAP_SHARED,
                fd,
                0,
            )
        };
        if pointer == libc::MAP_FAILED {
            return Err(last_os("mmap"));
        }
        let base = NonNull::new(pointer.cast()).ok_or(LinuxError::InvalidCapability)?;
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

fn validate_fd(fd: RawFd, expected_len: usize) -> Result<(), LinuxError> {
    // SAFETY: output structures are valid for the live descriptor.
    let mut stat: libc::stat = unsafe { zeroed() };
    if unsafe { libc::fstat(fd, &mut stat) } != 0 {
        return Err(last_os("fstat"));
    }
    let mut statfs: libc::statfs = unsafe { zeroed() };
    if unsafe { libc::fstatfs(fd, &mut statfs) } != 0 {
        return Err(last_os("fstatfs"));
    }
    // SAFETY: descriptor is live and command takes no pointer argument.
    let seals = unsafe { libc::fcntl(fd, libc::F_GET_SEALS) };
    if seals < 0
        || seals & REQUIRED_SEALS != REQUIRED_SEALS
        || stat.st_size != expected_len as libc::off_t
        || stat.st_nlink != 0
        || stat.st_mode & libc::S_IFMT != libc::S_IFREG
        || statfs.f_type != TMPFS_MAGIC
    {
        return Err(LinuxError::InvalidCapability);
    }
    Ok(())
}

fn peer_credentials(stream: &UnixStream) -> Result<PeerCredentials, LinuxError> {
    let mut credentials: libc::ucred = unsafe { zeroed() };
    let mut length = size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: output buffer and length pointer are valid.
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    } != 0
        || length as usize != size_of::<libc::ucred>()
    {
        return Err(last_os("getsockopt(SO_PEERCRED)"));
    }
    Ok(PeerCredentials {
        pid: credentials.pid as u32,
        uid: credentials.uid,
        gid: credentials.gid,
    })
}

fn pidfd_open(pid: u32) -> Result<OwnedFd, LinuxError> {
    // SAFETY: syscall has scalar arguments and returns a new fd on success.
    let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) } as libc::c_int;
    if raw < 0 {
        return Err(last_os("pidfd_open"));
    }
    // SAFETY: successful syscall returned an owned descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

fn send_fd(stream: &UnixStream, nonce: &[u8; 32], len: usize, fd: RawFd) -> Result<(), LinuxError> {
    let mut frame = [0_u8; FRAME_LEN];
    frame[..8].copy_from_slice(&FRAME_MAGIC);
    frame[8..16].copy_from_slice(&(len as u64).to_le_bytes());
    frame[16..48].copy_from_slice(nonce);
    let mut iovec = libc::iovec {
        iov_base: frame.as_mut_ptr().cast(),
        iov_len: frame.len(),
    };
    let control_len = unsafe { libc::CMSG_SPACE(size_of::<RawFd>() as u32) } as usize;
    let mut control = vec![0_u8; control_len];
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &mut iovec;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control.len();
    // SAFETY: message owns a suitably sized control buffer.
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(size_of::<RawFd>() as u32) as usize;
        std::ptr::write(libc::CMSG_DATA(header).cast::<RawFd>(), fd);
    }
    // SAFETY: iovec/control buffers remain live for the call.
    let sent = unsafe { libc::sendmsg(stream.as_raw_fd(), &message, libc::MSG_NOSIGNAL) };
    if sent != FRAME_LEN as isize {
        return Err(if sent < 0 {
            last_os("sendmsg")
        } else {
            LinuxError::InvalidFrame
        });
    }
    Ok(())
}

fn receive_fd(
    stream: &UnixStream,
    nonce: &[u8; 32],
    expected_len: usize,
) -> Result<OwnedFd, LinuxError> {
    let mut frame = [0_u8; FRAME_LEN];
    let mut iovec = libc::iovec {
        iov_base: frame.as_mut_ptr().cast(),
        iov_len: frame.len(),
    };
    let control_len = unsafe { libc::CMSG_SPACE(size_of::<RawFd>() as u32) } as usize;
    let mut control = vec![0_u8; control_len];
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &mut iovec;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control.len();
    // SAFETY: iovec/control buffers remain valid for the call.
    let received =
        unsafe { libc::recvmsg(stream.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) };
    if received != FRAME_LEN as isize
        || message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
        || frame[..8] != FRAME_MAGIC
        || frame[16..48] != *nonce
        || u64::from_le_bytes(frame[8..16].try_into().expect("fixed range")) != expected_len as u64
    {
        return Err(if received < 0 {
            last_os("recvmsg")
        } else {
            LinuxError::InvalidFrame
        });
    }
    // SAFETY: control buffer contains the kernel-produced cmsghdr chain.
    let header = unsafe { libc::CMSG_FIRSTHDR(&message) };
    if header.is_null()
        || unsafe { (*header).cmsg_level } != libc::SOL_SOCKET
        || unsafe { (*header).cmsg_type } != libc::SCM_RIGHTS
        || unsafe { (*header).cmsg_len }
            != unsafe { libc::CMSG_LEN(size_of::<RawFd>() as u32) } as usize
        || !unsafe { libc::CMSG_NXTHDR(&message, header) }.is_null()
    {
        return Err(LinuxError::InvalidAncillaryData);
    }
    // SAFETY: exact cmsg length proves one aligned fd payload.
    let raw = unsafe { std::ptr::read(libc::CMSG_DATA(header).cast::<RawFd>()) };
    if raw < 0 {
        return Err(LinuxError::InvalidAncillaryData);
    }
    // SAFETY: SCM_RIGHTS installed one new descriptor in this process.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
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

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(DIGITS[(byte >> 4) as usize] as char);
        encoded.push(DIGITS[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn parse_nonce(encoded: &str) -> Result<[u8; 32], LinuxError> {
    if encoded.len() != 64 {
        return Err(LinuxError::Bootstrap);
    }
    let mut nonce = [0_u8; 32];
    for (output, pair) in nonce.iter_mut().zip(encoded.as_bytes().chunks_exact(2)) {
        let high = (pair[0] as char)
            .to_digit(16)
            .ok_or(LinuxError::Bootstrap)?;
        let low = (pair[1] as char)
            .to_digit(16)
            .ok_or(LinuxError::Bootstrap)?;
        *output = ((high << 4) | low) as u8;
    }
    Ok(nonce)
}

fn last_os(operation: &'static str) -> LinuxError {
    LinuxError::Os {
        operation,
        code: io::Error::last_os_error().raw_os_error().unwrap_or(-1),
    }
}

/// Reports an enforced sealed-memfd backend on supported Linux kernels.
pub const fn status() -> BackendStatus {
    BackendStatus::Available
}

#[cfg(test)]
mod tests {
    use super::*;
    use native_ipc_core::layout::{
        AcknowledgementRouteSpec, Endpoint, LayoutLimits, RegionSpec, RoleId,
    };

    #[test]
    fn backend_reports_available() {
        assert_eq!(status(), BackendStatus::Available);
    }

    #[test]
    fn peer_credentials_are_kernel_derived() {
        let (left, right) = UnixStream::pair().unwrap();
        let expected = peer_credentials(&right).unwrap();
        let channel = AuthenticatedChannel::new(left, expected, [7; 32]).unwrap();
        assert_eq!(channel.peer(), expected);
    }

    #[test]
    fn sealed_capability_transfers_and_binds_payload_path() {
        let producer = RoleId::new(1).unwrap();
        let peer = RoleId::new(2).unwrap();
        let specs = [
            RegionSpec {
                role: producer,
                writer: Endpoint::Initiator,
                slot_count: 1,
                payload_bytes: 16,
                acknowledgement_count: 1,
            },
            RegionSpec {
                role: peer,
                writer: Endpoint::Responder,
                slot_count: 1,
                payload_bytes: 16,
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
            [5; 32],
            13,
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
        let layout = topology.region(producer).unwrap();
        let mut owner = QuiescentRegion::new(layout.total_size() as usize).unwrap();
        layout.encode_into(owner.as_bytes_mut()).unwrap();
        let expected = ValidationExpectations {
            schema_id: [5; 32],
            generation: 13,
            role: producer,
            writer: Endpoint::Initiator,
            maximum_mapping_size: owner.len() as u64,
        };
        let prepared = owner.prepare_writer(expected, topology.clone()).unwrap();
        let capability = prepared.export_reader().unwrap();

        // A sealed exported fd cannot create another writable mapping.
        let denied = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                capability.len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                capability.fd.as_raw_fd(),
                0,
            )
        };
        assert_eq!(denied, libc::MAP_FAILED);

        let (left, right) = UnixStream::pair().unwrap();
        let credentials = peer_credentials(&left).unwrap();
        let sender = AuthenticatedChannel::new(left, credentials, [8; 32]).unwrap();
        let receiver = AuthenticatedChannel::new(right, credentials, [8; 32]).unwrap();
        let reader = std::thread::scope(|scope| {
            let sent = scope.spawn(|| sender.send(&capability));
            let received =
                receiver.receive_reader(prepared.mapping.mapping.len, expected, topology.clone());
            sent.join().unwrap().unwrap();
            received.unwrap()
        });
        let mut writer = prepared.bind().unwrap();
        writer.publish(0, 1, None, b"linux").unwrap();
        assert_eq!(reader.copy_payload(0, 1).unwrap(), b"linux");
    }

    #[test]
    fn spawned_helper_is_pid_authenticated_and_owned() {
        let executable = std::env::current_exe().unwrap();
        let arguments = [
            OsStr::new("--exact"),
            OsStr::new("linux::tests::spawned_helper_entry"),
            OsStr::new("--ignored"),
            OsStr::new("--nocapture"),
        ];
        let session = ChildSession::spawn(executable.as_os_str(), &arguments).unwrap();
        assert_eq!(session.channel().peer().pid, session.child_id());
        session.terminate().unwrap();
    }

    #[test]
    #[ignore = "spawned only by the owned-child integration test"]
    fn spawned_helper_entry() {
        let channel = connect_spawned_helper().unwrap();
        assert_ne!(channel.peer().pid, 0);
        std::thread::sleep(Duration::from_secs(30));
    }
}
