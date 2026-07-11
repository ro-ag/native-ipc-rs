//! Linux sealed-memfd mappings and authenticated descriptor transfer.

use std::ffi::OsStr;
use std::fmt;
use std::io::{self, Write};
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
use crate::protocol::{CONTROL_FRAME_LEN, ManifestEntry, PeerAccess, TransferManifest};

const REQUIRED_SEALS: libc::c_int =
    libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_FUTURE_WRITE | libc::F_SEAL_SEAL;
const CAPABILITY_MAGIC: [u8; 8] = *b"NIPCFD\0\0";
const READY_MAGIC: [u8; 8] = *b"NIPCRDY1";
const COMMIT_MAGIC: [u8; 8] = *b"NIPCCMT1";
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

    /// Exclusive transaction access to the authenticated capability channel.
    pub const fn channel_mut(&mut self) -> &mut AuthenticatedChannel {
        &mut self.channel
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
    AuthenticatedChannel::new_with_identity(stream, expected, nonce, parent_pid, std::process::id())
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
    parent_pid: u32,
    child_pid: u32,
    next_transfer_id: u64,
    poisoned: bool,
}

impl AuthenticatedChannel {
    /// Authenticates an already-private post-exec Unix connection.
    pub fn new(
        stream: UnixStream,
        expected: PeerCredentials,
        nonce: [u8; 32],
    ) -> Result<Self, LinuxError> {
        Self::new_with_identity(stream, expected, nonce, std::process::id(), expected.pid)
    }

    fn new_with_identity(
        stream: UnixStream,
        expected: PeerCredentials,
        nonce: [u8; 32],
        parent_pid: u32,
        child_pid: u32,
    ) -> Result<Self, LinuxError> {
        let peer = peer_credentials(&stream)?;
        if peer != expected || nonce == [0; 32] {
            return Err(LinuxError::WrongPeer);
        }
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .map_err(|_| LinuxError::Bootstrap)?;
        stream
            .set_write_timeout(Some(Duration::from_secs(10)))
            .map_err(|_| LinuxError::Bootstrap)?;
        let pidfd = pidfd_open(peer.pid)?;
        Ok(Self {
            stream,
            nonce,
            peer,
            pidfd,
            parent_pid,
            child_pid,
            next_transfer_id: 1,
            poisoned: false,
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

    /// Transfers a prepared reader capability and withholds the local writer
    /// until authenticated peer validation completes the READY/COMMIT barrier.
    pub fn transfer_writer(
        &mut self,
        prepared: PreparedWriter,
    ) -> Result<WriterRegion<LinuxWriterMapping>, LinuxError> {
        let result = (|| {
            self.ensure_live()?;
            let manifest = self.manifest(prepared.expected, prepared.len, PeerAccess::ReadOnly)?;
            send_fd(&self.stream, &manifest, prepared.capability.fd.as_raw_fd())?;
            receive_control(&self.stream, READY_MAGIC, &manifest)?;
            send_control(&self.stream, COMMIT_MAGIC, &manifest)?;
            let writer = prepared.region;
            self.next_transfer_id = self
                .next_transfer_id
                .checked_add(1)
                .ok_or(LinuxError::InvalidFrame)?;
            Ok(writer)
        })();
        if result.is_err() {
            self.poison();
        }
        result
    }

    /// Receives, validates, maps, and binds one read-only capability.
    pub fn receive_reader(
        &mut self,
        expected_len: usize,
        expected: ValidationExpectations,
        topology: RegionSetLayout,
    ) -> Result<ReaderRegion<LinuxReaderMapping>, LinuxError> {
        let result = (|| {
            self.ensure_live()?;
            let manifest = self.manifest(expected, expected_len, PeerAccess::ReadOnly)?;
            let fd = receive_fd(&self.stream, &manifest)?;
            let pending = LinuxReaderMapping::import(fd, expected_len, expected, topology)?;
            send_control(&self.stream, READY_MAGIC, &manifest)?;
            receive_control(&self.stream, COMMIT_MAGIC, &manifest)?;
            let reader = pending.bind();
            self.next_transfer_id = self
                .next_transfer_id
                .checked_add(1)
                .ok_or(LinuxError::InvalidFrame)?;
            Ok(reader)
        })();
        if result.is_err() {
            self.poison();
        }
        result
    }

    fn manifest(
        &self,
        expected: ValidationExpectations,
        len: usize,
        access: PeerAccess,
    ) -> Result<TransferManifest, LinuxError> {
        let entry =
            ManifestEntry::validated(expected, len, access).ok_or(LinuxError::InvalidFrame)?;
        TransferManifest::new(
            self.nonce,
            self.parent_pid,
            self.child_pid,
            self.next_transfer_id,
            vec![entry],
        )
        .ok_or(LinuxError::InvalidFrame)
    }

    fn ensure_live(&self) -> Result<(), LinuxError> {
        if self.poisoned || self.peer_exited()? {
            Err(LinuxError::Bootstrap)
        } else {
            Ok(())
        }
    }

    fn poison(&mut self) {
        self.poisoned = true;
        let _ = self.stream.shutdown(std::net::Shutdown::Both);
        if std::process::id() == self.parent_pid {
            // SAFETY: pidfd identifies the exact authenticated helper; null
            // siginfo and zero flags request an ordinary SIGKILL delivery.
            let _ = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    self.pidfd.as_raw_fd(),
                    libc::SIGKILL,
                    std::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            };
        }
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
        let mapping = LinuxWriterMapping {
            fd: self.fd,
            mapping: self.mapping,
        };
        let raw = unsafe { libc::fcntl(mapping.fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        if raw < 0 {
            return Err(last_os("fcntl(F_DUPFD_CLOEXEC)"));
        }
        let len = mapping.mapping.len;
        let region = WriterRegion::new(mapping, layout, topology)?;
        Ok(PreparedWriter {
            region,
            capability: ExportedReaderCapability {
                // SAFETY: successful fcntl returned a new owned descriptor.
                fd: unsafe { OwnedFd::from_raw_fd(raw) },
            },
            expected,
            len,
        })
    }
}

/// Sealed sole-writer mapping awaiting export/commit.
///
/// ```compile_fail
/// use native_ipc_platform::linux::PreparedWriter;
/// fn publish_early(mut pending: PreparedWriter) {
///     pending.publish(0, 1, None, b"too early").unwrap();
/// }
/// ```
pub struct PreparedWriter {
    region: WriterRegion<LinuxWriterMapping>,
    capability: ExportedReaderCapability,
    expected: ValidationExpectations,
    len: usize,
}

/// Sealed descriptor intended for one authenticated reader transfer.
pub struct ExportedReaderCapability {
    fd: OwnedFd,
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

struct PendingLinuxReader {
    region: ReaderRegion<LinuxReaderMapping>,
}

impl PendingLinuxReader {
    fn bind(self) -> ReaderRegion<LinuxReaderMapping> {
        self.region
    }
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
    ) -> Result<PendingLinuxReader, LinuxError> {
        validate_fd(fd.as_raw_fd(), len)?;
        let mapping = Mapping::map(fd.as_raw_fd(), len, libc::PROT_READ)?;
        mapping.advise()?;
        // SAFETY: READY/COMMIT protocol keeps the writer quiescent during import.
        let bytes = unsafe { std::slice::from_raw_parts(mapping.base.as_ptr(), len) };
        let layout = unsafe { ValidatedRegionLayout::validate(bytes, expected, &topology) }?;
        Ok(PendingLinuxReader {
            region: ReaderRegion::new(Self { _fd: fd, mapping }, layout, topology)?,
        })
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

fn send_fd(stream: &UnixStream, manifest: &TransferManifest, fd: RawFd) -> Result<(), LinuxError> {
    let mut frame = manifest.encode(CAPABILITY_MAGIC);
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
    let sent = loop {
        // SAFETY: iovec/control buffers remain live for the call. Retrying only
        // on EINTR is safe because a failing sendmsg transferred no bytes/fd.
        let sent = unsafe { libc::sendmsg(stream.as_raw_fd(), &message, libc::MSG_NOSIGNAL) };
        if sent >= 0 {
            break sent as usize;
        }
        if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return Err(last_os("sendmsg"));
        }
    };
    if sent == 0 || sent > CONTROL_FRAME_LEN {
        return Err(LinuxError::InvalidFrame);
    }
    if sent < CONTROL_FRAME_LEN {
        // SCM_RIGHTS is attached to the first byte. Once that byte is sent,
        // complete the stream frame without attaching the descriptor again.
        let mut stream = stream;
        stream
            .write_all(&frame[sent..])
            .map_err(|_| LinuxError::InvalidFrame)?;
    }
    Ok(())
}

fn receive_fd(stream: &UnixStream, manifest: &TransferManifest) -> Result<OwnedFd, LinuxError> {
    let (frame, mut descriptors, flags, ancillary_valid) = receive_message(stream)?;
    if flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0
        || !manifest.matches_frame(CAPABILITY_MAGIC, &frame)
    {
        return Err(LinuxError::InvalidFrame);
    }
    if !ancillary_valid || descriptors.len() != 1 {
        return Err(LinuxError::InvalidAncillaryData);
    }
    Ok(descriptors.pop().expect("exactly one descriptor"))
}

fn send_control(
    stream: &UnixStream,
    magic: [u8; 8],
    manifest: &TransferManifest,
) -> Result<(), LinuxError> {
    let frame = manifest.encode(magic);
    let mut stream = stream;
    stream
        .write_all(&frame)
        .map_err(|_| LinuxError::InvalidFrame)
}

fn receive_control(
    stream: &UnixStream,
    magic: [u8; 8],
    manifest: &TransferManifest,
) -> Result<(), LinuxError> {
    let (frame, descriptors, flags, ancillary_valid) = receive_message(stream)?;
    if flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 || !manifest.matches_frame(magic, &frame) {
        return Err(LinuxError::InvalidFrame);
    }
    if !ancillary_valid || !descriptors.is_empty() {
        return Err(LinuxError::InvalidAncillaryData);
    }
    Ok(())
}

fn receive_message(
    stream: &UnixStream,
) -> Result<([u8; CONTROL_FRAME_LEN], Vec<OwnedFd>, libc::c_int, bool), LinuxError> {
    let mut frame = [0_u8; CONTROL_FRAME_LEN];
    // Leave enough room to adopt and close a bounded set of excess descriptors.
    // MSG_CTRUNC still fails closed after every descriptor that fit is owned.
    const MAX_RECEIVED_FDS: u32 = 16;
    let control_len =
        unsafe { libc::CMSG_SPACE((size_of::<RawFd>() * MAX_RECEIVED_FDS as usize) as u32) }
            as usize;
    let mut descriptors = Vec::new();
    let mut ancillary_valid = true;
    let mut flags = 0;
    let mut offset = 0;
    while offset < frame.len() {
        let mut iovec = libc::iovec {
            // SAFETY: `offset` remains within `frame` and the remaining length
            // describes the initialized output capacity for recvmsg.
            iov_base: unsafe { frame.as_mut_ptr().add(offset) }.cast(),
            iov_len: frame.len() - offset,
        };
        let mut control = vec![0_u8; control_len];
        let mut message: libc::msghdr = unsafe { zeroed() };
        message.msg_iov = &mut iovec;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = control.len();
        let received = loop {
            // SAFETY: iovec/control buffers remain valid for the call.
            let received =
                unsafe { libc::recvmsg(stream.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) };
            if received >= 0 {
                break received as usize;
            }
            if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                return Err(last_os("recvmsg"));
            }
        };

        // Adopt every installed descriptor from every stream fragment before
        // any fallible frame validation. Drop closes all on rejection.
        // SAFETY: the kernel initialized the chain within `msg_controllen`.
        let mut header = unsafe { libc::CMSG_FIRSTHDR(&message) };
        while !header.is_null() {
            // SAFETY: `header` is part of the kernel-produced chain.
            let current = unsafe { &*header };
            let minimum = unsafe { libc::CMSG_LEN(0) } as usize;
            if current.cmsg_len < minimum || current.cmsg_len > message.msg_controllen {
                ancillary_valid = false;
                break;
            }
            if current.cmsg_level != libc::SOL_SOCKET || current.cmsg_type != libc::SCM_RIGHTS {
                ancillary_valid = false;
            } else {
                let payload_len = current.cmsg_len - minimum;
                if payload_len == 0 || !payload_len.is_multiple_of(size_of::<RawFd>()) {
                    ancillary_valid = false;
                } else {
                    let count = payload_len / size_of::<RawFd>();
                    for index in 0..count {
                        // SAFETY: cmsg length proves this payload element exists.
                        let raw = unsafe {
                            std::ptr::read_unaligned(
                                libc::CMSG_DATA(header).cast::<RawFd>().add(index),
                            )
                        };
                        if raw < 0 {
                            ancillary_valid = false;
                        } else {
                            // SAFETY: SCM_RIGHTS installed this new descriptor.
                            descriptors.push(unsafe { OwnedFd::from_raw_fd(raw) });
                        }
                    }
                }
            }
            // SAFETY: advances within this kernel-produced control buffer.
            header = unsafe { libc::CMSG_NXTHDR(&message, header) };
        }
        flags |= message.msg_flags;
        if received == 0 || received > frame.len() - offset {
            return Err(LinuxError::InvalidFrame);
        }
        offset += received;
    }
    Ok((frame, descriptors, flags, ancillary_valid))
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
        AcknowledgementRouteSpec, Endpoint, LayoutError, LayoutLimits, RegionSpec, RoleId,
    };

    fn send_fragmented_with_fds(
        stream: &UnixStream,
        frame: &[u8; CONTROL_FRAME_LEN],
        fds: &[RawFd],
        first_bytes: usize,
    ) {
        send_chunk_with_fds(stream, &frame[..first_bytes], fds);
        let mut stream = stream;
        stream.write_all(&frame[first_bytes..]).unwrap();
    }

    fn send_chunk_with_fds(stream: &UnixStream, bytes: &[u8], fds: &[RawFd]) {
        let mut prefix = bytes.to_vec();
        let mut iovec = libc::iovec {
            iov_base: prefix.as_mut_ptr().cast(),
            iov_len: prefix.len(),
        };
        let control_len = unsafe { libc::CMSG_SPACE(std::mem::size_of_val(fds) as u32) } as usize;
        let mut control = vec![0_u8; control_len];
        let mut message: libc::msghdr = unsafe { zeroed() };
        message.msg_iov = &mut iovec;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr().cast();
        message.msg_controllen = control.len();
        // SAFETY: the control allocation exactly fits the supplied descriptor slice.
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&message);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of_val(fds) as u32) as usize;
            std::ptr::copy_nonoverlapping(
                fds.as_ptr(),
                libc::CMSG_DATA(header).cast::<RawFd>(),
                fds.len(),
            );
            assert_eq!(
                libc::sendmsg(stream.as_raw_fd(), &message, libc::MSG_NOSIGNAL),
                bytes.len() as isize
            );
        }
    }

    fn open_fd_count() -> usize {
        std::fs::read_dir("/proc/self/fd").unwrap().count()
    }

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
    fn invalid_sizes_capabilities_and_peer_identity_fail_exactly() {
        assert!(matches!(
            QuiescentRegion::new(0),
            Err(LinuxError::InvalidSize(0))
        ));
        assert!(matches!(
            QuiescentRegion::new(usize::MAX),
            Err(LinuxError::InvalidSize(usize::MAX))
        ));

        let unsealed = QuiescentRegion::new(1).unwrap();
        assert!(matches!(
            validate_fd(unsealed.fd.as_raw_fd(), unsealed.len()),
            Err(LinuxError::InvalidCapability)
        ));

        let (left, right) = UnixStream::pair().unwrap();
        let actual = peer_credentials(&right).unwrap();
        let wrong = PeerCredentials {
            pid: actual.pid.wrapping_add(1),
            ..actual
        };
        assert!(matches!(
            AuthenticatedChannel::new(left, wrong, [9; 32]),
            Err(LinuxError::WrongPeer)
        ));

        let (left, right) = UnixStream::pair().unwrap();
        let actual = peer_credentials(&right).unwrap();
        assert!(matches!(
            AuthenticatedChannel::new(left, actual, [0; 32]),
            Err(LinuxError::WrongPeer)
        ));
    }

    #[test]
    fn fragmented_stream_frame_preserves_ancillary_ownership() {
        let expected = ValidationExpectations {
            schema_id: [3; 32],
            generation: 9,
            role: RoleId::new(7).unwrap(),
            writer: Endpoint::Initiator,
            maximum_mapping_size: 4096,
        };
        let entry = ManifestEntry::validated(expected, 4096, PeerAccess::ReadOnly).unwrap();
        let nonce = [4; 32];
        let manifest = TransferManifest::new(nonce, 1, 2, 1, vec![entry]).unwrap();
        let frame = manifest.encode(CAPABILITY_MAGIC);
        let file = std::fs::File::open("/dev/null").unwrap();
        let (sender, receiver) = UnixStream::pair().unwrap();
        let received = std::thread::scope(|scope| {
            let task = scope.spawn(|| receive_fd(&receiver, &manifest));
            send_fragmented_with_fds(&sender, &frame, &[file.as_raw_fd()], 1);
            task.join().unwrap().unwrap()
        });
        assert!(received.as_raw_fd() >= 0);
    }

    #[test]
    #[ignore = "spawned in an isolated process by descriptor_cleanup_is_zero_growth"]
    fn malformed_extra_descriptor_frame_has_zero_fd_growth() {
        let before = open_fd_count();
        {
            let expected = ValidationExpectations {
                schema_id: [5; 32],
                generation: 11,
                role: RoleId::new(8).unwrap(),
                writer: Endpoint::Responder,
                maximum_mapping_size: 4096,
            };
            let entry = ManifestEntry::validated(expected, 4096, PeerAccess::ReadOnly).unwrap();
            let nonce = [6; 32];
            let manifest = TransferManifest::new(nonce, 1, 2, 1, vec![entry]).unwrap();
            let frame = manifest.encode(CAPABILITY_MAGIC);
            let first = std::fs::File::open("/dev/null").unwrap();
            let second = std::fs::File::open("/dev/null").unwrap();
            let (sender, receiver) = UnixStream::pair().unwrap();
            std::thread::scope(|scope| {
                let task = scope.spawn(|| receive_fd(&receiver, &manifest));
                send_fragmented_with_fds(
                    &sender,
                    &frame,
                    &[first.as_raw_fd(), second.as_raw_fd()],
                    7,
                );
                assert!(matches!(
                    task.join().unwrap(),
                    Err(LinuxError::InvalidAncillaryData)
                ));
            });
        }
        assert_eq!(open_fd_count(), before);
    }

    #[test]
    #[ignore = "spawned in an isolated process by descriptor_cleanup_is_zero_growth"]
    fn ancillary_on_later_stream_fragment_is_adopted_and_rejected() {
        let before = open_fd_count();
        {
            let expected = ValidationExpectations {
                schema_id: [7; 32],
                generation: 13,
                role: RoleId::new(9).unwrap(),
                writer: Endpoint::Initiator,
                maximum_mapping_size: 4096,
            };
            let entry = ManifestEntry::validated(expected, 4096, PeerAccess::ReadOnly).unwrap();
            let manifest = TransferManifest::new([8; 32], 1, 2, 1, vec![entry]).unwrap();
            let frame = manifest.encode(CAPABILITY_MAGIC);
            let first = std::fs::File::open("/dev/null").unwrap();
            let second = std::fs::File::open("/dev/null").unwrap();
            let (sender, receiver) = UnixStream::pair().unwrap();
            std::thread::scope(|scope| {
                let task = scope.spawn(|| receive_fd(&receiver, &manifest));
                send_chunk_with_fds(&sender, &frame[..7], &[first.as_raw_fd()]);
                send_chunk_with_fds(&sender, &frame[7..], &[second.as_raw_fd()]);
                assert!(matches!(
                    task.join().unwrap(),
                    Err(LinuxError::InvalidAncillaryData)
                ));
            });
        }
        assert_eq!(open_fd_count(), before);
    }

    #[test]
    fn descriptor_cleanup_is_zero_growth() {
        let executable = std::env::current_exe().unwrap();
        for test in [
            "linux::tests::malformed_extra_descriptor_frame_has_zero_fd_growth",
            "linux::tests::ancillary_on_later_stream_fragment_is_adopted_and_rejected",
        ] {
            let status = Command::new(&executable)
                .args(["--exact", test, "--ignored", "--nocapture"])
                .status()
                .unwrap();
            assert!(status.success(), "isolated descriptor test failed: {test}");
        }
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
        let transfer_len = prepared.len;
        let capability = &prepared.capability;

        // A sealed exported fd cannot create another writable mapping.
        let denied = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                transfer_len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                capability.fd.as_raw_fd(),
                0,
            )
        };
        assert_eq!(denied, libc::MAP_FAILED);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));

        // Seals also deny descriptor writes and any size change with exact EPERM.
        let byte = 0xff_u8;
        let written =
            unsafe { libc::pwrite(capability.fd.as_raw_fd(), (&raw const byte).cast(), 1, 0) };
        assert_eq!(written, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
        assert_eq!(
            unsafe {
                libc::ftruncate(
                    capability.fd.as_raw_fd(),
                    transfer_len.saturating_add(4096) as libc::off_t,
                )
            },
            -1
        );
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
        assert_eq!(unsafe { libc::ftruncate(capability.fd.as_raw_fd(), 1) }, -1);
        assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));

        let (left, right) = UnixStream::pair().unwrap();
        let credentials = peer_credentials(&left).unwrap();
        let mut sender = AuthenticatedChannel::new(left, credentials, [8; 32]).unwrap();
        let mut receiver = AuthenticatedChannel::new(right, credentials, [8; 32]).unwrap();
        std::thread::scope(|scope| {
            let received = scope.spawn(|| {
                let reader = receiver
                    .receive_reader(transfer_len, expected, topology.clone())
                    .unwrap();
                for _ in 0..10_000 {
                    if let Ok(payload) = reader.copy_payload(0, 1) {
                        assert_eq!(payload, b"linux");
                        return;
                    }
                    std::thread::yield_now();
                }
                panic!("reader never observed publication");
            });
            let mut writer = sender.transfer_writer(prepared).unwrap();
            assert_eq!(
                writer.publish(0, 1, None, &[0xaa; 17]).unwrap_err(),
                BindingError::Layout(LayoutError::PayloadOutOfBounds {
                    length: 17,
                    capacity: 16,
                })
            );
            writer.publish(0, 1, None, b"linux").unwrap();
            received.join().unwrap();
        });
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
