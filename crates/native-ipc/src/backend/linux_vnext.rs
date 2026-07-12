//! vNext Linux anonymous packet transport primitives.

pub(crate) mod memory;
mod process;
pub(crate) mod spawn;

use core::cell::Cell;
use core::marker::PhantomData;
use core::mem::{ManuallyDrop, align_of, size_of, zeroed};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use crate::protocol::CONTROL_FRAME_LEN;
use crate::session::{AbsoluteDeadline, AtomicCapabilities, NegotiationError};

const MAX_PACKET_FDS: usize = 16;
const CONTROL_CAPACITY: usize = 256;
/// Conservative Linux-native one-datagram ceiling; the generic HELLO hard max
/// is intentionally not claimed as universally supported by `SOCK_SEQPACKET`.
const MAX_ZERO_RIGHTS_PACKET_BYTES: usize = 64 * 1024;

// Every supported Linux build must have compiler-backed lock-free operations
// for the widths that vNext can advertise. These are target facts, not runtime
// guesses or hardcoded truth values.
const _: () = assert!(cfg!(target_has_atomic = "32"));
const _: () = assert!(cfg!(target_has_atomic = "64"));

fn discover_atomic_capabilities() -> Result<AtomicCapabilities, NegotiationError> {
    // SAFETY: sysconf receives documented scalar selectors and returns values
    // without writing through pointers.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as i128;
    // SAFETY: this Linux selector reports the L1 data-cache line size.
    let cache_line = unsafe { libc::sysconf(libc::_SC_LEVEL1_DCACHE_LINESIZE) } as i128;
    atomic_capabilities_from_native_facts(page, cache_line)
}

fn atomic_capabilities_from_native_facts(
    page: i128,
    cache_line: i128,
) -> Result<AtomicCapabilities, NegotiationError> {
    let page = checked_native_alignment(page)?;
    let cache_line = checked_native_alignment(cache_line)?;
    AtomicCapabilities::from_verified_native(
        page,
        cache_line,
        cfg!(target_has_atomic = "32"),
        cfg!(target_has_atomic = "64"),
    )
}

fn checked_native_alignment(value: i128) -> Result<usize, NegotiationError> {
    if value <= 0 {
        return Err(NegotiationError::AtomicUnsupported);
    }
    let value = usize::try_from(value).map_err(|_| NegotiationError::NativeSizeNarrowing)?;
    if !value.is_power_of_two()
        || value
            < align_of::<core::sync::atomic::AtomicU32>()
                .max(align_of::<core::sync::atomic::AtomicU64>())
    {
        return Err(NegotiationError::AtomicUnsupported);
    }
    Ok(value)
}

#[repr(C)]
union ControlStorage {
    alignment: ManuallyDrop<libc::cmsghdr>,
    bytes: [u8; CONTROL_CAPACITY],
}

impl ControlStorage {
    const fn zeroed() -> Self {
        Self {
            bytes: [0; CONTROL_CAPACITY],
        }
    }

    fn as_mut_ptr(&mut self) -> *mut libc::c_void {
        // SAFETY: reading the active byte field only obtains its storage address.
        unsafe { self.bytes.as_mut_ptr().cast() }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PacketCredentials {
    pid: u32,
    uid: u32,
    gid: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PacketError {
    InvalidInput,
    WouldBlock,
    Interrupted,
    Truncated,
    RecordTooLarge,
    MalformedAncillary,
    WrongPeer,
    WrongDescriptorCount,
    DeadlineExpired,
    AmbiguousAfterSend,
    AmbiguousAfterReceive,
    Poisoned,
    PeerExited,
    Native(i32),
}

struct ReceivedPacket {
    bytes: Vec<u8>,
    descriptors: Vec<OwnedFd>,
    credentials: PacketCredentials,
}

struct ReceivedAncillary {
    descriptors: Vec<OwnedFd>,
    credentials: Option<PacketCredentials>,
    rights_records: usize,
    valid: bool,
}

impl ReceivedAncillary {
    fn validate(
        self,
        expected_peer: PacketCredentials,
        expected_descriptors: usize,
    ) -> Result<(Vec<OwnedFd>, PacketCredentials), PacketError> {
        if !self.valid {
            return Err(PacketError::MalformedAncillary);
        }
        let credentials = self.credentials.ok_or(PacketError::MalformedAncillary)?;
        if credentials != expected_peer {
            return Err(PacketError::WrongPeer);
        }
        if self.descriptors.len() != expected_descriptors {
            return Err(PacketError::WrongDescriptorCount);
        }
        if (expected_descriptors == 0 && self.rights_records != 0)
            || (expected_descriptors != 0 && self.rights_records != 1)
        {
            return Err(PacketError::MalformedAncillary);
        }
        Ok((self.descriptors, credentials))
    }
}

struct SeqPacketEndpoint {
    fd: OwnedFd,
    not_sync: PhantomData<Cell<()>>,
    #[cfg(test)]
    post_receive_poll_errno: Option<i32>,
}

struct ProcessBoundEndpoint {
    endpoint: SeqPacketEndpoint,
    peer_pidfd: OwnedFd,
    peer: PacketCredentials,
    poisoned: bool,
    #[cfg(test)]
    faults: tests::DeadlineFaults,
}

impl SeqPacketEndpoint {
    fn pair() -> Result<(Self, Self), PacketError> {
        let mut pair = [-1; 2];
        // SAFETY: `pair` has space for the two returned descriptors.
        if unsafe {
            libc::socketpair(
                libc::AF_UNIX,
                libc::SOCK_SEQPACKET | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                0,
                pair.as_mut_ptr(),
            )
        } != 0
        {
            return Err(last_native());
        }
        // SAFETY: successful socketpair returned two independently owned fds.
        let left = unsafe { OwnedFd::from_raw_fd(pair[0]) };
        // SAFETY: successful socketpair returned two independently owned fds.
        let right = unsafe { OwnedFd::from_raw_fd(pair[1]) };
        enable_passcred(left.as_raw_fd())?;
        enable_passcred(right.as_raw_fd())?;
        configure_packet_buffers(left.as_raw_fd())?;
        configure_packet_buffers(right.as_raw_fd())?;
        Ok((Self::from_owned(left), Self::from_owned(right)))
    }

    fn from_owned(fd: OwnedFd) -> Self {
        Self {
            fd,
            not_sync: PhantomData,
            #[cfg(test)]
            post_receive_poll_errno: None,
        }
    }

    /// # Safety
    ///
    /// `raw` must be the uniquely owned inherited end of a vNext socket pair.
    unsafe fn from_inherited(raw: RawFd) -> Result<Self, PacketError> {
        if raw < 0 {
            return Err(PacketError::InvalidInput);
        }
        // SAFETY: caller transfers unique ownership of the inherited endpoint.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        set_cloexec(fd.as_raw_fd())?;
        enable_passcred(fd.as_raw_fd())?;
        configure_packet_buffers(fd.as_raw_fd())?;
        Ok(Self::from_owned(fd))
    }

    fn send(&mut self, bytes: &[u8], descriptors: &[RawFd]) -> Result<(), PacketError> {
        self.send_bounded(bytes, descriptors, CONTROL_FRAME_LEN)
    }

    fn send_zero_rights(&mut self, bytes: &[u8]) -> Result<(), PacketError> {
        self.send_bounded(bytes, &[], MAX_ZERO_RIGHTS_PACKET_BYTES)
    }

    fn send_bounded(
        &mut self,
        bytes: &[u8],
        descriptors: &[RawFd],
        maximum: usize,
    ) -> Result<(), PacketError> {
        if bytes.is_empty()
            || bytes.len() > maximum
            || descriptors.len() > MAX_PACKET_FDS
            || descriptors.iter().any(|fd| *fd < 0)
        {
            return Err(PacketError::InvalidInput);
        }
        let mut iovec = libc::iovec {
            iov_base: bytes.as_ptr().cast_mut().cast(),
            iov_len: bytes.len(),
        };
        let control_len = if descriptors.is_empty() {
            0
        } else {
            // SAFETY: the bounded descriptor byte count fits the UAPI argument.
            unsafe { libc::CMSG_SPACE(std::mem::size_of_val(descriptors) as u32) as usize }
        };
        if control_len > CONTROL_CAPACITY {
            return Err(PacketError::InvalidInput);
        }
        let mut control = ControlStorage::zeroed();
        // SAFETY: zero is the canonical initialization for unused msghdr fields.
        let mut message: libc::msghdr = unsafe { zeroed() };
        message.msg_iov = &mut iovec;
        message.msg_iovlen = 1;
        if control_len != 0 {
            message.msg_control = control.as_mut_ptr();
            message.msg_controllen = control_len;
            // SAFETY: the control buffer was sized for this exact rights record.
            unsafe {
                let header = libc::CMSG_FIRSTHDR(&message);
                (*header).cmsg_level = libc::SOL_SOCKET;
                (*header).cmsg_type = libc::SCM_RIGHTS;
                (*header).cmsg_len =
                    libc::CMSG_LEN(std::mem::size_of_val(descriptors) as u32) as usize;
                core::ptr::copy_nonoverlapping(
                    descriptors.as_ptr(),
                    libc::CMSG_DATA(header).cast::<RawFd>(),
                    descriptors.len(),
                );
            }
        }
        // SAFETY: all iovec and control storage remains live for this call.
        let sent = unsafe { libc::sendmsg(self.fd.as_raw_fd(), &message, libc::MSG_NOSIGNAL) };
        if sent < 0 {
            return Err(last_io_kind());
        }
        if sent as usize != bytes.len() {
            return Err(PacketError::Truncated);
        }
        Ok(())
    }

    fn receive(
        &mut self,
        expected_len: usize,
        expected_peer: PacketCredentials,
        expected_descriptors: usize,
    ) -> Result<ReceivedPacket, PacketError> {
        if expected_len == 0
            || expected_len > CONTROL_FRAME_LEN
            || expected_descriptors > MAX_PACKET_FDS
        {
            return Err(PacketError::InvalidInput);
        }
        self.receive_bounded(
            CONTROL_FRAME_LEN,
            Some(expected_len),
            expected_peer,
            expected_descriptors,
        )
    }

    fn receive_zero_rights(
        &mut self,
        expected_peer: PacketCredentials,
    ) -> Result<ReceivedPacket, PacketError> {
        self.receive_zero_rights_bounded(MAX_ZERO_RIGHTS_PACKET_BYTES, expected_peer)
    }

    fn receive_zero_rights_bounded(
        &mut self,
        capacity: usize,
        expected_peer: PacketCredentials,
    ) -> Result<ReceivedPacket, PacketError> {
        self.receive_bounded(capacity, None, expected_peer, 0)
    }

    fn receive_bounded(
        &mut self,
        capacity: usize,
        expected_len: Option<usize>,
        expected_peer: PacketCredentials,
        expected_descriptors: usize,
    ) -> Result<ReceivedPacket, PacketError> {
        if capacity == 0 || capacity > MAX_ZERO_RIGHTS_PACKET_BYTES {
            return Err(PacketError::InvalidInput);
        }
        let mut bytes = vec![0_u8; capacity];
        let mut iovec = libc::iovec {
            iov_base: bytes.as_mut_ptr().cast(),
            iov_len: bytes.len(),
        };
        // Separate aligned space is reserved for one credentials record and
        // the maximum rights record. Every installed fd that fits is adopted.
        let control_len = unsafe {
            libc::CMSG_SPACE(size_of::<libc::ucred>() as u32) as usize
                + libc::CMSG_SPACE((MAX_PACKET_FDS * size_of::<RawFd>()) as u32) as usize
        };
        if control_len > CONTROL_CAPACITY {
            return Err(PacketError::InvalidInput);
        }
        let mut control = ControlStorage::zeroed();
        // SAFETY: zero is the canonical initialization for output msghdr fields.
        let mut message: libc::msghdr = unsafe { zeroed() };
        message.msg_iov = &mut iovec;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr();
        message.msg_controllen = control_len;
        // SAFETY: all output buffers remain writable and live for this call.
        let received = unsafe {
            libc::recvmsg(
                self.fd.as_raw_fd(),
                &mut message,
                libc::MSG_CMSG_CLOEXEC | libc::MSG_DONTWAIT,
            )
        };
        if received < 0 {
            return Err(last_io_kind());
        }

        // SAFETY: recvmsg initialized the returned cmsg chain and uniquely
        // installed every nonnegative SCM_RIGHTS descriptor in this process.
        let ancillary = unsafe { adopt_received_ancillary(&message, control_len)? };

        if message.msg_flags & libc::MSG_CTRUNC != 0 {
            return Err(PacketError::MalformedAncillary);
        }
        if message.msg_flags & libc::MSG_TRUNC != 0 {
            return Err(PacketError::RecordTooLarge);
        }
        if received == 0 {
            return Err(if self.socket_has_hung_up()? {
                PacketError::PeerExited
            } else {
                // SOCK_SEQPACKET permits a live peer to enqueue an empty
                // record. Consuming one is malformed input, not proof that
                // the peer exited.
                PacketError::Truncated
            });
        }
        if expected_len.is_some_and(|expected| received as usize != expected) {
            return Err(PacketError::Truncated);
        }
        let (descriptors, credentials) = ancillary.validate(expected_peer, expected_descriptors)?;
        bytes.truncate(received as usize);
        Ok(ReceivedPacket {
            bytes,
            descriptors,
            credentials,
        })
    }

    fn socket_has_hung_up(&mut self) -> Result<bool, PacketError> {
        #[cfg(test)]
        if let Some(errno) = self.post_receive_poll_errno.take() {
            return Err(PacketError::Native(errno));
        }
        let mut descriptor = libc::pollfd {
            fd: self.fd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `descriptor` is a live pollfd for the duration of the call.
        let result = unsafe { libc::poll(&mut descriptor, 1, 0) };
        if result < 0 {
            // recvmsg already consumed the empty hostile record. In particular,
            // EINTR here is terminal and must never make a caller retry receive.
            return Err(PacketError::Native(
                io::Error::last_os_error().raw_os_error().unwrap_or(-1),
            ));
        }
        if descriptor.revents & libc::POLLNVAL != 0 {
            return Err(PacketError::Native(libc::EBADF));
        }
        Ok(descriptor.revents & (libc::POLLERR | libc::POLLHUP) != 0)
    }
}

/// Parses a kernel-produced, structurally traversable ancillary chain and
/// adopts every complete descriptor word in each reachable `SCM_RIGHTS`
/// record before returning its validation result.
///
/// # Safety
///
/// Every nonnegative descriptor encoded in a reachable `SCM_RIGHTS` payload
/// must be a newly installed, uniquely owned descriptor. The complete
/// `msg_control` range must remain live for this call. No installed descriptor
/// may lie in or beyond a malformed header whose bounds or length make the
/// remainder of the chain untraversable; recovery from such synthetic layouts
/// is intentionally outside this function's contract.
unsafe fn adopt_received_ancillary(
    message: &libc::msghdr,
    control_capacity: usize,
) -> Result<ReceivedAncillary, PacketError> {
    if message.msg_controllen > control_capacity {
        return Err(PacketError::MalformedAncillary);
    }
    let mut ancillary = ReceivedAncillary {
        descriptors: Vec::new(),
        credentials: None,
        rights_records: 0,
        valid: true,
    };
    let control_start = message.msg_control as usize;
    let control_end = control_start
        .checked_add(message.msg_controllen)
        .ok_or(PacketError::MalformedAncillary)?;
    // SAFETY: the caller guarantees a live cmsg range.
    let mut header = unsafe { libc::CMSG_FIRSTHDR(message) };
    while !header.is_null() {
        let address = header as usize;
        if address < control_start
            || !address.is_multiple_of(align_of::<libc::cmsghdr>())
            || address
                .checked_add(size_of::<libc::cmsghdr>())
                .is_none_or(|end| end > control_end)
        {
            ancillary.valid = false;
            break;
        }
        // SAFETY: the complete cmsghdr lies inside the caller-provided range.
        let current = unsafe { &*header };
        // SAFETY: CMSG_LEN performs scalar layout arithmetic only.
        let minimum = unsafe { libc::CMSG_LEN(0) as usize };
        if current.cmsg_len < minimum
            || address
                .checked_add(current.cmsg_len)
                .is_none_or(|end| end > control_end)
        {
            ancillary.valid = false;
            break;
        }
        let payload_len = current.cmsg_len - minimum;
        match (current.cmsg_level, current.cmsg_type) {
            (libc::SOL_SOCKET, libc::SCM_CREDENTIALS) => {
                if payload_len != size_of::<libc::ucred>() || ancillary.credentials.is_some() {
                    ancillary.valid = false;
                } else {
                    // SAFETY: exact payload length proves one ucred is present.
                    let native = unsafe {
                        core::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<libc::ucred>())
                    };
                    if native.pid <= 0 {
                        ancillary.valid = false;
                    } else {
                        ancillary.credentials = Some(PacketCredentials {
                            pid: native.pid as u32,
                            uid: native.uid,
                            gid: native.gid,
                        });
                    }
                }
            }
            (libc::SOL_SOCKET, libc::SCM_RIGHTS) => {
                ancillary.rights_records += 1;
                if ancillary.rights_records > 1 {
                    ancillary.valid = false;
                }
                if payload_len == 0 || !payload_len.is_multiple_of(size_of::<RawFd>()) {
                    ancillary.valid = false;
                }
                for index in 0..payload_len / size_of::<RawFd>() {
                    // SAFETY: the cmsg length proves this complete fd word exists.
                    let raw = unsafe {
                        core::ptr::read_unaligned(
                            libc::CMSG_DATA(header).cast::<RawFd>().add(index),
                        )
                    };
                    if raw < 0 {
                        ancillary.valid = false;
                    } else {
                        // SAFETY: the caller transferred unique ownership.
                        ancillary
                            .descriptors
                            .push(unsafe { OwnedFd::from_raw_fd(raw) });
                    }
                }
            }
            _ => ancillary.valid = false,
        }
        // SAFETY: advances only within the caller-provided control chain.
        header = unsafe { libc::CMSG_NXTHDR(message, header) };
    }
    Ok(ancillary)
}

impl ProcessBoundEndpoint {
    /// # Safety
    ///
    /// `peer_pidfd` must identify the exact process whose kernel packet
    /// credentials are `peer`. `endpoint` must be the locally retained end of
    /// the exact socketpair whose connected counterpart was inherited by that
    /// process. The topology proof, process handle, credentials, and local
    /// endpoint remain inseparable.
    unsafe fn from_verified_process(
        endpoint: SeqPacketEndpoint,
        peer_pidfd: OwnedFd,
        peer: PacketCredentials,
    ) -> Self {
        Self {
            endpoint,
            peer_pidfd,
            peer,
            poisoned: false,
            #[cfg(test)]
            faults: tests::DeadlineFaults::default(),
        }
    }

    fn send_before(
        &mut self,
        bytes: &[u8],
        descriptors: &[RawFd],
        deadline: AbsoluteDeadline,
    ) -> Result<(), PacketError> {
        if self.poisoned {
            return Err(PacketError::Poisoned);
        }
        loop {
            ensure_running(self.peer_pidfd.as_raw_fd(), deadline)?;
            if deadline.is_expired() {
                return Err(PacketError::DeadlineExpired);
            }
            let result = if self.inject_send_interrupt() {
                Err(PacketError::Interrupted)
            } else {
                self.endpoint.send(bytes, descriptors)
            };
            match result {
                Ok(()) => {
                    self.inject_expiry_after_send(deadline);
                    if deadline.is_expired() {
                        self.poisoned = true;
                        return Err(PacketError::AmbiguousAfterSend);
                    }
                    return Ok(());
                }
                Err(PacketError::WouldBlock) => poll_until(
                    self.endpoint.fd.as_raw_fd(),
                    self.peer_pidfd.as_raw_fd(),
                    libc::POLLOUT,
                    deadline,
                )?,
                Err(PacketError::Interrupted) => continue,
                Err(error) => return Err(error),
            }
        }
    }

    fn send_zero_rights_before(
        &mut self,
        bytes: &[u8],
        deadline: AbsoluteDeadline,
    ) -> Result<(), PacketError> {
        if self.poisoned {
            return Err(PacketError::Poisoned);
        }
        if bytes.is_empty() || bytes.len() > MAX_ZERO_RIGHTS_PACKET_BYTES {
            return Err(PacketError::InvalidInput);
        }
        loop {
            ensure_running(self.peer_pidfd.as_raw_fd(), deadline)?;
            if deadline.is_expired() {
                return Err(PacketError::DeadlineExpired);
            }
            let result = if self.inject_send_interrupt() {
                Err(PacketError::Interrupted)
            } else {
                self.endpoint.send_zero_rights(bytes)
            };
            match result {
                Ok(()) => {
                    self.inject_expiry_after_send(deadline);
                    if deadline.is_expired() {
                        self.poisoned = true;
                        return Err(PacketError::AmbiguousAfterSend);
                    }
                    return Ok(());
                }
                Err(PacketError::WouldBlock) => poll_until(
                    self.endpoint.fd.as_raw_fd(),
                    self.peer_pidfd.as_raw_fd(),
                    libc::POLLOUT,
                    deadline,
                )?,
                Err(PacketError::Interrupted) => continue,
                Err(error) => return Err(error),
            }
        }
    }

    fn receive_before(
        &mut self,
        expected_len: usize,
        expected_descriptors: usize,
        deadline: AbsoluteDeadline,
    ) -> Result<ReceivedPacket, PacketError> {
        if self.poisoned {
            return Err(PacketError::Poisoned);
        }
        loop {
            ensure_running(self.peer_pidfd.as_raw_fd(), deadline)?;
            if deadline.is_expired() {
                return Err(PacketError::DeadlineExpired);
            }
            let result = if self.inject_receive_interrupt() {
                Err(PacketError::Interrupted)
            } else {
                self.endpoint
                    .receive(expected_len, self.peer, expected_descriptors)
            };
            match result {
                Ok(packet) => {
                    self.inject_expiry_after_receive(deadline);
                    if deadline.is_expired() {
                        self.poisoned = true;
                        return Err(PacketError::AmbiguousAfterReceive);
                    }
                    return Ok(packet);
                }
                Err(PacketError::WouldBlock) => poll_until(
                    self.endpoint.fd.as_raw_fd(),
                    self.peer_pidfd.as_raw_fd(),
                    libc::POLLIN,
                    deadline,
                )?,
                Err(PacketError::Interrupted) => continue,
                Err(error) => return Err(error),
            }
        }
    }

    fn receive_zero_rights_before(
        &mut self,
        deadline: AbsoluteDeadline,
    ) -> Result<ReceivedPacket, PacketError> {
        if self.poisoned {
            return Err(PacketError::Poisoned);
        }
        loop {
            ensure_running(self.peer_pidfd.as_raw_fd(), deadline)?;
            if deadline.is_expired() {
                return Err(PacketError::DeadlineExpired);
            }
            let result = if self.inject_receive_interrupt() {
                Err(PacketError::Interrupted)
            } else {
                self.endpoint.receive_zero_rights(self.peer)
            };
            match result {
                Ok(packet) => {
                    self.inject_expiry_after_receive(deadline);
                    if deadline.is_expired() {
                        self.poisoned = true;
                        return Err(PacketError::AmbiguousAfterReceive);
                    }
                    return Ok(packet);
                }
                Err(PacketError::WouldBlock) => poll_until(
                    self.endpoint.fd.as_raw_fd(),
                    self.peer_pidfd.as_raw_fd(),
                    libc::POLLIN,
                    deadline,
                )?,
                Err(PacketError::Interrupted) => continue,
                Err(error) => return Err(error),
            }
        }
    }

    #[cfg(not(test))]
    const fn inject_send_interrupt(&mut self) -> bool {
        false
    }

    #[cfg(not(test))]
    const fn inject_receive_interrupt(&mut self) -> bool {
        false
    }

    #[cfg(not(test))]
    const fn inject_expiry_after_send(&mut self, _: AbsoluteDeadline) {}

    #[cfg(not(test))]
    const fn inject_expiry_after_receive(&mut self, _: AbsoluteDeadline) {}
}

fn ensure_running(pidfd: RawFd, deadline: AbsoluteDeadline) -> Result<(), PacketError> {
    if pidfd < 0 {
        return Err(PacketError::InvalidInput);
    }
    loop {
        if deadline.is_expired() {
            return Err(PacketError::DeadlineExpired);
        }
        let mut peer = libc::pollfd {
            fd: pidfd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `peer` points to one initialized poll entry.
        let result = unsafe { libc::poll(&mut peer, 1, 0) };
        if result < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(last_native());
        }
        if result != 0 || peer.revents != 0 {
            return Err(PacketError::PeerExited);
        }
        return Ok(());
    }
}

fn poll_until(
    socket: RawFd,
    pidfd: RawFd,
    requested: libc::c_short,
    deadline: AbsoluteDeadline,
) -> Result<(), PacketError> {
    if socket < 0 || pidfd < 0 {
        return Err(PacketError::InvalidInput);
    }
    loop {
        let remaining = deadline.remaining();
        if remaining.is_zero() {
            return Err(PacketError::DeadlineExpired);
        }
        let timeout = remaining
            .as_nanos()
            .div_ceil(1_000_000)
            .min(i32::MAX as u128) as libc::c_int;
        let mut descriptors = [
            libc::pollfd {
                fd: socket,
                events: requested,
                revents: 0,
            },
            libc::pollfd {
                fd: pidfd,
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        // SAFETY: both initialized entries remain live for the complete call.
        let result = unsafe { libc::poll(descriptors.as_mut_ptr(), 2, timeout) };
        if result < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(last_native());
        }
        if deadline.is_expired() {
            return Err(PacketError::DeadlineExpired);
        }
        if descriptors[1].revents != 0 {
            return Err(PacketError::PeerExited);
        }
        if descriptors[0].revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            return Err(PacketError::PeerExited);
        }
        if descriptors[0].revents & requested != 0 {
            return Ok(());
        }
    }
}

fn enable_passcred(fd: RawFd) -> Result<(), PacketError> {
    let enabled: libc::c_int = 1;
    // SAFETY: the scalar option value has the documented size.
    if unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PASSCRED,
            (&enabled as *const libc::c_int).cast(),
            size_of::<libc::c_int>() as libc::socklen_t,
        )
    } != 0
    {
        return Err(last_native());
    }
    Ok(())
}

fn configure_packet_buffers(fd: RawFd) -> Result<(), PacketError> {
    let requested =
        i32::try_from(MAX_ZERO_RIGHTS_PACKET_BYTES * 2).map_err(|_| PacketError::InvalidInput)?;
    for option in [libc::SO_SNDBUF, libc::SO_RCVBUF] {
        // SAFETY: requested is one initialized scalar socket option value.
        if unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                option,
                (&requested as *const i32).cast(),
                size_of::<i32>() as libc::socklen_t,
            )
        } != 0
        {
            return Err(last_native());
        }
        let mut actual = 0_i32;
        let mut length = size_of::<i32>() as libc::socklen_t;
        // SAFETY: actual and length are valid writable option outputs.
        if unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                option,
                (&mut actual as *mut i32).cast(),
                &mut length,
            )
        } != 0
            || length as usize != size_of::<i32>()
            || actual < requested
        {
            return Err(PacketError::InvalidInput);
        }
    }
    Ok(())
}

fn set_cloexec(fd: RawFd) -> Result<(), PacketError> {
    // SAFETY: descriptor is live and F_GETFD has no pointer argument.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(last_native());
    }
    // SAFETY: descriptor is live and the flag mask is valid.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } != 0 {
        return Err(last_native());
    }
    Ok(())
}

fn last_io_kind() -> PacketError {
    let error = io::Error::last_os_error();
    match error.kind() {
        io::ErrorKind::WouldBlock => PacketError::WouldBlock,
        io::ErrorKind::Interrupted => PacketError::Interrupted,
        _ => PacketError::Native(error.raw_os_error().unwrap_or(-1)),
    }
}

fn last_native() -> PacketError {
    PacketError::Native(io::Error::last_os_error().raw_os_error().unwrap_or(-1))
}

#[cfg(test)]
#[path = "linux_vnext_test.rs"]
mod tests;
