//! vNext Linux anonymous packet transport primitives.

mod memory;

use core::cell::Cell;
use core::marker::PhantomData;
use core::mem::{ManuallyDrop, size_of, zeroed};
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use crate::protocol::CONTROL_FRAME_LEN;
use crate::session::AbsoluteDeadline;

const MAX_PACKET_FDS: usize = 16;
const CONTROL_CAPACITY: usize = 256;

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

struct SeqPacketEndpoint {
    fd: OwnedFd,
    not_sync: PhantomData<Cell<()>>,
}

struct ProcessBoundEndpoint {
    endpoint: SeqPacketEndpoint,
    peer_pidfd: OwnedFd,
    peer: PacketCredentials,
    poisoned: bool,
    #[cfg(test)]
    faults: DeadlineFaults,
}

#[cfg(test)]
#[derive(Default)]
struct DeadlineFaults {
    send_interrupts: u8,
    receive_interrupts: u8,
    expire_after_send: bool,
    expire_after_receive: bool,
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
        Ok((Self::from_owned(left), Self::from_owned(right)))
    }

    fn from_owned(fd: OwnedFd) -> Self {
        Self {
            fd,
            not_sync: PhantomData,
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
        Ok(Self::from_owned(fd))
    }

    fn send(&mut self, bytes: &[u8], descriptors: &[RawFd]) -> Result<(), PacketError> {
        if bytes.is_empty()
            || bytes.len() > CONTROL_FRAME_LEN
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
        let mut bytes = vec![0_u8; CONTROL_FRAME_LEN];
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

        let mut descriptors = Vec::new();
        let mut credentials = None;
        let mut rights_records = 0_usize;
        let mut ancillary_valid = true;
        if message.msg_controllen > control_len {
            return Err(PacketError::MalformedAncillary);
        }
        let control_start = message.msg_control as usize;
        let control_end = control_start
            .checked_add(message.msg_controllen)
            .ok_or(PacketError::MalformedAncillary)?;
        // SAFETY: the kernel initialized a cmsg chain within `msg_controllen`.
        let mut header = unsafe { libc::CMSG_FIRSTHDR(&message) };
        while !header.is_null() {
            let address = header as usize;
            if address < control_start
                || address
                    .checked_add(size_of::<libc::cmsghdr>())
                    .is_none_or(|end| end > control_end)
            {
                ancillary_valid = false;
                break;
            }
            // SAFETY: the complete cmsghdr lies inside the returned control bytes.
            let current = unsafe { &*header };
            let minimum = unsafe { libc::CMSG_LEN(0) as usize };
            if current.cmsg_len < minimum
                || address
                    .checked_add(current.cmsg_len)
                    .is_none_or(|end| end > control_end)
            {
                ancillary_valid = false;
                break;
            }
            let payload_len = current.cmsg_len - minimum;
            match (current.cmsg_level, current.cmsg_type) {
                (libc::SOL_SOCKET, libc::SCM_CREDENTIALS) => {
                    if payload_len != size_of::<libc::ucred>() || credentials.is_some() {
                        ancillary_valid = false;
                    } else {
                        // SAFETY: exact payload length proves one ucred is present.
                        let native = unsafe {
                            core::ptr::read_unaligned(libc::CMSG_DATA(header).cast::<libc::ucred>())
                        };
                        if native.pid <= 0 {
                            ancillary_valid = false;
                        } else {
                            credentials = Some(PacketCredentials {
                                pid: native.pid as u32,
                                uid: native.uid,
                                gid: native.gid,
                            });
                        }
                    }
                }
                (libc::SOL_SOCKET, libc::SCM_RIGHTS) => {
                    rights_records += 1;
                    if rights_records > 1 {
                        ancillary_valid = false;
                    }
                    if payload_len == 0 || !payload_len.is_multiple_of(size_of::<RawFd>()) {
                        ancillary_valid = false;
                    } else {
                        for index in 0..payload_len / size_of::<RawFd>() {
                            // SAFETY: the cmsg length proves this fd element exists.
                            let raw = unsafe {
                                core::ptr::read_unaligned(
                                    libc::CMSG_DATA(header).cast::<RawFd>().add(index),
                                )
                            };
                            if raw < 0 {
                                ancillary_valid = false;
                            } else {
                                // SAFETY: SCM_RIGHTS installed a new owned descriptor.
                                descriptors.push(unsafe { OwnedFd::from_raw_fd(raw) });
                            }
                        }
                    }
                }
                _ => ancillary_valid = false,
            }
            // SAFETY: advances only within the kernel-produced control chain.
            header = unsafe { libc::CMSG_NXTHDR(&message, header) };
        }

        if message.msg_flags & (libc::MSG_TRUNC | libc::MSG_CTRUNC) != 0 {
            return Err(PacketError::Truncated);
        }
        if received == 0 || received as usize != expected_len {
            return Err(PacketError::Truncated);
        }
        if !ancillary_valid {
            return Err(PacketError::MalformedAncillary);
        }
        let credentials = credentials.ok_or(PacketError::MalformedAncillary)?;
        if credentials != expected_peer {
            return Err(PacketError::WrongPeer);
        }
        if descriptors.len() != expected_descriptors {
            return Err(PacketError::WrongDescriptorCount);
        }
        if (expected_descriptors == 0 && rights_records != 0)
            || (expected_descriptors != 0 && rights_records != 1)
        {
            return Err(PacketError::MalformedAncillary);
        }
        bytes.truncate(received as usize);
        Ok(ReceivedPacket {
            bytes,
            descriptors,
            credentials,
        })
    }
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
            faults: DeadlineFaults::default(),
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

    #[cfg(test)]
    fn inject_send_interrupt(&mut self) -> bool {
        if self.faults.send_interrupts == 0 {
            false
        } else {
            self.faults.send_interrupts -= 1;
            true
        }
    }

    #[cfg(not(test))]
    const fn inject_send_interrupt(&mut self) -> bool {
        false
    }

    #[cfg(test)]
    fn inject_receive_interrupt(&mut self) -> bool {
        if self.faults.receive_interrupts == 0 {
            false
        } else {
            self.faults.receive_interrupts -= 1;
            true
        }
    }

    #[cfg(not(test))]
    const fn inject_receive_interrupt(&mut self) -> bool {
        false
    }

    #[cfg(test)]
    fn inject_expiry_after_send(&mut self, deadline: AbsoluteDeadline) {
        if self.faults.expire_after_send {
            self.faults.expire_after_send = false;
            while !deadline.is_expired() {
                std::thread::yield_now();
            }
        }
    }

    #[cfg(not(test))]
    const fn inject_expiry_after_send(&mut self, _: AbsoluteDeadline) {}

    #[cfg(test)]
    fn inject_expiry_after_receive(&mut self, deadline: AbsoluteDeadline) {
        if self.faults.expire_after_receive {
            self.faults.expire_after_receive = false;
            while !deadline.is_expired() {
                std::thread::yield_now();
            }
        }
    }

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
mod tests {
    use super::*;
    use static_assertions::{assert_impl_all, assert_not_impl_any};
    use std::os::unix::process::CommandExt;
    use std::process::Command;
    use std::time::{Duration, Instant};

    const ENV_CHILD_FD: &str = "NATIVE_IPC_VNEXT_TEST_CHILD_FD";
    const ENV_PARENT_PID: &str = "NATIVE_IPC_VNEXT_TEST_PARENT_PID";
    const ENV_PARENT_UID: &str = "NATIVE_IPC_VNEXT_TEST_PARENT_UID";
    const ENV_PARENT_GID: &str = "NATIVE_IPC_VNEXT_TEST_PARENT_GID";

    assert_impl_all!(SeqPacketEndpoint: Send);
    assert_not_impl_any!(SeqPacketEndpoint: Sync, Clone);
    assert_impl_all!(ProcessBoundEndpoint: Send);
    assert_not_impl_any!(ProcessBoundEndpoint: Sync, Clone);

    fn current_credentials() -> PacketCredentials {
        PacketCredentials {
            pid: std::process::id(),
            // SAFETY: scalar identity syscalls have no preconditions.
            uid: unsafe { libc::geteuid() },
            // SAFETY: scalar identity syscalls have no preconditions.
            gid: unsafe { libc::getegid() },
        }
    }

    fn receive_until(
        endpoint: &mut SeqPacketEndpoint,
        expected_len: usize,
        peer: PacketCredentials,
        descriptors: usize,
    ) -> Result<ReceivedPacket, PacketError> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match endpoint.receive(expected_len, peer, descriptors) {
                Err(PacketError::WouldBlock | PacketError::Interrupted)
                    if Instant::now() < deadline =>
                {
                    std::thread::yield_now();
                }
                result => return result,
            }
        }
    }

    fn open_fd_count() -> usize {
        std::fs::read_dir("/proc/self/fd").unwrap().count()
    }

    fn send_unchecked_rights(endpoint: &SeqPacketEndpoint, bytes: &[u8], fds: &[RawFd]) {
        let mut iovec = libc::iovec {
            iov_base: bytes.as_ptr().cast_mut().cast(),
            iov_len: bytes.len(),
        };
        let control_len = unsafe { libc::CMSG_SPACE(std::mem::size_of_val(fds) as u32) as usize };
        assert!(control_len <= CONTROL_CAPACITY);
        let mut control = ControlStorage::zeroed();
        let mut message: libc::msghdr = unsafe { zeroed() };
        message.msg_iov = &mut iovec;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr();
        message.msg_controllen = control_len;
        unsafe {
            let header = libc::CMSG_FIRSTHDR(&message);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of_val(fds) as u32) as usize;
            core::ptr::copy_nonoverlapping(
                fds.as_ptr(),
                libc::CMSG_DATA(header).cast::<RawFd>(),
                fds.len(),
            );
            assert_eq!(
                libc::sendmsg(endpoint.fd.as_raw_fd(), &message, libc::MSG_NOSIGNAL),
                bytes.len() as isize
            );
        }
    }

    fn cached_peer_credentials(endpoint: &SeqPacketEndpoint) -> PacketCredentials {
        let mut native: libc::ucred = unsafe { zeroed() };
        let mut length = size_of::<libc::ucred>() as libc::socklen_t;
        let result = unsafe {
            libc::getsockopt(
                endpoint.fd.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut native as *mut libc::ucred).cast(),
                &mut length,
            )
        };
        assert_eq!(result, 0);
        assert_eq!(length as usize, size_of::<libc::ucred>());
        PacketCredentials {
            pid: native.pid as u32,
            uid: native.uid,
            gid: native.gid,
        }
    }

    fn open_pidfd(pid: u32) -> OwnedFd {
        // SAFETY: pidfd_open has scalar arguments and returns a new fd.
        let raw = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) } as RawFd;
        assert!(raw >= 0);
        // SAFETY: successful pidfd_open returned a new owned descriptor.
        unsafe { OwnedFd::from_raw_fd(raw) }
    }

    fn self_bound_pair() -> (ProcessBoundEndpoint, ProcessBoundEndpoint) {
        let (left, right) = SeqPacketEndpoint::pair().unwrap();
        let credentials = current_credentials();
        // SAFETY: both socket peers and pidfds name this exact test process.
        let left = unsafe {
            ProcessBoundEndpoint::from_verified_process(
                left,
                open_pidfd(std::process::id()),
                credentials,
            )
        };
        // SAFETY: both socket peers and pidfds name this exact test process.
        let right = unsafe {
            ProcessBoundEndpoint::from_verified_process(
                right,
                open_pidfd(std::process::id()),
                credentials,
            )
        };
        (left, right)
    }

    #[test]
    fn one_packet_has_exact_credentials_and_zero_to_sixteen_owned_fds() {
        let (mut sender, mut receiver) = SeqPacketEndpoint::pair().unwrap();
        let file = std::fs::File::open("/dev/null").unwrap();
        let credentials = current_credentials();
        for count in [0, 1, 2, 16] {
            let descriptors = vec![file.as_raw_fd(); count];
            sender.send(b"packet", &descriptors).unwrap();
            let packet = receive_until(&mut receiver, 6, credentials, count).unwrap();
            assert_eq!(packet.bytes, b"packet");
            assert_eq!(packet.credentials, credentials);
            assert_eq!(packet.descriptors.len(), count);
            for descriptor in &packet.descriptors {
                // SAFETY: descriptor is live and F_GETFD has no pointer argument.
                let flags = unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFD) };
                assert_ne!(flags & libc::FD_CLOEXEC, 0);
            }
        }
    }

    #[test]
    fn one_absolute_deadline_bounds_nonblocking_send_receive_and_silence() {
        let (mut sender, mut receiver) = self_bound_pair();
        let deadline = AbsoluteDeadline::after(Duration::from_secs(1)).unwrap();
        sender.send_before(b"packet", &[], deadline).unwrap();
        let packet = receiver.receive_before(6, 0, deadline).unwrap();
        assert_eq!(packet.bytes, b"packet");

        let started = Instant::now();
        let silence = AbsoluteDeadline::after(Duration::from_millis(25)).unwrap();
        assert!(matches!(
            receiver.receive_before(6, 0, silence),
            Err(PacketError::DeadlineExpired)
        ));
        assert!(started.elapsed() >= Duration::from_millis(1));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn saturated_send_recomputes_one_deadline_while_pollout_stays_blocked() {
        let (mut sender, _receiver) = SeqPacketEndpoint::pair().unwrap();
        let packet = [0_u8; CONTROL_FRAME_LEN];
        let mut saturated = false;
        for _ in 0..100_000 {
            match sender.send(&packet, &[]) {
                Ok(()) => {}
                Err(PacketError::WouldBlock) => {
                    saturated = true;
                    break;
                }
                Err(PacketError::Interrupted) => {}
                Err(error) => panic!("unexpected saturation error: {error:?}"),
            }
        }
        assert!(saturated, "bounded socket send queue never saturated");
        // SAFETY: the connected peer and pidfd both name this exact process.
        let mut sender = unsafe {
            ProcessBoundEndpoint::from_verified_process(
                sender,
                open_pidfd(std::process::id()),
                current_credentials(),
            )
        };
        let started = Instant::now();
        let deadline = AbsoluteDeadline::after(Duration::from_millis(25)).unwrap();
        assert!(matches!(
            sender.send_before(&packet, &[], deadline),
            Err(PacketError::DeadlineExpired)
        ));
        assert!(started.elapsed() >= Duration::from_millis(1));
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn injected_eintr_retries_and_late_io_has_ambiguous_terminal_errors() {
        let (mut sender, mut receiver) = self_bound_pair();
        sender.faults.send_interrupts = 2;
        receiver.faults.receive_interrupts = 2;
        let deadline = AbsoluteDeadline::after(Duration::from_secs(1)).unwrap();
        sender.send_before(b"eintr!", &[], deadline).unwrap();
        assert_eq!(
            receiver.receive_before(6, 0, deadline).unwrap().bytes,
            b"eintr!"
        );

        sender.faults.expire_after_send = true;
        let deadline = AbsoluteDeadline::after(Duration::from_millis(5)).unwrap();
        assert_eq!(
            sender.send_before(b"late-s", &[], deadline),
            Err(PacketError::AmbiguousAfterSend)
        );
        let fresh = AbsoluteDeadline::after(Duration::from_secs(1)).unwrap();
        assert_eq!(
            receiver.receive_before(6, 0, fresh).unwrap().bytes,
            b"late-s"
        );
        assert_eq!(
            sender.send_before(b"again!", &[], fresh),
            Err(PacketError::Poisoned)
        );

        let (mut second_sender, mut second_receiver) = self_bound_pair();
        second_sender.send_before(b"late-r", &[], fresh).unwrap();
        second_receiver.faults.expire_after_receive = true;
        let deadline = AbsoluteDeadline::after(Duration::from_millis(5)).unwrap();
        assert!(matches!(
            second_receiver.receive_before(6, 0, deadline),
            Err(PacketError::AmbiguousAfterReceive)
        ));
        assert!(matches!(
            second_receiver.receive_before(6, 0, fresh),
            Err(PacketError::Poisoned)
        ));
    }

    #[test]
    #[ignore = "spawned alone by descriptor_cleanup_is_zero_growth"]
    fn short_wrong_peer_and_extra_rights_packets_close_every_installed_fd() {
        let file = std::fs::File::open("/dev/null").unwrap();
        let credentials = current_credentials();
        let wrong_peer = PacketCredentials {
            pid: credentials.pid.wrapping_add(1),
            ..credentials
        };
        for (expected_len, peer, expected_fds) in
            [(7, credentials, 2), (6, wrong_peer, 2), (6, credentials, 1)]
        {
            let (mut sender, mut receiver) = SeqPacketEndpoint::pair().unwrap();
            let before = open_fd_count();
            sender
                .send(b"packet", &[file.as_raw_fd(), file.as_raw_fd()])
                .unwrap();
            assert!(receive_until(&mut receiver, expected_len, peer, expected_fds).is_err());
            assert_eq!(open_fd_count(), before);
        }
    }

    #[test]
    #[ignore = "spawned alone by descriptor_cleanup_is_zero_growth"]
    fn truncated_ancillary_closes_every_fd_that_the_kernel_installed() {
        let (sender, mut receiver) = SeqPacketEndpoint::pair().unwrap();
        let file = std::fs::File::open("/dev/null").unwrap();
        let descriptors = vec![file.as_raw_fd(); MAX_PACKET_FDS + 1];
        let before = open_fd_count();
        send_unchecked_rights(&sender, b"packet", &descriptors);
        assert!(matches!(
            receive_until(&mut receiver, 6, current_credentials(), MAX_PACKET_FDS),
            Err(PacketError::Truncated)
        ));
        assert_eq!(open_fd_count(), before);
    }

    #[test]
    fn descriptor_cleanup_is_zero_growth() {
        let executable = std::env::current_exe().unwrap();
        for test in [
            "backend::linux_vnext::tests::short_wrong_peer_and_extra_rights_packets_close_every_installed_fd",
            "backend::linux_vnext::tests::truncated_ancillary_closes_every_fd_that_the_kernel_installed",
        ] {
            let status = Command::new(&executable)
                .args(["--exact", test, "--ignored", "--nocapture"])
                .status()
                .unwrap();
            assert!(status.success(), "isolated descriptor test failed: {test}");
        }
    }

    #[test]
    #[ignore = "spawned as the post-exec credential helper"]
    fn spawned_credential_helper() {
        let raw: RawFd = std::env::var(ENV_CHILD_FD).unwrap().parse().unwrap();
        let parent = PacketCredentials {
            pid: std::env::var(ENV_PARENT_PID).unwrap().parse().unwrap(),
            uid: std::env::var(ENV_PARENT_UID).unwrap().parse().unwrap(),
            gid: std::env::var(ENV_PARENT_GID).unwrap().parse().unwrap(),
        };
        // SAFETY: the pre-exec hook transferred the sole inherited endpoint here.
        let mut endpoint = unsafe { SeqPacketEndpoint::from_inherited(raw) }.unwrap();
        let packet = receive_until(&mut endpoint, 6, parent, 0).unwrap();
        assert_eq!(packet.bytes, b"parent");
        endpoint.send(b"child", &[]).unwrap();
        let acknowledgement = receive_until(&mut endpoint, 3, parent, 0).unwrap();
        assert_eq!(acknowledgement.bytes, b"ack");
    }

    #[test]
    #[ignore = "spawned as an immediate pidfd-exit helper"]
    fn immediate_exit_helper() {}

    #[test]
    fn retained_pidfd_wakes_a_long_socket_wait_on_peer_exit() {
        let (_sender, receiver) = SeqPacketEndpoint::pair().unwrap();
        let executable = std::env::current_exe().unwrap();
        let mut child = Command::new(executable)
            .args([
                "--exact",
                "backend::linux_vnext::tests::immediate_exit_helper",
                "--ignored",
            ])
            .spawn()
            .unwrap();
        let pidfd = open_pidfd(child.id());
        let started = Instant::now();
        let deadline = AbsoluteDeadline::after(Duration::from_secs(10)).unwrap();
        assert!(matches!(
            poll_until(
                receiver.fd.as_raw_fd(),
                pidfd.as_raw_fd(),
                libc::POLLIN,
                deadline
            ),
            Err(PacketError::PeerExited)
        ));
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(child.wait().unwrap().success());
    }

    #[test]
    fn spawned_packet_credentials_match_exact_child_and_retained_pidfd() {
        let (parent_endpoint, child_endpoint) = SeqPacketEndpoint::pair().unwrap();
        let source = child_endpoint.fd.as_raw_fd();
        let parent = current_credentials();
        assert_eq!(cached_peer_credentials(&parent_endpoint), parent);
        let executable = std::env::current_exe().unwrap();
        let mut command = Command::new(executable);
        command
            .args([
                "--exact",
                "backend::linux_vnext::tests::spawned_credential_helper",
                "--ignored",
                "--nocapture",
            ])
            .env(ENV_CHILD_FD, source.to_string())
            .env(ENV_PARENT_PID, parent.pid.to_string())
            .env(ENV_PARENT_UID, parent.uid.to_string())
            .env(ENV_PARENT_GID, parent.gid.to_string());
        // SAFETY: only async-signal-safe fd syscalls run between fork and exec.
        unsafe {
            command.pre_exec(move || {
                if libc::fcntl(source, libc::F_SETFD, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn().unwrap();
        let child_credentials = PacketCredentials {
            pid: child.id(),
            uid: parent.uid,
            gid: parent.gid,
        };
        let pidfd = open_pidfd(child.id());
        drop(child_endpoint);
        // SAFETY: the packet topology, expected credentials, Child ID, and
        // freshly opened pidfd all identify this exact live helper.
        let mut parent_endpoint = unsafe {
            ProcessBoundEndpoint::from_verified_process(parent_endpoint, pidfd, child_credentials)
        };
        let deadline = AbsoluteDeadline::after(Duration::from_secs(10)).unwrap();
        parent_endpoint
            .send_before(b"parent", &[], deadline)
            .unwrap();
        let packet = parent_endpoint.receive_before(5, 0, deadline).unwrap();
        assert_eq!(packet.bytes, b"child");
        assert_eq!(packet.credentials.pid, child.id());
        assert_ne!(
            packet.credentials.pid,
            cached_peer_credentials(&parent_endpoint.endpoint).pid
        );
        parent_endpoint.send_before(b"ack", &[], deadline).unwrap();
        assert!(child.wait().unwrap().success());
        let mut poll = libc::pollfd {
            fd: parent_endpoint.peer_pidfd.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: poll points to one initialized entry.
        assert_eq!(unsafe { libc::poll(&mut poll, 1, 0) }, 1);
        assert_ne!(poll.revents, 0);
    }
}
