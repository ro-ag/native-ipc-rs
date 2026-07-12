use super::*;
use static_assertions::{assert_impl_all, assert_not_impl_any};
use std::os::fd::IntoRawFd;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::time::{Duration, Instant};

const ENV_CHILD_FD: &str = "NATIVE_IPC_VNEXT_TEST_CHILD_FD";
const ENV_PARENT_PID: &str = "NATIVE_IPC_VNEXT_TEST_PARENT_PID";
const ENV_PARENT_UID: &str = "NATIVE_IPC_VNEXT_TEST_PARENT_UID";
const ENV_PARENT_GID: &str = "NATIVE_IPC_VNEXT_TEST_PARENT_GID";

#[derive(Default)]
pub(super) struct DeadlineFaults {
    send_interrupts: u8,
    receive_interrupts: u8,
    send_interrupts_until_expired: bool,
    receive_interrupts_until_expired: bool,
    expire_after_send: bool,
    expire_after_receive: bool,
}

impl ProcessBoundEndpoint {
    pub(super) fn inject_send_interrupt(&mut self) -> bool {
        if self.faults.send_interrupts_until_expired {
            true
        } else if self.faults.send_interrupts == 0 {
            false
        } else {
            self.faults.send_interrupts -= 1;
            true
        }
    }

    pub(super) fn inject_receive_interrupt(&mut self) -> bool {
        if self.faults.receive_interrupts_until_expired {
            true
        } else if self.faults.receive_interrupts == 0 {
            false
        } else {
            self.faults.receive_interrupts -= 1;
            true
        }
    }

    pub(super) fn inject_expiry_after_send(&mut self, deadline: AbsoluteDeadline) {
        if self.faults.expire_after_send {
            self.faults.expire_after_send = false;
            while !deadline.is_expired() {
                std::thread::yield_now();
            }
        }
    }

    pub(super) fn inject_expiry_after_receive(&mut self, deadline: AbsoluteDeadline) {
        if self.faults.expire_after_receive {
            self.faults.expire_after_receive = false;
            while !deadline.is_expired() {
                std::thread::yield_now();
            }
        }
    }
}

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

fn wait_until_expired(deadline: AbsoluteDeadline) {
    while !deadline.is_expired() {
        std::thread::yield_now();
    }
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

#[derive(Clone, Copy)]
enum MalformedRightsTail {
    DuplicateRights,
    EmptyRights,
    NegativeRight,
    WrongLevel,
    WrongType,
    ShortLength,
    LongLength,
    RightWithTrailingByte,
}

unsafe fn write_synthetic_header(
    control: &mut ControlStorage,
    offset: usize,
    level: libc::c_int,
    kind: libc::c_int,
    declared_len: usize,
) -> *mut libc::cmsghdr {
    // SAFETY: callers use aligned CMSG_SPACE offsets within ControlStorage.
    let header = unsafe {
        control
            .as_mut_ptr()
            .cast::<u8>()
            .add(offset)
            .cast::<libc::cmsghdr>()
    };
    // SAFETY: the complete aligned header lies inside ControlStorage.
    unsafe {
        header.write(libc::cmsghdr {
            cmsg_len: declared_len,
            cmsg_level: level,
            cmsg_type: kind,
        });
    }
    header
}

unsafe fn write_synthetic_right(control: &mut ControlStorage, offset: usize, raw: RawFd) -> usize {
    // SAFETY: CMSG_LEN performs scalar layout arithmetic only.
    let length = unsafe { libc::CMSG_LEN(size_of::<RawFd>() as u32) as usize };
    // SAFETY: caller reserved a complete rights record at this aligned offset.
    let header = unsafe {
        write_synthetic_header(control, offset, libc::SOL_SOCKET, libc::SCM_RIGHTS, length)
    };
    // SAFETY: the rights payload has exact RawFd size and alignment is not required.
    unsafe { core::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<RawFd>(), raw) };
    // SAFETY: CMSG_SPACE performs scalar layout arithmetic only.
    offset + unsafe { libc::CMSG_SPACE(size_of::<RawFd>() as u32) as usize }
}

fn assert_malformed_rights_tail_closes_adopted_fds(tail: MalformedRightsTail) {
    let before = open_fd_count();
    let first = std::fs::File::open("/dev/null").unwrap().into_raw_fd();
    let mut control = ControlStorage::zeroed();
    // SAFETY: ownership of `first` transfers into the synthetic SCM_RIGHTS record.
    let second_offset = unsafe { write_synthetic_right(&mut control, 0, first) };
    // SAFETY: CMSG_LEN/CMSG_SPACE perform scalar layout arithmetic only.
    let minimum = unsafe { libc::CMSG_LEN(0) as usize };
    // SAFETY: every chosen range remains within the fixed control storage.
    let control_len = unsafe {
        match tail {
            MalformedRightsTail::DuplicateRights => {
                let second = std::fs::File::open("/dev/null").unwrap().into_raw_fd();
                write_synthetic_right(&mut control, second_offset, second)
            }
            MalformedRightsTail::EmptyRights => {
                write_synthetic_header(
                    &mut control,
                    second_offset,
                    libc::SOL_SOCKET,
                    libc::SCM_RIGHTS,
                    minimum,
                );
                second_offset + minimum
            }
            MalformedRightsTail::NegativeRight => {
                let length = libc::CMSG_LEN(size_of::<RawFd>() as u32) as usize;
                let header = write_synthetic_header(
                    &mut control,
                    second_offset,
                    libc::SOL_SOCKET,
                    libc::SCM_RIGHTS,
                    length,
                );
                core::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<RawFd>(), -1);
                second_offset + libc::CMSG_SPACE(size_of::<RawFd>() as u32) as usize
            }
            MalformedRightsTail::WrongLevel => {
                write_synthetic_header(
                    &mut control,
                    second_offset,
                    libc::IPPROTO_IP,
                    libc::SCM_RIGHTS,
                    minimum,
                );
                second_offset + minimum
            }
            MalformedRightsTail::WrongType => {
                write_synthetic_header(
                    &mut control,
                    second_offset,
                    libc::SOL_SOCKET,
                    libc::SCM_CREDENTIALS + 1,
                    minimum,
                );
                second_offset + minimum
            }
            MalformedRightsTail::ShortLength => {
                write_synthetic_header(
                    &mut control,
                    second_offset,
                    libc::SOL_SOCKET,
                    libc::SCM_RIGHTS,
                    minimum - 1,
                );
                second_offset + minimum
            }
            MalformedRightsTail::LongLength => {
                write_synthetic_header(
                    &mut control,
                    second_offset,
                    libc::SOL_SOCKET,
                    libc::SCM_RIGHTS,
                    minimum + 1,
                );
                second_offset + minimum
            }
            MalformedRightsTail::RightWithTrailingByte => {
                let trailing = std::fs::File::open("/dev/null").unwrap().into_raw_fd();
                let payload_len = size_of::<RawFd>() + 1;
                let length = libc::CMSG_LEN(payload_len as u32) as usize;
                let header = write_synthetic_header(
                    &mut control,
                    second_offset,
                    libc::SOL_SOCKET,
                    libc::SCM_RIGHTS,
                    length,
                );
                core::ptr::write_unaligned(libc::CMSG_DATA(header).cast::<RawFd>(), trailing);
                libc::CMSG_DATA(header)
                    .cast::<u8>()
                    .add(size_of::<RawFd>())
                    .write(0xa5);
                second_offset + libc::CMSG_SPACE(payload_len as u32) as usize
            }
        }
    };
    assert!(control_len <= CONTROL_CAPACITY);
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_control = control.as_mut_ptr();
    message.msg_controllen = control_len;
    // SAFETY: all nonnegative fds in rights records were transferred with
    // IntoRawFd and the complete synthetic control range remains live.
    let ancillary = unsafe { adopt_received_ancillary(&message, control_len) }.unwrap();
    assert!(matches!(
        ancillary.validate(current_credentials(), 1),
        Err(PacketError::MalformedAncillary)
    ));
    assert_eq!(open_fd_count(), before);
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
fn variable_zero_rights_packets_enforce_native_ceiling_and_credentials() {
    let (mut sender, mut receiver) = SeqPacketEndpoint::pair().unwrap();
    let credentials = current_credentials();
    for payload in [vec![7_u8; 1], vec![9_u8; MAX_ZERO_RIGHTS_PACKET_BYTES]] {
        sender.send_zero_rights(&payload).unwrap();
        let packet = receiver.receive_zero_rights(credentials).unwrap();
        assert_eq!(packet.bytes, payload);
        assert!(packet.descriptors.is_empty());
        assert_eq!(packet.credentials, credentials);
    }
    assert_eq!(
        sender.send_zero_rights(&vec![0; MAX_ZERO_RIGHTS_PACKET_BYTES + 1]),
        Err(PacketError::InvalidInput)
    );
    assert!(matches!(
        receiver.receive_zero_rights(credentials),
        Err(PacketError::WouldBlock)
    ));
    assert_eq!(sender.send_zero_rights(&[]), Err(PacketError::InvalidInput));

    sender.send_zero_rights(b"wrong").unwrap();
    let wrong = PacketCredentials {
        pid: credentials.pid.saturating_add(1),
        ..credentials
    };
    assert!(matches!(
        receiver.receive_zero_rights(wrong),
        Err(PacketError::WrongPeer)
    ));
}

#[test]
fn queued_oversize_and_injected_rights_are_consumed_without_fd_growth() {
    let (sender, mut receiver) = SeqPacketEndpoint::pair().unwrap();
    let credentials = current_credentials();
    let oversize = vec![1_u8; MAX_ZERO_RIGHTS_PACKET_BYTES + 1];
    // SAFETY: the buffer is live and the connected socket consumes one datagram.
    assert_eq!(
        unsafe {
            libc::send(
                sender.fd.as_raw_fd(),
                oversize.as_ptr().cast(),
                oversize.len(),
                libc::MSG_NOSIGNAL,
            )
        },
        oversize.len() as isize
    );
    assert_eq!(
        receiver.receive_zero_rights(credentials).err().unwrap(),
        PacketError::Truncated
    );
    assert!(matches!(
        receiver.receive_zero_rights(credentials),
        Err(PacketError::WouldBlock)
    ));

    let before = open_fd_count();
    let file = std::fs::File::open("/dev/null").unwrap();
    send_unchecked_rights(&sender, b"r", &[file.as_raw_fd()]);
    assert_eq!(
        receiver.receive_zero_rights(credentials).err().unwrap(),
        PacketError::WrongDescriptorCount
    );
    assert_eq!(open_fd_count(), before + 1);
    drop(file);
    assert_eq!(open_fd_count(), before);
}

#[test]
fn variable_zero_rights_deadlines_interruptions_and_late_completion_poison() {
    let (mut sender, mut receiver) = self_bound_pair();
    sender.faults.send_interrupts = 2;
    receiver.faults.receive_interrupts = 2;
    let deadline = AbsoluteDeadline::after(Duration::from_secs(1)).unwrap();
    sender.send_zero_rights_before(b"eintr", deadline).unwrap();
    assert_eq!(
        receiver.receive_zero_rights_before(deadline).unwrap().bytes,
        b"eintr"
    );

    let silence = AbsoluteDeadline::after(Duration::from_millis(20)).unwrap();
    assert_eq!(
        receiver.receive_zero_rights_before(silence).err().unwrap(),
        PacketError::DeadlineExpired
    );

    sender.faults.expire_after_send = true;
    let late = AbsoluteDeadline::after(Duration::from_millis(5)).unwrap();
    assert_eq!(
        sender.send_zero_rights_before(b"late", late),
        Err(PacketError::AmbiguousAfterSend)
    );
    assert_eq!(
        sender.send_zero_rights_before(b"again", deadline),
        Err(PacketError::Poisoned)
    );

    let (mut second_sender, mut second_receiver) = self_bound_pair();
    second_sender
        .send_zero_rights_before(b"late-r", deadline)
        .unwrap();
    second_receiver.faults.expire_after_receive = true;
    let late = AbsoluteDeadline::after(Duration::from_millis(5)).unwrap();
    assert_eq!(
        second_receiver
            .receive_zero_rights_before(late)
            .err()
            .unwrap(),
        PacketError::AmbiguousAfterReceive
    );
    assert!(matches!(
        second_receiver.receive_zero_rights_before(deadline),
        Err(PacketError::Poisoned)
    ));

    let (mut saturated, _peer) = self_bound_pair();
    let packet = vec![0_u8; MAX_ZERO_RIGHTS_PACKET_BYTES];
    while matches!(
        saturated.endpoint.send_zero_rights(&packet),
        Ok(()) | Err(PacketError::Interrupted)
    ) {}
    let short = AbsoluteDeadline::after(Duration::from_millis(20)).unwrap();
    assert_eq!(
        saturated.send_zero_rights_before(&packet, short),
        Err(PacketError::DeadlineExpired)
    );
}

#[test]
fn variable_zero_rights_wait_wakes_on_exact_peer_exit() {
    let (sender, receiver) = SeqPacketEndpoint::pair().unwrap();
    let inherited = sender.fd.as_raw_fd();
    let executable = std::env::current_exe().unwrap();
    let mut command = Command::new(executable);
    command.args([
        "--exact",
        "backend::linux_vnext::tests::immediate_exit_helper",
        "--ignored",
    ]);
    // SAFETY: only the async-signal-safe fcntl syscall runs before exec; this
    // exact connected endpoint is the sole intentional inherited test fd.
    unsafe {
        command.pre_exec(move || {
            if libc::fcntl(inherited, libc::F_SETFD, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = command.spawn().unwrap();
    let credentials = PacketCredentials {
        pid: child.id(),
        uid: current_credentials().uid,
        gid: current_credentials().gid,
    };
    let pidfd = open_pidfd(child.id());
    drop(sender);
    // SAFETY: receiver is the connected endpoint and pidfd/credentials name the child.
    let mut receiver =
        unsafe { ProcessBoundEndpoint::from_verified_process(receiver, pidfd, credentials) };
    let deadline = AbsoluteDeadline::after(Duration::from_secs(2)).unwrap();
    assert_eq!(
        receiver.receive_zero_rights_before(deadline).err().unwrap(),
        PacketError::PeerExited
    );
    assert!(child.wait().unwrap().success());
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
fn expired_deadline_performs_no_io_and_does_not_consume_a_queued_packet() {
    let (mut sender, mut receiver) = self_bound_pair();
    let expired_send = AbsoluteDeadline::after(Duration::from_millis(2)).unwrap();
    wait_until_expired(expired_send);
    assert_eq!(
        sender.send_before(b"never!", &[], expired_send),
        Err(PacketError::DeadlineExpired)
    );
    assert!(matches!(
        receiver.endpoint.receive(6, current_credentials(), 0),
        Err(PacketError::WouldBlock)
    ));

    let (mut sender, mut receiver) = self_bound_pair();
    let fresh = AbsoluteDeadline::after(Duration::from_secs(1)).unwrap();
    sender.send_before(b"queued", &[], fresh).unwrap();
    let expired_receive = AbsoluteDeadline::after(Duration::from_millis(2)).unwrap();
    wait_until_expired(expired_receive);
    assert!(matches!(
        receiver.receive_before(6, 0, expired_receive),
        Err(PacketError::DeadlineExpired)
    ));
    assert_eq!(
        receiver
            .endpoint
            .receive(6, current_credentials(), 0)
            .unwrap()
            .bytes,
        b"queued"
    );
}

#[test]
fn continuous_interruption_retries_cannot_extend_one_absolute_deadline() {
    let (mut sender, mut receiver) = self_bound_pair();
    sender.faults.send_interrupts_until_expired = true;
    let started = Instant::now();
    let deadline = AbsoluteDeadline::after(Duration::from_millis(25)).unwrap();
    assert_eq!(
        sender.send_before(b"never!", &[], deadline),
        Err(PacketError::DeadlineExpired)
    );
    assert!(started.elapsed() < Duration::from_secs(1));

    receiver.faults.receive_interrupts_until_expired = true;
    let started = Instant::now();
    let deadline = AbsoluteDeadline::after(Duration::from_millis(25)).unwrap();
    assert!(matches!(
        receiver.receive_before(6, 0, deadline),
        Err(PacketError::DeadlineExpired)
    ));
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
#[ignore = "spawned alone by descriptor_cleanup_is_zero_growth"]
fn truncated_payload_closes_rights_installed_before_msg_trunc_is_reported() {
    let (sender, mut receiver) = SeqPacketEndpoint::pair().unwrap();
    let file = std::fs::File::open("/dev/null").unwrap();
    let bytes = vec![0_u8; CONTROL_FRAME_LEN + 1];
    let before = open_fd_count();
    send_unchecked_rights(&sender, &bytes, &[file.as_raw_fd()]);
    assert!(matches!(
        receive_until(&mut receiver, CONTROL_FRAME_LEN, current_credentials(), 1),
        Err(PacketError::Truncated)
    ));
    assert_eq!(open_fd_count(), before);
}

#[test]
#[ignore = "spawned alone by descriptor_cleanup_is_zero_growth"]
fn malformed_rights_chains_close_every_fd_adopted_before_rejection() {
    for tail in [
        MalformedRightsTail::DuplicateRights,
        MalformedRightsTail::EmptyRights,
        MalformedRightsTail::NegativeRight,
        MalformedRightsTail::WrongLevel,
        MalformedRightsTail::WrongType,
        MalformedRightsTail::ShortLength,
        MalformedRightsTail::LongLength,
    ] {
        assert_malformed_rights_tail_closes_adopted_fds(tail);
    }
}

#[test]
#[ignore = "spawned alone by descriptor_cleanup_is_zero_growth"]
fn rights_payload_with_complete_fd_and_trailing_byte_closes_every_fd() {
    assert_malformed_rights_tail_closes_adopted_fds(MalformedRightsTail::RightWithTrailingByte);
}

#[test]
fn descriptor_cleanup_is_zero_growth() {
    let executable = std::env::current_exe().unwrap();
    for test in [
        "backend::linux_vnext::tests::short_wrong_peer_and_extra_rights_packets_close_every_installed_fd",
        "backend::linux_vnext::tests::truncated_ancillary_closes_every_fd_that_the_kernel_installed",
        "backend::linux_vnext::tests::truncated_payload_closes_rights_installed_before_msg_trunc_is_reported",
        "backend::linux_vnext::tests::malformed_rights_chains_close_every_fd_adopted_before_rejection",
        "backend::linux_vnext::tests::rights_payload_with_complete_fd_and_trailing_byte_closes_every_fd",
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
