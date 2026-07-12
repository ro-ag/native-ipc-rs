use super::*;
use static_assertions::{assert_impl_all, assert_not_impl_any};
use std::os::fd::IntoRawFd;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

const ENV_CHILD_FD: &str = "NATIVE_IPC_VNEXT_TEST_CHILD_FD";
const ENV_PARENT_PID: &str = "NATIVE_IPC_VNEXT_TEST_PARENT_PID";
const ENV_PARENT_UID: &str = "NATIVE_IPC_VNEXT_TEST_PARENT_UID";
const ENV_PARENT_GID: &str = "NATIVE_IPC_VNEXT_TEST_PARENT_GID";
const PR_SET_PDEATHSIG_TEST: libc::c_int = 1;

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

fn open_map_count() -> usize {
    std::fs::read_to_string("/proc/self/maps")
        .unwrap()
        .lines()
        .count()
}

fn direct_child_is_absent(pid: libc::pid_t) -> bool {
    !std::fs::read_to_string("/proc/thread-self/children")
        .unwrap()
        .split_ascii_whitespace()
        .any(|value| value.parse::<libc::pid_t>() == Ok(pid))
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
#[ignore = "spawned alone by queued_oversize_and_injected_rights_are_consumed_without_fd_growth"]
fn isolated_queued_oversize_and_injected_rights_are_consumed_without_fd_growth() {
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
fn queued_oversize_and_injected_rights_are_consumed_without_fd_growth() {
    let status = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "backend::linux_vnext::tests::isolated_queued_oversize_and_injected_rights_are_consumed_without_fd_growth",
            "--ignored",
            "--nocapture",
        ])
        .status()
        .unwrap();
    assert!(status.success());
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

struct AtomicProbeMapping {
    address: *mut libc::c_void,
    length: usize,
}

impl AtomicProbeMapping {
    fn new(length: usize) -> Self {
        // SAFETY: anonymous shared mapping needs no fd or offset object.
        let address = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                length,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        assert_ne!(address, libc::MAP_FAILED);
        Self { address, length }
    }
}

impl Drop for AtomicProbeMapping {
    fn drop(&mut self) {
        // SAFETY: this object uniquely owns the complete live mapping.
        assert_eq!(unsafe { libc::munmap(self.address, self.length) }, 0);
    }
}

#[test]
#[ignore = "spawned alone by linux_atomic_capabilities_match_native_publication"]
fn isolated_linux_atomic_capabilities_match_native_publication() {
    const PUBLISHED_U32: u32 = 0x51a7_c032;
    const ACK_U32: u32 = 0xa11c_0032;
    const PUBLISHED_U64: u64 = 0x51a7_c064_51a7_c064;
    const ACK_U64: u64 = 0xa11c_0064_a11c_0064;

    let before_fds = open_fd_count();
    let before_maps = open_map_count();
    let capabilities = discover_atomic_capabilities().unwrap();
    // SAFETY: scalar sysconf selectors have no pointer arguments.
    let page = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    // SAFETY: scalar sysconf selectors have no pointer arguments.
    let cache_line = unsafe { libc::sysconf(libc::_SC_LEVEL1_DCACHE_LINESIZE) };
    assert!(page > 0 && cache_line > 0);
    assert_eq!(capabilities.page_alignment(), page as usize);
    assert_eq!(capabilities.cache_line_alignment(), cache_line as usize);
    assert_eq!(
        capabilities.atomic_u32_alignment(),
        core::mem::align_of::<AtomicU32>()
    );
    assert_eq!(
        capabilities.atomic_u64_alignment(),
        core::mem::align_of::<AtomicU64>()
    );
    assert_eq!(
        capabilities.atomic_u32_lock_free(),
        cfg!(target_has_atomic = "32")
    );
    assert_eq!(
        capabilities.atomic_u64_lock_free(),
        cfg!(target_has_atomic = "64")
    );
    capabilities.require(true, true).unwrap();

    let stride = capabilities.cache_line_alignment();
    let required = stride.checked_mul(4).unwrap();
    assert!(required <= capabilities.page_alignment());
    let mapping = AtomicProbeMapping::new(capabilities.page_alignment());
    let base = mapping.address.cast::<u8>();
    // SAFETY: the page-aligned mapping covers four cache-line-aligned slots;
    // each atomic is initialized before fork and has a disjoint address.
    let (published_u32, ack_u32, published_u64, ack_u64) = unsafe {
        let published_u32 = base.cast::<AtomicU32>();
        let ack_u32 = base.add(stride).cast::<AtomicU32>();
        let published_u64 = base.add(stride * 2).cast::<AtomicU64>();
        let ack_u64 = base.add(stride * 3).cast::<AtomicU64>();
        published_u32.write(AtomicU32::new(0));
        ack_u32.write(AtomicU32::new(0));
        published_u64.write(AtomicU64::new(0));
        ack_u64.write(AtomicU64::new(0));
        (&*published_u32, &*ack_u32, &*published_u64, &*ack_u64)
    };
    for address in [
        published_u32 as *const AtomicU32 as usize,
        ack_u32 as *const AtomicU32 as usize,
    ] {
        assert!(address.is_multiple_of(capabilities.atomic_u32_alignment()));
    }
    for address in [
        published_u64 as *const AtomicU64 as usize,
        ack_u64 as *const AtomicU64 as usize,
    ] {
        assert!(address.is_multiple_of(capabilities.atomic_u64_alignment()));
    }

    // SAFETY: the isolated test process has initialized all fork-shared state.
    let parent_pid = unsafe { libc::getpid() };
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        // Child audit: target_has_atomic compile-time gates prove these widths
        // lock-free; only raw syscalls, atomic operations, spin hints, and raw
        // _exit follow. PDEATHSIG is the failure-path backstop for a panicking
        // isolated parent.
        // SAFETY: scalar raw syscall arguments install an uncatchable death signal.
        if unsafe {
            libc::syscall(
                libc::SYS_prctl,
                PR_SET_PDEATHSIG_TEST,
                libc::SIGKILL,
                0,
                0,
                0,
            )
        } != 0
            // SAFETY: scalar raw syscall checks the parent-death race.
            || unsafe { libc::syscall(libc::SYS_getppid) } != libc::c_long::from(parent_pid)
        {
            // SAFETY: the raw child must not unwind or run Rust destructors.
            unsafe { libc::_exit(124) };
        }
        while published_u32.load(Ordering::Acquire) != PUBLISHED_U32 {
            core::hint::spin_loop();
        }
        ack_u32.store(ACK_U32, Ordering::Release);
        while published_u64.load(Ordering::Acquire) != PUBLISHED_U64 {
            core::hint::spin_loop();
        }
        ack_u64.store(ACK_U64, Ordering::Release);
        // SAFETY: the raw child must not unwind or run Rust destructors.
        unsafe { libc::_exit(0) };
    }

    published_u32.store(PUBLISHED_U32, Ordering::Release);
    let deadline = Instant::now() + Duration::from_secs(5);
    while ack_u32.load(Ordering::Acquire) != ACK_U32 {
        assert!(Instant::now() < deadline, "u32 cross-process ack stalled");
        core::hint::spin_loop();
    }
    published_u64.store(PUBLISHED_U64, Ordering::Release);
    while ack_u64.load(Ordering::Acquire) != ACK_U64 {
        assert!(Instant::now() < deadline, "u64 cross-process ack stalled");
        core::hint::spin_loop();
    }

    let mut status = 0;
    loop {
        // SAFETY: this isolated parent owns the exact direct child; WNOHANG
        // cannot block and consumes only this child's status.
        let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        if waited == pid {
            break;
        }
        assert_eq!(waited, 0);
        assert!(Instant::now() < deadline, "atomic child did not exit");
        std::thread::yield_now();
    }
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 0);
    assert!(direct_child_is_absent(pid));
    // SAFETY: the exact child status was consumed above.
    assert_eq!(
        unsafe { libc::waitpid(pid, core::ptr::null_mut(), libc::WNOHANG) },
        -1
    );
    assert_eq!(
        io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
    drop(mapping);
    assert_eq!(open_fd_count(), before_fds);
    assert_eq!(open_map_count(), before_maps);
}

#[test]
fn linux_atomic_capabilities_match_native_publication() {
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "backend::linux_vnext::tests::isolated_linux_atomic_capabilities_match_native_publication",
            "--ignored",
            "--nocapture",
        ])
        .spawn()
        .unwrap();
    let pid = child.id() as libc::pid_t;
    let pidfd = open_pidfd(child.id());
    let watchdog = Instant::now() + Duration::from_secs(10);
    let mut event = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        // SAFETY: the sole pidfd poll entry remains live for this bounded query.
        let ready = unsafe { libc::poll(&mut event, 1, 10) };
        if ready > 0 {
            break;
        }
        if ready < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            panic!(
                "atomic probe pidfd poll failed: {}",
                io::Error::last_os_error()
            );
        }
        if Instant::now() >= watchdog {
            // SAFETY: pidfd_send_signal targets only this exact isolated helper.
            let result = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    pidfd.as_raw_fd(),
                    libc::SIGKILL,
                    core::ptr::null::<libc::siginfo_t>(),
                    0,
                )
            };
            assert!(result == 0 || io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH));
            let kill_deadline = Instant::now() + Duration::from_secs(5);
            loop {
                // SAFETY: the exact pidfd remains live for this bounded poll.
                let killed = unsafe { libc::poll(&mut event, 1, 10) };
                if killed > 0 {
                    break;
                }
                if killed < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                    panic!(
                        "atomic probe kill poll failed: {}",
                        io::Error::last_os_error()
                    );
                }
                assert!(
                    Instant::now() < kill_deadline,
                    "atomic probe remained alive after exact SIGKILL"
                );
            }
            break;
        }
    }
    let status = child.wait().unwrap();
    assert!(status.success());
    // SAFETY: Child::wait consumed this exact direct-child status.
    assert_eq!(
        unsafe { libc::waitpid(pid, core::ptr::null_mut(), libc::WNOHANG) },
        -1
    );
    assert_eq!(
        io::Error::last_os_error().raw_os_error(),
        Some(libc::ECHILD)
    );
}

#[test]
fn linux_atomic_capability_discovery_fails_closed() {
    assert_eq!(
        atomic_capabilities_from_native_facts(-1, 64),
        Err(NegotiationError::AtomicUnsupported)
    );
    assert_eq!(
        atomic_capabilities_from_native_facts(4096, 0),
        Err(NegotiationError::AtomicUnsupported)
    );
    assert_eq!(
        atomic_capabilities_from_native_facts(4097, 64),
        Err(NegotiationError::AtomicUnsupported)
    );
    assert_eq!(
        atomic_capabilities_from_native_facts(4096, 1),
        Err(NegotiationError::AtomicUnsupported)
    );
    assert_eq!(
        atomic_capabilities_from_native_facts(i128::MAX, 64),
        Err(NegotiationError::NativeSizeNarrowing)
    );
    let unavailable = AtomicCapabilities::from_verified_native(4096, 64, false, true).unwrap();
    assert_eq!(
        unavailable.require(true, false),
        Err(NegotiationError::AtomicUnsupported)
    );
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
