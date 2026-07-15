//! Fixed broker start/death gate entrypoint.
//!
//! This module consumes only the fixed process ABI installed by the atomic
//! broker spawner. Crossing the gate does not authorize a launcher, target,
//! path, PID, signal, task port, or filesystem operation. A future broker
//! control channel must bind a separately staged canonical launch plan to the
//! exact service child and watchdog session before this gate is released.

use std::ffi::{OsStr, c_int, c_void};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::UnixStream;
use std::time::Instant;

use super::SupervisorWireError;
use super::auth_adapter::broker_plan::{
    AcknowledgedBrokerLaunchPlan, BROKER_ACK_BYTES, BROKER_PLAN_PREFIX_BYTES,
    ExactParentBrokerLaunchPlan, MAX_BROKER_PLAN_BYTES, ReceivedBrokerLaunchPlan, broker_plan_ack,
    parse_broker_plan_prefix,
};
use super::auth_adapter::broker_spawn::{
    BROKER_CONTROL_FD, BROKER_GATE_FD, INSTALLED_BROKER_MODE, INSTALLED_BROKER_PATH,
    INSTALLED_CONTROL_ARGUMENT, INSTALLED_GATE_ARGUMENT, START_BYTE,
};

const F_GETFD: c_int = 1;
const F_SETFD: c_int = 2;
const F_GETFL: c_int = 3;
const F_SETFL: c_int = 4;
const FD_CLOEXEC: c_int = 1;
const O_ACCMODE: c_int = 3;
const O_RDONLY: c_int = 0;
const O_RDWR: c_int = 2;
const O_NONBLOCK: c_int = 0x0000_0004;
const EAGAIN: c_int = 35;
const EINTR: c_int = 4;
const POLLIN: i16 = 0x0001;
const POLLOUT: i16 = 0x0004;
const POLLERR: i16 = 0x0008;
const POLLHUP: i16 = 0x0010;
const POLLNVAL: i16 = 0x0020;
const SOL_SOCKET: c_int = 0xffff;
const SO_TYPE: c_int = 0x1008;
const SOCK_STREAM: c_int = 1;

#[repr(C)]
struct PollFd {
    fd: c_int,
    events: i16,
    revents: i16,
}

unsafe extern "C" {
    fn _exit(status: c_int) -> !;
    fn fcntl(fd: c_int, command: c_int, ...) -> c_int;
    fn getsockopt(
        fd: c_int,
        level: c_int,
        option: c_int,
        value: *mut c_void,
        length: *mut u32,
    ) -> c_int;
    fn poll(descriptors: *mut PollFd, count: u32, timeout_ms: c_int) -> c_int;
    fn read(fd: c_int, buffer: *mut u8, count: usize) -> isize;
}

/// Failure before or while consuming the fixed broker gate protocol.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum BrokerEntryError {
    /// The process vector was not the one fixed by the installed spawner.
    InvalidArguments,
    /// Descriptor 3 was absent, not read-only, or not a FIFO reader.
    ///
    /// Public Darwin descriptor metadata does not distinguish an anonymous
    /// pipe from a named FIFO. Gate shape is defensive validation, never
    /// service or session authentication. Only exact direct-child ownership
    /// plus a future authenticated control-plan binding supplies provenance.
    InvalidGate,
    /// Descriptor 4 was absent or was not a bidirectional Unix stream socket.
    InvalidControl,
    /// A descriptor operation failed with this Darwin error number.
    Descriptor(c_int),
    /// A blocking gate read failed with this Darwin error number.
    Read(c_int),
    /// The gate carried a wrong, repeated, or otherwise noncanonical byte.
    InvalidActivation,
    /// The framed broker plan was malformed, expired, or noncanonical.
    Plan(SupervisorWireError),
    /// The fixed control stream failed with this Darwin error number.
    Control(c_int),
}

/// Clean gate termination caused by loss of the sole service writer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum BrokerGateExit {
    /// The service disappeared before releasing the registered broker.
    ServiceGoneBeforeActivation,
    /// The service disappeared after releasing the registered broker.
    ServiceGone,
}

/// Linear owner of the broker gate before watchdog registration releases it.
#[must_use = "a dormant broker gate must be consumed or closed"]
#[derive(Debug)]
pub(super) struct DormantBrokerGate {
    reader: OwnedFd,
}

/// Exact fixed process channels before the canonical plan has been ACKed.
pub(super) struct DormantBrokerProcess {
    gate: DormantBrokerGate,
    control: UnixStream,
}

/// ACKed plan retained inseparably with the still-dormant gate.
pub(super) struct StagedDormantBroker {
    gate: DormantBrokerGate,
    plan: AcknowledgedBrokerLaunchPlan,
}

/// Exact plan authority minted only by the later sole FD3 START observation.
pub(super) struct ActiveBrokerProcess {
    pub(super) gate: ActiveBrokerGate,
    pub(super) plan: ExactParentBrokerLaunchPlan,
}

/// Linear service-death capability retained after one exact activation.
#[must_use = "an active broker must retain and monitor service death"]
#[derive(Debug)]
pub(super) struct ActiveBrokerGate {
    reader: OwnedFd,
}

impl DormantBrokerGate {
    /// Adopts the fixed installed broker process ABI.
    ///
    /// # Safety
    ///
    /// This must run on the dedicated broker's main thread before threads,
    /// children, launch policy, or any effect-bearing endpoint are initialized.
    /// Descriptor 3 must have no other Rust owner. A fixture may perform only
    /// read-only dispatch over its process vector before calling; the signed
    /// artifact must enter directly without effect-bearing preprocessing.
    pub(super) unsafe fn adopt_fixed_process() -> Result<DormantBrokerProcess, BrokerEntryError> {
        validate_fixed_arguments(std::env::args_os())?;
        // SAFETY: the caller promises exclusive ownership of fixed descriptors
        // 3 and 4 in this just-execed process.
        let gate = unsafe { Self::adopt_fixed_gate() }?;
        // SAFETY: the same fixed process ABI transfers sole ownership of FD4.
        let control = unsafe { adopt_fixed_control() }?;
        Ok(DormantBrokerProcess { gate, control })
    }

    /// Waits for the sole exact activation byte or service-death EOF.
    pub(super) fn wait_for_activation(
        self,
    ) -> Result<Result<ActiveBrokerGate, BrokerGateExit>, BrokerEntryError> {
        let mut activation = 0_u8;
        match read_retry(self.reader.as_raw_fd(), &mut activation)? {
            0 => return Ok(Err(BrokerGateExit::ServiceGoneBeforeActivation)),
            1 if activation == START_BYTE[0] => {}
            1 => return Err(BrokerEntryError::InvalidActivation),
            _ => unreachable!("one-byte read returned an impossible length"),
        }

        set_nonblocking(self.reader.as_raw_fd(), true)?;
        let mut extra = 0_u8;
        let probe = read_once(self.reader.as_raw_fd(), &mut extra);
        match probe {
            Ok(0) => Ok(Err(BrokerGateExit::ServiceGone)),
            Ok(1) => Err(BrokerEntryError::InvalidActivation),
            Ok(_) => unreachable!("one-byte read returned an impossible length"),
            Err(error) if error == EAGAIN => {
                set_nonblocking(self.reader.as_raw_fd(), false)?;
                Ok(Ok(ActiveBrokerGate {
                    reader: self.reader,
                }))
            }
            Err(error) if error == EINTR => {
                set_nonblocking(self.reader.as_raw_fd(), false)?;
                let active = ActiveBrokerGate {
                    reader: self.reader,
                };
                active.reject_extra_or_confirm_live()
            }
            Err(error) => Err(BrokerEntryError::Read(error)),
        }
    }

    unsafe fn adopt_fixed_gate() -> Result<Self, BrokerEntryError> {
        // Validate before creating OwnedFd: FromRawFd requires a live fd.
        // SAFETY: F_GETFD is a read-only descriptor query.
        if unsafe { fcntl(BROKER_GATE_FD, F_GETFD) } < 0 {
            return Err(BrokerEntryError::InvalidGate);
        }
        // SAFETY: the entrypoint contract transfers sole ownership here.
        let reader = unsafe { OwnedFd::from_raw_fd(BROKER_GATE_FD) };
        // SAFETY: F_GETFL is a read-only query on the now-owned descriptor.
        let flags = unsafe { fcntl(reader.as_raw_fd(), F_GETFL) };
        if flags < 0 {
            return Err(BrokerEntryError::Descriptor(last_errno()));
        }
        if flags & O_ACCMODE != O_RDONLY {
            return Err(BrokerEntryError::InvalidGate);
        }

        let file = File::from(reader);
        let metadata = file
            .metadata()
            .map_err(|error| BrokerEntryError::Descriptor(error.raw_os_error().unwrap_or(0)))?;
        if !metadata.file_type().is_fifo() {
            return Err(BrokerEntryError::InvalidGate);
        }
        // SAFETY: File::into_raw_fd transfers the still-live descriptor, which
        // is immediately re-adopted by exactly one OwnedFd.
        let reader = unsafe { OwnedFd::from_raw_fd(file.into_raw_fd()) };
        // SAFETY: the descriptor is live and F_SETFD accepts FD_CLOEXEC.
        if unsafe { fcntl(reader.as_raw_fd(), F_SETFD, FD_CLOEXEC) } != 0 {
            return Err(BrokerEntryError::Descriptor(last_errno()));
        }
        set_nonblocking(reader.as_raw_fd(), false)?;
        Ok(Self { reader })
    }
}

impl DormantBrokerProcess {
    #[cfg(test)]
    pub(in crate::backend::macos::supervisor) unsafe fn adopt_test_channels()
    -> Result<Self, BrokerEntryError> {
        // The isolated pre-main test child exercises the production spawn file
        // actions. Gate shape validation is covered separately.
        // SAFETY: F_GETFD is a read-only liveness query.
        if unsafe { fcntl(BROKER_GATE_FD, F_GETFD) } < 0 {
            return Err(BrokerEntryError::InvalidGate);
        }
        // SAFETY: the test spawn transfers sole ownership of live FD3.
        let reader = unsafe { OwnedFd::from_raw_fd(BROKER_GATE_FD) };
        set_nonblocking(reader.as_raw_fd(), false)?;
        let gate = DormantBrokerGate { reader };
        // SAFETY: the same child installs a private Unix stream at FD4.
        if unsafe { fcntl(BROKER_CONTROL_FD, F_GETFD) } < 0 {
            return Err(BrokerEntryError::InvalidControl);
        }
        // SAFETY: the test spawn transfers sole ownership of live FD4.
        let control = UnixStream::from(unsafe { OwnedFd::from_raw_fd(BROKER_CONTROL_FD) });
        control
            .set_nonblocking(true)
            .map_err(|error| BrokerEntryError::Descriptor(error.raw_os_error().unwrap_or(0)))?;
        Ok(Self { gate, control })
    }

    /// Receives exactly one bounded frame while FD3 remains dormant, validates
    /// its original deadline as soon as the fixed prefix arrives, then writes
    /// the complete-frame ACK before making START admissible.
    pub(super) fn stage_plan(
        mut self,
    ) -> Result<Result<StagedDormantBroker, BrokerGateExit>, BrokerEntryError> {
        set_nonblocking(self.gate.reader.as_raw_fd(), true)?;
        let mut outer = [0_u8; 4];
        if let Some(exit) = read_control_while_dormant(
            &mut self.control,
            self.gate.reader.as_raw_fd(),
            &mut outer,
            None,
        )? {
            return Ok(Err(exit));
        }
        let frame_len = usize::try_from(u32::from_le_bytes(outer))
            .map_err(|_| BrokerEntryError::Plan(SupervisorWireError::LimitExceeded))?;
        if !(256..=MAX_BROKER_PLAN_BYTES).contains(&frame_len) {
            return Err(BrokerEntryError::Plan(SupervisorWireError::LimitExceeded));
        }
        let mut frame = vec![0_u8; frame_len];
        let (prefix, remaining) = frame.split_at_mut(BROKER_PLAN_PREFIX_BYTES);
        if let Some(exit) = read_control_while_dormant(
            &mut self.control,
            self.gate.reader.as_raw_fd(),
            prefix,
            None,
        )? {
            return Ok(Err(exit));
        }
        let prefix: &[u8; BROKER_PLAN_PREFIX_BYTES] = (&*prefix)
            .try_into()
            .map_err(|_| BrokerEntryError::Plan(SupervisorWireError::Malformed))?;
        let parsed = parse_broker_plan_prefix(prefix, frame_len).map_err(BrokerEntryError::Plan)?;
        if parsed.frame_len != frame_len {
            return Err(BrokerEntryError::Plan(SupervisorWireError::Malformed));
        }
        if let Some(exit) = read_control_while_dormant(
            &mut self.control,
            self.gate.reader.as_raw_fd(),
            remaining,
            Some(parsed.deadline.local()),
        )? {
            return Ok(Err(exit));
        }
        if let Some(exit) = require_control_frame_eof(
            &mut self.control,
            self.gate.reader.as_raw_fd(),
            parsed.deadline.local(),
        )? {
            return Ok(Err(exit));
        }
        let received = ReceivedBrokerLaunchPlan::decode_with_deadline(&frame, parsed.deadline)
            .map_err(BrokerEntryError::Plan)?;
        ensure_deadline_live(Some(received.deadline().local()))?;
        let ack = broker_plan_ack(&frame);
        debug_assert_eq!(ack.len(), BROKER_ACK_BYTES);
        if let Some(exit) = write_control_while_dormant(
            &mut self.control,
            self.gate.reader.as_raw_fd(),
            &ack,
            received.deadline().local(),
        )? {
            return Ok(Err(exit));
        }
        ensure_deadline_live(Some(received.deadline().local()))?;
        // SAFETY: FD4 was adopted from the fixed process ABI, the exact frame
        // decoded above, and its complete digest ACK was just written while
        // FD3 remained byte-free and live.
        let plan = unsafe { received.acknowledge_exact_parent() };
        drop(self.control);
        Ok(Ok(StagedDormantBroker {
            gate: self.gate,
            plan,
        }))
    }
}

impl StagedDormantBroker {
    pub(super) fn wait_for_activation(
        self,
    ) -> Result<Result<ActiveBrokerProcess, BrokerGateExit>, BrokerEntryError> {
        let deadline = self.plan.deadline().local();
        match self.gate.wait_for_activation_until(deadline)? {
            Err(exit) => Ok(Err(exit)),
            Ok(gate) => {
                ensure_deadline_live(Some(deadline))?;
                // SAFETY: wait_for_activation consumed the sole exact START
                // byte after this plan's ACK and rejected any extra byte.
                let plan = unsafe { self.plan.activate() };
                Ok(Ok(ActiveBrokerProcess { gate, plan }))
            }
        }
    }
}

impl DormantBrokerGate {
    fn wait_for_activation_until(
        self,
        deadline: Instant,
    ) -> Result<Result<ActiveBrokerGate, BrokerGateExit>, BrokerEntryError> {
        set_nonblocking(self.reader.as_raw_fd(), true)?;
        loop {
            let mut activation = 0_u8;
            match read_once(self.reader.as_raw_fd(), &mut activation) {
                Ok(0) => return Ok(Err(BrokerGateExit::ServiceGoneBeforeActivation)),
                Ok(1) if activation == START_BYTE[0] => break,
                Ok(1) => return Err(BrokerEntryError::InvalidActivation),
                Ok(_) => unreachable!("one-byte read returned impossible length"),
                Err(error) if error == EINTR => continue,
                Err(error) if error == EAGAIN => {
                    poll_gate_until(self.reader.as_raw_fd(), deadline)?
                }
                Err(error) => return Err(BrokerEntryError::Read(error)),
            }
        }
        let mut extra = 0_u8;
        loop {
            match read_once(self.reader.as_raw_fd(), &mut extra) {
                Ok(0) => return Ok(Err(BrokerGateExit::ServiceGone)),
                Ok(1) => return Err(BrokerEntryError::InvalidActivation),
                Ok(_) => unreachable!("one-byte read returned impossible length"),
                Err(error) if error == EINTR => continue,
                Err(error) if error == EAGAIN => {
                    set_nonblocking(self.reader.as_raw_fd(), false)?;
                    ensure_deadline_live(Some(deadline))?;
                    return Ok(Ok(ActiveBrokerGate {
                        reader: self.reader,
                    }));
                }
                Err(error) => return Err(BrokerEntryError::Read(error)),
            }
        }
    }
}

fn poll_gate_until(fd: c_int, deadline: Instant) -> Result<(), BrokerEntryError> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(BrokerEntryError::Plan(SupervisorWireError::LimitExceeded))?;
        let mut descriptor = PollFd {
            fd,
            events: POLLIN,
            revents: 0,
        };
        let timeout = c_int::try_from(remaining.as_millis()).unwrap_or(c_int::MAX);
        // SAFETY: descriptor is one initialized writable pollfd.
        let result = unsafe { poll(&raw mut descriptor, 1, timeout) };
        if result > 0 {
            return Ok(());
        }
        if result == 0 {
            ensure_deadline_live(Some(deadline))?;
            continue;
        }
        let error = last_errno();
        if error != EINTR {
            return Err(BrokerEntryError::Read(error));
        }
    }
}

unsafe fn adopt_fixed_control() -> Result<UnixStream, BrokerEntryError> {
    // SAFETY: read-only liveness query before ownership construction.
    if unsafe { fcntl(BROKER_CONTROL_FD, F_GETFD) } < 0 {
        return Err(BrokerEntryError::InvalidControl);
    }
    // SAFETY: F_GETFL is a read-only query on the still-unowned live FD4.
    let flags = unsafe { fcntl(BROKER_CONTROL_FD, F_GETFL) };
    let mut socket_type: c_int = 0;
    let mut socket_type_len = u32::try_from(std::mem::size_of::<c_int>())
        .map_err(|_| BrokerEntryError::InvalidControl)?;
    // SAFETY: socket_type and its length are writable scalar output storage.
    if flags < 0
        || flags & O_ACCMODE != O_RDWR
        || unsafe {
            getsockopt(
                BROKER_CONTROL_FD,
                SOL_SOCKET,
                SO_TYPE,
                (&raw mut socket_type).cast(),
                &raw mut socket_type_len,
            )
        } != 0
        || socket_type_len as usize != std::mem::size_of::<c_int>()
        || socket_type != SOCK_STREAM
    {
        return Err(BrokerEntryError::InvalidControl);
    }
    // SAFETY: the fixed entry contract transfers sole ownership of live FD4.
    let owned = unsafe { OwnedFd::from_raw_fd(BROKER_CONTROL_FD) };
    let file = File::from(owned);
    let metadata = file
        .metadata()
        .map_err(|error| BrokerEntryError::Descriptor(error.raw_os_error().unwrap_or(0)))?;
    if !metadata.file_type().is_socket() {
        return Err(BrokerEntryError::InvalidControl);
    }
    // SAFETY: transfer the still-live descriptor directly into UnixStream.
    let owned = unsafe { OwnedFd::from_raw_fd(file.into_raw_fd()) };
    // SAFETY: live descriptor accepts the close-on-exec flag.
    if unsafe { fcntl(owned.as_raw_fd(), F_SETFD, FD_CLOEXEC) } != 0 {
        return Err(BrokerEntryError::Descriptor(last_errno()));
    }
    let stream = UnixStream::from(owned);
    stream
        .set_nonblocking(true)
        .map_err(|error| BrokerEntryError::Descriptor(error.raw_os_error().unwrap_or(0)))?;
    Ok(stream)
}

fn read_control_while_dormant(
    control: &mut UnixStream,
    gate_fd: c_int,
    mut bytes: &mut [u8],
    deadline: Option<Instant>,
) -> Result<Option<BrokerGateExit>, BrokerEntryError> {
    while !bytes.is_empty() {
        if let Some(exit) = probe_dormant_gate(gate_fd)? {
            return Ok(Some(exit));
        }
        ensure_deadline_live(deadline)?;
        match control.read(bytes) {
            Ok(0) => return Err(BrokerEntryError::Control(0)),
            Ok(count) => bytes = &mut bytes[count..],
            Err(ref error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if let Some(exit) =
                    poll_control_and_gate(gate_fd, control.as_raw_fd(), POLLIN, deadline)?
                {
                    return Ok(Some(exit));
                }
            }
            Err(error) => {
                return Err(BrokerEntryError::Control(error.raw_os_error().unwrap_or(0)));
            }
        }
    }
    Ok(None)
}

fn write_control_while_dormant(
    control: &mut UnixStream,
    gate_fd: c_int,
    mut bytes: &[u8],
    deadline: Instant,
) -> Result<Option<BrokerGateExit>, BrokerEntryError> {
    while !bytes.is_empty() {
        if let Some(exit) = probe_dormant_gate(gate_fd)? {
            return Ok(Some(exit));
        }
        ensure_deadline_live(Some(deadline))?;
        match control.write(bytes) {
            Ok(0) => return Err(BrokerEntryError::Control(0)),
            Ok(count) => bytes = &bytes[count..],
            Err(ref error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if let Some(exit) =
                    poll_control_and_gate(gate_fd, control.as_raw_fd(), POLLOUT, Some(deadline))?
                {
                    return Ok(Some(exit));
                }
            }
            Err(error) => {
                return Err(BrokerEntryError::Control(error.raw_os_error().unwrap_or(0)));
            }
        }
    }
    Ok(None)
}

fn require_control_frame_eof(
    control: &mut UnixStream,
    gate_fd: c_int,
    deadline: Instant,
) -> Result<Option<BrokerGateExit>, BrokerEntryError> {
    let mut extra = [0_u8; 1];
    loop {
        if let Some(exit) = probe_dormant_gate(gate_fd)? {
            return Ok(Some(exit));
        }
        ensure_deadline_live(Some(deadline))?;
        match control.read(&mut extra) {
            Ok(0) => return Ok(None),
            Ok(1) => return Err(BrokerEntryError::Plan(SupervisorWireError::Malformed)),
            Ok(_) => unreachable!("one-byte read returned impossible length"),
            Err(ref error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if let Some(exit) =
                    poll_control_and_gate(gate_fd, control.as_raw_fd(), POLLIN, Some(deadline))?
                {
                    return Ok(Some(exit));
                }
            }
            Err(error) => {
                return Err(BrokerEntryError::Control(error.raw_os_error().unwrap_or(0)));
            }
        }
    }
}

fn probe_dormant_gate(gate_fd: c_int) -> Result<Option<BrokerGateExit>, BrokerEntryError> {
    let mut byte = 0_u8;
    loop {
        return match read_once(gate_fd, &mut byte) {
            Ok(0) => Ok(Some(BrokerGateExit::ServiceGoneBeforeActivation)),
            Ok(1) => Err(BrokerEntryError::InvalidActivation),
            Ok(_) => unreachable!("one-byte read returned impossible length"),
            Err(error) if error == EINTR => continue,
            Err(error) if error == EAGAIN => Ok(None),
            Err(error) => Err(BrokerEntryError::Read(error)),
        };
    }
}

fn ensure_deadline_live(deadline: Option<Instant>) -> Result<(), BrokerEntryError> {
    if deadline.is_some_and(|value| Instant::now() >= value) {
        Err(BrokerEntryError::Plan(SupervisorWireError::LimitExceeded))
    } else {
        Ok(())
    }
}

fn poll_control_and_gate(
    gate_fd: c_int,
    control_fd: c_int,
    control_events: i16,
    deadline: Option<Instant>,
) -> Result<Option<BrokerGateExit>, BrokerEntryError> {
    loop {
        let timeout = match deadline {
            Some(deadline) => {
                let remaining = deadline
                    .checked_duration_since(Instant::now())
                    .ok_or(BrokerEntryError::Plan(SupervisorWireError::LimitExceeded))?;
                c_int::try_from(remaining.as_millis()).unwrap_or(c_int::MAX)
            }
            None => -1,
        };
        let mut descriptors = [
            PollFd {
                fd: gate_fd,
                events: POLLIN,
                revents: 0,
            },
            PollFd {
                fd: control_fd,
                events: control_events,
                revents: 0,
            },
        ];
        // SAFETY: descriptors contains two initialized writable pollfd values.
        let result = unsafe { poll(descriptors.as_mut_ptr(), 2, timeout) };
        if result == 0 {
            if deadline.is_some_and(|value| Instant::now() >= value) {
                return Err(BrokerEntryError::Plan(SupervisorWireError::LimitExceeded));
            }
            continue;
        }
        if result < 0 {
            let error = last_errno();
            if error == EINTR {
                continue;
            }
            return Err(BrokerEntryError::Control(error));
        }
        if descriptors[0].revents != 0 {
            let mut byte = 0_u8;
            return match read_once(gate_fd, &mut byte) {
                Ok(0) => Ok(Some(BrokerGateExit::ServiceGoneBeforeActivation)),
                Ok(1) => Err(BrokerEntryError::InvalidActivation),
                Ok(_) => unreachable!("one-byte read returned impossible length"),
                Err(error) if error == EAGAIN || error == EINTR => continue,
                Err(error) => Err(BrokerEntryError::Read(error)),
            };
        }
        if descriptors[1].revents & control_events != 0 {
            return Ok(None);
        }
        if descriptors[1].revents & (POLLERR | POLLHUP | POLLNVAL) != 0 {
            return Err(BrokerEntryError::Control(0));
        }
    }
}

impl ActiveBrokerGate {
    /// Blocks until service-death EOF. Any further byte is a protocol failure.
    pub(super) fn wait_for_service_death(self) -> Result<BrokerGateExit, BrokerEntryError> {
        let mut unexpected = 0_u8;
        match read_retry(self.reader.as_raw_fd(), &mut unexpected)? {
            0 => Ok(BrokerGateExit::ServiceGone),
            1 => Err(BrokerEntryError::InvalidActivation),
            _ => unreachable!("one-byte read returned an impossible length"),
        }
    }

    fn reject_extra_or_confirm_live(
        self,
    ) -> Result<Result<Self, BrokerGateExit>, BrokerEntryError> {
        set_nonblocking(self.reader.as_raw_fd(), true)?;
        let mut extra = 0_u8;
        loop {
            match read_once(self.reader.as_raw_fd(), &mut extra) {
                Ok(0) => return Ok(Err(BrokerGateExit::ServiceGone)),
                Ok(1) => return Err(BrokerEntryError::InvalidActivation),
                Ok(_) => unreachable!("one-byte read returned an impossible length"),
                Err(error) if error == EINTR => continue,
                Err(error) if error == EAGAIN => {
                    set_nonblocking(self.reader.as_raw_fd(), false)?;
                    return Ok(Ok(self));
                }
                Err(error) => return Err(BrokerEntryError::Read(error)),
            }
        }
    }

    #[cfg(test)]
    fn descriptor(&self) -> c_int {
        self.reader.as_raw_fd()
    }
}

/// Runs the no-callback fixed broker-entry process used by the executable fixture.
///
/// This receives and acknowledges the authority-free staged launch plan but
/// performs no launch effect. Only the active arm may later consume the plan;
/// gate shape, frame bytes, ACK, and START alone remain non-authoritative.
///
/// # Safety
///
/// This must run in a just-execed dedicated broker before threads, children,
/// policy, or effect-bearing endpoints. Its exact process vector and
/// descriptors 3 and 4 must come from the fixed spawner, and no Rust value may
/// already own either descriptor.
pub(in crate::backend::macos) unsafe fn run_fixed_gate_process() -> ! {
    // SAFETY: the caller promises the complete process-entry contract.
    let adopted = unsafe { DormantBrokerGate::adopt_fixed_process() };
    let status = match adopted {
        Err(_) => 64,
        Ok(dormant) => match dormant.stage_plan() {
            Ok(Err(BrokerGateExit::ServiceGoneBeforeActivation | BrokerGateExit::ServiceGone)) => 0,
            Err(_) => 65,
            Ok(Ok(staged)) => match staged.wait_for_activation() {
                Ok(Err(
                    BrokerGateExit::ServiceGoneBeforeActivation | BrokerGateExit::ServiceGone,
                )) => 0,
                Err(_) => 65,
                Ok(Ok(active)) => {
                    let _plan = active.plan;
                    match active.gate.wait_for_service_death() {
                        Ok(BrokerGateExit::ServiceGone) => 0,
                        Ok(BrokerGateExit::ServiceGoneBeforeActivation) => 66,
                        Err(_) => 65,
                    }
                }
            },
        },
    };
    // SAFETY: the entry process has no authority-bearing cleanup beyond
    // descriptor close, which the kernel performs at exit. Avoid arbitrary
    // process-global exit callbacks after the terminal gate decision.
    unsafe { _exit(status) }
}

fn validate_fixed_arguments(
    arguments: impl IntoIterator<Item = impl AsRef<OsStr>>,
) -> Result<(), BrokerEntryError> {
    let mut arguments = arguments.into_iter();
    let expected = [
        INSTALLED_BROKER_PATH.as_bytes(),
        INSTALLED_BROKER_MODE.as_bytes(),
        INSTALLED_GATE_ARGUMENT.as_bytes(),
        INSTALLED_CONTROL_ARGUMENT.as_bytes(),
    ];
    for expected in expected {
        let Some(argument) = arguments.next() else {
            return Err(BrokerEntryError::InvalidArguments);
        };
        if argument.as_ref().as_bytes() != expected {
            return Err(BrokerEntryError::InvalidArguments);
        }
    }
    if arguments.next().is_some() {
        return Err(BrokerEntryError::InvalidArguments);
    }
    Ok(())
}

fn read_retry(fd: c_int, byte: &mut u8) -> Result<isize, BrokerEntryError> {
    loop {
        match read_once(fd, byte) {
            Err(error) if error == EINTR => continue,
            Err(error) => return Err(BrokerEntryError::Read(error)),
            Ok(count) => return Ok(count),
        }
    }
}

fn read_once(fd: c_int, byte: &mut u8) -> Result<isize, c_int> {
    // SAFETY: fd is the live gate reader and byte is writable for one byte.
    let count = unsafe { read(fd, byte, 1) };
    if count < 0 {
        Err(last_errno())
    } else {
        Ok(count)
    }
}

fn set_nonblocking(fd: c_int, enabled: bool) -> Result<(), BrokerEntryError> {
    // SAFETY: fd is live and F_GETFL is a read-only descriptor query.
    let flags = unsafe { fcntl(fd, F_GETFL) };
    if flags < 0 {
        return Err(BrokerEntryError::Descriptor(last_errno()));
    }
    let desired = if enabled {
        flags | O_NONBLOCK
    } else {
        flags & !O_NONBLOCK
    };
    // SAFETY: fd is live and desired preserves all unrelated status flags.
    if unsafe { fcntl(fd, F_SETFL, desired) } != 0 {
        return Err(BrokerEntryError::Descriptor(last_errno()));
    }
    Ok(())
}

fn last_errno() -> c_int {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

#[cfg(test)]
#[path = "supervisor_broker_entry_test.rs"]
mod tests;
