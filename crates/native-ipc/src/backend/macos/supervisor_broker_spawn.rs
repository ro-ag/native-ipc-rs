//! Fixed-image broker spawn and exact direct-child lifecycle authority.

use std::ffi::{CStr, CString, c_char, c_int};
use std::io::{Read, Write};
use std::marker::PhantomData;
use std::net::Shutdown;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;
use std::rc::Rc;
use std::time::Instant;

use super::super::super::supervisor_watchdog::{
    AtomicallySpawnedBroker, ExactBroker, ExactBrokerAuthority, FreshSessionId, ReapedBroker,
    TerminationReason,
};
use super::super::ValidatedSpawn;
#[cfg(test)]
use super::SessionAssignedSpawn;
use super::broker_plan::trace_report_binding_from_frame;
use super::broker_plan::{BROKER_ACK_BYTES, StagedBrokerSpawn, broker_plan_ack};
use super::broker_report::BrokerTraceReportReceiver;
use super::{DedicatedChildWaitDomain, PendingSpawnReply};
use crate::backend::macos::supervisor::deployer_helper_path;
use crate::backend::macos::supervisor::spawn_primitives::{
    SpawnAttributes, SpawnFileActions, spawn,
};

pub(super) type FixedImageAtomicBroker =
    AtomicallySpawnedBroker<ValidatedSpawn, DirectChildBrokerAuthority, BrokerTraceReportReceiver>;
pub(super) type PendingFixedImageBroker = PendingSpawnReply<FixedImageAtomicBroker>;
type FixedImageSpawnResult =
    Result<PendingFixedImageBroker, Box<PendingSpawnReply<BrokerSpawnError>>>;

pub(in crate::backend::macos::supervisor) const INSTALLED_BROKER_MODE: &str = "--supervisor-broker";
pub(in crate::backend::macos::supervisor) const INSTALLED_GATE_ARGUMENT: &str = "--gate-fd=3";
pub(in crate::backend::macos::supervisor) const INSTALLED_CONTROL_ARGUMENT: &str = "--control-fd=4";
pub(in crate::backend::macos::supervisor) const INSTALLED_TRACE_ARGUMENT: &str = "--trace-fd=5";
const CANONICAL_PATH: &str = "PATH=/usr/bin:/bin";
const CANONICAL_LANG: &str = "LANG=C";
const CANONICAL_LOCALE: &str = "LC_ALL=C";

pub(in crate::backend::macos::supervisor) const BROKER_GATE_FD: c_int = 3;
pub(in crate::backend::macos::supervisor) const BROKER_CONTROL_FD: c_int = 4;
pub(in crate::backend::macos::supervisor) const BROKER_TRACE_FD: c_int = 5;
const STABLE_FD_MINIMUM: c_int = 10;
pub(in crate::backend::macos::supervisor) const START_BYTE: [u8; 1] = [1];

const F_GETFL: c_int = 3;
const F_SETFL: c_int = 4;
const F_SETFD: c_int = 2;
const F_DUPFD_CLOEXEC: c_int = 67;
const F_SETNOSIGPIPE: c_int = 73;
const FD_CLOEXEC: c_int = 1;
const O_NONBLOCK: c_int = 0x0000_0004;

const ECHILD: c_int = 10;
const EINTR: c_int = 4;
const ESRCH: c_int = 3;
const SIGKILL: c_int = 9;
const SIGSTOP: c_int = 17;
const WNOHANG: c_int = 1;
const EAGAIN: c_int = 35;
const POLLIN: i16 = 0x0001;
const POLLOUT: i16 = 0x0004;
const POLLERR: i16 = 0x0008;
const POLLHUP: i16 = 0x0010;
const POLLNVAL: i16 = 0x0020;

#[repr(C)]
struct PollFd {
    fd: c_int,
    events: i16,
    revents: i16,
}

unsafe extern "C" {
    fn fcntl(fd: c_int, command: c_int, ...) -> c_int;
    fn kill(pid: c_int, signal: c_int) -> c_int;
    fn pipe(descriptors: *mut c_int) -> c_int;
    fn poll(descriptors: *mut PollFd, count: u32, timeout_ms: c_int) -> c_int;
    fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int;
    fn write(fd: c_int, buffer: *const u8, count: usize) -> isize;
}

/// Preparation or exact-spawn failure before child authority is minted.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::backend::macos) enum BrokerSpawnError {
    InvalidFixedImage,
    Pipe(c_int),
    Descriptor(c_int),
    FileActions(c_int),
    Attributes(c_int),
    Spawn(c_int),
    Wait(c_int),
    Signal(c_int),
    Activation(c_int),
    Control(c_int),
    ControlProtocol,
    DeadlineExpired,
    InvalidTransition,
    InvalidWaitDomain,
}

/// Installation-only fixed broker image and its canonical process vectors.
///
/// This value contains no request-selected path, PID, signal, filesystem
/// operation, requirement, or descriptor. The same-user runtime must verify
/// the deployer-supplied replacement-resistant signed image before constructing it.
pub(in crate::backend::macos::supervisor) struct InstalledBrokerImage {
    path: CString,
    mode: CString,
    gate_argument: CString,
    control_argument: CString,
    trace_argument: CString,
    environment_path: CString,
    environment_lang: CString,
    environment_locale: CString,
}

impl InstalledBrokerImage {
    /// # Safety
    ///
    /// `path` must be an absolute compile-time constant supplied by the
    /// deployer's helper artifact, not request data. The caller must have
    /// verified that exact path as its replacement-resistant signed broker.
    /// This source boundary does not itself claim installation, signing, or
    /// packaging evidence.
    pub(in crate::backend::macos::supervisor) unsafe fn from_verified_installation(
        path: &CStr,
    ) -> Result<Self, BrokerSpawnError> {
        Ok(Self {
            path: deployer_helper_path(path).ok_or(BrokerSpawnError::InvalidFixedImage)?,
            mode: fixed_cstring(INSTALLED_BROKER_MODE)?,
            gate_argument: fixed_cstring(INSTALLED_GATE_ARGUMENT)?,
            control_argument: fixed_cstring(INSTALLED_CONTROL_ARGUMENT)?,
            trace_argument: fixed_cstring(INSTALLED_TRACE_ARGUMENT)?,
            environment_path: fixed_cstring(CANONICAL_PATH)?,
            environment_lang: fixed_cstring(CANONICAL_LANG)?,
            environment_locale: fixed_cstring(CANONICAL_LOCALE)?,
        })
    }

    fn argv(&self) -> [*mut c_char; 6] {
        [
            self.path.as_ptr().cast_mut(),
            self.mode.as_ptr().cast_mut(),
            self.gate_argument.as_ptr().cast_mut(),
            self.control_argument.as_ptr().cast_mut(),
            self.trace_argument.as_ptr().cast_mut(),
            std::ptr::null_mut(),
        ]
    }

    fn environment(&self) -> [*mut c_char; 4] {
        [
            self.environment_path.as_ptr().cast_mut(),
            self.environment_lang.as_ptr().cast_mut(),
            self.environment_locale.as_ptr().cast_mut(),
            std::ptr::null_mut(),
        ]
    }
}

fn fixed_cstring(value: &'static str) -> Result<CString, BrokerSpawnError> {
    CString::new(value).map_err(|_| BrokerSpawnError::InvalidFixedImage)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DirectChildState {
    Dormant,
    Active,
    TerminationSent,
    Reaped,
    AuthorityLost,
}

/// Exact sole-waiter authority for one fixed-image direct broker child.
///
/// The PID is usable only while the unreaped direct-child relation pins it.
/// No audit token, start time, PID version, task port, or reconstructible
/// numeric identity can replace that relation.
pub(in crate::backend::macos) struct DirectChildBrokerAuthority {
    pid: c_int,
    gate_writer: Option<OwnedFd>,
    state: DirectChildState,
    _wait_domain: PhantomData<Rc<()>>,
}

impl DirectChildBrokerAuthority {
    fn close_gate(&mut self) {
        drop(self.gate_writer.take());
    }

    fn observe_exact_reap(
        &mut self,
        options: c_int,
    ) -> Result<Option<ReapedBroker>, BrokerSpawnError> {
        if matches!(
            self.state,
            DirectChildState::Reaped | DirectChildState::AuthorityLost
        ) {
            std::process::abort();
        }
        let mut status = 0;
        // SAFETY: this authority is the service's sole waiter for exactly pid.
        let result = unsafe { waitpid(self.pid, &raw mut status, options) };
        if result == self.pid {
            self.state = DirectChildState::Reaped;
            // SAFETY: the successful exact wait above consumed this child.
            return Ok(Some(unsafe { ReapedBroker::from_exact_reap() }));
        }
        if result == 0 {
            return Ok(None);
        }
        let error = last_error(ECHILD);
        if error == ECHILD {
            self.state = DirectChildState::AuthorityLost;
            // Never attempt a numeric fallback once the kernel relation is lost.
            std::process::abort();
        }
        Err(BrokerSpawnError::Wait(error))
    }

    fn signal_exact_child(&mut self) -> Result<(), BrokerSpawnError> {
        if matches!(
            self.state,
            DirectChildState::Reaped | DirectChildState::AuthorityLost
        ) {
            std::process::abort();
        }
        if self.state == DirectChildState::TerminationSent {
            return Ok(());
        }
        // SAFETY: an unreaped direct child or zombie pins this numeric PID.
        if unsafe { kill(self.pid, SIGKILL) } == 0 {
            self.state = DirectChildState::TerminationSent;
            return Ok(());
        }
        let error = last_error(ESRCH);
        if error == ESRCH {
            // ESRCH is not reap proof; exact waitpid must retire the authority.
            self.state = DirectChildState::TerminationSent;
            Ok(())
        } else {
            Err(BrokerSpawnError::Signal(error))
        }
    }

    fn terminate_and_wait(&mut self) -> Result<ReapedBroker, BrokerSpawnError> {
        self.close_gate();
        loop {
            match self.observe_exact_reap(WNOHANG) {
                Ok(Some(proof)) => return Ok(proof),
                Ok(None) => break,
                Err(BrokerSpawnError::Wait(EINTR)) => continue,
                Err(error) => return Err(error),
            }
        }
        self.signal_exact_child()?;
        loop {
            match self.observe_exact_reap(0) {
                Ok(Some(proof)) => return Ok(proof),
                Ok(None) => std::process::abort(),
                Err(BrokerSpawnError::Wait(EINTR)) => continue,
                Err(error) => return Err(error),
            }
        }
    }

    fn emergency_terminate_and_wait(&mut self) -> ReapedBroker {
        match self.terminate_and_wait() {
            Ok(proof) => proof,
            Err(_) => std::process::abort(),
        }
    }
}

// SAFETY: this implementation uses only the exact unreaped direct-child
// relation. ECHILD aborts at discovery, ESRCH still requires exact waitpid,
// and every termination path closes the retained start/death gate first.
unsafe impl ExactBrokerAuthority for DirectChildBrokerAuthority {
    type Failure = BrokerSpawnError;

    fn activate_after_registration(&mut self) -> Result<(), Self::Failure> {
        if self.state != DirectChildState::Dormant {
            return Err(BrokerSpawnError::InvalidTransition);
        }
        let writer = self
            .gate_writer
            .as_ref()
            .unwrap_or_else(|| std::process::abort());
        // SAFETY: the fixed one-byte buffer and live nonblocking writer are valid.
        let result = unsafe { write(writer.as_raw_fd(), START_BYTE.as_ptr(), START_BYTE.len()) };
        if result == 1 {
            self.state = DirectChildState::Active;
            Ok(())
        } else if result < 0 {
            Err(BrokerSpawnError::Activation(last_error(ECHILD)))
        } else {
            Err(BrokerSpawnError::Activation(ECHILD))
        }
    }

    fn terminate_and_reap(
        &mut self,
        _reason: TerminationReason,
    ) -> Result<ReapedBroker, Self::Failure> {
        self.terminate_and_wait()
    }

    fn emergency_terminate_and_reap(&mut self, _reason: Option<TerminationReason>) -> ReapedBroker {
        self.emergency_terminate_and_wait()
    }
}

/// Sealed provenance bundle created only by the fixed-image spawn transition.
pub(in crate::backend::macos) struct FixedImageBrokerSpawn {
    session: FreshSessionId,
    launch: ValidatedSpawn,
    broker: ExactBroker<DirectChildBrokerAuthority>,
    report: BrokerTraceReportReceiver,
}

impl FixedImageBrokerSpawn {
    pub(in crate::backend::macos) fn into_parts(
        self,
    ) -> (
        FreshSessionId,
        ValidatedSpawn,
        ExactBroker<DirectChildBrokerAuthority>,
        BrokerTraceReportReceiver,
    ) {
        (self.session, self.launch, self.broker, self.report)
    }
}

/// The sole production broker-creation transition. It accepts only a frame
/// already minted with the complete authenticated/session-assigned typestate,
/// and returns success only after the exact child ACKs those complete bytes.
pub(super) fn spawn_staged_broker(
    staged: StagedBrokerSpawn,
    image: &InstalledBrokerImage,
    wait_domain: &mut DedicatedChildWaitDomain,
) -> FixedImageSpawnResult {
    let (pending, frame) = staged.into_spawn_parts();
    let PendingSpawnReply {
        reply,
        freshness,
        bound_session,
        output,
    } = pending;
    let deadline = output.spawn.deadline();
    let expected_report = match trace_report_binding_from_frame(&frame) {
        Ok(binding) => binding,
        Err(_) => {
            return Err(Box::new(PendingSpawnReply {
                reply,
                freshness,
                bound_session,
                output: BrokerSpawnError::ControlProtocol,
            }));
        }
    };
    let (broker, control, trace) = match spawn_fixed_image_with_control(image, wait_domain) {
        Ok(spawned) => spawned,
        Err(error) => {
            return Err(Box::new(PendingSpawnReply {
                reply,
                freshness,
                bound_session,
                output: error,
            }));
        }
    };
    if let Err(error) = send_plan_and_require_ack(control, &frame, deadline) {
        drop(broker);
        return Err(Box::new(PendingSpawnReply {
            reply,
            freshness,
            bound_session,
            output: error,
        }));
    }
    let report =
        match BrokerTraceReportReceiver::new(UnixStream::from(trace), expected_report, deadline) {
            Ok(report) => report,
            Err(_) => {
                drop(broker);
                return Err(Box::new(PendingSpawnReply {
                    reply,
                    freshness,
                    bound_session,
                    output: BrokerSpawnError::ControlProtocol,
                }));
            }
        };
    let spawned = FixedImageBrokerSpawn {
        session: output.session,
        launch: output.spawn,
        broker,
        report,
    };
    Ok(PendingSpawnReply {
        reply,
        freshness,
        bound_session,
        output: AtomicallySpawnedBroker::from_fixed_image_spawn(spawned),
    })
}

fn spawn_fixed_image_with_control(
    image: &InstalledBrokerImage,
    wait_domain: &mut DedicatedChildWaitDomain,
) -> Result<(ExactBroker<DirectChildBrokerAuthority>, OwnedFd, OwnedFd), BrokerSpawnError> {
    wait_domain
        .verify_single_threaded_spawn()
        .map_err(|_| BrokerSpawnError::InvalidWaitDomain)?;
    let (parent_control, child_control) = create_control_pair()?;
    let (parent_trace, child_trace) = create_control_pair()?;
    let broker = spawn_fixed_image_internal(
        image,
        wait_domain,
        Some(&child_control),
        Some(&parent_control),
        Some(&child_trace),
        Some(&parent_trace),
    )?;
    drop(child_control);
    drop(child_trace);
    Ok((broker, parent_control, parent_trace))
}

#[cfg(test)]
fn spawn_fixed_image(
    image: &InstalledBrokerImage,
    wait_domain: &mut DedicatedChildWaitDomain,
) -> Result<ExactBroker<DirectChildBrokerAuthority>, BrokerSpawnError> {
    spawn_fixed_image_internal(image, wait_domain, None, None, None, None)
}

#[cfg(test)]
impl PendingSpawnReply<SessionAssignedSpawn> {
    fn spawn_gate_only_test(
        self,
        image: &InstalledBrokerImage,
        wait_domain: &mut DedicatedChildWaitDomain,
    ) -> Result<
        PendingSpawnReply<AtomicallySpawnedBroker<ValidatedSpawn, DirectChildBrokerAuthority>>,
        Box<PendingSpawnReply<BrokerSpawnError>>,
    > {
        let Self {
            reply,
            freshness,
            bound_session,
            output,
        } = self;
        let broker = match spawn_fixed_image(image, wait_domain) {
            Ok(broker) => broker,
            Err(error) => {
                return Err(Box::new(PendingSpawnReply {
                    reply,
                    freshness,
                    bound_session,
                    output: error,
                }));
            }
        };
        // SAFETY: this test-only gate path models the exact child created for
        // the same already session-assigned authenticated launch.
        let spawned = unsafe {
            AtomicallySpawnedBroker::from_test_atomic_spawn(output.session, output.spawn, broker)
        };
        Ok(PendingSpawnReply {
            reply,
            freshness,
            bound_session,
            output: spawned,
        })
    }
}

fn spawn_fixed_image_internal(
    image: &InstalledBrokerImage,
    wait_domain: &mut DedicatedChildWaitDomain,
    child_control: Option<&OwnedFd>,
    parent_control: Option<&OwnedFd>,
    child_trace: Option<&OwnedFd>,
    parent_trace: Option<&OwnedFd>,
) -> Result<ExactBroker<DirectChildBrokerAuthority>, BrokerSpawnError> {
    wait_domain
        .verify_single_threaded_spawn()
        .map_err(|_| BrokerSpawnError::InvalidWaitDomain)?;
    let (gate_reader, gate_writer) = create_gate_pipe()?;
    let mut actions = SpawnFileActions::new().map_err(BrokerSpawnError::FileActions)?;
    actions
        .add_dup2(gate_reader.as_raw_fd(), BROKER_GATE_FD)
        .map_err(BrokerSpawnError::FileActions)?;
    actions
        .add_close(gate_reader.as_raw_fd())
        .map_err(BrokerSpawnError::FileActions)?;
    actions
        .add_close(gate_writer.as_raw_fd())
        .map_err(BrokerSpawnError::FileActions)?;
    if let (Some(child_control), Some(parent_control)) = (child_control, parent_control) {
        actions
            .add_dup2(child_control.as_raw_fd(), BROKER_CONTROL_FD)
            .map_err(BrokerSpawnError::FileActions)?;
        actions
            .add_close(child_control.as_raw_fd())
            .map_err(BrokerSpawnError::FileActions)?;
        actions
            .add_close(parent_control.as_raw_fd())
            .map_err(BrokerSpawnError::FileActions)?;
    }
    if let (Some(child_trace), Some(parent_trace)) = (child_trace, parent_trace) {
        actions
            .add_dup2(child_trace.as_raw_fd(), BROKER_TRACE_FD)
            .map_err(BrokerSpawnError::FileActions)?;
        actions
            .add_close(child_trace.as_raw_fd())
            .map_err(BrokerSpawnError::FileActions)?;
        actions
            .add_close(parent_trace.as_raw_fd())
            .map_err(BrokerSpawnError::FileActions)?;
    }

    let mut attributes = SpawnAttributes::new().map_err(BrokerSpawnError::Attributes)?;
    attributes
        .configure_canonical_signals()
        .map_err(BrokerSpawnError::Attributes)?;

    let argv = image.argv();
    let environment = image.environment();
    // SAFETY: all CString storage, pointer arrays, file actions, attributes,
    // and pipe topology were completely prepared and remain live for the call.
    let pid = unsafe {
        spawn(
            image.path.as_c_str(),
            &actions,
            &attributes,
            &argv,
            &environment,
        )
    }
    .map_err(BrokerSpawnError::Spawn)?;
    if pid <= 0 {
        std::process::abort();
    }

    // No allocation, callback, or fallible operation may occur between the
    // successful positive spawn and these two armed ownership transitions.
    let authority = DirectChildBrokerAuthority {
        pid,
        gate_writer: Some(gate_writer),
        state: DirectChildState::Dormant,
        _wait_domain: PhantomData,
    };
    // SAFETY: the just-created authority owns the positive direct child and
    // the dedicated service wait domain is the sole waiter.
    let broker = unsafe { ExactBroker::from_unreaped_direct_child(authority) };

    // The parent's reader and the prepared C objects may be destroyed only
    // after the exact child authority is armed.
    drop(gate_reader);
    Ok(broker)
}

fn create_control_pair() -> Result<(OwnedFd, OwnedFd), BrokerSpawnError> {
    let (parent, child) = UnixStream::pair()
        .map_err(|error| BrokerSpawnError::Control(error.raw_os_error().unwrap_or(ECHILD)))?;
    let parent = duplicate_cloexec(parent.as_raw_fd())?;
    let child = duplicate_cloexec(child.as_raw_fd())?;
    set_nonblocking(parent.as_raw_fd())?;
    set_nonblocking(child.as_raw_fd())?;
    for fd in [parent.as_raw_fd(), child.as_raw_fd()] {
        // Darwin's F_SETNOSIGPIPE prevents a dead peer from terminating either
        // the permanent service or the just-execed broker during the ACK.
        if unsafe { fcntl(fd, F_SETNOSIGPIPE, 1) } != 0 {
            return Err(BrokerSpawnError::Descriptor(last_error(ECHILD)));
        }
    }
    Ok((parent, child))
}

fn send_plan_and_require_ack(
    control: OwnedFd,
    frame: &[u8],
    deadline: Instant,
) -> Result<(), BrokerSpawnError> {
    let mut stream = UnixStream::from(control);
    let outer_len = u32::try_from(frame.len()).map_err(|_| BrokerSpawnError::ControlProtocol)?;
    write_all_deadline(&mut stream, &outer_len.to_le_bytes(), deadline)?;
    write_all_deadline(&mut stream, frame, deadline)?;
    stream
        .shutdown(Shutdown::Write)
        .map_err(|error| BrokerSpawnError::Control(error.raw_os_error().unwrap_or(ECHILD)))?;
    let mut ack = [0_u8; BROKER_ACK_BYTES];
    read_exact_deadline(&mut stream, &mut ack, deadline)?;
    if Instant::now() >= deadline {
        return Err(BrokerSpawnError::DeadlineExpired);
    }
    if ack != broker_plan_ack(frame) {
        return Err(BrokerSpawnError::ControlProtocol);
    }
    let mut extra = [0_u8; 1];
    match stream.read(&mut extra) {
        Ok(0) => {}
        Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
        Ok(_) => return Err(BrokerSpawnError::ControlProtocol),
        Err(error) => {
            return Err(BrokerSpawnError::Control(
                error.raw_os_error().unwrap_or(ECHILD),
            ));
        }
    }
    if Instant::now() >= deadline {
        Err(BrokerSpawnError::DeadlineExpired)
    } else {
        Ok(())
    }
}

fn write_all_deadline(
    stream: &mut UnixStream,
    mut bytes: &[u8],
    deadline: Instant,
) -> Result<(), BrokerSpawnError> {
    while !bytes.is_empty() {
        if Instant::now() >= deadline {
            return Err(BrokerSpawnError::DeadlineExpired);
        }
        match stream.write(bytes) {
            Ok(0) => return Err(BrokerSpawnError::ControlProtocol),
            Ok(count) => bytes = &bytes[count..],
            Err(ref error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                poll_one(stream.as_raw_fd(), POLLOUT, deadline)?;
            }
            Err(error) => {
                return Err(BrokerSpawnError::Control(
                    error.raw_os_error().unwrap_or(ECHILD),
                ));
            }
        }
    }
    Ok(())
}

fn read_exact_deadline(
    stream: &mut UnixStream,
    mut bytes: &mut [u8],
    deadline: Instant,
) -> Result<(), BrokerSpawnError> {
    while !bytes.is_empty() {
        if Instant::now() >= deadline {
            return Err(BrokerSpawnError::DeadlineExpired);
        }
        match stream.read(bytes) {
            Ok(0) => return Err(BrokerSpawnError::ControlProtocol),
            Ok(count) => bytes = &mut bytes[count..],
            Err(ref error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                poll_one(stream.as_raw_fd(), POLLIN, deadline)?;
            }
            Err(error) => {
                return Err(BrokerSpawnError::Control(
                    error.raw_os_error().unwrap_or(ECHILD),
                ));
            }
        }
    }
    Ok(())
}

fn poll_one(fd: c_int, events: i16, deadline: Instant) -> Result<(), BrokerSpawnError> {
    loop {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .ok_or(BrokerSpawnError::DeadlineExpired)?;
        let timeout = c_int::try_from(remaining.as_millis()).unwrap_or(c_int::MAX);
        let mut descriptor = PollFd {
            fd,
            events,
            revents: 0,
        };
        // SAFETY: descriptor is one initialized writable pollfd.
        let result = unsafe { poll(&raw mut descriptor, 1, timeout) };
        if result > 0 {
            if descriptor.revents & events != 0 {
                return Ok(());
            }
            if descriptor.revents & (POLLERR | POLLHUP | POLLNVAL) != 0 {
                return Err(BrokerSpawnError::ControlProtocol);
            }
            continue;
        }
        if result == 0 {
            if Instant::now() >= deadline {
                return Err(BrokerSpawnError::DeadlineExpired);
            }
            continue;
        }
        let error = last_error(ECHILD);
        if error != EINTR {
            return Err(BrokerSpawnError::Control(error));
        }
    }
}

fn create_gate_pipe() -> Result<(OwnedFd, OwnedFd), BrokerSpawnError> {
    let mut descriptors = [-1; 2];
    // SAFETY: descriptors points to two writable integers.
    if unsafe { pipe(descriptors.as_mut_ptr()) } != 0 {
        return Err(BrokerSpawnError::Pipe(last_error(ECHILD)));
    }
    // SAFETY: successful pipe returned two distinct owned descriptors.
    let reader = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
    // SAFETY: successful pipe returned two distinct owned descriptors.
    let writer = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
    set_cloexec(reader.as_raw_fd())?;
    set_cloexec(writer.as_raw_fd())?;
    let reader = duplicate_cloexec(reader.as_raw_fd())?;
    let writer = duplicate_cloexec(writer.as_raw_fd())?;
    set_nonblocking(writer.as_raw_fd())?;
    // Darwin's F_SETNOSIGPIPE keeps a dead broker from terminating the service.
    if unsafe { fcntl(writer.as_raw_fd(), F_SETNOSIGPIPE, 1) } != 0 {
        return Err(BrokerSpawnError::Descriptor(last_error(ECHILD)));
    }
    Ok((reader, writer))
}

fn duplicate_cloexec(fd: c_int) -> Result<OwnedFd, BrokerSpawnError> {
    // SAFETY: fd is live and F_DUPFD_CLOEXEC returns a new owned descriptor.
    let duplicate = unsafe { fcntl(fd, F_DUPFD_CLOEXEC, STABLE_FD_MINIMUM) };
    if duplicate < 0 {
        return Err(BrokerSpawnError::Descriptor(last_error(ECHILD)));
    }
    // SAFETY: the successful fcntl returned a fresh descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(duplicate) })
}

fn set_cloexec(fd: c_int) -> Result<(), BrokerSpawnError> {
    // SAFETY: fd is live and F_SETFD accepts the scalar FD_CLOEXEC flag.
    if unsafe { fcntl(fd, F_SETFD, FD_CLOEXEC) } == 0 {
        Ok(())
    } else {
        Err(BrokerSpawnError::Descriptor(last_error(ECHILD)))
    }
}

fn set_nonblocking(fd: c_int) -> Result<(), BrokerSpawnError> {
    // SAFETY: fd is live and F_GETFL has no variadic argument.
    let flags = unsafe { fcntl(fd, F_GETFL) };
    if flags < 0 {
        return Err(BrokerSpawnError::Descriptor(last_error(ECHILD)));
    }
    // SAFETY: fd is live and F_SETFL accepts the returned status flags.
    if unsafe { fcntl(fd, F_SETFL, flags | O_NONBLOCK) } == 0 {
        Ok(())
    } else {
        Err(BrokerSpawnError::Descriptor(last_error(ECHILD)))
    }
}

fn last_error(fallback: c_int) -> c_int {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(fallback)
}

#[cfg(test)]
#[path = "supervisor_broker_spawn_test.rs"]
mod tests;
