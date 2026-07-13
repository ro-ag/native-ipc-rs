//! Accepted Windows message-pipe and duplicated-handle transports.

use core::cell::Cell;
use core::marker::PhantomData;
use core::time::Duration;

use windows_sys::Win32::Foundation::{
    ERROR_BROKEN_PIPE, ERROR_MORE_DATA, ERROR_NO_DATA, ERROR_PIPE_LISTENING,
    ERROR_PIPE_NOT_CONNECTED, GetLastError, HANDLE, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows_sys::Win32::System::JobObjects::{
    JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JobObjectBasicAccountingInformation,
    QueryInformationJobObject, TerminateJobObject,
};
use windows_sys::Win32::System::Pipes::PeekNamedPipe;
use windows_sys::Win32::System::Threading::{GetCurrentProcessId, WaitForSingleObject};

use super::vnext_memory::{WindowsMixedDirectionBatch, WindowsReceivedHandle};
use super::{ChildChannel, ChildSession, MAX_VNEXT_RECORD_BYTES, duplicate_to};
use crate::backend::{
    AuthenticatedZeroRightsTransport, CoordinatorAcceptedEvidence, CoordinatorCapabilityTransport,
    OwnedChildLifecycle, PeerState, ReceiverCapabilityTransport, ReceiverSpawnerEvidence,
    SessionTransportError, sealed,
};
use crate::protocol::{CONTROL_FRAME_LEN, CapabilityFrame, NativeAuthorityProfile};
use crate::session::AbsoluteDeadline;

const MAX_CAPABILITY_COUNT: usize = 16;
const MAX_CAPABILITY_RECORD_BYTES: usize =
    CONTROL_FRAME_LEN + MAX_CAPABILITY_COUNT * size_of::<u64>();
const TERMINATION_EXIT_CODE: u32 = 127;

#[cfg(test)]
thread_local! {
    static POST_IO_DELAY_MS: Cell<u64> = const { Cell::new(0) };
}

#[cfg(test)]
pub(super) fn set_post_io_delay_for_test(milliseconds: u64) {
    POST_IO_DELAY_MS.set(milliseconds);
}

/// Coordinator-only accepted transport retaining the exact process and Job.
pub(crate) struct CoordinatorWindowsControlTransport {
    session: ChildSession,
    evidence: CoordinatorAcceptedEvidence,
    remote_ledger: Vec<usize>,
    poisoned: bool,
    not_sync: PhantomData<Cell<()>>,
}

/// Receiver-only accepted transport with no child lifecycle authority.
pub(crate) struct ReceiverWindowsControlTransport {
    channel: ChildChannel,
    evidence: ReceiverSpawnerEvidence,
    poisoned: bool,
    not_sync: PhantomData<Cell<()>>,
}

// SAFETY: each transport uniquely owns its pipe/process/Job handles and is
// explicitly non-Sync. Moving the complete owner preserves serialized access.
unsafe impl Send for CoordinatorWindowsControlTransport {}
// SAFETY: same unique-owner argument for the receiver pipe endpoint.
unsafe impl Send for ReceiverWindowsControlTransport {}

/// Immediately owned handles installed by one canonical capability record.
pub(crate) struct WindowsReceivedCapabilities {
    handles: Vec<WindowsReceivedHandle>,
    not_sync: PhantomData<Cell<()>>,
}

impl WindowsReceivedCapabilities {
    pub(crate) fn len(&self) -> usize {
        self.handles.len()
    }

    pub(crate) fn into_handles(self) -> Vec<WindowsReceivedHandle> {
        self.handles
    }
}

impl CoordinatorWindowsControlTransport {
    pub(crate) fn from_accepted(
        session: ChildSession,
        evidence: CoordinatorAcceptedEvidence,
    ) -> Result<Self, SessionTransportError> {
        let facts = evidence.facts();
        if facts.parent_pid() != unsafe { GetCurrentProcessId() }
            || facts.child_pid() != session.pid()
            || facts.nonce() != session.vnext_nonce()
        {
            return Err(SessionTransportError::IdentityMismatch);
        }
        Ok(Self {
            session,
            evidence,
            remote_ledger: Vec::new(),
            poisoned: false,
            not_sync: PhantomData,
        })
    }

    pub(crate) fn session_parameters(&self) -> crate::backend::AcceptedSessionParameters {
        self.evidence
            .session_parameters(NativeAuthorityProfile::WindowsSectionsV1)
    }

    pub(crate) fn complete_remote_capability_transaction(&mut self) {
        self.remote_ledger.clear();
    }

    fn ensure_live(&self) -> Result<(), SessionTransportError> {
        if self.poisoned {
            Err(SessionTransportError::Native(None))
        } else {
            Ok(())
        }
    }

    fn terminal<T>(
        &mut self,
        result: Result<T, SessionTransportError>,
    ) -> Result<T, SessionTransportError> {
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
}

impl ReceiverWindowsControlTransport {
    pub(crate) fn from_accepted(
        channel: ChildChannel,
        evidence: ReceiverSpawnerEvidence,
    ) -> Result<Self, SessionTransportError> {
        let facts = evidence.facts();
        if facts.child_pid() != unsafe { GetCurrentProcessId() }
            || facts.parent_pid() != channel.parent_pid()
            || facts.nonce() != channel.vnext_nonce()
        {
            return Err(SessionTransportError::IdentityMismatch);
        }
        Ok(Self {
            channel,
            evidence,
            poisoned: false,
            not_sync: PhantomData,
        })
    }

    pub(crate) fn session_parameters(&self) -> crate::backend::AcceptedSessionParameters {
        self.evidence
            .session_parameters(NativeAuthorityProfile::WindowsSectionsV1)
    }

    fn ensure_live(&self) -> Result<(), SessionTransportError> {
        if self.poisoned {
            Err(SessionTransportError::Native(None))
        } else {
            Ok(())
        }
    }

    fn terminal<T>(
        &mut self,
        result: Result<T, SessionTransportError>,
    ) -> Result<T, SessionTransportError> {
        if result.is_err() {
            self.poisoned = true;
        }
        result
    }
}

impl sealed::Sealed for CoordinatorWindowsControlTransport {}
impl sealed::Sealed for ReceiverWindowsControlTransport {}

impl AuthenticatedZeroRightsTransport for CoordinatorWindowsControlTransport {
    fn send_record(
        &mut self,
        bytes: &[u8],
        deadline: AbsoluteDeadline,
    ) -> Result<(), SessionTransportError> {
        self.ensure_live()?;
        let result = write_message(
            self.session.pipe.0,
            bytes,
            deadline,
            Some(self.session.process.0),
        );
        self.terminal(result)
    }

    fn receive_record(
        &mut self,
        maximum: usize,
        deadline: AbsoluteDeadline,
    ) -> Result<Vec<u8>, SessionTransportError> {
        self.ensure_live()?;
        let result = read_message(
            self.session.pipe.0,
            maximum,
            deadline,
            Some(self.session.process.0),
        );
        self.terminal(result)
    }

    fn try_poll_peer(&mut self) -> Result<PeerState, SessionTransportError> {
        self.ensure_live()?;
        let result = poll_process(self.session.process.0);
        self.terminal(result)
    }

    fn poison(&mut self) {
        self.poisoned = true;
    }
}

impl AuthenticatedZeroRightsTransport for ReceiverWindowsControlTransport {
    fn send_record(
        &mut self,
        bytes: &[u8],
        deadline: AbsoluteDeadline,
    ) -> Result<(), SessionTransportError> {
        self.ensure_live()?;
        let result = write_message(self.channel.pipe.0, bytes, deadline, None);
        self.terminal(result)
    }

    fn receive_record(
        &mut self,
        maximum: usize,
        deadline: AbsoluteDeadline,
    ) -> Result<Vec<u8>, SessionTransportError> {
        self.ensure_live()?;
        let result = read_message(self.channel.pipe.0, maximum, deadline, None);
        self.terminal(result)
    }

    fn try_poll_peer(&mut self) -> Result<PeerState, SessionTransportError> {
        self.ensure_live()?;
        let result = poll_pipe(self.channel.pipe.0);
        self.terminal(result)
    }

    fn poison(&mut self) {
        self.poisoned = true;
    }
}

impl CoordinatorCapabilityTransport for CoordinatorWindowsControlTransport {
    type Capabilities<'a> = &'a WindowsMixedDirectionBatch;

    fn send_capability_record(
        &mut self,
        frame: &CapabilityFrame,
        capabilities: Self::Capabilities<'_>,
        deadline: AbsoluteDeadline,
    ) -> Result<(), SessionTransportError> {
        self.ensure_live()?;
        let result = (|| {
            if !self.remote_ledger.is_empty() {
                return Err(SessionTransportError::MalformedRecord);
            }
            let sources = capabilities
                .capability_sources()
                .map_err(|_| SessionTransportError::MalformedRecord)?;
            if sources.len() != frame.capability_count()
                || !(1..=MAX_CAPABILITY_COUNT).contains(&sources.len())
            {
                return Err(SessionTransportError::MalformedRecord);
            }
            let mut ledger = RemoteHandleLedger::new();
            let operation = (|| {
                for (source, access) in sources {
                    let remote = duplicate_to(source, self.session.process.0, access)
                        .map_err(map_windows_error)?;
                    ledger.push(remote.0);
                }
                let mut record = Vec::with_capacity(CONTROL_FRAME_LEN + ledger.handles.len() * 8);
                record.extend_from_slice(frame.as_bytes());
                for handle in &ledger.handles {
                    record.extend_from_slice(
                        &u64::try_from(*handle)
                            .map_err(|_| SessionTransportError::MalformedRecord)?
                            .to_le_bytes(),
                    );
                }
                write_message(
                    self.session.pipe.0,
                    &record,
                    deadline,
                    Some(self.session.process.0),
                )
            })();
            self.remote_ledger = ledger.into_handles();
            if operation.is_err() {
                terminate_session(&mut self.session, deadline)?;
                self.remote_ledger.clear();
            }
            operation
        })();
        self.terminal(result)
    }
}

impl ReceiverCapabilityTransport for ReceiverWindowsControlTransport {
    type ReceivedCapabilities = WindowsReceivedCapabilities;

    fn receive_capability_record(
        &mut self,
        expected: &CapabilityFrame,
        deadline: AbsoluteDeadline,
    ) -> Result<Self::ReceivedCapabilities, SessionTransportError> {
        self.ensure_live()?;
        if !(1..=MAX_CAPABILITY_COUNT).contains(&expected.capability_count()) {
            return Err(SessionTransportError::MalformedRecord);
        }
        let result = read_message(
            self.channel.pipe.0,
            MAX_CAPABILITY_RECORD_BYTES,
            deadline,
            None,
        )
        .and_then(|record| adopt_capability_record(record, expected));
        self.terminal(result)
    }
}

impl OwnedChildLifecycle for CoordinatorWindowsControlTransport {
    fn terminate_and_reap(
        &mut self,
        deadline: AbsoluteDeadline,
    ) -> Result<(), SessionTransportError> {
        self.poisoned = true;
        let result = terminate_session(&mut self.session, deadline);
        if result.is_ok() {
            self.remote_ledger.clear();
        }
        result
    }
}

struct RemoteHandleLedger {
    handles: Vec<usize>,
}

impl RemoteHandleLedger {
    fn new() -> Self {
        Self {
            handles: Vec::with_capacity(MAX_CAPABILITY_COUNT),
        }
    }

    fn push(&mut self, handle: usize) {
        self.handles.push(handle);
    }

    fn into_handles(self) -> Vec<usize> {
        self.handles
    }
}

pub(super) fn adopt_capability_record(
    record: Vec<u8>,
    expected: &CapabilityFrame,
) -> Result<WindowsReceivedCapabilities, SessionTransportError> {
    let mut malformed = record.len() < CONTROL_FRAME_LEN
        || !(record.len().saturating_sub(CONTROL_FRAME_LEN)).is_multiple_of(8);
    let tail = record.get(CONTROL_FRAME_LEN..).unwrap_or_default();
    let mut raw = Vec::with_capacity((tail.len() / 8).min(MAX_CAPABILITY_COUNT));
    for bytes in tail.chunks_exact(8).take(MAX_CAPABILITY_COUNT) {
        let Ok(value) = usize::try_from(u64::from_le_bytes(bytes.try_into().expect("fixed chunk")))
        else {
            malformed = true;
            continue;
        };
        if value == 0 || raw.contains(&value) {
            malformed = true;
        } else {
            raw.push(value);
        }
    }
    if tail.len() / 8 > MAX_CAPABILITY_COUNT {
        malformed = true;
    }
    let mut handles = Vec::with_capacity(raw.len());
    for handle in raw {
        // SAFETY: the authenticated spawning coordinator installed and sent
        // each unique numeric value for this exact process and record.
        match unsafe { WindowsReceivedHandle::from_raw(handle) } {
            Ok(handle) => handles.push(handle),
            Err(_) => malformed = true,
        }
    }
    let exact_len = CONTROL_FRAME_LEN + expected.capability_count() * 8;
    if malformed
        || record.len() != exact_len
        || handles.len() != expected.capability_count()
        || record.get(..CONTROL_FRAME_LEN) != Some(expected.as_bytes().as_slice())
    {
        return Err(SessionTransportError::MalformedRecord);
    }
    Ok(WindowsReceivedCapabilities {
        handles,
        not_sync: PhantomData,
    })
}

fn write_message(
    pipe: HANDLE,
    bytes: &[u8],
    deadline: AbsoluteDeadline,
    process: Option<HANDLE>,
) -> Result<(), SessionTransportError> {
    if bytes.is_empty() || bytes.len() > MAX_VNEXT_RECORD_BYTES {
        return Err(SessionTransportError::RecordTooLarge);
    }
    let length = u32::try_from(bytes.len()).map_err(|_| SessionTransportError::RecordTooLarge)?;
    loop {
        check_deadline(deadline)?;
        let mut written = 0_u32;
        // SAFETY: the pipe and byte range remain live; PIPE_NOWAIT makes this
        // synchronous call nonblocking and message mode preserves boundaries.
        if unsafe {
            WriteFile(
                pipe,
                bytes.as_ptr(),
                length,
                &mut written,
                core::ptr::null_mut(),
            )
        } != 0
        {
            if written == length {
                check_deadline_after_io(deadline)?;
                return Ok(());
            }
            if written == 0 {
                wait_retry(deadline)?;
            } else {
                return Err(SessionTransportError::Ambiguous);
            }
            continue;
        }
        let code = unsafe { GetLastError() };
        if is_disconnected(code) || process.is_some_and(process_exited) {
            return Err(SessionTransportError::PeerExited);
        }
        if code != ERROR_NO_DATA && code != ERROR_PIPE_LISTENING {
            return Err(native_error(code));
        }
        wait_retry(deadline)?;
    }
}

fn read_message(
    pipe: HANDLE,
    maximum: usize,
    deadline: AbsoluteDeadline,
    process: Option<HANDLE>,
) -> Result<Vec<u8>, SessionTransportError> {
    if maximum == 0 {
        return Err(SessionTransportError::RecordTooLarge);
    }
    let maximum = maximum.min(MAX_VNEXT_RECORD_BYTES);
    let capacity = u32::try_from(maximum).map_err(|_| SessionTransportError::RecordTooLarge)?;
    let mut bytes = vec![0_u8; maximum];
    loop {
        check_deadline(deadline)?;
        let mut read = 0_u32;
        // SAFETY: the pipe and output range remain live; message mode returns
        // one record or ERROR_MORE_DATA without allocating from peer length.
        if unsafe {
            ReadFile(
                pipe,
                bytes.as_mut_ptr(),
                capacity,
                &mut read,
                core::ptr::null_mut(),
            )
        } != 0
        {
            if read == 0 {
                return Err(SessionTransportError::MalformedRecord);
            }
            bytes.truncate(read as usize);
            check_deadline_after_io(deadline)?;
            return Ok(bytes);
        }
        let code = unsafe { GetLastError() };
        if code == ERROR_MORE_DATA {
            return Err(SessionTransportError::RecordTooLarge);
        }
        if is_disconnected(code) || process.is_some_and(process_exited) {
            return Err(SessionTransportError::PeerExited);
        }
        if code != ERROR_NO_DATA && code != ERROR_PIPE_LISTENING {
            return Err(native_error(code));
        }
        wait_retry(deadline)?;
    }
}

fn poll_process(process: HANDLE) -> Result<PeerState, SessionTransportError> {
    match unsafe { WaitForSingleObject(process, 0) } {
        WAIT_OBJECT_0 => Ok(PeerState::ExitedUnknown),
        WAIT_TIMEOUT => Ok(PeerState::Running),
        _ => Err(native_error(unsafe { GetLastError() })),
    }
}

fn poll_pipe(pipe: HANDLE) -> Result<PeerState, SessionTransportError> {
    // SAFETY: null data outputs request a state-only peek on the live pipe.
    if unsafe {
        PeekNamedPipe(
            pipe,
            core::ptr::null_mut(),
            0,
            core::ptr::null_mut(),
            core::ptr::null_mut(),
            core::ptr::null_mut(),
        )
    } != 0
    {
        return Ok(PeerState::Running);
    }
    let code = unsafe { GetLastError() };
    if is_disconnected(code) {
        Ok(PeerState::ExitedUnknown)
    } else {
        Err(native_error(code))
    }
}

fn terminate_session(
    session: &mut ChildSession,
    deadline: AbsoluteDeadline,
) -> Result<(), SessionTransportError> {
    if session.reaped {
        return Ok(());
    }
    if job_is_empty(session._job.0.0)?
        && poll_process(session.process.0)? == PeerState::ExitedUnknown
    {
        session.reaped = true;
        return Ok(());
    }
    // SAFETY: this session uniquely retains the kill-on-close Job containing
    // the exact still-live child and every descendant.
    if unsafe { TerminateJobObject(session._job.0.0, TERMINATION_EXIT_CODE) } == 0 {
        return Err(native_error(unsafe { GetLastError() }));
    }
    loop {
        if job_is_empty(session._job.0.0)?
            && poll_process(session.process.0)? == PeerState::ExitedUnknown
        {
            session.reaped = true;
            return Ok(());
        }
        wait_retry(deadline)?;
    }
}

fn job_is_empty(job: HANDLE) -> Result<bool, SessionTransportError> {
    let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
    // SAFETY: the held Job is live and the fixed output structure is writable.
    if unsafe {
        QueryInformationJobObject(
            job,
            JobObjectBasicAccountingInformation,
            (&raw mut accounting).cast(),
            size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
            core::ptr::null_mut(),
        )
    } == 0
    {
        Err(native_error(unsafe { GetLastError() }))
    } else {
        Ok(accounting.ActiveProcesses == 0)
    }
}

fn process_exited(process: HANDLE) -> bool {
    (unsafe { WaitForSingleObject(process, 0) }) == WAIT_OBJECT_0
}

fn is_disconnected(code: u32) -> bool {
    matches!(code, ERROR_BROKEN_PIPE | ERROR_PIPE_NOT_CONNECTED)
}

fn check_deadline(deadline: AbsoluteDeadline) -> Result<(), SessionTransportError> {
    if deadline.is_expired() {
        Err(SessionTransportError::DeadlineExpired)
    } else {
        Ok(())
    }
}

fn check_deadline_after_io(deadline: AbsoluteDeadline) -> Result<(), SessionTransportError> {
    #[cfg(test)]
    POST_IO_DELAY_MS.with(|delay| {
        let milliseconds = delay.get();
        if milliseconds != 0 {
            std::thread::sleep(Duration::from_millis(milliseconds));
        }
    });
    check_deadline(deadline)
}

fn wait_retry(deadline: AbsoluteDeadline) -> Result<(), SessionTransportError> {
    check_deadline(deadline)?;
    std::thread::sleep(Duration::from_millis(1).min(deadline.remaining()));
    check_deadline(deadline)
}

fn map_windows_error(error: super::WindowsError) -> SessionTransportError {
    match error {
        super::WindowsError::TimedOut(_) => SessionTransportError::DeadlineExpired,
        super::WindowsError::ChildExit(_) => SessionTransportError::PeerExited,
        super::WindowsError::Os { code, .. } => native_error(code),
        _ => SessionTransportError::Native(None),
    }
}

fn native_error(code: u32) -> SessionTransportError {
    SessionTransportError::Native(i32::try_from(code).ok())
}

const fn size_of<T>() -> usize {
    core::mem::size_of::<T>()
}
