//! Fused exact-message authentication state for the privileged supervisor.
//!
//! This is a source-level raw receive and ownership boundary, not an installed
//! Mach service. The deployable adapter must add clean-exec Security.framework
//! workers and exact worker authority inside this child module so the parent
//! module's unsafe peer/message factories stay private.

use std::collections::HashSet;
use std::ffi::c_int;
use std::marker::PhantomData;
use std::mem::{MaybeUninit, size_of, size_of_val};
use std::os::fd::{AsRawFd, OwnedFd};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use sha2::{Digest, Sha256};

#[cfg(test)]
use super::super::supervisor_watchdog::ExactBroker;
use super::super::supervisor_watchdog::{
    AtomicallySpawnedBroker, ExactBrokerAuthority, FreshSessionId, NonblockingReadySend,
    PendingReadyDelivery, PendingRegisteredSession, RegisteredLaunchPermit, SessionHandle,
    TerminationReason, TraceEstablished, WatchdogStateError, WatchdogTable,
};
use super::super::{MachPort, current_task, deallocate_port};
use super::{
    AuthenticatedSpawnRequest, ConnectionGeneration, ConnectionIdentity, FreshServiceNonce,
    InstalledPolicyCatalog, MAX_SUPERVISOR_RECORD_BYTES, RecordKind, SupervisorConnection,
    SupervisorDeadline, SupervisorWireError, ValidatedSpawn, VerifiedMessage, VerifiedPeer,
    decode_header, encode_ready_spawn_result,
};

#[path = "supervisor_broker_spawn.rs"]
pub(in crate::backend::macos) mod broker_spawn;

const MAX_AUTH_WORKERS: usize = 4;
const MAX_PENDING_PER_UID: usize = 2;
const FRAME_DIGEST_DOMAIN: &[u8] = b"native-ipc-macos-supervisor-auth-frame-v1";
const AUTH_WORKER_JOB_MAGIC: [u8; 8] = *b"NIPCAWJ1";
const AUTH_WORKER_RESULT_MAGIC: [u8; 8] = *b"NIPCAWR1";
const AUTH_WORKER_WIRE_VERSION: u16 = 1;
const AUTH_WORKER_JOB_BYTES: usize = 152;
const AUTH_WORKER_RESULT_BYTES: usize = 200;
const DARWIN_PIPE_BUF: usize = 512;

const JOB_VERSION_OFFSET: usize = 8;
const JOB_RESERVED_OFFSET: usize = 10;
const JOB_LENGTH_OFFSET: usize = 12;
const JOB_SLOT_OFFSET: usize = 16;
const JOB_SLOT_RESERVED_OFFSET: usize = 17;
const JOB_GENERATION_OFFSET: usize = 24;
const JOB_ID_OFFSET: usize = 32;
const JOB_ROUTE_RESERVED_OFFSET: usize = 64;
const JOB_AUDIT_OFFSET: usize = 72;
const JOB_UID_OFFSET: usize = 104;
const JOB_GID_OFFSET: usize = 108;
const JOB_DIGEST_OFFSET: usize = 112;
const JOB_DEADLINE_OFFSET: usize = 144;

const RESULT_VERSION_OFFSET: usize = 8;
const RESULT_DECISION_OFFSET: usize = 10;
const RESULT_LENGTH_OFFSET: usize = 12;
const RESULT_JOB_OFFSET: usize = 16;
const RESULT_CODE_IDENTITY_OFFSET: usize = RESULT_JOB_OFFSET + AUTH_WORKER_JOB_BYTES;

const AUTH_WORKER_VALIDATED: u16 = 1;
const AUTH_WORKER_REJECTED: u16 = 2;

type MachMsgReturn = c_int;

const MACH_PORT_NULL: MachPort = 0;
const MACH_MSGH_BITS_COMPLEX: u32 = 0x8000_0000;
const MACH_MSG_TYPE_PORT_SEND: u32 = 17;
const MACH_MSG_TYPE_PORT_SEND_ONCE: u32 = 18;
const MACH_SEND_MSG: u32 = 0x0000_0001;
const MACH_SEND_TIMEOUT: u32 = 0x0000_0010;
const MACH_SEND_INTERRUPT: u32 = 0x0000_0040;
const MACH_SEND_INVALID_DEST: MachMsgReturn = 0x1000_0003;
const MACH_SEND_TIMED_OUT: MachMsgReturn = 0x1000_0004;
const MACH_SEND_INTERRUPTED: MachMsgReturn = 0x1000_0007;
const MACH_RCV_MSG: u32 = 0x0000_0002;
const MACH_RCV_TIMEOUT: u32 = 0x0000_0100;
const MACH_RCV_INTERRUPT: u32 = 0x0000_0400;
const MACH_RCV_TRAILER_AUDIT: u32 = 3 << 24;
const MACH_RCV_TIMED_OUT: MachMsgReturn = 0x1000_4003;
const MACH_RCV_TOO_LARGE: MachMsgReturn = 0x1000_4004;
const MACH_RCV_INTERRUPTED: MachMsgReturn = 0x1000_4005;
const SUPERVISOR_MESSAGE_ID: c_int = 0x4e49_5355;
const SUPERVISOR_RECEIVED_BITS: u32 = MACH_MSG_TYPE_PORT_SEND_ONCE | (MACH_MSG_TYPE_PORT_SEND << 8);

#[repr(C)]
#[derive(Clone, Copy)]
struct MachMsgHeader {
    bits: u32,
    size: u32,
    remote_port: MachPort,
    local_port: MachPort,
    voucher_port: MachPort,
    id: c_int,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AuditToken {
    values: [u32; 8],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct AuditTrailer {
    trailer_type: u32,
    trailer_size: u32,
    sequence: u32,
    sender_security: [u32; 2],
    audit: AuditToken,
}

#[repr(C)]
#[derive(Clone, Copy, Eq, PartialEq)]
struct DarwinSigaction {
    handler: usize,
    mask: u32,
    flags: c_int,
}

unsafe extern "C" {
    fn mach_msg(
        message: *mut MachMsgHeader,
        option: u32,
        send_size: u32,
        receive_limit: u32,
        receive_name: MachPort,
        timeout: u32,
        notify: MachPort,
    ) -> MachMsgReturn;
    fn mach_msg_destroy(message: *mut MachMsgHeader);
    fn kill(pid: c_int, signal: c_int) -> c_int;
    fn read(fd: c_int, buffer: *mut u8, count: usize) -> isize;
    fn pthread_is_threaded_np() -> c_int;
    fn pthread_main_np() -> c_int;
    fn pthread_sigmask(how: c_int, set: *const u32, previous: *mut u32) -> c_int;
    fn sigaction(
        signal: c_int,
        action: *const DarwinSigaction,
        previous: *mut DarwinSigaction,
    ) -> c_int;
    fn sigaddset(set: *mut u32, signal: c_int) -> c_int;
    fn sigemptyset(set: *mut u32) -> c_int;
    fn sigismember(set: *const u32, signal: c_int) -> c_int;
    fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int;
    fn write(fd: c_int, buffer: *const u8, count: usize) -> isize;
}

const ECHILD: c_int = 10;
const EAGAIN: c_int = 35;
const EINVAL: c_int = 22;
const EINTR: c_int = 4;
const ESRCH: c_int = 3;
const SIGKILL: c_int = 9;
const SIGCHLD: c_int = 20;
const SIG_BLOCK: c_int = 1;
const SA_NOCLDWAIT: c_int = 0x0020;
const WNOHANG: c_int = 1;

static CHILD_WAIT_DOMAIN_CLAIMED: AtomicBool = AtomicBool::new(false);

#[link(name = "bsm")]
unsafe extern "C" {
    fn audit_token_to_euid(token: AuditToken) -> u32;
    fn audit_token_to_egid(token: AuditToken) -> u32;
}

/// Failure to decode one fixed private-pipe worker frame.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AuthWorkerWireError {
    /// The frame length, magic, version, reserved bytes, or scalar encoding was
    /// not the one canonical representation.
    Malformed,
    /// A worker, job, audit, credential, digest, or deadline identity was
    /// zero, reserved, or outside the fixed service bounds.
    InvalidIdentity,
    /// The decision and code-identity representation disagreed.
    InvalidDecision,
}

/// Failure to consume one authenticated request's exact send-once reply right.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum MachReplyError {
    /// The reply was empty, oversized, or not naturally aligned for Mach IPC.
    InvalidReply,
    /// The nonblocking send failed; the exact right was then deallocated.
    MachSend(c_int),
}

/// Failure while associating one raw Mach record with one disposable worker.
#[derive(Debug, Eq, PartialEq)]
pub(super) enum AuthAdapterError<WorkerFailure> {
    /// The supplied port was not a launchd-owned receive right.
    InvalidReceiveRight,
    /// A delivered Mach header, inline shape, padding, or audit trailer was
    /// not canonical. Any delivered rights were destroyed before returning.
    MalformedMachMessage,
    /// The kernel destroyed an oversized head message because the receiver
    /// deliberately omitted `MACH_RCV_LARGE`.
    RecordTooLarge,
    /// The raw Mach receive operation failed with a native status.
    MachReceive(c_int),
    /// No worker is immediately available; the adapter never queues work.
    Saturated,
    /// A per-UID or service-generation bound was exceeded.
    CapacityExceeded,
    /// A job identifier was zero or reused in this service generation.
    InvalidJobIdentity,
    /// A worker slot or generation did not match a live exact worker.
    UnknownWorker,
    /// A result did not echo the exact retained message binding.
    ResultMismatch,
    /// Exact worker cleanup made bounded progress but is not yet reaped.
    WorkerRetirementPending(AuthWorkerIdentity),
    /// The exact worker was reaped but did not exit normally with status zero.
    WorkerExitedAbnormally,
    /// Security validation did not produce a nonzero installed code identity.
    AuthenticationRejected,
    /// The original absolute deadline expired before authority could be minted.
    DeadlineExpired,
    /// A replacement was attempted before exact retirement or reused a slot.
    InvalidReplacement,
    /// Exact worker termination/reap failed while retaining the same authority.
    WorkerCleanupFailed(WorkerFailure),
    /// The shared-clock or supervisor record contract rejected the input.
    Protocol(SupervisorWireError),
}

/// Fresh service-local generation for one pre-created worker process.
#[derive(Debug, Eq, PartialEq)]
pub(super) struct FreshAuthWorkerGeneration(u64);

impl FreshAuthWorkerGeneration {
    /// # Safety
    ///
    /// `value` must be nonzero and never reused during this service lifetime.
    pub(super) const unsafe fn from_unique_service_value(
        value: u64,
    ) -> Result<Self, AuthAdapterError<std::convert::Infallible>> {
        if value == 0 {
            Err(AuthAdapterError::InvalidReplacement)
        } else {
            Ok(Self(value))
        }
    }
}

/// Fresh unpredictable identifier consumed by exactly one authentication job.
#[derive(Debug, Eq, Hash, PartialEq)]
pub(super) struct FreshAuthJobId([u8; 32]);

impl FreshAuthJobId {
    /// # Safety
    ///
    /// `value` must come from the OS CSPRNG and must not match a live job. The
    /// complete association identity is the private endpoint's never-reused
    /// worker generation plus this value; the pool permits a coincidental
    /// repeat only after exact worker reap destroys the old endpoint.
    pub(super) unsafe fn from_fresh_random(
        value: [u8; 32],
    ) -> Result<Self, AuthAdapterError<std::convert::Infallible>> {
        if value == [0; 32] {
            Err(AuthAdapterError::InvalidJobIdentity)
        } else {
            Ok(Self(value))
        }
    }
}

/// Exact identity for one pre-created worker and its private reply endpoint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct AuthWorkerIdentity {
    slot: u8,
    generation: u64,
}

/// Fixed worker input. It contains no path, requirement string, Security flags,
/// signal, filesystem operation, task port, or caller-selected policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct AuthWorkerJob {
    worker: AuthWorkerIdentity,
    job_id: [u8; 32],
    audit_identity: [u8; 32],
    effective_uid: u32,
    effective_gid: u32,
    frame_digest: [u8; 32],
    deadline: u64,
}

/// One pre-created worker's parent-side one-job pipe capability.
struct AuthWorkerEndpoint {
    request: OwnedFd,
    result: OwnedFd,
}

impl AuthWorkerEndpoint {
    /// # Safety
    ///
    /// `request` must be the sole nonblocking, CLOEXEC parent writer for one
    /// fresh worker's private job pipe, with `F_SETNOSIGPIPE` enabled. `result`
    /// must be that same worker's sole nonblocking, CLOEXEC parent reader. The
    /// worker endpoints must never be shared with another slot or generation.
    unsafe fn from_private_parent_pipe_ends(request: OwnedFd, result: OwnedFd) -> Self {
        Self { request, result }
    }
}

/// Failure on a one-job worker's private fixed-size pipes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum AuthWorkerPipeError {
    Native(c_int),
    DeadlineExpired,
    ShortWrite,
    PrematureEof,
    ExtraResultBytes,
    InvalidResult(AuthWorkerWireError),
}

/// Pipe failure retaining the exact worker identity needed for pool cleanup.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct AuthWorkerPipeFailure {
    worker: AuthWorkerIdentity,
    error: AuthWorkerPipeError,
}

impl AuthWorkerPipeFailure {
    pub(super) const fn worker(&self) -> AuthWorkerIdentity {
        self.worker
    }

    pub(super) const fn error(&self) -> AuthWorkerPipeError {
        self.error
    }
}

/// Linear receipt bound to the exact private reply endpoint assigned at
/// dispatch. The worker cannot provide or reconstruct this value.
pub(super) struct AuthWorkerReplyReceipt {
    worker: AuthWorkerIdentity,
    job_id: [u8; 32],
    result: OwnedFd,
    deadline: SupervisorDeadline,
    bytes: [u8; AUTH_WORKER_RESULT_BYTES],
    filled: usize,
}

/// Serialized job plus the non-serializable receipt for its private endpoint.
pub(super) struct DispatchedAuthJob {
    job: AuthWorkerJob,
    request: OwnedFd,
    reply_receipt: AuthWorkerReplyReceipt,
}

impl DispatchedAuthJob {
    /// Identity to retain for exact cancellation if this linear token is
    /// dropped or its one-shot submission fails.
    pub(super) const fn worker(&self) -> AuthWorkerIdentity {
        self.job.worker
    }

    /// Atomically submits the one fixed frame, then closes the sole request
    /// writer so the clean-exec worker must observe EOF after that frame.
    pub(super) fn submit(self) -> Result<AuthWorkerReplyReceipt, AuthWorkerPipeFailure> {
        let Self {
            job,
            request,
            reply_receipt,
        } = self;
        let bytes = job.encode_pipe_frame();
        if SupervisorDeadline::from_wire(job.deadline)
            .to_local_instant()
            .is_err()
        {
            return Err(AuthWorkerPipeFailure {
                worker: job.worker,
                error: AuthWorkerPipeError::DeadlineExpired,
            });
        }
        // SAFETY: `request` is the private live writer and `bytes` is valid
        // for its complete fixed length, which is no larger than PIPE_BUF.
        let written = unsafe { write(request.as_raw_fd(), bytes.as_ptr(), bytes.len()) };
        if written == isize::try_from(bytes.len()).expect("fixed frame fits isize") {
            drop(request);
            return Ok(reply_receipt);
        }
        if written >= 0 {
            return Err(AuthWorkerPipeFailure {
                worker: job.worker,
                error: AuthWorkerPipeError::ShortWrite,
            });
        }
        Err(AuthWorkerPipeFailure {
            worker: job.worker,
            error: AuthWorkerPipeError::Native(last_errno()),
        })
    }

    #[cfg(test)]
    pub(super) fn into_parts(self) -> (AuthWorkerJob, AuthWorkerReplyReceipt) {
        let Self {
            job,
            request,
            reply_receipt,
        } = self;
        drop(request);
        (job, reply_receipt)
    }
}

/// One bounded nonblocking read step over the linear exact result endpoint.
pub(super) enum AuthWorkerResultPoll {
    Pending(AuthWorkerReplyReceipt),
    Complete(ReceivedAuthWorkerResult),
}

impl AuthWorkerReplyReceipt {
    /// Identity to retain for exact cancellation if polling is abandoned.
    pub(super) const fn worker(&self) -> AuthWorkerIdentity {
        self.worker
    }

    pub(super) fn poll(mut self) -> Result<AuthWorkerResultPoll, AuthWorkerPipeFailure> {
        while self.filled < self.bytes.len() {
            self.ensure_deadline()?;
            let destination = &mut self.bytes[self.filled..];
            // SAFETY: result is the private reader and destination is writable
            // for exactly its reported nonzero remaining length.
            let read_count = unsafe {
                read(
                    self.result.as_raw_fd(),
                    destination.as_mut_ptr(),
                    destination.len(),
                )
            };
            if read_count > 0 {
                self.filled += usize::try_from(read_count).expect("positive read fits usize");
                continue;
            }
            if read_count == 0 {
                return Err(self.failure(AuthWorkerPipeError::PrematureEof));
            }
            let error = last_errno();
            if error == EINTR {
                return Ok(AuthWorkerResultPoll::Pending(self));
            }
            if error == EAGAIN {
                return Ok(AuthWorkerResultPoll::Pending(self));
            }
            return Err(self.failure(AuthWorkerPipeError::Native(error)));
        }

        let mut extra = 0_u8;
        self.ensure_deadline()?;
        // SAFETY: result is the private reader and `extra` is writable.
        let read_count = unsafe { read(self.result.as_raw_fd(), &raw mut extra, 1) };
        if read_count == 0 {
            let bytes = self.bytes;
            let worker = self.worker;
            // SAFETY: these bytes came exclusively from this receipt's
            // exact endpoint, form one full frame, and EOF was observed.
            let received = unsafe { ReceivedAuthWorkerResult::from_private_pipe(self, &bytes) }
                .map_err(|error| AuthWorkerPipeFailure {
                    worker,
                    error: AuthWorkerPipeError::InvalidResult(error),
                })?;
            return Ok(AuthWorkerResultPoll::Complete(received));
        }
        if read_count > 0 {
            return Err(self.failure(AuthWorkerPipeError::ExtraResultBytes));
        }
        let error = last_errno();
        if error == EINTR || error == EAGAIN {
            return Ok(AuthWorkerResultPoll::Pending(self));
        }
        Err(self.failure(AuthWorkerPipeError::Native(error)))
    }

    fn failure(&self, error: AuthWorkerPipeError) -> AuthWorkerPipeFailure {
        AuthWorkerPipeFailure {
            worker: self.worker,
            error,
        }
    }

    fn ensure_deadline(&self) -> Result<(), AuthWorkerPipeFailure> {
        self.deadline
            .to_local_instant()
            .map(|_| ())
            .map_err(|_| self.failure(AuthWorkerPipeError::DeadlineExpired))
    }
}

impl AuthWorkerJob {
    pub(super) const fn worker(&self) -> AuthWorkerIdentity {
        self.worker
    }

    pub(super) const fn job_id(&self) -> [u8; 32] {
        self.job_id
    }

    pub(super) const fn audit_identity(&self) -> [u8; 32] {
        self.audit_identity
    }

    pub(super) const fn effective_uid(&self) -> u32 {
        self.effective_uid
    }

    pub(super) const fn effective_gid(&self) -> u32 {
        self.effective_gid
    }

    pub(super) const fn frame_digest(&self) -> [u8; 32] {
        self.frame_digest
    }

    pub(super) const fn deadline(&self) -> u64 {
        self.deadline
    }

    /// Encodes the only job shape accepted by the clean-exec worker. The
    /// frame deliberately has no path, requirement, flags, PID, signal, task,
    /// or filesystem-operation field.
    pub(super) fn encode_pipe_frame(&self) -> [u8; AUTH_WORKER_JOB_BYTES] {
        encode_auth_worker_job(*self)
    }

    /// Decodes one complete fixed-size job read from the worker's private
    /// inherited pipe.
    pub(super) fn decode_pipe_frame(bytes: &[u8]) -> Result<Self, AuthWorkerWireError> {
        decode_auth_worker_job(bytes)
    }
}

/// Exact raw Mach receive retained by the permanent authority.
pub(super) struct RawMachRecord {
    audit_identity: [u8; 32],
    effective_uid: u32,
    effective_gid: u32,
    bytes: Vec<u8>,
    reply: MachSendOnceRight,
}

/// Linear send-once reply right delivered in one canonical request header.
pub(super) struct MachSendOnceRight(MachPort);

enum ClassifiedMachSendError {
    Recoverable(MachReplyError),
    Indeterminate(MachMsgReturn),
}

/// Fully allocated and encoded one-shot Mach send. Dropping before the syscall
/// destroys the exact retained message/right; an indeterminate syscall result
/// disarms Drop because the kernel may already have consumed part of it.
struct PreparedMachSend {
    storage: Vec<u64>,
    message_size: u32,
    armed: bool,
}

impl PreparedMachSend {
    fn send_classified(mut self) -> Result<(), ClassifiedMachSendError> {
        let bytes = words_as_bytes_mut(&mut self.storage);
        // SAFETY: preparation created one complete aligned inline message. A
        // zero timeout makes the single send syscall nonblocking.
        let status = unsafe {
            mach_msg(
                bytes.as_mut_ptr().cast(),
                MACH_SEND_MSG | MACH_SEND_TIMEOUT | MACH_SEND_INTERRUPT,
                self.message_size,
                0,
                MACH_PORT_NULL,
                0,
                MACH_PORT_NULL,
            )
        };
        match status {
            0 => {
                self.armed = false;
                Ok(())
            }
            MACH_SEND_INVALID_DEST | MACH_SEND_TIMED_OUT | MACH_SEND_INTERRUPTED => {
                // The kernel pseudo-receives recoverable failed sends back into
                // this buffer and may rewrite the right's numeric name.
                destroy_mach_message(bytes);
                self.armed = false;
                Err(ClassifiedMachSendError::Recoverable(
                    MachReplyError::MachSend(status),
                ))
            }
            _ => {
                // The buffer may be partially consumed. Exact right cleanup is
                // no longer possible; the caller must exact-clean its session
                // authority and fail-stop without touching this message again.
                self.armed = false;
                Err(ClassifiedMachSendError::Indeterminate(status))
            }
        }
    }
}

impl Drop for PreparedMachSend {
    fn drop(&mut self) {
        if self.armed {
            destroy_mach_message(words_as_bytes_mut(&mut self.storage));
            self.armed = false;
        }
    }
}

impl MachSendOnceRight {
    /// # Safety
    ///
    /// `name` must be the nonzero remote send-once right installed by one
    /// successfully received canonical Mach request. The caller must not also
    /// pass that received message to `mach_msg_destroy`.
    unsafe fn from_received(
        name: MachPort,
    ) -> Result<Self, AuthAdapterError<std::convert::Infallible>> {
        if name == MACH_PORT_NULL {
            Err(AuthAdapterError::MalformedMachMessage)
        } else {
            Ok(Self(name))
        }
    }

    #[cfg(test)]
    const fn synthetic() -> Self {
        Self(MACH_PORT_NULL)
    }

    #[cfg(test)]
    unsafe fn from_test_name(name: MachPort) -> Self {
        Self(name)
    }

    #[cfg(test)]
    const fn name(&self) -> MachPort {
        self.0
    }

    fn prepare(mut self, payload: &[u8]) -> Result<PreparedMachSend, MachReplyError> {
        let unrounded_size = size_of::<MachMsgHeader>()
            .checked_add(payload.len())
            .ok_or(MachReplyError::InvalidReply)?;
        let message_size =
            round_mach_message(unrounded_size).ok_or(MachReplyError::InvalidReply)?;
        if payload.is_empty()
            || payload.len() > MAX_SUPERVISOR_RECORD_BYTES
            || message_size != unrounded_size
        {
            return Err(MachReplyError::InvalidReply);
        }
        let message_size_wire =
            u32::try_from(message_size).map_err(|_| MachReplyError::InvalidReply)?;
        let mut storage = vec![0_u64; message_size.div_ceil(size_of::<u64>())];
        let bytes = words_as_bytes_mut(&mut storage);
        let reply = std::mem::replace(&mut self.0, MACH_PORT_NULL);
        let header = MachMsgHeader {
            bits: MACH_MSG_TYPE_PORT_SEND_ONCE,
            size: message_size_wire,
            remote_port: reply,
            local_port: MACH_PORT_NULL,
            voucher_port: MACH_PORT_NULL,
            id: SUPERVISOR_MESSAGE_ID,
        };
        // SAFETY: the aligned initialized buffer contains the complete inline
        // header and reply. A send-once reply cannot block on queue capacity.
        // Ownership moved from `self` into this message before the syscall.
        unsafe { bytes.as_mut_ptr().cast::<MachMsgHeader>().write(header) };
        bytes[size_of::<MachMsgHeader>()..message_size].copy_from_slice(payload);
        Ok(PreparedMachSend {
            storage,
            message_size: message_size_wire,
            armed: true,
        })
    }

    fn send(self, payload: &[u8]) -> Result<(), MachReplyError> {
        match self.prepare(payload)?.send_classified() {
            Ok(()) => Ok(()),
            Err(ClassifiedMachSendError::Recoverable(error)) => Err(error),
            Err(ClassifiedMachSendError::Indeterminate(_)) => {
                // Generic replies own no proof-bound broker to clean first.
                std::process::abort()
            }
        }
    }
}

impl Drop for MachSendOnceRight {
    fn drop(&mut self) {
        if self.0 != MACH_PORT_NULL {
            deallocate_port(current_task(), self.0);
            self.0 = MACH_PORT_NULL;
        }
    }
}

impl RawMachRecord {
    /// Constructs one record only inside the eventual descriptor-destroying
    /// raw Mach receive implementation.
    ///
    /// # Safety
    ///
    /// All identity facts must come from the audit trailer attached to the
    /// same exact received message whose immutable bytes are supplied here.
    unsafe fn from_exact_audit_trailer(
        audit_identity: [u8; 32],
        effective_uid: u32,
        effective_gid: u32,
        bytes: Vec<u8>,
        reply: MachSendOnceRight,
    ) -> Self {
        Self {
            audit_identity,
            effective_uid,
            effective_gid,
            bytes,
            reply,
        }
    }

    #[cfg(test)]
    unsafe fn from_test_exact_audit_trailer(
        audit_identity: [u8; 32],
        effective_uid: u32,
        effective_gid: u32,
        bytes: Vec<u8>,
    ) -> Self {
        // SAFETY: tests model one fused exact-message receive boundary.
        unsafe {
            Self::from_exact_audit_trailer(
                audit_identity,
                effective_uid,
                effective_gid,
                bytes,
                MachSendOnceRight::synthetic(),
            )
        }
    }
}

/// Borrowed launchd receive right plus one reusable aligned receive buffer.
/// The installed service owns and closes the receive right; this parser never
/// reconstructs it from a numeric name after that owner is lost.
pub(super) struct RawMachReceiver {
    receive_port: MachPort,
    receive_limit: u32,
    storage: Vec<u64>,
}

impl RawMachReceiver {
    /// # Safety
    ///
    /// `receive_port` must remain the live launchd-checked-in receive right for
    /// this receiver's entire lifetime, with no concurrent receiver consuming
    /// its queue. The caller retains the receive-right owner.
    pub(super) unsafe fn from_borrowed_launchd_receive_right(
        receive_port: MachPort,
    ) -> Result<Self, AuthAdapterError<std::convert::Infallible>> {
        if receive_port == MACH_PORT_NULL {
            return Err(AuthAdapterError::InvalidReceiveRight);
        }
        let receive_bytes = supervisor_receive_bytes().ok_or(AuthAdapterError::RecordTooLarge)?;
        let receive_limit =
            u32::try_from(receive_bytes).map_err(|_| AuthAdapterError::RecordTooLarge)?;
        Ok(Self {
            receive_port,
            receive_limit,
            storage: vec![0_u64; receive_bytes.div_ceil(size_of::<u64>())],
        })
    }

    /// Receives under one service-owned poll bound, then authenticates under
    /// the earlier of a service-owned authentication cap and the original
    /// spawn deadline carried by the exact received bytes.
    ///
    /// A client hello has no effect deadline, so it uses only `auth_cap`.
    /// Parsing unauthenticated bytes here can only shorten or reject work; it
    /// cannot create a peer, connection, policy effect, or watchdog entry.
    pub(super) fn receive_and_dispatch_capped<Authority: ExactAuthWorkerAuthority>(
        &mut self,
        job_id: FreshAuthJobId,
        receive_deadline: SupervisorDeadline,
        auth_cap: SupervisorDeadline,
        pool: &mut AuthWorkerPool<Authority>,
    ) -> Result<DispatchedAuthJob, AuthAdapterError<Authority::Failure>> {
        let raw = self
            .receive(receive_deadline)
            .map_err(|error| match error {
                AuthAdapterError::InvalidReceiveRight => AuthAdapterError::InvalidReceiveRight,
                AuthAdapterError::MalformedMachMessage => AuthAdapterError::MalformedMachMessage,
                AuthAdapterError::RecordTooLarge => AuthAdapterError::RecordTooLarge,
                AuthAdapterError::MachReceive(code) => AuthAdapterError::MachReceive(code),
                AuthAdapterError::DeadlineExpired => AuthAdapterError::DeadlineExpired,
                AuthAdapterError::Protocol(error) => AuthAdapterError::Protocol(error),
                _ => unreachable!("raw receive cannot return worker-state errors"),
            })?;
        let deadline = raw
            .authentication_deadline(auth_cap)
            .map_err(AuthAdapterError::Protocol)?;
        pool.dispatch(raw, job_id, deadline)
    }

    fn receive(
        &mut self,
        deadline: SupervisorDeadline,
    ) -> Result<RawMachRecord, AuthAdapterError<std::convert::Infallible>> {
        let bytes = words_as_bytes_mut(&mut self.storage);
        loop {
            bytes.fill(0);
            let timeout = mach_receive_timeout(deadline).map_err(AuthAdapterError::Protocol)?;
            // SAFETY: the buffer is naturally aligned, zero initialized, and
            // sized for the maximum inline message plus exact audit trailer.
            let status = unsafe {
                mach_msg(
                    bytes.as_mut_ptr().cast(),
                    MACH_RCV_MSG | MACH_RCV_TIMEOUT | MACH_RCV_INTERRUPT | MACH_RCV_TRAILER_AUDIT,
                    0,
                    self.receive_limit,
                    self.receive_port,
                    timeout,
                    MACH_PORT_NULL,
                )
            };
            match status {
                0 => break,
                MACH_RCV_INTERRUPTED => continue,
                MACH_RCV_TIMED_OUT if deadline.to_local_instant().is_ok() => continue,
                MACH_RCV_TIMED_OUT => return Err(AuthAdapterError::DeadlineExpired),
                MACH_RCV_TOO_LARGE => return Err(AuthAdapterError::RecordTooLarge),
                code => return Err(AuthAdapterError::MachReceive(code)),
            }
        }

        let Some(header) = read_wire::<MachMsgHeader>(bytes, 0) else {
            destroy_mach_message(bytes);
            return Err(AuthAdapterError::MalformedMachMessage);
        };
        if header.bits & MACH_MSGH_BITS_COMPLEX != 0 {
            destroy_mach_message(bytes);
            return Err(AuthAdapterError::MalformedMachMessage);
        }
        if deadline.to_local_instant().is_err() {
            destroy_mach_message(bytes);
            return Err(AuthAdapterError::DeadlineExpired);
        }
        let message_size = header.size as usize;
        let Some(trailer_offset) = round_mach_message(message_size) else {
            destroy_mach_message(bytes);
            return Err(AuthAdapterError::MalformedMachMessage);
        };
        let trailer_end = trailer_offset.checked_add(size_of::<AuditTrailer>());
        let trailer = read_wire::<AuditTrailer>(bytes, trailer_offset);
        let payload_offset = size_of::<MachMsgHeader>();
        let canonical = header.bits == SUPERVISOR_RECEIVED_BITS
            && header.remote_port != MACH_PORT_NULL
            && header.local_port == self.receive_port
            && header.voucher_port == MACH_PORT_NULL
            && header.id == SUPERVISOR_MESSAGE_ID
            && message_size > payload_offset
            && message_size <= payload_offset + MAX_SUPERVISOR_RECORD_BYTES
            && trailer_end.is_some_and(|end| end <= bytes.len())
            && bytes
                .get(message_size..trailer_offset)
                .is_some_and(|padding| padding.iter().all(|byte| *byte == 0))
            && trailer.is_some_and(|value| {
                value.trailer_type == 0 && value.trailer_size as usize == size_of::<AuditTrailer>()
            });
        if !canonical {
            destroy_mach_message(bytes);
            return Err(AuthAdapterError::MalformedMachMessage);
        }
        let trailer = trailer.expect("canonical trailer");
        let audit_identity = encode_audit_token(trailer.audit);
        // SAFETY: both public BSM decoders consume the exact complete token
        // copied from this same message's checked kernel audit trailer.
        let effective_uid = unsafe { audit_token_to_euid(trailer.audit) };
        // SAFETY: same checked complete token and public BSM ABI as above.
        let effective_gid = unsafe { audit_token_to_egid(trailer.audit) };
        let received_payload = &bytes[payload_offset..message_size];
        let payload = match exact_logical_supervisor_record(received_payload) {
            Some(payload) => payload.to_vec(),
            None => {
                destroy_mach_message(bytes);
                return Err(AuthAdapterError::MalformedMachMessage);
            }
        };
        // SAFETY: the checked nonzero received remote port is the canonical
        // send-once reply right. We do not destroy this accepted message.
        let reply = unsafe { MachSendOnceRight::from_received(header.remote_port) }
            .map_err(|_| AuthAdapterError::MalformedMachMessage)?;
        // SAFETY: payload, token, credentials, and reply all came from this one
        // exact successfully received and canonically validated Mach message.
        Ok(unsafe {
            RawMachRecord::from_exact_audit_trailer(
                audit_identity,
                effective_uid,
                effective_gid,
                payload,
                reply,
            )
        })
    }
}

impl RawMachRecord {
    /// Selects an authentication deadline from the exact retained request.
    ///
    /// Only a canonical Spawn envelope contributes caller authority. Its
    /// prefix must contain the fixed absolute deadline before any worker is
    /// assigned. Every other canonical request is bounded by the service cap
    /// and is classified after exact-message authentication.
    fn authentication_deadline(
        &self,
        auth_cap: SupervisorDeadline,
    ) -> Result<SupervisorDeadline, SupervisorWireError> {
        auth_cap.to_local_instant()?;
        let header = decode_header(&self.bytes)?;
        let deadline = if header.kind == RecordKind::Spawn {
            if header.payload_len < super::SPAWN_PREFIX_LEN {
                return Err(SupervisorWireError::Malformed);
            }
            let wire = super::u64_at(&self.bytes[super::HEADER_LEN..], 0)?;
            SupervisorDeadline::from_wire(wire).earlier(auth_cap)
        } else {
            auth_cap
        };
        deadline.to_local_instant()?;
        Ok(deadline)
    }
}

/// Result received only from the assigned worker's fresh private endpoint.
pub(super) struct AuthWorkerResult {
    job: AuthWorkerJob,
    code_identity: [u8; 32],
}

impl AuthWorkerResult {
    /// # Safety
    ///
    /// The installed one-job worker must have validated `job.audit_identity`
    /// through `kSecGuestAttributeAudit` against its fixed compiled client
    /// requirement, and this result must arrive on that worker's private reply
    /// endpoint. No dynamic validation result may be cached.
    unsafe fn from_security_validation(job: AuthWorkerJob, code_identity: [u8; 32]) -> Self {
        Self { job, code_identity }
    }

    /// Encodes one terminal worker decision. A validated result must carry a
    /// nonzero installed-policy code identity; a rejection must carry zero.
    fn encode_pipe_frame(&self) -> Result<[u8; AUTH_WORKER_RESULT_BYTES], AuthWorkerWireError> {
        encode_auth_worker_result(self)
    }

    #[cfg(test)]
    unsafe fn from_test_security_validation(job: AuthWorkerJob, code_identity: [u8; 32]) -> Self {
        // SAFETY: tests model a result from the assigned private endpoint.
        unsafe { Self::from_security_validation(job, code_identity) }
    }
}

/// Result bytes fused to the consumed linear receipt for the exact private
/// worker endpoint that delivered them.
pub(super) struct ReceivedAuthWorkerResult {
    receipt: AuthWorkerReplyReceipt,
    result: AuthWorkerResult,
}

impl ReceivedAuthWorkerResult {
    pub(super) const fn worker(&self) -> AuthWorkerIdentity {
        self.receipt.worker
    }

    /// # Safety
    ///
    /// `bytes` must have been read from the fresh private result endpoint
    /// represented by `receipt`, after that endpoint delivered exactly one
    /// complete frame and reached EOF. No sibling module may construct this
    /// value from caller-selected or recombined bytes.
    unsafe fn from_private_pipe(
        receipt: AuthWorkerReplyReceipt,
        bytes: &[u8],
    ) -> Result<Self, AuthWorkerWireError> {
        Ok(Self {
            receipt,
            result: decode_auth_worker_result(bytes)?,
        })
    }

    #[cfg(test)]
    unsafe fn from_test_private_pipe(
        receipt: AuthWorkerReplyReceipt,
        bytes: &[u8],
    ) -> Result<Self, AuthWorkerWireError> {
        // SAFETY: tests model bytes read from the consumed receipt's exact
        // private result endpoint.
        unsafe { Self::from_private_pipe(receipt, bytes) }
    }
}

/// Proof that one exact auth-worker direct child has been reaped, including
/// whether it reached the only exit status allowed to authorize a result.
pub(super) struct ReapedAuthWorker {
    clean_exit: bool,
}

impl ReapedAuthWorker {
    /// # Safety
    ///
    /// The exact worker owned by the calling authority must already be reaped,
    /// and `status` must be the status returned by that exact `waitpid` call.
    const unsafe fn from_exact_wait_status(status: c_int) -> Self {
        Self {
            clean_exit: wait_status_is_clean_exit(status),
        }
    }
}

const fn wait_status_is_clean_exit(status: c_int) -> bool {
    status & 0x7f == 0 && (status >> 8) & 0xff == 0
}

/// Failure to establish the permanent process-wide auth-worker wait domain.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChildWaitDomainError {
    /// Another owner already claimed the process-wide auth-worker wait domain.
    AlreadyClaimed,
    /// The current SIGCHLD disposition could not be queried.
    Sigaction(c_int),
    /// SIGCHLD was ignored or handled instead of retaining the default action.
    NonDefaultSigchld,
    /// The process requested automatic child reaping, which destroys PID pins.
    AutoReapEnabled,
    /// Initialization did not run on the process's main thread.
    NotMainThread,
    /// Another thread had already existed before the wait domain was claimed.
    ProcessAlreadyThreaded,
    /// Canonical SIGCHLD state could not be installed.
    InstallSigaction(c_int),
    /// A public signal-set operation failed.
    SignalSet(c_int),
    /// Blocking SIGCHLD for the service thread failed.
    SignalMask(c_int),
    /// A post-installation recheck did not observe canonical SIGCHLD state.
    NonCanonicalSigchld,
    /// A post-installation recheck did not observe SIGCHLD blocked.
    SigchldNotBlocked,
}

/// One-shot proof that the dedicated service claimed its child wait domain.
///
/// This proof is intentionally neither `Clone` nor `Copy`. It can verify the
/// public process-wide SIGCHLD prerequisites, while the absence of competing
/// `wait*` callers remains a service-topology and source-ownership invariant.
#[must_use = "the dedicated child wait domain must own every auth worker"]
pub(in crate::backend::macos::supervisor) struct DedicatedChildWaitDomain {
    // The concrete runtime must remain on the dedicated service main thread.
    _not_send_or_sync: PhantomData<Rc<()>>,
    #[cfg(test)]
    bypass_spawn_recheck: bool,
}

impl DedicatedChildWaitDomain {
    /// Establishes the permanent process-wide child wait domain.
    ///
    /// # Safety
    ///
    /// This must run during single-threaded service startup, before any child
    /// is spawned or any code capable of calling `wait*` is initialized. The
    /// installed service must reserve all direct children for this module and
    /// must serialize every later child creation through an exclusive borrow
    /// of this domain, never race a raw fork/spawn against pipe CLOEXEC setup,
    /// and never change SIGCHLD disposition or enable `SA_NOCLDWAIT`.
    unsafe fn establish_at_service_startup() -> Result<Self, ChildWaitDomainError> {
        // SAFETY: these public Darwin queries have no arguments or side effects.
        if unsafe { pthread_main_np() } == 0 {
            return Err(ChildWaitDomainError::NotMainThread);
        }
        // SAFETY: same public read-only process-state query.
        if unsafe { pthread_is_threaded_np() } != 0 {
            return Err(ChildWaitDomainError::ProcessAlreadyThreaded);
        }
        Self::validate_disposition(Self::query_disposition()?)?;
        CHILD_WAIT_DOMAIN_CLAIMED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| ChildWaitDomainError::AlreadyClaimed)?;

        let canonical = DarwinSigaction {
            handler: 0,
            mask: 0,
            flags: 0,
        };
        // SAFETY: canonical has Darwin's public sigaction layout; the domain
        // contract guarantees no concurrent disposition mutation.
        if unsafe { sigaction(SIGCHLD, &raw const canonical, std::ptr::null_mut()) } != 0 {
            return Err(ChildWaitDomainError::InstallSigaction(
                std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(EINVAL),
            ));
        }

        let mut blocked = 0_u32;
        // SAFETY: `blocked` points to one Darwin sigset_t.
        if unsafe { sigemptyset(&raw mut blocked) } != 0
            || unsafe { sigaddset(&raw mut blocked, SIGCHLD) } != 0
        {
            return Err(ChildWaitDomainError::SignalSet(
                std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(EINVAL),
            ));
        }
        // pthread_sigmask returns its error directly rather than through errno.
        // SAFETY: the set is initialized and the previous mask is not needed.
        let mask_error =
            unsafe { pthread_sigmask(SIG_BLOCK, &raw const blocked, std::ptr::null_mut()) };
        if mask_error != 0 {
            return Err(ChildWaitDomainError::SignalMask(mask_error));
        }

        if Self::query_disposition()? != canonical {
            return Err(ChildWaitDomainError::NonCanonicalSigchld);
        }
        let mut current_mask = 0_u32;
        // SAFETY: a null set performs a read-only query into current_mask.
        let mask_error =
            unsafe { pthread_sigmask(SIG_BLOCK, std::ptr::null(), &raw mut current_mask) };
        if mask_error != 0 {
            return Err(ChildWaitDomainError::SignalMask(mask_error));
        }
        // SAFETY: current_mask was initialized by successful pthread_sigmask.
        if unsafe { sigismember(&raw const current_mask, SIGCHLD) } != 1 {
            return Err(ChildWaitDomainError::SigchldNotBlocked);
        }
        Ok(Self {
            _not_send_or_sync: PhantomData,
            #[cfg(test)]
            bypass_spawn_recheck: false,
        })
    }

    fn verify_single_threaded_spawn(&mut self) -> Result<(), ChildWaitDomainError> {
        #[cfg(test)]
        if self.bypass_spawn_recheck {
            return Ok(());
        }
        // Darwin has no pipe2. Remaining permanently on the main thread with
        // pthread_is_threaded_np still clear is the enforced exclusion that
        // prevents any concurrent fork/exec from observing a new pipe before
        // both ends receive FD_CLOEXEC.
        // SAFETY: these public Darwin queries have no arguments or side effects.
        if unsafe { pthread_main_np() } == 0 {
            return Err(ChildWaitDomainError::NotMainThread);
        }
        // SAFETY: same public read-only process-state query.
        if unsafe { pthread_is_threaded_np() } != 0 {
            return Err(ChildWaitDomainError::ProcessAlreadyThreaded);
        }
        Self::validate_disposition(Self::query_disposition()?)?;
        let mut current_mask = 0_u32;
        // SAFETY: a null set performs a read-only query into current_mask.
        let mask_error =
            unsafe { pthread_sigmask(SIG_BLOCK, std::ptr::null(), &raw mut current_mask) };
        if mask_error != 0 {
            return Err(ChildWaitDomainError::SignalMask(mask_error));
        }
        // SAFETY: current_mask was initialized by successful pthread_sigmask.
        if unsafe { sigismember(&raw const current_mask, SIGCHLD) } != 1 {
            return Err(ChildWaitDomainError::SigchldNotBlocked);
        }
        Ok(())
    }

    fn query_disposition() -> Result<DarwinSigaction, ChildWaitDomainError> {
        let mut disposition = MaybeUninit::<DarwinSigaction>::uninit();
        // SAFETY: a null action performs a read-only query and `disposition`
        // points to writable storage with Darwin's public sigaction layout.
        if unsafe { sigaction(SIGCHLD, std::ptr::null(), disposition.as_mut_ptr()) } != 0 {
            return Err(ChildWaitDomainError::Sigaction(
                std::io::Error::last_os_error()
                    .raw_os_error()
                    .unwrap_or(EINVAL),
            ));
        }
        // SAFETY: successful sigaction initialized the complete structure.
        Ok(unsafe { disposition.assume_init() })
    }

    const fn validate_disposition(
        disposition: DarwinSigaction,
    ) -> Result<(), ChildWaitDomainError> {
        if disposition.handler != 0 {
            return Err(ChildWaitDomainError::NonDefaultSigchld);
        }
        if disposition.flags & SA_NOCLDWAIT != 0 {
            return Err(ChildWaitDomainError::AutoReapEnabled);
        }
        Ok(())
    }
}

/// Native failure while retaining one exact direct-child worker authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum DirectChildAuthWorkerError {
    /// The spawn result was not a positive direct-child PID.
    InvalidChild,
    /// The sole-waiter invariant was lost. No numeric signal is permitted.
    WaitAuthorityLost,
    /// An exact nonblocking wait failed while the child remained unreaped.
    Wait(c_int),
    /// Signaling the still-unreaped direct child failed.
    Signal(c_int),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DirectChildState {
    Unreaped,
    TerminationSent,
    Reaped,
    AuthorityLost,
}

/// Sole-waiter authority for one exact worker returned by `posix_spawn`.
///
/// This type deliberately retains no audit-token snapshot, start time, PID
/// version, or other reconstructible identity. Its only permission to use the
/// numeric PID is the kernel's unreaped-direct-child relation: a live child or
/// zombie pins the PID until this authority's exact `waitpid` consumes it.
struct DirectChildAuthWorkerAuthority {
    pid: c_int,
    state: DirectChildState,
}

impl DirectChildAuthWorkerAuthority {
    /// # Safety
    ///
    /// `pid` must be the positive PID returned by a successful exact-path
    /// `posix_spawn` performed by this process. This object must be installed
    /// immediately into the service's serialized sole-waiter domain. SIGCHLD
    /// must retain normal zombie semantics: neither `SIG_IGN` nor
    /// `SA_NOCLDWAIT` is permitted for the service process.
    #[cfg(test)]
    unsafe fn from_test_spawned_direct_child(
        pid: c_int,
    ) -> Result<Self, DirectChildAuthWorkerError> {
        if pid <= 0 {
            return Err(DirectChildAuthWorkerError::InvalidChild);
        }
        Ok(Self {
            pid,
            state: DirectChildState::Unreaped,
        })
    }

    fn observe_exact_reap(
        &mut self,
        options: c_int,
    ) -> Result<Option<ReapedAuthWorker>, DirectChildAuthWorkerError> {
        if matches!(
            self.state,
            DirectChildState::Reaped | DirectChildState::AuthorityLost
        ) {
            return Err(DirectChildAuthWorkerError::WaitAuthorityLost);
        }
        let mut status = 0;
        // SAFETY: the constructor requires this object to be the sole waiter
        // for this exact positive direct child, and `status` is writable.
        let result = unsafe { waitpid(self.pid, &raw mut status, options) };
        if result == self.pid {
            self.state = DirectChildState::Reaped;
            // SAFETY: status came from the successful exact wait above.
            return Ok(Some(unsafe {
                ReapedAuthWorker::from_exact_wait_status(status)
            }));
        }
        if result == 0 {
            return Ok(None);
        }
        let error = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(ECHILD);
        if error == ECHILD {
            self.state = DirectChildState::AuthorityLost;
            // No kernel relation remains that could authorize use of the PID.
            // Returning would leave a lost-authority slot live; fail-stop at
            // the exact discovery site without attempting a numeric signal.
            std::process::abort();
        } else {
            Err(DirectChildAuthWorkerError::Wait(error))
        }
    }

    fn signal_exact_child(&mut self) -> Result<(), DirectChildAuthWorkerError> {
        if matches!(
            self.state,
            DirectChildState::Reaped | DirectChildState::AuthorityLost
        ) {
            return Err(DirectChildAuthWorkerError::WaitAuthorityLost);
        }
        if self.state == DirectChildState::TerminationSent {
            return Ok(());
        }
        // SAFETY: no successful exact reap has occurred. If the child exited
        // after the preceding observation, its unreaped zombie still pins this
        // PID, so this call cannot target a replacement process.
        if unsafe { kill(self.pid, SIGKILL) } == 0 {
            self.state = DirectChildState::TerminationSent;
            return Ok(());
        }
        let error = std::io::Error::last_os_error()
            .raw_os_error()
            .unwrap_or(ESRCH);
        if error == ESRCH {
            // ESRCH is compatible with an already-exited, still-unreaped child.
            // Only exact waitpid may retire the authority.
            self.state = DirectChildState::TerminationSent;
            Ok(())
        } else {
            Err(DirectChildAuthWorkerError::Signal(error))
        }
    }

    fn emergency_cleanup(&mut self) -> ReapedAuthWorker {
        if matches!(
            self.state,
            DirectChildState::Reaped | DirectChildState::AuthorityLost
        ) {
            std::process::abort();
        }
        if self.state == DirectChildState::Unreaped && self.signal_exact_child().is_err() {
            std::process::abort();
        }
        loop {
            match self.observe_exact_reap(0) {
                Ok(Some(proof)) => return proof,
                Ok(None) => std::process::abort(),
                Err(DirectChildAuthWorkerError::Wait(EINTR)) => continue,
                Err(
                    DirectChildAuthWorkerError::InvalidChild
                    | DirectChildAuthWorkerError::WaitAuthorityLost
                    | DirectChildAuthWorkerError::Wait(_)
                    | DirectChildAuthWorkerError::Signal(_),
                ) => std::process::abort(),
            }
        }
    }
}

/// Exact worker cleanup and sole-waiter behavior.
///
/// # Safety
///
/// Implementations must exclusively retain one unreaped direct-child or traced
/// worker authority. Numeric signaling is permitted only while that relation
/// pins the PID. `Err` must retain the same unreaped authority for retry.
/// A reaped nonzero/signaled exit must be represented faithfully and can never
/// authorize authentication. `ECHILD`, auto-reap, or waiter loss must never
/// trigger a numeric fallback. If an error represents permanent authority
/// loss, all later cleanup must fail-stop. Emergency cleanup must abort the
/// service rather than abandon authority.
pub(super) unsafe trait ExactAuthWorkerAuthority {
    type Failure;

    /// Performs one bounded nonblocking exact-reap observation after a result.
    fn try_reap_after_result(&mut self) -> Result<Option<ReapedAuthWorker>, Self::Failure>;

    /// Performs one bounded nonblocking exact terminate/reap progress step.
    fn try_terminate_and_reap(&mut self) -> Result<Option<ReapedAuthWorker>, Self::Failure>;
    fn emergency_terminate_and_reap(&mut self) -> ReapedAuthWorker;
}

unsafe impl ExactAuthWorkerAuthority for DirectChildAuthWorkerAuthority {
    type Failure = DirectChildAuthWorkerError;

    fn try_reap_after_result(&mut self) -> Result<Option<ReapedAuthWorker>, Self::Failure> {
        self.observe_exact_reap(WNOHANG)
    }

    fn try_terminate_and_reap(&mut self) -> Result<Option<ReapedAuthWorker>, Self::Failure> {
        if let Some(proof) = self.observe_exact_reap(WNOHANG)? {
            return Ok(Some(proof));
        }
        self.signal_exact_child()?;
        self.observe_exact_reap(WNOHANG)
    }

    fn emergency_terminate_and_reap(&mut self) -> ReapedAuthWorker {
        self.emergency_cleanup()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuthWorkerRetirement {
    Pending,
    Clean,
    Rejected,
}

struct ExactAuthWorker<Authority: ExactAuthWorkerAuthority> {
    authority: Authority,
    armed: bool,
}

impl<Authority: ExactAuthWorkerAuthority> ExactAuthWorker<Authority> {
    /// # Safety
    ///
    /// `authority` must satisfy [`ExactAuthWorkerAuthority`] for one pre-created
    /// one-job worker and its sole waiter domain.
    unsafe fn from_unreaped_direct_child(authority: Authority) -> Self {
        Self {
            authority,
            armed: true,
        }
    }

    #[cfg(test)]
    unsafe fn from_test_unreaped_direct_child(authority: Authority) -> Self {
        // SAFETY: the test authority models one exact unreaped direct child.
        unsafe { Self::from_unreaped_direct_child(authority) }
    }

    fn try_reap_after_result(&mut self) -> Result<AuthWorkerRetirement, Authority::Failure> {
        let Some(proof) = self.authority.try_reap_after_result()? else {
            return Ok(AuthWorkerRetirement::Pending);
        };
        let clean_exit = proof.clean_exit;
        self.mark_reaped(proof);
        Ok(if clean_exit {
            AuthWorkerRetirement::Clean
        } else {
            AuthWorkerRetirement::Rejected
        })
    }

    fn try_terminate_and_reap(&mut self) -> Result<bool, Authority::Failure> {
        let Some(proof) = self.authority.try_terminate_and_reap()? else {
            return Ok(false);
        };
        self.mark_reaped(proof);
        Ok(true)
    }

    fn mark_reaped(&mut self, _proof: ReapedAuthWorker) {
        self.armed = false;
    }
}

impl ExactAuthWorker<DirectChildAuthWorkerAuthority> {
    #[cfg(test)]
    unsafe fn from_test_spawned_direct_child(
        pid: c_int,
    ) -> Result<Self, DirectChildAuthWorkerError> {
        // SAFETY: the test caller supplies the documented exact direct-child
        // and sole-waiter invariants.
        let authority =
            unsafe { DirectChildAuthWorkerAuthority::from_test_spawned_direct_child(pid)? };
        // SAFETY: the authority was just created for this exact unreaped child
        // and cannot escape before the armed wrapper owns it.
        Ok(unsafe { Self::from_unreaped_direct_child(authority) })
    }
}

impl<Authority: ExactAuthWorkerAuthority> Drop for ExactAuthWorker<Authority> {
    fn drop(&mut self) {
        if self.armed {
            let proof = self.authority.emergency_terminate_and_reap();
            self.mark_reaped(proof);
        }
    }
}

struct PendingRecord {
    raw: RawMachRecord,
    job: AuthWorkerJob,
    deadline: SupervisorDeadline,
    outcome: PendingOutcome,
}

#[derive(Clone, Copy)]
enum PendingOutcome {
    AwaitingResult,
    Validated([u8; 32]),
    Rejected,
}

struct WorkerSlot<Authority: ExactAuthWorkerAuthority> {
    identity: AuthWorkerIdentity,
    worker: ExactAuthWorker<Authority>,
    endpoint: Option<AuthWorkerEndpoint>,
    pending: Option<PendingRecord>,
}

/// Exact record authenticated only after the one-job worker is reaped.
pub(super) struct AuthenticatedMachRecord {
    raw: RawMachRecord,
    code_identity: [u8; 32],
    deadline: SupervisorDeadline,
}

/// Authenticated, exact-reaped request shape ready for service-state routing.
pub(super) enum AuthenticatedMachRoute {
    /// A hello that may create one fresh connection only after full decoding.
    ClientHello(AuthenticatedClientHello),
    /// A spawn naming an existing authenticated service generation.
    Spawn(AuthenticatedSpawn),
}

pub(super) struct AuthenticatedClientHello(AuthenticatedMachRecord);

pub(super) struct AuthenticatedSpawn {
    record: AuthenticatedMachRecord,
    freshness: SpawnReplyFreshness,
}

/// Exact accepted spawn-header facts retained with its send-once reply right.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct SpawnReplyFreshness {
    connection: ConnectionIdentity,
    generation: u64,
    sequence: u64,
    client_nonce: [u8; 32],
    service_nonce: [u8; 32],
}

impl std::fmt::Debug for SpawnReplyFreshness {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SpawnReplyFreshness(..)")
    }
}

/// Operation output still bound to the exact request's linear send-once reply
/// right. Callers cannot substitute a reply route from another request.
pub(super) struct AuthenticatedMachRequest<Output> {
    reply: MachSendOnceRight,
    output: Output,
}

impl<Output> AuthenticatedMachRequest<Output> {
    fn bind_spawn(self, freshness: SpawnReplyFreshness) -> PendingSpawnReply<Output> {
        PendingSpawnReply {
            reply: self.reply,
            freshness,
            bound_session: None,
            output: self.output,
        }
    }

    #[cfg(test)]
    pub(super) fn into_parts(self) -> (MachSendOnceRight, Output) {
        (self.reply, self.output)
    }
}

/// Linear spawn operation output bound to the exact request reply and header.
///
/// Later launch, trace, and watchdog transformations must consume this wrapper
/// so no caller can combine an outcome with another request's reply authority.
#[must_use = "dropping a pending spawn reply abandons its exact reply authority"]
pub(super) struct PendingSpawnReply<Output> {
    reply: MachSendOnceRight,
    freshness: SpawnReplyFreshness,
    bound_session: Option<SessionHandle>,
    output: Output,
}

impl<Output> PendingSpawnReply<Output> {
    #[cfg(test)]
    pub(super) fn map_output<Next>(
        self,
        operation: impl FnOnce(Output) -> Next,
    ) -> PendingSpawnReply<Next> {
        PendingSpawnReply {
            reply: self.reply,
            freshness: self.freshness,
            bound_session: self.bound_session,
            output: operation(self.output),
        }
    }

    #[cfg(test)]
    pub(super) fn try_map_output<Next, Failure>(
        self,
        operation: impl FnOnce(Output) -> Result<Next, Failure>,
    ) -> Result<PendingSpawnReply<Next>, PendingSpawnReply<Failure>> {
        let Self {
            reply,
            freshness,
            bound_session,
            output,
        } = self;
        match operation(output) {
            Ok(output) => Ok(PendingSpawnReply {
                reply,
                freshness,
                bound_session,
                output,
            }),
            Err(output) => Err(PendingSpawnReply {
                reply,
                freshness,
                bound_session,
                output,
            }),
        }
    }

    #[cfg(test)]
    pub(super) fn into_parts(
        self,
    ) -> (
        MachSendOnceRight,
        SpawnReplyFreshness,
        Option<SessionHandle>,
        Output,
    ) {
        (self.reply, self.freshness, self.bound_session, self.output)
    }
}

impl PendingSpawnReply<AuthenticatedSpawnRequest> {
    /// Consumes the exact authenticated request through the immutable catalog
    /// without permitting a closure to substitute another effect authority.
    pub(super) fn validate(
        self,
        catalog: &InstalledPolicyCatalog,
    ) -> Result<PendingSpawnReply<ValidatedSpawn>, Box<PendingSpawnReply<SupervisorWireError>>>
    {
        let Self {
            reply,
            freshness,
            bound_session,
            output,
        } = self;
        match output.validate(catalog) {
            Ok(output) => Ok(PendingSpawnReply {
                reply,
                freshness,
                bound_session,
                output,
            }),
            Err(output) => Err(Box::new(PendingSpawnReply {
                reply,
                freshness,
                bound_session,
                output,
            })),
        }
    }
}

/// Validated request after its fresh opaque session is inseparably assigned to
/// the exact reply path, before any broker child can be created.
pub(super) struct SessionAssignedSpawn {
    session: FreshSessionId,
    spawn: ValidatedSpawn,
}

impl PendingSpawnReply<ValidatedSpawn> {
    pub(super) fn assign_session(
        self,
        session: FreshSessionId,
    ) -> PendingSpawnReply<SessionAssignedSpawn> {
        let Self {
            reply,
            freshness,
            bound_session,
            output,
        } = self;
        debug_assert!(bound_session.is_none());
        let handle = session.handle();
        PendingSpawnReply {
            reply,
            freshness,
            bound_session: Some(handle),
            output: SessionAssignedSpawn {
                session,
                spawn: output,
            },
        }
    }
}

#[cfg(test)]
impl PendingSpawnReply<SessionAssignedSpawn> {
    unsafe fn attach_test_atomic_broker<Authority: ExactBrokerAuthority>(
        self,
        broker: ExactBroker<Authority>,
    ) -> PendingSpawnReply<AtomicallySpawnedBroker<ValidatedSpawn, Authority>> {
        let Self {
            reply,
            freshness,
            bound_session,
            output,
        } = self;
        // SAFETY: the test caller models the broker as the exact child created
        // for this already assigned launch operation.
        let output = unsafe {
            AtomicallySpawnedBroker::from_test_atomic_spawn(output.session, output.spawn, broker)
        };
        PendingSpawnReply {
            reply,
            freshness,
            bound_session,
            output,
        }
    }
}

/// Trace proof did not match the armed registered-session obligation.
pub(super) struct TraceBindingMismatch;

enum ReadyNativeSendError {
    Binding,
    DeadlineExpired,
    Recoverable(MachReplyError),
    Indeterminate(MachMsgReturn),
}

/// Terminal result of attempting the exact authenticated Ready reply.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ReadyReplyError {
    Protocol(SupervisorWireError),
    Watchdog(WatchdogStateError),
    Mach(MachReplyError),
}

struct PreparedReadyMachSend {
    message: PreparedMachSend,
    expected_handle: SessionHandle,
    expected_connection: ConnectionIdentity,
}

// SAFETY: all allocation and encoding occur before this value is constructed.
// send_once performs only scalar binding/deadline checks and one zero-timeout
// Mach send over the exact retained send-once reply authority.
unsafe impl NonblockingReadySend for PreparedReadyMachSend {
    type Error = ReadyNativeSendError;

    fn cleanup_reason(error: &Self::Error) -> TerminationReason {
        match error {
            ReadyNativeSendError::DeadlineExpired => TerminationReason::DeadlineExpired,
            ReadyNativeSendError::Binding
            | ReadyNativeSendError::Recoverable(_)
            | ReadyNativeSendError::Indeterminate(_) => TerminationReason::SpawnResultUndeliverable,
        }
    }

    fn send_once(
        self,
        handle: SessionHandle,
        connection: ConnectionIdentity,
        deadline: Instant,
    ) -> Result<(), Self::Error> {
        if handle != self.expected_handle || connection != self.expected_connection {
            return Err(ReadyNativeSendError::Binding);
        }
        if Instant::now() >= deadline {
            return Err(ReadyNativeSendError::DeadlineExpired);
        }
        self.message.send_classified().map_err(|error| match error {
            ClassifiedMachSendError::Recoverable(error) => ReadyNativeSendError::Recoverable(error),
            ClassifiedMachSendError::Indeterminate(error) => {
                ReadyNativeSendError::Indeterminate(error)
            }
        })
    }
}

impl<Authority: ExactBrokerAuthority>
    PendingSpawnReply<AtomicallySpawnedBroker<ValidatedSpawn, Authority>>
{
    /// Registers one atomic spawn result while retaining a session-specific
    /// armed obligation through trusted launch, trace binding, and Ready.
    pub(super) fn register_watchdog(
        self,
        table: &mut WatchdogTable<Authority>,
    ) -> Result<
        PendingSpawnReply<PendingRegisteredSession<ValidatedSpawn, Authority>>,
        Box<PendingSpawnReply<WatchdogStateError>>,
    > {
        let Self {
            reply,
            freshness,
            bound_session,
            output,
        } = self;
        debug_assert!(bound_session.is_some());
        match table.register_armed(output) {
            Ok(mut registered) => {
                let handle = registered.handle();
                if bound_session != Some(handle) || registered.connection() != freshness.connection
                {
                    registered.mark_protocol_violation();
                    drop(registered);
                    return Err(Box::new(PendingSpawnReply {
                        reply,
                        freshness,
                        bound_session,
                        output: WatchdogStateError::WrongConnection,
                    }));
                }
                Ok(PendingSpawnReply {
                    reply,
                    freshness,
                    bound_session: Some(handle),
                    output: registered,
                })
            }
            Err(output) => Err(Box::new(PendingSpawnReply {
                reply,
                freshness,
                bound_session,
                output,
            })),
        }
    }
}

impl<Authority: ExactBrokerAuthority>
    PendingSpawnReply<PendingRegisteredSession<ValidatedSpawn, Authority>>
{
    pub(super) fn registered_launch_permit(
        &self,
    ) -> Result<RegisteredLaunchPermit<'_, ValidatedSpawn, Authority>, WatchdogStateError> {
        self.output.launch_permit()
    }

    /// Accepts only the trace proof for the exact registered handle and
    /// authenticated connection retained with this request's reply. A mismatch
    /// exact-cleans before returning the error wrapper.
    pub(super) fn bind_trace(
        mut self,
        trace: TraceEstablished,
    ) -> Result<Self, Box<PendingSpawnReply<TraceBindingMismatch>>> {
        if self.bound_session == Some(self.output.handle())
            && self.output.connection() == self.freshness.connection
            && trace.handle() == self.output.handle()
            && trace.connection() == self.output.connection()
            && self.output.bind_trace(trace).is_ok()
        {
            Ok(self)
        } else {
            self.output.mark_protocol_violation();
            let Self {
                reply,
                freshness,
                bound_session,
                output,
            } = self;
            drop(output);
            Err(Box::new(PendingSpawnReply {
                reply,
                freshness,
                bound_session,
                output: TraceBindingMismatch,
            }))
        }
    }

    /// Transitions directly into the armed table-borrowing Ready guard; no
    /// loose Ready proof can escape between trace transition and reply cleanup.
    pub(super) fn establish_ready(
        self,
    ) -> Result<PendingSpawnReply<PendingReadyDelivery<Authority>>, WatchdogStateError> {
        let Self {
            reply,
            freshness,
            bound_session,
            output,
        } = self;
        if bound_session != Some(output.handle())
            || freshness.connection != output.connection()
            || freshness.generation != freshness.connection.get()
            || freshness.sequence != 1
            || freshness.client_nonce == [0; 32]
            || freshness.service_nonce == [0; 32]
            || freshness.client_nonce == freshness.service_nonce
        {
            let mut output = output;
            output.mark_protocol_violation();
            drop(output);
            return Err(WatchdogStateError::WrongConnection);
        }
        let output = output.mark_traced_for_delivery()?;
        Ok(PendingSpawnReply {
            reply,
            freshness,
            bound_session,
            output,
        })
    }
}

impl<Authority: ExactBrokerAuthority> PendingSpawnReply<PendingReadyDelivery<Authority>> {
    /// Encodes and commits Ready only through the armed watchdog guard. Every
    /// error drops that guard and emergency exact-cleans before it is returned;
    /// an indeterminate Mach send exact-cleans and then fail-stops.
    pub(super) fn send_ready(self) -> Result<(), ReadyReplyError> {
        let Self {
            reply,
            freshness,
            bound_session,
            output,
        } = self;
        let handle = bound_session.ok_or(ReadyReplyError::Watchdog(
            WatchdogStateError::UnknownSession,
        ))?;
        let payload = encode_ready_spawn_result(
            handle.bytes(),
            freshness.generation,
            freshness.client_nonce,
            freshness.service_nonce,
        )
        .map_err(ReadyReplyError::Protocol)?;
        let message = reply.prepare(&payload).map_err(ReadyReplyError::Mach)?;
        let send = PreparedReadyMachSend {
            message,
            expected_handle: handle,
            expected_connection: freshness.connection,
        };
        match output.deliver(send) {
            Ok(Ok(())) => Ok(()),
            Err(error) => Err(ReadyReplyError::Watchdog(error)),
            Ok(Err(ReadyNativeSendError::Binding)) => Err(ReadyReplyError::Watchdog(
                WatchdogStateError::WrongConnection,
            )),
            Ok(Err(ReadyNativeSendError::DeadlineExpired)) => Err(ReadyReplyError::Watchdog(
                WatchdogStateError::DeadlineExpired,
            )),
            Ok(Err(ReadyNativeSendError::Recoverable(error))) => Err(ReadyReplyError::Mach(error)),
            Ok(Err(ReadyNativeSendError::Indeterminate(error))) => {
                let _ = error;
                std::process::abort()
            }
        }
    }
}

impl AuthenticatedMachRequest<Vec<u8>> {
    /// Sends the response only over this request's exact kernel send-once
    pub(super) fn send_reply(self) -> Result<(), MachReplyError> {
        self.reply.send(&self.output)
    }
}

impl AuthenticatedMachRecord {
    /// Parses only the routing envelope after exact-message authentication and
    /// exact worker reap. No unauthenticated generation can consume or poison
    /// connection state or pre-authentication worker capacity.
    pub(super) fn route(self) -> Result<AuthenticatedMachRoute, SupervisorWireError> {
        self.deadline.to_local_instant()?;
        let header = decode_header(&self.raw.bytes)?;
        match header.kind {
            RecordKind::ClientHello if header.generation == 0 => Ok(
                AuthenticatedMachRoute::ClientHello(AuthenticatedClientHello(self)),
            ),
            RecordKind::Spawn if header.generation != 0 => {
                Ok(AuthenticatedMachRoute::Spawn(AuthenticatedSpawn {
                    record: self,
                    freshness: SpawnReplyFreshness {
                        connection: ConnectionIdentity(header.generation),
                        generation: header.generation,
                        sequence: header.sequence,
                        client_nonce: header.client_nonce,
                        service_nonce: header.service_nonce,
                    },
                }))
            }
            RecordKind::ClientHello
            | RecordKind::ServiceHello
            | RecordKind::Spawn
            | RecordKind::SpawnResult => Err(SupervisorWireError::Malformed),
        }
    }

    fn with_verified_message<Output>(
        self,
        connection_identity: ConnectionIdentity,
        operation: impl FnOnce(VerifiedMessage<'_>) -> Result<Output, SupervisorWireError>,
    ) -> Result<AuthenticatedMachRequest<Output>, SupervisorWireError> {
        let Self {
            raw,
            code_identity,
            deadline,
        } = self;
        deadline.to_local_instant()?;
        let RawMachRecord {
            audit_identity,
            effective_uid,
            effective_gid,
            bytes,
            reply,
        } = raw;
        // SAFETY: the adapter retained one immutable message and its exact
        // audit token through matching Security validation and exact worker
        // reap. No caller can independently construct or recombine these facts.
        let peer = unsafe {
            VerifiedPeer::from_authenticated_message_audit_token(
                connection_identity,
                audit_identity,
                effective_uid,
                effective_gid,
                code_identity,
            )?
        };
        // SAFETY: `peer` was derived from the same retained raw message bytes.
        let message =
            unsafe { VerifiedMessage::from_authenticated_message_audit_token(peer, &bytes) };
        let output = operation(message)?;
        Ok(AuthenticatedMachRequest { reply, output })
    }

    fn receive_client_hello(
        self,
        connection: &mut SupervisorConnection,
    ) -> Result<AuthenticatedMachRequest<Vec<u8>>, SupervisorWireError> {
        self.with_verified_message(connection.connection_identity(), |message| {
            connection.receive_client_hello(message)
        })
    }

    fn receive_spawn(
        self,
        connection: &mut SupervisorConnection,
    ) -> Result<AuthenticatedMachRequest<super::AuthenticatedSpawnRequest>, SupervisorWireError>
    {
        self.with_verified_message(connection.connection_identity(), |message| {
            connection.receive_spawn(message)
        })
    }
}

impl AuthenticatedClientHello {
    /// Creates a service connection only if the fully authenticated hello is
    /// canonical. A failure returns no connection for a registry to insert.
    pub(super) fn accept(
        self,
        generation: ConnectionGeneration,
        service_nonce: FreshServiceNonce,
    ) -> Result<(SupervisorConnection, AuthenticatedMachRequest<Vec<u8>>), SupervisorWireError>
    {
        let mut connection = SupervisorConnection::new(generation, service_nonce);
        let reply = self.0.receive_client_hello(&mut connection)?;
        Ok((connection, reply))
    }
}

impl AuthenticatedSpawn {
    pub(super) const fn generation(&self) -> u64 {
        self.freshness.generation
    }

    /// Applies the request only to the registry-selected exact generation.
    pub(super) fn accept(
        self,
        connection: &mut SupervisorConnection,
    ) -> Result<PendingSpawnReply<super::AuthenticatedSpawnRequest>, SupervisorWireError> {
        if connection.connection_identity() != self.freshness.connection {
            return Err(SupervisorWireError::ReplayOrSubstitution);
        }
        let request = self.record.receive_spawn(connection)?;
        Ok(request.bind_spawn(self.freshness))
    }
}

/// Fixed-capacity, no-queue set of pre-created one-job auth workers.
pub(super) struct AuthWorkerPool<Authority: ExactAuthWorkerAuthority> {
    slots: Vec<Option<WorkerSlot<Authority>>>,
    live_jobs: HashSet<[u8; 32]>,
    last_worker_generation: u64,
}

impl<Authority: ExactAuthWorkerAuthority> AuthWorkerPool<Authority> {
    fn from_precreated_workers(
        workers: Vec<(
            FreshAuthWorkerGeneration,
            ExactAuthWorker<Authority>,
            AuthWorkerEndpoint,
        )>,
    ) -> Result<Self, AuthAdapterError<Authority::Failure>> {
        if workers.is_empty() || workers.len() > MAX_AUTH_WORKERS {
            return Err(AuthAdapterError::CapacityExceeded);
        }
        let mut seen_worker_generations = HashSet::with_capacity(workers.len());
        let mut last_worker_generation = 0;
        let mut slots = Vec::with_capacity(workers.len());
        for (slot, (generation, worker, endpoint)) in workers.into_iter().enumerate() {
            if !seen_worker_generations.insert(generation.0) {
                return Err(AuthAdapterError::InvalidReplacement);
            }
            last_worker_generation = last_worker_generation.max(generation.0);
            slots.push(Some(WorkerSlot {
                identity: AuthWorkerIdentity {
                    slot: u8::try_from(slot).expect("worker bound fits u8"),
                    generation: generation.0,
                },
                worker,
                endpoint: Some(endpoint),
                pending: None,
            }));
        }
        Ok(Self {
            slots,
            live_jobs: HashSet::new(),
            last_worker_generation,
        })
    }

    #[cfg(test)]
    fn from_test_precreated_workers(
        workers: Vec<(
            FreshAuthWorkerGeneration,
            ExactAuthWorker<Authority>,
            AuthWorkerEndpoint,
        )>,
    ) -> Result<Self, AuthAdapterError<Authority::Failure>> {
        Self::from_precreated_workers(workers)
    }

    /// Assigns immediately to one idle worker. No Security call, process spawn,
    /// blocking send, filesystem lookup, or queue operation occurs here.
    pub(super) fn dispatch(
        &mut self,
        raw: RawMachRecord,
        job_id: FreshAuthJobId,
        deadline: SupervisorDeadline,
    ) -> Result<DispatchedAuthJob, AuthAdapterError<Authority::Failure>> {
        deadline
            .to_local_instant()
            .map_err(AuthAdapterError::Protocol)?;
        if raw.bytes.len() > MAX_SUPERVISOR_RECORD_BYTES
            || raw.audit_identity == [0; 32]
            || raw.effective_uid == 0
            || raw.effective_gid == 0
            || raw.effective_uid == u32::MAX
            || raw.effective_gid == u32::MAX
        {
            return Err(AuthAdapterError::CapacityExceeded);
        }
        if self.live_jobs.contains(&job_id.0) {
            return Err(AuthAdapterError::InvalidJobIdentity);
        }
        let uid_pending = self
            .slots
            .iter()
            .flatten()
            .filter_map(|slot| slot.pending.as_ref())
            .filter(|pending| pending.raw.effective_uid == raw.effective_uid)
            .count();
        if uid_pending >= MAX_PENDING_PER_UID {
            return Err(AuthAdapterError::CapacityExceeded);
        }
        let slot = self
            .slots
            .iter_mut()
            .flatten()
            .find(|slot| slot.pending.is_none() && slot.endpoint.is_some())
            .ok_or(AuthAdapterError::Saturated)?;
        let frame_digest = frame_digest(&raw);
        let job = AuthWorkerJob {
            worker: slot.identity,
            job_id: job_id.0,
            audit_identity: raw.audit_identity,
            effective_uid: raw.effective_uid,
            effective_gid: raw.effective_gid,
            frame_digest,
            deadline: deadline.wire_value(),
        };
        self.live_jobs.insert(job.job_id);
        let endpoint = slot
            .endpoint
            .take()
            .expect("idle worker retains one private endpoint");
        slot.pending = Some(PendingRecord {
            raw,
            job,
            deadline,
            outcome: PendingOutcome::AwaitingResult,
        });
        Ok(DispatchedAuthJob {
            job,
            request: endpoint.request,
            reply_receipt: AuthWorkerReplyReceipt {
                worker: job.worker,
                job_id: job.job_id,
                result: endpoint.result,
                deadline,
                bytes: [0; AUTH_WORKER_RESULT_BYTES],
                filled: 0,
            },
        })
    }

    /// Accepts a result only from the linear receipt minted for its exact reply
    /// endpoint. Authority is minted only if a bounded nonblocking reap has
    /// already produced the typed exact-worker proof.
    pub(super) fn complete(
        &mut self,
        received: ReceivedAuthWorkerResult,
    ) -> Result<AuthenticatedMachRecord, AuthAdapterError<Authority::Failure>> {
        let ReceivedAuthWorkerResult { receipt, result } = received;
        let slot_index = usize::from(receipt.worker.slot);
        let mismatch = match self.slots.get(slot_index).and_then(Option::as_ref) {
            Some(slot) if slot.identity == receipt.worker => match &slot.pending {
                Some(pending) => {
                    receipt.job_id != pending.job.job_id
                        || !matches!(pending.outcome, PendingOutcome::AwaitingResult)
                        || pending.job != result.job
                }
                None => true,
            },
            _ => return Err(AuthAdapterError::UnknownWorker),
        };
        if mismatch {
            self.mark_rejected(slot_index);
            return match self.terminate_slot(slot_index) {
                Ok(()) => Err(AuthAdapterError::ResultMismatch),
                Err(error) => Err(error),
            };
        }
        let deadline = self.slots[slot_index]
            .as_ref()
            .and_then(|slot| slot.pending.as_ref())
            .expect("matched pending job")
            .deadline;
        if deadline.to_local_instant().is_err() {
            self.mark_rejected(slot_index);
            return match self.terminate_slot(slot_index) {
                Ok(()) => Err(AuthAdapterError::DeadlineExpired),
                Err(error) => Err(error),
            };
        }
        if result.code_identity == [0; 32] {
            self.mark_rejected(slot_index);
            return match self.terminate_slot(slot_index) {
                Ok(()) => Err(AuthAdapterError::AuthenticationRejected),
                Err(error) => Err(error),
            };
        }
        let pending = self.slots[slot_index]
            .as_mut()
            .and_then(|slot| slot.pending.as_mut())
            .expect("matched pending job");
        pending.outcome = PendingOutcome::Validated(result.code_identity);
        self.poll_completed(receipt.worker)
    }

    /// Makes one bounded nonblocking exact-reap observation for a previously
    /// validated result. `WorkerRetirementPending` retains all authority.
    pub(super) fn poll_completed(
        &mut self,
        worker: AuthWorkerIdentity,
    ) -> Result<AuthenticatedMachRecord, AuthAdapterError<Authority::Failure>> {
        let slot_index = usize::from(worker.slot);
        let slot = self
            .slots
            .get_mut(slot_index)
            .and_then(Option::as_mut)
            .ok_or(AuthAdapterError::UnknownWorker)?;
        if slot.identity != worker {
            return Err(AuthAdapterError::UnknownWorker);
        }
        let pending = slot
            .pending
            .as_ref()
            .ok_or(AuthAdapterError::UnknownWorker)?;
        let code_identity = match pending.outcome {
            PendingOutcome::Validated(code_identity) => code_identity,
            PendingOutcome::AwaitingResult | PendingOutcome::Rejected => {
                return Err(AuthAdapterError::ResultMismatch);
            }
        };
        if pending.deadline.to_local_instant().is_err() {
            self.mark_rejected(slot_index);
            return match self.terminate_slot(slot_index) {
                Ok(()) => Err(AuthAdapterError::DeadlineExpired),
                Err(error) => Err(error),
            };
        }
        match slot
            .worker
            .try_reap_after_result()
            .map_err(AuthAdapterError::WorkerCleanupFailed)?
        {
            AuthWorkerRetirement::Pending => {
                return Err(AuthAdapterError::WorkerRetirementPending(worker));
            }
            AuthWorkerRetirement::Rejected => {
                let pending = slot.pending.take().expect("validated pending job");
                self.live_jobs.remove(&pending.job.job_id);
                self.slots[slot_index] = None;
                return Err(AuthAdapterError::WorkerExitedAbnormally);
            }
            AuthWorkerRetirement::Clean => {}
        }
        let pending = slot.pending.take().expect("validated pending job");
        self.live_jobs.remove(&pending.job.job_id);
        self.slots[slot_index] = None;
        Ok(AuthenticatedMachRecord {
            raw: pending.raw,
            code_identity,
            deadline: pending.deadline,
        })
    }

    /// Cancels or retires a wedged/malformed worker using only retained exact
    /// unreaped-child authority. On failure the same slot remains unavailable.
    pub(super) fn cancel(
        &mut self,
        worker: AuthWorkerIdentity,
    ) -> Result<(), AuthAdapterError<Authority::Failure>> {
        let slot_index = usize::from(worker.slot);
        let slot = self
            .slots
            .get(slot_index)
            .and_then(Option::as_ref)
            .ok_or(AuthAdapterError::UnknownWorker)?;
        if slot.identity != worker {
            return Err(AuthAdapterError::UnknownWorker);
        }
        self.mark_rejected(slot_index);
        self.terminate_slot(slot_index)
    }

    /// Installs a fresh pre-created worker only into an exactly retired slot.
    fn install_replacement(
        &mut self,
        slot_index: u8,
        generation: FreshAuthWorkerGeneration,
        worker: ExactAuthWorker<Authority>,
        endpoint: AuthWorkerEndpoint,
    ) -> Result<AuthWorkerIdentity, AuthAdapterError<Authority::Failure>> {
        let index = usize::from(slot_index);
        if index >= self.slots.len()
            || self.slots[index].is_some()
            || generation.0 <= self.last_worker_generation
        {
            return Err(AuthAdapterError::InvalidReplacement);
        }
        let identity = AuthWorkerIdentity {
            slot: slot_index,
            generation: generation.0,
        };
        self.last_worker_generation = generation.0;
        self.slots[index] = Some(WorkerSlot {
            identity,
            worker,
            endpoint: Some(endpoint),
            pending: None,
        });
        Ok(identity)
    }

    #[cfg(test)]
    fn install_test_replacement(
        &mut self,
        slot_index: u8,
        generation: FreshAuthWorkerGeneration,
        worker: ExactAuthWorker<Authority>,
        endpoint: AuthWorkerEndpoint,
    ) -> Result<AuthWorkerIdentity, AuthAdapterError<Authority::Failure>> {
        self.install_replacement(slot_index, generation, worker, endpoint)
    }

    fn terminate_slot(
        &mut self,
        slot_index: usize,
    ) -> Result<(), AuthAdapterError<Authority::Failure>> {
        let slot = self
            .slots
            .get_mut(slot_index)
            .and_then(Option::as_mut)
            .ok_or(AuthAdapterError::UnknownWorker)?;
        if !slot
            .worker
            .try_terminate_and_reap()
            .map_err(AuthAdapterError::WorkerCleanupFailed)?
        {
            return Err(AuthAdapterError::WorkerRetirementPending(slot.identity));
        }
        if let Some(pending) = &slot.pending {
            self.live_jobs.remove(&pending.job.job_id);
        }
        self.slots[slot_index] = None;
        Ok(())
    }

    fn mark_rejected(&mut self, slot_index: usize) {
        if let Some(pending) = self
            .slots
            .get_mut(slot_index)
            .and_then(Option::as_mut)
            .and_then(|slot| slot.pending.as_mut())
        {
            pending.outcome = PendingOutcome::Rejected;
        }
    }
}

fn encode_auth_worker_job(job: AuthWorkerJob) -> [u8; AUTH_WORKER_JOB_BYTES] {
    let mut bytes = [0_u8; AUTH_WORKER_JOB_BYTES];
    bytes[..AUTH_WORKER_JOB_MAGIC.len()].copy_from_slice(&AUTH_WORKER_JOB_MAGIC);
    write_u16(&mut bytes, JOB_VERSION_OFFSET, AUTH_WORKER_WIRE_VERSION);
    write_u32(&mut bytes, JOB_LENGTH_OFFSET, AUTH_WORKER_JOB_BYTES as u32);
    bytes[JOB_SLOT_OFFSET] = job.worker.slot;
    write_u64(&mut bytes, JOB_GENERATION_OFFSET, job.worker.generation);
    bytes[JOB_ID_OFFSET..JOB_ID_OFFSET + job.job_id.len()].copy_from_slice(&job.job_id);
    bytes[JOB_AUDIT_OFFSET..JOB_AUDIT_OFFSET + job.audit_identity.len()]
        .copy_from_slice(&job.audit_identity);
    write_u32(&mut bytes, JOB_UID_OFFSET, job.effective_uid);
    write_u32(&mut bytes, JOB_GID_OFFSET, job.effective_gid);
    bytes[JOB_DIGEST_OFFSET..JOB_DIGEST_OFFSET + job.frame_digest.len()]
        .copy_from_slice(&job.frame_digest);
    write_u64(&mut bytes, JOB_DEADLINE_OFFSET, job.deadline);
    bytes
}

fn decode_auth_worker_job(bytes: &[u8]) -> Result<AuthWorkerJob, AuthWorkerWireError> {
    if bytes.len() != AUTH_WORKER_JOB_BYTES
        || bytes.get(..AUTH_WORKER_JOB_MAGIC.len()) != Some(AUTH_WORKER_JOB_MAGIC.as_slice())
        || read_u16(bytes, JOB_VERSION_OFFSET) != Some(AUTH_WORKER_WIRE_VERSION)
        || read_u16(bytes, JOB_RESERVED_OFFSET) != Some(0)
        || read_u32(bytes, JOB_LENGTH_OFFSET) != Some(AUTH_WORKER_JOB_BYTES as u32)
        || bytes
            .get(JOB_SLOT_RESERVED_OFFSET..JOB_GENERATION_OFFSET)
            .is_none_or(|reserved| reserved.iter().any(|byte| *byte != 0))
        || read_u64(bytes, JOB_ROUTE_RESERVED_OFFSET) != Some(0)
    {
        return Err(AuthWorkerWireError::Malformed);
    }
    let slot = *bytes
        .get(JOB_SLOT_OFFSET)
        .ok_or(AuthWorkerWireError::Malformed)?;
    let generation =
        read_u64(bytes, JOB_GENERATION_OFFSET).ok_or(AuthWorkerWireError::Malformed)?;
    let job_id = array_at::<32>(bytes, JOB_ID_OFFSET).ok_or(AuthWorkerWireError::Malformed)?;
    let audit_identity =
        array_at::<32>(bytes, JOB_AUDIT_OFFSET).ok_or(AuthWorkerWireError::Malformed)?;
    let effective_uid = read_u32(bytes, JOB_UID_OFFSET).ok_or(AuthWorkerWireError::Malformed)?;
    let effective_gid = read_u32(bytes, JOB_GID_OFFSET).ok_or(AuthWorkerWireError::Malformed)?;
    let frame_digest =
        array_at::<32>(bytes, JOB_DIGEST_OFFSET).ok_or(AuthWorkerWireError::Malformed)?;
    let deadline = read_u64(bytes, JOB_DEADLINE_OFFSET).ok_or(AuthWorkerWireError::Malformed)?;
    if usize::from(slot) >= MAX_AUTH_WORKERS
        || generation == 0
        || job_id == [0; 32]
        || audit_identity == [0; 32]
        || effective_uid == 0
        || effective_gid == 0
        || effective_uid == u32::MAX
        || effective_gid == u32::MAX
        || frame_digest == [0; 32]
        || deadline == 0
    {
        return Err(AuthWorkerWireError::InvalidIdentity);
    }
    Ok(AuthWorkerJob {
        worker: AuthWorkerIdentity { slot, generation },
        job_id,
        audit_identity,
        effective_uid,
        effective_gid,
        frame_digest,
        deadline,
    })
}

fn encode_auth_worker_result(
    result: &AuthWorkerResult,
) -> Result<[u8; AUTH_WORKER_RESULT_BYTES], AuthWorkerWireError> {
    let decision = if result.code_identity == [0; 32] {
        AUTH_WORKER_REJECTED
    } else {
        AUTH_WORKER_VALIDATED
    };
    let mut bytes = [0_u8; AUTH_WORKER_RESULT_BYTES];
    bytes[..AUTH_WORKER_RESULT_MAGIC.len()].copy_from_slice(&AUTH_WORKER_RESULT_MAGIC);
    write_u16(&mut bytes, RESULT_VERSION_OFFSET, AUTH_WORKER_WIRE_VERSION);
    write_u16(&mut bytes, RESULT_DECISION_OFFSET, decision);
    write_u32(
        &mut bytes,
        RESULT_LENGTH_OFFSET,
        AUTH_WORKER_RESULT_BYTES as u32,
    );
    bytes[RESULT_JOB_OFFSET..RESULT_CODE_IDENTITY_OFFSET]
        .copy_from_slice(&encode_auth_worker_job(result.job));
    bytes[RESULT_CODE_IDENTITY_OFFSET..].copy_from_slice(&result.code_identity);
    Ok(bytes)
}

fn decode_auth_worker_result(bytes: &[u8]) -> Result<AuthWorkerResult, AuthWorkerWireError> {
    if bytes.len() != AUTH_WORKER_RESULT_BYTES
        || bytes.get(..AUTH_WORKER_RESULT_MAGIC.len()) != Some(AUTH_WORKER_RESULT_MAGIC.as_slice())
        || read_u16(bytes, RESULT_VERSION_OFFSET) != Some(AUTH_WORKER_WIRE_VERSION)
        || read_u32(bytes, RESULT_LENGTH_OFFSET) != Some(AUTH_WORKER_RESULT_BYTES as u32)
    {
        return Err(AuthWorkerWireError::Malformed);
    }
    let decision = read_u16(bytes, RESULT_DECISION_OFFSET).ok_or(AuthWorkerWireError::Malformed)?;
    let job = decode_auth_worker_job(
        bytes
            .get(RESULT_JOB_OFFSET..RESULT_CODE_IDENTITY_OFFSET)
            .ok_or(AuthWorkerWireError::Malformed)?,
    )?;
    let code_identity =
        array_at::<32>(bytes, RESULT_CODE_IDENTITY_OFFSET).ok_or(AuthWorkerWireError::Malformed)?;
    match decision {
        AUTH_WORKER_VALIDATED if code_identity != [0; 32] => {}
        AUTH_WORKER_REJECTED if code_identity == [0; 32] => {}
        AUTH_WORKER_VALIDATED | AUTH_WORKER_REJECTED => {
            return Err(AuthWorkerWireError::InvalidDecision);
        }
        _ => return Err(AuthWorkerWireError::Malformed),
    }
    Ok(AuthWorkerResult { job, code_identity })
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    array_at::<2>(bytes, offset).map(u16::from_le_bytes)
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    array_at::<4>(bytes, offset).map(u32::from_le_bytes)
}

fn read_u64(bytes: &[u8], offset: usize) -> Option<u64> {
    array_at::<8>(bytes, offset).map(u64::from_le_bytes)
}

fn array_at<const N: usize>(bytes: &[u8], offset: usize) -> Option<[u8; N]> {
    let end = offset.checked_add(N)?;
    bytes.get(offset..end)?.try_into().ok()
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn supervisor_receive_bytes() -> Option<usize> {
    size_of::<MachMsgHeader>()
        .checked_add(MAX_SUPERVISOR_RECORD_BYTES)
        .and_then(round_mach_message)
        .and_then(|size| size.checked_add(size_of::<AuditTrailer>()))
}

/// Removes only Darwin's mandatory zero alignment bytes from one inline
/// supervisor record. The embedded protocol length remains the authenticated
/// logical length; inconsistent or nonzero padding is never normalized.
fn exact_logical_supervisor_record(bytes: &[u8]) -> Option<&[u8]> {
    if bytes.len() < super::HEADER_LEN {
        return None;
    }
    let payload_len = usize::try_from(super::u32_at(bytes, 12).ok()?).ok()?;
    let logical_len = super::HEADER_LEN.checked_add(payload_len)?;
    if logical_len > MAX_SUPERVISOR_RECORD_BYTES
        || round_mach_message(logical_len)? != bytes.len()
        || bytes
            .get(logical_len..)?
            .iter()
            .any(|padding| *padding != 0)
    {
        return None;
    }
    bytes.get(..logical_len)
}

fn mach_receive_timeout(deadline: SupervisorDeadline) -> Result<u32, SupervisorWireError> {
    let local_deadline = deadline.to_local_instant()?;
    let remaining = local_deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(SupervisorWireError::LimitExceeded);
    }
    Ok(remaining
        .as_nanos()
        .div_ceil(1_000_000)
        .min(u128::from(u32::MAX)) as u32)
}

fn round_mach_message(size: usize) -> Option<usize> {
    size.checked_add(size_of::<u32>() - 1)
        .map(|value| value & !(size_of::<u32>() - 1))
}

fn read_wire<T: Copy>(bytes: &[u8], offset: usize) -> Option<T> {
    let end = offset.checked_add(size_of::<T>())?;
    (end <= bytes.len()).then(|| {
        // SAFETY: the complete range is in bounds and unaligned reads support
        // the kernel's naturally aligned Mach message/trailer wire layout.
        unsafe { bytes.as_ptr().add(offset).cast::<T>().read_unaligned() }
    })
}

fn words_as_bytes_mut(words: &mut [u64]) -> &mut [u8] {
    // SAFETY: a u64 slice is contiguous initialized storage; byte access spans
    // exactly the same allocation and preserves its natural alignment.
    unsafe { core::slice::from_raw_parts_mut(words.as_mut_ptr().cast(), size_of_val(words)) }
}

fn destroy_mach_message(bytes: &mut [u8]) {
    // SAFETY: this is either a successfully delivered live Mach message or a
    // recoverable failed send pseudo-received back into the same buffer.
    // libSystem consumes its returned rights and complex resources.
    unsafe { mach_msg_destroy(bytes.as_mut_ptr().cast()) };
}

fn encode_audit_token(token: AuditToken) -> [u8; 32] {
    let mut encoded = [0_u8; 32];
    for (destination, value) in encoded.chunks_exact_mut(4).zip(token.values) {
        destination.copy_from_slice(&value.to_ne_bytes());
    }
    encoded
}

fn frame_digest(raw: &RawMachRecord) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(FRAME_DIGEST_DOMAIN);
    hasher.update(raw.audit_identity);
    hasher.update(raw.effective_uid.to_le_bytes());
    hasher.update(raw.effective_gid.to_le_bytes());
    hasher.update(
        u64::try_from(raw.bytes.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    hasher.update(&raw.bytes);
    hasher.finalize().into()
}

fn last_errno() -> c_int {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(ECHILD)
}

const _: () = assert!(AUTH_WORKER_JOB_BYTES <= DARWIN_PIPE_BUF);
const _: () = assert!(AUTH_WORKER_RESULT_BYTES <= DARWIN_PIPE_BUF);

#[cfg(test)]
#[path = "supervisor_auth_adapter_test.rs"]
mod tests;
