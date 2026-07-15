use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::{process::Command, thread};

use std::io::{Read, Write};
use std::os::fd::FromRawFd;
use std::os::unix::process::ExitStatusExt;

use static_assertions::assert_not_impl_any;

use super::*;
use crate::backend::macos::supervisor::{
    ConnectionGeneration, FreshServiceNonce, InstalledPolicyCatalog, SpawnRequest,
    TargetEnvironmentEntry, TargetPolicyDefinition, encode_client_hello, encode_spawn_request,
};
use crate::backend::macos::supervisor_watchdog::{ReapedBroker, TerminationReason};

const MACH_PORT_RIGHT_RECEIVE: c_int = 1;
const MACH_MSG_TYPE_COPY_SEND: u32 = 19;
const MACH_MSG_TYPE_MOVE_RECEIVE: u8 = 16;
const MACH_MSG_TYPE_MAKE_SEND: c_int = 20;
const MACH_MSG_TYPE_MAKE_SEND_ONCE: u32 = 21;
const MACH_SEND_MSG: u32 = 1;
const MACH_MSG_PORT_DESCRIPTOR: u8 = 0;
const MACH_NOTIFY_SEND_ONCE: c_int = 0o107;
const MACH_PORT_TYPE_DEAD_NAME: u32 = 1 << 20;
const MACH_PORT_TYPE_RECEIVE: u32 = 1 << 17;
const MACH_PORT_TYPE_SEND: u32 = 1 << 16;
const MACH_PORT_TYPE_SEND_ONCE: u32 = 1 << 18;

unsafe extern "C" {
    fn fcntl(fd: c_int, command: c_int, ...) -> c_int;
    fn mach_port_allocate(task: MachPort, right: c_int, name: *mut MachPort) -> c_int;
    fn mach_port_insert_right(
        task: MachPort,
        name: MachPort,
        poly: MachPort,
        disposition: c_int,
    ) -> c_int;
    fn mach_port_extract_right(
        task: MachPort,
        name: MachPort,
        disposition: u32,
        extracted: *mut MachPort,
        extracted_type: *mut u32,
    ) -> c_int;
    fn mach_port_mod_refs(task: MachPort, name: MachPort, right: c_int, delta: c_int) -> c_int;
    fn mach_port_type(task: MachPort, name: MachPort, port_type: *mut u32) -> c_int;
    fn mach_port_get_attributes(
        task: MachPort,
        name: MachPort,
        flavor: c_int,
        info: *mut c_int,
        count: *mut u32,
    ) -> c_int;
    fn geteuid() -> u32;
    fn getegid() -> u32;
    fn pipe(fds: *mut c_int) -> c_int;
}

const MACH_PORT_RECEIVE_STATUS: c_int = 2;
const F_SETFD: c_int = 2;
const F_GETFL: c_int = 3;
const F_SETFL: c_int = 4;
const F_SETNOSIGPIPE: c_int = 73;
const FD_CLOEXEC: c_int = 1;
const O_NONBLOCK: c_int = 4;
const EPIPE: c_int = 32;

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct MachPortStatus {
    port_sets: u32,
    sequence: u32,
    make_send_count: u32,
    queue_limit: u32,
    message_count: u32,
    send_once_rights: u32,
    send_rights_present: u32,
    port_deleted_request: u32,
    no_senders_request: u32,
    flags: u32,
}

const AUDIT_IDENTITY: [u8; 32] = [0x11; 32];
const CLIENT_CODE_IDENTITY: [u8; 32] = [0x22; 32];
const CLIENT_NONCE: [u8; 32] = [0x33; 32];
const SERVICE_NONCE: [u8; 32] = [0x44; 32];
const TARGET_CODE_IDENTITY: [u8; 32] = [0x77; 32];

#[derive(Default)]
struct ReadyBrokerState {
    normal_attempts: usize,
    emergency_attempts: usize,
    emergency_reason: Option<TerminationReason>,
}

struct ReadyBroker {
    state: Arc<Mutex<ReadyBrokerState>>,
}

// SAFETY: this fake retains one modeled exact broker and mints reap proof only
// after its corresponding modeled cleanup action completes.
unsafe impl ExactBrokerAuthority for ReadyBroker {
    type Failure = ();

    fn activate_after_registration(&mut self) -> Result<(), Self::Failure> {
        Ok(())
    }

    fn terminate_and_reap(
        &mut self,
        _reason: TerminationReason,
    ) -> Result<ReapedBroker, Self::Failure> {
        self.state.lock().unwrap().normal_attempts += 1;
        // SAFETY: the fake models exact normal reap completion.
        Ok(unsafe { ReapedBroker::from_exact_reap() })
    }

    fn emergency_terminate_and_reap(&mut self, reason: Option<TerminationReason>) -> ReapedBroker {
        let mut state = self.state.lock().unwrap();
        state.emergency_attempts += 1;
        state.emergency_reason = reason;
        // SAFETY: the fake models exact emergency reap completion.
        unsafe { ReapedBroker::from_exact_reap() }
    }
}

assert_not_impl_any!(FreshAuthWorkerGeneration: Clone, Copy);
assert_not_impl_any!(FreshAuthJobId: Clone, Copy);
assert_not_impl_any!(AuthenticatedMachRecord: Clone, Copy);
assert_not_impl_any!(AuthWorkerReplyReceipt: Clone, Copy);
assert_not_impl_any!(DispatchedAuthJob: Clone, Copy);
assert_not_impl_any!(ReceivedAuthWorkerResult: Clone, Copy);
assert_not_impl_any!(MachSendOnceRight: Clone, Copy);

struct TestReceiveRight {
    name: MachPort,
    send_reference: bool,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct MachMsgPortDescriptor {
    name: MachPort,
    pad1: u32,
    pad2: u16,
    disposition: u8,
    descriptor_type: u8,
}

impl TestReceiveRight {
    fn allocate() -> Self {
        let mut name = MACH_PORT_NULL;
        // SAFETY: `name` is writable and the current task is valid.
        assert_eq!(
            unsafe { mach_port_allocate(current_task(), MACH_PORT_RIGHT_RECEIVE, &mut name) },
            0
        );
        assert_ne!(name, MACH_PORT_NULL);
        Self {
            name,
            send_reference: false,
        }
    }

    fn make_send(&mut self) {
        // SAFETY: this object exclusively owns the live receive right.
        assert_eq!(
            unsafe {
                mach_port_insert_right(
                    current_task(),
                    self.name,
                    self.name,
                    MACH_MSG_TYPE_MAKE_SEND,
                )
            },
            0
        );
        self.send_reference = true;
    }

    fn make_send_once(&self) -> MachSendOnceRight {
        let mut extracted = MACH_PORT_NULL;
        let mut extracted_type = 0_u32;
        // SAFETY: this object owns the live receive right and both output
        // pointers are valid for the kernel to mint one send-once reference.
        assert_eq!(
            unsafe {
                mach_port_extract_right(
                    current_task(),
                    self.name,
                    MACH_MSG_TYPE_MAKE_SEND_ONCE,
                    &raw mut extracted,
                    &raw mut extracted_type,
                )
            },
            0
        );
        assert_ne!(extracted, MACH_PORT_NULL);
        assert_eq!(extracted_type, MACH_MSG_TYPE_PORT_SEND_ONCE);
        // SAFETY: the preceding successful insertion created exactly one live
        // send-once right under this name; the returned owner is linear.
        unsafe { MachSendOnceRight::from_test_name(extracted) }
    }

    fn destroy_receive(&mut self) {
        assert!(!self.send_reference);
        // SAFETY: this object owns exactly one live receive-right reference.
        assert_eq!(
            unsafe { mach_port_mod_refs(current_task(), self.name, MACH_PORT_RIGHT_RECEIVE, -1) },
            0
        );
        self.name = MACH_PORT_NULL;
    }

    fn port_type(&self) -> u32 {
        port_type(self.name).unwrap()
    }

    fn send_once_rights(&self) -> u32 {
        let mut status = MachPortStatus::default();
        let mut count = u32::try_from(size_of::<MachPortStatus>() / size_of::<u32>()).unwrap();
        // SAFETY: the status storage and count are writable and correctly sized.
        assert_eq!(
            unsafe {
                mach_port_get_attributes(
                    current_task(),
                    self.name,
                    MACH_PORT_RECEIVE_STATUS,
                    (&raw mut status).cast(),
                    &raw mut count,
                )
            },
            0
        );
        assert_eq!(
            count as usize,
            size_of::<MachPortStatus>() / size_of::<u32>()
        );
        status.send_once_rights
    }
}

fn port_type(name: MachPort) -> Result<u32, c_int> {
    let mut port_type = 0;
    // SAFETY: `port_type` is writable; the kernel validates `name`.
    let status = unsafe { mach_port_type(current_task(), name, &mut port_type) };
    if status == 0 {
        Ok(port_type)
    } else {
        Err(status)
    }
}

impl Drop for TestReceiveRight {
    fn drop(&mut self) {
        if self.send_reference {
            deallocate_port(current_task(), self.name);
        }
        // SAFETY: this object still owns exactly one receive-right reference.
        let _ =
            unsafe { mach_port_mod_refs(current_task(), self.name, MACH_PORT_RIGHT_RECEIVE, -1) };
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FakeFailure {
    LostWaitAuthority,
}

#[derive(Default)]
struct FakeState {
    result_reaps: usize,
    terminations: usize,
    emergency_cleanups: usize,
    fail_next: bool,
    reap_pending_once: bool,
    termination_pending_once: bool,
    result_wait_status: c_int,
}

struct FakeAuthority {
    state: Arc<Mutex<FakeState>>,
}

unsafe impl ExactAuthWorkerAuthority for FakeAuthority {
    type Failure = FakeFailure;

    fn try_reap_after_result(&mut self) -> Result<Option<ReapedAuthWorker>, Self::Failure> {
        let mut state = self.state.lock().unwrap();
        if std::mem::take(&mut state.fail_next) {
            return Err(FakeFailure::LostWaitAuthority);
        }
        if std::mem::take(&mut state.reap_pending_once) {
            return Ok(None);
        }
        state.result_reaps += 1;
        // SAFETY: the fake models exact reap by the sole worker waiter.
        // SAFETY: the fake models an exact wait returning this controlled
        // status from the sole worker waiter.
        Ok(Some(unsafe {
            ReapedAuthWorker::from_exact_wait_status(state.result_wait_status)
        }))
    }

    fn try_terminate_and_reap(&mut self) -> Result<Option<ReapedAuthWorker>, Self::Failure> {
        let mut state = self.state.lock().unwrap();
        if std::mem::take(&mut state.fail_next) {
            return Err(FakeFailure::LostWaitAuthority);
        }
        if std::mem::take(&mut state.termination_pending_once) {
            return Ok(None);
        }
        state.terminations += 1;
        // SAFETY: the fake models exact termination and reap under retained
        // unreaped direct-child authority.
        // SAFETY: the fake models exact termination and reap. Status 9 is the
        // Darwin wait status for termination by SIGKILL.
        Ok(Some(unsafe {
            ReapedAuthWorker::from_exact_wait_status(SIGKILL)
        }))
    }

    fn emergency_terminate_and_reap(&mut self) -> ReapedAuthWorker {
        self.state.lock().unwrap().emergency_cleanups += 1;
        // SAFETY: the fake emergency path models exact terminate and reap.
        unsafe { ReapedAuthWorker::from_exact_wait_status(SIGKILL) }
    }
}

fn worker(
    generation: u64,
) -> (
    FreshAuthWorkerGeneration,
    ExactAuthWorker<FakeAuthority>,
    Arc<Mutex<FakeState>>,
) {
    let state = Arc::new(Mutex::new(FakeState::default()));
    // SAFETY: test generations are unique and nonzero within each pool.
    let generation = unsafe {
        FreshAuthWorkerGeneration::from_unique_service_value(generation)
            .map_err(|error| match error {
                AuthAdapterError::InvalidReplacement => (),
                _ => unreachable!(),
            })
            .unwrap()
    };
    // SAFETY: each fake owns one modeled exact unreaped worker.
    let exact = unsafe {
        ExactAuthWorker::from_test_unreaped_direct_child(FakeAuthority {
            state: Arc::clone(&state),
        })
    };
    (generation, exact, state)
}

struct TestWorkerPipePeer {
    request: OwnedFd,
    result: OwnedFd,
}

fn test_worker_endpoint_pair() -> (AuthWorkerEndpoint, TestWorkerPipePeer) {
    let mut request = [-1; 2];
    let mut result = [-1; 2];
    // SAFETY: both arrays provide storage for exactly two descriptors.
    assert_eq!(unsafe { pipe(request.as_mut_ptr()) }, 0);
    // SAFETY: both arrays provide storage for exactly two descriptors.
    assert_eq!(unsafe { pipe(result.as_mut_ptr()) }, 0);
    // SAFETY: each nonnegative descriptor is newly owned exactly once below.
    let request_read = unsafe { OwnedFd::from_raw_fd(request[0]) };
    // SAFETY: see above.
    let request_write = unsafe { OwnedFd::from_raw_fd(request[1]) };
    // SAFETY: see above.
    let result_read = unsafe { OwnedFd::from_raw_fd(result[0]) };
    // SAFETY: see above.
    let result_write = unsafe { OwnedFd::from_raw_fd(result[1]) };
    for fd in [&request_read, &request_write, &result_read, &result_write] {
        // SAFETY: each descriptor is live; fcntl does not consume it.
        assert_eq!(unsafe { fcntl(fd.as_raw_fd(), F_SETFD, FD_CLOEXEC) }, 0);
    }
    for fd in [&request_write, &result_read] {
        // SAFETY: F_GETFL has no variadic argument and preserves ownership.
        let flags = unsafe { fcntl(fd.as_raw_fd(), F_GETFL) };
        assert!(flags >= 0);
        // SAFETY: F_SETFL updates status flags without consuming the fd.
        assert_eq!(
            unsafe { fcntl(fd.as_raw_fd(), F_SETFL, flags | O_NONBLOCK) },
            0
        );
    }
    // SAFETY: this write end is live and remains owned by the parent endpoint.
    assert_eq!(
        unsafe { fcntl(request_write.as_raw_fd(), F_SETNOSIGPIPE, 1) },
        0
    );
    // SAFETY: the configured ends satisfy the private one-worker endpoint
    // contract and the peer ends remain isolated in this test object.
    let endpoint =
        unsafe { AuthWorkerEndpoint::from_private_parent_pipe_ends(request_write, result_read) };
    (
        endpoint,
        TestWorkerPipePeer {
            request: request_read,
            result: result_write,
        },
    )
}

fn test_worker_endpoint() -> AuthWorkerEndpoint {
    let (endpoint, peer) = test_worker_endpoint_pair();
    drop(peer);
    endpoint
}

fn test_receipt(worker: AuthWorkerIdentity, job_id: [u8; 32]) -> AuthWorkerReplyReceipt {
    let endpoint = test_worker_endpoint();
    drop(endpoint.request);
    AuthWorkerReplyReceipt {
        worker,
        job_id,
        result: endpoint.result,
        deadline: deadline_after(Duration::from_secs(5)),
        bytes: [0; AUTH_WORKER_RESULT_BYTES],
        filled: 0,
    }
}

fn pool(generations: &[u64]) -> (AuthWorkerPool<FakeAuthority>, Vec<Arc<Mutex<FakeState>>>) {
    let mut states = Vec::new();
    let workers = generations
        .iter()
        .copied()
        .map(|generation| {
            let (generation, worker, state) = worker(generation);
            states.push(state);
            (generation, worker, test_worker_endpoint())
        })
        .collect();
    (
        AuthWorkerPool::from_test_precreated_workers(workers).unwrap(),
        states,
    )
}

fn connection(generation: u64) -> SupervisorConnection {
    // SAFETY: each test supplies a unique nonzero connection generation.
    let generation =
        unsafe { ConnectionGeneration::from_unique_service_value(generation).unwrap() };
    let nonce = service_nonce(generation.0);
    // SAFETY: each test connection uses a distinct nonzero nonce.
    let nonce = unsafe { FreshServiceNonce::from_fresh_random(nonce).unwrap() };
    SupervisorConnection::new(generation, nonce)
}

fn service_nonce(generation: u64) -> [u8; 32] {
    let mut nonce = SERVICE_NONCE;
    nonce[..8].copy_from_slice(&generation.to_le_bytes());
    nonce
}

fn raw(audit_identity: [u8; 32], effective_uid: u32, bytes: Vec<u8>) -> RawMachRecord {
    // SAFETY: tests model bytes and all identity facts from one exact message.
    unsafe {
        RawMachRecord::from_test_exact_audit_trailer(audit_identity, effective_uid, 20, bytes)
    }
}

fn accept_client_hello(
    authenticated: AuthenticatedMachRecord,
    generation: u64,
) -> (SupervisorConnection, AuthenticatedMachRequest<Vec<u8>>) {
    // SAFETY: each test supplies a unique nonzero connection generation.
    let generation =
        unsafe { ConnectionGeneration::from_unique_service_value(generation).unwrap() };
    // SAFETY: each test connection uses a distinct nonzero nonce.
    let nonce =
        unsafe { FreshServiceNonce::from_fresh_random(service_nonce(generation.0)).unwrap() };
    let AuthenticatedMachRoute::ClientHello(hello) = authenticated.route().unwrap() else {
        panic!("authenticated record was not a client hello")
    };
    hello.accept(generation, nonce).unwrap()
}

fn accepted_spawn_reply(
    generation: u64,
) -> (
    PendingSpawnReply<AuthenticatedSpawnRequest>,
    ConnectionIdentity,
) {
    let (mut pool, _states) = pool(&[generation + 10, generation + 11]);
    let (hello_job, hello_receipt) = pool
        .dispatch(
            raw(
                AUDIT_IDENTITY,
                501,
                encode_client_hello(CLIENT_NONCE).unwrap(),
            ),
            job_id(0xa1),
            deadline_after(Duration::from_secs(5)),
        )
        .unwrap()
        .into_parts();
    let authenticated = pool
        .complete(received_result(hello_receipt, validated_result(hello_job)))
        .unwrap();
    let (mut connection, _hello_reply) = accept_client_hello(authenticated, generation);
    let owner = connection.connection_identity();
    let request = SpawnRequest::new(
        deadline_after(Duration::from_secs(5)),
        b"com.example.receiver".to_vec(),
        vec![b"--mode=test".to_vec()],
        vec![TargetEnvironmentEntry::new(b"LANG".to_vec(), b"C".to_vec()).unwrap()],
    )
    .unwrap();
    let bytes = encode_spawn_request(
        &request,
        owner.get(),
        CLIENT_NONCE,
        service_nonce(generation),
    )
    .unwrap();
    let (spawn_job, spawn_receipt) = pool
        .dispatch(
            raw(AUDIT_IDENTITY, 501, bytes),
            job_id(0xa2),
            deadline_after(Duration::from_secs(5)),
        )
        .unwrap()
        .into_parts();
    let authenticated = pool
        .complete(received_result(spawn_receipt, validated_result(spawn_job)))
        .unwrap();
    let AuthenticatedMachRoute::Spawn(spawn) = authenticated.route().unwrap() else {
        panic!("authenticated record was not a spawn")
    };
    let pending = spawn.accept(&mut connection).unwrap();
    (pending, owner)
}

fn replace_spawn_reply<Output>(
    pending: PendingSpawnReply<Output>,
    reply: MachSendOnceRight,
) -> PendingSpawnReply<Output> {
    let (old_reply, freshness, bound_session, output) = pending.into_parts();
    drop(old_reply);
    PendingSpawnReply {
        reply,
        freshness,
        bound_session,
        output,
    }
}

fn installed_catalog() -> InstalledPolicyCatalog {
    let definition = TargetPolicyDefinition::new(
        b"com.example.receiver".to_vec(),
        CLIENT_CODE_IDENTITY,
        TARGET_CODE_IDENTITY,
        b"/Library/PrivilegedHelperTools/com.example.receiver".to_vec(),
        b"receiver".to_vec(),
        4,
        vec![b"LANG".to_vec()],
    )
    .unwrap();
    // SAFETY: this test models one immutable root-owned installed catalog.
    unsafe { InstalledPolicyCatalog::from_verified_installation(vec![definition]).unwrap() }
}

fn job_id(value: u8) -> FreshAuthJobId {
    let mut bytes = [value; 32];
    bytes[0] = value.max(1);
    // SAFETY: test values are nonzero and callers avoid reuse unless testing it.
    unsafe { FreshAuthJobId::from_fresh_random(bytes).unwrap() }
}

fn deadline_after(duration: Duration) -> SupervisorDeadline {
    SupervisorDeadline::from_instant(Instant::now() + duration).unwrap()
}

#[test]
fn authentication_deadline_is_the_earlier_wire_deadline_or_service_cap() {
    let connection = connection(0x4141);
    let wire_deadline = deadline_after(Duration::from_secs(2));
    let later_cap = deadline_after(Duration::from_secs(5));
    let request = SpawnRequest::new(
        wire_deadline,
        b"com.example.receiver".to_vec(),
        vec![b"--mode=test".to_vec()],
        vec![TargetEnvironmentEntry::new(b"LANG".to_vec(), b"C".to_vec()).unwrap()],
    )
    .unwrap();
    let spawn = raw(
        AUDIT_IDENTITY,
        501,
        encode_spawn_request(
            &request,
            connection.connection_identity().get(),
            CLIENT_NONCE,
            service_nonce(0x4141),
        )
        .unwrap(),
    );
    assert_eq!(
        spawn.authentication_deadline(later_cap).unwrap(),
        wire_deadline
    );

    let earlier_cap = deadline_after(Duration::from_millis(250));
    assert_eq!(
        spawn.authentication_deadline(earlier_cap).unwrap(),
        earlier_cap
    );

    let hello = raw(
        AUDIT_IDENTITY,
        501,
        encode_client_hello(CLIENT_NONCE).unwrap(),
    );
    assert_eq!(
        hello.authentication_deadline(earlier_cap).unwrap(),
        earlier_cap
    );
}

#[test]
fn expired_or_short_spawn_deadline_rejects_before_authentication_dispatch() {
    let connection = connection(0x4242);
    let request = SpawnRequest::new(
        deadline_after(Duration::from_secs(2)),
        b"com.example.receiver".to_vec(),
        vec![b"--mode=test".to_vec()],
        vec![TargetEnvironmentEntry::new(b"LANG".to_vec(), b"C".to_vec()).unwrap()],
    )
    .unwrap();
    let mut bytes = encode_spawn_request(
        &request,
        connection.connection_identity().get(),
        CLIENT_NONCE,
        service_nonce(0x4242),
    )
    .unwrap();
    bytes[super::super::HEADER_LEN..super::super::HEADER_LEN + size_of::<u64>()]
        .copy_from_slice(&0_u64.to_le_bytes());
    assert_eq!(
        raw(AUDIT_IDENTITY, 501, bytes)
            .authentication_deadline(deadline_after(Duration::from_secs(5))),
        Err(SupervisorWireError::LimitExceeded)
    );

    let mut short = encode_spawn_request(
        &request,
        connection.connection_identity().get(),
        CLIENT_NONCE,
        service_nonce(0x4242),
    )
    .unwrap();
    short.truncate(super::super::HEADER_LEN + size_of::<u64>());
    short[12..16].copy_from_slice(&(size_of::<u64>() as u32).to_le_bytes());
    assert_eq!(
        raw(AUDIT_IDENTITY, 501, short)
            .authentication_deadline(deadline_after(Duration::from_secs(5))),
        Err(SupervisorWireError::Malformed)
    );
}

#[test]
fn darwin_alignment_normalization_accepts_only_exact_zero_padding() {
    let connection = connection(0x4343);
    let request = SpawnRequest::new(
        deadline_after(Duration::from_secs(2)),
        b"com.example.receiver".to_vec(),
        vec![b"--mode=test".to_vec()],
        vec![TargetEnvironmentEntry::new(b"LANG".to_vec(), b"C".to_vec()).unwrap()],
    )
    .unwrap();
    let logical = encode_spawn_request(
        &request,
        connection.connection_identity().get(),
        CLIENT_NONCE,
        service_nonce(0x4343),
    )
    .unwrap();
    assert_ne!(logical.len() % size_of::<u32>(), 0);
    let mut padded = logical.clone();
    padded.resize(round_mach_message(logical.len()).unwrap(), 0);
    assert_eq!(
        exact_logical_supervisor_record(&padded),
        Some(logical.as_slice())
    );

    *padded.last_mut().unwrap() = 1;
    assert_eq!(exact_logical_supervisor_record(&padded), None);
    *padded.last_mut().unwrap() = 0;
    padded[12..16].copy_from_slice(&u32::MAX.to_le_bytes());
    assert_eq!(exact_logical_supervisor_record(&padded), None);
}

fn validated_result(job: AuthWorkerJob) -> AuthWorkerResult {
    // SAFETY: tests model successful Security validation on the assigned
    // worker's private endpoint.
    unsafe { AuthWorkerResult::from_test_security_validation(job, CLIENT_CODE_IDENTITY) }
}

fn received_result(
    receipt: AuthWorkerReplyReceipt,
    result: AuthWorkerResult,
) -> ReceivedAuthWorkerResult {
    let bytes = result.encode_pipe_frame().unwrap();
    // SAFETY: this complete frame models a read from the consumed receipt's
    // exact private worker endpoint.
    unsafe { ReceivedAuthWorkerResult::from_test_private_pipe(receipt, &bytes).unwrap() }
}

fn send_supervisor_request(
    destination: MachPort,
    reply: MachPort,
    payload: &[u8],
) -> MachMsgReturn {
    send_inline_request(destination, reply, SUPERVISOR_MESSAGE_ID, payload)
}

fn send_inline_request(
    destination: MachPort,
    reply: MachPort,
    message_id: c_int,
    payload: &[u8],
) -> MachMsgReturn {
    let message_size = size_of::<MachMsgHeader>() + payload.len();
    let mut storage = vec![0_u64; message_size.div_ceil(size_of::<u64>())];
    let bytes = words_as_bytes_mut(&mut storage);
    let header = MachMsgHeader {
        bits: MACH_MSG_TYPE_COPY_SEND | (MACH_MSG_TYPE_MAKE_SEND_ONCE << 8),
        size: u32::try_from(message_size).unwrap(),
        remote_port: destination,
        local_port: reply,
        voucher_port: MACH_PORT_NULL,
        id: message_id,
    };
    // SAFETY: storage has room for the complete header and payload.
    unsafe { bytes.as_mut_ptr().cast::<MachMsgHeader>().write(header) };
    bytes[size_of::<MachMsgHeader>()..message_size].copy_from_slice(payload);
    // SAFETY: storage contains one complete initialized inline Mach message.
    unsafe {
        mach_msg(
            bytes.as_mut_ptr().cast(),
            MACH_SEND_MSG,
            u32::try_from(round_mach_message(message_size).unwrap()).unwrap(),
            0,
            MACH_PORT_NULL,
            0,
            MACH_PORT_NULL,
        )
    }
}

fn send_complex_receive_right(
    destination: MachPort,
    reply: MachPort,
    transferred_receive_right: MachPort,
) -> MachMsgReturn {
    let body_offset = size_of::<MachMsgHeader>();
    let descriptor_offset = body_offset + size_of::<u32>();
    let message_size = descriptor_offset + size_of::<MachMsgPortDescriptor>();
    let mut storage = vec![0_u64; message_size.div_ceil(size_of::<u64>())];
    let bytes = words_as_bytes_mut(&mut storage);
    let header = MachMsgHeader {
        bits: MACH_MSGH_BITS_COMPLEX
            | MACH_MSG_TYPE_COPY_SEND
            | (MACH_MSG_TYPE_MAKE_SEND_ONCE << 8),
        size: u32::try_from(message_size).unwrap(),
        remote_port: destination,
        local_port: reply,
        voucher_port: MACH_PORT_NULL,
        id: SUPERVISOR_MESSAGE_ID,
    };
    let descriptor = MachMsgPortDescriptor {
        name: transferred_receive_right,
        pad1: 0,
        pad2: 0,
        disposition: MACH_MSG_TYPE_MOVE_RECEIVE,
        descriptor_type: MACH_MSG_PORT_DESCRIPTOR,
    };
    // SAFETY: storage has room for the header, body count, and descriptor.
    unsafe {
        bytes.as_mut_ptr().cast::<MachMsgHeader>().write(header);
        bytes.as_mut_ptr().add(body_offset).cast::<u32>().write(1);
        bytes
            .as_mut_ptr()
            .add(descriptor_offset)
            .cast::<MachMsgPortDescriptor>()
            .write(descriptor);
        mach_msg(
            bytes.as_mut_ptr().cast(),
            MACH_SEND_MSG,
            u32::try_from(message_size).unwrap(),
            0,
            MACH_PORT_NULL,
            0,
            MACH_PORT_NULL,
        )
    }
}

fn receive_inline_message(receive_port: MachPort) -> (MachMsgHeader, Vec<u8>) {
    let receive_limit = size_of::<MachMsgHeader>() + MAX_SUPERVISOR_RECORD_BYTES;
    let mut storage = vec![0_u64; receive_limit.div_ceil(size_of::<u64>())];
    let bytes = words_as_bytes_mut(&mut storage);
    // SAFETY: the aligned initialized buffer is large enough for a full reply.
    assert_eq!(
        unsafe {
            mach_msg(
                bytes.as_mut_ptr().cast(),
                MACH_RCV_MSG | MACH_RCV_TIMEOUT | MACH_RCV_INTERRUPT,
                0,
                u32::try_from(receive_limit).unwrap(),
                receive_port,
                1_000,
                MACH_PORT_NULL,
            )
        },
        0
    );
    let header = read_wire::<MachMsgHeader>(bytes, 0).unwrap();
    let message_size = header.size as usize;
    assert_eq!(header.local_port, receive_port);
    assert!(message_size >= size_of::<MachMsgHeader>());
    (
        header,
        bytes[size_of::<MachMsgHeader>()..message_size].to_vec(),
    )
}

fn receive_send_once_destroyed(receive_port: MachPort) {
    let (header, payload) = receive_inline_message(receive_port);
    assert_eq!(header.id, MACH_NOTIFY_SEND_ONCE);
    assert!(payload.is_empty());
}

#[test]
fn raw_mach_receive_fuses_exact_kernel_audit_and_linear_reply_right() {
    assert_eq!(size_of::<MachMsgHeader>(), 24);
    assert_eq!(size_of::<AuditToken>(), 32);
    assert_eq!(size_of::<AuditTrailer>(), 52);

    let mut service = TestReceiveRight::allocate();
    service.make_send();
    let reply = TestReceiveRight::allocate();
    let hello = encode_client_hello(CLIENT_NONCE).unwrap();
    assert_eq!(send_supervisor_request(service.name, reply.name, &hello), 0);
    assert_eq!(reply.send_once_rights(), 1);

    let (mut pool, states) = pool(&[80]);
    // SAFETY: this test is the sole receiver and keeps the checked-in-model
    // receive right alive for the receiver's complete lifetime.
    let mut receiver =
        unsafe { RawMachReceiver::from_borrowed_launchd_receive_right(service.name).unwrap() };
    let (job, receipt) = receiver
        .receive_and_dispatch_capped(
            job_id(80),
            deadline_after(Duration::from_secs(5)),
            deadline_after(Duration::from_secs(4)),
            &mut pool,
        )
        .unwrap()
        .into_parts();
    assert_ne!(job.audit_identity(), [0; 32]);
    assert_ne!(job.frame_digest(), [0; 32]);
    // SAFETY: libc identity getters have no preconditions.
    assert_eq!(job.effective_uid(), unsafe { geteuid() });
    // SAFETY: libc identity getters have no preconditions.
    assert_eq!(job.effective_gid(), unsafe { getegid() });
    let authenticated = pool
        .complete(received_result(receipt, validated_result(job)))
        .unwrap();
    assert_eq!(states[0].lock().unwrap().result_reaps, 1);
    let (_connection, request) = accept_client_hello(authenticated, 79);
    assert_eq!(reply.send_once_rights(), 1);
    request.send_reply().unwrap();
    let (reply_header, response) = receive_inline_message(reply.name);
    assert_eq!(reply_header.id, SUPERVISOR_MESSAGE_ID);
    assert_eq!(reply.send_once_rights(), 0);
    assert!(!response.is_empty());
    assert_ne!(reply.port_type() & MACH_PORT_TYPE_RECEIVE, 0);
}

#[test]
fn native_spawn_receive_dispatches_only_under_minimum_deadline_and_drops_rejections() {
    for (wire_duration, cap_duration, expected_wire) in [
        (Duration::from_millis(500), Duration::from_secs(2), true),
        (Duration::from_secs(2), Duration::from_millis(500), false),
    ] {
        let mut service = TestReceiveRight::allocate();
        service.make_send();
        let reply = TestReceiveRight::allocate();
        let wire_deadline = deadline_after(wire_duration);
        let auth_cap = deadline_after(cap_duration);
        let request = SpawnRequest::new(
            wire_deadline,
            b"com.example.receiver".to_vec(),
            vec![b"--mode=test".to_vec()],
            vec![TargetEnvironmentEntry::new(b"LANG".to_vec(), b"C".to_vec()).unwrap()],
        )
        .unwrap();
        let bytes =
            encode_spawn_request(&request, 0x5151, CLIENT_NONCE, service_nonce(0x5151)).unwrap();
        assert_eq!(send_supervisor_request(service.name, reply.name, &bytes), 0);

        let (mut pool, states) = pool(&[0x5151]);
        // SAFETY: this test is the sole receiver and retains the live right.
        let mut receiver =
            unsafe { RawMachReceiver::from_borrowed_launchd_receive_right(service.name).unwrap() };
        let dispatched = receiver
            .receive_and_dispatch_capped(
                job_id(if expected_wire { 0x51 } else { 0x52 }),
                deadline_after(Duration::from_secs(2)),
                auth_cap,
                &mut pool,
            )
            .unwrap();
        let worker = dispatched.worker();
        let (job, receipt) = dispatched.into_parts();
        assert_eq!(
            job.deadline(),
            if expected_wire {
                wire_deadline.wire_value()
            } else {
                auth_cap.wire_value()
            }
        );
        drop(receipt);
        pool.cancel(worker).unwrap();
        assert_eq!(states[0].lock().unwrap().terminations, 1);
        receive_send_once_destroyed(reply.name);
    }

    let mut service = TestReceiveRight::allocate();
    service.make_send();
    let reply = TestReceiveRight::allocate();
    let request = SpawnRequest::new(
        deadline_after(Duration::from_secs(2)),
        b"com.example.receiver".to_vec(),
        Vec::new(),
        Vec::new(),
    )
    .unwrap();
    let mut bytes =
        encode_spawn_request(&request, 0x5252, CLIENT_NONCE, service_nonce(0x5252)).unwrap();
    bytes[super::super::HEADER_LEN..super::super::HEADER_LEN + size_of::<u64>()]
        .copy_from_slice(&0_u64.to_le_bytes());
    assert_eq!(send_supervisor_request(service.name, reply.name, &bytes), 0);
    let (mut pool, states) = pool(&[0x5252]);
    // SAFETY: this test is the sole receiver and retains the live right.
    let mut receiver =
        unsafe { RawMachReceiver::from_borrowed_launchd_receive_right(service.name).unwrap() };
    assert!(matches!(
        receiver.receive_and_dispatch_capped(
            job_id(0x53),
            deadline_after(Duration::from_secs(2)),
            deadline_after(Duration::from_secs(2)),
            &mut pool,
        ),
        Err(AuthAdapterError::Protocol(
            SupervisorWireError::LimitExceeded
        ))
    ));
    assert!(pool.slots[0].as_ref().unwrap().pending.is_none());
    assert_eq!(states[0].lock().unwrap().terminations, 0);
    receive_send_once_destroyed(reply.name);
}

#[test]
fn raw_mach_receive_destroys_malformed_reply_and_preserves_queue_progress() {
    let mut service = TestReceiveRight::allocate();
    service.make_send();
    let malformed_reply = TestReceiveRight::allocate();
    let valid_reply = TestReceiveRight::allocate();
    let hello = encode_client_hello(CLIENT_NONCE).unwrap();
    assert_eq!(
        send_inline_request(
            service.name,
            malformed_reply.name,
            SUPERVISOR_MESSAGE_ID + 1,
            &hello,
        ),
        0
    );
    assert_eq!(malformed_reply.send_once_rights(), 1);

    let (mut pool, _states) = pool(&[85]);
    // SAFETY: the test is the sole receiver and retains the live receive right.
    let mut receiver =
        unsafe { RawMachReceiver::from_borrowed_launchd_receive_right(service.name).unwrap() };
    assert!(matches!(
        receiver.receive_and_dispatch_capped(
            job_id(85),
            deadline_after(Duration::from_secs(5)),
            deadline_after(Duration::from_secs(5)),
            &mut pool,
        ),
        Err(AuthAdapterError::MalformedMachMessage)
    ));
    receive_send_once_destroyed(malformed_reply.name);
    assert_eq!(malformed_reply.send_once_rights(), 0);
    assert_ne!(malformed_reply.port_type() & MACH_PORT_TYPE_RECEIVE, 0);

    assert_eq!(
        send_supervisor_request(service.name, valid_reply.name, &hello),
        0
    );
    let (job, receipt) = receiver
        .receive_and_dispatch_capped(
            job_id(86),
            deadline_after(Duration::from_secs(5)),
            deadline_after(Duration::from_secs(5)),
            &mut pool,
        )
        .unwrap()
        .into_parts();
    let authenticated = pool
        .complete(received_result(receipt, validated_result(job)))
        .unwrap();
    let (_connection, request) = accept_client_hello(authenticated, 84);
    let (reply_right, response) = request.into_parts();
    assert!(!response.is_empty());
    drop(reply_right);
}

#[test]
fn raw_mach_receive_immediately_destroys_complex_transferred_rights() {
    let mut service = TestReceiveRight::allocate();
    service.make_send();
    let reply = TestReceiveRight::allocate();
    let mut transferred = TestReceiveRight::allocate();
    transferred.make_send();
    assert_eq!(
        send_complex_receive_right(service.name, reply.name, transferred.name),
        0
    );
    assert_eq!(reply.send_once_rights(), 1);
    let after_send = transferred.port_type();
    assert_eq!(after_send & MACH_PORT_TYPE_RECEIVE, 0);
    assert_ne!(after_send & MACH_PORT_TYPE_SEND, 0);

    let (mut pool, _states) = pool(&[87]);
    // SAFETY: the test is the sole receiver and retains the live receive right.
    let mut receiver =
        unsafe { RawMachReceiver::from_borrowed_launchd_receive_right(service.name).unwrap() };
    assert!(matches!(
        receiver.receive_and_dispatch_capped(
            job_id(87),
            deadline_after(Duration::from_secs(5)),
            deadline_after(Duration::from_secs(5)),
            &mut pool,
        ),
        Err(AuthAdapterError::MalformedMachMessage)
    ));
    receive_send_once_destroyed(reply.name);
    assert_eq!(reply.send_once_rights(), 0);
    assert_ne!(transferred.port_type() & MACH_PORT_TYPE_DEAD_NAME, 0);
    assert_ne!(reply.port_type() & MACH_PORT_TYPE_RECEIVE, 0);
}

#[test]
fn oversized_mach_record_is_destroyed_without_blocking_following_request() {
    let mut service = TestReceiveRight::allocate();
    service.make_send();
    let oversized_reply = TestReceiveRight::allocate();
    let valid_reply = TestReceiveRight::allocate();
    assert_eq!(
        send_supervisor_request(
            service.name,
            oversized_reply.name,
            &vec![0x5a; MAX_SUPERVISOR_RECORD_BYTES + size_of::<u32>()],
        ),
        0
    );
    assert_eq!(oversized_reply.send_once_rights(), 1);

    let (mut pool, _states) = pool(&[88]);
    // SAFETY: the test is the sole receiver and retains the live receive right.
    let mut receiver =
        unsafe { RawMachReceiver::from_borrowed_launchd_receive_right(service.name).unwrap() };
    match receiver.receive_and_dispatch_capped(
        job_id(88),
        deadline_after(Duration::from_secs(5)),
        deadline_after(Duration::from_secs(5)),
        &mut pool,
    ) {
        Err(error) => assert_eq!(error, AuthAdapterError::RecordTooLarge),
        Ok(_) => panic!("oversized record was dispatched"),
    }
    receive_send_once_destroyed(oversized_reply.name);
    assert_eq!(oversized_reply.send_once_rights(), 0);
    assert_ne!(oversized_reply.port_type() & MACH_PORT_TYPE_RECEIVE, 0);

    let hello = encode_client_hello(CLIENT_NONCE).unwrap();
    assert_eq!(
        send_supervisor_request(service.name, valid_reply.name, &hello),
        0
    );
    let (job, receipt) = receiver
        .receive_and_dispatch_capped(
            job_id(89),
            deadline_after(Duration::from_secs(5)),
            deadline_after(Duration::from_secs(5)),
            &mut pool,
        )
        .unwrap()
        .into_parts();
    let authenticated = pool
        .complete(received_result(receipt, validated_result(job)))
        .unwrap();
    let (_connection, request) = accept_client_hello(authenticated, 89);
    let (reply_right, response) = request.into_parts();
    assert!(!response.is_empty());
    drop(reply_right);
}

#[test]
fn raw_mach_receive_obeys_original_empty_queue_deadline() {
    let service = TestReceiveRight::allocate();
    let (mut pool, _states) = pool(&[90]);
    // SAFETY: the test is the sole receiver and retains the live receive right.
    let mut receiver =
        unsafe { RawMachReceiver::from_borrowed_launchd_receive_right(service.name).unwrap() };
    let started = Instant::now();
    assert!(matches!(
        receiver.receive_and_dispatch_capped(
            job_id(90),
            deadline_after(Duration::from_millis(50)),
            deadline_after(Duration::from_secs(5)),
            &mut pool,
        ),
        Err(AuthAdapterError::DeadlineExpired)
    ));
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[test]
fn authenticated_reply_send_handles_dead_and_invalid_destinations() {
    let mut service = TestReceiveRight::allocate();
    service.make_send();
    let mut reply = TestReceiveRight::allocate();
    let hello = encode_client_hello(CLIENT_NONCE).unwrap();
    assert_eq!(send_supervisor_request(service.name, reply.name, &hello), 0);

    let (mut pool, _states) = pool(&[91]);
    // SAFETY: the test is the sole receiver and retains the live receive right.
    let mut receiver =
        unsafe { RawMachReceiver::from_borrowed_launchd_receive_right(service.name).unwrap() };
    let (job, receipt) = receiver
        .receive_and_dispatch_capped(
            job_id(91),
            deadline_after(Duration::from_secs(5)),
            deadline_after(Duration::from_secs(5)),
            &mut pool,
        )
        .unwrap()
        .into_parts();
    let authenticated = pool
        .complete(received_result(receipt, validated_result(job)))
        .unwrap();
    let (_connection, request) = accept_client_hello(authenticated, 91);

    assert_eq!(reply.send_once_rights(), 1);
    let old_receive_name = reply.name;
    reply.destroy_receive();
    let started = Instant::now();
    assert_eq!(request.send_reply(), Ok(()));
    assert!(started.elapsed() < Duration::from_secs(1));

    // SAFETY: this deliberately models a numeric name that became invalid
    // before send, exercising recoverable-send cleanup of the post-call buffer.
    let invalid = unsafe { MachSendOnceRight::from_test_name(old_receive_name) };
    assert_eq!(
        invalid.send(&hello),
        Err(MachReplyError::MachSend(MACH_SEND_INVALID_DEST))
    );
}

#[test]
fn private_pipe_frames_are_fixed_canonical_and_round_trip_exactly() {
    let (mut pool, _states) = pool(&[81]);
    let (job, _receipt) = pool
        .dispatch(
            raw(
                AUDIT_IDENTITY,
                501,
                encode_client_hello(CLIENT_NONCE).unwrap(),
            ),
            job_id(83),
            deadline_after(Duration::from_secs(5)),
        )
        .unwrap()
        .into_parts();

    let encoded_job = job.encode_pipe_frame();
    assert_eq!(encoded_job.len(), AUTH_WORKER_JOB_BYTES);
    assert_eq!(AuthWorkerJob::decode_pipe_frame(&encoded_job), Ok(job));
    assert_eq!(
        &encoded_job[..8],
        &AUTH_WORKER_JOB_MAGIC,
        "job wire identity must not depend on signing or packaging"
    );

    let validated = validated_result(job);
    let encoded_result = validated.encode_pipe_frame().unwrap();
    assert_eq!(encoded_result.len(), AUTH_WORKER_RESULT_BYTES);
    let decoded_result = decode_auth_worker_result(&encoded_result).unwrap();
    assert_eq!(decoded_result.job, job);
    assert_eq!(decoded_result.code_identity, CLIENT_CODE_IDENTITY);

    // SAFETY: zero code identity models the worker's fixed reject decision.
    let rejected = unsafe { AuthWorkerResult::from_test_security_validation(job, [0; 32]) };
    let rejected = decode_auth_worker_result(&rejected.encode_pipe_frame().unwrap()).unwrap();
    assert_eq!(rejected.job, job);
    assert_eq!(rejected.code_identity, [0; 32]);
}

#[test]
fn private_pipe_frames_reject_truncation_extension_reserved_and_identity_errors() {
    let (mut pool, _states) = pool(&[91]);
    let (job, _receipt) = pool
        .dispatch(
            raw(
                AUDIT_IDENTITY,
                501,
                encode_client_hello(CLIENT_NONCE).unwrap(),
            ),
            job_id(93),
            deadline_after(Duration::from_secs(5)),
        )
        .unwrap()
        .into_parts();
    let encoded_job = job.encode_pipe_frame();
    for length in 0..AUTH_WORKER_JOB_BYTES {
        assert!(AuthWorkerJob::decode_pipe_frame(&encoded_job[..length]).is_err());
    }
    let mut extended_job = encoded_job.to_vec();
    extended_job.push(0);
    assert_eq!(
        AuthWorkerJob::decode_pipe_frame(&extended_job),
        Err(AuthWorkerWireError::Malformed)
    );

    for offset in [
        0,
        JOB_VERSION_OFFSET,
        JOB_RESERVED_OFFSET,
        JOB_LENGTH_OFFSET,
        JOB_SLOT_RESERVED_OFFSET,
        JOB_ROUTE_RESERVED_OFFSET,
    ] {
        let mut malformed = encoded_job;
        malformed[offset] ^= 1;
        assert_eq!(
            AuthWorkerJob::decode_pipe_frame(&malformed),
            Err(AuthWorkerWireError::Malformed)
        );
    }

    let mut invalid_slot = encoded_job;
    invalid_slot[JOB_SLOT_OFFSET] = MAX_AUTH_WORKERS as u8;
    assert_eq!(
        AuthWorkerJob::decode_pipe_frame(&invalid_slot),
        Err(AuthWorkerWireError::InvalidIdentity)
    );
    for (offset, length) in [
        (JOB_GENERATION_OFFSET, 8),
        (JOB_ID_OFFSET, 32),
        (JOB_AUDIT_OFFSET, 32),
        (JOB_UID_OFFSET, 4),
        (JOB_GID_OFFSET, 4),
        (JOB_DIGEST_OFFSET, 32),
        (JOB_DEADLINE_OFFSET, 8),
    ] {
        let mut invalid = encoded_job;
        invalid[offset..offset + length].fill(0);
        assert_eq!(
            AuthWorkerJob::decode_pipe_frame(&invalid),
            Err(AuthWorkerWireError::InvalidIdentity)
        );
    }

    let encoded_result = validated_result(job).encode_pipe_frame().unwrap();
    for length in 0..AUTH_WORKER_RESULT_BYTES {
        assert!(decode_auth_worker_result(&encoded_result[..length]).is_err());
    }
    let mut extended_result = encoded_result.to_vec();
    extended_result.push(0);
    assert_eq!(
        decode_auth_worker_result(&extended_result).err(),
        Some(AuthWorkerWireError::Malformed)
    );
    for offset in [0, RESULT_VERSION_OFFSET, RESULT_LENGTH_OFFSET] {
        let mut malformed = encoded_result;
        malformed[offset] ^= 1;
        assert_eq!(
            decode_auth_worker_result(&malformed).err(),
            Some(AuthWorkerWireError::Malformed)
        );
    }
    let mut unknown_decision = encoded_result;
    write_u16(&mut unknown_decision, RESULT_DECISION_OFFSET, u16::MAX);
    assert_eq!(
        decode_auth_worker_result(&unknown_decision).err(),
        Some(AuthWorkerWireError::Malformed)
    );
    let mut validated_without_identity = encoded_result;
    validated_without_identity[RESULT_CODE_IDENTITY_OFFSET..].fill(0);
    assert_eq!(
        decode_auth_worker_result(&validated_without_identity).err(),
        Some(AuthWorkerWireError::InvalidDecision)
    );
    let mut rejected_with_identity = encoded_result;
    write_u16(
        &mut rejected_with_identity,
        RESULT_DECISION_OFFSET,
        AUTH_WORKER_REJECTED,
    );
    assert_eq!(
        decode_auth_worker_result(&rejected_with_identity).err(),
        Some(AuthWorkerWireError::InvalidDecision)
    );
}

#[test]
fn private_pipe_endpoint_submits_once_and_requires_exact_result_eof() {
    let (generation, worker, state) = worker(97);
    let (endpoint, peer) = test_worker_endpoint_pair();
    let mut pool =
        AuthWorkerPool::from_test_precreated_workers(vec![(generation, worker, endpoint)]).unwrap();
    let dispatched = pool
        .dispatch(
            raw(
                AUDIT_IDENTITY,
                501,
                encode_client_hello(CLIENT_NONCE).unwrap(),
            ),
            job_id(98),
            deadline_after(Duration::from_secs(5)),
        )
        .unwrap();
    let job = dispatched.job;
    let receipt = dispatched.submit().unwrap();

    let mut request = Vec::new();
    let mut request_reader = std::fs::File::from(peer.request);
    request_reader.read_to_end(&mut request).unwrap();
    assert_eq!(request, job.encode_pipe_frame());

    let receipt = match receipt.poll().unwrap() {
        AuthWorkerResultPoll::Pending(receipt) => receipt,
        AuthWorkerResultPoll::Complete(_) => unreachable!(),
    };
    let encoded = validated_result(job).encode_pipe_frame().unwrap();
    let mut result_writer = std::fs::File::from(peer.result);
    result_writer.write_all(&encoded).unwrap();
    let receipt = match receipt.poll().unwrap() {
        AuthWorkerResultPoll::Pending(receipt) => receipt,
        AuthWorkerResultPoll::Complete(_) => unreachable!(),
    };
    drop(result_writer);
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut receipt = receipt;
    let received = loop {
        match receipt.poll().unwrap() {
            AuthWorkerResultPoll::Complete(received) => break received,
            AuthWorkerResultPoll::Pending(next) => {
                assert!(Instant::now() < deadline);
                receipt = next;
                thread::yield_now();
            }
        }
    };
    let worker = received.worker();
    state.lock().unwrap().reap_pending_once = true;
    assert_eq!(
        pool.complete(received).err(),
        Some(AuthAdapterError::WorkerRetirementPending(worker))
    );
    assert!(pool.poll_completed(worker).is_ok());
    assert_eq!(state.lock().unwrap().result_reaps, 1);
}

#[test]
fn private_pipe_endpoint_rejects_premature_eof_and_extra_result_bytes() {
    for extra in [false, true] {
        let (generation, worker, _state) = worker(if extra { 100 } else { 99 });
        let (endpoint, peer) = test_worker_endpoint_pair();
        let mut pool =
            AuthWorkerPool::from_test_precreated_workers(vec![(generation, worker, endpoint)])
                .unwrap();
        let dispatched = pool
            .dispatch(
                raw(
                    AUDIT_IDENTITY,
                    501,
                    encode_client_hello(CLIENT_NONCE).unwrap(),
                ),
                job_id(if extra { 100 } else { 99 }),
                deadline_after(Duration::from_secs(5)),
            )
            .unwrap();
        let job = dispatched.job;
        let receipt = dispatched.submit().unwrap();
        drop(peer.request);
        let mut result_writer = std::fs::File::from(peer.result);
        if extra {
            let mut encoded = validated_result(job).encode_pipe_frame().unwrap().to_vec();
            encoded.push(0);
            result_writer.write_all(&encoded).unwrap();
        } else {
            result_writer.write_all(&[0; 17]).unwrap();
        }
        drop(result_writer);
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut receipt = receipt;
        let failure = loop {
            match receipt.poll() {
                Err(failure) => break failure,
                Ok(AuthWorkerResultPoll::Pending(next)) => {
                    assert!(Instant::now() < deadline);
                    receipt = next;
                    thread::yield_now();
                }
                Ok(AuthWorkerResultPoll::Complete(_)) => unreachable!(),
            }
        };
        assert_eq!(failure.worker(), job.worker());
        assert_eq!(
            failure.error(),
            if extra {
                AuthWorkerPipeError::ExtraResultBytes
            } else {
                AuthWorkerPipeError::PrematureEof
            }
        );
        pool.cancel(failure.worker()).unwrap();
    }
}

#[test]
fn private_pipe_submit_failure_returns_exact_worker_for_cleanup() {
    const CHILD_MARKER: &str = "NATIVE_IPC_TEST_AUTH_PIPE_EPIPE";
    if std::env::var_os(CHILD_MARKER).is_none() {
        let status = Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("backend::macos::supervisor::auth_adapter::tests::private_pipe_submit_failure_returns_exact_worker_for_cleanup")
            .arg("--nocapture")
            .env(CHILD_MARKER, "1")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }

    let (generation, worker, state) = worker(103);
    let (endpoint, peer) = test_worker_endpoint_pair();
    let mut pool =
        AuthWorkerPool::from_test_precreated_workers(vec![(generation, worker, endpoint)]).unwrap();
    let dispatched = pool
        .dispatch(
            raw(
                AUDIT_IDENTITY,
                501,
                encode_client_hello(CLIENT_NONCE).unwrap(),
            ),
            job_id(103),
            deadline_after(Duration::from_secs(5)),
        )
        .unwrap();
    let worker = dispatched.job.worker();
    drop(peer.request);
    drop(peer.result);
    let failure = match dispatched.submit() {
        Err(failure) => failure,
        Ok(_) => unreachable!(),
    };
    assert_eq!(failure.worker(), worker);
    assert_eq!(failure.error(), AuthWorkerPipeError::Native(EPIPE));
    pool.cancel(worker).unwrap();
    assert_eq!(state.lock().unwrap().terminations, 1);
}

#[test]
fn decoded_pipe_result_still_requires_exact_parent_binding_and_reap() {
    let (mut pool, states) = pool(&[94]);
    let (job, receipt) = pool
        .dispatch(
            raw(
                AUDIT_IDENTITY,
                501,
                encode_client_hello(CLIENT_NONCE).unwrap(),
            ),
            job_id(96),
            deadline_after(Duration::from_secs(5)),
        )
        .unwrap()
        .into_parts();
    let mut result = validated_result(job).encode_pipe_frame().unwrap();
    result[RESULT_JOB_OFFSET + JOB_AUDIT_OFFSET] ^= 1;
    // SAFETY: this modeled result arrived on the exact receipt endpoint.
    let decoded =
        unsafe { ReceivedAuthWorkerResult::from_test_private_pipe(receipt, &result).unwrap() };
    assert_eq!(
        pool.complete(decoded).err(),
        Some(AuthAdapterError::ResultMismatch)
    );
    assert_eq!(states[0].lock().unwrap().terminations, 1);
}

#[test]
fn exact_result_mints_a_message_only_after_exact_worker_reap() {
    let (mut pool, states) = pool(&[101]);
    let hello = encode_client_hello(CLIENT_NONCE).unwrap();
    let (job, receipt) = pool
        .dispatch(
            raw(AUDIT_IDENTITY, 501, hello),
            job_id(1),
            deadline_after(Duration::from_secs(5)),
        )
        .unwrap()
        .into_parts();
    let authenticated = pool
        .complete(received_result(receipt, validated_result(job)))
        .unwrap();
    let state = states[0].lock().unwrap();
    assert_eq!(state.result_reaps, 1);
    assert_eq!(state.terminations, 0);
    drop(state);
    let (_connection, reply) = accept_client_hello(authenticated, 201);
    let (_reply_right, reply) = reply.into_parts();
    assert!(!reply.is_empty());
}

#[test]
fn result_cannot_mint_until_nonblocking_exact_reap_completes() {
    let (mut pool, states) = pool(&[211]);
    let (job, receipt) = pool
        .dispatch(
            raw(
                AUDIT_IDENTITY,
                501,
                encode_client_hello(CLIENT_NONCE).unwrap(),
            ),
            job_id(2),
            deadline_after(Duration::from_secs(5)),
        )
        .unwrap()
        .into_parts();
    states[0].lock().unwrap().reap_pending_once = true;
    assert_eq!(
        pool.complete(received_result(receipt, validated_result(job)))
            .err()
            .unwrap(),
        AuthAdapterError::WorkerRetirementPending(job.worker())
    );
    assert_eq!(states[0].lock().unwrap().result_reaps, 0);
    assert!(pool.poll_completed(job.worker()).is_ok());
    assert_eq!(states[0].lock().unwrap().result_reaps, 1);
}

#[test]
fn abnormal_worker_exit_retires_slot_without_minting_authentication() {
    let (mut pool, states) = pool(&[212]);
    let (job, receipt) = pool
        .dispatch(
            raw(
                AUDIT_IDENTITY,
                501,
                encode_client_hello(CLIENT_NONCE).unwrap(),
            ),
            job_id(3),
            deadline_after(Duration::from_secs(5)),
        )
        .unwrap()
        .into_parts();
    states[0].lock().unwrap().result_wait_status = 7 << 8;
    assert_eq!(
        pool.complete(received_result(receipt, validated_result(job)))
            .err(),
        Some(AuthAdapterError::WorkerExitedAbnormally)
    );
    assert_eq!(states[0].lock().unwrap().result_reaps, 1);
    assert_eq!(
        pool.poll_completed(job.worker()).err(),
        Some(AuthAdapterError::UnknownWorker)
    );
}

fn spawned_pid(command: &mut Command) -> c_int {
    let child = command.spawn().unwrap();
    let pid = c_int::try_from(child.id()).unwrap();
    // The authority below becomes the sole waiter. `Child::drop` currently
    // performs no wait, but forgetting makes that ownership transfer explicit.
    std::mem::forget(child);
    pid
}

#[test]
fn dedicated_child_wait_domain_validates_public_darwin_signal_abi() {
    assert_eq!(size_of::<DarwinSigaction>(), 16);
    assert_eq!(std::mem::align_of::<DarwinSigaction>(), 8);
    assert_not_impl_any!(DedicatedChildWaitDomain: Clone, Copy, Send, Sync);

    let canonical = DarwinSigaction {
        handler: 0,
        mask: 0,
        flags: 0,
    };
    assert_eq!(
        DedicatedChildWaitDomain::validate_disposition(canonical),
        Ok(())
    );
    assert_eq!(
        DedicatedChildWaitDomain::validate_disposition(DarwinSigaction {
            handler: 1,
            ..canonical
        }),
        Err(ChildWaitDomainError::NonDefaultSigchld)
    );
    assert_eq!(
        DedicatedChildWaitDomain::validate_disposition(DarwinSigaction {
            handler: 0x1234,
            ..canonical
        }),
        Err(ChildWaitDomainError::NonDefaultSigchld)
    );
    assert_eq!(
        DedicatedChildWaitDomain::validate_disposition(DarwinSigaction {
            flags: SA_NOCLDWAIT,
            ..canonical
        }),
        Err(ChildWaitDomainError::AutoReapEnabled)
    );
}

#[test]
fn pending_spawn_reply_preserves_exact_freshness_through_both_map_branches() {
    assert_not_impl_any!(PendingSpawnReply<()>: Clone, Copy);
    let freshness = SpawnReplyFreshness {
        connection: ConnectionIdentity(77),
        generation: 77,
        sequence: 1,
        client_nonce: [0x31; 32],
        service_nonce: [0x42; 32],
    };
    let pending = PendingSpawnReply {
        reply: MachSendOnceRight::synthetic(),
        freshness,
        bound_session: None,
        output: 5_u8,
    };
    let (_reply, mapped_freshness, bound_session, output) =
        pending.map_output(u16::from).into_parts();
    assert_eq!(mapped_freshness, freshness);
    assert_eq!(bound_session, None);
    assert_eq!(output, 5_u16);

    let pending = PendingSpawnReply {
        reply: MachSendOnceRight::synthetic(),
        freshness,
        bound_session: None,
        output: 6_u8,
    };
    let retained_error = pending
        .try_map_output(|value| Err::<u16, _>(u16::from(value)))
        .err()
        .unwrap();
    let (_reply, error_freshness, bound_session, error) = retained_error.into_parts();
    assert_eq!(error_freshness, freshness);
    assert_eq!(bound_session, None);
    assert_eq!(error, 6_u16);
}

#[test]
fn exact_spawn_reply_registers_binds_trace_and_arms_cleanup_without_substitution() {
    let (pending, owner) = accepted_spawn_reply(1301);
    let pending = match pending.validate(&installed_catalog()) {
        Ok(pending) => pending,
        Err(_) => panic!("installed policy rejected exact authenticated spawn"),
    };
    let mut table = WatchdogTable::new();
    let state = Arc::new(Mutex::new(ReadyBrokerState::default()));
    // SAFETY: the fake models one exact unreaped broker child.
    let broker = unsafe {
        ExactBroker::from_unreaped_direct_child(ReadyBroker {
            state: Arc::clone(&state),
        })
    };
    let mut session_id = [0x91; 32];
    session_id[..8].copy_from_slice(&1301_u64.to_le_bytes());
    // SAFETY: this nonzero test session value is unique in the local table.
    let session = unsafe { FreshSessionId::from_fresh_random(session_id).unwrap() };
    let pending = pending.assign_session(session);
    // SAFETY: this test models the broker as the exact child created by the
    // same spawn operation that consumed this assigned launch.
    let pending = unsafe { pending.attach_test_atomic_broker(broker) };
    let pending = match pending.register_watchdog(&mut table) {
        Ok(registered) => registered,
        Err(_) => panic!("exact watchdog registration failed"),
    };
    let handle = {
        let launch = pending
            .registered_launch_permit()
            .expect("registered launch is linear and initially present");
        assert_eq!(launch.connection(), owner);
        launch.handle()
    };
    // SAFETY: this models the broker consuming both stops for the exact
    // registered launch returned alongside the retained reply binding.
    let trace = unsafe { TraceEstablished::from_broker_handshake(handle, owner) };
    let pending = match pending.bind_trace(trace) {
        Ok(pending) => pending,
        Err(_) => panic!("exact trace proof did not match registered reply"),
    };
    let ready = pending.establish_ready().unwrap();
    drop(ready);
    let state = state.lock().unwrap();
    assert_eq!(state.normal_attempts, 0);
    assert_eq!(state.emergency_attempts, 1);
    assert_eq!(
        state.emergency_reason,
        Some(TerminationReason::SpawnResultUndeliverable)
    );
    drop(state);
    assert_eq!(
        table.terminate_for_client_request(handle, owner),
        Err(WatchdogStateError::UnknownSession)
    );
}

#[test]
fn registered_reply_drop_exactly_cleans_before_ready() {
    assert_not_impl_any!(SessionAssignedSpawn: Clone, Copy);
    assert_not_impl_any!(
        AtomicallySpawnedBroker<ValidatedSpawn, ReadyBroker>: Clone,
        Copy
    );
    assert_not_impl_any!(
        PendingRegisteredSession<ValidatedSpawn, ReadyBroker>: Clone,
        Copy
    );

    let (pending, owner) = accepted_spawn_reply(1302);
    let pending = match pending.validate(&installed_catalog()) {
        Ok(pending) => pending,
        Err(_) => panic!("installed policy rejected exact authenticated spawn"),
    };
    let state = Arc::new(Mutex::new(ReadyBrokerState::default()));
    // SAFETY: the fake models one exact unreaped broker child.
    let broker = unsafe {
        ExactBroker::from_unreaped_direct_child(ReadyBroker {
            state: Arc::clone(&state),
        })
    };
    let mut session_id = [0x92; 32];
    session_id[..8].copy_from_slice(&1302_u64.to_le_bytes());
    // SAFETY: this nonzero test session value is unique in the local table.
    let session = unsafe { FreshSessionId::from_fresh_random(session_id).unwrap() };
    let handle = session.handle();
    let pending = pending.assign_session(session);
    // SAFETY: the test broker is paired with this assigned launch.
    let pending = unsafe { pending.attach_test_atomic_broker(broker) };
    let mut table = WatchdogTable::new();
    let registered = match pending.register_watchdog(&mut table) {
        Ok(registered) => registered,
        Err(_) => panic!("exact watchdog registration failed"),
    };
    drop(registered);

    let state = state.lock().unwrap();
    assert_eq!(state.normal_attempts, 0);
    assert_eq!(state.emergency_attempts, 1);
    assert_eq!(
        state.emergency_reason,
        Some(TerminationReason::LaunchAbandoned)
    );
    drop(state);
    assert_eq!(
        table.terminate_for_client_request(handle, owner),
        Err(WatchdogStateError::UnknownSession)
    );
}

#[test]
fn substituted_atomic_session_is_rejected_and_exactly_cleaned() {
    let (pending, _owner) = accepted_spawn_reply(1303);
    let pending = match pending.validate(&installed_catalog()) {
        Ok(pending) => pending,
        Err(_) => panic!("installed policy rejected exact authenticated spawn"),
    };
    let mut assigned_id = [0x93; 32];
    assigned_id[..8].copy_from_slice(&1303_u64.to_le_bytes());
    let mut substituted_id = [0x94; 32];
    substituted_id[..8].copy_from_slice(&2303_u64.to_le_bytes());
    // SAFETY: both modeled session IDs are nonzero and distinct.
    let assigned = unsafe { FreshSessionId::from_fresh_random(assigned_id).unwrap() };
    // SAFETY: both modeled session IDs are nonzero and distinct.
    let substituted = unsafe { FreshSessionId::from_fresh_random(substituted_id).unwrap() };
    let pending = pending.assign_session(assigned);
    let (reply, freshness, bound_session, output) = pending.into_parts();
    let state = Arc::new(Mutex::new(ReadyBrokerState::default()));
    // SAFETY: the fake models one exact unreaped broker child.
    let broker = unsafe {
        ExactBroker::from_unreaped_direct_child(ReadyBroker {
            state: Arc::clone(&state),
        })
    };
    // SAFETY: this deliberately models a broken atomic spawner so registration
    // must reject the substituted session before any launch authority escapes.
    let output = unsafe {
        AtomicallySpawnedBroker::from_test_atomic_spawn(substituted, output.spawn, broker)
    };
    let pending = PendingSpawnReply {
        reply,
        freshness,
        bound_session,
        output,
    };
    let mut table = WatchdogTable::new();
    let error = pending.register_watchdog(&mut table).err().unwrap();
    assert_eq!(error.output, WatchdogStateError::WrongConnection);
    drop(error);
    let state = state.lock().unwrap();
    assert_eq!(state.emergency_attempts, 1);
    assert_eq!(
        state.emergency_reason,
        Some(TerminationReason::ProtocolViolation)
    );
}

#[test]
fn trace_binding_mismatch_exactly_cleans_registered_broker() {
    let (pending, owner) = accepted_spawn_reply(1304);
    let pending = match pending.validate(&installed_catalog()) {
        Ok(pending) => pending,
        Err(_) => panic!("installed policy rejected exact authenticated spawn"),
    };
    let state = Arc::new(Mutex::new(ReadyBrokerState::default()));
    // SAFETY: the fake models one exact unreaped broker child.
    let broker = unsafe {
        ExactBroker::from_unreaped_direct_child(ReadyBroker {
            state: Arc::clone(&state),
        })
    };
    let mut session_id = [0x95; 32];
    session_id[..8].copy_from_slice(&1304_u64.to_le_bytes());
    // SAFETY: this nonzero test session value is unique in the local table.
    let session = unsafe { FreshSessionId::from_fresh_random(session_id).unwrap() };
    let pending = pending.assign_session(session);
    // SAFETY: the test broker is paired with this assigned launch.
    let pending = unsafe { pending.attach_test_atomic_broker(broker) };
    let mut table = WatchdogTable::new();
    let registered = match pending.register_watchdog(&mut table) {
        Ok(registered) => registered,
        Err(_) => panic!("exact watchdog registration failed"),
    };
    let handle = registered.registered_launch_permit().unwrap().handle();
    let wrong_owner = connection(9304).connection_identity();
    // SAFETY: this deliberately models a trace proof from another connection.
    let wrong_trace = unsafe { TraceEstablished::from_broker_handshake(handle, wrong_owner) };
    let error = registered.bind_trace(wrong_trace).err().unwrap();
    drop(error);

    let state = state.lock().unwrap();
    assert_eq!(state.emergency_attempts, 1);
    assert_eq!(
        state.emergency_reason,
        Some(TerminationReason::ProtocolViolation)
    );
    drop(state);
    assert_eq!(
        table.terminate_for_client_request(handle, owner),
        Err(WatchdogStateError::UnknownSession)
    );
}

#[test]
fn ready_freshness_failure_exactly_cleans_registered_broker() {
    let (pending, owner) = accepted_spawn_reply(1305);
    let pending = match pending.validate(&installed_catalog()) {
        Ok(pending) => pending,
        Err(_) => panic!("installed policy rejected exact authenticated spawn"),
    };
    let state = Arc::new(Mutex::new(ReadyBrokerState::default()));
    // SAFETY: the fake models one exact unreaped broker child.
    let broker = unsafe {
        ExactBroker::from_unreaped_direct_child(ReadyBroker {
            state: Arc::clone(&state),
        })
    };
    let mut session_id = [0x96; 32];
    session_id[..8].copy_from_slice(&1305_u64.to_le_bytes());
    // SAFETY: this nonzero test session value is unique in the local table.
    let session = unsafe { FreshSessionId::from_fresh_random(session_id).unwrap() };
    let pending = pending.assign_session(session);
    // SAFETY: the test broker is paired with this assigned launch.
    let pending = unsafe { pending.attach_test_atomic_broker(broker) };
    let mut table = WatchdogTable::new();
    let registered = match pending.register_watchdog(&mut table) {
        Ok(registered) => registered,
        Err(_) => panic!("exact watchdog registration failed"),
    };
    let handle = registered.registered_launch_permit().unwrap().handle();
    // SAFETY: this models the exact broker completing both launch stops.
    let trace = unsafe { TraceEstablished::from_broker_handshake(handle, owner) };
    let mut registered = registered.bind_trace(trace).ok().unwrap();
    registered.freshness.sequence = 2;
    assert_eq!(
        registered.establish_ready().err(),
        Some(WatchdogStateError::WrongConnection)
    );

    let state = state.lock().unwrap();
    assert_eq!(state.emergency_attempts, 1);
    assert_eq!(
        state.emergency_reason,
        Some(TerminationReason::ProtocolViolation)
    );
    drop(state);
    assert_eq!(
        table.terminate_for_client_request(handle, owner),
        Err(WatchdogStateError::UnknownSession)
    );
}

#[test]
fn native_ready_send_delivers_exact_authenticated_result_and_stays_live() {
    let (pending, owner) = accepted_spawn_reply(1306);
    let reply_port = TestReceiveRight::allocate();
    let pending = replace_spawn_reply(pending, reply_port.make_send_once());
    let freshness = pending.freshness;
    let pending = match pending.validate(&installed_catalog()) {
        Ok(pending) => pending,
        Err(_) => panic!("installed policy rejected exact authenticated spawn"),
    };
    let state = Arc::new(Mutex::new(ReadyBrokerState::default()));
    // SAFETY: the fake models one exact unreaped broker child.
    let broker = unsafe {
        ExactBroker::from_unreaped_direct_child(ReadyBroker {
            state: Arc::clone(&state),
        })
    };
    let mut session_id = [0x97; 32];
    session_id[..8].copy_from_slice(&1306_u64.to_le_bytes());
    // SAFETY: this nonzero test session value is unique in the local table.
    let session = unsafe { FreshSessionId::from_fresh_random(session_id).unwrap() };
    let pending = pending.assign_session(session);
    // SAFETY: the test broker is paired with this assigned launch.
    let pending = unsafe { pending.attach_test_atomic_broker(broker) };
    let mut table = WatchdogTable::new();
    let registered = match pending.register_watchdog(&mut table) {
        Ok(registered) => registered,
        Err(_) => panic!("exact watchdog registration failed"),
    };
    let handle = registered.registered_launch_permit().unwrap().handle();
    // SAFETY: this models the exact broker completing both launch stops.
    let trace = unsafe { TraceEstablished::from_broker_handshake(handle, owner) };
    let registered = registered.bind_trace(trace).ok().unwrap();
    let ready = registered.establish_ready().unwrap();
    assert_eq!(ready.send_ready(), Ok(()));

    let (header, payload) = receive_inline_message(reply_port.name);
    assert_eq!(header.id, SUPERVISOR_MESSAGE_ID);
    let decoded = super::super::decode_spawn_result(
        &payload,
        freshness.generation,
        freshness.client_nonce,
        freshness.service_nonce,
    )
    .unwrap();
    let super::super::DecodedSpawnResult::Ready(decoded_handle) = decoded else {
        panic!("native Ready send returned a rejection")
    };
    assert_eq!(decoded_handle.bytes(), handle.bytes());
    assert_eq!(state.lock().unwrap().emergency_attempts, 0);
    assert_eq!(
        table.terminate_for_client_request(handle, owner),
        Ok(Ok(()))
    );
    assert_eq!(state.lock().unwrap().normal_attempts, 1);
}

#[test]
fn recoverable_native_ready_send_exactly_cleans_before_returning_error() {
    let (pending, owner) = accepted_spawn_reply(1307);
    let mut invalid_port = TestReceiveRight::allocate();
    let invalid_name = invalid_port.name;
    invalid_port.destroy_receive();
    // SAFETY: this deliberately models a send-once destination name that is
    // already invalid so the prepared Ready send takes its recoverable path.
    let invalid_reply = unsafe { MachSendOnceRight::from_test_name(invalid_name) };
    let pending = replace_spawn_reply(pending, invalid_reply);
    let pending = match pending.validate(&installed_catalog()) {
        Ok(pending) => pending,
        Err(_) => panic!("installed policy rejected exact authenticated spawn"),
    };
    let state = Arc::new(Mutex::new(ReadyBrokerState::default()));
    // SAFETY: the fake models one exact unreaped broker child.
    let broker = unsafe {
        ExactBroker::from_unreaped_direct_child(ReadyBroker {
            state: Arc::clone(&state),
        })
    };
    let mut session_id = [0x98; 32];
    session_id[..8].copy_from_slice(&1307_u64.to_le_bytes());
    // SAFETY: this nonzero test session value is unique in the local table.
    let session = unsafe { FreshSessionId::from_fresh_random(session_id).unwrap() };
    let pending = pending.assign_session(session);
    // SAFETY: the test broker is paired with this assigned launch.
    let pending = unsafe { pending.attach_test_atomic_broker(broker) };
    let mut table = WatchdogTable::new();
    let registered = match pending.register_watchdog(&mut table) {
        Ok(registered) => registered,
        Err(_) => panic!("exact watchdog registration failed"),
    };
    let handle = registered.registered_launch_permit().unwrap().handle();
    // SAFETY: this models the exact broker completing both launch stops.
    let trace = unsafe { TraceEstablished::from_broker_handshake(handle, owner) };
    let registered = registered.bind_trace(trace).ok().unwrap();
    let ready = registered.establish_ready().unwrap();
    assert_eq!(
        ready.send_ready(),
        Err(ReadyReplyError::Mach(MachReplyError::MachSend(
            MACH_SEND_INVALID_DEST
        )))
    );

    let state = state.lock().unwrap();
    assert_eq!(state.normal_attempts, 0);
    assert_eq!(state.emergency_attempts, 1);
    assert_eq!(
        state.emergency_reason,
        Some(TerminationReason::SpawnResultUndeliverable)
    );
    drop(state);
    assert_eq!(
        table.terminate_for_client_request(handle, owner),
        Err(WatchdogStateError::UnknownSession)
    );
}

#[test]
fn direct_child_authority_accepts_only_clean_exact_reap() {
    let pid = spawned_pid(&mut Command::new("/usr/bin/true"));
    // SAFETY: `pid` is the exact direct child just spawned by this test; no
    // other code waits for it and SIGCHLD retains normal zombie semantics.
    let mut worker = unsafe { ExactAuthWorker::from_test_spawned_direct_child(pid).unwrap() };
    let deadline = Instant::now() + Duration::from_secs(5);
    let retirement = loop {
        let retirement = worker.try_reap_after_result().unwrap();
        if retirement != AuthWorkerRetirement::Pending {
            break retirement;
        }
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(1));
    };
    assert_eq!(retirement, AuthWorkerRetirement::Clean);
    assert_eq!(
        worker.try_terminate_and_reap(),
        Err(DirectChildAuthWorkerError::WaitAuthorityLost)
    );
}

#[test]
fn direct_child_authority_kills_and_exactly_reaps_without_pid_fallback() {
    let mut command = Command::new("/bin/sleep");
    command.arg("30");
    let pid = spawned_pid(&mut command);
    // SAFETY: `pid` is the exact direct child just spawned by this test; no
    // other code waits for it and SIGCHLD retains normal zombie semantics.
    let mut worker = unsafe { ExactAuthWorker::from_test_spawned_direct_child(pid).unwrap() };
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if worker.try_terminate_and_reap().unwrap() {
            break;
        }
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(1));
    }
}

#[test]
fn direct_child_authority_rejects_nonpositive_pid() {
    // SAFETY: invalid values are deliberately supplied to exercise rejection;
    // the constructor creates no authority for them.
    assert!(matches!(
        unsafe { ExactAuthWorker::from_test_spawned_direct_child(0) },
        Err(DirectChildAuthWorkerError::InvalidChild)
    ));
}

#[test]
fn armed_direct_child_drop_exactly_kills_and_reaps() {
    let mut command = Command::new("/bin/sleep");
    command.arg("30");
    let pid = spawned_pid(&mut command);
    // SAFETY: this test is the exact parent and sole waiter with normal zombie
    // semantics for the newly spawned direct child.
    let worker = unsafe { ExactAuthWorker::from_test_spawned_direct_child(pid).unwrap() };
    drop(worker);
    let mut status = 0;
    // SAFETY: the armed Drop must already have consumed this exact child.
    assert_eq!(unsafe { waitpid(pid, &raw mut status, WNOHANG) }, -1);
    assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(ECHILD));
}

#[test]
fn stolen_wait_authority_fails_stop_without_pid_fallback() {
    const CHILD_MARKER: &str = "NATIVE_IPC_TEST_AUTH_WORKER_ECHILD_ABORT";
    if std::env::var_os(CHILD_MARKER).is_some() {
        let pid = spawned_pid(&mut Command::new("/usr/bin/true"));
        // SAFETY: this subprocess initially owns the exact child and is its
        // sole waiter with normal zombie semantics.
        let mut worker = unsafe { ExactAuthWorker::from_test_spawned_direct_child(pid).unwrap() };
        let mut status = 0;
        loop {
            // SAFETY: intentionally steal the exact wait authority to exercise
            // the fail-stop ECHILD branch in the armed owner.
            let result = unsafe { waitpid(pid, &raw mut status, 0) };
            if result == pid {
                break;
            }
            assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(EINTR));
        }
        let _ = worker.try_reap_after_result();
        panic!("ECHILD must abort before returning");
    }

    let status = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("backend::macos::supervisor::auth_adapter::tests::stolen_wait_authority_fails_stop_without_pid_fallback")
        .arg("--nocapture")
        .env(CHILD_MARKER, "1")
        .status()
        .unwrap();
    assert_eq!(status.signal(), Some(6));
}

#[test]
fn every_result_binding_change_terminates_and_reaps_without_effect() {
    for mutation in 0..7 {
        let generation = 300 + mutation;
        let (mut pool, states) = pool(&[generation]);
        let (job, receipt) = pool
            .dispatch(
                raw(
                    AUDIT_IDENTITY,
                    501,
                    encode_client_hello(CLIENT_NONCE).unwrap(),
                ),
                job_id(u8::try_from(mutation + 10).unwrap()),
                deadline_after(Duration::from_secs(5)),
            )
            .unwrap()
            .into_parts();
        let mut result = validated_result(job);
        match mutation {
            0 => result.job.worker.generation ^= 1,
            1 => result.job.job_id[0] ^= 1,
            2 => result.job.audit_identity[0] ^= 1,
            3 => result.job.effective_uid ^= 1,
            4 => result.job.effective_gid ^= 1,
            5 => result.job.frame_digest[0] ^= 1,
            6 => result.job.deadline ^= 1,
            _ => unreachable!(),
        }
        let error = pool
            .complete(received_result(receipt, result))
            .err()
            .unwrap();
        assert_eq!(error, AuthAdapterError::ResultMismatch);
        assert_eq!(states[0].lock().unwrap().terminations, 1);
    }
}

#[test]
fn saturation_and_per_uid_limits_reject_without_queueing() {
    let (mut pool, _states) = pool(&[501, 502, 503, 504]);
    let hello = || encode_client_hello(CLIENT_NONCE).unwrap();
    let (first, _first_receipt) = pool
        .dispatch(
            raw(AUDIT_IDENTITY, 501, hello()),
            job_id(31),
            deadline_after(Duration::from_secs(5)),
        )
        .unwrap()
        .into_parts();
    let (second, _second_receipt) = pool
        .dispatch(
            raw(AUDIT_IDENTITY, 501, hello()),
            job_id(32),
            deadline_after(Duration::from_secs(5)),
        )
        .unwrap()
        .into_parts();
    assert_eq!(
        pool.dispatch(
            raw(AUDIT_IDENTITY, 501, hello()),
            job_id(33),
            deadline_after(Duration::from_secs(5)),
        )
        .err()
        .unwrap(),
        AuthAdapterError::CapacityExceeded
    );
    pool.cancel(first.worker()).unwrap();
    pool.cancel(second.worker()).unwrap();
}

#[test]
fn late_or_rejected_result_cannot_survive_worker_cleanup() {
    let (mut pool, states) = pool(&[701, 702]);
    let short = deadline_after(Duration::from_millis(2));
    let (late_job, late_receipt) = pool
        .dispatch(
            raw(
                AUDIT_IDENTITY,
                501,
                encode_client_hello(CLIENT_NONCE).unwrap(),
            ),
            job_id(41),
            short,
        )
        .unwrap()
        .into_parts();
    std::thread::sleep(Duration::from_millis(5));
    assert_eq!(
        pool.complete(received_result(late_receipt, validated_result(late_job),))
            .err()
            .unwrap(),
        AuthAdapterError::DeadlineExpired
    );
    assert_eq!(states[0].lock().unwrap().terminations, 1);

    let (rejected_job, rejected_receipt) = pool
        .dispatch(
            raw(
                AUDIT_IDENTITY,
                502,
                encode_client_hello(CLIENT_NONCE).unwrap(),
            ),
            job_id(42),
            deadline_after(Duration::from_secs(5)),
        )
        .unwrap()
        .into_parts();
    // SAFETY: this models an invalid worker result that lacks code identity.
    let rejected =
        unsafe { AuthWorkerResult::from_test_security_validation(rejected_job, [0; 32]) };
    assert_eq!(
        pool.complete(received_result(rejected_receipt, rejected))
            .err()
            .unwrap(),
        AuthAdapterError::AuthenticationRejected
    );
    assert_eq!(states[1].lock().unwrap().terminations, 1);
}

#[test]
fn cleanup_failure_retains_authority_and_blocks_replacement_until_retry() {
    let (mut pool, states) = pool(&[901]);
    let (job, receipt) = pool
        .dispatch(
            raw(
                AUDIT_IDENTITY,
                501,
                encode_client_hello(CLIENT_NONCE).unwrap(),
            ),
            job_id(51),
            deadline_after(Duration::from_secs(5)),
        )
        .unwrap()
        .into_parts();
    states[0].lock().unwrap().fail_next = true;
    let mut mismatched = validated_result(job);
    mismatched.job.frame_digest[0] ^= 1;
    assert_eq!(
        pool.complete(received_result(receipt, mismatched))
            .err()
            .unwrap(),
        AuthAdapterError::WorkerCleanupFailed(FakeFailure::LostWaitAuthority)
    );
    let (replacement_generation, replacement, replacement_state) = worker(903);
    assert_eq!(
        pool.install_test_replacement(
            0,
            replacement_generation,
            replacement,
            test_worker_endpoint(),
        )
        .unwrap_err(),
        AuthAdapterError::InvalidReplacement
    );
    assert_eq!(replacement_state.lock().unwrap().emergency_cleanups, 1);
    pool.cancel(job.worker()).unwrap();
    assert_eq!(states[0].lock().unwrap().terminations, 1);
}

#[test]
fn old_result_and_job_id_cannot_cross_exact_reap_and_replacement() {
    let (mut pool, states) = pool(&[1001]);
    let (first_job, first_receipt) = pool
        .dispatch(
            raw(
                AUDIT_IDENTITY,
                501,
                encode_client_hello(CLIENT_NONCE).unwrap(),
            ),
            job_id(61),
            deadline_after(Duration::from_secs(5)),
        )
        .unwrap()
        .into_parts();
    pool.complete(received_result(first_receipt, validated_result(first_job)))
        .unwrap();
    assert_eq!(states[0].lock().unwrap().result_reaps, 1);

    let (replacement_generation, replacement, replacement_state) = worker(1003);
    let replacement_identity = pool
        .install_test_replacement(
            0,
            replacement_generation,
            replacement,
            test_worker_endpoint(),
        )
        .unwrap();
    assert_ne!(replacement_identity, first_job.worker());
    let (second_job, _second_receipt) = pool
        .dispatch(
            raw(
                AUDIT_IDENTITY,
                502,
                encode_client_hello(CLIENT_NONCE).unwrap(),
            ),
            job_id(61),
            deadline_after(Duration::from_secs(5)),
        )
        .unwrap()
        .into_parts();
    // SAFETY: model one late result that was already queued on the retired
    // worker's old private endpoint before exact reap destroyed that endpoint.
    let old_receipt = test_receipt(first_job.worker(), first_job.job_id());
    assert_eq!(
        pool.complete(received_result(old_receipt, validated_result(first_job)))
            .err()
            .unwrap(),
        AuthAdapterError::UnknownWorker
    );
    assert_eq!(replacement_state.lock().unwrap().terminations, 0);
    pool.cancel(second_job.worker()).unwrap();
}

#[test]
fn complete_audit_token_transition_still_cannot_cross_adapter() {
    let (mut pool, _states) = pool(&[1101, 1102, 1104, 1105]);
    let (hello_job, hello_receipt) = pool
        .dispatch(
            raw(
                AUDIT_IDENTITY,
                501,
                encode_client_hello(CLIENT_NONCE).unwrap(),
            ),
            job_id(71),
            deadline_after(Duration::from_secs(5)),
        )
        .unwrap()
        .into_parts();
    let authenticated = pool
        .complete(received_result(hello_receipt, validated_result(hello_job)))
        .unwrap();
    let (mut connection, _reply) = accept_client_hello(authenticated, 1103);

    let request = SpawnRequest::new(
        deadline_after(Duration::from_secs(5)),
        b"com.example.receiver".to_vec(),
        vec![b"--mode=test".to_vec()],
        vec![TargetEnvironmentEntry::new(b"LANG".to_vec(), b"C".to_vec()).unwrap()],
    )
    .unwrap();
    let spawn_bytes = encode_spawn_request(
        &request,
        connection.connection_identity().get(),
        CLIENT_NONCE,
        service_nonce(1103),
    )
    .unwrap();
    let mut changed_audit = AUDIT_IDENTITY;
    changed_audit[31] ^= 1;
    let (spawn_job, spawn_receipt) = pool
        .dispatch(
            raw(changed_audit, 501, spawn_bytes.clone()),
            job_id(72),
            deadline_after(Duration::from_secs(5)),
        )
        .unwrap()
        .into_parts();
    let authenticated = pool
        .complete(received_result(spawn_receipt, validated_result(spawn_job)))
        .unwrap();
    let AuthenticatedMachRoute::Spawn(wrong_peer) = authenticated.route().unwrap() else {
        panic!("authenticated record was not a spawn")
    };
    assert_eq!(
        wrong_peer.generation(),
        connection.connection_identity().get()
    );
    assert_eq!(
        wrong_peer.accept(&mut connection).err().unwrap(),
        SupervisorWireError::PeerMismatch
    );

    let mut wrong_nonce = spawn_bytes.clone();
    wrong_nonce[32] ^= 1;
    let (spawn_job, spawn_receipt) = pool
        .dispatch(
            raw(AUDIT_IDENTITY, 501, wrong_nonce),
            job_id(73),
            deadline_after(Duration::from_secs(5)),
        )
        .unwrap()
        .into_parts();
    let authenticated = pool
        .complete(received_result(spawn_receipt, validated_result(spawn_job)))
        .unwrap();
    let AuthenticatedMachRoute::Spawn(wrong_nonce) = authenticated.route().unwrap() else {
        panic!("authenticated record was not a spawn")
    };
    assert_eq!(
        wrong_nonce.accept(&mut connection).err().unwrap(),
        SupervisorWireError::ReplayOrSubstitution
    );

    let (spawn_job, spawn_receipt) = pool
        .dispatch(
            raw(AUDIT_IDENTITY, 501, spawn_bytes),
            job_id(74),
            deadline_after(Duration::from_secs(5)),
        )
        .unwrap()
        .into_parts();
    let authenticated = pool
        .complete(received_result(spawn_receipt, validated_result(spawn_job)))
        .unwrap();
    let AuthenticatedMachRoute::Spawn(spawn) = authenticated.route().unwrap() else {
        panic!("authenticated record was not a spawn")
    };
    let pending = spawn.accept(&mut connection).unwrap();
    let (_reply, freshness, bound_session, _request) = pending.into_parts();
    assert_eq!(bound_session, None);
    assert_eq!(freshness.connection, connection.connection_identity());
    assert_eq!(freshness.generation, 1103);
    assert_eq!(freshness.sequence, 1);
    assert_eq!(freshness.client_nonce, CLIENT_NONCE);
    assert_eq!(freshness.service_nonce, service_nonce(1103));
}

#[test]
fn malformed_authenticated_hello_returns_no_connection_and_service_reply_cannot_route() {
    let (mut pool, _states) = pool(&[1201, 1202]);
    let mut malformed_hello = encode_client_hello(CLIENT_NONCE).unwrap();
    malformed_hello[24] = 1;
    let (job, receipt) = pool
        .dispatch(
            raw(AUDIT_IDENTITY, 501, malformed_hello),
            job_id(81),
            deadline_after(Duration::from_secs(5)),
        )
        .unwrap()
        .into_parts();
    let authenticated = pool
        .complete(received_result(receipt, validated_result(job)))
        .unwrap();
    let AuthenticatedMachRoute::ClientHello(hello) = authenticated.route().unwrap() else {
        panic!("malformed hello was routed as another request kind")
    };
    // SAFETY: this modeled generation is fresh and nonzero.
    let generation = unsafe { ConnectionGeneration::from_unique_service_value(1203).unwrap() };
    // SAFETY: this modeled nonce is fresh and nonzero.
    let nonce = unsafe { FreshServiceNonce::from_fresh_random(service_nonce(1203)).unwrap() };
    assert_eq!(
        hello.accept(generation, nonce).err().unwrap(),
        SupervisorWireError::AuthenticationRequired
    );

    let (job, receipt) = pool
        .dispatch(
            raw(
                AUDIT_IDENTITY,
                501,
                encode_client_hello(CLIENT_NONCE).unwrap(),
            ),
            job_id(82),
            deadline_after(Duration::from_secs(5)),
        )
        .unwrap()
        .into_parts();
    let authenticated = pool
        .complete(received_result(receipt, validated_result(job)))
        .unwrap();
    let (_connection, service_reply) = accept_client_hello(authenticated, 1204);
    let (_reply_right, service_reply) = service_reply.into_parts();

    let (replacement_generation, replacement, _state) = worker(1205);
    pool.install_test_replacement(
        0,
        replacement_generation,
        replacement,
        test_worker_endpoint(),
    )
    .unwrap();
    let (job, receipt) = pool
        .dispatch(
            raw(AUDIT_IDENTITY, 501, service_reply),
            job_id(83),
            deadline_after(Duration::from_secs(5)),
        )
        .unwrap()
        .into_parts();
    let authenticated = pool
        .complete(received_result(receipt, validated_result(job)))
        .unwrap();
    assert_eq!(
        authenticated.route().err().unwrap(),
        SupervisorWireError::Malformed
    );
}

#[test]
fn rejected_authentication_cannot_consume_live_connection_state() {
    let (mut pool, _states) = pool(&[1301, 1302, 1303]);
    let (hello_job, hello_receipt) = pool
        .dispatch(
            raw(
                AUDIT_IDENTITY,
                501,
                encode_client_hello(CLIENT_NONCE).unwrap(),
            ),
            job_id(84),
            deadline_after(Duration::from_secs(5)),
        )
        .unwrap()
        .into_parts();
    let authenticated = pool
        .complete(received_result(hello_receipt, validated_result(hello_job)))
        .unwrap();
    let (mut connection, _reply) = accept_client_hello(authenticated, 1304);

    let request = SpawnRequest::new(
        deadline_after(Duration::from_secs(5)),
        b"com.example.receiver".to_vec(),
        vec![b"--mode=test".to_vec()],
        Vec::new(),
    )
    .unwrap();
    let spawn_bytes = encode_spawn_request(
        &request,
        connection.connection_identity().get(),
        CLIENT_NONCE,
        service_nonce(1304),
    )
    .unwrap();
    let (rejected_job, rejected_receipt) = pool
        .dispatch(
            raw(AUDIT_IDENTITY, 501, spawn_bytes.clone()),
            job_id(85),
            deadline_after(Duration::from_secs(5)),
        )
        .unwrap()
        .into_parts();
    // SAFETY: this models the assigned worker's canonical reject decision.
    let rejected =
        unsafe { AuthWorkerResult::from_test_security_validation(rejected_job, [0; 32]) };
    assert_eq!(
        pool.complete(received_result(rejected_receipt, rejected))
            .err()
            .unwrap(),
        AuthAdapterError::AuthenticationRejected
    );

    let (valid_job, valid_receipt) = pool
        .dispatch(
            raw(AUDIT_IDENTITY, 501, spawn_bytes),
            job_id(86),
            deadline_after(Duration::from_secs(5)),
        )
        .unwrap()
        .into_parts();
    let authenticated = pool
        .complete(received_result(valid_receipt, validated_result(valid_job)))
        .unwrap();
    let AuthenticatedMachRoute::Spawn(spawn) = authenticated.route().unwrap() else {
        panic!("authenticated spawn was routed as another request kind")
    };
    assert_eq!(spawn.generation(), connection.connection_identity().get());
    assert!(spawn.accept(&mut connection).is_ok());
}
