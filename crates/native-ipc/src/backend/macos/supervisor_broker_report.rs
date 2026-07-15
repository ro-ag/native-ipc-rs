//! Exact one-shot broker trace report carried on the fixed service channel.

use std::io::{Read, Write};
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::time::Instant;

use super::super::{ConnectionIdentity, SupervisorDeadline, SupervisorWireError};
use crate::backend::macos::supervisor_watchdog::SessionHandle;

const MAGIC: [u8; 8] = *b"NIPCBTR1";
const VERSION: u16 = 1;
const EXEC_TRAP_HELD: u16 = 2;
pub(in crate::backend::macos::supervisor) const BROKER_TRACE_REPORT_BYTES: usize = 224;
pub(in crate::backend::macos) const BROKER_RESUME_BYTE: [u8; 1] = [1];

/// Exact canonical plan facts allowed in the broker's one-shot trace report.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::backend::macos::supervisor) struct BrokerTraceReportBinding {
    deadline: SupervisorDeadline,
    connection_generation: u64,
    sequence: u64,
    effective_uid: u32,
    effective_gid: u32,
    session: [u8; 32],
    client_nonce: [u8; 32],
    service_nonce: [u8; 32],
    target_identity: [u8; 32],
    plan_digest: [u8; 32],
}

impl BrokerTraceReportBinding {
    #[allow(clippy::too_many_arguments)]
    pub(super) const fn new(
        deadline: SupervisorDeadline,
        connection_generation: u64,
        sequence: u64,
        effective_uid: u32,
        effective_gid: u32,
        session: [u8; 32],
        client_nonce: [u8; 32],
        service_nonce: [u8; 32],
        target_identity: [u8; 32],
        plan_digest: [u8; 32],
    ) -> Self {
        Self {
            deadline,
            connection_generation,
            sequence,
            effective_uid,
            effective_gid,
            session,
            client_nonce,
            service_nonce,
            target_identity,
            plan_digest,
        }
    }

    pub(super) const fn deadline(self) -> SupervisorDeadline {
        self.deadline
    }

    fn validate(self) -> Result<(), BrokerTraceReportError> {
        if self.deadline.wire_value() == 0
            || self.connection_generation == 0
            || self.sequence != 1
            || self.effective_uid == 0
            || self.effective_gid == 0
            || self.session == [0; 32]
            || self.client_nonce == [0; 32]
            || self.service_nonce == [0; 32]
            || self.client_nonce == self.service_nonce
            || self.target_identity == [0; 32]
            || self.plan_digest == [0; 32]
        {
            Err(BrokerTraceReportError::Malformed)
        } else {
            Ok(())
        }
    }
}

/// Nonblocking service-side receipt inseparable from one exact broker spawn.
pub(in crate::backend::macos) struct BrokerTraceReportReceiver {
    stream: Option<UnixStream>,
    expected: BrokerTraceReportBinding,
    deadline: Instant,
    bytes: [u8; BROKER_TRACE_REPORT_BYTES],
    filled: usize,
    finished: bool,
}

impl BrokerTraceReportReceiver {
    pub(super) fn new(
        stream: UnixStream,
        expected: BrokerTraceReportBinding,
        deadline: Instant,
    ) -> Result<Self, BrokerTraceReportError> {
        expected.validate()?;
        if Instant::now() >= deadline {
            return Err(BrokerTraceReportError::DeadlineExpired);
        }
        stream
            .set_nonblocking(true)
            .map_err(|error| BrokerTraceReportError::Io(error.raw_os_error().unwrap_or(0)))?;
        Ok(Self {
            stream: Some(stream),
            expected,
            deadline,
            bytes: [0; BROKER_TRACE_REPORT_BYTES],
            filled: 0,
            finished: false,
        })
    }

    pub(super) fn poll(
        &mut self,
    ) -> Result<Option<ReceivedBrokerTraceReport>, BrokerTraceReportError> {
        if self.finished {
            return Err(BrokerTraceReportError::InvalidTransition);
        }
        let stream = self
            .stream
            .as_mut()
            .ok_or(BrokerTraceReportError::InvalidTransition)?;
        if Instant::now() >= self.deadline {
            return Err(BrokerTraceReportError::DeadlineExpired);
        }
        while self.filled < self.bytes.len() {
            match stream.read(&mut self.bytes[self.filled..]) {
                Ok(0) => return Err(BrokerTraceReportError::Malformed),
                Ok(count) => self.filled += count,
                Err(ref error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    return Ok(None);
                }
                Err(error) => {
                    return Err(BrokerTraceReportError::Io(
                        error.raw_os_error().unwrap_or(0),
                    ));
                }
            }
        }
        let mut extra = [0_u8; 1];
        loop {
            match stream.read(&mut extra) {
                Ok(0) => break,
                Ok(_) => return Err(BrokerTraceReportError::Malformed),
                Err(ref error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(ref error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    return Ok(None);
                }
                Err(error) => {
                    return Err(BrokerTraceReportError::Io(
                        error.raw_os_error().unwrap_or(0),
                    ));
                }
            }
        }
        if Instant::now() >= self.deadline {
            return Err(BrokerTraceReportError::DeadlineExpired);
        }
        let binding = ReceivedBrokerTraceReport::decode(&self.bytes)?;
        if binding != self.expected {
            return Err(BrokerTraceReportError::Binding);
        }
        let resume = BrokerResumeSender {
            stream: Some(
                self.stream
                    .take()
                    .ok_or(BrokerTraceReportError::InvalidTransition)?,
            ),
        };
        self.finished = true;
        Ok(Some(ReceivedBrokerTraceReport { binding, resume }))
    }
}

/// Canonical exact-frame report that still requires registered-session binding.
pub(super) struct ReceivedBrokerTraceReport {
    binding: BrokerTraceReportBinding,
    resume: BrokerResumeSender,
}

impl ReceivedBrokerTraceReport {
    fn decode(
        bytes: &[u8; BROKER_TRACE_REPORT_BYTES],
    ) -> Result<BrokerTraceReportBinding, BrokerTraceReportError> {
        if bytes[..8] != MAGIC
            || get_u16(bytes, 8) != VERSION
            || get_u16(bytes, 10) != EXEC_TRAP_HELD
            || get_u32(bytes, 12) != BROKER_TRACE_REPORT_BYTES as u32
            || bytes[208..].iter().any(|byte| *byte != 0)
        {
            return Err(BrokerTraceReportError::Malformed);
        }
        let mut session = [0; 32];
        session.copy_from_slice(&bytes[48..80]);
        let mut client_nonce = [0; 32];
        client_nonce.copy_from_slice(&bytes[80..112]);
        let mut service_nonce = [0; 32];
        service_nonce.copy_from_slice(&bytes[112..144]);
        let mut target_identity = [0; 32];
        target_identity.copy_from_slice(&bytes[144..176]);
        let mut plan_digest = [0; 32];
        plan_digest.copy_from_slice(&bytes[176..208]);
        let binding = BrokerTraceReportBinding::new(
            SupervisorDeadline::from_wire(get_u64(bytes, 16)),
            get_u64(bytes, 24),
            get_u64(bytes, 32),
            get_u32(bytes, 40),
            get_u32(bytes, 44),
            session,
            client_nonce,
            service_nonce,
            target_identity,
            plan_digest,
        );
        binding.validate()?;
        Ok(binding)
    }

    pub(super) fn authenticate_registered(
        self,
        handle: SessionHandle,
        connection: ConnectionIdentity,
    ) -> Result<AuthenticatedBrokerTraceReport, (BrokerTraceReportError, BrokerResumeSender)> {
        if self.binding.session != handle.bytes()
            || self.binding.connection_generation != connection.get()
        {
            return Err((BrokerTraceReportError::Binding, self.resume));
        }
        Ok(AuthenticatedBrokerTraceReport {
            handle,
            connection,
            resume: self.resume,
        })
    }
}

/// Sealed proof constructible only by exact report receipt and binding.
pub(in crate::backend::macos) struct AuthenticatedBrokerTraceReport {
    handle: SessionHandle,
    connection: ConnectionIdentity,
    resume: BrokerResumeSender,
}

impl AuthenticatedBrokerTraceReport {
    pub(in crate::backend::macos) const fn handle(&self) -> SessionHandle {
        self.handle
    }

    pub(in crate::backend::macos) const fn connection(&self) -> ConnectionIdentity {
        self.connection
    }

    pub(in crate::backend::macos) fn into_parts(
        self,
    ) -> (SessionHandle, ConnectionIdentity, BrokerResumeSender) {
        (self.handle, self.connection, self.resume)
    }
}

/// Linear reverse commit retained until the authenticated Ready send succeeds.
pub(in crate::backend::macos) struct BrokerResumeSender {
    stream: Option<UnixStream>,
}

impl BrokerResumeSender {
    #[cfg(test)]
    pub(in crate::backend::macos) fn from_test_stream(stream: UnixStream) -> Self {
        Self {
            stream: Some(stream),
        }
    }

    pub(in crate::backend::macos) fn commit_after_ready(
        &mut self,
    ) -> Result<(), BrokerTraceReportError> {
        let stream = self
            .stream
            .as_mut()
            .ok_or(BrokerTraceReportError::InvalidTransition)?;
        loop {
            match stream.write(&BROKER_RESUME_BYTE) {
                Ok(1) => break,
                Ok(_) => return Err(BrokerTraceReportError::InvalidTransition),
                Err(ref error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    return Err(BrokerTraceReportError::Io(
                        error.raw_os_error().unwrap_or(0),
                    ));
                }
            }
        }
        drop(self.stream.take());
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(in crate::backend::macos) enum BrokerTraceReportError {
    Malformed,
    Binding,
    DeadlineExpired,
    InvalidTransition,
    Io(i32),
}

pub(in crate::backend::macos::supervisor) fn encode_broker_trace_report(
    binding: BrokerTraceReportBinding,
) -> Result<[u8; BROKER_TRACE_REPORT_BYTES], BrokerTraceReportError> {
    binding.validate()?;
    let mut bytes = [0_u8; BROKER_TRACE_REPORT_BYTES];
    bytes[..8].copy_from_slice(&MAGIC);
    put_u16(&mut bytes, 8, VERSION);
    put_u16(&mut bytes, 10, EXEC_TRAP_HELD);
    put_u32(&mut bytes, 12, BROKER_TRACE_REPORT_BYTES as u32);
    put_u64(&mut bytes, 16, binding.deadline.wire_value());
    put_u64(&mut bytes, 24, binding.connection_generation);
    put_u64(&mut bytes, 32, binding.sequence);
    put_u32(&mut bytes, 40, binding.effective_uid);
    put_u32(&mut bytes, 44, binding.effective_gid);
    bytes[48..80].copy_from_slice(&binding.session);
    bytes[80..112].copy_from_slice(&binding.client_nonce);
    bytes[112..144].copy_from_slice(&binding.service_nonce);
    bytes[144..176].copy_from_slice(&binding.target_identity);
    bytes[176..208].copy_from_slice(&binding.plan_digest);
    Ok(bytes)
}

pub(in crate::backend::macos::supervisor) fn finish_broker_trace_report(
    stream: &UnixStream,
) -> Result<(), BrokerTraceReportError> {
    stream
        .shutdown(Shutdown::Write)
        .map_err(|error| BrokerTraceReportError::Io(error.raw_os_error().unwrap_or(0)))
}

fn get_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(bytes[offset..offset + 2].try_into().expect("fixed field"))
}

fn get_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(bytes[offset..offset + 4].try_into().expect("fixed field"))
}

fn get_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(bytes[offset..offset + 8].try_into().expect("fixed field"))
}

fn put_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

impl From<BrokerTraceReportError> for SupervisorWireError {
    fn from(error: BrokerTraceReportError) -> Self {
        match error {
            BrokerTraceReportError::DeadlineExpired => SupervisorWireError::LimitExceeded,
            BrokerTraceReportError::Binding => SupervisorWireError::ReplayOrSubstitution,
            BrokerTraceReportError::Malformed
            | BrokerTraceReportError::InvalidTransition
            | BrokerTraceReportError::Io(_) => SupervisorWireError::Malformed,
        }
    }
}

#[cfg(test)]
#[path = "supervisor_broker_report_test.rs"]
mod tests;
