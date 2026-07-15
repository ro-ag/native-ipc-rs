//! Fixed broker start/death gate entrypoint.
//!
//! This module consumes only the fixed process ABI installed by the atomic
//! broker spawner. Crossing the gate does not authorize a launcher, target,
//! path, PID, signal, task port, or filesystem operation. A future broker
//! control channel must bind a separately staged canonical launch plan to the
//! exact service child and watchdog session before this gate is released.

use std::ffi::{OsStr, c_int};
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileTypeExt;

use super::auth_adapter::broker_spawn::{
    BROKER_GATE_FD, INSTALLED_BROKER_MODE, INSTALLED_BROKER_PATH, INSTALLED_GATE_ARGUMENT,
    START_BYTE,
};

const F_GETFD: c_int = 1;
const F_SETFD: c_int = 2;
const F_GETFL: c_int = 3;
const F_SETFL: c_int = 4;
const FD_CLOEXEC: c_int = 1;
const O_ACCMODE: c_int = 3;
const O_RDONLY: c_int = 0;
const O_NONBLOCK: c_int = 0x0000_0004;
const EAGAIN: c_int = 35;
const EINTR: c_int = 4;

unsafe extern "C" {
    fn _exit(status: c_int) -> !;
    fn fcntl(fd: c_int, command: c_int, ...) -> c_int;
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
    /// A descriptor operation failed with this Darwin error number.
    Descriptor(c_int),
    /// A blocking gate read failed with this Darwin error number.
    Read(c_int),
    /// The gate carried a wrong, repeated, or otherwise noncanonical byte.
    InvalidActivation,
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
    pub(super) unsafe fn adopt_fixed_process() -> Result<Self, BrokerEntryError> {
        validate_fixed_arguments(std::env::args_os())?;
        // SAFETY: the caller promises exclusive ownership of fixed descriptor
        // 3 in this just-execed process.
        unsafe { Self::adopt_fixed_gate() }
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

/// Runs the no-callback fixed gate process used by the executable fixture.
///
/// This performs no launch effect. A future packaged broker may extend only
/// the active arm with a separately authenticated, staged, session-bound
/// control plan. Gate shape and START alone remain non-authoritative.
///
/// # Safety
///
/// This must run in a just-execed dedicated broker before threads, children,
/// policy, or effect-bearing endpoints. Its exact process vector and descriptor
/// 3 must come from the fixed spawner, and no Rust value may already own FD 3.
pub(in crate::backend::macos) unsafe fn run_fixed_gate_process() -> ! {
    // SAFETY: the caller promises the complete process-entry contract.
    let adopted = unsafe { DormantBrokerGate::adopt_fixed_process() };
    let status = match adopted {
        Err(_) => 64,
        Ok(dormant) => match dormant.wait_for_activation() {
            Ok(Err(BrokerGateExit::ServiceGoneBeforeActivation | BrokerGateExit::ServiceGone)) => 0,
            Err(_) => 65,
            Ok(Ok(active)) => match active.wait_for_service_death() {
                Ok(BrokerGateExit::ServiceGone) => 0,
                Ok(BrokerGateExit::ServiceGoneBeforeActivation) => 66,
                Err(_) => 65,
            },
        },
    };
    // SAFETY: the gate-only process has no authority-bearing cleanup beyond
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
