//! Private native backend implementations.
#![allow(
    dead_code,
    reason = "private role-scoped evidence remains unreachable until native session composition"
)]

use crate::negotiation::AcceptedTranscriptFacts;
use crate::session::AbsoluteDeadline;
use core::cell::Cell;
use core::marker::PhantomData;

/// Exact spawned-pair identities shared by role-scoped evidence constructors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SpawnIdentityFacts {
    parent_pid: u32,
    child_pid: u32,
    parent_uid: u32,
    parent_gid: u32,
    child_uid: u32,
    child_gid: u32,
    nonce: [u8; 32],
}

impl SpawnIdentityFacts {
    fn new(
        parent_pid: u32,
        child_pid: u32,
        parent_uid: u32,
        parent_gid: u32,
        child_uid: u32,
        child_gid: u32,
        nonce: [u8; 32],
    ) -> Option<Self> {
        if parent_pid == 0 || child_pid == 0 || parent_pid == child_pid || nonce == [0; 32] {
            return None;
        }
        Some(Self {
            parent_pid,
            child_pid,
            parent_uid,
            parent_gid,
            child_uid,
            child_gid,
            nonce,
        })
    }

    pub(crate) const fn parent_pid(self) -> u32 {
        self.parent_pid
    }

    pub(crate) const fn child_pid(self) -> u32 {
        self.child_pid
    }

    pub(crate) const fn parent_uid(self) -> u32 {
        self.parent_uid
    }

    pub(crate) const fn parent_gid(self) -> u32 {
        self.parent_gid
    }

    pub(crate) const fn child_uid(self) -> u32 {
        self.child_uid
    }

    pub(crate) const fn child_gid(self) -> u32 {
        self.child_gid
    }

    pub(crate) const fn nonce(self) -> [u8; 32] {
        self.nonce
    }
}

/// Coordinator-only evidence of the exact child-channel authentication flow.
pub(crate) struct CoordinatorChildChannelReceipt {
    facts: SpawnIdentityFacts,
}

impl CoordinatorChildChannelReceipt {
    /// # Safety
    ///
    /// `facts` must have been established by the backend's complete kernel
    /// endpoint-authentication and bootstrap-nonce state machine.
    unsafe fn from_verified_native(facts: SpawnIdentityFacts) -> Self {
        Self { facts }
    }
}

/// Coordinator-only evidence retaining the exact spawned child image owner.
pub(crate) struct CoordinatorChildImageReceipt {
    facts: SpawnIdentityFacts,
}

impl CoordinatorChildImageReceipt {
    /// # Safety
    ///
    /// The normative pre/post-spawn image identity must have been verified and
    /// its race-resistant native state must remain owned by the endpoint.
    unsafe fn from_verified_native(facts: SpawnIdentityFacts) -> Self {
        Self { facts }
    }
}

/// Coordinator evidence after exact child channel, image, and bilateral ACCEPT.
pub(crate) struct CoordinatorAcceptedEvidence {
    facts: SpawnIdentityFacts,
    transcript: AcceptedTranscriptFacts,
    not_sync: PhantomData<Cell<()>>,
}

impl CoordinatorAcceptedEvidence {
    fn combine(
        channel: CoordinatorChildChannelReceipt,
        image: CoordinatorChildImageReceipt,
        transcript: AcceptedTranscriptFacts,
    ) -> Result<Self, SessionTransportError> {
        if channel.facts != image.facts || channel.facts.nonce != transcript.nonce() {
            return Err(SessionTransportError::IdentityMismatch);
        }
        Ok(Self {
            facts: channel.facts,
            transcript,
            not_sync: PhantomData,
        })
    }

    pub(crate) const fn facts(&self) -> SpawnIdentityFacts {
        self.facts
    }
}

/// Receiver-only evidence of the authenticated trusted spawning coordinator.
///
/// This deliberately carries no coordinator-owned child-image or pidfd proof.
pub(crate) struct ReceiverSpawnerEvidence {
    facts: SpawnIdentityFacts,
    transcript: AcceptedTranscriptFacts,
    not_sync: PhantomData<Cell<()>>,
}

impl ReceiverSpawnerEvidence {
    /// # Safety
    ///
    /// `facts` must come from the exact inherited endpoint's validated spawning
    /// parent credentials and the local child identity captured during HELLO.
    unsafe fn from_verified_native(
        facts: SpawnIdentityFacts,
        transcript: AcceptedTranscriptFacts,
    ) -> Result<Self, SessionTransportError> {
        if facts.nonce != transcript.nonce() {
            return Err(SessionTransportError::IdentityMismatch);
        }
        Ok(Self {
            facts,
            transcript,
            not_sync: PhantomData,
        })
    }

    pub(crate) const fn facts(&self) -> SpawnIdentityFacts {
        self.facts
    }
}

/// Peer lifecycle state observed without surrendering endpoint ownership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PeerState {
    Running,
    ExitedUnknown,
}

/// Bounded platform-neutral native session transport failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SessionTransportError {
    DeadlineExpired,
    PeerExited,
    MalformedRecord,
    RecordTooLarge,
    IdentityMismatch,
    Native,
}

pub(crate) mod sealed {
    pub(crate) trait Sealed {}
}

/// Private authenticated duplex zero-rights record transport.
///
/// Implementations must reject ancillary capability delivery, bound record
/// allocation by `maximum`, preserve one caller-derived absolute deadline
/// across every retry, and poison themselves after ambiguous transmission.
pub(crate) trait AuthenticatedZeroRightsTransport: sealed::Sealed {
    fn send_record(
        &mut self,
        bytes: &[u8],
        deadline: AbsoluteDeadline,
    ) -> Result<(), SessionTransportError>;

    fn receive_record(
        &mut self,
        maximum: usize,
        deadline: AbsoluteDeadline,
    ) -> Result<Vec<u8>, SessionTransportError>;

    /// Performs one nonblocking peer observation without inventing an exit
    /// code that the authenticated record transport cannot prove.
    fn try_poll_peer(&mut self) -> Result<PeerState, SessionTransportError>;

    /// Permanently invalidates the transport. Every later I/O operation must
    /// fail immediately without touching native state.
    fn poison(&mut self);
}

/// Coordinator-only owned-child lifecycle operations.
pub(crate) trait OwnedChildLifecycle: sealed::Sealed {
    fn terminate_and_reap(
        &mut self,
        deadline: AbsoluteDeadline,
    ) -> Result<(), SessionTransportError>;
}

mod accepted_control;

#[cfg(target_os = "linux")]
#[allow(dead_code)]
pub(crate) mod linux;
#[cfg(target_os = "linux")]
#[allow(dead_code)]
mod linux_vnext;
#[cfg(target_os = "macos")]
#[allow(dead_code)]
pub(crate) mod macos;
#[cfg(target_os = "windows")]
#[allow(dead_code)]
pub(crate) mod windows;

#[cfg(target_os = "linux")]
pub(crate) fn mint_incarnation() -> Result<[u8; 16], ()> {
    let mut bytes = [0_u8; 16];
    let mut filled = 0;
    while filled < bytes.len() {
        // SAFETY: the remaining byte slice is writable for the supplied length.
        let result = unsafe {
            libc::getrandom(bytes[filled..].as_mut_ptr().cast(), bytes.len() - filled, 0)
        };
        if result < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(());
        }
        if result == 0 {
            return Err(());
        }
        filled += usize::try_from(result).map_err(|_| ())?;
    }
    (bytes != [0; 16]).then_some(bytes).ok_or(())
}

#[cfg(target_os = "macos")]
pub(crate) fn mint_incarnation() -> Result<[u8; 16], ()> {
    unsafe extern "C" {
        fn arc4random_buf(buffer: *mut core::ffi::c_void, length: usize);
    }
    let mut bytes = [0_u8; 16];
    // SAFETY: `bytes` is writable for exactly its length; arc4random_buf has no
    // failure return and fills caller-owned storage.
    unsafe { arc4random_buf(bytes.as_mut_ptr().cast(), bytes.len()) };
    (bytes != [0; 16]).then_some(bytes).ok_or(())
}

#[cfg(target_os = "windows")]
pub(crate) fn mint_incarnation() -> Result<[u8; 16], ()> {
    use windows_sys::Win32::Security::Cryptography::{
        BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom,
    };
    let mut bytes = [0_u8; 16];
    // SAFETY: the system-preferred RNG accepts a null algorithm handle and the
    // output buffer is writable for exactly the supplied length.
    let status = unsafe {
        BCryptGenRandom(
            core::ptr::null_mut(),
            bytes.as_mut_ptr(),
            bytes.len() as u32,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG,
        )
    };
    if status != 0 || bytes == [0; 16] {
        return Err(());
    }
    Ok(bytes)
}

#[cfg(test)]
#[path = "mod_test.rs"]
mod receipt_tests;

#[cfg(test)]
#[path = "accepted_control_test.rs"]
mod accepted_control_tests;
