//! Private native backend implementations.
#![allow(
    dead_code,
    reason = "phase-4c receipt facade remains unreachable until native image identity is proven"
)]

use crate::session::AbsoluteDeadline;
use core::cell::Cell;
use core::marker::PhantomData;

/// Authenticated endpoint role in the asymmetric spawned-child session.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum EndpointRole {
    Coordinator,
    Receiver,
}

/// Opaque, platform-neutral identity facts retained after endpoint authentication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct PeerFacts {
    parent_pid: u32,
    child_pid: u32,
    nonce: [u8; 32],
    local_role: EndpointRole,
}

impl PeerFacts {
    fn new(
        parent_pid: u32,
        child_pid: u32,
        nonce: [u8; 32],
        local_role: EndpointRole,
    ) -> Option<Self> {
        if parent_pid == 0 || child_pid == 0 || parent_pid == child_pid || nonce == [0; 32] {
            return None;
        }
        Some(Self {
            parent_pid,
            child_pid,
            nonce,
            local_role,
        })
    }

    pub(crate) const fn parent_pid(self) -> u32 {
        self.parent_pid
    }

    pub(crate) const fn child_pid(self) -> u32 {
        self.child_pid
    }

    pub(crate) const fn nonce(self) -> [u8; 32] {
        self.nonce
    }

    pub(crate) const fn local_role(self) -> EndpointRole {
        self.local_role
    }
}

/// Evidence produced only by a backend after kernel endpoint authentication
/// and exact bootstrap nonce validation.
pub(crate) struct ChannelPeerReceipt {
    facts: PeerFacts,
}

impl ChannelPeerReceipt {
    /// # Safety
    ///
    /// `facts` must have been established by the backend's complete kernel
    /// endpoint-authentication and bootstrap-nonce state machine.
    unsafe fn from_verified_native(facts: PeerFacts) -> Self {
        Self { facts }
    }
}

/// Evidence produced only after the normative executable image-identity policy
/// has been checked before and after spawn while race-resistant native state is held.
pub(crate) struct ImageIdentityReceipt {
    facts: PeerFacts,
}

impl ImageIdentityReceipt {
    /// # Safety
    ///
    /// The normative pre/post-spawn image identity must have been verified and
    /// its race-resistant native state must remain owned by the endpoint.
    unsafe fn from_verified_native(facts: PeerFacts) -> Self {
        Self { facts }
    }
}

/// Combined endpoint and image evidence. No current backend may construct this
/// until its image-identity state machine is implemented.
pub(crate) struct AuthenticatedPeerReceipt {
    facts: PeerFacts,
}

impl AuthenticatedPeerReceipt {
    fn combine(
        channel: ChannelPeerReceipt,
        image: ImageIdentityReceipt,
    ) -> Result<Self, SessionTransportError> {
        if channel.facts != image.facts {
            return Err(SessionTransportError::IdentityMismatch);
        }
        Ok(Self {
            facts: channel.facts,
        })
    }

    pub(crate) const fn facts(&self) -> PeerFacts {
        self.facts
    }
}

/// A native transport that cannot be separated from its authentication evidence.
pub(crate) struct AuthenticatedNativeEndpoint<T> {
    transport: T,
    receipt: AuthenticatedPeerReceipt,
    not_sync: PhantomData<Cell<()>>,
}

impl<T> AuthenticatedNativeEndpoint<T> {
    /// # Safety
    ///
    /// `transport` must be the exact native owner that produced and continues
    /// to retain every resource represented by `receipt`.
    unsafe fn from_verified_native(transport: T, receipt: AuthenticatedPeerReceipt) -> Self {
        Self {
            transport,
            receipt,
            not_sync: PhantomData,
        }
    }

    pub(crate) const fn peer_facts(&self) -> PeerFacts {
        self.receipt.facts()
    }
}

/// Peer lifecycle state observed without surrendering endpoint ownership.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PeerState {
    Running,
    Exited(i32),
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

mod sealed {
    pub trait Sealed {}
}

/// Private authenticated duplex record transport.
///
/// Implementations must validate a fixed record header and `maximum` before
/// allocating, preserve one caller-derived absolute deadline across every
/// retry/chunk, and poison themselves after ambiguous partial transmission.
trait AuthenticatedControl: sealed::Sealed {
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

    /// Performs one nonblocking kernel observation of peer lifecycle state.
    fn try_poll_peer(&mut self) -> Result<PeerState, SessionTransportError>;

    /// Permanently invalidates the transport. Every later I/O operation must
    /// fail immediately without touching native state.
    fn poison(&mut self);
}

/// Coordinator-only owned-child lifecycle operations.
trait OwnedChildControl: AuthenticatedControl {
    fn terminate_and_reap(
        &mut self,
        deadline: AbsoluteDeadline,
    ) -> Result<(), SessionTransportError>;
}

#[allow(
    private_bounds,
    reason = "only the receipt-gated endpoint is crate-visible; raw transport traits stay backend-private"
)]
impl<T: AuthenticatedControl> AuthenticatedNativeEndpoint<T> {
    pub(crate) fn send_record(
        &mut self,
        bytes: &[u8],
        deadline: AbsoluteDeadline,
    ) -> Result<(), SessionTransportError> {
        self.transport.send_record(bytes, deadline)
    }

    pub(crate) fn receive_record(
        &mut self,
        maximum: usize,
        deadline: AbsoluteDeadline,
    ) -> Result<Vec<u8>, SessionTransportError> {
        self.transport.receive_record(maximum, deadline)
    }

    pub(crate) fn try_poll_peer(&mut self) -> Result<PeerState, SessionTransportError> {
        self.transport.try_poll_peer()
    }

    pub(crate) fn poison(&mut self) {
        self.transport.poison();
    }
}

#[allow(
    private_bounds,
    reason = "coordinator child control is reachable only through the receipt-gated endpoint"
)]
impl<T: OwnedChildControl> AuthenticatedNativeEndpoint<T> {
    pub(crate) fn terminate_and_reap(
        &mut self,
        deadline: AbsoluteDeadline,
    ) -> Result<(), SessionTransportError> {
        self.transport.terminate_and_reap(deadline)
    }
}

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
