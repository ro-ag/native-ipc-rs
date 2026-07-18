//! Platform-neutral session negotiation facts.

use crate::batch::{ActiveRegionSet, BatchError, ExpectedBatch, TransferBatch};
use crate::control::{ControlError, ControlFrame};
use core::cell::Cell;
use core::marker::PhantomData;
#[cfg(any(target_os = "macos", target_os = "windows"))]
use core::sync::atomic::{AtomicBool, Ordering};
#[cfg(target_os = "linux")]
use core::sync::atomic::{AtomicI32, Ordering};
use std::ffi::OsString;
use std::num::NonZeroU32;
#[cfg(target_os = "linux")]
use std::os::fd::{FromRawFd, OwnedFd};
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use std::path::Path;
use std::path::PathBuf;
use std::time::{Duration, Instant};

pub use crate::liveness::{ActiveLeaseFacts, LeaseFactsConsistency};

#[cfg(target_os = "linux")]
const RECEIVER_BOOTSTRAP_ENV_PREFIX: &[u8] = b"NATIVE_IPC_VNEXT_BOOTSTRAP_FD=";
#[cfg(target_os = "linux")]
const RECEIVER_PUBLIC_BOOTSTRAP_ENV_ENTRY: &[u8] = b"NATIVE_IPC_VNEXT_PUBLIC_BOOTSTRAP=1";
#[cfg(target_os = "linux")]
const PR_GET_MDWE: libc::c_int = 66;
#[cfg(target_os = "linux")]
const PR_MDWE_REFUSE_EXEC_GAIN: libc::c_ulong = 1;
#[cfg(target_os = "linux")]
const BOOTSTRAP_ABSENT: i32 = -2;
#[cfg(target_os = "linux")]
const BOOTSTRAP_INVALID: i32 = -1;
#[cfg(target_os = "linux")]
const BOOTSTRAP_TAKEN: i32 = -3;
#[cfg(target_os = "linux")]
static RECEIVER_BOOTSTRAP_FD: AtomicI32 = AtomicI32::new(BOOTSTRAP_ABSENT);
#[cfg(any(target_os = "macos", target_os = "windows"))]
static RECEIVER_BOOTSTRAP_TAKEN: AtomicBool = AtomicBool::new(false);

/// Executable-only ELF preinitializer referenced by [`crate::receiver_main!`].
///
/// # Safety
///
/// This function may be invoked only by the ELF loader through a
/// `.preinit_array` entry in the initial receiver executable. Its pointers must
/// be the loader-supplied initial argument and environment vectors. The hook is
/// a no-op on non-Linux targets solely to keep the helper-only signature
/// platform-neutral.
#[doc(hidden)]
pub unsafe extern "C" fn __receiver_bootstrap_preinit(
    _argument_count: core::ffi::c_int,
    _arguments: *mut *mut core::ffi::c_char,
    environment: *mut *mut core::ffi::c_char,
) {
    #[cfg(target_os = "linux")]
    // SAFETY: the public hook forwards the loader-supplied environment under
    // the same pre-initializer contract.
    unsafe {
        receiver_bootstrap_preinit_linux(environment);
    }
    #[cfg(not(target_os = "linux"))]
    let _ = environment;
}

#[cfg(target_os = "linux")]
unsafe fn receiver_bootstrap_preinit_linux(environment: *mut *mut libc::c_char) {
    // This ELF pre-initializer runs before Rust main and ordinary init-array
    // constructors. It performs no allocation and publishes only after all
    // exact child/descriptor facts and immediate CLOEXEC installation pass.
    let mut entry = environment;
    let public_bootstrap = loop {
        if entry.is_null() {
            return;
        }
        // SAFETY: the loader supplies a null-terminated environment vector.
        let candidate = unsafe { *entry };
        if candidate.is_null() {
            return;
        }
        let mut matches = true;
        for (offset, expected) in RECEIVER_PUBLIC_BOOTSTRAP_ENV_ENTRY.iter().enumerate() {
            // SAFETY: read only the current byte; a NUL ends this C string and
            // prevents any later offset from being dereferenced.
            let actual = unsafe { *candidate.add(offset) }.to_ne_bytes()[0];
            if actual == 0 || actual != *expected {
                matches = false;
                break;
            }
        }
        if matches
            // SAFETY: the exact fixed entry was readable through its last byte.
            && unsafe { *candidate.add(RECEIVER_PUBLIC_BOOTSTRAP_ENV_ENTRY.len()) } == 0
        {
            break candidate;
        }
        // SAFETY: advance within the loader-supplied pointer vector.
        entry = unsafe { entry.add(1) };
    };
    // SAFETY: initial-stack environment strings are writable process storage.
    // Scrubbing the routing marker before normal code prevents descendants from
    // reinterpreting this process's one-shot startup designation.
    unsafe { *public_bootstrap = 0 };

    let mut entry = environment;
    let value = loop {
        if entry.is_null() {
            return;
        }
        // SAFETY: the loader supplies a null-terminated environment vector.
        let candidate = unsafe { *entry };
        if candidate.is_null() {
            return;
        }
        let mut matches = true;
        for (offset, expected) in RECEIVER_BOOTSTRAP_ENV_PREFIX.iter().enumerate() {
            // SAFETY: read only the current byte; a NUL ends this C string and
            // prevents any later offset from being dereferenced.
            let actual = unsafe { *candidate.add(offset) }.to_ne_bytes()[0];
            if actual == 0 || actual != *expected {
                matches = false;
                break;
            }
        }
        if matches {
            // SAFETY: the matched fixed prefix lies within this environment entry.
            let value = unsafe { candidate.add(RECEIVER_BOOTSTRAP_ENV_PREFIX.len()) };
            // SAFETY: initial-stack environment strings are writable process
            // storage. Retain the parsed pointer locally but erase the inherited
            // numeric authority before any normal constructor or application code.
            unsafe { *candidate = 0 };
            break value;
        }
        // SAFETY: advance within the loader-supplied pointer vector.
        entry = unsafe { entry.add(1) };
    };
    let mut raw = 0_i32;
    let mut length = 0_usize;
    loop {
        if length == 10 {
            RECEIVER_BOOTSTRAP_FD.store(BOOTSTRAP_INVALID, Ordering::Release);
            return;
        }
        // SAFETY: getenv returned a live NUL-terminated process string.
        let byte = unsafe { *value.add(length) }.to_ne_bytes()[0];
        if byte == 0 {
            break;
        }
        if !byte.is_ascii_digit() || (length == 0 && byte == b'0') {
            RECEIVER_BOOTSTRAP_FD.store(BOOTSTRAP_INVALID, Ordering::Release);
            return;
        }
        let Some(next) = raw
            .checked_mul(10)
            .and_then(|current| current.checked_add(i32::from(byte - b'0')))
        else {
            RECEIVER_BOOTSTRAP_FD.store(BOOTSTRAP_INVALID, Ordering::Release);
            return;
        };
        raw = next;
        length += 1;
    }
    if length == 0 || raw < 3 {
        RECEIVER_BOOTSTRAP_FD.store(BOOTSTRAP_INVALID, Ordering::Release);
        return;
    }

    // SAFETY: these scalar queries and exact getsockopt output have valid
    // arguments and do not transfer descriptor ownership.
    let descriptor_flags = unsafe { libc::fcntl(raw, libc::F_GETFD) };
    let descriptor_status = unsafe { libc::fcntl(raw, libc::F_GETFL) };
    let mdwe = unsafe { libc::prctl(PR_GET_MDWE, 0, 0, 0, 0) } as libc::c_ulong;
    let pid = unsafe { libc::getpid() };
    let sid = unsafe { libc::getsid(0) };
    let process_group = unsafe { libc::getpgrp() };
    let mut socket_type = 0_i32;
    let mut socket_type_len = core::mem::size_of::<i32>() as libc::socklen_t;
    let socket_result = unsafe {
        libc::getsockopt(
            raw,
            libc::SOL_SOCKET,
            libc::SO_TYPE,
            (&mut socket_type as *mut i32).cast(),
            &mut socket_type_len,
        )
    };
    if descriptor_flags != 0
        || descriptor_status < 0
        || descriptor_status & libc::O_NONBLOCK == 0
        || mdwe != PR_MDWE_REFUSE_EXEC_GAIN
        || pid <= 0
        || sid != pid
        || process_group != pid
        || socket_result != 0
        || socket_type_len as usize != core::mem::size_of::<i32>()
        || socket_type != libc::SOCK_SEQPACKET
    {
        // SAFETY: the process environment designated this live numeric slot as
        // bootstrap authority before any Rust application code ran. Fail closed
        // by removing it rather than permitting later Command inheritance.
        let _ = unsafe { libc::close(raw) };
        RECEIVER_BOOTSTRAP_FD.store(BOOTSTRAP_INVALID, Ordering::Release);
        return;
    }
    // SAFETY: this descriptor is the validated inherited endpoint. Installing
    // CLOEXEC before any application code removes every safe Command delegation
    // window. On failure, close the exact startup descriptor.
    if unsafe { libc::fcntl(raw, libc::F_SETFD, libc::FD_CLOEXEC) } != 0 {
        let _ = unsafe { libc::close(raw) };
        RECEIVER_BOOTSTRAP_FD.store(BOOTSTRAP_INVALID, Ordering::Release);
        return;
    }
    RECEIVER_BOOTSTRAP_FD.store(raw, Ordering::Release);
}

/// Hard protocol maximum for one atomic transfer batch.
pub const HARD_MAX_REGIONS_PER_BATCH: u16 = 16;
/// Hard maximum for the opaque HELLO application payload.
pub const HARD_MAX_BOOTSTRAP_PAYLOAD_BYTES: u32 = 16 * 1024 * 1024;
/// Hard maximum for one opaque application-control payload.
pub const HARD_MAX_CONTROL_PAYLOAD_BYTES: u32 = 16 * 1024 * 1024;
/// Hard maximum logical size of one region.
pub const HARD_MAX_REGION_BYTES: u64 = 1 << 40;
/// Hard maximum aggregate bytes in one transaction.
pub const HARD_MAX_BATCH_BYTES: u64 = 1 << 42;
/// Hard maximum simultaneously charged region mappings.
pub const HARD_MAX_ACTIVE_REGIONS: u32 = 1 << 20;
/// Hard maximum simultaneously charged mapping bytes.
pub const HARD_MAX_ACTIVE_BYTES: u64 = 1 << 44;
/// Hard maximum transactions in one fresh session.
pub const HARD_MAX_TRANSACTIONS: u64 = 1 << 48;

/// Coordinator endpoint marker for [`Session`].
pub struct Coordinator;
/// Receiver endpoint marker for [`Session`].
pub struct Receiver;
/// Authenticated HELLO state awaiting application decisions.
pub struct Negotiating;
/// Bilaterally accepted state that may carry bounded application control.
pub struct Ready;

/// Availability of the public lifecycle/session composition on this target.
///
/// This status applies only to the vNext session layer. The published shared-
/// memory API remains available on every supported target. Consumers may use
/// [`backend_status`] as a const preflight or handle
/// [`SessionError::BackendUnavailable`] from a construction attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendStatus {
    /// Public spawn and inherited-bootstrap session construction are composed.
    Available,
    /// Reserved for a supported target whose lifecycle adapter is not composed.
    /// Every target the crate currently compiles for reports [`Self::Available`];
    /// no supported target returns this today.
    Unavailable,
}

/// Reports whether the public lifecycle/session composition is available.
///
/// Linux, macOS Arm64, and Windows all report [`BackendStatus::Available`]:
/// public spawn and inherited-bootstrap session construction are composed on
/// every supported target. [`BackendStatus::Unavailable`] remains reserved for
/// targets whose adapter is not composed.
pub const fn backend_status() -> BackendStatus {
    BackendStatus::Available
}

/// Accepted wire protocol version bound into both challenged ACCEPT frames.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProtocolVersion {
    major: u16,
    minor: u16,
}

impl ProtocolVersion {
    #[allow(dead_code, reason = "wired into accepted session facts below")]
    pub(crate) const fn new(major: u16, minor: u16) -> Self {
        Self { major, minor }
    }

    /// Incompatible-major protocol number.
    pub const fn major(self) -> u16 {
        self.major
    }

    /// Backward-compatible minor protocol number.
    pub const fn minor(self) -> u16 {
        self.minor
    }
}

/// Locally observed accepted-session reducer state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionState {
    /// Application control and native transactions may be attempted.
    Ready,
    /// A terminal ambiguity, malformed peer action, or native failure poisoned the session.
    Poisoned,
}

/// Nonblocking peer observation that does not invent an exit code.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerStatus {
    /// No authenticated control-endpoint disconnect has been observed.
    Connected,
    /// The authenticated control endpoint closed; this does not prove process exit.
    Disconnected,
}

/// Exact direct-child termination fact reaped by the coordinator.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChildExitStatus {
    /// The direct child exited normally with this code.
    Exited(i32),
    /// The direct child was terminated by a signal.
    Signaled {
        /// Signal number reported by the kernel.
        signal: i32,
        /// Whether the kernel reported a core dump.
        dumped_core: bool,
    },
    /// Another process-global waiter consumed the direct-child status first.
    AlreadyReaped,
}

/// Bounded statement about descendant cleanup outside the atomic pidfd owner.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DescendantCleanupStatus {
    /// The trusted fresh-session checkpoint was not established.
    NotEstablished,
    /// A fresh process group existed, but bounded group termination could not
    /// be performed under a kernel-witnessed direct-child identity pin.
    FreshGroupUnverified,
    /// SIGKILL was delivered to the kernel-verified fresh process group while
    /// the unreaped direct child pinned its numeric identity, terminating
    /// every ordinary descendant that had not left the group.
    FreshGroupTerminated,
    /// A target-owned containment object proved the complete spawned process tree empty.
    ContainedProcessTreeComplete,
    /// A target-owned containment object exists, but bounded cleanup did not prove it empty.
    OwnedContainmentUnverified,
}

/// Bounded coordinator-owned direct-child cleanup result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChildCleanupFacts {
    direct_child: Option<ChildExitStatus>,
    descendants: DescendantCleanupStatus,
    native_error: Option<i32>,
}

impl ChildCleanupFacts {
    #[allow(dead_code, reason = "wired into coordinator lifecycle facts below")]
    pub(crate) const fn new(
        direct_child: Option<ChildExitStatus>,
        descendants: DescendantCleanupStatus,
        native_error: Option<i32>,
    ) -> Self {
        Self {
            direct_child,
            descendants,
            native_error,
        }
    }

    /// Reaped direct-child status, or `None` when bounded cleanup is incomplete.
    pub const fn direct_child(self) -> Option<ChildExitStatus> {
        self.direct_child
    }

    /// What can safely be claimed about the fresh descendant group.
    pub const fn descendants(self) -> DescendantCleanupStatus {
        self.descendants
    }

    /// Last bounded native errno when cleanup could not complete.
    pub const fn native_error(self) -> Option<i32> {
        self.native_error
    }

    /// Whether the exact direct child has been reaped or was already reaped.
    pub const fn direct_child_complete(self) -> bool {
        self.direct_child.is_some()
    }
}

/// Recoverable coordinator close result.
pub enum CoordinatorCloseOutcome {
    /// No active leases remained and the exact direct child was reaped.
    Closed(ChildCleanupFacts),
    /// Active mappings still retain the session; drop them and retry with the returned owner.
    ActiveLeases {
        /// Unconsumed live session owner.
        session: CoordinatorSession<Ready>,
        /// Bounded current active mapping facts.
        facts: ActiveLeaseFacts,
    },
    /// The deadline elapsed or cleanup failed; the returned owner retains exact child authority.
    CleanupPending {
        /// Unconsumed live session owner.
        session: CoordinatorSession<Ready>,
        /// Bounded cleanup facts from this attempt.
        facts: ChildCleanupFacts,
        /// Exact close failure category and the same retained cleanup evidence.
        failure: SessionFailure,
    },
    /// An unexpected local close transition failed without consuming ownership.
    Failed {
        /// Unconsumed session owner that may be aborted or retried.
        session: CoordinatorSession<Ready>,
        /// Bounded failure diagnostics including cleanup already attempted.
        error: SessionFailure,
    },
}

/// Recoverable receiver close result.
pub enum ReceiverCloseOutcome {
    /// No active mappings remained and the inherited endpoint was closed.
    Closed,
    /// Active mappings still retain the session; drop them and retry with the returned owner.
    ActiveLeases {
        /// Unconsumed live session owner.
        session: ReceiverSession<Ready>,
        /// Bounded current active mapping facts.
        facts: ActiveLeaseFacts,
    },
    /// An unexpected local close transition failed without consuming ownership.
    Failed {
        /// Unconsumed session owner that may be aborted or retried.
        session: ReceiverSession<Ready>,
        /// Bounded local failure diagnostics.
        error: SessionFailure,
    },
}

/// Terminal coordinator abort result with bounded cleanup diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CoordinatorAbortOutcome {
    cleanup: ChildCleanupFacts,
    failure: Option<SessionFailure>,
}

impl CoordinatorAbortOutcome {
    /// Bounded exact-child and descendant cleanup facts.
    pub const fn cleanup(self) -> ChildCleanupFacts {
        self.cleanup
    }

    /// Failure record when bounded termination/reap did not complete.
    pub const fn failure(self) -> Option<SessionFailure> {
        self.failure
    }
}

/// Role- and state-typed session owner.
///
/// The role aliases [`CoordinatorSession`] and [`ReceiverSession`] are the
/// ordinary spellings. Session values are movable but deliberately not
/// shareable between threads; every control transition requires `&mut self`.
pub struct Session<Role, State> {
    inner: SessionInner,
    role: PhantomData<Role>,
    state: PhantomData<State>,
    not_sync: PhantomData<Cell<()>>,
}

/// Coordinator-owned exact-child session in the supplied typestate.
pub type CoordinatorSession<State> = Session<Coordinator, State>;
/// Receiver-owned inherited-bootstrap session in the supplied typestate.
pub type ReceiverSession<State> = Session<Receiver, State>;

/// Unique inherited receiver bootstrap authority.
///
/// Ordinary helpers obtain this token only from [`crate::receiver_main!`]. Consuming
/// the token transfers the sole inherited native endpoint into negotiation;
/// it is non-cloneable and exposes no raw descriptor.
pub struct ReceiverBootstrap {
    #[cfg(target_os = "linux")]
    inherited: OwnedFd,
    not_sync: PhantomData<Cell<()>>,
}

/// Defines a helper-process entry point with one ownership-bearing bootstrap.
///
/// The supplied closure receives `Result<ReceiverBootstrap, SessionFailure>` and
/// runs only after the library has attempted the one-shot reservation take.
/// Linux validates and reserves its inherited descriptor in an ELF
/// pre-initializer. macOS consumes its one-shot bootstrap designation from
/// Rust main and scrubs the public marker there; the Mach nonce and parent
/// identity are taken and scrubbed when the receiver session connects.
/// Windows takes and scrubs its pipe, nonce, and parent designation when the
/// receiver session connects from the environment.
#[macro_export]
macro_rules! receiver_main {
    ($entry:expr) => {
        #[cfg(target_os = "linux")]
        #[used]
        #[unsafe(link_section = ".preinit_array")]
        static NATIVE_IPC_RECEIVER_BOOTSTRAP_PREINIT: unsafe extern "C" fn(
            ::core::ffi::c_int,
            *mut *mut ::core::ffi::c_char,
            *mut *mut ::core::ffi::c_char,
        ) = $crate::session::__receiver_bootstrap_preinit;

        fn main() {
            let bootstrap = $crate::session::__take_receiver_bootstrap();
            ($entry)(bootstrap);
        }
    };
}

/// Takes the pre-initialized inherited endpoint exactly once.
///
/// This is exported only so [`crate::receiver_main!`] can expand in downstream
/// crates. Applications must invoke that macro instead of calling this hook.
#[doc(hidden)]
pub fn __take_receiver_bootstrap() -> Result<ReceiverBootstrap, SessionFailure> {
    #[cfg(target_os = "linux")]
    {
        let raw = RECEIVER_BOOTSTRAP_FD.swap(BOOTSTRAP_TAKEN, Ordering::AcqRel);
        if raw < 3 {
            return Err(SessionFailure::new(
                SessionOperation::Bootstrap,
                SessionTransactionState::NotEstablished,
                SessionError::InvalidInput,
            ));
        }
        // SAFETY: the pre-initializer reserved this validated descriptor for
        // the one successful atomic take and installed CLOEXEC before main.
        let inherited = unsafe { OwnedFd::from_raw_fd(raw) };
        Ok(ReceiverBootstrap {
            inherited,
            not_sync: PhantomData,
        })
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Err(SessionFailure::new(
            SessionOperation::Bootstrap,
            SessionTransactionState::NotEstablished,
            SessionError::BackendUnavailable,
        ))
    }
    #[cfg(target_os = "windows")]
    {
        if RECEIVER_BOOTSTRAP_TAKEN.swap(true, Ordering::AcqRel)
            || std::env::var_os("NATIVE_IPC_VNEXT_PUBLIC_BOOTSTRAP").as_deref()
                != Some(std::ffi::OsStr::new("1"))
        {
            return Err(SessionFailure::new(
                SessionOperation::Bootstrap,
                SessionTransactionState::NotEstablished,
                SessionError::InvalidInput,
            ));
        }
        Ok(ReceiverBootstrap {
            not_sync: PhantomData,
        })
    }
    #[cfg(target_os = "macos")]
    {
        if RECEIVER_BOOTSTRAP_TAKEN.swap(true, Ordering::AcqRel)
            || std::env::var_os("NATIVE_IPC_VNEXT_PUBLIC_BOOTSTRAP").as_deref()
                != Some(std::ffi::OsStr::new("1"))
        {
            return Err(SessionFailure::new(
                SessionOperation::Bootstrap,
                SessionTransactionState::NotEstablished,
                SessionError::InvalidInput,
            ));
        }
        // Scrub the one-shot routing marker so descendants of this receiver
        // cannot reinterpret its bootstrap designation, matching the Linux
        // pre-init and Windows connect scrubs. The Mach nonce and parent PID are
        // scrubbed where they are consumed, in `ChildChannel::connect_from_environment`.
        // SAFETY: the bootstrap environment is process-local startup state
        // consumed exactly once here before any application or descendant code.
        unsafe { std::env::remove_var("NATIVE_IPC_VNEXT_PUBLIC_BOOTSTRAP") };
        Ok(ReceiverBootstrap {
            not_sync: PhantomData,
        })
    }
}

enum SessionInner {
    #[cfg(target_os = "linux")]
    CoordinatorNegotiating(crate::backend::linux_vnext::spawn::LinuxCoordinatorNegotiatingSession),
    #[cfg(target_os = "linux")]
    ReceiverNegotiating(crate::backend::linux_vnext::spawn::LinuxReceiverNegotiatingSession),
    #[cfg(target_os = "linux")]
    CoordinatorReady(crate::backend::linux_vnext::spawn::LinuxCoordinatorReadySession),
    #[cfg(target_os = "linux")]
    ReceiverReady(crate::backend::linux_vnext::spawn::LinuxReceiverReadySession),
    #[cfg(target_os = "macos")]
    CoordinatorNegotiating(crate::backend::macos::vnext_session::MacCoordinatorNegotiatingSession),
    #[cfg(target_os = "macos")]
    ReceiverNegotiating(crate::backend::macos::vnext_session::MacReceiverNegotiatingSession),
    #[cfg(target_os = "macos")]
    CoordinatorReady(crate::backend::macos::vnext_session::MacCoordinatorReadySession),
    #[cfg(target_os = "macos")]
    ReceiverReady(crate::backend::macos::vnext_session::MacReceiverReadySession),
    #[cfg(target_os = "windows")]
    CoordinatorNegotiating(
        Box<crate::backend::windows::vnext_session::WindowsCoordinatorNegotiatingSession>,
    ),
    #[cfg(target_os = "windows")]
    ReceiverNegotiating(
        Box<crate::backend::windows::vnext_session::WindowsReceiverNegotiatingSession>,
    ),
    #[cfg(target_os = "windows")]
    CoordinatorReady(Box<crate::backend::windows::vnext_session::WindowsCoordinatorReadySession>),
    #[cfg(target_os = "windows")]
    ReceiverReady(Box<crate::backend::windows::vnext_session::WindowsReceiverReadySession>),
    #[allow(dead_code)]
    Unavailable,
}

/// Required executable-identity policy for an owned helper launch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExecutableIdentityPolicy {
    /// Open and retain one absolute regular executable without any symlink
    /// traversal and apply the target's documented image-identity checks.
    /// Linux executes the held object directly. macOS authenticates the
    /// running image against the retained file by content: the kernel-
    /// registered code-directory hash of the exact audit-token-bound child
    /// execution must match a hash computed from the held descriptor, at
    /// launch and again through ACCEPT, independent of pathnames and of the
    /// signing identity (an ad-hoc linker signature suffices). A macOS
    /// executable that carries no code directory — an unsigned image or a
    /// script — cannot be bound and fails construction closed. Windows
    /// retains the opened file, spawns from the retained image, binds the
    /// session transport to the exact spawned process identity, and holds
    /// the child and its descendants in a kill-on-close Job.
    ExactOpenedFile,
}

/// Exact child command. The environment is explicit and starts empty.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionCommand {
    executable: PathBuf,
    arguments: Vec<OsString>,
    environment: Vec<(OsString, OsString)>,
}

impl SessionCommand {
    /// Starts a command whose argument zero is the supplied executable path.
    pub fn new(executable: impl Into<PathBuf>) -> Self {
        let executable = executable.into();
        Self {
            arguments: vec![executable.as_os_str().to_owned()],
            executable,
            environment: Vec::new(),
        }
    }

    /// Replaces argument zero without changing the selected executable path.
    pub fn arg0(mut self, argument: impl Into<OsString>) -> Self {
        self.arguments[0] = argument.into();
        self
    }

    /// Appends one exact child argument.
    pub fn arg(mut self, argument: impl Into<OsString>) -> Self {
        self.arguments.push(argument.into());
        self
    }

    /// Adds or replaces one exact child environment entry.
    pub fn env(mut self, key: impl Into<OsString>, value: impl Into<OsString>) -> Self {
        let key = key.into();
        let value = value.into();
        if let Some((_, existing)) = self
            .environment
            .iter_mut()
            .find(|(existing, _)| *existing == key)
        {
            *existing = value;
        } else {
            self.environment.push((key, value));
        }
        self
    }

    /// The cross-platform union of reserved bootstrap environment names.
    /// Every target rejects the full union so a command that spawns on one
    /// platform is not silently accepted with a reserved key on another.
    fn has_reserved_environment(&self) -> bool {
        const RESERVED: [&str; 6] = [
            "NATIVE_IPC_VNEXT_BOOTSTRAP_FD",
            "NATIVE_IPC_VNEXT_PUBLIC_BOOTSTRAP",
            "NATIVE_IPC_MACH_NONCE",
            "NATIVE_IPC_PARENT_PID",
            "NATIVE_IPC_WINDOWS_PIPE",
            "NATIVE_IPC_WINDOWS_NONCE",
        ];
        self.environment.iter().any(|(key, _)| {
            RESERVED
                .iter()
                .any(|name| key.as_os_str() == std::ffi::OsStr::new(name))
        })
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    pub(crate) fn executable(&self) -> &Path {
        &self.executable
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    pub(crate) fn arguments(&self) -> &[OsString] {
        &self.arguments
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    pub(crate) fn environment(&self) -> &[(OsString, OsString)] {
        &self.environment
    }
}

/// Finite negotiation inputs retained under one caller-derived deadline.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionOptions {
    deadline: AbsoluteDeadline,
    limits: SessionLimits,
    application_payload: Vec<u8>,
    executable_identity: ExecutableIdentityPolicy,
    require_atomic_u32: bool,
    require_atomic_u64: bool,
}

impl SessionOptions {
    /// Creates an exact-deadline offer with finite default limits.
    pub fn new(deadline: AbsoluteDeadline, executable_identity: ExecutableIdentityPolicy) -> Self {
        Self {
            deadline,
            limits: SessionLimits::default(),
            application_payload: Vec::new(),
            executable_identity,
            require_atomic_u32: false,
            require_atomic_u64: false,
        }
    }

    /// Replaces the finite local limit offer.
    pub fn with_limits(mut self, limits: SessionLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Replaces the bounded opaque application HELLO payload.
    pub fn with_application_payload(mut self, payload: Vec<u8>) -> Self {
        self.application_payload = payload;
        self
    }

    /// Requires lock-free cross-process 32-bit atomic support.
    pub fn require_atomic_u32(mut self) -> Self {
        self.require_atomic_u32 = true;
        self
    }

    /// Requires lock-free cross-process 64-bit atomic support.
    pub fn require_atomic_u64(mut self) -> Self {
        self.require_atomic_u64 = true;
        self
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    pub(crate) const fn limits(&self) -> SessionLimits {
        self.limits
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    pub(crate) fn application_payload(&self) -> &[u8] {
        &self.application_payload
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    pub(crate) const fn requires_atomic_u32(&self) -> bool {
        self.require_atomic_u32
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    pub(crate) const fn requires_atomic_u64(&self) -> bool {
        self.require_atomic_u64
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    pub(crate) const fn deadline(&self) -> AbsoluteDeadline {
        self.deadline
    }
}

/// Endpoint that made a clean application negotiation rejection.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionEndpoint {
    /// Spawning owner of the exact helper.
    Coordinator,
    /// Exact inherited-bootstrap helper.
    Receiver,
}

/// Nonzero application negotiation rejection reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RejectionReason(NonZeroU32);

impl RejectionReason {
    /// The application declined without a more specific incompatibility.
    pub const APPLICATION_DECLINED: Self = Self(NonZeroU32::MIN);
    /// Application protocols or schemas are incompatible.
    pub const INCOMPATIBLE_APPLICATION_PROTOCOL: Self =
        Self(NonZeroU32::new(2).expect("two is nonzero"));
    /// Local application policy rejected the peer.
    pub const APPLICATION_POLICY: Self = Self(NonZeroU32::new(3).expect("three is nonzero"));

    /// Constructs an application-specific reason from the high-half namespace.
    pub const fn application_specific(value: u32) -> Option<Self> {
        if value < 0x8000_0000 {
            return None;
        }
        match NonZeroU32::new(value) {
            Some(value) => Some(Self(value)),
            None => None,
        }
    }

    /// Numeric wire value for logging or application dispatch.
    pub const fn get(self) -> u32 {
        self.0.get()
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    fn from_wire(value: NonZeroU32) -> Option<Self> {
        match value.get() {
            1 => Some(Self::APPLICATION_DECLINED),
            2 => Some(Self::INCOMPATIBLE_APPLICATION_PROTOCOL),
            3 => Some(Self::APPLICATION_POLICY),
            value => Self::application_specific(value),
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    const fn as_nonzero(self) -> NonZeroU32 {
        self.0
    }
}

/// Explicit application decision after the peer HELLO is available.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NegotiationDecision {
    /// Accept the peer's bounded opaque HELLO payload and negotiated facts.
    Accept,
    /// Cleanly reject with a fixed nonzero application reason.
    Reject(RejectionReason),
}

/// Clean application-level result of the challenged negotiation.
pub enum NegotiationOutcome<T> {
    /// Bilateral exact ACCEPT yielded the ready session owner.
    Accepted(T),
    /// One endpoint made a canonical clean application rejection.
    Rejected {
        /// Endpoint that rejected.
        by: SessionEndpoint,
        /// Exact nonzero reason carried by the peer or local decision.
        reason: RejectionReason,
        /// Coordinator-owned child cleanup facts; receivers have no child authority.
        cleanup: Option<ChildCleanupFacts>,
    },
}

/// Public session construction, negotiation, or control failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionError {
    /// The selected native target adapter is not composed yet.
    BackendUnavailable,
    /// Local command, environment, payload, or option input is invalid.
    InvalidInput,
    /// The one caller-derived absolute deadline expired.
    DeadlineExpired,
    /// The authenticated control endpoint closed before the operation completed.
    PeerDisconnected,
    /// Kernel-authenticated process or executable identity did not match.
    IdentityMismatch,
    /// The peer supplied malformed or noncanonical framing.
    MalformedPeer,
    /// Local I/O completed at the deadline boundary with unknowable peer state.
    Ambiguous,
    /// HELLO or challenged decision validation failed.
    NegotiationFailed,
    /// Local native capability discovery or limit negotiation failed.
    NativeNegotiation(NegotiationError),
    /// Application-control sequencing or bounds validation failed.
    Control(ControlError),
    /// Portable batch construction or committed-set validation failed.
    Batch(BatchError),
    /// Current active region or byte capacity cannot admit the whole batch.
    ActiveLimit,
    /// The peer reported a bounded local native-preparation failure before capability transfer.
    PeerPreparationFailed,
    /// Native mapping activation failed atomically without exposing a partial set.
    ActivationFailed,
    /// Native negotiation transport was already terminally poisoned.
    Poisoned,
    /// A bounded native operation failed without a more specific safe category.
    Native,
}

impl core::fmt::Display for SessionError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "session operation failed: {self:?}")
    }
}

impl std::error::Error for SessionError {}

/// Bounded public operation category attached to a session failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionOperation {
    /// Process-entry bootstrap adoption.
    Bootstrap,
    /// Exact child spawn and authenticated HELLO exchange.
    Spawn,
    /// Bilateral application negotiation.
    Negotiate,
    /// Nonblocking peer observation.
    PollPeer,
    /// Bounded peer/direct-child wait.
    WaitForExit,
    /// Graceful session close.
    Close,
    /// Terminal session abort.
    Abort,
    /// Coordinator capability transfer and activation.
    TransferBatch,
    /// Receiver capability import and activation.
    ReceiveBatch,
    /// Opaque application-control send.
    SendControl,
    /// Opaque application-control receive.
    ReceiveControl,
}

/// Bounded reducer state observed for a failed public operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionTransactionState {
    /// No session owner had been established.
    NotEstablished,
    /// An exact child exists, but authenticated HELLO negotiation has not begun.
    Spawned,
    /// The authenticated endpoints were still negotiating.
    Negotiating,
    /// The accepted control reducer was idle and ready.
    Ready,
    /// A native capability transaction had begun. Only backends whose batch
    /// activation is non-atomic report this state (Linux); macOS and Windows
    /// activate atomically and expose no partially-open transaction, so a
    /// portable consumer must not depend on observing it on every target.
    TransactionOpen,
    /// The session reducer was terminally poisoned.
    Poisoned,
}

/// Bounded diagnostics retained for a failed public session operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionFailure {
    operation: SessionOperation,
    transaction_state: SessionTransactionState,
    reason: SessionError,
    native_code: Option<i32>,
    poisoned: bool,
    peer: Option<PeerStatus>,
    cleanup: Option<ChildCleanupFacts>,
}

impl SessionFailure {
    const fn new(
        operation: SessionOperation,
        transaction_state: SessionTransactionState,
        reason: SessionError,
    ) -> Self {
        Self {
            operation,
            transaction_state,
            reason,
            native_code: None,
            poisoned: matches!(transaction_state, SessionTransactionState::Poisoned),
            peer: if matches!(reason, SessionError::PeerDisconnected) {
                Some(PeerStatus::Disconnected)
            } else {
                None
            },
            cleanup: None,
        }
    }

    const fn with_cleanup(mut self, cleanup: ChildCleanupFacts) -> Self {
        self.cleanup = Some(cleanup);
        self
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    const fn with_optional_cleanup(mut self, cleanup: Option<ChildCleanupFacts>) -> Self {
        self.cleanup = cleanup;
        self
    }

    const fn with_native_code(mut self, native_code: Option<i32>) -> Self {
        self.native_code = native_code;
        self
    }

    const fn with_poisoned(mut self, poisoned: bool) -> Self {
        self.poisoned = poisoned;
        self
    }

    /// Public operation that failed.
    pub const fn operation(self) -> SessionOperation {
        self.operation
    }

    /// Reducer/transaction state observed for the failure.
    pub const fn transaction_state(self) -> SessionTransactionState {
        self.transaction_state
    }

    /// Portable bounded failure reason.
    pub const fn reason(self) -> SessionError {
        self.reason
    }

    /// Native error code when the backend can preserve one safely.
    pub const fn native_code(self) -> Option<i32> {
        self.native_code
    }

    /// Whether the operation left the session terminally poisoned.
    pub const fn is_poisoned(self) -> bool {
        self.poisoned
    }

    /// Bounded peer observation associated with the failure.
    pub const fn peer(self) -> Option<PeerStatus> {
        self.peer
    }

    /// Coordinator-owned cleanup facts, when this operation consumed child authority.
    pub const fn cleanup(self) -> Option<ChildCleanupFacts> {
        self.cleanup
    }
}

impl core::fmt::Display for SessionFailure {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            formatter,
            "session {:?} failed in {:?}: {:?}",
            self.operation, self.transaction_state, self.reason
        )
    }
}

impl std::error::Error for SessionFailure {}

/// Finite resource limits offered and negotiated by both endpoints.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionLimits {
    /// Maximum entries in one batch; hard maximum sixteen.
    pub max_regions_per_batch: u16,
    /// Maximum logical bytes in one region.
    pub max_region_bytes: u64,
    /// Maximum aggregate logical/mapped bytes in one batch.
    pub max_batch_bytes: u64,
    /// Maximum charged active region mappings.
    pub max_active_regions: u32,
    /// Maximum charged active mapping bytes.
    pub max_active_bytes: u64,
    /// Maximum monotonically increasing transactions.
    pub max_transactions: u64,
    /// Maximum opaque HELLO application payload bytes.
    pub max_bootstrap_payload_bytes: u32,
    /// Maximum opaque application-control payload bytes.
    pub max_control_payload_bytes: u32,
}

impl Default for SessionLimits {
    fn default() -> Self {
        Self {
            max_regions_per_batch: 16,
            max_region_bytes: 256 * 1024 * 1024,
            max_batch_bytes: 1024 * 1024 * 1024,
            max_active_regions: 4096,
            max_active_bytes: 8 * 1024 * 1024 * 1024,
            max_transactions: 1 << 32,
            max_bootstrap_payload_bytes: 1024 * 1024,
            max_control_payload_bytes: 1024 * 1024,
        }
    }
}

/// Invalid local or peer negotiation offer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NegotiationError {
    /// A numeric limit is zero.
    ZeroLimit,
    /// A numeric limit exceeds its field-specific hard maximum.
    AboveHardMaximum,
    /// A byte limit cannot narrow to this target's `usize`.
    NativeSizeNarrowing,
    /// Required lock-free atomic width is not available.
    AtomicUnsupported,
    /// A monotonic deadline cannot be represented.
    InvalidDeadline,
}

impl core::fmt::Display for NegotiationError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "session negotiation failed: {self:?}")
    }
}

impl std::error::Error for NegotiationError {}

impl SessionLimits {
    /// Validates every field before allocation or native import.
    pub fn validate(self) -> Result<Self, NegotiationError> {
        self.validate_for_native_max(usize::MAX as u64)
    }

    fn validate_for_native_max(self, native_usize_max: u64) -> Result<Self, NegotiationError> {
        if self.max_regions_per_batch == 0
            || self.max_region_bytes == 0
            || self.max_batch_bytes == 0
            || self.max_active_regions == 0
            || self.max_active_bytes == 0
            || self.max_transactions == 0
            || self.max_bootstrap_payload_bytes == 0
            || self.max_control_payload_bytes == 0
        {
            return Err(NegotiationError::ZeroLimit);
        }
        if self.max_regions_per_batch > HARD_MAX_REGIONS_PER_BATCH
            || self.max_region_bytes > HARD_MAX_REGION_BYTES
            || self.max_batch_bytes > HARD_MAX_BATCH_BYTES
            || self.max_active_regions > HARD_MAX_ACTIVE_REGIONS
            || self.max_active_bytes > HARD_MAX_ACTIVE_BYTES
            || self.max_transactions > HARD_MAX_TRANSACTIONS
            || self.max_bootstrap_payload_bytes > HARD_MAX_BOOTSTRAP_PAYLOAD_BYTES
            || self.max_control_payload_bytes > HARD_MAX_CONTROL_PAYLOAD_BYTES
        {
            return Err(NegotiationError::AboveHardMaximum);
        }
        if self.max_region_bytes > native_usize_max
            || self.max_batch_bytes > native_usize_max
            || self.max_active_bytes > native_usize_max
            || u64::from(self.max_bootstrap_payload_bytes) > native_usize_max
            || u64::from(self.max_control_payload_bytes) > native_usize_max
        {
            return Err(NegotiationError::NativeSizeNarrowing);
        }
        Ok(self)
    }

    /// Computes checked effective minima after validating both offers.
    pub fn negotiate(local: Self, peer: Self) -> Result<Self, NegotiationError> {
        let local = local.validate()?;
        let peer = peer.validate()?;
        Self {
            max_regions_per_batch: local.max_regions_per_batch.min(peer.max_regions_per_batch),
            max_region_bytes: local.max_region_bytes.min(peer.max_region_bytes),
            max_batch_bytes: local.max_batch_bytes.min(peer.max_batch_bytes),
            max_active_regions: local.max_active_regions.min(peer.max_active_regions),
            max_active_bytes: local.max_active_bytes.min(peer.max_active_bytes),
            max_transactions: local.max_transactions.min(peer.max_transactions),
            max_bootstrap_payload_bytes: local
                .max_bootstrap_payload_bytes
                .min(peer.max_bootstrap_payload_bytes),
            max_control_payload_bytes: local
                .max_control_payload_bytes
                .min(peer.max_control_payload_bytes),
        }
        .validate()
    }
}

/// Cross-process atomic and layout alignment facts for the selected target.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AtomicCapabilities {
    atomic_u32_lock_free: bool,
    atomic_u32_alignment: usize,
    atomic_u64_lock_free: bool,
    atomic_u64_alignment: usize,
    page_alignment: usize,
    cache_line_alignment: usize,
}

impl AtomicCapabilities {
    pub(crate) const fn from_accepted_offer(value: crate::negotiation::AtomicOffer) -> Self {
        Self {
            atomic_u32_lock_free: value.u32_lock_free,
            atomic_u32_alignment: value.u32_alignment as usize,
            atomic_u64_lock_free: value.u64_lock_free,
            atomic_u64_alignment: value.u64_alignment as usize,
            page_alignment: value.page_alignment as usize,
            cache_line_alignment: value.cache_line_alignment as usize,
        }
    }

    /// Constructs facts only after private native discovery has established
    /// lock freedom and runtime page/cache-line alignment.
    #[allow(dead_code, reason = "wired into native HELLO discovery in phase 4b")]
    pub(crate) fn from_verified_native(
        page_alignment: usize,
        cache_line_alignment: usize,
        atomic_u32_lock_free: bool,
        atomic_u64_lock_free: bool,
    ) -> Result<Self, NegotiationError> {
        let atomic_u32_alignment = core::mem::align_of::<core::sync::atomic::AtomicU32>();
        let atomic_u64_alignment = core::mem::align_of::<core::sync::atomic::AtomicU64>();
        if !page_alignment.is_power_of_two()
            || !cache_line_alignment.is_power_of_two()
            || page_alignment < atomic_u32_alignment.max(atomic_u64_alignment)
            || cache_line_alignment < atomic_u32_alignment.max(atomic_u64_alignment)
        {
            return Err(NegotiationError::AtomicUnsupported);
        }
        Ok(Self {
            atomic_u32_lock_free,
            atomic_u32_alignment,
            atomic_u64_lock_free,
            atomic_u64_alignment,
            page_alignment,
            cache_line_alignment,
        })
    }

    /// Whether private target discovery established lock-free 32-bit atomics.
    pub fn atomic_u32_lock_free(self) -> bool {
        self.atomic_u32_lock_free
    }

    /// Required alignment for an atomic 32-bit value.
    pub fn atomic_u32_alignment(self) -> usize {
        self.atomic_u32_alignment
    }

    /// Whether private target discovery established lock-free 64-bit atomics.
    pub fn atomic_u64_lock_free(self) -> bool {
        self.atomic_u64_lock_free
    }

    /// Required alignment for an atomic 64-bit value.
    pub fn atomic_u64_alignment(self) -> usize {
        self.atomic_u64_alignment
    }

    /// Runtime native page alignment.
    pub fn page_alignment(self) -> usize {
        self.page_alignment
    }

    /// Runtime native cache-line alignment used by application layouts.
    pub fn cache_line_alignment(self) -> usize {
        self.cache_line_alignment
    }

    /// Rejects negotiation if required widths are unavailable.
    #[allow(dead_code, reason = "wired into native HELLO negotiation in phase 4b")]
    pub(crate) fn require(
        self,
        u32_required: bool,
        u64_required: bool,
    ) -> Result<Self, NegotiationError> {
        if (u32_required && !self.atomic_u32_lock_free)
            || (u64_required && !self.atomic_u64_lock_free)
        {
            return Err(NegotiationError::AtomicUnsupported);
        }
        Ok(self)
    }
}

/// One monotonic absolute deadline shared by a complete operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AbsoluteDeadline(Instant);

impl AbsoluteDeadline {
    /// Derives a deadline once at operation entry.
    pub fn after(duration: Duration) -> Result<Self, NegotiationError> {
        if duration.is_zero() {
            return Err(NegotiationError::InvalidDeadline);
        }
        Instant::now()
            .checked_add(duration)
            .map(Self)
            .ok_or(NegotiationError::InvalidDeadline)
    }

    /// Returns the remaining duration, or zero after expiry.
    pub fn remaining(self) -> Duration {
        self.0.saturating_duration_since(Instant::now())
    }

    /// Whether the absolute deadline has expired.
    pub fn is_expired(self) -> bool {
        self.remaining().is_zero()
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
impl<Role, State> Session<Role, State> {
    fn from_inner(inner: SessionInner) -> Self {
        Self {
            inner,
            role: PhantomData,
            state: PhantomData,
            not_sync: PhantomData,
        }
    }
}

impl Session<Coordinator, Negotiating> {
    /// Spawns and authenticates the selected helper under the target's
    /// documented executable-identity policy through both HELLOs.
    pub fn spawn(command: SessionCommand, options: SessionOptions) -> Result<Self, SessionFailure> {
        validate_public_options(&options).map_err(|reason| {
            SessionFailure::new(
                SessionOperation::Spawn,
                SessionTransactionState::NotEstablished,
                reason,
            )
        })?;
        if command.has_reserved_environment() {
            return Err(SessionFailure::new(
                SessionOperation::Spawn,
                SessionTransactionState::NotEstablished,
                SessionError::InvalidInput,
            ));
        }
        #[cfg(target_os = "linux")]
        {
            let inner =
                crate::backend::linux_vnext::spawn::LinuxCoordinatorNegotiatingSession::spawn(
                    &command, &options,
                )
                .map_err(|failure| {
                    let native_code = linux_public_native_code(failure.error);
                    let transaction_state = match failure.state {
                        crate::backend::linux_vnext::spawn::LinuxCoordinatorFailureState::NotEstablished => {
                            SessionTransactionState::NotEstablished
                        }
                        crate::backend::linux_vnext::spawn::LinuxCoordinatorFailureState::Spawned => {
                            SessionTransactionState::Spawned
                        }
                        crate::backend::linux_vnext::spawn::LinuxCoordinatorFailureState::Negotiating => {
                            SessionTransactionState::Negotiating
                        }
                    };
                    SessionFailure::new(
                        SessionOperation::Spawn,
                        transaction_state,
                        failure.error.into(),
                    )
                    .with_native_code(native_code)
                    .with_poisoned(failure.poisoned)
                    .with_optional_cleanup(failure.cleanup)
                })?;
            Ok(Self::from_inner(SessionInner::CoordinatorNegotiating(
                inner,
            )))
        }
        #[cfg(target_os = "macos")]
        {
            let inner =
                crate::backend::macos::vnext_session::MacCoordinatorNegotiatingSession::spawn(
                    &command, &options,
                )
                .map_err(|failure| {
                    let transaction_state = match failure.state {
                        crate::backend::macos::vnext_session::MacCoordinatorFailureState::NotEstablished => {
                            SessionTransactionState::NotEstablished
                        }
                        crate::backend::macos::vnext_session::MacCoordinatorFailureState::Spawned => {
                            SessionTransactionState::Spawned
                        }
                        crate::backend::macos::vnext_session::MacCoordinatorFailureState::Negotiating => {
                            SessionTransactionState::Negotiating
                        }
                    };
                    mac_session_failure(
                        SessionOperation::Spawn,
                        transaction_state,
                        failure.error,
                        failure.poisoned,
                    )
                    .with_optional_cleanup(failure.cleanup)
                })?;
            Ok(Self::from_inner(SessionInner::CoordinatorNegotiating(
                inner,
            )))
        }
        #[cfg(target_os = "windows")]
        {
            let inner = crate::backend::windows::vnext_session::WindowsCoordinatorNegotiatingSession::spawn(
                &command,
                &options,
            )
            .map_err(|failure| {
                let transaction_state = match failure.state {
                    crate::backend::windows::vnext_session::WindowsCoordinatorFailureState::NotEstablished => SessionTransactionState::NotEstablished,
                    crate::backend::windows::vnext_session::WindowsCoordinatorFailureState::Spawned => SessionTransactionState::Spawned,
                    crate::backend::windows::vnext_session::WindowsCoordinatorFailureState::Negotiating => SessionTransactionState::Negotiating,
                };
                windows_session_failure(
                    SessionOperation::Spawn,
                    transaction_state,
                    failure.error,
                    failure.poisoned,
                )
                .with_optional_cleanup(failure.cleanup)
            })?;
            Ok(Self::from_inner(SessionInner::CoordinatorNegotiating(
                Box::new(inner),
            )))
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            let _ = command;
            Err(SessionFailure::new(
                SessionOperation::Spawn,
                SessionTransactionState::NotEstablished,
                SessionError::BackendUnavailable,
            ))
        }
    }

    /// Peer HELLO application payload, available before the coordinator decides.
    pub fn peer_application_payload(&self) -> &[u8] {
        match &self.inner {
            #[cfg(target_os = "linux")]
            SessionInner::CoordinatorNegotiating(inner) => inner.peer_application_payload(),
            #[cfg(target_os = "macos")]
            SessionInner::CoordinatorNegotiating(inner) => inner.peer_application_payload(),
            #[cfg(target_os = "windows")]
            SessionInner::CoordinatorNegotiating(inner) => inner.peer_application_payload(),
            #[cfg(target_os = "linux")]
            _ => unreachable!("coordinator negotiating typestate owns its exact backend state"),
            #[cfg(target_os = "macos")]
            _ => unreachable!("coordinator negotiating typestate owns its exact backend state"),
            #[cfg(target_os = "windows")]
            _ => unreachable!("coordinator negotiating typestate owns its exact backend state"),
            #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
            SessionInner::Unavailable => {
                unreachable!("unavailable backend cannot construct a session")
            }
        }
    }

    /// Makes the explicit coordinator decision and awaits the receiver decision.
    pub fn decide(
        self,
        decision: NegotiationDecision,
    ) -> Result<NegotiationOutcome<Session<Coordinator, Ready>>, SessionFailure> {
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        let _ = decision;
        match self.inner {
            #[cfg(target_os = "linux")]
            SessionInner::CoordinatorNegotiating(inner) => {
                let outcome = inner
                    .decide(decision_rejection(decision))
                    .map_err(|failure| {
                        let native_code = linux_public_native_code(failure.error);
                        SessionFailure::new(
                            SessionOperation::Negotiate,
                            SessionTransactionState::Negotiating,
                            failure.error.into(),
                        )
                        .with_native_code(native_code)
                        .with_poisoned(failure.poisoned)
                        .with_optional_cleanup(failure.cleanup)
                    })?;
                map_linux_coordinator_outcome(outcome)
            }
            #[cfg(target_os = "macos")]
            SessionInner::CoordinatorNegotiating(inner) => {
                let outcome = inner
                    .decide(decision_rejection(decision))
                    .map_err(|failure| {
                        mac_session_failure(
                            SessionOperation::Negotiate,
                            SessionTransactionState::Negotiating,
                            failure.error,
                            failure.poisoned,
                        )
                        .with_optional_cleanup(failure.cleanup)
                    })?;
                map_mac_coordinator_outcome(outcome)
            }
            #[cfg(target_os = "windows")]
            SessionInner::CoordinatorNegotiating(inner) => {
                let outcome = (*inner)
                    .decide(decision_rejection(decision))
                    .map_err(|failure| {
                        windows_session_failure(
                            SessionOperation::Negotiate,
                            SessionTransactionState::Negotiating,
                            failure.error,
                            failure.poisoned,
                        )
                        .with_optional_cleanup(failure.cleanup)
                    })?;
                map_windows_coordinator_outcome(outcome)
            }
            #[cfg(target_os = "linux")]
            _ => unreachable!("coordinator negotiating typestate owns its exact backend state"),
            #[cfg(target_os = "macos")]
            _ => unreachable!("coordinator negotiating typestate owns its exact backend state"),
            #[cfg(target_os = "windows")]
            _ => unreachable!("coordinator negotiating typestate owns its exact backend state"),
            #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
            SessionInner::Unavailable => {
                unreachable!("unavailable backend cannot construct a session")
            }
        }
    }
}

impl Session<Receiver, Negotiating> {
    /// Consumes the unique process-entry bootstrap and exchanges HELLOs.
    pub fn from_bootstrap(
        bootstrap: ReceiverBootstrap,
        options: SessionOptions,
    ) -> Result<Self, SessionFailure> {
        validate_public_options(&options).map_err(|reason| {
            SessionFailure::new(
                SessionOperation::Bootstrap,
                SessionTransactionState::NotEstablished,
                reason,
            )
        })?;
        #[cfg(target_os = "linux")]
        {
            let inner = crate::backend::linux_vnext::spawn::LinuxReceiverNegotiatingSession::from_inherited_bootstrap(
                bootstrap.inherited,
                options.limits,
                options.application_payload,
                options.require_atomic_u32,
                options.require_atomic_u64,
                options.deadline,
            )
            .map_err(|error| {
                SessionFailure::new(
                    SessionOperation::Bootstrap,
                    SessionTransactionState::Negotiating,
                    error.into(),
                )
                .with_native_code(linux_public_native_code(error))
                .with_poisoned(true)
            })?;
            Ok(Self::from_inner(SessionInner::ReceiverNegotiating(inner)))
        }
        #[cfg(target_os = "macos")]
        {
            let _bootstrap = bootstrap;
            let inner =
                crate::backend::macos::vnext_session::MacReceiverNegotiatingSession::from_environment(
                    options.limits,
                    options.application_payload,
                    options.require_atomic_u32,
                    options.require_atomic_u64,
                    options.deadline,
                )
                .map_err(|error| {
                    // Parity: an absent bootstrap designation or invalid
                    // caller input means no peer exists and nothing was
                    // negotiated, matching the Linux mapping.
                    let invalid_input = matches!(
                        error,
                        crate::backend::macos::vnext_session::MacPublicSessionError::InvalidInput
                    );
                    let state = if invalid_input {
                        SessionTransactionState::NotEstablished
                    } else {
                        SessionTransactionState::Negotiating
                    };
                    mac_session_failure(
                        SessionOperation::Bootstrap,
                        state,
                        error,
                        !invalid_input,
                    )
                })?;
            Ok(Self::from_inner(SessionInner::ReceiverNegotiating(inner)))
        }
        #[cfg(target_os = "windows")]
        {
            let _bootstrap = bootstrap;
            let inner = crate::backend::windows::vnext_session::WindowsReceiverNegotiatingSession::from_environment(&options)
            .map_err(|error| {
                // Parity: an absent bootstrap designation or invalid caller
                // input means no peer exists and nothing was negotiated,
                // matching the Linux mapping.
                let invalid_input = matches!(
                    error,
                    crate::backend::windows::vnext_session::WindowsPublicSessionError::InvalidInput
                );
                let state = if invalid_input {
                    SessionTransactionState::NotEstablished
                } else {
                    SessionTransactionState::Negotiating
                };
                windows_session_failure(
                    SessionOperation::Bootstrap,
                    state,
                    error,
                    !invalid_input,
                )
            })?;
            Ok(Self::from_inner(SessionInner::ReceiverNegotiating(
                Box::new(inner),
            )))
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            let _ = bootstrap;
            Err(SessionFailure::new(
                SessionOperation::Bootstrap,
                SessionTransactionState::NotEstablished,
                SessionError::BackendUnavailable,
            ))
        }
    }

    /// Peer HELLO application payload, available before awaiting the decision.
    pub fn peer_application_payload(&self) -> &[u8] {
        match &self.inner {
            #[cfg(target_os = "linux")]
            SessionInner::ReceiverNegotiating(inner) => inner.peer_application_payload(),
            #[cfg(target_os = "macos")]
            SessionInner::ReceiverNegotiating(inner) => inner.peer_application_payload(),
            #[cfg(target_os = "windows")]
            SessionInner::ReceiverNegotiating(inner) => inner.peer_application_payload(),
            #[cfg(target_os = "linux")]
            _ => unreachable!("receiver negotiating typestate owns its exact backend state"),
            #[cfg(target_os = "macos")]
            _ => unreachable!("receiver negotiating typestate owns its exact backend state"),
            #[cfg(target_os = "windows")]
            _ => unreachable!("receiver negotiating typestate owns its exact backend state"),
            #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
            SessionInner::Unavailable => {
                unreachable!("unavailable backend cannot construct a session")
            }
        }
    }

    /// Awaits exact coordinator ACCEPT before invoking the receiver decision.
    pub fn decide_after_coordinator(
        self,
        decide: impl FnOnce(&[u8]) -> NegotiationDecision,
    ) -> Result<NegotiationOutcome<Session<Receiver, Ready>>, SessionFailure> {
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        let _ = decide;
        match self.inner {
            #[cfg(target_os = "linux")]
            SessionInner::ReceiverNegotiating(inner) => {
                let outcome = inner
                    .decide_after_coordinator(|payload| decision_rejection(decide(payload)))
                    .map_err(|error| {
                        SessionFailure::new(
                            SessionOperation::Negotiate,
                            SessionTransactionState::Negotiating,
                            error.into(),
                        )
                        .with_native_code(linux_public_native_code(error))
                        .with_poisoned(true)
                    })?;
                map_linux_receiver_outcome(outcome)
            }
            #[cfg(target_os = "macos")]
            SessionInner::ReceiverNegotiating(inner) => {
                let outcome = inner
                    .decide_after_coordinator(|payload| decision_rejection(decide(payload)))
                    .map_err(|error| {
                        mac_session_failure(
                            SessionOperation::Negotiate,
                            SessionTransactionState::Negotiating,
                            error,
                            true,
                        )
                    })?;
                map_mac_receiver_outcome(outcome)
            }
            #[cfg(target_os = "windows")]
            SessionInner::ReceiverNegotiating(inner) => {
                let outcome = (*inner)
                    .decide_after_coordinator(|payload| decision_rejection(decide(payload)))
                    .map_err(|error| {
                        windows_session_failure(
                            SessionOperation::Negotiate,
                            SessionTransactionState::Negotiating,
                            error,
                            true,
                        )
                    })?;
                map_windows_receiver_outcome(outcome)
            }
            #[cfg(target_os = "linux")]
            _ => unreachable!("receiver negotiating typestate owns its exact backend state"),
            #[cfg(target_os = "macos")]
            _ => unreachable!("receiver negotiating typestate owns its exact backend state"),
            #[cfg(target_os = "windows")]
            _ => unreachable!("receiver negotiating typestate owns its exact backend state"),
            #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
            SessionInner::Unavailable => {
                unreachable!("unavailable backend cannot construct a session")
            }
        }
    }
}

impl Session<Coordinator, Ready> {
    #[cfg(all(test, target_os = "linux"))]
    pub(crate) fn fail_next_cleanup_signal_for_test(&self, code: i32) {
        match &self.inner {
            SessionInner::CoordinatorReady(inner) => {
                inner.fail_next_cleanup_signal_for_test(code);
            }
            _ => unreachable!("coordinator ready typestate owns its exact backend state"),
        }
    }

    /// Effective finite limits bound into the accepted transcript.
    pub fn negotiated_limits(&self) -> SessionLimits {
        match &self.inner {
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
            SessionInner::CoordinatorReady(inner) => inner.limits(),
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
            _ => unreachable!("coordinator ready typestate owns its exact backend state"),
            #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
            SessionInner::Unavailable => {
                unreachable!("unavailable backend cannot construct a session")
            }
        }
    }

    /// Effective lock-free atomic and layout alignment facts bound into ACCEPT.
    pub fn atomic_capabilities(&self) -> AtomicCapabilities {
        match &self.inner {
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
            SessionInner::CoordinatorReady(inner) => inner.atomics(),
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
            _ => unreachable!("coordinator ready typestate owns its exact backend state"),
            #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
            SessionInner::Unavailable => {
                unreachable!("unavailable backend cannot construct a session")
            }
        }
    }

    /// Accepted protocol version from the exact challenged transcript.
    pub fn protocol_version(&self) -> ProtocolVersion {
        match &self.inner {
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
            SessionInner::CoordinatorReady(inner) => inner.protocol_version(),
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
            _ => unreachable!("coordinator ready typestate owns its exact backend state"),
            #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
            SessionInner::Unavailable => {
                unreachable!("unavailable backend cannot construct a session")
            }
        }
    }

    /// Current local reducer/liveness state.
    pub fn state(&self) -> SessionState {
        match &self.inner {
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
            SessionInner::CoordinatorReady(inner) => inner.state(),
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
            _ => unreachable!("coordinator ready typestate owns its exact backend state"),
            #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
            SessionInner::Unavailable => {
                unreachable!("unavailable backend cannot construct a session")
            }
        }
    }

    /// Bounded current active-mapping lease counters.
    pub fn active_leases(&self) -> ActiveLeaseFacts {
        match &self.inner {
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
            SessionInner::CoordinatorReady(inner) => inner.active_leases(),
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
            _ => unreachable!("coordinator ready typestate owns its exact backend state"),
            #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
            SessionInner::Unavailable => {
                unreachable!("unavailable backend cannot construct a session")
            }
        }
    }

    /// Performs one nonblocking authenticated peer observation.
    pub fn poll_peer(&mut self) -> Result<PeerStatus, SessionFailure> {
        match &mut self.inner {
            #[cfg(target_os = "linux")]
            SessionInner::CoordinatorReady(inner) => {
                let result = inner.poll_peer();
                let state = inner.state();
                result
                    .map_err(|error| linux_ready_failure(SessionOperation::PollPeer, state, error))
            }
            #[cfg(target_os = "macos")]
            SessionInner::CoordinatorReady(inner) => {
                let result = inner.poll_peer();
                let state = inner.state();
                result.map_err(|error| mac_ready_failure(SessionOperation::PollPeer, state, error))
            }
            #[cfg(target_os = "windows")]
            SessionInner::CoordinatorReady(inner) => {
                let result = inner.poll_peer();
                let state = inner.state();
                result.map_err(|error| {
                    windows_ready_failure(SessionOperation::PollPeer, state, error)
                })
            }
            #[cfg(target_os = "linux")]
            _ => unreachable!("coordinator ready typestate owns its exact backend state"),
            #[cfg(target_os = "macos")]
            _ => unreachable!("coordinator ready typestate owns its exact backend state"),
            #[cfg(target_os = "windows")]
            _ => unreachable!("coordinator ready typestate owns its exact backend state"),
            #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
            SessionInner::Unavailable => Err(SessionFailure::new(
                SessionOperation::PollPeer,
                SessionTransactionState::NotEstablished,
                SessionError::BackendUnavailable,
            )),
        }
    }

    /// Boundedly waits for and reaps the exact direct child without consuming the session.
    pub fn wait_for_exit(&mut self, deadline: AbsoluteDeadline) -> ChildCleanupFacts {
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        let _ = deadline;
        match &mut self.inner {
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
            SessionInner::CoordinatorReady(inner) => inner.wait_for_exit(deadline),
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
            _ => unreachable!("coordinator ready typestate owns its exact backend state"),
            #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
            SessionInner::Unavailable => {
                ChildCleanupFacts::new(None, DescendantCleanupStatus::NotEstablished, None)
            }
        }
    }

    /// Gracefully closes only after active leases are gone and the exact child is reaped.
    pub fn try_close(mut self, deadline: AbsoluteDeadline) -> CoordinatorCloseOutcome {
        let facts = self.active_leases();
        if !facts.is_empty() {
            return CoordinatorCloseOutcome::ActiveLeases {
                session: self,
                facts,
            };
        }
        let cleanup = self.wait_for_exit(deadline);
        if !cleanup.direct_child_complete() {
            let reason = if cleanup.native_error().is_some() {
                SessionError::Native
            } else {
                SessionError::DeadlineExpired
            };
            let failure = SessionFailure::new(
                SessionOperation::Close,
                if self.state() == SessionState::Poisoned {
                    SessionTransactionState::Poisoned
                } else {
                    SessionTransactionState::Ready
                },
                reason,
            )
            .with_native_code(cleanup.native_error())
            .with_poisoned(self.state() == SessionState::Poisoned)
            .with_cleanup(cleanup);
            return CoordinatorCloseOutcome::CleanupPending {
                session: self,
                facts: cleanup,
                failure,
            };
        }
        let close: Result<(), SessionFailure> = match &mut self.inner {
            #[cfg(target_os = "linux")]
            SessionInner::CoordinatorReady(inner) => {
                let result = inner.close_resources();
                let state = inner.state();
                result.map_err(|error| {
                    linux_ready_failure(SessionOperation::Close, state, error).with_cleanup(cleanup)
                })
            }
            #[cfg(target_os = "macos")]
            SessionInner::CoordinatorReady(inner) => {
                let result = inner.close_resources();
                let state = inner.state();
                result.map_err(|error| {
                    mac_ready_failure(SessionOperation::Close, state, error).with_cleanup(cleanup)
                })
            }
            #[cfg(target_os = "windows")]
            SessionInner::CoordinatorReady(inner) => {
                let result = inner.close_resources();
                let state = inner.state();
                result.map_err(|error| {
                    windows_ready_failure(SessionOperation::Close, state, error)
                        .with_cleanup(cleanup)
                })
            }
            #[cfg(target_os = "linux")]
            _ => unreachable!("coordinator ready typestate owns its exact backend state"),
            #[cfg(target_os = "macos")]
            _ => unreachable!("coordinator ready typestate owns its exact backend state"),
            #[cfg(target_os = "windows")]
            _ => unreachable!("coordinator ready typestate owns its exact backend state"),
            #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
            SessionInner::Unavailable => Err(SessionFailure::new(
                SessionOperation::Close,
                SessionTransactionState::NotEstablished,
                SessionError::BackendUnavailable,
            )
            .with_cleanup(cleanup)),
        };
        if let Err(error) = close {
            return CoordinatorCloseOutcome::Failed {
                session: self,
                error,
            };
        }
        CoordinatorCloseOutcome::Closed(cleanup)
    }

    /// Terminally poisons live mappings, terminates the exact child, and returns cleanup facts.
    pub fn abort(mut self, deadline: AbsoluteDeadline) -> CoordinatorAbortOutcome {
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        let _ = deadline;
        let cleanup = match &mut self.inner {
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
            SessionInner::CoordinatorReady(inner) => inner.abort(deadline),
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
            _ => unreachable!("coordinator ready typestate owns its exact backend state"),
            #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
            SessionInner::Unavailable => {
                ChildCleanupFacts::new(None, DescendantCleanupStatus::NotEstablished, None)
            }
        };
        let failure = if cleanup.direct_child_complete() {
            None
        } else {
            let reason = if cleanup.native_error().is_some() {
                SessionError::Native
            } else {
                SessionError::DeadlineExpired
            };
            Some(
                SessionFailure::new(
                    SessionOperation::Abort,
                    SessionTransactionState::Poisoned,
                    reason,
                )
                .with_native_code(cleanup.native_error())
                .with_poisoned(true)
                .with_cleanup(cleanup),
            )
        };
        CoordinatorAbortOutcome { cleanup, failure }
    }

    /// Starts a local batch builder bounded by this accepted session.
    pub fn new_transfer_batch(&self) -> Result<TransferBatch, BatchError> {
        let limits = self.negotiated_limits();
        TransferBatch::new(
            limits.max_regions_per_batch,
            limits.max_region_bytes,
            limits.max_batch_bytes,
        )
    }

    /// Completes one atomic capability transaction and activates its full set.
    pub fn transfer_batch(
        &mut self,
        batch: TransferBatch,
        deadline: AbsoluteDeadline,
    ) -> Result<ActiveRegionSet, SessionFailure> {
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        let _ = (batch, deadline);
        match &mut self.inner {
            #[cfg(target_os = "linux")]
            SessionInner::CoordinatorReady(inner) => {
                let result = inner.transfer_batch(batch, deadline);
                let state = inner.state();
                result.map_err(|error| {
                    linux_ready_batch_failure(SessionOperation::TransferBatch, state, error)
                })
            }
            #[cfg(target_os = "macos")]
            SessionInner::CoordinatorReady(inner) => {
                let result = inner.transfer_batch(batch, deadline);
                let state = inner.state();
                result.map_err(|error| {
                    mac_ready_failure(SessionOperation::TransferBatch, state, error)
                })
            }
            #[cfg(target_os = "windows")]
            SessionInner::CoordinatorReady(inner) => {
                let result = inner.transfer_batch(batch, deadline);
                let state = inner.state();
                result.map_err(|error| {
                    windows_ready_failure(SessionOperation::TransferBatch, state, error)
                })
            }
            #[cfg(target_os = "linux")]
            _ => unreachable!("coordinator ready typestate owns its exact backend state"),
            #[cfg(target_os = "macos")]
            _ => unreachable!("coordinator ready typestate owns its exact backend state"),
            #[cfg(target_os = "windows")]
            _ => unreachable!("coordinator ready typestate owns its exact backend state"),
            #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
            SessionInner::Unavailable => {
                unreachable!("unavailable backend cannot construct a session")
            }
        }
    }

    /// Sends one bounded opaque application record under the supplied deadline.
    pub fn send_control(
        &mut self,
        kind: u32,
        payload: &[u8],
        deadline: AbsoluteDeadline,
    ) -> Result<(), SessionFailure> {
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        let _ = (kind, payload, deadline);
        match &mut self.inner {
            #[cfg(target_os = "linux")]
            SessionInner::CoordinatorReady(inner) => {
                let result = inner.send_control(kind, payload, deadline);
                let state = inner.state();
                result.map_err(|error| {
                    linux_ready_failure(SessionOperation::SendControl, state, error)
                })
            }
            #[cfg(target_os = "macos")]
            SessionInner::CoordinatorReady(inner) => {
                let result = inner.send_control(kind, payload, deadline);
                let state = inner.state();
                result
                    .map_err(|error| mac_ready_failure(SessionOperation::SendControl, state, error))
            }
            #[cfg(target_os = "windows")]
            SessionInner::CoordinatorReady(inner) => {
                let result = inner.send_control(kind, payload, deadline);
                let state = inner.state();
                result.map_err(|error| {
                    windows_ready_failure(SessionOperation::SendControl, state, error)
                })
            }
            #[cfg(target_os = "linux")]
            _ => unreachable!("coordinator ready typestate owns its exact backend state"),
            #[cfg(target_os = "macos")]
            _ => unreachable!("coordinator ready typestate owns its exact backend state"),
            #[cfg(target_os = "windows")]
            _ => unreachable!("coordinator ready typestate owns its exact backend state"),
            #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
            SessionInner::Unavailable => {
                unreachable!("unavailable backend cannot construct a session")
            }
        }
    }

    /// Receives one bounded opaque peer record under the supplied deadline.
    pub fn receive_control(
        &mut self,
        deadline: AbsoluteDeadline,
    ) -> Result<ControlFrame, SessionFailure> {
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        let _ = deadline;
        match &mut self.inner {
            #[cfg(target_os = "linux")]
            SessionInner::CoordinatorReady(inner) => {
                let result = inner.receive_control(deadline);
                let state = inner.state();
                result.map_err(|error| {
                    linux_ready_failure(SessionOperation::ReceiveControl, state, error)
                })
            }
            #[cfg(target_os = "macos")]
            SessionInner::CoordinatorReady(inner) => {
                let result = inner.receive_control(deadline);
                let state = inner.state();
                result.map_err(|error| {
                    mac_ready_failure(SessionOperation::ReceiveControl, state, error)
                })
            }
            #[cfg(target_os = "windows")]
            SessionInner::CoordinatorReady(inner) => {
                let result = inner.receive_control(deadline);
                let state = inner.state();
                result.map_err(|error| {
                    windows_ready_failure(SessionOperation::ReceiveControl, state, error)
                })
            }
            #[cfg(target_os = "linux")]
            _ => unreachable!("coordinator ready typestate owns its exact backend state"),
            #[cfg(target_os = "macos")]
            _ => unreachable!("coordinator ready typestate owns its exact backend state"),
            #[cfg(target_os = "windows")]
            _ => unreachable!("coordinator ready typestate owns its exact backend state"),
            #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
            SessionInner::Unavailable => {
                unreachable!("unavailable backend cannot construct a session")
            }
        }
    }
}

impl Session<Receiver, Ready> {
    /// Effective finite limits bound into the accepted transcript.
    pub fn negotiated_limits(&self) -> SessionLimits {
        match &self.inner {
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
            SessionInner::ReceiverReady(inner) => inner.limits(),
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
            _ => unreachable!("receiver ready typestate owns its exact backend state"),
            #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
            SessionInner::Unavailable => {
                unreachable!("unavailable backend cannot construct a session")
            }
        }
    }

    /// Effective lock-free atomic and layout alignment facts bound into ACCEPT.
    pub fn atomic_capabilities(&self) -> AtomicCapabilities {
        match &self.inner {
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
            SessionInner::ReceiverReady(inner) => inner.atomics(),
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
            _ => unreachable!("receiver ready typestate owns its exact backend state"),
            #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
            SessionInner::Unavailable => {
                unreachable!("unavailable backend cannot construct a session")
            }
        }
    }

    /// Accepted protocol version from the exact challenged transcript.
    pub fn protocol_version(&self) -> ProtocolVersion {
        match &self.inner {
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
            SessionInner::ReceiverReady(inner) => inner.protocol_version(),
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
            _ => unreachable!("receiver ready typestate owns its exact backend state"),
            #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
            SessionInner::Unavailable => {
                unreachable!("unavailable backend cannot construct a session")
            }
        }
    }

    /// Current local reducer/liveness state.
    pub fn state(&self) -> SessionState {
        match &self.inner {
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
            SessionInner::ReceiverReady(inner) => inner.state(),
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
            _ => unreachable!("receiver ready typestate owns its exact backend state"),
            #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
            SessionInner::Unavailable => {
                unreachable!("unavailable backend cannot construct a session")
            }
        }
    }

    /// Bounded current active-mapping lease counters.
    pub fn active_leases(&self) -> ActiveLeaseFacts {
        match &self.inner {
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
            SessionInner::ReceiverReady(inner) => inner.active_leases(),
            #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
            _ => unreachable!("receiver ready typestate owns its exact backend state"),
            #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
            SessionInner::Unavailable => {
                unreachable!("unavailable backend cannot construct a session")
            }
        }
    }

    /// Performs one nonblocking authenticated peer observation.
    pub fn poll_peer(&mut self) -> Result<PeerStatus, SessionFailure> {
        match &mut self.inner {
            #[cfg(target_os = "linux")]
            SessionInner::ReceiverReady(inner) => {
                let result = inner.poll_peer();
                let state = inner.state();
                result
                    .map_err(|error| linux_ready_failure(SessionOperation::PollPeer, state, error))
            }
            #[cfg(target_os = "macos")]
            SessionInner::ReceiverReady(inner) => {
                let result = inner.poll_peer();
                let state = inner.state();
                result.map_err(|error| mac_ready_failure(SessionOperation::PollPeer, state, error))
            }
            #[cfg(target_os = "windows")]
            SessionInner::ReceiverReady(inner) => {
                let result = inner.poll_peer();
                let state = inner.state();
                result.map_err(|error| {
                    windows_ready_failure(SessionOperation::PollPeer, state, error)
                })
            }
            #[cfg(target_os = "linux")]
            _ => unreachable!("receiver ready typestate owns its exact backend state"),
            #[cfg(target_os = "macos")]
            _ => unreachable!("receiver ready typestate owns its exact backend state"),
            #[cfg(target_os = "windows")]
            _ => unreachable!("receiver ready typestate owns its exact backend state"),
            #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
            SessionInner::Unavailable => Err(SessionFailure::new(
                SessionOperation::PollPeer,
                SessionTransactionState::NotEstablished,
                SessionError::BackendUnavailable,
            )),
        }
    }

    /// Boundedly waits for authenticated peer endpoint closure under one deadline.
    pub fn wait_for_exit(
        &mut self,
        deadline: AbsoluteDeadline,
    ) -> Result<PeerStatus, SessionFailure> {
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        let _ = deadline;
        match &mut self.inner {
            #[cfg(target_os = "linux")]
            SessionInner::ReceiverReady(inner) => {
                let result = inner.wait_for_exit(deadline);
                let state = inner.state();
                result.map_err(|error| {
                    linux_ready_failure(SessionOperation::WaitForExit, state, error)
                })
            }
            #[cfg(target_os = "macos")]
            SessionInner::ReceiverReady(inner) => {
                let result = inner.wait_for_exit(deadline);
                let state = inner.state();
                result
                    .map_err(|error| mac_ready_failure(SessionOperation::WaitForExit, state, error))
            }
            #[cfg(target_os = "windows")]
            SessionInner::ReceiverReady(inner) => {
                let result = inner.wait_for_exit(deadline);
                let state = inner.state();
                result.map_err(|error| {
                    windows_ready_failure(SessionOperation::WaitForExit, state, error)
                })
            }
            #[cfg(target_os = "linux")]
            _ => unreachable!("receiver ready typestate owns its exact backend state"),
            #[cfg(target_os = "macos")]
            _ => unreachable!("receiver ready typestate owns its exact backend state"),
            #[cfg(target_os = "windows")]
            _ => unreachable!("receiver ready typestate owns its exact backend state"),
            #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
            SessionInner::Unavailable => Err(SessionFailure::new(
                SessionOperation::WaitForExit,
                SessionTransactionState::NotEstablished,
                SessionError::BackendUnavailable,
            )),
        }
    }

    /// Closes the inherited endpoint only after every active mapping lease is gone.
    pub fn try_close(mut self) -> ReceiverCloseOutcome {
        let facts = self.active_leases();
        if !facts.is_empty() {
            return ReceiverCloseOutcome::ActiveLeases {
                session: self,
                facts,
            };
        }
        let close: Result<(), SessionFailure> = match &mut self.inner {
            #[cfg(target_os = "linux")]
            SessionInner::ReceiverReady(inner) => {
                let result = inner.close_resources();
                let state = inner.state();
                result.map_err(|error| linux_ready_failure(SessionOperation::Close, state, error))
            }
            #[cfg(target_os = "macos")]
            SessionInner::ReceiverReady(inner) => {
                let result = inner.close_resources();
                let state = inner.state();
                result.map_err(|error| mac_ready_failure(SessionOperation::Close, state, error))
            }
            #[cfg(target_os = "windows")]
            SessionInner::ReceiverReady(inner) => {
                let result = inner.close_resources();
                let state = inner.state();
                result.map_err(|error| windows_ready_failure(SessionOperation::Close, state, error))
            }
            #[cfg(target_os = "linux")]
            _ => unreachable!("receiver ready typestate owns its exact backend state"),
            #[cfg(target_os = "macos")]
            _ => unreachable!("receiver ready typestate owns its exact backend state"),
            #[cfg(target_os = "windows")]
            _ => unreachable!("receiver ready typestate owns its exact backend state"),
            #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
            SessionInner::Unavailable => Err(SessionFailure::new(
                SessionOperation::Close,
                SessionTransactionState::NotEstablished,
                SessionError::BackendUnavailable,
            )),
        };
        if let Err(error) = close {
            return ReceiverCloseOutcome::Failed {
                session: self,
                error,
            };
        }
        ReceiverCloseOutcome::Closed
    }

    /// Terminally poisons every live mapping and closes the inherited endpoint.
    pub fn abort(mut self) {
        match &mut self.inner {
            #[cfg(target_os = "linux")]
            SessionInner::ReceiverReady(inner) => inner.abort(),
            #[cfg(target_os = "macos")]
            SessionInner::ReceiverReady(inner) => inner.abort(),
            #[cfg(target_os = "windows")]
            SessionInner::ReceiverReady(inner) => inner.abort(),
            #[cfg(target_os = "linux")]
            _ => unreachable!("receiver ready typestate owns its exact backend state"),
            #[cfg(target_os = "macos")]
            _ => unreachable!("receiver ready typestate owns its exact backend state"),
            #[cfg(target_os = "windows")]
            _ => unreachable!("receiver ready typestate owns its exact backend state"),
            #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
            SessionInner::Unavailable => {}
        }
    }

    /// Receives, validates, commits, and activates one exact expected batch.
    pub fn receive_batch(
        &mut self,
        expected: ExpectedBatch,
        deadline: AbsoluteDeadline,
    ) -> Result<ActiveRegionSet, SessionFailure> {
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        let _ = (expected, deadline);
        match &mut self.inner {
            #[cfg(target_os = "linux")]
            SessionInner::ReceiverReady(inner) => {
                let result = inner.receive_batch(expected, deadline);
                let state = inner.state();
                result.map_err(|error| {
                    linux_ready_batch_failure(SessionOperation::ReceiveBatch, state, error)
                })
            }
            #[cfg(target_os = "macos")]
            SessionInner::ReceiverReady(inner) => {
                let result = inner.receive_batch(expected, deadline);
                let state = inner.state();
                result.map_err(|error| {
                    mac_ready_failure(SessionOperation::ReceiveBatch, state, error)
                })
            }
            #[cfg(target_os = "windows")]
            SessionInner::ReceiverReady(inner) => {
                let result = inner.receive_batch(expected, deadline);
                let state = inner.state();
                result.map_err(|error| {
                    windows_ready_failure(SessionOperation::ReceiveBatch, state, error)
                })
            }
            #[cfg(target_os = "linux")]
            _ => unreachable!("receiver ready typestate owns its exact backend state"),
            #[cfg(target_os = "macos")]
            _ => unreachable!("receiver ready typestate owns its exact backend state"),
            #[cfg(target_os = "windows")]
            _ => unreachable!("receiver ready typestate owns its exact backend state"),
            #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
            SessionInner::Unavailable => {
                unreachable!("unavailable backend cannot construct a session")
            }
        }
    }

    /// Sends one bounded opaque application record under the supplied deadline.
    pub fn send_control(
        &mut self,
        kind: u32,
        payload: &[u8],
        deadline: AbsoluteDeadline,
    ) -> Result<(), SessionFailure> {
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        let _ = (kind, payload, deadline);
        match &mut self.inner {
            #[cfg(target_os = "linux")]
            SessionInner::ReceiverReady(inner) => {
                let result = inner.send_control(kind, payload, deadline);
                let state = inner.state();
                result.map_err(|error| {
                    linux_ready_failure(SessionOperation::SendControl, state, error)
                })
            }
            #[cfg(target_os = "macos")]
            SessionInner::ReceiverReady(inner) => {
                let result = inner.send_control(kind, payload, deadline);
                let state = inner.state();
                result
                    .map_err(|error| mac_ready_failure(SessionOperation::SendControl, state, error))
            }
            #[cfg(target_os = "windows")]
            SessionInner::ReceiverReady(inner) => {
                let result = inner.send_control(kind, payload, deadline);
                let state = inner.state();
                result.map_err(|error| {
                    windows_ready_failure(SessionOperation::SendControl, state, error)
                })
            }
            #[cfg(target_os = "linux")]
            _ => unreachable!("receiver ready typestate owns its exact backend state"),
            #[cfg(target_os = "macos")]
            _ => unreachable!("receiver ready typestate owns its exact backend state"),
            #[cfg(target_os = "windows")]
            _ => unreachable!("receiver ready typestate owns its exact backend state"),
            #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
            SessionInner::Unavailable => {
                unreachable!("unavailable backend cannot construct a session")
            }
        }
    }

    /// Receives one bounded opaque peer record under the supplied deadline.
    pub fn receive_control(
        &mut self,
        deadline: AbsoluteDeadline,
    ) -> Result<ControlFrame, SessionFailure> {
        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        let _ = deadline;
        match &mut self.inner {
            #[cfg(target_os = "linux")]
            SessionInner::ReceiverReady(inner) => {
                let result = inner.receive_control(deadline);
                let state = inner.state();
                result.map_err(|error| {
                    linux_ready_failure(SessionOperation::ReceiveControl, state, error)
                })
            }
            #[cfg(target_os = "macos")]
            SessionInner::ReceiverReady(inner) => {
                let result = inner.receive_control(deadline);
                let state = inner.state();
                result.map_err(|error| {
                    mac_ready_failure(SessionOperation::ReceiveControl, state, error)
                })
            }
            #[cfg(target_os = "windows")]
            SessionInner::ReceiverReady(inner) => {
                let result = inner.receive_control(deadline);
                let state = inner.state();
                result.map_err(|error| {
                    windows_ready_failure(SessionOperation::ReceiveControl, state, error)
                })
            }
            #[cfg(target_os = "linux")]
            _ => unreachable!("receiver ready typestate owns its exact backend state"),
            #[cfg(target_os = "macos")]
            _ => unreachable!("receiver ready typestate owns its exact backend state"),
            #[cfg(target_os = "windows")]
            _ => unreachable!("receiver ready typestate owns its exact backend state"),
            #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
            SessionInner::Unavailable => {
                unreachable!("unavailable backend cannot construct a session")
            }
        }
    }
}

fn validate_public_options(options: &SessionOptions) -> Result<(), SessionError> {
    if options.deadline.is_expired()
        || options.application_payload.len() > options.limits.max_bootstrap_payload_bytes as usize
    {
        return Err(if options.deadline.is_expired() {
            SessionError::DeadlineExpired
        } else {
            SessionError::InvalidInput
        });
    }
    match options.executable_identity {
        ExecutableIdentityPolicy::ExactOpenedFile => {}
    }
    options
        .limits
        .validate()
        .map(|_| ())
        .map_err(SessionError::NativeNegotiation)
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
const fn decision_rejection(decision: NegotiationDecision) -> Option<NonZeroU32> {
    match decision {
        NegotiationDecision::Accept => None,
        NegotiationDecision::Reject(reason) => Some(reason.as_nonzero()),
    }
}

#[cfg(target_os = "macos")]
fn map_mac_role(role: crate::backend::macos::vnext_session::MacNegotiationRole) -> SessionEndpoint {
    match role {
        crate::backend::macos::vnext_session::MacNegotiationRole::Coordinator => {
            SessionEndpoint::Coordinator
        }
        crate::backend::macos::vnext_session::MacNegotiationRole::Receiver => {
            SessionEndpoint::Receiver
        }
    }
}

#[cfg(target_os = "macos")]
fn map_mac_coordinator_outcome(
    outcome: crate::backend::macos::vnext_session::MacNegotiationOutcome<
        crate::backend::macos::vnext_session::MacCoordinatorReadySession,
    >,
) -> Result<NegotiationOutcome<Session<Coordinator, Ready>>, SessionFailure> {
    match outcome {
        crate::backend::macos::vnext_session::MacNegotiationOutcome::Accepted(inner) => {
            Ok(NegotiationOutcome::Accepted(Session::from_inner(
                SessionInner::CoordinatorReady(inner),
            )))
        }
        crate::backend::macos::vnext_session::MacNegotiationOutcome::Rejected {
            by,
            reason,
            cleanup,
        } => {
            let reason = RejectionReason::from_wire(reason).ok_or_else(|| {
                let failure = SessionFailure::new(
                    SessionOperation::Negotiate,
                    SessionTransactionState::Poisoned,
                    SessionError::MalformedPeer,
                );
                cleanup.map_or(failure, |facts| failure.with_cleanup(facts))
            })?;
            Ok(NegotiationOutcome::Rejected {
                by: map_mac_role(by),
                reason,
                cleanup,
            })
        }
    }
}

#[cfg(target_os = "macos")]
fn map_mac_receiver_outcome(
    outcome: crate::backend::macos::vnext_session::MacNegotiationOutcome<
        crate::backend::macos::vnext_session::MacReceiverReadySession,
    >,
) -> Result<NegotiationOutcome<Session<Receiver, Ready>>, SessionFailure> {
    match outcome {
        crate::backend::macos::vnext_session::MacNegotiationOutcome::Accepted(inner) => Ok(
            NegotiationOutcome::Accepted(Session::from_inner(SessionInner::ReceiverReady(inner))),
        ),
        crate::backend::macos::vnext_session::MacNegotiationOutcome::Rejected {
            by,
            reason,
            cleanup,
        } => {
            let reason = RejectionReason::from_wire(reason).ok_or_else(|| {
                SessionFailure::new(
                    SessionOperation::Negotiate,
                    SessionTransactionState::Poisoned,
                    SessionError::MalformedPeer,
                )
            })?;
            Ok(NegotiationOutcome::Rejected {
                by: map_mac_role(by),
                reason,
                cleanup,
            })
        }
    }
}

#[cfg(target_os = "windows")]
fn map_windows_role(
    role: crate::backend::windows::vnext_session::WindowsNegotiationRole,
) -> SessionEndpoint {
    match role {
        crate::backend::windows::vnext_session::WindowsNegotiationRole::Coordinator => {
            SessionEndpoint::Coordinator
        }
        crate::backend::windows::vnext_session::WindowsNegotiationRole::Receiver => {
            SessionEndpoint::Receiver
        }
    }
}

#[cfg(target_os = "windows")]
fn map_windows_coordinator_outcome(
    outcome: crate::backend::windows::vnext_session::WindowsNegotiationOutcome<
        crate::backend::windows::vnext_session::WindowsCoordinatorReadySession,
    >,
) -> Result<NegotiationOutcome<Session<Coordinator, Ready>>, SessionFailure> {
    match outcome {
        crate::backend::windows::vnext_session::WindowsNegotiationOutcome::Accepted(inner) => {
            Ok(NegotiationOutcome::Accepted(Session::from_inner(
                SessionInner::CoordinatorReady(Box::new(inner)),
            )))
        }
        crate::backend::windows::vnext_session::WindowsNegotiationOutcome::Rejected {
            by,
            reason,
            cleanup,
        } => {
            let reason = RejectionReason::from_wire(reason).ok_or_else(|| {
                let failure = SessionFailure::new(
                    SessionOperation::Negotiate,
                    SessionTransactionState::Poisoned,
                    SessionError::MalformedPeer,
                );
                cleanup.map_or(failure, |facts| failure.with_cleanup(facts))
            })?;
            Ok(NegotiationOutcome::Rejected {
                by: map_windows_role(by),
                reason,
                cleanup,
            })
        }
    }
}

#[cfg(target_os = "windows")]
fn map_windows_receiver_outcome(
    outcome: crate::backend::windows::vnext_session::WindowsNegotiationOutcome<
        crate::backend::windows::vnext_session::WindowsReceiverReadySession,
    >,
) -> Result<NegotiationOutcome<Session<Receiver, Ready>>, SessionFailure> {
    match outcome {
        crate::backend::windows::vnext_session::WindowsNegotiationOutcome::Accepted(inner) => {
            Ok(NegotiationOutcome::Accepted(Session::from_inner(
                SessionInner::ReceiverReady(Box::new(inner)),
            )))
        }
        crate::backend::windows::vnext_session::WindowsNegotiationOutcome::Rejected {
            by,
            reason,
            cleanup,
        } => {
            let reason = RejectionReason::from_wire(reason).ok_or_else(|| {
                SessionFailure::new(
                    SessionOperation::Negotiate,
                    SessionTransactionState::Poisoned,
                    SessionError::MalformedPeer,
                )
            })?;
            Ok(NegotiationOutcome::Rejected {
                by: map_windows_role(by),
                reason,
                cleanup,
            })
        }
    }
}

#[cfg(target_os = "linux")]
fn map_linux_role(
    role: crate::backend::linux_vnext::spawn::LinuxNegotiationRole,
) -> SessionEndpoint {
    match role {
        crate::backend::linux_vnext::spawn::LinuxNegotiationRole::Coordinator => {
            SessionEndpoint::Coordinator
        }
        crate::backend::linux_vnext::spawn::LinuxNegotiationRole::Receiver => {
            SessionEndpoint::Receiver
        }
    }
}

#[cfg(target_os = "linux")]
fn map_linux_coordinator_outcome(
    outcome: crate::backend::linux_vnext::spawn::LinuxNegotiationOutcome<
        crate::backend::linux_vnext::spawn::LinuxCoordinatorReadySession,
    >,
) -> Result<NegotiationOutcome<Session<Coordinator, Ready>>, SessionFailure> {
    match outcome {
        crate::backend::linux_vnext::spawn::LinuxNegotiationOutcome::Accepted(inner) => {
            Ok(NegotiationOutcome::Accepted(Session::from_inner(
                SessionInner::CoordinatorReady(inner),
            )))
        }
        crate::backend::linux_vnext::spawn::LinuxNegotiationOutcome::Rejected {
            by,
            reason,
            cleanup,
        } => {
            let reason = RejectionReason::from_wire(reason).ok_or_else(|| {
                let failure = SessionFailure::new(
                    SessionOperation::Negotiate,
                    SessionTransactionState::Poisoned,
                    SessionError::MalformedPeer,
                );
                cleanup.map_or(failure, |facts| failure.with_cleanup(facts))
            })?;
            Ok(NegotiationOutcome::Rejected {
                by: map_linux_role(by),
                reason,
                cleanup,
            })
        }
    }
}

#[cfg(target_os = "linux")]
fn map_linux_receiver_outcome(
    outcome: crate::backend::linux_vnext::spawn::LinuxNegotiationOutcome<
        crate::backend::linux_vnext::spawn::LinuxReceiverReadySession,
    >,
) -> Result<NegotiationOutcome<Session<Receiver, Ready>>, SessionFailure> {
    match outcome {
        crate::backend::linux_vnext::spawn::LinuxNegotiationOutcome::Accepted(inner) => Ok(
            NegotiationOutcome::Accepted(Session::from_inner(SessionInner::ReceiverReady(inner))),
        ),
        crate::backend::linux_vnext::spawn::LinuxNegotiationOutcome::Rejected {
            by,
            reason,
            cleanup,
        } => {
            let reason = RejectionReason::from_wire(reason).ok_or_else(|| {
                SessionFailure::new(
                    SessionOperation::Negotiate,
                    SessionTransactionState::Poisoned,
                    SessionError::MalformedPeer,
                )
            })?;
            Ok(NegotiationOutcome::Rejected {
                by: map_linux_role(by),
                reason,
                cleanup,
            })
        }
    }
}

#[cfg(target_os = "linux")]
fn linux_ready_failure(
    operation: SessionOperation,
    state: SessionState,
    error: crate::backend::linux_vnext::spawn::LinuxPublicSessionError,
) -> SessionFailure {
    let native_code = linux_public_native_code(error);
    let poisoned = state == SessionState::Poisoned;
    SessionFailure::new(
        operation,
        if poisoned {
            SessionTransactionState::Poisoned
        } else {
            SessionTransactionState::Ready
        },
        error.into(),
    )
    .with_native_code(native_code)
    .with_poisoned(poisoned)
}

#[cfg(target_os = "linux")]
fn linux_ready_batch_failure(
    operation: SessionOperation,
    state: SessionState,
    failure: crate::backend::linux_vnext::spawn::LinuxPublicReadyFailure,
) -> SessionFailure {
    let native_code = linux_public_native_code(failure.error);
    let poisoned = state == SessionState::Poisoned;
    SessionFailure::new(
        operation,
        if failure.transaction_open_on_failure {
            SessionTransactionState::TransactionOpen
        } else if poisoned {
            SessionTransactionState::Poisoned
        } else {
            SessionTransactionState::Ready
        },
        failure.error.into(),
    )
    .with_native_code(native_code)
    .with_poisoned(poisoned)
}

#[cfg(target_os = "linux")]
const fn linux_public_native_code(
    error: crate::backend::linux_vnext::spawn::LinuxPublicSessionError,
) -> Option<i32> {
    match error {
        crate::backend::linux_vnext::spawn::LinuxPublicSessionError::Native(code) => code,
        crate::backend::linux_vnext::spawn::LinuxPublicSessionError::ActivationFailed(code) => code,
        _ => None,
    }
}

#[cfg(target_os = "linux")]
impl From<crate::backend::linux_vnext::spawn::LinuxPublicSessionError> for SessionError {
    fn from(error: crate::backend::linux_vnext::spawn::LinuxPublicSessionError) -> Self {
        match error {
            crate::backend::linux_vnext::spawn::LinuxPublicSessionError::InvalidInput => {
                Self::InvalidInput
            }
            crate::backend::linux_vnext::spawn::LinuxPublicSessionError::DeadlineExpired => {
                Self::DeadlineExpired
            }
            crate::backend::linux_vnext::spawn::LinuxPublicSessionError::PeerExited => {
                Self::PeerDisconnected
            }
            crate::backend::linux_vnext::spawn::LinuxPublicSessionError::IdentityMismatch => {
                Self::IdentityMismatch
            }
            crate::backend::linux_vnext::spawn::LinuxPublicSessionError::MalformedPeer => {
                Self::MalformedPeer
            }
            crate::backend::linux_vnext::spawn::LinuxPublicSessionError::Ambiguous => {
                Self::Ambiguous
            }
            crate::backend::linux_vnext::spawn::LinuxPublicSessionError::NegotiationFailed => {
                Self::NegotiationFailed
            }
            crate::backend::linux_vnext::spawn::LinuxPublicSessionError::NativeNegotiation(
                error,
            ) => Self::NativeNegotiation(error),
            crate::backend::linux_vnext::spawn::LinuxPublicSessionError::Control(error) => {
                Self::Control(error)
            }
            crate::backend::linux_vnext::spawn::LinuxPublicSessionError::Batch(error) => {
                Self::Batch(error)
            }
            crate::backend::linux_vnext::spawn::LinuxPublicSessionError::ActiveLimit => {
                Self::ActiveLimit
            }
            crate::backend::linux_vnext::spawn::LinuxPublicSessionError::PeerPreparationFailed => {
                Self::PeerPreparationFailed
            }
            crate::backend::linux_vnext::spawn::LinuxPublicSessionError::ActivationFailed(_) => {
                Self::ActivationFailed
            }
            crate::backend::linux_vnext::spawn::LinuxPublicSessionError::Poisoned => Self::Poisoned,
            crate::backend::linux_vnext::spawn::LinuxPublicSessionError::Native(_) => Self::Native,
        }
    }
}

#[cfg(target_os = "macos")]
fn mac_session_failure(
    operation: SessionOperation,
    transaction_state: SessionTransactionState,
    error: crate::backend::macos::vnext_session::MacPublicSessionError,
    poisoned: bool,
) -> SessionFailure {
    SessionFailure::new(operation, transaction_state, error.into())
        .with_native_code(mac_public_native_code(error))
        .with_poisoned(poisoned)
}

#[cfg(target_os = "macos")]
fn mac_ready_failure(
    operation: SessionOperation,
    state: SessionState,
    error: crate::backend::macos::vnext_session::MacPublicSessionError,
) -> SessionFailure {
    let poisoned = state == SessionState::Poisoned;
    mac_session_failure(
        operation,
        if poisoned {
            SessionTransactionState::Poisoned
        } else {
            SessionTransactionState::Ready
        },
        error,
        poisoned,
    )
}

#[cfg(target_os = "macos")]
const fn mac_public_native_code(
    error: crate::backend::macos::vnext_session::MacPublicSessionError,
) -> Option<i32> {
    match error {
        crate::backend::macos::vnext_session::MacPublicSessionError::Native(code) => code,
        _ => None,
    }
}

#[cfg(target_os = "macos")]
impl From<crate::backend::macos::vnext_session::MacPublicSessionError> for SessionError {
    fn from(error: crate::backend::macos::vnext_session::MacPublicSessionError) -> Self {
        use crate::backend::macos::vnext_session::MacPublicSessionError as MacError;
        match error {
            MacError::InvalidInput => Self::InvalidInput,
            MacError::DeadlineExpired => Self::DeadlineExpired,
            MacError::PeerExited => Self::PeerDisconnected,
            MacError::IdentityMismatch => Self::IdentityMismatch,
            MacError::MalformedPeer => Self::MalformedPeer,
            MacError::Ambiguous => Self::Ambiguous,
            MacError::NegotiationFailed => Self::NegotiationFailed,
            MacError::NativeNegotiation(error) => Self::NativeNegotiation(error),
            MacError::Control(error) => Self::Control(error),
            MacError::Batch(error) => Self::Batch(error),
            MacError::ActiveLimit => Self::ActiveLimit,
            MacError::PeerPreparationFailed => Self::PeerPreparationFailed,
            MacError::ActivationFailed => Self::ActivationFailed,
            MacError::Poisoned => Self::Poisoned,
            MacError::Native(_) => Self::Native,
        }
    }
}

#[cfg(target_os = "windows")]
fn windows_session_failure(
    operation: SessionOperation,
    transaction_state: SessionTransactionState,
    error: crate::backend::windows::vnext_session::WindowsPublicSessionError,
    poisoned: bool,
) -> SessionFailure {
    let native_code = match &error {
        crate::backend::windows::vnext_session::WindowsPublicSessionError::Native(code) => *code,
        _ => None,
    };
    SessionFailure::new(operation, transaction_state, error.into())
        .with_native_code(native_code)
        .with_poisoned(poisoned)
}

#[cfg(target_os = "windows")]
fn windows_ready_failure(
    operation: SessionOperation,
    state: SessionState,
    error: crate::backend::windows::vnext_session::WindowsPublicSessionError,
) -> SessionFailure {
    let poisoned = state == SessionState::Poisoned;
    windows_session_failure(
        operation,
        if poisoned {
            SessionTransactionState::Poisoned
        } else {
            SessionTransactionState::Ready
        },
        error,
        poisoned,
    )
}

#[cfg(target_os = "windows")]
impl From<crate::backend::windows::vnext_session::WindowsPublicSessionError> for SessionError {
    fn from(error: crate::backend::windows::vnext_session::WindowsPublicSessionError) -> Self {
        use crate::backend::windows::vnext_session::WindowsPublicSessionError as WindowsError;
        match error {
            WindowsError::InvalidInput => Self::InvalidInput,
            WindowsError::DeadlineExpired => Self::DeadlineExpired,
            WindowsError::PeerExited => Self::PeerDisconnected,
            WindowsError::IdentityMismatch => Self::IdentityMismatch,
            WindowsError::MalformedPeer => Self::MalformedPeer,
            WindowsError::Ambiguous => Self::Ambiguous,
            WindowsError::NegotiationFailed => Self::NegotiationFailed,
            WindowsError::NativeNegotiation(error) => Self::NativeNegotiation(error),
            WindowsError::Control(error) => Self::Control(error),
            WindowsError::Batch(error) => Self::Batch(error),
            WindowsError::ActiveLimit => Self::ActiveLimit,
            WindowsError::PeerPreparationFailed => Self::PeerPreparationFailed,
            WindowsError::ActivationFailed => Self::ActivationFailed,
            WindowsError::Poisoned => Self::Poisoned,
            WindowsError::Native(_) => Self::Native,
        }
    }
}

const _: () = assert!(cfg!(target_has_atomic = "32"));
const _: () = assert!(cfg!(target_has_atomic = "64"));

#[cfg(test)]
#[path = "session_test.rs"]
mod tests;
