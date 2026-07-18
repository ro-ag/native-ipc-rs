//! Production macOS exact-child negotiation owners.
//!
//! These private owners bind a held executable identity, the Mach audit-PID
//! authenticated bootstrap channel, canonical HELLOs, and ordered bilateral
//! decisions before either role can obtain accepted transport authority.

use core::cell::Cell;
use core::marker::PhantomData;
use std::ffi::{CStr, CString, OsStr, OsString, c_char, c_int, c_void};
use std::fs::{File, OpenOptions};
use std::num::NonZeroU32;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use super::bootstrap::{
    self, BootstrapError, ChildChannel, MacChildLifecycle, ParentChannel, SpawnedHelper,
};
use super::vnext_image_identity as image_identity;
use super::vnext_image_identity::ImageIdentityError;
use super::vnext_memory::{MacBatchError, MacMixedDirectionBatch};
use super::vnext_transport::{CoordinatorMacControlTransport, ReceiverMacControlTransport};
use crate::backend::accepted_control::{
    AcceptedControlDispatcher, AcceptedControlError, MacActivationError, MacCapabilityBatchError,
};
use crate::backend::{
    CoordinatorAcceptedEvidence, CoordinatorChildChannelReceipt, CoordinatorChildImageReceipt,
    ReceiverSpawnerEvidence, SessionTransportError, SpawnIdentityFacts,
};
use crate::batch::{ActiveRegionSet, BatchError, ExpectedBatch, TransferBatch};
use crate::control::{CONTROL_HEADER_LEN, ControlError, ControlFrame};
use crate::liveness::ResourceError;
use crate::negotiation::{
    AtomicOffer, DecisionChallenge, FeatureBits, HEADER_LEN, HelloFrame, HelloPair,
    NegotiatedTranscript, NegotiationFrame, NegotiationWireError, SenderRole, TargetFacts,
    decode_frame,
};
use crate::protocol::CoordinatorCapacityStatus;
use crate::session::{
    AbsoluteDeadline, ActiveLeaseFacts, AtomicCapabilities, ChildCleanupFacts,
    DescendantCleanupStatus, NegotiationError, PeerStatus, ProtocolVersion, SessionCommand,
    SessionLimits, SessionOptions, SessionState,
};

const NONCE_LEN: usize = 32;
const ESRCH: c_int = 3;
const O_CLOEXEC: c_int = 0x0100_0000;
const O_NOFOLLOW_ANY: c_int = 0x2000_0000;
const MAX_MAC_HELLO_PAYLOAD: usize = bootstrap::MAX_VNEXT_RECORD_BYTES - HEADER_LEN;
const MAX_MAC_CONTROL_PAYLOAD: u32 =
    (bootstrap::MAX_VNEXT_RECORD_BYTES - CONTROL_HEADER_LEN) as u32;
const PUBLIC_BOOTSTRAP_ENV: &[u8] = b"NATIVE_IPC_VNEXT_PUBLIC_BOOTSTRAP";
const RESERVED_ENVIRONMENT: [&[u8]; 4] = [
    b"NATIVE_IPC_VNEXT_BOOTSTRAP_FD",
    PUBLIC_BOOTSTRAP_ENV,
    b"NATIVE_IPC_MACH_NONCE",
    b"NATIVE_IPC_PARENT_PID",
];

unsafe extern "C" {
    fn sysctlbyname(
        name: *const c_char,
        old_value: *mut c_void,
        old_length: *mut usize,
        new_value: *mut c_void,
        new_length: usize,
    ) -> c_int;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MacPublicSessionError {
    InvalidInput,
    DeadlineExpired,
    PeerExited,
    IdentityMismatch,
    MalformedPeer,
    Ambiguous,
    NegotiationFailed,
    NativeNegotiation(NegotiationError),
    Control(ControlError),
    Batch(BatchError),
    ActiveLimit,
    PeerPreparationFailed,
    ActivationFailed,
    Poisoned,
    Native(Option<i32>),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MacCoordinatorFailureState {
    NotEstablished,
    Spawned,
    Negotiating,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MacCoordinatorSessionFailure {
    pub(crate) error: MacPublicSessionError,
    pub(crate) cleanup: Option<ChildCleanupFacts>,
    pub(crate) state: MacCoordinatorFailureState,
    pub(crate) poisoned: bool,
}

impl MacCoordinatorSessionFailure {
    const fn before_child(error: MacPublicSessionError) -> Self {
        Self {
            error,
            cleanup: None,
            state: MacCoordinatorFailureState::NotEstablished,
            poisoned: false,
        }
    }

    const fn after_spawn(error: MacPublicSessionError, cleanup: ChildCleanupFacts) -> Self {
        Self {
            error,
            cleanup: Some(cleanup),
            state: MacCoordinatorFailureState::Spawned,
            poisoned: true,
        }
    }

    const fn during_negotiation(error: MacPublicSessionError, cleanup: ChildCleanupFacts) -> Self {
        Self {
            error,
            cleanup: Some(cleanup),
            state: MacCoordinatorFailureState::Negotiating,
            poisoned: true,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum MacNegotiationRole {
    Coordinator,
    Receiver,
}

pub(crate) enum MacNegotiationOutcome<T> {
    Accepted(T),
    Rejected {
        by: MacNegotiationRole,
        reason: NonZeroU32,
        cleanup: Option<ChildCleanupFacts>,
    },
}

struct MacHelloOffer {
    supported_features: FeatureBits,
    required_features: FeatureBits,
    limits: SessionLimits,
    application_payload: Vec<u8>,
}

pub(super) struct HeldExecutable {
    _file: File,
    cdhashes: Vec<[u8; image_identity::CDHASH_LEN]>,
}

pub(crate) struct MacCoordinatorNegotiatingSession {
    channel: ParentChannel,
    lifecycle: Option<MacChildLifecycle>,
    executable: HeldExecutable,
    transcript: NegotiatedTranscript,
    nonce: [u8; NONCE_LEN],
    deadline: AbsoluteDeadline,
    peer_application_payload: Vec<u8>,
    #[cfg(test)]
    wait_for_peer_exit_before_image_recheck: bool,
    not_sync: PhantomData<Cell<()>>,
}

pub(crate) struct MacReceiverNegotiatingSession {
    channel: ChildChannel,
    transcript: NegotiatedTranscript,
    nonce: [u8; NONCE_LEN],
    deadline: AbsoluteDeadline,
    peer_application_payload: Vec<u8>,
    not_sync: PhantomData<Cell<()>>,
}

/// Accepted coordinator transport plus the still-held pre-spawn image owner.
pub(crate) struct MacCoordinatorReadySession {
    dispatcher: AcceptedControlDispatcher<CoordinatorMacControlTransport>,
    _executable: HeldExecutable,
}

/// Accepted receiver transport carrying only receiver-scoped spawner evidence.
pub(crate) struct MacReceiverReadySession {
    dispatcher: AcceptedControlDispatcher<ReceiverMacControlTransport>,
}

impl HeldExecutable {
    fn open(path: &Path) -> Result<Self, MacPublicSessionError> {
        if !path.is_absolute() {
            return Err(MacPublicSessionError::InvalidInput);
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(O_CLOEXEC | O_NOFOLLOW_ANY)
            .open(path)
            .map_err(native_io)?;
        let metadata = file.metadata().map_err(native_io)?;
        if !metadata.file_type().is_file() || metadata.mode() & 0o6000 != 0 {
            return Err(MacPublicSessionError::InvalidInput);
        }
        // The content identity is read through the retained descriptor, never
        // the pathname, so later pathname swaps cannot move this baseline. A
        // file with no computable code directory (unsigned or script input)
        // can never be bound to a running image and fails closed here.
        let cdhashes = image_identity::held_image_cdhashes(&file).map_err(|error| match error {
            ImageIdentityError::UnsupportedImage | ImageIdentityError::MalformedImage => {
                MacPublicSessionError::InvalidInput
            }
            ImageIdentityError::Native(code) => MacPublicSessionError::Native(code),
        })?;
        Ok(Self {
            cdhashes,
            _file: file,
        })
    }

    /// Compares the kernel-registered code-directory hash of the exact
    /// execution named by `token_values` against the held file's hashes.
    ///
    /// The kernel refuses the query once the PID no longer carries that exact
    /// audit token, so a reused PID or a post-capture `exec` reports as an
    /// exit rather than as another process's identity.
    fn matches_running_image(
        &self,
        pid: u32,
        token_values: Option<[u32; 8]>,
    ) -> Result<bool, MacPublicSessionError> {
        let token_values = token_values.ok_or(MacPublicSessionError::Ambiguous)?;
        match image_identity::process_cdhash_with_token(pid, token_values) {
            Ok(hash) => Ok(self.cdhashes.contains(&hash)),
            Err(Some(ESRCH)) => Err(MacPublicSessionError::PeerExited),
            Err(code) => Err(MacPublicSessionError::Native(code)),
        }
    }
}

impl MacCoordinatorNegotiatingSession {
    pub(crate) fn spawn(
        command: &SessionCommand,
        options: &SessionOptions,
    ) -> Result<Self, MacCoordinatorSessionFailure> {
        Self::spawn_with_hooks(command, options, || (), || ())
    }

    /// Runs the production spawn with injection points around the launch so a
    /// test can replace the configured file after the identity baseline is
    /// retained and restore it before any recheck could observe the swap.
    #[cfg(test)]
    pub(crate) fn spawn_with_image_hooks_for_test(
        command: &SessionCommand,
        options: &SessionOptions,
        after_open_before_spawn: impl FnOnce(),
        after_spawn_before_check: impl FnOnce(),
    ) -> Result<Self, MacCoordinatorSessionFailure> {
        Self::spawn_with_hooks(
            command,
            options,
            after_open_before_spawn,
            after_spawn_before_check,
        )
    }

    fn spawn_with_hooks(
        command: &SessionCommand,
        options: &SessionOptions,
        after_open_before_spawn: impl FnOnce(),
        after_spawn_before_check: impl FnOnce(),
    ) -> Result<Self, MacCoordinatorSessionFailure> {
        if options.deadline().is_expired() || command.arguments().is_empty() {
            return Err(MacCoordinatorSessionFailure::before_child(
                if options.deadline().is_expired() {
                    MacPublicSessionError::DeadlineExpired
                } else {
                    MacPublicSessionError::InvalidInput
                },
            ));
        }
        let offer = public_offer(options).map_err(MacCoordinatorSessionFailure::before_child)?;
        let atomics =
            discover_atomic_capabilities().map_err(MacCoordinatorSessionFailure::before_child)?;
        let executable = HeldExecutable::open(command.executable())
            .map_err(MacCoordinatorSessionFailure::before_child)?;
        let path = cstring(command.executable().as_os_str())
            .map_err(MacCoordinatorSessionFailure::before_child)?;
        let arguments = command
            .arguments()
            .iter()
            .map(|argument| cstring(argument.as_os_str()))
            .collect::<Result<Vec<_>, _>>()
            .map_err(MacCoordinatorSessionFailure::before_child)?;
        let mut environment = encode_environment(command.environment())
            .map_err(MacCoordinatorSessionFailure::before_child)?;
        environment.push(
            CString::new([PUBLIC_BOOTSTRAP_ENV, b"=1"].concat())
                .expect("fixed public bootstrap environment"),
        );

        after_open_before_spawn();
        let helper = match SpawnedHelper::spawn_explicit(&path, &arguments, &environment) {
            Ok(helper) => helper,
            Err(BootstrapError::ExactAuthorityUnavailable { native_error }) => {
                return Err(MacCoordinatorSessionFailure::after_spawn(
                    MacPublicSessionError::Native(native_error),
                    ChildCleanupFacts::new(
                        None,
                        DescendantCleanupStatus::FreshGroupUnverified,
                        native_error,
                    ),
                ));
            }
            Err(error) => {
                return Err(MacCoordinatorSessionFailure::before_child(
                    map_bootstrap_error(error),
                ));
            }
        };
        let child_pid = helper.pid();
        after_spawn_before_check();
        // Bind the exec'd incarnation to the held content before waiting on
        // any child cooperation. The token was captured while the fresh child
        // was still suspended, so a pathname swapped between the identity
        // baseline and `posix_spawn` is caught here even if the path is
        // restored immediately after launch.
        match executable.matches_running_image(child_pid, helper.suspended_audit_token_values()) {
            Ok(true) => {}
            Ok(false) => {
                let cleanup = helper.cleanup_vnext_until(options.deadline());
                return Err(MacCoordinatorSessionFailure::after_spawn(
                    MacPublicSessionError::IdentityMismatch,
                    cleanup,
                ));
            }
            Err(error) => {
                let cleanup = helper.cleanup_vnext_until(options.deadline());
                return Err(MacCoordinatorSessionFailure::after_spawn(error, cleanup));
            }
        }
        let (mut channel, lifecycle) = helper
            .authenticate_vnext_until(options.deadline())
            .map_err(|(error, cleanup)| {
                MacCoordinatorSessionFailure::after_spawn(map_bootstrap_error(error), cleanup)
            })?;
        let image_matches =
            match executable.matches_running_image(child_pid, channel.peer_audit_values()) {
                Ok(matches) => matches,
                Err(error) => {
                    drop(channel);
                    let cleanup = lifecycle.terminate_and_reap_facts(options.deadline());
                    return Err(MacCoordinatorSessionFailure::after_spawn(error, cleanup));
                }
            };
        if !image_matches {
            drop(channel);
            let cleanup = lifecycle.terminate_and_reap_facts(options.deadline());
            return Err(MacCoordinatorSessionFailure::after_spawn(
                MacPublicSessionError::IdentityMismatch,
                cleanup,
            ));
        }
        let cleanup_lifecycle = lifecycle.clone();
        let result = (move || -> Result<Self, MacPublicSessionError> {
            let nonce = channel.vnext_nonce();
            let coordinator = make_hello(SenderRole::Coordinator, nonce, offer, atomics)?;
            channel
                .send_vnext_zero_rights(
                    &encode_frame(&NegotiationFrame::Hello(clone_hello(&coordinator)))?,
                    options.deadline(),
                )
                .map_err(map_transport_error)?;
            let bytes = channel
                .receive_vnext_zero_rights(bootstrap::MAX_VNEXT_RECORD_BYTES, options.deadline())
                .map_err(map_transport_error)?;
            let receiver = match decode_frame(
                &bytes,
                SenderRole::Receiver,
                nonce,
                MAX_MAC_HELLO_PAYLOAD as u32,
            )
            .map_err(map_negotiation_error)?
            {
                NegotiationFrame::Hello(frame) => frame,
                NegotiationFrame::Accept(_) | NegotiationFrame::Reject(_) => {
                    return Err(MacPublicSessionError::MalformedPeer);
                }
            };
            let peer_application_payload = receiver.application_payload.clone();
            let transcript =
                NegotiatedTranscript::from_hellos(HelloPair::new(coordinator, receiver), atomics)
                    .map_err(map_negotiation_error)?;
            Ok(Self {
                channel,
                lifecycle: Some(lifecycle),
                executable,
                transcript,
                nonce,
                deadline: options.deadline(),
                peer_application_payload,
                #[cfg(test)]
                wait_for_peer_exit_before_image_recheck: false,
                not_sync: PhantomData,
            })
        })();
        result.map_err(|error| {
            MacCoordinatorSessionFailure::during_negotiation(
                error,
                cleanup_lifecycle.terminate_and_reap_facts(options.deadline()),
            )
        })
    }

    pub(crate) fn peer_application_payload(&self) -> &[u8] {
        &self.peer_application_payload
    }

    /// Forces `decide` to observe the exact child's exit between the receipt
    /// of the receiver decision and the live-image recheck, making the
    /// accept-then-exit ordering deterministic instead of load-dependent.
    #[cfg(test)]
    pub(crate) fn wait_for_peer_exit_before_image_recheck_for_test(&mut self) {
        self.wait_for_peer_exit_before_image_recheck = true;
    }

    pub(crate) fn decide(
        self,
        rejection: Option<NonZeroU32>,
    ) -> Result<MacNegotiationOutcome<MacCoordinatorReadySession>, MacCoordinatorSessionFailure>
    {
        let cleanup_lifecycle = self.lifecycle.as_ref().cloned();
        let deadline = self.deadline;
        self.decide_inner(rejection).map_err(|error| {
            let cleanup = cleanup_lifecycle.map_or_else(
                || {
                    ChildCleanupFacts::new(
                        None,
                        DescendantCleanupStatus::FreshGroupUnverified,
                        None,
                    )
                },
                |lifecycle| lifecycle.terminate_and_reap_facts(deadline),
            );
            MacCoordinatorSessionFailure::during_negotiation(error, cleanup)
        })
    }

    fn decide_inner(
        mut self,
        rejection: Option<NonZeroU32>,
    ) -> Result<MacNegotiationOutcome<MacCoordinatorReadySession>, MacPublicSessionError> {
        let challenge = decision_challenge()?;
        if let Some(reason) = rejection {
            let reject = self
                .transcript
                .coordinator_reject(challenge, reason)
                .map_err(map_negotiation_error)?;
            self.channel
                .send_vnext_zero_rights(
                    &encode_frame(&NegotiationFrame::Reject(reject))?,
                    self.deadline,
                )
                .map_err(map_transport_error)?;
            let cleanup = self.terminate_after_rejection();
            return Ok(MacNegotiationOutcome::Rejected {
                by: MacNegotiationRole::Coordinator,
                reason,
                cleanup: Some(cleanup),
            });
        }

        let accept = self
            .transcript
            .coordinator_accept(challenge)
            .map_err(map_negotiation_error)?;
        self.transcript
            .validate_accept(accept, SenderRole::Coordinator)
            .map_err(map_negotiation_error)?;
        self.channel
            .send_vnext_zero_rights(
                &encode_frame(&NegotiationFrame::Accept(accept))?,
                self.deadline,
            )
            .map_err(map_transport_error)?;
        let bytes = self
            .channel
            .receive_vnext_zero_rights(bootstrap::MAX_VNEXT_RECORD_BYTES, self.deadline)
            .map_err(map_transport_error)?;
        match decode_frame(
            &bytes,
            SenderRole::Receiver,
            self.nonce,
            MAX_MAC_HELLO_PAYLOAD as u32,
        )
        .map_err(map_negotiation_error)?
        {
            NegotiationFrame::Accept(accept) => self
                .transcript
                .validate_accept(accept, SenderRole::Receiver)
                .map_err(map_negotiation_error)?,
            NegotiationFrame::Reject(reject) => {
                let reason = self
                    .transcript
                    .validate_reject(reject, SenderRole::Receiver)
                    .map_err(map_negotiation_error)?;
                let cleanup = self.terminate_after_rejection();
                return Ok(MacNegotiationOutcome::Rejected {
                    by: MacNegotiationRole::Receiver,
                    reason,
                    cleanup: Some(cleanup),
                });
            }
            NegotiationFrame::Hello(_) => return Err(MacPublicSessionError::MalformedPeer),
        }
        #[cfg(test)]
        if self.wait_for_peer_exit_before_image_recheck {
            let lifecycle = self
                .lifecycle
                .as_ref()
                .expect("lifecycle held through negotiation");
            while !matches!(
                lifecycle.try_poll().map_err(map_transport_error)?,
                crate::backend::PeerState::ExitedUnknown
            ) {
                if self.deadline.is_expired() {
                    return Err(MacPublicSessionError::DeadlineExpired);
                }
                std::thread::sleep(core::time::Duration::from_millis(1));
            }
        }
        // The receiver's validated decision is already in hand and every
        // received record was bound to the authenticated child execution by
        // the pinned kernel audit trailer and nonce. A child that exited
        // after sending its decision therefore completed negotiation, and the
        // queued decision must win over any exit observation. The image
        // verdict below is audit-token bound: the kernel answers only while
        // the exact authenticated execution is still behind `peer_pid`, and a
        // reused PID or a post-authentication `exec` reports `ESRCH` instead
        // of another image's identity. Anything but a token-bound match or a
        // confirmed exact exit stays fail-closed.
        let lifecycle = self
            .lifecycle
            .as_ref()
            .ok_or(MacPublicSessionError::PeerExited)?;
        match self
            .executable
            .matches_running_image(self.channel.peer_pid(), self.channel.peer_audit_values())
        {
            Ok(true) => {}
            Err(MacPublicSessionError::PeerExited) => {
                // The authenticated execution is gone: it exited (possibly
                // still a zombie), was reaped, or replaced itself with a
                // different image. Confirm the exact reap under the caller
                // deadline before treating negotiation as won; a live
                // replaced child never reaps and therefore fails closed here.
                lifecycle
                    .wait_and_reap_status(self.deadline)
                    .map_err(map_transport_error)?;
            }
            Ok(false) => {
                // The authenticated execution is alive and still reports a
                // code-directory hash the held file does not carry. This can
                // only be the launch-time swap that the spawn-side check
                // exists to reject, so it is terminal.
                if !matches!(
                    lifecycle.try_poll().map_err(map_transport_error)?,
                    crate::backend::PeerState::ExitedUnknown
                ) {
                    return Err(MacPublicSessionError::IdentityMismatch);
                }
            }
            Err(error) => {
                // The image could not be compared. Fail closed unless the
                // exact child is already confirmed reaped, in which case the
                // verdict named an unrelated reuse of the freed PID.
                if !matches!(
                    lifecycle.try_poll().map_err(map_transport_error)?,
                    crate::backend::PeerState::ExitedUnknown
                ) {
                    return Err(error);
                }
            }
        }
        let transcript = self
            .transcript
            .take_accepted_facts()
            .map_err(map_negotiation_error)?;
        let facts = SpawnIdentityFacts::new(
            std::process::id(),
            self.channel.peer_pid(),
            0,
            0,
            0,
            0,
            self.nonce,
        )
        .ok_or(MacPublicSessionError::IdentityMismatch)?;
        // SAFETY: the private Mach bootstrap receive validated the exact audit
        // PID and nonce before this owner could exchange either HELLO.
        let channel_receipt =
            unsafe { CoordinatorChildChannelReceipt::from_verified_native(facts) };
        // SAFETY: the running image's kernel-registered code-directory hash
        // matched a hash computed from the retained descriptor at spawn and
        // after channel authentication, both bound to the authenticated audit
        // token. After ACCEPT it either matched again, or the exact child was
        // confirmed reaped by its sole waiter, in which case no execution
        // remains that could carry a different image.
        let image_receipt = unsafe { CoordinatorChildImageReceipt::from_verified_native(facts) };
        let evidence =
            CoordinatorAcceptedEvidence::combine(channel_receipt, image_receipt, transcript)
                .map_err(map_transport_error)?;
        let parameters =
            evidence.session_parameters(crate::protocol::NativeAuthorityProfile::MacMachV1);
        let lifecycle = self
            .lifecycle
            .take()
            .ok_or(MacPublicSessionError::PeerExited)?;
        let transport = CoordinatorMacControlTransport::from_accepted_with_lifecycle(
            self.channel,
            lifecycle,
            evidence,
        )
        .map_err(map_transport_error)?;
        let dispatcher = AcceptedControlDispatcher::new(transport, parameters)
            .map_err(|_| MacPublicSessionError::InvalidInput)?;
        Ok(MacNegotiationOutcome::Accepted(
            MacCoordinatorReadySession {
                dispatcher,
                _executable: self.executable,
            },
        ))
    }

    fn terminate_after_rejection(&mut self) -> ChildCleanupFacts {
        match self.lifecycle.take() {
            Some(lifecycle) => lifecycle.terminate_and_reap_facts(self.deadline),
            None => {
                ChildCleanupFacts::new(None, DescendantCleanupStatus::FreshGroupUnverified, None)
            }
        }
    }
}

impl MacReceiverNegotiatingSession {
    pub(crate) fn from_environment(
        limits: SessionLimits,
        application_payload: Vec<u8>,
        require_atomic_u32: bool,
        require_atomic_u64: bool,
        deadline: AbsoluteDeadline,
    ) -> Result<Self, MacPublicSessionError> {
        let offer = validate_offer(MacHelloOffer {
            supported_features: FeatureBits([3, 0]),
            required_features: FeatureBits([
                u64::from(require_atomic_u32) | (u64::from(require_atomic_u64) << 1),
                0,
            ]),
            limits,
            application_payload,
        })?;
        let atomics = discover_atomic_capabilities()?;
        let mut channel =
            ChildChannel::connect_from_environment_until(deadline).map_err(map_bootstrap_error)?;
        let nonce = channel.vnext_nonce();
        let bytes = channel
            .receive_vnext_zero_rights(bootstrap::MAX_VNEXT_RECORD_BYTES, deadline)
            .map_err(map_transport_error)?;
        let coordinator = match decode_frame(
            &bytes,
            SenderRole::Coordinator,
            nonce,
            MAX_MAC_HELLO_PAYLOAD as u32,
        )
        .map_err(map_negotiation_error)?
        {
            NegotiationFrame::Hello(frame) => frame,
            NegotiationFrame::Accept(_) | NegotiationFrame::Reject(_) => {
                return Err(MacPublicSessionError::MalformedPeer);
            }
        };
        let peer_application_payload = coordinator.application_payload.clone();
        let receiver = make_hello(SenderRole::Receiver, nonce, offer, atomics)?;
        channel
            .send_vnext_zero_rights(
                &encode_frame(&NegotiationFrame::Hello(clone_hello(&receiver)))?,
                deadline,
            )
            .map_err(map_transport_error)?;
        let transcript =
            NegotiatedTranscript::from_hellos(HelloPair::new(coordinator, receiver), atomics)
                .map_err(map_negotiation_error)?;
        Ok(Self {
            channel,
            transcript,
            nonce,
            deadline,
            peer_application_payload,
            not_sync: PhantomData,
        })
    }

    pub(crate) fn peer_application_payload(&self) -> &[u8] {
        &self.peer_application_payload
    }

    pub(crate) fn decide_after_coordinator(
        mut self,
        decide: impl FnOnce(&[u8]) -> Option<NonZeroU32>,
    ) -> Result<MacNegotiationOutcome<MacReceiverReadySession>, MacPublicSessionError> {
        let bytes = self
            .channel
            .receive_vnext_zero_rights(bootstrap::MAX_VNEXT_RECORD_BYTES, self.deadline)
            .map_err(map_transport_error)?;
        match decode_frame(
            &bytes,
            SenderRole::Coordinator,
            self.nonce,
            MAX_MAC_HELLO_PAYLOAD as u32,
        )
        .map_err(map_negotiation_error)?
        {
            NegotiationFrame::Accept(accept) => self
                .transcript
                .validate_accept(accept, SenderRole::Coordinator)
                .map_err(map_negotiation_error)?,
            NegotiationFrame::Reject(reject) => {
                let reason = self
                    .transcript
                    .validate_reject(reject, SenderRole::Coordinator)
                    .map_err(map_negotiation_error)?;
                return Ok(MacNegotiationOutcome::Rejected {
                    by: MacNegotiationRole::Coordinator,
                    reason,
                    cleanup: None,
                });
            }
            NegotiationFrame::Hello(_) => return Err(MacPublicSessionError::MalformedPeer),
        }
        if let Some(reason) = decide(&self.peer_application_payload) {
            let reject = self
                .transcript
                .receiver_reject(reason)
                .map_err(map_negotiation_error)?;
            self.channel
                .send_vnext_zero_rights(
                    &encode_frame(&NegotiationFrame::Reject(reject))?,
                    self.deadline,
                )
                .map_err(map_transport_error)?;
            return Ok(MacNegotiationOutcome::Rejected {
                by: MacNegotiationRole::Receiver,
                reason,
                cleanup: None,
            });
        }
        let accept = self
            .transcript
            .receiver_accept()
            .map_err(map_negotiation_error)?;
        self.transcript
            .validate_accept(accept, SenderRole::Receiver)
            .map_err(map_negotiation_error)?;
        self.channel
            .send_vnext_zero_rights(
                &encode_frame(&NegotiationFrame::Accept(accept))?,
                self.deadline,
            )
            .map_err(map_transport_error)?;
        let transcript = self
            .transcript
            .take_accepted_facts()
            .map_err(map_negotiation_error)?;
        let facts = SpawnIdentityFacts::new(
            self.channel.vnext_parent_pid(),
            std::process::id(),
            0,
            0,
            0,
            0,
            self.nonce,
        )
        .ok_or(MacPublicSessionError::IdentityMismatch)?;
        // SAFETY: the inherited special-port authority and every received Mach
        // record were audit-PID and nonce authenticated to the spawning parent.
        let evidence = unsafe { ReceiverSpawnerEvidence::from_verified_native(facts, transcript) }
            .map_err(map_transport_error)?;
        let parameters =
            evidence.session_parameters(crate::protocol::NativeAuthorityProfile::MacMachV1);
        let transport = ReceiverMacControlTransport::from_accepted(self.channel, evidence)
            .map_err(map_transport_error)?;
        let dispatcher = AcceptedControlDispatcher::new(transport, parameters)
            .map_err(|_| MacPublicSessionError::InvalidInput)?;
        Ok(MacNegotiationOutcome::Accepted(MacReceiverReadySession {
            dispatcher,
        }))
    }
}

impl MacCoordinatorReadySession {
    pub(crate) const fn limits(&self) -> SessionLimits {
        self.dispatcher.limits()
    }

    pub(crate) const fn atomics(&self) -> AtomicCapabilities {
        self.dispatcher.atomics()
    }

    pub(crate) const fn protocol_version(&self) -> ProtocolVersion {
        self.dispatcher.protocol_version()
    }

    pub(crate) fn state(&self) -> SessionState {
        self.dispatcher.session_state()
    }

    pub(crate) fn active_leases(&self) -> ActiveLeaseFacts {
        self.dispatcher.active_lease_facts()
    }

    pub(crate) fn poll_peer(&mut self) -> Result<PeerStatus, MacPublicSessionError> {
        self.dispatcher
            .try_poll_peer()
            .map(peer_status)
            .map_err(map_control_error)
    }

    pub(crate) fn wait_for_exit(&mut self, deadline: AbsoluteDeadline) -> ChildCleanupFacts {
        self.dispatcher.wait_for_macos_child(deadline)
    }

    pub(crate) fn close_resources(&mut self) -> Result<(), MacPublicSessionError> {
        self.dispatcher
            .try_close_resources()
            .map_err(map_resource_error)
    }

    pub(crate) fn abort(&mut self, deadline: AbsoluteDeadline) -> ChildCleanupFacts {
        self.dispatcher.abort_macos_child(deadline)
    }

    pub(crate) fn send_control(
        &mut self,
        kind: u32,
        payload: &[u8],
        deadline: AbsoluteDeadline,
    ) -> Result<(), MacPublicSessionError> {
        self.dispatcher
            .send_parts(kind, payload, deadline)
            .map_err(map_control_error)
    }

    pub(crate) fn receive_control(
        &mut self,
        deadline: AbsoluteDeadline,
    ) -> Result<ControlFrame, MacPublicSessionError> {
        self.dispatcher.receive(deadline).map_err(map_control_error)
    }

    pub(crate) fn transfer_batch(
        &mut self,
        batch: TransferBatch,
        deadline: AbsoluteDeadline,
    ) -> Result<ActiveRegionSet, MacPublicSessionError> {
        if deadline.is_expired() {
            return Err(MacPublicSessionError::DeadlineExpired);
        }
        let frame = self
            .dispatcher
            .begin_public_macos_transfer_capacity(&batch, deadline)
            .map_err(map_batch_error)?;
        let reservations = self.dispatcher.reserve_macos_transfer_batch(&batch);
        let preparation = if reservations.is_ok() {
            Some(MacMixedDirectionBatch::prepare(
                batch,
                self.dispatcher.authority_profile(),
                deadline,
            ))
        } else {
            drop(batch);
            None
        };
        let local_status = if reservations.is_err() {
            CoordinatorCapacityStatus::ActiveLimit
        } else if preparation
            .as_ref()
            .is_some_and(|prepared| prepared.is_err())
        {
            CoordinatorCapacityStatus::PreparationFailed
        } else {
            CoordinatorCapacityStatus::Ready
        };
        let peer_ready = self
            .dispatcher
            .exchange_public_macos_transfer_capacity(&frame, local_status, deadline)
            .map_err(map_batch_error)?;
        let reservations = reservations.map_err(|_| MacPublicSessionError::ActiveLimit)?;
        let prepared = preparation
            .expect("successful reservation attempts native preparation")
            .map_err(map_memory_error)?;
        if !peer_ready {
            return Err(MacPublicSessionError::ActiveLimit);
        }
        let mut transaction = self
            .dispatcher
            .begin_public_macos_mixed_direction_batch_preflighted(
                prepared,
                reservations,
                frame,
                deadline,
            )
            .map_err(map_batch_error)?;
        transaction.prepare().map_err(map_batch_error)?;
        let committed = transaction.commit().map_err(map_batch_error)?;
        self.dispatcher
            .activate_macos_coordinator_mixed_direction_batch(committed)
            .map_err(map_activation_error)
    }

    #[cfg(test)]
    pub(crate) fn wait_for_child_exit_for_test(
        &self,
        deadline: AbsoluteDeadline,
    ) -> Result<(), SessionTransportError> {
        self.dispatcher.wait_for_macos_child_exit_for_test(deadline)
    }
}

impl MacReceiverReadySession {
    pub(crate) const fn limits(&self) -> SessionLimits {
        self.dispatcher.limits()
    }

    pub(crate) const fn atomics(&self) -> AtomicCapabilities {
        self.dispatcher.atomics()
    }

    pub(crate) const fn protocol_version(&self) -> ProtocolVersion {
        self.dispatcher.protocol_version()
    }

    pub(crate) fn state(&self) -> SessionState {
        self.dispatcher.session_state()
    }

    pub(crate) fn active_leases(&self) -> ActiveLeaseFacts {
        self.dispatcher.active_lease_facts()
    }

    pub(crate) fn poll_peer(&mut self) -> Result<PeerStatus, MacPublicSessionError> {
        self.dispatcher
            .try_poll_peer()
            .map(peer_status)
            .map_err(map_control_error)
    }

    pub(crate) fn wait_for_exit(
        &mut self,
        deadline: AbsoluteDeadline,
    ) -> Result<PeerStatus, MacPublicSessionError> {
        loop {
            match self.poll_peer()? {
                PeerStatus::Disconnected => return Ok(PeerStatus::Disconnected),
                PeerStatus::Connected if deadline.is_expired() => {
                    return Err(MacPublicSessionError::DeadlineExpired);
                }
                PeerStatus::Connected => std::thread::sleep(
                    core::time::Duration::from_millis(1).min(deadline.remaining()),
                ),
            }
        }
    }

    pub(crate) fn close_resources(&mut self) -> Result<(), MacPublicSessionError> {
        self.dispatcher
            .try_close_resources()
            .map_err(map_resource_error)
    }

    pub(crate) fn abort(&mut self) {
        self.dispatcher.poison_session();
    }

    pub(crate) fn send_control(
        &mut self,
        kind: u32,
        payload: &[u8],
        deadline: AbsoluteDeadline,
    ) -> Result<(), MacPublicSessionError> {
        self.dispatcher
            .send_parts(kind, payload, deadline)
            .map_err(map_control_error)
    }

    pub(crate) fn receive_control(
        &mut self,
        deadline: AbsoluteDeadline,
    ) -> Result<ControlFrame, MacPublicSessionError> {
        self.dispatcher.receive(deadline).map_err(map_control_error)
    }

    pub(crate) fn receive_batch(
        &mut self,
        expected: ExpectedBatch,
        deadline: AbsoluteDeadline,
    ) -> Result<ActiveRegionSet, MacPublicSessionError> {
        if deadline.is_expired() {
            return Err(MacPublicSessionError::DeadlineExpired);
        }
        let mut transaction = self
            .dispatcher
            .begin_public_macos_expected_mixed_direction_batch(expected, deadline)
            .map_err(map_batch_error)?;
        transaction.prepare().map_err(map_batch_error)?;
        let committed = transaction.commit().map_err(map_batch_error)?;
        self.dispatcher
            .activate_macos_receiver_mixed_direction_batch(committed)
            .map_err(map_activation_error)
    }
}

fn public_offer(options: &SessionOptions) -> Result<MacHelloOffer, MacPublicSessionError> {
    validate_offer(MacHelloOffer {
        supported_features: FeatureBits([3, 0]),
        required_features: FeatureBits([
            u64::from(options.requires_atomic_u32())
                | (u64::from(options.requires_atomic_u64()) << 1),
            0,
        ]),
        limits: options.limits(),
        application_payload: options.application_payload().to_vec(),
    })
}

fn validate_offer(mut offer: MacHelloOffer) -> Result<MacHelloOffer, MacPublicSessionError> {
    if offer.application_payload.len() > MAX_MAC_HELLO_PAYLOAD {
        return Err(MacPublicSessionError::InvalidInput);
    }
    offer.limits.max_bootstrap_payload_bytes = offer
        .limits
        .max_bootstrap_payload_bytes
        .min(MAX_MAC_HELLO_PAYLOAD as u32);
    offer.limits.max_control_payload_bytes = offer
        .limits
        .max_control_payload_bytes
        .min(MAX_MAC_CONTROL_PAYLOAD);
    offer
        .limits
        .validate()
        .map_err(MacPublicSessionError::NativeNegotiation)?;
    if offer.application_payload.len() > offer.limits.max_bootstrap_payload_bytes as usize {
        return Err(MacPublicSessionError::InvalidInput);
    }
    Ok(offer)
}

fn make_hello(
    role: SenderRole,
    nonce: [u8; NONCE_LEN],
    offer: MacHelloOffer,
    atomics: AtomicCapabilities,
) -> Result<HelloFrame, MacPublicSessionError> {
    Ok(HelloFrame {
        role,
        nonce,
        supported_features: offer.supported_features,
        required_features: offer.required_features,
        limits: offer.limits,
        atomics: AtomicOffer::from_local(atomics).map_err(map_negotiation_error)?,
        target: TargetFacts::current(),
        application_payload: offer.application_payload,
    })
}

fn clone_hello(hello: &HelloFrame) -> HelloFrame {
    HelloFrame {
        role: hello.role,
        nonce: hello.nonce,
        supported_features: hello.supported_features,
        required_features: hello.required_features,
        limits: hello.limits,
        atomics: hello.atomics,
        target: hello.target,
        application_payload: hello.application_payload.clone(),
    }
}

fn encode_frame(frame: &NegotiationFrame) -> Result<Vec<u8>, MacPublicSessionError> {
    let length = frame.encoded_len().map_err(map_negotiation_error)?;
    if length > bootstrap::MAX_VNEXT_RECORD_BYTES {
        return Err(MacPublicSessionError::InvalidInput);
    }
    let mut bytes = vec![0; length];
    frame
        .encode_into(&mut bytes)
        .map_err(map_negotiation_error)?;
    Ok(bytes)
}

fn decision_challenge() -> Result<DecisionChallenge, MacPublicSessionError> {
    let entropy = bootstrap::random_nonce().map_err(map_bootstrap_error)?;
    DecisionChallenge::from_os_csprng(entropy[..16].try_into().expect("fixed challenge slice"))
        .map_err(map_negotiation_error)
}

fn discover_atomic_capabilities() -> Result<AtomicCapabilities, MacPublicSessionError> {
    let page_alignment = super::page_size().map_err(|_| MacPublicSessionError::Native(None))?;
    let cache_line_alignment = sysctl_usize(c"hw.cachelinesize")?;
    AtomicCapabilities::from_verified_native(
        page_alignment,
        cache_line_alignment,
        cfg!(target_has_atomic = "32"),
        cfg!(target_has_atomic = "64"),
    )
    .map_err(MacPublicSessionError::NativeNegotiation)
}

fn sysctl_usize(name: &CStr) -> Result<usize, MacPublicSessionError> {
    let mut value: u64 = 0;
    let mut length = core::mem::size_of::<u64>();
    // SAFETY: name is NUL-terminated and both output pointers are valid.
    let result = unsafe {
        sysctlbyname(
            name.as_ptr(),
            (&mut value as *mut u64).cast(),
            &mut length,
            core::ptr::null_mut(),
            0,
        )
    };
    if result != 0 || length == 0 || length > core::mem::size_of::<u64>() {
        return Err(MacPublicSessionError::Native(
            std::io::Error::last_os_error().raw_os_error(),
        ));
    }
    usize::try_from(value)
        .ok()
        .filter(|value| value.is_power_of_two())
        .ok_or(MacPublicSessionError::Native(None))
}

fn encode_environment(
    environment: &[(OsString, OsString)],
) -> Result<Vec<CString>, MacPublicSessionError> {
    environment
        .iter()
        .map(|(key, value)| {
            let key = key.as_os_str().as_bytes();
            if key.is_empty() || key.contains(&b'=') || RESERVED_ENVIRONMENT.contains(&key) {
                return Err(MacPublicSessionError::InvalidInput);
            }
            let mut entry = Vec::with_capacity(key.len() + value.as_os_str().as_bytes().len() + 1);
            entry.extend_from_slice(key);
            entry.push(b'=');
            entry.extend_from_slice(value.as_os_str().as_bytes());
            CString::new(entry).map_err(|_| MacPublicSessionError::InvalidInput)
        })
        .collect()
}

fn cstring(value: &OsStr) -> Result<CString, MacPublicSessionError> {
    CString::new(value.as_bytes()).map_err(|_| MacPublicSessionError::InvalidInput)
}

fn native_io(error: std::io::Error) -> MacPublicSessionError {
    MacPublicSessionError::Native(error.raw_os_error())
}

fn map_bootstrap_error(error: BootstrapError) -> MacPublicSessionError {
    match error {
        BootstrapError::DeadlineExpired => MacPublicSessionError::DeadlineExpired,
        BootstrapError::Ambiguous => MacPublicSessionError::Ambiguous,
        BootstrapError::WrongPeer { .. } => MacPublicSessionError::IdentityMismatch,
        BootstrapError::InvalidMessage | BootstrapError::InvalidEnvironment => {
            MacPublicSessionError::MalformedPeer
        }
        BootstrapError::MissingEnvironment => MacPublicSessionError::InvalidInput,
        BootstrapError::Spawn(code) => MacPublicSessionError::Native(Some(code)),
        BootstrapError::Mach { code, .. } => MacPublicSessionError::Native(Some(code)),
        BootstrapError::ExactAuthorityUnavailable { native_error } => {
            MacPublicSessionError::Native(native_error)
        }
    }
}

fn map_transport_error(error: SessionTransportError) -> MacPublicSessionError {
    match error {
        SessionTransportError::DeadlineExpired => MacPublicSessionError::DeadlineExpired,
        SessionTransportError::PeerExited => MacPublicSessionError::PeerExited,
        SessionTransportError::IdentityMismatch => MacPublicSessionError::IdentityMismatch,
        SessionTransportError::Ambiguous => MacPublicSessionError::Ambiguous,
        SessionTransportError::MalformedRecord | SessionTransportError::RecordTooLarge => {
            MacPublicSessionError::MalformedPeer
        }
        SessionTransportError::Poisoned => MacPublicSessionError::Poisoned,
        SessionTransportError::Native(code) => MacPublicSessionError::Native(code),
    }
}

fn map_negotiation_error(_: NegotiationWireError) -> MacPublicSessionError {
    MacPublicSessionError::NegotiationFailed
}

fn peer_status(state: crate::backend::PeerState) -> PeerStatus {
    match state {
        crate::backend::PeerState::Running => PeerStatus::Connected,
        crate::backend::PeerState::ExitedUnknown => PeerStatus::Disconnected,
    }
}

fn map_control_error(error: AcceptedControlError) -> MacPublicSessionError {
    match error {
        AcceptedControlError::Control(ControlError::Poisoned) => MacPublicSessionError::Poisoned,
        AcceptedControlError::Control(error) => MacPublicSessionError::Control(error),
        AcceptedControlError::Transport(error) => map_transport_error(error),
    }
}

fn map_memory_error(error: MacBatchError) -> MacPublicSessionError {
    match error {
        MacBatchError::DeadlineExpired => MacPublicSessionError::DeadlineExpired,
        MacBatchError::InvalidBatch
        | MacBatchError::InvalidSize
        | MacBatchError::WrongProvenance => MacPublicSessionError::InvalidInput,
        MacBatchError::WrongObject => MacPublicSessionError::MalformedPeer,
        MacBatchError::GuardUnavailable | MacBatchError::Mach(_) => {
            MacPublicSessionError::Native(None)
        }
    }
}

fn map_batch_error(error: MacCapabilityBatchError) -> MacPublicSessionError {
    match error {
        MacCapabilityBatchError::Memory(error) => map_memory_error(error),
        MacCapabilityBatchError::Control(error) => map_control_error(error),
        MacCapabilityBatchError::Resource(_) => MacPublicSessionError::ActiveLimit,
        MacCapabilityBatchError::ActiveLimit => MacPublicSessionError::ActiveLimit,
        MacCapabilityBatchError::PeerPreparationFailed => {
            MacPublicSessionError::PeerPreparationFailed
        }
    }
}

fn map_activation_error(error: MacActivationError) -> MacPublicSessionError {
    match error {
        MacActivationError::Batch(error) => MacPublicSessionError::Batch(error),
        MacActivationError::WrongSession
        | MacActivationError::Memory(_)
        | MacActivationError::Active(_) => MacPublicSessionError::ActivationFailed,
    }
}

fn map_resource_error(error: ResourceError) -> MacPublicSessionError {
    match error {
        ResourceError::ActiveLeases(_) | ResourceError::ActiveLimit => {
            MacPublicSessionError::ActiveLimit
        }
        ResourceError::Poisoned | ResourceError::Closed => MacPublicSessionError::Poisoned,
        ResourceError::InvalidLimits | ResourceError::MappedLengthMismatch { .. } => {
            MacPublicSessionError::Native(None)
        }
    }
}
