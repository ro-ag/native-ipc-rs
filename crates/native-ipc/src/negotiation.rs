use crate::session::{AtomicCapabilities, HARD_MAX_BOOTSTRAP_PAYLOAD_BYTES, SessionLimits};
use sha2::{Digest, Sha256};

const MAGIC: [u8; 8] = *b"NIPCHEL1";
const WIRE_MAJOR: u16 = 1;
const WIRE_MINOR: u16 = 0;
pub(crate) const HEADER_LEN: usize = 224;

const KIND_HELLO: u16 = 1;
const KIND_ACCEPT: u16 = 2;
const KIND_REJECT: u16 = 3;
const ATOMIC_U32_LOCK_FREE: u32 = 1 << 0;
const ATOMIC_U64_LOCK_FREE: u32 = 1 << 1;
const KNOWN_ATOMIC_FLAGS: u32 = ATOMIC_U32_LOCK_FREE | ATOMIC_U64_LOCK_FREE;
const FEATURE_ATOMIC_U32: FeatureBits = FeatureBits([1 << 0, 0]);
const FEATURE_ATOMIC_U64: FeatureBits = FeatureBits([1 << 1, 0]);
const KNOWN_FEATURES: FeatureBits =
    FeatureBits([FEATURE_ATOMIC_U32.0[0] | FEATURE_ATOMIC_U64.0[0], 0]);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub(crate) enum SenderRole {
    Coordinator = 1,
    Receiver = 2,
}

impl SenderRole {
    fn decode(value: u8) -> Result<Self, NegotiationWireError> {
        match value {
            1 => Ok(Self::Coordinator),
            2 => Ok(Self::Receiver),
            _ => Err(NegotiationWireError::BadRole),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct FeatureBits(pub(crate) [u64; 2]);

impl FeatureBits {
    pub(crate) const fn is_subset_of(self, other: Self) -> bool {
        (self.0[0] & !other.0[0]) == 0 && (self.0[1] & !other.0[1]) == 0
    }

    const fn intersection(self, other: Self) -> Self {
        Self([self.0[0] & other.0[0], self.0[1] & other.0[1]])
    }

    const fn union(self, other: Self) -> Self {
        Self([self.0[0] | other.0[0], self.0[1] | other.0[1]])
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TargetFacts {
    pub(crate) os: u16,
    pub(crate) architecture: u16,
    pub(crate) pointer_width: u8,
    pub(crate) endian: u8,
}

impl TargetFacts {
    pub(crate) const fn current() -> Self {
        let os = if cfg!(target_os = "linux") {
            1
        } else if cfg!(target_os = "macos") {
            2
        } else {
            3
        };
        let architecture = if cfg!(target_arch = "x86_64") { 1 } else { 2 };
        Self {
            os,
            architecture,
            pointer_width: 64,
            endian: 1,
        }
    }

    fn validate(self) -> Result<Self, NegotiationWireError> {
        if !(1..=3).contains(&self.os)
            || !(1..=2).contains(&self.architecture)
            || self.pointer_width != 64
            || self.endian != 1
        {
            return Err(NegotiationWireError::BadTarget);
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AtomicOffer {
    pub(crate) u32_lock_free: bool,
    pub(crate) u64_lock_free: bool,
    pub(crate) u32_alignment: u16,
    pub(crate) u64_alignment: u16,
    pub(crate) page_alignment: u32,
    pub(crate) cache_line_alignment: u32,
}

impl AtomicOffer {
    pub(crate) fn from_local(value: AtomicCapabilities) -> Result<Self, NegotiationWireError> {
        let offer = Self {
            u32_lock_free: value.atomic_u32_lock_free(),
            u64_lock_free: value.atomic_u64_lock_free(),
            u32_alignment: u16::try_from(value.atomic_u32_alignment())
                .map_err(|_| NegotiationWireError::LengthOverflow)?,
            u64_alignment: u16::try_from(value.atomic_u64_alignment())
                .map_err(|_| NegotiationWireError::LengthOverflow)?,
            page_alignment: u32::try_from(value.page_alignment())
                .map_err(|_| NegotiationWireError::LengthOverflow)?,
            cache_line_alignment: u32::try_from(value.cache_line_alignment())
                .map_err(|_| NegotiationWireError::LengthOverflow)?,
        };
        offer.validate()
    }

    fn validate(self) -> Result<Self, NegotiationWireError> {
        let u32_alignment = usize::from(self.u32_alignment);
        let u64_alignment = usize::from(self.u64_alignment);
        let page_alignment = self.page_alignment as usize;
        let cache_line_alignment = self.cache_line_alignment as usize;
        if !u32_alignment.is_power_of_two()
            || !u64_alignment.is_power_of_two()
            || !page_alignment.is_power_of_two()
            || !cache_line_alignment.is_power_of_two()
            || page_alignment < u32_alignment.max(u64_alignment)
            || cache_line_alignment < u32_alignment.max(u64_alignment)
        {
            return Err(NegotiationWireError::BadAtomicFacts);
        }
        Ok(self)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct HelloFrame {
    pub(crate) role: SenderRole,
    pub(crate) nonce: [u8; 32],
    pub(crate) supported_features: FeatureBits,
    pub(crate) required_features: FeatureBits,
    pub(crate) limits: SessionLimits,
    pub(crate) atomics: AtomicOffer,
    pub(crate) target: TargetFacts,
    pub(crate) application_payload: Vec<u8>,
}

/// Session-owned, single-use input to negotiation reduction.
pub(crate) struct HelloPair {
    coordinator: HelloFrame,
    receiver: HelloFrame,
}

impl HelloPair {
    pub(crate) fn new(coordinator: HelloFrame, receiver: HelloFrame) -> Self {
        Self {
            coordinator,
            receiver,
        }
    }
}

/// Checked result of both HELLOs plus ordered one-shot decision state.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct NegotiatedTranscript {
    nonce: [u8; 32],
    selected_features: FeatureBits,
    effective_limits: SessionLimits,
    effective_atomics: AtomicOffer,
    target: TargetFacts,
    wire_major: u16,
    wire_minor: u16,
    hello_digest: [u8; 32],
    accepted_roles: u8,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct AcceptFrame {
    pub(crate) role: SenderRole,
    pub(crate) nonce: [u8; 32],
    pub(crate) selected_features: FeatureBits,
    pub(crate) effective_limits: SessionLimits,
    pub(crate) atomics: AtomicOffer,
    pub(crate) target: TargetFacts,
    pub(crate) hello_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RejectFrame {
    pub(crate) role: SenderRole,
    pub(crate) nonce: [u8; 32],
    pub(crate) reason: u32,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum NegotiationFrame {
    Hello(HelloFrame),
    Accept(AcceptFrame),
    Reject(RejectFrame),
}

impl NegotiationFrame {
    pub(crate) fn encoded_len(&self) -> Result<usize, NegotiationWireError> {
        match self {
            Self::Hello(frame) => frame.validate()?,
            Self::Accept(frame) => frame.validate()?,
            Self::Reject(frame) => frame.validate()?,
        }
        HEADER_LEN
            .checked_add(match self {
                Self::Hello(frame) => frame.application_payload.len(),
                Self::Accept(_) | Self::Reject(_) => 0,
            })
            .ok_or(NegotiationWireError::LengthOverflow)
    }

    pub(crate) fn encode_into(
        &self,
        destination: &mut [u8],
    ) -> Result<usize, NegotiationWireError> {
        let required = self.encoded_len()?;
        if destination.len() < required {
            return Err(NegotiationWireError::DestinationTooSmall);
        }
        destination[..required].fill(0);
        destination[..8].copy_from_slice(&MAGIC);
        put_u16(destination, 8, WIRE_MAJOR);
        put_u16(destination, 10, WIRE_MINOR);
        put_u32(destination, 16, HEADER_LEN as u32);
        put_u32(
            destination,
            20,
            u32::try_from(required).map_err(|_| NegotiationWireError::LengthOverflow)?,
        );
        let payload_len = u32::try_from(required - HEADER_LEN)
            .map_err(|_| NegotiationWireError::LengthOverflow)?;
        put_u32(destination, 24, payload_len);

        match self {
            Self::Hello(frame) => {
                frame.validate()?;
                put_u16(destination, 12, KIND_HELLO);
                destination[14] = frame.role as u8;
                encode_common(
                    destination,
                    frame.nonce,
                    frame.supported_features,
                    frame.required_features,
                    frame.limits,
                    frame.atomics,
                    frame.target,
                );
                destination[HEADER_LEN..required].copy_from_slice(&frame.application_payload);
            }
            Self::Accept(frame) => {
                frame.validate()?;
                put_u16(destination, 12, KIND_ACCEPT);
                destination[14] = frame.role as u8;
                encode_common(
                    destination,
                    frame.nonce,
                    frame.selected_features,
                    FeatureBits::default(),
                    frame.effective_limits,
                    frame.atomics,
                    frame.target,
                );
                destination[166..198].copy_from_slice(&frame.hello_digest);
            }
            Self::Reject(frame) => {
                frame.validate()?;
                put_u16(destination, 12, KIND_REJECT);
                destination[14] = frame.role as u8;
                put_u32(destination, 28, frame.reason);
                destination[32..64].copy_from_slice(&frame.nonce);
            }
        }
        Ok(required)
    }
}

impl NegotiatedTranscript {
    pub(crate) fn from_hellos(
        hellos: HelloPair,
        verified_local_atomics: AtomicCapabilities,
    ) -> Result<Self, NegotiationWireError> {
        let HelloPair {
            coordinator,
            receiver,
        } = hellos;
        coordinator.validate()?;
        receiver.validate()?;
        if coordinator.role != SenderRole::Coordinator || receiver.role != SenderRole::Receiver {
            return Err(NegotiationWireError::BadRole);
        }
        if coordinator.nonce != receiver.nonce {
            return Err(NegotiationWireError::NonceMismatch);
        }
        let target = TargetFacts::current();
        if coordinator.target != target || receiver.target != target {
            return Err(NegotiationWireError::TargetMismatch);
        }
        let local_atomics = AtomicOffer::from_local(verified_local_atomics)?;
        for offer in [coordinator.atomics, receiver.atomics] {
            if offer.u32_alignment != local_atomics.u32_alignment
                || offer.u64_alignment != local_atomics.u64_alignment
                || offer.page_alignment != local_atomics.page_alignment
                || offer.cache_line_alignment != local_atomics.cache_line_alignment
            {
                return Err(NegotiationWireError::AtomicMismatch);
            }
        }
        let effective_atomics = AtomicOffer {
            u32_lock_free: local_atomics.u32_lock_free
                && coordinator.atomics.u32_lock_free
                && receiver.atomics.u32_lock_free,
            u64_lock_free: local_atomics.u64_lock_free
                && coordinator.atomics.u64_lock_free
                && receiver.atomics.u64_lock_free,
            ..local_atomics
        };
        let atomic_features = FeatureBits([
            (u64::from(effective_atomics.u32_lock_free) * FEATURE_ATOMIC_U32.0[0])
                | (u64::from(effective_atomics.u64_lock_free) * FEATURE_ATOMIC_U64.0[0]),
            0,
        ]);
        let selected_features = coordinator
            .supported_features
            .intersection(receiver.supported_features)
            .intersection(KNOWN_FEATURES)
            .intersection(atomic_features);
        let required = coordinator
            .required_features
            .union(receiver.required_features);
        if !required.is_subset_of(selected_features) {
            return Err(NegotiationWireError::RequiredFeatureNotSupported);
        }
        Ok(Self {
            nonce: coordinator.nonce,
            selected_features,
            effective_limits: SessionLimits::negotiate(coordinator.limits, receiver.limits)
                .map_err(|_| NegotiationWireError::BadLimits)?,
            effective_atomics,
            target,
            wire_major: WIRE_MAJOR,
            wire_minor: WIRE_MINOR,
            hello_digest: canonical_hello_digest(&coordinator, &receiver),
            accepted_roles: 0,
        })
    }

    pub(crate) const fn expected_accept(&self, role: SenderRole) -> AcceptFrame {
        AcceptFrame {
            role,
            nonce: self.nonce,
            selected_features: self.selected_features,
            effective_limits: self.effective_limits,
            atomics: self.effective_atomics,
            target: self.target,
            hello_digest: self.hello_digest,
        }
    }

    pub(crate) fn validate_accept(
        &mut self,
        accept: AcceptFrame,
        expected_role: SenderRole,
    ) -> Result<(), NegotiationWireError> {
        if self.wire_major != WIRE_MAJOR || self.wire_minor != WIRE_MINOR {
            return Err(NegotiationWireError::BadVersion);
        }
        let expected_bit = match expected_role {
            SenderRole::Coordinator => 1,
            SenderRole::Receiver => 2,
        };
        if self.accepted_roles == u8::MAX
            || (expected_bit == 2 && self.accepted_roles != 1)
            || self.accepted_roles & expected_bit != 0
        {
            self.accepted_roles = u8::MAX;
            return Err(NegotiationWireError::DecisionReplayOrOrder);
        }
        if accept != self.expected_accept(expected_role) {
            self.accepted_roles = u8::MAX;
            return Err(NegotiationWireError::EffectiveMismatch);
        }
        self.accepted_roles |= expected_bit;
        Ok(())
    }
}

impl HelloFrame {
    fn validate(&self) -> Result<(), NegotiationWireError> {
        if self.nonce == [0; 32] {
            return Err(NegotiationWireError::NonceMismatch);
        }
        if !self.required_features.is_subset_of(self.supported_features) {
            return Err(NegotiationWireError::RequiredFeatureNotSupported);
        }
        self.limits
            .validate()
            .map_err(|_| NegotiationWireError::BadLimits)?;
        self.atomics.validate()?;
        self.target.validate()?;
        let payload_len = u32::try_from(self.application_payload.len())
            .map_err(|_| NegotiationWireError::LengthOverflow)?;
        validate_payload_len(payload_len, self.limits.max_bootstrap_payload_bytes)?;
        Ok(())
    }
}

impl AcceptFrame {
    fn validate(&self) -> Result<(), NegotiationWireError> {
        if self.nonce == [0; 32] {
            return Err(NegotiationWireError::NonceMismatch);
        }
        if self.hello_digest == [0; 32] {
            return Err(NegotiationWireError::EffectiveMismatch);
        }
        self.effective_limits
            .validate()
            .map_err(|_| NegotiationWireError::BadLimits)?;
        self.atomics.validate()?;
        self.target.validate()?;
        Ok(())
    }
}

impl RejectFrame {
    fn validate(&self) -> Result<(), NegotiationWireError> {
        if self.nonce == [0; 32] {
            return Err(NegotiationWireError::NonceMismatch);
        }
        if self.reason == 0 {
            return Err(NegotiationWireError::BadRejectReason);
        }
        Ok(())
    }
}

pub(crate) fn decode_frame(
    source: &[u8],
    expected_role: SenderRole,
    expected_nonce: [u8; 32],
    local_payload_limit: u32,
) -> Result<NegotiationFrame, NegotiationWireError> {
    if source.len() < HEADER_LEN {
        return Err(NegotiationWireError::Truncated);
    }
    if source[..8] != MAGIC {
        return Err(NegotiationWireError::BadMagic);
    }
    let major = get_u16(source, 8);
    let minor = get_u16(source, 10);
    if major != WIRE_MAJOR || minor != WIRE_MINOR {
        return Err(NegotiationWireError::BadVersion);
    }
    let kind = get_u16(source, 12);
    let role = SenderRole::decode(source[14])?;
    if role != expected_role {
        return Err(NegotiationWireError::BadRole);
    }
    if source[15] != 0
        || get_u32(source, 16) != HEADER_LEN as u32
        || source[198..224].iter().any(|byte| *byte != 0)
    {
        return Err(NegotiationWireError::NonCanonical);
    }
    let frame_len = get_u32(source, 20) as usize;
    let payload_len = get_u32(source, 24);
    let expected_len = HEADER_LEN
        .checked_add(payload_len as usize)
        .ok_or(NegotiationWireError::LengthOverflow)?;
    if frame_len != expected_len || source.len() != expected_len {
        return Err(NegotiationWireError::NonCanonical);
    }
    let nonce: [u8; 32] = source[32..64].try_into().expect("fixed checked range");
    if nonce == [0; 32] || nonce != expected_nonce {
        return Err(NegotiationWireError::NonceMismatch);
    }

    match kind {
        KIND_HELLO => {
            if get_u32(source, 28) != 0 || source[166..198].iter().any(|byte| *byte != 0) {
                return Err(NegotiationWireError::NonCanonical);
            }
            validate_payload_len(payload_len, local_payload_limit)?;
            let supported_features = decode_features(source, 64);
            let required_features = decode_features(source, 80);
            if !required_features.is_subset_of(supported_features) {
                return Err(NegotiationWireError::RequiredFeatureNotSupported);
            }
            let limits = decode_limits(source)?
                .validate()
                .map_err(|_| NegotiationWireError::BadLimits)?;
            let atomics = decode_atomics(source)?;
            let target = decode_target(source)?;
            validate_payload_len(payload_len, limits.max_bootstrap_payload_bytes)?;
            let mut application_payload = Vec::new();
            application_payload
                .try_reserve_exact(payload_len as usize)
                .map_err(|_| NegotiationWireError::AllocationFailed)?;
            application_payload.extend_from_slice(&source[HEADER_LEN..]);
            let frame = HelloFrame {
                role,
                nonce,
                supported_features,
                required_features,
                limits,
                atomics,
                target,
                application_payload,
            };
            frame.validate()?;
            Ok(NegotiationFrame::Hello(frame))
        }
        KIND_ACCEPT => {
            if payload_len != 0
                || get_u32(source, 28) != 0
                || source[80..96].iter().any(|byte| *byte != 0)
            {
                return Err(NegotiationWireError::NonCanonical);
            }
            let frame = AcceptFrame {
                role,
                nonce,
                selected_features: decode_features(source, 64),
                effective_limits: decode_limits(source)?
                    .validate()
                    .map_err(|_| NegotiationWireError::BadLimits)?,
                atomics: decode_atomics(source)?,
                target: decode_target(source)?,
                hello_digest: source[166..198].try_into().expect("fixed checked range"),
            };
            frame.validate()?;
            Ok(NegotiationFrame::Accept(frame))
        }
        KIND_REJECT => {
            if payload_len != 0 || source[64..198].iter().any(|byte| *byte != 0) {
                return Err(NegotiationWireError::NonCanonical);
            }
            let frame = RejectFrame {
                role,
                nonce,
                reason: get_u32(source, 28),
            };
            frame.validate()?;
            Ok(NegotiationFrame::Reject(frame))
        }
        _ => Err(NegotiationWireError::BadKind),
    }
}

fn validate_payload_len(length: u32, offered_limit: u32) -> Result<(), NegotiationWireError> {
    if length > HARD_MAX_BOOTSTRAP_PAYLOAD_BYTES || length > offered_limit {
        return Err(NegotiationWireError::PayloadTooLarge);
    }
    Ok(())
}

fn canonical_hello_digest(coordinator: &HelloFrame, receiver: &HelloFrame) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"native-ipc-vnext-hello-transcript-v1");
    hash_hello(&mut hasher, coordinator);
    hash_hello(&mut hasher, receiver);
    hasher.finalize().into()
}

fn hash_hello(hasher: &mut Sha256, frame: &HelloFrame) {
    hasher.update(MAGIC);
    hasher.update(WIRE_MAJOR.to_le_bytes());
    hasher.update(WIRE_MINOR.to_le_bytes());
    hasher.update(KIND_HELLO.to_le_bytes());
    hasher.update([frame.role as u8]);
    hasher.update(frame.nonce);
    for word in frame.supported_features.0 {
        hasher.update(word.to_le_bytes());
    }
    for word in frame.required_features.0 {
        hasher.update(word.to_le_bytes());
    }
    hasher.update(frame.limits.max_regions_per_batch.to_le_bytes());
    hasher.update(frame.limits.max_active_regions.to_le_bytes());
    hasher.update(frame.limits.max_region_bytes.to_le_bytes());
    hasher.update(frame.limits.max_batch_bytes.to_le_bytes());
    hasher.update(frame.limits.max_active_bytes.to_le_bytes());
    hasher.update(frame.limits.max_transactions.to_le_bytes());
    hasher.update(frame.limits.max_bootstrap_payload_bytes.to_le_bytes());
    hasher.update(frame.limits.max_control_payload_bytes.to_le_bytes());
    let mut atomic_flags = 0_u32;
    if frame.atomics.u32_lock_free {
        atomic_flags |= ATOMIC_U32_LOCK_FREE;
    }
    if frame.atomics.u64_lock_free {
        atomic_flags |= ATOMIC_U64_LOCK_FREE;
    }
    hasher.update(atomic_flags.to_le_bytes());
    hasher.update(frame.atomics.u32_alignment.to_le_bytes());
    hasher.update(frame.atomics.u64_alignment.to_le_bytes());
    hasher.update(frame.atomics.page_alignment.to_le_bytes());
    hasher.update(frame.atomics.cache_line_alignment.to_le_bytes());
    hasher.update(frame.target.os.to_le_bytes());
    hasher.update(frame.target.architecture.to_le_bytes());
    hasher.update([frame.target.pointer_width, frame.target.endian]);
    hasher.update(
        u32::try_from(frame.application_payload.len())
            .expect("validated HELLO payload length")
            .to_le_bytes(),
    );
    hasher.update(&frame.application_payload);
}

fn encode_common(
    destination: &mut [u8],
    nonce: [u8; 32],
    supported: FeatureBits,
    required: FeatureBits,
    limits: SessionLimits,
    atomics: AtomicOffer,
    target: TargetFacts,
) {
    destination[32..64].copy_from_slice(&nonce);
    encode_features(destination, 64, supported);
    encode_features(destination, 80, required);
    put_u16(destination, 96, limits.max_regions_per_batch);
    put_u32(destination, 100, limits.max_active_regions);
    put_u64(destination, 104, limits.max_region_bytes);
    put_u64(destination, 112, limits.max_batch_bytes);
    put_u64(destination, 120, limits.max_active_bytes);
    put_u64(destination, 128, limits.max_transactions);
    put_u32(destination, 136, limits.max_bootstrap_payload_bytes);
    put_u32(destination, 140, limits.max_control_payload_bytes);
    let mut atomic_flags = 0;
    if atomics.u32_lock_free {
        atomic_flags |= ATOMIC_U32_LOCK_FREE;
    }
    if atomics.u64_lock_free {
        atomic_flags |= ATOMIC_U64_LOCK_FREE;
    }
    put_u32(destination, 144, atomic_flags);
    put_u16(destination, 148, atomics.u32_alignment);
    put_u16(destination, 150, atomics.u64_alignment);
    put_u32(destination, 152, atomics.page_alignment);
    put_u32(destination, 156, atomics.cache_line_alignment);
    put_u16(destination, 160, target.os);
    put_u16(destination, 162, target.architecture);
    destination[164] = target.pointer_width;
    destination[165] = target.endian;
}

fn decode_limits(source: &[u8]) -> Result<SessionLimits, NegotiationWireError> {
    if get_u16(source, 98) != 0 {
        return Err(NegotiationWireError::NonCanonical);
    }
    Ok(SessionLimits {
        max_regions_per_batch: get_u16(source, 96),
        max_active_regions: get_u32(source, 100),
        max_region_bytes: get_u64(source, 104),
        max_batch_bytes: get_u64(source, 112),
        max_active_bytes: get_u64(source, 120),
        max_transactions: get_u64(source, 128),
        max_bootstrap_payload_bytes: get_u32(source, 136),
        max_control_payload_bytes: get_u32(source, 140),
    })
}

fn decode_atomics(source: &[u8]) -> Result<AtomicOffer, NegotiationWireError> {
    let flags = get_u32(source, 144);
    if flags & !KNOWN_ATOMIC_FLAGS != 0 {
        return Err(NegotiationWireError::BadAtomicFacts);
    }
    AtomicOffer {
        u32_lock_free: flags & ATOMIC_U32_LOCK_FREE != 0,
        u64_lock_free: flags & ATOMIC_U64_LOCK_FREE != 0,
        u32_alignment: get_u16(source, 148),
        u64_alignment: get_u16(source, 150),
        page_alignment: get_u32(source, 152),
        cache_line_alignment: get_u32(source, 156),
    }
    .validate()
}

fn decode_target(source: &[u8]) -> Result<TargetFacts, NegotiationWireError> {
    TargetFacts {
        os: get_u16(source, 160),
        architecture: get_u16(source, 162),
        pointer_width: source[164],
        endian: source[165],
    }
    .validate()
}

fn encode_features(destination: &mut [u8], offset: usize, value: FeatureBits) {
    put_u64(destination, offset, value.0[0]);
    put_u64(destination, offset + 8, value.0[1]);
}

fn decode_features(source: &[u8], offset: usize) -> FeatureBits {
    FeatureBits([get_u64(source, offset), get_u64(source, offset + 8)])
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

fn get_u16(bytes: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes(
        bytes[offset..offset + 2]
            .try_into()
            .expect("fixed checked range"),
    )
}

fn get_u32(bytes: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes(
        bytes[offset..offset + 4]
            .try_into()
            .expect("fixed checked range"),
    )
}

fn get_u64(bytes: &[u8], offset: usize) -> u64 {
    u64::from_le_bytes(
        bytes[offset..offset + 8]
            .try_into()
            .expect("fixed checked range"),
    )
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NegotiationWireError {
    Truncated,
    BadMagic,
    BadVersion,
    BadKind,
    BadRole,
    BadTarget,
    TargetMismatch,
    BadAtomicFacts,
    AtomicMismatch,
    BadLimits,
    BadRejectReason,
    NonceMismatch,
    NonCanonical,
    EffectiveMismatch,
    DecisionReplayOrOrder,
    RequiredFeatureNotSupported,
    PayloadTooLarge,
    LengthOverflow,
    AllocationFailed,
    DestinationTooSmall,
}

#[cfg(test)]
mod tests {
    use super::*;
    use static_assertions::assert_not_impl_any;

    assert_not_impl_any!(HelloFrame: Clone);
    assert_not_impl_any!(HelloPair: Clone);
    assert_not_impl_any!(NegotiatedTranscript: Clone);

    const NONCE: [u8; 32] = [0x5a; 32];

    fn atomics() -> AtomicOffer {
        AtomicOffer::from_local(
            AtomicCapabilities::from_verified_native(4096, 128, true, true).unwrap(),
        )
        .unwrap()
    }

    fn hello(payload: &[u8]) -> NegotiationFrame {
        NegotiationFrame::Hello(HelloFrame {
            role: SenderRole::Coordinator,
            nonce: NONCE,
            supported_features: FeatureBits([0x11, 0x22]),
            required_features: FeatureBits([0x01, 0x02]),
            limits: SessionLimits::default(),
            atomics: atomics(),
            target: TargetFacts::current(),
            application_payload: payload.to_vec(),
        })
    }

    fn duplicate_hello(frame: &HelloFrame) -> HelloFrame {
        HelloFrame {
            role: frame.role,
            nonce: frame.nonce,
            supported_features: frame.supported_features,
            required_features: frame.required_features,
            limits: frame.limits,
            atomics: frame.atomics,
            target: frame.target,
            application_payload: frame.application_payload.clone(),
        }
    }

    fn negotiate(
        coordinator: &HelloFrame,
        receiver: &HelloFrame,
        verified: AtomicCapabilities,
    ) -> Result<NegotiatedTranscript, NegotiationWireError> {
        NegotiatedTranscript::from_hellos(
            HelloPair::new(duplicate_hello(coordinator), duplicate_hello(receiver)),
            verified,
        )
    }

    fn encoded(frame: &NegotiationFrame) -> Vec<u8> {
        let mut bytes = vec![0; frame.encoded_len().unwrap()];
        let len = frame.encode_into(&mut bytes).unwrap();
        assert_eq!(len, bytes.len());
        bytes
    }

    #[test]
    fn hello_is_fixed_little_endian_bounded_and_round_trips_opaque_payload() {
        let bytes = encoded(&hello(b"opaque"));
        assert_eq!(&bytes[..8], &MAGIC);
        assert_eq!(get_u16(&bytes, 8), WIRE_MAJOR);
        assert_eq!(get_u16(&bytes, 10), WIRE_MINOR);
        assert_eq!(get_u16(&bytes, 12), KIND_HELLO);
        assert_eq!(bytes[14], SenderRole::Coordinator as u8);
        assert_eq!(get_u32(&bytes, 16), HEADER_LEN as u32);
        assert_eq!(get_u32(&bytes, 20) as usize, HEADER_LEN + 6);
        assert_eq!(get_u32(&bytes, 24), 6);
        assert_eq!(&bytes[32..64], &NONCE);
        assert_eq!(get_u64(&bytes, 64), 0x11);
        assert_eq!(get_u64(&bytes, 72), 0x22);
        assert_eq!(&bytes[HEADER_LEN..], b"opaque");
        assert_eq!(
            decode_frame(
                &bytes,
                SenderRole::Coordinator,
                NONCE,
                HARD_MAX_BOOTSTRAP_PAYLOAD_BYTES,
            )
            .unwrap(),
            hello(b"opaque")
        );

        assert!(matches!(
            hello(&[0; 2]).encode_into(&mut [0; HEADER_LEN + 1]),
            Err(NegotiationWireError::DestinationTooSmall)
        ));
        assert!(matches!(
            decode_frame(&bytes, SenderRole::Coordinator, NONCE, 5),
            Err(NegotiationWireError::PayloadTooLarge)
        ));
        assert_eq!(
            validate_payload_len(
                HARD_MAX_BOOTSTRAP_PAYLOAD_BYTES,
                HARD_MAX_BOOTSTRAP_PAYLOAD_BYTES,
            ),
            Ok(())
        );
        assert_eq!(
            validate_payload_len(
                HARD_MAX_BOOTSTRAP_PAYLOAD_BYTES + 1,
                HARD_MAX_BOOTSTRAP_PAYLOAD_BYTES + 1,
            ),
            Err(NegotiationWireError::PayloadTooLarge)
        );

        let empty = encoded(&hello(b""));
        assert!(matches!(
            decode_frame(&empty, SenderRole::Coordinator, NONCE, 0),
            Ok(NegotiationFrame::Hello(HelloFrame {
                application_payload,
                ..
            })) if application_payload.is_empty()
        ));
    }

    #[test]
    fn accept_and_reject_are_payload_free_exact_decisions() {
        let accept = NegotiationFrame::Accept(AcceptFrame {
            role: SenderRole::Receiver,
            nonce: NONCE,
            selected_features: FeatureBits([1, 2]),
            effective_limits: SessionLimits::default(),
            atomics: atomics(),
            target: TargetFacts::current(),
            hello_digest: [7; 32],
        });
        let accept_bytes = encoded(&accept);
        assert_eq!(accept_bytes.len(), HEADER_LEN);
        assert_eq!(
            decode_frame(
                &accept_bytes,
                SenderRole::Receiver,
                NONCE,
                HARD_MAX_BOOTSTRAP_PAYLOAD_BYTES,
            )
            .unwrap(),
            accept
        );

        let reject = NegotiationFrame::Reject(RejectFrame {
            role: SenderRole::Receiver,
            nonce: NONCE,
            reason: 7,
        });
        let reject_bytes = encoded(&reject);
        assert_eq!(get_u32(&reject_bytes, 28), 7);
        assert_eq!(
            decode_frame(
                &reject_bytes,
                SenderRole::Receiver,
                NONCE,
                HARD_MAX_BOOTSTRAP_PAYLOAD_BYTES,
            )
            .unwrap(),
            reject
        );

        let zero_reason = NegotiationFrame::Reject(RejectFrame {
            role: SenderRole::Receiver,
            nonce: NONCE,
            reason: 0,
        });
        assert_eq!(
            zero_reason.encode_into(&mut [0; HEADER_LEN]),
            Err(NegotiationWireError::BadRejectReason)
        );
    }

    #[test]
    fn hostile_header_and_every_truncation_fail_before_payload_copy() {
        let bytes = encoded(&hello(b"payload"));
        for len in 0..bytes.len() {
            let error = decode_frame(
                &bytes[..len],
                SenderRole::Coordinator,
                NONCE,
                HARD_MAX_BOOTSTRAP_PAYLOAD_BYTES,
            )
            .unwrap_err();
            if len < HEADER_LEN {
                assert_eq!(error, NegotiationWireError::Truncated, "length {len}");
            } else {
                assert_eq!(error, NegotiationWireError::NonCanonical, "length {len}");
            }
        }

        let mutations: &[(usize, NegotiationWireError)] = &[
            (0, NegotiationWireError::BadMagic),
            (8, NegotiationWireError::BadVersion),
            (12, NegotiationWireError::BadKind),
            (14, NegotiationWireError::BadRole),
            (15, NegotiationWireError::NonCanonical),
            (16, NegotiationWireError::NonCanonical),
            (20, NegotiationWireError::NonCanonical),
            (24, NegotiationWireError::NonCanonical),
            (28, NegotiationWireError::NonCanonical),
            (32, NegotiationWireError::NonceMismatch),
            (98, NegotiationWireError::NonCanonical),
            (144, NegotiationWireError::BadAtomicFacts),
            (164, NegotiationWireError::BadTarget),
            (166, NegotiationWireError::NonCanonical),
            (191, NegotiationWireError::NonCanonical),
        ];
        for &(offset, error) in mutations {
            let mut bad = bytes.clone();
            bad[offset] ^= 0x80;
            assert_eq!(
                decode_frame(
                    &bad,
                    SenderRole::Coordinator,
                    NONCE,
                    HARD_MAX_BOOTSTRAP_PAYLOAD_BYTES,
                ),
                Err(error),
                "offset {offset}"
            );
        }
        for offset in 166..HEADER_LEN {
            let mut bad = bytes.clone();
            bad[offset] = 1;
            assert_eq!(
                decode_frame(
                    &bad,
                    SenderRole::Coordinator,
                    NONCE,
                    HARD_MAX_BOOTSTRAP_PAYLOAD_BYTES,
                ),
                Err(NegotiationWireError::NonCanonical),
                "reserved offset {offset}"
            );
        }
        assert_eq!(
            decode_frame(
                &bytes,
                SenderRole::Receiver,
                NONCE,
                HARD_MAX_BOOTSTRAP_PAYLOAD_BYTES,
            ),
            Err(NegotiationWireError::BadRole)
        );
        assert_eq!(
            decode_frame(
                &bytes,
                SenderRole::Coordinator,
                [1; 32],
                HARD_MAX_BOOTSTRAP_PAYLOAD_BYTES,
            ),
            Err(NegotiationWireError::NonceMismatch)
        );
    }

    #[test]
    fn feature_atomic_limit_and_payload_invariants_fail_closed() {
        let mut invalid_feature = match hello(b"") {
            NegotiationFrame::Hello(frame) => frame,
            _ => unreachable!(),
        };
        invalid_feature.required_features = FeatureBits([1 << 63, 0]);
        assert_eq!(
            NegotiationFrame::Hello(invalid_feature).encode_into(&mut [0; HEADER_LEN]),
            Err(NegotiationWireError::RequiredFeatureNotSupported)
        );

        let mut invalid_limit = match hello(b"") {
            NegotiationFrame::Hello(frame) => frame,
            _ => unreachable!(),
        };
        invalid_limit.limits.max_transactions = 0;
        assert_eq!(
            NegotiationFrame::Hello(invalid_limit).encode_into(&mut [0; HEADER_LEN]),
            Err(NegotiationWireError::BadLimits)
        );

        let mut payload_over_offer = match hello(b"xx") {
            NegotiationFrame::Hello(frame) => frame,
            _ => unreachable!(),
        };
        payload_over_offer.limits.max_bootstrap_payload_bytes = 1;
        assert_eq!(
            NegotiationFrame::Hello(duplicate_hello(&payload_over_offer)).encoded_len(),
            Err(NegotiationWireError::PayloadTooLarge)
        );
        assert_eq!(
            NegotiationFrame::Hello(payload_over_offer).encode_into(&mut [0; HEADER_LEN + 2]),
            Err(NegotiationWireError::PayloadTooLarge)
        );

        let mut bad_atomic = encoded(&hello(b""));
        put_u16(&mut bad_atomic, 148, 3);
        assert_eq!(
            decode_frame(
                &bad_atomic,
                SenderRole::Coordinator,
                NONCE,
                HARD_MAX_BOOTSTRAP_PAYLOAD_BYTES,
            ),
            Err(NegotiationWireError::BadAtomicFacts)
        );
    }

    #[test]
    fn exact_two_hello_transcript_binds_both_accept_decisions() {
        let verified = AtomicCapabilities::from_verified_native(4096, 128, true, true).unwrap();
        let mut coordinator = match hello(b"coordinator") {
            NegotiationFrame::Hello(frame) => frame,
            _ => unreachable!(),
        };
        coordinator.supported_features = FeatureBits([3, 1 << 40]);
        coordinator.required_features = FeatureBits([1, 0]);
        let mut receiver = duplicate_hello(&coordinator);
        receiver.role = SenderRole::Receiver;
        receiver.application_payload = b"receiver".to_vec();
        receiver.supported_features = FeatureBits([3, 0]);
        receiver.required_features = FeatureBits([2, 0]);
        receiver.limits.max_regions_per_batch = 4;

        let mut transcript = negotiate(&coordinator, &receiver, verified).unwrap();
        let coordinator_accept = transcript.expected_accept(SenderRole::Coordinator);
        let receiver_accept = transcript.expected_accept(SenderRole::Receiver);
        assert_ne!(receiver_accept.hello_digest, [0; 32]);
        assert_eq!(coordinator_accept.selected_features, FeatureBits([3, 0]));
        assert_eq!(coordinator_accept.effective_limits.max_regions_per_batch, 4);
        let mut out_of_order = negotiate(&coordinator, &receiver, verified).unwrap();
        assert_eq!(
            out_of_order.validate_accept(receiver_accept, SenderRole::Receiver),
            Err(NegotiationWireError::DecisionReplayOrOrder)
        );

        let mut substitutions = Vec::new();
        let mut wrong = receiver_accept;
        wrong.selected_features.0[0] ^= 1;
        substitutions.push(wrong);
        let mut wrong = receiver_accept;
        wrong.effective_limits.max_transactions -= 1;
        substitutions.push(wrong);
        let mut wrong = receiver_accept;
        wrong.atomics.u64_lock_free = false;
        substitutions.push(wrong);
        let mut wrong = receiver_accept;
        wrong.target.architecture = if wrong.target.architecture == 1 { 2 } else { 1 };
        substitutions.push(wrong);
        let mut wrong = receiver_accept;
        wrong.nonce[0] ^= 1;
        substitutions.push(wrong);
        let mut wrong = receiver_accept;
        wrong.hello_digest[0] ^= 1;
        substitutions.push(wrong);
        for wrong in substitutions {
            let mut substitution_transcript = negotiate(&coordinator, &receiver, verified).unwrap();
            substitution_transcript
                .validate_accept(coordinator_accept, SenderRole::Coordinator)
                .unwrap();
            assert_eq!(
                substitution_transcript.validate_accept(wrong, SenderRole::Receiver),
                Err(NegotiationWireError::EffectiveMismatch)
            );
        }
        let mut wrong_role = negotiate(&coordinator, &receiver, verified).unwrap();
        assert_eq!(
            wrong_role.validate_accept(receiver_accept, SenderRole::Coordinator),
            Err(NegotiationWireError::EffectiveMismatch)
        );

        transcript
            .validate_accept(coordinator_accept, SenderRole::Coordinator)
            .unwrap();
        transcript
            .validate_accept(receiver_accept, SenderRole::Receiver)
            .unwrap();

        let mut replay = negotiate(&coordinator, &receiver, verified).unwrap();
        replay
            .validate_accept(coordinator_accept, SenderRole::Coordinator)
            .unwrap();
        assert_eq!(
            replay.validate_accept(coordinator_accept, SenderRole::Coordinator),
            Err(NegotiationWireError::DecisionReplayOrOrder)
        );
        let mut changed_payload = duplicate_hello(&receiver);
        changed_payload.application_payload.push(b'!');
        let changed = negotiate(&coordinator, &changed_payload, verified).unwrap();
        assert_ne!(
            changed.expected_accept(SenderRole::Receiver).hello_digest,
            receiver_accept.hello_digest
        );

        let mut unknown_required = duplicate_hello(&receiver);
        unknown_required.supported_features.0[1] = 1;
        unknown_required.required_features.0[1] = 1;
        assert_eq!(
            negotiate(&coordinator, &unknown_required, verified),
            Err(NegotiationWireError::RequiredFeatureNotSupported)
        );

        let mut false_required_atomic = duplicate_hello(&receiver);
        false_required_atomic.atomics.u64_lock_free = false;
        assert_eq!(
            negotiate(&coordinator, &false_required_atomic, verified),
            Err(NegotiationWireError::RequiredFeatureNotSupported)
        );

        let mut optional_coordinator = duplicate_hello(&coordinator);
        optional_coordinator.required_features = FeatureBits::default();
        let mut optional_receiver = duplicate_hello(&receiver);
        optional_receiver.required_features = FeatureBits::default();
        optional_receiver.atomics.u64_lock_free = false;
        let optional = negotiate(&optional_coordinator, &optional_receiver, verified).unwrap();
        assert_eq!(
            optional
                .expected_accept(SenderRole::Coordinator)
                .selected_features,
            FeatureBits([1, 0])
        );

        let mut wrong_target = receiver;
        wrong_target.target.os = if wrong_target.target.os == 1 { 2 } else { 1 };
        assert_eq!(
            negotiate(&coordinator, &wrong_target, verified),
            Err(NegotiationWireError::TargetMismatch)
        );
    }

    #[test]
    fn hello_digest_has_a_platform_independent_golden_vector() {
        let fixed_target = TargetFacts {
            os: 1,
            architecture: 1,
            pointer_width: 64,
            endian: 1,
        };
        let fixed_atomics = AtomicOffer {
            u32_lock_free: true,
            u64_lock_free: true,
            u32_alignment: 4,
            u64_alignment: 8,
            page_alignment: 4096,
            cache_line_alignment: 128,
        };
        let mut coordinator = match hello(b"coordinator") {
            NegotiationFrame::Hello(frame) => frame,
            _ => unreachable!(),
        };
        coordinator.supported_features = FeatureBits([3, 1 << 40]);
        coordinator.required_features = FeatureBits([1, 0]);
        coordinator.target = fixed_target;
        coordinator.atomics = fixed_atomics;
        let mut receiver = duplicate_hello(&coordinator);
        receiver.role = SenderRole::Receiver;
        receiver.application_payload = b"receiver".to_vec();
        receiver.supported_features = FeatureBits([3, 0]);
        receiver.required_features = FeatureBits([2, 0]);
        receiver.limits.max_regions_per_batch = 4;
        let hello_digest = canonical_hello_digest(&coordinator, &receiver);

        assert_eq!(
            hello_digest,
            [
                165, 94, 237, 164, 126, 159, 1, 36, 189, 159, 155, 103, 94, 123, 53, 111, 220, 114,
                205, 225, 115, 255, 125, 98, 172, 215, 161, 88, 25, 185, 49, 42,
            ]
        );
    }
}
