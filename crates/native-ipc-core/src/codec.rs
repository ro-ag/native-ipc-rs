//! Fixed-width little-endian envelopes and explicit payload codecs.

use alloc::vec::Vec;
use core::fmt;
use core::ops::Range;

/// Wire signature at the start of every encoded message.
pub const MESSAGE_MAGIC: u32 = 0x4e49_5043;
/// Current incompatible wire revision.
pub const VERSION_MAJOR: u16 = 1;
/// Current exact wire revision; decoders reject any different minor value.
pub const VERSION_MINOR: u16 = 0;
/// Bytes occupied by the common message envelope.
pub const ENVELOPE_LEN: usize = 72;

/// Bounded decoder policy applied before a protocol allocates or creates records.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Maximum complete encoded message size.
    pub max_message_bytes: u32,
    /// Maximum opaque payload size after the common envelope.
    pub max_payload_bytes: u32,
    /// Maximum variable records a protocol decoder may construct.
    pub max_records: u32,
    /// Maximum aggregate allocation a protocol decoder may perform.
    pub max_allocation_bytes: u32,
}

/// Stateful resource budget shared by one complete protocol decode.
pub struct DecodeContext<'a> {
    limits: &'a Limits,
    records_remaining: u32,
    allocation_remaining: u32,
}

impl<'a> DecodeContext<'a> {
    fn new(limits: &'a Limits) -> Self {
        Self {
            limits,
            records_remaining: limits.max_records,
            allocation_remaining: limits.max_allocation_bytes,
        }
    }

    /// Returns the immutable outer decoder policy.
    pub const fn limits(&self) -> &Limits {
        self.limits
    }

    /// Charges records against the aggregate budget before constructing them.
    pub fn claim_records(&mut self, count: u32) -> Result<(), DecodeError> {
        self.records_remaining = self
            .records_remaining
            .checked_sub(count)
            .ok_or(DecodeError::LimitExceeded(LimitKind::Records))?;
        Ok(())
    }

    /// Charges bytes against the aggregate allocation budget before allocation.
    pub fn claim_allocation(&mut self, bytes: u32) -> Result<(), DecodeError> {
        self.allocation_remaining = self
            .allocation_remaining
            .checked_sub(bytes)
            .ok_or(DecodeError::LimitExceeded(LimitKind::AllocationBytes))?;
        Ok(())
    }

    /// Charges and copies hostile bytes into owned storage.
    pub fn copy_bytes(&mut self, source: &[u8]) -> Result<Vec<u8>, DecodeError> {
        let len = u32::try_from(source.len()).map_err(|_| DecodeError::LengthOverflow)?;
        self.claim_allocation(len)?;
        Ok(source.to_vec())
    }
}

impl Limits {
    /// Creates an explicit decoder policy.
    pub const fn new(
        max_message_bytes: u32,
        max_payload_bytes: u32,
        max_records: u32,
        max_allocation_bytes: u32,
    ) -> Self {
        Self {
            max_message_bytes,
            max_payload_bytes,
            max_records,
            max_allocation_bytes,
        }
    }
}

/// Caller-provided metadata for a newly encoded message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Envelope {
    /// Numeric message kind; interpretation belongs to the protocol.
    pub kind: u32,
    /// Numeric flags; unknown required bits must be rejected by the protocol.
    pub flags: u32,
    /// Nonzero connection generation.
    pub generation: u64,
    /// Nonzero per-direction sequence.
    pub sequence: u64,
    payload_len: u32,
}

impl Envelope {
    /// Creates envelope metadata. The encoder fills the payload length.
    pub const fn new(kind: u32, flags: u32, generation: u64, sequence: u64) -> Self {
        Self {
            kind,
            flags,
            generation,
            sequence,
            payload_len: 0,
        }
    }

    /// Returns the encoded payload size.
    pub const fn payload_len(self) -> u32 {
        self.payload_len
    }

    /// Returns the total encoded size after checked conversion.
    pub fn total_len(self) -> Result<usize, EncodeError> {
        ENVELOPE_LEN
            .checked_add(self.payload_len as usize)
            .ok_or(EncodeError::LengthOverflow)
    }

    fn with_payload_len(mut self, payload_len: usize) -> Result<Self, EncodeError> {
        self.payload_len = u32::try_from(payload_len).map_err(|_| EncodeError::LengthOverflow)?;
        Ok(self)
    }
}

/// An owned, fully validated decoded message and its common metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedMessage<T> {
    /// Validated common metadata.
    pub envelope: Envelope,
    /// Protocol-owned safe message value.
    pub message: T,
}

/// Explicit protocol payload codec.
///
/// Implementations must manually encode fixed-width values and must apply
/// the decode context before allocation or record construction. The common envelope is
/// encoded and validated by [`encode_message`] and [`decode_message`].
pub trait Protocol {
    /// Safe, owned protocol message representation.
    type Message;

    /// Exact 256-bit schema identity for this protocol revision.
    const SCHEMA_ID: [u8; 32];

    /// Encodes only the protocol-specific payload.
    fn encode_payload(
        message: &Self::Message,
        destination: &mut [u8],
    ) -> Result<usize, EncodeError>;

    /// Decodes hostile payload bytes into an owned safe value.
    fn decode_payload(
        source: &[u8],
        context: &mut DecodeContext<'_>,
    ) -> Result<Self::Message, DecodeError>;
}

/// Encodes a common envelope followed by an explicitly encoded payload.
pub fn encode_message<P: Protocol>(
    envelope: Envelope,
    message: &P::Message,
    destination: &mut [u8],
) -> Result<usize, EncodeError> {
    if envelope.generation == 0 {
        return Err(EncodeError::ZeroGeneration);
    }
    if envelope.sequence == 0 {
        return Err(EncodeError::ZeroSequence);
    }
    if destination.len() < ENVELOPE_LEN {
        return Err(EncodeError::DestinationTooSmall {
            required: ENVELOPE_LEN,
            actual: destination.len(),
        });
    }

    let payload_len = P::encode_payload(message, &mut destination[ENVELOPE_LEN..])?;
    let envelope = envelope.with_payload_len(payload_len)?;
    let total_len = envelope.total_len()?;
    if total_len > destination.len() {
        return Err(EncodeError::DestinationTooSmall {
            required: total_len,
            actual: destination.len(),
        });
    }
    encode_envelope::<P>(envelope, &mut destination[..ENVELOPE_LEN]);
    Ok(total_len)
}

/// Validates the common envelope, bounds, and schema before decoding a payload.
pub fn decode_message<P: Protocol>(
    source: &[u8],
    limits: &Limits,
) -> Result<DecodedMessage<P::Message>, DecodeError> {
    if source.len() < ENVELOPE_LEN {
        return Err(DecodeError::Truncated {
            required: ENVELOPE_LEN,
            actual: source.len(),
        });
    }
    if source.len() > limits.max_message_bytes as usize {
        return Err(DecodeError::LimitExceeded(LimitKind::MessageBytes));
    }
    let envelope = decode_envelope::<P>(&source[..ENVELOPE_LEN])?;
    let payload_len = envelope.payload_len as usize;
    if payload_len > limits.max_payload_bytes as usize {
        return Err(DecodeError::LimitExceeded(LimitKind::PayloadBytes));
    }
    let total_len = ENVELOPE_LEN
        .checked_add(payload_len)
        .ok_or(DecodeError::LengthOverflow)?;
    if total_len != source.len() {
        return Err(DecodeError::NonCanonicalLength {
            declared: total_len,
            actual: source.len(),
        });
    }
    let mut context = DecodeContext::new(limits);
    let message = P::decode_payload(&source[ENVELOPE_LEN..], &mut context)?;
    Ok(DecodedMessage { envelope, message })
}

/// A checked relative byte range within one containing record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelativeRange(Range<usize>);

impl RelativeRange {
    /// Validates a `u32` offset and length relative to a containing record.
    pub fn new(offset: u32, len: u32, containing_len: usize) -> Result<Self, DecodeError> {
        let start = offset as usize;
        let end = start
            .checked_add(len as usize)
            .ok_or(DecodeError::LengthOverflow)?;
        if end > containing_len {
            return Err(DecodeError::RelativeRangeOutOfBounds {
                offset,
                len,
                containing_len,
            });
        }
        Ok(Self(start..end))
    }

    /// Returns the validated range.
    pub fn range(&self) -> Range<usize> {
        self.0.clone()
    }
}

/// Encoder failures; values remain bounded and contain no peer-provided text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EncodeError {
    /// Destination cannot contain the requested encoding.
    DestinationTooSmall {
        /// Minimum destination size.
        required: usize,
        /// Supplied destination size.
        actual: usize,
    },
    /// A length cannot be represented by the wire format.
    LengthOverflow,
    /// Generation zero is reserved.
    ZeroGeneration,
    /// Sequence zero is reserved.
    ZeroSequence,
    /// Protocol-specific bounded failure code.
    Protocol(u16),
}

/// Decoder resource limit that was exceeded.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LimitKind {
    /// Complete encoded message size.
    MessageBytes,
    /// Opaque payload size.
    PayloadBytes,
    /// Protocol record count.
    Records,
    /// Aggregate protocol allocation.
    AllocationBytes,
}

/// Decoder failures; values remain bounded and contain no peer-provided text.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
    /// Input ends before a required byte.
    Truncated {
        /// Minimum input size for the attempted decode.
        required: usize,
        /// Supplied input size.
        actual: usize,
    },
    /// Message signature is not recognized.
    BadMagic(u32),
    /// Wire version is unsupported.
    BadVersion {
        /// Received major version.
        major: u16,
        /// Received minor version.
        minor: u16,
    },
    /// Schema identity differs from the selected protocol.
    SchemaMismatch,
    /// Generation zero is reserved.
    ZeroGeneration,
    /// Sequence zero is reserved.
    ZeroSequence,
    /// Declared and actual sizes do not form one canonical record.
    NonCanonicalLength {
        /// Length declared by the envelope.
        declared: usize,
        /// Length of the supplied record.
        actual: usize,
    },
    /// Checked length arithmetic overflowed.
    LengthOverflow,
    /// A checked relative range escapes its containing record.
    RelativeRangeOutOfBounds {
        /// Peer-declared byte offset.
        offset: u32,
        /// Peer-declared byte length.
        len: u32,
        /// Size of the containing validated record.
        containing_len: usize,
    },
    /// A configured resource limit was exceeded.
    LimitExceeded(LimitKind),
    /// Protocol-specific bounded failure code.
    Protocol(u16),
}

impl fmt::Display for EncodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "message encoding failed: {self:?}")
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "message decoding failed: {self:?}")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for EncodeError {}
#[cfg(feature = "std")]
impl std::error::Error for DecodeError {}

fn encode_envelope<P: Protocol>(envelope: Envelope, bytes: &mut [u8]) {
    put_u32(bytes, 0, MESSAGE_MAGIC);
    put_u16(bytes, 4, VERSION_MAJOR);
    put_u16(bytes, 6, VERSION_MINOR);
    put_u32(bytes, 8, envelope.kind);
    put_u32(bytes, 12, envelope.flags);
    put_u32(bytes, 16, envelope.payload_len);
    put_u32(bytes, 20, ENVELOPE_LEN as u32);
    put_u64(bytes, 24, envelope.generation);
    put_u64(bytes, 32, envelope.sequence);
    bytes[40..72].copy_from_slice(&P::SCHEMA_ID);
}

fn decode_envelope<P: Protocol>(bytes: &[u8]) -> Result<Envelope, DecodeError> {
    let magic = get_u32(bytes, 0);
    if magic != MESSAGE_MAGIC {
        return Err(DecodeError::BadMagic(magic));
    }
    let major = get_u16(bytes, 4);
    let minor = get_u16(bytes, 6);
    if major != VERSION_MAJOR || minor != VERSION_MINOR {
        return Err(DecodeError::BadVersion { major, minor });
    }
    let header_len = get_u32(bytes, 20);
    if header_len != ENVELOPE_LEN as u32 {
        return Err(DecodeError::NonCanonicalLength {
            declared: header_len as usize,
            actual: ENVELOPE_LEN,
        });
    }
    if bytes[40..72] != P::SCHEMA_ID {
        return Err(DecodeError::SchemaMismatch);
    }
    let generation = get_u64(bytes, 24);
    if generation == 0 {
        return Err(DecodeError::ZeroGeneration);
    }
    let sequence = get_u64(bytes, 32);
    if sequence == 0 {
        return Err(DecodeError::ZeroSequence);
    }
    Ok(Envelope {
        kind: get_u32(bytes, 8),
        flags: get_u32(bytes, 12),
        generation,
        sequence,
        payload_len: get_u32(bytes, 16),
    })
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

#[cfg(test)]
#[path = "codec_test.rs"]
mod tests;
