//! Cross-platform committed protocol golden-vector conformance.

use native_ipc_core::codec::{
    DecodeContext, DecodeError, EncodeError, Envelope, Limits, Protocol, decode_message,
};
use native_ipc_testkit::{every_truncation, golden_message};

struct U32Protocol;

impl Protocol for U32Protocol {
    type Message = u32;
    const SCHEMA_ID: [u8; 32] = [0xa5; 32];

    fn encode_payload(
        message: &Self::Message,
        destination: &mut [u8],
    ) -> Result<usize, EncodeError> {
        if destination.len() < 4 {
            return Err(EncodeError::DestinationTooSmall {
                required: 4,
                actual: destination.len(),
            });
        }
        destination[..4].copy_from_slice(&message.to_le_bytes());
        Ok(4)
    }

    fn decode_payload(
        source: &[u8],
        _context: &mut DecodeContext<'_>,
    ) -> Result<Self::Message, DecodeError> {
        let bytes: [u8; 4] = source.try_into().map_err(|_| DecodeError::Protocol(1))?;
        Ok(u32::from_le_bytes(bytes))
    }
}

fn decode_hex(source: &str) -> Vec<u8> {
    let compact = source.trim();
    assert_eq!(compact.len() % 2, 0);
    compact
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(pair, 16).unwrap()
        })
        .collect()
}

#[test]
fn committed_golden_vector_is_platform_independent() {
    let expected = decode_hex(include_str!("vectors/u32-message.hex"));
    let actual =
        golden_message::<U32Protocol>(Envelope::new(7, 0x10, 2, 3), &0x1122_3344, 4).unwrap();
    assert_eq!(actual, expected);

    let limits = Limits::new(1024, 512, 8, 512);
    let decoded = decode_message::<U32Protocol>(&actual, &limits).unwrap();
    assert_eq!(decoded.message, 0x1122_3344);
}

#[test]
fn every_truncated_golden_vector_is_rejected_without_panic() {
    let vector = decode_hex(include_str!("vectors/u32-message.hex"));
    let limits = Limits::new(1024, 512, 8, 512);
    for truncation in every_truncation(&vector).take(vector.len()) {
        assert!(decode_message::<U32Protocol>(truncation, &limits).is_err());
    }
}
