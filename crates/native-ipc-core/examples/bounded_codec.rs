//! Encodes and decodes one manually defined protocol under explicit limits.

use native_ipc_core::codec::{
    DecodeContext, DecodeError, EncodeError, Envelope, Limits, Protocol, decode_message,
    encode_message,
};

struct CounterProtocol;

impl Protocol for CounterProtocol {
    type Message = u32;

    const SCHEMA_ID: [u8; 32] = [0x43; 32];

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
        let encoded: [u8; 4] = source.try_into().map_err(|_| DecodeError::Protocol(1))?;
        Ok(u32::from_le_bytes(encoded))
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut wire = [0_u8; 128];
    let written = encode_message::<CounterProtocol>(Envelope::new(1, 0, 7, 1), &42, &mut wire)?;

    let limits = Limits::new(128, 16, 1, 16);
    let decoded = decode_message::<CounterProtocol>(&wire[..written], &limits)?;

    assert_eq!(decoded.message, 42);
    assert_eq!(decoded.envelope.generation, 7);
    println!(
        "decoded counter {} from {} bounded bytes",
        decoded.message, written
    );
    Ok(())
}
