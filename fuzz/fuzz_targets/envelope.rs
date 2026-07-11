#![no_main]

use libfuzzer_sys::fuzz_target;
use native_ipc_core::codec::{
    DecodeContext, DecodeError, EncodeError, Limits, Protocol, decode_message,
};

struct BytesProtocol;

impl Protocol for BytesProtocol {
    type Message = Vec<u8>;
    const SCHEMA_ID: [u8; 32] = [0x46; 32];

    fn encode_payload(
        message: &Self::Message,
        destination: &mut [u8],
    ) -> Result<usize, EncodeError> {
        if destination.len() < message.len() {
            return Err(EncodeError::DestinationTooSmall {
                required: message.len(),
                actual: destination.len(),
            });
        }
        destination[..message.len()].copy_from_slice(message);
        Ok(message.len())
    }

    fn decode_payload(
        source: &[u8],
        context: &mut DecodeContext<'_>,
    ) -> Result<Self::Message, DecodeError> {
        context.copy_bytes(source)
    }
}

fuzz_target!(|data: &[u8]| {
    if data.len() > 4096 {
        return;
    }
    let limits = Limits::new(4096, 2048, 16, 2048);
    let _ = decode_message::<BytesProtocol>(data, &limits);
});
