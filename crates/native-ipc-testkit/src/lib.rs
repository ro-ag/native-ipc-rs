//! Adversarial inputs and cross-platform golden fixtures for `native-ipc`.

use native_ipc_core::codec::{ENVELOPE_LEN, Envelope, Protocol, encode_message};

/// Produces truncations of `input`, including the empty and complete input.
pub fn every_truncation(input: &[u8]) -> impl Iterator<Item = &[u8]> {
    (0..=input.len()).map(|len| &input[..len])
}

/// Encodes a message into an exactly sized owned golden vector.
pub fn golden_message<P: Protocol>(
    envelope: Envelope,
    message: &P::Message,
    payload_capacity: usize,
) -> Result<Vec<u8>, native_ipc_core::codec::EncodeError> {
    let total_capacity = ENVELOPE_LEN
        .checked_add(payload_capacity)
        .ok_or(native_ipc_core::codec::EncodeError::LengthOverflow)?;
    let mut bytes = vec![0; total_capacity];
    let written = encode_message::<P>(envelope, message, &mut bytes)?;
    bytes.truncate(written);
    Ok(bytes)
}
