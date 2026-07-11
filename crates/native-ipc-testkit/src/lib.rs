#![doc = include_str!("../README.md")]

use native_ipc_core::codec::{ENVELOPE_LEN, Envelope, Protocol, encode_message};

/// Produces truncations of `input`, including the empty and complete input.
pub fn every_truncation(input: &[u8]) -> impl Iterator<Item = &[u8]> {
    (0..=input.len()).map(|len| &input[..len])
}

/// Produces at most `limit` deterministic one-bit hostile mutations.
///
/// The explicit limit keeps decoder corpora bounded in CI and downstream tests.
pub fn bounded_bit_mutations(input: &[u8], limit: usize) -> Vec<Vec<u8>> {
    input
        .iter()
        .enumerate()
        .take(limit)
        .map(|(index, _)| {
            let mut mutated = input.to_vec();
            mutated[index] ^= 1;
            mutated
        })
        .collect()
}

/// Produces bounded hostile region-header/layout mutations at fixed fields.
pub fn hostile_layout_mutations(valid_region: &[u8]) -> Vec<Vec<u8>> {
    const OFFSETS: [usize; 12] = [0, 8, 12, 16, 56, 64, 68, 72, 80, 88, 96, 108];
    OFFSETS
        .into_iter()
        .filter(|offset| *offset < valid_region.len())
        .map(|offset| {
            let mut mutated = valid_region.to_vec();
            mutated[offset] ^= 1;
            mutated
        })
        .collect()
}

/// Boundary values for hostile relative-offset and declared-length corpora.
pub const HOSTILE_U64_BOUNDARIES: [u64; 7] = [0, 1, 71, 72, 127, u32::MAX as u64, u64::MAX];

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
