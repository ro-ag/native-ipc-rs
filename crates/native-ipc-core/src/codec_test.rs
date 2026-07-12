use super::*;

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
        if source.len() != 4 {
            return Err(DecodeError::Protocol(1));
        }
        Ok(u32::from_le_bytes(source.try_into().unwrap()))
    }
}

const LIMITS: Limits = Limits::new(1024, 512, 8, 512);

#[test]
fn golden_envelope_is_manual_little_endian() {
    let mut actual = [0; ENVELOPE_LEN + 4];
    let len =
        encode_message::<U32Protocol>(Envelope::new(7, 0x10, 2, 3), &0x1122_3344, &mut actual)
            .unwrap();
    assert_eq!(len, 76);
    let mut expected = [0; ENVELOPE_LEN + 4];
    expected[0..4].copy_from_slice(&MESSAGE_MAGIC.to_le_bytes());
    expected[4..6].copy_from_slice(&VERSION_MAJOR.to_le_bytes());
    expected[6..8].copy_from_slice(&VERSION_MINOR.to_le_bytes());
    expected[8..12].copy_from_slice(&7_u32.to_le_bytes());
    expected[12..16].copy_from_slice(&0x10_u32.to_le_bytes());
    expected[16..20].copy_from_slice(&4_u32.to_le_bytes());
    expected[20..24].copy_from_slice(&(ENVELOPE_LEN as u32).to_le_bytes());
    expected[24..32].copy_from_slice(&2_u64.to_le_bytes());
    expected[32..40].copy_from_slice(&3_u64.to_le_bytes());
    expected[40..72].fill(0xa5);
    expected[72..76].copy_from_slice(&0x1122_3344_u32.to_le_bytes());
    assert_eq!(actual, expected);

    let decoded = decode_message::<U32Protocol>(&actual, &LIMITS).unwrap();
    assert_eq!(decoded.envelope.kind, 7);
    assert_eq!(decoded.message, 0x1122_3344);
}

#[test]
fn hostile_common_fields_are_rejected_before_payload_decode() {
    let mut bytes = [0; ENVELOPE_LEN + 4];
    encode_message::<U32Protocol>(Envelope::new(1, 0, 5, 1), &7, &mut bytes).unwrap();

    for len in 0..ENVELOPE_LEN {
        assert!(matches!(
            decode_message::<U32Protocol>(&bytes[..len], &LIMITS),
            Err(DecodeError::Truncated { .. })
        ));
    }
    let mut bad = bytes;
    bad[40] ^= 1;
    assert_eq!(
        decode_message::<U32Protocol>(&bad, &LIMITS).unwrap_err(),
        DecodeError::SchemaMismatch
    );
    let mut bad = bytes;
    bad[16..20].copy_from_slice(&500_u32.to_le_bytes());
    assert!(matches!(
        decode_message::<U32Protocol>(&bad, &LIMITS),
        Err(DecodeError::NonCanonicalLength { .. })
    ));
    let strict = Limits::new(75, 512, 8, 512);
    assert_eq!(
        decode_message::<U32Protocol>(&bytes, &strict).unwrap_err(),
        DecodeError::LimitExceeded(LimitKind::MessageBytes)
    );
}

#[test]
fn relative_ranges_and_allocation_limits_are_checked() {
    assert_eq!(RelativeRange::new(2, 3, 5).unwrap().range(), 2..5);
    assert!(matches!(
        RelativeRange::new(u32::MAX, 2, 8),
        Err(DecodeError::RelativeRangeOutOfBounds { .. })
    ));
    let limits = Limits::new(10, 10, 1, 8);
    let mut context = DecodeContext::new(&limits);
    assert_eq!(
        context.copy_bytes(&[0; 9]).unwrap_err(),
        DecodeError::LimitExceeded(LimitKind::AllocationBytes)
    );
    let aggregate_limits = Limits::new(10, 10, 1, 8);
    let mut context = DecodeContext::new(&aggregate_limits);
    assert_eq!(context.copy_bytes(&[0; 4]).unwrap(), &[0; 4]);
    assert_eq!(context.copy_bytes(&[0; 4]).unwrap(), &[0; 4]);
    assert_eq!(
        context.copy_bytes(&[0; 1]).unwrap_err(),
        DecodeError::LimitExceeded(LimitKind::AllocationBytes)
    );
}
