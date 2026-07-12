use super::*;
use static_assertions::{assert_impl_all, assert_not_impl_any};

assert_impl_all!(ControlState: Send);
assert_not_impl_any!(ControlState: Sync, Clone);
assert_not_impl_any!(ValidatedControlHeader: Clone);
assert_not_impl_any!(PendingControlReceive<'static>: Clone);

const NONCE: [u8; 32] = [9; 32];

fn frame(payload: &[u8]) -> ControlFrame {
    ControlFrame {
        kind: APPLICATION_KIND_MIN + 7,
        payload: payload.to_vec(),
    }
}

fn encode(state: &mut ControlState, frame: &ControlFrame) -> Vec<u8> {
    let mut bytes = vec![0; state.encoded_len(frame).unwrap()];
    let len = state.encode_into(frame, &mut bytes).unwrap();
    assert_eq!(len, bytes.len());
    bytes
}

#[test]
fn bounded_opaque_duplex_records_are_exact_and_sequenced() {
    let mut sender = ControlState::new(NONCE, 16).unwrap();
    let mut receiver = ControlState::new(NONCE, 16).unwrap();
    let first = encode(&mut sender, &frame(b"one"));
    assert_eq!(&first[..8], &MAGIC);
    assert_eq!(get_u32(&first, 12), HEADER_LEN as u32);
    assert_eq!(get_u32(&first, 16) as usize, HEADER_LEN + 3);
    assert_eq!(get_u32(&first, 20), 3);
    assert_eq!(get_u64(&first, 64), 1);
    assert_eq!(receiver.decode(&first).unwrap(), frame(b"one"));

    let second = encode(&mut sender, &frame(b""));
    assert_eq!(get_u64(&second, 64), 2);
    assert_eq!(receiver.decode(&second).unwrap(), frame(b""));

    assert!(ControlState::new([0; 32], 1).is_none());
    assert!(ControlState::new(NONCE, 0).is_none());
    assert!(ControlState::new(NONCE, HARD_MAX_CONTROL_PAYLOAD_BYTES + 1).is_none());
}

#[test]
fn every_truncation_mutation_and_replay_poisons_receive_state() {
    let mut sender = ControlState::new(NONCE, 16).unwrap();
    let bytes = encode(&mut sender, &frame(b"payload"));
    for len in 0..bytes.len() {
        let mut receiver = ControlState::new(NONCE, 16).unwrap();
        assert!(receiver.decode(&bytes[..len]).is_err(), "length {len}");
        assert_eq!(receiver.decode(&bytes), Err(ControlError::Poisoned));
    }

    let mutations = [0, 8, 10, 12, 16, 20, 28, 32, 64];
    for offset in mutations {
        let mut bad = bytes.clone();
        bad[offset] ^= 0x80;
        let mut receiver = ControlState::new(NONCE, 16).unwrap();
        assert!(receiver.decode(&bad).is_err(), "offset {offset}");
        assert_eq!(receiver.decode(&bytes), Err(ControlError::Poisoned));
    }

    let mut reserved_kind = bytes.clone();
    put_u32(&mut reserved_kind, 24, 1);
    let mut receiver = ControlState::new(NONCE, 16).unwrap();
    assert_eq!(
        receiver.decode(&reserved_kind),
        Err(ControlError::ReservedKind)
    );

    let mut receiver = ControlState::new(NONCE, 16).unwrap();
    receiver.decode(&bytes).unwrap();
    assert_eq!(receiver.decode(&bytes), Err(ControlError::ReplayOrReorder));
    assert_eq!(receiver.decode(&bytes), Err(ControlError::Poisoned));
}

#[test]
fn transaction_conflict_and_reserved_or_oversized_local_frames_fail_closed() {
    let mut state = ControlState::new(NONCE, 3).unwrap();
    let oversized = frame(b"four");
    assert_eq!(
        state.encode_into(&oversized, &mut [0; HEADER_LEN + 4]),
        Err(ControlError::PayloadTooLarge)
    );
    let reserved = ControlFrame {
        kind: APPLICATION_KIND_MIN - 1,
        payload: Vec::new(),
    };
    assert_eq!(
        state.encode_into(&reserved, &mut [0; HEADER_LEN]),
        Err(ControlError::ReservedKind)
    );
    assert_eq!(encode(&mut state, &frame(b"ok")).len(), HEADER_LEN + 2);

    state.begin_transaction().unwrap();
    assert_eq!(
        state.encode_into(&frame(b""), &mut [0; HEADER_LEN]),
        Err(ControlError::TransactionConflict)
    );
    assert_eq!(state.end_transaction(), Err(ControlError::Poisoned));
}

#[test]
fn header_first_tokens_and_bidirectional_boundaries_are_exact() {
    let mut a = ControlState::new(NONCE, 3).unwrap();
    let mut b = ControlState::new(NONCE, 3).unwrap();
    let a_to_b = encode(
        &mut a,
        &ControlFrame {
            kind: APPLICATION_KIND_MIN,
            payload: b"max".to_vec(),
        },
    );
    let header = b.validate_header(&a_to_b[..HEADER_LEN]).unwrap();
    assert_eq!(header.payload_len(), 3);
    assert_eq!(
        header.finish(&a_to_b[HEADER_LEN..]).unwrap(),
        ControlFrame {
            kind: APPLICATION_KIND_MIN,
            payload: b"max".to_vec(),
        }
    );

    let b_to_a = encode(&mut b, &frame(b"b"));
    assert_eq!(a.decode(&b_to_a).unwrap(), frame(b"b"));
    let second_a_to_b = encode(&mut a, &frame(b"a"));
    assert_eq!(b.decode(&second_a_to_b).unwrap(), frame(b"a"));

    let mut future = second_a_to_b.clone();
    put_u64(&mut future, 64, 9);
    let mut fresh = ControlState::new(NONCE, 3).unwrap();
    assert_eq!(fresh.decode(&future), Err(ControlError::ReplayOrReorder));

    let mut short_destination = ControlState::new(NONCE, 3).unwrap();
    assert_eq!(
        short_destination.encode_into(&frame(b"x"), &mut [0; HEADER_LEN]),
        Err(ControlError::DestinationTooSmall)
    );
    assert_eq!(
        get_u64(&encode(&mut short_destination, &frame(b"x")), 64),
        1
    );

    let mut during_transaction = ControlState::new(NONCE, 3).unwrap();
    during_transaction.begin_transaction().unwrap();
    assert_eq!(
        during_transaction.decode(&a_to_b),
        Err(ControlError::TransactionConflict)
    );
    assert_eq!(
        during_transaction.decode(&a_to_b),
        Err(ControlError::Poisoned)
    );

    let mut exhausted_send = ControlState::new(NONCE, 3).unwrap();
    exhausted_send.next_send = u64::MAX;
    assert_eq!(
        exhausted_send.encode_into(&frame(b""), &mut [0; HEADER_LEN]),
        Err(ControlError::SequenceExhausted)
    );
    assert_eq!(
        exhausted_send.begin_transaction(),
        Err(ControlError::Poisoned)
    );

    let mut exhausted_receive = ControlState::new(NONCE, 3).unwrap();
    exhausted_receive.next_receive = u64::MAX;
    let mut maximum_sequence = a_to_b;
    put_u64(&mut maximum_sequence, 64, u64::MAX);
    assert_eq!(
        exhausted_receive.decode(&maximum_sequence),
        Err(ControlError::SequenceExhausted)
    );
}

#[test]
fn dropping_a_validated_header_guard_immediately_poisons() {
    let mut sender = ControlState::new(NONCE, 8).unwrap();
    let bytes = encode(&mut sender, &frame(b"value"));
    let mut first = ControlState::new(NONCE, 8).unwrap();
    let header = first.validate_header(&bytes[..HEADER_LEN]).unwrap();
    assert_eq!(header.payload_len(), 5);
    drop(header);
    assert_eq!(first.decode(&bytes), Err(ControlError::Poisoned));
}
