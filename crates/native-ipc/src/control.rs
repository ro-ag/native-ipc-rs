use crate::session::HARD_MAX_CONTROL_PAYLOAD_BYTES;
use core::cell::Cell;
use core::marker::PhantomData;

const MAGIC: [u8; 8] = *b"NIPCAPP1";
const VERSION_MAJOR: u16 = 1;
const VERSION_MINOR: u16 = 0;
const HEADER_LEN: usize = 72;
const APPLICATION_KIND_MIN: u32 = 0x8000_0000;

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ControlFrame {
    pub(crate) kind: u32,
    pub(crate) payload: Vec<u8>,
}

pub(crate) struct ControlState {
    nonce: [u8; 32],
    maximum_payload: u32,
    next_send: u64,
    next_receive: u64,
    transaction_open: bool,
    poisoned: bool,
    pending_receive: bool,
    not_sync: PhantomData<Cell<()>>,
}

impl ControlState {
    pub(crate) fn new(nonce: [u8; 32], maximum_payload: u32) -> Option<Self> {
        if nonce == [0; 32]
            || maximum_payload == 0
            || maximum_payload > HARD_MAX_CONTROL_PAYLOAD_BYTES
        {
            return None;
        }
        Some(Self {
            nonce,
            maximum_payload,
            next_send: 1,
            next_receive: 1,
            transaction_open: false,
            poisoned: false,
            pending_receive: false,
            not_sync: PhantomData,
        })
    }

    pub(crate) fn encoded_len(&self, frame: &ControlFrame) -> Result<usize, ControlError> {
        self.check_local(frame)?;
        HEADER_LEN
            .checked_add(frame.payload.len())
            .ok_or(ControlError::LengthOverflow)
    }

    pub(crate) fn encode_into(
        &mut self,
        frame: &ControlFrame,
        destination: &mut [u8],
    ) -> Result<usize, ControlError> {
        if self.transaction_open || self.pending_receive {
            self.poisoned = true;
            return Err(ControlError::TransactionConflict);
        }
        if self.next_send == u64::MAX {
            self.poisoned = true;
            return Err(ControlError::SequenceExhausted);
        }
        let required = self.encoded_len(frame)?;
        if destination.len() < required {
            return Err(ControlError::DestinationTooSmall);
        }
        destination[..required].fill(0);
        destination[..8].copy_from_slice(&MAGIC);
        put_u16(destination, 8, VERSION_MAJOR);
        put_u16(destination, 10, VERSION_MINOR);
        put_u32(destination, 12, HEADER_LEN as u32);
        put_u32(
            destination,
            16,
            u32::try_from(required).map_err(|_| ControlError::LengthOverflow)?,
        );
        put_u32(
            destination,
            20,
            u32::try_from(frame.payload.len()).map_err(|_| ControlError::LengthOverflow)?,
        );
        put_u32(destination, 24, frame.kind);
        destination[32..64].copy_from_slice(&self.nonce);
        put_u64(destination, 64, self.next_send);
        destination[HEADER_LEN..required].copy_from_slice(&frame.payload);
        self.next_send = self
            .next_send
            .checked_add(1)
            .ok_or(ControlError::SequenceExhausted)?;
        Ok(required)
    }

    pub(crate) fn decode(&mut self, source: &[u8]) -> Result<ControlFrame, ControlError> {
        if source.len() < HEADER_LEN {
            self.poisoned = true;
            return Err(ControlError::Truncated);
        }
        let header = self.validate_header(&source[..HEADER_LEN])?;
        let expected = HEADER_LEN + header.payload_len();
        if source.len() != expected {
            return Err(ControlError::NonCanonical);
        }
        header.finish(&source[HEADER_LEN..])
    }

    pub(crate) fn validate_header(
        &mut self,
        source: &[u8],
    ) -> Result<PendingControlReceive<'_>, ControlError> {
        let result = self.validate_header_inner(source);
        if result.is_err() {
            self.poisoned = true;
        } else {
            self.pending_receive = true;
        }
        result.map(|header| PendingControlReceive {
            state: self,
            kind: header.kind,
            payload_len: header.payload_len,
            committed: false,
        })
    }

    pub(crate) fn begin_transaction(&mut self) -> Result<(), ControlError> {
        if self.poisoned {
            return Err(ControlError::Poisoned);
        }
        if self.transaction_open || self.pending_receive {
            self.poisoned = true;
            return Err(ControlError::TransactionConflict);
        }
        self.transaction_open = true;
        Ok(())
    }

    pub(crate) fn end_transaction(&mut self) -> Result<(), ControlError> {
        if self.poisoned {
            return Err(ControlError::Poisoned);
        }
        if !self.transaction_open {
            self.poisoned = true;
            return Err(ControlError::TransactionConflict);
        }
        self.transaction_open = false;
        Ok(())
    }

    fn check_local(&self, frame: &ControlFrame) -> Result<(), ControlError> {
        if self.poisoned {
            return Err(ControlError::Poisoned);
        }
        if self.transaction_open {
            return Err(ControlError::TransactionConflict);
        }
        if frame.kind < APPLICATION_KIND_MIN {
            return Err(ControlError::ReservedKind);
        }
        let payload_len =
            u32::try_from(frame.payload.len()).map_err(|_| ControlError::LengthOverflow)?;
        if payload_len > self.maximum_payload || payload_len > HARD_MAX_CONTROL_PAYLOAD_BYTES {
            return Err(ControlError::PayloadTooLarge);
        }
        if self.next_send == u64::MAX {
            return Err(ControlError::SequenceExhausted);
        }
        Ok(())
    }

    fn validate_header_inner(&self, source: &[u8]) -> Result<ValidatedControlHeader, ControlError> {
        if self.poisoned {
            return Err(ControlError::Poisoned);
        }
        if self.transaction_open {
            return Err(ControlError::TransactionConflict);
        }
        if self.pending_receive {
            return Err(ControlError::ReplayOrReorder);
        }
        if source.len() != HEADER_LEN {
            return Err(ControlError::Truncated);
        }
        if source[..8] != MAGIC {
            return Err(ControlError::BadMagic);
        }
        if get_u16(source, 8) != VERSION_MAJOR || get_u16(source, 10) != VERSION_MINOR {
            return Err(ControlError::BadVersion);
        }
        if get_u32(source, 12) != HEADER_LEN as u32 || get_u32(source, 28) != 0 {
            return Err(ControlError::NonCanonical);
        }
        let frame_len = get_u32(source, 16) as usize;
        let payload_len = get_u32(source, 20);
        let expected_len = HEADER_LEN
            .checked_add(payload_len as usize)
            .ok_or(ControlError::LengthOverflow)?;
        if frame_len != expected_len {
            return Err(ControlError::NonCanonical);
        }
        if payload_len > self.maximum_payload || payload_len > HARD_MAX_CONTROL_PAYLOAD_BYTES {
            return Err(ControlError::PayloadTooLarge);
        }
        let kind = get_u32(source, 24);
        if kind < APPLICATION_KIND_MIN {
            return Err(ControlError::ReservedKind);
        }
        if source[32..64] != self.nonce {
            return Err(ControlError::WrongSession);
        }
        if get_u64(source, 64) != self.next_receive {
            return Err(ControlError::ReplayOrReorder);
        }
        if self.next_receive == u64::MAX {
            return Err(ControlError::SequenceExhausted);
        }
        Ok(ValidatedControlHeader { kind, payload_len })
    }
}

pub(crate) struct ValidatedControlHeader {
    kind: u32,
    payload_len: u32,
}

pub(crate) struct PendingControlReceive<'a> {
    state: &'a mut ControlState,
    kind: u32,
    payload_len: u32,
    committed: bool,
}

impl PendingControlReceive<'_> {
    pub(crate) const fn payload_len(&self) -> usize {
        self.payload_len as usize
    }

    pub(crate) fn finish(mut self, payload_source: &[u8]) -> Result<ControlFrame, ControlError> {
        if payload_source.len() != self.payload_len as usize {
            return Err(ControlError::NonCanonical);
        }
        let mut payload = Vec::new();
        payload
            .try_reserve_exact(self.payload_len as usize)
            .map_err(|_| ControlError::AllocationFailed)?;
        payload.extend_from_slice(payload_source);
        self.state.next_receive = self
            .state
            .next_receive
            .checked_add(1)
            .ok_or(ControlError::SequenceExhausted)?;
        self.state.pending_receive = false;
        self.committed = true;
        Ok(ControlFrame {
            kind: self.kind,
            payload,
        })
    }
}

impl Drop for PendingControlReceive<'_> {
    fn drop(&mut self) {
        if !self.committed {
            self.state.pending_receive = false;
            self.state.poisoned = true;
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ControlError {
    Poisoned,
    Truncated,
    BadMagic,
    BadVersion,
    NonCanonical,
    WrongSession,
    ReservedKind,
    PayloadTooLarge,
    ReplayOrReorder,
    TransactionConflict,
    SequenceExhausted,
    LengthOverflow,
    AllocationFailed,
    DestinationTooSmall,
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
mod tests {
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
}
