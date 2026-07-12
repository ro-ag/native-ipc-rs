use crate::session::HARD_MAX_CONTROL_PAYLOAD_BYTES;
use core::cell::Cell;
use core::marker::PhantomData;

const MAGIC: [u8; 8] = *b"NIPCAPP1";
const VERSION_MAJOR: u16 = 1;
const VERSION_MINOR: u16 = 0;
pub(crate) const CONTROL_HEADER_LEN: usize = 72;
const APPLICATION_KIND_MIN: u32 = 0x8000_0000;

pub(crate) const fn control_wire_len(payload_len: usize) -> Option<usize> {
    CONTROL_HEADER_LEN.checked_add(payload_len)
}

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
        control_wire_len(frame.payload.len()).ok_or(ControlError::LengthOverflow)
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
        put_u32(destination, 12, CONTROL_HEADER_LEN as u32);
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
        destination[CONTROL_HEADER_LEN..required].copy_from_slice(&frame.payload);
        self.next_send = self
            .next_send
            .checked_add(1)
            .ok_or(ControlError::SequenceExhausted)?;
        Ok(required)
    }

    pub(crate) fn decode(&mut self, source: &[u8]) -> Result<ControlFrame, ControlError> {
        if source.len() < CONTROL_HEADER_LEN {
            self.poisoned = true;
            return Err(ControlError::Truncated);
        }
        let header = self.validate_header(&source[..CONTROL_HEADER_LEN])?;
        let expected =
            control_wire_len(header.payload_len()).ok_or(ControlError::LengthOverflow)?;
        if source.len() != expected {
            return Err(ControlError::NonCanonical);
        }
        header.finish(&source[CONTROL_HEADER_LEN..])
    }

    pub(crate) fn decode_owned(
        &mut self,
        mut source: Vec<u8>,
    ) -> Result<ControlFrame, ControlError> {
        if source.len() < CONTROL_HEADER_LEN {
            self.poisoned = true;
            return Err(ControlError::Truncated);
        }
        let header = self.validate_header(&source[..CONTROL_HEADER_LEN])?;
        let payload_len = header.payload_len();
        let expected = control_wire_len(payload_len).ok_or(ControlError::LengthOverflow)?;
        if source.len() != expected {
            return Err(ControlError::NonCanonical);
        }
        source.copy_within(CONTROL_HEADER_LEN..expected, 0);
        source.truncate(payload_len);
        header.finish_owned(source)
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

    pub(crate) fn poison(&mut self) {
        self.poisoned = true;
    }

    pub(crate) const fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    pub(crate) const fn is_transaction_open(&self) -> bool {
        self.transaction_open
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
        if source.len() != CONTROL_HEADER_LEN {
            return Err(ControlError::Truncated);
        }
        if source[..8] != MAGIC {
            return Err(ControlError::BadMagic);
        }
        if get_u16(source, 8) != VERSION_MAJOR || get_u16(source, 10) != VERSION_MINOR {
            return Err(ControlError::BadVersion);
        }
        if get_u32(source, 12) != CONTROL_HEADER_LEN as u32 || get_u32(source, 28) != 0 {
            return Err(ControlError::NonCanonical);
        }
        let frame_len = get_u32(source, 16) as usize;
        let payload_len = get_u32(source, 20);
        let expected_len =
            control_wire_len(payload_len as usize).ok_or(ControlError::LengthOverflow)?;
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

    pub(crate) fn finish(self, payload_source: &[u8]) -> Result<ControlFrame, ControlError> {
        if payload_source.len() != self.payload_len as usize {
            return Err(ControlError::NonCanonical);
        }
        let mut payload = Vec::new();
        payload
            .try_reserve_exact(self.payload_len as usize)
            .map_err(|_| ControlError::AllocationFailed)?;
        payload.extend_from_slice(payload_source);
        self.finish_owned(payload)
    }

    pub(crate) fn finish_owned(mut self, payload: Vec<u8>) -> Result<ControlFrame, ControlError> {
        if payload.len() != self.payload_len as usize {
            return Err(ControlError::NonCanonical);
        }
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
#[path = "control_test.rs"]
mod tests;
