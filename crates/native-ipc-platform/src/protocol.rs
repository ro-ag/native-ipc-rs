use native_ipc_core::layout::ValidationExpectations;

pub(crate) const CONTROL_VERSION: u32 = 1;
pub(crate) const MAX_TRANSFER_ENTRIES: usize = 16;
pub(crate) const ENTRY_LEN: usize = 64;
pub(crate) const CONTROL_FRAME_LEN: usize = 96 + MAX_TRANSFER_ENTRIES * ENTRY_LEN;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
#[allow(dead_code)] // Each target uses the access modes its native backend supports.
pub(crate) enum PeerAccess {
    ReadOnly = 1,
    SoleWriter = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ManifestEntry {
    pub(crate) schema_id: [u8; 32],
    pub(crate) generation: u64,
    pub(crate) role: u32,
    pub(crate) writer: u32,
    pub(crate) access: PeerAccess,
    pub(crate) capability_len: u64,
}

impl ManifestEntry {
    pub(crate) fn validated(
        expected: ValidationExpectations,
        capability_len: usize,
        access: PeerAccess,
    ) -> Option<Self> {
        let capability_len = u64::try_from(capability_len).ok()?;
        if expected.generation == 0 || capability_len == 0 {
            return None;
        }
        Some(Self {
            schema_id: expected.schema_id,
            generation: expected.generation,
            role: expected.role.get(),
            writer: expected.writer as u32,
            access,
            capability_len,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TransferManifest {
    pub(crate) nonce: [u8; 32],
    pub(crate) parent_pid: u32,
    pub(crate) child_pid: u32,
    pub(crate) transfer_id: u64,
    entries: Vec<ManifestEntry>,
}

impl TransferManifest {
    pub(crate) fn new(
        nonce: [u8; 32],
        parent_pid: u32,
        child_pid: u32,
        transfer_id: u64,
        mut entries: Vec<ManifestEntry>,
    ) -> Option<Self> {
        if nonce == [0; 32]
            || parent_pid == 0
            || child_pid == 0
            || transfer_id == 0
            || transfer_id == u64::MAX
            || entries.is_empty()
            || entries.len() > MAX_TRANSFER_ENTRIES
        {
            return None;
        }
        entries.sort_unstable_by_key(|entry| entry.role);
        if entries.windows(2).any(|pair| pair[0].role == pair[1].role) {
            return None;
        }
        Some(Self {
            nonce,
            parent_pid,
            child_pid,
            transfer_id,
            entries,
        })
    }

    pub(crate) fn encode(&self, magic: [u8; 8]) -> [u8; CONTROL_FRAME_LEN] {
        let mut frame = [0_u8; CONTROL_FRAME_LEN];
        frame[..8].copy_from_slice(&magic);
        frame[8..12].copy_from_slice(&CONTROL_VERSION.to_le_bytes());
        frame[12..16].copy_from_slice(&(self.entries.len() as u32).to_le_bytes());
        frame[16..48].copy_from_slice(&self.nonce);
        frame[48..52].copy_from_slice(&self.parent_pid.to_le_bytes());
        frame[52..56].copy_from_slice(&self.child_pid.to_le_bytes());
        frame[56..64].copy_from_slice(&self.transfer_id.to_le_bytes());
        for (index, entry) in self.entries.iter().enumerate() {
            let start = 96 + index * ENTRY_LEN;
            frame[start..start + 32].copy_from_slice(&entry.schema_id);
            frame[start + 32..start + 40].copy_from_slice(&entry.generation.to_le_bytes());
            frame[start + 40..start + 44].copy_from_slice(&entry.role.to_le_bytes());
            frame[start + 44..start + 48].copy_from_slice(&entry.writer.to_le_bytes());
            frame[start + 48..start + 52].copy_from_slice(&(entry.access as u32).to_le_bytes());
            frame[start + 56..start + 64].copy_from_slice(&entry.capability_len.to_le_bytes());
        }
        frame
    }

    #[allow(dead_code)] // macOS compares the same fixed transcript in Mach receive validation.
    pub(crate) fn matches_frame(&self, magic: [u8; 8], frame: &[u8]) -> bool {
        frame.len() == CONTROL_FRAME_LEN && self.encode(magic).as_slice() == frame
    }
}

/// Mints a process-unique channel identity for pending-value provenance.
#[cfg(any(target_os = "macos", target_os = "windows"))]
pub(crate) fn mint_channel_id() -> u64 {
    use core::sync::atomic::{AtomicU64, Ordering};
    static NEXT_CHANNEL_ID: AtomicU64 = AtomicU64::new(1);
    NEXT_CHANNEL_ID.fetch_add(1, Ordering::Relaxed)
}

/// Unforgeable binding from a pending runtime value to the exact channel
/// transaction that created it.
///
/// Private fields keep values unmintable and unmodifiable outside this crate,
/// so a commit operation can require that every supplied pending value came
/// from its own channel and its currently open transfer transaction.
#[cfg(any(target_os = "macos", target_os = "windows"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct TransferProvenance {
    channel_id: u64,
    transfer_id: u64,
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
impl TransferProvenance {
    pub(crate) const fn new(channel_id: u64, transfer_id: u64) -> Self {
        Self {
            channel_id,
            transfer_id,
        }
    }
}

#[cfg(test)]
#[path = "protocol_test.rs"]
mod tests;
