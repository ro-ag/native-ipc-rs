pub(crate) const CONTROL_VERSION: u32 = 1;
pub(crate) const MAX_TRANSFER_ENTRIES: usize = 16;
pub(crate) const ENTRY_LEN: usize = 64;
pub(crate) const CONTROL_FRAME_LEN: usize = 96 + MAX_TRANSFER_ENTRIES * ENTRY_LEN;
const MANIFEST_FLAG_CANONICAL: u32 = 1;
const ENTRY_FLAG_NON_EXECUTABLE: u16 = 1;
const ENTRY_FLAG_SIZE_FROZEN: u16 = 2;
const REQUIRED_ENTRY_FLAGS: u16 = ENTRY_FLAG_NON_EXECUTABLE | ENTRY_FLAG_SIZE_FROZEN;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
#[allow(dead_code)] // Each target uses the access modes its native backend supports.
pub(crate) enum PeerAccess {
    ReadOnly = 1,
    SoleWriter = 2,
}

/// Application-neutral facts attached to one prepared native object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct NativeRegionSpec {
    pub(crate) region_id: u128,
    pub(crate) incarnation: [u8; 16],
    pub(crate) writer: u32,
    pub(crate) logical_len: u64,
    pub(crate) mapped_len: u64,
}

impl NativeRegionSpec {
    #[allow(dead_code)]
    pub(crate) fn new(
        region_id: u128,
        incarnation: [u8; 16],
        writer: u32,
        logical_len: usize,
        mapped_len: usize,
    ) -> Option<Self> {
        let logical_len = u64::try_from(logical_len).ok()?;
        let mapped_len = u64::try_from(mapped_len).ok()?;
        if region_id == 0 || incarnation == [0; 16] || logical_len == 0 || logical_len > mapped_len
        {
            return None;
        }
        Some(Self {
            region_id,
            incarnation,
            writer,
            logical_len,
            mapped_len,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ManifestEntry {
    pub(crate) region_id: u128,
    pub(crate) incarnation: [u8; 16],
    pub(crate) writer: u32,
    pub(crate) access: PeerAccess,
    pub(crate) logical_len: u64,
    pub(crate) mapped_len: u64,
    pub(crate) ordinal: u16,
    pub(crate) flags: u16,
}

impl ManifestEntry {
    pub(crate) const fn from_native(spec: NativeRegionSpec, access: PeerAccess) -> Self {
        Self {
            region_id: spec.region_id,
            incarnation: spec.incarnation,
            writer: spec.writer,
            access,
            logical_len: spec.logical_len,
            mapped_len: spec.mapped_len,
            ordinal: 0,
            flags: REQUIRED_ENTRY_FLAGS,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TransferManifest {
    pub(crate) nonce: [u8; 32],
    pub(crate) parent_pid: u32,
    pub(crate) child_pid: u32,
    pub(crate) transfer_id: u64,
    total_logical: u64,
    total_mapped: u64,
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
        let mut total_logical = 0_u64;
        let mut total_mapped = 0_u64;
        for entry in &entries {
            if entry.region_id == 0
                || entry.incarnation == [0; 16]
                || entry.logical_len == 0
                || entry.logical_len > entry.mapped_len
                || entry.flags != REQUIRED_ENTRY_FLAGS
            {
                return None;
            }
            total_logical = total_logical.checked_add(entry.logical_len)?;
            total_mapped = total_mapped.checked_add(entry.mapped_len)?;
        }
        entries.sort_unstable_by_key(|entry| entry.region_id);
        if entries
            .windows(2)
            .any(|pair| pair[0].region_id == pair[1].region_id)
        {
            return None;
        }
        for left in 0..entries.len() {
            if entries[left + 1..]
                .iter()
                .any(|right| right.incarnation == entries[left].incarnation)
            {
                return None;
            }
        }
        for (ordinal, entry) in entries.iter_mut().enumerate() {
            entry.ordinal = u16::try_from(ordinal).ok()?;
        }
        Some(Self {
            nonce,
            parent_pid,
            child_pid,
            transfer_id,
            total_logical,
            total_mapped,
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
        let frame_kind = u32::from_le_bytes([magic[4], magic[5], magic[6], magic[7]]);
        frame[64..68].copy_from_slice(&frame_kind.to_le_bytes());
        frame[68..72].copy_from_slice(&MANIFEST_FLAG_CANONICAL.to_le_bytes());
        frame[72..76].copy_from_slice(&(CONTROL_FRAME_LEN as u32).to_le_bytes());
        frame[80..88].copy_from_slice(&self.total_logical.to_le_bytes());
        frame[88..96].copy_from_slice(&self.total_mapped.to_le_bytes());
        for (index, entry) in self.entries.iter().enumerate() {
            let start = 96 + index * ENTRY_LEN;
            frame[start..start + 16].copy_from_slice(&entry.region_id.to_le_bytes());
            frame[start + 16..start + 32].copy_from_slice(&entry.incarnation);
            frame[start + 32..start + 40].copy_from_slice(&entry.logical_len.to_le_bytes());
            frame[start + 40..start + 48].copy_from_slice(&entry.mapped_len.to_le_bytes());
            frame[start + 48..start + 52].copy_from_slice(&entry.writer.to_le_bytes());
            frame[start + 52..start + 56].copy_from_slice(&(entry.access as u32).to_le_bytes());
            frame[start + 56..start + 58].copy_from_slice(&entry.ordinal.to_le_bytes());
            frame[start + 58..start + 60].copy_from_slice(&entry.flags.to_le_bytes());
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
mod tests {
    use super::*;

    fn entry(role: u32) -> ManifestEntry {
        let spec = NativeRegionSpec::new(role.into(), [role as u8; 16], 1, 4096, 4096).unwrap();
        ManifestEntry::from_native(spec, PeerAccess::ReadOnly)
    }

    #[test]
    fn canonical_manifest_rejects_invalid_identity_and_duplicate_roles() {
        assert!(TransferManifest::new([0; 32], 1, 2, 1, vec![entry(1)]).is_none());
        assert!(TransferManifest::new([1; 32], 0, 2, 1, vec![entry(1)]).is_none());
        assert!(TransferManifest::new([1; 32], 1, 0, 1, vec![entry(1)]).is_none());
        assert!(TransferManifest::new([1; 32], 1, 2, 0, vec![entry(1)]).is_none());
        assert!(TransferManifest::new([1; 32], 1, 2, 1, vec![]).is_none());
        assert!(TransferManifest::new([1; 32], 1, 2, 1, vec![entry(1), entry(1)]).is_none());
        let mut duplicate_incarnation = entry(2);
        duplicate_incarnation.incarnation = entry(1).incarnation;
        assert!(
            TransferManifest::new([1; 32], 1, 2, 1, vec![entry(1), duplicate_incarnation],)
                .is_none()
        );
    }

    #[test]
    fn canonical_manifest_is_fixed_width_sorted_and_exact() {
        let manifest =
            TransferManifest::new([9; 32], 10, 11, 12, vec![entry(2), entry(1)]).unwrap();
        assert_eq!(manifest.entries[0].region_id, 1);
        let magic = *b"NIPCTEST";
        let frame = manifest.encode(magic);
        assert!(manifest.matches_frame(magic, &frame));
        assert_eq!(u32::from_le_bytes(frame[68..72].try_into().unwrap()), 1);
        assert_eq!(
            u32::from_le_bytes(frame[72..76].try_into().unwrap()) as usize,
            CONTROL_FRAME_LEN
        );
        assert_eq!(u64::from_le_bytes(frame[80..88].try_into().unwrap()), 8192);
        assert_eq!(u64::from_le_bytes(frame[88..96].try_into().unwrap()), 8192);
        let mut stale = frame;
        stale[56] ^= 1;
        assert!(!manifest.matches_frame(magic, &stale));
    }

    #[test]
    fn exact_frame_rejects_every_transcript_field_and_size_change() {
        let manifest =
            TransferManifest::new([9; 32], 10, 11, 12, vec![entry(1), entry(2)]).unwrap();
        let magic = *b"NIPCTEST";
        let frame = manifest.encode(magic);
        for offset in [
            0, 8, 12, 16, 48, 52, 56, 96, 112, 128, 136, 144, 148, 152, 154,
        ] {
            let mut wrong = frame;
            wrong[offset] ^= 1;
            assert!(!manifest.matches_frame(magic, &wrong), "offset {offset}");
        }
        assert!(!manifest.matches_frame(magic, &frame[..frame.len() - 1]));
        let mut oversized = frame.to_vec();
        oversized.push(0);
        assert!(!manifest.matches_frame(magic, &oversized));
    }
}
