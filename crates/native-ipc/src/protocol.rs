use crate::session::SessionLimits;

pub(crate) const CONTROL_VERSION: u32 = 1;
pub(crate) const MAX_TRANSFER_ENTRIES: usize = 16;
pub(crate) const ENTRY_LEN: usize = 64;
pub(crate) const CONTROL_FRAME_LEN: usize = 96 + MAX_TRANSFER_ENTRIES * ENTRY_LEN;
#[allow(
    dead_code,
    reason = "private G1b capability transport is currently implemented only on Linux"
)]
pub(crate) const CAPABILITY_MAGIC: [u8; 8] = *b"NIPCCAP1";
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const IMPORTED_MAGIC: [u8; 8] = *b"NIPCIMP1";
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
const SEALED_MAGIC: [u8; 8] = *b"NIPCSEA1";
const MANIFEST_FLAG_CANONICAL: u32 = 1;
const ENTRY_FLAG_LIBRARY_VIEW_NO_EXECUTE: u16 = 1;
const ENTRY_FLAG_SIZE_FROZEN: u16 = 2;
const REQUIRED_ENTRY_FLAGS: u16 = ENTRY_FLAG_LIBRARY_VIEW_NO_EXECUTE | ENTRY_FLAG_SIZE_FROZEN;

/// Exact backend authority policy and accepted residual limitations bound into
/// a vNext transfer transcript.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub(crate) enum NativeAuthorityProfile {
    /// Compatibility profile used only by the landed pre-vNext native helpers.
    Legacy = 0,
    /// Linux library views are non-executable, inherited MDWE refuses execute
    /// gain, RX aliases remain possible, and a receiver-writer may delegate its
    /// pre-seal fd outside the MDWE tree.
    #[cfg_attr(
        not(target_os = "linux"),
        allow(dead_code, reason = "Linux accepted-session profile")
    )]
    LinuxMdweV1 = 1,
}

impl NativeAuthorityProfile {
    pub(crate) const fn is_vnext(self) -> bool {
        !matches!(self, Self::Legacy)
    }
}

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
    authority_profile: NativeAuthorityProfile,
    total_logical: u64,
    total_mapped: u64,
    entries: Vec<ManifestEntry>,
}

/// Exact canonical capability packet expected by both transaction endpoints.
///
/// Construction from a validated manifest keeps application framing and native
/// transaction framing disjoint without exposing caller-selected wire magic.
#[allow(
    dead_code,
    reason = "private G1b capability transport is currently implemented only on Linux"
)]
pub(crate) struct CapabilityFrame {
    bytes: [u8; CONTROL_FRAME_LEN],
    capability_count: usize,
}

/// Exact full-manifest Linux preparation receipt kind.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum PreparationFrameKind {
    Imported,
    Sealed,
}

/// Zero-rights preparation frame derived only from a canonical capability
/// frame retained by the accepted transaction owner.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) struct PreparationFrame {
    bytes: [u8; CONTROL_FRAME_LEN],
}

#[allow(
    dead_code,
    reason = "private G1b capability transport is currently implemented only on Linux"
)]
impl CapabilityFrame {
    pub(crate) fn from_manifest(manifest: &TransferManifest) -> Self {
        Self {
            bytes: manifest.encode(CAPABILITY_MAGIC),
            capability_count: manifest.entries.len(),
        }
    }

    pub(crate) const fn as_bytes(&self) -> &[u8; CONTROL_FRAME_LEN] {
        &self.bytes
    }

    pub(crate) const fn capability_count(&self) -> usize {
        self.capability_count
    }

    pub(crate) fn decode(bytes: &[u8]) -> Option<(Self, TransferManifest)> {
        let manifest = TransferManifest::decode(CAPABILITY_MAGIC, bytes)?;
        Some((Self::from_manifest(&manifest), manifest))
    }

    pub(crate) fn preparation_frame(&self, kind: PreparationFrameKind) -> PreparationFrame {
        let (_, manifest) = Self::decode(&self.bytes)
            .expect("capability frames are constructed from canonical manifests");
        PreparationFrame {
            bytes: manifest.encode(match kind {
                PreparationFrameKind::Imported => IMPORTED_MAGIC,
                PreparationFrameKind::Sealed => SEALED_MAGIC,
            }),
        }
    }
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
impl PreparationFrame {
    pub(crate) const fn as_bytes(&self) -> &[u8; CONTROL_FRAME_LEN] {
        &self.bytes
    }

    pub(crate) fn matches(&self, bytes: &[u8]) -> bool {
        bytes == self.bytes
    }
}

impl TransferManifest {
    fn decode(magic: [u8; 8], frame: &[u8]) -> Option<Self> {
        if frame.len() != CONTROL_FRAME_LEN
            || frame[..8] != magic
            || u32::from_le_bytes(frame[8..12].try_into().ok()?) != CONTROL_VERSION
        {
            return None;
        }
        let count = usize::try_from(u32::from_le_bytes(frame[12..16].try_into().ok()?)).ok()?;
        if !(1..=MAX_TRANSFER_ENTRIES).contains(&count) {
            return None;
        }
        let authority_profile = match u32::from_le_bytes(frame[76..80].try_into().ok()?) {
            0 => NativeAuthorityProfile::Legacy,
            1 => NativeAuthorityProfile::LinuxMdweV1,
            _ => return None,
        };
        let mut entries = Vec::with_capacity(count);
        for index in 0..count {
            let start = 96 + index * ENTRY_LEN;
            let access = match u32::from_le_bytes(frame[start + 52..start + 56].try_into().ok()?) {
                1 => PeerAccess::ReadOnly,
                2 => PeerAccess::SoleWriter,
                _ => return None,
            };
            entries.push(ManifestEntry {
                region_id: u128::from_le_bytes(frame[start..start + 16].try_into().ok()?),
                incarnation: frame[start + 16..start + 32].try_into().ok()?,
                logical_len: u64::from_le_bytes(frame[start + 32..start + 40].try_into().ok()?),
                mapped_len: u64::from_le_bytes(frame[start + 40..start + 48].try_into().ok()?),
                writer: u32::from_le_bytes(frame[start + 48..start + 52].try_into().ok()?),
                access,
                ordinal: u16::from_le_bytes(frame[start + 56..start + 58].try_into().ok()?),
                flags: u16::from_le_bytes(frame[start + 58..start + 60].try_into().ok()?),
            });
        }
        let manifest = Self::new_with_authority(
            frame[16..48].try_into().ok()?,
            u32::from_le_bytes(frame[48..52].try_into().ok()?),
            u32::from_le_bytes(frame[52..56].try_into().ok()?),
            u64::from_le_bytes(frame[56..64].try_into().ok()?),
            authority_profile,
            entries,
        )?;
        (manifest.encode(magic).as_slice() == frame).then_some(manifest)
    }

    pub(crate) fn new(
        nonce: [u8; 32],
        parent_pid: u32,
        child_pid: u32,
        transfer_id: u64,
        entries: Vec<ManifestEntry>,
    ) -> Option<Self> {
        Self::new_with_authority(
            nonce,
            parent_pid,
            child_pid,
            transfer_id,
            NativeAuthorityProfile::Legacy,
            entries,
        )
    }

    pub(crate) fn new_with_authority(
        nonce: [u8; 32],
        parent_pid: u32,
        child_pid: u32,
        transfer_id: u64,
        authority_profile: NativeAuthorityProfile,
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
            authority_profile,
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
        frame[76..80].copy_from_slice(&(self.authority_profile as u32).to_le_bytes());
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

    pub(crate) fn fits_limits(&self, limits: SessionLimits) -> bool {
        self.entries.len() <= usize::from(limits.max_regions_per_batch)
            && self.total_logical <= limits.max_batch_bytes
            && self.total_mapped <= limits.max_batch_bytes
            && self
                .entries
                .iter()
                .all(|entry| entry.logical_len <= limits.max_region_bytes)
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) const fn authority_profile(&self) -> NativeAuthorityProfile {
        self.authority_profile
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) const fn total_logical(&self) -> u64 {
        self.total_logical
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) const fn total_mapped(&self) -> u64 {
        self.total_mapped
    }

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn entries(&self) -> &[ManifestEntry] {
        &self.entries
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
