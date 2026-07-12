use super::*;
use native_ipc_core::layout::{Endpoint, RoleId};

fn entry(role: u32) -> ManifestEntry {
    ManifestEntry::validated(
        ValidationExpectations {
            schema_id: [role as u8; 32],
            generation: 7,
            role: RoleId::new(role).unwrap(),
            writer: Endpoint::Initiator,
            maximum_mapping_size: 4096,
        },
        4096,
        PeerAccess::ReadOnly,
    )
    .unwrap()
}

#[test]
fn canonical_manifest_rejects_invalid_identity_and_duplicate_roles() {
    assert!(TransferManifest::new([0; 32], 1, 2, 1, vec![entry(1)]).is_none());
    assert!(TransferManifest::new([1; 32], 0, 2, 1, vec![entry(1)]).is_none());
    assert!(TransferManifest::new([1; 32], 1, 0, 1, vec![entry(1)]).is_none());
    assert!(TransferManifest::new([1; 32], 1, 2, 0, vec![entry(1)]).is_none());
    assert!(TransferManifest::new([1; 32], 1, 2, 1, vec![]).is_none());
    assert!(TransferManifest::new([1; 32], 1, 2, 1, vec![entry(1), entry(1)]).is_none());
}

#[test]
fn canonical_manifest_is_fixed_width_sorted_and_exact() {
    let manifest = TransferManifest::new([9; 32], 10, 11, 12, vec![entry(2), entry(1)]).unwrap();
    assert_eq!(manifest.entries[0].role, 1);
    let magic = *b"NIPCTEST";
    let frame = manifest.encode(magic);
    assert!(manifest.matches_frame(magic, &frame));
    let mut stale = frame;
    stale[56] ^= 1;
    assert!(!manifest.matches_frame(magic, &stale));
}

#[test]
fn exact_frame_rejects_every_transcript_field_and_size_change() {
    let manifest = TransferManifest::new([9; 32], 10, 11, 12, vec![entry(1), entry(2)]).unwrap();
    let magic = *b"NIPCTEST";
    let frame = manifest.encode(magic);
    for offset in [0, 8, 12, 16, 48, 52, 56, 96, 128, 136, 140, 144, 152] {
        let mut wrong = frame;
        wrong[offset] ^= 1;
        assert!(!manifest.matches_frame(magic, &wrong), "offset {offset}");
    }
    assert!(!manifest.matches_frame(magic, &frame[..frame.len() - 1]));
    let mut oversized = frame.to_vec();
    oversized.push(0);
    assert!(!manifest.matches_frame(magic, &oversized));
}
