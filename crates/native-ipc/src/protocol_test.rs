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
        TransferManifest::new([1; 32], 1, 2, 1, vec![entry(1), duplicate_incarnation],).is_none()
    );
}

#[test]
fn canonical_manifest_is_fixed_width_sorted_and_exact() {
    let manifest = TransferManifest::new([9; 32], 10, 11, 12, vec![entry(2), entry(1)]).unwrap();
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
fn capability_frame_has_the_only_native_capability_magic() {
    let manifest = TransferManifest::new([9; 32], 10, 11, 12, vec![entry(1)]).unwrap();
    let frame = CapabilityFrame::from_manifest(&manifest);
    assert_eq!(&frame.as_bytes()[..8], &CAPABILITY_MAGIC);
    assert_eq!(frame.capability_count(), 1);
    assert_ne!(&frame.as_bytes()[..8], b"NIPCAPP1");
    assert!(manifest.matches_frame(CAPABILITY_MAGIC, frame.as_bytes()));
}

#[test]
fn exact_frame_rejects_every_transcript_field_and_size_change() {
    let manifest = TransferManifest::new([9; 32], 10, 11, 12, vec![entry(1), entry(2)]).unwrap();
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
