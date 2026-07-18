use super::*;
use crate::session::SessionLimits;

#[test]
fn public_memory_transport_vocabulary_remains_application_neutral() {
    const PUBLIC_MODULES: [(&str, &str); 6] = [
        ("memory", include_str!("memory.rs")),
        ("session", include_str!("session.rs")),
        ("region", include_str!("region.rs")),
        ("batch", include_str!("batch.rs")),
        ("control", include_str!("control.rs")),
        ("active", include_str!("active.rs")),
    ];
    const FORBIDDEN: [&str; 9] = [
        "vst3",
        "audio",
        "bus",
        "sample",
        "event",
        "parameter",
        "plugin",
        "slot",
        "ring",
    ];

    for (module, source) in PUBLIC_MODULES {
        for (line_number, line) in source.lines().enumerate() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("//")
                && !trimmed.starts_with("///")
                && !trimmed.starts_with("//!")
            {
                continue;
            }
            let lowercase = trimmed.to_ascii_lowercase();
            let words = lowercase
                .split(|character: char| !character.is_ascii_alphanumeric())
                .filter(|word| !word.is_empty());
            for word in words {
                assert!(
                    !FORBIDDEN.contains(&word),
                    "application vocabulary {word:?} escaped into {module}.rs:{}",
                    line_number + 1
                );
            }
            assert!(
                !lowercase.contains("plug-in"),
                "application vocabulary escaped into {module}.rs:{}",
                line_number + 1
            );
        }
    }
}

#[test]
fn consumer_modules_have_no_target_gated_public_items() {
    const PUBLIC_MODULES: [(&str, &str); 6] = [
        ("memory", include_str!("memory.rs")),
        ("session", include_str!("session.rs")),
        ("region", include_str!("region.rs")),
        ("batch", include_str!("batch.rs")),
        ("control", include_str!("control.rs")),
        ("active", include_str!("active.rs")),
    ];

    for (module, source) in PUBLIC_MODULES {
        let mut attribute_depth = 0_i32;
        let mut target_gated = false;
        for (line_number, line) in source.lines().enumerate() {
            let trimmed = line.trim_start();
            if attribute_depth > 0 || trimmed.starts_with("#[") {
                attribute_depth += line.matches('[').count() as i32;
                attribute_depth -= line.matches(']').count() as i32;
                target_gated |= line.contains("target_os") || line.contains("target_arch");
                continue;
            }
            if trimmed.is_empty() || trimmed.starts_with("//") {
                continue;
            }
            assert!(
                !target_gated || !trimmed.starts_with("pub "),
                "target-gated public consumer item in {module}.rs:{}: {trimmed}",
                line_number + 1
            );
            target_gated = false;
        }
    }
}

#[test]
fn base_manifest_has_no_application_layout_dependency() {
    let source = include_str!("protocol.rs");
    for forbidden in ["native_ipc_core", "native-ipc-core", "crate::core"] {
        assert!(
            !source.contains(forbidden),
            "base native protocol depends on {forbidden}"
        );
    }
}

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
fn capability_frame_decode_requires_canonical_structure_and_reserved_bytes() {
    let manifest = TransferManifest::new_with_authority(
        [9; 32],
        10,
        11,
        12,
        NativeAuthorityProfile::LinuxMdweV1,
        vec![entry(1), entry(2)],
    )
    .unwrap();
    let frame = CapabilityFrame::from_manifest(&manifest);
    let (decoded, decoded_manifest) = CapabilityFrame::decode(frame.as_bytes()).unwrap();
    assert_eq!(decoded.as_bytes(), frame.as_bytes());
    assert_eq!(decoded_manifest.entries(), manifest.entries());
    assert_eq!(decoded_manifest.total_logical(), 8192);
    assert_eq!(decoded_manifest.total_mapped(), 8192);
    assert_eq!(
        decoded_manifest.authority_profile(),
        NativeAuthorityProfile::LinuxMdweV1
    );

    for offset in [0, 8, 12, 64, 68, 72, 80, 88, 148, 152, 154, 156, 224] {
        let mut wrong = *frame.as_bytes();
        wrong[offset] ^= 1;
        assert!(CapabilityFrame::decode(&wrong).is_none(), "offset {offset}");
    }
    for offset in [16, 48, 52, 56, 76, 112, 144, 160] {
        let mut substituted = *frame.as_bytes();
        substituted[offset] ^= 1;
        let (decoded, _) = CapabilityFrame::decode(&substituted).unwrap();
        assert_eq!(decoded.as_bytes(), &substituted, "offset {offset}");
    }
    assert!(CapabilityFrame::decode(&frame.as_bytes()[..CONTROL_FRAME_LEN - 1]).is_none());
    let mut oversized = frame.as_bytes().to_vec();
    oversized.push(0);
    assert!(CapabilityFrame::decode(&oversized).is_none());
}

#[test]
fn capacity_preflight_distinguishes_limits_preparation_and_both_roles() {
    let manifest = TransferManifest::new_with_authority(
        [0x29; 32],
        10,
        11,
        12,
        NativeAuthorityProfile::LinuxMdweV1,
        vec![entry(1)],
    )
    .unwrap();
    let capability = CapabilityFrame::from_manifest(&manifest);
    let coordinator_ready = capability.coordinator_capacity_frame(CoordinatorCapacityStatus::Ready);
    let coordinator_limit =
        capability.coordinator_capacity_frame(CoordinatorCapacityStatus::ActiveLimit);
    let coordinator_preparation =
        capability.coordinator_capacity_frame(CoordinatorCapacityStatus::PreparationFailed);
    let receiver_ready = capability.receiver_capacity_frame(true);
    let receiver_limit = capability.receiver_capacity_frame(false);
    let frames = [
        coordinator_ready.as_bytes(),
        coordinator_limit.as_bytes(),
        coordinator_preparation.as_bytes(),
        receiver_ready.as_bytes(),
        receiver_limit.as_bytes(),
    ];
    for left in 0..frames.len() {
        for right in 0..frames.len() {
            assert_eq!(frames[left] == frames[right], left == right);
        }
    }
    for (frame, status) in [
        (coordinator_ready, CoordinatorCapacityStatus::Ready),
        (coordinator_limit, CoordinatorCapacityStatus::ActiveLimit),
        (
            coordinator_preparation,
            CoordinatorCapacityStatus::PreparationFailed,
        ),
    ] {
        let (decoded, decoded_manifest, decoded_status) =
            CapabilityFrame::decode_coordinator_capacity(frame.as_bytes()).unwrap();
        assert_eq!(decoded.as_bytes(), capability.as_bytes());
        assert_eq!(decoded_manifest, manifest);
        assert_eq!(decoded_status, status);
    }
    assert!(CapabilityFrame::decode_coordinator_capacity(receiver_ready.as_bytes()).is_none());
}

#[test]
fn preparation_frames_are_disjoint_exact_full_manifest_receipts() {
    let manifest = TransferManifest::new_with_authority(
        [0x31; 32],
        10,
        11,
        12,
        NativeAuthorityProfile::LinuxMdweV1,
        vec![entry(1), entry(2)],
    )
    .unwrap();
    let capability = CapabilityFrame::from_manifest(&manifest);
    let imported = capability.preparation_frame(PreparationFrameKind::Imported);
    let sealed = capability.preparation_frame(PreparationFrameKind::Sealed);
    assert_ne!(capability.as_bytes(), imported.as_bytes());
    assert_ne!(capability.as_bytes(), sealed.as_bytes());
    assert_ne!(imported.as_bytes(), sealed.as_bytes());
    assert!(imported.matches(imported.as_bytes()));
    assert!(sealed.matches(sealed.as_bytes()));

    for offset in [0, 8, 12, 16, 48, 52, 56, 64, 68, 72, 76, 80, 88, 96, 112] {
        let mut substituted = *imported.as_bytes();
        substituted[offset] ^= 1;
        assert!(!imported.matches(&substituted), "offset {offset}");
    }
    for length in 0..CONTROL_FRAME_LEN {
        assert!(
            !imported.matches(&imported.as_bytes()[..length]),
            "truncation {length}"
        );
        assert!(
            !sealed.matches(&sealed.as_bytes()[..length]),
            "sealed truncation {length}"
        );
    }
    let mut oversized = imported.as_bytes().to_vec();
    oversized.push(0);
    assert!(!imported.matches(&oversized));
}

#[test]
fn completion_frames_are_disjoint_exact_full_manifest_barriers() {
    let manifest = TransferManifest::new_with_authority(
        [0x42; 32],
        10,
        11,
        12,
        NativeAuthorityProfile::LinuxMdweV1,
        vec![entry(1), entry(2)],
    )
    .unwrap();
    let capability = CapabilityFrame::from_manifest(&manifest);
    let imported = capability.preparation_frame(PreparationFrameKind::Imported);
    let sealed = capability.preparation_frame(PreparationFrameKind::Sealed);
    let ready = capability.completion_frame(CompletionFrameKind::Ready);
    let commit = capability.completion_frame(CompletionFrameKind::Commit);

    assert_ne!(capability.as_bytes(), ready.as_bytes());
    assert_ne!(capability.as_bytes(), commit.as_bytes());
    assert_ne!(imported.as_bytes(), ready.as_bytes());
    assert_ne!(sealed.as_bytes(), ready.as_bytes());
    assert_ne!(ready.as_bytes(), commit.as_bytes());
    assert!(ready.matches(ready.as_bytes()));
    assert!(commit.matches(commit.as_bytes()));

    for offset in [0, 8, 12, 16, 48, 52, 56, 64, 68, 72, 76, 80, 88, 96, 112] {
        let mut substituted = *ready.as_bytes();
        substituted[offset] ^= 1;
        assert!(!ready.matches(&substituted), "offset {offset}");
    }
    for length in 0..CONTROL_FRAME_LEN {
        assert!(
            !ready.matches(&ready.as_bytes()[..length]),
            "ready truncation {length}"
        );
        assert!(
            !commit.matches(&commit.as_bytes()[..length]),
            "commit truncation {length}"
        );
    }
    let mut oversized = commit.as_bytes().to_vec();
    oversized.push(0);
    assert!(!commit.matches(&oversized));
}

#[test]
fn vnext_authority_profile_is_exactly_transcript_bound() {
    let legacy = TransferManifest::new([9; 32], 10, 11, 12, vec![entry(1)]).unwrap();
    let linux = TransferManifest::new_with_authority(
        [9; 32],
        10,
        11,
        12,
        NativeAuthorityProfile::LinuxMdweV1,
        vec![entry(1)],
    )
    .unwrap();
    let macos = TransferManifest::new_with_authority(
        [9; 32],
        10,
        11,
        12,
        NativeAuthorityProfile::MacMachV1,
        vec![entry(1)],
    )
    .unwrap();
    let windows = TransferManifest::new_with_authority(
        [9; 32],
        10,
        11,
        12,
        NativeAuthorityProfile::WindowsSectionsV1,
        vec![entry(1)],
    )
    .unwrap();
    let legacy = legacy.encode(CAPABILITY_MAGIC);
    let linux = linux.encode(CAPABILITY_MAGIC);
    let macos = macos.encode(CAPABILITY_MAGIC);
    let windows = windows.encode(CAPABILITY_MAGIC);
    assert_eq!(u32::from_le_bytes(legacy[76..80].try_into().unwrap()), 0);
    assert_eq!(u32::from_le_bytes(linux[76..80].try_into().unwrap()), 1);
    assert_eq!(u32::from_le_bytes(macos[76..80].try_into().unwrap()), 2);
    assert_eq!(u32::from_le_bytes(windows[76..80].try_into().unwrap()), 3);
    assert_ne!(legacy, linux);
    assert_ne!(linux, macos);
    assert_ne!(macos, windows);
}

#[test]
fn manifest_checks_negotiated_count_region_and_batch_limits() {
    let manifest = TransferManifest::new([9; 32], 10, 11, 12, vec![entry(1), entry(2)]).unwrap();
    let limits = SessionLimits {
        max_regions_per_batch: 2,
        max_region_bytes: 4096,
        max_batch_bytes: 8192,
        ..SessionLimits::default()
    };
    assert!(manifest.fits_limits(limits));
    assert!(!manifest.fits_limits(SessionLimits {
        max_regions_per_batch: 1,
        ..limits
    }));
    assert!(!manifest.fits_limits(SessionLimits {
        max_region_bytes: 4095,
        ..limits
    }));
    assert!(!manifest.fits_limits(SessionLimits {
        max_batch_bytes: 8191,
        ..limits
    }));

    let rounded = NativeRegionSpec::new(3, [3; 16], 1, 4095, 4096).unwrap();
    let rounded = TransferManifest::new(
        [9; 32],
        10,
        11,
        12,
        vec![ManifestEntry::from_native(rounded, PeerAccess::ReadOnly)],
    )
    .unwrap();
    let rounded_limits = SessionLimits {
        max_regions_per_batch: 1,
        max_region_bytes: 4095,
        max_batch_bytes: 4096,
        ..SessionLimits::default()
    };
    assert!(rounded.fits_limits(rounded_limits));
    assert!(!rounded.fits_limits(SessionLimits {
        max_region_bytes: 4094,
        ..rounded_limits
    }));
}

#[test]
fn exact_frame_rejects_every_transcript_field_and_size_change() {
    let manifest = TransferManifest::new([9; 32], 10, 11, 12, vec![entry(1), entry(2)]).unwrap();
    let magic = *b"NIPCTEST";
    let frame = manifest.encode(magic);
    for offset in [
        0, 8, 12, 16, 48, 52, 56, 76, 96, 112, 128, 136, 144, 148, 152, 154,
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
