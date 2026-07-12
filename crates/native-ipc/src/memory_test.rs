use super::*;

#[test]
fn capabilities_report_the_compilation_architecture() {
    let capabilities = native_memory_capabilities();

    #[cfg(target_arch = "aarch64")]
    assert_eq!(capabilities.architecture(), NativeArchitecture::Arm64);
    #[cfg(target_arch = "x86_64")]
    assert_eq!(capabilities.architecture(), NativeArchitecture::Amd64);
}

#[test]
fn growable_region_preserves_bytes_and_reports_policy() {
    let options = RegionOptions::growable(32, 128, WriterOwner::Creator);
    let mut region = NativeRegion::allocate(options).unwrap();
    region.initialize(|bytes| bytes[..4].copy_from_slice(b"NIPC"));
    region.grow(96).unwrap();

    let status = region.status();
    assert_eq!(status.logical_len, 96);
    assert_eq!(status.maximum_len, 128);
    assert!(status.can_grow);
    assert_eq!(status.permissions.creator_access(), MemoryAccess::ReadWrite);
    assert_eq!(status.permissions.peer_access(), MemoryAccess::ReadOnly);
    assert!(!status.permissions.library_view_executable());
    region.initialize(|bytes| assert_eq!(&bytes[..4], b"NIPC"));
}

#[test]
fn fixed_and_bounded_growth_fail_closed() {
    let mut fixed = NativeRegion::allocate(RegionOptions::fixed(32, WriterOwner::Peer)).unwrap();
    assert!(matches!(fixed.grow(64), Err(MemoryError::FixedSize)));

    let mut bounded =
        NativeRegion::allocate(RegionOptions::growable(32, 64, WriterOwner::Peer)).unwrap();
    assert!(matches!(
        bounded.grow(65),
        Err(MemoryError::MaximumExceeded {
            requested: 65,
            maximum: 64
        })
    ));
    assert!(matches!(
        bounded.grow(16),
        Err(MemoryError::ShrinkUnsupported {
            current: 32,
            requested: 16
        })
    ));
}

#[test]
fn clear_covers_logical_bytes() {
    let mut region =
        NativeRegion::allocate(RegionOptions::fixed(32, WriterOwner::Creator)).unwrap();
    region.initialize(|bytes| bytes.fill(0xaa));
    region.clear();
    region.initialize(|bytes| assert!(bytes.iter().all(|byte| *byte == 0)));
    region.initialize(|bytes| bytes[..4].copy_from_slice(b"REUS"));
    region.initialize(|bytes| assert_eq!(&bytes[..4], b"REUS"));
    region.destroy();
}

#[test]
fn share_request_preserves_permissions_and_removes_byte_access() {
    let region = NativeRegion::allocate(RegionOptions::fixed(32, WriterOwner::Peer)).unwrap();
    let request = region.prepare_for_sharing().unwrap();
    assert_ne!(request.incarnation(), [0; 16]);
    let native = request.native_spec(7).unwrap();
    assert_eq!(native.incarnation, request.incarnation());
    assert_eq!(native.region_id, 7);
    assert_eq!(request.seal_policy(), SealPolicy::RequiredOnShare);
    assert_eq!(
        request.permissions().creator_access(),
        MemoryAccess::ReadOnly
    );
    assert_eq!(request.permissions().peer_access(), MemoryAccess::ReadWrite);
    assert!(request.mapped_len() >= 32);
    request.destroy();
}

#[test]
fn each_prepared_object_gets_an_independent_incarnation() {
    let first = NativeRegion::allocate(RegionOptions::fixed(32, WriterOwner::Creator))
        .unwrap()
        .prepare_for_sharing()
        .unwrap();
    let second = NativeRegion::allocate(RegionOptions::fixed(32, WriterOwner::Creator))
        .unwrap()
        .prepare_for_sharing()
        .unwrap();
    assert_ne!(first.incarnation(), second.incarnation());
}
