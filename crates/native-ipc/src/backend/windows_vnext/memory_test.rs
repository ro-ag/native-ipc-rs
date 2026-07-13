use super::vnext_memory::{
    WindowsBatchError, WindowsExpectedMixedDirectionBatch, WindowsMixedDirectionBatch,
    WindowsReceivedHandle, live_handles_for_test, live_views_for_test,
};
use super::{OwnedHandle, QuiescentRegion, View, duplicate_to};
use crate::batch::{ExpectedBatch, ExpectedRegion, LocalRegionAuthority, TransferBatch};
use crate::protocol::{NativeAuthorityProfile, TransferManifest};
use crate::region::{PrivateRegion, RegionId, RegionOptions, RegionSpec, WriterEndpoint};
use crate::session::{AbsoluteDeadline, SessionLimits};
use std::mem::zeroed;
use std::time::Duration;
use windows_sys::Win32::Foundation::{
    HANDLE, HANDLE_FLAG_INHERIT, HANDLE_FLAG_PROTECT_FROM_CLOSE, INVALID_HANDLE_VALUE,
    SetHandleInformation,
};
use windows_sys::Win32::System::Memory::{
    CreateFileMappingW, FILE_MAP_READ, FILE_MAP_WRITE, MEM_COMMIT, PAGE_EXECUTE_READWRITE,
    PAGE_READWRITE, SEC_RESERVE, VirtualAlloc, VirtualProtect,
};
use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
use windows_sys::Win32::System::Threading::GetCurrentProcess;

fn deadline() -> AbsoluteDeadline {
    AbsoluteDeadline::after(Duration::from_secs(10)).unwrap()
}

fn page_size() -> usize {
    let mut information: SYSTEM_INFO = unsafe { zeroed() };
    unsafe { GetSystemInfo(&mut information) };
    information.dwPageSize as usize
}

fn build_batch(count: usize) -> (TransferBatch, ExpectedBatch) {
    let mut batch = TransferBatch::new(16, 1 << 20, 16 << 20).unwrap();
    let mut expected = Vec::with_capacity(count);
    for index in (0..count).rev() {
        let id = RegionId::new((index + 1) as u128).unwrap();
        let writer = if index % 2 == 0 {
            WriterEndpoint::Coordinator
        } else {
            WriterEndpoint::Receiver
        };
        let logical_len = 31 + index;
        let mut region = PrivateRegion::allocate(RegionOptions::fixed(logical_len)).unwrap();
        region.initialize(|bytes| {
            bytes.fill(0);
            bytes[0] = (index + 1) as u8;
        });
        batch
            .add(region.prepare(RegionSpec { id, writer }).unwrap())
            .unwrap();
        expected.push(ExpectedRegion::new(id, writer, logical_len));
    }
    (batch, ExpectedBatch::try_from_regions(expected).unwrap())
}

#[test]
fn received_handle_accounting_survives_cross_thread_drop() {
    let (batch, _) = build_batch(1);
    let prepared = WindowsMixedDirectionBatch::prepare(
        batch,
        NativeAuthorityProfile::WindowsSectionsV1,
        deadline(),
    )
    .unwrap();
    let handle = prepared.duplicate_capability_for_test(0).unwrap();
    std::thread::spawn(move || drop(handle)).join().unwrap();
}

fn manifest(entries: Vec<crate::protocol::ManifestEntry>) -> TransferManifest {
    TransferManifest::new_with_authority(
        [7; 32],
        unsafe { windows_sys::Win32::System::Threading::GetCurrentProcessId() },
        unsafe { windows_sys::Win32::System::Threading::GetCurrentProcessId() } + 1,
        1,
        NativeAuthorityProfile::WindowsSectionsV1,
        entries,
    )
    .unwrap()
}

#[test]
fn mixed_batches_prepare_import_and_activate_complementary_authority() {
    for count in [1, 2, 4, 16] {
        let (batch, expected) = build_batch(count);
        let mut prepared = WindowsMixedDirectionBatch::prepare(
            batch,
            NativeAuthorityProfile::WindowsSectionsV1,
            deadline(),
        )
        .unwrap();
        let transfer = manifest(prepared.manifest_entries());
        let handles = prepared.copied_capabilities_for_test().unwrap();
        let expected =
            WindowsExpectedMixedDirectionBatch::new(expected, SessionLimits::default(), deadline())
                .unwrap();
        assert!(expected.matches_manifest(&transfer));
        let mut imported = expected.import(&transfer, handles).unwrap();

        for ordinal in 0..count {
            if ordinal % 2 == 0 {
                assert_eq!(
                    imported.read_coordinator_for_test(ordinal, 0),
                    (ordinal + 1) as u8
                );
                prepared.write_coordinator_for_test(ordinal, 1, 0x40 + ordinal as u8);
                assert_eq!(
                    imported.read_coordinator_for_test(ordinal, 1),
                    0x40 + ordinal as u8
                );
            } else {
                imported.write_receiver_for_test(ordinal, 1, 0x60 + ordinal as u8);
                assert_eq!(
                    prepared.read_receiver_for_test(ordinal, 1),
                    0x60 + ordinal as u8
                );
            }
        }

        let local_specs = prepared.activation_specs().unwrap();
        let peer_specs = imported.activation_specs(deadline()).unwrap();
        assert_eq!(local_specs.len(), count);
        assert_eq!(peer_specs.len(), count);
        for (ordinal, (local, peer)) in local_specs.iter().zip(&peer_specs).enumerate() {
            assert_eq!(local.id, peer.id);
            assert_eq!(local.logical_len, peer.logical_len);
            assert_eq!(local.mapped_len, peer.mapped_len);
            assert_eq!(
                (local.authority, peer.authority),
                if ordinal % 2 == 0 {
                    (LocalRegionAuthority::Writer, LocalRegionAuthority::Reader)
                } else {
                    (LocalRegionAuthority::Reader, LocalRegionAuthority::Writer)
                }
            );
        }

        let local_owners = prepared.into_active_region_owners();
        let peer_owners = imported.into_active_region_owners();
        for (ordinal, (local, peer)) in local_owners.into_iter().zip(peer_owners).enumerate() {
            if ordinal % 2 == 0 {
                let mut writer = local.into_writer().unwrap();
                let reader = peer.into_reader().unwrap();
                unsafe { core::ptr::write_volatile(writer.as_mut_ptr().add(2), 0x80) };
                assert_eq!(
                    unsafe { core::ptr::read_volatile(reader.as_ptr().add(2)) },
                    0x80
                );
            } else {
                let reader = local.into_reader().unwrap();
                let mut writer = peer.into_writer().unwrap();
                unsafe { core::ptr::write_volatile(writer.as_mut_ptr().add(2), 0x90) };
                assert_eq!(
                    unsafe { core::ptr::read_volatile(reader.as_ptr().add(2)) },
                    0x90
                );
            }
        }
    }
}

#[test]
fn preparation_and_import_failures_restore_handle_baselines() {
    for count in [1, 2, 4, 16] {
        for failure_at in 1..=count {
            let before = live_handles_for_test();
            let views_before = live_views_for_test();
            let (batch, _) = build_batch(count);
            assert!(matches!(
                WindowsMixedDirectionBatch::prepare_with_failure_for_test(
                    batch,
                    failure_at,
                    deadline()
                ),
                Err(WindowsBatchError::WrongObject)
            ));
            assert_eq!(live_handles_for_test(), before);
            assert_eq!(live_views_for_test(), views_before);
        }

        for failure_at in 1..=count {
            let (batch, expected) = build_batch(count);
            let prepared = WindowsMixedDirectionBatch::prepare(
                batch,
                NativeAuthorityProfile::WindowsSectionsV1,
                deadline(),
            )
            .unwrap();
            let transfer = manifest(prepared.manifest_entries());
            let before = live_handles_for_test();
            let views_before = live_views_for_test();
            let handles = prepared.copied_capabilities_for_test().unwrap();
            let expected = WindowsExpectedMixedDirectionBatch::new(
                expected,
                SessionLimits::default(),
                deadline(),
            )
            .unwrap();
            assert!(matches!(
                expected.import_with_failure_for_test(&transfer, handles, failure_at),
                Err(WindowsBatchError::WrongObject)
            ));
            assert_eq!(live_handles_for_test(), before);
            assert_eq!(live_views_for_test(), views_before);
            prepared.revalidate_before_send().unwrap();
        }
    }
}

#[test]
fn duplicate_object_and_wrong_profile_fail_closed() {
    let (batch, expected) = build_batch(2);
    let prepared = WindowsMixedDirectionBatch::prepare(
        batch,
        NativeAuthorityProfile::WindowsSectionsV1,
        deadline(),
    )
    .unwrap();
    let transfer = manifest(prepared.manifest_entries());
    let first = prepared.duplicate_capability_for_test(0).unwrap();
    let duplicate = prepared.duplicate_capability_for_test(0).unwrap();
    let expected =
        WindowsExpectedMixedDirectionBatch::new(expected, SessionLimits::default(), deadline())
            .unwrap();
    assert!(matches!(
        expected.import(&transfer, vec![first, duplicate]),
        Err(WindowsBatchError::WrongObject)
    ));

    let (batch, _) = build_batch(1);
    assert!(matches!(
        WindowsMixedDirectionBatch::prepare(batch, NativeAuthorityProfile::LinuxMdweV1, deadline()),
        Err(WindowsBatchError::WrongProvenance)
    ));
}

#[test]
fn expectation_rejects_active_region_and_byte_limits_before_import() {
    let (_, expected) = build_batch(2);
    let limits = SessionLimits {
        max_active_regions: 1,
        ..SessionLimits::default()
    };
    assert!(matches!(
        WindowsExpectedMixedDirectionBatch::new(expected, limits, deadline()),
        Err(WindowsBatchError::InvalidBatch)
    ));

    let (_, expected) = build_batch(1);
    let limits = SessionLimits {
        max_active_bytes: u64::try_from(page_size() - 1).unwrap(),
        ..SessionLimits::default()
    };
    assert!(matches!(
        WindowsExpectedMixedDirectionBatch::new(expected, limits, deadline()),
        Err(WindowsBatchError::InvalidSize)
    ));
}

#[test]
fn exact_size_and_access_are_rejected_before_activation() {
    let (batch, expected) = build_batch(1);
    let prepared = WindowsMixedDirectionBatch::prepare(
        batch,
        NativeAuthorityProfile::WindowsSectionsV1,
        deadline(),
    )
    .unwrap();
    let transfer = manifest(prepared.manifest_entries());

    let oversized = QuiescentRegion::new(page_size() + 1).unwrap();
    let remote = duplicate_to(
        oversized.section.0,
        unsafe { GetCurrentProcess() },
        windows_sys::Win32::System::Memory::FILE_MAP_READ,
    )
    .unwrap();
    let oversized = unsafe { WindowsReceivedHandle::from_raw(remote.0) }.unwrap();
    let expected_batch =
        WindowsExpectedMixedDirectionBatch::new(expected, SessionLimits::default(), deadline())
            .unwrap();
    assert!(matches!(
        expected_batch.import(&transfer, vec![oversized]),
        Err(WindowsBatchError::WrongObject)
    ));

    let (strong_batch, _) = build_batch(2);
    let strong = WindowsMixedDirectionBatch::prepare(
        strong_batch,
        NativeAuthorityProfile::WindowsSectionsV1,
        deadline(),
    )
    .unwrap();
    let wrong_access = strong.duplicate_capability_for_test(1).unwrap();
    let expected = WindowsExpectedMixedDirectionBatch::new(
        ExpectedBatch::try_from_regions(vec![ExpectedRegion::new(
            RegionId::new(1).unwrap(),
            WriterEndpoint::Coordinator,
            31,
        )])
        .unwrap(),
        SessionLimits::default(),
        deadline(),
    )
    .unwrap();
    assert!(matches!(
        expected.import(&transfer, vec![wrong_access]),
        Err(WindowsBatchError::WrongAccess)
    ));
}

#[test]
fn split_reserved_tail_cannot_bypass_exact_allocation_size() {
    let page = page_size();
    let (batch, expected) = build_batch(1);
    let prepared = WindowsMixedDirectionBatch::prepare(
        batch,
        NativeAuthorityProfile::WindowsSectionsV1,
        deadline(),
    )
    .unwrap();
    let transfer = manifest(prepared.manifest_entries());
    let oversized = page.checked_mul(2).unwrap();
    // SAFETY: pagefile sentinel, null security/name, and exact nonzero size.
    let section = unsafe {
        CreateFileMappingW(
            INVALID_HANDLE_VALUE,
            core::ptr::null(),
            PAGE_READWRITE | SEC_RESERVE,
            0,
            u32::try_from(oversized).unwrap(),
            core::ptr::null(),
        )
    };
    let section = OwnedHandle::new(section).unwrap();
    let view = View::map(section.0, oversized, FILE_MAP_WRITE).unwrap();
    // SAFETY: the address is the base of this reserved section view and one
    // page is inside it; committing that prefix creates the split VQ runs.
    assert_eq!(
        unsafe { VirtualAlloc(view.base.as_ptr().cast(), page, MEM_COMMIT, PAGE_READWRITE,) },
        view.base.as_ptr().cast()
    );
    let remote = duplicate_to(section.0, unsafe { GetCurrentProcess() }, FILE_MAP_READ).unwrap();
    let remote = unsafe { WindowsReceivedHandle::from_raw(remote.0) }.unwrap();
    let expected =
        WindowsExpectedMixedDirectionBatch::new(expected, SessionLimits::default(), deadline())
            .unwrap();
    assert!(matches!(
        expected.import(&transfer, vec![remote]),
        Err(WindowsBatchError::WrongObject)
    ));
}

#[test]
fn inherited_and_protected_raw_handles_are_rejected_and_closed() {
    for flag in [HANDLE_FLAG_INHERIT, HANDLE_FLAG_PROTECT_FROM_CLOSE] {
        let (batch, _) = build_batch(1);
        let prepared = WindowsMixedDirectionBatch::prepare(
            batch,
            NativeAuthorityProfile::WindowsSectionsV1,
            deadline(),
        )
        .unwrap();
        let before = live_handles_for_test();
        let raw = prepared.duplicate_raw_capability_for_test(0).unwrap();
        let mask = HANDLE_FLAG_INHERIT | HANDLE_FLAG_PROTECT_FROM_CLOSE;
        // SAFETY: DuplicateHandle just installed this live test-owned handle.
        assert_ne!(
            unsafe { SetHandleInformation(raw as HANDLE, mask, flag) },
            0
        );
        assert!(matches!(
            unsafe { WindowsReceivedHandle::from_raw(raw) },
            Err(WindowsBatchError::WrongAccess)
        ));
        assert_eq!(live_handles_for_test(), before);
    }
}

#[test]
fn flags_added_after_adoption_are_rejected_and_closed() {
    for flag in [HANDLE_FLAG_INHERIT, HANDLE_FLAG_PROTECT_FROM_CLOSE] {
        let (batch, expected) = build_batch(1);
        let prepared = WindowsMixedDirectionBatch::prepare(
            batch,
            NativeAuthorityProfile::WindowsSectionsV1,
            deadline(),
        )
        .unwrap();
        let transfer = manifest(prepared.manifest_entries());
        let before = live_handles_for_test();
        let handle = prepared.duplicate_capability_for_test(0).unwrap();
        assert!(handle.set_flags_for_test(flag));
        let expected =
            WindowsExpectedMixedDirectionBatch::new(expected, SessionLimits::default(), deadline())
                .unwrap();
        assert!(matches!(
            expected.import(&transfer, vec![handle]),
            Err(WindowsBatchError::WrongAccess)
        ));
        assert_eq!(live_handles_for_test(), before);
    }
}

#[test]
fn imported_views_cannot_gain_write_or_execute() {
    let (batch, expected) = build_batch(2);
    let prepared = WindowsMixedDirectionBatch::prepare(
        batch,
        NativeAuthorityProfile::WindowsSectionsV1,
        deadline(),
    )
    .unwrap();
    let transfer = manifest(prepared.manifest_entries());
    let handles = prepared.copied_capabilities_for_test().unwrap();
    let expected =
        WindowsExpectedMixedDirectionBatch::new(expected, SessionLimits::default(), deadline())
            .unwrap();
    let imported = expected.import(&transfer, handles).unwrap();
    for owner in imported.into_active_region_owners() {
        let spec = owner.spec();
        let mut prior = 0;
        match spec.authority {
            LocalRegionAuthority::Reader => {
                let owner = owner.into_reader().unwrap();
                assert_eq!(
                    unsafe {
                        VirtualProtect(
                            owner.as_ptr().cast_mut().cast(),
                            spec.mapped_len,
                            PAGE_EXECUTE_READWRITE,
                            &mut prior,
                        )
                    },
                    0
                );
                assert_eq!(
                    unsafe {
                        VirtualProtect(
                            owner.as_ptr().cast_mut().cast(),
                            spec.mapped_len,
                            windows_sys::Win32::System::Memory::PAGE_READWRITE,
                            &mut prior,
                        )
                    },
                    0
                );
            }
            LocalRegionAuthority::Writer => {
                let mut owner = owner.into_writer().unwrap();
                assert_eq!(
                    unsafe {
                        VirtualProtect(
                            owner.as_mut_ptr().cast(),
                            spec.mapped_len,
                            PAGE_EXECUTE_READWRITE,
                            &mut prior,
                        )
                    },
                    0
                );
            }
        }
    }
}
