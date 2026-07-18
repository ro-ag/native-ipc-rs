use super::vnext_memory::{
    MacActiveRegionOwner, MacBatchError, MacExpectedMixedDirectionBatch, MacMixedDirectionBatch,
};
use super::{
    LocalWriterRegion, QuiescentRegion, VM_PROT_EXECUTE, VM_PROT_READ, VM_PROT_WRITE, bootstrap,
    current_task, mach_vm_protect, page_size, set_vnext_drop_observer_for_test,
};
use crate::batch::{ExpectedBatch, ExpectedRegion, LocalRegionAuthority, TransferBatch};
use crate::protocol::{NativeAuthorityProfile, TransferManifest};
use crate::region::{
    GuardPolicy, PrivateRegion, RegionId, RegionOptions, RegionSpec, WriterEndpoint,
};
use crate::session::{AbsoluteDeadline, SessionLimits};
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn deadline() -> AbsoluteDeadline {
    AbsoluteDeadline::after(Duration::from_secs(10)).unwrap()
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

fn manifest(entries: Vec<crate::protocol::ManifestEntry>) -> TransferManifest {
    TransferManifest::new_with_authority(
        [7; 32],
        std::process::id(),
        std::process::id().checked_add(1).unwrap(),
        1,
        NativeAuthorityProfile::MacMachV1,
        entries,
    )
    .unwrap()
}

fn run_full_cycle(count: usize) {
    let (batch, expected) = build_batch(count);
    let prepared =
        MacMixedDirectionBatch::prepare(batch, NativeAuthorityProfile::MacMachV1, deadline())
            .unwrap();
    let transfer = manifest(prepared.manifest_entries());
    let rights = prepared.copied_capabilities_for_test().unwrap();
    let expected =
        MacExpectedMixedDirectionBatch::new(expected, SessionLimits::default(), deadline())
            .unwrap();
    let imported = expected.import(&transfer, rights).unwrap();
    // Drop both sides: the imported activation owners and the coordinator-side
    // prepared batch. Every native mapping, memory entry, and send right must
    // be released here.
    drop(imported.into_active_region_owners());
    drop(prepared);
}

#[test]
fn native_owner_lifecycle_has_no_leak_across_ten_thousand_cycles() {
    const COUNT: usize = 2;
    const CYCLES: usize = 10_000;
    // Calibrate the exact native drop events for one full prepare, import,
    // activate, and drop cycle.
    let calibration = Arc::new(Mutex::new(Vec::new()));
    set_vnext_drop_observer_for_test(Some(calibration.clone()));
    run_full_cycle(COUNT);
    set_vnext_drop_observer_for_test(None);
    let per_cycle = calibration.lock().unwrap().len();
    assert!(per_cycle > 0, "a full cycle must drop native owners");
    // Every subsequent cycle must drop exactly the same owners. Any leak,
    // double-drop, or accumulation over ten thousand iterations changes the
    // total, so an exact multiple is the leak baseline.
    let drops = Arc::new(Mutex::new(Vec::new()));
    set_vnext_drop_observer_for_test(Some(drops.clone()));
    for _ in 0..CYCLES {
        run_full_cycle(COUNT);
    }
    set_vnext_drop_observer_for_test(None);
    assert_eq!(
        drops.lock().unwrap().len(),
        per_cycle * CYCLES,
        "every native owner released across {CYCLES} cycles with no leak"
    );
}

#[test]
fn native_owner_drop_order_is_leak_free_in_both_permutations() {
    fn cycle_drops(drop_imported_first: bool) -> usize {
        let (batch, expected) = build_batch(4);
        let prepared =
            MacMixedDirectionBatch::prepare(batch, NativeAuthorityProfile::MacMachV1, deadline())
                .unwrap();
        let transfer = manifest(prepared.manifest_entries());
        let rights = prepared.copied_capabilities_for_test().unwrap();
        let expected =
            MacExpectedMixedDirectionBatch::new(expected, SessionLimits::default(), deadline())
                .unwrap();
        let owners = expected
            .import(&transfer, rights)
            .unwrap()
            .into_active_region_owners();
        // Observe only the two owner drops so the count reflects the release
        // order under test, not the transient import churn.
        let drops = Arc::new(Mutex::new(Vec::new()));
        set_vnext_drop_observer_for_test(Some(drops.clone()));
        if drop_imported_first {
            drop(owners);
            drop(prepared);
        } else {
            drop(prepared);
            drop(owners);
        }
        set_vnext_drop_observer_for_test(None);
        drops.lock().unwrap().len()
    }
    let imported_first = cycle_drops(true);
    let prepared_first = cycle_drops(false);
    assert!(
        imported_first > 0,
        "dropping the owners must release natives"
    );
    assert_eq!(
        imported_first, prepared_first,
        "both endpoints release the same native owners regardless of drop order"
    );
}

#[test]
fn mixed_batches_prepare_import_and_activate_complementary_authority() {
    for count in [1, 2, 4, 16] {
        let (batch, expected) = build_batch(count);
        let mut prepared =
            MacMixedDirectionBatch::prepare(batch, NativeAuthorityProfile::MacMachV1, deadline())
                .unwrap();
        let transfer = manifest(prepared.manifest_entries());
        let rights = prepared.copied_capabilities_for_test().unwrap();
        let expected =
            MacExpectedMixedDirectionBatch::new(expected, SessionLimits::default(), deadline())
                .unwrap();
        assert!(expected.matches_manifest(&transfer));
        let mut imported = expected.import(&transfer, rights).unwrap();

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
        assert_eq!(local_owners.len(), count);
        assert_eq!(peer_owners.len(), count);
        for (ordinal, (local, peer)) in local_owners.into_iter().zip(peer_owners).enumerate() {
            if ordinal % 2 == 0 {
                let mut writer = local.into_writer().expect("coordinator owns writer");
                let reader = peer.into_reader().expect("receiver owns reader");
                unsafe { core::ptr::write_volatile(writer.as_mut_ptr().add(2), 0x80) };
                assert_eq!(
                    unsafe { core::ptr::read_volatile(reader.as_ptr().add(2)) },
                    0x80
                );
            } else {
                let reader = local.into_reader().expect("coordinator owns reader");
                let mut writer = peer.into_writer().expect("receiver owns writer");
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
fn preparation_and_import_failures_drop_partial_native_owners() {
    for count in [1, 2, 4, 16] {
        for failure_at in 1..=count {
            let (batch, _) = build_batch(count);
            let drops = Arc::new(Mutex::new(Vec::new()));
            set_vnext_drop_observer_for_test(Some(drops.clone()));
            assert_eq!(
                MacMixedDirectionBatch::prepare_with_failure_for_test(
                    batch,
                    failure_at,
                    deadline()
                )
                .err()
                .unwrap(),
                MacBatchError::WrongObject
            );
            set_vnext_drop_observer_for_test(None);
            let drops = drops.lock().unwrap();
            // Every region drops its quiescent mapping, and every prepared
            // entry additionally dropped one original view when its guarded
            // replacement was carved.
            assert_eq!(
                drops.iter().filter(|event| **event == "mapping").count(),
                count + failure_at
            );
            // Every prepared entry drops its peer entry; coordinator-writer
            // entries (even ordinals) also drop one transient self entry
            // used to carve the guarded writable view.
            assert_eq!(
                drops
                    .iter()
                    .filter(|event| **event == "memory-entry")
                    .count(),
                failure_at + failure_at.div_ceil(2)
            );
        }

        for failure_at in 1..=count {
            let (batch, expected) = build_batch(count);
            let prepared = MacMixedDirectionBatch::prepare(
                batch,
                NativeAuthorityProfile::MacMachV1,
                deadline(),
            )
            .unwrap();
            let transfer = manifest(prepared.manifest_entries());
            let rights = prepared.copied_capabilities_for_test().unwrap();
            let expected =
                MacExpectedMixedDirectionBatch::new(expected, SessionLimits::default(), deadline())
                    .unwrap();
            let drops = Arc::new(Mutex::new(Vec::new()));
            set_vnext_drop_observer_for_test(Some(drops.clone()));
            assert_eq!(
                expected
                    .import_with_failure_for_test(&transfer, rights, failure_at)
                    .err()
                    .unwrap(),
                MacBatchError::WrongObject
            );
            set_vnext_drop_observer_for_test(None);
            let drops = drops.lock().unwrap();
            assert_eq!(
                drops.iter().filter(|event| **event == "mapping").count(),
                failure_at
            );
            assert_eq!(
                drops.iter().filter(|event| **event == "send-right").count(),
                count
            );
            drop(drops);
            prepared.revalidate_before_send().unwrap();
        }
    }
}

#[test]
fn duplicate_right_and_wrong_profile_fail_closed() {
    let (batch, expected) = build_batch(2);
    let prepared =
        MacMixedDirectionBatch::prepare(batch, NativeAuthorityProfile::MacMachV1, deadline())
            .unwrap();
    let transfer = manifest(prepared.manifest_entries());
    let first = prepared.capability_names()[0];
    let rights = vec![
        bootstrap::SendRight::copy_existing(first).unwrap(),
        bootstrap::SendRight::copy_existing(first).unwrap(),
    ];
    let expected =
        MacExpectedMixedDirectionBatch::new(expected, SessionLimits::default(), deadline())
            .unwrap();
    assert_eq!(
        expected.import(&transfer, rights).err().unwrap(),
        MacBatchError::WrongObject
    );

    let (batch, _) = build_batch(1);
    assert_eq!(
        MacMixedDirectionBatch::prepare(batch, NativeAuthorityProfile::LinuxMdweV1, deadline())
            .err()
            .unwrap(),
        MacBatchError::WrongProvenance
    );
}

#[test]
fn expectation_rejects_active_region_and_byte_limits_before_import() {
    let (_, expected) = build_batch(2);
    let limits = SessionLimits {
        max_active_regions: 1,
        ..SessionLimits::default()
    };
    assert_eq!(
        MacExpectedMixedDirectionBatch::new(expected, limits, deadline())
            .err()
            .unwrap(),
        MacBatchError::InvalidBatch
    );

    let (_, expected) = build_batch(1);
    let limits = SessionLimits {
        max_active_bytes: u64::try_from(page_size().unwrap() - 1).unwrap(),
        ..SessionLimits::default()
    };
    assert_eq!(
        MacExpectedMixedDirectionBatch::new(expected, limits, deadline())
            .err()
            .unwrap(),
        MacBatchError::InvalidSize
    );
}

#[test]
fn oversized_and_excess_right_capabilities_are_rejected() {
    let (batch, expected) = build_batch(1);
    let prepared =
        MacMixedDirectionBatch::prepare(batch, NativeAuthorityProfile::MacMachV1, deadline())
            .unwrap();
    let transfer = manifest(prepared.manifest_entries());

    let page = page_size().unwrap();
    let LocalWriterRegion {
        peer_entry: oversized,
        ..
    } = QuiescentRegion::new(page + 1)
        .unwrap()
        .into_local_writer(page * 2)
        .unwrap();
    let oversized = vec![bootstrap::SendRight::copy_existing(oversized.name).unwrap()];
    let expected_batch = MacExpectedMixedDirectionBatch::new(
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
    assert_eq!(
        expected_batch.import(&transfer, oversized).err().unwrap(),
        MacBatchError::WrongObject
    );

    let (strong_batch, _) = build_batch(2);
    let strong = MacMixedDirectionBatch::prepare(
        strong_batch,
        NativeAuthorityProfile::MacMachV1,
        deadline(),
    )
    .unwrap();
    let excessive =
        vec![bootstrap::SendRight::copy_existing(strong.capability_names()[1]).unwrap()];
    let expected =
        MacExpectedMixedDirectionBatch::new(expected, SessionLimits::default(), deadline())
            .unwrap();
    assert_eq!(
        expected.import(&transfer, excessive).err().unwrap(),
        MacBatchError::WrongObject
    );
}

#[test]
fn imported_maximum_protections_exclude_execute() {
    let (batch, expected) = build_batch(2);
    let prepared =
        MacMixedDirectionBatch::prepare(batch, NativeAuthorityProfile::MacMachV1, deadline())
            .unwrap();
    let transfer = manifest(prepared.manifest_entries());
    let rights = prepared.copied_capabilities_for_test().unwrap();
    let expected =
        MacExpectedMixedDirectionBatch::new(expected, SessionLimits::default(), deadline())
            .unwrap();
    let imported = expected.import(&transfer, rights).unwrap();
    for owner in imported.into_active_region_owners() {
        let spec = owner.spec();
        match spec.authority {
            LocalRegionAuthority::Reader => {
                let owner = owner.into_reader().unwrap();
                let address = owner.as_ptr() as u64;
                // SAFETY: this deliberately probes the checked maximum of the
                // exact live imported reader mapping without changing it on failure.
                let write_result = unsafe {
                    mach_vm_protect(
                        current_task(),
                        address,
                        spec.mapped_len as u64,
                        0,
                        VM_PROT_READ | VM_PROT_WRITE,
                    )
                };
                assert_ne!(write_result, super::KERN_SUCCESS);
                // SAFETY: the owner remains live across this negative probe.
                let result = unsafe {
                    mach_vm_protect(
                        current_task(),
                        address,
                        spec.mapped_len as u64,
                        0,
                        VM_PROT_READ | VM_PROT_EXECUTE,
                    )
                };
                assert_ne!(result, super::KERN_SUCCESS);
            }
            LocalRegionAuthority::Writer => {
                let mut owner = owner.into_writer().unwrap();
                let address = owner.as_mut_ptr() as u64;
                // SAFETY: the owner remains live across this negative probe.
                let result = unsafe {
                    mach_vm_protect(
                        current_task(),
                        address,
                        spec.mapped_len as u64,
                        0,
                        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE,
                    )
                };
                assert_ne!(result, super::KERN_SUCCESS);
            }
        }
    }
}

fn build_batch_with_policy(count: usize, guard: GuardPolicy) -> (TransferBatch, ExpectedBatch) {
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
        let mut region =
            PrivateRegion::allocate(RegionOptions::fixed(logical_len).with_guard_policy(guard))
                .unwrap();
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

/// Returns `(region_start, region_size, current_protection)` for the VM
/// region containing or following `address`, via `mach_vm_region`.
fn region_protection(address: u64) -> (u64, u64, i32) {
    unsafe extern "C" {
        fn mach_vm_region(
            target_task: u32,
            address: *mut u64,
            size: *mut u64,
            flavor: i32,
            info: *mut u32,
            info_count: *mut u32,
            object_name: *mut u32,
        ) -> i32;
    }
    const VM_REGION_BASIC_INFO_64: i32 = 9;
    const VM_REGION_BASIC_INFO_COUNT_64: u32 = 9;
    let mut start = address;
    let mut size = 0_u64;
    let mut info = [0_u32; VM_REGION_BASIC_INFO_COUNT_64 as usize];
    let mut count = VM_REGION_BASIC_INFO_COUNT_64;
    let mut object_name = 0_u32;
    // SAFETY: every out-pointer is valid and the info buffer holds exactly
    // VM_REGION_BASIC_INFO_COUNT_64 natural words.
    let result = unsafe {
        mach_vm_region(
            current_task(),
            &mut start,
            &mut size,
            VM_REGION_BASIC_INFO_64,
            info.as_mut_ptr(),
            &mut count,
            &mut object_name,
        )
    };
    assert_eq!(result, super::KERN_SUCCESS, "mach_vm_region failed");
    (start, size, info[0] as i32)
}

/// A guard band page must be inaccessible: covered with no current permission.
fn assert_band_inaccessible(address: u64) {
    let (start, size, protection) = region_protection(address);
    assert!(
        start <= address && address < start + size,
        "guard band at {address:#x} is not mapped"
    );
    assert_eq!(
        protection, 0,
        "guard band at {address:#x} is accessible: {protection:#x}"
    );
}

fn assert_owner_view_guarded(owner: &MacActiveRegionOwner, page: usize, installed: bool) {
    // The owner must stay alive across every probe: dropping it unmaps the
    // view and deallocates its bands.
    let (base, len, reported) = match owner {
        MacActiveRegionOwner::Reader { owner, .. } => {
            (owner.as_ptr() as u64, owner.len(), owner.guard_installed())
        }
        MacActiveRegionOwner::Writer { owner, .. } => {
            (owner.as_ptr() as u64, owner.len(), owner.guard_installed())
        }
    };
    assert_eq!(reported, installed, "owner guard reporting is dishonest");
    if installed {
        assert_band_inaccessible(base - page as u64);
        assert_band_inaccessible(base + len as u64);
        let (_, _, interior) = region_protection(base);
        assert_ne!(interior, 0, "interior view lost its access");
    }
}

#[test]
fn mixed_active_owners_install_guard_bands_on_both_endpoints() {
    let (batch, expected) = build_batch(2);
    let prepared =
        MacMixedDirectionBatch::prepare(batch, NativeAuthorityProfile::MacMachV1, deadline())
            .unwrap();
    let transfer = manifest(prepared.manifest_entries());
    let rights = prepared.copied_capabilities_for_test().unwrap();
    let expected =
        MacExpectedMixedDirectionBatch::new(expected, SessionLimits::default(), deadline())
            .unwrap();
    let imported = expected.import(&transfer, rights).unwrap();
    let page = page_size().unwrap();
    for spec in prepared.activation_specs().unwrap() {
        assert_eq!(spec.guard_requested, GuardPolicy::BestEffort);
    }
    for owner in prepared.into_active_region_owners() {
        assert_owner_view_guarded(&owner, page, true);
    }
    for spec in imported.activation_specs(deadline()).unwrap() {
        assert_eq!(spec.guard_requested, GuardPolicy::BestEffort);
    }
    for owner in imported.into_active_region_owners() {
        assert_owner_view_guarded(&owner, page, true);
    }
}

#[test]
fn required_guard_policy_commits_with_installed_bands() {
    let (batch, _) = build_batch_with_policy(2, GuardPolicy::Require);
    let prepared =
        MacMixedDirectionBatch::prepare(batch, NativeAuthorityProfile::MacMachV1, deadline())
            .unwrap();
    let page = page_size().unwrap();
    for spec in prepared.activation_specs().unwrap() {
        assert_eq!(spec.guard_requested, GuardPolicy::Require);
    }
    for owner in prepared.into_active_region_owners() {
        assert_owner_view_guarded(&owner, page, true);
    }
}

#[test]
fn disabled_guard_policy_keeps_creator_views_unguarded_and_honest() {
    let (batch, expected) = build_batch_with_policy(2, GuardPolicy::Disable);
    let prepared =
        MacMixedDirectionBatch::prepare(batch, NativeAuthorityProfile::MacMachV1, deadline())
            .unwrap();
    let transfer = manifest(prepared.manifest_entries());
    let rights = prepared.copied_capabilities_for_test().unwrap();
    let expected =
        MacExpectedMixedDirectionBatch::new(expected, SessionLimits::default(), deadline())
            .unwrap();
    let imported = expected.import(&transfer, rights).unwrap();
    let page = page_size().unwrap();
    for spec in prepared.activation_specs().unwrap() {
        assert_eq!(spec.guard_requested, GuardPolicy::Disable);
    }
    for owner in prepared.into_active_region_owners() {
        assert_owner_view_guarded(&owner, page, false);
    }
    // The importing endpoint cannot see the creator's policy and still
    // applies best-effort placement to its own views.
    for owner in imported.into_active_region_owners() {
        assert_owner_view_guarded(&owner, page, true);
    }
}
