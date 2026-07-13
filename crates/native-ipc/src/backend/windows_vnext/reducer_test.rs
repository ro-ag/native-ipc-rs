use super::connect_spawned_helper;
use super::vnext_memory::{WindowsMixedDirectionBatch, live_handles_for_test, live_views_for_test};
use super::vnext_transport_test::{
    coordinator_transport, deadline, receiver_transport, spawn_helper,
};
use crate::backend::accepted_control::{
    AcceptedControlDispatcher, AcceptedControlError, WindowsCapabilityBatchError,
};
use crate::batch::{ExpectedBatch, ExpectedRegion, TransferBatch};
use crate::control::ControlError;
use crate::region::{PrivateRegion, RegionId, RegionOptions, RegionSpec, WriterEndpoint};

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

fn coordinator_dispatcher(
    helper: &str,
) -> AcceptedControlDispatcher<super::vnext_transport::CoordinatorWindowsControlTransport> {
    let transport = coordinator_transport(spawn_helper(helper));
    let parameters = transport.session_parameters();
    AcceptedControlDispatcher::new(transport, parameters)
        .map_err(|_| ())
        .unwrap()
}

#[test]
fn accepted_full_manifest_reducer_commits_then_activates_mixed_1_2_4_16() {
    let handles = live_handles_for_test();
    let views = live_views_for_test();
    let mut dispatcher =
        coordinator_dispatcher("backend::windows::vnext_reducer_test::mixed_reducer_helper");
    for count in [1, 2, 4, 16] {
        let (batch, _) = build_batch(count);
        let prepared = WindowsMixedDirectionBatch::prepare(
            batch,
            crate::protocol::NativeAuthorityProfile::WindowsSectionsV1,
            deadline(),
        )
        .unwrap();
        let operation_deadline = prepared.deadline();
        let mut transaction = dispatcher
            .begin_windows_mixed_direction_batch(prepared, operation_deadline)
            .unwrap();
        transaction.prepare().unwrap();
        assert_eq!(transaction.remote_capability_count_for_test(), count);
        let committed = transaction.commit().unwrap();
        assert_eq!(dispatcher.windows_remote_capability_count_for_test(), 0);
        let mut active = dispatcher
            .activate_windows_coordinator_mixed_direction_batch(committed)
            .unwrap();
        assert_eq!(active.len(), count);
        assert_eq!(
            dispatcher.active_lease_facts_for_test().regions(),
            count as u32
        );
        for ordinal in (0..count).step_by(2) {
            let id = RegionId::new((ordinal + 1) as u128).unwrap();
            active
                .take_writer(id)
                .unwrap()
                .write_from(1, &[0xa0 + ordinal as u8])
                .unwrap();
        }
        dispatcher
            .send_parts(0x8000_0051, &[count as u8], deadline())
            .unwrap();
        let acknowledgement = dispatcher.receive(deadline()).unwrap();
        assert_eq!(acknowledgement.kind, 0x8000_0052);
        assert_eq!(acknowledgement.payload, vec![count as u8]);
        for ordinal in (1..count).step_by(2) {
            let id = RegionId::new((ordinal + 1) as u128).unwrap();
            let reader = active.take_reader(id).unwrap();
            let mut byte = [0];
            reader.read_into(1, &mut byte).unwrap();
            assert_eq!(byte, [0xc0 + ordinal as u8]);
        }
        assert!(active.is_empty());
        assert!(dispatcher.active_lease_facts_for_test().is_empty());
        assert_eq!(live_handles_for_test(), handles);
        assert_eq!(live_views_for_test(), views);
    }
    dispatcher
        .wait_for_windows_child_exit_for_test(deadline())
        .unwrap();
}

#[test]
fn substituted_sealed_poison_drops_exact_imported_batch() {
    let handles = live_handles_for_test();
    let views = live_views_for_test();
    let mut dispatcher =
        coordinator_dispatcher("backend::windows::vnext_reducer_test::substituted_sealed_helper");
    let (batch, _) = build_batch(4);
    let prepared = WindowsMixedDirectionBatch::prepare(
        batch,
        crate::protocol::NativeAuthorityProfile::WindowsSectionsV1,
        deadline(),
    )
    .unwrap();
    let operation_deadline = prepared.deadline();
    let mut transaction = dispatcher
        .begin_windows_mixed_direction_batch(prepared, operation_deadline)
        .unwrap();
    transaction.substitute_sealed_for_test();
    assert_noncanonical(transaction.prepare().unwrap_err());
    assert_eq!(transaction.remote_capability_count_for_test(), 4);
    drop(transaction);
    assert_eq!(dispatcher.windows_remote_capability_count_for_test(), 4);
    assert_eq!(live_handles_for_test(), handles);
    assert_eq!(live_views_for_test(), views);
    assert_eq!(
        dispatcher.send_parts(0x8000_0053, &[], deadline()),
        Err(AcceptedControlError::Control(ControlError::Poisoned))
    );
    assert!(dispatcher.active_lease_facts_for_test().is_empty());
    dispatcher
        .wait_for_windows_child_exit_for_test(deadline())
        .unwrap();
    assert_eq!(dispatcher.windows_remote_capability_count_for_test(), 0);
}

#[test]
fn substituted_commit_poison_drops_exact_imported_batch() {
    let handles = live_handles_for_test();
    let views = live_views_for_test();
    let mut dispatcher =
        coordinator_dispatcher("backend::windows::vnext_reducer_test::substituted_commit_helper");
    let (batch, _) = build_batch(4);
    let prepared = WindowsMixedDirectionBatch::prepare(
        batch,
        crate::protocol::NativeAuthorityProfile::WindowsSectionsV1,
        deadline(),
    )
    .unwrap();
    let operation_deadline = prepared.deadline();
    let mut transaction = dispatcher
        .begin_windows_mixed_direction_batch(prepared, operation_deadline)
        .unwrap();
    transaction.prepare().unwrap();
    assert_eq!(transaction.remote_capability_count_for_test(), 4);
    transaction.substitute_commit_for_test();
    match transaction.commit() {
        Err(error) => assert_noncanonical(error),
        Ok(_) => panic!("substituted COMMIT must not commit the coordinator batch"),
    }
    assert_eq!(dispatcher.windows_remote_capability_count_for_test(), 4);
    assert_eq!(live_handles_for_test(), handles);
    assert_eq!(live_views_for_test(), views);
    assert_eq!(
        dispatcher.send_parts(0x8000_0054, &[], deadline()),
        Err(AcceptedControlError::Control(ControlError::Poisoned))
    );
    assert!(dispatcher.active_lease_facts_for_test().is_empty());
    dispatcher
        .wait_for_windows_child_exit_for_test(deadline())
        .unwrap();
    assert_eq!(dispatcher.windows_remote_capability_count_for_test(), 0);
}

#[test]
fn substituted_imported_poison_drops_exact_pending_batch() {
    let handles = live_handles_for_test();
    let views = live_views_for_test();
    let mut dispatcher =
        coordinator_dispatcher("backend::windows::vnext_reducer_test::substituted_imported_helper");
    let (batch, _) = build_batch(4);
    let prepared = WindowsMixedDirectionBatch::prepare(
        batch,
        crate::protocol::NativeAuthorityProfile::WindowsSectionsV1,
        deadline(),
    )
    .unwrap();
    let operation_deadline = prepared.deadline();
    let mut transaction = dispatcher
        .begin_windows_mixed_direction_batch(prepared, operation_deadline)
        .unwrap();
    assert_noncanonical(transaction.prepare().unwrap_err());
    assert_eq!(transaction.remote_capability_count_for_test(), 4);
    drop(transaction);
    assert_eq!(dispatcher.windows_remote_capability_count_for_test(), 4);
    assert_eq!(live_handles_for_test(), handles);
    assert_eq!(live_views_for_test(), views);
    assert!(dispatcher.active_lease_facts_for_test().is_empty());
    assert_eq!(
        dispatcher.send_parts(0x8000_0055, &[], deadline()),
        Err(AcceptedControlError::Control(ControlError::Poisoned))
    );
    dispatcher
        .wait_for_windows_child_exit_for_test(deadline())
        .unwrap();
    assert_eq!(dispatcher.windows_remote_capability_count_for_test(), 0);
}

#[test]
fn substituted_ready_poison_drops_exact_pending_batch() {
    let handles = live_handles_for_test();
    let views = live_views_for_test();
    let mut dispatcher =
        coordinator_dispatcher("backend::windows::vnext_reducer_test::substituted_ready_helper");
    let (batch, _) = build_batch(4);
    let prepared = WindowsMixedDirectionBatch::prepare(
        batch,
        crate::protocol::NativeAuthorityProfile::WindowsSectionsV1,
        deadline(),
    )
    .unwrap();
    let operation_deadline = prepared.deadline();
    let mut transaction = dispatcher
        .begin_windows_mixed_direction_batch(prepared, operation_deadline)
        .unwrap();
    transaction.prepare().unwrap();
    assert_eq!(transaction.remote_capability_count_for_test(), 4);
    match transaction.commit() {
        Err(error) => assert_noncanonical(error),
        Ok(_) => panic!("substituted READY must not commit the coordinator batch"),
    }
    assert_eq!(dispatcher.windows_remote_capability_count_for_test(), 4);
    assert_eq!(live_handles_for_test(), handles);
    assert_eq!(live_views_for_test(), views);
    assert!(dispatcher.active_lease_facts_for_test().is_empty());
    assert_eq!(
        dispatcher.send_parts(0x8000_0056, &[], deadline()),
        Err(AcceptedControlError::Control(ControlError::Poisoned))
    );
    dispatcher
        .wait_for_windows_child_exit_for_test(deadline())
        .unwrap();
    assert_eq!(dispatcher.windows_remote_capability_count_for_test(), 0);
}

fn assert_noncanonical(error: WindowsCapabilityBatchError) {
    assert!(matches!(
        error,
        WindowsCapabilityBatchError::Control(AcceptedControlError::Control(
            ControlError::NonCanonical
        ))
    ));
}

#[test]
#[ignore = "spawned only by the accepted Windows mixed reducer integration test"]
fn mixed_reducer_helper() {
    let handles = live_handles_for_test();
    let views = live_views_for_test();
    let channel = connect_spawned_helper().unwrap();
    let transport = receiver_transport(channel);
    let parameters = transport.session_parameters();
    let mut dispatcher = AcceptedControlDispatcher::new(transport, parameters)
        .map_err(|_| ())
        .unwrap();
    for count in [1, 2, 4, 16] {
        let (_, expected) = build_batch(count);
        let mut transaction = dispatcher
            .begin_windows_expected_mixed_direction_batch(expected, deadline())
            .unwrap();
        transaction.prepare().unwrap();
        let committed = transaction.commit().unwrap();
        let mut active = dispatcher
            .activate_windows_receiver_mixed_direction_batch(committed)
            .unwrap();
        assert_eq!(
            dispatcher.active_lease_facts_for_test().regions(),
            count as u32
        );
        let notification = dispatcher.receive(deadline()).unwrap();
        assert_eq!(notification.kind, 0x8000_0051);
        assert_eq!(notification.payload, vec![count as u8]);
        for ordinal in 0..count {
            let id = RegionId::new((ordinal + 1) as u128).unwrap();
            if ordinal % 2 == 0 {
                let reader = active.take_reader(id).unwrap();
                let mut bytes = [0; 2];
                reader.read_into(0, &mut bytes).unwrap();
                assert_eq!(bytes, [(ordinal + 1) as u8, 0xa0 + ordinal as u8]);
            } else {
                active
                    .take_writer(id)
                    .unwrap()
                    .write_from(1, &[0xc0 + ordinal as u8])
                    .unwrap();
            }
        }
        assert!(active.is_empty());
        assert!(dispatcher.active_lease_facts_for_test().is_empty());
        assert_eq!(live_handles_for_test(), handles);
        assert_eq!(live_views_for_test(), views);
        dispatcher
            .send_parts(0x8000_0052, &[count as u8], deadline())
            .unwrap();
    }
}

#[test]
#[ignore = "spawned only by the substituted SEALED integration test"]
fn substituted_sealed_helper() {
    let handles = live_handles_for_test();
    let views = live_views_for_test();
    let channel = connect_spawned_helper().unwrap();
    let transport = receiver_transport(channel);
    let parameters = transport.session_parameters();
    let mut dispatcher = AcceptedControlDispatcher::new(transport, parameters)
        .map_err(|_| ())
        .unwrap();
    let (_, expected) = build_batch(4);
    let mut transaction = dispatcher
        .begin_windows_expected_mixed_direction_batch(expected, deadline())
        .unwrap();
    assert_noncanonical(transaction.prepare().unwrap_err());
    drop(transaction);
    assert!(dispatcher.active_lease_facts_for_test().is_empty());
    assert_eq!(
        dispatcher.send_parts(0x8000_0055, &[], deadline()),
        Err(AcceptedControlError::Control(ControlError::Poisoned))
    );
    assert_eq!(live_handles_for_test(), handles);
    assert_eq!(live_views_for_test(), views);
}

#[test]
#[ignore = "spawned only by the substituted COMMIT integration test"]
fn substituted_commit_helper() {
    let handles = live_handles_for_test();
    let views = live_views_for_test();
    let channel = connect_spawned_helper().unwrap();
    let transport = receiver_transport(channel);
    let parameters = transport.session_parameters();
    let mut dispatcher = AcceptedControlDispatcher::new(transport, parameters)
        .map_err(|_| ())
        .unwrap();
    let (_, expected) = build_batch(4);
    let mut transaction = dispatcher
        .begin_windows_expected_mixed_direction_batch(expected, deadline())
        .unwrap();
    transaction.prepare().unwrap();
    match transaction.commit() {
        Err(error) => assert_noncanonical(error),
        Ok(_) => panic!("substituted COMMIT must not commit the receiver batch"),
    }
    assert!(dispatcher.active_lease_facts_for_test().is_empty());
    assert_eq!(
        dispatcher.send_parts(0x8000_0056, &[], deadline()),
        Err(AcceptedControlError::Control(ControlError::Poisoned))
    );
    assert_eq!(live_handles_for_test(), handles);
    assert_eq!(live_views_for_test(), views);
}

#[test]
#[ignore = "spawned only by the substituted IMPORTED integration test"]
fn substituted_imported_helper() {
    let handles = live_handles_for_test();
    let views = live_views_for_test();
    let channel = connect_spawned_helper().unwrap();
    let transport = receiver_transport(channel);
    let parameters = transport.session_parameters();
    let mut dispatcher = AcceptedControlDispatcher::new(transport, parameters)
        .map_err(|_| ())
        .unwrap();
    let (_, expected) = build_batch(4);
    let mut transaction = dispatcher
        .begin_windows_expected_mixed_direction_batch(expected, deadline())
        .unwrap();
    transaction.substitute_imported_for_test();
    assert_noncanonical(transaction.prepare().unwrap_err());
    drop(transaction);
    assert!(dispatcher.active_lease_facts_for_test().is_empty());
    assert_eq!(
        dispatcher.send_parts(0x8000_0055, &[], deadline()),
        Err(AcceptedControlError::Control(ControlError::Poisoned))
    );
    assert_eq!(live_handles_for_test(), handles);
    assert_eq!(live_views_for_test(), views);
}

#[test]
#[ignore = "spawned only by the substituted READY integration test"]
fn substituted_ready_helper() {
    let handles = live_handles_for_test();
    let views = live_views_for_test();
    let channel = connect_spawned_helper().unwrap();
    let transport = receiver_transport(channel);
    let parameters = transport.session_parameters();
    let mut dispatcher = AcceptedControlDispatcher::new(transport, parameters)
        .map_err(|_| ())
        .unwrap();
    let (_, expected) = build_batch(4);
    let mut transaction = dispatcher
        .begin_windows_expected_mixed_direction_batch(expected, deadline())
        .unwrap();
    transaction.prepare().unwrap();
    transaction.substitute_ready_for_test();
    match transaction.commit() {
        Err(error) => assert_noncanonical(error),
        Ok(_) => panic!("substituted READY must not commit the receiver batch"),
    }
    assert!(dispatcher.active_lease_facts_for_test().is_empty());
    assert_eq!(
        dispatcher.send_parts(0x8000_0056, &[], deadline()),
        Err(AcceptedControlError::Control(ControlError::Poisoned))
    );
    assert_eq!(live_handles_for_test(), handles);
    assert_eq!(live_views_for_test(), views);
}
