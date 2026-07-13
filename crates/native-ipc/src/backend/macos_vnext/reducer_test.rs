use super::bootstrap;
use super::vnext_memory::MacMixedDirectionBatch;
use super::vnext_transport_test::{
    coordinator_transport, deadline, receiver_transport, spawn_helper,
};
use crate::backend::accepted_control::{
    AcceptedControlDispatcher, AcceptedControlError, MacCapabilityBatchError,
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
) -> AcceptedControlDispatcher<super::vnext_transport::CoordinatorMacControlTransport> {
    let transport = coordinator_transport(spawn_helper(helper));
    let parameters = transport.session_parameters();
    AcceptedControlDispatcher::new(transport, parameters)
        .map_err(|_| ())
        .unwrap()
}

#[test]
fn accepted_full_manifest_reducer_commits_then_activates_mixed_1_2_4_16() {
    let mut dispatcher =
        coordinator_dispatcher("backend::macos::vnext_reducer_test::mixed_reducer_helper");
    for count in [1, 2, 4, 16] {
        let (batch, _) = build_batch(count);
        let prepared = MacMixedDirectionBatch::prepare(
            batch,
            crate::protocol::NativeAuthorityProfile::MacMachV1,
            deadline(),
        )
        .unwrap();
        let operation_deadline = prepared.deadline();
        let mut transaction = dispatcher
            .begin_macos_mixed_direction_batch(prepared, operation_deadline)
            .unwrap();
        transaction.prepare().unwrap();
        let committed = transaction.commit().unwrap();
        let mut active = dispatcher
            .activate_macos_coordinator_mixed_direction_batch(committed)
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
            .send_parts(0x8000_0041, &[count as u8], deadline())
            .unwrap();
        let acknowledgement = dispatcher.receive(deadline()).unwrap();
        assert_eq!(acknowledgement.kind, 0x8000_0042);
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
    }
}

#[test]
fn substituted_sealed_poison_drops_exact_imported_batch() {
    let mut dispatcher =
        coordinator_dispatcher("backend::macos::vnext_reducer_test::substituted_sealed_helper");
    let (batch, _) = build_batch(4);
    let prepared = MacMixedDirectionBatch::prepare(
        batch,
        crate::protocol::NativeAuthorityProfile::MacMachV1,
        deadline(),
    )
    .unwrap();
    let operation_deadline = prepared.deadline();
    let mut transaction = dispatcher
        .begin_macos_mixed_direction_batch(prepared, operation_deadline)
        .unwrap();
    transaction.substitute_sealed_for_test();
    assert_eq!(transaction.prepare(), Err(noncanonical_batch_error()));
    drop(transaction);
    assert_eq!(
        dispatcher.send_parts(0x8000_0043, &[], deadline()),
        Err(AcceptedControlError::Control(ControlError::Poisoned))
    );
    assert!(dispatcher.active_lease_facts_for_test().is_empty());
    dispatcher
        .wait_for_macos_child_exit_for_test(deadline())
        .unwrap();
}

#[test]
fn substituted_commit_poison_drops_exact_imported_batch() {
    let mut dispatcher =
        coordinator_dispatcher("backend::macos::vnext_reducer_test::substituted_commit_helper");
    let (batch, _) = build_batch(4);
    let prepared = MacMixedDirectionBatch::prepare(
        batch,
        crate::protocol::NativeAuthorityProfile::MacMachV1,
        deadline(),
    )
    .unwrap();
    let operation_deadline = prepared.deadline();
    let mut transaction = dispatcher
        .begin_macos_mixed_direction_batch(prepared, operation_deadline)
        .unwrap();
    transaction.prepare().unwrap();
    transaction.substitute_commit_for_test();
    match transaction.commit() {
        Err(error) => assert_eq!(error, noncanonical_batch_error()),
        Ok(_) => panic!("substituted COMMIT must not commit the coordinator batch"),
    }
    assert_eq!(
        dispatcher.send_parts(0x8000_0044, &[], deadline()),
        Err(AcceptedControlError::Control(ControlError::Poisoned))
    );
    assert!(dispatcher.active_lease_facts_for_test().is_empty());
    dispatcher
        .wait_for_macos_child_exit_for_test(deadline())
        .unwrap();
}

fn noncanonical_batch_error() -> MacCapabilityBatchError {
    MacCapabilityBatchError::Control(AcceptedControlError::Control(ControlError::NonCanonical))
}

fn assert_exact_import_cleanup(events: &[&'static str], count: usize) {
    assert_eq!(
        events.iter().filter(|event| **event == "mapping").count(),
        count
    );
    let poison = events.iter().position(|event| *event == "poison").unwrap();
    let first_mapping = events.iter().position(|event| *event == "mapping").unwrap();
    assert!(poison < first_mapping);
    assert_eq!(
        events
            .iter()
            .filter(|event| **event == "send-right")
            .count(),
        count
    );
}

#[test]
#[ignore = "spawned only by the accepted macOS mixed reducer integration test"]
fn mixed_reducer_helper() {
    let channel = bootstrap::ChildChannel::connect_from_environment().unwrap();
    let transport = receiver_transport(channel);
    let parameters = transport.session_parameters();
    let mut dispatcher = AcceptedControlDispatcher::new(transport, parameters)
        .map_err(|_| ())
        .unwrap();
    for count in [1, 2, 4, 16] {
        let (_, expected) = build_batch(count);
        let mut transaction = dispatcher
            .begin_macos_expected_mixed_direction_batch(expected, deadline())
            .unwrap();
        transaction.prepare().unwrap();
        let committed = transaction.commit().unwrap();
        let mut active = dispatcher
            .activate_macos_receiver_mixed_direction_batch(committed)
            .unwrap();
        assert_eq!(
            dispatcher.active_lease_facts_for_test().regions(),
            count as u32
        );
        let notification = dispatcher.receive(deadline()).unwrap();
        assert_eq!(notification.kind, 0x8000_0041);
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
        dispatcher
            .send_parts(0x8000_0042, &[count as u8], deadline())
            .unwrap();
    }
}

#[test]
#[ignore = "spawned only by the substituted SEALED integration test"]
fn substituted_sealed_helper() {
    let channel = bootstrap::ChildChannel::connect_from_environment().unwrap();
    let transport = receiver_transport(channel);
    let parameters = transport.session_parameters();
    let mut dispatcher = AcceptedControlDispatcher::new(transport, parameters)
        .map_err(|_| ())
        .unwrap();
    let (_, expected) = build_batch(4);
    let observer = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    dispatcher.observe_macos_receiver_poison_for_test(observer.clone());
    super::set_vnext_drop_observer_for_test(Some(observer.clone()));
    let mut transaction = dispatcher
        .begin_macos_expected_mixed_direction_batch(expected, deadline())
        .unwrap();
    assert_eq!(transaction.prepare(), Err(noncanonical_batch_error()));
    drop(transaction);
    assert_eq!(
        dispatcher.send_parts(0x8000_0043, &[], deadline()),
        Err(AcceptedControlError::Control(ControlError::Poisoned))
    );
    assert!(dispatcher.active_lease_facts_for_test().is_empty());
    super::set_vnext_drop_observer_for_test(None);
    assert_exact_import_cleanup(&observer.lock().unwrap(), 4);
}

#[test]
#[ignore = "spawned only by the substituted COMMIT integration test"]
fn substituted_commit_helper() {
    let channel = bootstrap::ChildChannel::connect_from_environment().unwrap();
    let transport = receiver_transport(channel);
    let parameters = transport.session_parameters();
    let mut dispatcher = AcceptedControlDispatcher::new(transport, parameters)
        .map_err(|_| ())
        .unwrap();
    let (_, expected) = build_batch(4);
    let observer = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    dispatcher.observe_macos_receiver_poison_for_test(observer.clone());
    super::set_vnext_drop_observer_for_test(Some(observer.clone()));
    let mut transaction = dispatcher
        .begin_macos_expected_mixed_direction_batch(expected, deadline())
        .unwrap();
    transaction.prepare().unwrap();
    match transaction.commit() {
        Err(error) => assert_eq!(error, noncanonical_batch_error()),
        Ok(_) => panic!("substituted COMMIT must not commit the receiver batch"),
    }
    assert_eq!(
        dispatcher.send_parts(0x8000_0044, &[], deadline()),
        Err(AcceptedControlError::Control(ControlError::Poisoned))
    );
    assert!(dispatcher.active_lease_facts_for_test().is_empty());
    super::set_vnext_drop_observer_for_test(None);
    assert_exact_import_cleanup(&observer.lock().unwrap(), 4);
}
