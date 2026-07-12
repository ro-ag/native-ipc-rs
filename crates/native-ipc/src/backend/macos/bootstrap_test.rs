use super::*;
use native_ipc_core::layout::{
    AcknowledgementRouteSpec, Endpoint, LayoutLimits, RegionSetLayout, RegionSpec, RoleId,
    ValidationExpectations,
};
use std::os::unix::ffi::OsStrExt;
use std::time::{Duration, Instant};

fn native(
    role: RoleId,
    writer: Endpoint,
    logical_len: usize,
    mapped_len: usize,
) -> NativeRegionSpec {
    NativeRegionSpec::new(
        role.get().into(),
        [role.get() as u8; 16],
        writer as u32,
        logical_len,
        mapped_len,
    )
    .unwrap()
}

fn topology() -> (RegionSetLayout, RoleId, RoleId) {
    let producer = RoleId::new(1).unwrap();
    let peer = RoleId::new(2).unwrap();
    let specs = [
        RegionSpec {
            role: producer,
            writer: Endpoint::Initiator,
            slot_count: 1,
            payload_bytes: 32,
            acknowledgement_count: 1,
        },
        RegionSpec {
            role: peer,
            writer: Endpoint::Responder,
            slot_count: 1,
            payload_bytes: 32,
            acknowledgement_count: 1,
        },
    ];
    let routes = [
        AcknowledgementRouteSpec {
            owner: peer,
            target: producer,
            slot_index: 0,
            cell_index: 0,
        },
        AcknowledgementRouteSpec {
            owner: producer,
            target: peer,
            slot_index: 0,
            cell_index: 0,
        },
    ];
    let topology = RegionSetLayout::calculate(
        [6; 32],
        17,
        &specs,
        &routes,
        LayoutLimits {
            maximum_mapping_size: 1 << 20,
            maximum_slot_count: 2,
            maximum_acknowledgement_count: 2,
            maximum_payload_bytes: 64,
        },
    )
    .unwrap();
    (topology, producer, peer)
}

#[test]
fn spawned_helper_uses_private_port_and_audit_pid() {
    let executable = std::env::current_exe().unwrap();
    let path = CString::new(executable.as_os_str().as_bytes()).unwrap();
    let arguments = [
        CString::new("--exact").unwrap(),
        CString::new("backend::macos::bootstrap::tests::spawned_helper_entry").unwrap(),
        CString::new("--ignored").unwrap(),
        CString::new("--nocapture").unwrap(),
    ];
    let helper = SpawnedHelper::spawn(&path, &arguments).unwrap();
    let expected_pid = helper.pid();
    let channel = helper.authenticate().unwrap();
    assert_eq!(channel.peer_pid(), expected_pid);
}

#[test]
#[ignore = "spawned only by the private Mach bootstrap integration test"]
fn spawned_helper_entry() {
    let _channel = ChildChannel::connect_from_environment().unwrap();
    std::thread::sleep(Duration::from_secs(30));
}

#[test]
fn spawned_helper_imports_memory_entry_and_reads_payload() {
    let (topology, producer, peer) = topology();
    let layout = topology.region(producer).unwrap();
    let mut owner = super::super::QuiescentRegion::new(layout.total_size() as usize).unwrap();
    layout.encode_into(owner.as_bytes_mut()).unwrap();
    let expected = ValidationExpectations {
        schema_id: [6; 32],
        generation: 17,
        role: producer,
        writer: Endpoint::Initiator,
        maximum_mapping_size: owner.len() as u64,
    };
    let peer_layout = topology.region(peer).unwrap();
    let mut peer_owner =
        super::super::QuiescentRegion::new(peer_layout.total_size() as usize).unwrap();
    peer_layout.encode_into(peer_owner.as_bytes_mut()).unwrap();
    let peer_expected = ValidationExpectations {
        schema_id: [6; 32],
        generation: 17,
        role: peer,
        writer: Endpoint::Responder,
        maximum_mapping_size: peer_owner.len() as u64,
    };
    let executable = std::env::current_exe().unwrap();
    let path = CString::new(executable.as_os_str().as_bytes()).unwrap();
    let arguments = [
        CString::new("--exact").unwrap(),
        CString::new("backend::macos::bootstrap::tests::memory_entry_helper").unwrap(),
        CString::new("--ignored").unwrap(),
        CString::new("--nocapture").unwrap(),
    ];
    let helper = SpawnedHelper::spawn(&path, &arguments).unwrap();
    let mut channel = helper.authenticate().unwrap();
    let native_writer = native(
        producer,
        expected.writer,
        layout.total_size() as usize,
        owner.len(),
    );
    let native_peer = native(
        peer,
        peer_expected.writer,
        peer_layout.total_size() as usize,
        peer_owner.len(),
    );
    let writer = owner
        .transfer_local_writer(native_writer, expected, topology.clone(), &mut channel)
        .unwrap();
    let peer_reader = peer_owner
        .transfer_remote_writer(native_peer, peer_expected, topology, &mut channel)
        .unwrap();
    let before_commit = Instant::now();
    let (mut writer, peer_reader) = channel.commit_transfers(writer, peer_reader).unwrap();
    assert!(before_commit.elapsed() >= Duration::from_millis(90));
    writer.publish(0, 1, None, b"cross-process-mach").unwrap();
    for _ in 0..10_000 {
        if let Ok(payload) = peer_reader.copy_payload(0, 1) {
            assert_eq!(payload, b"child-mach-writer");
            channel.wait().unwrap();
            return;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    panic!("child never published payload");
}

fn spawn_memory_helper() -> ParentChannel {
    let executable = std::env::current_exe().unwrap();
    let path = CString::new(executable.as_os_str().as_bytes()).unwrap();
    let arguments = [
        CString::new("--exact").unwrap(),
        CString::new("backend::macos::bootstrap::tests::memory_entry_helper").unwrap(),
        CString::new("--ignored").unwrap(),
        CString::new("--nocapture").unwrap(),
    ];
    SpawnedHelper::spawn(&path, &arguments)
        .unwrap()
        .authenticate()
        .unwrap()
}

fn pending_pair(
    channel: &mut ParentChannel,
) -> (
    super::super::PendingTransferredWriter,
    super::super::PendingTransferredReader,
) {
    let (topology, producer, peer) = topology();
    let layout = topology.region(producer).unwrap();
    let mut owner = super::super::QuiescentRegion::new(layout.total_size() as usize).unwrap();
    layout.encode_into(owner.as_bytes_mut()).unwrap();
    let expected = ValidationExpectations {
        schema_id: [6; 32],
        generation: 17,
        role: producer,
        writer: Endpoint::Initiator,
        maximum_mapping_size: owner.len() as u64,
    };
    let peer_layout = topology.region(peer).unwrap();
    let mut peer_owner =
        super::super::QuiescentRegion::new(peer_layout.total_size() as usize).unwrap();
    peer_layout.encode_into(peer_owner.as_bytes_mut()).unwrap();
    let peer_expected = ValidationExpectations {
        schema_id: [6; 32],
        generation: 17,
        role: peer,
        writer: Endpoint::Responder,
        maximum_mapping_size: peer_owner.len() as u64,
    };
    let native_writer = native(
        producer,
        expected.writer,
        layout.total_size() as usize,
        owner.len(),
    );
    let native_peer = native(
        peer,
        peer_expected.writer,
        peer_layout.total_size() as usize,
        peer_owner.len(),
    );
    let writer = owner
        .transfer_local_writer(native_writer, expected, topology.clone(), channel)
        .unwrap();
    let reader = peer_owner
        .transfer_remote_writer(native_peer, peer_expected, topology, channel)
        .unwrap();
    (writer, reader)
}

#[test]
fn foreign_pending_values_fail_closed_before_commit() {
    let mut first = spawn_memory_helper();
    let (first_writer, first_reader) = pending_pair(&mut first);

    let mut second = spawn_memory_helper();
    let (second_writer, second_reader) = pending_pair(&mut second);

    // Session two must reject session one's pending values before READY/COMMIT.
    assert!(matches!(
        second.commit_transfers(first_writer, first_reader),
        Err(super::super::MacBindingError::ForeignPending)
    ));

    // The mismatched transaction is poisoned: even the channel's own exact
    // pending values can no longer commit.
    assert!(
        second
            .commit_transfers(second_writer, second_reader)
            .is_err()
    );
}

#[test]
#[ignore = "spawned only by the memory-entry integration test"]
fn memory_entry_helper() {
    let (topology, producer, peer) = topology();
    let layout = topology.region(producer).unwrap();
    let page = super::super::page_size().unwrap();
    let len = super::super::page_align(layout.total_size() as usize, page).unwrap();
    let expected = ValidationExpectations {
        schema_id: [6; 32],
        generation: 17,
        role: producer,
        writer: Endpoint::Initiator,
        maximum_mapping_size: len as u64,
    };
    let peer_layout = topology.region(peer).unwrap();
    let peer_len = super::super::page_align(peer_layout.total_size() as usize, page).unwrap();
    let peer_expected = ValidationExpectations {
        schema_id: [6; 32],
        generation: 17,
        role: peer,
        writer: Endpoint::Responder,
        maximum_mapping_size: peer_len as u64,
    };
    let mut channel = ChildChannel::connect_from_environment().unwrap();
    std::thread::sleep(Duration::from_millis(50));
    let native_writer = native(producer, expected.writer, layout.total_size() as usize, len);
    let native_peer = native(
        peer,
        peer_expected.writer,
        peer_layout.total_size() as usize,
        peer_len,
    );
    let reader = channel
        .receive_reader(len, native_writer, expected, topology.clone())
        .unwrap();
    let peer_writer = channel
        .receive_writer(peer_len, native_peer, peer_expected, topology)
        .unwrap();
    let (reader, mut peer_writer) = channel.commit_imports(reader, peer_writer).unwrap();
    for _ in 0..10_000 {
        if let Ok(payload) = reader.copy_payload(0, 1) {
            assert_eq!(payload, b"cross-process-mach");
            peer_writer
                .publish(0, 1, None, b"child-mach-writer")
                .unwrap();
            return;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    panic!("parent never published payload");
}
