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

fn canonical_zero_rights_record(
    nonce: &[u8; 32],
    receive_port: MachPort,
    audit: AuditToken,
    payload: &[u8],
) -> Vec<u64> {
    let unrounded = size_of::<MachMsgHeader>() + size_of::<VnextEnvelope>() + payload.len();
    let message_size = round_message(unrounded).unwrap();
    let total = message_size + size_of::<AuditTrailer>();
    let mut storage = vec![0_u64; total.div_ceil(size_of::<u64>())];
    let bytes = slice_as_bytes_mut(&mut storage);
    write_value(
        bytes,
        0,
        MachMsgHeader {
            bits: u32::from(MACH_MSG_TYPE_PORT_SEND) << 8,
            size: message_size as u32,
            remote_port: MACH_PORT_NULL,
            local_port: receive_port,
            voucher_port: MACH_PORT_NULL,
            id: VNEXT_MESSAGE_ID,
        },
    );
    write_value(
        bytes,
        size_of::<MachMsgHeader>(),
        VnextEnvelope {
            magic: VNEXT_MESSAGE_MAGIC,
            nonce: *nonce,
            kind: 1,
            payload_len: payload.len() as u32,
        },
    );
    let payload_offset = size_of::<MachMsgHeader>() + size_of::<VnextEnvelope>();
    bytes[payload_offset..payload_offset + payload.len()].copy_from_slice(payload);
    write_value(
        bytes,
        message_size,
        AuditTrailer {
            trailer_type: 0,
            trailer_size: size_of::<AuditTrailer>() as u32,
            sequence: 0,
            sender_security: [0; 2],
            audit,
        },
    );
    storage
}

#[test]
fn parse_vnext_message_enforces_pinned_audit_token_continuity() {
    let nonce = [7_u8; 32];
    let receive_port: MachPort = 0x1234;
    let pid = 43_210_u32;
    let sender = AuditToken {
        values: [1, 501, 20, 501, 20, pid, 9, 4],
    };

    // A record whose kernel trailer matches the pinned token parses.
    let mut storage = canonical_zero_rights_record(&nonce, receive_port, sender, b"hello");
    let record = parse_vnext_message(
        slice_as_bytes_mut(&mut storage),
        receive_port,
        &nonce,
        pid,
        Some(&sender),
        64,
    )
    .unwrap();
    assert_eq!(record.bytes, b"hello");
    assert!(record.audit == sender);

    // A changed PID version (helper exec) keeps the PID but must reject.
    let mut execed = sender;
    execed.values[7] += 1;
    let mut storage = canonical_zero_rights_record(&nonce, receive_port, execed, b"hello");
    assert!(matches!(
        parse_vnext_message(
            slice_as_bytes_mut(&mut storage),
            receive_port,
            &nonce,
            pid,
            Some(&sender),
            64,
        ),
        Err(SessionTransportError::IdentityMismatch)
    ));

    // Any other credential change in the token must also reject.
    let mut setuid = sender;
    setuid.values[1] = 0;
    let mut storage = canonical_zero_rights_record(&nonce, receive_port, setuid, b"hello");
    assert!(matches!(
        parse_vnext_message(
            slice_as_bytes_mut(&mut storage),
            receive_port,
            &nonce,
            pid,
            Some(&sender),
            64,
        ),
        Err(SessionTransportError::IdentityMismatch)
    ));

    // Without a pinned token the exact audit PID check still applies.
    let mut storage = canonical_zero_rights_record(&nonce, receive_port, sender, b"hello");
    assert!(
        parse_vnext_message(
            slice_as_bytes_mut(&mut storage),
            receive_port,
            &nonce,
            pid,
            None,
            64,
        )
        .is_ok()
    );
    let mut storage = canonical_zero_rights_record(&nonce, receive_port, sender, b"hello");
    assert!(matches!(
        parse_vnext_message(
            slice_as_bytes_mut(&mut storage),
            receive_port,
            &nonce,
            pid + 1,
            None,
            64,
        ),
        Err(SessionTransportError::IdentityMismatch)
    ));
}
