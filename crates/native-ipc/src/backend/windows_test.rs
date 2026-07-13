use super::*;
use native_ipc_core::layout::{
    AcknowledgementRouteSpec, Endpoint, LayoutLimits, RegionSpec, RoleId,
};
use std::time::Duration;
use std::{ffi::OsStr, process::Command};
use windows_sys::Win32::System::Memory::{PAGE_EXECUTE_READWRITE, VirtualProtect};

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
        [7; 32],
        23,
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

fn expected(topology: &RegionSetLayout, role: RoleId, len: usize) -> ValidationExpectations {
    let region = topology.region(role).unwrap();
    ValidationExpectations {
        schema_id: [7; 32],
        generation: 23,
        role,
        writer: region.writer(),
        maximum_mapping_size: len as u64,
    }
}

fn native(
    topology: &RegionSetLayout,
    role: RoleId,
    logical_len: usize,
    mapped_len: usize,
) -> NativeRegionSpec {
    NativeRegionSpec::new(
        role.get().into(),
        [role.get() as u8; 16],
        topology.region(role).unwrap().writer() as u32,
        logical_len,
        mapped_len,
    )
    .unwrap()
}

#[test]
fn nonce_is_nonzero_and_job_is_constructible() {
    assert_ne!(session_nonce().unwrap(), [0; 32]);
    let _job = ChildJob::new().unwrap();
}

#[test]
fn named_pipe_security_is_one_noninheritable_logon_sid_ace() {
    let security = PipeSecurity::for_current_logon().unwrap();
    let acl = unsafe { &*security._acl.as_ptr().cast::<ACL>() };
    assert_eq!(acl.AceCount, 1);
    assert_eq!(security.attributes.bInheritHandle, 0);
    let ace = unsafe {
        &*security
            ._acl
            .as_ptr()
            .cast::<u8>()
            .add(size_of::<ACL>())
            .cast::<ACCESS_ALLOWED_ACE>()
    };
    assert_eq!(ace.Mask, FILE_GENERIC_READ | FILE_GENERIC_WRITE);
}

fn authenticated_test_pipe(name: &[u16]) -> OwnedHandle {
    let security = PipeSecurity::for_current_logon().unwrap();
    let pipe = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            4096,
            4096,
            WAIT_MS,
            &raw const security.attributes,
        )
    };
    OwnedHandle::new(pipe).unwrap()
}

fn spawn_wrong_pipe_client(name: &OsStr) -> std::process::Child {
    let executable = std::env::current_exe().unwrap();
    Command::new(executable)
        .args([
            "--exact",
            "backend::windows::tests::wrong_pipe_client_entry",
            "--ignored",
            "--nocapture",
        ])
        .env("NATIVE_IPC_WRONG_PIPE", name)
        .spawn()
        .unwrap()
}

#[test]
fn wrong_local_client_is_disconnected_before_the_expected_pid_connects() {
    let nonce = session_nonce().unwrap();
    let name = OsString::from(format!(r"\\.\pipe\native-ipc-wrong-client-{}", hex(&nonce)));
    let wide = wide_null(&name);
    let pipe = authenticated_test_pipe(&wide);
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut wrong = spawn_wrong_pipe_client(&name);
    connect_pipe_until(pipe.0, unsafe { GetCurrentProcess() }, deadline).unwrap();

    let real_name = wide.clone();
    let real = std::thread::spawn(move || {
        let client = open_pipe_until(real_name.as_ptr(), deadline).unwrap();
        std::thread::sleep(Duration::from_millis(100));
        drop(client);
    });
    connect_authenticated_pipe(
        pipe.0,
        unsafe { GetCurrentProcess() },
        unsafe { GetCurrentProcessId() },
        deadline,
    )
    .unwrap();
    real.join().unwrap();
    assert!(wrong.wait().unwrap().success());
}

#[test]
fn continuous_wrong_client_cannot_replace_the_accept_deadline() {
    let nonce = session_nonce().unwrap();
    let name = OsString::from(format!(
        r"\\.\pipe\native-ipc-wrong-deadline-{}",
        hex(&nonce)
    ));
    let wide = wide_null(&name);
    let pipe = authenticated_test_pipe(&wide);
    let initial_deadline = Instant::now() + Duration::from_secs(2);
    let mut wrong = spawn_wrong_pipe_client(&name);
    connect_pipe_until(pipe.0, unsafe { GetCurrentProcess() }, initial_deadline).unwrap();
    let result = connect_authenticated_pipe(
        pipe.0,
        unsafe { GetCurrentProcess() },
        unsafe { GetCurrentProcessId() },
        Instant::now() + Duration::from_millis(20),
    );
    assert!(matches!(result, Err(WindowsError::TimedOut(_))));
    assert!(wrong.wait().unwrap().success());
}

#[test]
fn unnamed_section_is_page_rounded_and_zeroed() {
    let region = QuiescentRegion::new(37).unwrap();
    assert!(region.len() >= 37);
    assert!(region.as_bytes().iter().all(|byte| *byte == 0));
    let mut prior = 0;
    // SAFETY: the complete live view and protection output are valid.
    assert_eq!(
        unsafe {
            VirtualProtect(
                region.view.base.as_ptr().cast(),
                region.len(),
                PAGE_EXECUTE_READWRITE,
                &mut prior,
            )
        },
        0
    );
}

#[test]
fn read_only_duplicate_rejects_writable_mapping() {
    let region = QuiescentRegion::new(4096).unwrap();
    let duplicate = duplicate_to(
        region.section.0,
        unsafe { GetCurrentProcess() },
        FILE_MAP_READ,
    )
    .unwrap();
    let duplicate = OwnedHandle::new(duplicate.0 as HANDLE).unwrap();
    // SAFETY: exact read-only section handle is live; the denied result is not owned.
    let denied = unsafe { MapViewOfFile(duplicate.0, FILE_MAP_WRITE, 0, 0, region.len()) };
    assert!(denied.Value.is_null());
}

#[test]
fn spawned_helper_is_pid_authenticated_and_job_owned() {
    let (topology, producer, peer) = topology();
    let producer_layout = topology.region(producer).unwrap();
    let mut producer_region = QuiescentRegion::new(producer_layout.total_size() as usize).unwrap();
    producer_layout
        .encode_into(producer_region.as_bytes_mut())
        .unwrap();
    let producer_expected = expected(&topology, producer, producer_region.len());
    let producer_native = native(
        &topology,
        producer,
        producer_layout.total_size() as usize,
        producer_region.len(),
    );
    let prepared_producer = producer_region
        .prepare_local_writer(producer_native, producer_expected, topology.clone())
        .unwrap();
    let peer_layout = topology.region(peer).unwrap();
    let mut peer_region = QuiescentRegion::new(peer_layout.total_size() as usize).unwrap();
    peer_layout.encode_into(peer_region.as_bytes_mut()).unwrap();
    let peer_expected = expected(&topology, peer, peer_region.len());
    let peer_native = native(
        &topology,
        peer,
        peer_layout.total_size() as usize,
        peer_region.len(),
    );
    let prepared_peer = peer_region
        .prepare_remote_writer(peer_native, peer_expected, topology.clone())
        .unwrap();
    let executable = std::env::current_exe().unwrap();
    let arguments = [
        OsString::from("--exact"),
        OsString::from("backend::windows::tests::spawned_helper_entry"),
        OsString::from("--ignored"),
        OsString::from("--nocapture"),
    ];
    let mut child = ChildSession::spawn(&executable, &arguments).unwrap();
    assert_ne!(child.pid(), unsafe { GetCurrentProcessId() });
    let (mut writer, reader) = child
        .commit_transfers(prepared_producer, prepared_peer)
        .unwrap();
    writer
        .publish(0, 1, None, b"cross-process-windows")
        .unwrap();
    for _ in 0..10_000 {
        if let Ok(payload) = reader.copy_payload(0, 1) {
            assert_eq!(payload, b"child-windows-writer");
            child.wait().unwrap();
            return;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    panic!("child never published payload");
}

#[test]
fn helper_exit_before_connect_is_bounded() {
    let executable = std::env::current_exe().unwrap();
    let arguments = [
        OsString::from("--exact"),
        OsString::from("backend::windows::tests::exit_before_connect_entry"),
        OsString::from("--ignored"),
    ];
    let result = ChildSession::spawn(&executable, &arguments);
    assert!(matches!(
        result,
        Err(WindowsError::ChildExit(0) | WindowsError::Os { .. })
    ));
}

#[test]
fn helper_stall_before_auth_is_bounded() {
    let executable = std::env::current_exe().unwrap();
    let arguments = [
        OsString::from("--exact"),
        OsString::from("backend::windows::tests::stall_before_auth_entry"),
        OsString::from("--ignored"),
    ];
    let result = ChildSession::spawn(&executable, &arguments);
    assert!(matches!(result, Err(WindowsError::TimedOut("pipe read"))));
}

#[test]
#[ignore = "spawned only by wrong-client accept-loop tests"]
fn wrong_pipe_client_entry() {
    let name = std::env::var_os("NATIVE_IPC_WRONG_PIPE").unwrap();
    let wide = wide_null(&name);
    let deadline = Instant::now() + Duration::from_secs(2);
    let pipe = open_pipe_until(wide.as_ptr(), deadline).unwrap();
    std::thread::sleep(Duration::from_millis(100));
    drop(pipe);
}

#[test]
#[ignore = "spawned only by the exact lifecycle test"]
fn spawned_helper_entry() {
    let (topology, producer, peer) = topology();
    let mut channel = connect_spawned_helper().unwrap();
    assert_ne!(channel.parent_pid(), unsafe { GetCurrentProcessId() });
    let (reader_handle, reader_len, writer_handle, writer_len) =
        channel.receive_capabilities().unwrap();
    // SAFETY: exact handles arrived from authenticated parent on private pipe.
    let reader = unsafe {
        channel
            .import_reader(
                reader_handle.0,
                reader_len,
                native(
                    &topology,
                    producer,
                    topology.region(producer).unwrap().total_size() as usize,
                    reader_len,
                ),
                expected(&topology, producer, reader_len),
                topology.clone(),
            )
            .unwrap()
    };
    // SAFETY: manifest designates this exact handle as the sole writer.
    let writer = unsafe {
        channel
            .import_writer(
                writer_handle.0,
                writer_len,
                native(
                    &topology,
                    peer,
                    topology.region(peer).unwrap().total_size() as usize,
                    writer_len,
                ),
                expected(&topology, peer, writer_len),
                topology,
            )
            .unwrap()
    };
    let (reader, mut writer) = channel.commit_imports(reader, writer).unwrap();
    for _ in 0..10_000 {
        if let Ok(payload) = reader.copy_payload(0, 1) {
            assert_eq!(payload, b"cross-process-windows");
            writer.publish(0, 1, None, b"child-windows-writer").unwrap();
            return;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    panic!("parent never published payload");
}

fn detached_channel() -> ChildChannel {
    let nonce = session_nonce().unwrap();
    let name = format!(r"\\.\pipe\native-ipc-test-{}", hex(&nonce));
    let pipe_name = wide_null(OsStr::new(&name));
    // SAFETY: terminated unique name; null security creates a private instance.
    let pipe = unsafe {
        CreateNamedPipeW(
            pipe_name.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            4096,
            4096,
            WAIT_MS,
            std::ptr::null(),
        )
    };
    ChildChannel {
        pipe: OwnedHandle::new(pipe).unwrap(),
        parent_pid: unsafe { GetCurrentProcessId() },
        nonce,
        channel_id: mint_channel_id(),
        next_transfer_id: 1,
        pending_transcript: None,
        poisoned: false,
    }
}

#[test]
fn foreign_pending_imports_fail_closed_before_ready() {
    let (topology, producer, peer) = topology();
    let producer_layout = topology.region(producer).unwrap();
    let mut producer_region = QuiescentRegion::new(producer_layout.total_size() as usize).unwrap();
    producer_layout
        .encode_into(producer_region.as_bytes_mut())
        .unwrap();
    let reader_len = producer_region.len();
    let reader_expected = expected(&topology, producer, reader_len);
    let reader_native = native(
        &topology,
        producer,
        producer_layout.total_size() as usize,
        reader_len,
    );
    let reader_dup = duplicate_to(
        producer_region.section.0,
        unsafe { GetCurrentProcess() },
        FILE_MAP_READ,
    )
    .unwrap();

    let peer_layout = topology.region(peer).unwrap();
    let mut peer_region = QuiescentRegion::new(peer_layout.total_size() as usize).unwrap();
    peer_layout.encode_into(peer_region.as_bytes_mut()).unwrap();
    let writer_len = peer_region.len();
    let writer_expected = expected(&topology, peer, writer_len);
    let writer_native = native(
        &topology,
        peer,
        peer_layout.total_size() as usize,
        writer_len,
    );
    let writer_dup = duplicate_to(
        peer_region.section.0,
        unsafe { GetCurrentProcess() },
        FILE_MAP_WRITE,
    )
    .unwrap();

    let first = detached_channel();
    let mut second = detached_channel();
    // SAFETY: both duplicated handles are locally created, owned, and unused elsewhere.
    let reader = unsafe {
        first
            .import_reader(
                reader_dup.0,
                reader_len,
                reader_native,
                reader_expected,
                topology.clone(),
            )
            .unwrap()
    };
    // SAFETY: the writable duplicate is the sole writer handle for its section.
    let writer = unsafe {
        first
            .import_writer(
                writer_dup.0,
                writer_len,
                writer_native,
                writer_expected,
                topology,
            )
            .unwrap()
    };

    // Pending imports from the first channel must fail closed on the second
    // channel before any READY frame is written.
    assert!(matches!(
        second.commit_imports(reader, writer),
        Err(WindowsError::ForeignPending)
    ));
    // The mismatched transaction stays poisoned for later operations.
    assert!(matches!(
        second.receive_capabilities(),
        Err(WindowsError::InvalidBootstrap)
    ));
}

#[test]
#[ignore = "spawned only by the exit-before-connect lifecycle test"]
fn exit_before_connect_entry() {}

#[test]
#[ignore = "spawned only by the stalled-auth lifecycle test"]
fn stall_before_auth_entry() {
    let name = wide_null(&std::env::var_os(PIPE_ENV).unwrap());
    // SAFETY: terminated private pipe name and existing-only open are valid.
    let pipe = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            std::ptr::null(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        )
    };
    let _pipe = OwnedHandle::new(pipe).unwrap();
    std::thread::sleep(Duration::from_secs(5));
}
