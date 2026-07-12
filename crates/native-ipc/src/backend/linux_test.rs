use super::*;
use native_ipc_core::layout::{
    AcknowledgementRouteSpec, Endpoint, LayoutError, LayoutLimits, RegionSpec, RoleId,
};

fn send_fragmented_with_fds(
    stream: &UnixStream,
    frame: &[u8; CONTROL_FRAME_LEN],
    fds: &[RawFd],
    first_bytes: usize,
) {
    send_chunk_with_fds(stream, &frame[..first_bytes], fds);
    let mut stream = stream;
    stream.write_all(&frame[first_bytes..]).unwrap();
}

fn send_chunk_with_fds(stream: &UnixStream, bytes: &[u8], fds: &[RawFd]) {
    let mut prefix = bytes.to_vec();
    let mut iovec = libc::iovec {
        iov_base: prefix.as_mut_ptr().cast(),
        iov_len: prefix.len(),
    };
    let control_len = unsafe { libc::CMSG_SPACE(std::mem::size_of_val(fds) as u32) } as usize;
    let mut control = vec![0_u8; control_len];
    let mut message: libc::msghdr = unsafe { zeroed() };
    message.msg_iov = &mut iovec;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = control.len();
    // SAFETY: the control allocation exactly fits the supplied descriptor slice.
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of_val(fds) as u32) as usize;
        std::ptr::copy_nonoverlapping(
            fds.as_ptr(),
            libc::CMSG_DATA(header).cast::<RawFd>(),
            fds.len(),
        );
        assert_eq!(
            libc::sendmsg(stream.as_raw_fd(), &message, libc::MSG_NOSIGNAL),
            bytes.len() as isize
        );
    }
}

fn open_fd_count() -> usize {
    std::fs::read_dir("/proc/self/fd").unwrap().count()
}

#[test]
fn backend_reports_available() {
    assert_eq!(status(), BackendStatus::Available);
}

#[test]
fn peer_credentials_are_kernel_derived() {
    let (left, right) = UnixStream::pair().unwrap();
    let expected = peer_credentials(&right).unwrap();
    let channel = AuthenticatedChannel::new(left, expected, [7; 32]).unwrap();
    assert_eq!(channel.peer(), expected);
}

#[test]
fn invalid_sizes_capabilities_and_peer_identity_fail_exactly() {
    assert!(matches!(
        QuiescentRegion::new(0),
        Err(LinuxError::InvalidSize(0))
    ));
    assert!(matches!(
        QuiescentRegion::new(usize::MAX),
        Err(LinuxError::InvalidSize(usize::MAX))
    ));

    let unsealed = QuiescentRegion::new(1).unwrap();
    assert!(matches!(
        validate_fd(unsealed.fd.as_raw_fd(), unsealed.len()),
        Err(LinuxError::InvalidCapability)
    ));

    let (left, right) = UnixStream::pair().unwrap();
    let actual = peer_credentials(&right).unwrap();
    let wrong = PeerCredentials {
        pid: actual.pid.wrapping_add(1),
        ..actual
    };
    assert!(matches!(
        AuthenticatedChannel::new(left, wrong, [9; 32]),
        Err(LinuxError::WrongPeer)
    ));

    let (left, right) = UnixStream::pair().unwrap();
    let actual = peer_credentials(&right).unwrap();
    assert!(matches!(
        AuthenticatedChannel::new(left, actual, [0; 32]),
        Err(LinuxError::WrongPeer)
    ));
}

#[test]
fn fragmented_stream_frame_preserves_ancillary_ownership() {
    let expected = ValidationExpectations {
        schema_id: [3; 32],
        generation: 9,
        role: RoleId::new(7).unwrap(),
        writer: Endpoint::Initiator,
        maximum_mapping_size: 4096,
    };
    let native = NativeRegionSpec::new(
        expected.role.get().into(),
        [1; 16],
        expected.writer as u32,
        4096,
        4096,
    )
    .unwrap();
    let entry = ManifestEntry::from_native(native, PeerAccess::ReadOnly);
    let nonce = [4; 32];
    let manifest = TransferManifest::new(nonce, 1, 2, 1, vec![entry]).unwrap();
    let frame = manifest.encode(CAPABILITY_MAGIC);
    let file = std::fs::File::open("/dev/null").unwrap();
    let (sender, receiver) = UnixStream::pair().unwrap();
    let received = std::thread::scope(|scope| {
        let task = scope.spawn(|| receive_fd(&receiver, &manifest));
        send_fragmented_with_fds(&sender, &frame, &[file.as_raw_fd()], 1);
        task.join().unwrap().unwrap()
    });
    assert!(received.as_raw_fd() >= 0);
}

#[test]
#[ignore = "spawned in an isolated process by descriptor_cleanup_is_zero_growth"]
fn malformed_extra_descriptor_frame_has_zero_fd_growth() {
    let before = open_fd_count();
    {
        let expected = ValidationExpectations {
            schema_id: [5; 32],
            generation: 11,
            role: RoleId::new(8).unwrap(),
            writer: Endpoint::Responder,
            maximum_mapping_size: 4096,
        };
        let native = NativeRegionSpec::new(
            expected.role.get().into(),
            [2; 16],
            expected.writer as u32,
            4096,
            4096,
        )
        .unwrap();
        let entry = ManifestEntry::from_native(native, PeerAccess::ReadOnly);
        let nonce = [6; 32];
        let manifest = TransferManifest::new(nonce, 1, 2, 1, vec![entry]).unwrap();
        let frame = manifest.encode(CAPABILITY_MAGIC);
        let first = std::fs::File::open("/dev/null").unwrap();
        let second = std::fs::File::open("/dev/null").unwrap();
        let (sender, receiver) = UnixStream::pair().unwrap();
        std::thread::scope(|scope| {
            let task = scope.spawn(|| receive_fd(&receiver, &manifest));
            send_fragmented_with_fds(&sender, &frame, &[first.as_raw_fd(), second.as_raw_fd()], 7);
            assert!(matches!(
                task.join().unwrap(),
                Err(LinuxError::InvalidAncillaryData)
            ));
        });
    }
    assert_eq!(open_fd_count(), before);
}

#[test]
#[ignore = "spawned in an isolated process by descriptor_cleanup_is_zero_growth"]
fn ancillary_on_later_stream_fragment_is_adopted_and_rejected() {
    let before = open_fd_count();
    {
        let expected = ValidationExpectations {
            schema_id: [7; 32],
            generation: 13,
            role: RoleId::new(9).unwrap(),
            writer: Endpoint::Initiator,
            maximum_mapping_size: 4096,
        };
        let native = NativeRegionSpec::new(
            expected.role.get().into(),
            [3; 16],
            expected.writer as u32,
            4096,
            4096,
        )
        .unwrap();
        let entry = ManifestEntry::from_native(native, PeerAccess::ReadOnly);
        let manifest = TransferManifest::new([8; 32], 1, 2, 1, vec![entry]).unwrap();
        let frame = manifest.encode(CAPABILITY_MAGIC);
        let first = std::fs::File::open("/dev/null").unwrap();
        let second = std::fs::File::open("/dev/null").unwrap();
        let (sender, receiver) = UnixStream::pair().unwrap();
        std::thread::scope(|scope| {
            let task = scope.spawn(|| receive_fd(&receiver, &manifest));
            send_chunk_with_fds(&sender, &frame[..7], &[first.as_raw_fd()]);
            send_chunk_with_fds(&sender, &frame[7..], &[second.as_raw_fd()]);
            assert!(matches!(
                task.join().unwrap(),
                Err(LinuxError::InvalidAncillaryData)
            ));
        });
    }
    assert_eq!(open_fd_count(), before);
}

#[test]
fn descriptor_cleanup_is_zero_growth() {
    let executable = std::env::current_exe().unwrap();
    for test in [
        "backend::linux::tests::malformed_extra_descriptor_frame_has_zero_fd_growth",
        "backend::linux::tests::ancillary_on_later_stream_fragment_is_adopted_and_rejected",
    ] {
        let status = Command::new(&executable)
            .args(["--exact", test, "--ignored", "--nocapture"])
            .status()
            .unwrap();
        assert!(status.success(), "isolated descriptor test failed: {test}");
    }
}

#[test]
fn sealed_capability_transfers_and_binds_payload_path() {
    let producer = RoleId::new(1).unwrap();
    let peer = RoleId::new(2).unwrap();
    let specs = [
        RegionSpec {
            role: producer,
            writer: Endpoint::Initiator,
            slot_count: 1,
            payload_bytes: 16,
            acknowledgement_count: 1,
        },
        RegionSpec {
            role: peer,
            writer: Endpoint::Responder,
            slot_count: 1,
            payload_bytes: 16,
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
        [5; 32],
        13,
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
    let layout = topology.region(producer).unwrap();
    let mut owner = QuiescentRegion::new(layout.total_size() as usize).unwrap();
    layout.encode_into(owner.as_bytes_mut()).unwrap();
    let expected = ValidationExpectations {
        schema_id: [5; 32],
        generation: 13,
        role: producer,
        writer: Endpoint::Initiator,
        maximum_mapping_size: owner.len() as u64,
    };
    let native = NativeRegionSpec::new(
        producer.get().into(),
        [7; 16],
        expected.writer as u32,
        owner.logical_len(),
        owner.len(),
    )
    .unwrap();
    let prepared = owner
        .prepare_writer(native, expected, topology.clone())
        .unwrap();
    let transfer_len = prepared.len;
    let capability = &prepared.capability;

    // A sealed exported fd cannot create another writable mapping.
    let denied = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            transfer_len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            capability.fd.as_raw_fd(),
            0,
        )
    };
    assert_eq!(denied, libc::MAP_FAILED);
    assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));

    // Seals also deny descriptor writes and any size change with exact EPERM.
    let byte = 0xff_u8;
    let written =
        unsafe { libc::pwrite(capability.fd.as_raw_fd(), (&raw const byte).cast(), 1, 0) };
    assert_eq!(written, -1);
    assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
    assert_eq!(
        unsafe {
            libc::ftruncate(
                capability.fd.as_raw_fd(),
                transfer_len.saturating_add(4096) as libc::off_t,
            )
        },
        -1
    );
    assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));
    assert_eq!(unsafe { libc::ftruncate(capability.fd.as_raw_fd(), 1) }, -1);
    assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EPERM));

    let (left, right) = UnixStream::pair().unwrap();
    let credentials = peer_credentials(&left).unwrap();
    let mut sender = AuthenticatedChannel::new(left, credentials, [8; 32]).unwrap();
    let mut receiver = AuthenticatedChannel::new(right, credentials, [8; 32]).unwrap();
    std::thread::scope(|scope| {
        let received = scope.spawn(|| {
            let reader = receiver
                .receive_reader(transfer_len, native, expected, topology.clone())
                .unwrap();
            for _ in 0..10_000 {
                if let Ok(payload) = reader.copy_payload(0, 1) {
                    assert_eq!(payload, b"linux");
                    return;
                }
                std::thread::yield_now();
            }
            panic!("reader never observed publication");
        });
        let mut writer = sender.transfer_writer(prepared).unwrap();
        assert_eq!(
            writer.publish(0, 1, None, &[0xaa; 17]).unwrap_err(),
            BindingError::Layout(LayoutError::PayloadOutOfBounds {
                length: 17,
                capacity: 16,
            })
        );
        writer.publish(0, 1, None, b"linux").unwrap();
        received.join().unwrap();
    });
}

// Serializes every test that creates a bootstrap directory so the
// zero-growth assertions cannot observe another test's live session.
static BOOTSTRAP_DIR_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

fn bootstrap_dirs() -> std::collections::BTreeSet<PathBuf> {
    std::fs::read_dir(std::env::temp_dir())
        .unwrap()
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with("native-ipc-"))
        })
        .collect()
}

#[test]
fn bootstrap_directory_is_created_with_private_mode() {
    let _serial = BOOTSTRAP_DIR_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let path = std::env::temp_dir().join(format!("native-ipc-mode-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    create_private_bootstrap_dir(&path).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    std::fs::remove_dir(&path).unwrap();
    assert_eq!(mode, 0o700);
}

#[test]
fn expired_accept_deadline_never_attempts_accept() {
    let expected = PeerCredentials {
        pid: std::process::id(),
        // SAFETY: scalar identity syscalls have no preconditions.
        uid: unsafe { libc::geteuid() },
        // SAFETY: scalar identity syscalls have no preconditions.
        gid: unsafe { libc::getegid() },
    };
    let mut accepts = 0;
    let result = accept_expected_peer(
        || {
            accepts += 1;
            Err(io::Error::from(io::ErrorKind::WouldBlock))
        },
        expected,
        Instant::now(),
    );
    assert!(matches!(result, Err(LinuxError::Bootstrap)));
    assert_eq!(accepts, 0);
}

#[test]
fn continuous_wrong_peer_accepts_cannot_extend_original_deadline() {
    let _serial = BOOTSTRAP_DIR_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let dir =
        std::env::temp_dir().join(format!("native-ipc-wrong-peer-test-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    create_private_bootstrap_dir(&dir).unwrap();
    let socket_path = dir.join("control.sock");
    let listener = UnixListener::bind(&socket_path).unwrap();
    listener.set_nonblocking(true).unwrap();

    let executable = std::env::current_exe().unwrap();
    let mut wrong_peer = Command::new(executable)
        .args([
            "--exact",
            "backend::linux::tests::wrong_peer_pressure_helper_entry",
            "--ignored",
            "--nocapture",
        ])
        .env("NATIVE_IPC_WRONG_PEER_SOCKET", &socket_path)
        .spawn()
        .unwrap();
    let wrong_pid = wrong_peer.id();
    let expected = PeerCredentials {
        pid: std::process::id(),
        // SAFETY: scalar identity syscalls have no preconditions.
        uid: unsafe { libc::geteuid() },
        // SAFETY: scalar identity syscalls have no preconditions.
        gid: unsafe { libc::getegid() },
    };
    let mut accepted = 0_usize;
    let mut attempts_after_deadline = 0_usize;
    let mut observed_pids = std::collections::BTreeSet::new();
    let started = Instant::now();
    let timeout = Duration::from_millis(100);
    let deadline = started + timeout;
    let result = accept_expected_peer(
        || {
            if Instant::now() >= deadline {
                attempts_after_deadline += 1;
            }
            match listener.accept() {
                Ok((stream, _address)) => {
                    accepted += 1;
                    observed_pids.insert(peer_credentials(&stream).unwrap().pid);
                    Ok(stream)
                }
                Err(error) => Err(error),
            }
        },
        expected,
        deadline,
    );

    let elapsed = started.elapsed();
    let _ = wrong_peer.kill();
    wrong_peer.wait().unwrap();
    drop(listener);
    std::fs::remove_dir_all(&dir).unwrap();

    assert!(matches!(result, Err(LinuxError::Bootstrap)));
    assert!(elapsed >= timeout);
    assert!(elapsed < Duration::from_secs(2));
    assert!(
        accepted >= 2,
        "hostile child did not sustain connection pressure"
    );
    assert_eq!(observed_pids, [wrong_pid].into_iter().collect());
    assert_eq!(attempts_after_deadline, 0);
}

#[test]
#[ignore = "spawned only by the wrong-peer deadline integration test"]
fn wrong_peer_pressure_helper_entry() {
    let socket_path = std::env::var_os("NATIVE_IPC_WRONG_PEER_SOCKET").unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut connections = Vec::new();
    while Instant::now() < deadline {
        if let Ok(stream) = UnixStream::connect(&socket_path) {
            connections.push(stream);
            if connections.len() > 64 {
                connections.remove(0);
            }
        }
    }
}

#[test]
fn spawned_helper_is_pid_authenticated_and_owned() {
    let _serial = BOOTSTRAP_DIR_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let executable = std::env::current_exe().unwrap();
    let arguments = [
        OsStr::new("--exact"),
        OsStr::new("backend::linux::tests::spawned_helper_entry"),
        OsStr::new("--ignored"),
        OsStr::new("--nocapture"),
    ];
    let session = ChildSession::spawn(executable.as_os_str(), &arguments).unwrap();
    assert_eq!(session.channel().peer().pid, session.child_id());
    session.terminate().unwrap();
}

#[test]
fn failed_spawn_cleans_bootstrap_resources() {
    let _serial = BOOTSTRAP_DIR_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let before = bootstrap_dirs();
    let Err(error) =
        ChildSession::spawn(OsStr::new("/definitely/not/a/real/native-ipc-helper"), &[])
    else {
        panic!("spawning a nonexistent helper must fail");
    };
    assert!(matches!(error, LinuxError::Bootstrap));
    assert_eq!(bootstrap_dirs(), before);
}

#[test]
fn timed_out_helper_cleans_bootstrap_resources_and_child() {
    let _serial = BOOTSTRAP_DIR_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let before = bootstrap_dirs();
    // The helper never connects, so spawn reaches its accept deadline; the
    // child must be killed and reaped and the directory removed.
    let executable = std::env::current_exe().unwrap();
    let arguments = [
        OsStr::new("--exact"),
        OsStr::new("backend::linux::tests::nonconnecting_helper_entry"),
        OsStr::new("--ignored"),
        OsStr::new("--nocapture"),
    ];
    let Err(error) = ChildSession::spawn(executable.as_os_str(), &arguments) else {
        panic!("a helper that never connects must time out");
    };
    assert!(matches!(error, LinuxError::Bootstrap));
    assert_eq!(bootstrap_dirs(), before);
}

#[test]
#[ignore = "spawned only by the bootstrap-timeout integration test"]
fn nonconnecting_helper_entry() {
    std::thread::sleep(Duration::from_secs(30));
}

#[test]
#[ignore = "spawned only by the owned-child integration test"]
fn spawned_helper_entry() {
    let channel = connect_spawned_helper().unwrap();
    assert_ne!(channel.peer().pid, 0);
    std::thread::sleep(Duration::from_secs(30));
}
