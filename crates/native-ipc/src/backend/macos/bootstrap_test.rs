use super::*;

#[test]
fn process_image_identity_requires_exact_pid_credentials_and_path() {
    let identity = TaskAuditIdentity {
        audit: AuditToken {
            values: [0, 0, 0, 0, 0, 42, 0, 7],
        },
        executable: b"/fixed-launcher".to_vec(),
    };
    assert!(identity.proves_exact_process_image(42, 0, 0, 0, 0, b"/fixed-launcher"));
    assert!(!identity.proves_exact_process_image(41, 0, 0, 0, 0, b"/fixed-launcher"));
    assert!(!identity.proves_exact_process_image(42, 501, 0, 0, 0, b"/fixed-launcher"));
    assert!(!identity.proves_exact_process_image(42, 0, 501, 0, 0, b"/fixed-launcher"));
    assert!(!identity.proves_exact_process_image(42, 0, 0, 20, 0, b"/fixed-launcher"));
    assert!(!identity.proves_exact_process_image(42, 0, 0, 0, 20, b"/fixed-launcher"));
    assert!(!identity.proves_exact_process_image(42, 0, 0, 0, 0, b"/substitute"));
}

#[test]
fn exec_identity_requires_real_and_effective_ids_and_exact_path() {
    let before = TaskAuditIdentity {
        audit: AuditToken {
            values: [0, 0, 0, 0, 0, 42, 0, 7],
        },
        executable: b"/before".to_vec(),
    };
    let partial_drop = TaskAuditIdentity {
        audit: AuditToken {
            values: [0, 501, 20, 0, 0, 42, 0, 8],
        },
        executable: b"/expected".to_vec(),
    };
    assert!(!partial_drop.proves_exec_transition_from(&before, 42, 501, 20, b"/expected"));

    let complete_drop = TaskAuditIdentity {
        audit: AuditToken {
            values: [0, 501, 20, 501, 20, 42, 0, 8],
        },
        executable: b"/expected".to_vec(),
    };
    assert!(complete_drop.proves_exec_transition_from(&before, 42, 501, 20, b"/expected"));
    assert!(!complete_drop.proves_exec_transition_from(&before, 42, 501, 20, b"/substitute"));
}
use native_ipc_core::layout::{
    AcknowledgementRouteSpec, Endpoint, LayoutLimits, RegionSetLayout, RegionSpec, RoleId,
    ValidationExpectations,
};
use std::io::Read;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

unsafe extern "C" {
    fn _exit(status: c_int) -> !;
    fn proc_pidinfo(
        pid: Pid,
        flavor: c_int,
        argument: u64,
        buffer: *mut c_void,
        buffer_size: c_int,
    ) -> c_int;
    fn getppid() -> Pid;
    fn ptrace(request: c_int, pid: Pid, address: *mut c_void, data: c_int) -> c_int;
    fn raise(signal: c_int) -> c_int;
    fn setrlimit(resource: c_int, limit: *const ResourceLimit) -> c_int;
    fn setsid() -> Pid;
    fn task_create_identity_token(task: MachPort, token: *mut MachPort) -> c_int;
    fn task_identity_token_get_task_port(
        token: MachPort,
        flavor: c_int,
        task: *mut MachPort,
    ) -> c_int;
}

const PROCESS_MARKER_ENV: &str = "NATIVE_IPC_MACOS_TEST_PROCESS_MARKER";
const PT_TRACE_ME: c_int = 0;
const PT_KILL: c_int = 8;
const SIGSTOP: c_int = 17;
const WUNTRACED: c_int = 2;
const PROC_PIDTBSDINFO: c_int = 3;
const PROC_PIDUNIQIDENTIFIERINFO: c_int = 17;
const RLIMIT_NPROC: c_int = 7;
const TASK_FLAVOR_NAME: c_int = 3;
const KERN_NOT_FOUND: c_int = 56;

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProcUniqueIdentifierInfo {
    executable_uuid: [u8; 16],
    unique_id: u64,
    parent_unique_id: u64,
    pid_version: i32,
    original_parent_pid_version: i32,
    reserved: [u64; 2],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ProcBsdInfo {
    flags: u32,
    status: u32,
    exit_status: u32,
    pid: u32,
    parent_pid: u32,
    uid: u32,
    gid: u32,
    real_uid: u32,
    real_gid: u32,
    saved_uid: u32,
    saved_gid: u32,
    reserved: u32,
    command: [u8; 16],
    name: [u8; 32],
    open_file_count: u32,
    process_group: u32,
    job_control_count: u32,
    controlling_tty: u32,
    foreground_process_group: u32,
    nice: i32,
    start_seconds: u64,
    start_microseconds: u64,
}

#[repr(C)]
struct ResourceLimit {
    current: u64,
    maximum: u64,
}

fn process_identity(pid: Pid) -> (ProcUniqueIdentifierInfo, ProcBsdInfo) {
    let mut unique = ProcUniqueIdentifierInfo {
        executable_uuid: [0; 16],
        unique_id: 0,
        parent_unique_id: 0,
        pid_version: 0,
        original_parent_pid_version: 0,
        reserved: [0; 2],
    };
    let unique_size = size_of::<ProcUniqueIdentifierInfo>() as c_int;
    // SAFETY: the private flavor writes one complete, correctly aligned
    // `ProcUniqueIdentifierInfo` into the supplied buffer.
    assert_eq!(
        unsafe {
            proc_pidinfo(
                pid,
                PROC_PIDUNIQIDENTIFIERINFO,
                0,
                (&mut unique as *mut ProcUniqueIdentifierInfo).cast(),
                unique_size,
            )
        },
        unique_size
    );

    let mut bsd = ProcBsdInfo {
        flags: 0,
        status: 0,
        exit_status: 0,
        pid: 0,
        parent_pid: 0,
        uid: 0,
        gid: 0,
        real_uid: 0,
        real_gid: 0,
        saved_uid: 0,
        saved_gid: 0,
        reserved: 0,
        command: [0; 16],
        name: [0; 32],
        open_file_count: 0,
        process_group: 0,
        job_control_count: 0,
        controlling_tty: 0,
        foreground_process_group: 0,
        nice: 0,
        start_seconds: 0,
        start_microseconds: 0,
    };
    let bsd_size = size_of::<ProcBsdInfo>() as c_int;
    // SAFETY: PROC_PIDTBSDINFO writes one complete, correctly aligned
    // `ProcBsdInfo` into the supplied buffer.
    assert_eq!(
        unsafe {
            proc_pidinfo(
                pid,
                PROC_PIDTBSDINFO,
                0,
                (&mut bsd as *mut ProcBsdInfo).cast(),
                bsd_size,
            )
        },
        bsd_size
    );
    (unique, bsd)
}

fn wait_for_process_identity_to_disappear(pid: Pid, expected_unique_id: u64) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let mut unique = ProcUniqueIdentifierInfo {
            executable_uuid: [0; 16],
            unique_id: 0,
            parent_unique_id: 0,
            pid_version: 0,
            original_parent_pid_version: 0,
            reserved: [0; 2],
        };
        let unique_size = size_of::<ProcUniqueIdentifierInfo>() as c_int;
        // SAFETY: the optional result is written into valid, aligned storage.
        let result = unsafe {
            proc_pidinfo(
                pid,
                PROC_PIDUNIQIDENTIFIERINFO,
                0,
                (&mut unique as *mut ProcUniqueIdentifierInfo).cast(),
                unique_size,
            )
        };
        if result != unique_size || unique.unique_id != expected_unique_id {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "original process remained present after tracer exit"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

fn wait_for_traced_stop(pid: Pid) -> c_int {
    let mut status = 0;
    // SAFETY: this test process is the tracer/parent and `status` is valid.
    assert_eq!(unsafe { waitpid(pid, &mut status, WUNTRACED) }, pid);
    assert_eq!(status & 0xff, 0x7f, "tracee did not stop: {status:#x}");
    status
}

fn vnext_helper_with_environment(test: &str, environment: &[CString]) -> SpawnedHelper {
    let executable = std::env::current_exe().unwrap();
    let path = CString::new(executable.as_os_str().as_bytes()).unwrap();
    let arguments = [
        CString::new("native-ipc-macos-task-identity-helper").unwrap(),
        CString::new("--exact").unwrap(),
        CString::new(test).unwrap(),
        CString::new("--ignored").unwrap(),
        CString::new("--nocapture").unwrap(),
    ];
    SpawnedHelper::spawn_explicit(&path, &arguments, environment).unwrap()
}

fn vnext_helper(test: &str) -> SpawnedHelper {
    vnext_helper_with_environment(test, &[])
}

fn test_deadline() -> AbsoluteDeadline {
    AbsoluteDeadline::after(Duration::from_secs(10)).unwrap()
}

fn process_marker(label: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!(
        "native-ipc-{label}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ))
}

fn wait_for_marker(path: &std::path::Path) -> Pid {
    let deadline = Instant::now() + Duration::from_secs(120);
    loop {
        // The child creates the marker file and then writes the PID in a second
        // step, so a read can observe the file after creation but before the
        // digits land. Retry until the contents parse rather than unwrapping an
        // empty string, and keep the deadline generous for slow shared runners.
        if let Ok(contents) = std::fs::read_to_string(path)
            && let Ok(pid) = contents.trim().parse()
        {
            return pid;
        }
        assert!(
            Instant::now() < deadline,
            "process marker was never written"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
}

struct ExactProcessGuard {
    task_name: TaskNameRight,
    audit: AuditToken,
}

impl ExactProcessGuard {
    fn capture(pid: Pid) -> Self {
        let (task_name, audit) = TaskNameRight::capture(pid).unwrap();
        Self { task_name, audit }
    }

    fn terminate(mut self) {
        signal_with_audit_token(&mut self.audit, 9).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while self.task_name.audit_token().is_ok() {
            assert!(Instant::now() < deadline, "exact process did not terminate");
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

impl Drop for ExactProcessGuard {
    fn drop(&mut self) {
        let _ = signal_with_audit_token(&mut self.audit, 9);
    }
}

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
fn suspended_spawn_captures_exact_task_identity_before_bootstrap() {
    let helper = vnext_helper("backend::macos::bootstrap::tests::suspended_task_identity_helper");
    let expected_pid = helper.pid();
    let initial_audit = helper
        .lifecycle
        .as_ref()
        .unwrap()
        .current_task_audit_token_for_test()
        .unwrap();
    // SAFETY: the token was returned by TASK_AUDIT_TOKEN for the retained
    // task-name right.
    assert_eq!(
        unsafe { audit_token_to_pid(initial_audit) } as u32,
        expected_pid
    );

    let (channel, lifecycle) = helper.authenticate_vnext_until(test_deadline()).unwrap();
    assert_eq!(channel.peer_audit, Some(initial_audit));
    let cleanup = lifecycle.terminate_and_reap_facts(test_deadline());
    assert!(cleanup.direct_child_complete());
}

#[test]
fn silent_prebootstrap_child_is_terminated_from_captured_audit_identity() {
    let helper = vnext_helper("backend::macos::bootstrap::tests::silent_prebootstrap_helper");
    let cleanup = helper.cleanup_vnext_until(test_deadline());
    assert!(cleanup.direct_child_complete());
    assert_eq!(cleanup.native_error(), None);
}

#[test]
fn retained_task_name_is_invalidated_by_exec() {
    let helper = vnext_helper("backend::macos::bootstrap::tests::exec_after_bootstrap_helper");
    let expected_pid = helper.pid();
    let (unique_before, bsd_before) = process_identity(expected_pid as Pid);
    let (channel, lifecycle) = helper.authenticate_vnext_until(test_deadline()).unwrap();
    let authenticated = channel.peer_audit.unwrap();

    let changed = Instant::now() + Duration::from_secs(5);
    let invalid_destination = loop {
        match lifecycle.current_task_audit_token_for_test() {
            Ok(current) => assert_eq!(current, authenticated),
            Err(BootstrapError::Mach { code, .. }) => break code,
            Err(error) => panic!("unexpected task-name failure after exec: {error}"),
        }
        assert!(
            Instant::now() < changed,
            "helper never completed its second exec"
        );
        std::thread::sleep(Duration::from_millis(1));
    };
    assert_eq!(invalid_destination, 0x1000_0003);
    assert_eq!(lifecycle.pid(), expected_pid);
    assert_eq!(lifecycle.try_poll(), Ok(PeerState::Running));
    let (unique_after, bsd_after) = process_identity(expected_pid as Pid);
    assert_eq!(unique_after.unique_id, unique_before.unique_id);
    assert_eq!(
        unique_after.parent_unique_id,
        unique_before.parent_unique_id
    );
    assert_ne!(unique_after.pid_version, unique_before.pid_version);
    assert_eq!(bsd_after.pid, bsd_before.pid);
    assert_eq!(bsd_after.parent_pid, bsd_before.parent_pid);
    assert_eq!(bsd_after.start_seconds, bsd_before.start_seconds);
    assert_eq!(bsd_after.start_microseconds, bsd_before.start_microseconds);

    let cleanup = lifecycle.wait_and_reap_facts(test_deadline());
    assert!(cleanup.direct_child_complete());
    assert_eq!(cleanup.native_error(), None);
}

#[test]
fn task_identity_token_is_exact_but_cannot_be_minted_from_name_or_survive_exec() {
    let helper = vnext_helper("backend::macos::bootstrap::tests::identity_token_exec_helper");
    let (mut channel, lifecycle) = helper.authenticate_vnext_until(test_deadline()).unwrap();

    let mut token_from_name = MACH_PORT_NULL;
    let create_from_name = {
        let state = lock_lifecycle(&lifecycle.shared.state);
        let task_name = state.task_name.as_ref().unwrap().0;
        // SAFETY: output storage is valid. The call intentionally supplies a
        // name-flavor port where the API requires a task-control port.
        unsafe { task_create_identity_token(task_name, &mut token_from_name) }
    };
    assert_ne!(create_from_name, KERN_SUCCESS);
    if token_from_name != MACH_PORT_NULL {
        deallocate_port(current_task(), token_from_name);
    }

    let record = channel
        .receive_vnext_capabilities(1, test_deadline())
        .unwrap();
    assert_eq!(record.bytes, [0]);
    assert_eq!(record.rights.len(), 1);
    let token = record.rights[0].name();

    let mut name = MACH_PORT_NULL;
    // SAFETY: token is a live child-created task identity token and output is
    // valid for one returned port name.
    assert_eq!(
        unsafe { task_identity_token_get_task_port(token, TASK_FLAVOR_NAME, &mut name) },
        KERN_SUCCESS
    );
    deallocate_port(current_task(), name);

    channel
        .send_vnext_zero_rights(&[0], test_deadline())
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        name = MACH_PORT_NULL;
        // SAFETY: token remains owned by `record` and output storage is valid.
        let result =
            unsafe { task_identity_token_get_task_port(token, TASK_FLAVOR_NAME, &mut name) };
        if result == KERN_NOT_FOUND {
            break;
        }
        assert_eq!(result, KERN_SUCCESS);
        deallocate_port(current_task(), name);
        assert!(
            Instant::now() < deadline,
            "task identity token remained valid across exec"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(lifecycle.try_poll(), Ok(PeerState::Running));

    let cleanup = lifecycle.wait_and_reap_facts(test_deadline());
    assert!(cleanup.direct_child_complete());
    assert_eq!(cleanup.native_error(), None);
}

#[test]
fn ptrace_relationship_survives_exec_and_exactly_kills_the_stopped_child() {
    let helper = vnext_helper("backend::macos::bootstrap::tests::ptrace_exec_helper");
    let child_pid = helper.pid() as Pid;
    let (mut channel, lifecycle) = helper.authenticate_vnext_until(test_deadline()).unwrap();

    assert_eq!(
        channel
            .receive_vnext_zero_rights(1, test_deadline())
            .unwrap(),
        [0]
    );

    channel
        .send_vnext_zero_rights(&[0], test_deadline())
        .unwrap();

    let exec_stop = wait_for_traced_stop(child_pid);
    assert_eq!((exec_stop >> 8) & 0xff, 5, "exec did not stop on SIGTRAP");
    assert_eq!(lifecycle.try_poll(), Ok(PeerState::Running));

    // SAFETY: PT_KILL is accepted only for this caller's currently stopped
    // tracee, so XNU retains and signals that exact proc rather than a later
    // process that happens to reuse the numeric PID.
    assert_eq!(
        unsafe { ptrace(PT_KILL, child_pid, std::ptr::null_mut(), 0) },
        0
    );
    let cleanup = lifecycle.wait_and_reap_facts(test_deadline());
    assert!(cleanup.direct_child_complete());
    assert_eq!(cleanup.native_error(), None);
}

#[test]
fn traced_running_child_can_be_stopped_and_exactly_killed_without_audit_spi() {
    let helper = vnext_helper("backend::macos::bootstrap::tests::ptrace_crash_child_helper");
    let child_pid = helper.pid() as Pid;
    let (mut channel, lifecycle) = helper.authenticate_vnext_until(test_deadline()).unwrap();
    assert_eq!(
        channel
            .receive_vnext_zero_rights(1, test_deadline())
            .unwrap(),
        [0]
    );

    // The tracer is the sole wait owner. A live child receives SIGSTOP; an
    // already-exited child remains a zombie and pins its PID until this owner
    // reaps it, so the numeric stop cannot hit a recycled process.
    // Hold the lifecycle's waiter gate while this test temporarily acts as the
    // sole waiter. Otherwise the background reaper may consume the stop first
    // and correctly treat that unexpected stop as terminal.
    let reaping_pause = lifecycle.pause_reaping();
    // The gate prevents future reaping, but the background waiter could have
    // won before the gate was acquired. Prove it did not before using the
    // numeric child PID; after this check, a later exit remains a PID-pinning
    // zombie until this test releases the gate.
    assert_eq!(lifecycle.try_poll(), Ok(PeerState::Running));
    // SAFETY: `child_pid` is this process's unreaped traced child.
    assert_eq!(unsafe { kill(child_pid, SIGSTOP) }, 0);
    let stop = wait_for_traced_stop(child_pid);
    assert_eq!((stop >> 8) & 0xff, SIGSTOP);

    // SAFETY: PT_KILL additionally requires this exact caller/tracee relation
    // and the stopped state checked above.
    assert_eq!(
        unsafe { ptrace(PT_KILL, child_pid, std::ptr::null_mut(), 0) },
        0
    );
    drop(reaping_pause);
    let cleanup = lifecycle.wait_and_reap_facts(test_deadline());
    assert!(cleanup.direct_child_complete());
    assert_eq!(cleanup.native_error(), None);
}

#[test]
fn hard_nproc_limit_survives_exec_and_denies_descendant_spawn() {
    let marker = process_marker("rlimit-nproc");
    let environment = [CString::new(format!("{PROCESS_MARKER_ENV}={}", marker.display())).unwrap()];
    let helper = vnext_helper_with_environment(
        "backend::macos::bootstrap::tests::rlimit_nproc_exec_helper",
        &environment,
    );
    let (mut channel, lifecycle) = helper.authenticate_vnext_until(test_deadline()).unwrap();
    channel
        .send_vnext_zero_rights(&[0], test_deadline())
        .unwrap();

    let denied_errno = wait_for_marker(&marker);
    assert_eq!(
        denied_errno, 35,
        "descendant spawn did not fail with EAGAIN"
    );
    let cleanup = lifecycle.wait_and_reap_facts(test_deadline());
    assert!(cleanup.direct_child_complete());
    assert_eq!(cleanup.native_error(), None);
    std::fs::remove_file(marker).unwrap();
}

#[test]
fn traced_launcher_handshake_precedes_rlimit_and_target_exec() {
    let marker = process_marker("traced-launcher-handshake");
    let environment = [CString::new(format!("{PROCESS_MARKER_ENV}={}", marker.display())).unwrap()];
    let helper = vnext_helper_with_environment(
        "backend::macos::bootstrap::tests::traced_launcher_helper",
        &environment,
    );
    let (mut channel, lifecycle) = helper.authenticate_vnext_until(test_deadline()).unwrap();
    channel
        .start_traced_launcher(&lifecycle, test_deadline())
        .unwrap();

    let marker_deadline = Instant::now() + Duration::from_secs(120);
    let denied_errno = loop {
        // Tolerate the create-before-write window: parse only once the digits
        // have landed, and keep the deadline generous for slow shared runners.
        if let Ok(contents) = std::fs::read_to_string(&marker)
            && let Ok(value) = contents.trim().parse::<Pid>()
        {
            break value;
        }
        if lifecycle.try_poll() == Ok(PeerState::ExitedUnknown) {
            panic!(
                "target exited before marker with wait status {:#x}",
                lifecycle.wait_and_reap_status(test_deadline()).unwrap()
            );
        }
        assert!(
            Instant::now() < marker_deadline,
            "target neither wrote its marker nor exited"
        );
        std::thread::sleep(Duration::from_millis(1));
    };
    assert_eq!(denied_errno, 35);
    let cleanup = lifecycle.wait_and_reap_facts(test_deadline());
    assert!(cleanup.direct_child_complete());
    assert_eq!(cleanup.native_error(), None);
    std::fs::remove_file(marker).unwrap();
}

#[test]
fn traced_launcher_lifecycle_uses_exact_ptrace_termination() {
    let helper =
        vnext_helper("backend::macos::bootstrap::tests::traced_long_running_launcher_helper");
    let (mut channel, lifecycle) = helper.authenticate_vnext_until(test_deadline()).unwrap();
    channel
        .start_traced_launcher(&lifecycle, test_deadline())
        .unwrap();

    let cleanup = lifecycle.terminate_and_reap_facts(test_deadline());
    assert!(cleanup.direct_child_complete());
    assert_eq!(cleanup.native_error(), None);
}

#[test]
fn supervisor_crash_drops_identity_authority_without_terminating_child() {
    let marker = process_marker("supervisor-crash");
    let status = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("backend::macos::bootstrap::tests::crashing_supervisor_helper")
        .arg("--ignored")
        .arg("--nocapture")
        .env(PROCESS_MARKER_ENV, &marker)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .unwrap();
    assert!(status.success());

    let child_pid = wait_for_marker(&marker);
    let survivor = ExactProcessGuard::capture(child_pid);
    // A replacement observer can reacquire this live process in the happy
    // case, but it has only a reusable PID at lookup time and therefore cannot
    // prove that it reacquired the original child after an arbitrary delay.
    survivor.terminate();
    std::fs::remove_file(marker).unwrap();
}

#[test]
fn tracer_crash_kernel_kills_the_exact_traced_child() {
    let marker = process_marker("ptrace-supervisor-crash");
    let mut supervisor = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("backend::macos::bootstrap::tests::crashing_ptrace_supervisor_helper")
        .arg("--ignored")
        .arg("--nocapture")
        .env(PROCESS_MARKER_ENV, &marker)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    let child_pid = wait_for_marker(&marker);
    let expected_unique_id = process_identity(child_pid).0.unique_id;
    let traced_child = ExactProcessGuard::capture(child_pid);
    let status = supervisor.wait().unwrap();
    assert!(status.success());

    let deadline = Instant::now() + Duration::from_secs(5);
    while traced_child.task_name.audit_token().is_ok() {
        assert!(
            Instant::now() < deadline,
            "traced child survived tracer process exit"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    wait_for_process_identity_to_disappear(child_pid, expected_unique_id);
    std::fs::remove_file(marker).unwrap();
}

#[test]
fn inherited_death_pipe_cascades_client_loss_through_broker_to_tracee() {
    let marker = process_marker("ptrace-death-pipe");
    let mut broker = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("backend::macos::bootstrap::tests::death_pipe_ptrace_broker_helper")
        .arg("--ignored")
        .arg("--nocapture")
        .env(PROCESS_MARKER_ENV, &marker)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let client_liveness = broker.stdin.take().unwrap();

    let child_pid = wait_for_marker(&marker);
    let expected_unique_id = process_identity(child_pid).0.unique_id;
    let traced_child = ExactProcessGuard::capture(child_pid);

    // Closing the only writer models abrupt client/service loss. The broker
    // sees EOF and exits; XNU then kills its exact traced child.
    drop(client_liveness);
    assert!(broker.wait().unwrap().success());

    let deadline = Instant::now() + Duration::from_secs(5);
    while traced_child.task_name.audit_token().is_ok() {
        assert!(
            Instant::now() < deadline,
            "traced child survived broker death-pipe EOF"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    wait_for_process_identity_to_disappear(child_pid, expected_unique_id);
    std::fs::remove_file(marker).unwrap();
}

#[test]
fn same_uid_tracee_can_stop_broker_and_suspend_cleanup_authority() {
    let marker = process_marker("ptrace-stopped-broker");
    let escaped_marker = marker.with_extension("escaped");
    let mut broker = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("backend::macos::bootstrap::tests::stoppable_ptrace_broker_helper")
        .arg("--ignored")
        .arg("--nocapture")
        .env(PROCESS_MARKER_ENV, &marker)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let broker_pid = broker.id() as Pid;
    let child_pid = wait_for_marker(&marker);
    let expected_unique_id = process_identity(child_pid).0.unique_id;
    let traced_child = ExactProcessGuard::capture(child_pid);

    let deadline = Instant::now() + Duration::from_secs(5);
    while !escaped_marker.exists() {
        assert!(
            Instant::now() < deadline,
            "tracee never signalled the same-UID broker"
        );
        std::thread::sleep(Duration::from_millis(1));
    }

    let mut stop_status = 0;
    // SAFETY: the broker is this process's direct unreaped child.
    assert_eq!(
        unsafe { waitpid(broker_pid, &mut stop_status, WUNTRACED) },
        broker_pid
    );
    assert_eq!(stop_status & 0xff, 0x7f);
    assert_eq!((stop_status >> 8) & 0xff, SIGSTOP);
    assert!(traced_child.task_name.audit_token().is_ok());

    // Killing the stopped broker remains fail-safe: XNU then kills its exact
    // tracee. The vulnerability is the unbounded interval before an external
    // authority performs this recovery.
    // SAFETY: the unreaped stopped broker still pins this PID.
    assert_eq!(unsafe { kill(broker_pid, 9) }, 0);
    assert!(!broker.wait().unwrap().success());
    let deadline = Instant::now() + Duration::from_secs(5);
    while traced_child.task_name.audit_token().is_ok() {
        assert!(
            Instant::now() < deadline,
            "tracee survived forced broker termination"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    wait_for_process_identity_to_disappear(child_pid, expected_unique_id);
    std::fs::remove_file(marker).unwrap();
    std::fs::remove_file(escaped_marker).unwrap();
}

#[test]
fn traced_watchdog_exactly_recovers_a_broker_stopped_by_its_tracee() {
    let marker = process_marker("ptrace-watchdog-stopped-broker");
    let escaped_marker = marker.with_extension("escaped");
    let mut broker = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("backend::macos::bootstrap::tests::watchdog_traced_broker_helper")
        .arg("--ignored")
        .arg("--nocapture")
        .env(PROCESS_MARKER_ENV, &marker)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let broker_pid = broker.id() as Pid;

    let proof_stop = wait_for_traced_stop(broker_pid);
    assert_eq!((proof_stop >> 8) & 0xff, SIGSTOP);
    ptrace_continue(broker_pid).unwrap();

    let child_pid = wait_for_marker(&marker);
    let expected_unique_id = process_identity(child_pid).0.unique_id;
    let traced_child = ExactProcessGuard::capture(child_pid);
    let deadline = Instant::now() + Duration::from_secs(5);
    while !escaped_marker.exists() {
        assert!(
            Instant::now() < deadline,
            "tracee never stopped the watchdog-traced broker"
        );
        std::thread::sleep(Duration::from_millis(1));
    }

    let hostile_stop = wait_for_traced_stop(broker_pid);
    assert_eq!((hostile_stop >> 8) & 0xff, SIGSTOP);
    // SAFETY: XNU accepts PT_KILL only for this caller's exact currently
    // stopped tracee. No lookup or reusable numeric-PID fallback occurs.
    assert_eq!(
        unsafe { ptrace(PT_KILL, broker_pid, std::ptr::null_mut(), 0) },
        0
    );
    assert!(!broker.wait().unwrap().success());

    let deadline = Instant::now() + Duration::from_secs(5);
    while traced_child.task_name.audit_token().is_ok() {
        assert!(
            Instant::now() < deadline,
            "broker's exact tracee survived watchdog PT_KILL and tracer exit"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    wait_for_process_identity_to_disappear(child_pid, expected_unique_id);
    std::fs::remove_file(marker).unwrap();
    std::fs::remove_file(escaped_marker).unwrap();
}

#[test]
fn direct_child_termination_does_not_contain_setsid_descendant() {
    let marker = process_marker("escaped-descendant");
    let environment = [CString::new(format!("{PROCESS_MARKER_ENV}={}", marker.display())).unwrap()];
    let helper = vnext_helper_with_environment(
        "backend::macos::bootstrap::tests::escaped_descendant_parent_helper",
        &environment,
    );
    let descendant_pid = wait_for_marker(&marker);
    let descendant = ExactProcessGuard::capture(descendant_pid);

    let cleanup = helper.cleanup_vnext_until(test_deadline());
    assert!(cleanup.direct_child_complete());
    assert_eq!(
        cleanup.descendants(),
        DescendantCleanupStatus::FreshGroupUnverified
    );
    // The exact descendant task remains live after direct-child cleanup.
    assert!(descendant.task_name.audit_token().is_ok());

    descendant.terminate();
    std::fs::remove_file(marker).unwrap();
}

#[test]
#[ignore = "spawned only by the suspended task-identity integration test"]
fn suspended_task_identity_helper() {
    let _channel = ChildChannel::connect_from_environment_until(test_deadline()).unwrap();
    std::thread::sleep(Duration::from_secs(30));
}

#[test]
#[ignore = "spawned only by the silent pre-bootstrap cleanup test"]
fn silent_prebootstrap_helper() {
    std::thread::sleep(Duration::from_secs(30));
}

#[test]
#[ignore = "spawned only by the post-bootstrap exec identity test"]
fn exec_after_bootstrap_helper() {
    let _channel = ChildChannel::connect_from_environment_until(test_deadline()).unwrap();
    let executable = std::env::current_exe().unwrap();
    let error = Command::new(executable)
        .arg("--exact")
        .arg("backend::macos::bootstrap::tests::post_exec_identity_helper")
        .arg("--ignored")
        .arg("--nocapture")
        .exec();
    panic!("second exec failed: {error}");
}

#[test]
#[ignore = "spawned only by the task identity-token exec test"]
fn identity_token_exec_helper() {
    let mut channel = ChildChannel::connect_from_environment_until(test_deadline()).unwrap();
    let mut token = MACH_PORT_NULL;
    // SAFETY: current_task is a live task-control port and output storage is
    // valid for one newly created identity-token send right.
    mach("task_create_identity_token", unsafe {
        task_create_identity_token(current_task(), &mut token)
    })
    .unwrap();
    channel
        .send_vnext_capabilities(&[0], &[token], test_deadline())
        .unwrap();
    deallocate_port(current_task(), token);
    channel
        .receive_vnext_zero_rights(1, test_deadline())
        .unwrap();

    let executable = std::env::current_exe().unwrap();
    let error = Command::new(executable)
        .arg("--exact")
        .arg("backend::macos::bootstrap::tests::post_exec_identity_helper")
        .arg("--ignored")
        .arg("--nocapture")
        .exec();
    panic!("second exec failed: {error}");
}

#[test]
#[ignore = "spawned only by the ptrace exec-lifecycle test"]
fn ptrace_exec_helper() {
    let mut channel = ChildChannel::connect_from_environment_until(test_deadline()).unwrap();
    // SAFETY: PT_TRACE_ME asks this process's actual parent to become its
    // tracer; the remaining arguments are ignored.
    assert_eq!(
        unsafe { ptrace(PT_TRACE_ME, 0, std::ptr::null_mut(), 0) },
        0
    );
    channel
        .send_vnext_zero_rights(&[0], test_deadline())
        .unwrap();
    channel
        .receive_vnext_zero_rights(1, test_deadline())
        .unwrap();

    let executable = std::env::current_exe().unwrap();
    let error = Command::new(executable)
        .arg("--exact")
        .arg("backend::macos::bootstrap::tests::post_exec_identity_helper")
        .arg("--ignored")
        .arg("--nocapture")
        .exec();
    panic!("traced exec failed: {error}");
}

#[test]
#[ignore = "spawned only by the hard RLIMIT_NPROC exec test"]
fn rlimit_nproc_exec_helper() {
    let mut channel = ChildChannel::connect_from_environment_until(test_deadline()).unwrap();
    channel
        .receive_vnext_zero_rights(1, test_deadline())
        .unwrap();
    let limit = ResourceLimit {
        current: 1,
        maximum: 1,
    };
    // SAFETY: resource is RLIMIT_NPROC and `limit` is a valid immutable input.
    assert_eq!(unsafe { setrlimit(RLIMIT_NPROC, &limit) }, 0);

    let executable = std::env::current_exe().unwrap();
    let error = Command::new(executable)
        .arg("--exact")
        .arg("backend::macos::bootstrap::tests::rlimit_nproc_post_exec_helper")
        .arg("--ignored")
        .arg("--nocapture")
        .exec();
    panic!("RLIMIT_NPROC exec failed: {error}");
}

#[test]
#[ignore = "spawned only by the traced-launcher handshake test"]
fn traced_launcher_helper() {
    let mut channel = ChildChannel::connect_from_environment_until(test_deadline()).unwrap();
    if let Err(error) = channel.prepare_traced_target_exec(test_deadline()) {
        let marker = std::path::PathBuf::from(std::env::var_os(PROCESS_MARKER_ENV).unwrap());
        std::fs::write(marker.with_extension("error"), format!("{error:?}")).unwrap();
        panic!("traced launcher preparation failed: {error:?}");
    }

    let executable = std::env::current_exe().unwrap();
    let error = Command::new(executable)
        .arg("--exact")
        .arg("backend::macos::bootstrap::tests::rlimit_nproc_post_exec_helper")
        .arg("--ignored")
        .arg("--nocapture")
        .exec();
    panic!("traced launcher exec failed: {error}");
}

#[test]
#[ignore = "spawned only by the traced lifecycle termination test"]
fn traced_long_running_launcher_helper() {
    let mut channel = ChildChannel::connect_from_environment_until(test_deadline()).unwrap();
    channel.prepare_traced_target_exec(test_deadline()).unwrap();

    let executable = std::env::current_exe().unwrap();
    let error = Command::new(executable)
        .arg("--exact")
        .arg("backend::macos::bootstrap::tests::traced_long_running_target_helper")
        .arg("--ignored")
        .arg("--nocapture")
        .exec();
    panic!("traced long-running launcher exec failed: {error}");
}

#[test]
#[ignore = "spawned only after the traced long-running exec transition"]
fn traced_long_running_target_helper() {
    std::thread::sleep(Duration::from_secs(30));
}

#[test]
#[ignore = "spawned only after the hard RLIMIT_NPROC exec transition"]
fn rlimit_nproc_post_exec_helper() {
    let marker = std::env::var_os(PROCESS_MARKER_ENV).unwrap();
    let error = Command::new("/usr/bin/true").status().unwrap_err();
    std::fs::write(marker, error.raw_os_error().unwrap().to_string()).unwrap();
}

#[test]
#[ignore = "spawned only after the task-identity exec transition"]
fn post_exec_identity_helper() {
    std::thread::sleep(Duration::from_millis(500));
}

#[test]
#[ignore = "spawned only by the supervisor-crash identity test"]
fn crashing_supervisor_helper() {
    let marker = std::env::var_os(PROCESS_MARKER_ENV).unwrap();
    let child = vnext_helper("backend::macos::bootstrap::tests::silent_prebootstrap_helper");
    std::fs::write(marker, child.pid().to_string()).unwrap();
    // SAFETY: this intentionally models an abrupt supervisor process death;
    // bypassing Rust destructors is the behavior under test.
    unsafe { _exit(0) }
}

#[test]
#[ignore = "spawned only by the ptrace supervisor-crash test"]
fn crashing_ptrace_supervisor_helper() {
    let marker = std::env::var_os(PROCESS_MARKER_ENV).unwrap();
    let child = vnext_helper("backend::macos::bootstrap::tests::ptrace_crash_child_helper");
    let child_pid = child.pid();
    let (mut channel, _lifecycle) = child.authenticate_vnext_until(test_deadline()).unwrap();
    assert_eq!(
        channel
            .receive_vnext_zero_rights(1, test_deadline())
            .unwrap(),
        [0]
    );
    std::fs::write(marker, child_pid.to_string()).unwrap();
    std::thread::sleep(Duration::from_millis(500));
    // SAFETY: model abrupt tracer/supervisor death without Rust cleanup.
    unsafe { _exit(0) }
}

#[test]
#[ignore = "spawned only by the death-pipe containment test"]
fn death_pipe_ptrace_broker_helper() {
    let marker = std::env::var_os(PROCESS_MARKER_ENV).unwrap();
    let child = vnext_helper("backend::macos::bootstrap::tests::ptrace_crash_child_helper");
    let child_pid = child.pid();
    let (mut channel, _lifecycle) = child.authenticate_vnext_until(test_deadline()).unwrap();
    assert_eq!(
        channel
            .receive_vnext_zero_rights(1, test_deadline())
            .unwrap(),
        [0]
    );
    std::fs::write(marker, child_pid.to_string()).unwrap();

    let mut byte = [0_u8; 1];
    assert_eq!(std::io::stdin().read(&mut byte).unwrap(), 0);
    // SAFETY: model broker loss immediately after its inherited liveness pipe
    // reports that the client/service disappeared.
    unsafe { _exit(0) }
}

#[test]
#[ignore = "spawned only by the stopped-broker adversarial test"]
fn stoppable_ptrace_broker_helper() {
    let marker = std::env::var_os(PROCESS_MARKER_ENV).unwrap();
    let environment = [CString::new(format!(
        "{PROCESS_MARKER_ENV}={}",
        std::path::PathBuf::from(&marker).display()
    ))
    .unwrap()];
    let child = vnext_helper_with_environment(
        "backend::macos::bootstrap::tests::broker_stopping_tracee_helper",
        &environment,
    );
    let child_pid = child.pid();
    let (mut channel, _lifecycle) = child.authenticate_vnext_until(test_deadline()).unwrap();
    assert_eq!(
        channel
            .receive_vnext_zero_rights(1, test_deadline())
            .unwrap(),
        [0]
    );
    std::fs::write(marker, child_pid.to_string()).unwrap();
    std::thread::sleep(Duration::from_secs(30));
}

#[test]
#[ignore = "spawned only by the watchdog stopped-broker recovery test"]
fn watchdog_traced_broker_helper() {
    // SAFETY: request tracing by this helper's actual parent/watchdog.
    assert_eq!(
        unsafe { ptrace(PT_TRACE_ME, 0, std::ptr::null_mut(), 0) },
        0
    );
    // SAFETY: produce the explicit proof stop consumed by the exact parent.
    assert_eq!(unsafe { raise(SIGSTOP) }, 0);

    let marker = std::env::var_os(PROCESS_MARKER_ENV).unwrap();
    let environment = [CString::new(format!(
        "{PROCESS_MARKER_ENV}={}",
        std::path::PathBuf::from(&marker).display()
    ))
    .unwrap()];
    let child = vnext_helper_with_environment(
        "backend::macos::bootstrap::tests::broker_stopping_tracee_helper",
        &environment,
    );
    let child_pid = child.pid();
    let (mut channel, _lifecycle) = child.authenticate_vnext_until(test_deadline()).unwrap();
    assert_eq!(
        channel
            .receive_vnext_zero_rights(1, test_deadline())
            .unwrap(),
        [0]
    );
    std::fs::write(marker, child_pid.to_string()).unwrap();
    std::thread::sleep(Duration::from_secs(30));
}

#[test]
#[ignore = "spawned only as the same-UID broker-stopping tracee"]
fn broker_stopping_tracee_helper() {
    let mut channel = ChildChannel::connect_from_environment_until(test_deadline()).unwrap();
    // SAFETY: request tracing by this process's current parent/broker.
    assert_eq!(
        unsafe { ptrace(PT_TRACE_ME, 0, std::ptr::null_mut(), 0) },
        0
    );
    channel
        .send_vnext_zero_rights(&[0], test_deadline())
        .unwrap();

    let marker = std::path::PathBuf::from(std::env::var_os(PROCESS_MARKER_ENV).unwrap());
    let deadline = Instant::now() + Duration::from_secs(5);
    while !marker.exists() {
        assert!(
            Instant::now() < deadline,
            "broker never published child PID"
        );
        std::thread::sleep(Duration::from_millis(1));
    }
    let limit = ResourceLimit {
        current: 1,
        maximum: 1,
    };
    // SAFETY: install the same irreversible descendant limit as the candidate.
    assert_eq!(unsafe { setrlimit(RLIMIT_NPROC, &limit) }, 0);
    // SAFETY: getppid has no preconditions and SIGSTOP is sent to the live
    // same-UID tracer/broker.
    assert_eq!(unsafe { kill(getppid(), SIGSTOP) }, 0);
    std::fs::write(marker.with_extension("escaped"), "1").unwrap();
    std::thread::sleep(Duration::from_secs(30));
}

#[test]
#[ignore = "spawned only as the ptrace supervisor's traced child"]
fn ptrace_crash_child_helper() {
    let mut channel = ChildChannel::connect_from_environment_until(test_deadline()).unwrap();
    // SAFETY: request tracing by this process's actual parent.
    assert_eq!(
        unsafe { ptrace(PT_TRACE_ME, 0, std::ptr::null_mut(), 0) },
        0
    );
    channel
        .send_vnext_zero_rights(&[0], test_deadline())
        .unwrap();
    std::thread::sleep(Duration::from_secs(30));
}

#[test]
#[ignore = "spawned only by the descendant-containment test"]
#[allow(clippy::zombie_processes)]
fn escaped_descendant_parent_helper() {
    // Intentionally do not wait: the test proves this child survives and is
    // reparented when its direct parent is terminated.
    let marker = std::env::var_os(PROCESS_MARKER_ENV).unwrap();
    let descendant = Command::new(std::env::current_exe().unwrap())
        .arg("--exact")
        .arg("backend::macos::bootstrap::tests::setsid_descendant_helper")
        .arg("--ignored")
        .arg("--nocapture")
        .spawn()
        .unwrap();
    std::fs::write(marker, descendant.id().to_string()).unwrap();
    std::thread::sleep(Duration::from_secs(30));
}

#[test]
#[ignore = "spawned only as the escaped descendant"]
fn setsid_descendant_helper() {
    // SAFETY: this process is not a process-group leader and intentionally
    // creates a new session to prove process-group escape.
    assert!(unsafe { setsid() } > 0);
    std::thread::sleep(Duration::from_secs(30));
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
