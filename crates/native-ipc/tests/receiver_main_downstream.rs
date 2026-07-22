//! Downstream executable regression for the public receiver entry-point macro.

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use std::time::Duration;

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use native_ipc::control::APPLICATION_CONTROL_KIND_MIN;
#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
use native_ipc::session::{
    AbsoluteDeadline, CoordinatorCloseOutcome, CoordinatorSession, ExecutableIdentityPolicy,
    Negotiating, NegotiationDecision, NegotiationOutcome, ReceiverCloseOutcome, ReceiverSession,
    SessionCommand, SessionLimits, SessionOptions,
};
use native_ipc::session::{ReceiverBootstrap, SessionFailure};

const RECEIVER_ARG: &str = "--native-ipc-downstream-receiver";

#[cfg(target_os = "macos")]
const TASK_BOOTSTRAP_PORT: i32 = 4;

#[cfg(target_os = "macos")]
unsafe extern "C" {
    static mach_task_self_: u32;

    fn task_get_special_port(task: u32, which: i32, port: *mut u32) -> i32;
    fn mach_port_deallocate(task: u32, port: u32) -> i32;
    fn mach_ports_lookup(task: u32, ports: *mut *mut u32, count: *mut u32) -> i32;
    fn vm_deallocate(task: u32, address: usize, size: usize) -> i32;
    fn bootstrap_parent(bootstrap: u32, parent: *mut u32) -> i32;
}

#[cfg(target_os = "macos")]
#[link(name = "CoreFoundation", kind = "framework")]
unsafe extern "C" {
    fn CFBundleCreate(
        allocator: *const core::ffi::c_void,
        url: *const core::ffi::c_void,
    ) -> *const core::ffi::c_void;
}

#[cfg(target_os = "macos")]
#[link(name = "CoreAudio", kind = "framework")]
unsafe extern "C" {
    fn AudioObjectGetPropertyData(
        object_id: u32,
        address: *const core::ffi::c_void,
        qualifier_size: u32,
        qualifier_data: *const core::ffi::c_void,
        data_size: *mut u32,
        data: *mut core::ffi::c_void,
    ) -> i32;
}

#[cfg(target_os = "macos")]
#[link(name = "AudioToolbox", kind = "framework")]
unsafe extern "C" {
    fn AudioComponentFindNext(
        component: *mut core::ffi::c_void,
        description: *const core::ffi::c_void,
    ) -> *mut core::ffi::c_void;
}

#[cfg(target_os = "macos")]
fn retain_framework_load_graph() {
    std::hint::black_box(CFBundleCreate as *const ());
    std::hint::black_box(AudioObjectGetPropertyData as *const ());
    std::hint::black_box(AudioComponentFindNext as *const ());
}

#[cfg(target_os = "macos")]
fn assert_launchd_preserved_and_registered_stash_cleared() {
    // SAFETY: this process owns its task-self send right.
    let task = unsafe { mach_task_self_ };
    let mut bootstrap = 0;
    // SAFETY: output storage is valid and slot 4 is the documented bootstrap
    // special port. The returned send-right reference is released below.
    assert_eq!(
        unsafe { task_get_special_port(task, TASK_BOOTSTRAP_PORT, &mut bootstrap) },
        0
    );
    assert_ne!(bootstrap, 0);

    let mut parent = 0;
    // SAFETY: `bootstrap` is the copied live launchd bootstrap right. A
    // successful MIG round trip proves it was not replaced by the private
    // native-ipc receive right.
    assert_eq!(unsafe { bootstrap_parent(bootstrap, &mut parent) }, 0);
    assert_ne!(parent, 0);
    // SAFETY: both calls release one copied send-right reference returned by
    // the two successful calls above.
    assert_eq!(unsafe { mach_port_deallocate(task, parent) }, 0);
    // SAFETY: same ownership argument for the bootstrap copy.
    assert_eq!(unsafe { mach_port_deallocate(task, bootstrap) }, 0);

    let mut registered = std::ptr::null_mut();
    let mut count = 0;
    // SAFETY: both outputs are valid; MIG returns an owned array released below.
    assert_eq!(
        unsafe { mach_ports_lookup(task, &mut registered, &mut count) },
        0
    );
    assert_eq!(count, 3);
    assert!(!registered.is_null());
    // SAFETY: mach_ports_lookup returned exactly `count` initialized names.
    let names = unsafe { std::slice::from_raw_parts(registered, count as usize) };
    assert_eq!(names, [0, 0, 0]);
    // SAFETY: MIG allocated this exact out-of-line array in the current task.
    assert_eq!(
        unsafe { vm_deallocate(task, registered as usize, size_of_val(names)) },
        0
    );
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn deadline() -> AbsoluteDeadline {
    AbsoluteDeadline::after(Duration::from_secs(5)).expect("fixture deadline")
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn options(payload: &[u8]) -> SessionOptions {
    SessionOptions::new(deadline(), ExecutableIdentityPolicy::ExactOpenedFile)
        .with_limits(SessionLimits {
            max_control_payload_bytes: 32,
            ..SessionLimits::default()
        })
        .with_application_payload(payload.to_vec())
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn run_receiver(bootstrap: ReceiverBootstrap) {
    let receiver =
        ReceiverSession::<Negotiating>::from_bootstrap(bootstrap, options(b"downstream-receiver"))
            .expect("receiver bootstrap negotiation");
    #[cfg(target_os = "macos")]
    assert_launchd_preserved_and_registered_stash_cleared();
    assert_eq!(
        receiver.peer_application_payload(),
        b"downstream-coordinator"
    );
    let mut ready = match receiver
        .decide_after_coordinator(|payload| {
            assert_eq!(payload, b"downstream-coordinator");
            NegotiationDecision::Accept
        })
        .expect("receiver decision")
    {
        NegotiationOutcome::Accepted(ready) => ready,
        NegotiationOutcome::Rejected { .. } => panic!("downstream receiver was rejected"),
    };
    let request = ready.receive_control(deadline()).expect("fixture request");
    assert_eq!(request.kind(), APPLICATION_CONTROL_KIND_MIN + 40);
    assert_eq!(request.payload(), b"request");
    ready
        .send_control(APPLICATION_CONTROL_KIND_MIN + 41, b"response", deadline())
        .expect("fixture response");
    assert!(matches!(ready.try_close(), ReceiverCloseOutcome::Closed));
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn run_driver() {
    let command = SessionCommand::new(std::env::current_exe().expect("fixture executable"))
        .arg0("native-ipc-receiver-main-downstream")
        .arg(RECEIVER_ARG)
        .env("A", "");
    let coordinator =
        CoordinatorSession::<Negotiating>::spawn(command, options(b"downstream-coordinator"))
            .expect("coordinator spawn");
    assert_eq!(
        coordinator.peer_application_payload(),
        b"downstream-receiver"
    );
    let mut ready = match coordinator
        .decide(NegotiationDecision::Accept)
        .expect("coordinator decision")
    {
        NegotiationOutcome::Accepted(ready) => ready,
        NegotiationOutcome::Rejected { .. } => panic!("downstream coordinator was rejected"),
    };
    ready
        .send_control(APPLICATION_CONTROL_KIND_MIN + 40, b"request", deadline())
        .expect("fixture request send");
    let response = ready
        .receive_control(deadline())
        .expect("queued final response survives receiver exit");
    assert_eq!(response.kind(), APPLICATION_CONTROL_KIND_MIN + 41);
    assert_eq!(response.payload(), b"response");
    match ready.try_close(deadline()) {
        CoordinatorCloseOutcome::Closed(facts) => {
            assert!(facts.direct_child_complete());
            assert_eq!(facts.native_error(), None);
        }
        _ => panic!("downstream coordinator did not close cleanly"),
    }
}

native_ipc::receiver_main!(|bootstrap: Result<ReceiverBootstrap, SessionFailure>| {
    #[cfg(target_os = "macos")]
    retain_framework_load_graph();
    let receiver_invocation = std::env::args().any(|argument| argument == RECEIVER_ARG);
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    if receiver_invocation {
        return run_receiver(bootstrap.expect("receiver preinit bootstrap"));
    }
    assert!(!receiver_invocation);
    assert!(bootstrap.is_err());
    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    run_driver();
});
