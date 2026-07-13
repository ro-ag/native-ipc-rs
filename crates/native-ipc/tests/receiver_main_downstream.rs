//! Downstream executable regression for the public receiver entry-point macro.

#[cfg(target_os = "linux")]
use std::time::Duration;

#[cfg(target_os = "linux")]
use native_ipc::control::APPLICATION_CONTROL_KIND_MIN;
#[cfg(target_os = "linux")]
use native_ipc::session::{
    AbsoluteDeadline, CoordinatorCloseOutcome, CoordinatorSession, ExecutableIdentityPolicy,
    Negotiating, NegotiationDecision, NegotiationOutcome, ReceiverCloseOutcome, ReceiverSession,
    SessionCommand, SessionLimits, SessionOptions,
};
use native_ipc::session::{ReceiverBootstrap, SessionFailure};

const RECEIVER_ARG: &str = "--native-ipc-downstream-receiver";

#[cfg(target_os = "linux")]
fn deadline() -> AbsoluteDeadline {
    AbsoluteDeadline::after(Duration::from_secs(5)).expect("fixture deadline")
}

#[cfg(target_os = "linux")]
fn options(payload: &[u8]) -> SessionOptions {
    SessionOptions::new(deadline(), ExecutableIdentityPolicy::ExactOpenedFile)
        .with_limits(SessionLimits {
            max_control_payload_bytes: 32,
            ..SessionLimits::default()
        })
        .with_application_payload(payload.to_vec())
}

#[cfg(target_os = "linux")]
fn run_receiver(bootstrap: ReceiverBootstrap) {
    let receiver =
        ReceiverSession::<Negotiating>::from_bootstrap(bootstrap, options(b"downstream-receiver"))
            .expect("receiver bootstrap negotiation");
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

#[cfg(target_os = "linux")]
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
    let receiver_invocation = std::env::args().any(|argument| argument == RECEIVER_ARG);
    #[cfg(target_os = "linux")]
    if receiver_invocation {
        return run_receiver(bootstrap.expect("receiver preinit bootstrap"));
    }
    assert!(!receiver_invocation);
    assert!(bootstrap.is_err());
    #[cfg(target_os = "linux")]
    run_driver();
});
