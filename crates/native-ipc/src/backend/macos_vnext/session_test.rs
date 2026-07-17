use super::vnext_session::{
    MacCoordinatorNegotiatingSession, MacNegotiationOutcome, MacReceiverNegotiatingSession,
};
use crate::session::{
    AbsoluteDeadline, ExecutableIdentityPolicy, SessionCommand, SessionLimits, SessionOptions,
};
use std::time::Duration;

fn deadline() -> AbsoluteDeadline {
    AbsoluteDeadline::after(Duration::from_secs(10)).unwrap()
}

fn helper_command(test: &str) -> SessionCommand {
    let executable = std::env::current_exe().unwrap();
    SessionCommand::new(&executable)
        .arg0("native-ipc-macos-session-helper")
        .arg("--exact")
        .arg(test)
        .arg("--ignored")
        .arg("--nocapture")
}

#[test]
fn production_spawn_rejects_relative_and_symlink_images() {
    let options = SessionOptions::new(deadline(), ExecutableIdentityPolicy::ExactOpenedFile);
    assert_eq!(
        MacCoordinatorNegotiatingSession::spawn(&SessionCommand::new("relative-helper"), &options,)
            .err()
            .map(|failure| failure.error),
        Some(super::vnext_session::MacPublicSessionError::InvalidInput)
    );

    use std::os::unix::fs::symlink;
    let unique = format!(
        "native-ipc-macos-symlink-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let directory = std::env::temp_dir().join(unique);
    std::fs::create_dir(&directory).unwrap();
    let link = directory.join("helper");
    symlink(std::env::current_exe().unwrap(), &link).unwrap();
    let error = MacCoordinatorNegotiatingSession::spawn(&SessionCommand::new(&link), &options)
        .err()
        .unwrap()
        .error;
    assert!(matches!(
        error,
        super::vnext_session::MacPublicSessionError::Native(Some(_))
    ));

    let real_directory = directory.join("real");
    std::fs::create_dir(&real_directory).unwrap();
    let real_helper = real_directory.join("helper");
    std::fs::hard_link(std::env::current_exe().unwrap(), &real_helper).unwrap();
    let linked_directory = directory.join("linked");
    symlink(&real_directory, &linked_directory).unwrap();
    let error = MacCoordinatorNegotiatingSession::spawn(
        &SessionCommand::new(linked_directory.join("helper")),
        &options,
    )
    .err()
    .unwrap()
    .error;
    assert!(matches!(
        error,
        super::vnext_session::MacPublicSessionError::Native(Some(_))
    ));
    std::fs::remove_file(linked_directory).unwrap();
    std::fs::remove_file(real_helper).unwrap();
    std::fs::remove_dir(real_directory).unwrap();
    std::fs::remove_file(link).unwrap();
    std::fs::remove_dir(directory).unwrap();
}

#[test]
fn launch_binds_the_retained_file_to_the_started_image_across_swap_and_restore() {
    let unique = format!(
        "native-ipc-macos-image-swap-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let directory = std::env::temp_dir().canonicalize().unwrap().join(unique);
    std::fs::create_dir(&directory).unwrap();
    let helper = directory.join("helper");
    let backup = directory.join("backup");
    let evil = directory.join("evil");
    std::fs::copy(std::env::current_exe().unwrap(), &helper).unwrap();
    std::fs::copy(std::env::current_exe().unwrap(), &backup).unwrap();
    // A differently-signed, different-content, long-lived platform binary
    // stands in for the replacement a normal installer or updater performs.
    std::fs::copy("/bin/sleep", &evil).unwrap();

    let command = SessionCommand::new(&helper).arg("1000");
    let options = SessionOptions::new(deadline(), ExecutableIdentityPolicy::ExactOpenedFile);
    let failure = MacCoordinatorNegotiatingSession::spawn_with_image_hooks_for_test(
        &command,
        &options,
        || std::fs::rename(&evil, &helper).unwrap(),
        || std::fs::rename(&backup, &helper).unwrap(),
    )
    .err()
    .expect("a swapped launch image must never negotiate");

    // The pathname holds the original file again, so any pathname-derived
    // recheck would pass; only the running-image binding can reject this.
    assert_eq!(
        failure.error,
        super::vnext_session::MacPublicSessionError::IdentityMismatch
    );
    assert_eq!(
        failure.state,
        super::vnext_session::MacCoordinatorFailureState::Spawned
    );
    assert!(failure.poisoned);
    let cleanup = failure
        .cleanup
        .expect("spawned child retains cleanup facts");
    assert!(cleanup.direct_child_complete());

    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn production_spawn_binds_image_hellos_and_bilateral_accept() {
    let command = helper_command("backend::macos::vnext_session_test::production_receiver_helper")
        .env("NATIVE_IPC_VNEXT_TEST_DECISION", "accept");
    let options = SessionOptions::new(deadline(), ExecutableIdentityPolicy::ExactOpenedFile)
        .with_application_payload(b"coordinator-hello".to_vec())
        .require_atomic_u32()
        .require_atomic_u64();
    let negotiating = MacCoordinatorNegotiatingSession::spawn(&command, &options).unwrap();
    assert_eq!(negotiating.peer_application_payload(), b"receiver-hello");
    let accepted = match negotiating.decide(None).unwrap() {
        MacNegotiationOutcome::Accepted(accepted) => accepted,
        MacNegotiationOutcome::Rejected { .. } => panic!("receiver rejected valid negotiation"),
    };
    accepted.wait_for_child_exit_for_test(deadline()).unwrap();
}

#[test]
fn production_accept_wins_over_receiver_exit_before_image_recheck() {
    let command = helper_command("backend::macos::vnext_session_test::production_receiver_helper")
        .env("NATIVE_IPC_VNEXT_TEST_DECISION", "accept");
    let options = SessionOptions::new(deadline(), ExecutableIdentityPolicy::ExactOpenedFile)
        .with_application_payload(b"coordinator-hello".to_vec())
        .require_atomic_u32()
        .require_atomic_u64();
    let mut negotiating = MacCoordinatorNegotiatingSession::spawn(&command, &options).unwrap();
    negotiating.wait_for_peer_exit_before_image_recheck_for_test();
    let accepted = match negotiating.decide(None).unwrap() {
        MacNegotiationOutcome::Accepted(accepted) => accepted,
        MacNegotiationOutcome::Rejected { .. } => panic!("receiver rejected valid negotiation"),
    };
    accepted.wait_for_child_exit_for_test(deadline()).unwrap();
}

#[test]
fn coordinator_rejection_is_canonical_and_bounded() {
    let command = helper_command("backend::macos::vnext_session_test::production_receiver_helper")
        .env("NATIVE_IPC_VNEXT_TEST_DECISION", "coordinator-reject");
    let options = SessionOptions::new(deadline(), ExecutableIdentityPolicy::ExactOpenedFile)
        .with_application_payload(b"coordinator-hello".to_vec());
    let negotiating = MacCoordinatorNegotiatingSession::spawn(&command, &options).unwrap();
    match negotiating
        .decide(Some(std::num::NonZeroU32::new(3).unwrap()))
        .unwrap()
    {
        MacNegotiationOutcome::Rejected {
            by: super::vnext_session::MacNegotiationRole::Coordinator,
            reason,
            cleanup: Some(cleanup),
        } => {
            assert_eq!(reason.get(), 3);
            assert!(cleanup.direct_child_complete());
            assert_eq!(
                cleanup.descendants(),
                crate::session::DescendantCleanupStatus::FreshGroupTerminated
            );
        }
        _ => panic!("coordinator rejection did not retain cleanup facts"),
    }
}

#[test]
fn receiver_rejection_is_challenge_bound_and_bounded() {
    let command = helper_command("backend::macos::vnext_session_test::production_receiver_helper")
        .env("NATIVE_IPC_VNEXT_TEST_DECISION", "receiver-reject");
    let options = SessionOptions::new(deadline(), ExecutableIdentityPolicy::ExactOpenedFile)
        .with_application_payload(b"coordinator-hello".to_vec());
    let negotiating = MacCoordinatorNegotiatingSession::spawn(&command, &options).unwrap();
    match negotiating.decide(None).unwrap() {
        MacNegotiationOutcome::Rejected {
            by: super::vnext_session::MacNegotiationRole::Receiver,
            reason,
            cleanup: Some(cleanup),
        } => {
            assert_eq!(reason.get(), 2);
            assert!(cleanup.direct_child_complete());
        }
        _ => panic!("receiver rejection did not retain coordinator cleanup facts"),
    }
}

#[test]
fn stalled_post_authentication_hello_expires_under_the_caller_deadline() {
    let command = helper_command("backend::macos::vnext_session_test::stalled_before_hello_helper");
    let short = AbsoluteDeadline::after(Duration::from_millis(50)).unwrap();
    let options = SessionOptions::new(short, ExecutableIdentityPolicy::ExactOpenedFile);
    assert_eq!(
        MacCoordinatorNegotiatingSession::spawn(&command, &options)
            .err()
            .map(|failure| failure.error),
        Some(super::vnext_session::MacPublicSessionError::DeadlineExpired)
    );
}

#[test]
#[ignore = "spawned alone by the production macOS session integration test"]
fn production_receiver_helper() {
    let negotiating = MacReceiverNegotiatingSession::from_environment(
        SessionLimits::default(),
        b"receiver-hello".to_vec(),
        true,
        true,
        deadline(),
    )
    .unwrap();
    assert_eq!(negotiating.peer_application_payload(), b"coordinator-hello");
    let mode = std::env::var("NATIVE_IPC_VNEXT_TEST_DECISION").unwrap();
    let outcome = negotiating
        .decide_after_coordinator(|_| match mode.as_str() {
            "receiver-reject" => Some(std::num::NonZeroU32::new(2).unwrap()),
            "accept" => None,
            "coordinator-reject" => panic!("receiver decision ran after coordinator rejection"),
            _ => panic!("unknown test decision"),
        })
        .unwrap();
    match mode.as_str() {
        "accept" => assert!(matches!(outcome, MacNegotiationOutcome::Accepted(_))),
        "coordinator-reject" => assert!(matches!(
            outcome,
            MacNegotiationOutcome::Rejected {
                by: super::vnext_session::MacNegotiationRole::Coordinator,
                reason,
                ..
            } if reason.get() == 3
        )),
        "receiver-reject" => assert!(matches!(
            outcome,
            MacNegotiationOutcome::Rejected {
                by: super::vnext_session::MacNegotiationRole::Receiver,
                reason,
                ..
            } if reason.get() == 2
        )),
        _ => unreachable!(),
    }
}

#[test]
#[ignore = "spawned alone by the deadline-bound macOS HELLO test"]
fn stalled_before_hello_helper() {
    let _channel =
        super::bootstrap::ChildChannel::connect_from_environment_until(deadline()).unwrap();
    std::thread::sleep(Duration::from_secs(30));
}
