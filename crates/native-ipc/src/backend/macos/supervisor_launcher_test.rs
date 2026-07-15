use static_assertions::assert_not_impl_any;

use super::*;
use crate::backend::macos::supervisor::{
    ConnectionGeneration, FreshServiceNonce, SupervisorConnection, TargetEnvironmentEntry,
};
use crate::backend::macos::supervisor_watchdog::{
    ExactBrokerAuthority, ReapedBroker, TerminationReason,
};

struct StaticAuthority;

// SAFETY: this type exists only for compile-time trait assertions and is never constructed.
unsafe impl ExactBrokerAuthority for StaticAuthority {
    type Failure = std::convert::Infallible;

    fn activate_after_registration(&mut self) -> Result<(), Self::Failure> {
        unreachable!()
    }

    fn terminate_and_reap(
        &mut self,
        _reason: TerminationReason,
    ) -> Result<ReapedBroker, Self::Failure> {
        unreachable!()
    }

    fn emergency_terminate_and_reap(&mut self, _reason: Option<TerminationReason>) -> ReapedBroker {
        unreachable!()
    }
}

assert_not_impl_any!(TraceBoundValidatedSpawn<'static, StaticAuthority>: Clone, Copy);
assert_not_impl_any!(AuthenticatedClientIdentity: Clone, Copy);

fn verified_peer() -> VerifiedPeer {
    // SAFETY: this isolated fixture uses one nonzero generation and nonce.
    let generation = unsafe { ConnectionGeneration::from_unique_service_value(9001).unwrap() };
    // SAFETY: this nonzero value models one fresh service nonce.
    let nonce = unsafe { FreshServiceNonce::from_fresh_random([0x55; 32]).unwrap() };
    let connection = SupervisorConnection::new(generation, nonce);
    // SAFETY: the fixture models exact-message verification for this connection.
    unsafe {
        VerifiedPeer::from_test_authenticated_message(
            connection.connection_identity(),
            [0x22; 32],
            501,
            20,
            [0x66; 32],
        )
        .unwrap()
    }
}

#[test]
fn validated_exec_preparation_is_complete_and_null_terminated() {
    let peer = verified_peer();
    let prepared = PreparedExec::from_validated(LauncherSpawnParts {
        peer,
        deadline: std::time::Instant::now(),
        policy_id: b"com.example.receiver".to_vec(),
        target_identity: [0x77; 32],
        installed_executable: b"/Library/PrivilegedHelperTools/com.example.receiver".to_vec(),
        arguments: vec![b"receiver".to_vec(), b"--mode=test".to_vec()],
        environment: vec![TargetEnvironmentEntry::new(b"LANG".to_vec(), b"C".to_vec()).unwrap()],
    })
    .unwrap();
    assert_eq!(
        prepared.executable.to_bytes(),
        b"/Library/PrivilegedHelperTools/com.example.receiver"
    );
    assert_eq!(prepared.arguments[0].to_bytes(), b"receiver");
    assert_eq!(prepared.environment[0].to_bytes(), b"LANG=C");
    for (owned, pointer) in prepared.arguments.iter().zip(&prepared.argument_pointers) {
        assert_eq!(owned.as_ptr(), *pointer);
    }
    for (owned, pointer) in prepared
        .environment
        .iter()
        .zip(&prepared.environment_pointers)
    {
        assert_eq!(owned.as_ptr(), *pointer);
    }
    assert!(prepared.argument_pointers.last().unwrap().is_null());
    assert!(prepared.environment_pointers.last().unwrap().is_null());
}

#[test]
fn expired_deadline_rejects_before_credential_preflight() {
    assert_eq!(
        preflight_deadline(std::time::Instant::now() - std::time::Duration::from_secs(1)),
        Err(CredentialDropError::DeadlineExpired)
    );
}

#[test]
fn nonroot_process_rejects_before_any_credential_mutation() {
    // SAFETY: credential and group-count getters have no preconditions.
    let before = unsafe {
        (
            getuid(),
            geteuid(),
            getgid(),
            getegid(),
            getgroups(0, std::ptr::null_mut()),
        )
    };
    if before.0 == 0 || before.1 == 0 {
        // Positive root-to-user evidence belongs to the installed native
        // fixture; never mutate the test runner's process credentials here.
        return;
    }
    assert_eq!(preflight_root(), Err(CredentialDropError::LauncherNotRoot));
    // SAFETY: getters verify that the rejected call made no process mutation.
    let after = unsafe {
        (
            getuid(),
            geteuid(),
            getgid(),
            getegid(),
            getgroups(0, std::ptr::null_mut()),
        )
    };
    assert_eq!(after, before);
}
