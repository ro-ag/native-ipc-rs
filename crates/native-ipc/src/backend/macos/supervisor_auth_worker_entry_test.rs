use super::*;

unsafe extern "C" {
    fn close(fd: c_int) -> c_int;
    fn pipe(descriptors: *mut c_int) -> c_int;
}

#[test]
fn fixed_worker_arguments_are_exact() {
    assert_eq!(
        validate_fixed_arguments([
            INSTALLED_AUTH_WORKER_PATH,
            INSTALLED_AUTH_WORKER_MODE,
            INSTALLED_AUTH_WORKER_REQUEST_ARGUMENT,
            INSTALLED_AUTH_WORKER_RESULT_ARGUMENT,
        ]),
        Ok(())
    );
    assert!(
        validate_fixed_arguments([
            INSTALLED_AUTH_WORKER_PATH,
            INSTALLED_AUTH_WORKER_MODE,
            INSTALLED_AUTH_WORKER_REQUEST_ARGUMENT,
        ])
        .is_err()
    );
    assert!(
        validate_fixed_arguments([
            INSTALLED_AUTH_WORKER_PATH,
            INSTALLED_AUTH_WORKER_MODE,
            "--request-fd=4",
            INSTALLED_AUTH_WORKER_RESULT_ARGUMENT,
        ])
        .is_err()
    );
}

#[test]
fn audit_token_decode_preserves_native_words() {
    let values = [1_u32, 2, 3, 4, 5, 6, 7, 8];
    let mut bytes = [0_u8; 32];
    for (destination, value) in bytes.chunks_exact_mut(4).zip(values) {
        destination.copy_from_slice(&value.to_ne_bytes());
    }
    assert_eq!(decode_audit_token(bytes).values, values);
}

#[test]
fn post_adoption_failure_cannot_close_exit_owned_result_fd() {
    let mut descriptors = [-1; 2];
    // SAFETY: storage holds exactly the two descriptors returned by pipe.
    assert_eq!(unsafe { pipe(descriptors.as_mut_ptr()) }, 0);
    // SAFETY: the successful pipe returned this owned writer.
    let writer = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
    let raw_writer = writer.as_raw_fd();

    fn reject_after_adoption(result: ExitOwnedResultFd) -> Result<(), c_int> {
        let _exit_owned = result;
        Err(97)
    }

    assert_eq!(
        reject_after_adoption(ExitOwnedResultFd::new(writer)),
        Err(97)
    );
    // SAFETY: F_GETFD only checks whether simulated error unwinding closed it.
    assert!(unsafe { fcntl(raw_writer, F_GETFD) } >= 0);
    // SAFETY: the exit-owned descriptor intentionally suppressed Rust drop;
    // this test process must close that raw descriptor explicitly.
    assert_eq!(unsafe { close(raw_writer) }, 0);
    // SAFETY: the successful pipe returned the still-owned reader.
    drop(unsafe { OwnedFd::from_raw_fd(descriptors[0]) });
}
