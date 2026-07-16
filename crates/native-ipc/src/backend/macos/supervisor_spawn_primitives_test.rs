use super::*;

unsafe extern "C" {
    fn waitpid(pid: c_int, status: *mut c_int, options: c_int) -> c_int;
}

#[test]
fn one_shared_primitive_builds_canonical_state_and_returns_raw_errors() {
    let mut invalid = SpawnFileActions::new().unwrap();
    assert_ne!(
        invalid.add_close(-1),
        Ok(()),
        "invalid actions must return their Darwin error to the caller",
    );

    let actions = SpawnFileActions::new().unwrap();
    let mut attributes = SpawnAttributes::new().unwrap();
    attributes.configure_canonical_signals().unwrap();

    let path = c"/usr/bin/true";
    let argv = [path.as_ptr().cast_mut(), std::ptr::null_mut()];
    let environment = [std::ptr::null_mut()];
    // SAFETY: both vectors are NUL-terminated and remain live; the returned
    // positive direct child is waited by exact PID below.
    let pid = unsafe { spawn(path, &actions, &attributes, &argv, &environment) }.unwrap();
    assert!(pid > 0);

    let mut status = 0;
    loop {
        // SAFETY: `status` is writable and this test owns the exact child.
        let observed = unsafe { waitpid(pid, &raw mut status, 0) };
        if observed == pid {
            break;
        }
        assert_eq!(
            std::io::Error::last_os_error().kind(),
            std::io::ErrorKind::Interrupted,
        );
    }
    assert_eq!(status, 0, "the canonical shared spawn must exit cleanly");

    // SAFETY: the exact child was already reaped above.
    assert_eq!(unsafe { waitpid(pid, &raw mut status, 0) }, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(ECHILD),
        "the shared primitive fixture must leave no zombie",
    );
}
