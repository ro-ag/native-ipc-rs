use super::*;

unsafe extern "C" {
    fn getpgid(pid: c_int) -> c_int;
    fn getsid(pid: c_int) -> c_int;
    fn kill(pid: c_int, signal: c_int) -> c_int;
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

#[test]
fn every_supervisor_child_starts_a_fresh_session_and_process_group() {
    let actions = SpawnFileActions::new().unwrap();
    let mut attributes = SpawnAttributes::new().unwrap();
    attributes.configure_canonical_signals().unwrap();

    let path = c"/bin/sleep";
    let duration = c"30";
    let argv = [
        path.as_ptr().cast_mut(),
        duration.as_ptr().cast_mut(),
        std::ptr::null_mut(),
    ];
    let environment = [std::ptr::null_mut()];
    // SAFETY: both vectors are NUL-terminated and remain live. The sleeping
    // child keeps its identity observable until this test kills and reaps it.
    let pid = unsafe { spawn(path, &actions, &attributes, &argv, &environment) }.unwrap();
    assert!(pid > 0);

    // SAFETY: both calls are read-only queries for the live exact child. Save
    // the observations and clean up before asserting, so a regression cannot
    // strand the fixture child.
    let session = unsafe { getsid(pid) };
    // SAFETY: same live exact-child query as above.
    let process_group = unsafe { getpgid(pid) };

    // SAFETY: the positive PID is still an unreaped direct child owned here.
    let killed = unsafe { kill(pid, SIGKILL) };
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
    // SAFETY: the exact child was already reaped above.
    assert_eq!(unsafe { waitpid(pid, &raw mut status, 0) }, -1);
    assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(ECHILD));
    assert_eq!(killed, 0, "fixture child must accept exact cleanup");
    assert_eq!(session, pid, "child must lead a fresh session");
    assert_eq!(process_group, pid, "child must lead a fresh process group",);
}
