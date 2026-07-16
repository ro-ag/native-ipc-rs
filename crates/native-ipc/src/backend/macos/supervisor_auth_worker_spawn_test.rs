use std::ffi::{CStr, CString, c_char, c_int};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::process::Command;
use std::rc::Rc;
use std::time::{Duration, Instant};

use super::*;
use crate::backend::macos::supervisor::SupervisorDeadline;

const WORKER_TEST: &str =
    "backend::macos::supervisor::auth_adapter::auth_worker_spawn::tests::fixed_worker_fixture";
const CODE_IDENTITY: [u8; 32] = [0x5a; 32];
const PREMAIN_ENV: &[u8] = b"NATIVE_IPC_TEST_AUTH_WORKER_ENTRY\0";
const DEPLOYER_AUTH_WORKER_PATH: &CStr =
    c"/example/NativeIPC.app/Contents/Helpers/native-ipc-auth-worker";

unsafe extern "C" {
    static mach_task_self_: u32;
    fn getenv(name: *const c_char) -> *mut c_char;
    fn getegid() -> u32;
    fn geteuid() -> u32;
    fn task_info(task: u32, flavor: c_int, info: *mut c_int, count: *mut u32) -> c_int;
}

#[used]
#[unsafe(link_section = "__DATA,__mod_init_func")]
static PREMAIN_AUTH_WORKER_HOOK: extern "C" fn() = premain_auth_worker_hook;

extern "C" fn premain_auth_worker_hook() {
    // SAFETY: getenv reads one fixed NUL-terminated name before main.
    let enabled = unsafe { getenv(PREMAIN_ENV.as_ptr().cast()) };
    if enabled.is_null() {
        return;
    }
    // SAFETY: this pre-main child was created only by the production-shaped
    // fixed spawner below and carries the exact FD3/FD4 process ABI.
    unsafe {
        super::super::auth_worker_entry::run_fixed_auth_worker_process(
            DEPLOYER_AUTH_WORKER_PATH,
            c"always",
            CODE_IDENTITY,
        )
    }
}

fn test_wait_domain() -> DedicatedChildWaitDomain {
    DedicatedChildWaitDomain {
        _not_send_or_sync: std::marker::PhantomData::<Rc<()>>,
        bypass_spawn_recheck: true,
    }
}

fn test_image() -> InstalledAuthWorkerImage {
    let executable = std::env::current_exe().unwrap();
    InstalledAuthWorkerImage {
        spawn_path: CString::new(executable.as_os_str().as_bytes()).unwrap(),
        argument0: CString::new(executable.as_os_str().as_bytes()).unwrap(),
        mode: CString::new("--exact").unwrap(),
        request_argument: CString::new(WORKER_TEST).unwrap(),
        result_argument: CString::new("--ignored").unwrap(),
        environment_path: CString::new(CANONICAL_PATH).unwrap(),
        environment_lang: CString::new(CANONICAL_LANG).unwrap(),
        environment_locale: CString::new(CANONICAL_LOCALE).unwrap(),
    }
}

fn real_entry_image() -> InstalledAuthWorkerImage {
    let executable = std::env::current_exe().unwrap();
    InstalledAuthWorkerImage {
        spawn_path: CString::new(executable.as_os_str().as_bytes()).unwrap(),
        argument0: DEPLOYER_AUTH_WORKER_PATH.to_owned(),
        mode: CString::new(INSTALLED_AUTH_WORKER_MODE).unwrap(),
        request_argument: CString::new(INSTALLED_AUTH_WORKER_REQUEST_ARGUMENT).unwrap(),
        result_argument: CString::new(INSTALLED_AUTH_WORKER_RESULT_ARGUMENT).unwrap(),
        environment_path: CString::new(CANONICAL_PATH).unwrap(),
        environment_lang: CString::new(CANONICAL_LANG).unwrap(),
        environment_locale: CString::new("NATIVE_IPC_TEST_AUTH_WORKER_ENTRY=1").unwrap(),
    }
}

fn generation(value: u64) -> FreshAuthWorkerGeneration {
    // SAFETY: every test supplies a distinct nonzero service generation.
    unsafe { FreshAuthWorkerGeneration::from_unique_service_value(value).unwrap() }
}

fn job_id(value: u8) -> super::super::FreshAuthJobId {
    let mut bytes = [value; 32];
    bytes[0] = value.max(1);
    // SAFETY: this nonzero test identifier is used by only one live job.
    unsafe { super::super::FreshAuthJobId::from_fresh_random(bytes).unwrap() }
}

fn deadline_after(duration: Duration) -> SupervisorDeadline {
    SupervisorDeadline::from_instant(Instant::now() + duration).unwrap()
}

#[test]
fn installed_worker_vectors_are_fixed_and_canonical() {
    // SAFETY: this test inspects only the source-level deployer-bound vector.
    let image =
        unsafe { InstalledAuthWorkerImage::from_verified_installation(DEPLOYER_AUTH_WORKER_PATH) }
            .unwrap();
    assert_eq!(
        image.spawn_path.to_bytes(),
        DEPLOYER_AUTH_WORKER_PATH.to_bytes()
    );
    assert_eq!(
        image.argument0.to_bytes(),
        DEPLOYER_AUTH_WORKER_PATH.to_bytes()
    );
    assert_eq!(image.mode.to_bytes(), INSTALLED_AUTH_WORKER_MODE.as_bytes());
    assert_eq!(
        image.request_argument.to_bytes(),
        INSTALLED_AUTH_WORKER_REQUEST_ARGUMENT.as_bytes()
    );
    assert_eq!(
        image.result_argument.to_bytes(),
        INSTALLED_AUTH_WORKER_RESULT_ARGUMENT.as_bytes()
    );
    assert_eq!(image.environment_path.to_bytes(), CANONICAL_PATH.as_bytes());
    assert_eq!(image.environment_lang.to_bytes(), CANONICAL_LANG.as_bytes());
    assert_eq!(
        image.environment_locale.to_bytes(),
        CANONICAL_LOCALE.as_bytes()
    );
    // SAFETY: the invalid test value is rejected before any spawn vector exists.
    assert!(matches!(
        unsafe { InstalledAuthWorkerImage::from_verified_installation(c"relative-worker") },
        Err(AuthWorkerSpawnError::InvalidFixedImage)
    ));
}

#[test]
fn surrounding_service_image_has_no_static_security_framework_dependency() {
    let output = Command::new("/usr/bin/otool")
        .arg("-L")
        .arg(std::env::current_exe().unwrap())
        .output()
        .unwrap();
    assert!(output.status.success());
    let load_commands = String::from_utf8(output.stdout).unwrap();
    assert!(!load_commands.contains("Security.framework"));
    assert!(!load_commands.contains("CoreFoundation.framework"));
}

#[test]
fn fixed_worker_spawn_round_trips_private_job_and_exact_clean_reap() {
    let mut domain = test_wait_domain();
    let spawned = spawn_installed_auth_worker(&test_image(), generation(8001), &mut domain)
        .expect("fixed worker spawn");
    let mut pool = AuthWorkerPool::from_spawned_workers(vec![spawned]).unwrap();
    // SAFETY: the fixture models exact bytes and facts from one Mach trailer.
    let raw = unsafe {
        super::super::RawMachRecord::from_test_exact_audit_trailer(
            [0x41; 32],
            501,
            20,
            vec![1, 2, 3],
        )
    };
    let receipt = pool
        .dispatch(raw, job_id(0x81), deadline_after(Duration::from_secs(25)))
        .unwrap()
        .submit()
        .unwrap();
    let worker = receipt.worker();
    let received = poll_result(receipt);
    let mut completed = pool.complete(received);
    while matches!(completed, Err(AuthAdapterError::WorkerRetirementPending(_))) {
        std::thread::sleep(Duration::from_millis(1));
        completed = pool.poll_completed(worker);
    }
    assert!(completed.is_ok());

    let replacement =
        spawn_installed_auth_worker(&test_image(), generation(8003), &mut domain).unwrap();
    let identity = pool.install_spawned_replacement(0, replacement).unwrap();
    assert_eq!(identity.slot, 0);
    assert_eq!(identity.generation, 8003);
    // SAFETY: this is a second distinct modeled exact Mach message.
    let raw = unsafe {
        super::super::RawMachRecord::from_test_exact_audit_trailer(
            [0x42; 32],
            502,
            21,
            vec![4, 5, 6],
        )
    };
    let receipt = pool
        .dispatch(raw, job_id(0x82), deadline_after(Duration::from_secs(25)))
        .unwrap()
        .submit()
        .unwrap();
    let worker = receipt.worker();
    let received = poll_result(receipt);
    let mut completed = pool.complete(received);
    while matches!(completed, Err(AuthAdapterError::WorkerRetirementPending(_))) {
        std::thread::sleep(Duration::from_millis(1));
        completed = pool.poll_completed(worker);
    }
    assert!(completed.is_ok());
}

#[test]
fn fixed_spawner_real_security_entry_and_pool_exact_reap_compose() {
    let mut domain = test_wait_domain();
    let spawned =
        spawn_installed_auth_worker(&real_entry_image(), generation(8010), &mut domain).unwrap();
    let mut pool = AuthWorkerPool::from_spawned_workers(vec![spawned]).unwrap();
    let audit = current_audit_identity();
    // SAFETY: the values come from this exact live process and its task audit
    // token, modeling one exact Mach audit trailer.
    let raw = unsafe {
        super::super::RawMachRecord::from_test_exact_audit_trailer(
            audit,
            geteuid(),
            getegid(),
            vec![7, 8, 9],
        )
    };
    let receipt = pool
        .dispatch(raw, job_id(0x83), deadline_after(Duration::from_secs(25)))
        .unwrap()
        .submit()
        .unwrap();
    let worker = receipt.worker();
    let received = poll_result(receipt);
    let mut completed = pool.complete(received);
    while matches!(completed, Err(AuthAdapterError::WorkerRetirementPending(_))) {
        std::thread::sleep(Duration::from_millis(1));
        completed = pool.poll_completed(worker);
    }
    assert!(completed.is_ok());
}

#[test]
fn failed_fixed_path_spawn_mints_no_worker_bundle() {
    let mut image = test_image();
    image.spawn_path = CString::new("/definitely/not/a/native-ipc-worker").unwrap();
    let mut domain = test_wait_domain();
    assert!(matches!(
        spawn_installed_auth_worker(&image, generation(8002), &mut domain),
        Err(AuthWorkerSpawnError::Spawn(_))
    ));
}

fn poll_result(
    mut receipt: super::super::AuthWorkerReplyReceipt,
) -> super::super::ReceivedAuthWorkerResult {
    loop {
        match receipt.poll().unwrap() {
            super::super::AuthWorkerResultPoll::Pending(next) => {
                receipt = next;
                std::thread::sleep(Duration::from_millis(1));
            }
            super::super::AuthWorkerResultPoll::Complete(received) => return received,
        }
    }
}

fn current_audit_identity() -> [u8; 32] {
    let mut values = [0_u32; 8];
    let mut count = 8;
    // SAFETY: current task is live and the output is exact TASK_AUDIT_TOKEN
    // storage expressed as its eight natural_t words.
    assert_eq!(
        unsafe {
            task_info(
                mach_task_self_,
                15,
                values.as_mut_ptr().cast(),
                &raw mut count,
            )
        },
        0
    );
    assert_eq!(count, 8);
    let mut bytes = [0_u8; 32];
    for (destination, value) in bytes.chunks_exact_mut(4).zip(values) {
        destination.copy_from_slice(&value.to_ne_bytes());
    }
    bytes
}

#[test]
#[ignore = "spawned alone as the fixed clean-exec authentication worker fixture"]
fn fixed_worker_fixture() {
    // SAFETY: the production-shaped file actions transferred sole ownership of
    // fixed request FD3 and result FD4 to this just-execed helper.
    let mut request =
        File::from(unsafe { std::os::fd::OwnedFd::from_raw_fd(AUTH_WORKER_REQUEST_FD) });
    // SAFETY: same spawn transferred the paired sole result writer at FD4.
    let mut result =
        File::from(unsafe { std::os::fd::OwnedFd::from_raw_fd(AUTH_WORKER_RESULT_FD) });
    let mut bytes = [0_u8; super::super::AUTH_WORKER_JOB_BYTES];
    request.read_exact(&mut bytes).unwrap();
    let mut extra = [0_u8; 1];
    assert_eq!(request.read(&mut extra).unwrap(), 0);
    let job = super::super::AuthWorkerJob::decode_pipe_frame(&bytes).unwrap();
    // SAFETY: this isolated fixture models successful fixed-requirement
    // Security validation for the exact received audit-token job.
    let response =
        unsafe { super::super::AuthWorkerResult::from_security_validation(job, CODE_IDENTITY) };
    let response = response.encode_pipe_frame().unwrap();
    assert_eq!(result.write(&response).unwrap(), response.len());
    drop(result);
    assert!(request.as_raw_fd() >= 0);
}
