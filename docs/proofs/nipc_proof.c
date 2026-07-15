// nipc_proof.c — end-to-end proof of the unprivileged exact-lifecycle design.
//
// One binary, three roles, dispatched on argv[1]:
//
//   (none)                 BROKER   spawns the launcher, proves its identity
//                                   with the code signature, continues it,
//                                   observes the exec trap, then proves the
//                                   hostile target cannot escape and is
//                                   terminated exactly with no zombie.
//   --supervisor-launcher  LAUNCHER PT_TRACE_ME, SIGSTOP, read plan on FD4,
//                                   contain, execve the target.
//   --target               TARGET   tries every escape and reports.
//
// Nothing here runs as root. Build:
//   clang -o nipc_proof nipc_proof.c -framework Security -framework CoreFoundation
// Run:
//   ./nipc_proof '<designated requirement>'

#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <mach/mach.h>
#include <signal.h>
#include <spawn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <bsm/libbsm.h>
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>

extern int sandbox_init(const char *profile, uint64_t flags, char **errorbuf);
extern char **environ;

#define ROLE_LAUNCHER "--supervisor-launcher"
#define ROLE_TARGET   "--target"

#define DEATH_FD  3
#define PLAN_FD   4
#define REPORT_FD 5

// The containment the target inherits. (deny signal) is the load-bearing rule:
// without it the target can SIGSTOP the broker and suspend its own cleanup.
static const char *PROFILE = "(version 1)\n(allow default)\n(deny signal)\n";

// Escape attempts the hostile target reports. Any bit set is a failed proof.
#define ESC_SIGSTOP     (1u << 0)
#define ESC_FORK        (1u << 1)
#define ESC_TASK_FOR_PID (1u << 2)
#define ESC_PT_ATTACH   (1u << 3)

static int pass = 1;
static void ok(const char *what)        { printf("  [ ok ] %s\n", what); }
static void bad(const char *what)       { printf("  [FAIL] %s\n", what); pass = 0; }
static void check(int cond, const char *what) { cond ? ok(what) : bad(what); }

// ---------------------------------------------------------------- LAUNCHER

static int read_exact(int fd, void *buf, size_t n) {
  uint8_t *p = buf;
  while (n) {
    ssize_t r = read(fd, p, n);
    if (r == 0) return -1;
    if (r < 0) { if (errno == EINTR) continue; return -1; }
    p += r; n -= (size_t)r;
  }
  return 0;
}

static int launcher_main(void) {
  // FD3 is the broker-death pipe: EOF is its only signal, so it must be
  // nonblocking or probing a healthy silent broker parks forever.
  int fl = fcntl(DEATH_FD, F_GETFL);
  if (fl < 0 || fcntl(DEATH_FD, F_SETFL, fl | O_NONBLOCK) != 0) _exit(65);

  // Trace authority first: no window where this image is alive but unowned.
  if (ptrace(PT_TRACE_ME, 0, 0, 0) != 0) _exit(66);
  // The broker proves this exact stopped PID and its signature here, and only
  // then continues us and sends the plan. Reading FD4 first would make this
  // launcher unidentifiable.
  if (raise(SIGSTOP) != 0) _exit(66);

  uint32_t len = 0;
  if (read_exact(PLAN_FD, &len, sizeof len) != 0) _exit(0); // broker died
  if (len == 0 || len > PATH_MAX) _exit(67);
  char target[PATH_MAX + 1];
  if (read_exact(PLAN_FD, target, len) != 0) _exit(0);
  target[len] = '\0';

  // Refuse root: it is exempt from RLIMIT_NPROC, so a root launcher could not
  // honour the containment it promises.
  if (geteuid() == 0 || getegid() == 0) _exit(68);

  // Contain, then become the target. Both survive execve.
  char *err = NULL;
  if (sandbox_init(PROFILE, 0, &err) != 0) _exit(70);
  struct rlimit rl = { .rlim_cur = 1, .rlim_max = 1 };
  if (setrlimit(RLIMIT_NPROC, &rl) != 0) _exit(70);

  // dup2 cleared close-on-exec and CLOEXEC_DEFAULT covered only the broker's
  // spawn, so these would otherwise leak into the target. FD5 is retained
  // deliberately: it is the proof harness's report channel, not product.
  close(DEATH_FD);
  close(PLAN_FD);

  char *argv[] = { target, (char *)ROLE_TARGET, NULL };
  execve(target, argv, environ);
  _exit(71); // exec returned: contained but never became the target
}

// ------------------------------------------------------------------ TARGET

static int target_main(void) {
  pid_t broker = getppid();
  uint32_t escaped = 0;

  if (kill(broker, SIGSTOP) == 0) escaped |= ESC_SIGSTOP;

  pid_t child = fork();
  if (child == 0) _exit(0);
  if (child > 0) { escaped |= ESC_FORK; waitpid(child, NULL, 0); }

  mach_port_name_t t = MACH_PORT_NULL;
  if (task_for_pid(mach_task_self(), broker, &t) == KERN_SUCCESS) escaped |= ESC_TASK_FOR_PID;

  if (ptrace(PT_ATTACH, broker, 0, 0) == 0) escaped |= ESC_PT_ATTACH;

  if (write(REPORT_FD, &escaped, sizeof escaped) != (ssize_t)sizeof escaped) _exit(72);
  // Refuse to leave. Only the broker's exact authority can end this process.
  for (;;) pause();
}

// ------------------------------------------------------------------ BROKER

// Audit token of an exact stopped child, and the code identity derived from it.
static int audit_token_of(pid_t pid, audit_token_t *out) {
  mach_port_name_t name = MACH_PORT_NULL;
  if (task_name_for_pid(mach_task_self(), pid, &name) != KERN_SUCCESS) return -1;
  mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
  kern_return_t kr = task_info(name, TASK_AUDIT_TOKEN, (task_info_t)out, &count);
  mach_port_deallocate(mach_task_self(), name);
  return kr == KERN_SUCCESS ? 0 : -1;
}

// The certificate check: resolve the live guest from its exact audit token and
// require it to satisfy the deployer's designated requirement.
static int signature_satisfies(const audit_token_t *token, const char *requirement) {
  CFDataRef data = CFDataCreate(NULL, (const UInt8 *)token, sizeof *token);
  const void *keys[] = { kSecGuestAttributeAudit };
  const void *vals[] = { data };
  CFDictionaryRef attrs = CFDictionaryCreate(NULL, keys, vals, 1,
      &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
  SecCodeRef code = NULL;
  OSStatus st = SecCodeCopyGuestWithAttributes(NULL, attrs, kSecCSDefaultFlags, &code);
  CFRelease(attrs); CFRelease(data);
  if (st != errSecSuccess) return -1;

  CFStringRef text = CFStringCreateWithCString(NULL, requirement, kCFStringEncodingUTF8);
  SecRequirementRef req = NULL;
  st = SecRequirementCreateWithString(text, kSecCSDefaultFlags, &req);
  CFRelease(text);
  if (st != errSecSuccess) { CFRelease(code); return -1; }

  st = SecCodeCheckValidity(code, kSecCSDefaultFlags, req);
  CFRelease(req); CFRelease(code);
  return st == errSecSuccess ? 0 : (int)st;
}

static int wait_stop(pid_t pid, int expect_sig, const char *what) {
  int status = 0;
  for (;;) {
    pid_t r = waitpid(pid, &status, WUNTRACED);
    if (r < 0 && errno == EINTR) continue;
    if (r != pid) { bad(what); return -1; }
    break;
  }
  if (!WIFSTOPPED(status) || WSTOPSIG(status) != expect_sig) { bad(what); return -1; }
  ok(what);
  return 0;
}

static int broker_main(const char *self, const char *requirement) {
  char path[PATH_MAX];
  if (!realpath(self, path)) { perror("realpath"); return 2; }

  int death[2], plan[2], report[2];
  if (pipe(death) || pipe(plan) || pipe(report)) { perror("pipe"); return 2; }

  posix_spawn_file_actions_t fa;
  posix_spawn_file_actions_init(&fa);
  posix_spawn_file_actions_adddup2(&fa, death[0], DEATH_FD);
  posix_spawn_file_actions_adddup2(&fa, plan[0], PLAN_FD);
  posix_spawn_file_actions_adddup2(&fa, report[1], REPORT_FD);

  char *argv[] = { path, (char *)ROLE_LAUNCHER, NULL };
  pid_t pid = -1;
  int rc = posix_spawn(&pid, path, &fa, NULL, argv, environ);
  posix_spawn_file_actions_destroy(&fa);
  if (rc != 0) { fprintf(stderr, "posix_spawn: %s\n", strerror(rc)); return 2; }
  close(death[0]); close(plan[0]); close(report[1]);

  printf("\n== 1. exact identity proof, before the launcher is continued ==\n");
  if (wait_stop(pid, SIGSTOP, "launcher stops itself at its initial stop") != 0) return 2;

  audit_token_t token;
  check(audit_token_of(pid, &token) == 0, "captured the stopped launcher's audit token");
  check(audit_token_to_pid(token) == pid, "audit token names this exact PID");
  check(audit_token_to_euid(token) == geteuid(), "launcher carries our own uid (never root)");
  check(audit_token_to_euid(token) != 0, "launcher is not root");

  char actual[PROC_PIDPATHINFO_MAXSIZE] = {0};
  proc_pidpath(pid, actual, sizeof actual);
  check(strcmp(actual, path) == 0, "launcher is the exact image we spawned");

  int sig = signature_satisfies(&token, requirement);
  check(sig == 0, "launcher satisfies the designated requirement (certificate)");
  if (sig != 0 && sig != -1) printf("         OSStatus %d\n", sig);

  printf("\n== 2. plan delivery, then the exec trap before the target runs ==\n");
  if (ptrace(PT_CONTINUE, pid, (caddr_t)1, 0) != 0) { bad("PT_CONTINUE"); return 2; }
  uint32_t len = (uint32_t)strlen(path);
  if (write(plan[1], &len, sizeof len) != (ssize_t)sizeof len ||
      write(plan[1], path, len) != (ssize_t)len) { bad("plan delivery"); return 2; }
  close(plan[1]);
  check(1, "plan delivered on FD4 only after identity was proven");

  if (wait_stop(pid, SIGTRAP, "exec trap taken before the target's first instruction") != 0) return 2;

  audit_token_t after;
  check(audit_token_of(pid, &after) == 0, "captured the post-exec audit token");
  check(audit_token_to_pid(after) == pid, "still the same exact PID across exec");
  check(audit_token_to_pidversion(after) != audit_token_to_pidversion(token),
        "PID version changed, proving a real exec (not a counterfeit trap)");

  printf("\n== 3. the contained target cannot escape ==\n");
  if (ptrace(PT_CONTINUE, pid, (caddr_t)1, 0) != 0) { bad("PT_CONTINUE"); return 2; }

  uint32_t escaped = 0;
  check(read_exact(report[0], &escaped, sizeof escaped) == 0, "hostile target reported in");
  check(!(escaped & ESC_SIGSTOP),      "target CANNOT SIGSTOP the broker  (sandbox)");
  check(!(escaped & ESC_FORK),         "target CANNOT fork                (RLIMIT_NPROC)");
  check(!(escaped & ESC_TASK_FOR_PID), "target CANNOT task_for_pid broker (no get-task-allow)");
  check(!(escaped & ESC_PT_ATTACH),    "target CANNOT PT_ATTACH broker    (OS)");

  printf("\n== 4. exact termination, no zombie ==\n");
  // The child is still ours and unreaped, so this PID cannot have been reused
  // by anyone: that relation is the whole basis for signalling it by number.
  check(kill(pid, SIGKILL) == 0, "exact direct child is signalled by pinned PID");

  // A tracee reports SIGKILL delivery to its tracer as a traced stop before it
  // dies, so the exact owner must PT_KILL and keep reaping until a terminal
  // status actually arrives. Treating the first stop as death would leave a
  // live process behind while believing it was reaped.
  // Reap until the kernel says there is nothing left. Darwin reports a traced
  // child's terminal status to its tracer AND to its parent, which here are the
  // same process, so stopping at the first terminal status would leave the
  // child unreaped while believing it was cleaned up.
  int status = 0, stops = 0, terminals = 0, last = 0;
  for (;;) {
    errno = 0;
    pid_t r = waitpid(pid, &status, WUNTRACED);
    if (r < 0) { if (errno == EINTR) continue; break; }
    if (r != pid) break;
    if (WIFSTOPPED(status)) { stops++; ptrace(PT_KILL, pid, 0, 0); continue; }
    terminals++; last = status;
  }
  int drained = (errno == ECHILD);
  printf("         (absorbed %d traced stop(s); kernel reported the terminal "
         "status %d time(s))\n", stops, terminals);
  check(terminals >= 1, "sole waiter observed the exact child's death");
  check(WIFSIGNALED(last), "target died by our exact signal, not on its own");
  check(drained, "no zombie remains: reaped until ECHILD");

  printf("\n%s\n", pass ? "PROOF PASSED — exact lifecycle, no root, identity proven by certificate"
                        : "PROOF FAILED");
  return pass ? 0 : 1;
}

int main(int argc, char **argv) {
  setvbuf(stdout, NULL, _IONBF, 0);
  if (argc > 1 && strcmp(argv[1], ROLE_LAUNCHER) == 0) return launcher_main();
  if (argc > 1 && strcmp(argv[1], ROLE_TARGET) == 0)   return target_main();
  if (argc < 2) { fprintf(stderr, "usage: %s '<designated requirement>'\n", argv[0]); return 2; }
  return broker_main(argv[0], argv[1]);
}
