# Native proofs

Standalone C proofs of macOS boundaries the Rust backend depends on. They are
not built by cargo and are not part of the crate; they exist so a claim can be
reproduced from scratch on a real machine, independently of the library.

## `nipc_proof.c` — unprivileged exact lifecycle

One binary, three roles (broker, launcher, hostile target), proving the whole
design end to end with **no root at any point**:

1. **Exact identity before the launcher is continued** — the broker captures the
   stopped launcher's audit token, checks it names that exact PID and our own
   non-root uid, checks the image path, and requires the live guest to satisfy
   the deployer's designated requirement through Security.framework.
2. **Plan then exec trap** — the plan is delivered on FD4 only after identity is
   proven, and the exec trap is taken before the target's first instruction. The
   PID version change proves a real exec rather than a counterfeit trap.
3. **The contained target cannot escape** — it cannot `SIGSTOP` the broker
   (sandbox `(deny signal)`), cannot `fork` (`RLIMIT_NPROC`), cannot
   `task_for_pid` the broker, and cannot `PT_ATTACH` it.
4. **Exact termination** — the broker signals the pinned PID of its own unreaped
   direct child, absorbs the traced stop, and reaps until `ECHILD`.

### Running it

Bring your own certificate. Nothing is hardcoded and no identity ships here.

```sh
IDENT="Developer ID Application: Your Name (TEAMID)"
BID=com.example.nipc-proof

clang -O1 -o nipc_proof docs/proofs/nipc_proof.c \
    -framework Security -framework CoreFoundation -lbsm
codesign --force --options runtime --identifier "$BID" --sign "$IDENT" ./nipc_proof

./nipc_proof "anchor apple generic and identifier \"$BID\" \
    and certificate leaf[subject.OU] = \"TEAMID\""
```

Exit status is 0 only if every check passed. To confirm the certificate check is
real rather than a rubber stamp, pass a requirement naming a different
identifier: it must fail with `errSecCSReqFailed` (-67050).

### What it does not prove

It is a reference proof of the mechanism, not of the shipped library. It does
not exercise the Rust backend, an installed artifact, or notarization. The
sandbox rests on `sandbox_init(3)`, which is deprecated, and on SBPL, which
Apple does not document.

It proves containment of the exact contained **process**, not of a same-user
**principal**. Adversarial review confirmed that a same-user sibling the broker
never sandboxed can still `SIGSTOP` the broker. This standalone proof uses only
`(deny signal)`, so it also does not prove launchd-delegation denial. The Rust
launcher separately measures an inherited profile that denies `mach-lookup`
and `mach-register`; that stronger source/native result must not be attributed
to this C proof. The guarantee demonstrated here is the narrower unprivileged
mechanism: the traced direct target cannot signal its broker, cannot fork, and
is terminated and reaped exactly. Installed-artifact and public-session claims
remain absent.
