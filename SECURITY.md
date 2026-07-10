# Security Policy

## Supported versions

Before the first stable release, only the latest `0.1.x` release and current
`main` branch receive security fixes.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting for this repository. Do not
open a public issue for a suspected vulnerability. Include affected versions,
platform, threat assumptions, reproduction steps, and whether the issue crosses
the documented safe/unsafe API boundary. Expect acknowledgement within seven
days; remediation timelines depend on impact and reproducibility.

## Security scope

Memory-safety failures reachable from safe Rust, unintended writable or
executable shared mappings, schema/generation/sequence bypasses, unchecked
hostile lengths or offsets, cross-process aliasing violations, and capability
leaks are in scope. Process separation alone is not claimed as a sandbox.
Incorrect use of explicitly unsafe APIs, kernel compromise, and platforms the
crate explicitly reports as incomplete are not production security guarantees,
but clear documentation or fail-closed regressions are still welcome.

See [the threat model](docs/threat-model.md) and
[architecture](docs/architecture.md) for detailed boundaries and invariants.
