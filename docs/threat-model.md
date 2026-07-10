# Repository Threat Model

## Overview

This repository is a Rust library foundation for local, cross-process message
and shared-memory IPC. Its security purpose is to preserve memory safety and
least authority when one authenticated peer is buggy or malicious. Primary
runtime surfaces are the explicit wire decoder, checked region layout parser,
atomic slot/acknowledgement state machine, and native OS mapping layer.

The library is not a sandbox, process launcher, or authentication policy. A
complete embedding must separately establish peer identity, private bootstrap
channels, lifecycle containment, and platform sandbox policy.

## Threat Model, Trust Boundaries, and Assumptions

Assets include the trusted process's memory integrity, availability, native
capabilities, generation identity, payload confidentiality, and the guarantee
that a peer reader cannot mutate writer-owned mappings or introduce executable
shared pages.

The main trust boundaries are:

1. hostile wire bytes entering a protocol decoder;
2. immutable region headers and mutable slot metadata entering through an OS
   mapping created or written by another process;
3. native descriptors, ports, or handles crossing a private control channel;
4. transitions from quiescent exclusive memory to concurrently accessible
   runtime memory; and
5. process lifecycle and reconnection, where stale generations and capabilities
   must become permanently unusable.

Peer-controlled inputs include every message byte, numeric kind/flag, declared
length, relative range, schema/generation/sequence value, slot payload and
length, acknowledgement value, capability count/type, and timing of mutation,
exit, or silence. Operator-controlled inputs include resource limits, region
roles/capacities, expected peer identity, and platform compatibility policy.
Developer-controlled inputs include protocol implementations and unsafe native
adapters.

Assumptions are that supported targets provide lock-free 64-bit atomics with
cross-process semantics, the native kernel correctly enforces maximum mapping
rights, the caller authenticates the intended peer, and callers uphold the
documented unsafe binding/quiescence contracts. Compromise of the kernel,
physical memory attacks, and a malicious trusted-process caller invoking unsafe
APIs incorrectly are out of scope.

## Attack Surface, Mitigations, and Attacker Stories

Relevant attacker stories include malformed lengths causing overflow or large
allocation; offsets escaping a containing record; generation replay after
restart; future acknowledgements authorizing ABA slot reuse; concurrent payload
mutation during a snapshot; a reader obtaining a writable mapping; executable
permission escalation; native capability substitution; and resource leaks or
hangs during peer failure.

Current mitigations are manual fixed-width little-endian codecs, exact schema
identity, explicit record/allocation limits, checked ranges and layout
arithmetic, nonzero generations and sequences, exact slot/acknowledgement state
transitions, Release/Acquire publication with post-copy recheck, separate safe
reader/writer capability types, slice-free runtime APIs, consuming macOS
typestates, and live kernel permission probes.

The Linux and Windows native transports, native capability transfer, peer
authentication, lifecycle containment, and cleanup ledger are not implemented.
Their APIs fail closed rather than claiming weaker functionality. Network
attack classes, web authentication bugs, injection into databases or shells,
and confidentiality against a peer explicitly granted read access are outside
this library's direct surface.

## Severity Calibration (Critical, High, Medium, Low)

Critical issues include safe-code remote memory corruption or arbitrary code
execution in the trusted process, or a reader capability that reliably permits
creating an executable writable mapping. High issues include cross-process
write authority where read-only was promised, unchecked peer lengths reaching
unsafe slice construction, stale-generation acceptance, or exact-ack bypass
allowing attacker-controlled concurrent aliasing.

Medium issues include bounded denial of service that escapes configured limits,
capability/resource leaks across repeated peer crashes, or failure to reject a
wrong authenticated peer when the embedding followed documented setup. Low
issues include non-secret diagnostic leakage, developer-only tooling weakness,
or documentation/API footguns that require the trusted caller to violate an
explicit unsafe contract without offering a safe exploit path.
