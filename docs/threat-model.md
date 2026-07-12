# Repository Threat Model

## Overview

This repository is a Rust library foundation for local, cross-process message
and shared-memory IPC. Its security purpose is to preserve memory safety and
least authority when one authenticated peer is buggy or malicious. Primary
runtime surfaces are the explicit wire decoder, checked region layout parser,
atomic slot/acknowledgement state machine, and native OS mapping layer.

A complete embedding establishes peer identity, private bootstrap channels,
lifecycle containment, and platform policy.

## Threat Model, Trust Boundaries, and Assumptions

Assets include the trusted process's memory integrity, availability, native
capabilities, generation identity, payload confidentiality, and the guarantee
that a peer reader cannot mutate writer-owned mappings. Library-created shared
views are non-executable. Linux's documented direction-specific authority—RX
aliases plus a receiver-writer fd delegate outside the MDWE tree retaining then
upgrading a pre-seal RW view—is an accepted kernel limit, not a claimed
object-level NX guarantee.

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
cross-process semantics, the native kernel correctly enforces the
backend-specific authority contract, the caller authenticates the intended
peer, and callers uphold the
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
arithmetic, nonzero generations and sequences, unique per-slot acknowledgement
routes, exact state transitions, Release publication with a fenced
generation/sequence/length recheck, platform-minted reader/writer mapping
witnesses, slice-free runtime APIs, consuming macOS typestates, validated zero
page padding, live kernel permission probes, private OS bootstrap channels,
kernel-derived exact peer PIDs, least-rights capability transfer, post-import
READY barriers, and parent-owned helper termination/reaping.

Copied payload bytes remain hostile and may be torn or change while metadata
stays constant. The recheck bounds access and detects metadata changes; it does
not establish payload integrity. Protocol decoders must reject inconsistent
owned payloads. A malicious sole writer can forge any unkeyed checksum or
seqlock state, so neither is described as integrity here.

Linux authenticates Unix peers with `SO_PEERCRED` and tracks exit with pidfds;
macOS authenticates Mach audit trailers; Windows checks both named-pipe endpoint
PIDs and assigns the still-suspended helper to a kill-on-close Job. Native
integration tests exercise capability transfer in real helper processes.

## Severity Calibration (Critical, High, Medium, Low)

Critical issues include safe-code remote memory corruption or arbitrary code
execution in the trusted process, or authority exceeding the documented native
backend limit. Linux RX aliases, dual RW/RX aliases inside the MDWE tree, and a
receiver-writer fd delegate outside that tree retaining then upgrading its
pre-seal RW view are explicit kernel limits of the malicious receiver
principal. A library-created executable view or failure to install MDWE remains
a security failure. High issues include cross-process
write authority where read-only was promised, unchecked peer lengths reaching
unsafe slice construction, stale-generation acceptance, or exact-ack bypass
allowing attacker-controlled concurrent aliasing.

Medium issues include bounded denial of service that escapes configured limits,
capability/resource leaks across repeated peer crashes, or failure to reject a
wrong authenticated peer when the embedding followed documented setup. Low
issues include non-secret diagnostic leakage, developer-only tooling weakness,
or documentation/API footguns that require the trusted caller to violate an
explicit unsafe contract without offering a safe exploit path.
