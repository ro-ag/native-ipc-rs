# native-ipc

`native-ipc` is the public facade for the `native-ipc-rs` workspace. It
re-exports:

- `native-ipc-core` for pointer-free codecs, checked shared-memory layouts,
  sequencing, and audited reader/writer bindings; and
- `native-ipc-platform` for least-authority native mappings, authenticated
  capability transfer, and owned helper-process lifecycles on Linux, macOS,
  and Windows.

Supported targets are Linux and Windows on ARM64 or AMD64, and macOS on ARM64:
`aarch64-unknown-linux-gnu`, `x86_64-unknown-linux-gnu`,
`aarch64-pc-windows-msvc`, `x86_64-pc-windows-msvc`, and
`aarch64-apple-darwin`. Other OS/architecture combinations fail compilation
instead of selecting an unaudited fallback.

The `native_ipc::memory` module provides one allocation and lifecycle API for
the best native object on the current target: sealed `memfd` on Linux, Mach VM
memory entries on macOS, and unnamed sections on Windows. Regions may be fixed
or replacement-growable before sharing, can be cleared for reuse, and can be
explicitly destroyed with a complete clearing pass.

Payload bytes received through shared memory remain hostile input. Readers copy
them into owned storage and recheck bounded metadata, but the library does not
claim integrity against a malicious same-sequence writer.

See the [repository README](https://github.com/ro-ag/native-ipc-rs#readme),
[architecture](https://github.com/ro-ag/native-ipc-rs/blob/main/docs/architecture.md),
and [threat model](https://github.com/ro-ag/native-ipc-rs/blob/main/docs/threat-model.md)
for the complete security contract.

Licensed under MIT or Apache-2.0 at your option.
