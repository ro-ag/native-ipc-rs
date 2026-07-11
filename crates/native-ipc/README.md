# native-ipc

`native-ipc` is the public facade for the `native-ipc-rs` workspace. It
re-exports:

- `native-ipc-core` for pointer-free codecs, checked shared-memory layouts,
  sequencing, and audited reader/writer bindings; and
- `native-ipc-platform` for least-authority native mappings, authenticated
  capability transfer, and owned helper-process lifecycles on Linux, macOS,
  and Windows.

Payload bytes received through shared memory remain hostile input. Readers copy
them into owned storage and recheck bounded metadata, but the library does not
claim integrity against a malicious same-sequence writer.

See the [repository README](https://github.com/ro-ag/native-ipc-rs#readme),
[architecture](https://github.com/ro-ag/native-ipc-rs/blob/main/docs/architecture.md),
and [threat model](https://github.com/ro-ag/native-ipc-rs/blob/main/docs/threat-model.md)
for the complete security contract.

Licensed under MIT or Apache-2.0 at your option.
