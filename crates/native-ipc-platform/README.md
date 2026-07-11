# native-ipc-platform

Least-authority native shared-memory mappings, authenticated capability
transfer, and owned helper lifecycles for
[`native-ipc`](https://crates.io/crates/native-ipc).

Supported targets:

- Linux ARM64/AMD64: sealed `memfd`, `SCM_RIGHTS`, `SO_PEERCRED`, and pidfds.
- macOS ARM64: typed Mach memory entries and audit-token PID authentication.
- Windows ARM64/AMD64: least-rights unnamed sections, PID-checked private
  pipes, held process handles, and kill-on-close Job Objects.

## Transaction invariant

Every transfer is a consuming transaction:

```text
CAPABILITY -> READY -> COMMIT -> runtime ReaderRegion / WriterRegion
```

`CAPABILITY` transfers native rights and a canonical manifest. The peer maps
and validates every region into pending values with no payload API. `READY`
confirms the exact batch, and `COMMIT` activates both endpoints atomically.
Runtime mappings cannot be obtained through an independent safe `bind`.

The manifest binds the control version, nonce, authenticated parent/child PIDs,
session-unique transfer ID, canonical role order, schema, generation, writer
endpoint, peer access, and exact page-rounded length. Control methods require
exclusive mutable channel access so transactions cannot interleave.

## API flow

The runnable [`ready_commit` example](https://github.com/ro-ag/native-ipc-rs/blob/main/crates/native-ipc-platform/examples/ready_commit.rs)
shows the consuming API signatures for every backend. Full native helper
fixtures live beside each backend because capability transfer requires two
authenticated processes.

Linux creator and peer:

```text
QuiescentRegion::prepare_writer
  -> AuthenticatedChannel::transfer_writer
  -> WriterRegion (only after COMMIT)

AuthenticatedChannel::receive_reader
  -> pending validated reader internally
  -> ReaderRegion (only after COMMIT)
```

macOS and Windows build both directional pending mappings, then commit the
whole batch with `commit_transfers` / `commit_imports`.

See also the runnable
[`quiescent_region` example](https://github.com/ro-ag/native-ipc-rs/blob/main/crates/native-ipc-platform/examples/quiescent_region.rs).

Licensed under MIT or Apache-2.0.
