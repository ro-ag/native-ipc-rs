# native-ipc-core

Platform-neutral, pointer-free wire formats, checked shared-memory layouts,
publication sequencing, and mapping-owned reader/writer bindings for
[`native-ipc`](https://crates.io/crates/native-ipc).

This crate is useful when implementing a custom transport or protocol. Most
applications should depend on `native-ipc`, which combines these primitives
with native capability enforcement.

## Main modules

- [`codec`](https://docs.rs/native-ipc-core/latest/native_ipc_core/codec/):
  fixed-width envelopes, bounded decoding, and protocol traits.
- [`layout`](https://docs.rs/native-ipc-core/latest/native_ipc_core/layout/):
  canonical multi-region layouts and hostile-memory validation.
- [`mapping`](https://docs.rs/native-ipc-core/latest/native_ipc_core/mapping/):
  mapping-owned runtime regions that prevent duplicate safe writer binding.
- [`slot`](https://docs.rs/native-ipc-core/latest/native_ipc_core/slot/):
  release/acquire publication, snapshot rechecks, and acknowledgements.

## Layout example

```rust
use native_ipc_core::layout::{
    AcknowledgementRouteSpec, Endpoint, LayoutLimits, RegionSetLayout,
    RegionSpec, RoleId,
};

let producer = RoleId::new(1).unwrap();
let peer = RoleId::new(2).unwrap();
let regions = [
    RegionSpec {
        role: producer,
        writer: Endpoint::Initiator,
        slot_count: 1,
        payload_bytes: 256,
        acknowledgement_count: 1,
    },
    RegionSpec {
        role: peer,
        writer: Endpoint::Responder,
        slot_count: 1,
        payload_bytes: 256,
        acknowledgement_count: 1,
    },
];
let routes = [
    AcknowledgementRouteSpec {
        owner: peer,
        target: producer,
        slot_index: 0,
        cell_index: 0,
    },
    AcknowledgementRouteSpec {
        owner: producer,
        target: peer,
        slot_index: 0,
        cell_index: 0,
    },
];
let topology = RegionSetLayout::calculate(
    [0x52; 32],
    1,
    &regions,
    &routes,
    LayoutLimits {
        maximum_mapping_size: 64 * 1024,
        maximum_slot_count: 8,
        maximum_acknowledgement_count: 8,
        maximum_payload_bytes: 4096,
    },
)?;
assert_eq!(topology.region(producer).unwrap().slot_count(), 1);
# Ok::<(), native_ipc_core::layout::LayoutError>(())
```

Complete examples:

- [checked multi-region layout](https://github.com/ro-ag/native-ipc-rs/blob/main/crates/native-ipc-core/examples/checked_layout.rs)
- [bounded message codec](https://github.com/ro-ag/native-ipc-rs/blob/main/crates/native-ipc-core/examples/bounded_codec.rs)

The crate supports `no_std` with allocation by disabling the default `std`
feature.

Licensed under MIT or Apache-2.0.
