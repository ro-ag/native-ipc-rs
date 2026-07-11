# native-ipc-testkit

Deterministic hostile-input generators and golden-message helpers for testing
protocols built on [`native-ipc-core`](https://crates.io/crates/native-ipc-core).

The helpers are deliberately bounded so they are suitable for ordinary unit
tests and CI, not only fuzzing jobs.

## Example

```rust
use native_ipc_testkit::{
    HOSTILE_U64_BOUNDARIES, bounded_bit_mutations, every_truncation,
};

let canonical = b"NIPC";
let truncations: Vec<_> = every_truncation(canonical).collect();
assert_eq!(truncations.first().unwrap().len(), 0);
assert_eq!(truncations.last().unwrap(), canonical);

let mutations = bounded_bit_mutations(canonical, 2);
assert_eq!(mutations.len(), 2);
assert_ne!(mutations[0], canonical);
assert_eq!(HOSTILE_U64_BOUNDARIES.last(), Some(&u64::MAX));
```

Additional helpers produce fixed-field shared-layout mutations and exactly
sized encoded golden vectors. The committed cross-platform fixtures are in the
[`golden_vectors` integration test](https://github.com/ro-ag/native-ipc-rs/blob/main/crates/native-ipc-testkit/tests/golden_vectors.rs).
The same bounded corpus API is runnable as the
[`hostile_inputs` example](https://github.com/ro-ag/native-ipc-rs/blob/main/crates/native-ipc-testkit/examples/hostile_inputs.rs).

Licensed under MIT or Apache-2.0.
