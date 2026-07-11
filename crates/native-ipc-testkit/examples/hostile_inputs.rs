//! Generates a small deterministic hostile-input corpus.

use native_ipc_testkit::{HOSTILE_U64_BOUNDARIES, bounded_bit_mutations, every_truncation};

fn main() {
    let canonical = b"NIPC";
    let truncation_count = every_truncation(canonical).count();
    let mutations = bounded_bit_mutations(canonical, canonical.len());
    println!(
        "{truncation_count} truncations, {} bit mutations, {} boundary lengths",
        mutations.len(),
        HOSTILE_U64_BOUNDARIES.len()
    );
}
