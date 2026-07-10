# Contributing

Changes must preserve the one-writer-per-mapping model, bounded hostile-input
validation, and the separation between read-only and store-capable APIs.

Use Rust 1.97 and run the complete command set in the README. Add adversarial
tests for every validation branch and a platform-native permission test for any
native capability change. Wire changes require updated cross-platform golden
vectors and an explicit compatibility decision.

Every unsafe block must have a local safety explanation covering provenance,
length, lifetime, aliasing, concurrent mutation, and native permissions as
applicable. Pull requests changing unsafe code or shared-memory invariants need
independent review.

Commits should be concise and intentional. Do not add `Co-authored-by` or other
co-author trailers.
