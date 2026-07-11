# Releasing

Releases are published from a clean, fully validated `main` checkout. The four
crates share one version and are tagged together.

## Prerequisites

- The changelog has a dated section for the workspace version.
- The GitHub `crates-io` environment has a `CARGO_REGISTRY_TOKEN` secret with
  publish permission.
- GitHub CLI authentication can create tags and releases in `ro-ag/native-ipc-rs`.
- The complete GitHub Actions matrix is green for the release-preparation PR.

## Validate

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-features --all-targets --locked -- -D warnings
cargo test --workspace --all-features --all-targets --locked
cargo test --workspace --no-default-features --all-targets --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
cargo deny check
git diff --check
```

The release workflow runs `cargo publish --dry-run` immediately before each
missing publish. Publishing follows dependency order because crates.io must
index each new dependency before its dependents can be packaged.

## Publish

```sh
git tag -a v0.1.0 -m "native-ipc 0.1.0"
git push origin v0.1.0
```

Pushing the tag runs `.github/workflows/release.yml`. The workflow verifies the
tag and workspace versions, skips crate versions already present, publishes
missing crates in dependency order, waits for crates.io indexing, and creates
the GitHub Release from the matching changelog section. It is idempotent and can
be rerun with `workflow_dispatch` against the existing tag.

For recovery only, the equivalent manual publish order is:

```sh
cargo publish -p native-ipc-core --locked
cargo publish -p native-ipc-platform --locked
cargo publish -p native-ipc-testkit --locked
cargo publish -p native-ipc --locked
```

Finally, verify all four crates, their docs.rs pages, the GitHub tag, and the
GitHub Release. A failed intermediate publish must be reported without tagging;
published crates cannot be overwritten or deleted.
