# Releasing

Releases are published from a clean, fully validated `main` checkout. The four
crates share one version and are tagged together.

## Prerequisites

- The changelog has a dated section for the workspace version.
- `cargo login` has configured a crates.io API token with publish permission.
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

Run `cargo publish --dry-run` immediately before each corresponding publish.
Publishing must follow dependency order because crates.io must index each new
dependency before its dependents can be packaged.

## Publish 0.1.0

```sh
cargo publish -p native-ipc-core --locked
# Wait until the crates.io API and index expose native-ipc-core 0.1.0.

cargo publish -p native-ipc-platform --locked
cargo publish -p native-ipc-testkit --locked
# Wait until both crates are visible in the crates.io index.

cargo publish -p native-ipc --locked
```

Never tag a partially published release. After every crate is visible and its
docs.rs build has started, tag the exact validated commit and create the GitHub
release from the matching changelog section:

```sh
git tag -a v0.1.0 -m "native-ipc 0.1.0"
git push origin v0.1.0
gh release create v0.1.0 --verify-tag --title "native-ipc 0.1.0" \
  --notes-file release-notes.md
```

Finally, verify all four crates, their docs.rs pages, the GitHub tag, and the
GitHub Release. A failed intermediate publish must be reported without tagging;
published crates cannot be overwritten or deleted.
