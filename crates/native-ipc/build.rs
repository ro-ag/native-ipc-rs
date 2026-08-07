//! Builds the audited external-memory volatile-copy boundary.

fn main() {
    println!("cargo::rustc-check-cfg=cfg(loom)");
    println!("cargo::rerun-if-changed=src/external_memory.c");
    println!("cargo::rerun-if-env-changed=DOCS_RS");

    if std::env::var_os("DOCS_RS").is_some() {
        return;
    }

    cc::Build::new()
        .file("src/external_memory.c")
        .warnings(true)
        .compile("native_ipc_external_memory");
}
