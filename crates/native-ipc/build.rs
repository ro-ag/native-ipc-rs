//! Builds the audited external-memory volatile-copy boundary.

fn main() {
    println!("cargo::rustc-check-cfg=cfg(loom)");
    println!("cargo::rerun-if-changed=src/external_memory.c");
    cc::Build::new()
        .file("src/external_memory.c")
        .warnings(true)
        .compile("native_ipc_external_memory");
}
