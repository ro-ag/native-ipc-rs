//! Shows the only phase where ordinary byte slices are exposed by native regions.

#[cfg(target_os = "linux")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut region = native_ipc_platform::linux::QuiescentRegion::new(256)?;
    initialize(&mut region.as_bytes_mut()[..256]);
    println!(
        "Linux memfd capability: {} page-rounded bytes",
        region.len()
    );
    Ok(())
}

#[cfg(target_os = "macos")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut region = native_ipc_platform::macos::QuiescentRegion::new(256)?;
    initialize(&mut region.as_bytes_mut()[..256]);
    println!("Mach VM capability: {} page-rounded bytes", region.len());
    Ok(())
}

#[cfg(target_os = "windows")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut region = native_ipc_platform::windows::QuiescentRegion::new(256)?;
    initialize(&mut region.as_bytes_mut()[..256]);
    println!(
        "Windows section capability: {} page-rounded bytes",
        region.len()
    );
    Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn main() {
    compile_error!("quiescent_region requires Linux, macOS, or Windows");
}

fn initialize(bytes: &mut [u8]) {
    assert!(bytes.iter().all(|byte| *byte == 0));
    bytes[..8].copy_from_slice(b"NIPCDEMO");
    // The consuming prepare/transfer transition removes this slice accessor
    // before another process can map the same capability.
}
