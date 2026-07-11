//! Uses one interface while selecting the best backend for the current OS.

use native_ipc::memory::{NativeRegion, RegionOptions, WriterOwner, native_memory_capabilities};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let capabilities = native_memory_capabilities();
    let options = RegionOptions::growable(128, 4096, WriterOwner::Creator);
    let mut region = NativeRegion::allocate(options)?;

    region.initialize(|bytes| bytes[..8].copy_from_slice(b"NIPCDEMO"));
    region.grow(512)?;
    region.initialize(|bytes| assert_eq!(&bytes[..8], b"NIPCDEMO"));

    let status = region.status();
    println!(
        "backend={:?} authority={:?} logical={} mapped={} maximum={}",
        capabilities.platform(),
        capabilities.authority_mechanism(),
        status.logical_len,
        status.mapped_len,
        status.maximum_len,
    );

    region.clear();
    region.initialize(|bytes| bytes[..8].copy_from_slice(b"REUSABLE"));

    // `destroy` explicitly clears the complete mapping before releasing it.
    // Use `prepare_for_sharing` instead when handing the region to the
    // authenticated platform transfer typestate.
    region.destroy();
    Ok(())
}
