//! Shows the consuming READY/COMMIT API boundary on every native backend.
//!
//! Real capability transfer requires two authenticated processes. These helper
//! functions make the compile-time transition explicit without creating an
//! unauthenticated demonstration transport.

#![allow(dead_code)] // The target-specific signatures are the example output.

use native_ipc_core::layout::{RegionSetLayout, ValidationExpectations};

#[cfg(target_os = "linux")]
fn creator(
    channel: &mut native_ipc_platform::linux::AuthenticatedChannel,
    prepared: native_ipc_platform::linux::PreparedWriter,
) -> Result<
    native_ipc_core::mapping::WriterRegion<native_ipc_platform::linux::LinuxWriterMapping>,
    native_ipc_platform::linux::LinuxError,
> {
    channel.transfer_writer(prepared)
}

#[cfg(target_os = "linux")]
fn peer(
    channel: &mut native_ipc_platform::linux::AuthenticatedChannel,
    len: usize,
    expected: ValidationExpectations,
    topology: RegionSetLayout,
) -> Result<
    native_ipc_core::mapping::ReaderRegion<native_ipc_platform::linux::LinuxReaderMapping>,
    native_ipc_platform::linux::LinuxError,
> {
    channel.receive_reader(len, expected, topology)
}

#[cfg(target_os = "macos")]
fn creator(
    channel: &mut native_ipc_platform::macos::bootstrap::ParentChannel,
    writer: native_ipc_platform::macos::PendingTransferredWriter,
    reader: native_ipc_platform::macos::PendingTransferredReader,
) -> Result<
    (
        native_ipc_core::mapping::WriterRegion<
            native_ipc_platform::macos::TransferredWriterMapping,
        >,
        native_ipc_core::mapping::ReaderRegion<
            native_ipc_platform::macos::TransferredReaderMapping,
        >,
    ),
    native_ipc_platform::macos::MacBindingError,
> {
    channel.commit_transfers(writer, reader)
}

#[cfg(target_os = "windows")]
fn creator(
    session: &mut native_ipc_platform::windows::ChildSession,
    writer: native_ipc_platform::windows::PreparedLocalWriter,
    reader: native_ipc_platform::windows::PreparedRemoteWriter,
) -> Result<
    (
        native_ipc_core::mapping::WriterRegion<native_ipc_platform::windows::WindowsWriterMapping>,
        native_ipc_core::mapping::ReaderRegion<native_ipc_platform::windows::WindowsReaderMapping>,
    ),
    native_ipc_platform::windows::WindowsError,
> {
    session.commit_transfers(writer, reader)
}

fn main() {
    let _ = std::mem::size_of::<ValidationExpectations>();
    let _ = std::mem::size_of::<RegionSetLayout>();
    println!("pending mappings expose runtime access only after COMMIT");
}
