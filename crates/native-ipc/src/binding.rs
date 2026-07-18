//! Safe audited binding from committed active mappings to core capabilities.
//!
//! This module is the safe, fully audited alternative to the feature-gated
//! `raw-pointer` escape. It converts a committed [`ActiveReader`] or
//! [`ActiveWriter`] into the matching `native-ipc-core` capability owner
//! ([`ReaderRegion`]/[`WriterRegion`]) by consuming the active mapping into a
//! witness the core boundary trusts. Running the audited core protocol over a
//! session-transferred region needs no consumer unsafe code and no
//! `raw-pointer` feature on this path.
//!
//! # Witness soundness
//!
//! An active mapping is uniquely owned and cannot be cloned. Its local native
//! view is released only by the owner's own `Drop`; session poison or close
//! gates the safe accessors but never unmaps the view. Moving the consumed
//! active value inside a witness therefore keeps the whole `base..base+len`
//! extent mapped and initialized — and, for the read side, OS-enforced
//! read-only — for the entire witness lifetime. `len` is the mapping's
//! validated logical extent ([`ActiveReader::len`]/[`ActiveWriter::len`]); the
//! page-rounded tail beyond it is deliberately excluded, matching the range the
//! [`ValidatedRegionLayout`] was validated over.
//!
//! After the peer session ends the peer is gone and the bytes are frozen or
//! stale: read witnesses still observe only hostile, memory-safe bytes, and
//! write witnesses simply publish to nobody. Liveness re-checking is
//! deliberately not part of the witness contract; a consumer that needs it
//! keeps the owning session handle and quiesces before dropping the witness.

use crate::active::{ActiveReader, ActiveWriter};
use crate::core::layout::{RegionSetLayout, ValidatedRegionLayout};
use crate::core::mapping::{
    BindingError, ReadOnlyMapping, ReaderRegion, SoleWriterMapping, WriterRegion,
};
use core::fmt;
use core::ptr::NonNull;

/// Read-only witness that owns its consumed active mapping.
///
/// A region bound over this witness is a unique capability; neither the witness
/// nor the region it backs can be duplicated:
///
/// ```compile_fail
/// use native_ipc::binding::BoundReadMapping;
/// use native_ipc::core::mapping::ReaderRegion;
/// fn duplicate(
///     region: ReaderRegion<BoundReadMapping>,
/// ) -> (ReaderRegion<BoundReadMapping>, ReaderRegion<BoundReadMapping>) {
///     let copy = region.clone();
///     (region, copy)
/// }
/// ```
pub struct BoundReadMapping {
    reader: ActiveReader,
    base: NonNull<u8>,
}

// SAFETY: the witness owns an `ActiveReader`, which is itself `Send + Sync`, and
// the cached `base` is a copy of that mapping's own base that can never outlive
// the owned reader. Moving or sharing the witness across threads only moves or
// shares the reader it already permits, so the markers grant no authority the
// inner mapping did not already have.
unsafe impl Send for BoundReadMapping {}
unsafe impl Sync for BoundReadMapping {}

// SAFETY: the owned `ActiveReader` uniquely owns exactly one page-aligned,
// OS-enforced read-only native view and releases it only in its own `Drop`;
// session poison or close gates the safe accessors without unmapping, so the
// view stays mapped and initialized for as long as this witness lives. `base`
// is that mapping's own base carrying its allocation provenance, and `len`
// reports its validated logical extent — precisely the bytes the caller's
// `ValidatedRegionLayout` was validated over. Peer mutation may race, but the
// core boundary only ever performs volatile loads through `base` and never
// forms a shared reference, so exposing this witness cannot violate memory
// safety.
unsafe impl ReadOnlyMapping for BoundReadMapping {
    fn base(&self) -> NonNull<u8> {
        self.base
    }

    fn len(&self) -> usize {
        self.reader.len()
    }
}

/// Sole-writer witness that owns its consumed active mapping.
pub struct BoundWriteMapping {
    writer: ActiveWriter,
    base: NonNull<u8>,
}

// SAFETY: the witness owns an `ActiveWriter`, which is `Send` but deliberately
// not `Sync`; moving it between threads transfers the single writable view
// without ever aliasing it, and the cached `base` cannot outlive that owned
// writer. Matching the inner mapping, the witness is `Send` only, so no shared
// cross-thread writer alias becomes reachable.
unsafe impl Send for BoundWriteMapping {}

// SAFETY: the owned `ActiveWriter` is, by construction, the region's only
// writable native view: it is non-cloneable, holds sole store authority, and
// releases its page-aligned view only in its own `Drop`. Session poison or
// close gates the safe accessors without unmapping, so the view stays mapped
// and writable for the witness lifetime. `base` is that mapping's own base with
// allocation provenance and `len` is its validated logical extent, exactly the
// range the `ValidatedRegionLayout` was validated over. While a `WriterRegion`
// owns this witness, safe code cannot recover a second writer for the region.
unsafe impl SoleWriterMapping for BoundWriteMapping {
    fn base(&self) -> NonNull<u8> {
        self.base
    }

    fn len(&self) -> usize {
        self.writer.len()
    }
}

impl BoundReadMapping {
    /// Releases the witness and returns the owned active mapping unchanged.
    pub fn into_active(self) -> ActiveReader {
        self.reader
    }
}

impl BoundWriteMapping {
    /// Releases the witness and returns the owned active mapping unchanged.
    pub fn into_active(self) -> ActiveWriter {
        self.writer
    }
}

/// A rejected bind that returns the consumed active mapping to its caller.
///
/// The bind boundary consumes the active mapping by value; on rejection this
/// carrier hands the exact same value back so the caller recovers it instead of
/// losing the committed mapping.
pub struct BindRejected<T> {
    /// Reason the validated layout could not bind to this mapping.
    pub error: BindingError,
    value: T,
}

impl<T> BindRejected<T> {
    /// Recovers the consumed active mapping unchanged.
    pub fn into_inner(self) -> T {
        self.value
    }
}

// The recovered active mapping is deliberately opaque, so this does not require
// `T: Debug`; only the binding error is reported.
impl<T> fmt::Debug for BindRejected<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BindRejected")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl ActiveReader {
    /// Consumes this committed mapping into an audited core read capability.
    ///
    /// On rejection the returned [`BindRejected`] carries this exact reader back
    /// through [`BindRejected::into_inner`].
    pub fn bind(
        self,
        layout: ValidatedRegionLayout,
        topology: RegionSetLayout,
    ) -> Result<ReaderRegion<BoundReadMapping>, Box<BindRejected<ActiveReader>>> {
        let base = self.payload_base();
        let witness = BoundReadMapping { reader: self, base };
        ReaderRegion::new(witness, layout, topology).map_err(|(witness, error)| {
            Box::new(BindRejected {
                error,
                value: witness.into_active(),
            })
        })
    }
}

impl ActiveWriter {
    /// Consumes this committed mapping into an audited core write capability.
    ///
    /// On rejection the returned [`BindRejected`] carries this exact writer back
    /// through [`BindRejected::into_inner`].
    pub fn bind(
        mut self,
        layout: ValidatedRegionLayout,
        topology: RegionSetLayout,
    ) -> Result<WriterRegion<BoundWriteMapping>, Box<BindRejected<ActiveWriter>>> {
        let base = self.payload_base_mut();
        let witness = BoundWriteMapping { writer: self, base };
        WriterRegion::new(witness, layout, topology).map_err(|(witness, error)| {
            Box::new(BindRejected {
                error,
                value: witness.into_active(),
            })
        })
    }
}

#[cfg(test)]
#[path = "binding_test.rs"]
mod tests;
