//! One-owner transfer transactions and keyed post-commit regions.

use std::collections::BTreeMap;

use crate::active::{ActiveReader, ActiveWriter};
use crate::region::{PreparedRegion, RegionId, WriterEndpoint};

/// Portable batch construction or active-set lookup failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BatchError {
    /// Negotiated batch limits are zero or exceed hard maxima.
    InvalidLimits,
    /// A batch must contain at least one region.
    Empty,
    /// Region count exceeds the negotiated limit or hard maximum of sixteen.
    TooManyRegions,
    /// A region ID occurs more than once in the transaction.
    DuplicateRegionId(RegionId),
    /// Checked aggregate logical or mapped bytes overflowed or exceeded limits.
    BatchBytesExceeded,
    /// The keyed active set does not contain this ID.
    UnknownRegion(RegionId),
    /// The requested runtime authority does not match the committed direction.
    WrongDirection(RegionId),
    /// Committed mappings do not exactly match pending IDs and directions.
    CommitMismatch,
}

impl core::fmt::Display for BatchError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "region batch operation failed: {self:?}")
    }
}

impl std::error::Error for BatchError {}

/// Consuming owner of every prepared object in one transfer transaction.
pub struct TransferBatch {
    regions: Vec<PreparedRegion>,
    max_regions: usize,
    max_batch_bytes: u64,
    total_logical: u64,
    total_mapped: u64,
}

impl TransferBatch {
    #[allow(dead_code)]
    pub(crate) fn new(max_regions: u16, max_batch_bytes: u64) -> Result<Self, BatchError> {
        let max_regions = usize::from(max_regions);
        if max_regions == 0 || max_regions > 16 {
            return Err(BatchError::TooManyRegions);
        }
        if max_batch_bytes == 0 {
            return Err(BatchError::InvalidLimits);
        }
        Ok(Self {
            regions: Vec::new(),
            max_regions,
            max_batch_bytes,
            total_logical: 0,
            total_mapped: 0,
        })
    }

    /// Consumes one prepared region into this transaction.
    pub fn add(&mut self, region: PreparedRegion) -> Result<(), BatchError> {
        if self.regions.len() == self.max_regions {
            return Err(BatchError::TooManyRegions);
        }
        let id = region.spec().id;
        if self.regions.iter().any(|existing| existing.spec().id == id) {
            return Err(BatchError::DuplicateRegionId(id));
        }
        let logical =
            u64::try_from(region.logical_len()).map_err(|_| BatchError::BatchBytesExceeded)?;
        let mapped =
            u64::try_from(region.mapped_len()).map_err(|_| BatchError::BatchBytesExceeded)?;
        let total_logical = self
            .total_logical
            .checked_add(logical)
            .ok_or(BatchError::BatchBytesExceeded)?;
        let total_mapped = self
            .total_mapped
            .checked_add(mapped)
            .ok_or(BatchError::BatchBytesExceeded)?;
        if total_logical > self.max_batch_bytes || total_mapped > self.max_batch_bytes {
            return Err(BatchError::BatchBytesExceeded);
        }
        self.total_logical = total_logical;
        self.total_mapped = total_mapped;
        self.regions.push(region);
        Ok(())
    }

    /// Current number of transaction-owned regions.
    pub fn len(&self) -> usize {
        self.regions.len()
    }

    /// Whether no region has been added yet.
    pub fn is_empty(&self) -> bool {
        self.regions.is_empty()
    }

    #[allow(dead_code)]
    pub(crate) fn into_pending(self) -> Result<PendingBatch, BatchError> {
        if self.regions.is_empty() {
            return Err(BatchError::Empty);
        }
        Ok(PendingBatch {
            regions: self.regions,
            total_logical: self.total_logical,
            total_mapped: self.total_mapped,
        })
    }
}

/// Complete transaction state after local validation and before COMMIT.
#[allow(dead_code)]
pub(crate) struct PendingBatch {
    pub(crate) regions: Vec<PreparedRegion>,
    pub(crate) total_logical: u64,
    pub(crate) total_mapped: u64,
}

#[allow(dead_code)]
pub(crate) enum CommittedRegion {
    Reader(ActiveReader),
    Writer(ActiveWriter),
}

/// Keyed complete runtime set returned only after batch COMMIT.
pub struct ActiveRegionSet {
    regions: BTreeMap<RegionId, CommittedRegion>,
}

impl ActiveRegionSet {
    #[allow(dead_code)]
    pub(crate) fn from_committed(
        pending: PendingBatch,
        regions: impl IntoIterator<Item = (RegionId, CommittedRegion)>,
    ) -> Result<Self, BatchError> {
        let mut keyed = BTreeMap::new();
        for (id, region) in regions {
            if keyed.insert(id, region).is_some() {
                return Err(BatchError::DuplicateRegionId(id));
            }
        }
        if keyed.len() != pending.regions.len() || keyed.len() > 16 {
            return Err(BatchError::CommitMismatch);
        }
        for expected in &pending.regions {
            let id = expected.spec().id;
            match (expected.spec().writer, keyed.get(&id)) {
                (WriterEndpoint::Coordinator, Some(CommittedRegion::Writer(_)))
                | (WriterEndpoint::Receiver, Some(CommittedRegion::Reader(_))) => {}
                _ => return Err(BatchError::CommitMismatch),
            }
        }
        drop(pending);
        Ok(Self { regions: keyed })
    }

    /// Number of active regions still retained by this set.
    pub fn len(&self) -> usize {
        self.regions.len()
    }

    /// Whether every region has been removed.
    pub fn is_empty(&self) -> bool {
        self.regions.is_empty()
    }

    /// Removes the coordinator-writer mapping for `id`.
    pub fn take_writer(&mut self, id: RegionId) -> Result<ActiveWriter, BatchError> {
        match self.regions.get(&id) {
            None => return Err(BatchError::UnknownRegion(id)),
            Some(CommittedRegion::Reader(_)) => return Err(BatchError::WrongDirection(id)),
            Some(CommittedRegion::Writer(_)) => {}
        }
        match self.regions.remove(&id) {
            Some(CommittedRegion::Writer(writer)) => Ok(writer),
            Some(CommittedRegion::Reader(_)) => Err(BatchError::WrongDirection(id)),
            None => Err(BatchError::UnknownRegion(id)),
        }
    }

    /// Removes the coordinator-reader mapping for `id`.
    pub fn take_reader(&mut self, id: RegionId) -> Result<ActiveReader, BatchError> {
        match self.regions.get(&id) {
            None => return Err(BatchError::UnknownRegion(id)),
            Some(CommittedRegion::Writer(_)) => return Err(BatchError::WrongDirection(id)),
            Some(CommittedRegion::Reader(_)) => {}
        }
        match self.regions.remove(&id) {
            Some(CommittedRegion::Reader(reader)) => Ok(reader),
            Some(CommittedRegion::Writer(_)) => Err(BatchError::WrongDirection(id)),
            None => Err(BatchError::UnknownRegion(id)),
        }
    }
}

#[cfg(test)]
#[path = "batch_test.rs"]
mod tests;
