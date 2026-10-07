//! Storage footprint measurement tool and evidence generation.

pub mod evidence;
pub mod logical;
pub mod physical_types;

#[cfg(unix)]
pub mod physical;

pub mod collector;

pub use collector::{MeasureStorageRequest, measure_storage_footprint};
pub use evidence::{BudgetEvidence, StorageFootprintEvidence, storage_footprint_json};
pub use logical::{LogicalLedger, LogicalOwner, logical_store_owners};
pub use physical_types::{
    ALLOCATED_BLOCK_BYTES, FootprintError, PhysicalCategory, PhysicalLedger, PhysicalNamespace,
    PhysicalObservationKind,
};

#[cfg(unix)]
pub use physical::{DataDirAnchor, measure_physical_tree};
