//! Bitcoin Core wire-contract boundary.
//!
//! [`convert`] owns the native <-> `bitcoin` conversions (consensus-byte
//! round trip or explicit field mapping) and the typed serde helpers the
//! handlers use to emit `corepc_types::v31` responses. Wire shapes are pinned
//! by the upstream types, never re-declared here.

/// Comparing results against Core's own declared result schemas.
pub mod schema;

pub(crate) mod convert;
