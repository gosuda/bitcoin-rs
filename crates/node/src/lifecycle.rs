//! The single owner of node startup, rollback, and ordered service shutdown.
//!
//! Startup returns a fully owned `Node`, not detached state and worker handles.
//! The daemon and embedding surfaces both enter this lifecycle directly.

mod rpc;
pub(crate) mod services;
pub(crate) mod startup;
