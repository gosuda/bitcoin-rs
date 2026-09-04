//! Chain-level policy constants shared by validation, storage, and RPC.
//!
//! These are consensus-adjacent policy numbers, not storage details: every
//! tier that names them (node services, RPC surface) already depends on this
//! crate, so the single definition lives here.

/// Minimum number of blocks kept below the active tip for Core-compatible
/// reorg safety.
pub const CORE_REORG_SAFETY_MARGIN: u32 = 288;

/// Maximum script size admitted to the authoritative UTXO set, in bytes.
pub const MAX_SCRIPT_SIZE: usize = 10_000;
