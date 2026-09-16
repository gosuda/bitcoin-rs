//! Chain-level policy constants shared by validation, storage, and RPC.
//!
//! These are consensus-adjacent policy numbers, not storage details: every
//! tier that names them (node services, RPC surface) already depends on this
//! crate, so the single definition lives here.

/// Minimum number of blocks kept below the active tip for Core-compatible
/// reorg safety.
pub const CORE_REORG_SAFETY_MARGIN: u32 = 288;

/// BIP141 `OP_RETURN`/`PUSH36` witness-commitment script prefix.
pub const WITNESS_COMMITMENT_PREFIX: [u8; 6] = [0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
