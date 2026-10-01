use crate::ColumnFamily;
use bitcoin_rs_primitives::Hash256;

const BLOCK_UNDO_PREFIX: u8 = b'u';
/// Undo records live in their own family, not alongside the block tree.
///
/// They were pruned out of `BlockTree` while the node wrote them to
/// `UndoData`, so pruning reported success and removed nothing. The only
/// writer that ever put a row where the pruner looked was a test helper.
pub(crate) const BLOCK_UNDO_CF: ColumnFamily = ColumnFamily::UndoData;
pub(crate) const BLOCK_UNDO_PREFIX_BYTES: &[u8] = b"u";
const HEIGHT_START: usize = 1;
const HEIGHT_END: usize = 5;
const KEY_LEN: usize = 37;

/// Builds the canonical pruning key for stored undo data for one block.
#[must_use]
pub fn block_undo_key(height: u32, hash: Hash256) -> [u8; KEY_LEN] {
    let mut key = [0_u8; KEY_LEN];
    key[0] = BLOCK_UNDO_PREFIX;
    key[HEIGHT_START..HEIGHT_END].copy_from_slice(&height.to_be_bytes());
    key[HEIGHT_END..].copy_from_slice(hash.as_byte_array());
    key
}
