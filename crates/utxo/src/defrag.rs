use crate::{UtxoKey, UtxoSet};

impl UtxoSet {
    /// Defragments one shard selected in round-robin order.
    ///
    /// The shard write lock is held while live records and script bytes are
    /// copied into a fresh self-cell arena. In the worst case a reader targeting
    /// that shard stalls for `live_records_in_shard * copy_cost`; the plan's
    /// budget models this as `live * 16ns`. Running this once per second across
    /// 256 shards amortizes the exposed reader stall to roughly
    /// `total_live / 256 * 16ns` per second while bounding tombstone growth.
    pub fn defrag_one_shard(&self) {
        let shard_idx = {
            let mut next = self.last_defragged_shard.lock();
            let shard_idx = *next;
            *next = next.wrapping_add(1);
            shard_idx
        };
        if let Err(error) = self.shards[usize::from(shard_idx)].defrag_if_needed() {
            tracing::warn!(shard = shard_idx, %error, "utxo shard defrag skipped");
        }
        debug_assert!(usize::from(shard_idx) < UtxoKey::SHARD_COUNT);
    }
}
