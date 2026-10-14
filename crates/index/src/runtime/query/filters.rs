//! Snapshot-gated compact-filter queries. No chain-transition lock is needed:
//! these answers depend only on immutable block identities and index rows.

use super::{
    DerivedIndexInfo, DerivedIndexQueryEngine, Hash256, IndexCapabilities, TxIndexSnapshot,
    TxQueryError,
};
use crate::{BasicFilter, CompactFilterQuery};

impl CompactFilterQuery for DerivedIndexQueryEngine {
    fn block_filter(&self, hash: Hash256) -> Result<Option<BasicFilter>, TxQueryError> {
        self.with_snapshot(IndexCapabilities::COMPACT_FILTERS, |snapshot, tip, _, _| {
            if self
                .block_tree
                .read()
                .active_height_of(tip.tip_id, hash)
                .is_none()
            {
                return Ok(None);
            }
            let filter = read_filter(snapshot, hash)?;
            Ok(Some(filter))
        })
    }

    fn for_each_filter(
        &self,
        start: u32,
        stop: Hash256,
        step: u32,
        emit: &mut dyn FnMut(Hash256, BasicFilter) -> bool,
    ) -> Result<Option<[u8; 32]>, TxQueryError> {
        if step != 1 && step != 1000 {
            return Ok(None);
        }
        self.with_snapshot(IndexCapabilities::COMPACT_FILTERS, |snapshot, tip, _, _| {
            let (previous, hashes) = {
                let tree = self.block_tree.read();
                let Some(end) = tree.active_height_of(tip.tip_id, stop) else {
                    return Ok(None);
                };
                if start > end {
                    return Ok((step == 1000 && start == 1000).then_some([0; 32]));
                }
                let count = (end - start) / step + 1;
                // BIP157 headers have at most 2000 hashes; checkpoints fit the
                // 4 MB protocol envelope. Bound work before allocating/walking.
                if (step == 1 && count > 2000) || count > 100_000 {
                    return Ok(None);
                }
                let hash_at = |height| {
                    tree.node_at_height_from(tip.tip_id, height)
                        .and_then(|id| tree.node(id).ok())
                        .map(|node| node.hash)
                        .ok_or(TxQueryError::Retry)
                };
                let previous = if start == 0 {
                    None
                } else {
                    Some(hash_at(start - 1)?)
                };
                let mut hashes =
                    Vec::with_capacity(usize::try_from(count).map_err(|_| TxQueryError::Retry)?);
                for height in
                    (start..=end).step_by(usize::try_from(step).map_err(|_| TxQueryError::Retry)?)
                {
                    hashes.push(hash_at(height)?);
                }
                (previous, hashes)
            };
            let previous_header = match previous {
                None => [0; 32],
                Some(hash) => read_filter(snapshot, hash)?.header,
            };
            for hash in hashes {
                if !emit(hash, read_filter(snapshot, hash)?) {
                    return Ok(None);
                }
            }
            Ok(Some(previous_header))
        })
    }

    fn filter_index_info(&self) -> Result<DerivedIndexInfo, TxQueryError> {
        self.require_enabled(IndexCapabilities::COMPACT_FILTERS)?;
        let progress = self.index_progress_for(IndexCapabilities::COMPACT_FILTERS)?;
        Ok(DerivedIndexInfo {
            synced: progress.synced && self.runtime.compact_filter_failure.read().is_none(),
            best_block_height: progress.processed_height,
        })
    }
}

fn read_filter(snapshot: &dyn TxIndexSnapshot, hash: Hash256) -> Result<BasicFilter, TxQueryError> {
    snapshot
        .compact_filter(&hash.to_le_bytes())
        .map_err(|error| TxQueryError::Storage(error.to_string().into()))?
        .ok_or_else(|| TxQueryError::Unavailable("compact filter data is missing".into()))
}
