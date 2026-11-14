use super::{
    DerivedIndexInfo, DerivedIndexQueryEngine, Hash256, IndexCapabilities, TxIndexSnapshot,
    TxQueryError, TxUnavailableCause,
};
use crate::{BasicFilter, CompactFilterQuery};

impl CompactFilterQuery for DerivedIndexQueryEngine {
    fn block_filter(&self, hash: Hash256) -> Result<Option<BasicFilter>, TxQueryError> {
        let (view, snapshot) = self.capture_view(IndexCapabilities::COMPACT_FILTERS)?;
        self.with_view(
            IndexCapabilities::COMPACT_FILTERS,
            &view,
            snapshot.as_ref(),
            |snapshot, view, _| {
                let Some(height) = self.block_tree.read().active_height_of(view.tip_id, hash)
                else {
                    return Ok(None);
                };
                let filter = read_filter(snapshot, height, hash)?;
                Ok(Some(filter))
            },
        )
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
        let (view, snapshot) = self.capture_view(IndexCapabilities::COMPACT_FILTERS)?;
        self.with_view(
            IndexCapabilities::COMPACT_FILTERS,
            &view,
            snapshot.as_ref(),
            |snapshot, view, _| {
                let (previous, hashes) = {
                    let tree = self.block_tree.read();
                    let Some(end) = tree.active_height_of(view.tip_id, stop) else {
                        return Ok(None);
                    };
                    if start > end {
                        return Ok((step == 1000 && start == 1000).then_some([0; 32]));
                    }
                    let count = (end - start) / step + 1;
                    if (step == 1 && count > 2000) || count > 100_000 {
                        return Ok(None);
                    }
                    let hash_at = |height| {
                        tree.node_at_height_from(view.tip_id, height)
                            .and_then(|id| tree.node(id).ok())
                            .map(|node| node.hash)
                            .ok_or_else(|| {
                                TxQueryError::Unavailable(TxUnavailableCause::BlockBodyMissing {
                                    height,
                                })
                            })
                    };
                    let previous = if start == 0 {
                        None
                    } else {
                        Some((start - 1, hash_at(start - 1)?))
                    };
                    let mut hashes = Vec::with_capacity(usize::try_from(count).map_err(|_| {
                        TxQueryError::Unavailable(TxUnavailableCause::FilterDataMissing)
                    })?);
                    for height in (start..=end).step_by(usize::try_from(step).map_err(|_| {
                        TxQueryError::Unavailable(TxUnavailableCause::FilterDataMissing)
                    })?) {
                        hashes.push((height, hash_at(height)?));
                    }
                    (previous, hashes)
                };
                let previous_header = match previous {
                    None => [0; 32],
                    Some((height, hash)) => read_filter(snapshot, height, hash)?.header,
                };
                for (height, hash) in hashes {
                    self.check_view(view)?;
                    let filter = read_filter(snapshot, height, hash)?;
                    self.check_view(view)?;
                    if !emit(hash, filter) {
                        return Ok(None);
                    }
                }
                Ok(Some(previous_header))
            },
        )
    }

    fn filter_index_info(&self) -> Result<DerivedIndexInfo, TxQueryError> {
        self.require_enabled(IndexCapabilities::COMPACT_FILTERS)?;
        let progress = self.index_progress_for(IndexCapabilities::COMPACT_FILTERS)?;
        let applied_height = self
            .applied_tip
            .load_full()
            .as_ref()
            .map_or(0, |tip| tip.height);
        let coverage_height = progress.processed_height;
        let verified_height = progress.processed_height.min(applied_height);
        Ok(DerivedIndexInfo {
            synced: progress.synced && self.runtime.compact_filter_failure.read().is_none(),
            best_block_height: progress.processed_height,
            applied_height,
            verified_height,
            historical_height: progress.processed_height,
            coverage_height,
        })
    }
}

fn read_filter(
    snapshot: &dyn TxIndexSnapshot,
    height: u32,
    hash: Hash256,
) -> Result<BasicFilter, TxQueryError> {
    snapshot
        .compact_filter(height, &hash.to_le_bytes())
        .map_err(|error| TxQueryError::Storage(error.to_string().into()))?
        .ok_or_else(|| TxQueryError::Unavailable(TxUnavailableCause::FilterDataMissing))
}
