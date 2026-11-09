use super::capability::{IndexCapabilities, IndexCapability, IndexWatermark};
use super::error::IndexError;
use super::write::IndexWriter;
use crate::segment::format::{TAIL_MAX_BLOCKS, TAIL_MAX_BYTES};
use crate::segment::tail::{self, SealedTxOrdinals, TailWriterState};
use crate::segment::{self, Coverage, SealedGen};
use bitcoin_rs_storage::{BufferedWriteBatch, CommittedBlock, KvStore};

pub(super) enum RollbackTail {
    Unwind,
    Retire(SealedGen),
}

impl<S: KvStore> IndexWriter<S> {
    pub(super) fn tail_for(
        &mut self,
        current: Option<IndexWatermark>,
    ) -> Result<TailWriterState, IndexError> {
        let expected = current.map(|watermark| (watermark.height, watermark.hash));
        if let Some(state) = self.tail.take().filter(|state| state.at == expected) {
            return Ok(state);
        }
        let snapshot = self.indexer.store.snapshot()?;
        tail::load(snapshot.as_ref())
    }

    pub(super) fn append_forward_tail(
        &self,
        state: &mut TailWriterState,
        blocks: &[CommittedBlock],
        batch: &mut BufferedWriteBatch,
    ) -> Result<(), IndexError> {
        let snapshot = self.indexer.store.snapshot()?;
        let gens = state.sealed.clone();
        let older = SealedTxOrdinals {
            snapshot: snapshot.as_ref(),
            gens: &gens,
        };
        for block in blocks {
            tail::append_tail_block(batch, block, state, &older)?;
        }
        Ok(())
    }

    pub(super) fn plan_rollback_tail(
        &self,
        state: &TailWriterState,
        capabilities: IndexCapabilities,
        current: IndexWatermark,
    ) -> Result<RollbackTail, IndexError> {
        let Some(newest) = state.newest() else {
            return Ok(RollbackTail::Unwind);
        };
        if newest.coverage.last_height < current.height {
            return Ok(RollbackTail::Unwind);
        }
        for capability in segment_capabilities(capabilities) {
            segment::retire_generation_rows(
                self.indexer.store.as_ref(),
                capability,
                newest.gen_id,
            )?;
        }
        Ok(RollbackTail::Retire(newest))
    }

    pub(super) fn apply_rollback_tail(
        &self,
        state: &mut TailWriterState,
        plan: RollbackTail,
        capabilities: IndexCapabilities,
        current: IndexWatermark,
        prev: Option<IndexWatermark>,
        batch: &mut BufferedWriteBatch,
    ) -> Result<(), IndexError> {
        let first_height = match plan {
            RollbackTail::Unwind => {
                let snapshot = self.indexer.store.snapshot()?;
                tail::unwind_tail_block(batch, snapshot.as_ref(), current.height)?;
                if state.tail_blocks > 1 {
                    state.first_height
                } else {
                    None
                }
            }
            RollbackTail::Retire(newest) => {
                state.sealed.retain(|sealed| sealed.gen_id != newest.gen_id);
                for capability in segment_capabilities(capabilities) {
                    segment::clear_retirement_markers(batch, capability, newest.gen_id);
                }
                None
            }
        };
        tail::put_generation_descriptors(
            batch,
            segment_capabilities(capabilities),
            tail::TailBounds {
                newest: state.newest(),
                first_height,
                at: prev.map(|watermark| (watermark.height, watermark.hash)),
            },
        );
        Ok(())
    }

    pub(super) fn seal_if_due(
        &self,
        state: &TailWriterState,
        capabilities: IndexCapabilities,
        tip: IndexWatermark,
    ) -> Result<bool, IndexError> {
        let byte_bound = u64::try_from(TAIL_MAX_BYTES).unwrap_or(u64::MAX);
        if state.tail_blocks <= TAIL_MAX_BLOCKS && state.tail_bytes <= byte_bound {
            return Ok(false);
        }
        let first_height = state.first_height.unwrap_or(tip.height);
        let coverage = Coverage::new(first_height, tip.height, tip.hash);
        segment::seal_tail_generation(
            self.indexer.store.as_ref(),
            state.next_gen_id,
            coverage,
            capabilities,
            &self.seal_scratch,
        )?;
        Ok(true)
    }
}

fn segment_capabilities(capabilities: IndexCapabilities) -> impl Iterator<Item = IndexCapability> {
    capabilities
        .iter()
        .filter(|capability| *capability != IndexCapability::ScriptLive)
}

pub(super) fn default_seal_scratch() -> std::path::PathBuf {
    std::env::temp_dir().join("bitcoin-rs-segment-seal")
}
