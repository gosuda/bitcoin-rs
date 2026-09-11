//! Bounded body preparation and contiguous forward-batch admission.

use super::{
    worker::PendingForward, worker::ReconcileAction, worker::TxIndexWorkerError, worker::Worker,
};
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_index::{
    IndexCapabilities, IndexError, IndexWatermark, IndexWatermarks, IndexWriteFence,
    NoSpentScripts, PreparedBatch, PreparedBlock,
};
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_storage::block_body::BlockBodyReader;
use rayon::prelude::*;
use std::time::Instant;

/// Exact spent-coin script anchor decoded from one block's undo record.
///
/// The undo restores are precisely the external coins spent by the block and
/// carry their full `script_pubkey`. Intra-block spends are absent because
/// those outputs never entered the committed UTXO set.
pub(crate) struct UndoScripts {
    scripts: hashbrown::HashMap<([u8; 32], u32), Vec<u8>>,
}

impl UndoScripts {
    pub(crate) fn from_undo_bytes(
        bytes: &[u8],
        hash: Hash256,
    ) -> Result<Self, bitcoin_rs_utxo::undo_codec::UndoCodecError> {
        let batch = bitcoin_rs_utxo::undo_codec::decode(bytes, hash)?;
        let mut scripts = hashbrown::HashMap::with_capacity(batch.restores().len());
        for add in batch.restores() {
            scripts.insert(
                (add.outpoint.txid.0.to_le_bytes(), add.outpoint.vout),
                add.txout.script_pubkey.as_bytes().to_vec(),
            );
        }
        Ok(Self { scripts })
    }
}

impl bitcoin_rs_index::SpentCoinScripts for UndoScripts {
    fn script_bytes(&self, txid: &[u8; 32], vout: u32) -> Option<&[u8]> {
        self.scripts.get(&(*txid, vout)).map(Vec::as_slice)
    }
}

impl Worker {
    pub(super) fn forward_selection(
        &self,
        watermarks: IndexWatermarks,
        target: &TipSnapshot,
    ) -> Option<(IndexCapabilities, Option<IndexWatermark>)> {
        let tx = self.enabled.tx_lookup.then_some(watermarks.tx_lookup);
        let script_index = self
            .enabled
            .script_history
            .then_some(watermarks.script_history);
        let script_live = self.enabled.script_live.then_some(watermarks.script_live);
        let needs_forward = |watermark: Option<IndexWatermark>| {
            watermark.is_none_or(|watermark| watermark.height < target.height)
        };
        let start_height = |watermark: Option<IndexWatermark>| {
            watermark.map_or(0, |watermark| watermark.height.saturating_add(1))
        };
        let selected_start = [tx, script_index, script_live]
            .into_iter()
            .flatten()
            .filter(|watermark| needs_forward(*watermark))
            .map(start_height)
            .min()?;
        let selected_watermark = if selected_start == 0 {
            None
        } else {
            let height = selected_start - 1;
            [tx, script_index, script_live]
                .into_iter()
                .flatten()
                .flatten()
                .find(|watermark| watermark.height == height)
        };
        Some((
            IndexCapabilities {
                tx_lookup: tx.is_some_and(|watermark| {
                    needs_forward(watermark) && start_height(watermark) == selected_start
                }),
                script_history: script_index.is_some_and(|watermark| {
                    needs_forward(watermark) && start_height(watermark) == selected_start
                }),
                script_live: script_live.is_some_and(|watermark| {
                    needs_forward(watermark) && start_height(watermark) == selected_start
                }),
            },
            selected_watermark,
        ))
    }
    /// Copies one bounded chunk of active-chain identities under one short
    /// read lock.
    fn collect_target_chain(
        &self,
        target: &TipSnapshot,
        start_height: u32,
        end_height: u32,
    ) -> Result<Vec<BlockIdentity>, TxIndexWorkerError> {
        let tree = self.block_tree.read();
        let capacity = usize::try_from(end_height.saturating_sub(start_height).saturating_add(1))
            .unwrap_or(usize::MAX);
        let mut identities = Vec::with_capacity(capacity);
        for height in start_height..=end_height {
            let node_id = tree
                .node_at_height_from(target.tip_id, height)
                .ok_or(TxIndexWorkerError::MissingTargetChain { height })?;
            let node = tree
                .node(node_id)
                .map_err(|_| TxIndexWorkerError::MissingTargetChain { height })?;
            let parent_hash = if height == 0 {
                [0_u8; 32]
            } else {
                let parent_id = tree
                    .parent_id(node_id)
                    .map_err(|_| TxIndexWorkerError::MissingTargetChain { height })?
                    .ok_or(TxIndexWorkerError::MissingTargetChain { height })?;
                let parent = tree
                    .node(parent_id)
                    .map_err(|_| TxIndexWorkerError::MissingTargetChain { height })?;
                *parent.hash.as_byte_array()
            };
            identities.push(BlockIdentity {
                height,
                hash: *node.hash.as_byte_array(),
                parent_hash,
            });
        }
        Ok(identities)
    }

    pub(super) fn catch_up_to(
        &self,
        target: &TipSnapshot,
        fence: IndexWriteFence,
        watermarks: IndexWatermarks,
        watermark: Option<IndexWatermark>,
        capabilities: IndexCapabilities,
        pending: &mut Option<PendingForward>,
    ) -> Result<ReconcileAction, TxIndexWorkerError> {
        if self.runtime.should_stop() {
            return Ok(ReconcileAction::Stalled);
        }

        let mut state = pending.take().unwrap_or_else(|| PendingForward {
            fence,
            watermarks,
            capabilities,
            durable: watermark,
            batch: PreparedBatch::new(self.batch_limits),
            deadline: Instant::now() + self.batch_delay,
        });
        if state.durable != watermark || state.capabilities != capabilities {
            return Err(TxIndexWorkerError::PendingDurableChanged);
        }
        let start_height = state.batch.watermark().map_or_else(
            || watermark.map_or(0, |w| w.height.saturating_add(1)),
            |endpoint| endpoint.height.saturating_add(1),
        );
        if start_height > target.height {
            return if self.sync_and_commit(state)?.is_some() {
                Ok(ReconcileAction::CaughtUp)
            } else {
                Ok(ReconcileAction::Stalled)
            };
        }

        let chunk_end = start_height
            .saturating_add(IDENTITY_CHUNK_BLOCKS - 1)
            .min(target.height);
        let identities = self.collect_target_chain(target, start_height, chunk_end)?;
        if self.runtime.should_stop() {
            return Ok(ReconcileAction::Stalled);
        }
        let Some(body_store) = self.body_store.as_ref() else {
            return Err(TxIndexWorkerError::NoBodyStore);
        };
        let mut body_reader = body_store.reader().map_err(TxIndexWorkerError::Storage)?;
        let mut requests = Vec::with_capacity(POSITION_PREFETCH_BLOCKS);
        for identities in identities.chunks(POSITION_PREFETCH_BLOCKS) {
            if self.runtime.should_stop() {
                return Ok(ReconcileAction::Stalled);
            }
            requests.clear();
            requests.extend(
                identities
                    .iter()
                    .map(|identity| (identity.height, Hash256::from_le_bytes(&identity.hash))),
            );
            body_reader
                .prefetch_positions(&requests)
                .map_err(TxIndexWorkerError::Storage)?;

            // Sub-chunk: load bodies serially until the count or byte cap
            // (preserving the reader's prefetch state), prepare blocks in
            // parallel across the rayon pool, then push prepared blocks into
            // the batch in height order. The single-writer commit and
            // watermark publish remain the only ordering points (#209
            // invariants).
            let mut remaining = identities;
            while !remaining.is_empty() {
                match self.prepare_and_admit_chunk(
                    &mut remaining,
                    &mut body_reader,
                    capabilities,
                    &mut state,
                    pending,
                )? {
                    ChunkAction::Continue => {}
                    ChunkAction::Stalled => return Ok(ReconcileAction::Stalled),
                    ChunkAction::Progressed => return Ok(ReconcileAction::Progressed),
                }
            }
        }

        self.finish_catch_up(state, chunk_end, target, pending)
    }

    /// Loads bodies serially until the count or byte cap, prepares that prefix
    /// in parallel across the rayon pool, then admits them into the batch in
    /// height order on the single writer thread. Advances `identities` past
    /// the loaded prefix. Returns `Stalled` if a body is missing or shutdown
    /// was requested, `Progressed` if the batch filled and was committed, or
    /// `Continue` to keep processing.
    #[allow(clippy::too_many_lines)]
    fn prepare_and_admit_chunk(
        &self,
        identities: &mut &[BlockIdentity],
        body_reader: &mut Box<dyn BlockBodyReader + '_>,
        capabilities: IndexCapabilities,
        state: &mut PendingForward,
        pending: &mut Option<PendingForward>,
    ) -> Result<ChunkAction, TxIndexWorkerError> {
        if self.runtime.should_stop() {
            return Ok(ChunkAction::Stalled);
        }

        // Load bodies serially through the single reader until either cap.
        // The first body is always retained so catch-up moves; a later body
        // that would cross the byte cap is left at the front of `identities`.
        let mut bodies = Vec::new();
        let mut loaded_bytes = 0_usize;
        for identity in *identities {
            if self.runtime.should_stop() {
                return Ok(ChunkAction::Stalled);
            }
            let hash = Hash256::from_le_bytes(&identity.hash);
            match body_reader.load_block_body(identity.height, hash) {
                Ok(Some(body)) => {
                    if !bodies.is_empty()
                        && loaded_bytes.saturating_add(body.len()) > PREPARE_CHUNK_BYTES
                    {
                        break;
                    }
                    loaded_bytes = loaded_bytes.saturating_add(body.len());
                    bodies.push(body);
                }
                Ok(None) => {
                    if !state.batch.is_empty() {
                        let replacement = PendingForward {
                            fence: state.fence,
                            watermarks: state.watermarks,
                            capabilities: state.capabilities,
                            durable: state.durable,
                            batch: PreparedBatch::new(self.batch_limits),
                            deadline: state.deadline,
                        };
                        *pending = Some(std::mem::replace(state, replacement));
                    }
                    return Ok(ChunkAction::Stalled);
                }
                Err(e) => return Err(TxIndexWorkerError::Storage(e)),
            }
            if bodies.len() >= PREPARE_CHUNK_BLOCKS {
                break;
            }
        }
        let loaded = bodies.len();
        let sub_chunk = &identities[..loaded];

        let anchors = if capabilities.script_live {
            let mut anchors = Vec::with_capacity(sub_chunk.len());
            for identity in sub_chunk {
                match self.live_anchor(identity.height, identity.hash) {
                    Ok(anchor) => anchors.push(anchor),
                    Err(error @ TxIndexWorkerError::UndoUnavailable { .. }) => {
                        *pending = None;
                        self.writer
                            .reset_capabilities(IndexCapabilities::SCRIPT_LIVE)
                            .map_err(TxIndexWorkerError::Index)?;
                        tracing::warn!(error = %error, "rebuilding ScriptLive after pruned undo");
                        return Ok(ChunkAction::Stalled);
                    }
                    Err(error) => return Err(error),
                }
            }
            Some(anchors)
        } else {
            None
        };

        // Prepare blocks in parallel. Each call takes a shared read lock on the
        // RwLock-backed writer, so the CPU-bound decode/row-build runs
        // concurrently across pool threads.
        let prepared: Vec<Result<PreparedBlock, IndexError>> = sub_chunk
            .par_iter()
            .zip(bodies.par_iter())
            .enumerate()
            .map(|(index, (identity, body))| {
                let spent: &dyn bitcoin_rs_index::SpentCoinScripts = match anchors.as_ref() {
                    Some(anchors) => &anchors[index],
                    None => &NoSpentScripts,
                };
                self.writer.prepare_block_with_spent_scripts(
                    capabilities,
                    identity.height,
                    identity.hash,
                    body.as_slice(),
                    spent,
                )
            })
            .collect();
        drop(bodies);

        if self.runtime.should_stop() {
            return Ok(ChunkAction::Stalled);
        }

        // Push prepared blocks into the batch in height order on the single
        // writer thread.
        for (result, identity) in prepared.into_iter().zip(sub_chunk.iter()) {
            let prepared = result.map_err(TxIndexWorkerError::Index)?;
            if identity.height > 0 && prepared.parent_hash != identity.parent_hash {
                return Err(TxIndexWorkerError::MissingTargetChain {
                    height: identity.height,
                });
            }
            if state.batch.try_push(prepared).is_err() {
                let replacement = PendingForward {
                    fence: state.fence,
                    watermarks: state.watermarks,
                    capabilities: state.capabilities,
                    durable: state.durable,
                    batch: PreparedBatch::new(self.batch_limits),
                    deadline: state.deadline,
                };
                return if self
                    .sync_and_commit(std::mem::replace(state, replacement))?
                    .is_some()
                {
                    Ok(ChunkAction::Progressed)
                } else {
                    Ok(ChunkAction::Stalled)
                };
            }
            if state.batch.is_full() {
                let replacement = PendingForward {
                    fence: state.fence,
                    watermarks: state.watermarks,
                    capabilities: state.capabilities,
                    durable: state.durable,
                    batch: PreparedBatch::new(self.batch_limits),
                    deadline: state.deadline,
                };
                return if self
                    .sync_and_commit(std::mem::replace(state, replacement))?
                    .is_some()
                {
                    Ok(ChunkAction::Progressed)
                } else {
                    Ok(ChunkAction::Stalled)
                };
            }
        }
        *identities = &identities[loaded..];
        Ok(ChunkAction::Continue)
    }
    pub(super) fn finish_catch_up(
        &self,
        state: PendingForward,
        chunk_end: u32,
        target: &TipSnapshot,
        pending: &mut Option<PendingForward>,
    ) -> Result<ReconcileAction, TxIndexWorkerError> {
        if chunk_end < target.height {
            *pending = Some(state);
            return Ok(ReconcileAction::Progressed);
        }

        let endpoint = state.endpoint();
        let latest = self.applied_tip.load_full();
        if latest.as_deref().is_some_and(|tip| {
            endpoint.height < tip.height && self.watermark_is_on_target_chain(endpoint, tip)
        }) {
            *pending = Some(state);
            return Ok(ReconcileAction::Progressed);
        }

        if latest.as_deref().is_some_and(|tip| {
            endpoint.height == tip.height && endpoint.hash == tip.hash.to_le_bytes()
        }) {
            *pending = Some(state);
            return Ok(ReconcileAction::Buffered);
        }

        if self.sync_and_commit(state)?.is_some() {
            Ok(ReconcileAction::Progressed)
        } else {
            Ok(ReconcileAction::Stalled)
        }
    }
}

const IDENTITY_CHUNK_BLOCKS: u32 = 65_536;

const POSITION_PREFETCH_BLOCKS: usize = 65_536;

/// In-memory parallel-prepare cap owned by this worker. 256 matches the IBD
/// download window so a filled staging set can prepare in one pass when bodies
/// are small; catch-up also prepares already-stored bodies, so this is not
/// `RECEIVED_BLOCK_BUDGET`. The byte budget below is independent of P2P staging.
const PREPARE_CHUNK_BLOCKS: usize = 256;

/// Serialized-body budget for one parallel prepare step. Later bodies are not
/// retained once this bound would be exceeded. Stops a 1 MiB-class window from
/// holding 256 bodies in RAM while still packing early-chain blocks up to the
/// count cap.
const PREPARE_CHUNK_BYTES: usize = 32 << 20;

/// Identity of one block on the active chain, captured under a short tree lock.
#[derive(Clone, Copy, Debug)]
struct BlockIdentity {
    height: u32,
    hash: [u8; 32],
    parent_hash: [u8; 32],
}

/// Outcome of one sub-chunk prepare-and-admit step.
enum ChunkAction {
    Continue,
    Stalled,
    Progressed,
}
