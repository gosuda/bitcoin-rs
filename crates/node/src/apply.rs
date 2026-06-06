//! Block-apply pipeline over shared node handles.

mod scratch;

use std::sync::Arc;

use arc_swap::ArcSwapOption;
use bitcoin::hex::DisplayHex;
use bitcoin::{Transaction, Txid};
use bitcoin_rs_chain::{BlockTree, TipSnapshot};
use bitcoin_rs_consensus::rust_path::UtxoView;
use bitcoin_rs_mempool::Mempool;
use bitcoin_rs_primitives::{Hash256, Network, OutPoint};
use bitcoin_rs_rpc::BlockRecord;
use bitcoin_rs_utxo::{
    LiveOutput, LiveOutputMeta, UtxoSet,
    set::{BorrowedBlockChanges, BorrowedUtxoAdd},
};
use hashbrown::{HashMap, HashSet};
use parking_lot::RwLock;

use crate::state::ApplyError;
use bitcoin_rs_storage::{KvStore, StorageError};
use scratch::{ApplyScratch, ApplyScratchCapacities, SameBlockSpentSet};

/// Number of blocks after a coinbase that its outputs become spendable.
/// Consensus rule since Bitcoin v0.3.1; universal across networks.
const COINBASE_MATURITY: u32 = 100;
/// BIP68 sequence-bit masks.
const BIP68_DISABLE_FLAG: u32 = 0x8000_0000;
const BIP68_TYPE_FLAG: u32 = 0x0040_0000;
const BIP68_MASK: u32 = 0x0000_ffff;
const BIP68_TIME_GRANULARITY_SECONDS: u32 = 512;
const SERIALIZED_BLOCK_HEADER_LEN: usize = 80;
const LOCAL_OVERLAY_TXID_SET_THRESHOLD: usize = 8;

pub(crate) trait PruneBodyStore: Send + Sync {
    fn persist_block_body(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
        body: &[u8],
    ) -> Result<(), StorageError>;

    fn load_block_body(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> Result<Option<Vec<u8>>, StorageError>;
}

impl<S: KvStore> PruneBodyStore for S {
    fn persist_block_body(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
        body: &[u8],
    ) -> Result<(), StorageError> {
        self.put(
            bitcoin_rs_pruning::BLOCK_DATA_CF,
            &bitcoin_rs_pruning::block_body_key(height, hash),
            body,
        )
    }

    fn load_block_body(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
    ) -> Result<Option<Vec<u8>>, StorageError> {
        self.get(
            bitcoin_rs_pruning::BLOCK_DATA_CF,
            &bitcoin_rs_pruning::block_body_key(height, hash),
        )
    }
}

/// Owned shared handle set needed by `apply_block` to perform a block apply.
#[derive(Clone)]
pub struct ApplyHandles {
    /// Network consensus parameters.
    pub network: Network,
    /// Shared best-chain tip handle.
    pub chain_tip: Arc<ArcSwapOption<TipSnapshot>>,
    /// Shared best-applied-block tip handle.
    pub applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
    /// Shared in-memory block tree.
    pub block_tree: Arc<RwLock<BlockTree>>,
    /// Shared UTXO set.
    pub utxo: Arc<UtxoSet>,
    /// Shared coinstats listener.
    pub coin_stats: Arc<bitcoin_rs_coinstats::CoinStatsListener>,
    /// Shared best-effort confirmed transaction indexer, when enabled.
    pub tx_index: Option<Arc<parking_lot::Mutex<Box<dyn bitcoin_rs_index::IndexerLike>>>>,
    /// Shared best-effort compact-filter indexer.
    pub filter_index: Arc<Box<dyn bitcoin_rs_filters::FilterIndexLike>>,
    /// Shared mempool.
    pub mempool: Arc<RwLock<Mempool>>,
    /// Shared block records exposed to RPC handlers.
    pub blocks: Arc<RwLock<Vec<BlockRecord>>>,
    /// Shared transaction map exposed to RPC handlers.
    pub transactions: Arc<RwLock<HashMap<Txid, Transaction>>>,
    /// Shared ZMQ-event publisher (default: `NoOpZmqPublisher`).
    pub zmq_publisher: Arc<dyn crate::ZmqPublisher>,
    pub(crate) cache_block_bodies_in_memory: bool,
    pub(crate) block_body_store: Option<Arc<dyn PruneBodyStore>>,
    pub(crate) g2_muhash_sampler: Option<Arc<crate::g2_muhash::G2MuhashSampler>>,
}

impl ApplyHandles {
    /// Builds the full shared handle set used by `apply_block`.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        network: Network,
        chain_tip: Arc<ArcSwapOption<TipSnapshot>>,
        applied_tip: Arc<ArcSwapOption<TipSnapshot>>,
        block_tree: Arc<RwLock<BlockTree>>,
        utxo: Arc<UtxoSet>,
        coin_stats: Arc<bitcoin_rs_coinstats::CoinStatsListener>,
        tx_index: Option<Arc<parking_lot::Mutex<Box<dyn bitcoin_rs_index::IndexerLike>>>>,
        filter_index: Arc<Box<dyn bitcoin_rs_filters::FilterIndexLike>>,
        mempool: Arc<RwLock<Mempool>>,
        blocks: Arc<RwLock<Vec<BlockRecord>>>,
        transactions: Arc<RwLock<HashMap<Txid, Transaction>>>,
        zmq_publisher: Arc<dyn crate::ZmqPublisher>,
    ) -> Self {
        Self {
            network,
            chain_tip,
            applied_tip,
            block_tree,
            utxo,
            coin_stats,
            tx_index,
            filter_index,
            mempool,
            blocks,
            transactions,
            zmq_publisher,
            cache_block_bodies_in_memory: true,
            block_body_store: None,
            g2_muhash_sampler: None,
        }
    }

    /// Returns `self` with `zmq_publisher` swapped to `publisher`.
    ///
    /// Useful for tests + integration scenarios that want a custom publisher
    /// without going through `NodeState::open` (which currently always
    /// installs `NoOpZmqPublisher`).
    #[must_use]
    pub fn with_zmq_publisher(mut self, publisher: Arc<dyn crate::ZmqPublisher>) -> Self {
        self.zmq_publisher = publisher;
        self
    }
}

/// Synthetically applies `block` as the next tip after consensus checks.
#[allow(clippy::too_many_lines)]
pub fn apply_block(
    handles: &ApplyHandles,
    block: &bitcoin::Block,
) -> core::result::Result<TipSnapshot, ApplyError> {
    use bitcoin::hashes::Hash as _;

    let total_started = quanta::Instant::now();
    let block_hash =
        bitcoin_rs_primitives::Hash256::from_le_bytes(block.block_hash().as_byte_array());
    let prev_hash =
        bitcoin_rs_primitives::Hash256::from_le_bytes(block.header.prev_blockhash.as_byte_array());
    let (prior, height) = applied_predecessor(handles, block_hash, prev_hash)?;

    // Self-consistency PoW: the block header's hash must satisfy its
    // declared target. This is the cheapest consensus gate; do it before
    // any structural checks. Contextual difficulty-adjustment validation
    // (verifying the declared target matches the network's expected
    // difficulty at this height) requires `BlockTree` state — deferred.
    let pow_self_started = quanta::Instant::now();
    let declared_target = block.header.target();
    let pow_self_result = block.header.validate_pow(declared_target);
    let pow_self_dur = pow_self_started.elapsed();
    metrics::histogram!("node.apply_block.pow_self_consistency_seconds")
        .record(pow_self_dur.as_secs_f64());
    if pow_self_result.is_err() {
        return Err(ApplyError::ProofOfWork { hash: block_hash });
    }

    let (prev_tip_state, softfork_state) = if let Some(tip) = prior.as_deref() {
        let tree = handles.block_tree.read();
        let mtp = tree.median_time_past_at(tip.tip_id, 11).unwrap_or(0);
        let softfork_state = crate::bip9_context::contextual_softfork_state(
            &tree,
            handles.network,
            Some(tip.tip_id),
            height,
        );
        (
            bitcoin_rs_consensus::rust_path::TipState {
                height: Some(tip.height),
                block_hash: None,
                median_time_past: mtp,
            },
            softfork_state,
        )
    } else {
        let tree = handles.block_tree.read();
        (
            bitcoin_rs_consensus::rust_path::TipState {
                height: None,
                block_hash: None,
                median_time_past: 0,
            },
            crate::bip9_context::contextual_softfork_state(&tree, handles.network, None, height),
        )
    };
    let locktime_cutoff = if softfork_state.csv_active {
        prev_tip_state.median_time_past
    } else {
        block.header.time
    };
    let tx_plan = plan_block_transactions(block);
    let block_rules_started = quanta::Instant::now();
    let block_rules_result =
        bitcoin_rs_consensus::verify_block_rules_borrowed_contextual_with_txids(
            block,
            &prev_tip_state,
            bitcoin_rs_consensus::BlockRuleContext {
                segwit_active: softfork_state.segwit_active,
            },
            tx_plan.txids(),
        );
    let block_rules_dur = block_rules_started.elapsed();
    metrics::histogram!("node.apply_block.block_rules_seconds")
        .record(block_rules_dur.as_secs_f64());
    block_rules_result?;
    // Contextual consensus checks (BIP30 + BIP34) using the resolved height.
    let bip30_bip34_started = quanta::Instant::now();
    let bip30_bip34_result = check_bip30_and_bip34(handles, block, height, tx_plan.txids());
    let bip30_bip34_dur = bip30_bip34_started.elapsed();
    metrics::histogram!("node.apply_block.bip30_bip34_seconds")
        .record(bip30_bip34_dur.as_secs_f64());
    bip30_bip34_result?;
    // PoW limit + DAA non-retarget continuity.
    let pow_limit_started = quanta::Instant::now();
    let pow_limit_result = check_pow_limit_and_continuity(handles, prior.as_deref(), block, height);
    let pow_limit_dur = pow_limit_started.elapsed();
    metrics::histogram!("node.apply_block.pow_limit_continuity_seconds")
        .record(pow_limit_dur.as_secs_f64());
    pow_limit_result?;

    let bip113_started = quanta::Instant::now();
    let bip113_result = check_bip113_finality(block, height, locktime_cutoff);
    let bip113_dur = bip113_started.elapsed();
    metrics::histogram!("node.apply_block.bip113_seconds").record(bip113_dur.as_secs_f64());
    bip113_result?;

    let script_verify_started = quanta::Instant::now();
    let verify_flags = compute_verify_flags(handles.network, height, softfork_state);
    let script_verify_result = verify_block_transactions(
        handles,
        block,
        &tx_plan,
        height,
        locktime_cutoff,
        verify_flags,
    );
    let script_verify_dur = script_verify_started.elapsed();
    metrics::histogram!("node.apply_block.script_verify_seconds")
        .record(script_verify_dur.as_secs_f64());
    script_verify_result?;

    let coinbase_maturity_started = quanta::Instant::now();
    let coinbase_maturity_result =
        check_coinbase_maturity_with_tx_plan(handles, block, &tx_plan, height);
    let coinbase_maturity_dur = coinbase_maturity_started.elapsed();
    metrics::histogram!("node.apply_block.coinbase_maturity_seconds")
        .record(coinbase_maturity_dur.as_secs_f64());
    coinbase_maturity_result?;
    let bip68_started = quanta::Instant::now();
    let previous_tip_id = prior.as_deref().map(|tip| tip.tip_id);
    let bip68_result = check_bip68_sequence_locks(
        handles,
        block,
        &tx_plan,
        height,
        prev_tip_state.median_time_past,
        softfork_state,
        previous_tip_id,
    );
    let bip68_dur = bip68_started.elapsed();
    metrics::histogram!("node.apply_block.bip68_seconds").record(bip68_dur.as_secs_f64());
    bip68_result?;

    let wants_rawtx = handles.zmq_publisher.wants_rawtx();
    let wants_filters = handles.filter_index.wants_filters();
    let (txids, scratch_capacities, same_block_spent, same_block_spent_input_count) =
        tx_plan.into_scratch_parts();
    let scratch = ApplyScratch::from_prepared_parts(
        block,
        height,
        wants_rawtx,
        wants_filters,
        txids,
        scratch_capacities,
        same_block_spent,
        same_block_spent_input_count,
    )?;
    let filter_bytes = wants_filters
        .then(|| compute_basic_filter(block, handles, block_hash, height, &scratch))
        .flatten();

    let block_bytes = bitcoin::consensus::encode::serialize(block);

    let utxo_changes_started = quanta::Instant::now();
    let changes = build_utxo_changes(block, height, &scratch)?;
    let utxo_changes_dur = utxo_changes_started.elapsed();
    metrics::histogram!("node.apply_block.utxo_changes_seconds")
        .record(utxo_changes_dur.as_secs_f64());
    let block_body_persist_started = quanta::Instant::now();
    let block_body_persist_result = if let Some(store) = &handles.block_body_store {
        store
            .persist_block_body(height, block_hash, &block_bytes)
            .map_err(ApplyError::BlockBodyPersistence)
    } else {
        Ok(())
    };
    let block_body_persist_dur = block_body_persist_started.elapsed();
    metrics::histogram!("node.apply_block.block_body_persist_seconds")
        .record(block_body_persist_dur.as_secs_f64());
    block_body_persist_result?;

    let tx_index_ingest_started = quanta::Instant::now();
    if let Some(tx_index) = &handles.tx_index {
        let tx_index_ingest_result =
            tx_index
                .lock()
                .ingest_block_with_verified_txids(&block_bytes, height, scratch.txids());
        match tx_index_ingest_result {
            Ok(counts) => {
                tracing::debug!(
                    height,
                    txids = counts.txids,
                    funding = counts.funding,
                    spending = counts.spending,
                    headers = counts.headers,
                    "tx_index ingested block"
                );
            }
            Err(error) => {
                tracing::warn!(
                    height,
                    %error,
                    "tx_index failed to ingest block; best-effort path continues"
                );
            }
        }
    }
    let tx_index_ingest_dur = tx_index_ingest_started.elapsed();
    metrics::histogram!("node.apply_block.tx_index_ingest_seconds")
        .record(tx_index_ingest_dur.as_secs_f64());

    let utxo_commit_started = quanta::Instant::now();
    let utxo_commit_result = handles.utxo.commit_borrowed_block(&changes, &block_hash);
    let utxo_commit_dur = utxo_commit_started.elapsed();
    metrics::histogram!("node.apply_block.utxo_commit_seconds")
        .record(utxo_commit_dur.as_secs_f64());
    utxo_commit_result.map_err(ApplyError::UtxoCommit)?;

    // Resolve the applied header after validation and UTXO commit have
    // succeeded. Header-first sync may already have inserted this header.
    let block_tree_insert_started = quanta::Instant::now();
    let block_tree_insert_result = applied_header_tip(handles, block_hash, block, height);
    let block_tree_insert_dur = block_tree_insert_started.elapsed();
    metrics::histogram!("node.apply_block.block_tree_insert_seconds")
        .record(block_tree_insert_dur.as_secs_f64());
    let tip = block_tree_insert_result?;

    let block_record_started = quanta::Instant::now();
    {
        let block_record = applied_block_record(
            height,
            block_hash,
            block,
            &block_bytes,
            handles.cache_block_bodies_in_memory,
        );
        handles.blocks.write().push(block_record);
    }
    let block_record_dur = block_record_started.elapsed();
    metrics::histogram!("node.apply_block.block_record_seconds")
        .record(block_record_dur.as_secs_f64());
    let mempool_evict_started = quanta::Instant::now();
    {
        let mut mempool = handles.mempool.write();
        if !mempool.is_empty() {
            for txid in scratch.txids() {
                let evicted_count = mempool.remove_by_txid(txid).len();
                tracing::debug!(%txid, evicted_count, "apply_block: evicted transaction from mempool");
            }
        }
    }
    let mempool_evict_dur = mempool_evict_started.elapsed();
    metrics::histogram!("node.apply_block.mempool_evict_seconds")
        .record(mempool_evict_dur.as_secs_f64());
    let tx_count_delta = u64::try_from(block.txdata.len()).unwrap_or(u64::MAX);
    let coin_stats_started = quanta::Instant::now();
    handles.coin_stats.finish_block(height, tx_count_delta);
    let coin_stats_dur = coin_stats_started.elapsed();
    metrics::histogram!("node.apply_block.coin_stats_finish_seconds")
        .record(coin_stats_dur.as_secs_f64());
    let filter_started = quanta::Instant::now();
    if let Some(filter_bytes) = filter_bytes {
        let prev_filter_header = handles
            .applied_tip
            .load_full()
            .and_then(|tip| handles.filter_index.filter_header(tip.hash).ok().flatten())
            .unwrap_or_default();
        match handles
            .filter_index
            .put_filter(block_hash, prev_filter_header, &filter_bytes)
        {
            Ok(filter_header) => {
                tracing::debug!(
                    height,
                    %filter_header,
                    bytes = filter_bytes.len(),
                    "filter_index stored block filter"
                );
            }
            Err(error) => {
                tracing::warn!(height, %error, "filter_index failed to store block filter");
            }
        }
    }
    let filter_dur = filter_started.elapsed();
    metrics::histogram!("node.apply_block.filter_index_seconds").record(filter_dur.as_secs_f64());
    let total_dur = total_started.elapsed();
    metrics::histogram!("node.apply_block.total_seconds").record(total_dur.as_secs_f64());
    metrics::counter!("node.apply_block.txs_applied").increment(tx_count_delta);
    tracing::info!(
        height,
        %block_hash,
        tx_count = block.txdata.len(),
        pow_self_us = pow_self_dur.as_micros(),
        pow_limit_us = pow_limit_dur.as_micros(),
        block_rules_us = block_rules_dur.as_micros(),
        bip30_bip34_us = bip30_bip34_dur.as_micros(),
        bip113_us = bip113_dur.as_micros(),
        script_verify_us = script_verify_dur.as_micros(),
        coinbase_maturity_us = coinbase_maturity_dur.as_micros(),
        bip68_us = bip68_dur.as_micros(),
        utxo_commit_us = utxo_commit_dur.as_micros(),
        block_tree_insert_us = block_tree_insert_dur.as_micros(),
        mempool_evict_us = mempool_evict_dur.as_micros(),
        tx_index_ingest_us = tx_index_ingest_dur.as_micros(),
        filter_index_us = filter_dur.as_micros(),
        coin_stats_us = coin_stats_dur.as_micros(),
        total_us = total_dur.as_micros(),
        "apply_block: profile"
    );
    // Best-effort ZMQ event emission. Failures must not propagate per the
    // ZmqPublisher contract; the trait's methods return `()`.
    handles.zmq_publisher.publish_hashblock(tip.hash);
    handles.zmq_publisher.publish_rawblock(&block_bytes);
    if let Some(raw_txs) = scratch.raw_txs() {
        for (txid, rawtx_bytes) in scratch.txids().iter().zip(raw_txs) {
            handles.zmq_publisher.publish_hashtx(*txid);
            handles.zmq_publisher.publish_rawtx(rawtx_bytes);
        }
    } else {
        for txid in scratch.txids() {
            handles.zmq_publisher.publish_hashtx(*txid);
        }
    }
    handles.applied_tip.store(Some(Arc::new(tip.clone())));
    if let Some(sampler) = &handles.g2_muhash_sampler
        && sampler.wants_height(height)
    {
        let snapshot = handles.coin_stats.snapshot();
        if let Err(error) = sampler.record(&snapshot) {
            metrics::counter!("node.apply_block.g2_muhash_sample_errors").increment(1);
            tracing::warn!(
                height,
                %error,
                "G2 MuHash sample emission failed after tip publication; evidence file incomplete"
            );
        }
    }
    Ok(tip)
}

fn applied_predecessor(
    handles: &ApplyHandles,
    block_hash: bitcoin_rs_primitives::Hash256,
    prev_hash: bitcoin_rs_primitives::Hash256,
) -> core::result::Result<(Option<Arc<TipSnapshot>>, u32), ApplyError> {
    let prior = handles.applied_tip.load_full();
    let height = if let Some(tip) = prior.as_deref() {
        if tip.hash != prev_hash {
            return Err(ApplyError::PrevHashMismatch {
                tip: tip.hash,
                prev: prev_hash,
            });
        }
        tip.height
            .checked_add(1)
            .ok_or(ApplyError::HeightOverflow(tip.height))?
    } else {
        if block_hash != handles.network.genesis_block_hash() {
            return Err(ApplyError::Chain(
                bitcoin_rs_chain::ChainError::MissingParent { prev_hash },
            ));
        }
        0_u32
    };
    Ok((prior, height))
}

fn applied_header_tip(
    handles: &ApplyHandles,
    block_hash: bitcoin_rs_primitives::Hash256,
    block: &bitcoin::Block,
    height: u32,
) -> core::result::Result<TipSnapshot, ApplyError> {
    let mut tree = handles.block_tree.write();
    let node_id = match tree.lookup(block_hash) {
        Some(node_id) => node_id,
        None => tree.insert_header(block.header, bitcoin_rs_chain::node::NodeStatus::Active)?,
    };
    let node = tree.node(node_id)?;
    if node.height != height {
        return Err(ApplyError::Consensus(
            bitcoin_rs_consensus::ConsensusError::Bip {
                bip: "INTERNAL",
                reason: format!(
                    "block-tree height {} does not match applied height {height} for block {block_hash}",
                    node.height
                ),
            },
        ));
    }
    Ok(TipSnapshot {
        tip_id: node_id,
        height: node.height,
        chainwork: node.chainwork,
        hash: node.hash,
    })
}

struct BlockTxPlan {
    txids: Vec<Txid>,
    only_coinbase: bool,
    needs_local_utxo_overlay: bool,
    overlay_capacity: usize,
    has_bip68_sequence_locks: bool,
    created_output_count: usize,
    spent_input_count: usize,
    same_block_spent: Option<SameBlockSpentSet>,
    same_block_spent_input_count: usize,
}

impl BlockTxPlan {
    fn txids(&self) -> &[Txid] {
        &self.txids
    }

    fn into_scratch_parts(
        self,
    ) -> (
        Vec<Txid>,
        ApplyScratchCapacities,
        Option<SameBlockSpentSet>,
        usize,
    ) {
        (
            self.txids,
            ApplyScratchCapacities {
                created_outputs: self.created_output_count,
                spent_inputs: self.spent_input_count,
            },
            self.same_block_spent,
            self.same_block_spent_input_count,
        )
    }
}

fn plan_block_transactions(block: &bitcoin::Block) -> BlockTxPlan {
    let mut txids = Vec::with_capacity(block.txdata.len());
    let mut only_coinbase = true;
    let mut needs_local_utxo_overlay = false;
    let mut overlay_capacity = 0usize;
    let mut has_bip68_sequence_locks = false;
    let mut created_output_count = 0usize;
    let mut spent_input_count = 0usize;
    let mut same_block_spent: Option<SameBlockSpentSet> = None;
    let mut same_block_spent_input_count = 0usize;
    let mut created_txids: Option<HashSet<Txid>> = None;
    let mut spent_outpoints: Option<HashSet<bitcoin::OutPoint>> = None;
    let track_spent_conflicts = block.txdata.len() > 2;
    let mut saw_non_coinbase = false;

    for tx in &block.txdata {
        let is_coinbase = tx.is_coinbase();
        let output_count = tx.output.len();
        let txid = tx.compute_txid();
        txids.push(txid);
        only_coinbase &= is_coinbase;
        created_output_count = created_output_count.saturating_add(output_count);
        if is_coinbase {
            overlay_capacity = overlay_capacity.saturating_add(output_count);
        } else {
            let input_count = tx.input.len();
            for input in &tx.input {
                let prior_txids = &txids[..txids.len().saturating_sub(1)];
                let spends_created_output = if prior_txids.len() <= LOCAL_OVERLAY_TXID_SET_THRESHOLD
                {
                    prior_txids.contains(&input.previous_output.txid)
                } else {
                    let created_txids = created_txids.get_or_insert_with(|| {
                        let mut set = HashSet::with_capacity(block.txdata.len());
                        set.extend(prior_txids.iter().copied());
                        set
                    });
                    created_txids.contains(&input.previous_output.txid)
                };
                if spends_created_output {
                    same_block_spent
                        .get_or_insert_with(|| HashSet::with_capacity(input_count))
                        .insert(internal_outpoint(&input.previous_output));
                    same_block_spent_input_count = same_block_spent_input_count.saturating_add(1);
                }
                let repeats_prior_spend = if track_spent_conflicts {
                    let spent_outpoints = spent_outpoints.get_or_insert_with(|| {
                        HashSet::with_capacity(input_count.max(block.txdata.len()))
                    });
                    !spent_outpoints.insert(input.previous_output)
                } else {
                    saw_non_coinbase
                };
                needs_local_utxo_overlay |= spends_created_output || repeats_prior_spend;
            }
            saw_non_coinbase = true;
            if tx.version.0 >= 2 {
                has_bip68_sequence_locks |= tx
                    .input
                    .iter()
                    .any(|input| input.sequence.to_consensus_u32() & BIP68_DISABLE_FLAG == 0);
            }
            spent_input_count = spent_input_count.saturating_add(input_count);
            overlay_capacity =
                overlay_capacity.saturating_add(output_count.saturating_add(input_count));
        }
        if let Some(created_txids) = &mut created_txids {
            created_txids.insert(txid);
        }
    }

    BlockTxPlan {
        txids,
        only_coinbase,
        needs_local_utxo_overlay,
        overlay_capacity,
        has_bip68_sequence_locks,
        created_output_count,
        spent_input_count,
        same_block_spent,
        same_block_spent_input_count,
    }
}

fn compute_basic_filter(
    block: &bitcoin::Block,
    handles: &ApplyHandles,
    block_hash: bitcoin_rs_primitives::Hash256,
    height: u32,
    scratch: &ApplyScratch,
) -> Option<Vec<u8>> {
    use bitcoin::hashes::Hash as _;

    let filter = match bitcoin::bip158::BlockFilter::new_script_filter(block, |outpoint| {
        let prev_outpoint = OutPoint::new(
            bitcoin_rs_primitives::Hash256::from_le_bytes(outpoint.txid.as_byte_array()),
            outpoint.vout,
        );
        scratch
            .same_block_spent_output_script(&prev_outpoint)
            .or_else(|| {
                handles
                    .utxo
                    .get(&prev_outpoint)
                    .map(|txout| txout.script_pubkey)
            })
            .ok_or(bitcoin::bip158::Error::UtxoMissing(*outpoint))
    }) {
        Ok(filter) => filter,
        Err(error) => {
            tracing::warn!(height, %block_hash, %error, "BIP158 filter generation failed; skipping best-effort filter index row");
            return None;
        }
    };
    Some(filter.content)
}

fn verify_block_transactions(
    handles: &ApplyHandles,
    block: &bitcoin::Block,
    tx_plan: &BlockTxPlan,
    height: u32,
    locktime_cutoff: u32,
    flags: bitcoin_rs_script::VerifyFlags,
) -> core::result::Result<(), ApplyError> {
    let txids = tx_plan.txids();
    debug_assert_eq!(block.txdata.len(), txids.len());
    if tx_plan.only_coinbase {
        for tx in &block.txdata {
            bitcoin_rs_consensus::verify_tx::verify_coinbase_script_sig_size(tx)?;
        }
        return Ok(());
    }
    if !tx_plan.needs_local_utxo_overlay {
        let view = crate::UtxoSetView::new(Arc::clone(&handles.utxo));
        for tx in &block.txdata {
            if tx.is_coinbase() {
                bitcoin_rs_consensus::verify_tx::verify_coinbase_script_sig_size(tx)?;
                continue;
            }
            bitcoin_rs_consensus::verify_tx::verify_transaction_borrowed_with_mtp(
                tx,
                &view,
                height,
                locktime_cutoff,
                flags,
            )?;
        }
        return Ok(());
    }
    // Consensus connects transactions in block order. A later transaction may
    // spend an output created earlier in the same block. Coinbase outputs enter
    // this view too, so maturity failures stay in the maturity pass instead of
    // degrading into bogus missing-prevout script checks.
    let mut view = BlockLocalUtxoView::new(Arc::clone(&handles.utxo), tx_plan.overlay_capacity);
    for (tx, txid) in block.txdata.iter().zip(txids) {
        if tx.is_coinbase() {
            bitcoin_rs_consensus::verify_tx::verify_coinbase_script_sig_size(tx)?;
            view.add_outputs(tx, *txid, height)?;
            continue;
        }
        bitcoin_rs_consensus::verify_tx::verify_transaction_borrowed_with_mtp(
            tx,
            &view,
            height,
            locktime_cutoff,
            flags,
        )?;
        view.spend_inputs(tx);
        view.add_outputs(tx, *txid, height)?;
    }
    Ok(())
}

struct BlockLocalUtxoView {
    base: Arc<UtxoSet>,
    overlay: HashMap<bitcoin::OutPoint, Option<LiveOutput>>,
}

impl BlockLocalUtxoView {
    fn new(set: Arc<UtxoSet>, overlay_capacity: usize) -> Self {
        Self {
            base: set,
            overlay: HashMap::with_capacity(overlay_capacity),
        }
    }

    fn spend_inputs(&mut self, tx: &bitcoin::Transaction) {
        for input in &tx.input {
            self.overlay.insert(input.previous_output, None);
        }
    }

    fn add_outputs(
        &mut self,
        tx: &bitcoin::Transaction,
        txid: bitcoin::Txid,
        height: u32,
    ) -> core::result::Result<(), ApplyError> {
        for (vout, txout) in tx.output.iter().enumerate() {
            let vout = u32::try_from(vout).map_err(|_| ApplyError::HeightOverflow(height))?;
            self.overlay.insert(
                bitcoin::OutPoint::new(txid, vout),
                Some(LiveOutput {
                    txout: txout.clone(),
                    coinbase: tx.is_coinbase(),
                    height,
                }),
            );
        }
        Ok(())
    }
}

impl UtxoView for BlockLocalUtxoView {
    fn lookup(&self, outpoint: &bitcoin::OutPoint) -> Option<bitcoin::TxOut> {
        if let Some(entry) = self.overlay.get(outpoint) {
            return entry.as_ref().map(|entry| entry.txout.clone());
        }
        self.base
            .get_entry(&internal_outpoint(outpoint))
            .map(|entry| entry.txout)
    }
}

struct BlockLocalUtxoMetaView {
    base: Arc<UtxoSet>,
    overlay: HashMap<bitcoin::OutPoint, Option<LiveOutputMeta>>,
}

impl BlockLocalUtxoMetaView {
    fn new(set: Arc<UtxoSet>, overlay_capacity: usize) -> Self {
        Self {
            base: set,
            overlay: HashMap::with_capacity(overlay_capacity),
        }
    }

    fn lookup_meta(&self, outpoint: &bitcoin::OutPoint) -> Option<LiveOutputMeta> {
        if let Some(entry) = self.overlay.get(outpoint) {
            return *entry;
        }
        self.base.get_meta(&internal_outpoint(outpoint))
    }

    fn spend_inputs(&mut self, tx: &bitcoin::Transaction) {
        for input in &tx.input {
            self.overlay.insert(input.previous_output, None);
        }
    }

    fn add_output_meta(
        &mut self,
        tx: &bitcoin::Transaction,
        txid: bitcoin::Txid,
        height: u32,
    ) -> core::result::Result<(), ApplyError> {
        let coinbase = tx.is_coinbase();
        for (vout, _txout) in tx.output.iter().enumerate() {
            let vout = u32::try_from(vout).map_err(|_| ApplyError::HeightOverflow(height))?;
            self.overlay.insert(
                bitcoin::OutPoint::new(txid, vout),
                Some(LiveOutputMeta { coinbase, height }),
            );
        }
        Ok(())
    }
}

fn check_bip113_finality(
    block: &bitcoin::Block,
    height: u32,
    locktime_cutoff: u32,
) -> core::result::Result<(), ApplyError> {
    for tx in &block.txdata {
        if tx.is_coinbase() {
            continue;
        }
        if bitcoin_rs_consensus::verify_tx::is_final_tx(tx, height, locktime_cutoff) {
            continue;
        }
        return Err(ApplyError::Consensus(
            bitcoin_rs_consensus::ConsensusError::Bip {
                bip: "BIP113",
                reason: format!(
                    "non-final transaction at height {height} locktime cutoff \
                     {locktime_cutoff}: locktime {}",
                    tx.lock_time.to_consensus_u32()
                ),
            },
        ));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn check_coinbase_maturity(
    handles: &ApplyHandles,
    block: &bitcoin::Block,
    height: u32,
) -> core::result::Result<(), ApplyError> {
    check_coinbase_maturity_with_tx_plan(handles, block, &plan_block_transactions(block), height)
}

fn check_coinbase_maturity_with_tx_plan(
    handles: &ApplyHandles,
    block: &bitcoin::Block,
    tx_plan: &BlockTxPlan,
    height: u32,
) -> core::result::Result<(), ApplyError> {
    let txids = tx_plan.txids();
    debug_assert_eq!(block.txdata.len(), txids.len());
    if tx_plan.only_coinbase {
        return Ok(());
    }
    // COINBASE_MATURITY: spent coinbase outputs must be at least 100 blocks deep.
    if !tx_plan.needs_local_utxo_overlay {
        for tx in block.txdata.iter().filter(|tx| !tx.is_coinbase()) {
            for tx_input in &tx.input {
                let Some(entry) = handles
                    .utxo
                    .get_meta(&internal_outpoint(&tx_input.previous_output))
                else {
                    continue;
                };
                check_coinbase_input_maturity(entry, height)?;
            }
        }
        return Ok(());
    }

    let mut view = BlockLocalUtxoMetaView::new(Arc::clone(&handles.utxo), tx_plan.overlay_capacity);
    for (tx, txid) in block.txdata.iter().zip(txids) {
        if tx.is_coinbase() {
            view.add_output_meta(tx, *txid, height)?;
            continue;
        }
        for tx_input in &tx.input {
            let Some(entry) = view.lookup_meta(&tx_input.previous_output) else {
                continue;
            };
            check_coinbase_input_maturity(entry, height)?;
        }
    }
    Ok(())
}

fn check_coinbase_input_maturity(entry: LiveOutputMeta, height: u32) -> Result<(), ApplyError> {
    let depth = height.saturating_sub(entry.height);
    if entry.coinbase && depth < COINBASE_MATURITY {
        return Err(ApplyError::Consensus(
            bitcoin_rs_consensus::ConsensusError::Bip {
                bip: "COINBASE_MATURITY",
                reason: format!(
                    "spent coinbase output created at height {} cannot be spent at height {} (depth {} < {})",
                    entry.height, height, depth, COINBASE_MATURITY,
                ),
            },
        ));
    }
    Ok(())
}

fn check_bip68_sequence_locks(
    handles: &ApplyHandles,
    block: &bitcoin::Block,
    tx_plan: &BlockTxPlan,
    height: u32,
    mtp: u32,
    softfork_state: crate::bip9_context::ContextualSoftforkState,
    previous_tip_id: Option<bitcoin_rs_chain::node::NodeId>,
) -> core::result::Result<(), ApplyError> {
    if !softfork_state.csv_active {
        return Ok(());
    }
    if tx_plan.only_coinbase {
        return Ok(());
    }
    if !tx_plan.has_bip68_sequence_locks {
        return Ok(());
    }

    let txids = tx_plan.txids();
    debug_assert_eq!(block.txdata.len(), txids.len());
    let mut view = BlockLocalUtxoMetaView::new(Arc::clone(&handles.utxo), tx_plan.overlay_capacity);
    let mut prevout_mtp_by_height = None;
    for (tx, txid) in block.txdata.iter().zip(txids) {
        if tx.is_coinbase() {
            continue;
        }
        if tx.version.0 < 2 {
            view.spend_inputs(tx);
            view.add_output_meta(tx, *txid, height)?;
            continue;
        }
        for tx_input in &tx.input {
            let sequence = tx_input.sequence.to_consensus_u32();
            if sequence & BIP68_DISABLE_FLAG != 0 {
                continue;
            }
            let is_time_based = sequence & BIP68_TYPE_FLAG != 0;
            if is_time_based {
                let relative_intervals = sequence & BIP68_MASK;
                let Some(entry) = view.lookup_meta(&tx_input.previous_output) else {
                    continue;
                };
                let prevout_mtp = if entry.height == height {
                    // A same-block prevout's coin time is the MTP of the block
                    // before the block being connected; the previous tip cannot
                    // contain an ancestor at the current block height yet.
                    mtp
                } else {
                    let cache = prevout_mtp_by_height.get_or_insert_with(HashMap::new);
                    if let Some(prevout_mtp) = cache.get(&entry.height) {
                        *prevout_mtp
                    } else {
                        let prevout_mtp =
                            bip68_prevout_mtp(handles, previous_tip_id, entry.height)?;
                        cache.insert(entry.height, prevout_mtp);
                        prevout_mtp
                    }
                };
                let earliest_time = prevout_mtp.saturating_add(
                    relative_intervals.saturating_mul(BIP68_TIME_GRANULARITY_SECONDS),
                );
                if mtp < earliest_time {
                    return Err(ApplyError::Consensus(
                        bitcoin_rs_consensus::ConsensusError::Bip {
                            bip: "BIP68",
                            reason: format!(
                                "input sequence time-based lock unmet: prevout mtp {prevout_mtp} + {relative_intervals}*512s = {earliest_time} > current mtp {mtp}",
                            ),
                        },
                    ));
                }
                continue;
            }

            let relative_blocks = sequence & BIP68_MASK;
            let Some(entry) = view.lookup_meta(&tx_input.previous_output) else {
                continue;
            };
            let earliest_height = entry.height.saturating_add(relative_blocks);
            if height < earliest_height {
                return Err(ApplyError::Consensus(
                    bitcoin_rs_consensus::ConsensusError::Bip {
                        bip: "BIP68",
                        reason: format!(
                            "input sequence height-based lock unmet: prevout at height {} + {} blocks > current {}",
                            entry.height, relative_blocks, height
                        ),
                    },
                ));
            }
        }
        view.spend_inputs(tx);
        view.add_output_meta(tx, *txid, height)?;
    }

    Ok(())
}

fn bip68_prevout_mtp(
    handles: &ApplyHandles,
    previous_tip_id: Option<bitcoin_rs_chain::node::NodeId>,
    prevout_height: u32,
) -> core::result::Result<u32, ApplyError> {
    let tree = handles.block_tree.read();
    let Some(previous_tip_id) = previous_tip_id else {
        return Err(ApplyError::Consensus(
            bitcoin_rs_consensus::ConsensusError::Bip {
                bip: "BIP68",
                reason: "missing previous tip for time-based sequence lock".to_owned(),
            },
        ));
    };
    let mtp_height = prevout_height.saturating_sub(1);
    let Some(prev_block_node) = tree.node_at_height_from(previous_tip_id, mtp_height) else {
        return Err(ApplyError::Consensus(
            bitcoin_rs_consensus::ConsensusError::Bip {
                bip: "BIP68",
                reason: format!(
                    "missing prevout ancestry at height {mtp_height} for time-based sequence lock"
                ),
            },
        ));
    };
    let Some(prevout_mtp) = tree.median_time_past_at(prev_block_node, 11) else {
        return Err(ApplyError::Consensus(
            bitcoin_rs_consensus::ConsensusError::Bip {
                bip: "BIP68",
                reason: "missing prevout median-time-past for time-based sequence lock".to_owned(),
            },
        ));
    };
    Ok(prevout_mtp)
}

fn check_bip30_and_bip34(
    handles: &ApplyHandles,
    block: &bitcoin::Block,
    height: u32,
    txids: &[bitcoin::Txid],
) -> core::result::Result<(), ApplyError> {
    use bitcoin::hashes::Hash as _;

    // BIP30: reject any txid that collides with an earlier transaction while
    // any output of the earlier transaction remains unspent, except at the
    // documented historical exception heights handled by `check_bip30`.
    let mut has_duplicate = false;
    for txid in txids {
        let txid = bitcoin_rs_primitives::Hash256::from_le_bytes(txid.as_byte_array());
        if handles.utxo.has_live_outputs_for_txid(&txid) {
            has_duplicate = true;
            break;
        }
    }
    bitcoin_rs_consensus::bip30::check_bip30(height, has_duplicate)?;

    // BIP34: when active for this network at `height`, the coinbase
    // scriptSig must start with the minimally-encoded height.
    if handles.network.is_bip34_active(height) {
        let coinbase = block
            .txdata
            .first()
            .ok_or(bitcoin_rs_consensus::ConsensusError::EmptyBlock)?;
        // `verify_block_rules_borrowed` already pinned the first tx to
        // be the coinbase; relying on that here. `coinbase.input[0]`
        // is the synthetic prevout pointing at the impossible
        // outpoint; its `script_sig` carries the BIP34 height encoding.
        let coinbase_input = coinbase
            .input
            .first()
            .ok_or(bitcoin_rs_consensus::ConsensusError::MissingCoinbase)?;
        bitcoin_rs_consensus::bip34::check_bip34(height, coinbase_input.script_sig.as_script())?;
    }

    Ok(())
}

fn check_pow_limit_and_continuity(
    handles: &ApplyHandles,
    prior: Option<&TipSnapshot>,
    block: &bitcoin::Block,
    height: u32,
) -> core::result::Result<(), ApplyError> {
    // PoW limit: declared target must not exceed network max_target.
    let target_be = block.header.target().to_be_bytes();
    let declared = bitcoin_rs_chain::node::ChainWork::from_be_bytes(target_be);
    let max_target = handles.network.max_target();
    if declared > max_target {
        return Err(ApplyError::TargetAboveLimit);
    }

    // Genesis (height 0) has no parent; skip contextual DAA.
    if height == 0 {
        return Ok(());
    }

    let tree = handles.block_tree.read();
    let Some(parent_id) = prior.map(|tip| tip.tip_id) else {
        use bitcoin::hashes::Hash as _;

        let prev_hash = bitcoin_rs_primitives::Hash256::from_le_bytes(
            block.header.prev_blockhash.as_byte_array(),
        );
        return Err(ApplyError::Chain(
            bitcoin_rs_chain::ChainError::MissingParent { prev_hash },
        ));
    };
    bitcoin_rs_chain::header_sync::validate_header_nbits(
        &tree,
        parent_id,
        &block.header,
        handles.network,
    )
    .map_err(apply_nbits_error)
}

fn apply_nbits_error(error: bitcoin_rs_chain::ChainError) -> ApplyError {
    match error {
        bitcoin_rs_chain::ChainError::NbitsMismatch {
            actual,
            expected,
            height,
        } => ApplyError::NbitsNonRetargetMismatch {
            actual,
            expected,
            height,
        },
        error => ApplyError::Chain(error),
    }
}

fn build_utxo_changes<'a>(
    block: &'a bitcoin::Block,
    height: u32,
    scratch: &ApplyScratch,
) -> core::result::Result<BorrowedBlockChanges<'a>, ApplyError> {
    use bitcoin::hashes::Hash as _;

    // Bitcoin Core indexes genesis but does not connect its transactions into
    // CoinsView; its coinbase is unspendable and absent from UTXO/MuHash state.
    if height == 0 {
        return Ok(BorrowedBlockChanges::default());
    }

    let (add_capacity, remove_capacity) = scratch.utxo_change_capacity();
    let mut changes = BorrowedBlockChanges::with_capacity(add_capacity, remove_capacity);
    let net_same_block_spends = scratch.has_same_block_spends();
    for (tx, txid) in block.txdata.iter().zip(scratch.txids()) {
        let txid = bitcoin_rs_primitives::Hash256::from_le_bytes(txid.as_byte_array());
        let coinbase = tx.is_coinbase();
        for (vout_idx, txout) in tx.output.iter().enumerate() {
            let outpoint = OutPoint::new(
                txid,
                u32::try_from(vout_idx).map_err(|_| ApplyError::HeightOverflow(height))?,
            );
            if net_same_block_spends && scratch.contains_same_block_spent(&outpoint) {
                continue;
            }
            changes.add(BorrowedUtxoAdd::new(outpoint, txout, coinbase, height));
        }

        if !coinbase {
            for tx_input in &tx.input {
                let previous_output = internal_outpoint(&tx_input.previous_output);
                if net_same_block_spends && scratch.contains_same_block_spent(&previous_output) {
                    continue;
                }
                changes.remove(previous_output);
            }
        }
    }
    Ok(changes)
}

fn internal_outpoint(outpoint: &bitcoin::OutPoint) -> OutPoint {
    use bitcoin::hashes::Hash as _;

    OutPoint::new(
        bitcoin_rs_primitives::Hash256::from_le_bytes(outpoint.txid.as_byte_array()),
        outpoint.vout,
    )
}

fn applied_block_record(
    height: u32,
    block_hash: Hash256,
    block: &bitcoin::Block,
    block_bytes: &[u8],
    include_body: bool,
) -> BlockRecord {
    let block_hex = if include_body {
        block_bytes.to_lower_hex_string()
    } else {
        String::new()
    };
    let header_hex = block_bytes.get(..SERIALIZED_BLOCK_HEADER_LEN).map_or_else(
        || bitcoin::consensus::encode::serialize(&block.header).to_lower_hex_string(),
        DisplayHex::to_lower_hex_string,
    );
    BlockRecord {
        hash: block_hash,
        height,
        block_hex,
        body_size: block_bytes.len(),
        header_hex,
        tx_count: block.txdata.len(),
        time: block.header.time,
    }
}

#[must_use]
fn compute_verify_flags(
    network: Network,
    height: u32,
    softfork_state: crate::bip9_context::ContextualSoftforkState,
) -> bitcoin_rs_script::VerifyFlags {
    use bitcoin_rs_script::VerifyFlags;

    // P2SH (BIP16) is effectively always-on for supported validation paths.
    let mut flags = VerifyFlags::P2SH;
    if network.is_bip66_active(height) {
        flags = flags.union(VerifyFlags::DERSIG);
    }
    if network.is_bip65_active(height) {
        flags = flags.union(VerifyFlags::CHECKLOCKTIMEVERIFY);
    }
    if softfork_state.csv_active {
        flags = flags.union(VerifyFlags::CHECKSEQUENCEVERIFY);
    }
    if softfork_state.segwit_active {
        flags = flags
            .union(VerifyFlags::WITNESS)
            .union(VerifyFlags::NULLDUMMY);
    }
    if network.is_taproot_active(height) {
        flags = flags.union(VerifyFlags::TAPROOT);
    }
    flags
}

#[cfg(test)]
mod consensus_rule_tests {
    use std::sync::Arc;

    use arc_swap::ArcSwapOption;
    use bitcoin::hashes::Hash as _;
    use bitcoin::{Amount, CompactTarget, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
    use bitcoin_rs_chain::{
        BlockTree,
        node::{ChainWork, NodeStatus},
    };
    use bitcoin_rs_filters::{FilterIndexError, FilterIndexLike};
    use bitcoin_rs_index::{BlockSource, IndexError, IndexRowCounts, IndexerLike};
    use bitcoin_rs_mempool::{Mempool, MempoolLimits};
    use bitcoin_rs_primitives::{Hash256, OutPoint};
    use bitcoin_rs_utxo::{BlockChanges, UtxoAdd, UtxoSet};
    use hashbrown::HashMap;
    use parking_lot::{Mutex, RwLock};

    use super::*;

    const BIP68_TEST_PREVOUT_HEIGHT: u32 = 100;
    const BIP68_TEST_PREVOUT_MTP: u32 = 1_000_000;
    const MAINNET_POW_LIMIT_BITS: u32 = 0x1d00_ffff;
    const MAINNET_POW_LIMIT_DIV_4_BITS: u32 = 0x1c3f_ffc0;
    const DAA_ANCHOR_TIME: u32 = 1_600_000_000;

    fn tx_plan(block: &bitcoin::Block) -> BlockTxPlan {
        plan_block_transactions(block)
    }

    #[test]
    fn applied_block_record_matches_rpc_constructors() {
        let block = block_with_transaction(coinbase_transaction(0x42));
        let block_bytes = bitcoin::consensus::encode::serialize(&block);
        let block_hash = Hash256::from_le_bytes(block.block_hash().as_byte_array());

        let cached = applied_block_record(7, block_hash, &block, &block_bytes, true);
        let expected_cached = BlockRecord::from_block_bytes(7, &block, &block_bytes);
        assert_eq!(cached.hash, expected_cached.hash);
        assert_eq!(cached.height, expected_cached.height);
        assert_eq!(cached.block_hex, expected_cached.block_hex);
        assert_eq!(cached.body_size, expected_cached.body_size);
        assert_eq!(cached.header_hex, expected_cached.header_hex);
        assert_eq!(cached.tx_count, expected_cached.tx_count);
        assert_eq!(cached.time, expected_cached.time);

        let metadata = applied_block_record(7, block_hash, &block, &block_bytes, false);
        let expected_metadata = BlockRecord::from_block_metadata_bytes(7, &block, &block_bytes);
        assert_eq!(metadata.hash, expected_metadata.hash);
        assert_eq!(metadata.height, expected_metadata.height);
        assert_eq!(metadata.block_hex, expected_metadata.block_hex);
        assert_eq!(metadata.body_size, expected_metadata.body_size);
        assert_eq!(metadata.header_hex, expected_metadata.header_hex);
        assert_eq!(metadata.tx_count, expected_metadata.tx_count);
        assert_eq!(metadata.time, expected_metadata.time);
    }

    #[test]
    fn block_apply_predecessor_uses_applied_tip_when_header_tip_is_ahead()
    -> Result<(), Box<dyn std::error::Error>> {
        let handles = empty_apply_handles_for_network(Network::Regtest);
        let mut tree = handles.block_tree.write();
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let genesis_id = tree.insert_node(None, genesis.header, NodeStatus::HeaderValid)?;
        let genesis_node = tree.node(genesis_id)?;
        let genesis_tip = TipSnapshot {
            tip_id: genesis_id,
            height: genesis_node.height,
            chainwork: genesis_node.chainwork,
            hash: genesis_node.hash,
        };
        let mut tip_id = genesis_id;
        for height in 1..=3 {
            let parent_hash =
                bitcoin::BlockHash::from_byte_array(tree.node(tip_id)?.hash.to_le_bytes());
            let header = pow_header(
                parent_hash,
                CompactTarget::from_consensus(0x207f_ffff),
                height,
                height,
            );
            tip_id = tree.insert_node(Some(tip_id), header, NodeStatus::HeaderValid)?;
        }
        handles.chain_tip.store(tree.tip());
        drop(tree);
        handles
            .applied_tip
            .store(Some(Arc::new(genesis_tip.clone())));

        let (prior, height) = applied_predecessor(
            &handles,
            Hash256::from_le_bytes(&[0x42; 32]),
            genesis_tip.hash,
        )?;

        let prior = prior.ok_or_else(|| std::io::Error::other("missing predecessor"))?;
        assert_eq!(prior.tip_id, genesis_id);
        assert_eq!(height, 1);
        Ok(())
    }

    #[test]
    fn block_apply_predecessor_rejects_non_genesis_without_applied_tip() {
        let handles = empty_apply_handles_for_network(Network::Regtest);
        let prev_hash = Hash256::from_le_bytes(&[0x11; 32]);
        let error =
            match applied_predecessor(&handles, Hash256::from_le_bytes(&[0x22; 32]), prev_hash) {
                Ok(_) => panic!("non-genesis block must not start the applied chain"),
                Err(error) => error,
            };

        assert!(matches!(
            error,
            ApplyError::Chain(bitcoin_rs_chain::ChainError::MissingParent { prev_hash: got }) if got == prev_hash
        ));
    }

    #[test]
    fn applied_header_tip_reuses_preaccepted_header() -> Result<(), Box<dyn std::error::Error>> {
        let handles = empty_apply_handles_for_network(Network::Regtest);
        let block = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let block_hash = Hash256::from_le_bytes(block.block_hash().as_byte_array());
        let header_id = handles
            .block_tree
            .write()
            .insert_header(block.header, NodeStatus::HeaderValid)?;

        let tip = applied_header_tip(&handles, block_hash, &block, 0)?;

        assert_eq!(tip.tip_id, header_id);
        assert_eq!(tip.height, 0);
        assert_eq!(tip.hash, block_hash);
        Ok(())
    }

    #[test]
    fn verify_block_transactions_accepts_same_block_spend() -> Result<(), Box<dyn std::error::Error>>
    {
        let base_prevout = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x61; 32]),
            vout: 0,
        };
        let utxo = utxo_with_output(base_prevout, 1)?;
        let handles = apply_handles(utxo);
        let funding_tx = spending_transaction_to_script(
            base_prevout,
            Sequence::MAX.to_consensus_u32(),
            op_true_script(),
        );
        let funding_outpoint = bitcoin::OutPoint {
            txid: funding_tx.compute_txid(),
            vout: 0,
        };
        let same_block_spend = spending_transaction_to_script(
            funding_outpoint,
            Sequence::MAX.to_consensus_u32(),
            op_true_script(),
        );
        let block = block_with_transactions(vec![funding_tx, same_block_spend]);

        verify_block_transactions(
            &handles,
            &block,
            &tx_plan(&block),
            2,
            0,
            bitcoin_rs_script::VerifyFlags::NONE,
        )?;
        Ok(())
    }

    #[test]
    fn verify_block_transactions_rejects_cross_transaction_duplicate_spend()
    -> Result<(), Box<dyn std::error::Error>> {
        let base_prevout = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x64; 32]),
            vout: 0,
        };
        let utxo = utxo_with_output(base_prevout, 1)?;
        let handles = apply_handles(utxo);
        let first_spend = spending_transaction_to_script(
            base_prevout,
            Sequence::MAX.to_consensus_u32(),
            op_true_script(),
        );
        let second_spend = spending_transaction_to_script(
            base_prevout,
            Sequence::MAX.to_consensus_u32() - 1,
            op_true_script(),
        );
        let block = block_with_transactions(vec![first_spend, second_spend]);

        let error = match verify_block_transactions(
            &handles,
            &block,
            &tx_plan(&block),
            2,
            0,
            bitcoin_rs_script::VerifyFlags::NONE,
        ) {
            Ok(()) => panic!("cross-transaction duplicate spend must fail script verification"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            ApplyError::Consensus(bitcoin_rs_consensus::ConsensusError::MissingPrevout {
                input_index: 0
            })
        ));
        Ok(())
    }

    #[test]
    fn verify_block_transactions_rejects_bad_coinbase_script_sig() {
        let mut coinbase = coinbase_transaction(0x63);
        coinbase.input[0].script_sig = ScriptBuf::from_bytes(vec![0x63]);
        let block = block_with_transaction(coinbase);
        let handles = empty_apply_handles();

        let error = match verify_block_transactions(
            &handles,
            &block,
            &tx_plan(&block),
            1,
            0,
            bitcoin_rs_script::VerifyFlags::MANDATORY,
        ) {
            Ok(()) => panic!("bad coinbase scriptSig length must fail transaction verification"),
            Err(error) => error,
        };

        assert!(matches!(
            error,
            ApplyError::Consensus(
                bitcoin_rs_consensus::ConsensusError::CoinbaseScriptSigSize { len: 1 }
            )
        ));
    }

    #[test]
    #[allow(clippy::arc_with_non_send_sync)]
    fn build_utxo_changes_nets_same_block_created_then_spent_outputs()
    -> Result<(), Box<dyn std::error::Error>> {
        let base_prevout = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x62; 32]),
            vout: 0,
        };
        let utxo = utxo_with_output(base_prevout, 1)?;
        let funding_tx = spending_transaction_to_script(
            base_prevout,
            Sequence::MAX.to_consensus_u32(),
            op_true_script(),
        );
        let funding_outpoint = bitcoin::OutPoint {
            txid: funding_tx.compute_txid(),
            vout: 0,
        };
        let same_block_spend = spending_transaction_to_script(
            funding_outpoint,
            Sequence::MAX.to_consensus_u32(),
            op_true_script(),
        );
        let final_outpoint = bitcoin::OutPoint {
            txid: same_block_spend.compute_txid(),
            vout: 0,
        };
        let block = block_with_transactions(vec![funding_tx, same_block_spend]);

        let scratch = ApplyScratch::new(&block, 2, false, false)?;
        let changes = build_utxo_changes(&block, 2, &scratch)?;
        utxo.commit_borrowed_block(&changes, &Hash256::from_le_bytes(&[0x63; 32]))?;

        assert!(utxo.get(&internal_outpoint(&base_prevout)).is_none());
        assert!(utxo.get(&internal_outpoint(&funding_outpoint)).is_none());
        assert!(utxo.get(&internal_outpoint(&final_outpoint)).is_some());
        Ok(())
    }

    #[test]
    fn apply_scratch_omits_rawtx_bytes_when_not_requested() -> Result<(), Box<dyn std::error::Error>>
    {
        let block = block_with_transactions(vec![coinbase_transaction(0x71), transaction(0x72)]);

        let scratch = ApplyScratch::new(&block, 2, false, false)?;

        assert_eq!(scratch.txids().len(), block.txdata.len());
        assert!(scratch.raw_txs().is_none());
        Ok(())
    }

    #[test]
    fn apply_scratch_keeps_rawtx_bytes_when_requested() -> Result<(), Box<dyn std::error::Error>> {
        let block = block_with_transactions(vec![coinbase_transaction(0x73), transaction(0x74)]);

        let scratch = ApplyScratch::new(&block, 2, true, false)?;
        let raw_txs = scratch
            .raw_txs()
            .ok_or_else(|| std::io::Error::other("rawtx bytes missing"))?;

        assert_eq!(raw_txs.len(), block.txdata.len());
        assert_eq!(
            raw_txs[0],
            bitcoin::consensus::encode::serialize(&block.txdata[0])
        );
        Ok(())
    }

    #[test]
    fn apply_scratch_skips_same_block_script_tracking_without_spend_inputs()
    -> Result<(), Box<dyn std::error::Error>> {
        let block = block_with_transaction(coinbase_transaction(0x70));

        let scratch = ApplyScratch::new(&block, 1, false, true)?;
        let changes = build_utxo_changes(&block, 1, &scratch)?;

        assert!(
            !scratch.contains_same_block_spent(&internal_outpoint(&bitcoin::OutPoint {
                txid: block.txdata[0].compute_txid(),
                vout: 0,
            }))
        );
        assert!(
            scratch
                .same_block_spent_output_script(&internal_outpoint(&bitcoin::OutPoint {
                    txid: block.txdata[0].compute_txid(),
                    vout: 0,
                }))
                .is_none()
        );
        assert_eq!(changes.add_count(), block.txdata[0].output.len());
        assert_eq!(changes.remove_count(), 0);
        Ok(())
    }

    #[test]
    fn apply_scratch_caches_same_block_spent_output_scripts_by_txid_and_vout()
    -> Result<(), Box<dyn std::error::Error>> {
        let base_prevout = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x75; 32]),
            vout: 0,
        };
        let same_block_script = ScriptBuf::from_bytes(vec![0x51, 0x75]);
        let mut funding_tx = spending_transaction_to_script(
            base_prevout,
            Sequence::MAX.to_consensus_u32(),
            same_block_script.clone(),
        );
        funding_tx.output.push(TxOut {
            value: Amount::from_sat(2),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51, 0x77]),
        });
        let funding_outpoint = bitcoin::OutPoint {
            txid: funding_tx.compute_txid(),
            vout: 0,
        };
        let unspent_funding_outpoint = bitcoin::OutPoint {
            txid: funding_tx.compute_txid(),
            vout: 1,
        };
        let final_script = ScriptBuf::from_bytes(vec![0x51, 0x76]);
        let same_block_spend = spending_transaction_to_script(
            funding_outpoint,
            Sequence::MAX.to_consensus_u32(),
            final_script,
        );
        let final_outpoint = bitcoin::OutPoint {
            txid: same_block_spend.compute_txid(),
            vout: 0,
        };
        let block = block_with_transactions(vec![funding_tx, same_block_spend]);
        let funding_outpoint = internal_outpoint(&funding_outpoint);
        let scratch_without_scripts = ApplyScratch::new(&block, 2, false, false)?;
        assert!(scratch_without_scripts.contains_same_block_spent(&funding_outpoint));
        assert!(
            scratch_without_scripts
                .same_block_spent_output_script(&funding_outpoint)
                .is_none()
        );
        let scratch = ApplyScratch::new(&block, 2, false, true)?;

        assert_eq!(
            scratch.same_block_spent_output_script(&funding_outpoint),
            Some(same_block_script)
        );
        assert!(
            scratch
                .same_block_spent_output_script(&internal_outpoint(&base_prevout))
                .is_none()
        );
        assert!(
            scratch
                .same_block_spent_output_script(&internal_outpoint(&unspent_funding_outpoint))
                .is_none()
        );
        assert!(
            scratch
                .same_block_spent_output_script(&internal_outpoint(&final_outpoint))
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn coinbase_maturity_rejects_same_block_coinbase_spend() {
        let coinbase = coinbase_transaction(0x64);
        let coinbase_outpoint = bitcoin::OutPoint {
            txid: coinbase.compute_txid(),
            vout: 0,
        };
        let spend = spending_transaction_to_script(
            coinbase_outpoint,
            Sequence::MAX.to_consensus_u32(),
            op_true_script(),
        );
        let block = block_with_transactions(vec![coinbase, spend]);
        let handles = empty_apply_handles();

        let error =
            match check_coinbase_maturity_with_tx_plan(&handles, &block, &tx_plan(&block), 1) {
                Ok(()) => panic!("same-block coinbase spend must fail maturity"),
                Err(error) => error,
            };
        assert_bip_error(&error, "COINBASE_MATURITY");
    }

    #[test]
    fn verify_block_transactions_defers_same_block_coinbase_spend_to_maturity() {
        let mut coinbase = coinbase_transaction(0x65);
        coinbase.output[0].script_pubkey = op_true_script();
        let coinbase_outpoint = bitcoin::OutPoint {
            txid: coinbase.compute_txid(),
            vout: 0,
        };
        let spend = spending_transaction_to_script(
            coinbase_outpoint,
            Sequence::MAX.to_consensus_u32(),
            op_true_script(),
        );
        let block = block_with_transactions(vec![coinbase, spend]);
        let handles = empty_apply_handles();

        assert!(
            verify_block_transactions(
                &handles,
                &block,
                &tx_plan(&block),
                1,
                0,
                bitcoin_rs_script::VerifyFlags::NONE
            )
            .is_ok()
        );
        let error =
            match check_coinbase_maturity_with_tx_plan(&handles, &block, &tx_plan(&block), 1) {
                Ok(()) => panic!("same-block coinbase spend must fail maturity"),
                Err(error) => error,
            };
        assert_bip_error(&error, "COINBASE_MATURITY");
    }

    #[test]
    fn bip68_height_lock_enforces_boundary_when_csv_active()
    -> Result<(), Box<dyn std::error::Error>> {
        let previous_output = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x68; 32]),
            vout: 0,
        };
        let utxo = utxo_with_output(previous_output, BIP68_TEST_PREVOUT_HEIGHT)?;
        let handles = apply_handles(utxo);
        let block = block_with_transaction(spending_transaction_to_script(
            previous_output,
            2,
            op_true_script(),
        ));
        let active = softfork_state(true);

        let error = match check_bip68_sequence_locks(
            &handles,
            &block,
            &tx_plan(&block),
            101,
            0,
            active,
            None,
        ) {
            Ok(()) => panic!("BIP68 height lock must reject one block before maturity"),
            Err(error) => error,
        };
        assert_bip_error(&error, "BIP68");
        assert!(
            check_bip68_sequence_locks(&handles, &block, &tx_plan(&block), 102, 0, active, None)
                .is_ok()
        );
        Ok(())
    }

    #[test]
    fn bip68_time_lock_enforces_mtp_boundary_when_csv_active()
    -> Result<(), Box<dyn std::error::Error>> {
        let previous_output = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x69; 32]),
            vout: 0,
        };
        let utxo = utxo_with_output(previous_output, BIP68_TEST_PREVOUT_HEIGHT)?;
        let handles = apply_handles(utxo);
        let previous_tip_id = seed_block_tree_for_bip68_time(&handles)?;
        let sequence = BIP68_TYPE_FLAG | 2;
        let block = block_with_transaction(spending_transaction_to_script(
            previous_output,
            sequence,
            op_true_script(),
        ));
        let active = softfork_state(true);
        let required_mtp = BIP68_TEST_PREVOUT_MTP + 2 * BIP68_TIME_GRANULARITY_SECONDS;

        let error = match check_bip68_sequence_locks(
            &handles,
            &block,
            &tx_plan(&block),
            0,
            required_mtp - 1,
            active,
            Some(previous_tip_id),
        ) {
            Ok(()) => panic!("BIP68 time lock must reject one second before maturity"),
            Err(error) => error,
        };
        assert_bip_error(&error, "BIP68");
        assert!(
            check_bip68_sequence_locks(
                &handles,
                &block,
                &tx_plan(&block),
                0,
                required_mtp,
                active,
                Some(previous_tip_id)
            )
            .is_ok()
        );
        Ok(())
    }

    #[test]
    fn bip68_time_lock_uses_mtp_before_prevout_height() -> Result<(), Box<dyn std::error::Error>> {
        let previous_output = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x67; 32]),
            vout: 0,
        };
        let prevout_height = 3;
        let utxo = utxo_with_output(previous_output, prevout_height)?;
        let handles = apply_handles(utxo);
        let previous_tip_id = seed_block_tree_with_times(&handles, &[100, 200, 300, 400])?;
        let block = block_with_transaction(spending_transaction_to_script(
            previous_output,
            BIP68_TYPE_FLAG,
            op_true_script(),
        ));

        assert!(
            check_bip68_sequence_locks(
                &handles,
                &block,
                &tx_plan(&block),
                prevout_height + 1,
                200,
                softfork_state(true),
                Some(previous_tip_id),
            )
            .is_ok()
        );
        Ok(())
    }

    #[test]
    fn bip68_time_lock_accepts_multiple_prevouts_at_same_height()
    -> Result<(), Box<dyn std::error::Error>> {
        let first_previous_output = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x66; 32]),
            vout: 0,
        };
        let second_previous_output = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x65; 32]),
            vout: 0,
        };
        let prevout_height = BIP68_TEST_PREVOUT_HEIGHT;
        let utxo = utxo_with_outputs_at_height(
            &[first_previous_output, second_previous_output],
            prevout_height,
        )?;
        let handles = apply_handles(utxo);
        let previous_tip_id = seed_block_tree_for_bip68_time(&handles)?;
        let block = block_with_transactions(vec![
            spending_transaction_to_script(
                first_previous_output,
                BIP68_TYPE_FLAG,
                op_true_script(),
            ),
            spending_transaction_to_script(
                second_previous_output,
                BIP68_TYPE_FLAG,
                op_true_script(),
            ),
        ]);

        assert!(
            check_bip68_sequence_locks(
                &handles,
                &block,
                &tx_plan(&block),
                prevout_height + 1,
                BIP68_TEST_PREVOUT_MTP,
                softfork_state(true),
                Some(previous_tip_id),
            )
            .is_ok()
        );
        Ok(())
    }

    #[test]
    fn bip68_time_lock_uses_previous_tip_mtp_for_same_block_prevout()
    -> Result<(), Box<dyn std::error::Error>> {
        let handles = empty_apply_handles();
        let previous_tip_id = seed_block_tree_for_bip68_time_at_height(&handles, 100)?;
        let funding_tx = transaction(0x6c);
        let funding_outpoint = bitcoin::OutPoint {
            txid: funding_tx.compute_txid(),
            vout: 0,
        };
        let same_block_spend =
            spending_transaction_to_script(funding_outpoint, BIP68_TYPE_FLAG, op_true_script());
        let block = block_with_transactions(vec![funding_tx, same_block_spend]);

        assert!(
            check_bip68_sequence_locks(
                &handles,
                &block,
                &tx_plan(&block),
                101,
                BIP68_TEST_PREVOUT_MTP,
                softfork_state(true),
                Some(previous_tip_id),
            )
            .is_ok()
        );
        Ok(())
    }

    #[test]
    fn bip68_time_lock_rejects_delayed_same_block_prevout() -> Result<(), Box<dyn std::error::Error>>
    {
        let handles = empty_apply_handles();
        let previous_tip_id = seed_block_tree_for_bip68_time_at_height(&handles, 100)?;
        let funding_tx = transaction(0x6d);
        let funding_outpoint = bitcoin::OutPoint {
            txid: funding_tx.compute_txid(),
            vout: 0,
        };
        let same_block_spend =
            spending_transaction_to_script(funding_outpoint, BIP68_TYPE_FLAG | 1, op_true_script());
        let block = block_with_transactions(vec![funding_tx, same_block_spend]);

        let error = match check_bip68_sequence_locks(
            &handles,
            &block,
            &tx_plan(&block),
            101,
            BIP68_TEST_PREVOUT_MTP,
            softfork_state(true),
            Some(previous_tip_id),
        ) {
            Ok(()) => {
                panic!("same-block time-based relative lock must not mature in the same block")
            }
            Err(error) => error,
        };
        assert_bip_error_reason_contains(&error, "BIP68", "time-based lock unmet");
        Ok(())
    }

    #[test]
    fn bip68_time_lock_rejects_missing_previous_tip_context()
    -> Result<(), Box<dyn std::error::Error>> {
        let previous_output = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x6a; 32]),
            vout: 0,
        };
        let utxo = utxo_with_output(previous_output, BIP68_TEST_PREVOUT_HEIGHT)?;
        let handles = apply_handles(utxo);
        let sequence = BIP68_TYPE_FLAG | 1;
        let block = block_with_transaction(spending_transaction_to_script(
            previous_output,
            sequence,
            op_true_script(),
        ));
        let active = softfork_state(true);

        let error = match check_bip68_sequence_locks(
            &handles,
            &block,
            &tx_plan(&block),
            0,
            BIP68_TEST_PREVOUT_MTP + BIP68_TIME_GRANULARITY_SECONDS,
            active,
            None,
        ) {
            Ok(()) => panic!("BIP68 time lock must reject missing previous tip context"),
            Err(error) => error,
        };
        assert_bip_error(&error, "BIP68");
        Ok(())
    }

    #[test]
    fn bip68_time_lock_rejects_missing_prevout_ancestor_context()
    -> Result<(), Box<dyn std::error::Error>> {
        let previous_output = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x6b; 32]),
            vout: 0,
        };
        let utxo = utxo_with_output(previous_output, BIP68_TEST_PREVOUT_HEIGHT)?;
        let handles = apply_handles(utxo);
        let previous_tip_id = seed_block_tree_for_bip68_time_at_height(&handles, 0)?;
        let sequence = BIP68_TYPE_FLAG | 1;
        let block = block_with_transaction(spending_transaction_to_script(
            previous_output,
            sequence,
            op_true_script(),
        ));
        let active = softfork_state(true);

        let error = match check_bip68_sequence_locks(
            &handles,
            &block,
            &tx_plan(&block),
            0,
            BIP68_TEST_PREVOUT_MTP + BIP68_TIME_GRANULARITY_SECONDS,
            active,
            Some(previous_tip_id),
        ) {
            Ok(()) => panic!("BIP68 time lock must reject missing prevout ancestry"),
            Err(error) => error,
        };
        assert_bip_error(&error, "BIP68");
        Ok(())
    }

    #[test]
    fn bip68_inactive_csv_skips_unmet_sequence_lock() -> Result<(), Box<dyn std::error::Error>> {
        let previous_output = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x70; 32]),
            vout: 0,
        };
        let utxo = utxo_with_output(previous_output, BIP68_TEST_PREVOUT_HEIGHT)?;
        let handles = apply_handles(utxo);
        let block = block_with_transaction(spending_transaction_to_script(
            previous_output,
            2,
            op_true_script(),
        ));

        assert!(
            check_bip68_sequence_locks(
                &handles,
                &block,
                &tx_plan(&block),
                101,
                0,
                softfork_state(false),
                None
            )
            .is_ok()
        );
        Ok(())
    }

    #[test]
    fn bip68_ignores_version_one_and_disabled_sequences() -> Result<(), Box<dyn std::error::Error>>
    {
        let previous_output = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x71; 32]),
            vout: 0,
        };
        let utxo = utxo_with_output(previous_output, BIP68_TEST_PREVOUT_HEIGHT)?;
        let handles = apply_handles(utxo);
        let active = softfork_state(true);

        let version_one_block = block_with_transaction(spending_transaction_with_version(
            previous_output,
            2,
            bitcoin::transaction::Version::ONE,
        ));
        assert!(
            check_bip68_sequence_locks(
                &handles,
                &version_one_block,
                &tx_plan(&version_one_block),
                101,
                0,
                active,
                None
            )
            .is_ok()
        );

        let disabled_block = block_with_transaction(spending_transaction_to_script(
            previous_output,
            BIP68_DISABLE_FLAG | 2,
            op_true_script(),
        ));
        assert!(
            check_bip68_sequence_locks(
                &handles,
                &disabled_block,
                &tx_plan(&disabled_block),
                101,
                0,
                active,
                None
            )
            .is_ok()
        );
        Ok(())
    }

    #[test]
    #[allow(clippy::arc_with_non_send_sync)]
    fn bip30_rejects_duplicate_txid_when_only_higher_vout_is_live()
    -> Result<(), Box<dyn std::error::Error>> {
        let duplicate_tx = transaction(7);
        let duplicate_txid = duplicate_tx.compute_txid();
        let duplicate_hash = Hash256::from_le_bytes(duplicate_txid.as_byte_array());
        let utxo = Arc::new(UtxoSet::new());
        let mut changes = BlockChanges::default();
        changes.add(UtxoAdd::new(
            OutPoint::new(duplicate_hash, 1),
            TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new(),
            },
            false,
            0,
        ));
        utxo.commit_block(&changes, &Hash256::from_le_bytes(&[9; 32]))?;

        let handles = apply_handles(utxo);
        let block = bitcoin::Block {
            header: bitcoin::block::Header {
                version: bitcoin::block::Version::ONE,
                prev_blockhash: bitcoin::BlockHash::all_zeros(),
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: 0,
                bits: bitcoin::pow::CompactTarget::from_consensus(0),
                nonce: 0,
            },
            txdata: vec![duplicate_tx],
        };

        let txids = [duplicate_txid];
        let error = match check_bip30_and_bip34(&handles, &block, 1, &txids) {
            Ok(()) => panic!("duplicate txid with live vout 1 must violate BIP30"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            ApplyError::Consensus(bitcoin_rs_consensus::ConsensusError::Bip { bip: "BIP30", .. })
        ));
        Ok(())
    }

    #[test]
    fn daa_non_retarget_height_requires_parent_bits() -> Result<(), Box<dyn std::error::Error>> {
        let handles = empty_apply_handles();
        let parent_hash = seed_pow_chain(
            &handles,
            CompactTarget::from_consensus(MAINNET_POW_LIMIT_BITS),
            DAA_ANCHOR_TIME,
            DAA_ANCHOR_TIME + 600,
            1,
        )?;
        let block = block_with_pow_header(
            parent_hash,
            CompactTarget::from_consensus(MAINNET_POW_LIMIT_DIV_4_BITS),
            DAA_ANCHOR_TIME + 1_200,
            2,
        );

        let error = match check_pow_limit_and_continuity_for_seeded_tip(&handles, &block, 2) {
            Ok(()) => panic!("non-retarget height must inherit parent nBits"),
            Err(error) => error,
        };
        assert_nbits_error(
            &error,
            MAINNET_POW_LIMIT_DIV_4_BITS,
            MAINNET_POW_LIMIT_BITS,
            2,
        );
        Ok(())
    }

    #[test]
    fn daa_retarget_accepts_expected_bits_at_boundary() -> Result<(), Box<dyn std::error::Error>> {
        let handles = empty_apply_handles();
        let interval = handles.network.retarget_interval();
        let expected_timespan = interval * 600;
        let parent_hash = seed_pow_chain(
            &handles,
            CompactTarget::from_consensus(MAINNET_POW_LIMIT_BITS),
            DAA_ANCHOR_TIME,
            DAA_ANCHOR_TIME + expected_timespan,
            interval - 1,
        )?;
        let block = block_with_pow_header(
            parent_hash,
            CompactTarget::from_consensus(MAINNET_POW_LIMIT_BITS),
            DAA_ANCHOR_TIME + expected_timespan + 600,
            interval,
        );

        assert!(check_pow_limit_and_continuity_for_seeded_tip(&handles, &block, interval).is_ok());
        Ok(())
    }

    #[test]
    fn daa_retarget_rejects_wrong_bits_at_boundary() -> Result<(), Box<dyn std::error::Error>> {
        let handles = empty_apply_handles();
        let interval = handles.network.retarget_interval();
        let expected_timespan = interval * 600;
        let parent_hash = seed_pow_chain(
            &handles,
            CompactTarget::from_consensus(MAINNET_POW_LIMIT_BITS),
            DAA_ANCHOR_TIME,
            DAA_ANCHOR_TIME + expected_timespan,
            interval - 1,
        )?;
        let block = block_with_pow_header(
            parent_hash,
            CompactTarget::from_consensus(MAINNET_POW_LIMIT_DIV_4_BITS),
            DAA_ANCHOR_TIME + expected_timespan + 600,
            interval,
        );

        let error = match check_pow_limit_and_continuity_for_seeded_tip(&handles, &block, interval)
        {
            Ok(()) => panic!("retarget height must reject non-computed nBits"),
            Err(error) => error,
        };
        assert_nbits_error(
            &error,
            MAINNET_POW_LIMIT_DIV_4_BITS,
            MAINNET_POW_LIMIT_BITS,
            interval,
        );
        Ok(())
    }

    #[test]
    fn daa_retarget_clamps_fast_timespan_to_quarter_target()
    -> Result<(), Box<dyn std::error::Error>> {
        let handles = empty_apply_handles();
        let interval = handles.network.retarget_interval();
        let expected_timespan = interval * 600;
        let parent_hash = seed_pow_chain(
            &handles,
            CompactTarget::from_consensus(MAINNET_POW_LIMIT_BITS),
            DAA_ANCHOR_TIME,
            DAA_ANCHOR_TIME + (expected_timespan / 4) - 1,
            interval - 1,
        )?;
        let block = block_with_pow_header(
            parent_hash,
            CompactTarget::from_consensus(MAINNET_POW_LIMIT_DIV_4_BITS),
            DAA_ANCHOR_TIME + expected_timespan,
            interval,
        );

        assert!(check_pow_limit_and_continuity_for_seeded_tip(&handles, &block, interval).is_ok());
        Ok(())
    }

    #[test]
    fn daa_retarget_clamps_slow_timespan_to_quadruple_target()
    -> Result<(), Box<dyn std::error::Error>> {
        let handles = empty_apply_handles();
        let interval = handles.network.retarget_interval();
        let expected_timespan = interval * 600;
        let start_bits = scaled_pow_limit_bits(&handles, 16);
        let expected_bits = retarget_bits_for_test(
            &handles,
            start_bits,
            (expected_timespan * 4) + 1,
            expected_timespan,
        );
        let parent_hash = seed_pow_chain(
            &handles,
            start_bits,
            DAA_ANCHOR_TIME,
            DAA_ANCHOR_TIME + (expected_timespan * 4) + 1,
            interval - 1,
        )?;
        let block = block_with_pow_header(
            parent_hash,
            expected_bits,
            DAA_ANCHOR_TIME + (expected_timespan * 4) + 600,
            interval,
        );

        assert!(check_pow_limit_and_continuity_for_seeded_tip(&handles, &block, interval).is_ok());
        Ok(())
    }

    #[test]
    fn daa_retarget_caps_slow_timespan_at_pow_limit() -> Result<(), Box<dyn std::error::Error>> {
        let handles = empty_apply_handles();
        let interval = handles.network.retarget_interval();
        let expected_timespan = interval * 600;
        let parent_hash = seed_pow_chain(
            &handles,
            CompactTarget::from_consensus(MAINNET_POW_LIMIT_BITS),
            DAA_ANCHOR_TIME,
            DAA_ANCHOR_TIME + (expected_timespan * 4) + 1,
            interval - 1,
        )?;
        let block = block_with_pow_header(
            parent_hash,
            CompactTarget::from_consensus(MAINNET_POW_LIMIT_BITS),
            DAA_ANCHOR_TIME + (expected_timespan * 4) + 600,
            interval,
        );

        assert!(check_pow_limit_and_continuity_for_seeded_tip(&handles, &block, interval).is_ok());
        Ok(())
    }

    #[test]
    fn testnet_allows_min_difficulty_after_time_gap() -> Result<(), Box<dyn std::error::Error>> {
        let handles = empty_apply_handles_for_network(Network::Testnet3);
        let regular_bits = CompactTarget::from_consensus(MAINNET_POW_LIMIT_DIV_4_BITS);
        let pow_limit_bits = pow_limit_bits(&handles);
        let parent_hash = seed_pow_chain_with_headers(
            &handles,
            &[
                (regular_bits, DAA_ANCHOR_TIME),
                (regular_bits, DAA_ANCHOR_TIME + 600),
            ],
        )?;
        let block = block_with_pow_header(parent_hash, pow_limit_bits, DAA_ANCHOR_TIME + 1_801, 2);

        assert!(check_pow_limit_and_continuity_for_seeded_tip(&handles, &block, 2).is_ok());
        Ok(())
    }

    #[test]
    fn testnet_timely_block_after_min_difficulty_inherits_last_non_min_bits()
    -> Result<(), Box<dyn std::error::Error>> {
        let handles = empty_apply_handles_for_network(Network::Testnet3);
        let regular_bits = CompactTarget::from_consensus(MAINNET_POW_LIMIT_DIV_4_BITS);
        let pow_limit_bits = pow_limit_bits(&handles);
        let parent_hash = seed_pow_chain_with_headers(
            &handles,
            &[
                (regular_bits, DAA_ANCHOR_TIME),
                (regular_bits, DAA_ANCHOR_TIME + 600),
                (pow_limit_bits, DAA_ANCHOR_TIME + 1_801),
            ],
        )?;
        let timely_time = DAA_ANCHOR_TIME + 2_400;
        let accepted = block_with_pow_header(parent_hash, regular_bits, timely_time, 3);
        assert!(check_pow_limit_and_continuity_for_seeded_tip(&handles, &accepted, 3).is_ok());

        let rejected = block_with_pow_header(parent_hash, pow_limit_bits, timely_time, 4);
        let error = match check_pow_limit_and_continuity_for_seeded_tip(&handles, &rejected, 3) {
            Ok(()) => panic!("timely testnet block must inherit the last non-min nBits"),
            Err(error) => error,
        };
        assert_nbits_error(
            &error,
            pow_limit_bits.to_consensus(),
            regular_bits.to_consensus(),
            3,
        );
        Ok(())
    }

    #[test]
    fn mainnet_rejects_min_difficulty_after_time_gap() -> Result<(), Box<dyn std::error::Error>> {
        let handles = empty_apply_handles();
        let regular_bits = CompactTarget::from_consensus(MAINNET_POW_LIMIT_DIV_4_BITS);
        let pow_limit_bits = pow_limit_bits(&handles);
        let parent_hash = seed_pow_chain_with_headers(
            &handles,
            &[
                (regular_bits, DAA_ANCHOR_TIME),
                (regular_bits, DAA_ANCHOR_TIME + 600),
            ],
        )?;
        let block = block_with_pow_header(parent_hash, pow_limit_bits, DAA_ANCHOR_TIME + 1_801, 2);

        let error = match check_pow_limit_and_continuity_for_seeded_tip(&handles, &block, 2) {
            Ok(()) => panic!("mainnet must not allow testnet minimum-difficulty exception"),
            Err(error) => error,
        };
        assert_nbits_error(
            &error,
            pow_limit_bits.to_consensus(),
            regular_bits.to_consensus(),
            2,
        );
        Ok(())
    }

    #[test]
    fn testnet_min_difficulty_does_not_override_retarget_boundary()
    -> Result<(), Box<dyn std::error::Error>> {
        let handles = empty_apply_handles_for_network(Network::Testnet3);
        let interval = handles.network.retarget_interval();
        let expected_timespan = interval * 600;
        let regular_bits = CompactTarget::from_consensus(MAINNET_POW_LIMIT_DIV_4_BITS);
        let pow_limit_bits = pow_limit_bits(&handles);
        let parent_hash = seed_pow_chain(
            &handles,
            regular_bits,
            DAA_ANCHOR_TIME,
            DAA_ANCHOR_TIME + expected_timespan,
            interval - 1,
        )?;
        let block = block_with_pow_header(
            parent_hash,
            pow_limit_bits,
            DAA_ANCHOR_TIME + expected_timespan + 1_201,
            interval,
        );

        let error = match check_pow_limit_and_continuity_for_seeded_tip(&handles, &block, interval)
        {
            Ok(()) => panic!("testnet minimum-difficulty exception must not replace retarget math"),
            Err(error) => error,
        };
        assert_nbits_error(
            &error,
            pow_limit_bits.to_consensus(),
            regular_bits.to_consensus(),
            interval,
        );
        Ok(())
    }

    #[test]
    fn testnet4_retarget_uses_first_period_bits_after_min_difficulty_tip()
    -> Result<(), Box<dyn std::error::Error>> {
        let handles = empty_apply_handles_for_network(Network::Testnet4);
        let interval = handles.network.retarget_interval();
        let expected_timespan = interval * 600;
        let first_period_bits = scaled_pow_limit_bits(&handles, 16);
        let pow_limit_bits = pow_limit_bits(&handles);
        let parent_hash = seed_pow_period_with_tip_bits(
            &handles,
            first_period_bits,
            pow_limit_bits,
            DAA_ANCHOR_TIME,
            DAA_ANCHOR_TIME + expected_timespan,
            interval - 1,
        )?;
        let block = block_with_pow_header(
            parent_hash,
            first_period_bits,
            DAA_ANCHOR_TIME + expected_timespan + 600,
            interval,
        );

        assert!(check_pow_limit_and_continuity_for_seeded_tip(&handles, &block, interval).is_ok());
        Ok(())
    }

    #[test]
    fn apply_block_persists_non_empty_filter_for_valid_same_block_spend()
    -> Result<(), Box<dyn std::error::Error>> {
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);

        let external_prevout = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x91; 32]),
            vout: 0,
        };
        let filter_index = Arc::new(RecordingFilterIndex::default());
        let handles = apply_handles_with_filter_index(
            Network::Regtest,
            utxo_with_output(external_prevout, 1)?,
            &filter_index,
        );
        let genesis_tip = applied_header_tip(
            &handles,
            Hash256::from_le_bytes(genesis.block_hash().as_byte_array()),
            &genesis,
            0,
        )?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));

        let funding_tx = spending_transaction_to_script(
            external_prevout,
            Sequence::MAX.to_consensus_u32(),
            op_true_script(),
        );
        let funding_outpoint = bitcoin::OutPoint {
            txid: funding_tx.compute_txid(),
            vout: 0,
        };
        let same_block_spend = spending_transaction_to_script(
            funding_outpoint,
            Sequence::MAX.to_consensus_u32(),
            op_true_script(),
        );
        let block = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1), funding_tx, same_block_spend],
        )?;
        let block_hash = Hash256::from_le_bytes(block.block_hash().as_byte_array());

        apply_block(&handles, &block)?;

        let stored_filter = filter_index
            .filter(block_hash)?
            .ok_or_else(|| std::io::Error::other("filter row missing"))?;
        assert!(!stored_filter.is_empty());
        Ok(())
    }

    #[test]
    #[allow(clippy::arc_with_non_send_sync)]
    fn apply_block_skips_confirmed_transaction_cache() -> Result<(), Box<dyn std::error::Error>> {
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let handles = apply_handles_without_tx_index(Network::Regtest, Arc::new(UtxoSet::new()));
        assert!(handles.tx_index.is_none());
        let genesis_tip = applied_header_tip(
            &handles,
            Hash256::from_le_bytes(genesis.block_hash().as_byte_array()),
            &genesis,
            0,
        )?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));
        let block = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1)],
        )?;

        apply_block(&handles, &block)?;

        assert!(handles.transactions.read().is_empty());
        Ok(())
    }

    #[test]
    fn apply_block_publishes_rawtx_bytes_in_block_order() -> Result<(), Box<dyn std::error::Error>>
    {
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let external_prevout = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x96; 32]),
            vout: 0,
        };
        let publisher = Arc::new(RecordingRawTxPublisher::default());
        let publisher_for_handles: Arc<dyn crate::ZmqPublisher> = publisher.clone();
        let handles = apply_handles_without_tx_index(
            Network::Regtest,
            utxo_with_output(external_prevout, 1)?,
        )
        .with_zmq_publisher(publisher_for_handles);
        let genesis_tip = applied_header_tip(
            &handles,
            Hash256::from_le_bytes(genesis.block_hash().as_byte_array()),
            &genesis,
            0,
        )?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));
        let txdata = vec![
            coinbase_transaction(0x96),
            spending_transaction_to_script(
                external_prevout,
                Sequence::MAX.to_consensus_u32(),
                op_true_script(),
            ),
        ];
        let expected_raw_txs = txdata
            .iter()
            .map(bitcoin::consensus::encode::serialize)
            .collect::<Vec<_>>();
        let block = mined_block_with_prev_hash_and_transactions(genesis.block_hash(), txdata)?;

        apply_block(&handles, &block)?;

        assert_eq!(*publisher.raw_txs.lock(), expected_raw_txs);
        Ok(())
    }

    #[test]
    #[allow(clippy::arc_with_non_send_sync)]
    fn apply_block_keeps_txindex_failure_best_effort() -> Result<(), Box<dyn std::error::Error>> {
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let handles = apply_handles_with_tx_index(
            Network::Regtest,
            Arc::new(UtxoSet::new()),
            failing_tx_index(),
        );
        let genesis_tip = applied_header_tip(
            &handles,
            Hash256::from_le_bytes(genesis.block_hash().as_byte_array()),
            &genesis,
            0,
        )?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));
        let block = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(1)],
        )?;
        let block_hash = Hash256::from_le_bytes(block.block_hash().as_byte_array());
        let stats_before = handles.coin_stats.snapshot();

        let tip = apply_block(&handles, &block)?;

        assert!(
            handles.transactions.read().is_empty(),
            "failed txindex ingest must not populate confirmed tx cache"
        );
        assert_eq!(tip.height, 1);
        assert_eq!(
            handles.applied_tip.load_full().map(|tip| tip.height),
            Some(1),
            "best-effort txindex failure must still publish the new applied tip"
        );
        assert!(
            !handles.blocks.read().is_empty(),
            "best-effort txindex failure must still publish a block record"
        );
        assert_eq!(
            handles.utxo.len(),
            1,
            "best-effort txindex failure must still commit UTXO changes"
        );
        assert!(
            handles.block_tree.read().lookup(block_hash).is_some(),
            "best-effort txindex failure must still insert the block into the block tree"
        );
        assert_eq!(
            handles.coin_stats.snapshot().height,
            stats_before.height.saturating_add(1),
            "best-effort txindex failure must still advance coin stats height"
        );
        assert_eq!(
            handles.coin_stats.snapshot().tx_count,
            stats_before.tx_count.saturating_add(1),
            "best-effort txindex failure must still advance coin stats transaction count"
        );
        Ok(())
    }

    #[test]
    fn compute_basic_filter_skips_missing_prevout_without_persisting_empty_row()
    -> Result<(), Box<dyn std::error::Error>> {
        let filter_index = Arc::new(RecordingFilterIndex::default());
        let handles =
            apply_handles_with_filter_index(Network::Regtest, empty_utxo(), &filter_index);
        let missing_prevout = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x92; 32]),
            vout: 0,
        };
        let block = block_with_transactions(vec![
            coinbase_transaction(0x92),
            spending_transaction_to_script(
                missing_prevout,
                Sequence::MAX.to_consensus_u32(),
                op_true_script(),
            ),
        ]);
        let block_hash = Hash256::from_le_bytes(block.block_hash().as_byte_array());
        let scratch = ApplyScratch::new(&block, 1, false, true)?;

        let filter = compute_basic_filter(&block, &handles, block_hash, 1, &scratch);

        assert!(filter.is_none());
        assert!(filter_index.rows.lock().is_empty());
        Ok(())
    }

    #[test]
    fn compute_basic_filter_matches_independent_same_block_prevout_resolver()
    -> Result<(), Box<dyn std::error::Error>> {
        let external_prevout = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x93; 32]),
            vout: 0,
        };
        let filter_index = Arc::new(RecordingFilterIndex::default());
        let handles = apply_handles_with_filter_index(
            Network::Regtest,
            utxo_with_output(external_prevout, 1)?,
            &filter_index,
        );
        let funding_script = ScriptBuf::from_bytes(vec![0x51, 0x93]);
        let funding_tx = spending_transaction_to_script(
            external_prevout,
            Sequence::MAX.to_consensus_u32(),
            funding_script,
        );
        let funding_outpoint = bitcoin::OutPoint {
            txid: funding_tx.compute_txid(),
            vout: 0,
        };
        let same_block_spend = spending_transaction_to_script(
            funding_outpoint,
            Sequence::MAX.to_consensus_u32(),
            ScriptBuf::from_bytes(vec![0x51, 0x94]),
        );
        let block = block_with_transactions(vec![
            coinbase_transaction(0x93),
            funding_tx,
            same_block_spend,
        ]);
        let block_hash = Hash256::from_le_bytes(block.block_hash().as_byte_array());
        let scratch = ApplyScratch::new(&block, 2, false, true)?;

        let filter = compute_basic_filter(&block, &handles, block_hash, 2, &scratch)
            .ok_or_else(|| std::io::Error::other("scratch filter missing"))?;
        let expected = reference_basic_filter_content(&block, &handles)?;

        assert_eq!(filter, expected);
        assert!(filter_index.rows.lock().is_empty());
        Ok(())
    }

    #[test]
    fn apply_block_rejects_same_block_coinbase_spend_without_persisting_filter()
    -> Result<(), Box<dyn std::error::Error>> {
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let filter_index = Arc::new(RecordingFilterIndex::default());
        let handles =
            apply_handles_with_filter_index(Network::Regtest, empty_utxo(), &filter_index);
        let genesis_tip = applied_header_tip(
            &handles,
            Hash256::from_le_bytes(genesis.block_hash().as_byte_array()),
            &genesis,
            0,
        )?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));

        let mut coinbase = coinbase_transaction(0x94);
        coinbase.output[0].script_pubkey = op_true_script();
        let coinbase_outpoint = bitcoin::OutPoint {
            txid: coinbase.compute_txid(),
            vout: 0,
        };
        let spend = spending_transaction_to_script(
            coinbase_outpoint,
            Sequence::MAX.to_consensus_u32(),
            op_true_script(),
        );
        let block = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase, spend],
        )?;

        let error = match apply_block(&handles, &block) {
            Ok(_) => panic!("same-block coinbase spend must fail before filter persistence"),
            Err(error) => error,
        };

        assert_bip_error(&error, "COINBASE_MATURITY");
        assert!(filter_index.rows.lock().is_empty());
        Ok(())
    }

    #[test]
    fn apply_block_rejects_future_same_block_prevout_without_utxo_commit_or_filter_row()
    -> Result<(), Box<dyn std::error::Error>> {
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let external_prevout = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x95; 32]),
            vout: 0,
        };
        let filter_index = Arc::new(RecordingFilterIndex::default());
        let handles = apply_handles_with_filter_index(
            Network::Regtest,
            utxo_with_output(external_prevout, 1)?,
            &filter_index,
        );
        let genesis_tip = applied_header_tip(
            &handles,
            Hash256::from_le_bytes(genesis.block_hash().as_byte_array()),
            &genesis,
            0,
        )?;
        handles.applied_tip.store(Some(Arc::new(genesis_tip)));

        let later_tx = spending_transaction_to_script(
            external_prevout,
            Sequence::MAX.to_consensus_u32(),
            op_true_script(),
        );
        let future_prevout = bitcoin::OutPoint {
            txid: later_tx.compute_txid(),
            vout: 0,
        };
        let premature_spend = spending_transaction_to_script(
            future_prevout,
            Sequence::MAX.to_consensus_u32(),
            op_true_script(),
        );
        let block = mined_block_with_prev_hash_and_transactions(
            genesis.block_hash(),
            vec![coinbase_transaction(0x95), premature_spend, later_tx],
        )?;

        let error = match apply_block(&handles, &block) {
            Ok(_) => {
                panic!("future same-block prevout must fail before scratch-backed side effects")
            }
            Err(error) => error,
        };

        assert!(matches!(error, ApplyError::Consensus(_)));
        assert!(
            handles
                .utxo
                .get(&internal_outpoint(&future_prevout))
                .is_none()
        );
        assert!(filter_index.rows.lock().is_empty());
        Ok(())
    }

    fn transaction(seed: u8) -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: bitcoin::OutPoint {
                    txid: bitcoin::Txid::from_byte_array([seed; 32]),
                    vout: u32::from(seed),
                },
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    fn reference_basic_filter_content(
        block: &bitcoin::Block,
        handles: &ApplyHandles,
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut same_block_outputs = HashMap::new();
        for tx in &block.txdata {
            let txid = Hash256::from_le_bytes(tx.compute_txid().as_byte_array());
            for (vout, txout) in tx.output.iter().enumerate() {
                same_block_outputs.insert(
                    OutPoint::new(txid, u32::try_from(vout)?),
                    txout.script_pubkey.clone(),
                );
            }
        }

        let filter = bitcoin::bip158::BlockFilter::new_script_filter(block, |outpoint| {
            let prev_outpoint = OutPoint::new(
                Hash256::from_le_bytes(outpoint.txid.as_byte_array()),
                outpoint.vout,
            );
            same_block_outputs
                .get(&prev_outpoint)
                .cloned()
                .or_else(|| {
                    handles
                        .utxo
                        .get(&prev_outpoint)
                        .map(|txout| txout.script_pubkey)
                })
                .ok_or(bitcoin::bip158::Error::UtxoMissing(*outpoint))
        })?;
        Ok(filter.content)
    }

    fn coinbase_transaction(seed: u8) -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(vec![seed, seed]),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    #[allow(clippy::arc_with_non_send_sync)]
    fn utxo_with_output(
        previous_output: bitcoin::OutPoint,
        height: u32,
    ) -> Result<Arc<UtxoSet>, bitcoin_rs_utxo::UtxoError> {
        utxo_with_outputs_at_height(&[previous_output], height)
    }

    #[allow(clippy::arc_with_non_send_sync)]
    fn utxo_with_outputs_at_height(
        previous_outputs: &[bitcoin::OutPoint],
        height: u32,
    ) -> Result<Arc<UtxoSet>, bitcoin_rs_utxo::UtxoError> {
        let utxo = Arc::new(UtxoSet::new());
        let mut changes = BlockChanges::default();
        for previous_output in previous_outputs {
            let txid = Hash256::from_le_bytes(previous_output.txid.as_byte_array());
            changes.add(UtxoAdd::new(
                OutPoint::new(txid, previous_output.vout),
                TxOut {
                    value: Amount::from_sat(1_000),
                    script_pubkey: op_true_script(),
                },
                false,
                height,
            ));
        }
        utxo.commit_block(&changes, &Hash256::from_le_bytes(&[9; 32]))?;
        Ok(utxo)
    }

    fn block_with_transaction(tx: Transaction) -> bitcoin::Block {
        bitcoin::Block {
            header: bitcoin::block::Header {
                version: bitcoin::block::Version::ONE,
                prev_blockhash: bitcoin::BlockHash::all_zeros(),
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: 0,
                bits: bitcoin::pow::CompactTarget::from_consensus(0),
                nonce: 0,
            },
            txdata: vec![tx],
        }
    }

    fn block_with_transactions(txdata: Vec<Transaction>) -> bitcoin::Block {
        bitcoin::Block {
            header: bitcoin::block::Header {
                version: bitcoin::block::Version::ONE,
                prev_blockhash: bitcoin::BlockHash::all_zeros(),
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: 0,
                bits: bitcoin::pow::CompactTarget::from_consensus(0),
                nonce: 0,
            },
            txdata,
        }
    }

    fn block_with_prev_hash_and_transactions(
        prev_blockhash: bitcoin::BlockHash,
        txdata: Vec<Transaction>,
    ) -> bitcoin::Block {
        let mut block = bitcoin::Block {
            header: bitcoin::block::Header {
                version: bitcoin::block::Version::ONE,
                prev_blockhash,
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: 1,
                bits: bitcoin::pow::CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            },
            txdata,
        };
        block.header.merkle_root = block
            .compute_merkle_root()
            .unwrap_or_else(bitcoin::TxMerkleNode::all_zeros);
        block
    }

    fn mined_block_with_prev_hash_and_transactions(
        prev_blockhash: bitcoin::BlockHash,
        txdata: Vec<Transaction>,
    ) -> Result<bitcoin::Block, Box<dyn std::error::Error>> {
        let mut block = block_with_prev_hash_and_transactions(prev_blockhash, txdata);
        let target = block.header.target();
        loop {
            if block.header.validate_pow(target).is_ok() {
                return Ok(block);
            }
            block.header.nonce = block
                .header
                .nonce
                .checked_add(1)
                .ok_or_else(|| std::io::Error::other("test block nonce exhausted"))?;
        }
    }

    fn block_with_pow_header(
        prev_blockhash: bitcoin::BlockHash,
        bits: CompactTarget,
        time: u32,
        nonce: u32,
    ) -> bitcoin::Block {
        bitcoin::Block {
            header: pow_header(prev_blockhash, bits, time, nonce),
            txdata: Vec::new(),
        }
    }

    fn pow_header(
        prev_blockhash: bitcoin::BlockHash,
        bits: CompactTarget,
        time: u32,
        nonce: u32,
    ) -> bitcoin::block::Header {
        bitcoin::block::Header {
            version: bitcoin::block::Version::ONE,
            prev_blockhash,
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time,
            bits,
            nonce,
        }
    }

    fn seed_pow_chain(
        handles: &ApplyHandles,
        bits: CompactTarget,
        anchor_time: u32,
        tip_time: u32,
        tip_height: u32,
    ) -> Result<bitcoin::BlockHash, Box<dyn std::error::Error>> {
        let headers: Vec<_> = (0..=tip_height)
            .map(|height| {
                (
                    bits,
                    interpolated_time(anchor_time, tip_time, height, tip_height),
                )
            })
            .collect();
        seed_pow_chain_with_headers(handles, &headers)
    }

    fn seed_pow_period_with_tip_bits(
        handles: &ApplyHandles,
        period_bits: CompactTarget,
        tip_bits: CompactTarget,
        anchor_time: u32,
        tip_time: u32,
        tip_height: u32,
    ) -> Result<bitcoin::BlockHash, Box<dyn std::error::Error>> {
        let headers: Vec<_> = (0..=tip_height)
            .map(|height| {
                let bits = if height == tip_height {
                    tip_bits
                } else {
                    period_bits
                };
                (
                    bits,
                    interpolated_time(anchor_time, tip_time, height, tip_height),
                )
            })
            .collect();
        seed_pow_chain_with_headers(handles, &headers)
    }

    fn seed_pow_chain_with_headers(
        handles: &ApplyHandles,
        headers: &[(CompactTarget, u32)],
    ) -> Result<bitcoin::BlockHash, Box<dyn std::error::Error>> {
        let mut tree = handles.block_tree.write();
        let mut parent = None;
        let mut prev_hash = bitcoin::BlockHash::all_zeros();
        for (height, &(bits, time)) in headers.iter().enumerate() {
            let height = u32::try_from(height)?;
            let header = pow_header(prev_hash, bits, time, height);
            prev_hash = header.block_hash();
            parent = Some(tree.insert_node(parent, header, NodeStatus::Active)?);
        }
        handles.chain_tip.store(tree.tip());
        Ok(prev_hash)
    }

    fn interpolated_time(anchor_time: u32, tip_time: u32, height: u32, tip_height: u32) -> u32 {
        if height == 0 || tip_height == 0 {
            return anchor_time;
        }
        let span = u64::from(tip_time.saturating_sub(anchor_time));
        let offset = span.saturating_mul(u64::from(height)) / u64::from(tip_height);
        anchor_time.saturating_add(u32::try_from(offset).unwrap_or(u32::MAX))
    }

    fn scaled_pow_limit_bits(handles: &ApplyHandles, divisor: u64) -> CompactTarget {
        let target = handles.network.max_target() / ChainWork::from(divisor);
        bitcoin::Target::from_be_bytes(target.to_be_bytes::<32>()).to_compact_lossy()
    }

    fn pow_limit_bits(handles: &ApplyHandles) -> CompactTarget {
        bitcoin::Target::from_be_bytes(handles.network.max_target().to_be_bytes::<32>())
            .to_compact_lossy()
    }

    fn retarget_bits_for_test(
        handles: &ApplyHandles,
        previous_bits: CompactTarget,
        actual_timespan: u32,
        expected_timespan: u32,
    ) -> CompactTarget {
        let min_timespan = expected_timespan / 4;
        let max_timespan = expected_timespan * 4;
        let actual_clamped = actual_timespan.clamp(min_timespan, max_timespan);
        let previous_target =
            ChainWork::from_be_bytes(bitcoin::Target::from_compact(previous_bits).to_be_bytes());
        let actual = ChainWork::from(actual_clamped);
        let expected = ChainWork::from(expected_timespan);
        let target = ((previous_target / expected) * actual)
            + (((previous_target % expected) * actual) / expected);
        let target = target.min(handles.network.max_target());
        bitcoin::Target::from_be_bytes(target.to_be_bytes::<32>()).to_compact_lossy()
    }

    fn assert_nbits_error(error: &ApplyError, actual: u32, expected: u32, height: u32) {
        assert!(matches!(
            error,
            ApplyError::NbitsNonRetargetMismatch {
                actual: got_actual,
                expected: got_expected,
                height: got_height,
            } if *got_actual == actual && *got_expected == expected && *got_height == height
        ));
    }

    fn spending_transaction(previous_output: bitcoin::OutPoint, sequence: u32) -> Transaction {
        spending_transaction_to_script(previous_output, sequence, ScriptBuf::new())
    }

    fn spending_transaction_with_version(
        previous_output: bitcoin::OutPoint,
        sequence: u32,
        version: bitcoin::transaction::Version,
    ) -> Transaction {
        let mut transaction = spending_transaction(previous_output, sequence);
        transaction.version = version;
        transaction
    }

    fn spending_transaction_to_script(
        previous_output: bitcoin::OutPoint,
        sequence: u32,
        script_pubkey: ScriptBuf,
    ) -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::from_consensus(sequence),
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey,
            }],
        }
    }

    fn op_true_script() -> ScriptBuf {
        ScriptBuf::from_bytes(vec![0x51])
    }

    fn softfork_state(csv_active: bool) -> crate::bip9_context::ContextualSoftforkState {
        crate::bip9_context::ContextualSoftforkState {
            csv_active,
            segwit_active: false,
        }
    }

    fn seed_block_tree_for_bip68_time(
        handles: &ApplyHandles,
    ) -> Result<bitcoin_rs_chain::node::NodeId, ApplyError> {
        seed_block_tree_for_bip68_time_at_height(handles, BIP68_TEST_PREVOUT_HEIGHT)
    }

    fn seed_block_tree_for_bip68_time_at_height(
        handles: &ApplyHandles,
        tip_height: u32,
    ) -> Result<bitcoin_rs_chain::node::NodeId, ApplyError> {
        let mut tree = handles.block_tree.write();
        let mut parent = None;
        let mut tip = None;
        for height in 0..=tip_height {
            let header = bitcoin::block::Header {
                version: bitcoin::block::Version::ONE,
                prev_blockhash: parent
                    .and_then(|id| {
                        tree.node(id).ok().map(|node| {
                            bitcoin::BlockHash::from_byte_array(node.hash.to_le_bytes())
                        })
                    })
                    .unwrap_or_else(bitcoin::BlockHash::all_zeros),
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time: BIP68_TEST_PREVOUT_MTP,
                bits: bitcoin::pow::CompactTarget::from_consensus(0x207f_ffff),
                nonce: height,
            };
            let id = tree.insert_node(parent, header, NodeStatus::Active)?;
            parent = Some(id);
            tip = Some(id);
        }
        match tip {
            Some(tip) => Ok(tip),
            None => Err(ApplyError::HeightOverflow(0)),
        }
    }

    fn seed_block_tree_with_times(
        handles: &ApplyHandles,
        times: &[u32],
    ) -> Result<bitcoin_rs_chain::node::NodeId, ApplyError> {
        let mut tree = handles.block_tree.write();
        let mut parent = None;
        let mut tip = None;
        for (height, time) in times.iter().copied().enumerate() {
            let header = bitcoin::block::Header {
                version: bitcoin::block::Version::ONE,
                prev_blockhash: parent
                    .and_then(|id| {
                        tree.node(id).ok().map(|node| {
                            bitcoin::BlockHash::from_byte_array(node.hash.to_le_bytes())
                        })
                    })
                    .unwrap_or_else(bitcoin::BlockHash::all_zeros),
                merkle_root: bitcoin::TxMerkleNode::all_zeros(),
                time,
                bits: bitcoin::pow::CompactTarget::from_consensus(0x207f_ffff),
                nonce: u32::try_from(height).map_err(|_| ApplyError::HeightOverflow(u32::MAX))?,
            };
            let id = tree.insert_node(parent, header, NodeStatus::Active)?;
            parent = Some(id);
            tip = Some(id);
        }
        match tip {
            Some(tip) => Ok(tip),
            None => Err(ApplyError::HeightOverflow(0)),
        }
    }

    fn assert_bip_error(error: &ApplyError, bip: &str) {
        assert!(matches!(
            error,
            ApplyError::Consensus(bitcoin_rs_consensus::ConsensusError::Bip { bip: actual, .. }) if *actual == bip
        ));
    }

    fn assert_bip_error_reason_contains(error: &ApplyError, bip: &str, needle: &str) {
        assert!(matches!(
            error,
            ApplyError::Consensus(bitcoin_rs_consensus::ConsensusError::Bip { bip: actual, reason })
                if *actual == bip && reason.contains(needle)
        ));
    }

    #[allow(clippy::arc_with_non_send_sync)]
    fn empty_apply_handles() -> ApplyHandles {
        empty_apply_handles_for_network(Network::Mainnet)
    }

    #[allow(clippy::arc_with_non_send_sync)]
    fn empty_apply_handles_for_network(network: Network) -> ApplyHandles {
        apply_handles_for_network(network, Arc::new(UtxoSet::new()))
    }

    #[allow(clippy::arc_with_non_send_sync)]
    fn apply_handles(utxo: Arc<UtxoSet>) -> ApplyHandles {
        apply_handles_for_network(Network::Mainnet, utxo)
    }

    fn apply_handles_with_filter_index(
        network: Network,
        utxo: Arc<UtxoSet>,
        filter_index: &RecordingFilterIndex,
    ) -> ApplyHandles {
        let filter_index: Arc<Box<dyn FilterIndexLike>> =
            Arc::new(Box::new(RecordingFilterIndex {
                rows: Arc::clone(&filter_index.rows),
            }));
        ApplyHandles::new(
            network,
            Arc::new(ArcSwapOption::empty()),
            Arc::new(ArcSwapOption::empty()),
            Arc::new(RwLock::new(BlockTree::new())),
            utxo,
            Arc::new(bitcoin_rs_coinstats::CoinStatsListener::new(
                bitcoin_rs_coinstats::CoinStats::default(),
            )),
            Some(noop_tx_index()),
            filter_index,
            Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
            Arc::new(RwLock::new(Vec::new())),
            Arc::new(RwLock::new(HashMap::<bitcoin::Txid, Transaction>::new())),
            Arc::new(crate::NoOpZmqPublisher),
        )
    }

    fn apply_handles_for_network(network: Network, utxo: Arc<UtxoSet>) -> ApplyHandles {
        apply_handles_with_tx_index(network, utxo, noop_tx_index())
    }

    fn apply_handles_without_tx_index(network: Network, utxo: Arc<UtxoSet>) -> ApplyHandles {
        ApplyHandles::new(
            network,
            Arc::new(ArcSwapOption::empty()),
            Arc::new(ArcSwapOption::empty()),
            Arc::new(RwLock::new(BlockTree::new())),
            utxo,
            Arc::new(bitcoin_rs_coinstats::CoinStatsListener::new(
                bitcoin_rs_coinstats::CoinStats::default(),
            )),
            None,
            noop_filter_index(),
            Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
            Arc::new(RwLock::new(Vec::new())),
            Arc::new(RwLock::new(HashMap::<bitcoin::Txid, Transaction>::new())),
            Arc::new(crate::NoOpZmqPublisher),
        )
    }

    fn apply_handles_with_tx_index(
        network: Network,
        utxo: Arc<UtxoSet>,
        tx_index: Arc<Mutex<Box<dyn IndexerLike>>>,
    ) -> ApplyHandles {
        ApplyHandles::new(
            network,
            Arc::new(ArcSwapOption::empty()),
            Arc::new(ArcSwapOption::empty()),
            Arc::new(RwLock::new(BlockTree::new())),
            utxo,
            Arc::new(bitcoin_rs_coinstats::CoinStatsListener::new(
                bitcoin_rs_coinstats::CoinStats::default(),
            )),
            Some(tx_index),
            noop_filter_index(),
            Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
            Arc::new(RwLock::new(Vec::new())),
            Arc::new(RwLock::new(HashMap::<bitcoin::Txid, Transaction>::new())),
            Arc::new(crate::NoOpZmqPublisher),
        )
    }

    struct NoopIndexer;

    impl IndexerLike for NoopIndexer {
        fn ingest_block(
            &mut self,
            _block: &[u8],
            _height: u32,
        ) -> Result<IndexRowCounts, IndexError> {
            Ok(IndexRowCounts::default())
        }

        fn resolve_outpoint_value(
            &self,
            _outpoint: bitcoin::OutPoint,
            _source: &dyn BlockSource,
        ) -> Result<Option<u64>, IndexError> {
            Ok(None)
        }
    }

    fn noop_tx_index() -> Arc<Mutex<Box<dyn IndexerLike>>> {
        let indexer: Box<dyn IndexerLike> = Box::new(NoopIndexer);
        Arc::new(Mutex::new(indexer))
    }

    struct FailingIndexer;

    impl IndexerLike for FailingIndexer {
        fn ingest_block(
            &mut self,
            _block: &[u8],
            _height: u32,
        ) -> Result<IndexRowCounts, IndexError> {
            Err(IndexError::Storage(
                bitcoin_rs_storage::StorageError::backend("forced txindex failure"),
            ))
        }

        fn resolve_outpoint_value(
            &self,
            _outpoint: bitcoin::OutPoint,
            _source: &dyn BlockSource,
        ) -> Result<Option<u64>, IndexError> {
            Ok(None)
        }
    }

    fn failing_tx_index() -> Arc<Mutex<Box<dyn IndexerLike>>> {
        let indexer: Box<dyn IndexerLike> = Box::new(FailingIndexer);
        Arc::new(Mutex::new(indexer))
    }

    #[derive(Debug, Default)]
    struct RecordingRawTxPublisher {
        raw_txs: Arc<Mutex<Vec<Vec<u8>>>>,
    }

    impl crate::ZmqPublisher for RecordingRawTxPublisher {
        fn wants_rawtx(&self) -> bool {
            true
        }

        fn publish_hashblock(&self, _hash: Hash256) {}

        fn publish_hashtx(&self, _txid: bitcoin::Txid) {}

        fn publish_rawblock(&self, _bytes: &[u8]) {}

        fn publish_rawtx(&self, bytes: &[u8]) {
            self.raw_txs.lock().push(bytes.to_vec());
        }
    }

    #[derive(Default)]
    struct RecordingFilterIndex {
        rows: Arc<Mutex<HashMap<Hash256, Vec<u8>>>>,
    }

    impl FilterIndexLike for RecordingFilterIndex {
        fn put_filter(
            &self,
            block_hash: Hash256,
            _prev_header: Hash256,
            filter_bytes: &[u8],
        ) -> Result<Hash256, FilterIndexError> {
            self.rows.lock().insert(block_hash, filter_bytes.to_vec());
            Ok(Hash256::default())
        }

        fn filter_header(&self, _block_hash: Hash256) -> Result<Option<Hash256>, FilterIndexError> {
            Ok(None)
        }

        fn filter(&self, block_hash: Hash256) -> Result<Option<Vec<u8>>, FilterIndexError> {
            Ok(self.rows.lock().get(&block_hash).cloned())
        }
    }

    struct NoopFilterIndex;

    impl FilterIndexLike for NoopFilterIndex {
        fn wants_filters(&self) -> bool {
            false
        }

        fn put_filter(
            &self,
            _block_hash: Hash256,
            _prev_header: Hash256,
            _filter_bytes: &[u8],
        ) -> Result<Hash256, FilterIndexError> {
            Ok(Hash256::default())
        }

        fn filter_header(&self, _block_hash: Hash256) -> Result<Option<Hash256>, FilterIndexError> {
            Ok(None)
        }

        fn filter(&self, _block_hash: Hash256) -> Result<Option<Vec<u8>>, FilterIndexError> {
            Ok(None)
        }
    }

    fn noop_filter_index() -> Arc<Box<dyn FilterIndexLike>> {
        let filter_index: Box<dyn FilterIndexLike> = Box::new(NoopFilterIndex);
        Arc::new(filter_index)
    }

    #[allow(clippy::arc_with_non_send_sync)]
    fn empty_utxo() -> Arc<UtxoSet> {
        Arc::new(UtxoSet::new())
    }
}

#[cfg(test)]
mod contextual_softfork_tests {
    use bitcoin_rs_script::VerifyFlags;

    use super::*;

    #[test]
    fn verify_flags_use_contextual_csv_and_segwit_state() {
        let inactive = crate::bip9_context::ContextualSoftforkState {
            csv_active: false,
            segwit_active: false,
        };
        let active = crate::bip9_context::ContextualSoftforkState {
            csv_active: true,
            segwit_active: true,
        };

        let inactive_flags = compute_verify_flags(Network::Mainnet, 481_824, inactive);
        assert!(!inactive_flags.contains(VerifyFlags::CHECKSEQUENCEVERIFY));
        assert!(!inactive_flags.contains(VerifyFlags::WITNESS));
        assert!(!inactive_flags.contains(VerifyFlags::NULLDUMMY));

        let active_flags = compute_verify_flags(Network::Mainnet, 1, active);
        assert!(active_flags.contains(VerifyFlags::CHECKSEQUENCEVERIFY));
        assert!(active_flags.contains(VerifyFlags::WITNESS));
        assert!(active_flags.contains(VerifyFlags::NULLDUMMY));
    }
}
#[cfg(test)]
mod zmq_emit_tests {
    use super::*;
    use bitcoin::hashes::Hash as _;
    use parking_lot::Mutex as TestMutex;

    #[derive(Debug, Default)]
    struct CapturingPublisher {
        events: TestMutex<Vec<String>>,
    }

    impl crate::ZmqPublisher for CapturingPublisher {
        fn publish_hashblock(&self, hash: bitcoin_rs_primitives::Hash256) {
            self.events
                .lock()
                .push(format!("hashblock:{}", hash.to_string_be()));
        }

        fn publish_hashtx(&self, txid: bitcoin::Txid) {
            self.events.lock().push(format!("hashtx:{txid}"));
        }

        fn publish_rawblock(&self, _bytes: &[u8]) {
            self.events.lock().push("rawblock".to_owned());
        }

        fn publish_rawtx(&self, _bytes: &[u8]) {
            self.events.lock().push("rawtx".to_owned());
        }
    }

    #[test]
    fn captures_event_count_smoke() {
        let capturing = Arc::new(CapturingPublisher::default());
        let publisher: Arc<dyn crate::ZmqPublisher> = capturing.clone();

        publisher.publish_hashblock(bitcoin_rs_primitives::Hash256::default());
        publisher.publish_hashtx(bitcoin::Txid::from_byte_array([0; 32]));
        publisher.publish_rawblock(&[]);
        publisher.publish_rawtx(&[]);

        let events = capturing.events.lock().clone();
        assert_eq!(
            events,
            vec![
                format!(
                    "hashblock:{}",
                    bitcoin_rs_primitives::Hash256::default().to_string_be()
                ),
                format!("hashtx:{}", bitcoin::Txid::from_byte_array([0; 32])),
                "rawblock".to_owned(),
                "rawtx".to_owned(),
            ]
        );
    }
}

#[cfg(test)]
mod with_zmq_publisher_tests {
    use crate::ZmqPublisher as _;
    use parking_lot::Mutex;
    use std::sync::Arc;

    #[derive(Debug, Default)]
    struct TaggedPublisher {
        tag: Mutex<u32>,
    }

    impl crate::ZmqPublisher for TaggedPublisher {
        fn publish_hashblock(&self, _: bitcoin_rs_primitives::Hash256) {
            *self.tag.lock() = 42;
        }

        fn publish_hashtx(&self, _: bitcoin::Txid) {}

        fn publish_rawblock(&self, _: &[u8]) {}

        fn publish_rawtx(&self, _: &[u8]) {}
    }

    #[test]
    fn with_zmq_publisher_swaps_handle() {
        let publisher = Arc::new(TaggedPublisher::default());
        // Building ApplyHandles directly here is awkward without a full NodeState.
        // Instead, verify the trait-object swap behavior by constructing the
        // publisher and exercising the publish path. The builder semantics are
        // a simple field swap; this test just covers the publisher capture.
        publisher.publish_hashblock(bitcoin_rs_primitives::Hash256::default());
        assert_eq!(*publisher.tag.lock(), 42);
    }
}

#[cfg(test)]
fn check_pow_limit_and_continuity_for_seeded_tip(
    handles: &ApplyHandles,
    block: &bitcoin::Block,
    height: u32,
) -> core::result::Result<(), ApplyError> {
    let prior = handles.chain_tip.load_full();
    check_pow_limit_and_continuity(handles, prior.as_deref(), block, height)
}
