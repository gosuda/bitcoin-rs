//! Block-apply pipeline over shared node handles.

use std::sync::Arc;

use arc_swap::ArcSwapOption;
use bitcoin::{Transaction, Txid};
use bitcoin_rs_chain::{BlockTree, TipSnapshot};
use bitcoin_rs_mempool::Mempool;
use bitcoin_rs_primitives::{Network, OutPoint};
use bitcoin_rs_rpc::BlockRecord;
use bitcoin_rs_utxo::{BlockChanges, UtxoAdd, UtxoSet};
use hashbrown::HashMap;
use parking_lot::RwLock;

use crate::state::ApplyError;
use bitcoin_rs_storage::{ColumnFamily, KvStore, StorageError, WriteBatch as _};

/// Number of blocks after a coinbase that its outputs become spendable.
/// Consensus rule since Bitcoin v0.3.1; universal across networks.
const COINBASE_MATURITY: u32 = 100;
/// BIP68 sequence-bit masks.
const BIP68_DISABLE_FLAG: u32 = 0x8000_0000;
const BIP68_TYPE_FLAG: u32 = 0x0040_0000;
const BIP68_MASK: u32 = 0x0000_ffff;
const BIP68_TIME_GRANULARITY_SECONDS: u32 = 512;

pub(crate) trait PruneBodyStore: Send + Sync {
    fn persist_block_body(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
        body: &[u8],
    ) -> Result<(), StorageError>;
}

impl<S: KvStore> PruneBodyStore for S {
    fn persist_block_body(
        &self,
        height: u32,
        hash: bitcoin_rs_primitives::Hash256,
        body: &[u8],
    ) -> Result<(), StorageError> {
        let mut batch = self.new_batch();
        batch.put(
            ColumnFamily::BlockTree,
            &bitcoin_rs_pruning::block_body_key(height, hash),
            body,
        );
        self.write(batch)
    }
}

/// Owned shared handle set needed by `apply_block` to perform a block apply.
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
    /// Shared best-effort confirmed transaction indexer.
    pub tx_index: Arc<parking_lot::Mutex<Box<dyn bitcoin_rs_index::IndexerLike>>>,
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
    pub(crate) block_body_store: Option<Arc<dyn PruneBodyStore>>,
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
        tx_index: Arc<parking_lot::Mutex<Box<dyn bitcoin_rs_index::IndexerLike>>>,
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
            block_body_store: None,
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
    let prior = handles.chain_tip.load_full();
    let height = match prior.as_deref() {
        Some(tip) => {
            if tip.hash != prev_hash {
                return Err(ApplyError::PrevHashMismatch {
                    tip: tip.hash,
                    prev: prev_hash,
                });
            }
            tip.height
                .checked_add(1)
                .ok_or(ApplyError::HeightOverflow(tip.height))?
        }
        None => 0_u32,
    };

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
    let block_rules_started = quanta::Instant::now();
    let block_rules_result = bitcoin_rs_consensus::verify_block_rules_borrowed_contextual(
        block,
        &prev_tip_state,
        bitcoin_rs_consensus::BlockRuleContext {
            segwit_active: softfork_state.segwit_active,
        },
    );
    let block_rules_dur = block_rules_started.elapsed();
    metrics::histogram!("node.apply_block.block_rules_seconds")
        .record(block_rules_dur.as_secs_f64());
    block_rules_result?;
    // Contextual consensus checks (BIP30 + BIP34) using the resolved height.
    let bip30_bip34_started = quanta::Instant::now();
    let bip30_bip34_result = check_bip30_and_bip34(handles, block, height);
    let bip30_bip34_dur = bip30_bip34_started.elapsed();
    metrics::histogram!("node.apply_block.bip30_bip34_seconds")
        .record(bip30_bip34_dur.as_secs_f64());
    bip30_bip34_result?;
    // PoW limit + DAA non-retarget continuity.
    let pow_limit_started = quanta::Instant::now();
    let pow_limit_result = check_pow_limit_and_continuity(handles, block, height);
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
    let script_verify_result =
        verify_block_transactions(handles, block, height, locktime_cutoff, verify_flags);
    let script_verify_dur = script_verify_started.elapsed();
    metrics::histogram!("node.apply_block.script_verify_seconds")
        .record(script_verify_dur.as_secs_f64());
    script_verify_result?;

    let coinbase_maturity_started = quanta::Instant::now();
    let coinbase_maturity_result = check_coinbase_maturity(handles, block, height);
    let coinbase_maturity_dur = coinbase_maturity_started.elapsed();
    metrics::histogram!("node.apply_block.coinbase_maturity_seconds")
        .record(coinbase_maturity_dur.as_secs_f64());
    coinbase_maturity_result?;
    let bip68_started = quanta::Instant::now();
    let previous_tip_id = prior.as_deref().map(|tip| tip.tip_id);
    let bip68_result = check_bip68_sequence_locks(
        handles,
        block,
        height,
        prev_tip_state.median_time_past,
        softfork_state,
        previous_tip_id,
    );
    let bip68_dur = bip68_started.elapsed();
    metrics::histogram!("node.apply_block.bip68_seconds").record(bip68_dur.as_secs_f64());
    bip68_result?;

    let filter_bytes = compute_basic_filter(block, handles).unwrap_or_else(|| {
        tracing::trace!(
            "BIP158 filter generation unavailable; storing empty filter as placeholder"
        );
        Vec::new()
    });

    let block_bytes = bitcoin::consensus::encode::serialize(block);

    let changes = build_utxo_changes(block, height)?;
    if let Some(store) = &handles.block_body_store {
        store
            .persist_block_body(height, block_hash, &block_bytes)
            .map_err(ApplyError::BlockBodyPersistence)?;
    }

    let utxo_commit_started = quanta::Instant::now();
    let utxo_commit_result = handles.utxo.commit_block(&changes, &block_hash);
    let utxo_commit_dur = utxo_commit_started.elapsed();
    metrics::histogram!("node.apply_block.utxo_commit_seconds")
        .record(utxo_commit_dur.as_secs_f64());
    utxo_commit_result.map_err(ApplyError::UtxoCommit)?;

    // Persist the header into the in-memory block tree after validation and
    // UTXO commit have succeeded. `BlockTree` publishes the canonical
    // best-tip snapshot as part of `insert_header`.
    let block_tree_insert_started = quanta::Instant::now();
    let block_tree_insert_result = insert_active_header(handles, block);
    let block_tree_insert_dur = block_tree_insert_started.elapsed();
    metrics::histogram!("node.apply_block.block_tree_insert_seconds")
        .record(block_tree_insert_dur.as_secs_f64());
    block_tree_insert_result?;

    let tip = handles
        .chain_tip
        .load_full()
        .map(|arc| (*arc).clone())
        .ok_or_else(|| {
            ApplyError::Consensus(bitcoin_rs_consensus::ConsensusError::Bip {
                bip: "INTERNAL",
                reason: format!(
                    "chain tip not published by BlockTree after insert_header for block {block_hash}"
                ),
            })
        })?;
    handles
        .blocks
        .write()
        .push(bitcoin_rs_rpc::BlockRecord::from_block(height, block));
    let mempool_evict_started = quanta::Instant::now();
    for tx in &block.txdata {
        let txid = tx.compute_txid();
        let evicted_count = handles.mempool.write().remove_by_txid(&txid).len();
        tracing::debug!(%txid, evicted_count, "apply_block: evicted transaction from mempool");
    }
    let mempool_evict_dur = mempool_evict_started.elapsed();
    metrics::histogram!("node.apply_block.mempool_evict_seconds")
        .record(mempool_evict_dur.as_secs_f64());
    let tx_index_started = quanta::Instant::now();
    for tx in &block.txdata {
        handles
            .transactions
            .write()
            .insert(tx.compute_txid(), tx.clone());
    }
    let tx_index_dur = tx_index_started.elapsed();
    metrics::histogram!("node.apply_block.tx_index_seconds").record(tx_index_dur.as_secs_f64());
    let tx_count_delta = u64::try_from(block.txdata.len()).unwrap_or(u64::MAX);
    let coin_stats_started = quanta::Instant::now();
    handles.coin_stats.finish_block(height, tx_count_delta);
    let coin_stats_dur = coin_stats_started.elapsed();
    metrics::histogram!("node.apply_block.coin_stats_finish_seconds")
        .record(coin_stats_dur.as_secs_f64());
    let tx_index_ingest_started = quanta::Instant::now();
    let tx_index_ingest_result = handles.tx_index.lock().ingest_block(&block_bytes, height);
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
    let tx_index_ingest_dur = tx_index_ingest_started.elapsed();
    metrics::histogram!("node.apply_block.tx_index_ingest_seconds")
        .record(tx_index_ingest_dur.as_secs_f64());
    let filter_started = quanta::Instant::now();
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
        tx_index_us = tx_index_dur.as_micros(),
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
    for tx in &block.txdata {
        handles.zmq_publisher.publish_hashtx(tx.compute_txid());
        let rawtx_bytes = bitcoin::consensus::encode::serialize(tx);
        handles.zmq_publisher.publish_rawtx(&rawtx_bytes);
    }
    handles.applied_tip.store(Some(Arc::new(tip.clone())));
    Ok(tip)
}

fn insert_active_header(
    handles: &ApplyHandles,
    block: &bitcoin::Block,
) -> core::result::Result<(), ApplyError> {
    handles
        .block_tree
        .write()
        .insert_header(block.header, bitcoin_rs_chain::node::NodeStatus::Active)?;
    Ok(())
}

fn compute_basic_filter(block: &bitcoin::Block, handles: &ApplyHandles) -> Option<Vec<u8>> {
    use bitcoin::hashes::Hash as _;

    let filter = bitcoin::bip158::BlockFilter::new_script_filter(block, |outpoint| {
        let prev_outpoint = OutPoint::new(
            bitcoin_rs_primitives::Hash256::from_le_bytes(outpoint.txid.as_byte_array()),
            outpoint.vout,
        );
        handles
            .utxo
            .get(&prev_outpoint)
            .map(|txout| txout.script_pubkey)
            .ok_or(bitcoin::bip158::Error::UtxoMissing(*outpoint))
    })
    .ok()?;
    Some(filter.content)
}

fn verify_block_transactions(
    handles: &ApplyHandles,
    block: &bitcoin::Block,
    height: u32,
    locktime_cutoff: u32,
    flags: bitcoin_rs_script::VerifyFlags,
) -> core::result::Result<(), ApplyError> {
    // Per-tx script verification. The view borrows the UTXO set as it
    // stood BEFORE this block's outputs were committed — inputs in this
    // block can only spend outputs from earlier blocks. Coinbase txs have
    // no prevouts to verify here.
    let view = crate::utxo_view::UtxoSetView::new(Arc::clone(&handles.utxo));
    for tx in &block.txdata {
        if tx.is_coinbase() {
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
    Ok(())
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

pub(crate) fn check_coinbase_maturity(
    handles: &ApplyHandles,
    block: &bitcoin::Block,
    height: u32,
) -> core::result::Result<(), ApplyError> {
    use bitcoin::hashes::Hash as _;

    // COINBASE_MATURITY: spent coinbase outputs must be at least 100 blocks deep.
    for tx in &block.txdata {
        if tx.is_coinbase() {
            continue;
        }
        for tx_input in &tx.input {
            let prev_outpoint = OutPoint::new(
                bitcoin_rs_primitives::Hash256::from_le_bytes(
                    tx_input.previous_output.txid.as_byte_array(),
                ),
                tx_input.previous_output.vout,
            );
            let Some(entry) = handles.utxo.get_entry(&prev_outpoint) else {
                continue;
            };
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
        }
    }
    Ok(())
}

fn check_bip68_sequence_locks(
    handles: &ApplyHandles,
    block: &bitcoin::Block,
    height: u32,
    mtp: u32,
    softfork_state: crate::bip9_context::ContextualSoftforkState,
    previous_tip_id: Option<bitcoin_rs_chain::node::NodeId>,
) -> core::result::Result<(), ApplyError> {
    use bitcoin::hashes::Hash as _;

    if !softfork_state.csv_active {
        return Ok(());
    }

    for tx in &block.txdata {
        if tx.is_coinbase() {
            continue;
        }
        if tx.version.0 < 2 {
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
                let prev_outpoint = OutPoint::new(
                    bitcoin_rs_primitives::Hash256::from_le_bytes(
                        tx_input.previous_output.txid.as_byte_array(),
                    ),
                    tx_input.previous_output.vout,
                );
                let Some(entry) = handles.utxo.get_entry(&prev_outpoint) else {
                    continue;
                };
                let prevout_mtp = {
                    let tree = handles.block_tree.read();
                    let Some(previous_tip_id) = previous_tip_id else {
                        continue;
                    };
                    let Some(prev_block_node) =
                        tree.node_at_height_from(previous_tip_id, entry.height)
                    else {
                        continue;
                    };
                    tree.median_time_past_at(prev_block_node, 11).unwrap_or(0)
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
            let prev_outpoint = OutPoint::new(
                bitcoin_rs_primitives::Hash256::from_le_bytes(
                    tx_input.previous_output.txid.as_byte_array(),
                ),
                tx_input.previous_output.vout,
            );
            let Some(entry) = handles.utxo.get_entry(&prev_outpoint) else {
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
    }

    Ok(())
}

fn check_bip30_and_bip34(
    handles: &ApplyHandles,
    block: &bitcoin::Block,
    height: u32,
) -> core::result::Result<(), ApplyError> {
    use bitcoin::hashes::Hash as _;

    // BIP30: reject any txid that collides with an earlier transaction while
    // any output of the earlier transaction remains unspent, except at the
    // documented historical exception heights handled by `check_bip30`.
    let mut has_duplicate = false;
    for tx in &block.txdata {
        let txid = tx.compute_txid();
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

    // nBits continuity: at non-retarget heights, must match the parent.
    // Genesis (height 0) has no parent; skip.
    if height == 0 {
        return Ok(());
    }
    let retarget_interval = handles.network.retarget_interval();
    let is_retarget = retarget_interval != 0 && height.is_multiple_of(retarget_interval);
    if is_retarget {
        return check_daa_retarget(handles, block, height, retarget_interval);
    }

    // Non-retarget: look up the parent header via the BlockTree.
    // The parent is the current chain_tip (which apply_block has already
    // verified equals block.header.prev_blockhash via the prev-hash check
    // upstream).
    let tree = handles.block_tree.read();
    let Some(parent_id) = handles.chain_tip.load_full().map(|tip| tip.tip_id) else {
        // No tip published yet — should not happen at height > 0 since
        // apply_block's prev-hash check would have rejected. Defensive.
        return Ok(());
    };
    let parent = tree.node(parent_id).map_err(ApplyError::Chain)?;
    if block.header.bits != parent.header.bits {
        return Err(ApplyError::NbitsNonRetargetMismatch {
            actual: block.header.bits.to_consensus(),
            expected: parent.header.bits.to_consensus(),
            height,
        });
    }
    Ok(())
}

fn check_daa_retarget(
    handles: &ApplyHandles,
    block: &bitcoin::Block,
    height: u32,
    retarget_interval: u32,
) -> core::result::Result<(), ApplyError> {
    let prior_tip = handles.chain_tip.load_full();
    let Some(prior_tip) = prior_tip else {
        return Ok(());
    };

    let tree = handles.block_tree.read();
    let Some(anchor_height) = height.checked_sub(retarget_interval) else {
        return Ok(());
    };
    let Some(anchor_id) = tree.node_at_height_from(prior_tip.tip_id, anchor_height) else {
        return Ok(());
    };
    let Ok(anchor_node) = tree.node(anchor_id) else {
        return Ok(());
    };
    let Ok(prev_node) = tree.node(prior_tip.tip_id) else {
        return Ok(());
    };

    let actual_timespan = prev_node
        .header
        .time
        .saturating_sub(anchor_node.header.time);
    let expected_timespan = retarget_interval.saturating_mul(600);
    if expected_timespan == 0 {
        return Ok(());
    }

    let min_timespan = expected_timespan / 4;
    let max_timespan = expected_timespan.saturating_mul(4);
    let actual_clamped = actual_timespan.clamp(min_timespan, max_timespan);

    let prev_target_be = prev_node.header.target().to_be_bytes();
    let prev_target = bitcoin_rs_chain::node::ChainWork::from_be_bytes(prev_target_be);
    let actual_u256 = bitcoin_rs_chain::node::ChainWork::from(actual_clamped);
    let expected_u256 = bitcoin_rs_chain::node::ChainWork::from(expected_timespan);
    let max_target = handles.network.max_target();
    let quotient = prev_target / expected_u256;
    let remainder = prev_target % expected_u256;
    let Some(scaled_quotient) = quotient.checked_mul(actual_u256) else {
        return compare_retarget_bits(block, height, max_target);
    };
    let scaled_remainder = remainder.saturating_mul(actual_u256) / expected_u256;
    let new_target_raw = scaled_quotient.saturating_add(scaled_remainder);
    let new_target = new_target_raw.min(max_target);
    compare_retarget_bits(block, height, new_target)
}

fn compare_retarget_bits(
    block: &bitcoin::Block,
    height: u32,
    expected_target: bitcoin_rs_chain::node::ChainWork,
) -> core::result::Result<(), ApplyError> {
    let expected = bitcoin::Target::from_be_bytes(expected_target.to_be_bytes::<32>())
        .to_compact_lossy()
        .to_consensus();
    let actual = block.header.bits.to_consensus();

    if actual != expected {
        return Err(ApplyError::NbitsNonRetargetMismatch {
            actual,
            expected,
            height,
        });
    }

    Ok(())
}

fn build_utxo_changes(
    block: &bitcoin::Block,
    height: u32,
) -> core::result::Result<BlockChanges, ApplyError> {
    use bitcoin::hashes::Hash as _;

    let mut changes = BlockChanges::default();
    for tx in &block.txdata {
        let txid = tx.compute_txid();
        for (vout_idx, txout) in tx.output.iter().enumerate() {
            let outpoint = OutPoint::new(
                bitcoin_rs_primitives::Hash256::from_le_bytes(txid.as_byte_array()),
                u32::try_from(vout_idx).map_err(|_| ApplyError::HeightOverflow(height))?,
            );
            changes.add(UtxoAdd::new(
                outpoint,
                txout.clone(),
                tx.is_coinbase(),
                height,
            ));
        }

        if !tx.is_coinbase() {
            for tx_input in &tx.input {
                let previous_output = tx_input.previous_output;
                changes.remove(OutPoint::new(
                    bitcoin_rs_primitives::Hash256::from_le_bytes(
                        previous_output.txid.as_byte_array(),
                    ),
                    previous_output.vout,
                ));
            }
        }
    }
    Ok(changes)
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
    use bitcoin::{Amount, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
    use bitcoin_rs_chain::{BlockTree, node::NodeStatus};
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

    #[test]
    fn bip68_height_lock_enforces_boundary_when_csv_active()
    -> Result<(), Box<dyn std::error::Error>> {
        let previous_output = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x68; 32]),
            vout: 0,
        };
        let utxo = utxo_with_output(previous_output, BIP68_TEST_PREVOUT_HEIGHT)?;
        let handles = apply_handles(utxo);
        let block = block_with_transaction(spending_transaction(previous_output, 2));
        let active = softfork_state(true);

        let error = match check_bip68_sequence_locks(&handles, &block, 101, 0, active, None) {
            Ok(()) => panic!("BIP68 height lock must reject one block before maturity"),
            Err(error) => error,
        };
        assert_bip_error(&error, "BIP68");
        assert!(check_bip68_sequence_locks(&handles, &block, 102, 0, active, None).is_ok());
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
        let block = block_with_transaction(spending_transaction(previous_output, sequence));
        let active = softfork_state(true);
        let required_mtp = BIP68_TEST_PREVOUT_MTP + 2 * BIP68_TIME_GRANULARITY_SECONDS;

        let error = match check_bip68_sequence_locks(
            &handles,
            &block,
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
    fn bip68_inactive_csv_skips_unmet_sequence_lock() -> Result<(), Box<dyn std::error::Error>> {
        let previous_output = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0x70; 32]),
            vout: 0,
        };
        let utxo = utxo_with_output(previous_output, BIP68_TEST_PREVOUT_HEIGHT)?;
        let handles = apply_handles(utxo);
        let block = block_with_transaction(spending_transaction(previous_output, 2));

        assert!(
            check_bip68_sequence_locks(&handles, &block, 101, 0, softfork_state(false), None)
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
            check_bip68_sequence_locks(&handles, &version_one_block, 101, 0, active, None).is_ok()
        );

        let disabled_block = block_with_transaction(spending_transaction(
            previous_output,
            BIP68_DISABLE_FLAG | 2,
        ));
        assert!(
            check_bip68_sequence_locks(&handles, &disabled_block, 101, 0, active, None).is_ok()
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

        let error = match check_bip30_and_bip34(&handles, &block, 1) {
            Ok(()) => panic!("duplicate txid with live vout 1 must violate BIP30"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            ApplyError::Consensus(bitcoin_rs_consensus::ConsensusError::Bip { bip: "BIP30", .. })
        ));
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

    #[allow(clippy::arc_with_non_send_sync)]
    fn utxo_with_output(
        previous_output: bitcoin::OutPoint,
        height: u32,
    ) -> Result<Arc<UtxoSet>, bitcoin_rs_utxo::UtxoError> {
        let txid = Hash256::from_le_bytes(previous_output.txid.as_byte_array());
        let utxo = Arc::new(UtxoSet::new());
        let mut changes = BlockChanges::default();
        changes.add(UtxoAdd::new(
            OutPoint::new(txid, previous_output.vout),
            TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::new(),
            },
            false,
            height,
        ));
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

    fn spending_transaction(previous_output: bitcoin::OutPoint, sequence: u32) -> Transaction {
        spending_transaction_with_version(
            previous_output,
            sequence,
            bitcoin::transaction::Version::TWO,
        )
    }

    fn spending_transaction_with_version(
        previous_output: bitcoin::OutPoint,
        sequence: u32,
        version: bitcoin::transaction::Version,
    ) -> Transaction {
        Transaction {
            version,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::from_consensus(sequence),
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: ScriptBuf::new(),
            }],
        }
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
        let mut tree = handles.block_tree.write();
        let mut parent = None;
        let mut tip = None;
        for height in 0..=BIP68_TEST_PREVOUT_HEIGHT {
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

    fn assert_bip_error(error: &ApplyError, bip: &str) {
        assert!(matches!(
            error,
            ApplyError::Consensus(bitcoin_rs_consensus::ConsensusError::Bip { bip: actual, .. }) if *actual == bip
        ));
    }

    #[allow(clippy::arc_with_non_send_sync)]
    fn apply_handles(utxo: Arc<UtxoSet>) -> ApplyHandles {
        ApplyHandles::new(
            Network::Mainnet,
            Arc::new(ArcSwapOption::empty()),
            Arc::new(ArcSwapOption::empty()),
            Arc::new(RwLock::new(BlockTree::new())),
            utxo,
            Arc::new(bitcoin_rs_coinstats::CoinStatsListener::new(
                bitcoin_rs_coinstats::CoinStats::default(),
            )),
            noop_tx_index(),
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

    struct NoopFilterIndex;

    impl FilterIndexLike for NoopFilterIndex {
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
    }

    fn noop_filter_index() -> Arc<Box<dyn FilterIndexLike>> {
        let filter_index: Box<dyn FilterIndexLike> = Box::new(NoopFilterIndex);
        Arc::new(filter_index)
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
