//! Shared node state aggregating subsystem handles.
//!
//! V1 keeps this deliberately minimal: it owns the resolved [`Config`], the
//! data-directory path, the open chainstate storage backend, and the replay log
//! used by [`crate::crash_recovery`]. Subsystem wiring (chain / utxo / mempool
//! / index / p2p / rpc / electrum) parks here as the integration point matures.

use arc_swap::{ArcSwap, ArcSwapOption};
use bitcoin::{Transaction, Txid};
use bitcoin_rs_chain::TipSnapshot;
use bitcoin_rs_rpc::{BlockRecord, NetworkState};
use compact_str::CompactString;
use core::fmt;
#[allow(unused_imports)]
use crossbeam_channel::Receiver;
use hashbrown::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context as _, Result, bail};
use bitcoin_rs_mempool::{Mempool, MempoolLimits};
use bitcoin_rs_primitives::OutPoint;
use bitcoin_rs_utxo::{BlockChanges, UtxoAdd, UtxoSet};
use parking_lot::{Mutex, RwLock};

use crate::Config;

/// Number of blocks after a coinbase that its outputs become spendable.
/// Consensus rule since Bitcoin v0.3.1; universal across networks.
const COINBASE_MATURITY: u32 = 100;

/// Errors produced when applying a block to the node state.
#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    /// The block's previous header hash does not match the current tip's hash.
    #[error("prev hash mismatch: tip {tip}, block prev {prev}")]
    PrevHashMismatch {
        /// Current tip header hash, big-endian hex.
        tip: bitcoin_rs_primitives::Hash256,
        /// Block's previous header hash, big-endian hex.
        prev: bitcoin_rs_primitives::Hash256,
    },
    /// Height arithmetic overflowed `u32::MAX`.
    #[error("height overflow at tip {0}")]
    HeightOverflow(u32),
    /// The block header hash does not satisfy its declared proof-of-work target.
    #[error("proof-of-work: header hash {hash} exceeds declared target")]
    ProofOfWork {
        /// Block header hash, big-endian display.
        hash: bitcoin_rs_primitives::Hash256,
    },
    /// Declared target exceeds the network's proof-of-work limit.
    #[error("declared target exceeds network max_target")]
    TargetAboveLimit,
    /// Declared `nBits` does not match the parent block's `nBits` at a non-retarget height.
    #[error(
        "nBits {actual:08x} does not match parent {expected:08x} at non-retarget height {height}"
    )]
    NbitsNonRetargetMismatch {
        /// This block's `nBits`.
        actual: u32,
        /// Parent block's `nBits`.
        expected: u32,
        /// Block height.
        height: u32,
    },
    /// Consensus validation rejected the block.
    #[error("consensus: {0}")]
    Consensus(#[from] bitcoin_rs_consensus::ConsensusError),
    /// Block-tree insertion rejected the header.
    #[error("chain: {0}")]
    Chain(#[from] bitcoin_rs_chain::ChainError),
    /// UTXO commit failed during block apply.
    #[error("utxo commit: {0}")]
    UtxoCommit(#[from] bitcoin_rs_utxo::UtxoError),
}

enum NodeStorage {
    #[cfg(feature = "rocksdb")]
    RocksDb(bitcoin_rs_storage::RocksDbStore),
    #[cfg(feature = "fjall")]
    Fjall(bitcoin_rs_storage::FjallStore),
    #[cfg(feature = "redb")]
    Redb(bitcoin_rs_storage::RedbStore),
    #[cfg(feature = "mdbx")]
    Mdbx(bitcoin_rs_storage::MdbxStore),
}

impl NodeStorage {
    fn open(config: &Config) -> Result<Self> {
        let chainstate_dir = config.data_dir.join("chainstate");
        std::fs::create_dir_all(&chainstate_dir)
            .with_context(|| format!("create chainstate_dir {}", chainstate_dir.display()))?;

        match config.storage_backend.as_str() {
            #[cfg(feature = "rocksdb")]
            "rocksdb" => Ok(Self::RocksDb(
                bitcoin_rs_storage::RocksDbStore::open(&chainstate_dir)
                    .map_err(anyhow::Error::new)?,
            )),
            #[cfg(feature = "fjall")]
            "fjall" => Ok(Self::Fjall(
                bitcoin_rs_storage::FjallStore::open(&chainstate_dir)
                    .map_err(anyhow::Error::new)?,
            )),
            #[cfg(feature = "redb")]
            "redb" => Ok(Self::Redb(
                bitcoin_rs_storage::RedbStore::open(&chainstate_dir).map_err(anyhow::Error::new)?,
            )),
            #[cfg(feature = "mdbx")]
            "mdbx" => Ok(Self::Mdbx(
                bitcoin_rs_storage::MdbxStore::open(&chainstate_dir).map_err(anyhow::Error::new)?,
            )),
            other => bail!(
                "unsupported storage backend: {other} (compiled features = {CompiledStorageFeatures})"
            ),
        }
    }

    const fn kind(&self) -> &'static str {
        match self {
            #[cfg(feature = "rocksdb")]
            Self::RocksDb(store) => {
                let _ = store;
                "rocksdb"
            }
            #[cfg(feature = "fjall")]
            Self::Fjall(store) => {
                let _ = store;
                "fjall"
            }
            #[cfg(feature = "redb")]
            Self::Redb(store) => {
                let _ = store;
                "redb"
            }
            #[cfg(feature = "mdbx")]
            Self::Mdbx(store) => {
                let _ = store;
                "mdbx"
            }
        }
    }
}

const COMPILED_STORAGE_FEATURES: &[&str] = &[
    #[cfg(feature = "rocksdb")]
    "rocksdb",
    #[cfg(feature = "fjall")]
    "fjall",
    #[cfg(feature = "redb")]
    "redb",
    #[cfg(feature = "mdbx")]
    "mdbx",
];

struct CompiledStorageFeatures;

impl fmt::Display for CompiledStorageFeatures {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Some((first, rest)) = COMPILED_STORAGE_FEATURES.split_first() else {
            return f.write_str("none");
        };

        f.write_str(first)?;
        for feature in rest {
            f.write_str(",")?;
            f.write_str(feature)?;
        }
        Ok(())
    }
}

/// Aggregate handle to a running node.
pub struct NodeState {
    config: Config,
    data_dir: PathBuf,
    storage: NodeStorage,
    utxo: Arc<UtxoSet>,
    mempool: Arc<RwLock<Mempool>>,
    chain_tip: Arc<ArcSwapOption<TipSnapshot>>,
    block_tree: Arc<RwLock<bitcoin_rs_chain::BlockTree>>,
    blocks: Arc<RwLock<Vec<BlockRecord>>>,
    transactions: Arc<RwLock<HashMap<Txid, Transaction>>>,
    network: Arc<RwLock<NetworkState>>,
    peers: Arc<RwLock<Vec<bitcoin_rs_p2p::PeerInfo>>>,
    mining_template_id: Arc<ArcSwap<CompactString>>,
    replayed: Mutex<Vec<u32>>,
}

impl NodeState {
    /// Opens (or creates) the node's data directory and configured storage
    /// backend.
    #[allow(clippy::arc_with_non_send_sync)]
    pub fn open(config: Config) -> Result<Self> {
        std::fs::create_dir_all(&config.data_dir)
            .with_context(|| format!("create data_dir {}", config.data_dir.display()))?;
        let storage = NodeStorage::open(&config)?;
        let utxo = Arc::new(UtxoSet::new());
        let mempool = Arc::new(RwLock::new(Mempool::new(MempoolLimits::default())));
        let block_tree = Arc::new(RwLock::new(bitcoin_rs_chain::BlockTree::new()));
        let chain_tip = block_tree.read().tip_handle();
        let blocks = Arc::new(RwLock::new(Vec::new()));
        let transactions = Arc::new(RwLock::new(HashMap::new()));
        let network = Arc::new(RwLock::new(NetworkState::default()));
        let peers = Arc::new(RwLock::new(Vec::new()));
        let mining_template_id = Arc::new(ArcSwap::from_pointee(CompactString::new("0")));
        tracing::info!(
            backend = storage.kind(),
            chainstate_dir = %config.data_dir.join("chainstate").display(),
            "opened storage backend"
        );
        let data_dir = config.data_dir.clone();
        Ok(Self {
            config,
            data_dir,
            storage,
            utxo,
            mempool,
            chain_tip,
            block_tree,
            blocks,
            transactions,
            network,
            peers,
            mining_template_id,
            replayed: Mutex::new(Vec::new()),
        })
    }

    /// Returns a borrow of the resolved configuration.
    #[must_use]
    pub const fn config(&self) -> &Config {
        &self.config
    }

    /// Returns the node's data directory.
    #[must_use]
    pub fn data_dir(&self) -> &Path {
        &self.data_dir
    }

    /// Returns the configured storage backend that was opened.
    #[must_use]
    pub const fn storage_kind(&self) -> &'static str {
        self.storage.kind()
    }

    /// Returns the shared UTXO set handle.
    #[must_use]
    pub fn utxo(&self) -> Arc<UtxoSet> {
        Arc::clone(&self.utxo)
    }

    /// Returns the shared mempool handle.
    #[must_use]
    pub fn mempool(&self) -> Arc<RwLock<Mempool>> {
        Arc::clone(&self.mempool)
    }

    /// Returns the shared best-chain tip handle.
    #[must_use]
    pub fn chain_tip(&self) -> Arc<ArcSwapOption<TipSnapshot>> {
        Arc::clone(&self.chain_tip)
    }

    /// Returns the shared block-tree handle.
    #[must_use]
    pub fn block_tree(&self) -> Arc<RwLock<bitcoin_rs_chain::BlockTree>> {
        Arc::clone(&self.block_tree)
    }

    /// Returns the shared block-records handle exposed to RPC handlers.
    #[must_use]
    pub fn blocks(&self) -> Arc<RwLock<Vec<BlockRecord>>> {
        Arc::clone(&self.blocks)
    }

    /// Returns the shared txid → transaction map exposed to RPC handlers.
    #[must_use]
    pub fn transactions(&self) -> Arc<RwLock<HashMap<Txid, Transaction>>> {
        Arc::clone(&self.transactions)
    }

    /// Returns the shared network-counters handle exposed to RPC handlers.
    #[must_use]
    pub fn network(&self) -> Arc<RwLock<NetworkState>> {
        Arc::clone(&self.network)
    }

    /// Returns the shared registry of currently-handshook peers.
    #[must_use]
    pub fn peers(&self) -> Arc<RwLock<Vec<bitcoin_rs_p2p::PeerInfo>>> {
        Arc::clone(&self.peers)
    }

    /// Returns the shared getblocktemplate long-poll id.
    #[must_use]
    pub fn mining_template_id(&self) -> Arc<ArcSwap<CompactString>> {
        Arc::clone(&self.mining_template_id)
    }

    /// Heights walked by the most recent crash-recovery replay.
    #[must_use]
    pub fn replayed_heights(&self) -> Vec<u32> {
        self.replayed.lock().clone()
    }

    /// Records a height in the in-memory replay log.
    pub(crate) fn push_replayed(&self, height: u32) {
        self.replayed.lock().push(height);
    }

    /// Test helper: writes the recovery metadata as if a block at `height`
    /// had just been fully committed. Real block commits flow through the
    /// `crates/utxo` listener; this helper exists so crash-recovery tests
    /// can simulate a chain without bringing up the full subsystem stack.
    pub fn record_synthetic_block_for_recovery(&self, height: u32) -> Result<()> {
        let meta = crate::crash_recovery::Meta {
            height,
            last_committed_height: height,
        };
        crate::crash_recovery::write_meta(self, &meta)
    }

    /// Applies `block` as the next tip after non-contextual consensus checks.
    ///
    /// This is the v1 contract: the block hash is taken from the decoded
    /// header, the new height is `current_tip.height + 1` (or zero when no
    /// tip is published yet), and contextual BIP30 / BIP34 checks run against
    /// the resolved height. The block is stored in `blocks` for RPC consumers.
    /// Broader soft-fork checks, BIP9 deployment state, and reorg planning
    /// land in follow-up turns.
    ///
    /// Returns the `TipSnapshot` published by the `BlockTree`.
    pub fn apply_block(
        &self,
        block: &bitcoin::Block,
    ) -> core::result::Result<bitcoin_rs_chain::TipSnapshot, ApplyError> {
        use bitcoin::hashes::Hash as _;

        let block_hash =
            bitcoin_rs_primitives::Hash256::from_le_bytes(block.block_hash().as_byte_array());
        let prev_hash = bitcoin_rs_primitives::Hash256::from_le_bytes(
            block.header.prev_blockhash.as_byte_array(),
        );
        let prior = self.chain_tip.load_full();
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
        let declared_target = block.header.target();
        if block.header.validate_pow(declared_target).is_err() {
            return Err(ApplyError::ProofOfWork { hash: block_hash });
        }

        let prev_tip_state = match prior.as_deref() {
            Some(tip) => bitcoin_rs_consensus::rust_path::TipState {
                height: Some(tip.height),
                block_hash: None,
                median_time_past: 0,
            },
            None => bitcoin_rs_consensus::rust_path::TipState {
                height: None,
                block_hash: None,
                median_time_past: 0,
            },
        };
        bitcoin_rs_consensus::verify_block::verify_block_rules_borrowed(block, &prev_tip_state)?;
        // Contextual consensus checks (BIP30 + BIP34) using the resolved height.
        self.check_bip30_and_bip34(block, height)?;
        // PoW limit + DAA non-retarget continuity.
        self.check_pow_limit_and_continuity(block, height)?;

        self.verify_block_transactions(block, height)?;

        self.check_coinbase_maturity(block, height)?;

        let changes = build_utxo_changes(block, height)?;
        self.utxo
            .commit_block(&changes, &block_hash)
            .map_err(ApplyError::UtxoCommit)?;

        // Persist the header into the in-memory block tree after validation and
        // UTXO commit have succeeded. `BlockTree` publishes the canonical
        // best-tip snapshot as part of `insert_header`.
        self.insert_active_header(block)?;

        let tip = self
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
        self.blocks
            .write()
            .push(bitcoin_rs_rpc::BlockRecord::from_block(height, block));
        for tx in &block.txdata {
            let txid = tx.compute_txid();
            let evicted_count = self.mempool.write().remove_by_txid(&txid).len();
            tracing::debug!(%txid, evicted_count, "apply_block: evicted transaction from mempool");
            self.transactions.write().insert(txid, tx.clone());
        }
        tracing::info!(
            height,
            %block_hash,
            tx_count = block.txdata.len(),
            utxo_adds = changes.add_count(),
            utxo_removes = changes.remove_count(),
            "apply_block: chain advance committed"
        );
        Ok(tip)
    }

    fn insert_active_header(&self, block: &bitcoin::Block) -> core::result::Result<(), ApplyError> {
        self.block_tree
            .write()
            .insert_header(block.header, bitcoin_rs_chain::node::NodeStatus::Active)?;
        Ok(())
    }

    fn verify_block_transactions(
        &self,
        block: &bitcoin::Block,
        height: u32,
    ) -> core::result::Result<(), ApplyError> {
        // Per-tx script verification. The view borrows the UTXO set as it
        // stood BEFORE this block's outputs were committed — inputs in this
        // block can only spend outputs from earlier blocks. Coinbase txs
        // early-return inside `verify_transaction`.
        let flags = compute_verify_flags(self.config.network, height);
        let view = crate::utxo_view::UtxoSetView::new(Arc::clone(&self.utxo));
        for tx in &block.txdata {
            if tx.is_coinbase() {
                continue;
            }
            // TODO(perf): drop the per-tx clone once `verify_transaction_borrowed(&bitcoin::Transaction, ...)`
            // lands on `bitcoin_rs_consensus`. See DEVIATIONS §7.
            let wrapped = bitcoin_rs_primitives::Tx(tx.clone());
            bitcoin_rs_consensus::verify_transaction(&wrapped, &view, height, flags)?;
        }
        Ok(())
    }

    pub(crate) fn check_coinbase_maturity(
        &self,
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
                let Some(entry) = self.utxo.get_entry(&prev_outpoint) else {
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

    fn check_bip30_and_bip34(
        &self,
        block: &bitcoin::Block,
        height: u32,
    ) -> core::result::Result<(), ApplyError> {
        use bitcoin::hashes::Hash as _;

        // BIP30: best-effort — reject if any tx in the block re-uses an
        // outpoint that the UTXO set still considers live. The first vout
        // (index 0) lookup catches the common-case duplicate-coinbase
        // scenario that BIP30 was written to address. A proper any-vout
        // sweep needs an accessor on `UtxoSet` that walks all live outputs
        // for a given txid; see follow-up.
        let mut has_duplicate = false;
        for tx in &block.txdata {
            let txid = tx.compute_txid();
            let outpoint = bitcoin_rs_primitives::OutPoint::new(
                bitcoin_rs_primitives::Hash256::from_le_bytes(txid.as_byte_array()),
                0,
            );
            if self.utxo.get(&outpoint).is_some() {
                has_duplicate = true;
                break;
            }
        }
        bitcoin_rs_consensus::bip30::check_bip30(height, has_duplicate)?;

        // BIP34: when active for this network at `height`, the coinbase
        // scriptSig must start with the minimally-encoded height.
        if self.config.network.is_bip34_active(height) {
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
            bitcoin_rs_consensus::bip34::check_bip34(
                height,
                coinbase_input.script_sig.as_script(),
            )?;
        }

        Ok(())
    }

    fn check_pow_limit_and_continuity(
        &self,
        block: &bitcoin::Block,
        height: u32,
    ) -> core::result::Result<(), ApplyError> {
        // PoW limit: declared target must not exceed network max_target.
        let target_be = block.header.target().to_be_bytes();
        let declared = bitcoin_rs_chain::node::ChainWork::from_be_bytes(target_be);
        let max_target = self.config.network.max_target();
        if declared > max_target {
            return Err(ApplyError::TargetAboveLimit);
        }

        // nBits continuity: at non-retarget heights, must match the parent.
        // Genesis (height 0) has no parent; skip.
        if height == 0 {
            return Ok(());
        }
        let retarget_interval = self.config.network.retarget_interval();
        let is_retarget = retarget_interval != 0 && height.is_multiple_of(retarget_interval);
        if is_retarget {
            // Retarget heights compute a new target from the last 2016 blocks'
            // timespan; full computation is deferred to a follow-up. For now
            // we already verified `declared <= max_target` above, so we let
            // any retarget-height nBits through.
            return Ok(());
        }

        // Non-retarget: look up the parent header via the BlockTree.
        // The parent is the current chain_tip (which apply_block has already
        // verified equals block.header.prev_blockhash via the prev-hash check
        // upstream).
        let tree = self.block_tree.read();
        let Some(parent_id) = self.chain_tip.load_full().map(|tip| tip.tip_id) else {
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
const fn compute_verify_flags(
    network: bitcoin_rs_primitives::Network,
    height: u32,
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
    if network.is_csv_active(height) {
        flags = flags.union(VerifyFlags::CHECKSEQUENCEVERIFY);
    }
    if network.is_segwit_active(height) {
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
mod tests {
    use super::*;

    #[test]
    fn open_constructs_empty_handles() -> anyhow::Result<()> {
        use tempfile::tempdir;

        let dir = tempdir()?;
        let config = crate::Config {
            data_dir: dir.path().join("node"),
            ..crate::Config::default()
        };

        let state = NodeState::open(config)?;
        let utxo = state.utxo();
        let mempool = state.mempool();

        assert!(
            Arc::strong_count(&utxo) >= 2,
            "caller and NodeState should both hold a strong ref"
        );
        assert!(Arc::strong_count(&mempool) >= 2);
        assert_eq!(mempool.read().len(), 0, "fresh mempool must be empty");

        Ok(())
    }

    #[test]
    fn open_constructs_empty_block_tree() -> anyhow::Result<()> {
        use tempfile::tempdir;

        let dir = tempdir()?;
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config)?;
        let tree = state.block_tree();

        assert!(
            tree.read().is_empty(),
            "freshly opened tree has zero headers"
        );
        Ok(())
    }

    #[test]
    fn open_constructs_empty_peer_registry() -> anyhow::Result<()> {
        use tempfile::tempdir;

        let dir = tempdir()?;
        let mut config = crate::Config::default_for_network(crate::Network::Regtest);
        config.data_dir = dir.path().join("node");
        config.p2p_listen.clear();
        let state = NodeState::open(config)?;

        assert!(
            state.peers().read().is_empty(),
            "freshly opened registry is empty"
        );
        Ok(())
    }

    #[test]
    fn open_constructs_full_rpc_handle_set() -> anyhow::Result<()> {
        use tempfile::tempdir;

        let dir = tempdir()?;
        let config = crate::Config {
            data_dir: dir.path().join("node"),
            ..crate::Config::default()
        };

        let state = NodeState::open(config)?;
        let chain_tip = state.chain_tip();
        let blocks = state.blocks();
        let transactions = state.transactions();
        let network = state.network();
        let mining_template_id = state.mining_template_id();

        assert!(chain_tip.load().is_none(), "fresh chain tip must be empty");
        assert!(blocks.read().is_empty(), "fresh blocks must be empty");
        assert!(
            transactions.read().is_empty(),
            "fresh transactions must be empty"
        );
        assert_eq!(network.read().connection_count, 0);
        assert_eq!(mining_template_id.load().as_str(), "0");

        Ok(())
    }
}
