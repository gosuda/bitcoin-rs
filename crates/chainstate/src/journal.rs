//! Maps block changes into journal records and replays authenticated records at boot.
//!
//! Creates and BIP30 overwrites precede spends, matching the UTXO commit order.
//! Same-block spends are already netted out by the UTXO owner. Each remaining
//! spend requires its full undo preimage; duplicate and unmatched restores fail.
//! Replay validates header identity and live-coin preimages before committing.

use bitcoin_rs_chain::BlockTree;
use bitcoin_rs_chain::ChainTxCount;
use bitcoin_rs_chain::NodeStatus;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_primitives::Header;
use bitcoin_rs_storage::chainstate_journal::Coin;
use bitcoin_rs_storage::chainstate_journal::JournalRecord;
use bitcoin_rs_storage::chainstate_journal::JournalReplayBase;
use bitcoin_rs_storage::chainstate_journal::JournalReplayError;
use bitcoin_rs_storage::chainstate_journal::Mutation;
use bitcoin_rs_storage::chainstate_journal::replay_committed_range;
use bitcoin_rs_utxo::BlockChanges;
use bitcoin_rs_utxo::UtxoAdd;
use bitcoin_rs_utxo::UtxoSet;
use hashbrown::HashMap;
use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum JournalDeltaError {
    /// A spend has no full-coin undo preimage.
    #[error("journal spend {0:?} has no undo coin")]
    MissingSpend(bitcoin_rs_primitives::OutPoint),
    /// More than one undo restore named the same outpoint.
    #[error("journal undo restores duplicate outpoint {0:?}")]
    DuplicateRestore(bitcoin_rs_primitives::OutPoint),
    /// An undo restore matched neither an add nor a spend.
    #[error("journal undo restore {0:?} matches no block mutation")]
    UnmatchedRestore(bitcoin_rs_primitives::OutPoint),
}

/// Extracts the ordered journal mutations for one fully applied block.
///
/// `undo_coins` supplies the full preimage of each spent or overwritten
/// outpoint. Records are matched by outpoint, not by input order. Creates and
/// overwrites precede spends; same-block spends are already netted out.
pub(crate) fn mutations_for_block(
    changes: &BlockChanges<&'_ bitcoin_rs_primitives::TxOut>,
    undo_coins: impl IntoIterator<Item = Coin>,
) -> Result<Vec<Mutation>, JournalDeltaError> {
    let mut restores = HashMap::new();
    for coin in undo_coins {
        let outpoint = coin.outpoint;
        if restores.insert(outpoint, coin).is_some() {
            return Err(JournalDeltaError::DuplicateRestore(outpoint));
        }
    }
    let mut mutations = Vec::with_capacity(changes.add_count() + changes.remove_count());
    for add in changes.adds() {
        let new_coin = Coin {
            outpoint: add.outpoint,
            txout: add.txout.clone(),
            height: add.height,
            coinbase: add.coinbase,
        };
        match restores.remove(&add.outpoint) {
            Some(old_coin) => mutations.push(Mutation::Overwrite { old_coin, new_coin }),
            None => mutations.push(Mutation::Create { coin: new_coin }),
        }
    }
    for outpoint in changes.spent_outpoints() {
        let coin = restores
            .remove(outpoint)
            .ok_or(JournalDeltaError::MissingSpend(*outpoint))?;
        mutations.push(Mutation::Spend { coin });
    }
    if let Some((outpoint, _)) = restores.into_iter().next() {
        return Err(JournalDeltaError::UnmatchedRestore(outpoint));
    }
    Ok(mutations)
}

/// State reconstructed by a successful replay.
pub(crate) struct ReplayedState {
    pub tree: BlockTree,
    pub utxo: UtxoSet,
    pub coin_stats: bitcoin_rs_utxo::stats::CoinStats,
    pub applied_tip: bitcoin_rs_chain::TipSnapshot,
    pub chain_tx_count: u64,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn replay_from_journal(
    dir: &cap_std::fs::Dir,
    base_generation: u64,
    tree: BlockTree,
    utxo: UtxoSet,
    coin_stats: bitcoin_rs_utxo::stats::CoinStats,
    base_tip: bitcoin_rs_chain::TipSnapshot,
    base_chain_tx_count: u64,
) -> Result<Box<ReplayedState>, JournalReplayError> {
    let base_tip_hash = base_tip.hash.to_le_bytes();
    let base_tip_height = base_tip.height;
    let mut replay = ReplayAccumulator::new(tree, utxo, coin_stats, base_tip, base_chain_tx_count)?;
    let head = replay_committed_range(
        dir,
        JournalReplayBase {
            generation: base_generation,
            height: base_tip_height,
            block_hash: base_tip_hash,
            chain_tx_count: base_chain_tx_count,
        },
        |record| replay.apply(record),
    )?;
    let state = replay.finish();
    validate_replayed_head(&state, head.height, head.block_hash)?;
    if state.chain_tx_count != head.chain_tx_count {
        return Err(JournalReplayError::CommittedRangeInvalid(
            "chain transaction count does not match head marker".to_owned(),
        ));
    }
    Ok(Box::new(state))
}

fn validate_replayed_head(
    state: &ReplayedState,
    height: u32,
    block_hash: [u8; 32],
) -> Result<(), JournalReplayError> {
    if state.applied_tip.height != height || state.applied_tip.hash.to_le_bytes() != block_hash {
        return Err(JournalReplayError::CommittedRangeInvalid(
            "replayed tip identity does not match head marker".to_owned(),
        ));
    }
    Ok(())
}

/// Applies ordered records above a restored checkpoint state.
///
/// Headers first regenerate valid `NodeId`s and chainwork. Mutations then pass
/// through the same `UtxoSet` commit surface as live apply, with a listener
/// seeded from the checkpoint `CoinStats`.
struct ReplayAccumulator {
    tree: BlockTree,
    utxo: UtxoSet,
    coin_stats: bitcoin_rs_utxo::stats::CoinStatsListener,
    applied_tip: bitcoin_rs_chain::TipSnapshot,
    chain_tx_count: u64,
}

impl ReplayAccumulator {
    fn new(
        tree: BlockTree,
        mut utxo: UtxoSet,
        initial_coin_stats: bitcoin_rs_utxo::stats::CoinStats,
        base_tip: bitcoin_rs_chain::TipSnapshot,
        base_chain_tx_count: u64,
    ) -> Result<Self, JournalReplayError> {
        let base_node = tree.node(base_tip.tip_id).map_err(|error| {
            JournalReplayError::HeaderRebuildRejected(format!(
                "checkpoint tip node is unavailable: {error}"
            ))
        })?;
        if base_node.height != base_tip.height
            || base_node.hash != base_tip.hash
            || base_node.chainwork != base_tip.chainwork
        {
            return Err(JournalReplayError::HeaderRebuildRejected(
                "checkpoint tip snapshot does not match its tree node".to_owned(),
            ));
        }
        let coin_stats = bitcoin_rs_utxo::stats::CoinStatsListener::new(initial_coin_stats);
        utxo.set_listener(Box::new(coin_stats.clone()));
        Ok(Self {
            tree,
            utxo,
            coin_stats,
            applied_tip: base_tip,
            chain_tx_count: base_chain_tx_count,
        })
    }

    fn apply(&mut self, record: &JournalRecord) -> Result<(), JournalReplayError> {
        // `0` is the codebase's unknown-count sentinel: a checkpoint whose
        // count is legacy/overflow-unknown keeps replaying the durable suffix
        // with the count still unknown rather than being refused outright.
        self.chain_tx_count = if self.chain_tx_count == 0 {
            0
        } else {
            self.chain_tx_count
                .checked_add(record.block_tx_count)
                .ok_or_else(|| {
                    JournalReplayError::CommittedRangeInvalid(
                        "chain transaction count overflow".to_owned(),
                    )
                })?
        };
        self.applied_tip = insert_replayed_header(
            &mut self.tree,
            record,
            self.applied_tip.hash.to_le_bytes(),
            self.chain_tx_count,
        )?;
        apply_record_mutations(&self.utxo, record)?;
        advance_coin_stats(&self.coin_stats, record)?;
        Ok(())
    }

    fn finish(self) -> ReplayedState {
        ReplayedState {
            tree: self.tree,
            utxo: self.utxo,
            coin_stats: self.coin_stats.snapshot(),
            applied_tip: self.applied_tip,
            chain_tx_count: self.chain_tx_count,
        }
    }
}

#[cfg(test)]
#[allow(clippy::needless_pass_by_value)]
fn replay_records(
    records: Vec<JournalRecord>,
    tree: BlockTree,
    utxo: UtxoSet,
    initial_coin_stats: bitcoin_rs_utxo::stats::CoinStats,
    base_tip: bitcoin_rs_chain::TipSnapshot,
    base_chain_tx_count: u64,
) -> Result<ReplayedState, JournalReplayError> {
    let mut replay = ReplayAccumulator::new(
        tree,
        utxo,
        initial_coin_stats,
        base_tip,
        base_chain_tx_count,
    )?;
    for record in &records {
        replay.apply(record)?;
    }
    Ok(replay.finish())
}

fn insert_replayed_header(
    tree: &mut BlockTree,
    record: &JournalRecord,
    expected_prev: [u8; 32],
    chain_tx_count: u64,
) -> Result<bitcoin_rs_chain::TipSnapshot, JournalReplayError> {
    let header = Header::consensus_decode(&record.raw_header[..]).map_err(|error| {
        JournalReplayError::HeaderRebuildRejected(format!("height {}: {error}", record.height))
    })?;
    if expected_prev != record.prev_hash
        || header.prev_blockhash.0.to_le_bytes() != record.prev_hash
        || header.compute_hash().0.to_le_bytes() != record.block_hash
    {
        return Err(JournalReplayError::CommittedRangeInvalid(format!(
            "record {} header identity does not match its chain fields",
            record.height
        )));
    }
    let parent = tree
        .lookup(Hash256::from_le_bytes(&expected_prev))
        .ok_or_else(|| {
            JournalReplayError::HeaderRebuildRejected(format!(
                "height {}: parent {} missing from checkpoint tree",
                record.height,
                bitcoin_rs_storage::checkpoint::hex_encode(&record.prev_hash)
            ))
        })?;
    let node_id = tree
        .insert_node(Some(parent), header, NodeStatus::HeaderValid)
        .map_err(|error| {
            JournalReplayError::HeaderRebuildRejected(format!("height {}: {error}", record.height))
        })?;
    tree.restore_chain_tx_count(node_id, ChainTxCount::from_wire(chain_tx_count))
        .map_err(|error| {
            JournalReplayError::HeaderRebuildRejected(format!("height {}: {error}", record.height))
        })?;
    let node = tree.node(node_id).map_err(|error| {
        JournalReplayError::HeaderRebuildRejected(format!("height {}: {error}", record.height))
    })?;
    if node.height != record.height || node.hash.to_le_bytes() != record.block_hash {
        return Err(JournalReplayError::HeaderRebuildRejected(format!(
            "height {}: rebuilt node identity mismatch",
            record.height
        )));
    }
    Ok(bitcoin_rs_chain::TipSnapshot {
        tip_id: node_id,
        height: node.height,
        chainwork: node.chainwork,
        hash: node.hash,
    })
}

fn apply_record_mutations(
    utxo: &UtxoSet,
    record: &JournalRecord,
) -> Result<(), JournalReplayError> {
    let mut changes = BlockChanges::with_capacity(record.mutations.len(), record.mutations.len());
    for mutation in &record.mutations {
        match mutation {
            Mutation::Create { coin } => {
                if utxo.get_entry(&coin.outpoint).is_some() {
                    return Err(JournalReplayError::CommittedRangeInvalid(format!(
                        "create at height {} overwrites a live coin",
                        record.height
                    )));
                }
                changes.add(UtxoAdd::new(
                    coin.outpoint,
                    &coin.txout,
                    coin.coinbase,
                    coin.height,
                ));
            }
            Mutation::Spend { coin } => {
                require_live_coin(utxo, coin, record.height, "spend")?;
                changes.remove(coin.outpoint);
            }
            Mutation::Overwrite { old_coin, new_coin } => {
                require_live_coin(utxo, old_coin, record.height, "overwrite")?;
                if old_coin.outpoint != new_coin.outpoint {
                    return Err(JournalReplayError::CommittedRangeInvalid(format!(
                        "overwrite at height {} changes its outpoint",
                        record.height
                    )));
                }
                changes.add(UtxoAdd::new(
                    new_coin.outpoint,
                    &new_coin.txout,
                    new_coin.coinbase,
                    new_coin.height,
                ));
            }
        }
    }
    utxo.commit_block(&changes, &Hash256::from_le_bytes(&record.block_hash))
        .map_err(|error| {
            JournalReplayError::CommittedRangeInvalid(format!(
                "height {}: utxo commit failed: {error}",
                record.height
            ))
        })
}

fn advance_coin_stats(
    coin_stats: &bitcoin_rs_utxo::stats::CoinStatsListener,
    record: &JournalRecord,
) -> Result<(), JournalReplayError> {
    let expected_height = i64::from(coin_stats.snapshot().height)
        .checked_add(record.coin_stats_height_delta)
        .and_then(|height| u32::try_from(height).ok())
        .ok_or_else(|| {
            JournalReplayError::CommittedRangeInvalid(format!(
                "height {}: invalid CoinStats height delta {}",
                record.height, record.coin_stats_height_delta
            ))
        })?;
    if expected_height != record.height {
        return Err(JournalReplayError::CommittedRangeInvalid(format!(
            "height {}: CoinStats delta reaches {expected_height}",
            record.height
        )));
    }
    coin_stats.finish_block(record.height, record.block_tx_count);
    Ok(())
}

fn require_live_coin(
    utxo: &UtxoSet,
    coin: &Coin,
    record_height: u32,
    mutation: &str,
) -> Result<(), JournalReplayError> {
    let Some(live) = utxo.get_entry(&coin.outpoint) else {
        return Err(JournalReplayError::CommittedRangeInvalid(format!(
            "{mutation} at height {record_height} references a missing coin"
        )));
    };
    if live.height != coin.height || live.coinbase != coin.coinbase || live.txout != coin.txout {
        return Err(JournalReplayError::CommittedRangeInvalid(format!(
            "{mutation} at height {record_height} does not match the live coin"
        )));
    }
    Ok(())
}

#[cfg(test)]
#[path = "../tests/unit/chainstate_journal_delta.rs"]
mod delta_tests;

#[cfg(test)]
#[path = "../tests/unit/chainstate_journal_replay.rs"]
mod replay_tests;
