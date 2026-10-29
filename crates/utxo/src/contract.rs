//! The chainstate-facing apply/commit/disconnect contract.

use std::borrow::Borrow;

use bitcoin_rs_primitives::{Block, Hash256, OutPoint, Tx, TxOut, Txid};
use bitcoin_rs_storage::{DisconnectPhase, StorageError, UndoStore};
use hashbrown::HashSet;

use crate::set::{UtxoCoin, UtxoError, UtxoSet};
use crate::stats::{CoinStatsListener, CoinStatsRewindError};
use crate::undo_codec;

pub use crate::undo_codec::{
    UndoCodecError, decode as decode_undo_record, record_size_limit as undo_record_size_limit,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UtxoAdd<T = TxOut> {
    pub outpoint: OutPoint,
    pub txout: T,
    pub coinbase: bool,
    pub height: u32,
}

impl<T> UtxoAdd<T> {
    #[must_use]
    pub const fn new(outpoint: OutPoint, txout: T, coinbase: bool, height: u32) -> Self {
        Self {
            outpoint,
            txout,
            coinbase,
            height,
        }
    }
}

impl<T: Borrow<TxOut>> UtxoAdd<T> {
    pub(crate) fn payload(&self) -> crate::set::BuildPayload<'_> {
        crate::set::BuildPayload {
            outpoint: &self.outpoint,
            vout: self.outpoint.vout,
            txout: self.txout.borrow(),
            coinbase: self.coinbase,
            height: self.height,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockChanges<T = TxOut> {
    adds: Vec<UtxoAdd<T>>,
    removes: Vec<OutPoint>,
}

impl<T> Default for BlockChanges<T> {
    fn default() -> Self {
        Self::with_capacity(0, 0)
    }
}

impl<T> BlockChanges<T> {
    #[must_use]
    pub fn with_capacity(adds: usize, removes: usize) -> Self {
        Self {
            adds: Vec::with_capacity(adds),
            removes: Vec::with_capacity(removes),
        }
    }

    pub fn add(&mut self, add: UtxoAdd<T>) {
        self.adds.push(add);
    }

    pub fn remove(&mut self, outpoint: OutPoint) {
        self.removes.push(outpoint);
    }

    #[must_use]
    pub const fn add_count(&self) -> usize {
        self.adds.len()
    }

    #[must_use]
    pub const fn remove_count(&self) -> usize {
        self.removes.len()
    }

    #[must_use]
    pub fn adds(&self) -> &[UtxoAdd<T>] {
        &self.adds
    }

    #[must_use]
    pub fn spent_outpoints(&self) -> &[OutPoint] {
        &self.removes
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct UndoBatch {
    pub(crate) restores: Vec<UtxoAdd>,
    pub(crate) removes: Vec<OutPoint>,
}

impl UndoBatch {
    #[must_use]
    pub(crate) const fn empty() -> Self {
        Self {
            restores: Vec::new(),
            removes: Vec::new(),
        }
    }

    #[must_use]
    pub fn restores(&self) -> &[UtxoAdd] {
        &self.restores
    }

    #[must_use]
    pub fn removes(&self) -> &[OutPoint] {
        &self.removes
    }

    pub(crate) fn restore(&mut self, add: UtxoAdd) {
        self.restores.push(add);
    }

    pub(crate) fn remove(&mut self, outpoint: OutPoint) {
        self.removes.push(outpoint);
    }

    #[must_use]
    pub(crate) const fn from_parts(restores: Vec<UtxoAdd>, removes: Vec<OutPoint>) -> Self {
        Self { restores, removes }
    }
}

pub struct UndoRecord(Vec<u8>);

impl std::fmt::Debug for UndoRecord {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("UndoRecord").field(&self.0.len()).finish()
    }
}

impl UndoRecord {
    pub(crate) fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Debug)]
pub struct DisconnectReceipt {
    pub restored_parents: Vec<Txid>,
}

pub trait SpentOutputLookup {
    fn entry(&self, outpoint: &OutPoint) -> Option<&UtxoCoin>;
}

/// Where a block's prevouts are read from: the committed set, or a window
/// overlay over blocks prepared but not yet committed.
pub trait OutputSource {
    fn get_entry(&self, outpoint: &OutPoint) -> Option<UtxoCoin>;
}

impl OutputSource for UtxoSet {
    fn get_entry(&self, outpoint: &OutPoint) -> Option<UtxoCoin> {
        Self::get_entry(self, outpoint)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BlockValueTotals {
    pub coinbase_out: u64,
    pub spent_in: u64,
    pub created_out: u64,
}

impl BlockValueTotals {
    #[must_use]
    pub const fn fees(self) -> Option<u64> {
        self.spent_in.checked_sub(self.created_out)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BlockChangeError {
    #[error("block value total overflows the satoshi range")]
    BlockValueOverflow,
    #[error("output count of transaction {txid} exceeds the vout index range")]
    VoutOverflow { txid: Txid },
    #[error("block has {transactions} transactions but {txids} txids were supplied")]
    TxidCountMismatch { transactions: usize, txids: usize },
    #[error("undo record cannot restore spent output {txid}:{vout}")]
    UndoPrevoutMissing { txid: Txid, vout: u32 },
}

#[derive(Debug, thiserror::Error)]
#[expect(missing_docs)]
pub enum UndoLoadError {
    #[error("undo record read: {0}")]
    Read(#[source] StorageError),
    #[error("no undo record for block {hash} at height {height}")]
    Missing { hash: Hash256, height: u32 },
    #[error("undo record for block {hash} is unreadable: {source}")]
    Unreadable {
        hash: Hash256,
        #[source]
        source: UndoCodecError,
    },
}

pub use bitcoin_rs_storage::{BoundedReadError, pruning::HistoryUnavailable};

pub trait BlockUndoSource: Send + Sync {
    /// Reads one complete block/input view without exposing storage mutation.
    fn block_spends(
        &self,
        hash: Hash256,
        expected_applied_hash: Hash256,
    ) -> Result<BlockSpends, BlockSpendsError>;
}

#[derive(Debug)]
pub struct BlockSpends {
    pub block: Block,
    /// Complete input rows (coinbase empty), or the typed reason this body
    /// has no certified retained undo. Partial rows are never returned.
    pub spent: Result<Vec<Vec<UtxoCoin>>, HistoryUnavailable>,
}

#[derive(Debug, thiserror::Error)]
pub enum BlockSpendsError {
    #[error("Block not found")]
    UnknownBlock,
    #[error(transparent)]
    History(#[from] HistoryUnavailable),
    #[error(transparent)]
    Undo(#[from] UndoLoadError),
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error("block body read: {0}")]
    BodyRead(#[source] bitcoin_rs_storage::BoundedReadError),
    #[error(transparent)]
    BoundedRead(#[from] bitcoin_rs_storage::BoundedReadError),
    #[error("inconsistent retained block/undo: {0}")]
    Corrupt(&'static str),
    #[error("chain history changed during the query; retry")]
    Retry,
    #[error("chain history is unavailable while the node is closed for recovery")]
    Closed,
    #[error("block undo query exceeds its read budget")]
    ResourceLimit,
}

pub fn decode_undo_record_for_block(
    bytes: &[u8],
    block: &Block,
) -> Result<UndoBatch, UndoCodecError> {
    let inputs = block
        .txs
        .iter()
        .filter(|tx| !tx.is_coinbase())
        .map(|tx| tx.inputs.len())
        .sum::<usize>();
    let outputs = block.txs.iter().map(|tx| tx.outputs.len()).sum::<usize>();
    undo_codec::decode_bounded(
        bytes,
        block.block_hash().into(),
        inputs.saturating_add(outputs),
        outputs,
    )
}

pub fn block_spent_outputs(
    block: &Block,
    height: u32,
    undo: &UndoBatch,
) -> Result<Vec<Vec<UtxoCoin>>, BlockSpendsError> {
    let restores: hashbrown::HashMap<_, _> = undo
        .restores()
        .iter()
        .map(|coin| (coin.outpoint, coin))
        .collect();
    let mut earlier: hashbrown::HashMap<Txid, (&Tx, bool)> = hashbrown::HashMap::new();
    let mut spent = Vec::with_capacity(block.txs.len());
    for tx in &block.txs {
        let coinbase = tx.is_coinbase();
        let mut inputs = Vec::with_capacity(if coinbase { 0 } else { tx.inputs.len() });
        if !coinbase {
            for input in &tx.inputs {
                let outpoint = input.previous_output;
                let txid = outpoint.txid;
                let vout = outpoint.vout;
                let coin = if let Some((parent, generated)) = earlier.get(&txid) {
                    let txout = usize::try_from(vout)
                        .ok()
                        .and_then(|vout| parent.outputs.get(vout))
                        .ok_or(BlockSpendsError::Corrupt(
                            "same-block prevout index is absent",
                        ))?;
                    UtxoCoin {
                        outpoint,
                        txout: txout.clone(),
                        coinbase: *generated,
                        height,
                    }
                } else {
                    let coin = restores
                        .get(&outpoint)
                        .ok_or(BlockSpendsError::Corrupt("input is absent from block undo"))?;
                    if coin.height >= height {
                        return Err(BlockSpendsError::Corrupt(
                            "external prevout height is not historical",
                        ));
                    }
                    UtxoCoin {
                        outpoint,
                        txout: coin.txout.clone(),
                        coinbase: coin.coinbase,
                        height: coin.height,
                    }
                };
                inputs.push(coin);
            }
        }
        spent.push(inputs);
        earlier.insert(tx.txid(), (tx, coinbase));
    }
    Ok(spent)
}

#[derive(Debug, thiserror::Error)]
#[expect(missing_docs)]
pub enum RollbackError {
    #[error("rollback refused: {0}")]
    Refused(#[source] StorageError),
    #[error("utxo undo: {0}")]
    Utxo(#[source] UtxoError),
    #[error("coinstats rewind: {0}")]
    CoinStats(#[source] CoinStatsRewindError),
    #[error("disconnect marker: {0}")]
    Marker(#[source] StorageError),
}

pub fn commit_block_changes<T: Borrow<TxOut>>(
    set: &UtxoSet,
    changes: &BlockChanges<T>,
    block_hash: &Hash256,
) -> Result<(), UtxoError> {
    set.commit_block(changes, block_hash)
}

/// # Errors [`BlockChangeError::TxidCountMismatch`] when `txids` does not cover every
/// transaction, refused before iterating so no trailing transaction can be silently
/// dropped; [`BlockChangeError::VoutOverflow`] when a transaction carries more outputs
/// than a `u32` vout can index; [`BlockChangeError::BlockValueOverflow`] when value
/// totals overflow; and [`BlockChangeError::UndoPrevoutMissing`] when a spend has no
/// resolved prevout.
///
/// Genesis returns empty mutations.
#[expect(clippy::too_many_arguments)]
pub fn build_block_changes<'a>(
    block: &'a Block,
    height: u32,
    txids: &[Txid],
    same_block_spent: Option<&HashSet<OutPoint>>,
    add_capacity: usize,
    remove_capacity: usize,
    resolved: &impl SpentOutputLookup,
    overwritten: Option<&UtxoSet>,
    max_script_size: usize,
) -> Result<(BlockChanges<&'a TxOut>, UndoBatch, BlockValueTotals), BlockChangeError> {
    if block.txs.len() != txids.len() {
        return Err(BlockChangeError::TxidCountMismatch {
            transactions: block.txs.len(),
            txids: txids.len(),
        });
    }
    if height == 0 {
        return Ok((
            BlockChanges::default(),
            UndoBatch::empty(),
            BlockValueTotals::default(),
        ));
    }

    let net_same_block_spends = same_block_spent.is_some_and(|s| !s.is_empty());
    let mut changes = BlockChanges::with_capacity(add_capacity, remove_capacity);
    let mut undo = UndoBatch::empty();
    let mut totals = BlockValueTotals::default();
    for (tx, txid) in block.txs.iter().zip(txids) {
        let txid = *txid;
        let coinbase = tx.is_coinbase();
        for (vout_idx, txout) in tx.outputs.iter().enumerate() {
            let value = txout.value.to_sat();
            let vout =
                u32::try_from(vout_idx).map_err(|_| BlockChangeError::VoutOverflow { txid })?;
            let outpoint = OutPoint::new(txid, vout);
            let same_block =
                net_same_block_spends && same_block_spent.is_some_and(|s| s.contains(&outpoint));
            if coinbase {
                totals.coinbase_out = totals
                    .coinbase_out
                    .checked_add(value)
                    .ok_or(BlockChangeError::BlockValueOverflow)?;
            } else if !same_block {
                totals.created_out = totals
                    .created_out
                    .checked_add(value)
                    .ok_or(BlockChangeError::BlockValueOverflow)?;
            }
            if same_block
                || txout.script_pubkey.first() == Some(&0x6a)
                || txout.script_pubkey.len() > max_script_size
            {
                continue;
            }
            let replaced = overwritten.and_then(|set| set.get_entry(&outpoint));
            changes.add(UtxoAdd::new(outpoint, txout, coinbase, height));
            match replaced {
                Some(previous) => undo.restore(UtxoAdd::new(
                    outpoint,
                    previous.txout,
                    previous.coinbase,
                    previous.height,
                )),
                None => undo.remove(outpoint),
            }
        }

        if !coinbase {
            for tx_input in &tx.inputs {
                let previous_output = tx_input.previous_output;
                if net_same_block_spends
                    && same_block_spent.is_some_and(|s| s.contains(&previous_output))
                {
                    continue;
                }
                changes.remove(previous_output);
                let spent = resolved.entry(&tx_input.previous_output).ok_or(
                    BlockChangeError::UndoPrevoutMissing {
                        txid: previous_output.txid,
                        vout: previous_output.vout,
                    },
                )?;
                totals.spent_in = totals
                    .spent_in
                    .checked_add(spent.txout.value.to_sat())
                    .ok_or(BlockChangeError::BlockValueOverflow)?;
                undo.restore(UtxoAdd::new(
                    previous_output,
                    spent.txout.clone(),
                    spent.coinbase,
                    spent.height,
                ));
            }
        }
    }
    Ok((changes, undo, totals))
}

pub fn persist_block_undo(
    store: &dyn UndoStore,
    height: u32,
    hash: Hash256,
    undo: &UndoBatch,
) -> Result<UndoRecord, StorageError> {
    let record = undo_codec::encode(undo, hash);
    store.persist_undo(height, hash, &record)?;
    Ok(UndoRecord::new(record))
}

/// # Errors
/// Read failure, absent record, or a record that does not decode as this
/// block's.
pub fn load_block_undo(
    store: &dyn UndoStore,
    height: u32,
    hash: Hash256,
) -> Result<UndoBatch, UndoLoadError> {
    let record = store
        .load_undo(height, hash)
        .map_err(UndoLoadError::Read)?
        .ok_or(UndoLoadError::Missing { hash, height })?;
    undo_codec::decode(&record, hash).map_err(|source| UndoLoadError::Unreadable { hash, source })
}

/// # Errors
/// [`RollbackError::Refused`] before the marker is armed; every other variant
/// after.
pub fn rollback_block(
    store: &dyn UndoStore,
    utxo: &UtxoSet,
    coin_stats: &CoinStatsListener,
    hash: Hash256,
    height: u32,
    parent_height: u32,
    tx_count_delta: u64,
    undo: &UndoBatch,
) -> Result<DisconnectReceipt, RollbackError> {
    if store
        .load_disconnect_marker()
        .map_err(RollbackError::Refused)?
        .is_some_and(|marker| marker.phase == DisconnectPhase::InFlight)
    {
        return Err(RollbackError::Refused(StorageError::InvalidOperation(
            "a disconnect is already in flight",
        )));
    }
    store
        .arm_disconnect(height, hash)
        .map_err(RollbackError::Refused)?;
    rollback_block_recovery(
        utxo,
        coin_stats,
        height,
        parent_height,
        tx_count_delta,
        undo,
    )?;
    store
        .complete_disconnect(height, hash)
        .map_err(RollbackError::Marker)?;
    Ok(DisconnectReceipt {
        restored_parents: undo
            .restores()
            .iter()
            .map(|restored| restored.outpoint.txid)
            .collect(),
    })
}

/// # Errors
/// `RollbackError::Utxo` or `RollbackError::CoinStats`. Never `Refused`:
/// the arming guard does not apply to a marker recovery already owns.
pub fn rollback_block_recovery(
    utxo: &UtxoSet,
    coin_stats: &CoinStatsListener,
    height: u32,
    parent_height: u32,
    tx_count_delta: u64,
    undo: &UndoBatch,
) -> Result<(), RollbackError> {
    coin_stats
        .check_rewind(height, tx_count_delta)
        .map_err(RollbackError::CoinStats)?;
    utxo.undo_block(undo).map_err(RollbackError::Utxo)?;
    coin_stats
        .rewind_block(height, parent_height, tx_count_delta)
        .map_err(RollbackError::CoinStats)
}

#[cfg(test)]
mod tests;
