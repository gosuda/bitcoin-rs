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
mod tests {
    use bitcoin_rs_primitives::{
        Amount, Block, BlockHash, CompactTarget, Hash256, Header, LockTime, OutPoint, Script,
        Sequence, Tx, TxIn, TxOut, Txid, Witness,
    };
    use bitcoin_rs_storage::{
        DisconnectMarker, DisconnectPhase, InMemoryUndoStore, StorageError, UndoStore,
    };

    use super::*;
    use crate::stats::CoinStats;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const HEIGHT: u32 = 91;
    const HASH: Hash256 = Hash256::from_le_bytes(&[0x5a; 32]);
    const FUNDED: OutPoint = OutPoint {
        txid: Txid(Hash256::from_le_bytes(&[0x31; 32])),
        vout: 0,
    };
    const CREATED: OutPoint = OutPoint {
        txid: Txid(Hash256::from_le_bytes(&[0x42; 32])),
        vout: 0,
    };

    fn coin(value: u64) -> TxOut {
        TxOut {
            value: Amount::from_sat(value),
            script_pubkey: Script::from_bytes(vec![0x51]),
        }
    }

    #[test]
    fn spent_output_projection_orders_inputs_and_ignores_bip30_restorations() -> TestResult {
        let mut cb = Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: vec![0x01, 0x01].into(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![coin(50)],
        };
        let spend = |previous_output, value| Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output,
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![coin(value)],
        };
        let parent = spend(FUNDED, 800);
        let same_block = OutPoint::new(parent.txid(), 0);
        let child = spend(same_block, 700);
        let mut undo = UndoBatch::empty();
        undo.restore(UtxoAdd::new(OutPoint::new(cb.txid(), 0), coin(60), true, 1));
        undo.restore(UtxoAdd::new(FUNDED, coin(900), true, 2));
        let block = Block {
            header: bitcoin_rs_primitives::Network::Regtest
                .genesis_block()
                .header,
            txs: vec![cb.clone(), parent, child],
        };
        let spent = block_spent_outputs(&block, HEIGHT, &undo)?;
        assert_eq!(spent[0], Vec::<UtxoCoin>::new());
        assert_eq!(
            spent[1],
            vec![UtxoCoin {
                outpoint: FUNDED,
                txout: coin(900),
                coinbase: true,
                height: 2
            }]
        );
        assert_eq!(
            spent[2],
            vec![UtxoCoin {
                outpoint: same_block,
                txout: coin(800),
                coinbase: false,
                height: HEIGHT
            }]
        );
        let missing = UndoBatch::empty();
        assert!(matches!(
            block_spent_outputs(&block, HEIGHT, &missing),
            Err(BlockSpendsError::Corrupt(_))
        ));
        cb.outputs.clear();
        let no_outputs = Block {
            header: block.header,
            txs: vec![cb],
        };
        let bytes = crate::undo_codec::encode(&undo, no_outputs.block_hash().into());
        assert!(decode_undo_record(&bytes, no_outputs.block_hash().into()).is_ok());
        assert!(matches!(
            decode_undo_record_for_block(&bytes, &no_outputs),
            Err(UndoCodecError::BlockCountLimit { .. })
        ));
        Ok(())
    }

    struct NoSpend;
    impl SpentOutputLookup for NoSpend {
        fn entry(&self, _outpoint: &OutPoint) -> Option<&UtxoCoin> {
            None
        }
    }

    fn connected() -> Result<(UtxoSet, CoinStatsListener, State, UndoBatch), UtxoError> {
        let mut utxo = UtxoSet::new();
        let coin_stats = CoinStatsListener::new(CoinStats::new());
        utxo.track_coin_stats(coin_stats.clone());
        let mut seed = BlockChanges::default();
        seed.add(UtxoAdd::new(FUNDED, coin(900), false, 1));
        commit_block_changes(&utxo, &seed, &Hash256::from_le_bytes(&[0x01; 32]))?;
        coin_stats.finish_block(1, 1);
        let before = observe(&utxo, &coin_stats)?;

        let mut changes = BlockChanges::default();
        changes.remove(FUNDED);
        changes.add(UtxoAdd::new(CREATED, coin(850), false, HEIGHT));
        commit_block_changes(&utxo, &changes, &HASH)?;
        coin_stats.finish_block(HEIGHT, 2);
        let mut undo = UndoBatch::empty();
        undo.restore(UtxoAdd::new(FUNDED, coin(900), false, 1));
        undo.remove(CREATED);
        Ok((utxo, coin_stats, before, undo))
    }

    type State = (Hash256, Hash256, [u64; 5]);

    fn observe(utxo: &UtxoSet, coin_stats: &CoinStatsListener) -> Result<State, UtxoError> {
        let s = coin_stats.snapshot();
        Ok((
            utxo.lock_stable_view().hash_serialized_3()?,
            s.muhash.finalize_hash(),
            [
                s.height.into(),
                s.total_amount,
                s.bogo_size,
                s.tx_count,
                s.utxo_count,
            ],
        ))
    }

    #[cfg(feature = "fjall")]
    #[test]
    fn persisted_record_survives_reopening_the_store() -> TestResult {
        use std::sync::Arc;

        use bitcoin_rs_storage::{FjallStore, KvUndoStore};

        let dir = tempfile::tempdir()?;
        let (.., undo) = connected()?;
        persist_block_undo(
            &KvUndoStore::new(Arc::new(FjallStore::open(dir.path())?)),
            HEIGHT,
            HASH,
            &undo,
        )?;
        let reopened = KvUndoStore::new(Arc::new(FjallStore::open(dir.path())?));
        assert_eq!(load_block_undo(&reopened, HEIGHT, HASH)?, undo);
        Ok(())
    }

    #[test]
    fn missing_and_foreign_records_are_refused() -> TestResult {
        let store = InMemoryUndoStore::default();
        let outcome = load_block_undo(&store, HEIGHT, HASH);
        assert!(
            matches!(outcome, Err(UndoLoadError::Missing { hash, height }) if hash == HASH && height == HEIGHT),
            "{outcome:?}"
        );

        let other = Hash256::from_le_bytes(&[0xab; 32]);
        let record = persist_block_undo(&store, HEIGHT, other, &UndoBatch::empty())?;
        store.persist_undo(HEIGHT, HASH, record.as_bytes())?;
        let outcome = load_block_undo(&store, HEIGHT, HASH);
        assert!(
            matches!(outcome, Err(UndoLoadError::Unreadable { hash, .. }) if hash == HASH),
            "{outcome:?}"
        );
        Ok(())
    }

    #[test]
    fn persisted_record_bytes_decode_back_to_the_batch() -> TestResult {
        let (.., undo) = connected()?;
        let store = InMemoryUndoStore::default();
        let record = persist_block_undo(&store, HEIGHT, HASH, &undo)?;
        assert_eq!(decode_undo_record(record.as_bytes(), HASH)?, undo);
        assert_eq!(load_block_undo(&store, HEIGHT, HASH)?, undo);
        Ok(())
    }

    #[test]
    fn rollback_restores_the_exact_prior_state() -> TestResult {
        let (utxo, coin_stats, before, undo) = connected()?;
        let store = InMemoryUndoStore::default();

        let receipt = rollback_block(&store, &utxo, &coin_stats, HASH, HEIGHT, 1, 2, &undo)?;

        assert!(utxo.get_entry(&CREATED).is_none());
        assert_eq!(
            utxo.get_entry(&FUNDED).map(|e| (e.txout, e.height)),
            Some((coin(900), 1))
        );
        assert_eq!(observe(&utxo, &coin_stats)?, before);
        assert_eq!(receipt.restored_parents, vec![FUNDED.txid]);
        let marker = store.load_disconnect_marker()?.ok_or("marker missing")?;
        assert_eq!(
            (marker.phase, marker.height, marker.hash),
            (DisconnectPhase::RolledBack, HEIGHT, HASH)
        );
        Ok(())
    }

    #[test]
    fn in_flight_marker_refuses_before_arming() -> TestResult {
        let (utxo, coin_stats, _, undo) = connected()?;
        let connected_state = observe(&utxo, &coin_stats)?;
        let store = InMemoryUndoStore::default();
        let torn = Hash256::from_le_bytes(&[0x77; 32]);
        store.arm_disconnect(HEIGHT - 1, torn)?;

        let outcome = rollback_block(&store, &utxo, &coin_stats, HASH, HEIGHT, 1, 2, &undo);

        assert!(
            matches!(outcome, Err(RollbackError::Refused(_))),
            "{outcome:?}"
        );
        assert_eq!(observe(&utxo, &coin_stats)?, connected_state);
        let marker = store.load_disconnect_marker()?.ok_or("marker missing")?;
        assert_eq!(
            (marker.phase, marker.height, marker.hash),
            (DisconnectPhase::InFlight, HEIGHT - 1, torn)
        );
        Ok(())
    }

    #[test]
    fn recovery_rewind_preserves_the_surviving_marker() -> TestResult {
        let (utxo, coin_stats, before, undo) = connected()?;
        let store = InMemoryUndoStore::default();
        let torn = Hash256::from_le_bytes(&[0x77; 32]);
        store.arm_disconnect(HEIGHT - 1, torn)?;

        rollback_block_recovery(&utxo, &coin_stats, HEIGHT, 1, 2, &undo)?;

        assert_eq!(observe(&utxo, &coin_stats)?, before);
        let marker = store.load_disconnect_marker()?.ok_or("marker missing")?;
        assert_eq!(
            (marker.phase, marker.height, marker.hash),
            (DisconnectPhase::InFlight, HEIGHT - 1, torn)
        );
        Ok(())
    }

    #[test]
    fn rolled_back_marker_carries_into_the_next_disconnect() -> TestResult {
        let (utxo, coin_stats, before, undo) = connected()?;
        let store = InMemoryUndoStore::default();
        let prior = Hash256::from_le_bytes(&[0x66; 32]);
        store.arm_disconnect(HEIGHT - 1, prior)?;
        store.complete_disconnect(HEIGHT - 1, prior)?;

        let receipt = rollback_block(&store, &utxo, &coin_stats, HASH, HEIGHT, 1, 2, &undo)?;

        assert_eq!(observe(&utxo, &coin_stats)?, before);
        assert_eq!(receipt.restored_parents, vec![FUNDED.txid]);
        let marker = store.load_disconnect_marker()?.ok_or("marker missing")?;
        assert_eq!(
            (marker.phase, marker.height, marker.hash),
            (DisconnectPhase::RolledBack, HEIGHT, HASH)
        );
        Ok(())
    }

    #[derive(Default)]
    struct MarkerFails {
        inner: InMemoryUndoStore,
        at: Option<DisconnectPhase>,
    }

    impl UndoStore for MarkerFails {
        fn persist_undo(&self, h: u32, hash: Hash256, r: &[u8]) -> Result<(), StorageError> {
            self.inner.persist_undo(h, hash, r)
        }
        fn load_undo(&self, h: u32, hash: Hash256) -> Result<Option<Vec<u8>>, StorageError> {
            self.inner.load_undo(h, hash)
        }
        fn arm_disconnect(&self, h: u32, hash: Hash256) -> Result<(), StorageError> {
            if self.at == Some(DisconnectPhase::InFlight) {
                return Err(StorageError::Backend("injected".into()));
            }
            self.inner.arm_disconnect(h, hash)
        }
        fn complete_disconnect(&self, h: u32, hash: Hash256) -> Result<(), StorageError> {
            if self.at == Some(DisconnectPhase::RolledBack) {
                return Err(StorageError::Backend("injected".into()));
            }
            self.inner.complete_disconnect(h, hash)
        }
        fn disarm_disconnect(&self) -> Result<(), StorageError> {
            self.inner.disarm_disconnect()
        }
        fn retire_disconnect_marker(&self) -> Result<(), StorageError> {
            self.inner.retire_disconnect_marker()
        }
        fn load_disconnect_marker(&self) -> Result<Option<DisconnectMarker>, StorageError> {
            self.inner.load_disconnect_marker()
        }
    }

    #[test]
    fn arm_failure_refuses_before_any_mutation() -> TestResult {
        let (utxo, coin_stats, _, undo) = connected()?;
        let connected_state = observe(&utxo, &coin_stats)?;
        let store = MarkerFails {
            at: Some(DisconnectPhase::InFlight),
            ..MarkerFails::default()
        };
        let outcome = rollback_block(&store, &utxo, &coin_stats, HASH, HEIGHT, 1, 2, &undo);
        assert!(
            matches!(outcome, Err(RollbackError::Refused(_))),
            "{outcome:?}"
        );
        assert_eq!(observe(&utxo, &coin_stats)?, connected_state);
        assert_eq!(store.load_disconnect_marker()?, None);
        Ok(())
    }

    #[test]
    fn completion_failure_is_fatal_and_leaves_the_marker_in_flight() -> TestResult {
        let (utxo, coin_stats, _, undo) = connected()?;
        let store = MarkerFails {
            at: Some(DisconnectPhase::RolledBack),
            ..MarkerFails::default()
        };
        let outcome = rollback_block(&store, &utxo, &coin_stats, HASH, HEIGHT, 1, 2, &undo);
        assert!(
            matches!(outcome, Err(RollbackError::Marker(_))),
            "{outcome:?}"
        );
        let marker = store.load_disconnect_marker()?.ok_or("marker missing")?;
        assert_eq!(marker.phase, DisconnectPhase::InFlight);
        Ok(())
    }

    #[test]
    fn coinstats_refusal_precedes_the_undo() -> TestResult {
        let (utxo, coin_stats, _, undo) = connected()?;
        let connected_state = observe(&utxo, &coin_stats)?;
        let store = InMemoryUndoStore::default();
        let outcome = rollback_block(&store, &utxo, &coin_stats, HASH, HEIGHT + 1, 1, 2, &undo);
        assert!(
            matches!(outcome, Err(RollbackError::CoinStats(_))),
            "{outcome:?}"
        );
        assert_eq!(observe(&utxo, &coin_stats)?, connected_state);
        Ok(())
    }

    fn undo_txid(seed: u64) -> Hash256 {
        let mut bytes = [0_u8; 32];
        bytes[..8].copy_from_slice(&seed.to_le_bytes());
        bytes[8..16].copy_from_slice(&seed.rotate_left(9).to_le_bytes());
        bytes[16..24].copy_from_slice(&seed.wrapping_mul(0xd6e8_feb8_6659_fd93).to_le_bytes());
        bytes[24..32].copy_from_slice(&seed.wrapping_add(0xfeed_face_cafe_beef).to_le_bytes());
        Hash256::from_le_bytes(&bytes)
    }

    fn undo_txout(seed: u64) -> TxOut {
        let mut script = Vec::with_capacity(10);
        script.extend_from_slice(&[0x00, 0x08]);
        script.extend_from_slice(&seed.to_le_bytes());
        TxOut {
            value: Amount::from_sat(50_000 + seed),
            script_pubkey: script.into(),
        }
    }

    fn build_undo_blocks() -> Result<Vec<(BlockChanges, UndoBatch)>, Box<dyn std::error::Error>> {
        let mut live: Vec<UtxoAdd> = Vec::new();
        let mut blocks = Vec::with_capacity(10);

        for height in 1_u32..=10 {
            let mut changes = BlockChanges::default();
            let mut undo = UndoBatch::empty();

            let remove_count = live.len().min(50);
            for _ in 0..remove_count {
                let add = live.remove(0);
                changes.remove(add.outpoint);
                undo.restore(add);
            }

            for n in 0_u64..100 {
                let seed = u64::from(height) * 1_000 + n;
                let outpoint = OutPoint::new(undo_txid(seed).into(), u32::try_from(n % 3)?);
                let txout = undo_txout(seed);
                let add = UtxoAdd::new(outpoint, txout, height == 1, height);
                live.push(add.clone());
                changes.add(add);
                undo.remove(outpoint);
            }

            blocks.push((changes, undo));
        }

        Ok(blocks)
    }

    #[test]
    fn undoing_last_five_blocks_matches_first_five_only_state() -> TestResult {
        let blocks = build_undo_blocks()?;
        let full = UtxoSet::new();

        for (height, (changes, _undo)) in (1_u64..=10).zip(&blocks) {
            commit_block_changes(&full, changes, &undo_txid(height))?;
        }
        for (_changes, undo) in blocks.iter().rev().take(5) {
            full.undo_block(undo)?;
        }

        let first_five = UtxoSet::new();
        for (height, (changes, _undo)) in (1_u64..=5).zip(&blocks) {
            commit_block_changes(&first_five, changes, &undo_txid(height))?;
        }

        assert_eq!(
            full.lock_stable_view().hash_serialized_3()?,
            first_five.lock_stable_view().hash_serialized_3()?
        );
        assert_eq!(full.len(), first_five.len());

        Ok(())
    }

    fn listener_set() -> (UtxoSet, CoinStatsListener) {
        let listener = CoinStatsListener::new(CoinStats::new());
        let mut set = UtxoSet::new();
        set.track_coin_stats(listener.clone());
        (set, listener)
    }

    fn first_undo_test_block(
        coinbase_outpoint: OutPoint,
        coinbase_txout: TxOut,
        kept_outpoint: OutPoint,
        kept_txout: TxOut,
    ) -> BlockChanges {
        let mut changes = BlockChanges::default();
        changes.add(UtxoAdd::new(coinbase_outpoint, coinbase_txout, true, 1));
        changes.add(UtxoAdd::new(kept_outpoint, kept_txout, false, 1));
        changes
    }

    #[test]
    fn listener_undo_restores_muhash_and_accounting() -> TestResult {
        let (full, full_listener) = listener_set();
        let coinbase_outpoint = OutPoint::new(undo_txid(40).into(), 0);
        let coinbase_txout = undo_txout(40);
        let kept_outpoint = OutPoint::new(undo_txid(41).into(), 0);
        let kept_txout = undo_txout(41);
        let replacement_outpoint = OutPoint::new(undo_txid(42).into(), 0);
        let replacement_txout = undo_txout(42);

        let first = first_undo_test_block(
            coinbase_outpoint,
            coinbase_txout.clone(),
            kept_outpoint,
            kept_txout.clone(),
        );
        commit_block_changes(&full, &first, &undo_txid(140))?;

        let mut second = BlockChanges::default();
        second.remove(coinbase_outpoint);
        second.add(UtxoAdd::new(
            replacement_outpoint,
            replacement_txout,
            false,
            2,
        ));
        let mut undo = UndoBatch::empty();
        undo.restore(UtxoAdd::new(
            coinbase_outpoint,
            coinbase_txout.clone(),
            true,
            1,
        ));
        undo.remove(replacement_outpoint);

        commit_block_changes(&full, &second, &undo_txid(141))?;
        full.undo_block(&undo)?;

        let (first_only, first_only_listener) = listener_set();
        commit_block_changes(&first_only, &first, &undo_txid(140))?;

        assert_eq!(full.get(&coinbase_outpoint), Some(coinbase_txout));
        assert_eq!(full.get(&kept_outpoint), Some(kept_txout));
        assert_eq!(full.get(&replacement_outpoint), None);
        assert_eq!(full.len(), first_only.len());
        assert_eq!(
            observe(&full, &full_listener)?,
            observe(&first_only, &first_only_listener)?
        );
        assert_eq!(
            full_listener.snapshot().muhash.finalize(),
            first_only_listener.snapshot().muhash.finalize()
        );
        Ok(())
    }

    fn block_with_short_txids() -> (Block, Vec<Txid>) {
        let make_tx = |seed: u8| Tx {
            version: 1,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[seed; 32])), u32::MAX),
                script_sig: vec![0x00].into(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![coin(500)],
        };
        let block = Block {
            header: Header {
                version: 1,
                prev_blockhash: BlockHash(Hash256::default()),
                merkle_root: Hash256::default(),
                time: 0,
                bits: CompactTarget::from_consensus(0x2100_ffff),
                nonce: 0,
            },
            txs: vec![make_tx(1), make_tx(2)],
        };
        let txids = vec![Txid(Hash256::from_le_bytes(&[0x77; 32]))];
        (block, txids)
    }

    #[test]
    fn a_short_txid_list_is_refused_at_every_height() {
        let (block, txids) = block_with_short_txids();
        for height in [0, HEIGHT] {
            let outcome =
                build_block_changes(&block, height, &txids, None, 4, 4, &NoSpend, None, 64);
            assert!(
                matches!(
                    outcome,
                    Err(BlockChangeError::TxidCountMismatch {
                        transactions: 2,
                        txids: 1
                    })
                ),
                "a short txid list was accepted at height {height}"
            );
        }
    }
}
