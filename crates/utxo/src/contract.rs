//! The chainstate-facing apply/commit/disconnect contract.
//!
//! Chainstate hands this crate one connected block at a time and gets back the
//! mutation payload, its undo record, and the value totals consensus checks
//! need; a disconnect loads the same block's undo record and rolls it back.
//! Everything the contract reads — resolved prevouts, the live set at BIP30
//! exception heights — enters through the two read traits here, so record,
//! shard, event, and codec machinery never leaves the crate.

use std::borrow::Borrow;

use bitcoin_rs_primitives::{Block, Hash256, OutPoint, Tx, TxOut, Txid};
use bitcoin_rs_storage::{DisconnectPhase, StorageError, UndoStore};
use hashbrown::HashSet;

use crate::set::{UtxoCoin, UtxoError, UtxoSet};
use crate::stats::{CoinStatsListener, CoinStatsRewindError};
use crate::undo_codec;

pub use crate::undo_codec::UndoCodecError;

/// One UTXO output to add, owning a `TxOut` or borrowing it from a block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UtxoAdd<T = TxOut> {
    /// Outpoint being created.
    pub outpoint: OutPoint,
    /// Output payload.
    pub txout: T,
    /// Whether the creating transaction is coinbase.
    pub coinbase: bool,
    /// Creating block height.
    pub height: u32,
}

impl<T> UtxoAdd<T> {
    /// Constructs an add operation.
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

/// UTXO mutations with owned or borrowed output payloads.
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
    /// Creates an empty change set with storage reserved for known operation counts.
    #[must_use]
    pub fn with_capacity(adds: usize, removes: usize) -> Self {
        Self {
            adds: Vec::with_capacity(adds),
            removes: Vec::with_capacity(removes),
        }
    }

    /// Appends an output creation.
    pub fn add(&mut self, add: UtxoAdd<T>) {
        self.adds.push(add);
    }

    /// Appends an output spend.
    pub fn remove(&mut self, outpoint: OutPoint) {
        self.removes.push(outpoint);
    }

    /// Returns the number of add operations.
    #[must_use]
    pub const fn add_count(&self) -> usize {
        self.adds.len()
    }

    /// Returns the number of remove operations.
    #[must_use]
    pub const fn remove_count(&self) -> usize {
        self.removes.len()
    }

    /// Returns output creations in commit order.
    #[must_use]
    pub fn adds(&self) -> &[UtxoAdd<T>] {
        &self.adds
    }

    /// Iterates the spent outpoints in commit order (one per non-netted spend).
    #[must_use]
    pub fn spent_outpoints(&self) -> &[OutPoint] {
        &self.removes
    }

    pub(crate) fn adds_slice(&self) -> &[UtxoAdd<T>] {
        &self.adds
    }

    pub(crate) fn removes_slice(&self) -> &[OutPoint] {
        &self.removes
    }
}

/// Inverse mutations needed to disconnect one block.
///
/// No public constructor: batches come from [`build_block_changes`] or the
/// undo decoder ([`load_block_undo`]), so a rollback can never be asked to
/// replay a batch the contract did not produce.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UndoBatch {
    pub(crate) restores: Vec<UtxoAdd>,
    pub(crate) removes: Vec<OutPoint>,
}

impl UndoBatch {
    /// A batch with no inverse mutations, for the genesis skip and codec tests.
    #[must_use]
    pub(crate) const fn empty() -> Self {
        Self {
            restores: Vec::new(),
            removes: Vec::new(),
        }
    }

    /// Outputs this batch restores, i.e. those the disconnected block spent.
    #[must_use]
    pub fn restores(&self) -> &[UtxoAdd] {
        &self.restores
    }

    /// Outputs this batch removes, i.e. those the disconnected block created.
    #[must_use]
    pub fn removes(&self) -> &[OutPoint] {
        &self.removes
    }

    /// Restores an output the disconnected block spent into this `UndoBatch`.
    ///
    /// Crate-visible on purpose: only the apply path ([`build_block_changes`])
    /// and the undo decoder build batches; everything outside this crate
    /// receives them from the contract.
    pub(crate) fn restore(&mut self, add: UtxoAdd) {
        self.restores.push(add);
    }

    /// Removes an output the disconnected block created from this `UndoBatch`.
    ///
    /// Crate-visible on purpose: see [`Self::restore`].
    pub(crate) fn remove(&mut self, outpoint: OutPoint) {
        self.removes.push(outpoint);
    }

    /// Returns true when the undo batch is empty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.restores.is_empty() && self.removes.is_empty()
    }

    /// Rebuilds a batch from its decoded parts.
    ///
    /// Crate-visible on purpose: the decoder rejects a record where one
    /// outpoint appears in both halves, and this constructor performs no check
    /// at all, so a public one is a way to build exactly the batch the codec
    /// refuses. The decoder is the only caller and it has already done the work.
    #[must_use]
    pub(crate) const fn from_parts(restores: Vec<UtxoAdd>, removes: Vec<OutPoint>) -> Self {
        Self { restores, removes }
    }
}

/// The raw encoded undo record one block left behind.
///
/// Produced alongside its [`UndoBatch`] by [`persist_block_undo`]. It survives
/// block-level persistence so the same bytes can be stored in a durable head
/// batch instead of re-encoding them.
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

    /// Returns the encoded record bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

/// The outcome of rolling one block back out of the UTXO set.
#[derive(Clone, Debug, Default)]
pub struct DisconnectReceipt {
    /// Parent transactions of the outputs restored into the live set.
    pub restored_parents: Vec<Txid>,
}

/// Returns true when `tx` is a coinbase: one input with the null outpoint.
#[must_use]
pub fn is_coinbase_tx(tx: &Tx) -> bool {
    tx.inputs.len() == 1
        && tx.inputs[0].previous_output.txid == Txid::default()
        && tx.inputs[0].previous_output.vout == u32::MAX
}

/// Lookup for the full resolved coin of a spent output, including creation
/// metadata.
///
/// Implemented by chainstate's resolved-prevout view, which resolves a
/// block's external prevouts from the committed set (or a window overlay).
pub trait SpentOutputLookup {
    /// Full resolved coin for a spent outpoint, or `None` if it is not live.
    fn entry(&self, outpoint: &OutPoint) -> Option<&UtxoCoin>;
}

/// Where a block's prevouts are read from: the committed set, or a window
/// overlay over blocks prepared but not yet committed.
pub trait OutputSource {
    /// The live coin an outpoint refers to, or `None` if unspendable here.
    fn get_entry(&self, outpoint: &OutPoint) -> Option<UtxoCoin>;
}

impl OutputSource for UtxoSet {
    fn get_entry(&self, outpoint: &OutPoint) -> Option<UtxoCoin> {
        Self::get_entry(self, outpoint)
    }
}

/// What a block pays its coinbase and what it earned in fees.
///
/// Gathered by [`build_block_changes`] because that walk already visits exactly
/// the right two sets. Outputs created and spent inside the same block are
/// skipped there, and they cancel in the fee sum — a same-block output is one
/// transaction's output and another's input — so leaving both out is exact,
/// not an approximation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BlockValueTotals {
    /// Total value the coinbase outputs claim.
    pub coinbase_out: u64,
    /// Input value of the block's non-coinbase transactions, same-block
    /// spends excluded.
    pub spent_in: u64,
    /// Output value of the block's non-coinbase transactions, outputs spent
    /// in the same block excluded.
    pub created_out: u64,
}

impl BlockValueTotals {
    /// Fees the block earned, or `None` if the totals are inconsistent.
    ///
    /// Returns `None` rather than saturating: outputs exceeding inputs is a
    /// consensus failure that per-transaction verification should already have
    /// rejected, and silently reporting zero fees would let it through here.
    #[must_use]
    pub const fn fees(self) -> Option<u64> {
        self.spent_in.checked_sub(self.created_out)
    }
}

/// Errors produced while building UTXO connect changes for one block.
#[derive(Debug, thiserror::Error)]
pub enum BlockChangeError {
    /// Summing a block's input or output values left the satoshi range.
    #[error("block value total overflows the satoshi range")]
    BlockValueOverflow,
    /// A transaction carries more outputs than a `u32` vout can index.
    #[error("output count of transaction {txid} exceeds the vout index range")]
    VoutOverflow {
        /// Transaction id whose output count overflowed.
        txid: Txid,
    },
    /// The supplied txid slice does not cover every transaction in the block.
    #[error("block has {transactions} transactions but {txids} txids were supplied")]
    TxidCountMismatch {
        /// Transactions in the block.
        transactions: usize,
        /// Txids supplied for them.
        txids: usize,
    },
    /// A spent output had no resolved prevout, so the undo record would be
    /// unable to restore it.
    #[error("undo record cannot restore spent output {txid}:{vout}")]
    UndoPrevoutMissing {
        /// Transaction id of the unresolvable spend.
        txid: Txid,
        /// Output index of the unresolvable spend.
        vout: u32,
    },
}

/// Why a stored undo record could not be turned back into an [`UndoBatch`].
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
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

/// Only `Refused` leaves state untouched; the rest fire after the marker is
/// armed and may leave state torn for recovery to reconcile.
#[derive(Debug, thiserror::Error)]
#[allow(missing_docs)]
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

/// Applies one connected block's [`BlockChanges`] to the set.
///
/// The public commit entry point: chainstate and every test seam commit
/// through this function, so `utxo::contract` owns the full
/// build → commit → persist/disconnect mutation surface and the set itself
/// keeps no public mutator.
///
/// # Errors
///
/// [`UtxoError`] when a shard mutation fails.
pub fn commit_block_changes<T: Borrow<TxOut>>(
    set: &UtxoSet,
    changes: &BlockChanges<T>,
    block_hash: &Hash256,
) -> Result<(), UtxoError> {
    set.commit_block(changes, block_hash)
}

/// Builds the UTXO mutation, undo batch, and value totals for one connected
/// block.
///
/// # Parameters
///
/// - `block`: the block being connected.
/// - `height`: the height at which it connects.
/// - `txids`: precomputed txids for the block's transactions, in order.
/// - `same_block_spent`: outpoints spent within the same block (netted out),
///   or `None` when no same-block detection ran.
/// - `add_capacity` / `remove_capacity`: pre-reserved capacities for the
///   change sets.
/// - `resolved`: lookup for the full coins of outputs the block spends.
/// - `overwritten`: the committed set, passed only at BIP30 exception heights
///   where a coinbase reuses a still-live txid.
/// - `max_script_size`: consensus limit; outputs whose script exceeds this are
///   not added to the UTXO set.
///
/// # Errors
///
/// [`BlockChangeError::TxidCountMismatch`] when `txids` does not cover every
/// transaction, refused before iterating so no trailing transaction can be
/// silently dropped; [`BlockChangeError::VoutOverflow`] when a transaction
/// carries more outputs than a `u32` vout can index;
/// [`BlockChangeError::BlockValueOverflow`] when value totals overflow; and
/// [`BlockChangeError::UndoPrevoutMissing`] when a spend has no resolved
/// prevout. Genesis returns empty mutations.
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
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
    // Zipping would silently drop whichever sequence is longer, leaving
    // trailing transactions out of the changes, undo, and value totals while
    // reporting success - the window overlay refuses the same mismatch. This
    // runs before the genesis early return so a mismatched slice is refused at
    // every height, matching the documented contract.
    if block.txs.len() != txids.len() {
        return Err(BlockChangeError::TxidCountMismatch {
            transactions: block.txs.len(),
            txids: txids.len(),
        });
    }
    // Bitcoin Core indexes genesis but does not connect its transactions into
    // CoinsView; its coinbase is unspendable and absent from UTXO/MuHash state.
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
        let coinbase = is_coinbase_tx(tx);
        for (vout_idx, txout) in tx.outputs.iter().enumerate() {
            // Before the unspendable-output skip below: an OP_RETURN output
            // never enters the UTXO set, but the transaction that created it
            // still paid for it, so it counts against the fee.
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
            // At a BIP30 exception height the coinbase reuses an earlier txid
            // whose outputs are still live, so this add OVERWRITES a coin
            // rather than creating one. `overwritten` is `Some` only at those
            // two mainnet heights, so every other block pays no lookup.
            let replaced = overwritten.and_then(|set| set.get_entry(&outpoint));
            changes.add(UtxoAdd::new(outpoint, txout, coinbase, height));
            match replaced {
                // The inverse of overwriting is writing the old coin back, not
                // deleting the outpoint. Emitting a remove as well would depend
                // on the undo applying restores after removes, and it does the
                // opposite, so the older coin would be lost and the rewound
                // UTXO set, MuHash, and coinstats would not match the parent.
                Some(previous) => undo.restore(UtxoAdd::new(
                    outpoint,
                    previous.txout,
                    previous.coinbase,
                    previous.height,
                )),
                // Disconnecting the block deletes what it created.
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
                // ...and restores what it spent. A spend with no resolved
                // prevout would make the record unable to restore that output,
                // so refuse rather than persist an undo that silently loses it.
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

/// Encodes and persists a block's undo record, returning the raw record so the
/// caller can put the same row into its durable head batch.
///
/// # Errors
///
/// The store's write failure.
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

/// Loads and decodes the record [`persist_block_undo`] wrote for a block.
///
/// # Errors
///
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

/// Decodes one raw undo record that the caller already holds.
///
/// The stored head certifies an undo record in the same batch as its block
/// body, so a replay that reads the body from its own store can decode the
/// same row without going through [`load_block_undo`]'s `UndoStore`.
///
/// # Errors
///
/// A malformed record, or one bound to a different block.
pub fn decode_undo_record(bytes: &[u8], block_hash: Hash256) -> Result<UndoBatch, UndoCodecError> {
    undo_codec::decode(bytes, block_hash)
}

/// Rolls one block out of the UTXO set under a durable disconnect marker.
///
/// The marker is read before arming so a refusal cannot overwrite the
/// previous disconnect's marker: an `InFlight` marker is a torn rollback that
/// must not be armed over, while a `RolledBack` marker is owed checkpoint
/// debt that sequential disconnects carry into the next arm. On success the
/// marker stays `RolledBack` until the caller durably publishes the
/// rolled-back state. A marker that survives to the next startup no longer
/// refuses it: startup recovers automatically from the durable certified
/// head before anything serves (`docs/contracts/recovery.md`). Per-coin
/// coinstats follow the set's undo through the listener; only height and
/// transaction count are rewound here.
///
/// # Errors
///
/// [`RollbackError::Refused`] before the marker is armed; every other variant
/// after.
#[allow(clippy::too_many_arguments)]
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
    utxo.undo_block(undo).map_err(RollbackError::Utxo)?;
    coin_stats
        .rewind_block(height, parent_height, tx_count_delta)
        .map_err(RollbackError::CoinStats)?;
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
    use crate::snapshot::aggregate_hash;
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

    /// `FUNDED` at height 1, then the block at `HEIGHT` spending it and
    /// creating `CREATED`; returns the set, its listener, the observable state
    /// before that block, and the block's undo.
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

    /// UTXO digest, coinstats digest (`MuHash` limbs are representation, not
    /// state) and the coinstats scalars.
    type State = (Hash256, Hash256, [u64; 5]);

    fn observe(utxo: &UtxoSet, coin_stats: &CoinStatsListener) -> Result<State, UtxoError> {
        let s = coin_stats.snapshot();
        Ok((
            aggregate_hash(utxo)?,
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

    /// A torn rollback's `InFlight` marker must not be armed over: the
    /// refusal leaves both the set and the marker untouched.
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

    /// A `RolledBack` marker only owes a checkpoint of the rolled-back set, so
    /// the next disconnect re-arms over it and supersedes its identity.
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

    /// Marker writes fail in the chosen phase.
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
    fn coinstats_refusal_after_the_undo_is_fatal() -> TestResult {
        let (utxo, coin_stats, _, undo) = connected()?;
        let store = InMemoryUndoStore::default();
        let outcome = rollback_block(&store, &utxo, &coin_stats, HASH, HEIGHT + 1, 1, 2, &undo);
        assert!(
            matches!(outcome, Err(RollbackError::CoinStats(_))),
            "{outcome:?}"
        );
        assert!(utxo.get_entry(&FUNDED).is_some(), "undo had already run");
        Ok(())
    }

    // Undo-determinism coverage, relocated from the crate's integration
    // tests once the raw inverse (`undo_block`) and the `UndoBatch` builders
    // became crate-visible only.

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

    /// Ten blocks of 100 creates and up to 50 spends each, with the matching
    /// undo batches.
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

    /// Undo coverage for deterministic block disconnects: undoing the last
    /// five of ten blocks lands exactly on the five-block-only state.
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

        assert_eq!(aggregate_hash(&full)?, aggregate_hash(&first_five)?);
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

    /// The listener must restore the exact `MuHash` and accounting of the
    /// history the undone blocks never touched.
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

    /// A block of two transactions paired with a one-element `txids` slice:
    /// the fixture for every mismatch-refusal test below.
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

    /// A `txids` slice shorter than the block would let `zip` silently drop
    /// trailing transactions from the changes, undo, and value totals while
    /// reporting success. The build refuses the mismatch before iterating.
    #[test]
    fn short_txid_list_is_refused_before_iterating() {
        struct NoSpend;
        impl SpentOutputLookup for NoSpend {
            fn entry(&self, _outpoint: &OutPoint) -> Option<&UtxoCoin> {
                None
            }
        }

        let (block, txids) = block_with_short_txids();
        let outcome = build_block_changes(&block, HEIGHT, &txids, None, 4, 4, &NoSpend, None, 64);
        assert!(
            matches!(
                outcome,
                Err(BlockChangeError::TxidCountMismatch {
                    transactions: 2,
                    txids: 1
                })
            ),
            "a short txid list must be refused before iterating"
        );
    }

    /// The genesis early return must not skip validation: a mismatched
    /// `txids` slice is refused at height 0 too, as the contract documents.
    #[test]
    fn short_txid_list_is_refused_at_genesis_height() {
        struct NoSpend;
        impl SpentOutputLookup for NoSpend {
            fn entry(&self, _outpoint: &OutPoint) -> Option<&UtxoCoin> {
                None
            }
        }

        let (block, txids) = block_with_short_txids();
        let outcome = build_block_changes(&block, 0, &txids, None, 4, 4, &NoSpend, None, 64);
        assert!(
            matches!(
                outcome,
                Err(BlockChangeError::TxidCountMismatch {
                    transactions: 2,
                    txids: 1
                })
            ),
            "a short txid list must be refused at genesis height too"
        );
    }
}
