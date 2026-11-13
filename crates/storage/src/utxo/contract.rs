use hashbrown::HashSet;
use std::borrow::Borrow;

use crate::{StorageError, UndoStore};
use bitcoin_rs_consensus::primitives::{
    Block, BlockImage, Hash256, OutPoint, Script, TransactionView, Tx, TxOut, Txid,
};

use crate::utxo::set::{UtxoCoin, UtxoError, UtxoSet};
use crate::utxo::undo_codec;

pub use crate::utxo::undo_codec::{
    UndoCodecError, decode as decode_undo_record, encode as encode_undo_record,
    record_size_limit as undo_record_size_limit,
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
    pub const fn from_parts(restores: Vec<UtxoAdd>, removes: Vec<OutPoint>) -> Self {
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
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

pub trait SpentOutputLookup {
    fn entry(&self, outpoint: &OutPoint) -> Option<&UtxoCoin>;
}

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

pub use bitcoin_rs_consensus::{
    BlockSpends, BlockSpendsError, BlockUndoSource, BoundedReadError, HistoryUnavailable,
    UndoReadError,
};

impl From<UndoLoadError> for BlockSpendsError {
    fn from(error: UndoLoadError) -> Self {
        Self::Undo(match error {
            UndoLoadError::Read(source) => UndoReadError::Store(source.to_string()),
            UndoLoadError::Missing { hash, height } => UndoReadError::Missing {
                block: hash,
                height,
            },
            UndoLoadError::Unreadable { hash, .. } => UndoReadError::Unreadable { block: hash },
        })
    }
}

impl From<StorageError> for BlockSpendsError {
    fn from(error: StorageError) -> Self {
        Self::Storage(error.to_string())
    }
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

/// Applies UTXO changes directly to the coin store without advancing chain durability.
///
/// This updates coin rows and CoinStore statistics only; it does not advance the durable head
/// or write undo data. Offline fixtures and rebuilds may use it. Active chainstate commits MUST
/// use [`crate::CommitAuthority`] so coin rows, the durable head, and undo data are published as
/// one commit.
pub fn populate_block_changes<T: Borrow<TxOut>>(
    coin_store: &crate::CoinStore,
    changes: &BlockChanges<T>,
) -> Result<(), UtxoError> {
    use crate::utxo::record::{OwnedUtxoOut, UtxoRecord};
    use crate::{Bytes, CoinKey, WindowDelta};
    use std::collections::{HashMap, HashSet};
    let mut touched = HashSet::new();
    let mut adds_by_txid: HashMap<Hash256, Vec<&UtxoAdd<T>>> = HashMap::new();
    let mut removes_by_txid: HashMap<Hash256, Vec<u32>> = HashMap::new();

    for add in changes.adds() {
        let txid = Hash256::from(add.outpoint.txid);
        touched.insert(txid);
        adds_by_txid.entry(txid).or_default().push(add);
    }
    for remove in changes.spent_outpoints() {
        let txid = Hash256::from(remove.txid);
        touched.insert(txid);
        removes_by_txid.entry(txid).or_default().push(remove.vout);
    }

    let mut delta = WindowDelta::default();
    for txid in touched {
        let key = CoinKey(txid.to_le_bytes());
        let existing = coin_store.get(&key)?;
        let mut outputs: Vec<OwnedUtxoOut> = if let Some(bytes) = existing {
            let record = UtxoRecord::from_encoded(bytes.to_vec().into_boxed_slice())?;
            record
                .outputs()
                .map(|out| OwnedUtxoOut {
                    vout: out.vout,
                    value: out.value,
                    script_pubkey: out.script_pubkey.to_vec(),
                    coinbase: out.coinbase,
                    height: out.height,
                })
                .collect()
        } else {
            Vec::new()
        };

        if let Some(removes) = removes_by_txid.get(&txid) {
            let remove_set: HashSet<u32> = removes.iter().copied().collect();
            outputs.retain(|out| !remove_set.contains(&out.vout));
        }

        if let Some(adds) = adds_by_txid.get(&txid) {
            let mut add_vouts: HashSet<u32> = adds.iter().map(|add| add.outpoint.vout).collect();
            outputs.retain(|out| !add_vouts.contains(&out.vout));
            for add in adds.iter().rev() {
                let vout = add.outpoint.vout;
                if !add_vouts.remove(&vout) {
                    continue;
                }
                outputs.push(OwnedUtxoOut {
                    vout,
                    value: add.txout.borrow().value.to_sat(),
                    script_pubkey: add.txout.borrow().script_pubkey.to_vec(),
                    coinbase: add.coinbase,
                    height: add.height,
                });
            }
        }

        outputs.sort_by_key(|out| out.vout);

        if outputs.is_empty() {
            delta.push_final(key, None);
        } else {
            let record = UtxoRecord::from_owned_outputs(txid, &outputs)?;
            delta.push_final(key, Some(Bytes::copy_from_slice(record.bytes())));
        }
    }
    delta.records.sort_by_key(|(k, _)| *k);
    let mut batch = coin_store.store().new_batch();
    coin_store.append_window(&mut batch, &delta)?;
    let stats_feed = coin_store.plan_stats_feed(&delta)?;
    coin_store.store().write_durable(batch)?;
    coin_store.install_committed(&delta, stats_feed);
    Ok(())
}

pub fn build_block_changes<'a>(
    inputs: &BlockChangeInputs<'a, '_>,
    resolved: &impl SpentOutputLookup,
) -> Result<(BlockChanges<TxOut>, UndoBatch, BlockValueTotals), BlockChangeError> {
    if inputs.block.tx_count() != inputs.txids.len() {
        return Err(BlockChangeError::TxidCountMismatch {
            transactions: inputs.block.tx_count(),
            txids: inputs.txids.len(),
        });
    }
    if inputs.height == 0 {
        return Ok((
            BlockChanges::default(),
            UndoBatch::empty(),
            BlockValueTotals::default(),
        ));
    }

    let mut builder =
        ChangeBuilder::with_capacity(inputs.add_capacity, inputs.remove_capacity, inputs.height);
    for (tx_index, txid) in (0..inputs.block.tx_count()).zip(inputs.txids) {
        let tx = inputs.block.tx(tx_index);
        builder.add_outputs(&tx, *txid, inputs)?;
        if !tx.is_coinbase() {
            builder.add_spends(&tx, inputs, resolved)?;
        }
    }
    Ok(builder.finish())
}

pub struct BlockChangeInputs<'a, 'b> {
    pub block: &'a BlockImage,
    pub height: u32,
    pub txids: &'b [Txid],
    pub same_block_spent: Option<&'b HashSet<OutPoint>>,
    pub add_capacity: usize,
    pub remove_capacity: usize,
    pub max_script_size: usize,
}

impl BlockChangeInputs<'_, '_> {
    fn contains(&self, outpoint: OutPoint) -> bool {
        self.same_block_spent
            .is_some_and(|spends| spends.contains(&outpoint))
    }

    fn is_unstorable(&self, txout: &TxOut) -> bool {
        txout.script_pubkey.first() == Some(&0x6a)
            || txout.script_pubkey.len() > self.max_script_size
    }
}

struct ChangeBuilder {
    changes: BlockChanges<TxOut>,
    undo: UndoBatch,
    totals: BlockValueTotals,
    height: u32,
}

impl ChangeBuilder {
    fn with_capacity(adds: usize, removes: usize, height: u32) -> Self {
        Self {
            changes: BlockChanges::with_capacity(adds, removes),
            undo: UndoBatch::empty(),
            totals: BlockValueTotals::default(),
            height,
        }
    }

    fn finish(self) -> (BlockChanges<TxOut>, UndoBatch, BlockValueTotals) {
        (self.changes, self.undo, self.totals)
    }

    fn add_outputs(
        &mut self,
        tx: &TransactionView<'_>,
        txid: Txid,
        inputs: &BlockChangeInputs<'_, '_>,
    ) -> Result<(), BlockChangeError> {
        let coinbase = tx.is_coinbase();
        for vout_idx in 0..tx.output_count() {
            let vout =
                u32::try_from(vout_idx).map_err(|_| BlockChangeError::VoutOverflow { txid })?;
            let outpoint = OutPoint::new(txid, vout);
            let same_block = inputs.contains(outpoint);
            let value = tx.output_value(vout_idx);
            self.account_output_value(coinbase, same_block, value.to_sat())?;
            let txout = TxOut {
                value,
                script_pubkey: Script::from_bytes(tx.output_script(vout_idx).to_vec()),
            };
            if same_block || inputs.is_unstorable(&txout) {
                continue;
            }
            self.stage_created(outpoint, txout, coinbase);
        }
        Ok(())
    }

    fn account_output_value(
        &mut self,
        coinbase: bool,
        same_block: bool,
        value: u64,
    ) -> Result<(), BlockChangeError> {
        let total = if coinbase {
            &mut self.totals.coinbase_out
        } else if !same_block {
            &mut self.totals.created_out
        } else {
            return Ok(());
        };
        *total = total
            .checked_add(value)
            .ok_or(BlockChangeError::BlockValueOverflow)?;
        Ok(())
    }

    fn stage_created(&mut self, outpoint: OutPoint, txout: TxOut, coinbase: bool) {
        self.changes
            .add(UtxoAdd::new(outpoint, txout, coinbase, self.height));
        self.undo.remove(outpoint);
    }

    fn add_spends(
        &mut self,
        tx: &TransactionView<'_>,
        inputs: &BlockChangeInputs<'_, '_>,
        resolved: &impl SpentOutputLookup,
    ) -> Result<(), BlockChangeError> {
        for input_index in 0..tx.input_count() {
            let previous_output = tx.input_outpoint(input_index);
            if inputs.contains(previous_output) {
                continue;
            }
            self.changes.remove(previous_output);
            let spent =
                resolved
                    .entry(&previous_output)
                    .ok_or(BlockChangeError::UndoPrevoutMissing {
                        txid: previous_output.txid,
                        vout: previous_output.vout,
                    })?;
            self.account_spent_value(spent.txout.value.to_sat())?;
            self.undo.restore(UtxoAdd::new(
                previous_output,
                spent.txout.clone(),
                spent.coinbase,
                spent.height,
            ));
        }
        Ok(())
    }

    fn account_spent_value(&mut self, value: u64) -> Result<(), BlockChangeError> {
        self.totals.spent_in = self
            .totals
            .spent_in
            .checked_add(value)
            .ok_or(BlockChangeError::BlockValueOverflow)?;
        Ok(())
    }
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

pub struct BlockUndoCheck<'a> {
    pub block: &'a Block,
    pub txids: &'a [Txid],
    pub max_script_size: usize,
}

pub fn load_block_undo_for_block(
    store: &dyn UndoStore,
    height: u32,
    hash: Hash256,
    check: &BlockUndoCheck<'_>,
) -> Result<UndoBatch, UndoLoadError> {
    let undo = load_block_undo(store, height, hash)?;
    validate_undo_for_block(check, height, &undo)
        .map_err(|source| UndoLoadError::Unreadable { hash, source })?;
    Ok(undo)
}

fn validate_undo_for_block(
    check: &BlockUndoCheck<'_>,
    height: u32,
    undo: &UndoBatch,
) -> Result<(), UndoCodecError> {
    if height == 0 {
        return Ok(());
    }
    if check.block.txs.len() != check.txids.len() {
        return Err(UndoCodecError::BlockMismatch {
            reason: "transaction id count differs from the block transaction count",
        });
    }
    let (created, mut expected_removes) = block_outputs(check)?;
    let (external_inputs, same_block_inputs) = block_inputs(check);
    expected_removes.retain(|outpoint| !same_block_inputs.contains(outpoint));

    let mut restored: HashSet<OutPoint> = HashSet::with_capacity(undo.restores().len());
    for add in undo.restores() {
        if add.height >= height {
            return Err(UndoCodecError::BlockMismatch {
                reason: "restored coin height is not historical",
            });
        }
        if !external_inputs.contains(&add.outpoint) && !created.contains(&add.outpoint) {
            return Err(UndoCodecError::BlockMismatch {
                reason: "restored outpoint is not an input or output of the block",
            });
        }
        restored.insert(add.outpoint);
    }
    if !external_inputs
        .iter()
        .all(|outpoint| restored.contains(outpoint))
    {
        return Err(UndoCodecError::BlockMismatch {
            reason: "an external input has no restored coin",
        });
    }
    expected_removes.retain(|outpoint| !restored.contains(outpoint));
    let removed: HashSet<OutPoint> = undo.removes().iter().copied().collect();
    if removed != expected_removes {
        return Err(UndoCodecError::BlockMismatch {
            reason: "removed outpoints differ from the block's retained outputs",
        });
    }
    Ok(())
}

/// Deletes overwritten outpoints on disconnect, matching Bitcoin Core.
///
/// Returns `None` when the record restores no outpoint of a created txid.
pub fn rewrite_overwrite_restores(
    record: &[u8],
    block_hash: Hash256,
    created_txids: &HashSet<Txid>,
) -> Result<Option<Vec<u8>>, UndoCodecError> {
    let batch = undo_codec::decode(record, block_hash)?;
    let mut restores = Vec::with_capacity(batch.restores.len());
    let mut overwritten = Vec::new();
    for add in batch.restores {
        if created_txids.contains(&add.outpoint.txid) {
            overwritten.push(add.outpoint);
        } else {
            restores.push(add);
        }
    }
    if overwritten.is_empty() {
        return Ok(None);
    }
    let mut removes = batch.removes;
    let mut seen: HashSet<OutPoint> = removes.iter().copied().collect();
    for outpoint in overwritten {
        if seen.insert(outpoint) {
            removes.push(outpoint);
        }
    }
    Ok(Some(undo_codec::encode(
        &UndoBatch::from_parts(restores, removes),
        block_hash,
    )))
}

fn block_outputs(
    check: &BlockUndoCheck<'_>,
) -> Result<(HashSet<OutPoint>, HashSet<OutPoint>), UndoCodecError> {
    let mut created = HashSet::new();
    let mut retained = HashSet::new();
    for (tx, txid) in check.block.txs.iter().zip(check.txids) {
        for (index, txout) in tx.outputs.iter().enumerate() {
            let vout = u32::try_from(index).map_err(|_| UndoCodecError::BlockMismatch {
                reason: "block output index exceeds the vout range",
            })?;
            let outpoint = OutPoint::new(*txid, vout);
            created.insert(outpoint);
            let unstorable = txout.script_pubkey.first() == Some(&0x6a)
                || txout.script_pubkey.len() > check.max_script_size;
            if !unstorable {
                retained.insert(outpoint);
            }
        }
    }
    Ok((created, retained))
}

fn block_inputs(check: &BlockUndoCheck<'_>) -> (HashSet<OutPoint>, HashSet<OutPoint>) {
    let mut prior_txids: HashSet<Txid> = HashSet::with_capacity(check.block.txs.len());
    let mut external = HashSet::new();
    let mut same_block = HashSet::new();
    for (tx, txid) in check.block.txs.iter().zip(check.txids) {
        if tx.is_coinbase() {
            prior_txids.insert(*txid);
            continue;
        }
        for input in &tx.inputs {
            let outpoint = input.previous_output;
            match prior_txids.contains(&outpoint.txid) {
                true => {
                    same_block.insert(outpoint);
                }
                false => {
                    external.insert(outpoint);
                }
            }
        }
        prior_txids.insert(*txid);
    }
    (external, same_block)
}

#[cfg(test)]
mod tests;
