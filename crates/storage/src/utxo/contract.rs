use hashbrown::{HashMap, HashSet};
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

    #[must_use]
    pub(crate) fn into_restores(self) -> Vec<UtxoAdd> {
        self.restores
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

    fn get_entries(&self, outpoints: &[OutPoint]) -> Vec<Option<UtxoCoin>> {
        outpoints
            .iter()
            .map(|outpoint| self.get_entry(outpoint))
            .collect()
    }
}

impl OutputSource for UtxoSet {
    fn get_entry(&self, outpoint: &OutPoint) -> Option<UtxoCoin> {
        Self::get_entry(self, outpoint)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CoinEntryError {
    #[error(transparent)]
    Read(#[from] StorageError),
    #[error(transparent)]
    Record(#[from] UtxoError),
}

const COIN_ENTRY_TXIDS_PER_FETCH: usize = 64;

pub fn resolve_coin_entries(
    coins: &crate::CoinStore,
    outpoints: &[OutPoint],
) -> Result<Vec<Option<UtxoCoin>>, CoinEntryError> {
    let mut slots: HashMap<Txid, usize> = HashMap::with_capacity(outpoints.len());
    let mut keys = Vec::new();
    for outpoint in outpoints {
        slots.entry(outpoint.txid).or_insert_with(|| {
            keys.push(crate::CoinKey(outpoint.txid.0.to_le_bytes()));
            keys.len() - 1
        });
    }
    let mut records: Vec<Option<crate::utxo::record::UtxoRecord>> = Vec::with_capacity(keys.len());
    for chunk in keys.chunks(COIN_ENTRY_TXIDS_PER_FETCH) {
        let values = coins.multi_get(chunk)?;
        for value in values {
            records.push(
                value
                    .map(|bytes| {
                        crate::utxo::record::UtxoRecord::from_encoded(
                            bytes.to_vec().into_boxed_slice(),
                        )
                    })
                    .transpose()?,
            );
        }
    }
    Ok(outpoints
        .iter()
        .map(|outpoint| {
            let slot = *slots.get(&outpoint.txid)?;
            let record = records.get(slot)?.as_ref()?;
            let out = record.find_output(outpoint.vout)?;
            Some(UtxoCoin {
                outpoint: *outpoint,
                txout: TxOut {
                    value: bitcoin_rs_consensus::primitives::Amount::from_sat(out.value),
                    script_pubkey: out.script_pubkey.to_vec().into(),
                },
                coinbase: out.coinbase,
                height: out.height,
            })
        })
        .collect())
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
    let batch = undo_codec::decode_bounded(
        bytes,
        block.block_hash().into(),
        inputs.saturating_add(outputs),
    )?;
    let restores = batch.into_restores();
    let max_script_size = bitcoin_rs_consensus::MAX_SCRIPT_SIZE;
    let txids: Vec<Txid> = block.txs.iter().map(|tx| tx.txid()).collect();
    let check = BlockUndoCheck {
        block,
        txids: &txids,
        max_script_size,
    };
    let removes = derive_removes(&check, &restores)?;
    Ok(UndoBatch::from_parts(restores, removes))
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

    fn is_unstorable(&self, script_pubkey: &[u8]) -> bool {
        script_pubkey.first() == Some(&0x6a) || script_pubkey.len() > self.max_script_size
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
            undo: UndoBatch::from_parts(Vec::with_capacity(removes), Vec::with_capacity(adds)),
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
            let script_pubkey = tx.output_script(vout_idx);
            if same_block || inputs.is_unstorable(script_pubkey) {
                continue;
            }
            let txout = TxOut {
                value,
                script_pubkey: Script::from_bytes(script_pubkey.to_vec()),
            };
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
    if height == 0 {
        return Ok(undo);
    }
    let removes = derive_removes(check, undo.restores())
        .map_err(|source| UndoLoadError::Unreadable { hash, source })?;
    Ok(UndoBatch::from_parts(undo.into_restores(), removes))
}

fn derive_removes(
    check: &BlockUndoCheck<'_>,
    restores: &[UtxoAdd],
) -> Result<Vec<OutPoint>, UndoCodecError> {
    let (_, mut derived) = block_outputs(check)?;
    let (_, same_block) = block_inputs(check);
    derived.retain(|outpoint| !same_block.contains(outpoint));
    let restored: HashSet<OutPoint> = restores.iter().map(|add| add.outpoint).collect();
    derived.retain(|outpoint| !restored.contains(outpoint));
    let mut removes: Vec<OutPoint> = derived.into_iter().collect();
    removes.sort_by(|a, b| {
        let a_txid = a.txid;
        let b_txid = b.txid;
        let a_vout = a.vout;
        let b_vout = b.vout;
        a_txid
            .as_bytes()
            .cmp(b_txid.as_bytes())
            .then_with(|| a_vout.cmp(&b_vout))
    });
    Ok(removes)
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
    let (created, _) = block_outputs(check)?;
    let (external_inputs, _) = block_inputs(check);

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
    let mut dropped = false;
    for add in batch.restores {
        if created_txids.contains(&add.outpoint.txid) {
            dropped = true;
        } else {
            restores.push(add);
        }
    }
    if !dropped {
        return Ok(None);
    }
    Ok(Some(undo_codec::encode(
        &UndoBatch::from_parts(restores, Vec::new()),
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
mod tests {
    use super::*;
    use crate::InMemoryUndoStore;
    use bitcoin_rs_consensus::primitives::{
        Amount, Block, BlockHash, BlockImage, CompactTarget, Hash256, Header, LockTime, OutPoint,
        Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
    };

    use crate::utxo::test_support::{TestError, TestResult};

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
            header: bitcoin_rs_consensus::primitives::Network::Regtest
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
        let bytes = crate::utxo::undo_codec::encode(&undo, no_outputs.block_hash().into());
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

    fn sample_undo() -> UndoBatch {
        let mut undo = UndoBatch::empty();
        undo.restore(UtxoAdd::new(FUNDED, coin(900), false, 1));
        undo
    }
    #[test]
    fn persisted_record_survives_reopening_the_store() -> TestResult {
        use std::sync::Arc;

        use crate::{KvUndoStore, RocksDbStore};

        let dir = tempfile::tempdir()?;
        let undo = sample_undo();
        persist_block_undo(
            &KvUndoStore::new(Arc::new(RocksDbStore::open(dir.path())?)),
            HEIGHT,
            HASH,
            &undo,
        )?;
        let reopened = KvUndoStore::new(Arc::new(RocksDbStore::open(dir.path())?));
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
        let undo = sample_undo();
        let store = InMemoryUndoStore::default();
        let record = persist_block_undo(&store, HEIGHT, HASH, &undo)?;
        assert_eq!(decode_undo_record(record.as_bytes(), HASH)?, undo);
        assert_eq!(load_block_undo(&store, HEIGHT, HASH)?, undo);
        Ok(())
    }

    #[test]
    fn populate_block_changes_applies_adds_and_spends_to_coin_store() -> TestResult {
        use crate::{CoinKey, CoinStore, MemoryKvStore};
        use std::sync::Arc;
        let store = Arc::new(MemoryKvStore::new());
        let coin_store = CoinStore::open(store, 64 * 1024 * 1024);

        let mut block1 = BlockChanges::default();
        block1.add(UtxoAdd::new(FUNDED, coin(900), false, 1));
        let untouched = OutPoint::new(FUNDED.txid, 3);
        block1.add(UtxoAdd::new(untouched, coin(125), true, 2));
        let spent = OutPoint::new(FUNDED.txid, 1);
        block1.add(UtxoAdd::new(spent, coin(200), false, 2));
        populate_block_changes(&coin_store, &block1)?;

        let key_funded = CoinKey(FUNDED.txid.0.to_le_bytes());
        let coin1 = coin_store
            .get(&key_funded)?
            .ok_or(TestError::Missing("funded exists"))?;
        let record1 =
            crate::utxo::record::UtxoRecord::from_encoded(coin1.to_vec().into_boxed_slice())?;
        assert_eq!(record1.find_output(FUNDED.vout).map(|o| o.value), Some(900));

        let mut block2 = BlockChanges::default();
        block2.remove(FUNDED);
        block2.remove(spent);
        block2.add(UtxoAdd::new(FUNDED, coin(700), false, 3));
        block2.add(UtxoAdd::new(
            FUNDED,
            TxOut {
                value: Amount::from_sat(650),
                script_pubkey: Script::from_bytes(vec![0x52, 0x53]),
            },
            true,
            4,
        ));
        block2.add(UtxoAdd::new(CREATED, coin(850), false, HEIGHT));
        populate_block_changes(&coin_store, &block2)?;

        let funded = coin_store.get(&key_funded)?.ok_or(TestError::Missing(
            "replacement and untouched outputs exist",
        ))?;
        let funded_record =
            crate::utxo::record::UtxoRecord::from_encoded(funded.to_vec().into_boxed_slice())?;
        let funded_outputs: Vec<_> = funded_record
            .outputs()
            .map(|out| {
                (
                    out.vout,
                    out.value,
                    out.script_pubkey.to_vec(),
                    out.coinbase,
                    out.height,
                )
            })
            .collect();
        assert_eq!(
            funded_outputs,
            vec![
                (0, 650, vec![0x52, 0x53], true, 4),
                (3, 125, vec![0x51], true, 2),
            ]
        );
        let key_created = CoinKey(CREATED.txid.0.to_le_bytes());
        let coin2 = coin_store
            .get(&key_created)?
            .ok_or(TestError::Missing("created exists"))?;
        let record2 =
            crate::utxo::record::UtxoRecord::from_encoded(coin2.to_vec().into_boxed_slice())?;
        assert_eq!(
            record2.find_output(CREATED.vout).map(|o| o.value),
            Some(850)
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
            let outcome = build_block_changes(
                &BlockChangeInputs {
                    block: &BlockImage::from_local(block.clone()),
                    height,
                    txids: &txids,
                    same_block_spent: None,
                    add_capacity: 4,
                    remove_capacity: 4,
                    max_script_size: 64,
                },
                &NoSpend,
            );
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

    fn spending(previous_output: OutPoint, outputs: Vec<TxOut>) -> Tx {
        Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output,
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs,
        }
    }

    fn shaped_block() -> Block {
        let coinbase_tx = spending(
            OutPoint::null(),
            vec![TxOut {
                value: Amount::from_sat(50),
                script_pubkey: Script::from_bytes(vec![0x51]),
            }],
        );
        let parent = spending(FUNDED, vec![coin(90), coin(5)]);
        let child = spending(OutPoint::new(parent.txid(), 0), vec![coin(80)]);
        Block {
            header: bitcoin_rs_consensus::primitives::Network::Regtest
                .genesis_block()
                .header,
            txs: vec![coinbase_tx, parent, child],
        }
    }

    fn shaped_undo(_block: &Block) -> UndoBatch {
        let mut undo = UndoBatch::empty();
        undo.restore(UtxoAdd::new(FUNDED, coin(90), false, HEIGHT - 1));
        undo
    }

    // RCV-08
    #[test]
    fn undo_validation_matches_the_block_shape() -> TestResult {
        const MAX_SCRIPT_SIZE: usize = 10_000;
        let block = shaped_block();
        let txids: Vec<Txid> = block.txs.iter().map(|tx| tx.txid()).collect();
        let check = BlockUndoCheck {
            block: &block,
            txids: &txids,
            max_script_size: MAX_SCRIPT_SIZE,
        };
        let undo = shaped_undo(&block);
        assert_eq!(validate_undo_for_block(&check, HEIGHT, &undo), Ok(()));

        let short = BlockUndoCheck {
            block: &block,
            txids: &txids[..2],
            max_script_size: MAX_SCRIPT_SIZE,
        };
        assert!(
            matches!(
                validate_undo_for_block(&short, HEIGHT, &undo),
                Err(UndoCodecError::BlockMismatch { .. })
            ),
            "a short transaction id slice must refuse instead of validating fewer transactions"
        );

        let mut extra_remove = shaped_undo(&block);
        extra_remove.remove(OutPoint::new(block.txs[1].txid(), 0));
        assert_eq!(
            validate_undo_for_block(&check, HEIGHT, &extra_remove),
            Ok(()),
        );

        let mut foreign_restore = shaped_undo(&block);
        foreign_restore.restore(UtxoAdd::new(CREATED, coin(1), false, HEIGHT - 1));
        assert!(matches!(
            validate_undo_for_block(&check, HEIGHT, &foreign_restore),
            Err(UndoCodecError::BlockMismatch { .. })
        ));

        let mut future_restore = shaped_undo(&block);
        future_restore.restore(UtxoAdd::new(FUNDED, coin(90), false, HEIGHT));
        assert!(matches!(
            validate_undo_for_block(&check, HEIGHT, &future_restore),
            Err(UndoCodecError::BlockMismatch { .. })
        ));

        let missing_restore = UndoBatch::empty();
        assert!(matches!(
            validate_undo_for_block(&check, HEIGHT, &missing_restore),
            Err(UndoCodecError::BlockMismatch { .. })
        ));

        let mut overwritten = UndoBatch::empty();
        overwritten.restore(UtxoAdd::new(FUNDED, coin(90), false, HEIGHT - 1));
        overwritten.restore(UtxoAdd::new(
            OutPoint::new(block.txs[1].txid(), 1),
            coin(1),
            false,
            HEIGHT - 2,
        ));
        assert_eq!(
            validate_undo_for_block(&check, HEIGHT, &overwritten),
            Ok(()),
            "a BIP30 overwrite restores the replaced output instead of removing it"
        );
        Ok(())
    }

    #[test]
    fn every_undo_truncation_and_flip_is_refused_or_canonical() -> TestResult {
        let hash = Hash256::from_le_bytes(&[0x5A; 32]);
        let mut batch = UndoBatch::empty();
        batch.restore(UtxoAdd::new(FUNDED, coin(50_000), true, 11));
        let second = OutPoint::new(Txid(Hash256::from_le_bytes(&[0x32; 32])), 7);
        batch.restore(UtxoAdd::new(
            second,
            TxOut {
                value: Amount::from_sat(1),
                script_pubkey: Script::from_bytes(vec![0x51; 129]),
            },
            false,
            12,
        ));
        let bytes = crate::utxo::undo_codec::encode(&batch, hash);
        for cut in 0..bytes.len() {
            assert!(
                crate::utxo::undo_codec::decode(&bytes[..cut], hash).is_err(),
                "truncation at {cut} decoded"
            );
        }
        for (index, byte) in bytes.iter().enumerate() {
            for bit in 0..8_u8 {
                let mut mutated = bytes.clone();
                mutated[index] = *byte ^ (1 << bit);
                let Ok(decoded) = crate::utxo::undo_codec::decode(&mutated, hash) else {
                    continue;
                };
                assert_eq!(
                    crate::utxo::undo_codec::encode(&decoded, hash),
                    mutated,
                    "flip at byte {index} bit {bit} decoded to a non-canonical batch"
                );
            }
        }
        Ok(())
    }

    #[test]
    fn coin_stats_feed_tracks_utxo_accounting_through_populate() -> TestResult {
        use crate::utxo::stats::{CoinStats, CoinStatsListener};
        use crate::{CoinStore, MemoryKvStore};
        use std::sync::Arc;
        let store = Arc::new(MemoryKvStore::new());
        let coin_store = CoinStore::open(store, 64 * 1024 * 1024);
        let listener = CoinStatsListener::new(CoinStats::new());
        coin_store.track_coin_stats(listener.clone());

        let mut block1 = BlockChanges::default();
        block1.add(UtxoAdd::new(FUNDED, coin(900), false, 1));
        block1.add(UtxoAdd::new(CREATED, coin(700), true, 1));
        populate_block_changes(&coin_store, &block1)?;
        listener.finish_block(1, 2);

        let mut expected = CoinStats::new();
        expected.insert_utxo(&FUNDED, &coin(900), 1, false);
        expected.insert_utxo(&CREATED, &coin(700), 1, true);
        expected.finish_block(1, 2);
        assert_eq!(listener.snapshot(), expected);

        let mut block2 = BlockChanges::default();
        block2.remove(CREATED);
        block2.add(UtxoAdd::new(FUNDED, coin(800), false, 2));
        populate_block_changes(&coin_store, &block2)?;
        listener.finish_block(2, 1);

        expected.remove_utxo(&CREATED, &coin(700), 1, true);
        expected.remove_utxo(&FUNDED, &coin(900), 1, false);
        expected.insert_utxo(&FUNDED, &coin(800), 2, false);
        expected.finish_block(2, 1);
        assert_eq!(listener.snapshot(), expected);
        Ok(())
    }
    // CMT-06
    #[test]
    fn undo_record_holds_only_spent_coins_and_derives_created_outputs() -> TestResult {
        const MAX_SCRIPT_SIZE: usize = 10_000;
        let mut blocks = Vec::new();
        blocks.push(shaped_block());
        let mut coinbase_only = shaped_block();
        coinbase_only.txs.truncate(1);
        blocks.push(coinbase_only);
        let mut op_return_block = shaped_block();
        op_return_block.txs[1].outputs[1] = TxOut {
            value: Amount::from_sat(5),
            script_pubkey: Script::from_bytes(vec![0x6a, 0x01]),
        };
        blocks.push(op_return_block);
        for block in &blocks {
            let txids: Vec<Txid> = block.txs.iter().map(|tx| tx.txid()).collect();
            let mut created: Vec<OutPoint> = Vec::new();
            for (tx, txid) in block.txs.iter().zip(txids.iter()) {
                for (index, _) in tx.outputs.iter().enumerate() {
                    let vout = u32::try_from(index).map_err(|_| {
                        TestError::Missing("block output index exceeds the vout range")
                    })?;
                    created.push(OutPoint::new(*txid, vout));
                }
            }
            let mut prior: hashbrown::HashSet<Txid> = hashbrown::HashSet::new();
            let mut same_block: hashbrown::HashSet<OutPoint> = hashbrown::HashSet::new();
            let mut external: Vec<OutPoint> = Vec::new();
            for (tx, txid) in block.txs.iter().zip(txids.iter()) {
                if tx.is_coinbase() {
                    prior.insert(*txid);
                    continue;
                }
                for input in &tx.inputs {
                    let prev = input.previous_output;
                    if prior.contains(&prev.txid) {
                        same_block.insert(prev);
                    } else if !external.contains(&prev) {
                        external.push(prev);
                    }
                }
                prior.insert(*txid);
            }
            let mut undo = UndoBatch::empty();
            for prev in &external {
                undo.restore(UtxoAdd::new(*prev, coin(90), false, HEIGHT - 1));
            }
            let hash = block.block_hash().0;
            let bytes = crate::utxo::undo_codec::encode(&undo, hash);
            let mut expected_len = 37_usize;
            for add in undo.restores() {
                let script_len = add.txout.script_pubkey.len();
                let varint_len = if script_len < 253 { 1 } else { 3 };
                expected_len = expected_len
                    .saturating_add(36)
                    .saturating_add(8)
                    .saturating_add(varint_len)
                    .saturating_add(script_len)
                    .saturating_add(1)
                    .saturating_add(4);
            }
            assert_eq!(bytes.len(), expected_len);
            for point in &created {
                if undo.restores().iter().any(|add| add.outpoint == *point) {
                    continue;
                }
                let mut needle = [0_u8; 36];
                needle[..32].copy_from_slice(point.txid.as_bytes());
                needle[32..].copy_from_slice(&point.vout.to_le_bytes());
                let mut found = false;
                if bytes.len() >= needle.len() {
                    for window in 0..=bytes.len() - needle.len() {
                        if bytes[window..window + needle.len()] == needle {
                            found = true;
                            break;
                        }
                    }
                }
                assert!(!found, "encoded record holds a created outpoint");
            }
            let decoded = decode_undo_record_for_block(&bytes, block)?;
            assert_eq!(decoded.restores().len(), undo.restores().len());
            for (got, want) in decoded.restores().iter().zip(undo.restores()) {
                assert_eq!(got.outpoint, want.outpoint);
                assert_eq!(got.txout, want.txout);
                assert_eq!(got.coinbase, want.coinbase);
                assert_eq!(got.height, want.height);
            }
            let mut retained: hashbrown::HashSet<OutPoint> = hashbrown::HashSet::new();
            for (tx, txid) in block.txs.iter().zip(txids.iter()) {
                for (index, txout) in tx.outputs.iter().enumerate() {
                    let vout = u32::try_from(index).map_err(|_| {
                        TestError::Missing("block output index exceeds the vout range")
                    })?;
                    let unstorable = txout.script_pubkey.first() == Some(&0x6a)
                        || txout.script_pubkey.len() > MAX_SCRIPT_SIZE;
                    if !unstorable {
                        retained.insert(OutPoint::new(*txid, vout));
                    }
                }
            }
            let restored: hashbrown::HashSet<OutPoint> =
                undo.restores().iter().map(|add| add.outpoint).collect();
            let mut expected_removes: Vec<OutPoint> = retained
                .into_iter()
                .filter(|point| !same_block.contains(point) && !restored.contains(point))
                .collect();
            expected_removes.sort_by(|a, b| {
                let a_txid = a.txid;
                let b_txid = b.txid;
                let a_vout = a.vout;
                let b_vout = b.vout;
                a_txid
                    .as_bytes()
                    .cmp(b_txid.as_bytes())
                    .then_with(|| a_vout.cmp(&b_vout))
            });
            let mut got_removes: Vec<OutPoint> = decoded.removes().to_vec();
            got_removes.sort_by(|a, b| {
                let a_txid = a.txid;
                let b_txid = b.txid;
                let a_vout = a.vout;
                let b_vout = b.vout;
                a_txid
                    .as_bytes()
                    .cmp(b_txid.as_bytes())
                    .then_with(|| a_vout.cmp(&b_vout))
            });
            assert_eq!(got_removes, expected_removes);
        }
        Ok(())
    }
}
