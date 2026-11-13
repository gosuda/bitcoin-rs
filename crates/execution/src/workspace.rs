//! Window-local coin state and window commit construction (WIN-01..WIN-07).
//!
//! Consistency contract: the workspace is a linearizable read view over the
//! published coin store plus the uncommitted window prefix. Publication of a
//! window prefix is linearized by the durable head batch; cache install is
//! strictly ordered after it (CMT-02, CMT-03).

use std::collections::BTreeMap;

use bitcoin_rs_consensus::primitives::{Amount, Block, Hash256, OutPoint, TxOut, Txid};
use bitcoin_rs_storage::utxo::UtxoCoin;
use bitcoin_rs_storage::utxo::contract::OutputSource;
use bitcoin_rs_storage::utxo::record::{OwnedUtxoOut, UtxoRecord};
use bitcoin_rs_storage::utxo::set::UtxoError;
use bitcoin_rs_storage::{CoinKey, CoinStore, StorageError, WindowDelta};
use bytes::Bytes;
use hashbrown::{HashMap, HashSet};
#[cfg(test)]
thread_local! {
    static FOLD_EVENTS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn count_fold_event() {
    FOLD_EVENTS.with(|events| events.set(events.get() + 1));
}

#[cfg(test)]
thread_local! {
    static FOLD_VISITS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn count_fold_visit() {
    FOLD_VISITS.with(|visits| visits.set(visits.get() + 1));
}

#[cfg(not(test))]
const fn count_fold_visit() {}
#[cfg(not(test))]
const fn count_fold_event() {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CreatedOwned {
    pub txid: Txid,
    pub vout: u32,
    pub coinbase: bool,
    pub height: u32,
    pub value: u64,
    pub script_pubkey: Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UndoCoin {
    pub outpoint: OutPoint,
    pub txout: TxOut,
    pub height: u32,
    pub coinbase: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BlockTransition {
    pub height: u32,
    pub hash: Hash256,
    pub prev_hash: Hash256,
    pub created: Vec<CreatedOwned>,
    pub spent_outpoints: Vec<OutPoint>,
    pub bip30_overwrites: Vec<UndoCoin>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct LiveOut {
    pub vout: u32,
    pub value: u64,
    pub script_pubkey: Bytes,
    pub coinbase: bool,
    pub height: u32,
    pub spent: bool,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum WindowWorkspaceError {
    #[error("block has {transactions} transactions but {txids} txids were supplied")]
    TxidCountMismatch { transactions: usize, txids: usize },
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum WindowReadError {
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Record(#[from] UtxoError),
}

pub(crate) struct WindowWorkspace {
    max_script_size: usize,
    live: HashMap<Txid, Vec<LiveOut>>,
    spent: HashSet<OutPoint>,
    transitions: Vec<BlockTransition>,
    resolved_external: HashMap<OutPoint, UtxoCoin>,
    initial_records: HashMap<Txid, Option<UtxoRecord>>,
    flushed_transitions: usize,
    touched: HashMap<Txid, Vec<usize>>,
    engine_presence: HashMap<Txid, bool>,
    coin_cursor: usize,
    coin_entries: HashMap<Txid, usize>,
    coin_bytes: usize,
    coin_states: HashMap<Txid, BTreeMap<u32, OwnedUtxoOut>>,
}

impl WindowWorkspace {
    #[must_use]
    pub(crate) fn new(max_script_size: usize) -> Self {
        Self {
            max_script_size,
            live: HashMap::new(),
            spent: HashSet::new(),
            transitions: Vec::new(),
            resolved_external: HashMap::new(),
            initial_records: HashMap::new(),
            flushed_transitions: 0,
            touched: HashMap::new(),
            engine_presence: HashMap::new(),
            coin_cursor: 0,
            coin_entries: HashMap::new(),
            coin_bytes: 0,
            coin_states: HashMap::new(),
        }
    }
    #[must_use]
    pub(crate) fn has_live_outputs(&self, txid: Txid) -> bool {
        if self
            .live
            .get(&txid)
            .is_some_and(|outs| outs.iter().any(|out| !out.spent))
        {
            return true;
        }
        match self.initial_records.get(&txid) {
            Some(Some(record)) => record
                .outputs()
                .any(|out| !self.spent.contains(&OutPoint::new(txid, out.vout))),
            _ => false,
        }
    }

    #[must_use]
    pub(crate) fn unflushed_transitions(&self) -> usize {
        self.transitions.len() - self.flushed_transitions
    }

    #[must_use]
    pub(crate) fn covers(&self, blocks: usize) -> bool {
        self.unflushed_transitions() >= blocks
    }

    pub(crate) fn build_flush_delta(
        &mut self,
        pending_count: usize,
    ) -> Result<bitcoin_rs_storage::WindowDelta, UtxoError> {
        let start = self.flushed_transitions;
        let end = (start + pending_count).min(self.transitions.len());
        let prefix = &self.transitions[start..end];
        let delta = Self::build_window_delta(prefix, &self.initial_records)?;
        merge_delta_records(&mut self.initial_records, delta.records.iter())?;
        self.flushed_transitions = end;
        self.coin_cursor = end;
        self.coin_entries.clear();
        self.coin_bytes = 0;
        self.coin_states.clear();
        Ok(delta)
    }

    pub(crate) fn staged_coin_bytes(&mut self, pending_count: usize) -> Result<usize, UtxoError> {
        let target = (self.flushed_transitions + pending_count).min(self.transitions.len());
        while self.coin_cursor < target {
            let index = self.coin_cursor;
            Self::apply_transition(
                &mut self.coin_states,
                &self.initial_records,
                &self.transitions[index],
            );
            let mut seen = HashSet::new();
            for txid in transition_txids(&self.transitions[index]) {
                if !seen.insert(txid) {
                    continue;
                }
                let bytes = {
                    let current: Vec<_> = self
                        .coin_states
                        .get(&txid)
                        .into_iter()
                        .flat_map(|outputs| outputs.values().cloned())
                        .collect();
                    let entry = txid_entry(&self.initial_records, txid, &current)?;
                    entry.as_ref().map_or(0, entry_encoded_len)
                };
                let previous = self.coin_entries.insert(txid, bytes).unwrap_or(0);
                self.coin_bytes = self
                    .coin_bytes
                    .saturating_sub(previous)
                    .saturating_add(bytes);
            }
            self.coin_cursor += 1;
        }
        Ok(self.coin_bytes)
    }

    pub(crate) fn resolve_external_batch(
        &mut self,
        coin_store: &CoinStore,
        outpoints: &[OutPoint],
    ) -> Result<(), WindowReadError> {
        let needed_txids = unresolved_txids(self, outpoints);
        if !needed_txids.is_empty() {
            let coin_keys: Vec<CoinKey> = needed_txids
                .iter()
                .map(|txid| CoinKey(txid.0.to_le_bytes()))
                .collect();
            let records = coin_store.multi_get(&coin_keys)?;
            install_resolved_records(self, &needed_txids, records)?;
        }
        Ok(())
    }

    pub(crate) fn advance(
        &mut self,
        block: &Block,
        txids: &[Txid],
        height: u32,
        same_block_spent: &HashSet<OutPoint>,
    ) -> Result<(), WindowWorkspaceError> {
        if block.txs.len() != txids.len() {
            return Err(WindowWorkspaceError::TxidCountMismatch {
                transactions: block.txs.len(),
                txids: txids.len(),
            });
        }
        if height == 0 {
            return Ok(());
        }

        let is_bip30 = bitcoin_rs_consensus::bip30::is_bip30_exception(
            height,
            Hash256::from(block.block_hash()),
        );
        let mut created_owned = Vec::new();
        let mut spent_outpoints = Vec::new();
        let mut bip30_overwrites = Vec::new();

        for (tx, &txid) in block.txs.iter().zip(txids) {
            if is_bip30 {
                record_bip30_overwrites(
                    &mut self.live,
                    &self.initial_records,
                    &self.spent,
                    txid,
                    &mut bip30_overwrites,
                );
            }

            let (created, live_outs) = collect_created_outputs(
                tx,
                txid,
                height,
                coinbase(tx),
                self.max_script_size,
                same_block_spent,
            );
            created_owned.extend(created);
            if !live_outs.is_empty() {
                for out in &live_outs {
                    self.spent.remove(&OutPoint::new(txid, out.vout));
                }
                self.live.insert(txid, live_outs);
            }

            if !coinbase(tx) {
                for input in &tx.inputs {
                    let prev = input.previous_output;
                    if same_block_spent.contains(&prev) {
                        continue;
                    }
                    self.spent.insert(prev);
                    spent_outpoints.push(prev);
                    spend_input_in_workspace(&mut self.live, prev);
                }
            }
        }

        let transition = BlockTransition {
            height,
            hash: Hash256::from(block.block_hash()),
            prev_hash: block.header.prev_blockhash.into(),
            created: created_owned,
            spent_outpoints,
            bip30_overwrites,
        };
        index_transition(&mut self.touched, self.transitions.len(), &transition);
        self.transitions.push(transition);

        Ok(())
    }

    /// Returns the duplicate-probe answer for `txid` at `height` when the
    /// uncommitted window prefix below that height determines it, and `None`
    /// when the engine coin store stays authoritative (`WIN-07`).
    #[must_use]
    pub(crate) fn staged_coin_presence_before(&self, txid: Txid, height: u32) -> Option<bool> {
        let mut tracked = self.initial_records.contains_key(&txid);
        let mut unspent: HashSet<u32> = HashSet::new();
        if let Some(Some(record)) = self.initial_records.get(&txid) {
            unspent.extend(record.outputs().map(|output| output.vout));
        }
        for &index in self.touched.get(&txid).into_iter().flatten() {
            if index < self.flushed_transitions {
                continue;
            }
            let Some(transition) = self.transitions.get(index) else {
                continue;
            };
            if transition.height >= height {
                continue;
            }
            if transition
                .bip30_overwrites
                .iter()
                .any(|overwrite| overwrite.outpoint.txid == txid)
            {
                unspent.clear();
                tracked = true;
            }
            for created in &transition.created {
                if created.txid == txid {
                    unspent.insert(created.vout);
                    tracked = true;
                }
            }
            for spent in &transition.spent_outpoints {
                if spent.txid == txid {
                    let vout = spent.vout;
                    unspent.remove(&vout);
                    tracked = true;
                }
            }
        }
        tracked.then_some(!unspent.is_empty())
    }

    pub(crate) fn resolve_engine_presence(
        &mut self,
        coin_store: &CoinStore,
        txids: &[Txid],
    ) -> Result<(), StorageError> {
        let keys: Vec<CoinKey> = txids
            .iter()
            .map(|txid| CoinKey(txid.0.to_le_bytes()))
            .collect();
        let records = coin_store.multi_get(&keys)?;
        for (txid, record) in txids.iter().zip(records) {
            self.engine_presence.insert(*txid, record.is_some());
        }
        Ok(())
    }

    #[must_use]
    pub(crate) fn resolved_engine_presence(&self, txid: Txid) -> Option<bool> {
        self.engine_presence.get(&txid).copied()
    }

    #[must_use]
    pub(crate) fn coin_presence_before(&self, txid: Txid, height: u32) -> Option<bool> {
        self.staged_coin_presence_before(txid, height)
            .or_else(|| self.resolved_engine_presence(txid))
    }

    pub(crate) fn build_window_delta(
        prefix: &[BlockTransition],
        initial_records: &HashMap<Txid, Option<UtxoRecord>>,
    ) -> Result<WindowDelta, UtxoError> {
        let mut states: HashMap<Txid, BTreeMap<u32, OwnedUtxoOut>> = HashMap::new();
        for transition in prefix {
            Self::apply_transition(&mut states, initial_records, transition);
        }
        let mut delta = WindowDelta::default();
        for (txid, current_outputs) in states {
            let current_outputs: Vec<_> = current_outputs.into_values().collect();
            if let Some((key, record)) = txid_entry(initial_records, txid, &current_outputs)? {
                delta.push_final(key, record);
            }
        }
        delta.records.sort_by_key(|(key, _)| *key);
        Ok(delta)
    }

    fn apply_transition(
        states: &mut HashMap<Txid, BTreeMap<u32, OwnedUtxoOut>>,
        initial_records: &HashMap<Txid, Option<UtxoRecord>>,
        transition: &BlockTransition,
    ) {
        let mut seen = HashSet::new();
        for txid in transition_txids(transition) {
            if seen.insert(txid) {
                count_fold_event();
            }
        }
        for overwrite in &transition.bip30_overwrites {
            count_fold_visit();
            outputs_for(states, initial_records, overwrite.outpoint.txid).clear();
        }
        for created in &transition.created {
            count_fold_visit();
            let outputs = outputs_for(states, initial_records, created.txid);
            outputs.insert(
                created.vout,
                OwnedUtxoOut {
                    vout: created.vout,
                    value: created.value,
                    script_pubkey: created.script_pubkey.to_vec(),
                    coinbase: created.coinbase,
                    height: created.height,
                },
            );
        }
        for spent in &transition.spent_outpoints {
            count_fold_visit();
            let vout = spent.vout;
            outputs_for(states, initial_records, spent.txid).remove(&vout);
        }
    }
}

fn coinbase(tx: &bitcoin_rs_consensus::primitives::Tx) -> bool {
    tx.is_coinbase()
}

fn collect_created_outputs(
    tx: &bitcoin_rs_consensus::primitives::Tx,
    txid: Txid,
    height: u32,
    coinbase: bool,
    max_script_size: usize,
    same_block_spent: &HashSet<OutPoint>,
) -> (Vec<CreatedOwned>, Vec<LiveOut>) {
    let mut created = Vec::new();
    let mut live_outs = Vec::new();
    for (vout, txout) in (0u32..).zip(&tx.outputs) {
        let script = &txout.script_pubkey;
        let outpoint = OutPoint::new(txid, vout);
        if script.first() == Some(&0x6a)
            || script.len() > max_script_size
            || same_block_spent.contains(&outpoint)
        {
            continue;
        }
        let script_pubkey = Bytes::copy_from_slice(script.as_bytes());
        let value = txout.value.to_sat();
        created.push(CreatedOwned {
            txid,
            vout,
            coinbase,
            height,
            value,
            script_pubkey: script_pubkey.clone(),
        });
        live_outs.push(LiveOut {
            vout,
            value,
            script_pubkey,
            coinbase,
            height,
            spent: false,
        });
    }
    (created, live_outs)
}

fn record_bip30_overwrites(
    live: &mut HashMap<Txid, Vec<LiveOut>>,
    initial_records: &HashMap<Txid, Option<UtxoRecord>>,
    spent: &HashSet<OutPoint>,
    txid: Txid,
    overwrites: &mut Vec<UndoCoin>,
) {
    let removed = live.remove(&txid);
    let prior_outputs: Vec<LiveOut> = match removed {
        Some(outs) => outs,
        None => match initial_records.get(&txid) {
            Some(Some(record)) => record
                .outputs()
                .map(|out| LiveOut {
                    vout: out.vout,
                    value: out.value,
                    script_pubkey: out.script_pubkey.to_vec().into(),
                    coinbase: out.coinbase,
                    height: out.height,
                    spent: spent.contains(&OutPoint::new(txid, out.vout)),
                })
                .collect(),
            _ => Vec::new(),
        },
    };
    for prior in prior_outputs {
        if prior.spent {
            continue;
        }
        overwrites.push(UndoCoin {
            outpoint: OutPoint::new(txid, prior.vout),
            txout: TxOut {
                value: Amount::from_sat(prior.value),
                script_pubkey: prior.script_pubkey.to_vec().into(),
            },
            height: prior.height,
            coinbase: prior.coinbase,
        });
    }
}

fn spend_input_in_workspace(live: &mut HashMap<Txid, Vec<LiveOut>>, prev: OutPoint) {
    if let Some(outs) = live.get_mut(&prev.txid) {
        if let Some(out) = outs.iter_mut().find(|o| o.vout == prev.vout && !o.spent) {
            out.spent = true;
        }
    }
}
fn unresolved_txids(workspace: &WindowWorkspace, outpoints: &[OutPoint]) -> Vec<Txid> {
    let mut needed: Vec<Txid> = outpoints
        .iter()
        .filter(|op| {
            !workspace.spent.contains(*op)
                && !workspace.live.contains_key(&op.txid)
                && !workspace.resolved_external.contains_key(*op)
        })
        .map(|op| op.txid)
        .collect();
    needed.sort_unstable();
    needed.dedup();
    needed
}

fn install_resolved_records(
    workspace: &mut WindowWorkspace,
    txids: &[Txid],
    records: Vec<Option<Bytes>>,
) -> Result<(), UtxoError> {
    for (txid, record_opt) in txids.iter().zip(records) {
        match record_opt {
            Some(record_bytes) => {
                let record = UtxoRecord::from_encoded(record_bytes.to_vec().into_boxed_slice())?;
                for out in record.outputs() {
                    let outpoint = OutPoint::new(*txid, out.vout);
                    workspace.resolved_external.insert(
                        outpoint,
                        UtxoCoin {
                            outpoint,
                            txout: TxOut {
                                value: Amount::from_sat(out.value),
                                script_pubkey: out.script_pubkey.to_vec().into(),
                            },
                            coinbase: out.coinbase,
                            height: out.height,
                        },
                    );
                }
                workspace
                    .initial_records
                    .entry(*txid)
                    .or_insert(Some(record));
            }
            None => {
                workspace.initial_records.entry(*txid).or_insert(None);
            }
        }
    }
    Ok(())
}

fn transition_txids(transition: &BlockTransition) -> impl Iterator<Item = Txid> + '_ {
    transition
        .created
        .iter()
        .map(|created| created.txid)
        .chain(transition.spent_outpoints.iter().map(|spent| spent.txid))
        .chain(
            transition
                .bip30_overwrites
                .iter()
                .map(|overwrite| overwrite.outpoint.txid),
        )
}

fn outputs_for<'s>(
    states: &'s mut HashMap<Txid, BTreeMap<u32, OwnedUtxoOut>>,
    initial_records: &HashMap<Txid, Option<UtxoRecord>>,
    txid: Txid,
) -> &'s mut BTreeMap<u32, OwnedUtxoOut> {
    states
        .entry(txid)
        .or_insert_with(|| initial_outputs_for_txid(initial_records, txid))
}

fn index_transition(
    touched: &mut HashMap<Txid, Vec<usize>>,
    index: usize,
    transition: &BlockTransition,
) {
    for txid in transition_txids(transition) {
        let entries = touched.entry(txid).or_default();
        if entries.last() != Some(&index) {
            entries.push(index);
        }
    }
}

type CoinEntry = (CoinKey, Option<Bytes>);

fn txid_entry(
    initial_records: &HashMap<Txid, Option<UtxoRecord>>,
    txid: Txid,
    current_outputs: &[OwnedUtxoOut],
) -> Result<Option<CoinEntry>, UtxoError> {
    let existed_before = initial_records
        .get(&txid)
        .and_then(Option::as_ref)
        .is_some();
    let key = CoinKey(txid.0.to_le_bytes());
    match (existed_before, current_outputs.is_empty()) {
        (false, true) => Ok(None),
        (true, true) => Ok(Some((key, None))),
        (_, false) => {
            let record = UtxoRecord::from_owned_outputs(
                Hash256::from_le_bytes(&txid.0.to_le_bytes()),
                current_outputs,
            )?;
            Ok(Some((key, Some(Bytes::copy_from_slice(record.bytes())))))
        }
    }
}

fn entry_encoded_len(entry: &CoinEntry) -> usize {
    entry.0.as_bytes().len() + entry.1.as_ref().map_or(0, Bytes::len)
}

fn merge_delta_records<'r>(
    initial_records: &mut HashMap<Txid, Option<UtxoRecord>>,
    records: impl Iterator<Item = &'r (CoinKey, Option<Bytes>)>,
) -> Result<(), UtxoError> {
    for (key, record) in records {
        let txid = Txid(Hash256::from_le_bytes(key.as_bytes()));
        let decoded = match record {
            Some(bytes) => Some(UtxoRecord::from_encoded(bytes.to_vec().into_boxed_slice())?),
            None => None,
        };
        initial_records.insert(txid, decoded);
    }
    Ok(())
}

fn initial_outputs_for_txid(
    initial_records: &HashMap<Txid, Option<UtxoRecord>>,
    txid: Txid,
) -> BTreeMap<u32, OwnedUtxoOut> {
    match initial_records.get(&txid) {
        Some(Some(record)) => record
            .outputs()
            .map(|out| {
                (
                    out.vout,
                    OwnedUtxoOut {
                        vout: out.vout,
                        value: out.value,
                        script_pubkey: out.script_pubkey.to_vec(),
                        coinbase: out.coinbase,
                        height: out.height,
                    },
                )
            })
            .collect(),
        _ => BTreeMap::new(),
    }
}

impl OutputSource for WindowWorkspace {
    fn get_entry(&self, outpoint: &OutPoint) -> Option<UtxoCoin> {
        if self.spent.contains(outpoint) {
            return None;
        }
        if let Some(outs) = self.live.get(&outpoint.txid) {
            if let Some(out) = outs
                .iter()
                .find(|out| out.vout == outpoint.vout && !out.spent)
            {
                return Some(UtxoCoin {
                    outpoint: *outpoint,
                    txout: TxOut {
                        value: Amount::from_sat(out.value),
                        script_pubkey: out.script_pubkey.clone().to_vec().into(),
                    },
                    coinbase: out.coinbase,
                    height: out.height,
                });
            }
        }
        self.resolved_external.get(outpoint).cloned()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use bytes::Bytes;

    use super::{
        Amount, BlockTransition, CoinKey, CreatedOwned, FOLD_VISITS, Hash256, HashMap, OutPoint,
        OwnedUtxoOut, TxOut, Txid, UndoCoin, UtxoError, UtxoRecord, WindowWorkspace,
        merge_delta_records,
    };

    type Outputs = std::collections::BTreeMap<u32, (u64, Vec<u8>, bool, u32)>;
    type Model = std::collections::BTreeMap<(u32, u32), (u64, Vec<u8>, bool, u32)>;

    const POOL: u32 = 5;
    const VOUTS: u32 = 4;

    struct Lcg(u64);

    impl Lcg {
        fn below(&mut self, bound: u32) -> u32 {
            self.0 = self
                .0
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            u32::try_from((self.0 >> 33) % u64::from(bound)).expect("below the bound")
        }
    }

    fn indexed_txid(index: u32) -> Txid {
        let mut bytes = [0_u8; 32];
        bytes[..4].copy_from_slice(&index.to_le_bytes());
        Txid(Hash256::from_le_bytes(&bytes))
    }

    fn index_of(key: &CoinKey) -> u32 {
        let bytes = key.as_bytes();
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
    }

    fn empty_transition(height: u32) -> BlockTransition {
        BlockTransition {
            height,
            hash: Hash256::from_le_bytes(&[0xb0; 32]),
            prev_hash: Hash256::from_le_bytes(&[0xb1; 32]),
            created: Vec::new(),
            spent_outpoints: Vec::new(),
            bip30_overwrites: Vec::new(),
        }
    }

    fn created_output(index: u32, vout: u32, value: u64, height: u32) -> CreatedOwned {
        CreatedOwned {
            txid: indexed_txid(index),
            vout,
            coinbase: value.is_multiple_of(2),
            height,
            value,
            script_pubkey: Bytes::from(vec![0x51, u8::try_from(value % 200).expect("byte")]),
        }
    }

    fn overwrite_of(index: u32) -> UndoCoin {
        UndoCoin {
            outpoint: OutPoint::new(indexed_txid(index), 0),
            txout: TxOut {
                value: Amount::from_sat(1),
                script_pubkey: vec![0x51].into(),
            },
            height: 1,
            coinbase: true,
        }
    }

    fn model_apply(model: &mut Model, transition: &BlockTransition) {
        for overwrite in &transition.bip30_overwrites {
            let index = index_of(&CoinKey(overwrite.outpoint.txid.0.to_le_bytes()));
            model.retain(|(owner, _), _| *owner != index);
        }
        for created in &transition.created {
            let index = index_of(&CoinKey(created.txid.0.to_le_bytes()));
            model.insert(
                (index, created.vout),
                (
                    created.value,
                    created.script_pubkey.to_vec(),
                    created.coinbase,
                    created.height,
                ),
            );
        }
        for spent in &transition.spent_outpoints {
            let index = index_of(&CoinKey(spent.txid.0.to_le_bytes()));
            model.remove(&(index, spent.vout));
        }
    }

    fn outputs_of(record: &UtxoRecord) -> Outputs {
        record
            .outputs()
            .map(|out| {
                (
                    out.vout,
                    (
                        out.value,
                        out.script_pubkey.to_vec(),
                        out.coinbase,
                        out.height,
                    ),
                )
            })
            .collect()
    }

    fn model_outputs(model: &Model, index: u32) -> Outputs {
        model
            .iter()
            .filter(|((owner, _), _)| *owner == index)
            .map(|((_, vout), out)| (*vout, out.clone()))
            .collect()
    }

    fn random_initial(
        rng: &mut Lcg,
        value: &mut u64,
    ) -> (HashMap<Txid, Option<UtxoRecord>>, Model) {
        let mut records = HashMap::new();
        let mut model = Model::new();
        for index in 0..POOL {
            if rng.below(2) == 0 {
                continue;
            }
            let mut outs = Vec::new();
            for vout in 0..VOUTS {
                if rng.below(2) == 0 {
                    *value += 1;
                    outs.push(OwnedUtxoOut {
                        vout,
                        value: *value,
                        script_pubkey: vec![0x52],
                        coinbase: false,
                        height: 3,
                    });
                    model.insert((index, vout), (*value, vec![0x52], false, 3));
                }
            }
            if !outs.is_empty() {
                let record = UtxoRecord::from_owned_outputs(indexed_txid(index).0, &outs)
                    .expect("initial record");
                records.insert(indexed_txid(index), Some(record));
            }
        }
        (records, model)
    }

    fn random_transition(rng: &mut Lcg, value: &mut u64, height: u32) -> BlockTransition {
        let mut transition = empty_transition(height);
        for index in 0..POOL {
            if rng.below(6) == 0 {
                transition.bip30_overwrites.push(overwrite_of(index));
            }
        }
        for _ in 0..rng.below(5) {
            *value += 1;
            let (index, vout) = (rng.below(POOL), rng.below(VOUTS));
            transition
                .created
                .push(created_output(index, vout, *value, height));
        }
        for _ in 0..rng.below(5) {
            let (index, vout) = (rng.below(POOL), rng.below(VOUTS));
            transition
                .spent_outpoints
                .push(OutPoint::new(indexed_txid(index), vout));
        }
        transition
    }

    fn touched_indexes(transitions: &[BlockTransition]) -> std::collections::BTreeSet<u32> {
        let mut touched = std::collections::BTreeSet::new();
        for transition in transitions {
            for overwrite in &transition.bip30_overwrites {
                touched.insert(index_of(&CoinKey(overwrite.outpoint.txid.0.to_le_bytes())));
            }
            for created in &transition.created {
                touched.insert(index_of(&CoinKey(created.txid.0.to_le_bytes())));
            }
            for spent in &transition.spent_outpoints {
                touched.insert(index_of(&CoinKey(spent.txid.0.to_le_bytes())));
            }
        }
        touched
    }

    // WIN-03, WIN-07
    #[test]
    fn window_delta_matches_an_outpoint_model_across_overwrites_and_flushes() {
        let mut rng = Lcg(0x5eed);
        let mut value = 0_u64;
        for round in 0..300_u32 {
            let (initial, seed_model) = random_initial(&mut rng, &mut value);
            let count = 1 + rng.below(8);
            let transitions: Vec<BlockTransition> = (1..=count)
                .map(|height| random_transition(&mut rng, &mut value, height))
                .collect();
            let mut model = seed_model.clone();
            for transition in &transitions {
                model_apply(&mut model, transition);
            }

            let delta =
                WindowWorkspace::build_window_delta(&transitions, &initial).expect("window delta");
            assert!(
                delta.records.windows(2).all(|pair| pair[0].0 < pair[1].0),
                "round {round}: records must be strictly sorted by key"
            );
            let mut expected: std::collections::BTreeMap<u32, Option<Outputs>> =
                std::collections::BTreeMap::new();
            for index in touched_indexes(&transitions) {
                let outputs = model_outputs(&model, index);
                let existed = initial
                    .get(&indexed_txid(index))
                    .and_then(Option::as_ref)
                    .is_some();
                if !outputs.is_empty() {
                    expected.insert(index, Some(outputs));
                } else if existed {
                    expected.insert(index, None);
                }
            }
            let actual: std::collections::BTreeMap<u32, Option<Outputs>> = delta
                .records
                .iter()
                .map(|(key, bytes)| {
                    let outputs = bytes.as_ref().map(|bytes| {
                        outputs_of(
                            &UtxoRecord::from_encoded(bytes.to_vec().into_boxed_slice())
                                .expect("record"),
                        )
                    });
                    (index_of(key), outputs)
                })
                .collect();
            assert_eq!(
                actual, expected,
                "round {round}: delta diverged from the model"
            );

            let split = usize::try_from(rng.below(count + 1)).expect("split");
            let mut state = initial.clone();
            for part in [&transitions[..split], &transitions[split..]] {
                let delta = WindowWorkspace::build_window_delta(part, &state).expect("part delta");
                merge_delta_records(&mut state, delta.records.iter()).expect("merge");
            }
            for index in 0..POOL {
                let held = state
                    .get(&indexed_txid(index))
                    .and_then(Option::as_ref)
                    .map(outputs_of)
                    .unwrap_or_default();
                assert_eq!(
                    held,
                    model_outputs(&model, index),
                    "round {round}: state after flushing at {split} diverged for txid {index}"
                );
            }
        }
    }

    // WIN-07
    #[test]
    fn repeated_overwrites_keep_only_the_last_creations() {
        let mut initial = HashMap::new();
        let seeded = [
            OwnedUtxoOut {
                vout: 0,
                value: 900,
                script_pubkey: vec![0x52],
                coinbase: true,
                height: 1,
            },
            OwnedUtxoOut {
                vout: 1,
                value: 901,
                script_pubkey: vec![0x52],
                coinbase: true,
                height: 1,
            },
        ];
        initial.insert(
            indexed_txid(0),
            Some(UtxoRecord::from_owned_outputs(indexed_txid(0).0, &seeded).expect("seed")),
        );

        let mut first = empty_transition(2);
        first.bip30_overwrites.push(overwrite_of(0));
        first.created.push(created_output(0, 0, 10, 2));
        let mut second = empty_transition(3);
        second
            .spent_outpoints
            .push(OutPoint::new(indexed_txid(0), 0));
        let mut third = empty_transition(4);
        third.created.push(created_output(0, 0, 11, 4));
        third.created.push(created_output(0, 2, 12, 4));
        let mut fourth = empty_transition(5);
        fourth.bip30_overwrites.push(overwrite_of(0));
        let mut fifth = empty_transition(6);
        fifth.created.push(created_output(0, 1, 13, 6));
        let transitions = [first, second, third, fourth, fifth];

        for split in 0..=transitions.len() {
            let mut state = initial.clone();
            for part in [&transitions[..split], &transitions[split..]] {
                let delta = WindowWorkspace::build_window_delta(part, &state).expect("part delta");
                merge_delta_records(&mut state, delta.records.iter()).expect("merge");
            }
            let held = state
                .get(&indexed_txid(0))
                .and_then(Option::as_ref)
                .map(outputs_of)
                .expect("the txid survives with its last creation");
            let expected: Outputs = [(1, (13, vec![0x51, 13], false, 6))].into_iter().collect();
            assert_eq!(held, expected, "flush split at {split}");
        }
    }

    // WIN-03
    #[test]
    fn window_delta_visits_each_transition_entry_once() {
        let count = 200_u32;
        let mut transitions = Vec::new();
        for index in 0..count {
            let mut transition = empty_transition(index + 1);
            transition
                .created
                .push(created_output(index, 0, u64::from(index) + 1, index + 1));
            if index > 0 {
                transition
                    .spent_outpoints
                    .push(OutPoint::new(indexed_txid(index - 1), 0));
            }
            if index % 10 == 0 {
                transition.bip30_overwrites.push(overwrite_of(index));
            }
            transitions.push(transition);
        }
        let entries: usize = transitions
            .iter()
            .map(|transition| {
                transition.created.len()
                    + transition.spent_outpoints.len()
                    + transition.bip30_overwrites.len()
            })
            .sum();

        FOLD_VISITS.with(|visits| visits.set(0));
        let delta = WindowWorkspace::build_window_delta(&transitions, &HashMap::new())
            .expect("window delta");

        assert_eq!(
            delta.records.len(),
            1,
            "only the last creation stays unspent"
        );
        assert_eq!(
            FOLD_VISITS.with(std::cell::Cell::get),
            entries,
            "every created, spent and overwrite entry is visited once, not once per touched txid"
        );
    }
    // WIN-05
    #[test]
    fn corrupt_delta_record_is_a_typed_error() {
        let mut initial_records = HashMap::new();
        let records = [(CoinKey([0x11; 32]), Some(Bytes::from_static(&[0xff; 5])))];
        assert!(matches!(
            merge_delta_records(&mut initial_records, records.iter()),
            Err(UtxoError::CorruptRecord)
        ));
        assert!(
            initial_records.is_empty(),
            "a corrupt record must not be stored as an absent coin"
        );
    }

    #[test]
    fn recreated_outpoint_is_readable_and_its_next_spend_undo_names_the_new_incarnation() {
        use crate::chain::regtest_fixture::{coinbase, mined_block_with_prev_hash};
        use bitcoin_rs_consensus::primitives::Network;
        use bitcoin_rs_storage::KvStore as _;
        use bitcoin_rs_storage::utxo::contract::OutputSource;
        use hashbrown::HashSet;
        use std::sync::Arc;

        let original = coinbase(1);
        let txid = original.txid();
        let outpoint = OutPoint::new(txid, 0);
        let mut spend = coinbase(2);
        spend.inputs[0].previous_output = outpoint;
        let mut workspace = WindowWorkspace::new(bitcoin_rs_consensus::MAX_SCRIPT_SIZE);
        let mut prev = Network::Regtest.genesis_block().block_hash();
        for (height, tx) in [(1, original.clone()), (101, spend.clone()), (102, original)] {
            let txids = [tx.txid()];
            let block = mined_block_with_prev_hash(prev, height, vec![tx]).expect("fixture block");
            workspace
                .advance(&block, &txids, height, &HashSet::new())
                .expect("advance");
            prev = block.block_hash();
            if height == 101 {
                assert_eq!(workspace.get_entry(&outpoint), None);
            }
        }

        let replacement = workspace
            .get_entry(&outpoint)
            .expect("recreated output is live");
        assert_eq!(replacement.height, 102);
        assert!(replacement.coinbase);
        assert_eq!(replacement.txout, coinbase(1).outputs[0]);
        let delta = workspace.build_flush_delta(3).expect("flush recreation");
        let bytes = delta
            .records
            .iter()
            .find(|(key, _)| *key == CoinKey(txid.0.to_le_bytes()))
            .and_then(|(_, bytes)| bytes.as_ref())
            .expect("replacement record");
        let record = UtxoRecord::from_encoded(bytes.to_vec().into_boxed_slice()).expect("record");
        let outputs: Vec<_> = record.outputs().collect();
        assert_eq!(outputs.len(), 1);
        assert_eq!((outputs[0].vout, outputs[0].height), (0, 102));

        let spend_id = spend.txid();
        let block = mined_block_with_prev_hash(prev, 202, vec![spend]).expect("spend block");
        let undo_for = |source: &WindowWorkspace| {
            use bitcoin_rs_storage::utxo::contract::{
                BlockChangeInputs, SpentOutputLookup, build_block_changes,
            };
            struct SpentCoin(bitcoin_rs_storage::utxo::UtxoCoin);
            impl SpentOutputLookup for SpentCoin {
                fn entry(
                    &self,
                    outpoint: &OutPoint,
                ) -> Option<&bitcoin_rs_storage::utxo::UtxoCoin> {
                    (self.0.outpoint == *outpoint).then_some(&self.0)
                }
            }
            let resolved = SpentCoin(source.get_entry(&outpoint).expect("replacement prevout"));
            let image = bitcoin_rs_consensus::primitives::BlockImage::from_local(block.clone());
            let (_, undo, _) = build_block_changes(
                &BlockChangeInputs {
                    block: &image,
                    height: 202,
                    txids: &[spend_id],
                    same_block_spent: None,
                    add_capacity: 1,
                    remove_capacity: 1,
                    max_script_size: bitcoin_rs_consensus::MAX_SCRIPT_SIZE,
                },
                &resolved,
            )
            .expect("replacement spend changes");
            assert_eq!(undo.restores().len(), 1);
            assert_eq!(undo.restores()[0].outpoint, outpoint);
            assert_eq!(undo.restores()[0].height, 102);
            assert_eq!(undo.restores()[0].txout, replacement.txout);
            assert!(undo.restores()[0].coinbase);
            undo
        };
        let staged_undo = undo_for(&workspace);
        workspace
            .advance(&block, &[spend_id], 202, &HashSet::new())
            .expect("spend replacement");
        assert_eq!(workspace.get_entry(&outpoint), None);
        let transition = workspace.transitions.last().expect("spend transition");
        assert_eq!(transition.spent_outpoints, vec![outpoint]);
        let spent_delta = workspace
            .build_flush_delta(1)
            .expect("flush replacement spend");
        assert!(
            spent_delta
                .records
                .iter()
                .any(|(key, value)| { *key == CoinKey(txid.0.to_le_bytes()) && value.is_none() }),
            "spending the replacement removes its published record"
        );

        let store = Arc::new(bitcoin_rs_storage::MemoryKvStore::new());
        store
            .put(
                bitcoin_rs_storage::ColumnFamily::Coins,
                CoinKey(txid.0.to_le_bytes()).as_bytes(),
                bytes.as_ref(),
            )
            .expect("publish replacement record");
        let coins = super::CoinStore::open(store, 1 << 20);
        let mut next_workspace = WindowWorkspace::new(bitcoin_rs_consensus::MAX_SCRIPT_SIZE);
        next_workspace
            .resolve_external_batch(&coins, &[outpoint])
            .expect("resolve published replacement");
        assert_eq!(
            next_workspace.get_entry(&outpoint),
            Some(replacement.clone())
        );
        let published_undo = undo_for(&next_workspace);
        assert_eq!(published_undo, staged_undo);
        next_workspace
            .advance(&block, &[spend_id], 202, &HashSet::new())
            .expect("spend published replacement");
        assert_eq!(next_workspace.get_entry(&outpoint), None);
    }

    #[test]
    fn many_outputs_preserve_last_creation_then_spend_and_overwrite_order() {
        let mut first = empty_transition(10);
        first.created = (0..512)
            .rev()
            .map(|vout| created_output(1, vout, 1000 + u64::from(vout), 10))
            .collect();
        let mut second = empty_transition(11);
        second.created.push(created_output(1, 7, 7777, 11));
        first.created.push(created_output(2, 4, 4444, 10));
        second.created.push(created_output(1, 7, 8888, 11));
        second.spent_outpoints = (0..512)
            .filter(|vout| vout % 3 == 0)
            .map(|vout| OutPoint::new(indexed_txid(1), vout))
            .collect();
        let mut third = empty_transition(12);
        third.bip30_overwrites.push(overwrite_of(2));
        third.created.push(created_output(2, 9, 9999, 12));
        let initial = HashMap::new();
        let delta =
            WindowWorkspace::build_window_delta(&[first, second, third], &initial).expect("delta");
        let mut expected = Outputs::new();
        for vout in 0..512 {
            if vout % 3 != 0 {
                let (value, height) = if vout == 7 {
                    (8888, 11)
                } else {
                    (1000 + u64::from(vout), 10)
                };
                expected.insert(
                    vout,
                    (
                        value,
                        vec![0x51, u8::try_from(value % 200).expect("byte")],
                        value.is_multiple_of(2),
                        height,
                    ),
                );
            }
        }
        assert_eq!(delta.records.len(), 2);
        for (key, bytes) in &delta.records {
            let record = UtxoRecord::from_encoded(
                bytes
                    .as_ref()
                    .expect("live record")
                    .to_vec()
                    .into_boxed_slice(),
            )
            .expect("record");
            if *key == CoinKey(indexed_txid(1).0.to_le_bytes()) {
                assert_eq!(outputs_of(&record), expected);
            } else {
                assert_eq!(*key, CoinKey(indexed_txid(2).0.to_le_bytes()));
                let expected_other = [(9, (9999, vec![0x51, 199], false, 12))]
                    .into_iter()
                    .collect();
                assert_eq!(outputs_of(&record), expected_other);
            }
        }
    }

    #[test]
    fn staged_presence_reads_flushed_and_unflushed_transitions() {
        use crate::chain::regtest_fixture::{coinbase, mined_block_with_prev_hash};
        use bitcoin_rs_consensus::primitives::{Block, Network};
        use hashbrown::HashSet;

        let mut blocks: Vec<Block> = Vec::new();
        let mut prev = Network::Regtest.genesis_block().block_hash();
        for height in 1..=3_u32 {
            let block = mined_block_with_prev_hash(prev, height, vec![coinbase(height)])
                .expect("fixture block");
            prev = block.block_hash();
            blocks.push(block);
        }
        let txid_of = |block: &Block| block.txs[0].txid();
        let (x1, x2, x3) = (
            txid_of(&blocks[0]),
            txid_of(&blocks[1]),
            txid_of(&blocks[2]),
        );
        let untracked = Txid(Hash256::from_le_bytes(&[0x42; 32]));

        let mut workspace = WindowWorkspace::new(bitcoin_rs_consensus::MAX_SCRIPT_SIZE);
        for (index, block) in blocks.iter().enumerate() {
            let txids = [txid_of(block)];
            let height = u32::try_from(index + 1).expect("height");
            workspace
                .advance(block, &txids, height, &HashSet::new())
                .expect("advance");
        }

        assert_eq!(workspace.staged_coin_presence_before(x1, 1), None);
        assert_eq!(workspace.staged_coin_presence_before(x1, 2), Some(true));
        assert_eq!(workspace.staged_coin_presence_before(x3, 3), None);
        assert_eq!(workspace.staged_coin_presence_before(untracked, 4), None);

        workspace
            .build_flush_delta(2)
            .expect("flush first two blocks");

        assert_eq!(workspace.staged_coin_presence_before(x1, 3), Some(true));
        assert_eq!(workspace.staged_coin_presence_before(x2, 3), Some(true));
        assert_eq!(workspace.staged_coin_presence_before(x3, 4), Some(true));
        assert_eq!(workspace.staged_coin_presence_before(x3, 3), None);
        assert_eq!(workspace.staged_coin_presence_before(untracked, 4), None);
    }

    fn reference_presence(workspace: &WindowWorkspace, txid: Txid, height: u32) -> Option<bool> {
        let mut tracked = workspace.initial_records.contains_key(&txid);
        let mut unspent: hashbrown::HashSet<u32> = match workspace.initial_records.get(&txid) {
            Some(Some(record)) => record.outputs().map(|output| output.vout).collect(),
            _ => hashbrown::HashSet::new(),
        };
        for transition in workspace.transitions[workspace.flushed_transitions..]
            .iter()
            .filter(|transition| transition.height < height)
        {
            if transition
                .bip30_overwrites
                .iter()
                .any(|overwrite| overwrite.outpoint.txid == txid)
            {
                unspent.clear();
                tracked = true;
            }
            for created in &transition.created {
                if created.txid == txid {
                    unspent.insert(created.vout);
                    tracked = true;
                }
            }
            for spent in &transition.spent_outpoints {
                if spent.txid == txid {
                    let vout = spent.vout;
                    unspent.remove(&vout);
                    tracked = true;
                }
            }
        }
        tracked.then_some(!unspent.is_empty())
    }

    #[test]
    fn staged_presence_index_matches_the_linear_scan() {
        use crate::chain::regtest_fixture::{coinbase, mined_block_with_prev_hash};
        use bitcoin_rs_consensus::primitives::{
            Amount, LockTime, Network, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Witness,
        };
        use hashbrown::HashSet;

        let spend = |previous: OutPoint| Tx {
            version: 2,
            lock_time: LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: previous,
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(1),
                script_pubkey: vec![0x51].into(),
            }],
        };
        let genesis_hash = Network::Regtest.genesis_block().block_hash();
        let block_1 =
            mined_block_with_prev_hash(genesis_hash, 1, vec![coinbase(1)]).expect("fixture block");
        let x1 = block_1.txs[0].txid();
        let block_2 = mined_block_with_prev_hash(
            block_1.block_hash(),
            2,
            vec![coinbase(2), spend(OutPoint::new(x1, 0))],
        )
        .expect("fixture block");
        let x2 = block_2.txs[0].txid();
        let s2 = block_2.txs[1].txid();
        let block_3 = mined_block_with_prev_hash(
            block_2.block_hash(),
            3,
            vec![
                coinbase(3),
                spend(OutPoint::new(x2, 0)),
                spend(OutPoint::new(s2, 0)),
            ],
        )
        .expect("fixture block");
        let blocks = [block_1, block_2, block_3];

        let mut candidates: Vec<Txid> = blocks
            .iter()
            .flat_map(|block| block.txs.iter().map(Tx::txid))
            .collect();
        candidates.push(Txid(Hash256::from_le_bytes(&[0x42; 32])));

        let mut workspace = WindowWorkspace::new(bitcoin_rs_consensus::MAX_SCRIPT_SIZE);
        for (index, block) in blocks.iter().enumerate() {
            let txids: Vec<Txid> = block.txs.iter().map(Tx::txid).collect();
            let height = u32::try_from(index + 1).expect("height");
            workspace
                .advance(block, &txids, height, &HashSet::new())
                .expect("advance");
        }

        for flushed in 0..=blocks.len() {
            for height in 0..=4_u32 {
                for txid in &candidates {
                    assert_eq!(
                        workspace.staged_coin_presence_before(*txid, height),
                        reference_presence(&workspace, *txid, height),
                        "indexed presence diverged at height {height} after {flushed} flushed blocks"
                    );
                }
            }
            if flushed < blocks.len() {
                workspace.build_flush_delta(1).expect("flush one block");
            }
        }
    }

    // WIN-07
    #[test]
    fn bip30_exception_block_stays_an_explicit_overwrite_of_the_engine_coin()
    -> Result<(), Box<dyn std::error::Error>> {
        use super::CoinStore;
        use bitcoin_rs_consensus::bip30::BIP30_DUPLICATE_TXID_EXCEPTIONS;
        use bitcoin_rs_consensus::primitives::{Block, OutPoint, Tx, deserialize};
        use bitcoin_rs_storage::KvStore as _;
        use bitcoin_rs_storage::memory_kv::MemoryKvStore;
        use bitcoin_rs_storage::utxo::record::{OwnedUtxoOut, UtxoRecord};
        use hashbrown::HashSet;
        use std::sync::Arc;

        let (exception_height, exception_hash) = BIP30_DUPLICATE_TXID_EXCEPTIONS[0];
        let block: Block = deserialize(include_bytes!("../../consensus/tests/testdata/91842.bin"))?;
        assert_eq!(Hash256::from(block.block_hash()), exception_hash);
        let txids: Vec<Txid> = block.txs.iter().map(Tx::txid).collect();
        let duplicated = txids[0];
        let earlier = OwnedUtxoOut {
            vout: 0,
            value: 5_000_000_000,
            script_pubkey: vec![0x51],
            coinbase: true,
            height: 91_812,
        };
        let earlier_record = UtxoRecord::from_owned_outputs(duplicated.0, &[earlier])?;
        let store = Arc::new(MemoryKvStore::new());
        store.put(
            bitcoin_rs_storage::ColumnFamily::Coins,
            CoinKey(duplicated.0.to_le_bytes()).as_bytes(),
            earlier_record.bytes(),
        )?;
        let coins = CoinStore::open(store, 1 << 20);

        let mut workspace = WindowWorkspace::new(bitcoin_rs_consensus::MAX_SCRIPT_SIZE);
        workspace.resolve_external_batch(&coins, &[OutPoint::new(duplicated, 0)])?;
        workspace.advance(&block, &txids, exception_height, &HashSet::new())?;

        let overwritten = &workspace.transitions[0].bip30_overwrites;
        assert_eq!(overwritten.len(), 1);
        assert_eq!(overwritten[0].outpoint, OutPoint::new(duplicated, 0));
        assert_eq!(overwritten[0].height, 91_812);
        assert!(overwritten[0].coinbase);
        assert_eq!(overwritten[0].txout.value.to_sat(), 5_000_000_000);
        assert_eq!(
            workspace.staged_coin_presence_before(duplicated, exception_height + 1),
            Some(true),
            "the exception block's own coin is unspent after it"
        );

        let delta = workspace.build_flush_delta(1)?;
        let (_, row) = delta
            .records
            .iter()
            .find(|(key, _)| *key == CoinKey(duplicated.0.to_le_bytes()))
            .ok_or("the delta must rewrite the duplicated txid")?;
        let row = row
            .as_ref()
            .ok_or("the exception block must leave its own coin")?;
        let record = UtxoRecord::from_encoded(row.to_vec().into_boxed_slice())?;
        let outputs: Vec<_> = record.outputs().collect();
        assert_eq!(outputs.len(), 1);
        assert_eq!(outputs[0].height, exception_height);
        assert_eq!(outputs[0].value, block.txs[0].outputs[0].value.to_sat());
        assert!(outputs[0].coinbase);
        Ok(())
    }

    #[derive(Debug, thiserror::Error)]
    enum CoinBytesError {
        #[error(transparent)]
        Fixture(Box<crate::test_fixtures::TestError>),
        #[error(transparent)]
        Read(#[from] super::WindowReadError),
        #[error(transparent)]
        Workspace(#[from] super::WindowWorkspaceError),
        #[error(transparent)]
        Utxo(#[from] UtxoError),
        #[error(transparent)]
        Height(#[from] std::num::TryFromIntError),
    }

    impl From<crate::test_fixtures::TestError> for CoinBytesError {
        fn from(error: crate::test_fixtures::TestError) -> Self {
            Self::Fixture(Box::new(error))
        }
    }

    // BUD-06, WIN-05
    #[test]
    fn staged_coin_bytes_equal_the_flush_encoder_after_each_block() -> Result<(), CoinBytesError> {
        let corpus = crate::test_fixtures::churn_corpus()?;
        let limits = crate::window_limits::WindowLimits::durable_head_defaults();
        let chain = crate::test_fixtures::funded_chain(&corpus, limits)?;
        let outpoints: Vec<super::OutPoint> = corpus
            .blocks
            .iter()
            .flat_map(|block| block.txs.iter().filter(|tx| !tx.is_coinbase()))
            .flat_map(|tx| tx.inputs.iter().map(|input| input.previous_output))
            .collect();
        let mut workspace = WindowWorkspace::new(bitcoin_rs_consensus::MAX_SCRIPT_SIZE);
        workspace.resolve_external_batch(chain.coins.as_ref(), &outpoints)?;
        for (index, block) in corpus.blocks.iter().enumerate() {
            let txids: Vec<Txid> = block.txs.iter().map(|tx| tx.txid()).collect();
            let height = u32::try_from(corpus.prefix.len() + index + 1)?;
            workspace.advance(block, &txids, height, &super::HashSet::new())?;
            let running = workspace.staged_coin_bytes(index + 1)?;
            let flushed = WindowWorkspace::build_window_delta(
                &workspace.transitions[..=index],
                &workspace.initial_records,
            )?;
            let encoder_bytes: usize = flushed.records.iter().map(super::entry_encoded_len).sum();
            assert_eq!(
                running, encoder_bytes,
                "running coin bytes diverged from the flush encoder after block {index}"
            );
        }
        assert!(
            workspace.coin_bytes > 0,
            "the churn blocks must stage coin bytes"
        );
        Ok(())
    }
    // WIN-03
    #[test]
    fn window_delta_matches_the_outpoint_model_and_folds_each_event_once()
    -> Result<(), CoinBytesError> {
        use super::{
            BlockTransition, CreatedOwned, FOLD_EVENTS, HashSet, OutPoint, OwnedUtxoOut, TxOut,
            UndoCoin, UtxoRecord,
        };

        let txid_a = Txid(Hash256::from_le_bytes(&[0xa0; 32]));
        let txid_b = Txid(Hash256::from_le_bytes(&[0xb0; 32]));
        let txid_c = Txid(Hash256::from_le_bytes(&[0xc0; 32]));
        let txid_d = Txid(Hash256::from_le_bytes(&[0xd0; 32]));
        let txid_e = Txid(Hash256::from_le_bytes(&[0xe0; 32]));
        let script = Bytes::from_static(&[0x51]);
        let create = |txid: Txid, vout: u32, value: u64, height: u32| CreatedOwned {
            txid,
            vout,
            coinbase: false,
            height,
            value,
            script_pubkey: script.clone(),
        };
        let overwrite = |txid: Txid, height: u32| UndoCoin {
            outpoint: OutPoint::new(txid, 0),
            txout: TxOut::default(),
            height,
            coinbase: false,
        };
        let block = |height: u32,
                     created: Vec<CreatedOwned>,
                     spent: Vec<OutPoint>,
                     overwrites: Vec<UndoCoin>| BlockTransition {
            height,
            hash: Hash256::default(),
            prev_hash: Hash256::default(),
            created,
            spent_outpoints: spent,
            bip30_overwrites: overwrites,
        };
        let prefix = vec![
            block(
                1,
                vec![create(txid_c, 0, 100, 1), create(txid_c, 1, 101, 1)],
                vec![OutPoint::new(txid_a, 0)],
                Vec::new(),
            ),
            block(
                2,
                vec![create(txid_d, 0, 200, 2), create(txid_c, 2, 102, 2)],
                vec![OutPoint::new(txid_c, 0), OutPoint::new(txid_b, 0)],
                Vec::new(),
            ),
            block(
                3,
                vec![create(txid_e, 0, 300, 3), create(txid_a, 5, 305, 3)],
                vec![OutPoint::new(txid_d, 0), OutPoint::new(txid_c, 1)],
                vec![overwrite(txid_a, 3)],
            ),
        ];

        let initial_outputs = vec![
            (
                txid_a,
                vec![
                    OwnedUtxoOut::new(0, 1_000, vec![0x51], false, 1),
                    OwnedUtxoOut::new(1, 1_001, vec![0x51], false, 1),
                ],
            ),
            (
                txid_b,
                vec![OwnedUtxoOut::new(0, 2_000, vec![0x51], false, 1)],
            ),
        ];
        let mut initial_records = HashMap::new();
        for (txid, outputs) in &initial_outputs {
            let record = UtxoRecord::from_owned_outputs(txid.0, outputs)?;
            initial_records.insert(*txid, Some(record));
        }

        let mut existed: HashSet<Txid> = HashSet::new();
        for (txid, _) in &initial_outputs {
            existed.insert(*txid);
        }
        let mut referenced: HashSet<Txid> = HashSet::new();
        for transition in &prefix {
            for created in &transition.created {
                referenced.insert(created.txid);
            }
            for spent in &transition.spent_outpoints {
                referenced.insert(spent.txid);
            }
            for overwrite in &transition.bip30_overwrites {
                referenced.insert(overwrite.outpoint.txid);
            }
        }
        let mut expected: Vec<(CoinKey, Option<Bytes>)> = Vec::new();
        for txid in referenced {
            let mut current: Vec<OwnedUtxoOut> = initial_outputs
                .iter()
                .find(|(id, _)| *id == txid)
                .map(|(_, outputs)| outputs.clone())
                .unwrap_or_default();
            for transition in &prefix {
                if transition
                    .bip30_overwrites
                    .iter()
                    .any(|overwrite| overwrite.outpoint.txid == txid)
                {
                    current.clear();
                }
                for created in &transition.created {
                    if created.txid == txid {
                        current.retain(|out| out.vout != created.vout);
                        current.push(OwnedUtxoOut {
                            vout: created.vout,
                            value: created.value,
                            script_pubkey: created.script_pubkey.to_vec(),
                            coinbase: created.coinbase,
                            height: created.height,
                        });
                    }
                }
                for spent in &transition.spent_outpoints {
                    if spent.txid == txid {
                        current.retain(|out| out.vout != spent.vout);
                    }
                }
            }
            let key = CoinKey(txid.0.to_le_bytes());
            match (existed.contains(&txid), current.is_empty()) {
                (false, true) => {}
                (true, true) => expected.push((key, None)),
                (_, false) => {
                    let record = UtxoRecord::from_owned_outputs(txid.0, &current)?;
                    expected.push((key, Some(Bytes::copy_from_slice(record.bytes()))));
                }
            }
        }
        expected.sort_by_key(|(key, _)| *key);

        let events_expected: usize = prefix
            .iter()
            .map(|transition| {
                let mut seen = HashSet::new();
                for created in &transition.created {
                    seen.insert(created.txid);
                }
                for spent in &transition.spent_outpoints {
                    seen.insert(spent.txid);
                }
                for overwrite in &transition.bip30_overwrites {
                    seen.insert(overwrite.outpoint.txid);
                }
                seen.len()
            })
            .sum();
        FOLD_EVENTS.with(|events| events.set(0));
        let delta = WindowWorkspace::build_window_delta(&prefix, &initial_records)?;
        assert_eq!(delta.records, expected);
        assert_eq!(FOLD_EVENTS.with(std::cell::Cell::get), events_expected,);
        Ok(())
    }

    // WIN-03
    #[test]
    fn window_fold_counts_one_event_per_transition_txid_pair_under_spend_churn()
    -> Result<(), CoinBytesError> {
        use super::{
            BlockTransition, CreatedOwned, FOLD_EVENTS, OutPoint, OwnedUtxoOut, UtxoRecord,
            index_transition,
        };
        let victim = Txid(Hash256::from_le_bytes(&[0xf0; 32]));
        let script = Bytes::from_static(&[0x51]);
        let create = |txid: Txid, vout: u32, value: u64, height: u32| CreatedOwned {
            txid,
            vout,
            coinbase: false,
            height,
            value,
            script_pubkey: script.clone(),
        };
        let block =
            |height: u32, created: Vec<CreatedOwned>, spent: Vec<OutPoint>| BlockTransition {
                height,
                hash: Hash256::default(),
                prev_hash: Hash256::default(),
                created,
                spent_outpoints: spent,
                bip30_overwrites: Vec::new(),
            };
        let mut prefix = Vec::new();
        for (index, byte) in (0..16_u8).enumerate() {
            let height = u32::try_from(index + 1)?;
            let fresh = Txid(Hash256::from_le_bytes(&[byte; 32]));
            prefix.push(block(
                height,
                vec![create(fresh, 0, 2_000, height)],
                Vec::new(),
            ));
        }
        let spends: Vec<OutPoint> = (0..200_u32)
            .map(|vout| OutPoint::new(victim, vout))
            .collect();
        prefix.push(block(17, Vec::new(), spends));

        let mut victim_outputs = Vec::new();
        for vout in 0..200_u32 {
            victim_outputs.push(OwnedUtxoOut::new(
                vout,
                1_000 + u64::from(vout),
                vec![0x51],
                false,
                1,
            ));
        }
        let mut initial_records = HashMap::new();
        let victim_record = UtxoRecord::from_owned_outputs(victim.0, &victim_outputs)?;
        initial_records.insert(victim, Some(victim_record));

        let mut expected: Vec<(CoinKey, Option<Bytes>)> = Vec::new();
        expected.push((CoinKey(victim.0.to_le_bytes()), None));
        for (index, byte) in (0..16_u8).enumerate() {
            let height = u32::try_from(index + 1)?;
            let fresh = Txid(Hash256::from_le_bytes(&[byte; 32]));
            let outputs = vec![OwnedUtxoOut::new(0, 2_000, vec![0x51], false, height)];
            let record = UtxoRecord::from_owned_outputs(fresh.0, &outputs)?;
            expected.push((
                CoinKey(fresh.0.to_le_bytes()),
                Some(Bytes::copy_from_slice(record.bytes())),
            ));
        }
        expected.sort_by_key(|(key, _)| *key);
        let reference_bytes: usize = expected
            .iter()
            .map(|(key, record)| key.as_bytes().len() + record.as_ref().map_or(0, Bytes::len))
            .sum();

        FOLD_EVENTS.with(|events| events.set(0));
        let delta = WindowWorkspace::build_window_delta(&prefix, &initial_records)?;
        assert_eq!(delta.records, expected);
        assert_eq!(FOLD_EVENTS.with(std::cell::Cell::get), 16 + 1);
        let mut workspace = WindowWorkspace::new(10_000);
        workspace.transitions = prefix;
        workspace.initial_records = initial_records;
        for (index, transition) in workspace.transitions.iter().enumerate() {
            index_transition(&mut workspace.touched, index, transition);
        }
        FOLD_EVENTS.with(|events| events.set(0));
        workspace.staged_coin_bytes(16)?;
        let staged = workspace.staged_coin_bytes(17)?;
        assert_eq!(
            FOLD_EVENTS.with(std::cell::Cell::get),
            16 + 1,
            "staging the churn block must not refold the prefix"
        );
        assert_eq!(
            staged, reference_bytes,
            "staged coin bytes must equal the modelled records"
        );
        Ok(())
    }
}
