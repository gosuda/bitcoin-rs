//! Window-local coin state and window commit construction (WIN-01..WIN-07).
//!
//! Consistency contract: the workspace is a linearizable read view over the
//! published coin store plus the uncommitted window prefix. Publication of a
//! window prefix is linearized by the durable head batch; cache install is
//! strictly ordered after it (CMT-02, CMT-03).

use bitcoin_rs_consensus::primitives::{Amount, Block, Hash256, OutPoint, TxOut, Txid};
use bitcoin_rs_storage::utxo::UtxoCoin;
use bitcoin_rs_storage::utxo::contract::OutputSource;
use bitcoin_rs_storage::utxo::record::{OwnedUtxoOut, UtxoRecord};
use bitcoin_rs_storage::utxo::set::UtxoError;
use bitcoin_rs_storage::{CoinKey, CoinStore, StorageError, WindowDelta};
use bytes::Bytes;
use hashbrown::{HashMap, HashSet};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct CreatedOwned {
    pub txid: Txid,
    pub vout: u32,
    pub coinbase: bool,
    pub height: u32,
    pub value: u64,
    pub script_pubkey: Bytes,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum UndoKind {
    ExternalSpend,
    Bip30Overwrite,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UndoCoin {
    pub outpoint: OutPoint,
    pub txout: TxOut,
    pub height: u32,
    pub coinbase: bool,
    pub kind: UndoKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BlockTransition {
    pub height: u32,
    pub hash: Hash256,
    pub prev_hash: Hash256,
    pub created: Vec<CreatedOwned>,
    pub spent_external: Vec<UndoCoin>,
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
        Ok(delta)
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
        let mut spent_external = Vec::new();
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
                    if let Some(undo) =
                        spend_input_in_workspace(&mut self.live, &self.resolved_external, prev)
                    {
                        spent_external.push(undo);
                    }
                }
            }
        }

        self.transitions.push(BlockTransition {
            height,
            hash: Hash256::from(block.block_hash()),
            prev_hash: block.header.prev_blockhash.into(),
            created: created_owned,
            spent_external,
            spent_outpoints,
            bip30_overwrites,
        });

        Ok(())
    }

    /// Returns the duplicate-probe answer for `txid` at `height` when the
    /// uncommitted window prefix below that height determines it, and `None`
    /// when the engine coin store stays authoritative (`WIN-07`).
    #[must_use]
    pub(crate) fn staged_coin_presence_before(&self, txid: Txid, height: u32) -> Option<bool> {
        let mut tracked = self.initial_records.contains_key(&txid);
        let mut unspent: HashSet<u32> = initial_outputs_for_txid(&self.initial_records, txid)
            .into_iter()
            .map(|output| output.vout)
            .collect();
        for transition in self.transitions[self.flushed_transitions..]
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

    pub(crate) fn build_window_delta(
        prefix: &[BlockTransition],
        initial_records: &HashMap<Txid, Option<UtxoRecord>>,
    ) -> Result<WindowDelta, UtxoError> {
        let touched_txids = touched_txids(prefix);
        let mut delta = WindowDelta::default();
        for txid in touched_txids {
            let existed_before = initial_records
                .get(&txid)
                .and_then(Option::as_ref)
                .is_some();
            let mut current_outputs = initial_outputs_for_txid(initial_records, txid);
            for transition in prefix {
                apply_transition_to_txid_outputs(transition, txid, &mut current_outputs);
            }
            match (existed_before, current_outputs.is_empty()) {
                (false, true) => {}
                (true, true) => delta.push_final(CoinKey(txid.0.to_le_bytes()), None),
                (_, false) => {
                    let record = UtxoRecord::from_owned_outputs(
                        Hash256::from_le_bytes(&txid.0.to_le_bytes()),
                        &current_outputs,
                    )?;
                    delta.push_final(
                        CoinKey(txid.0.to_le_bytes()),
                        Some(Bytes::copy_from_slice(record.bytes())),
                    );
                }
            }
        }
        delta.records.sort_by_key(|(key, _)| *key);
        Ok(delta)
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
            kind: UndoKind::Bip30Overwrite,
        });
    }
}

fn spend_input_in_workspace(
    live: &mut HashMap<Txid, Vec<LiveOut>>,
    resolved_external: &HashMap<OutPoint, UtxoCoin>,
    prev: OutPoint,
) -> Option<UndoCoin> {
    if let Some(outs) = live.get_mut(&prev.txid) {
        if let Some(out) = outs.iter_mut().find(|o| o.vout == prev.vout && !o.spent) {
            out.spent = true;
            return None;
        }
    }
    resolved_external.get(&prev).map(|coin| UndoCoin {
        outpoint: prev,
        txout: coin.txout.clone(),
        height: coin.height,
        coinbase: coin.coinbase,
        kind: UndoKind::ExternalSpend,
    })
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

fn touched_txids(prefix: &[BlockTransition]) -> Vec<Txid> {
    let mut touched = HashSet::new();
    for transition in prefix {
        for created in &transition.created {
            touched.insert(created.txid);
        }
        for spent in &transition.spent_outpoints {
            touched.insert(spent.txid);
        }
        for overwrite in &transition.bip30_overwrites {
            touched.insert(overwrite.outpoint.txid);
        }
    }
    let mut txids: Vec<Txid> = touched.into_iter().collect();
    txids.sort_unstable();
    txids
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
) -> Vec<OwnedUtxoOut> {
    match initial_records.get(&txid) {
        Some(Some(record)) => record
            .outputs()
            .map(|out| OwnedUtxoOut {
                vout: out.vout,
                value: out.value,
                script_pubkey: out.script_pubkey.to_vec(),
                coinbase: out.coinbase,
                height: out.height,
            })
            .collect(),
        _ => Vec::new(),
    }
}

fn apply_transition_to_txid_outputs(
    transition: &BlockTransition,
    txid: Txid,
    current_outputs: &mut Vec<OwnedUtxoOut>,
) {
    if transition
        .bip30_overwrites
        .iter()
        .any(|overwrite| overwrite.outpoint.txid == txid)
    {
        current_outputs.clear();
    }
    for created in &transition.created {
        if created.txid == txid {
            current_outputs.retain(|out| out.vout != created.vout);
            current_outputs.push(OwnedUtxoOut {
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
            current_outputs.retain(|out| out.vout != spent.vout);
        }
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

    use super::{CoinKey, HashMap, UtxoError, merge_delta_records};

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
}
