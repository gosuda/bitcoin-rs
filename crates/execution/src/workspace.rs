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
    touched: HashMap<Txid, Vec<usize>>,
    engine_presence: HashMap<Txid, bool>,
    coin_cursor: usize,
    coin_entries: HashMap<Txid, usize>,
    coin_bytes: usize,
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
        Ok(delta)
    }

    pub(crate) fn staged_coin_bytes(&mut self, pending_count: usize) -> Result<usize, UtxoError> {
        let target = (self.flushed_transitions + pending_count).min(self.transitions.len());
        while self.coin_cursor < target {
            let index = self.coin_cursor;
            for txid in transition_txids(&self.transitions[index]) {
                let entry = self.coin_entry(txid, index)?;
                let bytes = entry.as_ref().map_or(0, entry_encoded_len);
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

    fn coin_entry(&self, txid: Txid, through: usize) -> Result<Option<CoinEntry>, UtxoError> {
        let mut current_outputs = initial_outputs_for_txid(&self.initial_records, txid);
        for &index in self.touched.get(&txid).into_iter().flatten() {
            if index >= self.flushed_transitions && index <= through {
                apply_transition_to_txid_outputs(
                    &self.transitions[index],
                    txid,
                    &mut current_outputs,
                );
            }
        }
        txid_entry(&self.initial_records, txid, &current_outputs)
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

        let transition = BlockTransition {
            height,
            hash: Hash256::from(block.block_hash()),
            prev_hash: block.header.prev_blockhash.into(),
            created: created_owned,
            spent_external,
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
        let mut delta = WindowDelta::default();
        for txid in touched_txids(prefix) {
            let mut current_outputs = initial_outputs_for_txid(initial_records, txid);
            for transition in prefix {
                apply_transition_to_txid_outputs(transition, txid, &mut current_outputs);
            }
            if let Some((key, record)) = txid_entry(initial_records, txid, &current_outputs)? {
                delta.push_final(key, record);
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

fn touched_txids(prefix: &[BlockTransition]) -> Vec<Txid> {
    let mut touched = HashSet::new();
    for transition in prefix {
        touched.extend(transition_txids(transition));
    }
    let mut txids: Vec<Txid> = touched.into_iter().collect();
    txids.sort_unstable();
    txids
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

    use super::{CoinKey, Hash256, HashMap, Txid, UtxoError, WindowWorkspace, merge_delta_records};

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
}
