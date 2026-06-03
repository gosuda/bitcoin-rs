use bitcoin::hashes::Hash as _;
use bitcoin::{ScriptBuf, Transaction, Txid};
use bitcoin_rs_primitives::{Hash256, OutPoint};
use hashbrown::{HashMap, HashSet};

use crate::state::ApplyError;

type SameBlockScriptMap = HashMap<OutPoint, ScriptBuf>;
type SameBlockSpentSet = HashSet<OutPoint>;
type SameBlockSpendResult = Result<(Option<SameBlockScriptMap>, SameBlockSpentSet), ApplyError>;

pub(super) struct ApplyScratch {
    txids: Vec<Txid>,
    raw_txs: Option<Vec<Vec<u8>>>,
    same_block_spent_output_scripts: Option<SameBlockScriptMap>,
    same_block_spent: SameBlockSpentSet,
}

impl ApplyScratch {
    #[cfg(test)]
    pub(super) fn new(
        block: &bitcoin::Block,
        height: u32,
        include_raw_txs: bool,
        include_same_block_output_scripts: bool,
    ) -> Result<Self, ApplyError> {
        let txids = block.txdata.iter().map(Transaction::compute_txid).collect();
        Self::with_txids(
            block,
            height,
            include_raw_txs,
            include_same_block_output_scripts,
            txids,
        )
    }

    pub(super) fn with_txids(
        block: &bitcoin::Block,
        height: u32,
        include_raw_txs: bool,
        include_same_block_output_scripts: bool,
        txids: Vec<Txid>,
    ) -> Result<Self, ApplyError> {
        debug_assert_eq!(txids.len(), block.txdata.len());
        let mut raw_txs = include_raw_txs.then(|| Vec::with_capacity(block.txdata.len()));
        for tx in &block.txdata {
            if let Some(raw_txs) = &mut raw_txs {
                raw_txs.push(bitcoin::consensus::encode::serialize(tx));
            }
        }
        let (same_block_spent_output_scripts, same_block_spent) = same_block_spends(
            &block.txdata,
            &txids,
            height,
            include_same_block_output_scripts,
        )?;
        Ok(Self {
            txids,
            raw_txs,
            same_block_spent_output_scripts,
            same_block_spent,
        })
    }

    pub(super) fn txids(&self) -> &[Txid] {
        &self.txids
    }

    pub(super) fn raw_txs(&self) -> Option<&[Vec<u8>]> {
        self.raw_txs.as_deref()
    }

    pub(super) fn same_block_spent(&self) -> &SameBlockSpentSet {
        &self.same_block_spent
    }

    pub(super) fn same_block_spent_output_script(&self, outpoint: &OutPoint) -> Option<ScriptBuf> {
        self.same_block_spent_output_scripts
            .as_ref()?
            .get(outpoint)
            .cloned()
    }
}

fn same_block_spends(
    txdata: &[Transaction],
    txids: &[Txid],
    height: u32,
    include_output_scripts: bool,
) -> SameBlockSpendResult {
    if txdata.iter().all(Transaction::is_coinbase) {
        return Ok((None, HashSet::new()));
    }

    if include_output_scripts {
        return same_block_spends_with_scripts(txdata, txids, height);
    }

    let created_capacity = txdata.iter().map(|tx| tx.output.len()).sum();
    let spent_capacity = txdata
        .iter()
        .filter(|tx| !tx.is_coinbase())
        .map(|tx| tx.input.len())
        .sum();
    let mut created_outpoints: SameBlockSpentSet = HashSet::with_capacity(created_capacity);
    let mut spent = HashSet::with_capacity(spent_capacity);
    for (tx, txid) in txdata.iter().zip(txids) {
        if !tx.is_coinbase() {
            for input in &tx.input {
                let previous_output = internal_outpoint(&input.previous_output);
                if created_outpoints.contains(&previous_output) {
                    spent.insert(previous_output);
                }
            }
        }

        let txid = Hash256::from_le_bytes(txid.as_byte_array());
        for (vout, _txout) in tx.output.iter().enumerate() {
            let outpoint = OutPoint::new(
                txid,
                u32::try_from(vout).map_err(|_| ApplyError::HeightOverflow(height))?,
            );
            created_outpoints.insert(outpoint);
        }
    }
    Ok((None, spent))
}

fn same_block_spends_with_scripts(
    txdata: &[Transaction],
    txids: &[Txid],
    height: u32,
) -> SameBlockSpendResult {
    let created_capacity = txdata.iter().map(|tx| tx.output.len()).sum();
    let spent_capacity = txdata
        .iter()
        .filter(|tx| !tx.is_coinbase())
        .map(|tx| tx.input.len())
        .sum();
    let mut created_scripts: SameBlockScriptMap = HashMap::with_capacity(created_capacity);
    let mut spent_scripts: SameBlockScriptMap = HashMap::with_capacity(spent_capacity);
    let mut spent = HashSet::with_capacity(spent_capacity);
    for (tx, txid) in txdata.iter().zip(txids) {
        if !tx.is_coinbase() {
            for input in &tx.input {
                let previous_output = internal_outpoint(&input.previous_output);
                if let Some(script) = created_scripts.get(&previous_output) {
                    spent.insert(previous_output);
                    spent_scripts.insert(previous_output, script.clone());
                }
            }
        }

        let txid = Hash256::from_le_bytes(txid.as_byte_array());
        for (vout, txout) in tx.output.iter().enumerate() {
            let outpoint = OutPoint::new(
                txid,
                u32::try_from(vout).map_err(|_| ApplyError::HeightOverflow(height))?,
            );
            created_scripts.insert(outpoint, txout.script_pubkey.clone());
        }
    }
    Ok((Some(spent_scripts), spent))
}

fn internal_outpoint(outpoint: &bitcoin::OutPoint) -> OutPoint {
    OutPoint::new(
        Hash256::from_le_bytes(outpoint.txid.as_byte_array()),
        outpoint.vout,
    )
}
