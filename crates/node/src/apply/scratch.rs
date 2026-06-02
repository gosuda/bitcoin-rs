use bitcoin::hashes::Hash as _;
use bitcoin::{ScriptBuf, Transaction, Txid};
use bitcoin_rs_primitives::{Hash256, OutPoint};
use hashbrown::{HashMap, HashSet};

use crate::state::ApplyError;

pub(super) struct ApplyScratch {
    txids: Vec<Txid>,
    raw_txs: Option<Vec<Vec<u8>>>,
    same_block_spent_output_scripts: HashMap<OutPoint, ScriptBuf>,
    same_block_spent: HashSet<OutPoint>,
}

impl ApplyScratch {
    pub(super) fn new(
        block: &bitcoin::Block,
        height: u32,
        include_raw_txs: bool,
    ) -> Result<Self, ApplyError> {
        let mut txids = Vec::with_capacity(block.txdata.len());
        let mut raw_txs = include_raw_txs.then(|| Vec::with_capacity(block.txdata.len()));
        for tx in &block.txdata {
            txids.push(tx.compute_txid());
            if let Some(raw_txs) = &mut raw_txs {
                raw_txs.push(bitcoin::consensus::encode::serialize(tx));
            }
        }
        let (same_block_spent_output_scripts, same_block_spent) =
            same_block_spends(&block.txdata, &txids, height)?;
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

    pub(super) fn same_block_spent(&self) -> &HashSet<OutPoint> {
        &self.same_block_spent
    }

    pub(super) fn same_block_spent_output_script(&self, outpoint: &OutPoint) -> Option<ScriptBuf> {
        self.same_block_spent_output_scripts.get(outpoint).cloned()
    }
}

fn same_block_spends(
    txdata: &[Transaction],
    txids: &[Txid],
    height: u32,
) -> Result<(HashMap<OutPoint, ScriptBuf>, HashSet<OutPoint>), ApplyError> {
    if txdata.iter().all(Transaction::is_coinbase) {
        return Ok((HashMap::new(), HashSet::new()));
    }

    let mut created: HashMap<OutPoint, ScriptBuf> = HashMap::new();
    let mut spent_scripts: HashMap<OutPoint, ScriptBuf> = HashMap::new();
    let mut spent = HashSet::new();
    for (tx, txid) in txdata.iter().zip(txids) {
        if !tx.is_coinbase() {
            for input in &tx.input {
                let previous_output = internal_outpoint(&input.previous_output);
                if let Some(script) = created.get(&previous_output) {
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
            created.insert(outpoint, txout.script_pubkey.clone());
        }
    }
    Ok((spent_scripts, spent))
}

fn internal_outpoint(outpoint: &bitcoin::OutPoint) -> OutPoint {
    OutPoint::new(
        Hash256::from_le_bytes(outpoint.txid.as_byte_array()),
        outpoint.vout,
    )
}
