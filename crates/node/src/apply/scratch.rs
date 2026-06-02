use bitcoin::hashes::Hash as _;
use bitcoin::{Transaction, Txid};
use bitcoin_rs_primitives::{Hash256, OutPoint};
use hashbrown::HashSet;

use crate::state::ApplyError;

pub(super) struct ApplyScratch {
    txids: Vec<Txid>,
    raw_txs: Vec<Vec<u8>>,
    same_block_spent: HashSet<OutPoint>,
}

impl ApplyScratch {
    pub(super) fn new(block: &bitcoin::Block, height: u32) -> Result<Self, ApplyError> {
        let mut txids = Vec::with_capacity(block.txdata.len());
        let mut raw_txs = Vec::with_capacity(block.txdata.len());
        for tx in &block.txdata {
            txids.push(tx.compute_txid());
            raw_txs.push(bitcoin::consensus::encode::serialize(tx));
        }
        let same_block_spent = same_block_spent_outpoints(&block.txdata, &txids, height)?;
        Ok(Self {
            txids,
            raw_txs,
            same_block_spent,
        })
    }

    pub(super) fn txids(&self) -> &[Txid] {
        &self.txids
    }

    pub(super) fn raw_txs(&self) -> &[Vec<u8>] {
        &self.raw_txs
    }

    pub(super) fn same_block_spent(&self) -> &HashSet<OutPoint> {
        &self.same_block_spent
    }
}

fn same_block_spent_outpoints(
    txdata: &[Transaction],
    txids: &[Txid],
    height: u32,
) -> Result<HashSet<OutPoint>, ApplyError> {
    let mut created = HashSet::new();
    let mut spent = HashSet::new();
    for (tx, txid) in txdata.iter().zip(txids) {
        if !tx.is_coinbase() {
            for input in &tx.input {
                let previous_output = internal_outpoint(&input.previous_output);
                if created.contains(&previous_output) {
                    spent.insert(previous_output);
                }
            }
        }

        let txid = Hash256::from_le_bytes(txid.as_byte_array());
        for (vout, _txout) in tx.output.iter().enumerate() {
            created.insert(OutPoint::new(
                txid,
                u32::try_from(vout).map_err(|_| ApplyError::HeightOverflow(height))?,
            ));
        }
    }
    Ok(spent)
}

fn internal_outpoint(outpoint: &bitcoin::OutPoint) -> OutPoint {
    OutPoint::new(
        Hash256::from_le_bytes(outpoint.txid.as_byte_array()),
        outpoint.vout,
    )
}
