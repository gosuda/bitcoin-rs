use bitcoin::hashes::Hash as _;
use bitcoin::{ScriptBuf, Txid};
use bitcoin_rs_primitives::{Hash256, OutPoint};
use hashbrown::{HashMap, HashSet};

use crate::state::ApplyError;

type SameBlockScriptMap = HashMap<OutPoint, ScriptBuf>;
type SameBlockSpentSet = HashSet<OutPoint>;

#[derive(Clone, Copy)]
pub(super) struct ApplyScratchCapacities {
    pub(super) created_outputs: usize,
    pub(super) spent_inputs: usize,
}

pub(super) struct ApplyScratch {
    txids: Vec<Txid>,
    raw_txs: Option<Vec<Vec<u8>>>,
    same_block_spent_output_scripts: Option<SameBlockScriptMap>,
    same_block_spent: Option<SameBlockSpentSet>,
    utxo_add_capacity: usize,
    utxo_remove_capacity: usize,
}

impl ApplyScratch {
    #[cfg(test)]
    pub(super) fn new(
        block: &bitcoin::Block,
        height: u32,
        include_raw_txs: bool,
        include_same_block_output_scripts: bool,
    ) -> Result<Self, ApplyError> {
        let txids = block
            .txdata
            .iter()
            .map(bitcoin::Transaction::compute_txid)
            .collect();
        Self::with_txids(
            block,
            height,
            include_raw_txs,
            include_same_block_output_scripts,
            txids,
        )
    }

    #[cfg(test)]
    pub(super) fn with_txids(
        block: &bitcoin::Block,
        height: u32,
        include_raw_txs: bool,
        include_same_block_output_scripts: bool,
        txids: Vec<Txid>,
    ) -> Result<Self, ApplyError> {
        let capacities = ApplyScratchCapacities {
            created_outputs: block.txdata.iter().map(|tx| tx.output.len()).sum(),
            spent_inputs: block
                .txdata
                .iter()
                .filter(|tx| !tx.is_coinbase())
                .map(|tx| tx.input.len())
                .sum(),
        };
        Self::with_txids_and_capacities(
            block,
            height,
            include_raw_txs,
            include_same_block_output_scripts,
            txids,
            capacities,
        )
    }

    pub(super) fn with_txids_and_capacities(
        block: &bitcoin::Block,
        height: u32,
        include_raw_txs: bool,
        include_same_block_output_scripts: bool,
        txids: Vec<Txid>,
        capacities: ApplyScratchCapacities,
    ) -> Result<Self, ApplyError> {
        debug_assert_eq!(txids.len(), block.txdata.len());
        let mut raw_txs = include_raw_txs.then(|| Vec::with_capacity(block.txdata.len()));
        let created_capacity = capacities.created_outputs;
        let spent_capacity = capacities.spent_inputs;
        let track_same_block_spends = spent_capacity != 0;
        let track_same_block_scripts = include_same_block_output_scripts && track_same_block_spends;
        let mut created_outpoints: Option<SameBlockSpentSet> = (track_same_block_spends
            && !track_same_block_scripts)
            .then(|| HashSet::with_capacity(created_capacity));
        let mut created_scripts: Option<SameBlockScriptMap> =
            track_same_block_scripts.then(|| HashMap::with_capacity(created_capacity));
        let mut same_block_spent: Option<SameBlockSpentSet> = None;
        let mut same_block_spent_output_scripts: Option<SameBlockScriptMap> =
            track_same_block_scripts.then(|| HashMap::with_capacity(spent_capacity));
        let mut same_block_spent_input_count = 0usize;

        for (tx, txid) in block.txdata.iter().zip(&txids) {
            if let Some(raw_txs) = &mut raw_txs {
                raw_txs.push(bitcoin::consensus::encode::serialize(tx));
            }

            if !tx.is_coinbase() {
                for input in &tx.input {
                    let previous_output = internal_outpoint(&input.previous_output);
                    if let Some(created_scripts) = &created_scripts {
                        if let Some(script) = created_scripts.get(&previous_output) {
                            same_block_spent
                                .get_or_insert_with(|| HashSet::with_capacity(spent_capacity))
                                .insert(previous_output);
                            same_block_spent_input_count += 1;
                            if let Some(spent_scripts) = &mut same_block_spent_output_scripts {
                                spent_scripts.insert(previous_output, script.clone());
                            }
                        }
                    } else if let Some(created_outpoints) = &created_outpoints
                        && created_outpoints.contains(&previous_output)
                    {
                        same_block_spent
                            .get_or_insert_with(|| HashSet::with_capacity(spent_capacity))
                            .insert(previous_output);
                        same_block_spent_input_count += 1;
                    }
                }
            }

            let txid = Hash256::from_le_bytes(txid.as_byte_array());
            for (vout, txout) in tx.output.iter().enumerate() {
                let outpoint = OutPoint::new(
                    txid,
                    u32::try_from(vout).map_err(|_| ApplyError::HeightOverflow(height))?,
                );
                if let Some(created_scripts) = &mut created_scripts {
                    created_scripts.insert(outpoint, txout.script_pubkey.clone());
                } else if let Some(created_outpoints) = &mut created_outpoints {
                    created_outpoints.insert(outpoint);
                }
            }
        }
        let same_block_spent_len = same_block_spent
            .as_ref()
            .map_or(0_usize, SameBlockSpentSet::len);
        let utxo_add_capacity = created_capacity.saturating_sub(same_block_spent_len);
        let utxo_remove_capacity = spent_capacity.saturating_sub(same_block_spent_input_count);
        Ok(Self {
            txids,
            raw_txs,
            same_block_spent_output_scripts,
            same_block_spent,
            utxo_add_capacity,
            utxo_remove_capacity,
        })
    }

    pub(super) fn txids(&self) -> &[Txid] {
        &self.txids
    }

    pub(super) fn raw_txs(&self) -> Option<&[Vec<u8>]> {
        self.raw_txs.as_deref()
    }

    pub(super) fn contains_same_block_spent(&self, outpoint: &OutPoint) -> bool {
        self.same_block_spent
            .as_ref()
            .is_some_and(|spent| spent.contains(outpoint))
    }

    pub(super) fn utxo_change_capacity(&self) -> (usize, usize) {
        (self.utxo_add_capacity, self.utxo_remove_capacity)
    }

    pub(super) fn same_block_spent_output_script(&self, outpoint: &OutPoint) -> Option<ScriptBuf> {
        self.same_block_spent_output_scripts
            .as_ref()?
            .get(outpoint)
            .cloned()
    }
}

fn internal_outpoint(outpoint: &bitcoin::OutPoint) -> OutPoint {
    OutPoint::new(
        Hash256::from_le_bytes(outpoint.txid.as_byte_array()),
        outpoint.vout,
    )
}
