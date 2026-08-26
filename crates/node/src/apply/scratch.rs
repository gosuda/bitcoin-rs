use bitcoin::Txid;
#[cfg(test)]
use bitcoin::hashes::Hash as _;
#[cfg(test)]
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_primitives::OutPoint;
use hashbrown::HashSet;

pub(super) type SameBlockSpentSet = HashSet<OutPoint>;

#[derive(Clone, Copy)]
pub(super) struct ApplyScratchCapacities {
    pub(super) created_outputs: usize,
    pub(super) spent_inputs: usize,
}

pub(super) struct ApplyScratch {
    txids: Vec<Txid>,
    raw_txs: Option<Vec<Vec<u8>>>,
    same_block_spent: Option<SameBlockSpentSet>,
    utxo_add_capacity: usize,
    utxo_remove_capacity: usize,
}

impl ApplyScratch {
    #[cfg(test)]
    pub(super) fn new(block: &bitcoin::Block, include_raw_txs: bool) -> Self {
        let txids = block
            .txdata
            .iter()
            .map(bitcoin::Transaction::compute_txid)
            .collect();
        Self::with_txids(block, include_raw_txs, txids)
    }

    #[cfg(test)]
    pub(super) fn with_txids(
        block: &bitcoin::Block,
        include_raw_txs: bool,
        txids: Vec<Txid>,
    ) -> Self {
        let capacities = ApplyScratchCapacities {
            created_outputs: block.txdata.iter().map(|tx| tx.output.len()).sum(),
            spent_inputs: block
                .txdata
                .iter()
                .filter(|tx| !tx.is_coinbase())
                .map(|tx| tx.input.len())
                .sum(),
        };
        let (same_block_spent, same_block_spent_input_count) =
            detect_same_block_spends(block, &txids, capacities.spent_inputs);
        Self::from_prepared_parts(
            block,
            include_raw_txs,
            txids,
            capacities,
            same_block_spent,
            same_block_spent_input_count,
        )
    }

    pub(super) fn from_prepared_parts(
        block: &bitcoin::Block,
        include_raw_txs: bool,
        txids: Vec<Txid>,
        capacities: ApplyScratchCapacities,
        same_block_spent: Option<SameBlockSpentSet>,
        same_block_spent_input_count: usize,
    ) -> Self {
        debug_assert_eq!(txids.len(), block.txdata.len());
        let mut raw_txs = include_raw_txs.then(|| Vec::with_capacity(block.txdata.len()));
        let created_capacity = capacities.created_outputs;
        let spent_capacity = capacities.spent_inputs;

        if let Some(raw_txs) = &mut raw_txs {
            for tx in &block.txdata {
                raw_txs.push(bitcoin::consensus::encode::serialize(tx));
            }
        }
        let same_block_spent_len = same_block_spent
            .as_ref()
            .map_or(0_usize, SameBlockSpentSet::len);
        let utxo_add_capacity = created_capacity.saturating_sub(same_block_spent_len);
        let utxo_remove_capacity = spent_capacity.saturating_sub(same_block_spent_input_count);
        Self {
            txids,
            raw_txs,
            same_block_spent,
            utxo_add_capacity,
            utxo_remove_capacity,
        }
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

    pub(super) fn has_same_block_spends(&self) -> bool {
        self.same_block_spent
            .as_ref()
            .is_some_and(|spent| !spent.is_empty())
    }

    pub(super) fn utxo_change_capacity(&self) -> (usize, usize) {
        (self.utxo_add_capacity, self.utxo_remove_capacity)
    }
}

#[cfg(test)]
fn detect_same_block_spends(
    block: &bitcoin::Block,
    txids: &[Txid],
    spent_capacity: usize,
) -> (Option<SameBlockSpentSet>, usize) {
    if spent_capacity == 0 {
        return (None, 0);
    }

    let mut seen_txids = HashSet::with_capacity(block.txdata.len());
    let mut same_block_spent = None;
    let mut same_block_spent_input_count = 0usize;
    for (tx, txid) in block.txdata.iter().zip(txids) {
        if !tx.is_coinbase() {
            for input in &tx.input {
                let previous_txid =
                    Hash256::from_le_bytes(input.previous_output.txid.as_byte_array());
                if seen_txids.contains(&previous_txid) {
                    same_block_spent
                        .get_or_insert_with(|| HashSet::with_capacity(spent_capacity))
                        .insert(internal_outpoint(&input.previous_output));
                    same_block_spent_input_count = same_block_spent_input_count.saturating_add(1);
                }
            }
        }
        seen_txids.insert(Hash256::from_le_bytes(txid.as_byte_array()));
    }
    (same_block_spent, same_block_spent_input_count)
}

#[cfg(test)]
fn internal_outpoint(outpoint: &bitcoin::OutPoint) -> OutPoint {
    OutPoint::new(
        Hash256::from_le_bytes(outpoint.txid.as_byte_array()),
        outpoint.vout,
    )
}
