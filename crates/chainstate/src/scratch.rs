use bitcoin_rs_primitives::{Block, OutPoint, Txid, consensus_bytes};
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
    pub(super) fn from_prepared_parts(
        block: &Block,
        include_raw_txs: bool,
        txids: Vec<Txid>,
        capacities: ApplyScratchCapacities,
        same_block_spent: Option<SameBlockSpentSet>,
        same_block_spent_input_count: usize,
    ) -> Self {
        debug_assert_eq!(txids.len(), block.txs.len());
        let mut raw_txs = include_raw_txs.then(|| Vec::with_capacity(block.txs.len()));
        let created_capacity = capacities.created_outputs;
        let spent_capacity = capacities.spent_inputs;

        if let Some(raw_txs) = &mut raw_txs {
            for tx in &block.txs {
                raw_txs.push(consensus_bytes(tx));
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

    /// Takes the derived-consumer payloads out of scratch after the UTXO commit.
    pub(super) fn into_payloads(self) -> (Vec<Txid>, Option<Vec<Vec<u8>>>) {
        (self.txids, self.raw_txs)
    }

    pub(super) fn same_block_spent(&self) -> Option<&SameBlockSpentSet> {
        self.same_block_spent.as_ref()
    }

    pub(super) fn utxo_change_capacity(&self) -> (usize, usize) {
        (self.utxo_add_capacity, self.utxo_remove_capacity)
    }
}
