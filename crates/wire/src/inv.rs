use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin_rs_consensus::primitives::{BlockHash, Hash256};

pub fn native_block_hash(hash: bitcoin::BlockHash) -> BlockHash {
    use bitcoin::hashes::Hash as _;
    BlockHash::from(Hash256::from_le_bytes(hash.as_byte_array()))
}

pub fn wire_block_hash(hash: BlockHash) -> bitcoin::BlockHash {
    use bitcoin::hashes::Hash as _;
    bitcoin::BlockHash::from_byte_array(*hash.as_bytes())
}

pub const MAX_INV_PER_MSG: usize = 50_000;

pub fn request_witness(items: &mut [Inventory]) {
    for item in items {
        if let Inventory::Transaction(txid) = *item {
            *item = Inventory::WitnessTransaction(txid);
        }
    }
}

pub fn inventory_block_hash(item: &Inventory) -> Option<Hash256> {
    use bitcoin::hashes::Hash as _;
    match item {
        Inventory::Block(hash) | Inventory::WitnessBlock(hash) => {
            Some(Hash256::from_le_bytes(hash.as_byte_array()))
        }
        _ => None,
    }
}

pub(crate) fn inventory_tx_hash(item: &Inventory) -> Option<Hash256> {
    use bitcoin::hashes::Hash as _;
    match item {
        Inventory::Transaction(txid) | Inventory::WitnessTransaction(txid) => {
            Some(Hash256::from_le_bytes(txid.as_byte_array()))
        }
        Inventory::WTx(wtxid) => Some(Hash256::from_le_bytes(wtxid.as_byte_array())),
        _ => None,
    }
}

pub(crate) const fn is_within_inventory_bound(items: &[Inventory]) -> bool {
    items.len() <= MAX_INV_PER_MSG
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash as _;

    #[test]
    fn witness_flag_upgrades_transactions_only() {
        let txid = bitcoin::Txid::from_byte_array([1; 32]);
        let blockhash = bitcoin::BlockHash::from_byte_array([2; 32]);
        let mut items = vec![
            Inventory::Transaction(txid),
            Inventory::Block(blockhash),
            Inventory::WitnessBlock(blockhash),
            Inventory::WitnessTransaction(txid),
            Inventory::Unknown {
                inv_type: 7,
                hash: [3; 32],
            },
        ];
        let unchanged = items.clone();
        request_witness(&mut items);
        let mut expected = unchanged;
        expected[0] = Inventory::WitnessTransaction(txid);
        assert_eq!(items, expected);
    }
}
