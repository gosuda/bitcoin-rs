use bitcoin_rs_primitives::{Hash256, Txid};

use super::{ChunkKey, MAX_CHUNK_FEE};

// POL-05
#[kani::proof]
fn chunk_key_cmp_is_antisymmetric() {
    let left = any_key();
    let right = any_key();
    assert_eq!(left.cmp(&right), right.cmp(&left).reverse());
}

fn any_key() -> ChunkKey {
    let fee: i128 = kani::any();
    kani::assume(fee >= -MAX_CHUNK_FEE && fee <= MAX_CHUNK_FEE);
    let charged_weight: u64 = kani::any();
    kani::assume(charged_weight > 0 && charged_weight <= u64::from(u32::MAX));
    let prefix_weight: u64 = kani::any();
    let bytes: [u8; 32] = kani::any();
    let component: u32 = kani::any();
    let ordinal: u32 = kani::any();
    ChunkKey {
        modified_fee: fee,
        charged_weight,
        prefix_weight,
        max_txid: Txid(Hash256::from_le_bytes(&bytes)),
        component,
        ordinal,
    }
}
