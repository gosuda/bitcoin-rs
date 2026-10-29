#[path = "support/pow_oracle.rs"]
mod pow_oracle;

use bitcoin_rs_primitives::{BlockHash, Network};
use pow_oracle::pow_is_met;

#[test]
fn oracle_accepts_genesis_and_rejects_a_far_hash() {
    let genesis = Network::Regtest.genesis_block();
    assert!(
        pow_is_met(genesis.header.bits, &genesis.block_hash()),
        "the regtest genesis must meet its own compact target"
    );
    let far_hash = BlockHash(bitcoin_rs_primitives::Hash256::from_le_bytes(
        &[0xff_u8; 32],
    ));
    assert!(
        !pow_is_met(genesis.header.bits, &far_hash),
        "an all-ones hash must exceed the regtest target"
    );
    let mut le_bytes = [0_u8; 32];
    le_bytes[31] = 0x80;
    let le_2_pow_255 = BlockHash(bitcoin_rs_primitives::Hash256::from_le_bytes(&le_bytes));
    assert!(
        !pow_is_met(genesis.header.bits, &le_2_pow_255),
        "a hash encoding 2^255 little-endian must exceed the regtest target"
    );
}
