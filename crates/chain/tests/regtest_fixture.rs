//! Differential checks for the shared regtest builders.

use bitcoin::hashes::Hash;
use bitcoin::script::Builder;
use bitcoin_rs_chain::regtest_fixture::{self, REGTEST_BITS};
use bitcoin_rs_chain::validate_pow;
use bitcoin_rs_primitives::{Block, BlockHash, Hash256, Network};

fn assert_merkle_root(block: &Block, height: u32) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        Some(block.header.merkle_root),
        regtest_fixture::merkle_root(&block.txs),
        "height {height}"
    );
    let txids = block
        .txs
        .iter()
        .map(|tx| bitcoin::Txid::from_byte_array(*tx.txid().as_bytes()));
    let root = bitcoin::merkle_tree::calculate_root(txids).ok_or("block has transactions")?;
    assert_eq!(
        block.header.merkle_root,
        Hash256::from_le_bytes(root.as_byte_array()),
        "height {height}"
    );
    Ok(())
}

#[test]
fn mined_children_bind_transactions_and_meet_the_declared_target_deterministically()
-> Result<(), Box<dyn std::error::Error>> {
    let parent = BlockHash::from(Network::Regtest.genesis_block_hash());
    for height in 1..=3 {
        let child = regtest_fixture::mined_regtest_child_at(parent, height)?;
        assert_eq!(child.header.version, 4, "height {height}");
        assert_eq!(
            child.header.bits.to_consensus(),
            REGTEST_BITS,
            "height {height}"
        );
        let target =
            bitcoin::Target::from_compact(bitcoin::CompactTarget::from_consensus(REGTEST_BITS));
        assert!(
            target.is_met_by(bitcoin::BlockHash::from_byte_array(
                *child.block_hash().as_bytes()
            )),
            "height {height}"
        );
        validate_pow(
            &child.header,
            Hash256::from(child.block_hash()),
            Network::Regtest,
        )?;
        let script = &child.txs[0].inputs[0].script_sig;
        assert!(
            script
                .as_bytes()
                .starts_with(&regtest_fixture::script_num_push(i64::from(height))),
            "height {height}"
        );
        assert!(
            (2..=100).contains(&script.as_bytes().len()),
            "height {height}"
        );
        assert_merkle_root(&child, height)?;
        let repeated = regtest_fixture::mined_regtest_child_at(parent, height)?;
        assert_eq!(child.header, repeated.header, "height {height}");
        assert_eq!(child.block_hash(), repeated.block_hash(), "height {height}");
    }
    Ok(())
}

#[test]
fn mined_block_binds_an_odd_transaction_count() -> Result<(), Box<dyn std::error::Error>> {
    let coinbase = regtest_fixture::coinbase(3);
    let mut tx2 = coinbase.clone();
    tx2.lock_time = bitcoin_rs_primitives::LockTime::from_consensus(1);
    let mut tx3 = coinbase.clone();
    tx3.lock_time = bitcoin_rs_primitives::LockTime::from_consensus(2);
    let block = regtest_fixture::mined_block_with_prev_hash(
        BlockHash::from(Network::Regtest.genesis_block_hash()),
        3,
        vec![coinbase, tx2, tx3],
    )?;
    assert_merkle_root(&block, 3)
}

#[test]
fn script_num_push_matches_cscriptnum() {
    for (value, expected) in [
        (0, &[0x00][..]),
        (1, &[0x51]),
        (16, &[0x60]),
        (127, &[0x01, 0x7f]),
        (128, &[0x02, 0x80, 0x00]),
        (-1, &[0x4f]),
    ] {
        let actual = regtest_fixture::script_num_push(value);
        let script = Builder::new().push_int(value).into_script();
        assert_eq!(actual, expected, "value {value}");
        assert_eq!(script.as_bytes(), expected, "bitcoin oracle for {value}");
        assert_eq!(
            actual,
            script.as_bytes(),
            "bitcoin/fixture differential for {value}"
        );
    }
}
