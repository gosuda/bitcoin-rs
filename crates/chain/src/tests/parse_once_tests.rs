use std::sync::Arc;

use crate::chain::regtest_fixture::mined_regtest_child_at as mined_child;
use bitcoin_rs_consensus::kernel::{block_parse_call_count, reset_block_parse_call_count};
use bitcoin_rs_consensus::primitives::layout::{
    parse_exact_call_count, reset_parse_exact_call_count,
};
use bitcoin_rs_consensus::primitives::{BlockImage, Network};
use bitcoin_rs_storage::utxo::UtxoSet;

use crate::test_fixtures::{TestResult, commit_genesis_head, handles, seed_genesis};

// BLK-01
#[test]
fn normal_path_parses_each_block_once() -> TestResult {
    let chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    seed_genesis(&chain)?;
    commit_genesis_head(&chain)?;

    let genesis_hash = Network::Regtest.genesis_block().block_hash();
    let block = mined_child(genesis_hash, 1)?;
    let image = BlockImage::from_local(block.clone());

    reset_parse_exact_call_count();
    reset_block_parse_call_count();
    chain.admit_headers(&[block.header])?;
    chain.apply_block(&image)?;

    assert_eq!(
        block_parse_call_count(),
        0,
        "the normal path must not re-parse the block"
    );
    assert_eq!(
        parse_exact_call_count(),
        0,
        "the normal path must not re-parse the block bytes"
    );
    Ok(())
}
