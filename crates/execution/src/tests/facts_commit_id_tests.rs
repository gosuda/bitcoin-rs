//! Committed facts carry the durable commit id (#PRJ-01).

use std::sync::Arc;

use crate::chain::regtest_fixture::mined_regtest_child_at as mined_child;
use bitcoin_rs_consensus::primitives::{BlockImage, Hash256, Network};
use bitcoin_rs_storage::utxo::UtxoSet;
use bitcoin_rs_storage::{DurableHead, assumeutxo::AssumeUtxoDiskStatus};

use super::Chainstate;
use crate::test_fixtures::{TestResult, handles, seed_durable_head, seed_genesis};

fn commit_genesis_head(chain: &Chainstate) -> TestResult<u64> {
    let genesis = Network::Regtest.genesis_block();
    let head = DurableHead {
        assumeutxo: AssumeUtxoDiskStatus::Uninitialized,
        commit_id: 1,
        height: 0,
        tip: Hash256::from(genesis.block_hash()),
        chain_tx_count: 1,
        body_extent: None,
        undo_extent: None,
    };
    let commit_id = head.commit_id;
    seed_durable_head(chain, head)?;
    Ok(commit_id)
}

// PRJ-01
#[test]
fn committed_facts_carry_the_durable_commit_id() -> TestResult {
    let chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    chain.set_committed_facts_consumer(true);
    seed_genesis(&chain)?;
    let genesis_commit = commit_genesis_head(&chain)?;

    let child = mined_child(Network::Regtest.genesis_block().block_hash(), 1)?;
    let outcome = chain.apply_block(&BlockImage::from_local(child.clone()))?;

    assert!(outcome.commit_id > genesis_commit);
    let facts =
        outcome
            .committed_facts
            .as_ref()
            .ok_or(crate::test_fixtures::TestError::Missing(
                "committed facts on the live path",
            ))?;
    assert_eq!(
        facts.commit_id, outcome.commit_id,
        "facts must carry the commit id of the batch that published them"
    );
    assert_eq!(facts.blocks.len(), 1);
    assert_eq!(facts.blocks[0].height, 1);
    assert_eq!(facts.blocks[0].hash, *child.block_hash().as_bytes());
    Ok(())
}
