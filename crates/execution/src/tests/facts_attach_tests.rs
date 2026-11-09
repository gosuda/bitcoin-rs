use std::sync::Arc;

use bitcoin_rs_consensus::primitives::{
    Amount, BlockImage, LockTime, Network, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Witness,
};
use bitcoin_rs_storage::utxo::UtxoSet;

use crate::chain::regtest_fixture::{
    coinbase, mined_block_with_prev_hash, mined_regtest_child_at as mined_child,
};
use crate::test_fixtures::{TestError, TestResult, handles, seed_genesis};

// CMT-09
#[test]
fn connect_builds_no_facts_without_a_consumer() -> TestResult {
    let chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    seed_genesis(&chain)?;
    let genesis = Network::Regtest.genesis_block();
    let outcome = chain.apply_block(&BlockImage::from_local(mined_child(
        genesis.block_hash(),
        1,
    )?))?;

    assert!(
        outcome.committed_facts.is_none(),
        "no consumer is attached, so the connect must not build facts"
    );
    assert_eq!(
        chain.committed_facts_builds(),
        0,
        "no consumer is attached, so no CommittedFacts may be constructed"
    );
    Ok(())
}

// CMT-09
#[test]
fn connect_hands_facts_to_an_attached_consumer_unchanged() -> TestResult {
    let chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    chain.set_committed_facts_consumer(true);
    seed_genesis(&chain)?;
    let genesis = Network::Regtest.genesis_block();
    let block = mined_child(genesis.block_hash(), 1)?;
    let expected_hash = *block.block_hash().as_bytes();
    let expected_txs = block.txs.len();
    let outcome = chain.apply_block(&BlockImage::from_local(block))?;

    assert_eq!(chain.committed_facts_builds(), 1);
    let facts = outcome
        .committed_facts
        .as_ref()
        .ok_or(TestError::Missing("attached consumer must receive facts"))?;
    assert_eq!(facts.commit_id, outcome.commit_id);
    assert_eq!(facts.blocks.len(), 1);
    assert_eq!(facts.blocks[0].height, 1);
    assert_eq!(facts.blocks[0].hash, expected_hash);
    assert_eq!(facts.blocks[0].txs.len(), expected_txs);
    Ok(())
}

fn spend(previous_output: OutPoint, value: u64) -> Tx {
    Tx {
        version: 1,
        inputs: vec![TxIn {
            previous_output,
            script_sig: Script::from_bytes(vec![0x51]),
            sequence: Sequence::from_consensus(0xffff_ffff),
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: Script::from_bytes(vec![0x51]),
        }],
        lock_time: LockTime::ZERO,
    }
}

// CMT-09
#[test]
fn attached_consumer_receives_spend_prevouts_and_scripts_unchanged() -> TestResult {
    let chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    chain.set_committed_facts_consumer(true);
    seed_genesis(&chain)?;
    let mut parent = Network::Regtest.genesis_block().block_hash();
    for height in 1..=100 {
        let block = mined_block_with_prev_hash(parent, height, vec![coinbase(height)])?;
        chain.apply_block(&BlockImage::from_local(block.clone()))?;
        parent = block.block_hash();
    }

    let funding = coinbase(1);
    let funded = funding.outputs[0].clone();
    let spending = spend(OutPoint::new(funding.txid(), 0), 1_000);
    let block = mined_block_with_prev_hash(parent, 101, vec![coinbase(101), spending.clone()])?;
    let outcome = chain.apply_block(&BlockImage::from_local(block.clone()))?;

    let facts = outcome
        .committed_facts
        .as_ref()
        .ok_or(TestError::Missing("attached consumer must receive facts"))?;
    assert_eq!(facts.blocks.len(), 1);
    let committed = &facts.blocks[0];
    assert_eq!(committed.height, 101);
    assert_eq!(committed.hash, *block.block_hash().as_bytes());
    assert_eq!(committed.txs.len(), 2);

    let coinbase_facts = &committed.txs[0];
    assert!(coinbase_facts.inputs.is_empty());
    assert_eq!(coinbase_facts.outputs.len(), 1);
    assert_eq!(
        coinbase_facts.outputs[0].script.as_ref(),
        coinbase(101).outputs[0].script_pubkey.as_bytes()
    );

    let spend_facts = &committed.txs[1];
    assert_eq!(spend_facts.txid, *spending.txid().as_bytes());
    assert_eq!(spend_facts.inputs.len(), 1);
    let input = &spend_facts.inputs[0];
    assert_eq!(input.txid, *funding.txid().as_bytes());
    assert_eq!(input.vout, 0);
    assert_eq!(input.value, funded.value.to_sat());
    assert_eq!(input.script.as_ref(), funded.script_pubkey.as_bytes());
    assert_eq!(input.height, 1);
    assert!(input.coinbase);
    assert_eq!(spend_facts.outputs.len(), 1);
    assert_eq!(spend_facts.outputs[0].vout, 0);
    assert_eq!(spend_facts.outputs[0].value, 1_000);
    assert_eq!(
        spend_facts.outputs[0].script.as_ref(),
        spending.outputs[0].script_pubkey.as_bytes()
    );
    Ok(())
}
