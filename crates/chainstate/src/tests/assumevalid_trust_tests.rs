//! `AssumeValid` script trust fails closed and follows pin ancestry (#1742).

use std::sync::Arc;

use bitcoin_rs_chain::regtest_fixture::{
    merkle_root, mine_block_to_declared_target, mined_regtest_child_at as mined_child,
};
use bitcoin_rs_consensus::{ConsensusError, ValidationEngine};
use bitcoin_rs_primitives::{
    Amount, Block, BlockHash, BlockPayload, LockTime, Network, OutPoint, Sequence, Tx, TxIn, TxOut,
    Witness,
};
use bitcoin_rs_script::{
    VerifyFlags,
    opcode::{OP_PUSHNUM_1, OP_RETURN},
};
use bitcoin_rs_utxo::UtxoSet;

use super::{ApplyError, AssumeValidGate, BlockProvenance, Chainstate, ValidationMode};
use crate::test_fixtures::{handles, seed_genesis};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct SpendView(OutPoint, TxOut);

impl bitcoin_rs_consensus::UtxoView for SpendView {
    fn lookup(&self, outpoint: &OutPoint) -> Option<TxOut> {
        (*outpoint == self.0).then(|| self.1.clone())
    }
}

fn remine(block: &mut Block) -> TestResult {
    block.header.merkle_root = merkle_root(&block.txs).ok_or("missing merkle root")?;
    mine_block_to_declared_target(block)?;
    Ok(())
}

fn funded_chain() -> TestResult<(Chainstate, OutPoint, TxOut, BlockHash)> {
    let chain = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    seed_genesis(&chain)?;
    let mut funding = mined_child(Network::Regtest.genesis_block().block_hash(), 1)?;
    funding.txs[0].outputs = vec![TxOut {
        value: Amount::from_sat(10_000),
        script_pubkey: vec![OP_PUSHNUM_1].into(),
    }];
    remine(&mut funding)?;
    chain.apply_block(&BlockPayload::from_local(funding.clone()))?;
    let outpoint = OutPoint::new(funding.txs[0].txid(), 0);
    let prevout = funding.txs[0].outputs[0].clone();
    let mut parent = funding.block_hash();
    for height in 2..=100 {
        let child = mined_child(parent, height)?;
        chain.apply_block(&BlockPayload::from_local(child.clone()))?;
        parent = child.block_hash();
    }
    Ok((chain, outpoint, prevout, parent))
}

fn spend_tx(funding: OutPoint, opcode: u8) -> Tx {
    Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: funding,
            script_sig: vec![opcode].into(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: vec![OP_PUSHNUM_1].into(),
        }],
        lock_time: LockTime::ZERO,
    }
}

fn spend_block(parent: BlockHash, funding: OutPoint, opcode: u8) -> TestResult<Block> {
    let mut block = mined_child(parent, 101)?;
    block.txs.push(spend_tx(funding, opcode));
    remine(&mut block)?;
    Ok(block)
}

fn check_script_verdict(block: &Block, prevout: &TxOut) -> Result<(), ConsensusError> {
    let spend = &block.txs[1];
    bitcoin_rs_consensus::verify_transaction(
        spend,
        &SpendView(spend.inputs[0].previous_output, prevout.clone()),
        101,
        0,
        VerifyFlags::MANDATORY,
        ValidationEngine::Native,
        None,
    )
}

fn assert_script_invalid(block: &Block, prevout: &TxOut) {
    let verdict = check_script_verdict(block, prevout);
    assert!(
        matches!(verdict, Err(ConsensusError::Script { .. })),
        "the fixture spend must be script-invalid, got {verdict:?}"
    );
}

fn assert_script_valid(block: &Block, prevout: &TxOut) -> TestResult {
    check_script_verdict(block, prevout)?;
    Ok(())
}

fn assert_rejected_unchanged(
    chain: &Chainstate,
    result: &Result<crate::ConnectOutcome, ApplyError>,
    funding: &OutPoint,
    tip_before: bitcoin_rs_primitives::Hash256,
) -> TestResult {
    assert!(
        matches!(
            &result,
            Err(ApplyError::Consensus(ConsensusError::Script { .. }))
        ),
        "the script-invalid spend must be rejected, got {result:?}"
    );
    assert_eq!(chain.applied_tip_snapshot().ok_or("tip")?.hash, tip_before);
    assert!(
        chain.utxo.get(funding).is_some(),
        "the funding coin must stay unspent"
    );
    Ok(())
}

#[test]
fn assume_valid_without_matching_pin_does_not_skip_scripts() -> TestResult {
    let (mut chain, funding, prevout, parent) = funded_chain()?;
    let invalid = spend_block(parent, funding, OP_RETURN)?;
    assert_script_invalid(&invalid, &prevout);
    chain.validation_mode = ValidationMode::AssumeValid;
    chain.assume_valid_height = 101;
    chain.assume_valid_gate = Arc::new(AssumeValidGate::with_anchor(None));
    chain.assume_valid_gate.evaluate(&chain.block_tree.read());
    let tip_before = chain.applied_tip_snapshot().ok_or("tip")?.hash;
    let failed = chain.apply_block(&BlockPayload::from_local(invalid));
    assert_rejected_unchanged(&chain, &failed, &funding, tip_before)?;
    Ok(())
}

#[test]
fn assume_valid_sibling_below_the_pin_runs_scripts() -> TestResult {
    let (mut chain, funding, prevout, parent) = funded_chain()?;
    let pin = spend_block(parent, funding, OP_PUSHNUM_1)?;
    assert_script_valid(&pin, &prevout)?;
    let mut successor = mined_child(pin.block_hash(), 102)?;
    remine(&mut successor)?;
    let sibling = spend_block(parent, funding, OP_RETURN)?;
    assert_script_invalid(&sibling, &prevout);
    chain.admit_headers(&[pin.header, successor.header, sibling.header])?;
    chain.validation_mode = ValidationMode::AssumeValid;
    chain.assume_valid_height = 101;
    chain.assume_valid_gate = Arc::new(AssumeValidGate::with_anchor(Some((
        101,
        pin.block_hash().0,
    ))));
    chain.assume_valid_gate.evaluate(&chain.block_tree.read());
    assert!(
        chain.scripts_verified_upstream(BlockProvenance::Network, 101, pin.block_hash().0),
        "the pin itself is the reachability control"
    );
    let tip_before = chain.applied_tip_snapshot().ok_or("tip")?.hash;
    let failed = chain.apply_block(&BlockPayload::from_local(sibling));
    assert_rejected_unchanged(&chain, &failed, &funding, tip_before)?;
    Ok(())
}

#[test]
fn assume_valid_pin_at_its_own_height_still_skips_scripts() -> TestResult {
    let (mut chain, funding, prevout, parent) = funded_chain()?;
    let pin = spend_block(parent, funding, OP_PUSHNUM_1)?;
    assert_script_valid(&pin, &prevout)?;
    let mut successor = mined_child(pin.block_hash(), 102)?;
    remine(&mut successor)?;
    chain.admit_headers(&[pin.header, successor.header])?;
    chain.validation_mode = ValidationMode::AssumeValid;
    chain.assume_valid_height = 101;
    chain.assume_valid_gate = Arc::new(AssumeValidGate::with_anchor(Some((
        101,
        pin.block_hash().0,
    ))));
    chain.assume_valid_gate.evaluate(&chain.block_tree.read());
    assert!(
        chain.scripts_verified_upstream(BlockProvenance::Network, 101, pin.block_hash().0),
        "the pin is on the best header chain and may skip"
    );
    chain.apply_block(&BlockPayload::from_local(pin))?;
    assert_eq!(chain.applied_tip_snapshot().ok_or("tip")?.height, 101);
    Ok(())
}

#[test]
fn assume_valid_trust_is_revoked_when_a_reorg_drops_the_pin() -> TestResult {
    let (mut chain, funding, prevout, parent) = funded_chain()?;
    let pin = spend_block(parent, funding, OP_PUSHNUM_1)?;
    let mut pin_successor = mined_child(pin.block_hash(), 102)?;
    remine(&mut pin_successor)?;
    let branch_block = spend_block(parent, funding, OP_RETURN)?;
    assert_script_invalid(&branch_block, &prevout);
    let mut branch_second = mined_child(branch_block.block_hash(), 102)?;
    remine(&mut branch_second)?;
    let mut branch_third = mined_child(branch_second.block_hash(), 103)?;
    remine(&mut branch_third)?;
    chain.admit_headers(&[
        pin.header,
        pin_successor.header,
        branch_block.header,
        branch_second.header,
        branch_third.header,
    ])?;
    chain.validation_mode = ValidationMode::AssumeValid;
    chain.assume_valid_height = 101;
    chain.assume_valid_gate = Arc::new(AssumeValidGate::with_anchor(Some((
        101,
        pin.block_hash().0,
    ))));
    chain.assume_valid_gate.evaluate(&chain.block_tree.read());
    let tip_before = chain.applied_tip_snapshot().ok_or("tip")?.hash;
    let failed = chain.apply_block(&BlockPayload::from_local(branch_block));
    assert_rejected_unchanged(&chain, &failed, &funding, tip_before)?;
    Ok(())
}
