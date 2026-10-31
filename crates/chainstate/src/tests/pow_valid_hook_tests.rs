#![expect(
    clippy::expect_used,
    reason = "poisoned test-recorder locks must fail the test"
)]

use std::sync::{Arc, Mutex};

use bitcoin_rs_chain::regtest_fixture::{
    merkle_root, mine_block_to_declared_target, mined_regtest_child_at as mined_child,
};
use bitcoin_rs_primitives::{BlockPayload, Hash256, Network};
use bitcoin_rs_utxo::UtxoSet;

use super::ApplyError;
use crate::test_fixtures::{TestError, TestResult, handles, seed_genesis};

type HookCalls = Arc<Mutex<Vec<(Hash256, u32)>>>;

fn recording_hook(calls: &HookCalls) -> crate::PowValidBlockHook {
    let calls = Arc::clone(calls);
    Arc::new(move |_block, hash, height| {
        calls.lock().expect("hook calls").push((hash, height));
    })
}

#[test]
fn pow_valid_hook_fires_once_for_tip_child_commit() -> TestResult {
    let handles = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    let calls: HookCalls = Arc::new(Mutex::new(Vec::new()));
    handles
        .set_pow_valid_block(recording_hook(&calls))
        .map_err(|_| TestError::HookAlreadyInstalled("hook installs once"))?;
    let genesis_tip = seed_genesis(&handles)?;
    assert!(calls.lock().expect("hook calls").is_empty());

    let child = mined_child(genesis_tip.hash.into(), 1)?;
    let outcome = handles.apply_block(&BlockPayload::from_local(child.clone()))?;
    assert_eq!(outcome.height, 1);
    let fired = calls.lock().expect("hook calls").clone();
    assert_eq!(fired.len(), 1, "one early fire per committed tip child");
    assert_eq!(fired[0].0, Hash256::from(child.block_hash()));
    assert_eq!(fired[0].1, 1);
    Ok(())
}

#[test]
fn pow_valid_hook_skips_stale_parent_and_failed_connects() -> TestResult
{
    let handles = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    let calls: HookCalls = Arc::new(Mutex::new(Vec::new()));
    handles
        .set_pow_valid_block(recording_hook(&calls))
        .map_err(|_| TestError::HookAlreadyInstalled("hook installs once"))?;
    let genesis_tip = seed_genesis(&handles)?;
    for height in 1..=3 {
        let tip = handles.applied_tip_snapshot().ok_or(TestError::Missing("tip"))?;
        let block = mined_child(tip.hash.into(), height)?;
        handles.apply_block(&BlockPayload::from_local(block))?;
    }
    assert_eq!(handles.applied_tip_snapshot().ok_or(TestError::Missing("tip"))?.height, 3);
    calls.lock().expect("hook calls").clear();

    let stale = mined_child(genesis_tip.hash.into(), 1)?;
    let _ = handles.apply_block(&BlockPayload::from_local(stale));
    assert!(
        calls.lock().expect("hook calls").is_empty(),
        "a stale-parent block never announces early"
    );
    assert_eq!(
        handles.applied_tip_snapshot().ok_or(TestError::Missing("tip"))?.height,
        3,
        "a stale fork never moves the published tip"
    );

    let tip = handles.applied_tip_snapshot().ok_or(TestError::Missing("tip"))?;
    let mut falling = mined_child(tip.hash.into(), 4)?;
    let coinbase = falling
        .txs
        .first_mut()
        .ok_or(TestError::Missing("coinbase"))?
        .outputs
        .first_mut()
        .ok_or(TestError::Missing("coinbase output"))?;
    coinbase.value = bitcoin_rs_primitives::Amount::from_sat(
        coinbase
            .value
            .to_sat()
            .checked_add(1)
            .ok_or(TestError::Missing("value overflow"))?,
    );
    falling.header.merkle_root =
        merkle_root(&falling.txs).ok_or(TestError::Missing("merkle root of non-empty block"))?;
    mine_block_to_declared_target(&mut falling)
        .map_err(|source| TestError::Regrind { what: "overspend", source })?;
    let failed: Result<_, ApplyError> =
        handles.apply_block(&BlockPayload::from_local(falling.clone()));
    assert!(
        matches!(
            failed,
            Err(ApplyError::Consensus(
                bitcoin_rs_consensus::ConsensusError::CoinbaseAmount { .. }
            ))
        ),
        "an overspent coinbase must fail connect after rules"
    );
    let fired = calls.lock().expect("hook calls").clone();
    assert_eq!(
        fired.len(),
        1,
        "exactly the rules-boundary fire, nothing after the failure"
    );
    assert_eq!(fired[0].0, Hash256::from(falling.block_hash()));
    assert_eq!(
        handles.applied_tip_snapshot().ok_or(TestError::Missing("tip"))?.height,
        3,
        "a failed connect leaves the published tip unchanged"
    );
    Ok(())
}

#[test]
fn pow_valid_hook_skips_non_final_commit_intent_block() -> TestResult {
    let handles = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    let calls: HookCalls = Arc::new(Mutex::new(Vec::new()));
    handles
        .set_pow_valid_block(recording_hook(&calls))
        .map_err(|_| TestError::HookAlreadyInstalled("hook installs once"))?;
    seed_genesis(&handles)?;
    let tip = handles.applied_tip_snapshot().ok_or(TestError::Missing("tip"))?;
    let mut non_final = mined_child(tip.hash.into(), 1)?;
    let coinbase = non_final.txs.first_mut().ok_or(TestError::Missing("coinbase"))?;
    coinbase.lock_time = bitcoin_rs_primitives::LockTime::from_consensus(2);
    coinbase
        .inputs
        .first_mut()
        .ok_or(TestError::Missing("coinbase input"))?
        .sequence = bitcoin_rs_primitives::Sequence::from_consensus(0);
    non_final.header.merkle_root =
        merkle_root(&non_final.txs).ok_or(TestError::Missing("merkle root of non-empty block"))?;
    mine_block_to_declared_target(&mut non_final)
        .map_err(|source| TestError::Regrind { what: "non-final", source })?;
    let failed: Result<_, ApplyError> = handles.apply_block(&BlockPayload::from_local(non_final));
    assert!(
        matches!(
            failed,
            Err(ApplyError::Consensus(
                bitcoin_rs_consensus::ConsensusError::Bip { .. }
            ))
        ),
        "a non-final block must fail connect, got {failed:?}"
    );
    assert!(
        calls.lock().expect("hook calls").is_empty(),
        "a non-final block never announces early"
    );
    Ok(())
}

#[test]
fn pow_valid_hook_skips_bip34_violating_commit_intent_block()
-> TestResult {
    let handles = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    let calls: HookCalls = Arc::new(Mutex::new(Vec::new()));
    handles
        .set_pow_valid_block(recording_hook(&calls))
        .map_err(|_| TestError::HookAlreadyInstalled("hook installs once"))?;
    let mut tip_hash = seed_genesis(&handles)?.hash;
    for height in 1..=499 {
        let block = mined_child(tip_hash.into(), height)?;
        handles.apply_block(&BlockPayload::from_local(block.clone()))?;
        tip_hash = Hash256::from(block.block_hash());
    }
    assert_eq!(handles.applied_tip_snapshot().ok_or(TestError::Missing("tip"))?.height, 499);
    calls.lock().expect("hook calls").clear();
    let mut violating = mined_child(tip_hash.into(), 500)?;
    violating
        .txs
        .first_mut()
        .ok_or(TestError::Missing("coinbase"))?
        .inputs
        .first_mut()
        .ok_or(TestError::Missing("coinbase input"))?
        .script_sig = vec![0x51, 0x51].into();
    violating.header.merkle_root =
        merkle_root(&violating.txs).ok_or(TestError::Missing("merkle root of non-empty block"))?;
    mine_block_to_declared_target(&mut violating)
        .map_err(|source| TestError::Regrind { what: "violating", source })?;
    let failed: Result<_, ApplyError> = handles.apply_block(&BlockPayload::from_local(violating));
    assert!(
        matches!(
            failed,
            Err(ApplyError::Consensus(
                bitcoin_rs_consensus::ConsensusError::Bip { .. }
            ))
        ),
        "a BIP34-violating block must fail connect, got {failed:?}"
    );
    assert!(
        calls.lock().expect("hook calls").is_empty(),
        "a BIP34-violating block never announces early"
    );
    Ok(())
}

#[test]
fn hook_installation_after_a_clone_is_visible_through_both_handles()
-> TestResult {
    let handles = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    let shadow = handles.clone();
    let calls: HookCalls = Arc::new(Mutex::new(Vec::new()));
    shadow
        .set_pow_valid_block(recording_hook(&calls))
        .map_err(|_| TestError::HookAlreadyInstalled("hook installs once"))?;
    assert!(
        handles.set_pow_valid_block(recording_hook(&calls)).is_err(),
        "the original must see the clone's install and refuse a second one"
    );
    seed_genesis(&handles)?;
    let tip = handles.applied_tip_snapshot().ok_or(TestError::Missing("tip"))?;
    let child = mined_child(tip.hash.into(), 1)?;
    handles.apply_block(&BlockPayload::from_local(child.clone()))?;
    let fired = calls.lock().expect("hook calls").clone();
    assert_eq!(fired.len(), 1, "the clone-installed hook must announce");
    assert_eq!(fired[0].0, Hash256::from(child.block_hash()));
    handles
        .set_tip_staged(Arc::new(|_, _| {}))
        .map_err(|_| TestError::HookAlreadyInstalled("hook installs once"))?;
    assert!(
        shadow.set_tip_staged(Arc::new(|_, _| {})).is_err(),
        "the clone must see the install and refuse a second one"
    );
    Ok(())
}

#[test]
fn pow_valid_hook_skips_legacy_sigop_violating_block() -> TestResult {
    let handles = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    let calls: HookCalls = Arc::new(Mutex::new(Vec::new()));
    handles
        .set_pow_valid_block(recording_hook(&calls))
        .map_err(|_| TestError::HookAlreadyInstalled("hook installs once"))?;
    let genesis_tip = seed_genesis(&handles)?;
    let mut block = mined_child(genesis_tip.hash.into(), 1)?;
    block.txs[0].outputs[0].script_pubkey =
        vec![bitcoin_rs_script::opcode::OP_CHECKSIG; 20_001].into();
    block.header.merkle_root = merkle_root(&block.txs).ok_or(TestError::Missing("merkle root of non-empty block"))?;
    mine_block_to_declared_target(&mut block)
        .map_err(|source| TestError::Regrind { what: "legacy sigop", source })?;
    let failed: Result<_, ApplyError> = handles.apply_block(&BlockPayload::from_local(block));
    assert!(
        matches!(
            &failed,
            Err(ApplyError::Consensus(
                bitcoin_rs_consensus::ConsensusError::SigopsLimit {
                    cost: 80_004,
                    max: 80_000,
                }
            ))
        ),
        "legacy sigop violation must fail connect, got {failed:?}"
    );
    assert!(
        calls.lock().expect("hook calls").is_empty(),
        "legacy sigop violation must be rejected before pow_valid hook"
    );
    Ok(())
}

#[test]
fn proposal_intent_rejects_non_final_coinbase_parity() -> TestResult {
    let handles = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    seed_genesis(&handles)?;
    let tip = handles.applied_tip_snapshot().ok_or(TestError::Missing("tip"))?;
    let mut non_final = mined_child(tip.hash.into(), 1)?;
    let coinbase = non_final.txs.first_mut().ok_or(TestError::Missing("coinbase"))?;
    coinbase.lock_time = bitcoin_rs_primitives::LockTime::from_consensus(2);
    coinbase
        .inputs
        .first_mut()
        .ok_or(TestError::Missing("coinbase input"))?
        .sequence = bitcoin_rs_primitives::Sequence::from_consensus(0);
    non_final.header.merkle_root =
        merkle_root(&non_final.txs).ok_or(TestError::Missing("merkle root of non-empty block"))?;
    mine_block_to_declared_target(&mut non_final)
        .map_err(|source| TestError::Regrind { what: "non-final", source })?;
    let payload = BlockPayload::from_local(non_final);
    let failed = handles.validate_block(&payload);
    assert!(
        matches!(
            &failed,
            Err(ApplyError::Consensus(
                bitcoin_rs_consensus::ConsensusError::Bip { bip: "BIP113", .. }
            ))
        ),
        "proposal intent must reject non-final coinbase under BIP113, got {failed:?}"
    );
    Ok(())
}
