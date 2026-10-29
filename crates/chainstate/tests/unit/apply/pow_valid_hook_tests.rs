//! Early compact-block announce hook: firing rules at the connect site.
//!
//! The hook fires exactly once per commit-intent tip child whose parent is
//! the published tip, after block rules pass and before the durable commit.
//! It never fires for a block whose parent is stale, and a later connect
//! failure sends nothing more while leaving the published tip unchanged.

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
use crate::test_fixtures::{handles, seed_genesis};

type HookCalls = Arc<Mutex<Vec<(Hash256, u32)>>>;

fn recording_hook(calls: &HookCalls) -> crate::PowValidBlockHook {
    let calls = Arc::clone(calls);
    Arc::new(move |_block, hash, height| {
        calls.lock().expect("hook calls").push((hash, height));
    })
}

#[test]
fn pow_valid_hook_fires_once_for_tip_child_commit() -> Result<(), Box<dyn std::error::Error>> {
    let handles = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    let calls: HookCalls = Arc::new(Mutex::new(Vec::new()));
    handles
        .set_pow_valid_block(recording_hook(&calls))
        .map_err(|_| "hook installs once")?;
    // Seeding publishes the tip directly: no connect, no hook.
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
fn pow_valid_hook_skips_stale_parent_and_failed_connects() -> Result<(), Box<dyn std::error::Error>>
{
    let handles = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    let calls: HookCalls = Arc::new(Mutex::new(Vec::new()));
    handles
        .set_pow_valid_block(recording_hook(&calls))
        .map_err(|_| "hook installs once")?;
    let genesis_tip = seed_genesis(&handles)?;
    for height in 1..=3 {
        let tip = handles.applied_tip_snapshot().ok_or("tip")?;
        let block = mined_child(tip.hash.into(), height)?;
        handles.apply_block(&BlockPayload::from_local(block))?;
    }
    assert_eq!(handles.applied_tip_snapshot().ok_or("tip")?.height, 3);
    calls.lock().expect("hook calls").clear();

    // A fork off genesis: its parent is not the published tip, so the hook
    // must not fire whether the fork stages or is refused.
    let stale = mined_child(genesis_tip.hash.into(), 1)?;
    let _ = handles.apply_block(&BlockPayload::from_local(stale));
    assert!(
        calls.lock().expect("hook calls").is_empty(),
        "a stale-parent block never announces early"
    );
    assert_eq!(
        handles.applied_tip_snapshot().ok_or("tip")?.height,
        3,
        "a stale fork never moves the published tip"
    );

    // A rules-valid tip child that fails later (coinbase overspend): the
    // hook fires at the rules boundary, then the failure sends nothing more
    // and the published tip stays put.
    let tip = handles.applied_tip_snapshot().ok_or("tip")?;
    let mut falling = mined_child(tip.hash.into(), 4)?;
    let coinbase = falling
        .txs
        .first_mut()
        .ok_or("coinbase")?
        .outputs
        .first_mut()
        .ok_or("coinbase output")?;
    coinbase.value = bitcoin_rs_primitives::Amount::from_sat(
        coinbase
            .value
            .to_sat()
            .checked_add(1)
            .ok_or("value overflow")?,
    );
    falling.header.merkle_root =
        merkle_root(&falling.txs).ok_or("merkle root of non-empty block")?;
    mine_block_to_declared_target(&mut falling)
        .map_err(|error| format!("regrind overspend block: {error:?}"))?;
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
        handles.applied_tip_snapshot().ok_or("tip")?.height,
        3,
        "a failed connect leaves the published tip unchanged"
    );
    Ok(())
}

#[test]
fn pow_valid_hook_skips_non_final_commit_intent_block() -> Result<(), Box<dyn std::error::Error>> {
    let handles = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    let calls: HookCalls = Arc::new(Mutex::new(Vec::new()));
    handles
        .set_pow_valid_block(recording_hook(&calls))
        .map_err(|_| "hook installs once")?;
    seed_genesis(&handles)?;
    let tip = handles.applied_tip_snapshot().ok_or("tip")?;
    // A coinbase timelock with an enabled sequence is non-final at height 1.
    // Block rules still pass, so only the contextual precheck can refuse it
    // before the announcement.
    let mut non_final = mined_child(tip.hash.into(), 1)?;
    let coinbase = non_final.txs.first_mut().ok_or("coinbase")?;
    coinbase.lock_time = bitcoin_rs_primitives::LockTime::from_consensus(2);
    coinbase
        .inputs
        .first_mut()
        .ok_or("coinbase input")?
        .sequence = bitcoin_rs_primitives::Sequence::from_consensus(0);
    non_final.header.merkle_root =
        merkle_root(&non_final.txs).ok_or("merkle root of non-empty block")?;
    mine_block_to_declared_target(&mut non_final)
        .map_err(|error| format!("regrind non-final block: {error:?}"))?;
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
-> Result<(), Box<dyn std::error::Error>> {
    let handles = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    let calls: HookCalls = Arc::new(Mutex::new(Vec::new()));
    handles
        .set_pow_valid_block(recording_hook(&calls))
        .map_err(|_| "hook installs once")?;
    // Regtest enforces BIP34 from height 500: seed the chain to 499 so the
    // next child is the first BIP34-gated block.
    let mut tip_hash = seed_genesis(&handles)?.hash;
    for height in 1..=499 {
        let block = mined_child(tip_hash.into(), height)?;
        handles.apply_block(&BlockPayload::from_local(block.clone()))?;
        tip_hash = Hash256::from(block.block_hash());
    }
    assert_eq!(handles.applied_tip_snapshot().ok_or("tip")?.height, 499);
    calls.lock().expect("hook calls").clear();
    // A coinbase that does not start with the height push violates BIP34
    // while passing block rules, so only the contextual precheck can refuse
    // it before the announcement.
    let mut violating = mined_child(tip_hash.into(), 500)?;
    violating
        .txs
        .first_mut()
        .ok_or("coinbase")?
        .inputs
        .first_mut()
        .ok_or("coinbase input")?
        .script_sig = vec![0x51].into();
    violating.header.merkle_root =
        merkle_root(&violating.txs).ok_or("merkle root of non-empty block")?;
    mine_block_to_declared_target(&mut violating)
        .map_err(|error| format!("regrind violating block: {error:?}"))?;
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
-> Result<(), Box<dyn std::error::Error>> {
    let handles = handles(Network::Regtest, Arc::new(UtxoSet::new()));
    let shadow = handles.clone();
    let calls: HookCalls = Arc::new(Mutex::new(Vec::new()));
    // Install through the pre-install clone: the original must refuse a
    // second install, and firing through the original must reach the
    // clone-installed hook.
    shadow
        .set_pow_valid_block(recording_hook(&calls))
        .map_err(|_| "hook installs once")?;
    assert!(
        handles.set_pow_valid_block(recording_hook(&calls)).is_err(),
        "the original must see the clone's install and refuse a second one"
    );
    seed_genesis(&handles)?;
    let tip = handles.applied_tip_snapshot().ok_or("tip")?;
    let child = mined_child(tip.hash.into(), 1)?;
    handles.apply_block(&BlockPayload::from_local(child.clone()))?;
    let fired = calls.lock().expect("hook calls").clone();
    assert_eq!(fired.len(), 1, "the clone-installed hook must announce");
    assert_eq!(fired[0].0, Hash256::from(child.block_hash()));
    handles
        .set_tip_staged(Arc::new(|_, _| {}))
        .map_err(|_| "hook installs once")?;
    assert!(
        shadow.set_tip_staged(Arc::new(|_, _| {})).is_err(),
        "the clone must see the install and refuse a second one"
    );
    Ok(())
}
