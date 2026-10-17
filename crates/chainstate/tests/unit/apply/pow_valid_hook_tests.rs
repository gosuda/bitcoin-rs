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
use bitcoin_rs_primitives::{Hash256, Network};
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
    let outcome = handles.apply_block(&child, None)?;
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
        handles.apply_block(&block, None)?;
    }
    assert_eq!(handles.applied_tip_snapshot().ok_or("tip")?.height, 3);
    calls.lock().expect("hook calls").clear();

    // A fork off genesis: its parent is not the published tip, so the hook
    // must not fire whether the fork stages or is refused.
    let stale = mined_child(genesis_tip.hash.into(), 1)?;
    let _ = handles.apply_block(&stale, None);
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
    let failed: Result<_, ApplyError> = handles.apply_block(&falling, None);
    assert!(
        failed.is_err(),
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
