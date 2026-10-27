//! Early compact-block announce hook at the node composition boundary.
//!
//! A rules-valid tip child fires the installed hook exactly once before the
//! durable commit; a block that fails later in connect sends nothing more
//! and leaves the published tip unchanged.

#![expect(
    clippy::expect_used,
    reason = "poisoned test-recorder locks must fail the test"
)]

use super::*;

use std::sync::Mutex;

type HookFires = Arc<Mutex<Vec<(Hash256, u32)>>>;

fn open_hook_chain(heights: u32) -> anyhow::Result<(tempfile::TempDir, NodeState, HookFires)> {
    let dir = tempfile::tempdir()?;
    let mut config = crate::NodeConfig::default_for_network(crate::Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    let state = NodeState::open(config, None)?;
    let fires: HookFires = Arc::new(Mutex::new(Vec::new()));
    let recorder = Arc::clone(&fires);
    state
        .chainstate()
        .set_pow_valid_block(Arc::new(move |_block, hash, height| {
            recorder
                .lock()
                .expect("hook recorder poisoned")
                .push((hash, height));
        }))
        .map_err(|_| anyhow::anyhow!("pow-valid hook installs once"))?;
    let genesis = bitcoin_rs_primitives::Network::Regtest.genesis_block();
    state.apply_block(&bitcoin_rs_primitives::BlockPayload::from_local(
        genesis.clone(),
    ))?;
    let mut previous = genesis.block_hash();
    let mut time = genesis.header.time;
    for height in 1..=heights {
        time += 1;
        let block = regtest_fixture::mined_regtest_child_at_time(previous, time, height)?;
        state.apply_block(&bitcoin_rs_primitives::BlockPayload::from_local(
            block.clone(),
        ))?;
        previous = block.block_hash();
    }
    fires.lock().expect("hook recorder poisoned").clear();
    Ok((dir, state, fires))
}

#[test]
fn connect_failure_after_early_send_keeps_tip_and_sends_nothing_more() -> anyhow::Result<()> {
    let (_dir, state, fires) = open_hook_chain(2)?;
    let tip_before = state
        .chainstate()
        .applied_tip_snapshot()
        .ok_or_else(|| anyhow::anyhow!("no applied tip"))?;

    // A rules-valid tip child: the hook fires once, then the tip advances.
    let valid = regtest_fixture::mined_regtest_child_at_time(
        tip_before.hash.into(),
        tip_before_time(&state)? + 1,
        tip_before.height + 1,
    )?;
    state.apply_block(&bitcoin_rs_primitives::BlockPayload::from_local(
        valid.clone(),
    ))?;
    let fired = fires.lock().expect("hook recorder poisoned").clone();
    assert_eq!(fired.len(), 1, "one early fire per committed tip child");
    assert_eq!(fired[0].0, Hash256::from(valid.block_hash()));
    assert_eq!(fired[0].1, tip_before.height + 1);

    // A rules-valid tip child that overspends its coinbase: the hook fires
    // at the rules boundary, the later amount check fails, the tip stays
    // put, and nothing fires again.
    let tip = state
        .chainstate()
        .applied_tip_snapshot()
        .ok_or_else(|| anyhow::anyhow!("no applied tip"))?;
    let mut falling = regtest_fixture::mined_regtest_child_at_time(
        tip.hash.into(),
        tip_before_time(&state)? + 2,
        tip.height + 1,
    )?;
    let coinbase = falling
        .txs
        .first_mut()
        .ok_or_else(|| anyhow::anyhow!("no coinbase"))?
        .outputs
        .first_mut()
        .ok_or_else(|| anyhow::anyhow!("no coinbase output"))?;
    coinbase.value = bitcoin_rs_primitives::Amount::from_sat(
        coinbase
            .value
            .to_sat()
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("value overflow"))?,
    );
    falling.header.merkle_root =
        regtest_fixture::merkle_root(&falling.txs).ok_or_else(|| anyhow::anyhow!("no root"))?;
    regtest_fixture::mine_block_to_declared_target(&mut falling)
        .map_err(|error| anyhow::anyhow!("regrind overspend block: {error:?}"))?;
    assert!(
        state
            .apply_block(&bitcoin_rs_primitives::BlockPayload::from_local(
                falling.clone(),
            ))
            .is_err(),
        "an overspent coinbase must fail connect after rules"
    );
    let fired = fires.lock().expect("hook recorder poisoned").clone();
    assert_eq!(
        fired.len(),
        2,
        "exactly the rules-boundary fire, nothing after the failure"
    );
    assert_eq!(fired[1].0, Hash256::from(falling.block_hash()));
    let tip_after = state
        .chainstate()
        .applied_tip_snapshot()
        .ok_or_else(|| anyhow::anyhow!("no applied tip"))?;
    assert_eq!(tip_after.height, tip.height);
    assert_eq!(tip_after.hash, tip.hash);
    Ok(())
}

fn tip_before_time(state: &NodeState) -> anyhow::Result<u32> {
    let tip = state
        .chainstate()
        .applied_tip_snapshot()
        .ok_or_else(|| anyhow::anyhow!("no applied tip"))?;
    let tree = state.chainstate().block_tree_reader();
    let guard = tree.read();
    let node = guard
        .node(tip.tip_id)
        .map_err(|error| anyhow::anyhow!("tip node missing: {error:?}"))?;
    Ok(node.header.time)
}
