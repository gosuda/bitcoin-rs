use alloc::sync::Arc;

use bitcoin_rs_chain::{NodeStatus, TipSnapshot};
use sonic_rs::{JsonValueTrait, json};

use super::*;

pub(super) const TIP_TIME: u32 = 1_700_000_123;

pub(super) fn insert_counted_chain(ctx: &Context, times: &[u32], counts: &[u64]) -> TipSnapshot {
    assert_eq!(times.len(), counts.len());
    let mut tree = ctx.chain.block_tree.write();
    let mut parent = None;
    let mut prev = BlockHash::default();
    let mut tip = None;
    for (index, (time, count)) in times
        .iter()
        .copied()
        .zip(counts.iter().copied())
        .enumerate()
    {
        let height = u32::try_from(index).unwrap_or(u32::MAX);
        let header = Header {
            version: 1,
            prev_blockhash: prev,
            merkle_root: Hash256::default(),
            time,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: height,
        };
        prev = header.compute_hash();
        let id = tree
            .insert_node(parent, header, NodeStatus::Active)
            .unwrap_or_else(|err| panic!("insert {height}: {err}"));
        tree.restore_chain_tx_count(id, bitcoin_rs_chain::ChainTxCount::established(count))
            .unwrap_or_else(|err| panic!("count {height}: {err}"));
        parent = Some(id);
        let node = tree
            .node(id)
            .unwrap_or_else(|err| panic!("node {height}: {err}"));
        tip = Some(TipSnapshot {
            tip_id: id,
            height: node.height,
            chainwork: node.chainwork,
            hash: node.hash,
            chain_tx_count: node.chain_tx_count,
        });
    }
    tip.unwrap_or_else(|| panic!("missing tip"))
}

fn restarted_ctx(chain_tx_count: Option<u64>) -> Arc<Context> {
    let ctx = Context::new();
    let counts = match chain_tx_count {
        Some(count) => [1_u64, count],
        None => [0, 0],
    };
    let tip = insert_counted_chain(&ctx, &[1_000_000, TIP_TIME], &counts);
    ctx.chain.applied_tip.store(Some(Arc::new(tip)));
    let ctx = Arc::new(ctx);
    assert!(
        ctx.chain.blocks.read().is_empty(),
        "the fixture must leave the record log empty, or it is not a restart"
    );
    ctx
}

pub(super) fn insert_uncounted_chain(ctx: &Arc<Context>, blocks: usize) -> Vec<Hash256> {
    let mut parent = None;
    let mut prev = BlockHash::default();
    let mut hashes = Vec::new();
    let mut tip = None;
    for index in 0..blocks {
        let height = u32::try_from(index).unwrap_or(u32::MAX);
        let header = Header {
            version: 1,
            prev_blockhash: prev,
            merkle_root: Hash256::default(),
            time: 1_000_u32.saturating_add(height.saturating_mul(10)),
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: height,
        };
        prev = header.compute_hash();
        let mut tree = ctx.chain.block_tree.write();
        let id = tree
            .insert_node(parent, header, NodeStatus::Active)
            .unwrap_or_else(|err| panic!("insert {height}: {err}"));
        let node = tree
            .node(id)
            .unwrap_or_else(|err| panic!("node {height}: {err}"));
        hashes.push(node.hash);
        tip = Some(TipSnapshot {
            tip_id: id,
            height: node.height,
            chainwork: node.chainwork,
            hash: node.hash,
            chain_tx_count: node.chain_tx_count,
        });
        parent = Some(id);
    }
    ctx.chain.applied_tip.store(Some(Arc::new(
        tip.unwrap_or_else(|| panic!("chain of {blocks} blocks")),
    )));
    hashes
}

pub(super) fn stats_of(ctx: &Arc<Context>) -> sonic_rs::Value {
    getchaintxstats(ctx, &json!([])).unwrap_or_else(|err| panic!("getchaintxstats failed: {err}"))
}

#[test]
fn stats_come_from_the_selected_node_not_the_in_process_log() {
    let known = stats_of(&restarted_ctx(Some(1_315_805_869)));
    assert_eq!(
        known.get("txcount").and_then(JsonValueTrait::as_u64),
        Some(1_315_805_869),
        "folding the empty log would have reported zero"
    );
    assert_eq!(
        known.get("time").and_then(JsonValueTrait::as_u64),
        Some(u64::from(TIP_TIME)),
        "the tree knows the tip's timestamp; the log does not have to"
    );

    let unknown = restarted_ctx(None);
    assert_eq!(
        stats_of(&unknown)
            .get("txcount")
            .and_then(JsonValueTrait::as_u64),
        Some(0),
        "it must not invent a count it does not have"
    );
    let Some(tip) = unknown.chain.applied_tip.load_full() else {
        panic!("fixture has no applied tip");
    };
    unknown.chain.add_block(BlockRecord {
        hash: BlockHash::from(tip.hash),
        height: tip.height,
        body_size: 0,
        header: None,
        tx_count: 7,
        time: TIP_TIME,
    });
    assert_eq!(
        stats_of(&unknown)
            .get("txcount")
            .and_then(JsonValueTrait::as_u64),
        Some(0),
        "an unknown node count must not fall back to the in-process log"
    );
}

#[test]
fn historical_selection_uses_the_selected_nodes_count_and_mtp() {
    let ctx = Context::new();
    let tip = insert_counted_chain(
        &ctx,
        &[1_000, 1_600, 2_200, 2_800, 3_400],
        &[1, 4, 9, 16, 25],
    );
    ctx.chain.applied_tip.store(Some(Arc::new(tip.clone())));
    let ctx = Arc::new(ctx);
    let mid_hash = {
        let tree = ctx.chain.block_tree.read();
        let id = tree
            .node_at_height_from(tip.tip_id, 3)
            .unwrap_or_else(|| panic!("missing height 3"));
        tree.node(id)
            .unwrap_or_else(|err| panic!("mid node: {err}"))
            .hash
    };
    let value = getchaintxstats(&ctx, &json!([1, mid_hash.to_string_be()]))
        .unwrap_or_else(|err| panic!("historical getchaintxstats failed: {err}"));
    assert_eq!(
        value.get("txcount").and_then(JsonValueTrait::as_u64),
        Some(16)
    );
    assert_eq!(
        value
            .get("window_tx_count")
            .and_then(JsonValueTrait::as_u64),
        Some(7)
    );
    assert_eq!(
        value
            .get("window_interval")
            .and_then(JsonValueTrait::as_u64),
        Some(600)
    );
    assert_eq!(
        value
            .get("window_final_block_height")
            .and_then(JsonValueTrait::as_u64),
        Some(3)
    );
}

#[test]
fn default_tip_selection_uses_the_applied_node_count() {
    let ctx = Context::new();
    let tip = insert_counted_chain(&ctx, &[1_000, TIP_TIME], &[1, 11]);
    ctx.chain.applied_tip.store(Some(Arc::new(tip)));
    let ctx = Arc::new(ctx);
    assert_eq!(
        stats_of(&ctx)
            .get("txcount")
            .and_then(JsonValueTrait::as_u64),
        Some(11)
    );
}

#[test]
fn historical_stats_survive_an_empty_block_log() {
    let ctx = Context::new();
    let tip = insert_counted_chain(&ctx, &[1_000_000, 1_000_100, TIP_TIME], &[1, 1, 42]);
    ctx.chain.applied_tip.store(Some(Arc::new(tip)));
    let ctx = Arc::new(ctx);
    assert!(ctx.chain.blocks.read().is_empty());
    let hash = ctx.chain.applied_hash().to_string_be();
    let value = getchaintxstats(&ctx, &json!([1, hash.as_str()]))
        .unwrap_or_else(|err| panic!("reopen stats failed: {err}"));
    assert_eq!(
        value.get("txcount").and_then(JsonValueTrait::as_u64),
        Some(42)
    );
    assert_eq!(
        value
            .get("window_tx_count")
            .and_then(JsonValueTrait::as_u64),
        Some(41)
    );
}

#[test]
fn getchaintxstats_rejects_mismatched_log_prefix() {
    let ctx = Arc::new(Context::new());
    let branch = insert_uncounted_chain(&ctx, 3);
    let record = |height: u32, hash: Hash256| BlockRecord {
        hash: BlockHash::from(hash),
        height,
        body_size: 100,
        header: None,
        tx_count: 1,
        time: 1_000_u32.saturating_add(height.saturating_mul(10)),
    };

    for (index, hash) in branch.iter().enumerate() {
        let height = u32::try_from(index).unwrap_or(u32::MAX);
        ctx.chain.add_block(record(height, *hash));
    }
    let matched = getchaintxstats(&ctx, &json!([]))
        .unwrap_or_else(|err| panic!("matching-prefix stats failed: {err}"));
    assert_eq!(
        matched.get("txcount").and_then(JsonValueTrait::as_u64),
        Some(3),
        "a matching genesis prefix is a chain total"
    );
    let matched_window = getchaintxstats(&ctx, &json!([1]))
        .unwrap_or_else(|err| panic!("matching-prefix window failed: {err}"));
    assert_eq!(
        matched_window
            .get("window_tx_count")
            .and_then(JsonValueTrait::as_u64),
        Some(1),
        "one log answers both window ends"
    );

    ctx.chain.blocks.write().clear();
    let displaced = Hash256::from_le_bytes(&[0xee_u8; 32]);
    for (index, hash) in branch.iter().enumerate() {
        let height = u32::try_from(index).unwrap_or(u32::MAX);
        let claimed = if height == 1 { displaced } else { *hash };
        ctx.chain.add_block(record(height, claimed));
    }
    let mismatched = getchaintxstats(&ctx, &json!([]))
        .unwrap_or_else(|err| panic!("displaced-prefix stats failed: {err}"));
    assert_eq!(
        mismatched.get("txcount").and_then(JsonValueTrait::as_u64),
        Some(0),
        "the applied tip answers an unknown count as zero, never as 3"
    );
    let mismatched_window = getchaintxstats(&ctx, &json!([1]))
        .unwrap_or_else(|err| panic!("displaced-prefix window failed: {err}"));
    assert!(
        mismatched_window.get("window_tx_count").is_none(),
        "a displaced prefix must not name a window: {mismatched_window}"
    );
}

fn reorg_fixture(ctx: &Context) -> (Hash256, Hash256, TipSnapshot) {
    let mut tree = ctx.chain.block_tree.write();
    let genesis = Header {
        version: 1,
        prev_blockhash: BlockHash::default(),
        merkle_root: Hash256::default(),
        time: 1_000,
        bits: CompactTarget::from_consensus(0x207f_ffff),
        nonce: 0,
    };
    let genesis_id = tree
        .insert_node(None, genesis, NodeStatus::Active)
        .unwrap_or_else(|err| panic!("genesis: {err}"));
    tree.restore_chain_tx_count(genesis_id, bitcoin_rs_chain::ChainTxCount::established(1))
        .unwrap_or_else(|err| panic!("genesis count: {err}"));
    let lost = Header {
        version: 1,
        prev_blockhash: genesis.compute_hash(),
        merkle_root: Hash256::default(),
        time: 1_100,
        bits: CompactTarget::from_consensus(0x207f_ffff),
        nonce: 1,
    };
    let lost_id = tree
        .insert_node(Some(genesis_id), lost, NodeStatus::HeaderValid)
        .unwrap_or_else(|err| panic!("lost: {err}"));
    tree.restore_chain_tx_count(lost_id, bitcoin_rs_chain::ChainTxCount::established(3))
        .unwrap_or_else(|err| panic!("lost count: {err}"));
    let won = Header {
        version: 1,
        prev_blockhash: genesis.compute_hash(),
        merkle_root: Hash256::default(),
        time: 1_200,
        bits: CompactTarget::from_consensus(0x207f_ffff),
        nonce: 2,
    };
    let won_id = tree
        .insert_node(Some(genesis_id), won, NodeStatus::Active)
        .unwrap_or_else(|err| panic!("won: {err}"));
    tree.restore_chain_tx_count(won_id, bitcoin_rs_chain::ChainTxCount::established(8))
        .unwrap_or_else(|err| panic!("won count: {err}"));
    let child = Header {
        version: 1,
        prev_blockhash: won.compute_hash(),
        merkle_root: Hash256::default(),
        time: 1_300,
        bits: CompactTarget::from_consensus(0x207f_ffff),
        nonce: 3,
    };
    let child_id = tree
        .insert_node(Some(won_id), child, NodeStatus::Active)
        .unwrap_or_else(|err| panic!("child: {err}"));
    tree.restore_chain_tx_count(child_id, bitcoin_rs_chain::ChainTxCount::established(15))
        .unwrap_or_else(|err| panic!("child count: {err}"));
    let lost_hash = tree
        .node(lost_id)
        .unwrap_or_else(|err| panic!("lost node: {err}"))
        .hash;
    let child_node = tree
        .node(child_id)
        .unwrap_or_else(|err| panic!("child node: {err}"));
    (
        tree.node(genesis_id)
            .unwrap_or_else(|err| panic!("genesis node: {err}"))
            .hash,
        lost_hash,
        TipSnapshot {
            tip_id: child_id,
            height: child_node.height,
            chainwork: child_node.chainwork,
            hash: child_node.hash,
            chain_tx_count: child_node.chain_tx_count,
        },
    )
}

#[test]
fn reorg_selects_the_winning_branch_counts() {
    let ctx = Context::new();
    let (genesis_hash, lost_hash, won) = reorg_fixture(&ctx);
    ctx.chain.applied_tip.store(Some(Arc::new(won.clone())));
    let ctx = Arc::new(ctx);
    let _ = genesis_hash;
    assert_eq!(
        stats_of(&ctx)
            .get("txcount")
            .and_then(JsonValueTrait::as_u64),
        Some(15),
        "default selection must follow the applied branch"
    );
    let err = getchaintxstats(&ctx, &json!([1, lost_hash.to_string_be()])).unwrap_err();
    assert!(matches!(
        err,
        RpcError::InvalidParameter(message) if message == "Block is not in main chain"
    ));
    let value = getchaintxstats(&ctx, &json!([1, won.hash.to_string_be()]))
        .unwrap_or_else(|err| panic!("winning branch stats failed: {err}"));
    assert_eq!(
        value.get("txcount").and_then(JsonValueTrait::as_u64),
        Some(15)
    );
    assert_eq!(
        value
            .get("window_tx_count")
            .and_then(JsonValueTrait::as_u64),
        Some(7)
    );
}
