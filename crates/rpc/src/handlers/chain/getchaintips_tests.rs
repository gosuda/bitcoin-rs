use alloc::sync::Arc;

use bitcoin_rs_chain::{ChainWork, NodeId, TipSnapshot};
use bitcoin_rs_primitives::Hash256;

use super::*;

fn synthetic_header(prev_blockhash: BlockHash, time: u32) -> Header {
    Header {
        version: 1,
        prev_blockhash,
        merkle_root: Hash256::default(),
        time,
        bits: CompactTarget::from_consensus(0x207f_ffff),
        nonce: 0,
    }
}

#[test]
fn getchaintips_returns_empty_on_fresh_context() {
    let ctx = Arc::new(Context::new());
    let result =
        getchaintips(&ctx, &json!([])).unwrap_or_else(|err| panic!("getchaintips failed: {err}"));
    let Some(arr) = result.as_array() else {
        panic!("expected array, got {result:?}");
    };
    assert!(arr.is_empty());
}

#[test]
fn getchaintips_emits_the_applied_tip_as_active() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = Arc::new(Context::new());
    let genesis = synthetic_header(BlockHash::default(), 1_000_000);
    let hash = genesis.compute_hash().0;
    let tip_id = {
        let mut tree = ctx.chain.block_tree.write();
        tree.insert_node(None, genesis, NodeStatus::Active)?
    };
    let tip = TipSnapshot {
        tip_id,
        height: 0,
        chainwork: ChainWork::ZERO,
        hash,
        chain_tx_count: bitcoin_rs_chain::ChainTxCount::UNKNOWN,
    };
    ctx.chain.chain_tip.store(Some(Arc::new(tip.clone())));
    ctx.chain.applied_tip.store(Some(Arc::new(tip)));
    let result =
        getchaintips(&ctx, &json!([])).unwrap_or_else(|err| panic!("getchaintips failed: {err}"));
    let Some(arr) = result.as_array() else {
        panic!("expected array, got {result:?}");
    };
    assert_eq!(arr.len(), 1);
    let Some(first) = arr.first() else {
        panic!("expected first element");
    };
    let Some(height) = first.get("height").and_then(JsonValueTrait::as_u64) else {
        panic!("height missing");
    };
    assert_eq!(height, 0);
    let Some(status) = first.get("status").and_then(JsonValueTrait::as_str) else {
        panic!("status missing");
    };
    assert_eq!(status, "active");
    Ok(())
}

#[test]
fn getchaintips_serves_snapshot_tip_without_a_tree_row() {
    let ctx = Arc::new(Context::new());
    let hash = Hash256::from_le_bytes(&[42_u8; 32]);
    ctx.chain.applied_tip.store(Some(Arc::new(TipSnapshot {
        tip_id: NodeId::new(0),
        height: 42,
        chainwork: ChainWork::ZERO,
        hash,
        chain_tx_count: bitcoin_rs_chain::ChainTxCount::UNKNOWN,
    })));
    let tips =
        getchaintips(&ctx, &json!([])).unwrap_or_else(|err| panic!("getchaintips failed: {err}"));
    let Some(list) = tips.as_array() else {
        panic!("expected array, got {tips:?}");
    };
    assert_eq!(list.len(), 1, "the snapshot tip must be listed: {tips:?}");
    let Some(tip) = list.first() else {
        panic!("expected first element");
    };
    assert_eq!(
        tip.get("status").and_then(JsonValueTrait::as_str),
        Some("active"),
        "applied tip must map to Core's active status: {tip:?}"
    );
    assert_eq!(
        tip.get("hash").and_then(JsonValueTrait::as_str),
        Some(hash.to_string_be().as_str())
    );
    assert_eq!(tip.get("height").and_then(JsonValueTrait::as_i64), Some(42));
    assert_eq!(
        tip.get("branchlen").and_then(JsonValueTrait::as_i64),
        Some(0)
    );
}

#[test]
fn getchaintips_emits_two_tips_when_chain_is_forked() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = Arc::new(Context::new());
    let (active_tip_id, active_chainwork, active_hash) = {
        let mut tree = ctx.chain.block_tree.write();
        let genesis = synthetic_header(BlockHash::default(), 1_000_000);
        let genesis_hash = genesis.compute_hash();
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::Active)?;
        let child_b_header = synthetic_header(genesis_hash, 1_000_900);
        let active_tip = tree.insert_node(Some(genesis_id), child_b_header, NodeStatus::Active)?;
        let mut child_a = synthetic_header(genesis_hash, 1_000_600);
        child_a.nonce = 1;
        let _header_tip = tree.insert_node(Some(genesis_id), child_a, NodeStatus::HeaderValid)?;
        let active_node = tree.node(active_tip)?;
        (active_tip, active_node.chainwork, active_node.hash)
    };
    let tip = TipSnapshot {
        tip_id: active_tip_id,
        height: 1,
        chainwork: active_chainwork,
        hash: active_hash,
        chain_tx_count: bitcoin_rs_chain::ChainTxCount::UNKNOWN,
    };
    ctx.chain.chain_tip.store(Some(Arc::new(tip.clone())));
    ctx.chain.applied_tip.store(Some(Arc::new(tip)));

    let result =
        getchaintips(&ctx, &json!([])).unwrap_or_else(|err| panic!("getchaintips failed: {err}"));
    let Some(arr) = result.as_array() else {
        panic!("expected array: {result:?}");
    };
    assert_eq!(arr.len(), 2, "expected two leaves: {arr:?}");
    let active_count = arr
        .iter()
        .filter(|tip| tip.get("status").and_then(JsonValueTrait::as_str) == Some("active"))
        .count();
    let headers_only_count = arr
        .iter()
        .filter(|tip| tip.get("status").and_then(JsonValueTrait::as_str) == Some("headers-only"))
        .count();
    assert_eq!(active_count, 1, "expected one active tip: {arr:?}");
    assert_eq!(
        headers_only_count, 1,
        "expected one headers-only tip: {arr:?}"
    );
    Ok(())
}
#[test]
fn getchaintips_emits_branchlen_one_for_non_active_sibling_of_active_tip()
-> Result<(), Box<dyn std::error::Error>> {
    let ctx = Arc::new(Context::new());

    let sibling_height = {
        let mut tree = ctx.chain.block_tree.write();
        let genesis = synthetic_header(BlockHash::default(), 1_000_000);
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::Active)?;
        let genesis_hash = tree.node(genesis_id)?.hash;
        let mut sibling = synthetic_header(genesis.compute_hash(), 1_000_600);
        sibling.nonce = 9;
        let sibling_id = tree.insert_node(Some(genesis_id), sibling, NodeStatus::HeaderValid)?;
        ctx.chain.chain_tip.store(Some(Arc::new(TipSnapshot {
            tip_id: genesis_id,
            height: 0,
            chainwork: ChainWork::ZERO,
            hash: genesis_hash,
            chain_tx_count: bitcoin_rs_chain::ChainTxCount::UNKNOWN,
        })));
        tree.node(sibling_id)?.height
    };

    let result =
        getchaintips(&ctx, &json!([])).unwrap_or_else(|err| panic!("getchaintips failed: {err}"));
    let Some(arr) = result.as_array() else {
        panic!("expected array: {result:?}");
    };
    let Some(sibling_entry) = arr
        .iter()
        .find(|entry| entry.get("status").and_then(JsonValueTrait::as_str) != Some("active"))
    else {
        panic!("expected non-active tip: {result:?}");
    };
    let Some(branchlen) = sibling_entry
        .get("branchlen")
        .and_then(JsonValueTrait::as_u64)
    else {
        panic!("branchlen missing: {sibling_entry:?}");
    };

    assert_eq!(
        branchlen, 1,
        "sibling at height 1 should have branchlen 1: {sibling_entry:?}"
    );
    assert_eq!(sibling_height, 1);
    Ok(())
}

fn ctx_with_headers_ahead(
    applied_height: u32,
    header_height: u32,
) -> Result<
    (
        Arc<Context>,
        bitcoin_rs_chain::NodeId,
        bitcoin_rs_chain::NodeId,
    ),
    Box<dyn std::error::Error>,
> {
    let ctx = Arc::new(Context::new());
    let mut previous = BlockHash::default();
    let mut parent = None;
    let mut applied = None;
    let mut header_tip = None;
    {
        let mut tree = ctx.chain.block_tree.write();
        for height in 0..=header_height {
            let header = synthetic_header(previous, 1_000_000 + height * 600);
            previous = header.compute_hash();
            let status = if height <= applied_height {
                NodeStatus::Active
            } else {
                NodeStatus::HeaderValid
            };
            let id = tree.insert_node(parent, header, status)?;
            parent = Some(id);
            if height == applied_height {
                applied = Some((id, tree.node(id)?.hash, tree.node(id)?.chainwork));
            }
            header_tip = Some(id);
        }
    }
    let (Some((applied_id, applied_hash, applied_work)), Some(header_id)) = (applied, header_tip)
    else {
        panic!("the fixture builds both tips");
    };
    ctx.chain.applied_tip.store(Some(Arc::new(TipSnapshot {
        tip_id: applied_id,
        height: applied_height,
        chainwork: applied_work,
        hash: applied_hash,
        chain_tx_count: bitcoin_rs_chain::ChainTxCount::UNKNOWN,
    })));
    Ok((ctx, applied_id, header_id))
}

fn tips_of(ctx: &Arc<Context>) -> Vec<sonic_rs::Value> {
    let result =
        getchaintips(ctx, &json!([])).unwrap_or_else(|err| panic!("getchaintips failed: {err}"));
    let Some(array) = result.as_array() else {
        panic!("expected array, got {result:?}");
    };
    array.iter().cloned().collect()
}

fn field<'a>(tip: &'a sonic_rs::Value, key: &str) -> &'a str {
    tip.get(key)
        .and_then(JsonValueTrait::as_str)
        .unwrap_or_else(|| panic!("{key} missing from {tip:?}"))
}

#[test]
fn the_applied_tip_is_reported_even_when_headers_run_ahead()
-> Result<(), Box<dyn std::error::Error>> {
    let (ctx, _applied, _header) = ctx_with_headers_ahead(3, 6)?;

    let tips = tips_of(&ctx);

    assert_eq!(
        tips.len(),
        2,
        "the header tip and the applied tip: {tips:?}"
    );
    let active: Vec<&sonic_rs::Value> = tips
        .iter()
        .filter(|tip| field(tip, "status") == "active")
        .collect();
    assert_eq!(active.len(), 1, "exactly one active tip: {tips:?}");
    assert_eq!(
        active
            .first()
            .and_then(|tip| tip.get("height"))
            .and_then(JsonValueTrait::as_u64),
        Some(3),
        "the active tip is the applied one, not the header one"
    );
    Ok(())
}

#[test]
fn a_header_tip_ahead_of_the_applied_tip_is_headers_only() -> Result<(), Box<dyn std::error::Error>>
{
    let (ctx, _applied, _header) = ctx_with_headers_ahead(3, 6)?;

    let tips = tips_of(&ctx);
    let Some(header_tip) = tips
        .iter()
        .find(|tip| tip.get("height").and_then(JsonValueTrait::as_u64) == Some(6))
    else {
        panic!("no tip at the header height: {tips:?}");
    };

    assert_eq!(field(header_tip, "status"), "headers-only");
    assert_eq!(
        header_tip.get("branchlen").and_then(JsonValueTrait::as_u64),
        Some(3),
        "three headers past the applied tip"
    );
    Ok(())
}

#[test]
fn the_active_tip_has_no_branch_length() -> Result<(), Box<dyn std::error::Error>> {
    let (ctx, _applied, _header) = ctx_with_headers_ahead(3, 6)?;
    let tips = tips_of(&ctx);
    let Some(active) = tips.iter().find(|tip| field(tip, "status") == "active") else {
        panic!("no active tip: {tips:?}");
    };
    assert_eq!(
        active.get("branchlen").and_then(JsonValueTrait::as_u64),
        Some(0)
    );
    Ok(())
}

#[test]
fn a_branch_left_behind_by_a_reorg_is_reported_as_headers_only()
-> Result<(), Box<dyn std::error::Error>> {
    let ctx = Arc::new(Context::new());
    let (abandoned_height, new_tip) = {
        let mut tree = ctx.chain.block_tree.write();
        let genesis = synthetic_header(BlockHash::default(), 1_000_000);
        let genesis_hash = genesis.compute_hash();
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::Active)?;

        let a1 = synthetic_header(genesis_hash, 1_000_600);
        let a1_hash = a1.compute_hash();
        let a1_id = tree.insert_node(Some(genesis_id), a1, NodeStatus::Active)?;
        let a2 = synthetic_header(a1_hash, 1_001_200);
        let a2_id = tree.insert_node(Some(a1_id), a2, NodeStatus::Active)?;
        let abandoned_height = tree.node(a2_id)?.height;

        let mut b2 = synthetic_header(a1_hash, 1_001_100);
        b2.nonce = 77;
        let b2_id = tree.insert_node(Some(a1_id), b2, NodeStatus::HeaderValid)?;
        let b3 = synthetic_header(b2.compute_hash(), 1_001_700);
        let b3_id = tree.insert_node(Some(b2_id), b3, NodeStatus::Active)?;

        assert_eq!(
            tree.node(a2_id)?.status,
            NodeStatus::Stale,
            "the fixture must actually displace the old tip"
        );
        let node = tree.node(b3_id)?;
        (
            abandoned_height,
            (b3_id, node.height, node.chainwork, node.hash),
        )
    };
    let (tip_id, height, chainwork, hash) = new_tip;
    ctx.chain.applied_tip.store(Some(Arc::new(TipSnapshot {
        tip_id,
        height,
        chainwork,
        hash,
        chain_tx_count: bitcoin_rs_chain::ChainTxCount::UNKNOWN,
    })));

    let tips = tips_of(&ctx);
    let Some(abandoned) = tips.iter().find(|tip| {
        tip.get("height").and_then(JsonValueTrait::as_u64) == Some(u64::from(abandoned_height))
    }) else {
        panic!("the abandoned tip is missing: {tips:?}");
    };

    assert_eq!(field(abandoned, "status"), "headers-only");
    assert_eq!(
        abandoned.get("branchlen").and_then(JsonValueTrait::as_u64),
        Some(1),
        "one block past the fork point"
    );
    Ok(())
}

#[test]
fn an_invalidated_applied_tip_is_not_reported_as_active() -> Result<(), Box<dyn std::error::Error>>
{
    let ctx = Arc::new(Context::new());
    let tip = {
        let mut tree = ctx.chain.block_tree.write();
        let genesis = synthetic_header(BlockHash::default(), 1_000_000);
        let genesis_hash = genesis.compute_hash();
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::Active)?;
        let child = synthetic_header(genesis_hash, 1_000_600);
        let child_id = tree.insert_node(Some(genesis_id), child, NodeStatus::Active)?;
        let node = tree.node(child_id)?;
        TipSnapshot {
            tip_id: child_id,
            height: node.height,
            chainwork: node.chainwork,
            hash: node.hash,
            chain_tx_count: node.chain_tx_count,
        }
    };
    ctx.chain.applied_tip.store(Some(Arc::new(tip.clone())));

    let before = tips_of(&ctx);
    let Some(active) = before
        .iter()
        .find(|reported| field(reported, "status") == "active")
    else {
        panic!("the applied tip must start out active: {before:?}");
    };
    assert_eq!(
        active.get("height").and_then(JsonValueTrait::as_u64),
        Some(u64::from(tip.height))
    );

    {
        let mut tree = ctx.chain.block_tree.write();
        tree.invalidate_subtree(tip.tip_id)?;
    }

    let after = tips_of(&ctx);
    let Some(reported) = after.iter().find(|reported| {
        reported.get("hash").and_then(JsonValueTrait::as_str)
            == Some(tip.hash.to_string_be().as_str())
    }) else {
        panic!("the invalidated block must still be listed: {after:?}");
    };
    assert_eq!(
        field(reported, "status"),
        "invalid",
        "an invalidated block must not be reported as the active chain"
    );
    assert!(
        !after
            .iter()
            .any(|reported| field(reported, "status") == "active"),
        "nothing is active while the invalidation is in flight: {after:?}"
    );
    Ok(())
}

/// Tips come back highest first, with no special place for the active one.
///
/// Core orders by height descending. A fork longer than the active chain is what an
/// operator is looking for, and sorting the active tip to the front would bury it.
#[test]
fn tips_are_ordered_by_height_descending() -> Result<(), Box<dyn std::error::Error>> {
    let (ctx, _applied, _header) = ctx_with_headers_ahead(3, 6)?;

    let heights: Vec<u64> = tips_of(&ctx)
        .iter()
        .map(|tip| {
            tip.get("height")
                .and_then(JsonValueTrait::as_u64)
                .unwrap_or_default()
        })
        .collect();

    assert_eq!(heights, vec![6, 3], "highest first: {heights:?}");
    Ok(())
}

#[test]
fn getchaintips_marks_unapplied_best_header_as_headers_only()
-> Result<(), Box<dyn std::error::Error>> {
    let ctx = Arc::new(Context::new());
    let (genesis_id, genesis_chainwork, genesis_hash) = {
        let mut tree = ctx.chain.block_tree.write();
        let genesis = synthetic_header(BlockHash::default(), 1_000_000);
        let genesis_id = tree.insert_node(None, genesis, NodeStatus::Active)?;
        let genesis_hash = tree.node(genesis_id)?.hash;
        let child = synthetic_header(genesis.compute_hash(), 1_000_900);
        let child_id = tree.insert_node(Some(genesis_id), child, NodeStatus::HeaderValid)?;
        assert_eq!(
            tree.node(child_id)?.status,
            NodeStatus::Active,
            "the heavier header leaf is promoted even before apply"
        );
        let genesis_node = tree.node(genesis_id)?;
        (genesis_id, genesis_node.chainwork, genesis_hash)
    };
    ctx.chain.applied_tip.store(Some(Arc::new(TipSnapshot {
        tip_id: genesis_id,
        height: 0,
        chainwork: genesis_chainwork,
        hash: genesis_hash,
        chain_tx_count: bitcoin_rs_chain::ChainTxCount::UNKNOWN,
    })));

    let result =
        getchaintips(&ctx, &json!([])).unwrap_or_else(|err| panic!("getchaintips failed: {err}"));
    let Some(arr) = result.as_array() else {
        panic!("expected array: {result:?}");
    };
    let headers_only_count = arr
        .iter()
        .filter(|tip| tip.get("status").and_then(JsonValueTrait::as_str) == Some("headers-only"))
        .count();
    let valid_fork_count = arr
        .iter()
        .filter(|tip| tip.get("status").and_then(JsonValueTrait::as_str) == Some("valid-fork"))
        .count();
    assert_eq!(
        headers_only_count, 1,
        "unapplied best header must be headers-only: {arr:?}"
    );
    assert_eq!(
        valid_fork_count, 0,
        "header-first continuation is not a valid-fork: {arr:?}"
    );
    Ok(())
}
