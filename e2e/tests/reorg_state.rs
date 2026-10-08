//! Process-level chain transition regressions against pinned Bitcoin Core.
//!
//! The two candidate nodes begin with identical Core-mined blocks. One
//! connects a losing branch before receiving Core's winning branch; the
//! other receives only the winning branch. Their public chainstate and
//! mempool observations must converge.

#![allow(clippy::unwrap_used)]
#![allow(clippy::expect_used)]

use std::time::{Duration, Instant};

use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::{Block, BlockHash, Sequence, Transaction};
use bitcoin_rs_e2e::differential::{CommonFunds, compare_reply, mine_common_chain};
use bitcoin_rs_e2e::helpers::{
    funding_address, grind_pow, mempool_txids, mine_bare_blocks, signed_spend, submit_genesis,
    tx_hex,
};
use bitcoin_rs_e2e::live_peer::LivePeer;
use bitcoin_rs_e2e::{Error, Kind, ProcessNode, Result, SpawnOptions, ValueExt};
use serde_json::{Value, json};

fn core_block(core: &mut ProcessNode, hash: &str) -> Result<Block> {
    let hex = core.rpc("getblock", &json!([hash, 0]))?;
    deserialize_hex(
        hex.as_str()
            .ok_or_else(|| Error::Assertion(format!("Core getblock did not return hex: {hex}")))?,
    )
    .map_err(|error| Error::Assertion(format!("Core block decode: {error}")))
}

fn mine_core_block(core: &mut ProcessNode, transactions: &[String]) -> Result<Block> {
    let reply = core.rpc(
        "generateblock",
        &json!([funding_address()?.to_string(), transactions]),
    )?;
    let hash = reply.str_field("hash")?.to_owned();
    let block = core_block(core, &hash)?;
    assert_eq!(block.block_hash().to_string(), hash);
    Ok(block)
}

fn feed_common_blocks(node: &mut ProcessNode, funds: &CommonFunds) -> Result<()> {
    submit_genesis(node)?;
    for bytes in &funds.common_block_bytes {
        let block: Block = bitcoin::consensus::deserialize(bytes)
            .map_err(|error| Error::Assertion(format!("shared block decode: {error}")))?;
        let reply = node.rpc("submitblock", &json!([serialize_hex(&block)]))?;
        assert!(reply.is_null(), "shared Core block was refused: {reply}");
    }
    Ok(())
}

fn submit_competing_headers(node: &mut ProcessNode, blocks: &[Block]) -> Result<()> {
    for block in blocks {
        assert_eq!(
            node.rpc("submitheader", &json!([serialize_hex(&block.header)]))?,
            Value::Null
        );
    }
    Ok(())
}

fn dial_core(core: &ProcessNode, node: &mut ProcessNode) -> Result<()> {
    assert_eq!(
        node.rpc("addnode", &json!([core.p2p_addr.to_string(), "onetry"]))?,
        Value::Null
    );
    Ok(())
}

/// Stable, implementation-independent fields of the public chain/UTXO view.
/// Disk-size estimates are intentionally absent; Core and fjall store the
/// same coins using different physical layouts.
fn chain_view(node: &mut ProcessNode) -> Result<Value> {
    let chain = node.rpc("getblockchaininfo", &json!([]))?;
    let coins = node.rpc("gettxoutsetinfo", &json!(["muhash", null, false]))?;
    Ok(json!({
        "height": chain.u64_field("blocks")?,
        "tip": chain.str_field("bestblockhash")?,
        "work": chain.str_field("chainwork")?,
        "utxo_height": coins.u64_field("height")?,
        "utxo_tip": coins.str_field("bestblock")?,
        "transactions": coins.u64_field("transactions")?,
        "txouts": coins.u64_field("txouts")?,
        "amount": coins.field("total_amount")?.as_f64().ok_or_else(|| {
            Error::Assertion(format!("gettxoutsetinfo total_amount: {coins}"))
        })?,
        "muhash": coins.str_field("muhash")?,
    }))
}

fn compare_chain_views(
    core: &mut ProcessNode,
    reorg: &mut ProcessNode,
    clean: &mut ProcessNode,
) -> Result<()> {
    let reference = chain_view(core)?;
    compare_reply(
        "reorg chain and UTXO vs Core",
        &reference,
        &chain_view(reorg)?,
    )?;
    compare_reply(
        "clean sync chain and UTXO vs Core",
        &reference,
        &chain_view(clean)?,
    )
}

fn sorted_mempool(node: &mut ProcessNode) -> Result<Vec<String>> {
    let mut txids = mempool_txids(node)?;
    txids.sort();
    Ok(txids)
}

fn coin(node: &mut ProcessNode, txid: &str, include_mempool: bool) -> Result<Value> {
    let reply = node.rpc("gettxout", &json!([txid, 0, include_mempool]))?;
    if reply.is_null() {
        return Ok(Value::Null);
    }
    Ok(json!({
        "bestblock": reply.str_field("bestblock")?,
        "confirmations": reply.u64_field("confirmations")?,
        "coinbase": reply.field("coinbase")?,
        "value": reply.field("value")?,
    }))
}

fn compare_coin(
    core: &mut ProcessNode,
    reorg: &mut ProcessNode,
    clean: &mut ProcessNode,
    txid: &str,
    include_mempool: bool,
) -> Result<Value> {
    let reference = coin(core, txid, include_mempool)?;
    compare_reply(
        "reorg coin vs Core",
        &reference,
        &coin(reorg, txid, include_mempool)?,
    )?;
    compare_reply(
        "clean coin vs Core",
        &reference,
        &coin(clean, txid, include_mempool)?,
    )?;
    Ok(reference)
}

fn submit_mempool(node: &mut ProcessNode, tx: &Transaction) -> Result<()> {
    assert_eq!(
        node.rpc("sendrawtransaction", &json!([tx_hex(tx)]))?,
        json!(tx.compute_txid().to_string())
    );
    Ok(())
}

fn confirmed_tx(node: &mut ProcessNode, txid: &str, block: &str) -> Result<Value> {
    let reply = node.rpc("getrawtransaction", &json!([txid, true, block]))?;
    Ok(json!({
        "txid": reply.str_field("txid")?,
        "blockhash": reply.str_field("blockhash")?,
        "confirmations": reply.u64_field("confirmations")?,
        "in_active_chain": reply.field("in_active_chain")?,
    }))
}

fn assert_transaction_status(
    core: &mut ProcessNode,
    reorg: &mut ProcessNode,
    clean: &mut ProcessNode,
    survivor_txid: &str,
    new_txid: &str,
    new_block_hash: &str,
    old_txid: &str,
) -> Result<()> {
    for node in [&mut *core, &mut *reorg, &mut *clean] {
        let unconfirmed = node.rpc("getrawtransaction", &json!([survivor_txid, true]))?;
        assert_eq!(unconfirmed.str_field("txid")?, survivor_txid);
        assert!(unconfirmed.get("blockhash").is_none());
        assert!(unconfirmed.get("confirmations").is_none());
    }
    let confirmation = confirmed_tx(core, new_txid, new_block_hash)?;
    assert_eq!(confirmation["in_active_chain"], json!(true));
    assert_eq!(confirmation["confirmations"], json!(4));
    compare_reply(
        "reorg transaction confirmation vs Core",
        &confirmation,
        &confirmed_tx(reorg, new_txid, new_block_hash)?,
    )?;
    compare_reply(
        "clean transaction confirmation vs Core",
        &confirmation,
        &confirmed_tx(clean, new_txid, new_block_hash)?,
    )?;
    for node in [&mut *reorg, &mut *clean] {
        let old = node.rpc_raw(&json!({
            "jsonrpc": "2.0", "id": 1, "method": "getrawtransaction",
            "params": [old_txid, true]
        }))?;
        assert_eq!(old["error"]["code"], json!(-5));
    }
    Ok(())
}

fn deliver_invalid_branch(
    node: &mut ProcessNode,
    rival: &[Block],
    first_hash: BlockHash,
) -> Result<()> {
    assert_eq!(rival.len(), 2);
    let mut peer = LivePeer::connect_with_height(node, "invalid-reorg", 2)?;
    peer.offer_bodies(rival);
    peer.headers = rival.iter().map(|block| block.header).collect();
    let deadline = Instant::now() + Duration::from_secs(10);
    let headers = peer.headers.clone();
    peer.send(NetworkMessage::Headers(headers), deadline)?;
    peer.send(
        NetworkMessage::Inv(vec![Inventory::Block(rival[1].block_hash())]),
        deadline,
    )?;
    let deadline = Instant::now() + Duration::from_secs(25);
    let mut served_invalid_body = false;
    let mut serve_error = None;
    while Instant::now() < deadline && !served_invalid_body && !peer.dropped {
        peer.pump(Duration::from_millis(250), &mut |peer, items| {
            let deadline = Instant::now() + Duration::from_secs(5);
            for item in items {
                let first = matches!(item,
                    Inventory::WitnessBlock(hash) | Inventory::CompactBlock(hash) | Inventory::Block(hash)
                        if *hash == first_hash
                );
                match peer.serve_item(item, deadline) {
                    Ok(()) if first => served_invalid_body = true,
                    Err(error) => serve_error = Some(error),
                    Ok(()) => {}
                }
            }
        });
        if let Some(error) = serve_error.take() {
            return Err(error);
        }
    }
    assert!(
        served_invalid_body,
        "node never requested and received the invalid higher-work branch body"
    );
    node.wait_for("invalid branch status", Duration::from_secs(10), |node| {
        let tips = node.rpc("getchaintips", &json!([]))?;
        let invalid = tips.as_array().is_some_and(|tips| {
            tips.iter().any(|tip| {
                tip.get("hash") == Some(&json!(rival[1].block_hash().to_string()))
                    && tip.get("status") == Some(&json!("invalid"))
            })
        });
        Ok(invalid.then_some(()))
    })
}

/// Three disconnected blocks contain a transaction that conflicts with the
/// new branch and an independent transaction that must return to the pool.
/// The clean path starts with the same two mempool transactions, so the
/// final mempool comparison tests both eviction and resurrection.
#[test]
fn deep_reorg_mempool_matches_clean_sync() -> Result<()> {
    let mut core = ProcessNode::spawn(Kind::Core)?;
    let mut reorg = ProcessNode::spawn(Kind::BitcoinRs)?;
    let funds = mine_common_chain(&mut core, &mut reorg, 101)?;
    let mut clean = ProcessNode::spawn(Kind::BitcoinRs)?;
    feed_common_blocks(&mut clean, &funds)?;

    let (conflict_outpoint, conflict_prevout) = funds.confirmed_output(0)?;
    let (survivor_outpoint, survivor_prevout) = funds.confirmed_output(1)?;
    let old_tx = signed_spend(conflict_outpoint, &conflict_prevout, 1_500, Sequence::MAX)?;
    let new_tx = signed_spend(conflict_outpoint, &conflict_prevout, 2_500, Sequence::MAX)?;
    let survivor = signed_spend(survivor_outpoint, &survivor_prevout, 1_500, Sequence::MAX)?;
    let old_txid = old_tx.compute_txid().to_string();
    let new_txid = new_tx.compute_txid().to_string();
    let survivor_txid = survivor.compute_txid().to_string();
    assert_ne!(old_txid, new_txid);
    for node in [&mut reorg, &mut clean] {
        submit_mempool(node, &old_tx)?;
        submit_mempool(node, &survivor)?;
    }

    let mined = reorg.rpc(
        "generateblock",
        &json!(["raw(51)", [old_txid, survivor_txid]]),
    )?;
    let old_first = mined.str_field("hash")?.to_owned();
    let old_tail = mine_bare_blocks(&mut reorg, 2)?;
    let old_tip = old_tail[1].clone();
    let old_block = reorg.rpc("getblock", &json!([old_first, 2]))?;
    let old_txs = old_block["tx"]
        .as_array()
        .ok_or_else(|| Error::Assertion("losing block lacks transaction array".into()))?;
    let confirmed_ids = old_txs
        .iter()
        .skip(1)
        .map(|tx| tx.str_field("txid").map(str::to_owned))
        .collect::<Result<Vec<_>>>()?;
    assert_eq!(confirmed_ids, vec![old_txid.clone(), survivor_txid.clone()]);
    assert_eq!(
        confirmed_tx(&mut reorg, &survivor_txid, &old_first)?["confirmations"],
        json!(3),
        "survivor must first be confirmed on the losing branch"
    );
    assert_eq!(sorted_mempool(&mut reorg)?, Vec::<String>::new());

    // Core mines only the specified conflicting transaction. Its independent
    // spend stays out of the winning branch and remains eligible for mempool.
    let mut rival = vec![mine_core_block(&mut core, &[tx_hex(&new_tx)])?];
    rival.push(mine_core_block(&mut core, &[])?);
    rival.push(mine_core_block(&mut core, &[])?);
    submit_competing_headers(&mut reorg, &rival)?;
    assert_eq!(
        reorg.rpc("getbestblockhash", &json!([]))?,
        json!(old_tip),
        "equal-work three-block rival must not disconnect the old chain"
    );
    assert_ne!(old_first, rival[0].block_hash().to_string());

    let winner = mine_core_block(&mut core, &[])?;
    submit_mempool(&mut core, &survivor)?;
    dial_core(&core, &mut reorg)?;
    dial_core(&core, &mut clean)?;
    reorg.wait_block_count(105, Duration::from_mins(2))?;
    clean.wait_block_count(105, Duration::from_mins(2))?;
    assert_eq!(
        reorg.rpc("getbestblockhash", &json!([]))?,
        json!(winner.block_hash().to_string())
    );
    compare_chain_views(&mut core, &mut reorg, &mut clean)?;

    let expected_pool = vec![survivor_txid.clone()];
    assert_eq!(sorted_mempool(&mut core)?, expected_pool);
    assert_eq!(sorted_mempool(&mut reorg)?, expected_pool);
    assert_eq!(sorted_mempool(&mut clean)?, expected_pool);
    let conflict_coin = conflict_outpoint.txid.to_string();
    assert!(compare_coin(&mut core, &mut reorg, &mut clean, &conflict_coin, false)?.is_null());
    let survivor_coin = survivor_outpoint.txid.to_string();
    assert!(!compare_coin(&mut core, &mut reorg, &mut clean, &survivor_coin, false)?.is_null());
    assert!(compare_coin(&mut core, &mut reorg, &mut clean, &survivor_coin, true)?.is_null());
    let new_block_hash = rival[0].block_hash().to_string();
    assert_transaction_status(
        &mut core,
        &mut reorg,
        &mut clean,
        &survivor_txid,
        &new_txid,
        &new_block_hash,
        &old_txid,
    )?;

    reorg.stop()?;
    clean.stop()?;
    core.stop()
}

/// A scripted peer offers a higher-work branch with valid `PoW` and Merkle
/// commitments, but its first coinbase overclaims the subsidy. This is a
/// permanent consensus failure rather than a mutated-body transport error.
/// The old coins and the ability to extend the valid branch must survive.
#[test]
fn invalid_higher_work_body_cannot_change_active_chain() -> Result<()> {
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;
    submit_genesis(&mut node)?;
    let old_tip = mine_bare_blocks(&mut node, 1)?.remove(0);
    let before = chain_view(&mut node)?;
    let old_block = node.rpc("getblock", &json!([old_tip, 2]))?;
    let old_coinbase = old_block["tx"][0].str_field("txid")?.to_owned();

    let mut core = ProcessNode::spawn(Kind::Core)?;
    let mut invalid = mine_core_block(&mut core, &[])?;
    let mut descendant = mine_core_block(&mut core, &[])?;
    invalid.txdata[0].output[0].value = bitcoin::Amount::from_sat(5_000_000_001);
    invalid.header.merkle_root = invalid
        .compute_merkle_root()
        .ok_or_else(|| Error::Assertion("invalid fixture has no Merkle root".into()))?;
    invalid.header.nonce = 0;
    grind_pow(&mut invalid.header)?;
    let first_hash = invalid.block_hash();
    descendant.header.prev_blockhash = first_hash;
    descendant.header.nonce = 0;
    grind_pow(&mut descendant.header)?;
    let rival = [invalid, descendant];
    assert_eq!(
        rival[0].compute_merkle_root(),
        Some(rival[0].header.merkle_root)
    );

    // Run the exact overclaim body through the pinned independent validator
    // from genesis. This distinguishes the intended consensus failure from
    // an accidentally malformed header or Merkle commitment.
    let mut oracle = ProcessNode::spawn(Kind::Core)?;
    assert_eq!(
        oracle.rpc("submitblock", &json!([serialize_hex(&rival[0])]))?,
        json!("bad-cb-amount")
    );
    assert_eq!(oracle.rpc("getblockcount", &json!([]))?, json!(0));
    oracle.stop()?;

    deliver_invalid_branch(&mut node, &rival, first_hash)?;
    compare_reply(
        "invalid branch kept chain and UTXO",
        &before,
        &chain_view(&mut node)?,
    )?;
    assert!(!coin(&mut node, &old_coinbase, false)?.is_null());
    assert_eq!(sorted_mempool(&mut node)?, Vec::<String>::new());
    assert_eq!(node.rpc("getblockhash", &json!([1]))?, json!(old_tip));

    // Invalid-branch recovery reconnects the old branch through durable
    // commits. Kill immediately after the public state has returned to that
    // branch, then check the same tip and coins before allowing new work.
    let datadir = node.take_datadir()?;
    node.send_sigkill();
    drop(node);
    let mut node =
        ProcessNode::spawn_in_datadir(Kind::BitcoinRs, &SpawnOptions::default(), datadir)?;
    compare_reply(
        "invalid-branch recovery survived SIGKILL",
        &before,
        &chain_view(&mut node)?,
    )?;
    assert!(!coin(&mut node, &old_coinbase, false)?.is_null());
    assert_eq!(node.rpc("getblockhash", &json!([1]))?, json!(old_tip));
    let valid_extension = mine_bare_blocks(&mut node, 1)?.remove(0);
    assert_eq!(
        node.rpc("getbestblockhash", &json!([]))?,
        json!(valid_extension)
    );
    node.stop()?;
    core.stop()
}
