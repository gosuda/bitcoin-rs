use std::path::Path;
use std::time::{Duration, Instant};

use bitcoin::consensus::encode::serialize_hex;
use bitcoin::p2p::message::NetworkMessage;
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::{OutPoint, Sequence, Transaction};
use bitcoin_rs_e2e::{Kind, ProcessNode, SpawnOptions, helpers};
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, json};

type TestResult = Result<(), Box<dyn std::error::Error>>;

use crate::support::wire_peer;

fn options(enabled: bool) -> SpawnOptions<'static> {
    SpawnOptions {
        binary: Some(Path::new(env!("CARGO_BIN_EXE_bitcoin-rs"))),
        toml_extra: if enabled {
            "persist_mempool = true\n"
        } else {
            "persist_mempool = false\n"
        },
        ..Default::default()
    }
}

fn parent_and_child(
    node: &mut ProcessNode,
) -> Result<(Transaction, Transaction), Box<dyn std::error::Error>> {
    let (point, prevout) = helpers::mature_funding(node)?;
    let script = helpers::funding_address()?.script_pubkey();
    let mut parent = helpers::spend_anyone(point, &prevout, 10_000);
    parent.output[0].script_pubkey = script;
    let mut child = helpers::raw_spend_to(
        OutPoint::new(parent.compute_txid(), 0),
        &parent.output[0],
        10_000,
        Sequence::MAX,
        &parent.output[0].script_pubkey,
    );
    helpers::sign_p2pkh_inputs(&mut child, &parent.output)?;
    node.rpc("sendrawtransaction", &json!([serialize_hex(&parent)]))?;
    node.rpc("sendrawtransaction", &json!([serialize_hex(&child)]))?;
    Ok((parent, child))
}

fn assert_membership(node: &mut ProcessNode, transactions: &[&Transaction]) -> TestResult {
    let mut expected: Vec<_> = transactions
        .iter()
        .map(|tx| tx.compute_txid().to_string())
        .collect();
    expected.sort();
    let mut actual = helpers::mempool_txids(node)?;
    actual.sort();
    assert_eq!(actual, expected);
    let verbose = node.rpc("getrawmempool", &json!([true]))?;
    for tx in transactions {
        let txid = tx.compute_txid().to_string();
        let entry = node.rpc("getmempoolentry", &json!([txid]))?;
        assert_eq!(verbose.get(&txid), Some(&entry));
        let raw = node.rpc("getrawtransaction", &json!([txid]))?;
        assert_eq!(raw, sonic_rs::Value::from(serialize_hex(tx).as_str()));
    }
    let template = node.rpc("getblocktemplate", &json!([{"rules": ["segwit"]}]))?;
    let ids: Vec<_> = template["transactions"]
        .as_array()
        .ok_or("template transactions")?
        .iter()
        .map(|tx| tx["txid"].as_str().ok_or("template txid"))
        .collect::<Result<_, _>>()?;
    assert_eq!(ids.len(), transactions.len());
    for tx in transactions {
        assert!(ids.contains(&tx.compute_txid().to_string().as_str()));
    }
    Ok(())
}

fn pending_inventory(
    node: &ProcessNode,
    wanted: &Transaction,
    forbidden: Option<&Transaction>,
    name: &str,
) -> Result<(wire_peer::Peer, Inventory), Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(45);
    let mut peer = wire_peer::Peer::connect(node.p2p_addr, "mempool-restart", name, 0, deadline)?;
    loop {
        match peer.recv(deadline)? {
            NetworkMessage::Ping(nonce) => peer.send(NetworkMessage::Pong(nonce), deadline)?,
            NetworkMessage::Inv(items) => {
                let matches = |item: &Inventory, tx: &Transaction| match item {
                    Inventory::Transaction(id) | Inventory::WitnessTransaction(id) => {
                        *id == tx.compute_txid()
                    }
                    Inventory::WTx(id) => *id == tx.compute_wtxid(),
                    _ => false,
                };
                assert!(
                    !items
                        .iter()
                        .any(|item| forbidden.is_some_and(|tx| matches(item, tx))),
                    "a completed initial broadcast must not be replayed to a fresh peer"
                );
                if let Some(item) = items.into_iter().find(|item| matches(item, wanted)) {
                    return Ok((peer, item));
                }
            }
            _ => {}
        }
    }
}

fn request_body(peer: &mut wire_peer::Peer, item: Inventory, wanted: &Transaction) -> TestResult {
    let deadline = Instant::now() + Duration::from_secs(10);
    peer.send(NetworkMessage::GetData(vec![item]), deadline)?;
    loop {
        match peer.recv(deadline)? {
            NetworkMessage::Tx(tx) => {
                assert_eq!(&tx, wanted);
                return Ok(());
            }
            NetworkMessage::Ping(nonce) => peer.send(NetworkMessage::Pong(nonce), deadline)?,
            _ => {}
        }
    }
}

#[test]
fn restart_retries_only_uncompleted_local_initial_broadcasts() -> TestResult {
    let mut node = ProcessNode::spawn_with(Kind::BitcoinRs, &options(true))?;
    let (parent, child) = parent_and_child(&mut node)?;
    assert_eq!(
        node.rpc("getmempoolinfo", &json!([]))?["unbroadcastcount"],
        2
    );
    let dir = node.stop_keep_datadir()?;
    let mut node = ProcessNode::spawn_in_datadir(Kind::BitcoinRs, &options(true), dir)?;
    let (mut peer, item) = pending_inventory(&node, &parent, None, "pending-parent")?;
    assert_eq!(
        node.rpc("getmempoolinfo", &json!([]))?["unbroadcastcount"],
        2,
        "inventory alone does not complete initial broadcast"
    );
    request_body(&mut peer, item, &parent)?;
    assert_eq!(
        node.rpc(
            "getmempoolentry",
            &json!([parent.compute_txid().to_string()])
        )?["unbroadcast"],
        false
    );
    assert_eq!(
        node.rpc(
            "getmempoolentry",
            &json!([child.compute_txid().to_string()])
        )?["unbroadcast"],
        true
    );
    drop(peer);
    let dir = node.stop_keep_datadir()?;
    let mut node = ProcessNode::spawn_in_datadir(Kind::BitcoinRs, &options(true), dir)?;
    assert_eq!(
        node.rpc("getmempoolinfo", &json!([]))?["unbroadcastcount"],
        1
    );
    let (mut peer, item) = pending_inventory(&node, &child, Some(&parent), "pending-child")?;
    request_body(&mut peer, item, &child)?;
    assert_eq!(
        node.rpc("getmempoolinfo", &json!([]))?["unbroadcastcount"],
        0
    );
    drop(peer);
    node.stop_keep_datadir()?;
    Ok(())
}

#[test]
fn clean_restart_restores_dependencies_priority_lookup_and_mining() -> TestResult {
    let mut node = ProcessNode::spawn_with(Kind::BitcoinRs, &options(true))?;
    let (parent, child) = parent_and_child(&mut node)?;
    let parent_id = parent.compute_txid().to_string();
    node.rpc("prioritisetransaction", &json!([parent_id, 0, 1_000]))?;
    assert_membership(&mut node, &[&parent, &child])?;
    let tip = helpers::best_hash(&mut node)?;
    let dir = node.stop_keep_datadir()?;
    let file = dir.path().join("node/mempool-snapshot.dat");
    assert!(file.is_file());
    let snapshot = std::fs::read(&file)?;
    let mut node = ProcessNode::spawn_in_datadir(Kind::BitcoinRs, &options(true), dir)?;
    assert_eq!(helpers::best_hash(&mut node)?, tip);
    assert_membership(&mut node, &[&parent, &child])?;
    let entry = node.rpc("getmempoolentry", &json!([parent_id]))?;
    assert_eq!(entry["fees"]["modified"], json!(0.00011));
    let template = node.rpc("getblocktemplate", &json!([{"rules": ["segwit"]}]))?;
    assert_eq!(template["transactions"][1]["depends"], json!([1]));
    let dir = node.stop_keep_datadir()?;

    let before_disabled = std::fs::read(&file)?;
    let mut node = ProcessNode::spawn_in_datadir(Kind::BitcoinRs, &options(false), dir)?;
    assert_eq!(helpers::mempool_txids(&mut node)?, Vec::<String>::new());
    let dir = node.stop_keep_datadir()?;
    assert_eq!(std::fs::read(&file)?, before_disabled);

    let mut node = ProcessNode::spawn_in_datadir(Kind::BitcoinRs, &options(false), dir)?;
    node.rpc("sendrawtransaction", &json!([serialize_hex(&parent)]))?;
    node.rpc(
        "generateblock",
        &json!(["raw(51)", [serialize_hex(&parent)]]),
    )?;
    let dir = node.stop_keep_datadir()?;
    let mut node = ProcessNode::spawn_in_datadir(Kind::BitcoinRs, &options(true), dir)?;
    assert_membership(&mut node, &[&child])?;
    let dir = node.stop_keep_datadir()?;

    let mut rejected = snapshot;
    rejected[0] ^= 1;
    std::fs::write(&file, &rejected)?;
    let mut node = ProcessNode::spawn_in_datadir(Kind::BitcoinRs, &options(true), dir)?;
    assert_eq!(helpers::mempool_txids(&mut node)?, Vec::<String>::new());
    let evidence = node.evidence.clone();
    let _dir = node.stop_keep_datadir()?;
    assert_ne!(std::fs::read(&file)?, rejected);
    assert!(
        std::fs::read_dir(file.parent().ok_or("snapshot directory")?)?
            .filter_map(Result::ok)
            .any(|entry| {
                entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with("mempool-snapshot-rejected-")
                    && std::fs::read(entry.path().join("mempool-snapshot.dat"))
                        .is_ok_and(|bytes| bytes == rejected)
            })
    );
    let logs = std::fs::read_to_string(evidence.join("stderr.log"))?;
    assert!(logs.contains("mempool snapshot rejected"));
    Ok(())
}
