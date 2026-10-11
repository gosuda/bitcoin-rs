//! Core v31.1 `p2p_tx_download.py` comparison at the real process boundary.
//! Timing need not match: single ownership and immediate failed-source fallback do.

use bitcoin::hashes::Hash as _;
use bitcoin::p2p::{message::NetworkMessage, message_blockdata::Inventory};
use bitcoin_rs_e2e::helpers::{mine_bare_blocks, submit_genesis};
use bitcoin_rs_e2e::live_peer::LivePeer;
use bitcoin_rs_e2e::{Error, Kind, ProcessNode, Result};
use serde_json::json;
use std::time::{Duration, Instant};

fn count(peer: &LivePeer, hash: &str) -> usize {
    peer.getdata_seen
        .iter()
        .flat_map(|seen| &seen.items)
        .filter(|(_, id)| id == hash)
        .count()
}

fn pump(peers: &mut [LivePeer], duration: Duration) {
    let end = Instant::now() + duration;
    while Instant::now() < end {
        for peer in peers.iter_mut() {
            peer.pump(Duration::from_millis(20), &mut |_, _| {});
        }
    }
}

fn wait_count(peers: &mut [LivePeer], hash: &str, expected: usize) -> Result<()> {
    let end = Instant::now() + Duration::from_secs(10);
    while peers.iter().map(|peer| count(peer, hash)).sum::<usize>() < expected
        && Instant::now() < end
    {
        pump(peers, Duration::from_millis(50));
    }
    let actual = peers.iter().map(|peer| count(peer, hash)).sum::<usize>();
    if actual != expected {
        return Err(Error::Assertion(format!(
            "expected {expected} requests for {hash}, got {actual}"
        )));
    }
    Ok(())
}

fn scenario(kind: Kind) -> Result<()> {
    let mut node = ProcessNode::spawn(kind)?;
    if kind == Kind::BitcoinRs {
        submit_genesis(&mut node)?;
    } else {
        // ProcessNode defaults to a fixed Core mocktime; request deadlines
        // need an advancing clock in this live comparison.
        node.rpc("setmocktime", &json!([0]))?;
    }
    mine_bare_blocks(&mut node, 1)?;
    assert_eq!(
        node.rpc("getblockchaininfo", &json!([]))?["initialblockdownload"],
        false
    );
    let mut peers = vec![
        LivePeer::connect_with_height(&node, "tx-source-a", 0)?,
        LivePeer::connect_with_height(&node, "tx-source-b", 0)?,
        LivePeer::connect_with_height(&node, "tx-non-source", 0)?,
    ];
    let identity = bitcoin::Wtxid::from_byte_array([0x71; 32]);
    let item = Inventory::WTx(identity);
    for peer in &mut peers[..2] {
        peer.send(
            NetworkMessage::Inv(vec![item]),
            Instant::now() + Duration::from_secs(2),
        )?;
    }
    wait_count(&mut peers, &identity.to_string(), 1)?;
    let owner = usize::from(count(&peers[1], &identity.to_string()) == 1);
    let alternate = 1 - owner;
    peers[2].send(
        NetworkMessage::NotFound(vec![item]),
        Instant::now() + Duration::from_secs(2),
    )?;
    pump(&mut peers, Duration::from_millis(300));
    assert_eq!(
        peers
            .iter()
            .map(|peer| count(peer, &identity.to_string()))
            .sum::<usize>(),
        1,
        "spurious notfound stole ownership"
    );
    peers[owner].send(
        NetworkMessage::NotFound(vec![item]),
        Instant::now() + Duration::from_secs(2),
    )?;
    wait_count(&mut peers, &identity.to_string(), 2)?;
    assert_eq!(count(&peers[alternate], &identity.to_string()), 1);

    let identity = bitcoin::Wtxid::from_byte_array([0x72; 32]);
    let item = Inventory::WTx(identity);
    for peer in &mut peers[..2] {
        peer.send(
            NetworkMessage::Inv(vec![item]),
            Instant::now() + Duration::from_secs(2),
        )?;
    }
    wait_count(&mut peers, &identity.to_string(), 1)?;
    let owner = usize::from(count(&peers[1], &identity.to_string()) == 1);
    drop(peers.remove(owner));
    wait_count(&mut peers, &identity.to_string(), 1)?;
    pump(&mut peers, Duration::from_millis(300));
    assert_eq!(
        count(&peers[0], &identity.to_string()),
        1,
        "fallback duplicated a live request"
    );
    node.stop()
}

#[test]
fn request_owner_notfound_and_disconnect_match_core() -> Result<()> {
    scenario(Kind::BitcoinRs)?;
    scenario(Kind::Core)
}

/// Core's `ByTxHash` keys ignore the `GenTxid` inventory kind for identical bytes.
/// Use a legacy-announcing peer and a BIP339 peer so both inv forms are valid.
fn mixed_identity_scenario(kind: Kind) -> Result<()> {
    let mut node = ProcessNode::spawn(kind)?;
    if kind == Kind::BitcoinRs {
        submit_genesis(&mut node)?;
    } else {
        node.rpc("setmocktime", &json!([0]))?;
    }
    mine_bare_blocks(&mut node, 1)?;
    let mut peers = vec![
        LivePeer::connect_with_wtxid_relay(&node, "legacy-txid-source", 0, false)?,
        LivePeer::connect_with_height(&node, "wtxid-source", 0)?,
    ];
    let raw = [0x73; 32];
    let txid = bitcoin::Txid::from_byte_array(raw);
    let wtxid = bitcoin::Wtxid::from_byte_array(raw);
    peers[0].send(
        NetworkMessage::Inv(vec![Inventory::Transaction(txid)]),
        Instant::now() + Duration::from_secs(2),
    )?;
    wait_count(&mut peers, &txid.to_string(), 1)?;
    assert_eq!(count(&peers[0], &txid.to_string()), 1);
    peers[1].send(
        NetworkMessage::Inv(vec![Inventory::WTx(wtxid)]),
        Instant::now() + Duration::from_secs(2),
    )?;
    pump(&mut peers, Duration::from_secs(3));
    assert_eq!(
        peers
            .iter()
            .map(|peer| count(peer, &txid.to_string()))
            .sum::<usize>(),
        1,
        "identical TX/WTX hashes must not acquire simultaneous owners after delay"
    );
    peers[0].send(
        NetworkMessage::NotFound(vec![Inventory::WitnessTransaction(txid)]),
        Instant::now() + Duration::from_secs(2),
    )?;
    wait_count(&mut peers, &txid.to_string(), 2)?;
    assert_eq!(count(&peers[1], &txid.to_string()), 1);
    assert!(
        peers[1]
            .getdata_seen
            .iter()
            .flat_map(|seen| &seen.items)
            .any(|(kind, hash)| *kind == 5 && *hash == txid.to_string()),
        "fallback must retain the alternate's WTX wire kind"
    );
    node.stop()
}

#[test]
fn identical_txid_wtxid_request_ownership_matches_core() -> Result<()> {
    mixed_identity_scenario(Kind::BitcoinRs)?;
    mixed_identity_scenario(Kind::Core)
}
