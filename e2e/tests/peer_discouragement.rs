//! Core 31.1 comparison of local disconnects and operator `NoBan` protection.

use std::time::{Duration, Instant};

use bitcoin::p2p::message::{CommandString, NetworkMessage};
use bitcoin_rs_e2e::live_peer::LivePeer;
use bitcoin_rs_e2e::{Error, Kind, ProcessNode, Result, SpawnOptions};
use serde_json::{Value, json};

fn oversized_headers() -> Result<NetworkMessage> {
    // Core checks this count against MAX_HEADERS_RESULTS before reading any
    // headers and calls Misbehaving. The three-byte payload is intentional.
    Ok(NetworkMessage::Unknown {
        command: CommandString::try_from("headers")
            .map_err(|error| Error::Assertion(error.to_string()))?,
        payload: vec![0xfd, 0xd1, 0x07], // CompactSize(2001)
    })
}

fn compare(kind: Kind, protected: bool) -> Result<()> {
    let options = match (kind, protected) {
        (Kind::BitcoinRs, true) => SpawnOptions {
            extra_args: &["--p2p-noban", "127.0.0.1/32"],
            ..Default::default()
        },
        (Kind::Core, true) => SpawnOptions {
            extra_args: &["-whitelist=noban@127.0.0.1"],
            ..Default::default()
        },
        _ => SpawnOptions::default(),
    };
    let mut node = ProcessNode::spawn_with(kind, &options)?;
    let mut peer = LivePeer::connect_with_height(&node, "discouragement-reference", 0)?;
    peer.ping_barrier(0x1388_0001, Instant::now() + Duration::from_secs(5))?;
    let info = node.rpc("getpeerinfo", &json!([]))?;
    let permissions = info[0]["permissions"]
        .as_array()
        .ok_or_else(|| Error::Assertion(format!("missing permissions: {info}")))?;
    assert_eq!(
        permissions.iter().any(|value| value == "noban"),
        protected,
        "{kind:?}: {info}"
    );
    peer.send(
        oversized_headers()?,
        Instant::now() + Duration::from_secs(5),
    )?;
    if protected {
        peer.ping_barrier(0x1388_0002, Instant::now() + Duration::from_secs(5))?;
        assert_eq!(node.rpc("getconnectioncount", &json!([]))?, json!(1));
    } else {
        node.wait_for(
            "local invalid peer disconnect",
            Duration::from_secs(5),
            |node| {
                let count = node.rpc("getconnectioncount", &json!([]))?;
                Ok((count == 0).then_some(()))
            },
        )?;
        // Core's local exemption is disconnect-only. A fresh local connection
        // succeeds after the violation; no subnet/address ban was created.
        let mut fresh = LivePeer::connect_with_height(&node, "local-reconnect", 0)?;
        fresh.ping_barrier(0x1388_0003, Instant::now() + Duration::from_secs(5))?;
    }
    assert_eq!(
        node.rpc("listbanned", &json!([]))?,
        Value::Array(Vec::new())
    );
    node.stop()
}

#[test]
fn core_and_candidate_keep_protected_peers_and_allow_local_reconnect() -> Result<()> {
    for kind in [Kind::Core, Kind::BitcoinRs] {
        for protected in [false, true] {
            compare(kind, protected)?;
        }
    }
    Ok(())
}
