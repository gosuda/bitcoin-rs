//! `AddrMan`'s public contract: learned wire addresses survive a daemon restart
//! and remain usable when DNS is disabled and no operator peer is configured.
#![expect(clippy::expect_used, reason = "process fixture assertions")]

use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bitcoin::hashes::Hash as _;
use bitcoin::p2p::ServiceFlags;
use bitcoin::p2p::address::{AddrV2, AddrV2Message, Address};
use bitcoin::p2p::message::NetworkMessage;
use bitcoin_rs_e2e::live_peer::LivePeer;
use bitcoin_rs_e2e::{Error, Kind, ProcessNode, SpawnOptions};
use serde_json::json;

#[test]
fn dns_disabled_restart_reconnects_to_a_gossiped_peer() -> Result<(), Error> {
    let options = SpawnOptions {
        binary: Some(Path::new(env!("CARGO_BIN_EXE_bitcoin-rs"))),
        ..SpawnOptions::default()
    };
    restart_reconnects(&options, None)
}

#[test]
fn configured_asmap_survives_dns_disabled_restart() -> Result<(), Error> {
    let directory = tempfile::tempdir()?;
    let map = directory.path().join("asmap.raw");
    let bytes = include_bytes!("../../../crates/p2p/tests/data/asmap-linked-ipv4-core-v31.1.raw");
    std::fs::write(&map, bytes)?;
    let args = ["--asmap", map.to_str().expect("temporary path")];
    let options = SpawnOptions {
        binary: Some(Path::new(env!("CARGO_BIN_EXE_bitcoin-rs"))),
        extra_args: &args,
        ..SpawnOptions::default()
    };
    restart_reconnects(
        &options,
        Some(bitcoin::hashes::sha256::Hash::hash(bytes).to_byte_array()),
    )
}

fn restart_reconnects(
    options: &SpawnOptions<'_>,
    expected_map: Option<[u8; 32]>,
) -> Result<(), Error> {
    let destination = ProcessNode::spawn_with(Kind::BitcoinRs, options)?;
    let mut learner = ProcessNode::spawn_with(Kind::BitcoinRs, options)?;
    let mut gossip = LivePeer::connect_with_height(&learner, "addr-source", 0)?;
    let timestamp = u32::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_secs(),
    )
    .expect("timestamp");
    let services = ServiceFlags::NETWORK | ServiceFlags::WITNESS;
    let deadline = Instant::now() + Duration::from_secs(10);
    // Exercise both decoders; duplicate gossip must preserve one candidate.
    gossip.send(
        NetworkMessage::Addr(vec![(
            timestamp,
            Address::new(&destination.p2p_addr, services),
        )]),
        deadline,
    )?;
    let ip = match destination.p2p_addr.ip() {
        std::net::IpAddr::V4(ip) => AddrV2::Ipv4(ip),
        std::net::IpAddr::V6(ip) => AddrV2::Ipv6(ip),
    };
    gossip.send(
        NetworkMessage::AddrV2(vec![AddrV2Message {
            time: timestamp,
            services,
            addr: ip,
            port: destination.p2p_addr.port(),
        }]),
        deadline,
    )?;
    let expected = destination.p2p_addr.to_string();
    learner.wait_for(
        "learned outbound connection",
        Duration::from_secs(20),
        |node| {
            let peers = node.rpc("getpeerinfo", &json!([]))?;
            Ok(peers
                .as_array()
                .is_some_and(|peers| {
                    peers
                        .iter()
                        .any(|peer| peer["addr"] == expected && peer["inbound"] == false)
                })
                .then_some(()))
        },
    )?;
    drop(gossip);
    let datadir = learner.stop_keep_datadir()?;
    let bytes = std::fs::read(datadir.path().join("node/peers-fabfb5da.dat"))?;
    let book: serde_json::Value = serde_json::from_slice(&bytes[..bytes.len() - 32])?;
    assert_eq!(book["version"], 7);
    assert_eq!(
        book["asmap_id"],
        json!(expected_map),
        "CLI configuration reaches the one persisted classifier owner"
    );
    let mut restarted = ProcessNode::spawn_in_datadir(Kind::BitcoinRs, options, datadir)?;
    restarted.wait_for(
        "persisted outbound connection",
        Duration::from_secs(20),
        |node| {
            let peers = node.rpc("getpeerinfo", &json!([]))?;
            Ok(peers
                .as_array()
                .is_some_and(|peers| {
                    peers
                        .iter()
                        .any(|peer| peer["addr"] == expected && peer["inbound"] == false)
                })
                .then_some(()))
        },
    )?;
    restarted.stop()?;
    destination.stop()?;
    Ok(())
}
