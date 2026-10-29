//! External Tor / pinned IVNP interoperability. Ordinary CI uses local protocol fixtures.
#![allow(clippy::expect_used)]
use bitcoin_rs_e2e::helpers::{mine_bare_blocks, submit_genesis};
use bitcoin_rs_e2e::{Error, Kind, ProcessNode, Result, SpawnOptions};
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, json};
use std::{env, time::Duration};

fn setting(name: &str) -> Result<String> {
    env::var(name).map_err(|_| {
        Error::Assertion(format!(
            "required external backend setting {name} is absent"
        ))
    })
}
fn service(node: &mut ProcessNode, suffix: &'static str) -> Result<String> {
    node.wait_for(
        "overlay service address",
        Duration::from_secs(180),
        |node| {
            let info = node.rpc("getnetworkinfo", &json!([]))?;
            Ok(info["localaddresses"].as_array().and_then(|rows| {
                rows.iter().find_map(|row| {
                    let address = row["address"].as_str()?;
                    address
                        .ends_with(suffix)
                        .then(|| format!("{address}:{}", row["port"]))
                })
            }))
        },
    )
}
fn ready(node: &mut ProcessNode, network: &'static str, expected: Option<&str>) -> Result<()> {
    node.wait_for(
        "overlay Bitcoin handshake",
        Duration::from_secs(180),
        |node| {
            let peers = node.rpc("getpeerinfo", &json!([]))?;
            Ok(peers
                .as_array()
                .is_some_and(|peers| {
                    peers.iter().any(|peer| {
                        peer["network"] == network
                            && peer["version"]
                                .as_u64()
                                .is_some_and(|version| version >= 70016)
                            && expected.is_none_or(|expected| peer["addr"] == expected)
                            && peer["bytesrecv"].as_u64().is_some_and(|bytes| bytes > 0)
                            && peer["bytessent"].as_u64().is_some_and(|bytes| bytes > 0)
                    })
                })
                .then_some(()))
        },
    )
}
fn exchange(
    sender: &mut ProcessNode,
    receiver: &mut ProcessNode,
    count: u32,
    height: u64,
) -> Result<()> {
    let hashes = mine_bare_blocks(sender, count)?;
    let tip = hashes.last().expect("nonempty mined chain");
    receiver.wait_block_count(height, Duration::from_secs(180))?;
    assert_eq!(receiver.rpc("getbestblockhash", &json!([]))?, json!(tip));
    for hash in hashes {
        assert_eq!(
            receiver.rpc("getblockheader", &json!([hash, false]))?,
            sender.rpc("getblockheader", &json!([hash, false]))?
        );
        assert_eq!(
            receiver.rpc("getblock", &json!([hash, 0]))?,
            sender.rpc("getblock", &json!([hash, 0]))?
        );
    }
    Ok(())
}
fn roundtrip(
    network: &'static str,
    suffix: &'static str,
    server_config: &str,
    client_config: &str,
) -> Result<()> {
    let options = SpawnOptions {
        toml_extra: server_config,
        ..SpawnOptions::default()
    };
    let mut server = ProcessNode::spawn_with(Kind::BitcoinRs, &options)?;
    let mut client = ProcessNode::spawn_with(
        Kind::BitcoinRs,
        &SpawnOptions {
            toml_extra: client_config,
            ..SpawnOptions::default()
        },
    )?;
    submit_genesis(&mut server)?;
    submit_genesis(&mut client)?;
    let address = service(&mut server, suffix)?;
    client.rpc("addnode", &json!([address, "add"]))?;
    ready(&mut client, network, Some(&address))?;
    ready(&mut server, network, None)?;
    exchange(&mut server, &mut client, 3, 3)?;
    let peers = server.rpc("getpeerinfo", &json!([]))?;
    let remote = peers[0]["addr"].as_str().expect("remote identity");
    if network == "onion" {
        assert!(remote.starts_with("tor-inbound-"), "{remote}");
    } else {
        assert!(remote.contains(".b32.i2p:"), "{remote}");
    }
    exchange(&mut client, &mut server, 2, 5)?;
    let info = client.rpc("getnetworkinfo", &json!([]))?;
    for row in info["networks"].as_array().expect("networks") {
        if row["name"] == "ipv4" || row["name"] == "ipv6" {
            assert_eq!(row["limited"], true);
            assert_eq!(row["reachable"], false);
        }
    }
    client.rpc("setnetworkactive", &json!([false]))?;
    let datadir = server.take_datadir()?;
    server.stop()?;
    let mut server = ProcessNode::spawn_in_datadir(Kind::BitcoinRs, &options, datadir)?;
    assert_eq!(
        service(&mut server, suffix)?,
        address,
        "application identity must survive restart"
    );
    client.rpc("setnetworkactive", &json!([true]))?;
    ready(&mut client, network, Some(&address))?;
    ready(&mut server, network, None)?;
    exchange(&mut server, &mut client, 1, 6)?;
    exchange(&mut client, &mut server, 1, 7)?;
    client.stop()?;
    server.stop()
}

#[test]
#[ignore = "requires an external Tor SOCKS/control service; run the overlay interoperability workflow"]
fn tor_bitcoin_exchange_and_service_identity_restart() -> Result<()> {
    let proxy = setting("OVERLAY_TOR_PROXY")?;
    let control = setting("OVERLAY_TOR_CONTROL")?;
    let cookie = setting("OVERLAY_TOR_COOKIE")?;
    let client = format!("onlynet = [\"onion\"]\nonion_proxy = {proxy:?}\n");
    let server = format!("{client}tor_control = {control:?}\ntor_cookie = {cookie:?}\n");
    roundtrip("onion", ".onion", &server, &client)
}

#[test]
#[ignore = "requires pinned ivnpd with a working SAM bridge; run the overlay interoperability workflow"]
fn ivnp_bitcoin_exchange_and_destination_identity_restart() -> Result<()> {
    let sam = setting("OVERLAY_IVNP_SAM")?;
    let client = format!("onlynet = [\"i2p\"]\ni2p_sam = {sam:?}\n");
    let server = format!("{client}i2p_accept = true\n");
    roundtrip("i2p", ".b32.i2p", &server, &client)
}
