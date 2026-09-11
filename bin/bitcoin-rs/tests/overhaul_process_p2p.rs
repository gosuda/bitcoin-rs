//! REF-07/P2P-01: the compatibility lane enters through real loopback peers.

#![expect(clippy::expect_used, reason = "public process test assertions")]

mod support;

use std::time::{Duration, Instant};

use bitcoin::consensus::serialize;
use bitcoin::p2p::Magic;
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use serde_json::json;
use support::process_node::{NodeBinary, ProcessNode, compare_rpc, mine_common_chain};
use support::process_peer::{ProcessPeer, decode_frame};

/// REF-07b/c: RPC may become ready before the independent P2P bind.
#[test]
fn p2p_connect_waits_for_a_delayed_listener() {
    use std::net::TcpListener;
    let reservation = TcpListener::bind("127.0.0.1:0").expect("reserve fixture port");
    let addr = reservation.local_addr().expect("fixture address");
    drop(reservation);
    let server = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(150));
        let listener = TcpListener::bind(addr).expect("delayed listener");
        listener
            .set_nonblocking(true)
            .expect("bounded fixture accept");
        let deadline = Instant::now() + Duration::from_secs(1);
        while Instant::now() < deadline {
            if listener.accept().is_ok() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        false
    });
    let result =
        support::process_peer::connect_loopback(addr, Instant::now() + Duration::from_secs(1));
    let accepted = server.join().expect("fixture joins");
    assert!(
        result.is_ok(),
        "temporary refusal is not failed startup: {result:?}"
    );
    assert!(accepted);
}

#[test]
fn p2p_connect_to_an_absent_listener_has_a_fixed_deadline() {
    use std::net::TcpListener;
    let reservation = TcpListener::bind("127.0.0.1:0").expect("reserve fixture port");
    let addr = reservation.local_addr().expect("fixture address");
    drop(reservation);
    let start = Instant::now();
    let result = support::process_peer::connect_loopback(addr, start + Duration::from_millis(80));
    assert!(result.is_err());
    assert!(start.elapsed() < Duration::from_millis(600));
}

/// REF-07b/c: a failed operation after handshake closes the peer and reaps the child.
#[test]
#[cfg(target_os = "linux")]
fn p2p_timeout_releases_the_connected_peer_and_process() {
    for binary in [NodeBinary::BitcoinRs, NodeBinary::ReferenceCore] {
        let mut node = ProcessNode::start(binary).expect("normal startup");
        let pid = node.pid();
        let mut peer = ProcessPeer::connect(&node).expect("connected peer");
        let result = peer.wait_for_pong(u64::MAX, Instant::now() + Duration::from_millis(100));
        assert!(
            result.is_err(),
            "a nonce never sent cannot receive a matching pong"
        );
        drop(peer);
        let deadline = Instant::now() + Duration::from_secs(5);
        while node
            .rpc("getconnectioncount", &json!([]))
            .expect("public connection count")
            != json!(0)
        {
            assert!(Instant::now() < deadline, "failed peer remained connected");
            std::thread::sleep(Duration::from_millis(20));
        }
        let evidence = node.evidence.clone();
        drop(node);
        assert!(
            !std::path::Path::new(&format!("/proc/{pid}")).exists(),
            "child was not reaped"
        );
        assert!(
            std::fs::read_to_string(evidence.join("p2p.jsonl"))
                .expect("failure evidence")
                .contains("failure")
        );
    }
}

/// REF-07c: a peer sending one byte at a time cannot renew the operation's
/// total deadline. The test fixture only faults transport, not node behavior.
#[test]
fn fragmented_p2p_response_obeys_one_total_deadline() {
    use std::io::Write as _;
    use std::net::{TcpListener, TcpStream};

    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback fixture");
    let mut client = TcpStream::connect_timeout(
        &listener.local_addr().expect("fixture address"),
        Duration::from_secs(1),
    )
    .expect("connected fixture");
    let (mut server, _) = listener.accept().expect("queued local connection");
    server
        .set_write_timeout(Some(Duration::from_secs(1)))
        .expect("bounded fixture write");
    let writer = std::thread::spawn(move || {
        let frame = serialize(&RawNetworkMessage::new(
            Magic::REGTEST,
            NetworkMessage::Ping(19),
        ));
        for byte in frame {
            if server.write_all(&[byte]).is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(30));
        }
    });
    let start = Instant::now();
    let result = support::process_peer::read_frame(&mut client, start + Duration::from_millis(100));
    let elapsed = start.elapsed();
    drop(client);
    writer.join().expect("fixture joins");
    assert!(result.is_err(), "dribbled response must not complete");
    assert!(
        elapsed >= Duration::from_millis(80),
        "unexpected early transport failure: {result:?}"
    );
    assert!(
        elapsed < Duration::from_millis(600),
        "dribbled bytes renewed the deadline: {elapsed:?}"
    );
}

/// REF-07c/d: reject the header before allocating or waiting for its body.
#[test]
fn oversized_p2p_length_is_rejected_without_a_body() {
    use std::io::Write as _;
    use std::net::{TcpListener, TcpStream};

    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback fixture");
    let mut client = TcpStream::connect_timeout(
        &listener.local_addr().expect("fixture address"),
        Duration::from_secs(1),
    )
    .expect("connected fixture");
    let (mut server, _) = listener.accept().expect("queued local connection");
    server
        .set_write_timeout(Some(Duration::from_secs(1)))
        .expect("bounded fixture write");
    let mut header = [0_u8; 24];
    header[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
    server.write_all(&header).expect("header only");
    let error =
        support::process_peer::read_frame(&mut client, Instant::now() + Duration::from_millis(200))
            .expect_err("oversized length must fail before reading the missing body");
    assert!(
        matches!(error, support::process_node::HarnessError::Protocol(ref message) if message == "P2P payload byte limit")
    );
}

fn admit_over_p2p(process: &mut ProcessNode, transaction: &bitcoin::Transaction) {
    let txid = transaction.compute_txid().to_string();
    let mut peer = ProcessPeer::connect(process).expect("real version/verack handshake");
    peer.send_transaction(transaction)
        .expect("wire transaction and ping barrier");
    // A pong orders wire processing but does not claim asynchronous admission
    // completion. Observe that completion only through the public RPC.
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let pool = process
            .rpc("getrawmempool", &json!([]))
            .expect("public pool");
        if pool == json!([txid]) {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "P2P admission did not publish {txid}: {pool}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let transcript = std::fs::read_to_string(process.evidence.join("p2p.jsonl"))
        .expect("retained ordered P2P wire evidence");
    let messages: Vec<serde_json::Value> = transcript
        .lines()
        .map(|line| serde_json::from_str(line).expect("wire event JSON"))
        .collect();
    assert!(
        messages
            .iter()
            .any(|event| event["direction"] == "sent" && event["command"] == "tx")
    );
    assert!(
        messages
            .iter()
            .any(|event| event["direction"] == "received" && event["command"] == "verack")
    );
}

/// No listener, service, or pool is constructed in the test process. The same
/// signed transaction enters each binary's ordinary inbound P2P path.
#[test]
fn p2p_transaction_reaches_admission_confirmation_and_public_queries() {
    let mut core = ProcessNode::start(NodeBinary::ReferenceCore).expect("reference process");
    let mut node = ProcessNode::start_with_options(
        NodeBinary::BitcoinRs,
        &["--txindex", "true"],
        Duration::from_secs(30),
    )
    .expect("candidate process with explorer transaction lookup enabled");
    let funds = mine_common_chain(&mut core, &mut node, 101).expect("identical mature funds");
    let transaction = funds.signed_spend().expect("signed spend");
    let txid = transaction.compute_txid().to_string();
    let raw = bitcoin::consensus::encode::serialize_hex(&transaction);
    assert_eq!(
        compare_rpc(&mut core, &mut node, "getrawmempool", &json!([])).expect("initial pools"),
        json!([]),
    );
    for process in [&mut core, &mut node] {
        admit_over_p2p(process, &transaction);
    }
    assert_eq!(
        compare_rpc(
            &mut core,
            &mut node,
            "getrawtransaction",
            &json!([txid, false])
        )
        .expect("public mempool transaction"),
        json!(raw)
    );
    assert_eq!(
        node.http_get_json(&format!("/api/tx/{txid}/status"))
            .expect("public explorer mempool status"),
        json!({"confirmed": false})
    );
    let confirmation =
        mine_common_chain(&mut core, &mut node, 1).expect("identical confirming block");
    let block: bitcoin::Block = bitcoin::consensus::deserialize(
        confirmation
            .common_block_bytes
            .first()
            .expect("confirmation bytes"),
    )
    .expect("confirmation block");
    assert!(
        block
            .txdata
            .iter()
            .any(|tx| tx.compute_txid() == transaction.compute_txid())
    );
    let hash = block.block_hash().to_string();
    assert_eq!(
        compare_rpc(&mut core, &mut node, "getbestblockhash", &json!([]))
            .expect("confirmed common tip"),
        json!(hash)
    );
    assert_eq!(
        compare_rpc(&mut core, &mut node, "getrawmempool", &json!([])).expect("confirmed pools"),
        json!([])
    );
    assert_eq!(
        compare_rpc(
            &mut core,
            &mut node,
            "getrawtransaction",
            &json!([txid, false, hash])
        )
        .expect("confirmed public lookup"),
        json!(raw)
    );
    let spent = transaction
        .input
        .first()
        .expect("funding input")
        .previous_output;
    assert_eq!(
        compare_rpc(
            &mut core,
            &mut node,
            "gettxout",
            &json!([spent.txid.to_string(), spent.vout, false])
        )
        .expect("confirmed funding spend"),
        json!(null)
    );
    // Block acceptance publishes the chain tip before the derived index catches up.
    wait_for_txindex(&mut node, 102);
    assert_eq!(
        node.http_get_json(&format!("/api/tx/{txid}/status"))
            .expect("public explorer confirmed status"),
        json!({
            "confirmed": true, "block_height": 102, "block_hash": hash, "block_time": block.header.time,
        })
    );
    core.stop().expect("reap reference");
    node.stop().expect("reap candidate");
}

fn wait_for_txindex(node: &mut ProcessNode, height: u32) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let status = node
            .rpc_until("getindexinfo", &json!(["txindex"]), deadline)
            .expect("public transaction index progress");
        let synced = status["txindex"]["synced"]
            .as_bool()
            .expect("enabled txindex must report its synchronization state");
        if synced {
            assert_eq!(status["txindex"]["best_block_height"], json!(height));
            return;
        }
        assert!(
            Instant::now() < deadline,
            "txindex did not catch up: {status}"
        );
        std::thread::sleep(
            deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(20)),
        );
    }
}

/// A valid envelope is a positive control for each independent rejection.
#[test]
fn malformed_p2p_frames_are_protocol_failures_not_behavior_evidence() {
    let valid = serialize(&RawNetworkMessage::new(
        Magic::REGTEST,
        NetworkMessage::Ping(19),
    ));
    assert!(matches!(
        decode_frame(&valid).expect("valid reference envelope"),
        NetworkMessage::Ping(19)
    ));
    let mut checksum = valid.clone();
    checksum[20] ^= 1;
    let wrong_network = serialize(&RawNetworkMessage::new(
        Magic::BITCOIN,
        NetworkMessage::Ping(19),
    ));
    let mut trailing = valid.clone();
    trailing.push(0);
    let mut length = valid.clone();
    length[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
    for bytes in [
        checksum,
        wrong_network,
        trailing,
        length,
        valid[..23].to_vec(),
        valid[..27].to_vec(),
    ] {
        assert!(matches!(
            decode_frame(&bytes),
            Err(support::process_node::HarnessError::Protocol(_))
        ));
    }
}
