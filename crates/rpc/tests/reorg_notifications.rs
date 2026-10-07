//! Public-process `sequence` stream across a branch switch. The subscriber
//! lives in the RPC surface crate, which owns the optional libzmq dependency.

#![cfg(feature = "zmq")]

use std::time::{Duration, Instant};

use bitcoin::BlockHash;
use bitcoin::hashes::Hash as _;
use bitcoin_rs_e2e::helpers::{funding_address, mine_bare_blocks, submit_genesis};
use bitcoin_rs_e2e::{Kind, ProcessNode, Result, SpawnOptions};
use serde_json::{Value, json};

#[derive(Debug, Eq, PartialEq, serde::Serialize)]
struct SequenceBlock {
    hash: String,
    label: u8,
    counter: u32,
}

fn receive_block(socket: &zmq::Socket, timeout: Duration) -> Result<Option<SequenceBlock>> {
    socket
        .set_rcvtimeo(i32::try_from(timeout.as_millis()).map_err(|error| {
            bitcoin_rs_e2e::Error::Assertion(format!("ZMQ receive timeout: {error}"))
        })?)
        .map_err(|error| bitcoin_rs_e2e::Error::Assertion(error.to_string()))?;
    let frames = match socket.recv_multipart(0) {
        Ok(frames) => frames,
        Err(zmq::Error::EAGAIN) => return Ok(None),
        Err(error) => return Err(bitcoin_rs_e2e::Error::Assertion(error.to_string())),
    };
    assert_eq!(frames.len(), 3, "sequence message must have three frames");
    assert_eq!(frames[0].as_slice(), b"sequence");
    assert_eq!(
        frames[1].len(),
        33,
        "coinbase-only reorg cannot emit mempool A/R messages"
    );
    assert_eq!(frames[2].len(), 4);
    let mut hash = [0_u8; 32];
    hash.copy_from_slice(&frames[1][..32]);
    hash.reverse();
    let counter = u32::from_le_bytes(frames[2].as_slice().try_into().map_err(|_| {
        bitcoin_rs_e2e::Error::Assertion("sequence counter is not four bytes".into())
    })?);
    Ok(Some(SequenceBlock {
        hash: BlockHash::from_byte_array(hash).to_string(),
        label: frames[1][32],
        counter,
    }))
}

fn next_block(socket: &zmq::Socket) -> Result<SequenceBlock> {
    receive_block(socket, Duration::from_secs(15))?.ok_or_else(|| {
        bitcoin_rs_e2e::Error::Assertion("timed out waiting for a sequence event".into())
    })
}

fn mine_and_submit_core_block(core: &mut ProcessNode, node: &mut ProcessNode) -> Result<String> {
    let hashes = core.rpc(
        "generatetoaddress",
        &json!([1, funding_address()?.to_string()]),
    )?;
    let hash = hashes[0]
        .as_str()
        .ok_or_else(|| bitcoin_rs_e2e::Error::Assertion(format!("Core mining reply: {hashes}")))?;
    let body = core.rpc("getblock", &json!([hash, 0]))?;
    assert_eq!(node.rpc("submitblock", &json!([body]))?, Value::Null);
    Ok(hash.to_owned())
}

fn spawn_sequence_subscriber() -> Result<(tempfile::TempDir, ProcessNode, zmq::Context, zmq::Socket)>
{
    let socket_dir = tempfile::tempdir()?;
    let endpoint = format!(
        "ipc://{}",
        socket_dir.path().join("sequence.sock").display()
    );
    // A Windows path's backslashes are escapes in a TOML basic string, so
    // the emitted endpoint is escaped — a literal string would instead
    // break on a path containing a single quote (e.g. a user named
    // O'Brien). `endpoint` keeps its real value for the subscriber and the
    // assertions below.
    let endpoint_escaped = endpoint.replace('\\', "\\\\").replace('"', "\\\"");
    let toml_extra = format!(
        "[[notifications.zmq]]\nendpoint = \"{endpoint_escaped}\"\ntopics = [\"sequence\"]\nhwm = 1000\n"
    );
    let mut node = ProcessNode::spawn_with(
        Kind::BitcoinRs,
        &SpawnOptions {
            toml_extra: &toml_extra,
            ..SpawnOptions::default()
        },
    )?;
    submit_genesis(&mut node)?;
    let notifications = node.rpc("getzmqnotifications", &json!([]))?;
    assert!(
        notifications
            .as_array()
            .is_some_and(|rows| rows.iter().any(|row| {
                row.get("type") == Some(&json!("pubsequence"))
                    && row.get("address") == Some(&json!(endpoint))
            })),
        "sequence publisher did not bind the configured endpoint: {notifications}"
    );

    let context = zmq::Context::new();
    let subscriber = context
        .socket(zmq::SUB)
        .map_err(|error| bitcoin_rs_e2e::Error::Assertion(error.to_string()))?;
    subscriber
        .set_subscribe(b"sequence")
        .map_err(|error| bitcoin_rs_e2e::Error::Assertion(error.to_string()))?;
    subscriber
        .connect(&endpoint)
        .map_err(|error| bitcoin_rs_e2e::Error::Assertion(error.to_string()))?;
    Ok((socket_dir, node, context, subscriber))
}

fn wait_for_subscription_probe(
    core: &mut ProcessNode,
    node: &mut ProcessNode,
    subscriber: &zmq::Socket,
) -> Result<SequenceBlock> {
    // A bounded observed C event proves readiness without a PUB/SUB sleep.
    for _ in 0..8 {
        let hash = mine_and_submit_core_block(core, node)?;
        let deadline = Instant::now() + Duration::from_secs(1);
        while Instant::now() < deadline {
            if let Some(event) = receive_block(subscriber, Duration::from_millis(100))?
                && event.hash == hash
                && event.label == b'C'
            {
                return Ok(event);
            }
        }
    }
    Err(bitcoin_rs_e2e::Error::Assertion(
        "ZMQ subscriber never observed a probe block".into(),
    ))
}

fn mine_core_rival(core: &mut ProcessNode) -> Result<Vec<String>> {
    let rival = core.rpc(
        "generatetoaddress",
        &json!([3, funding_address()?.to_string()]),
    )?;
    let rival = rival
        .as_array()
        .ok_or_else(|| bitcoin_rs_e2e::Error::Assertion("Core rival hashes missing".into()))?;
    assert_eq!(rival.len(), 3);
    rival
        .iter()
        .map(|hash| {
            hash.as_str().map(str::to_owned).ok_or_else(|| {
                bitcoin_rs_e2e::Error::Assertion("Core rival hash is not a string".into())
            })
        })
        .collect()
}

fn assert_sequence_stream(
    subscriber: &zmq::Socket,
    ancestor: SequenceBlock,
    old: &[String],
    rival: &[String],
) -> Result<Vec<SequenceBlock>> {
    assert_eq!(old.len(), 2);
    assert_eq!(rival.len(), 3);
    let expected = [
        (old[0].as_str(), b'C'),
        (old[1].as_str(), b'C'),
        (old[1].as_str(), b'D'),
        (old[0].as_str(), b'D'),
        (rival[0].as_str(), b'C'),
        (rival[1].as_str(), b'C'),
        (rival[2].as_str(), b'C'),
    ];
    let mut counter = ancestor.counter;
    let mut observed = vec![ancestor];
    for (hash, label) in expected {
        let event = next_block(subscriber)?;
        counter = counter.wrapping_add(1);
        assert_eq!(
            event,
            SequenceBlock {
                hash: hash.to_owned(),
                label,
                counter
            }
        );
        observed.push(event);
    }
    assert!(
        receive_block(subscriber, Duration::from_millis(200))?.is_none(),
        "branch switch emitted an unexpected extra sequence event"
    );
    Ok(observed)
}

fn assert_post_switch_recovery(core: &mut ProcessNode, mut node: ProcessNode) -> Result<()> {
    // The last C is the externally observed commit boundary. Kill before a
    // graceful stop can publish another checkpoint, then reopen the datadir.
    let datadir = node.take_datadir()?;
    node.send_sigkill();
    drop(node);
    let mut recovered =
        ProcessNode::spawn_in_datadir(Kind::BitcoinRs, &SpawnOptions::default(), datadir)?;
    assert_eq!(
        recovered.rpc("getbestblockhash", &json!([]))?,
        core.rpc("getbestblockhash", &json!([]))?
    );
    let reference_coins = core.rpc("gettxoutsetinfo", &json!(["muhash", null, false]))?;
    let recovered_coins = recovered.rpc("gettxoutsetinfo", &json!(["muhash", null, false]))?;
    for key in ["height", "bestblock", "transactions", "txouts", "muhash"] {
        assert_eq!(
            recovered_coins.get(key),
            reference_coins.get(key),
            "recovered {key} differs from pinned Core"
        );
    }
    assert_eq!(
        recovered_coins["total_amount"].as_f64(),
        reference_coins["total_amount"].as_f64(),
        "recovered total UTXO amount differs from pinned Core"
    );
    recovered.stop()
}

/// Bitcoin Core's `interface_zmq.py` checks that `sequence` publishes every
/// disconnected block newest-first, then every connected block oldest-first.
/// The subscription is proven live with an observed probe before any reorg
/// event is asserted, avoiding a PUB/SUB slow-join false pass or timeout.
#[test]
fn sequence_reports_exact_disconnect_connect_order() -> Result<()> {
    let mut core = ProcessNode::spawn(Kind::Core)?;
    let (_socket_dir, mut node, _context, subscriber) = spawn_sequence_subscriber()?;
    let ancestor = wait_for_subscription_probe(&mut core, &mut node, &subscriber)?;
    let old = mine_bare_blocks(&mut node, 2)?;
    // The peers remain disconnected until Core has the strictly better
    // branch, so neither can accidentally adopt the other's equal-work tip.
    let rival = mine_core_rival(&mut core)?;
    node.rpc("addnode", &json!([core.p2p_addr.to_string(), "onetry"]))?;
    let winning_height = core
        .rpc("getblockcount", &json!([]))?
        .as_u64()
        .ok_or_else(|| {
            bitcoin_rs_e2e::Error::Assertion("Core block count is not an integer".into())
        })?;
    node.wait_block_count(winning_height, Duration::from_secs(90))?;
    assert_eq!(node.rpc("getbestblockhash", &json!([]))?, json!(rival[2]));
    let observed = assert_sequence_stream(&subscriber, ancestor, &old, &rival)?;
    std::fs::write(
        node.evidence.join("sequence.json"),
        serde_json::to_vec_pretty(&observed)?,
    )?;
    assert_post_switch_recovery(&mut core, node)?;
    core.stop()
}
