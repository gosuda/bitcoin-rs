//! REF-02/REF-07 — the differential lane runs two public processes, never handlers.
//!
//! The pinned Core 31.1 `bitcoind` and the `bitcoin-rs` binary each start in
//! an isolated regtest datadir, share identical block bytes, answer only
//! through their public RPC surface, and leave no child behind. A missing or
//! substituted reference binary is a typed failure that names the pinned
//! digest; it is never a skipped test.

#![expect(
    clippy::expect_used,
    reason = "process custody failures must name the offending identity"
)]

mod support;

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use bitcoin::hashes::{Hash as _, sha256};
use bitcoin_rs_rpc::capabilities::CapabilityState;
use serde_json::{Value, json};
use support::process_node::{
    ClockControl, HarnessError, NodeBinary, ProcessNode, START_TIMEOUT, compare_reply, compare_rpc,
    exchange, mine_common_chain, verify_reference_binary,
};
use support::reference_set::reference_set;

// A height-1 coinbase is mature for admission after 101 common blocks.
const COMMON_BLOCKS: u32 = 101;

/// Waits for the kernel to drop `/proc/<pid>` after the child is reaped.
fn assert_reaped(pid: u32) {
    let proc_entry = format!("/proc/{pid}");
    let deadline = Instant::now() + Duration::from_secs(5);
    while Path::new(&proc_entry).exists() {
        assert!(Instant::now() < deadline, "child {pid} survived cleanup");
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn start(binary: NodeBinary) -> ProcessNode {
    ProcessNode::start(binary).expect("public process must start")
}

/// REF-07/P2P-01: compatibility must reach the binary's public P2P listener.
#[test]
fn normal_startup_exposes_an_isolated_loopback_p2p_listener() {
    for binary in [NodeBinary::BitcoinRs, NodeBinary::ReferenceCore] {
        let node = start(binary);
        let pid = node.pid();
        assert!(node.p2p_addr.ip().is_loopback());
        let peer = support::process_peer::connect_loopback(
            node.p2p_addr,
            Instant::now() + Duration::from_secs(1),
        )
        .expect("normal startup must expose its configured P2P listener");
        drop(peer);
        node.stop().expect("stop after public P2P connection");
        assert_reaped(pid);
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "keep the ordered public-process scenario and its observations together"
)]
fn signed_transaction_reaches_both_mempools_confirmation_and_public_queries() {
    let mut core = start(NodeBinary::ReferenceCore);
    let mut node = start(NodeBinary::BitcoinRs);
    let (core_pid, node_pid) = (core.pid(), node.pid());
    // Only Core exposes a mock clock today; the gap stays visible here.
    assert!(matches!(core.clock, ClockControl::Mock(_)));
    assert_eq!(node.clock, ClockControl::None);

    let funds = mine_common_chain(&mut core, &mut node, COMMON_BLOCKS).expect("common chain");
    let expected = usize::try_from(COMMON_BLOCKS).expect("count");
    assert_eq!(funds.common_block_bytes.len(), expected);
    assert_eq!(funds.common_outpoints.len(), expected);

    let tip = compare_rpc(&mut core, &mut node, "getbestblockhash", &json!([]))
        .expect("tips agree after identical block bytes");
    let last = funds.common_block_bytes.last().expect("mined block");
    let last: bitcoin::Block = bitcoin::consensus::deserialize(last).expect("block bytes");
    assert_eq!(tip, json!(last.block_hash().to_string()));
    assert_eq!(
        compare_rpc(&mut core, &mut node, "getrawmempool", &json!([]))
            .expect("empty initial pools"),
        json!([]),
    );

    let spend = funds.signed_spend().expect("sign mature coinbase");
    let txid = spend.compute_txid().to_string();
    let raw = bitcoin::consensus::encode::serialize_hex(&spend);
    let mut invalid = spend.clone();
    let input = invalid.input.first_mut().expect("signature input");
    let mut script = input.script_sig.as_bytes().to_vec();
    let signature_length = usize::from(*script.first().expect("signature push length"));
    // Change the last S scalar byte, preserving DER structure and sighash type.
    *script
        .get_mut(signature_length.checked_sub(1).expect("signature length"))
        .expect("signature scalar") ^= 1;
    input.script_sig = bitcoin::ScriptBuf::from_bytes(script);
    let invalid_raw = bitcoin::consensus::encode::serialize_hex(&invalid);
    let mut valid_previews = Vec::new();
    let mut invalid_previews = Vec::new();
    let mut rejection_codes = Vec::new();
    for process in [&mut core, &mut node] {
        let valid = process
            .rpc("testmempoolaccept", &json!([[raw]]))
            .expect("valid signed preview reaches the public admission owner");
        valid_previews.push(
            valid
                .pointer("/0/allowed")
                .expect("valid preview allowed field")
                .clone(),
        );
        let invalid = process
            .rpc("testmempoolaccept", &json!([[invalid_raw]]))
            .expect("invalid signature is a semantic preview reply");
        invalid_previews.push(
            invalid
                .pointer("/0/allowed")
                .expect("invalid preview allowed field")
                .clone(),
        );
        let rejection = process
            .rpc("sendrawtransaction", &json!([invalid_raw]))
            .expect_err("invalid signature cannot be admitted");
        let HarnessError::Rpc { code, .. } = rejection else {
            panic!("transport or setup failure is not an admission rejection: {rejection}");
        };
        rejection_codes.push(json!(code));
    }
    for allowed in &valid_previews {
        compare_reply("valid signature preview allowed", &json!(true), allowed)
            .expect("valid signature preview");
    }
    for allowed in &invalid_previews {
        compare_reply("invalid signature preview allowed", &json!(false), allowed)
            .expect("invalid signature preview");
    }
    // Rejection text is implementation-specific; the semantic allow verdict and
    // JSON-RPC error code are this scenario's named compatibility observations.
    for code in &rejection_codes {
        compare_reply("invalid signature send error code", &json!(-26), code)
            .expect("invalid signature rejection code");
    }
    assert_eq!(
        compare_rpc(&mut core, &mut node, "getrawmempool", &json!([]))
            .expect("previews leave both pools unchanged"),
        json!([]),
    );
    assert_eq!(
        compare_rpc(&mut core, &mut node, "sendrawtransaction", &json!([raw]))
            .expect("both production admission paths accept the signed spend"),
        json!(txid),
    );
    assert_eq!(
        compare_rpc(&mut core, &mut node, "getrawmempool", &json!([])).expect("admitted pools"),
        json!([txid]),
    );
    assert_eq!(
        compare_rpc(
            &mut core,
            &mut node,
            "getrawtransaction",
            &json!([txid, false])
        )
        .expect("public mempool lookup"),
        json!(raw),
    );
    let spent = spend.input.first().expect("funding input").previous_output;
    assert_eq!(
        compare_rpc(
            &mut core,
            &mut node,
            "gettxout",
            &json!([spent.txid.to_string(), spent.vout, true])
        )
        .expect("mempool spend hides its funding output"),
        json!(null),
    );

    let confirmation = mine_common_chain(&mut core, &mut node, 1).expect("mine the admitted spend");
    let block: bitcoin::Block = bitcoin::consensus::deserialize(
        confirmation
            .common_block_bytes
            .first()
            .expect("confirming block bytes"),
    )
    .expect("confirming block");
    assert!(
        block
            .txdata
            .iter()
            .any(|transaction| transaction.compute_txid() == spend.compute_txid())
    );
    let block_hash = block.block_hash().to_string();
    assert_eq!(
        compare_rpc(&mut core, &mut node, "getbestblockhash", &json!([]))
            .expect("confirmed common tip"),
        json!(block_hash),
    );
    assert_eq!(
        compare_rpc(&mut core, &mut node, "getrawmempool", &json!([])).expect("confirmed pools"),
        json!([]),
    );
    assert_eq!(
        compare_rpc(&mut core, &mut node, "getindexinfo", &json!(["txindex"]))
            .expect("confirmed lookup must run with txindex disabled on both nodes"),
        json!({}),
    );
    assert_eq!(
        compare_rpc(
            &mut core,
            &mut node,
            "getrawtransaction",
            &json!([txid, false, block_hash])
        )
        .expect("public confirmed lookup without txindex"),
        json!(raw),
    );
    assert_eq!(
        compare_rpc(
            &mut core,
            &mut node,
            "gettxout",
            &json!([spent.txid.to_string(), spent.vout, false])
        )
        .expect("confirmed funding spend"),
        json!(null),
    );

    let transcript = std::fs::read_to_string(node.evidence.join("transcript.jsonl"))
        .expect("transcript custody");
    // All setup and scenario requests retain their ordered raw replies.
    assert!(transcript.lines().count() >= expected + 12);
    for line in transcript.lines() {
        let entry: serde_json::Value = serde_json::from_str(line).expect("JSONL event");
        assert!(entry.get("request").is_some() && entry.get("reply").is_some());
    }
    for process in [&core, &node] {
        let launch: serde_json::Value = serde_json::from_slice(
            &std::fs::read(process.evidence.join("launch.json")).expect("launch evidence"),
        )
        .expect("launch JSON");
        assert_eq!(
            launch["executable_sha256"]
                .as_str()
                .expect("binary hash")
                .len(),
            64
        );
        assert!(
            launch["argv"]
                .as_array()
                .is_some_and(|args| !args.is_empty())
        );
        eprintln!("process evidence: {}", process.evidence.display());
    }

    core.stop().expect("core stop");
    node.stop().expect("node stop");
    assert_reaped(core_pid);
    assert_reaped(node_pid);
}

#[test]
fn dropped_process_is_reaped_without_stop() {
    let node = start(NodeBinary::BitcoinRs);
    let pid = node.pid();
    drop(node);
    assert_reaped(pid);
}

#[test]
fn missing_reference_binary_names_the_pinned_digest() {
    let path = Path::new("/nonexistent/reference/bitcoind");
    let pinned = reference_set()
        .expect("reference set")
        .release
        .bitcoind_sha256;
    let pinned = sha256::Hash::from_byte_array(pinned).to_string();

    let error = verify_reference_binary(path).expect_err("absent binary must fail");
    let HarnessError::Reference {
        path: reported,
        expected,
        ..
    } = &error
    else {
        panic!("expected a reference identity failure, got {error}");
    };
    assert_eq!(reported, path);
    assert_eq!(*expected, pinned);
    let text = error.to_string();
    assert!(text.contains(&pinned) && text.contains("/nonexistent/reference/bitcoind"));
}

/// REF-07a: a value difference is behavioral evidence, never transport success.
#[test]
fn deliberately_different_reply_is_a_behavior_failure() {
    let reference = json!({"txids": ["expected"], "mempool_sequence": 2});
    let candidate = json!({"txids": ["different"], "mempool_sequence": 2});
    assert!(compare_reply("getrawmempool", &reference, &reference).is_ok());
    assert!(matches!(
        compare_reply("getrawmempool", &reference, &candidate),
        Err(HarnessError::Difference { .. }),
    ));
}

/// REF-07b: rejected startup must report and reap the exact child process.
#[test]
fn rejected_startup_options_leave_no_child() {
    let error = match ProcessNode::start_with_options(
        NodeBinary::BitcoinRs,
        &["--process-harness-invalid-option"],
        Duration::from_secs(5),
    ) {
        Ok(_) => panic!("invalid startup option succeeded"),
        Err(error) => error,
    };
    let HarnessError::ChildExit {
        pid,
        evidence,
        status,
    } = error
    else {
        panic!("startup must report child exit: {error}");
    };
    assert!(!status.success());
    assert!(
        std::fs::read_to_string(evidence.join("stderr.log"))
            .expect("startup stderr")
            .contains("--process-harness-invalid-option")
    );
    assert_reaped(pid);
}

/// REF-07b: an early successful exit is not readiness and leaves no child.
#[test]
fn successful_child_exit_before_readiness_is_not_startup_success() {
    let error = match ProcessNode::start_with_options(
        NodeBinary::BitcoinRs,
        &["--help"],
        Duration::from_secs(5),
    ) {
        Ok(_) => panic!("help exit was mistaken for a ready node"),
        Err(error) => error,
    };
    let HarnessError::ChildExit { pid, status, .. } = error else {
        panic!("early successful exit must report child exit: {error}");
    };
    assert!(status.success());
    assert_reaped(pid);
}

/// REF-07c: readiness is deadline-bounded and expiration reaps the child.
#[test]
fn readiness_deadline_reaps_the_child() {
    let error = match ProcessNode::start_with_options(NodeBinary::BitcoinRs, &[], Duration::ZERO) {
        Ok(_) => panic!("expired startup deadline succeeded"),
        Err(error) => error,
    };
    let HarnessError::Deadline { pid, operation, .. } = error else {
        panic!("readiness must report its deadline: {error}");
    };
    assert_eq!(operation, "readiness");
    assert_reaped(pid);
}

// A local transport peer exercises the same HTTP owner; it never stands in
// for either node in the compatibility scenario above.
fn serve_reply(reply: &'static [u8], delay: Duration) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback responder");
    let addr = listener.local_addr().expect("loopback address");
    listener.set_nonblocking(true).expect("bounded accept");
    let server = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "client never connected");
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("loopback accept: {error}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("read bound");
        stream
            .set_write_timeout(Some(Duration::from_secs(1)))
            .expect("write bound");
        // Drain the entire bounded request before closing, so unread request
        // bytes cannot turn a malformed reply into a TCP reset instead.
        let mut request = Vec::new();
        loop {
            assert!(request.len() < 4096, "unexpected oversized fixture request");
            let mut chunk = [0_u8; 512];
            let count = stream.read(&mut chunk).expect("request bytes");
            assert!(count > 0, "request ended before its body");
            request.extend_from_slice(chunk.get(..count).expect("read chunk"));
            if let Some(split) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                let headers = std::str::from_utf8(request.get(..split).expect("HTTP headers"))
                    .expect("ASCII request headers");
                let length: usize = headers
                    .lines()
                    .find_map(|line| line.strip_prefix("Content-Length: "))
                    .expect("request content length")
                    .parse()
                    .expect("numeric content length");
                if request.len() >= split.saturating_add(4).saturating_add(length) {
                    break;
                }
            }
        }
        std::thread::sleep(delay);
        // A timed-out client may have already closed its socket.
        let _write_result = stream.write_all(reply);
    });
    (addr, server)
}

/// REF-07d: malformed HTTP and JSON are transport failures, not comparisons.
#[test]
fn malformed_http_and_json_replies_are_transport_failures() {
    for reply in [
        b"no HTTP header terminator".as_slice(),
        b"invalid status\r\nContent-Length: 2\r\n\r\n{}".as_slice(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n{}".as_slice(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\nnot json".as_slice(),
    ] {
        let (addr, server) = serve_reply(reply, Duration::ZERO);
        let result = exchange(
            addr,
            &json!({"method": "getblockcount"}),
            Instant::now() + Duration::from_secs(1),
        );
        server.join().expect("responder exits");
        assert!(matches!(
            result,
            Err(HarnessError::Protocol(_) | HarnessError::Json(_))
        ));
    }
}

/// REF-07c: a readable socket must not renew the total response deadline.
#[test]
fn dribbled_http_response_cannot_renew_the_request_deadline() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback responder");
    let addr = listener.local_addr().expect("loopback address");
    let server = std::thread::spawn(move || {
        listener.set_nonblocking(true).expect("bounded accept");
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(Instant::now() < deadline, "client must connect");
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(error) => panic!("accept: {error}"),
            }
        };
        stream
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("bounded read");
        stream
            .set_write_timeout(Some(Duration::from_secs(1)))
            .expect("bounded write");
        let mut request = [0_u8; 4096];
        assert!(stream.read(&mut request).expect("request") > 0);
        for byte in b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}" {
            if stream.write_all(&[*byte]).is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
    });
    let start = Instant::now();
    let result = exchange(
        addr,
        &json!({"method": "getblockcount"}),
        start + Duration::from_millis(100),
    );
    let elapsed = start.elapsed();
    server.join().expect("dribbling responder joins");
    assert!(
        result.is_err(),
        "a reply arriving after the deadline is not evidence"
    );
    assert!(
        elapsed < Duration::from_millis(600),
        "response renewed its deadline: {elapsed:?}"
    );
}

/// REF-07c: a slow request reader cannot renew the upload deadline.
#[test]
fn slow_http_request_reader_obeys_one_total_deadline() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback fixture");
    let addr = listener.local_addr().expect("fixture address");
    listener.set_nonblocking(true).expect("bounded accept");
    let server = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(2);
        let mut stream = loop {
            if let Ok((stream, _)) = listener.accept() {
                break stream;
            }
            assert!(Instant::now() < deadline, "client never connected");
            std::thread::sleep(Duration::from_millis(2));
        };
        stream
            .set_read_timeout(Some(Duration::from_millis(50)))
            .expect("bounded read");
        let mut bytes = [0; 4096];
        while Instant::now() < deadline {
            match stream.read(&mut bytes) {
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock
                    ) => {}
                Ok(0) | Err(_) => break,
                Ok(_) => std::thread::sleep(Duration::from_millis(2)),
            }
        }
    });
    let request = json!({"data": "x".repeat(12 * 1024 * 1024)});
    let start = Instant::now();
    let result = exchange(addr, &request, start + Duration::from_millis(500));
    let elapsed = start.elapsed();
    server.join().expect("slow request reader joins");
    assert!(result.is_err(), "slow upload must not complete");
    assert!(
        elapsed < Duration::from_millis(1200),
        "upload renewed deadline: {elapsed:?}"
    );
}

/// REF-07c: each reference request obeys its fixed deadline.
#[test]
fn stalled_response_respects_the_request_deadline() {
    let (addr, server) = serve_reply(b"", Duration::from_millis(250));
    let start = Instant::now();
    let result = exchange(
        addr,
        &json!({"method": "getblockcount"}),
        start + Duration::from_millis(80),
    );
    let elapsed = start.elapsed();
    server.join().expect("stalled responder exits");
    assert!(result.is_err(), "a silent peer cannot produce a reply");
    assert!(
        elapsed < Duration::from_secs(1),
        "request exceeded its deadline: {elapsed:?}"
    );
}

// ---------------------------------------------------------------------------
// #653 readiness scenarios: the txindex capability's readiness facts must be
// one fact everywhere they render — the `getcapabilities` row, the
// `getindexinfo` report Core parity checks, the Esplora tip, and the
// Prometheus readiness gauge all read the same node-owned status snapshot.
// ---------------------------------------------------------------------------

/// Regtest payout for single-node block production. No readiness scenario
/// spends from these coinbases.
const MINING_ADDRESS: &str = "bcrt1qw508d6qejxtdg4y5r3zarvary0c5xw7kygt080";

/// The readiness outcomes documented for the txindex capability. The gauge
/// label and the `getcapabilities` row spell them identically; a state
/// outside this vocabulary is a behavior failure, never a poll artifact.
const READINESS_OUTCOMES: [&str; 8] = CapabilityState::ALL_WIRE_NAMES;

fn readiness_deadline() -> Instant {
    Instant::now() + Duration::from_secs(120)
}

/// Starts the node with its derived index enabled.
fn start_txindex_node() -> ProcessNode {
    ProcessNode::start_with_options(NodeBinary::BitcoinRs, &["--txindex=true"], START_TIMEOUT)
        .expect("txindex node must start")
}

/// Extracts the txindex readiness outcome from a `getcapabilities` row.
///
/// Unit outcomes render as strings; payload outcomes render as one-key
/// objects. Either way the token must be documented vocabulary.
fn readiness_outcome(row: &Value) -> String {
    let state = row
        .pointer("/capabilities/0/state")
        .unwrap_or_else(|| panic!("getcapabilities has no txindex row: {row}"));
    let tag = if let Some(spelled) = state.as_str() {
        spelled.to_owned()
    } else {
        state
            .as_object()
            .and_then(|object| object.keys().next())
            .unwrap_or_else(|| panic!("untagged readiness state: {state}"))
            .to_owned()
    };
    assert!(
        READINESS_OUTCOMES.contains(&tag.as_str()),
        "readiness outcome outside the documented vocabulary: {tag}"
    );
    tag
}

/// Polls until the txindex row reports Ready, returning the distinct
/// outcomes observed on the way.
fn wait_until_ready(
    node: &mut ProcessNode,
    deadline: Instant,
) -> Result<Vec<String>, HarnessError> {
    let mut observed = Vec::new();
    loop {
        let row = node.rpc("getcapabilities", &json!([]))?;
        let outcome = readiness_outcome(&row);
        if observed.last() != Some(&outcome) {
            observed.push(outcome.clone());
        }
        let enabled = row
            .pointer("/capabilities/0/enabled")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if outcome == "Ready" && enabled {
            return Ok(observed);
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Deadline {
                pid: node.pid(),
                operation: "readiness",
                evidence: node.evidence.clone(),
                detail: format!("observed outcomes: {observed:?}"),
            });
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Polls until `getindexinfo` reports the txindex watermark synced.
fn wait_txindex_synced(node: &mut ProcessNode, deadline: Instant) -> Result<(), HarnessError> {
    loop {
        let info = node.rpc("getindexinfo", &json!(["txindex"]))?;
        if info.pointer("/txindex/synced") == Some(&json!(true)) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Deadline {
                pid: node.pid(),
                operation: "txindex sync",
                evidence: node.evidence.clone(),
                detail: format!("getindexinfo: {info}"),
            });
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Mines `blocks` on a lone node through its public mining RPC.
///
/// Startup anchors the tip at genesis but applies that block on the first
/// one-second sync tick, so an immediate mine races the applied tip. The
/// retry is bounded and only tolerates that one startup message.
fn mine_on_node(node: &mut ProcessNode, blocks: u32) -> Result<Vec<String>, HarnessError> {
    let deadline = readiness_deadline();
    let mined = loop {
        match node.rpc("generatetoaddress", &json!([blocks, MINING_ADDRESS])) {
            Ok(mined) => break mined,
            Err(HarnessError::Rpc { message, .. })
                if message.contains("applied tip is not available") =>
            {
                assert!(
                    Instant::now() < deadline,
                    "the applied tip never became available"
                );
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(error) => return Err(error),
        }
    };
    let hashes = mined
        .as_array()
        .ok_or_else(|| HarnessError::Protocol("mining result is not an array".into()))?;
    hashes
        .iter()
        .map(|hash| {
            hash.as_str()
                .map(str::to_owned)
                .ok_or_else(|| HarnessError::Protocol("mining result hash is not a string".into()))
        })
        .collect()
}

/// Reserves an ephemeral loopback address for `--metrics-bind`.
fn reserved_metrics_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("reserve metrics port");
    listener.local_addr().expect("reserved metrics address")
}

/// Scrapes the readiness gauge series from a node's metrics listener.
fn scrape_readiness(addr: SocketAddr) -> Vec<(String, f64)> {
    let prefix = "node_capability_txindex_readiness{";
    let mut last = None;
    for _ in 0..50 {
        if let Ok(mut stream) = TcpStream::connect_timeout(&addr, Duration::from_millis(100)) {
            stream
                .write_all(b"GET /metrics HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
                .expect("write metrics scrape");
            let mut body = String::new();
            stream
                .read_to_string(&mut body)
                .expect("read metrics scrape");
            return body
                .lines()
                .filter_map(|line| {
                    let rest = line.strip_prefix(prefix)?;
                    let (labels, value) = rest.split_once('}')?;
                    let state = labels
                        .split(',')
                        .find_map(|pair| {
                            pair.trim()
                                .strip_prefix("state=\"")
                                .and_then(|spelled| spelled.strip_suffix('"'))
                        })?
                        .to_owned();
                    let value = value.trim().parse::<f64>().ok()?;
                    Some((state, value))
                })
                .collect();
        }
        last = Some(());
        std::thread::sleep(Duration::from_millis(100));
    }
    panic!("metrics scrape failed after retries: {last:?}");
}

/// Exact one/zero gauge values: outcomes are set from `bool`, so exact bit
/// comparison is the honest check.
fn is_one(value: f64) -> bool {
    value.to_bits() == 1.0f64.to_bits()
}

fn is_zero(value: f64) -> bool {
    value.to_bits() == 0.0f64.to_bits()
}

/// The scraped series must show exactly one active outcome and it must be
/// the one the RPC row reported: metrics and RPC are one fact.
fn assert_one_active(samples: &[(String, f64)], expected: &str) {
    assert_eq!(
        samples.len(),
        READINESS_OUTCOMES.len(),
        "every documented outcome must render: {samples:?}"
    );
    let active: Vec<_> = samples.iter().filter(|(_, value)| is_one(*value)).collect();
    assert_eq!(
        active.len(),
        1,
        "exactly one readiness outcome must be active: {samples:?}"
    );
    assert_eq!(
        active.first().map(|(state, _)| state.as_str()),
        Some(expected),
        "the active gauge label must equal the RPC outcome"
    );
    assert!(
        samples
            .iter()
            .all(|(_, value)| is_one(*value) || is_zero(*value)),
        "outcome values are flags: {samples:?}"
    );
}

/// First confirmed transaction of a block, through the public surface.
fn first_block_txid(process: &mut ProcessNode, height: u32) -> String {
    let hash = process
        .rpc("getblockhash", &json!([height]))
        .expect("block hash");
    let block = process.rpc("getblock", &json!([hash, 2])).expect("block");
    block
        .pointer("/tx/0/txid")
        .and_then(Value::as_str)
        .expect("coinbase txid")
        .to_owned()
}

/// Polls the scrape until exactly one outcome is active and it is
/// `expected`: the sampled gauge converging on the RPC row.
fn wait_gauge_active(addr: SocketAddr, expected: &str, deadline: Instant) -> Vec<(String, f64)> {
    loop {
        let samples = scrape_readiness(addr);
        let active: Vec<_> = samples.iter().filter(|(_, value)| is_one(*value)).collect();
        if active.len() == 1 && active.first().map(|(state, _)| state.as_str()) == Some(expected) {
            return samples;
        }
        assert!(
            Instant::now() < deadline,
            "the gauge never reported {expected} active: {samples:?}"
        );
        std::thread::sleep(Duration::from_millis(200));
    }
}

/// #653 startup: at one captured tip, the capability row, the Core-parity
/// index report, the Esplora tip, and the Prometheus gauge all agree.
#[test]
fn startup_readiness_agrees_across_rpc_esplora_and_metrics() {
    let metrics_addr = reserved_metrics_addr();
    let metrics_flag = format!("--metrics-bind={metrics_addr}");
    let mut core =
        ProcessNode::start_with_options(NodeBinary::ReferenceCore, &["-txindex=1"], START_TIMEOUT)
            .expect("core with txindex must start");
    let mut node = ProcessNode::start_with_options(
        NodeBinary::BitcoinRs,
        &["--txindex=true", metrics_flag.as_str()],
        START_TIMEOUT,
    )
    .expect("node with txindex must start");
    let (core_pid, node_pid) = (core.pid(), node.pid());
    let deadline = readiness_deadline();

    mine_common_chain(&mut core, &mut node, COMMON_BLOCKS).expect("common chain");
    wait_until_ready(&mut node, deadline).expect("node readiness");
    wait_txindex_synced(&mut core, deadline).expect("core txindex synced");
    wait_txindex_synced(&mut node, deadline).expect("node txindex synced");

    // The capability row: enabled and Ready at the captured tip.
    let row = node
        .rpc("getcapabilities", &json!([]))
        .expect("capabilities");
    assert_eq!(row.pointer("/capabilities/0/id"), Some(&json!("txindex")));
    assert_eq!(row.pointer("/capabilities/0/compiled"), Some(&json!(true)));
    assert_eq!(row.pointer("/capabilities/0/enabled"), Some(&json!(true)));
    assert_eq!(readiness_outcome(&row), "Ready");

    // Core parity: both binaries render the same synced index report.
    let synced = compare_rpc(&mut core, &mut node, "getindexinfo", &json!(["txindex"]))
        .expect("index report parity");
    assert_eq!(
        synced.pointer("/txindex/synced"),
        Some(&json!(true)),
        "parity reply: {synced}"
    );

    // Esplora renders the same tip the RPC reports.
    let tip = node.rpc("getblockcount", &json!([])).expect("tip height");
    let esplora = node
        .http_get_json("/api/blocks/tip/height")
        .expect("esplora tip height");
    assert_eq!(tip, esplora, "RPC and Esplora must agree on the tip");

    // The readiness gauge is that same fact in Prometheus form. The gauge
    // is a sampled view, so require convergence with the RPC outcome within
    // the deadline, then assert the full one-active rendering.
    let samples = wait_gauge_active(metrics_addr, "Ready", deadline);
    assert_one_active(&samples, "Ready");

    core.stop().expect("core stop");
    node.stop().expect("node stop");
    assert_reaped(core_pid);
    assert_reaped(node_pid);
}

/// #653 disabled index: the disabled capability has its own documented row,
/// not silence, and the absence is identical to Core's.
#[test]
fn disabled_index_reports_its_documented_disabled_row() {
    let mut core = start(NodeBinary::ReferenceCore);
    let mut node = start(NodeBinary::BitcoinRs);
    let (core_pid, node_pid) = (core.pid(), node.pid());

    mine_common_chain(&mut core, &mut node, COMMON_BLOCKS).expect("common chain");

    let row = node
        .rpc("getcapabilities", &json!([]))
        .expect("capabilities");
    assert_eq!(row.pointer("/capabilities/0/id"), Some(&json!("txindex")));
    assert_eq!(row.pointer("/capabilities/0/compiled"), Some(&json!(true)));
    assert_eq!(row.pointer("/capabilities/0/enabled"), Some(&json!(false)));
    assert_eq!(readiness_outcome(&row), "Disabled");

    // Both binaries report the absent index identically.
    assert_eq!(
        compare_rpc(&mut core, &mut node, "getindexinfo", &json!(["txindex"]))
            .expect("disabled parity"),
        json!({}),
    );

    // Chain data still serves without an index; verbose history does not.
    let esplora = node
        .http_get_json("/api/blocks/tip/height")
        .expect("esplora tip height");
    assert_eq!(esplora, json!(COMMON_BLOCKS));
    let txid = first_block_txid(&mut node, 1);
    for process in [&mut core, &mut node] {
        let error = process
            .rpc("getrawtransaction", &json!([txid, true]))
            .expect_err("verbose history needs an index");
        assert!(
            matches!(error, HarnessError::Rpc { .. }),
            "verbose lookup without an index is a typed RPC failure: {error}"
        );
    }

    core.stop().expect("core stop");
    node.stop().expect("node stop");
    assert_reaped(core_pid);
    assert_reaped(node_pid);
}

/// #653 catch-up: blocks applied ahead of the derived worker must surface
/// only documented intermediate outcomes, and the poll ends Ready.
#[test]
fn catch_up_poll_stays_inside_the_documented_outcomes() {
    let mut node = start_txindex_node();
    let pid = node.pid();
    let deadline = readiness_deadline();

    mine_on_node(&mut node, 20).expect("initial chain");
    wait_until_ready(&mut node, deadline).expect("initial readiness");

    mine_on_node(&mut node, 40).expect("catch-up chain");
    let observed = wait_until_ready(&mut node, deadline).expect("catch-up readiness");
    for outcome in &observed {
        assert!(
            READINESS_OUTCOMES.contains(&outcome.as_str()),
            "undocumented catch-up outcome: {outcome}"
        );
    }
    wait_txindex_synced(&mut node, deadline).expect("synced after catch-up");
    assert_eq!(
        node.rpc("getblockcount", &json!([])).expect("tip height"),
        json!(60)
    );

    node.stop().expect("node stop");
    assert_reaped(pid);
}

/// #653 index failure: a destroyed derived store recovers by rebuilding from
/// retained canonical chainstate, and the historical row comes back.
#[test]
fn destroyed_index_rebuilds_from_canonical_data_and_restores_history() {
    let mut node = start_txindex_node();
    let deadline = readiness_deadline();

    mine_on_node(&mut node, COMMON_BLOCKS).expect("chain");
    wait_until_ready(&mut node, deadline).expect("initial readiness");
    wait_txindex_synced(&mut node, deadline).expect("initial sync");

    // A confirmed historical row the index owns, captured before the loss.
    let txid = first_block_txid(&mut node, 5);
    let raw = node
        .rpc("getrawtransaction", &json!([txid]))
        .expect("indexed raw transaction");

    let datadir = node.take_datadir().expect("datadir custody");
    node.stop().expect("stop before recovery");
    // The resolved data dir is `<datadir>/node`; the derived store lives
    // beside the chainstate inside it. Destroy it only when it is really
    // there: a silent no-op would make the rebuild vacuous.
    let derived_store = datadir.path().join("node").join("txindex");
    assert!(
        derived_store.is_dir(),
        "the derived index store must exist at {}: {:?}",
        derived_store.display(),
        std::fs::read_dir(datadir.path())
            .map(|entries| entries
                .filter_map(Result::ok)
                .map(|entry| entry.file_name())
                .collect::<Vec<_>>())
            .unwrap_or_default(),
    );
    std::fs::remove_dir_all(&derived_store).expect("destroy the disposable derived store");

    let mut rebuilt = ProcessNode::start_with_datadir(
        NodeBinary::BitcoinRs,
        &["--txindex=true"],
        START_TIMEOUT,
        datadir,
    )
    .expect("restart over the retained chainstate");
    let observed = wait_until_ready(&mut rebuilt, deadline).expect("rebuilt readiness");
    for outcome in &observed {
        assert!(
            READINESS_OUTCOMES.contains(&outcome.as_str()),
            "undocumented rebuild outcome: {outcome}"
        );
    }
    wait_txindex_synced(&mut rebuilt, deadline).expect("rebuilt sync");
    // Backfill may trail the watermark report; poll the row, and on failure
    // keep the chain-side evidence in the panic.
    let mut restored = None;
    let row_deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < row_deadline {
        if let Ok(back) = rebuilt.rpc("getrawtransaction", &json!([txid])) {
            restored = Some(back);
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let restored = restored.unwrap_or_else(|| {
        let block5 = rebuilt.rpc("getblockhash", &json!([5])).expect("block 5");
        let via_chain = rebuilt.rpc("getrawtransaction", &json!([txid, false, block5]));
        panic!(
            "the rebuilt index never restored the historical row; index info: {:?}; chain-side lookup: {:?}",
            rebuilt.rpc("getindexinfo", &json!(["txindex"])),
            via_chain
        );
    });
    assert_eq!(
        restored, raw,
        "the rebuilt index must restore the row verbatim"
    );

    let pid = rebuilt.pid();
    rebuilt.stop().expect("stop rebuilt node");
    assert_reaped(pid);
}

/// #653 restart: a clean stop and restart over the same datadir restores
/// Ready readiness at the pinned tip with the index intact.
#[test]
fn clean_restart_restores_ready_readiness_at_the_pinned_tip() {
    let mut node = start_txindex_node();
    let deadline = readiness_deadline();

    mine_on_node(&mut node, COMMON_BLOCKS).expect("chain");
    wait_until_ready(&mut node, deadline).expect("initial readiness");
    wait_txindex_synced(&mut node, deadline).expect("initial sync");
    let tip = node
        .rpc("getbestblockhash", &json!([]))
        .expect("pinned tip hash");

    let datadir = node.take_datadir().expect("datadir custody");
    node.stop().expect("clean stop");
    let mut restarted = ProcessNode::start_with_datadir(
        NodeBinary::BitcoinRs,
        &["--txindex=true"],
        START_TIMEOUT,
        datadir,
    )
    .expect("restart over the same datadir");
    wait_until_ready(&mut restarted, deadline).expect("readiness after restart");
    assert_eq!(
        restarted
            .rpc("getbestblockhash", &json!([]))
            .expect("tip after restart"),
        tip,
        "the restarted node must resume the pinned tip"
    );
    wait_txindex_synced(&mut restarted, deadline).expect("index after restart");

    let pid = restarted.pid();
    restarted.stop().expect("stop restarted node");
    assert_reaped(pid);
}

/// #653 reorg: invalidating a mid-chain block and mining a fork rewinds the
/// derived watermark and returns readiness to Ready on the forked tip.
#[test]
fn reorg_returns_readiness_to_ready_on_the_forked_tip() {
    let mut node = start_txindex_node();
    let deadline = readiness_deadline();

    mine_on_node(&mut node, COMMON_BLOCKS).expect("chain");
    wait_until_ready(&mut node, deadline).expect("initial readiness");
    wait_txindex_synced(&mut node, deadline).expect("initial sync");

    // Abandon the last two blocks and re-mine from height 99 on a fork.
    let fork_base = node
        .rpc("getblockhash", &json!([COMMON_BLOCKS - 2]))
        .expect("fork base hash");
    node.rpc("invalidateblock", &json!([fork_base]))
        .expect("invalidate the fork base");
    let fork = mine_on_node(&mut node, 3).expect("fork blocks");
    assert_eq!(fork.len(), 3);

    wait_until_ready(&mut node, deadline).expect("readiness after reorg");
    wait_txindex_synced(&mut node, deadline).expect("index synced after reorg");
    assert_eq!(
        node.rpc("getblockcount", &json!([]))
            .expect("count after reorg"),
        json!(COMMON_BLOCKS)
    );
    assert_eq!(
        node.rpc("getbestblockhash", &json!([]))
            .expect("tip after reorg"),
        json!(fork.last().expect("fork tip")),
        "the active tip must be the fork tip"
    );

    let pid = node.pid();
    node.stop().expect("node stop");
    assert_reaped(pid);
}
