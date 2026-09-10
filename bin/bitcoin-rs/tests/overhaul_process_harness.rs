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
use std::net::{SocketAddr, TcpListener};
use std::path::Path;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use bitcoin::hashes::{Hash as _, sha256};
use serde_json::json;
use support::process_node::{
    ClockControl, HarnessError, NodeBinary, ProcessNode, compare_reply, compare_rpc, exchange,
    mine_common_chain, verify_reference_binary,
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
