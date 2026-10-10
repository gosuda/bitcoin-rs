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

// The harness consumes only the release identity's binary digest; the rest
// of the reference record stays dead in this binary.
#[expect(dead_code, reason = "only the release bitcoind digest is read")]
#[path = "support/reference_set.rs"]
mod reference_set;

#[path = "support/psbt_codec_cases.rs"]
mod psbt_codec_cases;

#[path = "support/script_decode_cases.rs"]
mod script_decode_cases;

#[path = "support/policy_cases.rs"]
mod policy_cases;

#[path = "support/spending_prevout_cases.rs"]
mod spending_prevout_cases;

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use bitcoin::hashes::{Hash as _, sha256};
use bitcoin_rs_e2e::differential::{
    compare_reply, compare_rpc, mine_common_chain, verify_reference_binary,
};
use bitcoin_rs_e2e::node::START_TIMEOUT;
use bitcoin_rs_e2e::process_peer::connect_loopback;
use bitcoin_rs_e2e::rpc::exchange;
use bitcoin_rs_e2e::{ClockControl, Error, Kind, ProcessNode, SpawnOptions};
use reference_set::reference_set;
use serde_json::{Value, json};

// A height-1 coinbase is mature for admission after 101 common blocks.
const COMMON_BLOCKS: u32 = 101;

/// Whether the OS still reports a live process under `pid`. On unix the
/// kernel drops `/proc/<pid>` once the parent reaps the child; Windows
/// answers via the process object's exit code.
#[cfg(unix)]
fn pid_is_alive(pid: u32) -> bool {
    Path::new(&format!("/proc/{pid}")).exists()
}

/// Whether the OS still reports a live process under `pid`. Windows marks
/// a terminated object's exit code, so a present-but-dead pid is not alive.
#[cfg(windows)]
fn pid_is_alive(pid: u32) -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, STILL_ACTIVE};
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };
    // SAFETY: the returned handle is checked for null and closed on every
    // path; `code` is a plain out-param the call fully overwrites.
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid);
        if handle.is_null() {
            return false;
        }
        let mut code = 0_u32;
        let alive = GetExitCodeProcess(handle, std::ptr::from_mut(&mut code)) != 0
            && i32::try_from(code) == Ok(STILL_ACTIVE);
        let _ = CloseHandle(handle);
        alive
    }
}

/// Waits for the kernel to drop the child after it is reaped.
fn assert_reaped(pid: u32) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while pid_is_alive(pid) {
        assert!(Instant::now() < deadline, "child {pid} survived cleanup");
        std::thread::sleep(Duration::from_millis(20));
    }
}

/// The exact binary this test package is compiled against — not the
/// newest-file heuristic the e2e crate uses for cross-package callers.
fn self_binary() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_bitcoin-rs"))
}

fn start(binary: Kind) -> ProcessNode {
    ProcessNode::spawn_with(
        binary,
        &SpawnOptions {
            binary: Some(self_binary()),
            ..Default::default()
        },
    )
    .expect("public process must start")
}

/// API-01/API-02: Core 31.1 omits inapplicable pruning and signet fields.
/// Only that response-shape claim is compared; this node does not ship Core's
/// block-filter RPC and must continue to report method-not-found for it.
#[test]
fn chaininfo_optional_fields_follow_core_without_claiming_blockfilters() {
    for (kind, rest_flag) in [(Kind::Core, "-rest=1"), (Kind::BitcoinRs, "--rest=true")] {
        let mut node = ProcessNode::spawn_with(
            kind,
            &SpawnOptions {
                binary: Some(self_binary()),
                extra_args: &[rest_flag],
                ..Default::default()
            },
        )
        .expect("isolated unpruned regtest node with REST must start");
        let pid = node.pid();
        let rpc = node
            .rpc("getblockchaininfo", &json!([]))
            .expect("chaininfo RPC");
        let rest = node
            .http_get("/rest/chaininfo.json")
            .expect("chaininfo REST");
        assert_eq!(rest.status, 200);
        let rest = rest.json().expect("chaininfo REST JSON");
        for response in [&rpc, &rest] {
            assert_eq!(response.get("chain"), Some(&json!("regtest")));
            assert_eq!(response.get("pruned"), Some(&json!(false)));
            // Core src/rpc/blockchain.cpp inserts these keys only for the
            // relevant pruning mode or signet, never as JSON null.
            for field in [
                "automatic_pruning",
                "prune_target_size",
                "pruneheight",
                "signet_challenge",
            ] {
                assert!(
                    response.get(field).is_none(),
                    "{kind:?} {field}: {response}"
                );
            }
        }
        if kind == Kind::BitcoinRs {
            let error = node
                .rpc("getblockfilter", &json!([rpc["bestblockhash"], "basic"]))
                .expect_err("block filters are inventoried but unimplemented");
            assert!(matches!(error, Error::Rpc { code: -32_601, .. }), "{error}");
        }
        node.stop().expect("node stop");
        assert_reaped(pid);
    }
}

/// API-02: ordinary named arguments share Core's positional binding rules.
#[test]
fn named_rpc_arguments_follow_core() {
    let mut core = start(Kind::Core);
    let mut node = start(Kind::BitcoinRs);
    for (method, params) in [
        (
            "createrawtransaction",
            json!({"inputs": [], "outputs": {}, "locktime": 7}),
        ),
        (
            "createrawtransaction",
            json!({"args": [[]], "outputs": {}, "locktime": 7}),
        ),
        (
            "createrawtransaction",
            json!({"args": false, "inputs": [], "outputs": {}}),
        ),
        (
            "createrawtransaction",
            json!({"args": [[], {}], "inputs": null, "extra": 1}),
        ),
        (
            "createrawtransaction",
            json!({"inputs": [], "outputs": {}, "extra": 1}),
        ),
        ("decoderawtransaction", json!({"hexstring": "zz"})),
        ("decoderawtransaction", json!({"args": ["zz"]})),
        ("gettxspendingprevout", json!({"outputs": []})),
        (
            "gettxspendingprevout",
            json!({"args": [[]], "mempool_only": true, "return_spending_tx": false}),
        ),
        (
            "gettxspendingprevout",
            json!({"outputs": [], "options": null, "mempool_only": true}),
        ),
        (
            "gettxspendingprevout",
            json!({"args": [[], {}], "mempool_only": true}),
        ),
        (
            "gettxspendingprevout",
            json!({"args": [[], {}], "outputs": null, "extra": 1}),
        ),
    ] {
        let request = json!({"jsonrpc": "2.0", "id": "named", "method": method, "params": params});
        let reference = core.rpc_raw(&request).expect("Core named request");
        let candidate = node.rpc_raw(&request).expect("candidate named request");
        compare_reply(&request.to_string(), &reference, &candidate)
            .expect("named binding and method errors match Core");
    }
    // Preserve repeated JSON keys until the binder rejects them. Building
    // these requests through serde_json::Value would discard that evidence.
    for body in [
        r#"{"jsonrpc":"2.0","id":"duplicate","method":"createrawtransaction","params":{"inputs":[],"inputs":[],"outputs":{}}}"#,
        r#"{"jsonrpc":"2.0","id":"duplicate","method":"gettxspendingprevout","params":{"outputs":[],"mempool_only":true,"mempool_only":false}}"#,
        r#"{"jsonrpc":"2.0","id":"duplicate","method":"decoderawtransaction","params":{"args":["zz"],"args":["00"]}}"#,
    ] {
        let reference = core
            .http("POST", "/", body.as_bytes(), true)
            .expect("Core duplicate-name request")
            .json()
            .expect("Core JSON");
        let candidate = node
            .http("POST", "/", body.as_bytes(), true)
            .expect("candidate duplicate-name request")
            .json()
            .expect("candidate JSON");
        compare_reply(body, &reference, &candidate).expect("duplicate-name refusal matches Core");
    }
    core.stop().expect("core stop");
    node.stop().expect("node stop");
}

/// REF-07/P2P-01: compatibility must reach the binary's public P2P listener.
#[test]
fn normal_startup_exposes_an_isolated_loopback_p2p_listener() {
    // Each binary's startup, listener probe, and shutdown are independent.
    std::thread::scope(|scope| {
        for binary in [Kind::BitcoinRs, Kind::Core] {
            scope.spawn(move || {
                let node = start(binary);
                let pid = node.pid();
                assert!(node.p2p_addr.ip().is_loopback());
                let peer = connect_loopback(node.p2p_addr, Instant::now() + Duration::from_secs(1))
                    .expect("normal startup must expose its configured P2P listener");
                drop(peer);
                node.stop().expect("stop after public P2P connection");
                assert_reaped(pid);
            });
        }
    });
}

/// POL-05/REF-07: signaling never decides replacement eligibility. Both
/// nodes still reject an underpaying replacement without changing the pool.
#[test]
fn replacement_signaling_matches_pinned_core() {
    // The signaled and unsignaled scenarios are independent node pairs.
    std::thread::scope(|scope| {
        for signals in [false, true] {
            scope.spawn(move || replacement_signaling_case(signals));
        }
    });
}

#[expect(
    clippy::too_many_lines,
    reason = "keep the ordered replacement and rejection observations together"
)]
fn replacement_signaling_case(signals: bool) {
    use bitcoin::Sequence;
    use bitcoin::consensus::encode::serialize_hex;

    {
        let (mut core, mut node) = std::thread::scope(|scope| {
            let core = scope.spawn(|| start(Kind::Core));
            let node = scope.spawn(|| start(Kind::BitcoinRs));
            (
                core.join().expect("reference launch panicked"),
                node.join().expect("candidate launch panicked"),
            )
        });
        let funds = mine_common_chain(&mut core, &mut node, COMMON_BLOCKS).expect("common chain");
        let sequence = if signals {
            Sequence::ENABLE_RBF_NO_LOCKTIME
        } else {
            Sequence::MAX
        };
        let original = funds.signed_spend(10_000, sequence).expect("original");
        let replacement = funds
            .signed_spend(20_000, Sequence::MAX)
            .expect("higher-fee replacement");
        let original_txid = original.compute_txid().to_string();
        let replacement_txid = replacement.compute_txid().to_string();
        let replacement_raw = serialize_hex(&replacement);
        let underpaying = funds
            .signed_spend(9_000, Sequence::MAX)
            .expect("replacement below the original's fee");
        let underpaying_raw = serialize_hex(&underpaying);

        // The replacement is independently valid before there is a conflict.
        // A script or funding failure must not masquerade as an RBF difference.
        let raws = [&replacement_raw, &underpaying_raw];
        std::thread::scope(|scope| {
            for process in [&mut core, &mut node] {
                scope.spawn(move || {
                    for raw in raws {
                        let preview = process
                            .rpc("testmempoolaccept", &json!([[raw]]))
                            .expect("unconflicted replacement preview");
                        assert_eq!(preview[0]["allowed"], json!(true), "{preview}");
                    }
                });
            }
        });
        assert_eq!(
            compare_rpc(&mut core, &mut node, "getrawmempool", &json!([]))
                .expect("unconflicted previews leave the pools empty"),
            json!([]),
        );
        assert_eq!(
            compare_rpc(
                &mut core,
                &mut node,
                "sendrawtransaction",
                &json!([serialize_hex(&original)]),
            )
            .expect("both nodes admit the same original"),
            json!(original_txid),
        );

        // Independent public response expectations for the pinned fee-policy case.
        // The per-process observation sequences are independent.
        let rejection_case = |process: &mut ProcessNode, rejection: &str| {
            let before = process
                .rpc("getrawmempool", &json!([false, true]))
                .expect("membership and sequence before preview");
            assert_eq!(before["txids"], json!([original_txid]));
            let sequence_before = before["mempool_sequence"].as_u64().expect("pool sequence");
            let rejected = process
                .rpc("testmempoolaccept", &json!([[underpaying_raw]]))
                .expect("underpaying preview");
            assert_eq!(rejected[0]["allowed"], json!(false), "{rejected}");
            assert_eq!(rejected[0]["reject-reason"], json!(rejection));
            assert_eq!(
                process
                    .rpc("getrawmempool", &json!([false, true]))
                    .expect("after rejected preview"),
                before,
            );
            let submitted = process.rpc("sendrawtransaction", &json!([underpaying_raw]));
            assert!(
                matches!(submitted, Err(Error::Rpc { code: -26, ref message, .. }) if message.contains(rejection)),
                "a fee-policy rejection must not be a transport failure: {submitted:?}",
            );
            assert_eq!(
                process
                    .rpc("getrawmempool", &json!([false, true]))
                    .expect("after rejected submission"),
                before,
                "underpaying replacement must preserve membership and sequence",
            );
            let preview = process
                .rpc("testmempoolaccept", &json!([[replacement_raw]]))
                .expect("replacement preview");
            assert_eq!(preview[0]["txid"], json!(replacement_txid));
            assert_eq!(preview[0]["allowed"], json!(true), "{preview}");
            assert_eq!(
                process
                    .rpc("getrawmempool", &json!([false, true]))
                    .expect("after preview"),
                before,
                "preview must not evict the original or advance the sequence",
            );

            let submitted = process.rpc("sendrawtransaction", &json!([replacement_raw]));
            let after = process
                .rpc("getrawmempool", &json!([false, true]))
                .expect("membership and sequence after submission");
            assert_eq!(
                submitted.expect("replacement accepted"),
                json!(replacement_txid)
            );
            assert_eq!(after["txids"], json!([replacement_txid]));
            assert!(after["mempool_sequence"].as_u64().expect("pool sequence") > sequence_before);
            let policy = process
                .rpc("getmempoolinfo", &json!([]))
                .expect("enforced policy");
            assert_eq!(policy["fullrbf"], json!(true));
        };
        std::thread::scope(|scope| {
            for (process, rejection) in [
                (&mut core, "insufficient fee"),
                (&mut node, "insufficient fee"),
            ] {
                scope.spawn(move || rejection_case(process, rejection));
            }
        });
        let (core_pid, node_pid) = (core.pid(), node.pid());
        core.stop().expect("stop reference");
        node.stop().expect("stop candidate");
        assert_reaped(core_pid);
        assert_reaped(node_pid);
    }
}

#[test]
#[expect(
    clippy::too_many_lines,
    reason = "keep the ordered public-process scenario and its observations together"
)]
fn signed_transaction_reaches_both_mempools_confirmation_and_public_queries() {
    let (mut core, mut node) = std::thread::scope(|scope| {
        let core = scope.spawn(|| start(Kind::Core));
        let node = scope.spawn(|| start(Kind::BitcoinRs));
        (
            core.join().expect("reference launch panicked"),
            node.join().expect("candidate launch panicked"),
        )
    });
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

    let spend = funds
        .signed_spend(10_000, bitcoin::Sequence::MAX)
        .expect("sign mature coinbase");
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
    // The per-process preview and rejection observations are independent.
    let signature_case = |process: &mut ProcessNode| {
        let valid = process
            .rpc("testmempoolaccept", &json!([[raw]]))
            .expect("valid signed preview reaches the public admission owner");
        let valid_allowed = valid
            .pointer("/0/allowed")
            .expect("valid preview allowed field")
            .clone();
        let invalid = process
            .rpc("testmempoolaccept", &json!([[invalid_raw]]))
            .expect("invalid signature is a semantic preview reply");
        let invalid_allowed = invalid
            .pointer("/0/allowed")
            .expect("invalid preview allowed field")
            .clone();
        let rejection = process
            .rpc("sendrawtransaction", &json!([invalid_raw]))
            .expect_err("invalid signature cannot be admitted");
        let Error::Rpc { code, .. } = rejection else {
            panic!("transport or setup failure is not an admission rejection: {rejection}");
        };
        (valid_allowed, invalid_allowed, json!(code))
    };
    let (valid_previews, invalid_previews, rejection_codes) = std::thread::scope(|scope| {
        let reference = scope.spawn(|| signature_case(&mut core));
        let candidate = scope.spawn(|| signature_case(&mut node));
        let (reference, candidate) = (
            reference.join().expect("reference signature case panicked"),
            candidate.join().expect("candidate signature case panicked"),
        );
        (
            vec![reference.0, candidate.0],
            vec![reference.1, candidate.1],
            vec![reference.2, candidate.2],
        )
    });
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
    let node = start(Kind::BitcoinRs);
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
        .current_artifact()
        .expect("a pinned artifact for this platform")
        .bitcoind_sha256;
    let pinned = sha256::Hash::from_byte_array(pinned).to_string();

    let error = verify_reference_binary(path).expect_err("absent binary must fail");
    let Error::Reference {
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
        Err(Error::Difference { .. }),
    ));
}

/// REF-07b: rejected startup must report and reap the exact child process.
#[test]
fn rejected_startup_options_leave_no_child() {
    let error = match ProcessNode::spawn_with(
        Kind::BitcoinRs,
        &SpawnOptions {
            binary: Some(self_binary()),
            extra_args: &["--process-harness-invalid-option"],
            timeout: Some(Duration::from_secs(5)),
            ..Default::default()
        },
    ) {
        Ok(_) => panic!("invalid startup option succeeded"),
        Err(error) => error,
    };
    let Error::ChildExit {
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
    let error = match ProcessNode::spawn_with(
        Kind::BitcoinRs,
        &SpawnOptions {
            binary: Some(self_binary()),
            extra_args: &["--help"],
            timeout: Some(Duration::from_secs(5)),
            ..Default::default()
        },
    ) {
        Ok(_) => panic!("help exit was mistaken for a ready node"),
        Err(error) => error,
    };
    let Error::ChildExit { pid, status, .. } = error else {
        panic!("early successful exit must report child exit: {error}");
    };
    assert!(status.success());
    assert_reaped(pid);
}

/// REF-07c: readiness is deadline-bounded and expiration reaps the child.
#[test]
fn readiness_deadline_reaps_the_child() {
    let error = match ProcessNode::spawn_with(
        Kind::BitcoinRs,
        &SpawnOptions {
            binary: Some(self_binary()),
            timeout: Some(Duration::ZERO),
            ..Default::default()
        },
    ) {
        Ok(_) => panic!("expired startup deadline succeeded"),
        Err(error) => error,
    };
    let Error::Timeout { pid, operation, .. } = error else {
        panic!("readiness must report its deadline: {error}");
    };
    assert_eq!(operation, "readiness");
    assert_reaped(pid);
}

// A local transport peer exercises the same HTTP owner; it never stands in
// for either node in the compatibility scenario above.
fn serve_once(
    respond: impl FnOnce(TcpStream, Instant) + Send + 'static,
) -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback responder");
    let addr = listener.local_addr().expect("loopback address");
    listener.set_nonblocking(true).expect("bounded accept");
    let server = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(2);
        let stream = loop {
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
        respond(stream, deadline);
    });
    (addr, server)
}

fn serve_reply(reply: &'static [u8], delay: Duration) -> (SocketAddr, JoinHandle<()>) {
    serve_once(move |mut stream, deadline| {
        // Drain the entire bounded request before closing, so unread request
        // bytes cannot turn a malformed reply into a TCP reset instead.
        let mut request = Vec::new();
        loop {
            assert!(request.len() < 4096, "unexpected oversized fixture request");
            let mut chunk = [0_u8; 512];
            let count = match stream.read(&mut chunk) {
                Ok(count) => count,
                // RCVTIMEO expiry arrives as WouldBlock; a loaded scheduler
                // can stall the client past one read bound, so retry against
                // the responder's total deadline.
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    assert!(Instant::now() < deadline, "client stalled on its request");
                    continue;
                }
                Err(error) => panic!("request bytes: {error}"),
            };
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
    })
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
        assert!(matches!(result, Err(Error::Protocol(_) | Error::Json(_))));
    }
}

/// REF-07c: a readable socket must not renew the total response deadline.
#[test]
fn dribbled_http_response_cannot_renew_the_request_deadline() {
    let (addr, server) = serve_once(|mut stream, deadline| {
        let mut request = [0_u8; 4096];
        loop {
            match stream.read(&mut request) {
                Ok(count) if count > 0 => break,
                Ok(_) => panic!("request ended before its body"),
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    assert!(Instant::now() < deadline, "client never sent");
                }
                Err(error) => panic!("request: {error}"),
            }
        }
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
    let (addr, server) = serve_once(|mut stream, deadline| {
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
const READINESS_OUTCOMES: [&str; 8] = [
    "Ready",
    "CatchingUp",
    "RollingBack",
    "Rebuilding",
    "Failed",
    "Disabled",
    "Opening",
    "ShutdownAbandoned",
];

fn readiness_deadline() -> Instant {
    Instant::now() + Duration::from_mins(2)
}

/// Starts the node with its derived index enabled.
fn start_txindex_node() -> ProcessNode {
    ProcessNode::spawn_with(
        Kind::BitcoinRs,
        &SpawnOptions {
            binary: Some(self_binary()),
            extra_args: &["--txindex=true"],
            timeout: Some(START_TIMEOUT),
            ..Default::default()
        },
    )
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
fn wait_until_ready(node: &mut ProcessNode, deadline: Instant) -> Result<Vec<String>, Error> {
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
            return Err(Error::Timeout {
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
fn wait_txindex_synced(node: &mut ProcessNode, deadline: Instant) -> Result<(), Error> {
    loop {
        let info = node.rpc("getindexinfo", &json!(["txindex"]))?;
        if info.pointer("/txindex/synced") == Some(&json!(true)) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(Error::Timeout {
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
fn mine_on_node(node: &mut ProcessNode, blocks: u32) -> Result<Vec<String>, Error> {
    let deadline = readiness_deadline();
    let mined = loop {
        // The transport shares the readiness deadline: a bulk mine
        // legitimately exceeds the per-request budget on slow hosts.
        match node.rpc_until(
            "generatetoaddress",
            &json!([blocks, MINING_ADDRESS]),
            deadline,
        ) {
            Ok(mined) => break mined,
            Err(Error::Rpc { message, .. }) if message.contains("applied tip is not available") => {
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
        .ok_or_else(|| Error::Protocol("mining result is not an array".into()))?;
    hashes
        .iter()
        .map(|hash| {
            hash.as_str()
                .map(str::to_owned)
                .ok_or_else(|| Error::Protocol("mining result hash is not a string".into()))
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
    let mut core = ProcessNode::spawn_with(
        Kind::Core,
        &SpawnOptions {
            extra_args: &["-txindex=1"],
            timeout: Some(START_TIMEOUT),
            ..Default::default()
        },
    )
    .expect("core with txindex must start");
    let mut node = ProcessNode::spawn_with(
        Kind::BitcoinRs,
        &SpawnOptions {
            binary: Some(self_binary()),
            extra_args: &["--txindex=true", metrics_flag.as_str()],
            timeout: Some(START_TIMEOUT),
            ..Default::default()
        },
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
    let mut core = start(Kind::Core);
    let mut node = start(Kind::BitcoinRs);
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
            matches!(error, Error::Rpc { .. }),
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

    let mut rebuilt = ProcessNode::spawn_in_datadir(
        Kind::BitcoinRs,
        &SpawnOptions {
            binary: Some(self_binary()),
            extra_args: &["--txindex=true"],
            timeout: Some(START_TIMEOUT),
            ..Default::default()
        },
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
    let row_deadline = Instant::now() + Duration::from_mins(1);
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
    let mut restarted = ProcessNode::spawn_in_datadir(
        Kind::BitcoinRs,
        &SpawnOptions {
            binary: Some(self_binary()),
            extra_args: &["--txindex=true"],
            timeout: Some(START_TIMEOUT),
            ..Default::default()
        },
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

/// API-02 / REF-07: an explicit retained block lookup follows Core's applied
/// ancestry after disconnect and replacement, while its raw bytes stay readable.
#[test]
fn retained_transaction_confirmations_match_core_after_reorg() {
    // Compare this contract's chain fields and byte identity. Script asm and
    // descriptor rendering have their own compatibility evidence.
    let compare_transaction = |core: &mut ProcessNode, node: &mut ProcessNode, params: &Value| {
        let reference = core
            .rpc("getrawtransaction", params)
            .expect("reference transaction");
        let candidate = node
            .rpc("getrawtransaction", params)
            .expect("candidate transaction");
        for field in [
            "blockhash",
            "in_active_chain",
            "confirmations",
            "time",
            "blocktime",
            "hex",
        ] {
            assert_eq!(
                candidate.get(field),
                reference.get(field),
                "transaction field {field}"
            );
        }
        reference
    };
    let mut core = start(Kind::Core);
    let mut node = start(Kind::BitcoinRs);
    mine_common_chain(&mut core, &mut node, 3).expect("common chain");
    let hash =
        compare_rpc(&mut core, &mut node, "getblockhash", &json!([1])).expect("height-one block");
    let txid = first_block_txid(&mut core, 1);
    let params = json!([txid, true, hash]);
    let active = compare_transaction(&mut core, &mut node, &params);
    assert_eq!(active["in_active_chain"], true);
    assert_eq!(active["confirmations"], 3);
    assert!(active.get("time").is_some());
    assert!(active.get("blocktime").is_some());
    let raw_params = json!([txid, false, hash]);
    let original = compare_rpc(&mut core, &mut node, "getrawtransaction", &raw_params)
        .expect("original raw bytes");

    compare_rpc(&mut core, &mut node, "invalidateblock", &json!([hash]))
        .expect("disconnect the containing block");
    for replaced in [false, true] {
        if replaced {
            // The reference starts with fixed mocktime. Move it forward so
            // mining with the same payout cannot recreate the invalidated
            // block byte for byte.
            let replacement_time = active["time"]
                .as_u64()
                .expect("original block time")
                .checked_add(600)
                .expect("replacement block time");
            core.rpc("setmocktime", &json!([replacement_time]))
                .expect("advance reference clock for a distinct branch");
            mine_common_chain(&mut core, &mut node, 3).expect("replacement branch");
            let replacement = compare_rpc(&mut core, &mut node, "getblockhash", &json!([1]))
                .expect("replacement height-one block");
            assert_ne!(replacement, hash, "replacement must be a distinct branch");
        }
        let stale = compare_transaction(&mut core, &mut node, &params);
        assert_eq!(stale["blockhash"], hash);
        assert_eq!(stale["in_active_chain"], false);
        assert_eq!(stale["confirmations"], 0);
        assert!(stale.get("time").is_none());
        assert!(stale.get("blocktime").is_none());
        assert_eq!(
            compare_rpc(&mut core, &mut node, "getrawtransaction", &raw_params)
                .expect("retained raw bytes"),
            original
        );
    }
    let core_pid = core.pid();
    let node_pid = node.pid();
    core.stop().expect("stop reference");
    node.stop().expect("stop candidate");
    assert_reaped(core_pid);
    assert_reaped(node_pid);
}
