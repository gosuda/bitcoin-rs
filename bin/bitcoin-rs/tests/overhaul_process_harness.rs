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

use std::path::Path;
use std::time::{Duration, Instant};

use bitcoin::hashes::{Hash as _, sha256};
use serde_json::json;
use support::process_node::{
    ClockControl, HarnessError, NodeBinary, ProcessNode, mine_common_chain, verify_reference_binary,
};

const COMMON_BLOCKS: u32 = 3;

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
fn both_processes_share_one_chain_and_leave_no_child() {
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

    let core_tip = core.rpc("getbestblockhash", &json!([])).expect("core tip");
    let node_tip = node.rpc("getbestblockhash", &json!([])).expect("node tip");
    assert_eq!(
        core_tip, node_tip,
        "tips diverge after identical block bytes"
    );
    let last = funds.common_block_bytes.last().expect("mined block");
    let last: bitcoin::Block = bitcoin::consensus::deserialize(last).expect("block bytes");
    assert_eq!(node_tip, json!(last.block_hash().to_string()));

    let transcript = std::fs::read_to_string(node.evidence.join("transcript.jsonl"))
        .expect("transcript custody");
    // Genesis submit, one submit per block, one tip read.
    assert!(transcript.lines().count() >= expected + 2);

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
