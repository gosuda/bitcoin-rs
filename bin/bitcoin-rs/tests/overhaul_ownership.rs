//! ARCH-01/ARCH-02/ARCH-08 ownership boundary checks.
//!
//! The suite validates dependency direction, storage-engine confinement,
//! single mempool mutation ownership, derived-index capability ownership,
//! peer registration/cancellation ownership, and the frozen P2P
//! forwarding-wrapper inventory.

#![expect(
    clippy::expect_used,
    reason = "cargo metadata subprocess, JSON parse, and file-read failures are unrecoverable in this gate"
)]

mod support;

use std::io::Write as _;
use std::path::Path;

use support::dependency_graph::{BIN_CRATE, Validation, WorkspaceGraph};
use support::ownership_scan::{OwnershipScanResult, scan_ownership_violations};

#[test]
fn real_metadata_validates() {
    let graph = WorkspaceGraph::from_cargo_metadata();
    let Validation {
        checked_edges,
        checked_engine_edges,
        checked_features,
        classified,
        summary,
    } = graph
        .validate()
        .expect("real workspace graph must be valid");

    let _ = writeln!(
        std::io::stderr(),
        "overhaul_ownership real metadata: {summary} | crates: {classified} | binary: {BIN_CRATE}"
    );

    assert!(checked_edges > 0, "no internal edges were checked");
    assert!(
        checked_engine_edges > 0,
        "engine-edge count must be reported"
    );
    assert!(
        checked_features > 0,
        "no feature forwarding assertions were checked"
    );
}

#[test]
fn synthetic_upward_dependency_fails() {
    let mut graph = WorkspaceGraph::from_cargo_metadata();
    graph.add_normal_dep("bitcoin-rs-primitives", "bitcoin-rs-mempool");

    let err = graph.validate().expect_err("upward edge must fail");
    assert!(
        err.iter().any(|line| {
            line.contains("dependency direction violation")
                && line.contains("bitcoin-rs-primitives")
                && line.contains("bitcoin-rs-mempool")
        }),
        "expected upward-dependency violation, got: {err:?}"
    );
}

#[test]
fn synthetic_storage_engine_leak_fails() {
    let mut graph = WorkspaceGraph::from_cargo_metadata();
    graph.add_engine_dep("bitcoin-rs-rpc", "fjall");

    let err = graph.validate().expect_err("rpc engine leak must fail");
    assert!(
        err.iter().any(|line| {
            line.contains("engine dependencies")
                && line.contains("bitcoin-rs-storage")
                && line.contains("bitcoin-rs-rpc")
        }),
        "expected engine-leak violation, got: {err:?}"
    );
}

#[test]
fn synthetic_empty_backend_marker_fails() {
    let mut graph = WorkspaceGraph::from_cargo_metadata();
    graph.set_feature("bitcoin-rs-chain", "rocksdb", &[]);

    let err = graph
        .validate()
        .expect_err("empty backend marker on an approved adapter must fail");
    assert!(
        err.iter().any(|line| {
            line.contains("empty backend marker")
                && line.contains("bitcoin-rs-chain")
                && line.contains("rocksdb")
        }),
        "expected empty-marker violation, got: {err:?}"
    );
}

#[test]
fn synthetic_unauthorized_backend_feature_fails() {
    let mut graph = WorkspaceGraph::from_cargo_metadata();
    graph.set_feature(
        "bitcoin-rs-mempool",
        "rocksdb",
        &["bitcoin-rs-storage/rocksdb"],
    );

    let err = graph
        .validate()
        .expect_err("a non-approved crate must not define a backend feature");
    assert!(
        err.iter().any(|line| {
            line.contains("must not define or forward the backend feature")
                && line.contains("bitcoin-rs-mempool")
                && line.contains("rocksdb")
        }),
        "expected unauthorized backend-feature violation, got: {err:?}"
    );
}

#[test]
fn synthetic_core_backend_feature_fails() {
    let mut graph = WorkspaceGraph::from_cargo_metadata();
    graph.set_feature("bitcoin-rs-script", "fjall", &["bitcoin-rs-storage/fjall"]);

    let err = graph
        .validate()
        .expect_err("a layer-0 crate defining a backend feature must fail");
    assert!(
        err.iter().any(|line| {
            line.contains("must not define or forward the backend feature")
                && line.contains("bitcoin-rs-script")
                && line.contains("fjall")
        }),
        "expected core backend-feature violation, got: {err:?}"
    );
}

#[test]
fn synthetic_backend_feature_mismatch_fails() {
    let mut graph = WorkspaceGraph::from_cargo_metadata();
    graph.set_feature("bitcoin-rs-node", "rocksdb", &["bitcoin-rs-chain/fjall"]);

    let err = graph
        .validate()
        .expect_err("mismatched backend feature forwarding must fail");
    assert!(
        err.iter().any(|line| {
            line.contains("without matching forwarding")
                && line.contains("bitcoin-rs-node")
                && line.contains("rocksdb")
        }),
        "expected backend-feature mismatch violation, got: {err:?}"
    );
}

#[test]
fn real_adapters_forward_their_backend_features() {
    let graph = WorkspaceGraph::from_cargo_metadata();
    graph
        .validate()
        .expect("real workspace feature tables must satisfy the forwarding rules");
}

#[test]
fn mempool_writer_source_scan_passes() {
    let OwnershipScanResult {
        mempool_writer_violations,
        files_scanned,
        pool_writes_found,
        mempool_mutations_found,
        ..
    } = scan_ownership_violations();

    let _ = writeln!(
        std::io::stderr(),
        "mempool writer scan: files={files_scanned}, \
         .pool().write()/.mempool().write()={pool_writes_found}, \
         mutating_calls={mempool_mutations_found}, \
         violations={}",
        mempool_writer_violations.len()
    );
    assert!(
        mempool_writer_violations.is_empty(),
        "non-owner production code must not call mutating mempool methods or \
         .pool().write(): {mempool_writer_violations:?}"
    );
}

#[test]
fn index_capability_scan_passes() {
    let OwnershipScanResult {
        index_capability_violations,
        index_capability_sites,
        files_scanned,
        ..
    } = scan_ownership_violations();

    let _ = writeln!(
        std::io::stderr(),
        "index capability scan: files={files_scanned}, \
         capability sites={index_capability_sites}, \
         violations={}",
        index_capability_violations.len()
    );
    assert!(
        index_capability_violations.is_empty(),
        "config-optional derived-index capability selection must stay with its \
         owners (crates/index, the node txindex runtime, and the node state \
         config projection): {index_capability_violations:?}"
    );
    assert!(
        index_capability_sites > 0,
        "the index capability scan matched no production capability selection"
    );
}

#[test]
fn p2p_peer_owner_scan_passes() {
    let OwnershipScanResult {
        peer_owner_violations,
        peer_mutations_found,
        files_scanned,
        ..
    } = scan_ownership_violations();

    let _ = writeln!(
        std::io::stderr(),
        "p2p peer owner scan: files={files_scanned}, \
         peer mutation sites={peer_mutations_found}, \
         violations={}",
        peer_owner_violations.len()
    );
    assert!(
        peer_owner_violations.is_empty(),
        "peer registration and cancellation must stay with the P2P owner \
         (PeerTable/P2pService) apart from the audited sync teardown handles \
         and the RPC disconnectnode operator path: {peer_owner_violations:?}"
    );
    assert!(
        peer_mutations_found > 0,
        "the p2p peer owner scan matched no production peer mutation"
    );
}

const KNOWN_P2P_FORWARDING_WRAPPERS: &[&str] = &[
    "peer_table",
    "banned_subnets",
    "network_active",
    "p2p_outbound_sender",
    "p2p_outbound_receiver",
    "inbound_blocks_rx_handle",
    "inbound_tx_rx_handle",
    "added_nodes",
];

#[test]
fn p2p_forwarding_wrapper_audit_is_frozen() {
    let found = scan_node_p2p_forwarding_wrappers();

    let _ = writeln!(
        std::io::stderr(),
        "forwarding-wrapper audit: found {} known wrappers",
        found.len()
    );
    for wrapper in &found {
        let _ = writeln!(std::io::stderr(), "  - {wrapper}");
    }

    let mut unexpected: Vec<_> = found
        .iter()
        .filter(|w| !KNOWN_P2P_FORWARDING_WRAPPERS.contains(&w.as_str()))
        .cloned()
        .collect();
    unexpected.sort();
    assert!(
        unexpected.is_empty(),
        "new NodeState forwarding wrappers must be collapsed or approved: {unexpected:?}"
    );

    let missing: Vec<_> = KNOWN_P2P_FORWARDING_WRAPPERS
        .iter()
        .filter(|w| !found.iter().any(|f| f.as_str() == **w))
        .copied()
        .collect();
    assert!(
        missing.is_empty(),
        "known forwarding wrappers disappeared without updating the audit: {missing:?}"
    );
}

#[expect(
    clippy::too_many_lines,
    reason = "the p2p forwarding-wrapper audit scans the entire `impl NodeState` block"
)]
fn scan_node_p2p_forwarding_wrappers() -> Vec<String> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("crates/node/src/state.rs");
    let content = std::fs::read_to_string(&path).unwrap_or_default();
    let lines: Vec<&str> = content.lines().collect();

    let mut wrappers = Vec::new();
    let mut current_method: Option<String> = None;
    let mut in_impl_node_state = false;
    let mut skip_rest = false;

    for (index, raw_line) in lines.iter().enumerate() {
        let line = if let Some(pos) = raw_line.find("//") {
            &raw_line[..pos]
        } else {
            raw_line
        };
        let trimmed = line.trim();
        let leading_spaces = raw_line.len() - raw_line.trim_start().len();

        if skip_rest {
            continue;
        }

        if trimmed.starts_with("#[cfg(test)]") {
            let mut is_test_module = false;
            for next in lines.iter().skip(index + 1) {
                let next_trimmed = next.trim();
                if next_trimmed.is_empty()
                    || next_trimmed.starts_with("//")
                    || next_trimmed.starts_with("#!")
                    || next_trimmed.starts_with("#[")
                {
                    continue;
                }
                if next_trimmed.starts_with("mod ") {
                    is_test_module = true;
                }
                break;
            }
            if is_test_module {
                skip_rest = true;
                continue;
            }
        } else if trimmed.starts_with("#[test]") {
            let mut is_test_fn = false;
            for next in lines.iter().skip(index + 1) {
                let next_trimmed = next.trim();
                if next_trimmed.is_empty()
                    || next_trimmed.starts_with("//")
                    || next_trimmed.starts_with("#!")
                    || next_trimmed.starts_with("#[")
                {
                    continue;
                }
                if next_trimmed.starts_with("fn ") {
                    is_test_fn = true;
                }
                break;
            }
            if is_test_fn {
                skip_rest = true;
                continue;
            }
        }

        if in_impl_node_state
            && leading_spaces == 0
            && (trimmed.starts_with("impl ") || trimmed.starts_with('}'))
        {
            in_impl_node_state = false;
            current_method = None;
        }
        if trimmed.starts_with("impl NodeState {") || trimmed == "impl NodeState" {
            in_impl_node_state = true;
            current_method = None;
            continue;
        }
        if !in_impl_node_state {
            continue;
        }

        if trimmed.starts_with("pub fn ") || trimmed.starts_with("pub(crate) fn ") {
            if let Some(name) = trimmed.split("fn ").nth(1) {
                current_method = name.split('(').next().map(|s| s.trim().to_owned());
                if matches!(current_method.as_deref(), Some("open" | "new")) {
                    current_method = None;
                }
            }
        }

        let p2p_field = line.contains("p2p_outbound_tx")
            || line.contains("p2p_outbound_rx")
            || line.contains("inbound_blocks_rx")
            || line.contains("inbound_tx_rx")
            || line.contains("&self.network_active")
            || line.contains("&self.banned")
            || line.contains("&self.peer_table");
        let p2p_call = line.contains("self.p2p.added_nodes_handle()")
            || line.contains("self.p2p.outbound_sender()")
            || line.contains("self.p2p.banned_handle()")
            || line.contains("self.p2p.network_active_handle()")
            || line.contains("self.p2p.table()")
            || line.contains("self.p2p.outbound_receiver()")
            || line.contains("self.p2p.inbound_blocks_rx()")
            || line.contains("self.p2p.inbound_tx_rx()");

        if (p2p_field || p2p_call)
            && let Some(method) = current_method.as_ref()
            && !wrappers.contains(method)
        {
            wrappers.push(method.clone());
        }
    }

    wrappers.sort();
    wrappers
}
