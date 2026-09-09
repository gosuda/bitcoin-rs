//! CONTRACT: docs/contracts/architecture.md#ARCH-01, #ARCH-02 and #ARCH-08.
//!
//! T03 — Enforce owner boundaries before moving code.
//!
//! This test validates:
//!
//! 1. The five-layer one-way dependency direction on real `cargo metadata`.
//! 2. Synthetic upward dependency edges fail the gate.
//! 3. Synthetic storage-engine leaks outside `bitcoin-rs-storage` fail the gate.
//! 4. No production code outside `crates/mempool/src/` calls a mutating
//!    `Mempool` method or acquires the pool write lock.
//! 5. Known `NodeState` forwarding wrappers around `P2pService` handles are
//!    exactly the set approved for T24/T28 collapse; any new wrapper fails.

#![expect(
    clippy::expect_used,
    reason = "cargo metadata subprocess, JSON parse, and file-read failures are unrecoverable in this gate"
)]

mod support;

use std::io::Write as _;
use std::path::Path;

use support::dependency_graph::{BIN_CRATE, Validation, WorkspaceGraph};
use support::ownership_scan::{WriterScanResult, scan_mempool_writer_violations};

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
        classified >= 12,
        "workspace crates went missing from metadata: {classified} classified"
    );
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
fn mempool_writer_source_scan_passes() {
    let WriterScanResult {
        violations,
        files_scanned,
        pool_writes_found,
        mutating_calls_found,
    } = scan_mempool_writer_violations();

    let _ = writeln!(
        std::io::stderr(),
        "mempool writer scan: files={files_scanned}, \
         .pool().write()/.mempool().write()={pool_writes_found}, \
         mutating_calls={mutating_calls_found}, \
         violations={}",
        violations.len()
    );
    assert!(
        files_scanned > 50,
        "source scan must examine a meaningful number of files; got {files_scanned}"
    );
    assert!(
        violations.is_empty(),
        "non-owner production code must not call mutating mempool methods or \
         .pool().write(): {violations:?}"
    );
}

/// Known forwarding wrappers in `NodeState` that clone or delegate to
/// `P2pService` handles. They are approved boundaries for T24/T28 because
/// collapsing them requires migrating P2P callers across the node and RPC
/// surface.
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

    // Every known wrapper must still exist in the source; if one was collapsed
    // without removing it from this list, the list has drifted.
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

        // `#[cfg(test)]` stops scanning only when it introduces a test *module*.
        // `#[test]` introduces a unit-test function and stops scanning from that
        // point onward. Intervening attributes like `#[allow(...)]` are skipped.
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

        // Scope to `impl NodeState {`. Leave when another `impl` starts, or a
        // `}` at the same indentation as the `impl` closes it.
        if in_impl_node_state {
            if leading_spaces == 0 && (trimmed.starts_with("impl ") || trimmed.starts_with('}')) {
                in_impl_node_state = false;
                current_method = None;
            }
        }
        if trimmed.starts_with("impl NodeState {") || trimmed == "impl NodeState" {
            in_impl_node_state = true;
            current_method = None;
            continue;
        }
        if !in_impl_node_state {
            continue;
        }

        // Very coarse method-boundary detection: a `pub fn` at the top level
        // of the `impl NodeState` block.
        if trimmed.starts_with("pub fn ") || trimmed.starts_with("pub(crate) fn ") {
            if let Some(name) = trimmed.split("fn ").nth(1) {
                current_method = name.split('(').next().map(|s| s.trim().to_owned());
                // `open` is the node constructor; `new` is not in `impl NodeState`
                // but guard both so the audit stays robust if the impl is reorganized.
                if current_method.as_deref() == Some("open")
                    || current_method.as_deref() == Some("new")
                {
                    current_method = None;
                }
            }
        }

        // Detect the wrapper pattern: the method body reaches into a P2P-owned
        // field or calls a `P2pService` handle accessor.
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

        if p2p_field || p2p_call {
            if let Some(method) = current_method.as_ref() {
                if !wrappers.contains(method) {
                    wrappers.push(method.clone());
                }
            }
        }
    }

    wrappers.sort();
    wrappers
}
