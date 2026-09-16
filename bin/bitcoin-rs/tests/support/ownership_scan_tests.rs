//! Unit tests for the ownership scan's lexical masking and audit matching.
//!
//! Included only by the `support_unit_tests` target so each assertion runs
//! once per profile instead of once per embedding binary (issue #1083).

use std::collections::BTreeSet;
use std::path::Path;

use crate::support::ownership_scan::{
    LexState, cfg_test_module_stems_from, code_line, empty_result, is_authorized_gateway_call,
    is_test_module_file, scan_source,
};

const MINING_HANDLER: &str = "/workspace/crates/rpc/src/handlers/mining.rs";
const NON_OWNER: &str = "/workspace/crates/node/src/fake.rs";

fn authorized(path: &str, source: &str) -> bool {
    let raw: Vec<&str> = source.lines().collect();
    let mut lex = LexState::default();
    let lines: Vec<String> = raw.iter().map(|line| code_line(line, &mut lex)).collect();
    let (line_index, line) = lines
        .iter()
        .enumerate()
        .find(|(_, line)| line.contains("prioritise("))
        .expect("fixture contains prioritise call");
    let method_pos = line.find("prioritise(").expect("method position");
    is_authorized_gateway_call(path, line, method_pos, &lines, line_index)
}

fn violations(source: &str) -> Vec<String> {
    let mut result = empty_result();
    scan_source(NON_OWNER, source, &mut result);
    result.mempool_writer_violations
}

#[test]
fn cfg_test_stems_cover_external_module_declarations_only() {
    let stems = cfg_test_module_stems_from([
        "#[cfg(test)]\nmod tests;\n".to_owned(),
        "#[cfg(all(test, feature = \"fjall\"))]\nmod body_reader_tests;\n".to_owned(),
        "#[cfg(test)] mod tests;\n".to_owned(),
        "#[cfg(test)]\n\n// leading comment\n#[expect(unused)]\nmod helpers;\n".to_owned(),
        "#[cfg(test)]\npub(crate) mod testing;\n".to_owned(),
        "#[cfg(test)]\npub mod published;\n".to_owned(),
    ]);
    let expected: BTreeSet<String> = [
        "body_reader_tests",
        "helpers",
        "published",
        "testing",
        "tests",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    assert_eq!(stems, expected);

    let not_stems = cfg_test_module_stems_from([
        "#[cfg(not(test))]\nmod production;\n".to_owned(),
        "#[cfg(test)]\nmod inline {\n    fn helper() {}\n}\n".to_owned(),
        "#[cfg(test)]\nfn a_test_helper() {}\n".to_owned(),
        "mod plainly_gated;\n".to_owned(),
    ]);
    assert!(not_stems.is_empty(), "{not_stems:?}");
}

#[test]
fn a_test_module_file_is_skipped_by_its_stem() {
    let stems = cfg_test_module_stems_from(["#[cfg(test)]\nmod tests;\n".to_owned()]);
    assert!(is_test_module_file(
        Path::new("/workspace/crates/node/src/sync/tests.rs"),
        &stems
    ));
    assert!(!is_test_module_file(
        Path::new("/workspace/crates/node/src/sync/peers.rs"),
        &stems
    ));
    assert!(!is_test_module_file(
        Path::new("/workspace/crates/node/src/lib.rs"),
        &stems
    ));
}

#[test]
fn only_derived_index_owners_select_capabilities() {
    for (path, source) in [
        (
            "/workspace/crates/node/src/state/index.rs",
            "bitcoin_rs_index::IndexCapabilities {\n    tx_lookup: config.indexes.txindex,\n}",
        ),
        (
            "/workspace/crates/node/src/state/open.rs",
            "let indexed = !derived_index_capabilities(&config).is_empty();",
        ),
        (
            "/workspace/crates/index/src/runtime/query.rs",
            "self.with_snapshot(IndexCapabilities::TX_LOOKUP, |snapshot, tip, budget| {})",
        ),
        (
            "/workspace/crates/index/src/write.rs",
            "writer.reset_capabilities(IndexCapabilities::SCRIPT_LIVE)?;",
        ),
    ] {
        let mut result = empty_result();
        scan_source(path, source, &mut result);
        assert!(
            result.index_capability_violations.is_empty(),
            "{path}: {:?}",
            result.index_capability_violations
        );
        assert_eq!(result.index_capability_sites, 1, "{path}");
    }
}

/// Forcing capability selection in a compose or apply path is exactly
/// the config-optional index becoming required.
#[test]
fn capability_forcing_outside_the_owners_is_flagged() {
    for (path, source) in [
        (
            "/workspace/crates/node/src/apply/connect.rs",
            "let caps = IndexCapabilities::ALL;",
        ),
        (
            "/workspace/crates/node/src/startup.rs",
            "let spec = build_derived_index_open_spec(&config, 0, 1)?.unwrap();",
        ),
        (
            "/workspace/crates/rpc/src/handlers/chain.rs",
            "IndexCapabilities::TX_LOOKUP",
        ),
    ] {
        let mut result = empty_result();
        scan_source(path, source, &mut result);
        assert_eq!(
            result.index_capability_violations.len(),
            1,
            "{path}: {:?}",
            result.index_capability_violations
        );
    }
}

#[test]
fn capability_type_mentions_and_text_do_not_force_anything() {
    for source in [
        "fn f(capabilities: IndexCapabilities) {}",
        "use bitcoin_rs_index::IndexCapabilities;",
        "const T: &str = \"IndexCapabilities::ALL\";",
        "// IndexCapabilities::ALL in a comment",
    ] {
        let mut result = empty_result();
        scan_source(NON_OWNER, source, &mut result);
        assert!(result.index_capability_violations.is_empty(), "{source}");
        assert_eq!(result.index_capability_sites, 0, "{source}");
    }
}

#[test]
fn only_the_p2p_owner_and_audited_handles_mutate_peers() {
    for (path, call, expected_violations) in [
        (
            "/workspace/crates/p2p/src/peer_table.rs",
            "table.register(addr, lease.clone());",
            0,
        ),
        (
            "/workspace/crates/p2p/src/connection.rs",
            "self.table.cancel_all();",
            0,
        ),
        (
            "/workspace/crates/node/src/sync/headers.rs",
            "self.peer_table.disconnect_source(source)",
            0,
        ),
        (
            "/workspace/crates/node/src/sync/headers.rs",
            "if self.peer_table.disconnect_source(source) {",
            0,
        ),
        (
            "/workspace/crates/node/src/sync/headers.rs",
            "xself.peer_table.disconnect_source(source)",
            1,
        ),
        (
            "/workspace/crates/node/src/sync/peers.rs",
            "if !self\n    .peer_table\n    .disconnect_connection(peer_addr, connection_id)\n{\n}",
            0,
        ),
        (
            "/workspace/crates/rpc/src/handlers/network.rs",
            "ctx.peer_table.disconnect(addr);",
            0,
        ),
        (
            "/workspace/crates/node/src/fake.rs",
            "self.peer_table.disconnect_source(source)",
            1,
        ),
        (
            "/workspace/crates/node/src/sync/headers.rs",
            "other.peer_table.disconnect_source(source)",
            1,
        ),
        (
            "/workspace/crates/rpc/src/handlers/mining.rs",
            "ctx.peer_table.register(addr, lease.clone());",
            1,
        ),
        (
            "/workspace/crates/rpc/src/handlers/network.rs",
            "ctx.peer_table.register(addr, lease.clone());",
            1,
        ),
        (
            "/workspace/crates/node/src/fake.rs",
            "ctx.peer_table.disconnect(addr);",
            1,
        ),
    ] {
        let mut result = empty_result();
        scan_source(path, call, &mut result);
        assert_eq!(
            result.peer_owner_violations.len(),
            expected_violations,
            "{path}: {call}"
        );
    }
}

#[test]
fn peer_scan_excludes_other_disconnects_and_masked_text() {
    // `ChainTransition::disconnect` shares the bare name and must stay
    // outside the peer scan entirely.
    let mut result = empty_result();
    scan_source(
        "/workspace/crates/node/src/apply/entrypoints.rs",
        "let result = transition.disconnect(block);",
        &mut result,
    );
    assert!(result.peer_owner_violations.is_empty());
    assert_eq!(result.peer_mutations_found, 0);

    // Text that only looks like a mutator is masked out.
    let mut result = empty_result();
    scan_source(
        NON_OWNER,
        "const T: &str = \"peer_table.register(addr)\";",
        &mut result,
    );
    assert!(result.peer_owner_violations.is_empty());
    assert_eq!(result.peer_mutations_found, 0);
}
#[test]
fn chainstate_transition_promotion_stays_in_node() {
    const NODE_APPLY: &str = "/workspace/crates/node/src/apply.rs";
    const RPC_HANDLER: &str = "/workspace/crates/rpc/src/handlers/network.rs";

    let mut result = empty_result();
    scan_source(
        NODE_APPLY,
        "let lock = self.lock_transition()?;",
        &mut result,
    );
    assert!(result.transition_owner_violations.is_empty());
    assert_eq!(result.transition_sites, 1);

    let mut result = empty_result();
    scan_source(
        NODE_APPLY,
        "let transition = self.begin_transition_locked(lock)?;",
        &mut result,
    );
    assert!(result.transition_owner_violations.is_empty());
    assert_eq!(result.transition_sites, 1);

    let mut result = empty_result();
    scan_source(
        RPC_HANDLER,
        "let lock = handles.lock_transition()?;",
        &mut result,
    );
    assert_eq!(result.transition_owner_violations.len(), 1);
    assert_eq!(result.transition_sites, 1);

    let mut result = empty_result();
    scan_source(
        RPC_HANDLER,
        "let transition = handles.begin_transition_locked(lock)?;",
        &mut result,
    );
    assert_eq!(result.transition_owner_violations.len(), 1);
    assert_eq!(result.transition_sites, 1);
}

/// POL-06: the dynamic `mempoolminfee` heuristic has one owner. The
/// audited RPC outlet may call it; the mempool owner legitimately
/// derives and enforces it; any other quoting surface is flagged, and
/// any non-owner reading the pool's lowest fee rate is re-deriving the
/// heuristic and flagged even without calling the owner function.
#[test]
fn pressure_floor_quotation_and_derivation_stay_with_the_owner() {
    const MEMPOOL_OWNER: &str = "/workspace/crates/mempool/src/gateway.rs";
    const RPC_OUTLET: &str = "/workspace/crates/rpc/src/handlers/mempool.rs";
    const NON_OWNER: &str = "/workspace/crates/rpc/src/handlers/network.rs";

    let mut result = empty_result();
    scan_source(
        MEMPOOL_OWNER,
        "let floor = crate::eviction::mempool_min_fee_sat_per_kvb(pool, 1_000);",
        &mut result,
    );
    assert!(result.pressure_floor_owner_violations.is_empty());
    assert_eq!(result.pressure_floor_sites, 1);

    let mut result = empty_result();
    scan_source(
        RPC_OUTLET,
        "let floor = eviction::mempool_min_fee_sat_per_kvb(&pool, 1_000);",
        &mut result,
    );
    assert!(result.pressure_floor_owner_violations.is_empty());
    assert_eq!(result.pressure_floor_sites, 1);

    let mut result = empty_result();
    scan_source(
        NON_OWNER,
        "let floor = mempool::eviction::mempool_min_fee_sat_per_kvb(&pool, 1_000);",
        &mut result,
    );
    assert_eq!(result.pressure_floor_owner_violations.len(), 1);

    let mut result = empty_result();
    scan_source(
        NON_OWNER,
        "let lowest = pool.lowest_fee_rate();",
        &mut result,
    );
    assert_eq!(result.pressure_floor_owner_violations.len(), 1);
    assert_eq!(result.pressure_floor_sites, 1);

    let mut result = empty_result();
    scan_source(
        MEMPOOL_OWNER,
        "let lowest = pool.lowest_fee_rate();",
        &mut result,
    );
    assert!(result.pressure_floor_owner_violations.is_empty());
    assert_eq!(result.pressure_floor_sites, 1);
}

/// The audited outlet is path-pinned, so a lookalike path or a new
/// outlet without an audit is a violation, not a silent pass.
#[test]
fn floor_outlet_audit_covers_only_the_audited_handler_path() {
    let mut result = empty_result();
    scan_source(
        "/workspace/crates/rpc/src/handlers/mempoolish.rs",
        "let floor = mempool_min_fee_sat_per_kvb(&pool, 1_000);",
        &mut result,
    );
    assert_eq!(result.pressure_floor_owner_violations.len(), 1);

    let mut result = empty_result();
    scan_source(
        "/workspace/crates/rpc/src/handlers/chain.rs",
        "let floor = mempool_min_fee_sat_per_kvb(&pool, 1_000);",
        &mut result,
    );
    assert_eq!(result.pressure_floor_owner_violations.len(), 1);
}

#[test]
fn only_the_audited_qualified_gateway_receiver_is_authorized() {
    assert!(authorized(
        MINING_HANDLER,
        "ctx.mempool\n    .prioritise(txid, fee_delta)"
    ));
    assert!(authorized(
        MINING_HANDLER,
        "ctx.mempool.prioritise(txid, fee_delta)"
    ));

    for source in [
        "gateway.prioritise(txid, fee_delta)",
        "mempool.prioritise(txid, fee_delta)",
        "other.mempool.prioritise(txid, fee_delta)",
        "ctx.mempool_gateway.prioritise(txid, fee_delta)",
    ] {
        assert!(!authorized(MINING_HANDLER, source), "{source}");
    }
    for path in [
        "/workspace/crates/node/src/apply.rs",
        "/workspace/fakecrates/rpc/src/handlers/mining.rs",
    ] {
        assert!(!authorized(
            path,
            "ctx.mempool\n    .prioritise(txid, fee_delta)"
        ));
    }
}

/// ARCH-07 permits this gateway call, not a second mempool mutation owner.
#[test]
fn node_connection_authorizes_only_its_typed_gateway_receiver() {
    let owner = "/workspace/crates/node/src/apply/connect.rs";
    for (path, call, expected_violations) in [
        (
            owner,
            "handles.mempool_gateway.remove_for_block(origin, txs, txids, height);",
            0,
        ),
        (
            "crates/node/src/reorg/execution.rs",
            "handles.mempool_gateway.reconsider_disconnected(AdmissionOrigin::Reorg, candidates.into_entries());",
            0,
        ),
        (
            NON_OWNER,
            "handles.mempool_gateway.reconsider_disconnected(AdmissionOrigin::Reorg, candidates.into_entries());",
            1,
        ),
        (
            "crates/node/src/reorg/execution.rs",
            "let _ = handles\n    .mempool_gateway\n    .reconsider_disconnected(origin, candidates);",
            0,
        ),
        (
            NON_OWNER,
            "let _ = handles\n    .mempool_gateway\n    .reconsider_disconnected(origin, candidates);",
            1,
        ),
        (
            "crates/node/src/reorg/execution.rs",
            "let _ = other\n    .mempool_gateway\n    .reconsider_disconnected(origin, candidates);",
            1,
        ),
        (
            "crates/node/src/reorg/execution.rs",
            "other.handles\n    .mempool_gateway\n    .reconsider_disconnected(origin, candidates);",
            1,
        ),
        (
            "crates/node/src/reorg/execution.rs",
            "other\u{301}handles.mempool_gateway.reconsider_disconnected(origin, candidates);",
            1,
        ),
        (
            "crates/node/src/reorg/execution.rs",
            "handles.mempool_gateway.write()\n    .reconsider_disconnected(origin, candidates);",
            1,
        ),
        (
            "crates/node/src/reorg/execution.rs",
            "other.mempool_gateway /* handles.mempool_gateway */\n    .reconsider_disconnected(origin, candidates);",
            1,
        ),
        (
            NON_OWNER,
            "handles.mempool_gateway.remove_for_block(origin, txs, txids, height);",
            1,
        ),
        (
            owner,
            "handles.mempool.remove_for_block(origin, txs, txids, height);",
            1,
        ),
        (
            owner,
            "handles.mempool_gateway.write().remove_for_block(origin, txs, txids, height);",
            1,
        ),
    ] {
        let mut result = empty_result();
        scan_source(path, call, &mut result);
        assert_eq!(
            result.mempool_writer_violations.len(),
            expected_violations,
            "{path}: {call}"
        );
        assert_eq!(result.mempool_mutations_found, 1);
    }
}

#[test]
fn only_the_current_connect_gateway_path_is_authorized() {
    for (path, receiver, permitted) in [
        (
            "/workspace/crates/node/src/apply/connect.rs",
            "handles.mempool_gateway",
            true,
        ),
        (
            "/workspace/crates/node/src/apply.rs",
            "handles.mempool_gateway",
            false,
        ),
        (
            "/workspace/crates/node/src/apply/connect.rs",
            "handles.mempool",
            false,
        ),
        (
            "/workspace/crates/node/src/apply/connect.rs",
            "handles.mempool_gateway.pool().write()",
            false,
        ),
    ] {
        let mut result = empty_result();
        scan_source(
            path,
            &format!("{receiver}.remove_for_block(block_txs, block_txids, height);"),
            &mut result,
        );
        assert_eq!(
            result.mempool_writer_violations.is_empty(),
            permitted,
            "{path}: {receiver}"
        );
    }
}

#[test]
fn multiline_receiver_chain_resolves_to_its_root() {
    let owner = "/workspace/crates/node/src/reorg/execution.rs";
    for (path, call, expected_violations) in [
        (
            owner,
            "let _ = handles\n.mempool_gateway\n.reconsider_disconnected(origin, entries);",
            0,
        ),
        (
            owner,
            "let _ = other\n.mempool_gateway\n.reconsider_disconnected(origin, entries);",
            1,
        ),
        (
            NON_OWNER,
            "let _ = handles\n.mempool_gateway\n.reconsider_disconnected(origin, entries);",
            1,
        ),
    ] {
        let mut result = empty_result();
        scan_source(path, call, &mut result);
        assert_eq!(
            result.mempool_writer_violations.len(),
            expected_violations,
            "{path}: {call}"
        );
        assert_eq!(result.mempool_mutations_found, 1);
    }
}

#[test]
fn a_raw_write_chain_is_never_authorized() {
    assert!(!authorized(
        MINING_HANDLER,
        "ctx.mempool.write().prioritise(txid, fee_delta)"
    ));
}

#[test]
fn strings_and_comments_do_not_create_mutation_matches() {
    let source = r##"
const TEXT: &str = "gateway.prioritise(txid, 1) // not code";
const RAW: &str = r#"mempool.prioritise(txid, 2)"#;
/* pool.prioritise(txid, 3); */
// gateway.prioritise(txid, 4);
pub fn production() {}
"##;
    assert!(violations(source).is_empty());
}

#[test]
fn string_continuation_does_not_hide_following_production() {
    let source = r#"
const TEXT: &str = "continued\
";
pub fn production() {
gateway.prioritise(txid, 9);
}
"#;
    let found = violations(source);
    assert_eq!(found.len(), 1);
    assert!(found[0].contains("gateway.prioritise(txid, 9)"));
}

#[test]
fn production_after_an_inline_test_module_is_still_scanned() {
    let source = r##"
#[cfg(test)]
mod tests {
#[test]
fn fixture() {
    let _ = r#"
}
gateway.prioritise(txid, 1)
"#;
    gateway.prioritise(txid, 2);
}
} // trailing comment must not hide production below

pub fn production() {
gateway.prioritise(txid, 3);
}
"##;
    let found = violations(source);
    assert_eq!(found.len(), 1, "only production mutation is scanned");
    assert!(found[0].contains("gateway.prioritise(txid, 3)"));
}

#[test]
fn cfg_test_helper_and_visibility_qualified_test_are_skipped_only_to_their_end() {
    let source = r"
#[cfg(test)]
pub fn helper() {
gateway.prioritise(txid, 1);
}

#[test]
pub fn fixture() {
mempool.prioritise(txid, 2);
}

pub fn production() {
mempool.prioritise(txid, 3);
}
";
    let found = violations(source);
    assert_eq!(found.len(), 1);
    assert!(found[0].contains("mempool.prioritise(txid, 3)"));
}

#[test]
fn external_test_module_declaration_does_not_hide_following_production() {
    let source = r"
#[cfg(test)]
mod tests;

pub fn production() {
gateway.prioritise(txid, 3);
}
";
    let found = violations(source);
    assert_eq!(found.len(), 1);
    assert!(found[0].contains("gateway.prioritise(txid, 3)"));
}
