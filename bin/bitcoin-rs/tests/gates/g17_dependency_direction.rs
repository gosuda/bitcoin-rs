#[path = "../support/dependency_graph.rs"]
mod dependency_graph;

#[path = "../support/capability_compile.rs"]
mod capability_compile;
use crate::support::TestError;
use dependency_graph::WorkspaceGraph;

const READ_CONTROL: &str = r"
use std::sync::Arc;
use bitcoin_rs_execution::chain::{BlockTreeReader, TipReader, TipSnapshot};
use bitcoin_rs_execution::{Chainstate, ChainstateSnapshot};
use bitcoin_rs_node::p2p::sync::SyncChain;
use bitcoin_rs_node::p2p::sync::chain::{ReorgError, HistoricalAdvance, WindowApplyDisposition};

pub fn sync_outcomes(
    branch: bitcoin_rs_execution::reorg::ReorgError,
    historical: bitcoin_rs_execution::assumeutxo::HistoricalAdvance,
    disposition: bitcoin_rs_execution::WindowApplyDisposition,
) -> (ReorgError, HistoricalAdvance, WindowApplyDisposition) {
    (branch, historical, disposition)
}

pub fn observe(state: &Chainstate) -> (Option<Arc<TipSnapshot>>, usize) {
    let header: TipReader = state.header_tip_reader();
    let applied: TipReader = state.applied_tip_reader();
    let tree: BlockTreeReader = state.block_tree_reader();
    let _: Option<Arc<TipSnapshot>> = header.clone().load_full();
    let _: Option<Arc<TipSnapshot>> = state.header_tip();
    let _: Option<Arc<TipSnapshot>> = state.applied_tip_snapshot();
    let _: ChainstateSnapshot = state.snapshot();
    let _ = state.chain_snapshot();
    let _ = tree.read().tip();
    let _ = state.utxo_reader();
    (applied.load_full(), tree.clone().read().len())
}

pub fn observe_undo(state: &Chainstate) {
    if let Some(tip) = state.applied_tip_snapshot() {
        let reader: &dyn bitcoin_rs_storage::utxo::contract::BlockUndoSource = state;
        let _ = reader.block_spends(tip.hash, tip.hash);
    }
}

pub fn observe_sync(chain: &dyn SyncChain) -> Option<Arc<TipSnapshot>> {
    let _ = chain.block_tree().tip();
    let _ = chain.chain_tip();
    chain.applied_tip()
}
";

// ARCH-01, ARCH-02, ARCH-04, FEAT-02, MOD-03, MOD-05
#[test]
fn workspace_dependency_direction_is_one_way() {
    let graph = WorkspaceGraph::from_cargo_metadata();
    assert!(
        graph.classified >= 12,
        "workspace crates went missing from metadata: {} classified",
        graph.classified
    );
    match graph.validate() {
        Ok(report) => {
            assert!(
                report.checked_edges > 0 && report.checked_features > 0,
                "validator checked nothing: {}",
                report.summary
            );
            assert!(
                report.cycle_checked_crates >= 12,
                "cycle check did not run: {}",
                report.summary
            );
        }
        Err(violations) => {
            panic!(
                "dependency direction violations:\n{}",
                violations.join("\n")
            );
        }
    }
}

// EMB-03
#[test]
fn node_composition_root_is_not_a_production_embedding_api() -> Result<(), TestError> {
    let manifest = dependency_graph::workspace_root_manifest();
    let root = manifest
        .parent()
        .ok_or(TestError::Missing("workspace root"))?
        .canonicalize()?;
    let consumer = capability_compile::ProductionConsumer::with_node(&root)?;
    let control = r"
use bitcoin_rs_node::Node;
pub fn observe(node: &Node) {
    let _ = node.snapshot();
    let _ = node.sync_progress();
    let _ = node.mempool_info();
}
";
    consumer.allow_reads(control)?;
    consumer.deny(
        &format!("{control}\nuse bitcoin_rs_node::state::NodeState;"),
        &["E0603"],
        "state",
    )?;
    consumer.deny(
        &format!("{control}\nuse bitcoin_rs_node::tx_ingress::spawn_tx_ingress_consumer;"),
        &["E0603"],
        "tx_ingress",
    )?;
    Ok(())
}
#[test]
fn fixture_owners_expose_no_production_injection_or_synthetic_constructors() -> Result<(), TestError>
{
    let manifest = dependency_graph::workspace_root_manifest();
    let root = manifest
        .parent()
        .ok_or(TestError::Missing("workspace root"))?
        .canonicalize()?;
    let consumer = capability_compile::ProductionConsumer::with_fixture_owners(&root)?;
    consumer.allow_reads(&format!(
        "{READ_CONTROL}\npub fn compose(handles: bitcoin_rs_serving::context::ContextHandles) -> bitcoin_rs_serving::context::Context {{ bitcoin_rs_serving::context::Context::from_handles(handles) }}"
    ))?;
    for (source, codes, member) in [
        (
            "use bitcoin_rs_storage::PersistFault;",
            &["E0432"][..],
            "PersistFault",
        ),
        (
            "use bitcoin_rs_storage::checkpoint::CheckpointFailpoint;",
            &["E0432"][..],
            "CheckpointFailpoint",
        ),
        (
            "use bitcoin_rs_storage::footprint;",
            &["E0432"][..],
            "footprint",
        ),
        (
            "pub fn denied(store: &dyn bitcoin_rs_storage::KvStore) { let _ = store.arm_persist_fault; }",
            &["E0609", "E0599"][..],
            "arm_persist_fault",
        ),
        (
            "pub fn denied() { let _ = bitcoin_rs_execution::Chainstate::new; }",
            &["E0599"][..],
            "new",
        ),
        (
            "pub fn denied() { let _ = bitcoin_rs_serving::context::Context::new; }",
            &["E0599"][..],
            "new",
        ),
        (
            "pub fn denied() { let _ = bitcoin_rs_serving::context::ContextHandles::default; }",
            &["E0599"][..],
            "default",
        ),
    ] {
        consumer.deny(source, codes, member)?;
    }
    Ok(())
}

#[test]
fn chainstate_facade_exposes_no_production_raw_mutation_handles() -> Result<(), TestError> {
    let manifest = dependency_graph::workspace_root_manifest();
    let root = manifest
        .parent()
        .ok_or(TestError::Missing("workspace root"))?
        .canonicalize()?;
    let consumer = capability_compile::ProductionConsumer::new(&root)?;
    consumer.allow_reads(READ_CONTROL)?;

    for (receiver, statement, member) in [
        ("tip: &TipReader", "tip.store(None)", "store"),
        ("tree: &BlockTreeReader", "tree.write()", "write"),
    ] {
        consumer.deny(
            &format!("{READ_CONTROL}\npub fn denied({receiver}) {{ let _ = {statement}; }}"),
            &["E0599"],
            member,
        )?;
    }
    consumer.deny(
        &format!("{READ_CONTROL}\npub fn denied(reader: &dyn bitcoin_rs_storage::utxo::contract::BlockUndoSource, state: &Chainstate) {{ if let Some(tip) = state.applied_tip_snapshot() {{ let _ = reader.persist_undo(tip.height, tip.hash, b\"\"); }} }}"),
        &["E0599"],
        "persist_undo",
    )?;
    for (receiver, member) in [
        ("tip: &TipReader", "tip.inner"),
        ("tree: &BlockTreeReader", "tree.inner"),
        ("state: &Chainstate", "state.chain_tip"),
        ("state: &Chainstate", "state.applied_tip"),
        ("state: &Chainstate", "state.block_tree"),
        ("state: &Chainstate", "state.chain_transition"),
        ("state: &Chainstate", "state.undo_store"),
        ("state: &Chainstate", "state.history"),
    ] {
        let field = member.rsplit('.').next().unwrap_or(member);
        consumer.deny(
            &format!("{READ_CONTROL}\npub fn denied({receiver}) {{ let _ = &{member}; }}"),
            &["E0616", "E0609"],
            field,
        )?;
    }
    consumer.deny(
        &format!(
            "{READ_CONTROL}\n\
             pub fn denied(tree: &BlockTreeReader) {{\n\
                 let mut guard = tree.read();\n\
                 guard.tip_handle().store(None);\n\
             }}"
        ),
        &["E0596"],
        "tip_handle",
    )?;

    for method in [
        "chain_tip",
        "applied_tip",
        "chain_tip_handle",
        "applied_tip_handle",
        "block_tree",
        "block_tree_handle",
        "read_block_tree",
        "transition_barrier",
        "retention_handle",
        "read_fence",
        "utxo",
        "utxo_handle",
        "coins",
        "commit_authority",
        "coin_store",
        "coin_store_handle",
        "apply_block",
        "apply_block_with_serialized",
        "disconnect_block",
        "apply_window",
    ] {
        consumer.deny(
            &format!("{READ_CONTROL}\npub fn denied() {{ let _ = Chainstate::{method}; }}"),
            &["E0599"],
            method,
        )?;
    }
    consumer.deny(
        &format!(
            "{READ_CONTROL}\npub fn denied(reader: &bitcoin_rs_storage::utxo::UtxoReader) {{ let _ = reader.fixture_set(); }}"
        ),
        &["E0599"],
        "fixture_set",
    )?;
    Ok(())
}

// ARCH-07a
#[test]
fn utxo_queries_expose_no_production_mutation_capability() -> Result<(), TestError> {
    let manifest = dependency_graph::workspace_root_manifest();
    let root = manifest
        .parent()
        .ok_or(TestError::Missing("workspace root"))?
        .canonicalize()?;
    let consumer = capability_compile::ProductionConsumer::new(&root)?;
    let control = r"
use bitcoin_rs_storage::utxo::{UtxoReader, UtxoSetView};
pub fn observe(reader: &UtxoReader, view: &UtxoSetView<'_>) {
    let _ = reader.with_stable_view(|view| view.len());
    let _ = reader.scan_coin_snapshot();
    let _ = reader.confirmation_height(&Default::default(), u32::MAX);
    let _ = view.record_count();
}
";
    consumer.allow_reads(control)?;
    for (receiver, method) in [
        ("reader: &UtxoReader", "coin_store"),
        ("reader: &UtxoReader", "set"),
        ("reader: &UtxoReader", "fixture_set"),
        ("reader: &UtxoReader", "fixture_coin_store"),
        ("view: &UtxoSetView<'_>", "coin_store"),
        ("view: &UtxoSetView<'_>", "set"),
        ("view: &UtxoSetView<'_>", "store"),
    ] {
        let variable = receiver.split(':').next().unwrap_or("reader");
        consumer.deny(
            &format!("{control}\npub fn denied({receiver}) {{ let _ = {variable}.{method}(); }}"),
            &["E0599"],
            method,
        )?;
    }
    for (receiver, field) in [
        ("reader: &UtxoReader", "coin_store"),
        ("reader: &UtxoReader", "set"),
        ("view: &UtxoSetView<'_>", "set"),
        ("view: &UtxoSetView<'_>", "backing"),
    ] {
        let variable = receiver.split(':').next().unwrap_or("reader");
        consumer.deny(
            &format!("{control}\npub fn denied({receiver}) {{ let _ = &{variable}.{field}; }}"),
            &["E0616", "E0609"],
            field,
        )?;
    }
    consumer.deny(
        &format!("{control}\npub fn denied(view: &UtxoSetView<'_>) {{ let _ = view.shard(0); }}"),
        &["E0624"],
        "shard",
    )?;
    Ok(())
}
