//! ARCH-01..ARCH-04: check the live Cargo graph against the architecture contract.

#[path = "../support/dependency_graph.rs"]
mod dependency_graph;

#[path = "../support/capability_compile.rs"]
mod capability_compile;
use dependency_graph::WorkspaceGraph;

const READ_CONTROL: &str = r"
use std::sync::Arc;
use bitcoin_rs_chain::{BlockTreeReader, TipReader, TipSnapshot};
use bitcoin_rs_chainstate::{Chainstate, ChainstateSnapshot};
use bitcoin_rs_p2p::sync::SyncChain;
use bitcoin_rs_p2p::sync::chain::{ReorgError, HistoricalAdvance, WindowApplyDisposition};

pub fn sync_outcomes(
    branch: bitcoin_rs_chainstate::reorg::ReorgError,
    historical: bitcoin_rs_chainstate::assumeutxo::HistoricalAdvance,
    disposition: bitcoin_rs_chainstate::WindowApplyDisposition,
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
    // The read-only UTXO capability is what production consumers receive;
    // it must compile without the fixture seam.
    let _ = state.utxo_reader();
    (applied.load_full(), tree.clone().read().len())
}

pub fn observe_sync(chain: &dyn SyncChain) -> Option<Arc<TipSnapshot>> {
    let _ = chain.block_tree().tip();
    let _ = chain.chain_tip();
    chain.applied_tip()
}
";

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

/// EMB-03: a real production embedder must not inherit fixture visibility
/// through Cargo's workspace dev-feature unification.
#[test]
fn node_composition_root_is_not_a_production_embedding_api() -> anyhow::Result<()> {
    let manifest = dependency_graph::workspace_root_manifest();
    let root = manifest
        .parent()
        .ok_or_else(|| std::io::Error::other("workspace root"))?
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
/// Compile a consumer in a separate workspace: dev feature unification must
/// not make persistence injection or synthetic worlds into production APIs.
#[test]
fn fixture_owners_expose_no_production_injection_or_synthetic_constructors() -> anyhow::Result<()> {
    let manifest = dependency_graph::workspace_root_manifest();
    let root = manifest
        .parent()
        .ok_or_else(|| std::io::Error::other("workspace root"))?
        .canonicalize()?;
    let consumer = capability_compile::ProductionConsumer::with_fixture_owners(&root)?;
    consumer.allow_reads(&format!(
        "{READ_CONTROL}\npub fn compose(handles: bitcoin_rs_rpc::context::ContextHandles) -> bitcoin_rs_rpc::context::Context {{ bitcoin_rs_rpc::context::Context::from_handles(handles) }}"
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
            "pub fn denied() { let _ = bitcoin_rs_chainstate::Chainstate::new; }",
            &["E0599"][..],
            "new",
        ),
        (
            "pub fn denied() { let _ = bitcoin_rs_rpc::context::Context::new; }",
            &["E0599"][..],
            "new",
        ),
        (
            "pub fn denied() { let _ = bitcoin_rs_rpc::context::ContextHandles::default; }",
            &["E0599"][..],
            "default",
        ),
    ] {
        consumer.deny(source, codes, member)?;
    }
    Ok(())
}

#[test]
fn chainstate_facade_exposes_no_production_raw_mutation_handles() -> anyhow::Result<()> {
    let manifest = dependency_graph::workspace_root_manifest();
    let root = manifest
        .parent()
        .ok_or_else(|| std::io::Error::other("workspace root"))?
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
    // A private field may also be removed: both outcomes seal the capability.
    for (receiver, member) in [
        ("tip: &TipReader", "tip.inner"),
        ("tree: &BlockTreeReader", "tree.inner"),
        ("state: &Chainstate", "state.chain_tip"),
        ("state: &Chainstate", "state.applied_tip"),
        ("state: &Chainstate", "state.block_tree"),
        ("state: &Chainstate", "state.chain_transition"),
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

    // Refer to associated methods without supplying arguments: this rejects
    // availability regardless of signature, and deleted APIs remain valid.
    for method in [
        "chain_tip",
        "applied_tip",
        "chain_tip_handle",
        "applied_tip_handle",
        "block_tree",
        "block_tree_handle",
        // Tree reads go through `BlockTreeReader`; a facade read guard would
        // be a second route to the same lock.
        "read_block_tree",
        "transition_barrier",
        // Retained-history authority lives in storage/pruning; chainstate
        // keeps only `MandatoryRetention` and must not broker the registry.
        "retention_handle",
        // The transition domain is minted by composition and split into roles;
        // chainstate holds one role and must not republish a fence.
        "read_fence",
        // The authoritative UTXO set stays with its mutation owner; consumers
        // take `UtxoReader`, which carries no `utxo::contract` path.
        "utxo",
        "utxo_handle",
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
    // `UtxoReader::fixture_set` is the only route from a read capability back
    // to the set `utxo::contract` mutates. It is compiled out of production
    // builds, so a production consumer must not be able to name it.
    consumer.deny(
        &format!(
            "{READ_CONTROL}\npub fn denied(reader: &bitcoin_rs_utxo::UtxoReader) {{ let _ = reader.fixture_set(); }}"
        ),
        &["E0599"],
        "fixture_set",
    )?;
    Ok(())
}
