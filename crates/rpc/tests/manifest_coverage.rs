//! Compatibility-manifest coverage gate.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;

use bitcoin_rs_rpc::context::Context;
use bitcoin_rs_rpc::manifest::{self, Entry, Status, SurfaceKind};
use bitcoin_rs_rpc::{Handler, RpcError};
use sonic_rs::json;

/// ZMQ PUB topics Bitcoin Core 31.x registers (src/zmq/zmqpublishnotifier.cpp).
const CORE_ZMQ_TOPICS: [&str; 5] = ["hashblock", "hashtx", "rawblock", "rawtx", "sequence"];

const CARGO_LOCK: &str = include_str!("../../../Cargo.lock");

fn handler() -> Handler {
    Handler::new(Arc::new(Context::new()))
}

#[test]
fn silent_payments_requires_build_and_runtime_opt_in() {
    let result = handler().dispatch("getblocktweaks", &json!([0]));
    #[cfg(feature = "silent-payments")]
    assert!(matches!(result, Err(RpcError::MethodDisabled(_))));
    #[cfg(not(feature = "silent-payments"))]
    assert!(matches!(result, Err(RpcError::MethodNotFound(_))));
}

fn shipped(kind: SurfaceKind) -> impl Iterator<Item = &'static Entry> {
    manifest::entries_of_kind(kind).filter(|entry| entry.shipped())
}

fn not_dispatchable(handler: &Handler, name: &str) -> bool {
    matches!(
        handler.dispatch(name, &json!([])),
        Err(RpcError::MethodNotFound(_))
    )
}

#[test]
fn rpc_rows_and_the_live_registry_agree_both_ways() {
    let live: BTreeSet<&str> = bitcoin_rs_rpc::handlers::live_registry().collect();
    assert!(
        !live.is_empty(),
        "live registry must not silently empty out"
    );
    let shipped_rows: BTreeSet<&str> = shipped(SurfaceKind::Rpc).map(|entry| entry.name).collect();
    let armless: Vec<&str> = shipped_rows.difference(&live).copied().collect();
    assert!(
        armless.is_empty(),
        "shipped manifest rows with no live dispatch arm: {armless:?}"
    );
    let undeclared: Vec<&str> = live.difference(&shipped_rows).copied().collect();
    assert!(
        undeclared.is_empty(),
        "live dispatch arms missing a shipped manifest row: {undeclared:?}"
    );
}

#[test]
fn every_unimplemented_rpc_row_answers_method_not_found() {
    let handler = handler();
    let unimplemented: BTreeSet<&str> = manifest::entries_of_kind(SurfaceKind::Rpc)
        .filter(|entry| entry.status == Status::Unimplemented)
        .map(|entry| entry.name)
        .collect();
    assert!(
        !unimplemented.is_empty(),
        "Unimplemented set must not silently empty out"
    );
    for name in &unimplemented {
        assert!(
            not_dispatchable(&handler, name),
            "`{name}` is declared Unimplemented but the dispatcher answers it"
        );
    }
    assert!(
        unimplemented.is_disjoint(&shipped(SurfaceKind::Rpc).map(|entry| entry.name).collect()),
        "a row cannot be both Unimplemented and shipped"
    );
}

#[test]
fn rest_rows_and_router_registrations_agree_both_ways() {
    let registered: BTreeSet<&str> = bitcoin_rs_rpc::rest::REGISTRATIONS
        .iter()
        .copied()
        .collect();
    let manifest_rest: BTreeSet<&str> = shipped(SurfaceKind::Rest)
        .filter(|entry| entry.name.starts_with("/rest/"))
        .map(|entry| entry.name)
        .collect();
    let unregistered: Vec<&str> = manifest_rest.difference(&registered).copied().collect();
    assert!(
        unregistered.is_empty(),
        "manifest REST rows missing from rest::REGISTRATIONS: {unregistered:?}"
    );
    let undeclared: Vec<&str> = registered.difference(&manifest_rest).copied().collect();
    assert!(
        undeclared.is_empty(),
        "rest::REGISTRATIONS prefixes missing a manifest row: {undeclared:?}"
    );
}

#[test]
fn zmq_rows_are_valid_core_topics() {
    let declared: BTreeSet<&str> = manifest::entries_of_kind(SurfaceKind::Zmq)
        .map(|entry| entry.name)
        .collect();
    let core: BTreeSet<&str> = CORE_ZMQ_TOPICS.iter().copied().collect();
    assert_eq!(
        declared, core,
        "the ZMQ rows must name exactly the Core-registered topics"
    );
}

#[test]
fn deviation_rows_name_their_difference() {
    let silent: Vec<&str> = manifest::MANIFEST
        .iter()
        .filter(|entry| entry.status == Status::Deviation && entry.notes.trim().is_empty())
        .map(|entry| entry.name)
        .collect();
    assert!(
        silent.is_empty(),
        "these rows claim a deviation without stating it: {silent:?}"
    );
}

#[test]
fn supported_is_not_claimable_without_the_harness() {
    let table: toml::Table = toml::from_str(manifest::MANIFEST_TOML)
        .unwrap_or_else(|err| panic!("the reference custody record must parse: {err}"));
    let harness = table
        .get("reference")
        .and_then(toml::Value::as_table)
        .and_then(|reference| reference.get("differential_harness"))
        .and_then(toml::Value::as_bool)
        .unwrap_or_else(|| panic!("`reference.differential_harness` must be a boolean"));
    if harness {
        return;
    }
    let claiming: Vec<&str> = manifest::MANIFEST
        .iter()
        .filter(|entry| entry.status == Status::Supported)
        .map(|entry| entry.name)
        .collect();
    assert!(
        claiming.is_empty(),
        "these rows claim `Supported` while no differential harness exists to have \
         verified them: {claiming:?}"
    );
}

#[test]
fn the_pinned_core_reference_matches_the_locked_kernel() {
    let table: toml::Table = toml::from_str(manifest::MANIFEST_TOML)
        .unwrap_or_else(|err| panic!("the reference custody record must parse: {err}"));
    let Some(reference) = table.get("reference").and_then(toml::Value::as_table) else {
        panic!("the reference custody record must carry a `reference` table");
    };

    for (name_key, version_key) in [
        ("kernel_crate", "kernel_crate_version"),
        ("kernel_sys_crate", "kernel_sys_crate_version"),
    ] {
        let name = reference
            .get(name_key)
            .and_then(toml::Value::as_str)
            .unwrap_or_else(|| panic!("`{name_key}` must be a string"));
        let version = reference
            .get(version_key)
            .and_then(toml::Value::as_str)
            .unwrap_or_else(|| panic!("`{version_key}` must be a string"));
        let lock: toml::Table = toml::from_str(CARGO_LOCK)
            .unwrap_or_else(|err| panic!("Cargo.lock must parse as TOML: {err}"));
        let locked: Vec<&str> = lock
            .get("package")
            .and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
            .filter(|package| package.get("name").and_then(toml::Value::as_str) == Some(name))
            .filter_map(|package| package.get("version").and_then(toml::Value::as_str))
            .collect();
        assert!(
            !locked.is_empty(),
            "`{name}` is pinned in the reference record but absent from Cargo.lock"
        );
        assert!(
            locked
                .iter()
                .all(|&locked_version| locked_version == version),
            "`{name}` is locked at {locked:?} but the reference record is written \
             against {version}. The pinned Bitcoin Core revision comes from this \
             crate's vendored tree, so a bump means the claims in \
             crates/rpc/core-compat.toml need re-reading, not just this line."
        );
    }
}

#[test]
fn esplora_extension_row_resolves_to_the_router() {
    let row = manifest::MANIFEST
        .iter()
        .find(|entry| entry.name == "esplora/*")
        .unwrap_or_else(|| panic!("esplora/* extension row missing from MANIFEST"));
    assert_eq!(row.status, Status::Extension);
    let (surface, path) = bitcoin_rs_rpc::esplora::namespace("/api/mempool")
        .unwrap_or_else(|| panic!("/api/mempool is the public Esplora directory"));
    let response = bitcoin_rs_rpc::esplora::route(&handler(), surface, path, "");
    assert_eq!(
        response.status, 200,
        "esplora router must serve the row it declares"
    );
}

/// Invariant 2: no duplicate (kind, name) rows.
#[test]
fn manifest_has_no_duplicate_rows() {
    let mut seen = BTreeSet::new();
    for entry in manifest::MANIFEST {
        assert!(
            seen.insert((entry.kind, entry.name)),
            "duplicate manifest row: {:?} {}",
            entry.kind,
            entry.name
        );
    }
}

/// Notes must be single-line, pipe-free text so the generated Markdown table
/// cannot be broken by row content.
#[test]
fn notes_are_markdown_table_safe() {
    for entry in manifest::MANIFEST {
        assert!(
            !entry.notes.contains('|'),
            "row `{}` notes contain a pipe",
            entry.name
        );
        assert!(
            !entry.notes.contains('\n'),
            "row `{}` notes contain a newline",
            entry.name
        );
    }
}

#[test]
fn generated_reference_matches_checked_in() {
    const REGEN: &str = "REGEN_RPC_REFERENCE=1 cargo test -p bitcoin-rs-rpc \
        --test manifest_coverage -- --ignored regenerate_reference";
    assert!(
        std::env::var_os("REGEN_RPC_REFERENCE").is_none(),
        "REGEN_RPC_REFERENCE is set: this is a coverage-only guard. Regenerate with \
         `{REGEN}`, unset the variable, and rerun."
    );
    let rendered = manifest::render_reference();
    let doc_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/rpc-reference.md");
    let checked_in = std::fs::read_to_string(&doc_path).unwrap_or_else(|err| {
        panic!(
            "cannot read {}: {err}; regenerate with \
             REGEN_RPC_REFERENCE=1 cargo test -p bitcoin-rs-rpc --test manifest_coverage \
             -- --ignored regenerate_reference",
            doc_path.display()
        )
    });
    if rendered != checked_in {
        let first_diff = rendered
            .lines()
            .zip(checked_in.lines())
            .position(|(generated, checked_in)| generated != checked_in)
            .unwrap_or_else(|| rendered.lines().count().min(checked_in.lines().count()));
        panic!(
            "docs/rpc-reference.md drifted from the manifest at line {}:\n  generated: {:?}\n  checked in: {:?}\n\
             regenerate with REGEN_RPC_REFERENCE=1 cargo test -p bitcoin-rs-rpc --test manifest_coverage -- --ignored regenerate_reference",
            first_diff + 1,
            rendered.lines().nth(first_diff),
            checked_in.lines().nth(first_diff)
        );
    }
}

#[ignore = "writes docs/rpc-reference.md; run explicitly with REGEN_RPC_REFERENCE=1"]
#[test]
fn regenerate_reference() {
    assert!(
        std::env::var_os("REGEN_RPC_REFERENCE").is_some(),
        "guarded against accidental writes: run with REGEN_RPC_REFERENCE=1"
    );
    let doc_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/rpc-reference.md");
    std::fs::write(&doc_path, manifest::render_reference())
        .unwrap_or_else(|err| panic!("failed to write {}: {err}", doc_path.display()));
}
