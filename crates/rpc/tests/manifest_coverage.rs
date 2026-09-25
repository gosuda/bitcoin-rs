//! Compatibility-manifest coverage gate (issue #78).
//!
//! Proves four invariants:
//! 1. the dispatcher's live dispatch registry and the shipped manifest rows
//!    are set-equal in both directions (REST and ZMQ likewise against their
//!    live registrations), and every `Unimplemented` row really answers
//!    `method not found`;
//! 2. the manifest carries no duplicate rows;
//! 3. `docs/rpc-reference.md` is byte-identical to a regeneration of the
//!    manifest; drift names the delta and the regen command. Regeneration
//!    is a separate ignored test, so a coverage run never writes and a
//!    regen run never passes silently;
//! 4. the declared claims stay honest: every `Deviation` row states its
//!    difference, no row claims `Supported` while the pinned reference
//!    carries no differential harness, and the reference identity still
//!    matches `Cargo.lock`.

use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Arc;

use bitcoin_rs_rpc::context::Context;
use bitcoin_rs_rpc::manifest::{self, Entry, Status, SurfaceKind};
use bitcoin_rs_rpc::{Handler, RpcError};
use sonic_rs::json;

/// ZMQ PUB topics Bitcoin Core 31.x registers (src/zmq/zmqpublishnotifier.cpp).
const CORE_ZMQ_TOPICS: [&str; 5] = ["hashblock", "hashtx", "rawblock", "rawtx", "sequence"];

/// `Cargo.lock`, so the pinned reference cannot quietly stop being pinned.
const CARGO_LOCK: &str = include_str!("../../../Cargo.lock");

fn handler() -> Handler {
    Handler::new(Arc::new(Context::new()))
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

/// Invariant 1 (RPC, bidirectional): the live dispatch registry and the
/// shipped manifest rows are set-equal in both directions. Both sides come
/// from one static table (`registry::REGISTRY`) that binds each name to its
/// handler arm and that `Handler::dispatch` itself consumes, so a method can
/// neither dispatch without a shipped row nor ship a row without an arm.
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

/// Invariant 1 (RPC, reverse): every `Unimplemented` row is genuinely absent
/// from the dispatcher, and a manifest row is never both shipped and
/// unimplemented.
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

/// Invariant 1 (REST): shipped route prefixes are exactly the prefixes the
/// REST router registers; every registered prefix has a manifest row.
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

/// Invariant 1 (ZMQ): the declared topic rows are exactly the five topics
/// Bitcoin Core registers, and every shipped topic names its activation
/// requirements. The row set is checked feature-independently, because a
/// topic declared only when `zmq` is compiled would let the table and the
/// publisher disagree in a build nobody tests.
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
    for entry in shipped(SurfaceKind::Zmq) {
        assert!(
            !entry.notes.is_empty(),
            "ZMQ topic `{}` must name its activation requirements",
            entry.name
        );
    }
}

/// Invariant 4: a row that claims `Deviation` has to say what the deviation
/// is. The status alone tells a client that this node differs and not how,
/// which is the least useful thing a compatibility table can say.
#[test]
fn every_deviation_states_itself() {
    let deviations: Vec<&Entry> = manifest::MANIFEST
        .iter()
        .filter(|entry| entry.status == Status::Deviation)
        .collect();
    assert!(
        !deviations.is_empty(),
        "the registry must record its deviations"
    );
    for entry in deviations {
        assert!(
            entry.notes.trim().len() > 40,
            "the {} row `{}` claims a deviation in {} characters, \
             which cannot describe one",
            entry.kind.label(),
            entry.name,
            entry.notes.trim().len()
        );
    }
}

/// Invariant 4: nothing may claim `Supported` until something can verify it.
///
/// `Supported` means differentially verified against the pinned reference,
/// and no harness compares result values or shapes against Core's own
/// declarations yet. The reference record carries a flag for whether it
/// does, and this refuses the claim while the flag is false. Without it,
/// `Supported` becomes a synonym for "implemented" one row at a time, which
/// is the failure mode the whole vocabulary exists to prevent.
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

/// Invariant 4: the pinned reference is pinned to something the build
/// actually links.
///
/// The Core revision in the reference record comes from the kernel crate's
/// vendored tree, so the claim is only as good as that version staying put.
/// Checked against `Cargo.lock` rather than against a comment: a dependency
/// bump that moves the Core source has to come back through this file, which
/// is exactly when the compatibility claims need re-reading.
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
        // Every `[[package]]` block naming the crate contributes its version;
        // a crate locked at two versions must agree at both, not just at the
        // first substring hit.
        let locked: Vec<&str> = CARGO_LOCK
            .split("\n[[package]]\n")
            .filter_map(|block| {
                let mut lines = block.lines();
                let declared = lines.next()?.strip_prefix("name = \"")?.strip_suffix('"')?;
                if declared != name {
                    return None;
                }
                lines.find_map(|line| {
                    line.strip_prefix("version = \"")
                        .and_then(|rest| rest.strip_suffix('"'))
                })
            })
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
             docs/api/core-compat.toml need re-reading, not just this line."
        );
    }
}

/// The `esplora` extension row resolves against the live Esplora router.
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

/// The pending extension row is the contract, not the method: it must not
/// dispatch until it ships.
#[test]
fn pending_extension_rows_do_not_dispatch() {
    let handler = handler();
    for entry in manifest::entries_of_kind(SurfaceKind::Rpc)
        .filter(|entry| entry.status == Status::Extension && entry.since == "pending")
    {
        assert!(
            not_dispatchable(&handler, entry.name),
            "`{}` is marked since=pending but the dispatcher answers it",
            entry.name
        );
    }
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

/// Invariant 3: the checked-in reference is byte-identical to a
/// regeneration of the manifest. This test never writes; it fails when
/// `REGEN_RPC_REFERENCE` is set so a regeneration run can never double as
/// a passing coverage run.
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

/// Explicit regeneration of `docs/rpc-reference.md` from the manifest.
/// Ignored by default; run it with `REGEN_RPC_REFERENCE=1` set.
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
