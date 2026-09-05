//! G20 — The resolved graph carries one copy of each consensus-stack crate.
//!
//! **G20 — Unique consensus crates.** The workspace pins one `bitcoin`,
//! one `bitcoin_hashes`, one `secp256k1`, and one `secp256k1-sys`. A second
//! copy of any of them is a graph split in the consensus stack: types
//! stop lining up and deny.toml's skip list is not the owner of that rule.
//!
//! `cargo metadata --all-features` (full resolve, every optional backend
//! and kernel) is the proof. `deny.toml` `multiple-versions = "deny"` is
//! the graph-wide companion; this gate names the four crates that must
//! never appear on that skip list, including version-qualified entries.
//!
//! Contract: `docs/contracts/dependency-range.md` — `DEP-02`.

#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::process::Command;

/// Crates that must resolve to exactly one copy in the full graph.
const UNIQUE_CRATES: [&str; 4] = ["bitcoin", "bitcoin_hashes", "secp256k1", "secp256k1-sys"];

fn workspace_root() -> PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root")
}

fn workspace_root_manifest() -> PathBuf {
    workspace_root().join("Cargo.toml")
}

/// Package ids per crate name from a fully-featured workspace resolve.
fn resolved_ids() -> BTreeMap<String, BTreeSet<String>> {
    let output = Command::new(env!("CARGO"))
        .args([
            "metadata",
            "--format-version",
            "1",
            "--all-features",
            "--manifest-path",
            workspace_root_manifest().to_str().expect("utf8 root path"),
        ])
        .output()
        .expect("run cargo metadata");
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse cargo metadata JSON");

    let mut ids: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for package in metadata["packages"].as_array().expect("packages array") {
        let name = package["name"].as_str().expect("package name");
        if !UNIQUE_CRATES.contains(&name) {
            continue;
        }
        let id = package["id"].as_str().expect("package id");
        ids.entry(name.to_owned())
            .or_default()
            .insert(id.to_owned());
    }
    ids
}

/// Crate names listed in `deny.toml` `[bans].skip`, with any `@version` stripped.
fn deny_skip_names() -> BTreeSet<String> {
    let text = std::fs::read_to_string(workspace_root().join("deny.toml")).expect("read deny.toml");
    let deny: toml::Value = toml::from_str(&text).expect("parse deny.toml");
    let skip = deny
        .get("bans")
        .and_then(|bans| bans.get("skip"))
        .and_then(toml::Value::as_array)
        .expect("[bans].skip array");
    skip.iter()
        .filter_map(|entry| {
            let spec = entry.get("crate")?.as_str()?;
            Some(spec.split('@').next().unwrap_or(spec).to_owned())
        })
        .collect()
}

#[test]
fn consensus_stack_crates_resolve_to_one_copy() {
    let ids = resolved_ids();
    for crate_name in UNIQUE_CRATES {
        let found = ids.get(crate_name).cloned().unwrap_or_default();
        assert_eq!(
            found.len(),
            1,
            "`{crate_name}` must resolve to exactly one copy; found {found:?}. \
             Do not add a deny.toml skip for this crate — pin the workspace \
             dependency so the graph carries one copy."
        );
    }
}

#[test]
fn consensus_stack_crates_are_absent_from_deny_skip() {
    let skip = deny_skip_names();
    for crate_name in UNIQUE_CRATES {
        assert!(
            !skip.contains(crate_name),
            "`{crate_name}` must not appear in deny.toml [bans].skip \
             (including version-qualified entries); found {skip:?}"
        );
    }
}
