//! G20 — The resolved graph carries one copy of each consensus-stack crate.
//!
//! **G20 — Unique consensus crates.** The workspace pins one `bitcoin`,
//! one `bitcoin_hashes`, one `secp256k1`, and one `secp256k1-sys`. A second
//! version of any of them is a graph split in the consensus stack: types
//! stop lining up and deny.toml's skip list is not the owner of that rule.
//!
//! `cargo metadata` (full resolve) is the proof. `deny.toml`
//! `multiple-versions = "deny"` is the graph-wide companion; this gate names
//! the four crates that must never appear on that skip list.
//!
//! Contract: `docs/contracts/dependency-range.md` — `DEP-02`.

#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::process::Command;

/// Crates that must resolve to exactly one version in the full graph.
const UNIQUE_CRATES: [&str; 4] = ["bitcoin", "bitcoin_hashes", "secp256k1", "secp256k1-sys"];

fn workspace_root_manifest() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("Cargo.toml")
}

fn resolved_versions() -> BTreeMap<String, BTreeSet<String>> {
    let output = Command::new(env!("CARGO"))
        .args([
            "metadata",
            "--format-version",
            "1",
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

    let mut versions: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for package in metadata["packages"].as_array().expect("packages array") {
        let name = package["name"].as_str().expect("package name");
        if !UNIQUE_CRATES.contains(&name) {
            continue;
        }
        let version = package["version"].as_str().expect("package version");
        versions
            .entry(name.to_owned())
            .or_default()
            .insert(version.to_owned());
    }
    versions
}

#[test]
fn consensus_stack_crates_resolve_to_one_version() {
    let versions = resolved_versions();
    for crate_name in UNIQUE_CRATES {
        let found = versions.get(crate_name).cloned().unwrap_or_default();
        assert_eq!(
            found.len(),
            1,
            "`{crate_name}` must resolve to exactly one version; found {found:?}. \
             Do not add a deny.toml skip for this crate — pin the workspace \
             dependency so the graph carries one copy."
        );
    }
}
