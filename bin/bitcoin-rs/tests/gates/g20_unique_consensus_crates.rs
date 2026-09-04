//! G20 proves the workspace's dependency-graph invariant.
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
            "--all-features",
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
    let reachable: BTreeSet<&str> = metadata["resolve"]["nodes"].as_array().expect("resolve nodes array").iter().filter_map(|node| node["id"].as_str()).collect();
    for package in metadata["packages"].as_array().expect("packages array") {
        let name = package["name"].as_str().expect("package name");
        if !UNIQUE_CRATES.contains(&name) || !reachable.contains(package["id"].as_str().expect("package id")) {
            continue;
        }
        let version = package["version"].as_str().expect("package version");
        versions
            .entry(name.to_owned())
            .or_default()
            .insert(format!("{} ({})", version, package["id"].as_str().expect("package id")));
    }
    versions
}

#[test]
fn consensus_stack_crates_resolve_to_one_version() {
    let deny: toml::Value = toml::from_str(&std::fs::read_to_string(workspace_root_manifest().with_file_name("deny.toml")).expect("read deny.toml")).expect("parse deny.toml");
    if let Some(skip) = deny.get("bans").and_then(|b| b.get("skip")).and_then(toml::Value::as_array) {
        for entry in skip { let text = entry.get("crate").and_then(toml::Value::as_str).unwrap_or(""); assert!(!UNIQUE_CRATES.iter().any(|name| text == *name || text.starts_with(&format!("{}@", name))), "protected crate in deny.toml skip: {text}"); }
    }
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
