//! G20 proves the `DEP-02` contract for the resolved, full-feature workspace graph.
//! The gate also checks the local deny-list policy for the protected crates.
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

fn resolved_package_ids() -> BTreeMap<String, BTreeSet<String>> {
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

    let mut versions: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    for package in metadata["packages"].as_array().expect("packages array") {
        let name = package["name"].as_str().expect("package name");
        if !UNIQUE_CRATES.contains(&name) {
            continue;
        }
        let id = package["id"].as_str().expect("package id");
        versions
            .entry(name.to_owned())
            .or_default()
            .insert(id.to_owned());
    }
    versions
}

#[test]
fn consensus_stack_crates_resolve_to_one_version() {
    let package_ids = resolved_package_ids();
    for crate_name in UNIQUE_CRATES {
        let found = package_ids.get(crate_name).cloned().unwrap_or_default();
        assert_eq!(
            found.len(),
            1,
            "`{crate_name}` must resolve to exactly one package; found {found:?}"
        );
    }

    let deny = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../deny.toml"),
    )
    .expect("read deny.toml");
    let deny: toml::Value = deny.parse().expect("parse deny.toml");
    let skips = deny["bans"]["skip"].as_array().expect("bans.skip array");
    for skip in skips {
        let specification = skip["crate"].as_str().expect("skip crate");
        let name = specification.split('@').next().expect("crate name");
        assert!(
            !UNIQUE_CRATES.contains(&name),
            "protected crate `{name}` must not appear in deny.toml bans.skip"
        );
    }
}
