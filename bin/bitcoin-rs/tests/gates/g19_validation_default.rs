//! G19 — Validation-engine default matches the recorded #213 verdict.
//!
//! **G19 — Validation default.** `bitcoin-rs-consensus` and `bitcoin-rs-node`
//! omit `kernel` from `default` while [`RECORDED_VERDICT`] is
//! [`Verdict::PromoteNative`]. `bin/bitcoin-rs` default features never include
//! `kernel`. Reverting that split is one coordinated change: flip the verdict
//! and put `kernel` back in the two library defaults in the same commit.
//!
//! The check walks each package's default feature graph, including local
//! aliases and `crate/feature` / `dep:bitcoinkernel` forwarding, so an
//! effective kernel engine cannot hide behind a renamed default.
//!
//! Contract: `docs/contracts/validation-default.md` — `VAL-01` (library
//! default), `VAL-03` (binary stays kernel-free).

#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

/// Recorded #213 promotion verdict.
///
/// Change this only together with the matching `default` lists in
/// `crates/consensus/Cargo.toml` and `crates/node/Cargo.toml`.
const RECORDED_VERDICT: Verdict = Verdict::PromoteNative;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Verdict {
    /// Library crates keep `kernel` in `default`.
    #[allow(dead_code, reason = "retained so a revert is one coordinated flip")]
    KeepKernel,
    /// Library crates have dropped `kernel` from `default`.
    PromoteNative,
}

const CONSENSUS: &str = "bitcoin-rs-consensus";
const NODE: &str = "bitcoin-rs-node";
const BIN: &str = "bitcoin-rs";

type FeatureMap = BTreeMap<String, BTreeMap<String, Vec<String>>>;

fn workspace_root_manifest() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("Cargo.toml")
}

fn package_features() -> FeatureMap {
    let output = Command::new(env!("CARGO"))
        .args([
            "metadata",
            "--no-deps",
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

    let mut features = BTreeMap::new();
    for package in metadata["packages"].as_array().expect("packages array") {
        let name = package["name"].as_str().expect("package name").to_owned();
        let mut feature_map = BTreeMap::new();
        for (feature, implies) in package["features"].as_object().expect("features object") {
            let implies = implies
                .as_array()
                .expect("feature implies array")
                .iter()
                .map(|value| value.as_str().expect("feature string").to_owned())
                .collect();
            feature_map.insert(feature.clone(), implies);
        }
        features.insert(name, feature_map);
    }
    features
}

fn default_features<'a>(features: &'a FeatureMap, package: &str) -> &'a [String] {
    features
        .get(package)
        .unwrap_or_else(|| panic!("workspace package `{package}` missing from cargo metadata"))
        .get("default")
        .map_or(&[], Vec::as_slice)
}

fn token_is_kernel(token: &str) -> bool {
    token == "kernel" || token == "dep:bitcoinkernel"
}

fn reaches_kernel(
    features: &FeatureMap,
    package: &str,
    token: &str,
    visited: &mut BTreeSet<(String, String)>,
) -> bool {
    if token_is_kernel(token) {
        return true;
    }
    if !visited.insert((package.to_owned(), token.to_owned())) {
        return false;
    }
    if let Some((dependency, dependency_feature)) = token.split_once('/') {
        return reaches_kernel(features, dependency, dependency_feature, visited);
    }
    features
        .get(package)
        .and_then(|package_features| package_features.get(token))
        .into_iter()
        .flatten()
        .any(|implied| reaches_kernel(features, package, implied, visited))
}

fn default_has_kernel(features: &FeatureMap, package: &str) -> bool {
    default_features(features, package)
        .iter()
        .any(|feature| reaches_kernel(features, package, feature, &mut BTreeSet::new()))
}

#[test]
fn library_defaults_match_recorded_verdict() {
    let features = package_features();
    let consensus = default_has_kernel(&features, CONSENSUS);
    let node = default_has_kernel(&features, NODE);
    match RECORDED_VERDICT {
        Verdict::KeepKernel => {
            assert!(
                consensus,
                "VAL-01: bitcoin-rs-consensus default must include kernel \
                 while RECORDED_VERDICT is KeepKernel"
            );
            assert!(
                node,
                "VAL-01: bitcoin-rs-node default must include kernel \
                 while RECORDED_VERDICT is KeepKernel"
            );
        }
        Verdict::PromoteNative => {
            assert!(
                !consensus,
                "VAL-01: bitcoin-rs-consensus default must not include kernel \
                 while RECORDED_VERDICT is PromoteNative"
            );
            assert!(
                !node,
                "VAL-01: bitcoin-rs-node default must not include kernel \
                 while RECORDED_VERDICT is PromoteNative"
            );
        }
    }
}

#[test]
fn binary_default_excludes_kernel() {
    let features = package_features();
    assert!(
        !default_has_kernel(&features, BIN),
        "VAL-03: bin/bitcoin-rs default features must stay kernel-free"
    );
}

#[test]
fn kernel_feature_exists_on_each_manifest() {
    let features = package_features();
    for package in [CONSENSUS, NODE, BIN] {
        assert!(
            features
                .get(package)
                .unwrap_or_else(|| panic!("workspace package `{package}` missing"))
                .contains_key("kernel"),
            "{package} must keep a `kernel` feature so the default check is not \
             vacuously comparing against a missing name"
        );
    }
}

#[test]
fn alias_and_dep_forwarding_count_as_kernel() {
    let mut pkg = BTreeMap::new();
    pkg.insert("default".to_owned(), vec!["prod".to_owned()]);
    pkg.insert("prod".to_owned(), vec!["engine".to_owned()]);
    pkg.insert("engine".to_owned(), vec!["dep:bitcoinkernel".to_owned()]);
    let mut features = BTreeMap::new();
    features.insert("example".to_owned(), pkg);
    assert!(
        default_has_kernel(&features, "example"),
        "a renamed default that forwards to dep:bitcoinkernel must count as kernel"
    );
}

#[test]
fn crate_feature_forwarding_counts_as_kernel() {
    let mut node = BTreeMap::new();
    node.insert("default".to_owned(), vec!["prod".to_owned()]);
    node.insert(
        "prod".to_owned(),
        vec!["bitcoin-rs-consensus/kernel".to_owned()],
    );
    let mut consensus = BTreeMap::new();
    consensus.insert("kernel".to_owned(), vec!["dep:bitcoinkernel".to_owned()]);
    let mut features = BTreeMap::new();
    features.insert("bitcoin-rs-node".to_owned(), node);
    features.insert("bitcoin-rs-consensus".to_owned(), consensus);
    assert!(
        default_has_kernel(&features, "bitcoin-rs-node"),
        "default -> crate/kernel forwarding must count as kernel"
    );
}

#[test]
fn unrelated_defaults_do_not_count_as_kernel() {
    let mut pkg = BTreeMap::new();
    pkg.insert("default".to_owned(), vec!["fjall".to_owned()]);
    pkg.insert("kernel".to_owned(), vec!["dep:bitcoinkernel".to_owned()]);
    pkg.insert(
        "fjall".to_owned(),
        vec!["bitcoin-rs-storage/fjall".to_owned()],
    );
    let mut features = BTreeMap::new();
    features.insert("example".to_owned(), pkg);
    assert!(
        !default_has_kernel(&features, "example"),
        "an unused kernel feature must not make the default look enabled"
    );
}
