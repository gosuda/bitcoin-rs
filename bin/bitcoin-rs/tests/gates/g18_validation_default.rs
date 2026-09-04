//! G18 — Validation-engine default matches the recorded #213 verdict.
//!
//! **G18 — Validation default.** `bitcoin-rs-consensus` and `bitcoin-rs-node`
//! default to `kernel` while [`RECORDED_VERDICT`] is [`Verdict::KeepKernel`].
//! `bin/bitcoin-rs` default features never include `kernel`. Promoting native
//! is one coordinated change: flip the verdict and drop `kernel` from the two
//! library defaults in the same commit, after the measurement gates in
//! `docs/benchmarks/native-validation-default.md` pass.
//!
//! Contract: `docs/contracts/validation-default.md` — `VAL-01` (library
//! default), `VAL-03` (binary stays kernel-free).

#![allow(clippy::expect_used)]

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

/// Recorded #213 promotion verdict.
///
/// Change this only together with the matching `default` lists in
/// `crates/consensus/Cargo.toml` and `crates/node/Cargo.toml`, and only after
/// every gate in `docs/benchmarks/native-validation-default.md` passes.
const RECORDED_VERDICT: Verdict = Verdict::KeepKernel;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Verdict {
    /// Library crates keep `kernel` in `default`.
    KeepKernel,
    /// Library crates have dropped `kernel` from `default`.
    #[allow(dead_code, reason = "constructed when RECORDED_VERDICT flips")]
    PromoteNative,
}

const CONSENSUS: &str = "bitcoin-rs-consensus";
const NODE: &str = "bitcoin-rs-node";
const BIN: &str = "bitcoin-rs";

fn workspace_root_manifest() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("Cargo.toml")
}

fn package_features() -> BTreeMap<String, BTreeMap<String, Vec<String>>> {
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

fn default_features<'a>(
    features: &'a BTreeMap<String, BTreeMap<String, Vec<String>>>,
    package: &str,
) -> &'a [String] {
    features
        .get(package)
        .unwrap_or_else(|| panic!("workspace package `{package}` missing from cargo metadata"))
        .get("default")
        .map_or(&[], Vec::as_slice)
}

fn default_has_kernel(
    features: &BTreeMap<String, BTreeMap<String, Vec<String>>>,
    package: &str,
) -> bool {
    default_features(features, package)
        .iter()
        .any(|feature| feature == "kernel")
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
