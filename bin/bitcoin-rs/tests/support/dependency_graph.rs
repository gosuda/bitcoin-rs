//! Shared dependency-graph parser and validator for `g17_dependency_direction`
//! and `overhaul_ownership`.
//!
//! The validator enforces the five-layer one-way dependency model, the
//! storage-engine ownership boundary, the ZMQ surface ownership boundary,
//! and backend feature-forwarding rules described in
//! `docs/contracts/architecture.md`.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::process::Command;
use std::sync::LazyLock;

/// Storage engine crates. Only `bitcoin-rs-storage` may depend on these.
pub(crate) const ENGINE_CRATES: [&str; 3] = ["fjall", "redb", "rust-rocksdb"];
/// External ZMQ implementation dependency owned by the surface crate.
pub(crate) const ZMQ_CRATE: &str = "zmq";

/// Backend feature names whose forwarding above storage is forbidden.
pub(crate) const BACKEND_FEATURES: [&str; 3] = ["rocksdb", "fjall", "redb"];

/// The crate that owns every storage engine dependency.
pub(crate) const STORAGE_CRATE: &str = "bitcoin-rs-storage";

/// The RPC surface crate.
pub(crate) const RPC_CRATE: &str = "bitcoin-rs-rpc";

/// The node composition crate.
pub(crate) const NODE_CRATE: &str = "bitcoin-rs-node";

/// The node binary.
pub(crate) const BIN_CRATE: &str = "bitcoin-rs";

/// Crates permitted to define and forward storage backend feature selection.
pub(crate) const BACKEND_FORWARDING_CRATES: [&str; 7] = [
    STORAGE_CRATE,
    "bitcoin-rs-chain",
    "bitcoin-rs-utxo",
    "bitcoin-rs-p2p",
    "bitcoin-rs-index",
    NODE_CRATE,
    BIN_CRATE,
];

/// Approved layer for each workspace crate.
///
/// Crates not listed here cause the validator to fail closed so the layer
/// table cannot drift silently.
pub(crate) fn approved_layer(crate_name: &str) -> u8 {
    match crate_name {
        "bitcoin-rs-primitives" | "bitcoin-rs-script" | "bitcoin-rs-consensus" => 0,
        STORAGE_CRATE => 1,
        "bitcoin-rs-chain"
        | "bitcoin-rs-chainstate"
        | "bitcoin-rs-utxo"
        | "bitcoin-rs-p2p"
        | "bitcoin-rs-mempool"
        | "bitcoin-rs-index"
        | "bitcoin-rs-mining" => 2,
        RPC_CRATE => 3,
        NODE_CRATE | BIN_CRATE => 4,
        other => panic!("unclassified workspace crate `{other}`: add it to the layer table"),
    }
}

/// Parsed workspace dependency graph used by the gates.
#[derive(Clone, Debug)]
pub(crate) struct WorkspaceGraph {
    /// Normal `bitcoin-rs-*` dependencies per crate.
    pub normal_deps: BTreeMap<String, Vec<String>>,
    /// Storage engine dependencies per crate.
    pub engine_deps: BTreeMap<String, Vec<String>>,
    /// External ZMQ implementation dependencies per crate.
    pub zmq_deps: BTreeMap<String, Vec<String>>,
    /// Cargo feature implies per crate.
    pub features: BTreeMap<String, BTreeMap<String, Vec<String>>>,
    /// Number of workspace packages seen in the metadata.
    pub classified: usize,
}

/// Result of validating a graph.
#[derive(Debug)]
pub(crate) struct Validation {
    /// Number of normal internal dependency edges checked.
    pub checked_edges: usize,
    /// Number of engine-dependency assertions checked.
    pub checked_engine_edges: usize,
    /// Number of feature assertions checked.
    pub checked_features: usize,
    /// Number of crate packages classified.
    pub classified: usize,
    /// Human-readable summary.
    pub summary: String,
}

/// One operator-facing binary feature profile, mirroring a CI build lane.
#[derive(Clone, Copy, Debug)]
pub(crate) struct FeatureProfile {
    /// Lane name used in violation messages.
    pub(crate) name: &'static str,
    /// CLI `--features` tokens applied to the binary crate.
    pub(crate) features: &'static [&'static str],
    /// Whether the binary's default features participate.
    pub(crate) defaults: bool,
}

impl FeatureProfile {
    pub(crate) const fn new(
        name: &'static str,
        features: &'static [&'static str],
        defaults: bool,
    ) -> Self {
        Self {
            name,
            features,
            defaults,
        }
    }
}

/// Locates the workspace root `Cargo.toml` from the integration test's
/// manifest directory.
pub(crate) fn workspace_root_manifest() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("Cargo.toml")
}

/// Runs `cargo metadata --locked --offline --no-deps --format-version 1`
/// against the workspace root manifest.
fn run_cargo_metadata() -> serde_json::Value {
    let output = Command::new(env!("CARGO"))
        .args([
            "metadata",
            "--locked",
            "--offline",
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
    serde_json::from_slice(&output.stdout).expect("parse cargo metadata JSON")
}

/// Directories of the cargo-metadata workspace members, resolved once.
///
/// The ownership scan walks exactly these directories: sibling checkouts
/// under `.outline/worktree/`, vendored trees, and any other non-member
/// production code under the checkout root must never influence a gate run.
pub(crate) fn workspace_member_dirs() -> &'static [PathBuf] {
    static DIRS: LazyLock<Vec<PathBuf>> = LazyLock::new(|| {
        let metadata = run_cargo_metadata();
        let mut dirs: Vec<PathBuf> = metadata["packages"]
            .as_array()
            .expect("packages array")
            .iter()
            .map(|package| {
                let manifest = package["manifest_path"].as_str().expect("manifest path");
                std::path::Path::new(manifest)
                    .parent()
                    .expect("manifest parent")
                    .to_owned()
            })
            .collect();
        dirs.sort();
        dirs.dedup();
        dirs
    });
    DIRS.as_slice()
}

impl WorkspaceGraph {
    /// Runs `cargo metadata --locked --offline --no-deps --format-version 1` and
    /// parses the result.
    pub(crate) fn from_cargo_metadata() -> Self {
        Self::from_json(&run_cargo_metadata())
    }

    /// Parses the same `cargo metadata --format-version 1` shape from a
    /// `serde_json::Value`. This lets synthetic tests build a graph without
    /// spawning a subprocess.
    pub(crate) fn from_json(metadata: &serde_json::Value) -> Self {
        let mut normal_deps = BTreeMap::new();
        let mut engine_deps = BTreeMap::new();
        let mut zmq_deps = BTreeMap::new();
        let mut features = BTreeMap::new();
        let mut classified = 0_usize;

        for package in metadata["packages"].as_array().expect("packages array") {
            let name = package["name"].as_str().expect("package name").to_owned();
            let _ = approved_layer(&name);
            classified += 1;

            let mut edges = Vec::new();
            let mut engines = Vec::new();
            let mut zmq = Vec::new();
            for dependency in package["dependencies"].as_array().expect("deps array") {
                let dep_name = dependency["name"].as_str().expect("dep name").to_owned();
                if dep_name == ZMQ_CRATE {
                    zmq.push(dep_name.clone());
                }
                if ENGINE_CRATES.contains(&dep_name.as_str()) {
                    engines.push(dep_name);
                    continue;
                }
                if !dep_name.starts_with("bitcoin-rs") {
                    continue;
                }
                // Normal and build edges both count: a build dependency is
                // still a dependency edge, and the RPC storage-independence
                // rule admits no per-kind backdoor. Dev-dependencies stay
                // excluded (the bench-only fixture exception the RPC manifest
                // documents).
                if matches!(
                    dependency["kind"].as_str().unwrap_or("normal"),
                    "normal" | "build"
                ) {
                    edges.push(dep_name);
                }
            }
            normal_deps.insert(name.clone(), edges);
            engine_deps.insert(name.clone(), engines);
            zmq_deps.insert(name.clone(), zmq);

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

        Self {
            normal_deps,
            engine_deps,
            zmq_deps,
            features,
            classified,
        }
    }

    /// Adds a synthetic normal dependency for use in negative tests.
    pub(crate) fn add_normal_dep(&mut self, from: &str, to: &str) {
        self.normal_deps
            .entry(from.to_owned())
            .or_default()
            .push(to.to_owned());
    }

    /// Adds a synthetic storage-engine dependency for use in negative tests.
    pub(crate) fn add_engine_dep(&mut self, on: &str, engine: &str) {
        assert!(
            ENGINE_CRATES.contains(&engine),
            "`{engine}` is not a known storage engine"
        );
        self.engine_deps
            .entry(on.to_owned())
            .or_default()
            .push(engine.to_owned());
    }

    /// Adds or replaces a synthetic cargo feature for use in negative tests.
    /// Replacing (rather than merging) keeps each negative test focused on
    /// the rule it attacks; pass the full implies list the crate really has
    /// when attacking something else.
    pub(crate) fn set_feature(&mut self, on: &str, feature: &str, implies: &[&str]) {
        self.features.entry(on.to_owned()).or_default().insert(
            feature.to_owned(),
            implies.iter().map(ToString::to_string).collect(),
        );
    }

    /// Validates the graph and returns either a summary or a list of violations.
    pub(crate) fn validate(&self) -> Result<Validation, Vec<String>> {
        let mut violations = Vec::new();

        // 1. Every normal bitcoin-rs edge points to the same or a lower layer.
        let mut checked_edges = 0_usize;
        for (name, edges) in &self.normal_deps {
            let layer = approved_layer(name);
            for dep in edges {
                let dep_layer = approved_layer(dep);
                if dep_layer > layer {
                    violations.push(format!(
                        "dependency direction violation: `{name}` (layer {layer}) depends on \
                         `{dep}` (layer {dep_layer}); edges must point down the layer model"
                    ));
                }
                checked_edges += 1;
            }
        }

        // 2. No crate outside storage names a storage-engine dependency.
        let mut checked_engine_edges = 0_usize;
        for (name, engines) in &self.engine_deps {
            if name != STORAGE_CRATE && !engines.is_empty() {
                violations.push(format!(
                    "engine dependencies {engines:?} must be named by `{STORAGE_CRATE}` only; \
                     found on `{name}`"
                ));
            }
            checked_engine_edges += engines.len();
        }

        // 3. RPC names no storage backend at all.
        if let Some(rpc_edges) = self.normal_deps.get(RPC_CRATE) {
            for dep in rpc_edges {
                if dep == STORAGE_CRATE {
                    violations.push(
                        "rpc must not depend on the storage crate; it consumes node capabilities \
                         through query traits"
                            .to_owned(),
                    );
                }
                if ENGINE_CRATES.contains(&dep.as_str()) {
                    violations.push(format!("rpc must not name the engine dependency `{dep}`"));
                }
            }
        }

        let rpc_features = self.features.get(RPC_CRATE);
        if let Some(rpc_features) = rpc_features {
            for (feature, implies) in rpc_features {
                let forwards = BACKEND_FEATURES.contains(&feature.as_str())
                    || implies.iter().any(|entry| {
                        BACKEND_FEATURES
                            .iter()
                            .any(|backend| entry.contains(backend))
                    });
                if forwards {
                    violations.push(format!(
                        "rpc feature `{feature}` still forwards a storage backend"
                    ));
                }
            }
        }

        let mut checked_features = 0_usize;
        checked_features += self.validate_backend_forwarding(&mut violations);

        // 5. The external ZMQ dependency is owned by the RPC surface crate.
        //    Node may forward the surface feature but must not name the
        //    external dependency directly.
        checked_features += self.validate_zmq_surface(&mut violations);

        if violations.is_empty() {
            Ok(Validation {
                checked_edges,
                checked_engine_edges,
                checked_features,
                classified: self.classified,
                summary: format!(
                    "dependency direction: {checked_edges} edges; \
                     engine edges: {checked_engine_edges}; features: {checked_features}; \
                     classified crates: {}",
                    self.classified
                ),
            })
        } else {
            Err(violations)
        }
    }

    /// Rule 4: backend features carry a real backend choice and only the
    /// forwarding allowlist may define them (see `BACKEND_FORWARDING_CRATES`).
    fn validate_backend_forwarding(&self, violations: &mut Vec<String>) -> usize {
        let mut checked_features = 0_usize;
        for (name, feature_map) in &self.features {
            for (feature, implies) in feature_map {
                checked_features += 1;
                if !BACKEND_FEATURES.contains(&feature.as_str()) {
                    continue;
                }
                if !BACKEND_FORWARDING_CRATES.contains(&name.as_str()) {
                    violations.push(format!(
                        "`{name}` must not define or forward the backend feature `{feature}`"
                    ));
                    continue;
                }
                if implies.is_empty() {
                    violations.push(format!(
                        "`{name}` defines empty backend marker `{feature}`; backend features \
                         must forward into storage or an approved adapter that does"
                    ));
                    continue;
                }
                let forwards = if name == STORAGE_CRATE {
                    implies.iter().all(|entry| {
                        let entry = entry.trim_start_matches("dep:");
                        ENGINE_CRATES.contains(&entry)
                    })
                } else {
                    implies.iter().all(|entry| {
                        let entry = entry.trim_start_matches("dep:");
                        let mut parts = entry.split('/');
                        let target = parts.next().unwrap_or_default();
                        let forwarded_feature = parts.next().unwrap_or_default();
                        parts.next().is_none()
                            && BACKEND_FORWARDING_CRATES.contains(&target)
                            && forwarded_feature == feature.as_str()
                    })
                };
                if !forwards {
                    violations.push(format!(
                        "`{name}` defines backend feature `{feature}` without matching \
                         forwarding into an approved adapter or storage crate with the same \
                         feature name"
                    ));
                }
            }
        }

        checked_features
    }

    /// Validates the ZMQ surface ownership boundary: the external ZMQ
    /// dependency is owned by the RPC surface crate, and node forwards
    /// the surface feature without naming the dependency directly.
    /// Returns the number of feature assertions checked.
    fn validate_zmq_surface(&self, violations: &mut Vec<String>) -> usize {
        let mut checked = 0_usize;
        for (name, dependencies) in &self.zmq_deps {
            if name != RPC_CRATE && !dependencies.is_empty() {
                violations.push(format!(
                    "the external ZMQ dependency must be owned by `{RPC_CRATE}`; found on `{name}`"
                ));
            }
            checked += dependencies.len();
        }
        match self
            .features
            .get(RPC_CRATE)
            .and_then(|feature_map| feature_map.get("zmq"))
        {
            Some(implies) if implies.iter().any(|entry| entry == "dep:zmq") => {
                checked += 1;
            }
            _ => violations
                .push("the RPC `zmq` feature must enable its owned external dependency".to_owned()),
        }
        let node_zmq = self
            .features
            .get(NODE_CRATE)
            .and_then(|feature_map| feature_map.get("zmq"));
        match node_zmq {
            Some(implies) if implies.iter().any(|entry| entry == "bitcoin-rs-rpc/zmq") => {
                checked += 1;
            }
            _ => violations
                .push("the node `zmq` feature must forward the RPC surface feature".to_owned()),
        }
        match node_zmq {
            Some(implies) if implies.iter().all(|entry| entry != "dep:zmq") => {
                checked += 1;
            }
            _ => violations.push(
                "the node `zmq` feature must not enable a direct external dependency".to_owned(),
            ),
        }
        checked
    }

    /// Resolves one binary feature profile to the activated workspace
    /// crate/feature sets, walking the same `crate/feature` and `dep:` token
    /// chains as `g19_validation_default`.
    ///
    /// Dependency-edge default features are deliberately not modeled: the
    /// workspace pins `default-features = false` on the consensus and node
    /// edges, and every engine surface (kernel, zmq, backends) reaches the
    /// binary only through the explicit forwarding chains this walk follows.
    pub(crate) fn resolve_profile(
        &self,
        profile: &FeatureProfile,
    ) -> BTreeMap<String, BTreeSet<String>> {
        let mut activated: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
        let mut queue: Vec<(String, String)> = Vec::new();
        if profile.defaults
            && let Some(defaults) = self
                .features
                .get(BIN_CRATE)
                .and_then(|features| features.get("default"))
        {
            for feature in defaults {
                queue.push((BIN_CRATE.to_owned(), feature.clone()));
            }
        }
        for feature in profile.features {
            queue.push((BIN_CRATE.to_owned(), (*feature).to_owned()));
        }
        while let Some((package, feature)) = queue.pop() {
            if !activated
                .entry(package.clone())
                .or_default()
                .insert(feature.clone())
            {
                continue;
            }
            let Some(implies) = self
                .features
                .get(&package)
                .and_then(|features| features.get(&feature))
            else {
                continue;
            };
            for token in implies {
                if let Some((target, target_feature)) = token.split_once('/') {
                    let target = target.trim_end_matches('?');
                    queue.push((target.to_owned(), target_feature.to_owned()));
                } else if token == "default" {
                    if let Some(defaults) = self
                        .features
                        .get(&package)
                        .and_then(|features| features.get("default"))
                    {
                        for default in defaults {
                            queue.push((package.clone(), default.clone()));
                        }
                    }
                } else {
                    // Same-package features and `dep:` activation markers.
                    queue.push((package.clone(), token.clone()));
                }
            }
        }
        activated
    }

    /// Returns the ownership violations of one binary feature profile: the
    /// profile must reach a storage backend through the node forwarding
    /// chain, backend features must stay on the forwarding allowlist, and
    /// the kernel and ZMQ engines must follow their explicit selection
    /// chains — present exactly when the profile selects them.
    pub(crate) fn profile_ownership_violations(&self, profile: &FeatureProfile) -> Vec<String> {
        let activated = self.resolve_profile(profile);
        let mut violations = Vec::new();

        // The backend must reach the storage crate as an activated feature
        // through the node forwarding chain: a backend feature name at node
        // alone does not compose storage. Storage declares every backend by
        // its plain name (`fjall`, `redb`, `rocksdb`), so the plain test
        // covers every engine uniformly.
        let backend_reached = activated.get(STORAGE_CRATE).is_some_and(|features| {
            features
                .iter()
                .any(|feature| BACKEND_FEATURES.contains(&feature.as_str()))
        });
        if !backend_reached {
            violations.push(format!(
                "profile `{}` activates no storage backend through the node \
                 forwarding chain; a node without a backend cannot compose its \
                 storage",
                profile.name
            ));
        }

        let node_features = activated.get(NODE_CRATE);
        for (package, features) in &activated {
            for feature in features {
                if BACKEND_FEATURES.contains(&feature.as_str())
                    && !BACKEND_FORWARDING_CRATES.contains(&package.as_str())
                {
                    violations.push(format!(
                        "profile `{}` activates backend feature `{feature}` on \
                         non-forwarding crate `{package}`",
                        profile.name
                    ));
                }
            }
        }

        let kernel_selected = node_features.is_some_and(|features| features.contains("kernel"));
        let consensus_kernel = activated
            .get("bitcoin-rs-consensus")
            .is_some_and(|features| features.contains("dep:bitcoinkernel"));
        if kernel_selected != consensus_kernel {
            violations.push(if kernel_selected {
                format!(
                    "profile `{}` selects `kernel` without reaching `dep:bitcoinkernel` \
                     on `bitcoin-rs-consensus`",
                    profile.name
                )
            } else {
                format!(
                    "profile `{}` must keep the kernel engine out of the production graph",
                    profile.name
                )
            });
        }

        let zmq_selected = activated
            .get(BIN_CRATE)
            .is_some_and(|features| features.contains("zmq"));
        let zmq_owned = activated
            .get(RPC_CRATE)
            .is_some_and(|features| features.contains("dep:zmq"));
        if zmq_selected != zmq_owned {
            violations.push(if zmq_selected {
                format!(
                    "profile `{}` selects `zmq` without enabling the owned `dep:zmq` \
                     dependency on `{RPC_CRATE}`",
                    profile.name
                )
            } else {
                format!(
                    "profile `{}` must keep the ZMQ surface out of the production graph",
                    profile.name
                )
            });
        }

        violations
    }
}
