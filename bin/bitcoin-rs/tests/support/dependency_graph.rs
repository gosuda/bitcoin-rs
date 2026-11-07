#![expect(
    clippy::expect_used,
    reason = "malformed Cargo metadata is a test failure"
)]

use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _};
use std::collections::{BTreeMap, BTreeSet};
use std::process::Command;
#[cfg(test)]
#[path = "dependency_graph_tests.rs"]
mod tests;

pub(crate) const ENGINE_CRATES: [&str; 6] = [
    "fjall",
    "redb",
    "rust-rocksdb",
    "surrealkv",
    "signet-libmdbx",
    "tokio",
];
pub(crate) const ZMQ_CRATE: &str = "zmq";

pub(crate) const STORAGE_CRATE: &str = "bitcoin-rs-storage";
pub(crate) const CONVERTER_CRATE: &str = "bitcoin-rs-storage-convert";

pub(crate) const SERVING_CRATE: &str = "bitcoin-rs-serving";

pub(crate) const NODE_CRATE: &str = "bitcoin-rs-node";

pub(crate) const BIN_CRATE: &str = "bitcoin-rs";
pub(crate) const MEMPOOL_CRATE: &str = "bitcoin-rs-mempool";
pub(crate) const CHAINSTATE_CRATE: &str = "bitcoin-rs-execution";

pub(crate) const MEMPOOL_CONSUMER_CRATES: [&str; 4] =
    ["bitcoin-rs-wire", SERVING_CRATE, NODE_CRATE, BIN_CRATE];

pub(crate) fn approved_layer(crate_name: &str) -> u8 {
    match crate_name {
        "bitcoin-rs-consensus" => 0,
        STORAGE_CRATE => 1,
        CHAINSTATE_CRATE | "bitcoin-rs-wire" | "bitcoin-rs-mempool" | "bitcoin-rs-projection" => 2,
        SERVING_CRATE => 3,
        NODE_CRATE
        | BIN_CRATE
        | "bitcoin-rs-e2e"
        | "bitcoin-rs-storage-footprint"
        | "bitcoin-rs-snapshot"
        | "bitcoin-rs-p2pk-scan"
        | CONVERTER_CRATE
        | "contract-index" => 4,
        other => panic!("unclassified workspace crate `{other}`: add it to the layer table"),
    }
}

struct FeatureDependency {
    name: String,
    alias: String,
    features: Vec<String>,
    uses_default_features: bool,
}

pub(crate) struct WorkspaceGraph {
    normal_deps: BTreeMap<String, Vec<String>>,
    engine_deps: BTreeMap<String, Vec<String>>,
    zmq_deps: BTreeMap<String, Vec<String>>,
    features: BTreeMap<String, BTreeMap<String, Vec<String>>>,
    production_deps: BTreeMap<String, Vec<FeatureDependency>>,
    pub classified: usize,
}

#[derive(Debug)]
pub(crate) struct Validation {
    pub checked_edges: usize,
    pub checked_features: usize,
    pub cycle_checked_crates: usize,
    pub summary: String,
}

pub(crate) fn workspace_root_manifest() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("Cargo.toml")
}

fn run_cargo_metadata() -> sonic_rs::Value {
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
    sonic_rs::from_slice(&output.stdout).expect("parse cargo metadata JSON")
}

impl WorkspaceGraph {
    pub(crate) fn from_cargo_metadata() -> Self {
        Self::from_json(&run_cargo_metadata())
    }

    pub(crate) fn from_json(metadata: &sonic_rs::Value) -> Self {
        let mut normal_deps = BTreeMap::new();
        let mut engine_deps = BTreeMap::new();
        let mut zmq_deps = BTreeMap::new();
        let mut features = BTreeMap::new();
        let mut production_deps = BTreeMap::new();
        let mut classified = 0_usize;

        for package in metadata["packages"].as_array().expect("packages array") {
            let name = package["name"].as_str().expect("package name").to_owned();
            let _ = approved_layer(&name);
            classified += 1;

            let mut edges = Vec::new();
            let mut engines = Vec::new();
            let mut zmq = Vec::new();
            let mut feature_deps = Vec::new();
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
                if matches!(
                    dependency["kind"].as_str().unwrap_or("normal"),
                    "normal" | "build"
                ) {
                    feature_deps.push(FeatureDependency {
                        alias: dependency["rename"]
                            .as_str()
                            .unwrap_or(&dep_name)
                            .to_owned(),
                        name: dep_name.clone(),
                        features: dependency["features"]
                            .as_array()
                            .expect("dependency features")
                            .iter()
                            .map(|feature| feature.as_str().expect("dependency feature").to_owned())
                            .collect(),
                        uses_default_features: dependency["uses_default_features"]
                            .as_bool()
                            .expect("dependency default-features flag"),
                    });
                    edges.push(dep_name);
                }
            }
            normal_deps.insert(name.clone(), edges);
            engine_deps.insert(name.clone(), engines);
            zmq_deps.insert(name.clone(), zmq);
            production_deps.insert(name.clone(), feature_deps);

            let mut feature_map = BTreeMap::new();
            for (feature, implies) in package["features"].as_object().expect("features object") {
                let implies: Vec<String> = implies
                    .as_array()
                    .expect("feature implies array")
                    .iter()
                    .map(|value| value.as_str().expect("feature string").to_owned())
                    .collect();
                feature_map.insert(feature.to_owned(), implies);
            }
            features.insert(name, feature_map);
        }

        Self {
            normal_deps,
            engine_deps,
            zmq_deps,
            features,
            production_deps,
            classified,
        }
    }

    pub(crate) fn validate(&self) -> Result<Validation, Vec<String>> {
        let mut violations = Vec::new();

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

        if let Some(mempool_edges) = self.normal_deps.get(MEMPOOL_CRATE) {
            for dep in mempool_edges {
                if MEMPOOL_CONSUMER_CRATES.contains(&dep.as_str()) {
                    violations.push(format!(
                        "dependency direction violation: `{MEMPOOL_CRATE}` must not depend on \
                         its transaction consumer `{dep}`; consumers depend on the mempool"
                    ));
                }
            }
        }

        let execution_present = self.normal_deps.contains_key("bitcoin-rs-execution")
            || self
                .normal_deps
                .values()
                .any(|edges| edges.iter().any(|d| d == "bitcoin-rs-execution"));
        if execution_present {
            for (name, edges) in &self.normal_deps {
                let layer = approved_layer(name);
                for dep in edges {
                    let dep_layer = approved_layer(dep);
                    if dep_layer == layer
                        && layer < 4
                        && !(name == "bitcoin-rs-projection" && dep == "bitcoin-rs-execution")
                    {
                        violations.push(format!(
                            "same-layer edge violation: `{name}` (layer {layer}) depends on `{dep}` (layer {dep_layer}); only projection -> execution is permitted"
                        ));
                    }
                }
            }
        }

        let cycle_checked_crates = self.detect_cycles(&mut violations);

        let mut checked_engine_edges = 0_usize;
        for (name, engines) in &self.engine_deps {
            for engine in engines {
                checked_engine_edges += 1;
                match (name.as_str(), engine.as_str()) {
                    (STORAGE_CRATE, "rust-rocksdb" | "surrealkv" | "signet-libmdbx" | "tokio") => {}
                    (CONVERTER_CRATE, "fjall" | "redb") => {}
                    (STORAGE_CRATE, other) => {
                        violations.push(format!(
                            "`{STORAGE_CRATE}` may only name `rust-rocksdb`, `surrealkv`, `signet-libmdbx`, or `tokio` as an engine; found `{other}`"
                        ));
                    }
                    (CONVERTER_CRATE, other) => {
                        violations.push(format!(
                            "`{CONVERTER_CRATE}` may only name `fjall` and `redb` to read retired datadirs; found `{other}`"
                        ));
                    }
                    (other, engine) => {
                        violations.push(format!(
                            "engine dependency `{engine}` must not be named by `{other}`"
                        ));
                    }
                }
            }
        }

        if let Some(serving_edges) = self.normal_deps.get(SERVING_CRATE) {
            for dep in serving_edges {
                if ENGINE_CRATES.contains(&dep.as_str()) {
                    violations.push(format!(
                        "serving must not name the engine dependency `{dep}`"
                    ));
                }
            }
        }

        let mut checked_features = 0_usize;
        checked_features += self.validate_backend_features(&mut violations);
        checked_features += self.validate_zmq_surface(&mut violations);
        checked_features += self.validate_test_seam_isolation(&mut violations);

        if violations.is_empty() {
            Ok(Validation {
                checked_edges,
                checked_features,
                cycle_checked_crates,
                summary: format!(
                    "dependency direction: {checked_edges} edges; \
                     engine edges: {checked_engine_edges}; features: {checked_features}; \
                     cycle-checked crates: {cycle_checked_crates}; classified crates: {}",
                    self.classified
                ),
            })
        } else {
            Err(violations)
        }
    }

    fn validate_zmq_surface(&self, violations: &mut Vec<String>) -> usize {
        let mut checked = 0_usize;
        for (name, dependencies) in &self.zmq_deps {
            if name != SERVING_CRATE && !dependencies.is_empty() {
                violations.push(format!(
                    "the external ZMQ dependency must be owned by `{SERVING_CRATE}`; found on `{name}`"
                ));
            }
            checked += dependencies.len();
        }
        match self
            .features
            .get(SERVING_CRATE)
            .and_then(|feature_map| feature_map.get("zmq"))
        {
            Some(implies) if implies.iter().any(|entry| entry == "dep:zmq") => {
                checked += 1;
            }
            _ => violations.push(
                "the serving `zmq` feature must enable its owned external dependency".to_owned(),
            ),
        }
        let node_zmq = self
            .features
            .get(NODE_CRATE)
            .and_then(|feature_map| feature_map.get("zmq"));
        match node_zmq {
            Some(implies)
                if implies
                    .iter()
                    .any(|entry| entry == "bitcoin-rs-serving/zmq") =>
            {
                checked += 1;
            }
            _ => violations
                .push("the node `zmq` feature must forward the serving surface feature".to_owned()),
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

    fn validate_backend_features(&self, violations: &mut Vec<String>) -> usize {
        let mut checked = 0_usize;
        checked += self.validate_storage_tokio_feature(violations);
        checked += self.validate_backend_forwarding_allowlist(violations);
        checked
    }

    fn validate_storage_tokio_feature(&self, violations: &mut Vec<String>) -> usize {
        let Some(features) = self.features.get(STORAGE_CRATE) else {
            return 0;
        };
        for (feature, implies) in features {
            let enables_tokio = implies.iter().any(|entry| entry == "dep:tokio");
            if enables_tokio && feature != "surrealkv" {
                violations.push(format!(
                    "`{STORAGE_CRATE}` feature `{feature}` must not enable `dep:tokio`; only `surrealkv` may enable tokio"
                ));
            }
        }
        features.len()
    }

    fn validate_backend_forwarding_allowlist(&self, violations: &mut Vec<String>) -> usize {
        const ALLOWED: [&str; 7] = [
            STORAGE_CRATE,
            "bitcoin-rs-utxo",
            CHAINSTATE_CRATE,
            "bitcoin-rs-projection",
            NODE_CRATE,
            BIN_CRATE,
            CONVERTER_CRATE,
        ];
        let mut checked = 0;
        for (crate_name, feature_map) in &self.features {
            let crate_allowed = ALLOWED.contains(&crate_name.as_str());
            for (feature, implies) in feature_map {
                checked += 1;
                let forwards = feature == "surrealkv"
                    || feature == "mdbx"
                    || implies
                        .iter()
                        .any(|entry| entry.ends_with("/surrealkv") || entry.ends_with("/mdbx"));
                if forwards && !crate_allowed {
                    violations.push(format!(
                        "`{crate_name}` must not define or forward backend feature `{feature}`"
                    ));
                }
            }
        }
        checked
    }

    fn validate_test_seam_isolation(&self, violations: &mut Vec<String>) -> usize {
        let mut checked = 0;
        for (name, dependencies) in &self.production_deps {
            for dependency in dependencies {
                let selected = dependency
                    .features
                    .iter()
                    .map(String::as_str)
                    .chain(dependency.uses_default_features.then_some("default"));
                for feature in selected {
                    checked += 1;
                    if let Some(target) = self.test_seam_target(&dependency.name, feature) {
                        violations.push(format!(
                            "production dependency `{name}` -> `{}` selects `{feature}`, \
                             enabling `{target}/test-seam`",
                            dependency.name
                        ));
                    }
                }
            }
        }
        for (name, features) in &self.features {
            for feature in features.keys().filter(|feature| *feature != "test-seam") {
                checked += 1;
                if let Some(target) = self.test_seam_target(name, feature) {
                    violations.push(format!(
                        "production feature `{name}/{feature}` enables `{target}/test-seam`"
                    ));
                }
            }
        }
        checked
    }

    fn test_seam_target<'a>(&'a self, name: &'a str, feature: &'a str) -> Option<&'a str> {
        let mut pending = vec![(name, feature)];
        let mut visited = BTreeSet::new();
        while let Some((name, feature)) = pending.pop() {
            if !visited.insert((name, feature)) {
                continue;
            }
            if feature == "test-seam" {
                return Some(name);
            }
            let Some(implies) = self
                .features
                .get(name)
                .and_then(|features| features.get(feature))
            else {
                continue;
            };
            for entry in implies {
                if let Some((alias, forwarded)) = entry.split_once('/') {
                    for dependency in self.production_deps.get(name).into_iter().flatten() {
                        if dependency.alias == alias.trim_end_matches('?') {
                            pending.push((&dependency.name, forwarded));
                        }
                    }
                } else if !entry.starts_with("dep:") {
                    pending.push((name, entry));
                }
            }
        }
        None
    }

    fn detect_cycles(&self, violations: &mut Vec<String>) -> usize {
        let mut color: BTreeMap<&str, u8> = BTreeMap::new();
        let mut stack: Vec<String> = Vec::new();

        fn visit<'a>(
            graph: &'a WorkspaceGraph,
            color: &mut BTreeMap<&'a str, u8>,
            stack: &mut Vec<String>,
            violations: &mut Vec<String>,
            node: &'a str,
        ) {
            color.insert(node, 1);
            stack.push(node.to_owned());
            for next in graph.normal_deps.get(node).into_iter().flatten() {
                match color.get(next.as_str()).copied().unwrap_or(0) {
                    0 => visit(graph, color, stack, violations, next),
                    1 => {
                        let cycle = stack
                            .iter()
                            .skip_while(|n| n.as_str() != next.as_str())
                            .cloned()
                            .chain(std::iter::once(next.to_owned()))
                            .collect::<Vec<_>>()
                            .join("` -> `");
                        violations.push(format!(
                            "dependency direction violation: workspace dependency cycle: \
                             `{cycle}`; edges must form an acyclic DAG"
                        ));
                    }
                    _ => {}
                }
            }
            stack.pop();
            color.insert(node, 2);
        }

        for node in self.normal_deps.keys() {
            if color.get(node.as_str()).copied().unwrap_or(0) == 0 {
                visit(self, &mut color, &mut stack, violations, node);
            }
        }

        color.len()
    }
}
