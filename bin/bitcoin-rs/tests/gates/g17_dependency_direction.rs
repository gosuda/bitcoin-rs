//! G17 — One-way crate dependency direction.
//!
//! **G17 — Dependency direction.** The workspace crates form a one-way layer
//! model; `cargo metadata` proves every edge points the approved way, no crate
//! outside `bitcoin-rs-storage` names a storage-engine dependency
//! (`rust-rocksdb`, `fjall`, `redb`, `signet-libmdbx`), and the RPC crate
//! names no storage backend at all — neither as a dependency nor as a
//! forwarded cargo feature.
//!
//! Approved layer direction (a crate may depend only on crates in the same or
//! a strictly lower layer):
//!
//! ```text
//!   layer 0  core       consensus, script, primitives
//!   layer 1  storage    storage
//!   layer 2  services   chain, utxo, p2p, mempool, index, mining
//!   layer 3  surface    rpc
//!   layer 4  compose    node, bin (bitcoin-rs)
//! ```
//!
//! Notes that keep this model honest rather than aspirational:
//! - `chain` and `utxo` depend on `storage` (undo records, snapshots), so they
//!   sit in the services layer, not core.
//! - `mining` depends on `mempool` and `chain`; all three live in services.
//! - `p2p` depends on `mempool` for transaction inventory and relay consumers.
//!   `mempool` cannot depend back on p2p, RPC, node, or the binary: admission
//!   owns transaction state without owning its network or runtime consumers.
//! - `chain` depends on `consensus` for BIP9 parameters and the BIP113 cutoff.
//! - `rpc` may consume node capabilities (`index`, `mining`, `mempool`,
//!   `chain`, `utxo`, `p2p`) but never `node` or the binary, and never names a
//!   storage backend.
//! - The engine rule is the storage-boundary rule: only the storage crate may
//!   name a backend engine. Everything above talks to the `KvStore` facade.
//! - Backend *feature* forwarding is confined to the operator-facing tiers
//!   (node, binary) and the services-tier adapters; rpc forwards none.
//!
//! The gate fails loudly, naming the offending edge, when any assertion does
//! not hold.
//!
//! Contract: `docs/contracts/architecture.md` —
//! `workspace_dependency_direction_is_one_way` pins `ARCH-01` (one-way
//! layer edges), `ARCH-02` (engine-crate exclusivity), `ARCH-03` (backend
//! feature-forwarding confinement), and `ARCH-04` (RPC storage
//! independence).

#![allow(clippy::expect_used)]

use std::collections::BTreeMap;
use std::process::Command;

/// Storage engine crates. Only `bitcoin-rs-storage` may depend on these.
const ENGINE_CRATES: [&str; 4] = ["fjall", "redb", "rust-rocksdb", "signet-libmdbx"];

/// External ZMQ implementation dependency owned by the surface crate.
const ZMQ_CRATE: &str = "zmq";

/// Backend feature names whose forwarding above storage is forbidden.
const BACKEND_FEATURES: [&str; 4] = ["rocksdb", "fjall", "redb", "mdbx"];

/// The crate that owns every storage engine dependency.
const STORAGE_CRATE: &str = "bitcoin-rs-storage";

/// The RPC surface crate.
const RPC_CRATE: &str = "bitcoin-rs-rpc";

/// Transaction admission and lifecycle owner.
const MEMPOOL_CRATE: &str = "bitcoin-rs-mempool";

/// Peer transaction inventory and relay owner.
const P2P_CRATE: &str = "bitcoin-rs-p2p";

/// The node composition crate.
const NODE_CRATE: &str = "bitcoin-rs-node";

/// The node binary.
const BIN_CRATE: &str = "bitcoin-rs";

/// Workspace root manifest, resolved relative to the gate's own checkout.
fn workspace_root_manifest() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("Cargo.toml")
}

/// Approved layer for each workspace crate.
fn approved_layer(crate_name: &str) -> u8 {
    match crate_name {
        "bitcoin-rs-primitives" | "bitcoin-rs-script" | "bitcoin-rs-consensus" => 0,
        STORAGE_CRATE => 1,
        "bitcoin-rs-chain" | "bitcoin-rs-utxo" | "bitcoin-rs-p2p" | "bitcoin-rs-mempool"
        | "bitcoin-rs-index" | "bitcoin-rs-mining" => 2,
        RPC_CRATE => 3,
        NODE_CRATE | BIN_CRATE => 4,
        other => panic!("unclassified workspace crate `{other}`: add it to the layer table"),
    }
}

struct WorkspaceMetadata {
    normal_deps: BTreeMap<String, Vec<String>>,
    engine_deps: BTreeMap<String, Vec<String>>,
    zmq_deps: BTreeMap<String, Vec<String>>,
    features: BTreeMap<String, BTreeMap<String, Vec<String>>>,
    classified: usize,
}

fn assert_internal_dependencies_point_down(normal_deps: &BTreeMap<String, Vec<String>>) {
    let mut checked_edges = 0_usize;
    for (name, edges) in normal_deps {
        let layer = approved_layer(name);
        for dep in edges {
            let dep_layer = approved_layer(dep);
            assert!(
                dep_layer <= layer,
                "dependency direction violation: `{name}` (layer {layer}) depends on \
                 `{dep}` (layer {dep_layer}); edges must point down the layer model"
            );
            checked_edges += 1;
        }
    }
    assert!(
        checked_edges > 0,
        "no internal edges were checked; the metadata parse is suspect"
    );
}

fn assert_storage_owns_engine_dependencies(engine_deps: &BTreeMap<String, Vec<String>>) {
    for (name, engines) in engine_deps {
        assert!(
            name == STORAGE_CRATE || engines.is_empty(),
            "engine dependencies {engines:?} must be named by `{STORAGE_CRATE}` only; \
             found on `{name}`"
        );
    }
}

fn assert_mempool_is_independent_of_transaction_consumers(
    normal_deps: &BTreeMap<String, Vec<String>>,
) {
    let mempool_edges = normal_deps.get(MEMPOOL_CRATE).expect("mempool in metadata");
    for consumer in [P2P_CRATE, RPC_CRATE, NODE_CRATE, BIN_CRATE] {
        assert!(
            mempool_edges
                .iter()
                .all(|dependency| dependency != consumer),
            "mempool must not depend on transaction consumer `{consumer}`; \
             p2p, RPC, and node consume mempool admission and lifecycle state"
        );
    }
}

fn assert_rpc_owns_zmq_dependency(
    zmq_deps: &BTreeMap<String, Vec<String>>,
    features: &BTreeMap<String, BTreeMap<String, Vec<String>>>,
) {
    for (name, dependencies) in zmq_deps {
        assert!(
            name == RPC_CRATE || dependencies.is_empty(),
            "the external ZMQ dependency must be owned by `{RPC_CRATE}`; found on `{name}`"
        );
    }
    assert!(
        features[RPC_CRATE]["zmq"]
            .iter()
            .any(|entry| entry == "dep:zmq"),
        "the RPC `zmq` feature must enable its owned external dependency"
    );
    assert!(
        features[NODE_CRATE]["zmq"]
            .iter()
            .any(|entry| entry == "bitcoin-rs-rpc/zmq"),
        "the node `zmq` feature must forward the RPC surface feature"
    );
    assert!(
        features[NODE_CRATE]["zmq"]
            .iter()
            .all(|entry| entry != "dep:zmq"),
        "the node `zmq` feature must not enable a direct external dependency"
    );
}

fn assert_rpc_is_storage_independent(
    normal_deps: &BTreeMap<String, Vec<String>>,
    features: &BTreeMap<String, BTreeMap<String, Vec<String>>>,
) {
    let rpc_edges = normal_deps.get(RPC_CRATE).expect("rpc in metadata");
    for dep in rpc_edges {
        assert_ne!(
            dep.as_str(),
            STORAGE_CRATE,
            "rpc must not depend on the storage crate; it consumes node capabilities \
             through query traits"
        );
        assert!(
            !ENGINE_CRATES.contains(&dep.as_str()),
            "rpc must not name the engine dependency `{dep}`"
        );
    }
    let rpc_features = features.get(RPC_CRATE).expect("rpc features");
    for (feature, implies) in rpc_features {
        let forwards = BACKEND_FEATURES.contains(&feature.as_str())
            || implies.iter().any(|entry| {
                BACKEND_FEATURES
                    .iter()
                    .any(|backend| entry.contains(backend))
            });
        assert!(
            !forwards,
            "rpc feature `{feature}` still forwards a storage backend"
        );
    }
}

fn assert_backend_feature_forwarding_is_confined(
    features: &BTreeMap<String, BTreeMap<String, Vec<String>>>,
) {
    for (name, feature_map) in features {
        if name == STORAGE_CRATE || name == RPC_CRATE {
            continue;
        }
        let carries_choice = approved_layer(name) >= 2;
        for (feature, implies) in feature_map {
            let forwards = BACKEND_FEATURES.contains(&feature.as_str())
                || implies.iter().any(|entry| {
                    let entry = entry.trim_start_matches("dep:");
                    BACKEND_FEATURES
                        .iter()
                        .any(|backend| entry.split('/').next() == Some(backend))
                });
            if !forwards || carries_choice || implies.is_empty() {
                continue;
            }
            panic!(
                "`{name}` forwards the backend feature `{feature}`; backend feature \
                 forwarding above storage is allowed only on node, the binary, and \
                 the services-tier adapters"
            );
        }
    }
}

fn workspace_metadata() -> WorkspaceMetadata {
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
            if dependency["kind"].as_str().unwrap_or("normal") == "normal" {
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
    WorkspaceMetadata {
        normal_deps,
        engine_deps,
        zmq_deps,
        features,
        classified,
    }
}

#[test]
fn workspace_dependency_direction_is_one_way() {
    let WorkspaceMetadata {
        normal_deps,
        engine_deps,
        zmq_deps,
        features,
        classified,
    } = workspace_metadata();
    assert!(
        classified >= 12,
        "workspace crates went missing from metadata: {classified} classified"
    );

    // 1. Every normal bitcoin-rs edge points to the same or a lower layer.
    assert_internal_dependencies_point_down(&normal_deps);

    // Same-layer edges still respect transaction ownership: p2p consumes
    // mempool queries, never the reverse.
    assert_mempool_is_independent_of_transaction_consumers(&normal_deps);

    // 2. No crate outside storage names a storage-engine dependency (any
    //    dependency kind counts: an engine must not leak in as a dev-dep
    //    either).
    assert_storage_owns_engine_dependencies(&engine_deps);

    // The Surface tier owns the external ZMQ implementation. Node may forward
    // the surface feature, but must not regain a direct libzmq dependency.
    assert_rpc_owns_zmq_dependency(&zmq_deps, &features);

    // 3. RPC names no storage backend at all: no non-test dependency edge on
    //    the storage crate (the bench-only dev-dependency that feeds the
    //    `txoutproof` fixture is documented in the rpc manifest) and no
    //    forwarded backend feature.
    assert_rpc_is_storage_independent(&normal_deps, &features);

    // 4. Backend feature forwarding is confined to the tiers that must carry
    //    the operator's backend choice: node and the binary (operator-facing
    //    feature tables) and the services-tier adapter crates (whose backend
    //    features exist so `-p` selection propagates into storage). The RPC
    //    surface forwards none, and workspace-selection marker features that
    //    gate no code are tolerated.
    assert_backend_feature_forwarding_is_confined(&features);
}

#[test]
fn transaction_consumers_can_depend_on_mempool() {
    let dependencies = BTreeMap::from([
        (MEMPOOL_CRATE.to_owned(), Vec::new()),
        (P2P_CRATE.to_owned(), vec![MEMPOOL_CRATE.to_owned()]),
        (RPC_CRATE.to_owned(), vec![MEMPOOL_CRATE.to_owned()]),
        (NODE_CRATE.to_owned(), vec![MEMPOOL_CRATE.to_owned()]),
    ]);
    assert_internal_dependencies_point_down(&dependencies);
    assert_mempool_is_independent_of_transaction_consumers(&dependencies);
}

#[test]
fn mempool_cannot_depend_on_transaction_consumers() {
    for consumer in [P2P_CRATE, RPC_CRATE, NODE_CRATE, BIN_CRATE] {
        let dependencies = BTreeMap::from([(MEMPOOL_CRATE.to_owned(), vec![consumer.to_owned()])]);
        let result = std::panic::catch_unwind(|| {
            assert_mempool_is_independent_of_transaction_consumers(&dependencies);
        });
        assert!(result.is_err(), "mempool dependency on {consumer} passed");
    }
}
