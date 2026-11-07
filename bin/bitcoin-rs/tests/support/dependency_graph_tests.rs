use super::WorkspaceGraph;
use sonic_rs::{JsonValueMutTrait as _, Value, json};

fn dependency(name: &str, kind: Option<&str>, features: &[&str]) -> Value {
    json!({
        "name": name,
        "rename": null,
        "kind": kind,
        "features": features,
        "uses_default_features": false,
        "optional": false,
        "target": null,
    })
}

fn fixture() -> Value {
    json!({"packages": [
        {
            "name": "bitcoin-rs-consensus",
            "dependencies": [],
            "features": {"default": [], "test-seam": []},
        },
        {
            "name": "bitcoin-rs-execution",
            "dependencies": [dependency("bitcoin-rs-consensus", None, &[])],
            "features": {"default": [], "test-seam": []},
        },
        {
            "name": "bitcoin-rs-rpc",
            "dependencies": [dependency("zmq", None, &[])],
            "features": {"zmq": ["dep:zmq"]},
        },
        {
            "name": "bitcoin-rs-node",
            "dependencies": [
                dependency("bitcoin-rs-execution", None, &[]),
                dependency("bitcoin-rs-rpc", None, &[]),
            ],
            "features": {"default": [], "zmq": ["bitcoin-rs-rpc/zmq"]},
        },
    ]})
}

fn package<'a>(metadata: &'a mut Value, name: &str) -> &'a mut Value {
    metadata["packages"]
        .as_array_mut()
        .expect("fixture packages")
        .iter_mut()
        .find(|package| package["name"] == name)
        .expect("fixture package")
}

fn assert_test_seam_rejected(metadata: &Value, origin: &str, target: &str) {
    let violations = WorkspaceGraph::from_json(metadata)
        .validate()
        .expect_err("production test-seam must be rejected");
    assert!(
        violations
            .iter()
            .all(|violation| violation.contains("test-seam")),
        "fixture failed for an unrelated graph rule: {violations:?}"
    );
    assert!(
        violations.iter().any(|violation| {
            violation.contains(&format!("`{origin}`"))
                && violation.contains(&format!("`{target}/test-seam`"))
        }),
        "missing test-seam path from `{origin}` to `{target}`: {violations:?}"
    );
}

#[test]
fn normal_and_build_dependencies_cannot_select_test_seam() {
    for kind in [None, Some("build")] {
        let mut metadata = fixture();
        package(&mut metadata, "bitcoin-rs-node")["dependencies"][0] =
            dependency("bitcoin-rs-execution", kind, &["test-seam"]);
        assert_test_seam_rejected(&metadata, "bitcoin-rs-node", "bitcoin-rs-execution");
    }
}

#[test]
fn optional_target_dependency_cannot_select_test_seam() {
    let mut metadata = fixture();
    let node = package(&mut metadata, "bitcoin-rs-node");
    node["dependencies"][0]["features"] = json!(["test-seam"]);
    node["dependencies"][0]["optional"] = json!(true);
    node["dependencies"][0]["target"] = json!("cfg(unix)");
    assert_test_seam_rejected(&metadata, "bitcoin-rs-node", "bitcoin-rs-execution");
}

#[test]
fn dev_only_fixture_selection_is_allowed_without_feature_unification() {
    let mut metadata = fixture();
    package(&mut metadata, "bitcoin-rs-node")["dependencies"]
        .as_array_mut()
        .expect("fixture dependencies")
        .push(dependency(
            "bitcoin-rs-execution",
            Some("dev"),
            &["test-seam"],
        ));
    assert!(WorkspaceGraph::from_json(&metadata).validate().is_ok());
}

#[test]
fn production_and_default_features_cannot_forward_test_seam() {
    for feature in ["default", "production"] {
        let mut metadata = fixture();
        package(&mut metadata, "bitcoin-rs-node")["features"][feature] =
            json!(["bitcoin-rs-execution/test-seam"]);
        assert_test_seam_rejected(
            &metadata,
            &format!("bitcoin-rs-node/{feature}"),
            "bitcoin-rs-execution",
        );
    }
}

#[test]
fn chained_local_and_cross_crate_features_cannot_enable_test_seam() {
    let mut metadata = fixture();
    let node = package(&mut metadata, "bitcoin-rs-node");
    node["features"]["default"] = json!(["production"]);
    node["features"]["production"] = json!(["bitcoin-rs-execution/bridge"]);
    let chainstate = package(&mut metadata, "bitcoin-rs-execution");
    chainstate["features"]["bridge"] = json!(["helper"]);
    chainstate["features"]["helper"] = json!(["bitcoin-rs-consensus/test-seam"]);
    assert_test_seam_rejected(&metadata, "bitcoin-rs-node/default", "bitcoin-rs-consensus");
}

#[test]
fn renamed_weak_feature_forwarding_cannot_enable_test_seam() {
    let mut metadata = fixture();
    let node = package(&mut metadata, "bitcoin-rs-node");
    node["dependencies"][0]["rename"] = json!("state");
    node["dependencies"][0]["optional"] = json!(true);
    node["features"]["production"] = json!(["dep:state", "state?/test-seam"]);
    assert_test_seam_rejected(
        &metadata,
        "bitcoin-rs-node/production",
        "bitcoin-rs-execution",
    );
}

#[test]
fn dependency_feature_alias_cannot_hide_test_seam() {
    for kind in [None, Some("build")] {
        let mut metadata = fixture();
        package(&mut metadata, "bitcoin-rs-node")["dependencies"][0] =
            dependency("bitcoin-rs-execution", kind, &["fixture-alias"]);
        package(&mut metadata, "bitcoin-rs-execution")["features"]["fixture-alias"] =
            json!(["test-seam"]);
        assert_test_seam_rejected(&metadata, "bitcoin-rs-node", "bitcoin-rs-execution");
    }
}

#[test]
fn dependency_defaults_cannot_enable_test_seam() {
    let mut metadata = fixture();
    package(&mut metadata, "bitcoin-rs-node")["dependencies"][0]["uses_default_features"] =
        json!(true);
    package(&mut metadata, "bitcoin-rs-execution")["features"]["default"] = json!(["test-seam"]);
    assert_test_seam_rejected(&metadata, "bitcoin-rs-node", "bitcoin-rs-execution");
}

#[test]
fn dedicated_test_seam_forwarding_and_dev_only_features_are_allowed() {
    let mut metadata = fixture();
    let chainstate = package(&mut metadata, "bitcoin-rs-execution");
    chainstate["features"]["test-seam"] = json!(["bitcoin-rs-consensus/test-seam"]);
    let node = package(&mut metadata, "bitcoin-rs-node");
    node["dependencies"][0]["kind"] = json!("dev");
    node["features"]["fixtures"] = json!(["bitcoin-rs-execution/test-seam"]);
    assert!(WorkspaceGraph::from_json(&metadata).validate().is_ok());
}

#[test]
fn feature_cycles_terminate_and_still_detect_a_test_seam_escape() {
    let mut metadata = fixture();
    let node = package(&mut metadata, "bitcoin-rs-node");
    node["features"]["first"] = json!(["second"]);
    node["features"]["second"] = json!(["first"]);
    assert!(WorkspaceGraph::from_json(&metadata).validate().is_ok());
    package(&mut metadata, "bitcoin-rs-node")["features"]["second"] =
        json!(["first", "bitcoin-rs-execution/test-seam"]);
    assert_test_seam_rejected(&metadata, "bitcoin-rs-node/first", "bitcoin-rs-execution");
}
