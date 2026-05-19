//! Loader smoke test for Core's script vector file.

use std::path::Path;

#[test]
#[ignore = "Core script_tests.json is run explicitly after consensus vectors are vendored"]
fn core_script_tests_json_loads() {
    let path = Path::new("../consensus/tests/vectors/script_tests.json");
    if !path.exists() {
        eprintln!("vectors not yet vendored; rerun after Task 2");
        return;
    }
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) => panic!("script_tests.json should be readable: {error}"),
    };
    let json: serde_json::Value = match serde_json::from_str(&text) {
        Ok(json) => json,
        Err(error) => panic!("script_tests.json should parse as JSON: {error}"),
    };
    let Some(entries) = json.as_array() else {
        panic!("script_tests.json root should be an array");
    };
    let runnable = entries
        .iter()
        .filter(|entry| entry.as_array().is_some_and(|row| row.len() >= 4))
        .count();
    println!("script_tests.json loaded: {runnable} runnable vector rows");
    assert!(runnable > 0);
}
