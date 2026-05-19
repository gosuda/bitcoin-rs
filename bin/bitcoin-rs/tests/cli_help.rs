//! Integration smoke test: the binary prints help and exits cleanly.

use std::process::Command;

#[test]
fn help_prints_binary_name() {
    let output = Command::new(env!("CARGO_BIN_EXE_bitcoin-rs"))
        .arg("--help")
        .output()
        .unwrap_or_else(|error| panic!("failed to run bitcoin-rs binary: {error}"));

    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("bitcoin-rs"));
}
