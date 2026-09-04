//! Integration smoke tests: the binary's public CLI is the launcher surface.

use std::collections::BTreeSet;
use std::process::Command;

fn help_text() -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_bitcoin-rs"))
        .arg("--help")
        .output()
        .unwrap_or_else(|error| panic!("failed to run bitcoin-rs binary: {error}"));

    assert!(
        output.status.success(),
        "bitcoin-rs --help must succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn help_prints_binary_name() {
    assert!(help_text().contains("bitcoin-rs"));
}

#[test]
fn help_exposes_only_launcher_flags() {
    let help = help_text();
    let longs: BTreeSet<&str> = help
        .split_whitespace()
        .filter_map(|token| token.strip_prefix("--")?.split(['<', ',', '=']).next())
        .filter(|name| !name.is_empty())
        .collect();

    assert_eq!(
        longs,
        BTreeSet::from([
            "bitcoin-conf",
            "config",
            "data-dir",
            "help",
            "network",
            "version"
        ])
    );
}

#[test]
fn version_prints_and_exits_cleanly() {
    let output = Command::new(env!("CARGO_BIN_EXE_bitcoin-rs"))
        .arg("--version")
        .output()
        .unwrap_or_else(|error| panic!("failed to run bitcoin-rs binary: {error}"));
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("bitcoin-rs"), "{text}");
}

#[test]
fn runtime_knobs_are_not_cli_flags() {
    let output = Command::new(env!("CARGO_BIN_EXE_bitcoin-rs"))
        .args(["--storage-backend", "fjall"])
        .output()
        .unwrap_or_else(|error| panic!("failed to run bitcoin-rs binary: {error}"));
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unexpected argument") || stderr.contains("unrecognized"),
        "{stderr}"
    );
}
