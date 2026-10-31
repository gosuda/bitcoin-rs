#![expect(clippy::expect_used, reason = "test assertions")]

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn run(root: &Path, check: bool) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_contract-index"));
    command.arg("--root").arg(root);
    if check {
        command.arg("--check");
    }
    command.output().expect("contract-index runs")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn write(root: &Path, path: &str, text: &str) {
    let target = root.join(path);
    fs::create_dir_all(target.parent().expect("parent")).expect("directories");
    fs::write(target, text).expect("write");
}

fn fixture() -> tempfile::TempDir {
    let directory = tempfile::tempdir().expect("temp dir");
    write(
        directory.path(),
        "docs/contracts/README.md",
        "# Contracts\n\n## Index\n<!-- contract-index:start -->\n<!-- contract-index:end -->\n",
    );
    write(
        directory.path(),
        "docs/contracts/demo.md",
        "# Demo\n\n### `DEMO-01`: One rule\n\nText.\n",
    );
    write(
        directory.path(),
        "crates/demo/src/lib.rs",
        "// DEMO-01\n#[test]\nfn proves_one_rule() {}\n",
    );
    directory
}

#[test]
fn generation_records_a_tagged_test_in_both_outputs() {
    let directory = fixture();
    let output = run(directory.path(), false);
    assert!(output.status.success(), "{}", stderr(&output));

    let index = fs::read_to_string(directory.path().join("docs/contracts/evidence-index.md"))
        .expect("evidence index written");
    assert!(
        index.contains("1 clauses, 1 with proof artifacts, 0 gaps."),
        "one clause with one proof must be counted, got:\n{index}"
    );
    assert!(
        index.contains("`crates/demo/src/lib.rs`::proves_one_rule (test)"),
        "the tagged test must appear as a test artifact, got:\n{index}"
    );

    let readme = fs::read_to_string(directory.path().join("docs/contracts/README.md"))
        .expect("readme written");
    assert!(
        readme.contains("<!-- contract-index:start -->\n- [demo.md](demo.md): `DEMO-01`.\n<!-- contract-index:end -->"),
        "the generated contract list must list the clause, got:\n{readme}"
    );
}

#[test]
fn check_passes_on_a_generated_tree() {
    let directory = fixture();
    let generate = run(directory.path(), false);
    assert!(generate.status.success(), "{}", stderr(&generate));
    let output = run(directory.path(), true);
    assert!(output.status.success(), "{}", stderr(&output));
}

#[test]
fn check_fails_when_the_index_is_stale() {
    let directory = fixture();
    let generate = run(directory.path(), false);
    assert!(generate.status.success(), "{}", stderr(&generate));
    write(
        directory.path(),
        "docs/contracts/demo.md",
        "# Demo\n\n### `DEMO-01`: One rule\n\n### `DEMO-02`: A second rule\n\nText.\n",
    );
    let output = run(directory.path(), true);
    assert!(
        !output.status.success(),
        "a new clause must make the index stale"
    );
    assert!(
        stderr(&output).contains("evidence-index.md is stale"),
        "the failure must name the stale index, got:\n{}",
        stderr(&output)
    );
}

#[test]
fn check_fails_on_a_tag_naming_an_unknown_clause() {
    let directory = fixture();
    let generate = run(directory.path(), false);
    assert!(generate.status.success(), "{}", stderr(&generate));
    write(
        directory.path(),
        "crates/demo/src/bogus.rs",
        "// XYZ-99\n#[test]\nfn bogus_tag() {}\n",
    );
    let output = run(directory.path(), true);
    assert!(
        !output.status.success(),
        "a tag naming an undefined clause must fail the check"
    );
    assert!(
        stderr(&output).contains("XYZ-99"),
        "the failure must name the unknown clause ID, got:\n{}",
        stderr(&output)
    );
}

#[test]
fn check_fails_on_a_broken_relative_link() {
    let directory = fixture();
    let generate = run(directory.path(), false);
    assert!(generate.status.success(), "{}", stderr(&generate));
    write(
        directory.path(),
        "docs/broken.md",
        "# Broken\n\n[missing](missing.md)\n",
    );
    let output = run(directory.path(), true);
    assert!(
        !output.status.success(),
        "a relative link to an absent file must fail the check"
    );
    assert!(
        stderr(&output).contains("docs/broken.md:3") && stderr(&output).contains("missing.md"),
        "the failure must name the file, line and target, got:\n{}",
        stderr(&output)
    );
}

#[test]
fn check_fails_on_a_broken_symbol_citation() {
    let directory = fixture();
    let generate = run(directory.path(), false);
    assert!(generate.status.success(), "{}", stderr(&generate));
    write(
        directory.path(),
        "docs/contracts/demo.md",
        "# Demo\n\n### `DEMO-01`: One rule\n\nSee `crates/demo/src/lib.rs::absent_symbol`.\n",
    );
    let output = run(directory.path(), true);
    assert!(
        !output.status.success(),
        "a path::symbol citation to an absent symbol must fail the check"
    );
    assert!(
        stderr(&output).contains("absent_symbol"),
        "the failure must name the absent symbol, got:\n{}",
        stderr(&output)
    );
}

#[test]
fn check_fails_on_a_missing_code_path() {
    let directory = fixture();
    let generate = run(directory.path(), false);
    assert!(generate.status.success(), "{}", stderr(&generate));
    write(
        directory.path(),
        "docs/contracts/demo.md",
        "# Demo\n\n### `DEMO-01`: One rule\n\nSee `crates/demo/src/absent.rs`.\n",
    );
    let output = run(directory.path(), true);
    assert!(
        !output.status.success(),
        "a backticked code path to an absent file must fail the check"
    );
    assert!(
        stderr(&output).contains("absent.rs"),
        "the failure must name the absent path, got:\n{}",
        stderr(&output)
    );
}

#[test]
fn dated_records_cite_the_tree_at_their_measurement_date() {
    let directory = fixture();
    let generate = run(directory.path(), false);
    assert!(generate.status.success(), "{}", stderr(&generate));
    write(
        directory.path(),
        "docs/benchmarks/data/measurement-2026-01-01.md",
        "# Measurement\n\n`crates/demo/src/retired.rs` was deleted after this run.\n",
    );
    let output = run(directory.path(), true);
    assert!(
        output.status.success(),
        "a dated record may cite a path retired after its run, got:\n{}",
        stderr(&output)
    );
}
