from pathlib import Path
import subprocess


def run(*args: str) -> str:
    result = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if result.returncode:
        print(result.stdout, flush=True)
        raise SystemExit(result.returncode)
    return result.stdout


def replace(path: str, old: str, new: str) -> None:
    file = Path(path)
    text = file.read_text()
    assert text.count(old) == 1, (path, text.count(old), old)
    file.write_text(text.replace(old, new, 1))


base = "f846c7fbeed40e70431cf83ab4f2cb656bf9ea0b"
branch = "ci/manual-formal-model-execution"
assert run("git", "rev-parse", "HEAD").strip() == base
assert not run("git", "ls-remote", "--heads", "origin", f"refs/heads/{branch}").strip()
run("git", "switch", "-c", branch)

g20 = "bin/bitcoin-rs/tests/gates/g20_formal_models.rs"
replace(
    g20,
    '''#[test]
fn all_model_specs_check_with_apalache() {
''',
    '''#[test]
#[ignore = "full Apalache execution is manual while the proof inventory is BLOCKED"]
fn all_model_specs_check_with_apalache() {
''',
)

ci = ".github/workflows/ci.yml"
replace(
    ci,
    '''      # This pass includes the binary's process and formal gates, unfiltered.
''',
    '''      # This pass includes binary process gates and the G20 tool/inventory
      # checks. The six long Apalache proof invocations are ignored by default
      # while the proof inventory is BLOCKED and run by formal-models.yml.
''',
)

constraints = "CONSTRAINTS.md"
replace(
    constraints,
    '''Gate `g20` (`bin/bitcoin-rs/tests/gates/g20_formal_models.rs`) runs six
invocations per pass, three safety and three temporal:
''',
    '''Gate `g20` (`bin/bitcoin-rs/tests/gates/g20_formal_models.rs`) defines six
checker invocations per pass, three safety and three temporal. The all-model
execution test is `#[ignore]` in ordinary `cargo test` while this inventory has
`UNMEASURED` or nonzero outcomes. PR CI still compiles the gate and runs its
pinned-tool, hash-inventory, and JVM-register tests. Explicit proof execution is
owned by the manual-only `.github/workflows/formal-models.yml` lane; a manual
run that does not complete all six invocations at rc 0 leaves the inventory
`BLOCKED`:
''',
)

formal = Path(".github/workflows/formal-models.yml")
assert not formal.exists()
formal.write_text('''name: formal-models

on:
  workflow_dispatch:

permissions:
  contents: read

env:
  CARGO_TERM_COLOR: never
  RUST_BACKTRACE: 1
  CARGO_INCREMENTAL: 0

jobs:
  apalache:
    runs-on: ubuntu-latest
    timeout-minutes: 360
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4
      - uses: dtolnay/rust-toolchain@6bed0761d98439e5a578e2877258200ad565ba87 # stable
      - uses: Swatinem/rust-cache@49a0bdc70d2e1b713ca9e2869b211fcce03d3c1c # v2
      - name: Provision pinned reference fixtures
        run: bash scripts/provision-ci-reference-fixtures.sh
      - name: Run the ignored G20 proof execution explicitly
        run: |
          rm -rf -- target/apalache
          mkdir -p target/apalache
          printf 'commit=%s\\nrun_id=%s\\nattempt=%s\\nprofile=formal-models-manual\\n' \\
            "$GITHUB_SHA" "$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT" \\
            > target/apalache/run-context.txt
          cargo test --locked -p bitcoin-rs \\
            --no-default-features --features fjall \\
            --test g20_formal_models all_model_specs_check_with_apalache -- \\
            --exact --ignored --nocapture
      - name: Preserve formal evidence
        if: ${{ always() }}
        uses: actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a # v7.0.1
        with:
          name: apalache-manual-${{ github.run_attempt }}
          path: |
            target/apalache/**/run-*.txt
            target/apalache/**/detailed*.log
            target/apalache/**/counterexample*
          if-no-files-found: warn
          retention-days: 14
''')

run("rustfmt", "--edition", "2024", g20)
run("git", "diff", "--check")
changed = run("git", "diff", "--name-only").splitlines()
assert set(changed) == {g20, ci, constraints, str(formal)}, changed
print(run("git", "diff", "--stat"), flush=True)
print(run("git", "diff", "--", g20, ci, constraints, str(formal)), flush=True)
run("git", "add", "--", g20, ci, constraints, str(formal))
run(
    "git",
    "-c",
    "user.name=github-actions[bot]",
    "-c",
    "user.email=41898282+github-actions[bot]@users.noreply.github.com",
    "commit",
    "-m",
    "ci: move blocked formal execution to an explicit manual lane",
)
run("git", "push", "origin", f"HEAD:refs/heads/{branch}")
print("PUBLISHED_SHA=" + run("git", "rev-parse", "HEAD").strip(), flush=True)
