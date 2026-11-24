#!/usr/bin/env bash
set -euo pipefail

qa_commit="$(git rev-parse HEAD)"
qa_evidence="$PWD/target/mining-pressure-proof"
qa_config="${RUNNER_TEMP:?}/mining-pressure-nextest.toml"
export CARGO_TARGET_DIR="$PWD/target"
mkdir -p "$qa_evidence"
printf '%s\n' "$qa_commit" > "$qa_evidence/commit.txt"
cat > "$qa_config" <<'TOML'
[profile.controls]
retries = 0
fail-fast = false
test-threads = 2

[profile.controls.junit]
path = "junit.xml"
report-skipped = "none"
TOML

restore_source() {
  git restore --source="$qa_commit" --staged --worktree -- crates/node/src/mining.rs
}
trap restore_source EXIT

run_case() {
  local label="$1" expected_failures="$2"
  shift 2
  local filter="" test_name
  for test_name in "$@"; do
    if [[ -n "$filter" ]]; then filter+=' | '; fi
    filter+="test(=$test_name)"
  done
  local feature_args=()
  if [[ "${QA_TEST_PACKAGE:-bitcoin-rs-node}" == bitcoin-rs-node ]]; then feature_args=(--no-default-features); fi
  local report="$CARGO_TARGET_DIR/nextest/controls/junit.xml"
  rm -f "$report"
  git rev-parse HEAD > "$qa_evidence/$label-source.txt"
  git diff > "$qa_evidence/$label-mutation.patch"
  set +e
  cargo nextest run --locked -p "${QA_TEST_PACKAGE:-bitcoin-rs-node}" --lib "${feature_args[@]}" \
    --config-file "$qa_config" --profile controls --color never --no-tests fail \
    --no-fail-fast -E "$filter" 2>&1 | tee "$qa_evidence/$label.log"
  local pipeline_status=("${PIPESTATUS[@]}")
  set -e
  local expected_status=0
  if (( expected_failures != 0 )); then expected_status=100; fi
  if (( pipeline_status[1] != 0 || pipeline_status[0] != expected_status )); then
    printf 'unexpected nextest status for %s: cargo=%s tee=%s expected=%s\n' \
      "$label" "${pipeline_status[0]}" "${pipeline_status[1]}" "$expected_status" >&2
    return 1
  fi
  node - "$report" "$expected_failures" "$@" <<'NODE'
const fs = require('node:fs');
const [reportPath, failureCount, ...expectedNames] = process.argv.slice(2);
const xml = fs.readFileSync(reportPath, 'utf8');
const root = /<testsuites\b([^>]*)>/.exec(xml);
if (!root) throw new Error('missing nextest testsuites result');
const counts = Object.fromEntries(
  [...root[1].matchAll(/\b(tests|failures|errors)="(\d+)"/g)]
    .map(([, key, value]) => [key, Number(value)]),
);
if (counts.tests !== expectedNames.length || counts.failures !== Number(failureCount) || counts.errors !== 0) {
  throw new Error(`unexpected nextest result counts: ${JSON.stringify(counts)}`);
}
const names = [...xml.matchAll(/<testcase\b[^>]*\bname="([^"]+)"/g)]
  .map(([, name]) => name).sort();
if (JSON.stringify(names) !== JSON.stringify(expectedNames.sort())) {
  throw new Error(`unexpected nextest test set: ${JSON.stringify(names)}`);
}
console.log(JSON.stringify({tests: names, ...counts}));
NODE
  cp "$report" "$qa_evidence/$label.xml"
}

duplicate='mining::tests::local_submission_rechecks_a_competing_commit_after_accounting_refusal'
candidate='mining::tests::candidate_preflight_refuses_exhausted_shared_image_memory_and_recovers'
witness='mining::tests::witness_repair_releases_the_original_before_reserving_its_replacement'
run_case pressure-positive 0 "$duplicate" "$candidate" "$witness"

node <<'NODE'
const fs = require('node:fs');
const path = 'crates/node/src/mining.rs';
const source = fs.readFileSync(path, 'utf8');
const expected = "                if let Ok(_transition) = self.chainstate.lock_transition()\n                    && matches!(\n                        self.known_block_result(block_hash),\n                        Some(BlockValidationResult::Duplicate)\n                    )\n                {\n                    return Ok(BlockValidationResult::Duplicate);\n                }\n";
const replacement = "";
if (source.split(expected).length !== 2) throw new Error("duplicate-recheck-control source changed");
fs.writeFileSync(path, source.replace(expected, replacement));
NODE
run_case duplicate-recheck-control 1 "$duplicate"
restore_source

node <<'NODE'
const fs = require('node:fs');
const path = 'crates/node/src/mining.rs';
const source = fs.readFileSync(path, 'utf8');
const expected = "        let payload = AccountedBlock::from_local(block, &self.block_memory)?;\n        self.chainstate\n            .validate_block(&payload.image)\n            .map_err(|error| test_block_validity_error(&error))";
const replacement = "        self.chainstate\n            .validate_block(&BlockImage::from_local(block))\n            .map_err(|error| test_block_validity_error(&error))";
if (source.split(expected).length !== 2) throw new Error("candidate-reservation-control source changed");
fs.writeFileSync(path, source.replace(expected, replacement));
NODE
run_case candidate-reservation-control 1 "$candidate"
restore_source

node <<'NODE'
const fs = require('node:fs');
const path = 'crates/node/src/mining.rs';
const source = fs.readFileSync(path, 'utf8');
const expected = "                    drop(payload);\n                    return AccountedBlock::from_local(trial, &self.block_memory);";
const replacement = "                    let repaired = AccountedBlock::from_local(trial, &self.block_memory);\n                    drop(payload);\n                    return repaired;";
if (source.split(expected).length !== 2) throw new Error("witness-release-control source changed");
fs.writeFileSync(path, source.replace(expected, replacement));
NODE
run_case witness-release-control 1 "$witness"
restore_source

run_case pressure-restored 0 "$duplicate" "$candidate" "$witness" \
  mining::tests::local_generated_backing_stays_charged_until_last_reader \
  mining::tests::local_submissions_account_backing_and_witness_rebuilds \
  mining::tests::local_submission_budget_refusal_preserves_state_and_duplicate_results
git diff --exit-code
