#!/usr/bin/env bash
set -euo pipefail

qa_commit="$(git rev-parse HEAD)"
qa_evidence="$PWD/target/p2p-cache-controls"
qa_config="$RUNNER_TEMP/p2p-cache-nextest.toml"
qa_product="72feebf7426eccbce37ecee64a49b3e909cb7bfc"
qa_height_control="c3435fb144201ca0ca558fa02e85a037428822e0"
qa_chain_control="991c608a019542d5fb892f78a8393daeaccadc05"
export CARGO_TARGET_DIR="$PWD/target"
mkdir -p "$qa_evidence"
printf '%s\n' "$qa_commit" > "$qa_evidence/workflow-source.txt"
cat > "$qa_config" <<'TOML'
[profile.p2p_cache_controls]
retries = 0
fail-fast = false
test-threads = 1

[profile.p2p_cache_controls.junit]
path = "junit.xml"
report-skipped = "none"
TOML

restore_source() {
  git checkout --detach "$qa_commit"
}
trap restore_source EXIT

run_case() {
  local label="$1" expected_failures="$2" package="$3" test_name="$4"
  shift 4
  local report="$CARGO_TARGET_DIR/nextest/p2p_cache_controls/junit.xml"
  rm -f "$report"
  git rev-parse HEAD > "$qa_evidence/$label-source.txt"
  git diff > "$qa_evidence/$label-mutation.patch"
  set +e
  cargo nextest run --locked -p "$package" --lib --no-default-features \
    --config-file "$qa_config" --profile p2p_cache_controls --color never --no-tests fail \
    --no-fail-fast -E "test(=$test_name)" 2>&1 | tee "$qa_evidence/$label.log"
  local pipeline_status=("${PIPESTATUS[@]}")
  set -e
  if [[ -f "$report" ]]; then cp "$report" "$qa_evidence/$label.xml"; fi
  local expected_status=0
  if (( expected_failures != 0 )); then expected_status=100; fi
  if (( pipeline_status[1] != 0 || pipeline_status[0] != expected_status )); then
    printf 'unexpected nextest status for %s: cargo=%s tee=%s expected=%s\n' \
      "$label" "${pipeline_status[0]}" "${pipeline_status[1]}" "$expected_status" >&2
    return 1
  fi
  node - "$report" "$expected_failures" "$test_name" "$qa_evidence/$label.log" "$@" <<'NODE' | tee "$qa_evidence/$label-result.json"
const fs = require('node:fs');
const [reportPath, failureCount, expectedName, logPath, ...fragments] = process.argv.slice(2);
const xml = fs.readFileSync(reportPath, 'utf8');
const root = /<testsuites\b([^>]*)>/.exec(xml);
if (!root) throw new Error('missing nextest testsuites result');
const counts = Object.fromEntries(
  [...root[1].matchAll(/\b(tests|failures|errors)="(\d+)"/g)]
    .map(([, key, value]) => [key, Number(value)]),
);
if (counts.tests !== 1 || counts.failures !== Number(failureCount) || counts.errors !== 0) {
  throw new Error('unexpected nextest result counts: ' + JSON.stringify(counts));
}
const names = [...xml.matchAll(/<testcase\b[^>]*\bname="([^"]+)"/g)]
  .map(([, name]) => name);
if (names.length !== 1 || names[0] !== expectedName || /<skipped\b/.test(xml)) {
  throw new Error('unexpected nextest test set: ' + JSON.stringify(names));
}
const log = fs.readFileSync(logPath, 'utf8');
for (const fragment of fragments) {
  if (!log.includes(fragment)) throw new Error('missing expected behavioral failure: ' + fragment);
}
console.log(JSON.stringify({tests: names, ...counts, behavioralFragments: fragments}));
NODE
}

height_test='p2p::block_announce::tests::recent_block_budget_refusal_preserves_slot_and_last_reader'
chain_test='tests::chain_only_getdata_serves_recent_transactions_without_inventory'
git fetch --depth=1 origin "$qa_height_control" "$qa_chain_control" "$qa_product"

git checkout --detach "$qa_height_control"
run_case skipped-height-before-fix 1 bitcoin-rs-node "$height_test" 'left: 2' 'right: 0'

git checkout --detach "$qa_chain_control"
run_case chain-only-before-fix 1 bitcoin-rs-p2p "$chain_test" 'left: [NotFound' 'right: [Tx'

git checkout --detach "$qa_product"
git diff --exit-code
run_case skipped-height-current-source 0 bitcoin-rs-node "$height_test"
run_case chain-only-current-source 0 bitcoin-rs-p2p "$chain_test"
git diff --exit-code
