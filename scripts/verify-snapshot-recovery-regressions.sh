#!/usr/bin/env bash
set -euo pipefail

qa_commit="$(git rev-parse HEAD)"
qa_evidence="$PWD/target/snapshot-recovery-proof"
qa_config="${RUNNER_TEMP:?}/snapshot-recovery-nextest.toml"
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
  git restore --source="$qa_commit" --staged --worktree -- crates/node/src/snapshot.rs
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

snapshot='snapshot::tests::snapshot_settlement_refusal_after_durable_activation_keeps_admission_closed'
run_case snapshot-positive 0 "$snapshot"

node <<'NODE'
const fs = require('node:fs');
const path = 'crates/node/src/snapshot.rs';
const source = fs.readFileSync(path, 'utf8');
const expected = "        if result.is_ok()\n            && let Err(settlement) = self.followers.on_snapshot(change.as_ref())\n        {\n            self.chainstate.fail_closed_for_recovery();\n            return Err(SnapshotImportError::Settlement(settlement));\n        }";
const replacement = "        if result.is_ok()\n            && let Err(settlement) = self.followers.on_snapshot(change.as_ref())\n        {\n            return Err(SnapshotImportError::Settlement(settlement));\n        }";
if (source.split(expected).length !== 2) throw new Error('snapshot settlement owner changed');
fs.writeFileSync(path, source.replace(expected, replacement));
NODE
run_case recovery-closure-control 1 "$snapshot"
restore_source

node <<'NODE'
const fs = require('node:fs');
const path = 'crates/node/src/snapshot.rs';
const source = fs.readFileSync(path, 'utf8');
const expected = "        if result.is_ok()\n            && let Err(settlement) = self.followers.on_snapshot(change.as_ref())\n        {\n            self.chainstate.fail_closed_for_recovery();\n            return Err(SnapshotImportError::Settlement(settlement));\n        }";
const replacement = "        if result.is_ok()\n            && let Err(settlement) = self.followers.on_snapshot(change.as_ref())\n        {\n            if let Some(change) = change { change.finish().expect(\"negative control must reopen admission\"); }\n            self.chainstate.fail_closed_for_recovery();\n            return Err(SnapshotImportError::Settlement(settlement));\n        }";
if (source.split(expected).length !== 2) throw new Error('snapshot settlement owner changed');
fs.writeFileSync(path, source.replace(expected, replacement));
NODE
run_case admission-reopen-control 1 "$snapshot"
restore_source

run_case snapshot-restored 0 "$snapshot"
git diff --exit-code
