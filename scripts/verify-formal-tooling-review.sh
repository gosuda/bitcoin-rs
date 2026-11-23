#!/usr/bin/env bash
set -euo pipefail
mkdir -p target/formal-tooling-review
review_dir="$PWD/target/formal-tooling-review"
cp scripts/ci-pr.sh "$review_dir/ci-pr.fixed"
cp scripts/provision-ci-reference-fixtures.sh "$review_dir/provision.fixed"
restore() {
  cp "$review_dir/ci-pr.fixed" scripts/ci-pr.sh
  cp "$review_dir/provision.fixed" scripts/provision-ci-reference-fixtures.sh
}
trap restore EXIT

uv run --no-project --python 3.11 python scripts/tests/test_check_models.py --verbose \
  2>&1 | tee "$review_dir/model-runner-tests.log"
uv run --no-project --python 3.11 python scripts/tests/proofs_crate_paths.py --verbose \
  2>&1 | tee "$review_dir/proofs-stage-restored.log"

node <<'NODE'
const fs = require('node:fs');
const path = 'scripts/ci-pr.sh';
const content = fs.readFileSync(path, 'utf8');
const begin = content.indexOf('  local proof_jobs\n');
const end = content.indexOf('\n  local -a pending_pids=', begin);
if (begin < 0 || end <= begin) throw new Error('worker normalization boundary missing');
const original = '  local proof_jobs\n'
  + '  proof_jobs="${PROOFS_JOBS:-$default_jobs}"\n'
  + '  if ! [[ "$proof_jobs" =~ ^[0-9]+$ ]] || (( proof_jobs < 1 )); then\n'
  + '    proof_jobs=1\n'
  + '  fi\n';
fs.writeFileSync(path, content.slice(0, begin) + original + content.slice(end));
NODE
set +e
uv run --no-project --python 3.11 python scripts/tests/proofs_crate_paths.py \
  ProofsJobLimitsTest --verbose > "$review_dir/decimal-negative.log" 2>&1
decimal_status=$?
set -e
printf 'DECIMAL_NEGATIVE_EXIT %s\n' "$decimal_status"
test "$decimal_status" -eq 1
rg -F 'model jobs must be canonical decimal 10, got 010' "$review_dir/decimal-negative.log"
rg -F 'test_invalid_limit_refuses_before_launching_proof_jobs' "$review_dir/decimal-negative.log"
restore

node <<'NODE'
const fs = require('node:fs');
const path = 'scripts/ci-pr.sh';
const content = fs.readFileSync(path, 'utf8');
const from = 'python3 scripts/check_models.py --jobs "$proof_jobs"';
if (content.split(from).length !== 2) throw new Error('model invocation is not unique');
fs.writeFileSync(path, content.replace(from, 'python3 scripts/check_models.py'));
NODE
set +e
uv run --no-project --python 3.11 python scripts/tests/proofs_crate_paths.py \
  ProofsJobLimitsTest.test_decimal_limit_reaches_both_schedulers --verbose \
  > "$review_dir/forwarding-negative.log" 2>&1
forwarding_status=$?
set -e
printf 'FORWARDING_NEGATIVE_EXIT %s\n' "$forwarding_status"
test "$forwarding_status" -eq 1
rg -F 'the following arguments are required: --jobs' "$review_dir/forwarding-negative.log"
restore

node <<'NODE'
const fs = require('node:fs');
const path = 'scripts/provision-ci-reference-fixtures.sh';
const content = fs.readFileSync(path, 'utf8');
const from = '[[ "$observed_version" == "$register_version" ]]';
const to = '[[ "${observed_version%%+*}" == "${register_version%%+*}" ]]';
if (content.split(from).length !== 2) throw new Error('Java identity comparison is not unique');
fs.writeFileSync(path, content.replace(from, to));
NODE
set +e
uv run --no-project --python 3.11 python scripts/tests/test_check_models.py \
  FormalRuntimeIdentityTests.test_same_release_wrong_build_refuses_before_download --verbose \
  > "$review_dir/java-build-negative.log" 2>&1
java_status=$?
set -e
printf 'JAVA_BUILD_NEGATIVE_EXIT %s\n' "$java_status"
test "$java_status" -eq 1
rg -F '97 != 1' "$review_dir/java-build-negative.log"
restore

uv run --no-project --python 3.11 python scripts/tests/proofs_crate_paths.py \
  ProofsJobLimitsTest --verbose 2>&1 | tee "$review_dir/scheduler-restored.log"
uv run --no-project --python 3.11 python scripts/tests/test_check_models.py \
  FormalRuntimeIdentityTests --verbose 2>&1 | tee "$review_dir/java-identity-restored.log"
git diff --exit-code -- scripts/ci-pr.sh scripts/provision-ci-reference-fixtures.sh
printf 'ALL_NEGATIVE_CONTROLS_FAILED_BEHAVIORALLY_AND_RESTORED_CHECKS_PASSED\n'
