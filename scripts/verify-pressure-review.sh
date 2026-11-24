#!/usr/bin/env bash
set -euo pipefail
mode="$1"
evidence="target/pressure-review-proof"
mkdir -p "$evidence"
git rev-parse HEAD > "$evidence/source.txt"
cat > "$evidence/nextest.toml" <<'CONFIG'
[profile.controls]
retries = 0
[profile.controls.junit]
path = "junit.xml"
CONFIG
restore_source() {
  git restore --source=HEAD -- crates/p2p/src/listener.rs crates/node/src/pool/ledger.rs crates/node/src/pool/sv2.rs
}
run_case() {
  local label="$1" outcome="$2" names="$3" filter="$4"
  rm -f target/nextest/controls/junit.xml
  set +e
  cargo nextest run --locked -p "$package" --lib --no-default-features "${features[@]}" \
    --config-file "$evidence/nextest.toml" --profile controls --no-tests fail --no-fail-fast \
    -E "$filter" 2>&1 | tee "$evidence/$label.log"
  local status="${PIPESTATUS[0]}"
  set -e
  test -f target/nextest/controls/junit.xml
  cp target/nextest/controls/junit.xml "$evidence/$label.xml"
  node scripts/verify-pressure-review.cjs check "$evidence/$label.xml" "$status" "$outcome" "$names"
}
trap restore_source EXIT
if [[ "$mode" == compact ]]; then
  package=bitcoin-rs-p2p
  features=()
  test_name=listener::aggregate_budget_tests::compact_receipt_refusal_preserves_discovery_and_requests_full_body
  names='["listener::aggregate_budget_tests::compact_receipt_refusal_preserves_discovery_and_requests_full_body","listener::aggregate_budget_tests::compact_completion_refuses_shared_or_underestimated_backing","listener::aggregate_budget_tests::compact_forward_backpressure_keeps_source_and_image_charged","listener::aggregate_budget_tests::compact_admission_refusal_preserves_header_for_ordinary_sync"]'
  filter="test(=$test_name) | test(=listener::aggregate_budget_tests::compact_completion_refuses_shared_or_underestimated_backing) | test(=listener::aggregate_budget_tests::compact_forward_backpressure_keeps_source_and_image_charged) | test(=listener::aggregate_budget_tests::compact_admission_refusal_preserves_header_for_ordinary_sync)"
  run_case positive pass "$names" "$filter"
  node scripts/verify-pressure-review.cjs mutate compact
  run_case lost-fallback fail "[\"$test_name\"]" "test(=$test_name)"
  restore_source
  run_case restored pass "$names" "$filter"
elif [[ "$mode" == pool ]]; then
  package=bitcoin-rs-node
  features=(--features pool-sv2)
  test_name=pool::sv2::tests::unavailable_sv2_submission_retains_its_bounded_block_until_admission_recovers
  names='["pool::sv2::tests::unavailable_sv2_submission_retains_its_bounded_block_until_admission_recovers","pool::sv2::tests::unavailable_retry_deadline_starts_after_submission_completes","pool::sv2::tests::terminal_sv2_submission_errors_do_not_enter_the_admission_retry_queue","pool::sv2::tests::undetermined_sv2_block_withholds_success_and_retries_authoritative_state","pool::sv2::tests::applied_sv2_block_retires_the_common_job_before_a_sibling_reaches_the_node"]'
  filter="test(=$test_name) | test(=pool::sv2::tests::unavailable_retry_deadline_starts_after_submission_completes) | test(=pool::sv2::tests::terminal_sv2_submission_errors_do_not_enter_the_admission_retry_queue) | test(=pool::sv2::tests::undetermined_sv2_block_withholds_success_and_retries_authoritative_state) | test(=pool::sv2::tests::applied_sv2_block_retires_the_common_job_before_a_sibling_reaches_the_node)"
  run_case positive pass "$names" "$filter"
  for mutation in drop-unavailable consume-refusal-attempt omit-retry-delay; do
    restore_source
    node scripts/verify-pressure-review.cjs mutate "$mutation"
    run_case "$mutation" fail "[\"$test_name\"]" "test(=$test_name)"
  done
  restore_source
  node scripts/verify-pressure-review.cjs mutate stale-retry-clock
  clock_test=pool::sv2::tests::unavailable_retry_deadline_starts_after_submission_completes
  run_case stale-retry-clock fail "[\"$clock_test\"]" "test(=$clock_test)"
  restore_source
  run_case restored pass "$names" "$filter"
else
  exit 2
fi
git diff --exit-code -- crates/p2p/src/listener.rs crates/node/src/pool/ledger.rs crates/node/src/pool/sv2.rs > "$evidence/restored.diff"
