#!/usr/bin/env bash
set -euo pipefail

qa_commit="$(git rev-parse HEAD)"
qa_evidence="$PWD/target/verification-logs"
qa_config="${RUNNER_TEMP:?}/resolution-nextest.toml"
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
  git restore --source="$qa_commit" --staged --worktree -- \
    crates/mempool/src/admission.rs \
    crates/node/src/mining.rs \
    crates/node/src/mining/coordinator.rs \
    crates/chain/src/chain/tree.rs
  git checkout --detach "$qa_commit"
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
  local report="$CARGO_TARGET_DIR/nextest/controls/junit.xml"
  rm -f "$report"
  git rev-parse HEAD > "$qa_evidence/$label-source.txt"
  git diff > "$qa_evidence/$label-mutation.patch"
  set +e
  cargo nextest run --locked -p "${QA_TEST_PACKAGE:-bitcoin-rs-node}" --lib --no-default-features \
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

recent_lookup='p2p::chain_query::tests::recent_block_lookup_keeps_typed_identities_and_one_body'
recent_dispatch='p2p::dispatch_tests::recent_block_getdata_preserves_privacy_and_broadcast_state'
snapshot_mining='snapshot::tests::mining_resumes_after_snapshot_replaces_a_settled_tip'
snapshot_state='snapshot::tests::successful_snapshot_import_preserves_nonresident_fee_prioritisation'
submission='mining::tests::fresh_submission_rechecks_generation_under_transition_and_reopens_admission'
joined='mining::coordinator::tests::joined_prepared_requests_share_validation_and_its_refusal'
interrupted='mining::coordinator::tests::interrupted_validation_releases_joiners_without_publishing_failure'

git fetch --depth=1 origin d0695a87e667f4eb16d8210f6e49e1561993afcb
git checkout --detach d0695a87e667f4eb16d8210f6e49e1561993afcb
run_case recent-block-before-fix 2 "$recent_lookup" "$recent_dispatch"
git checkout --detach "$qa_commit"

node <<'NODE'
const fs = require('node:fs');
const path = 'crates/mempool/src/admission.rs';
const source = fs.readFileSync(path, 'utf8');
const expected = '        let mut pool = self.pool.write();\n        pool.settle_for_snapshot();';
if (source.split(expected).length !== 2) throw new Error('snapshot mutation no longer matches its owner');
fs.writeFileSync(path, source.replace(expected, '        let _pool = self.pool.read();'));
NODE
run_case snapshot-settlement-control 2 "$snapshot_mining" "$snapshot_state"
git restore --source="$qa_commit" --worktree -- crates/mempool/src/admission.rs

node <<'NODE'
const fs = require('node:fs');
const path = 'crates/node/src/mining.rs';
const source = fs.readFileSync(path, 'utf8');
const expected = `        if generation.is_some_and(|key| self.service.live_generation_key() != key) {
            if let Err(error) =
                ChainFollowers::finish_transition(&self.chainstate, transition, mempool_change)
            {
                return map_apply_error(error);
            }
            return Err(coordinator::generation_race());
        }
`;
if (source.split(expected).length !== 2) throw new Error('submission mutation no longer matches its owner');
fs.writeFileSync(path, source.replace(expected, ''));
NODE
run_case submission-fence-control 1 "$submission"
git restore --source="$qa_commit" --worktree -- crates/node/src/mining.rs

node <<'NODE'
const fs = require('node:fs');
const path = 'crates/node/src/mining/coordinator.rs';
const source = fs.readFileSync(path, 'utf8');
const expected = '                state.ordinary_waiters += 1;';
if (source.split(expected).length !== 2) throw new Error('waiter mutation no longer matches its owner');
fs.writeFileSync(path, source.replace(expected, `${expected}\n${expected}`));
NODE
run_case waiter-accounting-control 2 "$joined" "$interrupted"
git restore --source="$qa_commit" --worktree -- crates/node/src/mining/coordinator.rs

git diff --exit-code
run_case current-source 0 "$recent_lookup" "$recent_dispatch" \
  "$snapshot_mining" "$snapshot_state" "$submission" "$joined" "$interrupted"
git diff --exit-code

tree_prefix='chain::tree::tests'
node <<'NODE'
const fs = require('node:fs');
const path = 'crates/chain/src/chain/tree.rs';
const source = fs.readFileSync(path, 'utf8');
const expected = '        if self.len() <= max_resident || max_removals == 0 {';
if (source.split(expected).length !== 2) throw new Error('reclamation mutation no longer matches its owner');
const disabled = '        let max_removals = max_removals.saturating_sub(max_removals);\n';
fs.writeFileSync(path, source.replace(expected, disabled + expected));
NODE
QA_TEST_PACKAGE=bitcoin-rs-chain run_case reclamation-control 2 \
  "$tree_prefix::reclaimed_ids_never_alias_reused_slots_or_cached_states" \
  "$tree_prefix::reclamation_bounds_resident_slots_across_repeated_forks"
git restore --source="$qa_commit" --worktree -- crates/chain/src/chain/tree.rs
QA_TEST_PACKAGE=bitcoin-rs-chain run_case retained-header-storage 0 \
  "$tree_prefix::reclaimed_ids_never_alias_reused_slots_or_cached_states" \
  "$tree_prefix::reclamation_bounds_resident_slots_across_repeated_forks" \
  "$tree_prefix::reclamation_preserves_required_roots_and_their_ancestors" \
  "$tree_prefix::unknown_required_root_prevents_all_reclamation" \
  "$tree_prefix::reclamation_compacts_sparse_storage_without_rekeying_public_ids" \
  "$tree_prefix::replay_keeps_parents_before_children_after_slot_reuse" \
  "$tree_prefix::invalidation_uses_logical_order_and_resident_slots_after_reuse" \
  "$tree_prefix::exhausted_logical_ids_refuse_insert_before_mutation_even_with_free_slots" \
  "$tree_prefix::reclamation_rebuilds_test_mutated_topology_without_losing_ancestors" \
  "$tree_prefix::reclamation_refuses_unknown_test_parent_before_removing_any_leaf"
git diff --exit-code
