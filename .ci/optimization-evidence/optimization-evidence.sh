#!/usr/bin/env bash
set -euo pipefail

: "${RUNNER_TEMP:?Run this script on the isolated GitHub measurement runner}"

baseline_revision=0f220663e87b74e1591f10986594bad98e8601ce
current_revision=f9503be293d27a62989ca7742340861ab87589b4
current_tree=$(git rev-parse --show-toplevel)
sources="$current_tree/.ci/optimization-evidence"
evidence_dir=$(mktemp -d "$RUNNER_TEMP/optimization-evidence.XXXXXX")
baseline_tree="$evidence_dir/baseline"
export CARGO_TARGET_DIR="$evidence_dir/target"

git merge-base --is-ancestor "$current_revision" HEAD
git diff --exit-code "$current_revision" HEAD -- \
    crates Cargo.toml Cargo.lock rust-toolchain.toml
git diff --exit-code HEAD -- crates Cargo.toml Cargo.lock rust-toolchain.toml
git diff --exit-code "$baseline_revision" "$current_revision" -- \
    Cargo.toml Cargo.lock rust-toolchain.toml

printf 'OPTIMIZATION_EVIDENCE_ENVIRONMENT_BEGIN\n'
printf 'baseline_revision=%s\ncurrent_revision=%s\nworkflow_revision=%s\n' \
    "$baseline_revision" "$current_revision" "$(git rev-parse HEAD)"
printf 'test_profile=test\nbenchmark_profile=release\ncargo_build_jobs=%s\n' "${CARGO_BUILD_JOBS:-default}"
rustc -Vv
cargo -V
uname -m
printf 'OPTIMIZATION_EVIDENCE_ENVIRONMENT_END\n'

git worktree add --detach "$baseline_tree" "$baseline_revision"
git diff --binary "$baseline_revision" "$current_revision" -- \
    crates/index/src/index.rs crates/mempool/Cargo.toml > "$evidence_dir/tests-only.patch"
git -C "$baseline_tree" apply --check "$evidence_dir/tests-only.patch"
git -C "$baseline_tree" apply "$evidence_dir/tests-only.patch"
cp "$current_tree/crates/p2p/decode_heap_amplification_tests.rs" \
    "$baseline_tree/crates/p2p/decode_heap_amplification_tests.rs"
cp "$current_tree/crates/mempool/graph_walk_allocation_tests.rs" \
    "$baseline_tree/crates/mempool/graph_walk_allocation_tests.rs"
cmp "$baseline_tree/Cargo.lock" "$current_tree/Cargo.lock"

printf 'OPTIMIZATION_EVIDENCE_BASELINE_OVERLAY_BEGIN\n'
cat "$evidence_dir/tests-only.patch"
git -C "$baseline_tree" diff --stat
printf 'untracked_test=crates/mempool/graph_walk_allocation_tests.rs\n'
printf 'OPTIMIZATION_EVIDENCE_BASELINE_OVERLAY_END\n'

install_example() {
    local tree=$1 source=$2 package=$3 name=$4
    local destination="$tree/crates/$package/examples/$name.rs"
    if [[ -e "$destination" ]]; then
        printf 'Refusing to replace an existing example: %s\n' "$destination" >&2
        return 1
    fi
    mkdir -p "$tree/crates/$package/examples"
    cp "$sources/$source" "$destination"
}

for tree in "$baseline_tree" "$current_tree"; do
    install_example "$tree" p2p_queued_encode_bench.rs p2p \
        optimization_evidence_p2p_queued_encode
    install_example "$tree" script_snapshot_bench.rs mempool \
        optimization_evidence_script_snapshot
    install_example "$tree" mempool_graph_walk_bench.rs mempool \
        optimization_evidence_mempool_graph_walk
done

run_regression() {
    local phase=$1 tree=$2 expected_exit=$3 name=$4
    shift 4
    local actual_exit=0
    printf 'OPTIMIZATION_EVIDENCE_TEST_BEGIN phase=%s name=%s expected_exit=%s\n' \
        "$phase" "$name" "$expected_exit"
    if (
        cd "$tree" &&
            cargo nextest run --locked --cargo-profile test --no-fail-fast \
                --no-tests=fail --retries 0 --test-threads 1 \
                --success-output final --failure-output final "$@" \
                -E "test(=$name)"
    ); then
        actual_exit=0
    else
        actual_exit=$?
    fi
    printf 'OPTIMIZATION_EVIDENCE_TEST_END phase=%s name=%s actual_exit=%s\n' \
        "$phase" "$name" "$actual_exit"
    if [[ "$actual_exit" -ne "$expected_exit" ]]; then
        printf 'Expected nextest exit %s, received %s for %s/%s\n' \
            "$expected_exit" "$actual_exit" "$phase" "$name" >&2
        return 1
    fi
}

run_regressions() {
    local phase=$1 tree=$2 expected_exit=$3
    local name
    for name in \
        wire_length_borrows_retained_payloads \
        encoding_inventory_allocates_only_the_output \
        borrowed_payloads_match_rust_bitcoin_without_length_allocations; do
        run_regression "$phase" "$tree" "$expected_exit" "$name" \
            -p bitcoin-rs-p2p --test decode_heap_amplification
    done
    for name in \
        index::tail_gate_tests::disabled_script_history_skips_script_hashes \
        index::tail_gate_tests::lookup_and_history_disabled_skip_script_hashes; do
        run_regression "$phase" "$tree" "$expected_exit" "$name" \
            -p bitcoin-rs-index --lib
    done
    run_regression "$phase" "$tree" "$expected_exit" \
        local_graph_walk_allocation_ignores_unrelated_entries \
        -p bitcoin-rs-mempool --features test-seam --test graph_walk_allocation
}

run_example() {
    local phase=$1 tree=$2 package=$3 name=$4 mode=$5
    shift 5
    local artifacts="$evidence_dir/$phase-$name-$mode-artifacts.jsonl"
    local executable
    local rustc_arguments=()
    if [[ "$mode" == allocations ]]; then
        rustc_arguments+=(--cfg count_allocations)
    fi
    (
        cd "$tree"
        cargo rustc --locked --profile release -p "$package" --example "$name" "$@" \
            --message-format=json-render-diagnostics \
            -- --check-cfg 'cfg(count_allocations)' "${rustc_arguments[@]}" > "$artifacts"
    )
    executable=$(jq -er --arg name "$name" -s \
        '[.[] | select(.reason == "compiler-artifact" and .target.name == $name and .executable != null and .profile.test == false and .profile.opt_level == "3")] | if length == 1 then .[0].executable else error("expected exactly one Cargo executable") end' \
        "$artifacts")
    [[ -x "$executable" ]]
    printf 'OPTIMIZATION_EVIDENCE_BENCH_BEGIN phase=%s name=%s mode=%s\n' \
        "$phase" "$name" "$mode"
    "$executable"
    printf 'OPTIMIZATION_EVIDENCE_BENCH_END phase=%s name=%s mode=%s\n' \
        "$phase" "$name" "$mode"
}

run_benchmarks() {
    local phase=$1 tree=$2
    run_example "$phase" "$tree" bitcoin-rs-p2p \
        optimization_evidence_p2p_queued_encode timing
    run_example "$phase" "$tree" bitcoin-rs-p2p \
        optimization_evidence_p2p_queued_encode allocations
    run_example "$phase" "$tree" bitcoin-rs-mempool \
        optimization_evidence_script_snapshot timing --features test-seam
    run_example "$phase" "$tree" bitcoin-rs-mempool \
        optimization_evidence_mempool_graph_walk timing --features test-seam
    run_example "$phase" "$tree" bitcoin-rs-mempool \
        optimization_evidence_mempool_graph_walk allocations --features test-seam
}

run_regressions baseline "$baseline_tree" 100
run_benchmarks baseline "$baseline_tree"
run_regressions current "$current_tree" 0
run_benchmarks current "$current_tree"

printf 'OPTIMIZATION_EVIDENCE_PROOF_BEGIN phase=current name=index_tail_and_filter\n'
(
    cd "$current_tree"
    cargo nextest run --locked --cargo-profile test --no-fail-fast --no-tests=fail \
        --retries 0 --test-threads 1 --success-output final --failure-output final \
        -p bitcoin-rs-index --lib \
        -E 'test(index::tail_gate_tests) | test(index::filter_build_tests)'
)
printf 'OPTIMIZATION_EVIDENCE_PROOF_END phase=current name=index_tail_and_filter\n'

for name in \
    second_writer_contention_rejects_a_stale_fence \
    rolling_back_a_bip30_duplicate_restores_the_earlier_coin_row; do
    printf 'OPTIMIZATION_EVIDENCE_PROOF_BEGIN phase=current name=%s\n' "$name"
    (
        cd "$current_tree"
        cargo nextest run --locked --cargo-profile test --no-fail-fast --no-tests=fail \
            --retries 0 --test-threads 1 --success-output final --failure-output final \
            -p bitcoin-rs-index --test suite -E "test($name)"
    )
    printf 'OPTIMIZATION_EVIDENCE_PROOF_END phase=current name=%s\n' "$name"
done

git -C "$baseline_tree" diff --exit-code -- Cargo.lock
git -C "$current_tree" diff --exit-code -- Cargo.lock
cmp "$baseline_tree/Cargo.lock" "$current_tree/Cargo.lock"
printf 'OPTIMIZATION_EVIDENCE_COMPLETE baseline=%s current=%s\n' \
    "$baseline_revision" "$current_revision"
