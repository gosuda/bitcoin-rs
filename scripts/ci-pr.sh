#!/usr/bin/env bash
# Gate commands shared by CI, pre-commit, and CONTRIBUTING.md.
# PR lanes fail fast; deep collects every failure. Build/test lanes are
# kernel-free; deny resolves the kernel graph without compiling it.
set -euo pipefail

cd "$(dirname "$0")/.."

usage() {
  echo "usage: $0 {fmt|clippy|test-crates|test-binary|test-workspace|test|deny|contracts|deep|all|proofs}" >&2
  exit 2
}

[[ $# -eq 1 ]] || usage

failures=0
collect_failures=false

profile() {
  local label="$1"
  shift
  echo "==> ${label}"
  if "$@"; then
    echo "==> ok: ${label}"
  else
    echo "==> FAILED: ${label}" >&2
    failures=$((failures + 1))
    [[ "$collect_failures" == true ]] || exit 1
  fi
}

finish() {
  if [[ ${failures} -gt 0 ]]; then
    echo "${failures} profile(s) failed" >&2
    exit 1
  fi
}

# CI test lanes install cargo-nextest (.github/workflows/ci.yml,
# .github/actions/test-deps): its pooled scheduler runs test binaries
# concurrently instead of serially, which removes the long tail of
# process-harness binaries on the 4-vCPU runners. There are no doctests in
# the tree, so the two runners execute the same tests. Environments without
# nextest (local, pre-commit) fall back to `cargo test --no-fail-fast`.
cargo_test() {
  if command -v cargo-nextest >/dev/null 2>&1; then
    cargo nextest run --locked --no-fail-fast "$@"
  else
    cargo test --locked --no-fail-fast "$@"
  fi
}

clippy_profiles() {
  # Four kernel-free all-target profiles. The kernel capability is opt-in and
  # never implied by a default, so these lanes exercise the plain builds. The
  # explicit `--no-default-features` spellings keep the per-crate rows'
  # feature sets pinned even if a default changes again; the workspace row
  # builds with default features by design (it is the "plain build works"
  # row).
  profile "clippy: workspace (kernel-free)" \
    cargo clippy --locked --workspace --all-targets \
      --features bitcoin-rs/silent-payments \
      --exclude bitcoin-rs-consensus --exclude bitcoin-rs-chainstate \
      --exclude bitcoin-rs-node \
      -- -D warnings
  profile "clippy: bitcoin-rs-consensus (native)" \
    cargo clippy --locked -p bitcoin-rs-consensus \
      --no-default-features --all-targets -- -D warnings
  profile "clippy: bitcoin-rs-chainstate (native,fjall)" \
    cargo clippy --locked -p bitcoin-rs-chainstate \
      --no-default-features --features fjall --all-targets -- -D warnings
  profile "clippy: bitcoin-rs-node (fjall,zmq,silent-payments)" \
    cargo clippy --locked -p bitcoin-rs-node \
      --no-default-features --features fjall,zmq,silent-payments --all-targets -- -D warnings
  # All-target builds unify test-seam features through dev-dependencies. Check
  # the operator build separately so test-only capabilities cannot hide here.
  profile "check: bitcoin-rs (production silent-payments)" \
    cargo check --locked -p bitcoin-rs \
      --no-default-features --features fjall,silent-payments
}

test_crates_profiles() {
  profile "test: bitcoin-rs-rpc (silent-payments adapter)" \
    cargo_test -p bitcoin-rs-rpc --features silent-payments --lib handlers::silent_payments
  profile "test: bitcoin-rs (silent-payments process)" \
    cargo_test -p bitcoin-rs --no-default-features --features fjall,silent-payments --test suite silent_payments::
  profile "test: bitcoin-rs (certified inputs process)" \
    cargo_test -p bitcoin-rs --no-default-features --features fjall,silent-payments --test suite block_inputs::
  profile "test: bitcoin-rs-index (silent-payments codec)" \
    cargo_test -p bitcoin-rs-index --features silent-payments --test suite silent_payments::
  # Per-crate profiles may use checked-in fixtures but need no pinned Core
  # daemon. Tests launching that daemon run in the workspace lane below.
  # Smallest first.
  # primitives owns the QAC-05 corpus-decoder gate (BITCOIN_RS_FUZZ_CORPUS);
  # it must run in the PR lane, not only the merge-only workspace lane.
  profile "test: bitcoin-rs-primitives" \
    cargo_test -p bitcoin-rs-primitives
  # The offline CLI uses the checked-in Core snapshot, not a running daemon.
  profile "test: bitcoin-rs-snapshot" \
    cargo_test -p bitcoin-rs-snapshot
  profile "test: bitcoin-rs-consensus (native)" \
    cargo_test -p bitcoin-rs-consensus --no-default-features
  profile "test: bitcoin-rs-chainstate (native,fjall)" \
    cargo_test -p bitcoin-rs-chainstate \
      --no-default-features --features fjall
  profile "test: bitcoin-rs-p2p" \
    cargo_test -p bitcoin-rs-p2p
  profile "test: bitcoin-rs-node (fjall,zmq)" \
    cargo_test -p bitcoin-rs-node \
      --no-default-features --features fjall,zmq
  # Isolated so node's default zmq feature cannot unify this package on.
  profile "test: bitcoin-rs-rpc (no default features)" \
    cargo_test -p bitcoin-rs-rpc --no-default-features
}

test_binary_profiles() {
  # Requires the pinned Core fixture. Formal checks have their own workflow.
  profile "test: bitcoin-rs binary (rocksdb,fjall,redb)" \
    cargo_test -p bitcoin-rs \
      --no-default-features --features "rocksdb,fjall,redb"
}

test_workspace_profiles() {
  # Also expects the pinned fixtures: bin/bitcoin-rs is a workspace member,
  # so this profile runs its default-feature (fjall,redb,zmq) test binaries,
  # including the process-harness suite that launches the pinned bitcoind.
  profile "test: workspace (kernel-free)" \
    cargo_test --workspace \
      --exclude bitcoin-rs-consensus --exclude bitcoin-rs-chainstate \
      --exclude bitcoin-rs-p2p \
      --exclude bitcoin-rs-node --exclude bitcoin-rs-rpc \
      --exclude bitcoin-rs-snapshot
  # The RPC package owns libzmq. Its feature-gated process subscriber must
  # run explicitly so feature resolution cannot turn it into a zero-test
  # binary. Build and identify the daemon with the same default zmq profile.
  profile "test: bitcoin-rs-rpc (zmq, process notifications)" test_rpc_reorg_notifications
}

test_rpc_reorg_notifications() {
  cargo build --locked -p bitcoin-rs || return $?
  local target_dir="${CARGO_TARGET_DIR:-$PWD/target}"
  if [[ "$target_dir" != /* ]]; then
    target_dir="$PWD/$target_dir"
  fi
  BITCOIN_RS_NODE="$target_dir/debug/bitcoin-rs" \
    cargo_test -p bitcoin-rs-rpc --features zmq
}

# Proof lanes. `all` does not call this stage: CI runners carry no Kani,
# Lean, or Aeneas toolchain. AGENTS.md requires it for proof-owning changes.
proofs_stage() {
  local log_dir
  log_dir="$PWD/target/proofs-logs"
  mkdir -p "$log_dir"

  local -a kani_crates=()
  if [[ -n "${PROOFS_CRATES:-}" ]]; then
    read -r -a kani_crates <<< "${PROOFS_CRATES}"
  elif [[ -n "${PROOFS_KANI_CRATES:-}" ]]; then
    read -r -a kani_crates <<< "${PROOFS_KANI_CRATES}"
  else
    while IFS= read -r crate; do
      [[ -n "$crate" ]] && kani_crates+=("$crate")
    done < <(find crates bin tools -path '*/src/*' -name proofs.rs -type f \
      | sed 's|/src/.*||' | sort -u)
  fi

  local nproc_val
  nproc_val=$(nproc 2>/dev/null || echo 1)
  local num_crates
  num_crates="${#kani_crates[@]}"
  local default_jobs
  default_jobs=$(( num_crates < nproc_val ? num_crates : nproc_val ))
  if (( default_jobs < 1 )); then
    default_jobs=1
  fi
  local kani_jobs
  kani_jobs="${PROOFS_JOBS:-$default_jobs}"
  if ! [[ "$kani_jobs" =~ ^[0-9]+$ ]] || (( kani_jobs < 1 )); then
    kani_jobs=1
  fi

  local -a pending_pids=()
  local -A job_labels=()
  local -A job_logs=()
  local -A job_starts=()
  local stage_failed=0

  report_job() {
    local pid="$1"
    local rc=0
    wait "$pid" || rc=$?
    local label
    label="${job_labels[$pid]}"
    local log
    log="${job_logs[$pid]}"
    local start
    start="${job_starts[$pid]}"
    local duration
    duration=$((SECONDS - start))

    if (( rc == 0 )); then
      echo "==> ok: ${label} (${duration}s)"
      if [[ "${PROOFS_VERBOSE:-0}" == "1" ]]; then
        cat "${log}"
      fi
    else
      echo "==> FAILED: ${label} (${duration}s)" >&2
      echo "--- Log: ${log} ---" >&2
      cat "${log}" >&2
      echo "--- End log: ${log} ---" >&2
      stage_failed=$((stage_failed + 1))
    fi
  }

  local lean_log
  lean_log="$log_dir/lean.log"
  local lean_start
  lean_start=$SECONDS
  echo "==> lean: pipeline"
  (
    set -euo pipefail
    if [[ ! -x scripts/extract_lean.sh ]]; then
      echo "scripts/extract_lean.sh is missing" >&2
      exit 1
    fi
    local -a extract_cmd=(./scripts/extract_lean.sh --check)
    if [[ -n "${PROOFS_EXTRACT_LEAN_CMD:-}" ]]; then
      read -r -a extract_cmd <<< "${PROOFS_EXTRACT_LEAN_CMD}"
    fi
    "${extract_cmd[@]}"
    env -C docs/lean lake build
    if rg -n '\bsorry\b|\badmit\b' docs/lean --glob '!Extracted/**'; then
      echo "unfinished Lean proof found in docs/lean" >&2
      exit 1
    fi
  ) > "$lean_log" 2>&1 &
  local lean_pid
  lean_pid=$!
  pending_pids+=("$lean_pid")
  job_labels[$lean_pid]="lean: pipeline"
  job_logs[$lean_pid]="$lean_log"
  job_starts[$lean_pid]=$lean_start

  if [[ -f scripts/check_models.py && "${PROOFS_MODELS:-0}" == "1" ]]; then
    local models_log
    models_log="$log_dir/models.log"
    local models_start
    models_start=$SECONDS
    echo "==> models: check_models"
    python3 scripts/check_models.py > "$models_log" 2>&1 &
    local models_pid
    models_pid=$!
    pending_pids+=("$models_pid")
    job_labels[$models_pid]="models: check_models"
    job_logs[$models_pid]="$models_log"
    job_starts[$models_pid]=$models_start
  fi

  local -a running_kani=()
  local crate
  for crate in "${kani_crates[@]}"; do
    local crate_name
    crate_name="${crate##*/}"
    local kani_target_dir
    kani_target_dir="$PWD/target/kani/${crate_name}"
    mkdir -p "$kani_target_dir"
    local kani_log
    kani_log="$log_dir/kani-${crate_name}.log"
    local kani_label
    kani_label="kani: ${crate}"
    local kani_start
    kani_start=$SECONDS

    echo "==> ${kani_label}"
    (
      set -euo pipefail
      local -a cmd=(cargo kani --tests)
      if [[ -n "${PROOFS_KANI_CMD:-}" ]]; then
        read -r -a cmd <<< "${PROOFS_KANI_CMD}"
      fi
      env -C "${crate}" CARGO_TARGET_DIR="${kani_target_dir}" "${cmd[@]}"
    ) > "$kani_log" 2>&1 &
    local kani_pid
    kani_pid=$!

    pending_pids+=("$kani_pid")
    running_kani+=("$kani_pid")
    job_labels[$kani_pid]="$kani_label"
    job_logs[$kani_pid]="$kani_log"
    job_starts[$kani_pid]=$kani_start

    if (( ${#running_kani[@]} >= kani_jobs )); then
      local fin=""
      wait -n -p fin "${running_kani[@]}" || true
      if [[ -z "$fin" ]]; then
        local p
        for p in "${running_kani[@]}"; do
          if ! kill -0 "$p" 2>/dev/null; then
            fin="$p"
            break
          fi
        done
      fi
      report_job "$fin"

      local -a next_running=()
      local p
      for p in "${running_kani[@]}"; do
        if [[ "$p" != "$fin" ]]; then
          next_running+=("$p")
        fi
      done
      running_kani=("${next_running[@]}")

      local -a next_pending=()
      for p in "${pending_pids[@]}"; do
        if [[ "$p" != "$fin" ]]; then
          next_pending+=("$p")
        fi
      done
      pending_pids=("${next_pending[@]}")
    fi
  done

  while (( ${#pending_pids[@]} > 0 )); do
    local fin=""
    wait -n -p fin "${pending_pids[@]}" || true
    if [[ -z "$fin" ]]; then
      local p
      for p in "${pending_pids[@]}"; do
        if ! kill -0 "$p" 2>/dev/null; then
          fin="$p"
          break
        fi
      done
      if [[ -z "$fin" && ${#pending_pids[@]} -gt 0 ]]; then
        fin="${pending_pids[0]}"
      fi
    fi
    report_job "$fin"

    local -a next_pending=()
    for p in "${pending_pids[@]}"; do
      if [[ "$p" != "$fin" ]]; then
        next_pending+=("$p")
      fi
    done
    pending_pids=("${next_pending[@]}")
  done

  if (( stage_failed > 0 )); then
    failures=$((failures + stage_failed))
    return 1
  fi
}

case "$1" in
  fmt)
    cargo fmt --all -- --check
    ;;

  clippy)
    clippy_profiles
    ;;

  test-crates)
    test_crates_profiles
    ;;

  test-binary)
    test_binary_profiles
    ;;

  test-workspace)
    test_workspace_profiles
    ;;

  test)
    # Local composition of every test lane, smallest first. CI runs the
    # lanes as parallel jobs (.github/workflows/ci.yml); this subcommand
    # stays the full sequential gate for pre-commit and local use.
    "$0" test-crates
    "$0" test-binary
    "$0" test-workspace
    ;;

  deny)
    # Full dependency graph: every storage backend plus the kernel engine.
    # cargo-deny 0.20 takes the cargo metadata flags before the subcommand.
    cargo deny \
      --workspace --no-default-features --features "rocksdb,fjall,redb,kernel" \
      check
    ;;

  contracts)
    cargo run --locked -p contract-index -- --check
    ;;

  proofs)
    proofs_stage
    ;;

  deep)
    collect_failures=true
    clippy_profiles
    test_crates_profiles
    test_binary_profiles
    test_workspace_profiles
    finish
    ;;

  all)
    "$0" fmt || failures=$((failures + 1))
    "$0" deep || failures=$((failures + 1))
    "$0" deny || failures=$((failures + 1))
    "$0" contracts || failures=$((failures + 1))
    finish
    ;;

  *)
    usage
    ;;
esac
