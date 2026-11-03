#!/usr/bin/env bash
set -euo pipefail

cleanup() {
    trap - EXIT INT TERM
}
trap cleanup EXIT INT TERM

cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"
readonly REPO_ROOT
# shellcheck source=scripts/fuzz-policy.sh
source "${REPO_ROOT}/scripts/fuzz-policy.sh"

HOST_TARGET="$(rustc +nightly -vV | sed -n 's/^host: //p')"
readonly HOST_TARGET
[[ -n "${HOST_TARGET}" ]] || {
    printf '%s\n' "could not determine the nightly host target" >&2
    exit 2
}

command -v cargo >/dev/null
command -v jq >/dev/null
command -v sha1sum >/dev/null

if [[ "${FUZZ_DEBUG_ASSERTIONS:-1}" == "1" || "${FUZZ_DEBUG_ASSERTIONS:-}" == "true" ]]; then
    export RUSTFLAGS="${RUSTFLAGS:-} -C debug-assertions -C overflow-checks"
fi

discover_fuzz_targets() {
    local manifest="${REPO_ROOT}/fuzz/Cargo.toml"
    if [[ ! -f "${manifest}" ]]; then
        printf '%s\n' "manifest not found: ${manifest}" >&2
        return 1
    fi
    awk -F'=' '
        /\[\[bin\]\]/ { in_bin=1; next }
        in_bin && /name[ \t]*=/ {
            gsub(/[ \t"]/, "", $2);
            print $2;
            in_bin=0
        }
    ' "${manifest}"
}

get_target_weight() {
    local target="$1"
    case "${target}" in
        script_eval|script_differential)
            printf '%s\n' 4 ;;
        block_validate|tx_validate|tx_differential|chainstate_reorg_model)
            printf '%s\n' 3 ;;
        p2p_message|p2p_message_structured|bip324_transport|compact_block_reconstruct)
            printf '%s\n' 2 ;;
        block_decode_roundtrip|header_sync_sequence|utxo_snapshot|undo_row_decode|index_row_decode|utxo_record_decode|mempool_dat_load)
            printf '%s\n' 2 ;;
        addrman_load|socks_sam_reply|rpc_http_request|jsonrpc_batch|esplora_route|rpc_hex_params)
            printf '%s\n' 1 ;;
        *)
            printf '%s\n' 2 ;;
    esac
}

usage() {
    cat >&2 <<EOF
usage: $0 [<target>|all|full] [<duration-seconds>] [<corpus-dir>] [<output-dir>]
       $0 <target> <duration-seconds> <corpus-dir> <output-dir>

Modes:
  <target>   Run a single fuzz target.
  all        Run every target discovered in fuzz/Cargo.toml for <duration-seconds> each.
  full       Run every target for a total bounded time split by weights, then cmin each.

Environment:
  FUZZ_TIMEOUT            Per-input timeout in seconds (default: 10)
  FUZZ_RSS_LIMIT_MB       RSS memory limit in MB (default: 2048)
  FUZZ_MALLOC_LIMIT_MB    Malloc memory limit in MB (default: 2048)
  FUZZ_DEBUG_ASSERTIONS   1 to enable -C debug-assertions -C overflow-checks (default: 1)
EOF
    exit 2
}

MODE="${1:-full}"
DURATION_ARG="${2:-${FUZZ_MAX_TOTAL_TIME:-3600}}"
CORPUS_ARG="${3:-}"
OUTPUT_DIR="${4:-campaign-output}"

[[ "${DURATION_ARG}" =~ ^[0-9]+$ ]] || usage
DURATION_SECONDS="${DURATION_ARG}"
(( DURATION_SECONDS >= 1 && DURATION_SECONDS <= 86400 )) || usage

FUZZ_CORPUS_DIR="${FUZZ_CORPUS_DIR:-}"
if [[ -z "${FUZZ_CORPUS_DIR}" ]]; then
    if [[ -d "${REPO_ROOT}/.outline/fuzz-corpus/corpus" ]]; then
        FUZZ_CORPUS_DIR="${REPO_ROOT}/.outline/fuzz-corpus/corpus"
    elif [[ -d "${REPO_ROOT}/../bitcoin-rs-fuzz-corpus/corpus" ]]; then
        FUZZ_CORPUS_DIR="${REPO_ROOT}/../bitcoin-rs-fuzz-corpus/corpus"
    fi
fi

if [[ -z "${CORPUS_ARG}" ]]; then
    CORPUS_BASE="${REPO_ROOT}/fuzz/corpus"
else
    CORPUS_BASE="${CORPUS_ARG}"
fi

LLVM_COV="$(rustc +nightly --print sysroot)/lib/rustlib/${HOST_TARGET}/bin/llvm-cov"
HAVE_LLVM_COV=false
if [[ -x "${LLVM_COV}" ]]; then
    HAVE_LLVM_COV=true
fi

run_with_tee() {
    local log_path="$1"
    local status_name="$2"
    local -a pipeline_status
    shift 2

    if "$@" 2>&1 | tee "${log_path}"; then
        printf -v "${status_name}" '%s' 0
        return 0
    fi
    pipeline_status=("${PIPESTATUS[@]}")
    if (( pipeline_status[1] != 0 )); then
        return "${pipeline_status[1]}"
    fi
    printf -v "${status_name}" '%s' "${pipeline_status[0]}"
}

count_inputs() {
    local dir="$1"
    find "${dir}" -maxdepth 1 -type f | wc -l
}

count_bytes() {
    local dir="$1"
    find "${dir}" -maxdepth 1 -type f -printf '%s\n' |
        awk '{ total += $1 } END { print total + 0 }'
}

run_target_coverage() {
    local target="$1"
    local phase="$2"
    local corpus_dir="$3"
    local report_dir="${OUTPUT_DIR}/reports/${target}"
    local coverage_path="${REPO_ROOT}/fuzz/coverage/${target}"
    local saved_path="${OUTPUT_DIR}/.coverage-${target}-${phase}"
    local coverage_binary="${REPO_ROOT}/fuzz/target/${HOST_TARGET}/release/${target}"

    if [[ "${FUZZ_COVERAGE:-0}" != "1" && "${FUZZ_COVERAGE:-}" != "true" ]] || [[ "${HAVE_LLVM_COV}" != "true" ]]; then
        printf '%s\n' "none" > "${report_dir}/${phase}-coverage.txt"
        return 0
    fi
    rm -rf -- "${coverage_path:?missing coverage path}" "${saved_path:?missing saved path}"

    env -u RUSTC_WRAPPER -u CARGO_BUILD_BUILD_DIR CARGO_INCREMENTAL=0 \
        cargo +nightly fuzz coverage \
        --sanitizer none \
        --target "${HOST_TARGET}" \
        --target-dir "${REPO_ROOT}/fuzz/target" \
        "${target}" "${corpus_dir}" -- -timeout=10 \
        2>&1 | tee "${report_dir}/${phase}-coverage.log" || true

    if [[ -f "${coverage_path}/coverage.profdata" && -f "${coverage_binary}" ]]; then
        "${LLVM_COV}" report "${coverage_binary}" \
            --instr-profile="${coverage_path}/coverage.profdata" \
            --ignore-filename-regex='(/\.cargo/registry/|/\.rustup/|/rustc/)' \
            | tee "${report_dir}/${phase}-coverage.txt" || printf '%s\n' "none" > "${report_dir}/${phase}-coverage.txt"

        cp "${coverage_path}/coverage.profdata" "${report_dir}/${phase}.profdata" 2>/dev/null || true
        mv "${coverage_path}" "${saved_path}" 2>/dev/null || true
    else
        printf '%s\n' "none" > "${report_dir}/${phase}-coverage.txt"
    fi
}

run_single_campaign() {
    local target="$1"
    local target_duration="$2"
    local target_corpus="$3"

    printf '%s\n' "================================================================="
    printf '%s\n' "Starting campaign for target: ${target} (${target_duration}s)"
    printf '%s\n' "Corpus: ${target_corpus}"
    printf '%s\n' "================================================================="

    mkdir -p \
        "${target_corpus}" \
        "${OUTPUT_DIR}/artifacts/${target}" \
        "${OUTPUT_DIR}/corpus/${target}" \
        "${OUTPUT_DIR}/metadata" \
        "${OUTPUT_DIR}/reports/${target}"

    if [[ "$(stat -c %d fuzz)" != "$(stat -c %d "${target_corpus}")" ]]; then
        printf '%s\n' "cargo fuzz cmin requires the corpus and fuzz project on one filesystem" >&2
        exit 2
    fi

    local ref_seed_dir="${FUZZ_CORPUS_DIR:-${CORPUS_BASE}}"
    if [[ -d "${ref_seed_dir}/${target}" ]] &&
       [[ "$(cd "${ref_seed_dir}/${target}" && pwd -P)" != "$(cd "${target_corpus}" && pwd -P)" ]] &&
       ! find "${target_corpus}" -maxdepth 1 -type f -print -quit | grep -q .; then
        cp -a "${ref_seed_dir}/${target}/." "${target_corpus}/"
    fi

    if ! find "${target_corpus}" -maxdepth 1 -type f -print -quit | grep -q .; then
        local zero_hash
        zero_hash="$(printf '\x00' | sha1sum | cut -d' ' -f1)"
        printf '\x00' > "${target_corpus}/${zero_hash}"
    fi

    local report_dir="${OUTPUT_DIR}/reports/${target}"
    local started_at
    started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    local start_count
    start_count="$(count_inputs "${target_corpus}")"
    local start_bytes
    start_bytes="$(count_bytes "${target_corpus}")"

    run_target_coverage "${target}" "before" "${target_corpus}"

    local -a fuzz_args=(
        "-max_total_time=${target_duration}"
        "-max_len=${FUZZ_MAX_SEED_BYTES}"
        "-timeout=${FUZZ_TIMEOUT:-${FUZZ_DEFAULT_TIMEOUT_SECS:-10}}"
        "-rss_limit_mb=${FUZZ_RSS_LIMIT_MB:-${FUZZ_DEFAULT_RSS_LIMIT_MB:-2048}}"
        "-malloc_limit_mb=${FUZZ_MALLOC_LIMIT_MB:-${FUZZ_DEFAULT_MALLOC_LIMIT_MB:-2048}}"
        "-use_value_profile=1"
    )

    if [[ -n "${FUZZ_JOBS:-}" ]]; then
        fuzz_args+=("-jobs=${FUZZ_JOBS}")
    fi
    if [[ -n "${FUZZ_WORKERS:-}" ]]; then
        fuzz_args+=("-workers=${FUZZ_WORKERS}")
    fi

    local dict_path="${REPO_ROOT}/fuzz/dictionaries/${target}.dict"
    if [[ -f "${dict_path}" ]]; then
        fuzz_args+=("-dict=${dict_path}")
    fi

    local fuzz_status=0
    printf '%s\n' "Running cargo +nightly fuzz run for ${target}..."
    run_with_tee "${report_dir}/fuzz.log" fuzz_status \
        env -u RUSTC_WRAPPER -u CARGO_BUILD_BUILD_DIR CARGO_INCREMENTAL=0 \
        cargo +nightly fuzz run \
            --target "${HOST_TARGET}" \
            --target-dir "${REPO_ROOT}/fuzz/target" \
            "${target}" "${target_corpus}" -- \
            "${fuzz_args[@]}" || true

    local cmin_status=0
    printf '%s\n' "Minimizing corpus with cargo +nightly fuzz cmin for ${target}..."
    run_with_tee "${report_dir}/cmin.log" cmin_status \
        env -u RUSTC_WRAPPER -u CARGO_BUILD_BUILD_DIR CARGO_INCREMENTAL=0 \
        cargo +nightly fuzz cmin \
            --target "${HOST_TARGET}" \
            --target-dir "${REPO_ROOT}/fuzz/target" \
            "${target}" "${target_corpus}" -- \
            -timeout="${FUZZ_TIMEOUT:-${FUZZ_DEFAULT_TIMEOUT_SECS:-10}}" \
            -max_len="${FUZZ_MAX_SEED_BYTES}" \
            -rss_limit_mb="${FUZZ_RSS_LIMIT_MB:-${FUZZ_DEFAULT_RSS_LIMIT_MB:-2048}}" || true

    if grep -Fq 'Failed to minimize corpus:' "${report_dir}/cmin.log"; then
        cmin_status=1
    fi

    if [[ -d "${REPO_ROOT}/fuzz/artifacts/${target}" ]]; then
        cp -a "${REPO_ROOT}/fuzz/artifacts/${target}/." "${OUTPUT_DIR}/artifacts/${target}/" 2>/dev/null || true
    fi
    find "${REPO_ROOT}" -maxdepth 1 \( -name 'crash-*' -o -name 'oom-*' -o -name 'timeout-*' -o -name 'leak-*' \) \
        -exec mv -t "${OUTPUT_DIR}/artifacts/${target}/" {} + 2>/dev/null || true

    run_target_coverage "${target}" "after" "${target_corpus}"

    if (( cmin_status == 0 )); then
        if ! "${REPO_ROOT}/scripts/validate-corpus-seeds.sh" \
            "${target_corpus}" "${target}"; then
            printf '%s\n' "refusing to publish corpus for ${target}" >&2
            return 1
        fi
        rsync -a --delete "${target_corpus}/" "${OUTPUT_DIR}/corpus/${target}/"
    fi

    local end_count
    end_count="$(count_inputs "${target_corpus}")"
    local end_bytes
    end_bytes="$(count_bytes "${target_corpus}")"
    local completed_at
    completed_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    local before_total="none"
    if [[ -f "${report_dir}/before-coverage.txt" ]]; then
        before_total="$(tail -n 1 "${report_dir}/before-coverage.txt")"
    fi
    local after_total="none"
    if [[ -f "${report_dir}/after-coverage.txt" ]]; then
        after_total="$(tail -n 1 "${report_dir}/after-coverage.txt")"
    fi

    local leak_detection=true
    if [[ "${ASAN_OPTIONS:-}" == *detect_leaks=0* ]]; then
        leak_detection=false
    fi

    local source_commit="${GITHUB_SHA:-$(git rev-parse HEAD 2>/dev/null || printf '%s' unknown)}"
    local source_repo="${GITHUB_REPOSITORY:-gosuda/bitcoin-rs}"
    local run_url=""
    if [[ -n "${GITHUB_RUN_ID:-}" ]]; then
        run_url="https://github.com/${source_repo}/actions/runs/${GITHUB_RUN_ID}"
    fi

    jq -n \
        --arg target "${target}" \
        --arg source_repository "${source_repo}" \
        --arg source_commit "${source_commit}" \
        --arg corpus_base_commit "${FUZZ_CORPUS_BASE_SHA:-unknown}" \
        --arg run_url "${run_url}" \
        --arg started_at "${started_at}" \
        --arg completed_at "${completed_at}" \
        --arg coverage_before_total "${before_total}" \
        --arg coverage_after_total "${after_total}" \
        --argjson duration_seconds "${target_duration}" \
        --argjson max_seed_bytes "${FUZZ_MAX_SEED_BYTES}" \
        --argjson start_count "${start_count}" \
        --argjson start_bytes "${start_bytes}" \
        --argjson end_count "${end_count}" \
        --argjson end_bytes "${end_bytes}" \
        --argjson fuzz_exit_status "${fuzz_status}" \
        --argjson cmin_exit_status "${cmin_status}" \
        --argjson fuzz_leak_detection "${leak_detection}" \
        '{
            target: $target,
            source_repository: $source_repository,
            source_commit: $source_commit,
            corpus_base_commit: $corpus_base_commit,
            run_url: $run_url,
            started_at: $started_at,
            completed_at: $completed_at,
            duration_seconds: $duration_seconds,
            max_seed_bytes: $max_seed_bytes,
            corpus: {
                before: {inputs: $start_count, bytes: $start_bytes},
                after: {inputs: $end_count, bytes: $end_bytes}
            },
            coverage: {
                before_total: $coverage_before_total,
                after_total: $coverage_after_total
            },
            sanitizers: {
                fuzz: "address",
                fuzz_leak_detection: $fuzz_leak_detection,
                coverage: "none"
            },
            fuzz_exit_status: $fuzz_exit_status,
            cmin_exit_status: $cmin_exit_status
        }' > "${OUTPUT_DIR}/metadata/${target}.json"

    if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
        {
            printf '%s\n' "### ${target}"
            printf '\n'
            printf '%s\n' "- Corpus: ${start_count} inputs / ${start_bytes} bytes -> ${end_count} inputs / ${end_bytes} bytes"
            printf '%s\n' "- Coverage before: \`${before_total}\`"
            printf '%s\n' "- Coverage after: \`${after_total}\`"
            printf '%s\n' "- Fuzzer exit: ${fuzz_status}; minimizer exit: ${cmin_status}"
        } >> "${GITHUB_STEP_SUMMARY}"
    fi

    printf '%s\n' "--- Target ${target} final stats ---"
    local stats_line
    stats_line="$(grep -E '(INITED|NEW|DONE|RELOAD)' "${report_dir}/fuzz.log" 2>/dev/null | tail -n 1 || printf '%s\n' "no stats line")"
    printf '%s\n' "${stats_line}"

    if (( fuzz_status != 0 || cmin_status != 0 )); then
        return 1
    fi
    return 0
}

TARGETS=()
if [[ "${MODE}" == "full" || "${MODE}" == "all" ]]; then
    while IFS= read -r t; do
        [[ -n "${t}" ]] && TARGETS+=("${t}")
    done < <(discover_fuzz_targets)
    if (( ${#TARGETS[@]} == 0 )); then
        printf '%s\n' "no fuzz targets discovered in fuzz/Cargo.toml" >&2
        exit 2
    fi
else
    TARGETS=("${MODE}")
    if ! cargo +nightly fuzz list | grep -Fxq -- "${MODE}"; then
        printf '%s\n' "unknown fuzz target: ${MODE}" >&2
        exit 2
    fi
fi

CAMPAIGN_FAILED=0

if [[ "${MODE}" == "full" ]]; then
    TOTAL_WEIGHT=0
    for t in "${TARGETS[@]}"; do
        w="$(get_target_weight "${t}")"
        TOTAL_WEIGHT=$(( TOTAL_WEIGHT + w ))
    done

    printf '%s\n' "Running FULL fuzz campaign across ${#TARGETS[@]} targets (Total time: ${DURATION_SECONDS}s, Total weight: ${TOTAL_WEIGHT})"

    for t in "${TARGETS[@]}"; do
        w="$(get_target_weight "${t}")"
        allocated_secs=$(( DURATION_SECONDS * w / TOTAL_WEIGHT ))
        (( allocated_secs >= 1 )) || allocated_secs=1
        target_corpus="${CORPUS_BASE}/${t}"
        if ! run_single_campaign "${t}" "${allocated_secs}" "${target_corpus}"; then
            CAMPAIGN_FAILED=1
        fi
    done

elif [[ "${MODE}" == "all" ]]; then
    printf '%s\n' "Running ALL fuzz campaign across ${#TARGETS[@]} targets (${DURATION_SECONDS}s each)"
    for t in "${TARGETS[@]}"; do
        target_corpus="${CORPUS_BASE}/${t}"
        if ! run_single_campaign "${t}" "${DURATION_SECONDS}" "${target_corpus}"; then
            CAMPAIGN_FAILED=1
        fi
    done

else
    t="${MODE}"
    if [[ -n "${CORPUS_ARG}" ]]; then
        target_corpus="${CORPUS_ARG}"
    else
        target_corpus="${CORPUS_BASE}/${t}"
    fi
    if ! run_single_campaign "${t}" "${DURATION_SECONDS}" "${target_corpus}"; then
        CAMPAIGN_FAILED=1
    fi
fi

printf '\n'
printf '%s\n' "================================================================="
printf '%s\n' "                   FUZZ CAMPAIGN CRASH SUMMARY                   "
printf '%s\n' "================================================================="
ARTIFACT_COUNT=0
if [[ -d "${OUTPUT_DIR}/artifacts" ]]; then
    ARTIFACT_COUNT="$(find "${OUTPUT_DIR}/artifacts" -type f | wc -l)"
fi

if (( ARTIFACT_COUNT > 0 )); then
    printf '%s\n' "CRITICAL: Found ${ARTIFACT_COUNT} artifact(s) in ${OUTPUT_DIR}/artifacts:"
    find "${OUTPUT_DIR}/artifacts" -type f -exec ls -la {} +
    printf '%s\n' "================================================================="
    exit 1
else
    printf '%s\n' "SUCCESS: 0 crash artifacts found across all tested targets."
    printf '%s\n' "================================================================="
fi

if (( CAMPAIGN_FAILED != 0 )); then
    printf '%s\n' "Target execution failed." >&2
    exit 1
fi

exit 0
