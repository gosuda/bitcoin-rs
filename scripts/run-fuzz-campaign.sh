#!/usr/bin/env bash
# Run one bounded fuzz campaign against a writable external corpus, minimize
# the result, and retain coverage and reproduction evidence for publication.
set -euo pipefail

cd "$(dirname "$0")/.."
REPO_ROOT="$(pwd)"
readonly REPO_ROOT
# shellcheck source=scripts/fuzz-policy.sh
source "${REPO_ROOT}/scripts/fuzz-policy.sh"
HOST_TARGET="$(rustc +nightly -vV | sed -n 's/^host: //p')"
readonly HOST_TARGET

usage() {
    echo "usage: $0 <target> <duration-seconds> <corpus-dir> <output-dir>" >&2
    exit 2
}

[[ $# -eq 4 ]] || usage

readonly TARGET="$1"
readonly DURATION_SECONDS="$2"
readonly CORPUS_DIR="$3"
readonly OUTPUT_DIR="$4"

[[ "${DURATION_SECONDS}" =~ ^[0-9]+$ ]] || usage
(( DURATION_SECONDS >= 1 && DURATION_SECONDS <= 21600 )) || usage
[[ -n "${HOST_TARGET}" ]] || {
    echo "could not determine the nightly host target" >&2
    exit 2
}

command -v cargo >/dev/null
command -v jq >/dev/null
command -v sha1sum >/dev/null

if ! cargo +nightly fuzz list | grep -Fxq -- "${TARGET}"; then
    echo "unknown fuzz target: ${TARGET}" >&2
    exit 2
fi

mkdir -p "${CORPUS_DIR}"
if [[ "$(stat -c %d fuzz)" != "$(stat -c %d "${CORPUS_DIR}")" ]]; then
    echo "cargo fuzz cmin requires the corpus and fuzz project on one filesystem" >&2
    exit 2
fi
if [[ -d "fuzz/corpus/${TARGET}" ]]; then
    cp -a "fuzz/corpus/${TARGET}/." "${CORPUS_DIR}/"
fi

if ! find "${CORPUS_DIR}" -maxdepth 1 -type f -print -quit | grep -q .; then
    echo "corpus has no inputs: ${CORPUS_DIR}" >&2
    exit 2
fi

readonly COVERAGE_PATH="${REPO_ROOT}/fuzz/coverage/${TARGET}"
if [[ -e "${COVERAGE_PATH}" ]]; then
    echo "preserving existing coverage data; move it before running: ${COVERAGE_PATH}" >&2
    exit 2
fi

mkdir -p \
    "${OUTPUT_DIR}/artifacts/${TARGET}" \
    "${OUTPUT_DIR}/corpus/${TARGET}" \
    "${OUTPUT_DIR}/metadata" \
    "${OUTPUT_DIR}/reports/${TARGET}"

readonly REPORT_DIR="${OUTPUT_DIR}/reports/${TARGET}"
readonly COVERAGE_BINARY="${REPO_ROOT}/fuzz/target/${HOST_TARGET}/release/${TARGET}"
LLVM_COV="$(rustc +nightly --print sysroot)/lib/rustlib/${HOST_TARGET}/bin/llvm-cov"
readonly LLVM_COV
[[ -x "${LLVM_COV}" ]] || {
    echo "llvm-cov is missing; install nightly's llvm-tools-preview component" >&2
    exit 2
}

count_inputs() {
    find "${CORPUS_DIR}" -maxdepth 1 -type f | wc -l
}

count_bytes() {
    find "${CORPUS_DIR}" -maxdepth 1 -type f -printf '%s\n' |
        awk '{ total += $1 } END { print total + 0 }'
}

coverage_report() {
    local phase="$1"
    local saved_path="${OUTPUT_DIR}/.coverage-${phase}"

    env -u RUSTC_WRAPPER -u CARGO_BUILD_BUILD_DIR CARGO_INCREMENTAL=0 \
        cargo +nightly fuzz coverage \
        --sanitizer none \
        --target "${HOST_TARGET}" \
        --target-dir "${REPO_ROOT}/fuzz/target" \
        "${TARGET}" "${CORPUS_DIR}" -- -timeout=10 \
        2>&1 | tee "${REPORT_DIR}/${phase}-coverage.log"

    "${LLVM_COV}" report "${COVERAGE_BINARY}" \
        --instr-profile="${COVERAGE_PATH}/coverage.profdata" \
        --ignore-filename-regex='(/\.cargo/registry/|/\.rustup/|/rustc/)' \
        | tee "${REPORT_DIR}/${phase}-coverage.txt"

    cp "${COVERAGE_PATH}/coverage.profdata" "${REPORT_DIR}/${phase}.profdata"
    mv "${COVERAGE_PATH}" "${saved_path}"
}

# Stream a command's output while returning its status through the named
# caller variable. A logging failure remains fatal; a command failure is
# recorded so the campaign can still preserve artifacts and coverage.
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

STARTED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
readonly STARTED_AT
START_COUNT="$(count_inputs)"
readonly START_COUNT
START_BYTES="$(count_bytes)"
readonly START_BYTES

coverage_report before

FUZZ_STATUS=0
run_with_tee "${REPORT_DIR}/fuzz.log" FUZZ_STATUS \
    env -u RUSTC_WRAPPER -u CARGO_BUILD_BUILD_DIR CARGO_INCREMENTAL=0 \
    cargo +nightly fuzz run \
        --target "${HOST_TARGET}" \
        --target-dir "${REPO_ROOT}/fuzz/target" \
        "${TARGET}" "${CORPUS_DIR}" -- \
        -max_total_time="${DURATION_SECONDS}" \
        -max_len="${FUZZ_MAX_SEED_BYTES}" \
        -timeout=10

CMIN_STATUS=0
run_with_tee "${REPORT_DIR}/cmin.log" CMIN_STATUS \
    env -u RUSTC_WRAPPER -u CARGO_BUILD_BUILD_DIR CARGO_INCREMENTAL=0 \
    cargo +nightly fuzz cmin \
        --target "${HOST_TARGET}" \
        --target-dir "${REPO_ROOT}/fuzz/target" \
        "${TARGET}" "${CORPUS_DIR}" -- -timeout=10
if grep -Fq 'Failed to minimize corpus:' "${REPORT_DIR}/cmin.log"; then
    CMIN_STATUS=1
fi

if [[ -d "fuzz/artifacts/${TARGET}" ]]; then
    cp -a "fuzz/artifacts/${TARGET}/." "${OUTPUT_DIR}/artifacts/${TARGET}/"
fi

coverage_report after

if (( CMIN_STATUS == 0 )); then
    find "${CORPUS_DIR}" -maxdepth 1 -type f -exec chmod 0644 {} +
    while IFS= read -r -d '' input; do
        expected="$(basename "${input}")"
        actual="$(sha1sum "${input}")"
        actual="${actual%% *}"
        if [[ "${expected}" != "${actual}" ]]; then
            echo "corpus input is not content-addressed: ${input}" >&2
            exit 1
        fi
    done < <(find "${CORPUS_DIR}" -maxdepth 1 -type f -print0)
    cp -a "${CORPUS_DIR}/." "${OUTPUT_DIR}/corpus/${TARGET}/"
fi

END_COUNT="$(count_inputs)"
readonly END_COUNT
END_BYTES="$(count_bytes)"
readonly END_BYTES
COMPLETED_AT="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
readonly COMPLETED_AT
BEFORE_TOTAL="$(tail -n 1 "${REPORT_DIR}/before-coverage.txt")"
readonly BEFORE_TOTAL
AFTER_TOTAL="$(tail -n 1 "${REPORT_DIR}/after-coverage.txt")"
readonly AFTER_TOTAL
FUZZ_LEAK_DETECTION=true
if [[ "${ASAN_OPTIONS:-}" == *detect_leaks=0* ]]; then
    FUZZ_LEAK_DETECTION=false
fi
readonly FUZZ_LEAK_DETECTION
SOURCE_COMMIT="${GITHUB_SHA:-$(git rev-parse HEAD)}"
readonly SOURCE_COMMIT
SOURCE_REPOSITORY="${GITHUB_REPOSITORY:-gosuda/bitcoin-rs}"
readonly SOURCE_REPOSITORY
if [[ -n "${GITHUB_RUN_ID:-}" ]]; then
    RUN_URL="${GITHUB_SERVER_URL:-https://github.com}/${SOURCE_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}"
else
    RUN_URL="local"
fi
readonly RUN_URL

jq -n \
    --arg target "${TARGET}" \
    --arg source_repository "${SOURCE_REPOSITORY}" \
    --arg source_commit "${SOURCE_COMMIT}" \
    --arg corpus_base_commit "${FUZZ_CORPUS_BASE_SHA:-unknown}" \
    --arg run_url "${RUN_URL}" \
    --arg started_at "${STARTED_AT}" \
    --arg completed_at "${COMPLETED_AT}" \
    --arg coverage_before_total "${BEFORE_TOTAL}" \
    --arg coverage_after_total "${AFTER_TOTAL}" \
    --argjson duration_seconds "${DURATION_SECONDS}" \
    --argjson max_seed_bytes "${FUZZ_MAX_SEED_BYTES}" \
    --argjson start_count "${START_COUNT}" \
    --argjson start_bytes "${START_BYTES}" \
    --argjson end_count "${END_COUNT}" \
    --argjson end_bytes "${END_BYTES}" \
    --argjson fuzz_exit_status "${FUZZ_STATUS}" \
    --argjson cmin_exit_status "${CMIN_STATUS}" \
    --argjson fuzz_leak_detection "${FUZZ_LEAK_DETECTION}" \
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
    }' > "${OUTPUT_DIR}/metadata/${TARGET}.json"

if [[ -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
    {
        echo "### ${TARGET}"
        echo
        echo "- Corpus: ${START_COUNT} inputs / ${START_BYTES} bytes -> ${END_COUNT} inputs / ${END_BYTES} bytes"
        echo "- Coverage before: \`${BEFORE_TOTAL}\`"
        echo "- Coverage after: \`${AFTER_TOTAL}\`"
        echo "- Fuzzer exit: ${FUZZ_STATUS}; minimizer exit: ${CMIN_STATUS}"
    } >> "${GITHUB_STEP_SUMMARY}"
fi

if (( FUZZ_STATUS != 0 || CMIN_STATUS != 0 )); then
    exit 1
fi
