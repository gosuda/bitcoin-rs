#!/usr/bin/env bash
# Runner for Bitcoin Core v31.1 functional tests against the bitcoin-rs node.
#
# Usage:
#   tools/core-functional/run.sh [options] [test ...]
#
# Options:
#   --jobs N           parallel tests (default 4)
#   --timeout SECS     per-test timeout (default 300)
#   --results-dir DIR  default target/core-functional/results/<timestamp>
#   --dest DIR         extraction dir (default target/core-functional/core-v31.1;
#                      create it first with fetch-core-tests.sh)
#   --list             print the clean-candidate test names and exit
#
# Environment:
#   BITCOIN_RS_BIN     (required) path to the bitcoin-rs node binary
#   BITCOIN_RS_EXTRA_ARGS  (optional) extra bitcoin-rs flags, appended verbatim
#                      by the wrapper after translation
#
# Exit codes: 0 no failures, 1 at least one FAIL, 2 usage/environment error.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

DEST="${REPO_ROOT}/target/core-functional/core-v31.1"
RESULTS_DIR=""
JOBS=4
TIMEOUT=300
TESTS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --jobs) JOBS="$2"; shift 2 ;;
        --timeout) TIMEOUT="$2"; shift 2 ;;
        --results-dir) RESULTS_DIR="$2"; shift 2 ;;
        --dest) DEST="$2"; shift 2 ;;
        --list) sed '/^#/d;/^$/d' "${SCRIPT_DIR}/tests/clean-candidates.txt"; exit 0 ;;
        -h|--help) sed -n '2,25p' "${BASH_SOURCE[0]}"; exit 0 ;;
        --*) echo "run.sh: unknown option: $1" >&2; exit 2 ;;
        *) TESTS+=("$1"); shift ;;
    esac
done

# Fail-safe before doing anything: the node binary must be named and present.
if [[ -z "${BITCOIN_RS_BIN:-}" ]]; then
    cat >&2 <<EOF
run.sh: BITCOIN_RS_BIN is not set.

Build (or locate) the bitcoin-rs node binary and export it, e.g.
  cargo build --release --bin bitcoin-rs
  export BITCOIN_RS_BIN="${REPO_ROOT}/target/release/bitcoin-rs"
then re-run tools/core-functional/run.sh
EOF
    exit 2
fi
if [[ ! -x "${BITCOIN_RS_BIN}" ]]; then
    echo "run.sh: BITCOIN_RS_BIN=${BITCOIN_RS_BIN} is not executable" >&2
    exit 2
fi

if [[ ! -d "${DEST}/test/functional/test_framework" ]]; then
    echo "run.sh: ${DEST} has no extracted Core tests." >&2
    echo "  run: ${SCRIPT_DIR}/fetch-core-tests.sh --dest ${DEST}" >&2
    exit 2
fi

# The framework finds the node through BITCOIND or <BUILDDIR>/bin/bitcoind;
# both point at the wrapper (fetch-core-tests.sh also maintains this symlink).
mkdir -p "${DEST}/bin"
ln -sfn "${SCRIPT_DIR}/bin/bitcoind-wrapper" "${DEST}/bin/bitcoind"

if [[ ${#TESTS[@]} -eq 0 ]]; then
    mapfile -t TESTS < <(sed '/^#/d;/^$/d' "${SCRIPT_DIR}/tests/clean-candidates.txt")
fi

# Validate names against the extracted tree (accept bare names or *.py).
NORMALIZED=()
for test in "${TESTS[@]}"; do
    name="${test%.py}"
    if [[ ! -f "${DEST}/test/functional/${name}.py" ]]; then
        echo "run.sh: no such test in ${DEST}/test/functional: ${test}" >&2
        exit 2
    fi
    NORMALIZED+=("${name}")
done

if [[ -z "${RESULTS_DIR}" ]]; then
    RESULTS_DIR="${REPO_ROOT}/target/core-functional/results/$(date -u +%Y%m%dT%H%M%SZ)"
fi
mkdir -p "${RESULTS_DIR}"

export BITCOIND="${DEST}/bin/bitcoind"
export PYTHONPATH="${SCRIPT_DIR}/shim${PYTHONPATH:+:${PYTHONPATH}}"

exec python3 "${SCRIPT_DIR}/bin/runner.py" \
    --tests "${NORMALIZED[@]}" \
    --dest "${DEST}" \
    --template "${SCRIPT_DIR}/config.ini" \
    --config "${RESULTS_DIR}/config.ini" \
    --results-dir "${RESULTS_DIR}" \
    --jobs "${JOBS}" \
    --timeout "${TIMEOUT}"
