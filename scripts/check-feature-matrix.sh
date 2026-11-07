#!/usr/bin/env bash

set -euo pipefail

usage() {
  printf '%s\n' 'usage: scripts/check-feature-matrix.sh [all|pure|native]'
}

FILTER=${1:-all}
case "${FILTER}" in
  all|pure|native) ;;
  -h|--help)
    usage
    exit 0
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac

ROOT="$(git rev-parse --show-toplevel)"
cd "${ROOT}"
MATRIX="${ROOT}/scripts/feature-matrix.tsv"
[[ -f "${MATRIX}" ]] || {
  printf 'error: missing %s\n' "${MATRIX}" >&2
  exit 1
}

log() { printf '[feature-matrix] %s\n' "$*"; }

checked=0
while IFS=$'\t' read -r name package lane args; do
  [[ -z "${name}" || "${name}" == \#* ]] && continue
  case "${FILTER}" in
    pure) [[ "${lane}" == pure ]] || continue ;;
    native) [[ "${lane}" == native ]] || continue ;;
  esac
  log "${name}: cargo check --locked -p ${package} ${args}"
  # shellcheck disable=SC2086
  cargo check --locked -p "${package}" ${args}
  checked=$((checked + 1))
done < "${MATRIX}"

if [[ "${checked}" -eq 0 ]]; then
  log "ABORT: no rows matched filter ${FILTER}"
  exit 1
fi
log "ok (${checked} combinations, filter=${FILTER})"
