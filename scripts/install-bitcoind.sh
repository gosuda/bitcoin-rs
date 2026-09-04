#!/usr/bin/env bash
# Install the pinned Bitcoin Core 31.1 bitcoind used by the live differential.
#
# Downloads the official x86_64 Linux tarball from bitcoincore.org, checks it
# against the hardcoded SHA-256, and extracts bitcoind. Prints the bitcoind
# path on stdout (log lines go to stderr).
#
#   eval "$(scripts/install-bitcoind.sh --export)"
#   scripts/install-bitcoind.sh --print-path
#
# Owner: docs/contracts/core-differential.md (CORE-01).

set -euo pipefail

readonly CORE_VERSION="31.1"
readonly TARBALL="bitcoin-${CORE_VERSION}-x86_64-linux-gnu.tar.gz"
readonly TARBALL_SHA256="b80d9c3e04da78fb6f0569685673418cf686fadba9042d926d13fb87ff503f9e"
readonly TARBALL_URL="https://bitcoincore.org/bin/bitcoin-core-${CORE_VERSION}/${TARBALL}"
readonly PREFIX="${BITCOIND_PREFIX:-${HOME}/bitcoin-core-${CORE_VERSION}}"
readonly BITCOIND="${PREFIX}/bin/bitcoind"

usage() {
  printf '%s\n' 'usage: scripts/install-bitcoind.sh [--print-path|--export]'
}

MODE=install
case "${1:-}" in
  --print-path) MODE=print-path ;;
  --export) MODE=export ;;
  -h|--help) usage; exit 0 ;;
  "") ;;
  *) usage >&2; exit 2 ;;
esac

log() { printf '[install-bitcoind] %s\n' "$*" >&2; }

readonly STAMP="${PREFIX}/.bitcoin-rs-core-tarball-sha256"
cached_matches_pin() {
  [[ -x "${BITCOIND}" && -f "${STAMP}" ]] || return 1
  [[ "$(cat -- "${STAMP}")" == "${TARBALL_SHA256}" ]] || return 1
  local version
  version="$("${BITCOIND}" -version 2>/dev/null | head -n1 || true)"
  [[ "${version}" == *"v${CORE_VERSION}"* ]]
}

if cached_matches_pin; then
  log "already installed at ${BITCOIND} (tarball ${TARBALL_SHA256})"
else
  if [[ -x "${BITCOIND}" ]]; then
    log "cached ${BITCOIND} is not the pinned Core ${CORE_VERSION} artifact; reinstalling"
  fi
  log "downloading ${TARBALL_URL}"
  WORKDIR="$(mktemp -d /tmp/bitcoind-install.XXXXXX)"
  trap 'rm -rf -- "${WORKDIR:?}"' EXIT
  curl -fsSL --retry 4 --retry-delay 4 -o "${WORKDIR}/${TARBALL}" "${TARBALL_URL}"
  got="$(sha256sum -- "${WORKDIR}/${TARBALL}" | awk '{ print $1 }')"
  if [[ "${got}" != "${TARBALL_SHA256}" ]]; then
    log "ABORT: tarball sha256 ${got} != ${TARBALL_SHA256}"
    exit 1
  fi
  mkdir -p "${PREFIX}/bin"
  tar -xzf "${WORKDIR}/${TARBALL}" -C "${WORKDIR}"
  install -m 0755 "${WORKDIR}/bitcoin-${CORE_VERSION}/bin/bitcoind" "${BITCOIND}"
  if [[ -f "${WORKDIR}/bitcoin-${CORE_VERSION}/bin/bitcoin-cli" ]]; then
    install -m 0755 "${WORKDIR}/bitcoin-${CORE_VERSION}/bin/bitcoin-cli" "${PREFIX}/bin/bitcoin-cli"
  fi
  printf '%s\n' "${TARBALL_SHA256}" > "${STAMP}"
  log "installed ${BITCOIND}"
fi

case "${MODE}" in
  print-path) printf '%s\n' "${BITCOIND}" ;;
  export) printf 'BITCOIND_COMMAND=%q\n' "${BITCOIND}" ;;
  install) printf '%s\n' "${BITCOIND}" ;;
esac
