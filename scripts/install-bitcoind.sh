#!/usr/bin/env bash
# Install the pinned Bitcoin Core 31.1 bitcoind used by the live differential.
#
# Downloads the official release artifact for the host platform — the
# x86_64 Linux tarball or, under MSYS/MINGW/CYGWIN on Windows, the win64
# zip — checks it against the hardcoded SHA-256, and extracts bitcoind.
# Prints the bitcoind path on stdout (log lines go to stderr).
#
#   scripts/install-bitcoind.sh --print-path
#   eval "$(scripts/install-bitcoind.sh --export)"   # exports BITCOIND_COMMAND
#
# Owner: docs/contracts/core-differential.md (CORE-01).

set -euo pipefail

readonly CORE_VERSION="31.1"
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*)
    TARBALL="bitcoin-${CORE_VERSION}-win64.zip"
    TARBALL_SHA256="c99ef173471c58e6766d9eebd12e6c35349082eeed3939bc99eed58ef57db587"
    BITCOIND_NAME="bitcoind.exe"
    BITCOIN_CLI_NAME="bitcoin-cli.exe"
    ;;
  *)
    TARBALL="bitcoin-${CORE_VERSION}-x86_64-linux-gnu.tar.gz"
    TARBALL_SHA256="b80d9c3e04da78fb6f0569685673418cf686fadba9042d926d13fb87ff503f9e"
    BITCOIND_NAME="bitcoind"
    BITCOIN_CLI_NAME="bitcoin-cli"
    ;;
esac
readonly TARBALL TARBALL_SHA256 BITCOIND_NAME BITCOIN_CLI_NAME
readonly TARBALL_URL="https://bitcoincore.org/bin/bitcoin-core-${CORE_VERSION}/${TARBALL}"
readonly PREFIX="${BITCOIND_PREFIX:-${HOME}/bitcoin-core-${CORE_VERSION}}"
readonly BITCOIND="${PREFIX}/bin/${BITCOIND_NAME}"

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
  version="$("${BITCOIND}" -version 2>/dev/null)" || return 1
  version="${version%%$'\n'*}"
  # Component-exact match against the canonical pin, mirroring
  # crates/p2p/tests/core_interop_live.rs version_is_pinned_line: the pinned
  # "31.1" accepts 31.1(.N) but not 31.10(.N), 31.2(.N), or 30.1(.N).
  [[ "${version}" =~ ([0-9]+(\.[0-9]+)*) ]] || return 1
  local -a parsed=()
  IFS='.' read -r -a parsed <<< "${BASH_REMATCH[1]}"
  local -a pinned=()
  IFS='.' read -r -a pinned <<< "${CORE_VERSION}"
  ((${#parsed[@]} >= ${#pinned[@]})) || return 1
  local i
  for ((i = 0; i < ${#pinned[@]}; i++)); do
    [[ "${parsed[i]}" == "${pinned[i]}" ]] || return 1
  done
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
  # GNU tar cannot read zip archives, so the win64 artifact extracts with
  # unzip while the linux tarball keeps tar.
  case "${TARBALL}" in
    *.zip) unzip -o -q "${WORKDIR}/${TARBALL}" -d "${WORKDIR}" ;;
    *) tar -xzf "${WORKDIR}/${TARBALL}" -C "${WORKDIR}" ;;
  esac
  install -m 0755 "${WORKDIR}/bitcoin-${CORE_VERSION}/bin/${BITCOIND_NAME}" "${BITCOIND}"
  if [[ -f "${WORKDIR}/bitcoin-${CORE_VERSION}/bin/${BITCOIN_CLI_NAME}" ]]; then
    install -m 0755 "${WORKDIR}/bitcoin-${CORE_VERSION}/bin/${BITCOIN_CLI_NAME}" "${PREFIX}/bin/${BITCOIN_CLI_NAME}"
  fi
  printf '%s\n' "${TARBALL_SHA256}" > "${STAMP}"
  log "installed ${BITCOIND}"
fi

case "${MODE}" in
  print-path) printf '%s\n' "${BITCOIND}" ;;
  export) printf 'export BITCOIND_COMMAND=%q\n' "${BITCOIND}" ;;
  install) printf '%s\n' "${BITCOIND}" ;;
esac
