#!/usr/bin/env bash
# Install the pinned Bitcoin Core 31.1 bitcoind used by the live differential.
#
# Downloads the official tarball for this platform from bitcoincore.org,
# checks it against the SHA-256 pinned in crates/rpc/core-compat.toml, and
# extracts bitcoind. Prints the bitcoind path on stdout (log lines go to
# stderr).
#
#   scripts/install-bitcoind.sh --print-path
#   eval "$(scripts/install-bitcoind.sh --export)"   # exports BITCOIND_COMMAND
#
# Owner: docs/contracts/core-differential.md (CORE-01).

set -euo pipefail

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

# Resolve the manifest without changing the process directory: a relative
# BITCOIND_PREFIX keeps meaning the caller's directory.
REPO="$(cd -- "$(dirname -- "$0")/.." && pwd)"

# tomllib needs Python >=3.11; the system python3 on macOS is older, so
# probe the versioned interpreters before falling back to plain python3.
PYTHON=""
for candidate in python3.13 python3.12 python3.11 python3; do
  if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import tomllib' 2>/dev/null; then
    PYTHON="$candidate"
    break
  fi
done
[[ -n "$PYTHON" ]] || { echo "a Python >=3.11 interpreter (tomllib) is required" >&2; exit 1; }

# Stock macOS has no sha256sum; shasum ships with it.
sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum < "$1" | awk '{print $1}'
  else
    shasum -a 256 < "$1" | awk '{print $1}'
  fi
}

# The manifest owns the pinned digests; this selects the artifact row for
# the host platform's release target. While-read keeps this working under
# the bash 3.2 that still ships with macOS (no mapfile).
pin=()
while IFS= read -r line; do pin+=("$line"); done < <("$PYTHON" - "$REPO" <<'PY'
from pathlib import Path
import platform
import sys
import tomllib

TARGETS = {
    ("linux", "x86_64"): "x86_64-linux-gnu",
    ("linux", "aarch64"): "aarch64-linux-gnu",
    ("darwin", "arm64"): "arm64-apple-darwin",
    ("darwin", "x86_64"): "x86_64-apple-darwin",
}
target = TARGETS.get((sys.platform, platform.machine()))
with (Path(sys.argv[1]) / "crates/rpc/core-compat.toml").open("rb") as stream:
    release = tomllib.load(stream)["reference"]["release"]
artifacts = {row["target"]: row for row in release.get("platforms", [])}
artifacts[release["target"]] = release
row = artifacts.get(target)
if row is None:
    raise SystemExit(f"no pinned Core artifact for {sys.platform}-{platform.machine()}")
print(release["core_version"])
print(row["archive"])
print(row["archive_sha256"])
PY
)
[[ "${#pin[@]}" -eq 3 ]] || { echo "incomplete Core artifact pin" >&2; exit 1; }
readonly CORE_VERSION="${pin[0]}"
readonly TARBALL="${pin[1]}"
readonly TARBALL_SHA256="${pin[2]}"
readonly TARBALL_URL="https://bitcoincore.org/bin/bitcoin-core-${CORE_VERSION}/${TARBALL}"
readonly PREFIX="${BITCOIND_PREFIX:-${HOME}/bitcoin-core-${CORE_VERSION}}"
readonly BITCOIND="${PREFIX}/bin/bitcoind"

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
  got="$(sha256_of "${WORKDIR}/${TARBALL}")"
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
  export) printf 'export BITCOIND_COMMAND=%q\n' "${BITCOIND}" ;;
  install) printf '%s\n' "${BITCOIND}" ;;
esac
