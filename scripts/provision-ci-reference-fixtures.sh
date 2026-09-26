#!/usr/bin/env bash
# Provision one external proof lane. Normal node tests need Core, not Java.
set -euo pipefail
cd "$(dirname "$0")/.."

mode="${1:-}"
case "$mode" in
  core|formal) ;;
  *) echo "usage: $0 {core|formal}" >&2; exit 2 ;;
esac

mapfile -t identity < <(python3 - "$mode" <<'PY'
from pathlib import Path
import re
import sys
import tomllib

with Path("crates/rpc/core-compat.toml").open("rb") as stream:
    reference = tomllib.load(stream)["reference"]
if sys.argv[1] == "core":
    pin = reference["release"]
    values = tuple(pin[key] for key in (
        "core_version", "archive", "archive_sha256", "bitcoind_sha256", "version_output"
    ))
else:
    pin = reference["formal_tool"]
    if pin["name"] != "apalache-mc":
        raise SystemExit("unexpected formal tool")
    archive = re.search(r"^\| Archive \| `([^`]+)`", Path("CONSTRAINTS.md").read_text(), re.MULTILINE)
    if archive is None:
        raise SystemExit("formal archive identity missing")
    values = (pin["version"], archive[1], pin["archive_sha256"], pin["jar_sha256"], pin["version"])
if not all(isinstance(value, str) and "\n" not in value for value in values):
    raise SystemExit("invalid fixture identity")
print("\n".join(values))
PY
)
[[ "${#identity[@]}" -eq 5 ]] || { echo "incomplete fixture identity" >&2; exit 1; }
version="${identity[0]}"
archive="${identity[1]}"
archive_hash="${identity[2]}"
binary_hash="${identity[3]}"
expected_version="${identity[4]}"
download="target/ci-reference-downloads/$archive"
mkdir -p "$(dirname "$download")"

if [[ "$mode" == core ]]; then
  url="https://bitcoincore.org/bin/bitcoin-core-$version/$archive"
  install="target/reference-core-$version"
  binary="$install/bitcoin-$version/bin/bitcoind"
else
  url="https://github.com/apalache-mc/apalache/releases/download/v$version/$archive"
  install="target/tools/apalache-$version"
  binary="$install/bin/apalache-mc"
  # Hosted runners expose the pinned Java major here; local runs may use an
  # explicitly selected JAVA_HOME instead. Never require Java for Core tests.
  # WHY JAVA_HOME_25_X64: legacy variable name; whatever JDK it selects must
  # still match the register's observed-Java row below.
  export JAVA_HOME="${JAVA_HOME_25_X64:-${JAVA_HOME:?set JAVA_HOME for the formal lane}}"
  [[ -x "$JAVA_HOME/bin/java" ]] || { echo "Java executable missing" >&2; exit 1; }
  # The register records what java -version actually printed (CONSTRAINTS.md
  # "Java | ... Java <version>"); a JDK that no longer matches that
  # observation invalidates the formal lane's tool identity, before PATH
  # export so nothing downstream runs against the wrong JVM.
  observed="$("$JAVA_HOME/bin/java" -version 2>&1)" || {
    printf '%s\n' "$observed" >&2
    printf '%s\n' "Java version probe failed" >&2
    exit 1
  }
  # The banner's label varies by vendor (openjdk, java, Temurin's java);
  # only the quoted version token is identity.
  observed_version="$(printf '%s\n' "$observed" | sed -n '1s/^[[:space:]]*[a-z][a-z]*[[:space:]]\+version[[:space:]]\+"\([^"]*\)".*/\1/p')"
  register_version="$(sed -n 's/^| Java |.*[[:space:]]Java \([0-9.][0-9.]*\)[[:space:]]*|[[:space:]]*$/\1/p' CONSTRAINTS.md)"
  [[ -n "$observed_version" && -n "$register_version" ]] || {
    printf '%s\n' "Java identity missing: observed '${observed_version:-none}' vs register '${register_version:-none}'" >&2
    exit 1
  }
  [[ "$observed_version" == "$register_version" ]] || {
    printf '%s\n' "Java version mismatch: selected JDK ${observed_version}, register ${register_version}" >&2
    exit 1
  }
  export PATH="$JAVA_HOME/bin:$PATH"
  if [[ -n "${GITHUB_ENV:-}" ]]; then
    printf 'JAVA_HOME=%s\n' "$JAVA_HOME" >> "$GITHUB_ENV"
  fi
  if [[ -n "${GITHUB_PATH:-}" ]]; then
    printf '%s\n' "$JAVA_HOME/bin" >> "$GITHUB_PATH"
  fi
fi

curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error --output "$download" "$url"
printf '%s  %s\n' "$archive_hash" "$download" | sha256sum --check --strict
# Only the named, ignored fixture install is replaced, after archive custody.
rm -rf -- "$install"
if [[ "$mode" == core ]]; then
  mkdir -p "$install"
  tar --extract --gzip --file "$download" --directory "$install"
  printf '%s  %s\n' "$binary_hash" "$binary" | sha256sum --check --strict
  probe="$(mktemp -d target/ci-reference-downloads/core-version.XXXXXX)"
  trap 'rm -rf -- "$probe"' EXIT
  # The probe result is the version report, so capture stderr too; without a
  # failure branch set -e would exit silently with the child code.
  actual_version="$("$binary" "-datadir=$probe" -version 2>&1)" || {
    printf '%s\n' "$actual_version" >&2
    printf '%s\n' "Core version probe failed" >&2
    exit 1
  }
  [[ "${actual_version%%$'\n'*}" == "$expected_version" ]] || {
    printf '%s\n' "Core version mismatch: expected ${expected_version}, got:" >&2
    printf '%s\n' "$actual_version" >&2
    exit 1;
  }
else
  mkdir -p "$(dirname "$install")"
  unzip -q "$download" -d "$(dirname "$install")"
  printf '%s  %s\n' "$binary_hash" "$install/lib/apalache.jar" | sha256sum --check --strict
  APALACHE_HOME="$install" python3 scripts/check_models.py --check-only
fi
printf 'Provisioned %s\n' "$binary"
