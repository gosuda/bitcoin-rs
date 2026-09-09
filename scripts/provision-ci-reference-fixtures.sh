#!/usr/bin/env bash
set -euo pipefail

mapfile -t reference_values < <(
  python3 - <<'PY'
import re
import tomllib
from pathlib import Path

with Path("docs/api/core-compat.toml").open("rb") as manifest_file:
    manifest = tomllib.load(manifest_file)
release = manifest["reference"]["release"]
formal = manifest["reference"]["formal_tool"]
constraints = Path("CONSTRAINTS.md").read_text(encoding="utf-8")
archive_match = re.search(r"^\| Archive \| `([^`]+)`", constraints, re.MULTILINE)
if archive_match is None:
    raise SystemExit("formal-tool archive name missing from CONSTRAINTS.md")
values = (
    release["core_version"],
    release["archive"],
    release["archive_sha256"],
    release["bitcoind_sha256"],
    release["version_output"],
    formal["name"],
    formal["version"],
    formal["archive_sha256"],
    formal["jar_sha256"],
    archive_match.group(1),
)
if not all(isinstance(value, str) for value in values):
    raise SystemExit("reference identity contains a non-string value")
for value in values:
    print(value)
PY
)

if [[ "${#reference_values[@]}" -ne 10 ]]; then
  echo "reference manifest did not provide all fixture identities" >&2
  exit 1
fi

core_version="${reference_values[0]}"
core_archive="${reference_values[1]}"
core_archive_sha256="${reference_values[2]}"
core_bitcoind_sha256="${reference_values[3]}"
core_version_output="${reference_values[4]}"
formal_name="${reference_values[5]}"
formal_version="${reference_values[6]}"
formal_archive_sha256="${reference_values[7]}"
formal_jar_sha256="${reference_values[8]}"
formal_archive="${reference_values[9]}"

if [[ "$formal_name" != "apalache-mc" ]]; then
  echo "formal tool name does not match the g20 executable contract" >&2
  exit 1
fi

: "${JAVA_HOME_25_X64:?ubuntu-latest must provide JAVA_HOME_25_X64}"
if [[ ! -x "$JAVA_HOME_25_X64/bin/java" ]]; then
  echo "JAVA_HOME_25_X64 does not contain an executable java" >&2
  exit 1
fi
export JAVA_HOME="$JAVA_HOME_25_X64"
export PATH="$JAVA_HOME/bin:$PATH"

if [[ -n "${GITHUB_ENV:-}" ]]; then
  printf 'JAVA_HOME=%s\n' "$JAVA_HOME" >> "$GITHUB_ENV"
  # `funArrays` preserves the TLA+ model while encoding its function-heavy
  # state with SMT arrays; this branch tests whether that avoids g20's
  # ChainAdmission temporal translation/solver timeout.
  printf 'SMT_ENCODING=funArrays\n' >> "$GITHUB_ENV"
fi
if [[ -n "${GITHUB_PATH:-}" ]]; then
  printf '%s\n' "$JAVA_HOME/bin" >> "$GITHUB_PATH"
fi

core_url="https://bitcoincore.org/bin/bitcoin-core-${core_version}/${core_archive}"
formal_url="https://github.com/apalache-mc/apalache/releases/download/v${formal_version}/${formal_archive}"
download_dir="target/ci-reference-downloads"
core_archive_path="${download_dir}/${core_archive}"
formal_archive_path="${download_dir}/${formal_archive}"
core_install="target/reference-core-${core_version}"
core_binary="${core_install}/bitcoin-${core_version}/bin/bitcoind"
formal_home="target/tools/apalache-${formal_version}"
formal_binary="${formal_home}/bin/${formal_name}"
formal_jar="${formal_home}/lib/apalache.jar"

mkdir -p "$download_dir"
curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
  --output "$core_archive_path" "$core_url"
curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
  --output "$formal_archive_path" "$formal_url"

printf '%s  %s\n' "$core_archive_sha256" "$core_archive_path" | sha256sum --check --strict
printf '%s  %s\n' "$formal_archive_sha256" "$formal_archive_path" | sha256sum --check --strict

rm -rf -- "$core_install" "$formal_home"
mkdir -p "$core_install" "$(dirname "$formal_home")"
tar --extract --gzip --file "$core_archive_path" --directory "$core_install"
unzip -q "$formal_archive_path" -d "$(dirname "$formal_home")"

[[ -x "$core_binary" ]] || {
  echo "Core archive did not provide $core_binary" >&2
  exit 1
}
[[ -x "$formal_binary" ]] || {
  echo "Apalache archive did not provide $formal_binary" >&2
  exit 1
}
[[ -f "$formal_jar" ]] || {
  echo "Apalache archive did not provide $formal_jar" >&2
  exit 1
}

printf '%s  %s\n' "$core_bitcoind_sha256" "$core_binary" | sha256sum --check --strict
printf '%s  %s\n' "$formal_jar_sha256" "$formal_jar" | sha256sum --check --strict

core_probe_dir="$(mktemp -d "$download_dir/core-version.XXXXXX")"
if ! core_version_text="$("$core_binary" "-datadir=$core_probe_dir" -version 2>&1)"; then
  printf 'pinned bitcoind -version failed: %s\n' "$core_version_text" >&2
  exit 1
fi
core_version_line="${core_version_text%%$'\n'*}"
if [[ "$core_version_line" != *"$core_version_output"* ]]; then
  printf 'unexpected bitcoind version: %s\n' "$core_version_line" >&2
  exit 1
fi

if ! formal_version_text="$("$formal_binary" version 2>&1)"; then
  printf 'pinned apalache-mc version failed: %s\n' "$formal_version_text" >&2
  exit 1
fi
if [[ "$formal_version_text" != *"$formal_version"* ]]; then
  printf 'unexpected apalache-mc version output: %s\n' "$formal_version_text" >&2
  exit 1
fi

printf 'Provisioned %s and %s\n' "$core_binary" "$formal_binary"
