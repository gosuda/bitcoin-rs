#!/usr/bin/env bash
# Provision one external proof lane. Normal node tests need Core, not Java.
set -euo pipefail
cd "$(dirname "$0")/.."

mode="${1:-}"
case "$mode" in
  core|formal) ;;
  *) echo "usage: $0 {core|formal}" >&2; exit 2 ;;
esac

# resolve_reference_identity.py carries its own manifest reader for
# interpreters without tomllib; probe any Python >=3.6 (versioned first,
# since the system python3 on macOS predates tomllib). The formal lane's
# check_models.py still requires tomllib on the resolved interpreter.
PYTHON=""
for candidate in python3.13 python3.12 python3.11 python3.10 python3.9 python3; do
  if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import sys; sys.exit(sys.version_info < (3, 6))' 2>/dev/null; then
    PYTHON="$candidate"
    break
  fi
done
[[ -n "$PYTHON" ]] || { echo "a Python >=3.6 interpreter is required" >&2; exit 1; }

# Exact-match digest gate; stock macOS ships shasum, not sha256sum.
sha256_check() {
  local got
  if command -v sha256sum >/dev/null 2>&1; then
    got="$(sha256sum < "$2" | awk '{print $1}')"
  else
    got="$(shasum -a 256 < "$2" | awk '{print $1}')"
  fi
  [[ "$got" == "$1" ]] || { printf 'sha256 mismatch for %s\n' "$2" >&2; exit 1; }
}

# resolve_reference_identity.py is the single owner of the fixture identity
# tuple. Capturing stdout propagates the interpreter's exit status; the
# while-read keeps this working under the bash 3.2 that still ships with
# macOS (no mapfile, no heredoc inside a substitution — bash 3.2 cannot
# parse that).
identity_text="$("$PYTHON" scripts/resolve_reference_identity.py "$mode" .)" || exit 1
identity=()
while IFS= read -r line; do identity+=("$line"); done <<< "$identity_text"
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
  # still match the formal contract's observed-Java row below.
  export JAVA_HOME="${JAVA_HOME_25_X64:-${JAVA_HOME:?set JAVA_HOME for the formal lane}}"
  [[ -x "$JAVA_HOME/bin/java" ]] || { echo "Java executable missing" >&2; exit 1; }
  # The formal contract records what java -version actually printed
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
  register_version="$(sed -n 's/^| Java |.*[[:space:]]Java \([0-9.][0-9.]*\)[[:space:]]*|[[:space:]]*$/\1/p' docs/contracts/formal-verification.md)"
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
sha256_check "$archive_hash" "$download"
# Only the named, ignored fixture install is replaced, after archive custody.
rm -rf -- "$install"
if [[ "$mode" == core ]]; then
  mkdir -p "$install"
  tar --extract --gzip --file "$download" --directory "$install"
  sha256_check "$binary_hash" "$binary"
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
  sha256_check "$binary_hash" "$install/lib/apalache.jar"
  APALACHE_HOME="$install" "$PYTHON" scripts/check_models.py --check-only
fi
printf 'Provisioned %s\n' "$binary"
