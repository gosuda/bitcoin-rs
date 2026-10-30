#!/usr/bin/env bash
# Extract Bitcoin Core's functional test suite from a pinned tag of a local
# Core checkout into the gitignored scratch area, plus a PROVENANCE stamp.
#
# Usage:
#   tools/core-functional/fetch-core-tests.sh [--core-repo <path>] [--tag <tag>] [--dest <dir>]
#
# Defaults: --core-repo /home/deploy/git/bitcoin, --tag v31.1,
#           --dest <repo-root>/target/core-functional/core-v31.1
#
# Idempotent: the destination is wiped and re-extracted on every run.
# Extracted from the tag: test/functional (the suite), contrib/linearize and
# share/rpcauth (needed by clean-candidates feature_loadblock.py and
# rpc_whitelist.py through the framework's SRCDIR/RPCAUTH config entries).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

CORE_REPO="/home/deploy/git/bitcoin"
TAG="v31.1"
DEST="${REPO_ROOT}/target/core-functional/core-v31.1"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --core-repo) CORE_REPO="$2"; shift 2 ;;
        --tag) TAG="$2"; shift 2 ;;
        --dest) DEST="$2"; shift 2 ;;
        -h|--help)
            sed -n '2,15p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *)
            echo "fetch-core-tests.sh: unknown argument: $1" >&2; exit 2 ;;
    esac
done

if ! command -v git >/dev/null 2>&1 || ! command -v tar >/dev/null 2>&1; then
    echo "fetch-core-tests.sh: git and tar are required" >&2
    exit 1
fi
if [[ ! -d "${CORE_REPO}/.git" ]]; then
    echo "fetch-core-tests.sh: ${CORE_REPO} is not a git checkout (use --core-repo)" >&2
    exit 1
fi

# Refuse to run unless the tag resolves to a concrete commit in that checkout.
if ! COMMIT="$(git -C "${CORE_REPO}" rev-parse --verify --quiet "${TAG}^{commit}")"; then
    echo "fetch-core-tests.sh: tag ${TAG} cannot be resolved in ${CORE_REPO}" >&2
    echo "  hint: git -C ${CORE_REPO} fetch --tags" >&2
    exit 1
fi

echo "Extracting ${TAG} (${COMMIT}) from ${CORE_REPO} into ${DEST}"
rm -rf "${DEST}"
mkdir -p "${DEST}"

git -C "${CORE_REPO}" archive "${COMMIT}" \
    test/functional contrib/linearize share/rpcauth | tar -x -C "${DEST}"

if [[ ! -d "${DEST}/test/functional/test_framework" ]]; then
    echo "fetch-core-tests.sh: extraction incomplete (missing test_framework)" >&2
    exit 1
fi

cat > "${DEST}/PROVENANCE" <<EOF
core_tag=${TAG}
core_commit=${COMMIT}
extracted_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)
source_repo=${CORE_REPO}
extracted_paths=test/functional contrib/linearize share/rpcauth
license=MIT (Bitcoin Core; see test/functional and the upstream COPYING)
EOF

# The framework resolves its node binary through BITCOIND or
# <BUILDDIR>/bin/bitcoind (test_framework/util.py get_binary_paths); run.sh
# relies on this symlink existing so both paths lead to the wrapper.
mkdir -p "${DEST}/bin"
ln -sfn "${SCRIPT_DIR}/bin/bitcoind-wrapper" "${DEST}/bin/bitcoind"

TEST_COUNT="$(find "${DEST}/test/functional" -maxdepth 1 -name '*.py' | wc -l)"
echo "Done: ${TEST_COUNT} test scripts under ${DEST}/test/functional"
echo "Next: tools/core-functional/run.sh --list"
