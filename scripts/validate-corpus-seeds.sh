#!/usr/bin/env bash
# Single owner of the corpus seed-content invariant, shared by the fuzz
# campaign worker (scripts/run-fuzz-campaign.sh) and the corpus publication
# job (.github/workflows/daily-fuzz.yml).
#
# Usage: validate-corpus-seeds.sh [-n max-seeds] [-b max-bytes] <corpus-dir> [label]
#
# Every entry under <corpus-dir> (including dotfiles and nested paths, which
# shell globs miss but rsync would copy) must be a non-symlink regular file
# named by its own SHA-1 digest, no larger than FUZZ_MAX_SEED_BYTES, with a
# positive count. The -n/-b sanity budget applies only when passed (the
# publish job, guarding the corpus repo against floods); the worker path
# omits it so the budget can never cap the corpus's lifetime growth. Modes
# are normalized to 0644, the corpus repo's required mode. Exits non-zero
# on the first refusal.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=fuzz-policy.sh
source "${SCRIPT_DIR}/fuzz-policy.sh"

max_seeds=0
max_bytes=0
while getopts ':n:b:' option; do
    case "${option}" in
        n) max_seeds="${OPTARG}" ;;
        b) max_bytes="${OPTARG}" ;;
        *) printf 'usage: %s [-n max-seeds] [-b max-bytes] <corpus-dir> [label]\n' "$0" >&2; exit 2 ;;
    esac
done
shift $(( OPTIND - 1 ))
CORPUS_DIR="${1:?usage: validate-corpus-seeds.sh [-n max-seeds] [-b max-bytes] <corpus-dir> [label]}"
LABEL="${2:-${CORPUS_DIR}}"

seed_count=0
seed_bytes=0
while IFS= read -r -d '' seed; do
    rel="${seed#"${CORPUS_DIR}"/}"
    [[ -f "${seed}" && ! -L "${seed}" ]] || {
        printf 'refusing non-regular seed: %s\n' "${LABEL}/${rel}" >&2
        exit 1
    }
    size="$(stat -c%s "${seed}")"
    (( size <= FUZZ_MAX_SEED_BYTES )) || {
        printf 'refusing oversized seed (%s bytes): %s\n' "${size}" "${LABEL}/${rel}" >&2
        exit 1
    }
    hash="$(sha1sum "${seed}")"
    hash="${hash%% *}"
    [[ "${rel}" == "${hash}" ]] || {
        printf 'refusing seed not named by its sha1: %s\n' "${LABEL}/${rel}" >&2
        exit 1
    }
    seed_count=$(( seed_count + 1 ))
    seed_bytes=$(( seed_bytes + size ))
done < <(find "${CORPUS_DIR}" -mindepth 1 -print0)

(( seed_count > 0 )) || { printf 'refusing empty corpus: %s\n' "${LABEL}" >&2; exit 1; }
if (( max_seeds > 0 && seed_count > max_seeds )) ||
   (( max_bytes > 0 && seed_bytes > max_bytes )); then
    printf 'refusing corpus over budget: %s (%s seeds, %s bytes)\n' \
        "${LABEL}" "${seed_count}" "${seed_bytes}" >&2
    exit 1
fi

find "${CORPUS_DIR}" -mindepth 1 -type f -exec chmod 0644 {} +
printf 'validated %s seeds (%s bytes) for %s\n' "${seed_count}" "${seed_bytes}" "${LABEL}" >&2
