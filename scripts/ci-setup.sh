#!/usr/bin/env bash
set -euo pipefail

if [ "$1" = changed ]; then
  [ "${GITHUB_EVENT_NAME:-}" = pull_request ] || exit 0
  git fetch -q --depth=1 origin "$GITHUB_BASE_REF" || exit 2
  git diff --name-only FETCH_HEAD HEAD > /tmp/changed.txt || exit 2
  grep -Eq "$2" /tmp/changed.txt
  exit
fi

gh=https://github.com
tool() {
  local d; d="$(mktemp -d)"
  curl -fsSL --retry 3 -o "$d/t.tgz" "$2"
  echo "$3  $d/t.tgz" | sha256sum --check --strict -
  tar -xzf "$d/t.tgz" -C "$d"
  sudo install -m 0755 "$(find "$d" -type f -name "$1" | head -n 1)" "/usr/local/bin/$1"
}

for t in "$@"; do
  case "$t" in
    apt) dpkg -s cmake libboost-dev libclang-dev mold >/dev/null 2>&1 || { sudo apt-get update -qq && sudo apt-get install -y -qq cmake libboost-dev libclang-dev mold; } ;;
    nextest) tool cargo-nextest "$gh/nextest-rs/nextest/releases/download/cargo-nextest-0.9.151/cargo-nextest-0.9.151-x86_64-unknown-linux-gnu.tar.gz" 1d4ce302b820c41f4b89c5fb9bce45f0f0c94882c1cf08fc360caf08be6e7df4 ;;
    deny) tool cargo-deny "$gh/EmbarkStudios/cargo-deny/releases/download/0.20.2/cargo-deny-0.20.2-x86_64-unknown-linux-musl.tar.gz" 9f12ed4c49936e09b48bf862b595cde2fe64fcbd9d74dfacac6131ca824c8d5f ;;
    mdbook) tool mdbook "$gh/rust-lang/mdBook/releases/download/v0.5.4/mdbook-v0.5.4-x86_64-unknown-linux-gnu.tar.gz" 3f28de05dafca9d0f2eab99c662116b0e37b89b1d96a08f8f430b9eeae958cd7 ;;
    fuzz) tool cargo-fuzz "$gh/rust-fuzz/cargo-fuzz/releases/download/0.13.2/cargo-fuzz-0.13.2-x86_64-unknown-linux-musl.tar.gz" b5b704018b63e0f151c17a057ac53b5111e1db545d1b9f72fee79f08a545931c ;;
    corpus) git clone -q --depth 1 "$gh/gosuda/bitcoin-rs-fuzz-corpus.git" /tmp/fuzz-corpus ;;
    nightly) rustup toolchain install nightly --profile minimal ;;
    msrv) rustup toolchain install 1.99.0 --profile minimal --component clippy ;;
    *) echo "unknown tool: $t" >&2; exit 2 ;;
  esac
done
