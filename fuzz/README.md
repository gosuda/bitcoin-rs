# Fuzz targets

Five `cargo-fuzz` harnesses: P2P wire messages, block/transaction consensus after rust-bitcoin parse, the production script interpreter, and UTXO snapshot loading. Seeds live in [gosuda/bitcoin-rs-fuzz-corpus](https://github.com/gosuda/bitcoin-rs-fuzz-corpus) under `corpus/<target>/`, imported from rust-bitcoin/qa-assets by `scripts/import-qa-assets.sh` and from Core/btcd vectors by `scripts/import-reference-corpora.sh`. Provenance: [CORPUS_PROVENANCE.md](CORPUS_PROVENANCE.md). Parser-only rust-bitcoin decode targets are not kept.

## Prerequisites

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
```

## Running a target

From the repository root (`p2p_message` shown; any target below works):

```sh
cargo +nightly fuzz run p2p_message
```

| Target           | Surface                                                                 |
|------------------|-------------------------------------------------------------------------|
| `p2p_message`    | P2P wire message decoder (`read_message`)                               |
| `block_validate` | rust-bitcoin block parse, then `verify_block_rules`                     |
| `tx_validate`    | rust-bitcoin tx/witness parse, then consensus + mempool `is_standard_tx` |
| `script_eval`    | Production interpreter (`Interpreter::execute_with_prevouts`, fuzz-selected `VerifyFlags`) |
| `utxo_snapshot`  | Strict native v4 loading; Core v2 metadata, compiled-anchor verification, fixture-body mutations |

The snapshot target also embeds the [independent Core regtest-200 fixture](../crates/utxo/tests/fixtures/core-v2/README.md): 51-byte pinned header preserved, at most 256 input triples as little-endian body-offset/XOR-byte mutations; empty/no-op inputs exercise the complete positive fixture and reach coin decoding with no foreign-format seed. Fixture compiled in; no companion-corpus import needed for that arm.

```sh
cargo +nightly fuzz run p2p_message -- -max_total_time=60
```

## Shared corpus and local campaigns

Seeds evolve in the companion repo; targets and instructions live here. A daily campaign runs each target one hour, minimizes, and commits via `github-actions[bot]` only on change; reports and crashes stay with the run. PRs touching `fuzz/**` compile every target in [`fuzz-build.yml`](../.github/workflows/fuzz-build.yml).

Longer local run: clone the companion repo beside bitcoin-rs (triple below is Linux x86_64; elsewhere use `rustc +nightly -vV`):

```sh
git clone https://github.com/gosuda/bitcoin-rs-fuzz-corpus.git \
  ../bitcoin-rs-fuzz-corpus
cargo +nightly fuzz run script_eval \
  ../bitcoin-rs-fuzz-corpus/corpus/script_eval \
  --target x86_64-unknown-linux-gnu -- -max_total_time=3600
cargo +nightly fuzz cmin script_eval \
  ../bitcoin-rs-fuzz-corpus/corpus/script_eval \
  --target x86_64-unknown-linux-gnu
```

Public-corpus reads need no automation write token. Keep the clone on the same filesystem: `cargo fuzz cmin` atomically replaces the minimized directory.

Submit minimized finds with bitcoin-rs commit, starting corpus revision, command, and coverage. In-repo promotions must protect a named current contract or reproduce a fixed bug, with provenance updated together ([QA corpus contract](../docs/contracts/qa-corpus.md)).

## Adding a corpus

Seeds live at `corpus/<target>/` in a sibling companion checkout (one file per input):

```sh
mkdir -p ../bitcoin-rs-fuzz-corpus/corpus/p2p_message
# Add binary seed files, e.g. a captured wire message:
cp some_block_message.bin ../bitcoin-rs-fuzz-corpus/corpus/p2p_message/
```

`fuzz/corpus/<target>/` also works ad-hoc (untracked, never committed); merge new coverage with:

```sh
cargo +nightly fuzz run p2p_message -- -merge=1 fuzz/corpus/p2p_message
```

## Reproducing a crash

Crashes land in `fuzz/artifacts/<target>/`:

```sh
cargo +nightly fuzz run p2p_message -- fuzz/artifacts/p2p_message/crash-<hash>
```

Without `cargo-fuzz` (the `libfuzzer_sys` harness reads one file argument):

```sh
cargo +nightly run --manifest-path fuzz/Cargo.toml --bin p2p_message \
  -- fuzz/artifacts/p2p_message/crash-<hash>
```

`--manifest-path` is required: `fuzz/` is its own workspace, and the root workspace exposes only the `bitcoin-rs` binary (`no bin target named p2p_message`).

```sh
RUST_BACKTRACE=1 cargo +nightly fuzz run p2p_message -- fuzz/artifacts/p2p_message/crash-<hash>
```

Refresh seeds from qa-assets (CC0): clone beside this checkout (or set `FUZZ_CORPUS_DIR` to its `corpus/`) and run from root:

```sh
scripts/import-qa-assets.sh
```

The script checks the clone's disk footprint, shallow-clones upstream, remaps seeds per harness framing, minimizes via `cargo fuzz cmin` (staged through a real `fuzz/corpus/<target>` directory, never a symlink), deletes the clone, and rewrites `fuzz/CORPUS_PROVENANCE.md`. `scripts/import-reference-corpora.sh` does the same for pinned bitcoin/bitcoin and btcsuite/btcd vectors, refreshing the `## Reference corpora` section.
