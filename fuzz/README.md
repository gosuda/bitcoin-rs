# Fuzz Targets

Five `cargo-fuzz` harnesses covering the untrusted-input surfaces of
bitcoin-rs: P2P wire messages, block/transaction **consensus** after
rust-bitcoin deserialization, the production script interpreter, and UTXO
snapshot loading. Seed corpora under `fuzz/corpus/` are imported from
rust-bitcoin/qa-assets by `scripts/import-qa-assets.sh`; see
`fuzz/CORPUS_PROVENANCE.md` for upstream commit, license, and mapping.
Parser-only rust-bitcoin decode targets are not kept.

## Prerequisites

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
```

## Running a target

From the repository root:

```sh
cargo +nightly fuzz run p2p_message
```

Replace `p2p_message` with any of:

| Target           | Surface                                                                 |
|------------------|-------------------------------------------------------------------------|
| `p2p_message`    | P2P wire message decoder (`read_message`)                               |
| `block_validate` | rust-bitcoin block parse, then `verify_block_rules`                     |
| `tx_validate`    | rust-bitcoin tx/witness parse, then consensus + mempool `check_acceptance` |
| `script_eval`    | Production interpreter entry point (`Interpreter::execute` with fuzz-selected `VerifyFlags`) |
| `utxo_snapshot`  | UTXO snapshot deserializer (`read_snapshot_strict_v4`)                  |

To limit the run to 60 seconds:

```sh
cargo +nightly fuzz run p2p_message -- -max_total_time=60
```

## Shared corpus and local campaigns

The companion corpus repository is
[gosuda/bitcoin-rs-fuzz-corpus](https://github.com/gosuda/bitcoin-rs-fuzz-corpus).
It is the destination for the evolving exploration corpus; fuzz targets and
local execution instructions live here in `bitcoin-rs`. A weekly campaign runs
each target for one hour, minimizes its corpus, and commits through
`github-actions[bot]` only when the minimized set changes. Reports and crash
inputs are retained with the workflow run.

For a longer local run, clone the companion repository next to bitcoin-rs and
use its target directory as the writable corpus. For example, from the
bitcoin-rs repository root on Linux x86_64:

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

On other platforms, use the host triple reported by `rustc +nightly -vV`.
Reading a public corpus does not require the automation's write token.
Keep the corpus clone on the same filesystem as bitcoin-rs because
`cargo fuzz cmin` atomically replaces the minimized directory.

Submit minimized exploration inputs to the companion repository, with the
bitcoin-rs commit, starting corpus revision, command, and coverage evidence.
Inputs promoted into this repository should protect a named current contract
or reproduce a fixed bug; update their provenance and any applicable verdict
manifest together (see [the QA corpus contract](../docs/contracts/qa-corpus.md)).

## Adding a corpus

Each target has a seed corpus directory at `fuzz/corpus/<target>/`. Create it
and add seed files (one file per input):

```sh
mkdir -p fuzz/corpus/p2p_message
# Add binary seed files, e.g. a captured wire message:
cp some_block_message.bin fuzz/corpus/p2p_message/
```

To merge new coverage finds into the corpus:

```sh
cargo +nightly fuzz run p2p_message -- -merge=1 fuzz/corpus/p2p_message
```

## Reproducing a crash

When a target finds a crash, `cargo-fuzz` writes the crashing input to
`fuzz/artifacts/<target>/`. Reproduce it with:

```sh
cargo +nightly fuzz run p2p_message -- fuzz/artifacts/p2p_message/crash-<hash>
```

Or reproduce directly without `cargo-fuzz` by building the target and feeding
the crash file on stdin (the `libfuzzer_sys` harness reads one file argument):

```sh
cargo +nightly run --manifest-path fuzz/Cargo.toml --bin p2p_message \
  -- fuzz/artifacts/p2p_message/crash-<hash>
```

`--manifest-path` is required. `fuzz/` declares its own workspace, so run from
the repository root without it Cargo selects the root workspace, whose metadata
exposes only the `bitcoin-rs` binary, and the command fails with `no bin target
named p2p_message` before it reads the artifact.

To get a full backtrace, set `RUST_BACKTRACE=1`:

```sh
RUST_BACKTRACE=1 cargo +nightly fuzz run p2p_message -- fuzz/artifacts/p2p_message/crash-<hash>
```

To refresh the seed corpora from rust-bitcoin/qa-assets (CC0), run from the
repository root:

```sh
scripts/import-qa-assets.sh
```

The script declares and checks the clone's disk footprint, shallow-clones the
upstream corpus repo, remaps the seeds to each harness's input framing,
minimizes with `cargo fuzz cmin`, deletes the clone, and rewrites
`fuzz/CORPUS_PROVENANCE.md`.
