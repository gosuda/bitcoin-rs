# Fuzz Targets

Five `cargo-fuzz` harnesses covering the untrusted-input surfaces of
bitcoin-rs: P2P wire messages, block/transaction **consensus** after
rust-bitcoin deserialization, the production script interpreter, and UTXO
snapshot loading. Seed corpora live in the companion repository
[gosuda/bitcoin-rs-fuzz-corpus](https://github.com/gosuda/bitcoin-rs-fuzz-corpus)
under `corpus/<target>/`; they are imported from rust-bitcoin/qa-assets by
`scripts/import-qa-assets.sh` and from Bitcoin Core and btcd test vectors
by `scripts/import-reference-corpora.sh`. See `fuzz/CORPUS_PROVENANCE.md`
for upstream commits, licenses, and mapping. Parser-only rust-bitcoin
decode targets are not kept.

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
| `tx_validate`    | rust-bitcoin tx/witness parse, then consensus + mempool `is_standard_tx` |
| `script_eval`    | Production interpreter entry point (`Interpreter::execute_with_prevouts` with fuzz-selected `VerifyFlags`) |
| `utxo_snapshot`  | Strict native v4 loading; Core v2 metadata, compiled-anchor verification, and fixture-body mutations |

The snapshot target passes raw input to both formats. It also embeds the
[independent Core regtest-200 fixture](../crates/utxo/tests/fixtures/core-v2/README.md),
preserves its 51-byte pinned header, and applies at most 256 input triples as
little-endian body-offset/XOR-byte mutations. Empty or no-op inputs exercise the
complete positive fixture. This arm reaches coin decoding without requiring a
foreign-format corpus seed to discover the compiled base hash. The fixture is
compiled into the harness; no companion-corpus import is required for that arm.

To limit the run to 60 seconds:

```sh
cargo +nightly fuzz run p2p_message -- -max_total_time=60
```

## Shared corpus and local campaigns

The companion corpus repository is
[gosuda/bitcoin-rs-fuzz-corpus](https://github.com/gosuda/bitcoin-rs-fuzz-corpus).
It is the destination for the evolving exploration corpus; fuzz targets and
local execution instructions live here in `bitcoin-rs`. A daily campaign runs
each target for one hour, minimizes its corpus, and commits through
`github-actions[bot]` only when the minimized set changes. Reports and crash
inputs are retained with the workflow run.
Pull requests that change `fuzz/**` compile every target in
[`fuzz-build.yml`](../.github/workflows/fuzz-build.yml).

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
or reproduce a fixed bug; update their provenance together (see
[the QA corpus contract](../docs/contracts/qa-corpus.md)).

## Adding a corpus

Committed seeds live in the companion repository at `corpus/<target>/`.
Add seed files there (one file per input) in a sibling checkout:

```sh
mkdir -p ../bitcoin-rs-fuzz-corpus/corpus/p2p_message
# Add binary seed files, e.g. a captured wire message:
cp some_block_message.bin ../bitcoin-rs-fuzz-corpus/corpus/p2p_message/
```

A local `fuzz/corpus/<target>/` directory also works for ad-hoc runs — it
is untracked and never committed. To merge new coverage finds into a local
corpus:

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

To refresh the seed corpora from rust-bitcoin/qa-assets (CC0), clone
bitcoin-rs-fuzz-corpus beside this checkout (or set `FUZZ_CORPUS_DIR` to
its `corpus/` directory) and run from the repository root:

```sh
scripts/import-qa-assets.sh
```

The script declares and checks the clone's disk footprint, shallow-clones the
upstream corpus repo, remaps the seeds to each harness's input framing into
the corpus checkout, minimizes with `cargo fuzz cmin` (staged through
a real `fuzz/corpus/<target>` staging directory — `cargo fuzz cmin`
cannot minimize through a symlink), deletes the clone, and rewrites
`fuzz/CORPUS_PROVENANCE.md`.

`scripts/import-reference-corpora.sh` does the same for the pinned
bitcoin/bitcoin and btcsuite/btcd test vectors and refreshes the
`## Reference corpora` section of `fuzz/CORPUS_PROVENANCE.md`.
