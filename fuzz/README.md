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

To limit the number of iterations:

```sh
cargo +nightly fuzz run p2p_message -- -max_total_time=60
```

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
