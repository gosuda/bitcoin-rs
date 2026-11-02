# Fuzz targets

Harnesses for untrusted input surfaces: P2P wire framing, v2 transport, block/transaction validation, differential execution against rust-bitcoin, script execution, snapshot and storage decoding, and RPC/REST parsing. Seeds live in [gosuda/bitcoin-rs-fuzz-corpus](https://github.com/gosuda/bitcoin-rs-fuzz-corpus) under `corpus/<target>/`, imported from rust-bitcoin/qa-assets by `scripts/import-qa-assets.sh` and from Core/btcd vectors by `scripts/import-reference-corpora.sh`. Provenance: [CORPUS_PROVENANCE.md](CORPUS_PROVENANCE.md).
## Prerequisites

```sh
rustup toolchain install nightly
cargo install cargo-fuzz
```

## Running a target

Run this from the repository root. The example shows `p2p_message`, and any target below works:

```sh
cargo +nightly fuzz run p2p_message
```

| Target                      | Surface                                                                 |
|-----------------------------|-------------------------------------------------------------------------|
| `p2p_message`               | P2P wire message decoder (`read_message`)                               |
| `p2p_message_structured`    | Structured P2P wire message parser and state handling                   |
| `bip324_transport`          | BIP324 v2 encrypted transport framing, packet headers, and AEAD tags     |
| `addrman_load`              | Address manager (`peers.dat`) deserialization and network addresses     |
| `compact_block_reconstruct` | BIP152 compact block reconstruction and short transaction ID decoding   |
| `socks_sam_reply`           | SOCKS5 and I2P SAM proxy handshake and command reply parsing            |
| `block_validate`            | Block parsing and consensus rules (`verify_block_rules`)                |
| `tx_validate`               | Transaction/witness parse, consensus validation, and `is_standard_tx`   |
| `tx_differential`           | Differential transaction validation against reference decoders         |
| `script_eval`               | Production script interpreter (`Interpreter::execute_with_prevouts`)    |
| `script_differential`       | Differential script interpreter verification against reference engine   |
| `utxo_snapshot`             | Strict native v4 loading and Core v2 metadata/anchor verification       |
| `utxo_record_decode`        | UTXO storage coin record and key prefix decoding                        |
| `undo_row_decode`           | Block undo rows, disconnect markers, and journal records                |
| `index_row_decode`          | Block index entries, filter headers, and consumer cursors               |
| `mempool_dat_load`          | Mempool snapshot files and fee estimator history loading                |
| `rpc_http_request`          | HTTP request headers, chunked transfer encoding, and basic auth parsing |
| `jsonrpc_batch`             | JSON-RPC 2.0 batch parsing, method routing, and parameter validation    |
| `esplora_route`             | Esplora and REST path routing, endpoint query decoding                  |
| `rpc_hex_params`            | Hex parameters, address parsing, and output descriptor evaluation       |
| `block_decode_roundtrip`    | Structured block generation, byte mutation, canonical re-encoding       |
| `header_sync_sequence`      | Header batches, alternative-branch reorgs, and tip selection by work    |
| `chainstate_reorg_model`    | Connect, disconnect, flush, and reopen against an in-memory model       |

The snapshot target also embeds the [independent Core regtest-200 fixture](../crates/utxo/tests/fixtures/core-v2/README.md). The fixture keeps its 51-byte pinned header. It yields at most 256 input triples as little-endian body-offset/XOR-byte mutations. Empty and no-op inputs exercise the complete positive fixture and reach coin decoding with no foreign-format seed. The fixture is compiled in. That arm needs no companion-corpus import.

```sh
cargo +nightly fuzz run p2p_message -- -max_total_time=60
```

## Dictionaries and adversarial execution

Target-specific dictionaries live in `fuzz/dictionaries/<target>.dict` containing protocol command names, network magics, opcode values, varint boundaries, HTTP verbs, and JSON-RPC method tokens. LibFuzzer loads them via `-dict=fuzz/dictionaries/<target>.dict`.

Fuzz builds enable AddressSanitizer and value profiling (`-use_value_profile=1`), with debug assertions and integer overflow checks (`-C debug-assertions -C overflow-checks`). Campaigns enforce memory ceilings (`-rss_limit_mb=2048`, `-malloc_limit_mb=2048`) and execution timeouts (`-timeout=10`).

## Campaign automation

`scripts/run-fuzz-campaign.sh` runs campaigns against single targets or discovers all targets from `fuzz/Cargo.toml`:

```sh
# Run full campaign across all discovered targets (weighted time, then cmin):
scripts/run-fuzz-campaign.sh full 3600

# Run all discovered targets for 60 seconds each:
scripts/run-fuzz-campaign.sh all 60

# Run single target for 60 seconds:
scripts/run-fuzz-campaign.sh p2p_message 60
```

Campaign configuration environment variables:
- `FUZZ_MAX_TOTAL_TIME`: Total campaign duration in seconds.
- `FUZZ_TIMEOUT`: Single-input timeout in seconds (default: 10).
- `FUZZ_RSS_LIMIT_MB`: RSS ceiling in MB (default: 2048).
- `FUZZ_MALLOC_LIMIT_MB`: Malloc limit in MB (default: 2048).
- `FUZZ_JOBS`, `FUZZ_WORKERS`: Concurrent worker processes for libFuzzer.
- `FUZZ_DEBUG_ASSERTIONS`: Toggle debug assertions and overflow checks (default: 1).

The campaign script verifies that zero crash artifacts exist in `fuzz/artifacts/<target>/` or `campaign-output/artifacts/`, exiting non-zero if any crash, OOM, or timeout occurs.

PRs touching `fuzz/**` run [`fuzz-build.yml`](../.github/workflows/fuzz-build.yml), which compiles all targets; execution stays with the scheduled daily campaign below.

A daily campaign runs each target, minimizes with `cargo fuzz cmin`, and publishes non-empty minimized corpora via `github-actions[bot]`.

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

`--manifest-path` is required. `fuzz/` is its own workspace, and the root workspace exposes only the `bitcoin-rs` binary (`no bin target named p2p_message`).

```sh
RUST_BACKTRACE=1 cargo +nightly fuzz run p2p_message -- fuzz/artifacts/p2p_message/crash-<hash>
```

To refresh seeds from qa-assets (CC0), clone beside this checkout, or set `FUZZ_CORPUS_DIR` to its `corpus/`. Then run this from the root:

```sh
scripts/import-qa-assets.sh
```

The script checks the clone's disk footprint and shallow-clones upstream. It remaps seeds per harness framing. It minimizes via `cargo fuzz cmin`, staged through a real `fuzz/corpus/<target>` directory and never a symlink. It deletes the clone, and it rewrites `fuzz/CORPUS_PROVENANCE.md`. `scripts/import-reference-corpora.sh` does the same for pinned bitcoin/bitcoin and btcsuite/btcd vectors. That script refreshes the `## Reference corpora` section.
