# Offline full-validation comparator

Harness `tools/benchmark-campaign/offline_full_validation.py`, tests `tools/benchmark-campaign/test_offline_full_validation.py`; addresses issue #34, implements the frozen parity contract of issue #46. Core 31.1 and bitcoin-rs build chainstate from the same hash-pinned Core-framed archive; neither node is reached inside; the ratio is computed only after all custody and correctness gates pass. No live C150/Cmodern campaign is claimed: CI proves the harness with fixture nodes only.

## What is held identical

One `offline-full-validation-config-v1` document binds every arm: archive (Bitcoin Core `blk*.dat` framing only: 4-byte magic, LE length, consensus block; `O_NOFOLLOW` open, hash, per-record manifest walk; trailing bytes, magic, length, or header-hash mismatch refuses before any child starts; block hash is Core `CBlockHeader::GetHash`, double-SHA256 of the 80-byte header, checked against mainnet genesis `000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f`); manifest (`core-framed-archive-manifest-v1` or producer `bitcoin-rs-corpus-manifest` v1 only; contiguous heights from `start_height`, exact archive consumption, network and magic MUST equal the node identity); optional indexed parity (producer `bitcoin-rs-corpus-index-v1` plus `blkNNNNN.dat` sources plus freeze; `verify_index` runs first, then `iter_indexed_framed` bytes MUST equal the packed digest and size); pinned custody (`<root>/custody/archive|manifest|index|sources/`, re-hashed with `0o400`, device, inode, size, and mtime checked before and after every child; transient under `TemporaryDirectory(prefix="offline-full-validation-")`, only the result JSON survives); posture (`assume_valid` false, `txindex`/`blockfilterindex`/`coinstatsindex` off, cache `process-cold/page-cache-unspecified`; page-cache-eviction posture is refused); certified state (height, best block equal to manifest tip, UTXO count, satoshis, MuHash, `hash_serialized_3`, body availability plus one-block disconnect readiness, both true); lifecycle (`fresh` timed spawn-to-clean-exit, `reopen` untimed same-state reopen); binaries SHA-256 pinned, `{binary}` placeholder to a per-arm verified `0o500` copy re-hashed before every spawn; the timed command MUST carry an assume-valid-off token and MUST NOT carry index-on tokens.

Timed boundary: wall is `time.monotonic_ns` from child creation to wait-exit (read, parse, validation, mutation, persistence, flush, shutdown; nothing subtracted). CPU (`utime+stime`) and peak RSS come from `/proc` and are reported separately. The child MUST stay in the foreground and exit. Core consumes `{corpus_path}` through its checked-in `-loadblock` family (`src/init.cpp:529`, `blockstorage.cpp:1270`, `validation.cpp:4975`; `-daemon=0 -stopafterblockimport=1 -assumevalid=0 -stopatheight=H`). bitcoin-rs consumes the same file through `crates/node/src/offline_import.rs` (`--corpus --manifest --state --data-dir --assume-valid-height 0`); it persists bodies plus undo, publishes the clean checkpoint, exits nonzero on any gate failure, never daemonizes or forks; an empty process group with no subreaper-owned leftover descendants is required, else the arm is refused.

Correctness gates (`_require_comparable`, in order): exactly 14 arms (2 per pair, Core plus bitcoin-rs); alternation; archive and binary identities unchanged; exit 0 (reopen arms also 0); certified state equals the expectation on both arms and agrees across arms. Refusal raises `ContractError`, exits 2, and emits NO result JSON. Atomic publish: unnamed `O_TMPFILE` plus fsync plus `linkat(AT_EMPTY_PATH)` plus dir fsync; a pre-link crash is retriable, a post-link crash or `EEXIST` MUST NOT overwrite, no retries.

Result `offline-full-validation-result-v1`: config hash, custody block, `correctness` block (all `true`), every arm wall/CPU/RSS/exit/state, per-role percentile summaries, `candidate_over_core_p50_ratio`; `result_sha256` over the canonical form without that field; index and source digests bound through `config_sha256`. Raw argv is never published (same category-only projection as the P2P loopback comparator).

```bash
python3 tools/benchmark-campaign/offline_full_validation.py --config <config.json> --output <result.json>
```

Tests use a two-block Core-framed archive plus deterministic fixture nodes; indexed tests add a dual packed/indexed case (synthetic harness freeze, not C150/Cmodern) that proves the harness, not live performance. A live campaign needs hash-pinned `bitcoind` plus bitcoin-rs plus an issue-42 frozen corpus export ([`docs/contracts/campaign-corpora.md`](../contracts/campaign-corpora.md)); archive bytes are never stored in git; indexed-only arm execution is unresolved and unclaimed.

| Ceiling | Bound |
|---|---|
| archive | 1 TiB (packed plus indexed logical stream via byte-parity size equality) |
| manifest | 512 MiB |
| index | 512 MiB (Cmodern metadata: tens of MB) |
| blocks | 2,000,000 |
| blk sources | 10,000 |

Bounds admit Cmodern (genesis to 709,635), NOT the live full-tip chain (about 760 GiB, not a product corpus under #42).

Conclusion: this is the processing-bound regime (local blocks; wall equals validation plus durable commit), NOT download-bound IBD. Historical 1.654x C150 numbers are not carried forward; a new ratio exists only after a gated result file against a frozen corpus.
