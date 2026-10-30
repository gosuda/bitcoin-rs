# Offline full-validation comparator

Harness `tools/benchmark-campaign/offline_full_validation.py`, tests `tools/benchmark-campaign/test_offline_full_validation.py`; addresses issue #34, implements the frozen parity contract of issue #46. Core 31.1 and bitcoin-rs build chainstate from the same hash-pinned Core-framed archive; neither node is reached inside; the ratio is computed only after all custody and correctness gates pass. No live C150/Cmodern campaign is claimed: CI proves the harness with fixture nodes only.

## What is held identical

One `offline-full-validation-config-v1` document binds every arm. The archive entry accepts Bitcoin Core `blk*.dat` framing only: 4-byte magic, LE length, consensus block. The harness opens it with `O_NOFOLLOW` and hashes it, then walks the per-record manifest. Trailing bytes, magic, length or header-hash mismatch refuses before any child starts. The block hash is Core `CBlockHeader::GetHash`, the double-SHA256 of the 80-byte header, checked against mainnet genesis `000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f`. The manifest entry accepts `core-framed-archive-manifest-v1` or producer `bitcoin-rs-corpus-manifest` v1 only. It requires contiguous heights from `start_height`, exact archive consumption, and a network and magic that MUST equal the node identity. The optional indexed parity entry takes producer `bitcoin-rs-corpus-index-v1` plus `blkNNNNN.dat` sources plus freeze. `verify_index` runs first. Then the bytes of `iter_indexed_framed` MUST equal the packed digest and size. The pinned custody entry uses `<root>/custody/archive|manifest|index|sources/`, re-hashed with `0o400`, and it checks device, inode, size and mtime before and after every child. Custody is transient under `TemporaryDirectory(prefix="offline-full-validation-")`, and only the result JSON survives. The posture entry sets `assume_valid` false, `txindex`/`blockfilterindex`/`coinstatsindex` off, and cache `process-cold/page-cache-unspecified`; page-cache-eviction posture is refused. The certified state entry requires height, a best block equal to the manifest tip, UTXO count, satoshis, MuHash and `hash_serialized_3`. It also requires body availability plus one-block disconnect readiness, both true. The lifecycle entry is `fresh` timed spawn-to-clean-exit or `reopen` untimed same-state reopen. Binaries are SHA-256 pinned, and the `{binary}` placeholder points to a per-arm verified `0o500` copy that is re-hashed before every spawn. The timed command MUST carry an assume-valid-off token and MUST NOT carry index-on tokens.

Timed boundary: wall is `time.monotonic_ns` from child creation to wait-exit. That span covers read, parse, validation, mutation, persistence, flush and shutdown, and nothing is subtracted. CPU (`utime+stime`) and peak RSS come from `/proc` and are reported separately. The child MUST stay in the foreground and exit. Core consumes `{corpus_path}` through its checked-in `-loadblock` family (`src/init.cpp`, `blockstorage.cpp`, `validation.cpp`; `-daemon=0 -stopafterblockimport=1 -assumevalid=0 -stopatheight=H`). bitcoin-rs consumes the same file through `crates/node/src/offline_import.rs` (`--corpus --manifest --state --data-dir --assume-valid-height 0`). It persists bodies plus undo, publishes the clean checkpoint, and exits nonzero on any gate failure. It never daemonizes or forks. An empty process group with no subreaper-owned leftover descendants is required, else the arm is refused.

The gates run in this order (`_require_comparable`). First, exactly 14 arms (2 per pair, Core plus bitcoin-rs). Second, alternation. Third, unchanged archive and binary identities. Fourth, exit 0, and reopen arms also exit 0. Fifth, a certified state that equals the expectation on both arms and agrees across arms. Refusal raises `ContractError`, exits 2, and emits NO result JSON. Atomic publish uses an unnamed `O_TMPFILE` plus fsync plus `linkat(AT_EMPTY_PATH)` plus dir fsync. A pre-link crash is retriable. A post-link crash or `EEXIST` MUST NOT overwrite, and there are no retries.

Result `offline-full-validation-result-v1` holds the config hash, the custody block, the `correctness` block (all `true`), and every arm wall, CPU, RSS, exit status and state. It adds per-role percentile summaries and `candidate_over_core_p50_ratio`. `result_sha256` covers the canonical form without that field, and index and source digests are bound through `config_sha256`. Raw argv is never published, with the same category-only projection as the P2P loopback comparator.

```bash
python3 tools/benchmark-campaign/offline_full_validation.py --config <config.json> --output <result.json>
```

Tests use a two-block Core-framed archive plus deterministic fixture nodes. Indexed tests add a dual packed/indexed case (synthetic harness freeze, not C150/Cmodern), and that case proves the harness, not live performance. A live campaign needs hash-pinned `bitcoind` plus bitcoin-rs plus an issue-42 frozen corpus export ([`docs/contracts/campaign-corpora.md`](../contracts/campaign-corpora.md)). Archive bytes are never stored in git. Indexed-only arm execution is unresolved and unclaimed.

| Ceiling | Bound |
|---|---|
| archive | 1 TiB (packed plus indexed logical stream via byte-parity size equality) |
| manifest | 512 MiB |
| index | 512 MiB (Cmodern metadata: tens of MB) |
| blocks | 2,000,000 |
| blk sources | 10,000 |

Bounds admit Cmodern (genesis to 709,635). They do NOT admit the live full-tip chain, which is about 760 GiB and not a product corpus under #42.

Conclusion: this is the processing-bound regime, where local blocks make the wall equal validation plus durable commit. It is NOT download-bound IBD. Historical 1.654x C150 numbers are not carried forward. A new ratio exists only after a gated result file against a frozen corpus.
