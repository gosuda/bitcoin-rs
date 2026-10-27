# Offline full-validation comparator

Harness: `tools/benchmark-campaign/offline_full_validation.py`. Tests:
`tools/benchmark-campaign/test_offline_full_validation.py`. Addresses issue #34
and implements the frozen parity contract from issue #46.

Both Bitcoin Core 31.1 and bitcoin-rs construct chainstate from the **same**
hash-pinned Core-framed archive. The comparator never reaches inside either
node. A ratio is computed only after every custody and correctness gate
passes. The harness also accepts a dual packed/indexed input for custody
parity: the packed archive plus a producer-owned indexed blk stream over the
same verified logical bytes. This repository does not claim a live C150 or
Cmodern campaign: CI proves the harness with fixture nodes only.

## What is held identical

One `offline-full-validation-config-v1` document binds every arm:

- **Archive**: Bitcoin Core `blk*.dat` framing only — 4-byte message start,
  4-byte little-endian payload length, consensus-serialized block. No
  padding, stale-chain records, or backend-specific bytes. The comparator
  opens the file `O_NOFOLLOW`, hashes it, and walks every record against the
  manifest. Trailing bytes, a magic mismatch, a length mismatch, or a header
  hash that does not match the manifest refuse the run before any child
  starts. Block hash is Bitcoin Core `CBlockHeader::GetHash`: double-SHA256
  of the 80-byte header, displayed little-endian. The helper is checked
  against the published mainnet genesis header
  (`000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f`
  from Core `CMainParams`), not only against synthetic fixture bytes hashed
  with the same algorithm.
- **Manifest**: either `core-framed-archive-manifest-v1` (top-level
  `start_height`/`stop_height`, `archive_sha256`/`archive_bytes`, `blocks`)
  or the producer `bitcoin-rs-corpus-manifest` version 1 (`range`
  `{start_height,stop_height}`, `archive` `{sha256,size}`, `entries`; only
  version 1 is accepted and unknown schemas are refused). Both readers parse
  both shapes directly with no converted or duplicate manifest. Both shapes
  name network, magic, inclusive height range, archive digest and size, and
  one packed entry per height (`height`, `hash`, `offset`, `payload_length`).
  Heights are contiguous from `start_height`. The packed records must
  consume the archive exactly. The manifest `network` must equal the
  configured node network identity (`config.network.identity_name()`, so a
  regtest run accepts `regtest`) and its magic must equal that network's
  magic; there is no mainnet-only literal.
- **Indexed parity (harness)**: an optional `indexed` block names a
  producer-owned `bitcoin-rs-corpus-index-v1` document, a directory of Core
  `blkNNNNN.dat` sources, and the freeze file that binds them. At config
  load the comparator runs producer `verify_index` once, then fully exhausts
  `iter_indexed_framed` and requires the streamed framed bytes to equal the
  packed archive digest and size. Magic must match, order and stop hash are
  bound through the freeze tip plus the packed manifest tip, and any source
  or index mutation refuses before any child starts.
- **Pinned corpus**: after config load, the campaign copies archive and
  manifest into a private campaign directory, re-hashes both, and
  chmod's them `0o400`. When `indexed` is present it also copies the index
  document and every declared `blkNNNNN.dat` source into private custody at
  `0o400`. Both arms read the archive pin: `_corpus_path_for_arm` binds
  `{corpus_path}` to `custody/archive`, the single regular file whose bytes
  equal the indexed logical stream by the verified parity above. The index
  and blk pins are custody-pinned and re-hashed before and after every
  child, but they are never passed as `{corpus_path}`: the custody `sources`
  directory holds multiple `blkNNNNN.dat` files while the timed command
  expects one regular corpus file, and Core opens each `-loadblock` path
  with `fopen(path, "rb")` (`bitcoin-core/src/node/blockstorage.cpp`,
  `ImportBlocks`). Before and after every child, the controller re-hashes
  every pin (archive, manifest, index, each blk source) and checks device,
  inode, size, and mtime. A same-user child that chmod's and rewrites a pin
  fails closed. Dual custody transiently holds the corpus twice (packed
  bytes plus indexed sources); no third copy is materialized because parity
  already binds the executed bytes to the indexed stream.
- **Posture**: `assume_valid` must be false. `txindex`, `blockfilterindex`,
  and `coinstatsindex` must be off. Cache policy is the closed set
  `process-cold/page-cache-unspecified`. The sibling MuHash comparator
  requires hash-bound evidence before it will claim page-cache eviction;
  this harness does not enact eviction, so that policy string is refused
  rather than published as a posture the run did not take.
- **Certified state**: height, best block, UTXO count, total amount in
  satoshis, MuHash, `hash_serialized_3`, body availability, and one-block
  disconnect readiness. Height and best block must equal the manifest tip.
  Body availability and disconnect readiness must be true.
- **Lifecycle**: `fresh` times one process from spawn through durable clean
  exit. `reopen` then runs an untimed reopen command against the same data
  directory and requires the same certified state.
- **Binaries**: SHA-256 pinned. `command[0]` is the `{binary}` placeholder.
  The controller copies the pinned program into a private arm directory,
  verifies the copy, strips owner-write (`0o500`), and re-hashes immediately
  before every spawn. Placeholders are `{binary}`, `{data_dir}`,
  `{corpus_path}`, `{manifest_path}`, `{state_path}`. The timed command
  must carry a known assume-valid-off token (`-assumevalid=0`,
  `--assume-valid-height=0`, or the two-token form with `0`) and must not
  carry a known index-on token (`-txindex`, `-txindex=1`, `--txindex=true`,
  `-blockfilterindex`, `-coinstatsindex`, and the same spellings with
  `--` and `=1`/`=true`). Reopen commands are not re-checked. The
  comparator does not parse the rest of either product's flag dialect.

## Timed boundary

Wall time is `time.monotonic_ns` from child creation through wait-for-exit.
It includes archive read, framing parse, validation, chainstate mutation,
persistence, flush, and shutdown. No stage is subtracted. CPU (`utime+stime`)
and peak RSS are sampled from `/proc` and reported separately; they are not
an alternate definition of speed.

The child must remain in the foreground and exit. Bitcoin Core consumes the
`{corpus_path}` file through its checked-in `-loadblock` family: flag
`bitcoin-core/src/init.cpp:529`, collection `2128-2136` (`vImportFiles`,
`ImportBlocks(chainman, vImportFiles)`, then `ActivateBestChains`), fan-out
`bitcoin-core/src/node/blockstorage.cpp:1270` (`ImportBlocks`), and
`bitcoin-core/src/validation.cpp:4975`
(`ChainstateManager::LoadExternalBlockFile` magic scan, size gate, header
hash, `AcceptBlock` without `ProcessNewBlock`). Core commands must not
daemonize (`-daemon=0`) and should stop after import
(`-stopafterblockimport=1`, `-assumevalid=0`, `-stopatheight=H`).
bitcoin-rs consumes the same single regular `{corpus_path}` file through
`crates/node/src/offline_import.rs` (`--corpus`, `--manifest`, `--state`
with `--data-dir` and `--assume-valid-height 0`): Core-framed walk with
manifest binding, full validation, durable bodies plus undo, production
clean checkpoint, and an eight-field certified state. It persists bodies
and undo, publishes the production clean checkpoint, exits nonzero when
publication or any gate fails, never daemonizes or forks, and leaves no
descendants. After wait, the process group must be empty and the
comparator, running as a Linux child subreaper, must own no leftover
descendants. A fixture that forks a sleeper and then exits 0 is refused; no
result JSON is published.

## Correctness gates, in order

`_require_comparable` runs before any statistics:

1. Exactly 14 arms, two per pair, one Core and one bitcoin-rs.
2. Alternation: even pairs Core-first, odd pairs bitcoin-rs-first.
3. Archive and binary identities unchanged from the campaign pin.
4. Each arm exited 0 (durable clean exit). Reopen arms additionally exited 0.
5. Certified state equals the config expectation on both arms and the two
   arms agree with each other.

Any refusal raises `ContractError`, the process exits 2, and **no result
JSON is emitted**. Publication is atomic: bytes are written to an unnamed
`O_TMPFILE` inode, fsynced, and linked with `linkat(AT_EMPTY_PATH)`. The
commit point is a successful link. Crash before the link leaves the
destination unchanged and is retriable; crash after the link (or a retry
against an existing name) is `EEXIST` and must not overwrite. Directory
fsync follows the link. This function does not retry.

## Result contract

`offline-full-validation-result-v1` binds the config canonical hash, the
custody block (magic, network, height range, archive/manifest/binary
digests, posture, lifecycle), a `correctness` block (every gate `true` —
the document cannot exist otherwise), every arm's wall/CPU/RSS, exit code,
and certified state, per-role percentile summaries, and
`candidate_over_core_p50_ratio`. `result_sha256` is the canonical hash of
the document without that field. The indexed index digest and per-source
digests are bound through `config_sha256` (the indexed block is part of the
hashed config); the custody block keeps the packed archive/manifest shape so
the result schema is unchanged.

Raw argv is never published. Public command digests use the same
category-only projection as the P2P loopback comparator.

## Standalone usage

```
python3 tools/benchmark-campaign/offline_full_validation.py \
  --config <config.json> --output <result.json>
python3 -m unittest test_offline_full_validation   # from tools/benchmark-campaign/
```

Tests use a two-block Core-framed archive and deterministic fixture nodes
that read the archive and write the certified state file. Indexed harness
tests add a dual packed/indexed case over the same two linked bytes with a
synthetic harness freeze (not C150/Cmodern): an indexed golden plus source,
truncation, index-tamper, and post-load pin refusals. They prove the
harness, not live node performance. A live seven-pair campaign still needs
hash-pinned `bitcoind` and bitcoin-rs binaries plus an exported archive of
a corpus frozen by issue #42
([`docs/contracts/campaign-corpora.md`](../contracts/campaign-corpora.md));
archive bytes are not stored in git. Indexed-only arm execution (no packed
archive for arms) remains unresolved and is not claimed here.

## Limits

Campaign ceilings: archive 1 TiB, manifest 512 MiB, index 512 MiB,
2 000 000 blocks, at most 10 000 blk sources. The 1 TiB bound covers both
the packed archive and the indexed logical stream via byte-parity size
equality; the index bound covers Cmodern metadata (tens of megabytes).
Those bounds admit the Cmodern corpus (genesis .. 709,635); they are not a
promise to ingest the live full-tip chain (~760 GiB), which is not a
product corpus under issue #42.

This is the processing-bound regime in CONCEPTS.md: blocks are local, wall
is validation plus durable commit. It is not download-bound IBD. Historical
1.654× C150 numbers are not carried forward; a new ratio exists only after
a gated result file is published against a frozen corpus.
