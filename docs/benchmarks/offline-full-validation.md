# Offline full-validation comparator

This document owns the offline full-validation comparator lane: bitcoin-rs and Bitcoin Core `v31.1` construct chainstate from the same hash-pinned Core-framed archive, and a ratio exists only after every custody and correctness gate passes. Harness: `tools/benchmark-campaign/offline_full_validation.py`; tests: `tools/benchmark-campaign/test_offline_full_validation.py`. In the target node this lane supplies the full-replay evidence for T15 parity and T17 promotion, the `replay.offline_full_validation` cell of [`overhaul-product-cells.md`](overhaul-product-cells.md), and the CL-06 and CL-20 constraint rows.

## Cell it owns

Processing-bound wall from child spawn to durable clean exit, over a pinned archive, for one bitcoin-rs artifact against the pinned Core `v31.1` binary, plus certified end state (height, best block, UTXO count, total amount, MuHash, `hash_serialized_3`).

## Reference identities

| Arm | Identity |
|---|---|
| Bitcoin Core | release `v31.1`, commit `9be056a8a72b624dae9623b2f7bded92c2a21c91`, x86_64 linux archive SHA-256 `b80d9c3e04da78fb6f0569685673418cf686fadba9042d926d13fb87ff503f9e`, `bitcoind` SHA-256 `986e63b3c8770f08d0059820ad3dd085d1ab9e1bea23946c243f858a06888a08` |
| bitcoin-rs | final strict-Rust artifact after T16, built `--no-default-features --features fjall` under `CARGO_TARGET_DIR=target/native`; SHA-256 recorded per run |
| Corpora | C150 and Cmodern archives frozen by [`docs/contracts/campaign-corpora.md`](../contracts/campaign-corpora.md); archive and manifest digests recorded per run, `UNMEASURED` here |
| Full mainnet | genesis to the pinned stop identity (height and hash recorded before the run, `UNMEASURED` here) |

## End-state cells

| Cell | Required outcome | Status |
|---|---|---|
| C150 seven-pair alternating campaign | every gate `true`; `candidate_over_core_p50_ratio` reported with p50/p95/p99/max | `planned_not_executed` |
| Cmodern seven-pair alternating campaign | same | `planned_not_executed` |
| Full mainnet replay to pinned stop | certified state equal on both arms; sampled and exact coin comparison; zero unexplained mismatches | `planned_not_executed` |
| Invalid and contextual corpora | rejection parity, every exclusion counted and classified (T15) | `planned_not_executed` |
| Reopen lifecycle | untimed reopen reproduces the certified state | `planned_not_executed` |

The signed-spend Criterion target and this lane answer different questions; neither substitutes for the other. A version string alone never passes; a missing `bitcoind` or archive digest marks the lane `BLOCKED`.

## Required identities per sample

Every sample in this cell records six identities. The T02 collector rejects a sample that lacks any of them; a rejected sample is not evidence.

| Identity | Content |
|---|---|
| Artifact | SHA-256 of the exact binary, library or image measured; source commit |
| Configuration | Resolved `NodeConfig`, feature set, allocator, validation mode |
| Corpus | Corpus digest, height range, stop height and stop hash |
| Durability | Backend, batch mode (`write`, `write_deferred`, `write_durable`), flush and sync posture |
| Toolchain | `rustc 1.95.0`, edition 2024, profile, enabled features |
| Hardware | CPU model, pinned core set, memory, storage device, OS kernel |

## Acceptance rule

- Promotion of a candidate over its control requires a median gain of at least 1.05x over at least three alternating candidate/control runs. Each arm stays within 5% of its own median. The improvement must exceed the observed host noise.
- Non-target cells guard at no more than 3% median regression and no more than 5% p99 regression, measured with repeated runs and reported uncertainty. Average-only reporting never passes.
- Report p50, p95, p99 and max with the sample count. Never sum nested intervals. Never sum concurrent intervals. Parallel worker walls and inclusive stage histograms are reported beside the process wall, not added to it.
- Retain raw samples beside every summary. A Criterion adaptive elapsed total is not a median source.
- A missing binary, corpus, hardware target or digest marks the cell `BLOCKED` with the missing identity named. `BLOCKED` is never a pass and never a skip.

## Status

`planned_not_executed`. No end-state cell in this document has run. Every value in the end-state tables is a required contract value, not a measurement. The section `Prior candidate evidence` below is historical and unchanged; it does not prove any end-state cell.

## Prior candidate evidence (harness contract before the end-state rewrite)

Retained verbatim from the pre-rewrite document. Headings are demoted one level. Nothing below is end-state proof.

Harness: `tools/benchmark-campaign/offline_full_validation.py`. Tests:
`tools/benchmark-campaign/test_offline_full_validation.py`. Addresses issue #34
and implements the frozen parity contract from issue #46.

Both Bitcoin Core 31.1 and bitcoin-rs construct chainstate from the **same**
hash-pinned Core-framed archive. The comparator never reaches inside either
node. A ratio is computed only after every custody and correctness gate
passes. This repository does not claim a live C150 or Cmodern campaign: CI
proves the harness with fixture nodes.

### What is held identical

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
- **Manifest**: `core-framed-archive-manifest-v1` names network, magic,
  inclusive height range, archive digest and size, and one packed entry per
  height (`hash`, `offset`, `payload_length`). Heights are contiguous. The
  packed records must consume the archive exactly.
- **Pinned corpus**: after config load, the campaign copies archive and
  manifest into a private campaign directory, re-hashes both, and
  chmod's them `0o400`. Every arm reads those pins. Before and after every
  child, the controller re-hashes both pins and checks device, inode, size,
  and mtime. A same-user child that chmod's and rewrites a pin fails closed.
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

### Timed boundary

Wall time is `time.monotonic_ns` from child creation through wait-for-exit.
It includes archive read, framing parse, validation, chainstate mutation,
persistence, flush, and shutdown. No stage is subtracted. CPU (`utime+stime`)
and peak RSS are sampled from `/proc` and reported separately; they are not
an alternate definition of speed.

The child must remain in the foreground and exit. Bitcoin Core commands
must not daemonize (`-daemon=0`) and should stop after import
(`-stopafterblockimport=1`, `-assumevalid=0`, `-stopatheight=H`). bitcoin-rs
commands must apply the same archive through height `H` with
`--assume-valid-height 0`, persist bodies and undo, publish the production
clean checkpoint, and exit nonzero if publication fails. After wait, the
process group must be empty and the comparator, running as a Linux child
subreaper, must own no leftover descendants. A fixture that forks a
sleeper and then exits 0 is refused; no result JSON is published.

### Correctness gates, in order

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

### Result contract

`offline-full-validation-result-v1` binds the config canonical hash, the
custody block (magic, network, height range, archive/manifest/binary
digests, posture, lifecycle), a `correctness` block (every gate `true` —
the document cannot exist otherwise), every arm's wall/CPU/RSS, exit code,
and certified state, per-role percentile summaries, and
`candidate_over_core_p50_ratio`. `result_sha256` is the canonical hash of
the document without that field.

Raw argv is never published. Public command digests use the same
category-only projection as the P2P loopback comparator.

### Standalone usage

```
python3 tools/benchmark-campaign/offline_full_validation.py \
  --config <config.json> --output <result.json>
python3 -m unittest test_offline_full_validation   # from tools/benchmark-campaign/
```

Tests use a two-block Core-framed archive and deterministic fixture nodes
that read the archive and write the certified state file. They prove the
harness, not live node performance. A live seven-pair campaign still needs
hash-pinned `bitcoind` and bitcoin-rs binaries plus an exported archive of
a corpus frozen by issue #42
([`docs/contracts/campaign-corpora.md`](../contracts/campaign-corpora.md));
archive bytes are not stored in git.

### Limits

Campaign ceilings: archive 1 TiB, manifest 512 MiB, 2 000 000 blocks.
Those bounds admit the Cmodern corpus (genesis .. 709,635); they are not a
promise to ingest the live full-tip chain (~760 GiB), which is not a
product corpus under issue #42.

This is the processing-bound regime in CONCEPTS.md: blocks are local, wall
is validation plus durable commit. It is not download-bound IBD. Historical
1.654× C150 numbers are not carried forward; a new ratio exists only after
a gated result file is published against a frozen corpus.
