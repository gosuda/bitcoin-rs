# Offline full-validation comparator

Harness: `tools/benchmark-campaign/offline_full_validation.py`. Tests:
`tools/benchmark-campaign/test_offline_full_validation.py`. Addresses issue #34
and implements the frozen parity contract from issue #46.

Both Bitcoin Core 31.1 and bitcoin-rs construct chainstate from the **same**
hash-pinned Core-framed archive. The comparator never reaches inside either
node. A ratio is computed only after every custody and correctness gate
passes. This repository does not claim a live C150 or Cmodern campaign: CI
proves the harness with fixture nodes.

## What is held identical

One `offline-full-validation-config-v1` document binds every arm:

- **Archive**: Bitcoin Core block-file framing only — 4-byte network magic,
  4-byte little-endian payload length, consensus-serialized block. No
  padding, stale-chain records, or backend-specific bytes. The comparator
  opens the file `O_NOFOLLOW`, hashes it, and walks every record against the
  manifest. Trailing bytes, a magic mismatch, a length mismatch, or a header
  hash that does not match the manifest refuse the run before any child
  starts. Block hash is double-SHA256 of the 80-byte header, displayed
  little-endian, matching Bitcoin. The hash helper is checked against the
  published 80-byte mainnet genesis header
  (`000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f`),
  not only against synthetic fixture bytes hashed with the same algorithm.
- **Manifest**: `core-framed-archive-manifest-v1` names network, magic,
  inclusive height range, archive digest and size, and one packed entry per
  height (`hash`, `offset`, `payload_length`). Heights are contiguous. The
  packed records must consume the archive exactly.
- **Pinned corpus**: after config load, the campaign copies archive and
  manifest into a private campaign directory, re-hashes both, and
  chmod's them `0o400`. Every arm reads those pins. A same-size rewrite
  of the operator path after load cannot change what the children see.
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

The child must remain in the foreground and exit. Bitcoin Core commands
must not daemonize (`-daemon=0`) and should stop after import
(`-stopafterblockimport=1`, `-assumevalid=0`, `-stopatheight=H`). bitcoin-rs
commands must apply the same archive through height `H` with
`--assume-valid-height 0`, persist bodies and undo, publish the production
clean checkpoint, and exit nonzero if publication fails. After wait, the
process group must be empty and the comparator, running as a Linux child
subreaper, must own no leftover descendants. A fixture that forks a
sleeper and then exits 0 is refused; no result JSON is published.

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
the document without that field.

Raw argv is never published. Public command digests use the same
category-only projection as the P2P loopback comparator.

## Standalone usage

```
python3 tools/benchmark-campaign/offline_full_validation.py \
  --config <config.json> --output <result.json>
python3 -m unittest test_offline_full_validation   # from tools/benchmark-campaign/
```

Tests use a two-block Core-framed archive and deterministic fixture nodes
that read the archive and write the certified state file. They prove the
harness, not live node performance. A live seven-pair campaign still needs
hash-pinned `bitcoind` and bitcoin-rs binaries plus a frozen corpus from
issue #42.

## Limits

Campaign ceilings: archive 1 TiB, manifest 512 MiB, 2 000 000 blocks.
Those bounds admit a Cmodern prefix; they are not a promise to ingest the
live full-tip chain (~760 GiB) until issue #42 freezes that corpus.

This is the processing-bound regime in CONCEPTS.md: blocks are local, wall
is validation plus durable commit. It is not download-bound IBD. Historical
1.654× C150 numbers are not carried forward; a new ratio exists only after
a gated result file is published against a frozen corpus.
