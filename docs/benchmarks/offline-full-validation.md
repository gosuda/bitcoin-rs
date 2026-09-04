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
  little-endian, matching Bitcoin.
- **Manifest**: `core-framed-archive-manifest-v1` names network, magic,
  inclusive height range, archive digest and size, and one packed entry per
  height (`hash`, `offset`, `payload_length`). Heights are contiguous. The
  packed records must consume the archive exactly.
- **Posture**: `assume_valid` must be false. `txindex`, `blockfilterindex`,
  and `coinstatsindex` must be off. Cache policy is a closed set
  (`process-cold/page-cache-unspecified` or
  `process-cold/page-cache-evicted`). A configured cache number that
  production code does not consume cannot appear here as if it established
  parity.
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
  `{corpus_path}`, `{manifest_path}`, `{state_path}`.

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
clean checkpoint, and exit nonzero if publication fails. The comparator
does not parse product-specific flags; the pinned command and the certified
state are the proof.

## Correctness gates, in order

`_require_comparable` runs before any statistics:

1. Exactly 14 arms, two per pair, one Core and one bitcoin-rs.
2. Alternation: even pairs Core-first, odd pairs bitcoin-rs-first.
3. Archive and binary identities unchanged from config load.
4. Each arm exited 0 (durable clean exit). Reopen arms additionally exited 0.
5. Certified state equals the config expectation on both arms and the two
   arms agree with each other.

Any refusal raises `ContractError`, the process exits 2, and **no result
JSON is emitted**. Publication is atomic: bytes are written to an unnamed
`O_TMPFILE` inode, fsynced, and linked with `linkat(AT_EMPTY_PATH)`. An
existing destination survives.

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

This is the processing-bound regime in CONCEPTS.md: blocks are local, wall
is validation plus durable commit. It is not download-bound IBD. Historical
1.654× C150 numbers are not carried forward; a new ratio exists only after
a gated result file is published against a frozen corpus.
