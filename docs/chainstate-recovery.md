# Chainstate crash recovery

The node keeps an authenticated checkpoint and a bounded chainstate journal. A restart restores the checkpoint and replays only the journal's durable committed range instead of validating every block applied since the last clean shutdown.

## Safety contract

`head.json` is the journal commit point. It identifies the checkpoint generation and base tip, the durable journal cursor and tip, cumulative transaction count, and committed record count. A record contains the validated header plus exact UTXO mutations needed to reconstruct UTXO state and CoinStats.

A durability boundary runs in this order:

1. flush the storage backend so previously written block bodies and undo rows are durable;
2. fsync the journal segment;
3. atomically replace and directory-sync `head.json`.

The writer appends segment bytes between boundaries without per-block fsync. A crash may lose the current uncommitted batch, but startup never treats bytes beyond `head.json` as committed.

Checkpoint publication is one serialized operation: pause chain transitions, freeze and flush the journal, publish the checkpoint, rebase and compact the journal, then resume appends. A crash during publication may select either the previous or new durable frontier; it must not combine identities from both.

## Restore outcomes

| Observed state | Startup action |
|---|---|
| Checkpoint and matching journal head | Stream committed records, verify CRC/contiguity/header identity, and publish the journal tip |
| Checkpoint with no journal | Use the checkpoint and initialize an empty journal |
| Unreadable journal head, committed-range corruption, base mismatch, or rejected header | Discard that journal generation and use the checkpoint |
| No complete checkpoint | Start cold and initialize a journal |
| Reorg below the checkpoint base | Persist `chainstate-journal/full-revalidation` and start cold on every restart until a replacement checkpoint publishes |
| Journal disabled | Use checkpoint-only recovery |

Replay mutates an owned checkpoint state. Any error discards the partially reconstructed state before it can become runtime state. Segment contents are read one frame at a time; memory use is bounded by checkpoint state plus one decoded journal record rather than the complete replay gap.

## Reorg behavior

A reorg whose fork is at or above the checkpoint base rewrites `head.json` to the fork before truncating and deleting old-branch segment tails. The disconnect marker is released only after the new journal frontier is durable. A replacement block can then append to the rewritten frontier and survives another restart.

A fork below the checkpoint base cannot be represented as a suffix of that checkpoint. The writer invalidates the journal generation and publishes the full-revalidation marker. Operators should not delete this marker while the old checkpoint remains. Successful publication of a checkpoint rebuilt by normal validation replaces the base and removes the marker.

## Degraded mode

Journal append, extraction, or durability errors are logged and counted, but do not roll back an already committed block. Recovery then falls back to the last valid checkpoint. This can increase restart work; it does not authorize replay of an unauthenticated or partial journal.

Investigate repeated `append_failures`, `storage_flush_seconds` spikes, increasing lag, or fallback counters. Preserve the datadir before manually removing files when corruption evidence is needed.

## Disk and cadence policy

The `[chainstate_journal]` configuration controls the independent durability and retention bounds:

| Setting | Default | Meaning |
|---|---:|---|
| `enabled` | `true` | Enable journal write and replay |
| `blocks` | 500 | Maximum block batch before a durability boundary |
| `seconds` | 5 | Maximum time batch before a boundary |
| `rotate_mib` | 256 | Active segment rotation threshold |
| `max_journal_mib` | 2048 | Retention/disk bound |
| `max_lag_blocks` | 500 | Apply backpressure threshold in blocks |
| `max_lag_seconds` | 30 | Apply backpressure threshold in time |

Durability lag and replay length are different properties. `blocks`/`seconds` bound new progress that a crash can lose. Checkpoint cadence plus `max_journal_mib` bounds the amount of journal work a restart may replay.

## Metrics and logs

Prometheus names use the `node.chainstate_journal` prefix:

| Metric | Type | Meaning |
|---|---|---|
| `lag_blocks` | gauge | Latest appended height minus durable head height |
| `head_height` | gauge | Durable journal head height |
| `size_mib` | gauge | Bytes in journal segment files, reported in MiB at head publication |
| `replay_seconds` | histogram | Journal validation and replay duration |
| `fallback_total{reason}` | counter | Checkpoint/cold fallback classified by a bounded reason label |
| `checksum_failures_total` | counter | Head or committed-record checksum rejection |
| `append_failures` | counter | Journal extraction or append failure after block commit |
| `storage_flush_seconds` | histogram | Storage-side flush latency at a durability boundary |

Restore logs include `restore_source`, checkpoint generation/height, selected height/hash, transaction count, replayed record count, duration, and fallback reason where applicable.

## Upgrade behavior

The current binary accepts an existing checkpoint-only datadir and initializes a journal. Partial journal initialization, a retired V1 `recovery_meta.json` sidecar, an incompatible journal version, or a checkpoint-generation mismatch never becomes an integrity error for the checkpoint itself: the journal is rejected and checkpoint recovery continues. Current checkpoint corruption still follows the strict datadir format policy in [policies/db-migration.md](policies/db-migration.md).

The retired V1 sidecar is not read or migrated. It did not contain enough state to provide bounded replay and is intentionally outside the authoritative recovery path.

## Verification

Process-level tests kill child processes after journal, reorg, and publication transitions and verify the next process restores the expected frontier. The upgrade matrix covers no journal, partial initialization, stale V1 sidecar, version mismatch, and checkpoint generation change.

The opt-in Linux/Docker performance gate is:

```bash
cargo test -p bitcoin-rs-node --test chainstate_journal_bench \
  replay_10k_records_with_bounded_time_and_memory -- --ignored --exact --nocapture
```

A single synthetic regtest run against the rebased Task 10 candidate replayed 10,000 one-transaction records in **2.804 seconds**, with a measured peak-RSS delta of **11,344 KiB** (`VmHWM`, isolated replay process). The gate limits replay to 60 seconds and 256 MiB RSS delta. This is a bounded regression datapoint, not a mainnet IBD result or a controlled journaling-on/off apply-throughput comparison.
