# Storage and memory

RocksDB is the mandatory default storage engine, always compiled into the binary. `fjall` and `redb` are removed from runtime; legacy epoch-2 datadirs are migrated offline using `tools/storage-convert` (see the [datadir format policy](https://github.com/gosuda/bitcoin-rs/blob/main/docs/policies/db-migration.md)). Engine crate ownership and feature-forwarding rules are owned by `ARCH-02` and `ARCH-03` in the [architecture contract](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/architecture.md). Transcripts below write `$DATA` for the data directory you pass to `--data-dir`.

## Choose a backend

```sh
$ timeout 5 ./target/release/bitcoin-rs --network regtest --data-dir $DATA \
  --p2p-listen 127.0.0.1:0 --rpc-bind 127.0.0.1:0 --dns-seeds-enabled=false \
  --storage-backend rocksdb
```

It starts and names `"backend":"rocksdb"` in the storage line.

The accepted values are `rocksdb` (the default, always compiled), `surrealkv` (when compiled with cargo feature `surrealkv`), and `mdbx` (when compiled with cargo feature `mdbx`). An unknown name is rejected before startup:

```sh
$ ./target/release/bitcoin-rs --storage-backend bogus --network regtest --data-dir $DATA
error: invalid value 'bogus' for '--storage-backend <STORAGE_BACKEND>': unsupported storage backend bogus
```
Retired backends `fjall` and `redb` are rejected before startup with the same `unsupported storage backend <value>` error.

If a data directory was initialized by one engine and reopened with another, the node detects the engine mismatch and refuses startup with `<namespace> was created by <found>; start with --storage-backend <found> or convert with bitcoin-rs-storage-convert` (use `tools/storage-convert --from <old> --to <new> --to-engine <engine>` to migrate between engines).

In prior builds where `rocksdb` was an optional feature, running without `--features rocksdb` produced:

```sh
$ ./target/release/bitcoin-rs --storage-backend rocksdb --network regtest --data-dir $DATA
Error: unsupported storage backend rocksdb
```

In the current runtime, RocksDB is always compiled in, so a separate `--features rocksdb` flag is no longer required. Historical epoch-2 datadirs wrote `chainstate/0.jnl` plus numbered `chainstate/keyspaces/` (`fjall`) or `chainstate/redb.db` (`redb`); current epoch-6 datadirs write native RocksDB files (including `chainstate/CURRENT`).

The backend appears in the startup line:

```
{"timestamp":"...","level":"INFO","fields":{"message":"opened storage backend with effective cache capacities","backend":"rocksdb","chainstate_dir":"$DATA/chainstate","chainstate_cache_bytes":471859200,"txindex_cache_bytes":0,"total_cache_bytes":471859200},"target":"bitcoin_rs_node::state::open"}
```

## dbcache

`--dbcache-mb` sets the storage-engine cache budget in MiB. The default is 450 MiB. The value is clamped between 16 MiB and 1 TiB.

```sh
$ timeout 5 ./target/release/bitcoin-rs --network regtest --data-dir $DATA \
  --p2p-listen 127.0.0.1:0 --rpc-bind 127.0.0.1:0 --dns-seeds-enabled=false \
  --dbcache-mb 1 2>&1 | grep -o 'chainstate_cache_bytes":[0-9]*,"txindex_cache_bytes":[0-9]*,"total_cache_bytes":[0-9]*'
chainstate_cache_bytes":16777216,"txindex_cache_bytes":0,"total_cache_bytes":16777216
```

With the transaction index enabled, the budget splits 80 percent to chainstate and 20 percent to the index cache:

```sh
$ timeout 5 ./target/release/bitcoin-rs --network regtest --data-dir $DATA \
  --p2p-listen 127.0.0.1:0 --rpc-bind 127.0.0.1:0 --dns-seeds-enabled=false \
  --dbcache-mb 500 --txindex=true 2>&1 | grep -o 'chainstate_cache_bytes":[0-9]*,"txindex_cache_bytes":[0-9]*,"total_cache_bytes":[0-9]*'
chainstate_cache_bytes":419430400,"txindex_cache_bytes":104857600,"total_cache_bytes":524288000
```

A value above the ceiling clamps to 1 TiB:

```sh
$ timeout 5 ./target/release/bitcoin-rs --network regtest --data-dir $DATA \
  --p2p-listen 127.0.0.1:0 --rpc-bind 127.0.0.1:0 --dns-seeds-enabled=false \
  --dbcache-mb 2000000 2>&1 | grep -o '"total_cache_bytes":[0-9]*'
"total_cache_bytes":1099511627776
```

dbcache is a storage cache budget, not a process memory cap. Block staging has its own bounded wire budget, fixed at 256 blocks and 512 MiB in production. The signals that attribute staged bytes are backlog gauges, not an RSS reading; [`OBS-01`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/observability.md) owns that boundary.

## Pruning

`--prune-target-mb` turns on pruning when it is greater than zero. A pruned node advertises `NETWORK_LIMITED` instead of `NETWORK`, and `getblockchaininfo` reports `"pruned": true`.

Pruning is not compatible with the transaction, script, or compact-filter indexes:

```sh
$ timeout 5 ./target/release/bitcoin-rs --network regtest --data-dir $DATA \
  --p2p-listen 127.0.0.1:0 --rpc-bind 127.0.0.1:0 --dns-seeds-enabled=false \
  --prune-target-mb 600 --txindex=true
Error: transaction, script and compact-filter indexing are not compatible with -prune
```

The process exits with status 1. Pruning keeps a reorg safety margin of 288 blocks below the applied tip, so a recent reorg can still disconnect and reconnect. Older block bodies are removed; a query that needs them reports the history unavailable instead of returning an empty success.

## Schema and migrations

The authoritative format has one current epoch, `6`, recorded in `CURRENT_SCHEMA`. The node does not migrate, translate, or repair an incompatible directory in place. It refuses to open it and:

- preserves the directory untouched,
- reports `incompatible_schema` when the marker, epoch, or referenced bytes do not match,
- requires a separately named data directory and a fresh replay, or an implemented offline conversion step, for a format change.

Owner-local state carries its own versions. Rejected mempool snapshots move intact to a `mempool-snapshot-rejected-*` directory; a fee estimator with no usable history reports insufficient data. Those cases never move `CURRENT_SCHEMA`.

> **Warning** An epoch change is not an in-place upgrade. Stop all node processes and prevent changes to the source and target trees throughout conversion. Keep the old directory and use a distinct empty destination for each conversion run. Convert a retired epoch-2, epoch-3, epoch-4, or epoch-5 datadir offline with `tools/storage-convert`. An epoch-3, epoch-4, or epoch-5 source converts to epoch `6` in one run: the conversion chains the retired steps and writes marker `6`. An epoch-2 source converts to epoch `3` first, and a second run converts the result to epoch `6`; do not start the current node on the intermediate epoch-3 directory. Run `bitcoin-rs-storage-convert --from <epoch-2-dir> --to <epoch-3-dir> --to-engine rocksdb` and inspect its JSON verification report, then run `bitcoin-rs-storage-convert --from <epoch-3-dir> --to <epoch-6-dir> --to-engine rocksdb` and inspect that report before switching to the converted directory. The `3 -> 4` step requires a complete checkpoint and the block bodies and undo rows needed to replay its suffix to the durable head. It moves the coins from the retired checkpoint coin image into the engine `Coins` keyspace and publishes an engine-backed checkpoint. If the required inputs are unavailable, use a separately named directory and fresh replay instead. The `3 -> 4` run carries a legacy `chainstate-journal/full-revalidation` marker to the target root when the source has it, and the `4 -> 6` run carries an existing root marker or falls back to that journal marker; both reject markers larger than 9 bytes and preserve the full-revalidation requirement in the target. The [datadir format policy](https://github.com/gosuda/bitcoin-rs/blob/main/docs/policies/db-migration.md) owns the procedure, and [`RCV-09`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/recovery.md) owns the fresh-replay and schema-refusal rule.

## Next

See what recovery does after a crash: [Sync, recovery, and pruning](sync-and-recovery.md).
