# Storage and memory

RocksDB is the mandatory default storage engine, always compiled into the binary. `fjall` and `redb` are removed from runtime; legacy epoch-2 datadirs are migrated offline using `tools/storage-convert` (see the [datadir format policy](https://github.com/gosuda/bitcoin-rs/blob/main/docs/policies/db-migration.md)). Transcripts below write `$DATA` for the data directory you pass to `--data-dir`.

## Choose a backend

```sh
$ timeout 5 ./target/release/bitcoin-rs --network regtest --data-dir $DATA \
  --p2p-listen 127.0.0.1:0 --rpc-bind 127.0.0.1:0 --dns-seeds-enabled=false \
  --storage-backend rocksdb
```

It starts and names `"backend":"rocksdb"` in the storage line.

The accepted value is `rocksdb`. An unknown name is rejected before startup:

```sh
$ ./target/release/bitcoin-rs --storage-backend bogus --network regtest --data-dir $DATA
error: invalid value 'bogus' for '--storage-backend <STORAGE_BACKEND>': unsupported storage backend bogus
```
Retired backends `fjall` and `redb` are rejected before startup with the same `unsupported storage backend <value>` error.

In prior builds where `rocksdb` was an optional feature, running without `--features rocksdb` produced:

```sh
$ ./target/release/bitcoin-rs --storage-backend rocksdb --network regtest --data-dir $DATA
Error: unsupported storage backend rocksdb
```

In the current runtime, RocksDB is always compiled in, so a separate `--features rocksdb` flag is no longer required. Historical epoch-2 datadirs wrote `chainstate/0.jnl` plus numbered `chainstate/keyspaces/` (`fjall`) or `chainstate/redb.db` (`redb`); current epoch-3 datadirs write native RocksDB files (including `chainstate/CURRENT`).

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

## The chainstate journal

`chainstate_journal` is a TOML table with no CLI flags. Each field also has a `BITCOIN_RS_CHAINSTATE_JOURNAL*` environment spelling. It controls the derived journal that records committed chain events for consumers. Defaults from the resolved config are `blocks = 500`, `seconds = 5`, `rotate_mib = 256`, `max_journal_mib = 2048`, `max_lag_blocks = 500`, and `max_lag_seconds = 30`. The journal may lag the durable head, never lead it, and losing it does not lose chainstate.

## Schema and migrations

The authoritative format has one current epoch, `3`, recorded in `CURRENT_SCHEMA`. The node does not migrate, translate, or repair an incompatible directory in place. It refuses to open it and:

- preserves the directory untouched,
- reports `incompatible_schema` when the marker, epoch, or referenced bytes do not match,
- requires a separately named data directory and a fresh replay for a format change.

Owner-local state carries its own versions. Rejected mempool snapshots move intact to a `mempool-snapshot-rejected-*` directory; a fee estimator with no usable history reports insufficient data. Those cases never move `CURRENT_SCHEMA`.

> **Warning** An epoch change is not an in-place upgrade. Keep the old directory, create a new one, sync it, then switch (or migrate retired epoch-2 datadirs using `tools/storage-convert`). The [datadir format policy](https://github.com/gosuda/bitcoin-rs/blob/main/docs/policies/db-migration.md) owns the procedure, and [`RCV-09`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/recovery.md) owns the fresh-replay and schema-refusal rule.

## Next

See what recovery does after a crash: [Sync, recovery, and pruning](sync-and-recovery.md).
