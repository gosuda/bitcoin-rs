# Storage and memory

Three storage engines are selectable. `fjall` is the default, `redb` is compiled into the default binary, and `rocksdb` is a non-default feature.

## Choose a backend

```sh
$ timeout 5 ./target/release/bitcoin-rs --network regtest --data-dir /tmp/btcrs-book/redb \
  --p2p-listen 127.0.0.1:0 --rpc-bind 127.0.0.1:0 --dns-seeds-enabled=false \
  --storage-backend redb
```

It starts and names `"backend":"redb"` in the storage line.

The accepted values are `fjall`, `redb`, and `rocksdb`. An unknown name is rejected before startup:

```sh
$ ./target/release/bitcoin-rs --storage-backend bogus --network regtest --data-dir /tmp/btcrs-book/x
error: invalid value 'bogus' for '--storage-backend <STORAGE_BACKEND>': unsupported storage backend bogus
```

A known name that this build does not include fails config validation:

```sh
$ ./target/release/bitcoin-rs --storage-backend rocksdb --network regtest --data-dir /tmp/btcrs-book/x
bitcoin-rs: unsupported storage backend rocksdb
```

`rocksdb` needs a build with `--features rocksdb`. Giving each engine its own data directory when you compare them avoids mixing on-disk layouts; `fjall` writes `chainstate/0.jnl` plus numbered `chainstate/keyspaces/`, while `redb` writes `chainstate/redb.db`.

The backend appears in the startup line:

```
{"timestamp":"...","level":"INFO","fields":{"message":"opened storage backend with effective cache capacities","backend":"fjall","chainstate_dir":"/tmp/btcrs-book/regtest/chainstate","chainstate_cache_bytes":471859200,"txindex_cache_bytes":0,"total_cache_bytes":471859200},"target":"bitcoin_rs_node::state::open"}
```

## dbcache

`--dbcache-mb` sets the storage-engine cache budget in MiB. The default is 450 MiB. The value is clamped between 16 MiB and 1 TiB.

```sh
$ timeout 5 ./target/release/bitcoin-rs --network regtest --data-dir /tmp/btcrs-book/cache-16 \
  --p2p-listen 127.0.0.1:0 --rpc-bind 127.0.0.1:0 --dns-seeds-enabled=false \
  --dbcache-mb 1 2>&1 | grep -o 'chainstate_cache_bytes":[0-9]*,"txindex_cache_bytes":[0-9]*,"total_cache_bytes":[0-9]*'
chainstate_cache_bytes":16777216,"txindex_cache_bytes":0,"total_cache_bytes":16777216
```

With the transaction index enabled, the budget splits 80 percent to chainstate and 20 percent to the index cache:

```sh
$ timeout 5 ./target/release/bitcoin-rs --network regtest --data-dir /tmp/btcrs-book/cache-txindex \
  --p2p-listen 127.0.0.1:0 --rpc-bind 127.0.0.1:0 --dns-seeds-enabled=false \
  --dbcache-mb 500 --txindex=true 2>&1 | grep -o 'chainstate_cache_bytes":[0-9]*,"txindex_cache_bytes":[0-9]*,"total_cache_bytes":[0-9]*'
chainstate_cache_bytes":419430400,"txindex_cache_bytes":104857600,"total_cache_bytes":524288000
```

A value above the ceiling clamps to 1 TiB:

```sh
$ timeout 5 ./target/release/bitcoin-rs --network regtest --data-dir /tmp/btcrs-book/cache-1tib \
  --p2p-listen 127.0.0.1:0 --rpc-bind 127.0.0.1:0 --dns-seeds-enabled=false \
  --dbcache-mb 2000000 2>&1 | grep -o '"total_cache_bytes":[0-9]*'
"total_cache_bytes":1099511627776
```

dbcache is a storage cache budget, not a process memory cap. Block staging has its own bounded wire budget, fixed at 256 blocks and 512 MiB in production. The signals that attribute staged bytes are backlog gauges, not an RSS reading; [`OBS-01`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/observability.md) owns that boundary.

## Pruning

`--prune-target-mb` turns on pruning when it is greater than zero. A pruned node advertises `NETWORK_LIMITED` instead of `NETWORK`, and `getblockchaininfo` reports `"pruned": true`.

Pruning is not compatible with the transaction, script, or compact-filter indexes:

```sh
$ timeout 5 ./target/release/bitcoin-rs --network regtest --data-dir /tmp/btcrs-book/prune-index \
  --p2p-listen 127.0.0.1:0 --rpc-bind 127.0.0.1:0 --dns-seeds-enabled=false \
  --prune-target-mb 600 --txindex=true
bitcoin-rs: transaction, script and compact-filter indexing are not compatible with -prune
```

The process exits with status 1. Pruning keeps a reorg safety margin of 288 blocks below the applied tip, so a recent reorg can still disconnect and reconnect. Older block bodies are removed; a query that needs them reports the history unavailable instead of returning an empty success.

## The chainstate journal

`chainstate_journal` is a TOML table with no CLI flags. Each field also has a `BITCOIN_RS_CHAINSTATE_JOURNAL*` environment spelling. It controls the derived journal that records committed chain events for consumers. Defaults from the resolved config are `blocks = 500`, `seconds = 5`, `rotate_mib = 256`, `max_journal_mib = 2048`, `max_lag_blocks = 500`, and `max_lag_seconds = 30`. The journal may lag the durable head, never lead it, and losing it does not lose chainstate.

## Schema and migrations

The authoritative format has one current epoch, `2`, recorded in `CURRENT_SCHEMA`. The node does not migrate, translate, or repair an incompatible directory in place. It refuses to open it and:

- preserves the directory untouched,
- reports `incompatible_schema` when the marker, epoch, or referenced bytes do not match,
- requires a separately named data directory and a fresh replay for a format change.

Owner-local state carries its own versions. Rejected mempool snapshots move intact to a `mempool-snapshot-rejected-*` directory; a fee estimator with no usable history reports insufficient data. Those cases never move `CURRENT_SCHEMA`.

> **Warning** An epoch change is not an in-place upgrade. Keep the old directory, create a new one, sync it, then switch. The [datadir format policy](https://github.com/gosuda/bitcoin-rs/blob/main/docs/policies/db-migration.md) owns the procedure, and [`RCV-09`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/recovery.md) owns the fresh-replay and schema-refusal rule.

## Next

See what recovery does after a crash: [Sync, recovery, and pruning](sync-and-recovery.md).
