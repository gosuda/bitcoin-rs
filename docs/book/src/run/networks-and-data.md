# Networks and the data directory

The node writes all persistent state under one data directory. Select the network with `--network`; the directory defaults to `.bitcoin-rs` in the current working directory. Transcripts and layouts below write `$DATA` for that directory.

## Networks and default ports

| Network | P2P port | RPC port |
| --- | --- | --- |
| `mainnet` | 8333 | 8332 |
| `testnet3` | 18333 | 18332 |
| `testnet4` | 48333 | 48332 |
| `signet` | 38333 | 38332 |
| `regtest` | 18444 | 18443 |

`--network` also accepts `main` and `bitcoin` for mainnet, `test` and `testnet` for testnet3, and `drynet4`. `drynet4` is a test selection that uses mainnet consensus rules, its own P2P magic, DNS seeds off, and one fixed peer at `drynet4.drivechain.dev:8533`.

The data directory is not partitioned by network. Two networks pointed at the same directory will not open each other's chainstate; startup validates the root's network pin in the [architecture contract](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/architecture.md). Give each network its own directory.

## What the node creates

A fresh regtest node on an empty directory produces this layout at height zero:

```text
$DATA
├── .cookie
├── .lock
├── .process-epoch.lock
├── CURRENT_SCHEMA
├── blocks/
│   └── blk00000.dat
├── chainstate/
│   ├── CURRENT
│   ├── LOCK
│   ├── LOG
│   ├── MANIFEST-*
│   ├── OPTIONS-*
│   └── ...
└── process-epoch
```

A clean shutdown adds the checkpoint and the owner-local files:

```text
├── applied-tip-witness.json
├── chainstate-checkpoints/
│   └── CURRENT
├── fee-estimator-history.dat
└── mempool-snapshot.dat
```

`CURRENT_SCHEMA` holds the datadir format epoch. For this commit the file contains `4` followed by a newline. It is written and synced before any authoritative store opens.

`.lock` is the data-directory lock. `process-epoch` is a monotonically increasing number written at startup, and `.process-epoch.lock` guards it. A corrupt `process-epoch` refuses startup instead of reusing an epoch.

`chainstate/` is the authoritative chainstate store. With the default `rocksdb` backend it holds native RocksDB files. The exact file set varies with the RocksDB version; `CURRENT` marks the set. Coins live in the `coins` keyspace (`ColumnFamily::Coins`). `blocks/` holds block body files with `BRSB` framing.

`.cookie` is generated with mode `0600` and rotated before each listener starts. `applied-tip-witness.json` records the published applied tip. `chainstate-checkpoints/` holds published checkpoints, and `CURRENT` names the active generation.

When you enable onion or I2P inbound service, the node also writes keys under `overlay-<P2P-magic>/`, such as `onion.key` and `i2p.key`. Those files are create-once; an unreadable or damaged key fails startup rather than being regenerated. Back them up if you need to keep inbound addresses.

## What you may delete

Stop the node first. Then:

`.cookie` is safe to delete. The next start generates a new one.

`fee-estimator-history.dat` is owner-local. Deleting it discards fee estimation history; the estimator degrades to insufficient data and does not fabricate a rate.

`mempool-snapshot.dat` is owner-local. Deleting it starts the next run with an empty pool. It has no effect on chainstate, and the node logs `no mempool snapshot; starting with an empty pool` when it is absent.

`chainstate/`, `blocks/`, `chainstate-checkpoints/`, `CURRENT_SCHEMA`, and `process-epoch` are not independent caches. Removing one of them can leave a durable head that references missing bytes. The node then fails closed with `incompatible_schema` or a recovery error; it does not rebuild, reset, or repair in place.

> **Warning** Do not delete `chainstate` or `blocks` to clear a startup error. Read the error, check `CURRENT_SCHEMA`, and follow the [datadir format policy](https://github.com/gosuda/bitcoin-rs/blob/main/docs/policies/db-migration.md). A full reset means moving the whole data directory aside, not deleting parts of it.

## Full reset

To start from nothing, stop the node and move the directory:

```sh
$ mv $DATA $DATA.old
```

Start with the same `--data-dir` path. An empty directory is created and initialized at the current schema. Keep the old directory until you no longer need its history; the node never deletes operator data on its own.

## Next

Choose a backend and size the cache: [Storage and memory](storage.md).
