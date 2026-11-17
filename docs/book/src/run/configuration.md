# Configuration

Configuration resolves in five layers, low to high. A later layer overrides only the fields it supplies.

1. Built-in defaults
2. `--config` TOML file
3. `--bitcoin-conf` Core-style file
4. `BITCOIN_RS_*` environment variables
5. CLI flags

There is no command that writes a config file. The node prints its resolved `NodeConfig` in the `bitcoin-rs node booting` log line, and that line is the check that your layers produced what you meant.

## A worked override

Start with a TOML file that sets one storage value:

```toml
# layer.toml
network = "regtest"
dns_seeds_enabled = false
storage_backend = "rocksdb"
dbcache_mb = 100
```

Run with the file, then add each layer in turn. `$DATA` stands for the data directory you pass to `--data-dir`. The snippet filters the boot line to the field under test.

```sh
$ timeout 5 ./target/release/bitcoin-rs --config layer.toml \
  --data-dir $DATA \
  --p2p-listen 127.0.0.1:0 --rpc-bind 127.0.0.1:0 2>&1 | grep -o 'dbcache_mb: [0-9]*'
dbcache_mb: 100
```

An environment variable wins over the TOML file:

```sh
$ BITCOIN_RS_DBCACHE_MB=200 timeout 5 ./target/release/bitcoin-rs --config layer.toml \
  --data-dir $DATA \
  --p2p-listen 127.0.0.1:0 --rpc-bind 127.0.0.1:0 2>&1 | grep -o 'dbcache_mb: [0-9]*'
dbcache_mb: 200
```

A CLI flag wins over both:

```sh
$ BITCOIN_RS_DBCACHE_MB=200 timeout 5 ./target/release/bitcoin-rs --config layer.toml \
  --data-dir $DATA --dbcache-mb 300 \
  --p2p-listen 127.0.0.1:0 --rpc-bind 127.0.0.1:0 2>&1 | grep -o 'dbcache_mb: [0-9]*'
dbcache_mb: 300
```

The Core-style file sits between TOML and the environment. A `bitcoin.conf` containing `dbcache=400` overrides `dbcache_mb = 100` from the TOML file:

```sh
$ timeout 5 ./target/release/bitcoin-rs --config layer.toml --bitcoin-conf bitcoin.conf \
  --data-dir $DATA \
  --p2p-listen 127.0.0.1:0 --rpc-bind 127.0.0.1:0 2>&1 | grep -o 'dbcache_mb: [0-9]*'
dbcache_mb: 400
```

Add `BITCOIN_RS_DBCACHE_MB=200` and the environment wins again. Environment variables override the Core-style file, and CLI flags override both.

## TOML keys are flat

`--config` reads a flat table of keys such as `network`, `data_dir`, `storage_backend`, `dbcache_mb`, `prune_target_mb`, `p2p_listen`, and `rpc_bind`. One key takes structured values: `notifications` holds the `[[notifications.zmq]]` endpoint groups. Unknown keys fail startup; the TOML layer rejects them rather than ignoring typos.

The accepted list for this commit is in the option table in [`crates/node/src/options.rs`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/node/src/options.rs), and the [configuration keys reference](../reference/config-keys.md) restates it for readers.

## bitcoin.conf is a small Core subset

`--bitcoin-conf` reads Core-style `key=value` lines and network sections. It understands these keys and nothing else:

`dbcache`, `prune`, `dnsseed`, `proxy`, `onion`, `i2psam`, `torcontrol`, `i2pacceptincoming`, `proxyrandomize`, `onlynet`, `v2transport`, `rest`, `rpcuser`, `rpcpassword`, `rpccookiefile`, `scripthash-limit`, `txindex`, `blockfilterindex`.

`listen=0` is the one special form: it clears the P2P listen list. Sections such as `[regtest]` apply only when the selected network matches.

Environment variables follow the TOML key with an uppercase `BITCOIN_RS_` prefix, for example `BITCOIN_RS_DBCACHE_MB`. An unrecognized `BITCOIN_RS_*` variable is skipped. An unrecognized CLI flag is a parse error.

> **Warning** Do not pass a Core `bitcoin.conf` to `--config`. The TOML reader rejects Core's key names and file shape. Use `--bitcoin-conf` for that file.

## Values that are checked together

Layers merge first; validation runs afterwards. Network-dependent checks therefore see the final value, not the layer that supplied it. A mining payout address is decoded and checked against the selected network after the merge.

An empty data directory string fails validation:

```sh
$ BITCOIN_RS_DATA_DIR= ./target/release/bitcoin-rs --network regtest
Error: data-dir must not be empty
```

The process exits with status 1. The rule exists so a missing value cannot silently select `.bitcoin-rs`. An unset `--data-dir` still uses `.bitcoin-rs` by default.

Authentication fields also interact. Supplying `--rpc-cookie` clears `rpc-user` and `rpc-password`; supplying either of those clears `rpc-cookie`. The last layer that sets one family wins.

Other checks that reject at startup include a non-loopback RPC bind without explicit credentials, the legacy password `bitcoin-rs`, pruning combined with an index, a storage backend that is not compiled in, and a validation engine this build does not support. Each prints `Error: <message>` on stderr, with the error's cause appended after a colon when there is one, and exits 1.

## Check what you configured

Read the resolved dump instead of guessing:

```sh
$ timeout 5 ./target/release/bitcoin-rs --config layer.toml --network signet \
  --data-dir $DATA \
  --p2p-listen 127.0.0.1:0 --rpc-bind 127.0.0.1:0 2>&1 | grep -o 'NodeConfig { network: [A-Za-z0-9]*'
NodeConfig { network: Signet
```

The dump names every resolved field, including defaults you did not set. Compare it with the layer you expected before you file a bug against a flag.

## Next

Understand what the node writes: [Networks and the data directory](networks-and-data.md).
