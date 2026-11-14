# Configuration keys

Each setting has a TOML key. Most also have an uppercase `BITCOIN_RS_*` environment name, and some accept a Bitcoin Core `bitcoin.conf` alias. The precedence order, from lowest to highest, is defaults, `--config` TOML, `--bitcoin-conf`, environment, then command-line flags.

## File rules

The `--config` file is strict. An unknown key is an error. The `--bitcoin-conf` file follows the Bitcoin Core file rules: keys without a mapping below are ignored, a line whose key starts with `-` is a parse error (`options in configuration file must be specified without leading -`), and the first `#` starts a comment. `rpcpassword` is the exception: a `#` in that line is refused as ambiguous because the parser cannot tell a comment from part of the password.

Boolean values in `bitcoin.conf` follow Core's `InterpretBool`: an empty value is true, and any other value goes through Core's `LocaleIndependentAtoi`. That parser trims surrounding whitespace, accepts one leading `+` (but answers 0 for `+-`), parses only the numeric prefix of the value, and saturates out-of-range numbers at the 32-bit limits. So `dnsseed=2`, `dnsseed=+1`, `dnsseed=1abc`, and `dnsseed=2147483648` are true, while `dnsseed=0`, `dnsseed=true`, and `dnsseed=--1` are false.

A key of the form `no<key>` negates a key that has a `bitcoin.conf` alias in the tables below, following Core's negation rule. `no<key>=1` (or any value that reads as true) stores the false reading: booleans become false, integer keys become `0`, string keys hold the word `0`, repeatable keys (`uacomment`, `onlynet`) become empty lists, and address, path, and `listen` keys are cleared. `no<key>=0` stores the true reading: booleans become true, integer keys become `1`, string and path keys hold the word `1`, repeatable keys still become empty lists, and an address key then refuses the word `1` as an invalid address, exactly like a literal line. Keys without a `bitcoin.conf` alias keep being ignored, with or without the `no` prefix.

A line, a key, and a value are trimmed with the space, tab, carriage return, and line feed characters only, as in Core; any other leading or trailing whitespace is part of the key or the value.

`bitcoin.conf` sections select a network: `[main]` or `[mainnet]`, `[test]`, `[testnet]`, or `[testnet3]`, `[testnet4]`, `[signet]`, `[regtest]`. The selected section overrides global keys. The network comes from the TOML file, the environment, or the CLI, and the later layer wins.

`listen=0` and `nolisten=1` in `bitcoin.conf` set an empty P2P listen list; `nolisten=0` leaves the default list in place. There is no `includeconf` support.

Environment booleans accept `1`, `true`, `yes`, `on` and `0`, `false`, `no`, `off`. TOML uses native booleans.

## Core keys

### Process and network

| TOML key | Environment | `bitcoin.conf` | Default |
| --- | --- | --- | --- |
| `network` | `BITCOIN_RS_NETWORK` | no | `mainnet` |
| `data_dir` | `BITCOIN_RS_DATA_DIR` | no | `.bitcoin-rs` |
| `persist_mempool` | `BITCOIN_RS_PERSIST_MEMPOOL` | no | `true` |
| `mempool_snapshot_max_mb` | `BITCOIN_RS_MEMPOOL_SNAPSHOT_MAX_MB` | no | `64` |
| `mempool_snapshot_restore_timeout_secs` | `BITCOIN_RS_MEMPOOL_SNAPSHOT_RESTORE_TIMEOUT_SECS` | no | `max(60, max_mb)` |
| `storage_backend` | `BITCOIN_RS_STORAGE_BACKEND` | no | `rocksdb` |
| `dbcache_mb` | `BITCOIN_RS_DBCACHE_MB` | `dbcache` | `450` |
| `prune_target_mb` | `BITCOIN_RS_PRUNE_TARGET_MB` | `prune` | `0` |

`storage_backend` selects the underlying key-value engine. It accepts `rocksdb` (the default, always compiled), `surrealkv` (when compiled with cargo feature `surrealkv`), and `mdbx` (when compiled with cargo feature `mdbx`).

### Peer-to-peer

| TOML key | Environment | `bitcoin.conf` | Default |
| --- | --- | --- | --- |
| `p2p_magic` | `BITCOIN_RS_P2P_MAGIC` | no | network magic |
| `ua_comments` | no | `uacomment` (repeatable) | empty |
| `p2p_listen` | `BITCOIN_RS_P2P_LISTEN` | `listen` (`0` and `nolisten` clear the list) | `0.0.0.0:<p2p port>` |
| `dns_seeds_enabled` | `BITCOIN_RS_DNS_SEEDS_ENABLED` | `dnsseed` | `true`; `false` for `drynet4` |
| `asmap` | `BITCOIN_RS_ASMAP` | no | unset |
| `p2p_noban` | `BITCOIN_RS_P2P_NOBAN` | no | empty |
| `connect` | `BITCOIN_RS_CONNECT` | no | empty; one default on `drynet4` |
| `proxy` | `BITCOIN_RS_PROXY` | `proxy` | unset |
| `onion_proxy` | `BITCOIN_RS_ONION_PROXY` | `onion` | unset |
| `i2p_sam` | `BITCOIN_RS_I2P_SAM` | `i2psam` | unset |
| `tor_control` | `BITCOIN_RS_TOR_CONTROL` | `torcontrol` | unset |
| `tor_cookie` | `BITCOIN_RS_TOR_COOKIE` | no | unset |
| `i2p_accept` | `BITCOIN_RS_I2P_ACCEPT` | `i2pacceptincoming` | `false` |
| `proxy_randomize_credentials` | `BITCOIN_RS_PROXY_RANDOMIZE_CREDENTIALS` | `proxyrandomize` | `true` |
| `overlay_port` | `BITCOIN_RS_OVERLAY_PORT` | no | network P2P port |
| `onlynet` | `BITCOIN_RS_ONLYNET` | `onlynet` | empty (all networks) |
| `fast_sync` | `BITCOIN_RS_FAST_SYNC` | no | `false` |
| `v2_transport` | `BITCOIN_RS_V2_TRANSPORT` | `v2transport` | `true` |
| `p2p_package_relay` | `BITCOIN_RS_P2P_PACKAGE_RELAY` | no | `false` |
| `p2p_stale_tip_relay` | `BITCOIN_RS_P2P_STALE_TIP_RELAY` | no | `false` |
| `p2p_stale_tip_prefers_blocks` | `BITCOIN_RS_P2P_STALE_TIP_PREFERS_BLOCKS` | no | `false` |

`p2p_noban`, `connect`, and `onlynet` take TOML arrays of strings, and their environment form accepts a comma-separated list. `ua_comments` takes one comment per array entry or repeated `uacomment=` line and has no environment form.

### RPC, REST, and features

| TOML key | Environment | `bitcoin.conf` | Default |
| --- | --- | --- | --- |
| `silent_payments` | `BITCOIN_RS_SILENT_PAYMENTS` | no | `false` |
| `compressed_transactions` | `BITCOIN_RS_COMPRESSED_TRANSACTIONS` | no | `false` |
| `rpc_bind` | `BITCOIN_RS_RPC_BIND` | no | `127.0.0.1:<rpc port>` |
| `public_bind` | `BITCOIN_RS_PUBLIC_BIND` | no | unset |
| `rpc_max_connections` | `BITCOIN_RS_RPC_MAX_CONNECTIONS` | no | `128` |
| `public_max_connections` | `BITCOIN_RS_PUBLIC_MAX_CONNECTIONS` | no | `128` |
| `esplora_max_queries` | `BITCOIN_RS_ESPLORA_MAX_QUERIES` | no | `2` |
| `rest` | `BITCOIN_RS_REST` | `rest` | `false` |
| `rpc_user` | `BITCOIN_RS_RPC_USER` | `rpcuser` | unset |
| `rpc_password` | `BITCOIN_RS_RPC_PASSWORD` | `rpcpassword` | unset |
| `rpc_cookie` | `BITCOIN_RS_RPC_COOKIE` | `rpccookiefile` | unset |

### Indexes

| TOML key | Environment | `bitcoin.conf` | Default |
| --- | --- | --- | --- |
| `scripthash_limit` | `BITCOIN_RS_SCRIPTHASH_LIMIT` | `scripthash-limit` | `25000` |
| `txindex` | `BITCOIN_RS_TXINDEX` | `txindex` | `false` |
| `blockfilterindex` | `BITCOIN_RS_BLOCKFILTERINDEX` | `blockfilterindex` | `false` |
| `script_index` | `BITCOIN_RS_SCRIPTINDEX` | no | disabled |
| `index_bundle_import` | `BITCOIN_RS_INDEX_BUNDLE_IMPORT` | no | unset |
| `index_bundle_export` | `BITCOIN_RS_INDEX_BUNDLE_EXPORT` | no | unset |

`script_index` takes `utxo`, `full`, or a boolean. The older boolean spellings still work: `true`, `1`, and `yes` mean `full`; `false`, `0`, and `no` mean disabled.

### Observability, validation, and mining

| TOML key | Environment | `bitcoin.conf` | Default |
| --- | --- | --- | --- |
| `log_level` | `BITCOIN_RS_LOG_LEVEL` | no | `info` |
| `metrics_bind` | `BITCOIN_RS_METRICS_BIND` | no | unset |
| `assume_valid_height` | `BITCOIN_RS_ASSUME_VALID_HEIGHT` | no | `938343` mainnet, `0` elsewhere |
| `validation_mode` | `BITCOIN_RS_VALIDATION_MODE` | no | `assume-valid` |
| `validation_engine` | `BITCOIN_RS_VALIDATION_ENGINE` | no | `native` |
| `mining_payout_address` | `BITCOIN_RS_MINING_PAYOUT_ADDRESS` | no | unset |

`mining_payout_address` is required when `pool` is true. It sets the pool payout script; solo generation takes its address in the RPC call.

### Pool

No pool key has a `bitcoin.conf` alias. Sub-options are refused when `pool` is false.

| TOML key | Environment | Default |
| --- | --- | --- |
| `pool` | `BITCOIN_RS_POOL` | `false` |
| `pool_datadir` | `BITCOIN_RS_POOL_DATADIR` | required |
| `pool_v1_bind` | `BITCOIN_RS_POOL_V1_BIND` | unset |
| `pool_sv2_bind` | `BITCOIN_RS_POOL_SV2_BIND` | unset |
| `pool_sv2_authority_key` | `BITCOIN_RS_POOL_SV2_AUTHORITY_KEY` | unset |
| `pool_allow_non_loopback` | `BITCOIN_RS_POOL_ALLOW_NON_LOOPBACK` | `false` |
| `pool_max_connections` | `BITCOIN_RS_POOL_MAX_CONNECTIONS` | `128` |
| `pool_max_connections_per_ip` | `BITCOIN_RS_POOL_MAX_CONNECTIONS_PER_IP` | `8` |
| `pool_share_difficulty` | `BITCOIN_RS_POOL_SHARE_DIFFICULTY` | required |
| `pool_window_work` | `BITCOIN_RS_POOL_WINDOW_WORK` | required |
| `pool_fee_bps` | `BITCOIN_RS_POOL_FEE_BPS` | `0` |
| `pool_reward_script` | `BITCOIN_RS_POOL_REWARD_SCRIPT` | required |
| `pool_maturity` | `BITCOIN_RS_POOL_MATURITY` | `100` |
| `pool_payout_confirmations` | `BITCOIN_RS_POOL_PAYOUT_CONFIRMATIONS` | `6` |
| `pool_reorg_watch_depth` | `BITCOIN_RS_POOL_REORG_WATCH_DEPTH` | `1000` |
| `pool_min_payout_sat` | `BITCOIN_RS_POOL_MIN_PAYOUT_SAT` | `546` |
| `pool_max_payout_outputs` | `BITCOIN_RS_POOL_MAX_PAYOUT_OUTPUTS` | `2500` |

## Tables without a CLI flag

### `notifications`

ZeroMQ endpoints use a TOML table only. There is no environment form and no `bitcoin.conf` alias:

```toml
[notifications]
[[notifications.zmq]]
endpoint = "tcp://127.0.0.1:55555"
topics = ["hashblock", "hashtx", "rawblock", "rawtx", "sequence"]
hwm = 1000
```

## A complete regtest file

This file starts a regtest node with the same settings as the examples. `$DATA` stands for the data directory you pass to `--data-dir` or the `data_dir` key:

```toml
network = "regtest"
data_dir = "$DATA"
rpc_bind = "127.0.0.1:45869"
p2p_listen = ["127.0.0.1:48471"]
dns_seeds_enabled = false
rest = true
txindex = true
script_index = "full"
log_level = "info"
rpc_user = "book"
rpc_password = "bookpass"
```

The node logged the materialized result, including `v2_transport: true`, `esplora_max_queries: 2`, `scripthash_limit: 25000`, and `persist_mempool: true`. Those values match the defaults above.

For the command-line spelling of the same settings, see [Command-line flags](cli.md). For the pool's operational rules, see [Mining and the native pool](../use/mining-and-pool.md).
