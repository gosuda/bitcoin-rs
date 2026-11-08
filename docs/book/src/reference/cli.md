# Command-line flags

Every flag accepted by `bitcoin-rs` appears in one of the tables below, with the value it takes, its default, and one sentence on what it changes. Defaults are the values the binary materializes when a flag is absent; network-dependent defaults name the network.

Boolean flags come in two forms. Some require an explicit true or false value. Others may be bare, which means `true`, or take `true` or `false`.

## Process and configuration files

| Flag | Value | Default | Purpose |
| --- | --- | --- | --- |
| `--config` | TOML path | unset | Reads a strict TOML layer first; unknown keys are refused. |
| `--bitcoin-conf` | path | unset | Reads Core-style `key=value` lines after the TOML layer; the network section is selected by `--network`. |
| `--corpus` | path | unset | Replays a Core-framed corpus archive offline; requires `--manifest` and `--state`. |
| `--manifest` | path | unset | Pins the corpus archive and stop height. |
| `--state` | directory | unset | Holds certification state for the offline import. |
| `--version` | none | none | Prints `bitcoin-rs daemon version <version>` and exits 0 before any config or data-directory work. |
| `-h`, `--help` | none | none | Prints the flag list and exits. |

## Network and data

| Flag | Value | Default | Purpose |
| --- | --- | --- | --- |
| `--network` | `mainnet`, `main`, `bitcoin`, `testnet3`, `test`, `testnet`, `testnet4`, `signet`, `regtest`, `drynet4` | `mainnet` | Selects chain parameters, default ports, and magic. |
| `--data-dir` | path | `.bitcoin-rs` | Holds chainstate, indexes, cookie, and mempool snapshot. |
| `--persist-mempool` | `true` or `false` | `true` | Saves the pool on clean shutdown and restores it at startup. |
| `--mempool-snapshot-max-mb` | MiB | `64` | Caps the snapshot file and restore work. |
| `--mempool-snapshot-restore-timeout-secs` | seconds | `max(60, max-mb)` | Deadline for restoring and revalidating the snapshot. |

## Storage

| Flag | Value | Default | Purpose |
| --- | --- | --- | --- |
| `--storage-backend` | `rocksdb`, `surrealkv`, `mdbx` | `rocksdb` | Selects the storage backend: `rocksdb` (default, always compiled), `surrealkv` (requires cargo feature `surrealkv`), and `mdbx` (requires cargo feature `mdbx`). Reopening a data directory created by a different engine refuses startup with `<namespace> was created by <found>; start with --storage-backend <found> or convert with bitcoin-rs-storage-convert`. `fjall` and `redb` fail with `unsupported storage backend <value>`. |
| `--dbcache-mb` | MiB | `450` | Splits the storage cache between chainstate and index storage. |
| `--prune-target-mb` | MiB | `0` | Prunes block history to the target; `0` keeps everything. Indexes refuse pruning. |

## Peer-to-peer and privacy

| Flag | Value | Default | Purpose |
| --- | --- | --- | --- |
| `--uacomment` | text | empty | Adds a comment to the advertised subversion as `/bitcoin-rs:<version>(<comment>; ...)/`; unsafe characters or a composed subversion over 256 bytes fail startup. |
| `--p2p-magic` | 8 hex digits | network magic | Overrides the wire magic; allowed only on mainnet with `--connect` and DNS seeds off. |
| `--p2p-listen` | `addr[,addr]` | `0.0.0.0:<p2p port>` | Sets inbound P2P listen addresses. |
| `--dns-seeds-enabled` | `true` or `false` | `true` | Resolves DNS seeds; `drynet4` starts false. |
| `--asmap` | path | unset | Loads an AS map for address bucketing. |
| `--p2p-noban` | subnet[,subnet] | empty | Exempts subnets from banning. |
| `--connect` | `host:port[,host:port]` | empty | Adds explicit outbound peers; `drynet4` has one default. |
| `--proxy` | socket address | unset | Routes IPv4 and IPv6 peers through a SOCKS proxy. |
| `--onion-proxy` | socket address | unset | Routes onion peers through a separate proxy. |
| `--i2p-sam` | socket address | unset | Connects to an I2P SAM bridge. |
| `--tor-control` | socket address | unset | Sets the Tor control endpoint. |
| `--tor-cookie` | path | unset | Sets the Tor control cookie file. |
| `--i2p-accept` | `[bool]` | `false` | Accepts inbound I2P connections; needs `--i2p-sam`. |
| `--proxy-randomize-credentials` | `[bool]` | `true` | Randomizes proxy credentials per connection. |
| `--overlay-port` | port | network P2P port | Advertises the shared Bitcoin service port. |
| `--onlynet` | `ipv4,ipv6,onion,i2p` | empty (all) | Restricts outbound peers to the named networks. |
| `--fast-sync` | `[bool]` | `false` | Enables the fast-sync path. |
| `--v2transport` | `[bool]` | `true` | Negotiates BIP324 v2 transport; `--v2transport=false` keeps v1. |
| `--p2p-package-relay` | `[bool]` | `false` | Offers package relay. |
| `--p2p-stale-tip-relay` | `[bool]` | `false` | Offers stale-tip relay. |
| `--p2p-stale-tip-prefers-blocks` | `[bool]` | `false` | Prefers block announcements for stale tips; requires stale-tip relay. |

## RPC, public listener, and features

| Flag | Value | Default | Purpose |
| --- | --- | --- | --- |
| `--rpc-bind` | socket address | `127.0.0.1:<rpc port>` | Binds the management JSON-RPC listener. |
| `--public-bind` | socket address | unset | Splits REST and Esplora onto a second listener. |
| `--rpc-max-connections` | count | `128` | Caps management listener connections. |
| `--public-max-connections` | count | `128` | Caps public listener connections. |
| `--esplora-max-queries` | count | `2` | Caps concurrent expensive Esplora reads. |
| `--rest` | `true` or `false` | `false` | Enables unauthenticated `/rest/*` routes. |
| `--rpc-user` | text | unset | Sets the basic-auth user; pairs with `--rpc-password`. |
| `--rpc-password` | text | unset | Sets the basic-auth password; the legacy default `bitcoin-rs` is refused. |
| `--rpc-cookie` | path | unset | Reads basic-auth credentials from a `user:password` file. |
| `--silent-payments` | `[bool]` | `false` | Enables the experimental BIP352 `getblocktweaks` extension when compiled. |
| `--compressed-transactions` | `[bool]` | `false` | Enables the BIP337 compress and decompress RPCs. |

## Indexes

| Flag | Value | Default | Purpose |
| --- | --- | --- | --- |
| `--scripthash-limit` | count | `25000` | Caps candidate positions scanned per script query. |
| `--txindex` | `true` or `false` | `false` | Enables transaction-id lookup and the Core `txindex` row. |
| `--blockfilterindex` | `[bool]` | `false` | Enables basic BIP158 compact filters. |
| `--scriptindex` | `utxo`, `full`, or bool | disabled | Enables live script queries; `full` adds history. Alias: `--script-index`. Bare means `full`. |
| `--index-bundle-import` | directory | unset | Imports a transaction-lookup bundle once; requires `--txindex`. |
| `--index-bundle-export` | directory | unset | Exports a transaction-lookup bundle once; requires `--txindex`. |

## Observability and validation

| Flag | Value | Default | Purpose |
| --- | --- | --- | --- |
| `--log-level` | level | `info` | Sets the tracing filter. |
| `--metrics-bind` | socket address | unset | Exposes the metrics listener. |
| `--assume-valid-height` | height | `938343` on mainnet, `0` elsewhere | Skips script validation below the height. |
| `--validation-mode` | `full`, `assume-valid` | `assume-valid` | Chooses full or assume-valid validation. |
| `--validation-engine` | `native`, `kernel` | `native` | Selects the engine; `kernel` needs a build with the `kernel` feature, and the default binary is kernel-free. |

## Mining

| Flag | Value | Default | Purpose |
| --- | --- | --- | --- |
| `--mining-payout-address` | address | unset | Sets the pool payout script; required with `--pool`. Generated blocks take their address from the call. |

## Native pool

| Flag | Value | Default | Purpose |
| --- | --- | --- | --- |
| `--pool` | `[bool]` | `false` | Enables the native pool; needs a `pool` build. |
| `--pool-datadir` | path | unset | Dedicated ledger directory; required when the pool is on. |
| `--pool-v1-bind` | socket address | unset | Stratum V1 mining listener. |
| `--pool-sv2-bind` | socket address | unset | Stratum V2 mining listener; pairs with the authority key. |
| `--pool-sv2-authority-key` | path | unset | BIP340 authority keypair for SV2 Noise. |
| `--pool-allow-non-loopback` | `[bool]` | `false` | Permits a non-loopback mining bind. |
| `--pool-max-connections` | count | `128` | Caps live SV1 plus SV2 connections. |
| `--pool-max-connections-per-ip` | count | `8` | Caps live connections per IP. |
| `--pool-share-difficulty` | decimal string | required | Fixes share difficulty exactly. |
| `--pool-window-work` | work units | required | Sets the PPLNS window in accepted-share work. |
| `--pool-fee-bps` | basis points | `0` | Takes a pool fee of at most 10,000 basis points. |
| `--pool-reward-script` | scriptPubKey hex | required | Sets the only coinbase script the ledger credits. |
| `--pool-maturity` | count | `100` | Sets the coinbase maturity threshold, at least 100. |
| `--pool-payout-confirmations` | count | `6` | Sets the confirmation depth for a payout batch. |
| `--pool-reorg-watch-depth` | count | `1000` | Sets the reorg watch horizon. |
| `--pool-min-payout-sat` | satoshis | `546` | Sets the minimum payout batch value. |
| `--pool-max-payout-outputs` | count | `2500` | Caps outputs in one payout batch. |

## Not on the command line

One configuration surface has no CLI flag:

- `notifications` is a TOML table holding ZeroMQ endpoints. See [ZeroMQ notifications](../use/zmq.md).

The TOML and environment forms of every key are in [Configuration keys](config-keys.md). A script that extracts every flag name from `bitcoin-rs --help` and compares it with the tables above reports zero missing and zero extra flags.
