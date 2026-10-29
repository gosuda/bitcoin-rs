# Getting started

## Prerequisites

The repository development toolchain is `stable`; the workspace MSRV is Rust `1.99.0`. See [policies/source-compatibility.md](policies/source-compatibility.md).

The default build compiles bundled ZeroMQ from source, so it needs C and C++ compilers plus `ar` (`build-essential` on Debian/Ubuntu); no system ZeroMQ headers, `pkg-config`, `cmake`, or `libsodium` are needed. A C compiler stays required without the `zmq` feature (vendored secp256k1 and mimalloc).

The default binary is kernel-free. Building the optional `kernel` lane also needs CMake and Boost on Debian/Ubuntu:

```sh
sudo apt-get install -y cmake libboost-dev
```

## Build

Use a lane deliberately:

| Lane | Command | Purpose |
| --- | --- | --- |
| Default | `cargo build --locked --release -p bitcoin-rs` | Normal binary: `fjall`, `redb`, `zmq`; no kernel |
| Minimal native | `cargo build --locked --release -p bitcoin-rs --no-default-features --features fjall` | One storage backend, optional extensions off |
| Kernel | `CARGO_TARGET_DIR=target/oracle cargo build --locked --release -p bitcoin-rs --features kernel` | Optional `bitcoinkernel` validation/oracle lane |

Keep the kernel lane in a separate `CARGO_TARGET_DIR` when proving a kernel-free build. BIP324 v2 transport is on by default, as in Bitcoin Core; `--v2transport=false` keeps every connection on v1. See [bip-support.md](bip-support.md).

## Configuration

Precedence, low to high:

1. defaults
2. `--config` TOML
3. `--bitcoin-conf`
4. `BITCOIN_RS_*` environment variables
5. CLI flags

A later layer overrides only fields it supplies. Network-dependent validation, including mining payout addresses, runs after merge. Runtime test controls are not public configuration.

Common network names are `mainnet`, `signet`, `testnet4`, and `regtest`; retained aliases are documented by the compatibility contracts.

### Tor and IVNP I2P networking

Overlay networking is opt-in. With no overlay settings, ordinary IPv4/IPv6
connections and DNS seeding retain their defaults. The node does not launch
Tor or an I2P router. The [P2P compatibility policy](policies/p2p-compatibility.md#overlay-transports)
describes routing, persistence, and the evidence boundary.

| CLI option | TOML key | Default and behavior |
| --- | --- | --- |
| `--proxy IP:port` | `proxy` | Unset. SOCKS5 for IP destinations; does not enable onion routing. |
| `--onion-proxy IP:port` | `onion_proxy` | Unset. SOCKS5 for Tor v3 destinations, sent as domain names. |
| `--proxy-randomize-credentials=false` | `proxy_randomize_credentials` | `true`. Require RFC1929 with fresh credentials per connection; `false` selects no-auth SOCKS5. |
| `--onlynet onion,i2p` | `onlynet = ["onion", "i2p"]` | Unset permits IP and configured overlays. Explicit lists restrict manual/automatic outbound paths, listeners, and reconnects. Values: `ipv4`, `ipv6`, `onion`, `i2p`. |
| `--i2p-sam IP:port` | `i2p_sam` | Unset. SAM v3.1–3.3 on an operator-managed `ivnpd`; its usual bridge is `127.0.0.1:7656`. |
| `--i2p-accept` | `i2p_accept` | `false`. Persistent I2P application destination and `STREAM ACCEPT`; requires `i2p_sam`. |
| `--tor-control IP:port` | `tor_control` | Unset. Enables a persistent v3 onion service; requires `onion_proxy`. |
| `--tor-cookie PATH` | `tor_cookie` | Unset selects Tor control NULL authentication; set this to external Tor's 32-byte authentication cookie file and enable SAFECOOKIE on its control endpoint. |
| `--overlay-port PORT` | `overlay_port` | The selected Bitcoin network's default P2P port. Public service port, independent of local forwarding sockets. |

Each option also has a `BITCOIN_RS_` environment spelling using the uppercase
TOML key (for example `BITCOIN_RS_I2P_SAM`). `BITCOIN_RS_ONLYNET` uses a comma
list. These new options are available through CLI, environment and TOML;
they do not add `bitcoin.conf` aliases.

All proxy, SAM and control endpoints must be numeric loopback sockets with
nonzero ports. Proxy/router failure never selects a direct connection.
DNS seeds are suppressed when `proxy` is configured or both IP families are
excluded. Ordinary hostname peers are rejected with a general proxy; use
numeric IP endpoints there. Onion destinations never use local DNS.
Human-readable `.i2p` names from `--connect` or `addnode` use IVNP's SAM naming
resolver when available; Bitcoin peer identity is the resulting Destination
hash. Use canonical `*.b32.i2p:port` addresses for deterministic removal.

For Tor-only outbound operation, start external Tor with a SOCKS port and run:

```sh
bitcoin-rs --onion-proxy 127.0.0.1:9050 --onlynet onion \
  --connect VALID_V3_SERVICE.onion:8333
```

Use a real v3 service address in place of the placeholder. To add an inbound
onion service, enable external Tor's cookie-authenticated control port and
add `--tor-control 127.0.0.1:9051 --tor-cookie /path/to/control_auth_cookie`.
Tor forwards to a dedicated, unprivileged local listener. Accepted circuits
have opaque `tor-inbound-N:0` connection handles because Tor does not reveal
the remote peer's onion address; they receive no localhost policy exemptions.

Build IVNP using the revision owned by
[`scripts/overlay-interop.py`](../scripts/overlay-interop.py), then run its daemon:

```sh
git clone https://github.com/gosuda/IVNP.git
git -C IVNP checkout "$(python3 scripts/overlay-interop.py --ivnp-revision)"
(cd IVNP && go build -o ivnpd ./cmd/ivnpd)
./IVNP/ivnpd -config /path/to/ivnp.conf
bitcoin-rs --i2p-sam 127.0.0.1:7656 --i2p-accept --onlynet i2p \
  --connect PEER.b32.i2p:8333
```

The pinned IVNP revision requires Go 1.27 or newer. IVNP owns its router
keys, tunnels and router data directory. bitcoin-rs owns application keys in
`<data-dir>/overlay-<P2P-magic>/i2p.key` and `onion.key`, with create-once
publication, checksums and private Unix permissions. Back up those files to
retain inbound addresses. An existing unreadable/damaged key fails startup;
it is never silently regenerated. SAM control loss invalidates its stream
epoch and reconnects with backoff capped at 60 seconds, reusing a stable key
when inbound I2P is enabled. Persistently added overlay peers use the existing
outbound drain for bounded retries.

`getpeerinfo` reports logical network identities and separate local socket
bindings. `getnetworkinfo` reports configured routes, effective restrictions,
live reachability observations and active inbound service addresses. A live
control service is not evidence of end-to-end Bitcoin interoperability, and
fresh SOCKS credentials alone do not establish anonymity. The manually run
[overlay interoperability workflow](../.github/workflows/overlay-interop.yml)
records external-backend Bitcoin exchange and restart evidence separately
from deterministic local protocol fixtures.

## Storage

`fjall` is the default backend; `redb` is also compiled into the default binary.

```sh
./target/release/bitcoin-rs --storage-backend redb
```

or:

```sh
export BITCOIN_RS_STORAGE_BACKEND=fjall
```

RocksDB is a non-default backend used as a shipped alternative and comparison engine.

## Mempool persistence

Mempool persistence is on by default. Clean shutdown saves eligible mempool transactions to
`mempool-snapshot.dat` in the node data directory. Startup rechecks those
candidates against recovered Chainstate and current policy before serving
requests. Admission ages and operator fee deltas are retained; membership,
derived fees and dependencies are recomputed. Startup logs distinguish no
file, full/partial restore and a rejected file.

To start with a fresh pool while preserving the snapshot, set
`--persist-mempool=false`, `BITCOIN_RS_PERSIST_MEMPOOL=false`, or
`persist_mempool = false` in TOML. This disables saving as well. A corrupt,
unknown-version or wrong-network ordinary snapshot is preserved at startup
and moved intact into a unique `mempool-snapshot-rejected-*` directory when
the next clean shutdown publishes a fresh snapshot. Snapshots are bounded
by a byte budget, defaulting to 64 MiB. Raise it with
`--mempool-snapshot-max-mb=256`, `BITCOIN_RS_MEMPOOL_SNAPSHOT_MAX_MB=256`, or
TOML `mempool_snapshot_max_mb = 256`. There is no separate 100,000-transaction
cap. Choose enough space for serialized transactions and metadata to preserve
the entire live pool; the same budget applies on read. Raising it also raises
the possible memory and I/O cost. Larger pools save complete connected
families until the first family does not fit and log saved/omitted counts; all operator fee deltas
are retained, or saving fails if those overlays alone exceed the bound.
Restore excludes candidates older than fourteen days and runs within a cooperative
timeout, defaulting to at least 60 seconds and scaling dynamically with the configured byte budget
(`max(60, mempool_snapshot_max_mb)`). Raise it with `--mempool-snapshot-restore-timeout-secs=180`,
`BITCOIN_RS_MEMPOOL_SNAPSHOT_RESTORE_TIMEOUT_SECS=180`, or TOML
`mempool_snapshot_restore_timeout_secs = 180`. Multi-generational CPFP packages (e.g.
grandparent, parent, child) are restored atomically in topological order within package
standardness limits. Candidate records persist precomputed BIP16/BIP141 SigOp costs
(version 2 format), validated upfront against standardness limits before script execution.
Note that mempool persistence is an operational optimization for clean shutdowns;
abrupt termination (power loss, crash, kill) does not record a snapshot.
Locally submitted transactions awaiting initial broadcast retain that status
across restart if re-admitted. The existing P2P relay worker retries them in
bounded batches, including after absent peers or queue saturation. A successful
getdata body response completes initial broadcast; `getmempoolentry.unbroadcast`
and `getmempoolinfo.unbroadcastcount` report pending status. Other restored
transactions are not automatically announced.
Power-loss preservation and Core `savemempool`/`importmempool` compatibility
are not provided by this initial implementation.

## Start the node

```sh
./target/release/bitcoin-rs --data-dir .bitcoin-rs
```

Important defaults:

| Setting | Default |
| --- | --- |
| network | `mainnet` |
| data dir | `.bitcoin-rs` |
| storage backend | `fjall` |
| RPC bind | `127.0.0.1:8332` on mainnet |
| REST | off |
| RPC authentication | Fresh `.cookie` in the data directory (mode `0600` on Unix) |
| dbcache | 450 MiB |
| pruning | off |
| mempool persistence | on |
| txindex | off |
| scriptindex | off |
| fast sync | off |
| metrics listener | off |
| mining payout | unset |

RPC binds to loopback by default. A non-loopback RPC bind requires an
explicit nonempty password (`--rpc-password` or `BITCOIN_RS_RPC_PASSWORD`)
or an operator-supplied `--rpc-cookie` file. The generated cookie is
rotated before each listener starts and cannot be used for a non-loopback
bind without an explicit cookie-file configuration. The legacy public
password `bitcoin-rs` is rejected as a Basic-auth password on every bind;
an operator-supplied cookie file is used as written, so choose its secret
yourself.

The Docker image also keeps RPC on loopback. To serve RPC outside the
container, explicitly set `BITCOIN_RS_RPC_BIND=0.0.0.0:8332` together
with operator-specific credentials. Publish the port only to trusted
clients; Basic auth is not encrypted without a TLS-terminating proxy.

`--txindex` is the explicit Core-compatible txindex promise. `--scriptindex=utxo` enables the live script view; `--scriptindex=full` also enables confirmed script history. `--rest=true` enables the unauthenticated Core REST routes on the RPC listener.

`--index-bundle-export <dir>` saves the `--txindex` lookup data to a bundle directory, and `--index-bundle-import <dir>` loads a bundle into a `--txindex` that has not started building. The environment variables are `BITCOIN_RS_INDEX_BUNDLE_EXPORT` and `BITCOIN_RS_INDEX_BUNDLE_IMPORT`, the TOML keys are `index_bundle_export` and `index_bundle_import`, and `bitcoin.conf` cannot set them. Both need `--txindex`, and you cannot use both in one run. Each is a one-shot request that runs when the index opens, so remove the setting after the run. A bundle holds only the lookup data, not script-index or block-filter data. The rules, including how an import is checked, are in the [indexing contract](contracts/indexing.md#idx-11-portable-index-bundle).

The optional `silent-payments` build feature plus `--silent-payments` enables
the authenticated, experimental `getblocktweaks` RPC. It needs retained certified
block inputs rather than txindex; see [Silent Payments usage and limits](silent-payments.md).

`--fast-sync` (also `BITCOIN_RS_FAST_SYNC` or `fast_sync` in TOML) relaxes the block-download policy: the node targets 32 full-relay outbound peers instead of 8 (its two block-relay-only slots are unchanged), fans block requests out as soon as two eligible outbound peers are connected instead of eight, and divides the 256-block download window across the eligible peers with a floor of 8 blocks per peer instead of 16 (two peers get 128 each; the 8-block floor is reached at 32 peers). Consensus validation is unchanged. The mode is opt-in and its throughput has not been measured against the default.

## Check progress

```sh
curl -s --user "$(cat .bitcoin-rs/.cookie)" \
  -H 'content-type: application/json' \
  -d '{"jsonrpc":"1.0","id":"1","method":"getblockchaininfo","params":[]}' \
  http://127.0.0.1:8332/
```

For the tip hash only, use `getbestblockhash` with the same empty parameter list.

[rpc-reference.md](rpc-reference.md) is generated from the RPC registry and names each surface's honest state: `Supported`, `Deviation`, `Implemented (unverified)`, `Extension`, `Disabled`, or `Unimplemented`. The node has no in-tree wallet or private-key custody; key-free descriptor/PSBT helpers remain available for external signers.

## Capability state

Index-backed queries expose the owner's capability state rather than treating unavailable data as empty. [contracts/indexing.md](contracts/indexing.md) owns the state vocabulary, readiness conditions, and exact query gating.

## Public consumers

### Esplora

Public Esplora routes live under `/api`. Script/address routes require the applicable script-index capability. `/esplora` is the versioned backend superset; `/api/v1` belongs to the external mempool application, not this node.

Example regtest startup:

```sh
./target/release/bitcoin-rs \
  --network regtest \
  --p2p-listen 127.0.0.1:18444 \
  --dns-seeds-enabled=false \
  --scriptindex \
  --data-dir .bitcoin-rs-regtest \
  --rpc-bind 127.0.0.1:18443
```

The wallet-facing contract is [contracts/wallet-facing.md](contracts/wallet-facing.md).

To keep public connections from using management RPC capacity, add
`--public-bind 0.0.0.0:8080`. In this opt-in mode `/api`, `/esplora`, and
REST (when enabled) move to the public port; `--rpc-bind` serves authenticated
JSON-RPC only. Keep the management port on loopback or a trusted network.
The public port preserves both existing Esplora namespaces, including backend
helpers and transaction broadcast; choose exposure accordingly. A public port
does not accept JSON-RPC, even with valid credentials.

`--rpc-max-connections` and `--public-max-connections` each default to 128
and must be positive. The bounds include slow/incomplete requests and idle
keep-alives, with the existing per-source reservation and head/body/idle
timeouts. Separation protects connection capacity; CPU, process descriptor
limits, storage and locks remain shared. Without `--public-bind`, the existing
combined listener and routes remain the default.

These options also resolve through TOML (`public_bind`, `rpc_max_connections`,
`public_max_connections`) and environment variables (`BITCOIN_RS_PUBLIC_BIND`,
`BITCOIN_RS_RPC_MAX_CONNECTIONS`, `BITCOIN_RS_PUBLIC_MAX_CONNECTIONS`), using
the normal file < environment < CLI precedence. Both listeners use the same
chain, mempool, indexes and broadcast gateway.

A Compose example runs the upstream mempool explorer against these endpoints: [btc-mempool-explorer](../tools/btc-mempool-explorer/README.md).

### REST

`--rest=true` (or `rest=1` in `bitcoin.conf`) serves Core-compatible REST without
authentication on the combined `--rpc-bind` listener by default. With
`--public-bind`, REST moves to that public listener and the RPC port serves
management JSON-RPC only. The CLI option takes an explicit boolean; bare
`--rest` is not the enablement syntax. See [rest-interface.md](rest-interface.md).

### ZMQ

ZMQ endpoint groups are configured with `[[notifications.zmq]]` (`endpoint`, `topics`, optional `hwm`). `getzmqnotifications` reports the live configuration. `bitcoin_rs_rpc::zmq` owns topic framing and transport compatibility.

## Datadir compatibility

Follow [policies/db-migration.md](policies/db-migration.md) for authoritative and owner-local format changes. Never treat a schema mismatch as permission to rewrite or delete an operator datadir implicitly.

The durable-root recovery model and its evidence status are owned by [contracts/recovery.md](contracts/recovery.md).

## Measure storage

Storage snapshots are collected by a separate Linux-only tool after stopping
the node:

```sh
cargo run --locked -p bitcoin-rs-storage-footprint -- .bitcoin-rs \
  > ../bitcoin-rs-footprint.json
```

The tool reads filesystem metadata only; it does not open or initialize a DB.
A report must be written outside the measured directory.
A snapshot is a lower bound on peak usage, not a storage-budget verdict.
See [contracts/storage-footprint.md](contracts/storage-footprint.md).

## Validation mode

`--validation-mode` (also `BITCOIN_RS_VALIDATION_MODE` or `validation_mode` in TOML) selects which historical script verification the apply path may skip. Non-script consensus checks always run.

- `assume-valid` (default): Bitcoin Core `-assumevalid` semantics. Scripts are skipped through `--assume-valid-height` only while the active chain contains the pinned network anchor.
- `full`: every script executes; `--assume-valid-height` is ignored.
- `fast`: scripts are skipped for every block that lies on the best header chain strictly below its tip, so only the block at the tip executes scripts while catching up. Blocks on competing branches always run scripts. This trusts the most-work header chain and is independent of `--fast-sync`.

```sh
./target/release/bitcoin-rs --data-dir .bitcoin-rs --validation-mode full
```

## Validation engine

`--validation-engine` (also `BITCOIN_RS_VALIDATION_ENGINE` or `validation_engine` in TOML) selects which script-verification engine validation runs on. The setting is resolved once at startup and passed to every script-verification seam; `--validation-mode` above is a separate policy and is unchanged. Layers run in the documented precedence — defaults, then config file, then environment, then CLI — so an operator override at any of them wins over the layer below.

- `native` (default): the native Rust interpreter. It is compiled in every build.
- `kernel`: Bitcoin Core's C++ engine (`libbitcoinkernel`). Requires a build with `--features kernel` (plus `cmake` and `libboost-dev`). The feature compiles kernel support in; the setting selects it.

Setting `kernel` on a build without the `kernel` feature fails at startup with an unsupported-build error — ``validation engine `kernel` is not supported by this build: bitcoinkernel support is not compiled in (enable the `kernel` feature)`` — before chain state opens or workers start. There is no silent engine substitution.

```sh
cargo build --release -p bitcoin-rs --features kernel
./target/release/bitcoin-rs --data-dir .bitcoin-rs --validation-engine kernel
```

Direct `bitcoin-rs-consensus` library callers have no config file, environment, or CLI to set: `kernel::BlockParse::parse(raw, engine)` takes a `bitcoin_rs_consensus::ValidationEngine` value, while `kernel::verify_tx_scripts(tx, spent, flags, engine, signature_cache)` and `verify_transaction(..., engine, signature_cache)` take both the engine and a trailing `Option<&bitcoin_rs_script::SignatureCache>`. Pass `None` for uncached calls, or `Some(&cache)` for serial native reuse across multiple passes over the same transaction. When `ValidationEngine::Kernel` is selected, kernel verification ignores the signature cache while running all standard checks, and its behavior is unchanged. Lower-level callers using `PreparedTransaction::verify_input(input_index, flags, signature_cache)` also pass the optional cache reference per call without storing it inside the prepared transaction, keeping `PreparedTransaction` shareable across parallel input checks during block verification. A binary embedder that wants one setting should resolve `ValidationEngine` itself and pass it down exactly as `bitcoin-rs-node` does.

## Operator migration: validation engine

- No change for `bin/bitcoin-rs` users who never set an engine: the binary's default was already kernel-free and remains `native`. Direct library users take the next bullet instead.
- `crates/consensus`, `crates/chainstate`, and `crates/node` library builds changed behavior: their defaults used to compile **and implicitly select** `kernel`, and now compile nothing kernel-related and default to `native`. A library user who relied on the old kernel default must both enable the `kernel` feature and select `validation_engine = "kernel"` (binary config, env, or CLI) — or, for a direct `bitcoin-rs-consensus` caller, pass `ValidationEngine::Kernel` to the verify/parse entries described above.
- To use bitcoinkernel, do both: build with `--features kernel` and set `validation_engine = "kernel"` (TOML), `BITCOIN_RS_VALIDATION_ENGINE=kernel` (env), or `--validation-engine kernel` (CLI).
- Setting `kernel` without the feature fails at startup with the unsupported-build error above.
- Bare `bitcoin-rs` runs native. The shipped Docker image compiles kernel support (`--features fjall,kernel`) and selects `kernel` at the **config-file** layer (`/etc/bitcoin-rs/default.toml`), so bare `docker run` keeps today's kernel behavior while `BITCOIN_RS_VALIDATION_ENGINE=native` or a config file mounted over that one still override it without touching CMD. A CLI override (`--validation-engine`) replaces CMD wholesale under docker semantics — `docker run IMAGE args` runs `bitcoin-rs args` — so going that route means repeating the whole argument list (`--config --data-dir --p2p-listen` included).
- `--validation-mode` / `validation_mode` (Full/AssumeValid/Fast) is the separate script-skip policy and is unchanged.

## More

- [README.md](README.md): documentation index and release gates
- [contracts/](contracts/): normative contracts
- [../CONTRIBUTING.md](../CONTRIBUTING.md): development workflow
- [Snapshot inspector](../tools/snapshot/README.md): inspect and verify Core snapshot files without starting a node
- [Validation tooling](validation-tooling.md): evidence lanes behind the interfaces above
