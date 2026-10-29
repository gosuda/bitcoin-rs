# Lightning Interoperability Verification Matrix

*Scope*: Issue #1488, Plan Step 30 (`ENG-94`).  
*Authoritative Policy*: [`docs/contracts/ecosystem-compatibility.md`](contracts/ecosystem-compatibility.md) (`ECO-01`–`ECO-09`).  
*Executable Runner*: [`scripts/verify-lightning-interop.sh`](../scripts/verify-lightning-interop.sh).  
*Related In-Tree Embedding Boundary*: [`docs/lightning-integration.md`](lightning-integration.md) (`ENG-83`, `ENG-96`, Issue #1631).

---

## 1. Executive Summary & Qualification Principles

This document maintains the independent empirical qualification record for external Lightning Network daemons and integration libraries interacting with `bitcoin-rs` strictly across documented public interfaces (JSON-RPC, REST, and ZMQ notifications).

In strict compliance with `ECO-08` and `ECO-09`:
1. **Unmodified Binaries Only**: Verification requires released or revision-pinned upstream binaries running unmodified. No downstream forks, mock shims, or monkey patches are permitted.
2. **No Version Spoofing or Fake RPCs**: `bitcoin-rs` reports its truthful `client_version()` (`1400` from crate version `0.14.0`). We strictly refuse to spoof Core version numbers (e.g. `290000`) or synthesize mock wallet RPCs to force external tools to pass.
3. **No Wallet Emulation**: `bitcoin-rs` strictly maintains a [`NO_WALLET`](contracts/wallet-facing.md) boundary. Targets requiring Core wallet RPCs (such as `gettransaction`) are recorded as blocked under `NO_WALLET`.
4. **Differential Oracle Comparison**: Bitcoin Core 31.1 (`<bitcoind-bin>`) serves solely as a differential comparator for suspected failures to distinguish target-side defects from node discrepancies. Core 31.1 is never a fallback, replacement, or surrogate pass.
5. **No Nearest-Version Substitution**: Targets without approved pins in the Step 30 specification must remain `not exercised` naming the missing pin prerequisite. Substituting unapproved newer releases is forbidden.

---

## 2. Target Scenarios & Five-Behavior Qualification Matrix

Each target scenario is evaluated across five distinct observable behaviors:
- **`startup`**: Target daemon process initializes, reads configuration, binds control interfaces, and establishes connection to `bitcoin-rs`.
- **`chain sync`**: Target queries chain tip (`getblockchaininfo`, `getblockcount`, `getblockhash`) and synchronizes its internal chain state.
- **`block/tx detection`**: Target observes newly mined blocks and admitted mempool transactions via ZMQ notifications (`rawblock`, `rawtx`) or polling.
- **`broadcast`**: Target successfully submits on-chain funding, sweep, or penalty transactions via `sendrawtransaction`.
- **`restart/reorg`**: Target cleanly handles node restarts, disconnects, and chain reorganizations without state corruption or crash.

### Status Vocabulary (`ECO-08` / Runner Internal)
- **`passed`**: Exercised against a live `bitcoin-rs` node and confirmed by observable public protocol outcomes.
- **`failed`**: Exercised against a live `bitcoin-rs` node and reproducibly failed on a `bitcoin-rs` incompatibility (verified via differential Core 31.1 comparison).
- **`not exercised`**: Unexercised due to a named, truthful prerequisite (e.g., missing pinned binary, rejected pin or provenance, absent approved pin, a host prerequisite such as a missing shared library or `bitcoin-cli` reported as `blocked on host`, unconfigured transport, or research-only status).

---

### Detailed Behavior Ledger (55 Behavior Cells)

| Target | Scenario / Mode | Behavior Cell | Approved Pin | Status | Exact Reason / Prerequisite | Distinct-Value Decision |
|---|---|---|---|---|---|---|
| **LDK Server** | Normal (zero-fee default) | `startup` | `c17dc11dde38...` | `not exercised` | Missing binary prerequisite: `ldk-server` at pinned commit `c17dc11` not provisioned | Normal zero-fee-default mode: `[bitcoind]` RPC with `txindex`. Proves daemon lifecycle and standard on-chain interaction. |
| **LDK Server** | Normal (zero-fee default) | `chain sync` | `c17dc11dde38...` | `not exercised` | Missing binary prerequisite: `ldk-server` at pinned commit `c17dc11` not provisioned | Validates height and block hash synchronization across JSON-RPC and REST. |
| **LDK Server** | Normal (zero-fee default) | `block/tx detection` | `c17dc11dde38...` | `not exercised` | Missing binary prerequisite: `ldk-server` at pinned commit `c17dc11` not provisioned | Validates detection of newly mined blocks via polling or notifications. |
| **LDK Server** | Normal (zero-fee default) | `broadcast` | `c17dc11dde38...` | `not exercised` | Missing binary prerequisite: `ldk-server` at pinned commit `c17dc11` not provisioned | Validates `sendrawtransaction` publishing and mempool acceptance. |
| **LDK Server** | Normal (zero-fee default) | `restart/reorg` | `c17dc11dde38...` | `not exercised` | Missing binary prerequisite: `ldk-server` at pinned commit `c17dc11` not provisioned | Validates persistent state survival across node stop and restart. |
| **LDK Server** | Advanced (zero-fee commitments) | `startup` | `c17dc11dde38...` | `not exercised` | Blocked by `getnetworkinfo.version >= 290000` version gate (bitcoin-rs returns `1400`) and all-V3 `submitpackage` gate | Advanced mode gates on Core 29.0+ version identity and package relay. Version spoofing strictly rejected. |
| **LDK Server** | Advanced (zero-fee commitments) | `chain sync` | `c17dc11dde38...` | `not exercised` | Blocked by version identity gate and missing binary | Requires Core 29.0+ version check to proceed to sync. |
| **LDK Server** | Advanced (zero-fee commitments) | `block/tx detection` | `c17dc11dde38...` | `not exercised` | Blocked by version identity gate and missing binary | Requires ephemeral dust and package detection. |
| **LDK Server** | Advanced (zero-fee commitments) | `broadcast` | `c17dc11dde38...` | `not exercised` | Blocked by all-V3 `submitpackage` requirement (#1574) and TRUC/P2A validation | Evaluates 1p1c package submission for zero-fee commitment sweeps. |
| **LDK Server** | Advanced (zero-fee commitments) | `restart/reorg` | `c17dc11dde38...` | `not exercised` | Blocked by version identity gate and missing binary | Evaluates reorg handling under V3 package rules. |
| **Lampo** | `backend=core` | `startup` | `v24.06` (`657f25c`) | `not exercised` | Missing binary prerequisite: `lampod-cli` binary matching pinned release `v24.06` (`657f25c`) not provisioned; local code fact: `gettransaction` returns `-32601 MethodNotFound` under `NO_WALLET` policy (`crates/rpc/src/registry.rs`); runtime pin identity verification unavailable from binary (--version unhandled) | Core backend requires `gettransaction` under `NO_WALLET` (code fact: method blocked) and `txindex` for confirmed `getrawtransaction`. |
| **Lampo** | `backend=core` | `chain sync` | `v24.06` (`657f25c`) | `not exercised` | Blocked by startup `NO_WALLET` barrier and unprovisioned binary | Requires `--txindex` for confirmed `getrawtransaction`. |
| **Lampo** | `backend=core` | `block/tx detection` | `v24.06` (`657f25c`) | `not exercised` | Blocked by startup `NO_WALLET` barrier and unprovisioned binary | Evaluates polling-based block detection. |
| **Lampo** | `backend=core` | `broadcast` | `v24.06` (`657f25c`) | `not exercised` | Blocked by startup `NO_WALLET` barrier and unprovisioned binary | Evaluates on-chain transaction broadcast. |
| **Lampo** | `backend=core` | `restart/reorg` | `v24.06` (`657f25c`) | `not exercised` | Blocked by startup `NO_WALLET` barrier and unprovisioned binary | Evaluates Lampo SQLite recovery across node restarts. |
| **LND** | Standard ZMQ | `startup` | `v0.21.4-beta` (`390b2d2`) | `not exercised` | No retained in-repo evidence: the only record (`parent-live-4`) is gitignored scratch absent from this checkout (61-dirty tree, runner copy diverging from the tracked script, unverified manifest signature, no Core 31.1 comparison). The dirty-tree wallet-unlock observation carries no verdict; re-run under the tracked runner to qualify. | Standard ZMQ (`zmqpubrawblock`/`zmqpubrawtx`), never `rpcpolling`. Requires `txindex = true` for confirmation queries. |
| **LND** | Standard ZMQ | `chain sync` | `v0.21.4-beta` (`390b2d2`) | `not exercised` | No retained in-repo evidence: the only record (`parent-live-4`) is gitignored scratch absent from this checkout (61-dirty tree, runner copy diverging from the tracked script, unverified manifest signature, no Core 31.1 comparison). The `synced_to_chain=true` observation (height 101, hash match) carries no verdict; re-run under the tracked runner to qualify. | Syncs active tip via RPC `getblock` and ZMQ block notifications. |
| **LND** | Standard ZMQ | `block/tx detection` | `v0.21.4-beta` (`390b2d2`) | `not exercised` | No retained in-repo evidence: the only record (`parent-live-4`) is gitignored scratch absent from this checkout (61-dirty tree, runner copy diverging from the tracked script, unverified manifest signature, no Core 31.1 comparison). Push-speed insert timing on the dirty tree had no topic-level capture; carries no verdict. Classify transport only from an external run, never by mutating production ZMQ. | Standard ZMQ (`zmqpubrawblock`/`zmqpubrawtx`). Push-speed unconfirmed insert plus block confirmation observed in `parent-live-4` against unmodified `lnd`. |
| **LND** | Standard ZMQ | `broadcast` | `v0.21.4-beta` (`390b2d2`) | `not exercised` | No retained in-repo evidence: the only record (`parent-live-4`) is gitignored scratch absent from this checkout (61-dirty tree, runner copy diverging from the tracked script, unverified manifest signature, no Core 31.1 comparison). The dirty-tree `sendcoins`/`getrawmempool` observation carries no verdict; re-run under the tracked runner to qualify. | Evaluates channel funding transaction broadcast. |
| **LND** | Standard ZMQ | `restart/reorg` | `v0.21.4-beta` (`390b2d2`) | `not exercised` | No retained in-repo evidence: the only record (`parent-live-4`) is gitignored scratch absent from this checkout (61-dirty tree, runner copy diverging from the tracked script, unverified manifest signature, no Core 31.1 comparison). The dirty-tree restart plus one-block-reorg observation carries no verdict; re-run under the tracked runner to qualify. | Evaluates channel state machine across chain reorgs. |
| **CLN** | `bcli` plugin | `startup` | `v26.06.9` (`a217658`) | `failed` | Retained qualified run `run-2` (`.outline/evidence/lightning-live-cln/run-2/evidence.json`, `2026-10-26T00:47:25Z`): unmodified `lightningd` exited `1` as `bcli_version_gate` (`Unsupported bitcoind version 1400, at least 220000 required`; log refused `1400`, probed `getnetworkinfo.version=1400`) while the identical scenario against Core 31.1 (`version 310100`) reached `getinfo`-ready (`argv` identical except ports/dirs; `pin_status=verified_approved_pin`; no spoofing). Source identity HEAD `aab50bd64`, 7 dirty entries, 758 inputs (`68cf6054…`), no unreadable/missing, `stale_allowed:false`, unchanged during run; node `48129ac5…`; Core `986e63b3…`; artifact `run-2/work/cln-startup-classification.json`. | Unmodified `bcli` / `bitcoin-cli` plugin. Version spoofing strictly rejected; no wallet or method changes. |
| **CLN** | `bcli` plugin | `chain sync` | `v26.06.9` (`a217658`) | `not exercised` | Retained `run-2` (causal prerequisite: startup=`failed`, so sync never reached). Independent probes in `run-2/work/cln-bcli-probes.json` / `run-2/work/cln-core-bcli-probes.json`: `getblockfrompeer` `rs=method_not_found` (`-32601 method not found`) vs `core=rpc_error` (`-1 Block header missing`); `bcli` fallback only when `getblock` cannot serve a block, not a sync prerequisite on this unpruned node. | `bcli` block polling; `getblockfrompeer` fallback tracked independently. |
| **CLN** | `bcli` plugin | `block/tx detection` | `v26.06.9` (`a217658`) | `not exercised` | Retained `run-2` (causal prerequisite: startup=`failed`, so detection never attempted). Mempool-tx polling additionally requires a funded CLN wallet, which the runner does not provision. | Evaluates block and transaction polling via `bcli` (new-block polling only; no funded wallet). |
| **CLN** | `bcli` plugin | `broadcast` | `v26.06.9` (`a217658`) | `not exercised` | Retained `run-2` (causal prerequisite: startup=`failed`). No funded CLN wallet or channel broadcast exists to observe. | Evaluates `sendrawtransaction` via `bitcoin-cli`. |
| **CLN** | `bcli` plugin | `restart/reorg` | `v26.06.9` (`a217658`) | `not exercised` | Retained `run-2` (causal prerequisite: startup=`failed`). No restart/reorg scenario ran. | Evaluates `bcli` reorg tracking and channel stability. |
| **Alby Hub** | Embedded LDK Node | `startup` | None | `not exercised` | Missing approved pin in Step 30 specification; nearest release `v1.24.4` cannot be substituted per pin rule | Overlap target: embedded LDK mode delegates directly to LDK Node bitcoind chain source rather than introducing a distinct L1 driver. |
| **Alby Hub** | Embedded LDK Node | `chain sync` | None | `not exercised` | Missing approved pin in Step 30 specification | LND/CLN backend modes in Alby Hub are indirect Lightning daemon integrations. |
| **Alby Hub** | Embedded LDK Node | `block/tx detection` | None | `not exercised` | Missing approved pin in Step 30 specification | Address indexing requires Esplora (`--scriptindex=full`). |
| **Alby Hub** | Embedded LDK Node | `broadcast` | None | `not exercised` | Missing approved pin in Step 30 specification | Uses LDK Node broadcaster. |
| **Alby Hub** | Embedded LDK Node | `restart/reorg` | None | `not exercised` | Missing approved pin in Step 30 specification | Reorg handled by underlying LDK Node. |
| **Fedimint** | Guardian direct RPC | `startup` | None | `not exercised` | Missing approved pin in Step 30 specification; nearest releases `v0.12.2`/`v0.11.4` cannot be substituted per pin rule | Overlap target: `fedimintd` guardian direct bitcoind RPC (`fedimint-server-bitcoin-rpc`) requires `height >= 1` (calls `getblockhash(1)`). |
| **Fedimint** | Guardian direct RPC | `chain sync` | None | `not exercised` | Missing approved pin in Step 30 specification | Requires `--txindex=true` for transaction resolution. |
| **Fedimint** | Guardian direct RPC | `block/tx detection` | None | `not exercised` | Missing approved pin in Step 30 specification | Guardian polls blocks via bitcoind RPC. |
| **Fedimint** | Guardian direct RPC | `broadcast` | None | `not exercised` | Missing approved pin in Step 30 specification | Submits consensus federation pegs/sweeps via `sendrawtransaction`. |
| **Fedimint** | Guardian direct RPC | `restart/reorg` | None | `not exercised` | Missing approved pin in Step 30 specification | Guardian consensus handles chain reorgs. |
| **LDK Node** | Library API | `startup` | `v0.7.1` (`edc8916e...`) | `not exercised` | Library crate ([lib], no standalone daemon); distinct library qualification harness for 4-arg set_chain_source_bitcoind_rpc unprovisioned; Phase B native chain source blocked upstream (`ENG-96`); commit 179b4b2 is comparison-only | Approved pin: tag `v0.7.1` (peeled commit `edc8916e...`) exposing 4-arg RPC setter. Commit `179b4b2` is comparison-only (adds `wallet_rescan_from_height`). Phase B native chain source blocked upstream (`ENG-96`). |
| **LDK Node** | Library API | `chain sync` | `v0.7.1` (`edc8916e...`) | `not exercised` | Library crate; distinct library qualification harness unprovisioned; commit 179b4b2 comparison-only | Intended to probe 4-arg `set_chain_source_bitcoind_rpc` chain sync contract. |
| **LDK Node** | Library API | `block/tx detection` | `v0.7.1` (`edc8916e...`) | `not exercised` | Library crate; distinct library qualification harness unprovisioned; commit 179b4b2 comparison-only | Intended to probe block header sync and transaction polling. |
| **LDK Node** | Library API | `broadcast` | `v0.7.1` (`edc8916e...`) | `not exercised` | Library crate; distinct library qualification harness unprovisioned; commit 179b4b2 comparison-only | Intended to probe `BroadcasterInterface` over RPC. |
| **LDK Node** | Library API | `restart/reorg` | `v0.7.1` (`edc8916e...`) | `not exercised` | Library crate; distinct library qualification harness unprovisioned; commit 179b4b2 comparison-only | Intended to probe crash recovery and ChannelMonitor persistence. |
| **Lexe** | Research-only | `startup` | None | `not exercised` | Research-only / not applicable: no public direct bitcoind RPC/ZMQ backend interface configurable | Research target: no configurable public bitcoind RPC/ZMQ backend interface. Formally classified as not applicable; run nothing. |
| **Lexe** | Research-only | `chain sync` | None | `not exercised` | Research-only / not applicable | No configurable direct bitcoind backend; not an L1 integration target. |
| **Lexe** | Research-only | `block/tx detection` | None | `not exercised` | Research-only / not applicable | No configurable direct bitcoind backend; not an L1 integration target. |
| **Lexe** | Research-only | `broadcast` | None | `not exercised` | Research-only / not applicable | No configurable direct bitcoind backend; not an L1 integration target. |
| **Lexe** | Research-only | `restart/reorg` | None | `not exercised` | Research-only / not applicable | No configurable direct bitcoind backend; not an L1 integration target. |
| **lightning-kmp** | Research-only | `startup` | None | `not exercised` | Research-only / not applicable: mobile Kotlin Multiplatform SDK; no public direct bitcoind RPC/ZMQ backend interface | Research target: mobile client SDK without direct bitcoind RPC/ZMQ backend interface. Formally classified as not applicable; run nothing. |
| **lightning-kmp** | Research-only | `chain sync` | None | `not exercised` | Research-only / not applicable | Mobile client without direct bitcoind backend; not an L1 integration target. |
| **lightning-kmp** | Research-only | `block/tx detection` | None | `not exercised` | Research-only / not applicable | Mobile client without direct bitcoind backend; not an L1 integration target. |
| **lightning-kmp** | Research-only | `broadcast` | None | `not exercised` | Research-only / not applicable | Mobile client without direct bitcoind backend; not an L1 integration target. |
| **lightning-kmp** | Research-only | `restart/reorg` | None | `not exercised` | Research-only / not applicable | Mobile client without direct bitcoind backend; not an L1 integration target. |
| **Eclair** | Bitcoind with wallet | `startup` | None | `not exercised` | Missing approved pin in Step 30 specification; nearest release `v0.14.5` cannot be substituted per pin rule | No approved pin in Step 30 specification. Nearest release substitution prohibited. No execution planned. |
| **Eclair** | Bitcoind with wallet | `chain sync` | None | `not exercised` | Missing approved pin in Step 30 specification; nearest release `v0.14.5` cannot be substituted per pin rule | No approved pin in Step 30 specification. Nearest release substitution prohibited. No execution planned. |
| **Eclair** | Bitcoind with wallet | `block/tx detection` | None | `not exercised` | Missing approved pin in Step 30 specification; nearest release `v0.14.5` cannot be substituted per pin rule | No approved pin in Step 30 specification. Nearest release substitution prohibited. No execution planned. |
| **Eclair** | Bitcoind with wallet | `broadcast` | None | `not exercised` | Missing approved pin in Step 30 specification; nearest release `v0.14.5` cannot be substituted per pin rule | No approved pin in Step 30 specification. Nearest release substitution prohibited. No execution planned. |
| **Eclair** | Bitcoind with wallet | `restart/reorg` | None | `not exercised` | Missing approved pin in Step 30 specification; nearest release `v0.14.5` cannot be substituted per pin rule | No approved pin in Step 30 specification. Nearest release substitution prohibited. No execution planned. |

---

## 3. Detailed Target Analyses & Distinct-Value Decisions

### 3.1 Priority 1 (P1) Targets

#### LDK Server (Commit `c17dc11dde38f88c53457039ddf30c6b90a63ba2`)
- **Pinned Upstream Sources**:
  - Configuration schema: [`contrib/ldk-server-config.toml`](https://github.com/lightningdevkit/ldk-server/blob/c17dc11dde38f88c53457039ddf30c6b90a63ba2/contrib/ldk-server-config.toml) (`[node] network = "regtest"`, `[bitcoind] rpc_address`, `rpc_user`, `rpc_password`, `rest_address`)
  - Documentation: `docs/configuration.md`
  - CLI invocation: positional `ldk-server <config.toml>` (with `[node] listening_addresses`/`grpc_service_address`, `[storage.disk] dir_path`, `[bitcoind] rpc_address`/`rpc_user`/`rpc_password`; `--version` prints `ldk-server 0.1.0 (<full 40-hex sha>)`)
  - Serving lifecycle: `src/main.rs`, `src/service.rs` (binary daemon only, `pub(crate) struct NodeService`)
- **Normal Zero-Fee-Default Mode**: Planned probe requires `bitcoin-rs` regtest configured with `--txindex=true`, `--scriptindex=full`, and `--rest=true` via standard `[bitcoind]` RPC. Intended to probe basic daemon lifecycle, block sync, transaction broadcast, and restart.
- **Advanced Mode (`enable_zero_fee_commitments = true`)**:
  - Requires `getnetworkinfo.version >= 290000` (Core 29.0+). `bitcoin-rs` truthfully reports `1400` from `PKG_VERSION = 0.14.0` (`crates/primitives/src/version.rs`, `crates/rpc/src/handlers/network.rs`). This is a version-identity gate failure, not a capability failure. `bitcoin-rs` strictly refuses version spoofing.
  - Requires all-V3 `submitpackage` package relay, TRUC, P2A, and ephemeral dust (Issue #1574 / PR #1667).
  - Both gates are recorded separately in the matrix and JSON evidence.

#### Lampo (`v24.06`, Commit `657f25c3940a956b6ee5ba9d5ef3ac67a61a302f`)
- **Pinned Upstream Sources**:
  - Sample configuration: [`lampo.example.conf`](https://github.com/vincenzopalazzo/lampo.rs/blob/657f25c3940a956b6ee5ba9d5ef3ac67a61a302f/lampo.example.conf) (`backend=core`, `core-url=http://...`, `core-user=...`, `core-pass=...`)
  - Network parsing: [`lampod-cli/src/args.rs`](https://github.com/vincenzopalazzo/lampo.rs/blob/657f25c3940a956b6ee5ba9d5ef3ac67a61a302f/lampod-cli/src/args.rs#L59-L64) (`--network regtest` maps to `Network::Regtest`; any value other than `bitcoin`, `testnet`, `regtest`, `signet` is rejected); the config-file route parses `network=` with `Network::from_str` at [`lampo-common/src/conf.rs`](https://github.com/vincenzopalazzo/lampo.rs/blob/657f25c3940a956b6ee5ba9d5ef3ac67a61a302f/lampo-common/src/conf.rs#L213)
  - Bitcoin Core backend: `lampo-bitcoind/src/lib.rs` (wraps `bitcoincore_rpc::Client`)
  - Official release page: [`releases/tag/v24.06`](https://github.com/vincenzopalazzo/lampo.rs/releases/tag/v24.06)
  - CLI entrypoint & parser: [`lampod-cli/src/args.rs`](https://github.com/vincenzopalazzo/lampo.rs/blob/657f25c3940a956b6ee5ba9d5ef3ac67a61a302f/lampod-cli/src/args.rs) and [`lampod-cli/src/main.rs`](https://github.com/vincenzopalazzo/lampo.rs/blob/657f25c3940a956b6ee5ba9d5ef3ac67a61a302f/lampod-cli/src/main.rs) (workspace member and executable `lampod-cli`, the daemon; lexopt options `--data-dir`/`-d`, `--network`/`-n`, `--client`, `--core-url`, `--core-user`, `--core-pass`, `--log-file`, `--log-level`, `--restore-wallet`, `--help`; every other argument, including `--version` and `--config-file`, is rejected by `arg.unexpected()`). `lampo-cli` is the separate Unix-socket RPC client and is not the daemon.
- **Configuration**: the runner passes the backend as CLI flags (`--network regtest --data-dir <dir> --client core --core-url http://127.0.0.1:<rpcport> --core-user <user> --core-pass <password>`). There is no `--config-file` flag: a `lampo.conf` (`backend=core`, `core-url`, `core-user`, `core-pass`) is read only from the data directory path `lampo-common/src/conf.rs` derives (`<data-dir>/<network>/lampo.conf`), and CLI flags override its values; the runner writes none.
- **Distinct Blocker**: Lampo's on-chain wallet manager invokes `gettransaction` during node initialization and channel monitoring. Under `bitcoin-rs`'s `NO_WALLET` policy, `gettransaction` returns `-32601 MethodNotFound` (`crates/rpc/src/registry.rs`), blocking wallet synchronization. Additionally, runtime identity verification is unavailable from the binary itself because `lampod-cli` does not implement `--version` or report its git revision in its lexopt parser.
- **Prerequisite**: Requires `--txindex=true` for confirmed `getrawtransaction` lookups.

#### LND (`v0.21.4-beta`, Commit `390b2d2b7bdcc335c183962e483f5daeceb8f0e7`)
- **Pinned Upstream Sources**:
  - Sample configuration: [`sample-lnd.conf`](https://github.com/lightningnetwork/lnd/blob/v0.21.4-beta/sample-lnd.conf) (`bitcoin.active=1`, `bitcoin.regtest=1`, `bitcoin.node=bitcoind`, `bitcoind.rpchost`, `bitcoind.rpcuser`, `bitcoind.rpcpass`, `bitcoind.zmqpubrawblock`, `bitcoind.zmqpubrawtx`)
  - Release manifest: `manifest-v0.21.4-beta.txt` (signed tag `4a6ec2fd659c997e8aec14a9769eb13223c41327`)
  - Daemon CLI invocation: `lnd --lnddir=<dir> --configfile=<path>`
  - Client CLI invocation: `lncli --network=regtest --lnddir=<dir> getinfo`
- **Configuration**: `bitcoin.node=bitcoind` with standard ZMQ endpoints (`bitcoind.zmqpubrawblock`, `bitcoind.zmqpubrawtx`). Never use `rpcpolling`.
- **Prerequisites**: `bitcoin-rs` must configure `[[notifications.zmq]]` in its TOML configuration. Requires `--txindex=true` for confirmation queries.
- **Static ZMQ Gap as Run-Contemporary Code Fact**: At the `parent-live-4` commit `ce94561`, static code analysis showed `crates/node/src/chain_effects.rs` invoking `zmq.publish_hashtx` and `publish_rawtx` only during block connection, with mempool admission attaching only `MempoolSequenceObserver` (emitting the `sequence` topic, not `rawtx`/`hashtx`). Commit `4aeb37e3d` ("Publish admitted mempool transactions over ZMQ", carried on this branch as `a5aef4b`) changed this: `MempoolSequenceObserver::on_mutation` now publishes `rawtx` for accepted transactions when the subscriber wants it (`crates/rpc/src/zmq.rs`; attached at `crates/node/src/state/open.rs`). This bullet describes the clean commit, not the run binary. `summary.json` records 61 dirty entries whose newest file is `crates/rpc/src/zmq.rs`, older than the node binary (built `2026-10-25T22:20:50Z`), so the binary ran with uncommitted `zmq.rs` changes; the `rawtx`-publish change was committed directly atop `ce94561` as `4aeb37e3d` two minutes after the run ended. The push-speed unconfirmed insert corroborates a dirty-tree `rawtx` push, but no topic-level capture was retained, so transport attribution rests on timing plus build-order evidence. The code fact stands as context for the clean commit, never as a verdict on the run binary.
- **Provenance Limits of the Unretained `parent-live-4` Scratch Record** (`.outline/evidence/lightning-live-lnd/parent-live-4/`, gitignored and absent from this checkout; its `summary.json` verdict `all_cells_passed` is a historical observation, not a shippable `passed` claim): pinned-scenario evidence only, not a clean-HEAD or fresh-Core comparison claim.
  - `bitcoin-rs` at git HEAD `ce94561` with **61 dirty entries**; node binary sha256 `eeb1afd3…` (mtime `2026-10-25T22:20:50Z`); no rebuild from a clean tree was performed.
  - The run used the `.outline` runner copy (`sha256 a79fc245…`), **not** `scripts/verify-lightning-interop.sh` (whose sha256 at run time was `79cf7195…` per `summary.json` `runner_original_sha256`; see `runner-delta.diff`); results do not transfer silently to the tracked runner.
  - The upstream release manifest signature was **not verified** (no signature file is retained in `lightning-artifacts/`); identity rests on sha256 equality between the `lnd`/`lncli` executables, the manifest rows, and the tarball members.
  - No fresh Core 31.1 comparison was recorded in this run (`backend_api_probe.core.rows = 0`); the five observations stand on direct observation against `bitcoin-rs` only and carry no `passed` verdict.
  - This run does **not** reproduce at the current branch head: rerunning requires the parent's rebuild and a new retained run, including the source-identity guard the tracked runner now enforces plus topic-level ZMQ capture for any transport claim.

#### Core Lightning / CLN (`v26.06.9`, Commit `a2176589f235b63bc1a37e69362dfd6c925397e9`)
- **Pinned Upstream Sources**:
  - Configuration manual: [`doc/lightningd-config.5.md`](https://github.com/ElementsProject/lightning/blob/v26.06.9/doc/lightningd-config.5.md) (`--network=regtest`, `--bitcoin-cli`, `--bitcoin-rpcconnect`, `--bitcoin-rpcport`, `--bitcoin-rpcuser`, `--bitcoin-rpcpassword`, `--bitcoin-datadir`, `--lightning-dir`, `--addr`)
  - Bitcoin backend plugin: `plugins/bcli.c` (checks `getnetworkinfo.version >= 220000`, calls `getblockfrompeer`)
  - Daemon CLI invocation: `lightningd --bitcoin-cli=<bitcoin-cli path> --bitcoin-datadir=<owned empty dir> --network=regtest --lightning-dir=<dir> --addr=127.0.0.1:<port> --grpc-port=<port> --bitcoin-rpcuser=... --bitcoin-rpcpassword=... --bitcoin-rpcconnect=127.0.0.1 --bitcoin-rpcport=<port> --bitcoin-retry-timeout=<secs> --log-level=debug --log-file=<file>`
  - Client CLI invocation: `lightning-cli --network=regtest --lightning-dir=<dir> getinfo`
  - Pinned-binary evidence (no source checkout required): the digest-verified Ubuntu 26.04 amd64 `libexec/c-lightning/plugins/bcli` loads `0x35b60` (`220000`) as the required-minimum argument of `plugin_err("Unsupported bitcoind version %u, at least %u required.")`; its rodata also references `getblockfrompeer` alongside `getpeerinfo` and `failed to fetch block %s from the bitcoin backend (maybe pruned)`, i.e. the pruned/missing-block fallback path.
- **Configuration**: Unmodified `bcli` plugin communicating via `bitcoin-cli`.
- **Distinct Blockers**:
  1. `version >= 220000` gate: CLN `bcli` checks `getnetworkinfo.version` (binary fact: pinned `bcli` loads `0x35b60`, refusing with `Unsupported bitcoind version %u, at least %u required.`). Retained qualified run `run-2` (`.outline/evidence/lightning-live-cln/run-2/`) observed the refusal live: `run-2/work/cln.log` records `Unsupported bitcoind version 1400, at least 220000 required` with `**BROKEN** plugin-bcli: Unsupported bitcoind version 1400, at least 220000 required`, `end=exited exit=1 kind=bcli_version_gate`; probed `bitcoin-rs` `getnetworkinfo.version=1400` (`run-2/work/cln-bcli-probes.json`; `PKG_VERSION = 0.14.0`) and Core `310100` (`run-2/work/cln-core-bcli-probes.json`); identical `lightningd` options (differ only in ports/dirs, `argv_option_names_identical=true` in `run-2/work/cln-startup-classification.json`) with Core reaching `lightning-cli getinfo`-ready. `bitcoin-rs` refuses version spoofing. A refusal with an unusable comparator, mismatched versions, non-identical options, or any unclassified exit stays `not exercised` with the log as artifact.
  2. `getblockfrompeer` RPC: `bitcoin-rs` marks `getblockfrompeer` as `Unimplemented` (row `"getblockfrompeer"` in `crates/rpc/src/registry.rs`, `Status::Unimplemented`). The runner probed it independently in `run-2` (`run-2/work/cln-bcli-probes.json` class `method_not_found`: `method not found: getblockfrompeer`; `run-2/work/cln-core-bcli-probes.json` class `rpc_error`: `code=-1 Block header missing`; classes recorded in `run-2/work/cln-startup-classification.json`); per the pinned-binary strings it is `bcli`'s fallback when `getblock` cannot serve a block, not a prerequisite for chain sync on this unpruned node, so the chain-sync cell cites the startup prerequisite rather than this RPC.
  Both blockers are tracked independently.
- Retained qualified run `run-2` (`.outline/evidence/lightning-live-cln/run-2/evidence.json`, `2026-10-26T00:47:25Z`, 1 `failed` plus 4 `not exercised`) ran the parent frozen runner `scripts/verify-lightning-interop.sh` (`86eba76fcefb093f6ca5e9876f402b7a375cabf8ebc8ed890344e613032e5707` in `.outline/evidence/lightning-live-cln/frozen-runner.sha256`, before equals after, not edited here; parent job `bg_543` ran checksum before plus `bash -n` plus private `ShellCheck` plus real campaign plus checksum after in one chain with exit `0`, recorded in `.outline/evidence/lightning-live-cln/run-2/verification.json` with `runner_sha256` `86eba76fcefb093f6ca5e9876f402b7a375cabf8ebc8ed890344e613032e5707` and `bash_syntax_exit` `0` and `shellcheck_exit` `0` and `campaign_exit` `0`) with frozen node binary `.outline/evidence/lightning-live-cln/bin/bitcoin-rs-aab50bd64` (`48129ac5f2fccb1e430587a09286b3ae6a71399fb3379be9b61ddfd7c6d6bbf6`) at HEAD `aab50bd644d4e47f674d6175c4e9c8b2e34d48f6` (7 dirty entries read from the evidence JSON, not invented; 758 build inputs `68cf6054…`, no unreadable or missing inputs, `stale_allowed:false`, unchanged during run; Core comparator `986e63b3…` with `Bitcoin Core daemon version v31.1.0 bitcoind` verified).
- Retained raw run `run-1` (`.outline/evidence/lightning-live-cln/run-1/evidence.json`) uses a mixed runner revision, so it stays NOT qualified and carries no claim.
- **Executed-Run Protocol** (tracked runner; replaces the former always-`not exercised` CLN branch):
  - Pin: `--cln-release-archive` digest-checked against the official `SHA256SUMS-v26.06.9` table and `--cln-bin` verified byte-identical to the archive's `usr/bin` + `usr/libexec/c-lightning` trees; `lightningd --version` must print exactly `v26.06.9`; `lightning-cli` must be the sibling binary in the same tree.
  - Host: missing shared objects (notably `libpq.so.5`) are resolved via scoped `--cln-library-path` (e.g. the privately extracted `libpq-probe/root/usr/lib/x86_64-linux-gnu`), prepended to `LD_LIBRARY_PATH` only for CLN's own `ldd`/`--version`/spawn/`lightning-cli` probes; `bitcoin-rs`, Core, and RPC probes never see it.
  - Readiness: `lightning-cli getinfo` must return an `id` twice (2s apart, daemon still alive); process liveness excludes zombies; spawn identity (`cln-spawn-identity.tsv`) requires the supervised pid's `/proc` exe to resolve to the verified `lightningd` in its own process group.
  - Freshness: the runner hashes every tracked and untracked (not ignored) build input (`Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `build.rs`, `.cargo/`, `bin/`, `crates/`) into `bitcoin-rs-source-identity.json` and refuses (exit 1) when any input is newer than the node binary, unless `--allow-stale-bitcoin-rs` records the override; a post-run rehash records whether sources moved during the run.
  - Comparator: `bitcoind --version` must print exactly `Bitcoin Core daemon version v31.1.0 bitcoind` inside an owned scratch datadir (never `~/.bitcoin`) before Core may serve as the differential comparator.
  - No version spoofing, no wallet emulation, no synthetic RPCs; `bitcoin-cli` runs with an owned empty `--bitcoin-datadir` so no real `~/.bitcoin` config is ever read.

---

### 3.2 Overlap Targets

#### Alby Hub
- **Nearest Research Reference (Unapproved, Not Pinned Authority)**:
  - Configuration model: [`config/models.go:50-54`](https://github.com/getAlby/hub/blob/v1.24.4/config/models.go) (`NETWORK`, `LDK_BITCOIND_RPC_HOST`, `LDK_BITCOIND_RPC_PORT`, `LDK_BITCOIND_RPC_USER`, `LDK_BITCOIND_RPC_PASSWORD`, `LDK_ESPLORA_SERVER`)
  - LDK integration: [`lnclient/ldk/ldk.go:88-125`](https://github.com/getAlby/hub/blob/v1.24.4/lnclient/ldk/ldk.go) (`builder.SetChainSourceBitcoindRpc(...)`)
- **Distinct-Value Decision**: Alby Hub's embedded LDK mode delegates directly to LDK Node's bitcoind RPC chain source rather than introducing a distinct L1 driver contract. Alternate backend modes (`LN_BACKEND_TYPE=LND/CLN`) are indirect Lightning daemon integrations.

#### Fedimint (`fedimintd`)
- **Nearest Research Reference (Unapproved, Not Pinned Authority)**:
  - Direct RPC client: [`fedimint-server-bitcoin-rpc/src/bitcoind.rs`](https://github.com/fedimint/fedimint/blob/v0.12.2/fedimint-server-bitcoin-rpc/src/bitcoind.rs) (`FM_BITCOIN_RPC_URL`, `FM_BITCOIN_RPC_KIND="bitcoind"`, calls `get_block_hash(1)`)
  - Test configuration: `devimint/src/cfg/bitcoin.conf` (`regtest=1`)
- **Distinct-Value Decision**: Focuses exclusively on the `fedimintd` guardian direct RPC path (`fedimint-server-bitcoin-rpc`). Requires `height >= 1` (calls `getblockhash(1)` for chain ID) and `--txindex=true`. Watch-only wallet and LN-gateway paths are non-goals.

#### LDK Node (`v0.7.1`, Peeled Commit `edc8916e289d39a4135b6eda66978a9f765396bb` / Comparison Commit `179b4b263762155a7ff515ddad7e757a80807fd5`)
- **Pinned Upstream Sources**:
  - Approved Release Tag `v0.7.1` (Peeled commit [`edc8916e289d39a4135b6eda66978a9f765396bb`](https://github.com/lightningdevkit/ldk-node/tree/edc8916e289d39a4135b6eda66978a9f765396bb), annotated tag object [`3534a3d2072c...`](https://api.github.com/repos/lightningdevkit/ldk-node/git/tags/3534a3d2072c0d98ff4ecb677017033003d4888d) via [`git/refs/tags/v0.7.1`](https://api.github.com/repos/lightningdevkit/ldk-node/git/refs/tags/v0.7.1)):
    - Builder API: [`src/builder.rs`](https://github.com/lightningdevkit/ldk-node/blob/edc8916e289d39a4135b6eda66978a9f765396bb/src/builder.rs#L328-L410) (`builder.set_network(Network::Regtest)`, four-parameter `builder.set_chain_source_bitcoind_rpc(rpc_host, rpc_port, rpc_user, rpc_password)`)
    - Chain sources: [`src/chain/mod.rs`](https://github.com/lightningdevkit/ldk-node/blob/edc8916e289d39a4135b6eda66978a9f765396bb/src/chain/mod.rs#L93-L97) (`ChainSourceKind` enum with concrete variants `Esplora`, `Electrum`, `Bitcoind`)
    - Manifest: [`Cargo.toml`](https://github.com/lightningdevkit/ldk-node/blob/edc8916e289d39a4135b6eda66978a9f765396bb/Cargo.toml) (`[lib]`, no daemon executable; `lightning = "0.2.0"`)
  - Git Commit [`179b4b263762155a7ff515ddad7e757a80807fd5`](https://github.com/lightningdevkit/ldk-node/tree/179b4b263762155a7ff515ddad7e757a80807fd5) (Comparison Reference):
    - Builder API: [`src/builder.rs`](https://github.com/lightningdevkit/ldk-node/blob/179b4b263762155a7ff515ddad7e757a80807fd5/src/builder.rs#L396-L503) (five-parameter `builder.set_chain_source_bitcoind_rpc(rpc_host, rpc_port, rpc_user, rpc_password, wallet_rescan_from_height)`)
    - Chain sources: [`src/chain/mod.rs`](https://github.com/lightningdevkit/ldk-node/blob/179b4b263762155a7ff515ddad7e757a80807fd5/src/chain/mod.rs#L153-L158)
    - Manifest: [`Cargo.toml:86-97`](https://github.com/lightningdevkit/ldk-node/blob/179b4b263762155a7ff515ddad7e757a80807fd5/Cargo.toml#L86-L97) (`[lib]`, no daemon executable; git revision `d7a980641c6325ddda5072a0f470ef8392676cf5` resolving to `lightning 0.3.0-rc3`)
- **Distinct-Value Decision**:
  - A distinct library-level qualification harness for either setter signature is unprovisioned in the test environment; moreover, Phase B native in-process chain source is blocked upstream (`ENG-96` / `docs/lightning-integration.md`).
  - Status is `not exercised` naming the unprovisioned library qualification harness and distinct setter requirements.

---

### 3.3 Research / Inapplicable Targets

#### Lexe
- **Upstream Sources**: Hosted custodial multi-party computation architecture without a configurable public Bitcoin Core backend interface.
- **Classification**: Research-only / Not Applicable.

#### lightning-kmp
- **Upstream Sources**: Kotlin Multiplatform client SDK repository designed for light clients without a direct `bitcoind` RPC/ZMQ interface.
- **Classification**: Research-only / Not Applicable.

#### Eclair
- **Nearest Research Reference (Unapproved, Not Pinned Authority)**:
  - Reference configuration: [`eclair-core/src/main/resources/reference.conf:10-25`](https://github.com/ACINQ/eclair/blob/v0.14.5/eclair-core/src/main/resources/reference.conf) (`chain = "regtest"`, `bitcoind { host, rpcport, zmqblock, zmqtx, wallet }`)
- **Classification**: Not Exercised (No Approved Pin).
- **Distinct-Value Decision**: No approved pin exists in the Step 30 specification. The nearest official release (`v0.14.5`) cannot be substituted per the pin rule. Under `ECO-08`, absent an approved pin and provisioned execution, every cell remains `not exercised: no approved pin`. Any wallet/PSBT refusal under `NO_WALLET` can be recorded only after an executed run against an approved pin.

---

## 4. Test Runner & Execution Protocol

The automated runner [`scripts/verify-lightning-interop.sh`](../scripts/verify-lightning-interop.sh) provisions isolated regtest `bitcoin-rs` environments and executes or qualifies target binaries.

### Invocation Examples

```bash
# Validate CLI help and argument parsing
scripts/verify-lightning-interop.sh --help

# Run all targets against bitcoin-rs (unprovisioned binaries emit truthful 'not exercised' records)
scripts/verify-lightning-interop.sh \
  --bitcoin-rs-bin target/release/bitcoin-rs \
  --output-json target/lightning-interop-evidence.json

# Run a specific target with provisioned binary
scripts/verify-lightning-interop.sh \
  --bitcoin-rs-bin target/release/bitcoin-rs \
  --target lnd \
  --lnd-bin <lnd-dir>/lnd \
  --bitcoind-bin <bitcoind-bin> \
  --output-json target/lnd-evidence.json

# Qualify provisioned artifacts only: no bitcoin-rs node, no Core comparator, no target daemon, no
# --bitcoin-rs-bin needed. Every cell stays 'not exercised'; one PIN-* line is printed per target.
scripts/verify-lightning-interop.sh --verify-pins-only --target lnd \
  --lnd-bin <dir>/lnd-linux-amd64-v0.21.4-beta/lnd
scripts/verify-lightning-interop.sh --verify-pins-only --target cln \
  --cln-bin <extract-dir>/usr/bin/lightningd \
  --cln-release-archive <dir>/clightning-v26.06.9-Ubuntu-26.04-amd64.tar.xz

# Live CLN cell (starts a bitcoin-rs regtest node and, if needed, the Core 31.1 comparator).
# Portable command shape with caller-provided artifacts (--cln-library-path scopes a
# privately extracted libpq5 to CLN commands only; no outer LD_LIBRARY_PATH is needed).
# `timeout` is the wall-clock bound (`--timeout-seconds` bounds each wait only); TERM runs the
# runner's exit trap, which reaps the node and daemon groups (exit 124 on timeout).
# Historical evidence for this shape is retained in Section 4 prose (`run-2` with its
# frozen runner digest and verification record); the command below is the portable
# contract, not the host-specific retained run.
timeout --signal=TERM --kill-after=30 900 bash scripts/verify-lightning-interop.sh \
  --bitcoin-rs-bin <bitcoin-rs-bin> \
  --bitcoind-bin <bitcoind-bin> \
  --target cln \
  --cln-bin <cln-extract-dir>/usr/bin/lightningd \
  --cln-release-archive <artifact-dir>/clightning-v26.06.9-Ubuntu-26.04-amd64.tar.xz \
  --cln-library-path <libpq-dir> \
  --workdir <workdir> \
  --output-json <output-json> \
  --timeout-seconds 60
# Source/files needed: scripts/verify-lightning-interop.sh (tracked) + the bitcoin-rs checkout it
# was built from (source-identity guard, default: the checkout holding the script) + the four
# pinned paths above (lightningd extraction, release archive with SHA256SUMS-v26.06.9, private
# libpq5 dir, Core 31.1 bitcoind with its sibling bitcoin-cli). No build, test, lint, or format
# runs inside this command; the parent orchestrates those once.
```

### Exit Status Contract

The exit status reports whether the runner could do its job; the evidence JSON, not the exit status, is the verdict on any cell. A missing binary, a rejected pin or a host-blocked target therefore does **not** make a normal run fail: the cell is recorded `not exercised` with its named prerequisite and the run exits `0`.

| Exit | Meaning |
|---|---|
| `0` | The run finished and the evidence JSON was written. With `--verify-pins-only`: every selected `ldk-server`/`lampo`/`lnd`/`cln` target printed `PIN-ACCEPTED` (no such target selected also exits `0`). |
| `1` | Usage or prerequisite error before any target ran: unknown option or target, an option given without its value (`ERROR: option <name> requires a value.`), missing or non-executable `--bitcoin-rs-bin` (optional only with `--verify-pins-only`), `--timeout-seconds` that is not a positive integer, a missing `--cln-library-path` directory, `setsid`/`timeout` missing, or the `bitcoin-rs` source-identity guard failed (a build input is newer than the node binary, a tracked input is missing, git cannot list them, the source root lacks `Cargo.toml` and `crates/` inputs, or the binary is unreadable; rerun with `--allow-stale-bitcoin-rs` to record-but-continue). |
| `2` | `--verify-pins-only` only: a selected `ldk-server`/`lampo`/`lnd`/`cln` target printed `PIN-REJECTED`, `PIN-HOST-BLOCKED` or `PIN-UNPROVISIONED`. |
| `130` / `143` | Interrupted by `INT` / terminated by `TERM`; children are reaped by the exit trap. |

### Pin and Provenance Qualification Routes

A provisioned binary is run only after its identity is qualified; no target is run on a nearest-release substitution. `pin_status` in the evidence JSON records how:

| Target | Accepted when | `pin_status` | Otherwise |
|---|---|---|---|
| LDK Server | `--version` first line ends with ` 0.1.0 (<full 40-hex pinned commit>)`; with `--ldk-server-provenance` the six-line provenance file must also match the approved commit, a clean tree, `rustc -V` toolchain and the executable's sha256 | `self_reported_revision` (revision only), `source_qualified` (with provenance) | `pin_unverified` (probe timed out or failed), `pin_mismatch` (wrong revision or provenance) |
| Lampo | `--lampo-provenance` file matches the approved commit `657f25c3940a956b6ee5ba9d5ef3ac67a61a302f`, a clean tree, `rustc -V` toolchain and the executable's sha256 (`lampod-cli` prints no version) | `source_qualified` | `pin_unverified` (no provenance file), `pin_mismatch` (provenance rejected) |
| LND | sha256 of the `lnd` executable equals the upstream `manifest-v0.21.4-beta.txt` value for `lnd-linux-amd64-v0.21.4-beta/lnd`: `f19efdbde7cbd449d8b3e67bf3e69d0fdc7e6fabed7bed7599829d201c5aa1e8` (`lncli`: `7d53b3ab15b7f080c9698a668db7e3169438b9857301ecca5ed9137b3635ec1f`; the tarball is `beffe4949a5e46410d90c0e6d020a1b685468440b0004fc4d59740a6291178fb`); Linux x86-64 only | `verified_approved_pin` | `pin_unverified` (no manifest value for this platform), `pin_mismatch` (digest differs) |
| CLN | `--cln-release-archive` is an official `clightning-v26.06.9-*` archive (sha256 in the runner's table of the official `SHA256SUMS-v26.06.9` / `-arm64` / `-armv7` digests; Ubuntu 26.04 amd64: `25379fe80763787f174f91961f66ec98de881160184faeb40a5f2fc29c68b29c`) and `--cln-bin` is the `<prefix>/bin/lightningd` of an unmodified extraction: every file under `bin` and `libexec/c-lightning` is byte-identical to the archive and no symlink is present; `lightning-cli` must be the sibling binary in the same tree and resolve its own shared objects | `verified_approved_pin` | `pin_unverified` (no `--cln-release-archive`), `pin_mismatch` (archive digest unknown or install tree differs) |

`--verify-pins-only` prints one stdout line per target after qualification: `PIN-ACCEPTED`, `PIN-REJECTED` (pin or provenance check failed), `PIN-HOST-BLOCKED` (pin qualified, binary cannot run here) or `PIN-UNPROVISIONED` (no binary). The same lines are printed in a normal run, which then continues to the live cell only after `PIN-ACCEPTED`.

### Blocked on Host

After the pin is qualified and before any bitcoin-rs node is started, the runner checks that the binary can run on the host: `ldd` on the executable (for CLN: `lightningd` and every executable under `libexec/c-lightning`), and for CLN `lightningd --version` must also print exactly `v26.06.9`. A missing shared library, loader error or timed-out probe is recorded as `not exercised: blocked on host: ...` with the qualified `pin_status` unchanged and a statement that it is a host prerequisite, not a `bitcoin-rs` result; no differential Core 31.1 run is made for it.

CLN additionally needs a `bitcoin-cli` executable for its `bcli` plugin. The runner resolves it as the `bitcoin-cli` beside `--bitcoind-bin`, else the first `bitcoin-cli` on `PATH`, passes it as `--bitcoin-cli=<absolute path>` (verified present in `lightningd --help`: `--bitcoin-cli <arg>  bitcoin-cli pathname`) so `lightningd` never depends on `PATH`, and records `blocked on host` when none exists. `lightningd` is also given `--addr=127.0.0.1:<free port>` and `--grpc-port=<free port>` so the isolated run never listens on default addresses.

Host fact observed 2026-10-25 on the qualification host (Ubuntu 26.04): `ldd` on the digest-verified `usr/bin/lightningd` of `clightning-v26.06.9-Ubuntu-26.04-amd64.tar.xz` reports `libpq.so.5 => not found` (every other binary under `bin` and `libexec/c-lightning` resolves). Without `--cln-library-path` the CLN cell on this host is `PIN-HOST-BLOCKED`, not a `bitcoin-rs` incompatibility. `PIN-ACCEPTED` with a private libpq5 was proved with an outer `LD_LIBRARY_PATH` (`pin-proofs/cln-genuine-with-private-libpq`: rc 0); the scoped `--cln-library-path` route was exercised by the retained qualified run `run-2` (the live cell above), which started `lightningd` past the libpq host block; without the flag the cell is `PIN-HOST-BLOCKED`.

### Source Identity and Comparator Identity

Before any live run (skipped only with `--verify-pins-only`), the runner records two identity blocks into the evidence JSON's `runner` section:
- `bitcoin_rs_source_identity`: exact identity (git HEAD, dirty count, per-file sha256 digest) of every tracked and untracked-but-not-ignored build input (`Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `build.rs`, `.cargo/`, `bin/`, `crates/`) under `--bitcoin-rs-source` (default: the checkout holding the script). The run refuses (exit `1`) when any input is newer than `--bitcoin-rs-bin`, a tracked input is missing from disk, git cannot list them, the source root lacks `Cargo.toml` and `crates/` inputs, or the binary is unreadable; `--allow-stale-bitcoin-rs` records the override instead (`stale_allowed: true`). After the run a second record captures whether sources moved mid-run (`bitcoin_rs_build_inputs_changed_during_run`).
- `core_comparator_identity`: the `bitcoind --version` first line (required: exactly `Bitcoin Core daemon version v31.1.0 bitcoind`, probed inside an owned scratch datadir so the default `~/.bitcoin` is never touched) and the comparator binary sha256. A wrong-version `bitcoind` can never serve as the differential comparator.

### Generated Artifacts
- **Evidence JSON**: Adheres to schema `bitcoin-rs-lightning-interop-v1`; `runner.verify_pins_only` is `true` (and `runner.bitcoin_rs_bin` is `null`) for a `--verify-pins-only` report. Live runs additionally carry `runner.bitcoin_rs_source_identity` and `runner.core_comparator_identity`; CLN runs carry `cln-bcli-probes.json`, `cln-core-bcli-probes.json`, `cln-startup-classification.json`, `cln-spawn-identity.tsv`, and the `cln.log` / `cln-core.log` daemon logs.
- **Node Logs**: Preserved unconditionally in `--workdir` as evidence artifacts across all runs.

---

## 5. Relationship to Ecosystem Compatibility Policy (`ECO-08`)

Per `docs/contracts/ecosystem-compatibility.md` (`ECO-08`), entries in `docs/api/ecosystem-compat.toml` remain strictly evidence-gated:
- Surfaces are only marked `externally verified` when a retained, reproducible run of an unmodified external consumer exists.
- In-tree tests, mock runners, and unexercised targets remain classified as `implemented` or `experimental`.
- No speculative compatibility rows are added to `docs/api/ecosystem-compat.toml` until actual retained runs are produced.
