# In-process Lightning integration: architecture and upstream prerequisites

This document records the architectural assessment and upstream status for
in-process Lightning integration in `bitcoin-rs`, covering [issue #1631](https://github.com/gosuda/bitcoin-rs/issues/1631)
(`ENG-83` and `ENG-96`), grounded in David Parnas's module boundary principles
and Richard Feynman's observational discipline.

In-process integration divides into two distinct phases, each blocked on an
independent upstream component:

| Phase | Scope | Upstream blocker |
| :--- | :--- | :--- |
| Phase A (`ENG-83`) | In-process LDK Server daemon hosting | [`lightningdevkit/ldk-server`](https://github.com/lightningdevkit/ldk-server/tree/c17dc11dde38f88c53457039ddf30c6b90a63ba2) at `c17dc11` |
| Phase B (`ENG-96`) | Direct in-memory LDK Node chain backend | [`lightningdevkit/ldk-node`](https://github.com/lightningdevkit/ldk-node/tree/179b4b263762155a7ff515ddad7e757a80807fd5) at `179b4b2` and `v0.7.1` (peeled commit `edc8916`, annotated tag `3534a3d`) |

Neither phase can be satisfied by scaffolds, copied gRPC code, loopback HTTP
proxies, or patched Cargo dependencies.

---

## 1. Scope and system boundaries

### Boundary with issue #815 (tools/ldk)
The existing [`tools/ldk`](../tools/ldk/README.md) adapter was authored for
[issue #815](https://github.com/gosuda/bitcoin-rs/issues/815). It proves that
the production `Node` embedding contract (`crates/node/src/embed.rs`,
[`docs/contracts/embedding.md`](contracts/embedding.md)) can satisfy the low-level
trait requirements of `rust-lightning` (`BroadcasterInterface`, `FeeEstimator`,
and `BlockSource` from `lightning = "=0.2.7"` and `lightning-block-sync = "=0.2.0"`).

`tools/ldk` lives in an independent Cargo workspace with its own `Cargo.lock`,
keeping LDK dependencies entirely out of the authoritative `bitcoin-rs` workspace
dependency graph and default CI.

`tools/ldk` serves strictly as an L1 adapter proof:
- It does not manage Lightning channels, peer sessions, or `ChannelMonitor`
  state.
- It does not host an LDK Server daemon, gRPC service, or macaroon store.
- Its pinned `lightning = "=0.2.7"` dependency from crates.io cannot be assumed
  type-compatible with upstream `ldk-node` or `ldk-server` git revisions.

### Boundary with issue #1488 (transport interoperability)
External black-box verification of Lightning implementations (LDK Server,
LND, Core Lightning, Lampo, Eclair) over JSON-RPC, REST, and ZMQ belongs
exclusively to [issue #1488](https://github.com/gosuda/bitcoin-rs/issues/1488).
That issue owns the external verification evidence to be recorded in
`docs/lightning-interop-matrix.md` and exercised via `scripts/verify-lightning-interop.sh`.
Pin and provenance qualification of the external binaries without starting any node
(`--verify-pins-only`) and the runner's exit-status contract are specified in
[`docs/lightning-interop-matrix.md`](lightning-interop-matrix.md) section 4.
Issue #1631 addresses only in-process, native Rust embedding.

---

## 2. Phase A blocker: in-process LDK Server (ENG-83)

### Upstream baseline

| Field | Value |
| :--- | :--- |
| Repository | [`lightningdevkit/ldk-server`](https://github.com/lightningdevkit/ldk-server/tree/c17dc11dde38f88c53457039ddf30c6b90a63ba2) |
| Pinned revision | Commit [`c17dc11dde38f88c53457039ddf30c6b90a63ba2`](https://github.com/lightningdevkit/ldk-server/tree/c17dc11dde38f88c53457039ddf30c6b90a63ba2) |
| Upstream status | `BLOCKED` |

### Technical findings

#### 1. Binary-only manifest and lack of library target
The manifest at [`ldk-server/Cargo.toml`](https://github.com/lightningdevkit/ldk-server/blob/c17dc11dde38f88c53457039ddf30c6b90a63ba2/ldk-server/Cargo.toml)
defines a standalone binary crate. It contains no `[lib]` section, and the source
tree contains `src/main.rs` but no `src/lib.rs`.

The repository root manifest at [`Cargo.toml`](https://github.com/lightningdevkit/ldk-server/blob/c17dc11dde38f88c53457039ddf30c6b90a63ba2/Cargo.toml)
defines workspace members `["ldk-server-cli", "ldk-server-client", "ldk-server-grpc", "ldk-server", "ldk-server-mcp", "ldk-server-macaroons"]`.
None of these provides an embeddable server library capable of driving the LDK
Server daemon lifecycle in-process.

#### 2. Absence of an accepted serving interface
The absence of a `[lib]` section is only a surface obstacle. Even if a
library target were declared, the codebase lacks any public serving API.

`NodeService` is private. Defined in [`ldk-server/src/service.rs:115-139`](https://github.com/lightningdevkit/ldk-server/blob/c17dc11dde38f88c53457039ddf30c6b90a63ba2/ldk-server/src/service.rs#L115-L139),
`NodeService`, its constructor `NodeService::new`, and its inner `Context`
(which holds `Arc<Node>`) are declared `pub(crate)`. Neither can be constructed
or accessed outside the `ldk-server` binary crate.

In [`ldk-server/src/main.rs:78-835`](https://github.com/lightningdevkit/ldk-server/blob/c17dc11dde38f88c53457039ddf30c6b90a63ba2/ldk-server/src/main.rs#L78-L835),
the complete runtime, networking, and event lifecycle is hardcoded within private
functions:
- Node construction is private: `fn build_node(...) -> Result<Node, BuildError>`
  (`main.rs:822-835`).
- Node startup is called directly inside `main()`: `node.start()` (`main.rs:325`).
- Service instantiation happens exclusively inside the private socket accept loop:
  `NodeService::new(...)` (`main.rs:730-737`).
- The serving loop is a private inline Tokio event loop (`main.rs:680-773`) driving
  `grpc_listener.accept()` on a local `TcpListener` (`main.rs:726`), in-line TLS
  handshake via `acceptor.accept(stream)` (`main.rs:740`), HTTP/2 serving via
  `http2::Builder::new(TokioExecutor::new()).serve_connection(io_stream, node_service)`
  (`main.rs:742-745`), and LDK event polling via `event_node.next_event_async()`
  (`main.rs:683`). Events are processed internally and emitted via a private
  broadcast channel (`event_sender: broadcast::Sender<EventEnvelope>` at `service.rs:120`),
  with no public API for external consumers to subscribe to, poll, or process
  these events directly.
- Shutdown handling is coupled to system signals (`SIGTERM`/`Ctrl-C`), systemd
  notification (`systemd::notify_stopping()`), and immediate `node.stop()`
  (`main.rs:775-780`). There is no public interface for an orderly shutdown
  sequence that stops incoming connections, drains active gRPC calls and event
  dispatch queues, and then closes the node safely.

There is no public type or function that accepts an externally managed
`Arc<ldk_node::Node>` and provides programmatic control over the gRPC listener,
TLS configuration, macaroon authentication, event polling and dispatch, and
orderly shutdown sequence.

#### 3. Status of upstream issue #310
The tracking issue is [lightningdevkit/ldk-server#310](https://github.com/lightningdevkit/ldk-server/issues/310)
("Expose LDK Server as an embeddable library for bitcoin-rs in-process integration"),
opened 2026-10-10 by `@gosunuts`. Its status is open.

Maintainers questioned the direction, proposing instead that `bitcoin-rs`
be imported into `ldk-server` behind a feature flag. As of 2026-10-24, the
inspected issue does not establish an accepted interface or design agreement
for in-process embedding.

### Upstream prerequisite for Phase A
Phase A is blocked on an accepted upstream `ldk-server` serving interface that:
1. Exposes an embeddable library interface accepting an externally managed
   `Arc<ldk_node::Node>`.
2. Provides programmatic control over gRPC socket binding, TLS configuration,
   macaroon storage, and event dispatch.
3. Exposes public event subscription and an orderly shutdown sequence that drains
   active gRPC requests and events before node teardown.
4. Avoids taking ownership of OS signal handling, systemd notifications, or the
   caller's Tokio runtime.

Maintaining a downstream fork of `ldk-server`, copying its private gRPC handlers
into `bitcoin-rs`, or substituting a loopback HTTP probe is explicitly rejected.

---

## 3. Phase B blocker: native LDK Node chain backend (ENG-96)

### Upstream baseline

| Field | Value |
| :--- | :--- |
| Repository | [`lightningdevkit/ldk-node`](https://github.com/lightningdevkit/ldk-node/tree/179b4b263762155a7ff515ddad7e757a80807fd5) |
| Pinned commit | Commit [`179b4b263762155a7ff515ddad7e757a80807fd5`](https://github.com/lightningdevkit/ldk-node/tree/179b4b263762155a7ff515ddad7e757a80807fd5) |
| Pinned release tag | Tag [`v0.7.1`](https://github.com/lightningdevkit/ldk-node/tree/v0.7.1) (peeled commit [`edc8916e289d39a4135b6eda66978a9f765396bb`](https://github.com/lightningdevkit/ldk-node/tree/edc8916e289d39a4135b6eda66978a9f765396bb), annotated tag object [`3534a3d2072c...`](https://api.github.com/repos/lightningdevkit/ldk-node/git/tags/3534a3d2072c0d98ff4ecb677017033003d4888d) via [`git/refs/tags/v0.7.1`](https://api.github.com/repos/lightningdevkit/ldk-node/git/refs/tags/v0.7.1)) |
| Upstream status | `BLOCKED` |

### Technical findings

#### 1. Closed builder chain-source setters
The builder in `ldk-node` exposes only concrete, remote chain-source setters, with signatures that differ across the two baselines.

At tag `v0.7.1` (peeled commit `edc8916e`, [`src/builder.rs:328-410`](https://github.com/lightningdevkit/ldk-node/blob/edc8916e289d39a4135b6eda66978a9f765396bb/src/builder.rs#L328-L410)), `set_chain_source_bitcoind_rpc` is a four-parameter setter:
```rust
pub fn set_chain_source_esplora(&mut self, server_url: String, sync_config: Option<EsploraSyncConfig>) -> &mut Self;
pub fn set_chain_source_esplora_with_headers(&mut self, server_url: String, headers: HashMap<String, String>, sync_config: Option<EsploraSyncConfig>) -> &mut Self;
pub fn set_chain_source_electrum(&mut self, server_url: String, sync_config: Option<ElectrumSyncConfig>) -> &mut Self;
pub fn set_chain_source_bitcoind_rpc(&mut self, rpc_host: String, rpc_port: u16, rpc_user: String, rpc_password: String) -> &mut Self;
pub fn set_chain_source_bitcoind_rest(&mut self, rest_host: String, rest_port: u16, rpc_host: String, rpc_port: u16, rpc_user: String, rpc_password: String) -> &mut Self;
```

At commit `179b4b2` ([`src/builder.rs:396-503`](https://github.com/lightningdevkit/ldk-node/blob/179b4b263762155a7ff515ddad7e757a80807fd5/src/builder.rs#L396-L503)), `wallet_rescan_from_height: Option<u32>` was added, yielding a five-parameter RPC setter (and seven-parameter REST setter):
```rust
pub fn set_chain_source_esplora(&mut self, server_url: String, sync_config: Option<EsploraSyncConfig>) -> &mut Self;
pub fn set_chain_source_esplora_with_headers(&mut self, server_url: String, headers: HashMap<String, String>, sync_config: Option<EsploraSyncConfig>) -> &mut Self;
pub fn set_chain_source_electrum(&mut self, server_url: String, sync_config: Option<ElectrumSyncConfig>) -> &mut Self;
pub fn set_chain_source_bitcoind_rpc(&mut self, rpc_host: String, rpc_port: u16, rpc_user: String, rpc_password: String, wallet_rescan_from_height: Option<u32>) -> &mut Self;
pub fn set_chain_source_bitcoind_rest(&mut self, rest_host: String, rest_port: u16, rpc_host: String, rpc_port: u16, rpc_user: String, rpc_password: String, wallet_rescan_from_height: Option<u32>) -> &mut Self;
```

In both revisions, there is no generic setter, no trait object parameter (`Box<dyn ChainSource>`), and no custom backend registration hook.

#### 2. Closed ChainSourceKind enumeration
Internal dispatch is mediated by a private enum at `179b4b2`
([`src/chain/mod.rs:153-158`](https://github.com/lightningdevkit/ldk-node/blob/179b4b263762155a7ff515ddad7e757a80807fd5/src/chain/mod.rs#L153-L158))
and `v0.7.1` ([`src/chain/mod.rs:93-97`](https://github.com/lightningdevkit/ldk-node/blob/edc8916e289d39a4135b6eda66978a9f765396bb/src/chain/mod.rs#L93-L97)):

```rust
enum ChainSourceKind {
    #[cfg(feature = "chain-esplora")]
    Esplora(EsploraChainSource),
    #[cfg(feature = "chain-electrum")]
    Electrum(ElectrumChainSource),
    #[cfg(feature = "chain-bitcoind")]
    Bitcoind(BitcoindChainSource),
}
```

`ChainSourceKind` is private (unadorned `enum ChainSourceKind`), and contains
only three variants corresponding to external HTTP and TCP network clients.
The internal configuration enum `ChainDataSourceConfig` (`src/builder.rs`) is
equally private and closed.

#### 3. Absence of custom-backend extension points
Across both revisions, there are zero extension points for an in-process caller to
supply chain services:

| Chain capability | Implementation in `ldk-node` | Extension status |
| :--- | :--- | :--- |
| Full-block and wallet sync | `sync_onchain_wallet` and `sync_lightning_wallet` ([`src/chain/mod.rs:445-485`](https://github.com/lightningdevkit/ldk-node/blob/179b4b263762155a7ff515ddad7e757a80807fd5/src/chain/mod.rs#L445-L485)) dispatch via `match &self.kind` to concrete clients. Bitcoind mode delegates to internal `lightning-block-sync::SpvClient` / `ChainPoller` polling over HTTP REST/RPC ([`src/chain/bitcoind.rs:460-520`](https://github.com/lightningdevkit/ldk-node/blob/179b4b263762155a7ff515ddad7e757a80807fd5/src/chain/bitcoind.rs#L460-L520)). | Closed |
| Fee estimation | `OnchainFeeEstimator` ([`src/fee_estimator.rs`](https://github.com/lightningdevkit/ldk-node/blob/179b4b263762155a7ff515ddad7e757a80807fd5/src/fee_estimator.rs)) is an internal concrete struct, not an open trait. Concrete clients poll remote endpoints and mutate an internal fee rate cache. | Closed |
| Transaction broadcast | `TransactionBroadcaster` ([`src/tx_broadcaster.rs`](https://github.com/lightningdevkit/ldk-node/blob/179b4b263762155a7ff515ddad7e757a80807fd5/src/tx_broadcaster.rs)) queues packages and broadcasts directly through concrete clients via bitcoind RPC `sendrawtransaction`/`submitpackage`, Esplora HTTP, or Electrum TCP. | Closed |
| Tip and filter observation | Driven strictly within internal `SpvClient` and `ChainPoller` polling loops. External listeners cannot attach to the node native chain feed. | Closed |

#### 4. Rust type identity and dependency qualification
In Rust, type identity is nominal and bound to the specific crate instance and source: types
defined across distinct crate sources, git revisions, or disparate builds cannot be unified.

| Target | Declared `lightning` dependency | Resolved version | Compatibility with `tools/ldk` |
| :--- | :--- | :--- | :--- |
| Git commit `179b4b2` | `rev = "d7a980641c6325ddda5072a0f470ef8392676cf5"` in [`ldk-node/Cargo.toml:86-97`](https://github.com/lightningdevkit/ldk-node/blob/179b4b263762155a7ff515ddad7e757a80807fd5/Cargo.toml#L86-L97) | Resolves to `0.3.0-rc3` in `ldk-server` lockfile | Incompatible with crates.io `0.2.7` |
| Release tag `v0.7.1` | `version = "0.2.0"` in [`ldk-node/Cargo.toml:34`](https://github.com/lightningdevkit/ldk-node/blob/edc8916e289d39a4135b6eda66978a9f765396bb/Cargo.toml#L34) | SemVer range `>= 0.2.0, < 0.3.0` (capable of resolving `0.2.7`) | Nominal identity unproven without compiling consumer proof |
| Local `tools/ldk` | `version = "=0.2.7"` in [`tools/ldk/Cargo.toml:12`](../tools/ldk/Cargo.toml) | Exact crates.io `0.2.7` | Self-contained |

Under Cargo SemVer rules, the declaration `version = "0.2.0"` in `v0.7.1` can resolve to crates.io `0.2.7`. However, SemVer compatibility alone does not establish nominal type identity: in Rust, types from two independently resolved crates or different crate sources cannot be unified without a compiling consumer proof. For commit `179b4b2`, the explicit git pin resolves to `0.3.0-rc3`, which is definitively incompatible with `tools/ldk`'s crates.io `0.2.7`. In accordance with plan Step 29, `tools/ldk` must not be assumed identical to `ldk-node`'s source until an actual compiling consumer proof is established.

### Upstream prerequisite for Phase B
Phase B is blocked on an accepted upstream `ldk-node` custom chain source
interface that:
1. Defines an accepted public extension point (such as an open `ChainSource`
   trait or builder setter) accepting custom in-process implementations.
2. Supplies on-chain and Lightning wallet sync, fee estimation, transaction
   and package broadcast, and tip or filter observation.
3. Decouples wallet synchronization from remote REST or RPC polling loops.
4. Uses a stable `lightning` dependency version compatible with the embedding
   application without git patch overrides.

Shipping a downstream fork of `ldk-node`, maintaining patched dependency tables,
or routing requests through a local HTTP loopback server is explicitly rejected.

---

## 4. Acceptance criteria traceability matrix

Every criterion from issue #1631 and the approved plan is mapped below to its
exact upstream prerequisite and current verdict:

| Criterion | Target scope | Current status | Blocking upstream prerequisite |
| :--- | :--- | :--- | :--- |
| Independent compilation | Build with unmodified upstream dependencies | `BLOCKED` | Phase A requires `ldk-server` to export a public library target (`[lib]`). Phase B requires `ldk-node` to align on compatible `lightning` dependency pins without requiring git patch overrides. |
| gRPC, TLS, macaroon, and events lifecycle | Programmatic TLS, macaroon auth, gRPC listener, event polling and dispatch, and coordinated shutdown draining | `BLOCKED` | Phase A requires `ldk-server` to export a public serving interface (`NodeService` or server runner) accepting an external `Arc<ldk_node::Node>`, with public event subscription and deterministic shutdown ordering before node teardown. |
| Channel lifecycle | Open, pay, close, and persisted restart | `BLOCKED` | Blocked on Phase A (cannot drive LDK Server channels via programmatic gRPC) and Phase B (cannot drive channel monitoring or wallet state via in-process chain feed). |
| Reorg and missed-notification recovery | Positional chain replay without dropped blocks | `BLOCKED` | Blocked on Phase B. `ldk-node` internal `sync_lightning_wallet` and `SpvClient` cannot be bound to `Node::subscribe_chain` / `replay_chain`. |
| Zero-loopback native chain backend | In-memory block, fee, mempool, and broadcast queries | `BLOCKED` | Phase B requires `ldk-node` to provide a public custom chain-source extension (such as an open `ChainSource` trait or builder setter) accepting in-process implementations. |
| Matched native versus transport performance | Compare in-process memory calls against RPC loopback | `BLOCKED` | Cannot perform comparative benchmark until native Phase B integration exists without loopback network hops. |

---

## 5. Architectural invariants and policy compliance

### Rejection of scaffolding as completion
A test scaffold or mock server that simulates LDK Server responses over
loopback TCP does not constitute an in-process integration. No acceptance item
may be marked as passed based on stubbed or simulated components.

### Preservation of workspace boundaries
Neither `tools/ldk-server` nor any new LDK dependency may be added to the
authoritative `bitcoin-rs` workspace. The only permitted LDK consumer remains
the isolated `tools/ldk` adapter crate for issue #815.

### Preservation of synchronization and node invariants
When upstream components eventually provide the required extension points,
native integration must comply with:
- [`SYNC-03`](contracts/synchronization.md): In-memory adapter calls must be
  bounded, non-blocking, and unable to stall node progress.
- [`SYNC-05`](contracts/synchronization.md): Adapter queries must honestly
  reflect consensus and storage state without masking persistent errors.
- [`EMB-01` through `EMB-04`](contracts/embedding.md): Embedders must interact
  solely through the public `Node` interface, without bypassing module fences
  or accessing internal storage locks.
