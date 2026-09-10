# bitcoin-rs-node

The integration crate for running a synchronous `bitcoin-rs` node: layered
configuration, storage-backend selection, signal bridging, metrics/tracing setup,
and the central crossbeam-driven event loop that connects the
subsystem crates.

`run` is the top-level entry point: it consumes the resolved `NodeConfig` (with RPC
`Auth`) and drives `event_loop`, the central synchronous loop.
`NodeState` holds the shared state and the `Chainstate` facade for
authoritative apply; `ChainFollowers` dispatch post-commit RPC/ZMQ/index,
mining, and admission work while the `ChainTransition` is still held;
`BlockSync` orchestrates block download; `reorg` switches the applied chain
from one branch to another. The chainstate facade serializes connect,
disconnect, and window apply behind `ChainTransition`. Owning crates expose
the domain surfaces `node` wires:
chain BIP9/softfork lookups, P2P `ActiveChainQuery`, mining candidate context,
and the txindex worker's private block-source bridge. The RPC surface crate owns
the ZMQ protocol and transport; node constructs its `ZmqPublisher`, attaches the
mempool observer, and orders publication with committed chain effects. `signal`
and `shutdown` bridge process signals into graceful shutdown.

For transactions, node supplies the chain view and wires the runtime workers and
committed-result handoffs. The authoritative cross-crate ownership split is
[ARCH-05](../../docs/contracts/architecture.md#arch-05-node-composition-and-orchestration-boundary).

Crash recovery uses a checkpoint plus an authenticated, bounded chainstate journal.
See [Chainstate crash recovery](../../docs/chainstate-recovery.md) for durability
ordering, fallback and reorg behavior, configuration, metrics, and verification.

Data-directory storage evidence is an explicit command, not a node service:
`bitcoin-rs --measure-storage` emits the logical and physical ledgers defined
in [storage-footprint.md](../../docs/contracts/storage-footprint.md).

The node crate registers `benches/sync_pipeline.rs` and
`benches/chainstate_journal.rs` as Criterion benchmarks.

## Configuration and observability modules

`config.rs` and `metrics.rs` are public entry points with explicit re-exports.
Their implementation modules are private; callers continue to use the existing
`bitcoin_rs_node::config`, `bitcoin_rs_node::metrics`, and crate-root paths.

| Owner | Responsibility |
| --- | --- |
| `config/layer.rs` | Parser-independent overrides and last-set-field-wins merging. `None` preserves a lower layer; explicit empty, false, and zero values replace it. |
| `config/resolution.rs` | Ordered application of layers, network-profile resets, and mining-address decoding against the final network. |
| `config/resolved.rs` | Resolved settings, defaults, and cross-field validation. |
| `config/auth.rs`, `network.rs`, `index.rs`, `journal.rs` | Credential redaction, network spellings, index modes, and journal settings with their local invariants. |
| `config/runtime.rs` | Process dependencies such as shutdown receivers and observers, separate from user configuration. |
| `metrics/server.rs`, `catalog.rs` | Scrape-listener lifecycle, the single process-wide recorder, and metric descriptions. |
| `metrics/uptime.rs`, `warnings.rs` | The single uptime origin and first-message-wins warning registry. |
| `metrics/evidence.rs` | Measurement identity, interval accounting, and ledger serialization, independent of scrape transport. |

Configuration regression tests live in `config/tests.rs`; metrics lifecycle tests
live next to their owners, including `metrics/server/tests.rs`. Moving an owner
must not introduce a second global registry, recorder, or representation.

## Features
- `default` (enables `fjall`, `kernel`, and `zmq`): the performance-oriented fjall
  storage backend plus the bitcoinkernel consensus verifier and ZMQ notifications,
  so per-crate `cargo check` works out of the box. The `bitcoin-rs` binary's own
  defaults are the pure-Rust `fjall,redb,zmq`; `kernel` stays opt-in there. Issue
  #213 is the measurement gate for dropping `kernel` from this crate's defaults.
- `rocksdb`, `fjall`, `redb`: forward the named storage backend to every subsystem
  crate.
- `mdbx`: forward the mdbx backend to the crates that provide one.
- `kernel`: route consensus verification through bitcoinkernel
  (`bitcoin-rs-consensus/kernel`).
- `prometheus-http`: enables the `metrics-exporter-prometheus/http-listener` feature;
  the production listener itself is controlled by `metrics_bind`.

Part of [`bitcoin-rs`](../../README.md); see [`CONCEPTS.md`](../../CONCEPTS.md) for the
project vocabulary.
