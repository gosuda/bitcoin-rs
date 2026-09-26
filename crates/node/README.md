# bitcoin-rs-node

The integration crate for running a synchronous `bitcoin-rs` node: layered
configuration, storage-backend selection, signal bridging, metrics/tracing setup,
and the central crossbeam-driven event loop that connects the
subsystem crates.

## Source layout

Production files live directly in `src/`. Small single-owner fragments are
folded into their owner; substantial apply, checkpoint, and state implementations
use domain-prefixed companion files. Explicit module paths preserve Rust privacy
and the existing public API without recreating the directory hierarchy.

Unit-test trees live in `tests/unit/` and compile through their production parent
modules. Public-API integration tests remain directly in `tests/`.

`run` is the top-level entry point: it loads the layered `Config` (with RPC `Auth`), and
drives `event_loop`, the central synchronous loop.
`NodeState` holds the shared state and the `Chainstate` facade for
authoritative apply; `ChainFollowers` dispatch post-commit RPC/ZMQ/index,
mining, and admission work while the `ChainTransition` is still held;
`BlockSync` (owned by P2P) executes block download over `DownloadWindow` and `BlockStager`;
`reorg` switches the applied chain from one branch to another. The chainstate facade serializes connect,
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
See [contracts/recovery.md](../../docs/contracts/recovery.md) for durability
ordering, fallback and reorg behavior, and verification.

Data-directory storage evidence is an explicit command, not a node service:
`bitcoin-rs --measure-storage` emits the logical and physical ledgers defined
in [storage-footprint.md](../../docs/contracts/storage-footprint.md).

The node crate registers `benches/sync_pipeline.rs` as a Criterion benchmark and
`benches/chainstate_journal.rs` as a harness-less replay gate (its own `main`).
Large corpus/replay/evidence harnesses are intentionally not shipped by this
runtime crate.

## Features
- `default` (enables `fjall` and `zmq`): the performance-oriented fjall
  storage backend plus ZMQ notifications, so per-crate `cargo check` works out
  of the box. The default is kernel-free in every crate, so no build links a
  C++ engine unless asked.
- `rocksdb`, `fjall`, `redb`: forward the named storage backend to every subsystem
  crate.
- `kernel`: compiles bitcoinkernel support in (`bitcoin-rs-consensus/kernel`).
  Selection is the runtime `validation.engine` setting (`native` by default);
  the feature alone never routes consensus verification to the kernel.
- `prometheus-http`: enables the `metrics-exporter-prometheus/http-listener` feature;
  the production listener itself is controlled by `metrics_bind`.

Part of [`bitcoin-rs`](../../README.md); see [`CONCEPTS.md`](../../CONCEPTS.md) for the
project vocabulary.
