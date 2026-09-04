# bitcoin-rs-node

The integration crate for running a synchronous `bitcoin-rs` node: layered
configuration, storage-backend selection, signal bridging, metrics/tracing setup,
and the central crossbeam-driven event loop that connects the
subsystem crates.

`run` is the top-level entry point: it loads the layered `Config` (with RPC `Auth`), and
drives `event_loop`, the central synchronous loop.
`NodeState` holds the shared state and the `apply` block-apply pipeline;
`BlockSync` orchestrates block download; `reorg` switches the applied chain from one
branch to another. Adapters expose node state to the rest of the system —
`UtxoSetView` for consensus transaction checks, `NodeBlockSource` bridging in-memory
block records to the index crate's block source, `NodeP2pChainQuery` for server-side
P2P responders, and `BlockTreeContext` for BIP9 deployment state. Notifications leave
through the `ZmqPublisher` trait and its `SocketZmqPublisher` / `TracingZmqPublisher`
/ `NoOpZmqPublisher` implementations and the `TxIndexRuntime` worker; `signal` and
`shutdown` bridge process signals into graceful shutdown.

Crash recovery uses a checkpoint plus an authenticated, bounded chainstate journal.
See [Chainstate crash recovery](../../docs/chainstate-recovery.md) for durability
ordering, fallback and reorg behavior, configuration, metrics, and verification.

The node crate registers only `benches/sync_pipeline.rs` as a Criterion benchmark.
Large corpus/replay/evidence harnesses are intentionally not shipped by this
runtime crate.

## Features
- `default` (enables `fjall`, `kernel`, and `zmq`): the performance-oriented fjall
  storage backend plus the bitcoinkernel consensus verifier and ZMQ notifications,
  so per-crate `cargo check` works out of the box. The `bitcoin-rs` binary's own
  defaults are the pure-Rust `fjall,redb,zmq`; `kernel` stays opt-in there.
- `rocksdb`, `fjall`, `redb`: forward the named storage backend to every subsystem
  crate.
- `mdbx`: forward the mdbx backend to the crates that provide one.
- `kernel`: route consensus verification through bitcoinkernel
  (`bitcoin-rs-consensus/kernel`).
- `prometheus-http`: enables the `metrics-exporter-prometheus/http-listener` feature;
  the production listener itself is controlled by `metrics_bind`.

Part of [`bitcoin-rs`](../../README.md); see [`CONCEPTS.md`](../../CONCEPTS.md) for the
project vocabulary.
