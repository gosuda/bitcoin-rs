# bitcoin-rs-node

The integration crate for running a synchronous `bitcoin-rs` node: layered
configuration, storage-backend selection, signal bridging, metrics/tracing setup,
startup crash recovery, and the central crossbeam-driven event loop that connects the
subsystem crates.

`run` is the top-level entry point: it loads the layered `Config` (with RPC `Auth`),
recovers via `crash_recovery`, and drives `event_loop`, the central synchronous loop.
`NodeState` holds the shared state and the `apply` block-apply pipeline;
`BlockSync` orchestrates block download; `reorg` switches the applied chain from one
branch to another. Adapters expose node state to the rest of the system —
`UtxoSetView` for consensus transaction checks, `NodeBlockSource` bridging in-memory
block records to the index crate's block source, `NodeP2pChainQuery` for server-side
P2P responders, and `BlockTreeContext` for BIP9 deployment state. Notifications leave
through the `ZmqPublisher` trait and its `SocketZmqPublisher` / `TracingZmqPublisher`
/ `NoOpZmqPublisher` implementations and the `TxIndexRuntime` worker; `signal` and
`shutdown` bridge process signals into graceful shutdown.

## Features
- `default` (enables `fjall` and `kernel`): the performance-oriented fjall storage
  backend plus the bitcoinkernel consensus verifier, so per-crate `cargo check` works
  out of the box.
- `rocksdb`, `fjall`, `redb`: forward the named storage backend to every subsystem
  crate.
- `mdbx`: forward the mdbx backend to the crates that provide one.
- `kernel`: route consensus verification through bitcoinkernel
  (`bitcoin-rs-consensus/kernel`).
- `checksig-census`: `kernel` plus the consensus crate's checksig-census
  instrumentation.
- `mimalloc`: pulls the optional `mimalloc` dependency; the
  `mainnet_prefix_replay` example registers it as the global allocator.
- `prometheus-http`: enables the `metrics-exporter-prometheus/http-listener` feature;
  the in-process metrics recorder does not start an HTTP listener.

Part of [`bitcoin-rs`](../../README.md); see [`CONCEPTS.md`](../../CONCEPTS.md) for the
project vocabulary.
