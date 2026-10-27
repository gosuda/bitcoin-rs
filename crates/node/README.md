# bitcoin-rs-node

Integration crate for running a synchronous `bitcoin-rs` node: layered configuration, storage backend selection, signal bridging, metrics/tracing setup, and the central crossbeam-driven event loop that composes chainstate with peer, mempool, mining, index, and RPC services.

`Node::start` boots the daemon service graph in-process on the caller runtime and returns an owned `Node`; `run()` runs the same lifecycle for the daemon. Typed reads mirror the RPC facts without JSON: `snapshot` and `settled_snapshot`, `sync_progress`, `capabilities`, `block_header`, `block_by_hash`, and `tx_by_id`. Admission shares the mempool gateway with RPC and Esplora: `broadcast` carries `sendrawtransaction`'s default fee-rate cap, and `broadcast_package` admits bounded child-with-independent-parents packages. `mining_control` borrows the attached coordinator. `subscribe_chain`, `poll_chain`, `replay_chain`, and `pin_chain` expose settled positional replay. `shutdown` consumes the node and publishes the clean checkpoint; a dropped node tears down without one.

Start here:

- [Embedded node lifecycle](../../docs/contracts/embedding.md) owns the `Node` lifecycle, readiness, broadcast, and shutdown contract; [architecture](../../docs/contracts/architecture.md#arch-05-node-composition-and-orchestration-boundary) owns the composition boundary.
- [Getting started](../../docs/getting-started.md) builds, configures, and runs the same service graph as a daemon.
- [`src/embed.rs`](src/embed.rs) and [`src/chain_feed.rs`](src/chain_feed.rs) hold the typed surface; [`tests/embed.rs`](tests/embed.rs) runs start, reads, broadcast, shutdown, and reopen in-process without an RPC socket.
- [LDK adapter](../../tools/ldk/README.md) borrows the production `Node` for block-source, fee-estimate, and broadcast traits; [Stratum V2 example](../../tools/stratum-sv2/README.md) runs the production `Node` behind the template-distribution adapter on regtest.

- `kernel`: compiles bitcoinkernel support in (`bitcoin-rs-consensus/kernel`).
  Selection is the runtime `validation.engine` setting (`native` by default);
  the feature alone never routes consensus verification to the kernel.

Part of [`bitcoin-rs`](../../README.md); see [`CONCEPTS.md`](../../CONCEPTS.md) for the
project vocabulary.
