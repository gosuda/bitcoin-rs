# Embedding the node

Link the `bitcoin-rs-node` crate when your process needs a node in its own address space and wants typed results instead of JSON-RPC. Run the `bitcoin-rs` binary when you want a separate process with RPC, REST, ZeroMQ, configuration files, and signal handling.

The two paths share one lifecycle. `run()` and `Node::start` both boot through `crates/node/src/lifecycle.rs::start_node`, so an embedder gets the same storage open, recovery, worker startup, and ordered teardown as the daemon (`EMB-01`, [embedding contract](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/embedding.md#invariants)).

In-process embedding fits tools that already own a Tokio runtime or an execution loop: the LDK adapter at [`tools/ldk`](https://github.com/gosuda/bitcoin-rs/tree/main/tools/ldk) uses the production `Node` for block source, fee estimates, and broadcast, and the Stratum V2 template provider at [`tools/stratum-sv2`](https://github.com/gosuda/bitcoin-rs/tree/main/tools/stratum-sv2) runs the node behind its adapter on regtest.

## The typed surface

`Node` exposes operations, not subsystem handles. No public embedding signature names a storage backend, `NodeStorage`, index internals, or `NodeState` (`EMB-03`). The composition boundary is owned by [`ARCH-05`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/architecture.md#arch-05-node-composition-and-orchestration-boundary), and the read-only capability rule by [`ARCH-09`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/architecture.md#arch-09-authoritative-owners-and-read-only-capability-boundaries). Node keeps no parallel admission store or notifier model.

| Need | Method | Notes |
| --- | --- | --- |
| Incident health | `consensus_quarantined()` | Check before consuming chain-dependent observations |
| Applied tip | `snapshot()` | `ChainSnapshot { epoch, sequence, tip_hash, tip_height }` |
| Sync projection | `sync_progress()` | Same fields as `getblockchaininfo` (`EMB-04`) |
| Index capability state | `capabilities()` | One `txindex` row from `CapabilitySnapshot` |
| Header by hash | `block_header(hash)` | Header, height, cumulative work; no body |
| Block by hash | `block_by_hash(hash)` | `Unavailable` when the body is pruned |
| Transaction lookup | `tx_by_id(txid)` | Mempool first, then the confirmed index (`EMB-06`) |
| Mempool statistics | `mempool_info()` | `MempoolStats` |
| Fee estimate | `fee_estimate(target)` | `None` when history is insufficient |
| Admission | `broadcast(tx)` | Same gateway as `sendrawtransaction` (`EMB-05`) |
| Package admission | `broadcast_package(txs)` | Bounded child-with-independent-parents CPFP |
| Mining control | `mining_control()` | Bounded to the node's lifetime |
| Chainstates | `chainstates_summary()` | Active and historical roles |
| Settled reads | `settled_snapshot()`, `subscribe_chain()`, `poll_chain()`, `pin_chain()`, `replay_chain()` | Replay is positional and bounded |
| Historical index reads | `transaction_at_prefix()`, `script_history_at_prefix()`, `spender_at_prefix()` | Synchronous, caller-selected prefix |

During quarantine, `tx_by_id()` returns the transaction for the requested ID and `mempool_info()` reports local pool statistics for diagnosis. Neither result establishes transaction confirmation or finality. Check `consensus_quarantined()` before interpreting diagnostic observations as current. New broadcasts, mining work, fee estimates, snapshot activation and historical prefix queries are unavailable.

Every read mirrors an RPC fact without JSON: `snapshot()` is the coherent applied-tip cell, and `sync_progress()` runs the `getblockchaininfo` projection through the same `ChainHandles` code the RPC dispatcher uses. Settled reads exist for followers that must not observe a half-applied transition; the plain `snapshot()` keeps live applied-tip semantics.

Historical prefix reads are blocking and take no live UTXO or chain-transition lock. Each call returns its own covered prefix, so compare prefixes instead of assuming one anchor. Absence is scoped to the returned range, never a global negative, and no mempool data is merged in. The consistency rules are owned by `IDX-12`; the calling shape is in the [embedding contract](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/embedding.md#historical-prefix-reads).

## Feature flags

The node crate's default features are `fjall` and `zmq`. Storage backend features only compile an engine in; the runtime `storage.backend` setting selects it, and a build that lacks the selected backend refuses to start.

| Feature | Effect | Use |
| --- | --- | --- |
| `fjall` | Compiles the default storage engine | Keep unless packaging a different backend |
| `redb` | Compiles the redb backend and its fixed-width transaction index | Alternative backend |
| `rocksdb` | Compiles the RocksDB backend | Alternative backend |
| `zmq` | Compiles the ZeroMQ publisher surface | Only when notifications are needed |
| `kernel` | Compiles bitcoinkernel support in | Oracle runs; never selects the engine by itself |
| `silent-payments` | Enables the silent-payments RPC subset | Only when that surface is needed |
| `pool` | Enables the native pool surface | Pool operators |
| `pool-sv2` | Adds Stratum V2 transport on top of `pool` | Pool operators |
| `test-seam` | Exposes `NodeState` and fixtures | Tests and benchmarks only |

`test-seam` is not a production feature. The `g17_dependency_direction` gate rejects any production dependency or feature that enables it ([`bin/bitcoin-rs/tests/support/dependency_graph.rs`](https://github.com/gosuda/bitcoin-rs/blob/main/bin/bitcoin-rs/tests/support/dependency_graph.rs)), and `EMB-03` forbids a production edge to the seam. Embedders that need richer access add their own wrapper around the typed methods.

The `kernel` feature is a capability, not a choice. A build with it still runs native verification unless `validation.engine = "kernel"` is set, and the default binary leaves it out (`VAL-03`). The [validation chapter](../how/validation.md) covers the engine distinction.

## A Cargo.toml that compiles

The workspace crates are path dependencies in this repository. Point the path at your checkout; set `default-features = false` and choose the backends you ship.

```toml
[package]
name = "embed-tip"
version = "0.1.0"
edition = "2024"

[dependencies]
bitcoin-rs-node = { path = "../bitcoin-rs/crates/node", default-features = false, features = ["fjall"] }
tokio = { version = "1", features = ["rt-multi-thread"] }
tempfile = "3"
```

The node never creates, enters, or retains a runtime (`EMB-02`). `Node::start` and `Node::shutdown` are `async fn` values that do their synchronous work when polled, so the caller supplies the executor. The example uses a Tokio runtime; a different executor works if it can poll the futures.

## A complete example

This program starts a regtest node on a fresh temporary data directory, prints the applied tip, and shuts down. It clears the P2P listener, binds RPC to an ephemeral loopback port, and disables metrics so it needs no fixed ports and no network.

```rust
use bitcoin_rs_node::{Network, Node, NodeConfig, RuntimeInputs};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;

    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    config.rpc.bind = "127.0.0.1:0".parse()?;
    config.observability.metrics_bind = None;

    let runtime = tokio::runtime::Runtime::new()?;
    let node = runtime.block_on(Node::start(config, RuntimeInputs::default()))?;

    let tip = node.snapshot();
    println!("tip height={} hash={}", tip.tip_height, tip.tip_hash);

    runtime.block_on(node.shutdown())?;
    Ok(())
}
```

Compiled and run against this repository:

```text
$ cargo run --offline --locked
tip height=0 hash=0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206
```

A fresh regtest chain has only the genesis block, so height 0 and the regtest genesis hash are the correct readiness result. The node does not mine or connect to peers in this configuration.

`Node::start` returns after storage opens, recovery finishes, and workers start. The first `snapshot()` is the readiness fact; there is no separate ready flag and no sleep to wait out.

## Threads and blocking

The node drives its own threads synchronously. `Node::start` and `Node::shutdown` run their real work when the future is polled, so polling them on a shared async worker blocks that worker for the duration. Start the node from `spawn_blocking`, a dedicated thread, or a runtime you own for this purpose.

The node itself spawns the event loop, RPC listeners, P2P workers, index worker, and metrics. Do not wrap those in your own tasks or expect `Node` to yield while they run.

`RuntimeInputs::with_shutdown(receiver)` lets your process trigger the same shutdown path from a signal handler or supervisor channel. Without it, only `Node::shutdown` or `Drop` stops the node.

## Failures you will see

`Node::start` returns `NodeError::Startup` for configuration, storage, recovery, or bind failures, and it rolls back through the same ordered teardown with no clean checkpoint. `Node::shutdown` returns `NodeError::Shutdown` only from a consuming shutdown, never from `Drop`. Reads return `Unavailable` when a capability is disabled and `NotFound` when a proven-absent transaction is requested. Prefix reads return `HistoricalQueryError`, not `NodeError`.

Two startup refusals matter for embedders:

- An empty `data_dir` fails `NodeConfig::validate` with `ConfigError::DataDirEmpty`.
- A directory already locked by another node fails with `DataDirLockError::InUse`, mapped to `NodeError::Startup`.

The [node lifecycle](lifecycle.md) chapter covers shutdown ordering, the data-directory lock, and failure settlement. The [crate map](crates.md) lists what each workspace crate owns.
