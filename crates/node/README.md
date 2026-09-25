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

The node crate registers three benchmark targets: `benches/sync_pipeline.rs`,
a harness-less deterministic initial-sync proxy benchmark (its own `main`);
`benches/chainstate_journal.rs`, a harness-less journal replay performance
and memory gate (its own `main`); and `benches/evidence.rs`, the recorded
sync-pipeline evidence unit tests behind the built-in harness.

## Features
- `default` (enables `fjall`, `kernel`, and `zmq`): the performance-oriented fjall
  storage backend plus the bitcoinkernel consensus verifier and ZMQ notifications,
  so per-crate `cargo check` works out of the box. The `bitcoin-rs` binary's own
  defaults are the pure-Rust `fjall,redb,zmq`; `kernel` stays opt-in there. Issue
  #213 is the measurement gate for dropping `kernel` from this crate's defaults.
- `rocksdb`, `fjall`, `redb`: forward the named storage backend to every subsystem
  crate.
- `kernel`: route consensus verification through bitcoinkernel
  (`bitcoin-rs-consensus/kernel`).

Part of [`bitcoin-rs`](../../README.md); see [`CONCEPTS.md`](../../CONCEPTS.md) for the
project vocabulary.
