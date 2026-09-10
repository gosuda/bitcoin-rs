# bitcoin-rs-node

The integration crate for running a synchronous `bitcoin-rs` node: layered
configuration, storage-backend selection, signal bridging, metrics/tracing setup,
and the central crossbeam-driven event loop that connects the subsystem crates.

`config::resolve` combines configuration layers into a validated `NodeConfig`.
`run` accepts that configuration and separate `RuntimeInputs`, then drives the
shared lifecycle and central synchronous `event_loop`.
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

The node crate registers only `benches/sync_pipeline.rs` as a Criterion benchmark.
Large corpus/replay/evidence harnesses are intentionally not shipped by this
runtime crate.

## Configuration and lifecycle ownership

[`src/config.rs`](src/config.rs) is the public configuration facade. Its private
modules separate credentials (`auth`), network profiles (`network`), source-layer
DTOs and last-set-value-wins merging (`overrides`), resolved values (`types`),
defaults and cross-field validation (`resolution`), and non-configuration runtime
dependencies (`runtime`). Public imports through `config` and the crate root stay
stable. An absent override is not the same as an explicit `false`, zero, or empty
collection. Mining payout addresses are decoded against the final resolved
network, after every source layer has been applied.

[`src/run.rs`](src/run.rs) is the daemon wrapper over the shared lifecycle.
[`run/startup.rs`](src/run/startup.rs) composes and immediately records each
started service. [`run/rpc.rs`](src/run/rpc.rs) binds RPC over the node's existing
handles and uses the configuration's authentication conversion.
[`run/services.rs`](src/run/services.rs) owns startup rollback and the one ordered
teardown: request shutdown, wake and join the event loop, join core services,
drain subsystems, join bootstrap/checkpoint/signal workers, and only then publish
a clean checkpoint. Cleanup continues after a failure, retaining the first error;
any failure suppresses clean checkpoint publication.

P2P listener, outbound, DNS, and fixed-peer workers belong to `P2pService`, not a
parallel node implementation. Node lifecycle tests retain failure-injection
handles only under `cfg(test)`. Configuration regressions live in
[`config/tests.rs`](src/config/tests.rs); lifecycle regressions and shared isolated
fixtures live in [`run/services/tests.rs`](src/run/services/tests.rs).

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
