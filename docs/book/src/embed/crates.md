# Crate map

The workspace has five layers. A crate may depend only on crates in its own layer or a lower one, and the `g17_dependency_direction` gate fails the build on an upward edge or a cycle (`ARCH-01`, [architecture contract](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/architecture.md#arch-01-five-layer-one-way-dependency-direction)).

The dependency column is the normal (non-dev) edge set from `cargo metadata --no-deps`. Layer numbers come from the `approved_layer` table in the gate, which mirrors the contract's layer model.

```text
4  compose   bitcoin-rs, bitcoin-rs-node, e2e, snapshot,
             storage-footprint, contract-index, p2pk-scan, storage-convert
3  surface   bitcoin-rs-serving
2  services  execution, wire, mempool, projection
1  storage   bitcoin-rs-storage
0  core      consensus

Dependencies point down. No crate may depend on a crate in a higher layer, and a cycle fails the gate even inside one layer.

Layer 0 holds protocol types and validation with no storage, network, or filesystem I/O. Layer 1 is the only place an engine driver exists; everything above it reads and writes through `KvStore`. Layer 2 holds domain state and services, with `bitcoin-rs-execution` as the authoritative applied-chain owner. Layer 3 is the external protocol surface, and it reaches state only through capabilities passed in by the node. Layer 4 assembles the runtime or ships offline tooling; no other crate may depend on it.

The gate checks two rules on the resolved graph: every edge goes to the same or a lower layer, and no cycle exists even inside one layer. `ARCH-06` requires a gate-table update, a contract update, and a passing `g17_dependency_direction` run for any new crate or edge.

| Crate | Layer | Job | Depends on |
| --- | --- | --- | --- |
| [`bitcoin-rs-consensus`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/consensus/README.md) | 0 | Fixed-layout primitives, script interpreter, and consensus rule checks; native engine plus optional bitcoinkernel | none |
| [`bitcoin-rs-storage`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/storage/README.md) | 1 | `KvStore` facade, RocksDB backend, UTXO storage, block bodies, durable head, snapshots, checkpoints | consensus |
| [`bitcoin-rs-execution`](https://github.com/gosuda/bitcoin-rs/tree/main/crates/execution) | 2 | Authoritative applied-chain mutation, block tree, recovery, branch switching, checkpoint publication | consensus, storage |
| [`bitcoin-rs-projection`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/projection/README.md) | 2 | Confirmed transaction index, script history and live views, compact filters, prefix queries | consensus, execution, storage |
| [`bitcoin-rs-mempool`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/mempool/README.md) | 2 | Unconfirmed pool, cluster and replacement policy, packages, orphan parking, fee estimator | consensus |
| [`bitcoin-rs-wire`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/wire/README.md) | 2 | Wire codec, handshake, transport, listeners, addresses, compact block decode | consensus, storage |
| [`bitcoin-rs-serving`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/serving/README.md) | 3 | Core-compatible JSON-RPC, REST, Esplora, ZeroMQ, Stratum mining and pool surface | consensus, execution, mempool, projection, storage, wire |
| [`bitcoin-rs-node`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/node/README.md) | 4 | Composition, lifecycle, configuration resolution, mining coordination, pool ledger, typed embedding surface | every service crate |
| [`bitcoin-rs`](https://github.com/gosuda/bitcoin-rs/tree/main/bin/bitcoin-rs) | 4 | The daemon binary: option table, signal bridging, process entry | consensus, execution, node, storage, wire |
| [`bitcoin-rs-e2e`](https://github.com/gosuda/bitcoin-rs/tree/main/e2e) | 4 | Process-level end-to-end tests over public surfaces | serving |
| [`bitcoin-rs-snapshot`](https://github.com/gosuda/bitcoin-rs/tree/main/tools/snapshot) | 4 | Offline inspection and pinned-state verification of Core snapshots | consensus, storage |
| [`bitcoin-rs-storage-footprint`](https://github.com/gosuda/bitcoin-rs/tree/main/tools/storage-footprint) | 4 | Offline Linux filesystem allocation snapshot for benchmark evidence | none |
| [`contract-index`](https://github.com/gosuda/bitcoin-rs/tree/main/tools/contract-index) | 4 | Generates and checks the contract evidence index from clause tags | none |
| [`bitcoin-rs-p2pk-scan`](https://github.com/gosuda/bitcoin-rs/tree/main/tools/p2pk-scan) | 4 | Read-only listing of unspent pay-to-pubkey outputs from a raw block file | consensus, storage |
| [`bitcoin-rs-storage-convert`](https://github.com/gosuda/bitcoin-rs/tree/main/tools/storage-convert) | 4 | Offline migration tool for retired datadirs | storage |
Edges that are easy to misread:

- `bitcoin-rs-execution` does not depend on mempool, wire, projection, serving, node, or the binary. It composes consensus and storage capabilities only.
- `bitcoin-rs-wire` defines the `ChainQuery` and `TxInventory` traits; the node implements them over mempool and projection. Mempool never depends on wire, serving, node, or the binary.
- `bitcoin-rs-serving` depends directly on `bitcoin-rs-storage` for backend-neutral capabilities and shared storage-owned types (`ARCH-04`). It has no dependencies on concrete storage engine crates (`rust-rocksdb`, `surrealkv`, `signet-libmdbx`) and defines or forwards no storage backend features. The node supplies its capabilities through `Context::from_handles(ContextHandles)`. Serving uses those capabilities for storage access and chain operations, without independent database access or transition authority.
- `bitcoin-rs-storage` is the only crate allowed to name storage engine crates (`rust-rocksdb`, `surrealkv`, `signet-libmdbx`, and `tokio` for the SurrealKV bridge only) (`ARCH-02`); only `bitcoin-rs-storage-convert` may name `fjall` and `redb`, to read retired datadirs. Every other crate reaches state through `KvStore`.

Changing a layer assignment, adding a workspace crate, or adding a cross-crate edge requires the three steps in `ARCH-06`: update the gate table, update the architecture contract, and pass `g17_dependency_direction`.

The [architecture chapter](../how/architecture.md) traces how the runtime composes these crates.
