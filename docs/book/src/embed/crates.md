# Crate map

The workspace has five layers. A crate may depend only on crates in its own layer or a lower one, and the `g17_dependency_direction` gate fails the build on an upward edge or a cycle (`ARCH-01`, [architecture contract](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/architecture.md#arch-01-five-layer-one-way-dependency-direction)).

The dependency column is the normal (non-dev) edge set from `cargo metadata --no-deps`. Layer numbers come from the `approved_layer` table in the gate, which mirrors the contract's layer model.

```text
4  compose   bitcoin-rs, bitcoin-rs-node, e2e, snapshot,
             storage-footprint, contract-index, p2pk-scan
3  surface   bitcoin-rs-rpc
2  services  chain, chainstate, utxo, p2p, mempool, index, mining
1  storage   bitcoin-rs-storage
0  core      primitives, script, consensus
```

Dependencies point down. No crate may depend on a crate in a higher layer, and a cycle fails the gate even inside one layer.

Layer 0 holds protocol types and validation with no storage, network, or filesystem I/O. Layer 1 is the only place an engine driver exists; everything above it reads and writes through `KvStore`. Layer 2 holds domain state and services, with `chainstate` as the authoritative applied-chain owner. Layer 3 is the external protocol surface, and it reaches state only through capabilities passed in by the node. Layer 4 assembles the runtime or ships offline tooling; no other crate may depend on it.

The gate checks two rules on the resolved graph: every edge goes to the same or a lower layer, and no cycle exists even inside one layer. `ARCH-06` requires a gate-table update, a contract update, and a passing `g17_dependency_direction` run for any new crate or edge.

| Crate | Layer | Job | Depends on |
| --- | --- | --- | --- |
| [`bitcoin-rs-primitives`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/primitives/README.md) | 0 | Fixed-layout consensus types: hashes, outpoints, amounts, transaction, block, header, txid and wtxid | none |
| [`bitcoin-rs-script`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/script/README.md) | 0 | Native script interpreter, `VerifyFlags`, Taproot, sigop counting, signature cache | primitives |
| [`bitcoin-rs-consensus`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/consensus/README.md) | 0 | Transaction and block rule checks; native engine plus the optional bitcoinkernel capability | primitives, script |
| [`bitcoin-rs-storage`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/storage/README.md) | 1 | `KvStore` facade, RocksDB backend (Fjall and redb retired to `tools/storage-convert`), flat block files, durable head, snapshots, checkpoints | primitives |
| [`bitcoin-rs-utxo`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/utxo/README.md) | 2 | Live UTXO set, narrow apply/commit/disconnect contract, snapshot format, undo codec | primitives, storage |
| [`bitcoin-rs-chain`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/chain/README.md) | 2 | In-memory block tree, header acceptance with proof of work, best-tip selection, reorg planning | consensus, primitives |
| [`bitcoin-rs-chainstate`](https://github.com/gosuda/bitcoin-rs/tree/main/crates/chainstate) | 2 | Authoritative applied-chain mutation, recovery, branch switching, checkpoint publication | chain, consensus, primitives, script, storage, utxo |
| [`bitcoin-rs-index`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/index/README.md) | 2 | Confirmed transaction index, script history and live views, compact filters, prefix queries | chain, primitives, script, storage, utxo |
| [`bitcoin-rs-mempool`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/mempool/README.md) | 2 | Unconfirmed pool, cluster and replacement policy, packages, orphan parking, fee estimator | consensus, primitives, script |
| [`bitcoin-rs-p2p`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/p2p/README.md) | 2 | Wire codec, handshake, listeners, addresses, compact blocks, download window and block stager | chain, chainstate, consensus, index, mempool, primitives, storage |
| [`bitcoin-rs-mining`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/mining/README.md) | 2 | Candidate and template assembly, `MiningControl`, generation signal | chain, consensus, mempool, primitives, script, storage |
| [`bitcoin-rs-rpc`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/rpc/README.md) | 3 | Core-compatible JSON-RPC, REST, Esplora, and ZeroMQ surface | chain, consensus, index, mempool, mining, p2p, primitives, script, utxo |
| [`bitcoin-rs-node`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/node/README.md) | 4 | Composition, lifecycle, configuration resolution, typed embedding surface | every service crate |
| [`bitcoin-rs`](https://github.com/gosuda/bitcoin-rs/tree/main/bin/bitcoin-rs) | 4 | The daemon binary: option table, signal bridging, process entry | chainstate, consensus, node, storage |
| [`bitcoin-rs-e2e`](https://github.com/gosuda/bitcoin-rs/tree/main/e2e) | 4 | Process-level end-to-end tests over public surfaces | rpc |
| [`bitcoin-rs-snapshot`](https://github.com/gosuda/bitcoin-rs/tree/main/tools/snapshot) | 4 | Offline inspection and pinned-state verification of Core snapshots | primitives, utxo |
| [`bitcoin-rs-storage-footprint`](https://github.com/gosuda/bitcoin-rs/tree/main/tools/storage-footprint) | 4 | Offline Linux filesystem allocation snapshot for benchmark evidence | none |
| [`contract-index`](https://github.com/gosuda/bitcoin-rs/tree/main/tools/contract-index) | 4 | Generates and checks the contract evidence index from clause tags | none |
| [`bitcoin-rs-p2pk-scan`](https://github.com/gosuda/bitcoin-rs/tree/main/tools/p2pk-scan) | 4 | Read-only listing of unspent pay-to-pubkey outputs from a raw block file | primitives, script, utxo |

Edges that are easy to misread:

- `bitcoin-rs-utxo` sits in Layer 2 because it depends on storage for undo records and persisted coin statistics (`ARCH-01`).
- `bitcoin-rs-chainstate` does not depend on mempool, P2P, index, mining, RPC, node, or the binary. It composes protocol, chain, UTXO, and storage capabilities only.
- `bitcoin-rs-p2p` depends on mempool for the inventory view and the committed-mutation relay consumer. Mempool never depends on P2P, RPC, node, or the binary.
- `bitcoin-rs-rpc` has no dependency on `bitcoin-rs-storage` (`ARCH-04`). It reads storage-backed facts through node-supplied capabilities, never through a database handle.
- `bitcoin-rs-storage` is the only crate allowed to name storage engine crates (`rust-rocksdb`, `surrealkv`, `signet-libmdbx`, and `tokio` for the SurrealKV bridge only) (`ARCH-02`); only `bitcoin-rs-storage-convert` may name `fjall` and `redb`, to read retired datadirs. Every other crate reaches state through `KvStore`.

Changing a layer assignment, adding a workspace crate, or adding a cross-crate edge requires the three steps in `ARCH-06`: update the gate table, update the architecture contract, and pass `g17_dependency_direction`.

The [architecture chapter](../how/architecture.md) traces how the runtime composes these crates.
