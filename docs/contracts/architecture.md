# Architecture contract

The normative contract for workspace crate layering, one-way dependency
direction, storage engine confinement, and composition boundaries.

Owners:
- `Cargo.toml`, `crates/*/Cargo.toml`, `bin/bitcoin-rs/Cargo.toml`
- Workspace dependency gate in `bin/bitcoin-rs/tests/gates/g17_dependency_direction.rs`

## Layer model

```text
  ┌─────────────────────────────────────────────────────────────────────────┐
  │ Layer 4: Compose                                                        │
  │   bitcoin-rs-node, bitcoin-rs                                           │
  │   - Lifecycle orchestration, runtime assembly, config, cache allocation │
  └────────────────────────────────────┬────────────────────────────────────┘
                                       ▼
  ┌─────────────────────────────────────────────────────────────────────────┐
  │ Layer 3: Surface                                                        │
  │   bitcoin-rs-rpc                                                       │
  │   - Protocol boundaries and RPC dispatch                               │
  └────────────────────────────────────┬────────────────────────────────────┘
                                       ▼
  ┌─────────────────────────────────────────────────────────────────────────┐
  │ Layer 2: Services                                                       │
  │   bitcoin-rs-chain, bitcoin-rs-utxo, bitcoin-rs-p2p,                    │
  │   bitcoin-rs-mempool, bitcoin-rs-index, bitcoin-rs-mining               │
  │   - Domain capabilities, index query runtimes, network protocol state   │
  └────────────────────────────────────┬────────────────────────────────────┘
                                       ▼
  ┌─────────────────────────────────────────────────────────────────────────┐
  │ Layer 1: Storage                                                        │
  │   bitcoin-rs-storage                                                    │
  │   - Storage abstractions (KvStore), exclusive owner of engine deps      │
  └────────────────────────────────────┬────────────────────────────────────┘
                                       ▼
  ┌─────────────────────────────────────────────────────────────────────────┐
  │ Layer 0: Core                                                           │
  │   bitcoin-rs-primitives, bitcoin-rs-script, bitcoin-rs-consensus          │
  │   - Protocol types, script validation, consensus rules; zero storage/IO │
  └─────────────────────────────────────────────────────────────────────────┘
```

## Clauses

### `ARCH-01`: Five-layer one-way dependency direction

- Every workspace crate is assigned to an approved layer (0 to 4).
- A crate may depend only on crates in the same layer or a strictly lower layer.
  Edges pointing upward or across forbidden boundaries fail the
  `g17_dependency_direction` gate.
- Crate layer assignments:
  - **Layer 0 (Core)**: `bitcoin-rs-primitives`, `bitcoin-rs-script`,
    `bitcoin-rs-consensus`. Pure protocol types, consensus verification, and
    script interpreter logic. Layer 0 crates have zero dependencies on storage,
    network, or filesystem I/O.
  - **Layer 1 (Storage)**: `bitcoin-rs-storage`. Key-value storage abstractions,
    batching primitives, and backend engine drivers.
  - **Layer 2 (Services)**: `bitcoin-rs-chain`, `bitcoin-rs-utxo`,
    `bitcoin-rs-p2p`, `bitcoin-rs-mempool`, `bitcoin-rs-index`,
    `bitcoin-rs-mining`. Domain services and capability runtimes.
    `chain` and `utxo` sit in Layer 2 because they depend on `storage` for
    block index records, undo storage, and UTXO snapshots. `mining` sits in
    Layer 2 because it depends on `mempool` for candidate selection.
  - **Layer 3 (Surface)**: `bitcoin-rs-rpc`. External wire protocols and RPC
    handlers.
  - **Layer 4 (Compose)**: `bitcoin-rs-node`, `bitcoin-rs`. Daemon assembly,
    subsystem lifecycle coordination, and CLI binary entry points.
- **Explicit non-goal**: Layer numbers do not justify speculative new crates or
  thin wrapper layers. A boundary exists only when it isolates external
  dependencies, enforces safety/consensus boundaries, or separates independent
  runtime lifecycles.

### `ARCH-02`: Exclusive storage engine dependency ownership

- `bitcoin-rs-storage` is the sole crate in the workspace permitted to depend on
  underlying storage engine crates (`fjall`, `redb`, `rust-rocksdb`,
  `signet-libmdbx`).
- No crate outside `bitcoin-rs-storage` may name a storage engine dependency in
  `[dependencies]`, `[build-dependencies]`, or `[dev-dependencies]`.
- All higher layers interact with persistent state through the `KvStore` facade
  and storage abstractions exported by `bitcoin-rs-storage`.

### `ARCH-03`: Storage backend feature forwarding confinement

- Backend feature forwarding (`fjall`, `redb`, `rocksdb`, `mdbx`) is strictly
  confined to:
  1. Operator-facing entry points (`bitcoin-rs-node`, `bitcoin-rs`) that expose
     backend selection to operators and packaging scripts.
  2. Services-tier adapter crates (Layer 2) whose features exist solely so `-p`
     package builds propagate backend selection into `bitcoin-rs-storage`.
- Crates in Layer 0 (Core) and Layer 3 (Surface / RPC) must never define or
  forward storage backend features.

### `ARCH-04`: RPC surface independence from storage

- `bitcoin-rs-rpc` must have zero non-test dependency edges on
  `bitcoin-rs-storage` and zero dependencies on storage engine crates.
- RPC consumes node capabilities (chain, mempool, index, mining, p2p, utxo)
  exclusively through capability query handles and domain context interfaces
  (`Context`, `ContextHandles`), never through direct database access.
- `bitcoin-rs-rpc` defines and forwards zero backend features. (The bench-only
  dev-dependency used for offline `txoutproof` fixtures is isolated to test
  scope and documented in `crates/rpc/Cargo.toml`).

### `ARCH-05`: Node composition and orchestration boundary

- `bitcoin-rs-node` (Layer 4) is the assembly and lifecycle orchestration layer.
  It wires together storage backends, consensus validators, mempool gateway, P2P
  listeners, index reconciliation workers, and RPC services into an executable
  node runtime.
- Domain mechanics belong to domain crates: consensus rules in consensus/script,
  mempool admission and mutation sequencing in mempool, connection lifecycle in
  p2p, template assembly in mining, and index schemas in their owning crates.
- `bitcoin-rs-node` owns runtime startup/shutdown sequencing, configuration
  resolution and validation (`UserConfig` layers → `NodeConfig`), and
  process-level cache budgeting (`dbcache` distribution across chainstate and
  txindex namespaces). The `bitcoin-rs` binary owns argv, environment, and
  TOML parsing. Applied-tip mutation is owned by the chainstate facade
  (`ARCH-07`), not by a public field bag of subsystem handles.

### `ARCH-06`: Hierarchy change and exception process

- Any change to workspace crate layer assignments, introduction of new workspace
  crates, or addition of cross-crate dependencies requires:
  1. Updating the `approved_layer` table or engine crate assertions in
     `bin/bitcoin-rs/tests/gates/g17_dependency_direction.rs`.
  2. Updating this normative contract (`docs/contracts/architecture.md`) with
     the rationale and invariant justification.
  3. Passing the `g17_dependency_direction` gate test.
- Speculative or circular dependency edges that violate the one-way flow are
  rejected by automated gate enforcement in CI.

### `ARCH-07`: Chainstate facade owns transition admission

- `bitcoin_rs_node::Chainstate` is the in-process owner of applied-tip
  mutation. `NodeState`, `BlockSync`, mining, and RPC chain-control hold or
  clone that facade; they do not assemble a transition from independent locks.
- `Chainstate::begin_transition` is the only public constructor of a
  `ChainTransition`. Reorg planning that must abort without mutating takes
  `lock_transition` first and promotes it with `begin_transition_locked` only
  after the authoritative plan matches the preloaded plan.
- Snapshot reads (`Chainstate::snapshot`, `ChainEventPublisher` cells) copy
  published values. They do not take the transition lock and cannot mutate
  chainstate.
- Authoritative apply still lives in `crates/node` because it composes chain,
  consensus, utxo, and storage. Optional consumers (RPC `BlockLog`, ZMQ,
  TxIndex wake) remain wired here until #77's committed-event consumers own
  them. Do not push cross-store ordering into `utxo` or `storage`.

## Live gaps

- **Node slimming and extraction (#217)**: Peer connection session and lease
  ownership has moved to `PeerTable` in `crates/p2p` (#215, #217), orphaned
  node corpus tooling (`corpus.rs`) was dropped, and applied-tip mutation now
  goes through the `Chainstate` / `ChainTransition` facade (`ARCH-07`).
  `crates/node` still carries download scheduling (`sync.rs`), storage-backend
  construction (`state.rs`), and post-commit RPC/ZMQ/index wiring inside
  apply. Relocating those remaining domain-owned mechanics remains tracked
  under #217. A dedicated `crates/chainstate` waits until the facade is
  dependency-acyclic.

## Proven by

- `bin/bitcoin-rs/tests/gates/g17_dependency_direction.rs`:
  - `workspace_dependency_direction_is_one_way`: parses `cargo metadata --no-deps`,
    validates every internal workspace dependency edge against the approved
    layer table, verifies `bitcoin-rs-storage` exclusively owns storage engine
    dependencies, confirms `bitcoin-rs-rpc` has no dependency on storage and
    forwards no backend features, and verifies backend feature forwarding is
    confined to operator tiers and service adapters.
- Manifest enforcement:
  - Root `Cargo.toml`: workspace member list and package versions.
  - `crates/storage/Cargo.toml`: engine dependency definitions.
  - `crates/rpc/Cargo.toml`: zero storage backend dependencies or features.
  - `crates/node/Cargo.toml` and `bin/bitcoin-rs/Cargo.toml`: confined
    operator-tier backend feature flags.
- `crates/node/src/apply.rs` tests `snapshot_reads_applied_tip_without_taking_a_transition`,
  `chain_transition_connect_and_finish_publish_the_new_tip`: the facade
  copies published tips without reserving generation, and connect/finish
  through `ChainTransition` is the mutation path.
