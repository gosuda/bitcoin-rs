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
  parsing, and process-level cache budgeting (`dbcache` distribution across
  chainstate and txindex namespaces).

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

## Live gaps

- **Node slimming and extraction (#217)**: While peer connection lifecycle
  ownership has moved to `crates/p2p` (#215), `crates/node` still carries legacy
  domain mechanics: UTXO undo persistence and disconnect markers (`apply.rs`),
  the P2P download scheduler (`sync.rs`), direct backend construction and cache
  share dispatch (`state.rs`), and offline custody/test tooling (`corpus.rs`,
  `g2_muhash.rs`, `g14_utxo_commit.rs`). Relocating these domain-owned mechanics
  into `crates/utxo`, `crates/storage`, `crates/p2p`, and dedicated tooling
  crates remains tracked under #217 (open). `crates/node` is the composition
  layer, but is not yet fully slim.

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
