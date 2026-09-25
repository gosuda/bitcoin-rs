# Architecture contract

The normative contract for workspace crate layering, one-way dependency
direction, storage engine confinement, and composition boundaries.

Owners:
- `Cargo.toml`, `crates/*/Cargo.toml`, `bin/bitcoin-rs/Cargo.toml`
- Workspace dependency gate in `bin/bitcoin-rs/tests/gates/g17_dependency_direction.rs`

## Layer model

| Layer | Crates | Responsibility |
| --- | --- | --- |
| 4: Compose | `node`, `bitcoin-rs`, `e2e` | Runtime assembly and lifecycle |
| 3: Surface | `rpc` | External protocol boundaries |
| 2: Services | `chain`, `chainstate`, `utxo`, `p2p`, `mempool`, `index`, `mining` | Domain state and services |
| 1: Storage | `storage` | Storage contracts and engine drivers |
| 0: Core | `primitives`, `script`, `consensus` | Protocol types and validation, without storage or I/O |

Crate names use the `bitcoin-rs-` prefix except for the `bitcoin-rs` binary.

## Clauses

### `ARCH-01`: Five-layer one-way dependency direction

- Every workspace crate is assigned to an approved layer (0 to 4).
- A crate may depend only on crates in the same layer or a strictly lower layer.
  Edges pointing upward or across forbidden boundaries fail the
  `g17_dependency_direction` gate.
- The resolved workspace dependency graph is a directed acyclic graph. Any
  cycle among workspace crates, even within the same layer, fails the gate.
- Crate layer assignments:
  - **Layer 0 (Core)**: `bitcoin-rs-primitives`, `bitcoin-rs-script`,
    `bitcoin-rs-consensus`. Pure protocol types, consensus verification, and
    script interpreter logic. Layer 0 crates have zero dependencies on storage,
    network, or filesystem I/O.
  - **Layer 1 (Storage)**: `bitcoin-rs-storage`. Key-value storage abstractions,
    batching primitives, and backend engine drivers.
  - **Layer 2 (Services)**: `bitcoin-rs-chain`, `bitcoin-rs-chainstate`, `bitcoin-rs-utxo`,
    `bitcoin-rs-p2p`, `bitcoin-rs-mempool`, `bitcoin-rs-index`,
    `bitcoin-rs-mining`. Domain services and capability runtimes.
    `chainstate` is the authoritative applied-chain owner. It composes only
    lower/same-layer protocol, chain, UTXO, and storage capabilities; it must
    not depend on mempool, P2P, index, mining, RPC, node, or the binary.
    `chain` and `utxo` sit in Layer 2 because they depend on `storage` for
    block index records, undo storage, and UTXO snapshots. `chain` also
    depends on `consensus` for BIP9 parameters and the BIP113 locktime
    cutoff. `mining` sits in Layer 2 because it depends on `mempool` for
    candidate selection and `chain` for candidate header/work/time context.
    `p2p` depends on `mempool` for the transaction inventory view and
    committed-mutation relay consumer. This same-layer edge keeps peer
    protocol mechanics with their consumer; `mempool` must not depend on
    `p2p`, `rpc`, `node`, or the binary. Admission retains peer attribution
    as data without owning connections or runtime assembly. The
    `g17_dependency_direction` gate checks this boundary explicitly.
  - **Layer 3 (Surface)**: `bitcoin-rs-rpc`. External wire protocols and RPC
    handlers, including the Bitcoin Core-compatible ZMQ protocol and transport.
  - **Layer 4 (Compose)**: `bitcoin-rs-node`, `bitcoin-rs`, `bitcoin-rs-e2e`.
    Daemon assembly, subsystem lifecycle coordination, and CLI binary entry
    points. `bitcoin-rs-e2e` is the process-level test harness that drives
    the composed daemon and the pinned reference node over their public
    surfaces only; it declares no internal dependencies and no workspace
    crate may depend on it.
- **Explicit non-goal**: Layer numbers do not justify speculative new crates or
  thin wrapper layers. A boundary exists only when it isolates external
  dependencies, enforces safety/consensus boundaries, or separates independent
  runtime lifecycles.

### `ARCH-02`: Exclusive storage engine dependency ownership

- `bitcoin-rs-storage` is the sole crate in the workspace permitted to depend on
  underlying storage engine crates (`fjall`, `redb`, `rust-rocksdb`).
- No crate outside `bitcoin-rs-storage` may name a storage engine dependency in
  `[dependencies]`, `[build-dependencies]`, or `[dev-dependencies]`.
- All higher layers interact with persistent state through the `KvStore` facade
  and storage abstractions exported by `bitcoin-rs-storage`.

### `ARCH-03`: Storage backend feature forwarding confinement

- Backend feature forwarding (`fjall`, `redb`, `rocksdb`) is strictly
  confined to:
  1. Operator-facing entry points (`bitcoin-rs-node`, `bitcoin-rs`) that expose
     backend selection to operators and packaging scripts.
  2. Services-tier adapter crates (`bitcoin-rs-chain`, `bitcoin-rs-chainstate`,
     `bitcoin-rs-utxo`, `bitcoin-rs-p2p`, `bitcoin-rs-index`) whose features exist solely so `-p`
     package builds propagate backend selection into `bitcoin-rs-storage`.
  3. `bitcoin-rs-storage` itself, which owns the concrete backend engine
     dependencies and exposes them through the `KvStore` facade.
- Crates in Layer 0 (Core) and Layer 3 (Surface / RPC) must never define or
  forward storage backend features.
- `bitcoin-rs-mempool` and `bitcoin-rs-mining` do not own storage and must not
  define or forward backend feature names; an empty `rocksdb = []` marker
  counts as defining a backend feature and is forbidden.
- `bitcoin-rs-node` and `bitcoin-rs` may forward backend selection only into
  engine-selecting crates (`bitcoin-rs-storage`, `bitcoin-rs-chain`,
  `bitcoin-rs-chainstate`, `bitcoin-rs-utxo`, `bitcoin-rs-p2p`,
  `bitcoin-rs-index`).
- `fjall` is the default shipped product backend. `redb` and `rocksdb` are
  retained shipped alternatives and independent product-matrix comparisons.
  MDBX had only a diagnostic role and no current consumer; it is removed as a
  complete ownership unit. Existing MDBX datadirs are not migrated or opened.
- `crates/node/src/storage_backend.rs` is the sole owner of concrete runtime
  backend construction in the node. Chainstate and txindex each cross that
  boundary once, then immediately compose backend-neutral capabilities for
  undo, pruning, journal, indexing, and footprint inspection. The consumer
  visitor is only a composition seam; `KvStore` remains the owner of reads,
  writes, batches, and durability. The txindex redb lane retains its specialized
  fixed-width store rather than being widened to the generic redb adapter.

### `ARCH-04`: RPC surface independence from storage

- `bitcoin-rs-rpc` must have zero non-test dependency edges on
  `bitcoin-rs-storage` and zero dependencies on storage engine crates.
- RPC consumes node capabilities (chain, mempool, index, network, mining, utxo)
  exclusively through the capability groups `Context` stores (`ChainHandles`,
  `MempoolHandles`, `IndexHandles`, `NetworkHandles`, `MiningHandles`), never
  through direct database access. `Context::from_handles(ContextHandles)` is
  the single composition point: one `ContextHandles` value carries every
  capability, including the chain owner's transition barrier, and nothing
  attaches to a built `Context`.
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
  p2p, template assembly and the mining control contract in mining, and index
  schemas in their owning crates. `bitcoin-rs-mining` owns `Candidate`,
  `BlockTemplate`, `MiningInfo`, and `MiningControl`, plus the candidate
  lifecycle: the `(applied_tip_hash, mempool_sequence)` generation key, the
  bounded template cache with single-flight assembly, long-poll publication,
  and BIP22/BIP23 template projection (`MiningService`, fed by node-owned
  capability sources). Mining also owns `MiningGenerationSignal` (the
  authoritative-mutation wake seam, `generation_signal`), `getnetworkhashps`
  estimation (`network_hashps`), and the BIP22/`submitheader` reject
  vocabulary (`bip22`). RPC maps those types onto BIP22/BIP23 JSON and does
  not cache templates or long-poll.
- `bitcoin-rs-mempool` owns transaction admission preparation and retry,
  orphan bodies and their indexes, ready-orphan work, and recent rejects
  through the shared `MempoolGateway`. It also owns the fee-estimator history
  file format and its atomic datadir persistence (`fee_history`,
  `fee-estimator-history.dat`); node only calls `load` at open and `save` at
  shutdown. `bitcoin-rs-p2p` owns the transaction
  inventory implementation, missing-parent requests, source-connection checks,
  and the bounded transaction relay queue, worker, and saturation policy.
  Node supplies the chain view, connects committed admission results to relay
  and mining, and owns channel wiring and worker startup/shutdown. It keeps no
  second admission-state store or transaction policy implementation. Admission
  sequencing follows [MPL-04](mempool-mutations.md); wire behavior and its
  deviations follow [P2P-01](p2p-wire.md).
- `bitcoin-rs-node` owns runtime startup/shutdown sequencing, configuration
  resolution and validation (`UserConfig` layers → `NodeConfig`), the mining
  control facade (`MiningCoordinator`: it composes the mining lifecycle
  service with the chainstate/follower handles, publishes applied tips,
  submits solved blocks, and admits headers),
  watch-only coinbase payout configuration (`MiningConfig::payout_script`), and
  process-level cache budgeting (`dbcache` distribution across chainstate and
  txindex namespaces). The `bitcoin-rs` binary owns argv, environment, and
  TOML parsing. Applied-tip mutation, recovery, checkpoint publication,
  retention, and branch switching are owned by `bitcoin-rs-chainstate`
  (`ARCH-07`), not by a public field bag of subsystem handles.
- `bitcoin-rs-rpc::zmq` owns ZMQ topics, framing, HWM validation, socket
  transport, mempool sequence projection, and live notifier enumeration.
  `bitcoin-rs-node` constructs and wires the publisher and continues to own when
  committed chain effects are emitted. The same live publisher is the source for
  `getzmqnotifications`; node does not keep a parallel notifier metadata model.
  The `g17_dependency_direction` gate pins the external `zmq` dependency to the
  surface crate and permits node only to forward `bitcoin-rs-rpc/zmq`.
- `ARCH-07` owns transition reservation and post-commit follower dispatch.
- `UserConfig::overlay` applies a later layer field-wise: a set field replaces
  the earlier value; an unset field leaves it. Nested override structs merge
  the same way, including `ChainstateJournalOverrides` and `MiningOverrides`. Proof:
  `crates/node/src/config.rs` tests `user_config_overlay_lets_set_fields_win` and
  `mining_payout_overlay_lets_the_later_address_win`.

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

### `ARCH-07`: Chainstate owns authoritative applied-chain mutation

- `bitcoin_rs_chainstate::Chainstate` is the in-process owner of applied-tip
  mutation, recovery, branch switching, checkpoint publication, and retention.
  `NodeState`, `BlockSync`, mining, and RPC chain-control hold or clone that
  service; they do not assemble a transition from independent locks.
- `Chainstate::begin_transition` and `TransitionLock::into_transition` are the
  only constructors of a `ChainTransition`. Reorg planning that must abort
  without mutating takes `lock_transition` first and promotes the lock with
  `into_transition` only after the authoritative plan matches the preloaded
  plan.
- Snapshot reads (`Chainstate::snapshot`) copy the independently published
  header tip and a coherent applied-tip / chain-tx-count pair. They do not
  take the transition lock and cannot mutate chainstate. `ChainEventPublisher`
  cells remain a separate coherent snapshot of the applied tip for index
  consumers (`EVT-01`).
- `Chainstate::validate_block` dry-runs the apply path's pre-write consensus
  gates under `lock_transition`. It does not take mempool generation and does
  not persist. BIP22 proposal omits proof-of-work; every other pre-write gate
  is the same function commit runs. Owner: `crates/chainstate/src/lib.rs`.
- Authoritative apply lives in `crates/chainstate`. The crate does not hold
  or import mempool, RPC, ZMQ, index, mining, P2P, or node types. Apply publishes the tip and
  returns a `ConnectOutcome` or `DisconnectOutcome`. Capture flags
  are set at construction so apply can produce
  `rawtx` and canonical block bytes without holding the consumers.
- Node owns cross-domain sequencing around a chain transition: it reserves the
  mempool generation, dispatches `ChainFollowers`, then publishes the stable
  mempool generation before the chain transition is dropped. Convenience
  chainstate methods do not dispatch followers.
  RPC `BlockLog`, hash/raw ZMQ, TxIndex wake, sequence `C`/`D`, mining
  generation, admission, block-confirmation eviction, and reorg
  reconsideration run from node-owned dispatch. Consumer failure cannot
  invalidate chainstate. Issue #77
  owns the durable event journal; this is dependency direction, not a second
  event contract. Do not push cross-store ordering into `utxo` or `storage`.
- Reorg planning, body retention/loading, disconnect/connect execution,
  invalidation, and checkpoint-debt settlement live in chainstate. Node supplies
  a `ReorgObserver` for mempool/follower effects and holds the mempool
  generation fence around the operation. Reorg body memory is bounded by the
  chainstate streaming window; no whole departed branch is retained.

### `ARCH-08`: Durable pruning and reorg retention

- Transaction-cache pruning must not remove transactions from a block above
  the durable checkpoint's reorg-retention floor. A requested prune height
  becomes eligible only after durability has been published through
  `CORE_REORG_SAFETY_MARGIN`; this protects reconsideration of disconnected
  transactions during reorg handling.

## Remaining composition boundary

`crates/chainstate` owns authoritative applied-chain mutation, recovery,
checkpoint payload assembly/publication, reorg, and retention. Storage still
owns generic journal/checkpoint formats, filesystem operations, backend
drivers, and durability primitives. Node owns process configuration, concrete
backend selection, mempool/P2P/index/mining/RPC wiring, and post-commit
cross-domain effects. Backend construction stays at the `ARCH-03`
composition seam.

## Proven by

- `bin/bitcoin-rs/tests/gates/g17_dependency_direction.rs`:
  - `workspace_dependency_direction_is_one_way`: parses `cargo metadata --no-deps`,
    validates every internal workspace dependency edge against the approved
    layer table, rejects any workspace dependency cycle, and verifies
    `bitcoin-rs-mempool` does not depend on its transaction consumers (`p2p`,
    `rpc`, `node`, or the binary). It also verifies `bitcoin-rs-storage`
    exclusively owns storage engine dependencies, confirms `bitcoin-rs-rpc` has
    no dependency on storage and forwards no backend features, and verifies
    backend feature forwarding is confined to operator tiers and service
    adapters, and rejects empty backend markers on crates that do not own an
    engine.
- Manifest enforcement:
  - Root `Cargo.toml`: workspace member list and package versions.
  - `crates/storage/Cargo.toml`: engine dependency definitions.
  - `crates/rpc/Cargo.toml`: zero storage backend dependencies or features.
  - `crates/node/Cargo.toml` and `bin/bitcoin-rs/Cargo.toml`: confined
    operator-tier backend feature flags.
- `crates/chainstate/tests/unit/apply/admission_tests.rs` and
  `crates/chainstate/tests/unit/apply/chain_tx_count_tests.rs` cover admission
  shutdown and coherent chain transaction-count publication. Checkpoint and
  journal tests moved with their owner under `crates/chainstate/tests/unit/`.
- `crates/node/src/chain_effects.rs` and node mining/sync/reorg integration
  tests prove that mempool/follower work consumes committed chainstate outcomes
  without making chainstate depend on those consumers.
- `crates/node/src/chain_effects.rs` tests `noop_asks_for_no_payloads`,
  `connect_then_disconnect_rewinds_the_rpc_log_and_emits_in_order`,
  `disconnect_does_not_pop_a_different_tail`: post-commit RPC/ZMQ work is
  owned by `ChainEffects`, not by apply; the connect/disconnect test also
  proves that the configured ZMQ publisher receives the committed effects.
- `crates/node/src/config.rs` test `user_config_overlay_lets_set_fields_win`:
  later `UserConfig` layers win on set fields, including nested
  `ChainstateJournalOverrides` (`ARCH-05`).
- `crates/node/src/config.rs` test `mining_payout_overlay_lets_the_later_address_win`
  and `crates/node/tests/config_layered.rs` test
  `mining_payout_address_decodes_after_all_layers`: watch-only mining payout is
  decoded once after overlay, against the resolved network (`ARCH-05`).
