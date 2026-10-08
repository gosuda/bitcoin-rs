# Architecture contract

The normative contract for workspace crate layering, one-way dependency
direction, storage engine confinement, and composition boundaries.

These boundaries are internal architecture, not a compatibility promise:
they are the replaceable side of the project's external-contracts
boundary. A demonstrated better internal design may redraw them — the
`ARCH-06` change process governs layer assignments and workspace
dependency boundaries.

Owners:
- `Cargo.toml`, `crates/*/Cargo.toml`, `bin/bitcoin-rs/Cargo.toml`
- Workspace dependency gate in `bin/bitcoin-rs/tests/gates/g17_dependency_direction.rs`

## Layer model

| Layer | Crates | Responsibility |
| --- | --- | --- |
| 4: Compose | `node`, `bitcoin-rs`, `e2e`, `storage-footprint` | Runtime assembly, lifecycle, and offline tooling |
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
- The [layer model](#layer-model) assigns every crate. Additional boundaries:
  - Layer 0 crates have zero dependencies on storage, network, or filesystem I/O.
  - In Layer 2,
    `chainstate` is the authoritative applied-chain owner. It composes only
    lower/same-layer protocol, chain, UTXO, and storage capabilities; it must
    not depend on mempool, P2P, index, mining, RPC, node, or the binary.
    `utxo` sits in Layer 2 because it depends on `storage` for undo records
    and persisted coin statistics. `chain` depends on `consensus` for BIP9
    parameters and the BIP113 locktime cutoff. It does not read block bodies;
    it defines the `BlockBodySource` capability through which P2P, index,
    and RPC read persisted bodies. `mining` sits in Layer 2 because it
    depends on `mempool` for candidate selection and `chain` for candidate
    header/work/time context.
    `p2p` depends on `mempool` for the transaction inventory view and
    committed-mutation relay consumer. This same-layer edge keeps peer
    protocol mechanics with their consumer; `mempool` must not depend on
    `p2p`, `rpc`, `node`, or the binary. Admission retains peer attribution
    as data without owning connections or runtime assembly. The
    `g17_dependency_direction` gate checks this boundary explicitly.
  - In Layer 4, the footprint package is an offline Linux
    filesystem utility with no node/runtime-workspace or storage-engine
    dependencies.
    `bitcoin-rs-e2e` is the process-level test harness that drives
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
- Storage owns generic journal/checkpoint formats, filesystem operations and
  durability primitives. Its bounded `HistoryAccess` supplies optional consumers.

### `ARCH-03`: Storage backend feature forwarding confinement

- Backend feature forwarding (`fjall`, `redb`, `rocksdb`) is strictly
  confined to:
  1. Operator-facing entry points (`bitcoin-rs-node`, `bitcoin-rs`) that expose
     backend selection to operators and packaging scripts.
  2. Services-tier adapter crates (`bitcoin-rs-chainstate`, `bitcoin-rs-utxo`,
     `bitcoin-rs-index`) whose features exist solely so `-p` package builds
     propagate backend selection into `bitcoin-rs-storage`.
  3. `bitcoin-rs-storage` itself, which owns the concrete backend engine
     dependencies and exposes them through the `KvStore` facade.
- Crates in Layer 0 (Core) and Layer 3 (Surface / RPC) must never define or
  forward storage backend features.
- `bitcoin-rs-chain`, `bitcoin-rs-p2p`, `bitcoin-rs-mempool`, and
  `bitcoin-rs-mining` do not own storage and must not define or forward
  backend feature names; an empty `rocksdb = []` marker counts as defining a
  backend feature and is forbidden.
- `bitcoin-rs-node` and `bitcoin-rs` may forward backend selection only into
  engine-selecting crates (`bitcoin-rs-storage`, `bitcoin-rs-chainstate`,
  `bitcoin-rs-utxo`, `bitcoin-rs-index`).
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
  capability, including the transition-exclusion read role, and production
  wiring attaches nothing to a built `Context`.
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
  service with Chainstate's read and transition capabilities, submits solved
  blocks, and requests header admission from Chainstate),
  watch-only coinbase payout configuration (`MiningConfig::payout_script`), and
  process-level cache budgeting (`dbcache` distribution across chainstate and
  txindex namespaces). The node option table (`crates/node/src/options.rs`)
  declares every operator option once, with its value grammar and its spelling
  on each process-input surface; the `bitcoin-rs` binary expands that table into
  its argv, environment, TOML, and `bitcoin.conf` readers. Applied-tip mutation,
  recovery, checkpoint publication,
  mandatory retention consumption, and branch switching are owned by
  `bitcoin-rs-chainstate`
  (`ARCH-07`), not by a public field bag of subsystem handles. The
  retained-history authority itself — the registry, the executed frontier, and
  prune reserve/commit — is owned by `bitcoin-rs-storage::pruning`; node
  composes that one authority into chainstate, the prune service, and bounded
  index history.
- `bitcoin-rs-rpc::zmq` owns ZMQ topics, framing, HWM validation, socket
  transport, mempool sequence projection, and live notifier enumeration.
  `bitcoin-rs-node` constructs and wires the publisher and continues to own when
  committed chain effects are emitted. The same live publisher is the source for
  `getzmqnotifications`; node does not keep a parallel notifier metadata model.
  The `g17_dependency_direction` gate pins the external `zmq` dependency to the
  surface crate and permits node only to forward `bitcoin-rs-rpc/zmq`.
- `ARCH-07` owns transition reservation and post-commit follower dispatch.
- The option table is the one declaration of an operator option. A row names
  its configuration slot, its text grammar, and its spelling on the command
  line, in the environment, in the TOML file, and in `bitcoin.conf`. The
  `bitcoin-rs` binary holds no option name or grammar of its own beyond the two
  configuration-file selectors and the storage-measurement flags.
- `resolve` folds every layer through `UserConfig::overlay` in precedence order,
  lowest first: a set field replaces the earlier value, an unset field leaves
  it, and nested override structs merge the same way, including
  `ChainstateJournalOverrides` and `MiningOverrides`. `overlay` also applies the
  RPC credential style rule within the layer being folded, so a later password
  clears an inherited cookie path and a later cookie path clears inherited
  user and password. After the fold, the winning `network` value fills the
  profile-owned fields once through `NetworkProfile::for_selection`, and
  `rpc_auth` chooses the final credential style from the winning values.
  Proofs: `crates/node/tests/unit/config/tests.rs`
  `resolve_prefers_higher_layers_field_by_field`,
  `rpc_cookie_and_credential_layers_keep_one_auth_source`, and
  `earlier_set_fields_survive_a_later_bare_network_selection`.

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
  mutation, recovery, branch switching, checkpoint payload assembly/publication,
  and mandatory retention consumption. `NodeState`, `BlockSync`, mining, and RPC
  chain-control hold or clone that service; they do not assemble a transition
  from independent locks.
  Retained-history *authority* is not chainstate's:
  `bitcoin-rs-storage::pruning` owns the `RetentionRegistry`, the executed
  frontier, and prune reserve/commit, and node composition seeds that one
  registry and distributes it. Chainstate receives only
  [`bitcoin_rs_storage::MandatoryRetention`], which can acquire and release
  the pins a transition re-reads and reports what is already gone; it has no
  prune, commit, or shutdown path and is not a broker for the registry.
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
- Long-lived RPC, P2P, index, and mining consumers receive `TipReader`,
  `BlockTreeReader`, and `StableRead` capabilities. The readers expose
  snapshot load and tree read guards respectively; every `&self` tree
  accessor is a pure read, and the tip publication cell is only shareable
  through `&mut BlockTree`. `StableRead` excludes authoritative transitions
  for as long as a read that needs one coherent chainstate runs; its only
  verbs are `lock` and `try_lock`, it hands back an opaque guard, and it has
  no way to reveal its matching `TransitionAuthority` — the role chainstate
  and destructive pruning hold across a mutation. `NodeState::open` mints one
  `TransitionDomain` for that node and distributes matching roles to its
  production consumers. `Chainstate` does not republish a fence:
  `Chainstate::read_fence` does not exist and the g17 facade gate denies it.
  This is a production wiring guarantee, not a type-level provenance guarantee:
  `TransitionDomain::new`, `Default`, and `stable_read` are public, and
  `ChainHandles::default` in the public `Context::new` fixture mints a private
  domain. Passing such a role to a live node reader does not exclude that
  node's transitions. Header admission uses
  `Chainstate::admit_headers`; normal genesis connect publishes through the
  tree's shared tip cell without a separate publication fallback.
  Short-lived `ChainAdmissionView` values borrow readers; the P2P transaction
  ingress worker acquires its owned readers once at startup.
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
  mempool generation before the chain transition is dropped. Follower-free
  convenience methods are compiled only for tests or the `test-seam` capability.
  In-workspace production dependencies and feature forwarding must not enable
  that capability; production composition uses explicit transitions plus
  follower settlement. Downstream users can explicitly opt into `test-seam`.
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
- Runtime capability ownership remains with the subsystem that mutates it.
  `P2pService` owns peer sessions, bans, the network-active latch, and its
  header/block/outbound channels; `ChainFollowers` owns the RPC block log,
  ZMQ publisher, and mining-generation signal; `Chainstate` owns the IBD
  latch. `NodeState` composes those services and returns their handles without
  retaining parallel fields. Its inbound transaction channel is node-owned
  because node orchestration drains it into `MempoolGateway`. Confirmed
  transaction bodies are queried through the derived index and durable block
  storage, never through a second node/RPC transaction map. RPC network
  answers and control operations likewise read and mutate network state through
  `P2pService` directly (querying the P2P-owned peer table, traffic counters,
  ban list, added-node list, and network-active latch, and invoking service
  control methods for bans, added nodes, network-active toggling, and
  disconnections). RPC no longer receives raw handles for bans, added nodes,
  the network-active latch, or the outbound dial channel; the peer table stays
  as a read view, and there is no parallel RPC-local network-state projection
  or duplicate mutation authority.
- `MempoolGateway` owns the process mempool handle; `NodeState::mempool` is a
  read/composition capability borrowed from that gateway, not a parallel
  retained `Arc`. Gateway interning remains the public one-gateway-per-pool
  enforcement boundary for test seams and downstream composition; production
  constructs that same owner once. `NodeState` retains `PruneService` as a
  node/storage mutation capability because it is created only after
  chainstate supplies prune authority and is handed to the later RPC
  lifecycle; it contains no duplicate block or transaction projection.

### `ARCH-07a`: Chainstate mutates `utxo` through one narrow contract

`bitcoin-rs-utxo` is not a second mutation authority: it holds the live coin
set and the persistence formats, and chainstate drives it through one
coherent apply/commit/disconnect contract (`crates/utxo/src/contract.rs`).

- **Apply**: `build_block_changes` turns one validated block into its
  `BlockChanges`, its `UndoBatch`, and the `BlockValueTotals` the coinbase
  check needs. Resolved prevouts enter through `SpentOutputLookup`; the live
  set at BIP30 exception heights enters as the optional overwritten lookup.
- **Commit**: `contract::commit_block_changes` applies one block's
  `BlockChanges` and
  emits commit events to the single attached `CoinStatsListener`; the set's
  raw mutator is crate-private.
- **Disconnect**: `persist_block_undo` / `load_block_undo` round-trip one
  block's `UndoBatch` as the `UndoRecord` bytes the durable head receipt
  names, and `rollback_block` applies that batch under the durable
  disconnect marker plus the coinstats rewind. The raw inverse
  (`UtxoSet::undo_block`) is crate-private: every external disconnect goes
  through `rollback_block`.
- **Read**: `UtxoSet::get` returns the `TxOut` payload while `get_entry`
  returns the one `UtxoCoin` shape; whole-set
  reads run under `with_stable_view` (`UtxoSetView`), which also serves the
  `hash_serialized_3` commitment, script scans, and memory accounting.
  Windowed apply reads through `WindowOverlay` over the same `OutputSource`.
- **Distribution**: production consumers receive `UtxoReader`, never the
  set. It answers `get`, `get_entry`, `has_live_outputs_for_txid`,
  `scan_script_pubkeys`, and the two stable whole-set reads, and carries no
  route to `utxo::contract`. `Chainstate::utxo` and
  `Chainstate::utxo_handle` are fixture-only seams, and
  `UtxoReader::fixture_set` — the one route back to the set — is compiled
  out of production builds, so the g17 facade gate can deny all three from
  an isolated production consumer.
- Shard, record, commit-event, and undo-codec machinery is crate-private.
  Rollback sequencing is split at the marker fence, which is exactly where
  the crate boundary runs: `utxo::contract::rollback_block` owns the fenced
  set mutation (arm the marker, undo the set, rewind coinstats, complete the
  marker) and nothing beyond it. Chainstate owns everything around that
  fence — refusing a stale tip before arming, then journal rewind, durable
  head advance, and publication. It disarms the marker only when the journal
  rewind succeeds; otherwise a matching clean checkpoint disarms it after
  publishing the rolled-back set. Chainstate owns this surrounding order and
  durability policy (`ARCH-07`).
- The contract surface is `bitcoin_rs_utxo::contract`; the crate root keeps
  only read, snapshot, and statistics names. RPC and P2P admission read
  through `UtxoReader` (`UtxoCoin`, `UtxoScan`); index is the read consumer
  that decodes the contract's `UndoBatch`. None assembles mutations outside
  tests, which build fixture sets through
  `BlockChanges` + `commit_block_changes` on `fixture_set()`.

### `ARCH-07b`: AssumeUTXO chainstate roles and single active authority

- **Chainstate roles**:
  `bitcoin_rs_chainstate::ChainstateRole` explicitly defines the lifecycle state
  of every instantiated chainstate:
  1. `Ordinary`: standard fully validated chainstate.
  2. `AssumedActive`: snapshot-loaded chainstate actively driving the node tip,
     retaining its snapshot base height and block hash.
  3. `Historical`: background chainstate validating from genesis or an accepted
     historical checkpoint up to the snapshot base height.
- **Single active authority invariant**:
  At all times, exactly one chainstate acts as the authoritative active chainstate
  (`Ordinary` or `AssumedActive`). Only the active chainstate drives mempool admission,
  mining block template assembly, RPC/ZMQ chain effects, indexer updates, and pruning
  execution. The historical chainstate runs background validation using the consensus
  connect path (`Chainstate::connect`), but its events are detached and never routed to
  mempool, mining, RPC, ZMQ, or indexers.
- **Snapshot activation and pinned metadata**:
  Activation of an AssumeUTXO snapshot is coordinated exclusively by `AssumeUtxoManager`.
  Snapshot height and block hash must match pinned network metadata (`AssumeUtxoData`).
  The manager consumes the imported set and computes its `hash_serialized_3` commitment;
  caller-supplied digests and snapshot trailers do not establish trust. This is Core's
  `HASH_SERIALIZED` commitment, not MuHash. The pinned transaction count seeds the
  active tip; it is independently checked during historical finalization. The base
  header must already exist at the pinned height. Coin statistics are rebuilt from
  the imported coins, and the resolved header supplies chainwork. Installation and
  role changes serialize with chain transitions; failed validation publishes nothing.
- **Background validation and convergence**:
  The historical chainstate validates blocks up to the snapshot base height. It refuses
  to connect blocks past the base height or blocks that diverge from the expected target
  hash (`ApplyError::ConnectPastHistoricalTarget` and
  `ApplyError::HistoricalTargetHashMismatch`, respectively). When validation reaches
  the base height, the reconstructed `hash_serialized_3` and cumulative transaction
  count must match the pinned metadata:
  - If valid, the active chainstate transitions from `AssumedActive` to `Ordinary`, the
    historical chainstate is retired, and disk status is marked `Finalized`.
  - If invalid, the manager persists `AssumeUtxoDiskStatus::Failed`, marks the active
    chainstate permanently closed for recovery (`Chainstate::fail_closed_for_recovery`), and
    refuses subsequent restarts to protect operator data.
  Historical replay uses its own isolated coins, transient durable-head and undo stores,
  no body writer, and detached events. The manager archives validated body locators
  and undo records together with lifecycle progress in the active durable-head batch.
  These batches advance `commit_id` while preserving the active tip and transaction
  count. They publish no active-chain notification. Transient undo is released after
  the archive receipt, so it does not accumulate through the entire history.
  Historical progress checkpoints reuse the chainstate checkpoint format in a
  separate namespace. The durable head records the accepted generation, height,
  and hash; startup restores that checkpoint and replays only its certified
  archive suffix. Without an accepted checkpoint, startup safely falls back to
  genesis replay. The summary exposes live progress separately.
  Historical publication retains earlier generations until the head accepts
  the replacement; recovery selects the head's generation independently of
  `CURRENT`. Snapshot activation refuses an unresolved full-revalidation marker.
  Replaying a block already covered by an archive receipt does not rewrite its
  body or progress. Before checking a new body, the manager syncs its staged bytes and commits a
  pending-validation reference in the same root. If a crash or terminal-status
  write failure leaves that reference, startup reconstructs the dependencies and
  completes the check before returning node state. A mismatch cannot be forgotten
  by restarting after a failed `Failed` write. Finalization is durable before the
  role becomes `Ordinary`; unresolved storage errors close both admissions.
  Production sync pipelines bodies on the pinned base ancestry through a separate
  instance of the existing download window and block stager: at most 32 pending
  and staged bodies in total, 16 in flight per peer, and 64 MiB of staged wire
  payload (plus the stager's one-front-body allowance to avoid a full-tail deadlock).
  Decoded bodies also occupy bounded memory alongside their wire payloads.
  Smaller configured budgets still apply. Archive-capable peers supply batches;
  connection leases, timeouts, retry and backpressure use the shared download policy.
  Body binding is checked before staging. Each historical pass makes at most nine
  chain-owner calls, each replaying at most eight retained blocks, and admits at most
  eight staged bodies in pinned ancestry order, refilling the window while later
  bodies remain staged. A sync tick runs a pass before and
  after draining deliveries. Replay retires overtaken downloads; completion clears
  transient staging. Only validation publishes body locators and lifecycle progress.
  Foreground and historical deliveries have separate owners. Mainnet throughput and
  absolute restart-latency guarantees remain unproven follow-ups to #1288; the
  restart contract is bounded by the historical checkpoint interval once an
  accepted checkpoint exists.
- **Reorg and pruning constraints**:
  - Reorgs on the `AssumedActive` chainstate cannot disconnect blocks at or below the
    snapshot base height (`ApplyError::DisconnectBelowSnapshotBase`).
  - `PruneAuthority::begin` refuses prefix pruning while either chainstate has a
    snapshot role. Even a requested height above the base would delete required
    history. The role check shares the chain-transition lock with activation and
    finalization, so pruning cannot race a role change.
- **Operator observability**:
  `AssumeUtxoManager::chainstates_summary` provides a unified read projection of both
  active and background chainstates, reporting roles, tips, validation progress, and
  commitments without exposing internal lock primitives.
- **Durable activation and recovery**:
  Immutable coin and header archives are synced before the active head commits the
  pinned base and lifecycle status. That head is the only activation authority;
  orphan import files do not activate a snapshot. Startup admits the current schema,
  validates the root's network pin, and restores a compatible checkpoint or verifies
  the snapshot archive, then replays the certified foreground suffix to the head.
  A checkpoint remains an accelerator, including after finalized history is pruned.
  Activation detaches the old checkpoint journal; anchored recovery does not replay
  that journal across the snapshot jump. Node activation fences mempool admission,
  clears old transactions, and wakes index/mining consumers. It does not manufacture
  per-block ZMQ events for imported history. Historical undo makes below-base reorgs
  possible after finalization; crossing below the base removes the snapshot anchor
  in the disconnect's authoritative batch.

### `ARCH-08`: Durable pruning and reorg retention

- Transaction-cache pruning must not remove transactions from a block above
  the durable checkpoint's reorg-retention floor. A requested prune height
  becomes eligible only after durability has been published through
  `CORE_REORG_SAFETY_MARGIN`; this protects reconsideration of disconnected
  transactions during reorg handling.

### `ARCH-09`: Authoritative owners and read-only capability boundaries

- Subsystems keep exactly one authoritative mutation owner for each piece of
  state. External consumers and cross-subsystem adapters receive read-only
  capabilities or single-consumer ownership rather than cloneable mutable handles:
  - **`BlockLog`**: Exclusively owned and mutated by `ChainFollowers`. Consumers
    (RPC handlers, derived index runtime, node queries) access block records
    through the read-only capability `BlockLogReader`. Mutation methods
    (`BlockLogReader::write`) and raw mutable handles (`BlockLogReader::raw_handle`)
    are gated behind the explicit `test-seam` feature.
  - **P2P Inbound Channels**: Single-consumer ownership is enforced for ingress
    channels. Channel receivers (`inbound_headers_rx`, `inbound_blocks_rx`,
    `inbound_tx_rx`) are moved by value to their respective worker loops
    (`BlockSync`, `spawn_tx_ingress_consumer`) using single-take accessors
    (`take_inbound_headers_receiver`, `take_inbound_blocks_receiver`,
    `take_inbound_tx_receiver`). Exposing cloneable `Arc<Mutex<Receiver<...>>>`
    handles in production runtime wiring is prohibited.
  - **`Chainstate`**: Owns the block tree, applied/header tip cells, and process
    shutdown signal. Construction via `ChainstateParts` consumes `BlockTree` by
    value and `restored_applied_tip: Option<TipSnapshot>`, eliminating
    construction-time mutable handle leaks. Mutation authority remains strictly
    confined to chainstate methods; external consumers observe tip state via
    `TipReader` and `BlockTreeReader`.
  - **Shutdown and Ban Capabilities**: Cancellation and ban state are exposed
    through read-only capabilities (`LatchReader`, `BannedReader`). Ordinary
    workers and subsystems query ban status and observe shutdown through these
    capabilities without holding mutable handles or raw atomic pointers.
    Shutdown mutation authority remains strictly encapsulated behind
    `request_shutdown()` and dedicated lifecycle handlers.
- Intentional `Arc` / `Weak` shared ownership invariants:
  - `Arc<PeerTable>`: Shared among P2P service, connection listeners, sync, and
    RPC network handles. `PeerTable` is internally synchronized and owns peer
    leases and address tracking.
  - `Weak<MempoolGateway>`: Held by the P2P transaction relay observer
    (`LocalTxRelayObserver`) to prevent cyclic reference cycles and ensure that
    observer registration does not artificially prolong gateway lifetime.
  - `UtxoReader`: Read-only projection of the authoritative `UtxoSet` (which is
    mutated solely by chainstate under transition locks) to mempool and RPC.
  - `InitialBlockDownload`: Supplies the shared IBD decision across sync and
    header presync by observing chain progress through read-only capabilities
    (`TipReader`, `BlockTreeReader`), while worker orchestration belongs to
    `BlockSync`.

## Test and evidence isolation

Default production builds contain no storage persistence fault slots,
checkpoint/journal injection branches, synthetic `Chainstate::new`, or RPC
synthetic-world constructors/defaults. Explicit `test-seam` features expose
fixtures; only dev-dependencies opt in in the production workspace graph.
This is build isolation, not a security boundary against downstream feature
selection. Production RPC composition remains `Context::from_handles` and
chainstate composition remains `Chainstate::from_parts`.

Offline allocation measurement and its dependencies live in
`tools/storage-footprint`, never in node startup/storage behavior.

## Remaining composition boundary

Ownership is defined in [ARCH-02](#arch-02-exclusive-storage-engine-dependency-ownership)
and [ARCH-03](#arch-03-storage-backend-feature-forwarding-confinement) (storage and
backend construction), [ARCH-05](#arch-05-node-composition-and-orchestration-boundary)
(node assembly) and [ARCH-07](#arch-07-chainstate-owns-authoritative-applied-chain-mutation)
(chainstate transitions and the separate storage retention authority).

## Proven by

- `bin/bitcoin-rs/tests/gates/g17_dependency_direction.rs`:
  - `workspace_dependency_direction_is_one_way`: validates `cargo metadata --no-deps`
    against the manifest-level portions of `ARCH-01`–`ARCH-04` and the production
    feature isolation rule above.
  - `fixture_owners_expose_no_production_injection_or_synthetic_constructors`:
    compiles an isolated consumer; ordinary read/composition APIs must compile,
    while persistence/checkpoint injection, the old footprint module, and
    synthetic chainstate/RPC constructors must be absent.
  - `chainstate_facade_exposes_no_production_raw_mutation_handles`: compiles an
    isolated Cargo consumer without dev-feature unification. Read operations
    must compile; raw mutation handles, reader write/publication methods,
    mutable tip-cell access through a read guard, and `SyncChain` fixture
    methods must fail with the intended compiler diagnostics. Removing an
    obsolete accessor or private field remains allowed, and the deleted
    `Chainstate::retention_handle`, `Chainstate::read_fence`,
    `Chainstate::utxo`, and `Chainstate::utxo_handle` accessors stay deleted:
    retained-history authority, the transition domain, and the authoritative
    UTXO set are owned elsewhere and chainstate must not broker any of them.
    The deleted `Chainstate::read_block_tree` stays deleted too: tree reads,
    including the P2P `SyncChain` adapter's, go through `BlockTreeReader`.
    The same consumer asserts `UtxoReader::fixture_set` is unavailable, so a
    production reader cannot reach the set `utxo::contract` mutates.
- `crates/chainstate/tests/unit/apply/admission_tests.rs` and
  `crates/chainstate/tests/unit/apply/chain_tx_count_tests.rs` cover admission
  shutdown and coherent chain transaction-count publication. Checkpoint and
  journal tests moved with their owner under `crates/chainstate/tests/unit/`.
- `crates/node/src/chain_effects.rs` and node mining/sync/reorg integration
  tests prove that mempool/follower work consumes committed chainstate outcomes
  without making chainstate depend on those consumers.
- `crates/node/tests/unit/state/tests/construction.rs` test
  `runtime_accessors_borrow_their_subsystem_owner` and
  `crates/node/tests/unit/lifecycle/tests.rs` test
  `rpc_network_handles_borrow_p2p_service_state` prove that node and RPC
  composition reuse the owning service's handles rather than retaining
  parallel runtime projections.
- `crates/node/src/chain_effects.rs` tests `noop_asks_for_no_payloads`,
  `connect_then_disconnect_rewinds_the_rpc_log_and_emits_in_order`,
  `disconnect_does_not_pop_a_different_tail`: post-commit RPC/ZMQ work is
  owned by `ChainFollowers`, not by apply; the connect/disconnect test also
  proves that the configured ZMQ publisher receives the committed effects.
- `crates/node/tests/unit/config/tests.rs` tests
  `resolve_prefers_higher_layers_field_by_field` and
  `rpc_cookie_and_credential_layers_keep_one_auth_source`: later `UserConfig`
  layers win on set fields, including nested `ChainstateJournalOverrides`, and
  the RPC credential style is settled per layer and again after the fold
  (`ARCH-05`).
- `crates/node/tests/unit/config/tests.rs` test
  `earlier_set_fields_survive_a_later_bare_network_selection`: the network
  profile fills unset fields only (`ARCH-05`).
- `crates/node/tests/config_layered.rs` test
  `mining_payout_address_decodes_after_all_layers`: watch-only mining payout is
  decoded once after every layer, against the resolved network (`ARCH-05`).
- `bin/bitcoin-rs/src/bitcoin_conf.rs` test
  `every_table_core_key_reaches_its_slot`: each `bitcoin.conf` key the option
  table names writes the slot the table names.
- `crates/mempool/tests/gateway_tests.rs`, `crates/chain/tests/latch_tests.rs`,
  `crates/index/tests/block_log_tests.rs`, and `crates/p2p/tests/service_tests.rs`
  prove single mutation ownership, capability encapsulation, and single-consumer
  channel ownership (`ARCH-09`).
