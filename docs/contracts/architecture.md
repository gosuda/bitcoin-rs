# Architecture contract

The normative contract for workspace crate layering, one-way dependency
direction, storage engine confinement, owner boundaries, and the node
composition surface.

Owners:
- `Cargo.toml`, `crates/*/Cargo.toml`, `bin/bitcoin-rs/Cargo.toml`
- Workspace dependency gate: `bin/bitcoin-rs/tests/gates/g17_dependency_direction.rs`
- `crates/chainstate/src/transition.rs`, `crates/chainstate/src/recovery.rs`

## Layer model

```text
  +-------------------------------------------------------------------------+
  | Layer 4: Compose                                                        |
  |   bitcoin-rs-node, bitcoin-rs                                           |
  |   - Lifecycle orchestration, runtime assembly, config, cache allocation |
  +----------------------------------+--------------------------------------+
                                     |
                                     v
  +-------------------------------------------------------------------------+
  | Layer 3: Surface                                                        |
  |   bitcoin-rs-rpc                                                        |
  |   - Protocol boundaries and RPC/REST/Esplora dispatch                   |
  +----------------------------------+--------------------------------------+
                                     |
                                     v
  +-------------------------------------------------------------------------+
  | Layer 2: Services                                                       |
  |   bitcoin-rs-chain, bitcoin-rs-chainstate, bitcoin-rs-utxo,             |
  |   bitcoin-rs-p2p, bitcoin-rs-mempool, bitcoin-rs-index,                 |
  |   bitcoin-rs-mining                                                     |
  |   - Domain capabilities, chainstate authority, index runtimes, network  |
  +----------------------------------+--------------------------------------+
                                     |
                                     v
  +-------------------------------------------------------------------------+
  | Layer 1: Storage                                                        |
  |   bitcoin-rs-storage                                                    |
  |   - Storage abstractions (KvStore), exclusive owner of engine deps      |
  +----------------------------------+--------------------------------------+
                                     |
                                     v
  +-------------------------------------------------------------------------+
  | Layer 0: Core                                                           |
  |   bitcoin-rs-primitives, bitcoin-rs-script, bitcoin-rs-consensus        |
  |   - Protocol types, script validation, consensus rules; zero storage/IO |
  +----------------------------------+--------------------------------------+
```

## Owner table

| Owner | Owns | Must not own |
| --- | --- | --- |
| `primitives` | IDs, canonical encodings, borrowed transaction and block layouts, network constants | Runtime policy, sockets, storage |
| `script` | Interpreter, sighash execution context, verification primitives | Chain lookup, mempool policy, thread scheduling |
| `consensus` | Pure structural and contextual validity and verification plans | Database, peers, operator RPC |
| `storage` | Engine adapters, batches and snapshots, framed segment I/O, flush contract, physical accounting | Consensus, active-chain selection, mempool mechanics |
| `utxo` | Coin formats, grouped record mutation, coin views, undo encoding | Cross-store transition sequencing, optional script and history index |
| `chain` | Header tree, chainwork, activation context, common ancestors, branch selection | Socket lifetime, HTTP schemas |
| `chainstate` | Transition serialization, accepted-prefix commit, durable root, connect, disconnect, recovery | RPC, mining selection, P2P session ownership, optional index policy |
| `mempool` | Admission preparation and verification, graph, RBF, lifecycle, fee policy and estimation, orphans | Network sockets, chain persistence |
| `p2p` | Transport, sessions, addresses, scheduling, relay and request state | A second mempool evaluator or UTXO writer |
| `index` | Generic schemas, backfill, selective rebuild, readiness and query engines | Authoritative chain apply |
| `mining` | Candidate selection, GBT state, generations, proposal and submission interface | Private keys, independent admission policy |
| `rpc` | Core RPC, REST, public Esplora and backend dialect adapters, typed error mapping | Storage engines, direct mutable NodeState, template ownership |
| `node` | Resolved configuration, lifecycle, resource budgets, wiring, cross-owner ordering | Domain algorithms already assigned above |
| Binary | argv, environment, TOML and `bitcoin.conf` parsing, process signals, measurement commands | Consensus decisions |

## Clauses

### `ARCH-01`: Five-layer one-way dependency direction

- Every workspace crate is assigned to an approved layer from 0 to 4.
- A crate may depend only on crates in the same layer or in a strictly lower layer.
- Edges pointing upward or across forbidden boundaries fail the `g17_dependency_direction` gate.
- Crate layer assignments are:
  - Layer 0 (Core): `bitcoin-rs-primitives`, `bitcoin-rs-script`, `bitcoin-rs-consensus`.
  - Layer 1 (Storage): `bitcoin-rs-storage`.
  - Layer 2 (Services): `bitcoin-rs-chain`, `bitcoin-rs-chainstate`, `bitcoin-rs-utxo`, `bitcoin-rs-p2p`, `bitcoin-rs-mempool`, `bitcoin-rs-index`, `bitcoin-rs-mining`.
  - Layer 3 (Surface): `bitcoin-rs-rpc`.
  - Layer 4 (Compose): `bitcoin-rs-node`, `bitcoin-rs`.
- `chainstate` sits in Layer 2 because it depends on `chain`, `utxo`, `consensus`, and `storage`.
- `chain` and `utxo` remain in Layer 2 because they depend on `storage` for block index records, undo storage, and UTXO snapshots.
- `mining` sits in Layer 2 because it depends on `mempool` for candidate selection and on `chain` for candidate header and work context.
- Layer numbers do not justify speculative new crates or thin wrapper layers. A boundary exists only when it isolates external dependencies, enforces safety or consensus boundaries, or separates independent runtime lifecycles.

### `ARCH-02`: Exclusive storage engine dependency ownership

- `bitcoin-rs-storage` is the sole crate in the workspace permitted to depend on underlying storage engine crates (`fjall`, `redb`, `rust-rocksdb`, `mdbx`).
- No crate outside `bitcoin-rs-storage` may name a storage engine dependency in `[dependencies]`, `[build-dependencies]`, or `[dev-dependencies]`.
- All higher layers interact with persistent state through the `KvStore` facade and storage abstractions exported by `bitcoin-rs-storage`.

### `ARCH-03`: Storage backend feature forwarding confinement

- Backend feature forwarding (`fjall`, `redb`, `rocksdb`, `mdbx`) is strictly confined to:
  1. Operator-facing entry points (`bitcoin-rs-node`, `bitcoin-rs`) that expose backend selection to operators and packaging scripts.
  2. Services-tier adapter crates (Layer 2) whose features exist solely so `cargo -p` package builds propagate backend selection into `bitcoin-rs-storage`.
- Crates in Layer 0 (Core) and Layer 3 (Surface and RPC) must never define or forward storage backend features.

### `ARCH-04`: RPC surface independence from storage

- `bitcoin-rs-rpc` must have zero non-test dependency edges on `bitcoin-rs-storage` and zero dependencies on storage engine crates.
- RPC consumes node capabilities (`chain`, `mempool`, `index`, `mining`, `p2p`, `utxo`) exclusively through capability query handles and domain clinician interfaces (`Context`, `ContextHandlers`).
- `bitcoin-rs-rpc` defines and forwards zero backend features. The `bench-only` `dev-dependency` used for offline `txoutproof` fixtures is isolated to test scope and documented in `crates/rpc/Cargo.toml`.

### `ARCH-05`: Node composition and orchestration boundary

- `bitcoin-rs-node` (Layer 4) is the assembly and lifecycle orchestration layer.
- It wires together storage backends, consensus validators, the mempool gateway, P2P listeners, index reconciliation workers, and RPC services into an executable node runtime.
- Domain mechanics belong to domain crates:
  - consensus rules live in `consensus` and `script`;
  - mempool admission and mutation sequencing live in `mempool`;
  - connection lifecycle and request scheduling live in `p2p`;
  - template assembly and the BIP22/BIP23 JSON contract live in `mining`;
  - index schemas and backfill live in `index`.
- `bitcoin-rs-node` owns runtime startup and shutdown sequencing, configuration resolution and validation, `UserConfig` to `NodeConfig` overlay, and process-level cache budgeting.
- Applied-tip mutation is owned by the `chainstate` owner, not by a public field bag of subsystem handles.
- The composition root (`NodeState`, `BlockSync`, reorg logic, mining) dispatches `ChainFollowers` while the `ChainTransition` is still held, then calls `finish` to release the chain transition reservation. Convenience methods that finish before returning (`apply_block`, `disconnect_block`) do not dispatch followers. RPC, `BlockLog`, hash/zmq, `TxIndex` wake, sequence `C`/`D`, mining generation, and admission run from that dispatch. Mempool eviction stays inside `apply`.

### `ARCH-06`: Hierarchy change and exception process

- Any change to workspace crate layer assignments, introduction of new workspace crates, or addition of cross-crate dependencies requires:
  1. Updating the approved layer table and engine crate assertions in `bin/bitcoin-rs/tests/gates/g17_dependency_direction.rs`.
  2. Updating this normative contract (`docs/contracts/architecture.md`) with the rationale and invariant justification.
  3. Passing the `g17_dependency_direction` gate test.
- Speculative or circular dependency edges that violate the one-way flow are rejected by automated gate enforcement in CI.

### `ARCH-07`: Chainstate owner owns transition admission

- `crates/chainstate` is the in-process owner of applied-tip mutation.
- `NodeState`, `BlockSync`, mining, and RPC chain-control hold or clone the `Chainstate` owner; they do not assemble a transition from independent locks.
- `Chainstate::begin_transition` is the only public constructor of a `ChainTransition`. Reorg planning that must abort without mutating takes the lock and promotes it with `begin_transition_locked` only after the authoritative plan matches the preloaded plan.
- Snapshot reads (`Chainstate::snapshot`) copy the independently published header tip and a coherent applied-tip and chain-tx-count pair. They do not take the transition lock and cannot mutate chainstate.
- `ChainEventPublisher` calls remain a separate coherent snapshot of the applied tip for index consumers (`EVT-01`).
- `Chainstate::validate_block` dry-runs the apply path's pre-write consensus gates under `lock_transition`. It does not take mempool generation and does not persist. BIP22 proposal omits proof-of-work; every other pre-write gate is the same function called with `Mode::Proposal`.
- Authoritative apply still lives in `crates/chainstate` because it composes `chain`, `consensus`, `utxo`, and `storage`.
- `Chainstate` does not hold or import RPC, ZMQ, `TxIndex`, mining, or P2P admission types.
- Apply publishes the tip and returns a `ConnectOutcome` or `DisconnectOutcome`. Capture flags are set at construction so apply can produce `rawtx` bytes and canonical block bytes without holding consumers.
- The composition root dispatches `ChainFollowers` while the `ChainTransition` is still held, then calls `finish`. Consumer failure cannot invalidate chainstate.

## Coherent view protocol

`ReadStamp` is the coherent view token:

```rust
struct ReadStamp {
    process_epoch: u64,
    chain_generation: u64,
    chain_tip: BlockHash,
    mempool_sequence: u64,
    policy_epoch: u64,
}
```

- All fields are checked where relevant.
- `chain_generation` is even while stable and odd during a coordinated change.
- A caller cannot compose a view by separately loading a tip and mutable UTXOs.
- The initial implementation retains the existing bounded read fence that protects live UTXO resolution. A later storage snapshot plus immutable committed-cache overlay with the same version is a measured optimization, not a correctness prerequisite.
- During a chain change, admission and mixed chain-and-mempool reads are closed. `chainstate` durably commits the transition, `mempool` consumes the committed facts, the coordinator publishes the coherent stable generation, then best-effort consumers are notified in contract order.
- A failure before stability leaves the fence closed until explicit recovery. A guard destructor must never quietly reopen the fence after an error.

## Lock and order contract

- Acquire the chain-transition reservation before beginning the mempool chain-change fence.
- Never hold the mempool write lock while doing script verification, network I/O, fsync, or callbacks.
- Do not await while holding a non-async mutex guard.
- Snapshot gathering copies or retains owned facts, then releases locks.
- Observer delivery occurs outside all domain locks.

## Anti-shim cutover rule

- Every in-tree caller of an approved cut symbol migrates to the new owner location in the same changeset.
- The obsolete path is deleted with no re-export shim, alias, forwarding handle, or compatibility flag.
- Generic advice to keep a one-release re-export does not apply.
- Before each cut, resolve forward and reverse exported-symbol references and generated or external consumers; display the exact tracked file and symbol set; classify every old behavior as `dead`, `duplicate`, `superseded`, `generated residue`, or `keep`.
- Any newly discovered public boundary not covered by the approved boundary set stops that cut.

## Proven by

- `bin/bitcoin-rs/tests/gates/g17_dependency_direction.rs`:
  - parses `cargo metadata` with `--no-deps`;
  - validates every internal workspace dependency edge against the approved layer table;
  - verifies `bitcoin-rs-storage` exclusively owns storage engine dependencies;
  - confirms `bitcoin-rs-rpc` has no dependency on `bitcoin-rs-storage` and forwards no backend features;
  - validates backend feature forwarding is confined to operator tiers and service adapters.
- `bin/bitcoin-rs/tests/gates/g20_formal_models.rs` (planned): checks the TLA+ models `ChainAdmission`, `PeerLeases`, and `ProjectionMining` with Apalache 0.62.2 before production bodies in `chainstate`, `mempool`, `p2p`, and `index` are changed.
- `crates/chainstate/src/transition.rs` (planned): owns `Chainstate`, `ChainTransition`, and the ordered commit protocol.
- `crates/chainstate/src/recovery.rs` (planned): owns durable root recovery and `CURRENT_SCHEMA` refusal.
- `crates/node/tests/overhaul_checkpoint_independence.rs` (planned): candidate `chainstate` recovery, retained maintenance, matched startup and replay performance, and full-tip storage checks before complete authority cutover.

## Vocabulary

Terms used above are defined in [`../../CONCEPTS.md`](../../CONCEPTS.md): five-layer direction, chainstate owner, coherent view protocol, `ReadStamp`.
