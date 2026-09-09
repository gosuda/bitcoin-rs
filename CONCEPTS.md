# Concepts

Project-specific vocabulary only. Normative behavior and implementation status live in `docs/contracts/`; measurements live with their evidence. **Target** marks architecture or features not present in the current workspace.

## Owners

### Owner table
One crate owns each domain: `primitives` IDs/encoding/layouts; `script` script execution; `consensus` validity; `storage` engines/batches/snapshots/files; `utxo` coins/undo; `chain` header tree/chainwork; `mempool` admission and pool policy; `p2p` peer protocol/session state; `index` derived indexes; `mining` candidates/templates; `rpc` public protocol adapters; `node` configuration/lifecycle/wiring; binary argv/env/config/signals. `docs/contracts/architecture.md` is authoritative.

### Five-layer direction
`ARCH-01` assigns Core, Storage, Services, Surface, and Compose layers. Dependencies point within or downward only.

### Chainstate owner
**Target.** The planned `crates/chainstate` owner serializes applied-chain transitions and durable recovery. It is not currently a workspace crate.

### Storage ladder
`KvStore` is the backend-neutral storage boundary: reads, ordered/bounded prefix scans, coherent snapshots, atomic batches, deferred/durable writes, and conditional durable writes.

### Index owner
The index runtime owns schemas, watermarks, readiness, backfill/rebuild, and queries. Status adapters project that state rather than inventing their own readiness.

### Mining owner
The mining domain owns candidate selection and template state. RPC renders protocol results; it does not own a second template cache.

### MempoolGateway
The admission owner described by `POL-02`: transaction preparation, policy/script verification, stale-context recheck, and commit belong behind one gateway. The contract and current tests determine which ingress paths have completed that cutover.

## Node interfaces

### Wallet-free RPC boundary
The node has no in-tree wallet or private-key custody. Key-free descriptor, PSBT, scan, and broadcast surfaces may support external wallets.

### Watch-only mining payout
A configured payout address resolves to a network-checked coinbase `scriptPubKey`; the node does not hold its keys.

### Wallet-facing public surface
The public wallet contract is RPC plus Esplora data/broadcast without exposing `NodeState`, UTXO internals, index handles, or datadir access.

### REST gateway
Optional Core-compatible REST shares the RPC listener. `docs/rest-interface.md` and `API-*` own exact behavior.

### Esplora dialects
`/api` is the public Esplora surface. `/esplora` is the versioned backend superset. Neither is a separate chain database.

### Sequence stream
Core-compatible ZMQ sequence events: block `C`/`D` and mempool `A`/`R`, with mempool sequence on transaction events. `bitcoin_rs_rpc::zmq` owns framing/transport.

### Embedded node
`bitcoin_rs_node::Node` is the in-process lifecycle surface over the same runtime as the daemon. See `EMB-*`.

### Node network selection
The resolved network selects consensus and peer bootstrap identity together. Current accepted spellings are owned by configuration code and contracts.

### Configuration precedence
Low to high: defaults, TOML, `bitcoin.conf`, environment, CLI. `UserConfig` resolves to validated `NodeConfig`; runtime test controls are separate.

### Build lanes
The default binary is kernel-free. A minimal native binary uses `--no-default-features --features fjall`; the optional kernel lane uses `--features kernel` in a separate target directory. **Target:** BIP324 has no Cargo feature in this checkout.

## Coherent views and transitions

### ReadStamp
A mixed-read identity containing process epoch, chain generation/tip, mempool sequence, and policy epoch. Partial stamps are not equivalent.

### Chain generation
Even denotes a stable published chain generation; odd denotes an in-progress coordinated transition. It does not replace required read fencing.

### Chain-transition reservation
Exclusive authority to begin a coordinated chain change. Reservation precedes the mempool fence.

### Pool chain-change fence
The mempool generation window that closes admission/mixed reads during a chain transition and reopens only through explicit successful publication.

### Coherent publication
Durable/authoritative transition work precedes mempool reconciliation and stable-generation publication; best-effort observers run afterward.

### Policy epoch
The admission-policy version carried by `ReadStamp`; prepared work under an old epoch is stale.

## Block parsing and validation

### ParsedBlock / ParsedTransaction
Checked borrowed wire layouts over one immutable byte image. Bounds, canonical lengths, segwit framing, and trailing bytes are validated before consumers use spans.

### PreparedTx / ResolvedCoin
Prepared verification data retaining input-ordered coin facts and shared transaction-level sighash work; no pointer may outlive replaceable coin storage.

### Validation window states
`Missing`, `Existing`, `Created`, and `Spent` describe the bounded overlay used while validating consecutive blocks.

### Accepted prefix
The longest contiguous run of prepared blocks valid under one predecessor/context. Later completed work cannot publish across a failed predecessor.

### Native interpreter
With `kernel` disabled, the pure-Rust script path is the complete portable verifier (`VAL-02`). This does not imply that every library currently defaults to native.

### bitcoinkernel
`bitcoinkernel 0.2.1` is the optional kernel engine/oracle. The binary default excludes it; consensus/node library defaults remain governed by `VAL-01` until the recorded promotion changes.

### Strict-Rust versus kernel-free closure
Kernel-free means the dependency is absent. Strict-Rust additionally asserts that the reviewed native verification/crypto path ran. They are separate claims.

### Guarded hash dispatch
Runtime SHA256d implementations have independent capability guards; the portable scalar path remains available everywhere.

### Script-flag exceptions (BIP16Exception)
Named historical blocks whose applicable script flags differ from the normal activation set. Source and tests own the exact list.

### Difficulty-1 target
Compact nBits `0x1d00ffff`, Core's network-independent reference target for difficulty calculations.

### Float value/text parity
Equal floating-point value is distinct from identical JSON spelling; compatibility requirements must say which one matters.

### Provably unspendable outputs
Outputs excluded from live UTXO admission (for example `OP_RETURN` or scripts beyond the live-state limit) while history may still retain them.

### assumevalid
Skipping selected historical script-signature verification below a trusted anchor while retaining the other consensus checks.

### Hash-pinned assume-valid anchor
An assumevalid height is usable only when the active header chain contains its pinned block hash.

### Optimized default posture
The benchmark configuration intended to represent the shipped binary. It is a measurement identity, not a claim about library default features.

## Chain state and durability

### Durable root
**Target.** One authoritative persisted transition identity tying tip, coin version, and committed body/undo extents together. See `RCV-*` for status and proof.

### Ordered commit protocol
**Target.** The required ordering from transition reservation through durable state, publication, and post-commit effects. `RCV-02` owns the exact sequence.

### Orphan append tail
Segment bytes beyond the authoritative committed extent; decodability alone does not promote them.

### Undo record
The exact inverse facts needed to disconnect one block, identified by block identity rather than height alone.

### Owed derived state
Derived data whose owner must define connect, disconnect, and reconciliation semantics.

### Streaming reorg
Disconnecting and reconnecting a reorg through bounded ordinary transitions rather than preloading the entire branch.

### Fresh replay
Schema policy that refuses incompatible authoritative bytes and rebuilds in a separately named datadir instead of translating them in place.

### Post-commit chain effects
Relay, index wakeups, mining invalidation, logs, ZMQ, and other derived work dispatched after authoritative publication.

### Chain control
Operator/RPC requests that change the active chain must use the same transition authority as synchronization.

## Mempool

### AdmissionMode
`Preview` evaluates without mutation; `Commit` continues through the owner-held mutation boundary.

### Admission verdict
A result carrying per-transaction verdicts, context stamp, and optional committed mutation facts.

### Typed Busy
The admission result for repeated stale-context rechecks; callers start fresh rather than reuse stale verification evidence.

### Admission origin
The source category attached to admission (RPC, peer, Esplora, package, reorg, load) so request-specific policy is explicit.

### Sigop cost
Consensus/policy signature-operation accounting derived from transaction and resolved prevout facts, not trusted from ingress metadata.

### AdmissionPolicy
The versioned startup-resolved mempool policy value. `POL-*` and `docs/policies/mempool-policy.md` own current supported rules.

### Replacement profile
The pinned replacement rule set used for RBF/cluster decisions. Version it; do not use “BIP125” as an unqualified synonym for modern policy.

### Cluster graph
Connected components of the unconfirmed spend graph plus deterministic fee/size ordering metadata.

### Generation-safe EntryId
A pool handle tagged with a generation so slot reuse cannot make a stale handle name an unrelated entry.

### Orphan pool
Mempool-owned bounded storage for missing-input transactions and recent rejects.

### Observer bounded delivery
The design in which optional observers consume bounded mutation delivery and reconcile after gaps rather than forcing unbounded memory growth.

### Resolution-time sampling
Recording estimator outcome when confirmation/removal resolves it, with numerator and denominator classified together.

### Estimator state
Versioned owner-local fee-estimator persistence that may reset to insufficient data without becoming authoritative chainstate.

## P2P

### Initial Block Download (IBD)
Initial acquisition and validation from the starting chainstate to the best known chain.

### Sync regimes
Download-bound measurements are dominated by delivery; processing-bound measurements are dominated by local validation/storage. Benchmarks must name the regime.

### Apply frontier
Highest height for which all preceding blocks are validated and committed; distinct from header and download progress.

### Download window
The bounded set of in-flight block requests and associated retry/frontier state. `P2P-*` owns current scheduling boundaries.

### Count-and-byte bound
A variable-sized work window constrained by both item count and bytes.

### Staller
A peer preventing frontier progress by failing to deliver assigned work while local apply is not the bottleneck.

### Peer lease
Generation-scoped request/session authority that makes stale completions harmless and terminal release exactly once.

### Address book
**Target.** A bounded persistent peer-discovery owner; no `crates/p2p/src/address_book.rs` exists in this checkout.

### Compact-block reconstruction
**Target.** BIP152 reconstruction with missing-transaction request and full-block fallback; current status is owned by `P2P-*` and the policy matrix.

### v2 transport
**Target.** Optional BIP324 encrypted transport. No `bip324` dependency or Cargo feature exists today.

### Notification configuration
Configuration grouping external notification endpoints, topics, and per-endpoint options.

## Derived indexes

### Capability
An independently ready projection such as transaction lookup, live script outputs, or script history.

### Capability watermark
Durable capability identity including height, block hash, schema, and revision. Height alone is insufficient.

### Capability state machine
The owner state vocabulary: disabled/opening/catching-up/ready plus rollback, rebuild, failure, and shutdown states.

### Capability status
The adapter projection of capability state plus one runtime revision.

### Unavailable is not empty
A query whose required projection is disabled, stale, rebuilding, or unavailable returns a typed unavailable/retry result rather than successful emptiness.

### Occurrence key
A transaction-history identity including transaction id, block identity, and position so duplicate txids/branches cannot alias.

### ScriptLive view
A compact live-output locator keyed by script accelerator plus full outpoint and verified against authoritative coins.

### Consumer cursor
Durable sequence/chain identity naming the state a derived consumer has applied.

### Rollback-versus-rebuild cutover
The measured depth at which rebuilding a projection is preferred to reversing contributions one block at a time.

### Compact block filters
Derived BIP157/158 data owned by the index side and advertised only when available under the P2P contract.

## Mining

### Generation key
The complete identity that makes one cached template reusable: chain/pool stamp plus template policy, fee-delta, and time-validity revisions.

### Selection
Dependency-aware candidate ordering from an immutable admitted-pool snapshot using exact fee/size accounting.

### Proposal
Nonmutating BIP22 candidate validation. Submission is a separate state-changing operation.

## Storage

### UTXO record
Transaction-grouped live-coin storage keyed by full txid identity; accelerators are hints only.

### Canonical record spelling
One logical record has one canonical byte representation.

### Deferred write
An atomic visible write whose crash durability is completed by a later `flush`.

### Logical owner ledger
Serialized bytes attributed to logical storage owners.

### Physical namespace ledger
Allocated filesystem bytes attributed to top-level datadir namespaces; the storage contract owns the budget and proof method.

### Work-count assertion
A deterministic count of expensive work, distinct from a wall-clock benchmark.

## Reference and evidence

### ReferenceSet
The machine-readable identity set for released Core, the kernel tree, corpora, and formal tools. `docs/api/core-compat.toml` and compatibility code govern.

### Compatibility class versus readiness versus evidence
Manifest support status, runtime readiness, and executed evidence are three independent facts.

### Guard register
`CONSTRAINTS.md`, the root index of current constraints and gate/evidence status.

### Formal models
The TLA+ abstractions under `docs/models/`. A bounded model-check result is evidence about the model, not proof of the implementation.

### Blocked gate
A required check missing an authenticated tool, corpus, hardware target, or other prerequisite. Missing prerequisites do not count as pass.

## Measurement

### Product performance cell
One frozen product-domain/corpus/architecture/backend coordinate under `HPA-*`.

### Hot-path attribution ledger
The machine inventory in `docs/benchmarks/hot-path-ledger.toml`; nested/concurrent timings are not additive wall time.

### Evidence identity
Artifact, configuration, corpus, durability, and host/reference identity attached to a measurement sample.

### Promotion floor
The minimum measured product improvement and stability required before retaining an optimization; `HPA-13` owns the numbers.

### Retained benchmark contract
A permanent benchmark must exercise shipped production behavior and protect a current regression or decision.

### C150 / Cmodern
Pinned campaign corpora defined by `docs/contracts/campaign-corpora.md`.

### Matched-harness comparison
A cross-system benchmark in which non-target variables are matched before quoting a ratio.

### Offline full-validation comparator
The processing-bound Core-versus-bitcoin-rs chainstate comparison defined by its benchmark contract.

### CPU-seconds
Process CPU time recorded beside wall time so parallelism cannot appear free.

### Contended-harness tuning artefact
A tuning result obtained while the harness competes with the node for CPU; not valid as an isolated-node optimum.

### CI lane parity
A branch is green only against the actual workflow commands and current required gates.
