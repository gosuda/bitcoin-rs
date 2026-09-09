# Concepts

Project-specific glossary. Normative rules live in `docs/contracts/`; measured results live with their evidence. Entries marked **Target** describe intended architecture that is not yet present.

## Owners

### Owner table
One crate owns each domain: `primitives` IDs/encoding/layouts; `script` interpreter and sighash primitives; `consensus` validity; `storage` engines/batches/snapshots/files; `utxo` coins/undo; `chain` header tree and chainwork; `mempool` admission/graph/policy/estimation/orphans; `p2p` transport/sessions/relay/download scheduling; `index` schemas/backfill/readiness/query; `mining` candidate/template state; `rpc` public protocol adapters; `node` configuration/lifecycle/wiring/cross-owner ordering; binary argv/env/config/signals/measurement. `docs/contracts/architecture.md` and gate `g17` own the assignment.

**Target:** `crates/chainstate` becomes the transition owner. That crate is not currently in the workspace.

### Five-layer direction
`ARCH-01`: Layer 0 `primitives`, `script`, `consensus`; Layer 1 `storage`; Layer 2 `chain`, `utxo`, `chainstate`, `mempool`, `p2p`, `index`, `mining`; Layer 3 `rpc`; Layer 4 `node` and binary. Dependencies point only within or downward. The `chainstate` entry is target architecture until that crate exists.

### Chainstate owner
**Target.** `crates/chainstate` serializes chain transitions, owns the durable root, and performs connect/disconnect/recovery. Node coordinates external effects around it. No compatibility facade or checkpoint-worker alias.

### Storage ladder
`KvStore` is the only backend-neutral storage trait: reads, ordered/bounded prefix scans, snapshots, batches, deferred/durable writes, and conditional durable writes. `Ok(true)` means committed and durable; `Ok(false)` means condition mismatch with no write; `Err` means backend failure. `ColumnFamily` is the shared logical namespace. Atomic visibility and crash durability are distinct.

### Index owner
`crates/index` owns row schemas, backfill, selective rebuild, capability state, watermarks, and queries. Node only schedules the worker; adapters project owner state.

### Mining owner
`crates/mining` owns selection, template generations/cache, long-poll wakeups, and invalidation. RPC renders protocol results but owns no template cache.

### MempoolGateway
The node-constructed `Arc<MempoolGateway>` is the single admission path for RPC, P2P, Esplora, packages, and reorg re-admission. It captures a `ReadStamp`, resolves inputs once, verifies outside the pool writer, then rechecks context and commits under one writer acquisition.

## Node interfaces

### Wallet-free RPC boundary
The node holds no private keys and has no in-tree wallet. Key-free descriptor, PSBT, and bounded UTXO-scan helpers may remain node RPCs for external-wallet workflows.

### Watch-only mining payout
`--mining-payout-address` resolves to a network-checked coinbase `scriptPubKey`; the node never holds payout keys. Empty configuration keeps transport-only GBT assembly.

### Wallet-facing public surface
External wallets use native Esplora `/api`, address/script lookups, `POST /tx`, and wallet-free RPCs. They receive no `NodeState`, `UtxoSet`, index handle, or datadir access. See `docs/contracts/wallet-facing.md`.

### REST gateway
Optional Core-compatible REST shares the JSON-RPC listener and is enabled by `rest=1`. Mixed reads use one coherent view; a moved chain generation yields HTTP 503. See `docs/rest-interface.md`.

### Esplora dialects
`/api` is public Esplora. `/esplora` is the versioned backend superset. Both project the same node/index state; neither is a separate database or node mode. `/api/v1` belongs to the external mempool application.

### Sequence stream
Core-compatible `pubsequence`: block hash + `C`/`D`; mempool txid + `A`/`R` + little-endian sequence. A mined transaction emits no `R`. Reorg disconnects precede connects. `bitcoin_rs_rpc::zmq` owns payload/transport compatibility; chain effects own emission timing. Default HWM is 1,000.

### Embedded node
`bitcoin_rs_node::Node` exposes the daemon lifecycle in process. Contract methods may be `async fn` with synchronous bodies; the embedder owns any executor. See `docs/contracts/embedding.md` (`EMB-02`).

### Node network selection
`BITCOIN_RS_NETWORK` / `--network` selects consensus and bootstrap identity together. Supported names include mainnet, signet, testnet4, regtest, retained testnet3 aliases where documented, and `drynet4`.

### Configuration precedence
Low to high: defaults, TOML, `bitcoin.conf`, environment, CLI. `UserConfig` resolves once into validated `NodeConfig`; test clocks/fault controls stay in `RuntimeInputs`.

### Product lanes
Minimal native: `--no-default-features --features fjall`. Default: default features, unpruned fjall, optional indexes off. Oracle: `--features kernel` in a separate target directory. **Target optional-on lane:** BIP324 plus compact filters; BIP324 is not currently wired in this workspace.

## Coherent view and transitions

### ReadStamp
Coherent mixed reads carry `{ process_epoch, chain_generation, chain_tip, mempool_sequence, policy_epoch }`; all fields are checked. Height-only or partial stamp keys are invalid.

### Chain generation
Even means stable/open; odd means coordinated chain change in progress. The generation counter does not replace the read fence protecting mutable UTXO resolution.

### Chain-transition reservation
Exclusive right to begin a chain transition. Reservation is acquired before the pool fence.

### Pool chain-change fence
`begin_chain_change` / `ChainChangeGuard` closes admission commits and mixed reads during a transition. Reopening is explicit after durable commit and pool reconciliation; drop after error does not reopen it.

### Coherent publication
Durable chain commit precedes mempool reconciliation, stable-generation publication, then best-effort relay/index/ZMQ/observer notification.

### Policy epoch
`ReadStamp.policy_epoch` changes with `AdmissionPolicy`. Prepared work from an old epoch is stale and must be retried from fresh facts.

## Block parsing and validation

### ParsedBlock / ParsedTransaction
Checked borrowed wire layouts in `crates/primitives/src/layout.rs`. Bounds, canonical lengths, segwit marker/flag rules, and trailing bytes are validated before slicing. IDs, weight, positions, and Merkle mutation derive from the layout once.

### PreparedTx / ResolvedCoin
Prepared verification retains input-ordered resolved coins with value, script, height, and coinbase status. Inputs resolve once; transaction-wide sighash aggregates are cached once. Borrowed pointers into replaceable coin records are forbidden.

### Validation window states
`WindowOverlay`: `Missing`, `Existing`, `Created`, `Spent`. Same-block create-then-spend retains a tombstone. The window is bounded by bytes, inputs, retained coin bytes, CPU jobs, and age.

### Accepted prefix
Longest contiguous run of window blocks proved valid under one context. Only that prefix may publish; later completed work cannot skip a failed predecessor.

### Native interpreter
The mandatory production verifier is pure Rust (`crates/script`) using the reviewed strict-Rust cryptography path. Historical DER/high-S, TapTweak overflow, and hybrid-key parity rules remain explicit.

### bitcoinkernel
`bitcoinkernel 0.2.1` is an opt-in differential oracle in the `kernel` lane, never a silent fallback or default runtime verifier.

### Strict-Rust versus kernel-free closure
Kernel-free means no transitive production `bitcoinkernel`; strict-Rust additionally proves the reviewed Rust validation/crypto path executed. They are separate gates.

### Guarded hash dispatch
Runtime SHA256d kernels have independent AVX2, x86 SHA, and ARMv8 SHA2 guards; portable scalar always exists. Merkle batching preserves duplicate-last and mutation rules.

### Script-flag exceptions (BIP16Exception)
Core hardcoded reduced-flag blocks: mainnet 170060 (P2SH), 692261 (Taproot), testnet3 394. `Network::is_bip16_p2sh_exception` reproduces the P2SH exception; Taproot activation is height-gated separately.

### Difficulty-1 target
Core's network-independent reference target: compact nBits `0x1d00ffff`, not the selected network PoW limit.

### Float value/text parity
Compatibility preserves IEEE-754 value and operation order. It does not require Core's `%.16g` JSON spelling when shortest round-trip text encodes the same value.

### Provably unspendable outputs (UTXO admission)
UTXO state excludes scripts beginning with `OP_RETURN` or longer than `MAX_SCRIPT_SIZE`; history indexes may retain them.

### assumevalid
At or below a trusted height, script-signature checks may be skipped while all other consensus checks still run. Height zero requests full verification.

### Hash-pinned assume-valid anchor
Mainnet anchor: height 938343, hash `00000000000000000000ccebd6d74d9194d8dcdc1d177c478e094bfad51ba5ac`. Skipping applies only if the active header chain contains that exact hash.

### Optimized default posture
Default measurement posture: fjall, hash-pinned assumevalid, 450 MiB `dbcache`, tx/script indexes off, pruning off, native strict-Rust validation, P2P-owned multi-peer download. Benchmarks must record deviations.

## Chain state and durability

### Durable root
`DurableHead { format_version, commit_id, tip_hash, height, chain_tx_count, block_segment_end, undo_segment_end }` is authoritative and shares the final atomic coin/metadata batch. Recovery reads it rather than inferring a head from segment files.

### Ordered commit protocol
Reserve and fence; build forward/undo facts; append and sync body/undo frames; atomically write coins/metadata/durable head; complete backend durability; reconcile mempool; publish stable generation; notify. I/O failure never reports success.

### Orphan append tail
Segment bytes after the durable-root cursor. They may be truncated during recovery and never promote state by themselves.

### Undo record
Per-block inverse keyed by height and block hash, encoded by `undo_codec` with `UNDO_FORMAT_VERSION = 1`.

### Owed derived state
Every derived owner affected by connect must define disconnect/reconciliation behavior. Coin stats invert explicitly; indexes reconcile from durable-root identity.

### Streaming reorg
Disconnect tip-to-fork in bounded exact-inverse chunks, then connect the competing branch through the normal pipeline. Missing required undo fails closed.

### Fresh replay
Authoritative schema changes increment `CURRENT_SCHEMA` and require an explicitly fresh datadir; incompatible existing datadirs are neither converted nor deleted. Owner-local derived files version and degrade independently.

### Post-commit chain effects
RPC block logs, ZMQ, index wakeups, mining generation, and mempool alignment run after committed publication under `ChainFollowers` / `ChainEffects` ownership.

### Chain control
Consensus-affecting RPCs request transitions through the same chain-transition authority as sync; they do not mutate the block tree directly.

## Mempool

### AdmissionMode
`Preview` runs the same preparation/resolution/policy/script path as `Commit` and stops before mutation. `Commit` continues to the one writer acquisition.

### Admission verdict
`AdmissionVerdict { stamp, rows, changes }`; `changes` exists only for a committed mutation. A preview is contextual evidence, not a reservation.

### Typed Busy
`AdmitError::Busy` follows four stale recheck attempts. Each attempt recaptures chain generation, pool sequence, and policy epoch; stale evidence is never reused.

### Admission origin
`AdmissionOrigin`: `Rpc`, `Peer(PeerToken)`, `Esplora`, `Package`, `Reorg`, `Load`. Only retained accepted entries become relay candidates.

### Sigop cost
The gateway computes `total_sigop_cost` from resolved prevouts and enforces `MAX_STANDARD_TX_SIGOPS_COST = 16_000`; ingress never supplies the count.

### AdmissionPolicy
One startup-resolved policy value owns relay/dust/datacarrier/package/RBF/TRUC/script limits for the pinned Core 31.1 profile. Contradictory configuration is a startup error.

### Replacement profile
Core 31.1 replacement uses feerate-diagram conditions over candidate and victim clusters with all-or-nothing commit. TRUC v3 topology constraints are included; the modern profile is not simply “BIP125 rules 1-6”.

### Cluster graph
Spend-graph components carry revision, aggregate fee/size, deterministic linearization/chunks, and bounded rebuild. Ranking uses checked integer cross-products and is shared by eviction, mining, and package limits.

### Generation-safe EntryId
Slab handles include a generation; stale handles resolve to `None` after slot reuse.

### Orphan pool
Mempool owns missing-input transactions and recent rejects with bounded quotas, reverse parent index, and peer cleanup. Node only routes peer events.

### Observer bounded delivery
Optional mutation observers use a capped queue outside domain locks. Overflow records a gap/reconcile signal; canonical estimator accounting is never dropped.

### Resolution-time sampling
Estimator numerator and denominator are recorded together when confirmation outcome is known. Unclassifiable removals are `Excluded`, not confirmations.

### Estimator state
Versioned owner-local fee-estimator state may reset to insufficient data on corruption/unknown version; it never fabricates a rate.

## P2P

### Initial Block Download (IBD)
One-time download and full validation from the start point to the network's best known tip.

### Sync regimes (download-bound vs processing-bound)
Measurements name whether wall time is dominated by network delivery or local validation/storage.

### Apply frontier
Highest height for which every preceding block has been validated and committed. Downloaded or header-only progress does not advance it.

### Download window
`P2pService::DownloadWindow` owns in-flight block byte/height budgets, deadlines, retries, and frontier priority. Node supplies demand and validates results; it owns no scheduler copy.

### Count-and-byte bound
A variable-size window obeys both item-count and byte caps; one oversized block may proceed alone.

### Staller
A peer that blocks the apply frontier by failing to deliver its assigned frontier block while local apply is not the bottleneck.

### Peer lease
`PeerTable` / `PeerLease` is the peer-lifetime authority. Session generation plus request identity makes stale completions no-ops; each request lease releases exactly once.

### Address book
`crates/p2p/src/address_book.rs` owns bounded tried/new address state, timestamps, addrv2, seeding, intake limits, and owner-local persistence. Corruption degrades to seeded discovery rather than failing authoritative startup.

### Compact-block reconstruction
BIP152 yields `Complete`, `Missing{txids}`, or `Fallback`. Short IDs are not identities; ambiguity requests missing transactions or falls back, and reconstructed blocks still use ordinary validation.

### v2 transport
**Target.** Optional BIP324 transport belongs in `connection.rs`, with authenticated failure never downgrading. No `bip324` dependency or Cargo feature is currently wired.

### Notification configuration
`NotificationConfig` groups external adapters; each ZMQ endpoint owns its topics and optional HWM override.

## Derived indexes

### Capability
Independent projection: `TxLookup`, `ScriptLive`, or `ScriptHistory`. `ScriptIndex(full)` means live + history; `ScriptIndex(utxo)` means live only. Core `txindex` advertisement is explicit, not inferred.

### Capability watermark
Durable `(capability, height, hash, schema, revision)` committed with the rows it describes. Height alone is not identity.

### Capability state machine
`Disabled -> Opening -> CatchingUp -> Ready`, plus `RollingBack`, `Rebuilding`, `Failed`, `Shutdown`. Readiness requires health and watermark equality with the queried active tip.

### Capability status
`CapabilitySnapshot` / `CapabilityStatus` projects index-owner state and one runtime revision across adapters.

### Unavailable is not empty
Lagging, rebuilding, disabled, or pruned-away data returns typed `Unavailable`/`Retry`, never successful emptiness.

### Occurrence key
Transaction occurrence keys include txid, block identity, and position so duplicate txids and side branches cannot overwrite evidence.

### ScriptLive view
Compact script-prefix + full-outpoint locators resolve value/script against authoritative coins and stay unqueryable until the final watermark commits.

### Consumer cursor
Durable `{ epoch, sequence, height, hash }` written atomically with the rows it names.

### Rollback-versus-rebuild cutover
Depth where an index resets/rebuilds instead of reversing contributions. The 100,000-block baseline must be remeasured on target storage; see `docs/benchmarks/index-rollback-rebuild-cutover.md`.

### Compact block filters
BIP158 filters/BIP157 headers are index-owned derived data served through P2P. A pruned node without required source data does not advertise them.

## Mining

### Generation key
Template identity is the full `ReadStamp` plus template-policy, fee-delta, and time-validity revisions. Any relevant tip/policy/fee/time change invalidates it.

### Selection
Selection consumes an immutable pool snapshot and shared cluster/chunk ordering, includes dependencies once, and updates exact integer scores. Modified fees rank; actual fees pay coinbase. Bounded subset search handles near-limit chunks.

### Proposal
BIP22 proposal validation is nonmutating and distinct from submission. A matching previous hash alone is never a valid proposal verdict.

## Storage

### UTXO record (v5)
`UtxoRecord`: transaction-grouped full-txid identity with canonical compressed outputs and `u16` script-length bound. Persist changed grouped records with exact before-images; accelerators are never identity.

### Canonical record spelling
Each logical `UtxoRecord` has one canonical byte encoding, enforced by minimal varints, narrow directory widths, and complementary amount codecs.

### Deferred write
`write_deferred` makes an atomic batch visible before its own fsync; `flush` completes deferred durability.

### Logical owner ledger
Serialized key/value bytes attributable to a logical owner. It explains data-model size and is separate from physical allocation.

### Physical namespace ledger
Allocated filesystem blocks per top-level datadir namespace. The default unpruned fjall posture with optional indexes off targets a conservative physical high-water of at most `1_000_000_000_000` decimal bytes at the pinned mainnet stop. `--measure-storage` owns collection; `docs/contracts/storage-footprint.md` owns the gate.

### Work-count assertion
A deterministic count of expensive operations. Wall-clock assertions belong in paired benchmarks.

## Reference and evidence

### ReferenceSet
`docs/api/core-compat.toml` and `compat_manifest.rs` pin released Core 31.1 (`v31.1`, commit `9be056a8a72b624dae9623b2f7bded92c2a21c91`, archive SHA256 `b80d9c3e04da78fb6f0569685673418cf686fadba9042d926d13fb87ff503f9e`, bitcoind SHA256 `986e63b3c8770f08d0059820ad3dd085d1ab9e1bea23946c243f858a06888a08`) separately from the 31.99.0 kernel tree via `bitcoinkernel 0.2.1`.

### Compatibility class versus readiness versus evidence
Manifest implementation status, runtime capability readiness, and executed evidence are independent facts.

### Guard register
`CONSTRAINTS.md` records CL-01..CL-23, formal-tool pins, and proof inventory; it points to normative owners rather than duplicating policy.

### Formal models
`docs/models/{ChainAdmission,PeerLeases,ProjectionMining}.tla` and `.cfg`, checked with Apalache 0.62.2 at K=128. Bounded model checking is evidence for the abstraction, not implementation proof.

### Blocked gate
A check missing a required binary, corpus, digest, identity, or hardware records `BLOCKED`; absence never counts as pass.

## Measurement

### Product performance cell
One product domain (`offline`, `p2p`, `muhash`) × corpus (`c150`, `cmodern`) × native architecture × backend. See `docs/contracts/hot-path-attribution.md`.

### Hot-path attribution ledger
`docs/benchmarks/hot-path-ledger.toml` is the single hot-path/overlap/disposition inventory. Nested or parallel stage timings are diagnostics, not additive product wall time.

### Evidence identity
Samples record artifact hash, configuration, corpus, durability, toolchain/features, host, and reference identities.

### Promotion floor
Keep an optimization only with at least 1.05x median gain on the named cell, three alternating candidate/control runs, <=5% arm instability, gain above host noise, and identical result hashes. Non-target guards are 3% median and 5% p99. Missing target hardware blocks performance proof.

### Retained benchmark contract
Permanent benchmarks call shipped production paths with product-shaped workloads and protect current regressions. Workflow `bench-smoke` jobs own CI compilation coverage.

### C150
Historical corpus: mainnet genesis through height 150,000. `docs/contracts/campaign-corpora.md` owns identity and census.

### Cmodern
Modern corpus: mainnet genesis through height 709,635. `docs/contracts/campaign-corpora.md` owns identity and census.

### Matched-harness comparison
Cross-node ratios require matched block source, validation posture, allocator, CPU pinning, and measurement phase, with interleaved arms on an idle host.

### Offline full-validation comparator
Processing-bound Core 31.1 vs bitcoin-rs chainstate build from one hash-pinned archive under full validation, matched index posture, and production durability. See `docs/benchmarks/offline-full-validation.md`.

### CPU-seconds as a first-class metric
Throughput work records CPU time as well as wall time so parallelism cannot hide extra compute.

### Contended-harness tuning artefact
Do not tune parallelism while the harness competes with the node for CPU; that measures contention, not the node.

### CI lane parity
A branch is green only against workflow commands. `.github/workflows/ci.yml` is the PR gate; `.github/workflows/main.yml` owns main-only oracle work. `cargo deny` failures are defects, not lint noise.
