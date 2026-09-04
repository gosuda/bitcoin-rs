# Concepts

Shared domain vocabulary for this project: entities, named processes, and status concepts with project-specific meaning. Glossary only, not a spec, changelog, or benchmark ledger; measured numbers belong in the PR that produced them.

## Node interfaces

### Wallet-free RPC boundary
The node has no in-tree wallet and owns no private keys. Wallet funding,
signing, import, and fee-bump methods are absent. Key-free descriptor helpers,
`scantxoutset`, `combinepsbt`, and `finalizepsbt` remain node RPCs so an external
signer can drive a PSBT workflow without giving key custody to the node.

### Stable chainstate RPC read
A whole-UTXO RPC read that shares the node's chain-transition mutex. The mutex
spans both UTXO mutation and applied-tip publication, so `scantxoutset` cannot
combine outputs from one committed state with height, hash, or confirmation
metadata from another.

### REST gateway
The optional, unauthenticated Bitcoin Core-compatible HTTP surface served on
the existing JSON-RPC listener. It is enabled with `rest=1`; JSON-RPC requests
on the same listener retain their configured authentication.

### Esplora request chain view
The applied-tip identity captured when an Esplora GET request begins. One
Esplora response may compose several index, mempool, and block queries, so the
router returns `503` if the applied-tip identity changed before composition
finished, rather than mixing answers from opposite sides of a reorg.

### Sequence stream
The Core-compatible `pubsequence` ZMQ stream. Block events carry the 32-byte
reversed block hash and label byte (`C` connect, `D` disconnect). Mempool
events carry the 32-byte reversed txid, label byte (`A` admission, `R`
removal), and the 8-byte little-endian mempool sequence number assigned to the
change. A transaction mined in a connected block emits no `R`: the block's `C`
event covers it, matching Core. Every event concludes with a topic-local
little-endian `u32` sequence counter frame. Reorg disconnects are emitted
tip-first before connects on the replacement branch.

### Authoritative peer table
The single owner of live peer connections and their published handshake
metadata (`bitcoin_rs_p2p::PeerTable`). It enforces one connection per remote
address, cancels predecessors atomically on replacement, prevents stale
connection handles from evicting newer sessions via connection-identity checks,
and ties handshake metadata strictly to the live connection identity.

### Embedded node
The typed in-process surface (`bitcoin_rs_node::Node`) over the same
lifecycle the daemon runs: start against a data dir on the caller's
Tokio runtime, typed snapshot/progress/capability reads, mempool
statistics, fee estimates, gateway-routed broadcast, and a consuming
shutdown that publishes the clean checkpoint. No second lifecycle exists —
the daemon's `run()` is a signal wrapper around the identical start and
shutdown path (see `docs/contracts/embedding.md`).

## Initial Block Download

### Initial Block Download (IBD)
The one-time bulk process of downloading and fully validating the chain from the start point (genesis, or a trusted snapshot) up to the network's current best tip. Its dominant cost at high block heights is download bandwidth, not local validation.

### Apply frontier
The greatest height up to which every block has been validated and committed to the UTXO set in one unbroken run — distinct from the header tip and from blocks downloaded but not yet applied. It advances only over a contiguous run: one missing block at the frontier stalls all apply progress, which is how a slow peer can freeze sync.

### Download window
The bounded set of blocks in flight — requested but not yet received. Capped jointly by a block count and an estimated-bytes budget (see *Count-and-byte bound*) and refilled as blocks arrive.

### Staller
A peer holding up the apply frontier by failing to deliver a frontier block it was assigned. Stalling detection identifies it by window-blocked detection (not raw `applied_tip+1` stagnation), does not blame a peer when local apply/stager backpressure is the bottleneck, and disconnects it so another peer can supply the block. See `docs/solutions/architecture-patterns/multi-peer-block-download-requires-core-stalling-disconnect.md`.

### assumevalid
Skipping script-signature verification for blocks at or below a trusted height while performing every other consensus check. Mainnet defaults to the hash-pinned anchor below; other networks default to height 0. `--assume-valid-height 0` requests full verification; a custom nonzero height skips without hash gating.

### Hash-pinned assume-valid anchor
The mainnet checkpoint (height 938343, block `00000000000000000000ccebd6d74d9194d8dcdc1d177c478e094bfad51ba5ac`). Script verification is skipped at or below it only after the active header chain is shown to contain this exact hash; sub-anchor header tips and diverged chains verify fully.

### Optimized default posture
The default mainnet configuration: `fjall` backend, multi-peer download (outbound target 8, pending block budget 128, 16 in-flight per peer), hash-pinned assume-valid, 450 MiB `dbcache`, `txindex` and pruning off. The checked-in Compose specialization compiles only `fjall` + `bitcoinkernel`, runs unprivileged, and namespaces node and enforcer data by `BITCOIN_RS_NETWORK`.

### Node network selection
`BITCOIN_RS_NETWORK`/`--network` atomically selects consensus rules and P2P bootstrap identity while preserving later low-level overrides. The internal consensus `Network` remains the consensus selector: `drynet4` keeps mainnet consensus with message start `eca5d404`, no Bitcoin DNS seeds, and `drynet4.drivechain.dev:8533`. See `docs/solutions/architecture-patterns/network-selection-keeps-p2p-identity-atomic.md`.

### Sync regimes (download-bound vs processing-bound)
The two cost regimes a sync measurement must name before its numbers mean anything. **Download-bound:** wall is decided by the network path — live IBD. **Processing-bound:** blocks are local and wall is decided by validation plus storage commit — reindex and replay. A node can rank differently in the two, so a faster-than-X claim needs the regime and validation posture stated.

All benchmark campaign evidence and tooling is retired by #224. The seven
retained Criterion benchmark targets are compiled in the `bench-smoke` CI lane
(`bitcoin-rs-consensus --bench merkle`, `bitcoin-rs-consensus --bench verify_tx`,
`bitcoin-rs-storage --bench kvstore_backends`, `bitcoin-rs-utxo --bench record_codec`,
`bitcoin-rs-utxo --bench utxo_commit`, `bitcoin-rs-mining --bench candidate`,
`bitcoin-rs-node --bench sync_pipeline`).
## Consensus validation

### bitcoinkernel
Bitcoin Core's C++ consensus engine (`libbitcoinkernel`), the production consensus default. It is both the input-script verifier for every script class and the block **parser** on the apply path (*One-shot kernel block parse*). Rust performs the surrounding non-script transaction and block checks. Default builds need `cmake` and `libboost-dev`.
### Rust interpreter (portable posture)
The pure-Rust script path under `--no-default-features`. It fully verifies the Taproot key path; its non-Taproot path is a stub accepting only a bare `OP_TRUE` spend, and it has no Taproot script-path support. Retained for differential testing and lightweight non-production environments; a mainnet sync stops at the first real spend.

### One-shot kernel block parse
Parsing each block exactly once with `bitcoinkernel::Block::new` (`KernelBlock`, `crates/consensus/src/kernel.rs`) and reusing that parse downstream for txids and the transaction objects script preparation borrows via `TransactionRef`. Price a replacement by everything it subsumes, not by the line item that motivated it.

### Script-flag exceptions (BIP16Exception)
Blocks Core hardcodes in `consensus.script_flag_exceptions` to validate under a reduced flag set. As of Core v29: mainnet 170060 (P2SH) and 692261 (Taproot); testnet3 394. The P2SH waivers are reproduced by `Network::is_bip16_p2sh_exception` (by block hash); missing them wedges full-validation sync. The Taproot override needs no exception because `is_taproot_active` already height-gates TAPROOT. Compare *effective* flag sets, not raw overrides.

### Difficulty-1 target
The network-independent reference target in Core's difficulty calculation:
compact nBits `0x1d00ffff`, not the selected network's PoW limit. Confusing
the two makes every network report difficulty `1.0` at its easiest target.

### Float value/text parity
Equal IEEE-754 values versus equal serialized spellings. Core's UniValue uses
`%.16g`; the RPC path's sonic-rs serializer uses shortest round-trip. Compatibility
means preserving value and operation order, not forcing JSON text to match. See
`docs/solutions/logic-errors/core-float-parity-is-value-parity-not-json-text-parity.md`.

### Provably unspendable outputs (UTXO admission)
Outputs the UTXO set never admits: a `scriptPubKey` starting with `OP_RETURN`, or longer than `MAX_SCRIPT_SIZE`. Excluding them changes no consensus outcome, so the snapshot codec carries the version tag `bitcoin-rs-utxo-spendable-v1`; a change to admission semantics is a codec change. See `docs/solutions/logic-errors/exclude-provably-unspendable-utxos.md`.

### Notification configuration

Node configuration groups external notification adapters below
`NotificationConfig`. ZMQ configuration follows the socket ownership boundary:
one endpoint group contains its endpoint, all topics published by that socket,
and an optional socket HWM override. Topics that share an endpoint therefore
cannot claim different HWM values. The ZMQ publisher owns the default HWM of
1,000; configuration mentions HWM only when an endpoint needs an operational
override.

The supported file form is `[[notifications.zmq]]` with `endpoint`, `topics`,
and optional `hwm`. The former topic-specific `zmqpub*` endpoint and HWM fields
are not part of node configuration, including CLI, environment, TOML, and
`bitcoin.conf` adapters.

## Block apply
### Window script batching
Verifying the ordered transaction unit of several consecutive blocks in one parallel dispatch. The window prepares each block against an ordered overlay, dispatches once, and issues a private, single-use `BlockValidationProof` that owns the `PreparedApply` it certifies and binds block hash, predecessor, height, flags, and locktime cutoff. Blocks then commit one at a time, in order; commit re-derives all five fields and on mismatch discards proof and prepared state and rebuilds from the live UTXO set. The proof bypasses only the transaction-validation slot: block rules and BIP30 stay before it, coinbase maturity and BIP68 after. Assume-valid produces a distinct `AssumeValidSkipped` state that never takes the bypass. See `docs/solutions/performance/script-batching-needs-a-split-apply-path.md`.

### Front-half duplication
The failure mode where a batched fast path recomputes the sequential path's preparation instead of replacing it, so the saving is paid straight back. The tell is that the accelerated stage shrinks by roughly what the new stage costs. The fix is splitting the sequential path into a prepare half and a commit half, never a cheaper second pass.

### Dispatch-bound parallelism
A stage that is parallel in shape but serial in effect because each dispatch is too small to amortise waking the workers. Diagnose with a scaling sweep (1, 4, 32 threads), not a profiler. Coarsening each dispatch makes it worse; only issuing fewer, larger dispatches fixes it.

### Parallel granularity (per-item cost rule)
Whether a fan-out pays is decided by per-item work against dispatch cost, not by how parallelizable the loop looks: ~100 µs script checks want more parallelism (`MIN_PARALLEL_SCRIPT_CHECKS` = 32, `crates/consensus/src/verify_tx.rs`), ~500 ns UTXO lookups want none, ~2.6 µs Merkle nodes gain from SIMD batching rather than task fan-out. Thresholds have an interior optimum in both directions. Gate on **elapsed**, never on the stage being targeted.

### Global rayon pool cap
The process-wide rayon pool is capped at `GLOBAL_RAYON_THREADS` by `cap_global_thread_pool` (`crates/node/src/run.rs`). It runs only short coarse jobs while `SCRIPT_VERIFY_POOL` separately holds up to 32 threads; uncapped, its unnamed workers oversubscribe a many-core host and spin, costing CPU without showing in wall time.

### Chain generation
The even/odd atomic counter on `MempoolGateway` that fences admission
against chain changes (`crates/mempool/src/gateway.rs`). Even values mean
the chain is stable and admission is open; odd values mean a connect,
disconnect, or reorg is in progress and admission is closed.
`stable_generation` returns `Some(even)` when stable, `None` when a chain
change is active. `begin_chain_change` takes the pool write lock, stores the
next odd value, and returns a `ChainChangeGuard` that owns the reservation.
Only `finish` may compare-exchange the odd value to the reserved even value,
reopening admission. A failed chain change leaves the generation odd —
admission stays closed until the operator restarts or the chain change
completes.

### Admission origin
The `AdmissionOrigin` enum on `MutationEnvelope` that identifies how a
transaction entered the node (`crates/mempool/src/mutation.rs`): `Rpc`
(submitted through `sendrawtransaction`), `Peer` (relayed from a network
peer, carrying a `PeerToken`), `Reorg` (re-admitted by a disconnect walk via
`reconsider_disconnected`), or `Block` (confirmed by block application). The
observer receives the origin alongside the committed `MutationResult` so
downstream consumers (ZMQ publisher, metrics) can distinguish relay from
reorg re-admission without inspecting call sites.

### Chain-change proof
The type-level binding of a `ChainTransition` to the `ChainChangeGuard` that
reserved the active odd generation (`crates/node/src/apply.rs`). Apply-path
functions accept `&ChainChangeProof`, not independent `&ChainTransition` and
`&ChainChangeGuard` arguments, so a call without an active odd generation
cannot compile. The proof's `odd_generation` returns the exact reserved
value, letting admission checks compare against a specific generation rather
than a snapshot that may have moved.

### Count-and-byte bound
A window sized by whichever of a count cap and a byte cap binds first, because item size varies by orders of magnitude across the chain. The script window uses it; the sync staging budget owes the same shape. One item larger than the whole byte cap still goes through alone.

## Chain state and reorg

### Chain control
Consensus-affecting RPCs never mutate the block tree directly; they delegate through the node-owned `ChainControl` so the same apply-admission and chain-transition locks protect RPC- and sync-triggered reorganizations. `invalidateblock` previews the replacement tip, loads every body the disconnect/connect plan needs, then holds the chain-transition witness through header invalidation and branch switching; its disconnects emit the same `pubsequence` `D` events as an organic reorg. `PruneAuthority` takes the same locks before reading the applied tip.

### Commit point (multi-store mutation)
The mutation that makes a multi-store operation visible; it does not make preceding mutations atomic. For an authoritative disconnect it is the `applied_tip` rollback, after the UTXO undo and coinstats rewind. The UTXO undo can fail after some shards changed and cannot be retried, so `DisconnectError` splits `Refused` (nothing touched) from `Fatal` (partly rolled back); `Fatal` closes apply admission and shuts the process down. See `docs/solutions/architecture-patterns/node-reorg-execution-design.md`.

### Disconnect marker phase
The durable record that an authoritative disconnect started and how far it got. Armed and flushed before the UTXO mutation, not on the error path, because a process that dies mid-rollback writes no error. `InFlight`: rollback started, completion unreported; a checkpoint must not clear it. `RolledBack`: UTXO set and applied tip moved together and need one clean checkpoint. Startup refuses either. Only the checkpoint that publishes the rolled-back state removes the marker.

### Undo record
The per-block inverse of a UTXO commit, queued before later apply mutations and made durable by the clean checkpoint rather than a per-block fsync. Keyed by height **and** block hash so an abandoned-branch record cannot replay against another block at the same height. Retained after a disconnect because branch flip-flop is normal.

### Owed derived state
State that connection writes and disconnection must account for. `coin_stats` needs an explicit inverse for its block-level fields (the default node recomputes them at checkpoint and stable reads). `TxIndex` is durable derived state outside the authoritative transaction (see *TxIndex capability watermarks*). `switch_to_branch` (`crates/node/src/reorg.rs`) is the production disconnect caller: it preloads all disconnect bodies and the available contiguous connect prefix, and a `ChainTransition` witness requires the authoritative plan to equal the preloaded plan before mutation. A permanent connect failure invalidates the failed header and descendants; an operational failure leaves the branch eligible for retry.

## Derived indexes

### TxIndex capability watermarks
Versioned durable `(height, block hash)` cursors identifying the exact active-chain prefix each independently ready row family represents. `TxLookup` owns `TxConfirmed` (`--txindex`); `ScriptHistory` owns `Funding` and `Spending` (`--scriptindex`, which also builds internal `TxLookup` rows for Esplora without changing Core txindex advertisement); `BlockHeaders` is shared rollback-integrity metadata whose row order and count must never be read as the active chain. Equal cursors advance in one body scan and one atomic batch; a lagging cursor moves independently. Height alone cannot prove identity across a reorg. Older or unversioned index formats are deleted and rebuilt on startup; a crash-resumable reset marker makes restart finish deletion before the writer is exposed.

### Coalesced TxIndex wake
The nonblocking hint published after a committed `applied_tip.store`: an atomic revision incremented with `Release` plus `try_send` on a capacity-one channel. Tokens may coalesce or drop; the worker checks the authoritative revision before sleeping and also wakes on a bounded timeout.

### Complete derived-index query
A query returns a result only when one snapshot proves every capability it consumes covers the exact applied tip: capture tip and revision, open one typed snapshot, check the required watermark(s) by height and hash, recheck tip and revision before returning. Capability lag, worker failure, missing body, truncated scan, budget exhaustion, tip change, or ABA revision change return `Retry` or `Unavailable`; none can become a false absence.

### Identity-bearing key
A key that says which producer wrote a row, not merely where it is. Funding, spending, and txid keys are an 8-byte prefix plus height, so two same-height blocks sharing a script collide and a second rollback of the first would delete the second's rows. The block-header row (keyed by the 80-byte header whose hash is the block hash) is identity-bearing; checking it before deleting stands in for rekeying the other families, which would break the electrs-compatible layout.

### All-or-scan position fallback
Index row values carry transaction byte positions without a block tag. The reader validates the whole position list (nonempty, strictly increasing, unique, in-bounds, no overflow), reads each range from the canonical `(height, full hash)` body, and exact-checks the decoded txid or scripthash. If any position fails it discards every tentative result for that row and scans the full block — never skipping one position and keeping the rest.

## Storage

### Datadir schema marker
`CURRENT_SCHEMA` at the datadir root is the sole persistent-format authority, written and synced before any checkpoint or KV store opens. Rules and the startup table live in `docs/policies/db-migration.md`. `Cold` means no committed checkpoint; `CURRENT` is the only checkpoint commit point and an invalid referenced generation is corruption with no legacy fallback. The node never deletes or converts state.

### UTXO snapshot read contract
The node accepts only complete native version-4 snapshots: exact magic and version, validated v4 records, the declared record count, a 384-byte MuHash trailer, and end-of-file. Versions 2 and 3 fail startup with a remove-and-resync instruction; there is no legacy reader.

### Deferred block-body index durability
`KvStore::write_deferred` (`crates/storage/src/trait_.rs`) writes a batch without its own fsync and leaves durability to the next checkpoint flush. Block-body index rows use it because a lost row is rebuilt from the block file. Correctness rests on ordering: body bytes are durable before the index row pointing at them is published. Weaker durability is opt-in per call site, never backend-wide. See `docs/solutions/performance-issues/defer-redb-block-body-index-durability.md`.

### Directory-layout record
`UtxoRecord` v5: `txid || output_count || inline_len || widths || vout_dir || len_dir || payloads`, with per-item keys and lengths in fixed-width arrays ahead of the items so `find_output(vout)` touches about two bytes per output instead of walking every earlier script. Each directory entry uses the narrowest width the record needs; the script is whatever remains of its payload, so no length is stored twice. See `docs/benchmarks/utxo-memory.md`.

### Canonical record spelling
One logical record has exactly one byte string; `UtxoRecord` compares and hashes by bytes. v5 enforces it with three rules: minimal varints, narrowest directory width, and compact/escape amount forms that are exact complements. The last is a safety rule: `decompress_amount` multiplies by up to a billion, so an unbounded input panics in debug and wraps in release. `decompress_accepts_exactly_the_encoder_image` states the whole rule as one property.

### Work-count assertion
Asserting how much of an expensive operation a code path performs, instead of how long it takes. A wall-clock assertion in a test suite is a flake generator, and an assertion that a function merely returns something passes for a stub. `find_output_decompresses_at_most_the_amount_it_returns` counts `decompress_amount` calls behind a `cfg(test)` thread-local and requires one for a hit, none for a miss and none for `max_vout`, at any record size — which is the algorithmic claim the layout rests on, stated deterministically. The counterpart is the case a count cannot make: where the claim really is about elapsed time, the assertion belongs in a paired-arm benchmark, not a test.
### Chain snapshot
The coherent, non-torn view of the applied tip the chain-event publisher keeps in one `RwLock`ed cell: `{ epoch, sequence, tip_hash, tip_height }` (`crates/node/src/state.rs`). The single writer replaces the whole cell per commit, so a reader never mixes two commit points. `epoch` is a persisted, strictly monotonic per-data-dir counter that makes an old run's cursors stale; `sequence` advances once per committed connect or disconnect and starts at 1. The snapshot is live state, never persisted per-event; readers take `NodeState::active_chain_snapshot`.

### Chain-event hint
The bounded-channel wake-up `ChainEventPublisher::record` emits after replacing the snapshot cell: `{ kind, height, hash, epoch, sequence }`, one per committed connect or disconnect. Hints carry no payload to apply and a full channel drops them without blocking the commit path; recovery is always positional re-planning over the chain itself. Hints are not a recovery log.

### Reconciliation consumer
An index that mirrors the applied chain by re-planning positionally against a fresh chain snapshot instead of receiving inline writes from the apply path. The txindex worker is the current consumer. A consumer owns its rows, its cursor, and its batch atomicity, and a failure or lag in it can never stall block application.

### ScriptLive view
The compact, rebuildable reverse view from script-hash prefix to currently
unspent outpoints. A `ScriptLive` row stores only an empty value and the full
outpoint after the lossy eight-byte prefix; the authoritative UTXO set owns
coin value, height, and script bytes. Queries hold the chain-transition
authority, resolve locators from one stable UTXO view, and exact-check the full
script before returning a result. Its watermark is independent of historical
script rows, so live queries can become ready while history is still catching
up.

### Consumer cursor
The durable 52-byte record `{ epoch, sequence, height, hash }` naming the exact chain state a consumer's rows already mirror (`crates/node/src/reconcile.rs`). Position (`height`, `hash`) anchors row truth; `epoch` and `sequence` are advisory identity that a restart or epoch bump invalidates without invalidating rows. It is written only when the publisher snapshot provably names the tip the rows reached, and always in the same atomic batch as the row mutations it describes.

### Capability status
The node-owned status report for concrete services exposed by the RPC layer. It
contains compiled/enabled state and progress facts without introducing a
generic extension registry or lifecycle abstraction.

## Mempool

### Resolution-time sampling
Recording a statistic when its outcome is known rather than when the subject arrives. The fee estimator samples numerator and denominator together at the moment a confirmation target resolves, so both decay from the same block. A transaction leaving for an unrelated reason (eviction) is untracked without being sampled.

## Measurement

### Retained benchmark contract
Permanent benchmarks call the shipped production path, use a product-shaped workload, and protect a regression that still matters. A/B refactor harnesses, synthetic microbenchmarks, and future-work measuring tools are not retained. The retained set: node sync/apply, reduced UTXO commit, end-to-end mempool admission, Merkle dispatch, and the real-file index resolver.

### Matched-harness comparison
A cross-node benchmark matches every input that is not the thing under test — block source, validation posture, allocator, CPU pinning, time of measurement — before any ratio is quoted. Interleave both nodes back-to-back on an idle host and quote paired medians. See `docs/solutions/performance/allocator-parity-changes-wall-not-cpu.md`.

### CPU-seconds as a first-class metric
A throughput change is measured against CPU time as well as wall time, because an idle many-core host lets wall-clock tuning spend cores for free. Sampling `utime+stime` from `/proc/<pid>/stat` while polling height is enough; per-thread attribution comes from `/proc/<pid>/task/*/stat`.

### Contended-harness tuning artefact
A parallelism constant tuned while the harness competes with the node for CPU, so the optimum measures the contention. Never tune a parallelism constant against a harness sharing CPU with the node, and never on wall alone.

### CI lane parity
A branch is green only against the commands in `.github/workflows/ci.yml`, never a local approximation: `-D warnings` on the `clippy` and `kernel-parity` lanes promotes warnings the workspace lint job merely reports; a virtual workspace drops `--workspace --features`, so the full surface is only reached through the per-crate `-p` invocations; `kernel-parity` adds `--include-ignored`. `cargo deny` failures are bug reports, not lint noise.
