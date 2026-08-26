# Concepts

Shared domain vocabulary for this project: entities, named processes, and status concepts with project-specific meaning. Seeded with core domain vocabulary, then grows as the project records new learnings; direct edits are fine. Glossary only, not a spec or catch-all.

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
The applied-tip identity captured when an Esplora GET request begins. Generic
index queries keep their own snapshot, watermark, and revision validation, but
one Esplora response may compose several such queries with mempool and block
metadata. The router therefore returns `503` if the applied-tip identity is not
the same when composition finishes, rather than mixing independently valid
answers from opposite sides of a reorg.

## Initial Block Download

### Initial Block Download (IBD)
The one-time bulk process of downloading and fully validating the chain from the start point (genesis, or a trusted snapshot) up to the network's current best tip; run when a node first starts or has fallen far behind normal operation. Its dominant cost at high block heights is download bandwidth, not local validation.

### Apply frontier
The greatest height up to which every block has been validated and committed to the UTXO set in one unbroken run — the contiguous tip of *applied* state, distinct from the header tip (how far valid headers are known) and from blocks already downloaded but not yet applied because an earlier block is still missing.

The frontier advances only over a contiguous run: a single missing or late block at the frontier stalls all apply progress even when many later blocks are already in hand. This is why a slow peer assigned the frontier block can freeze sync.

### Download window
The bounded set of blocks permitted to be in flight — requested from peers but not yet received — at any moment during sync. It is capped jointly by a block count and an estimated-bytes budget and is refilled as blocks arrive.

### Staller
A peer that holds up the apply frontier by having been assigned a frontier block it then fails to deliver promptly.

Stalling detection is the mechanism that identifies the staller and, in the reference (Bitcoin Core) design, disconnects it so another peer can supply the blocking block. Without stalling detection, a staller freezes apply progress until a long fixed timeout elapses.

### assumevalid
A validation mode that skips script-signature verification for blocks at or below a configured trusted height while still performing every other consensus check, used to accelerate IBD without abandoning validation; blocks above the height are fully verified. Mainnet nodes in `bitcoin-rs` default to assume-valid enabled at anchor height 938343.

### Hash-pinned assume-valid anchor
The mainnet consensus checkpoint (height 938343, block `00000000000000000000ccebd6d74d9194d8dcdc1d177c478e094bfad51ba5ac`) used by default on mainnet to gate historical script verification. The node skips script verification for blocks at or below height 938343 only after validating that the active header chain contains this exact anchor hash. Sub-anchor header tips and diverged chains remain untrusted and trigger full script verification. Passing `--assume-valid-height 0` explicitly requests full verification across all blocks. Custom nonzero heights skip script checks up to that height without hash gating. Non-mainnet networks default to height 0. Replay measurement tools like `mainnet_prefix_replay` retain a default of 0 to ensure full-validation benchmark fidelity.

### Optimized default posture
The standard node operational configuration tuned for mainnet sync: `fjall` storage backend, multi-peer block download active (outbound peer target 8, pending block budget 128, 16 in-flight requests per peer), hash-pinned assume-valid active on mainnet (height 938343), 450 MiB database cache (`dbcache`, matching Bitcoin Core parity), with the secondary `txindex` and pruning disabled by default.

### Container deployment posture
The checked-in Docker Compose specialization of the optimized default posture. The image compiles only the production `fjall` storage and `bitcoinkernel` verifier features and runs as an unprivileged user. The BIP300/301 integration Compose publishes P2P on the configured host port, keeps JSON-RPC on the host loopback interface, leaves `txindex` and `scriptindex` disabled, supplies local-development RPC credential fallbacks that deployments should override, and namespaces node and enforcer data by `BITCOIN_RS_NETWORK` so incompatible P2P networks never reuse runtime state. Esplora shares the node HTTP listener rather than adding a second bind surface. Shutdown allows up to 5 minutes because the bounded subsystem drain is followed by an unbounded, synchronous full-UTXO clean checkpoint; this is an operational SIGKILL guard, not a checkpoint-duration guarantee.

### Node network selection
The user-facing `BITCOIN_RS_NETWORK`/`--network` selection that atomically supplies consensus rules and P2P bootstrap identity while preserving later, low-level overrides. Standard Bitcoin names use their matching consensus `Network`, message start, and DNS bootstrap. `drynet4` uses mainnet consensus history with message start `eca5d404`, disables Bitcoin DNS seeds, and connects to `drynet4.drivechain.dev:8533`. Compose passes the same selection to bitcoin-rs and the BIP300/301 enforcer and uses it to namespace their data directories. The internal consensus `Network` remains `mainnet` for drynet4.

### Sync regimes (download-bound vs processing-bound)
The two distinct cost regimes any sync measurement must name before its numbers mean anything. **Download-bound:** wall-clock is decided by the network path (peer scheduling, per-peer bandwidth, staller handling) — the regime of live IBD. **Processing-bound:** blocks are already local and wall-clock is decided by validation plus storage commit — the regime of reindex and offline replay. A node can rank differently in the two regimes, so a faster-than-X claim is meaningless without stating which regime was measured and with what validation posture. Within a regime the comparison is only as good as its least-matched input — see *Matched-harness comparison*.

## Benchmark campaign tooling

### Native benchmark custody
The benchmark-campaign contract that binds each timed arm to hash-verified program and input objects held open for the child, while excluding proof and evidence processing from the measured interval and keeping the result inside its configured run.

Programs and inputs stay role-bound for the full cell. Before each child starts, the runner sets CPU affinity and requires the kernel's effective mask to equal the configured mask; it then restores the caller's mask. After the child exits, the runner fingerprints its native evidence, parses it through a retained descriptor, and verifies the configured path and descriptor before and after result publication. A successful arm includes complete process and resource measurements. A demonstrated correctness failure remains a failure when the other arm has no result. Later validation recomputes the verdict from the custody artifacts and rechecks every input after the last evidence read. Custody proves internal consistency, not a cryptographic signature.

## Consensus validation

### bitcoinkernel
Bitcoin Core's C++ consensus engine (`libbitcoinkernel`), compiled into `bitcoin-rs` as the production consensus default across consensus, node, and binary crates. Beyond script verification it is also the block **parser** on the apply path — see *One-shot kernel block parse*. It validates input scripts across all script classes (legacy, segwit, and Taproot key-path and script-path spends). Default builds require system dependencies (`cmake` and `libboost-dev`). Production transaction and block input-script verification route to bitcoinkernel when default features are enabled, while Rust performs surrounding non-script transaction and block consensus checks; the Rust `Interpreter` remains a separate portable script-verification surface under `--no-default-features`.
### bitcoinconsensus
Removed historical script verification backend. Previously linked as an extracted C library for non-taproot script checks before being deleted in favor of `bitcoinkernel`. The library lacked complete-prevout and Taproot script-path verification capabilities required for current mainnet script validation (exposed by block 938344 during mainnet IBD).

### Difficulty-1 target
The network-independent reference target used by Bitcoin Core's difficulty
calculation: compact nBits `0x1d00ffff`, rather than the selected network's
PoW limit. Confusing the two makes every network report difficulty `1.0` at
its easiest target. See
`docs/solutions/logic-errors/core-float-parity-is-value-parity-not-json-text-parity.md`.

### Float value/text parity
The distinction between equal IEEE-754 values and equal serialized spellings.
Core's UniValue uses `%.16g`, while the live RPC path's sonic-rs serializer
uses shortest-round-trip formatting, so compatibility means preserving the
value and operation order, not forcing JSON text to match. See
`docs/solutions/logic-errors/core-float-parity-is-value-parity-not-json-text-parity.md`.

### Rust interpreter (portable posture)
The pure-Rust script verification path maintained alongside the bitcoinkernel default. Enabled under `--no-default-features` without C++ build dependencies. Its non-Taproot path is a stub that accepts only a bare `OP_TRUE` spend with an empty scriptSig and witness, so it cannot validate ordinary spends either, and it has no Taproot script-path support. What it does verify is the Taproot key path, in full. It is retained for differential testing and lightweight non-production environments; a mainnet sync stops early on the first real spend.

### One-shot kernel block parse
Parsing each block exactly once with `bitcoinkernel::Block::new` (wrapped as `KernelBlock` in `crates/consensus/src/kernel.rs`) and reusing that parse for everything downstream. It supplies three things at once: the **txids** (Core's `CTransaction` hashes itself while deserializing, using the SHA-256 implementation Core selects at runtime — `avx2(8way)` on Skylake-SP), and the **transaction objects** that script preparation borrows via `TransactionRef` instead of re-serializing. It replaced a scalar `compute_txid` pass plus a per-transaction `encode::serialize` → `Transaction::new` round-trip, cutting `script_prepare` from 18.55s to 4.29s and the 0→150k replay from 137.3s to 121.9s. The costing lesson generalizes: **price a replacement by everything it subsumes**, not by the line item that motivated it — costed against parse-and-serialize alone the same change scores +1.54s and looks like a loss.

### Parallel granularity (per-item cost rule)
Whether a fan-out pays is decided by per-item work against dispatch cost, not by how parallelizable the loop looks. Measured both directions on the same apply path: script checks (~100 µs per input) wanted *more* parallelism, and a sweep lowering `MIN_PARALLEL_SCRIPT_CHECKS` from 16 to 4 read as 1.15× before it was refuted as a contended-harness artefact (see *Contended-harness tuning artefact*; the standing constant is 32, `crates/consensus/src/verify_tx.rs`); UTXO lookups (~500 ns) wanted *none*, and deleting two rayon fan-outs bought 1.07× and 1.11×. Merkle nodes (~2.6 µs) sit in between: Rayon task fan-out over scalar nodes measured neutral-to-worse (SIMD multi-buffer hashing is a different lever because it reduces cost per group rather than changing task granularity). A threshold has an interior optimum in both directions — below 4 the script threshold turns back up, and pool width peaks at 32 then degrades at 64. Always gate on **elapsed**, never on the stage being targeted: parallel prepare makes `script_prepare` 30% faster and the whole run 4% slower by contending with the script-verify pool. See `docs/solutions/performance-issues/processing-bound-sync-performance-evolution.md`.

The AVX2 Merkle result pins the distinction. Reusing prepared txids and hashing eight independent 64-byte parent pairs in SIMD lanes cut the matched fjall replay from 56.517s to 48.020s (1.177×), while scalar-library swaps and Rayon folds had failed. SIMD paid because it reduced the cost of a homogeneous batch without scheduling more tasks. The same candidate passed the RocksDB and redb gates at 1.171× and 1.112×.

### Matched-harness comparison
The requirement that a cross-node benchmark match every input that is not the thing under test — block source, validation posture, CPU pinning, and time of measurement — before any ratio is quoted. Each mismatch found in this repo moved the headline materially: Core's reference was months stale (67s → re-derived 59.6s); bitcoin-rs fetched blocks over REST from a live `bitcoind` while Core read local `blk*.dat`, which cost ~35s of harness *and* contended for CPU (121.9s → 84.6s once `--blocks-file` matched it); and GoCoin skips script verification below its default `LastTrustedBlock` of #940000, so it must be compared either against an assume-valid bitcoin-rs run or with that asymmetry stated. Interleave both nodes back-to-back on an idle host and quote paired medians; comparing your best run against someone else's old run is not a measurement.

The allocator is part of the harness too. At commit `ff2615a`, the same local
0→150,000 replay measured 63.43s / 399.63 CPU-s with the system allocator and
56.16s / 396.50 CPU-s with production-matched mimalloc. The allocator changed
wall scheduling, not total work, and raised peak RSS by 15.8%. A replay control
must therefore match the production allocator and report RSS with both time
axes. See
`docs/solutions/performance/allocator-parity-changes-wall-not-cpu.md`.

The final prepared-txid plus AVX2 Merkle panel follows this rule: three candidate and three Core runs were interleaved on CPU set `0-31`, with a 30-second cooldown, identical local blocks 0→150k, and full validation. The medians were 49.356s versus 64.914s wall and 390.542s versus 481.092s CPU, so bitcoin-rs led by 1.315× wall and 1.232× CPU. All three storage backends reached the same tip and UTXO commitments. See `docs/benchmarks/data/end-to-end-sync/avx2-merkle-custody-v1.json`.

### Script-flag exceptions (BIP16Exception)
The historical blocks Bitcoin Core hardcodes in `consensus.script_flag_exceptions` (chainparams) to be validated under a reduced script-verification flag set, because they contain spends valid under the rules in force at the time but invalid under a later-enforced flag. As of Core v29: mainnet block 170060 (`…ac4f9c22`, the BIP16/P2SH exception) and 692261 (`…e1e395ad`, the Taproot exception); testnet3 block 394; none on testnet4/signet/regtest. The two **P2SH waivers** (170060, 394) are reproduced explicitly by `Network::is_bip16_p2sh_exception` (keyed by block hash, mainnet/testnet3 only); missing them rejects canonical blocks and wedges full-validation sync past the assume-valid height. The **692261 Taproot override** needs no rs exception: Core's override only strips TAPROOT (which Core defaults on for all blocks), and rs already height-gates taproot (`is_taproot_active`, 709632 > 692261) so it never sets TAPROOT there — its computed flags already match Core's effective set. Compare *effective* flag sets, not raw overrides. See `docs/solutions/architecture-patterns/p2sh-flag-must-honor-core-script-flag-exceptions.md`.

### CI lane parity
The rule that a branch is green only against the commands in `.github/workflows/ci.yml`, never against a local approximation of them. Three differences bite: `-D warnings` on the `clippy` and `kernel-parity` lanes promotes every warning the workspace lint job merely reports (`dead_code`, `needless_borrow`, `doc_markdown`, `needless_collect`, `too_many_lines`); a virtual workspace silently drops `--workspace --features`, so the four-backend and kernel surface is only reached through `-p bitcoin-rs --no-default-features --features "$FULL_NODE_FEATURES"` plus a separate `-p bitcoin-rs-node` pass for its test targets; and `kernel-parity` adds `--include-ignored` on a debug profile. `cargo deny` belongs in the same sweep and is a bug report, not lint noise. See `docs/solutions/best-practices/workspace-clippy-does-not-predict-the-d-warnings-lanes.md`.

### CPU-seconds as a first-class metric
The rule that a throughput change is measured against CPU time as well as wall time, because a many-core idle benchmark host lets wall-clock tuning spend cores for free. Sampling `utime+stime` from `/proc/<pid>/stat` while polling height is enough; no profiler or metrics plumbing is required, and per-thread attribution comes from summing `/proc/<pid>/task/*/stat` by thread name.

The controlled one-peer daemon IBD panel in [`docs/benchmarks/data/end-to-end-sync/daemon-ibd-custody-v1.json`](docs/benchmarks/data/end-to-end-sync/daemon-ibd-custody-v1.json) establishes the current bounded network-regime baseline across mainnet 0–150,000: Bitcoin Core median elapsed time is 73.459s against bitcoin-rs 89.576s. Core's elapsed time was 0.820× bitcoin-rs's elapsed time, so Core delivered 1.219× bitcoin-rs throughput. The 2× throughput target is unmet on this bounded daemon workload. This benchmark measures single-peer requester and apply behavior over loopback P2P on early blocks; it does not generalize to current-tip blocks or multi-peer Internet IBD. Earlier uncontrolled loopback measurements (such as 76.3s wall / 318.4s CPU vs Core 42.5s / 65.0s) showed a wider CPU gap that highlighted rayon spin and oversubscription risks before pool capping.

The matched local-file processing panel at commit `ff2615a` supersedes the older processing-bound CPU deficit: production-matched bitcoin-rs measured 56.16s / 396.50 CPU-s against Core 31.0 at 64.74s / 477.82 CPU-s. The network-bound daemon IBD results remain valid for their download-and-apply regime; they cannot be carried into the local replay regime. See `docs/solutions/performance/allocator-parity-changes-wall-not-cpu.md`.

The final AVX2 panel adds the same proof after the Merkle change: bitcoin-rs beat Core by 1.315× wall and 1.232× CPU while using 1.042× its peak RSS. The CPU result rules out a wall-only win bought by extra parallel work; the kernel batches eight hashes in SIMD lanes inside one task.

### Global rayon pool cap
The process-wide rayon pool is capped at `GLOBAL_RAYON_THREADS` (4) by `cap_global_thread_pool` in `crates/node/src/run.rs`, called at the top of `run`. rayon otherwise sizes that pool at one worker per core, and because it leaves those workers unnamed they inherit the process name — which is why per-thread CPU attribution first blamed the async runtime. The pool runs only short coarse jobs (block txid hashing, shard commits) while `SCRIPT_VERIFY_POOL` separately holds up to 32 threads, so an uncapped global pool oversubscribes a many-core host and its workers spin for work that is not there. Capping it cut a loopback P2P sync to 150k from 75.6s wall / 314.4s CPU to 64.4s / 162.4s across three interleaved pairs — **both axes at once**, so it is not a wall-for-CPU trade. With the `MIN_PARALLEL_SCRIPT_CHECKS` correction stacked on top, that sync finally lands at 62.8s / 90.1s against Core's 45.9s / 67.8s. The width sweep is flat from 2 to 8; the full-verification replay is insensitive at every width because script verification dominates it and runs in its own pool. Contrast `Parallel granularity (per-item cost rule)`, which is about *when* to fan out; this is about *how wide* the shared pool may be.

### Contended-harness tuning artefact
The failure mode where a parallelism constant is tuned while the benchmark harness competes with the node for CPU, so the measured optimum is a property of the contention rather than of the code. In this repo it produced two wrong constants. `MIN_PARALLEL_SCRIPT_CHECKS` was walked down to 4 by a sweep whose harness fetched every block over REST from a second `bitcoind` on the same cores; the inflated serial path made ever-finer fan-out look free and the curve read as monotonic. Re-measured against local block files the ordering **inverts** — 4 becomes the worst point tested on both wall and CPU, and the optimum is 32 (75.5s / 649.6s versus 84.4s / 946.6s). The global rayon pool was the same mistake in a different guise: uncapped, it cost nothing measurable in wall time on an idle many-core host. Two rules follow: never tune a parallelism constant against a harness that shares CPU with the node, because contention changes the shape of the curve and not merely its offset; and never tune one on wall alone, because both bad constants were wall-optimal on the host that chose them. See also `CPU-seconds as a first-class metric` and `Global rayon pool cap`.

### Commit point (multi-store mutation)
The mutation that makes a multi-store operation visible. It identifies the state transition that readers treat as complete; it does not make every preceding mutation atomic. For an authoritative block disconnect, the commit point is the `applied_tip` rollback. It runs after the UTXO undo and the block-level coinstats rewind. `TxIndex` is derived state outside this transaction: publishing the applied tip increments its revision and wakes its worker, which later reconciles separate durable capability watermarks. The UTXO set is RAM-resident and becomes durable only at a clean checkpoint. A checkpoint flushes the shared storage backend before it publishes the matching UTXO state. The UTXO undo can fail after some shards changed, so it cannot be retried. `DisconnectError` therefore splits `Refused` (nothing touched) from `Fatal` (the authoritative state can be partly rolled back). An in-flight marker in `UndoData` is armed before the first authoritative mutation. A fatal outcome closes apply admission and triggers process shutdown. Startup refuses to serve the torn state. See *Disconnect marker phase* and `docs/solutions/architecture-patterns/node-reorg-execution-design.md`.

### Deferred block-body index durability
The `KvStore::write_deferred` path (`crates/storage/src/trait_.rs`), which writes a batch without forcing its own fsync and leaves durability to the next checkpoint flush. Block-body index rows use it because a lost row is rebuilt from the block file, so paying `Durability::None` per batch and one ordered flush at the checkpoint beats an fsync per batch. Correctness rests on flush ordering, not on the batch itself: the body bytes must be durable before the index row that points at them is published. See `docs/solutions/performance-issues/defer-redb-block-body-index-durability.md`.

### TxIndex capability watermarks
The two versioned durable `(height, block hash)` cursors that identify the exact active-chain prefixes represented by independently ready row families. `TxLookup` owns `TxConfirmed`; `ScriptHistory` owns `Funding` and `Spending`; `BlockHeaders` is shared rollback-integrity metadata. `--txindex` enables and publicly advertises `TxLookup`. `--scriptindex` enables the generic script UTXO and transaction-history view, and builds internal `TxLookup` rows for Esplora prevout, fee, and exact-transaction projections; it never changes Core txindex advertisement. When the cursors start together, one block-body scan prepares both families and one atomic batch writes their rows and both final watermarks. When they differ, the lagging capability advances or rolls back independently to the applied tip; the worker does not add an intermediate convergence boundary. Height alone cannot prove identity across a reorg. On startup, an older or unversioned derived-index format is deleted in bounded batches and rebuilt from the active chain before either capability becomes queryable; this never touches UTXO or block-body data.

If a preserved disabled capability is re-enabled after a reorg, the worker first reconciles its durable cursor. Shared block identities remain available for every ancestor that the preserved cursor may still need. Competing-branch identities can therefore coexist in `BlockHeaders`; its row order, count, and contents must never be interpreted as the active chain or its tip. Authoritative header serving and chain progress come from `BlockTree`. When a disconnected body or its rollback identity is no longer available, a crash-resumable reset atomically removes the affected cursor, deletes only its derived rows in bounded batches, and rebuilds it from available active-chain bodies. A reset marker makes restart finish deletion before the writer is exposed. Resetting `ScriptHistory` preserves `TxLookup` and shared block identities; resetting both also clears shared identities.

### Complete derived-index query
A query returns a result only when one snapshot proves that every capability it consumes covers the exact applied tip. Core transaction and outpoint lookup require the `TxLookup` watermark. Script UTXO and history queries require the `ScriptHistory` watermark. The query captures the applied tip and process-local revision, opens one typed storage snapshot, checks the required watermark(s) by height and hash, and rechecks the tip and revision before returning. Aggregate row, byte, scan, and body-load budgets bound the work. Capability lag, worker failure, a missing block body, a truncated scan, budget exhaustion, a tip change, and an ABA revision change return `Retry` or `Unavailable`; none can become a false absence.

### Checkpoint write batching

The checkpoint serializer writes many small record fields before it makes each
artifact durable. `HashingWriter` batches those writes in a 64 KiB userspace
buffer, then flushes the buffer before it returns the byte count and digest.
The following file `fsync`, directory sync, generation rename, and `CURRENT`
publication barriers do not change. The buffer changes syscall granularity,
not the checkpoint format or durability boundary. Its `finish` operation owns
the checked flush so a caller cannot publish a digest for buffered bytes that
were not handed to the file.

### Checkpoint MuHash batch

The independent checkpoint traversal derives CoinStats and MuHash again instead
of trusting the rolling listener that supplies live state. It encodes exact coin
preimages into a bounded arena and computes insert-only partial MuHash values in
parallel. The arena holds at most 262,144 coins or 16 MiB. Each flush uses no
more lanes than the active Rayon pool or the 32-lane cap. The larger batch
reduces partial-value construction and combination. It does not remove the
listener-versus-traversal check, change preimage bytes, change snapshot bytes,
or weaken checkpoint durability.

### Coalesced TxIndex wake
The nonblocking notification published immediately after a committed `applied_tip.store`. The publisher increments an atomic revision with `Release` ordering and calls `try_send` on a capacity-one channel. Channel tokens may coalesce or be dropped because they are only wake hints. While a forward batch is pending, each hint returns the worker to reconciliation without changing the batch's original fixed deadline. The worker checks the authoritative revision before it sleeps and also wakes on a bounded timeout when caught up.

### Provably unspendable outputs (UTXO admission)
Outputs the UTXO set never admits because no spend of them can ever be valid: an output whose `scriptPubKey` starts with `OP_RETURN`, and one longer than `MAX_SCRIPT_SIZE`. Excluding them at admission keeps the set smaller without changing any consensus outcome, so the snapshot codec carries its own version tag, `bitcoin-rs-utxo-spendable-v1`, and a set written by an older codec is not interchangeable with one written by this rule. See `docs/solutions/logic-errors/exclude-provably-unspendable-utxos.md`.

### Undo record

The per-block inverse of a UTXO commit: the outputs the block spent, with
enough metadata to recreate them, plus the outputs it created. Connection queues
the record before later apply mutations. The clean checkpoint flushes the shared
storage backend before it publishes the matching UTXO state, so the queued
record is not a separate per-block fsync boundary. The key contains height
**and** block hash so an abandoned branch record cannot be replayed against a
different block at the same height. The node retains the record after a
disconnect because flip-flop between competing branches is normal.

### Owed derived state

State that connection writes and disconnection must account for. The required action depends on how that state is addressed and published.

`coin_stats` needs an explicit inverse for its block-level fields. Its per-coin fields use the UTXO change listener, so the UTXO undo already reverses them. The filter index needs no row rollback because its rows are block-hash-addressed like block bodies; disconnection only repoints its last-tip cache. That cache and the `blocks` RPC pop are best-effort in-process refreshes.

`TxIndex` is durable derived state outside the authoritative disconnect transaction. After `applied_tip` moves, the node publishes a revision and a coalesced wake. One worker compares the enabled `TxLookup` and `ScriptHistory` watermarks with applied-tip ancestry, rolls stale cursors back to the common ancestor, and commits count-and-byte-bounded forward batches. Equal cursors share one body scan and atomic commit; divergent cursors move only the lagging capability. It can assemble one pending batch across strict descendant tip revisions. A rival, lower, or absent tip can make the worker commit the complete prepared prefix before the next pass repairs it. Queries gate on the exact capability watermarks they consume and refuse incomplete answers while any required cursor lags or the worker is unavailable.

`switch_to_branch` (`crates/node/src/reorg.rs`) is the production disconnect
caller. Sync drives it when the header and applied tips diverge. Each attempt
loads all disconnect bodies and the available contiguous connect prefix. The
disconnect preload is $O(\text{disconnect depth})$. A `ChainTransition`
witness then requires the complete authoritative plan to equal the preloaded
plan before mutation starts.

The available prefix becomes one coherent applied-tip checkpoint. If the next
body is absent, `MissingBody` identifies that suffix and sync resumes from the
published tip. A permanent connect failure invalidates the failed header and
its descendants, selects the best valid tip, and purges their bounded staging
and download ownership. An operational failure leaves the branch eligible and
keeps its ownership for retry.

Still open around it: returning a disconnected block's transactions through one
production admission pipeline shared by Esplora broadcast, P2P relay, and reorg handling;
and backfilling the filter index after a gap. The `pubsequence` stream publishes
block connect/disconnect notifications, but intentionally does not publish
mempool `A`/`R` events: the current mempool counter and mutation reasons cannot
yet guarantee the enforcer's required contiguous transaction event sequence.
Raw mempool insertion is not reconsideration because it cannot reconstruct fee,
policy, conflict, and ancestry metadata.

### Sequence stream

The Core-compatible `pubsequence` ZMQ stream is a unified block-event stream.
Each event carries the block hash, one label (`C` for connect or `D` for
disconnect), and a topic-local little-endian `u32` sequence counter. Reorg
disconnects are emitted tip-first before connects on the replacement branch.
This implementation deliberately omits mempool `A`/`R` events until the
mempool has per-transaction sequence assignment and explicit removal reasons.

### Chain control

Consensus-affecting RPCs do not mutate the RPC context's block-tree handle
directly. They delegate through the node-owned `ChainControl` boundary so the
same apply-admission and chain-transition locks protect RPC-triggered and
sync-triggered reorganizations. `invalidateblock` marks the named subtree
invalid, republishes the best remaining header tip, and moves applied
chainstate to it through the normal disconnect path. Before changing header
status it previews the replacement tip and loads every body required by the
complete disconnect/connect plan. The same chain-transition witness remains
held from that preflight through header invalidation and branch switching, so
another apply or reorg cannot enter between them; successful disconnects emit
the same `pubsequence` `D` events as an organic reorg.

Manual pruning uses `PruneAuthority`, which is derived from the apply handles.
It acquires the same apply-admission and chain-transition locks before it reads
the applied tip. It validates the monotonic prune height against that tip and
holds the authority until storage, file, and cache deletion completes.

### Dispatch-bound parallelism

A stage that is parallel in shape but serial in effect because each dispatch is
too small to amortise waking the workers. Script verification on mainnet
0..150_000 is the case: 2,868,199 input checks at a mean 69.4 us each yield only
4.4x on 32 threads. Blocks in the parallel row carry about 114 checks, while
14.6% of all checks fall below `MIN_PARALLEL_SCRIPT_CHECKS` and run serially.
The parallel rows still pay roughly 11s of dispatch across 21,474 fan-outs. The
diagnosis is a scaling sweep, not a profiler: measure the stage at 1, 4 and 32
threads and compare the speedup against the thread count. Coarsening each
dispatch does not fix it and makes it worse, because it throttles the blocks
that were scaling; only issuing fewer, larger dispatches does. See
`docs/solutions/performance/script-batching-needs-a-split-apply-path.md`.

### Window script batching

Verifying the ordered transaction unit of several consecutive blocks in one
parallel dispatch, so the fan-out is amortized over a run of blocks rather than
paid per block. The unit includes transaction pre-checks, every input script,
and transaction post-checks. The window prepares each block against an ordered
overlay, dispatches once, and issues a private, single-use
`BlockValidationProof`; the blocks then commit one at a time and in order, so
every rule needing committed state still sees the real chain. The proof owns
the `PreparedApply` it certifies and binds the block hash, predecessor, height,
flags, and locktime cutoff. Commit re-derives all five fields. A mismatch
discards both proof and prepared state and rebuilds from the live UTXO set.
Assume-valid produces a distinct `AssumeValidSkipped` state, which re-reads the
live trust gate and never takes the proof bypass.

The initial batching change took mainnet 0..150,000 from 78.4s / 643.4s CPU to
69.6s / 558.4s, with the dispatch itself falling from 44.08s to 12.55s. A later
three-run interleaved attribution panel showed that deleting the duplicate
commit-time transaction pass for matching proofs cut replay medians from
48.414266s / 406.954276s CPU to 30.438702s / 254.642286s. The proof bypass
applies only at the transaction-validation slot: block rules and BIP30 remain
before it; coinbase maturity and BIP68 remain after it. See
`docs/solutions/performance/script-batching-needs-a-split-apply-path.md`.

### Script-check floor

The native reference baseline for script verification, calculated by running the exact captured input corpus through `CPubKey::Verify` from `libbitcoinkernel-sys 0.3.0` (via bitcoinkernel 0.2.1, embedding Bitcoin Core 31.99.0 development sources: public key parsing, lax DER parsing, signature normalization, and `secp256k1_ecdsa_verify`). The capture pipeline uses same-open parse-stream custody to emit 24 fixed-order u64 counters and four file-bound native streams (`BRSCTX1\0` contexts, `BRSJRN1\0` journal, `BRSREC1\0` records, and 24-counter JSON).

On mainnet 0..150,000, all 2,868,199 input checks are ordinary legacy bare P2PKH spends that execute exactly one `OP_CHECKSIG` and one successful ECDSA verification ($a = 1.0$). `eval_script_entries` equals 5,736,398 ($2 \times 2,868,199$, two evaluator passes per input check: scriptSig + scriptPubKey). All 11 special context counters (`p2sh_redeem_spends`, `native_witness_v0_spends`, `p2sh_wrapped_witness_v0_spends`, `bare_multisig_checks`, `p2sh_multisig_checks`, `native_witness_v0_multisig_checks`, `p2sh_wrapped_witness_v0_multisig_checks`, `taproot_key_path_spends`, `tapscript_spends`, `tapscript_schnorr_checks`, `tapscript_checksigadd_checks`) and all 13 complementary execution counters are zero. The strict `classify-corpus-v2` classifier evaluates the exact product predicate (`_c150_passed`), yielding `all_passed: true` and `c150_passed: true`.

Authoritative C150/Cmodern certification requires file-bound binary streams, strict `mainnet-prefix-replay-v3` inputs, and exact classifier validation. Version 3 makes the replay's always-present txindex timing keys part of the exact contract; their values are nullable when txindex is disabled. The Cmodern product contract is pinned to mainnet height `709635` and block hash `00000000000000000001f9ee4f69cbc75ce61db5178175c2ad021fe1df5bad8f`, selected by the recovered diagnostic candidate and independently matched against Bitcoin Core REST. This pin selects the corpus boundary; it does not certify the diagnostic run. Cmodern certification still requires a fresh file-bound replay at that exact tip, valid custody and counter arithmetic, and positive counts for all 11 context classes. Direct Core REST export can export raw blocks before replay, but live REST export cannot replace file-bound census evidence. Sampled evidence (such as `kernel_verify_spike`) cannot certify a product corpus.

Native `CPubKey::Verify` execution averages 39.32 µs per attempt ($Y$), while width-1 kernel verification takes 73.62 µs per check ($X$). The residual $R = X - Y = 34.30\ \mu\text{s/check}$ represents non-ECDSA overhead (legacy sighash re-serialization, script parsing/evaluation, and FFI wrapper costs). The residual is a ceiling over non-native per-check work, not a promised or wholly removable gain. At 46.59% of per-check verification cost, this residual exceeds the 27.73% threshold required for a 5% total wall-time improvement (a 5.85s ceiling within the 12.55s script stage), keeping the non-crypto script optimization lever open.

Replay state stability is certified by untimed durability proofs (`crates/node/examples/verify_replay_durability.rs`) across all three storage backends (`fjall`, `rocksdb`, `redb`). Probes run on disposable reflink copies (`cp --reflink=always -a`), keeping original store contents untouched and byte-identical (`custody-summary.json`). Each backend executes production `switch_to_branch` parent/back reorg with durable bodies and undo records, publishes checkpoint generation 2, reopens twice, and confirms exact invariant equality (`before == after`). See `docs/solutions/performance/checksig-census-and-the-script-check-floor.md`.

### Terminal proof

A `BRSHGT1` checkpoint that binds one replay height and block hash to the committed row counts and byte endpoints of the `BRSCTX1`, `BRSREC1`, and `BRSJRN1` evidence streams. The proof is complete when every committed slice validates, all 11 Cmodern context classes have appeared, and the checkpoint height equals the last first-occurrence height. Child process exit is a separate fact. Slow chainstate teardown or a forced post-proof kill does not erase completed evidence and must not be reported as a clean exit.

Offline recovery preserves the failed source directory, hashes source bytes during semantic reconstruction, and materializes only the committed prefixes in a new single-writer directory. It creates missing recovery ancestors root-to-leaf and fsyncs each parent. Each clone states `EXACT_FULL_FILE` or `DIFFERS_FROM_SOURCE`; exact JSON clones must match the source size and digest, while normalized binary bodies must match their validated source bodies. Source and recovery descriptors and paths stay stable through candidate publication. A late mismatch durably removes the candidate. See `docs/solutions/performance/checksig-census-and-the-script-check-floor.md`.

### Front-half duplication

The failure mode where a batched fast path recomputes the sequential path's
preparation instead of replacing it, so a real saving is paid straight back.
Cross-block script batching cut crypto dispatch from 44.08s to 12.53s and moved
wall time not at all, because the batch resolved every prevout and parsed every
block that `apply_block` then resolved and parsed again for coinbase maturity,
BIP68, and the UTXO change set. The tell is that the accelerated stage shrinks
by roughly what the new stage costs. The fix is never a cheaper second pass; it
is splitting the sequential path into a prepare half and a commit half so the
preparation happens once.

### Disconnect marker phase
The durable record that an authoritative block disconnect started and how far it got. It is armed and flushed before the UTXO mutation, not written on the error path: a process that dies during rollback writes no error, which is the case the marker must detect. `TxIndex` is outside this transaction and recovers from its own atomic capability watermarks. `InFlight` means the authoritative rollback started and did not report completion; a checkpoint must not clear it because that would make a torn UTXO set durable. `RolledBack` means the in-memory UTXO set and applied tip moved together and still need one clean checkpoint. Startup refuses either phase. Only the checkpoint that publishes the rolled-back authoritative state may remove the marker.

### Count-and-byte bound
A window sized by whichever of two caps binds first. A count alone is wrong wherever item size varies by orders of magnitude: early-chain blocks average 4.6 KB, so 1024 of them is 5 MB, while at the tip the same 1024 is 2 GB. A byte cap alone is wrong in the other direction, letting a window hold tens of thousands of tiny items. Taking the minimum makes the batch large exactly where items are small and per-batch overhead dominates, and small where items are large and it does not. The script window uses it, and the same shape is owed by the sync staging budget, whose count is still sized for tip-scale blocks. One item larger than the whole byte cap still goes through alone: refusing it would stall the chain rather than process it.

### Identity-bearing key
A key that distinguishes which producer wrote a row, as opposed to one that merely locates it. The index's funding, spending, and txid keys are an 8-byte prefix plus a height, so two blocks at one height that share an output script derive identical keys, and rolling the first back a second time deletes the second's rows. The block-header row is shared rollback-integrity metadata, not owned by either capability. It is identity-bearing because its key is the 80-byte serialized header and the block hash is the double-SHA256 of exactly those bytes. Checking it before deleting is a proxy for rekeying the other three families, taken because rekeying breaks the electrs-compatible layout and forces a reindex.

### Prefix-row rescan cost
The former cost shape of every lossy-prefix index resolver: read the block once per matching row, deserialize it whole, then hash every output script in it to recover what the 8-byte prefix threw away. Measurements established the problem: `resolve_script_history` rose 63.9x for a 64x rise in funding rows and 3.6x for 4x the block bytes, so the two terms were linear and multiplied. An address funded at 64 heights therefore cost 86.53 ms end to end against a 30 ms budget. `resolve_unspent_outputs` paid roughly double because it computed a txid for every transaction before checking any script. The index now stores each matching transaction's byte position in the row value. Both `Indexer` and the snapshot-gated `TxIndexQueryEngine` read those exact ranges and retain the full txid or scripthash check. The async path charges one bounded body-read operation and the returned bytes for every range attempt. It scans the full block only when the value or exact check is unusable. See *All-or-scan position fallback* for the completeness rule and *Identity-bearing key* for the same lossy prefix on the rollback side.

### All-or-scan position fallback
The invariant that lets index row values carry transaction byte positions without a block tag. The valid-state prerequisite is strict: the single writer atomically commits every row mutation with its exact full-hash capability watermark, rolls rows back before a replacement, and snapshot queries accept a result only when every required watermark equals the applied tip and both revision and tip remain stable. The reader validates the complete position list before I/O: it must be nonempty, strictly increasing, unique, nonoverlapping, within the block bound, and free of arithmetic overflow. It then reads each range from the current canonical `(height, full hash)` and exact-checks the decoded txid or scripthash. If any position fails, the reader discards every tentative result for that row and scans the full block; it never skips one position and keeps the rest. This also handles ordinary 8-byte prefix collisions. A stale row under an accepted watermark requires manual mutation, broken backend atomicity, or storage corruption and is outside the valid index-state contract; a full scan cannot make an arbitrarily corrupted row key authoritative. A per-row block tag was rejected because it measured 0.66x on top of the 1.67x position cost. See *Prefix-row rescan cost* for the range-read gain and *Identity-bearing key* for the write-side rollback guard.

### Paired-arm benchmark
A Criterion group holding the before and after implementations of one change over one identical fixture, so the ratio comes from a single run. Adopted because a stored baseline cannot be trusted across a rebuild, and because the before implementation is wanted anyway as the equivalence oracle — the same function serves both roles. Its second use is diagnostic: while both arms still call the same code, their spread *is* the harness noise floor, measured rather than assumed. That reading is what disqualified the 64-height `subscribe` and `get_balance` groups, whose identical arms differ by 2.0-2.4x on a laptop and therefore cannot resolve a 1.05x gate, while `get_history` held within 1%. A group that cannot resolve the gate does not get to report a win.

### Resolution-time sampling
Recording a statistic when its outcome is known rather than when the subject arrives. The fee estimator counted a transaction against every confirmation target the moment it entered, so a fresh arrival was already a failure at every target and a burst silenced the estimator before anything had missed a deadline. It also broke the decay: the denominator had been decaying since entry while a confirmation arrived undecayed, reporting 81 successes in 100 as roughly 85%. Sampling numerator and denominator together at the moment a target resolves fixes both, because they then decay from the same block. The counterpart rule is that a subject leaving for an unrelated reason is untracked without being sampled: an eviction says something about the mempool, not about whether the transaction would have confirmed.

### Directory-layout record
A record that keeps its per-item lookup keys and item lengths in fixed-width arrays in front of the items, rather than inline with them. `UtxoRecord` v5 is `txid || output_count || legacy_inline_len || widths || vout_dir || len_dir || payloads`, where each directory entry is the narrowest little-endian width the record needs. The reason is random access: the hot read is `find_output(vout)` — every spent input resolves through `Shard::get`/`get_entry`/`get_meta` — and in a flat variable-length layout each field's length is what locates the next one, so finding output `i` walks the bytes of outputs `0..i`, scripts included. That was measured at 4.4-4.9x slower than the fixed-width v4 it replaced. With directories a lookup scans one dense byte array and sums a second, touching about two bytes per output instead of thirty-five. The two layouts cross over near 64 outputs: below it v5's fixed setup dominates and it is about 3 ns slower at the measured mainnet average of 3.626 outputs per record, above it the scan dominates and v5 wins by up to 1.58x. Storing lengths rather than script lengths is what makes the directory free — the script is whatever remains of its payload, so no length is stored twice. See `docs/benchmarks/utxo-memory.md`.

### Canonical record spelling
The rule that one logical record has exactly one byte string. Fixed-width fields give this away for free; variable-width encodings must enforce it, and `UtxoRecord` compares and hashes by bytes, so a second spelling makes equal records unequal. v5 needs three rules to keep it: a varint must be minimal, because `[0x80, 0x00]` also decodes to zero; a directory width must be the narrowest that fits, because a wider one describes the same record; and the compact amount form and the escape must be exact complements, so the compact form may encode only amounts the escape refuses and the escape refuses only amounts the compact form covers. The last of these is also a safety rule rather than a tidiness one: `read_varint` hands `decompress_amount` whatever a record contains and `validate_encoded` runs it over every output loaded from a snapshot, and the transform multiplies by up to a billion, so an unbounded input panics a debug build and wraps silently in a release one. `decompress_accepts_exactly_the_encoder_image` states the whole rule as one property over every `u64`.

### Work-count assertion
Asserting how much of an expensive operation a code path performs, instead of how long it takes. A wall-clock assertion in a test suite is a flake generator, and an assertion that a function merely returns something passes for a stub. `find_output_decompresses_at_most_the_amount_it_returns` counts `decompress_amount` calls behind a `cfg(test)` thread-local and requires one for a hit, none for a miss and none for `max_vout`, at any record size — which is the algorithmic claim the layout rests on, stated deterministically. The counterpart is the case a count cannot make: where the claim really is about elapsed time, the assertion belongs in a paired-arm benchmark, not a test.
