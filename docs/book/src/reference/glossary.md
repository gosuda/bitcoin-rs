# Glossary

The project's shared vocabulary is [`CONCEPTS.md`](https://github.com/gosuda/bitcoin-rs/blob/main/CONCEPTS.md). The entries below give the short form used in this book.

**Admission origin.** The `AdmissionOrigin` value on a mempool mutation that says how a transaction entered the node: RPC submission, peer relay, reorg re-admission, or block confirmation. Consumers such as the ZMQ publisher and metrics read it instead of inferring the path from a call site.

**Apply frontier.** The greatest height up to which every block has been validated and committed to the UTXO set in one unbroken run. One missing block at the frontier stalls all apply progress, which is how a slow peer freezes sync.

**assumevalid.** Skipping script-signature verification for blocks at or below a trusted height while still performing every other consensus check. Mainnet defaults to the hash-pinned anchor; other networks default to height 0, and `--assume-valid-height 0` requests full verification.

**BIP324 decoy packet.** A version-2 transport frame marked as a decoy, or a message-less frame of an empty or undefined type. It returns control to the session one packet at a time and does not count as receive activity, so a decoy-only peer expires on receive silence at 20 minutes.

**bitcoinkernel.** Bitcoin Core's C++ consensus engine, compiled in by the `kernel` Cargo feature. The feature is a capability, not a selection: `validation.engine` chooses `native` by default or `kernel` at runtime, and the default binary links no C++ engine.

**Chain generation.** The even/odd atomic counter on the mempool gateway that fences admission against chain changes. An even value means the chain is stable and admission is open; an odd value means a connect, disconnect, or reorg is in progress and admission is closed.

**Chainstate facade.** The in-process owner of applied-tip mutation. Callers take a `ChainstateSnapshot` or a `ChainTransition`; they do not hold the raw UTXO, tip, and lock cells and reproduce a partial transition.

**Complete derived-index query.** A query that returns only when one snapshot proves every capability it consumes covers the exact applied tip. Lag, worker failure, a tip change, or a missing body returns `Retry` or `Unavailable`, never a false absence.

**Data-dir lock.** The process-exclusive open-file lock a node takes on `{datadir}/.lock` before the schema check or process epoch runs. Ownership is the open file, so a stale file after a crash opens normally and a second open fails as in use.

**Deferred block-body index durability.** A `write_deferred` batch that does not fsync and leaves durability to the next durable write or explicit flush on the same store. Block-body index rows use it because a lost row is rebuilt, and the body bytes are durable before the row that points at them is published.

**Download window.** The bounded set of blocks that have been requested but not yet received. A block count and an estimated-bytes cap both apply, and the window refills as blocks arrive.

**Early compact announce.** A commit-intent block that passes block rules as a tip child and is relayed as a `cmpctblock` before the durable commit. Its body is held so compact requests can answer early, and the send never publishes a tip or advances the mining generation.

**Embedded node.** The typed in-process surface `bitcoin_rs_node::Node` over the same lifecycle the daemon runs. Its start, shutdown, broadcast, and typed reads are `async fn` with synchronous bodies, and the node never owns an async runtime.

**Hash-pinned assume-valid anchor.** The mainnet checkpoint at height 938343 with block hash `00000000000000000000ccebd6d74d9194d8dcdc1d177c478e094bfad51ba5ac`. Script verification is skipped at or below it only after the active header chain is shown to contain that exact hash; sub-anchor and diverged chains verify fully.

**Initial block download (IBD).** The one-time bulk process of downloading and fully validating the chain from the start point to the network's current best tip. It is the download-bound sync regime.

**Mempool expiry.** Removal of transactions strictly older than 336 hours along with their in-pool descendants. Expiry runs after each committed admission and during reorg trim; a read-only preview never expires an entry.

**Native protocol primitives.** The owned Bitcoin vocabulary in `crates/consensus/src/primitives`: `Tx`, `Block`, `Header`, `OutPoint`, `Amount`, `LockTime`, `Script`, `Witness`, hashes, sighash, and network constants. These are native types, not `rust-bitcoin` aliases; RPC rendering may use `rust-bitcoin` only at its boundary.

**Native Rust interpreter.** The pure-Rust script path in `crates/consensus/src/script`, and the default `validation.engine` in every build. It executes legacy, P2SH, SegWit v0, and Taproot key-path and script-path spends, and the Core script and transaction vectors pin zero native mismatches on runnable rows ([`VAL-02`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/validation-default.md)).

**One-shot block parse.** Parsing each block once on the apply path and reusing that parse for txids. On the kernel arm it also reuses the borrowed transaction references that script preparation needs; `kernel::BlockParse` follows the selected engine.

**Optimized default posture.** The default mainnet configuration uses the `rocksdb` backend and multi-peer download with an outbound target of 8, a pending block budget of 256, and 16 in flight per peer. It enables hash-pinned assume-valid and a 450 MiB `dbcache`, and it leaves `txindex` and pruning off.

**Paused getdata tail.** The unserved remainder of one `getdata` that stopped because the session could not reserve send credit. It stays in request order, misses go out in one `notfound` after a reservation, and reads stay held until the tail is served or the session ends at 20 minutes.

**Peer socket.** A connected P2P TCP stream after accept or dial. `CountingStream` owns its posture: it disables Nagle once, then wraps the stream so handshake, reads, and writes all count into one `PeerCounters`.

**Provably unspendable output.** An output whose `scriptPubKey` starts with `OP_RETURN` or exceeds `MAX_SCRIPT_SIZE`. The UTXO set never admits it, and the snapshot codec records that admission rule under the tag `bitcoin-rs-utxo-spendable-v1`.

**REST gateway.** The optional, unauthenticated Core-compatible HTTP surface served on the existing JSON-RPC listener. It is enabled with `rest=1`, and JSON-RPC requests on the same listener keep their configured authentication.

**Rolling minimum fee.** The mempool admission and relay floor. It rises with eviction or replacement trim, decays after a block with an occupancy-scaled half-life, and resets once the decayed rate falls below half the incremental relay fee; this node uses 1,000 sat/kvB and dynamic memory usage.

**Script-flag exceptions (BIP16Exception).** Blocks Core hardcodes to validate under a reduced script-flag set: mainnet heights 170060 and 692261, and testnet3 height 394. The P2SH waivers are reproduced by block hash, and the Taproot case needs no exception because activation is already height-gated.

**Signet block solution.** The BIP325 signature a signet block carries after a 4-byte header inside its coinbase witness-commitment output. Connect checks it against the default challenge; custom challenges are unsupported.

**Staller.** A peer that holds up the apply frontier by not delivering a frontier block assigned to it. The detector uses window-blocked progress rather than raw applied-tip stagnation, and it does not blame a peer when local backpressure is the cause.

**Sync regime.** The cost regime a sync measurement names: download-bound or processing-bound. Live IBD is download-bound; reindex and replay are processing-bound because local blocks make wall time equal validation plus commit. A speed claim must name the regime and the validation posture.

**TxIndex capability watermarks.** Versioned durable `(height, block hash)` cursors that identify the exact active-chain prefix each ready row family represents. Equal cursors advance in one body scan and one atomic batch; a height alone cannot prove identity across a reorg.

**UTXO snapshot read contract.** The node accepts only complete native version-4 snapshots: exact magic and version, validated records, the declared record count, a 384-byte MuHash trailer, and end of file. Versions 2 and 3 fail startup with a remove-and-resync instruction.

**Watch-only mining payout.** An operator-configured address whose `scriptPubKey` becomes the candidate coinbase payout. The node decodes it at config resolve and holds no keys; empty configuration keeps transport-only template assembly.

**Window script batching.** Verifying the ordered transaction unit of several consecutive blocks in one parallel dispatch. A private `BlockValidationProof` binds block hash, predecessor, height, flags, and locktime cutoff, and blocks still commit one at a time in order.

**Work-count assertion.** Asserting how much of an expensive operation a path performs instead of how long it takes. A count states an algorithmic claim at any input size; a claim about elapsed time belongs in a paired-arm benchmark.

The full definitions, owner paths, and Core differences are in [`CONCEPTS.md`](https://github.com/gosuda/bitcoin-rs/blob/main/CONCEPTS.md).
