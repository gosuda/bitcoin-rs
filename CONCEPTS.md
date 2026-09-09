# Concepts

Shared domain vocabulary for this project: entities, named processes, and
status concepts with project-specific meaning. Glossary only: not a spec, a
changelog, or a benchmark ledger. Measured numbers belong in the PR that
produced them; target values here are contracts, not measurements. One
definition per concept. Where a term has a rejected spelling, `*Avoid:*` names
it.

## Owners

### Owner table
The fixed assignment of one crate to each domain. `primitives`: IDs, canonical
encodings, borrowed transaction and block layouts, network constants. `script`:
interpreter, sighash execution context, verification primitives. `consensus`:
pure structural and contextual validity and verification plans. `storage`:
engine adapters, batches and snapshots, framed segment I/O, flush contract,
physical accounting. `utxo`: coin formats, grouped record mutation, coin views,
undo encoding. `chain`: header tree, chainwork, activation context, common
ancestors, branch selection. `chainstate`: transition serialization,
accepted-prefix commit, durable root, connect, disconnect, recovery. `mempool`:
admission preparation and verification, graph, RBF, lifecycle, fee policy and
estimation, orphans. `p2p`: transport, sessions, addresses, scheduling, relay
and request state. `index`: generic schemas, backfill, selective rebuild,
readiness, query engines. `mining`: candidate selection, GBT state, generations,
proposal and submission interface. `rpc`: Core RPC and REST, public Esplora and
backend dialect adapters, typed error mapping. `node`: resolved configuration,
lifecycle, resource budgets, wiring, cross-owner ordering. Binary: argv,
environment, TOML and `bitcoin.conf` parsing, signals, measurement commands.
Owner: `docs/contracts/architecture.md`, gate `g17`.

### Five-layer direction
Dependencies point one way through the layers `ARCH-01` assigns: Layer 0
`primitives`, `script`, `consensus`; Layer 1 `storage`; Layer 2 `chain`,
`utxo`, `chainstate`, `mempool`, `p2p`, `index`, `mining`; Layer 3 `rpc`;
Layer 4 `node` and the binary. A crate depends only on its own or a lower
layer. `crates/chainstate` is the only new crate the overhaul adds; it has no
dependency on mempool, index, rpc, or p2p, and the gate update ships in the
same cut that introduces it.

### Chainstate owner
`crates/chainstate`: the single authority for chain transitions. It serializes
transitions, commits the accepted prefix, owns the durable root, and performs
connect, disconnect, and recovery. Node coordinates the mempool and index
effects around it; it does not own them. *Avoid:* "chainstate facade",
"checkpoint worker" (removed; no compatibility flag retains it).

### Storage ladder
The one backend-neutral trait family in `crates/storage/src/trait_.rs`:
`KvStore` with `get`, ordered `iter_prefix`, bounded `scan_prefix_bounded`
under `PrefixScanLimit`, point-in-time `snapshot`, and `WriteBatch` applied by
`write`, `write_deferred`, `write_durable`, or `write_durable_if` with
`WriteCondition::{Absent,Equals}`. `Ok(true)` means committed and durable,
`Ok(false)` means condition mismatch and nothing applied, `Err` means backend
fault. `ColumnFamily` names the logical families every backend shares. Atomic
visibility is not fsync durability. There is no second storage trait and no
receipt trait. fjall is the recorded default backend.

### Index owner
`crates/index` owns the generic row schemas, backfill, selective rebuild, the
capability state machine, watermarks, and query engines. Node only spawns,
wakes, and stops the worker. Status adapters project index-owner state; none
invents a readiness flag.

### Mining owner
`crates/mining` owns candidate selection, template generation, the one bounded
generation cache, long-poll waking, and template invalidation. Node supplies
chain and pool views and connects submitted blocks through ordinary chainstate
and P2P orchestration. RPC renders BIP22/BIP23 and maps results; it keeps no
template cache. *Avoid:* "RPC-owned template cache".

### MempoolGateway
The one node-constructed `Arc<MempoolGateway>` that owns transaction admission
for RPC, P2P, Esplora, package, and reorg re-admission. It captures a coherent
`ReadStamp`, resolves each input once, runs policy and script verification
outside the pool writer, then takes the writer once for a complete context
recheck and atomic commit. No `REGISTRY` interning, no second evaluator, no
forwarding handle. Producers supply parsed bytes, mode, origin, and request fee
limits; they never resolve admission context themselves.

## Node interfaces

### Wallet-free RPC boundary
The node has no in-tree wallet and owns no private keys. Wallet funding,
signing, import, and fee-bump methods are absent. Key-free descriptor helpers
`getdescriptorinfo`, `deriveaddresses`, and the PSBT helpers `combinepsbt`,
`finalizepsbt`, plus the bounded `scantxoutset` domain query, remain node RPCs
so an external signer can drive a workflow without giving key custody to the
node.

### Watch-only mining payout
An operator-configured address whose `scriptPubKey` is the candidate coinbase
payout (`--mining-payout-address`). The node decodes it at config resolve time,
validates it against the resolved network after all layers merge, and never
holds keys. Empty configuration keeps transport-only GBT assembly.

### Wallet-facing public surface
What an external wallet is allowed to call: native Esplora HTTP at `/api` on
the JSON-RPC listener, address and script lookups, `POST /tx`, and the
wallet-free RPCs above. The consumer runs as a separate process. It
does not receive `NodeState`, `UtxoSet`, index, or datadir access. See
`docs/contracts/wallet-facing.md`.

### REST gateway
The optional, unauthenticated Bitcoin Core-compatible HTTP surface served on
the existing JSON-RPC listener, enabled with `rest=1`. Each request reads one
coherent view and returns HTTP 503 when the chain generation moves before the
response is assembled. See `docs/rest-interface.md`.

### Esplora dialects
`/api` exposes the public Esplora contract. `/esplora` exposes the versioned
mempool-backend superset (`/internal/txs`, `/internal/mempool/txs`,
`/internal/block/{hash}/txs`, batched outspends, address summaries). Both
project the same node and index state over coherent views. Neither is a
separate node mode or a separate blockchain database, and there is no electrs
proxy. `/api/v1` belongs to the external mempool application, not to this node.

### Sequence stream
The Core-compatible `pubsequence` ZMQ topic. Block events carry the 32-byte
reversed block hash and label `C` (connect) or `D` (disconnect); mempool events
carry the 32-byte reversed txid, label `A` (admission) or `R` (removal), and the
8-byte little-endian mempool sequence. A transaction mined in a connected block
emits no `R`; the block's `C` covers it. Every event concludes with a topic-local
little-endian `u32` sequence counter frame. Reorg disconnects are emitted
tip-first before connects. Each socket owns `DEFAULT_ZMQ_HWM = 1_000`.
`bitcoin_rs_rpc::zmq` owns the compatibility payload and transport;
`ChainFollowers` / `ChainEffects` own emission timing relative to committed
chain transitions.

### Embedded node
The typed in-process surface (`bitcoin_rs_node::Node`) over the same lifecycle
the daemon runs. `start`, `shutdown`, `broadcast`, and typed lookups are
`async fn` by contract with synchronous bodies driven by the node's own
threads; the embedder supplies whatever executor it owns. No second lifecycle
exists. See `docs/contracts/embedding.md` (`EMB-02`).

### Node network selection
`BITCOIN_RS_NETWORK` / `--network` selects consensus rules and P2P bootstrap
identity atomically. Supported deployments are mainnet, signet, testnet4, and
regtest; testnet3 only where explicitly retained; `drynet4` keeps mainnet
consensus with its own message start. Accepted spellings: `main`, `mainnet`,
`bitcoin`, `test`, `testnet`, `testnet3`, `testnet4`, `signet`, `regtest`,
`drynet4`.

### Configuration precedence
Low to high: defaults, TOML (`--config`), `bitcoin.conf` (`--bitcoin-conf`),
environment, CLI. The `bitcoin.conf` network section is selected from the
network resolved through TOML, environment, and CLI. `UserConfig` resolves once
into validated `NodeConfig`; `RuntimeInputs` (test clocks, fault controls) are
separate and never public config.

### Product lanes
The four build and run profiles every release proves separately. Minimal
native: `--no-default-features --features fjall`, optional extensions off.
Default full node: default features, unpruned fjall, optional indexes off. Oracle:
`--features kernel`, resolved in its own `CARGO_TARGET_DIR`; evidence only.
Optional-on: `bip324` transport and compact filters enabled. Optional means
disabled by default, not omitted.

## Coherent view and transitions

### ReadStamp
The token every mixed chain-and-mempool read carries:
`{ process_epoch, chain_generation, chain_tip, mempool_sequence, policy_epoch }`.
All relevant fields are checked. A caller never composes a view by loading a
tip and mutable UTXOs separately. Height-only caches are invalid. *Avoid:*
"applied-tip hash plus sequence" as a two-field key, "Esplora request chain
view" (an Esplora GET captures a `ReadStamp` and returns `503` if the chain
generation moved before the response is complete).

### Chain generation
The even/odd counter in `ReadStamp.chain_generation`. Even means the chain is
stable and admission is open; odd means a coordinated change is in progress and
admission and mixed reads are closed. Publication counters alone do not protect
a mutable UTXO read; live UTXO resolution keeps the bounded read fence.

### Chain-transition reservation
The exclusive right to begin a chain change, acquired from the chainstate
owner before anything else. Reservation before fence is the fixed lock order.

### Pool chain-change fence
The mempool's odd-generation window (`begin_chain_change`, `ChainChangeGuard`).
It closes admission commits and mixed reads for the whole transition. It
reopens only through explicit publication after durable commit and pool
reconciliation; a guard destructor never reopens it after an error.

### Coherent publication
The order every transition follows: chainstate commits durably, mempool consumes
the committed facts, the coordinator publishes the next even generation, then
best-effort consumers (relay, index wake, ZMQ, observers) are notified in
contract order. No interval exposes a new tip with an old stable generation.

### Policy epoch
The field of `ReadStamp` that changes when the versioned `AdmissionPolicy`
changes. Prepared admission work captured under an old epoch fails typed-stale
at recheck and follows the same retry rule as chain or pool staleness.

## Block parsing and validation

### ParsedBlock / ParsedTransaction
The checked borrowed wire layout in `crates/primitives/src/layout.rs`: byte
spans and metadata ranges over one immutable byte owner that outlives every
offset. `offset + length` is checked before slicing or reserving; segwit
marker and flag rules are enforced; trailing bytes, impossible counts, and
noncanonical lengths are typed `DecodeError`s. It is the only production parse;
IDs, weight, positions, and the Merkle mutation flag derive from it once.
*Avoid:* `KernelBlock` as a production parse.

### PreparedTx / ResolvedCoin
The prepared verification objects. A `PreparedTx` borrows layout metadata and
retains an input-ordered `ResolvedCoin` slice; each coin carries value, exact
script, origin height, and coinbase flag. Each input is resolved once and the
transaction-shared sighash cache computes BIP143 and BIP341 aggregates once. A
borrowed pointer into a replaceable coin record is never held.

### Validation window states
The `WindowOverlay` vocabulary for a bounded batch of consecutive blocks:
`Missing` (not in overlay, ask the committed set), `Existing` (live at window
base), `Created` (produced inside the window), `Spent` (consumed inside the
window; same-block create-then-spend keeps its tombstone). A future reference
or repeated spend fails; a same-block create-then-spend still participates in
fees, scripts, history, and accounting. The window is bounded by bytes, inputs,
retained coin bytes, CPU jobs, and age, not by block count.

### Accepted prefix
The longest contiguous run of window blocks whose proofs are all `Valid` under
the current context. One ordered writer publishes only an accepted prefix; a
failed first or middle block prevents later publication even when later jobs
finished. Context-bound evidence is never replayed under another predecessor.

### Native interpreter
The pure-Rust script engine (`crates/script`) and strict-Rust cryptography:
`k256 0.14.0` arithmetic and ECDSA with one general BIP340 operation composed
over library primitives. The `k256` high-level Schnorr type is withdrawn
because its signature stores a non-zero scalar and cannot represent the whole
BIP340 domain. Overflowing TapTweak is canonically rejected; hybrid-key parity
and historical DER and high-S rules are preserved. This is the mandatory
production validation path.

### bitcoinkernel
Bitcoin Core's C++ consensus engine via `bitcoinkernel 0.2.1` (kernel tree
31.99.0, `differential_harness = false`). It is an explicit opt-in oracle in
the `kernel` feature lane, used for differential evidence only. It is never a
silent fallback and never on the default runtime path.

### Strict-Rust versus kernel-free closure
Kernel-free means `bitcoinkernel` is absent from the transitive production
graph, proven by `cargo --locked tree`. Strict-Rust additionally means the
validation and crypto path runs the reviewed Rust verifier. A kernel-free
binary alone does not prove strict-Rust; both are separate release gates.

### Guarded hash dispatch
Runtime-selected SHA256d kernels (`crates/consensus/src/sha256d64.rs`) behind
independent capability guards: AVX2, x86 SHA, and ARMv8 SHA2 are separate
capabilities, and ARMv8 SHA2 is never implied by NEON. The portable scalar path
compiles on every target. Merkle parents batch across independent parents, odd
levels duplicate only the terminal leaf, and equal-sibling pairs are checked on
the original level so mutation detection survives.

### Script-flag exceptions (BIP16Exception)
Blocks Core hardcodes in `consensus.script_flag_exceptions` to validate under a
reduced flag set: mainnet 170060 (P2SH) and 692261 (Taproot); testnet3 394.
Reproduced by `Network::is_bip16_p2sh_exception`; the Taproot override needs no
exception because `is_taproot_active` already height-gates it.

### Difficulty-1 target
The network-independent reference target in Core's difficulty calculation:
compact nBits `0x1d00ffff`, not the selected network's PoW limit.

### Float value/text parity
Equal IEEE-754 values versus equal serialized spellings. Core's UniValue uses
`%.16g`; the RPC path uses shortest round-trip. Compatibility means preserving
value and operation order, not forcing JSON text to match.

### Provably unspendable outputs (UTXO admission)
Outputs the UTXO set never admits: `scriptPubKey` starting with `OP_RETURN` or
longer than `MAX_SCRIPT_SIZE`. Excluding them changes no consensus outcome.
History indexes retain them even though live state excludes them.

### assumevalid
Skipping script-signature verification for blocks at or below a trusted height
while performing every other consensus check. Mainnet defaults to the
hash-pinned anchor; `--assume-valid-height 0` requests full verification.

### Hash-pinned assume-valid anchor
The mainnet checkpoint (height 938343, block
`00000000000000000000ccebd6d74d9194d8dcdc1d177c478e094bfad51ba5ac`) below which
script verification is skipped only after the active header chain is shown to
contain this exact hash; diverged chains verify fully.

### Optimized default posture
The default full-node lane's shipped tuning: `fjall` backend, hash-pinned
assume-valid, 450 MiB `dbcache`, `txindex` and `scriptindex` off, pruning off,
native strict-Rust validation, P2P-owned multi-peer download. A benchmark that
does not match this posture is not measuring the shipped node; record the
posture in the artifact.

## Chain state and durability

### Durable root
The authoritative persisted record `DurableHead { format_version, commit_id,
tip_hash, height, chain_tx_count, block_segment_end, undo_segment_end }`,
persisted in the same atomic named-family batch as the final coin-record
updates. `commit_id` is monotonic across connects and disconnects; height can
decrease. Recovery reads this record; it never discovers a head by scanning
segment files.

### Ordered commit protocol
For one block or a bounded verified prefix: hold the reservation and close the
fence; build exact forward and undo facts; append body and undo frames; sync
files and any new directory entries; apply one atomic batch of coins, metadata,
and the new durable head; wait for the backend's documented durable
completion; publish the committed view to the mempool; publish the stable
generation; then notify. Live `submitblock` success waits for the whole
sequence; an I/O failure never returns success.

### Orphan append tail
Bytes after the durable head's segment cursor. They may be truncated on
recovery and are never authoritative: neither file length nor a decodable frame
promotes a root.

### Undo record
The per-block inverse of a UTXO commit, keyed by height **and** block hash so a
stale branch record cannot replay against another block at the same height.
Encoded by `undo_codec` (`UNDO_FORMAT_VERSION = 1`).

### Owed derived state
State that a connect writes and a disconnect must account for. `coin_stats`
needs an explicit inverse for its block-level fields; index rows are derived
state outside the authoritative transition and reconcile from the durable root
by hash. Disconnect restores live coins from the undo record and owes the
matching inverse to every derived owner.

### Streaming reorg
Disconnect tip-to-fork in bounded chunks through exact inverse transitions,
then validate and connect the competing branch through the ordinary pipeline.
No whole-branch preload. Each intermediate committed ancestor is a valid
restart point. Missing retained undo fails closed. *Avoid:* "full-revalidation
marker", "disconnect marker phase".

### Fresh replay
The only migration policy for authoritative chainstate bytes: increment
`CURRENT_SCHEMA`, refuse an incompatible datadir at open with
`incompatible_schema`, keep no translator or legacy reader, and require an
explicitly named fresh datadir. Existing operator datadirs are never opened,
converted, or deleted by newer code. Estimator, discovery, and index formats
carry owner-local versions; a corrupt or unknown owner-local file degrades that
owner and never fails authoritative startup.

### Post-commit chain effects
Derived work after a committed connect or disconnect: RPC `BlockLog`, ZMQ
projections, index wake, mining generation, and mempool alignment, owned by
`ChainFollowers` / `ChainEffects` and dispatched after publication.

### Chain control
Consensus-affecting RPCs never mutate the block tree directly; `invalidateblock`
previews the replacement plan, and branch switching runs through the chainstate
owner under the same reservation as sync-triggered reorgs.

## Mempool

### AdmissionMode
`Preview` or `Commit`, the named mode of one admission pipeline. Preview runs
the identical prepare, resolve, policy, and script path and stops before
mutation: no membership, estimator, relay state, sequence, or victim change.
Commit continues to the single writer acquisition. No boolean selector or
skip-verification override exists.

### Admission verdict
`AdmissionVerdict { stamp: ReadStamp, rows: Vec<TxVerdict>, changes:
Option<CommittedMutation> }`. `changes` is present only when a mutation
occurred. A preview describes one context, not a reservation; staleness is
visible through the stamp.

### Typed Busy
`AdmitError::Busy`, returned after the gateway's four attempts each found a
stale chain generation, pool sequence, or policy epoch at recheck. Each attempt
recaptures fresh facts; stale evidence is never reused. Callers map `Busy` to
their dialect; a new operation is a fresh start.

### Admission origin
`AdmissionOrigin` on the committed record: `Rpc`, `Peer(PeerToken)`,
`Esplora`, `Package`, `Reorg`, `Load`. Esplora is a distinct origin with its
own request fee limits, not an RPC alias. Only retained accepted entries become
relay candidates.

### Sigop cost
`total_sigop_cost` computed inside the gateway from resolved prevouts (legacy
x4, P2SH redeem x4, witness-program counts) and bounded by
`MAX_STANDARD_TX_SIGOPS_COST = 16_000`. Ingress never supplies a count.

### AdmissionPolicy
The one versioned policy value resolved from `NodeConfig` at startup: min-relay
1_000 sat/kvB, incremental relay 1_000, dust 3_000, datacarrier 83, cluster
count 64 and size 101_000 vB, `MAX_PACKAGE_COUNT` 25, max replacement evictions
100, max fee 0.1 BTC/kvB, standardness flags, TRUC v3 parameters, and script
verify flags, pinned to the Core 31.1 profile. Contradictory configuration is a
startup error.

### Replacement profile
The Core 31.1 feerate-diagram condition over the candidate's cluster and every
victim cluster, computed before any mutation, all-or-nothing at commit. Rules
1-6 keep their text where they fire first under the pinned precedence. TRUC v3
is supported with sibling and topology constraints. *Avoid:* "BIP125 rules 1-6"
as the modern profile.

### Cluster graph
Connected components of the spend graph, each with a revision, aggregate
modified fee and size, cached deterministic linearization and chunks, and
bounded rebuild on removal or replacement. Fee-rate comparisons use widened
checked integer cross-products. Eviction, mining snapshots, and package limits
all consume the same chunk ranking. No union-find and no external solver
dependency.

### Generation-safe EntryId
The slab handle tagged with an entry generation so a removed-and-reused slot
resolves to `None`, never to an unrelated transaction.

### Orphan pool
Mempool-owned storage for transactions with missing inputs and the bounded
recent-reject cache: count and weight quota, oldest-first eviction, per-parent
reverse index, per-peer eviction on disconnect. Node keeps peer-event routing
only. *Avoid:* "node orphan map".

### Observer bounded delivery
Committed `MutationEnvelope` records offered to optional subscribers in commit
order through a capped queue drained outside all domain locks. A full queue
records a sticky gap and a reconcile signal instead of growing; the subscriber
reconciles from gateway-owned snapshots. Canonical estimator accounting runs
inside the mutation and is never dropped. *Avoid:* "exactly-once in-process
queue".

### Resolution-time sampling
Recording an estimator statistic when its outcome is known. The fee estimator
samples numerator and denominator together at the block that resolves a
confirmation target; removals are classified per `RemovalReason` and
unclassifiable removals are `Excluded`, never counted as confirmations.

### Estimator state
The fee estimator's separate versioned persisted state (bucket aggregates,
pending map, decay height) with its own owner-local version. Corruption, a
missing file, or an unknown version resets estimation to insufficient data;
`estimate` returns `None` rather than a fabricated rate.

## P2P

### Initial Block Download (IBD)
The one-time bulk process of downloading and fully validating the chain from
the start point to the network's current best tip.

### Sync regimes (download-bound vs processing-bound)
The two cost regimes a sync measurement must name. Download-bound: wall is
decided by the network path. Processing-bound: blocks are local and wall is
decided by validation plus storage commit. A faster-than-X claim needs the
regime and validation posture stated.

### Apply frontier
The greatest height up to which every block has been validated and committed
in one unbroken run; distinct from the header tip and from blocks downloaded
but not yet applied. One missing block at the frontier stalls apply progress.

### Download window
The bounded set of block requests in flight, owned entirely by `P2pService`
(`DownloadWindow`: byte and height budget, deadlines, retries,
commit-frontier priority). Node submits chain demand and validates delivered
blocks; it holds no scheduler copy. *Avoid:* "node-owned download window",
`BlockSync` scheduler.

### Count-and-byte bound
A window sized by whichever of a count cap and a byte cap binds first, because
item size varies by orders of magnitude across the chain. One block larger than
the whole byte cap still goes through alone.

### Staller
A peer holding up the apply frontier by failing to deliver a frontier block it
was assigned. Detection is window-blocked, does not blame a peer when local
apply backpressure is the bottleneck, and disconnects the staller so another
peer can supply the block.

### Peer lease
The sole peer-lifetime authority (`PeerTable` / `PeerLease`). Each session has
a generation; a reconnect at the same address is a new session. Every
completion carries session generation and request identity; a stale-generation
completion is a typed no-op and cannot release, credit, or starve a lease owned
by the new session. Each request lease releases exactly once at its terminal
edge; on disconnect the requeued set equals the freed set.

### Address book
The bounded persistent address manager in `crates/p2p/src/address_book.rs`:
tried and new tables with timestamps and rate bounds, addrv2 formats, seed and
bootstrap policy, `getaddr` behavior, per-message and total intake caps. Its
state carries an owner-local version; a corrupt or unknown file degrades to
seeded discovery and never fails startup.

### Compact-block reconstruction
BIP152 v1/v2 over the existing wire types: `ReconstructionOutcome::{Complete,
Missing{txids}, Fallback}`. A short ID is never an authenticated identity;
ambiguity requests missing transactions or falls back to the full block, and
every reconstructed block enters ordinary validation.

### v2 transport
Optional BIP324 encrypted transport behind the `bip324` feature (`bip324
=0.11.0`, `std` only, tokio off) inside the existing `connection.rs` owner.
Negotiation yields `V2`, `V1Fallback`, or `Rejected{class}`; an authentication
failure closes the attempt and is never a downgrade. Disabled advertises
nothing and changes no validation result.

### Notification configuration
`NotificationConfig` groups external notification adapters. ZMQ configuration
follows socket ownership: one endpoint group contains its endpoint, all topics
published by it, and an optional HWM override.

## Derived indexes

### Capability
One independently ready projection: `TxLookup`, `ScriptLive`, `ScriptHistory`.
`ScriptIndex(full)` means `ScriptLive` plus `ScriptHistory`;
`ScriptIndex(utxo)` means `ScriptLive` only. Core `txindex` advertisement is a
separate explicit operator promise, never inferred from internal locators.

### Capability watermark
The durable row `(capability, height, hash, schema, revision)` committed
atomically with the rows and per-block contribution it describes. Height alone
cannot prove identity; a lagging capability moves independently.

### Capability state machine
`Disabled -> Opening -> CatchingUp -> Ready`, with `RollingBack{from,to}`,
`Rebuilding`, `Failed`, and `Shutdown`, owned by the index runtime. Readiness is
`healthy && watermark == queried active tip identity`; multi-capability queries
require every consumed capability to agree. `CapabilityState` is the one
vocabulary every RPC, REST, and Esplora status adapter projects.

### Capability status
The status report (`CapabilitySnapshot`, `CapabilityStatus`) projected from the
index owner's runtime revision and per-capability state. Every adapter exposes
the same revision.

### Unavailable is not empty
A query on a lagging, rebuilding, disabled, or pruned-away capability returns
typed `Unavailable` or `Retry`, never an empty successful result. History on a
pruned node without retained bodies or an archive input is unavailable.

### Occurrence key
The transaction-occurrence row `txid + block identity and position -> body
locator and byte range`, so pre-BIP34 duplicate txids and side branches cannot
overwrite evidence. Chronological keys use tested order-preserving integer
encoding.

### ScriptLive view
The compact live-output locator `script-prefix + full outpoint -> minimal
locator`; value and script resolve against authoritative coins with exact
script verification. It reseeds from a stable coin view and is unqueryable
until its final watermark commits.

### Consumer cursor
The durable record `{ epoch, sequence, height, hash }` naming the chain state
a consumer's rows mirror, written in the same atomic batch as the rows.

### Rollback-versus-rebuild cutover
The depth beyond which an index resets and rebuilds the affected capability
instead of reversing per-block contributions. The existing 100,000-block
baseline is remeasured on the target storage; see
`docs/benchmarks/index-rollback-rebuild-cutover.md`.

### Compact block filters
BIP158 filters and BIP157 header chains computed in the index owner from
retained block data and served by p2p through a `compat.rs` boundary type.
A pruned node without the data never advertises them.

## Mining

### Generation key
The full identity of one template: the entire `ReadStamp` plus
`template_policy_revision`, `fee_delta_revision`, and
`time_validity_revision`, checked field by field together with the time
validity predicate. A parent-tip change at equal height, a fee delta without
membership change, or a policy change invalidates the key. Long-poll waking is
coalesced and separate from invalidation.

### Selection
From an immutable admitted-pool snapshot, apply the shared cluster and chunk
ordering, pop best candidates, add only unselected dependencies, update
marginal scores with exact integer accounting. Modified fees rank; actual fees
pay the coinbase. An oversize chunk near the limit is searched for smaller
eligible subsets under a bounded work budget; remaining candidates are never
discarded. No global maximum is promised.

### Proposal
BIP22 nonmutating validation of a rendered candidate with proof-of-work omitted
where the protocol specifies. It changes no chain, pool, cache, or sequence
state and is never `true` merely because the previous hash matches. Submission
is distinct: a consensus-valid block may carry transactions absent from the
pool.

## Storage

### UTXO record (v5)
`UtxoRecord`: `txid || output_count || inline_len || widths || vout_dir ||
len_dir || payloads`, transaction-grouped with full 256-bit txid identity,
lossless compressed payloads, and `u16` script length bound
(`UtxoError::ScriptTooLarge{len}`). Accelerators are hints, never identity.
Persisted incrementally as grouped changed records with exact before-images.

### Canonical record spelling
One logical record has exactly one byte string; `UtxoRecord` compares and
hashes by bytes, enforced by minimal varints, narrowest directory width, and
exactly complementary compress and escape amounts.

### Deferred write
`KvStore::write_deferred` makes a batch visible without its own fsync, leaving
durability to the next `flush`. Correctness rests on ordering: body bytes are
durable before an index row pointing at them is published.

### Logical owner ledger
Exact serialized key and value bytes per column family or owning subsystem.
Explains data-model growth. Never added to the physical ledger.

### Physical namespace ledger
Allocated filesystem blocks (`st_blocks * 512`) per top-level datadir
namespace. The budget source: default unpruned fjall with optional indexes off
must keep conservative physical high-water at or below `1_000_000_000_000`
decimal bytes at the pinned mainnet stop, including compaction, restart, reorg,
and migration. A `du` snapshot is a lower bound on peak and cannot prove the
gate. Collected by `--measure-storage`. See
`docs/contracts/storage-footprint.md`.

### Work-count assertion
Asserting how much of an expensive operation a code path performs, not how
long it takes. Counting calls states a deterministic algorithmic claim; a
wall-clock assertion belongs in a paired-arm benchmark, not a test.

## Reference and evidence

### ReferenceSet
The identity record in `docs/api/core-compat.toml` `[reference]` and
`crates/rpc/src/compat_manifest.rs` carrying two distinct identities: released
Core 31.1 (tag `v31.1`, commit `9be056a8a72b624dae9623b2f7bded92c2a21c91`,
archive SHA256 `b80d9c3e04da78fb6f0569685673418cf686fadba9042d926d13fb87ff503f9e`,
bitcoind SHA256 `986e63b3c8770f08d0059820ad3dd085d1ab9e1bea23946c243f858a06888a08`)
and the 31.99.0 kernel tree via `bitcoinkernel 0.2.1`. A
version label or digest mismatch is rejected.
`docs/contracts/reference-set.md` is a readable projection; the manifest files
govern.

### Compatibility class versus readiness versus evidence
Three separate facts: the manifest `Status` of a surface (`Implemented`,
`Deviation`, `Extension`, `Unimplemented`), the runtime `CapabilityState`, and
whether an executed scenario proved the behavior. None implies another.

### Guard register
`CONSTRAINTS.md`: the root record of CL-01..CL-23 constraint rows, the formal
model tool pin, and the proof inventory. It references normative owners and is
never a second policy.

### Formal models
`docs/models/{ChainAdmission,PeerLeases,ProjectionMining}.tla` with `.cfg`,
checked by Apalache 0.62.2 through gate `g20` at step bound K = 128. Each
exports `Init`, `Next`, `TypeOK`, `Safety`, `TransitionSafety`,
`ConditionalProgress`; fairness is written as explicit LTL in the antecedent,
never inside `Next`. A bounded check is evidence for the abstraction, not a
proof of the implementation.

### Blocked gate
A gate whose required binary, corpus, digest, or hardware is
missing. It records the missing identity and stays `BLOCKED`; it never passes
by skip and never becomes a false verdict.

## Measurement

### Product performance cell
One coordinate of the frozen product denominator: one product domain
(`offline`, `p2p`, `muhash`), one corpus (`c150` or `cmodern`), one native
architecture, and one backend. Diagnostics are not cells. See
`docs/contracts/hot-path-attribution.md` and
`docs/benchmarks/overhaul-product-cells.md`.

### Hot-path attribution ledger
The single inventory of product hot paths, overlap groups, and dispositions,
owned by `docs/benchmarks/hot-path-ledger.toml`. Nested stage histograms are
diagnostics; parallel worker walls are never summed.

### Evidence identity
What every sample records: artifact hash, configuration, corpus, durability
identity, toolchain and features, host, and the reference identities it was
compared against. Schema validity never establishes a product result.

### Promotion floor
The rule for keeping an optimization: median gain at or above 1.05x on the
named cell, at least three alternating candidate and control runs, each arm
within the 5% stability rule, improvement exceeding observed host noise, and
identical result hashes. Non-target cells guard at 3% median and 5% p99.
Emulation is correctness evidence only; missing hardware blocks that target's
performance proof.

### Retained benchmark contract
Permanent benchmarks call the shipped production path, use a product-shaped
workload, and protect a regression that still matters. Which targets CI
compiles is owned by the `bench-smoke` jobs in the workflows, not by this
glossary.

### C150
The historical product corpus: mainnet genesis through height 150,000.
Identities, census, and state are owned by `docs/contracts/campaign-corpora.md`.

### Cmodern
The modern product corpus: mainnet genesis through height 709,635, the first
height with executed examples of every required post-P2SH script class. Owned
by `docs/contracts/campaign-corpora.md`.

### Matched-harness comparison
A cross-node benchmark matches every input that is not the thing under test
before any ratio is quoted: block source, validation posture, allocator, CPU
pinning, time of measurement. Interleave both arms on an idle host and quote
paired medians.

### Offline full-validation comparator
The processing-bound cross-node oracle: Core 31.1 and bitcoin-rs both build
chainstate from one hash-pinned archive under full validation, matched index
posture, and production durability. See
`docs/benchmarks/offline-full-validation.md`.

### CPU-seconds as a first-class metric
A throughput change is measured against CPU time as well as wall time, because
an idle many-core host lets wall-clock tuning spend cores for free.

### Contended-harness tuning artefact
A parallelism constant tuned while the harness competes with the node for CPU,
so the optimum measures the contention. Never tune against a sharing harness or
on wall alone.

### CI lane parity
A branch is green only against the commands in the workflows, never a local
approximation. `.github/workflows/ci.yml` is the required PR gate on the
kernel-free default features; `.github/workflows/main.yml` runs the oracle lane
on `main` pushes only. `cargo deny` failures are bug reports, not lint noise.
