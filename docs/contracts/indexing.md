# Indexing contract

Target contract for node-owned indexing runtimes, capability gating, and
asynchronous reconciliation across restarts, reorganizations, and
selective rebuilds. The index owner, not the node, hosts the runtime.
Node wires lifecycle; RPC projects status.

Owners:
- `crates/index/src/runtime.rs`: lifecycle, reconcile legs, watermark
  production, and query fencing.
- `crates/index/src/index.rs`, `crates/index/src/types.rs`: schemas and
  row families (`IndexWriter`, `Indexer`, `IndexWatermark`).
- `crates/rpc/src/capabilities.rs`: status projection only, in the
  `CapabilityState` vocabulary. No parallel status enum.

## Clauses

### `IDX-01`: Capabilities and watermarks

- The generic index store maintains three independent capabilities:
  `TxLookup`, `ScriptLive`, and `ScriptHistory`.
  `ScriptIndex(full)` means live plus history; `ScriptIndex(utxo)` means
  live only. There is no history-only mode.
- Each capability's durable watermark is
  `(capability, height, hash, schema, revision)`. Every commit writes
  row changes, per-block contributions, and the watermark as one atomic
  batch. Parent and target identity and the runtime revision are
  verified before commit; stale prepared work is discarded. Types:
  `IndexError::{WatermarkMismatch, NonContiguousPrepared, InvalidWatermark}`.
- A runtime revision also fences prepared work. A retarget need not
  rewrite an old durable watermark to invalidate a worker.
- Row families: transaction occurrence (`txid` plus block identity and
  position to body locator and byte range), script history (script
  digest plus chronological position plus event identity), live script
  locator (script prefix plus full outpoint, resolved against coherent
  authoritative coins), spender relation, and per-block undo or
  contribution records. Chronological keys use order-preserving integer
  encoding with explicitly tested byte order.

### `IDX-02`: History identity and Core txindex separation

- Occurrence keys include block identity and position, not txid alone.
  Pre-BIP34 duplicate txids and side branches never overwrite evidence.
- Core `txindex` advertisement is a separate explicit operator promise.
  Only `--txindex` advertises the Core `txindex` capability in
  `getindexinfo` and enables historical `getrawtransaction` lookups.
  Internal locators never infer it. `getcapabilities` reports the
  compiled row; a missing worker is `enabled: false` / `Disabled`.
- `getcapabilities` answers `{"revision", "capabilities"}`: `revision` is
  the one runtime revision every status adapter projects (`0` with no
  attached source); `capabilities` lists the compiled rows in stable
  node order.
- A truncated script prefix accelerates live lookup only with exact
  script verification. Prefix collisions never remove another script's
  row. History retains provably unspendable outputs even though live
  UTXO state excludes them.

### `IDX-03`: State machine and readiness fence

- Each capability follows
  `Disabled -> Opening -> CatchingUp -> Ready`, with `RollingBack`,
  `Rebuilding`, `Failed`, and `Shutdown` owned by one runtime state
  machine. Status adapters project that state and invent no separate
  readiness flags.
- Readiness is `healthy && capability watermark == queried active tip
  identity` (height and hash). A multi-capability query requires all
  consumed capabilities to agree. Mixed confirmed and unconfirmed
  responses additionally require a reconciled gateway-owned mempool
  overlay with a matching read stamp.
- A lagging, rebuilding, or rolling-back capability returns
  `Unavailable` or `Retry`, never a partial empty success. A capability
  missing from the configured selection is `Unavailable` with a distinct
  disabled reason.
- Query cancellation releases retained snapshots. Worker health never
  blocks ordinary chain progress: a disabled, failed, or late-open
  worker cannot block node startup or apply.

### `IDX-04`: Backfill and live reseed

- A worker takes a coherent applied-chain target, loads a bounded body
  batch, parses it once for aligned capabilities, and commits rows plus
  watermarks atomically. Independent per-capability watermarks let
  families backfill separately.
- Full history backfill requires retained bodies or an explicit archive
  or reindex input. A pruned node honestly reports unavailable history;
  it never invents it.
- `ScriptLive` reseeds from a stable coin view and stays unqueryable
  until its final watermark commits. A partial live row set is not
  readable.

### `IDX-05`: Rollback, rebuild, and version discipline

- Reorg handling finds the common ancestor by hash. Within the
  measured rollback-vs-rebuild crossover, the baseline 100_000-block
  cutoff, it reverses per-block contributions exactly, restoring
  before-images. Beyond it, the affected capability resets and rebuilds.
  The 100_000 cutoff is a baseline to remeasure on the target storage.
- Index-only durable layout changes increment `INDEX_FORMAT_VERSION`
  only. `CURRENT_SCHEMA` changes only when authoritative chainstate
  bytes change. No translator and no legacy reader exist. An unknown
  index version degrades that capability to unavailable or rebuilding
  through the `CapabilityState` vocabulary and never fails authoritative
  startup. A rejected index file stays in place until an authorized
  rebuild.
- There is no second explorer database. Historical prevout values
  resolve through body positions and a bounded decoded-transaction
  cache. Materialize only fields with measured query need.

## Proven by

- `crates/index/tests/overhaul_scriptindex.rs` (planned): independent
  watermarks and backfill, exact script collisions, historical duplicate
  occurrences, same-block spend history, live reseed, pruned-missing to
  unavailable.
- `crates/node/tests/overhaul_index_owner.rs` (planned): late-open,
  failed, and disabled workers; one revision across adapters; fence
  races; bounded rollback; unavailable distinct from empty.
- Existing suites keep their verdicts:
  `crates/index/tests/index_roundtrip.rs`,
  `crates/index/tests/le_order.rs`,
  `crates/index/tests/script_live.rs`,
  `crates/index/tests/tx_positions.rs`,
  `crates/node/src/txindex_worker_recovery_tests.rs` (owner-local after
  the T29 move), `crates/rpc/src/capabilities.rs` status tests.

## Vocabulary

[CapabilityState](../../CONCEPTS.md),
[IndexWatermark](../../CONCEPTS.md),
[ScriptIndex](../../CONCEPTS.md).
