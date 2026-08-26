# Optimization candidate survey and outcomes

The two-phase performance campaign finished what `PLAN.md` scheduled. Everything
in it either landed — the index read path, the v5 record codec — or was
**rejected on its own measurement** and recorded as such: the decoded-block cache
(`docs/benchmarks/index-read-path.md`) and the `bumpalo` arena (`DEVIATIONS.md`
§9, `docs/benchmarks/utxo-memory.md`).

That leaves a question the campaign never asked: **what was never looked at?** It
only examined crates that already had benchmarks — `consensus`, `coinstats`,
`storage`, `utxo`, `node` — plus the two it added them to. This page surveys the
ones that have none: `rpc` (9,137 LOC), `mempool` (4,254), `p2p` (3,295),
`chain` (3,010), `filters` (771).

Six candidates and the negative results are retained so the next reader does not
re-derive the survey. Candidates A, B, and C have since landed; their result
documents are linked below. Candidates D, E, and F remain survey findings whose
implementation or value is unresolved.

Every `file:line` below is against the tree this page lands on and was
re-verified there. The cross-references *out* of it are forward-looking:
`docs/benchmarks/index-read-path.md` arrives with the read-path PR, and
`docs/benchmarks/utxo-memory.md`, `DEVIATIONS.md` §9 and the benchmark-shape
best practice arrive with the UTXO-memory PR. The findings themselves depend on
neither.

Of the three G14 budgets only **tip RSS ≤ 16 GiB** is anywhere near binding: UTXO
commit p95 measures 2.4 ms against 50 ms. The ranking reflects that.

## Ranking

| | Candidate | Evidence | Expected gain | Budget touched |
|---|---|---|---|---|
| 1 | A — `gettxoutproof` scans the chain | structural, **not timed** | O(chain) reads -> one index lookup | none, but unbounded work per call |
| 2 | B — block-record log never shrinks | 264 B/block, arithmetic below | 241 MiB at tip | **tip RSS** |
| 3 | F — remaining record encoding | 6 B/output, **projected** | ~1.0 GiB at tip | **tip RSS** |
| 4 | C — mempool priority index | O(n² log n) rebuild, **not timed** | unknown | none |
| 5 | D — `dbcache_mb` reaches nothing | verified code absence | unlocks tuning | **tip RSS**, indirectly |
| 6 | E — one file open per position | 12.00 µs x P, **measured** | ~50 µs per 5-position height | ScriptIndex resolver headroom |

Only **B** and **E** carry measured per-unit costs. **A** and **C** are shapes,
not numbers. **F** rests on 3.626 outputs per record, which has not converged.

---

## A — `gettxoutproof` reads the whole chain when given no block hash

`crates/rpc/src/handlers/tx.rs:175`:

```rust
None => ctx.blocks.read().clone(),
```

With the optional `blockhash` argument absent, the handler deep-copies **every**
`BlockRecord`, then for each one loads the body, deserializes the whole block,
computes every txid into a `HashSet`, and tests whether it contains the wanted
set. At tip that is ~957,600 block loads and full deserializations to answer one
call, almost all of it discarded.

This is unbounded work for one authenticated RPC call, not a remote
denial-of-service. It still stalls the node for the duration and evicts
everything else from cache.

**The current tree lacks the required lookup.** `Context.tx_index`
(`crates/rpc/src/context.rs:372`) exposes `TxIndexQuery::transaction`, but that
contract returns only the transaction. It does not identify the block that
contains it. Add a txid-to-block-location query to the durable transaction
index and expose it through `TxIndexQuery`; then the handler can replace its
chain scan with one index lookup. Bitcoin Core takes the same route: its
`gettxoutproof` requires a block hash *unless* txindex is enabled.

**Before implementing:** time the current handler on a fixture of a few thousand
blocks and extrapolate, so the fix has a `before` arm. The refactor-set contract
needs one, and "obviously faster" is the claim this campaign was wrong about
twice.

## B — the block-record log grows one entry per block, forever

`crates/rpc/src/context.rs:534` pushes a record per applied block:

```rust
pub fn add_block(&self, record: BlockRecord) {
    self.blocks.write().push(record);
}
```

Nothing removes one. `NodePruneService::prune_to_height`
(`crates/node/src/state.rs:566`) walks the log and blanks `record.block_hex`, but
leaves the record itself. The only removal in the crate is the single-record
reorg undo at `crates/node/src/apply.rs:1167`, which pops one entry when a
disconnect matches the tail.

`applied_block_record` (`crates/node/src/apply.rs:3475`) makes `block_hex`
conditional on `cache_block_bodies_in_memory` — which production sets to `false`
(`crates/node/src/state.rs:1111`) — but `header_hex` is computed unconditionally
and the record is always pushed.

Per record, with the body already blanked:

| Field | Bytes |
|---|---:|
| `hash: Hash256` (`[u8; 32]`, `crates/primitives/src/hash.rs:27`) | 32 |
| `height: u32` | 4 |
| `block_hex: String` (empty in production: struct only) | 24 |
| `body_size: usize` | 8 |
| `header_hex: String` struct | 24 |
| `tx_count: usize` | 8 |
| `time: u32` | 4 |
| **struct total** | **104** |
| `header_hex` heap — an 80-byte header as lowercase hex | 160 |
| **per block** | **264** |

That is **103.9 MiB at height 412,732** and **241.1 MiB at 957,600**. The
attribution run at 412,732 left 0.64 GiB of RSS unattributed and named the
block-record log as one of four suspects (`docs/benchmarks/utxo-memory.md`); this
sizes it at **15.9% of that residual**, on the one budget that is at risk.

**`header_hex` is not dead — do not delete it.** It is returned directly at
`crates/rpc/src/handlers/chain.rs:286` and `:291`, and hex-decoded back to bytes
at `:886`. The candidate is to store the 80 raw bytes and encode on read: the
read is one RPC call, the storage is every block for the life of the process.
That alone is 160 B/block of the 264.

The second half — bounding the log, or dropping records below the prune height
the way `block_hex` already is — is a behaviour change, because
`crates/rpc/src/handlers/chain.rs:45` and `:171` scan the log. Establish what
those two need before removing anything.

## C — the mempool priority index re-sorts on every insert

`crates/mempool/src/pareto.rs:29-38`:

```rust
pub fn insert(&mut self, id: EntryId, entry: &MempoolEntry) {
    self.remove(id);
    self.entries.push(ParetoKey { .. });
    self.entries.sort_by(compare_keys);
}
```

`remove` is a linear scan (`pareto.rs:42`), and the sort covers the whole
`TinyVec`. It runs on every acceptance, via `crates/mempool/src/pool.rs:419`.

The rebuild is worse. Ancestor/descendant recomputation at
`crates/mempool/src/pool.rs:620-626` discards the front and re-inserts entry by
entry:

```rust
self.pareto = ParetoFront::new();
for (id, entry) in pareto_entries {
    self.pareto.insert(id, &entry);
}
```

Each of those inserts sorts everything inserted so far, so rebuilding *n* entries
is **O(n² log n)**.

**Not on a G14 budget**, and its real cost is unknown — a full mempool is tens of
thousands of entries, not millions, and `TinyVec` sorting is cache-friendly.
`mempool` has never been benchmarked at all, which is the actual finding here.

**Before implementing:** build the missing benchmark first. A sorted structure
with O(log n) insert is the obvious replacement, but the campaign's own lesson
(`docs/solutions/best-practices/benchmark-the-operation-the-workload-performs-not-the-one-the-api-exposes.md`)
is that the obvious replacement is worth nothing until the harness is shaped like
the workload — here, acceptance and template building, not `insert` in isolation.

## D — `dbcache_mb` never reaches a storage backend

Parsed from CLI and `bitcoin.conf` (`crates/node/src/config.rs:162`,
`crates/node/src/bitcoin_conf_compat.rs:64`), carried through config layering
(`config.rs:574`), and referenced **nowhere in `crates/storage`** — verified by
search, zero hits. Tracked as issue #51.

It has already cost this campaign once: `docs/benchmarks/utxo-memory.md` had to
retract a claim that 450 MB of residual RSS was the configured `dbcache`, because
the setting reaches no constructor. fjall takes builder defaults and RocksDB a
fixed 256 MiB block cache.

The consequence for everything else on this page: **there is no lever between
configuration and the backends**, so the one budget that is at risk cannot be
tuned, and the non-UTXO residual cannot be attributed by turning a knob and
re-measuring.

This is a design question before it is an optimization — `dbcache_mb` means
different things to four backends — so it does not fit the refactor-set contract
as stated.

## E — `load_range` opens the file once per position

Measured during the read-path campaign and deliberately deferred, with the
numbers already published in `docs/benchmarks/index-read-path.md`:

| Operation | Cost |
|---|---:|
| `load` — whole 250 KB body | 23.44 µs |
| `load_range` — 250 bytes | 12.00 µs |
| `load_range` x5 — five positions at one height | 62.34 µs |

The cost is the open/`fstat`/seek/read sequence, not the bytes: a 250-byte read
costs half a 250 KB one. The optimized resolver arm is now syscall-bound at ~13
µs per height, so a `load_ranges` that opens once per height recovers most of the
62 µs.

**This is headroom, not a regression.** The position path already beats the scan
path by 63-77x end to end. It only matters if a production ScriptIndex measurement
lands closer to the 30 ms budget than the synthetic fixtures suggest — and that
measurement has not been run.

## F — the record-encoding savings not taken

`PLAN.md` projected 17 B/output from four changes. Three shipped and measured
11.75 (`docs/benchmarks/utxo-memory.md`). The two remaining, ~3 B/output each:

- **Core-style scriptPubKey compression** — P2PKH 25→21, P2SH 23→21, P2PK
  35/67→33. No blocker known. Independent of the other half and could go first.
- **Hoisting `height` into the record header.** Needs "every output of a record
  shares one height" to hold, and BIP30's duplicate coinbase txids (mainnet
  blocks 91,842 and 91,880) are precisely where it might not. **The
  investigation is the prerequisite, not the encoding** — the invariant has never
  been checked, and the codec change is trivial once it is.

Together about 1.0 GiB at tip, on the same 3.626-outputs-per-record projection
that has not converged (2.296 at height 183k, 4.056 at 390k). Same caveat as the
v5 verdict: this is worth doing if tip RSS is actually near budget, and that has
never been measured.

---

## Negative results

Checked during the survey and cleared. Recorded so nobody re-checks them.

- **`crates/chain/src/tree.rs:100-118`** — the fork-point walk builds a `HashSet`
  of one side's ancestors and walks the other against it. O(depth), not
  quadratic.
- **`Context.transactions`** (`crates/rpc/src/context.rs:289`) — a
  `HashMap<Txid, Transaction>` that looks like candidate B, but the apply path
  never populates it. It is fed by `add_transaction` on the submission path and
  cleaned by the prune service. Not a per-block leak.
- **`crates/p2p/src/banlist.rs:138`** — the `retain` is a periodic expiry sweep,
  not per-message work.

## What blocks what

- **A** — landed; see `docs/benchmarks/gettxoutproof.md`.
- **B** — landed; see `docs/benchmarks/block-record-footprint.md`.
- **C** — landed; see `docs/benchmarks/mempool-pareto.md`.
- **D** — still needs a decision on what `dbcache_mb` should mean per backend first.
- **E** — gate on a production ScriptIndex measurement. Do not build it against
  synthetic fixtures.
- **F** — the height half is gated on the BIP30 investigation; the script half is
  not gated on anything.

Three of the six point at the same missing measurement: **G14 tip RSS on a synced
mainnet-tip node with `txindex` and the currently enabled derived indexes.** That run decides
whether B and F are worth their complexity, and it is the same run that decides
whether the v5 codec is kept or reverted (`DEVIATIONS.md` §9).
