# Generic index on-disk format

This document owns the on-disk format of the generic index in the target node (T30, gate G8). The frozen audit below (2026-09-02, `TxPosition` width, positioned Spending, LE height, per-CF cost, live locator) is retained as candidate evidence; its verdicts remain the baseline the target schema evolves from. Index-only layout changes bump whichever version axis they move and keep `CURRENT_SCHEMA` unchanged: the durability marker (`[0x00, b'V']`, currently row-format 5) is the hard open gate with full-reset recovery, and the row-value marker (`INDEX_FORMAT_VERSION`, currently 3) is the soft capability report that degrades to scans. There is no translator and no legacy reader; an unknown durability marker refuses start and recovery unattended-resets the derived namespace for rebuild from retained chainstate (operator cost of a format bump: one derived re-index on first start; authoritative data untouched). A rejected non-derived file is left in place until explicit authorized rebuild.

## Row families

| Family | Key | Value | Purpose |
|---|---|---|---|
| Transaction occurrence | `txid + block identity + position` | body locator and transaction byte range | pre-BIP34 duplicate txids and side branches never overwrite evidence |
| Script history | `script digest + chronological position + event identity` | funding or spending locator | ordering-preserving integer encoding, byte order explicitly tested; retains provably unspendable outputs |
| Live script locator | `script prefix + full outpoint` | minimal locator | truncated prefix accelerates lookup only with exact script verification; value and script resolve against coherent coins |
| Spender relation | `origin occurrence + vout` | spending occurrence and input index | outspend queries |
| Capability watermark | `capability` | height, hash, schema version, revision | readiness by hash, never height alone |
| Per-block contribution | `capability + block identity` | before and after row sets | exact reversal within the rollback cutover |

`ScriptIndex(full)` is live plus history; `ScriptIndex(utxo)` is live only. Core `txindex` advertisement is a separate explicit operator promise, never inferred from internal locators.

## Cells it owns

| Cell | Metric | Status |
|---|---|---|
| `index.format.bytes_per_row` per family | logical bytes per row and physical fjall bytes per row on a real pinned corpus | `planned_not_executed` |
| `index.format.amplification` | physical over logical per family, default fjall, after compaction | `planned_not_executed` |
| `index.backfill.throughput` | blocks/s and bytes/s per aligned capability set under `PreparedBatchLimits` | `planned_not_executed` |
| Byte-order and encoding contract | ordering-preserving keys proven by `le_order.rs`-class tests on persisted bytes | `planned_not_executed` |

Rows plus watermarks commit atomically per bounded batch after verifying parent, target identity and runtime revision; stale prepared work is discarded. Full history backfill requires retained bodies or an explicit archive or reindex input.

```bash
cargo test --locked -p bitcoin-rs-index --no-default-features --features fjall --test overhaul_scriptindex -- --nocapture
```

## Required identities per sample

Every sample in this cell records six identities. The T02 collector rejects a sample that lacks any of them; a rejected sample is not evidence.

| Identity | Content |
|---|---|
| Artifact | SHA-256 of the exact binary, library or image measured; source commit |
| Configuration | Resolved `NodeConfig`, feature set, allocator, validation mode |
| Corpus | Corpus digest, height range, stop height and stop hash |
| Durability | Backend, batch mode (`write`, `write_deferred`, `write_durable`), flush and sync posture |
| Toolchain | `rustc 1.95.0`, edition 2024, profile, enabled features |
| Hardware | CPU model, pinned core set, memory, storage device, OS kernel |

## Acceptance rule

- Promotion of a candidate over its control requires a median gain of at least 1.05x over at least three alternating candidate/control runs. Each arm stays within 5% of its own median. The improvement must exceed the observed host noise.
- Non-target cells guard at no more than 3% median regression and no more than 5% p99 regression, measured with repeated runs and reported uncertainty. Average-only reporting never passes.
- Report p50, p95, p99 and max with the sample count. Never sum nested intervals. Never sum concurrent intervals. Parallel worker walls and inclusive stage histograms are reported beside the process wall, not added to it.
- Retain raw samples beside every summary. A Criterion adaptive elapsed total is not a median source.
- A missing binary, corpus, hardware target or digest marks the cell `BLOCKED` with the missing identity named. `BLOCKED` is never a pass and never a skip.

## Status

`planned_not_executed`. No end-state cell in this document has run. Every value in the end-state tables is a required contract value, not a measurement. The section `Prior candidate evidence` below is historical and unchanged; it does not prove any end-state cell.

## Prior candidate evidence (frozen audit 2026-09-02)

Retained verbatim from the pre-rewrite document. Headings are demoted one level. Nothing below is end-state proof.

Froze 2026-09-02 at branch `overhaul/one-session` commit `a24d23b`.
This document is a **frozen** audit: the methodology and verdicts below are
the reference. Numbers recorded here are fixture-scale and labeled as such;
they are not mainnet projections.

### Freeze order

This document freezes its methodology before its numbers. The sections below
appear in the order they were settled:

1. **Trial count** — how many measurements back each number.
2. **Fjall-primary accounting** — how bytes are counted on the reference backend.
3. **Query mix** — which operations the audit exercises.
4. **Materiality rule** — what counts as a real finding.
5. **One-corpus / one-disposable-fixture guard** — what fixture is used and why.
6. **Logical vs physical bytes** — the measured table.
7. **Q1–Q5 verdicts** — the five design questions and their answers.
8. **Versioning** — per-capability format/reset contract.

### Trial count

Every byte count in this document is from a single synthetic fixture run on
the `MemoryStore` backend (a `BTreeMap`-backed `KvStore`). Logical byte counts
are exact by construction — they are computed from the serialized key and
value lengths defined in `crates/index/src/types.rs`, not measured from a
live database. Physical byte counts on fjall are taken from the existing
`crates/storage/examples/storage_footprint.rs` harness (200k rows per CF),
not re-run here.

No trial count is claimed for physical bytes: the fjall figures are cited
from `docs/benchmarks/storage-footprint.md` (single run, 200k rows, after the
LZ4-all-levels fix). They are labeled **fixture-scale** throughout.

### Fjall-primary accounting

Fjall is the reference backend for physical byte counts because it is the
backend the workspace ships with by default and the one whose compression
policy was audited (`docs/benchmarks/storage-footprint.md`).

**What is counted:**

- **Logical bytes** = `len(key) + len(value)` per row, summed across all rows
  in a column family. This is the payload the index produces, independent of
  backend overhead (bloom filters, block indices, journal pre-allocation,
  compression).
- **Physical bytes** = on-disk bytes reported by `du` on the keyspace
  directory after a memtable flush. This includes backend overhead and is
  after LZ4 compression on every level (the fix landed in
  `crates/storage/src/fjall_impl.rs`).

**What is not counted:**

- The 64 MiB fjall journal pre-allocation is excluded from per-CF accounting
  (it is a fixed cost, not per-row).
- Block-bodies and undo-data column families are out of scope: this audit
  covers only the four ScriptIndex column families.

### Query mix

The audit exercises the read-path operations that ScriptIndex callers use:

| Operation | Function | Column family |
|---|---|---|
| Funding row scan | `iter_funding_rows` | `Funding` |
| Spending row scan | `iter_spending_rows` | `Spending` |
| Txid row scan | `iter_txid_rows` | `TxConfirmed` |
| History resolve | `resolve_script_history` | `Funding` |
| Unspent resolve | `resolve_unspent_outputs_with_height` | `Funding` |

The query mix is read-only. No write-path measurement is in scope.

### Materiality rule

A finding is **material** if it changes a design decision or a caller
contract. A finding is **informational** if it confirms an existing decision.

- The LE-vs-numeric ordering finding is **material**: it changed
  `resolve_script_history` and `resolve_unspent_outputs_with_height` to sort
  by numeric height in the reader.
- The per-row byte counts are **informational**: they confirm the existing
  key/value layout but do not change it.
- The Q1–Q5 verdicts are **material**: they freeze decisions about
  `TxPosition` width, positioned Spending values, LE vs sortable keys, per-CF
  cost, and the Live locator.

### One-corpus / one-disposable-fixture guard

**No multi-GB corpus build was started.** The audit uses only:

1. **In-repo fixtures** — the `MemoryStore` backend (`crates/index/tests/common/mod.rs`)
   and the test blocks constructed in `crates/index/tests/le_order.rs`.
2. **Cited fjall figures** — from the existing
  `docs/benchmarks/storage-footprint.md` 200k-row synthetic corpus, not
  re-run.

The disposable-fixture guard: any fixture created for this audit (the
`be_order.rs` test blocks) is test-only, behind `#[test]`, and never shipped
as a benchmark corpus or a data file.

### Logical vs physical bytes

#### Logical byte layout (from `crates/index/src/types.rs`)

| Row type | Column family | Key bytes | Value bytes | Total per row |
|---|---|---|---|---|
| TxConfirmed | `TxConfirmed` | 8 (prefix) + 4 (BE height) = 12 | `n × 6` (TxPosition array, n ≥ 1) | 12 + 6n |
| Funding | `Funding` | 8 (prefix) + 4 (BE height) = 12 | `n × 6` (TxPosition array, n ≥ 1) | 12 + 6n |
| Spending | `Spending` | 8 (prefix) + 4 (BE height) = 12 | `n × 6` (TxPosition array, n ≥ 1) | 12 + 6n |
| BlockHeaders | `BlockHeaders` | 80 (raw header = block hash) | 0 (empty value) | 80 |

**Key observations:**

- `TxPosition` is 6 bytes: 3-byte LE offset + 3-byte LE length (`TX_POSITION_SIZE = 6`).
- The common case is n = 1 (one transaction at one height funds one script),
  so the typical Funding and TxConfirmed row is **18 bytes** (12 key + 6 value).
- Spending rows carry positions for the transactions that spend the outpoint.
  An empty value never means "no spending" — it is a legacy row value that
  requires a full-block scan.
- BlockHeaders rows are keyed by the raw 80-byte block header (which is also
  the block hash). The value is empty.

#### Physical bytes on fjall (fixture-scale, cited from storage-footprint.md)

These figures are from the 200k-row-per-CF synthetic corpus in
`docs/benchmarks/storage-footprint.md`, after the LZ4-all-levels fix. They
are **fixture-scale**, not mainnet projections.

| Column family | Key size | Value size | Rows | Logical (bytes) | On-disk (bytes) | Overhead/row |
|---|---|---|---|---|---|---|
| TxConfirmed | 12 | 8 | 200,000 | 4,000,000 | ~14.3 MiB | ~75 B |
| Funding | 12 | 8 | 200,000 | 4,000,000 | ~14.3 MiB | ~75 B |
| Spending | 12 | 0 | 200,000 | 2,400,000 | ~17.9 MiB | ~89 B |
| BlockHeaders | 80 | 0 | 200,000 | 16,000,000 | ~15.2 MiB | ~0 B (compressed) |

The Spending row was measured before format version 4 added positions to its
value; a current-format Spending row has the same 12 + 8n logical layout as
Funding.

**Why Spending costs more per row than Funding despite having no value:**
fjall's per-row overhead (bloom filter, block index, key encoding) is roughly
constant. A 12-byte key with a 0-byte value pays the same overhead as a
12-byte key with an 8-byte value, but the logical payload is smaller, so the
amplification ratio is higher. The LZ4 compression cannot recover the
overhead on rows with no value to compress.

**Why BlockHeaders on-disk is smaller than logical:** the 80-byte headers in
the synthetic corpus are highly repetitive (deterministic pattern), so LZ4
compresses them well. Real block headers are near-incompressible (they
contain hashes, timestamps, nonces); expect on-disk ≈ logical on mainnet.

### Q1–Q5 verdicts

#### Q1: TxPosition width — is 8 bytes (4+4) sufficient?

**Verdict: keep 8 bytes (4+4).**

`TxPosition` stores a 4-byte LE offset and a 4-byte LE length. The maximum
serialized block size on mainnet is 4 MB (the post-segwit weight limit
divided by 4), and both `offset` and `len` fit in `u32`. A block would need
to exceed 4 GB before a `u32` offset overflows, which is impossible under
consensus rules.

Widening to 8+8 would double the value size of every Funding and TxConfirmed
row (from 8n to 16n bytes) for zero benefit. The `Ord` implementation
already compares numerically, not lexicographically, so the LE encoding is
correct and the width is sufficient.

#### Q2: Empty Spending value vs position — should Spending carry positions?

**Verdict: Spending rows carry positions (format version 4).**

`spender_for` runs once per funding output for address history and UTXO
queries, so an unpositioned spend costs a 4 MB full-block reservation each and
exhausts the query budget after ~16 spends (issue #262). Positions make the
spend path the same one-transaction read as funding.

#### Q3: Keep LE height vs switch to sortable (big-endian) height?

**Verdict: keep LE. Sort in the reader.**

> Superseded by on-disk format 5: the height suffix is now big-endian, so
> store iteration already arrives in numeric height order. The reader-side
> numeric sort stays as a contract guarantee. The frozen verdict above is
> retained as the audit trail for the format-4 decision.

Switching the height suffix from little-endian to big-endian would make
lexicographic key order match numeric height order. That is not a
compatibility constraint: derived ScriptIndex bytes are disposable.
The pick is keep-LE because the reader already restores numeric order
cheaply, and BE would buy nothing the API does not already guarantee:

1. **The sort cost is negligible.** The reader sorts a `Vec` of
   `ScriptHistoryEntry` (two `u32` fields each) or `(Txid, u32, u64, u32)`
   tuples by height. For a typical scripthash with 10–100 funding rows, this
   is a few hundred nanoseconds — invisible against the block-fetch I/O that
   follows.
2. **LE is the electrs convention.** The index is shaped to match electrs's
   key layout for compatibility reasoning. Switching to BE would diverge
   from the reference design for no measurable query benefit.

The sort-in-reader approach (`entries.sort_by_key(|entry| entry.height)`) is
applied in `resolve_script_history`, `resolve_script_history_scan`,
`resolve_unspent_outputs_with_height`, and
`resolve_unspent_outputs_with_height_scan`. The raw `iter_funding_rows`,
`iter_spending_rows`, and `iter_txid_rows` functions document the LE caveat
and return rows in store order, so callers that want chronological order
must sort — but the high-level resolvers already do it for them.

#### Q4: Per-CF cost table (fixture-scale)

**Verdict: the per-CF cost table is labeled fixture-scale and cited from
`storage-footprint.md`.**

| Column family | Logical bytes/row | Physical bytes/row (fjall, fixture-scale) | Amplification |
|---|---|---|---|
| TxConfirmed | 20 (12 key + 8 value) | ~75 | 3.75× |
| Funding | 20 (12 key + 8 value) | ~75 | 3.75× |
| Spending | 12 (12 key + 0 value) | ~89 | 7.42× |
| BlockHeaders | 80 (80 key + 0 value) | ~0 (compressed, fixture) | <0.01× (fixture) |

**Caveats:**

- Physical bytes/row is computed as `on_disk / rows` from the 200k-row
  fixture. It includes bloom-filter, block-index, and key-encoding overhead.
- The BlockHeaders amplification is an artifact of the synthetic corpus
  (repetitive 80-byte headers compress to near-zero). On mainnet, expect
  amplification ≈ 1.0 (headers are incompressible).
- The Spending amplification figure predates positioned Spending values
  (format version 4) and has not been re-measured.

#### Q5: Live UTXO locator — what is the baseline key shape?

**Verdict: baseline is `prefix(8) || txid(32) || vout(4)` with an empty
value. A smaller locator requires an injectivity proof.**

ScriptLive is a compact reverse view of the authoritative UTXO set (current
outpoint locators per script), not a mempool index and not a Coin copy.
Rows were **not implemented** when this audit was frozen. This verdict
froze the baseline key shape so the implementation did not need to
revisit the decision. Since then `ScriptLiveRow` landed in
`crates/index/src/types.rs` with a 44-byte key, and format 5 narrowed the
`vout` suffix to u24: the key is now 43 bytes
(`SCRIPT_LIVE_ROW_SIZE = HASH_PREFIX_LEN + 32 + 3`).

**Baseline key: `prefix(8) || txid(32) || vout_u24(3)` = 43 bytes, empty value.**

Rationale:

- The confirmed index uses 8-byte prefixes for scan efficiency, but a
  mempool row must be deletable when the transaction confirms or is evicted.
  A prefix-only key is lossy: multiple outpoints can share a prefix, so
  deletion by prefix would remove unrelated rows.
- The full outpoint (`txid(32) || vout(3, u24)`) is injective: each outpoint
  maps to exactly one key. The 8-byte prefix is prepended to preserve the
  same scan-prefix contract as confirmed rows (`ScriptHashRow::scan_prefix`
  returns the first 8 bytes of the scripthash), so a single prefix scan
  over the Live CF returns both confirmed and unconfirmed rows for a
  scripthash without a second seek.
- The value is empty because the Live key already names the outpoint
  (`txid || vout`). The caller fetches the transaction from the mempool or
  the confirmed index by that txid; a stored position or coin copy would
  duplicate state the Live row is not authorized to own.

**A smaller locator (e.g. dropping the prefix, or hashing the outpoint to
fewer bytes) requires an injectivity proof:** a demonstration that no two
live outpoints can produce the same key, and that prefix-scan efficiency is
preserved. The u24 narrowing keeps the full txid and every consensus-valid
vout (all `<= U24_MAX`), so injectivity holds; the 43-byte key is current.

### Versioning: per-capability format and reset

The index tracks two independently versioned capabilities via
`IndexCapability`:

| Capability | Column families | Watermark key |
|---|---|---|
| `TxLookup` | `TxConfirmed`, `BlockHeaders` | `TX_LOOKUP_WATERMARK_KEY` |
| `ScriptHistory` | `Funding`, `Spending` | `SCRIPT_HISTORY_WATERMARK_KEY` |

**Per-capability format version.** The row-value format version
(`INDEX_FORMAT_VERSION`, currently 3) is the soft report marker in `UtxoMeta` (the
hard open-gate marker is the durability key `[0x00, b'V']`, row-format 5). It
arrays, and at which width (version 3: 6-byte u24 positions). The anticipated
`TxPosition`-width bump is this version. Readers already handle
`IndexFormat::Legacy` by falling back to full block scans, so an old-format
index remains correct, just slower.

**Per-capability reset.** The `IndexCapabilities` mask allows resetting one
capability without touching the other. `acquire_capability_reset` and
`resume_capability_reset` delete only the column families belonging to the
requested capability and clear only that capability's watermark. The reset
state is tracked in `RESET_CAPABILITIES_KEY` with a monotonic version that
prevents ABA across repeated resets.

Every durability marker (`[0x00, b'V']`) older than the current row-format 5
refuses start (`UnsupportedTxIndexFormatVersion`) and recovery full-resets
the store for rebuild: format 5 changed every row family, so no in-place
upgrade path exists. (Row-value format 3 is the soft report axis, not the gate.)

**Adding ScriptLive later must not force a History reindex.** ScriptLive
rows would occupy a new column family (not one of the existing four). The
`IndexCapability` enum would gain a `ScriptLive` variant with its own
watermark key. Because the reset mechanism is per-capability:

- Adding `ScriptLive` does not touch `Funding`, `Spending`, `TxConfirmed`,
  or `BlockHeaders` rows.
- A `ScriptHistory` reset (clearing `Funding` + `Spending`) does not touch
  `ScriptLive` rows.
- A `ScriptLive` reset clears only the Live CF.
- The `INDEX_FORMAT_VERSION` marker does not change: it governs the
  row-value format of existing CFs, not the existence of a new CF.

The only shared state between capabilities is the `ORDINARY_STATE_REVISION`
counter in `UtxoMeta`, which advances on every ordinary commit regardless of
which capability wrote. This is by design: the revision fences derived
writes against concurrent resets, and a new capability's writes must be
fenced the same way. Adding a capability does not change the revision
counter's semantics; it just means more writes advance it.

**No dual-read path.** The reader does not maintain a "read from old format,
then read from new format" fallback for a capability that has not been
reset. The `IndexFormat::Legacy` fallback is for the row-value format
(positions vs no positions), not for the presence or absence of a column
family. A new CF is either populated (after the first ingest) or empty
(before it); the reader handles both without a format check.

**No migration.** Adding a capability is additive: open the new keyspace,
start ingesting, advance the new watermark. No existing row is rewritten.
The only operator action is enabling the capability in the ingest
configuration; the reset mechanism handles the rest.
