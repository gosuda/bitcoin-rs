# ScriptIndex on-disk format audit

Froze 2026-09-02 at branch `overhaul/one-session` commit `a24d23b`.
This document is a **frozen** audit: the methodology and verdicts below are
the reference. Numbers recorded here are fixture-scale and labeled as such;
they are not mainnet projections.

## Freeze order

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

## Trial count

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

## Fjall-primary accounting

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

## Query mix

The audit exercises the read-path operations that ScriptIndex callers use:

| Operation | Function | Column family |
|---|---|---|
| Funding row scan | `iter_funding_rows` | `Funding` |
| Spending row scan | `iter_spending_rows` | `Spending` |
| Txid row scan | `iter_txid_rows` | `TxConfirmed` |
| History resolve | `resolve_script_history` | `Funding` |
| Unspent resolve | `resolve_unspent_outputs_with_height` | `Funding` |

The query mix is read-only. No write-path measurement is in scope.

## Materiality rule

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

## One-corpus / one-disposable-fixture guard

**No multi-GB corpus build was started.** The audit uses only:

1. **In-repo fixtures** — the `MemoryStore` backend (`crates/index/tests/common/mod.rs`)
   and the test blocks constructed in `crates/index/tests/le_order.rs`.
2. **Cited fjall figures** — from the existing
  `docs/benchmarks/storage-footprint.md` 200k-row synthetic corpus, not
  re-run.

The disposable-fixture guard: any fixture created for this audit (the
`le_order.rs` test blocks) is test-only, behind `#[test]`, and never shipped
as a benchmark corpus or a data file.

## Logical vs physical bytes

### Logical byte layout (from `crates/index/src/types.rs`)

| Row type | Column family | Key bytes | Value bytes | Total per row |
|---|---|---|---|---|
| TxConfirmed | `TxConfirmed` | 8 (prefix) + 4 (LE height) = 12 | `n × 8` (TxPosition array, n ≥ 1) | 12 + 8n |
| Funding | `Funding` | 8 (prefix) + 4 (LE height) = 12 | `n × 8` (TxPosition array, n ≥ 1) | 12 + 8n |
| Spending | `Spending` | 8 (prefix) + 4 (LE height) = 12 | `n × 8` (TxPosition array, n ≥ 1) | 12 + 8n |
| BlockHeaders | `BlockHeaders` | 80 (raw header = block hash) | 0 (empty value) | 80 |

**Key observations:**

- `TxPosition` is 8 bytes: 4-byte LE offset + 4-byte LE length (`TX_POSITION_SIZE = 8`).
- The common case is n = 1 (one transaction at one height funds one script),
  so the typical Funding and TxConfirmed row is **20 bytes** (12 key + 8 value).
- Spending rows carry positions for the transactions that spend the outpoint.
  An empty value never means "no spending" — it is a legacy row value that
  requires a full-block scan.
- BlockHeaders rows are keyed by the raw 80-byte block header (which is also
  the block hash). The value is empty.

### Physical bytes on fjall (fixture-scale, cited from storage-footprint.md)

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

## Q1–Q5 verdicts

### Q1: TxPosition width — is 8 bytes (4+4) sufficient?

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

### Q2: Empty Spending value vs position — should Spending carry positions?

**Verdict: Spending rows carry positions (format version 4).**

`spender_for` runs once per funding output for address history and UTXO
queries, so an unpositioned spend costs a 4 MB full-block reservation each and
exhausts the query budget after ~16 spends (issue #262). Positions make the
spend path the same one-transaction read as funding.

### Q3: Keep LE height vs switch to sortable (big-endian) height?

**Verdict: keep LE. Sort in the reader.**

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

### Q4: Per-CF cost table (fixture-scale)

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

### Q5: Live UTXO locator — what is the baseline key shape?

**Verdict: baseline is `prefix(8) || txid(32) || vout(4)` with an empty
value. A smaller locator requires an injectivity proof.**

ScriptLive is a compact reverse view of the authoritative UTXO set (current
outpoint locators per script), not a mempool index and not a Coin copy.
Rows are **not implemented** in this audit. This verdict freezes the
baseline key shape so a future implementation does not need to revisit
the decision.

**Baseline key: `prefix(8) || txid(32) || vout(4)` = 44 bytes, empty value.**

Rationale:

- The confirmed index uses 8-byte prefixes for scan efficiency, but a
  mempool row must be deletable when the transaction confirms or is evicted.
  A prefix-only key is lossy: multiple outpoints can share a prefix, so
  deletion by prefix would remove unrelated rows.
- The full outpoint (`txid(32) || vout(4)`) is injective: each outpoint
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
preserved. No such proof is offered here; the 44-byte baseline is the
default until one is.

## Versioning: per-capability format and reset

The index tracks two independently versioned capabilities via
`IndexCapability`:

| Capability | Column families | Watermark key |
|---|---|---|
| `TxLookup` | `TxConfirmed`, `BlockHeaders` | `TX_LOOKUP_WATERMARK_KEY` |
| `ScriptHistory` | `Funding`, `Spending` | `SCRIPT_HISTORY_WATERMARK_KEY` |

**Per-capability format version.** The row-value format version
(`INDEX_FORMAT_VERSION`, currently 2) is a single marker in `UtxoMeta`. It
governs whether Funding, Spending, and TxConfirmed values carry `TxPosition`
arrays.
A future format bump (e.g. changing `TxPosition` width) would increment this
version. Readers already handle
`IndexFormat::Legacy` by falling back to full block scans, so an old-format
index remains correct, just slower.

**Per-capability reset.** The `IndexCapabilities` mask allows resetting one
capability without touching the other. `acquire_capability_reset` and
`resume_capability_reset` delete only the column families belonging to the
requested capability and clear only that capability's watermark. The reset
state is tracked in `RESET_CAPABILITIES_KEY` with a monotonic version that
prevents ABA across repeated resets.

Opening a format-3 store (Spending keys without positions) is this kind of
reset: `IndexWriter::open` rebuilds `ScriptHistory` only and leaves
`TxLookup` ready. A foreign format version still refuses start.

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
