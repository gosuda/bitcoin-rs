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
| TxConfirmed | `TxConfirmed` | 8 (prefix) + 4 (BE height) = 12 | `n × 6` (packed TxPosition array, n ≥ 1) | 12 + 6n |
| Funding | `Funding` | 8 (prefix) + 4 (BE height) = 12 | `n × 6` | 12 + 6n |
| Spending | `Spending` | 8 (prefix) + 4 (BE height) = 12 | `n × 6` | 12 + 6n |
| BlockHeaders | `BlockHeaders` | 32 (sha256d of the header) | 0 (empty value) | 32 |
| ScriptLive | `ScriptLive` | 8 (prefix) + 32 (txid) + 3 (vout) = 43 | 0 | 43 |

**Key observations:**

- `TxPosition` is 6 bytes: 3-byte LE offset + 3-byte LE length (`TX_POSITION_SIZE = 6`).
- The common case is n = 1, so the typical Funding/TxConfirmed/Spending row is
  **18 bytes** (12 key + 6 value).
- Spending rows carry positions for the transactions that spend the outpoint.
  An empty value never means "no spending" — it is a malformed row that
  requires a full-block scan.
- BlockHeaders rows are keyed by the 32-byte double-SHA256 of the header.
- ScriptLive locators keep the full txid in the key so point deletes are
  identity-safe under an 8-byte script-prefix collision.

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

## Chosen format (store version 5)

Derived ScriptIndex bytes are disposable. Format 5 is a store-wide epoch:
opening version 3 or 4 resets every derived capability and rebuilds from
authoritative chain/UTXO state. There is no dual-read, dual-write, legacy
decoder, or conversion pass.

| Row | Key | Value |
|---|---|---|
| TxConfirmed / Funding / Spending | `prefix(8) \|\| height_be(4)` | packed `TxPosition[n]`, 6 bytes each |
| BlockHeaders | `sha256d(header)(32)` | empty |
| ScriptLive | `prefix(8) \|\| txid(32) \|\| vout_u24(3)` | empty |

`INDEX_FORMAT_VERSION` is 3 (packed positions). High-level history resolvers
still sort by numeric height so API order does not depend on the raw key
encoding.

### Q1: TxPosition width

**Verdict: pack to 6 bytes (`u24` offset + `u24` length).**

Consensus-serialized blocks cannot exceed 4 MiB, so 32-bit fields wasted two
bytes on every occurrence. Packed 6-byte entries stay zerocopy (`&[TxPosition]`
from the value slice). Delta-coded `u24` offsets cannot beat that for the
common `n = 1` row; a varint delta would win on `n > 1` but loses in-place
decode. Merge/batch admission uses `TX_POSITION_SIZE`, so the smaller value
automatically admits more positions under the same `max_bytes` cap.

Rejected: keep 8-byte `u32` pair (format 4); varint/delta as the production
codec (decode allocates and is not a win at `n = 1`).

### Q2: Empty Spending value vs position

**Verdict: Spending rows carry packed positions (unchanged from format 4).**

`spender_for` runs once per funding output. Unpositioned spends cost a full
block reservation each. Positions also identify the exact spender under an
8-byte outpoint-prefix collision, so the reader does not scan the block to
disambiguate.

Rejected: empty Spending values.

### Q3: Height endian

**Verdict: big-endian height. Sort in the reader anyway.**

LE keys made lexicographic order disagree with numeric height (height 256
sorted before height 1). That also scattered sequential IBD writes for a
hot script across the keyspace and defeated LSM prefix compression of the
8-byte hash prefix. BE makes store order chronological, clusters writes for
one prefix, and lets a bounded height scan walk the prefix in order.

API pagination still sorts by numeric height. Store order matching numeric
order is a physical win, not the API contract.

Rejected: keep LE "because electrs does" — electrs layout is not a
compatibility constraint for rebuildable derived state.

### Q4: Per-CF cost table (fixture-scale)

Logical bytes/row after format 5:

| Column family | Logical bytes/row |
|---|---|
| TxConfirmed | 18 (12 key + 6 value) |
| Funding | 18 (12 key + 6 value) |
| Spending | 18 (12 key + 6 value) |
| BlockHeaders | 32 (32-byte hash key + empty value) |
| ScriptLive | 43 (43-byte locator + empty value) |

Physical fjall figures in `storage-footprint.md` are still the format-4
200k-row corpus. Re-run `crates/storage/examples/storage_footprint.rs` on
format 5 before treating those numbers as current.

### Q5: Live UTXO locator

**Verdict: `prefix(8) \|\| txid(32) \|\| vout_u24(3)` = 43 bytes, empty value.**

The full txid stays in the key so the locator is injective on
`(script_prefix, outpoint)`. Two scripts that collide on the 8-byte prefix
cannot share an outpoint, and distinct outpoints cannot share a key, so a
point delete cannot remove another script's row. Prefix-range scans stay
read-only. `vout` packs to 3 bytes because consensus output counts cannot
reach `2^24` under the serialized-block size cap.

Rejected:

- `prefix \|\| txid \|\| vout_u32` (44-byte baseline): one unused identity byte.
- Shorter txid / hashed outpoint locators: not injective; a point delete
  can drop another live row, and no read-side exact-check recovers a row
  that is already gone.
- Grouping vouts under `(prefix, txid)`: requires read-modify-write on
  every spend and is unsafe if coalesced as last-op-per-key instead of
  last-op-per-vout.

## Versioning: per-capability reset, store-wide format epoch

The index tracks three independently reset capabilities via
`IndexCapability`:

| Capability | Column families | Watermark key |
|---|---|---|
| `TxLookup` | `TxConfirmed`, `BlockHeaders` | `TX_LOOKUP_WATERMARK_KEY` |
| `ScriptHistory` | `Funding`, `Spending` | `SCRIPT_HISTORY_WATERMARK_KEY` |
| `ScriptLive` | `ScriptLive` | `SCRIPT_LIVE_WATERMARK_KEY` |

Format 5 changes shared prefix-row encoding, packed positions, header keys,
and the Live locator, so opening version 3 or 4 resets **all** derived
capabilities. A later change that touches only Live can reset only
`ScriptLive`; a change that touches only packed positions still has to
reset TxLookup and ScriptHistory together because they share
`HashPrefixRow` / `TxPosition`.

`INDEX_FORMAT_VERSION` (currently 3) is the packed-position marker written
alongside a ScriptHistory reset. A foreign store version that is not 3, 4,
or 5 still refuses start.

**No dual-read path, no migration.** Previous ScriptIndex bytes are
deleted and rebuilt from authoritative chain/UTXO sources. Live is cheap
to re-seed (one pass over the UTXO set); History is a reindex.
