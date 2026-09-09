# UTXO set memory attribution

Step 2.1 of the memory campaign: measurement only, no encoding change. It exists
to decide whether the encoding and allocation work planned after it is worth
doing at all.

The question. `UtxoSet` is fully memory-resident across 256 shards with no
eviction tier, and the published tip-RSS evidence reached **13.83 GiB at height
645,804** without making the tip, against a G14 budget of 16 GiB. Nothing had
ever attributed that figure. The record constants predict roughly 5 GB at that
height, leaving ~9 GiB unexplained, and the plan named allocator fragmentation
across tens of millions of small allocations as the leading suspect.

The retired `utxo_memory_attribution` example used
`UtxoSetView::memory_report()` over a synthetic set with a mainnet-shaped script
mix and 1.5 live outputs per record. The measurements below are retained as
historical evidence; the one-off executable is no longer supported.

## What a UTXO costs

Bytes per live output, constant across every size measured:

| Layer | Bytes/output | Share |
|---|---:|---:|
| Record payload | 69.6 | 63% |
| ...plus allocation header and slack | 74.9 | 68% |
| ...plus hash-table backing store | 87.5 | 79% |
| Process RSS, 200% churn | 110.5 | 100% |

The absolute RSS-to-accounted ratio falls with scale as the fixed process
baseline amortizes — 1.431x at 750k outputs, 1.207x at 3M, 1.163x at 6M — so the
honest figure is the **marginal** cost between the 3M and 6M points, which
removes the baseline entirely: **97.96 bytes of RSS per output against 87.5
accounted, a 1.12x allocator overhead.**

## Where the payload goes

The 69.6 bytes of payload per output decompose as:

| Item | Bytes/output |
|---|---:|
| Record header amortized (37 B over 1.5 outputs) | 24.7 |
| ...of which the 32-byte txid alone | 21.3 |
| Per-output metadata (`vout`, value, height, coinbase, script_len) | 19.0 |
| Script bytes | 25.9 |

**The single largest item is the txid**, at 21.3 bytes per output, because a
record averages only 1.5 live outputs to amortize it over. It is also the one
item that cannot be compressed: the 8-byte key prefix is lossy and the full txid
is what makes a lookup exact.

## Fragmentation is not the answer

The plan's leading hypothesis was allocator fragmentation from tens of millions
of small allocations. Tested directly by spending the oldest tenth of the set and
refilling it, repeatedly, holding the live count constant:

| Churn | RSS bytes/output | RSS / accounted |
|---|---:|---:|
| None (monotonic insert) | 105.7 | 1.207x |
| 50% of the set replaced | 108.3 | 1.237x |
| 200% of the set replaced | 110.5 | 1.263x |

Churning twice the whole set costs **5% more RSS**, and the curve is flattening,
not climbing. Uniform small allocations are the case a size-class allocator
handles well. **The hypothesis is refuted at this scale on this allocator** —
with two caveats worth keeping: production links mimalloc rather than the system
allocator, and 645,804 blocks is far more churn than twenty rounds.

## Historical full-node measurement

A pruned mainnet sync to **height 412,732** (38,145,360 outputs across
10,519,335 records) settled the assumptions above. The figures below are
historical evidence collected by the former checkpoint RSS-attribution hook;
that hook is no longer part of the node runtime. Current full-node RSS evidence
must use an external process monitor. The former `snapshot_memory` helper was
also retired with the completed memory campaign.

| Layer | Bytes/output | Total |
|---|---:|---:|
| Record payload | 55.1 | 1.96 GiB |
| ...plus allocation header and slack | 57.3 | |
| ...plus hash-table backing store | 61.2 | 2.18 GiB |
| **Process RSS** | **79.2** | **2.81 GiB** |

**The UTXO set is 77.4% of process RSS**, not the ~44% an in-flight sample
suggested. The remaining 0.64 GiB is fjall, CoinStats, the block-record log and
the runtime.

An earlier revision attributed 450 MB of that residual to the configured
`dbcache`. That was wrong at the time: `Config::dbcache_mb` was parsed but never
reached a backend constructor. **Update:** the budget is now real —
`dbcache_mb` divides across namespaces and every backend takes its share
through `open_with_cache` (issue #51). The attribution numbers in this
document predate that change and a fresh RSS decomposition is needed before
any residual claim is re-earned.

**The synthetic harness is validated.** Re-run at the measured 3.626 outputs per
record it predicts 54.6 B/output of payload against 55.1 measured (0.9% apart)
and 62.0 accounted against 61.2 (1.3%). The v4 snapshot on disk is 57.3
B/output, a third independent path agreeing.

**Outputs per record was the assumption that mattered, and it was wrong.** The
first pass assumed 1.5; the real trajectory is 2.296 at height 183k, 3.427 at
302k, 4.056 at 390k (the 2015 UTXO-spam era) and 3.626 at 412k. It has not
converged, and the tip value is still unknown.

## Verdict

| | Tip projection, 180M outputs | Share of the 16 GiB budget |
|---|---:|---:|
| Today (v4) | **13.28 GiB** | **83%** |
| With the v5 codec, measured on a real chainstate | **11.35 GiB** | **71%** |
| Projected before building it | 9.61 GiB | 60% |

**The projection was optimistic and the measured figure is what stands.** It
assumed 17 B/output from four changes; three of them shipped and deliver a
measured **11.49 B/output of RSS** on a real 38,145,360-output chainstate, which
is 14.5% of process RSS and about **1.93 GiB at tip**. (An earlier revision of
this line quoted 11.75 from the synthetic bench; the real chainstate came in 5.1%
under it.) The fourth — hoisting `height` into the record header, worth roughly 3
B/output — was not attempted, because it needs an invariant BIP30 duplicate
txids may break. Core-style script compression, the other 3 B/output, is
untouched.

At 83% of budget on the UTXO path alone — before `txindex` and
the remaining derived indexes, which the G14 budget requires — that 12-point margin is
worth having, but it does not by itself settle the gate.

**Step 2.2 is justified and done. Step 2.4 is not**: fragmentation measured 5%
after churning twice the whole set.

### When to revert v5

Stated now, while the numbers are in front of us, so that whoever reads this
later does not have to reconstruct the trade.

v5 costs about **3 ns per lookup** at the measured mainnet average and **3-21%
on block commit p95**, against budgets with roughly twenty times the headroom.
It buys **12 points of the 16 GiB tip-RSS budget**. That is a good trade only
while tip RSS is actually near the budget — and the budget has never been
measured. The 13.83 GiB figure everything here is projected from comes from
*excluded* evidence at height 645,804, on a run that never made the tip.

**If G14 tip RSS measures well under budget — say below 10 GiB — this
complexity is not earning its keep and reverting is the right call.** The
historical v4 implementation and its comparison harness have since been
retired; the measurements below remain evidence for that decision, not a
current compatibility or benchmark contract.

The second thing that would change the answer is outputs per record. The
projection holds it at 3.626; it has not converged (2.296 at height 183k, 4.056
at 390k), and it is the number the result is most sensitive to, because the
32-byte txid amortizes over it directly.

## Step 2.2: the v5 record codec

**Result: 11.75 bytes saved per output (21.7% of the payload), for a lookup cost
of about 3 ns on a typical record and a lookup *win* on a fat one.**

> **Correction, 2026-08-16.** This section first said "lookups are faster than
> v4 rather than slower", quoting the `utxo_commit` arms. Those arms use a
> **256-output** record, and the two layouts cross over well above the record
> size mainnet actually has. The measured average is 3.626 outputs per record,
> where v5 is slower. The claim was true of the fixture and false of the
> workload, which is the more useful thing to be right about.

### Measured on the real chainstate, not the synthetic bench

Everything above about size came from a synthetic fixture. The same 2.03 GiB
`utxo-v4.dat` a real pruned sync produced at height 412,732 — 10,519,335 records
and **38,145,360 outputs** — was then loaded by a v4 build and a v5 build.
Same file, same machine, only the codec differs; both loads were measured
with the now-retired `snapshot_memory` campaign helper.

| Layer | v4 | v5 | Saved |
|---|---:|---:|---:|
| Record payload | 55.08 B/output | 43.90 B/output | **11.18** |
| ...plus allocation header and slack | 57.28 | 46.11 | 11.17 |
| ...plus hash-table backing store | 61.24 | 50.07 | 11.17 |
| **Process RSS** | **65.57** | **54.08** | **11.49** |

**The synthetic bench was 5.1% optimistic.** It predicted 11.75 B/output of
payload; the real chainstate gives **11.18**. The figure to quote is 11.18.

Two things corroborate the instrument. The v4 payload here is 55.08 B/output
against the 55.1 the original attribution run measured by a completely different
route, and the RSS saving (11.49) is slightly *larger* than the payload saving
(11.17), which is what an allocator returning whole size classes should do.

**And it is consensus-neutral on real data.** Both builds produce the identical
`hash_serialized_3` —
`438e59e4c0400b89cd06a5bb3623234a299ba5cf600043fb298ab345c328edfb` — and a
`MuHash` trailer whose SHA-256 matches the one the checkpoint manifest recorded
when the v4 node wrote it. That is the golden-vector assertion from
`crates/utxo/tests/snapshot_v4_golden.rs`, restated over 38 million real outputs
instead of 433 fixture ones.

What this does **not** measure is full-node tip RSS: it loads the UTXO set alone,
with no fjall, CoinStats, block-record log or runtime alongside it. The G14 gate
still needs a synced tip node with `txindex` and the remaining derived indexes.

### Where the two layouts cross over

`find_output`, by record size, `before_v4` against `after_v5`:

| outputs | `miss` | | | `hit_last` | | |
|---|---:|---:|---:|---:|---:|---:|
| | v4 | v5 | ratio | v4 | v5 | ratio |
| 1 | 2.6 ns | 7.6 ns | 0.35x | 2.5 ns | 15.6 ns | 0.16x |
| **3.626 (measured mainnet average)** | 3.9 ns | 6.9 ns | 0.57x | 3.6 ns | 17.1 ns | 0.21x |
| 16 | 16.6 ns | 20.7 ns | 0.80x | 17.1 ns | 39.7 ns | 0.43x |
| 64 | 108.4 ns | 78.7 ns | 1.38x | 126.8 ns | 135.4 ns | 0.94x |
| 256 | 462.1 ns | 294.1 ns | 1.57x | 476.7 ns | 492.5 ns | 0.97x |

v5 pays a fixed ~11 ns to read the directory header and decode the matched
payload, and then scans at a fraction of v4's per-output cost. Below roughly 64
outputs the fixed cost dominates; above it the scan does. `hit_first` never
crosses, because v4's best case is a single constant-offset read the optimizer
reduces to almost nothing.

Replacing the amount transform's `while` loop of up to nine dependent multiplies
with a power-of-ten lookup took that fixed cost from 12.5 ns to 11.3 ns — 1.1x,
real but small. It was worth doing for a different reason (see below); the
remaining fixed cost is the directory read and building the returned view, not
the arithmetic.

**In absolute terms the loss is 3 ns per lookup at the mainnet average.** At
~4,000 spent inputs per block that is 12 µs against a 50 ms commit budget —
0.02% — bought with 21.7% of the record payload. The win concentrates on batch
payouts, the records where a lookup was expensive in the first place.

The `utxo_commit` arms measure 705 ns -> 300 ns (2.35x) on their 256-output
fixture, against this harness's 472 ns -> 299 ns (1.58x) for the same shape.
The v5 figures agree; the v4 ones do not, because `utxo_commit` drives the real
`UtxoRecord::find_output` while this harness reimplements the v4 search as a
direct loop that the optimizer handles better. **The microbenchmark is the
conservative number** and the one quoted above.

v5 keeps v4's record header and replaces the per-output layout:

```
txid(32) || output_count(4) || inline_len(1) || widths(1)
|| vout_dir  : one fixed-width little-endian entry per output
|| len_dir   : one fixed-width payload length per output
|| payloads  : varint(amount) [|| raw amount] || varint(height << 1 | coinbase) || script
```

Three encodings do the shrinking, all pure per-output transforms with no
cross-output invariant to violate: Core's `CTxOutCompressor` amount transform,
`height` and `coinbase` packed into one varint, and directory widths that are
the narrowest the record needs. The script length is not stored at all — the
script is whatever remains of its payload, so the length directory pays for
itself.

Hoisting `height` into the record header would save 3 bytes more and is **not
done**: it needs "every output of a record shares one height" to hold, and
BIP30's duplicate coinbase txids are exactly where it might not.

### Rejected first draft: flat varints

The first v5 was a flat frame per output —
`varint(vout) || varint(amount) || varint(packed_height) || varint(script_len) || script`
— with no directories. It hit the size target and **failed on speed**, and the
way it failed is the part worth keeping.

| Operation | v4 | flat v5 | directory v5 |
|---|---:|---:|---:|
| `get_miss` (real shard lookup) | 705 ns | 3.42 µs | **300 ns** |
| `get_last` | 728 ns | 3.43 µs | **617 ns** |
| `get_middle` | 384 ns | 1.67 µs | **342 ns** |
| `spend_fanout_64` | 18.5 µs | 39.9 µs | 21.3 µs |
| `spend_fanout_64_noop_listener` | 86.7 µs | 115.2 µs | **77.1 µs** |

Those `same_txid_lookup` arms hold **256 outputs in one record**, which is the
far side of the crossover above. Read them as the fat-record case, not as the
typical one.

Two mistakes produced that 4.4-4.9x, and neither was visible until the benchmark
was reshaped:

1. **The benchmark measured the wrong operation.** It timed whole-record
   `encode`/`decode`. The operation that dominates is `find_output(vout)` —
   every spent input resolves through `Shard::get`/`get_entry`/`get_meta`, and
   all three land there. Whole-record decode is the snapshot and rescan path,
   which is rare by comparison.
2. **v4 gets lazy field skipping for free, and v5 cannot.** Every v4 field sits
   at a constant offset, so when only `vout` is read the optimizer deletes the
   loads for the rest. In a flat variable-length layout each varint's length is
   what locates the next field, so the reads are a serial dependency chain no
   optimizer can remove — and locating output `i` meant walking the bytes of
   outputs `0..i`, scripts included.

The directories fix exactly that: a lookup scans one dense fixed-width array and
sums a second, touching ~2 bytes per output instead of ~35. It is why `get_miss`
ends up **2.3x faster than v4**, not merely level with it.

### A corrupt record could panic the decoder

Found while looking at why `find_output` has a fixed cost, and worth more than
the answer to that question.

`decompress_amount` finished with a `while` loop multiplying by ten up to nine
times. `read_varint` hands it whatever a record contains, and
`validate_encoded` runs it over every output of every record loaded from a
snapshot — so a file on disk could reach it with an arbitrary `u64`.
`decompress_amount(u64::MAX)` is 2.05e22: **a panic in a debug build, a silent
wrap in a release one.** Reproduced before fixing, as
`an_absurd_compressed_amount_is_rejected_rather_than_overflowing`, which failed
with `attempt to multiply with overflow`.

The fix returns `Option` and requires the decompressed value back inside the
compressible domain, which also closes a canonicality hole that was open until
now: the compact form may encode only amounts the escape refuses, and the escape
refuses exactly the amounts the compact form covers, so each amount has one
spelling and no other.

`decompress_accepts_exactly_the_encoder_image` states that as a property over
every `u64`: whatever the decoder accepts must round-trip back to the same
compressed value through the encoder. It does not merely check for absence of
panics — it pins the accepted set to the encoder's image exactly.

### What it costs

Encoding is 1.6-2.4x slower, because the directory widths are a property of the
whole record, so nothing can be written until every payload length is known.
At block scale that shows up as commit p95 rising 3% (`existing`), 8%
(`uniform`) and 21% (`concentrated`, which puts all 10,000 entries in one
shard). Against the G14 budget of 50 ms this is not close to binding: the worst
case measured is 2.57 ms.

One encode "optimization" was tried and **rejected by measurement** — staging
both directories in a `SmallVec` scratch and copying once, instead of one push
per entry. It measured 505.7 ns against 428.5 ns on a 16-output record: setting
up the scratch costs more than the bounds checks it saves at one or two bytes
per entry.

### How it is checked

The former `record_codec_equivalence` integration test and `record_codec`
benchmark were retired with the A/B harness. Historical v4/v5 equivalence and
size checks remain on this page as evidence; current record correctness is
covered by the unit tests in `crates/utxo/src/record.rs` and the snapshot and
commit integration tests. The deterministic `find_output` work-count test
remains because it protects the lookup algorithm without asserting wall time.

Reproduce the retained production-shaped benchmark:

```
cargo bench -p bitcoin-rs-utxo --bench utxo_commit
```

## Superseded: the pre-measurement sizing

The section below was written from the synthetic harness alone, assuming 1.5
outputs per record. It concluded encoding work was worth ~7% of process RSS and
recommended against starting it. Both inputs were wrong. Kept because the
reasoning error is the instructive part: it priced a change against a component
size that had never been measured.

Extrapolating 110 bytes/output to the ~67M outputs live at height 645,804 gives
**about 6.9 GiB** — roughly **half** of the observed 13.83 GiB. The UTXO set is
not where the other ~7 GiB is. Candidates never yet measured: fjall/RocksDB
memtables and block caches, CoinStats MuHash state, the `Vec<BlockRecord>` log,
and the sync staging budgets.

Sizing the planned encoding work against the measured layout:

| Planned change | Saving | Share of UTXO RSS |
|---|---:|---:|
| Hoist `height` + `coinbase` to the record header | 5 B/output | 4.5% |
| Compressed amounts (8 B -> ~3 B) | 5 B/output | 4.5% |
| Varint `vout` and `script_len` (6 B -> ~2 B) | 4 B/output | 3.6% |
| Core-style script compression | ~3 B/output | 2.7% |
| **Total** | **~17 B/output** | **~15%** |

Fifteen percent of a component that is itself about half of process RSS is
**roughly 7% of the number the G14 budget is written against**. The arena work in
Step 2.4 targets the 8-byte allocation header plus the fragmentation measured
above — around 10% of UTXO RSS, or ~5% of process RSS — and it is the largest and
riskiest item in the plan.

**Recommendation: do not start Step 2.2 or 2.4 on this evidence.** Neither is
wrong, both are small, and the half of the problem that has never been measured
is larger than everything they can win together. Attribute the non-UTXO half
first.

## Caveats

- **1.5 live outputs per record is an assumption**, and it is the one the result
  is most sensitive to: the 32-byte txid amortizes over it directly. At 1.2
  outputs per record the txid share rises to 26.7 B/output; at 2.0 it falls to
  16 B/output. A real distribution should be taken from a synced node before the
  encoding table above is used to make a decision.
- The script mix is representative, not measured from chainstate.
- System allocator, not the mimalloc production links.
- Whether the 13.83 GiB run had `txindex` and all remaining derived indexes enabled is not
  recorded, so the ~7 GiB residual cannot yet be split between index structures
  and everything else.
