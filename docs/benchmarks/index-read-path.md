# Index read-path benchmarks

Baseline for the ScriptIndex resolver read path, captured before any optimization.
Prior performance campaigns covered the sync and apply path only; `crates/index`
had no benchmarks for this resolver, so no read-path number existed.

Harness: `crates/index/benches/history_resolve.rs`. It is Criterion and measures
only the retained current position-backed resolver over a production-shaped
flat-file fixture. The `before_scan` and `after_fast` arms described below are
historical evidence from the retired refactor harness; they are not current
targets.

The historical arms called different functions — the former `*_scan` reference
against the position-backed resolver — over the same rows and block files.

> **Harness correction, 2026-08-13 (second).** Between the resolver rewrite
> landing and this revision, the two `electrum_methods.rs` arms were *literally
> the same call* — one `IndexHandle`, invoked twice. Every Electrum figure
> published in that window was an absolute cost labelled as a paired arm, and the
> section that reported it said as much, but the harness should not have been
> shipped in that shape. Caught in review of PR #80. The Electrum tables below are
> the re-measurement with the arms actually separated.

## Fixture shape

Synthetic blocks of P2WPKH-shaped outputs: 2,200 filler transactions
(~250 KB serialized) or 9,000 (~1 MB), with one transaction paying the target
scripthash planted at each block's **midpoint**. Midpoint placement matters for
`resolve_transaction`, which returns on first match; planting at the front would
report half the scan cost.

"Heights" is the number of distinct block heights funding the target
scripthash — the number of funding rows the resolver walks. A real mainnet
address can have thousands.

Blocks are served from a **real `FlatFileBlockStore`**, the same path production
takes through `FlatFilePruneBodyStore`: a position lookup, then `load` for a
whole body or `load_range` for a slice, each paying the real
open/`fstat`/seek/read sequence.

> **Harness correction, 2026-08-13.** Figures published before this date came
> from an in-memory block source and contained **no file I/O at all**. The effect
> is very lopsided, and worth stating precisely rather than discounting
> everything:
>
> - The **`before_scan` arm barely moved** — 65.21 ms in memory against 65.644 ms
>   file-backed at 64 heights. One whole-body read is 23.44 µs against a 65 ms
>   scan, so I/O is ~0.04% of it. Every scan-path number on this page stands.
> - The **`after_fast` arm moved 4.5x** — 187.48 µs to 836.17 µs at the same
>   fixture. Once the resolver stops reading whole blocks, what is left *is* the
>   syscall sequence: `load_range` costs 12.00 µs whether it returns 250 bytes or
>   not, against 23.44 µs for a whole 250 KB body.
>
> So the ratios were inflated, not the baseline. Anything quoting an `after` arm
> below is the file-backed re-measurement.

Backend RocksDB. Medians of 20 samples. Apple Silicon laptop, not a quiet
measurement host — see the noise floor below.

## Index resolvers

Medians, `before_scan` arm, pre-optimization. Measured on the in-memory harness,
and retained: the scan path is CPU-bound, and re-measuring it against the
flat-file store moved 64 heights from 65.21 ms to 65.644 ms.

| Fixture | `resolve_script_history` | `resolve_unspent_..._with_height` | `resolve_transaction` | `resolve_outpoint_value` |
|---|---:|---:|---:|---:|
| 1 height, 250 KB | 1.02 ms | 2.42 ms | 0.90 ms | 0.91 ms |
| 8 heights, 250 KB | 9.33 ms | 17.43 ms | 1.13 ms | 0.91 ms |
| 64 heights, 250 KB | 65.21 ms | 136.50 ms | 0.92 ms | 0.91 ms |
| 8 heights, 1 MB | 33.52 ms | 82.04 ms | 4.48 ms | 3.75 ms |

**The cost is O(funding rows × block size).** `resolve_script_history` goes 1.02 -> 9.33 -> 65.21 ms
across 1 -> 8 -> 64 heights: a 63.9x rise for a 64x rise in rows. Holding rows at
8 and taking block size from 250 KB to 1 MB moves it 9.33 -> 33.52 ms, a 3.6x
rise for 4x the bytes. Both terms are linear and they multiply, because the
resolver reads and fully deserializes the whole block once per row and then
SHA256-hashes every output script in it.

`resolve_transaction` is flat in heights because a txid prefix matches one row,
so it scans exactly one block; it is linear in block size for the same reason
the others are.

**`resolve_unspent_outputs` costs about 2x `resolve_script_history` on the same
fixture** because it calls `tx.compute_txid()` for *every* transaction in the
block before checking any output script, while `resolve_script_history` computes
a txid only for transactions that matched. That is a double-SHA256 over every
full transaction serialization in the block, per row, thrown away for all but
one transaction.

## Historical Electrum dispatch evidence

> This protocol-level measurement is retained only as provenance for the resolver
> campaign. The Electrum server was removed; current consumers are `ScriptIndex`
> and Esplora.

End-to-end through `dispatch`, including JSON parameter parsing and rendering.
Medians, `before_scan` arm, pre-optimization, on the in-memory harness. The
64-height `get_history` figure of 86.53 ms sat well above the 65.6 ms the
resolver alone costs file-backed; that group's identical arms disagreed by up to
2.4x on this host at the time, so read it as "tens of milliseconds", not as a
precise number.

| Method | 1 height | 8 heights | 64 heights |
|---|---:|---:|---:|
| `blockchain.scripthash.get_history` | 1.01 ms | 8.14 ms | **86.53 ms** |
| `blockchain.scripthash.subscribe` | 1.03 ms | 8.05 ms | 71.99 ms |
| `blockchain.scripthash.get_balance` | 2.06 ms | 16.67 ms | 265.02 ms |
| `blockchain.scripthash.listunspent` | 2.06 ms | 22.04 ms | 131.42 ms |

**`get_history` is 2.9x over the 30 ms G14 budget at 64 funding heights over
250 KB blocks.** Since the index bench shows the cost is linear in block size,
the same address over tip-sized blocks projects several times higher again.
This is a synthetic fixture on a laptop and is **not** the G14 gate — that
historical gate remains unclaimed after the campaign tooling was retired. What
the number establishes is direction and shape, not a gate result.

`subscribe` runs the same resolution and then hashes the status. An Electrum
wallet issues one per address on connect, so it is the highest-volume caller of
this path.

## Harness noise floor

Measured at the baseline commit, when both arms of every group were the same
code and their spread was therefore pure noise. Both harnesses now run different
code in each arm, so this table cannot be re-derived from a current run — it is
retained as the calibration the ratios below are judged against. It is not
uniform:

| Group | Identical-arm spread |
|---|---|
| `get_history`, all height counts | <= 1% |
| index resolvers, >= 8 heights | 2-5% |
| index resolvers, 1 height | up to 21% |
| `get_balance`, 64 heights | 2.0x |
| `subscribe`, 64 heights | 2.4x |

Two separate effects. The 1-height index groups are fast enough (~1 ms) that
fixture-order and cache effects dominate. The 64-height `subscribe` and
`get_balance` groups run >70 ms per iteration, long enough for this host to
throttle mid-group.

**Consequence for the refactor sets:** `get_history` and the index resolvers at
>= 8 heights could resolve the 1.05x gate at baseline. `subscribe` and
`get_balance` at 64 heights could not — a win claimed there would have needed a
quiet host, more samples, or both.

That constraint is no longer binding: the `after` arm now runs in under a
millisecond. The measured 71.6x and 76.5x ratios are about 30x the largest
observed 2.4x spread, so the conclusion does not depend on the spread improving.

## Landed: lazy txid in the unspent-output resolvers

**Change.** `resolve_unspent_outputs_with_height` computed `tx.compute_txid()`
for every transaction in the block *before* testing any output script, and
discarded it for all but the matching one. The txid is now computed lazily, at
most once per matching transaction, via `Option::get_or_insert_with`.
`resolve_unspent_outputs` no longer duplicates the walk at all — it delegates and
drops the height. Pure code motion; no behavioural change.

**Historical equivalence (retired).** The former `resolver_equivalence`
integration tests compared the unspent-output resolvers with naive scan-only
references over single and multiple heights, duplicate matches, unresolvable
heights, never-indexed scripts, and random block/transaction/output shapes.
The tests and public scan-only oracle methods were retired with the A/B
harness. Current resolver behavior is covered by the Indexer unit tests and
the transaction-position contract tests; the private full-scan helpers remain
the live fallback path.

**Historical speed**, paired arms in one run, from the retired
`crates/index/benches/history_resolve.rs` harness.
In-memory harness, and unaffected by that: both arms here are scan-path variants,
so both are CPU-bound and I/O cancels out of the ratio.

| Fixture | `before_scan` | `after_fast` | Ratio |
|---|---:|---:|---:|
| 1 height, 250 KB | 2.050 ms | 1.001 ms | **2.05x** |
| 8 heights, 250 KB | 16.353 ms | 8.010 ms | **2.04x** |
| 64 heights, 250 KB | 135.95 ms | 64.016 ms | **2.12x** |
| 8 heights, 1 MB | 67.429 ms | 33.142 ms | **2.03x** |

`resolve_unspent` at 64 heights now lands at 64.0 ms against
`resolve_script_history`'s 65.2 ms on the same fixture. The two resolvers do the
same amount of block scanning, so their converging is the expected result: the
eager txid *was* the entire difference between them.

**Corroboration** end-to-end through Electrum `dispatch`. Both arms of that
harness call the same entry point, so this is a change against the stored
Criterion baseline rather than a paired comparison — weaker evidence, quoted only
because it agrees with the paired result: `get_balance` and `listunspent` each
fell about 50% at 1 and 8 heights. The 64-height groups are excluded per the
noise floor above; on this run their identical arms disagreed by 1.7x.

**Reference retirement.** The scan-only oracle and benchmark `before` arm were
removed after the comparison was completed. The historical numbers above remain
evidence for the lazy-txid change, not a current test or runtime contract.

## Landed: transaction byte positions in row values

The resolver now uses the positions for one-transaction reads.

**Change.** Funding and `TxConfirmed` row values were empty. They now carry a
packed `TxPosition[n]` — the `(offset, length)` byte range of each transaction
that produced the row, within its block's serialized body. Keys, key ordering
and row counts remain unchanged.
Spending rows now carry positions too, since `spender_for` reads them to resolve
the spending transaction without loading the full block.

**Storage cost, measured** on a 248 KB / 2,200-transaction block:

| Column family | Rows | Key bytes | Value bytes | Total vs before |
|---|---:|---:|---:|---:|
| Funding | 4,400 | 52,800 | 35,200 | **1.67x** |
| `TxConfirmed` | 2,200 | 26,400 | 17,600 | **1.67x** |
| Spending | 2,200 | 26,400 | 17,600 | **1.67x** |

Uncompressed and before the backend's own compression. At mainnet scale the
order of magnitude is tens of GB across the indexed row families; a real figure
needs a reindex.

**No block identity tag.** An earlier draft prefixed each value with 8 bytes of
block hash so a reader could detect positions left behind by a superseded block
at the same height. Measured, that tag cost another 0.66x on both families. It
was dropped in favour of an invariant the reader must honour instead: **fall back
to a full block scan the moment any single position fails to resolve**. Stale
offsets land at arbitrary points in a different block's bytes and essentially
never decode to a matching transaction, so they trigger the fallback; an 8-byte
prefix collision between two distinct scripthashes triggers it too, which is
correct and costs one scan per 2^64 pairs. The residual risk this accepts is a
stale offset landing exactly on a transaction boundary *and* that transaction
matching, while another transaction in the same block also matches.

**Position values.** `crates/index/tests/tx_positions.rs` covers the persisted
position encoding, exact transaction boundaries, and the independent row-value
contract. It intentionally does
not retain equivalence coverage for a second ingest implementation; the index
has one supported serialized-block ingest path.

## Landed: resolvers read only the transactions their positions name

**Change.** `resolve_script_history`, `resolve_unspent_outputs{,_with_height}`
and `resolve_transaction` now read each row's `TxPosition` list, fetch only
those byte ranges through `BlockSource::block_bytes_at_height`, and decode only
those transactions. Production resolvers use private per-height full-scan
helpers when positioned resolution fails; the former public scan-only oracle
methods were retired with the comparison harness.

**The all-or-scan rule is what makes this safe.** A resolver falls back to a full
block scan the moment any single position fails to resolve; it never skips a
failed position and keeps the rest. See the *All-or-scan position fallback*
concept.

**Speed**, paired arms in one run, over a real flat-file store:

| Fixture | Resolver | `before_scan` | `after_fast` | Ratio |
|---|---|---:|---:|---:|
| 1 height, 250 KB | `resolve_script_history` | 1.020 ms | 14.39 µs | **70.9x** |
| 8 heights, 250 KB | `resolve_script_history` | 8.182 ms | 106.38 µs | **76.9x** |
| 64 heights, 250 KB | `resolve_script_history` | 65.644 ms | 836.17 µs | **78.5x** |
| 8 heights, 1 MB | `resolve_script_history` | 33.275 ms | 106.26 µs | **313x** |
| 64 heights, 250 KB | `resolve_unspent_..._with_height` | 132.90 ms | 837.86 µs | **158x** |
| 8 heights, 1 MB | `resolve_unspent_..._with_height` | 67.713 ms | 106.50 µs | **636x** |
| 8 heights, 1 MB | `resolve_transaction` | 3.703 ms | 14.12 µs | **262x** |

**The block-size term is gone, which was the whole point.** At 8 heights the
resolver costs 106.38 µs over 250 KB blocks and 106.26 µs over 1 MB blocks — 4x
the bytes, no change at all. The `before` arm over the same two fixtures goes
8.182 ms to 33.275 ms. Cost is now set by how many transactions actually matched,
never by how large the blocks they sit in are, which is why the ratio climbs with
block size rather than holding steady.

**The `after` arm is now syscall-bound at ~13 µs per height** — 14.39 µs at one
height, 106.38 at eight, 836.17 at sixty-four, dead linear. That floor is the
`load_range` open/`fstat`/seek/read sequence, measured independently at 12.00 µs.
Removing it needs a batch read, not a cheaper resolver.

**End-to-end through Electrum `dispatch`**, over the same flat-file store,
**paired arms in one run**. `before_scan` is a handle whose block source declines
ranged reads, so the resolvers take the whole-block fallback; `after_fast` is a
handle over the identical rows and block files whose source serves them.

| Method | Heights | `before_scan` | `after_fast` | Ratio |
|---|---:|---:|---:|---:|
| `get_history` | 1 | 1.0198 ms | 15.99 µs | **63.8x** |
| `get_history` | 8 | 8.3475 ms | 115.94 µs | **72.0x** |
| `get_history` | 64 | 67.621 ms | 919.56 µs | **73.5x** |
| `subscribe` | 64 | 67.337 ms | 880.63 µs | **76.5x** |
| `get_balance` | 64 | 67.505 ms | 942.47 µs | **71.6x** |
| `listunspent` | 64 | 68.872 ms | 997.20 µs | **69.1x** |

Every group clears the 1.05x gate by two orders of magnitude, and the ratio is
stable at 62-77x across all twelve.

**`get_history` on this fixture went from 2.3x over the 30 ms G14 budget to 33x
under it.** Still a synthetic fixture on a laptop, and still not the gate.

Two cross-checks that the fixture is measuring what it claims:

- The `after_fast` arm tracks the index-resolver bench almost exactly — 919.56 µs
  end to end against 836.17 µs for `resolve_script_history` alone at 64 heights.
  Dispatch overhead is the ~83 µs difference, which is JSON parameter parsing and
  rendering 64 entries.
- The `before_scan` arm collapses the four methods onto one number (67.3-68.9 ms
  at 64 heights) where the pre-optimization baseline had them spread from 72 to
  265 ms. That is the lazy-txid change landing: `get_balance` and `listunspent`
  used to pay a double-SHA256 over every transaction in every block, and no
  longer do. They now cost what `get_history` costs, because all four are doing
  the same block scan.

The 64-height `subscribe` and `get_balance` groups, previously unusable at
2.0-2.4x identical-arm spread, are now stable: the `after` arm got cheap enough
that host thermal noise no longer dominates the group.

**Current contract coverage.** The resolver unit tests retain ordinary indexed
resolution and one deterministic fixture for an eight-byte prefix collision.
Rows whose positions are stale, malformed, or blank are outside the valid
watermark-backed index-state contract described in `CONCEPTS.md`, so they are
not promoted to permanent fallback contracts here. The private all-or-scan
fallback remains a defensive production path.

`TxPosition` implements `Ord` by hand: deriving it compares little-endian byte
arrays lexicographically, so offset 256 would sort before offset 1, and stored
positions would not be in block order. Emission order
is contractual — Electrum clients hash the sequence to derive a status.

## Rejected: decoded-block cache

Built, measured, reverted. Recorded so nobody rebuilds it without first removing
the reason it fails.

**The idea.** After the position rewrite, three callers still need whole decoded
blocks: `blockchain.transaction.get_merkle` and
`blockchain.transaction.id_from_pos`, which need every txid to build a merkle
proof and so cannot be served from positions at all, and the scan fallback on an
un-reindexed database. A wallet asking for proofs of several transactions in one
block decodes that block once per call. A small `(height, hash)`-keyed cache in
`NodeBlockSource` should have collapsed those to one decode.

**It did not pay.** Paired arms over a 250 KB / 2,200-transaction fixture, with a
metadata-only record log so every read goes through the decode path:

| Access pattern | Uncached | Cached |
|---|---:|---:|
| Repeated height (every read a hit) | 363.01 µs | 372.79 µs |
| Distinct heights (every read a miss) | 371.39 µs | 371.96 µs |

The miss case is free, as expected. The **hit** case is 1.027x *slower* than
decoding from scratch.

**Why.** `BlockSource::block_at_height` returns an owned `Block`, so a hit still
deep-clones the cached value: 2,200 `Transaction`s, each with its own input,
output and script `Vec`s. Both paths are dominated by the same few thousand
allocations, and cloning them costs what parsing them costs. Caching a value the
API forces you to copy saves nothing.

**What would work, and why it was not done.** Returning `Arc<Block>` would make
hits genuinely free, and only then would a cache pay. That is a change to a trait
with roughly ten implementations across four crates, it benefits only merkle
proofs and the un-reindexed fallback, and the budget this phase exists to meet is
already met with three orders of magnitude to spare. Treat it as an unproven
candidate with a known motivating measurement, not as pending work.

**Also not done: the `block_hex` round trip.** `NodeBlockSource::block_body_bytes`
hex-decodes a session-cached body on every read. Removing it means changing
`BlockRecord::block_hex` from `String` to bytes, which is a public RPC-crate shape
change — and production sets `cache_block_bodies_in_memory: false`, so the path is
off by default. Changing a public type for a win that cannot be measured in the
default configuration fails the same gate that rejected the cache.

## Platform check: is this an Apple Silicon artefact?

Asked directly, and worth recording, because two effects pull in opposite
directions and the published ratios are measured on the flattering side of one
of them.

**No read-path code is platform-gated.** `crates/index`, `crates/electrum`,
`crates/storage` and `crates/primitives` contain zero `cfg(target_arch)`,
`cfg(target_os)` or feature-detection sites. The workspace's only such file is
`crates/consensus/src/sha256d64.rs`, the AVX2 Merkle reducer, which is on the
apply path and is not reached by anything measured here. So there is no
Linux-only or x86-only optimization sitting idle on this host.

**SHA-256 is scalar here, and that flatters the `before` arm.**
`bitcoin_hashes 0.14` carries an x86-only SHA-NI path
(`is_x86_feature_detected!("sha")`, `_mm_sha256rnds2_epu32`) and **no aarch64
path at all**, so on Apple Silicon every scripthash runs the software
implementation. Measured on this host: 144 ns per SHA-256 of a 22-byte script,
so the 4,400 output scripts a 250 KB fixture block holds cost **634 µs** — that
is **64% of the 995.70 µs `before_scan` arm**. The `after` arm hashes almost
nothing.

On an x86 host *with* SHA-NI that 634 µs would fall by roughly 3-5x, taking the
`before` arm to somewhere near 520 µs and the ratio at that fixture from ~490x
to ~250x. Two things keep this from undermining the result: it is still two and
a half orders of magnitude, and the project's own reference host is a **Xeon
Gold 6138, which has no SHA-NI** — the same scalar regime measured here.

**The file-I/O gap is closed.** An earlier revision of this section flagged that
the harness served ranges from memory. It now uses a real `FlatFileBlockStore`,
and the re-measurement is in the tables above: the projection made here from
first principles — "roughly 73x per height on a real node, not 490x" — came out
at a measured **70.9x**. Standalone store costs, warm page cache:

| Operation | Cost |
|---|---:|
| `load` — whole 250 KB body | 23.44 µs |
| `load_range` — 250 bytes | 12.00 µs |
| `load_range` x5 (five positions at one height) | 62.34 µs |

A range read is only **2x** cheaper than reading a whole 250 KB body: at this
size both are dominated by the syscall sequence, not by bytes moved.

**`load_range` opens the file once per call, so P positions at one height cost P
opens.** Headroom, not a regression: even at five positions the positioned path
costs ~72 µs against the scan path's ~1,018 µs, because the scan still pays the
decode and the 4,400 hashes. A `load_ranges` batch that opens once per height
would recover most of the 62 µs. Left undone deliberately, and now cheap to gate
properly, since the harness is file-backed.

**Net platform expectation.** The two effects pull opposite ways. macOS syscalls
are more expensive than Linux ones, and the `after` arm is now syscall-bound at
~13 µs per height, so the I/O half of the win should be **better** on Linux.
SHA-NI on modern x86 speeds up the scan path, which is 64% SHA here, so the CPU
half of the win gets **smaller** there. On the project's SHA-NI-less Xeon
reference host both move toward what is published above.

What is not platform-dependent is the shape: the resolver's cost stopped scaling
with block size. That is a complexity change, and no amount of hardware moves
`resolve_script_history` at 8 heights off 106 µs whether the blocks are 250 KB or
1 MB.

## Historical protocol gate: still unclaimed

Everything above is in-tree resolver evidence. The retired protocol gate was
never run against a mainnet-tip node.

1. **The script needs Python 3.10+.** It annotates with PEP 604 unions
   (`dict[str, str | bool]`) that are evaluated at runtime. On a host with
   Python 3.9, it dies parsing its own arguments, and **79 of the 81 tests in
   `bin/bitcoin-rs/tests/g14_perf_evidence_script.rs` fail** with
   `TypeError: unsupported operand type(s) for |`. Verified pre-existing: the
   same 79 fail with this branch's changes stashed. The requirement is declared
   nowhere in the script or its usage text.
2. **The script is Linux-only.** Eight reads of `/proc` — `/proc/{pid}/exe` for
   the process-identity check, and the network tables for the
   accepted-connection proof. There is no macOS path.
3. **It needed a synced mainnet-tip node** with the retired server enabled and a corpus of
   real 64-hex scripthashes, one per line, with at least 10,000 non-empty
   histories.

The retired invocation is not a current reproduction command:

```
# retired command; retained arguments are historical only
  --output <measurement.json> --host <host> --port <port> \
  --pid <bitcoin-rs-pid> --tip-height <height> --tip-hash <64-hex> \
  --scripthashes <corpus-path> --sample-size 10000
```

Defaults were `--sample-size 10000 --seed g14-electrum-rss-v1
--timeout-seconds 30`; the emitted JSON carries schema
`g14-electrum-rss-measurement-v1`; the retired script is not a current command.

**Do not claim the gate from the numbers on this page.** They come from
synthetic fixtures on a laptop. What they establish is that the resolver's cost
no longer scales with block size and that the dominant term is gone — the
direction and the shape, not the gate result.

## Reproduce

```
cargo bench -p bitcoin-rs-index    --bench history_resolve   --features rocksdb
```

Both fixtures assert they resolve the expected entry count before benchmarking.
An earlier revision of the harness silently generated only 256 distinct scripts
— an LCG modulo 2^64 has period 256 in its low byte, and the generator sampled
`state & 0xff` — so filler scripts collided with the target and the resolver
returned 19 entries for a 1-height fixture. The assertion caught it. Keep it.
