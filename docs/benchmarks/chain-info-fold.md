# Chain-info RPC benchmarks

Baseline and refactor-set measurement for `getblockchaininfo` and
`getchaintxstats`, the two RPCs that folded the node's whole block-record log.

Harness: `crates/rpc/benches/chaininfo.rs`. Criterion, both arms of the refactor
set in one group over one fixture in one process, so the ratio cannot be
confounded by the rebuild and baseline drift recorded in
`docs/solutions/best-practices/criterion-bench-trust-rebuild-drift-baselines-allocator.md`.

## What was wrong

`Context::blocks` holds one `BlockRecord` per applied block and grows for the
life of the process — ~963k entries on a mainnet node at the time of writing.
`fold_block_records` walked all of it to produce five scalars.

`getblockchaininfo` used one of them. It folded 963k records to report
`size_on_disk`, and threw the rest of the fold away.

The cost is worse than wasted work, because the fold ran **under the log's read
lock** — the same lock `apply_block` takes to append the record for a block it
has just connected. A `getblockchaininfo` call therefore stalled block
application for the length of the walk, and the walk got longer with every block.

## What was measured

| Records | `before_fold` | `after_indexed` | ratio |
|---:|---:|---:|---:|
| 10,000 | 19.32 µs | 3.83 µs | **5.0x** |
| 100,000 | 552.7 µs | 3.94 µs | **140x** |
| 500,000 | 4.214 ms | 4.24 µs | **993x** |
| 963,124 | **7.450 ms** | **3.77 µs** | **1,977x** |

The ratio grows with the record count because the arms have different
complexity, which is the claim. The new arm is flat — 3.77 µs to 4.24 µs across
96x the records — because what it still walks is the caller's window, not the
chain.

The old arm is *worse* than linear: 96.3x the records cost 385.6x the time, a
measured exponent of **1.30**. A fold over 963k records of ~110 bytes touches
~100 MB, so it leaves cache long before it leaves the log.

End to end, through `Handler::dispatch`:

| Records | `getblockchaininfo` | `getchaintxstats` |
|---:|---:|---:|
| 10,000 | 2.66 µs | 4.88 µs |
| 100,000 | 2.62 µs | 4.75 µs |
| 500,000 | 2.73 µs | 4.76 µs |
| 963,124 | 2.79 µs | 4.43 µs |

Both are now independent of chain length.

## What replaced it

**`BlockLog`**, an encapsulated log that maintains what the fold used to compute:

- `total_body_size`, a running sum, is `size_on_disk`. `getblockchaininfo` reads
  it and releases the lock.
- `cumulative_tx_count[i]`, the sum of `tx_count` over `records[..=i]`, answers
  `txcount` and `window_tx_count` as differences across two boundaries.

Deliberately a type rather than a `Vec<BlockRecord>` with totals kept beside it.
The log is appended from `apply`, from `Context::add_block` and from tests; a
total any of those could forget to update is a total that will drift. Reads are
unchanged — the type derefs to `[BlockRecord]`, so every existing slice, index,
iterator and binary search over the log still compiles and still means the same
thing.

**`chain_stats`** replaces the fold for `getchaintxstats`. The log is appended in
height order and only ever popped from the tail (`apply::disconnect_block`
checks the tail's hash before popping), so it is non-decreasing by height —
`Context::block_at_height` already relies on that and binary-searches it. Three
boundaries are located the same way: the last record at or below the applied
tip, the *first* record at the applied height (duplicate heights are possible
across a reorg, and the fold took the first), and the first record in the window.

Only the window is then walked, and only for `earliest_window_time`: it is a
minimum over block timestamps, which are not monotonic, so no prefix sum can
answer it. That walk is the caller's `nblocks` — 4,320 by default — not the
chain.

### Why prefix sums rather than one more running total

A single running `total_tx_count` answers `txcount` only when the applied tip is
the log's last record. Anywhere else it has to subtract the records above the
tip, and the first version of this change did exactly that.

The benchmark caught it. The fixture had no applied tip, so `applied_height` was
zero, the "tail above the tip" was the entire log, and `getchaintxstats`
measured **6.23 ms** while the reader it was supposed to be using measured
4.79 µs. A production node keeps the applied tip level with the log, so the
subtraction would have been free there — but that is a cliff, not a bound, and
it is exactly the sort of thing that holds until the day something lags.

Prefix sums answer any prefix in constant time. They cost 8 bytes per record,
~7.7 MB at a mainnet tip, against the ~254 MB the records themselves occupy.

The fixture was wrong too, and was fixed: it now publishes an applied tip at the
end of the log, which is the shape a node is actually in. The numbers above are
from the corrected fixture.

## Correctness, and how the tests were checked

`fold_block_records` is retained whole: it is the oracle the equivalence tests
compare against and the benchmark's `before` arm. It makes no assumption about
the log's ordering, which is the point — the replacement binary-searches, and an
oracle that shared that assumption could not catch it being wrong.

`chain_stats_matches_the_fold_it_replaced` sweeps **every** applied height from 0
to past the end of the log against **every** window length from 0 to past the
whole log, and compares all four figures each time. The fixture records height 3
twice, as a reorg leaves it, so "the first record at this height" and "records at
or below this height" are not the same boundary; and its timestamps dip at height
5, because block times are not monotonic and an earliest-in-window that assumed
they were would be wrong there.

The tests were then audited by mutation:

| Mutation | Expected | Result |
|---|---|---|
| the applied-tip boundary excludes the tip's own records | red | 5 tests failed |
| `tip_time` takes the last record at the height, not the first | red | 2 tests failed |
| the window boundary is off by one height | red | 2 tests failed |
| `window_tx_count` is the whole applied prefix | red | 2 tests failed |
| `push` forgets to extend the prefix sums | red | 6 tests failed |
| `pop` forgets to shrink the prefix sums | red | 1 test failed |
| `pop` forgets the running body-size sum | red | 1 test failed |
| `tx_count_before` reads one prefix too far | red | 6 tests failed |
| `getblockchaininfo` reports the record count as `size_on_disk` | red | 1 test failed |
| `earliest_window_time` takes the latest, not the earliest | red | 2 tests failed |

The first run of the audit reported **every one of these as an invalid
mutation**. The harness classified a run as a broken build by grepping for
`^error`, and `cargo test` ends a failing run with `error: test failed, to rerun
pass ...`. Every kill was being recorded as a build failure. It now matches
`error[E####]` and `error: could not compile` instead. **An audit harness that
cannot tell a red test from a broken build reports the same thing for both, and
the thing it reports is not "killed".**

The `pop` mutations initially died for the wrong reason. Dropping the prefix
`pop` left the prefix vector longer than the records, and the clamp inside
`tx_count_before` happened to read out of the stale tail. That is an accident of
which length the clamp used, not the invariant being broken. `tx_count_before`
now asserts the two are parallel, so the mutation dies on what it actually broke.

## What is not claimed

- **No G14 budget item is touched directly.** The case for the change is that an
  RPC reporting a handful of scalars should not cost time linear in chain
  length, and should not hold the block-application lock while doing it.
- **The lock hold is argued, not measured.** The benchmark measures the call, not
  contention against a concurrent `apply_block`. What is measured is that the
  work done under the lock went from 7.45 ms to 3.77 µs.
- **The fixture is synthetic.** Body sizes and transaction counts are generated,
  not sampled from a real chain; the fixture establishes the shape of the cost.
- **`size_on_disk` still reports recorded block sizes, not disk usage.** Pruning
  does not remove records, so a pruned node reports the bytes its blocks would
  occupy. That is what the fold reported too — this change is not the place to
  alter what the field means.
- **The window is still the caller's to choose.** `getchaintxstats 963124` walks
  963k records, as it does in Core. The claim is that the *default* call no
  longer does.
- **`Context::record_for_hash` is untouched.** It still scans the log linearly
  under `getblock` and `getblockheader`, which is a hotter path than either RPC
  measured here. It has a height available from the block tree and should
  binary-search the same way; that is a separate change.
