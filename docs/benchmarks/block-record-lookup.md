# Block-record lookup benchmarks

Baseline and refactor-set measurement for `Context::record_for_hash`, the
hash-to-record resolver under `getblock`, `getblockheader`, `getblockstats`,
`getrawtransaction` with a blockhash, the REST block endpoint, and
`gettxoutproof`'s explicit-hash path.

Harness: `crates/rpc/benches/blocklookup.rs`. Criterion, both arms of the
refactor set in one group over one fixture in one process, so the ratio cannot be
confounded by the rebuild and baseline drift recorded in
`docs/solutions/best-practices/criterion-bench-trust-rebuild-drift-baselines-allocator.md`.

## What was wrong

`record_for_hash` step 1 asks the block tree for the hash. The tree answers with
the height. It then scanned the block-record log linearly for the matching
`(hash, height)` pair — with the height already in hand, over a log that is
ordered by height and grows one entry per block forever.

`verifychain` calls it once per block it checks, so that RPC was quadratic in
chain length.

## What was measured

| Records | Hash at | `before_scan` | `after_search` | ratio |
|---:|:---|---:|---:|---:|
| 10,000 | tip | 12.17 µs | 39.6 ns | **307x** |
| 10,000 | middle | 6.65 µs | 37.0 ns | **180x** |
| 100,000 | tip | 415.9 µs | 50.2 ns | **8,285x** |
| 100,000 | middle | 68.8 µs | 42.5 ns | **1,620x** |
| 500,000 | tip | 3.737 ms | 46.1 ns | **81,092x** |
| 500,000 | middle | 2.104 ms | 48.8 ns | **43,127x** |
| 963,124 | tip | **7.707 ms** | **48.3 ns** | **159,569x** |
| 963,124 | middle | 3.328 ms | 48.6 ns | **68,528x** |

The new arm is flat — 37 ns to 50 ns across 96x the records — because it is a
binary search: ~20 steps at a mainnet tip.

Two lookup positions are measured because measuring one would flatter the scan in
whichever direction was chosen. A hash at the *end* of the log is what a
tip-following client asks for and is the scan's worst case; a hash in the
*middle* is what a wallet rescanning history asks for, and costs the scan half as
much. Both are reported.

## Correctness

The linear scan is the oracle. It is written out in the tests and in the
benchmark's `before` arm rather than called through the crate: it is two lines,
and an oracle that shares code with the implementation cannot disagree with it.
The scan makes no assumption about the log's ordering, which is the point — the
search assumes it is non-decreasing by height.

`record_at_height_hash_matches_the_scan_it_replaced` sweeps every height in and
around the fixture against every hash in it, including hashes at the wrong
height, which must find nothing.
`record_at_height_matches_the_scan_it_replaced` does the same for the
height-only lookup, which has to return the *first* record at a duplicated
height because that is what the scan returned. A sweep rather than a chosen
pair, because a search is wrong at its boundaries and a test that picks one pair
picks whether it visits them.

| Mutation | Expected | Result |
|---|---|---|
| the search stops at the first record of the height run | red | 3 tests failed |
| `record_at_height_hash` skips the rewind to the run head | red | 3 tests failed |
| `record_at_height` skips the rewind to the run head | red | 3 tests failed |
| `record_at_height` trusts the direct index unconditionally | red | 4 tests failed |
| `record_at_height` drops only the preceding-record guard | red | 3 tests failed |
| `record_for_hash` ignores the hash and takes the run head | red | 1 test failed |
| `block_by_height` without a tip answers the last record | red | 1 test failed |

The last row was a coverage gap, not a check. `block_by_height`'s no-applied-tip
fallback is the path a Context takes before the first tip is published, and
replacing its whole body with "the last record in the log" turned nothing red.
`block_by_height_without_an_applied_tip_reads_the_log` now covers it, and it is
the *only* test that kills that mutation.

The fixture's starting height is load-bearing rather than decoration. The
preceding-record guard in the direct-index fast path only matters when index `h`
holds a record at height `h` that is not the first at that height, and a log
starting at zero can never be in that state. The fixture starts at height 1,
which puts a duplicate at index 3 and the run head at index 2. **A fixture that
cannot reach the state a check defends against tests the check by not reaching
it.**

## What is not claimed

- **The end-to-end RPC is not measured here.** The benchmark times the lookup,
  not `getblock`, which also deserializes a body. Populating a 963k-node block
  tree — which `record_for_hash` step 1 needs — is not something this harness
  builds. What is measured is that the lookup went from 7.71 ms to 48 ns.
- **Step 2 is still linear, deliberately.** When the block tree has no node for
  the hash there is no height, so there is nothing to search on. That path exists
  for cache-only fixtures and for blocks seen before a checkpoint restore.
- **The fixture is synthetic**, and its hashes are height-derived. It establishes
  the shape of the cost.
- **No G14 budget item is touched directly.** The case is that resolving one
  block record should not cost time linear in chain length.
