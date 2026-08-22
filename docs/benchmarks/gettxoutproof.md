# `gettxoutproof` benchmarks

Baseline and refactor-set measurement for the one RPC handler that did unbounded
work per call. `crates/rpc` had no benchmarks at all before this page, so no
number existed for it.

Harness: `crates/rpc/benches/txoutproof.rs`. Criterion, both arms of the refactor
set in one group over one fixture in one process, so the ratio cannot be
confounded by the rebuild and baseline drift recorded in
`docs/solutions/best-practices/criterion-bench-trust-rebuild-drift-baselines-allocator.md`.

The arms differ by whether the `Context` carries a txindex. `before_scan` is the
pre-index path: no `tx_index`, so the handler walks every block record, loads
each body, deserializes it and hashes every transaction in it. `after_index` is
the same call on the same fixture with a populated `Indexer<RocksDbStore>`
behind a `TxIndexQuery`.

That query implementation is the benchmark's, not production's: the real one is
`TxIndexQueryEngine` in `bitcoin-rs-node`, which `crates/rpc` cannot depend on
without a cycle. The bench's stands in for it over the *same* RocksDB index and
the *same* flat block files, so the measured cost is a real row lookup plus a
real body read rather than a `HashMap` hit — but it resolves through
`Indexer::resolve_tx_with_height`, which fetches the whole candidate block where
production reads only the bytes a stored `TxPosition` names. **The `after` arm is
therefore slower than production**, which puts the measured win on the
conservative side of the real one.

Block bodies are served from a real `FlatFileBlockStore`, the same open /
`fstat` / seek / read sequence production takes. Serving them from an in-memory
map would leave the syscalls out entirely, which is the mistake
`docs/benchmarks/index-read-path.md` records having made and corrected.

## What was measured

Two fixture shapes, because one cannot answer the question. With 8 tiny
transactions per block the per-record cost is the file open and read, which
understates a real chain; with 500 it is the deserialize-and-hash of the body,
which is what a mainnet block actually costs. Block counts differ so each shape
stays inside a Criterion run.

RocksDB-backed index, flat block files, machine otherwise idle — the mainnet IBD
sharing this host was stopped first and the run waited for writeback to drain.

| Shape | Arm | `first_block` | `last_block` |
|---|---|---:|---:|
| 2,000 blocks x 8 tx | `before_scan` | 46.485 µs | **75.383 ms** |
| | `after_index` | 95.186 µs | **32.556 µs** |
| | ratio | **0.49x** | **2,315x** |
| 200 blocks x 500 tx | `before_scan` | 611.94 µs | **74.849 ms** |
| | `after_index` | 834.84 µs | **780.85 µs** |
| | ratio | **0.73x** | **95.9x** |

Two positions, because the scan is position-dependent and the index is not.

**These numbers replace an earlier revision's and are not comparable to it.**
That revision was measured before this host's WSL memory allocation was cut from
36 GB to 12 GB, and the `before_scan` arm — whose code did not change between the
two runs — got 3.6x slower across the cut. Absolute figures here describe this
host under that allocation; only ratios measured *within* a run mean anything,
which is why both arms share one fixture in one process.

**The index arm is slower in the scan's best case, and that is a real cost, not
noise.** It runs 48.7 µs longer at 8 transactions per block and 222.9 µs longer
at 500. That is what consulting an index costs — a row lookup and a candidate
block load — and it does not go away, because the proof still needs the block
loaded either way. Part of it is the bench's own adapter loading whole candidate
blocks where production reads a positioned range, as noted above.

What makes it acceptable is what "the scan's best case" means: the scan walks
from height 0, so it wins only when the wanted transaction is in the *first block
on the chain*. On any real chain that case does not arise. The case that does
arise is the one the second column measures, where the index arm stays inside
33–95 µs / 780–835 µs regardless of position while the scan grows without bound.

One thing this run does not explain: within the index arm, `first_block` is
slower than `last_block` (95.2 vs 32.6 µs at 8 tx/block), which position alone
should not cause. Whatever it is — measurement order, index cache state, prefix
row counts — it is bounded by tens of microseconds and does not touch the
conclusion, but it is recorded rather than smoothed over.

## Extrapolating to a real chain

The scan is linear in the number of block records. Per record it costs **37.69 µs**
at 8 transactions per block and **374.2 µs** at 500. Against the 963,124 records a
mainnet node holds at the time of writing, that brackets one `gettxoutproof` call
at **36 seconds to 6 minutes** of unbounded work.

Real blocks range from a single coinbase to a few thousand transactions, so
neither shape is the chain and neither bound is a prediction. See
`docs/solutions/best-practices/small-window-benchmarks-do-not-predict-at-scale-throughput.md`
for why neither number should be scaled naively.

Note also what the fixture cannot show: at 200-2,000 records, `Context::block_by_height`
resolves a record by linear scan in negligible time. At 963k records that scan is
itself O(chain), and the index arm pays it too. That is fixed separately, by the
binary search in `record_at_height`.

## What is not claimed

- **No latency budget is touched.** `gettxoutproof` is not a G14 budget item. The
  case for the change is that one authenticated RPC call should not do O(chain)
  work and evict every cache on the node while it does.
- **The fixture is synthetic.** It is not a mainnet corpus; it establishes the
  shape of the cost, not its absolute value on real data.
- **Only the no-block-hash path changed.** Called with an explicit `blockhash`,
  the handler does what it always did, and that path is not in this benchmark.

## Correctness, and how the tests were checked

The scan is retained whole as `proof_from_block_log`: it is the fallback whenever
the index cannot answer, and the oracle the equivalence tests compare against.
Eleven tests cover the set — nine in `crates/rpc/src/handlers/tx.rs`, two in
`crates/node/src/txindex_worker_query_tests.rs`.

The tests were then audited by mutation, because a green suite proves nothing
until it is shown to fail when the behaviour it claims to pin is removed:

| Mutation | Expected | Result |
|---|---|---|
| a failing index decides the answer instead of falling back | red | the named test failed |
| only one arbitrary wanted txid is probed | red | 3 tests failed |
| a candidate block is trusted without holding every wanted txid | red | the named test failed |
| the scan holds the block-log read lock across every body load | red | the named test failed |
| `transaction_height` never resolves a height | red | the named test failed |
| `transaction_height` answers the tip height without proving the transaction is there | red | the 2 predicted tests failed |

One mutation was **invalid** and is recorded as such rather than as a pass:
replacing the index-error path's `return None` with `continue` left every test
green, but it does not remove the property those tests name — both keep the call
answerable from the scan, and `continue` is arguably the better behaviour. It was
reformulated as "a failing index decides the answer", which is the property, and
that one goes red.

The audit also found two real coverage gaps, both fixed here:

- `falls_back_when_the_indexed_block_lacks_some_wanted_txids` pinned the outcome
  but not the mechanism. Its stub index answered the same height for every probe,
  so "keeps probing after a failed candidate" and "gives up on the first" both
  landed in the fallback scan, which answers either way. Counting probes
  separates them: `keeps_probing_after_a_candidate_block_fails_verification`.
- `falls_back_to_the_scan_when_the_index_errors` asserted only that *some* string
  came back. It now compares against the scan's own answer, so a failing index
  cannot decide what the answer is — and it runs over all three `TxQueryError`
  variants rather than one.
