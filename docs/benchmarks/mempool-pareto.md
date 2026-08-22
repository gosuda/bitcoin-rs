# Mempool priority-index benchmarks

Baseline and refactor-set measurement for `ParetoFront`, the mempool's fee
priority index. `crates/mempool` had no benchmarks before this page, so no number
existed for it.

Harness: `crates/mempool/benches/pareto.rs`. Criterion, both arms of the refactor
set in one group over one fixture in one process, so the ratio cannot be
confounded by the rebuild and baseline drift recorded in
`docs/solutions/best-practices/criterion-bench-trust-rebuild-drift-baselines-allocator.md`.

## What was wrong

`ParetoFront::insert` held its keys in a flat `TinyVec` and, on every insert, did
a linear `remove` followed by `sort_by` over the whole index. Filling an index of
`n` entries was therefore `O(n^2 log n)`.

This is not an idle path. `Mempool::insert_entry` — the path that accepts a
transaction from a peer — calls `recompute_all_metadata`, which discards the
priority index and re-inserts every entry. So the quadratic cost was paid once
per accepted transaction, by anyone able to put transactions in the mempool.

## What was measured

| Entries | `before_sorted` | `after_ordered` | ratio |
|---:|---:|---:|---:|
| 1,000 | 2.064 ms | 151.0 µs | **13.7x** |
| 4,000 | 45.65 ms | 626.2 µs | **72.9x** |
| 16,000 | 464.7 ms | 3.046 ms | **152.6x** |
| 50,000 | **4.497 s** | **10.45 ms** | **430.4x** |

The ratio grows with `n` because the two arms have different complexity, which is
the claim. Across the 1,000 → 50,000 span (50x the entries) the old arm takes
2,183x longer — a measured exponent of **1.97**, i.e. `n^2`. The new arm takes 69x
longer over the same span against the 78x that `n log n` predicts.

Fee rates are spread by a multiplicative hash rather than ascending with the
insertion order. An index fed entries already in priority order never has to
reorder anything, and would have measured the best case of the arm being
replaced.

## What replaced it

An ordered set keyed by the priority comparison, plus a map from entry id to the
key currently indexed for it. Insert and remove are both `O(log n)`.

The id-to-key map is not redundant: removals arrive as an entry id while the
ordered set is keyed by priority, so without it a removal would have to search
the set — reintroducing the linear scan.

The final tiebreak on entry id in the ordering is load-bearing for the same
reason it was cosmetic before. The index is now a *set of keys*: two entries
whose keys compared equal would collapse into one, and a transaction would
silently vanish from the priority index. Entry ids are unique, so no two distinct
entries can compare equal. `entries_with_identical_priority_fields_are_all_retained`
pins it.

## Closing the outer quadratic

Replacing the index was not enough. `Mempool::insert_entry` called
`recompute_all_metadata`, which walked every entry on every insert, and then
consulted `total_vsize()`, which folded every entry again. With the index fixed
and nothing else changed, `insert_entry` still measured an exponent of **2.17**.

Two further changes removed both terms:

**The metadata refresh is incremental.** Linking one transaction into the spend
graph changes package totals for its transitive ancestors, itself, and its
transitive descendants — and nothing else. An entry `x` outside that set gains no
new ancestor, because `x` is not a descendant of the seed; and gains no new
descendant, because every new path runs through the seed, which would put `x`
among its ancestors. So `insert_entry` and `remove_entries` now recompute exactly
that closure. Its size is bounded by the ancestor and descendant *policy* limits
— 25 each by default — not by the number of entries in the pool.

The closure is taken *after* the entry enters the spend indexes on an insertion,
because a transaction can arrive after something that already spends its outputs;
and *before* the removal on a removal, because a removed entry's ancestors cannot
be walked once it is gone.

**`total_vsize` and `aggregate_fees` are running sums.** Both were folds over the
whole pool. `insert_entry` consults `total_vsize()` on every acceptance to decide
whether the pool is over its size limit, so that fold alone made insertion
quadratic. They are now maintained by the mutation methods and guarded by
`debug_assert`s against the folds they replaced.

| Transactions | before | after | ratio | per transaction, after |
|---:|---:|---:|---:|---:|
| 200 | 2.572 ms | 373.0 µs | **6.9x** | 1.87 µs |
| 800 | 51.27 ms | 1.760 ms | **29.1x** | 2.20 µs |
| 3,200 | 1.057 s | 7.079 ms | **149.3x** | 2.21 µs |
| 12,800 | *not measurable* | 37.87 ms | — | 2.96 µs |
| 51,200 | *not measurable* | **211.5 ms** | — | **4.13 µs** |

The last two sizes could not be measured before: at an exponent of 2.17, 51,200
transactions would have taken around seven minutes per sample. The per-transaction
cost is now nearly flat — 1.87 µs to 4.13 µs across 256x the entries — and the
measured exponent over the final leg is **1.24**, which is `n log n` for the fill
and therefore about `O(log n)` per accepted transaction.

Extrapolating from 51,200 to a Core-default mempool (~10^5 transactions) puts a
full fill near **half a second**, against the ~30 minutes the previous revision of
this page projected.

## A defect fixed on the way

`prioritise` applied its fee delta to each descendant's `ancestor_fee` by hand and
then never reindexed those descendants, so a descendant kept the priority key it
had before its ancestor was bumped. Since `prioritisetransaction` exists to move
transactions in the miner's template, leaving descendants ranked on the pre-bump
figure defeated it for exactly the packages it was aimed at. The three hand-applied
delta loops are now one call to the same refresh an insertion does, which both
fixes the staleness and deletes the duplicate accounting.

## Correctness, and how the tests were checked

The flat-vector index is retained whole as `SortedParetoFront`: it is the oracle
the equivalence tests compare against and the benchmark's `before` arm. Five
tests cover the set in `crates/mempool/tests/pareto_ordering.rs`, and the two
equivalence tests compare the *whole* index rather than a prefix — a `top_n(10)`
check passes while everything below the tenth entry is misordered, and
`mining::policy` reads the whole index via `top_n(len())`.

The incremental refresh is checked the same way: `recompute_all_metadata` is kept
under `cfg(test)` as the oracle. Nothing in the pool calls it any more, so
production cannot drift away from it. Each equivalence test drives the
incremental path, then runs the full recompute, and asserts nothing moved.

The tests were then audited by mutation:

| Mutation | Expected | Result |
|---|---|---|
| a replacement leaves the stale key in the ordered set | red | 2 tests failed |
| the ordering drops its entry-id tiebreak | red | 3 tests failed |
| the ordering puts the lowest fee rate first | red | 3 tests failed |
| `remove` forgets the ordered set | red | 2 tests failed |
| the refresh closure names only the seed | red | 5 tests failed |
| the closure forgets descendants | red | 3 tests failed |
| the closure forgets ancestors | red | 2 tests failed |
| a removal takes its closure after the removal | red | 1 test failed |
| eviction skips the priority reindex | red | 3 tests failed |
| descendant totals count only the entry itself | red | 5 tests failed |
| the refresh skips the priority reindex | red | 2 tests failed |
| an insertion forgets the running vsize total | red | 29 tests failed |
| a removal forgets the running fee total | red | 1 test failed |
| `prioritise` forgets the running fee total | red | 1 test failed |

The last two **survived the first pass**, and that is a finding rather than a
footnote. `total_vsize` and `aggregate_fees` each guard themselves with a
`debug_assert` against a fold of the entries they summarize — but a guard only
fires when something calls it. `insert_entry` consults `total_vsize()` on every
acceptance, so its bookkeeping was covered by accident, and the 29 failures above
are that accident. `aggregate_fees()` is only reached through `stats()`, and no
test called it after a removal or a fee bump, so deleting the bookkeeping in both
of those paths turned nothing red. `running_totals_track_inserts_removals_and_prioritise`
now calls both accessors after every kind of mutation and compares against an
independent fold, so the check survives a release build where the `debug_assert`s
are compiled out.

The audit found a real defect in the tests themselves. `SortedParetoFront`
originally shared `ParetoKey`'s `Ord` with the replacement, which looked tidy and
made the oracle worthless: under the reversed-ordering mutation both
implementations agreed with each other, so both equivalence tests stayed green
while the index was ordered backwards. Only `pool::tests::prioritise_reorders_priority_index`
caught it. The oracle now keeps its own verbatim copy of the comparison, and the
same mutation kills all three ordering tests. **An oracle that shares code with
the implementation cannot disagree with it.**

A second review pass found a defect the first audit could not have caught, because
the audit itself was reading a coin flip. `Mempool::by_txid` is a `HashMap`, so its
iteration order is randomized per process. Two of the tests above picked their
subject out of it — `victims.get(3)` and `by_txid.keys().next()` — and therefore
removed or bumped a *different* transaction on every run. Rebuilding the
"a removal takes its closure after the removal" mutant and running the binary 40
times put the row above at **36 red out of 60**: the mutation was reported killed
because the run that happened to be recorded had drawn a victim that exposed it.

Every subject is now addressed by entry id, which is the slab index and so follows
insertion order, and the removal test removes *each* of the six fixture entries in
turn rather than one. Re-run at 40 executions per mutant, every row above is now
40/40 red and the baseline 0/40. The exhaustive sweep also reaches a case no single
chosen victim could: removing `leaf` takes the fan-in `joined` with it while
`sibling` — `joined`'s *other* parent — survives and has to drop it from its
descendant totals.

`eviction_during_insertion_leaves_metadata_a_rebuild_agrees_with` closes the other
gap the pass found. `enforce_size_limit` is a `remove_entries` caller reached from
inside `insert_entry`, removing packages the caller never named, and no test drove
the refresh through it. It is now among the tests that kill both the
forgets-ancestors and the skips-the-reindex mutations.

**A test that chooses its subject from a `HashMap` is a different test on every
run**, and a mutation audit run once against one cannot distinguish "killed" from
"killed this time".

One measurement artefact, recorded because it briefly read as a coverage gap:
`cargo test -p <crate>` stops at the first failing target by default, so a
mutation that fails the lib suite never runs the integration suites. The
reversed-ordering mutation looked as though it killed only one test until it was
re-run against `--test pareto_ordering` directly.

## What is not claimed

- **No G14 budget item is touched directly.** The case for the change is that
  transaction acceptance should not cost time quadratic in mempool size.
- **The fixture is synthetic.** Fees and sizes are generated, not sampled from a
  real mempool; it establishes the shape of the cost, not its value on real
  traffic.
- **The half-second figure is an extrapolation** from an exponent measured over
  200-51,200 transactions, quoted to say the quadratic is gone, not as a
  prediction of behaviour on a real mempool. See
  `docs/solutions/best-practices/small-window-benchmarks-do-not-predict-at-scale-throughput.md`.
- **The ancestor and descendant walks are bounded by policy, not by the code.**
  A node configured with `max_ancestors`/`max_descendants` in the millions would
  make the refresh closure large again. The claim is that the cost no longer
  depends on *mempool size*, which is what an attacker controls.
- **`Mempool::entries` is still a public field.** The running totals assume every
  mutation goes through the pool's own methods, which is true of every caller in
  this workspace today. The `debug_assert`s are there because that is an
  assumption, not a guarantee.
