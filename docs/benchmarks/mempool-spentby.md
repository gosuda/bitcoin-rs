# `getrawmempool true`: answering `spentby` from the spend index

`getrawmempool true` renders one entry object per mempool transaction, and each
of those carries a `spentby` list — the in-pool transactions that spend one of
this transaction's outputs.

The handler answered each list by walking **every other entry's inputs**. One
response therefore cost `O(entries × inputs in the pool)` comparisons, plus an
uncached `Transaction::compute_txid()` — a double-SHA256 over the full
serialized body — for the key of every entry and again for every spender found.
All of it ran while holding `ctx.mempool.read()`, the lock transaction
acceptance needs to make progress.

`Mempool::spending` is a `BTreeSet<(OutPoint, EntryId)>` that already indexes
exactly this relation. `Mempool::spender_txids` reads it: for each of the
transaction's own outputs, a range scan over the index.

## Measured

Refactor-set benchmark, `crates/mempool/benches/spentby.rs`. Both arms run in
one Criterion group over one identical pool. `before_scan` is the scan, written
out in the benchmark rather than shared with the code it is compared against;
`after_index` is the shipped path. The two arms are asserted to render identical
output before either is timed.

The fixture is `n/2` independent parent → child packages, so the spend graph is
shallow and the measured cost is *finding* the spenders rather than walking a
deep package.

| pool entries | `before_scan` | `after_index` | ratio |
| --- | --- | --- | --- |
| 512 | 1.6492 ms | 237.48 µs | 6.9× |
| 2048 | 54.205 ms | 3.2104 ms | 16.9× |
| 4096 | 167.47 ms | 4.8303 ms | 34.7× |

Criterion median estimates. WSL2 Ubuntu on Windows 11, `-j4`, `--sample-size 10
--warm-up-time 1 --measurement-time 3`.

**The ratio is the point, not any one row.** The claim is about the shape of the
curve, which is why the group is parameterised by pool size:

- `before_scan` grows **3.1×** from 2048 to 4096 entries — quadratic.
- `after_index` grows **1.5×** over the same doubling.

A single measurement at a single size could not tell those apart, and a
figure quoted at 512 entries (6.9×) would understate what a real mempool pays.
Mainnet mempools run tens of thousands of transactions deep; 4096 is where the
harness stops, not where the curve does.

## What this does not measure

Only the `spentby` rendering. The rest of the verbose response — fee fields,
ancestor and descendant counts, JSON encoding — is unchanged, and the per-entry
package walks that produce `descendantcount` are bounded by the ancestor and
descendant policy limits rather than by pool size, so they are not part of this
curve.

## The cached txid

`MempoolEntry` now stores its `txid`, hashed once in `MempoolEntry::new`.
rust-bitcoin's `compute_txid()` caches nothing, so every call re-serializes and
re-hashes the transaction. Bitcoin Core hashes once in the `CTransaction`
constructor and keeps the result (`const Txid hash`); this is the same decision,
made at the point where the transaction becomes immutable pool state.

The entry owns an `Arc<Transaction>`, which cannot be mutated behind the pool's
back, so the field cannot drift — and a test asserts it against a recomputation
rather than assuming it.

This is folded into the `after_index` arm above; it is not measured separately.

## Behaviour

Identical output, with one narrowing: the index is keyed by the exact
`OutPoint`, so a child spending a `vout` the parent does not have is no longer
reported. That cannot happen for a transaction the pool would accept, and it is
the relation Bitcoin Core tracks — `mapNextTx` is keyed the same way.

Ordering is preserved: `spentby` is still rendered in txid order. The spend
index answers in insertion order, so the test fixture deliberately inserts the
root's two spenders highest-txid-first, making the two orders opposite. Dropping
the sort is then visible; with the fixture inserted in txid order already it was
not, and a mutation removing the sort survived the first audit because of it.
