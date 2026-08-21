# `size_on_disk` reports bytes on disk

Not a performance change. A correctness one, found by asking what Bitcoin Core
compatibility actually obliges — the RPC surface — rather than what it looks like
internally.

## What was wrong

`getblockchaininfo.size_on_disk` was the sum of `body_size` over every block
record: the serialized length of every block the node has seen.

Pruning does not remove block records. `NodePruneService::prune_to_height`
(`crates/node/src/state.rs`) clears each pruned record's cached `block_hex` and
leaves the rest of the record in the log — `body_size` included. **So the number
could not move.** A node that had just deleted hundreds of gigabytes went on
reporting them, under the one field an operator reads to check that pruning
worked.

It was wrong in the other direction too, for unpruned nodes: a sum of serialized
block lengths is not a disk measurement. It excludes undo data and per-file
overhead entirely.

Bitcoin Core answers the same field from the files:

```cpp
uint64_t BlockManager::CalculateCurrentUsage()
{
    uint64_t retval = 0;
    for (const CBlockFileInfo& file : m_blockfile_info) {
        retval += file.nSize + file.nUndoSize;
    }
    return retval;
}
```

`PruneOneBlockFile` resets a pruned file's entry, so Core's figure falls when
files go.

## What replaced it

`FlatFileBlockStore::disk_usage()` — the bytes this node's block files actually
occupy — reached through `BlockBodySource::disk_usage()`, which
`getblockchaininfo` prefers over the record sum.

The record sum stays as the fallback for a context with no durable storage
behind it. That is every test fixture and nothing else.

### Why a maintained figure rather than a walk

Measuring means one `stat` per block file — thousands at a mainnet-sized chain,
which is the same multi-millisecond cost `docs/benchmarks/chain-info-fold.md`
had just removed from this call. Putting a directory walk back into
`getblockchaininfo` would have undone that.

So the figure is maintained, the way Core maintains `m_blockfile_info`: seeded by
walking the directory once at open, then adjusted by the two operations that
change it — `append` adds a framed record, `delete_file_if_not_current`
subtracts a whole file. Every deletion in the workspace funnels through that one
method (`crates/pruning/src/lib.rs:87`), so there is no second path to forget.

`disk_usage` checks the running figure against a real walk under
`debug_assert`, and the seeding walk and the running figure are held to the same
definition of "block file" — a mismatch there would make the guard fire on a node
with nothing wrong with it.

## How it was checked

`disk_usage_follows_the_files_through_appends_and_deletion` compares the figure
against a fresh directory walk at every step, so it is pinned against the files
rather than against itself.

`pruning_a_block_file_reduces_the_reported_disk_size` is the end-to-end one, and
it asserts **both halves**: the store's figure falls by exactly the file that was
deleted, *and* the block-record sum does not move at all. The second assertion is
what makes the first worth having — it is the defect, written down.

| Mutation | Expected | Result |
|---|---|---|
| deleting a file does not reduce the usage figure | red | 2 tests failed |
| appending does not raise the usage figure | red | 2 tests failed |
| a reopened store starts from zero | red | 2 tests failed |
| `getblockchaininfo` ignores the store and sums the records | red | 1 test failed |
| the directory walk counts every file, not just block files | red | 1 test failed |

Baseline and restored green.

The last row **survived the first pass**. No test had a stray file in the blocks
directory, so the filter that distinguishes `blkNNNNN.dat` from anything else was
never exercised. It is not decoration: `append` counts framed records only, so a
seeding walk that counted every directory entry would seed a number the running
figure can never match, and `disk_usage`'s guard would fire on a healthy node the
first time a backup copy or an editor scratch file landed there.
`disk_usage_counts_only_block_files` closes it.

One note on the audit itself: a broken build is classified by `error[E####]` /
`error: could not compile`, never by a bare `^error`. `cargo test` ends a
*failing* run with `error: test failed`, and matching that once reported every
kill in this campaign as an invalid mutation.

## What is not claimed

- **Undo data is still not counted.** Core sums its undo *files* into the same
  number. Here undo lives in the key-value store (`ColumnFamily::UndoData`), not
  in files this store can see, so it is absent from the figure. That is a
  remaining divergence from Core, now a smaller one than the whole-chain
  overcount it replaces.
- **No performance claim.** The read stays O(1); nothing here was measured for
  time.
- **`core_compat.rs` checks key sets, not values.** It asserts `size_on_disk` is
  present, which it was throughout — a schema check cannot catch a field that
  means the wrong thing. The rest of the RPC surface has not been audited for
  value semantics, and this is one data point suggesting it should be.
