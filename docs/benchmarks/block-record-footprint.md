# Block-record footprint

Why the block header stopped being stored in `BlockRecord`, and the evidence that
it was safe to stop.

**There is no benchmark on this page.** The claim is footprint, not time:
`size_of::<BlockRecord>()` times the number of records. It is pinned by
`a_record_costs_88_bytes_and_carries_no_header` rather than measured at runtime,
and it should not be quoted as an observed RSS drop.

## The cost

The node holds one `BlockRecord` per applied block for the life of the process,
and nothing removes one. The record's own footprint is therefore the cost, once
per block on the chain — ~963k at a mainnet tip.

| Revision | per record | at a mainnet tip |
|---|---:|---:|
| header as a hex `String` | 264 B + 1 allocation | — |
| header as an inline `[u8; 80]` (#86) | 168 B | −88 MiB |
| header not stored at all | **88 B** | **−73.5 MiB** |

#86 also corrected the survey in #84, which had put its own step at 160 B/block
by counting the heap `String` as removed without counting the 64 bytes the inline
array adds back. This page's figure is `88 → 168` measured by `size_of`, not
derived from field widths.

## Why the header did not need storing

The `BlockTree` holds a full `bitcoin::block::Header` on every node
(`crates/chain/src/node.rs:58`). Storing it again in the record stored it twice.

The question that made this a design problem rather than a refactor: **can the
record log hold a block whose header the tree does not have?** If it can,
dropping the field turns a working `getblock` / `getblockheader` / REST answer
into an empty one. Both `Context::record_for_hash` step 2 and the singleton
fallback in `rest.rs` exist for exactly that case, and their comments describe it
as a real state — "a block seen before a checkpoint restore".

It is not reachable in a running node:

- **The header enters the tree before the record enters the log.** `apply_block`
  inserts via `applied_header_tip` (`crates/node/src/apply.rs:2338-2343`) and
  pushes the record afterwards (`:2354`), through the same
  `Arc<RwLock<BlockTree>>`.
- **The tree never drops a node.** The only `Slab` operation is `insert`
  (`crates/chain/src/tree.rs:604`). `invalidate_subtree` (`:629`) flips `status`
  and clears the height index, never the slab. The `"pruned out of BlockTree"`
  comment in `crates/pruning/src/undo_pruner.rs` is about the redb column family,
  not this tree.
- **The log is not durable.** `crates/node/src/state.rs:1061` builds it empty on
  every open, so a record cannot survive a restart into the state its own doc
  comment describes.
- **A restore rebuilds the tree from genesis, contiguously.** `read_headers`
  (`crates/node/src/checkpoint.rs:242-329`) asserts `node.height == height` from
  index 0 upward; the writer requires a genesis-rooted chain (`:188-197`).
- **`Context::add_block` has no non-test callers**, and every
  `BlockRecord::from_block*` call outside `applied_block_record` is a test or a
  bench.

`Context::header_record` (`context.rs:704`) was already the precedent: it builds
a record whose header comes from `tree.node_by_hash(hash)`, an O(1) hash lookup.

One of these needed checking rather than assuming. A reorg calls
`invalidate_subtree`, and if `lookup` filtered on node status then an
invalidated block's header would become unreachable while its record was still
in the log — a hole straight through the argument. `lookup` (`tree.rs:146-154`)
matches on hash alone, and `by_hash` is only ever `insert_unique`d (`:615`), so a
hash resolves for the life of the process whatever happens to the branch it is
on. Reorged-out blocks in fact answer *better* than before: the record is popped
on disconnect, but the tree node stays, so `getblockheader` still serves a
header.

### The ordering is enforced, not just argued

Everything above rests on one ordering: the header is in the tree before the
record is in the log. Nothing checked it. The push site now does:

```rust
debug_assert!(
    handles.block_tree.read().node_by_hash(block_hash).is_some(),
    "block {} is entering the record log with no block-tree node; \
     its header would be unrecoverable",
    block_hash.to_string_be()
);
```

The tree lock is free at that point — `applied_header_tip` released its write
guard before returning — and the check is one hash-table lookup, compiled out of
release builds.

It is not a lone test. Moving the record push above the tree insert, which is
exactly the mistake it defends against, fails **52 node tests**, each on this
assertion naming the block that would have lost its header. Every node test that
applies a block now exercises the invariant.

This is still weaker than Bitcoin Core, where `CBlockIndex` holds the header
*and* the payload facts in one structure, so "a record with no index entry" is
not representable. Here they are two structures held in step by an ordering.
Merging them is the Core-shaped end state and a separate change.

## What changed

Every constructor leaves `header: None`. `header_record` is the only thing that
produces one, from the tree node — so the tree is the single source of truth for
what a block's header is.

`record_for_hash` step 1 resolves the tree node first and then looks for a cached
record with the same hash and height. It used to return that cached record
verbatim, which would now answer with no header at all. It splices the tree's
header into the cached record instead. **This costs no extra lock**:
`header_record` has already taken and released the tree guard, and the header it
produced outlives it.

Consumers are unchanged. All four read through `header_bytes()` / `header_hex()`,
which #86 introduced: `handlers/chain.rs:286`, `:291`, `decode_header` at `:913`,
and `rest.rs:209`.

### The boxing is the saving

`Option<[u8; 80]>` costs its full 80 bytes in every record **even when it is
`None`**. Emptying the log's records while leaving the array inline would have
saved nothing at all. `Option<Box<[u8; 80]>>` makes an absent header cost 8
bytes, and allocates only where one is produced — once per RPC answer rather than
once per block.

#86 considered and rejected `Option<Box<[u8; 80]>>` on the grounds that it "lands
at the same 168 bytes total while keeping the per-block allocation". That was
correct while every record carried a header. It stops being correct once none of
them do, which is what this change makes true.

## Behaviour that changed

- **`rest.rs`'s singleton fallback has no header to serve.** Reaching it means
  the tree has no node for the hash, so there is none to be had. It now yields an
  empty result. The code and its comment are left in place: removing an
  unreachable fallback is a separate claim from removing a stored field.
  `headers_for_a_record_the_tree_does_not_know_serve_nothing` pins the outcome so
  it is recorded rather than silent.
- **Three `getblock` tests were built from a record alone.** They now seed the
  tree as well, through a `seed_block` helper that does what `apply_block` does —
  header into the tree, record into the log. A record on its own was never a
  node's state; those fixtures were asking `getblock` to answer from half of it.

## Mutation audit

Run serially — a concurrent audit editing the same file invalidated a run earlier
in this campaign. A broken build is classified by `error[E####]` /
`error: could not compile`, never by a bare `^error`: `cargo test` ends a
*failing* run with `error: test failed`, and matching that reported every kill as
an invalid mutation once already.

| Mutation | Expected | Result |
|---|---|---|
| `record_for_hash` drops the header splice | red | 4 tests failed |
| `header_record` does not read the header off the tree node | red | 6 tests failed |
| `applied_block_record` stores the header again | red | 1 test failed |
| `from_block_bytes` stores the header again | red | 4 tests failed |
| the header is un-boxed | red | 1 test failed |
| the record is pushed before the header reaches the tree | red | 52 tests failed |

Baseline and restored: green across all 14 test targets.

The third row is killed by `applied_block_record_matches_rpc_constructors`, which
predates this change. It asserts that the node's record builder and the rpc
constructors agree; now that both must agree on *no header*, it guards the memory
claim on the node side without having been written for it.

The last row is killed only by the `size_of` assertion, which is the point of
having one: un-boxing compiles, passes every behavioural test, and silently
returns 80 bytes per block to the heap.

## What is not claimed

- **No RSS measurement.** The figure is `size_of` × record count. No harness in
  this workspace attributes resident memory to the block-record log.
- **No G14 budget item is touched directly.** Tip RSS ≤ 16 GiB is the budget this
  is adjacent to; 73.5 MiB is headroom against it, not a fix for it.
- **The tree's own growth is untouched, and this raises its stakes.** Nothing
  removes a `BlockTree` node, and the tree is now the single source of every
  header. That is a separate candidate, and a more valuable one than it was
  before this change.
- **`record_for_hash` step 2 and the `rest.rs` fallback are still there.** The
  evidence above says they are unreachable in production; acting on that is a
  separate change.
