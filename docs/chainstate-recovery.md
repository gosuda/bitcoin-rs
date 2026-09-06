# Chainstate crash recovery

The node keeps one incrementally maintained durable chainstate root. A restart
reads that root, checks the segment ranges it references, and resumes from it.
There is no periodic full checkpoint, no separate recovery journal to replay,
and no checkpoint worker. The owner is `crates/chainstate`; the normative
clauses are in [contracts/recovery.md](contracts/recovery.md).

## Durable root

The authoritative record is `DurableHead`:

| Field | Meaning |
| --- | --- |
| `format_version` | The durable format identity; refused when it differs from the binary's `CURRENT_SCHEMA` |
| `commit_id` | Monotonic across connects and disconnects; the recovery identity |
| `tip_hash`, `height` | The active tip; height can decrease, `commit_id` never does |
| `chain_tx_count` | Cumulative transaction count at the tip |
| `block_segment_end`, `undo_segment_end` | Segment cursors (file, offset, frame version) bounding the body and undo bytes the root references |

The head is persisted in the same atomic named-family storage batch as the
final coin-record updates for its block. Storage cannot expose a new head with
old coins or new coins with an old head: at every persistence boundary the
backend recovers either the previous root or the whole proposed root.

Undo records are keyed by height and block hash. A record from an abandoned
branch cannot replay against a different block at the same height.

## Ordered commit protocol

Every connect or disconnect, and every bounded verified prefix during initial
block download, follows one order:

1. Acquire the chain-transition reservation, then close the mempool
   chain-change fence (odd generation). Admission and mixed reads stop here.
2. Build exact forward and undo facts without mutating the public stable view.
3. Append the body and undo frames to their segments.
4. Sync the segment files and any newly created directory entries.
5. Apply one atomic batch containing the coin updates, metadata, and the new
   `DurableHead`, then wait for the backend's documented durable completion.
6. Feed the committed chain update into the mempool's canonical lifecycle.
7. Publish the stable even generation.
8. Notify best-effort consumers (relay, index wake, ZMQ, observers) in contract
   order, outside all domain locks.

A durable head never references body or undo bytes that were not synced
first. `submitblock` on a live node returns success only after step 5
completes; an I/O failure in any step returns failure and leaves the fence
closed until explicit recovery. No guard destructor reopens the fence after an
error.

During initial block download a bounded verified prefix may share one batch.
Only committed prefixes are published; a failed first or middle block in the
window prevents publication of everything after it.

## Restart outcomes

| Observed state | Startup action |
| --- | --- |
| Root readable, referenced segment ranges present and framed | Install the root, advance the process epoch, initialize coherent views, start optional workers asynchronously |
| Bytes in a segment beyond the root's cursor | Ignore them. An orphan append tail is never authoritative; neither file length nor a decodable frame promotes a root |
| Backend reports an unresolved batch | Resolve by `commit_id`: the storage engine yields either the previous root or the whole proposed root, never a mix |
| Root references a missing or corrupt committed range | Fail closed with a corruption diagnosis and an explicit recovery or revalidation instruction; never silent promotion to an older frontier |
| `format_version` differs from `CURRENT_SCHEMA` | Refuse to open with `incompatible_schema`; see Schema changes below |
| Root durable but publication never ran before the crash | Recover the same coins and tip from the root; the volatile publication state is rebuilt from it |

Recovery is positional: it reads the root and the retained bodies and undo it
names. It does not depend on an append log, a checkpoint export, or any
optional projection. An optional index, estimator, or discovery file that is
missing, corrupt, or lagging is reported through its owner's state and never
blocks authoritative startup.

## Reorg behavior

A reorg streams tip-to-fork in bounded chunks: each disconnected block applies
its exact inverse from the undo record and commits a new root through the same
ordered protocol, so `commit_id` advances on every disconnect. Every
intermediate committed ancestor is a valid restart point; a crash mid-reorg
resumes best-chain selection from the last durable root without pretending the
whole reorg was one filesystem transaction.

A fork below the retained undo range cannot be represented and fails closed:
the node reports the missing range and requires explicit archive input or
fresh replay. Pruning operates only on segments whose whole contents lie below
the durable root's retention promise; open readers and bounded recovery
operations hold leases that pruning honors.

## Degraded modes

- A storage fault during steps 3 to 5 stops that block before the durable
  root changes. The fence stays closed, the failure is logged and counted, and
  the operator's next action is explicit: retry after the fault clears, or
  recover.
- Disk full follows the same path with an explicit frontier: the last durable
  root remains valid and nothing beyond it is claimed.
- A slow or failed optional consumer (index worker, observer, ZMQ endpoint)
  records a gap or a failed state in its owner and never stalls steps 1 to 7.

Preserve the datadir before manually removing files when corruption evidence
is needed.

## Schema changes

`CURRENT_SCHEMA` covers only the authoritative chainstate bytes. Changing that
format is a fresh-replay event: the new binary increments `CURRENT_SCHEMA`,
refuses any datadir carrying the old marker, and syncs a separately named fresh
datadir from the network. There is no converter, translator, or legacy reader,
and the node never opens, rewrites, or deletes an existing operator datadir
with incompatible code.

Owner-local formats (fee estimator state, peer discovery state, index layouts
under `INDEX_FORMAT_VERSION`) evolve independently and keep `CURRENT_SCHEMA`
unchanged. A rejected owner-local file degrades that owner (insufficient fee
data, reseeded discovery, `Rebuilding` capability) and is left in place until
an authorized rebuild. The full rule is in
[policies/db-migration.md](policies/db-migration.md).

## Metrics and logs

Restore logs include the recovered `commit_id`, tip hash and height, the
segment cursors validated, the process epoch assigned, and any corruption
diagnosis. Durable-commit metrics expose per-step timing for append, sync,
batch, and durable completion, the count of fence closures that ended in
failure, and the current fence state. Metric names are owned by
`crates/node/src/metrics.rs`; this page does not restate them.

## Verification

Process-level tests kill child processes at every crash point in the ordered
protocol (before and after append, after sync, batch visible but not durable,
durable but unpublished, during each reorg stage, during index watermark
commit) and additionally model backend lost and partial writes, since a process
kill leaves the OS page cache intact. Each point has a declared recovered
frontier; a valid complete frontier with exact coins and tip must result even
when publication never ran. The gate commands are the T09, T11, T12, T13, and
T14 targets recorded in [../CONSTRAINTS.md](../CONSTRAINTS.md) (CL-12,
CL-17, CL-18).
