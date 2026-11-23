# bitcoin-rs-chain::chain

Owns the in-memory block tree: header acceptance with proof-of-work validation, best-tip
selection, and reorganization planning. It tracks how far valid headers are known (the header
tip), independently of the apply frontier.

`BlockTree` owns resident nodes in reusable private slab slots. Public `NodeId`s are
monotonic logical identities. Reclamation removes an identity from lookup and never
assigns it to another node. A stale identity returns `ChainError::UnknownNode`.
`lookup` and `node_by_hash` resolve header hashes, and the best tip is published as an
atomically swappable `TipSnapshot` (`tip`, `tip_id`, `tip_height`) for
lock-free readers. `accept_headers` admits a header batch after proof of work, the
invalid-parent refusal, and one shared contextual gate (`validate_contextual_header`).
The gate enforces compact-target validation against difficulty rules
(`validate_header_nbits`) and the future-drift ceiling (`current_unix_seconds`).
It also checks the median-time-past floor from ancestor timestamps, the BIP94
timewarp floor at an adjustment boundary, and the
version floors of the buried deployments. It returns the new `NodeId`s.
`plan_reorg` walks parent pointers to the common ancestor and returns a `ReorgPlan`
naming the blocks to disconnect and connect. `BlockTree` privately owns
`Bip9Cache` in `tree.rs`, memoizing
versionbits deployment states per node and deployment. Entries remain valid
across branch switches because ancestry is unchanged; subtree invalidation
removes entries for invalid nodes. Leaf reclamation removes the reclaimed node's entries. `TipSnapshot` is defined at the crate root.
`BlockTreeNode` carries
parent, height, and header hash with a `NodeStatus` (`HeaderValid`, `Active`, `Stale`, or
`Invalid`), and every failure surfaces as a structured `ChainError` variant.
`InitialBlockDownload` (in `ibd`) owns the process-wide initial-block-download
latch over the published applied-tip and block-tree handles. The node builds
one `Arc` shared by RPC and P2P, so both surfaces answer identically
(Core `IsInitialBlockDownload` / `m_cached_is_ibd` semantics).
`ChainProgressReader` (in `progress`) derives synchronization progress beside
it: heights, best hash, tip time and median time past, Core's
`GuessVerificationProgress`, that latch's decision, and chain work. Chainstate
mints it from its own handles, so RPC and the embedding API report progress
without rebuilding it.

Part of [`bitcoin-rs`](../../../../README.md); see [`CONCEPTS.md`](../../../../CONCEPTS.md) for the
project vocabulary.

## Retained headers

`Chainstate::admit_headers` owns live header admission through
`header_admission.rs`. It uses the same proof-of-work and contextual validator as
`accept_headers`. A resource refusal does not mark a header consensus-invalid.

The ordinary resident bound is `K + A`. `K` is
`HEADER_SIDE_CACHE_LIMIT`, currently 65,536 headers. `A` is the number of distinct
headers in the required ancestry. The required roots are the best header tip,
the applied tips, pending application, the AssumeUTXO base, active transition
leases, and explicit operator-invalidated roots. Operator pins can increase
`A`. Stored body and undo bytes do not create permanent header pins.

The tree reclaims unpinned leaves first. This preserves the complete ancestry of
every required root. An admission or maintenance call removes at most 4,000
leaves. Slab compaction and hash-map shrinking can make a linear pass after
capacity falls by more than half. This is a removal bound, not a bound on total
CPU work.

`HeaderCandidate` permits a winning fork to exceed the side-cache allowance.
Its first pass checks every header's proof of work and contextual rules with
`HeaderValidationContext`. It keeps fixed-size context and chunk commitments.
This pass inserts no headers. Candidate anchors remain protected within `K`.
At most four candidates share one lifetime budget, including cancelled
candidates whose buffers have not been released.

A fully validated target must exceed current best work before authenticated
redownload can start resident replay. One FIFO replay owner can temporarily add
at most its verified target height minus its anchor height to the ordinary
bound. A chunk must match its commitment before any of its headers are released.
Replay reuses live admission. It acknowledges each successful prefix before
yielding for cleanup. A completed, cancelled, or superseded replay releases its
extra allowance. A shorter winning branch can reduce the ordinary bound before
cleanup has finished. Further ordinary allocation waits for bounded maintenance
to make room.

Header eviction does not delete body, undo, or checkpoint bytes. A stored side
body needs validated resident headers before it can participate in a new reorg.
Checkpoint recovery validates the complete retained artifact, including every
legacy side record, before returning a bounded resident side prefix. Oversized
legacy artifacts use a temporary context index proportional to the authenticated
artifact size. That index is scratch storage, not a second durable header owner.
