# bitcoin-rs-chain

Owns the in-memory block tree: header acceptance with proof-of-work validation, best-tip
selection, and reorganization planning — how far valid headers are known (the header
tip), tracked independently of the apply frontier.

`BlockTree` is the central type: nodes live in a slab addressed by compact `NodeId`s,
`lookup` and `node_by_hash` resolve header hashes, `ancestors` walks parent
chains, and the best tip is published as an
atomically swappable `TipSnapshot` (`tip`, `tip_id`, `tip_height`) for
lock-free readers. `accept_headers` admits a header batch after proof of work, the
invalid-parent refusal, and one shared contextual gate (`validate_contextual_header`):
compact-target validation against the network's difficulty rules
(`validate_header_nbits`), the median-time-past bound, the future-drift bound against
the wall clock (`current_unix_seconds`), the BIP94 timewarp floor at an adjustment
boundary, and the version floors of the buried deployments — returning the new `NodeId`s.
`plan_reorg` walks parent pointers to the common ancestor and returns a `ReorgPlan`
naming the blocks to disconnect and connect. An internal `Bip9Cache` memoizes
versionbits deployment states per node and is invalidated on reorg. `BlockTreeNode` carries
parent, height, and header hash with a `NodeStatus` (header-valid, active, or
off-best-chain), and every failure surfaces as a structured `ChainError` variant.
`InitialBlockDownload` (in `ibd`) owns the process-wide initial-block-download
latch over the published applied-tip and block-tree handles; the node builds
one `Arc` shared by RPC and P2P, so both surfaces answer identically
(Core `IsInitialBlockDownload` / `m_cached_is_ibd` semantics).

## Features
- `rocksdb`: enables the `RocksDB` backend in `bitcoin-rs-storage`
- `fjall`: enables the fjall backend in `bitcoin-rs-storage`
- `redb`: enables the redb backend in `bitcoin-rs-storage`

Part of [`bitcoin-rs`](../../README.md); see [`CONCEPTS.md`](../../CONCEPTS.md) for the
project vocabulary.
