# P2P wire contract

Target contract for the peer-wire surface: one scheduling owner, wire
compatibility, discovery, compact blocks, and the optional transport and
filters. The handshake field table, reject-or-ignore matrix, and
deviation ledger stay in
[docs/policies/p2p-compatibility.md](../policies/p2p-compatibility.md).
On conflict, fix the code and amend both pages in the same changeset.

Owners: `P2pService` in `crates/p2p/src/service.rs` (sessions, leases,
download-window scheduling); `PeerTable` and `PeerLease` in
`crates/p2p/src/peer_table.rs` (session identity); the address book in
`crates/p2p/src/address_book.rs`; compact blocks in
`crates/p2p/src/compact_block.rs`; optional transport in
`crates/p2p/src/transport_v2.rs`.

## Clauses

### `P2P-01`: Wire inventory and framing compatibility

- `crates/p2p/src/compat.rs` owns the decoded command inventory and
  `PINNED_CORE_VERSION` (Bitcoin Core 31.1). The policy document owns
  handshake fields, reject-or-ignore semantics, and recorded deviations.
  The `## 5. Message Surface` table in the policy page is a checked
  projection of `COMMANDS`.
- Message framing, the envelope decoder, service flags, and network
  magic follow the inventory. v1 frames for handshake and inventory
  commands stay byte-identical to rust-bitcoin's `RawNetworkMessage`.
  Payload bounds are per command, with a global cap.
- An unknown command and an oversize payload produce documented
  disconnect classes, never a hang. Idle timeouts and rejection classes
  match the pinned contract.

### `P2P-02`: One scheduling and session owner

- `P2pService` is the sole owner of sessions, leases, and the
  download-window scheduler. The node submits chain demand and receives
  delivered blocks as bounded events; it validates them. `crates/node`
  keeps no second scheduler, download-window copy, or peer table.
- `PeerTable` and `PeerLease` remain the one session-identity owner. A
  reconnect at the same socket address is a new session with a new
  generation. Each request lease is released exactly once.
- On disconnect, the union of requeued outstanding requests equals
  exactly the freed set. A stale-generation completion is ignored by
  generation; it cannot release, credit, or starve a lease owned by the
  new session.
- Control traffic (handshake, ping/pong, headers, disconnect) remains
  serviceable under block and transaction queue pressure. Receive and
  send buffers are bounded by bytes and work. A full queue drops bulk
  data with accounting and never starves control.

### `P2P-03`: Discovery and the persistent address book

- `crates/p2p/src/address_book.rs` owns the bounded persistent address
  manager: tried and new candidate tables with timestamps and rate
  bounds, IPv4/IPv6 and selected addrv2 formats, DNS seed and bootstrap
  policy, `getaddr`/`getaddr_rcv` behavior, per-message and total intake
  caps, and explicit proxy behavior.
- Discovery state persists across restart under a discovery-owned
  version field. A corrupt or unknown discovery version degrades to
  seeded or empty discovery with a typed reseed status; it never fails
  authoritative startup. A rejected discovery file stays in place until
  an authorized rebuild.
- `P2pService` maintains configured outbound diversity through its
  reconnect and backoff. No second connection owner appears. Peer
  status, connect and disconnect, network-active control, manual bans,
  and declared discouragement live under `P2pService`.
- Advertised service bits match the node's actual pruning and capability
  state. A disabled feature is never advertised.

### `P2P-04`: Compact blocks

- BIP152 v1 and v2 serialization and `sendcmpct` preference negotiation
  are explicit. Reconstruction in `crates/p2p/src/compact_block.rs`
  matches short IDs against the peer's announced mempool set, honors
  prefilled indexes, and treats colliding matches as missing data.
- Ambiguity yields an ordinary missing-data request or a full-block
  fallback. A short ID is never an authenticated transaction identity.
  Every reconstructed block enters the ordinary validation path.
  Compact blocks are a bandwidth optimization, never a consensus
  shortcut.
- A header or parent change safely drops incomplete reconstruction:
  no partial commit, leases freed through the owner. Serving side
  builds responses from stored bodies with bounded range reads and
  respects witness representation and pruning-profile honesty.

### `P2P-05`: Optional v2 transport and compact filters

- BIP324 v2 transport is an optional feature (`bip324`), disabled by
  default, implemented with the pinned `bip324 =0.11.0` sans-I/O
  handshake and cipher session. Negotiation outcomes are
  `V2`, `V1Fallback`, or `Rejected{class}`. An authentication failure
  produces a disconnect class, never a silent downgrade to v1.
- BIP157/158 compact filters are served only when the filter capability
  and retained block data allow honest advertising. The index owner
  computes filters and header chains; p2p serves precomputed bytes
  through a boundary type. No `p2p -> index` production dependency.
- With both optional features disabled, the node advertises nothing,
  sends no negotiation messages, and validates identically. Optional
  transport work never waits on index completion.

## Proven by

- `crates/p2p/tests/overhaul_download_owner.rs` (planned): exact
  requeue-equals-freed set, stale-generation ignore, control priority
  under pressure, byte-bounded buffers.
- `crates/p2p/tests/overhaul_peer_contract.rs` (planned): handshake
  exception table, unknown-command and oversize disconnect classes,
  restart survival of discovery state, intake bounds, outbound
  diversity, honest service bits.
- `crates/p2p/tests/overhaul_compact_blocks.rs` (planned): negotiation
  matrix, prefilled and missing indexes, short-ID collision fallback,
  byte-equal validation outcome, invalidation on reorg.
- `crates/p2p/tests/overhaul_optional_protocols.rs` (planned): BIP324
  vectors, negotiation and fallback, filter serving, and the
  disabled-advertisement negative lane.
- Existing suites keep their verdicts: `crates/p2p/tests/core_compat.rs`
  (command inventory, envelope, handshake, reject matrix),
  `crates/p2p/tests/wire_codec.rs`,
  `crates/p2p/tests/handshake_roundtrip.rs`,
  `crates/p2p/tests/core_interop_live.rs`,
  `crates/node/tests/tx_ingress_e2e.rs`.

## Vocabulary

[PeerLease](../../CONCEPTS.md),
[DownloadWindow](../../CONCEPTS.md).
