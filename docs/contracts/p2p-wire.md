# P2P wire contract (pointer)

The peer-wire contract is split across two owners. This page assigns
ownership and cites proof under the
[contracts precedence rule](README.md).

- [`crates/p2p/src/compat.rs`](../../crates/p2p/src/compat.rs) owns the
  decoded command inventory and the pinned Core version.
- [docs/policies/p2p-compatibility.md](../policies/p2p-compatibility.md)
  owns the handshake fields, reject-or-ignore matrix, deviation ledger,
  and verification process. The §5 table is a checked projection of
  `COMMANDS`.

## Clauses

### `P2P-01`: Protocol wire framing and handshake compatibility

- **Owner**: `crates/p2p/src/compat.rs` owns the 36-command inventory and
  `PINNED_CORE_VERSION` (Bitcoin Core 31.1). The policy document owns
  handshake fields, reject-or-ignore semantics, and recorded deviations.
- **Scope**: `crates/p2p` wire, handshake, protocol FSM, and message policy; the
  chain-serving query `crates/p2p/src/chain_query.rs`; and node network flags.
- Message framing, envelope decoder, service flags, and network magic follow
  the inventory and the policy document. v1 frames for handshake and inventory
  commands are byte-identical to rust-bitcoin's `RawNetworkMessage`.

### `P2P-02`: Connection lifecycle and peer lease ownership

- Peer connection sessions and `PeerLease` lifecycle are owned by `crates/p2p`.
- The node-side synchronization coordinator consumes peer lifecycle events
  without duplicating connection replacement or cancellation rules.

### `P2P-03`: Demonstrated best-known-height credit and request eligibility

- **Owner**: `crates/p2p/src/peer_table.rs` owns the per-connection credit
  record (`PeerInfo.best_known_height` plus the accepted header tips retained
  by the live session) and its identity-checked mutation
  (`PeerTable::note_announced_tip`, `PeerTable::note_announced_height`).
  `crates/node/src/sync.rs` owns the eligibility/ordering consumption
  (`sync_peer_candidate`, `outranks`) and the active-branch filter that
  decides which accepted headers establish credit.
- Credit is initialized from the handshake `start_height`, raised
  monotonically (never lowered), raisable only by the delivering connection
  (a same-address replacement never inherits its predecessor's credit), and
  raised only for accepted headers whose retained tip is on the currently
  selected best chain (the best chain is re-selected during acceptance, so a
  winning fork announcement earns credit in the same tick). When a later
  announcement makes a previously losing retained tip active, its delivering
  connection is re-evaluated before request selection. Until a session has
  accepted a header tip, body and hedge selection may use its handshake
  capability while header discovery is pending; after that point, the
  accepted tip must be on the active chain at or beyond the requested height.

## Live gaps

- **Peer lifecycle boundary**: Moving the remaining P2P scheduling and lifecycle policy out of `crates/node` is tracked under #217 (open).

## Proven by

- `crates/p2p/tests/core_compat.rs`:
  - `cargo test -p bitcoin-rs-p2p --test core_compat` pins the command
    inventory against the policy table, rust-bitcoin v1 envelopes, handshake
    fields, per-network framing, relay round-trips, the reject-or-ignore
    matrix, and peer-visible reorg/restart behavior.
- `crates/p2p/tests/core_interop_live.rs`: live interop lane running via
  `scripts/run-p2p-core-interop.sh` when an external `bitcoind` is provided.
- `crates/p2p/src/peer_table.rs` tests
  `note_announced_height_credits_only_the_delivering_connection` and
  `note_announced_height_raises_monotonically_and_reports_actual_updates`
  pin the identity-checked, monotonic credit mutation and retained tip
  evidence (P2P-03).
- `crates/node/src/sync.rs` tests `tick_fetches_new_tip_headers_from_at_tip_peers`
  (at-tip request eligibility after catch-up, P2P-03/#617) and
  `tick_fetches_reorg_fork_announced_by_at_tip_peer` (reorg announcements
  earn credit on the reselected best chain),
  `losing_fork_credit_survives_winner_disconnect` (retained branch evidence),
  and `cold_start_stall_hedges_front_without_reassigning_owner` (active-chain
  hedge eligibility).
