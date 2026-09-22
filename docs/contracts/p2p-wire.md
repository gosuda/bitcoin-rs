# P2P wire contract (pointer)

This page assigns ownership and cites proof under the
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
  `getdata` block serving writes stored consensus payload bytes
  (`Message::BlockPayload`) without a decode/re-encode round trip. The
  decoder still types inbound `block` as `Message::Block`.

### `P2P-02`: Connection lifecycle and peer lease ownership

- Peer connection sessions and `PeerLease` lifecycle are owned by `crates/p2p`.
- The node-side synchronization coordinator consumes peer lifecycle events
  without duplicating connection replacement or cancellation rules.
- Parent requests validate the delivering connection and enqueue under the
  same peer-table authority that serializes replacement. Requests from an
  already cancelled lease enqueue nothing.

### `P2P-03`: Demonstrated best-known-height credit and request eligibility

- **Owner**: `crates/p2p/src/peer_table.rs` owns the per-connection credit
  record (`PeerInfo.best_known_height` plus the accepted header tips retained
  by the live session) and its identity-checked mutation
  (`PeerTable::note_announced_tip`, `PeerTable::note_announced_height`).
  `crates/p2p/src/sync.rs` owns the eligibility/ordering consumption
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

### `P2P-04`: Connected-socket posture and vectored emission

- **Owner**: `CountingStream::from_connected` (`crates/p2p/src/counters.rs`).
- Every accepted or dialed P2P `TcpStream` is wrapped by that constructor
  before handshake bytes move. The constructor disables Nagle (`TCP_NODELAY`).
- `CountingStream` forwards `write_vectored` so `wire::write_message` emits
  header plus payload as one syscall. A wrapper that only implemented `write`
  would split the frame again.
- Handshake, the connection reader, and the writer-thread clone share one
  `PeerCounters`. Timeouts stay with the listener: handshake and the message
  loop use different poll intervals.

## Live gaps

- **Peer lifecycle boundary**: Header-request planning and getdata fan-out
  execute in `crates/p2p/src/sync.rs` `BlockSync` behind the node-provided
  `SyncChain` seam. Node retains applied-chain mutation; `P2pService` no longer
  holds a shadow download window.

## Proven by

- `crates/p2p/src/inv.rs` test
  `cancelled_missing_parent_source_does_not_enqueue_a_request` and
  `crates/p2p/src/peer_table.rs` test
  `with_current_rejects_stale_source_and_holds_live_identity` protect
  cancellation and identity-checked enqueue (P2P-02).
- `crates/p2p/tests/core_compat.rs`:
  - `cargo test -p bitcoin-rs-p2p --test core_compat` pins the command
    inventory against the policy table, rust-bitcoin v1 envelopes, handshake
    fields, per-network framing, relay round-trips, the reject-or-ignore
    matrix, and peer-visible reorg/restart behavior.
- `crates/p2p/tests/core_interop_live.rs`: live differential lane running via
  `scripts/run-p2p-core-interop.sh` against the pinned Core 31.1 `bitcoind`
  (`docs/contracts/core-differential.md`).
- `crates/p2p/src/counters.rs` tests
  `a_vectored_write_counts_every_slice_the_socket_took`,
  `a_short_vectored_write_counts_what_the_socket_took`, and
  `write_message_through_counting_stream_stays_vectored`: a v1 frame's header
  and payload leave as one `write_vectored`, and the wrapper counts every byte
  the socket took (`P2P-01`). Elapsed time is
  `crates/p2p/benches/write_message.rs`.
- `crates/p2p/src/peer_table.rs` tests
  `note_announced_height_credits_only_the_delivering_connection` and
  `note_announced_height_raises_monotonically_and_reports_actual_updates`
  pin the identity-checked, monotonic credit mutation and retained tip
  evidence (P2P-03).
- `crates/p2p/src/sync/tests/transitions_1.rs` tests `tick_fetches_new_tip_headers_from_at_tip_peers`
  (at-tip request eligibility after catch-up, P2P-03/#617) and
  `tick_fetches_reorg_fork_announced_by_at_tip_peer` (reorg announcements
  earn credit on the reselected best chain),
  `losing_fork_credit_survives_winner_disconnect` (retained branch evidence),
  and `cold_start_stall_hedges_front_without_reassigning_owner` (active-chain
  hedge eligibility).
- `crates/p2p/src/counters.rs` tests `a_vectored_write_counts_every_slice`,
  `from_connected_disables_nagle`: the counting wrapper forwards one
  `write_vectored` for header plus payload, and the connected-socket
  constructor owns `TCP_NODELAY` (P2P-04).
- `crates/p2p/src/listener.rs` test `session_sockets_disable_nagle`: inbound
  and outbound session sockets set `TCP_NODELAY` (`P2P-04`).
- `crates/p2p/src/handshake.rs` test
  `inbound_handshake_reaches_ready_after_remote_version_and_verack`: inbound
  handshake writes framed version, feature, and verack bytes once and reaches
  Ready (`P2P-01`).
- `crates/p2p/src/counters.rs` tests `leftover_bytes_do_not_revisit_the_socket`,
  `two_wire_messages_decode_from_one_socket_read`, and
  `a_timed_out_refill_does_not_replay_consumed_bytes`: one kernel delivery of
  two v1 frames decodes both without a second socket read, and a timed-out
  refill does not replay consumed bytes (`P2P-01`).

### `P2P-05`: Canonical frontier recovery without invented peer credit

- `crates/p2p/src/sync/frontier.rs` is the single owner of mutable P2P
  scheduler state and its canonical tick transition. The download window and
  block stager are subordinate bounded policy/storage components; they are not
  parallel scheduler authorities. The transition normalizes peer lifecycle,
  settles inbound bodies and recovery, then combines that state with chain
  facts obtained through `SyncChain` and one usable-peer projection. It owns
  no durable chainstate and does not move apply or reorg mutation into P2P.
- The applied chain and selected header ancestry own the next required body.
  The download cursor is a scan hint. An unowned frontier behind that hint
  becomes requestable again, including an applied rollback with unchanged
  headers. Existing pending and staged bodies retain their ownership.
- Request publication binds the exact `PeerSource` — address plus connection
  identity — while the download window stays address-scoped policy state.
  Body delivery, duplicate accounting, and malformed-body rejection preserve
  that identity at the `PeerTable` boundary; a same-address replacement
  cannot inherit its predecessor's pending ownership or peer blame.
- A known-header gap whose apply-frontier block is neither in flight nor
  staged triggers a header probe from the applied chain; staged successors
  behind an unowned frontier are stuck inventory, not progress. Beyond the
  initial handshake capability (P2P-03), only a subsequent accepted
  active-branch announcement grants body capability. Losing the last credited
  peer must not require restart or an unsolicited announcement from a
  surviving peer.
- The existing header request and timeout pace discovery. Empty responses
  preserve that deadline; expiry rotates among connected full witness peers.
  Nonempty responses consume their matching request even when rejected.
- Session validation and request publication hold the peer table before
  download or header-request state. A cancelled ready event does not wait for
  the download writer or modify its replacement's state. Tick reconciliation
  retires address-scoped window ownership and the header request of any
  replaced or disconnected connection before conviction observes the window,
  and again after a conviction removes a connection; no other path retires
  header ownership except the owner's own header reply.
- Header request ownership and body-send publication carry `PeerSource`
  connection identity. Header and body selection consume the same
  handshake-complete, uncancelled peer-table snapshot; a cancelled lease is
  not representable in that scheduler projection.
- When a known canonical body gap has no pending or staged owner, one
  reconciliation must either arm body/frontier recovery work or retain an
  explicit no-progress reason. Operator sync-progress logs expose the derived
  next body, body state (missing, in flight, or staged), header owner, and
  no-progress reason.
- Body/header binding failures reject the delivery, not the header branch.
  Rejection logs carry source, byte/transaction counts and coinbase witness
  shape. Compact reconstruction logs include the same block hash for joining
  evidence. A header ahead of the applied chain is not evidence that the
  applied-chain `getblockhash` RPC should return it.

Proof: `crates/p2p/src/sync/tests/frontier_recovery.rs` covers applied
rollback, duplicate request suppression, empty-response pacing/rotation and
cancelled readiness under contention.
`crates/p2p/src/sync/frontier.rs` property tests cover the action-or-reason
rule for arbitrary availability, peer, and apply-halt facts, and
`crates/p2p/src/peer_table.rs` proves that cancelled and handshaking sessions
are absent from the scheduler projection.
`crates/p2p/src/sync/tests/witness_staging_gate.rs` covers bad delivery,
peer replacement, relearned capability and eventual application. Existing
branch-plan, attribution, timeout and bounded-staging suites remain required.
