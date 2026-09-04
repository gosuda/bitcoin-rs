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

- **Peer lifecycle boundary**: Moving the remaining P2P scheduling and lifecycle policy out of `crates/node` is tracked under #217 (open).

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
- `crates/node/src/sync.rs` tests `tick_fetches_new_tip_headers_from_at_tip_peers`
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
- `crates/p2p/src/counters.rs` tests `leftover_bytes_do_not_revisit_the_socket`
  and `two_wire_messages_decode_from_one_socket_read`: one kernel delivery of
  two v1 frames decodes both without a second socket read (`P2P-01`).
