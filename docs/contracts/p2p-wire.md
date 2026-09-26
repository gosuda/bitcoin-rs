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
- Scheduler ownership is keyed on connection identity. Every tick runs two
  sweep passes over the peer table's live session set, and a ready event
  from a live connection runs one; a stale ready event runs none. Each
  sweep releases every window assignment, election, probe racer, header
  request and deferred body fetch owned by a connection outside that set,
  so a same-address replacement never inherits or loses its predecessor's
  work.

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
  raised only for accepted headers whose retained tip shares ancestry with
  the currently selected best chain (the best chain is re-selected during
  acceptance, so a winning fork announcement earns credit in the same tick).
  A retained tip attests the deepest active-chain node that is its ancestor
  — `shared_active_height`: an on-active tip attests its own height, while a
  losing fork tip still attests the shared prefix it proved the peer holds.
  When a later announcement makes a previously losing retained tip active,
  its delivering connection is re-evaluated before request selection. Until
  a session has accepted a header tip, body and hedge selection may use its
  handshake capability while header discovery is pending; after that point,
  the requested height must not exceed the deepest shared ancestor across
  its retained tips. Retained-tip evidence is compacted at each credit
  refresh: a tip that resolves on the active chain at or below the recorded
  maximum can never raise it again, so only unresolved (fork) tips and the
  max-resolving tip are kept. Unresolved tips are deduplicated to the
  maximal tip per branch and capped (`MAX_UNRESOLVED_DEMONSTRATED_TIPS`),
  so a peer cannot grow the record by announcing distinct side chains.

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

- The applied chain and selected header ancestry own the next required body.
  The download cursor is a scan hint. An unowned frontier behind that hint
  becomes requestable again, including an applied rollback with unchanged
  headers. Existing pending and staged bodies retain their ownership.
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
  the download writer or modify its replacement's state.
- Body/header binding failures reject the delivery, not the header branch.
  Rejection logs carry source, byte/transaction counts and coinbase witness
  shape. Compact reconstruction logs include the same block hash for joining
  evidence. A header ahead of the applied chain is not evidence that the
  applied-chain `getblockhash` RPC should return it.

Proof: `crates/p2p/src/sync/tests/frontier_recovery.rs` covers applied
rollback, duplicate request suppression, empty-response pacing/rotation and
cancelled readiness under contention.
`crates/p2p/src/sync/tests/witness_staging_gate.rs` covers bad delivery,
peer replacement, relearned capability and eventual application. Existing
branch-plan, attribution, timeout and bounded-staging suites remain required.

### `P2P-06`: Body-carried announcements reach header admission

- **Owner**: `ConnectionShared::send_block` (`crates/p2p/src/listener.rs`)
  forwards every inbound body's embedded header through the headers sink;
  `BlockSync::admit_staged_headers` (`crates/p2p/src/sync/receive.rs`) retries
  admission for staged bodies still lacking a tree node.
- A block body can never become the apply frontier's expected block while
  the tree does not know its hash. Every delivery path — `block` messages
  (`inv` getdata answers or unsolicited pushes), reconstructed compact
  blocks, and `cmpctblock` announcements — routes its embedded header into
  the same admission drain as `headers` messages, so credit (P2P-03),
  peer-fault disconnection, and ancestry requests apply uniformly.
- A batch that cannot attach (`MissingParent`) or cannot be admitted
  (`Refused`) requests the header ancestry from the delivering peer — or an
  eligible full-witness peer when no source was recorded — rather than
  silently dropping the announcement and leaving the live tip wedged behind
  one missed header. `Refused` re-requests are paced to the request timeout
  (`refused_rerequest_at`): a paused admission would otherwise replay the
  same locator at round-trip pace.
- The forwarded header is marked as such (`InboundHeaders::wire_response =
  false`): it is not a `getheaders` response, so it must not consume the
  outstanding request's pending slot — otherwise every delivered body would
  reset request pacing and emit duplicate `getheaders`.
- The staged retry carries the delivering connection
  (`ReceivedBlock::source`): a retry that admits credits that peer exactly
  as the headers drain would (`note_announced_tip`), and a peer-fault
  rejection discards the body, releases its download-window record outright
  (`discard_received`, never re-queued), disconnects the source, and marks
  it unresponsive — the same outcome a rejected `headers` batch produces.
- A `cmpctblock` outcome that fetches the body itself (`RequestMissing`'s
  `getblocktxn`, `Fallback`'s `getdata`) is marked
  (`InboundHeaders::body_fetch_owned`): once the tip admits, the window
  records the hash pending under the delivering connection
  (`DownloadWindow::mark_owned_fetch`) so normal scheduling does not issue
  a duplicate `getdata`. The mark honours the same gates a real request
  faces — window request capacity, the owner's per-peer inflight share,
  and the request frontier (a below-frontier mark could never be scheduled
  and its expiry would drag `next_request_height` back into a re-request
  sweep of applied heights). A tip that has not attached yet is retained
  in the bounded `SchedulerState::owned_body_fetches` set and resolved
  once ancestry admits it; marks whose source went stale are dropped, and
  delivery resolves the mark like any window request while expiry or
  disconnect hands it back to scheduling — a silently dropped compact
  fetch re-requests instead of wedging the tip.
- Every peer-removal path releases a `getheaders` gate the peer owned —
  wire-response consumption, send failure, and peer-fault disconnects in
  both the headers drain and the staged-header retry
  (`clear_header_request_for`, identity-exact), and otherwise the live-set
  sweep (P2P-02) — so a same-address reconnect cannot inherit a dead
  request deadline.

Proof: `crates/p2p/src/sync/tests/head_sync.rs` covers body-carried header
admission and apply, gap-fill requests for staged bodies ahead of their
header chain, announcer-directed `getheaders` on unattached batches,
non-response forwards preserving pending-request state, staged-retry
credit, shared-ancestor capability, bounded fork evidence, credit for
already-known tips, the compact-owned pending mark, and the retained
mark resolving once its tip header attaches. Capacity and frontier gates
on the owned-fetch mark are covered in
`crates/p2p/src/download_window.rs` tests; fault-path gate cleanup is
covered in `crates/p2p/src/sync/tests/transitions_4.rs`.
`crates/p2p/src/listener.rs` test `send_block_forwards_the_blocks_header`
covers the delivery-path forward.

### `P2P-07`: Block announcements lead with headers; ingress is bounded twice

- **Owner**: the block branch of `dispatch_inbound_full`
  (`crates/p2p/src/dispatch.rs`), `BlockSync::announce_block`
  (`crates/p2p/src/sync.rs`) and `BlockSync::drain_block_announcements`
  (`crates/p2p/src/sync/headers.rs`).
- `MSG_BLOCK` and `MSG_WITNESS_BLOCK` inventory vectors are availability
  information, never a body request: each one is queued against the
  announcing connection and drained by the header drain, which credits that
  connection with the hash when the tree already knows it
  (`note_announced_tip`, P2P-03) and asks it for headers when the tree does
  not. Body requests belong to header admission and the download window
  alone (Core 31.1 `net_processing.cpp:4370-4410`). Transaction vectors keep
  the relay gate, the have-filter, and the witness upgrade unchanged.
- The queue holds one entry per connection — the first unprocessed
  announcement wins — so a later vector cannot replace an unknown tip before
  the drain sees it, and a peer cannot grow scheduler state by announcing.
  While one `getheaders` request is outstanding, further unknown
  announcements stay queued for a later drain: the singleton
  `header_request` never has its owner overwritten mid-flight.
- **Near-tip direct fetch**: `BlockSync::direct_fetch_announced_tip` asks the
  connection that just proved a header for its body, inside the same drain
  that admitted it, instead of waiting for the next scheduler tick (Core
  `HeadersDirectFetchBlocks`, `net_processing.cpp:3098-3158`, gated by
  `CanDirectFetch` at `:1450-1453`). The request goes through
  `send_getdata_for_pending_blocks`, so the window's budget, the per-peer
  in-flight cap, the pending ownership stamp, and the compact-block flavor
  for a single near-tip fetch from a BIP152 peer all apply unchanged. A tip
  that is not on the branch the header tip ends at, or that leaves the apply
  frontier more than `COMPACT_RELAY_NEAR_TIP_BLOCKS` below it, is a bulk
  download or a large reorg and stays with the ordinary scheduler.
- **Ingress bounds**: the shared inbound block channel is bounded once for
  the node (`P2pServiceConfig::inbound_block_queue_limit`, set from
  `INBOUND_BLOCK_CHANNEL_LIMIT`), and
  `PeerLease::admit_block_forward` bounds each connection's unsolicited
  share of it at `MAX_UNSOLICITED_BLOCK_FORWARDS`
  (`crates/p2p/src/connection.rs`) before that channel. A body the download
  window owns for that exact connection — a window request or a deferred
  compact fetch (`BlockSync::owns_body_fetch`) — is always admitted. An
  over-bound unsolicited body is dropped together with its carried header —
  refused bodies must not grow the header queue either — with a debug record
  and a `node.sync.dropped_unsolicited_blocks` counter: the listener never
  waits on the shared channel for it and the connection is never
  disconnected for this bound alone. The credit rides the inbound payload and is released
  when sync takes the body, so staging, discarding, and rejecting all return
  the slot; ownership and credits are per connection, so a same-address
  replacement inherits neither.
- **Permanent consensus failure**: when a staged body's commit settles with
  `WindowCommitDisposition::Permanent` — in the apply pass or inside a
  branch switch (`BranchSwitchError::ConnectFailed`, attributed through the
  staged entry's recorded source) —
  `BlockSync::punish_permanent_delivery_source` disconnects the delivering
  connection — in the apply pass, after the invalidated hashes are purged;
  in a branch switch, before the purge drops the staged entry that carries
  the source — and releases its
  `getheaders` gate and marks it unresponsive only when that exact
  connection was current and removed (Core `net_processing.cpp:2031-2068`).
  Each punishment increments `node.sync.invalid_block_disconnects`. A
  `BodyMutated` or `Operational` settlement failure stays retryable and
  non-punitive, and a `Fatal` settlement halts admission without peer blame.
  A body that fails header binding before it can be staged keeps its
  existing delivery-rejection policy.
- **Unresolved-body quota**: a body staged while the tree cannot resolve its
  hash owes the admission clauses later (`gate_pending`); the staged
  `gate_pending` population is capped at `MAX_UNRESOLVED_STAGED_BODIES`
  (`crates/p2p/src/sync/receive.rs`), so a multi-peer orphan flood cannot
  fill the shared staging budget and evict valid progress.

Proof: `crates/p2p/src/dispatch.rs` test
`inv_block_uses_headers_not_body_getdata`; `crates/p2p/src/sync/tests/head_sync.rs`
test `announced_near_tip_is_direct_fetched_before_tick`;
`crates/p2p/src/listener.rs` test
`unsolicited_block_flood_is_bounded_per_source`; `crates/p2p/src/sync/tests.rs`
tests `permanent_consensus_body_disconnects_delivering_source` and
`binding_and_operational_failures_do_not_disconnect`.
