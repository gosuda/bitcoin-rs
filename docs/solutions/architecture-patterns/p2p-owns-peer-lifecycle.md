# P2P owns the peer lifecycle

## Problem

The listener registers a `PeerLease` before the handshake so live connection
accounting includes handshaking peers. A node-layer handshake callback also
mutated the same address-keyed lease map and peer metadata. That split
authority let metadata publication cancel the connection being published and
made stale sync decisions capable of racing a same-address replacement.

## Decision

`P2pService` is the runtime owner of P2P control state and workers. Live
sessions live in one `PeerTable`. `PeerLifecycle` wraps that table for
service-owned send, cancel, and disconnect helpers. P2P connection threads
register before handshake, publish metadata only while the publishing lease
remains current, replace a genuine predecessor, and remove themselves during
teardown.

Higher layers receive a handshake-completion notification carrying the
`PeerSource` only after P2P publishes that same connection as ready.
`publish_info` is the identity-checked Ready transition; a stale predecessor
whose publish is rejected must not reset address-scoped scheduler state.
`BlockSync` is the node-side download coordinator. It drives the P2P-owned
production download window and manages node-side header-request state
(`PendingHeaderRequest` / `pending_getheaders`). It clears leftover
address-scoped scheduler state when the current connection becomes ready, and
it may disconnect a current `PeerSource` after a peer-fault headers batch. Ready-peer snapshots carry the same source, and sync queues
messages through an identity-checked lease rather than resolving a
`SocketAddr` again. The source carries the connection identity, so a stale
operation cannot publish, send to, or cancel a replacement.

## Guardrails

- Address equality does not establish connection identity.
- Registering a replacement immediately hides the predecessor's ready metadata.
- Scheduler state is reset only after the current lease publishes ready
  metadata. A stale predecessor must not notify, and `BlockSync::on_peer_ready`
  ignores a `PeerSource` that is no longer current.
- Handshake metadata is published only for the current lease.
- The node starts one `P2pService`. RPC applies the same network-activity
  transition (`apply_network_active`) on the shared flag and `PeerTable`.
  Production block-download scheduling stays on `BlockSync`'s download window.
- Ready-peer selection carries `PeerSource` through the final send.
- Disconnect requests caused by received data use the data's `PeerSource`.
- Same-address replacement tests must cover stale publication and stale
  disconnect attempts.
- Listener sockets bind before `P2pService::start` reports success.
- Worker join failures return to node teardown before clean-checkpoint
  eligibility is evaluated.
- Inbound block delivery observes the start-scoped cancel token so teardown
  cannot block on a full apply queue.
