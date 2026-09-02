# P2P owns the peer lifecycle

## Problem

The listener registers a `PeerLease` before the handshake so live connection
accounting includes handshaking peers. A node-layer handshake callback also
mutated the same address-keyed lease map and peer metadata. That split
authority let metadata publication cancel the connection being published and
made stale sync decisions capable of racing a same-address replacement.

## Decision

`PeerLifecycle` is the sole mutation boundary for live leases and ready-peer
metadata. P2P connection threads use it to register before handshake, publish
metadata only while the publishing lease remains current, replace a genuine
predecessor, and remove themselves during teardown.

Higher layers receive a handshake-completion notification carrying the
`PeerSource` immediately before P2P publishes the connection as ready.
`BlockSync` uses it to clear scheduler state while the source is held current,
before a replacement becomes selectable. Ready-peer snapshots carry the same
source, and sync queues messages through an identity-checked lease rather than
resolving a `SocketAddr` again. Higher layers cannot insert into or remove from
the shared maps. The source carries the connection identity, so a stale
operation cannot publish, send to, or cancel a replacement.

## Guardrails

- Address equality does not establish connection identity.
- Registering a replacement immediately hides the predecessor's ready metadata.
- Scheduler state is reset under the current-source guard before replacement
  metadata is published.
- Handshake metadata is published only for the current lease.
- The node, RPC, sync, and listener share one `Arc<PeerLifecycle>` authority.
- Ready-peer selection carries `PeerSource` through the final send.
- Disconnect requests caused by received data use the data's `PeerSource`.
- Same-address replacement tests must cover stale publication and stale
  disconnect attempts.
