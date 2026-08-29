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

Higher layers receive a handshake-completion notification with only the peer
address immediately before P2P publishes the connection as ready. `BlockSync`
uses it to clear address-scoped scheduler state before the replacement becomes
selectable. It may snapshot peer facts, queue messages through a cloned current
lease, and request a disconnect using `PeerSource`. It cannot insert into or
remove from the shared maps. The source carries the connection identity, so a
stale sync decision cannot disconnect a newer connection that reused the same
socket address.

## Guardrails

- Address equality does not establish connection identity.
- Registering a replacement immediately hides the predecessor's ready metadata.
- Address-scoped scheduler state is reset before replacement metadata is published.
- Handshake metadata is published only for the current lease.
- Sync readiness callbacks carry no lease or metadata mutation capability.
- Disconnect requests caused by received data use the data's `PeerSource`.
- Same-address replacement tests must cover stale publication and stale
  disconnect attempts.
