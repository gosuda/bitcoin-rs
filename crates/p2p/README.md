# bitcoin-rs-p2p

The Bitcoin peer-to-peer network surface: the wire codec, peer lifecycle and
handshaking, inbound dispatch, connection management, and block-download
policy (`DownloadWindow` and `BlockStager`).

Each `Peer` owns one connection's stream and handshake state. Live connections are
identified by a `ConnectionId`, cleaned up through a `PeerLease`, and tracked with
ready metadata by the shared `PeerTable`. Inbound accept and outbound connect
share one socket policy in `socket::configure_peer_stream` (`TCP_NODELAY`,
blocking I/O, handshake/poll timeouts); the per-connection writer coalesces a
ready burst of control messages into one `write_messages` writev, and blocks and
transactions stay one frame. `P2pService` owns workers and the session store.
`BlockSync` owns the only production download window; the service does not hold a
second copy. The node supplies chain queries and coordinates chain application.

`PeerTable` is the single authoritative owner of live peer sessions (`PeerSession`),
connection control leases (`PeerLease`), and post-handshake metadata (`PeerInfo`).
A connected TCP stream enters that world only through `CountingStream::from_connected`,
which owns `TCP_NODELAY` and forwards vectored writes so `wire::write_message` stays
one `writev` on the socket. It enforces key invariants across the node:
- **Single connection per address**: Exactly one live session per remote `SocketAddr`.
- **Atomic predecessor cancellation**: Registering a new lease at an existing address
  atomically cancels and replaces the predecessor.
- **Identity-checked removal**: Removal operations (`remove_current`, `disconnect_source`,
  `disconnect_connection`) verify `ConnectionId` so a stale handle cannot evict or
  cancel a newer session.
- **Identity-bound metadata**: Post-handshake `PeerInfo` publication succeeds only if
  the publishing connection remains the active session for that address.

All consumers — the inbound TCP `listener`, outbound connection threads, the block
download scheduler, outbound transaction relay, and RPC methods (`getpeerinfo`,
`getnetworkinfo`, `disconnectnode`) — observe and mutate live connections exclusively
through `PeerTable`.

The `listener` module has one entry point per role: `bind_listener` binds a local
address, `serve` runs the accept loop on that bound listener until shutdown, and
`spawn_outbound_connection` dials one peer. All three read one cloneable
`ConnectionShared` wiring value per start epoch, which also owns the header, block,
and transaction sinks. `P2pService` seeds outbound addresses by resolving the
configured DNS seeds through `SystemDnsResolver` behind the `DnsResolver` injection
point and queueing dials through the bounded outbound request queue.

A connection negotiates version/verack in `handshake`, then runs the peer
finite-state machine in `fsm`; `wire` is the protocol codec, decoding `Message`
values and reporting `PeerError`. Inbound traffic reaches the host through
`dispatch_inbound_full`, which streams getdata responses block by block behind the
outbound budget's pre-load production headroom gate, filters transaction inventory
through the `TxInventory` trait, reads the active chain through the `ChainQuery`
trait, and consults the chain-owned initial-block-download latch shared with RPC:
while it is active, transaction-typed `inv` vectors are never requested and `tx`
bodies are dropped before ingress (Core 31.1 `net_processing.cpp:4401-4404`,
`:4713-4716`). Served block bodies are the stored consensus bytes
(`Message::BlockPayload`); they are not decoded and re-encoded. `inbound` hands
over `InboundBlock`, `InboundHeaders`, and `InboundTx` with their delivering peer
stamped. Manual bans exclude whole subnets as a `BannedSubnet` built from an
`IpSubnet`, held in memory. `wire` decodes BIP155 `addrv2` messages, and BIP339
wtxid-relay state lives in `wtxid`.

Transaction inventory, parent requests, and outbound relay are P2P consumers of the
shared transaction lifecycle. The authoritative cross-crate ownership split is
[ARCH-05](../../docs/contracts/architecture.md#arch-05-node-composition-and-orchestration-boundary);
peer-visible inventory and relay behavior are defined in
[P2P compatibility](../../docs/policies/p2p-compatibility.md).

## Features
- `default` (enables `fjall`): build with the fjall storage backend selected.
- `rocksdb`: forward the rocksdb storage backend to `bitcoin-rs-storage`.
- `fjall`: forward the fjall storage backend to `bitcoin-rs-storage`.
- `redb`: forward the redb storage backend to `bitcoin-rs-storage`.

Part of [`bitcoin-rs`](../../README.md); see [`CONCEPTS.md`](../../CONCEPTS.md) for the
project vocabulary.
