# bitcoin-rs-p2p

The Bitcoin peer-to-peer network surface: the wire codec, peer lifecycle and
handshaking, inbound dispatch, connection management, and block-download
policy (`DownloadWindow` and `BlockStager`).

Each `Peer` owns one connection's stream and handshake state. Live connections are
identified by a `ConnectionId`, cleaned up through a `PeerLease`, and tracked with
ready metadata by the shared `PeerTable`. Inbound accept and outbound connect
share one socket policy in `socket::configure_peer_stream` (`TCP_NODELAY`,
blocking I/O, handshake/poll timeouts). `P2pService` owns workers and the
session store, manual bans, persistent added nodes, network activity, and the
outbound dial queue. `BlockSync` owns the only production download window; the
service does not hold a second copy. The node supplies chain queries and
coordinates chain application. A connection
negotiates version/verack in `handshake`, then runs the peer finite-state machine
in `fsm`; `wire` is the protocol codec. The per-connection writer coalesces a ready
burst of control messages into one `write_messages` writev; blocks and transactions
stay one frame. Inbound traffic reaches the host through
`dispatch_inbound_with_chain`, which streams getdata responses behind the outbound
budget's pre-load production headroom gate and reads the active chain through the
`ChainQuery` trait. Served block bodies are the stored consensus bytes
(`Message::BlockPayload`); they are not decoded and re-encoded. `inbound` hands over
`InboundBlock` and `InboundHeaders` with their wire bytes preserved. Manual bans exclude
whole subnets as a `BannedSubnet` built from an `IpSubnet`, held in memory.
`wire` decodes BIP155 `addrv2` messages, and BIP339 wtxid-relay state lives in `wtxid`.

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
- **Serialized network disable**: Live inbound and outbound admission rechecks the
  service-owned activity switch under the table's registration lock. Disabling
  takes that same lock and cancels every admitted lease; an outbound TCP connect
  already in flight may finish, but cannot register while inactive. Socket I/O
  never runs under the table lock.

P2P workers — the inbound TCP `listener`, outbound connection threads, block
download scheduler, and outbound transaction relay — use `PeerTable` through
the owning service. RPC receives read-only `P2pQuery` snapshots and invokes
network mutations through `P2pControl`; it never receives the table or another
writable P2P handle.

Transaction inventory, parent requests, and outbound relay are P2P consumers of the
shared transaction lifecycle. The authoritative cross-crate ownership split is
[ARCH-05](../../docs/contracts/architecture.md#arch-05-node-composition-and-orchestration-boundary);
peer-visible inventory and relay behavior are defined in
[P2P compatibility](../../docs/policies/p2p-compatibility.md).

`PeerManager` owns DNS resolver and seed configuration and bootstraps outbound
addresses. Live session registration, replacement, metadata publication, and
identity-checked removal go through `PeerTable`, used by the inbound TCP
`listener` and connection-session paths. A connection is identified by a
`ConnectionId` and cleaned up through a `PeerLease`. The `listener` module has one
entry point per role: `bind_listener` binds a local address, `serve` runs the accept
loop on that bound listener until shutdown, and `spawn_outbound_connection` dials one
peer. `serve` and `spawn_outbound_connection` read one cloneable `ConnectionShared`
wiring value per start epoch, which also owns the header, block, and transaction sinks. A connection negotiates
version/verack in `handshake`, then runs the peer finite-state machine in `fsm`;
`wire` is the protocol codec, decoding `Message` values and reporting `PeerError`. Inbound traffic reaches
the host through `dispatch_inbound_full`, which streams getdata responses
block by block behind the outbound budget's pre-load production headroom gate,
filters transaction inventory through the `TxInventory` trait, reads the
active chain through the `ChainQuery` trait, and receives the chain-owned
initial-block-download gate that the `listener` supplies to it through its
`tx_relay_open` callback: while the gate is closed, transaction-typed `inv`
vectors are never requested and `tx` bodies are dropped before ingress (Core
31.1 `net_processing.cpp:4401-4404`, `:4713-4716`); `inbound` hands over
`InboundBlock`,
`InboundHeaders`, and `InboundTx` with their delivering peer stamped. Manual bans
exclude whole subnets as a `BannedSubnet` built from an `IpSubnet`, held in memory.
`wire` decodes BIP155 `addrv2` messages, and BIP339 wtxid-relay state lives in `wtxid`.

## Features

- `default` (enables `fjall`): build with the fjall storage backend selected.
- `rocksdb`: forward the rocksdb storage backend to `bitcoin-rs-storage`.
- `fjall`: forward the fjall storage backend to `bitcoin-rs-storage`.
- `redb`: forward the redb storage backend to `bitcoin-rs-storage`.

Part of [`bitcoin-rs`](../../README.md); see [`CONCEPTS.md`](../../CONCEPTS.md) for the
project vocabulary.
