# bitcoin-rs-p2p

The Bitcoin peer-to-peer network surface: the wire codec, peer lifecycle and
handshaking, the live peer session table, the inbound message dispatcher, and peer and subnet banning.

`PeerTable` is the single authoritative owner of live peer sessions (`PeerSession`),
connection control leases (`PeerLease`), and post-handshake metadata (`PeerInfo`).
It enforces key invariants across the node:
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

`PeerManager` owns DNS resolver and seed configuration and bootstraps outbound
addresses. Live session registration, replacement, metadata publication, and
identity-checked removal go through `PeerTable`, used by the inbound TCP
`listener` and connection-session paths. A connection is identified by a
`ConnectionId`, cleaned up through a `PeerLease`, and opened outbound through
`spawn_outbound_connection`, while the `listener` module accepts inbound TCP connections
with graceful shutdown. A connection negotiates version/verack in `handshake`, then runs
the peer finite-state machine in `fsm`; `wire` is the protocol codec, decoding `Message`
values and reporting `PeerError`. Inbound traffic reaches the host through
`dispatch_inbound_with_chain`, which streams getdata responses block by block behind the
outbound budget's pre-load production headroom gate and reads the active chain through
the `ChainQuery` trait, a read-only view for server-side responders; `inbound` hands
over `InboundBlock` and `InboundHeaders` with their wire bytes preserved. Misbehaving peers
are tracked via the file-persisted `BanList` of the `banlist` module, whole subnets are
excluded as a `BannedSubnet` built from an `IpSubnet`, and BIP155 addrv2 and BIP339
wtxid-relay state live in `addrv2` and `wtxid`.

## Features
- `default` (enables `fjall`): build with the fjall storage backend selected.
- `rocksdb`: forward the rocksdb storage backend to `bitcoin-rs-storage`.
- `fjall`: forward the fjall storage backend to `bitcoin-rs-storage`.
- `redb`: forward the redb storage backend to `bitcoin-rs-storage`.

Part of [`bitcoin-rs`](../../README.md); see [`CONCEPTS.md`](../../CONCEPTS.md) for the
project vocabulary.
