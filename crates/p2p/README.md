# bitcoin-rs-p2p

The Bitcoin peer-to-peer network surface: the wire codec, peer lifecycle and
handshaking, the inbound message dispatcher, and peer and subnet banning.

`PeerManager` tracks each connected `Peer` and its `PeerState`; a connection is
identified by a `ConnectionId`, cleaned up through a `PeerLease`, and opened outbound
through `spawn_outbound_connection`, while the `listener` module accepts inbound TCP
connections with graceful shutdown. A connection negotiates version/verack in
`handshake`, then runs the peer finite-state machine in `fsm`; `wire` is the protocol
codec, decoding `Message` values and reporting `PeerError`. Inbound traffic reaches
the host through `dispatch_inbound_full`, which streams getdata responses
block by block behind the outbound budget's pre-load production headroom gate,
filters transaction inventory through the `TxInventory` trait, and reads the
active chain through the `ChainQuery` trait; `inbound` hands over `InboundBlock`,
`InboundHeaders`, and `InboundTx` with their delivering peer stamped. Misbehaving peers accumulate score
on the file-persisted `BanList` of the `banlist` module (`PeerInfo` publishes the
post-handshake metadata), whole subnets are excluded as a `BannedSubnet` built from an
`IpSubnet`, and BIP155 addrv2 and BIP339 wtxid-relay state live in `addrv2` and
`wtxid`.

## Features
- `default` (enables `fjall`): build with the fjall storage backend selected.
- `rocksdb`: forward the rocksdb storage backend to `bitcoin-rs-storage`.
- `fjall`: forward the fjall storage backend to `bitcoin-rs-storage`.
- `redb`: forward the redb storage backend to `bitcoin-rs-storage`.

Part of [`bitcoin-rs`](../../README.md); see [`CONCEPTS.md`](../../CONCEPTS.md) for the
project vocabulary.
