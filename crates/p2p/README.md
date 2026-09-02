# bitcoin-rs-p2p

The Bitcoin peer-to-peer network surface: the wire codec, peer lifecycle and
handshaking, inbound dispatch, connection management, and block-download policy.

Each `Peer` owns one connection's stream and handshake state. Live connections are
identified by a `ConnectionId`, cleaned up through a `PeerLease`, and tracked with
ready metadata by the shared `PeerLifecycle`. `P2pService` owns that lifecycle,
network controls, bootstrap/dial workers, and the source-bearing download window;
the node supplies chain queries and coordinates chain application. A connection
negotiates version/verack in `handshake`, then runs the peer finite-state machine
in `fsm`; `wire` is the protocol codec. Inbound traffic reaches the host through
`dispatch_inbound_with_chain`, which streams getdata responses behind the outbound
budget's pre-load production headroom gate and reads the active chain through the
`ChainQuery` trait; `inbound` hands over `InboundBlock` and `InboundHeaders` with
their wire bytes preserved. Misbehaving peers accumulate score on the file-persisted
`BanList`; whole subnets are excluded as a `BannedSubnet` built from an `IpSubnet`,
and BIP155 addrv2 and BIP339 wtxid-relay state live in `addrv2` and `wtxid`.

## Features
- `default` (enables `fjall`): build with the fjall storage backend selected.
- `rocksdb`: forward the rocksdb storage backend to `bitcoin-rs-storage`.
- `fjall`: forward the fjall storage backend to `bitcoin-rs-storage`.
- `redb`: forward the redb storage backend to `bitcoin-rs-storage`.

Part of [`bitcoin-rs`](../../README.md); see [`CONCEPTS.md`](../../CONCEPTS.md) for the
project vocabulary.
