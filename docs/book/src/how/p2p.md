# Peer-to-peer networking

Inbound peers enter through a listener; outbound peers are redialed by one drain thread from the address book, feelers, and pinned peers. Both paths end in the same handshake and peer machine, and the node negotiates BIP324 v2 transport by default.

The wire protocols live in [`crates/wire`](https://github.com/gosuda/bitcoin-rs/tree/main/crates/wire), and sync, dispatch, and orchestration live in [`crates/node/src/p2p`](https://github.com/gosuda/bitcoin-rs/tree/main/crates/node/src/p2p). Wire compatibility and deviations are owned by [docs/contracts/p2p-wire.md](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/p2p-wire.md) and [docs/policies/p2p-compatibility.md](https://github.com/gosuda/bitcoin-rs/blob/main/docs/policies/p2p-compatibility.md).

```text
                     inbound                         outbound
TcpListener::bind  --accept-->  admit_inbound     drain thread (1 s tick)
                                   |                   |
                              PeerTable             address book / feeler
                                   |                   |
                             handshake thread      dial thread
                                   |                   |
                                   +---- transport ----+
                                   |
                          v2 (BIP324) or v1 framing
                                   |
                             peer message loop
                                   |
                    dispatch -> sync / mempool / header admission
```

## Listener

`bind_listener` binds each configured `p2p.listen` address. The accept loop backs off from 100 ms to 10 seconds on accept errors and never exits on a transient one. Each accepted socket enters `admit_inbound`, which registers it in `PeerTable` under the connection cap and may evict an existing inbound peer. The accept loop is the only inbound caller (`P2P-08`).

Admission is not acceptance. A peer that exceeds the cap or loses the eviction choice is closed before handshake work starts.

The listener log reports the configured address, not the bound one:

```text
{"level":"INFO","fields":{"message":"p2p listener bound","addr":"127.0.0.1:0"},"target":"bitcoin_rs_wire::service"}
```

A `:0` entry therefore does not reveal the chosen port in the log.

## Outbound

One thread named `bitcoin-rs-wire-outbound-drain` ticks every second. Each tick reaps finished dials, retires extra full-relay connections every 45 seconds, and starts dials for parked work when capacity frees. The default slot counts are 8 full-relay peers, 2 block-relay-only peers, and 200 total connections.

Automatic peers have no per-peer retry timer. The drain re-selects from `AddressBook` each tick. Pinned and manual peers retry from 1 second up to 60 seconds, with the delay reset when the peer is seen ready. A dial runs on its own thread and carries `DialPurpose::{Regular, Feeler, Anchor}`.

A v2 dial that receives no handshake bytes retries once over v1 with failure accounting suppressed. That covers a peer that cannot speak BIP324 but is otherwise reachable.

## BIP324 v2 transport

The node enables v2 by default: `config.p2p.v2_transport` defaults to true, and the node advertises the `P2P_V2` service bit when it is on. `--v2transport=false` pins v1 for that node's connections.

The library default is the opposite. `P2pServiceConfig::default()` leaves `v2_transport` false, and `ConnectionShared` defaults it false too. A library caller that builds `P2pService` directly must opt in. The node always sets the field from config, so a daemon gets v2 unless the operator disables it.

Outbound transport choice uses v2 only for manual peers or peers whose address-book entry advertises `P2P_V2`; everything else starts with `ForceV1`. The transport loop checks the handshake deadline on every iteration and returns either `Step::V1` or `Step::Established`. The key schedule, ciphers, handshake machine, and packet reader live in `crates/wire/src/bip324` (`P2P-11`).

Two regtest nodes from this build complete a v2 handshake:

```text
{"level":"INFO","fields":{"message":"p2p handshake complete; entering message loop","peer_addr":"127.0.0.1:34899","inbound":false,"transport":"v2"},"target":"bitcoin_rs_wire::listener"}
{"level":"INFO","fields":{"message":"p2p handshake complete; entering message loop","peer_addr":"127.0.0.1:42156","inbound":true,"transport":"v2"},"target":"bitcoin_rs_wire::listener"}
```

With `--v2transport=false` on the dialing node, the same pair logs `"transport":"v1"` on both sides.

## Handshake strictness

The handshake has one absolute 60 second deadline covering transport negotiation and the version handshake. A silent responder is closed at the deadline; `a_silent_responder_ends_at_the_handshake_deadline` pins that behavior.

Several rules are stricter than Bitcoin Core, and the code keeps them:

- A duplicate `verack`, or `sendheaders`, `sendaddrv2`, `sendcmpct`, or `wtxidrelay` before `version`, disconnects and discourages the peer. Core ignores these.
- Any non-handshake message before readiness disconnects. Core allows `sendtxrcncl`.
- A checksum failure disconnects and discourages. Core's v1 decoder resets.
- An empty `getblocktxn` index list disconnects. Core accepts it.
- `feature` is accepted only between `version` and `verack`, and only from peers at version 70017 or higher.

The advertised version is 70017; Core 31.1 advertises 70016. That is a recorded deviation, not a strictness rule. Protected connections (manual or `noban`) ignore recoverable violations under the same deadline.

The reject-or-ignore matrix is owned by [the compatibility policy](https://github.com/gosuda/bitcoin-rs/blob/main/docs/policies/p2p-compatibility.md).

## Misbehavior and bans

There is no numeric misbehavior score and no ban-threshold setting. A typed protocol violation discourages the remote IP for one hour. The discouraged set holds at most 4096 addresses with FIFO eviction, and automatic dials and inbound policy checks consult it before connecting.

`note_misbehavior` discourages only when the error is a misbehavior class, the lease is current, the peer is not protected, and the address is not local. A stale lease cannot punish an address that the connection no longer represents.

Manual bans are separate. Operator bans exclude whole subnets from an `IpSubnet`, and `--p2p-noban` marks subnets as protected from discouragement. The ban list is an in-memory structure owned by `P2pService`; the RPC surface reads and mutates it through service control methods (`P2P-02`).

## Message loop and budgets

Each connection has one reader and one writer. The writer coalesces a ready burst into one vectored write. Every queued data message is a `QueuedFrame` charged against both the connection's own limits (4,096 messages and 16 MiB, one quarter of the aggregate) and the node's shared 64 MiB outbound queue cap (`SHARED_OUTBOUND_QUEUE_MAX_BYTES`). Node-originated control frames, today only the keepalive `ping`, charge a separate bounded control lane of 8 messages and 64 KiB instead of the per-connection data budget; they still charge the shared aggregate, so nothing is exempt. The writer channel stays strict FIFO with no control priority: a probe admitted while data is queued joins behind it.

The keepalive owes its first `ping` on a connection's first message-loop pass after the handshake, then one probe per 2 minutes of send-or-receive silence with a fresh nonce. A refused probe stays owed and drains ahead of deferred replies once room returns; already-queued data keeps its order. Lane-full or dead-writer refusals are connection-local congestion: the probe is deferred, not lost, and the congestion is not a keepalive stall.

Send silence comes from the socket, not the queue. The writer's stream accounting stamps the lease's send-activity clock at the exact point the socket accepts bytes, and the message loop reads that clock each pass, so an admitted-but-unwritten frame never masks a stalled writer. With a stalled writer and live inbound traffic the connection still expires after `TIMEOUT_INTERVAL` (20 minutes) of silence following its last actual write.

When the shared cap is reached, the node stops accepting more queued work. That is backpressure, not a ban: getdata service defers requests and parks unserved work, and the connection lease stays alive. A slow reader therefore slows its own service without cancelling the peer or growing memory without bound (`P2P-04`, `P2P-07`).

## Compact blocks

BIP152 high-bandwidth mode goes to at most 3 peers. `fill_high_bandwidth_slots` sorts eligible peers by announcement sequence and sends `sendcmpct` with the compact version, rebalancing when a peer disconnects.

Reconstruction is bounded:

- 4 pending reconstructions, 8 MiB of retained bytes, 1 minute per pending item, 128 requested missing transactions.
- Prefills and mempool hints fill what they can. Missing slots produce one `getblocktxn`.
- A completed block is accepted only after the merkle root matches. A 64-byte transaction mutation is rejected.
- Any limit breach falls back to a full `getdata`.

Serving `getblocktxn` validates that indexes increase and that the list is non-empty. A violation disconnects the requester, and service runs only under the outbound headroom gate.

## Address book

`AddressBook` keeps 1024 new buckets and 256 tried buckets of 64 entries each. Entries older than 30 days are stale, gossip is capped at 32 addresses per message with a 24 hour cache, and at most 2 anchor peers are kept for 7 days. The file name includes the network magic, so networks cannot load each other's address book.

Wire ingress is bounded: `addr` and `addrv2` messages accept at most 1000 entries and 32 per connection.

## Header sync

`BlockSync` owns header requests. A request goes to one selected peer, records `AwaitingResponse`, and times out after 5 seconds. A timeout disconnects the source rather than leaving a stalled request in place. A chain-sync probe fires after 20 minutes without progress, and up to 4 outbound peers are protected from eviction while syncing.

Inbound headers pass through `HeadersSyncState::process`, which decides presync, redownload, or final phase. Only admitted headers reach `Chainstate::admit_headers`. The sync contract is [docs/contracts/synchronization.md](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/synchronization.md) (`SYNC-01` through `SYNC-07`).

## Contract clauses

| Clause | Rule |
| --- | --- |
| `P2P-01` | Wire framing and handshake compatibility against the pinned Core version |
| `P2P-02` | Connection lifecycle and lease ownership |
| `P2P-03` | Best-known-height credit rises monotonically and only through the delivering connection |
| `P2P-04` | Connected sockets set `TCP_NODELAY`, forward vectored writes, and count each inbound frame under its command name |
| `P2P-05` | A headers response before its deadline marks the request queued without granting credit |
| `P2P-06` | The header carried in every inbound body reaches header admission |
| `P2P-07` | Block announcements lead with headers and never trigger a body request |
| `P2P-08` | The accept loop is the sole inbound admission caller |
| `P2P-09` | Block-body service eligibility has one predicate |
| `P2P-10` | Header presync is the sole admission decider |
| `P2P-11` | BIP324 negotiation and key schedule ownership |

## Tests that pin p2p

| Invariant | Test | File |
| --- | --- | --- |
| An outbound v2 dial negotiates BIP324 | `an_outbound_v2_dial_negotiates_bip324` | [`crates/wire/src/listener/v2_transport_tests.rs`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/wire/src/listener/v2_transport_tests.rs) |
| A silent responder ends at the deadline | `a_silent_responder_ends_at_the_handshake_deadline` | [`crates/wire/src/listener/v2_transport_tests.rs`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/wire/src/listener/v2_transport_tests.rs) |
| An unanswered v2 dial retries over v1 | `an_unanswered_v2_dial_retries_once_over_v1` | [`crates/wire/src/listener/v2_transport_tests.rs`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/wire/src/listener/v2_transport_tests.rs) |
| Manual and protected peers never discourage an IP | `manual_and_protected_local_connections_never_discourage_an_ip` | [`crates/wire/src/listener/discouragement_tests.rs`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/wire/src/listener/discouragement_tests.rs) |
| Missing compact-block transactions complete through `getblocktxn` | `missing_tx_requests_getblocktxn_and_completes_on_blocktxn` | [`crates/wire/src/compact_blocks/tests.rs`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/wire/src/compact_blocks/tests.rs) |
| Invalid `getblocktxn` indexes disconnect | `invalid_getblocktxn_indexes_disconnect` | [`crates/wire/src/dispatch/tests.rs`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/wire/src/dispatch/tests.rs) |
| A same-address reconnect does not inherit a stalled request | `same_address_reconnect_does_not_inherit_stalled_inflight` | [`crates/node/src/p2p/sync/tests/header_rotation.rs`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/node/src/p2p/sync/tests/header_rotation.rs) |

The [architecture](architecture.md) chapter shows where a staged block goes next, and the [mempool](mempool.md) chapter covers transaction relay after admission.
