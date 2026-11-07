# BIP324 v2 transport and peer management

A connection becomes a peer only after two handshakes finish inside one deadline: the BIP324 v2 transport handshake, then the version and verack exchange. This chapter follows that path at code level: the key exchange and garbage terminator, packet encryption and length handling, the `v2transport` flag with its v1 fallback, the handshake-ordering rules that are stricter than Bitcoin Core, and the peer management around the connection: inbound eviction, netgroup keying and asmap, discouragement and ban timers, SOCKS dialing, and the relay offers the handshake negotiates. The wire contract is [docs/contracts/p2p-wire.md](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/p2p-wire.md) (`P2P-01`, `P2P-08`, `P2P-11`), and the Core comparison is [docs/policies/p2p-compatibility.md](https://github.com/gosuda/bitcoin-rs/blob/main/docs/policies/p2p-compatibility.md). The [peer-to-peer overview](p2p.md) owns the listener and drain threads; this chapter stays inside one connection and the table behind it.

## The key exchange

The v2 handshake is one ECDH round with secp256k1 keys encoded as 64-byte ElligatorSwift points, then a garbage-terminator scan on both sides. `bip324::Handshake` is a state machine with two constructors: `Handshake::initiator` starts in `ReadKey` and queues its key and garbage immediately; `Handshake::responder` starts in `DetectV1` and sends nothing until it has read 16 bytes (`crates/wire/src/bip324/handshake.rs:77` and `:91`).

```text
initiator                                        responder
ellswift(64) + garbage(0..=4095)  ---------->    DetectV1 on the first 16 bytes:
                                                 magic + "version" -> Step::V1
                                                 foreign magic     -> WrongNetworkV1
                                                 anything else     -> v2
                  <----------    ellswift(64) + garbage(0..=4095)
each side, once the peer key is complete (key_received):
                 queues own terminator(16) + empty sealed version packet
ScanTerminator scans the peer's garbage for its 16-byte terminator
version packet is opened with the peer's garbage as AEAD associated data
both sides reach Step::Established with the same 32-byte session id
```

Both sides call `shared_secret` with their party role (`crates/wire/src/bip324/keys.rs:17`), and `KeyMaterial::derive` expands seven outputs from HKDF-SHA256 salted with `bitcoin_v2_shared_secret` plus the 4-byte network magic (`keys.rs:45`): one length-cipher key and one packet-cipher key per direction, 32 bytes that split into the two 16-byte garbage terminators, and the session id (`keys.rs:69`). `Session::new` (`keys.rs:84`) hands each side its own direction and keeps the peer's terminator for scanning.

The garbage is not trusted by itself. The first sealed packet uses the sender's own garbage as its AEAD associated data, so a peer that fabricates garbage or sends none fails authentication on the version packet (`the_first_packet_must_authenticate_the_garbage_sent` in `crates/wire/src/bip324/handshake/tests.rs:440`). The terminator scan itself reads each inbound byte at most once: `partial_match` keeps only the longest suffix that could still complete the terminator (`handshake.rs:270`), and garbage longer than 4095 bytes fails with `BIP324 garbage terminator not found within the garbage limit` (`MAX_GARBAGE_LEN` at `handshake.rs:18`, `TransportError::TerminatorNotFound` at `crates/wire/src/bip324.rs`).

The session id is the only man-in-the-middle check BIP324 has. Both sides derive the same 32 bytes (`keys.rs:69`), comparing them out of band is the only detection there is, and BIP324 authenticates no peer, so a failed handshake never becomes a misbehavior report (`crates/wire/src/transport.rs`). `getpeerinfo` publishes the negotiated id in hex for exactly that comparison (`P2P-11`).

## Packets: length field, header byte, tag

After `Established`, every packet is an encrypted three-byte length field, a sealed one-byte header, sealed contents, and a 16-byte Poly1305 tag. The send side writes the little-endian length, encrypts it with the `FsChaCha20` length cipher, then seals header plus contents with `FsChaCha20Poly1305` (`crates/wire/src/bip324/packet.rs`). The header byte carries the ignore bit, `0x80`. A packet with that bit set authenticates and is then dropped: `PacketReader::read_contents` returns `None` and the connection keeps reading (`crates/wire/src/bip324/reader.rs:43`). That is the decoy mechanism, and the inbound loop treats `None` as no message rather than an error (`crates/wire/src/transport.rs`).

The receive side bounds memory before any body arrives. `decrypt_length` decrypts the three bytes and rejects contents above `MAX_RECV_CONTENTS_LEN = 1 + 12 + 4_000_000` with `BIP324 packet contents of N bytes exceed the receive limit` before the body is read (`reader.rs:13` and `:87`, `crates/wire/src/bip324.rs`). Both ciphers rekey automatically: `REKEY_INTERVAL = 224` at `crates/wire/src/bip324/cipher.rs:7`, and each cipher derives a fresh key once its counter reaches that value (`cipher.rs:40` and `:116`); the round-trip tests prove both ciphers keep working across repeated rekeys, and that failed decrypts advance the counter toward it (`cipher.rs:143`, `:163`, `:197`). A body interrupted by a poll timeout keeps only the bytes that arrived, and a length field split across reads decrypts exactly once (`a_length_field_split_by_a_timeout_decrypts_once` in `reader.rs:154`). One failed tag poisons the reader: every later packet on that connection fails, and none is accepted (`reader.rs:43`, `tag_failure_poisons_reader_so_subsequent_packets_are_never_accepted` in `reader.rs:239`).

Contents decode through a one-byte message-type table (`crates/wire/src/bip324/msg_type.rs:6`). Short ids 1 through 28 are assigned exactly as the BIP324 table fixes them, long form `0` carries the 12-byte v1 command for every other command, and short id 37 belongs to the draft `feature` command (`crates/wire/src/feature.rs:7`). An empty type or an unassigned id decodes to `None`, and the peer drops such a message without disconnecting (`msg_type.rs:75`). A v1 frame has no equivalent silence: it always carries a message.

## How v2 is chosen, and what a failed v2 attempt does

The `v2transport` flag is covered in [p2p.md](p2p.md): the node defaults it on, the library defaults it off, and the node advertises `NODE_P2P_V2` only while it is on. Per connection, the choice is narrower than the flag. `run_outbound_connection` starts v2 only for a manual dial or an automatic dial whose address-book entry advertises `P2P_V2`; everything else pins `ForceV1` and never sends a v2 key (`crates/wire/src/listener.rs`).

One 60-second deadline covers transport negotiation and the version handshake: `HANDSHAKE_TIMEOUT = Duration::from_mins(1)` (`listener.rs`). `transport::establish` checks lease cancellation and the deadline on every iteration and returns `Step::V1`, `Step::Established`, or an error (`crates/wire/src/transport.rs`).

Three outcomes exist for an outbound v2 attempt:

- The responder answers. Both sides complete the key exchange and enter the message loop with `transport_protocol_type` v2.
- The responder sends nothing. The dialer logs `p2p v2 handshake unanswered; retrying with v1 transport protocol` at debug level and redials once with `ForceV1`, with failure accounting suppressed so the address book does not punish a v1-only peer (`listener.rs`).
- The responder sends bytes that fail the handshake. The error ends the attempt with no v1 retry, and because transport errors are not in the misbehavior class, the address is not discouraged (`transport.rs`).

Inbound, `negotiate_inbound` (`listener.rs`) returns an all-v1 transport when the node runs with v2 off. Otherwise the responder sniffs the first 16 bytes. A v1 `version` under the node's own magic hands back `Step::V1` and the v1 decoder resumes from that prefix (`transport.rs`); a v1 `version` under a foreign magic fails with `peer sent a v1 version header for another network` (`crates/wire/src/bip324.rs`). Nothing is written to the socket before v1 is ruled out, so a v1 client never sees stray v2 bytes. A failed inbound negotiation logs `p2p inbound handshake failed` with the io error and closes the socket without discouragement.

## Version and verack: rules stricter than Core

The order is fixed. Outbound sends `version`, `wtxidrelay`, `sendaddrv2`, `sendheaders` (`crates/wire/src/handshake.rs`); inbound answers with the same four, loops until `Ready`, then sends `sendcmpct` after verack. A block-relay-only dial withdraws its package-relay offer before any message is queued.

The state machine in `crates/wire/src/fsm.rs` rejects messages that Core ignores, and [the compatibility policy](https://github.com/gosuda/bitcoin-rs/blob/main/docs/policies/p2p-compatibility.md) section 4 records that strictness as deliberate. Each rule below is one verified error string:

- A duplicate `version`, including before readiness, is `duplicate version message` and never replaces the accepted version or its receive timestamp (`fsm.rs:94`).
- `verack` before `version` is `verack received before version` (`fsm.rs:160`).
- A duplicate `verack` is `duplicate verack message` (`fsm.rs:163`).
- `wtxidrelay`, `sendaddrv2`, `sendheaders`, `sendcmpct`, or `sendpackages` before `version` is `negotiation message received before version` (`fsm.rs:170`).
- A negotiation message after the peer's verack is `negotiation message received outside the version-to-verack window` (`fsm.rs:143`).
- Any non-handshake message before readiness is `message received before handshake completed` (`fsm.rs:79`).

Every one of these is `PeerError::Misbehavior`, the class that can discourage an address. Two releases exist. Protected connections, manual or `noban`, ignore the violation and stay under the same deadline; the log line then reads `protected peer protocol violation ignored` (`crates/wire/src/handshake.rs`). And the BIP434 `feature` command is accepted only inside the version-to-verack window and only from a peer that advertised version 70017 or higher; below that it is `feature received from a peer below the feature protocol version` (`fsm.rs:117`).

## The peer table and inbound eviction

`PeerTable` is one write-locked map keyed by endpoint identity: canonical IP, Tor v3, or I2P destination; a loopback SOCKS or SAM hop is never the identity (policy section on overlay transports). Reservation, live inbound count, and eviction are one table operation: `try_register_inbound` (`crates/wire/src/peer_table.rs:202`) counts live inbound sessions against `max_inbound` and runs eviction in the same critical section. A newcomer whose address holds a live inbound session replaces that predecessor without growing the count; a live outbound session at the same address makes the newcomer count as growth, so a full table refuses it rather than dropping two connections for one (`a_full_table_refuses_an_inbound_newcomer_at_a_live_outbound_address` in `crates/wire/src/peer_table/tests.rs:628`).

Eviction has a fixed candidate filter: inbound, live, and not `noban` (`peer_table.rs:312`). If no candidate survives the filter, or the newcomer itself would replace a live outbound, the socket closes before any handshake thread exists. The chosen victim's lease is cancelled, so its reads fail mid-payload, and the table logs `inbound slots full; evicted a connection for a new inbound peer` at debug level (`peer_table.rs:308`).

`select_inbound_to_evict` (`crates/wire/src/eviction.rs:19`) sorts candidates newest-first and applies Core's protection passes in order:

1. Four by keyed netgroup.
2. Four by most recent mempool-accepted transaction delivery.
3. Eight block-relay-only peers with wanted services, by most recent committed block.
4. Four by most recent committed block.
5. Half of the rest by uptime, with a localhost quota of a quarter of the initial candidates (`protect_by_ratio`, `eviction.rs:74`).

Whatever survives loses its newest member of the largest remaining netgroup (`eviction.rs:99`). Each pass has a test that pins it: `the_flooding_netgroup_loses_its_newest_member` (`eviction.rs:158`), `a_recent_transaction_protects_a_connection` (`eviction.rs:166`), `a_recent_block_protects_a_connection` (`eviction.rs:174`), and `a_block_relay_only_peer_with_wanted_services_is_protected` (`eviction.rs:182`). Twelve plain candidates are all protected, so nothing is evicted until the thirteenth arrives (`eviction.rs:147`). One recorded deviation from Core remains: eviction has no minimum-ping protection because the node measures no ping RTT (contract `P2P-08` scope note, policy section 7 item 12).

## Netgroups and asmap

The netgroup is the unit that eviction and address-book bucketing spread peers over. `NetGroups::group` (`crates/wire/src/netgroup.rs:162`) returns prefix groups when no asmap is loaded: `vec![0]` for unroutable addresses, `[1, a, b]` for IPv4 or IPv4-linked addresses keyed on the /16, `[2, four bytes]` for IPv6 keyed on the /32 with one extra byte for the 2001:470::/32 range, `[4, key[0] | 15]` for onion, and `[5, hash[0] | 15]` for I2P (`prefix_group`, `netgroup.rs:86`). IPv4-mapped IPv6 is canonicalized first, so both spellings land in one group (`canonical_ip`, `netgroup.rs:4`).

`--asmap` swaps prefix groups for autonomous system numbers. `NetGroups::load` (`netgroup.rs:127`) reads at most 4 MiB, validates the bytecode with an independent interpreter, and stores the sha256 as the map identity. A good file logs `ASMap netgroup classifier active` with its hash; a bad or oversized file logs `ASMap unavailable; using IP prefix netgroups` and the node keeps running on prefixes (`netgroup.rs:133`). The eviction key is not the group bytes themselves: `PeerTable` hashes them through a per-process `RandomState` (`peer_table.rs:119`), so the largest-group computation is stable within one run and unpredictable from outside (`keyed_netgroup` at `peer_table.rs:232`).

## Discouragement and manual bans

Automatic discouragement holds canonical exact IPs, at most `MAX_DISCOURAGED_IPS = 4096` of them for `DISCOURAGEMENT_LIFETIME` of one hour (`crates/wire/src/discouragement.rs:10`). The structure is a deadline map plus a FIFO of insertion order. Repetition neither refreshes the deadline nor adds an entry, and at the capacity bound the oldest entry is dropped (`discouragement.rs:32`).

`note_misbehavior` (`crates/wire/src/listener.rs`) discourages only when all of these hold: the error is a misbehavior-class failure, the session is not cancelled, the network is active, the lease is not protected, and the address is not local. The warn line `peer protocol violation` carries the decision as fields, `peer_addr`, `node_id`, `error`, `protected`, `local`, and `discouraged`, so an operator can tell an enforcement from an exemption by reading one line.

Manual bans are a separate list of `BannedSubnet { subnet, banned_until: Option<SystemTime>, ban_created, reason }` (`crates/wire/src/subnet.rs:15`). `is_banned` compares `banned_until` against now, so a subnet with no expiry bans until the operator clears it (`subnet.rs:129`). `listbanned` and `clearbanned` see only this manual list; the discouraged set is process-local and bounded (`P2P-02`, policy section 6). Two verified Core differences: Core keeps a rolling Bloom filter of 50,000 elements with no expiry where this table keeps 4,096 canonical IPs for one monotonic hour, and Core's eviction adds a minimum-ping protection pass that this node cannot run because it measures no ping RTT (policy sections 6 and 7).

## SOCKS and proxy dialing

Route selection happens before any socket opens. `DialRoutes` carries `proxy`, `onion`, `proxy_randomize_credentials`, the SAM session, and the `onlynet` list (`crates/wire/src/endpoint.rs:214`), and `RouteTable::denial` (`endpoint.rs:261`) rejects an endpoint with `NotInOnlynet`, `NoOnionRoute`, or `NoI2pRoute` before dialing.

`connect_peer_stream` (`endpoint.rs:335`) picks one of three transports. An IP endpoint with `--proxy` configured goes through `socks_connect`, or through `socks_connect_isolated` when `--proxy-randomize-credentials` is set; the isolated variant offers username/password authentication with random base32 credentials, and refuses a proxy that answers no-auth (`socks.rs:187`). A Tor v3 endpoint dials its `<base32>.onion` name through `--onion-proxy` or `--proxy`, always with isolated credentials (`endpoint.rs:369`). An I2P endpoint goes through the SAM session and never through SOCKS.

SOCKS replies split into two failure classes (`DialFailure`, `endpoint.rs:286`). Reply code `0x05`, connection refused at the target, becomes `PeerUnreachable`, which counts as a peer failure for address-book retry accounting. Every other protocol failure is a local transport failure and does not count against the peer. Reply codes map onto io error kinds: `0x02` permission denied, `0x03` and `0x04` network unreachable, `0x05` connection refused, `0x06` timed out, anything else connection aborted (`reply_kind`, `crates/wire/src/socks.rs:335`).

TCP_NODELAY is best effort through a proxy and required on a direct dial. `socks_connect_with` calls `set_nodelay(true)` and drops the result (`socks.rs:278`); a failed direct dial never starts, because `configure_peer_stream` propagates the error (`listener.rs`). After the CONNECT reply succeeds, the per-exchange timeouts are cleared so the proxy deadline does not leak into the peer session (`socks.rs:323`).

## Relay and package policy hooks

The handshake negotiates three optional relay behaviors, all default off, all confined to the version-to-verack window. `RelayOffers` (`crates/wire/src/listener.rs`) carries `package_relay`, `stale_tip_relay`, and `stale_tip_prefers_blocks`, set from `--p2p-package-relay` and the stale-tip flags (`crates/node/src/config.rs`). `offer_relay_capabilities` offers `PKG_RELAY_PKGTXNS | PKG_RELAY_ANC` only on roles that relay transactions.

Package relay is the BIP331 draft with no Core 31.1 equivalent. The hooks sit in the tx relay layer, not the transport: a transaction held for missing parents requests `ancpkginfo` with `getdata(MSG_ANCPKGINFO)` (`crates/node/src/p2p/tx_policy.rs:993`); a `notfound` for that type releases the solicitation and falls back to `getdata` of the parent txids (`transaction_not_found`, `tx_policy.rs:942`); `getdata` of `MSG_PKGTXNS` is misbehavior on every connection because that type is notfound-only, and list messages without the negotiated bit are misbehavior too (`crates/wire/src/dispatch.rs:416` and `:423`).

BIP332 stale-tip relay rides the BIP434 `feature` command: one announcement with identifier `BIP332` and a one-byte `prefers_blocks` value, short id 37 on v2 (`crates/wire/src/feature.rs:78`). Decode bounds are fixed: identifier 4 to 80 bytes, data at most 512, non-minimal CompactSize rejected (`feature.rs:9` through `:13`). A peer may repeat an identifier; the first valid announcement wins and later ones are ignored (`fsm.rs:117`).

## A worked trace: one pair of regtest nodes, v2 then v1

Two throwaway regtest nodes from one build at this commit. The listening node binds `--p2p-listen 127.0.0.1:0`, so the log reports the configured address and the real port comes from `ss -tlnp`; both data directories are `$DATA`.

```console
$ ./target/release/bitcoin-rs --network regtest --data-dir $DATA/a --p2p-listen 127.0.0.1:0 \
    --rpc-bind 127.0.0.1:0 --dns-seeds-enabled false
$ ss -tlnp | grep 'pid=<listener-pid>'
LISTEN 0 128 127.0.0.1:38437  0.0.0.0:*
LISTEN 0 128 127.0.0.1:39989  0.0.0.0:*
```

The same pid holds two loopback listeners: the startup log reports `rpc listener bound` on 127.0.0.1:39989, so the p2p port is 38437. Then dial it from the second node:

```console
$ ./target/release/bitcoin-rs --network regtest --data-dir $DATA/b --p2p-listen 127.0.0.1:0 \
    --rpc-bind 127.0.0.1:0 --dns-seeds-enabled false --connect 127.0.0.1:38437
```

The dialing node logs its outbound session, the listening node the inbound one, both v2:

```text
{"level":"INFO","fields":{"message":"p2p handshake complete; entering message loop","peer_addr":"127.0.0.1:38437","inbound":false,"transport":"v2"},"target":"bitcoin_rs_p2p::listener"}
{"level":"INFO","fields":{"message":"p2p handshake complete; entering message loop","peer_addr":"127.0.0.1:44582","inbound":true,"transport":"v2"},"target":"bitcoin_rs_p2p::listener"}
```

Repeating the second command with `--v2transport=false` on the dialing node leaves the listening node untouched. The listening node still sniffs per connection and accepts the v1 starter:

```text
{"level":"INFO","fields":{"message":"p2p handshake complete; entering message loop","peer_addr":"127.0.0.1:38437","inbound":false,"transport":"v1"},"target":"bitcoin_rs_p2p::listener"}
{"level":"INFO","fields":{"message":"p2p handshake complete; entering message loop","peer_addr":"127.0.0.1:38002","inbound":true,"transport":"v1"},"target":"bitcoin_rs_p2p::listener"}
```

A peer that connects and closes before answering produces the inbound failure line with no discouragement:

```text
{"level":"WARN","fields":{"message":"p2p inbound handshake failed","peer_addr":"127.0.0.1:52216","error":"io error: unexpected end of file"},"target":"bitcoin_rs_p2p::listener"}
```

The decoder behind the v2 half runs under cargo. This test seals one decoy packet with the ignore bit, then a real packet, and asserts the reader yields `None` for the decoy and the payload for the real one:

```console
$ cargo test -p bitcoin-rs-p2p a_decoy_packet_yields_none_and_the_next_packet_still_arrives -- --nocapture
test bip324::reader::tests::a_decoy_packet_yields_none_and_the_next_packet_still_arrives ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 1308 filtered out; finished in 0.00s
```

## Where it is proven

Contract `P2P-11` owns v2 negotiation and the key schedule, `P2P-08` owns inbound admission and eviction, `P2P-04` owns `TCP_NODELAY` and vectored writes, and `P2P-01` owns wire framing compatibility, all in [docs/contracts/p2p-wire.md](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/p2p-wire.md). Policy sections 4, 6, and 7 own the strictness rules, the discouragement comparison, and the deviation ledger. The live Core evidence covers v2 negotiation, matching session ids, ping, and full sync in both directions against unmodified Core 31.1; the v1 retry after an unanswered v2 dial, decoy packets, and rekeying rest on in-tree tests only ([trust/bip-support.md](../trust/bip-support.md) records that split).

The in-tree proofs behind this chapter, each verified in the tree at this commit:

| Invariant | Test | File |
| --- | --- | --- |
| An outbound v2 dial negotiates BIP324 | `an_outbound_v2_dial_negotiates_bip324` | `crates/wire/src/listener/v2_transport_tests.rs` |
| An unanswered v2 dial retries once over v1 | `an_unanswered_v2_dial_retries_once_over_v1` | `crates/wire/src/listener/v2_transport_tests.rs` |
| A silent responder ends at the deadline | `a_silent_responder_ends_at_the_handshake_deadline` | `crates/wire/src/listener/v2_transport_tests.rs` |
| A v1 starter hands back to the v1 decoder | `responder_hands_a_v1_peer_back_after_sixteen_bytes` | `crates/wire/src/bip324/handshake/tests.rs` |
| Garbage beyond the limit is refused | `garbage_beyond_the_limit_is_refused` | `crates/wire/src/bip324/handshake/tests.rs` |
| Decoys before the version packet are skipped | `decoys_before_the_version_packet_are_skipped` | `crates/wire/src/bip324/handshake/tests.rs` |
| A tag failure poisons the reader | `tag_failure_poisons_reader_so_subsequent_packets_are_never_accepted` | `crates/wire/src/bip324/reader.rs` |
| A flooding netgroup loses its newest member | `the_flooding_netgroup_loses_its_newest_member` | `crates/wire/src/eviction.rs` |
| A full table yields to a different netgroup | `one_host_filling_every_inbound_slot_gives_way_to_another_netgroup` | `crates/wire/src/peer_table/tests.rs` |
| `noban` inbound connections are never evicted | `noban_inbound_connections_are_never_evicted` | `crates/wire/src/peer_table/tests.rs` |
| Manual and protected peers never discourage | `manual_and_protected_local_connections_never_discourage_an_ip` | `crates/wire/src/listener/discouragement_tests.rs` |

The peer_table tests above exercise `PeerTable` directly with leases and offers; the eviction unit tests in `eviction.rs` cover the pure selection function with synthetic candidates. Neither loads an asmap; `different_prefixes_in_one_asn_share_a_group_and_invalid_files_fall_back` in `netgroup.rs:391` covers the asmap interpreter against Core's published vectors.

Not exercised here: the trace never crossed a rekey interval, so rekeying rests on the cipher unit tests (`length_cipher_round_trips_across_rekeys`, `packet_cipher_round_trips_across_rekeys` in `crates/wire/src/bip324/cipher.rs`), the maximum-garbage and terminator paths are covered by unit tests rather than a live peer, and the trace ran on regtest loopback only.
