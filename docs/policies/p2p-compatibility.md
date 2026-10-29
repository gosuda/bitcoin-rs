# P2P Compatibility Policy

This document declares bitcoin-rs's peer-wire compatibility contract with Bitcoin Core and the rules for keeping it pinned.

## 1. Scope and Authority

This policy applies to the P2P transport and peer-protocol surface of `bitcoin-rs-p2p` (`crates/p2p`), including `ActiveChainQuery` (`crates/p2p/src/chain_query.rs`), and the network flags of the node binary. It is the peer-visible counterpart to `docs/policies/source-compatibility.md` (toolchain) and the RPC compatibility manifest (`crates/rpc/src/manifest.rs`, rendered as `docs/rpc-reference.md`).

The decoded command inventory is owned by `crates/p2p/src/compat.rs` (`COMMANDS`, `PINNED_CORE_VERSION`). This document owns the handshake fields, the reject-or-ignore matrix, the deviation ledger, and the verification process. Where this document and prose comments disagree, this document wins; where it and the code disagree, the code is the defect. The §5 table is a hand-maintained projection of `COMMANDS`, updated in the same change-set as the table it projects.

## 2. Pinned Reference Version

| Setting | Value |
| :--- | :--- |
| Reference implementation | Bitcoin Core |
| Pinned version | **31.1** (`crates/p2p/src/compat.rs::PINNED_CORE_VERSION`) |
| Protocol version advertised | `70017` (`crates/p2p/src/wire.rs::PROTOCOL_VERSION`); Core 31.1 advertises `70016` (§7, item 18) |
| Transport | BIP324 v2 by default with v1 detection and fallback; `--v2transport=false` keeps every connection on v1 (§7) |

### 2.1 Version-Bump Rules

Re-pinning to a newer Core version requires all of:

1. A passing run of `scripts/run-p2p-core-interop.sh` against the new version, with evidence stored under `docs/benchmarks/`.
2. A diff of the peer-protocol message set (below) against the new version's `net_processing`, with every delta either implemented or added to the deviation ledger (§7).
3. Updating this document's pin, `crates/p2p/src/compat.rs::COMMANDS`, and the deterministic fixtures in the same change-set — no intermediate states where the table and the code disagree (anti-shim rule, `docs/policies/source-compatibility.md` §5). The fuzz target `p2p_message` consumes `COMMANDS` directly.

## 3. Transport and Envelope

- Bitcoin P2P **v1 envelope**, used with v2 off or with a v1-only peer (`crates/p2p/src/wire.rs`): 4-byte network magic, 12-byte NUL-padded command, `u32` little-endian payload length, 4-byte checksum (first 4 bytes of double-SHA256 of the payload), then the payload.
- BIP324 v2 is on by default (`--v2transport`, as Core's `-v2transport`), with key exchange, packet framing (message payloads capped at `MAX_MESSAGE_PAYLOAD`, `crates/p2p/src/bip324/reader.rs`) and v1 detection and fallback (`crates/p2p/src/transport.rs`, `bip324.rs`). Live interop with Core 31.1 in both connection directions is recorded (https://github.com/gosuda/bitcoin-rs/pull/1612, `docs/contracts/core-differential.md` CORE-06; §7).
- Message payload bound: `MAX_MESSAGE_PAYLOAD = 4,000,000` bytes (`crates/p2p/src/wire.rs`), Bitcoin Core's `MAX_PROTOCOL_MESSAGE_LENGTH`, on either transport. A v1 frame header declaring more is refused before its body is read, as Core does. No block serializes above this bound.
- Network magic and default ports come from `bitcoin_rs_primitives::Network` and are asserted equal to Core's constants per network (mainnet 8333, testnet3 18333, testnet4 48333, signet 38333, regtest 18444).
- Fork networks sharing a chain may override the message-start bytes with `--p2p-magic` (a bitcoin-rs extension; requires `--network mainnet` semantics and explicit `--connect` peers). Not a Core option; recorded as extension, not parity.

## 4. Handshake Contract

An outbound bitcoin-rs connection sends, in order: `version`, `wtxidrelay` (BIP339), `sendaddrv2` (BIP155), `sendheaders` (BIP130). An inbound connection receives `version` and answers with the same four messages, then `verack` completes readiness (`crates/p2p/src/handshake.rs`, `dispatch.rs`).

BIP434 `feature` announcements, when there are any, follow those messages and precede `verack` on both roles, and go only to a peer whose `version` is `70017` or higher (`crates/p2p/src/feature.rs`, `handshake.rs`). Local feature announcements are disabled by default: `RelayOffers::stale_tip_relay` defaults off, so `Peer::stale_tip_offer` stays `None` and `negotiated_features` is empty, and no `feature` frame ever reaches a peer below `70017`. When stale-tip relay is enabled, `ConnectionShared::offer_relay_capabilities` calls `Peer::offer_stale_tip_relay` with the configured `stale_tip_prefers_blocks` byte, and `negotiated_features` emits one `BIP332` announcement carrying that byte in the same slot (`crates/p2p/src/listener.rs`, `peer.rs`).


The `version` message pins:

| Field | Value | Core 31.1 comparison |
| :--- | :--- | :--- |
| `version` | `70017` | deviation: Core 31.1 advertises `70016`. `70017` is the BIP434 `feature` negotiation threshold; `getnetworkinfo.protocolversion` reports the same `wire::PROTOCOL_VERSION`. The `version` field inside `getheaders` is rust-bitcoin's `70001`, not this value |
| `services` | `NETWORK \| WITNESS`, or `NETWORK_LIMITED \| WITNESS` when `storage.prune_target_mb > 0`; adds `P2P_V2` while `v2transport` is on (the default) and `COMPACT_FILTERS` only when the optional filter index is ready | Core derives the base set from the prune setting (`init.cpp:2022-2026`): a pruned node never advertises `NODE_NETWORK`. `--blockfilterindex` defaults off and requires unpruned history. `BLOOM` remains unsupported. |
| `relay` | `true` on a full-relay connection, `false` on a block-relay-only dial | matches Core's per-connection preference (`PushNodeVersion`, `net_processing.cpp:1651-1689`) |
| `user_agent` | `/bitcoin-rs:<version>/` | distinct subver string; Core records it in `getpeerinfo.subver` |
| `timestamp` | `0` | deviation: we do not send a real clock; Core 31 does not misbehave-score time offsets (live interop evidence), but this remains a recorded deviation |
| `start_height` | current applied tip height | matches Core semantics |

Rules, each enforced by the FSM (`crates/p2p/src/fsm.rs`) and identical to Core's posture unless noted:

- `verack` before `version` → disconnect. Duplicate `version` after completion → disconnect (Core: misbehavior; ours: disconnect without ban scoring, §6).
- Any non-handshake message before readiness → disconnect. Core has the same rule except for a small handshake whitelist (`sendtxrcncl`); see §7 for the one practical divergence.
- After `verack`, unknown commands are ignored and the connection stays up — identical to Core's handling of unrecognized commands.
- A `feature` message is accepted only after the peer's `version` and before its `verack`, and only from a peer that advertised `70017` or higher; received before `version`, after `verack`, or from a lower-version peer it is a handshake-ordering violation (§6). A payload that is truncated, uses a non-minimal `CompactSize`, carries an identifier length outside 4 to 80 bytes or more than 512 data bytes, or leaves trailing bytes is an invalid decoded payload (§6). Identifier bytes are not otherwise restricted on receipt. Unknown identifiers, and invalid data for a recognised identifier, are ignored without disconnect. Only a recognised identifier with valid data is retained per peer, and for a repeated identifier the first valid announcement wins; today the only such identifier is `BIP332` with a one-byte `0` or `1` payload. Identifiers this node advertises are limited to printable ASCII (`0x20..=0x7e`).

## 5. Message Surface

The decoder types exactly the commands in `crates/p2p/src/compat.rs::COMMANDS` (**42**). That table is the authority for names; this section owns each command's status and is the Core-comparison commentary, kept in sync with `COMMANDS` by hand in the same change-set.

| Command | Status | Behavior and Core 31.1 comparison |
| :--- | :--- | :--- |
| `version` | negotiated | §4. |
| `verack` | negotiated | §4. |
| `wtxidrelay` | negotiated | BIP339. Sent in handshake; inbound marks the peer wtxid-relay capable. |
| `sendaddrv2` | negotiated | BIP155. Sent in handshake; inbound tracked. |
| `sendheaders` | negotiated | BIP130. Sent in handshake; inbound tracked. |
| `feature` | negotiated | BIP434, draft. One announcement carries a feature identifier and its data, each behind a minimal `CompactSize`; BIP324 short ID 37, no Core 31.1 equivalent. Exchanged between `version` and `verack` with peers at `70017` or higher; only a valid `BIP332` announcement is retained per peer (first valid wins), every other identifier is ignored; this node announces `BIP332` carrying its one-byte `prefers_blocks` value only when `RelayOffers::stale_tip_relay` is set (§4). Core 31.1 does not support BIP434, so there is no Core comparison. |
| `sendpackages` / `ancpkginfo` / `getpkgtxns` / `pkgtxns` | negotiated, opt-in | BIP331 draft, no Core 31.1 equivalent. Typed wire codec in `crates/p2p/src/packages.rs`: `sendpackages` is one little-endian `u64`; the three list messages carry a minimal `CompactSize` count of 1 to 100, then wtxids (`ancpkginfo`, `getpkgtxns`) or witness-serialized transactions (`pkgtxns`); `ancpkginfo` rejects a repeated wtxid. A malformed payload is an invalid decoded payload (§6). A received `pkgtxns` surfaces as its raw payload (`Message::PkgTxnsPayload`, at most `MAX_MESSAGE_PAYLOAD`) and its transactions are parsed only by the consumer that has charged the frame. The offer is default-off (`RelayOffers::package_relay`, `p2p_package_relay`): when set the node sends one `sendpackages` carrying both `PKG_RELAY_PKGTXNS \| PKG_RELAY_ANC` bits between `version` and `verack` on relaying roles only, withdrawn for block-relay-only (`crates/p2p/src/listener.rs`, `handshake.rs`). Relay is the intersection of known bits both sides sent, active only once the handshake completes with the peer's `wtxidrelay` before `verack` and `fRelay` in its `version`; the peer's first `sendpackages` wins, `0`/unknown bits are ignored, and a `sendpackages` after `verack` is a protocol violation that changes nothing, with no protocol-version floor and no BIP434 mapping (`crates/p2p/src/peer.rs`, `fsm.rs`). `ancpkginfo` requires the `ANC` bit and `getpkgtxns`/`pkgtxns` require the `PKGTXNS` bit, otherwise rejected as `Misbehavior` (§6); a `getdata` for `MSG_PKGTXNS` is likewise rejected as `Misbehavior` (that type is `notfound`-only, never served) and `inv` of a package-relay-only type is rejected as `Misbehavior` (`crates/p2p/src/dispatch.rs`). Outbound, a transaction held for missing parents sends `getdata(MSG_ANCPKGINFO)` only to a peer that published `PKG_RELAY_ANC` and awaits its `ancpkginfo`, otherwise it falls back to `getdata` of the missing parents, and the follow-up `getpkgtxns` goes to the peer whose `ancpkginfo` answered that solicitation (`crates/node/src/tx_ingress.rs`, `crates/p2p/src/tx_policy.rs`). Inbound, `getdata(MSG_ANCPKGINFO)` is answered with `ancpkginfo` (`crates/p2p/src/dispatch.rs`). Initial-block-download gating is per-path, not a negotiation reset: a closed relay gate drops the `ancpkginfo` download request and releases its solicitation (`dispatch.rs`, `listener.rs`), and drops inbound `pkgtxns` admission (`listener.rs`), while `getpkgtxns` serving still answers from negotiation alone. Pinned by `package_relay_is_the_intersection_of_known_bits_both_sides_sent`, `package_relay_needs_every_handshake_precondition`, `package_relay_is_off_until_both_veracks_completed_the_handshake`, and `inbound_handshake_sends_one_sendpackages_before_verack_and_activates_the_common_bits`. |
| `staletip` | negotiated, opt-in | BIP332 draft, no Core 31.1 equivalent. Typed wire codec in `crates/p2p/src/staletip.rs`, carried by its 12-byte name on both transports (no BIP324 short ID). A payload over the header limit is ignored without punishment; any other malformed payload is an invalid decoded payload (§6). Stale-tip relay is active only when this node enabled it (`RelayOffers::stale_tip_relay`), the peer negotiated `BIP332`, and initial block download is inactive: the listener consumes an inbound `staletip` only under that triple gate, and the announcer relays only to peers with a recorded `BIP332` preference while not in initial block download (`crates/p2p/src/listener.rs`, `block_announce.rs`). The peer's `BIP332` preference is recorded only when this node offered stale-tip relay (`ConnectionShared::note_peer_stale_tip_relay`). |
| `ping` | served | Answered with `pong` echoing the nonce, ready peers only. No latency telemetry is kept. |
| `pong` | ignored | No ping RTT accounting exists; the pong body is unused. |
| `inv` | consumed | Missing transaction vectors enter the connection-bound transaction request owner; only the selected eligible source receives `getdata`. P2P's `TxInventory` implementation queries the shared mempool gateway (accepted transactions, resident orphan wtxids, and recent rejects); a resident orphan never suppresses a txid-typed request, because another witness of that txid can still be valid; `MSG_TX` announcements are requested as `MSG_WITNESS_TX` from `NODE_WITNESS` peers and as `MSG_TX` otherwise; `MSG_WTX` requests retain their wtxid and type. While the node is in initial block download, transaction-typed vectors are never requested (Core 31.1 `net_processing.cpp:4401-4404`). Block-typed vectors (`MSG_BLOCK`, `MSG_WITNESS_BLOCK`) are never answered with a body `getdata`: they are announced to header sync against the announcing connection, which credits its best-known block and receives `getheaders` (Core `net_processing.cpp:4370-4410`, `docs/contracts/p2p-wire.md` `P2P-07`). Outbound block announcement uses single-block `inv` (`MSG_BLOCK`) as a compatibility fallback when a peer did not negotiate BIP130 `sendheaders`, when an active-chain anchor cannot be established, or when the anchor's distance from the committed tip exceeds `MAX_BLOCKS_TO_ANNOUNCE` (8). Bound: 50 000 vectors (`MAX_INV_PER_MSG`, Core `MAX_INV_SZ`). |
| `getdata` | served | `MSG_BLOCK` streams stripped stored blocks from the applied chain or an eligible stale branch; `MSG_WITNESS_BLOCK` preserves the stored witness serialization (BIP144). For full-relay peers, transaction inventory is served from the mempool, or from the orphan map only for a `MSG_WTX` item whose exact wtxid is resident. For block-relay-only peers, the listener removes transaction vectors before dispatch and drops transaction-only requests without a response. `MSG_TX` receives stripped serialization; `MSG_WITNESS_TX` and `MSG_WTX` receive witness serialization (BIP144/BIP339), without changing the retained body. A `MSG_CMPCT_BLOCK` item is answered with a `cmpctblock` only while the block is within 5 of the applied tip; a deeper one is served as the whole witness-bearing `block`, as Core does (`net_processing.cpp:2705-2721`). Misses among dispatched inventory resolve to one trailing `notfound`. Items are served one at a time in request order. A saturated outbound queue pauses the request instead of disconnecting the peer. The queue is saturated for production when it has no free item slot (4 096 queued messages) or no room for one more worst-case block behind its queued bytes (64 MiB cap). The pause sends nothing for the unserved items: they stay with the connection in request order, and the connection reads nothing from the peer while they remain. The misses found before the pause go out in one `notfound` once a reservation for its exact length succeeds against both the connection's own bound and the node's aggregate outbound budget, as Core sends its `notfound` at once when it stops at its send-buffer limit and resumes its queued items later (`net_processing.cpp:2766-2833`); a refusal from either budget keeps the misses parked, the list untaken and unbuilt, and nothing is sent. A request served completely follows the same rule for its trailing `notfound`: when its last item took the last production reservation, the misses stay parked until a reservation for their exact length succeeds against both budgets. The remaining items are served in order once a fresh worst-case production reservation succeeds against both budgets. After a `getdata` that leaves no production reservation available, the connection also reads nothing further until a one-message probe charge succeeds against both budgets; the probe is returned at once and holds no slot, and the next reply is reserved only when it is dispatched, where a refusal still defers it; Core pauses message processing the same way while its send buffer is full (`net_processing.cpp:5459`), but for every message, whereas only a `getdata` establishes the hold here, and a peer that never sent one keeps the plain saturation policy (a full connection-local queue cancels the connection). A request or hold that lasts 20 minutes, or a writer that dies, ends the session; time during which the node's aggregate outbound budget (see "Outbound queue accounting" below) refused the connection is not counted toward the 20 minutes. Every message is queued under a reservation taken before it exists: a body is loaded only while the session holds a reservation for one worst-case frame, and the parked `notfound` is reserved at its exact length before it is built, so no check-then-send race remains. Bound: 50 000 vectors. |
| `notfound` | transaction fallback | A matching transaction request releases only its actual source and promptly considers retained alternatives; unrelated or unsolicited responses cannot release another connection's ownership. Block entries remain ignored. Decoded with the same inventory bound. |
| `getheaders` | served | Answered with `headers` from the active chain: first locator hash on the active chain anchors the walk, total miss anchors after genesis, stop hash truncates inclusively, ≤ 2 000 headers per message (Core's per-message maximum). Locator bound: 101 hashes (Core `MAX_LOCATOR_SZ`). Empty locator + zero stop answers nothing (Core clients always send a locator; unreachable in practice). |
| `getblocks` | ignored | Legacy locator request; Core answers with an `inv`, we stay silent. Documented deviation. Locator bound identical. |
| `headers` | sink / outbound | Forwarded to the node's header-sync pipeline. Newly committed active tips are announced via BIP130 `headers` (up to 8 headers, Core `MAX_BLOCKS_TO_ANNOUNCE`) to peers that negotiated `sendheaders` and can anchor on active chain history. Bound: ≤ 2 000 headers per message. |
| `block` | sink | Forwarded to the node's block pipeline with the original wire bytes preserved. The shared inbound channel is bounded once for the node, and each connection's unsolicited share of it is bounded separately; a body the download window asked that connection for is always admitted (`docs/contracts/p2p-wire.md` `P2P-07`). |
| `tx` | sink | Forwarded from a Ready peer into the node's bounded ingress channel, except while the node is in initial block download: unsolicited transaction bodies are then dropped before ingress, without a misbehavior score or disconnect (Core 31.1 `net_processing.cpp:4713-4716`). Mempool prepares and retries admission through its one gateway; node connects committed peer accepts to P2P's relay queue, which announces the negotiated inventory type excluding the exact delivering connection. P2P requests missing parents from that live connection using txid-typed `getdata`; mempool owns orphan retention and retry. A full ingress channel drops the body so the peer read loop can still service ping, headers, and blocks. No protocol response, no disconnect. |
| `mempool` | ignored | BIP35 mempool snapshot request; Core answers with an `inv` of relay-pool transactions. Deviation: silent. |
| `getaddr` | served | At most 32 retained IPv4/IPv6/Tor-v3/I2P addresses, once per full-relay connection; a peer that sent `sendaddrv2` gets `addrv2` rows from the same book, any other peer gets legacy `addr`. Book-disabled test/embedding connections remain silent. Core sends `addrv2` once negotiated (`net_processing.cpp:5803-5807`); legacy `addr` replies omit overlay endpoints. |
| `addr` / `addrv2` | consumed | Decoded with a 1,000-entry wire bound, then admitted to the shared address book behind a 32-entry connection allowance replenished one per 10 seconds. Source-group limits and routability apply before retention; Tor v3 and I2P identities are retained and relayed as `addrv2`; Tor v2, CJDNS and unknown families are ignored. Legacy `addr` replies contain only the IP subset. Anonymous inbound Tor circuits do not supply a durable address-learning source. |
| `feefilter` | applied | BIP133. Valid nonnegative thresholds through `MAX_MONEY` filter queued outbound transaction inventory for that connection; invalid values are ignored. The threshold never changes admission. Full-relay connections at protocol 70013+ receive rounded effective local floors on randomized refreshes. |
| `sendcmpct` | negotiated | BIP152. Sent after `verack` in low-bandwidth mode (`send_compact=false`, version 2). Up to 3 peers are promoted to high-bandwidth mode (`sendcmpct(true, 2)`), demoting older peers (`sendcmpct(false, 2)`) when the cap is reached. Inbound `sendcmpct` establishes peer compact-relay version and high-bandwidth preference. Ready peers in high-bandwidth mode receive unsolicited `cmpctblock` announcements for new tips if the peer is known to hold the parent block (`prev_blockhash`); suppressed in `blocksonly` mode. A high-bandwidth `cmpctblock` may precede connect for a PoW-valid tip child (rules passed, commit intent, segwit active); a later connect failure is not retracted and sends nothing further. Inbound announcements also publish compact-fetch eligibility. |
| `cmpctblock` / `blocktxn` | sink | BIP152 receive path. Like Core, a `cmpctblock` enters reconstruction only when its header earns the mempool scan. The header needs valid proof of work for the network, the block must not be marked invalid, and its parent must be a known block not marked invalid. The header must also pass the contextual checks header admission applies against that parent, including the required nBits, so a header mined at an easier target never earns the scan; as in admission, a header already in the tree is not rechecked. Finally it must either carry more work than the applied chain and be at most two blocks above the applied tip (Core `net_processing.cpp:4664`) or answer a body fetch the same connection owns. Any other `cmpctblock` routes only its header to admission. A hash already attempted on that connection within the reconstruction deadline is not scanned again. Admitted, `cmpctblock` starts bounded per-peer reconstruction: the prefilled coinbase/transactions plus short-ID matches against the mempool and the bounded reconstruction extra pool under the identity profile we advertised (`COMPACT_BLOCK_VERSION`) — the extra pool holds at most 100 wtxid-keyed bodies (transactions removed as replaced, peer orphan-held bodies, and peer policy-only rejects below 100 000 serialized bytes; never a coinbase; hint-only, never admitted or relayed by retention; Core `DEFAULT_BLOCK_RECONSTRUCTION_EXTRA_TXN`) — BIP152 identity is directional: our advertised version fixes what a compliant peer sends us, and the peer's recorded version fixes what we serve; version 1 matches by txid and version 2 by wtxid; two witness variants of one txid stay distinct while a pool-resident identity duplicated in the extra pool is one claim, not a collision; missing transactions are requested with `getblocktxn` on the same connection; two distinct hint identities that collide on one short ID retire only that slot, which `getblocktxn` then carries; a duplicate declared short ID, a count mismatch, or a reconstruction that fails the bounds checks falls back to one full-block `getdata`; an entry whose deadline passes is dropped silently and the peer relies on the connection's separate stall/liveness handling — this module sends no deadline-driven `getdata`. `blocktxn` completes a pending reconstruction. Before delivery both completion paths re-verify the assembled body against the header's transaction-ID merkle root and reject a mutated transaction-ID tree (CVE-2012-2459 duplicate-final-transaction collision) and a body without a coinbase that holds a 64-byte transaction (CVE-2017-12842), so a short-ID misguess can never publish a wrong block; a failed check falls back the same way. A verified block enters the ordinary block pipeline like any `block` message — no validation bypass. |
| `getblocktxn` | served | BIP152. A stored, non-invalid block within 10 of the applied tip is answered with `blocktxn`, including a block that became stale after its compact announcement. The most recently early-announced body also answers from the held bytes before the store carries it. As in Core, this shallow path requires body availability but does not apply the inventory stale-age filter. A deeper request uses full witness-bearing `block` inventory policy, including the stale validation and age restrictions below; depth is checked before past-the-end indexes. Unknown or unavailable blocks stay unanswered. The mutually supported compact serving profile determines transaction witness encoding. On the `blocktxn` path an index past the body is a protocol disconnect; empty or non-increasing indexes are rejected at the inbound boundary regardless of depth. The headroom gate runs before any body load or held-body reply construction. A saturated gate leaves the request unanswered without disconnecting the peer. |
| `merkleblock` / `filterload` / `filteradd` / `filterclear` | ignored | BIP37. We do not advertise `NODE_BLOOM`, so a default Core peer never sends them; if one does, they are ignored. |
| `getcfilters` / `getcfheaders` / `getcfcheckpt` | served when enabled and ready | BIP157 basic type 0 only; active-chain stop, at most 1,000 filters / 2,000 hashes; checkpoint headers at positive multiples of 1,000. Filter payloads stream under send headroom from one index snapshot. A pass that the outbound budget stops after a prefix was sent parks only the remainder, which resumes from the first unsent filter without replaying one and keeps the stop height the prefix was computed against; any other early stop of a sent prefix, or a resumed range whose stop height has moved, closes the connection. Unknown, unsupported, unavailable and oversized requests receive no answer. |
| `cfilter` / `cfheaders` / `cfcheckpt` | ignored | The node serves external consumers; it does not synchronize its validated chain through compact filters. |
| `reject` | decoded only | Decoded, never sent. Core 31 no longer emits `reject` for transaction acceptance results. |
| `alert` | ignored | Decoded as opaque bytes, ignored. The command is dead in Core. |

Outbound queue accounting. Every queued message is one charge of a message and its
full wire bytes against two budgets: the connection's own (4 096 messages, 64 MiB)
and the node's aggregate of queued outbound wire bytes, one strict 64 MiB cap shared
by every connection of a `P2pService` and never process-global. The aggregate's
pending total is never above its cap at any instant, with no exemption for a message
on an empty queue; the connection's own caps keep their rule that a lone oversized
message is admitted to an empty local queue, and that message is still charged to the
aggregate. A bulk body reservation must also fit under the cap less one maximum
frame, so control traffic still flows while bodies are refused. A charge has one owner
at every moment (the reservation, then the queued frame that carries it, then the
writer's burst) and returns to both budgets exactly once when that owner drops:
written, refused, discarded with the channel, or drained when the writer exits.

A refused charge takes nothing and names its cause. The connection's own cap, or a
writer that has returned, cancels the lease as before. The node aggregate is
backpressure only: the lease stays live and the sender keeps its intent. A request
whose reply cannot be reserved (`ping`, `getheaders`, an answerable `getaddr`, and the
`getblocktxn` or `getdata` follow-up to a `cmpctblock` or `blocktxn`) is deferred: the
connection reads nothing until the reply can be reserved, dispatches the request
once, and never produces an unreserved reply. A probe `ping` and an outbound
`getaddr` stay owed until they can be sent. Time the aggregate refused a connection
is a stall: it is not silence in either direction for the keepalive, not the age of a
parked `getdata` tail or deferred request, and not charged to a parked compact-filter
request's five-second allowance. Local saturation, a dead writer and silence outside
a stall keep their rules.

Background producers keep their intent when the aggregate refuses them. A
`getheaders`, block `getdata` or cold-start hedge marks nothing and is planned again
on the next tick (the hedge tries the next candidate); a transaction `getdata`
returns its claim to the request owner; a refused `feefilter` restores its schedule;
a refused relay `inv` returns its requests to the peer's pending queue; and a refused
block announcement, `sendcmpct` demotion or high-bandwidth rotation leaves the
selection as it was and is retried.

Block serving resolves each body by its own `(height, hash)`, so stale and winning
blocks at the same height cannot be confused. Header-chain membership or
`NodeStatus::Active` alone is not proof of body validation. Off-applied-chain
`getdata` and deep `getblocktxn` fallback require the chain owner's recorded
application count and, relative to the best header, both timestamp age and
proof-equivalent age strictly below 30 days. This follows
[Core 31.1 `BlockRequestAllowed`](https://github.com/bitcoin/bitcoin/blob/9be056a8a72b624dae9623b2f7bded92c2a21c91/src/net_processing.cpp#L1953-L1959);
[shallow `getblocktxn`](https://github.com/bitcoin/bitcoin/blob/9be056a8a72b624dae9623b2f7bded92c2a21c91/src/net_processing.cpp#L4333-L4391)
uses its separate stored-data path. Bodies are parsed and hash-checked outside
tree locks; eligibility and applied depth are rechecked after the read. Unknown,
invalid, pruned, missing and malformed bodies are never forwarded. Unsolicited
compact announcements retain their active-chain requirement. Already-stale
branches whose application counts were not restored by a checkpoint remain
ineligible for inventory replies until validation establishes that evidence;
this change does not add a persistent Core-style validation-status index.

Any command outside this table decodes as `Unknown` and follows §6 — which is also how the one Core 31 command absent above, `sendtxrcncl` (BIP330), is handled.

Transaction announcements target only connections with published handshake
metadata. A peer that negotiated `wtxidrelay` receives `MSG_WTX` with the
accepted transaction's actual wtxid; other ready peers receive `MSG_TX` with
its txid, following [BIP339](https://github.com/bitcoin/bips/blob/master/bip-0339.mediawiki).
RPC/reorg mutation observers resolve the retained entry's wtxid and skip
entries removed before observer delivery. Missing-parent requests use txids,
which BIP339 permits for unannounced parents. Sources advertising `NODE_WITNESS`
receive `MSG_WITNESS_TX` requests so the returned parent includes its witness;
other sources receive `MSG_TX`, following
[BIP144](https://github.com/bitcoin/bips/blob/master/bip-0144.mediawiki#relay). Relay queue
saturation drops the newest announcement without blocking admission;
a connection's own outbound saturation cancels that connection's lease, while
a full node aggregate (see "Outbound queue accounting") only defers the send
and cancels nothing. Each queued
announcement is checked against the shared mempool immediately before its
relay send, matched on the admission epoch recorded when the request was
queued: a transaction that left the pool before the check — or was
re-admitted under a new admission — is consumed with no `inv`. The check
narrows the stale-announcement window; it does not close it. A removal
landing between the check and a peer's send cannot be retracted, so a peer
can still receive inventory for a transaction that has just left the pool.

The inventory view respects the reject cache's identity scope: witness-only
refusals suppress the exact wtxid, not legacy txid inventory or another
witness variant. The cache and retry lifecycle are governed by
[MPL-04](../contracts/mempool-mutations.md#mpl-04-generation-validated-admission-and-chain-change-fencing).

## 6. Message policy and automatic discouragement

The P2P service owns both the existing in-memory manual subnet bans and a
separate bounded, process-local set of discouraged **exact IP addresses**.
There is no additive score or second persisted ban database. `listbanned` and
`clearbanned` describe only manual bans. An ordinary automatic peer's current
connection records a typed remote protocol violation before teardown; an old
lease cannot punish its same-address replacement. Local queue saturation,
network inactivity, startup cancellation, insufficient advertised services,
transport I/O/timeouts, and local encoding failures never discourage an IP.

| Condition | bitcoin-rs action for an ordinary automatic nonlocal peer | Core 31.1 reference |
| :--- | :--- | :--- |
| Unknown command after readiness | ignore | ignore |
| Decoded compact-filter requests with a non-basic type, unknown/unapplied stop, inverted range or more than 1,000 filters / 2,000 hashes | ignore and keep the connection open, without discouragement | `PrepareBlockFilterRequest` disconnects without discouragement; this is a deliberate connection-policy deviation, tested by the compact-filter wire probe |
| Invalid handshake ordering | disconnect and temporarily avoid the IP | Core ignores some cases, including redundant `version` and messages before `version`; bitcoin-rs retains its stricter FSM |
| Invalid decoded payload or structural count (including a malformed `feature` payload) | disconnect and temporarily avoid the IP | Core's payload exceptions and individual handlers have distinct rules; this is not blanket parsing-error parity |
| Checksum failure | disconnect and temporarily avoid the IP | Core v1 rejects the message and resets its decoder; this remains a stricter bitcoin-rs policy |
| Wrong magic (including a BIP324 key read with v2 off) | close the unread transport, without discouragement | Core closes the transport on a wrong message start without `Misbehaving` |
| Invalid command bytes or length above 4,000,000 bytes | close the unread transport; temporarily avoid ordinary remote IPs | Core transport rejection, with the same 4,000,000-byte cap, is separate from `Misbehaving` |
| `inv`/`getdata` above 50,000, `addr`/`addrv2` above 1,000, `headers` above 2,000 | disconnect and temporarily avoid the IP | the relevant Core handlers mark for discouragement |
| Locator above 101 or `notfound` above 50,000 | disconnect and temporarily avoid the IP | Core directly disconnects oversized locators; oversized `notfound` is ignored by request handling, without generic punishment |
| `getblocktxn` indexes beyond the body on the `blocktxn` serving path | disconnect and temporarily avoid the IP | Core marks these body-relative bounds violations for discouragement (`net_processing.cpp:2600-2608`), separately from differential decoding |
| Empty `getblocktxn` list or non-increasing in-process absolute indexes | disconnect and temporarily avoid the IP | Empty rejection is stricter native policy; Core accepts an empty list. Both wire decoders guarantee increasing indexes before lookup (`blockencodings.h:23-54`, `net_processing.cpp:4333-4340`), so non-increasing lists are defensive in-process cases. Core decodes `uint16_t` indexes; the native codec retains `u64` indexes, with different range acceptance |
| `tx` or transaction `inv` on a block-relay-only connection | disconnect without discouragement | connection-role rejection; not a new numeric penalty |
| `addr` or `addrv2` on a block-relay-only connection | ignore | address relay is declined |
| Idle connection | ping once a direction has been idle 2 minutes; disconnect once a direction is silent past 20 minutes, except that receive silence does not count while a paused `getdata` stops the connection from reading; no discouragement | periodic ping and outstanding-ping timeout remain distinct from misconduct |
| Valid traffic exceeds local queue/request budgets | bounded accounting, backpressure or connection-local cancellation | resource management, not a generic punishment score |

Discouragement retains at most 4,096 canonical IPs for one monotonic hour.
Repetition does not refresh the deadline or add another queue entry. At the
capacity bound the oldest entry is evicted. Core instead uses a rolling Bloom
filter with 50,000 elements and no explicit time expiry. The exact-set bound
keeps this auxiliary policy finite and avoids probabilistic false positives;
its smaller retention window is an explicit deviation, not a performance claim.
Selection snapshots are captured before the address-book lock and applied to
regular candidates, feelers and restart anchors. Inbound accepts and outbound
socket admission recheck current policy, including after a queued dial connects.

Manual connections and operator-protected peers discard a fully consumed bad
message and continue. An unread/unsafe frame still closes the transport without
address discouragement, as do unrelated I/O and resource failures. Other local
peers disconnect without recording their address. Locality follows Core's
`CNetAddr::IsLocal`: IPv4 0/8 and 127/8, and IPv6 `::1`; IPv4-mapped IPv6 is
canonicalized before matching. Private LAN addresses are not implicitly local.

The optional `--p2p-noban <IP/CIDR,...>` setting (TOML `p2p_noban`, environment
`BITCOIN_RS_P2P_NOBAN`) defaults to an empty list. The existing `IpSubnet` owner
parses and normalizes it. Permission is derived only from the actual socket IP,
never from a peer's advertised addresses. `getpeerinfo.permissions` reports
`noban` for these connections. This is an automatic-discouragement exemption,
not Core's complete permission framework: explicit manual ban admission still
wins, and transaction relay, fee filters, resource budgets and connection roles
remain unchanged. No `Relay`, `ForceRelay`, `Addr` or generic permission flags
are inferred.

References: pinned Core v31.1 [Misbehaving and exemption handling](https://github.com/bitcoin/bitcoin/blob/v31.1/src/net_processing.cpp),
[rolling discouraged set](https://github.com/bitcoin/bitcoin/blob/v31.1/src/banman.h),
[v1 checksum rejection](https://github.com/bitcoin/bitcoin/blob/v31.1/src/net.cpp),
and [canonical local-address classes](https://github.com/bitcoin/bitcoin/blob/v31.1/src/netaddress.cpp).
The process comparison in `e2e/tests/peer_discouragement.rs` uses an oversized
`headers` count, which actually reaches Core's `Misbehaving`, to test ordinary
local disconnect/reconnect and operator `NoBan` survival via a ping/pong barrier.

## 7. Deviation Ledger

Known deltas from Core 31.1 (the `TXR-nn` labels index Core's tx-relay
inventory in `net_processing.cpp`: TXR-01–07 are the per-peer request-tracker
duties Core 31.1 owns in `node::TxDownloadManager` (`src/node/txdownloadman.h`),
issued through `GetRequestsToSend` in `SendMessages` (`net_processing.cpp:6206`);
TXR-09 is the trickled inventory schedule, `m_next_inv_send_time` at
`net_processing.cpp:319` under the `INVENTORY_BROADCAST_*` delays at `:163-166`):

1. **BIP324 v2 transport**: on by default, as in Core 31. A live run against an unmodified Core 31.1 recorded v2 in both connection directions with matching session ids, ping answers and a full header and block sync over each, plus a v2-off node syncing over v1 from v2 Core (https://github.com/gosuda/bitcoin-rs/pull/1612; CORE-06). No deviation from Core is known; the v1 retry after an unanswered v2 dial, decoy packets and rekeying rest on in-tree tests only. `--v2transport=false` keeps every connection on v1 and stops advertising `NODE_P2P_V2`. BIP324 does not authenticate peers, so it does not stop an active MITM or eclipsing peer.
2. **BIP330 `sendtxrcncl`**: not implemented; it is the one Core 31 command missing from our 42-command table. Decoded as `Unknown`: ignored from a ready peer (Core ignores unknown commands too), disconnected before readiness. Core whitelists it during handshake, so the only affected topology is a Core peer *dialing* bitcoin-rs with `-txreconciliation=1`. The supported topology — bitcoin-rs dials Core, Core sees an inbound peer — never receives it, because Core sends `sendtxrcncl` to outbound peers only.
3. **Proactive block announcements**: implemented for newly committed active tips. Ready peers receive unsolicited BIP152 high-bandwidth compact blocks (up to 3 peers when parent is known and tx relay is active), BIP130 headers (up to 8 blocks when anchored to the active chain), or fallback to single-block `inv` (`MSG_BLOCK`). Stale tips across reorgs are discarded and intermediate tips are coalesced under queue backpressure.
4. **Address management**: one P2P-owned `AddressBook` retains canonical
   endpoints, their original source and health, and up to eight distinct New
   bucket references. IPv4-mapped IPv6 aliases are canonicalized at every book
   endpoint boundary, including attempt/success, refresh, connected exclusion,
   and pending claim/release/counting. Other linked IPv6 forms retain their
   distinct endpoint identity; only their netgroup classification links IPv4. Lookup tables are derived indexes, not another persisted
   peer store. Placement follows Core 31.1 `GetNewBucket`, `GetTriedBucket` and
   `GetBucketPosition`: SHA256d with the persisted 256-bit secret, Core vector
   framing, endpoint wire bytes, and separate New/Tried position domains. There
   are 1,024 New and 256 Tried buckets of 64 positions. One source group can
   reach at most 64 New buckets; a destination group reaches at most eight
   Tried buckets. The former 64-endpoint/source quota and public position hash
   are removed. IP grouping includes linked IPv4 /16, ordinary IPv6 /32,
   Hurricane Electric /36 and Core's local/unroutable group. New DNS sources use
   the first ten SHA256 bytes of the seed name as Core Internal identities.

   `AddSingle` ordering governs time/service updates, probabilistic additional
   references (1/2^existing-reference-count), and occupied-slot replacement.
   Gossip applies a two-hour time penalty, except a source's self-announcement;
   DNS applies none. An IsTerrible incumbent or one redundant reference of a
   healthy multiply referenced incumbent may yield a New slot to a fresh
   endpoint. Clearing a slot removes one reference; only the final New
   reference deletes the endpoint. Local pending ownership protects final
   endpoint deletion, not every redundant slot. Success promotes to a vacant
   Tried slot and removes all New references. A Tried collision retains the
   successful newcomer in New and enters a runtime-only set of at most ten
   distinct challengers, including multiple challengers for the same slot.
   Runtime-only creation IDs preserve Core's collision ordering across record
   swaps; no ID or collision set is added to the durable format.
   Core `ResolveCollisions` protects an incumbent successful within four hours;
   an attempt within four hours permits replacement only after more than 60
   seconds. Otherwise a challenger waiting more than 40 minutes can replace an
   untested incumbent. Exact boundaries use the existing health timestamps,
   not worker errors or a separate completion tracker. Replacement calls the
   same Good(false) health transition, clears all challenger New references,
   and demotes the incumbent to one original-source New reference. Only the
   collided destination New reference is cleared; identity disappears only
   at zero references. Pending final-reference victims defer the entire
   transition before health or table changes. Local active/manual/pending
   endpoints remain protected. Resolver policy snapshots cover at most twenty
   endpoints and run outside the state lock before current state is rechecked.
   Collision choice samples the shared RNG; feeler scheduling uses Core's
   Poisson interval with a two-minute mean, observed on the service tick. Selecting an already TCP-connected
   incumbent records Good and falls back to the existing New-only sampler;
   queued/inflight work alone never certifies Good. Feeler targets require stored
   NETWORK or NETWORK_LIMITED service advertisement. DNS records retain unknown
   service bits and use ordinary selection until a handshake supplies them.
   Ordinary candidate selection, restart-anchor admission, automatic dispatch
   and the final pre-TCP check share the existing desirable-service predicate:
   NETWORK plus WITNESS, or LIMITED plus WITNESS while approximate local tip
   depth is below 144. Selection rechecks current record metadata after its
   unlocked policy callback. Manual dials and feelers bypass this metadata
   prefilter; ordinary received VERSION validation remains in place.

   Accepted VERSION metadata overwrites the one stored service field before
   ordinary service rejection, without marking Good, changing health times or
   promoting membership. This field is an optional u64: unknown DNS metadata
   is `None`; an observed zero-bit claim is `Some(0)`. Gossip ORs service bits
   into the same field; zero-bit gossip preserves an existing unknown value.
   Direct VERSION zero and a fresh IP-sourced zero advertisement remain known
   zero. DNS without an advertisement preserves every known value. No second
   last-VERSION or fitness flag is introduced. Only genuine unknown DNS metadata can bootstrap
   ordinary selection; an accepted NONE VERSION is excluded immediately even
   without Good, through DNS refresh and restart. A successful NONE feeler
   still remains Good/Tried and is excluded from ordinary dialing. Native DNS
   does not claim Core's service-filtered x9 discovery.
   Feelers finish on a valid VERSION through the existing native parser/FSM,
   without readiness or sync work. This does not claim Core's inherited minimum
   protocol floor or connman-wide inbound self-nonce validation; ordinary
   handshake validation is unchanged. Collision state starts empty
   after restart. The former immediate failed-worker eviction path is removed.

   The shared IsTerrible predicate first protects attempts within 60 seconds,
   then checks future timestamps beyond ten minutes, age over 30 days, three
   never-success failures, or ten failures with success older than seven days.
   There is no periodic age/failure purge. Replacement cleanup happens at an
   actual New-slot admission; fresh getaddr samples filter IsTerrible. Failed,
   stale or clock-shifted knowledge remains selectable without DNS input.
   Attempt health is recorded only after an actual TCP attempt, on success or
   failure. Local ban/activity/cancellation refusal and failed thread creation
   do not age a peer. Failures count only once per global Good epoch and only
   with Core's persistent-outbound-netgroup connectivity gate, derived from
   `max_peer_connections`. Established manual and handshaking outbound sessions
   count; inbound, transient feelers and cancelled sessions do not. Manual attempts never count a
   failure or own an automatic claim. Good from any non-inbound handshake
   updates the epoch; known peers reset failures and record success/recent try,
   while unknown manual peers are not inserted. Good does not overwrite
   advertised last-seen time. Native periodic refresh applies only to ready
   automatic full-relay peers, excluding feelers, at intervals over 20 minutes; block-relay peers
   never refresh an advertised timestamp but still count for DNS recovery.
   This periodic lifecycle differs from Core's FinalizeNode Connected update.
   Last-try/count-attempt/global-Good times are runtime-only.

   Selection chooses New/Tried once with equal probability when both eligible
   tables exist, then samples a bucket and circular start position. Conditioning
   on nonempty eligible buckets removes empty retries without changing that
   distribution. Acceptance uses Core GetChance: 0.01 for attempts within ten
   minutes, multiplied by 0.66^min(failures,8), with a 1.2 factor after rejection.
   The minimum weight guarantees acceptance within 45 occupied proposals;
   there is no deterministic rank winner or hard failure delay. Empty or wholly
   excluded books return immediately. Policy callbacks run outside the book
   lock; current membership/health/pending constraints are evaluated after it
   is reacquired. Exact endpoint exclusion includes inbound; whole-group
   exclusion uses outbound/pending only. This conditions on local ban/connection
   exclusions, rather than duplicating Core net.cpp's outer 100-candidate loop.

   Explicit native boundaries remain: ingress rejects future (>10-minute) and
   older-than-30-day reports, whereas Core's wire caller normalizes some bad
   timestamps before Add. Existing native port/routability admission is retained
   (`addrman.rs::routable`), including its narrower accepted IPv6 ranges and
   reserved IPv4 exclusions; exact group/hash vectors do not claim that every
   Core-routable address is admitted. IP, Tor v3 and I2P destinations are supported.
   DNS remains
   bounded bootstrap input (64 results per seed pass), not a second address
   owner. Books with at least 64 records get 60 seconds to connect before a
   remaining ready-outbound deficit permits DNS recovery; smaller books query
   immediately. Each path makes at most one seed pass per 60 seconds.
   Full-relay gossip allowance is 32 entries, replenished one per ten seconds.
   Getaddr is answered once per inbound full-relay connection, never outbound.
   Its shared at-most-32-entry sample stays byte-stable for 24 hours across
   reconnects and discoveries, then rotates and applies IsTerrible filtering.
   This differs from Core's randomized 21–27-hour cache and response sizing.
   Tor v3 and I2P addrv2 families are retained; other non-IP families are ignored; block-relay-only peers neither learn nor
   serve addresses. These boundaries are not a claim of complete Core peer
   lifecycle equivalence.

   The fixed indexes occupy 327,680 bytes; endpoint count is bounded at 81,920,
   with at most eight New bucket IDs each and at most 65,536 occupied New slots.
   On the tested 64-bit target Candidate is 184 bytes and Source is 40 bytes,
   excluding allocator/index/vector overhead. Fixed-width serialized fields
   have a conservative 512-byte/record bound (315-byte max-width fixture), so
   record separators plus bounded header/checksum remain below the 64 MiB file
   ceiling. Reads bound both bytes and record/reference sequences. These are
   representation/work bounds, not RSS or performance measurements.

   `--asmap <file>` (TOML `asmap`, environment `BITCOIN_RS_ASMAP`) loads one
   immutable classifier through the P2P netgroup owner. Its validated Core
   bytecode is bounded at 4 MiB. Placement, incoming source corroboration,
   outbound diversity and persistent-TCP failure counting use that same map.
   Core ASN groups serialize as NET_IPV6 followed by little-endian ASN bytes,
   grouping IPv4/IPv6 together. ASN0 uses the corrected prefix/HE fallback;
   public linked-IPv4 forms use their embedded IPv4 without rewriting the dial
   endpoint. Internal DNS sources retain their source namespace.
   Startup logs the raw-file SHA256 identity. Invalid or unavailable configured
   maps permit memory-only prefix fallback but disable all book publication
   and incompatible-file preservation; restoring the map recovers the untouched
   book. Intentionally changing or omitting a map rebuckets the current format
   through the existing placement owner, prioritizing proven/recent successes
   and logging retained/demoted/dropped counts. Anchors are pruned only when
   their endpoint is removed. Same-map restart retains every reference.

   AddrMan reads and writes one canonical checksummed JSON snapshot, identified
   by `format: "bitcoin-rs-addrman"` and `version: 1`. `SCHEMA_VERSION` MUST remain
   `1` until the first official bitcoin-rs release. Before that release, edit
   this definition directly; do not add compatibility readers or increment the
   version. Only after release may a breaking change increment the version with
   an explicit compatibility decision; release itself needs no increment.

   Actual Core group/placement evidence includes 224 ASMap rows and official
   Tried236/New795 anchors. These are specific algorithm/persistence checks
   against the canonical v1 format, not full peer-lifecycle parity; no
   historical migration fixtures exist.
   The canonical object has `format`, `version`, `magic` (four P2P magic bytes),
   `secret` (32 bytes), `records`, `asmap_id` (null or 32 bytes), and `anchors`.
   The trailing 32 bytes are SHA256 of the exact UTF-8 JSON payload. Endpoint
   strings represent IP sockets, Tor-v3 host:port or I2P host:port; mapped IPv4
   endpoints canonicalize to IPv4. Each record contains `addr`, `services`,
   `source`, `last_seen`, `last_success`, `failures`, `tried`, `new_buckets`.
   Source is exactly one of `{"ip": <IP string>}`, `{"overlay": <onion/I2P
   address string>}`, or `{"internal": <10 SHA256 seed-hash bytes>}`. Overlay
   sources cannot contain IP or ephemeral connection handles. Each anchor is
   `{"addr": <endpoint string>, "confirmed_at": <Unix seconds>}` and must name
   a unique successful record, with at most two anchors. Runtime attempt,
   count-attempt, global-Good times and creation IDs are not persisted.

   Services is required: JSON null means unknown DNS metadata, while numeric
   zero means a known zero-bit claim. Null is valid only for an Internal source
   with no prior Good. Unknown fields, invalid membership, unsafe endpoints,
   malformed anchors, or excessive sizes fail closed. Tor/I2P endpoint hash
   keys use BIP155 tags 4/5 followed by the 32 identity bytes and big-endian
   port; netgroups are `[4, key[0] | 15]` / `[5, hash[0] | 15]`. Internal source
   groups use tag 6 plus the ten seed-hash bytes. ASMap applies only to IP.
   Both overlay branches must use these same identity, source and placement
   rules when adopting this canonical definition; divergent development v9
   layouts are not supported inputs for record import.

   Unmarked pre-release v1-v9 files are never decoded or migrated. Only their
   bounded JSON envelope, checksum and network identity are checked. Before
   replacing one with an empty or freshly seeded canonical book, its exact bytes
   are exclusively published and file/directory-synced to
   `.pre-release-<sha256>.bak`. A pre-existing backup is reusable only if it is a
   regular file with identical bytes and is flushed successfully. Preservation
   failure disables replacement. The original stays at its source path until
   atomic save succeeds; a crash before save can retry preservation safely.
   No old peers, secrets, health or anchors are imported. Relearning uses the
   existing discovery path. This discards development cache knowledge, not
   authoritative chainstate, keys or operator configuration.

   Filenames remain scoped to actual P2P magic: `peers.dat` becomes
   `peers-<8 hexadecimal magic digits>.dat`, including custom/drynet magics.
   A valid scoped book wins. A same-magic unscoped current book can be copied
   into the scoped path without altering its source; an unmarked development
   book there follows the same preservation-before-fresh-start rule. A valid
   foreign-magic base is left untouched. Corrupt/unknown/unreadable files
   disable publication while in-memory discovery continues. Publication
   retains exclusive random temporary creation with bounded collisions, file
   sync, atomic installation and the storage owner's directory-sync policy.
   First installation cannot overwrite a newly appeared destination. Saves
   retain the captured revision only after durable success, outside the state
   lock; concurrent later changes remain dirty. Periodic saves occur every
   15 minutes and shutdown/explicit barriers remain immediate.

   Actual Core group/placement evidence includes 224 ASMap rows and official
   Tried236/New795 anchors. Current-format tests retain IP/Tor/I2P round trips,
   anchors, membership, services, map changes and atomic publication proofs.
   These are specific algorithm/persistence checks, not full peer-lifecycle
   parity. Historical upgrade fixtures are not a compatibility requirement.

   Restart anchors come only from automatic block-relay peers that supplied
   accepted chain evidence, with the existing seven-day age limit. On the first
   active-network maintenance tick they
   are removed from the durable snapshot before any endpoint is exposed for
   dialing. Failed/read-only publication exposes no anchors. Their original
   confirmation metadata moves into the existing pending reservation; queued
   reservations consume a normal outbound slot, while feelers do not. Accepted
   worker dispatch consumes an anchor at most once, independently of actual TCP
   health accounting. Never-dispatched reservations return before shutdown save
   with the original confirmation time, without replacing newer demonstrated
   anchors. Dispatched attempts never return merely because connection fails.
   A stale queue item cannot dispatch after its reservation was returned.
5. **Service bits**: the base set follows storage (`init.cpp:2022-2026`): `NETWORK | WITNESS` normally, `NETWORK_LIMITED | WITNESS` when `storage.prune_target_mb > 0`, so a pruned node never claims a full block history. `NODE_P2P_V2` is added while `v2transport` is on, its default, as Core does. `NODE_BLOOM` remains unsupported. `NODE_COMPACT_FILTERS` is advertised on new handshakes only while the explicitly enabled filter index is healthy and caught up. Pruning and filter indexing cannot be enabled together. Existing connections retain their negotiated flags, but each filter query checks current readiness. See [the indexing contract](../contracts/indexing.md) and [the pinned Core/Kyoto runner](../../tools/compact-filter-interop/README.md).
6. **Timestamp**: `version.timestamp` is always 0 (§4).
7. **Automatic discouragement** (§6) uses bounded exact-IP expiry rather than Core's rolling Bloom filter. The explicit strict-parser, transport and permission differences are listed in §6; there is no additive score.
8. **Chain-sync timeout scope**: a full-relay outbound connection that stops bringing a better chain is timed out as Core does (`ConsiderEviction`, `net_processing.cpp:5498-5550`), with one `getheaders` probe at 20 minutes (`CHAIN_SYNC_TIMEOUT`, definition `net_processing.cpp:109`) and the first four outbound connections to reach the tip protected (`MAX_OUTBOUND_PEERS_TO_PROTECT_FROM_DISCONNECT`, definition `net_processing.cpp:107`). Protection and the timeout both key on a tip the peer actually handed us, never on the height its handshake claimed: Core reads `pindexBestKnownBlock` there, not `nStartingHeight` (use-site `net_processing.cpp:3203-3210`). An operator-pinned connection is exempt in both, as it is in Core: `IsOutboundOrBlockRelayConn()` excludes `ConnectionType::MANUAL` (`net_processing.cpp:5502`). Block-relay-only connections are exempt here; Core times out both outbound classes. A connection dialed for blocks alone is therefore never replaced by this timer.
9. **Download budgets**: bitcoin-rs bounds one sync at `PENDING_BUDGET = 256` in-flight bodies and `RECEIVED_BLOCK_BUDGET = 256` staged bodies (`crates/p2p/src/download_window/policy.rs:54,58`), and stripes at `MAX_BLOCKS_IN_TRANSIT_PER_PEER = 16` once `MIN_PEERS_FOR_FANOUT = 8` eligible peers exist (`:107,116`), where Core runs one `BLOCK_DOWNLOAD_WINDOW = 1024` ahead of the last common block with the same 16 per peer (`net_processing.cpp:151,133`). The 256 depth is measured, not assumed: a bounded 0–150,000 daemon single-peer IBD run at this window was 1.52× the 128-block control (`crates/p2p/src/download_window/policy.rs:50-51`). The shallower window is a bounded divergence kept by operator decision: it caps buffered bodies and re-request work per connection instead of matching Core's depth.
10. **Extra-peer selection**: once a stale tip needs no extra full-relay connection, bitcoin-rs retires the newest automatic full-relay outbound connection that sits one beyond the slots and is older than `MINIMUM_CONNECT_TIME` (`retire_extra_full_relay_connection`, `crates/p2p/src/service.rs:976`). An operator-pinned connection is outside the count and the victim set both, as in Core: neither `IsFullOutboundConn()` nor `IsBlockOnlyConn()` includes `ConnectionType::MANUAL` (`net_processing.cpp:5558-5604`). Core's `EvictExtraOutboundPeers` (`net_processing.cpp:5604-5668`) instead retires the connection that announced a block longest ago, breaking a tie by dropping the most recently connected one. The retired count is the same; the retired connection is not. A pinned outbound peer therefore neither creates an excess nor stands as a victim, matching `IsFullOutboundConn`/`IsBlockOnlyConn` excluding `ConnectionType::MANUAL` (`net_processing.cpp:5558-5604`).
11. **Unanswered ping**: Core sends one ping per `PING_INTERVAL` and remembers the nonce it asked for; when the pong has not arrived by `TIMEOUT_INTERVAL` after that ping, `MaybeSendPing` ends the connection regardless of any other traffic (`net_processing.cpp:5698-5712`). bitcoin-rs probes on the same cadence and ends a connection when either direction has been silent for `TIMEOUT_INTERVAL`, but it credits any inbound message as receive activity and keeps no outstanding-ping record, so a peer that never answers a probe while other traffic continues is not retired by that rule here.

12. **Inbound eviction**: once the live inbound count reaches `max_peer_connections - outbound_full_relay_slots - outbound_block_relay_slots` (default `200 - 8 - 2 = 190`, Core `net.h:1118`), a newcomer at an address holding a live inbound connection replaces it without eviction. Any other newcomer evicts the connection chosen by a port of Core's `SelectNodeToEvict` (`node/eviction.cpp:178-240`), or is refused when every candidate is protected or its address holds a live outbound connection (`crates/p2p/src/eviction.rs`, `PeerTable::try_register_inbound`; Core `net.cpp:1819-1826`). The port differs from Core as follows, so its choice can differ from Core's:
    - There is no minimum-ping protection. Core protects the eight connections with the lowest ping round trip, and bitcoin-rs measures none (item 11), so up to eight more connections are evictable.
    - Recency is an order, not a clock. Core compares last-block, last-transaction and connection times in whole seconds, so a same-second tie falls to the next criterion. bitcoin-rs orders by delivery sequence and monotonic instant.
    - A block counts once applied. Core credits a peer whose block is newly stored (`net_processing.cpp:3429-3432`), side-branch blocks included. bitcoin-rs credits a block when it is applied to the active chain.
    - Wanted services are judged at eviction. Core fixes `fRelevantServices` when the peer's `version` arrives (`net_processing.cpp:3672`). bitcoin-rs evaluates `has_all_desirable_service_flags` against the tip depth at the newcomer's arrival, which differs only for a `NODE_NETWORK_LIMITED` peer whose standing crossed the 144-block threshold in between.
    - A newcomer at an address holding a live outbound connection is refused instead of evicting. The table keys one connection per address, so admitting it would replace the outbound connection too. Core keeps both.
    - Core reserves part of the uptime protection for onion, I2P, CJDNS and localhost peers; this implementation still reserves uptime protection only for localhost, even when overlay transports are enabled.

    Two Core steps never apply. BIP37 filters are ignored, so no peer has the bloom filter Core's transaction-time tie-break looks at. A discouraged address is refused at accept, where Core admits it while the inbound slots are not almost full and then evicts it first (`net.cpp:1811-1817`), so no candidate is discouraged.
13. **Outbound service gate**: an outbound peer that does not advertise the desirable set is disconnected right after its `version`, before it is published as usable, exactly as Core's `HasAllDesirableServiceFlags` check does (`net_processing.cpp:1857-1872`, applied to an outbound connection at `:3864-3871`). The desirable set is `NETWORK | WITNESS`, or `NETWORK_LIMITED | WITNESS` while the local tip is younger than 144 blocks (`NODE_NETWORK_LIMITED_ALLOW_CONN_BLOCKS`). Inbound peers are not service-checked, as in Core.
14. **Limited peers and block download**: a connection without `NODE_NETWORK` is never asked for block bodies while the node is in initial block download, and after it only for the last 288 blocks of that peer's own chain (`net_processing.cpp:6521`, `NODE_NETWORK_LIMITED_MIN_BLOCKS` at `:159`, window applied at `:1637`). The rule reads the node's single `InitialBlockDownload` latch and applies to request, fan-out, probe, and hedge selection alike; header requests stay open to such a peer.
15. **Transaction download scheduling bounds**: one P2P owner tracks
   txid and wtxid announcements, with 5,000 retained announcements and 100
   in-flight requests per connection, a 60-second request lifetime, and
   two-second non-preferred, txid-while-wtxid-peers-exist, and overloaded
   source delays (Core `node/txdownloadman_impl.cpp:198-221`). An outbound
   eligible source wins over inbound candidates. Matching `notfound`,
   disconnect and expiry release ownership and make remaining announcers
   immediately eligible; unsolicited `notfound` cannot release another
   source's request. Admission completion releases only the delivering source; alternate witnesses
   remain eligible until mempool/orphan/reject state retires the matching
   identity. Accepted bodies retire both identities. A paced 100-ms pass checks
   at most 1,024 retained identities against known state and at most 1,024 ready
   request identities before sending. The ordered request owner supplies the
   resumable cursors for both sweeps and ready batches, so reannounced lower
   keys cannot starve older tail requests. These traversals still use that map;
   a separate derived set of candidate references serves only bounded admission.
   Every selected identity is checked even if its periodic sweep turn has not arrived. Gateway
   reads happen without policy/table locks; eligible candidates are rechecked
   before reserving and enqueueing under one owner lock. Only transaction inv
   wakes periodic policy work from the wire: ping, headers and unrelated traffic
   perform no gateway census. Matching notfound, disconnect and admission results
   use scoped immediate checks, preserving prompt fallback between periodic ticks.
   TX/WTX announcements carrying identical 32-byte hashes share one download
   ownership domain, including source preference and failure fallback (Core
   `txrequest.cpp` `ByPeer`/`ByTxHash`). Known/reject checks retain their inventory
   type. Different raw hashes remain independent until a body proves their
   txid/wtxid relationship; no persistent alias map or second body cache is added. Additional
   native resource policy: at most 100,000 total announcements and eight sources
   per raw 32-byte hash shared by TX/WTX. At either limit a preferred arrival may
   replace one non-preferred, non-owner candidate with the largest existing
   numeric priority. A full hash must replace within that hash; that one removal
   also frees a global slot when both caps are full. Current owners and preferred
   candidates are protected. Ordinary arrivals or fully protected limits are
   refused, as are duplicates and sources already at their 5,000-entry cap,
   without eviction or punishment. Core does not have these global/hash caps;
   this replacement rule is native resource policy, not Core contributor fairness.
   One derived ordered set holds at most 100,000 fixed-size references
   (priority, typed identity, connection ID), never announcement/owner copies.
   Admission uses a constant number of lookups and scans of candidate groups,
   each bounded by eight entries. Global victim selection uses the ordered index
   with logarithmic updates; there is no per-announcement full-table scan or lazy
   stale entry.
   Orphan-parent requests share the owner and limits but preserve their
   existing immediate source retry rather than Core's parent delay. A parent
   already announced by that source is expedited without another announcement
   or a second in-flight owner; ordinary duplicate inv cannot bypass its delay.
   A newly retained parent reports success even when replacing a weak candidate
   leaves the total announcement count unchanged.
   These hard caps are resource-policy bounds, not measured throughput claims.
16. **Inventory timing and bounds** (TXR-09): transaction identities are
   queued under the same P2P owner as downloads. Inbound connections share an
   exponential deadline by remote IP network class and actual local bind IP
   and port, matching Core's key for supported IP transports; outbound
   connections have independent deadlines. Remote addresses, source ports,
   netgroups, and ASNs do not split a shared clock. The shared map lasts for
   the policy owner's lifetime, keyed only by local endpoints and network
   classes, so disconnecting and reconnecting cannot redraw a future deadline.
   Deadlines use Core's 5-second inbound and 2-second outbound means, with an
   additional 30-second maximum delay. During IBD, due ticks advance the
   deadline without draining pending inventory. Outside IBD, each due tick
   orders queued parents before children and prefers higher-fee eligible
   entries, then sends at most
   `min(1000, 70 + 5 * (pending / 1000))` inventory vectors, matching Core's
   target and cap. Empty ticks also advance the deadline so a new admission
   does not define the broadcast clock. Additional bounds are 5,000 pending
   entries per peer and 100,000 globally; overflow drops new entries without
   blocking admission or discouraging peers. Each connection remembers 5,000
   exact recently known identities in a bounded FIFO set (Core uses a rolling
   Bloom filter). Version `relay=false`, block-relay roles, source exclusion,
   negotiated txid/wtxid encoding, the latest received fee filter, and the
   queued admission epoch are rechecked at their owning boundaries.
17. **Outgoing fee-filter timing**: the threshold comes from the gateway's
   existing mempool-pressure/min-relay projection and is rounded through
   Core v31.1's 1.1-spaced grid (50 sat/kvB initial boundary, 10,000,000 sat/kvB
   maximum grid). The final value is at least the configured min-relay floor.
   Unchanged values are not resent; randomized periodic refreshes average ten
   minutes. A substantial change advances a distant refresh to within five
   minutes. IBD uses the high filter and exit schedules an immediate floor
   refresh. The extra inventory latency cap and exact known-inventory FIFO
   are explicit bounded-resource choices; no throughput or bit-for-bit timing
   parity is claimed.
18. BIP434 `feature` negotiation and BIP332 stale-tip relay: implemented against the draft specifications in `crates/p2p/src/feature.rs` and `staletip.rs`, the handshake FSM and peer state, as default-off opt-in relay (`RelayOffers::stale_tip_relay`, `crates/p2p/src/listener.rs`, `service.rs`). An enabled node offers one `BIP332` announcement carrying its `stale_tip_prefers_blocks` byte to peers at `70017` or higher and records the peer's `BIP332` byte only when it offered; stale-tip relay in either direction additionally requires the peer's `BIP332` negotiation and inactive initial block download (§5). Core 31.1 does not support BIP434 and advertises `70016`, so bitcoin-rs never sends it a `feature` message; no Core 31.1 interoperability or support is claimed and that leg of the proof is blocked until a Core build that implements BIP434 is pinned (§2.1). No external consumer evidence exists for this command.

## 8. Verification

- **BIP434 negotiation and BIP332 relay**: `crates/p2p/src/handshake.rs` test `announcements_go_only_to_peers_at_the_feature_version` pins the default-off, opt-in, and `70017` gates (empty without an offer, one `BIP332` announcement when offered, nothing below the threshold), with `inbound_handshake_announces_an_offered_bip332_between_feature_messages_and_verack` and `inbound_handshake_never_announces_bip332_to_a_pre_bip434_peer` pinning the handshake slot; the feature codec, FSM, BIP324 and wire-codec tests and `core_compat` cover the remainder, which rest on in-tree tests only. The Core leg is blocked, because the pinned Core 31.1 does not support BIP434 (§7, item 18). No external-consumer result exists for this command.
- **Deterministic fixtures**: `crates/p2p/tests/core_compat.rs` pins the command inventory against rust-bitcoin's v1 envelope (`RawNetworkMessage`), the handshake fields and service bits, the per-role `relay` advertisement and the block-relay-only prohibition on transaction traffic, per-network magic/ports and framing, getheaders/headers semantics and bounds, inv/getdata relay round-trips with `notfound`, the reject-or-ignore matrix of §6, and the peer-visible behavior across a chain switch (reorg) and a restart at the `ChainQuery` seam: a rebuilt query serves byte-identical answers, a switched active branch serves the new branch from the fork point while recently validated stale bodies remain available by hash. Run with `cargo test -p bitcoin-rs-p2p --test core_compat`.
- **Transaction consumers**: `crates/p2p/src/dispatch.rs` test
  `gateway_inventory_filters_and_serves_txid_and_wtxid` exercises lookup,
  requested serialization, and retained-body immutability over the gateway.
  `announced_transactions_request_witness_without_changing_hashes` covers
  ordinary inventory requests with and without the inventory filter.
  Node's `tx_ingress_e2e` suite requires witness requests from its
  `NODE_WITNESS` dialers before delivering transactions. `crates/p2p/src/inv.rs` tests
  `missing_parents_use_txids_and_deduplicate_repeated_inputs`,
  `missing_parents_request_witness_by_service_not_announcement_preference`,
  `stale_missing_parent_source_cannot_send_to_or_cancel_replacement`,
  `cancelled_missing_parent_source_does_not_enqueue_a_request`, and
  `missing_parent_request_keeps_outbound_saturation_policy` cover txid parent
  requests and live-connection identity. `crates/p2p/src/tx_relay.rs` tests
  `peer_relay_reaches_replacement_and_cancels_only_saturated_peer` and
  `disconnected_relay_worker_does_not_count_queue_saturation` cover relay
  delivery and saturation ownership.
  `relay_waits_for_handshake_and_selects_the_peers_inventory_type` and
  `local_tx_relay_uses_committed_wtxid_and_ignores_peer_and_removed_entries`
  cover negotiated announcements and actual retained witness identity.
  Run with `cargo test -p bitcoin-rs-p2p --lib`.
- **Paused `getdata`**: `crates/p2p/src/dispatch.rs` tests
  `headroom_false_before_first_load_parks_without_loading`,
  `hostile_50000_item_getdata_parks_the_tail`,
  `halted_mixed_getdata_parks_ordered_tail_and_unsent_misses`, and
  `gate_closed_at_the_trailing_report_parks_the_misses` cover the park and
  the request order it keeps. `crates/p2p/src/listener/getdata_pause_tests.rs`
  drives `run_message_loop` over loopback sockets:
  `saturated_getdata_parks_tail_and_serves_it_after_drain` pins the wire order
  across a byte-saturated drain with the immediate `notfound`,
  `tiny_item_flood_pauses_at_the_item_cap_and_drains_in_order` the same for an
  item-cap-saturated queue where the `notfound` must wait,
  `a_getdata_that_fills_the_last_slot_parks_its_trailing_notfound_and_the_next_pong`
  the last-slot boundary (trailing `notfound` and the following `ping`),
  `a_drained_getdata_holds_reads_until_the_queue_can_take_a_reply` the read
  hold, `a_full_queue_keeps_the_misses_and_sends_nothing` the no-send-when-full
  invariant, `paused_peer_that_never_reads_ends_on_write_timeout` and
  `production_writer_marks_the_budget_dead_when_a_write_fails` the writer-death
  wake, and `lease_cancel_ends_a_parked_session` the cancel exit.
  `crates/p2p/src/connection.rs` tests cover the headroom and capacity
  predicates and the budget's wake protocol, and `keepalive_tests` cover the
  receive-silence exemption.
- **Aggregate outbound budget**: `crates/p2p/src/connection.rs` tests
  `strict_cap_no_empty_queue_bypass`, `reservation_is_the_admission`,
  `concurrent_reservations_never_exceed_cap`, `shrink_and_drop_wake_waiters`,
  `credit_drop_exactly_once`, `bulk_margin_keeps_control_flowing`,
  `send_with_fails_closed_and_releases_the_credit`,
  `dead_writer_refuses_charges_and_reclaims_nothing`,
  `healthy_peer_progresses_beside_a_locally_saturated_peer`, and
  `aggregate_waiter_resumes_on_another_connections_drain` pin the strict cap,
  the reservation as the admission, exactly-once release and the wake
  protocol. `crates/p2p/src/listener.rs` tests
  `queued_frames_release_on_writer_exit` and `writer_releases_budget_after_write`
  pin release on every writer exit path.
  `crates/p2p/src/listener/aggregate_budget_tests.rs` tests
  `headroom_retains_one_credit`, `parked_misses_reserved_before_build`,
  `reply_bound_covers_actual_replies`, `request_deferred_not_reply`,
  `deferred_request_retries_and_keeps_the_existing_local_rules`,
  `stall_exclusion_removes_only_shared_refusals`, and
  `a_bulk_tail_parked_on_the_aggregate_leaves_the_margin_for_control` cover
  deferral, the exact reservations and the stall rule over loopback sockets.
  `crates/p2p/src/peer.rs` test `filter_deadline_excludes_only_shared`,
  `crates/p2p/src/dispatch.rs` test
  `filter_remainder_is_the_parked_requests_only_cursor`, and
  `crates/p2p/src/chain_query.rs` tests
  `filter_backpressure_defers_unsent_responses_and_parks_the_remainder_of_a_partial_stream`
  and `compact_filter_interruptions_that_are_not_backpressure_stay_errors`
  cover the filter remainder and its deadline.
  `crates/p2p/src/sync/tests/aggregate_saturation.rs`,
  `crates/p2p/src/sync/tests.rs`
  `cold_front_hedge_skips_a_saturated_candidate_without_cancelling_it`,
  `crates/p2p/src/tx_policy/preferred_tests.rs` `tx_getdata_saturated_unclaims`,
  `crates/p2p/src/tx_policy/relay.rs` `feefilter_saturated_restores` and
  `relay_inv_saturated_requeues`, and `crates/p2p/src/block_announce.rs`
  `announcement_saturated_retried` and
  `demotion_saturated_keeps_the_selection_and_retries` cover the producers
  that keep their intent.
- **Compact receive admission**: three tests in
  `crates/p2p/src/sync/tests/head_sync.rs` together cover each branch of
  `BlockSync::compact_reconstruction_admissible`.
  - `compact_reconstruction_admission_follows_cores_header_gate` covers a
    target other than the required one and the case with nothing applied yet.
  - `compact_reconstruction_admission_reads_admitted_tree_state` covers an
    admitted header past the live clock ceiling, and a block or a parent
    marked invalid.
  - `compact_reconstruction_admission_stays_near_the_applied_tip` covers
    held headers one and two blocks above the applied tip, which earn the
    scan, three and five blocks above, which do not, and an owned fetch
    beyond that distance.

  `crates/p2p/src/listener.rs` test
  `compact_reconstruction_requires_an_earning_header` covers the message path
  through the listener. Run with `cargo test -p bitcoin-rs-p2p --lib`.
  - A header without proof of work, one with an unknown parent, and a
    replayed applied block are only announced, with no mempool scan.
  - Ownership counts only for the exact connection.
  - An extending or owned block reconstructs, and a repeat does not rescan.

  `compact_blocks::tests::replay_dedup_spans_more_than_sixty_four_blocks_until_the_deadline`
  holds deduplication across more than 64 hashes until the deadline.
- **Compact serving**: `crates/p2p/src/chain_query.rs` test
  `compact_exchange_keeps_the_mutually_supported_version` drives the
  production dispatcher through negotiation in both orders and checks
  serialized replies with rust-bitcoin and retained body immutability (BIP152).
  `getblocktxn_versions_preserve_missing_body_and_invalid_index_outcomes`
  covers unavailable blocks, empty index lists, and out-of-range indexes
  for the same profiles.
- **Stale-block serving**: `chain_query` tests cover same-height stale/winner
  identity, I/O-time reorg/invalidation/age changes, the strict 30-day time and
  proof-work bounds, applied-tip depth with headers ahead, and headroom before
  I/O. `bin/bitcoin-rs/tests/compact_blocks_e2e.rs` test
  `stale_compact_block_finishes_reconstruction_after_reorg` holds a compact
  response across an actual regtest process reorg, fetches its missing
  transaction, verifies reconstruction, and fetches both same-height bodies.
- **Fuzz**: `fuzz/fuzz_targets/p2p_message.rs` drives every payload decoder named by `COMMANDS` (a missing inventory row is a decoder no fuzz input can reach).
- **Live lane (cut)**: owned by [`CORE-01` / `CORE-02` / `CORE-03` / `CORE-05` / `CORE-06`](../contracts/core-differential.md). `CORE-05` compares outbound `inv`, `headers`, and high-bandwidth `cmpctblock` frames from equivalent peers on pinned Core and bitcoin-rs, including a live reorg. `CORE-06` runs BIP324 v2 against Core in both connection directions. This policy does not restate the Core version, RPC set, or CI job.
- Node-level reorg effects are coordinated in `crates/node/src/reorg.rs` (`switch_to_branch`, `invalidate_block`), which moves the applied tip off a losing branch; the node's P2P-chain adapter calls `switch_to_branch` when a higher-work header branch wins. The reorg fixture pins the peer-visible part of this at the `ChainQuery` seam — the exact surface `ActiveChainQuery` implements — via `reorg_switches_which_chain_a_peer_sees` (`crates/p2p/tests/core_compat.rs`).

See also [docs/contracts/p2p-wire.md](../contracts/p2p-wire.md) for the contracts index and precedence rule.

## Overlay transports

`primitives::endpoint` owns logical IP, Tor v3 and I2P destination identities.
Those identities key the existing peer table, connection sources, mempool
attribution, address book, netgroups and relay. A loopback SOCKS/SAM hop is
never the remote peer's identity. The existing listener owns Bitcoin framing,
handshake, leases, counters, admission and message processing for all streams.

`p2p::overlay` owns opt-in route selection and SOCKS5/SAM setup; its private
Tor control and IVNP SAM workers participate in `P2pService` startup/shutdown.
The service, transport and admission policy share one immutable routing
configuration. The SAM session owns its local destination; RPC advertises it
only while that session is live and inbound acceptance is enabled.
Allowed-network policy is checked both during selection and final admission.
The [configuration reference](../getting-started.md#tor-and-ivnp-i2p-networking)
owns option spellings and defaults. Setup uses absolute deadlines and bounded
cancellation polls for local overlay-service I/O. Direct IP dialing retains
the existing single 10-second TCP connect timeout and does not poll cancellation
during that call; the 100ms local-service reconnect helper is unsuitable for
high-latency remote TCP establishment. SAM session preparation has a 120-second bound; onion
circuit and I2P stream connection have a 60-second bound. Local service errors do not enter
remote protocol discouragement or count as failed overlay peer attempts.
Explicit SOCKS destination-unreachable/refused replies and SAM stream
`CANT_REACH_PEER`/`TIMEOUT` replies, plus a SAM naming `KEY_NOT_FOUND` reply
while dialing a destination, do update the existing address-book attempt
and retry policy. Undocumented naming results (including `TIMEOUT`),
authentication, malformed replies, local I/O and control
session failures remain local errors.

The existing outbound drain owns one retry policy for all `--connect` and
persistent `addnode` destinations, including direct IP, SOCKS and SAM routes.
The fixed-peer worker only resolves configured names and publishes desired
destinations. It never schedules a connection. The drain canonicalizes pins,
keeps at most one active dial per endpoint, and waits 1–60 seconds after
completion or local admission refusal before retrying. Observing a ready
connection resets its backoff; removing a pin removes its retry state.
One-shot manual requests do not create retained retry state. Remote-vs-local
failure attribution remains with the transport/listener and AddrMan owners
described above; there is no overlay-specific peer retry loop.

`run_sam` alone publishes/removes the SAM session record and starts replacement
epochs. Each epoch has one irreversible liveness marker shared by its streams
and leases. Control-session loss or `INVALID_ID` revokes only the observed
marker; a late failure cannot revoke the replacement. Reads, including reads
in the middle of a payload, use `PeerLease::is_cancelled`, which combines local
connection cancellation with that same epoch marker. The SAM worker asks the
peer table to wake only leases carrying its exact epoch marker. Ordinary
identity-checked lease teardown and sync reconciliation handle revocation;
there is no network-wide I2P cancellation sweep. The SAM worker restores the
selected stable destination with bounded backoff, independently of remote-peer retries.

Inbound Tor service identity is persistent but remote circuit identity is
unknown. Opaque per-connection handles are usable for disconnecting a live
connection; they are never persisted, learned as address-book sources, or
advertised as destinations. Inbound I2P uses `STREAM ACCEPT` Destination and
port metadata. Both paths use ordinary inbound capacity/eviction policy and
have no localhost exemptions. Core's special onion/I2P uptime protection in
eviction remains a deviation, as recorded above.

Inbound transaction-inventory clocks use the remote network class and local
bind endpoint. Tor circuits forwarded to one service share its bind clock.
Accepted I2P SAM streams have ephemeral local bind ports, so their clocks are
per stream rather than shared by application destination. This remains a
deviation from Core's shared inbound clock policy.

Routable `PeerAddress`/`PeerEndpoint` values contain only IP, Tor-v3 and I2P
destinations. Anonymous Tor circuits live in the connection owner's
`PeerRemote`, keyed by the lease's process-unique connection id. They share
one unknown-origin admission group, receive no proxy-loopback protection, and
have no destination to learn, persist, discourage or advertise through AddrMan.
Their RPC connection handle remains `tor-inbound-N:0`; it is not accepted by
destination configuration or dialing APIs.

AddrMan endpoint/source persistence follows the canonical v1 definition in
section 7. Invalid current source representations keep the original file
untouched with persistence disabled.
Application keys have a separate versioned,
checksummed create-once format. A bad existing identity fails startup and is
never replaced. IVNP router data and application identities have separate
owners and directories.

Local fixtures in `p2p::overlay` prove protocol transitions, refusal,
malformed input, timeout/cancellation, service loss and key preservation.
They do not prove privacy or external router interoperability. The manual
[`overlay-interoperability`](../../.github/workflows/overlay-interop.yml)
workflow runs `e2e/tests/overlay_connectivity.rs` through the existing process
harness against external Tor and the IVNP revision owned by
[`scripts/overlay-interop.py`](../../scripts/overlay-interop.py). Its artifacts
record executable hashes, Bitcoin peer identity/counters, headers/block
exchange and stable service-address restart observations. A failing or absent
campaign is unavailable interoperability evidence, not an advertised pass.
