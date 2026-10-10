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
| Protocol version advertised | `70016` (`crates/p2p/src/wire.rs::PROTOCOL_VERSION`) |
| Transport | Legacy v1 envelope only; BIP324 v2 is not implemented (§7) |

### 2.1 Version-Bump Rules

Re-pinning to a newer Core version requires all of:

1. A passing run of `scripts/run-p2p-core-interop.sh` against the new version, with evidence stored under `docs/benchmarks/`.
2. A diff of the peer-protocol message set (below) against the new version's `net_processing`, with every delta either implemented or added to the deviation ledger (§7).
3. Updating this document's pin, `crates/p2p/src/compat.rs::COMMANDS`, and the deterministic fixtures in the same change-set — no intermediate states where the table and the code disagree (anti-shim rule, `docs/policies/source-compatibility.md` §5). The fuzz target `p2p_message` consumes `COMMANDS` directly.

## 3. Transport and Envelope

- Bitcoin P2P **v1 envelope only** (`crates/p2p/src/wire.rs`): 4-byte network magic, 12-byte NUL-padded command, `u32` little-endian payload length, 4-byte checksum (first 4 bytes of double-SHA256 of the payload), then the payload.
- Payload bound: `MAX_MESSAGE_PAYLOAD = 32 MiB`. Core caps messages at 4 MiB; bitcoin-rs is deliberately looser so any protocol-maximal block fits. A peer that Core would disconnect for an oversized message may be accepted here; this is a bound difference, not a relay difference.
- Network magic and default ports come from `bitcoin_rs_primitives::Network` and are asserted equal to Core's constants per network (mainnet 8333, testnet3 18333, testnet4 48333, signet 38333, regtest 18444).
- Fork networks sharing a chain may override the message-start bytes with `--p2p-magic` (a bitcoin-rs extension; requires `--network mainnet` semantics and explicit `--connect` peers). Not a Core option; recorded as extension, not parity.

## 4. Handshake Contract

An outbound bitcoin-rs connection sends, in order: `version`, `wtxidrelay` (BIP339), `sendaddrv2` (BIP155), `sendheaders` (BIP130). An inbound connection receives `version` and answers with the same four messages, then `verack` completes readiness (`crates/p2p/src/handshake.rs`, `dispatch.rs`).


The `version` message pins:

| Field | Value | Core 31.1 comparison |
| :--- | :--- | :--- |
| `version` | `70016` | matches Core's latest protocol version |
| `services` | `NETWORK \| WITNESS`, or `NETWORK_LIMITED \| WITNESS` when `storage.prune_target_mb > 0` | Core derives the same set from the prune setting (`init.cpp:2022-2026`): a pruned node never advertises `NODE_NETWORK`. No `COMPACT_FILTERS`/`BLOOM`: those services do not exist here |
| `relay` | `true` on a full-relay connection, `false` on a block-relay-only dial | matches Core's per-connection preference (`PushNodeVersion`, `net_processing.cpp:1651-1689`) |
| `user_agent` | `/bitcoin-rs:<version>/` | distinct subver string; Core records it in `getpeerinfo.subver` |
| `timestamp` | `0` | deviation: we do not send a real clock; Core 31 does not misbehave-score time offsets (live interop evidence), but this remains a recorded deviation |
| `start_height` | current applied tip height | matches Core semantics |

Rules, each enforced by the FSM (`crates/p2p/src/fsm.rs`) and identical to Core's posture unless noted:

- `verack` before `version` → disconnect. Duplicate `version` after completion → disconnect (Core: misbehavior; ours: disconnect without ban scoring, §6).
- Any non-handshake message before readiness → disconnect. Core has the same rule except for a small handshake whitelist (`sendtxrcncl`); see §7 for the one practical divergence.
- After `verack`, unknown commands are ignored and the connection stays up — identical to Core's handling of unrecognized commands.

## 5. Message Surface

The decoder types exactly the commands in `crates/p2p/src/compat.rs::COMMANDS` (**36**). That table is the authority for names; this section owns each command's status and is the Core-comparison commentary, kept in sync with `COMMANDS` by hand in the same change-set.

| Command | Behavior and Core 31.1 comparison |
| :--- | :--- | :--- |
| `version` | negotiated | §4. |
| `verack` | negotiated | §4. |
| `wtxidrelay` | negotiated | BIP339. Sent in handshake; inbound marks the peer wtxid-relay capable. |
| `sendaddrv2` | negotiated | BIP155. Sent in handshake; inbound tracked. |
| `sendheaders` | negotiated | BIP130. Sent in handshake; inbound tracked. |
| `ping` | Answered with `pong` echoing the nonce, ready peers only. No latency telemetry is kept. |
| `pong` | ignored | No ping RTT accounting exists; the pong body is unused. |
| `inv` | Transaction vectors are answered with `getdata` for the ones the node does not already hold. P2P's `TxInventory` implementation queries the shared mempool gateway (accepted transactions, resident orphan wtxids, and recent rejects); a resident orphan never suppresses a txid-typed request, because another witness of that txid can still be valid; `MSG_TX` announcements are requested as `MSG_WITNESS_TX` from `NODE_WITNESS` peers and as `MSG_TX` otherwise; `MSG_WTX` requests retain their wtxid and type. While the node is in initial block download, transaction-typed vectors are never requested (Core 31.1 `net_processing.cpp:4401-4404`). Block-typed vectors (`MSG_BLOCK`, `MSG_WITNESS_BLOCK`) are never answered with a body `getdata`: they are announced to header sync against the announcing connection, which credits its best-known block and receives `getheaders` (Core `net_processing.cpp:4370-4410`, `docs/contracts/p2p-wire.md` `P2P-07`). Outbound block announcement uses single-block `inv` (`MSG_BLOCK`) as a compatibility fallback when a peer did not negotiate BIP130 `sendheaders`, when an active-chain anchor cannot be established, or when the anchor's distance from the committed tip exceeds `MAX_BLOCKS_TO_ANNOUNCE` (8). Bound: 50 000 vectors (`MAX_INV_PER_MSG`, Core `MAX_INV_SZ`). |
| `getdata` | `MSG_BLOCK` streams stripped stored blocks from the applied chain or an eligible stale branch; `MSG_WITNESS_BLOCK` preserves the stored witness serialization (BIP144). For full-relay peers, transaction inventory is served from the mempool, or from the orphan map only for a `MSG_WTX` item whose exact wtxid is resident. For block-relay-only peers, the listener removes transaction vectors before dispatch and drops transaction-only requests without a response. `MSG_TX` receives stripped serialization; `MSG_WITNESS_TX` and `MSG_WTX` receive witness serialization (BIP144/BIP339), without changing the retained body. A `MSG_CMPCT_BLOCK` item is answered with a `cmpctblock` only while the block is within 5 of the applied tip; a deeper one is served as the whole witness-bearing `block`, as Core does (`net_processing.cpp:2705-2721`). Misses among dispatched inventory resolve to one trailing `notfound`. Bound: 50 000 vectors. |
| `notfound` | ignored | Decoded with the same inventory bound. |
| `getheaders` | Answered with `headers` from the active chain: first locator hash on the active chain anchors the walk, total miss anchors after genesis, stop hash truncates inclusively, ≤ 2 000 headers per message (Core's per-message maximum). Locator bound: 101 hashes (Core `MAX_LOCATOR_SZ`). Empty locator + zero stop answers nothing (Core clients always send a locator; unreachable in practice). |
| `getblocks` | ignored | Legacy locator request; Core answers with an `inv`, we stay silent. Documented deviation. Locator bound identical. |
| `headers` | sink / outbound | Forwarded to the node's header-sync pipeline. Newly committed active tips are announced via BIP130 `headers` (up to 8 headers, Core `MAX_BLOCKS_TO_ANNOUNCE`) to peers that negotiated `sendheaders` and can anchor on active chain history. Bound: ≤ 2 000 headers per message. |
| `block` | sink | Forwarded to the node's block pipeline with the original wire bytes preserved. The shared inbound channel is bounded once for the node, and each connection's unsolicited share of it is bounded separately; a body the download window asked that connection for is always admitted (`docs/contracts/p2p-wire.md` `P2P-07`). |
| `tx` | sink | Forwarded from a Ready peer into the node's bounded ingress channel, except while the node is in initial block download: unsolicited transaction bodies are then dropped before ingress, without a misbehavior score or disconnect (Core 31.1 `net_processing.cpp:4713-4716`). Mempool prepares and retries admission through its one gateway; node connects committed peer accepts to P2P's relay queue, which announces the negotiated inventory type excluding the exact delivering connection. P2P requests missing parents from that live connection using txid-typed `getdata`; mempool owns orphan retention and retry. A full ingress channel drops the body so the peer read loop can still service ping, headers, and blocks. No protocol response, no disconnect. |
| `mempool` | ignored | BIP35 mempool snapshot request; Core answers with an `inv` of relay-pool transactions. Deviation: silent. |
| `getaddr` | served | At most 32 retained IP addresses, once per full-relay connection. Book-disabled test/embedding connections remain silent. |
| `addr` / `addrv2` | consumed | Decoded with a 1,000-entry wire bound, then admitted to the shared address book behind a 32-entry connection allowance replenished one per 10 seconds. Source-group limits and routability apply before retention; unsupported non-IP transports are ignored. |
| `feefilter` | ignored | BIP133. We never send one and do not enforce a peer's. Core filters relay by it. |
| `sendcmpct` | negotiated | BIP152. Sent after `verack` in low-bandwidth mode (`send_compact=false`, version 2). Up to 3 peers are promoted to high-bandwidth mode (`sendcmpct(true, 2)`), demoting older peers (`sendcmpct(false, 2)`) when the cap is reached. Inbound `sendcmpct` establishes peer compact-relay version and high-bandwidth preference. Ready peers in high-bandwidth mode receive unsolicited `cmpctblock` announcements for new tips if the peer is known to hold the parent block (`prev_blockhash`); suppressed in `blocksonly` mode. Inbound announcements also publish compact-fetch eligibility. |
| `cmpctblock` / `blocktxn` | sink | BIP152 receive path. `cmpctblock` starts bounded per-peer reconstruction: the prefilled coinbase/transactions plus short-ID matches against the mempool under the identity profile we advertised (`COMPACT_BLOCK_VERSION`) — BIP152 identity is directional: our advertised version fixes what a compliant peer sends us, and the peer's recorded version fixes what we serve; missing transactions are requested with `getblocktxn` on the same connection; two distinct mempool identities that collide on one short ID retire only that slot, which `getblocktxn` then carries; a duplicate declared short ID, a count mismatch, or a reconstruction that fails the bounds checks falls back to one full-block `getdata`; an entry whose deadline passes is dropped silently and the peer relies on the connection's separate stall/liveness handling — this module sends no deadline-driven `getdata`. `blocktxn` completes a pending reconstruction. Before delivery both completion paths re-verify the assembled body against the header's transaction-ID merkle root and reject a mutated transaction-ID tree (CVE-2012-2459 duplicate-final-transaction collision), so a short-ID misguess can never publish a wrong block; a failed check falls back the same way. A verified block enters the ordinary block pipeline like any `block` message — no validation bypass. |
| `getblocktxn` | served | BIP152. A stored, non-invalid block within 10 of the applied tip is answered with `blocktxn`, including a block that became stale after its compact announcement. As in Core, this shallow path requires body availability but does not apply the inventory stale-age filter. A deeper request uses full witness-bearing `block` inventory policy, including the stale validation and age restrictions below; depth is checked before past-the-end indexes. Unknown or unavailable blocks stay unanswered. The mutually supported compact serving profile determines transaction witness encoding. On the `blocktxn` path an index past the body is a protocol disconnect; empty or non-increasing indexes are rejected at the inbound boundary regardless of depth. The headroom gate runs before any body load. |
| `merkleblock` / `filterload` / `filteradd` / `filterclear` | ignored | BIP37. We do not advertise `NODE_BLOOM`, so a default Core peer never sends them; if one does, they are ignored. |
| `getcfilters` / `cfilter` / `getcfheaders` / `cfheaders` / `getcfcheckpt` / `cfcheckpt` | ignored | BIP157/158 compact-filter P2P is unsupported. We do not advertise `NODE_COMPACT_FILTERS` and do not serve compact filters. |
| `reject` | Decoded, never sent. Core 31 no longer emits `reject` for transaction acceptance results. |
| `alert` | Decoded as opaque bytes, ignored. The command is dead in Core. |

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
per-peer outbound saturation cancels that connection's lease. Each queued
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

## 6. Message Policy: Reject-or-Ignore, Disconnect Where Core Disconnects

| Condition | bitcoin-rs action | Core 31.1 action |
| :--- | :--- | :--- |
| Unknown command, peer ready | ignore, stay connected | ignore |
| Non-handshake command before readiness | disconnect | disconnect (misbehavior), except Core's handshake whitelist (§7) |
| Payload fails to decode | disconnect (typed `PeerError::Encode`) | disconnect (misbehavior) |
| Checksum mismatch | disconnect | disconnect |
| Wrong network magic | disconnect | disconnect |
| Declared length > 32 MiB | disconnect | disconnect (above Core's 4 MiB cap) |
| `inv`/`getdata`/`notfound` > 50 000 vectors | disconnect | misbehavior 40 → eventual ban |
| `addr`/`addrv2` > 1 000 entries | disconnect | misbehavior → eventual ban |
| Locator > 101 hashes | disconnect (checked before any state mutation) | misbehavior 255 → ban |
| `headers` > 2 000 entries | disconnect | misbehavior |
| `verack` before `version`; duplicate `version`; feature message while disconnected | disconnect | misbehavior |
| Idle connection | `ping` once a direction has been idle 2 min; disconnect once a direction is silent past 20 min | `ping` per 2 min regardless of traffic; disconnect when the outstanding ping goes unanswered for 20 min (`PING_INTERVAL`, `net_processing.cpp:125`; `TIMEOUT_INTERVAL`, `net.h:59`; `MaybeSendPing`, `net_processing.cpp:5698-5712`; `InactivityCheck`, `net.cpp:2043-2090`) |
| `tx` or a transaction `inv` on a block-relay-only connection | disconnect (protocol violation) | disconnect (`RejectIncomingTxs`, `net_processing.cpp:4706-4711`; the `inv` branch at `net_processing.cpp:4385-4390`) |
| `addr` or `addrv2` on a block-relay-only connection | ignored | ignored (address relay declined, `SetupAddressRelay`, `net_processing.cpp:5952-5970`) |

**Automatic misbehavior scoring and bans are not implemented.** Every row above that Core answers with a misbehavior score is answered here with a plain disconnect; banning exists only as the manual subnet mechanism (setban-style), held in memory. Repeated protocol abuse must be handled by the operator until automatic scoring lands (it is not scheduled; do not claim it in docs).

Structural invariants, verified by the deterministic fixtures (`crates/p2p/tests/core_compat.rs`):

- A rejected bound check fires *before* the FSM advances, so a rejected message never mutates peer state.
- No inbound message — valid, malformed, or unknown — can stall or abort the listener; errors tear down only their own connection. The accept loop and other peers continue (this is the peer-facing face of the never-block-core invariant).

## 7. Deviation Ledger

Known deltas from Core 31.1 (the `TXR-nn` labels index Core's tx-relay
inventory in `net_processing.cpp`: TXR-01–07 are the per-peer request-tracker
duties Core 31.1 owns in `node::TxDownloadManager` (`src/node/txdownloadman.h`),
issued through `GetRequestsToSend` in `SendMessages` (`net_processing.cpp:6206`);
TXR-09 is the trickled inventory schedule, `m_next_inv_send_time` at
`net_processing.cpp:319` under the `INVENTORY_BROADCAST_*` delays at `:163-166`):

1. **BIP324 v2 transport**: not implemented. We speak v1 only; Core 31 accepts v1 peers.
2. **BIP330 `sendtxrcncl`**: not implemented; it is the one Core 31 command missing from our 36-command table. Decoded as `Unknown`: ignored from a ready peer (Core ignores unknown commands too), disconnected before readiness. Core whitelists it during handshake, so the only affected topology is a Core peer *dialing* bitcoin-rs with `-txreconciliation=1`. The supported topology — bitcoin-rs dials Core, Core sees an inbound peer — never receives it, because Core sends `sendtxrcncl` to outbound peers only.
3. **Proactive block announcements**: implemented for newly committed active tips. Ready peers receive unsolicited BIP152 high-bandwidth compact blocks (up to 3 peers when parent is known and tx relay is active), BIP130 headers (up to 8 blocks when anchored to the active chain), or fallback to single-block `inv` (`MSG_BLOCK`). Stale tips across reorgs are discarded and intermediate tips are coalesced under queue backpressure.
4. **Address management**: one P2P-owned `AddressBook` retains canonical
   endpoints, their original source and health, and up to eight distinct New
   bucket references. Lookup tables are derived indexes, not another persisted
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
   successful newcomer in New until the collision-probe follow-up.

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
   count; inbound and cancelled sessions do not. Manual attempts never count a
   failure or own an automatic claim. Good from any non-inbound handshake
   updates the epoch; known peers reset failures and record success/recent try,
   while unknown manual peers are not inserted. Good does not overwrite
   advertised last-seen time. Native periodic refresh applies only to ready
   automatic full-relay peers, at intervals over 20 minutes; block-relay peers
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
   Core-routable address is admitted. Only existing IP transports are supported.
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
   Non-IP addrv2 families are ignored; block-relay-only peers neither learn nor
   serve addresses. These boundaries are not a claim of complete Core peer
   lifecycle equivalence.

   The fixed indexes occupy 327,680 bytes; endpoint count is bounded at 81,920,
   with at most eight New bucket IDs each and at most 65,536 occupied New slots.
   On the tested 64-bit target Candidate is 128 bytes and Source is 24 bytes,
   excluding allocator/index/vector overhead. Fixed-width serialized fields
   have a conservative 512-byte/record bound (315-byte max-width fixture), so
   record separators plus bounded header/checksum remain below the 64 MiB file
   ceiling. Reads bound both bytes and record/reference sequences. These are
   representation/work bounds, not RSS or performance measurements.

   Schema v5 persists the secret, source, health and New membership in one
   checksummed snapshot. Same-schema restart restores every reference. The
   known v1 format is validated using its original 4,096-record/64-source/slot
   rules before migration. The actual source bytes are copied to an exclusive,
   content-named `.v1-<sha256>.bak` and file/directory-synced before v5 can replace
   the book. Re-bucketing is deterministic, prioritizes proven/recent successes,
   logs retained/demoted/dropped counts, and preserves the original backup.
   Legacy DNS retained only a u64 hash: its labelled deterministic source
   namespace does not claim to recover the original seed name or Core hash.
   A backup failure allows in-memory recovery but disables writes for the run.
   Unknown child v2/v3/v4 or other schemas remain preserved/read-only here;
   their actual ASMap/anchor owners provide later migrations.

   Filenames remain scoped to actual P2P magic: `peers.dat` becomes
   `peers-<8 hexadecimal magic digits>.dat`, including custom/drynet magics.
   A valid scoped book wins; same-magic legacy-base import retains the base,
   and a valid foreign-magic base is left untouched. Corrupt/unknown/unreadable
   files disable publication while in-memory discovery continues. Publication
   retains exclusive random temporary creation with bounded collisions, file
   sync, atomic installation and the storage owner's directory-sync policy.
   First installation cannot overwrite a newly appeared destination. Saves
   retain the captured revision only after durable success, outside the state
   lock; concurrent later changes remain dirty. Periodic saves occur every
   15 minutes and shutdown/explicit barriers remain immediate. ASMap grouping,
   tried-collision probing and restart anchors remain stacked follow-ups under
   #1387; the final combined stack requires its own acceptance checks.
5. **Service bits**: the advertised set follows storage (`init.cpp:2022-2026`): `NETWORK | WITNESS` normally, `NETWORK_LIMITED | WITNESS` when `storage.prune_target_mb > 0`, so a pruned node never claims a full block history. No `NODE_BLOOM` or `NODE_COMPACT_FILTERS` — those services do not exist here.
6. **Timestamp**: `version.timestamp` is always 0 (§4).
7. **Automatic misbehavior bans** (§6) absent; manual bans only.
8. **Chain-sync timeout scope**: a full-relay outbound connection that stops bringing a better chain is timed out as Core does (`ConsiderEviction`, `net_processing.cpp:5498-5550`), with one `getheaders` probe at 20 minutes (`CHAIN_SYNC_TIMEOUT`, definition `net_processing.cpp:109`) and the first four outbound connections to reach the tip protected (`MAX_OUTBOUND_PEERS_TO_PROTECT_FROM_DISCONNECT`, definition `net_processing.cpp:107`). Protection and the timeout both key on a tip the peer actually handed us, never on the height its handshake claimed: Core reads `pindexBestKnownBlock` there, not `nStartingHeight` (use-site `net_processing.cpp:3203-3210`). An operator-pinned connection is exempt in both, as it is in Core: `IsOutboundOrBlockRelayConn()` excludes `ConnectionType::MANUAL` (`net_processing.cpp:5502`). Block-relay-only connections are exempt here; Core times out both outbound classes. A connection dialed for blocks alone is therefore never replaced by this timer.
9. **Download budgets**: bitcoin-rs bounds one sync at `PENDING_BUDGET = 256` in-flight bodies and `RECEIVED_BLOCK_BUDGET = 256` staged bodies (`crates/p2p/src/download_window/policy.rs:54,58`), and stripes at `MAX_BLOCKS_IN_TRANSIT_PER_PEER = 16` once `MIN_PEERS_FOR_FANOUT = 8` eligible peers exist (`:107,116`), where Core runs one `BLOCK_DOWNLOAD_WINDOW = 1024` ahead of the last common block with the same 16 per peer (`net_processing.cpp:151,133`). The 256 depth is measured, not assumed: a bounded 0–150,000 daemon single-peer IBD run at this window was 1.52× the 128-block control (`crates/p2p/src/download_window/policy.rs:50-51`). The shallower window is a bounded divergence kept by operator decision: it caps buffered bodies and re-request work per connection instead of matching Core's depth.
10. **Extra-peer selection**: once a stale tip needs no extra full-relay connection, bitcoin-rs retires the newest automatic full-relay outbound connection that sits one beyond the slots and is older than `MINIMUM_CONNECT_TIME` (`retire_extra_full_relay_connection`, `crates/p2p/src/service.rs:976`). An operator-pinned connection is outside the count and the victim set both, as in Core: neither `IsFullOutboundConn()` nor `IsBlockOnlyConn()` includes `ConnectionType::MANUAL` (`net_processing.cpp:5558-5604`). Core's `EvictExtraOutboundPeers` (`net_processing.cpp:5604-5668`) instead retires the connection that announced a block longest ago, breaking a tie by dropping the most recently connected one. The retired count is the same; the retired connection is not. A pinned outbound peer therefore neither creates an excess nor stands as a victim, matching `IsFullOutboundConn`/`IsBlockOnlyConn` excluding `ConnectionType::MANUAL` (`net_processing.cpp:5558-5604`).
11. **Unanswered ping**: Core sends one ping per `PING_INTERVAL` and remembers the nonce it asked for; when the pong has not arrived by `TIMEOUT_INTERVAL` after that ping, `MaybeSendPing` ends the connection regardless of any other traffic (`net_processing.cpp:5698-5712`). bitcoin-rs probes on the same cadence and ends a connection when either direction has been silent for `TIMEOUT_INTERVAL`, but it credits any inbound message as receive activity and keeps no outstanding-ping record, so a peer that never answers a probe while other traffic continues is not retired by that rule here.

12. **Inbound admission**: bitcoin-rs refuses an inbound socket once the live inbound count reaches `max_peer_connections - outbound_full_relay_slots - outbound_block_relay_slots` (default `200 - 8 - 2 = 190`, `net.h:1124-1127`), closing the stream before a handshake lease exists (`crates/p2p/src/listener.rs`, `PeerTable::try_register_inbound`). Core derives the same remainder and then scores an eviction (`AttemptToEvictConnection`, `net.cpp:1695-1735`) to make room. The eviction scoring is deliberately not implemented: no bitcoin-rs sync path depends on being able to displace an inbound peer, the resource-exhaustion defect closes at the admission boundary, and adding a second peer-selection policy would need an acceptance requirement it does not have. The operator-visible consequence is that the 191st inbound connection is refused rather than replacing a chosen peer.
13. **Outbound service gate**: an outbound peer that does not advertise the desirable set is disconnected right after its `version`, before it is published as usable, exactly as Core's `HasAllDesirableServiceFlags` check does (`net_processing.cpp:1857-1872`, applied to an outbound connection at `:3864-3871`). The desirable set is `NETWORK | WITNESS`, or `NETWORK_LIMITED | WITNESS` while the local tip is younger than 144 blocks (`NODE_NETWORK_LIMITED_ALLOW_CONN_BLOCKS`). Inbound peers are not service-checked, as in Core.
14. **Limited peers and block download**: a connection without `NODE_NETWORK` is never asked for block bodies while the node is in initial block download, and after it only for the last 288 blocks of that peer's own chain (`net_processing.cpp:6521`, `NODE_NETWORK_LIMITED_MIN_BLOCKS` at `:159`, window applied at `:1637`). The rule reads the node's single `InitialBlockDownload` latch and applies to request, fan-out, probe, and hedge selection alike; header requests stay open to such a peer.
15. **Transaction request tracker** (TXR-01–05, TXR-07): absent. On an
   announced transaction, bitcoin-rs immediately requests it from every
   announcing peer that supplies the announcement; it has no Core-style
   per-peer in-flight request tracker or cap and does not retry a transaction
   after `notfound`.
16. **Poisson trickle** (TXR-09): absent. bitcoin-rs sends each accepted
   queued transaction as an immediate single-item `inv`; Core batches and
   delays relay through its trickle scheduling.
17. **Proactive `feefilter` emission**: absent. Core sends
   `feefilter=MAX_MONEY` while initial block download is active; bitcoin-rs
   does not construct or send `feefilter`. This is distinct from the §5
   receive row, which states that bitcoin-rs neither emits nor enforces peer
   feefilters.

## 8. Verification

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
- **Live lane (cut)**: owned by [`CORE-01` / `CORE-02` / `CORE-03` / `CORE-05`](../contracts/core-differential.md). `CORE-05` compares outbound `inv`, `headers`, and high-bandwidth `cmpctblock` frames from equivalent peers on pinned Core and bitcoin-rs, including a live reorg. This policy does not restate the Core version, RPC set, or CI job.
- Node-level reorg effects are coordinated in `crates/node/src/reorg_effects.rs` (`switch_to_branch`, `invalidate_block`), which moves the applied tip off a losing branch; the node's P2P-chain adapter calls `switch_to_branch` when a higher-work header branch wins. The reorg fixture pins the peer-visible part of this at the `ChainQuery` seam — the exact surface `ActiveChainQuery` implements — via `reorg_switches_which_chain_a_peer_sees` (`crates/p2p/tests/core_compat.rs`).

See also [docs/contracts/p2p-wire.md](../contracts/p2p-wire.md) for the contracts index and precedence rule.
