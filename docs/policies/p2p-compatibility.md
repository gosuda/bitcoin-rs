# P2P Compatibility Policy

This document declares bitcoin-rs's peer-wire compatibility contract with Bitcoin Core and the rules for keeping it pinned.

## 1. Scope and Authority

This policy applies to the P2P transport and peer-protocol surface of `bitcoin-rs-p2p` (`crates/p2p`), the P2P chain-serving adapter (`crates/node/src/p2p_chain.rs`), and the network flags of the node binary. It is the peer-visible counterpart to `docs/policies/source-compatibility.md` (toolchain) and the RPC compatibility manifest (track 4a). Where this document and prose comments disagree, this document wins; where it and the code disagree, the code is the defect.

## 2. Pinned Reference Version

| Setting | Value |
| :--- | :--- |
| Reference implementation | Bitcoin Core |
| Pinned version | **31.1** (the version already recorded in custody evidence) |
| Protocol version advertised | `70016` (`crates/p2p/src/wire.rs::PROTOCOL_VERSION`) |
| Transport | BIP324 v1 envelope only |

### 2.1 Version-Bump Rules

Re-pinning to a newer Core version requires all of:

1. A passing run of `scripts/run-p2p-core-interop.sh` against the new version, with evidence stored under `docs/benchmarks/`.
2. A diff of the peer-protocol message set (below) against the new version's `net_processing`, with every delta either implemented or added to the deviation ledger (§7).
3. Updating this document's pin, the fuzz-target command list (`fuzz/fuzz_targets/p2p_message.rs::COMMANDS`), and the deterministic fixtures in the same change-set — no intermediate states where the table and the code disagree (anti-shim rule, `docs/policies/source-compatibility.md` §5).

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
| `services` | `NETWORK \| WITNESS` | Core default nodes also advertise `NETWORK_LIMITED` (and `COMPACT_FILTERS`/`BLOOM` when the corresponding index/flag is on); we never prune, so the honest set is exactly these two bits |
| `relay` | `true` | matches a default full-relay node |
| `user_agent` | `/bitcoin-rs:<version>/` | distinct subver string; Core records it in `getpeerinfo.subver` |
| `timestamp` | `0` | deviation: we do not send a real clock; Core 31 does not misbehave-score time offsets (live interop evidence), but this remains a recorded deviation |
| `start_height` | current applied tip height | matches Core semantics |

Rules, each enforced by the FSM (`crates/p2p/src/fsm.rs`) and identical to Core's posture unless noted:

- `verack` before `version` → disconnect. Duplicate `version` after completion → disconnect (Core: misbehavior; ours: disconnect without ban scoring, §6).
- Any non-handshake message before readiness → disconnect. Core has the same rule except for a small handshake whitelist (`sendtxrcncl`); see §7 for the one practical divergence.
- After `verack`, unknown commands are ignored and the connection stays up — identical to Core's handling of unrecognized commands.

## 5. Message Surface

The decoder in `crates/p2p/src/wire.rs::decode_payload` dispatches exactly **36 commands**; this table is the authority for each. Statuses: *negotiated* (sent and processed in the handshake), *served* (answered with protocol data), *sink* (decoded and forwarded into the node), *ignored* (decoded, FSM-accepted, no response), *legacy* (decoded for corpus/legacy tolerance only).

| Command | Status | Behavior and Core 31.1 comparison |
| :--- | :--- | :--- |
| `version` | negotiated | §4. |
| `verack` | negotiated | §4. |
| `wtxidrelay` | negotiated | BIP339. Sent in handshake; inbound marks the peer wtxid-relay capable. |
| `sendaddrv2` | negotiated | BIP155. Sent in handshake; inbound tracked. |
| `sendheaders` | negotiated | BIP130. Sent in handshake; inbound tracked. |
| `ping` | served | Answered with `pong` echoing the nonce, ready peers only; pongs feed peer RTT stats. |
| `pong` | ignored | Completes outstanding ping RTT accounting. |
| `inv` | served | Answered with `getdata` echoing the announced vectors verbatim (a wtxid-relay peer announcing `MSG_WTX` is asked for `MSG_WTX`). Bound: 50 000 vectors (`MAX_INV_PER_MSG`, Core `MAX_INV_SZ`). |
| `getdata` | served | Served from the active chain: block inventory resolves to `block` messages; misses resolve to one `notfound`. Bound: 50 000 vectors. |
| `notfound` | ignored | Decoded with the same inventory bound. |
| `getheaders` | served | Answered with `headers` from the active chain: first locator hash on the active chain anchors the walk, total miss anchors after genesis, stop hash truncates inclusively, ≤ 2 000 headers per message (Core's per-message maximum). Locator bound: 101 hashes (Core `MAX_LOCATOR_SZ`). Empty locator + zero stop answers nothing (Core clients always send a locator; unreachable in practice). |
| `getblocks` | ignored | Legacy locator request; Core answers with an `inv`, we stay silent. Documented deviation. Locator bound identical. |
| `headers` | sink | Forwarded to the node's header-sync pipeline. Bound: ≤ 2 000 headers per message. |
| `block` | sink | Forwarded to the node's block pipeline with the original wire bytes preserved. |
| `tx` | sink (incomplete) | Decoded and FSM-accepted, but not yet delivered into the mempool — production transaction relay is incomplete (see `CONCEPTS.md` "Tx relaying"). No response, no disconnect. |
| `mempool` | ignored | BIP35 mempool snapshot request; Core answers with an `inv` of relay-pool transactions. Deviation: silent. |
| `getaddr` | ignored | No address gossip: Core answers with an `addr` burst. Deviation: silent. |
| `addr` / `addrv2` | ignored | Decoded (bound: 1 000 entries, Core `MAX_ADDR_TO_SEND`); never gossiped onward. |
| `feefilter` | ignored | BIP133. We never send one and do not enforce a peer's. Core filters relay by it. |
| `sendcmpct` | ignored (tracked) | BIP152 preference recorded per peer. We never announce compact-block relay, so Core sends us full blocks — the compatible fallback. |
| `cmpctblock` / `getblocktxn` / `blocktxn` | ignored | BIP152 receive path unused because we never opt in. |
| `merkleblock` / `filterload` / `filteradd` / `filterclear` | ignored | BIP37. We do not advertise `NODE_BLOOM`, so a default Core peer never sends them; if one does, they are ignored. |
| `getcfilters` / `cfilter` / `getcfheaders` / `cfheaders` / `getcfcheckpt` / `cfcheckpt` | ignored | BIP157/158 compact-filter P2P is unsupported. We do not advertise `NODE_COMPACT_FILTERS` and do not serve compact filters. |
| `reject` | legacy | Decoded, never sent. Core 31 no longer emits `reject` for transaction acceptance results. |
| `alert` | legacy | Decoded as opaque bytes, ignored. The command is dead in Core. |

Any command outside this table decodes as `Unknown` and follows §6 — which is also how the one Core 31 command absent above, `sendtxrcncl` (BIP330), is handled.

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
| Idle connection | disconnect after 60 s | disconnect after 20 min |

**Automatic misbehavior scoring and bans are not implemented.** Every row above that Core answers with a misbehavior score is answered here with a plain disconnect; banning exists only as the manual subnet mechanism (`setban`-style `NetworkControls`, persisted ban list). Repeated protocol abuse must be handled by the operator until automatic scoring lands (it is not scheduled; do not claim it in docs).

Structural invariants, verified by the deterministic fixtures (`crates/p2p/tests/core_compat.rs`):

- A rejected bound check fires *before* the FSM advances, so a rejected message never mutates peer state.
- No inbound message — valid, malformed, or unknown — can stall or abort the listener; errors tear down only their own connection. The accept loop and other peers continue (this is the peer-facing face of the never-block-core invariant).

## 7. Deviation Ledger

Explicit deltas from Core 31.1, each intentional and safe:

1. **BIP324 v2 transport**: not implemented. We speak v1 only; Core 31 accepts v1 peers.
2. **BIP330 `sendtxrcncl`**: not implemented; it is the one Core 31 command missing from our 36-command table. Decoded as `Unknown`: ignored from a ready peer (Core ignores unknown commands too), disconnected before readiness. Core whitelists it during handshake, so the only affected topology is a Core peer *dialing* bitcoin-rs with `-txreconciliation=1`. The supported topology — bitcoin-rs dials Core, Core sees an inbound peer — never receives it, because Core sends `sendtxrcncl` to outbound peers only.
3. **Proactive announcements**: absent. We do not broadcast `inv`/`headers`/`cmpctblock` for new blocks or relay transaction announcements. The node is a header/block consumer and an on-demand server; live relay of Core-originated blocks into bitcoin-rs is exercised by the interop lane (§8).
4. **Address management**: no `getaddr` answers, no addr gossip, no DNS-seed-free peer discovery beyond configured `--connect`/`--addnode` surfaces.
5. **Service bits**: we advertise exactly `NETWORK | WITNESS`. No `NODE_BLOOM`, `NODE_COMPACT_FILTERS`, or `NODE_NETWORK_LIMITED` — honest, since none of those services exist here.
6. **Timestamp**: `version.timestamp` is always 0 (§4).
7. **Idle timeout** 60 s vs Core's 20 minutes.
8. **Automatic misbehavior bans** (§6) absent; manual bans only.
9. **Inbound transaction relay into the mempool** incomplete (§5 `tx` row); protocol-level acceptance is proven, mempool delivery is not claimed.

## 8. Verification

- **Deterministic fixtures**: `crates/p2p/tests/core_compat.rs` pins the handshake fields and service bits, per-network magic/ports and framing, getheaders/headers semantics and bounds, inv/getdata relay round-trips with `notfound`, the reject-or-ignore matrix of §6, and the peer-visible behavior across a chain switch (reorg) and a restart at the `ChainQuery` seam: a rebuilt query serves byte-identical answers, a switched active branch serves the new branch from the fork point and `notfound`s stale bodies. Run with `cargo test -p bitcoin-rs-p2p`.
- **Fuzz**: `fuzz/fuzz_targets/p2p_message.rs` drives all 36 payload decoders; its `COMMANDS` list must stay in step with `decode_payload` (a missing entry is a decoder no fuzz input can reach).
- **Live lane (cut, env-gated)**: `scripts/run-p2p-core-interop.sh --bitcoind-command <cmd>` drives a real Bitcoin Core 31.x (regtest) plus a bitcoin-rs node through the initial sync, mines extra blocks after the handshake to prove the node follows Core's announcements while connected (bitcoin-rs itself sends no proactive announcements; see the deviation ledger), records Core's own `getpeerinfo` view of us (services bits, subver) into an evidence JSON, and runs the `#[ignore]`d verifier `crates/p2p/tests/core_interop_live.rs`. The lane is never run in CI (no bitcoind on CI hosts); its evidence belongs under `docs/benchmarks/` when a Core bump is pinned.
- Node-level reorg is implemented: `crates/node/src/reorg.rs` (`switch_to_branch`, `invalidate_block`) moves the applied tip off a losing branch, and sync calls `switch_to_branch` when a higher-work header branch wins (`crates/node/src/sync.rs`). The reorg fixture pins the peer-visible part of this at the `ChainQuery` seam — the exact surface `NodeP2pChainQuery` implements — via `reorg_switches_which_chain_a_peer_sees` (`crates/p2p/tests/core_compat.rs`).

See also [docs/contracts/p2p-wire.md](../contracts/p2p-wire.md) for the contracts index and precedence rule.
