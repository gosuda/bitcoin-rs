# BIP support matrix

Capabilities in the merged default branch, grouped by area. Support describes
the implementation for the stated scope; external evidence is a separate axis.
The [adoption policy](policies/bip-adoption.md) owns promotion decisions, and the
[evidence inventory](api/ecosystem-compat.toml) owns recorded external runs.

**Support:** ✅ Implemented · ◐ Partial · 🧪 Experimental (default-off or
draft-pinned) · ☐ Planned (unmerged PR or issue) · ❌ Unsupported.

**External evidence:** ✓ Recorded run of an unmodified external consumer for
the noted scope · — No recorded external qualification for this capability.
In-tree tests and copied reference vectors never earn ✓. ✅ does not mean the
policy's `Shipped` lifecycle stage or externally verified compatibility.
Linked capability names lead to code or tests; notes link scope and evidence owners.

## Consensus, script, and mempool policy

| BIP | Capability | Support | External evidence | Notes |
| :-- | :-- | :--: | :--: | :-- |
| 9 | [Versionbits](../crates/consensus/src/bip9.rs) | ✅ | — | CSV/segwit deployment windows |
| 125 | [Replacement policy](policies/mempool-policy.md) | ◐ | — | Full-RBF; signaling reported, not admission-gating |
| 16 | [P2SH](../crates/consensus/src/verify_block.rs) | ✅ | — | Two [hash-pinned exceptions](../crates/primitives/src/network.rs) |
| 34 | [Coinbase height](../crates/consensus/src/bip34.rs) | ✅ | — | Core activation heights; BIP30 recheck limit |
| 65 | [CLTV](../crates/consensus/src/verify_block.rs) | ✅ | — | Core activation heights |
| 66 | [Strict DER](../crates/consensus/src/verify_block.rs) | ✅ | — | Core activation heights |
| 68/112/113 | [Relative locks / MTP](../crates/consensus/src/bip68.rs) | ✅ | — | [Block connection](../crates/chainstate/src/connect.rs); BIP9 activation |
| 94 | [Timewarp protection](../crates/chain/src/header_sync.rs) | ✅ | — | Testnet4 BIP94 candidate-timestamp floor at retarget boundaries |
| 141 | [Segwit validation](../crates/consensus/tests/witness_commitment_rules.rs) | ✅ | — | Commitments, weight, [sigops](../crates/consensus/tests/witness_sigop_activation.rs) |
| 143 | [Segwit v0 sighash](../crates/consensus/tests/shared_sighash.rs) | ✅ | — | [Reference vectors](../crates/primitives/tests/bip_vectors.rs) |
| 147 | [NULLDUMMY](../crates/script/src/eval.rs) | ✅ | — | Enforced with WITNESS flag |
| 320 | [General-purpose version bits](../crates/chain/src/deployment.rs) | ❌ | — | Candidates use versionbits; no general-purpose policy |
| 341 | [Taproot](../crates/script/src/taproot.rs) | ✅ | — | Height-gated; key and script paths |
| 342 | [Tapscript](../crates/script/src/eval.rs) | ✅ | — | OP_SUCCESSx; [tagged hashes](../crates/script/src/taproot.rs) |
| 431 | [TRUC v3](../crates/mempool/src/truc.rs) | ✅ | — | Topology, sibling and ephemeral-spend rules |

## P2P and network

| BIP | Capability | Support | External evidence | Notes |
| :-- | :-- | :--: | :--: | :-- |
| 37 | [Bloom filters](policies/p2p-compatibility.md#5-message-surface) | ❌ | — | Commands decoded then ignored; no filter service |
| 111 | [NODE_BLOOM](../crates/p2p/src/wire.rs) | ❌ | — | Service bit not advertised |
| 130 | [Headers announcements](../crates/p2p/src/block_announce.rs) | ✅ | — | Up to 8 headers; [CORE-05 qualification pending](contracts/core-differential.md#core-05-proactive-block-announcements-across-a-live-reorg) |
| 133 | [Fee filter](../crates/p2p/src/tx_policy/relay.rs) | ✅ | — | Per-peer inventory floor; rounded local refresh |
| 144 | [Segwit relay](../crates/p2p/src/dispatch.rs) | ✅ | — | Witness block/transaction inventory preserves bytes |
| 152 | [Compact blocks](../crates/p2p/src/compact_blocks.rs) | ✅ | ✓ | Announcements are implemented (see policy §7); only the CORE-05 live-reorg qualification is pending; [Core 31.1 request/response scope](api/ecosystem-compat.toml); reconstruction counts diagnostic |
| 155 | [Address v2](../crates/p2p/src/wire.rs) | ◐ | — | Negotiation and IP receive path; getaddr sends legacy addr |
| 157/158 | [Compact filters](../crates/index/src/index/filters.rs) | ✅ | ✓ | Optional blockfilterindex; basic active-chain filters; [Kyoto regtest scope](api/ecosystem-compat.toml) |
| 159 | [Limited-network service](../crates/node/src/state_open.rs) | ✅ | — | Pruned nodes advertise NETWORK_LIMITED + WITNESS |
| 324 | [v2 transport](../crates/p2p/src/transport.rs) | 🧪 | — | Opt-in; [vectors](../crates/p2p/tests/data/bip324/) and [negotiation tests](../crates/p2p/src/listener/v2_transport_tests.rs); bidirectional Core interop pending |
| 330 | [Erlay](https://github.com/gosuda/bitcoin-rs/issues/1501) | ❌ | — | Explicitly deferred backlog (#1501 tracks the deferral, so the policy keeps it `Unsupported` rather than `Planned`); sendtxrcncl ignored |
| 339 | [Wtxid relay](../crates/p2p/src/peer.rs) | ✅ | — | Negotiation, announcements and getdata |
| 35 | [Mempool request](../crates/p2p/src/dispatch.rs) | ❌ | — | Command decoded then ignored |

## Mining

| BIP | Capability | Support | External evidence | Notes |
| :-- | :-- | :--: | :--: | :-- |
| 22 | [GetBlockTemplate](../crates/mining/tests/template_shape.rs) | ✅ | — | Template contract; [mining evidence](api/ecosystem-compat.toml) in-tree only |
| 23 | [GBT extensions](../crates/mining/src/coordinator.rs) | ◐ | — | Proposal mode, long-poll and version bits; no submitold/workid |
| 141 | [Template witness commitment](../crates/mining/tests/coinbase_template.rs) | ✅ | — | Coinbase commitment and rules |

## Wallet, index, and application

| BIP | Capability | Support | External evidence | Notes |
| :-- | :-- | :--: | :--: | :-- |
| 32 | [BIP32 derivation](../crates/rpc/src/handlers/util.rs) | ✅ | — | Ranged descriptor addresses; no key custody |
| 173/350 | [Segwit addresses](../crates/rpc/src/convert.rs) | ✅ | — | Wallet-free script address rendering |
| 380 | [Output descriptors](../crates/rpc/src/handlers/util.rs) | ✅ | — | getdescriptorinfo/deriveaddresses; scantxoutset rejects ranged/multipath forms |
| 389 | [Multipath descriptors](../crates/rpc/src/handlers/util.rs) | ✅ | — | Multipath key expressions in getdescriptorinfo/deriveaddresses; rejected by scantxoutset |
| 352 | [Silent Payments](../crates/index/src/silent_payments.rs) | 🧪 | — | Opt-in library scan codec; [tweak service / thin index](https://github.com/gosuda/bitcoin-rs/issues/1491) remains planned; [docs](silent-payments.md) |

## Out of scope by policy

The [wallet-only class](policies/bip-adoption.md#1-classification) excludes
wallet secrets and per-user wallet state. Hosted remote scanners are part of
the WIP BIP352 index-server design, not BIP380 (descriptors/checksums).
PSBT signing roles beyond key-free combine/finalize helpers (BIP174),
sidechains handled by the separate enforcer (BIP300/301), and mnemonic/seed
handling (BIP39) require a policy change before becoming node features.

## Update checklist

1. Check support against the merged default branch, not an unmerged PR head.
2. Link current code/tests and keep notes to scope, limitations or pending work.
3. Keep planned and experimental work distinct from implemented support; the
   adoption policy separately governs promotion to `Shipped`.
4. Set ✓ only for the exact scope of a recorded external-consumer run in the
   evidence inventory ([ECO-08/09](contracts/ecosystem-compatibility.md)).
5. Update this page with capability changes. Do not add a registry, CI gate or
   an "X% of all BIPs" metric.
