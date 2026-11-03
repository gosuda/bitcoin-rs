# BIP support

The BIP matrix answers three separate questions: what the merged tree implements, what an unmodified external consumer has used, and which lifecycle stage the adoption policy allows. Read the columns separately.

## Read the matrix

[`docs/bip-support.md`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/bip-support.md) groups capabilities by area. The support column uses five states: implemented, partial, experimental, planned, and unsupported. Implemented means the code is in the merged default branch, not that the policy calls it shipped. Partial means the stated scope is narrower than the BIP or the integration. Experimental means default-off, draft-pinned, or both. Planned means an unmerged pull request or an open issue. Unsupported also covers a capability that a deferral note or a rejected issue closed.

The external evidence column is independent. A checkmark means a recorded run of an unmodified external consumer for the exact scope noted beside it. A dash means no such run exists. In-tree tests, self-authored harnesses, and copied reference vectors never earn a checkmark. A support symbol and an evidence checkmark can therefore disagree, and often do.

The notes column is part of the claim. It names the code or test path, the scope, and the pending qualification. Read the note before you read the symbol.

## Read the adoption policy

[`docs/policies/bip-adoption.md`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/policies/bip-adoption.md) owns promotion. Its lifecycle has three stages: Research, Experimental, and Shipped. Any stage can end as Deferred or Rejected. A Shipped row needs end-to-end interop with an unmodified external consumer, measured cost, and updated tables in the same change-set.

A P2P capability has an extra condition. Shipped requires the live Core evidence lane or an equivalent unmodified external consumer under [`ECO-08`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/ecosystem-compatibility.md), scoped by `ECO-09`. An in-tree test never upgrades external verification.

The rollout rules constrain what an implementation may do before promotion. An optional BIP must not change consensus validity, chainstate authority, or block acceptance. It must reuse the existing block, undo, UTXO, index, RPC, and P2P owners instead of starting parallel truth. It stays disableable and default-off until the implementer measures its effects. The node must not advertise a service bit or API support before end-to-end interop exists. Core is a reference, not a permission: non-consensus work does not wait for a Core merge.

## What a checkmark does not mean

Implemented is not Shipped. Shipped is not externally verified for behavior outside the recorded scope. Experimental is not a compatibility promise. Planned is not a schedule.

The policy forbids one more reading: an "X% of all BIPs" score. No single denominator exists, because many BIPs are wallet-only, informational, or inapplicable to a node. The matrix is a capability inventory, not a coverage percentage.

## Examples of the distinction

BIP324 v2 transport is implemented and externally verified for the recorded bidirectional Core 31.1 run. The policy calls it Shipped. The live evidence covers v2 negotiation, matching session ids, ping, and full sync in both directions. It does not cover a v1 retry after an unanswered v2 dial, decoy packets, or rekeying; those rest on in-tree tests.

BIP152 compact-block relay is implemented and externally verified for request and response behavior. Reconstruction and `getblocktxn` recovery counts are log-derived diagnostics and stay outside the external claim. Proactive block announcements have their own row because the `CORE-05` live-reorg qualification is still pending.

BIP157 and BIP158 compact filters are implemented and externally verified against a pinned Kyoto consumer on regtest. The scope is basic active-chain filters, and the node does not retain stale filters.

BIP352 Silent Payments is experimental. A keyless scan codec and a public-tweak RPC extension exist behind a feature, and the matrix records a REST sidecar run. Native RPC consumer and funded wallet discovery remain unverified. Wallet secrets stay out of the node.

BIP330 Erlay is unsupported. The tracking note records the deferral, so the policy keeps it below Planned. `sendtxrcncl` remains an untyped command.

BIP434 feature negotiation is experimental and draft-pinned at protocol `70017`. Core 31.1 does not implement it, so the node claims no Core interop for it.

## Out of scope by policy

The wallet-only class excludes wallet secrets and per-user wallet state. Hosted remote scanners belong to the WIP BIP352 index-server design, not to the descriptor BIPs. PSBT signing roles beyond key-free combine and finalize helpers need a policy change before they become node features. Sidechain enforcement and mnemonic or seed handling stay outside this node.

## Update the matrix with the code

Update the matrix in the same change-set as the capability. Check support against the merged default branch, never a pull-request head. Link the current code or tests. Keep planned, experimental, and implemented work distinct. Set the external checkmark only for the exact scope of a run recorded in [`docs/api/ecosystem-compat.toml`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/api/ecosystem-compat.toml). Do not add a runtime registry, a CI gate, or a percentage metric to render the page.

Owner: [`docs/bip-support.md`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/bip-support.md) for the matrix and [`docs/policies/bip-adoption.md`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/policies/bip-adoption.md) for promotion. Next: [Compatibility with Bitcoin Core](core-compatibility.md) covers the surfaces the matrix references.
