# BIP adoption policy

This document defines how bitcoin-rs selects, prototypes, verifies, promotes,
and retires BIP-based capabilities. It is policy, not a status table: the
per-surface status lives in [../api/ecosystem-compat.toml](../api/ecosystem-compat.toml),
the wire matrix lives in [p2p-compatibility.md](p2p-compatibility.md), and the
RPC surface lives in `REGISTRY` (`crates/rpc/src/registry.rs`).

## 1. Classification

Classify every candidate BIP before implementation:

| Class | Rule |
| :--- | :--- |
| Active consensus rules | Mandatory exact behavior. Bitcoin Core, `libbitcoinkernel`, vectors, historical-chain replay, and differential tests are reference evidence. No experimental consensus deviations on mainnet. |
| Proposed or unactivated consensus changes | Research, regtest, or explicitly isolated test-network experiments only. Do not enforce a rule on mainnet before the network activates it. Do not claim activation before the network activates it. |
| P2P, transport, relay, and policy BIPs | Investigate and prototype when peers, negotiation, fallback, and network safety can be verified. A Bitcoin Core merge is useful evidence, not a gate. |
| Wallet discovery, indexing, and application-layer BIPs | Evaluate optional node services when they have a credible consumer or clear research value. Wallet secrets and per-user wallet state stay outside the node by default. |
| Wallet-only formats and out-of-scope BIPs | Not node features by default. Document why a node-facing capability is useful instead of implementing every BIP for completeness. |

## 2. Adoption decision

Record the decision in the existing issue or PR. External contributors can
propose and prototype candidates via
[Proposing and implementing BIPs](../../CONTRIBUTING.md#proposing-and-implementing-bips).
Do not create a new tracking database or a mandatory feature-specific CI gate
for a prototype:

- Exact BIP version, status, or pinned draft commit; separate stable BIP
  requirements from experimental extension APIs.
- The intended consumer, the node use case, and the hypothesis under test. A
  research prototype is valid before production demand exists.
- Consensus and synchronization impact; P2P interoperability and
  feature-negotiation behavior.
- The existing crate and state owner that provides the capability. Reuse
  block/undo/UTXO state before adding durable rows, workers, or API surface.
- CPU, memory, disk, I/O, backfill/pruning/AssumeUTXO, restart/reorg, and
  denial-of-service consequences. Require bounded work and explicit
  unavailable states.
- Validation evidence: BIP reference vectors, an independent or differential
  implementation, unmodified external consumers or peers, regtest end-to-end
  runs, and relevant whole-node regressions.

Raise the evidence bar when promoting experimental behavior to enabled or
shipped support. A scorecard or permanent registry is not required at any
stage.

## 3. Implementation and rollout rules

- **Consensus invariance is non-negotiable.** An optional BIP cannot alter
  active consensus validity, chainstate authority, or block acceptance.
- **Synchronization is necessary but not sufficient.** No starvation of IBD,
  mempool, or existing network services. Enforce resource budgets,
  cancellation/backpressure, and failure isolation (`CONSTRAINTS.md`).
- **One authoritative chainstate.** Extensions reuse the existing
  `BlockBodySource`, `BlockUndoSource`, derived-index lifecycle, RPC/P2P
  adapters, and mutation owners where applicable. No parallel UTXO truth, no
  duplicate schedulers, no speculative generic plugin framework.
- **Independent opt-in.** An experimental BIP stays independently
  implementable, testable, and disableable. Default off when resource or
  compatibility effects are not proven; a disabled path imposes negligible
  overhead.
- **Honest advertisement.** Never set a service bit or mark an API supported
  before end-to-end interoperable behavior exists. Distinguish experimental,
  extension, and unsupported states with the existing status inventories
  (`docs/contracts/ecosystem-compatibility.md`, `crates/rpc/src/manifest.rs`).
- **Small and reversible first.** Vectors/codec or feasibility first, then
  bounded reads/serving, then optional persistence only when justified. Allow
  removal when measured costs exceed value.
- **Core is a reference, not a permission.** Compare against pinned Core
  behavior where relevant. Do not wait for a Core merge by policy for
  non-consensus features.

## 4. Lifecycle

`Research → Experimental → Shipped`, with any stage able to end as
`Deferred` or `Rejected`:

| Stage | Entry evidence | Exit evidence |
| :--- | :--- | :--- |
| Research | A feasible design over an existing owner; pinned BIP draft; the failure modes that would stop the work. | Reference vectors pass; the resource story is bounded; consumer or research value holds. |
| Experimental | A default-off implementation over existing owners with typed failures and bounded work. | In-tree vector and regression suites pass; end-to-end behavior exists in a test context. |
| Shipped | End-to-end interoperability with an unmodified external consumer; measured resource cost; docs and status tables updated in the same change-set. | Promoted rows in `ecosystem-compat.toml` and the owning status inventories. |

For P2P surfaces, "shipped" additionally requires the live Core evidence lane
or an equivalent unmodified external consumer, per `ECO-08`, with observable
protocol outcomes scoped by `ECO-09`. An in-tree test
never upgrades external verification.

Deferred is not a protocol failure: incompatibility, pruning limits, or weak
external adoption can justify postponement without a defect claim.

## 5. Coverage map maintenance

The user-facing BIP support matrix lives in
[../bip-support.md](../bip-support.md). Its rows follow `ECO-08`'s
evidence-axis rules — implementation status and external verification stay
separate axes; the matrix uses compact support symbols for `Implemented`,
`Partial`, `Experimental`, `Planned`, and `Unsupported`. `Implemented` means
the stated capability exists in the merged tree, not that it has reached this
policy's `Shipped` lifecycle stage. An external-consumer run is always
recorded in [api/ecosystem-compat.toml](../api/ecosystem-compat.toml), never here. Keep
the matrix updated when a BIP-related capability is added, promoted,
materially changed, or removed — in the same change-set as the code.

Maintenance rules:

- Verify every status against the merged default branch before publishing. A
  status is never read from a PR head or an open issue.
- Implementation support, lifecycle promotion, and external verification are
  distinct claims. A support checkmark alone never establishes `Shipped` or
  `Externally Verified`.
- Open PRs and active issues are `Planned` in the matrix; an issue that only
  records a deferral (`Reopen on upstream maturity`) keeps the row
  `Unsupported`, because the tracker entry is the deferral note, not planned
  work. Rejected issues remain `Unsupported`. Reserve `Experimental` for
  implementations already in the merged tree that are default-off or draft-pinned.
- Never publish an "X% of all BIPs supported" metric. There is no meaningful
  single denominator: many BIPs are wallet-only, informational, or inapplicable
  to a full node. Distinguish implemented, applicable-but-unsupported, and
  out-of-scope.
- Derive from existing owners; do not add a runtime registry, a status state
  machine, or a CI gate just to render the matrix.

## 6. Applied decisions

The lifecycle applied to the current open proposals; implementation work stays
in each issue:

- **#1502 BIP157/158 compact filters.** Optional light-client service. Not a
  consensus or wallet-architecture requirement; Esplora/ScriptIndex remains the
  default self-hosting path. Class: application-layer. Stage: Shipped —
  optional `blockfilterindex` is merged in the tree, with recorded unmodified
  Kyoto regtest verification per [api/ecosystem-compat.toml](../api/ecosystem-compat.toml).
  Stale-block filters and scanblocks are not implemented; production mainnet
  IBD performance is not claimed.
- **#1491 BIP352 Silent Payments.** Optional, keyless tweak service over
  existing chain data. Wallet scan keys and per-user history never enter the
  node. Class: wallet discovery. Stage: Experimental — keyless, stateless
  BIP352 scan codec merged in the tree behind the `silent-payments` Cargo feature;
  follow-up #1491 tracks an optional thin public-tweak index. The upstream
  index-server specification is WIP; pin the commit under test and do not
  present provisional endpoints as a stable standard. The hosted remote-scanner
  models stay out of scope by default: they hold wallet secrets, a materially
  worse privacy boundary.
- **#1503 BIP324 v2 transport.** Opportunistic encryption without peer
  authentication; do not claim it stops an active MITM or eclipsing peer. Class:
  P2P transport. Stage: Shipped — on by default, as Core's `-v2transport` is,
  with live interop with an unmodified Core 31.1 recorded in both connection
  directions ([api/ecosystem-compat.toml](../api/ecosystem-compat.toml),
  CORE-06). Measured cost, recorded with that run in
  https://github.com/gosuda/bitcoin-rs/pull/1612: a fresh node syncing the same
  250-block regtest chain received 119,945 bytes over v2 against 119,120 over
  v1, and sent 11,166 against 9,626 (the runner's `ibd_cost`); BIP324 allows up
  to 4,095 bytes of handshake garbage in each direction once per connection. An
  ad hoc measurement, not reproducible from the tree, timed sealing and opening
  one packet at 3.5-4 µs for 32-250 byte messages and 510-550 MB/s for 1-4 MB
  payloads (one 2.1 GHz Xeon core, release build).
- **#1501 BIP330 Erlay.** Class: P2P relay. Stage: Deferred (backlog watch per
  policy #1501). Bitcoin Core's implementation is incomplete (`DO NOT MERGE`),
  and a moving upstream design makes a parallel reconciliation policy pure
  maintenance. Reopen on upstream maturity plus measured benefit, not on
  feature parity.
- **#1514 snapshot bootstrap artifacts.** Class: application-layer/indexing.
  Stage: Research. Core v2 `dumptxoutset` export is the first reversible step;
  index sidecars never masquerade as Core format.
- **#1488 Lightning backends.** Class: external interop evidence. Stage:
  Research. Each Lightning backend is one row of external evidence, not a
  bitcoin-rs feature.

## 7. Relationship to existing contracts

This policy adds decision criteria only. The following remain authoritative;
do not duplicate their content here:

- `docs/contracts/architecture.md` (`ARCH-07`, `ARCH-07a`): chainstate
  authority and the single narrow UTXO mutation contract.
- `docs/contracts/indexing.md` (`IDX-01`–`IDX-10`): capability gating, watermark
  identity, query consistency.
- `docs/contracts/ecosystem-compatibility.md` (`ECO-01`–`ECO-09`): external
  evidence tiers and status vocabulary.
- [p2p-compatibility.md](p2p-compatibility.md): the wire matrix, pinned Core
  version, and the P2P deviation ledger.
- [mempool-policy.md](mempool-policy.md): admission policy pins.
- `CONSTRAINTS.md`: repository-wide invariants (bounded resources, single
  ownership, operator data safety).
