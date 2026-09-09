# Documentation

This tree is organised by where documents came from, not by who reads them.
This page maps it to what you might want.

## Start here

- [getting-started.md](getting-started.md) walks from a clone to a syncing
  node: build lanes, configuration precedence, networks, datadir rules, and the
  status vocabulary.
- [rest-interface.md](rest-interface.md) documents the optional Core-compatible
  REST gateway and its coherent-view rules.
- [chainstate-recovery.md](chainstate-recovery.md) documents durable-root crash
  recovery, the ordered commit protocol, and the fresh-replay rule.
- [../CONCEPTS.md](../CONCEPTS.md) is the project glossary. Read a term here
  before assuming it means what it means elsewhere in Bitcoin.
- [../AGENTS.md](../AGENTS.md) holds the behavioral rules for changing this
  repository. [../CONSTRAINTS.md](../CONSTRAINTS.md) is the guard register:
  the constraint ledger CL-01..CL-23, the formal-model tool pin, and the proof
  inventory.
- [../README.md](../README.md) covers the defaults and the benchmark records.

## Contracts

[docs/contracts/](contracts/) holds the normative behavior docs. Each one
states what the code must keep, then names the files and tests that prove
it. When documents disagree, the contract wins and the drift is a bug. The
precedence rule and the index of contract pages live in
[docs/contracts/README.md](contracts/README.md). The pages are:

- [architecture.md](contracts/architecture.md): five-layer dependency
  direction, storage engine confinement, the `chainstate` owner, node
  composition boundary (`ARCH-01`..`ARCH-07`).
- [reference-set.md](contracts/reference-set.md): the readable projection of
  the `ReferenceSet` identities (Core 31.1 release, 31.99.0 kernel tree,
  corpora and formal tool). The manifest files govern on conflict.
- [validation-default.md](contracts/validation-default.md): strict-Rust native
  validation as the production default; `kernel` as opt-in oracle only.
- [recovery.md](contracts/recovery.md): durable root, ordered commit,
  crash matrix, and fresh replay.
- [mempool-mutations.md](contracts/mempool-mutations.md) and
  [mempool-policy.md](contracts/mempool-policy.md): the single admission
  gateway, lifecycle operations, observer delivery, and the Core 31.1 policy
  profile.
- [chain-events.md](contracts/chain-events.md): post-commit effects and
  publication order.
- [indexing.md](contracts/indexing.md): capabilities, watermarks, the
  capability state machine, and query readiness.
- [p2p-wire.md](contracts/p2p-wire.md): peer leases, download ownership,
  discovery, compact blocks, and optional protocols.
- [external-api.md](contracts/external-api.md) and
  [wallet-facing.md](contracts/wallet-facing.md): RPC, REST, ZMQ, and Esplora
  dialects, and the surface an external wallet or explorer may consume.
- [embedding.md](contracts/embedding.md): the in-process node surface.
- [storage-footprint.md](contracts/storage-footprint.md): logical and physical
  ledgers and the 1 TB physical peak budget (`FP-01`..`FP-04`).
- [hot-path-attribution.md](contracts/hot-path-attribution.md),
  [campaign-corpora.md](contracts/campaign-corpora.md),
  [qa-corpus.md](contracts/qa-corpus.md), and
  [muhash-rpc.md](contracts/muhash-rpc.md): measurement denominators and
  corpora identities.

## Reference

- [policies/](policies/) holds the rules a change has to satisfy.
  [source-compatibility.md](policies/source-compatibility.md) covers the
  toolchain (Rust 1.95.0, edition 2024), dependency pins, and the workspace
  version rule; [db-migration.md](policies/db-migration.md) covers on-disk
  schema changes, `CURRENT_SCHEMA`, and owner-local versions;
  [mempool-policy.md](policies/mempool-policy.md) pins transaction acceptance
  against Bitcoin Core 31.1; [p2p-compatibility.md](policies/p2p-compatibility.md)
  pins the peer wire surface against Bitcoin Core 31.1.
- [rpc-reference.md](rpc-reference.md) is the generated JSON-RPC, REST, and
  ZMQ surface table. Do not edit it by hand; its source of truth is
  `MANIFEST` in `crates/rpc/src/manifest.rs`, and the file header gives the
  regeneration command.
- [api/](api/) holds machine-readable compatibility inputs embedded into the
  `bitcoin-rs-rpc` build: `core-compat.toml` (the Core compatibility manifest
  and `[reference]` identities, checked by `crates/rpc/src/compat_manifest.rs`)
  and `core-rpc-schema.json` (Core result schemas extracted by
  `tools/core-rpc-schema/extract.py`). Treat both as code, not prose.
- [models/](models/) holds the TLA+ models `ChainAdmission`, `PeerLeases`,
  and `ProjectionMining` with their `.cfg` files, checked by Apalache 0.62.2
  through gate `g20`. Their hashes and last outcomes are recorded in
  [../CONSTRAINTS.md](../CONSTRAINTS.md).
- [benchmarks/](benchmarks/) holds the retained benchmark notes and decision
  records: [overhaul-product-cells.md](benchmarks/overhaul-product-cells.md)
  (the versioned evidence schema and product cells),
  [end-to-end-sync.md](benchmarks/end-to-end-sync.md),
  [offline-full-validation.md](benchmarks/offline-full-validation.md),
  [p2p-loopback.md](benchmarks/p2p-loopback.md),
  [muhash-rpc.md](benchmarks/muhash-rpc.md),
  [index-read-path.md](benchmarks/index-read-path.md),
  [index-rollback-rebuild-cutover.md](benchmarks/index-rollback-rebuild-cutover.md),
  [utxo-memory.md](benchmarks/utxo-memory.md),
  [storage-footprint.md](benchmarks/storage-footprint.md),
  [overhaul-full-tip-storage.md](benchmarks/overhaul-full-tip-storage.md),
  [scriptindex-format.md](benchmarks/scriptindex-format.md),
  [simd-allocator-decision.md](benchmarks/simd-allocator-decision.md),
  [overhaul-optimization-decisions.md](benchmarks/overhaul-optimization-decisions.md),
  [native-crypto-decision.md](benchmarks/native-crypto-decision.md),
  [native-validation-default.md](benchmarks/native-validation-default.md),
  the product hot-path [ledger](benchmarks/hot-path-ledger.toml) with its
  [reading guide](benchmarks/hot-path-attribution.md), owned by
  [contracts/hot-path-attribution.md](contracts/hot-path-attribution.md).
  Read the methodology before quoting any number: the results depend on CPU
  pinning and on whether the harness competes with the node. A decision record
  whose evidence cells read `UNMEASURED` or `planned` records a required
  target, not a result. Raw run evidence lives in the corresponding PR
  discussions, not in the tree.
- [releases/overhaul-acceptance.md](releases/overhaul-acceptance.md) is the
  release closure table: every task, requirement, and gate with its evidence
  identity.

## Explanation

[solutions/](solutions/) is the durable knowledge base: a problem that cost
real time, and what was concluded. It is informative, not normative; each note
records the code and measurements at its date, so a note may describe a
mechanism the contracts have since replaced. Five areas:
`architecture-patterns`, `best-practices`, `logic-errors`, `performance`, and
`performance-issues`.

Search it before debugging a recurring problem or designing in an area someone
has already touched.

## Product lanes

Every release proves four lanes separately; see `Product lanes` in
[../CONCEPTS.md](../CONCEPTS.md).

| Lane | Build | What it must do |
| --- | --- | --- |
| Minimal native | `--no-default-features --features fjall` | Sync, restart, and reorg with one backend and every optional extension off; advertise nothing optional |
| Default full node | default features | Unpruned fjall, optional indexes off, native strict-Rust validation, mainnet, signet, testnet4, regtest |
| Oracle | `--features kernel`, separate `CARGO_TARGET_DIR` | Differential evidence against `bitcoinkernel`; never a runtime fallback |
| Optional-on | `--features bip324` plus compact filters enabled by configuration | v2 transport and BIP157/158 serving; disabled state must be byte-identical in validation |

Mainnet operation is supported on the default full-node lane. A release is
publishable only with G11 evidence recorded in
[releases/overhaul-acceptance.md](releases/overhaul-acceptance.md); a build
without that evidence is a candidate, not a release.

## Release gates

| Gate | Exit evidence |
| --- | --- |
| G0 reference freeze | `ReferenceSet` holds immutable source, binary, and corpus digests; Core 31.1 distinct from the 31.99 kernel tree; every requirement mapped to owner and test; deviations enumerated |
| G1 measurement baseline | Versioned evidence schema and named product cells; same-host repeated baseline with artifact, corpus, configuration, and durability identity; raw samples retained |
| G2 ownership seams | Narrow `ChainReader`, `CoinViewProvider`, `AdmissionHandle`, `P2pHandle`; `g17` passes; no hidden alternate mutation path |
| G3 native parsing | Boundary, ID, and weight parity over golden and expanded corpora; no second production decode; apply nonregression with the script backend held constant |
| G4 durability and recovery | Atomic durable root and coins; bounded reorg with exact inverse; checkpoint-independent recovery; checkpoint worker removed with no compatibility flag |
| G5 native promotion | `g19` plus full-chain comparator with zero unexplained mismatches; strict-Rust T16 before T17; binary, library, and image kernel-free |
| G6 mempool and fees | One preview and commit engine for RPC, P2P, Esplora, package, and reorg admission; script verification outside the pool writer; four-attempt retry; stateful Core differential |
| G7 P2P | Deterministic loopback handshake, download and serving ownership, discovery, fee-filter relay, compact blocks with full-block fallback, and selected v2 behavior |
| G8 index, API, wallet | Independent index runtime with per-capability watermarks; Core and Esplora dialects from coherent views |
| G9 mining | Coherent admitted-pool templates; nonmutating BIP22/BIP23 proposal; long-poll invalidation; external miner end to end with a second P2P node |
| G10 attributed optimization | One treatment at a time with scalar reference, isolated and full-domain benches, correctness and portability gates; MERKLE-ALL matrix recorded per target |
| G11 release and storage | Minimal, default, oracle, and optional-on profiles agree; default full-tip physical high-water at or below 1 TB with separate logical ledger; obsolete paths deleted with tests intact; evidence regenerated on the final hash |

On documentation itself: JSON-RPC uses Bitcoin Core's method names, so Core's
API documentation applies to the shared surface. The authoritative list of
what this node implements is `MANIFEST` in `crates/rpc/src/manifest.rs`,
rendered as [rpc-reference.md](rpc-reference.md); a manifest status is a
compatibility class, not a readiness state and not execution evidence.
