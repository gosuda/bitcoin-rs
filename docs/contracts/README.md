# Contracts

`docs/contracts/` owns current normative behavior. Each page names its owners and executable proof. `CONCEPTS.md` owns vocabulary; `docs/solutions/` and `docs/benchmarks/` hold historical or measured evidence.

## Precedence

1. `docs/contracts/`
2. Source comments for local invariants
3. `docs/policies/` for detailed domain matrices
4. Informative documents and historical evidence

When code and a contract disagree, fix the drift in the same change. Do not duplicate complete contract text into consumers; cite the owning clause instead.

## Index

| Contract | Clauses | Scope | Primary proof |
| --- | --- | --- | --- |
| [architecture.md](architecture.md) | `ARCH-01`–`ARCH-08` | Layering, storage confinement, composition, chainstate authority, single mutation owners | `g17_dependency_direction`; `overhaul_ownership`; node apply/effects tests |
| [validation-default.md](validation-default.md) | `VAL-01`–`VAL-03` | Kernel/native default decision and portable validation | `g19_validation_default`; Core-vector and kernel parity tests |
| [indexing.md](indexing.md) | `IDX-01`–`IDX-08` | Capability gating, coherent reads, reset/rebuild, reorg reconciliation, worker scheduling | txindex worker recovery/query/lifecycle/scheduling suites; RPC capability tests |
| [recovery.md](recovery.md) | `RCV-01`–`RCV-11` | Durable root, ordered commits, crash outcomes, reorgs, schema refusal | storage durability tests; txindex recovery tests; planned chainstate crash/reorg suites |
| [chain-events.md](chain-events.md) | `EVT-01`–`EVT-05` | Applied-chain event seam and consumer cursors | state/apply/txindex recovery tests |
| [mempool-mutations.md](mempool-mutations.md) | `MPL-01`–`MPL-04` | Mutation ordering, sequence events, chain-change fencing | mempool gateway, RPC ZMQ, and node apply tests |
| [mempool-policy.md](mempool-policy.md) | `POL-01`–`POL-06` | Admission owner, policy pins, preview/finality, replacement and package rules | policy/RBF suites plus planned admission/finality/cluster suites |
| [external-api.md](external-api.md) | `API-01`–`API-07` | RPC/REST/ZMQ manifest, errors, mining RPCs, reference provenance | manifest coverage, Core parity, mining tests |
| [wallet-facing.md](wallet-facing.md) | `WF-01`–`WF-03` | Public wallet-facing surface and isolation from node internals | wallet-facing and Esplora tests |
| [p2p-wire.md](p2p-wire.md) | `P2P-01`–`P2P-03` | Wire compatibility, peer leases, best-known-height credit | P2P compatibility/live interop, peer-table and sync tests |
| [qa-corpus.md](qa-corpus.md) | `QAC-01` | Fuzz corpus provenance | corpus provenance and fuzz targets |
| [campaign-corpora.md](campaign-corpora.md) | `CORP-01`–`CORP-05` | C150/Cmodern custody and Core-framed corpus format | `tools/campaign-corpus/test_corpus.py` |
| [muhash-rpc.md](muhash-rpc.md) | `MRPC-01`–`MRPC-03` | MuHash RPC arity and benchmark custody | RPC arity and benchmark-campaign tests |
| [embedding.md](embedding.md) | `EMB-01`–`EMB-08` | Embedded lifecycle and shared node services | `crates/node/tests/embed.rs`; daemon teardown test |
| [storage-footprint.md](storage-footprint.md) | `FP-01`–`FP-04` | Logical/physical storage accounting and 1-TB gate | storage/node footprint tests and CLI help |
| [hot-path-attribution.md](hot-path-attribution.md) | `HPA-01`–`HPA-13` | Product cells, overlap accounting, evidence identity, promotion thresholds | `g18_hot_path_ledger`; `overhaul_evidence` |
| [reference-set.md](reference-set.md) | `REF-01`–`REF-07` | Released Core, kernel, corpus, and formal-tool identities | compatibility manifest and `overhaul_reference_set` |

## Permanent suite traceability

The overhaul suites map to current contracts, not task numbers:

- `bin/bitcoin-rs/tests/overhaul_process_harness.rs` → `REF-02`, `REF-07`
- `bin/bitcoin-rs/tests/overhaul_evidence.rs` → `HPA-12`
- `bin/bitcoin-rs/tests/overhaul_ownership.rs` → `ARCH-01`, `ARCH-02`, `ARCH-08`
- `crates/consensus/tests/overhaul_parse_parity.rs` → `VAL-02`
- `crates/consensus/tests/overhaul_prepared_inputs.rs` → `POL-03`, `VAL-02`
- `crates/node/tests/overhaul_config_status.rs` → `ARCH-05`, `IDX-02`
- `crates/primitives/tests/overhaul_layout.rs` → `ARCH-01`
- `crates/utxo/tests/overhaul_persistent_coins.rs` → `RCV-02`, `RCV-03`

## Vocabulary

Project-specific terms are defined once in [../../CONCEPTS.md](../../CONCEPTS.md).
