# Contracts

`docs/contracts/` owns current normative behavior. Each page names its owners and executable proof. `CONCEPTS.md` owns vocabulary; `docs/benchmarks/` holds measured evidence.

## Precedence

1. `docs/contracts/`
2. Source comments for local invariants
3. `docs/policies/` for detailed domain matrices
4. Informative documents and historical evidence

When code and a contract disagree, fix the drift in the same change. Do not duplicate complete contract text into consumers; cite the owning clause instead.

## Index

| Contract | Clauses | Scope | Primary proof |
| --- | --- | --- | --- |
| [architecture.md](architecture.md) | `ARCH-01`–`ARCH-09` | Layering, storage confinement, composition, chainstate authority, single mutation owners, capability boundaries | `g17_dependency_direction`; node apply/effects tests; capability suites |
| [validation-default.md](validation-default.md) | `VAL-01`–`VAL-03` | Kernel/native default decision and portable validation | feature-matrix builds; Core vectors; measured promotion evidence |
| [consensus-difficulty.md](consensus-difficulty.md) | `DAA-01` | Core 31.1 difficulty adjustment: clamped retarget timespan and testnet minimum-difficulty exception | `crates/chain/tests/header_sync_roundtrip.rs` retarget and minimum-difficulty tests |
| [indexing.md](indexing.md) | `IDX-01`–`IDX-10` | Capability gating, coherent reads, reset/rebuild, reorg reconciliation, worker scheduling, canonical row cardinality, atomic commit durability | `index_roundtrip.rs` row occupancy; txindex worker recovery/query/lifecycle/scheduling suites; RPC capability tests |
| [recovery.md](recovery.md) | `RCV-01`–`RCV-15` | Durable root, ordered commits, crash outcomes, reorgs, schema refusal | storage durability tests; chainstate checkpoint/journal/replay suites; node crash/reorg suites; txindex recovery tests |
| [chain-events.md](chain-events.md) | `EVT-01`–`EVT-05` | Applied-chain event seam and consumer cursors | state/apply/txindex recovery tests |
| [mempool-mutations.md](mempool-mutations.md) | `MPL-01`–`MPL-04` | Mutation ordering, sequence events, chain-change fencing | mempool gateway, RPC ZMQ, and node apply tests |
| [mempool-policy.md](mempool-policy.md) | `POL-01`–`POL-06` | Admission owner, policy pins, preview/finality, replacement and package rules | policy/RBF suites plus planned admission/finality/cluster suites |
| [external-api.md](external-api.md) | `API-01`–`API-33` | RPC/REST/ZMQ behavior, mining requests, errors, and reference provenance | Manifest coverage, Core parity, mining and request-validation tests |
| [wallet-facing.md](wallet-facing.md) | `WF-01`–`WF-03` | Public wallet-facing surface and isolation from node internals | wallet-facing and Esplora tests; `listener_directory_table_is_closed_over_http` |
| [p2p-wire.md](p2p-wire.md) | `P2P-01`–`P2P-10` | Wire compatibility, peer leases, demonstrated capability, canonical frontier recovery, connected-socket posture, body-carried header admission, header-led block announcements with bounded ingress, inbound admission and outbound service gating, block-body service eligibility, header presync admission gating | P2P compatibility/live interop, dispatch/listener, peer-table and sync tests |
| [qa-corpus.md](qa-corpus.md) | `QAC-01` | Fuzz corpus provenance | corpus provenance and fuzz targets |
| [campaign-corpora.md](campaign-corpora.md) | `CORP-01`–`CORP-05` | C150/Cmodern custody and Core-framed corpus format | `tools/campaign-corpus/test_corpus.py` |
| [muhash-rpc.md](muhash-rpc.md) | `MRPC-01`–`MRPC-03` | MuHash RPC arity and benchmark custody | RPC arity and benchmark-campaign tests |
| [embedding.md](embedding.md) | `EMB-01`–`EMB-10` | Embedded lifecycle, shared node services and independent stall evidence | `crates/node/tests/embed.rs`; daemon teardown test; `crates/node/src/event_loop.rs` telemetry test; `scripts/tests/test_watch_runtime_stall.py` |
| [storage-footprint.md](storage-footprint.md) | `FP-01`–`FP-04` | Offline apparent/allocated snapshot boundary and evidence limits | offline-tool tests; isolated production API gate |
| [hot-path-attribution.md](hot-path-attribution.md) | `HPA-01`–`HPA-13` | Product cells, overlap accounting, evidence identity, promotion thresholds | benchmark evidence tests and measured campaign artifacts |
| [dependency-range.md](dependency-range.md) | `DEP-01`–`DEP-02` | Declared Cargo ranges compile at their minimum and maximum resolvable versions; one copy each of `bitcoin`, `bitcoin_hashes`, `secp256k1`, `secp256k1-sys` | `scripts/check-dep-range.sh`; `cargo deny check bans` |
| [feature-matrix.md](feature-matrix.md) | `FEAT-01`–`FEAT-02` | Named supported feature combinations; no empty backend markers on crates that do not own storage | `scripts/check-feature-matrix.sh`; `g17_dependency_direction` |
| [reference-set.md](reference-set.md) | `REF-01`–`REF-07` | Released Core, kernel, corpus, and formal-tool identities | reference record and `overhaul_reference_set` |
| [ecosystem-compatibility.md](ecosystem-compatibility.md) | `ECO-01`–`ECO-09` | External ecosystem compatibility strategy: black-box evidence, one representative consumer, evidence matrix and status vocabulary | [api/ecosystem-compat.toml](../api/ecosystem-compat.toml) rows; live Core interop lane (`core-differential.md`) |
| [formal-verification.md](formal-verification.md) | Formal inventory | Model hashes, runner identity, return-code mapping, and proof status | `scripts/check_models.py`; manual model-check workflow |
| [chainstate-journal-v1.md](chainstate-journal-v1.md) | `JW-*-1` | Chainstate journal writer: append ordering, durable head, rotation, retention, lifecycle | `crates/storage/src/chainstate_journal/writer/tests/` |

## Permanent suite traceability

Tests map to current contracts, not task numbers. [test-evidence.md](test-evidence.md) records
reviewed deletions, surviving proof owners and outstanding coverage gaps.

Representative retained suites:

- `bin/bitcoin-rs/tests/overhaul_process_harness.rs` → `REF-02`, `REF-07`
- `bin/bitcoin-rs/tests/overhaul_external_miner.rs` → `API-14`, `API-15`
- `crates/consensus/tests/overhaul_parse_parity.rs` → `VAL-02`
- `crates/consensus/tests/overhaul_prepared_inputs.rs` → `POL-03`, `VAL-02`
- `crates/node/tests/overhaul_fee_history.rs` → `API-26`, `EVT-02`, `RCV-11`
- `crates/primitives/tests/overhaul_layout.rs` → `ARCH-01`

## Vocabulary

Project-specific terms are defined once in [../../CONCEPTS.md](../../CONCEPTS.md).
