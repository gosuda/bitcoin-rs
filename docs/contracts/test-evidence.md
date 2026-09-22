# Test evidence ownership

Tests protect an observable contract or an independently checked result.
A test that only restates a constructor, field layout, historical task plan,
lookup count, or private call order is not a permanent compatibility rule.
Performance claims require measured evidence, not a source-shape assertion.

## Retained proof owners

The current suite is classified by owner family below. Every surviving test
belongs to one of these current-contract or externally anchored evidence
families. Tests may move with their owner without preserving an old module
layout; a new test that does not fit one of these families needs a contract or
regression invariant before it is retained.

| Owner | Contract and failure boundary | Disposition |
| --- | --- | --- |
| Primitives parsing, encoding, layout, arithmetic | Bitcoin wire identities, canonical bytes, malformed and truncated input; `P2P-01`, `VAL-02` | Keep independent golden/rust-bitcoin comparisons and rejection boundaries. Internal layout is not a public contract. |
| Script and consensus | `VAL-02`; Core vectors, signed-spend parity, witness and Merkle commitments, activation, missing coins and duplicate inputs | Keep. Remove lookup-count and parser-shape assertions when the same result has independent evidence. |
| Chain, chainstate and UTXO | `ARCH-07`, `RCV-01`..`RCV-14`, `EVT-01`..`EVT-05`; ancestry, authoritative mutation, branch selection, coin state, connect/disconnect, recovery and crash outcomes | Keep behavioral, differential and property tests with the owning crate. Do not retain node-local apply-shape tests or replace corruption refusals with fixture round trips. |
| Storage and index | `IDX-01`..`IDX-08`, `FP-01`..`FP-04`, recovery; backend persistence, capability errors, cursor/reorg recovery | Keep. Backend and restart tests cannot be replaced by in-memory mocks. |
| Mempool | `MPL-01`..`MPL-04`, `POL-01`..`POL-06`; admission, replacement, dependencies, sequence, fencing and bounded orphans | Keep mutation and concurrency scenarios; reorg admission must use the same current-chain evaluator. |
| P2P | `P2P-01`..`P2P-05`; independent wire envelopes, live peer identity, budgets, body attribution, stalled requests and branch recovery | Keep. Assert peer-visible requests and eventual application, not incidental message ordering. |
| Mining | External miner/API clauses, coherent template generations and invalid candidates | Keep independently valid blocks and public submission behavior. |
| RPC | `API-*`, `WF-*`, `MRPC-*`; requests, errors, values, capability refusal and coherent views | Keep public-boundary and pinned Core comparisons. A method inventory is not a successful call. |
| Node and binary | `EMB-*`, `EVT-*`, recovery; public process startup, shutdown, persistence, reorg and observer ordering | Keep process and durability scenarios. A successful `--help` exit does not prove lifecycle behavior. |
| Cargo dependency/feature graph | `ARCH-01`, `DEP-*`, `FEAT-*` | Keep the metadata-based dependency-direction gate, feature builds and cargo-deny. Do not add a second uniqueness checker. |
| Reference custody | `REF-*`, `CORP-*`, `QAC-01`; artifact identity and unavailable inputs | Keep typed refusal cases and real process/corpus custody. Mutate parsed fields rather than matching historical TOML text. |
| Benchmark evidence | `HPA-*`; identities, overlap and repeated samples | Run evidence-tool tests with `--bench evidence`; measured campaigns remain separate. No frozen path/cell inventory in normal Cargo tests. |
| Formal models | `CONSTRAINTS.md` proof inventory | Run `scripts/check_models.py` in the manual lane. Custody checks and runner regressions are not model proofs. |

This table is the contract → proof matrix at suite-family granularity. Exact
test names are intentionally not normative: the executable evidence may be
consolidated or rewritten as long as the row's independent reference,
failure-path coverage, and named contracts remain proved.

## Reviewed deletion and replacement

| Former test | Decision and replacement |
| --- | --- |
| `test_comp_lanes.py` and its fixture-only `comp_lanes.py` runner | Retire the wrapper as a whole. Direct P2P, offline-validation, and MuHash comparator suites own their CLI, custody, and error behavior. Historical fixture measurements remain archived; no live-product evidence is removed. |
| Offline `NonVacuityProofs` | Delete assertions that expect another assertion to fail on a deliberately wrong literal. Direct CLI tests still verify the actual schema, 14-arm count, result digest, rejection paths, and publication. |
| Per-engine `*_equivalence_hash` tests | Consolidate into `portable_backends_have_identical_aggregate_hashes`. Every enabled backend still runs the complete behavioral suite; multi-backend builds compare the resulting hashes without running each engine twice. Two-backend builds now compare too. |
| Separate peer-constructor direction tests | Consolidate into `constructors_preserve_direction_and_handshake_metadata`. Check both directions, shared metadata, negotiation defaults, and a version-receipt time distinct from handshake completion. |
| `g18_hot_path_ledger` | Delete historical matrix/path/disposition gates. The declared benchmark ledger and actual campaign artifacts remain. |
| `overhaul_evidence` | Move identity, overlap and repetition checks to `crates/node/benches/evidence.rs`. Delete the all-cells-unmeasured assertion. |
| `g19_validation_default` | Delete the hardcoded promotion verdict and ad-hoc Cargo feature parser. `VAL-01` requires measured promotion evidence; feature builds remain. |
| `g20_unique_consensus_crates` | Delete the duplicate graph checker. Both dependency-range endpoints require `cargo deny check bans`. |
| `g20_formal_models` | Remove external Java/solver execution and source-text checks from Rust tests. Keep pinned models, hashes, properties, K=128 and explicit failure outcomes in the dedicated runner. |
| `cli_help` | Delete the exit-status-only smoke. Public process suites and actual CLI/config behavior remain. |
| Reference manifest value enumeration | Delete duplicated pin literals and comment-sensitive text edits. Keep artifact custody and typed malformed/unbound identity matrices. |
| `single_pass_shape_is_observable_and_second_decode_shape_is_not` | Delete. Golden facts, witness binding and independent identity parity remain. |
| Exact input lookup counters | Delete both the integration assertion and duplicate inline counting-view test. Keep multi-input verification, missing-coin and duplicate-input errors. |
| `prepared_facts_survive_source_record_replacement` | Delete: it dropped a view and re-parsed a transaction, never testing record replacement. It supplied no lifetime evidence. |
| `sighash_variants_match_reference_oracle` | Rename to the transaction-identity behavior it actually checks. Signed-spend/Core suites, not this fixture, own sighash evidence. |
| Node `apply::consensus_rule_tests` fixture tree | Delete the node-level duplicate consensus/apply matrix. Consensus rules stay with consensus/script/vector owners; authoritative mutation/recovery tests move to `bitcoin-rs-chainstate`; node keeps only cross-domain behavior. `crates/chainstate/tests/unit/apply/persistence_tests.rs` retains the mutation failure boundaries that are not consensus duplicates: failed undo persistence is atomic and BIP30 overwrite undo restores the original coin. |
| `chain_generation_tests`, old reorg settlement tests, sync generation-settlement tests | Delete implementation-shape assertions around `ChainChangeProof`, `Chainstate.mempool_gateway`, odd/even generation internals, and no-op transition finish. Node integration/mining/reorg tests retain observable mempool fencing and reorg behavior. |
| Node checkpoint/journal/event/recovery owner-unit modules | Move the retained checkpoint, journal, admission, chain-tx-count and event-state proofs to `crates/chainstate`. Delete node copies and forwarding modules. |
| Test-only backend row injection, metrics recorder, scratch constructors, checkpoint failpoint forwarding | Delete after the reset left no contract test consumer. Production no longer exposes these seams solely for fixtures. |

The sync recovery cut also replaces four fake-application fixture paths
with delivered blocks through the ordinary binding/apply path. The old
`DownloadWindow::mark_applied` shortcut is private to its unit tests and no
longer a production API.

## Reset completion rule

The contract-first reset is complete when all retained suites fit the proof
matrix above, the full dependency/feature/process/recovery lanes pass, and no
production API remains solely because a deleted test called it. Future tests
follow the same rule: current contract proof or promoted real regression.

A formal runner test uses a synthetic executable and cannot establish a
model property. A successful evidence-parser test cannot establish a
performance improvement. Missing Core binaries, corpora, model completions
or measured comparisons remain unavailable evidence, never implied passes.
