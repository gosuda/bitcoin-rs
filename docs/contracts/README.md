# Contracts

A contract doc states behavior the code must keep, and names where the code
proves it. Every normative claim cites the file that implements it and the
test that pins it, both present in the tree. A contract page is short: the
invariants, the owners, the proof. Explanation lives in `CONCEPTS.md`, code
comments, and consumer documents that link back to the owning contract.

## Documentation roles

Documentation in this repository follows explicit ownership and precedence:

- `docs/contracts/`: current normative behavior, invariants, and ownership rules;
- `docs/plans/`: implementation planning and history; informative and archivable, never the current contract;
- `docs/solutions/`: historical decisions, evidence, and failed approaches; informative, not normative;
- `CONCEPTS.md`: project-specific domain vocabulary only;
- README/getting-started: user workflows and concise subsystem summaries that link to the owning contract;
- code comments: local invariants, lock/commit ordering, unsafe justification, and non-obvious constraints;
- tests: executable proof of named contract clauses.

Do not copy complete behavioral descriptions from a contract into every consumer. Consumer documents cite the canonical clause IDs defined here.

## Precedence

When documents disagree, use this order:

1. A contract page under `docs/contracts/` wins. Each page is code-cited:
   file paths, clause IDs, and test names, with no prose-only claims about behavior.
2. Source comments (rustdoc and inline comments) come next. They explain
   local intent and invariants. They do not override the contract.
3. Specialized domain policies under `docs/policies/` define detailed wire/parity matrices; pointer pages below fold those policies into this precedence chain.
4. Everything else is informative context: `docs/plans/`, `docs/solutions/`, `docs/benchmarks/`, `CONCEPTS.md`, and consumer `README.md` files.

On conflict between a contract page and the code, the drift is a bug. Fix the
code or amend the contract in the same commit. Never reword the contract to
match a regression.

## Index

| Contract page | Clauses | Scope | Consumed by | Proven by |
| --- | --- | --- | --- | --- |
| [architecture.md](architecture.md) | `ARCH-01`–`ARCH-06` | Five-layer dependency hierarchy, storage engine confinement, feature forwarding rules, RPC storage independence, and node composition boundary | Workspace crates, `crates/node`, `crates/rpc`, `crates/storage`, `bin/bitcoin-rs` | `bin/bitcoin-rs/tests/gates/g17_dependency_direction.rs` (`cargo test -p bitcoin-rs --test gates g17_dependency_direction`) |
| [indexing.md](indexing.md) | `IDX-01`–`IDX-07` | Index capability gating, watermark identity, query consistency, selective reset, reorg rollback, and error isolation | `crates/node/src/txindex_worker.rs`, `crates/index/src/index.rs`, RPC/Esplora queries | `crates/node/src/txindex_worker_recovery_tests.rs`, `crates/node/src/txindex_worker_query_tests.rs`, `crates/node/src/txindex_worker_lifecycle_tests.rs` |
| [recovery.md](recovery.md) | `RCV-01`–`RCV-04` | Chainstate authority, exact-identity index positions, behind/ahead/stale/absent transitions, rewind versus rebuild, operator-visible rollback evidence | `crates/node/src/state.rs`, `crates/node/src/txindex_worker.rs`, `crates/node/src/capabilities.rs`, `crates/rpc/src/context.rs` | `crates/node/src/txindex_worker_recovery_tests.rs`, `crates/node/src/recovery_evidence.rs` tests `reporter_report_index_ahead_writes_marker_and_warns`, `marker_write_failure_fails_only_the_reporting_index` |
| [chain-events.md](chain-events.md) | `EVT-01`–`EVT-05` | `ChainSnapshot`, `ChainEventHint`, `ChainEventPublisher`, `ConsumerCursor`, `UndoStore`/`DisconnectMarker`, `ChainChangeProof`: the seam between the apply path and reconciliation consumers | `crates/node/src/txindex_worker.rs` (first consumer); any index mirroring the applied chain | `crates/node/src/state.rs` tests `record_publishes_snapshot_and_hints_in_commit_order`, `record_drops_hints_when_channel_full`, `active_chain_snapshot_anchors_at_restored_tip_after_restart`; `crates/node/src/txindex_worker_recovery_tests.rs` tests `shallow_reorg_rewinds_to_common_ancestor_then_replays`, `tip_change_during_rebuild_converges_on_new_tip`; `crates/node/src/apply.rs` tests `a_clean_disconnect_leaves_no_in_flight_marker`, `chain_change_proof_finish_restores_even_generation` |
| [mempool-mutations.md](mempool-mutations.md) | `MPL-01`–`MPL-04` | Gateway ordering invariant, `MutationEnvelope`/`MutationResult` semantics, ZMQ `A`/`R` payload bytes, generation-validated admission and chain-change fencing | apply path (`crates/node/src/apply.rs`), `sendrawtransaction` (`crates/rpc/src/handlers/tx.rs`), ZMQ `sequence` subscribers (enforcer `--enable-mempool`) | `crates/mempool/src/gateway.rs` test `accepted_and_block_inclusion_events_arrive_in_commit_order`; `crates/node/src/mempool_observer.rs` test `block_inclusion_suppresses_r_frames`; `crates/node/src/zmq_publisher.rs` test `mempool_event_payloads_carry_reversed_txid_label_and_le_sequence`; `crates/node/src/apply.rs` test `stable_generation_is_even_before_and_after_connect` |
| [mempool-policy.md](mempool-policy.md) | `POL-01` | Pointer: relay policy contract pinned to Core 31.1 | `sendrawtransaction`/`testmempoolaccept` (`crates/rpc/src/handlers/tx.rs`), P2P relay admission | `crates/mempool/tests/policy_contract.rs` and `crates/rpc/tests/policy_contract.rs` (`cargo test -p bitcoin-rs-mempool --test policy_contract` / `-p bitcoin-rs-rpc --test policy_contract`) |
| [external-api.md](external-api.md) | `API-01`–`API-04` | Pointer: JSON-RPC/REST/ZMQ manifest, generated reference, error code mappings, and query budgeting | RPC/REST/ZMQ clients; `tools/bip300301-enforcer` | `crates/rpc/tests/manifest_coverage.rs` tests `rpc_rows_and_the_live_registry_agree_both_ways`, `generated_reference_matches_checked_in` |
| [p2p-wire.md](p2p-wire.md) | `P2P-01`–`P2P-02` | Pointer: peer-wire contract and connection lifecycle pinned to Core 31.1 | `crates/p2p` peers; `crates/node/src/p2p_chain.rs` chain-serving adapter | `crates/p2p/tests/core_compat.rs` (`cargo test -p bitcoin-rs-p2p --test core_compat`); live lane `scripts/run-p2p-core-interop.sh` |
| [qa-corpus.md](qa-corpus.md) | `QAC-01` | Pointer: fuzz seed provenance and refresh rules | `fuzz/fuzz_targets/{p2p_message,block_decode,tx_decode,script_eval}.rs`; CI fuzz lanes | `fuzz/CORPUS_PROVENANCE.md` mapping table; targets run under `cargo fuzz run <target> -- -runs=10000` |
| [embedding.md](embedding.md) | `Node::start`/`shutdown` lifecycle with `TeardownMode`, typed snapshot/progress/capability reads, TxLookup gating, shared gateway admission and the mining generation wake: the embedded-vs-daemon seam | In-process embedders; `crates/node/src/embed.rs`; daemon `run()` (first embedder) | `crates/node/tests/embed.rs` tests `embedded_node_lifecycle_round_trip`, `dropped_node_releases_services_and_datadir_for_reopen`; `crates/node/src/run.rs` test `daemon_and_embedded_paths_share_one_teardown` |

## Vocabulary

Terms used above are defined in [../../CONCEPTS.md](../../CONCEPTS.md). A
contract page may reference a concept by name without redefining it.
