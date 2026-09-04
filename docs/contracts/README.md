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
| [architecture.md](architecture.md) | `ARCH-01`–`ARCH-07` | Five-layer dependency hierarchy, storage engine confinement, feature forwarding rules, RPC storage independence, node composition boundary, and chainstate transition facade | Workspace crates, `crates/node`, `crates/rpc`, `crates/storage`, `bin/bitcoin-rs` | `bin/bitcoin-rs/tests/gates/g17_dependency_direction.rs` (`cargo test -p bitcoin-rs --test gates g17_dependency_direction`); `crates/node/src/apply.rs` tests `snapshot_reads_applied_tip_without_taking_a_transition`, `chain_transition_connect_and_finish_publish_the_new_tip`, `proposal_rejects_excess_coinbase_without_persisting`, `proposal_omits_proof_of_work`, `apply_block_publishes_rawtx_bytes_in_block_order`, `connected_sequence_event_observes_the_published_applied_tip`, `connect_and_disconnect_wake_the_mining_generation`, `follower_dispatch_holds_the_chain_transition`, `with_zmq_publisher_swaps_handle`; `crates/node/src/chain_effects.rs` tests `noop_asks_for_no_payloads`, `connect_then_disconnect_rewinds_the_rpc_log_and_emits_in_order`, `disconnect_does_not_pop_a_different_tail`; `crates/node/src/config.rs` test `user_config_overlay_lets_set_fields_win` |
| [validation-default.md](validation-default.md) | `VAL-01`–`VAL-03` | Library `kernel` default until the recorded #213 verdict promotes native; native interpreter is the complete portable engine; binary default stays kernel-free | `crates/consensus`, `crates/node`, `crates/script`, `bin/bitcoin-rs` | `bin/bitcoin-rs/tests/gates/g19_validation_default.rs` (`cargo test -p bitcoin-rs --test g19_validation_default`); `crates/script/tests/core_vectors.rs` native columns |
| [indexing.md](indexing.md) | `IDX-01`–`IDX-07` | Index capability gating, watermark identity, query consistency, selective reset, reorg rollback, and error isolation | `crates/node/src/txindex_worker.rs`, `crates/index/src/index.rs`, RPC/Esplora queries | `crates/node/src/txindex_worker_recovery_tests.rs`, `crates/node/src/txindex_worker_query_tests.rs`, `crates/node/src/txindex_worker_lifecycle_tests.rs`, `crates/node/src/txindex_worker_block_source_tests.rs`; `crates/rpc/src/capabilities.rs` tests `missing_source_is_the_disabled_txindex_row`, `attached_source_is_the_worker_row` |
| [recovery.md](recovery.md) | `RCV-01`–`RCV-04` | Chainstate authority, exact-identity index positions, behind/ahead/stale/absent transitions, rewind versus rebuild, operator-visible rollback evidence | `crates/node/src/state.rs`, `crates/node/src/txindex_worker.rs`, `crates/rpc/src/capabilities.rs` | `crates/node/src/txindex_worker_recovery_tests.rs`, `crates/node/src/txindex_worker_block_source_tests.rs`, `crates/node/src/recovery_evidence.rs` tests `reporter_report_index_ahead_writes_marker_and_warns`, `marker_write_failure_fails_only_the_reporting_index` |
| [chain-events.md](chain-events.md) | `EVT-01`–`EVT-05` | `ChainSnapshot`, `ChainEventHint`, `ChainEventPublisher`, `ConsumerCursor`, `UndoStore`/`DisconnectMarker`, `ChainChangeProof`: the seam between the apply path and reconciliation consumers | `crates/node/src/txindex_worker.rs` (first consumer); any index mirroring the applied chain | `crates/node/src/state.rs` tests `record_publishes_snapshot_and_hints_in_commit_order`, `record_drops_hints_when_channel_full`, `active_chain_snapshot_anchors_at_restored_tip_after_restart`; `crates/node/src/txindex_worker_recovery_tests.rs` tests `shallow_reorg_rewinds_to_common_ancestor_then_replays`, `tip_change_during_rebuild_converges_on_new_tip`; `crates/node/src/apply.rs` tests `a_clean_disconnect_leaves_no_in_flight_marker`, `chain_change_proof_finish_restores_even_generation` |
| [mempool-mutations.md](mempool-mutations.md) | `MPL-01`–`MPL-04` | Gateway ordering invariant, `MutationEnvelope`/`MutationResult` semantics, ZMQ `A`/`R` payload bytes, generation-validated admission and chain-change fencing | apply path (`crates/node/src/apply.rs`), `sendrawtransaction` (`crates/rpc/src/handlers/tx.rs`), ZMQ `sequence` subscribers (enforcer `--enable-mempool`) | `crates/mempool/src/gateway.rs` test `accepted_and_block_inclusion_events_arrive_in_commit_order`; `crates/node/src/zmq_publisher.rs` tests `block_inclusion_suppresses_r_frames` and `mempool_event_payloads_carry_reversed_txid_label_and_le_sequence`; `crates/node/src/apply.rs` test `stable_generation_is_even_before_and_after_connect` |
| [mempool-policy.md](mempool-policy.md) | `POL-01` | Pointer: relay policy contract pinned to Core 31.1 | `sendrawtransaction`/`testmempoolaccept` (`crates/rpc/src/handlers/tx.rs`), P2P relay admission | `crates/mempool/tests/policy_contract.rs` and `crates/rpc/tests/policy_contract.rs` (`cargo test -p bitcoin-rs-mempool --test policy_contract` / `-p bitcoin-rs-rpc --test policy_contract`) |
| [external-api.md](external-api.md) | `API-01`–`API-05` | Pointer: JSON-RPC/REST/ZMQ manifest, generated reference, error code mappings, query budgeting, and solo-mining generate | RPC/REST/ZMQ clients; `tools/bip300301-enforcer` | `crates/rpc/tests/manifest_coverage.rs` tests `rpc_rows_and_the_live_registry_agree_both_ways`, `generated_reference_matches_checked_in`; `crates/rpc/src/handlers/mining.rs` generate tests; `crates/node/tests/mining.rs` generate tests |
| [wallet-facing.md](wallet-facing.md) | `WF-01`–`WF-03` | Public Esplora/JSON-RPC surface an external wallet may use; no `NodeState` / `UtxoSet` / index types | [bitcoin-wallet](https://github.com/gosuda/bitcoin-wallet) (`btcw`); any Esplora HTTP client | `bin/bitcoin-rs/tests/wallet_facing.rs` tests `external_wallet_can_scan_estimate_and_broadcast`, `source_does_not_import_node_internals`; `crates/rpc/src/esplora.rs` tests `esplora_lives_only_under_the_api_prefix`, `api_is_the_closed_esplora_and_backend_namespace` |
| [p2p-wire.md](p2p-wire.md) | `P2P-01`–`P2P-02` | Pointer: command inventory in `crates/p2p/src/compat.rs`, handshake/reject/deviations pinned to Core 31.1 | `crates/p2p` peers; `crates/p2p/src/chain_query.rs` active-chain serving | `crates/p2p/tests/core_compat.rs` (`cargo test -p bitcoin-rs-p2p --test core_compat`); live lane `scripts/run-p2p-core-interop.sh` |
| [qa-corpus.md](qa-corpus.md) | `QAC-01` | Pointer: fuzz seed provenance and refresh rules | `fuzz/fuzz_targets/{p2p_message,block_decode,tx_decode,script_eval}.rs`; CI fuzz lanes | `fuzz/CORPUS_PROVENANCE.md` mapping table; targets run under `cargo fuzz run <target> -- -runs=10000` |
| [campaign-corpora.md](campaign-corpora.md) | `CORP-01`–`CORP-05` | C150 and Cmodern identities, Core-framed archive/manifest, full-validation posture, script census, and Core 31.1 MuHash oracle | Product-domain campaign cells; `tools/campaign-corpus/corpus.py` | `tools/campaign-corpus/test_corpus.py` (`python3 tools/campaign-corpus/test_corpus.py`) |
| [muhash-rpc.md](muhash-rpc.md) | `MRPC-01`–`MRPC-03` | Production `gettxoutsetinfo` arity, attested-child ownership of the timed RPC connection, and workspace copies of pinned arm configs | `crates/rpc` `gettxoutsetinfo`; `tools/benchmark-campaign/muhash_rpc.py` | `crates/rpc` `gettxoutsetinfo_rejects_trailing_parameters`; `tools/benchmark-campaign/test_muhash_rpc.py` (`python3.13 tools/benchmark-campaign/test_muhash_rpc.py`) |
| [embedding.md](embedding.md) | `Node::start`/`shutdown` lifecycle with `TeardownMode`, typed snapshot/progress/capability reads, TxLookup gating, shared gateway admission and the mining generation wake: the embedded-vs-daemon seam | In-process embedders; `crates/node/src/embed.rs`; daemon `run()` (first embedder) | `crates/node/tests/embed.rs` tests `embedded_node_lifecycle_round_trip`, `dropped_node_releases_services_and_datadir_for_reopen`; `crates/node/src/run.rs` test `daemon_and_embedded_paths_share_one_teardown` |
| [storage-footprint.md](storage-footprint.md) | `FP-01`–`FP-04` | Logical and physical data-directory ledgers, custody-grade collection, explicit `--measure-storage` command, default unpruned 1-TB peak budget | `crates/storage/src/footprint.rs`, `crates/node/src/storage_footprint.rs`, `bin/bitcoin-rs --measure-storage` | `crates/storage/tests/storage_footprint.rs`; `crates/node/src/storage_footprint.rs` tests `default_regtest_record_is_inapplicable_to_the_mainnet_budget`, `snapshot_of_default_mainnet_is_insufficient_for_the_peak_gate`; `bin/bitcoin-rs/tests/cli_help.rs` |
| [hot-path-attribution.md](hot-path-attribution.md) | `HPA-01`–`HPA-11` | Frozen 36-cell denominator, attribution noise floor, overlap-aware wall accounting, ledger ownership, forbidden probes, and dispositions | `docs/benchmarks/hot-path-ledger.toml`; product-domain comparators | `bin/bitcoin-rs/tests/gates/g18_hot_path_ledger.rs` (`cargo test -p bitcoin-rs --test g18_hot_path_ledger`) |

## Vocabulary

Terms used above are defined in [../../CONCEPTS.md](../../CONCEPTS.md). A
contract page may reference a concept by name without redefining it.
