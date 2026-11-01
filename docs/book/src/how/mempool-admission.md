# Mempool admission

Every transaction enters the pool through one owner, `MempoolGateway`. RPC `sendrawtransaction`, Esplora broadcast, peer relay, package relay, and reorg reconsideration all call the same preparation, verification, and commit code; producers do not re-implement policy. A submission is prepared against a captured chain generation, mempool sequence, and policy stamp, and it commits only if all three still match.

The operator-facing policy, persistence, and RPC surface are in [mempool policy](../use/mempool-and-policy.md) and [the mempool chapter](mempool.md). Contracts are [docs/contracts/mempool-policy.md](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/mempool-policy.md) (`POL-*`) and [docs/contracts/mempool-mutations.md](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/mempool-mutations.md) (`MPL-*`).

## One owner, five modes

`AdmissionMode` selects how much of the graph a submission may change (`crates/mempool/src/gateway.rs:147`):

| Mode | Caller | Replacement | Time floor |
| :--- | :--- | :--- | :--- |
| `Single` | preview and non-submitting checks | allowed | applied |
| `SingleSubmit` | `submit_transaction` | allowed | expire before trim |
| `PackageTest` | multi-row `testmempoolaccept` | disabled | none |
| `PackageSubmit` | native and peer package submission | disabled | none |
| `PackageRpcSubmit(max)` | RPC `submitpackage` | disabled | none, per-member max feerate |

Two public entries cover local use:

- `submit_local_transaction` returns `MutationResult` for a commit, an empty result for `AlreadyKnown`, and a policy error for `AlreadyConfirmed` or `Held` (`crates/mempool/src/admission.rs:401`).
- `submit_peer_package` reorders the batch into ancestor-first order, checks the ancestor-package shape, and submits atomically as a peer (`crates/mempool/src/submit_package.rs:270`).

## Preparation and the stamp

`submit_transaction_claimed` runs at most `MAX_ADMISSION_RETRIES` attempts, which is 4 (`crates/mempool/src/admission.rs:13`, `:465`). Each attempt:

1. Reads the pool sequence and checks the expected generation, sequence, and stamp.
2. Resolves mempool parents for the inputs, then asks the chain view for confirmed outputs when some are missing.
3. Builds an `AdmissionRequest` carrying the transaction, resolved prevouts, prevout metadata (height, MTP, coinbase), locktime cutoff, CSV activation, next-block script flags, fee cap, origin, and the captured generation and sequence (`crates/mempool/src/gateway.rs:98`).
4. Calls `admit_transaction_claimed`, which prepares the admission under the read lock, runs policy and scripts outside the write lock, then commits under the same lock with a recheck.

`check_admission_state` is the fence (`crates/mempool/src/gateway.rs:859`): a generation change (new block or reorg), a sequence change (membership or fee overlay), or a policy-stamp change returns `GenerationChanged` or `MempoolChanged`. The attempt loop retries those; four failures return `SubmitError::RetryExhausted`. The stamp records the enforced limits and standardness policy, so changing them mid-flight invalidates prepared work rather than admitting it under mixed rules.

Preparation and script execution happen before the write lock. The script cache key is inserted only after a committed result, so a rejected transaction cannot seed the cache.

## The check order

The order is deliberate: cheap facts first, scripts last, and the caller fee cap after verification. `prepare_admission` and `evaluate_one` implement it (`crates/mempool/src/gateway.rs:879`, `crates/mempool/src/standardness.rs:246`).

1. Already in the pool returns `txn-already-in-mempool` before any resolution.
2. Missing inputs covers a coinbase transaction, an unresolved outpoint, and an invalid mempool outpoint: `missing-inputs` (`POL-07`).
3. Transaction standardness runs `is_standard_tx`: version 1 through 3, weight at most 400,000 WU, push-only scriptSigs at most 1,652 bytes, output rules (datacarrier budget, dust, bare multisig shapes), and a 65-byte non-witness minimum (`crates/mempool/src/standardness.rs:96`).
4. Dust outputs are refused unless the base and modified fees are both zero, the ephemeral dust case.
5. Input and witness standardness runs only when every input resolved: `is_standard_spend` classifies each prevout script, checks P2SH redeem sigops and legacy sigops, then checks witness programs, P2WSH limits, and taproot shape (`standardness.rs:105`, `POL-07`).
6. Sigop cost above 16,000 is `too-many-sigops`. The gateway computes BIP141 cost from copied resolved outputs; a caller-supplied count never reaches an entry (`POL-04`).
7. Minimum fee compares the modified fee with the required fee at `min_fee_sat_per_kvb(now)`: `min relay fee not met`.
8. Caller maximum fee compares the base fee with `CFeeRate::GetFee(vsize)`: `max-fee-exceeded`.
9. BIP68 finality evaluates relative locks at tip plus one: `non-BIP68-final`.
10. Consensus non-script checks run inside `verify_policy`, including coinbase maturity over the prevout metadata. A failure is `consensus-verification-failed` at the submission boundary.
11. Scripts execute with `VerifyFlags::STANDARD`; failure is `script-verify-flag-failed`. A witness-strippable failure is scoped to the witness so a later valid-witness version is not blocked (`crates/mempool/src/gateway.rs:264`).
12. Graph policy (replacement or TRUC) is captured before verification, then verified with the scripts and committed under the fence.
13. Ephemeral spends are checked after graph policy: `missing-ephemeral-spends`.

A rejection is recorded in the peer lifecycle with a scope. A transaction-scoped rejection also rejects other witness variants of the same txid; a witness-scoped rejection blocks only that wtxid.

## TRUC

`truc_conflicts` runs for every non-package submission, after fee and finality checks and before scripts verify (`crates/mempool/src/truc.rs:24`). The rules:

- A transaction may not spend a parent whose version-3 status differs from its own (`TRUC-violation`).
- A version-3 root is at most 10,000 vbytes.
- A version-3 child has at most one unconfirmed parent, that parent has no unconfirmed ancestor, and the child is at most 1,000 vbytes.
- A parent with a resident child refuses a second child unless sibling eviction is allowed. The single-submission path allows it only when there is exactly one descendant and that descendant has exactly one ancestor; the victim joins the conflict set and the error string gains the sibling suffix. Package submission forbids sibling eviction and refuses.

A real regtest refusal of the root size rule, from a version-3 transaction with a 60,000-byte witness item:

```text
testmempoolaccept -> {"allowed":false,"reject-reason":"TRUC-violation",
  "txid":"5281b0bb79c896f57648543756a019b36fcbe8b8188fdafed9b42cf71c4c8765",
  "wtxid":"55b1b258219fd8a915cc37f727e9950e3cc39de687a2cfb0042cdc861ce110fd"}
sendrawtransaction -> {"code":-26,"message":"TRUC-violation"}
```

The txid and wtxid differ because the witness is not part of the txid. The node computes policy vsize from the sigop-adjusted weight, so the witness size is what pushed the root over 10,000.

## Packages

`submit_local_package` orders a child-with-independent-parents batch: the child is moved to the end, parents are sorted by txid, and `check_structure` enforces count, weight, uniqueness, and topology (`crates/mempool/src/submit_package.rs:246`, `crates/mempool/src/package.rs:12`). `submit_peer_package` additionally requires that every submitted transaction is an ancestor of the subject and that the batch is already ancestor-first.

`submit_package_attempt` then (`crates/mempool/src/submit_package.rs:320`):

1. Drops residents, and reports `DifferentWitness` when a resident txid has another wtxid.
2. Prepares every pending member under one stamp and one sequence.
3. Computes package entries and aggregate checks.
4. Commits the whole plan in one `commit_package` call, which inserts every accepted member or none (`crates/mempool/src/pool/package.rs:122`; the plan is built by `prepare_package` at `:16`).

Limits are 25 transactions and 404,000 weight units per package. A package pays one aggregate relay and pressure floor for its new members; resident parents and their fees are excluded, so a resident parent cannot subsidize a child. Package admission performs no replacement and no capacity eviction; a conflict inside a package is `conflict-in-package`, and a wider RPC package is refused before any member runs.

The RPC `submitpackage` path uses the same atomic operation for a singleton or one parent and one child, with Core's individual-first partial acceptance: a member that passes alone is committed first, then fee or missing-input failures are retried together (`POL-02`). Wider packages are refused with `package submission supports at most one parent and one child`.

Real refusal for a three-row package on regtest:

```text
submitpackage -> {"code":-25,"message":"package submission supports at most one parent and one child"}
```

## Replacement and chunk ordering

Replacement is full-RBF: BIP125 signaling and the old new-unconfirmed-input rule do not gate it (`POL-05`). A candidate must (`crates/mempool/src/rbf.rs`, `replacement_profile` tests):

- conflict with at most 100 distinct direct-conflict clusters;
- include every descendant of every victim;
- not spend a dependency that the replacement evicts;
- pay modified fees covering all victims plus the integer incremental relay charge;
- not have an affected fee diagram that equals or worsens the old one, including surviving relatives and newly joined clusters.

Failures surface as `insufficient fee`, `replacement-failed`, `too many potential replacements`, `TRUC-violation`, or `too-large-cluster`. Sibling-eviction cases append ` (including sibling eviction)`.

The pool keeps a chunk index for mining and eviction. `ChunkKey` orders chunks by exactly these keys, in order (`crates/mempool/src/chunk_index.rs:36`, `:45`):

1. Modified fee per charged weight, compared by cross multiplication so integer precision is kept.
2. Prefix weight within an equal-rate run.
3. Greatest member txid.
4. Component id.
5. Ordinal inside the component.

The linearizer builds that order from `fee_diagram::linearize`, and every insert, removal, or fee-delta change re-linearizes only the affected component. Mining and eviction walk the maintained index; a full re-solve exists only as the test oracle (`oracle_chunk_order`). Equal-rate parents stay before their children: `equal_rate_parent_sorts_before_its_child` and `max_txid_breaks_cross_component_ties` pin the behavior.

The exact solver does not emulate Core's bounded history-dependent SFL work or transient tie choices. This is a recorded deviation, not a parity claim.

## Rolling minimum fee

The rolling minimum starts at zero and only moves on evidence (`crates/mempool/src/rolling_min_fee.rs:19`).

- Eviction raises it to the removed chunk's fee rate via `track_package_removed`. A bump takes effect only after a block connects; before that, `current` returns the bumped rate unchanged.
- After a block stamp, decay begins only once more than 10 seconds have passed since the stamp.
- The half-life is 12 hours, divided by 4 when usage is below one quarter of the limit and by 2 when below one half.
- When the decayed rate falls below half the incremental relay fee, it resets to zero.
- The published floor is `max(rolling, min_relay_fee_sat_per_kvb)`, which defaults to 1,000 sat/kvB (`crates/mempool/src/pool.rs:530`).

The decay mirrors Core's `GetMinFee` arithmetic, including the double-precision rate and the usage thresholds. `mempool_min_fee_holds_until_a_block_connects_then_halves_each_half_life` pins the schedule, and `mempool_min_fee_remembers_a_capacity_eviction_and_the_preview_enforces_it` pins that a preview sees a raised floor.

## Eviction and memory

The pool is bounded by dynamic memory, not virtual size. `MempoolLimits::max_total_bytes` defaults to 300,000,000 (`crates/mempool/src/policy.rs:13`). `dynamic_memory_usage` sums, per entry, the heap of the transaction, one record in each index, the link records, and the chunk-index allowance (`crates/mempool/src/pool.rs:1110`, `entry_memory_usage` at `:2351`).

When usage exceeds the cap, `capture_eviction` walks chunks from the lowest fee rate upward, adds each member to the removal set, and subtracts its memory until the projected total fits (`crates/mempool/src/eviction.rs:36`). The highest removed chunk rate becomes the rolling bump. Removals are ordered parents before children so the graph stays consistent while the batch applies. If the walk cannot reach the target, the operation fails rather than over-evicting.

`getmempoolinfo.usage` reports the same number the limit bounds. `bytes`, fee rates, and package rates keep their virtual-size meaning.

## Fee estimator history

The estimator's samples outlive the process in `fee-estimator-history.dat`. `fee_history::load` refuses a path that is not a regular file or is larger than 64 MiB, decodes the bytes through `FeeEstimator::from_history_bytes`, and adopts them only on success (`crates/mempool/src/fee_history.rs:35`). A missing file logs at debug level; an unreadable or rejected file logs a warning and leaves the file in place, so the node starts with insufficient data instead of deleting evidence.

`fee_history::save` writes `fee-estimator-history.dat.tmp`, sends the bytes, syncs, and renames over the live file (`fee_history.rs:72`). It first re-reads the live file and refuses to replace one it cannot decode, so a corrupt history is preserved rather than overwritten. The node calls `save` during teardown, including startup-abort teardown; the estimator parameters and the RPC surface are in [mempool policy](../use/mempool-and-policy.md).

## Orphan handling

Only peer submissions can hold an orphan. `can_hold_orphan` requires a standard transaction without a null or invalid mempool input; local submissions never enter the hold path (`crates/mempool/src/admission.rs:78`).

The orphan pool defaults (`crates/mempool/src/orphan.rs:6`):

| Limit | Value |
| :--- | :--- |
| Entries | 100 |
| Total weight | 10,000,000 WU |
| Timeout | 120 seconds |
| Peer announcements | 100 |
| Peer weight | 1,000,000 |
| Peer latency budget | 1,000 |

A witness refresh for the same wtxid adds an announcer instead of a second body. Eviction removes the highest-scoring peer's oldest announcement first, so one noisy peer cannot evict another peer's work. `maintain` drops expired bodies and announcers from disconnected peers. A transaction-scoped rejection removes every witness variant of that txid and refunds their weight; a witness-scoped rejection removes only the matching body.

Readiness is event-driven. A new block or pool snapshot calls `chain_changed(parent_txids)` or `snapshot_changed`, which marks the affected orphans ready. `retry_orphans` attempts ready entries under the current fence and re-marks them ready if the attempt exhausts retries. `tx_ingress` calls both every loop iteration.

## Peer ingress

`crates/node/src/tx_ingress.rs` is the only bridge from P2P bodies to the gateway (`crates/node/src/tx_ingress.rs:88`).

- A single transaction calls `submit_transaction` with `AdmissionOrigin::Peer`. A `Committed` result is announced to the relay queue with its mutation sequence, and mining generation advances. `AlreadyConfirmed` forgets the peer's known-transaction entry. A `Held` result requests missing parents, or asks for an ancestor package when the peer advertised package relay.
- A package calls `submit_peer_package`. Accepted members are announced once each; the subject determines whether the package counts as useful traffic.
- `process_retries` runs orphan maintenance and retries before reading the next body (`tx_ingress.rs:185`). The loop polls every 100 ms (`TX_INGRESS_POLL`) when there is no work.

A failed admission does not answer success to the peer. `POL-05` owns the acknowledgement boundary for the pool; for relay, the absence of an announce is the refusal.

## Worked traces

A regtest node with an empty pool and a mature height-1 coinbase was driven over RPC. The transactions were hand-encoded and unsigned, and the node answered each one with a real refusal.

Zero-fee spend of a mature coinbase output:

```text
testmempoolaccept  -> [{"allowed":false,"reject-reason":"min relay fee not met",
  "txid":"b8bb5ecb48d98021135107995bd16e93ba74ba5d748bf6137c44afe91ec08282", ...}]
sendrawtransaction -> {"code":-26,"message":"min relay fee not met"}
```

Spend of an outpoint the node has never seen:

```text
testmempoolaccept  -> [{"allowed":false,"reject-reason":"missing-inputs",
  "txid":"031ba68213bc9026809cfb267003bb2da6ce018e7f81177d18a1ed058a60299f", ...}]
sendrawtransaction -> {"code":-25,"message":"bad-txns-inputs-missingorspent"}
```

`testmempoolaccept` reports the policy reason; `sendrawtransaction` maps the same fact to Core's transaction-level code. A transaction with an `OP_RETURN` output whose serialized script exceeds the 83-byte datacarrier limit shows the standardness check running before fee logic:

```text
testmempoolaccept -> [{"allowed":false,
  "reject-reason":"aggregate nulldata script bytes exceed the policy limit", ...}]
```

The pool still reports its enforced snapshot:

```json
{"bytes":0,"fullrbf":true,"incrementalrelayfee":1e-05,"limitclustercount":64,
 "limitclustersize":101000,"loaded":true,"maxdatacarriersize":83,
 "maxmempool":300000000,"mempoolminfee":1e-05,"minrelaytxfee":1e-05,
 "optimal":true,"permitbaremultisig":true,"size":0,"total_fee":0.0,
 "unbroadcastcount":0,"usage":0}
```

Two crate tests ran with `--nocapture` to pin the ordering and eviction paths:

```sh
$ env -u CARGO_BUILD_BUILD_DIR RUSTC_WRAPPER= \
    cargo test --offline --locked -p bitcoin-rs-mempool --lib \
    single_insertion_indexes_one_chunk -- --nocapture

test pool::chunk_order_tests::single_insertion_indexes_one_chunk ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 400 filtered out
```

```sh
$ env -u CARGO_BUILD_BUILD_DIR RUSTC_WRAPPER= \
    cargo test --offline --locked -p bitcoin-rs-mempool --test suite \
    policy_contract::size_limit_eviction_removes_the_lowest_fee_package_first \
    -- --nocapture

test policy_contract::size_limit_eviction_removes_the_lowest_fee_package_first ... ok
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 67 filtered out
```

The eviction test sets a three-unit memory cap, inserts 1,000, 3,000, and 2,000 sat/kvB entries, then admits a 6,000 sat/kvB entry. The result is one commit containing `Accepted(overflow)` followed by `Removed(PolicyEviction)` for the 1,000 sat/kvB entry, with the pool left at three entries.

## Failure modes

| Symptom | Cause | What the caller sees |
| :--- | :--- | :--- |
| `missing-inputs` | an input has no mempool or chain output | peer may hold; local policy error |
| `min relay fee not met` | modified fee below the current floor | `-26` at RPC |
| `max-fee-exceeded` | base fee above the caller's cap | policy error |
| `non-BIP68-final` | relative lock not satisfied at tip plus one | policy error |
| `TRUC-violation` | version, size, ancestor, or sibling rule | `-26` at RPC |
| `bip125-replacement-disallowed` | conflict inside a package or package RBF | policy error |
| `too-many-potential-replacements` | more than 100 direct-conflict clusters | policy error |
| `replacement-failed` | affected fee diagram does not improve | policy error |
| `too-large-cluster` | post-change cluster above 64 transactions or 101,000 vbytes | policy error |
| `missing-ephemeral-spends` | an ephemeral dust output was not fully spent | policy error |
| `admission retry exhausted` | chain or pool changed through four attempts | retryable at the caller |
| `MempoolError::Full` | admitted member did not survive a concurrent trim | policy error |

None of these mutate membership, the fee overlay, estimator input, or the mutation sequence. A failed replacement leaves the victims in place; the pool fingerprint tests compare membership and overlay after every refusal.

## Where the invariants are proven

| Clause | Rule |
| :--- | :--- |
| [`POL-02`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/mempool-policy.md#pol-02-one-admission-owner-and-admission-mode) | one owner, preview purity, package modes |
| [`POL-03`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/mempool-policy.md#pol-03-admission-pipeline-stamp-and-precedence) | stamp, retries, check precedence, memory bound |
| [`POL-04`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/mempool-policy.md#pol-04-owner-computed-sigop-cost) | owner-computed sigop cost |
| [`POL-05`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/mempool-policy.md#pol-05-replacement-cluster-and-package-policy) | replacement, clusters, chunk order, package limits |
| [`POL-06`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/mempool-policy.md#pol-06-preview-purity-and-finality) | preview changes nothing |
| [`POL-07`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/mempool-policy.md#pol-07-core-input-and-witness-standardness) | input and witness standardness |
| [`MPL-01`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/mempool-mutations.md#mpl-01-single-mutation-gateway-ordering-invariant) | one publication order for changes |

Tests that pin these rules, verified in the tree:

| Invariant | Test | File |
| :--- | :--- | :--- |
| single insertion indexes one chunk | `single_insertion_indexes_one_chunk` | `crates/mempool/src/pool/chunk_order_tests.rs` |
| equal-rate parent sorts before child | `equal_rate_parent_sorts_before_its_child` | `crates/mempool/src/pool/chunk_order_tests.rs` |
| max txid breaks cross-component ties | `max_txid_breaks_cross_component_ties` | `crates/mempool/src/chunk_index/tests.rs` |
| lowest-fee package evicts first | `size_limit_eviction_removes_the_lowest_fee_package_first` | `crates/mempool/tests/policy_contract.rs` |
| rolling fee holds then halves | `mempool_min_fee_holds_until_a_block_connects_then_halves_each_half_life` | `crates/mempool/tests/policy_contract.rs` |
| eviction raises the preview floor | `mempool_min_fee_remembers_a_capacity_eviction_and_the_preview_enforces_it` | `crates/mempool/tests/policy_contract.rs` |
| 100 clusters is the boundary | `one_hundred_conflicting_clusters_is_the_exact_boundary` | `crates/mempool/tests/replacement_profile.rs` |
| evicted dependency fails | `an_evicted_dependency_fails_without_narrowing_representable_fees` | `crates/mempool/tests/replacement_profile.rs` |
| TRUC sizes and sibling eviction | `truc_sizes_versions_and_sibling_eviction_match_bip431` | `crates/mempool/tests/replacement_profile.rs` |
| replacement refusal preserves state | `replace_transaction_rejection_preserves_pool_state` | `crates/mempool/tests/rbf_bip125.rs` |
| stale policy verdict is retryable | `stale_policy_verdict_becomes_retryable` | `crates/mempool/tests/admission.rs` |
| caller sigops are ignored | `caller_sigop_cost_is_ignored_in_stored_entry` | `crates/mempool/tests/admission.rs` |
| sibling eviction admits with no direct conflict | `v3_sibling_eviction_with_empty_direct_conflicts_admits_through_the_replacement_door` | `crates/mempool/tests/admission.rs` |
| package commits atomically in any input order | `native_package_aggregates_cpfp_atomically_and_ignores_input_order` | `crates/mempool/src/package/tests.rs` |
| resident parent fees do not subsidize | `native_package_resident_parent_fees_do_not_subsidize_child` | `crates/mempool/src/package/tests.rs` |
| package refusal keeps membership and overlay | `native_package_failure_keeps_membership_sequence_overlay_and_estimator` | `crates/mempool/src/package/tests.rs` |
| orphan readiness is deduplicated | `readiness_is_deduplicated_and_removed_with_eviction` | `crates/mempool/src/orphan/tests.rs` |
| orphan eviction trims the noisy peer | `eviction_trims_the_highest_peer_score_before_protected_peer` | `crates/mempool/src/orphan/tests.rs` |
| rejects are bounded and cleared on chain reset | `rejects_are_bounded_and_chain_reset_clears_both_indexes` | `crates/mempool/src/orphan/tests.rs` |

## Differences from Core

Full RBF is unconditional, so BIP125 metadata is reported but never gates replacement. Package admission is limited to a child with independent parents (native) or one parent and one child (RPC), refuses replacement and capacity eviction, and reports multi-row `testmempoolaccept` without aggregation. The graph linearization is exact-optimal and does not reproduce Core's bounded SFL tie history. The pool's memory bound is dynamic bytes, not virtual size. These differences are recorded in [docs/policies/mempool-policy.md](https://github.com/gosuda/bitcoin-rs/blob/main/docs/policies/mempool-policy.md); the tests above compare named cases, not default equivalence.
