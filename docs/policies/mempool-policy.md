# Mempool Policy Compatibility

This document declares the mempool and relay policy compatibility contract between bitcoin-rs and Bitcoin Core, and the rules that keep the contract pinned. It is the transaction-acceptance counterpart to `docs/policies/p2p-compatibility.md` (peer wire) and the RPC compatibility manifest (`crates/rpc/src/manifest.rs`, rendered as `docs/rpc-reference.md`). Where this document and prose comments disagree, this document wins. Where this document and the code disagree, the code is the defect.

## 1. Scope and implementation status

`MempoolGateway::admit_transaction` owns commit admission. RPC preview still uses
`evaluate_package_acceptance_all`; Esplora broadcast delegates to RPC. A shared
Preview/Commit API, owner-computed sigops, full BIP68/maturity policy, TRUC, and
feerate-diagram replacement are targets, not implemented guarantees. See
[the contract](../contracts/mempool-policy.md) for the exact boundary.

The matrix below records intended compatibility and existing fixture names.
Rows naming planned overhaul fixtures are not evidence that those features work.

## 2. Pinned Reference Version

| Setting | Value |
| :--- | :--- |
| Reference implementation | Bitcoin Core |
| Pinned release | **31.1**, tag `v31.1`, source commit `9be056a8a72b624dae9623b2f7bded92c2a21c91` |
| Release binary identity | x86_64 Linux archive SHA256 `b80d9c3e04da78fb6f0569685673418cf686fadba9042d926d13fb87ff503f9e`; `bitcoind` SHA256 `986e63b3c8770f08d0059820ad3dd085d1ab9e1bea23946c243f858a06888a08` |
| Kernel oracle | `bitcoinkernel 0.2.1` (kernel tree 31.99.0). Oracle evidence only; never a policy pin |
| Min relay fee default | 1 000 sat/kvB (`MempoolLimits::default`) |
| Incremental relay fee default | 1 000 sat/kvB (`DEFAULT_INCREMENTAL_RELAY_FEE_SAT_PER_KVB`) |
| Dust relay fee default | 3 000 sat/kvB (`StandardnessPolicy::default().dust_relay_fee`) |
| Data carrier default | 83 bytes (`max_datacarrier_bytes = Some(83)`) |
| Cluster limits | 64 transactions / 101 000 vB (`cluster_count`, `cluster_size_vbytes`) |
| Max package count | 25 (`MAX_PACKAGE_COUNT`) |
| Max replacement evictions | 100 (`max_replacement_evictions`) |
| Max fee guard default | 0.1 BTC/kvB (`DEFAULT_MAX_RAW_TX_FEE_RATE_SAT_PER_KVB`) |
| Sigop cost limit | 16 000 (`MAX_STANDARD_TX_SIGOPS_COST`), computed by the gateway from resolved prevouts |
| Admission retry bound | Four attempts with fresh facts, then typed `Busy` |
| Replacement profile | Core 31.1 feerate-diagram condition with cluster-aware victim projection |

### 2.1 Version-Bump Rules

Re-pinning to a newer Core version requires all of:

1. A green re-run of both fixture suites named in §6 against the new version's documented policy behavior, with every delta either implemented or added to the deviation ledger (§5).
2. A diff of the policy checks (`crates/mempool/src/standardness.rs` vs the new version's `policy/policy.cpp`) and of the package limits, with deltas recorded the same way.
3. An update of this document's pin and the fixtures in the same change-set. No intermediate state may leave the table and the code in disagreement (anti-shim rule, `docs/policies/source-compatibility.md` §5).

## 3. Policy Surface

Statuses: *implemented* (all admission outlets enforce it; fixture-cited), *deviation* (enforced with a recorded difference from Core, fixture-cited), *unimplemented* (§5 ledger; no fixture claims it). A fixture marked *(planned)* names a test target that the cited task adds; it is not yet executed.

Replacement rows follow the pinned Core 31.1 profile. The feerate-diagram condition and the cluster bounds are authoritative. The historical BIP125 rule classes remain for the cases where they fire first under the pinned precedence.

| Policy | Core 31.1 behavior | bitcoin-rs behavior | Status | Fixture |
| :--- | :--- | :--- | :--- | :--- |
| Min relay fee | ATMP `AreInputsStandard`-era floor: fee rate below `-minrelaytxfee` rejected `min relay fee not met`; configurable via `-minrelaytxfee` | Insert gate rejects below `limits.min_relay_fee_sat_per_kvb` with `BelowMinRelayFee`; the gateway preview (and therefore both RPC outlets) quotes the same floor; exactly-at-floor admits | implemented | `below_min_relay_fee_rejects_on_both_surfaces_at_the_same_floor`, `sendrawtransaction_rejects_below_min_relay_fee_and_agrees_with_the_pool` |
| Configured floor | `-minrelaytxfee` raises the admission floor node-wide | Same: pool limits carry the floor; both RPC outlets read it and quote it; exactly-at-floor admits | implemented | `configured_min_relay_floor_overrides_the_default` (pool side), `rpc_outlets_enforce_the_configured_floor` (both RPC outlets, boundary control) |
| Mempool-min fee under pressure | When the pool is ≥ half of `-maxmempool`, the effective floor rises to the cheapest evictable rate plus `-incrementalrelayfee` (`getmempoolinfo.mempoolminfee`) | Same heuristic (`eviction::mempool_min_fee_sat_per_kvb`); enforced by the gateway preview and both RPC outlets. The raw pool insert gate checks only the configured floor; the pressure floor is an acceptance-outlet policy | implemented | `mempool_min_fee_rises_under_size_pressure_and_the_preview_enforces_it` (pool side), `rpc_outlets_enforce_the_pressure_floor` (both RPC outlets; raw-gate contrast pinned) |
| `-maxmempool` size bound | Overflowing admissions evict the cheapest descendant packages first | `commit_insert` evicts lowest-fee packages until the pool fits, emitting `Removed(PolicyEviction)` in commit order | implemented | `size_limit_eviction_removes_the_lowest_fee_package_first` (pool side), `sendrawtransaction_admission_evicts_the_lowest_fee_packages_under_size_pressure` (post-submission pool membership/order) |
| Standardness: tx version and TRUC (v3) | `IsStandardTx`: versions 1-2 standard; version 3 standard only under the TRUC policy (one direct sibling, sibling and topology size caps, v3 parent-child restrictions) | Target; current limitations are listed in POL-02 through POL-06. | planned / partial | `crates/mempool/tests/overhaul_replacement_profile.rs` (planned: single v3 with one sibling within caps admitted, second sibling and topology violations rejected, v1/v2 unaffected) |
| Standardness: tx weight | `tx-size`: weight > 400 000 non-standard | Same bound (`MAX_STANDARD_TX_WEIGHT`) | implemented | `oversized_weight_is_not_standard_on_both_surfaces`, `sendrawtransaction_rejects_oversized_and_nonstandard_txs` |
| Standardness: tx size (small) | `tx-size-small`: non-witness size < 65 non-standard | Same bound (`MIN_NON_WITNESS_TX_SIZE`) | implemented | `standardness.rs` unit tests (tx-size-small vectors) |
| Standardness: scriptSig | Push-only, ≤ 1 650 bytes | Same (`ScriptSigNotPushOnly`, `ScriptSigTooLarge`) | implemented | `standardness.rs` unit tests (scriptSig push-only / size vectors) |
| Standardness: output script types | P2PKH, P2SH, P2PK, P2WPKH, P2WSH, P2TR, bare multisig ≤ 3 keys, anchor; otherwise `scriptpubkey` non-standard | Same list (`is_standard_output_script`, `is_p2a`, `is_standard_multisig`) | implemented | `nonstandard_output_script_is_not_standard_on_both_surfaces`, `sendrawtransaction_rejects_oversized_and_nonstandard_txs` |
| Standardness: datacarrier (OP_RETURN) | ≤ 83 bytes aggregate, pushes only, `-datacarrier` gate | Same (`is_standard_nulldata`, `max_datacarrier_bytes = Some(83)`) | implemented | `standardness.rs` unit tests (`accepts_two_nulldata_outputs_within_the_aggregate_limit`) |
| Standardness: dust | Output below `3 × dustRelayFee × size / 1000` non-standard | Same formula (`is_dust` via `minimal_non_dust_custom`) | implemented | `dust_output_is_not_standard_on_both_surfaces` |
| Standardness: sigop cost | `MAX_STANDARD_TX_SIGOPS_COST` = 16 000 per transaction, counted from resolved prevouts (legacy and P2SH redeem counts weighted, witness-program counts) | Target; current limitations are listed in POL-02 through POL-06. | planned / partial | `crates/mempool/tests/overhaul_admission_owner.rs` (planned: 16 000 admits, 16 001 rejects, wrong caller count ignored) |
| Finality: BIP68 sequence locks and maturity | Core rejects non-final transactions at admission (`non-BIP68-final`); finality is evaluated at the next block height and covers coinbase maturity, absolute locktime, and height- and time-based relative sequence locks with the disable flag | Target; current limitations are listed in POL-02 through POL-06. | planned / partial | `crates/mempool/tests/overhaul_finality_policy.rs` (planned: height and MTP boundaries, disable flag, coinbase maturity) |
| RBF signaling | Rule 0: a conflicting original must signal replaceability (BIP125 signal on an input, directly or via an unconfirmed ancestor) | Same (`signals_rbf_including_ancestors`) | implemented | `rbf_rule1_nonsignaling_originals_reject_on_both_surfaces`, `sendrawtransaction_rejects_nonsignaling_replacements_with_rule1`, `bip125_rule1_nonsignaling_originals_reject_on_both_rpcs` |
| RBF rule 2 | Replacement must not spend new unconfirmed inputs | Same (`is_unconfirmed_outpoint` vs originals' parents) | implemented | `rbf_rule2_replacement_may_not_add_unconfirmed_inputs`, `sendrawtransaction_rejects_rule2_replacements_adding_unconfirmed_inputs` |
| RBF rule 3 | Replacement absolute fee ≥ evicted transactions' fees | Same | implemented | `rbf_rule3_replacement_must_pay_evicted_fees`, `sendrawtransaction_rejects_rule3_replacements_that_underpay_evicted_fees` |
| RBF rule 4 | Replacement fee ≥ evicted fees + incremental relay fee × vsize | Same | implemented | `rbf_opt_in_replacement_sweeps_conflicts_and_descendants` (boundary), `bip125_rule4_replacement_must_pay_incremental_relay_fee_on_both_rpcs` |
| RBF rule 5 | Core 31.1 bounds the total evicted cluster; the pinned resource bound is 100 evicted transactions | Same (`max_replacement_evictions = 100`) | implemented | `rbf_bip125.rs::bip125_replacement_rules_are_enforced` (rule-5 case), `bip125_rule5_too_many_evicted_descendants_reject_on_both_rpcs` |
| RBF rule 6 | Replacement fee rate strictly above the direct conflicts' | Same | implemented | `rbf_rule6_replacement_rate_must_exceed_direct_conflicts`, `sendrawtransaction_rejects_rule6_replacements_that_do_not_improve_the_rate` |
| Replacement feerate diagram | The replacement cluster's feerate diagram must strictly improve on the merged diagram of every evicted cluster (direct conflicts plus descendants), under the pinned tie and resource-budget rules; victim clusters are computed before mutation | Same: candidate and victim clusters are computed from the bounded cluster structure before any mutation; the diagram comparison follows the pinned condition including ties and budget; a rejected replacement leaves membership, sequence, and estimator state unchanged | implemented | `crates/mempool/tests/overhaul_replacement_profile.rs` (planned: diagram-failure rejection, multi-cluster victims, tie cases, budget exhaustion) |
| RBF sweep on acceptance | Legal replacement evicts direct conflicts (reason: replaced) and their descendants (reason: descendant), parents first, then admits the replacement | Same commit order via `replace_transaction` → `MutationResult` | implemented | `rbf_opt_in_replacement_sweeps_conflicts_and_descendants`, `sendrawtransaction_applies_an_rbf_replacement_and_sweeps_the_conflicts` |
| Ancestor count limit | 25 unconfirmed ancestors inclusive (`-limitancestorcount`). Core 31 deprecated this as mempool policy and keeps it only for wallet coin selection | Same (`max_ancestors = 25`). Retained as mempool policy; retiring it is #114, not this change | implemented | `ancestor_count_limit_rejects_the_26th_unconfirmed_tx`, `sendrawtransaction_enforces_ancestor_count_limits_at_admission`, `testmempoolaccept_and_sendrawtransaction_agree_on_ancestor_count_limits` |
| Ancestor size limit | 101 000 vB ancestor package inclusive (`-limitancestorsize`). Same Core-31 deprecation as the ancestor count | Same (`max_ancestor_size = 101_000`). The equal default with `cluster_size_vbytes` is a coincidence of value, not of meaning | implemented | `ancestor_size_limit_rejects_an_oversized_package`, `sendrawtransaction_enforces_ancestor_size_limits_at_admission` |
| Descendant count limit | 25 unconfirmed descendants inclusive (`-limitdescendantcount`). Same Core-31 deprecation as the ancestor pair | Same (`max_descendants = 25`). Retained as mempool policy; retiring it is #114 | implemented | `descendant_count_limit_rejects_the_26th_child`, `sendrawtransaction_enforces_descendant_count_limits_at_admission` |
| Cluster count limit | 64 transactions in one connected component inclusive (`-limitclustercount`, `DEFAULT_CLUSTER_LIMIT`). A cluster is the undirected spend-graph component, not an ancestor package: siblings and cousins count | Same (`cluster_count = 64`). Enforced at admission and on the acceptance preview; replacements project the post-eviction cluster (evicted conflicts and descendants are absent from the walk) | implemented | `admission_refuses_a_transaction_over_the_cluster_count_limit`, `admission_counts_a_cousin_that_no_chain_through_the_parent_reaches`, `cluster_count_limit_rejects_a_sibling_that_ancestors_would_admit`, `check_package_limits_rejects_a_cluster_only_violation`, `a_replacement_that_evicts_from_a_full_cluster_is_admitted`, `testmempoolaccept_and_sendrawtransaction_agree_on_cluster_count_limits`, `testmempoolaccept_and_sendrawtransaction_agree_on_replacement_into_a_full_cluster` |
| Cluster size limit | 101 000 vB inclusive (`-limitclustersize`, `DEFAULT_CLUSTER_SIZE_LIMIT_KVB × 1000`) | Same (`cluster_size_vbytes = 101_000`). Same preview/admission/replacement projection as the count limit | implemented | `admission_refuses_a_transaction_over_the_cluster_size_limit`, `cluster_size_limit_rejects_on_both_surfaces`, `testmempoolaccept_and_sendrawtransaction_agree_on_cluster_size_limits` |
| Package submission bound | Package evaluation bounds one submission to 25 transactions (`MAX_PACKAGE_COUNT`), dependency-ordered, with intra-package conflict handling and package-RBF conditions | Same (`MAX_PACKAGE_COUNT = 25`); multi-transaction submissions evaluate as dependency-ordered packages through the shared pipeline and quote per-row verdicts | implemented | `crates/mempool/tests/overhaul_replacement_profile.rs` (planned: package evaluation and per-row verdicts) |
| Missing inputs / orphan submission | `sendrawtransaction` on an orphan: `missing-inputs` rejection (orphans are buffered on the P2P side only) | Preview reports `MissingInputs` for unresolvable prevouts; RPC quotes `missing-inputs`. Orphan buffering is owned by the mempool (`crates/mempool/src/orphan.rs`); the node owns peer-event routing only | implemented | `missing_inputs_fact_is_reported_by_the_preview`, `testmempoolaccept_reports_a_policy_verdict_per_row` (RPC row) |
| Policy script checks | ATMP `PolicyScriptChecks`: executes input scripts under `STANDARD_SCRIPT_VERIFY_FLAGS` before admission; the `testmempoolaccept` dry run applies the same script checks | Target; current limitations are listed in POL-02 through POL-06. | planned / partial | `admit_transaction_rejects_a_script_invalid_input` (`gateway.rs` unit tests), `crates/mempool/tests/overhaul_admission_owner.rs` (planned: script-invalid preview rejection) |
| Duplicate submission | A tx already in the mempool is not re-submitted (`node/transaction.cpp` `BroadcastTransaction`: "There's already a transaction in the mempool with this txid. Don't try to submit this transaction to the mempool"); a tx not in the mempool is processed again ("Transaction is not already in the mempool.") | Same distinction: `sendrawtransaction` returns the txid for a current pool hit without re-admission. A transaction that has left the pool is re-evaluated: admitted again if it is still valid, rejected if it still conflicts. Preview reports `txn-already-in-mempool` only for a pool hit | implemented | `transaction_methods.rs::sendrawtransaction_idempotent_for_already_in_mempool` (pool hit), `transaction_methods.rs::sendrawtransaction_readmits_a_transaction_evicted_from_the_mempool` (policy-evicted resubmission), `handlers/tx.rs::sendrawtransaction_does_not_treat_an_evicted_tx_as_already_known` (RBF-evicted retry) |
| `-maxfeerate` (absurd fee guard) | `sendrawtransaction`/`testmempoolaccept` reject above `maxfeerate` (default 0.10 BTC/kvB), **after** admission. Core 31.1 first runs the admission pass and returns its failure immediately (`node/transaction.cpp` `BroadcastTransaction`: "First, call ATMP with test_accept and check the fee. If ATMP fails here, return error immediately."); `MAX_FEE_EXCEEDED` is checked only on an admission-valid result. `testmempoolaccept` reports the per-row admission `reject-reason` and marks `max-fee-exceeded` only when the admission verdict is VALID (`rpc/mempool.cpp`). A tx below the floor *and* above `maxfeerate` therefore quotes the floor class. | Same default and order (`DEFAULT_MAX_RAW_TX_FEE_RATE_SAT_PER_KVB`, checked after the floor; matches the Core order above) | implemented | `sendrawtransaction_and_testmempoolaccept_quote_the_floor_before_maxfeerate` (both-predicates tx: floor class wins on both outlets; controls pin the ordinary accept and the `max-fee-exceeded` branch) |

## 4. Error Surface

Policy rejections reach callers with different envelopes per outlet; the class identity is stable across all of them:

| Class | Mempool preview fact | `sendrawtransaction` | `testmempoolaccept` row | Core 31.1 comparison |
| :--- | :--- | :--- | :--- | :--- |
| Below min relay | `MinRelayFeeNotMet` | JSON-RPC internal error, message contains `min-relay-fee-not-met` | `reject-reason: "min-relay-fee-not-met"` | Core: `min relay fee not met` (ATMP) / `min-relay-fee-not-met` (package); code −1/−26 by lane |
| Non-standard | `NonStandard(...)` | internal error, message is the standardness error text | `reject-reason` is the standardness error text (e.g. `non-standard output script`, `dust output`, `non-standard transaction version`) | Core: `version`, `dust`, `scriptpubkey`, `tx-size`; code −26/−27 by lane |
| RBF rules | `Replacement(RbfError)` | `TxRejected` (−26), containing `BIP125 rule N` | `reject-reason` carries the same text | Core: `bad-txns-bip125-replacement-*` family |
| Missing inputs | `MissingInputs` | `TxRejected` (−26), containing `missing-inputs` | `reject-reason: "missing-inputs"` | Core: `missing-inputs` (−25) |
| Package limits | `PackageLimit(PolicyError)` | internal error containing the pool policy text (e.g. `too many unconfirmed ancestors`, `ancestor package is too large`, `too many unconfirmed descendants`, `too many transactions in cluster`, `cluster is too large`) | `reject-reason` carries the same text | Core: `too-long-mempool-chain` / cluster-limit text, code −26 |
| Non-final (BIP68) | `NonBip68Final` | `TxRejected` (−26) with the typed non-final class text | `reject-reason` carries the same text | Core: `non-BIP68-final` |
| Consensus / Script verification | `Consensus` / script-verify class, commit admission only; preview omits verification | `RpcError::TxRejected("consensus-verification-failed")` | not checked by the current preview evaluator | Core: `mandatory-script-verify-flag-failed`, `non-mandatory-script-verify-flag`, code −26 |

Code values are the node's transaction-rejected code (−26), except `MaxFeeExceeded`, which is `InvalidParams` (−32602). Core uses its transaction error codes (−1/−25/−26/−27) for the same classes; the per-class message strings, not the numeric code, are the compatibility contract here. Aligning numeric codes is deferred to the RPC compatibility manifest (`crates/rpc/src/manifest.rs`) so there is one owner for the error-code table.

## 5. Active deviations

1. Preview and commit use different evaluators; preview is not proof of script validity.
2. Complete BIP68 sequence-lock and coinbase-maturity admission checks are absent.
3. Version 3 is still non-standard; TRUC and feerate-diagram replacement are absent.
4. Sigop cost is still caller context, not an authoritative owner computation.
5. Numeric rejection codes and messages differ by RPC/policy class; the manifest
   owns the declared wire deviations.

These deviations were not retired by planned T18/T19/T21 work. Existing fixtures
must not be presented as evidence for the missing paths.

## 6. Verification

- **Mempool-surface fixtures**: `cargo test -p bitcoin-rs-mempool --test policy_contract`: every §3 row's pool-side and preview-side verdicts, the RBF sweep commit order, eviction order under size pressure, the pressure-floor heuristic, and cluster count/size rejection plus a replacement that does not grow a full cluster.
- **RPC-surface fixtures**: `cargo test -p bitcoin-rs-rpc --test policy_contract`: the same policy classes through `sendrawtransaction` and `testmempoolaccept` over a real `Context`, each asserting the observable verdict (accept, or error code + message; per-row `reject-reason`) and its agreement with the direct pool outcome: the standardness classes, both fee floors (configured and pressure) and their precedence against `-maxfeerate`, the ancestor/descendant package limits and the cluster count/size limits (preview and admission agree, including a replacement that does not grow a full cluster), size-pressure eviction with post-submission pool membership/order, and the full BIP125 rule set: opt-in accept + sweep, rules 1-6 each with a dedicated both-RPC fixture asserting verdict + error class on `sendrawtransaction` AND `testmempoolaccept` + direct-pool cross-check.
- **Overhaul admission fixtures (planned)**: `cargo test -p bitcoin-rs-mempool --test overhaul_admission_owner` (planned; T18) covers one-pipeline parity across ingress shapes, script-invalid preview rejection, preview non-mutation, stale-context retry, typed `Busy` after four attempts, and the 16 000 sigop boundary. `cargo test -p bitcoin-rs-mempool --test overhaul_finality_policy` (planned; T19) covers BIP68 height and time boundaries, the disable flag, coinbase maturity, and policy-epoch invalidation. `cargo test -p bitcoin-rs-mempool --test overhaul_replacement_profile` (planned; T21) covers the feerate-diagram condition, cluster-aware victims, tie and budget rules, package evaluation, and TRUC v3.
- **Supplementary vectors**: `cargo test -p bitcoin-rs-mempool --test rbf_bip125` (per-rule RBF table incl. rule 5), `standardness.rs` unit tests (per-check standardness vectors), `gateway.rs` unit tests (`admit_transaction_rejects_a_script_invalid_input`, `admit_transaction_evaluates_finality_at_next_block_height`), and `cargo test -p bitcoin-rs-rpc --test transaction_methods` (POL-01 duplicate submission: in-mempool idempotency and policy-evicted resubmission).
- A policy change that alters any §3 row must update its fixture in the same commit; a fixture that no longer compiles against the doc is the defect (anti-shim rule).

See also [docs/contracts/mempool-policy.md](../contracts/mempool-policy.md) for the contracts index and precedence rule.
