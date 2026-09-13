# Mempool Policy Compatibility

This document declares bitcoin-rs's mempool/relay policy compatibility contract with Bitcoin Core and the rules for keeping it pinned. It is the transaction-acceptance counterpart to `docs/policies/p2p-compatibility.md` (peer wire) and the RPC compatibility manifest (`crates/rpc/src/manifest.rs`, rendered as `docs/rpc-reference.md`). Where this document and prose comments disagree, this document wins; where it and the code disagree, the code is the defect.

## 1. Scope and Authority

This policy applies to the transaction-acceptance surface of `bitcoin-rs-mempool` (`crates/mempool`: `standardness.rs`, `policy.rs`, `pool.rs`, `rbf.rs`, `eviction.rs`, `accept.rs`, `accounting.rs`, `admission.rs`, `gateway.rs`, `orphan.rs`, `reconsider.rs`) and its pool/RPC policy surfaces, including `sendrawtransaction` / `testmempoolaccept` (`crates/rpc/src/handlers/tx.rs`). Peer and RPC submissions share mempool-owned preparation and retry; P2P owns inventory, parent requests, and outbound relay. This document covers acceptance policy and gateway policy script checks: rules a full node enforces before admitting transactions to the mempool or relaying them. `MempoolGateway::admit_transaction` and `preview_transactions` share policy evaluation and input-script verification under Core's standard policy flags (`STANDARD_SCRIPT_VERIFY_FLAGS`, `validation.cpp::PolicyScriptChecks`). RPC `testmempoolaccept` calls that preview owner. Verification uses copied input outputs outside pool locks; generation, pool sequence and enforced policy are rechecked before publishing a verdict or committing. Full consensus validation at block application is governed by consensus rules (see `docs/contracts/validation-default.md` and the consensus tests).

The pool and RPC policy surfaces must quote the same verdict for the same transaction and pool state on every policy class this document marks `implemented`. RPC renders the gateway's semantic verdict with the documented transport-specific duplicate and error handling. Both surfaces use the same policy constants the pool enforces (`crates/mempool/src/eviction.rs::mempool_min_fee_sat_per_kvb`, `crates/mempool/src/rbf.rs::check_replacement`); a disagreement on an `implemented` class is a bug, not a policy.

`accounting.rs` assembles resolved-input fee, virtual size, and sigop-cost
facts using `bitcoin_rs_consensus::transaction_sigop_cost` for transaction-level
counting, implemented in `crates/consensus/src/sigops.rs`. Primitive script
counters remain in `bitcoin_rs_script::sigops`. Consensus verification, submission, preview, and
reorg preparation share that transaction counter without a second validation
engine. Consensus supplies the active verification flags; submission, preview,
and reorg accounting use `VerifyFlags::STANDARD`. Witness costs require an
active `WITNESS` flag, while existing P2SH accounting is unchanged. Legacy and P2SH sigops carry the witness scale factor; witness-v0
sigops carry unit cost, following
[BIP141](https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki#sigops)
and Core 31.1's
[`GetTransactionSigOpCost`](https://github.com/bitcoin/bitcoin/blob/v31.1/src/consensus/tx_verify.cpp).
`witness_sigop_cost_follows_the_active_bip141_flags` and
`assume_valid_and_prepared_sigop_checks_follow_witness_activation` prove the
flag boundary, including assume-valid and prepared block checks.
Incomplete preview context remains explicitly missing-input context; it is
not evidence that scripts or relative locks have been validated.
Package preview retains complete outputs from earlier package transactions as
prevout facts, including their scripts. The
`package_prevouts_preserve_sigops_without_mutating_the_pool` regression in
`crates/mempool/src/admission.rs` covers P2SH, native witness-v0, and nested witness
accounting, the selected output index, fee, vsize, and unchanged pool state.
Accounting alone is not script verification; the shared gateway verifier establishes the script verdict separately.

## 2. Pinned Reference Version

| Setting | Value |
| :--- | :--- |
| Reference implementation | Bitcoin Core |
| Pinned version | **31.1** (the version already recorded in custody evidence) |
| Min relay fee default | 1 000 sat/kvB (`MempoolLimits::default`) |
| Incremental relay fee default | 1 000 sat/kvB (`DEFAULT_INCREMENTAL_RELAY_FEE_SAT_PER_KVB`) |
| Dust relay fee default | 3 000 sat/kvB (`StandardnessPolicy::default().dust_relay_fee`) |
| Data carrier default | 83 bytes (`max_datacarrier_bytes = Some(83)`) |

### 2.1 Version-Bump Rules

Re-pinning to a newer Core version requires all of:

1. A green re-run of both fixture suites named in §6 against the new version's documented policy behavior, with every delta either implemented or added to the deviation ledger (§5).
2. A diff of the policy checks (`crates/mempool/src/standardness.rs` vs the new version's `policy/policy.cpp`) and of the package limits, with deltas recorded the same way.
3. Updating this document's pin and the fixtures in the same change-set — no intermediate states where the table and the code disagree (anti-shim rule, `docs/policies/source-compatibility.md` §5).

## 3. Policy Surface

Statuses: *implemented* (both admission outlets enforce it; fixture-cited), *deviation* (enforced with a recorded difference from Core, fixture-cited), *unimplemented* (§5 ledger; no fixture claims it).

| Policy | Core 31.1 behavior | bitcoin-rs behavior | Status | Fixture |
| :--- | :--- | :--- | :--- | :--- |
| Min relay fee | ATMP `AreInputsStandard`-era floor: fee rate below `-minrelaytime` rejected `min relay fee not met`; configurable via `-minrelaytxfee` | Insert gate rejects below `limits.min_relay_fee_sat_per_kvb` with `BelowMinRelayFee`; the acceptance preview (and therefore both RPC outlets) quotes the same floor; exactly-at-floor admits | implemented | `below_min_relay_fee_rejects_on_both_surfaces_at_the_same_floor`, `sendrawtransaction_rejects_below_min_relay_fee_and_agrees_with_the_pool` |
| Configured floor | `-minrelaytxfee` raises the admission floor node-wide | Same: pool limits carry the floor; both RPC outlets read it and quote it; exactly-at-floor admits | implemented | `configured_min_relay_floor_overrides_the_default` (pool side), `rpc_outlets_enforce_the_configured_floor` (both RPC outlets, boundary control) |
| Mempool-min fee under pressure | When the pool is ≥ half of `-maxmempool`, the effective floor rises to the cheapest evictable rate plus `-incrementalrelayfee` (`getmempoolinfo.mempoolminfee`) | Same heuristic with one owner (`eviction::mempool_min_fee_sat_per_kvb`): enforced by the acceptance preview and both RPC outlets, and reported by `getmempoolinfo` through the same function, so the quoted floor cannot drift from the enforced one. The raw pool insert gate checks only the configured floor — the pressure floor is an acceptance-outlet policy | implemented | `mempool_min_fee_rises_under_size_pressure_and_the_preview_enforces_it` (pool side), `rpc_outlets_enforce_the_pressure_floor` (both RPC outlets; raw-gate contrast pinned) |
| `-maxmempool` size bound | Overflowing admissions evict the cheapest descendant packages first | `commit_insert` evicts lowest-fee packages until the pool fits, emitting `Removed(PolicyEviction)` in commit order | implemented | `size_limit_eviction_removes_the_lowest_fee_package_first` (pool side), `sendrawtransaction_admission_evicts_the_lowest_fee_packages_under_size_pressure` (post-submission pool membership/order) |
| Standardness: tx version | `IsStandardTx`: versions 1–2 standard (3 under TRUC policy) | Versions 1–2 only; v3 rejected at the version gate (Core accepts v3 under TRUC; the TRUC package policy is not implemented — ledger §5.2) | deviation | `rejects_version_three_while_truc_policy_is_absent` (`standardness.rs` unit test), `testmempoolaccept_reports_a_policy_verdict_per_row` (RPC row: `non-standard transaction version`) |
| Standardness: scriptSig | Push-only, ≤ 1 650 bytes | Same (`ScriptSigNotPushOnly`, `ScriptSigTooLarge`) | implemented | `standardness.rs` unit tests (scriptSig push-only / size vectors) |
| Standardness: output script types | P2PKH, P2SH, P2PK, P2WPKH, P2WSH, P2TR, bare multisig ≤ 3 keys, anchor; otherwise `scriptpubkey` non-standard | Same list (`is_standard_output_script`, `is_p2a`, `is_standard_multisig`) | implemented | `nonstandard_output_script_is_not_standard_on_both_surfaces` (pool-side `is_standard_tx`), `sendrawtransaction_rejects_oversized_and_nonstandard_txs`, `testmempoolaccept_reports_a_policy_verdict_per_row` (RPC preview row) |
| Standardness: datacarrier (OP_RETURN) | ≤ 83 bytes aggregate, pushes only, `-datacarrier` gate | Same (`is_standard_nulldata`, `max_datacarrier_bytes = Some(83)`) | implemented | `standardness.rs` unit tests (`accepts_two_nulldata_outputs_within_the_aggregate_limit`) |
| Standardness: dust | Output below `3 × dustRelayFee × size / 1000` non-standard | Same formula (`is_dust` via `minimal_non_dust_custom`) | implemented | `dust_output_is_not_standard_on_both_surfaces` (pool-side `is_standard_tx`), `testmempoolaccept_reports_a_policy_verdict_per_row` (RPC preview row) |
| RBF signaling | Rule 0: a conflicting original must signal replaceability (BIP125 signal on an input, directly or via an unconfirmed ancestor) | Same (`signals_rbf_including_ancestors`) | implemented | `rbf_rule1_nonsignaling_originals_reject_on_both_surfaces`, `sendrawtransaction_rejects_nonsignaling_replacements_with_rule1`, `bip125_rule1_nonsignaling_originals_reject_on_both_rpcs` |
| RBF rule 2 | Replacement must not spend new unconfirmed inputs | Same (`is_unconfirmed_outpoint` vs originals' parents) | implemented | `rbf_rule2_replacement_may_not_add_unconfirmed_inputs`, `sendrawtransaction_rejects_rule2_replacements_adding_unconfirmed_inputs` |
| RBF rule 3 | Replacement absolute fee ≥ evicted transactions' fees | Same | implemented | `rbf_rule3_replacement_must_pay_evicted_fees`, `sendrawtransaction_rejects_rule3_replacements_that_underpay_evicted_fees` |
| RBF rule 4 | Replacement fee ≥ evicted fees + incremental relay fee × vsize | Same | implemented | `rbf_opt_in_replacement_sweeps_conflicts_and_descendants` (boundary), `bip125_rule4_replacement_must_pay_incremental_relay_fee_on_both_rpcs` |
| RBF rule 5 | Replacement must not evict more than 100 transactions | Same (`max_replacement_evictions = 100`) | implemented | `rbf_bip125.rs::bip125_replacement_rules_are_enforced` (rule-5 case), `bip125_rule5_too_many_evicted_descendants_reject_on_both_rpcs` |
| RBF rule 6 | Replacement fee rate strictly above the direct conflicts' | Same | implemented | `rbf_rule6_replacement_rate_must_exceed_direct_conflicts`, `sendrawtransaction_rejects_rule6_replacements_that_do_not_improve_the_rate` |
| RBF sweep on acceptance | Legal replacement evicts direct conflicts (reason: replaced) and their descendants (reason: descendant), parents first, then admits the replacement | Same commit order via `replace_transaction` → `MutationResult` | implemented | `rbf_opt_in_replacement_sweeps_conflicts_and_descendants`, `sendrawtransaction_applies_an_rbf_replacement_and_sweeps_the_conflicts` |
| Ancestor count limit | 25 unconfirmed ancestors inclusive (`-limitancestorcount`). Core 31 deprecated this as mempool policy and keeps it only for wallet coin selection | Same (`max_ancestors = 25`). Retained as mempool policy; retiring it is #114, not this change | implemented | `ancestor_count_limit_rejects_the_26th_unconfirmed_tx`, `sendrawtransaction_enforces_ancestor_count_limits_at_admission`, `testmempoolaccept_and_sendrawtransaction_agree_on_ancestor_count_limits` |
| Ancestor size limit | 101 000 vB ancestor package inclusive (`-limitancestorsize`). Same Core-31 deprecation as the ancestor count | Same (`max_ancestor_size = 101_000`). The equal default with `cluster_size_vbytes` is a coincidence of value, not of meaning | implemented | `ancestor_size_limit_rejects_an_oversized_package`, `sendrawtransaction_enforces_ancestor_size_limits_at_admission` |
| Descendant count limit | 25 unconfirmed descendants inclusive (`-limitdescendantcount`). Same Core-31 deprecation as the ancestor pair | Same (`max_descendants = 25`). Retained as mempool policy; retiring it is #114 | implemented | `descendant_count_limit_rejects_the_26th_child`, `sendrawtransaction_enforces_descendant_count_limits_at_admission` |
| Cluster count limit | 64 transactions in one connected component inclusive (`-limitclustercount`, `DEFAULT_CLUSTER_LIMIT`). A cluster is the undirected spend-graph component, not an ancestor package: siblings and cousins count | Same (`cluster_count = 64`). Enforced at admission and on the acceptance preview; replacements project the post-eviction cluster (evicted conflicts and descendants are absent from the walk) | implemented | `admission_refuses_a_transaction_over_the_cluster_count_limit`, `admission_counts_a_cousin_that_no_chain_through_the_parent_reaches`, `cluster_count_limit_rejects_a_sibling_that_ancestors_would_admit`, `check_package_limits_rejects_a_cluster_only_violation`, `a_replacement_that_evicts_from_a_full_cluster_is_admitted`, `testmempoolaccept_and_sendrawtransaction_agree_on_cluster_count_limits`, `testmempoolaccept_and_sendrawtransaction_agree_on_replacement_into_a_full_cluster` |
| Cluster size limit | 101 000 vB inclusive (`-limitclustersize`, `DEFAULT_CLUSTER_SIZE_LIMIT_KVB × 1000`) | Same (`cluster_size_vbytes = 101_000`). Same preview/admission/replacement projection as the count limit | implemented | `admission_refuses_a_transaction_over_the_cluster_size_limit`, `cluster_size_limit_rejects_on_both_surfaces`, `testmempoolaccept_and_sendrawtransaction_agree_on_cluster_size_limits` |
| Missing inputs / orphan submission | `sendrawtransaction` on an orphan: `missing-inputs` rejection (orphans are buffered for peer submissions only) | Preview reports `MissingInputs` for unresolvable prevouts; RPC quotes `missing-inputs`. The shared gateway retains peer-submitted orphans in its private `crates/mempool/src/orphan.rs` state; P2P consumes the resulting missing-parent IDs for requests. Retention follows [MPL-04](../contracts/mempool-mutations.md#mpl-04-generation-validated-admission-and-chain-change-fencing) | implemented | `missing_inputs_fact_is_reported_by_the_preview`, `testmempoolaccept_reports_a_policy_verdict_per_row` (RPC row) |
| BIP68 relative sequence locks | `CheckSequenceLocksAtTip`: version ≥ 2 inputs with an enabled sequence evaluate each prevout's height/MTP against the next block; unconfirmed parents count as the next block, `non-BIP68-final` otherwise | Same (`bip68::sequence_lock_satisfied` at admission over confirmed `PrevoutMeta` rows; pool and package parents encoded as the next block). Gated on `csv_active` for the next block; the RPC-surface fixture pins the inactive-gate case over a context with no CSV deployment state | implemented | `bip68_height_lock_boundary_enforces_at_admission`, `bip68_unconfirmed_parent_positive_relative_lock_fails`, `bip68_time_lock_uses_the_confirmed_median_time_past`, `bip68_check_is_inert_before_csv_activation` (pool/preview), `bip68_locked_tx_admits_while_csv_is_inactive_on_the_rpc_surface` (RPC) |
| Coinbase maturity | `CheckInputs` rejects coinbase-output spends under `COINBASE_MATURITY` (100 blocks) at ATMP with `bad-txns-premature-spend-of-coinbase` | Same depth rule at admission over confirmed coin metadata in the shared gateway, so preview and both RPC outlets enforce it before any mutation; the block-connect path keeps its own check. Rejected spends surface under the consensus class, not a dedicated string | implemented | `immature_coinbase_spend_rejects_before_100_confirmations` (pool/preview boundary), `immature_coinbase_spends_reject_on_both_rpcs_and_admit_at_maturity` (both RPC outlets, 99/100 boundary) |
| Policy script checks | ATMP `PolicyScriptChecks`: executes input scripts under `STANDARD_SCRIPT_VERIFY_FLAGS` before admitting to the pool | Both `preview_transactions` and `admit_transaction` run the same `verify_transaction` call with `VerifyFlags::STANDARD` over copied UTXO/mempool input outputs before any pool mutation or relay. Scripts run outside pool locks. | implemented | `preview_matches_submission_and_has_no_side_effects`, `admit_transaction_rejects_a_script_invalid_input`; production HTTP comparison in `overhaul_process_harness` |
| Standard sigop cost | `MAX_STANDARD_TX_SIGOPS_COST`: 16,000 weighted sigops | Gateway derives the cost from its resolved inputs and applies the cap before script execution on preview and submission | implemented | `admission_counts_resolved_sigops_before_verification` with independent rust-bitcoin P2SH accounting |
| Duplicate submission | A tx already in the mempool is not re-submitted (`node/transaction.cpp` `BroadcastTransaction`: "There's already a transaction in the mempool with this txid. Don't try to submit this transaction to the mempool"); a tx not in the mempool is processed again ("Transaction is not already in the mempool.") | Same distinction: `sendrawtransaction` returns the txid for a current pool hit without re-admission. A transaction that has left the pool is re-evaluated — admitted again if it is still valid, rejected if it still conflicts. Preview reports `txn-already-in-mempool` only for a pool hit | implemented | `transaction_methods.rs::sendrawtransaction_idempotent_for_already_in_mempool` (pool hit), `transaction_methods.rs::sendrawtransaction_readmits_a_transaction_evicted_from_the_mempool` (policy-evicted resubmission), `handlers/tx.rs::sendrawtransaction_does_not_treat_an_evicted_tx_as_already_known` (RBF-evicted retry) |
| `-maxfeerate` (absurd fee guard) | `sendrawtransaction`/`testmempoolaccept` reject above `maxfeerate` (default 0.10 BTC/kvB), **after** admission. Core 31.1 first runs the admission pass and returns its failure immediately (`node/transaction.cpp` `BroadcastTransaction`: "First, call ATMP with test_accept and check the fee. If ATMP fails here, return error immediately."); `MAX_FEE_EXCEEDED` is checked only on an admission-valid result. `testmempoolaccept` reports the per-row admission `reject-reason` and marks `max-fee-exceeded` only when the admission verdict is VALID (`rpc/mempool.cpp`). A tx below the floor *and* above `maxfeerate` therefore quotes the floor class. | Same default and order (`DEFAULT_MAX_RAW_TX_FEE_RATE_SAT_PER_KVB`, checked after the floor; matches the Core order above) | implemented | `sendrawtransaction_and_testmempoolaccept_quote_the_floor_before_maxfeerate` (both-predicates tx: floor class wins on both outlets; controls pin the ordinary accept and the `max-fee-exceeded` branch) |

## 4. Error Surface

Policy rejections reach callers with different envelopes per outlet; the class identity is stable across all of them:

| Class | Mempool preview fact | `sendrawtransaction` | `testmempoolaccept` row | Core 31.1 comparison |
| :--- | :--- | :--- | :--- | :--- |
| Below min relay | `MinRelayFeeNotMet` | JSON-RPC internal error, message contains `min-relay-fee-not-met` | `reject-reason: "min-relay-fee-not-met"` | Core: `min relay fee not met` (ATMP) / `min-relay-fee-not-met` (package); code −1/−26 by lane |
| Non-standard | `NonStandard(...)` | internal error, message is the standardness error text | `reject-reason` is the standardness error text (e.g. `non-standard output script`, `dust output`, `non-standard transaction version`) | Core: `version`, `dust`, `scriptpubkey`, `tx-size`; code −26/−27 by lane |
| RBF rules | `Replacement(RbfError)` | `TxRejected` (−26), containing `BIP125 rule N` | `reject-reason` carries the same text | Core: `bad-txns-bip125-replacement-*` family |
| Missing inputs | `MissingInputs` | `TxRejected` (−26), containing `missing-inputs` | `reject-reason: "missing-inputs"` | Core: `missing-inputs` (−25) |
| Non-BIP68-final | `NonBip68Final` | `TxRejected` (−26), containing `non-BIP68-final` | `reject-reason: "non-BIP68-final"` | Core: `non-BIP68-final` (ATMP), code −26 |
| Package limits | `PackageLimit(PolicyError)` | internal error containing the pool policy text (e.g. `too many unconfirmed ancestors`, `ancestor package is too large`, `too many unconfirmed descendants`, `too many transactions in cluster`, `cluster is too large`) | `reject-reason` carries the same text | Core: `too-long-mempool-chain` / cluster-limit text, code −26 |
| Consensus / Script verification | `ScriptVerify` | `RpcError::TxRejected("consensus-verification-failed")` | `reject-reason: "script-verify-flag-failed"` | Core reports more detailed `mandatory-script-verify-flag-failed` / `non-mandatory-script-verify-flag` strings, code −26 |

Code values are the node's transaction-rejected code (−26), except `MaxFeeExceeded`, which is `InvalidParams` (−32602). Core uses its transaction error codes (−1/−25/−26/−27) for the same classes; the per-class message strings, not the numeric code, are the compatibility contract here. Aligning numeric codes is deferred to the RPC compatibility manifest (`crates/rpc/src/manifest.rs`) so there is one owner for the error-code table.

## 5. Deviation Ledger

Explicit deltas from Core 31.1, each intentional and known:

1. **Generic script rejection text.** Preview and submission both verify scripts, but render their shared rejection as `script-verify-flag-failed` and `consensus-verification-failed`, respectively. Core exposes finer script-failure detail. No exact Core script-error-string parity is claimed.
2. **TRUC (v3) transactions are non-standard.** Core 31 accepts version-3 transactions under its TRUC package policy; bitcoin-rs rejects them at the version gate rather than copying the permissive half of the design without the constraining half. The §3 row is now classified `deviation` (not `implemented (stricter than Core)`). Pinned by `rejects_version_three_while_truc_policy_is_absent` and the RPC row in `testmempoolaccept_reports_a_policy_verdict_per_row`.
3. **Error codes.** Policy rejections surface as JSON-RPC internal errors (−32603) or rejected errors (−26) with the class text in the message, not Core's transaction error codes (§4). Numeric-code alignment is owned by the RPC compatibility manifest.
4. **Priorities (`prioritisetransaction`) affect only mining ordering**, never admission — matching Core's current posture, recorded so the fee-delta overlay is not mistaken for an admission lever.

## 6. Verification

- **Mempool-surface fixtures**: `cargo test -p bitcoin-rs-mempool --test policy_contract` — every §3 row's pool-side verdict plus the finality rows — next-block BIP68 height/time boundaries over confirmed metadata and unconfirmed parents, the csv-inactive gate control, and the coinbase maturity 99/100 boundary; the missing-inputs row also has a direct `MempoolGateway` preview fixture. The remaining preview-side verdicts are exercised through the RPC-surface fixtures below.
- **RPC-surface fixtures**: `cargo test -p bitcoin-rs-rpc --test policy_contract` — the same policy classes through `sendrawtransaction` and `testmempoolaccept` over a real `Context`, each asserting the observable verdict (accept, or error code + message; per-row `reject-reason`) and its agreement with the direct pool outcome: the standardness classes, both fee floors (configured and pressure) and their precedence against `-maxfeerate`, the ancestor/descendant package limits and the cluster count/size limits (preview and admission agree, including a replacement that does not grow a full cluster), size-pressure eviction with post-submission pool membership/order, the coinbase-maturity 99/100 boundary and the csv-inactive BIP68 control through the real admission producer, and the full BIP125 rule set — opt-in accept + sweep, rules 1–6 each with a dedicated both-RPC fixture asserting verdict + error class on `sendrawtransaction` AND `testmempoolaccept` + direct-pool cross-check.
- **Supplementary vectors**: `cargo test -p bitcoin-rs-mempool --test rbf_bip125` (per-rule RBF table incl. rule 5), `standardness.rs` unit tests (per-check standardness vectors), `gateway.rs` unit tests (`admit_transaction_rejects_a_script_invalid_input`, `admit_transaction_accepts_locktime_equal_to_tip_at_next_height`, `admit_transaction_rejects_locktime_one_past_tip`), and `cargo test -p bitcoin-rs-rpc --test transaction_methods` (POL-01 duplicate submission: in-mempool idempotency and policy-evicted resubmission).
- **Shared accounting**: `crates/mempool/src/accounting.rs` tests
  `bip141_accounting_matches_independent_transaction_oracle`,
  and `arbitrary_redeem_data_does_not_activate_witness_accounting` compare
  BIP141 cases against rust-bitcoin's transaction sigop-cost implementation.
  `non_push_only_p2sh_scripts_have_no_redeem_sigops` uses a Core-derived
  expected result: the rust-bitcoin comparison does not enforce Core's
  push-only precondition for this edge case.
  `incomplete_accounting_preserves_the_missing_input_fact` checks that
  provisional accounting does not erase missing-input classification.
  The shared transaction counter is covered by
  `transaction_sigop_cost_uses_prevout_type_and_push_only_redeem_rules`,
  `transaction_sigop_cost_resolves_partial_and_unordered_prevouts`, and
  `non_push_only_p2sh_does_not_count_redeem_sigops` in
  `crates/consensus/src/sigops.rs`.
  `crates/mempool/src/admission.rs` test
  `submission_carries_prepared_fee_size_and_weighted_sigops_into_entry`
  verifies that both RPC- and peer-originated submissions carry those
  accounting facts into committed entries.
  `bip141_sigops_are_preserved_from_restored_coins_and_offered_outputs` in
  `crates/mempool/src/reconsider.rs` covers restored and earlier-offered
  previous outputs. The mining integration test
  `reconsidered_prevout_cost_reaches_the_mining_sigop_budget`
  (`crates/mining/tests/coinbase_template.rs`) checks the stored reorg cost
  against template selection's sigop budget.
- **Package-parent accounting**: `package_prevouts_preserve_sigops_without_mutating_the_pool`
  in `crates/mempool/src/admission.rs` checks nonzero output selection for
  P2SH and native/nested witness programs against BIP141 and rust-bitcoin.
  One-past-end and maximum output indices stay missing, with no contextual
  sigops, invented fee, or pool mutation. These are accounting checks, not
  package script-verification claims.
- A policy change that alters any §3 row must update its fixture in the same commit; a fixture that no longer compiles against the doc is the defect (anti-shim rule).

See also [docs/contracts/mempool-policy.md](../contracts/mempool-policy.md) for the contracts index and precedence rule.
