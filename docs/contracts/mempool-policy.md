# Mempool policy contract

This page is the target contract for transaction admission. It names one
admission owner, the pin set it enforces, and the proof. The detailed
Core 31.1 behavior matrix stays in
[docs/policies/mempool-policy.md](../policies/mempool-policy.md). On
conflict between code and either page, fix the code and amend both in the
same changeset.

Owner: `MempoolGateway` in `crates/mempool/src/gateway.rs`. The node
constructs one `Arc<MempoolGateway>` and passes it to RPC, P2P ingress,
Esplora broadcast, package evaluation, and reorg reconciliation. No crate
holds a second admission evaluator.

## Clauses

### `POL-01`: Core 31.1 policy pin and versioned `AdmissionPolicy`

- The pinned reference is released Bitcoin Core 31.1. The gateway
  enforces this pin set. Pin values are Core truth and never edited
  to match implementation progress; rows the implementation has not
  yet reached are recorded as deviations in
  `docs/policies/mempool-policy.md` (§3 status column and §5 ledger).

  | Pin | Required value |
  |---|---|
  | Min-relay fee | 1_000 sat/kvB |
  | Incremental relay fee | 1_000 sat/kvB |
  | Dust rate | 3_000 sat/kvB |
  | `datacarrier` payload | 83 bytes |
  | Cluster count limit | 64 |
  | Cluster size limit | 101_000 vB |
  | Max package count | 25 |
  | Max replacement evictions | 100 |
  | Max fee | 0.1 BTC/kvB |
  | Standard transaction sigops | 16_000 |
| TRUC (v3) transactions | supported |

- `crates/mempool/src/policy.rs` resolves one versioned `AdmissionPolicy`
  from `NodeConfig` at startup. The gateway stamps every verdict with the
  `policy_epoch` field of `ReadStamp`. A policy change advances the epoch
  and invalidates prepared admission work.
- The gateway never re-derives policy from pool limits on a read guard.
  A deliberately different floor or datacarrier rule is machine-readable
  in the policy document.

### `POL-02`: One admission owner and admission mode

- `MempoolGateway` is the only production admission path. RPC
  `sendrawtransaction` and `testmempoolaccept`, P2P ingress, Esplora
  `POST /tx`, package submissions, and reorg reconsideration all call it.
- The operation accepts parsed transactions and request fee limits. An
  `AdmissionMode::{Preview, Commit}` selector, `Esplora` and `Package`
  origins, and per-transaction gateway verdicts are T18 work: no mode
  selector, `Esplora`/`Package` variants, or verdict types exist today
  (Esplora `POST /tx` dispatches as `Rpc`; previews live in the RPC
  outlet). Committed changes occur only when a mutation occurred.
- Peer ingress does not inherit RPC fee limits. Each origin declares its
  own request limits. The node wires narrow chain and coin providers;
  RPC and P2P do not resolve admission contexts themselves.

### `POL-03`: Admission pipeline, stamp, and precedence

- The gateway runs one pipeline: cheap checks, coherent stamp capture,
  one-pass input resolution, policy evaluation, script verification
  outside the pool writer, then one writer-held recheck and atomic
  commit.
- Cheap checks, in order: canonical parse shape, duplicate inputs,
  coinbase rejection, output range and sum checks, known identity, and
  request and package count bounds.
- Stamp capture records
  `ReadStamp{process_epoch, chain_generation, chain_tip, mempool_sequence, policy_epoch}`
  while the bounded read fence protects live UTXO resolution.
  `chain_generation` is even while stable and odd during a coordinated
  change. A caller never composes a view from a separately loaded tip
  and mutable coins.
- Input resolution runs once per input. It resolves from the
  admitted-pool overlay over chain coins and retains full coin metadata:
  value, exact script, origin height, coinbase flag, and MTP context.
  No borrowed pointer survives into a replaceable record.
- Script verification runs with `VerifyFlags::STANDARD` while no code
  holds the pool writer. Mandatory and policy script failures stay
  distinct typed classes. Shared per-transaction sighash facts feed the
  run.
- The commit step acquires the pool writer once, rechecks every stamp
  field plus pool and policy context, and applies the atomic mutation.
  Four stale attempts end in a typed `Busy` result. Callers map `Busy`
  to their dialect; they never reuse stale evidence and never spin.
- Error precedence: parse, missing input or coinbase, standardness, fee
  floor, max fee, BIP68 and absolute finality, mandatory versus policy
  script class, RBF and feerate diagram, package and cluster limits,
  commit recheck. A transaction below the floor and above the max fee
  quotes the floor class.

### `POL-04`: Owner-computed sigop cost

- The gateway computes `total_sigop_cost` from resolved prevouts: legacy
  and P2SH redeem script counting, plus witness program counting. It
  enforces `MAX_STANDARD_TX_SIGOPS_COST` at 16_000 per transaction.
- Ingress callers cannot supply a sigop count. A caller-supplied value
  is ignored in favor of the owner's computation. A cost above 16_000 is
  a typed sigop rejection.

### `POL-05`: Replacement, cluster, and package policy

- Replacement follows the pinned Core 31.1 feerate-diagram profile. It
  is not the unversioned historical BIP125 profile. BIP125 rules 1 to 6
  keep their classes where they fire first under the pinned precedence.
- The pool models each cluster as a dependency DAG with revision-tagged
  membership and cached deterministic linearization chunks. Fee and size
  comparisons use widened checked integer cross products, never floating
  point. A traversal that exceeds its work cap aborts as a typed
  failure, never a silent oversize.
- Replacement is all or nothing. Victims and their descendants are
  computed before the commit. A rejected replacement leaves membership,
  sequences, and estimator state unchanged. Tie and resource-budget
  behavior follows the pinned observable rules. An independently more
  optimal diagram is not parity.
- Package submissions evaluate dependency-ordered rows with count bounds
  and package RBF conditions. `submitpackage` stays `Unimplemented` in
  the RPC registry and Esplora `/txs/package` stays 404 until separately
  approved.

### `POL-06`: Preview purity and finality

- Preview runs the commit pipeline path and stops before mutation. It
  changes no membership, no estimator state, no relay state, no
  admission sequence, and no victims. It returns verdict rows with the
  captured stamp; a stale stamp is visible to the caller. It may
  populate safe verification caches. Preview/commit identical-pipeline
  parity (including script verification in preview) is T18 work:
  no `AdmissionMode::Preview` exists and the RPC preview does not run
  `verify_transaction` (deviation ledger entries 1-2).
- Absolute locktime evaluates at tip height + 1 from retained coin
  metadata and MTP context. Relative (BIP68) sequence locks are
  enforced at the next block from confirmed `PrevoutMeta` rows, with
  pool and package parents encoded as the next block and the gate
  closed while `csv_active` is false; a disabled sequence contributes
  no lock. Coinbase spends under `COINBASE_MATURITY` (100) reject
  before mutation on the same seam.
- `testmempoolaccept` returns preview rows in the frozen Core 31.1
  `TestMempoolAccept` / `MempoolAcceptance` shape with frozen
  reject-reason strings.

## Proven by

- `crates/mempool/tests/admission.rs`: stale-context retry
  (`stale_policy_verdict_becomes_retryable`), sigop boundary enforcement
  (`p2sh_sigop_cost_exceeds_standard_limit`,
  `p2wsh_sigop_cost_exceeds_standard_limit`), and owner-computed cost
  overriding a caller-supplied count
  (`caller_sigop_cost_is_ignored_in_stored_entry`).
- `crates/mempool/tests/policy_contract.rs`: next-block BIP68 height
  (`bip68_height_lock_boundary_enforces_at_admission`), unconfirmed
  parent (`bip68_unconfirmed_parent_positive_relative_lock_fails`),
  time lock (`bip68_time_lock_uses_the_confirmed_median_time_past`),
  csv-inactive control (`bip68_check_is_inert_before_csv_activation`),
  and coinbase maturity boundary
  (`immature_coinbase_spend_rejects_before_100_confirmations`);
  `crates/rpc/tests/policy_contract.rs` quotes the same classes
  through both outlets
  (`immature_coinbase_spends_reject_on_both_rpcs_and_admit_at_maturity`,
  `bip68_locked_tx_admits_while_csv_is_inactive_on_the_rpc_surface`).
- `crates/mempool/tests/overhaul_finality_policy.rs` (planned): policy
  pins, epoch invalidation, CSV boundaries at `tip+1`, fee precedence,
  pressure floor rise, and decay behavior.
- `crates/mempool/tests/overhaul_cluster_graph.rs` (planned): cluster
  revisions, deterministic chunk ordering, and overflow-typed integer
  accounting.
- `crates/mempool/tests/overhaul_replacement_profile.rs` (planned):
  feerate-diagram accept and reject, all-or-nothing victims, tie rules,
  and TRUC v3 sibling constraints.
- Existing suites keep their verdicts:
  `crates/mempool/tests/policy_contract.rs`,
  `crates/mempool/tests/rbf_bip125.rs`,
  `crates/mempool/tests/ancestor_limits.rs`,
  `crates/rpc/tests/policy_contract.rs`,
  `crates/rpc/tests/transaction_methods.rs`.

## Vocabulary

[ReadStamp](../../CONCEPTS.md),
[MempoolGateway](../../CONCEPTS.md).
