# Mempool policy contracts

The mempool owner implements the selected Core 31.1 replacement and preview
profile. [The policy matrix](../policies/mempool-policy.md) records behavior,
reference evidence and intentional unsupported cases. Compatibility claims are
owned by REGISTRY in `crates/rpc/src/registry.rs`; admission rows carry
their deviation notes there.

## Clauses

### `POL-01`: Core 31.1 policy pin and versioned `AdmissionPolicy`

- Core source and binary identities are pinned by the reference-set manifest.
  Tests use the selected rates explicitly: minimum and incremental relay
  1,000 sat/kvB, dust 3,000 sat/kvB and nulldata budget 83 bytes. Core 31.1
  defaults to 100 sat/kvB for both relay rates; these selected settings are
  not a claim about upstream defaults.
- Implemented owners are `MempoolLimits` and `MempoolPolicySnapshot`.
  Cluster count is 64, cluster weight is at most 404,000, and at most
  100 distinct direct-conflict clusters participate in a replacement.
  `MAX_PACKAGE_COUNT` is 25. Raw trusted insertion may supply a policy vsize;
  production admission derives sigop-adjusted weight and size.
- A dedicated resolved/versioned `AdmissionPolicy` startup object remains a
  target design. The current preparation stamp copies the actual enforced
  settings and rechecks them; no new configuration or persistence authority
  is introduced by the replacement implementation.

### `POL-02`: One admission owner and admission mode

- `MempoolGateway` owns RPC and peer submission, preview, reorg reconsideration,
  typed policy verdicts and publication. RPC/P2P do not repeat replacement rules.
- Single preview follows the same preparation, graph and script verification
  as a single commit, stopping before mutation. Multi-transaction preview uses
  Core's `PackageTestAccept` semantics: replacement and fee aggregation are
  disabled. Unsupported aggregate package submission is explicit in the
  manifest, not a hidden fallback to separate successful submissions.
- Chain reads, script execution and fee-diagram solving run outside write locks.
  Callbacks run after pool/lifecycle locks are released.

### `POL-03`: Admission pipeline, stamp, and precedence

- Preparation captures chain generation, membership sequence, enforced settings
  and the owner's private fee-delta sequence. Any mismatch makes the result
  retryable. Four attempts bound the shared producer; exhaustion is typed.
- Fee-only prioritisation changes do not advance the public mempool sequence,
  but invalidate prepared graphs and contextual rejection-cache entries.
- Standardness, available inputs, sigop limits, modified fee floors, next-block
  finality and graph policy precede scripts. The caller maximum fee guard runs
  only after successful admission verification, comparing the base fee to
  `CFeeRate::GetFee(vsize)` rather than a rounded rate quote. An invalid transaction cannot
  select a more convenient maximum-fee error.
- A verified plan carries prepared insertion and ordered removals. The writer
  rechecks its stamp before any mutation. Capacity refusal, stale preparation
  or a rejected replacement changes no pool membership, fee overlay, estimator
  input or observer sequence. Successful mutations use the ordered gateway
  publication seam in [MPL-01](mempool-mutations.md#mpl-01-single-mutation-gateway-ordering-invariant).

### `POL-04`: Owner-computed sigop cost

- The gateway computes BIP141 sigop cost against copied resolved outputs.
  Caller-provided sigop counts do not reach stored entries. More than 16,000
  is a typed rejection.
- Exact policy weight is `max(wire_weight, sigop_cost * 20)`. Virtual size is
  the ceiling of that weight divided by four. Cluster sums and fee diagrams
  retain weight precision rather than summing rounded virtual sizes.
- Confirmed inputs, admitted parents and earlier package outputs feed the same
  accounting owner. Missing input facts are preserved.

### `POL-05`: Replacement, cluster, and package policy

- Signaling and the old new-unconfirmed-input restriction do not gate replacement.
  At most 100 distinct direct-conflict clusters are considered. Victims include
  every descendant, and the candidate must not spend an evicted dependency.
- Modified fees retain the existing signed i128 representation of a u64 base
  fee plus i64 prioritisation. Large legal priority overlays cannot disable
  template construction, and only actual fees contribute to the coinbase.
  Modified fees, including priority deltas, cover all victims plus the integer
  incremental relay charge. Exact checked arithmetic rejects an unrepresentable
  fee/weight. Equality or crossing of complete affected fee diagrams rejects;
  surviving relatives and newly joined clusters participate in the comparison.
- Existing entries and their dependency links are the graph authority. An
  immutable projection supplies exact maximum-rate dependency closures to
  replacement, mining and eviction. No mutable alternate graph or persistent
  chunk representation is added. Solver work is bounded by the captured node
  and edge counts; each cluster follows its configured count/weight bounds.
- Mining treats every derived fee chunk as indivisible. If its finality,
  weight, serialized-size or sigop check fails, all members are skipped and
  dependent later chunks remain unavailable. The configured candidate limits
  are inclusive. Invalid or cyclic snapshot references produce typed owner
  errors, never a fabricated order. Core 31.1 `node/miner.cpp::addChunks`
  supplies the independent reference for whole-chunk skipping; local configured
  limits and BIP68 checks follow this contract and POL-06.
- Core's bounded, history-dependent SFL work behavior is intentionally not
  emulated. The exact solver and its independently checked arithmetic do not
  prove Core parity in non-optimal transient states. This difference remains
  in the compatibility manifest and prevents a whole-surface `supported` claim.
- Combined package previews enforce count/weight, txid uniqueness, dependency
  order, internal consistency and projected cluster bounds. First precheck
  failure leaves other rows unfinished. Script failures preserve only earlier
  script-success rows. `submitpackage` stays `Unimplemented` and Esplora
  `/txs/package` stays 404; aggregate CPFP/package RBF is unsupported.
- TRUC requires matching unconfirmed versions, at most one ancestor/descendant,
  10,000 adjusted vB for a root and 1,000 for a child. An eligible sole sibling
  joins single-transaction RBF and remains subject to its fees and diagrams.
  Multi-transaction preview forbids sibling eviction.
- At most one ephemeral dust output is standard, and both actual and modified
  fees must be zero. Any child of that unconfirmed transaction must spend its
  dust. The selected positive relay floor cannot admit such a parent alone.

### `POL-06`: Preview purity and finality

- Preview changes no membership, estimator state, fee overlay, relay state,
  admission sequence or victims. It may populate safe verification caches.
- Absolute locktime evaluates at tip+1. BIP68 evaluates confirmed height/MTP
  metadata and treats unconfirmed parents as the next block. The CSV gate
  controls these relative locks. Coinbase spends require depth at least 100.
- Completed preview rows use the pinned v31 response type. Unfinished package
  rows contain identities and optional package error, with no fabricated
  `allowed` value or fee. Generic script-detail and numeric-error differences
  are listed in the manifest.

## Proven by

- `overhaul_process_harness::replacement_signaling_matches_pinned_core` and
  `policy_cases`: isolated Core/candidate processes, identical funding blocks,
  real signatures, nonsignaling replacement, insufficient fees, graph merge/split,
  100/101 conflicting clusters, 64/65 connected members, 1 sat incremental
  boundaries, prioritisation, TRUC siblings/sizes and package verdict shapes.
- `crates/mempool/src/fee_diagram/tests.rs`: pinned Core comparison vectors,
  independent exhaustive small-DAG oracle and maximal 64-node topology.
- `crates/mempool/tests/replacement_profile.rs`, `graph_limits.rs`,
  `policy_contract.rs` and `admission.rs`: exact graph/TRUC bounds, atomic
  failures, fee arithmetic, next-block finality and sigops.
- `crates/mempool/src/package/tests.rs`: 25/26 and 404,000/404,001 package
  boundaries, reference-checked weight, TRUC/cluster projections, zero-floor
  ephemeral spending and fee-only invalidation.
- Gateway tests: publication order under concurrency/reentrancy, stale verdicts
  and rejected replacement preservation of estimator history and fee overlays.
- Mining/RPC suites: shared chunks, block resource limits, witness commitment
  oracle, both-RPC verdicts and manifest projection consistency.

Performance, Core transient SFL/churn behavior and the project-wide formal
model matrix remain unmeasured. Correctness tests do not promote defaults.

## Vocabulary

[ReadStamp](../../CONCEPTS.md),
[MempoolGateway](../../CONCEPTS.md).
