# Mempool policy contract

The current implementation is described in the
[policy compatibility ledger](../policies/mempool-policy.md). This page separates
implemented admission fences from the proposed unified policy owner. A target
clause or planned test is not proof of Core 31.1 policy parity.

### `POL-01`: Versioned admission policy (target)

One immutable policy profile should own admission limits and a policy epoch.
Today policy is assembled from pool limits and caller context; the complete
versioned `AdmissionPolicy`/`ReadStamp` design is not implemented. Concrete
current defaults belong to `MempoolLimits` and `StandardnessPolicy`, not a second
copy of constants on this page.

### `POL-02`: One admission owner and mode (partial)

`MempoolGateway::admit_transaction` owns verified commit admission. RPC preview
still uses the separate package-acceptance evaluator. There is no shared
`AdmissionMode::{Preview, Commit}` pipeline. Esplora broadcast currently calls
RPC `sendrawtransaction` and therefore uses its origin and fee limits.

The target is one pipeline for every ingress, explicit origin-specific limits,
and preview that stops before mutation. Do not claim this wiring is complete.

### `POL-03`: Stale admission evidence must not commit (implemented fence)

Script verification runs outside the pool writer. After every provisional
verdict, including a policy or script rejection, admission acquires the writer
and rechecks chain generation and mempool sequence before using that verdict.
A stale context returns its typed retryable error instead of an obsolete result.
`gateway.rs::rejected_verdicts_are_rechecked_after_verification` exercises both
rejection classes against both concurrent changes.

Complete coin metadata, policy epochs, one-pass owner input resolution, and one
shared cross-ingress retry policy remain targets. Current callers still prepare
admission context. This narrower fence does not establish full policy parity.

### `POL-04`: Owner-computed sigop cost (target)

Today `PolicyContext.total_sigop_cost` can be supplied by a caller; omitted
prevout-dependent cost is not an owner-computed total. The target owner must
compute legacy, P2SH, and witness cost from resolved inputs and enforce the
standard transaction limit. Boundary tests must cover missing and false caller
counts; no such guarantee is claimed for the current ingress paths.

### `POL-05`: Replacement, cluster, and package policy (partial)

Current replacement uses `rbf.rs`'s BIP125 checks and existing cluster limits.
The Core 31.1 feerate-diagram replacement profile and TRUC v3 topology rules are
not implemented. Version 3 remains non-standard. `submitpackage` remains
unimplemented. Preserve all-or-nothing replacement and test each future policy
change against the pinned product reference rather than treating existing BIP125
fixtures as proof of the new profile.

### `POL-06`: Preview purity and finality (partial)

Preview is non-mutating but is not the commit verifier: it does not establish
script validity. Absolute finality is checked at the next block height. Full
coinbase-maturity and BIP68 height/time sequence-lock policy are not implemented
by this admission path. Those need retained coin metadata, explicit typed
failures, and common preview/commit fixtures before promotion to implemented.

## Existing evidence

`gateway.rs` unit tests, `crates/mempool/tests/policy_contract.rs`,
`rbf_bip125.rs`, `ancestor_limits.rs`, and the RPC policy/transaction tests cover
their named existing behaviors. Planned `overhaul_admission_owner`,
`overhaul_finality_policy`, and `overhaul_replacement_profile` campaigns do not
supply evidence until implemented and run.
