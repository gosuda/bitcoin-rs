# Mempool policy contract (pointer)

The relay-policy contract lives in
[docs/policies/mempool-policy.md](../policies/mempool-policy.md). That
document is the owner: it pins Bitcoin Core 31.1, declares the policy
surface per check with Core's behavior alongside, and keeps a deviation
ledger. This page adds nothing normative; it places the policy under the
[contracts precedence rule](README.md).

## Clauses

### `POL-01`: Relay policy specification and Core 31.1 compatibility

- **Owner**: `docs/policies/mempool-policy.md` owns the mempool relay policy
  surface against Bitcoin Core 31.1. Consensus script and sighash validation
  are governed by consensus rules.
- **Scope**: admission checks in `crates/mempool/src/standardness.rs`,
  `policy.rs`, `pool.rs`, `rbf.rs`, `eviction.rs`, `accept.rs`, `gateway.rs`, and the RPC surface
  `sendrawtransaction` / `testmempoolaccept` in `crates/rpc/src/handlers/tx.rs`.
- Standardness rules, BIP125 RBF rules 1–6, ancestor/descendant package
  limits, cluster count/size limits, gateway policy script checks
  (`STANDARD_SCRIPT_VERIFY_FLAGS` at admission; not the `testmempoolaccept`
  preview evaluator), and eviction ranking follow the policy document.

## Proven by

- `crates/mempool/tests/policy_contract.rs` (`cargo test -p bitcoin-rs-mempool --test policy_contract`)
- `crates/rpc/tests/policy_contract.rs` (`cargo test -p bitcoin-rs-rpc --test policy_contract`)
- `crates/rpc/tests/transaction_methods.rs` (POL-01 duplicate submission: in-mempool idempotency and evicted resubmission)
- `crates/mempool/tests/rbf_bip125.rs` (BIP125 RBF rules 1–6)
- `crates/mempool/tests/ancestor_limits.rs` (ancestor and descendant limits)
- `crates/mempool` unit tests in `src/pool.rs` (cluster connectivity, count and
  size admission, post-eviction replacement projection, preview/admission
  agreement)
- `crates/mempool/src/gateway.rs` unit tests (policy script verification and finality at next block height)
