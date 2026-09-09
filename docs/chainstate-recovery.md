# Chainstate recovery

This page is an operator summary of the target recovery model in [contracts/recovery.md](contracts/recovery.md). It is not a second contract. `crates/chainstate` has not landed in the current workspace, so planned durable-root clauses are not implementation claims until their listed gates exist and pass.

## Target model

The authoritative state is one durable root containing full tip identity, a monotonic commit id, coin-state version, and committed body/undo extents. Coin updates and the new root commit atomically; body and undo bytes become durable before the root may reference them.

Connect and disconnect use the same order:

1. Reserve the chain transition and close mixed reads/admission.
2. Build forward and undo facts.
3. Append and sync required body/undo bytes.
4. Atomically persist coins, metadata, and the new durable root.
5. Reconcile mempool/projections, publish a stable generation, then notify best-effort consumers.

A failure before stable publication leaves recovery explicit. Ambiguous durable completion resolves to the prior or whole proposed root by commit identity; no mixed head/coin state is valid.

## Restart and reorg

Recovery trusts the durable root, not file length or a decodable append tail. Bytes beyond committed extents are orphan tails. Missing or corrupt committed ranges fail closed.

Reorgs disconnect tip-to-fork through exact per-block undo and ordinary durable transitions, then reconnect the winning branch through the normal apply path. Each committed ancestor is a valid restart point. Missing required undo or retained body data is an explicit recovery/replay condition, not an inferred success.

## Schema changes

Authoritative format changes increment `CURRENT_SCHEMA` and require a separately named fresh datadir. Incompatible operator data is neither converted nor deleted implicitly. Owner-local estimator, discovery, and index formats version and rebuild independently; see [policies/db-migration.md](policies/db-migration.md).

## Evidence

`contracts/recovery.md` owns crash outcomes and proof locations. Missing planned process-kill, lost-write, partial-write, reorg, or chainstate tests mean the corresponding target guarantee remains unproven.
