# Chainstate recovery

This page is an operator summary of the target recovery model in [contracts/recovery.md](contracts/recovery.md). It is not a second contract. `crates/chainstate` has not landed in the current workspace, so planned durable-root clauses are not implementation claims until their listed gates exist and pass.

## Current checkpoint implementation

`crates/node/src/checkpoint.rs` owns immutable checkpoint generations and the
`CURRENT` publication. Its `checkpoint/headers.rs` child owns the canonical
header codec: prefix and version, best/applied ancestry commitments, and
consensus-validated header reconstruction. Internal consumers name
`checkpoint::headers` directly; the former parent-level codec paths are removed.
The existing codec and publication regressions live in `checkpoint/tests.rs`.
This separation does not change checkpoint bytes, publication order, recovery
fallbacks, or the status of the planned durable-root model below.

## Current journal implementation

The optional checkpoint journal keeps its framed `head.json` codec and file-size
check in `crates/node/src/chainstate_journal/head.rs`; `segment.rs` owns the shared
filename grammar, and `error.rs` owns the shared typed failures. Writer startup
and replay use those owners directly. The former writer-level head paths and
`segment_name_pub` / `parse_segment_name_pub` forwarding wrappers are removed.

`writer.rs` remains the sole mutation and publication owner: storage flush,
segment sync, temporary-head write/sync, rename, then directory sync. Moving the
representation does not change those commit points, the existing JSON/CRC frame,
segment-name acceptance, checkpoint fallback, or operator data. Writer regressions
live in `writer/tests.rs`; head/segment representation controls live with their
owners. These controls are not a power-loss or durable-root acceptance claim.

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

`contracts/recovery.md` owns crash outcomes and proof locations. `CONSTRAINTS.md` owns gate status. Missing planned process-kill, lost-write, partial-write, reorg, or chainstate tests mean the corresponding target guarantee remains unproven.
