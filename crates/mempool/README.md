# bitcoin-rs-mempool

The in-memory unconfirmed transaction pool: cluster and replacement policy,
package preview, TRUC and ephemeral dust, orphan parking, relay standardness,
and the history-based fee-rate estimator.

`Mempool` owns the entry arena plus the txid, funding (keyed by `ScriptHash`, the
double-SHA256 of a script), spending, and fee-priority indexes; every accepted
transaction becomes a `MempoolEntry` addressed by its slab-index `EntryId`.
Production admission runs through `MempoolGateway::submit_transaction`, which
enforces the `MempoolLimits` (including min-relay fee) and returns
`SubmitError` on admission failure; `enforce_size_limit` delegates to
`evict_lowest_fee_packages` over the same dependency-closed chunks that mining and replacement consume;
`prioritise` adjusts an entry's effective fee, and `remove_for_block` /
`remove_for_reorg` handle chain-driven removal. The trusted-facts doors
`insert_entry`, `clear`, and `evict_below_fee_rate` remain as `test-seam`
fixture surfaces only. `MempoolStats` supplies the aggregate counters
behind `getmempoolinfo` and Esplora fee estimates. The `rbf` module plans
replacements, and `standardness` holds the relay policy. `ReplacementPlan` and its
oracle `check_replacement` exist only in test/test-seam builds; `ReplacementCandidate`
is their public input type. For
the transaction lifecycle ownership boundary, see
[ARCH-05](../../docs/contracts/architecture.md#arch-05-node-composition-and-orchestration-boundary).
`FeeEstimator` is fed by `tx_entered`, `tx_left`, and `block_connected`, and its
`estimate` answers a confirmation-target query with a `FeeRate` in sat/kvB, refusing
rather than fabricating when history is thin.
## Contract ownership

Mempool behavioral contracts are defined in `docs/contracts/`:

- **Mutation gateway and ordering**: Gateway serialization, atomic `MutationResult` records, per-change sequence assignments, and generation-validated admission/retry follow [`docs/contracts/mempool-mutations.md`](../../docs/contracts/mempool-mutations.md) (`MPL-01`, `MPL-02`, `MPL-04`).
- **Relay standardness and policy**: Admission checks, limits, Core 31.1 replacement rules, and eviction ranking follow [`docs/contracts/mempool-policy.md`](../../docs/contracts/mempool-policy.md) (`POL-01`, `POL-05`).

Part of [`bitcoin-rs`](../../README.md); see [`CONCEPTS.md`](../../CONCEPTS.md) for the
project vocabulary.
