# bitcoin-rs-mempool

The in-memory unconfirmed transaction pool: admission with ancestor and descendant
policy checks, BIP125 replacement, package eviction, orphan parking, relay
standardness, and the history-based fee-rate estimator.

`Mempool` owns the entry arena plus the txid, funding (keyed by `ScriptHash`, the
double-SHA256 of a script), spending, and fee-priority indexes; every accepted
transaction becomes a `MempoolEntry` addressed by its slab-index `EntryId`.
`insert_entry` enforces the `MempoolLimits` (including min-relay fee) and reports
violations as `PolicyError` or `MempoolError`; `enforce_size_limit` delegates to
`evict_lowest_fee_packages` over the `ParetoFront` ancestor-aware priority ordering;
`prioritise` adjusts an entry's effective fee, and `evict_below_fee_rate` /
`remove_for_block` handle removal. `MempoolStats` supplies the aggregate counters
behind `getmempoolinfo` and Esplora fee estimates. The `rbf` module plans
replacements as a `ReplacementCandidate` and `ReplacementPlan`, `standardness` holds
admission policy, and `MempoolGateway` is the transaction admission entry point.
The cross-crate ownership boundary is defined by
[ARCH-05](../../docs/contracts/architecture.md#arch-05-node-composition-and-orchestration-boundary).
`FeeEstimator` is fed by `tx_entered`, `tx_left`, and `block_connected`, and its
`estimate` answers a confirmation-target query with a `FeeRate` in sat/kvB, refusing
rather than fabricating when history is thin.
## Contract ownership

Mempool behavioral contracts are defined in `docs/contracts/`:

- **Mutation gateway and ordering**: Gateway serialization, atomic `MutationResult` records, per-change sequence assignments, and generation-validated admission/retry follow [`docs/contracts/mempool-mutations.md`](../../docs/contracts/mempool-mutations.md) (`MPL-01`, `MPL-02`, `MPL-04`).
- **Relay standardness and policy**: Admission checks, limits, BIP125 RBF rules, and eviction ranking follow [`docs/contracts/mempool-policy.md`](../../docs/contracts/mempool-policy.md) (`POL-01`).

## Features
- `rocksdb`: forwarding marker for the rocksdb storage backend; gates no code in
  this crate.
- `fjall`: forwarding marker for the fjall storage backend; gates no code in this
  crate.
- `redb`: forwarding marker for the redb storage backend; gates no code in this
  crate.

Part of [`bitcoin-rs`](../../README.md); see [`CONCEPTS.md`](../../CONCEPTS.md) for the
project vocabulary.
