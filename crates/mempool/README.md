# bitcoin-rs-mempool

The in-memory unconfirmed transaction pool: cluster and replacement policy,
package preview, TRUC and ephemeral dust, orphan parking, relay standardness,
and the history-based fee-rate estimator.

`Mempool` owns the entry arena plus the txid, funding (keyed by `ScriptHash`, the
single SHA256 of a script), spending, and fee-priority indexes; every accepted
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
Script-execution cache: the node shares one native-only, ephemeral
`ScriptExecutionCache` between the mempool gateway and block connect, keyed by
the exact `(wtxid, script-flag bits)` pair with take-once semantics. Admission
re-verifies a transaction under the next block's flags outside the pool write
lock; only a committed (accepted) mutation inserts the key, so rejected
admissions and failed packages never fill — peer, local, and package
submissions share this rule, and block connect consults it. A hit skips script
re-execution only; finality, amounts, BIP68 locks, and sigop limits always run,
and any flag divergence is a miss that re-verifies. No throughput claim is made
here.
## Contract ownership

Mempool behavioral contracts are defined in `docs/contracts/`:

- **Mutation gateway and ordering**: Gateway serialization, atomic `MutationResult` records, per-change sequence assignments, and generation-validated admission/retry follow [`docs/contracts/mempool-mutations.md`](../../docs/contracts/mempool-mutations.md) (`MPL-01`, `MPL-02`, `MPL-04`).
- **Relay standardness and policy**: Admission checks, limits, Core 31.1 replacement rules, and eviction ranking follow [`docs/contracts/mempool-policy.md`](../../docs/contracts/mempool-policy.md) (`POL-01`, `POL-05`).

Part of [`bitcoin-rs`](../../README.md); see [`CONCEPTS.md`](../../CONCEPTS.md) for the
project vocabulary.
