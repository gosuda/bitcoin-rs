# Mempool

`MempoolGateway` owns every admission path. `submit_local_transaction` serves `sendrawtransaction` and `Node::broadcast`; `submit_peer_package` serves peer relay; package submission has its own atomic entry under the same owner (`POL-02`, [mempool policy contract](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/mempool-policy.md#pol-02-one-admission-owner-and-admission-mode)).

The pool lives in [`crates/mempool`](https://github.com/gosuda/bitcoin-rs/tree/main/crates/mempool). Node wires it to RPC, P2P, mining, and chain effects; it keeps no second admission store.

```text
sendrawtransaction / Node::broadcast / peer relay
                      |
                      v
              MempoolGateway
                      |
       prepare against one chain generation
                      |
   standardness -> sigops -> finality -> fee floor
                      |
              script verification
                      |
        cluster and replacement limits
                      |
          commit + sequence + relay
```

## Admission

A transaction is prepared against a captured chain generation and the current policy settings. Any change to either makes the result retryable rather than silently admitted (`POL-03`). The gateway computes the BIP141 sigop cost itself from copied resolved outputs; a caller-supplied count never reaches an entry (`POL-04`).

The check order is:

1. Standardness: transaction version, input and witness standardness, TRUC, ephemeral dust.
2. Sigops: BIP141 cost with a 16,000 limit; policy weight is the larger of wire weight and sigops times 20.
3. Finality: locktime against the next block, BIP68 relative locks, coinbase depth 100.
4. Fee floor: minimum relay fee on the modified fee, then the rolling minimum.
5. Script verification with a native execution cache keyed by wtxid and flags.
6. Maximum fee: the base fee is compared with the integer charge at the caller's rate. A zero charge disables the guard.
7. Cluster and replacement limits.
8. Commit, sequence assignment, and publication.

The default minimum relay is 1000 sat/kvB. The rolling minimum rises when the pool is above its memory limit and decays with a 12 hour half-life. `sendrawtransaction` and `Node::broadcast` cap the fee rate at 10,000,000 sat/kvB, which is Core's 0.1 BTC/kvB default.

Admission returns a typed outcome. `AlreadyKnown` is an empty result, `AlreadyConfirmed` or `Held` is a policy rejection for missing inputs, and a committed transaction returns the mutation result with its sequence.

## Packages

`submitpackage` and `Node::broadcast_package` accept a bounded child-with-independent-parents CPFP package. Each transaction is tried alone first; rows that fail only on minimum relay or missing inputs are retried atomically as a package. At least two such rows are required, and any other failure makes the batch non-atomic.

Limits are 25 transactions and 404,000 weight units per package, with 400,000 as the per-transaction weight cap. Package rows are checked against resident wtxids so a witness change cannot slip through.

Package RBF is not implemented. A multi-transaction replacement refuses with `bip125-replacement-disallowed`, and package prechecks imply no replacement or capacity eviction. The policy matrix keeps that difference visible.

## Replacement and chunk ordering

Replacement does not depend on BIP125 signaling, and the old new-unconfirmed-input rule does not gate it (`POL-05`). A candidate must:

- conflict with at most 100 distinct clusters;
- pay an absolute fee covering the sum of the victims' modified fees;
- pay an incremental relay fee of at least 1000 sat/kvB;
- pass the fee diagram check: the affected clusters' after-diagram must be strictly greater than the before-diagram, compared as checked rationals.

Failure returns a typed error such as `insufficient fee`, `replacement-failed`, or `too many potential replacements`. Sibling-eviction cases carry a suffix.

Ordering uses cluster linearization. `fee_diagram::linearize` repeatedly finds the highest-feerate dependency-closed set among the remaining transactions, emits the minimal closed set at that rate, and removes its members. The graph linearization is exact-optimal and does not emulate Core's bounded history-dependent SFL or transient tie decisions. A cluster is at most 64 transactions and 101,000 virtual bytes.

Mining walks chunks in descending order and stops at the first chunk below 1 sat/kvB; the template tail is filled in prefix order. `shared_parent_requires_a_joint_chunk` pins the rule that a shared parent cannot be split across chunks.

## Eviction and memory

The pool is limited by dynamic memory, not virtual size. The default cap is 300,000,000 bytes. When usage exceeds the cap, eviction removes the lowest-feerate chunk and raises the rolling floor at the removed chunk's rate plus the incremental relay fee.

Block effects run through the same gateway:

- On connect, `remove_for_block` evicts confirmed transactions and their descendants that are now invalid, and records the block with the fee estimator.
- On disconnect, `reconsider_disconnected` re-admits disconnected non-coinbase transactions under a chain-change fence, withholding descendants of a refused parent. It caps collected bytes at 20,000,000 and uses `AdmissionOrigin::Reorg`, so re-admission does not feed the fee estimator.
- Expiry removes entries older than 336 hours. Re-admitted entries never expire by that timer.

Restart persistence is opt-in and clean-shutdown only. `persist_mempool` defaults to true, and the snapshot is capped at 64 MiB with a 14 day maximum age. A snapshot stores candidate transactions and operator fee deltas only; it does not store the cluster graph, computed fees, policy stamps, sequences, orphans, or relay state. Restored transactions do not register estimator samples and do not trigger blanket relay.

## Fee estimation

The estimator keeps per-target fee-rate estimates with a maximum of 1,000,000 sat/kvB, targets clamped to 25 blocks, a 0.85 success threshold, and a 0.998 decay factor. `estimate_fee_rate` returns `None` when the target is zero or history is insufficient.

History persists to `fee-estimator-history.dat` on every teardown, including startup-abort teardown. The file has a 64 MiB bound. `estimatesmartfee` reads the same estimator the node exposes through `Node::fee_estimate`.

## Worked trace

A clean regtest start and stop shows the persistence side of the pool. The binary emits one JSON object per line; fields are shown as `key=value` with the timestamp and unchanged fields removed.

```text
INFO bitcoin_rs_node::state::open no mempool snapshot; starting with an empty pool status=missing
INFO bitcoin_rs_mempool::snapshot prepared mempool snapshot transactions=0 bytes=84 elapsed_ms=0
INFO bitcoin_rs_mempool::fee_history saved fee-estimator history path=/tmp/book_embedhow_daemon2/fee-estimator-history.dat bytes=57965
```

The snapshot line appears only for a clean shutdown with no prior teardown error. An empty pool still writes an 84-byte snapshot.

## Contract clauses

| Clause | Rule |
| --- | --- |
| `POL-01` | Policy pinned to Core 31.1 through a versioned admission policy |
| `POL-02` | One admission owner for RPC, embedded, Esplora, and peer submission |
| `POL-03` | Admission preparation captures chain generation and settings; mismatch is retryable |
| `POL-04` | The gateway computes sigop cost; caller counts never reach entries |
| `POL-05` | Replacement, cluster, and package policy; signaling does not gate replacement |
| `POL-06` | Preview changes no membership, estimator, fee overlay, relay, sequence, or victims |
| `POL-07` | Every input is resolved and checked with Core input and witness standardness |

The mutation side is owned by [docs/contracts/mempool-mutations.md](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/mempool-mutations.md): one gateway ordering (`MPL-01`), atomic records and sequences (`MPL-02`), ZMQ payload mapping (`MPL-03`), and generation-validated admission and chain-change fencing (`MPL-04`).

## Tests that pin the pool

| Invariant | Test | File |
| --- | --- | --- |
| A confirmed parent leaves an unmined child and publishes only the parent | `remove_for_block_leaves_unmined_child_and_publishes_only_the_parent` | [`crates/mempool/src/gateway/tests.rs`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/mempool/src/gateway/tests.rs) |
| A native package aggregates CPFP atomically and ignores input order | `native_package_aggregates_cpfp_atomically_and_ignores_input_order` | [`crates/mempool/src/package/tests.rs`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/mempool/src/package/tests.rs) |
| Reorg re-admission admits parent then child under the fence | `reconsider_disconnected_admits_parent_then_child_under_the_guard` | [`crates/mempool/src/admission/tests.rs`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/mempool/src/admission/tests.rs) |
| A shared parent forms one joint chunk | `shared_parent_requires_a_joint_chunk` | [`crates/mempool/src/fee_diagram/tests.rs`](https://github.com/gosuda/bitcoin-rs/blob/main/crates/mempool/src/fee_diagram/tests.rs) |

The operator-facing policy differences are in [docs/policies/mempool-policy.md](https://github.com/gosuda/bitcoin-rs/blob/main/docs/policies/mempool-policy.md). The [architecture](architecture.md) chapter shows when block effects reach the pool, the [p2p](p2p.md) chapter covers relay after admission, and the [indexes](index.md) chapter covers the confirmed rows that replace evicted entries.
