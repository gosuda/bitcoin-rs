# The pool ledger

The ledger is the pool's only financial memory. A share earns credit once, a round pays exactly the coinbase value the chain shows, and a payout batch holds a reservation until the chain confirms it or the operator cancels it with a stated basis. Every one of those facts is written by one `Ledger` method as one store transaction.

The runtime that drives the ledger, including the Stratum listeners and the external signer, is described in [mining and the native pool](../use/mining-and-pool.md). Financial rules are owned by [docs/contracts/pool.md](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/pool.md) (`POOL-01` to `POOL-09`).

The HEAD build used for this book was compiled without the `pool` feature, so no pool run appears here. The evidence is the node pool-ledger tests in `crates/node/tests/pool_ledger.rs` with `--features pool,test-seam`, run against this tree. Two of them appear in the worked trace.

## What the ledger stores

`crates/node/src/pool/ledger` keeps 17 data tables plus two metadata tables under a schema version of 1 (`crates/node/src/pool/ledger/store.rs:42`):

| Purpose | Tables |
| :--- | :--- |
| Shares | `pplns_shares_v1`, `pplns_share_hashes_v1`, `pplns_share_tuples_v1`, `pplns_retired_hashes_v1`, `pplns_retired_jobs_v1` |
| Rounds | `pplns_rounds_v1`, `pplns_round_by_block_v1`, `pplns_round_weights_v1`, `pplns_round_allocs_v1`, `pplns_open_rounds_v1` |
| Accounts | `pplns_balances_v1`, `pplns_scripts_v1` |
| Payouts | `pplns_batches_v1`, `pplns_active_batches_v1`, `pplns_batch_idem_v1`, `pplns_batch_txids_v1` |
| Audit | `pplns_audit_v1` |

The pool config is immutable. `Ledger::create` refuses a non-empty namespace with `PathExists`; `Ledger::open` refuses a stored config that differs from the running one with `ConfigMismatch` and a missing schema with `NotALedger` (`store.rs:192`, `:214`). A policy change cannot reinterpret history; the operator must start a new ledger directory.

Startup allocates a run epoch the first time a ledger handle opens (`allocate_run_epoch`, `store.rs`). The node adapter combines it with the protocol job id:

```rust
job: (u64::from(run_epoch) << 32) | u64::from(share.job.get()),
```

(`crates/node/src/pool/ledger.rs:790`). A restarted pool reuses protocol job numbering, so the epoch is what keeps the ledger's job identity unique across restarts (`POOL-02`).

## Share identity and idempotency

A `ShareCredit` carries the header hash, the job, the account, the extranonce, the nonce, the header version, the header time, and the work (`crates/serving/src/mining/pool/ledger.rs`). Two keys decide what happens on a write:

- `header_hash` is the idempotency key. The same hash with the same work and the same tuple returns `ShareReceipt::Duplicate { seq }` and writes nothing.
- `tuple_key()` is the identity key: `job BE || account BE || nonce BE || version BE || ntime BE || extranonce` (`ledger.rs`). The same tuple under a different header hash is `ShareIdentityConflict`.

`credit_share` checks retired jobs first, then the header-hash index, then the retired-hash tombstone table, then the tuple index (`store.rs`). Five outcomes are possible:

| Situation | Result |
| :--- | :--- |
| job is retired | `JobRetired(job)` |
| same hash, same work, same tuple | `Duplicate { seq }` |
| same hash, different work or tuple | `ShareConflict { seq }` |
| same tuple, different hash | `ShareIdentityConflict { seq }` |
| new hash and new tuple | `Credited { seq }`, indexes updated |

`ShareConflict` and `JobRetired` are permanent: the node adapter maps them to `RecordOutcome::Rejected`, not a retry (`crates/node/src/pool/ledger.rs`). A version roll and an ntime roll produce different hashes and are credited separately; `version_and_ntime_rolls_are_distinct_shares_not_conflicts` pins that.

`retire_job` removes the job's tuples from the live index and moves its hashes into `pplns_retired_hashes_v1` as tombstones (`store.rs:331`). The work already credited stays in the PPLNS window. Only new records for that job are refused.

## Rounds and observations

A found block creates a `Round` in state `Pending` with the solving share sequence and a frozen PPLNS window (`record_found_block`, `store.rs:497`). The window is work-weighted: `collect_window` walks shares backward from the solving sequence until the accumulated work reaches `window_work` (`store.rs`). A solving share older than the pruned boundary returns `WindowPruned`; the ledger refuses rather than paying from a truncated window.

Round state has four values (`ledger.rs`):

```text
Pending --canonical coinbase observed--> Immature --maturity--> Matured
   |                                         |
   +--------------- displaced ---------------+--> Orphaned --revived--> Immature
```

`reconcile_rounds_checked` observes every open round by exact block hash, not by height (`store.rs:650`). The chain view answers `Canonical { height }`, `Side`, or `Unknown`, and a height match is required for `Canonical`. A displaced matured round is orphaned and its allocations reversed; a round that returns is revived. `a_claim_the_chain_contradicts_is_surfaced_and_never_applied` covers a contradiction between the recorded coinbase and the chain.

Reward fixing happens on the first canonical observation with a coinbase (`fix_reward`, `store.rs`):

1. The observed coinbase txid must equal the recorded txid.
2. The observed outputs must sum to the claimed value, and no sum may exceed `MAX_MONEY_SAT`.
3. The pool's share is the sum of outputs paying the configured reward script.
4. `split_pool_fee` floors the basis-point fee; `split_reward` divides the net by work, floors each share, and distributes the integer residual by descending remainder, then ascending account id (`ledger.rs`).
5. Allocations are stored per account under the round.

Maturity uses `tip_height - block_height + 1` confirmations. Crediting happens once at maturity; `reverse_round_credits` consumes available balance first and records the shortfall as `deficit_sat` (`store.rs`). A later credit clears deficit before adding available funds (`credit_round_allocations`, `store.rs`). The invariant is:

```text
available + reserved + paid - deficit = credited matured allocations
```

per account. `check_invariants` recomputes it from tables (`store.rs:1343`). The node does not call it at startup; it is a test and operator verification path, so a corrupt ledger is found by the audit chain or by tests, not by a boot check.

After the configured `reorg_watch_depth` without a canonical observation, an open round is marked `Orphaned` and removed from the open set (`apply_round_observation`, `store.rs`). `unseen_rounds_stop_being_monitored_after_the_watch_depth` pins that boundary.

## Payout batches

A batch moves through six states (`ledger.rs`):

```text
Prepared -> ExternallySigned -> Broadcast -> Confirmed
    |              |
    +--> Cancelled +--> Failed
```

`holds_reservation()` is true for `Prepared`, `ExternallySigned`, and `Broadcast`. Only those states can export a request or accept a receipt.

### Prepare

`prepare_payout_batch(idempotency_key, policy)` returns the existing batch when the key is known, otherwise selects balances at or above `min_payout_sat`, reserves them, and creates a batch whose id `compute_batch_id` derives from the domain string `btcrs.pool.payout-batch.v1`, the key, and the selected outputs (`store.rs:869`, `ledger.rs`). Selection stops at `MAX_PAYOUT_OUTPUT_WEIGHT_WU` (390,000 WU) and at `max_outputs`, so the resulting transaction stays under the 400,000 WU standard limit. The policy floor is at least the configured dust limit, and `max_outputs` is 1 through 2,500.

`preparing_a_batch_reserves_balances_atomically_and_never_double_allocates` pins that the same key returns the same batch and that balances cannot be reserved twice.

### Sign

`request_for` exports the exact outputs plus the authorized change scripts as a `BRPR` v1 request. `record_signed` accepts a `BRPT` v1 receipt and checks, in order (`store.rs:973`):

- the raw transaction parses and its recomputed txid equals the receipt txid;
- the batch exists and still holds its reservation;
- the batch holds fewer than `MAX_SIGNED_TXS_PER_BATCH` (32) signed transactions;
- the txid is not already used by another batch;
- the payout output multiset matches exactly, with at most one extra change output paying an authorized script;
- the new inputs conflict with every earlier signed transaction of the same batch, which prevents a double spend inside the batch.

A receipt never broadcasts. `record_broadcast` requires that the chain already observes the txid; an unknown txid returns `NotObserved` (`store.rs:1043`).

### Observe

`reconcile_payouts_checked` reads active batches in pages of 16 (`RECONCILE_PAYOUT_BATCH_LIMIT`), observes each signed txid through the chain view, and decides (`store.rs:1165`):

- confirmed on the canonical chain at the payout depth: `Confirmed`, reservation settles to paid;
- confirmed then orphaned: revert to `ExternallySigned`, restore the reservation;
- every signed transaction conclusively double-spent at the abandon depth: `Failed`, reservation released;
- some transactions still possible: no decision.

`a_batch_fails_only_when_every_signed_transaction_is_conclusively_double_spent` and `an_aborted_reconcile_defers_a_permanent_fail` pin the asymmetry: a missing or inconclusive observation is never treated as nonpayment.

`cancel_prepared` accepts only `Prepared` and only with an explicit `NeverHandedToSigner` or `SignerRevoked` basis; it releases the reservation and removes the batch from the active set (`store.rs:1113`). A failure, timeout, or rejection by the signer does not release anything by itself.

## Durability

Each public mutation runs `begin_write`, mutates one or more tables, calls `append_audit`, and commits once through `Ledger::commit` (`store.rs:309`). A commit either applies the whole operation or none of it. Idempotent replays are handled before the write transaction opens, so a retried `record_share` or `prepare_payout_batch` returns the first result without a second transaction.

The audit table is a hash chain. `append_audit` hashes `"btcrs.pool.audit.v1" || previous || seq BE || body` and stores the chain value in `audit_head` in the same transaction (`store.rs`). `verify_audit_chain` walks the table and returns the record count (`store.rs:1334`). Tests cover interrupted commits and lost replies with the `test-seam` fail plan:

| Fault | Expected result | Test |
| :--- | :--- | :--- |
| fail before commit | whole operation lost, retry succeeds | `an_interrupted_commit_loses_the_whole_operation_and_the_retry_succeeds` |
| fail after commit | operation durable, replay changes nothing | `a_commit_whose_reply_was_lost_is_durable_and_the_replay_changes_nothing` |
| restart | balances, audit, and sequence continue byte for byte | `state_survives_a_restart_byte_for_byte` |
| tampering | audit chain detects it | `the_audit_chain_is_deterministic_and_detects_tampering` |

All four live in `crates/node/tests/support/pool_ledger_cases.rs`, which is compiled once per backend; the current suite runs it against RocksDB (`crates/node/tests/pool_ledger.rs`).

## Retirement after an applied block

`POOL-05` makes job retirement synchronous with block acceptance, not with the pending-share count.

`PoolCore::submit_block_to_node` calls the node mining control. On `BlockStatus::Applied` it immediately calls `self.invalidate_active()` before returning the receipt (`crates/serving/src/mining/pool/core.rs:454`). `invalidate_active` marks every active job `Stale(Invalidated)`, clears the published job, and returns the invalidated ids (`core.rs:383`, `crates/serving/src/mining/pool/job.rs`).

Two consequences follow:

- A job id that falls below the retained front is reported as `Stale { reason: Retired }` by `JobBook::locate` (`job.rs`).
- `validate` checks the `seen` set before the stale check for a replayed header, so a byte-identical replay keeps duplicate identity: `Stale` for new work on the job, `Duplicate` for the exact share already accepted (`job.rs`).

The wire mapping is fixed. SV1 uses code 21 `"Stale share"` and code 22 `"Duplicate share"` (`crates/serving/src/mining/pool/stratum/sv1.rs`). SV2 answers `stale-share` and `duplicate-share`; `applied_sv2_block_retires_the_common_job_before_a_sibling_reaches_the_node` asserts `stale-share` on sequence 2 after an Applied block and `duplicate-share` for the replay.

On the ledger side, the retired job's later records are refused with `JobRetired(job)` and its header hashes stay reserved as tombstones, so a cross-job replay is `ShareConflict`, not a new credit (`a_retired_header_hash_is_never_credited_again`).

## Worked trace: the tests that pin retirement

Both commands ran in this tree with the pool and test-seam features. The HEAD binary cannot run the pool, so these tests are the end-to-end evidence for the retirement path.

```sh
$ env -u CARGO_BUILD_BUILD_DIR RUSTC_WRAPPER= \
    cargo test --offline --locked -p bitcoin-rs-node \
    --features pool,test-seam --test pool_ledger \
    rocksdb::retiring_a_job_bounds -- --nocapture

running 1 test
test rocksdb::retiring_a_job_bounds_the_index_and_refuses_late_shares ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 143 filtered out; finished in 0.01s
```

That test records a share on job 7 and one on job 8, retires job 7, asserts the retired hash is still queryable as a tombstone, asserts a new record on job 7 returns `JobRetired(7)`, asserts the retired work stays in the window, and asserts job 8 still credits.

```sh
$ env -u CARGO_BUILD_BUILD_DIR RUSTC_WRAPPER= \
    cargo test --offline --locked -p bitcoin-rs-serving \
    --features pool,test-seam --test suite \
    pool_sv1::applied_block_retires_job -- --nocapture

running 1 test
test pool_sv1::applied_block_retires_job_and_second_submit_is_stale ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 103 filtered out; finished in 0.01s
```

That test submits one winning nonce over a real SV1 connection, asserts the job was retired, submits a second winning nonce on the same job and gets `"error":[21,"Stale share"`, asserts the node saw exactly one block submission, then installs a new-parent job and gets a fresh acceptance.

## Failure modes

| Error | Meaning | Retry? |
| :--- | :--- | :--- |
| `PathExists` | `create` found a non-empty namespace | no, open it instead |
| `NotALedger` | schema or revision missing | no |
| `ConfigMismatch` | stored policy differs from the running policy | no |
| `WindowPruned` | solving share is older than the retained window | no |
| `JobRetired(job)` | work arrived for a retired job | no |
| `ShareConflict { seq }` | same header hash, different work or tuple | no |
| `ShareIdentityConflict { seq }` | same tuple, different header hash | no |
| `BlockConflict` | a second claim for the same block disagrees on height, txid, or value | no |
| `IllegalTransition` | action not allowed from the batch state | no |
| `NotObserved(txid)` | broadcast recorded before the chain sees the txid | retry after observation |
| `ReceiptError::TxidMismatch` | raw transaction does not hash to the receipt txid | no |
| `ReceiptError::NotConflicting` | replacement does not conflict with an earlier signed tx | no |
| `LedgerUnavailable` | storage or an unexpected error in the node adapter | yes, the node retries |

`LedgerUnavailable` is the node adapter's only retry class (`crates/node/src/pool/ledger.rs`). The core keeps failed records in its bounded outbox rather than answering success, which is why a queued write is not a committed share.

## Where the invariants are proven

| Clause | Rule |
| :--- | :--- |
| [`POOL-02`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/pool.md#pool-02-schema-consent-storage-and-immutable-policy) | schema consent, storage boundary, immutable policy, run epoch |
| [`POOL-03`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/pool.md#pool-03-shared-admission-and-bounded-deferred-work) | shared admission and bounded outbox |
| [`POOL-05`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/pool.md#pool-05-one-mining-owner-and-acknowledgement-boundaries) | one mining owner, synchronous retirement, stale and duplicate identity |
| [`POOL-06`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/pool.md#pool-06-pplns-reward-and-maturity) | PPLNS window, reward fixing, maturity |
| [`POOL-07`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/pool.md#pool-07-hash-keyed-reorg-reconciliation-and-conservation) | hash-keyed reorg handling, reversal, conservation |
| [`POOL-08`](https://github.com/gosuda/bitcoin-rs/blob/main/docs/contracts/pool.md#pool-08-external-signing-without-wallet-custody) | reservations, receipts, no wallet custody |

Tests that pin the financial behavior, all in `crates/node/tests/support/pool_ledger_cases.rs` unless noted:

| Invariant | Test |
| :--- | :--- |
| shares idempotent by hash, unique by identity | `shares_are_idempotent_by_header_hash_and_unique_by_identity` |
| retired job refuses late shares, keeps window work | `retiring_a_job_bounds_the_index_and_refuses_late_shares` |
| retired hash never pays twice | `a_retired_header_hash_is_never_credited_again` |
| reward fixed only from the observed coinbase | `the_pool_fee_comes_from_the_observed_reward_and_allocations_sum_to_net` |
| maturity gates credit | `rounds_mature_only_after_the_configured_confirmations_on_the_active_chain` |
| reconciliation writes no audit noise when nothing changed | `reconciliation_is_idempotent_and_writes_no_audit_noise` |
| reorg after maturity reverses and re-credits | `a_reorg_after_maturity_reverses_the_credits_and_re_credits_when_the_block_returns` |
| reversal creates an explicit deficit | `reversing_credits_that_were_already_reserved_creates_an_explicit_deficit` |
| prepare never double-allocates | `preparing_a_batch_reserves_balances_atomically_and_never_double_allocates` |
| receipts must pay exactly the batch | `a_signed_transaction_must_pay_exactly_the_batch_and_prove_its_own_txid` |
| replacements must conflict with earlier txs | `replacements_must_conflict_with_every_earlier_signed_transaction` |
| cancellation never releases after signing | `cancelling_a_prepared_batch_releases_the_reservation_but_never_after_signing` |
| a reorged payout reverts then reconfirms | `a_reorged_out_confirmation_reverts_the_payout_and_a_new_block_reconfirms_it` |
| fail is conclusive only for all txs | `a_batch_fails_only_when_every_signed_transaction_is_conclusively_double_spent` |
| bounded pages advance by cursor | `bounded_pages_advance_via_cursor_without_rescanning_head` |
| SV1 retirement and stale/duplicate codes | `pool_sv1::applied_block_retires_job_and_second_submit_is_stale` in `crates/serving/tests/mining_pool_sv1.rs` |
| job book stale and duplicate identity | `accepted_block_retirement_makes_second_same_job_nonce_stale` in `crates/serving/tests/mining_pool_jobs.rs` |

## What is not established

The pool has no Bitcoin Core counterpart, so no compatibility claim is made here. The ledger also does not claim to survive a reorg deeper than the configured `reorg_watch_depth`: reversal covers the watch horizon, and deeper displacement is outside the monitored set by design (`POOL-07`).

The storage backend under the pool directory is the same `KvStore` boundary as the node's chainstate; the pool opens it through `Ledger::create` or `Ledger::open` and never resets it. `POOL-02` states that approval for this family does not authorize deployment or existing-data cutover, and nothing here extends that approval.
