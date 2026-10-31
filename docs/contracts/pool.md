# Native pool contract
The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**, and **MAY** express requirement levels as defined in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119.txt). Operator use: [Native pool operation](../pool.md).
## Owners

| Boundary | Authoritative owner | Evidence boundary |
| --- | --- | --- |
| Operator configuration | `crates/node/src/options.rs`, `crates/node/src/config.rs` | Owner-local configuration refusal tests. |
| Composition and shutdown | `crates/node/src/lifecycle.rs`, `crates/node/src/pool.rs::composed_core_config` | Lifecycle and pool composition tests; no deployment certification. |
| Jobs and SV1 | `crates/mining/src/pool/job.rs`, `crates/mining/src/pool/core.rs`, `crates/mining/src/pool/stratum/sv1.rs` | In-tree job and SV1 protocol tests. |
| SV2 protocol | `crates/mining/src/pool/stratum/sv2.rs` | `crates/mining/tests/pool_sv2.rs`; no external miner interoperability claim. |
| Node SV2 adapter | `crates/node/src/pool/sv2.rs`, `crates/node/src/pool/authority.rs` | Adapter and authority-file refusal tests. |
| Accounting | `crates/mining/src/pool/ledger.rs`, `crates/mining/src/pool/ledger/store.rs`, `crates/mining/src/pool/ledger/kv.rs` | Shared ledger cases and the independent backend crash-worker target. |
| Applied-chain observations | `crates/node/src/pool/ledger.rs` | Local observation/reconciliation evidence, qualified by available indexes. |
| Management API | `crates/rpc/src/handlers/pool.rs` | Handler and authenticated HTTP tests. |

Source owners in the table use repository-relative paths.

## Clauses
### `POOL-01`: Explicit enablement and operator configuration
- The pool is off by default.
- The `pool` feature MUST NOT enable the runtime implicitly.
- SV2 additionally requires `pool-sv2`.
- Enabling MUST require a nonempty pool datadir and at least one explicit listener.
- Enabling MUST require an exact plain-decimal share difficulty and a positive work window.
- Enabling MUST require a reward script plus a node mining payout address.
- The node payout address and ledger reward script MUST be consistent.
- The ledger MUST NOT infer ownership or redirect a coinbase.
- Ports MUST be nonzero.
- SV1 and SV2 addresses MUST differ.
- Non-loopback binds MUST require `pool_allow_non_loopback`.
- Omission of `pool_allow_non_loopback` MUST NOT imply permission.
- The SV2 bind and authority-file path MUST be paired.
- Sub-options MUST NOT be silently ignored when disabled.
- The node MUST reject maturity below 100, zero payout confirmations, and fees above 10,000 basis points.
- The node MUST reject a reorg watch shorter than maturity, payout-confirmation depth, or the fixed 6-confirmation abandon depth.
- Reward scripts MUST be nonempty, at most 10,000 bytes, minimally encoded, and not `OP_RETURN`.
- Passing these checks MUST NOT be represented as proof of spendability or control.
### `POOL-02`: Schema consent, storage, and immutable policy
- The additive `PoolLedger` family has explicit approval.
- This approval does not authorize deployment or existing-data cutover.
- Verification MUST use disposable stores, including old-schema fixtures.
- Verification MUST NOT open or migrate operator databases.
- The pool MUST use the selected backend through the storage-owned `KvStore` boundary.
- The pool MUST NOT take a direct engine dependency or implicitly reset a database.
- The service MUST lock the dedicated pool directory.
- The service MUST create a ledger only when absent.
- The service MUST reopen only with the persisted immutable policy equal.
- Policy changes MUST NOT reinterpret history.
- A policy mismatch MUST fail rather than delete or recreate the database.
- Creation or opening plus run-epoch allocation MUST precede admission.
- The epoch MUST separate restarted protocol job identities.
### `POOL-03`: Shared admission and bounded deferred work
- SV1 and SV2 MUST share one total and per-IP limiter with defaults 128 total and 8 per IP.
- Both limits MUST be positive and per-IP MUST NOT exceed total.
- Retention MUST use limits owned by `crates/node/src/pool.rs`: `MAX_RETAINED_JOBS`, `SESSION_SLOTS_PER_CONNECTION`, and `MAX_SHARES_PER_JOB`.
- Owner sessions and TCP connections are distinct budgets.
- The deferred share-ledger outbox MUST use `MAX_OUTBOX_RECORDS` and `MAX_OUTBOX_BYTES`.
- Outbox exhaustion MUST reject work pre-validation.
- SV1 MUST withhold success until accounting completion.
- When a Stratum V2 connection ends, the host MUST release every owned session to keep the bounded session table available.
- Found-block processing MUST reserve capacity before feed or validation emits record-requiring work.
- The capacity reservation provides 8 slots shared by reservations and recovery records, with 4,000,000 bytes per slot.
- Failed writes MUST keep the compact projection, not full blocks.
- Per-connection limits stay in force.
- No single bound claims a total-process memory bound.
### `POOL-04`: Authority-key handling
- The SV2 authority MUST be a matching BIP340 x-only public and secret pair.
- The authority authenticates transport and MUST NOT be treated as payout custody.
- On Unix, the file MUST be a regular file with bits exactly `0600`.
- The file MUST be opened `RDONLY|CLOEXEC|NOFOLLOW|NONBLOCK` with descriptor-metadata validation.
- A final-component symlink or special file MUST NOT bypass the check.
- Content MUST be exactly two ASCII-whitespace-separated 64-hex-digit fields, with public first and secret second.
- Input over 256 bytes or extra fields MUST be rejected.
- Non-Unix systems MUST fail closed with an unsupported operation error.
- File, decoded-secret, and stored-secret buffers MUST use zeroizing ownership.
- `Debug` MUST redact the secret.
- Parse errors MUST NOT include key input.
- This rule does not certify dependency, kernel, or transient copies.
- Operators SHOULD protect ancestor directories.
- `NOFOLLOW` MUST NOT be described as an ancestor-directory guarantee.
### `POOL-05`: One mining owner and acknowledgement boundaries
- Both protocols MUST derive jobs and validate work through the shared `MiningControl`-backed owner.
- Both protocols MUST NOT add a second template or consensus validator.
- Found blocks MUST submit through node mining control before the accounting record finalizes.
- The outcome MUST NOT substitute for active-chain evidence.
- After `Applied`, the active job MUST retire synchronously.
- The node MUST run `invalidate_active` before ledger, outbox, or acknowledgement processing.
- Work on a retired job is stale.
- A byte-identical replay keeps duplicate identity (SV1 21 vs 22; SV2 `stale-share` vs `duplicate-share`).
- A duplicate or stale share MUST NOT receive a second credit.
- After a difficulty change, the easier of the old and new target MUST judge in-flight shares until the configured grace period ends.
- Miners MUST discard all earlier work when a job sets the clean-jobs flag.
- An exact `inconclusive-not-best-prevblk` receipt on an in-flight sibling MUST complete its durable record and answer nonfatal stale.
- Any other rejection MUST NOT be answered stale.
- SV2 `SubmitShares.Success` MUST wait for host confirmation of the durable outcome.
- An idempotent record MAY satisfy this confirmation.
- Queued or failed work MUST NOT present as committed.
- SV1 success MUST wait for a completion token covering the share write, plus block-record write for found blocks.
- Failed inline writes MAY sit in the bounded outbox, but queueing MUST NOT complete the response.
- Each SV1 session MUST keep at most one pending accounting response.
- Sessions MUST shed extra work pre-validation as retryable and poll only after completion.
- Work lost before completion MUST NOT have received success.
- Found records MUST start pending and deduplicate by block and share identity.
- Retries MUST NOT double-allocate.
- Parents, clean-job flags, and receipts MUST NOT serve as reorg/maturity evidence.
### `POOL-06`: PPLNS reward and maturity
- Rounds MUST snapshot the work-weighted accepted-share window at the solving share, not connection, account, or share counts.
- Fixing MUST require authoritative canonical observation of the exact block and coinbase with agreeing txid and value.
- Missing bodies or contradictions MUST NOT fabricate a reward.
- Gross reward MUST equal observed coinbase outputs paying the pool script.
- The fee MUST be floor-rounded integer basis points, and allocations MUST conserve net reward.
- Balances MUST credit only after configured maturity with confirmations `tip_height - block_height + 1`.
- The maturity threshold MUST be at or above 100.
- Admission MUST require a registered payout script.
- Decimal account IDs MAY carry one nonempty worker suffix.
- Login syntax MUST NOT be represented as ownership proof.
### `POOL-07`: Hash-keyed reorg reconciliation and conservation
- Membership MUST be observed by exact block hash, with height used as a lookup hint only.
- Known displaced hashes MUST stay distinguishable from unknown hashes, even when the replacement tip is lower or equal.
- The adapter MUST take stable applied-chain observations.
- The adapter MUST check transaction and spend index hints against the canonical body before accepting payout evidence.
- A displaced matured round MUST orphan and reverse allocations.
- Reversal MUST consume available funds first, with the remainder recorded as an explicit deficit.
- Reversal MUST NOT erase a reservation or rewrite paid amounts.
- Future credits MUST clear deficits before increasing available funds.
- Accounting MUST keep `available + reserved + paid - deficit` equal to credited matured allocations.
- Unknown membership MUST NOT prove canonicality or displacement.
- Monitoring is bounded by the watch horizon and MUST NOT be advertised as unlimited deep-reorg recovery.
- Payout reversal MUST preserve reservation and accounting transitions.
- Mempool absence MUST NOT prove unusable signatures or unspendable inputs.
### `POOL-08`: External signing without wallet custody
- Pool RPC MUST stay authenticated and key-free.
- The pool MUST NOT generate, import, expose, or use payout private keys.
- The external signer owns funding, input selection, signatures, and fees.
- `preparepayoutbatch` MUST reserve with a 32-byte idempotency key.
- It MUST NOT lower the minimum payout (floor 546 satoshis through `MAX_MONEY`) or exceed the output cap (absolute maximum 2500).
- Requests MUST use strict canonical BRPR v1 and receipts BRPT v1 with big-endian integers.
- BRPR specifies exact outputs plus authorized change scripts.
- BRPT specifies batch ID, txid, and raw transaction.
- Receipts MUST recompute the txid and match the exact payout-output multiset.
- Receipts MUST reject unauthorized extras and invalid or duplicate inputs.
- Receipts MUST preserve reservations on rejection.
- Replacements MUST conflict with earlier signed transactions rather than double-pay.
- At most one authorized change output is allowed, and node policy supplies none.
- Node-composed batches MUST reject all extra change.
- Receipt checks MUST NOT be described as signature or ownership verification.
- `recordpayoutreceipt` MUST NOT broadcast transactions.
- Chain observation of the txid provides acceptance evidence, and payment confirmation requires the configured depth.
- Failures, timeouts, and rejections MUST NOT implicitly release reservations.
- Cancellation MUST require a prepared batch plus an explicit `never_handed_to_signer`/`signer_revoked` basis established by the operator.
- Missing txindex or script-index observer errors MUST NOT become nonpayment or safe-abandonment evidence.
### `POOL-09`: Lifecycle and protocol scope
- Composition MUST build the ledger and operator handle before RPC publication.
- Listeners MUST start only after RPC bind plus an initial template.
- Reconciliation MUST NOT hold shutdown hostage to a future generation.
- Shutdown MUST stop admission, cancel and join workers, and drain bounded deferred work within the deadline.
- A deadline miss or panic MUST be reported as an error, not success.
- SV2 is limited to the `sv2.rs` role matrix.
- This matrix covers Noise responder, setup v2, standard and extended channels, per-connection group, job and share handling, plus reconnect.
- Custom jobs or work selection, Job Declaration, Template Distribution server, extranonce-prefix changes, and extensions negotiation MUST NOT be advertised.
- The in-process template source MUST NOT be confused with a Template Distribution server.
## Evidence boundary

Current execution results belong to CI or the PR. In-tree protocol and ledger evidence does not certify an external miner or the entire tree. Existing operator databases MUST remain untouched. Deployment and existing-data cutover require separate approval.
