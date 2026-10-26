# Native pool contract

This contract defines the boundaries of the native SV1/SV2 pool, its durable PPLNS ledger, and the external payout-signing interface. The [operator guide](../pool.md) describes configuration and management RPC usage.

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**, and **MAY** express requirement levels as defined in [RFC 2119](https://www.rfc-editor.org/rfc/rfc2119.txt). They govern this implementation contract; they do not claim complete Stratum specification coverage or external miner interoperability.

## Owners

| Boundary | Authoritative owner | Responsibility |
| --- | --- | --- |
| Operator options | `crates/node/src/options.rs`, `config.rs` | Feature/runtime gating, explicit configuration, and validation. |
| Composition and shutdown | `crates/node/src/lifecycle.rs`, `pool.rs` | Ledger construction, RPC handle publication, listeners, reconciliation, and draining. |
| Jobs and SV1 | `crates/stratum/src/` | MiningControl-backed jobs, share validation, bounded admission, and SV1 protocol handling. |
| SV2 protocol | `crates/stratum-v2/src/` | Noise responder, mining channels, job/share frames, and deferred acknowledgements. |
| Node SV2 adapter | `crates/node/src/pool/sv2.rs`, `authority.rs` | Socket lifecycle, account mapping, found-block handling, and authority-file security. |
| Accounting | `crates/pool-ledger/src/lib.rs`, `store.rs`, `kv.rs` | PPLNS work, round/batch transitions, balance conservation, audit records, and versioned payout codecs over `KvStore`. |
| Applied-chain observations | `crates/node/src/pool/ledger.rs` | Hash-keyed canonicality, coinbase bodies, payout transaction/spend observations, and stable reconciliation. |
| Management API | `crates/rpc/src/handlers/pool.rs` | Authenticated key-free accounting operations through the composed pool handle. |

## Clauses

### `POOL-01`: Explicit enablement and operator configuration

- The service MUST be off by default. The `pool` build feature MUST NOT enable the runtime implicitly. SV2 additionally requires `pool-sv2`.
- Enabling the runtime MUST require a nonempty dedicated pool data directory, at least one explicit listener, an exact plain-decimal share difficulty, a positive work window, and a reward script. Node mining MUST also have a payout address.
- The operator MUST configure the node mining payout address and ledger reward script consistently. The ledger MUST NOT infer ownership or redirect a coinbase from the reward-script setting.
- Listener ports MUST be nonzero. SV1 and SV2 addresses MUST differ. A non-loopback listener MUST require `pool_allow_non_loopback`; omission MUST NOT imply permission.
- SV2 bind and authority-file path MUST be configured together. Pool sub-options MUST NOT be silently ignored when the runtime is disabled.
- The node MUST reject maturity below 100, zero payout confirmations, fees above 10,000 basis points, and a reorg watch shorter than maturity, payout confirmation depth, or the fixed six-confirmation abandon depth.
- A reward script MUST be nonempty, bounded to 10,000 bytes, minimally encoded, and not begin with `OP_RETURN`. Passing these checks MUST NOT be represented as proof of spendability or control by the operator.

### `POOL-02`: Schema consent, storage, and immutable policy

- The additive `PoolLedger` storage family and local integration have explicit approval. This approval does not authorize deployment or an existing-data cutover.
- Backend verification MUST use disposable stores, including old-schema fixtures. This work MUST NOT open or migrate existing operator databases. Existing-data cutover requires separate approval.
- The pool MUST use the selected node storage backend through the storage-owned `KvStore` boundary. The ledger MUST NOT acquire a direct engine dependency or reset an existing database implicitly.
- The service MUST lock the dedicated pool directory. It MUST create a ledger only when absent and reopen an existing ledger with the persisted immutable policy checked for equality.
- Accounting policy changes MUST NOT silently reinterpret historical shares or funds. A configuration mismatch MUST fail rather than delete or recreate the ledger.
- Ledger creation/opening and run-epoch allocation MUST precede listener admission. A run epoch MUST distinguish restarted protocol job identities in durable share accounting.

### `POOL-03`: Shared admission and bounded deferred work

- SV1 and SV2 MUST use one shared total/per-IP connection limiter. Defaults are 128 total connections and 8 per IP. Both limits MUST be positive, and the per-IP limit MUST NOT exceed the total.
- Runtime job retention MUST be bounded at 64 jobs, owner sessions at twice the configured connection cap, and duplicate-share tracking at 65,536 entries per job. Owner sessions are not the same budget as live TCP connections.
- The node-composed deferred share-ledger outbox MUST be bounded by both 1024 records and 8 MiB. Exhaustion MUST reject work before validation. SV1 MUST withhold success for queued writes until their accounting completion is recorded.
- Found-block processing MUST reserve capacity before SV2 protocol feed/validation can emit work requiring a record. Found-record reservations and recovery records MUST share the eight-slot budget, with a 4,000,000-byte charge per slot. Failed writes MUST retain the compact accounting projection rather than serialized full blocks.
- Per-connection protocol limits MUST remain in force in addition to aggregate admission. None of these individual bounds is a claim of a total-process memory bound.

### `POOL-04`: Authority-key handling

- The SV2 authority MUST be a matching BIP340 x-only public/secret keypair. It authenticates the mining transport and MUST NOT be treated as payout custody.
- On Unix the key file MUST be a regular file with permission bits exactly `0600`. Opening MUST use `RDONLY`, `CLOEXEC`, `NOFOLLOW`, and `NONBLOCK`, followed by validation of the opened descriptor's metadata. A final-component symlink or special file MUST NOT bypass this check.
- The file MUST contain exactly two ASCII-whitespace-separated 64-digit hexadecimal fields, public key first and secret key second. Input larger than 256 bytes or extra fields MUST be rejected.
- Secure authority-file loading MUST fail closed where this implementation has no supported loader; the non-Unix path reports unsupported operation.
- The file input buffer, decoded secret buffer, and stored authority secret MUST use zeroizing ownership. Debug formatting MUST redact the stored secret, and parse errors MUST NOT include key input. This requirement does not certify zeroization of cryptographic dependency internals, kernel buffers, or every transient machine-level copy.
- Operators SHOULD protect ancestor directories. `NOFOLLOW` on the opened path MUST NOT be described as an ancestor-directory trust guarantee.

### `POOL-05`: One mining owner and acknowledgement boundaries

- Both protocols MUST derive jobs and validate work through the shared native pool owner backed by `MiningControl`. Protocol adapters MUST NOT introduce a second template or consensus validator.
- A found block MUST be submitted through node mining control before its accounting record is finalized. Submission outcome MUST NOT substitute for active-chain evidence. Applied, duplicate, rejected, missing-parent, and unavailable submission results do not by themselves authorize a reward.
- SV2 `SubmitShares.Success` MUST remain deferred until host confirmation of the durable accounting outcome. An idempotently recorded share MAY satisfy that confirmation; a failed or merely queued record MUST NOT be presented as committed.
- SV1 success MUST wait for a completion token covering the required durable share write and, for a found block, its block-record write. Failed inline writes MAY remain in the bounded volatile outbox, but queueing alone MUST NOT complete the response.
- Each SV1 session MUST retain at most one pending accounting response. Additional submissions while it is pending MUST be rejected before validation with a retryable accounting error. Polling MUST send the deferred success only after accounting completion. Process failure MAY lose queued work before completion, but such work MUST NOT already have received success.
- A found-block accounting record MUST initially be pending and deduplicated by its block/share identity. Retrying a record MUST NOT allocate the same reward twice.
- New job parents, clean-job flags, and submission receipts MUST NOT be used as reorg or maturity evidence.

### `POOL-06`: PPLNS reward and maturity

- A round MUST snapshot its accepted-share work window at the solving share. The window is work-weighted, not a count of connections, accounts, or shares.
- Reward fixing MUST require authoritative canonical observation of the exact found block and its coinbase. The observed coinbase txid and total value MUST agree with the recorded claim. Missing bodies or contradictory observations MUST NOT fabricate a reward.
- Gross pool reward MUST be the sum of observed coinbase outputs with the configured pool script. The fee MUST be computed in integer basis points, rounded down. Net allocations MUST conserve that reward after the fee.
- Available balances MUST be credited only after the configured maturity, using confirmations `tip_height - block_height + 1`. Node configuration MUST keep that threshold at or above 100.
- A registered payout script MUST be required for miner admission. Decimal account IDs MAY include one nonempty worker suffix. Login syntax MUST NOT be represented as cryptographic proof of payout-script ownership.

### `POOL-07`: Hash-keyed reorg reconciliation and conservation

- Active-chain membership MUST be observed by exact block hash. A claimed height is only a lookup hint. Known displaced hashes MUST remain distinguishable from unknown hashes even when the replacement tip is lower or equal.
- The node adapter MUST take stable applied-chain observations. Transaction and spend index hints MUST be checked against the corresponding canonical block body before being accepted as payout evidence.
- A monitored matured round displaced from the active chain MUST become orphaned and reverse its allocations. Reversal MUST consume available funds first; the remainder MUST become a deficit rather than erase a reservation or rewrite an already-paid amount.
- Future credits MUST offset deficits before increasing available funds. Per account, `available + reserved + paid - deficit` MUST equal credited matured-round allocations.
- Unknown membership MUST NOT be treated as proof of canonicality or displacement. Reorg monitoring is bounded: rounds and confirmed batches leave monitoring according to the configured watch horizon. This contract MUST NOT be advertised as unlimited deep-reorg recovery.
- Payout confirmation reversal MUST preserve the batch's financial reservation/accounting transitions. A transaction disappearing from a mempool MUST NOT prove that its signature is unusable or that its inputs cannot later be spent.

### `POOL-08`: External signing without wallet custody

- Management pool RPC MUST remain authenticated and key-free. The pool MUST NOT generate, import, expose, or use Bitcoin payout private keys. The external signer MUST own funding, input selection, signatures, and fee policy.
- `preparepayoutbatch` MUST reserve eligible funds with a 32-byte idempotency key. Its policy MUST NOT lower the configured minimum payout or exceed the configured output cap. The absolute maximum is 2500 outputs; the configured minimum is bounded from 546 satoshis through `MAX_MONEY`.
- The signer request MUST use the strict canonical BRPR version 1 codec. The receipt MUST use BRPT version 1. Metadata integers are big-endian. BRPR carries exact payout outputs and authorized change scripts; BRPT carries batch ID, txid, and raw transaction.
- Receipt recording MUST recompute the txid, match the exact payout-output multiset, reject unauthorized extra outputs, reject invalid or duplicate inputs, and preserve reservations on rejection. A replacement MUST conflict with earlier signed transactions of that batch rather than permit independent double payment.
- The generic verifier allows at most one authorized change output. The node policy supplies no authorized change scripts, so node-composed batches MUST reject all extra change outputs.
- Receipt validation MUST NOT be described as signature or input-ownership verification. `recordpayoutreceipt` MUST NOT broadcast. Chain observation of the recomputed txid supplies node-acceptance evidence; payment confirmation additionally requires the configured depth.
- Signing failure, timeout, or receipt rejection MUST NOT release a reservation implicitly. Cancellation MUST require a prepared batch and explicit `never_handed_to_signer` or `signer_revoked` basis. The operator MUST establish that external basis; the RPC cannot prove signer revocation.
- Lack of a transaction index prevents confirmed payout observation outside the mempool; lack of a script index prevents confirmed-spend observation. Such observer errors MUST NOT be converted into evidence of nonpayment or safe abandonment.

### `POOL-09`: Lifecycle and protocol scope

- Composition MUST construct the ledger/operator handle before management RPC publication. Mining listeners MUST start only after RPC binds successfully and an initial template is available.
- Reconciliation MUST refresh work and observe rounds/payouts without holding shutdown hostage to a future mining generation. Shutdown MUST stop admission, cancel and join protocol workers, and drain bounded deferred accounting work within the node's shutdown deadline. A missed deadline or worker panic MUST remain an error, not a success report.
- SV2 support is limited to the role matrix in `crates/stratum-v2/src/lib.rs`: Noise responder transport, mining setup version 2, standard and extended channels, a per-connection group, and job/share handling, including the adapter's reconnect API.
- Custom jobs/work selection, Job Declaration, a Template Distribution server, extranonce-prefix changes, and extensions negotiation MUST NOT be advertised as implemented. The in-process template source MUST NOT be confused with a Template Distribution server.

## Evidence boundary and source map

The supplied evidence baseline records **71 prior protocol tests**, **112 prior ledger tests**, and **111 selected node/RPC tests**. These are scoped results from separate runs, not a final all-features or whole-tree certification. Strict final gates remain pending. No external miner interoperability is claimed. No checks were run by this documentation assignment.

| Contract area | Source anchor | Evidence boundary |
| --- | --- | --- |
| Options and validation | `crates/node/src/options.rs`, `config.rs::resolve_pool`, `PoolConfig::validate` | Implemented configuration, not deployment approval. |
| Persistence and budgets | `crates/node/src/pool.rs::LedgerComposer`, `PoolService::prepare`, `PoolService::start`; `pool/ledger.rs::try_reserve_block_slot` | Approved additive storage and runtime bounds; no operator-data cutover. |
| Key security | `crates/node/src/pool/authority.rs::load`, `open_private_file`; `crates/stratum-v2/src/lib.rs::AuthorityKeypair` | Descriptor checks and explicitly owned zeroizing buffers. |
| Block and share records | `crates/node/src/pool/ledger.rs::record_submitted_block`; `pool/sv2.rs::handle_events`; `crates/stratum/src/sv1/session.rs::Completion`, `PoolCore::submit`, `on_submit`, `poll` | Submission ordering and deferred durable success in both protocols; not miner interoperability. |
| Canonicality and reward reversal | `crates/pool-ledger/src/store.rs::reconcile_rounds`, `apply_round_observation`, `fix_reward`, `reverse_round_credits`; node `RawChainView` | Hash-keyed observations within the watch horizon. |
| Signer codecs and receipt checks | `crates/pool-ledger/src/lib.rs::PayoutRequest`, `PayoutReceipt`, `verify_payout_transaction`; `store.rs::record_signed` | Exact output/txid checks; no in-process wallet or signature-verification claim. |
| Operator API | `crates/rpc/src/handlers/pool.rs` | Selected node/RPC evidence, not strict final-gate completion. |

For operator configuration and the external signing sequence, read [Native pool operation](../pool.md). Existing operator databases MUST remain untouched by this work. Deployment and existing-data cutover require separate approval.
