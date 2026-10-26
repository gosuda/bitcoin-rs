# Native pool operation

The native pool combines SV1 and optional SV2 mining listeners with PPLNS accounting and an external payout signer. It is disabled by default. The node builds mining candidates in process; it does not use a separate template-provider service.

The additive `PoolLedger` storage family and local integration are explicitly approved. This approval does not authorize a production deployment or an existing-data cutover. Backend verification MUST use disposable stores, including old-schema fixtures. Existing operator databases MUST remain untouched by this work. Pool operation remains opt-in. See the [pool contract](contracts/pool.md) for the financial and lifecycle requirements.

## Prerequisites

- The binary MUST include the `pool` feature. An SV2 listener additionally requires `pool-sv2`. These features do not enable the runtime by themselves.
- The operator MUST supply a dedicated pool data directory, at least one explicit mining listener, an exact share difficulty, a positive PPLNS work window, and the externally controlled reward script.
- The node also requires `--mining-payout-address`. The operator MUST ensure its resulting coinbase script matches `--pool-reward-script`; configuring an unrelated script does not redirect the candidate's coinbase. The ledger recognizes only observed coinbase outputs matching its configured reward script.
- An external signer MUST control payout funding and signing. The pool has no wallet custody. The SV2 Noise authority secret authenticates the mining service; it is not a Bitcoin payout key.
- Management RPC MUST remain on the authenticated management listener. Mining listener exposure does not grant management access.
- Payout confirmation requires transaction-index observations (`--txindex`); confirmed conflicting-spend observation requires the script index (`--scriptindex=full`). Index hints are checked against canonical block bodies. Operators MUST retain the bodies needed for those observations and MUST NOT treat an unavailable or incomplete index as evidence that a payout cannot confirm.

The option declarations are in [`options.rs`](../crates/node/src/options.rs), and resolution and validation are in [`config.rs`](../crates/node/src/config.rs). Native TOML keys are flat, such as `pool_v1_bind`; environment names use `BITCOIN_RS_` followed by the uppercase key. There are no pool-specific `bitcoin.conf` aliases.

## Configure the candidate

Before enabling the service, choose the reward destination with the external signer and obtain its address and exact scriptPubKey. Supply the address through `--mining-payout-address` and the script bytes as hexadecimal through `--pool-reward-script`. Operators MUST NOT copy a test script or someone else's address into a funded configuration.

Set `--pool` and provide each required value below. No listener, pool directory, difficulty, work window, or reward script is inferred.

| Option / TOML key | Type and default | Requirement |
| --- | --- | --- |
| `--pool` / `pool` | Boolean; `false` | Enables the service. Pool sub-options without this setting are rejected. |
| `--pool-datadir` / `pool_datadir` | Path; required | Dedicated ledger directory. The service locks it and opens its selected storage backend under `ledger/`. |
| `--pool-v1-bind` / `pool_v1_bind` | Socket address; unset | Explicit SV1 address, for example `127.0.0.1:3333`. |
| `--pool-sv2-bind` / `pool_sv2_bind` | Socket address; unset | Explicit SV2 address, for example `127.0.0.1:3336`; requires the authority-key path. |
| `--pool-sv2-authority-key` / `pool_sv2_authority_key` | Path; unset | Required exactly when an SV2 bind is configured. See key requirements below. |
| `--pool-allow-non-loopback` / `pool_allow_non_loopback` | Boolean; `false` | Explicit permission for non-loopback mining binds. |
| `--pool-share-difficulty` / `pool_share_difficulty` | Exact plain-decimal string; required | Fixed share difficulty, not a floating-point approximation or vardiff policy. |
| `--pool-window-work` / `pool_window_work` | Positive `u64`; required | PPLNS window in accepted-share work units, not a share count. |
| `--pool-reward-script` / `pool_reward_script` | Hexadecimal scriptPubKey; required | Nonempty, at most 10,000 bytes, minimally encoded, and not beginning with `OP_RETURN`. These checks do not prove the operator owns the destination. |
| `--pool-fee-bps` / `pool_fee_bps` | `u16`; `0` | Pool fee, from 0 through 10,000 basis points. |
| `--pool-max-connections` / `pool_max_connections` | Positive `u32`; `128` | Aggregate live connection limit across SV1 and SV2. |
| `--pool-max-connections-per-ip` / `pool_max_connections_per_ip` | Positive `u32`; `8` | Aggregate per-IP limit across both protocols; cannot exceed the total. |
| `--pool-maturity` / `pool_maturity` | `u32`; `100` | Coinbase confirmation threshold; MUST be at least 100. |
| `--pool-payout-confirmations` / `pool_payout_confirmations` | Positive `u32`; `6` | Confirmation threshold for a payout batch. |
| `--pool-reorg-watch-depth` / `pool_reorg_watch_depth` | `u32`; `1000` | MUST cover maturity, payout confirmations, and the fixed six-confirmation abandon depth. |
| `--pool-min-payout-sat` / `pool_min_payout_sat` | `u64`; `546` | Between 546 and 2,100,000,000,000,000 satoshis. |
| `--pool-max-payout-outputs` / `pool_max_payout_outputs` | `u32`; `2500` | Between 1 and 2500 outputs. |

Write difficulty with an ASCII-digit integer part and, if needed, a decimal point and fractional digits, such as `16384` or `0.001`. There MUST be at most 19 digits in total. Signs, exponent notation, a missing integer part, and zero are rejected. The target conversion uses integer-ratio arithmetic; see `ShareTarget::from_pool_difficulty_decimal` in [`job.rs`](../crates/stratum/src/job.rs).

At least one protocol bind MUST be present. Ports MUST be nonzero, and the two bind addresses MUST differ. Non-loopback binds require explicit permission even when the address is a wildcard. Operators SHOULD keep candidate listeners on loopback.

Accounting policy is persisted at ledger creation and checked on reopen. Changing the PPLNS window, fee, reward script, maturity, confirmation depths, or other immutable ledger policy is not a configuration-only migration. Operators MUST preserve the existing ledger; they MUST NOT delete it to bypass a policy mismatch.

## Protect the SV2 authority key

On Unix, the authority file MUST be a regular file with mode exactly `0600`, including no extra special permission bits. Its contents MUST be two ASCII-whitespace-separated fields: a 64-digit hexadecimal BIP340 x-only public key followed by a 64-digit hexadecimal secret key. Extra fields and files larger than 256 bytes are rejected. Operators MUST provision a matching keypair and distribute the public key through their miner trust configuration.

The loader opens the path with `RDONLY | CLOEXEC | NOFOLLOW | NONBLOCK` and checks metadata on the opened descriptor. A final-component symlink, FIFO, directory, or insecure mode is not accepted. `NOFOLLOW` is not a claim that every parent directory is trusted; operators SHOULD protect the containing directory from modification by other users. Secure authority-file loading fails closed on non-Unix platforms.

The input buffer, decoded secret, and stored authority secret use `Zeroizing`; the authority object's debug output redacts the secret. Parse errors do not include file contents. These protections cover the owned buffers in this implementation, not every internal copy in a cryptographic dependency or operating-system memory. See [`authority.rs`](../crates/node/src/pool/authority.rs) and [`AuthorityKeypair`](../crates/stratum-v2/src/lib.rs).

## Register miners and inspect accounting

Use the authenticated management JSON-RPC listener. The dispatcher and its shipped-method inventory include pool methods only when the `pool` feature is compiled. The `pool-sv2` feature also enables `pool`. With the feature compiled but the runtime off, these methods report `MethodDisabled`. Parameters are positional arrays.

| Method | Parameters | Result or effect |
| --- | --- | --- |
| `registerpoolaccount` | `[account, script_hex]` | Registers the numeric account's payout script. This is required before miner admission. |
| `getpoolinfo` | `[]` | PPLNS configuration, share count, and the last 20 audit records. |
| `getpoolbalances` | `[account]` | Available, reserved, paid, and deficit balances in satoshis, plus the payout script. |
| `getpoolrounds` | `[first_round, count]` | Round states and rewards; first round MUST be positive. Count defaults to 100 and is at most 1000. |
| `preparepayoutbatch` | `[idempotency_key_hex, min_payout_sat, max_outputs]` | Reserves eligible balances and returns `batch` and hexadecimal BRPR `request`, or `null` if no batch qualifies. The key MUST encode exactly 32 bytes. |
| `getpayoutrequest` | `[batch_id_hex]` | Returns the canonical BRPR request for a reservation-holding batch. |
| `recordpayoutreceipt` | `[receipt_hex]` | Validates and records a BRPT receipt. It does not broadcast the transaction. |
| `getpayoutbatch` | `[batch_id_hex]` | Returns the batch state, or `null` for an unknown batch. |
| `cancelpayoutbatch` | `[batch_id_hex, basis]` | Cancels a prepared batch with explicit basis `never_handed_to_signer` or `signer_revoked`. |

Miner logins are decimal account IDs, optionally followed by one nonempty worker suffix, such as `7.rig1`. Additional dots are rejected. A registered payout script is the admission prerequisite; a worker login is not proof of control of that script. Operators MUST restrict management access and register scripts only through their own account-authorization process.

RPC ownership: [`handlers/pool.rs`](../crates/rpc/src/handlers/pool.rs). Admission and shared durable accounting: [`pool/ledger.rs`](../crates/node/src/pool/ledger.rs).

## Complete a payout outside the node

1. Inspect balances and prepare a batch with a retained idempotency key. The requested minimum MUST be no lower than the configured minimum; the requested output count MUST be no higher than the configured cap.
2. Transfer the returned BRPR bytes to the external signer. BRPR version 1 contains the batch ID and exact account, amount, and script outputs, followed by allowed change scripts. The node's configured ledger authorizes no change scripts, so its receipts MUST NOT add a change output.
3. Have the signer fund and sign the transaction, then return a BRPT version 1 receipt containing the batch ID, claimed txid, and raw transaction. The signer remains responsible for funding, signatures, input ownership, and fee policy.
4. Submit the receipt with `recordpayoutreceipt`. The ledger recomputes the txid and checks the exact output multiset. Recording is not signature verification, broadcast, or payment confirmation.
5. Broadcast through the external transaction-submission workflow and observe `getpayoutbatch`. Node reconciliation advances a recorded transaction from observed mempool or chain state and confirms payment only at the configured active-chain depth. Without transaction/spend index observations, some historical payout or conflict evidence is unavailable; operators MUST NOT interpret missing evidence as proof that a signed transaction cannot confirm.

Both wire formats use strict versioned codecs with big-endian metadata fields. Reservations survive signing errors and rejected receipts. A timeout or a transaction disappearing from the mempool is not safe cancellation evidence. Operators MUST NOT assert `signer_revoked` unless the external signer has actually revoked the prepared request; the node cannot establish that external fact.

## Understand rewards, reorgs, and pressure

PPLNS fixes each found block's work window at its solving share. A submission receipt, a new job parent, or a reported height does not establish reward eligibility. The ledger first observes the exact block hash on the active chain, verifies the coinbase claim, and computes rewards from outputs matching the reward script. Confirmations are `tip_height - block_height + 1`. Only matured allocations become available for payout.

Within the configured reorg-watch horizon, displacement of a matured block reverses its allocations. Available funds are removed first; amounts already reserved or paid create a deficit that future credits offset. A lower or equal replacement tip does not hide displacement because canonicality is hash-based. Unknown membership is not positive canonicality evidence. Monitoring is bounded by the configured watch depth; this is not an indefinite deep-reorg guarantee.

Both mining protocols share the configured total and per-IP connection limiter. They also share the job and accounting owners. The runtime bounds retained jobs at 64, owner sessions at twice the configured connection limit, and duplicate-share tracking at 65,536 entries per job. The node explicitly sets the SV1 deferred ledger outbox to 1024 records and 8 MiB, overriding the standalone core defaults of 4096 records and 32 MiB. Found-block recovery has a shared eight-slot admission budget with 4,000,000 bytes charged per slot; failed records retain a compact ledger projection, not complete blocks. These are distinct budgets, not a total-process memory bound. A queue-pressure rejection is not an accepted share. SV1 retains failed writes in its bounded in-memory outbox but withholds success until the required share record and, for a found block, block record complete. Each SV1 session permits only one pending accounting response; additional submissions are rejected before validation with a retryable accounting error. Process failure can lose queued work before completion, but that work has not received a success response. SV2 likewise holds success until the host confirms the ledger record. Operators MUST NOT equate queued work with committed accounting.
 Once the node accepts a found block, the current job is retired at once: new and different shares on the old job are refused as stale (SV1 error 21, SV2 `stale-share`), while resending the exact accepted share reports a duplicate (SV1 error 22, SV2 `duplicate-share`) without extra credit. A block the backend answers with `inconclusive-not-best-prevblk` is still recorded, then refused as a nonfatal stale share; other node rejections are never answered as stale. The [pool contract](contracts/pool.md) states the authoritative rule.

## Evidence and operational limits

The recorded prior evidence is **71 protocol tests** and **112 ledger tests**. The selected node/RPC evidence is **111 tests**. These counts describe separate reported runs, not one final verification of the entire current tree. Strict final gates remain pending. This documentation task ran no builds, tests, linters, formatters, or interoperability checks.

No external miner interoperability is claimed. The SV2 implementation supports authenticated Noise responder transport, mining setup version 2, standard and extended channels, a per-connection group, and job/share handling. It does not implement custom mining jobs, Job Declaration, a Template Distribution server, extranonce-prefix changes, or extensions negotiation. Protocol implementation tests do not establish interoperability with a particular miner or proxy.

Before operation, inspect the [pool contract](contracts/pool.md). Keep existing operator databases unchanged. A deployment or existing-data cutover requires separate approval.
