# Block connect and reorg

The connect path turns admitted blocks into a durably committed chain tip: it checks each block in a fixed order, groups the writes of consecutive blocks into one commit, and keeps an undo record so any later reorg can roll back. Reorgs and invalidations run through the same machinery in reverse. Read [how/validation.md](validation.md) for the script rules and [run/sync-and-recovery.md](../run/sync-and-recovery.md) for what the operator sees; this page is the code-level view.

The whole path lives in `crates/execution/src`: `window.rs` owns the apply window and error classification, `connect.rs` owns per-block checks and commit, `reorg.rs` and `disconnect.rs` own rollback, `durable.rs` owns the durable head. The contracts own the guarantees: `SYNC-05` (commit-before-publish), `SYNC-04` (failure classification), `RCV-04` to `RCV-08` (recovery mechanics) in `docs/contracts/synchronization.md`.

## The apply window

The sync layer hands the chainstate a batch of consecutive blocks, not one at a time. `apply_window_admitted` (`window.rs`) walks the batch and stages each validated block in a `WindowGroup`. Staging builds the undo record and accumulates coin effects in the window workspace; block bodies are appended, but the durable head and published applied tip do not advance. The final `WindowDelta` is built at flush.

A group flushes when it holds 64 blocks (`DURABLE_HEAD_GROUP_BLOCKS`, `window.rs:16`) or 8 MiB of staged block bytes (`DURABLE_HEAD_GROUP_MAX_BYTES`, `window.rs:18`). `flush` (`window.rs:77`) then does one group commit:

```
staged blocks 1..n  --sync_appended_blocks-->  appended bodies durable
window workspace  --build_flush_delta-->  final coin replacements
undo rows + body locator rows + attestation + coin replacements + head
  --commit_prefix--> durable batch, then coin-cache and stats-feed installation, then receipt
receipt.commit_id backfilled into every ConnectOutcome, then tips published per block
```

Each block in the group must continue the previous one: `WindowGroup::predecessor` (`window.rs:46`) returns the last staged tip as the parent and rejects a `prev_hash` mismatch with `PrevHashMismatch { tip, prev }`. This lets validation chain block N+1 against block N's in-memory tip without a storage round trip.

The log line for a group flush is `durable_head: group commit` with `blocks`, `sync_us`, and `commit_us` fields (`window.rs:136`), and the counter `node.durable_head.group_flushes` increments per flush (`window.rs:161`). Single-block applies, such as `generatetoaddress` over RPC, take the `PublishMode::Now` path instead (`connect.rs:704`) and log `apply_block: tail begin` followed by `apply_block: publish profile` (`connect.rs:931`, `connect.rs:967`).

## Per-block checks and their order

`apply_block_admitted` (`connect.rs:973`) runs the same sequence for every block regardless of intent. The order matters because the first failing check decides the error, and because later checks are more expensive.

1. Locate the predecessor: `application_predecessor` (`connect.rs:62`) resolves the parent tip and height, from the staged group when grouped.
2. Historical-target guard (`connect.rs:79`): under the assumeutxo historical role, blocks past `base_height` fail with `ConnectPastHistoricalTarget` and a height-equal mismatch fails with `HistoricalTargetHashMismatch`.
3. Contextual header check (`connect.rs:106`): median-time-past, nbits, version gates, reusing `validate_contextual_header` from the execution chain module (`crates/execution/src/chain/header_sync.rs`) (see the next chapter).
4. Self proof of work (`connect.rs:146`).
5. `BlockRules::check` (`connect.rs:252`): block rules from `verify_block_rules_precomputed` (merkle roots, size, weight, coinbase structure), signet solution, block finality (`check_block_finality`, `connect.rs:1310`), an early BIP34 check, the optional pow-valid announce hook, and the combined BIP30/BIP34 scan (`check_bip30_and_bip34`, `connect.rs:1262`).
6. Script verification (`ScriptVerification::run`, `connect.rs:314`), possibly skipped under assume-valid; see [how/validation.md](validation.md) and clause `VAL-02` of `docs/contracts/validation-default.md`.
7. Budget checks (`BudgetChecks::run`, invoked at `connect.rs:824`): sigop cost (`check_block_sigops`, `connect.rs:1079`), coinbase maturity, BIP68 sequence locks, coinbase value.
8. Commit (`commit_application`, `connect.rs:859`): build UTXO changes and the undo record (`build_block_changes_checked`), check the coinbase value against subsidy and fees, persist the body, then publish via the mode picked by the caller.

The timing breakdown lines `apply_block: profile`, `apply_block: tail begin`, and `apply_block: publish profile` from a real regtest run are shown in [how/architecture.md](architecture.md); the `bip30_bip34_us` field in that profile times step 6's combined scan. Single-block RPC applies take the same path; a window commit from the p2p sync layer instead logs one `durable_head: group commit` line per flush, not per block.

## BIP30 and BIP34

BIP30 forbids a second live transaction with a txid that already has live outputs; BIP34 requires the coinbase scriptSig to start with the block height. `check_bip30_and_bip34` (`connect.rs:1262`) implements both in one pass:

- `bip30_duplicate_scan_required` (`crates/execution/src/chain/deployment.rs:299`) decides whether a live-output scan is needed at all. The scan runs unless the code can cheaply prove duplicates are impossible: it is required above `BIP34_IMPLIES_BIP30_LIMIT = 1_983_702` (`crates/consensus/src/bip30.rs:5`), below BIP34 activation, and whenever there is no known activation hash, no previous tip, or the ancestor at the activation height does not match the network's expected activation hash (`deployment.rs:305` to `deployment.rs:326`). Regtest has no activation hash (`crates/consensus/src/primitives/network/tests.rs:118`), so the scan always runs there; mainnet can skip it once BIP34 is active and the ancestor is confirmed.
- When scanning, `handles.utxo.has_live_outputs_for_txid` flags any duplicate; only then does `bip30::check_duplicate_txid` (`crates/consensus/src/bip30.rs:26`) run, which exempts exactly the two historical duplicate-coinbase blocks at heights 91,842 and 91,880 (`BIP30_DUPLICATE_TXID_EXCEPTIONS`, `bip30.rs:7`).
- `check_bip34` (`connect.rs:1291`) runs when `network.is_bip34_active(height)` and delegates to `bip34::check_bip34` (`crates/consensus/src/bip34.rs:5`), which minimally-encodes the height and compares it to the coinbase scriptSig prefix.

Error precedence here is fixed by call order: the early `check_bip34` at `connect.rs:286` runs before the combined check, so a block that violates both BIP34 and BIP30 reports the BIP34 error first; inside the combined check, the duplicate-txid error precedes the second BIP34 check (`connect.rs:1285` then `connect.rs:1287`). Accept and reject outcomes are unaffected by this ordering; only the reported error string differs. Both checks run only at `ApplyIntent::Commit` for the early path and the combined path is unconditional within `BlockRules::check`.

## Undo records

Every committed block produces an `UndoRecord`: the prevouts its inputs spent, built inside `build_block_changes_checked` (`connect.rs:879`). The window stage holds it as `PendingBlockCommit.undo_record` (`window.rs:31`) and `flush` writes all undo rows in the same `CommitRecords` batch as the body rows and durable-head facts (`window.rs:97`). Disconnects load the record back with `load_block_undo_for_block` and replay it through `rollback_block` (`disconnect.rs:80`). A disconnect whose removed outpoints differ from the stored undo fails (`disconnect_refuses_undo_whose_removed_outpoint_differs_from_the_block`, `crates/execution/src/tests/utxo_integrity_tests.rs:170`); a missing or truncated undo keeps state and refuses (`utxo_integrity_tests.rs:235`).

## Reorg attempt and settlement

A reorg is a planned disconnect-then-connect. `plan_reorg` (`crates/execution/src/chain/reorg.rs:9`) walks both tips back to the common ancestor and returns `ReorgPlan { disconnect, connect }`. `switch_to_branch` (`crates/execution/src/reorg.rs:389`) executes it:

1. Plan (`current_reorg_plan`, `reorg.rs:885`), prepare branches (`prepare_branches`, `reorg.rs:350`): resolve both node lists, take a retention lease down to the lowest height touched (`retention_lease_for`, `reorg.rs:312`), and load the connect-side bodies. The streaming windows hold at most 8 disconnect bodies and 8 connect bodies in memory (`DISCONNECT_STREAM_WINDOW` and `CONNECT_STREAM_WINDOW`, `reorg.rs:11`). A missing first connect body stops the plan with `ReorgError::MissingBody { hash, height }` before any mutation (`prepare_branches`, `reorg.rs:375`). Preparation loads only that first window (`load_available_branch_prefix`, `reorg.rs:542`). A gap inside it executes the loaded prefix first and then reports `ReorgError::MissingBody { hash, height }` for the first absent body (`finish_reorg_attempt`, `reorg.rs:505`). A body missing in a later window surfaces as `ReorgError::ConnectBodyLost` from `execute_connect_stream` (`reorg.rs:756`, `:778`) after the disconnects and the earlier windows have run.
2. Lock the transition and re-plan. If the plan changed under the lock, drop it and loop (`reorg.rs:441`).
3. `execute_streamed_plan` (`reorg.rs:685`) disconnects the old branch (undo per block) and connects the new one (full validation per block, streaming the loaded bodies).
4. `finish_reorg_attempt` (`reorg.rs:467`): if the connect side failed with a `Permanent` disposition after some disconnects and zero connects, `restore_disconnected_branch` (`reorg.rs:653`) replays the undo records and puts the old branch back. Restoration failure wraps the error in `RestorationFailed`.
5. Settle (`settle_reorg_transition`, `reorg.rs:903`): run the caller's `settle` callback, then, if `ReorgError::requires_recovery`, call `fail_closed_for_recovery` (`reorg.rs:931`).

`invalidate_block` (`reorg.rs:21`) is the same machinery plus subtree poisoning: after a clean disconnect to below the target, `invalidate_and_republish` (`reorg.rs:128`) marks the subtree invalid in the block tree and republishes the best remaining tip.

## Fatal versus Operational settlement

`classify_apply_error` (`window.rs:343`) sorts every `ApplyError` into one of four dispositions (`WindowApplyDisposition`, `crates/execution/src/lib.rs:1318`):

| Disposition | Cause class | What the node does |
|---|---|---|
| `Permanent` | consensus-invalid block: bad merkle root, `SigopsLimit`, `CoinbaseAmount`, `ProofOfWork`, `NbitsMismatch` | invalidate the block's subtree (`invalidate_permanent_failure`, `window.rs:317`) and return the list of invalidated hashes |
| `BodyMutated` | witness or merkle mutation of a staged body | same as `Operational` for the window; the peer that sent the mutated body is at fault |
| `Operational` | transient or local: `Shutdown`, `ConcurrentChainChange`, disconnect mismatches, missing bodies | stop the window, keep already-committed blocks, let the caller retry |
| `Fatal` | storage engine failures: `UtxoCommit`, `DurableHeadCommit`, `BlockBodyPersistence`, `UndoPersistence`, group flush failure | abandon the group, latch recovery, no retry |

The window treats them asymmetrically (`apply_window_admitted`, `window.rs:240`): a `Fatal` error abandons the staged group and returns immediately; a `Permanent` error first invalidates the offending subtree, then flushes what is still committable; an `Operational` error flushes the staged prefix and reports how many blocks landed in `WindowApplyError.applied`. A flush failure is inherently ambiguous (the durable head may or may not name the batch), so `flush_group` (`window.rs:346`) always converts it to `Fatal`.

`ReorgError::requires_recovery` (`reorg.rs:265`) maps the same rule: `Fatal`, `RestorationFailed`, `TransitionSettlement`, and a `ConnectFailed` whose inner disposition is `Fatal` latch the chainstate closed via `fail_closed_for_recovery`; everything else leaves the node retryable. This is the code side of clause `SYNC-04` in `docs/contracts/synchronization.md`: failed undo, body, UTXO, or durable-head writes settle `Fatal` and the event loop shuts the node down; transient failures hand over to the caller.

## Where this is proven

| Invariant | Test | Location |
|---|---|---|
| A window commits every block in order | `a_window_commits_every_block_in_order` | `crates/execution/src/tests/window_pipeline_tests.rs:188` |
| Duplicate live txid refused at any height | `a_block_with_a_duplicate_live_txid_is_refused_at_any_height` | `crates/execution/src/tests/utxo_integrity_tests.rs:283` |
| Disconnect refuses a mismatching undo | `disconnect_refuses_undo_whose_removed_outpoint_differs_from_the_block` | `crates/execution/src/tests/utxo_integrity_tests.rs:170` |
| Reorg below the retained undo window refuses before mutation | `a_reorg_below_the_retained_undo_window_refuses_before_mutation` | `crates/execution/src/tests/utxo_integrity_tests.rs:348` |
| Fatal pre-transition settlement closes admission | `fatal_pretransition_settlement_closes_admission` | `crates/execution/src/reorg.rs:956` |
| Committed outcome retained, retry forbidden on settlement failure | `committed_connect_settlement_failure_retains_outcome_and_forbids_retry` | `crates/node/src/chain_effects/tests.rs` (clause `SYNC-04` evidence) |

Running the window test at this tree:

```
$ cargo test --offline --locked -p bitcoin-rs-execution \
    a_window_commits_every_block_in_order -- --nocapture
test tests::window_pipeline_tests::a_window_commits_every_block_in_order ... ok
```

Contract clauses named: `SYNC-02`, `SYNC-04`, `SYNC-05`, `RCV-04` to `RCV-08`, `EVT-02` (in `docs/contracts/synchronization.md`), `VAL-02` and `DAA-01` (in `docs/contracts/validation-default.md`).

## Difference from Bitcoin Core

Bitcoin Core flushes coins and connects blocks inside `CoinsViews`/`ApplyChainState` with per-block batch commits and an undo file per block; here the durable head is a single named record advanced by `CommitAuthority::commit_prefix` once per group of up to 64 blocks, and the coin writes in the same batch are the only coin authority. A restart replays any gap between the newest checkpoint and that head. See [how/state-and-storage.md](state-and-storage.md) for the on-disk side and `docs/contracts/synchronization.md` clause `SYNC-05` for the commit-before-publish guarantee.

## Limits

- The group-flush log line (`durable_head: group commit`) was read from source but not observed on regtest; RPC-driven applies take the `PublishMode::Now` path. It fires under p2p window commits only.
- `BodyMutated` handling inside reorg connects (poisoning a body whose witness mutated mid-switch) is exercised by fault-injection tests, not by a live network run.
