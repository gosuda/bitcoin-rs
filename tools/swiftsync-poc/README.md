# SwiftSync prototype

Research record for SwiftSync-style synchronization hints, measured against a
pinned regtest chain. The prototype is offline. It never enters a node build and
it shares no code with `crates/p2p`, `crates/chainstate`, or `crates/index`.

The crate is an independent Cargo workspace, like `tools/ldk` and
`tools/compact-filter-interop`. Root workspace commands do not build it. Use
`--locked` because the crate commits its own `Cargo.lock`.

## What the tool proves

The tool replays a fixed 2,000-block regtest chain two ways and compares the
results.

1. **Fold.** For every block, hash each created output into one MuHash
   aggregate and hash each spent output out of it. The spent coins come from
   the block's undo data. Then hash every hinted coin out of the aggregate.
   If the hint is exactly the set of coins left unspent, the aggregate is the
   MuHash identity.
2. **Reconstruction.** Apply the same blocks to the production in-memory UTXO
   set through `bitcoin_rs_utxo::contract`, then scan the whole set with
   `bitcoin_rs_utxo::stats::scan_coin_stats`. That scan is the code path behind
   `gettxoutsetinfo` with `hash_type = "muhash"`.

The two runs must agree on the end-state MuHash. The fold must also reduce to
the identity after the hinted set is removed, and the hinted set must equal the
reconstructed final set.

## The MuHash element

One coin hashes as this byte string, the same preimage that
`coin_stats.rs` builds for `gettxoutsetinfo`:

```text
outpoint (32-byte txid in wire order, 4-byte vout, little endian)
| (height << 1 | coinbase) as 4 bytes, little endian
| value as 8 bytes, little endian
| script length as a CompactSize
| script
```

The creation height is part of the element. Two creations of one outpoint at
different heights therefore do not cancel each other. The aggregate detects a
BIP30 duplicate for that reason, and not because the hash is set-aware.

## The pinned fixture

The generator uses SplitMix64 with seed `0x5eed0fb17c01d5a3`. Block 0 is the
real regtest genesis. Blocks 1 to 2,000 are mined on top with the regtest target
`0x207fffff`. Each block pays `50 BTC >> (height / 150)`. Block contents come
from the seed alone, so the chain is reproducible on every host.

Recorded reference values for the pinned chain:

| Field | Value |
| :--- | :--- |
| Seed | `0x5eed0fb17c01d5a3` |
| Genesis hash | `0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206` |
| Blocks | 2,001 (genesis plus 2,000) |
| Transactions | 5,622 |
| Tip | `20e1a1db4449918afc8351066331d752e9d75fdfb90b48c82c6b17cb1011dde9` |
| Created outputs | 7,408 |
| Spent outputs | 5,429 |
| Coins unspent at the tip | 1,979 |
| End-state MuHash | `67865891c51a3b035d5d5867fb018b8ebd98ea1f8aa91521e09a664f47ebde11` |

The MuHash above is what the reconstruction computes, and the fold computes the
same value before any hint is applied. The integration test
`fold_of_created_minus_spent_equals_the_reconstruction_muhash` checks that
equality, and `pinned_chain_is_the_regtest_genesis_plus_two_thousand_seeded_blocks`
checks the recorded values.

Fixture limits. The generator never creates two transactions with one txid, so
a BIP30 duplicate needs a hand-built chain. No block spends an output created in
the same block. Every output is a 22-byte version-0 pay-to-witness-public-key-hash
script, so the tool never exercises the OP_RETURN or oversized-script exclusion
rules of the apply path. Both sides hash every output, so a chain containing
such an output would make the fold and the production apply path diverge; the
fixture excludes them for that reason. Every spend has at least 100
confirmations, so coinbase maturity never blocks the fold.

## The three variants and their trust

The prototype separates three shapes that a sync-hint design can take. It
implements variant B. It measures variant A as a check that B also performs.

### Variant A: hash-only commitment

The hint is one hash value at one height, for example an AssumeUTXO `muhash`
anchor. The node folds the range and compares the result.

- Guarantee: the folded set is the committed set, under the collision
  resistance of MuHash. The node that produced the anchor chose when to fold, so
  the anchor is a snapshot at that instant.
- Trust assumption: the anchor is authentic. A wrong anchor rejects a correct
  chain. The fold cannot repair a bad anchor.
- Not checked: nothing about the coin contents. The node ends with a number, and
  holds no coin store.
- Consistency: the anchor names one `(height, block hash)` pair. A consumer MUST
  treat an anchor from another height as unavailable, never as an empty success.

### Variant B: full-set hint

The hint is the complete coin set at the target height. The prototype
implements this: `hints.txt` holds every unspent coin with its outpoint, height,
coinbase flag and output. The fold removes the hinted coins from the aggregate
and requires the identity.

- Guarantee: the hinted set equals the set the chain creates minus the set the
  chain spends. A missing coin leaves its creation in the numerator, and an
  extra coin over-cancels the denominator. Neither survives the identity check.
- Trust assumption: the fold's inputs are authentic. The chain bodies and the
  undo records must be the real chain. The hint itself needs no trust, because
  the check is a proof of equality with the derived multiset.
- Not checked: consensus validity of the bodies. A forged header leaves every
  coin element untouched, so the aggregate still reduces to the identity. The
  structural validator owns that check.
- Consistency: the identity is order-independent and idempotent. A consumer MAY
  re-fold the same range any number of times, and a checkpoint only records how
  far the fold advanced. The hint is a snapshot at one height and one block
  hash; after a reorg the consumer MUST rewind and re-fold before it applies the
  hint again.

### Variant C: spent-set hint

The hint lists the coins that the range spends and that were created before the
range's base height, and the final set is `base_created - spent_hint`. The
prototype does not implement this variant.

- Guarantee: identical to variant B when the spent hint is complete and exact.
- Trust assumption: the same, plus the range MUST start at a known coin set. A
  spend of a coin created before the base cannot be resolved from the range's
  own bodies, so the hint must name that coin.
- Not checked: this prototype cannot measure the variant. Its chain starts at
  the genesis and has no pruned or missing undo path, so no coin is older than
  the range and the hint would be empty.
- Measured limit: a spent coin's hint entry carries the same fields as one undo
  record (outpoint, height, coinbase flag, output), so at equal encoding the
  hint does not shrink bytes against undo. Its size is the intersection of the
  range's spends with the base coin set. On this range 5,429 coins are spent and
  1,979 remain, so a hint that covered every spend would be 2.7 times the size
  of the variant B hint. Variant C therefore wins only where the base is close
  to the target height and most spends are of coins created inside the range.

Also, because the prototype holds undo data, the fold already derives the final
set without any hint. What the hint adds is a proof about an operator-supplied
set, not new information about the chain.

## Which adverse case each check catches

Measured by the integration test suite. "Aggregate" means the MuHash identity
check. "Validator" means `Chain::validate`. The reconstruction comparison is the
extra check that only a node holding the coin set can run.

| Adverse case | Aggregate | Validator | Test |
| :--- | :--- | :--- | :--- |
| Wrong hint value | Detected | Not applicable | `wrong_hint_value_breaks_the_identity` |
| Incomplete hints | Detected | Not applicable | `missing_hint_breaks_the_identity` |
| Extra hinted coin | Detected | Not applicable | `extra_hint_breaks_the_identity` |
| Mismatched undo payload | Detected | Detected (`UndoMismatch`) | `mismatched_undo_data_breaks_the_identity` |
| BIP30 duplicate outpoint at two heights | Detected, because the preimage binds height | Detected (`duplicate txid`) | `duplicate_outpoint_at_two_heights_breaks_the_identity` |
| Invalid proof of work | Missed | Detected (`proof of work`) | `invalid_proof_of_work_is_rejected_by_validation_and_missed_by_the_aggregate` |
| Invalid merkle root | Reaches a non-identity result only because the transaction set changed, so the reason is lost | Detected (`merkle root`) | `a_merkle_root_mismatch_is_rejected_by_validation` |
| Interruption and restart | Detected if the checkpoint is wrong; the resumed fold must equal a single pass | Not applicable | `interrupted_fold_resumes_from_the_checkpoint_without_recounting` |
| Reorg inside the range | Detected as a foreign parent, and only then | Not applicable | `reorg_inside_the_range_needs_a_rewind_and_then_zeros` |
| Immature coinbase spend | Missed | Detected (`coinbase maturity`) | `an_immature_coinbase_spend_is_rejected` |
| Duplicate input in one transaction | Missed | Detected (`duplicate input`) | `a_transaction_spending_one_outpoint_twice_is_rejected` |

The aggregate is therefore a sufficiency check, not a classification. A
non-identity result says "the hint and the chain disagree". It cannot say which
one is wrong. A production design MUST keep the structural and consensus checks
in front of the fold, exactly as the validator sits in front of the replay here.

Two consequences matter for adoption.

1. A same-height duplicate outpoint is invisible to the aggregate, because both
   creations hash to one element. The prototype cannot build one without two
   coinbases in one block, which the validator already rejects. A production
   design still MUST keep the BIP30 rule.
2. A reorg inside the range breaks the fold at the first foreign parent. The
   consumer MUST rewind to the fork point and re-fold. With that rewind the
   ledger test shows the aggregate still reduces to the identity.

## Measurements

Host: Intel Xeon Gold 6138 at 2.00 GHz, 80 hardware threads, Linux 7.0.0,
tmpfs under `/tmp`. Profile: the crate's `release` profile, `opt-level = 3`,
thin LTO, 16 codegen units. Build with `--locked`.

Range: the full pinned chain, 2,001 blocks and 5,622 transactions. Each command
runs in its own process. The timer starts after the chain file is read and
validated, so both figures exclude fixture parsing. Peak RSS is the process
`VmHWM`, so each figure covers one mode in isolation.

Commands, run from `tools/swiftsync-poc`:

```text
cargo run --locked --release -- gen --out /tmp/sspoc
cargo run --locked --release -- sync --chain /tmp/sspoc/chain.txt --hints /tmp/sspoc/hints.txt
cargo run --locked --release -- reconstruct --chain /tmp/sspoc/chain.txt --snapshot /tmp/sspoc/snapshot.bin
```

Three runs of each, in this order:

| Metric | Fold | Reconstruction |
| :--- | :--- | :--- |
| Wall time, ms | 108.3, 107.9, 83.5 | 652.1, 632.2, 626.4 |
| Wall time, median, ms | 107.9 | 632.2 |
| CPU time, ms | 108.3, 107.9, 83.5 | 10,205.3, 10,314.1, 10,490.5 |
| CPU time, median, ms | 107.9 | 10,314.1 |
| Peak RSS, MiB | 8.1, 8.1, 8.1 | 8.8, 8.7, 8.7 |
| Body bytes read | 1,324,877 | 1,324,877 |
| UTXO-set reads | 0 | 5,429 prevout lookups |
| Coin writes | 0 | 7,408 |
| Undo entries read | 5,429 | 5,429 |
| MuHash operations | 14,816 (7,408 inserts, 5,429 undo removals, 1,979 hint removals) | 14,816 (7,408 and 5,429 commit events, then 1,979 in the scan) |
| Final-set memory | 804 bytes of aggregate state | 167,929 bytes accounted for the set |
| Durable output written | 0 (1,719-byte checkpoint only when `--checkpoint` is set) | 145,775-byte native-v4 snapshot |

On this range the fold uses 5.9 times less wall time and 96 times less CPU time
than the reconstruction. The reconstruction CPU figure is the sum over threads,
and the fan-out is in the commit path: `UtxoSet` holds 256 shards,
`commit_multi_shard_with_listener` switches to a rayon `par_iter` once eight
shards are active, and the attached statistics listener folds its event chunks
with a second `par_iter`. The final whole-set scan does not fan out, because
`scan_coin_stats` uses the serial MuHash mode.

Artifact sizes on disk:

| File | Bytes | Contents |
| :--- | :--- | :--- |
| `chain.txt` | 3,502,923 | Block bodies as hex text plus undo records as text |
| `chain.txt` undo records | 677,248 | 5,429 spent coins inside `chain.txt`, as hex text |
| `hints.txt` | 250,111 | 1,979 hinted coins as hex text |
| Hint payload, binary | 131,988 | The same coins in a fixed binary layout |
| `snapshot.bin` | 145,775 | The production native-v4 coin export of the same set |

The hint text encoding is naive: two hex characters per byte and one line per
coin, so the 250,111-byte text file is the largest of the three coin encodings.
The binary payload line is the comparable figure for the same 1,979 coins in a
fixed layout. This record does not rank the two binary encodings: both carry the
same coins and neither is tuned for size, so the 13,787-byte difference says
more about record framing than about the design.

Interruption and restart, measured with `--checkpoint`:

| Step | Result |
| :--- | :--- |
| Crash after 1,500 folded blocks | Exit 1, checkpoint left at 1,400 blocks, 1,719 bytes |
| Resume | 47.4 ms wall, 47.3 ms CPU, 8.1 MiB peak RSS |
| Body bytes folded after resume | 417,821 of 1,324,877 (31.5 percent) |
| Aggregate after resume | Same MuHash as the single pass, identity after the hint |

Scope limits of these numbers.

- The chain is 1.3 MB of bodies. It is a model of a sync range, not a mainnet
  datadir, and the figures scale with the number of coin operations rather than
  with block size.
- The reconstruction writes the whole coin set once, as the node's checkpoint
  export does. It does not model KV or shard write amplification, undo record
  framing, or fsync cost. The fold writes nothing, so the real gap on a large
  range is wider than the table shows, not narrower.
- The reconstruction drives the `bitcoin-rs-utxo` contract directly: it builds
  `BlockChanges`, calls `commit_block_changes`, and scans the set. It does not
  stand up a `Chainstate`, so block-tree, durable-head and publication cost stay
  outside these numbers.
- The fold reads already-decoded rust-bitcoin blocks. The reconstruction
  re-serializes each block to feed the production decoder, so decoding is
  charged to the reconstruction only. Wire decoding is a cost both modes pay.
- Both modes hold the whole chain in memory, so peak RSS is dominated by the
  fixture and does not separate the two modes.
- One range, one seed, one host. No campaign claim is made.

## What a production adoption needs

Read only: this section maps the prototype against the owner contracts. No
contract file was edited.

`docs/contracts/architecture.md`, `ARCH-07` and `ARCH-07a`: chainstate owns
applied-chain mutation, and `bitcoin-rs-utxo` is not a second mutation
authority. A hint import therefore MUST be a chainstate transition, not a
side-channel write into `UtxoSet`. The hinted set MUST enter as a
`VerifiedSnapshotState`-style sealed value with its height, block hash and
commitment, in one atomic batch with its attestation, in the same shape the
prototype's reconstruct export uses. The prototype writes the set through
`write_snapshot_observed`; the matching read side is the production
`read_snapshot_strict_v4` path, which is the seam that would carry the proof.

`docs/contracts/synchronization.md`, `SYNC-01`: a hint is not a progress
authority. The fold's checkpoint is a progress hint, exactly as `SYNC-02`
describes transient work. The prototype enforces that order: the checkpoint only
records folded height, and the resumed run recomputes the aggregate. `SYNC-05`
then forces commit-before-publish: the imported set and its attestation MUST
commit in one batch before any consumer reads them.

`docs/contracts/synchronization.md`, `SYNC-03` and `SYNC-07`: a hinted import
runs as optional work. It MUST NOT hold the live UTXO lock while it folds, and it
MUST NOT discard undo records that an in-flight recovery still needs. The
prototype's fold touches no shared state, which is the property that makes the
claim plausible; the production version needs the existing worker and retention
owners to carry it.

`docs/contracts/recovery.md`, `RCV-02` and `RCV-11`: a hint is a durable
representation with its own version. The attestation row already specified for
script validation is the right shape: bind the row to the head's `commit_id` so
a stale row reads as unattested. A hint-derived set MUST carry its own version
and MUST fail closed on an unknown or mismatched one. The prototype's
checkpoint does the same thing at a smaller scale: a mismatched tip is refused,
never reinterpreted (`CheckpointMismatch`).

`docs/contracts/recovery.md`, `RCV-05` and `RCV-08`: a reorg inside the hinted
range invalidates the hint. The prototype's `Fold::rewind_to` shows the required
shape: rewind to the fork point with the per-block created and spent elements,
then re-fold the new branch. A production version MUST keep the same guarantee
that disconnect restores the pre-connect set exactly (`RCV-08`), so the fold's
ledger and the coin store cannot diverge.

`docs/contracts/indexing.md`, `IDX-02` and `IDX-05`: a hinted import does not
create index rows. `IDX-05` already forbids an index from signalling readiness
above its watermark, so a hint-imported tip MUST leave the index rebuilding from
retained history, and the index MUST NOT treat the imported set as proof of
history. The prototype does not touch an index and makes no claim here.

Concurrency and consistency, named once per invariant:

- The aggregate needs **order-independent** agreement only. MuHash is
  commutative, so a checkpoint written after block N is a legal resume point for
  any later process, and re-folding a block is safe. This is why the checkpoint
  can be a plain file with an atomic rename.
- The hint set needs **snapshot consistency** with one `(height, block hash)`
  pair. A hint read from a different tip is unavailable, not empty.
- The published coin store needs **linearizability** against the applied tip:
  the batch that publishes the set and its attestation is the commit point, and
  no reader may observe the set without the attestation. A transactional
  outbox is not needed here, because the durable head batch already carries the
  row the attestation rides in; the requirement is only that both land in one
  batch.
- Reorg handling is a **saga**: rewind, re-fold, re-attest, then publish. Every
  step must be retryable and idempotent, because the aggregate can be recomputed
  from the chain at any time.

## Reproduce

```text
cd tools/swiftsync-poc
cargo test --locked
cargo run --locked --release -- gen --out /tmp/sspoc
cargo run --locked --release -- sync --chain /tmp/sspoc/chain.txt --hints /tmp/sspoc/hints.txt
cargo run --locked --release -- verify --chain /tmp/sspoc/chain.txt --hints /tmp/sspoc/hints.txt --snapshot /tmp/sspoc/snapshot.bin
```

`verify` runs both modes, then prints the three verdicts: the aggregate is the
identity, the hinted set equals the reconstructed final set, and the folded
MuHash equals the reconstruction's `gettxoutsetinfo` value.

## Test inventory

Seventeen integration tests in `tests/suite.rs`:

| Test | Property under attack |
| :--- | :--- |
| `pinned_chain_is_the_regtest_genesis_plus_two_thousand_seeded_blocks` | The seed reproduces the recorded genesis, tip, counts and MuHash |
| `chain_file_round_trip_preserves_blocks_undo_and_final_set` | The text codec loses no block, undo entry or final coin |
| `fold_of_created_minus_spent_equals_the_reconstruction_muhash` | The fold equals `gettxoutsetinfo` over the production set |
| `hinted_set_equals_the_reconstructed_final_set` | The hint equals the set the production apply path holds |
| `wrong_hint_value_breaks_the_identity` | One shifted value cannot pass the identity check |
| `missing_hint_breaks_the_identity` | One omitted coin cannot pass the identity check |
| `extra_hint_breaks_the_identity` | One invented coin cannot pass the identity check |
| `mismatched_undo_data_breaks_the_identity` | A wrong undo payload cannot pass either check |
| `duplicate_outpoint_at_two_heights_breaks_the_identity` | A BIP30 duplicate is caught, and by which mechanism |
| `invalid_proof_of_work_is_rejected_by_validation_and_missed_by_the_aggregate` | The aggregate never stands in for structural validity |
| `a_merkle_root_mismatch_is_rejected_by_validation` | A changed transaction set fails the root check |
| `interrupted_fold_resumes_from_the_checkpoint_without_recounting` | A resumed fold equals a single pass and re-reads nothing |
| `reorg_inside_the_range_needs_a_rewind_and_then_zeros` | A foreign parent is refused, and a rewind restores the check |
| `hints_with_a_repeated_outpoint_are_refused` | The codec never double-counts a coin |
| `hints_for_another_height_are_refused` | A hint from another tip is unavailable, not accepted |
| `an_immature_coinbase_spend_is_rejected` | Coinbase maturity stays with the validator |
| `a_transaction_spending_one_outpoint_twice_is_rejected` | Duplicate inputs stay with the validator |

Red-before evidence, stated as observed:

- The identity check was first written as a comparison of two `CoinStats`
  values. The happy-path test failed on a correct chain, because `CoinStats`
  derives `PartialEq` over the lazily reduced MuHash representation instead of
  the finalized element. The check now compares finalized digests and the three
  counters. That failure came before the fix.
- The reorg test failed before the fold learned to compare a block's parent
  against the folded tip: it reported a height gap instead of a foreign parent.
- Three mutation probes broke one mechanism each, and the named tests failed:

| Probe | Change | Tests that failed |
| :--- | :--- | :--- |
| Identity check | Weakened to `muhash equal or count zero` | `wrong_hint_value`, `extra_hint`, `mismatched_undo_data` |
| Checkpoint resume | Ignored the stored checkpoint state | `interrupted_fold_resumes_from_the_checkpoint_without_recounting` |
| Undo parity | Skipped the undo payload comparison | `mismatched_undo_data_breaks_the_identity` (validator assertion) |

- The remaining tests were written after their mechanism existed and were green
  on the first run. The probes above are their fault-detection evidence, not a
  per-test red run.

The probes were reverted before the measurements above.

## Decision: continue research

Recommendation: continue research. Do not adopt now.

Why not adopt now:

1. The saving the prototype measures is the coin-store work, not bytes. The
   fold removes 5,429 random prevout reads, 7,408 coin writes and the
   whole-set scan, and it still reads the same bodies and the same undo records.
   In bytes the two modes are close: the fold needs 1,324,877 body bytes, 677,248
   bytes of undo text and a 131,988-byte binary hint, while the reconstruction
   needs the same bodies, the same undo and a 145,775-byte snapshot. The
   5.9-times wall-time saving is real work removed, but a node pays the
   coin-store cost once per block, while a hint saves it once per range.
2. The prototype does not show that a hint is necessary. Because it holds undo
   data, the fold already derives the complete final set without the hint. The
   hint is a redundant second copy that turns the fold into a proof about an
   operator-supplied set. A no-undo fold, which builds each spent element from
   the created set, would need no hint at all for a full-range sync. That variant
   is not implemented or measured.
3. The aggregate cannot reject an invalid body, and it cannot distinguish a bad
   hint from a bad chain. Adoption moves no consensus check, and the design must
   not appear to.

Next concrete trigger for the second step, in order:

1. Add a no-undo fold on the same pinned chain: build each spent element from
   the created set, and measure its memory and wall time against the current
   fold. If it wins, the hint's only remaining role is the commitment check of
   variant A, and the record must say so.
2. Implement variant C above a base height: seed the created set from a base
   snapshot, let the hint carry only the coins created before that base, and
   report its size against the variant B hint at the same height. Continue only
   if the hint is at least 2 times smaller than the full-set hint, which is the
   condition the 2.7-times-larger spent set here fails.
3. Extend the fixture to a chain with same-block spends, OP_RETURN outputs and
   other apply-path exclusions, so the fold is exercised outside the pinned
   shape.
4. Only then write a contract clause set. The clauses needed are a hint-import
   clause beside `ARCH-07a`, a `SYNC-*` clause for optional hint work, and an
   `RCV-*` clause for hint invalidation on reorg.

