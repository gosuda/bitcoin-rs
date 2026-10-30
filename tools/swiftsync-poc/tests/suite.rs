#![expect(clippy::expect_used, reason = "test assertions")]

use bitcoin::{Amount, ScriptBuf, TxOut};

use swiftsync_poc::chain::{
    self, Chain, ChainBuilder, ChainSpec, Spend, coinbase_script, replay_final_set,
};
use swiftsync_poc::fold::{Fold, SyncOptions, sync};
use swiftsync_poc::hints::{HintSet, compare};
use swiftsync_poc::{Error, reconstruct};

const REGTEST_GENESIS: &str = "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206";
const PINNED_TIP: &str = "20e1a1db4449918afc8351066331d752e9d75fdfb90b48c82c6b17cb1011dde9";
const PINNED_MUHASH: &str = "67865891c51a3b035d5d5867fb018b8ebd98ea1f8aa91521e09a664f47ebde11";
const PINNED_TRANSACTIONS: u64 = 5622;
const PINNED_FINAL_COINS: usize = 1979;
const PINNED_CREATED: u64 = 7408;
const PINNED_SPENT: u64 = 5429;

fn short_spec(blocks: u32) -> ChainSpec {
    ChainSpec {
        seed: 0x5eed_0fb1_7c01_d5a3,
        blocks,
    }
}

fn build(blocks: u32) -> Chain {
    let chain = chain::build(short_spec(blocks)).expect("fixture chain builds");
    chain.validate().expect("fixture chain validates");
    chain
}

fn hints_for(chain: &Chain) -> HintSet {
    HintSet::from_chain(chain)
}

fn fold_all(chain: &Chain, hints: &HintSet) -> Result<swiftsync_poc::fold::SyncReport, Error> {
    sync(chain, hints, &SyncOptions::default())
}

#[test]
fn pinned_chain_is_the_regtest_genesis_plus_two_thousand_seeded_blocks() {
    let chain = chain::build(ChainSpec::pinned()).expect("pinned chain builds");
    chain.validate().expect("pinned chain validates");
    assert_eq!(
        chain.blocks[0].hash().to_string(),
        REGTEST_GENESIS,
        "block zero must be the reference regtest genesis, not a synthesized header"
    );
    assert_eq!(chain.height(), 2000, "genesis plus 2,000 seeded blocks");
    assert_eq!(
        chain.transaction_count(),
        PINNED_TRANSACTIONS,
        "recorded transaction count of the seeded fixture"
    );
    assert_eq!(
        chain.tip().to_string(),
        PINNED_TIP,
        "the fixed seed must reproduce the recorded tip"
    );
    assert_eq!(
        chain.final_set.len(),
        PINNED_FINAL_COINS,
        "recorded count of coins left unspent at the tip"
    );
    let oracle = reconstruct(&chain, None).expect("reconstruction runs");
    assert_eq!(
        oracle.muhash.to_string_be(),
        PINNED_MUHASH,
        "bitcoin-rs gettxoutsetinfo muhash of the fixture final set"
    );
}

#[test]
fn chain_file_round_trip_preserves_blocks_undo_and_final_set() {
    let chain = build(300);
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("chain.txt");
    chain.write(&path).expect("chain file writes");
    let loaded = Chain::read(&path).expect("chain file reads");
    assert_eq!(loaded.blocks.len(), chain.blocks.len(), "block count");
    assert_eq!(
        loaded.tip(),
        chain.tip(),
        "tip after a chain file round trip"
    );
    for (written, read) in chain.blocks.iter().zip(&loaded.blocks) {
        assert_eq!(
            read.undo, written.undo,
            "undo data at height {} survives the text codec",
            written.height
        );
        assert_eq!(
            read.block, written.block,
            "block bytes at height {} survive the text codec",
            written.height
        );
    }
    assert_eq!(
        loaded.final_set, chain.final_set,
        "final set recomputed from the codec equals the builder's live set"
    );
    assert_eq!(
        replay_final_set(&loaded.blocks).expect("replay"),
        chain.final_set,
        "independent replay of the decoded blocks equals the builder's live set"
    );
}

#[test]
fn fold_of_created_minus_spent_equals_the_reconstruction_muhash() {
    let chain = chain::build(ChainSpec::pinned()).expect("pinned chain builds");
    let hints = hints_for(&chain);
    let report = fold_all(&chain, &hints).expect("honest chain and hints zero the aggregate");
    let reconstruction = reconstruct(&chain, None).expect("reconstruction runs");
    assert_eq!(
        report.created, PINNED_CREATED,
        "recorded created-output count of the fixture"
    );
    assert_eq!(
        report.spent, PINNED_SPENT,
        "recorded spent-output count of the fixture"
    );
    assert_eq!(
        usize::try_from(report.hint_coins).expect("hint count fits in usize"),
        PINNED_FINAL_COINS,
        "hint size equals the final coin count"
    );
    assert_eq!(
        report.folded_muhash, reconstruction.muhash,
        "the folded created-minus-spent MuHash must equal the gettxoutsetinfo scan"
    );
    assert_eq!(
        reconstruction.coins_written, report.created,
        "the reconstruction writes one coin per created output"
    );
    assert_eq!(
        reconstruction.undo_entries, report.spent,
        "the reconstruction resolves one prevout per spent output"
    );
    assert_eq!(
        reconstruction.prevout_reads, report.spent,
        "prevout reads equal resolved spends on a chain without same-block spends"
    );
}

#[test]
fn hinted_set_equals_the_reconstructed_final_set() {
    let chain = build(300);
    let hints = hints_for(&chain);
    let loaded = HintSet::decode(&hints.encode()).expect("hints codec round trips");
    assert_eq!(loaded, hints, "hints text codec is lossless");
    let diff = compare(&loaded, &chain.final_set);
    assert!(
        diff.is_empty(),
        "hint set built from the final set must differ in no coin: {diff:?}"
    );
    let reconstruction = reconstruct(&chain, None).expect("reconstruction runs");
    assert_eq!(
        u64::try_from(hints.coins.len()).expect("coin count fits in u64"),
        reconstruction.coins,
        "hint size equals the production UTXO-set size"
    );
}

#[test]
fn wrong_hint_value_breaks_the_identity() {
    let chain = build(300);
    let mut hints = hints_for(&chain);
    let outpoint = *hints.coins.keys().next().expect("hints are not empty");
    let coin = hints.coins.get_mut(&outpoint).expect("present");
    coin.txout.value += bitcoin::Amount::from_sat(1);
    let error = fold_all(&chain, &hints).expect_err("a shifted value must not zero");
    assert!(
        matches!(error, Error::AggregateNotZero { .. }),
        "the aggregate is the only signal a node has; got {error}"
    );
    assert_eq!(
        compare(&hints, &chain.final_set).mismatched,
        1,
        "the reconstruction control sees exactly one mismatched coin"
    );
}

#[test]
fn missing_hint_breaks_the_identity() {
    let chain = build(300);
    let mut hints = hints_for(&chain);
    let outpoint = *hints.coins.keys().next().expect("hints are not empty");
    hints.coins.remove(&outpoint);
    let error = fold_all(&chain, &hints).expect_err("an incomplete hint must not zero");
    assert!(
        matches!(error, Error::AggregateNotZero { .. }),
        "an omitted coin leaves its created element uncancelled; got {error}"
    );
    assert_eq!(
        compare(&hints, &chain.final_set).missing,
        1,
        "the reconstruction control sees exactly one missing coin"
    );
}

#[test]
fn extra_hint_breaks_the_identity() {
    let chain = build(300);
    let mut hints = hints_for(&chain);
    let spent = chain
        .blocks
        .iter()
        .find(|block| !block.undo.is_empty())
        .and_then(|block| block.undo.first())
        .expect("the fixture spends at least one coin");
    hints.coins.insert(spent.outpoint, spent.coin.clone());
    let error = fold_all(&chain, &hints).expect_err("an extra hint must not zero");
    assert!(
        matches!(error, Error::AggregateNotZero { .. }),
        "an invented coin over-cancels the aggregate; got {error}"
    );
    assert_eq!(
        compare(&hints, &chain.final_set).extra,
        1,
        "the reconstruction control sees exactly one extra coin"
    );
}

#[test]
fn mismatched_undo_data_breaks_the_identity() {
    let mut chain = build(300);
    let mut blocked = false;
    for block in &mut chain.blocks {
        let Some(entry) = block.undo.first_mut() else {
            continue;
        };
        entry.coin.txout.value += bitcoin::Amount::from_sat(1);
        blocked = true;
        break;
    }
    assert!(blocked, "the fixture spends at least one coin");
    let hints = hints_for(&chain);
    let error = fold_all(&chain, &hints).expect_err("a wrong undo payload must not zero");
    assert!(
        matches!(error, Error::AggregateNotZero { .. }),
        "the aggregate removes a different element than the block created; got {error}"
    );
    let validation = chain
        .validate()
        .expect_err("the structural undo check refuses it");
    assert!(
        matches!(validation, Error::UndoMismatch { .. }),
        "undo parity is the validator's check, not the aggregate's; got {validation}"
    );
}

#[test]
fn duplicate_outpoint_at_two_heights_breaks_the_identity() {
    let duplicate_script = b"\x04duplicate-outpoint\x00";
    let mut builder = ChainBuilder::new(0xb1_3000_0000_0001);
    builder
        .append_with_coinbase(duplicate_script, Vec::new())
        .expect("height 1");
    for _ in 0..100 {
        let next = builder.height().saturating_add(1);
        let script = coinbase_script(next, 7);
        builder
            .append_with_coinbase(&script, Vec::new())
            .expect("coinbase-only block");
    }
    builder
        .append_with_coinbase(duplicate_script, Vec::new())
        .expect("height 102");
    let chain = builder.finish();
    let validation = chain
        .validate()
        .expect_err("BIP30 refuses a txid that still has unspent outputs");
    assert!(
        matches!(
            validation,
            Error::InvalidBlock {
                check: "duplicate txid",
                ..
            }
        ),
        "the consensus rule is the primary guard; got {validation}"
    );
    let hints = hints_for(&chain);
    let error = fold_all(&chain, &hints).expect_err("the aggregate must not zero");
    assert!(
        matches!(error, Error::AggregateNotZero { .. }),
        "both creations differ in the preimage, so the overwritten coin stays in the numerator; got {error}"
    );
}

#[test]
fn invalid_proof_of_work_is_rejected_by_validation_and_missed_by_the_aggregate() {
    let mut chain = build(300);
    let last = chain.blocks.last_mut().expect("chain has blocks");
    let target = bitcoin::Target::from_compact(last.block.header.bits);
    let mut attempts = 0_u32;
    while last.block.header.validate_pow(target).is_ok() {
        last.block.header.nonce = last.block.header.nonce.wrapping_add(1);
        attempts = attempts.saturating_add(1);
        assert!(attempts < 64, "the regtest target is too easy to miss");
    }
    let validation = chain
        .validate()
        .expect_err("a regenerated nonce must not satisfy proof of work");
    assert!(
        matches!(
            validation,
            Error::InvalidBlock {
                check: "proof of work",
                ..
            }
        ),
        "the structural check owns proof of work; got {validation}"
    );
    let hints = hints_for(&chain);
    fold_all(&chain, &hints).expect(
        "the aggregate still zeros: only the structural validator can reject a forged header",
    );
}

#[test]
fn interrupted_fold_resumes_from_the_checkpoint_without_recounting() {
    let chain = build(300);
    let hints = hints_for(&chain);
    let total_body_bytes: u64 = chain
        .blocks
        .iter()
        .map(|block| u64::from(block.wire_len))
        .sum();
    let dir = tempfile::tempdir().expect("tempdir");
    let checkpoint = dir.path().join("checkpoint");
    let crashing = SyncOptions {
        checkpoint: Some(&checkpoint),
        checkpoint_every: 100,
        simulate_crash_after: Some(150),
    };
    let crash =
        sync(&chain, &hints, &crashing).expect_err("the simulated crash interrupts the fold");
    assert!(
        matches!(crash, Error::SimulatedCrash { folded: 150 }),
        "the crash lands after 150 folded blocks; got {crash}"
    );
    assert!(
        checkpoint.exists(),
        "the last interval checkpoint survives the crash"
    );
    let resumed = sync(
        &chain,
        &hints,
        &SyncOptions {
            checkpoint: Some(&checkpoint),
            checkpoint_every: 100,
            simulate_crash_after: None,
        },
    )
    .expect("the resumed run completes");
    assert_eq!(
        resumed.resumed_from, 100,
        "resume starts at the last checkpoint"
    );
    assert_eq!(
        resumed.folded, 301,
        "the resumed run folds every block once"
    );
    assert!(
        resumed.body_bytes < total_body_bytes,
        "resume must not re-pay the folded prefix: {} of {total_body_bytes} body bytes",
        resumed.body_bytes
    );
    assert_eq!(
        resumed.folded_muhash,
        fold_all(&chain, &hints).expect("single pass").folded_muhash,
        "a resumed fold must equal a single-pass fold"
    );
    assert!(
        !checkpoint.exists(),
        "a completed run removes its progress checkpoint"
    );
}

#[test]
fn reorg_inside_the_range_needs_a_rewind_and_then_zeros() {
    let branch_a = build(400);
    let mut fork = ChainBuilder::from_prefix(&branch_a, 200, 0xf02c_0000_0001)
        .expect("fork builder starts from a validated prefix");
    for _ in 0..200 {
        fork.append_random().expect("fork block");
    }
    let branch_b = fork.finish();
    branch_b.validate().expect("the fork validates on its own");

    let mut fold = Fold::new();
    for carried in branch_a.blocks.iter().take(251) {
        fold.fold_block(carried).expect("fold branch A prefix");
    }
    let error = fold
        .fold_block(&branch_b.blocks[251])
        .expect_err("a foreign parent is not silently folded");
    assert!(
        matches!(error, Error::ReorgDetected { height: 251, .. }),
        "the fold refuses a branch it did not follow; got {error}"
    );
    fold.rewind_to(201, &branch_a)
        .expect("rewind to the fork point");
    for carried in branch_b.blocks.iter().skip(201) {
        fold.fold_block(carried).expect("fold branch B");
    }
    let hints_b = hints_for(&branch_b);
    let report = fold
        .finish(&hints_b)
        .expect("the aggregate zeros after a correct rewind");
    assert_eq!(report.folded, 401, "the fold covers the whole new branch");
    let control = fold_all(&branch_b, &hints_b).expect("single-pass control");
    assert_eq!(
        report.folded_muhash, control.folded_muhash,
        "rewind plus re-fold must equal a single pass over the surviving branch"
    );
}

#[test]
fn a_merkle_root_mismatch_is_rejected_by_validation() {
    let mut chain = build(300);
    let block = &mut chain.blocks[100];
    block.block.txdata[0].output[0].value = Amount::from_sat(1);
    let error = chain
        .validate()
        .expect_err("a changed coinbase output leaves the header root stale");
    assert!(
        matches!(
            error,
            Error::InvalidBlock {
                check: "merkle root",
                ..
            }
        ),
        "the structural check owns the root; got {error}"
    );
}

#[test]
fn hints_with_a_repeated_outpoint_are_refused() {
    let chain = build(300);
    let text = hints_for(&chain).encode();
    let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
    let duplicate = lines[3].clone();
    lines.push(duplicate);
    let error = HintSet::decode(&lines.join("\n")).expect_err("a repeated outpoint is refused");
    assert!(
        matches!(error, Error::HintDuplicate { .. }),
        "the codec refuses a hint that would double-count a coin; got {error}"
    );
}

#[test]
fn hints_for_another_height_are_refused() {
    let chain = build(300);
    let mut hints = hints_for(&chain);
    hints.height = 400;
    let error = fold_all(&chain, &hints).expect_err("a hint for another tip is refused");
    assert!(
        matches!(error, Error::HintHeight { .. }),
        "a hint that names a different target cannot be checked; got {error}"
    );
}

#[test]
fn an_immature_coinbase_spend_is_rejected() {
    let mut builder = ChainBuilder::new(0x0000_c0ff_ee00_0001);
    builder
        .append_with_coinbase(b"\x04one\x00", Vec::new())
        .expect("height 1");
    let coinbase_coin = *builder
        .live()
        .keys()
        .next()
        .expect("the height 1 coinbase is the only coin");
    let spend = Spend::new(
        vec![coinbase_coin],
        vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    );
    builder
        .append_with_coinbase(b"\x04two\x00", vec![spend])
        .expect("the builder never checks maturity");
    let chain = builder.finish();
    let error = chain
        .validate()
        .expect_err("spending a coinbase with zero confirmations is invalid");
    assert!(
        matches!(
            error,
            Error::InvalidBlock {
                check: "coinbase maturity",
                height: 2,
            }
        ),
        "maturity is the validator's rule; got {error}"
    );
}

#[test]
fn a_transaction_spending_one_outpoint_twice_is_rejected() {
    let mut builder = ChainBuilder::new(0x0000_d0b1_0000_0001);
    builder
        .append_with_coinbase(b"\x04one\x00", Vec::new())
        .expect("height 1");
    for _ in 2..=101 {
        let next = builder.height().saturating_add(1);
        let script = coinbase_script(next, 3);
        builder
            .append_with_coinbase(&script, Vec::new())
            .expect("coinbase-only block");
    }
    let mature_coin = *builder
        .live()
        .iter()
        .find(|(_, coin)| coin.height == 1)
        .map(|(outpoint, _)| outpoint)
        .expect("the height 1 coinbase matured unspent");
    let spend = Spend::new(
        vec![mature_coin, mature_coin],
        vec![TxOut {
            value: Amount::from_sat(50_0000_0000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    );
    builder
        .append_with_coinbase(b"\x04two\x00", vec![spend])
        .expect("the builder never deduplicates inputs");
    let chain = builder.finish();
    let error = chain
        .validate()
        .expect_err("one outpoint cannot fund two inputs of the same transaction");
    assert!(
        matches!(
            error,
            Error::InvalidBlock {
                check: "duplicate input",
                height: 102,
            }
        ),
        "duplicate inputs are the validator's rule; got {error}"
    );
}
