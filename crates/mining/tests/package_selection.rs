//! Ancestor-package selection: topological order, whole-package admission,
//! child-pays-for-parent, and the sigop and coinbase-reserve budgets.

use std::error::Error;
use std::sync::Arc;

use bitcoin::hashes::Hash as _;
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
    transaction::Version,
};
use bitcoin_rs_mempool::{EntryId, Mempool, MempoolEntry, MempoolLimits};
use bitcoin_rs_mining::{
    BlockTemplate, BlockTemplateParams, DEFAULT_BLOCK_RESERVED_WEIGHT, MiningPolicy,
};
use bitcoin_rs_primitives::Hash256;

const SIGOP_BUDGET: u32 = 80_000;

/// A pool with no fee floor, so a deliberately cheap parent can be seeded.
fn pool() -> Mempool {
    Mempool::new(MempoolLimits {
        min_relay_fee_sat_per_kvb: 0,
        ..MempoolLimits::default()
    })
}

fn confirmed_outpoint(tag: u8) -> OutPoint {
    OutPoint::new(Txid::from_byte_array([tag; 32]), 0)
}

fn tx_spending(previous_output: OutPoint, tag: u8) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output,
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51, tag]),
        }],
    }
}

fn insert(
    pool: &mut Mempool,
    tx: Transaction,
    fee: u64,
    time: u64,
) -> Result<EntryId, Box<dyn Error>> {
    let vsize = u32::try_from(tx.vsize())?;
    Ok(pool.insert_entry(MempoolEntry::new(Arc::new(tx), vsize, fee, time, 0))?)
}

fn insert_with_sigops(
    pool: &mut Mempool,
    tx: Transaction,
    fee: u64,
    time: u64,
    sigops: u32,
) -> Result<EntryId, Box<dyn Error>> {
    let vsize = u32::try_from(tx.vsize())?;
    Ok(pool.insert_entry(
        MempoolEntry::new(Arc::new(tx), vsize, fee, time, 0).with_sigop_cost(sigops),
    )?)
}

fn weight_of(pool: &Mempool, id: EntryId) -> u64 {
    pool.entry(id).map_or(0, |entry| entry.tx.weight().to_wu())
}

fn position(selected: &[EntryId], id: EntryId) -> Option<usize> {
    selected.iter().position(|candidate| *candidate == id)
}

/// Fee-rate order alone puts the child first; the result must not.
#[test]
fn a_parent_always_precedes_its_child() -> Result<(), Box<dyn Error>> {
    let mut pool = pool();
    let parent = tx_spending(confirmed_outpoint(1), 1);
    let parent_txid = parent.compute_txid();
    // Cheap parent, expensive child: sorted by own fee rate the child wins.
    let parent_id = insert(&mut pool, parent, 100, 0)?;
    let child_id = insert(
        &mut pool,
        tx_spending(OutPoint::new(parent_txid, 0), 2),
        100_000,
        1,
    )?;

    let selected = MiningPolicy.select_transactions(&pool, 4_000_000, SIGOP_BUDGET);

    let (Some(parent_at), Some(child_at)) = (
        position(&selected, parent_id),
        position(&selected, child_id),
    ) else {
        panic!("both transactions fit and must both be selected: {selected:?}");
    };
    assert!(
        parent_at < child_at,
        "the parent must come first, got parent at {parent_at} and child at {child_at}"
    );
    Ok(())
}

/// Entry ids are not a dependency order, and this is the case that proves it.
///
/// The mempool's arena reuses freed slots, so a parent accepted while the low
/// slots are occupied, whose neighbours are then removed, ends up with a
/// **higher** id than a child inserted afterwards. Anything that sorts by id
/// and calls the result topological emits the child first here.
#[test]
fn entry_ids_are_not_a_dependency_order() -> Result<(), Box<dyn Error>> {
    let mut pool = pool();

    // Occupy the low slots.
    let mut fillers = Vec::new();
    for tag in 10_u8..15 {
        fillers.push(insert(
            &mut pool,
            tx_spending(confirmed_outpoint(tag), tag),
            1_000,
            0,
        )?);
    }

    let parent = tx_spending(confirmed_outpoint(1), 1);
    let parent_txid = parent.compute_txid();
    // Cheap parent, rich child, so the child is reached first and its package
    // is built as one unit containing both. With a parent cheap enough to be
    // visited on its own turn instead, the two land in separate one-element
    // packages and no ordering inside a package is ever exercised.
    let parent_id = insert(&mut pool, parent, 1, 1)?;

    // Free the low slots, then insert the child into one of them.
    for filler in fillers {
        let _removed = pool.remove_entry_and_descendants(filler);
    }
    let child_id = insert(
        &mut pool,
        tx_spending(OutPoint::new(parent_txid, 0), 2),
        1_000_000,
        2,
    )?;

    assert!(
        child_id < parent_id,
        "the fixture must give the child a lower id than its parent \
         (child {child_id}, parent {parent_id}) or it proves nothing"
    );

    let selected = MiningPolicy.select_transactions(&pool, 4_000_000, SIGOP_BUDGET);

    let (Some(parent_at), Some(child_at)) = (
        position(&selected, parent_id),
        position(&selected, child_id),
    ) else {
        panic!("both must be selected: {selected:?}");
    };
    assert!(
        parent_at < child_at,
        "the parent must still come first when its id is the higher one"
    );
    Ok(())
}

/// A package that does not fit is skipped whole, never truncated.
#[test]
fn a_child_is_never_taken_without_its_parent() -> Result<(), Box<dyn Error>> {
    let mut pool = pool();
    let parent = tx_spending(confirmed_outpoint(1), 1);
    let parent_txid = parent.compute_txid();
    let parent_id = insert(&mut pool, parent, 100, 0)?;
    let child_id = insert(
        &mut pool,
        tx_spending(OutPoint::new(parent_txid, 0), 2),
        100_000,
        1,
    )?;

    // Room for exactly one of the two, so a cut-off inside the package is
    // the failure this guards against.
    let budget = u32::try_from(weight_of(&pool, parent_id) + weight_of(&pool, child_id) - 1)?;
    let selected = MiningPolicy.select_transactions(&pool, budget, SIGOP_BUDGET);

    assert!(
        position(&selected, child_id).is_none(),
        "the child must not be selected without its parent: {selected:?}"
    );
    Ok(())
}

/// Child-pays-for-parent: the child's fee lifts the parent into the block.
///
/// The parent's own fee rate is the lowest in the pool, so own-fee-rate order
/// drops it — and drops the child with it, since the child cannot be mined
/// alone.
#[test]
fn a_high_fee_child_pulls_its_low_fee_parent_in() -> Result<(), Box<dyn Error>> {
    let mut pool = pool();
    let parent = tx_spending(confirmed_outpoint(1), 1);
    let parent_txid = parent.compute_txid();
    let parent_id = insert(&mut pool, parent, 1, 0)?;
    let child_id = insert(
        &mut pool,
        tx_spending(OutPoint::new(parent_txid, 0), 2),
        1_000_000,
        1,
    )?;
    // A middling competitor that beats the parent on its own fee rate.
    let rival_id = insert(&mut pool, tx_spending(confirmed_outpoint(3), 3), 5_000, 2)?;

    let package_weight = weight_of(&pool, parent_id) + weight_of(&pool, child_id);
    // Room for the package or the rival, not both.
    let budget = u32::try_from(package_weight + weight_of(&pool, rival_id) - 1)?;
    let selected = MiningPolicy.select_transactions(&pool, budget, SIGOP_BUDGET);

    assert!(
        position(&selected, parent_id).is_some() && position(&selected, child_id).is_some(),
        "the package must win on its ancestor fee rate: {selected:?}"
    );
    assert!(
        position(&selected, rival_id).is_none(),
        "the rival must lose to the package, or the budget did not bind"
    );
    Ok(())
}

/// The sigop budget bounds the block, using the count acceptance derived.
#[test]
fn the_sigop_budget_excludes_what_does_not_fit() -> Result<(), Box<dyn Error>> {
    let mut pool = pool();
    let cheap = insert_with_sigops(
        &mut pool,
        tx_spending(confirmed_outpoint(1), 1),
        10_000,
        0,
        10,
    )?;
    let heavy = insert_with_sigops(
        &mut pool,
        tx_spending(confirmed_outpoint(2), 2),
        9_000,
        1,
        5_000,
    )?;

    let generous = MiningPolicy.select_transactions(&pool, 4_000_000, SIGOP_BUDGET);
    assert!(
        position(&generous, heavy).is_some(),
        "with a generous budget both must fit, or the tight case proves nothing"
    );

    let tight = MiningPolicy.select_transactions(&pool, 4_000_000, 100);
    assert!(
        position(&tight, cheap).is_some(),
        "the ten-sigop transaction still fits a budget of a hundred"
    );
    assert!(
        position(&tight, heavy).is_none(),
        "the five-thousand-sigop transaction must not: {tight:?}"
    );
    Ok(())
}

/// Candidates are ordered by **ancestor** fee rate, not by their own.
///
/// For a plain two-transaction chain the two orders agree, so this needs the
/// case where they do not: a rich child whose parent is large and cheap. The
/// child's own fee rate is the highest in the pool, but the package it drags
/// along pays poorly per weight unit — and taking it costs the room several
/// better-paying independent transactions would have used.
///
/// Ordering by own fee rate takes the package and earns less from the same
/// space. That is the whole reason Core sorts by ancestor fee rate.
#[test]
fn candidates_are_ordered_by_ancestor_fee_rate() -> Result<(), Box<dyn Error>> {
    let mut pool = pool();

    // Large and cheap.
    let mut parent = tx_spending(confirmed_outpoint(1), 1);
    for tag in 40_u8..95 {
        parent.output.push(TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51, tag]),
        });
    }
    let parent_txid = parent.compute_txid();
    let parent_id = insert(&mut pool, parent, 800, 0)?;
    // Small and rich: the highest own fee rate in the pool.
    let child_id = insert(
        &mut pool,
        tx_spending(OutPoint::new(parent_txid, 0), 2),
        110_000,
        1,
    )?;

    // Independent transactions that beat the package per weight unit.
    let mut rivals = Vec::new();
    for tag in 2_u8..10 {
        rivals.push(insert(
            &mut pool,
            tx_spending(confirmed_outpoint(tag), tag),
            22_000,
            u64::from(tag),
        )?);
    }

    let package_weight = weight_of(&pool, parent_id) + weight_of(&pool, child_id);
    let rivals_weight = rivals.iter().map(|id| weight_of(&pool, *id)).sum::<u64>();
    assert!(
        rivals_weight <= package_weight,
        "the rivals must fit in the package's room ({rivals_weight} vs {package_weight})"
    );
    let rivals_fee = 22_000_u64 * 8;
    assert!(
        rivals_fee > 110_800,
        "the rivals must out-earn the package or the ordering is not the point"
    );

    let budget = u32::try_from(package_weight)?;
    let selected = MiningPolicy.select_transactions(&pool, budget, SIGOP_BUDGET);

    assert!(
        position(&selected, child_id).is_none() && position(&selected, parent_id).is_none(),
        "the poorly-paying package must lose its place: {selected:?}"
    );
    for rival in rivals {
        assert!(
            position(&selected, rival).is_some(),
            "every better-paying transaction must be taken: {selected:?}"
        );
    }
    Ok(())
}

/// A package too big for the remaining room is skipped, not a stop signal.
///
/// Core's assembler keeps going: a smaller candidate further down the order
/// can still fill what is left. Stopping at the first miss silently drops
/// every transaction behind it, and no ordering assertion can see that — the
/// block simply comes out smaller than it should.
#[test]
fn a_package_that_does_not_fit_does_not_end_selection() -> Result<(), Box<dyn Error>> {
    let mut pool = pool();
    // Highest ancestor fee rate, and deliberately the widest.
    let mut wide = tx_spending(confirmed_outpoint(1), 1);
    for tag in 20_u8..40 {
        wide.output.push(TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51, tag]),
        });
    }
    let wide_id = insert(&mut pool, wide, 1_000_000, 0)?;
    let narrow_id = insert(&mut pool, tx_spending(confirmed_outpoint(2), 2), 1_000, 1)?;

    let wide_weight = weight_of(&pool, wide_id);
    let narrow_weight = weight_of(&pool, narrow_id);
    assert!(
        narrow_weight < wide_weight,
        "the second candidate must be the smaller one or the case is empty"
    );

    // Room for the narrow transaction but not the wide one, which sorts first.
    let budget = u32::try_from(wide_weight - 1)?;
    let selected = MiningPolicy.select_transactions(&pool, budget, SIGOP_BUDGET);

    assert!(
        position(&selected, wide_id).is_none(),
        "the wide transaction does not fit: {selected:?}"
    );
    assert!(
        position(&selected, narrow_id).is_some(),
        "selection must continue past it and take the one that does fit"
    );
    Ok(())
}

/// The template reports the sigop cost it selected against.
///
/// The budget being enforced internally is not the same claim as the miner
/// being told the number: `sigops` was hardcoded to zero, and a miner cannot
/// budget against `sigoplimit` from a list that says every transaction is free.
#[test]
fn the_template_reports_each_transaction_sigop_cost() -> Result<(), Box<dyn Error>> {
    let mut pool = pool();
    let id = insert_with_sigops(
        &mut pool,
        tx_spending(confirmed_outpoint(1), 1),
        10_000,
        0,
        42,
    )?;
    assert_eq!(pool.entry(id).map(|entry| entry.sigop_cost), Some(42));

    let template = BlockTemplate::from_mempool(&pool, &MiningPolicy, params(4_000_000))?;

    let Some(entry) = template.transactions.first() else {
        panic!("the transaction must be selected");
    };
    assert_eq!(
        entry.sigops, 42,
        "the template must carry the count acceptance derived"
    );
    assert_eq!(template.sigoplimit, SIGOP_BUDGET);
    Ok(())
}

fn params(max_weight: u32) -> BlockTemplateParams {
    BlockTemplateParams {
        previous_block_hash: Hash256::from_le_bytes(&[1_u8; 32]),
        height: 800_001,
        version: 0x2000_0000,
        bits: "17034219".to_owned(),
        target: "0000000000000000000342190000000000000000000000000000000000000000".to_owned(),
        min_time: 1_700_000_000,
        current_time: 1_700_000_123,
        long_poll_id: "synthetic".to_owned(),
        max_weight,
        max_sigops: SIGOP_BUDGET,
        max_size: 4_000_000,
    }
}

/// The template holds back room for the coinbase it does not itself build.
///
/// Selection runs against `max_weight - DEFAULT_BLOCK_RESERVED_WEIGHT`, while
/// `weightlimit` still reports the full figure. Filling the advertised limit
/// and then adding a coinbase is how a miner builds an oversize block.
#[test]
fn the_coinbase_reserve_is_held_back_from_selection() -> Result<(), Box<dyn Error>> {
    let mut pool = pool();
    let id = insert(&mut pool, tx_spending(confirmed_outpoint(1), 1), 10_000, 0)?;
    let weight = u32::try_from(weight_of(&pool, id))?;

    // Exactly enough for the transaction if the reserve is ignored, and one
    // weight unit short once it is honoured.
    let max_weight = DEFAULT_BLOCK_RESERVED_WEIGHT + weight - 1;
    let template = BlockTemplate::from_mempool(&pool, &MiningPolicy, params(max_weight))?;

    assert!(
        template.transactions.is_empty(),
        "the reserve must be subtracted before selection"
    );
    assert_eq!(
        template.weightlimit, max_weight,
        "the advertised limit stays the full figure"
    );

    // One more weight unit of room and it fits, so the emptiness above is the
    // reserve and not something else refusing the transaction.
    let template = BlockTemplate::from_mempool(&pool, &MiningPolicy, params(max_weight + 1))?;
    assert_eq!(template.transactions.len(), 1);
    Ok(())
}

/// The advertised commitment must match the block the template describes.
///
/// Checked against rust-bitcoin's own `witness_root` / `compute_witness_commitment`
/// over a block assembled from the template, rather than against a number
/// copied out of this implementation.
#[test]
fn the_witness_commitment_matches_the_selected_set() -> Result<(), Box<dyn Error>> {
    let mut pool = pool();
    let parent = tx_spending(confirmed_outpoint(1), 1);
    let parent_txid = parent.compute_txid();
    let _parent = insert(&mut pool, parent, 10_000, 0)?;
    let _child = insert(
        &mut pool,
        tx_spending(OutPoint::new(parent_txid, 0), 2),
        20_000,
        1,
    )?;

    let template = BlockTemplate::from_mempool(&pool, &MiningPolicy, params(4_000_000))?;
    assert_eq!(template.transactions.len(), 2, "both must be selected");

    // Rebuild the block the template describes: a coinbase plus the selected
    // transactions, in the order the template lists them.
    let mut txdata = vec![coinbase()];
    for entry in &template.transactions {
        let bytes = <Vec<u8> as bitcoin::hex::FromHex>::from_hex(&entry.data)?;
        txdata.push(bitcoin::consensus::deserialize::<Transaction>(&bytes)?);
    }
    let block = bitcoin::Block {
        header: header(),
        txdata,
    };
    let Some(witness_root) = block.witness_root() else {
        panic!("the witness root must be computable");
    };
    let expected =
        bitcoin::Block::compute_witness_commitment(&witness_root, &[0_u8; 32]).to_byte_array();

    let advertised =
        <Vec<u8> as bitcoin::hex::FromHex>::from_hex(&template.default_witness_commitment)?;
    // OP_RETURN, push of 36, the four-byte tag, then the 32-byte commitment.
    let Some(commitment) = advertised.get(6..38) else {
        panic!("the commitment script is too short: {advertised:?}");
    };
    assert_eq!(
        commitment,
        expected.as_slice(),
        "the advertised commitment must describe the transactions the template selected"
    );
    Ok(())
}

fn coinbase() -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(vec![0x03, 0x01, 0x02, 0x03]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
        }],
    }
}

fn header() -> bitcoin::block::Header {
    bitcoin::block::Header {
        version: bitcoin::block::Version::TWO,
        prev_blockhash: bitcoin::BlockHash::from_byte_array([0_u8; 32]),
        merkle_root: bitcoin::TxMerkleNode::from_byte_array([0_u8; 32]),
        time: 1_700_000_000,
        bits: bitcoin::CompactTarget::from_consensus(0x1703_4219),
        nonce: 0,
    }
}
