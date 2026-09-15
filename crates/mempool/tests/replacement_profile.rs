//! Core 31.1 replacement graph policy (POL-05).
//! Raw entries isolate graph/fee facts; signed process fixtures cover funding.

use std::sync::Arc;

use bitcoin_rs_mempool::{
    Mempool, MempoolEntry, MempoolError, MempoolLimits, RbfError, ReplacementCandidate,
};
use bitcoin_rs_primitives::{
    Amount, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
};

fn coin(tag: u32) -> OutPoint {
    let mut hash = [0_u8; 32];
    hash[..4].copy_from_slice(&tag.to_le_bytes());
    OutPoint::new(Txid(Hash256::from_le_bytes(&hash)), 0)
}

fn spend(tag: u32, inputs: &[OutPoint], outputs: usize) -> Tx {
    Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: inputs
            .iter()
            .map(|&previous_output| TxIn {
                previous_output,
                script_sig: Script::from_bytes(tag.to_le_bytes().to_vec()),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            })
            .collect(),
        outputs: (0..outputs)
            .map(|_| TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: Script::from_bytes([vec![0, 20], vec![1; 20]].concat()),
            })
            .collect(),
    }
}

fn pool() -> Mempool {
    Mempool::new(MempoolLimits {
        min_relay_fee_sat_per_kvb: 0,
        ..MempoolLimits::default()
    })
}

fn entry(tx: Tx, fee: u64) -> MempoolEntry {
    let vsize = u32::try_from(tx.vsize()).unwrap_or(u32::MAX);
    MempoolEntry::new(Arc::new(tx), vsize, fee, 1, 1)
}

fn candidate(tx: Tx, fee: u64) -> ReplacementCandidate {
    let vsize = u32::try_from(tx.vsize()).unwrap_or(u32::MAX);
    ReplacementCandidate::new(Arc::new(tx), vsize, fee, 1_000)
}

#[test]
fn a_higher_direct_rate_and_total_fee_can_still_worsen_the_curve()
-> Result<(), Box<dyn std::error::Error>> {
    let mut pool = pool();
    let parent = spend(1, &[coin(100)], 1);
    let parent_id = parent.txid();
    pool.insert_entry(MempoolEntry::new(Arc::new(parent), 100, 0, 1, 1))?;
    let child = spend(2, &[OutPoint::new(parent_id, 0)], 1);
    pool.insert_entry(MempoolEntry::new(Arc::new(child), 100, 1_000, 1, 1))?;
    let replacement = spend(3, &[coin(100)], 1);
    let before = pool.mining_snapshot();
    // 1,400 pays the evicted 1,000 plus 300 relay satoshis. Its direct
    // rate beats the zero-fee parent, but 1,400/300 < 1,000/200.
    let error = pool
        .replace_transaction(
            ReplacementCandidate::new(Arc::new(replacement), 300, 1_400, 1_000),
            2,
            1,
            0,
        )
        .err();
    assert_eq!(error, Some(RbfError::InsufficientFeerateDiagram));
    assert_eq!(pool.mining_snapshot().entries, before.entries);
    assert_eq!(pool.sequence_number(), before.sequence);
    Ok(())
}

#[test]
fn lower_direct_rate_can_improve_the_parent_child_curve() -> Result<(), Box<dyn std::error::Error>>
{
    let mut pool = pool();
    let parent = spend(1, &[coin(100)], 1);
    let parent_id = parent.txid();
    pool.insert_entry(MempoolEntry::new(Arc::new(parent), 2_250, 0, 1, 1))?;
    let child = spend(2, &[OutPoint::new(parent_id, 0)], 1);
    let child_id = child.txid();
    pool.insert_entry(MempoolEntry::new(Arc::new(child), 100, 4_000, 1, 1))?;
    let replacement = spend(3, &[OutPoint::new(parent_id, 0)], 1);
    let replacement_id = replacement.txid();
    // Direct rate drops from 40 to 22.5 sat/vB, but the complete cluster
    // improves from 4,000/2,350 to 4,500/2,450 and pays the relay increment.
    pool.replace_transaction(
        ReplacementCandidate::new(Arc::new(replacement), 200, 4_500, 1_000),
        2,
        1,
        0,
    )?;
    assert!(pool.contains_txid(&parent_id));
    assert!(!pool.contains_txid(&child_id));
    assert!(pool.contains_txid(&replacement_id));
    Ok(())
}

#[test]
fn limit_counts_conflicting_clusters_not_evicted_transactions()
-> Result<(), Box<dyn std::error::Error>> {
    let mut pool = pool();
    let mut roots = Vec::new();
    for cluster in 0..3_u32 {
        let mut input = coin(10_000 + cluster);
        roots.push(input);
        for depth in 0..50_u32 {
            let tx = spend(cluster * 100 + depth, &[input], 1);
            input = OutPoint::new(tx.txid(), 0);
            pool.insert_entry(entry(tx, 1_000))?;
        }
    }
    let replacement = candidate(spend(999, &roots, 1), 600_000);
    let plan = pool.check_replacement(&replacement)?;
    assert_eq!(plan.evicted.len(), 150);
    pool.replace_transaction(replacement, 2, 1, 0)?;
    assert_eq!(pool.len(), 1);
    Ok(())
}

#[test]
fn one_hundred_conflicting_clusters_is_the_exact_boundary() -> Result<(), Box<dyn std::error::Error>>
{
    for count in [100_u32, 101] {
        let mut pool = pool();
        let mut inputs = Vec::new();
        for index in 0..count {
            let input = coin(10_000 + index);
            inputs.push(input);
            pool.insert_entry(entry(spend(index, &[input], 1), 1_000))?;
        }
        let replacement = candidate(spend(999, &inputs, 1), 1_000_000);
        let before = pool.sequence_number();
        let result = pool.replace_transaction(replacement, 2, 1, 0);
        if count == 100 {
            assert!(result.is_ok(), "{result:?}");
            assert_eq!(pool.len(), 1);
        } else {
            assert_eq!(result.err(), Some(RbfError::TooManyConflictingClusters));
            assert_eq!(pool.len(), 101);
            assert_eq!(pool.sequence_number(), before);
        }
    }
    Ok(())
}

#[test]
fn modified_fees_and_small_relay_charges_are_enforced() -> Result<(), Box<dyn std::error::Error>> {
    let mut pool = pool();
    let original = spend(1, &[coin(100)], 1);
    let original_id = original.txid();
    pool.insert_entry(entry(original, 1_000))?;
    let mut replacement = candidate(spend(2, &[coin(100)], 1), 1_000);
    replacement.min_relay_fee_rate = 1;
    assert_eq!(
        pool.check_replacement(&replacement).err(),
        Some(RbfError::Rule4InsufficientIncrementalFee)
    );
    pool.prioritise(original_id, 2_000)?;
    replacement.fee = 2_500;
    assert_eq!(
        pool.check_replacement(&replacement).err(),
        Some(RbfError::Rule3InsufficientAbsoluteFee)
    );
    pool.prioritise(replacement.tx.txid(), 1_000)?;
    pool.replace_transaction(replacement, 2, 1, 0)?;
    Ok(())
}

#[test]
fn an_evicted_dependency_fails_without_narrowing_representable_fees()
-> Result<(), Box<dyn std::error::Error>> {
    let mut pool = pool();
    let original = spend(1, &[coin(100)], 1);
    let original_id = original.txid();
    pool.insert_entry(entry(original, 1_000))?;
    let before = pool.sequence_number();
    let dependent = candidate(
        spend(2, &[coin(100), OutPoint::new(original_id, 0)], 1),
        10_000,
    );
    assert_eq!(
        pool.check_replacement(&dependent).err(),
        Some(RbfError::Mempool(MempoolError::EvictedParent))
    );
    let wide = candidate(spend(3, &[coin(100)], 1), u64::MAX);
    assert!(
        pool.check_replacement(&wide).is_ok(),
        "u64 fee metadata remains representable in the checked i128 diagram"
    );
    assert_eq!(pool.sequence_number(), before);
    assert!(pool.contains_txid(&original_id));
    Ok(())
}

#[test]
fn truc_sizes_versions_and_sibling_eviction_match_bip431() -> Result<(), Box<dyn std::error::Error>>
{
    use bitcoin_rs_mempool::TrucError;
    let mut pool = pool();
    let mut parent = spend(1, &[coin(100)], 2);
    parent.version = 3;
    let parent_id = parent.txid();
    for size in [10_000, 10_001] {
        let request = ReplacementCandidate::new(Arc::new(parent.clone()), size, 20_000, 1_000);
        let result = pool.check_replacement(&request);
        if size == 10_000 {
            assert!(result.is_ok());
        } else {
            assert_eq!(result.err(), Some(RbfError::Truc(TrucError::Size)));
        }
    }
    pool.insert_entry(entry(parent, 1_000))?;
    let mut child = spend(2, &[OutPoint::new(parent_id, 0)], 1);
    assert_eq!(
        pool.check_replacement(&candidate(child.clone(), 2_000))
            .err(),
        Some(RbfError::Truc(TrucError::Version))
    );
    child.version = 3;
    for size in [1_000, 1_001] {
        let request = ReplacementCandidate::new(Arc::new(child.clone()), size, 2_000, 1_000);
        let result = pool.check_replacement(&request);
        if size == 1_000 {
            assert!(result.is_ok());
        } else {
            assert_eq!(result.err(), Some(RbfError::Truc(TrucError::ChildSize)));
        }
    }
    let child_id = child.txid();
    pool.replace_transaction(candidate(child, 2_000), 1, 1, 0)?;
    let mut grandchild = spend(3, &[OutPoint::new(child_id, 0)], 1);
    grandchild.version = 3;
    assert_eq!(
        pool.check_replacement(&candidate(grandchild, 10_000)).err(),
        Some(RbfError::Truc(TrucError::Ancestors))
    );
    let mut sibling = spend(4, &[OutPoint::new(parent_id, 1)], 1);
    sibling.version = 3;
    let before = pool.mining_snapshot();
    assert_eq!(
        pool.check_replacement(&candidate(sibling.clone(), 2_000))
            .err(),
        Some(RbfError::SiblingIncrementalFee)
    );
    assert_eq!(pool.mining_snapshot().entries, before.entries);
    assert_eq!(pool.sequence_number(), before.sequence);
    let sibling_id = sibling.txid();
    let changes = pool.replace_transaction(candidate(sibling, 4_000), 1, 1, 0)?;
    assert_eq!(changes.removed_txids(), vec![child_id]);
    assert!(pool.contains_txid(&parent_id));
    assert!(pool.contains_txid(&sibling_id));
    assert_eq!(pool.len(), 2);
    Ok(())
}
