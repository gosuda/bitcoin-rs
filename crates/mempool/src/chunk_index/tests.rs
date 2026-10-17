//! Chunk key ordering and index maintenance pins.
//!
//! The comparator must keep an equal-rate parent before its child: the
//! equal-feerate prefix weight breaks the tie, never the raw chunk weight.
//! The maintenance tests prove that relinearize replaces and forget drops,
//! so absorbed and freed components leave no stale keys behind.

use alloc::sync::Arc;
use alloc::vec::Vec;

use bitcoin_rs_primitives::{
    Amount, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
};
use proptest::prelude::*;

use super::{ChunkIndex, ChunkKey, MemberFacts};
use crate::{EntryId, Mempool, MempoolEntry, MempoolLimits};

/// Label-unique synthetic transaction for index tests.
fn key_tx(label: u64) -> Tx {
    let mut seed = [0xB7_u8; 32];
    seed[..8].copy_from_slice(&label.to_le_bytes());
    Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: alloc::vec![TxIn {
            previous_output: OutPoint::new(Txid::from(Hash256::from_le_bytes(&seed)), 0),
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: alloc::vec![TxOut {
            value: Amount::from_sat(5_000 + (label % 9_000)),
            script_pubkey: Script::from(alloc::vec![0x51]),
        }],
    }
}

/// Entry whose policy weight is exactly `weight`: `weight` is a multiple of
/// four and `vsize` its quarter, so no rounding or sigop adjustment applies.
fn weighted_entry(label: u64, fee: u64, weight: u64) -> MempoolEntry {
    let vsize = u32::try_from(weight / 4).unwrap_or(u32::MAX);
    let mut entry = MempoolEntry::new(Arc::new(key_tx(label)), vsize, fee, label, 1, 0);
    entry.weight = weight;
    entry
}

fn dummy_pool() -> Mempool {
    Mempool::new(MempoolLimits::default())
}

/// An equal-rate parent and child stay two chunks with the parent first.
#[test]
fn equal_rate_parent_precedes_child_by_prefix() {
    let pool = dummy_pool();
    let parent = weighted_entry(1, 2_000, 800);
    let child = weighted_entry(2, 1_000, 400);
    let child_parents = [7];
    // Facts arrive child-first to prove the stored order is canonical, not
    // input order.
    let facts = [
        MemberFacts {
            id: 9,
            entry: &child,
            parents: &child_parents,
        },
        MemberFacts {
            id: 7,
            entry: &parent,
            parents: &[],
        },
    ];
    let mut index = ChunkIndex::default();
    index.relinearize(0, &facts);
    let order: Vec<Vec<EntryId>> = index
        .chunks_descending(&pool)
        .map(|chunk| chunk.members.to_vec())
        .collect();
    assert_eq!(order, alloc::vec![alloc::vec![7], alloc::vec![9]]);
    let views: Vec<_> = index.chunks_descending(&pool).collect();
    assert_eq!(views[0].modified_fee, 2_000);
    assert_eq!(views[0].charged_weight, 800);
    assert_eq!(views[1].modified_fee, 1_000);
    assert_eq!(views[1].charged_weight, 400);
}

fn key(
    fee: i128,
    weight: u64,
    prefix: u64,
    txid_byte: u8,
    component: u32,
    ordinal: u32,
) -> ChunkKey {
    ChunkKey {
        modified_fee: fee,
        charged_weight: weight,
        prefix_weight: prefix,
        max_txid: Txid::from(Hash256::from_le_bytes(&[txid_byte; 32])),
        component,
        ordinal,
    }
}

/// A higher feerate always wins, however the prefixes compare.
#[test]
fn rate_beats_prefix() {
    // rich: 300_000 / 10_000 = 30 per WU, prefix 10_000.
    // lean: 1_000 / 100 = 10 per WU, prefix 100.
    let rich = key(300_000, 10_000, 10_000, 0x01, 0, 0);
    let lean = key(1_000, 100, 100, 0x00, 1, 0);
    assert!(rich < lean);
    assert!(lean > rich);
}

/// Equal rates sort by ascending prefix weight, not by raw chunk weight: the
/// lighter equal-rate child (prefix 1200) follows its parent (prefix 800).
#[test]
fn prefix_breaks_equal_rate_ties() {
    let parent = key(2_000, 800, 800, 0x01, 0, 0);
    let child = key(1_000, 400, 1_200, 0x02, 0, 1);
    assert!(parent < child);
}

/// Equal rates and prefixes fall to the greatest member txid, Core's fallback
/// order across distinct clusters.
#[test]
fn max_txid_breaks_cross_component_ties() {
    let lower = key(2_000, 800, 800, 0x01, 0, 0);
    let higher = key(2_000, 800, 800, 0x02, 1, 0);
    assert!(lower < higher);
    assert!(higher > lower);
}

proptest! {
    /// The key order is a total order: antisymmetric and transitive over
    /// random keys inside the comparison's arithmetic bounds.
    #[test]
    fn chunk_key_order_is_total(
        a in (0_i128..1_000_000_000, 1_u64..1_000_000, 1_u64..100_000_000, 0_u8..255, 0_u32..8, 0_u32..4),
        b in (0_i128..1_000_000_000, 1_u64..1_000_000, 1_u64..100_000_000, 0_u8..255, 0_u32..8, 0_u32..4),
        c in (0_i128..1_000_000_000, 1_u64..1_000_000, 1_u64..100_000_000, 0_u8..255, 0_u32..8, 0_u32..4),
    ) {
        let key = |(fee, weight, prefix, byte, component, ordinal)| {
            self::key(fee, weight, prefix, byte, component, ordinal)
        };
        let (a, b, c) = (key(a), key(b), key(c));
        prop_assert!(!(a < b && b < a), "order is antisymmetric");
        if a <= b && b <= c {
            prop_assert!(a <= c, "order is transitive");
        }
        prop_assert!(a <= b || b <= a, "order is total");
    }
}

/// Relinearizing a component replaces its chunks; forgetting drops them.
#[test]
fn relinearize_replaces_and_forget_drops() {
    let pool = dummy_pool();
    let first = weighted_entry(1, 2_000, 800);
    let second = weighted_entry(2, 3_000, 800);
    let mut index = ChunkIndex::default();
    index.relinearize(
        0,
        &[MemberFacts {
            id: 7,
            entry: &first,
            parents: &[],
        }],
    );
    index.relinearize(
        1,
        &[MemberFacts {
            id: 9,
            entry: &second,
            parents: &[],
        }],
    );
    assert_eq!(index.len(), 2);
    index.forget(0);
    assert_eq!(index.len(), 1);
    let remaining: Vec<Vec<EntryId>> = index
        .chunks_descending(&pool)
        .map(|chunk| chunk.members.to_vec())
        .collect();
    assert_eq!(remaining, alloc::vec![alloc::vec![9]]);
    // An empty member list forgets the component too.
    index.relinearize(1, &[]);
    assert!(index.is_empty());
    assert!(index.chunks_descending(&pool).next().is_none());
}
