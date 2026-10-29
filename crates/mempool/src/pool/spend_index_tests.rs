use alloc::sync::Arc;
use alloc::vec::Vec;

use bitcoin_rs_primitives::{OutPoint, Tx, TxIn, TxOut};

use super::*;

fn tx_with(inputs: &[OutPoint], outputs: u32, tag: u64) -> Tx {
    Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: inputs
            .iter()
            .map(|previous_output| TxIn {
                previous_output: *previous_output,
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            })
            .collect(),
        outputs: (0..outputs)
            .map(|vout| TxOut {
                value: Amount::from_sat(
                    10_000_u64
                        .saturating_add(u64::from(vout))
                        .saturating_add(tag.saturating_mul(1_000)),
                ),
                script_pubkey: alloc::vec![0x51].into(),
            })
            .collect(),
    }
}

fn graph_pool() -> (Mempool, Txid) {
    let confirmed = OutPoint::new(txid_of([7_u8; 32]), 0);
    let root = tx_with(&[confirmed], 3, 1);
    let root_txid = root.txid();
    let child_a = tx_with(&[OutPoint::new(root_txid, 0)], 1, 2);
    let child_a_txid = child_a.txid();
    let child_b = tx_with(
        &[OutPoint::new(root_txid, 1), OutPoint::new(root_txid, 2)],
        1,
        3,
    );
    let child_c = tx_with(&[OutPoint::new(child_a_txid, 0)], 1, 4);

    let mut pool = Mempool::new(MempoolLimits::default());
    for tx in [root, child_a, child_b, child_c] {
        let entry = MempoolEntry::new(Arc::new(tx), 100, 10_000, 1, 7, 0);
        let Ok(_id) = pool.insert_entry(entry) else {
            panic!("mempool insert failed while building the fixture");
        };
    }
    (pool, root_txid)
}

#[test]
fn a_cluster_holds_siblings_that_no_ancestor_walk_reaches() {
    let (pool, root_txid) = graph_pool();
    let child_a_txid = child_a_txid_of(&pool, root_txid);
    let Some(child_a_id) = pool.entry_id_by_txid(&child_a_txid) else {
        panic!("fixture child_a is missing");
    };

    let cluster = pool.cluster_ids_seeded_by(&[child_a_id], &HashSet::new());
    let chain = pool.metadata_closure(&[child_a_id]);

    assert_eq!(
        cluster.len(),
        pool.len(),
        "the cluster must span the whole connected component"
    );
    assert!(
        chain.len() < cluster.len(),
        "this fixture must distinguish the two walks or it proves nothing: chain={} cluster={}",
        chain.len(),
        cluster.len()
    );
}

fn child_a_txid_of(pool: &Mempool, root_txid: Txid) -> Txid {
    let Some(root_id) = pool.entry_id_by_txid(&root_txid) else {
        panic!("fixture root is missing");
    };
    for child in pool.links(root_id).expect("pooled").children.clone() {
        if !pool.links(child).expect("pooled").children.is_empty()
            && let Some(entry) = pool.entry(child)
        {
            return entry.txid;
        }
    }
    panic!("fixture has no grandchild-bearing child");
}

#[test]
fn admission_refuses_a_transaction_over_the_cluster_count_limit() {
    let confirmed = OutPoint::new(txid_of([9_u8; 32]), 0);
    let root = tx_with(&[confirmed], 4, 1);
    let root_txid = root.txid();

    let build = |limit: u32| {
        let limits = MempoolLimits {
            cluster_count: limit,
            ..MempoolLimits::default()
        };
        let mut pool = Mempool::new(limits);
        let root_entry = MempoolEntry::new(Arc::new(root.clone()), 100, 10_000, 1, 7, 0);
        let Ok(_id) = pool.insert_entry(root_entry) else {
            panic!("root must be admitted");
        };
        let mut outcomes = Vec::new();
        for vout in 0..2_u32 {
            let child = tx_with(
                &[OutPoint::new(root_txid, vout)],
                1,
                u64::from(vout).saturating_add(2),
            );
            let entry = MempoolEntry::new(Arc::new(child), 100, 10_000, 1, 7, 0);
            outcomes.push(pool.insert_entry(entry));
        }
        outcomes
    };

    let refused = build(2);
    assert!(refused[0].is_ok(), "the first sibling fits: {refused:?}");
    assert!(
        matches!(
            refused[1],
            Err(MempoolError::Policy(PolicyError::ClusterCountLimit))
        ),
        "the second sibling must be refused on cluster count: {refused:?}"
    );

    let accepted = build(3);
    assert!(
        accepted.iter().all(Result::is_ok),
        "a limit of three admits the whole cluster: {accepted:?}"
    );
}

#[test]
fn admission_counts_a_cousin_that_no_chain_through_the_parent_reaches() {
    let confirmed = OutPoint::new(txid_of([17_u8; 32]), 0);
    let a = tx_with(&[confirmed], 2, 1);
    let a_txid = a.txid();
    let b = tx_with(&[OutPoint::new(a_txid, 0)], 1, 2);
    let b_txid = b.txid();
    let c = tx_with(&[OutPoint::new(a_txid, 1)], 1, 3);
    let d = tx_with(&[OutPoint::new(b_txid, 0)], 1, 4);

    let limits = MempoolLimits {
        cluster_count: 3,
        ..MempoolLimits::default()
    };
    let mut pool = Mempool::new(limits);
    for tx in [a, b, c] {
        let Ok(_id) = pool.insert_entry(MempoolEntry::new(Arc::new(tx), 100, 10_000, 1, 7, 0))
        else {
            panic!("the three-member cluster must be admitted under a limit of three");
        };
    }

    let outcome = pool.insert_entry(MempoolEntry::new(Arc::new(d), 100, 10_000, 1, 7, 0));
    assert!(
        matches!(
            outcome,
            Err(MempoolError::Policy(PolicyError::ClusterCountLimit))
        ),
        "C is in D's cluster although no chain through B reaches it: {outcome:?}"
    );
}

#[test]
fn admission_refuses_a_transaction_over_the_cluster_size_limit() {
    let confirmed = OutPoint::new(txid_of([11_u8; 32]), 0);
    let root = tx_with(&[confirmed], 2, 1);
    let root_txid = root.txid();

    let limits = MempoolLimits {
        cluster_count: 100,
        cluster_size_vbytes: 250,
        ..MempoolLimits::default()
    };
    let mut pool = Mempool::new(limits);

    let Ok(_id) = pool.insert_entry(MempoolEntry::new(Arc::new(root), 200, 10_000, 1, 7, 0)) else {
        panic!("root must be admitted");
    };
    let child = tx_with(&[OutPoint::new(root_txid, 0)], 1, 2);
    let outcome = pool.insert_entry(MempoolEntry::new(Arc::new(child), 100, 10_000, 1, 7, 0));
    assert!(
        matches!(
            outcome,
            Err(MempoolError::Policy(PolicyError::ClusterSizeLimit))
        ),
        "200 + 100 vbytes exceeds a 250-vbyte cluster: {outcome:?}"
    );
}

#[test]
fn a_cluster_includes_transactions_that_already_spend_the_candidate() {
    let confirmed = OutPoint::new(txid_of([13_u8; 32]), 0);
    let parent = tx_with(&[confirmed], 1, 1);
    let parent_txid = parent.txid();
    let child = tx_with(&[OutPoint::new(parent_txid, 0)], 1, 2);

    let limits = MempoolLimits {
        cluster_count: 1,
        ..MempoolLimits::default()
    };
    let mut pool = Mempool::new(limits);

    let Ok(_id) = pool.insert_entry(MempoolEntry::new(Arc::new(child), 100, 10_000, 1, 7, 0))
    else {
        panic!("the child must be admitted into an empty pool");
    };
    let outcome = pool.insert_entry(MempoolEntry::new(Arc::new(parent), 100, 10_000, 1, 7, 0));
    assert!(
        matches!(
            outcome,
            Err(MempoolError::Policy(PolicyError::ClusterCountLimit))
        ),
        "the pre-existing spender must count toward the cluster: {outcome:?}"
    );
}

#[test]
fn cluster_limits_default_to_cores_values_and_follow_configuration() {
    let pool = Mempool::new(MempoolLimits::default());
    assert_eq!(pool.cluster_limits(), (64, 101_000));

    let limits = MempoolLimits {
        cluster_count: 7,
        cluster_size_vbytes: 4_242,
        ..MempoolLimits::default()
    };
    let configured = Mempool::new(limits);
    assert_eq!(
        configured.cluster_limits(),
        (7, 4_242),
        "the reader must follow configuration, or the RPC reports a constant"
    );
}

#[test]
fn a_replacement_that_evicts_from_a_full_cluster_is_admitted() {
    let confirmed = OutPoint::new(txid_of([21_u8; 32]), 0);
    let root = tx_with(&[confirmed], 2, 1);
    let root_txid = root.txid();
    let mut a = tx_with(&[OutPoint::new(root_txid, 0)], 1, 2);
    a.inputs[0].sequence = Sequence::ENABLE_RBF_NO_LOCKTIME;
    let a_txid = a.txid();
    let b = tx_with(&[OutPoint::new(root_txid, 1)], 1, 3);

    let limits = MempoolLimits {
        cluster_count: 3,
        ..MempoolLimits::default()
    };
    let mut pool = Mempool::new(limits);
    for tx in [root, a, b] {
        let Ok(_id) = pool.insert_entry(MempoolEntry::new(Arc::new(tx), 100, 10_000, 1, 7, 0))
        else {
            panic!("the three-member cluster must be admitted under a limit of three");
        };
    }

    let replacement = tx_with(&[OutPoint::new(root_txid, 0)], 1, 4);
    let result = pool.replace_transaction(
        &crate::ReplacementCandidate::new(Arc::new(replacement), 100, 12_000, 1).with_sigop_cost(4),
        4,
        7,
    );
    assert!(
        result.is_ok(),
        "a replacement that evicts from a full cluster must be admitted, \
             not rejected by the entries it removes: {result:?}"
    );
    assert!(
        pool.entry_id_by_txid(&a_txid).is_none(),
        "the replaced original must leave the pool"
    );
}

#[test]
fn replacement_preview_rejects_a_cluster_only_violation() {
    let confirmed = OutPoint::new(txid_of([23_u8; 32]), 0);
    let root = tx_with(&[confirmed], 3, 1);
    let root_txid = root.txid();
    let child_a = tx_with(&[OutPoint::new(root_txid, 0)], 1, 2);
    let child_b = tx_with(&[OutPoint::new(root_txid, 1)], 1, 3);

    let limits = MempoolLimits {
        cluster_count: 3,
        ..MempoolLimits::default()
    };
    let mut pool = Mempool::new(limits);
    for tx in [root, child_a, child_b] {
        let Ok(_id) = pool.insert_entry(MempoolEntry::new(Arc::new(tx), 100, 10_000, 1, 7, 0))
        else {
            panic!("the three-member cluster must be admitted under a limit of three");
        };
    }

    let child_c = tx_with(&[OutPoint::new(root_txid, 2)], 1, 4);
    let preview = pool.check_replacement(&crate::ReplacementCandidate::new(
        Arc::new(child_c.clone()),
        100,
        10_000,
        1_000,
    ));
    assert!(
        matches!(
            preview,
            Err(crate::RbfError::Mempool(MempoolError::Policy(
                PolicyError::ClusterCountLimit
            )))
        ),
        "the preview must reject a cluster-only violation: {preview:?}"
    );

    let admission = pool.insert_entry(MempoolEntry::new(Arc::new(child_c), 100, 10_000, 4, 7, 0));
    assert!(
        matches!(
            admission,
            Err(MempoolError::Policy(PolicyError::ClusterCountLimit))
        ),
        "admission must reject on cluster count: {admission:?}"
    );
    assert_eq!(
        preview.map_err(crate::RbfError::into_pool_error).err(),
        admission.err(),
        "preview and admission must reject on the same error"
    );
}

#[test]
fn replacement_preview_excludes_planned_evictions() {
    let confirmed = OutPoint::new(txid_of([27_u8; 32]), 0);
    let root = tx_with(&[confirmed], 2, 1);
    let root_txid = root.txid();
    let mut a = tx_with(&[OutPoint::new(root_txid, 0)], 1, 2);
    a.inputs[0].sequence = Sequence::ENABLE_RBF_NO_LOCKTIME;
    let a_txid = a.txid();
    let b = tx_with(&[OutPoint::new(root_txid, 1)], 1, 3);

    let limits = MempoolLimits {
        cluster_count: 3,
        ..MempoolLimits::default()
    };
    let mut pool = Mempool::new(limits);
    for tx in [root, a, b] {
        let Ok(_id) = pool.insert_entry(MempoolEntry::new(Arc::new(tx), 100, 10_000, 1, 7, 0))
        else {
            panic!("the three-member cluster must be admitted under a limit of three");
        };
    }

    let Some(a_id) = pool.entry_id_by_txid(&a_txid) else {
        panic!("A must be in the pool");
    };
    let replacement = tx_with(&[OutPoint::new(root_txid, 0)], 1, 4);
    let preview = pool
        .check_replacement(&crate::ReplacementCandidate::new(
            Arc::new(replacement.clone()),
            100,
            20_000,
            1_000,
        ))
        .expect("replacement preview excludes its victim");
    assert_eq!(preview.evicted, vec![a_id]);
    assert_eq!(pool.len(), 3, "preview does not mutate");
    assert_eq!(
        pool.insert_entry(MempoolEntry::new(
            Arc::new(replacement),
            100,
            20_000,
            1,
            7,
            0
        ))
        .err(),
        Some(MempoolError::Policy(PolicyError::ClusterCountLimit)),
        "ordinary insertion cannot grow this full cluster"
    );
}

#[test]
fn the_cached_txid_matches_a_recomputation() {
    let (pool, _root_txid) = graph_pool();
    for (_id, entry) in pool.entries.iter() {
        assert_eq!(
            entry.txid,
            entry.tx.txid(),
            "the entry's cached txid drifted from its transaction"
        );
    }
}

#[test]
fn spender_txids_matches_a_scan_of_every_entrys_inputs() {
    let (pool, _root_txid) = graph_pool();

    let mut spenders_seen = 0_usize;
    for (index, entry) in pool.entries.iter() {
        let Ok(id) = EntryId::try_from(index) else {
            panic!("entry index {index} does not fit an EntryId");
        };

        let mut expected: Vec<Txid> = Vec::new();
        for (_other_index, candidate) in pool.entries.iter() {
            if candidate
                .tx
                .inputs
                .iter()
                .any(|input| input.previous_output.txid == entry.txid)
            {
                expected.push(candidate.tx.txid());
            }
        }
        expected.sort_unstable();
        spenders_seen = spenders_seen.saturating_add(expected.len());

        let mut actual = pool.spender_txids(id);
        actual.sort_unstable();
        assert_eq!(
            actual, expected,
            "spender_txids diverged from the scan for {}",
            entry.txid
        );
    }

    assert_eq!(
        spenders_seen, 3,
        "the fixture must exercise spenders: root has 2, child_a has 1"
    );
}

#[test]
fn spender_txids_includes_an_out_of_range_prevout_inserted_before_its_parent() {
    let confirmed = OutPoint::new(txid_of([8_u8; 32]), 0);
    let parent = tx_with(&[confirmed], 1, 10);
    let parent_txid = parent.txid();
    let child = tx_with(&[OutPoint::new(parent_txid, u32::MAX)], 1, 11);
    let child_txid = child.txid();
    let mut pool = Mempool::new(MempoolLimits::default());

    let child_entry = MempoolEntry::new(Arc::new(child), 100, 10_000, 1, 7, 0);
    assert!(
        pool.insert_entry(child_entry).is_ok(),
        "child insertion failed"
    );
    let parent_entry = MempoolEntry::new(Arc::new(parent), 100, 10_000, 1, 7, 0);
    assert!(
        pool.insert_entry(parent_entry).is_ok(),
        "parent insertion failed"
    );
    let parent_id = pool
        .entry_id_by_txid(&parent_txid)
        .expect("parent id resolves");

    assert_eq!(pool.spender_txids(parent_id), vec![child_txid]);
}

#[test]
fn a_transaction_reached_through_two_outputs_is_reported_once() {
    let (pool, root_txid) = graph_pool();
    let Some(root_id) = pool.entry_id_by_txid(&root_txid) else {
        panic!("root missing from the fixture pool");
    };
    let spenders = pool.spender_txids(root_id);
    let mut deduped = spenders.clone();
    deduped.sort_unstable();
    deduped.dedup();
    assert_eq!(
        spenders.len(),
        deduped.len(),
        "child_b spends two of the root's outputs and must still appear once"
    );
    assert_eq!(spenders.len(), 2, "the root has two distinct spenders");
}

#[test]
fn block_inclusion_removes_root_but_leaves_descendants() {
    let (mut pool, root_txid) = graph_pool();
    let Some(root) = pool.entry_by_txid(&root_txid) else {
        panic!("root missing from the fixture pool");
    };
    let root_tx = root.tx.clone();
    let before = pool.len();
    let removed = pool.remove_for_block(&[&root_tx], &[root_txid], 8, 1);
    assert_ne!(removed.len(), 0);
    assert!(pool.entry_id_by_txid(&root_txid).is_none());
    assert_eq!(pool.len(), before - 1);
    assert_ne!(pool.len(), 0);
}
