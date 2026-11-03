use super::*;

const TIME: u64 = 1_700_000_000;
const HEIGHT: u32 = 900;

fn graph_tx(nonce: u32, inputs: &[OutPoint], rbf: bool) -> Tx {
    Tx {
        version: 2,
        lock_time: LockTime::from_consensus(nonce),
        inputs: inputs
            .iter()
            .map(|previous_output| TxIn {
                previous_output: *previous_output,
                script_sig: Script::new(),
                sequence: if rbf {
                    Sequence::from_consensus(0xFFFF_FFFD)
                } else {
                    Sequence::MAX
                },
                witness: Witness::new(),
            })
            .collect(),
        outputs: alloc::vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: alloc::vec![0x51; 8].into(),
        }],
    }
}

fn fuzzer_pool() -> Mempool {
    Mempool::new(MempoolLimits {
        max_total_bytes: 0,
        min_relay_fee_sat_per_kvb: 0,
        cluster_count: 64,
        ..MempoolLimits::default()
    })
}

fn insert_ok(pool: &mut Mempool, nonce: u32, inputs: &[OutPoint], vsize: u32) -> Txid {
    let tx = graph_tx(nonce, inputs, false);
    let txid = tx.txid();
    pool.insert_entry(MempoolEntry::new(
        Arc::new(tx),
        vsize,
        1_000,
        TIME,
        HEIGHT,
        0,
    ))
    .expect("fixture insert must pass validation");
    txid
}

#[test]
fn batched_removal_of_two_thousand_independent_entries_settles() {
    const COUNT: u32 = 2000;
    let count = usize::try_from(COUNT).expect("test count fits");
    let mut pool = Mempool::new(MempoolLimits {
        max_total_bytes: 0,
        ..MempoolLimits::default()
    });
    let mut txids = Vec::with_capacity(count);
    for nonce in 0..COUNT {
        let mut seed = [0xD1_u8; 32];
        seed[..4].copy_from_slice(&nonce.to_le_bytes());
        let funding = OutPoint::new(Txid::from(Hash256::from_le_bytes(&seed)), 0);
        txids.push(insert_ok(&mut pool, nonce, &[funding], 100));
    }
    assert_eq!(pool.len(), count);
    let mut removals = Vec::with_capacity(count);
    for txid in &txids {
        removals.push((
            pool.entry_id_by_txid(txid).expect("inserted id resolves"),
            RemovalReason::BlockInclusion,
        ));
    }
    let mut changes = Vec::new();
    pool.remove_entries_with_reasons(&removals, &mut changes);
    assert_eq!(pool.len(), 0, "every independent entry leaves");
    assert_eq!(changes.len(), count);
    for (change, txid) in changes.iter().zip(txids.iter()) {
        assert_eq!(change.txid, Hash256::from(*txid));
        assert!(
            matches!(
                change.outcome,
                MutationOutcome::Removed(RemovalReason::BlockInclusion)
            ),
            "unexpected outcome for {txid}: {:?}",
            change.outcome
        );
    }
    assert!(
        pool.chunks_by_feerate().next().is_none(),
        "no component linearization survives the batch"
    );
}

fn reference_components(pool: &Mempool) -> Vec<Vec<EntryId>> {
    let mut seen: HashSet<EntryId> = HashSet::new();
    let mut components = Vec::new();
    let live: Vec<EntryId> = pool
        .derived
        .by_txid
        .values()
        .map(|indexed| indexed.id)
        .collect();
    for seed in live {
        if !seen.insert(seed) {
            continue;
        }
        let mut part = vec![seed];
        let mut queue = vec![seed];
        while let Some(id) = queue.pop() {
            let entry = pool.entry(id).expect("entry must exist in pool");
            let parents = entry
                .tx
                .inputs
                .iter()
                .filter_map(|input| pool.entry_id_by_txid(&input.previous_output.txid));
            let start = (
                SpendingKey::from(OutPoint::new(entry.txid, u32::MIN)),
                EntryId::MIN,
            );
            let end = (
                SpendingKey::from(OutPoint::new(entry.txid, u32::MAX)),
                EntryId::MAX,
            );
            let children = pool
                .derived
                .spending
                .range(start..=end)
                .map(|(_, child)| *child)
                .collect::<Vec<_>>();
            for neighbour in parents.chain(children) {
                if seen.insert(neighbour) {
                    part.push(neighbour);
                    queue.push(neighbour);
                }
            }
        }
        part.sort_unstable();
        components.push(part);
    }
    components.sort();
    components
}

fn assert_graph_exact(pool: &Mempool) {
    let mut cached: Vec<Vec<EntryId>> = Vec::new();
    let mut by_component: HashMap<u32, Vec<EntryId>> = HashMap::new();
    for (index, _entry) in pool.entries.iter() {
        let id = EntryId::try_from(index).expect("slot index fits u32");
        let component = pool.component_id(id).expect("live entry has a component");
        by_component.entry(component).or_default().push(id);
    }
    for members in by_component.values_mut() {
        members.sort_unstable();
        cached.push(members.clone());
    }
    cached.sort();
    assert_eq!(cached, reference_components(pool), "component partition");

    for (component, members) in &by_component {
        let summary = pool
            .component_summary(*component)
            .expect("component id names a live summary");
        let vsize = members.iter().fold(0_u64, |total, member| {
            total.saturating_add(
                pool.entry(*member)
                    .map_or(0, |entry| u64::from(entry.vsize)),
            )
        });
        assert_eq!(
            summary.member_count,
            u32::try_from(members.len()).unwrap_or(u32::MAX)
        );
        assert_eq!(
            summary.weight,
            vsize * 4,
            "summary vsize for component {component}"
        );
    }

    for (index, _entry) in pool.entries.iter() {
        let id = EntryId::try_from(index).expect("slot index fits u32");
        let links = pool.links(id).expect("live entry has links");
        let mut sorted_parents = links.parents.clone();
        sorted_parents.sort_unstable();
        sorted_parents.dedup();
        assert_eq!(
            sorted_parents, links.parents,
            "parents of {id} sorted+dedup"
        );
        let mut sorted_children = links.children.clone();
        sorted_children.sort_unstable();
        sorted_children.dedup();
        assert_eq!(
            sorted_children, links.children,
            "children of {id} sorted+dedup"
        );
        for parent in &links.parents {
            let back = pool.links(*parent).expect("parent link names a live entry");
            assert!(back.children.contains(&id), "link symmetry for {id}");
        }
        for child in &links.children {
            let back = pool.links(*child).expect("child link names a live entry");
            assert!(back.parents.contains(&id), "link symmetry for {id}");
        }
    }
}

fn graph_steps(pool: &Mempool) -> u64 {
    pool.graph_steps.load(Ordering::Relaxed)
}

#[test]
fn component_merges_and_splits_track_the_reference() {
    let mut pool = fuzzer_pool();
    let a1 = insert_ok(&mut pool, 1, &[], 100);
    let a2 = insert_ok(&mut pool, 2, &[OutPoint::new(a1, 0)], 100);
    let a3 = insert_ok(&mut pool, 3, &[OutPoint::new(a2, 0)], 100);
    let b1 = insert_ok(&mut pool, 4, &[], 110);
    let b2 = insert_ok(&mut pool, 5, &[OutPoint::new(b1, 0)], 110);
    assert_graph_exact(&pool);
    assert_eq!(reference_components(&pool).len(), 2, "two disjoint chains");

    let bridge = insert_ok(
        &mut pool,
        6,
        &[OutPoint::new(a3, 0), OutPoint::new(b2, 0)],
        120,
    );
    assert_graph_exact(&pool);
    let merged = reference_components(&pool);
    assert_eq!(merged.len(), 1, "bridge joins the chains: {merged:?}");
    assert_eq!(merged[0].len(), 6);

    let bridge_id = pool.entry_id_by_txid(&bridge).expect("bridge is pooled");
    let mut changes = Vec::new();
    pool.remove_entries_with_reasons(&[(bridge_id, RemovalReason::PolicyEviction)], &mut changes);
    assert_graph_exact(&pool);
    assert_eq!(
        reference_components(&pool).len(),
        2,
        "bridge removal splits"
    );
}

#[test]
fn recycled_slots_do_not_inherit_links_or_transaction_indexes() {
    let mut pool = fuzzer_pool();
    let parent = insert_ok(&mut pool, 1, &[], 100);
    let child = insert_ok(&mut pool, 2, &[OutPoint::new(parent, 0)], 100);
    let leaf = insert_ok(&mut pool, 3, &[OutPoint::new(child, 0)], 100);
    let child_id = pool.entry_id_by_txid(&child).expect("pooled child");
    let child_wtxid = pool.entry(child_id).expect("pooled child").wtxid;
    pool.remove_entries_with_reasons(
        &[(child_id, RemovalReason::PolicyEviction)],
        &mut Vec::new(),
    );

    let replacement = insert_ok(&mut pool, 4, &[], 100);
    assert_eq!(pool.entry_id_by_txid(&replacement), Some(child_id));
    assert!(pool.entry_by_txid(&child).is_none());
    assert!(pool.entry_by_wtxid(&child_wtxid).is_none());
    let links = pool.links(child_id).expect("reused slot");
    assert_eq!(links.parents, Vec::<u32>::new());
    assert_eq!(links.children, Vec::<u32>::new());
    let parent_id = pool.entry_id_by_txid(&parent).expect("pooled parent");
    let leaf_id = pool.entry_id_by_txid(&leaf).expect("pooled leaf");
    assert_eq!(
        pool.links(parent_id).expect("parent links").children,
        Vec::<u32>::new()
    );
    assert_eq!(
        pool.links(leaf_id).expect("leaf links").parents,
        Vec::<u32>::new()
    );
    assert_graph_exact(&pool);

    let retained_slots = pool.entries.capacity();
    let _ = pool.clear();
    assert_eq!(pool.entries.capacity(), retained_slots);
    let fresh = insert_ok(&mut pool, 5, &[], 100);
    assert_eq!(pool.entry_id_by_txid(&fresh), Some(0));
    assert_eq!(pool.len(), 1);
    for retired in [parent, leaf, replacement] {
        assert!(pool.entry_by_txid(&retired).is_none());
    }
    assert_graph_exact(&pool);
}

#[test]
fn wtxid_lookups_track_mutations() {
    let mut pool = fuzzer_pool();
    let first = insert_ok(&mut pool, 1, &[], 100);
    let wtxid = pool.entry_by_txid(&first).map(|entry| entry.wtxid);
    assert!(pool.contains_wtxid(&wtxid.expect("pooled")));
    assert_eq!(
        pool.entry_by_wtxid(&wtxid.expect("pooled"))
            .map(|entry| entry.txid),
        Some(first)
    );

    let first_id = pool.entry_id_by_txid(&first).expect("pooled");
    let mut changes = Vec::new();
    pool.remove_entries_with_reasons(&[(first_id, RemovalReason::PolicyEviction)], &mut changes);
    assert!(!pool.contains_wtxid(&wtxid.expect("pooled")));
    assert!(pool.entry_by_wtxid(&wtxid.expect("pooled")).is_none());

    let second = insert_ok(&mut pool, 2, &[], 100);
    let second_wtxid = pool.entry_by_txid(&second).map(|entry| entry.wtxid);
    assert_ne!(wtxid, second_wtxid);
    assert!(pool.contains_wtxid(&second_wtxid.expect("pooled")));
}

#[test]
fn plain_admission_enforces_cluster_limits_through_the_cache() {
    let mut pool = Mempool::new(MempoolLimits {
        max_total_bytes: 0,
        min_relay_fee_sat_per_kvb: 0,
        cluster_count: 4,
        cluster_size_vbytes: 1_000_000,
        ..MempoolLimits::default()
    });
    let a = insert_ok(&mut pool, 1, &[], 100);
    let b = insert_ok(&mut pool, 2, &[OutPoint::new(a, 0)], 100);
    let c = insert_ok(&mut pool, 3, &[], 100);
    let d = insert_ok(&mut pool, 4, &[OutPoint::new(c, 0)], 100);

    let joiner = graph_tx(5, &[OutPoint::new(b, 0), OutPoint::new(d, 0)], false);
    let entry = MempoolEntry::new(Arc::new(joiner.clone()), 100, 1_000, TIME, HEIGHT, 0);
    let error = pool
        .insert_entry(entry)
        .expect_err("cluster of five is over the limit");
    assert!(matches!(
        error,
        MempoolError::Policy(PolicyError::ClusterCountLimit)
    ));
    assert_eq!(pool.len(), 4, "rejection commits nothing");
    assert!(!pool.contains_txid(&joiner.txid()));

    assert!(matches!(
        pool.check_replacement(&crate::ReplacementCandidate::new(
            Arc::new(joiner),
            100,
            1_000,
            1_000
        )),
        Err(crate::RbfError::Mempool(MempoolError::Policy(
            PolicyError::ClusterCountLimit
        )))
    ));

    let _e = insert_ok(&mut pool, 6, &[OutPoint::new(a, 0)], 100);
    assert_graph_exact(&pool);
}

#[test]
fn check_cluster_limits_cached_matches_walk_across_graph_shapes() {
    fn agrees(pool: &Mempool, tx: &Tx, weight: u64, expected: Result<(), PolicyError>) {
        let excluded: HashSet<EntryId> = HashSet::new();
        assert_eq!(
            pool.check_cluster_limits_cached(tx, weight),
            expected,
            "cached verdict must match the pinned outcome"
        );
        assert_eq!(
            pool.check_cluster_limits_by_walk(tx, weight, &excluded),
            expected,
            "walk verdict must match the pinned outcome"
        );
    }

    fn shape_pool(count: u32) -> Mempool {
        Mempool::new(MempoolLimits {
            max_total_bytes: 0,
            min_relay_fee_sat_per_kvb: 0,
            cluster_count: count,
            cluster_size_vbytes: 1_000_000,
            ..MempoolLimits::default()
        })
    }

    let mut pool = shape_pool(4);
    let parent_one = insert_ok(&mut pool, 1, &[], 100);
    let child_one = insert_ok(&mut pool, 2, &[OutPoint::new(parent_one, 0)], 100);
    let parent_two = insert_ok(&mut pool, 3, &[], 100);
    let child_two = insert_ok(&mut pool, 4, &[OutPoint::new(parent_two, 0)], 100);
    let joiner = graph_tx(
        5,
        &[OutPoint::new(child_one, 0), OutPoint::new(child_two, 0)],
        false,
    );
    agrees(&pool, &joiner, 400, Err(PolicyError::ClusterCountLimit));

    let mut pool = shape_pool(4);
    let probe = insert_ok(&mut pool, 1, &[], 100);
    let c1 = insert_ok(&mut pool, 2, &[OutPoint::new(probe, 0)], 100);
    let _c2 = insert_ok(&mut pool, 3, &[OutPoint::new(probe, 0)], 100);
    let sibling_spender = graph_tx(4, &[OutPoint::new(c1, 0)], false);
    agrees(&pool, &sibling_spender, 400, Ok(()));

    let mut pool = shape_pool(3);
    let split_root = insert_ok(&mut pool, 1, &[], 100);
    let split_mid = insert_ok(&mut pool, 2, &[OutPoint::new(split_root, 0)], 100);
    let _split_tail = insert_ok(&mut pool, 3, &[OutPoint::new(split_mid, 0)], 100);
    let split_mid_id = pool
        .entry_id_by_txid(&split_mid)
        .expect("middle entry resolves");
    pool.remove_entries_with_reasons(&[(split_mid_id, RemovalReason::Conflict)], &mut Vec::new());
    let rejoiner = graph_tx(4, &[OutPoint::new(split_root, 0)], false);
    agrees(&pool, &rejoiner, 400, Ok(()));

    let mut pool = Mempool::new(MempoolLimits {
        max_total_bytes: 0,
        min_relay_fee_sat_per_kvb: 0,
        cluster_count: 8,
        cluster_size_vbytes: 200,
        ..MempoolLimits::default()
    });
    let oversize_root = insert_ok(&mut pool, 1, &[], 100);
    let oversize_mid = insert_ok(&mut pool, 2, &[OutPoint::new(oversize_root, 0)], 100);
    let overweight = graph_tx(3, &[OutPoint::new(oversize_mid, 0)], false);
    agrees(&pool, &overweight, 400, Err(PolicyError::ClusterSizeLimit));

    let mut pool = shape_pool(4);
    let parent_tx = graph_tx(1, &[], false);
    let parent_txid = parent_tx.txid();
    let _child = insert_ok(&mut pool, 2, &[OutPoint::new(parent_txid, 0)], 100);
    agrees(&pool, &parent_tx, 400, Ok(()));
    assert_eq!(pool.len(), 1, "the fixture pools the child only");
}

#[test]
fn removal_splits_repartition_by_bounded_walk() {
    let mut pool = Mempool::new(MempoolLimits {
        max_total_bytes: 0,
        min_relay_fee_sat_per_kvb: 0,
        cluster_count: 8,
        cluster_size_vbytes: 1_000_000,
        ..MempoolLimits::default()
    });
    let root = insert_ok(&mut pool, 1, &[], 100);
    let left = insert_ok(&mut pool, 2, &[OutPoint::new(root, 0)], 100);
    let right = insert_ok(&mut pool, 3, &[OutPoint::new(root, 0)], 100);
    let sink = insert_ok(
        &mut pool,
        4,
        &[OutPoint::new(left, 0), OutPoint::new(right, 0)],
        100,
    );
    let tail = insert_ok(&mut pool, 5, &[OutPoint::new(sink, 0)], 100);
    let end = insert_ok(&mut pool, 6, &[OutPoint::new(tail, 0)], 100);
    assert_graph_exact(&pool);
    assert_eq!(reference_components(&pool)[0].len(), 6);

    let sink_id = pool.entry_id_by_txid(&sink).expect("pooled");
    let mut changes = Vec::new();
    pool.remove_entries_with_reasons(&[(sink_id, RemovalReason::PolicyEviction)], &mut changes);
    assert_graph_exact(&pool);
    let parts = reference_components(&pool);
    assert_eq!(parts.len(), 2, "the sink held the two halves: {parts:?}");
    assert_eq!(parts[0].len() + parts[1].len(), 5);

    let root_id = pool.entry_id_by_txid(&root).expect("pooled");
    assert_eq!(pool.links(root_id).expect("pooled").children.len(), 2);
    let _ = end;
}

#[test]
fn graph_work_stays_local_on_worst_case_shapes() {
    let mut pool = Mempool::new(MempoolLimits {
        max_total_bytes: 0,
        min_relay_fee_sat_per_kvb: 0,
        cluster_count: 64,
        cluster_size_vbytes: 1_000_000,
        ..MempoolLimits::default()
    });
    let mut nonce = 0_u32;
    for _chain in 0..40 {
        let mut parent = insert_ok(&mut pool, nonce, &[], 100);
        nonce += 1;
        for _depth in 0..9 {
            parent = insert_ok(&mut pool, nonce, &[OutPoint::new(parent, 0)], 100);
            nonce += 1;
        }
    }
    assert_eq!(pool.len(), 400);

    pool.graph_steps.store(0, Ordering::Relaxed);
    let _ = insert_ok(&mut pool, nonce, &[], 100);
    nonce += 1;
    assert!(graph_steps(&pool) < 8, "isolated insert walked the pool");

    let live = pool.iter_txids();
    let anchor = live[live.len() / 2];
    pool.graph_steps.store(0, Ordering::Relaxed);
    let _ = insert_ok(&mut pool, nonce, &[OutPoint::new(anchor, 0)], 100);
    assert!(
        graph_steps(&pool) < 4 * 10 + 48,
        "leaf insert walked beyond its cluster: {}",
        graph_steps(&pool)
    );

    let middle = live[live.len() / 4];
    let middle_id = pool.entry_id_by_txid(&middle).expect("pooled");
    pool.graph_steps.store(0, Ordering::Relaxed);
    let mut changes = Vec::new();
    pool.remove_entries_with_reasons(&[(middle_id, RemovalReason::PolicyEviction)], &mut changes);
    assert!(
        graph_steps(&pool) < 4 * 10 + 64,
        "split recompute walked beyond the broken cluster: {}",
        graph_steps(&pool)
    );
    assert_graph_exact(&pool);
}

#[test]
fn a_surviving_node_is_measured_from_the_links_the_exclusion_keeps() {
    let mut pool = fuzzer_pool();
    let root = insert_ok(&mut pool, 1, &[], 100);
    let first = insert_ok(&mut pool, 2, &[OutPoint::new(root, 0)], 100);
    let second = insert_ok(&mut pool, 3, &[OutPoint::new(root, 0)], 100);
    let root_id = pool.entry_id_by_txid(&root).expect("pooled");
    let first_id = pool.entry_id_by_txid(&first).expect("pooled");
    let second_id = pool.entry_id_by_txid(&second).expect("pooled");
    assert_eq!(pool.entry_memory(root_id).expect("pooled"), {
        let sides = pool.links(root_id).expect("pooled").children.len();
        entry_memory_usage(&pool.entry(root_id).expect("pooled").tx)
            .saturating_add(link_memory_usage(sides, 1))
    });

    let (before, after) = pool
        .projected_graphs(&[], &[first_id, second_id], ProjectionScope::AllEntries)
        .expect("projection");
    let root_before = before
        .nodes
        .iter()
        .find(|node| node.id == Some(root_id))
        .expect("the root is projected");
    let root_after = after
        .nodes
        .iter()
        .find(|node| node.id == Some(root_id))
        .expect("the root survives");
    assert_eq!(
        root_after.memory,
        entry_memory_usage(&pool.entry(root_id).expect("pooled").tx),
        "a root whose children all leave keeps no link memory"
    );
    assert!(
        root_after.memory < root_before.memory,
        "the projection must stop charging the evicted links"
    );

    let mut changes = Vec::new();
    pool.remove_entries_with_reasons(
        &[
            (first_id, RemovalReason::PolicyEviction),
            (second_id, RemovalReason::PolicyEviction),
        ],
        &mut changes,
    );
    assert_eq!(
        root_after.memory,
        pool.entry_memory(root_id).expect("pooled"),
        "the projection must equal the accounting after the removals"
    );
}
