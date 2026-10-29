use super::*;
use bitcoin_rs_primitives::{Amount, LockTime, OutPoint, Script, Sequence, TxIn, TxOut, Witness};
fn source(id: u64) -> PeerToken {
    PeerToken {
        endpoint: Some(bitcoin_rs_primitives::PeerEndpoint::Ip(
            core::net::SocketAddr::from(([127, 0, 0, 1], 8333)),
        )),
        addr: Some(bitcoin_rs_primitives::PeerEndpoint::from((
            [127, 0, 0, 1],
            8333,
        ))),
        connection_id: id,
    }
}
fn tx(marker: u8, parent: Txid) -> Arc<Tx> {
    Arc::new(Tx {
        version: 2,
        lock_time: LockTime::from_consensus(u32::from(marker)),
        inputs: vec![TxIn {
            previous_output: OutPoint::new(parent, 0),
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: Script::from_bytes(vec![0x51]),
        }],
    })
}
fn re_witnessed(body: &Tx, item: u8) -> Arc<Tx> {
    let mut changed = (*body).clone();
    changed.inputs[0].witness = Witness::from_stack(vec![vec![item]]);
    Arc::new(changed)
}
#[test]
fn zero_quota_retains_no_body_or_index() {
    let mut pool = OrphanPool::new(0);
    let tx = tx(1, Txid::default());
    pool.insert(Arc::clone(&tx), source(1), 0);
    assert_eq!(pool.len(), 0);
    assert_eq!(pool.total_weight(), 0);
    assert!(pool.get(tx.wtxid()).is_none());
    pool.parent_ready(tx.inputs[0].previous_output.txid);
    assert!(pool.take_ready().is_empty());
    assert!(pool.by_parent.is_empty());
    assert!(pool.peer_usage.is_empty());
}
#[test]
fn witness_refresh_keeps_announce_order_and_announcer_set() {
    let parent = tx(9, Txid::default()).txid();
    let mut pool = OrphanPool::new(3);
    let first = tx(1, parent);
    let base_weight = first.weight();
    pool.insert(Arc::clone(&first), source(1), 1);
    pool.insert(tx(2, parent), source(1), 2);
    assert_eq!(pool.total_weight(), base_weight * 2);
    let changed = re_witnessed(&first, 1);
    pool.insert(Arc::clone(&changed), source(2), 3);
    assert_eq!(pool.len(), 3);
    assert_eq!(pool.total_weight(), changed.weight() + base_weight * 2);
    assert!(pool.get(first.wtxid()).is_some());
    assert!(pool.get(changed.wtxid()).is_some());
    pool.insert(Arc::clone(&first), source(3), 4);
    assert_eq!(pool.len(), 3);
    assert_eq!(pool.total_weight(), changed.weight() + base_weight * 2);
    assert_eq!(
        pool.get(first.wtxid()).map(|held| held.announcers.len()),
        Some(2)
    );
    assert_eq!(
        pool.get(first.wtxid()).map(|held| held.arrival_time),
        Some(1)
    );
    let live = HashSet::from([source(1), source(2), source(3)]);
    assert_eq!(pool.maintain(121, &live), 1);
    assert!(pool.get(first.wtxid()).is_none());
    assert!(pool.get(changed.wtxid()).is_some());
}
#[test]
fn readiness_is_deduplicated_and_removed_with_eviction() {
    let parent = tx(9, Txid::default()).txid();
    let mut pool = OrphanPool::new(1);
    let child = tx(1, parent);
    pool.insert(Arc::clone(&child), source(1), 0);
    pool.parent_ready(parent);
    pool.parent_ready(parent);
    let ready = pool.take_ready();
    assert_eq!(ready.len(), 1);
    assert_eq!(ready[0].1, source(1));
    assert_eq!(pool.len(), 1);
    pool.mark_ready(child.wtxid(), source(1));
    pool.insert(tx(2, parent), source(1), 0);
    assert!(pool.get(child.wtxid()).is_some());
    assert_eq!(pool.take_ready().len(), 1);
    pool.mark_ready(child.wtxid(), source(1));
    assert_eq!(pool.take_ready().len(), 1);
    pool.mark_ready(child.wtxid(), source(1));
    pool.remove(child.wtxid());
    assert!(pool.get(child.wtxid()).is_none());
    assert!(pool.ready_ids.is_empty());
    assert!(pool.ready.is_empty());
    assert!(pool.take_ready().is_empty());
}
#[test]
fn aggregate_weight_evicts_fifo_even_when_count_quota_has_room() {
    let parent = tx(9, Txid::default()).txid();
    let first = tx(1, parent);
    let second = tx(2, parent);
    let one_weight = first.weight();
    let mut pool = OrphanPool::with_limits(
        10,
        one_weight.saturating_add(1),
        DEFAULT_PEER_ANNOUNCEMENTS,
        DEFAULT_PEER_ANNOUNCEMENT_WEIGHT,
        DEFAULT_PEER_LATENCY,
    );

    pool.insert(Arc::clone(&first), source(1), 0);
    assert_eq!(pool.total_weight(), one_weight);
    pool.parent_ready(parent);
    pool.insert(Arc::clone(&second), source(1), 0);

    assert_eq!(pool.len(), 1);
    assert!(pool.get(first.wtxid()).is_some());
    assert!(pool.get(second.wtxid()).is_none());
    assert_eq!(pool.total_weight(), first.weight());
    assert!(pool.total_weight() <= one_weight.saturating_add(1));
    let ready = pool.take_ready();
    assert_eq!(ready.len(), 1);
    assert!(Arc::ptr_eq(&ready[0].0.tx, &first));
    assert_eq!(pool.peer_usage.len(), 1);
    assert_eq!(
        pool.peer_usage
            .get(&source(1))
            .map(|usage| usage.announcements),
        Some(1)
    );
}

#[test]
fn maintenance_expires_old_bodies_and_cleans_every_index() {
    let parent = tx(9, Txid::default()).txid();
    let mut pool = OrphanPool::new(10);
    let expired = tx(1, parent);
    let current = tx(2, parent);
    pool.insert(Arc::clone(&expired), source(1), 10);
    pool.insert(Arc::clone(&current), source(2), 20);
    pool.parent_ready(parent);

    let live = HashSet::from([source(1), source(2)]);
    assert_eq!(pool.maintain(131, &live), 1);
    assert!(pool.get(expired.wtxid()).is_none());
    assert!(pool.get(current.wtxid()).is_some());
    assert_eq!(pool.take_ready().len(), 1);
    assert_eq!(pool.total_weight(), current.weight());
}

#[test]
fn maintenance_uses_exact_connection_identity() {
    let parent = tx(9, Txid::default()).txid();
    let mut pool = OrphanPool::new(10);
    let predecessor = tx(1, parent);
    let successor = tx(2, parent);
    pool.insert(Arc::clone(&predecessor), source(1), 0);
    pool.insert(Arc::clone(&successor), source(2), 119);

    let live = HashSet::from([source(2)]);
    assert_eq!(pool.maintain(120, &live), 1);
    assert!(pool.get(predecessor.wtxid()).is_none());
    assert!(pool.get(successor.wtxid()).is_some());

    assert_eq!(pool.maintain(119 + DEFAULT_ORPHAN_TIMEOUT_SECS, &live), 1);
    assert_eq!(pool.len(), 0);
    assert_eq!(pool.total_weight(), 0);
    assert!(pool.entries.is_empty());
    assert!(pool.by_parent.is_empty());
    assert!(pool.peer_usage.is_empty());
}

#[test]
fn transaction_scoped_rejection_releases_the_resident_variants_weight() {
    let parent = tx(9, Txid::default()).txid();
    let resident = tx(1, parent);
    let sibling = tx(2, parent);
    let rejected = re_witnessed(&resident, 1);
    assert_ne!(resident.weight(), rejected.weight());
    let mut state = AdmissionLifecycle::default();
    state.orphans.insert(Arc::clone(&resident), source(1), 0);
    state.orphans.insert(Arc::clone(&rejected), source(2), 0);
    state.orphans.insert(Arc::clone(&sibling), source(3), 0);
    state.orphans.parent_ready(parent);
    assert!(state.orphans.get_by_txid(resident.txid()).is_some());
    state.reject(&rejected, RejectScope::Transaction);
    assert_eq!(state.orphans.total_weight(), sibling.weight());
    assert!(state.orphans.get_by_txid(resident.txid()).is_none());
    assert!(state.orphans.get(resident.wtxid()).is_none());
    assert!(state.orphans.get(rejected.wtxid()).is_none());
    let ready = state.orphans.take_ready();
    assert_eq!(ready.len(), 1);
    assert!(Arc::ptr_eq(&ready[0].0.tx, &sibling));
    assert_eq!(state.orphans.len(), 1);
}

#[test]
fn witness_refresh_does_not_extend_expiry() {
    let parent = tx(9, Txid::default()).txid();
    let mut pool = OrphanPool::new(10);
    let first = tx(1, parent);
    pool.insert(Arc::clone(&first), source(1), 0);
    pool.insert(Arc::clone(&first), source(2), 119);

    let live = HashSet::from([source(1), source(2)]);
    assert_eq!(pool.maintain(120, &live), 1);
    assert!(pool.get(first.wtxid()).is_none());
}

#[test]
fn rejects_are_bounded_and_chain_reset_clears_both_indexes() {
    let mut state = AdmissionLifecycle {
        reject_cap: 2,
        ..AdmissionLifecycle::default()
    };
    let first = tx(1, Txid::default());
    let second = tx(2, Txid::default());
    state.reject(&first, RejectScope::Transaction);
    state.reject(&second, RejectScope::Transaction);
    state.reject(&tx(3, Txid::default()), RejectScope::Transaction);
    assert_eq!(state.rejects_len(), 2);
    assert!(!state.is_rejected(Hash256::from(first.txid())));
    state.clear_rejects();
    assert_eq!(state.rejects_len(), 0);
    assert!(state.reject_order.is_empty());
    assert!(!state.is_rejected(Hash256::from(second.txid())));
}

#[test]
fn rejecting_another_witness_preserves_the_resident_body_and_ready_work() {
    let parent = tx(9, Txid::default()).txid();
    let resident = tx(1, parent);
    let rejected = re_witnessed(&resident, 1);
    let sibling = re_witnessed(&resident, 2);
    assert_eq!(resident.txid(), rejected.txid());
    assert_ne!(resident.wtxid(), rejected.wtxid());
    assert_ne!(rejected.wtxid(), sibling.wtxid());

    let mut state = AdmissionLifecycle::default();
    state.orphans.insert(Arc::clone(&resident), source(1), 0);
    state.orphans.insert(Arc::clone(&sibling), source(2), 0);
    state.orphans.parent_ready(parent);
    state.reject(&rejected, RejectScope::Witness);
    assert_eq!(
        state.orphans.total_weight(),
        resident.weight() + sibling.weight()
    );
    assert!(state.is_rejected(Hash256::from(rejected.wtxid())));
    assert!(!state.is_rejected(Hash256::from(resident.wtxid())));
    let ready = state.orphans.take_ready();
    assert_eq!(ready.len(), 2);
    assert!(
        ready
            .iter()
            .any(|(held, _)| Arc::ptr_eq(&held.tx, &resident))
    );
    assert!(
        ready
            .iter()
            .any(|(held, _)| Arc::ptr_eq(&held.tx, &sibling))
    );

    state.reject(&resident, RejectScope::Witness);
    assert_eq!(state.orphans.len(), 1);
    assert!(state.orphans.get(resident.wtxid()).is_none());
    assert!(state.orphans.get(sibling.wtxid()).is_some());
    assert_eq!(state.orphans.total_weight(), sibling.weight());
    assert_eq!(state.rejects_len(), 2);
}

#[test]
fn same_wtxid_keeps_all_announcers_and_disconnect_removes_one() {
    let parent = tx(9, Txid::default()).txid();
    let mut pool = OrphanPool::new(10);
    let body = tx(1, parent);
    pool.insert(Arc::clone(&body), source(1), 0);
    pool.insert(Arc::clone(&body), source(2), 0);
    assert_eq!(pool.len(), 1);
    assert_eq!(
        pool.get(body.wtxid()).map(|held| held.announcers.len()),
        Some(2)
    );

    let live = HashSet::from([source(1)]);
    assert_eq!(pool.maintain(1, &live), 0);
    assert!(pool.get(body.wtxid()).is_some());
    pool.parent_ready(parent);
    let ready = pool.take_ready();
    assert_eq!(ready.len(), 1);
    assert!(Arc::ptr_eq(&ready[0].0.tx, &body));
    assert_eq!(ready[0].1, source(1));

    let live = HashSet::new();
    assert_eq!(pool.maintain(2, &live), 1);
    assert!(pool.get(body.wtxid()).is_none());
    assert!(pool.peer_usage.is_empty());
}

#[test]
fn eviction_trims_the_highest_peer_score_before_protected_peer() {
    let parent = tx(9, Txid::default()).txid();
    let protected = tx(1, parent);
    let first = tx(2, parent);
    let second = tx(3, parent);
    let mut pool = OrphanPool::with_limits(
        2,
        DEFAULT_MAX_ORPHAN_WEIGHT,
        1,
        DEFAULT_PEER_ANNOUNCEMENT_WEIGHT,
        DEFAULT_PEER_LATENCY,
    );
    pool.insert(Arc::clone(&protected), source(1), 0);
    pool.insert(Arc::clone(&first), source(2), 1);
    pool.insert(Arc::clone(&second), source(2), 2);

    assert_eq!(pool.len(), 2);
    assert!(pool.get(protected.wtxid()).is_some());
    assert!(pool.get(first.wtxid()).is_none());
    assert!(pool.get(second.wtxid()).is_some());
}
