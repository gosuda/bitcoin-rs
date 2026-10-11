use super::tests::{CountingInventory, item, registered_source, select, source};
use super::*;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

fn candidate(
    peer: PeerSource,
    n: u32,
    now: Instant,
    preferred: bool,
    priority: u64,
) -> Announcement {
    Announcement {
        source: peer,
        item: item(n),
        ready: now,
        preferred,
        priority,
    }
}
fn tx(n: u32) -> Inventory {
    let Inventory::WTx(hash) = item(n) else {
        panic!("WTX fixture")
    };
    Inventory::WitnessTransaction(bitcoin::Txid::from_byte_array(hash.to_byte_array()))
}
fn identity(item: Inventory) -> Identity {
    Identity::from_inventory(item).expect("transaction inventory")
}

fn consistent(policy: &TxPolicy) {
    let mut expected = BTreeSet::new();
    let mut counts = HashMap::new();
    let mut raw_counts = HashMap::new();
    let mut sources = HashSet::new();
    let mut owners = HashSet::new();
    let mut in_flight = HashMap::new();
    let mut total = 0;
    for (&key, request) in &policy.requests {
        assert_ne!(request.candidates, []);
        if let Some((owner, _)) = request.owner {
            *in_flight.entry(owner).or_insert(0usize) += 1;
            assert!(
                request
                    .candidates
                    .iter()
                    .any(|candidate| candidate.source == owner)
            );
            assert!(
                owners.insert(key.hash_bytes()),
                "at most one raw-hash owner"
            );
        }
        for candidate in &request.candidates {
            assert_eq!(identity(candidate.item), key);
            assert!(
                sources.insert((key.hash_bytes(), candidate.source)),
                "same source/raw hash never duplicates across kinds"
            );
            *counts.entry(candidate.source).or_insert(0usize) += 1;
            *raw_counts.entry(key.hash_bytes()).or_insert(0usize) += 1;
            total += 1;
            if !candidate.preferred
                && request
                    .owner
                    .is_none_or(|(owner, _)| owner != candidate.source)
            {
                assert!(expected.insert((
                    candidate.priority,
                    key,
                    candidate.source.connection_id().get()
                )));
            }
        }
    }
    assert_eq!(policy.evictable, expected);
    assert_eq!(policy.counts, counts);
    assert_eq!(policy.announcements, total);
    assert_eq!(policy.counts.values().sum::<usize>(), total);
    assert!(total <= MAX_ANNOUNCEMENTS);
    assert!(
        counts
            .values()
            .all(|count| *count <= MAX_PEER_ANNOUNCEMENTS)
    );
    assert!(raw_counts.values().all(|count| *count <= MAX_ALTERNATES));
    assert!(in_flight.values().all(|count| *count <= MAX_PEER_IN_FLIGHT));
}

// Read-only snapshots prove all rejection paths preserve metadata as well as counts.
fn snapshot(policy: &TxPolicy) -> String {
    format!("{policy:?}")
}
fn fill(policy: &mut TxPolicy, now: Instant, preferred: bool) -> Vec<PeerSource> {
    let remaining = MAX_ANNOUNCEMENTS - policy.announcements;
    let mut peers = Vec::new();
    for n in 0..remaining {
        if n % MAX_PEER_ANNOUNCEMENTS == 0 {
            peers.push(source(
                u16::try_from(100 + n / MAX_PEER_ANNOUNCEMENTS).expect("port"),
            ));
        }
        let peer = *peers.last().expect("source");
        let n = u32::try_from(n).expect("count") + 100_000;
        assert!(policy.announce(candidate(peer, n, now, preferred, u64::from(n))));
    }
    peers
}

#[test]
fn combined_caps_use_one_local_victim_and_never_spend_an_unrelated_slot_on_refusal() {
    for protected in [false, true] {
        let now = Instant::now();
        let mut policy = TxPolicy::default();
        let mut peers = Vec::new();
        for n in 0..8u16 {
            let peer = source(n + 1);
            peers.push(peer);
            // The owner is the numeric worst victim, but initially the only ready
            // source. Omitting the owner filter must not turn admission into refusal.
            let ready = if n == 0 { now } else { now + SOURCE_DELAY };
            let priority = if n == 0 { u64::MAX } else { u64::from(n) };
            let mut entry = candidate(peer, 1, ready, protected, priority);
            if n % 2 == 0 {
                entry.item = tx(1);
            }
            assert!(policy.announce(entry));
        }
        let owner = select(&mut policy, now)[0];
        assert_eq!(owner.1.source, peers[0]);
        let deadline = policy.requests[&owner.0].owner;
        fill(&mut policy, now, false);
        consistent(&policy);
        let global = *policy.evictable.last().expect("global weak victim");
        assert_ne!(global.1.hash_bytes(), identity(item(1)).hash_bytes());
        let before = snapshot(&policy);
        assert_eq!(policy.counts[&peers[1]], 1);
        for duplicate_item in [item(1), tx(1)] {
            let mut duplicate = candidate(
                peers[1],
                1,
                now.checked_sub(SOURCE_DELAY).expect("prior instant"),
                !protected,
                0,
            );
            duplicate.item = duplicate_item;
            assert!(!policy.announce(duplicate));
            assert_eq!(
                snapshot(&policy),
                before,
                "low-count duplicate at both caps"
            );
        }
        let incoming = candidate(source(9), 1, now, true, 99);
        assert_eq!(policy.announce(incoming), !protected);
        if protected {
            assert_eq!(snapshot(&policy), before);
            assert!(!policy.request_parent(incoming));
            assert_eq!(snapshot(&policy), before);
        } else {
            assert!(!policy.counts.contains_key(&peers[7]));
            assert_eq!(policy.counts[&incoming.source], 1);
            assert!(
                policy.evictable.contains(&global),
                "local replacement never consumes the worse remote victim"
            );
            assert_eq!(policy.announcements, MAX_ANNOUNCEMENTS);
        }
        assert_eq!(policy.requests[&owner.0].owner, deadline);
        consistent(&policy);
    }
}

#[test]
fn protected_global_cap_and_ordinary_arrivals_refuse_without_mutation() {
    let now = Instant::now();
    let mut policy = TxPolicy::default();
    fill(&mut policy, now, true);
    consistent(&policy);
    let before = snapshot(&policy);
    for preferred in [false, true] {
        assert!(!policy.announce(candidate(source(40), 500_000, now, preferred, 0)));
        assert_eq!(snapshot(&policy), before);
    }
    let mut invalid = candidate(source(41), 500_001, now, true, 0);
    invalid.item = Inventory::Block(bitcoin::BlockHash::all_zeros());
    assert!(!policy.announce(invalid));
    assert_eq!(snapshot(&policy), before);
    consistent(&policy);
}

#[test]
fn duplicate_and_peer_limit_preflight_precede_global_eviction_and_parent_reports_retention() {
    let now = Instant::now();
    let mut policy = TxPolicy::default();
    let peers = fill(&mut policy, now, false);
    let peer = peers[0];
    let before = snapshot(&policy);
    let mut duplicate = candidate(
        peer,
        100_000,
        now.checked_sub(SOURCE_DELAY).expect("prior instant"),
        true,
        0,
    );
    duplicate.item = tx(100_000);
    assert!(
        !policy.announce(duplicate),
        "opposite-kind duplicate remains unchanged"
    );
    assert_eq!(snapshot(&policy), before);
    assert!(
        !policy.announce(candidate(peer, 500_000, now, true, 0)),
        "source5000 cannot replace to evade its cap"
    );
    assert_eq!(snapshot(&policy), before);
    assert!(!policy.announce(candidate(source(80), 500_001, now, false, 0)));
    assert_eq!(snapshot(&policy), before);
    let key = identity(item(100_000));
    let old = policy.requests[&key].candidates[0];
    assert!(
        policy.request_parent(duplicate),
        "existing parent expedites at source cap"
    );
    assert_eq!(policy.counts[&peer], MAX_PEER_ANNOUNCEMENTS);
    assert_eq!(
        policy.requests[&key].candidates[0].item,
        item(100_000),
        "WTX keeps its actual wire kind"
    );
    assert!(
        !policy
            .evictable
            .contains(&(old.priority, key, peer.connection_id().get()))
    );
    assert!(
        !policy
            .evictable
            .iter()
            .any(|(_, kind, id)| *kind == key && *id == peer.connection_id().get())
    );
    consistent(&policy);
    let new_parent = candidate(source(81), 500_002, now, true, 0);
    assert!(
        policy.request_parent(new_parent),
        "constant-total replacement still retains a new parent"
    );
    assert_eq!(policy.announcements, MAX_ANNOUNCEMENTS);
    assert_eq!(policy.counts[&new_parent.source], 1);
    consistent(&policy);
}

#[test]
fn owner_claim_parent_upgrade_failure_expiry_forget_and_epoch_disconnect_keep_exact_projection() {
    let now = Instant::now();
    let mut policy = TxPolicy::default();
    let old = source(1);
    let replacement = source(1);
    let alternate = source(2);
    assert!(policy.announce(candidate(old, 1, now, false, 1)));
    assert!(policy.announce(candidate(replacement, 1, now + SOURCE_DELAY, false, 2)));
    assert!(policy.announce(candidate(old, 2, now + SOURCE_DELAY, false, 3)));
    assert!(policy.announce(candidate(alternate, 2, now + SOURCE_DELAY, false, 4)));
    consistent(&policy);
    let planned = policy.plan(now, None);
    consistent(&policy);
    let selected = policy.claim(now, &planned);
    assert_eq!(selected.len(), 1);
    consistent(&policy);
    let owner_key = selected[0].0;
    let deadline = policy.requests[&owner_key].owner;
    let before = snapshot(&policy);
    assert!(!policy.failed(owner_key, replacement, now));
    assert_eq!(snapshot(&policy), before);
    let mut parent = candidate(old, 1, now, true, 0);
    parent.item = tx(1);
    assert!(policy.request_parent(parent));
    assert_eq!(
        policy.requests[&owner_key].owner, deadline,
        "parent never replaces an owner or renews its deadline"
    );
    consistent(&policy);
    policy.disconnected(old, now);
    consistent(&policy);
    assert!(!policy.counts.contains_key(&old));
    assert!(policy.counts.contains_key(&replacement));
    let chosen = select(&mut policy, now);
    assert_eq!(chosen.len(), 1);
    consistent(&policy);
    assert_eq!(chosen[0].1.source, replacement);
    let before = snapshot(&policy);
    policy.disconnected(old, now);
    assert_eq!(snapshot(&policy), before);
    policy.plan(now + REQUEST_LIFETIME, None);
    consistent(&policy);
    assert!(!policy.counts.contains_key(&replacement));
    policy.forget(identity(item(2)));
    consistent(&policy);
    assert_eq!(policy.announcements, 0);
}

#[test]
fn equal_priority_victim_order_is_typed_and_connection_stable() {
    let now = Instant::now();
    let mut policy = TxPolicy::default();
    let mut references = Vec::new();
    for n in 0..8u16 {
        let mut entry = candidate(source(n + 1), 1, now, false, 7);
        if n % 2 == 0 {
            entry.item = tx(1);
        }
        references.push((
            identity(entry.item),
            entry.source.connection_id().get(),
            entry.source,
        ));
        assert!(policy.announce(entry));
    }
    references.sort_by_key(|(kind, id, _)| (*kind, *id));
    let victim = references.last().expect("victim").2;
    assert!(policy.announce(candidate(source(9), 1, now, true, u64::MAX)));
    assert!(!policy.counts.contains_key(&victim));
    consistent(&policy);
}

struct EvictDuringRead<'a> {
    table: &'a PeerTable,
    incoming: Announcement,
    done: AtomicBool,
}
impl TxInventory for EvictDuringRead<'_> {
    fn have_tx(&self, _: Hash256, _: bool) -> bool {
        if !self.done.swap(true, Ordering::SeqCst) {
            assert!(
                self.table.tx_policy.try_lock().is_some(),
                "gateway callback is unlocked"
            );
            assert!(self.table.tx_policy.lock().announce(self.incoming));
        }
        false
    }
    fn get_tx(&self, _: Txid) -> Option<bitcoin_rs_primitives::Tx> {
        None
    }
    fn get_tx_by_wtxid(&self, _: Wtxid) -> Option<bitcoin_rs_primitives::Tx> {
        None
    }
}

#[test]
fn callback_time_eviction_invalidates_an_unsent_plan_without_claiming_new_work() {
    let now = Instant::now();
    let table = PeerTable::new();
    let (old, old_rx) = registered_source(&table, 1);
    let (strong, strong_rx) = registered_source(&table, 9);
    {
        let mut policy = table.tx_policy.lock();
        assert!(policy.announce(candidate(old, 1, now, false, 99)));
        for n in 0..7u16 {
            assert!(policy.announce(candidate(
                source(n + 2),
                1,
                now + SOURCE_DELAY,
                false,
                u64::from(n)
            )));
        }
        consistent(&policy);
    }
    let gateway = EvictDuringRead {
        table: &table,
        incoming: candidate(strong, 1, now, true, 77),
        done: AtomicBool::new(false),
    };
    let key = identity(item(1));
    table.send_transaction_requests(now, Some(&gateway), Some(&[key]), || now);
    assert!(gateway.done.load(Ordering::SeqCst));
    assert!(old_rx.try_recv().is_err());
    assert!(strong_rx.try_recv().is_err());
    {
        let policy = table.tx_policy.lock();
        assert!(!policy.counts.contains_key(&old));
        assert_eq!(policy.requests[&key].owner, None);
        consistent(&policy);
    }
    table.send_transaction_requests(now, Some(&gateway), Some(&[key]), || now);
    assert!(matches!(strong_rx.try_recv(),Ok(Message::GetData(items)) if items==vec![item(1)]));
    consistent(&table.tx_policy.lock());
    table.transaction_response_completed(
        strong,
        Txid(Hash256::from_le_bytes(&[0; 32])),
        Wtxid(key.hash_bytes()),
    );
    consistent(&table.tx_policy.lock());
}

fn registered_inbound(
    table: &PeerTable,
    port: u16,
) -> (PeerSource, crossbeam_channel::Receiver<Message>) {
    let (sender, receiver) = crossbeam_channel::bounded(32);
    let lease = crate::PeerLease::new_inbound(sender);
    let addr = ([127, 0, 0, 1], port).into();
    table.register(addr, lease.clone());
    let version = crate::handshake::version_message(
        1,
        0,
        crate::PeerRole::FullRelay,
        bitcoin::p2p::ServiceFlags::NETWORK | bitcoin::p2p::ServiceFlags::WITNESS,
    );
    table.publish_info(
        addr,
        &lease,
        crate::PeerInfo::inbound_from_version(
            addr,
            addr,
            &version,
            0,
            0,
            Arc::new(crate::PeerCounters::default()),
        ),
    );
    (lease.source(addr), receiver)
}

#[test]
fn public_peer_table_prefers_new_outbound_source_after_inbound_hash_flood() {
    let table = PeerTable::new();
    let mut receivers = Vec::new();
    let item = tx(11);
    for port in 1..=8 {
        let (source, receiver) = registered_inbound(&table, port);
        receivers.push(receiver);
        table.announce_transactions(source, &[item]);
    }
    let (preferred, outbound) = registered_source(&table, 9);
    table.announce_transactions(preferred, &[item]);
    {
        let policy = table.tx_policy.lock();
        assert_eq!(policy.announcements, MAX_ALTERNATES);
        assert!(
            policy.requests[&identity(item)]
                .candidates
                .iter()
                .any(|entry| entry.source == preferred && entry.preferred)
        );
        consistent(&policy);
    }
    table.poll_transaction_requests_at(
        &CountingInventory::default(),
        Instant::now() + SOURCE_DELAY + Duration::from_secs(1),
    );
    assert!(matches!(outbound.try_recv(),Ok(Message::GetData(items)) if items==vec![item]));
    assert!(
        receivers
            .iter()
            .all(|receiver| receiver.try_recv().is_err())
    );
    consistent(&table.tx_policy.lock());
}

#[test]
fn public_send_refusal_and_accepted_body_retirement_leave_no_stale_references() {
    let table = PeerTable::new();
    let (peer, receiver) = registered_inbound(&table, 1);
    table.announce_transactions(peer, &[tx(12), item(13)]);
    consistent(&table.tx_policy.lock());
    table.forget_known_transaction(
        Txid(identity(tx(12)).hash_bytes()),
        Wtxid(identity(item(13)).hash_bytes()),
    );
    assert_eq!(table.tx_policy.lock().announcements, 0);
    consistent(&table.tx_policy.lock());
    table.announce_transactions(peer, &[item(14)]);
    drop(receiver);
    table.poll_transaction_requests_at(
        &CountingInventory::default(),
        Instant::now() + SOURCE_DELAY + Duration::from_secs(1),
    );
    assert_eq!(
        table.tx_policy.lock().announcements,
        0,
        "failed enqueue retires its claimed source"
    );
    consistent(&table.tx_policy.lock());
}
