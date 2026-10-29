use super::{
    AdmissionMode, AdmissionRequest, AdmitError, AdmitOutcome, BLOCK_RECONSTRUCTION_EXTRA_TXN,
    BodyInterest, ChainChangeError, CompositeObserver, ExtraTxnRing, MempoolGateway,
    MempoolObserver, ValidationEngine,
};
use crate::mutation::{AdmissionOrigin, MutationEnvelope, MutationOutcome, RemovalReason};
use crate::orphan::RejectScope;
use crate::standardness::PackageTxContext;
use crate::{Mempool, MempoolEntry, MempoolLimits};
use alloc::sync::Arc;
use alloc::vec::Vec;
use bitcoin_rs_primitives::{
    Amount, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
};
use core::sync::atomic::Ordering;
use parking_lot::{Mutex, RwLock};
use std::sync::mpsc;

#[derive(Default)]
struct CounterKeyRecorder {
    keys: Mutex<Vec<(String, usize)>>,
}

impl metrics::Recorder for CounterKeyRecorder {
    fn describe_counter(
        &self,
        _key: metrics::KeyName,
        _unit: Option<metrics::Unit>,
        _description: metrics::SharedString,
    ) {
    }

    fn describe_gauge(
        &self,
        _key: metrics::KeyName,
        _unit: Option<metrics::Unit>,
        _description: metrics::SharedString,
    ) {
    }

    fn describe_histogram(
        &self,
        _key: metrics::KeyName,
        _unit: Option<metrics::Unit>,
        _description: metrics::SharedString,
    ) {
    }

    fn register_counter(
        &self,
        key: &metrics::Key,
        _metadata: &metrics::Metadata<'_>,
    ) -> metrics::Counter {
        self.keys
            .lock()
            .push((key.name().to_owned(), key.labels().count()));
        metrics::Counter::noop()
    }

    fn register_gauge(
        &self,
        _key: &metrics::Key,
        _metadata: &metrics::Metadata<'_>,
    ) -> metrics::Gauge {
        metrics::Gauge::noop()
    }

    fn register_histogram(
        &self,
        _key: &metrics::Key,
        _metadata: &metrics::Metadata<'_>,
    ) -> metrics::Histogram {
        metrics::Histogram::noop()
    }
}

fn tx(label: u8) -> Tx {
    Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[label; 32])), 0),
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: vec![0x51, label].into(),
        }],
    }
}

fn entry(tx: &Tx) -> MempoolEntry {
    MempoolEntry::new(Arc::new(tx.clone()), 100, 1_000, 1, 7, 0)
}

fn hash(txid: &Txid) -> Hash256 {
    Hash256::from_le_bytes(txid.as_bytes())
}

#[derive(Default)]
struct RecordingObserver {
    seen: Mutex<Vec<(Hash256, MutationOutcome)>>,
    origins: Mutex<Vec<AdmissionOrigin>>,
}

impl MempoolObserver for RecordingObserver {
    fn on_mutation(&self, envelope: &MutationEnvelope) {
        self.origins.lock().push(envelope.origin);
        let mut seen = self.seen.lock();
        for change in &envelope.result.changes {
            seen.push((change.txid, change.outcome));
        }
    }
}

#[derive(Default)]
struct PayloadObserver(Mutex<Vec<MutationEnvelope>>);

impl MempoolObserver for PayloadObserver {
    fn on_mutation(&self, envelope: &MutationEnvelope) {
        self.0.lock().push(envelope.clone());
    }
}

#[test]
fn package_expiry_preserves_same_batch_accepted_bodies_and_indices()
-> Result<(), Box<dyn std::error::Error>> {
    let observer = Arc::new(PayloadObserver::default());
    let gateway = gateway_with_bodies(observer.clone());
    let expired = tx(181);
    let surviving = tx(182);
    let expired_entry = entry(&expired);
    let expired_body = Arc::clone(&expired_entry.tx);
    let mut surviving_entry = entry(&surviving);
    surviving_entry.time = crate::policy::MEMPOOL_EXPIRY_SECS + 2;
    let surviving_body = Arc::clone(&surviving_entry.tx);
    let plan = gateway
        .read()
        .prepare_package(vec![expired_entry, surviving_entry], 1)?;
    let result = gateway.commit(
        AdmissionOrigin::Rpc,
        |pool| pool.commit_package(plan),
        |result| Some(result),
    )?;
    assert_eq!(result.changes.len(), 3);
    assert_eq!(result.changes[0].outcome, MutationOutcome::Accepted);
    assert_eq!(result.changes[1].outcome, MutationOutcome::Accepted);
    assert_eq!(
        result.changes[2].outcome,
        MutationOutcome::Removed(RemovalReason::Expiry)
    );
    assert_eq!(result.changes[2].txid, hash(&expired.txid()));
    assert!(gateway.read().entry_by_txid(&expired.txid()).is_none());
    assert_eq!(gateway.read().len(), 1);
    assert!(gateway.pool.read().accepted_capture.is_none());
    let envelopes = observer.0.lock();
    assert_eq!(envelopes.len(), 1);
    let envelope = &envelopes[0];
    assert_eq!(envelope.result, result);
    assert_eq!(envelope.accepted_transactions.len(), 2);
    for ((index, body), expected) in envelope
        .accepted_transactions
        .iter()
        .zip([&expired_body, &surviving_body])
    {
        assert!(
            Arc::ptr_eq(body, expected),
            "retain the admitted allocation"
        );
        assert_eq!(hash(&body.txid()), envelope.result.changes[*index].txid);
        assert_eq!(
            envelope.result.changes[*index].outcome,
            MutationOutcome::Accepted
        );
    }
    assert_eq!(envelope.accepted_transactions[0].0, 0);
    assert_eq!(envelope.accepted_transactions[1].0, 1);
    Ok(())
}

#[test]
fn failed_mutation_clears_capture_scope_before_the_next_success()
-> Result<(), Box<dyn std::error::Error>> {
    let observer = Arc::new(PayloadObserver::default());
    let gateway = gateway_with_bodies(observer.clone());
    let stale = Arc::new(tx(183));
    let mut capture_enabled = false;
    let failure: Result<crate::MutationResult, ()> = gateway.commit(
        AdmissionOrigin::Rpc,
        |pool| {
            let capture = pool.accepted_capture.as_mut().ok_or(())?;
            capture_enabled = true;
            capture.push((stale.txid(), Arc::clone(&stale)));
            Err(())
        },
        |result| Some(result),
    );
    assert!(capture_enabled);
    assert!(failure.is_err());
    assert!(gateway.pool.read().accepted_capture.is_none());
    assert!(observer.0.lock().is_empty());
    assert_eq!(gateway.read().len(), 0);
    let next = tx(184);
    gateway.insert_entry(AdmissionOrigin::Rpc, entry(&next))?;
    let envelopes = observer.0.lock();
    assert_eq!(envelopes.len(), 1);
    assert_eq!(envelopes[0].accepted_transactions.len(), 1);
    let (index, body) = &envelopes[0].accepted_transactions[0];
    assert_eq!(*index, 0);
    assert_eq!(body.txid(), next.txid());
    assert!(!Arc::ptr_eq(body, &stale));
    assert!(gateway.pool.read().accepted_capture.is_none());
    Ok(())
}

struct LockOrderObserver {
    pool: Arc<RwLock<Mempool>>,
    saw_write_locked: std::sync::atomic::AtomicBool,
    retained: Mutex<Vec<usize>>,
}

impl MempoolObserver for LockOrderObserver {
    fn on_mutation(&self, envelope: &MutationEnvelope) {
        if self.pool.is_locked_exclusive() {
            self.saw_write_locked.store(true, Ordering::SeqCst);
        }
        self.retained
            .lock()
            .push(envelope.accepted_transactions.len());
    }
}

#[test]
fn commit_runs_no_observer_code_under_the_pool_write_lock() -> Result<(), Box<dyn std::error::Error>>
{
    let composite = CompositeObserver::new();
    assert!(!composite.wants_bodies());
    let metadata = Arc::new(RecordingObserver::default());
    composite.add_leg("metadata", dyn_observer(&metadata), BodyInterest::Metadata);
    assert!(!composite.wants_bodies());
    let bodies = Arc::new(RecordingObserver::default());
    composite.add_leg("bodies", dyn_observer(&bodies), BodyInterest::Bodies);
    assert!(composite.wants_bodies());

    for interest in [BodyInterest::Metadata, BodyInterest::Bodies] {
        let pool = Arc::new(RwLock::new(Mempool::new(MempoolLimits::default())));
        let probe = Arc::new(LockOrderObserver {
            pool: Arc::clone(&pool),
            saw_write_locked: std::sync::atomic::AtomicBool::new(false),
            retained: Mutex::new(Vec::new()),
        });
        let gateway = MempoolGateway::new(
            pool,
            Some((dyn_observer(&probe), interest)),
            ValidationEngine::Native,
            None,
        );
        gateway.insert_entry(AdmissionOrigin::Rpc, entry(&tx(91)))?;
        assert!(
            !probe.saw_write_locked.load(Ordering::SeqCst),
            "no observer code may run under the pool write lock"
        );
        assert_eq!(
            *probe.retained.lock(),
            vec![usize::from(interest == BodyInterest::Bodies)],
            "retention follows the registration-time interest"
        );
    }
    Ok(())
}

struct PanickingObserver;

impl MempoolObserver for PanickingObserver {
    fn on_mutation(&self, _envelope: &MutationEnvelope) {
        panic!("observer exploded");
    }
}

fn gateway_with(observer: Option<Arc<dyn MempoolObserver>>) -> Arc<MempoolGateway> {
    Arc::new(MempoolGateway::new(
        Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
        observer.map(|observer| (observer, BodyInterest::Metadata)),
        ValidationEngine::Native,
        None,
    ))
}

fn gateway_with_bodies(observer: Arc<dyn MempoolObserver>) -> Arc<MempoolGateway> {
    Arc::new(MempoolGateway::new(
        Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
        Some((observer, BodyInterest::Bodies)),
        ValidationEngine::Native,
        None,
    ))
}

fn dyn_observer<T: MempoolObserver + 'static>(observer: &Arc<T>) -> Arc<dyn MempoolObserver> {
    observer.clone()
}

fn removed(reason: RemovalReason) -> MutationOutcome {
    MutationOutcome::Removed(reason)
}

fn standard_tx(label: u8) -> Tx {
    let mut script = Vec::with_capacity(25);
    script.push(0x76);
    script.push(0xa9);
    script.push(0x14);
    script.extend_from_slice(&[label; 20]);
    script.push(0x88);
    script.push(0xac);
    Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid(Hash256::from_le_bytes(&[label; 32])), 0),
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: script.into(),
        }],
    }
}

fn prevout_spend(prev: OutPoint, value: u64, script: u8) -> Tx {
    Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: prev,
            script_sig: Script::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: vec![script].into(),
        }],
    }
}

fn admit_request(gateway: &MempoolGateway, tx: &Tx, origin: AdmissionOrigin) -> AdmissionRequest {
    let generation = gateway
        .stable_generation()
        .expect("generation is even in test setup");
    let sequence = gateway.read().sequence_number();
    AdmissionRequest {
        tx: Arc::new(tx.clone()),
        context: PackageTxContext {
            fee: 1_000,
            vsize: 100,
            sigop_cost: 0,
            missing_inputs: false,
        },
        prevouts: vec![(
            tx.inputs[0].previous_output,
            TxOut {
                value: Amount::from_sat(11_000),
                script_pubkey: vec![0x51].into(),
            },
        )],
        prevout_meta: hashbrown::HashMap::new(),
        csv_active: false,
        next_block_script_flags: bitcoin_rs_script::VerifyFlags::STANDARD,
        locktime_cutoff: 0,
        max_feerate_sat_per_kvb: None,
        time: 1,
        height: 1,
        origin,
        expected_generation: generation,
        expected_sequence: sequence,
    }
}

#[test]
fn accepted_and_block_inclusion_events_arrive_in_commit_order() {
    let observer = Arc::new(RecordingObserver::default());
    let gateway = gateway_with(Some(dyn_observer(&observer)));

    let parent = tx(1);
    let parent_txid = parent.txid();
    let mut child = tx(2);
    child.inputs[0].previous_output = OutPoint::new(parent_txid, 0);
    gateway
        .insert_entry(AdmissionOrigin::Rpc, entry(&parent))
        .expect("parent in");
    gateway
        .insert_entry(AdmissionOrigin::Rpc, entry(&child))
        .expect("child in");
    gateway.remove_for_block(AdmissionOrigin::Rpc, &[&parent], &[parent_txid], 8, 1);

    let seen = observer.seen.lock();
    assert_eq!(
        *seen,
        vec![
            (hash(&parent_txid), MutationOutcome::Accepted),
            (hash(&child.txid()), MutationOutcome::Accepted),
            (hash(&parent_txid), removed(RemovalReason::BlockInclusion)),
        ],
        "one event per change, in commit order"
    );
    drop(seen);
    assert_eq!(
        *observer.origins.lock(),
        vec![
            AdmissionOrigin::Rpc,
            AdmissionOrigin::Rpc,
            AdmissionOrigin::Rpc
        ],
        "commit must publish the origin that entered the mutation"
    );
}

#[test]
fn remove_for_block_publishes_removals_with_origins() {
    let observer = Arc::new(RecordingObserver::default());
    let gateway = gateway_with(Some(dyn_observer(&observer)));

    let mined = tx(3);
    let mined_txid = mined.txid();
    gateway
        .insert_entry(AdmissionOrigin::Rpc, entry(&mined))
        .expect("in");
    observer.seen.lock().clear();
    gateway.remove_for_block(AdmissionOrigin::Rpc, &[&mined], &[mined_txid], 8, 1);

    let seen = observer.seen.lock();
    assert_eq!(
        *seen,
        vec![(hash(&mined_txid), removed(RemovalReason::BlockInclusion))],
    );
}

#[test]
fn remove_for_block_leaves_unmined_child_and_publishes_only_the_parent() {
    let observer = Arc::new(RecordingObserver::default());
    let gateway = gateway_with(Some(dyn_observer(&observer)));

    let parent = tx(15);
    let parent_txid = parent.txid();
    let mut child = tx(16);
    child.inputs[0].previous_output = OutPoint::new(parent_txid, 0);
    let child_txid = child.txid();
    gateway
        .insert_entry(AdmissionOrigin::Rpc, entry(&parent))
        .expect("parent in");
    gateway
        .insert_entry(AdmissionOrigin::Rpc, entry(&child))
        .expect("child in");
    observer.seen.lock().clear();

    let result = gateway.remove_for_block(AdmissionOrigin::Rpc, &[&parent], &[parent_txid], 8, 1);

    assert_eq!(result.changes.len(), 1);
    assert_eq!(
        *observer.seen.lock(),
        vec![(hash(&parent_txid), removed(RemovalReason::BlockInclusion))]
    );
    assert!(gateway.read().contains_txid(&child_txid));
    assert_eq!(gateway.read().len(), 1);
}

#[test]
fn failed_insert_and_noop_remove_publish_nothing() {
    let observer = Arc::new(RecordingObserver::default());
    let gateway = gateway_with(Some(dyn_observer(&observer)));
    let before = gateway.read().sequence_number();

    let poor = MempoolEntry::new(Arc::new(tx(4)), 100, 50, 1, 7, 0);
    assert!(gateway.insert_entry(AdmissionOrigin::Rpc, poor).is_err());
    let stranger = tx(5);
    let stranger_txid = stranger.txid();
    gateway.remove_for_block(AdmissionOrigin::Rpc, &[&stranger], &[stranger_txid], 8, 1);
    gateway.clear(AdmissionOrigin::Rpc);

    assert!(observer.seen.lock().is_empty());
    assert_eq!(
        gateway.read().sequence_number(),
        before,
        "no change may move the sequence"
    );
}

#[test]
fn replacement_tags_direct_conflicts_and_descendants() {
    let observer = Arc::new(RecordingObserver::default());
    let gateway = gateway_with(Some(dyn_observer(&observer)));

    let parent = tx(6);
    let parent_txid = parent.txid();
    gateway
        .insert_entry(AdmissionOrigin::Rpc, entry(&parent))
        .expect("parent in");
    let mut child = tx(7);
    child.inputs[0].previous_output = OutPoint::new(parent_txid, 0);
    child.inputs[0].sequence = Sequence::ENABLE_RBF_NO_LOCKTIME;
    let child_txid = child.txid();
    gateway
        .insert_entry(AdmissionOrigin::Rpc, entry(&child))
        .expect("child in");
    let mut grandchild = tx(8);
    grandchild.inputs[0].previous_output = OutPoint::new(child_txid, 0);
    grandchild.inputs[0].sequence = Sequence::ENABLE_RBF_NO_LOCKTIME;
    let grandchild_txid = grandchild.txid();
    gateway
        .insert_entry(AdmissionOrigin::Rpc, entry(&grandchild))
        .expect("grandchild in");
    observer.seen.lock().clear();

    let mut replacement = tx(9);
    replacement.inputs[0].previous_output = OutPoint::new(parent_txid, 0);
    replacement.inputs[0].sequence = Sequence::ENABLE_RBF_NO_LOCKTIME;
    let replacement_txid = replacement.txid();
    let result = gateway
        .replace_transaction(
            AdmissionOrigin::Rpc,
            &crate::ReplacementCandidate::new(Arc::new(replacement), 100, 5_000, 1),
            1,
            7,
        )
        .expect("replacement lands");

    assert_eq!(result.changes.len(), 3);
    assert_eq!(
        result.changes,
        vec![
            crate::mutation::change(&child_txid, removed(RemovalReason::Replaced)),
            crate::mutation::change(&grandchild_txid, removed(RemovalReason::Descendant),),
            crate::mutation::change(&replacement_txid, MutationOutcome::Accepted),
        ],
        "conflicts first (parent before descendant), then the replacement"
    );
    let seen = observer.seen.lock();
    assert_eq!(
        &*seen,
        &result
            .changes
            .iter()
            .map(|c| (c.txid, c.outcome))
            .collect::<Vec<_>>()
    );
}

#[test]
fn observer_panic_does_not_roll_back_the_mutation() {
    let gateway = gateway_with(Some(Arc::new(PanickingObserver)));

    let committed = tx(9);
    let committed_txid = committed.txid();
    gateway
        .insert_entry(AdmissionOrigin::Rpc, entry(&committed))
        .expect("still returns");

    assert!(
        gateway.read().contains_txid(&committed_txid),
        "the mutation stands after the observer panicked"
    );
}

#[test]
fn no_observer_still_mutates() {
    let gateway = gateway_with(None);
    let result = gateway
        .insert_entry(AdmissionOrigin::Rpc, entry(&tx(10)))
        .expect("in");
    assert_eq!(result.changes.len(), 1);
    assert_eq!(result.sequence_base, 1);
    assert_eq!(gateway.read().sequence_number(), 1);
}

#[test]
fn sequence_base_matches_per_change_assignment() {
    let gateway = gateway_with(None);
    let parent = tx(11);
    let parent_txid = parent.txid();
    let mut child = tx(12);
    child.inputs[0].previous_output = OutPoint::new(parent_txid, 0);
    gateway
        .insert_entry(AdmissionOrigin::Rpc, entry(&parent))
        .expect("in");
    gateway
        .insert_entry(AdmissionOrigin::Rpc, entry(&child))
        .expect("in");
    let removed = gateway.remove_for_block(AdmissionOrigin::Rpc, &[&parent], &[parent_txid], 8, 1);

    assert_eq!(removed.changes.len(), 1);
    assert_eq!(removed.sequence_base, 3);
    assert_eq!(removed.sequence_of(0), Some(3));
    assert_eq!(gateway.read().sequence_number(), 3);
}

#[test]
fn insert_reports_accepted_then_policy_evictions() {
    let observer = Arc::new(RecordingObserver::default());
    let gateway = MempoolGateway::new(
        Arc::new(RwLock::new(Mempool::new(MempoolLimits {
            min_relay_fee_sat_per_kvb: 0,
            max_total_bytes: 150,
            ..MempoolLimits::default()
        }))),
        Some((dyn_observer(&observer), BodyInterest::Metadata)),
        ValidationEngine::Native,
        None,
    );

    let low = MempoolEntry::new(Arc::new(tx(13)), 100, 100, 1, 7, 0);
    let high = MempoolEntry::new(Arc::new(tx(14)), 100, 900, 1, 7, 0);
    gateway
        .insert_entry(AdmissionOrigin::Rpc, low)
        .expect("low in");
    let result = gateway
        .insert_entry(AdmissionOrigin::Rpc, high)
        .expect("high in");

    assert_eq!(
        result.changes.len(),
        2,
        "the eviction is part of the insert"
    );
    assert_eq!(result.changes[0].outcome, MutationOutcome::Accepted);
    assert_eq!(result.changes[0].txid, hash(&tx(14).txid()));
    assert_eq!(
        result.changes[1].outcome,
        MutationOutcome::Removed(RemovalReason::PolicyEviction)
    );
    assert_eq!(result.changes[1].txid, hash(&tx(13).txid()));
    assert_eq!(result.sequence_base, 2);
    assert_eq!(result.sequence_of(1), Some(3));
    assert!(
        observer.seen.lock().ends_with(
            &result
                .changes
                .iter()
                .map(|change| (change.txid, change.outcome))
                .collect::<Vec<_>>()
        )
    );
}

#[test]
fn clear_reports_every_entry_and_empty_clear_moves_nothing() {
    let gateway = gateway_with(None);
    let first = tx(15);
    let second = tx(16);
    gateway
        .insert_entry(AdmissionOrigin::Rpc, entry(&first))
        .expect("in");
    gateway
        .insert_entry(AdmissionOrigin::Rpc, entry(&second))
        .expect("in");
    let before = gateway.read().sequence_number();

    let cleared = gateway.clear(AdmissionOrigin::Rpc);
    assert_eq!(cleared.changes.len(), 2);
    assert!(
        cleared
            .changes
            .iter()
            .all(|change| { change.outcome == MutationOutcome::Removed(RemovalReason::Clear) })
    );
    assert_eq!(cleared.sequence_base, before + 1);
    assert_eq!(gateway.read().sequence_number(), before + 2);

    let empty = gateway.clear(AdmissionOrigin::Rpc);
    assert!(empty.is_empty());
    assert_eq!(empty.sequence_base, 0);
    assert_eq!(
        gateway.read().sequence_number(),
        before + 2,
        "clear-on-empty assigns nothing"
    );
}

struct GatedObserver {
    entered: Mutex<Option<std::sync::mpsc::Sender<()>>>,
    release: Mutex<Option<std::sync::mpsc::Receiver<()>>>,
    stream: Mutex<Vec<u64>>,
}

impl MempoolObserver for GatedObserver {
    fn on_mutation(&self, envelope: &MutationEnvelope) {
        let result = &envelope.result;
        let mut stream = self.stream.lock();
        let first_call = stream.is_empty();
        for index in 0..result.len() {
            stream.push(result.sequence_of(index).unwrap_or(u64::MAX));
        }
        drop(stream);
        if first_call {
            self.entered
                .lock()
                .take()
                .expect("entered sender armed once")
                .send(())
                .expect("main thread still waiting");
            self.release
                .lock()
                .take()
                .expect("release receiver armed once")
                .recv()
                .expect("main thread still alive to release us");
        }
    }
}

#[test]
fn gated_callback_lets_concurrent_mutation_enqueue_and_return() {
    for (first_admission, second_admission) in
        [(false, false), (false, true), (true, false), (true, true)]
    {
        let (entered_tx, entered_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let observer = Arc::new(GatedObserver {
            entered: Mutex::new(Some(entered_tx)),
            release: Mutex::new(Some(release_rx)),
            stream: Mutex::new(Vec::new()),
        });
        let gateway = gateway_with(Some(dyn_observer(&observer)));

        let first_tx = if first_admission {
            standard_tx(20)
        } else {
            tx(20)
        };
        let first_txid = first_tx.txid();
        let first = Arc::clone(&gateway);
        let first_handle =
            std::thread::spawn(move || commit_ordering_tx(&first, &first_tx, first_admission));
        entered_rx
            .recv_timeout(core::time::Duration::from_secs(10))
            .expect("first observer call started");

        let second_tx = if second_admission {
            standard_tx(21)
        } else {
            tx(21)
        };
        let second_txid = second_tx.txid();
        let second = Arc::clone(&gateway);
        let second_handle = std::thread::spawn(move || {
            let result = commit_ordering_tx(&second, &second_tx, second_admission);
            let _ = done_tx.send(result);
        });

        let queued_result = done_rx
            .recv_timeout(core::time::Duration::from_secs(10))
            .expect("the concurrent mutation must return while the callback is gated");
        assert_eq!(
            queued_result.sequence_base, 2,
            "the enqueued batch keeps its committed sequence"
        );

        assert_eq!(
            observer.stream.lock().len(),
            1,
            "only the gated first batch is published so far"
        );

        release_tx.send(()).expect("gate thread alive");
        first_handle.join().expect("first publisher");
        second_handle.join().expect("second publisher");

        assert_eq!(
            *observer.stream.lock(),
            vec![1, 2],
            "publish order matches sequence order"
        );
        let pool_read = gateway.read();
        assert!(pool_read.contains_txid(&first_txid));
        assert!(pool_read.contains_txid(&second_txid));
    }
}

fn commit_ordering_tx(
    gateway: &MempoolGateway,
    tx: &Tx,
    admission: bool,
) -> crate::mutation::MutationResult {
    if !admission {
        return gateway
            .insert_entry(AdmissionOrigin::Rpc, entry(tx))
            .expect("inserted");
    }
    let outcome = gateway.admit_transaction(admit_request(gateway, tx, AdmissionOrigin::Rpc));
    let Ok(AdmitOutcome::Committed(result)) = outcome else {
        panic!("admission did not commit: {outcome:?}");
    };
    result
}

struct ReentrantObserver {
    gateway: Mutex<Option<Arc<MempoolGateway>>>,
    stream: Mutex<Vec<u64>>,
    nested: Mutex<Vec<crate::mutation::MutationResult>>,
}

impl MempoolObserver for ReentrantObserver {
    fn on_mutation(&self, envelope: &MutationEnvelope) {
        let result = &envelope.result;
        {
            let mut stream = self.stream.lock();
            for index in 0..result.len() {
                stream.push(result.sequence_of(index).unwrap_or(u64::MAX));
            }
        }
        if result.sequence_base == 1 {
            let gateway = self.gateway.lock().clone();
            if let Some(gateway) = gateway {
                let nested = gateway
                    .insert_entry(AdmissionOrigin::Rpc, entry(&tx(99)))
                    .expect("nested in");
                self.nested.lock().push(nested);
            }
        }
    }
}

#[test]
fn reentrant_observer_mutation_completes_with_callback_sequence_1_2() {
    let observer = Arc::new(ReentrantObserver {
        gateway: Mutex::new(None),
        stream: Mutex::new(Vec::new()),
        nested: Mutex::new(Vec::new()),
    });
    let gateway = Arc::new(MempoolGateway::new(
        Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
        Some((dyn_observer(&observer), BodyInterest::Metadata)),
        ValidationEngine::Native,
        None,
    ));
    *observer.gateway.lock() = Some(Arc::clone(&gateway));

    gateway
        .insert_entry(AdmissionOrigin::Rpc, entry(&tx(50)))
        .expect("first in");

    let nested = observer.nested.lock();
    assert_eq!(
        nested.len(),
        1,
        "the nested mutation completed and returned"
    );
    let nested = nested.first().cloned();
    let Some(nested) = nested else {
        panic!("nested mutation must be recorded");
    };
    assert_eq!(
        nested.sequence_base, 2,
        "the nested mutation took the next sequence"
    );
    assert_eq!(nested.len(), 1);
    assert_eq!(
        *observer.stream.lock(),
        vec![1, 2],
        "callbacks run exactly once per batch, in sequence order"
    );
}

fn insert_contended(gateway: &MempoolGateway, transaction: &Tx) {
    let deadline = std::time::Instant::now() + core::time::Duration::from_secs(10);
    loop {
        match gateway.insert_entry(AdmissionOrigin::Rpc, entry(transaction)) {
            Ok(_) => return,
            Err(crate::MempoolError::StalePolicy) if std::time::Instant::now() < deadline => {
                std::thread::yield_now();
            }
            other => panic!("concurrent admission did not settle: {other:?}"),
        }
    }
}

struct ContiguityObserver {
    gateway: Mutex<Option<Arc<MempoolGateway>>>,
    stream: Mutex<Vec<u64>>,
    nested_vout: std::sync::atomic::AtomicU32,
}

fn nested_tx(vout: u32) -> Tx {
    let mut nested = tx(5);
    nested.inputs[0].previous_output = OutPoint::new(Txid(Hash256::from_le_bytes(&[5; 32])), vout);
    nested
}

impl MempoolObserver for ContiguityObserver {
    fn on_mutation(&self, envelope: &MutationEnvelope) {
        let result = &envelope.result;
        {
            let mut stream = self.stream.lock();
            for index in 0..result.len() {
                stream.push(result.sequence_of(index).unwrap_or(u64::MAX));
            }
        }
        if result.sequence_base % 16 == 1 {
            let gateway = self.gateway.lock().clone();
            if let Some(gateway) = gateway {
                let vout = self
                    .nested_vout
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                insert_contended(&gateway, &nested_tx(vout));
            }
        }
    }
}

#[test]
fn concurrent_reentrant_stream_is_contiguous() {
    const CYCLES: usize = 60;
    const THREAD_BASES: [u8; 4] = [10, 70, 130, 190];
    let observer = Arc::new(ContiguityObserver {
        gateway: Mutex::new(None),
        stream: Mutex::new(Vec::new()),
        nested_vout: std::sync::atomic::AtomicU32::new(0),
    });
    let gateway = Arc::new(MempoolGateway::new(
        Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
        Some((dyn_observer(&observer), BodyInterest::Metadata)),
        ValidationEngine::Native,
        None,
    ));
    *observer.gateway.lock() = Some(Arc::clone(&gateway));

    let handles: Vec<_> = THREAD_BASES
        .iter()
        .map(|&base| {
            let gateway = Arc::clone(&gateway);
            std::thread::spawn(move || {
                for cycle in 0..CYCLES {
                    let label = base + u8::try_from(cycle).expect("label fits in u8");
                    insert_contended(&gateway, &tx(label));
                }
            })
        })
        .collect();
    for handle in handles {
        handle.join().expect("mutator thread");
    }

    let deadline = std::time::Instant::now() + core::time::Duration::from_secs(10);
    loop {
        let sequence = gateway.read().sequence_number();
        let published = u64::try_from(observer.stream.lock().len()).expect("length fits u64");
        if published == sequence {
            std::thread::sleep(core::time::Duration::from_millis(20));
            if u64::try_from(observer.stream.lock().len()).expect("length fits u64") == sequence {
                break;
            }
        }
        assert!(
            std::time::Instant::now() < deadline,
            "publication never settled: {published} of {sequence} batches published"
        );
        std::thread::sleep(core::time::Duration::from_millis(1));
    }

    let stream = observer.stream.lock();
    let expected: Vec<u64> = (1..=u64::try_from(stream.len()).expect("length fits u64")).collect();
    assert_eq!(
        *stream, expected,
        "the published stream must be exactly the contiguous sequence range"
    );
    assert_eq!(
        u64::try_from(stream.len()).expect("length fits u64"),
        gateway.read().sequence_number(),
        "every committed change was published exactly once"
    );
}

#[derive(Default)]
struct SequenceStreamObserver {
    stream: Mutex<Vec<u64>>,
}

impl MempoolObserver for SequenceStreamObserver {
    fn on_mutation(&self, envelope: &MutationEnvelope) {
        let result = &envelope.result;
        let mut stream = self.stream.lock();
        for index in 0..result.len() {
            stream.push(result.sequence_of(index).unwrap_or(u64::MAX));
        }
    }
}

#[test]
fn concurrent_mutations_publish_in_sequence_order() {
    const CYCLES: usize = 1_500;
    const MEMBER_LABELS: [u8; 4] = [20, 21, 22, 23];
    let observer = Arc::new(SequenceStreamObserver::default());
    let gateway = Arc::new(gateway_with(Some(dyn_observer(&observer))));

    let handles: Vec<_> = MEMBER_LABELS
        .iter()
        .map(|&label| {
            let gateway = Arc::clone(&gateway);
            std::thread::spawn(move || {
                let member = tx(label);
                let member_txid = member.txid();
                for _ in 0..CYCLES {
                    insert_contended(&gateway, &member);
                    gateway.remove_for_block(
                        AdmissionOrigin::Rpc,
                        &[&member],
                        &[member_txid],
                        8,
                        1,
                    );
                }
            })
        })
        .collect();
    for handle in handles {
        handle.join().expect("mutator thread");
    }

    let total = u64::try_from(MEMBER_LABELS.len() * CYCLES * 2).expect("change count fits u64");
    let stream = observer.stream.lock();
    assert_eq!(
        u64::try_from(stream.len()).expect("stream length fits u64"),
        total,
        "every committed change published exactly once"
    );
    let expected: Vec<u64> = (1..=total).collect();
    assert_eq!(*stream, expected, "publish order must equal commit order");
}

#[test]
fn refused_insertion_preserves_state_and_publishes_nothing() {
    let observer = Arc::new(RecordingObserver::default());
    let gateway = MempoolGateway::new(
        Arc::new(RwLock::new(Mempool::new(MempoolLimits {
            min_relay_fee_sat_per_kvb: 0,
            max_total_bytes: 150,
            ..MempoolLimits::default()
        }))),
        Some((dyn_observer(&observer), BodyInterest::Metadata)),
        ValidationEngine::Native,
        None,
    );

    let filler = tx(70);
    let filler_txid = filler.txid();
    gateway
        .insert_entry(
            AdmissionOrigin::Rpc,
            MempoolEntry::new(Arc::new(filler), 100, 9_000, 1, 7, 0),
        )
        .expect("filler in");
    observer.seen.lock().clear();

    let shed = tx(71);
    let shed_txid = shed.txid();
    let before = (
        gateway.read().sequence_number(),
        gateway.read().estimator_history(),
    );
    let error = gateway
        .insert_entry(
            AdmissionOrigin::Rpc,
            MempoolEntry::new(Arc::new(shed), 100, 100, 1, 7, 0),
        )
        .expect_err("entry cannot survive trimming");
    assert_eq!(error, crate::MempoolError::Full);
    assert!(!gateway.read().contains_txid(&shed_txid));
    assert_eq!(gateway.read().min_fee_sat_per_kvb(1), 2_000);
    assert!(gateway.read().contains_txid(&filler_txid));
    assert_eq!(gateway.read().sequence_number(), before.0);
    assert_eq!(gateway.read().estimator_history(), before.1);
    assert!(observer.seen.lock().is_empty());
}

#[test]
fn rejected_replacement_preserves_pool_history_and_publication() {
    let observer = Arc::new(RecordingObserver::default());
    let gateway = MempoolGateway::new(
        Arc::new(RwLock::new(Mempool::new(MempoolLimits {
            min_relay_fee_sat_per_kvb: 0,
            max_total_bytes: 1_000,
            ..MempoolLimits::default()
        }))),
        Some((dyn_observer(&observer), BodyInterest::Metadata)),
        ValidationEngine::Native,
        None,
    );

    let prev = OutPoint::new(Txid(Hash256::from_le_bytes(&[0x73; 32])), 0);

    let original = prevout_spend(prev, 1_000, 0x51);
    let original_txid = original.txid();
    gateway
        .insert_entry(
            AdmissionOrigin::Rpc,
            MempoolEntry::new(Arc::new(original), 100, 10_000, 1, 7, 0),
        )
        .expect("original in");

    let bystander = tx(72);
    let bystander_txid = bystander.txid();
    gateway
        .insert_entry(
            AdmissionOrigin::Rpc,
            MempoolEntry::new(Arc::new(bystander), 850, 8_500_000, 1, 7, 0),
        )
        .expect("bystander in");

    let replacement = prevout_spend(prev, 100, 0x52);
    let replacement_txid = replacement.txid();
    observer.seen.lock().clear();

    gateway.prioritise(original_txid, 500).expect("fee delta");
    let before = {
        let pool = gateway.read();
        (
            pool.mining_snapshot().entries,
            pool.estimator_history(),
            pool.prioritised_transactions(),
            pool.policy_stamp(),
        )
    };
    let error = gateway
        .replace_transaction(
            AdmissionOrigin::Rpc,
            &crate::ReplacementCandidate::new(Arc::new(replacement), 900, 100_000, 1)
                .with_sigop_cost(4),
            2,
            7,
        )
        .expect_err("replacement cannot survive capacity trimming");
    assert_eq!(error, crate::RbfError::Mempool(crate::MempoolError::Full));
    let pool = gateway.read();
    assert!(pool.contains_txid(&original_txid));
    assert!(pool.contains_txid(&bystander_txid));
    assert!(!pool.contains_txid(&replacement_txid));
    assert_eq!(pool.mining_snapshot().entries, before.0);
    assert_eq!(pool.estimator_history(), before.1);
    assert_eq!(pool.prioritised_transactions(), before.2);
    assert_ne!(pool.policy_stamp(), before.3);
    assert!(pool.min_fee_sat_per_kvb(9) > 0);
    assert!(
        observer.seen.lock().is_empty(),
        "failed replacement cannot publish"
    );
}

#[test]
fn admit_transaction_rejects_a_script_invalid_input() {
    let gateway = gateway_with(None);
    let tx = standard_tx(0x83);

    let mut request = admit_request(&gateway, &tx, AdmissionOrigin::Rpc);
    request.prevouts[0].1.script_pubkey = vec![0x00].into();

    let result = gateway.admit_transaction(request);
    assert!(
        matches!(result, Err(AdmitError::Consensus)),
        "a script-invalid spend must fail verification: {result:?}"
    );
    assert!(gateway.read().is_empty());
}

#[test]
fn admission_counts_resolved_sigops_before_verification() -> Result<(), Box<dyn std::error::Error>>
{
    let gateway = gateway_with(None);
    let mut tx = standard_tx(0x84);
    let redeem_script = vec![0xae; 201];
    tx.inputs[0].script_sig = Script::from_bytes(bitcoin_rs_script::push_data(&redeem_script));
    let mut request = admit_request(&gateway, &tx, AdmissionOrigin::Rpc);
    request.prevouts[0].1.script_pubkey =
        Script::from_bytes([vec![0xa9, 0x14], vec![1; 20], vec![0x87]].concat());
    request.context.sigop_cost = 0;
    let oracle: bitcoin::Transaction =
        bitcoin::consensus::deserialize(&bitcoin_rs_primitives::consensus_bytes(&tx))?;
    let previous = bitcoin::TxOut {
        value: bitcoin::Amount::from_sat(request.prevouts[0].1.value.to_sat()),
        script_pubkey: bitcoin::ScriptBuf::from_bytes(
            request.prevouts[0].1.script_pubkey.as_bytes().to_vec(),
        ),
    };
    let cost = oracle.total_sigop_cost(|_| Some(previous.clone()));
    assert!(u32::try_from(cost)? > crate::standardness::MAX_STANDARD_TX_SIGOPS_COST);
    assert_eq!(
        gateway.admit_transaction(request),
        Err(AdmitError::Policy(
            crate::standardness::AcceptanceRejectReason::TooManySigops
        ))
    );
    assert!(gateway.read().is_empty());
    assert_eq!(gateway.read().sequence_number(), 0);
    Ok(())
}

#[test]
fn stale_generation_rejects_without_mutation_or_publication() {
    let observer = Arc::new(RecordingObserver::default());
    let gateway = gateway_with(Some(dyn_observer(&observer)));
    let candidate = tx(40);

    let mut request = admit_request(&gateway, &candidate, AdmissionOrigin::Rpc);

    let current = gateway.chain_generation.load(Ordering::Relaxed);
    gateway
        .chain_generation
        .store(current + 1, Ordering::Release);

    request.expected_generation = current;

    let outcome = gateway.admit_transaction(request);
    assert!(
        matches!(outcome, Err(AdmitError::GenerationChanged)),
        "stale generation must return GenerationChanged, got {outcome:?}"
    );
    assert_eq!(
        gateway.read().sequence_number(),
        0,
        "no sequence change on stale generation"
    );
    assert!(
        observer.seen.lock().is_empty(),
        "no observer call on stale generation"
    );
    assert!(
        !gateway.read().contains_txid(&candidate.txid()),
        "no mutation on stale generation"
    );
}

#[test]
fn stale_mempool_sequence_rejects_without_mutation_or_publication() {
    let observer = Arc::new(RecordingObserver::default());
    let gateway = gateway_with(Some(dyn_observer(&observer)));
    let candidate = tx(41);

    let other = tx(42);
    gateway
        .insert_entry(AdmissionOrigin::Rpc, entry(&other))
        .expect("other tx admitted");
    observer.seen.lock().clear();

    let mut request = admit_request(&gateway, &candidate, AdmissionOrigin::Rpc);
    let captured_sequence = request.expected_sequence;

    let other_txid = other.txid();
    gateway.remove_for_block(AdmissionOrigin::Rpc, &[&other], &[other_txid], 8, 1);

    request.expected_sequence = captured_sequence;

    let outcome = gateway.admit_transaction(request);
    assert!(
        matches!(outcome, Err(AdmitError::MempoolChanged)),
        "stale sequence must return MempoolChanged, got {outcome:?}"
    );
    assert!(
        !gateway.read().contains_txid(&candidate.txid()),
        "no added transaction on stale sequence"
    );
    let seen = observer.seen.lock();
    assert_eq!(
        seen.len(),
        1,
        "only the removal publication, no extra observer call from admission"
    );
}

#[test]
fn admit_write_gate_retries_when_the_stamp_moved_after_prepare()
-> Result<(), Box<dyn std::error::Error>> {
    let observer = Arc::new(RecordingObserver::default());
    let gateway = gateway_with(Some(dyn_observer(&observer)));
    let resident = tx(60);
    let resident_txid = resident.txid();
    gateway.insert_entry(AdmissionOrigin::Rpc, entry(&resident))?;
    observer.seen.lock().clear();

    let candidate = standard_tx(61);
    let candidate_txid = candidate.txid();
    let request = admit_request(&gateway, &candidate, AdmissionOrigin::Rpc);
    let prepared = {
        let pool = gateway.read();
        MempoolGateway::prepare_admission(
            &pool,
            &request,
            AdmissionMode::Single,
            crate::admission::AdmissionFence::Stable,
            gateway.engine(),
        )
    };

    gateway.prioritise(resident_txid, 500)?;
    assert_eq!(
        gateway.read().sequence_number(),
        request.expected_sequence,
        "prioritisation must leave the membership sequence alone"
    );

    let pool = gateway.pool.write();
    assert_eq!(
        gateway.check_admission_state(
            &pool,
            request.expected_generation,
            request.expected_sequence,
            crate::admission::AdmissionFence::Stable,
            Some(prepared.stamp),
        ),
        Err(AdmitError::MempoolChanged),
        "a moved fee-delta stamp must reject the writer recheck"
    );
    drop(pool);
    assert!(
        !gateway.read().contains_txid(&candidate_txid),
        "the rejected attempt mutates nothing"
    );
    assert!(
        observer.seen.lock().is_empty(),
        "the rejected attempt publishes nothing"
    );

    let retry = admit_request(&gateway, &candidate, AdmissionOrigin::Rpc);
    assert!(matches!(
        gateway.admit_transaction(retry),
        Ok(AdmitOutcome::Committed(_))
    ));
    assert!(gateway.read().contains_txid(&candidate_txid));
    Ok(())
}

#[test]
fn exact_duplicate_is_success_without_second_publication() {
    let observer = Arc::new(RecordingObserver::default());
    let gateway = gateway_with(Some(dyn_observer(&observer)));
    let candidate = tx(43);
    let txid = candidate.txid();

    gateway
        .insert_entry(AdmissionOrigin::Rpc, entry(&candidate))
        .expect("first insert");
    observer.seen.lock().clear();

    let request = admit_request(&gateway, &candidate, AdmissionOrigin::Rpc);
    let outcome = gateway.admit_transaction(request);
    assert!(
        matches!(outcome, Ok(AdmitOutcome::AlreadyKnown)),
        "exact duplicate must return AlreadyKnown, got {outcome:?}"
    );
    assert!(
        observer.seen.lock().is_empty(),
        "no second publication on duplicate"
    );
    assert_eq!(
        gateway.read().sequence_number(),
        1,
        "no sequence change on duplicate"
    );
    assert!(
        gateway.read().contains_txid(&txid),
        "original entry is still there"
    );
}

#[test]
fn admit_transaction_publishes_ordered_removals_then_one_accept() {
    let observer = Arc::new(RecordingObserver::default());
    let gateway = gateway_with(Some(dyn_observer(&observer)));

    let mut original = standard_tx(44);
    original.inputs[0].sequence = Sequence::ENABLE_RBF_NO_LOCKTIME;
    let original_txid = original.txid();
    let mut replacement = standard_tx(45);
    replacement.inputs[0].previous_output = original.inputs[0].previous_output;
    replacement.inputs[0].sequence = Sequence::from_consensus(0xFFFF_FFFE);
    replacement.outputs[0].value = Amount::from_sat(5_000);
    let replacement_txid = replacement.txid();

    gateway
        .insert_entry(AdmissionOrigin::Rpc, entry(&original))
        .expect("original admitted");
    observer.seen.lock().clear();

    let generation = gateway.stable_generation().expect("generation is even");
    let sequence = gateway.read().sequence_number();
    let request = AdmissionRequest {
        tx: Arc::new(replacement.clone()),
        context: PackageTxContext {
            fee: 5_000,
            vsize: 100,
            sigop_cost: 0,
            missing_inputs: false,
        },
        prevouts: vec![(
            replacement.inputs[0].previous_output,
            TxOut {
                value: Amount::from_sat(10_000),
                script_pubkey: vec![0x51].into(),
            },
        )],
        prevout_meta: hashbrown::HashMap::new(),
        csv_active: false,
        next_block_script_flags: bitcoin_rs_script::VerifyFlags::STANDARD,
        locktime_cutoff: 0,
        max_feerate_sat_per_kvb: None,
        time: 1,
        height: 1,
        origin: AdmissionOrigin::Rpc,
        expected_generation: generation,
        expected_sequence: sequence,
    };

    let outcome = gateway.admit_transaction(request);
    assert!(
        matches!(outcome, Ok(AdmitOutcome::Committed(_))),
        "replacement must commit, got {outcome:?}"
    );

    let seen = observer.seen.lock();
    let mut removed_count = 0;
    let mut accepted_count = 0;
    for (_, outcome) in seen.iter() {
        match outcome {
            MutationOutcome::Removed(_) => removed_count += 1,
            MutationOutcome::Accepted => accepted_count += 1,
        }
    }
    assert!(
        removed_count >= 1,
        "at least one removal (the replaced original)"
    );
    assert_eq!(
        accepted_count, 1,
        "exactly one Accepted, not {accepted_count}"
    );
    let accepted_index = seen
        .iter()
        .position(|(_, o)| *o == MutationOutcome::Accepted)
        .expect("an Accepted event");
    for (i, (_, outcome)) in seen.iter().enumerate() {
        if i < accepted_index {
            assert!(
                matches!(outcome, MutationOutcome::Removed(_)),
                "removals must precede the Accepted event"
            );
        }
    }
    assert!(
        !gateway.read().contains_txid(&original_txid),
        "replaced original must be gone"
    );
    assert!(
        gateway.read().contains_txid(&replacement_txid),
        "replacement must be in the pool"
    );
}

fn reconstruction_identities(
    gateway: &MempoolGateway,
) -> Vec<(Txid, bitcoin_rs_primitives::Wtxid)> {
    let mut seen = Vec::new();
    gateway.for_each_reconstruction_identity(|txid, wtxid| seen.push((txid, wtxid)));
    seen
}

fn retain(ring: &mut ExtraTxnRing, tx: &Arc<Tx>) {
    ring.insert(tx.txid(), tx.wtxid(), tx);
}

#[test]
fn extra_txn_ring_is_fifo_bounded_and_ignores_repeats() {
    let bodies: Vec<Arc<Tx>> = (0..=100_u8).map(|label| Arc::new(tx(label))).collect();
    assert_eq!(bodies.len(), BLOCK_RECONSTRUCTION_EXTRA_TXN + 1);
    let mut ring = ExtraTxnRing::default();
    for body in &bodies[..BLOCK_RECONSTRUCTION_EXTRA_TXN] {
        retain(&mut ring, body);
    }
    retain(&mut ring, &bodies[0]);
    assert_eq!(ring.entries.len(), BLOCK_RECONSTRUCTION_EXTRA_TXN);

    retain(&mut ring, &bodies[BLOCK_RECONSTRUCTION_EXTRA_TXN]);
    assert_eq!(ring.entries.len(), BLOCK_RECONSTRUCTION_EXTRA_TXN);
    assert!(
        ring.by_wtxid(bodies[0].wtxid()).is_none(),
        "the repeat did not postpone the oldest body's eviction"
    );
    let held: Vec<_> = ring.entries.iter().map(|entry| entry.wtxid).collect();
    let expected: Vec<_> = bodies[1..].iter().map(|body| body.wtxid()).collect();
    assert_eq!(held, expected, "the newest 100 remain, oldest first");

    let mut coinbase = tx(200);
    coinbase.inputs[0].previous_output = OutPoint::new(Txid::default(), u32::MAX);
    assert!(coinbase.is_coinbase());
    retain(&mut ring, &Arc::new(coinbase));
    assert_eq!(ring.entries.len(), BLOCK_RECONSTRUCTION_EXTRA_TXN);
    assert_eq!(
        ring.entries
            .iter()
            .map(|entry| entry.wtxid)
            .collect::<Vec<_>>(),
        expected,
        "a coinbase changes nothing, not even by evicting"
    );

    let mut variant = (*bodies[1]).clone();
    variant.inputs[0].witness = Witness::from_stack(vec![vec![1]]);
    let variant = Arc::new(variant);
    assert_eq!(variant.txid(), bodies[1].txid());
    assert_ne!(variant.wtxid(), bodies[1].wtxid());
    let mut siblings = ExtraTxnRing::default();
    retain(&mut siblings, &bodies[1]);
    retain(&mut siblings, &variant);
    assert_eq!(siblings.entries.len(), 2);
    assert_eq!(siblings.by_wtxid(bodies[1].wtxid()), Some(&bodies[1]));
    assert_eq!(siblings.by_wtxid(variant.wtxid()), Some(&variant));
    assert_eq!(
        siblings.by_txid(variant.txid()),
        Some(&bodies[1]),
        "a txid lookup answers the oldest variant"
    );
}

#[test]
fn replaced_bodies_are_retained_for_reconstruction_and_stay_hint_only() {
    let gateway = gateway_with(None);
    let mut original = standard_tx(46);
    original.inputs[0].sequence = Sequence::ENABLE_RBF_NO_LOCKTIME;
    let child = prevout_spend(OutPoint::new(original.txid(), 0), 5_000, 9);
    let mut replacement = standard_tx(47);
    replacement.inputs[0].previous_output = original.inputs[0].previous_output;
    replacement.inputs[0].sequence = Sequence::from_consensus(0xFFFF_FFFE);
    replacement.outputs[0].value = Amount::from_sat(6_000);
    for resident in [&original, &child] {
        gateway
            .insert_entry(AdmissionOrigin::Rpc, entry(resident))
            .expect("resident admitted");
    }
    let mut request = admit_request(&gateway, &replacement, AdmissionOrigin::Rpc);
    request.context.fee = 5_000;
    let outcome = gateway.admit_transaction(request);
    assert!(
        matches!(outcome, Ok(AdmitOutcome::Committed(_))),
        "replacement must commit, got {outcome:?}"
    );
    assert!(!gateway.read().contains_txid(&original.txid()));
    assert!(!gateway.read().contains_txid(&child.txid()));

    for replaced in [&original, &child] {
        assert_eq!(
            gateway.reconstruction_tx_by_wtxid(replaced.wtxid()),
            Some(replaced.clone())
        );
        assert_eq!(
            gateway.reconstruction_tx_by_txid(replaced.txid()),
            Some(replaced.clone())
        );
        assert_eq!(gateway.get_tx(replaced.txid()), None);
        assert_eq!(gateway.get_tx_by_wtxid(replaced.wtxid()), None);
        assert!(!gateway.have_tx(hash(&replaced.txid()), false));
    }
    let identities = reconstruction_identities(&gateway);
    assert_eq!(identities.len(), 3, "replacement once, then both extras");
    assert_eq!(
        identities
            .iter()
            .filter(|(txid, _)| *txid == replacement.txid())
            .count(),
        1
    );
}

#[test]
fn block_and_size_limit_removals_are_not_retained() {
    let gateway = gateway_with(None);
    let mined = tx(60);
    let first = tx(61);
    let second = tx(62);
    for resident in [&mined, &first, &second] {
        gateway
            .insert_entry(AdmissionOrigin::Rpc, entry(resident))
            .expect("resident admitted");
    }
    gateway.remove_for_block(AdmissionOrigin::Rpc, &[&mined], &[mined.txid()], 8, 1);
    assert_eq!(gateway.reconstruction_tx_by_wtxid(mined.wtxid()), None);

    let trimmed = gateway
        .enforce_size_limit(AdmissionOrigin::Rpc, 100)
        .expect("size trim");
    assert_eq!(trimmed.removed_txids().len(), 1);
    for resident in [&first, &second] {
        assert_eq!(
            gateway.reconstruction_tx_by_wtxid(resident.wtxid()),
            gateway.get_tx_by_wtxid(resident.wtxid()),
            "an evicted body is not kept as a reconstruction extra"
        );
    }
    assert_eq!(reconstruction_identities(&gateway).len(), 1);
}

#[test]
fn composite_isolates_a_panicking_leg() {
    let recorder = Arc::new(RecordingObserver::default());
    let metric_recorder = CounterKeyRecorder::default();
    let composite = CompositeObserver::new();
    composite.add_leg(
        "panicker",
        Arc::new(PanickingObserver),
        BodyInterest::Metadata,
    );
    composite.add_leg("recorder", dyn_observer(&recorder), BodyInterest::Metadata);
    let composite = Arc::new(composite);
    let gateway = gateway_with(Some(dyn_observer(&composite)));

    let committed = tx(40);
    let committed_txid = committed.txid();
    metrics::with_local_recorder(&metric_recorder, || {
        gateway.insert_entry(AdmissionOrigin::Rpc, entry(&committed))
    })
    .expect("still returns");

    assert!(
        gateway.read().contains_txid(&committed_txid),
        "the mutation stands after a leg panicked"
    );
    assert_eq!(
        *recorder.seen.lock(),
        vec![(hash(&committed_txid), MutationOutcome::Accepted)],
        "the leg after the panicking one still recorded"
    );
    let keys = metric_recorder.keys.lock();
    let failure = keys
        .iter()
        .find(|(name, _)| name == "node.mempool.observer_failures_total")
        .expect("aggregate observer failure counter");
    assert_eq!(
        failure.1, 0,
        "observer identity belongs in tracing, not metric labels"
    );
}

#[test]
fn gateway_contains_a_panicking_payload_destructor() {
    let gateway = gateway_with(Some(Arc::new(PanickingObserver)));
    let committed = tx(52);
    let committed_txid = committed.txid();

    assert!(
        gateway
            .insert_entry(AdmissionOrigin::Rpc, entry(&committed))
            .is_ok()
    );
    assert!(gateway.read().contains_txid(&committed_txid));
}

#[test]
fn chain_generation_starts_even_at_zero() {
    let gateway = gateway_with(None);
    assert_eq!(
        gateway.stable_generation(),
        Some(0),
        "initial generation is even zero"
    );
}

#[test]
fn stable_generation_reads_even_values() {
    let gateway = gateway_with(None);
    gateway.chain_generation.store(4, Ordering::Release);
    assert_eq!(gateway.stable_generation(), Some(4));
    gateway.chain_generation.store(7, Ordering::Release);
    assert_eq!(
        gateway.stable_generation(),
        None,
        "odd generation is not stable"
    );
}

#[test]
fn begin_chain_change_rejects_nested_begin() {
    let gateway = gateway_with(None);
    let guard = gateway
        .begin_chain_change()
        .expect("first begin succeeds on even generation");
    assert_eq!(guard.odd_generation(), 1);
    assert_eq!(guard.reserved_even(), 2);
    assert_eq!(
        gateway.stable_generation(),
        None,
        "odd generation is not stable while a chain change is active"
    );
    let err = gateway
        .begin_chain_change()
        .expect_err("nested begin rejected while odd");
    assert_eq!(err, ChainChangeError::AlreadyActive);
    drop(guard);
}

#[test]
fn explicit_finish_restores_even_generation() {
    let gateway = gateway_with(None);
    let guard = gateway.begin_chain_change().expect("begin");
    assert_eq!(guard.odd_generation(), 1);
    assert_eq!(guard.reserved_even(), 2);
    guard
        .finish()
        .expect("finish stores the reserved even value");
    assert_eq!(
        gateway.stable_generation(),
        Some(2),
        "finish restored the exact reserved even value"
    );
}

#[test]
fn dropping_chain_change_stays_unstable() {
    let gateway = gateway_with(None);
    {
        let _guard = gateway.begin_chain_change().expect("begin");
        assert_eq!(gateway.stable_generation(), None);
    }
    assert_eq!(
        gateway.stable_generation(),
        None,
        "dropping the guard without finish leaves the generation odd"
    );
    let err = gateway
        .begin_chain_change()
        .expect_err("cannot begin while odd after a dropped guard");
    assert_eq!(err, ChainChangeError::AlreadyActive);
}

#[test]
fn chain_generation_overflow_fails_closed() {
    let gateway = gateway_with(None);
    gateway
        .chain_generation
        .store(u64::MAX - 1, Ordering::Relaxed);
    let err = gateway
        .begin_chain_change()
        .expect_err("overflow must fail before any store");
    assert_eq!(err, ChainChangeError::Overflow);
    assert_eq!(
        gateway.chain_generation.load(Ordering::Relaxed),
        u64::MAX - 1,
        "generation unchanged after overflow failure"
    );
}

#[test]
fn begin_chain_change_serializes_with_inflight_admission() {
    let gateway = gateway_with(None);

    let (held_tx, held_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let gateway_a = Arc::clone(&gateway);
    let a_handle = std::thread::spawn(move || {
        let _guard = gateway_a.pool().write();
        held_tx.send(()).expect("test waiting for lock acquisition");
        release_rx
            .recv_timeout(core::time::Duration::from_secs(10))
            .expect("test alive to release");
    });

    held_rx
        .recv_timeout(core::time::Duration::from_secs(10))
        .expect("thread A acquired the pool write lock");

    let gateway_b = Arc::clone(&gateway);
    let (b_done_tx, b_done_rx) = mpsc::channel();
    let b_handle = std::thread::spawn(move || {
        let guard = gateway_b
            .begin_chain_change()
            .expect("begin after lock release");
        b_done_tx
            .send(guard)
            .expect("test waiting for begin result");
    });

    std::thread::sleep(core::time::Duration::from_millis(100));
    assert_eq!(
        gateway.stable_generation(),
        Some(0),
        "begin must not store odd while an admission holds the write lock"
    );

    release_tx.send(()).expect("thread A alive");
    a_handle.join().expect("thread A completed");

    let guard = b_done_rx
        .recv_timeout(core::time::Duration::from_secs(10))
        .expect("begin_chain_change returned after lock release");
    assert_eq!(guard.odd_generation(), 1);
    assert_eq!(guard.reserved_even(), 2);
    assert_eq!(gateway.stable_generation(), None);
    guard.finish().expect("finish restores even");
    assert_eq!(gateway.stable_generation(), Some(2));
    b_handle.join().expect("thread B completed");
}

#[test]
fn remove_for_block_distinguishes_mined_from_conflicts() {
    let observer = Arc::new(RecordingObserver::default());
    let gateway = gateway_with(Some(dyn_observer(&observer)));

    let mined = tx(10);
    let mined_txid = mined.txid();
    gateway
        .insert_entry(AdmissionOrigin::Rpc, entry(&mined))
        .expect("mined in");

    let conflict_tx = tx(11);
    let conflict_txid = conflict_tx.txid();
    let spent_outpoint = conflict_tx.inputs[0].previous_output;
    gateway
        .insert_entry(AdmissionOrigin::Rpc, entry(&conflict_tx))
        .expect("conflict in");

    let mut child = tx(12);
    child.inputs[0].previous_output = OutPoint::new(conflict_txid, 0);
    let child_txid = child.txid();
    gateway
        .insert_entry(AdmissionOrigin::Rpc, entry(&child))
        .expect("child in");

    let mut double_spend = tx(13);
    double_spend.inputs[0] = TxIn {
        previous_output: spent_outpoint,
        script_sig: Script::new(),
        sequence: Sequence::MAX,
        witness: Witness::new(),
    };
    let double_spend_txid = double_spend.txid();

    observer.seen.lock().clear();
    gateway.remove_for_block(
        AdmissionOrigin::Block,
        &[&mined, &double_spend],
        &[mined_txid, double_spend_txid],
        8,
        1,
    );

    let seen = observer.seen.lock();
    assert_eq!(
        *seen,
        vec![
            (hash(&mined_txid), removed(RemovalReason::BlockInclusion)),
            (hash(&conflict_txid), removed(RemovalReason::Conflict)),
            (hash(&child_txid), removed(RemovalReason::Conflict)),
        ],
        "mined is BlockInclusion, conflict and descendant are Conflict, in deterministic order"
    );
}

#[test]
fn admit_transaction_enforces_finality_at_the_next_block() {
    for (label, tag, lock_time, cutoff, final_now) in [
        ("lock_time == tip_height", 0x80_u8, 100_u32, None, true),
        ("lock_time == tip_height + 1", 0x81, 101, None, false),
        (
            "time lock above the applied-tip MTP",
            0x82,
            1_800_000_000,
            Some(1_700_000_000),
            false,
        ),
    ] {
        let gateway = gateway_with(None);
        let mut tx = standard_tx(tag);
        tx.lock_time = LockTime::from_consensus(lock_time);
        tx.inputs[0].sequence = Sequence::from_consensus(0xFFFF_FFFE);

        let mut request = admit_request(&gateway, &tx, AdmissionOrigin::Rpc);
        request.height = 100;
        if let Some(cutoff) = cutoff {
            request.locktime_cutoff = cutoff;
        }

        let result = gateway.admit_transaction(request);
        if final_now {
            assert!(
                matches!(result, Ok(AdmitOutcome::Committed(_))),
                "{label} must be final in the next block: {result:?}"
            );
        } else {
            assert!(
                matches!(result, Err(AdmitError::Consensus)),
                "{label} must be non-final: {result:?}"
            );
        }
    }
}

#[test]
fn admit_transaction_rejects_a_transaction_with_no_prevouts() {
    let gateway = MempoolGateway::new(
        Arc::new(RwLock::new(Mempool::new(MempoolLimits {
            min_relay_fee_sat_per_kvb: 0,
            ..MempoolLimits::default()
        }))),
        None,
        ValidationEngine::Native,
        None,
    );
    let tx = standard_tx(0x44);
    let generation = gateway.stable_generation().expect("generation is even");
    let sequence = gateway.read().sequence_number();
    let request = AdmissionRequest {
        tx: Arc::new(tx),
        context: PackageTxContext {
            fee: 1_000,
            vsize: 100,
            sigop_cost: 0,
            missing_inputs: false,
        },
        prevouts: Vec::new(),
        prevout_meta: hashbrown::HashMap::new(),
        csv_active: false,
        next_block_script_flags: bitcoin_rs_script::VerifyFlags::STANDARD,
        locktime_cutoff: 0,
        max_feerate_sat_per_kvb: None,
        time: 1,
        height: 1,
        origin: AdmissionOrigin::Rpc,
        expected_generation: generation,
        expected_sequence: sequence,
    };
    let result = gateway.admit_transaction(request);
    assert!(
        matches!(result, Err(AdmitError::Consensus)),
        "a non-coinbase tx with no prevouts must be rejected: {result:?}"
    );
    assert!(gateway.read().is_empty());
}
#[test]
fn admit_transaction_rejects_duplicate_inputs_as_consensus() {
    let gateway = MempoolGateway::new(
        Arc::new(RwLock::new(Mempool::new(MempoolLimits {
            min_relay_fee_sat_per_kvb: 0,
            ..MempoolLimits::default()
        }))),
        None,
        ValidationEngine::Native,
        None,
    );
    let mut tx = standard_tx(0x45);
    tx.inputs.push(tx.inputs[0].clone());
    let generation = gateway.stable_generation().expect("generation is even");
    let sequence = gateway.read().sequence_number();
    let request = AdmissionRequest {
        tx: Arc::new(tx.clone()),
        context: PackageTxContext {
            fee: 1_000,
            vsize: 100,
            sigop_cost: 0,
            missing_inputs: false,
        },
        prevouts: vec![(
            tx.inputs[0].previous_output,
            TxOut {
                value: Amount::from_sat(11_000),
                script_pubkey: Script::new(),
            },
        )],
        prevout_meta: hashbrown::HashMap::new(),
        csv_active: false,
        next_block_script_flags: bitcoin_rs_script::VerifyFlags::STANDARD,
        locktime_cutoff: 0,
        max_feerate_sat_per_kvb: None,
        time: 1,
        height: 1,
        origin: AdmissionOrigin::Rpc,
        expected_generation: generation,
        expected_sequence: sequence,
    };
    let result = gateway.admit_transaction(request);
    assert!(
        matches!(result, Err(AdmitError::Consensus)),
        "duplicate inputs must fail consensus verification: {result:?}"
    );
    assert!(gateway.read().is_empty());
}

#[test]
fn input_structure_checks_follow_generation_and_sequence_guards() {
    let gateway = gateway_with(None);
    let mut candidate = standard_tx(93);
    candidate.inputs.push(candidate.inputs[0].clone());
    candidate.inputs[0].witness = Witness::from_stack(vec![vec![1]]);
    let origin = AdmissionOrigin::Peer(crate::PeerToken {
        endpoint: Some(bitcoin_rs_primitives::PeerEndpoint::Ip(
            core::net::SocketAddr::from(([127, 0, 0, 1], 8333)),
        )),
        addr: Some(bitcoin_rs_primitives::PeerEndpoint::from((
            [127, 0, 0, 1],
            8333,
        ))),
        connection_id: 7,
    });
    let request = admit_request(&gateway, &candidate, origin);
    gateway.chain_generation.store(2, Ordering::Release);
    assert_eq!(
        gateway.admit_transaction(request),
        Err(AdmitError::GenerationChanged)
    );
    assert_eq!(gateway.recent_rejects_count(), 0);

    let request = admit_request(&gateway, &candidate, origin);
    gateway
        .insert_entry(AdmissionOrigin::Rpc, entry(&tx(94)))
        .expect("fixture insert");
    assert_eq!(
        gateway.admit_transaction(request),
        Err(AdmitError::MempoolChanged)
    );
    assert_eq!(gateway.recent_rejects_count(), 0);
    assert_eq!(gateway.orphan_count(), 0);
    assert_eq!(gateway.read().sequence_number(), 1);
}

#[test]
fn input_structure_nonstandard_transactions_keep_policy_precedence() {
    use crate::standardness::{AcceptanceRejectReason, StandardnessError};
    for (version, witness_len, reason) in [
        (0, 1, StandardnessError::Version),
        (2, 400_001, StandardnessError::Weight),
    ] {
        let gateway = gateway_with(None);
        let mut candidate = standard_tx(95);
        candidate.version = version;
        candidate.inputs.push(candidate.inputs[0].clone());
        candidate.inputs[0].witness = Witness::from_stack(vec![vec![0; witness_len]]);
        let request = admit_request(&gateway, &candidate, AdmissionOrigin::Rpc);
        assert_eq!(
            gateway.admit_transaction(request),
            Err(AdmitError::Policy(AcceptanceRejectReason::NonStandard(
                reason
            )))
        );
        assert!(gateway.read().is_empty());
        assert_eq!(gateway.read().sequence_number(), 0);
    }
}

fn p2sh_prevout() -> TxOut {
    let mut script = Vec::with_capacity(23);
    script.push(0xa9);
    script.push(0x14);
    script.extend_from_slice(&[0x2a; 20]);
    script.push(0x87);
    TxOut {
        value: Amount::from_sat(11_000),
        script_pubkey: script.into(),
    }
}

#[test]
fn admission_fills_script_cache_under_next_block_flags() {
    let cache = Arc::new(bitcoin_rs_consensus::ScriptExecutionCache::new());
    let gateway = Arc::new(MempoolGateway::new(
        Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
        None,
        ValidationEngine::Native,
        Some(Arc::clone(&cache)),
    ));
    let candidate = standard_tx(0x60);
    let mut request = admit_request(&gateway, &candidate, AdmissionOrigin::Rpc);
    request.next_block_script_flags = bitcoin_rs_script::VerifyFlags::MANDATORY;
    let outcome = gateway
        .admit_transaction(request)
        .expect("standard-shaped spend must admit");
    assert!(matches!(outcome, AdmitOutcome::Committed(_)));
    assert!(cache.take(candidate.wtxid(), bitcoin_rs_script::VerifyFlags::MANDATORY));
    assert!(!cache.take(candidate.wtxid(), bitcoin_rs_script::VerifyFlags::STANDARD));
}

#[test]
fn rejected_admission_fills_no_script_cache_entry() {
    let cache = Arc::new(bitcoin_rs_consensus::ScriptExecutionCache::new());
    let gateway = Arc::new(MempoolGateway::new(
        Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
        None,
        ValidationEngine::Native,
        Some(Arc::clone(&cache)),
    ));
    let candidate = standard_tx(0x61);
    let mut request = admit_request(&gateway, &candidate, AdmissionOrigin::Rpc);
    request.prevouts = vec![(request.prevouts[0].0, p2sh_prevout())];
    request.next_block_script_flags = bitcoin_rs_script::VerifyFlags::MANDATORY;
    let result = gateway.admit_transaction(request);
    assert!(matches!(result, Err(AdmitError::Consensus)));
    assert!(!cache.take(candidate.wtxid(), bitcoin_rs_script::VerifyFlags::MANDATORY));
}

#[test]
fn package_fee_cap_keeps_signed_extremes_exact() {
    let gateway = gateway_with(None);
    let candidate = standard_tx(0x63);
    let request = admit_request(&gateway, &candidate, AdmissionOrigin::Rpc);
    for (fee, rejects) in [
        (i128::MIN, false),
        (-1, false),
        (0, false),
        (i128::from(u64::MAX) + i128::from(i64::MAX), true),
        (i128::MAX, true),
    ] {
        let mut prepared = MempoolGateway::prepare_admission(
            &gateway.read(),
            &request,
            AdmissionMode::PackageRpcSubmit(Some(1_000)),
            crate::admission::AdmissionFence::Stable,
            gateway.engine(),
        );
        assert!(prepared.rejection.is_none());
        prepared.fact.modified_fee = Some(fee);
        prepared.fact.effective_fee_rate = None;
        prepared.check_package_max_feerate(Some(1_000));
        assert_eq!(
            prepared.fact.reject_reason,
            rejects.then_some(crate::standardness::AcceptanceRejectReason::MaxFeeExceeded)
        );
    }
}

#[test]
fn fee_capped_admission_fills_no_script_cache_entry() {
    let cache = Arc::new(bitcoin_rs_consensus::ScriptExecutionCache::new());
    let gateway = Arc::new(MempoolGateway::new(
        Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
        None,
        ValidationEngine::Native,
        Some(Arc::clone(&cache)),
    ));
    let candidate = standard_tx(0x62);
    let mut request = admit_request(&gateway, &candidate, AdmissionOrigin::Rpc);
    request.max_feerate_sat_per_kvb = Some(1);
    request.next_block_script_flags = bitcoin_rs_script::VerifyFlags::MANDATORY;
    let result = gateway.admit_transaction(request);
    assert!(matches!(
        result,
        Err(AdmitError::Policy(
            crate::standardness::AcceptanceRejectReason::MaxFeeExceeded
        ))
    ));
    assert!(!cache.take(candidate.wtxid(), bitcoin_rs_script::VerifyFlags::MANDATORY));
}

#[test]
fn verify_without_commit_fills_nothing() {
    let cache = Arc::new(bitcoin_rs_consensus::ScriptExecutionCache::new());
    let gateway = Arc::new(MempoolGateway::new(
        Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
        None,
        ValidationEngine::Native,
        Some(Arc::clone(&cache)),
    ));
    let candidate = standard_tx(0x63);
    let mut request = admit_request(&gateway, &candidate, AdmissionOrigin::Rpc);
    request.next_block_script_flags = bitcoin_rs_script::VerifyFlags::MANDATORY;
    {
        let pool = gateway.read();
        let mut prepared = MempoolGateway::prepare_admission(
            &pool,
            &request,
            AdmissionMode::Single,
            crate::admission::AdmissionFence::Stable,
            gateway.engine(),
        );
        prepared.verify(&request, gateway.script_cache());
    }
    assert!(!cache.take(candidate.wtxid(), bitcoin_rs_script::VerifyFlags::MANDATORY));
    let outcome = gateway
        .admit_transaction(request)
        .expect("standard-shaped spend must admit");
    assert!(matches!(outcome, AdmitOutcome::Committed(_)));
    assert!(cache.take(candidate.wtxid(), bitcoin_rs_script::VerifyFlags::MANDATORY));
}

fn script_stage_rejection(engine: ValidationEngine) -> Option<(AdmitError, RejectScope)> {
    let pool = Arc::new(RwLock::new(Mempool::new(MempoolLimits {
        min_relay_fee_sat_per_kvb: 0,
        ..MempoolLimits::default()
    })));
    let gateway = MempoolGateway::new(Arc::clone(&pool), None, engine, None);
    let candidate = standard_tx(0x51);
    let mut request = admit_request(&gateway, &candidate, AdmissionOrigin::Rpc);
    request.prevouts = vec![(request.prevouts[0].0, p2sh_prevout())];
    let guard = pool.read();
    let mut prepared = MempoolGateway::prepare_admission(
        &guard,
        &request,
        AdmissionMode::Single,
        crate::admission::AdmissionFence::Stable,
        engine,
    );
    prepared.verify(&request, None);
    prepared.rejection
}

#[test]
fn genuine_script_verdicts_on_strippable_prevouts_stay_witness_scoped() {
    assert!(matches!(
        script_stage_rejection(ValidationEngine::Native),
        Some((AdmitError::Consensus, RejectScope::Witness))
    ));
}

#[test]
fn only_genuine_script_verdicts_are_witness_strippable() {
    use bitcoin_rs_consensus::ConsensusError;
    let prevouts = [(
        OutPoint::new(Txid(Hash256::from_le_bytes(&[0x5a; 32])), 0),
        p2sh_prevout(),
    )];
    assert!(super::witness_strippable_failure(
        &ConsensusError::Script {
            input_index: 0,
            reason: "script failed: false".to_owned(),
            engine: bitcoin_rs_consensus::ScriptEngine::Native,
        },
        &prevouts,
    ));
    assert!(!super::witness_strippable_failure(
        &ConsensusError::UnsupportedEngine {
            engine: ValidationEngine::Kernel,
        },
        &prevouts,
    ));
    assert!(!super::witness_strippable_failure(
        &ConsensusError::PrevoutCount {
            input_count: 2,
            prevout_count: 1,
        },
        &prevouts,
    ));
    assert!(!super::witness_strippable_failure(
        &ConsensusError::Kernel("kernel parse failed".to_owned()),
        &prevouts,
    ));
}

fn floor_trim_gateway_with_filler() -> MempoolGateway {
    let gateway = MempoolGateway::new(
        Arc::new(RwLock::new(Mempool::new(MempoolLimits {
            min_relay_fee_sat_per_kvb: 0,
            max_total_bytes: 150,
            ..MempoolLimits::default()
        }))),
        None,
        ValidationEngine::Native,
        None,
    );
    let filler = standard_tx(70);
    let outcome = gateway.admit_transaction(admit_request(&gateway, &filler, AdmissionOrigin::Rpc));
    assert!(
        matches!(outcome, Ok(AdmitOutcome::Committed(_))),
        "filler must commit: {outcome:?}"
    );
    gateway
}

fn floor_trim_candidate(gateway: &MempoolGateway) -> AdmissionRequest {
    let shed = standard_tx(71);
    let mut request = admit_request(gateway, &shed, AdmissionOrigin::Rpc);
    request.context.fee = 100;
    request.prevouts[0].1.value = Amount::from_sat(10_100);
    request
}

#[test]
fn admit_transaction_full_refusal_bumps_the_floor() {
    let gateway = floor_trim_gateway_with_filler();
    assert_eq!(gateway.read().min_fee_sat_per_kvb(1), 0);

    let request = floor_trim_candidate(&gateway);
    let error = gateway
        .admit_transaction(request)
        .expect_err("candidate cannot survive trimming");
    assert!(
        matches!(
            error,
            AdmitError::Policy(crate::standardness::AcceptanceRejectReason::Replacement(
                crate::RbfError::Mempool(crate::MempoolError::Full)
            ))
        ),
        "refusal keeps the mempool-full report: {error:?}"
    );
    assert_eq!(gateway.read().min_fee_sat_per_kvb(1), 2_000);
    assert_eq!(gateway.read().len(), 1);
}

#[test]
fn admit_transaction_invalid_script_refusal_leaves_the_floor() {
    let gateway = floor_trim_gateway_with_filler();

    let mut request = floor_trim_candidate(&gateway);
    request.prevouts[0].1.script_pubkey = vec![0x00].into();
    let error = gateway
        .admit_transaction(request)
        .expect_err("candidate cannot survive trimming");
    assert!(
        matches!(
            error,
            AdmitError::Policy(crate::standardness::AcceptanceRejectReason::Replacement(
                crate::RbfError::Mempool(crate::MempoolError::Full)
            ))
        ),
        "refusal keeps the mempool-full report: {error:?}"
    );
    assert_eq!(gateway.read().min_fee_sat_per_kvb(1), 0);
    assert_eq!(gateway.read().len(), 1);
}

#[test]
fn admit_transaction_overcap_refusal_earns_no_bump() {
    let gateway = floor_trim_gateway_with_filler();

    let mut request = floor_trim_candidate(&gateway);
    request.max_feerate_sat_per_kvb = Some(500);
    let error = gateway
        .admit_transaction(request)
        .expect_err("candidate cannot survive trimming");
    assert!(
        matches!(
            error,
            AdmitError::Policy(crate::standardness::AcceptanceRejectReason::Replacement(
                crate::RbfError::Mempool(crate::MempoolError::Full)
            ))
        ),
        "refusal keeps the mempool-full report: {error:?}"
    );
    assert_eq!(gateway.read().min_fee_sat_per_kvb(1), 0);
    assert_eq!(gateway.read().len(), 1);
}

#[test]
fn admission_prepared_before_a_floor_raise_is_retried() {
    let gateway = MempoolGateway::new(
        Arc::new(RwLock::new(Mempool::new(MempoolLimits {
            min_relay_fee_sat_per_kvb: 0,
            max_total_bytes: 1_000,
            ..MempoolLimits::default()
        }))),
        None,
        ValidationEngine::Native,
        None,
    );
    gateway
        .insert_entry(
            AdmissionOrigin::Rpc,
            MempoolEntry::new(Arc::new(tx(90)), 100, 9_000, 1, 7, 0),
        )
        .expect("seat");
    let (generation, sequence, stamp) = {
        let pool = gateway.read();
        (
            gateway.stable_generation().expect("even"),
            pool.sequence_number(),
            pool.policy_stamp(),
        )
    };
    let error = gateway
        .insert_entry(
            AdmissionOrigin::Rpc,
            MempoolEntry::new(Arc::new(tx(92)), 950, 100, 1, 7, 0),
        )
        .expect_err("oversized");
    assert_eq!(error, crate::MempoolError::Full);
    assert!(gateway.read().min_fee_sat_per_kvb(1) > 0);
    {
        let pool = gateway.read();
        assert!(!stamp.matches(&pool));
        assert_eq!(
            gateway.check_admission_state(
                &pool,
                generation,
                sequence,
                crate::admission::AdmissionFence::Stable,
                Some(stamp),
            ),
            Err(AdmitError::MempoolChanged)
        );
    }
}

#[test]
fn remove_for_block_stamps_the_floor_for_decay() {
    let gateway = MempoolGateway::new(
        Arc::new(RwLock::new(Mempool::new(MempoolLimits {
            min_relay_fee_sat_per_kvb: 1_000,
            max_total_bytes: 400,
            ..MempoolLimits::default()
        }))),
        None,
        ValidationEngine::Native,
        None,
    );
    gateway
        .insert_entry(
            AdmissionOrigin::Rpc,
            MempoolEntry::new(Arc::new(tx(1)), 200, 400, 1, 1, 0),
        )
        .expect("low");
    gateway
        .insert_entry(
            AdmissionOrigin::Rpc,
            MempoolEntry::new(Arc::new(tx(2)), 200, 800, 1, 1, 0),
        )
        .expect("high");
    gateway
        .enforce_size_limit(AdmissionOrigin::Rpc, 200)
        .expect("eviction");
    assert_eq!(gateway.read().min_fee_sat_per_kvb(1_000), 3_000);
    gateway.remove_for_block(AdmissionOrigin::Rpc, &[], &[], 8, 1_000);
    assert_eq!(
        gateway.read().min_fee_sat_per_kvb(1_000 + 12 * 60 * 60),
        1_500
    );
}

#[test]
fn expire_returns_none_when_fresh_and_some_when_stale() {
    use crate::policy::MEMPOOL_EXPIRY_SECS;
    let observer = Arc::new(RecordingObserver::default());
    let gateway = MempoolGateway::new(
        Arc::new(RwLock::new(Mempool::new(MempoolLimits::default()))),
        Some((dyn_observer(&observer), BodyInterest::Metadata)),
        ValidationEngine::Native,
        None,
    );
    let now = MEMPOOL_EXPIRY_SECS + 1;
    let fresh = tx(80);
    gateway
        .insert_entry(
            AdmissionOrigin::Rpc,
            MempoolEntry::new(Arc::new(fresh), 100, 1_000, now, 1, 0),
        )
        .expect("fresh");
    assert!(!gateway.read().has_expired_entries(now));
    let sequence = gateway.read().sequence_number();
    assert!(gateway.expire(AdmissionOrigin::Rpc, now).is_none());
    assert_eq!(gateway.read().sequence_number(), sequence);

    let stale = tx(81);
    let stale_txid = stale.txid();
    gateway
        .insert_entry(
            AdmissionOrigin::Rpc,
            MempoolEntry::new(Arc::new(stale), 100, 1_000, 0, 1, 0),
        )
        .expect("stale");
    observer.seen.lock().clear();
    let expired = gateway
        .expire(AdmissionOrigin::Rpc, now)
        .expect("stale entries expire");
    assert_eq!(expired.len(), 1);
    assert_eq!(
        *observer.seen.lock(),
        vec![(hash(&stale_txid), removed(RemovalReason::Expiry))],
        "expiry publishes exactly one Expiry change"
    );
    assert!(gateway.expire(AdmissionOrigin::Rpc, now).is_none());
}
