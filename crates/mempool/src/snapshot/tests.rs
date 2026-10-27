use super::*;
use crate::{AdmissionOrigin, ChainAdmissionSnapshot, Mempool, MempoolLimits, PrevoutMeta};
use bitcoin_rs_consensus::ValidationEngine;
use bitcoin_rs_primitives::{Amount, LockTime, OutPoint, Script, Sequence, TxIn, TxOut, Witness};
use parking_lot::{Mutex, RwLock};
use std::time::Duration;

type TestResult = Result<(), Box<dyn std::error::Error>>;
const NOW: u64 = 2_000_000;
const INTERRUPTED_STAGE: &str = "mempool-snapshot-interrupted.tmp";

mod restore_model;

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(10)
}

struct Coins {
    outputs: Vec<(OutPoint, TxOut)>,
    height: u32,
    coinbase: bool,
}
impl AdmissionChain for Coins {
    fn snapshot(&self, tx: &Tx) -> Option<ChainAdmissionSnapshot> {
        Some(ChainAdmissionSnapshot {
            prevouts: self.outputs.clone(),
            height: self.height,
            prevout_meta: self
                .outputs
                .iter()
                .map(|(point, _)| {
                    (
                        *point,
                        PrevoutMeta {
                            height: 1,
                            mtp: 0,
                            coinbase: self.coinbase,
                        },
                    )
                })
                .collect(),
            confirmed: self
                .outputs
                .iter()
                .any(|(point, _)| point.txid == tx.txid()),
            ..Default::default()
        })
    }
}

#[derive(Default)]
struct Seen(Mutex<Vec<crate::MutationEnvelope>>);
impl crate::MempoolObserver for Seen {
    fn on_mutation(&self, batch: &crate::MutationEnvelope) {
        self.0.lock().push(batch.clone());
    }
}

fn gateway(limits: MempoolLimits, seen: Option<Arc<Seen>>) -> MempoolGateway {
    MempoolGateway::new(
        Arc::new(RwLock::new(Mempool::new(limits))),
        seen.map(|observer| -> Arc<dyn crate::MempoolObserver> { observer }),
        ValidationEngine::Native,
        None,
    )
}
fn output(value: u64) -> TxOut {
    TxOut {
        value: Amount::from_sat(value),
        script_pubkey: Script::from_bytes([vec![0, 32], Sha256::digest([0x51]).to_vec()].concat()),
    }
}

fn spend(point: OutPoint, value: u64) -> Tx {
    Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: point,
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_stack(vec![vec![0x51]]),
        }],
        outputs: vec![output(value)],
    }
}

fn family() -> (Coins, Tx, Tx) {
    let point = OutPoint::new(Txid(Hash256::from_le_bytes(&[7; 32])), 0);
    let parent = spend(point, 99_000);
    let child = spend(OutPoint::new(parent.txid(), 0), 98_000);
    (
        Coins {
            outputs: vec![(point, output(100_000))],
            height: 100,
            coinbase: true,
        },
        parent,
        child,
    )
}

fn admit(gateway: &MempoolGateway, tx: &Tx, chain: &dyn AdmissionChain) -> TestResult {
    gateway.submit_transaction(
        Arc::new(tx.clone()),
        AdmissionOrigin::Rpc,
        None,
        NOW - 10,
        chain,
    )?;
    Ok(())
}

// MPL-01/POL-02: restoration publishes actual gateway commits once, in parent
// order, and does not adopt saved fees, graph links or membership sequences.
#[test]
fn restores_dependencies_priorities_and_gateway_publication() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (chain, parent, child) = family();
    let source = gateway(MempoolLimits::default(), None);
    admit(&source, &parent, &chain)?;
    admit(&source, &child, &chain)?;
    source.mark_broadcast(parent.wtxid());
    source.prioritise(parent.txid(), 500)?;
    let absent = Txid(Hash256::from_le_bytes(&[8; 32]));
    source.prioritise(absent, i64::MIN)?;
    let before_history = source.read().estimator_history();
    save(
        dir.path(),
        &source,
        Network::Regtest,
        DEFAULT_MAX_BYTES,
        deadline(),
    )?;
    let seen = Arc::new(Seen::default());
    let restored = gateway(MempoolLimits::default(), Some(Arc::clone(&seen)));
    crate::fee_history::save(dir.path(), &before_history);
    crate::fee_history::load(dir.path(), &restored.pool);
    let report = restore(
        dir.path(),
        &restored,
        Network::Regtest,
        &chain,
        NOW,
        DEFAULT_MAX_BYTES,
        deadline(),
    )?
    .ok_or("missing snapshot")?;
    assert_eq!(
        (
            report.candidates,
            report.restored,
            report.skipped,
            report.timed_out
        ),
        (2, 2, 0, false)
    );
    let pool = restored.read();
    let entry = pool.entry_by_txid(&child.txid()).ok_or("missing child")?;
    assert!(entry.unbroadcast);
    assert!(
        !pool
            .entry_by_txid(&parent.txid())
            .ok_or("missing parent")?
            .unbroadcast
    );
    assert_eq!(
        (
            entry.ancestor_fee,
            entry.ancestor_fee_delta,
            entry.time,
            entry.height
        ),
        (2_000, 500, NOW - 10, 100)
    );
    assert_eq!(
        pool.entry_by_txid(&parent.txid())
            .ok_or("missing parent")?
            .fee_delta,
        500
    );
    assert!(
        pool.prioritised_transactions()
            .iter()
            .any(|row| row.txid == absent && row.fee_delta == i64::MIN)
    );
    assert!(
        pool.estimator_history() == before_history,
        "snapshot restore must not rewrite estimator state"
    );
    assert_eq!(
        Sha256::digest(std::fs::read(dir.path().join("fee-estimator-history.dat"))?),
        Sha256::digest(&before_history)
    );
    drop(pool);
    let batches = seen.0.lock();
    assert_eq!(batches.len(), 1);
    assert_eq!(batches[0].result.changes.len(), 2);
    assert_eq!(
        batches[0].result.changes[0].txid,
        Hash256::from(parent.txid())
    );
    assert_eq!(
        batches[0].result.changes[1].txid,
        Hash256::from(child.txid())
    );
    assert!(
        batches
            .iter()
            .all(|batch| batch.origin == AdmissionOrigin::Snapshot)
    );
    assert_eq!(restored.orphan_count(), 0);
    assert_eq!(restored.recent_rejects_count(), 0);
    Ok(())
}

#[test]
fn rechecks_spent_coins_maturity_fee_floor_capacity_and_expiry() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (chain, parent, child) = family();
    let source = gateway(MempoolLimits::default(), None);
    admit(&source, &parent, &chain)?;
    admit(&source, &child, &chain)?;
    save(
        dir.path(),
        &source,
        Network::Regtest,
        DEFAULT_MAX_BYTES,
        deadline(),
    )?;
    for (chain, limits, now) in [
        (
            Coins {
                outputs: vec![],
                height: 100,
                coinbase: false,
            },
            MempoolLimits::default(),
            NOW,
        ),
        (
            Coins {
                outputs: chain.outputs.clone(),
                height: 1,
                coinbase: true,
            },
            MempoolLimits::default(),
            NOW,
        ),
        (
            Coins {
                outputs: chain.outputs.clone(),
                height: 100,
                coinbase: true,
            },
            MempoolLimits {
                min_relay_fee_sat_per_kvb: 1_000_000,
                ..Default::default()
            },
            NOW,
        ),
        (
            Coins {
                outputs: chain.outputs.clone(),
                height: 100,
                coinbase: true,
            },
            MempoolLimits {
                max_total_bytes: 1,
                ..Default::default()
            },
            NOW,
        ),
        (
            Coins {
                outputs: chain.outputs,
                height: 100,
                coinbase: true,
            },
            MempoolLimits::default(),
            NOW + MAX_AGE + 1,
        ),
    ] {
        let pool = gateway(limits, None);
        let report = restore(
            dir.path(),
            &pool,
            Network::Regtest,
            &chain,
            now,
            DEFAULT_MAX_BYTES,
            deadline(),
        )?
        .ok_or("missing snapshot")?;
        assert_eq!(report.restored, 0);
        assert!(pool.read().is_empty());
        assert_eq!(pool.read().unbroadcast_transactions().count(), 0);
        assert_eq!(pool.orphan_count(), 0);
    }
    // A confirmed parent no longer enters, while its child can use the live coin.
    let confirmed = Coins {
        outputs: vec![(OutPoint::new(parent.txid(), 0), parent.outputs[0].clone())],
        height: 101,
        coinbase: false,
    };
    let pool = gateway(MempoolLimits::default(), None);
    let report = restore(
        dir.path(),
        &pool,
        Network::Regtest,
        &confirmed,
        NOW,
        DEFAULT_MAX_BYTES,
        deadline(),
    )?
    .ok_or("missing snapshot")?;
    assert_eq!(report.restored, 1);
    assert!(pool.read().contains_txid(&child.txid()));
    Ok(())
}

#[test]
fn restores_cpfp_and_ephemeral_dust_through_atomic_package_admission() -> TestResult {
    for ephemeral in [false, true] {
        let dir = tempfile::tempdir()?;
        let (chain, mut parent, _) = family();
        parent.version = 3;
        parent.outputs[0].value = Amount::from_sat(100_000);
        if ephemeral {
            parent.outputs.push(output(0));
        }
        let mut child = spend(OutPoint::new(parent.txid(), 0), 98_000);
        child.version = 3;
        if ephemeral {
            let mut input = child.inputs[0].clone();
            input.previous_output.vout = 1;
            child.inputs.push(input);
        }
        let source = gateway(MempoolLimits::default(), None);
        source.submit_local_package(
            vec![child.clone(), parent.clone()],
            LocalOrigin::Rpc,
            None,
            NOW - 10,
            &chain,
        )?;
        let mut snapshot = Snapshot::capture(&source, deadline(), DEFAULT_MAX_BYTES, usize::MAX)?;
        for row in &mut snapshot.transactions {
            row.time = if row.txid == parent.txid() {
                NOW - 100
            } else {
                NOW - 10
            };
            row.unbroadcast = row.txid == child.txid();
        }
        std::fs::write(
            dir.path().join(FILE_NAME),
            snapshot.encode(Network::Regtest, DEFAULT_MAX_BYTES, deadline())?,
        )?;
        let seen = Arc::new(Seen::default());
        let target = gateway(MempoolLimits::default(), Some(Arc::clone(&seen)));
        let report = restore(
            dir.path(),
            &target,
            Network::Regtest,
            &chain,
            NOW,
            DEFAULT_MAX_BYTES,
            deadline(),
        )?
        .ok_or("missing snapshot")?;
        assert_eq!(report.restored, 2);
        assert_eq!(
            target
                .read()
                .unbroadcast_transactions()
                .map(|(txid, _, _)| txid)
                .collect::<Vec<_>>(),
            vec![child.txid()]
        );
        assert_eq!(
            target
                .read()
                .entry_by_txid(&parent.txid())
                .ok_or("parent")?
                .time,
            NOW - 100
        );
        assert_eq!(
            target
                .read()
                .entry_by_txid(&child.txid())
                .ok_or("child")?
                .time,
            NOW - 10
        );
        let batches = seen.0.lock();
        assert_eq!(batches.len(), 1);
        assert_eq!(batches[0].result.changes.len(), 2);
    }
    Ok(())
}

fn reseal(bytes: &mut [u8]) {
    let end = bytes.len() - 32;
    let digest = Sha256::digest(&bytes[..end]);
    bytes[end..].copy_from_slice(&digest);
}

#[test]
fn restores_valid_subset_when_a_descendant_becomes_nonfinal() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (mut chain, mut a, _) = family();
    a.outputs[0].value = Amount::from_sat(100_000);
    let funding_b = OutPoint::new(Txid(Hash256::from_le_bytes(&[9; 32])), 0);
    chain.outputs.push((funding_b, output(100_000)));
    let mut b = spend(funding_b, 50_000);
    b.outputs.push(output(50_000));
    let mut c = spend(OutPoint::new(a.txid(), 0), 150_000);
    let mut second = c.inputs[0].clone();
    second.previous_output = OutPoint::new(b.txid(), 0);
    c.inputs.push(second);
    let fee = a.vsize() + c.vsize();
    c.outputs[0].value = Amount::from_sat(150_000 - fee);
    let d = spend(OutPoint::new(b.txid(), 1), 49_000);
    let source = gateway(MempoolLimits::default(), None);
    source.submit_local_package(
        vec![b.clone(), d.clone()],
        LocalOrigin::Rpc,
        None,
        NOW - 20,
        &chain,
    )?;
    source.submit_local_package(
        vec![a.clone(), c.clone()],
        LocalOrigin::Rpc,
        None,
        NOW - 10,
        &chain,
    )?;
    // The complete family fails finality, but its four valid members can
    // still enter together without consuming either shared fee budget early.
    let mut nonfinal = spend(OutPoint::new(d.txid(), 0), 48_000);
    nonfinal.lock_time = LockTime::from_consensus(150);
    nonfinal.inputs[0].sequence = Sequence::ZERO;
    chain.height = 200;
    admit(&source, &nonfinal, &chain)?;
    chain.height = 100;
    save(
        dir.path(),
        &source,
        Network::Regtest,
        DEFAULT_MAX_BYTES,
        deadline(),
    )?;
    let seen = Arc::new(Seen::default());
    let target = gateway(MempoolLimits::default(), Some(Arc::clone(&seen)));
    let report = restore(
        dir.path(),
        &target,
        Network::Regtest,
        &chain,
        NOW,
        DEFAULT_MAX_BYTES,
        deadline(),
    )?
    .ok_or("snapshot")?;
    assert_eq!((report.restored, report.timed_out), (4, false));
    assert_eq!((report.candidates, report.skipped), (5, 1));
    assert!(!target.read().contains_txid(&nonfinal.txid()));
    for tx in [&a, &b, &c, &d] {
        assert!(target.read().contains_txid(&tx.txid()));
    }
    let batches = seen.0.lock();
    assert_eq!(batches.len(), 1);
    assert_eq!(batches[0].result.changes.len(), 4);
    assert!(
        batches[0]
            .result
            .changes
            .iter()
            .any(|row| row.txid == Hash256::from(d.txid()))
    );
    assert!(
        batches[0]
            .result
            .changes
            .iter()
            .any(|row| row.txid == Hash256::from(c.txid()))
    );
    Ok(())
}

#[test]
fn capacity_limits_save_whole_families_and_all_priorities() -> TestResult {
    let (mut chain, parent, child) = family();
    let source = gateway(MempoolLimits::default(), None);
    admit(&source, &parent, &chain)?;
    admit(&source, &child, &chain)?;
    let point = OutPoint::new(Txid(Hash256::from_le_bytes(&[9; 32])), 0);
    chain.outputs.push((point, output(100_000)));
    let independent = spend(point, 99_000);
    admit(&source, &independent, &chain)?;
    let absent = Txid(Hash256::from_le_bytes(&[10; 32]));
    source.prioritise(absent, 50)?;
    let family_bytes =
        84 + 40 + u64::try_from(parent.total_size())? + u64::try_from(child.total_size())? + 34;
    for (bytes, count) in [(family_bytes, usize::MAX), (DEFAULT_MAX_BYTES, 2)] {
        let snapshot = Snapshot::capture(&source, deadline(), bytes, count)?;
        assert_eq!(snapshot.transactions.len(), 2);
        assert!(
            snapshot
                .transactions
                .iter()
                .any(|row| row.txid == parent.txid())
        );
        assert!(
            snapshot
                .transactions
                .iter()
                .any(|row| row.txid == child.txid())
        );
        assert_eq!(snapshot.deltas, vec![(absent, 50)]);
        let dir = tempfile::tempdir()?;
        let encoded = snapshot.encode(Network::Regtest, DEFAULT_MAX_BYTES, deadline())?;
        assert!(u64::try_from(encoded.len())? <= bytes);
        std::fs::write(dir.path().join(FILE_NAME), encoded)?;
    }
    assert!(
        Snapshot::capture(&source, deadline(), family_bytes - 1, usize::MAX)?
            .transactions
            .is_empty()
    );
    assert!(
        Snapshot::capture(&source, deadline(), DEFAULT_MAX_BYTES, 1)?
            .transactions
            .is_empty()
    );
    // The same public save/read path honors a raised byte budget, retaining
    // every family rather than a small-budget prefix.
    let dir = tempfile::tempdir()?;
    save(
        dir.path(),
        &source,
        Network::Regtest,
        family_bytes,
        deadline(),
    )?;
    let target = gateway(MempoolLimits::default(), None);
    assert_eq!(
        restore(
            dir.path(),
            &target,
            Network::Regtest,
            &chain,
            NOW,
            family_bytes,
            deadline()
        )?
        .ok_or("snapshot")?
        .candidates,
        2
    );
    let full_bytes = family_bytes + u64::try_from(independent.total_size())? + 17;
    save(
        dir.path(),
        &source,
        Network::Regtest,
        full_bytes,
        deadline(),
    )?;
    let target = gateway(MempoolLimits::default(), None);
    let report = restore(
        dir.path(),
        &target,
        Network::Regtest,
        &chain,
        NOW,
        full_bytes,
        deadline(),
    )?
    .ok_or("snapshot")?;
    assert_eq!((report.candidates, report.restored), (3, 3));
    Ok(())
}

#[test]
fn byte_budget_allows_more_than_one_hundred_thousand_records() -> TestResult {
    let (_, parent, _) = family();
    let transactions = (0..100_001)
        .map(|index| {
            let mut tx = parent.clone();
            tx.inputs[0].previous_output.vout = index;
            let txid = tx.txid();
            SavedTransaction {
                tx: Arc::new(tx),
                txid,
                time: NOW,
                unbroadcast: false,
                sigop_cost: 0,
            }
        })
        .collect();
    let snapshot = Snapshot {
        transactions,
        deltas: Vec::new(),
    };
    let encoded = snapshot.encode(Network::Regtest, DEFAULT_MAX_BYTES, deadline())?;
    assert_eq!(
        Snapshot::decode(&encoded, Network::Regtest, DEFAULT_MAX_BYTES, deadline())?
            .transactions
            .len(),
        100_001
    );
    Ok(())
}

#[test]
fn restore_rejects_preexisting_absent_transaction_priorities() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (chain, parent, _) = family();
    let source = gateway(MempoolLimits::default(), None);
    source.prioritise(parent.txid(), 1)?;
    save(
        dir.path(),
        &source,
        Network::Regtest,
        DEFAULT_MAX_BYTES,
        deadline(),
    )?;
    let target = gateway(MempoolLimits::default(), None);
    target.prioritise(parent.txid(), i64::MAX)?;
    assert!(
        restore(
            dir.path(),
            &target,
            Network::Regtest,
            &chain,
            NOW,
            DEFAULT_MAX_BYTES,
            deadline()
        )
        .is_err()
    );
    assert_eq!(
        target.read().prioritised_transactions()[0].fee_delta,
        i64::MAX
    );
    Ok(())
}

#[test]
fn rejects_bad_artifacts_without_mutation_or_overwriting_operator_data() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (chain, parent, _) = family();
    let source = gateway(MempoolLimits::default(), None);
    admit(&source, &parent, &chain)?;
    let valid = Snapshot::capture(&source, deadline(), DEFAULT_MAX_BYTES, usize::MAX)?.encode(
        Network::Regtest,
        DEFAULT_MAX_BYTES,
        deadline(),
    )?;
    let mut version = valid.clone();
    version[8..12].copy_from_slice(&u32::MAX.to_le_bytes());
    reseal(&mut version);
    let mut network = valid.clone();
    network[12] ^= 1;
    reseal(&mut network);
    let mut count = valid.clone();
    count[44..48].copy_from_slice(&u32::MAX.to_le_bytes());
    reseal(&mut count);
    let mut length = valid.clone();
    length[61..65].copy_from_slice(&u32::MAX.to_le_bytes());
    reseal(&mut length);
    let mut checksum = valid.clone();
    checksum[65] ^= 1;
    let mut trailing = valid.clone();
    trailing.insert(trailing.len() - 32, 0);
    reseal(&mut trailing);
    for bytes in [
        version,
        network,
        count,
        length,
        checksum,
        trailing,
        valid[..valid.len() - 1].to_vec(),
    ] {
        std::fs::write(dir.path().join(FILE_NAME), &bytes)?;
        let pool = gateway(MempoolLimits::default(), None);
        assert!(
            restore(
                dir.path(),
                &pool,
                Network::Regtest,
                &chain,
                NOW,
                DEFAULT_MAX_BYTES,
                deadline()
            )
            .is_err()
        );
        assert!(pool.read().is_empty());
        save(
            dir.path(),
            &source,
            Network::Regtest,
            DEFAULT_MAX_BYTES,
            deadline(),
        )?;
        assert_eq!(std::fs::read(dir.path().join(FILE_NAME))?, valid);
        assert!(
            std::fs::read_dir(dir.path())?
                .filter_map(Result::ok)
                .any(|entry| {
                    entry
                        .file_name()
                        .to_string_lossy()
                        .starts_with("mempool-snapshot-rejected-")
                        && std::fs::read(entry.path().join(FILE_NAME))
                            .is_ok_and(|saved| saved == bytes)
                })
        );
    }
    Ok(())
}

#[test]
fn interrupted_or_failed_save_preserves_the_complete_live_snapshot() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (chain, parent, _) = family();
    let source = gateway(MempoolLimits::default(), None);
    admit(&source, &parent, &chain)?;
    save(
        dir.path(),
        &source,
        Network::Regtest,
        DEFAULT_MAX_BYTES,
        deadline(),
    )?;
    let before = std::fs::read(dir.path().join(FILE_NAME))?;
    let guard = source.pool.write();
    assert!(
        save(
            dir.path(),
            &source,
            Network::Regtest,
            DEFAULT_MAX_BYTES,
            Instant::now() + Duration::from_millis(2)
        )
        .is_err()
    );
    drop(guard);
    assert_eq!(std::fs::read(dir.path().join(FILE_NAME))?, before);
    std::fs::write(dir.path().join(INTERRUPTED_STAGE), b"interrupted write")?;
    let target = gateway(MempoolLimits::default(), None);
    assert_eq!(
        restore(
            dir.path(),
            &target,
            Network::Regtest,
            &chain,
            NOW,
            DEFAULT_MAX_BYTES,
            deadline()
        )?
        .ok_or("missing")?
        .restored,
        1
    );
    // Unknown staging entries belong to the operator; only the writer's own
    // unique temporary file is ever cleaned up.
    std::fs::remove_file(dir.path().join(INTERRUPTED_STAGE))?;
    std::fs::create_dir(dir.path().join(INTERRUPTED_STAGE))?;
    let marker = dir.path().join(INTERRUPTED_STAGE).join("operator-data");
    std::fs::write(&marker, b"preserve")?;
    save(
        dir.path(),
        &source,
        Network::Regtest,
        DEFAULT_MAX_BYTES,
        deadline(),
    )?;
    assert_eq!(std::fs::read(dir.path().join(FILE_NAME))?, before);
    assert_eq!(std::fs::read(marker)?, b"preserve");
    assert!(
        save(
            dir.path(),
            &source,
            Network::Regtest,
            DEFAULT_MAX_BYTES,
            Instant::now()
        )
        .is_err()
    );
    assert_eq!(std::fs::read(dir.path().join(FILE_NAME))?, before);
    Ok(())
}

#[cfg(windows)]
#[test]
fn failed_atomic_replacement_keeps_the_previous_snapshot() -> TestResult {
    use std::os::windows::fs::OpenOptionsExt as _;
    let dir = tempfile::tempdir()?;
    let (chain, parent, child) = family();
    let source = gateway(MempoolLimits::default(), None);
    admit(&source, &parent, &chain)?;
    save(
        dir.path(),
        &source,
        Network::Regtest,
        DEFAULT_MAX_BYTES,
        deadline(),
    )?;
    let path = dir.path().join(FILE_NAME);
    let before = std::fs::read(&path)?;
    // Permit reads but deny deletion/rename while the staging file is written.
    let guard = std::fs::OpenOptions::new()
        .read(true)
        .share_mode(1)
        .open(&path)?;
    admit(&source, &child, &chain)?;
    assert!(
        save(
            dir.path(),
            &source,
            Network::Regtest,
            DEFAULT_MAX_BYTES,
            deadline()
        )
        .is_err()
    );
    drop(guard);
    assert_eq!(std::fs::read(&path)?, before);
    assert_eq!(std::fs::read_dir(dir.path())?.count(), 1);
    Ok(())
}

#[test]
fn missing_oversized_and_non_file_snapshots_fail_safely() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (chain, _, _) = family();
    let pool = gateway(MempoolLimits::default(), None);
    assert!(
        restore(
            dir.path(),
            &pool,
            Network::Regtest,
            &chain,
            NOW,
            DEFAULT_MAX_BYTES,
            deadline()
        )?
        .is_none()
    );
    let path = dir.path().join(FILE_NAME);
    let file = std::fs::File::create(&path)?;
    file.set_len(DEFAULT_MAX_BYTES + 1)?;
    drop(file);
    assert!(
        restore(
            dir.path(),
            &pool,
            Network::Regtest,
            &chain,
            NOW,
            DEFAULT_MAX_BYTES,
            deadline()
        )
        .is_err()
    );
    save(
        dir.path(),
        &pool,
        Network::Regtest,
        DEFAULT_MAX_BYTES,
        deadline(),
    )?;
    let rejected = std::fs::read_dir(dir.path())?
        .filter_map(Result::ok)
        .find(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .ok_or("quarantine")?;
    assert_eq!(
        std::fs::metadata(rejected.path().join(FILE_NAME))?.len(),
        DEFAULT_MAX_BYTES + 1
    );
    std::fs::remove_file(&path)?;
    std::fs::create_dir(&path)?;
    std::fs::write(path.join("operator-data"), b"preserve")?;
    assert!(
        restore(
            dir.path(),
            &pool,
            Network::Regtest,
            &chain,
            NOW,
            DEFAULT_MAX_BYTES,
            deadline()
        )
        .is_err()
    );
    assert!(
        save(
            dir.path(),
            &pool,
            Network::Regtest,
            DEFAULT_MAX_BYTES,
            deadline()
        )
        .is_err()
    );
    assert_eq!(std::fs::read(path.join("operator-data"))?, b"preserve");
    Ok(())
}

#[test]
fn revalidates_witness_standardness_finality_and_only_saves_live_rbf_members() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (chain, parent, child) = family();
    let source = gateway(MempoolLimits::default(), None);
    admit(&source, &parent, &chain)?;
    admit(&source, &child, &chain)?;
    let mut replacement = parent.clone();
    replacement.outputs[0].value = Amount::from_sat(90_000);
    admit(&source, &replacement, &chain)?;
    save(
        dir.path(),
        &source,
        Network::Regtest,
        DEFAULT_MAX_BYTES,
        deadline(),
    )?;
    let target = gateway(MempoolLimits::default(), None);
    let report = restore(
        dir.path(),
        &target,
        Network::Regtest,
        &chain,
        NOW,
        DEFAULT_MAX_BYTES,
        deadline(),
    )?
    .ok_or("missing")?;
    assert_eq!((report.candidates, report.restored), (1, 1));
    assert!(target.read().contains_txid(&replacement.txid()));
    assert!(!target.read().contains_txid(&parent.txid()));
    assert!(!target.read().contains_txid(&child.txid()));

    let mut invalid_witness = parent.clone();
    invalid_witness.inputs[0].witness = Witness::from_stack(vec![vec![0x00]]);
    let mut nonstandard = parent.clone();
    nonstandard.outputs[0].script_pubkey = Script::from_bytes(vec![0x51]);
    let mut nonfinal = parent;
    nonfinal.lock_time = LockTime::from_consensus(200);
    nonfinal.inputs[0].sequence = Sequence::from_consensus(0xffff_fffe);
    for tx in [invalid_witness, nonstandard, nonfinal] {
        let snapshot = Snapshot {
            transactions: vec![SavedTransaction {
                txid: tx.txid(),
                tx: Arc::new(tx),
                time: NOW - 10,
                unbroadcast: false,
                sigop_cost: 0,
            }],
            deltas: vec![],
        };
        std::fs::write(
            dir.path().join(FILE_NAME),
            snapshot.encode(Network::Regtest, DEFAULT_MAX_BYTES, deadline())?,
        )?;
        let target = gateway(MempoolLimits::default(), None);
        let report = restore(
            dir.path(),
            &target,
            Network::Regtest,
            &chain,
            NOW,
            DEFAULT_MAX_BYTES,
            deadline(),
        )?
        .ok_or("missing")?;
        assert_eq!((report.restored, report.skipped), (0, 1));
        assert_eq!(target.read().sequence_number(), 0);
    }
    Ok(())
}

#[test]
fn concurrent_admission_and_save_capture_a_coherent_candidate_set() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (chain, parent, child) = family();
    let source = Arc::new(gateway(MempoolLimits::default(), None));
    admit(&source, &parent, &chain)?;
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let writer = {
        let source = Arc::clone(&source);
        let barrier = Arc::clone(&barrier);
        let data_dir = dir.path().to_path_buf();
        std::thread::spawn(move || {
            barrier.wait();
            source
                .submit_transaction(
                    Arc::new(child),
                    AdmissionOrigin::Rpc,
                    None,
                    NOW - 10,
                    &chain,
                )
                .map_err(io::Error::other)?;
            save(
                &data_dir,
                &source,
                Network::Regtest,
                DEFAULT_MAX_BYTES,
                deadline(),
            )
        })
    };
    barrier.wait();
    let first = save(
        dir.path(),
        &source,
        Network::Regtest,
        DEFAULT_MAX_BYTES,
        deadline(),
    );
    let second = writer.join().map_err(|_| "admission thread panicked")?;
    assert!(first.is_ok() || second.is_ok());
    // Windows can refuse one overlapping replacement while the other writer's
    // file handle is closing. Refusal must still leave a complete live file.
    for result in [first, second] {
        #[cfg(windows)]
        if let Err(error) = result {
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        }
        #[cfg(not(windows))]
        result?;
    }
    let (chain, _, _) = family();
    let target = gateway(MempoolLimits::default(), None);
    let report = restore(
        dir.path(),
        &target,
        Network::Regtest,
        &chain,
        NOW,
        DEFAULT_MAX_BYTES,
        deadline(),
    )?
    .ok_or("missing")?;
    assert!((1..=2).contains(&report.candidates));
    assert_eq!(report.restored, report.candidates);
    assert!(target.read().contains_txid(&parent.txid()));
    Ok(())
}

#[test]
fn restores_multi_generational_cpfp_package() -> TestResult {
    let dir = tempfile::tempdir()?;
    let point = OutPoint::new(Txid(Hash256::from_le_bytes(&[12; 32])), 0);
    let grandparent = spend(point, 100_000);
    let parent = spend(OutPoint::new(grandparent.txid(), 0), 100_000);
    let child = spend(OutPoint::new(parent.txid(), 0), 90_000);
    let chain = Coins {
        outputs: vec![(point, output(100_000))],
        height: 100,
        coinbase: true,
    };
    let snapshot = Snapshot {
        transactions: vec![
            SavedTransaction {
                tx: Arc::new(grandparent.clone()),
                txid: grandparent.txid(),
                time: NOW - 30,
                unbroadcast: false,
                sigop_cost: 0,
            },
            SavedTransaction {
                tx: Arc::new(parent.clone()),
                txid: parent.txid(),
                time: NOW - 20,
                unbroadcast: false,
                sigop_cost: 0,
            },
            SavedTransaction {
                tx: Arc::new(child.clone()),
                txid: child.txid(),
                time: NOW - 10,
                unbroadcast: true,
                sigop_cost: 0,
            },
        ],
        deltas: vec![],
    };
    std::fs::write(
        dir.path().join(FILE_NAME),
        snapshot.encode(Network::Regtest, DEFAULT_MAX_BYTES, deadline())?,
    )?;
    let target = gateway(MempoolLimits::default(), None);
    let report = restore(
        dir.path(),
        &target,
        Network::Regtest,
        &chain,
        NOW,
        DEFAULT_MAX_BYTES,
        deadline(),
    )?
    .ok_or("missing snapshot")?;
    assert_eq!(
        (report.candidates, report.restored, report.skipped),
        (3, 3, 0)
    );
    assert!(target.read().contains_txid(&grandparent.txid()));
    assert!(target.read().contains_txid(&parent.txid()));
    assert!(target.read().contains_txid(&child.txid()));
    assert_eq!(
        target
            .read()
            .unbroadcast_transactions()
            .map(|(txid, _, _)| txid)
            .collect::<Vec<_>>(),
        vec![child.txid()]
    );
    Ok(())
}

#[test]
fn snapshot_decode_rejects_excessive_sigop_cost() -> TestResult {
    let (_, parent, _) = family();
    let snapshot = Snapshot {
        transactions: vec![SavedTransaction {
            tx: Arc::new(parent.clone()),
            txid: parent.txid(),
            time: NOW,
            unbroadcast: false,
            sigop_cost: crate::standardness::MAX_STANDARD_TX_SIGOPS_COST + 1,
        }],
        deltas: Vec::new(),
    };
    let encoded = snapshot.encode(Network::Regtest, DEFAULT_MAX_BYTES, deadline())?;
    assert!(Snapshot::decode(&encoded, Network::Regtest, DEFAULT_MAX_BYTES, deadline()).is_err());
    Ok(())
}

#[test]
fn restores_cpfp_after_saved_ancestors_confirm_and_are_fully_spent() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (original_chain, grandparent, parent) = family();
    let low_fee = spend(OutPoint::new(parent.txid(), 0), 98_000);
    let paying_child = spend(OutPoint::new(low_fee.txid(), 0), 90_000);
    let source = gateway(MempoolLimits::default(), None);
    admit(&source, &grandparent, &original_chain)?;
    admit(&source, &parent, &original_chain)?;
    source.submit_local_package(
        vec![low_fee.clone(), paying_child.clone()],
        LocalOrigin::Rpc,
        None,
        NOW - 10,
        &original_chain,
    )?;
    save(
        dir.path(),
        &source,
        Network::Regtest,
        DEFAULT_MAX_BYTES,
        deadline(),
    )?;

    // G and P confirmed while offline. All G outputs are spent; only P's
    // output funding A remains in Chainstate. A needs C to pay its relay fee.
    let changed_chain = Coins {
        outputs: vec![(OutPoint::new(parent.txid(), 0), parent.outputs[0].clone())],
        height: 102,
        coinbase: false,
    };
    let control = gateway(MempoolLimits::default(), None);
    control.submit_local_package(
        vec![low_fee.clone(), paying_child.clone()],
        LocalOrigin::Rpc,
        None,
        NOW,
        &changed_chain,
    )?;
    assert_eq!(control.read().len(), 2, "independent gateway control");
    let target = gateway(MempoolLimits::default(), None);
    let report = restore(
        dir.path(),
        &target,
        Network::Regtest,
        &changed_chain,
        NOW,
        DEFAULT_MAX_BYTES,
        deadline(),
    )?
    .ok_or("missing snapshot")?;
    assert_eq!(
        (report.candidates, report.restored, report.skipped),
        (4, 2, 2)
    );
    assert!(target.read().contains_txid(&low_fee.txid()));
    assert!(target.read().contains_txid(&paying_child.txid()));
    assert!(!target.read().contains_txid(&grandparent.txid()));
    assert!(!target.read().contains_txid(&parent.txid()));
    Ok(())
}

#[test]
fn restores_parent_paying_for_a_low_fee_child_before_standalone_admission() -> TestResult {
    for with_sibling in [false, true] {
        let dir = tempfile::tempdir()?;
        let (chain, mut parent, _) = family();
        parent.outputs = vec![output(49_000), output(49_000)];
        let child = spend(OutPoint::new(parent.txid(), 0), 49_000);
        let sibling = spend(OutPoint::new(parent.txid(), 1), 48_000);
        let source = gateway(MempoolLimits::default(), None);
        source.submit_local_package(
            vec![parent.clone(), child.clone()],
            LocalOrigin::Rpc,
            None,
            NOW - 20,
            &chain,
        )?;
        if with_sibling {
            admit(&source, &sibling, &chain)?;
        }
        let expected = if with_sibling { 3 } else { 2 };
        assert_eq!(source.read().len(), expected, "normal gateway control");
        save(
            dir.path(),
            &source,
            Network::Regtest,
            DEFAULT_MAX_BYTES,
            deadline(),
        )?;
        let target = gateway(MempoolLimits::default(), None);
        let report = restore(
            dir.path(),
            &target,
            Network::Regtest,
            &chain,
            NOW,
            DEFAULT_MAX_BYTES,
            deadline(),
        )?
        .ok_or("missing snapshot")?;
        assert!(!report.timed_out);
        assert_eq!(
            report.restored, expected,
            "a resident parent's fee cannot be reused later"
        );
        assert!(target.read().contains_txid(&parent.txid()));
        assert!(target.read().contains_txid(&child.txid()));
    }
    Ok(())
}

#[test]
fn restore_timeout_preserves_all_priorities_through_the_next_save() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (chain, parent, _) = family();
    let source = gateway(MempoolLimits::default(), None);
    admit(&source, &parent, &chain)?;
    source.prioritise(parent.txid(), 500)?;
    source.prioritise(Txid(Hash256::from_le_bytes(&[8; 32])), i64::MIN)?;
    source.prioritise(Txid(Hash256::from_le_bytes(&[9; 32])), i64::MAX)?;
    let snapshot = Snapshot::capture(&source, deadline(), DEFAULT_MAX_BYTES, usize::MAX)?;
    let bytes = snapshot.encode(Network::Regtest, DEFAULT_MAX_BYTES, deadline())?;
    let decoded = Snapshot::decode(&bytes, Network::Regtest, DEFAULT_MAX_BYTES, deadline())?;
    let target = gateway(MempoolLimits::default(), None);
    // Deterministically expire the admission budget after successful decoding.
    let report = restore_candidates(&decoded, &target, &chain, NOW, Instant::now())?;
    assert!(report.timed_out);
    assert_eq!(report.restored, 0);
    let expected: std::collections::BTreeMap<_, _> = source.read().fee_deltas().collect();
    assert_eq!(
        target
            .read()
            .fee_deltas()
            .collect::<std::collections::BTreeMap<_, _>>(),
        expected
    );
    save(
        dir.path(),
        &target,
        Network::Regtest,
        DEFAULT_MAX_BYTES,
        deadline(),
    )?;
    let next = gateway(MempoolLimits::default(), None);
    restore(
        dir.path(),
        &next,
        Network::Regtest,
        &chain,
        NOW,
        DEFAULT_MAX_BYTES,
        deadline(),
    )?;
    assert_eq!(
        next.read()
            .fee_deltas()
            .collect::<std::collections::BTreeMap<_, _>>(),
        expected
    );
    assert!(next.read().is_empty());
    Ok(())
}

struct AncestorReads {
    calls: std::sync::atomic::AtomicUsize,
    expire_at: Option<Instant>,
}

impl AdmissionChain for AncestorReads {
    fn snapshot(&self, _: &Tx) -> Option<ChainAdmissionSnapshot> {
        self.calls
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if let Some(deadline) = self.expire_at {
            // Simulate a chain read that consumes the cooperative budget.
            // Its in-progress call cannot be preempted, but no next read is allowed.
            while Instant::now() < deadline {
                std::thread::sleep(deadline.saturating_duration_since(Instant::now()));
            }
        }
        Some(ChainAdmissionSnapshot::default())
    }
}

fn saved_ancestor_chain(count: usize) -> Vec<SavedTransaction> {
    let mut point = OutPoint::new(Txid(Hash256::from_le_bytes(&[31; 32])), 0);
    let mut rows = Vec::new();
    for _ in 0..count {
        let tx = Arc::new(spend(point, 100_000));
        point = OutPoint::new(tx.txid(), 0);
        rows.push(SavedTransaction {
            txid: tx.txid(),
            tx,
            time: NOW,
            unbroadcast: false,
            sigop_cost: 0,
        });
    }
    rows
}

#[test]
fn family_collection_stops_at_the_package_count_boundary() -> TestResult {
    let limit = crate::standardness::MAX_PACKAGE_COUNT;
    for count in [limit, limit + 1, limit * 4] {
        let rows = saved_ancestor_chain(count);
        let mut graph = RestoreGraph {
            neighbors: HashMap::new(),
            confirmed: hashbrown::HashSet::new(),
        };
        for pair in rows.windows(2) {
            graph
                .neighbors
                .entry(pair[0].txid)
                .or_default()
                .push(pair[1].txid);
            graph
                .neighbors
                .entry(pair[1].txid)
                .or_default()
                .push(pair[0].txid);
        }
        let family = collect_saved_family(rows[0].txid, &graph, deadline())?;
        assert_eq!(family.len(), count.min(limit + 1));
        assert_eq!(family.len() <= limit, count == limit);
    }
    Ok(())
}

#[test]
fn graph_build_stops_when_a_chain_read_exhausts_the_deadline() -> TestResult {
    let snapshot = Snapshot {
        transactions: saved_ancestor_chain(100),
        deltas: Vec::new(),
    };
    let positions = snapshot
        .transactions
        .iter()
        .map(|row| (row.txid, row))
        .collect();
    let expires = Instant::now() + Duration::from_secs(1);
    let chain = AncestorReads {
        calls: std::sync::atomic::AtomicUsize::new(0),
        expire_at: Some(expires),
    };
    let error = build_restore_graph(&snapshot, &positions, &chain, expires)
        .err()
        .ok_or("deadline must stop graph construction")?;
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert_eq!(chain.calls.load(std::sync::atomic::Ordering::Relaxed), 1);
    Ok(())
}
