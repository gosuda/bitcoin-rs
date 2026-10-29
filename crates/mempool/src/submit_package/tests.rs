use super::*;
use crate::{ChainAdmissionSnapshot, Mempool, MempoolLimits, MempoolObserver, MutationEnvelope};
use bitcoin::hashes::{Hash as _, sha256};
use bitcoin_rs_consensus::ValidationEngine;
use bitcoin_rs_primitives::{
    Amount, Hash256, LockTime, OutPoint, PeerEndpoint, Script, Sequence, TxIn, TxOut, Witness,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[derive(Default)]
struct Seen(parking_lot::Mutex<Vec<MutationEnvelope>>);

impl MempoolObserver for Seen {
    fn on_mutation(&self, envelope: &MutationEnvelope) {
        self.0.lock().push(envelope.clone());
    }
}

struct Coins(Vec<(OutPoint, TxOut)>);

impl AdmissionChain for Coins {
    fn snapshot(&self, _: &Tx) -> Option<ChainAdmissionSnapshot> {
        Some(ChainAdmissionSnapshot {
            prevouts: self.0.clone(),
            height: 200,
            csv_active: true,
            ..ChainAdmissionSnapshot::default()
        })
    }
}

fn source() -> PeerToken {
    let endpoint = PeerEndpoint::Ip(core::net::SocketAddr::from(([127, 0, 0, 1], 8333)));
    PeerToken {
        endpoint: Some(endpoint),
        addr: Some(endpoint),
        connection_id: 7,
    }
}

fn coin(tag: u32) -> OutPoint {
    let mut bytes = [0_u8; 32];
    bytes[..4].copy_from_slice(&tag.to_le_bytes());
    OutPoint::new(Txid(Hash256::from_le_bytes(&bytes)), 0)
}

fn funded(tags: &[u32]) -> Coins {
    Coins(
        tags.iter()
            .map(|tag| {
                (
                    coin(*tag),
                    TxOut {
                        value: Amount::from_sat(100_000),
                        script_pubkey: Script::from_bytes(vec![0x51]),
                    },
                )
            })
            .collect(),
    )
}

fn output(value: u64) -> TxOut {
    let hash = sha256::Hash::hash(&[0x51]);
    TxOut {
        value: Amount::from_sat(value),
        script_pubkey: Script::from_bytes([vec![0, 32], hash.to_byte_array().to_vec()].concat()),
    }
}

fn spend_coins(inputs: &[OutPoint], outputs: &[u64]) -> Tx {
    spend_with(inputs, outputs, &Witness::new())
}

fn spend_outputs(inputs: &[OutPoint], outputs: &[u64]) -> Tx {
    spend_with(inputs, outputs, &Witness::from_stack(vec![vec![0x51]]))
}

fn spend_with(inputs: &[OutPoint], outputs: &[u64], witness: &Witness) -> Tx {
    Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: inputs
            .iter()
            .map(|outpoint| TxIn {
                previous_output: *outpoint,
                sequence: Sequence::MAX,
                script_sig: Script::new(),
                witness: witness.clone(),
            })
            .collect(),
        outputs: outputs.iter().copied().map(output).collect(),
    }
}

fn gateway(min_relay: u64, observer: Option<Arc<dyn MempoolObserver>>) -> MempoolGateway {
    MempoolGateway::new(
        Arc::new(parking_lot::RwLock::new(Mempool::new(MempoolLimits {
            min_relay_fee_sat_per_kvb: min_relay,
            ..MempoolLimits::default()
        }))),
        observer.map(|observer| (observer, crate::BodyInterest::Metadata)),
        ValidationEngine::Native,
        None,
    )
}

fn txids(result: &MutationResult) -> Vec<Hash256> {
    result.changes.iter().map(|change| change.txid).collect()
}

fn ids(txs: &[Tx]) -> Vec<Hash256> {
    txs.iter().map(|tx| Hash256::from(tx.txid())).collect()
}

fn chain_of(length: usize) -> Vec<Tx> {
    let mut txs: Vec<Tx> = Vec::with_capacity(length);
    let mut value = 100_000_u64;
    for index in 0..length {
        let input = txs
            .last()
            .map_or_else(|| coin(1), |previous| OutPoint::new(previous.txid(), 0));
        value -= 1_000;
        txs.push(if index > 0 {
            spend_outputs(&[input], &[value])
        } else {
            spend_coins(&[input], &[value])
        });
    }
    txs
}

#[test]
fn peer_ancestor_package_commits_an_unpaid_chain_under_its_paying_subject() -> TestResult {
    let seen = Arc::new(Seen::default());
    let gateway = gateway(1_000, Some(seen.clone()));
    let chain = funded(&[1]);
    let grandparent = spend_coins(&[coin(1)], &[100_000]);
    let parent = spend_outputs(&[OutPoint::new(grandparent.txid(), 0)], &[100_000]);
    let subject = spend_outputs(&[OutPoint::new(parent.txid(), 0)], &[96_000]);
    let now = unix_time_secs();

    assert_eq!(
        gateway.submit_peer_package(
            &[grandparent.clone(), parent.clone()],
            source(),
            now,
            &chain
        ),
        Err(SubmitError::Policy(
            AcceptanceRejectReason::MinRelayFeeNotMet
        ))
    );
    assert!(gateway.read().is_empty());
    assert_eq!(gateway.orphan_count(), 0);
    assert_eq!(gateway.recent_rejects_count(), 0);
    assert!(seen.0.lock().is_empty());

    let package = vec![grandparent.clone(), parent.clone(), subject.clone()];
    let result = gateway.submit_peer_package(&package, source(), now, &chain)?;
    assert_eq!(txids(&result), ids(&package));
    assert_eq!(gateway.read().len(), 3);
    assert_eq!(
        seen.0.lock().as_slice(),
        &[MutationEnvelope {
            origin: AdmissionOrigin::Peer(source()),
            result,
            accepted_transactions: Vec::new(),
        }]
    );
    assert_eq!(
        gateway.ancestor_package_wtxids(subject.wtxid()),
        Some(vec![grandparent.wtxid(), parent.wtxid(), subject.wtxid()])
    );
    assert_eq!(
        gateway.ancestor_package_wtxids(grandparent.wtxid()),
        Some(vec![grandparent.wtxid()])
    );
    let outsider = spend_coins(&[coin(2)], &[100_000]);
    assert_eq!(gateway.ancestor_package_wtxids(outsider.wtxid()), None);

    let requested = [subject.wtxid(), grandparent.wtxid(), subject.wtxid()];
    let bodies = gateway
        .resident_package(&requested)
        .ok_or("every member is resident")?;
    assert_eq!(
        bodies.iter().map(|tx| tx.wtxid()).collect::<Vec<_>>(),
        requested
    );
    assert!(
        gateway
            .resident_package(&[grandparent.wtxid(), outsider.wtxid()])
            .is_none()
    );
    assert!(
        gateway
            .resident_package(&[])
            .is_some_and(|bodies| bodies.is_empty())
    );

    assert!(
        gateway
            .submit_peer_package(&package, source(), now, &chain)?
            .is_empty()
    );
    assert_eq!(seen.0.lock().len(), 1);
    Ok(())
}

#[test]
fn peer_package_keeps_the_senders_order_where_the_local_path_sorts() -> TestResult {
    let chain = funded(&[1, 2]);
    let mut parents = [
        spend_coins(&[coin(1)], &[100_000]),
        spend_coins(&[coin(2)], &[100_000]),
    ];
    parents.sort_by_key(Tx::txid);
    let subject = spend_outputs(
        &[
            OutPoint::new(parents[0].txid(), 0),
            OutPoint::new(parents[1].txid(), 0),
        ],
        &[196_000],
    );
    let descending = vec![parents[1].clone(), parents[0].clone(), subject.clone()];
    let ascending = vec![parents[0].clone(), parents[1].clone(), subject];
    let now = unix_time_secs();

    let peer = gateway(1_000, None);
    let result = peer.submit_peer_package(&descending, source(), now, &chain)?;
    assert_eq!(txids(&result), ids(&descending));

    let local = gateway(1_000, None);
    let result = local.submit_local_package(descending, LocalOrigin::Rpc, None, now, &chain)?;
    assert_eq!(txids(&result), ids(&ascending));
    Ok(())
}

#[test]
fn peer_package_admits_ancestors_the_sender_did_not_sort() -> TestResult {
    let chain = funded(&[1]);
    let grandparent = spend_coins(&[coin(1)], &[100_000]);
    let parent = spend_outputs(&[OutPoint::new(grandparent.txid(), 0)], &[98_000]);
    let subject = spend_outputs(&[OutPoint::new(parent.txid(), 0)], &[96_000]);
    let unsorted = vec![parent.clone(), grandparent.clone(), subject.clone()];

    let peer = gateway(1_000, None);
    let result = peer.submit_peer_package(&unsorted, source(), unix_time_secs(), &chain)?;
    assert_eq!(txids(&result), ids(&[grandparent, parent, subject]));
    Ok(())
}

#[test]
fn peer_package_structure_failures_touch_nothing() -> TestResult {
    let seen = Arc::new(Seen::default());
    let gateway = gateway(0, Some(seen.clone()));
    let chain = funded(&[1, 2]);
    let parent = spend_coins(&[coin(1)], &[100_000]);
    let child = spend_outputs(&[OutPoint::new(parent.txid(), 0)], &[96_000]);
    let unrelated = spend_coins(&[coin(2)], &[100_000]);
    let oversized: Vec<_> = (10..=10 + u32::try_from(crate::standardness::MAX_PACKAGE_COUNT)?)
        .map(|tag| spend_coins(&[coin(tag)], &[100_000]))
        .collect();
    assert_eq!(oversized.len(), crate::standardness::MAX_PACKAGE_COUNT + 1);
    let cases = [
        (vec![], AcceptanceRejectReason::PackageCount),
        (oversized, AcceptanceRejectReason::PackageCount),
        (
            vec![child.clone(), parent.clone()],
            AcceptanceRejectReason::PackageOrder,
        ),
        (
            vec![parent.clone(), parent.clone()],
            AcceptanceRejectReason::PackageDuplicates,
        ),
        (
            vec![parent.clone(), unrelated.clone()],
            AcceptanceRejectReason::PackageTopology,
        ),
        (
            vec![parent, child, unrelated],
            AcceptanceRejectReason::PackageTopology,
        ),
    ];
    let sequence = gateway.read().sequence_number();
    for (txs, reason) in cases {
        assert_eq!(
            gateway.submit_peer_package(&txs, source(), 1, &chain),
            Err(SubmitError::Policy(reason))
        );
    }
    assert!(gateway.read().is_empty());
    assert_eq!(gateway.read().sequence_number(), sequence);
    assert!(seen.0.lock().is_empty());
    assert_eq!(gateway.orphan_count(), 0);
    assert_eq!(gateway.recent_rejects_count(), 0);
    Ok(())
}

#[test]
fn refused_peer_package_rolls_back_and_caches_only_the_member_it_refused() -> TestResult {
    let seen = Arc::new(Seen::default());
    let gateway = gateway(0, Some(seen.clone()));
    let chain = funded(&[1]);
    let parent = spend_coins(&[coin(1)], &[100_000]);
    let child = spend_outputs(&[OutPoint::new(parent.txid(), 0)], &[96_000]);
    let mut inflating = child.clone();
    inflating.outputs[0].value = Amount::from_sat(200_000);
    let sequence = gateway.read().sequence_number();
    let now = unix_time_secs();

    assert_eq!(
        gateway.submit_peer_package(&[parent.clone(), inflating.clone()], source(), now, &chain),
        Err(SubmitError::Consensus)
    );
    assert!(gateway.read().is_empty());
    assert_eq!(gateway.read().sequence_number(), sequence);
    assert!(seen.0.lock().is_empty());
    assert!(gateway.is_rejected(Hash256::from(inflating.wtxid())));
    assert!(!gateway.is_rejected(Hash256::from(parent.wtxid())));
    assert_eq!(gateway.recent_rejects_count(), 1);
    assert_eq!(gateway.orphan_count(), 0);

    let result = gateway.submit_peer_package(&[parent, child], source(), now, &chain)?;
    assert_eq!(result.len(), 2);
    assert_eq!(seen.0.lock().len(), 1);
    Ok(())
}

#[test]
fn peer_package_with_an_unavailable_input_holds_the_orphan_and_reports_the_first_refusal() {
    let seen = Arc::new(Seen::default());
    let gateway = gateway(0, Some(seen.clone()));
    let chain = funded(&[1]);
    let parent = spend_coins(&[coin(1)], &[100_000]);
    let orphaned = spend_outputs(&[OutPoint::new(parent.txid(), 0), coin(9)], &[96_000]);
    let sequence = gateway.read().sequence_number();

    assert_eq!(
        gateway.submit_peer_package(
            &[parent, orphaned.clone()],
            source(),
            unix_time_secs(),
            &chain
        ),
        Err(SubmitError::Policy(AcceptanceRejectReason::MissingInputs))
    );
    assert!(gateway.read().is_empty());
    assert_eq!(gateway.read().sequence_number(), sequence);
    assert!(seen.0.lock().is_empty());
    assert_eq!(gateway.orphan_count(), 1);
    assert_eq!(gateway.recent_rejects_count(), 0);
    assert!(gateway.have_tx(Hash256::from(orphaned.wtxid()), true));
    assert_eq!(gateway.ancestor_package_wtxids(orphaned.wtxid()), None);
    assert!(gateway.resident_package(&[orphaned.wtxid()]).is_none());

    let first = spend_outputs(&[coin(9)], &[100_000]);
    let second = spend_outputs(&[OutPoint::new(first.txid(), 0)], &[200_000]);
    let fresh = self::gateway(0, None);
    assert_eq!(
        fresh.submit_peer_package(&[first, second], source(), unix_time_secs(), &chain),
        Err(SubmitError::Policy(AcceptanceRejectReason::MissingInputs))
    );
    assert_eq!(fresh.orphan_count(), 1);
    assert_eq!(fresh.recent_rejects_count(), 0);
}

#[test]
fn peer_package_admits_exactly_the_count_bound_atomically_and_serves_no_more() -> TestResult {
    let seen = Arc::new(Seen::default());
    let gateway = gateway(0, Some(seen.clone()));
    let chain = funded(&[1]);
    let count = crate::standardness::MAX_PACKAGE_COUNT;
    let txs = chain_of(count);
    let result = gateway.submit_peer_package(&txs, source(), unix_time_secs(), &chain)?;
    assert_eq!(txids(&result), ids(&txs));
    assert_eq!(seen.0.lock().len(), 1);
    assert_eq!(seen.0.lock()[0].result.len(), count);

    let tip = txs.last().ok_or("chain is not empty")?;
    let served = gateway
        .ancestor_package_wtxids(tip.wtxid())
        .ok_or("the 25-member package is servable")?;
    assert_eq!(
        served,
        txs.iter().map(Tx::wtxid).collect::<Vec<_>>(),
        "ancestors then the tip"
    );

    let next = spend_outputs(&[OutPoint::new(tip.txid(), 0)], &[74_000]);
    let extended = gateway.submit_peer_package(
        std::slice::from_ref(&next),
        source(),
        unix_time_secs(),
        &chain,
    )?;
    assert_eq!(extended.len(), 1);
    assert_eq!(gateway.ancestor_package_wtxids(next.wtxid()), None);
    assert_eq!(
        gateway
            .ancestor_package_wtxids(tip.wtxid())
            .map(|served| served.len()),
        Some(count)
    );

    let refused = self::gateway(0, None).submit_peer_package(
        &chain_of(count + 1),
        source(),
        unix_time_secs(),
        &chain,
    );
    assert_eq!(
        refused,
        Err(SubmitError::Policy(AcceptanceRejectReason::PackageCount))
    );
    Ok(())
}
