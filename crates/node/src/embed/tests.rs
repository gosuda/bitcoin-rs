#![allow(clippy::expect_used)]

use super::*;
use crate::NodeConfig;
use bitcoin_rs_mempool::{MempoolEntry, MempoolObserver};
use bitcoin_rs_primitives::{Amount, LockTime, OutPoint, Script, Sequence, TxIn, TxOut, Witness};
use bitcoin_rs_utxo::{BlockChanges, UtxoAdd};
use parking_lot::Mutex;

use bitcoin_rs_rpc::zmq::MempoolSequenceObserver;
use bitcoin_rs_rpc::zmq::{SequenceEvent, ZmqPublisher};

#[derive(Default)]
struct RecordingSequencePublisher {
    sequence_events: Mutex<Vec<SequenceEvent>>,
}

impl core::fmt::Debug for RecordingSequencePublisher {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("RecordingSequencePublisher")
    }
}

impl ZmqPublisher for RecordingSequencePublisher {
    fn wants_notifications(&self) -> bool {
        true
    }

    fn wants_rawtx(&self) -> bool {
        false
    }

    fn wants_rawblock(&self) -> bool {
        false
    }

    fn publish_hashblock(&self, _hash: Hash256) {}

    fn publish_hashtx(&self, _txid: Txid) {}

    fn publish_rawblock(&self, _bytes: &[u8]) {}

    fn publish_rawtx(&self, _bytes: &[u8]) {}

    fn publish_sequence(&self, event: SequenceEvent) {
        self.sequence_events.lock().push(event);
    }
}

fn embedded_config(data_dir: &std::path::Path) -> NodeConfig {
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = data_dir.to_path_buf();
    config.p2p.listen.clear();
    config.rpc.bind = std::net::SocketAddr::from(([127, 0, 0, 1], 0));
    config.observability.metrics_bind = None;
    config
}

/// `P2WSH(OP_TRUE)`, spendable without fixture signature material.
fn spendable_script() -> Vec<u8> {
    let mut script = vec![0x00, 0x20];
    script.extend_from_slice(&[
        0x4a, 0xe8, 0x15, 0x72, 0xf0, 0x6e, 0x1b, 0x88, 0xfd, 0x5c, 0xed, 0x7a, 0x1a, 0x00, 0x09,
        0x45, 0x43, 0x2e, 0x83, 0xe1, 0x55, 0x1e, 0x6f, 0x72, 0x1e, 0xe9, 0xc0, 0x0b, 0x8c, 0xc3,
        0x32, 0x60,
    ]);
    script
}

fn spending_tx(previous_output: OutPoint) -> Tx {
    Tx {
        version: 2,
        lock_time: LockTime::from_consensus(0),
        inputs: vec![TxIn {
            previous_output,
            script_sig: Script::new(),
            sequence: Sequence::from_consensus(0xffff_ffff),
            witness: Witness::from_stack(vec![vec![0x51]]),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(92_000),
            script_pubkey: Script::from_bytes(spendable_script()),
        }],
    }
}

#[test]
// CONTRACT: docs/contracts/architecture.md#ARCH-05
fn broadcast_publishes_one_ordered_a_event_through_the_shared_gateway() {
    let dir = tempfile::tempdir().expect("tempdir");
    let publisher = Arc::new(RecordingSequencePublisher::default());
    let recording: Arc<dyn bitcoin_rs_rpc::zmq::ZmqPublisher> = publisher.clone();
    let observer: Arc<dyn MempoolObserver> = Arc::new(MempoolSequenceObserver::new(recording));
    let config = embedded_config(&dir.path().join("node"));

    let node = testing::block_on(Node::start(
        config,
        crate::RuntimeInputs::default().with_mempool_observer(observer),
    ))
    .expect("embedded node starts");

    let broadcast_prevout = OutPoint::new(Txid(Hash256::from_le_bytes(&[0x5A; 32])), 0);
    let direct_prevout = OutPoint::new(Txid(Hash256::from_le_bytes(&[0x5B; 32])), 0);
    let mut changes = BlockChanges::default();
    for prevout in [broadcast_prevout, direct_prevout] {
        changes.add(UtxoAdd::new(
            prevout,
            TxOut {
                value: Amount::from_sat(100_000),
                script_pubkey: Script::from_bytes(spendable_script()),
            },
            false,
            1,
        ));
    }
    node.state
        .utxo()
        .commit_block(&changes, &Hash256::from_le_bytes(&[0xAB; 32]))
        .map_err(|error| format!("fixture utxo commit failed: {error}"))
        .expect("fixture utxo commit");

    let broadcast_tx = spending_tx(broadcast_prevout);
    let broadcast_txid = broadcast_tx.txid();
    let result = testing::block_on(node.broadcast(broadcast_tx)).expect("broadcast accepted");
    assert_eq!(result.len(), 1, "one admission commits one change");
    assert_eq!(
        result.changes[0].txid,
        Hash256::from(broadcast_txid),
        "the committed change is the broadcast transaction"
    );
    let sequence = result.sequence_of(0).expect("sequence of the change");

    let events = publisher.sequence_events.lock();
    assert_eq!(
        *events,
        vec![SequenceEvent::Added(broadcast_txid, sequence)],
        "Node::broadcast must publish exactly one ordered A event through the shared gateway"
    );
    drop(events);
    publisher.sequence_events.lock().clear();

    // Control: direct insertion cannot satisfy the gateway-publication test.
    let direct_tx = spending_tx(direct_prevout);
    let vsize = u32::try_from(direct_tx.vsize()).unwrap_or(u32::MAX);
    let entry = MempoolEntry::new(Arc::new(direct_tx), vsize, 8_000, 0, 1);
    node.state
        .mempool()
        .write()
        .insert_entry(entry)
        .expect("direct pool insert fixture");
    assert!(
        publisher.sequence_events.lock().is_empty(),
        "a direct pool insertion must not satisfy the gateway publication assertion"
    );

    testing::block_on(node.shutdown()).expect("clean shutdown");
}
