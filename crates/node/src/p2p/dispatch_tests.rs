use std::cell::RefCell;
use std::io::Cursor;
use std::sync::Arc;

use bitcoin::hashes::Hash as _;
use bitcoin::p2p::Magic;
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin_rs_consensus::ValidationEngine;
use bitcoin_rs_consensus::primitives::{
    Amount, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
};
use bitcoin_rs_mempool::{
    AdmissionChain, AdmissionOrigin, ChainAdmissionSnapshot, Mempool, MempoolEntry, MempoolGateway,
    MempoolLimits, PeerToken, SubmitOutcome,
};
use bitcoin_rs_wire::dispatch::{ChainQuery, TxInventory, dispatch_inbound_full, serve_getdata};
use bitcoin_rs_wire::peer::{Peer, PeerState};
use bitcoin_rs_wire::wire::{Message, PeerError};

use crate::p2p::RefTxInventory;

fn dummy_tx(byte: u8) -> Tx {
    Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from(Hash256::from_le_bytes(&[byte; 32])),
                vout: 0,
            },
            script_sig: vec![byte].into(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: vec![0x6A].into(),
        }],
        lock_time: LockTime::ZERO,
    }
}

fn ready_peer() -> Peer<Cursor<Vec<u8>>> {
    let mut peer = Peer::new(Cursor::new(Vec::new()), Magic::BITCOIN);
    peer.state = PeerState::Ready;
    peer
}

fn dispatch_collect_full<S: std::io::Read + std::io::Write>(
    peer: &mut Peer<S>,
    message: &Message,
    chain: Option<&dyn ChainQuery>,
    tx_inventory: Option<&dyn TxInventory>,
) -> Result<Vec<Message>, PeerError> {
    let collected = RefCell::new(Vec::new());
    dispatch_inbound_full(
        peer,
        message,
        chain,
        tx_inventory,
        &|| true,
        &|| true,
        &mut |response| {
            collected.borrow_mut().push(response);
            Ok(())
        },
        &mut |_| {},
        &mut |items| collected.borrow_mut().push(Message::GetData(items)),
    )?;
    Ok(collected.into_inner())
}

fn gateway_holding_witness_tx(orphan: bool) -> (MempoolGateway, Arc<Tx>) {
    struct MissingCoins;
    impl AdmissionChain for MissingCoins {
        fn snapshot(&self, _tx: &Tx) -> Option<ChainAdmissionSnapshot> {
            Some(ChainAdmissionSnapshot {
                prevouts: Vec::new(),
                height: 0,
                locktime_cutoff: 0,
                prevout_meta: hashbrown::HashMap::new(),
                csv_active: false,
                ..ChainAdmissionSnapshot::default()
            })
        }
    }

    let gateway = MempoolGateway::new(
        Arc::new(parking_lot::RwLock::new(Mempool::new(
            MempoolLimits::default(),
        ))),
        None,
        ValidationEngine::Native,
        None,
    );
    let mut tx = dummy_tx(0x51);
    tx.inputs[0].script_sig.clear();
    tx.inputs[0].witness = Witness::from_stack(vec![vec![0x51]]);
    tx.outputs[0].script_pubkey = Script::from_bytes(vec![0x6a, 4, 1, 2, 3, 4]);
    let tx = Arc::new(tx);
    if orphan {
        let source = PeerToken {
            endpoint: Some(bitcoin_rs_consensus::primitives::PeerEndpoint::Ip(
                std::net::SocketAddr::from(([127, 0, 0, 1], 8333)),
            )),
            addr: Some(bitcoin_rs_consensus::primitives::PeerEndpoint::from((
                [127, 0, 0, 1],
                8333,
            ))),
            connection_id: 1,
        };
        assert!(matches!(
            gateway.submit_transaction(
                Arc::clone(&tx),
                AdmissionOrigin::Peer(source),
                None,
                0,
                &MissingCoins,
            ),
            Ok(SubmitOutcome::Held { .. })
        ));
        assert_eq!(gateway.orphan_count(), 1);
    } else {
        assert!(
            gateway
                .insert_entry(
                    AdmissionOrigin::Rpc,
                    MempoolEntry::new(Arc::clone(&tx), 100, 10_000, 1, 0, 0),
                )
                .is_ok()
        );
    }
    (gateway, tx)
}

#[test]
fn getdata_completes_initial_broadcast_only_after_successful_send() -> Result<(), PeerError> {
    for kind in 0..3 {
        let gateway = MempoolGateway::new(
            Arc::new(parking_lot::RwLock::new(Mempool::new(
                MempoolLimits::default(),
            ))),
            None,
            ValidationEngine::Native,
            None,
        );
        let mut tx = dummy_tx(1);
        tx.inputs[0].witness = Witness::from_stack(vec![vec![0x51]]);
        let txid = tx.txid();
        let wtxid = tx.wtxid();
        gateway
            .insert_entry(
                AdmissionOrigin::Rpc,
                MempoolEntry::new(Arc::new(tx), 100, 1000, 1, 0, 0),
            )
            .expect("insert entry");
        let sequence = gateway.read().sequence_number();
        let item = match kind {
            0 => Inventory::Transaction(bitcoin::Txid::from_byte_array(*txid.as_bytes())),
            1 => Inventory::WitnessTransaction(bitcoin::Txid::from_byte_array(*txid.as_bytes())),
            _ => Inventory::WTx(bitcoin::Wtxid::from_byte_array(*wtxid.as_bytes())),
        };
        let mut not_found = Vec::new();
        assert!(
            serve_getdata(
                None,
                Some(&RefTxInventory(&gateway)),
                None,
                &[item],
                &mut not_found,
                &|| true,
                &mut |_| Err(PeerError::Misbehavior("test sink full")),
            )
            .is_err()
        );
        assert_eq!(gateway.read().unbroadcast_transactions().count(), 1);
        let mut responses = Vec::new();
        serve_getdata(
            None,
            Some(&RefTxInventory(&gateway)),
            None,
            &[item],
            &mut not_found,
            &|| true,
            &mut |message| {
                responses.push(message);
                Ok(())
            },
        )?;
        assert!(matches!(responses.as_slice(), [Message::Tx(_)]));
        assert_eq!(gateway.read().unbroadcast_transactions().count(), 0);
        assert_eq!(gateway.read().sequence_number(), sequence);
    }
    Ok(())
}

#[test]
fn one_sided_wtxid_negotiation_does_not_rerequest_pool_or_orphan_bodies() -> Result<(), PeerError> {
    for orphan in [false, true] {
        let (gateway, tx) = gateway_holding_witness_tx(orphan);
        let txid = bitcoin::Txid::from_byte_array(*tx.txid().as_bytes());
        let wtxid = bitcoin::Wtxid::from_byte_array(*tx.wtxid().as_bytes());
        assert_ne!(txid.as_byte_array(), wtxid.as_byte_array());
        for (remote_requested, item) in [
            (false, Inventory::WTx(wtxid)),
            (true, Inventory::Transaction(txid)),
            (true, Inventory::WitnessTransaction(txid)),
        ] {
            let mut peer = ready_peer();
            if remote_requested {
                peer.wtxid_relay.mark_peer_supported();
            }
            let held_suppresses = !orphan || matches!(item, Inventory::WTx(_));
            let responses = dispatch_collect_full(
                &mut peer,
                &Message::Inv(vec![item]),
                None,
                Some(&RefTxInventory(&gateway)),
            )?;
            if held_suppresses {
                assert!(
                    responses.is_empty(),
                    "inventory type must select the held body's identity in either relay direction"
                );
            } else {
                assert_eq!(responses, vec![Message::GetData(vec![item])]);
            }

            let unknown = Inventory::WTx(bitcoin::Wtxid::from_byte_array([0xff; 32]));
            let expected = if held_suppresses {
                vec![unknown]
            } else {
                vec![item, unknown]
            };
            assert_eq!(
                dispatch_collect_full(
                    &mut peer,
                    &Message::Inv(vec![item, unknown]),
                    None,
                    Some(&RefTxInventory(&gateway)),
                )?,
                vec![Message::GetData(expected)]
            );
        }
    }
    Ok(())
}

// P2P-01
#[test]
fn getdata_serves_mempool_bodies_but_never_held_orphans() -> Result<(), PeerError> {
    for orphan in [false, true] {
        let (gateway, tx) = gateway_holding_witness_tx(orphan);
        let item = Inventory::WTx(bitcoin::Wtxid::from_byte_array(*tx.wtxid().as_bytes()));
        let responses = dispatch_collect_full(
            &mut ready_peer(),
            &Message::GetData(vec![item]),
            None,
            Some(&RefTxInventory(&gateway)),
        )?;
        if orphan {
            assert_eq!(responses, vec![Message::NotFound(vec![item])]);
        } else {
            assert_eq!(responses, vec![Message::Tx((*tx).clone())]);
        }
    }
    Ok(())
}

#[test]
fn gateway_inventory_filters_and_serves_txid_and_wtxid() -> Result<(), PeerError> {
    let gateway = MempoolGateway::new(
        Arc::new(parking_lot::RwLock::new(Mempool::new(
            MempoolLimits::default(),
        ))),
        None,
        ValidationEngine::Native,
        None,
    );
    let mut tx = dummy_tx(0x42);
    tx.inputs[0].witness = Witness::from_stack(vec![vec![0x01]]);
    let txid_item = Inventory::Transaction(bitcoin::Txid::from_byte_array(*tx.txid().as_bytes()));
    let witness_txid_item =
        Inventory::WitnessTransaction(bitcoin::Txid::from_byte_array(*tx.txid().as_bytes()));
    let wtxid_item = Inventory::WTx(bitcoin::Wtxid::from_byte_array(*tx.wtxid().as_bytes()));
    assert_ne!(tx.txid().as_bytes(), tx.wtxid().as_bytes());
    assert!(
        gateway
            .insert_entry(
                AdmissionOrigin::Rpc,
                MempoolEntry::new(Arc::new(tx.clone()), 100, 10_000, 1, 0, 0),
            )
            .is_ok()
    );

    for (item, wtxid_relay) in [(txid_item, false), (wtxid_item, true)] {
        let mut peer = ready_peer();
        if wtxid_relay {
            peer.wtxid_relay.mark_peer_supported();
        }
        let responses = dispatch_collect_full(
            &mut peer,
            &Message::Inv(vec![item]),
            None,
            Some(&RefTxInventory(&gateway)),
        )?;
        assert_eq!(responses, []);
    }

    let mut stripped = tx.clone();
    for input in &mut stripped.inputs {
        input.witness.clear();
    }
    let missing = Inventory::WTx(bitcoin::Wtxid::from_byte_array([0xFF; 32]));
    let mut peer = ready_peer();
    peer.wtxid_relay.mark_peer_supported();
    let responses = dispatch_collect_full(
        &mut peer,
        &Message::GetData(vec![txid_item, witness_txid_item, wtxid_item, missing]),
        None,
        Some(&RefTxInventory(&gateway)),
    )?;
    assert_eq!(
        responses,
        vec![
            Message::Tx(stripped),
            Message::Tx(tx.clone()),
            Message::Tx(tx.clone()),
            Message::NotFound(vec![missing])
        ],
    );
    assert_eq!(gateway.get_tx_by_wtxid(tx.wtxid()), Some(tx));
    Ok(())
}
