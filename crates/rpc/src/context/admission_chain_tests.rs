use anyhow::Context as _;
use bitcoin_rs_chain::NodeStatus;
use bitcoin_rs_primitives::{Header, LockTime, Sequence, TxIn, TxOut, Witness};
use bitcoin_rs_utxo::contract::{BlockChanges, UtxoAdd};
use sha2::{Digest as _, Sha256};

use super::*;

fn spendable_script() -> Vec<u8> {
    let mut script = vec![0x00, 0x20];
    script.extend_from_slice(&Sha256::digest([0x51]));
    script
}

fn spending(outpoint: OutPoint) -> Tx {
    Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: outpoint,
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_stack(vec![vec![0x51]]),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(9_000),
            script_pubkey: Script::from_bytes(spendable_script()),
        }],
        lock_time: LockTime::ZERO,
    }
}

fn publish_tip(ctx: &Context, time: u32) -> anyhow::Result<()> {
    let mut tree = ctx.chain.block_tree.write();
    let parent = ctx.chain.applied_tip.load_full().map(|tip| tip.tip_id);
    let previous_hash = match parent {
        Some(id) => BlockHash::from(tree.node(id)?.hash),
        None => BlockHash::default(),
    };
    let id = tree
        .insert_node(
            parent,
            Header {
                version: 1,
                prev_blockhash: previous_hash,
                merkle_root: Hash256::default(),
                time,
                bits: CompactTarget::from_consensus(0x207f_ffff),
                nonce: time,
            },
            NodeStatus::Active,
        )
        .context("insert tip node")?;
    let node = tree.node(id)?;
    ctx.chain.applied_tip.store(Some(Arc::new(TipSnapshot {
        tip_id: id,
        height: node.height,
        chainwork: node.chainwork,
        hash: node.hash,
        chain_tx_count: node.chain_tx_count,
    })));
    Ok(())
}

#[test]
fn stable_chainstate_reader_does_not_block_transaction_admission() -> anyhow::Result<()> {
    use sonic_rs::{JsonValueTrait as _, json};

    let ctx = Arc::new(Context::new());
    let outpoint = OutPoint::new(Txid::from(Hash256::from_le_bytes(&[8; 32])), 0);
    let tx = spending(outpoint);
    let txid = tx.txid();
    let raw = consensus_bytes(&tx).to_lower_hex_string();
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(
        outpoint,
        TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: Script::from_bytes(spendable_script()),
        },
        false,
        0,
    ));
    bitcoin_rs_utxo::contract::commit_block_changes(
        &ctx.chain.utxo.fixture_set(),
        &changes,
        &Hash256::default(),
    )?;

    let accepted = ctx
        .chain
        .with_stable_chainstate(|| crate::handlers::tx::sendrawtransaction(&ctx, &json!([raw])))?;
    assert_eq!(accepted.as_str(), Some(txid.to_string()).as_deref());
    assert!(ctx.mempool.gateway.read().contains_txid(&txid));
    Ok(())
}

#[test]
fn unconfirmed_transaction_is_admitted_from_a_peer() -> anyhow::Result<()> {
    use bitcoin_rs_mempool::{AdmissionOrigin, PeerToken, SubmitOutcome};
    let ctx = Context::new();
    let outpoint = OutPoint::new(Txid::from(Hash256::from_le_bytes(&[9; 32])), 0);
    let tx = spending(outpoint);
    let txid = tx.txid();
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(
        outpoint,
        TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: Script::from_bytes(spendable_script()),
        },
        false,
        0,
    ));
    bitcoin_rs_utxo::contract::commit_block_changes(
        &ctx.chain.utxo.fixture_set(),
        &changes,
        &Hash256::default(),
    )?;
    assert!(
        !ctx.chain
            .admission_chain()
            .snapshot(&tx)
            .context("snapshot")?
            .confirmed
    );
    let result = ctx.mempool.gateway.submit_transaction(
        Arc::new(tx),
        AdmissionOrigin::Peer(PeerToken {
            endpoint: Some(bitcoin_rs_primitives::PeerEndpoint::Ip(
                std::net::SocketAddr::from(([127, 0, 0, 1], 18444)),
            )),
            addr: Some(std::net::SocketAddr::from(([127, 0, 0, 1], 18444)).into()),
            connection_id: 1,
        }),
        None,
        unix_time_secs(),
        &ctx.chain.admission_chain(),
    )?;
    assert!(matches!(result, SubmitOutcome::Committed(_)));
    assert!(ctx.mempool.gateway.read().contains_txid(&txid));
    Ok(())
}

#[test]
fn confirmed_hint_requires_live_chain_outputs() -> anyhow::Result<()> {
    let ctx = Context::new();
    let tx = spending(OutPoint::new(
        Txid::from(Hash256::from_le_bytes(&[10; 32])),
        0,
    ));
    let output = OutPoint::new(tx.txid(), 0);
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(output, tx.outputs[0].clone(), false, 0));
    bitcoin_rs_utxo::contract::commit_block_changes(
        &ctx.chain.utxo.fixture_set(),
        &changes,
        &Hash256::default(),
    )?;
    assert!(
        ctx.chain
            .admission_chain()
            .snapshot(&tx)
            .context("snapshot")?
            .confirmed
    );
    Ok(())
}

#[test]
fn admission_chain_uses_current_handles_and_one_applied_tip() -> anyhow::Result<()> {
    let mut ctx = Context::new();
    let outpoint = OutPoint::new(Txid::from(Hash256::from_le_bytes(&[7; 32])), 0);
    let tx = spending(outpoint);
    assert_eq!(
        ctx.chain
            .admission_chain()
            .snapshot(&tx)
            .context("empty snapshot")?
            .prevouts,
        []
    );

    ctx.chain.utxo = bitcoin_rs_utxo::UtxoReader::new(Arc::new(bitcoin_rs_utxo::UtxoSet::new()));
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(
        outpoint,
        TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: Script::from_bytes(vec![0x51]),
        },
        false,
        0,
    ));
    bitcoin_rs_utxo::contract::commit_block_changes(
        &ctx.chain.utxo.fixture_set(),
        &changes,
        &Hash256::default(),
    )
    .context("fund input")?;
    publish_tip(&ctx, 100)?;
    publish_tip(&ctx, 200)?;
    let snapshot = ctx
        .chain
        .admission_chain()
        .snapshot(&tx)
        .context("snapshot")?;
    assert_eq!(snapshot.height, 1);
    assert_eq!(snapshot.locktime_cutoff, 200);
    assert_eq!(snapshot.prevouts.len(), 1);
    assert_eq!(snapshot.prevouts[0].0, outpoint);
    assert_eq!(snapshot.prevouts[0].1.value, 10_000);
    assert!(
        !snapshot.confirmed,
        "an input UTXO is not evidence that the spending transaction is confirmed"
    );
    Ok(())
}

#[test]
#[expect(clippy::expect_used)]
fn admission_envelopes_share_gateway_outcomes() -> anyhow::Result<()> {
    use sonic_rs::{JsonValueTrait as _, Value, json};

    use crate::error::RpcError;
    use crate::handlers::tx;

    let outpoint = OutPoint::new(Txid::from(Hash256::from_le_bytes(&[21; 32])), 0);
    let spend = spending(outpoint);
    let raw = consensus_bytes(&spend).to_lower_hex_string();
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(
        outpoint,
        TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: Script::from_bytes(spendable_script()),
        },
        false,
        0,
    ));

    let rpc_ctx = Arc::new(Context::new());
    bitcoin_rs_utxo::contract::commit_block_changes(
        &rpc_ctx.chain.utxo.fixture_set(),
        &changes,
        &Hash256::default(),
    )?;
    let accepted = tx::sendrawtransaction(&rpc_ctx, &json!([raw]))?;
    assert_eq!(accepted.as_str(), Some(spend.txid().to_string()).as_deref());
    assert!(rpc_ctx.mempool.gateway.read().contains_txid(&spend.txid()));

    let orphan = spending(OutPoint::new(
        Txid::from(Hash256::from_le_bytes(&[22; 32])),
        0,
    ));
    let orphan_raw = consensus_bytes(&orphan).to_lower_hex_string();
    let refused = tx::sendrawtransaction(&rpc_ctx, &json!([orphan_raw]))
        .expect_err("an unknown prevout must be refused");
    assert_eq!(refused.code(), RpcError::CORE_VERIFY_ERROR);
    assert!(!rpc_ctx.mempool.gateway.read().contains_txid(&orphan.txid()));

    let preview_ctx = Arc::new(Context::new());
    bitcoin_rs_utxo::contract::commit_block_changes(
        &preview_ctx.chain.utxo.fixture_set(),
        &changes,
        &Hash256::default(),
    )?;
    let rows = tx::testmempoolaccept(&preview_ctx, &json!([[raw]]))?;
    assert_eq!(
        rows.get(0)
            .and_then(|row| row.get("allowed"))
            .and_then(Value::as_bool),
        Some(true)
    );
    assert!(
        !preview_ctx
            .mempool
            .gateway
            .read()
            .contains_txid(&spend.txid()),
        "the accepted preview must not insert"
    );
    Ok(())
}

fn burn_raw() -> String {
    let burn = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid::from(Hash256::from_le_bytes(&[7; 32])), 0),
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: Script::from_bytes(vec![0x6a, 0x01, 0x51]),
        }],
        lock_time: LockTime::ZERO,
    };
    consensus_bytes(&burn).to_lower_hex_string()
}

#[test]
#[expect(clippy::expect_used)]
fn sendrawtransaction_honors_maxburnamount_before_admission() {
    use sonic_rs::json;

    use crate::error::RpcError;
    use crate::handlers::tx;

    let rpc_ctx = Arc::new(Context::new());
    let raw = &burn_raw();
    let refused = tx::sendrawtransaction(&rpc_ctx, &json!([raw]))
        .expect_err("burn above the default cap must be refused");
    assert!(
        refused.to_string().contains("maxburnamount"),
        "unexpected refusal: {refused}"
    );
    let refused = tx::sendrawtransaction(&rpc_ctx, &json!([raw, null, "0.00001"]))
        .expect_err("unknown prevout must still be refused");
    assert_eq!(refused.code(), RpcError::CORE_VERIFY_ERROR);
    let refused = tx::sendrawtransaction(&rpc_ctx, &json!([raw, null, "0.00000999"]))
        .expect_err("burn above the explicit cap must be refused");
    assert!(
        refused.to_string().contains("maxburnamount"),
        "unexpected refusal: {refused}"
    );
    let refused = tx::sendrawtransaction(
        &rpc_ctx,
        &json!({"hexstring": raw, "maxburnamount": "0.00001"}),
    )
    .expect_err("unknown prevout must still be refused");
    assert_eq!(refused.code(), RpcError::CORE_VERIFY_ERROR);
}

#[derive(Debug, Default)]
struct RecordingPublisher {
    hashtx: std::sync::Mutex<Vec<Txid>>,
}

impl crate::zmq::ZmqPublisher for RecordingPublisher {
    fn publish_hashblock(&self, _hash: Hash256) {}

    fn publish_hashtx(&self, txid: Txid) {
        if let Ok(mut seen) = self.hashtx.lock() {
            seen.push(txid);
        }
    }

    fn publish_rawblock(&self, _bytes: &[u8]) {}

    fn publish_rawtx(&self, _bytes: &[u8]) {}
}

#[test]
#[expect(clippy::expect_used)]
fn sendrawtransaction_publishes_hashtx_once_per_admission() -> anyhow::Result<()> {
    use sonic_rs::json;

    use crate::handlers::tx;

    let outpoint = OutPoint::new(Txid::from(Hash256::from_le_bytes(&[31; 32])), 0);
    let spend = spending(outpoint);
    let raw = &consensus_bytes(&spend).to_lower_hex_string();
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(
        outpoint,
        TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: Script::from_bytes(spendable_script()),
        },
        false,
        0,
    ));

    let recording = Arc::new(RecordingPublisher::default());
    let publisher: Arc<dyn crate::zmq::ZmqPublisher> = recording.clone();
    let mut fresh_ctx = Context::new_with_mempool_observer(Arc::new(
        crate::zmq::MempoolSequenceObserver::new(publisher.clone()),
    ));
    fresh_ctx.zmq_publisher = publisher;
    let rpc_ctx = Arc::new(fresh_ctx);
    let published = || {
        recording
            .hashtx
            .lock()
            .map(|seen| seen.clone())
            .unwrap_or_default()
    };
    bitcoin_rs_utxo::contract::commit_block_changes(
        &rpc_ctx.chain.utxo.fixture_set(),
        &changes,
        &Hash256::default(),
    )?;

    tx::sendrawtransaction(&rpc_ctx, &json!([raw]))?;
    assert_eq!(
        published(),
        vec![spend.txid()],
        "admission must publish exactly one hashtx"
    );

    tx::sendrawtransaction(&rpc_ctx, &json!([raw]))?;
    assert_eq!(
        published().len(),
        1,
        "a duplicate admission must not republish"
    );

    let orphan = spending(OutPoint::new(
        Txid::from(Hash256::from_le_bytes(&[32; 32])),
        0,
    ));
    let orphan_raw = consensus_bytes(&orphan).to_lower_hex_string();
    tx::sendrawtransaction(&rpc_ctx, &json!([orphan_raw]))
        .expect_err("an unknown prevout must be refused");
    assert_eq!(
        published().len(),
        1,
        "a rejected submission must not publish"
    );
    Ok(())
}

#[test]
fn submitpackage_publishes_hashtx_only_for_newly_admitted() -> anyhow::Result<()> {
    use sonic_rs::json;

    use crate::handlers::tx::submit_package::submitpackage;

    let coin = OutPoint::new(Txid::from(Hash256::from_le_bytes(&[41; 32])), 0);
    let parent = spending(coin);
    let child = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(parent.txid(), 0),
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_stack(vec![vec![0x51]]),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(7_000),
            script_pubkey: Script::from_bytes(spendable_script()),
        }],
        lock_time: LockTime::ZERO,
    };
    let raws = [
        consensus_bytes(&parent).to_lower_hex_string(),
        consensus_bytes(&child).to_lower_hex_string(),
    ];
    let mut changes = BlockChanges::default();
    changes.add(UtxoAdd::new(
        coin,
        TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: Script::from_bytes(spendable_script()),
        },
        false,
        0,
    ));

    let recording = Arc::new(RecordingPublisher::default());
    let publisher: Arc<dyn crate::zmq::ZmqPublisher> = recording.clone();
    let mut fresh_ctx = Context::new_with_mempool_observer(Arc::new(
        crate::zmq::MempoolSequenceObserver::new(publisher.clone()),
    ));
    fresh_ctx.zmq_publisher = publisher;
    let rpc_ctx = Arc::new(fresh_ctx);
    let published = || {
        recording
            .hashtx
            .lock()
            .map(|seen| seen.clone())
            .unwrap_or_default()
    };
    bitcoin_rs_utxo::contract::commit_block_changes(
        &rpc_ctx.chain.utxo.fixture_set(),
        &changes,
        &Hash256::default(),
    )?;

    submitpackage(&rpc_ctx, &json!([[raws[0].clone(), raws[1].clone()]]))?;
    assert_eq!(
        published(),
        vec![parent.txid(), child.txid()],
        "each newly admitted member must publish hashtx"
    );

    submitpackage(&rpc_ctx, &json!([[raws[0].clone(), raws[1].clone()]]))?;
    assert_eq!(published().len(), 2, "resident members must not republish");
    Ok(())
}

#[test]
#[expect(clippy::expect_used)]
fn sendrawtransaction_rejects_unknown_extra_params() {
    use sonic_rs::json;

    use crate::handlers::tx;

    let rpc_ctx = Arc::new(Context::new());
    let raw = &burn_raw();
    let refused = tx::sendrawtransaction(&rpc_ctx, &json!([raw, null, null, "extra"]))
        .expect_err("a fourth parameter must be refused");
    assert!(
        refused.to_string().contains("too many parameters"),
        "unexpected refusal: {refused}"
    );
    let refused = tx::sendrawtransaction(&rpc_ctx, &json!({"hexstring": raw, "bogus": 1}))
        .expect_err("an unknown named parameter must be refused");
    assert!(
        refused.to_string().contains("Unknown named parameter"),
        "unexpected refusal: {refused}"
    );
}
