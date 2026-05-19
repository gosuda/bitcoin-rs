//! Smoke coverage for Task 17 Electrum protocol methods.

use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hashes::Hash as _;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use bitcoin_rs_electrum::methods::scripthash_hex;
use bitcoin_rs_electrum::{IndexHandle, MempoolHandle, dispatch};
use bitcoin_rs_index::ScriptHash;
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait, json};

#[test]
fn server_methods_return_electrum_shapes() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;

    let version = dispatch(
        "server.version",
        &fixture.index,
        &fixture.mempool,
        &json!(["client", ["1.4", "1.4"]]),
    )?;
    assert!(version.as_array().is_some_and(|array| array.len() == 2));

    assert!(
        dispatch(
            "server.banner",
            &fixture.index,
            &fixture.mempool,
            &json!([])
        )?
        .is_str()
    );
    assert!(
        dispatch(
            "server.donation_address",
            &fixture.index,
            &fixture.mempool,
            &json!([]),
        )?
        .is_null()
    );
    assert!(
        dispatch(
            "server.peers.subscribe",
            &fixture.index,
            &fixture.mempool,
            &json!([]),
        )?
        .as_array()
        .is_some()
    );
    assert!(dispatch("server.ping", &fixture.index, &fixture.mempool, &json!([]))?.is_null());

    Ok(())
}

#[test]
fn scripthash_methods_return_electrum_shapes() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let scripthash_param = json!([scripthash_hex(fixture.scripthash)]);

    let history = dispatch(
        "blockchain.scripthash.get_history",
        &fixture.index,
        &fixture.mempool,
        &scripthash_param,
    )?;
    let Some(history_rows) = history.as_array() else {
        panic!("history response must be an array");
    };
    assert!(
        history_rows
            .iter()
            .all(|entry| { entry.get("tx_hash").is_str() && entry.get("height").is_i64() })
    );

    let balance = dispatch(
        "blockchain.scripthash.get_balance",
        &fixture.index,
        &fixture.mempool,
        &scripthash_param,
    )?;
    assert!(balance.get("confirmed").is_u64());
    assert!(balance.get("unconfirmed").is_u64());

    let status = dispatch(
        "blockchain.scripthash.subscribe",
        &fixture.index,
        &fixture.mempool,
        &scripthash_param,
    )?;
    assert!(status.is_str());

    let unspent = dispatch(
        "blockchain.scripthash.listunspent",
        &fixture.index,
        &fixture.mempool,
        &scripthash_param,
    )?;
    let Some(unspent_rows) = unspent.as_array() else {
        panic!("listunspent response must be an array");
    };
    assert!(unspent_rows.iter().all(|entry| {
        entry.get("tx_hash").is_str()
            && entry.get("tx_pos").is_u64()
            && entry.get("height").is_i64()
            && entry.get("value").is_u64()
    }));

    Ok(())
}

#[test]
fn transaction_fee_and_header_methods_return_electrum_shapes()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;

    let indexed_hex = dispatch(
        "blockchain.transaction.get",
        &fixture.index,
        &fixture.mempool,
        &json!([fixture.indexed_txid.to_string()]),
    )?;
    assert!(indexed_hex.is_str());

    let mempool_txid_string = fixture.mempool_txid.to_string();
    let verbose = dispatch(
        "blockchain.transaction.get",
        &fixture.index,
        &fixture.mempool,
        &json!([mempool_txid_string.as_str(), true]),
    )?;
    assert_eq!(
        verbose.get("txid").and_then(JsonValueTrait::as_str),
        Some(mempool_txid_string.as_str())
    );

    let broadcast_tx = tx(3, ScriptBuf::from_bytes(vec![0x51, 0x03]));
    let broadcast = dispatch(
        "blockchain.transaction.broadcast",
        &fixture.index,
        &fixture.mempool,
        &json!([serialize_hex(&broadcast_tx)]),
    )?;
    assert!(broadcast.is_str());

    assert!(
        dispatch(
            "blockchain.estimatefee",
            &fixture.index,
            &fixture.mempool,
            &json!([6]),
        )?
        .is_i64()
    );

    let histogram = dispatch(
        "mempool.get_fee_histogram",
        &fixture.index,
        &fixture.mempool,
        &json!([]),
    )?;
    assert!(histogram.as_array().is_some());

    let headers = dispatch(
        "blockchain.block.headers",
        &fixture.index,
        &fixture.mempool,
        &json!([0, 1]),
    )?;
    assert_eq!(
        headers.get("count").and_then(JsonValueTrait::as_u64),
        Some(1)
    );
    assert!(headers.get("hex").is_str());
    assert!(headers.get("max").is_u64());

    let tip = dispatch(
        "blockchain.headers.subscribe",
        &fixture.index,
        &fixture.mempool,
        &json!([]),
    )?;
    assert!(tip.get("height").is_u64());
    assert!(tip.get("hex").is_str());

    Ok(())
}

struct Fixture {
    index: IndexHandle,
    mempool: MempoolHandle,
    scripthash: ScriptHash,
    indexed_txid: Txid,
    mempool_txid: Txid,
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let index = IndexHandle::new();
        let mempool = MempoolHandle::default();
        let script = ScriptBuf::from_bytes(vec![0x51]);
        let scripthash = ScriptHash::new(&script);
        let indexed_tx = tx(1, script.clone());
        let indexed_txid = indexed_tx.compute_txid();
        index.add_transaction(&indexed_tx);
        index.add_history_entry(scripthash, indexed_txid, 7, 5_000, 0, false);
        index.add_header(0, [1_u8; 80]);

        let mempool_tx = tx(2, script);
        let mempool_txid = mempool.insert_transaction(mempool_tx, 2_000, 1, 7)?;

        Ok(Self {
            index,
            mempool,
            scripthash,
            indexed_txid,
            mempool_txid,
        })
    }
}

fn tx(label: u8, script_pubkey: ScriptBuf) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: outpoint(label),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(5_000),
            script_pubkey,
        }],
    }
}

fn outpoint(label: u8) -> OutPoint {
    OutPoint {
        txid: Txid::from_byte_array([label; 32]),
        vout: 0,
    }
}
