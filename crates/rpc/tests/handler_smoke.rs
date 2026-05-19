//! Smoke tests for every required Task 16 RPC handler.
extern crate alloc;

use alloc::sync::Arc;

use bitcoin::consensus::encode::serialize_hex;
use bitcoin::hashes::Hash as _;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness};
use bitcoin_rs_chain::{ChainWork, NodeId, TipSnapshot};
use bitcoin_rs_mempool::MempoolEntry;
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_rpc::{BlockRecord, Context, Handler, RpcError};
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, json};

#[test]
fn all_required_handlers_return_core_shapes() -> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new()?;
    let handler = Handler::new(Arc::clone(&fixture.ctx));
    let raw_tx = serialize_hex(&fixture.tx);
    let txid = fixture.txid.to_string();
    let block_hash = fixture.block_hash.to_string_be();

    let calls = [
        ("getblockchaininfo", json!([])),
        ("getblockcount", json!([])),
        ("getblockhash", json!([7])),
        ("getbestblockhash", json!([])),
        ("getblock", json!([block_hash.as_str(), 1])),
        ("getblockheader", json!([block_hash.as_str(), true])),
        ("getblockstats", json!([7])),
        ("gettxoutsetinfo", json!([])),
        ("getblockfilter", json!([block_hash.as_str()])),
        ("getrawtransaction", json!([txid.as_str(), true])),
        ("gettxout", json!([txid.as_str(), 0])),
        ("gettxoutproof", json!([[txid.as_str()]])),
        ("verifytxoutproof", json!([""])),
        ("sendrawtransaction", json!([raw_tx.as_str()])),
        ("testmempoolaccept", json!([[raw_tx.as_str()]])),
        ("decoderawtransaction", json!([raw_tx.as_str()])),
        ("getmempoolinfo", json!([])),
        ("getmempoolentry", json!([txid.as_str()])),
        ("getrawmempool", json!([])),
        ("getmempoolancestors", json!([txid.as_str()])),
        ("getmempooldescendants", json!([txid.as_str()])),
        ("estimatesmartfee", json!([6])),
        ("estimaterawfee", json!([6])),
        ("getnetworkinfo", json!([])),
        ("getpeerinfo", json!([])),
        ("addnode", json!(["127.0.0.1", "onetry"])),
        ("disconnectnode", json!(["127.0.0.1"])),
        ("getconnectioncount", json!([])),
        ("getnettotals", json!([])),
        ("getblocktemplate", json!([{}])),
        ("submitblock", json!([""])),
        ("prioritisetransaction", json!([txid.as_str(), 0, 0])),
        (
            "getdescriptorinfo",
            json!(["addr(1111111111111111111114oLvT2)"]),
        ),
        (
            "deriveaddresses",
            json!(["addr(1111111111111111111114oLvT2)"]),
        ),
        ("scantxoutset", json!(["start", []])),
        ("walletcreatefundedpsbt", json!([[], []])),
        ("walletprocesspsbt", json!([""])),
        ("finalizepsbt", json!([""])),
        ("combinepsbt", json!([[""]])),
        ("bumpfee", json!([txid.as_str()])),
    ];

    for (method, params) in calls {
        let response = handler.dispatch(method, &params);
        assert!(response.is_ok(), "{method} failed: {response:?}");
    }

    assert!(
        handler
            .dispatch("getblockchaininfo", &json!([]))?
            .get("blocks")
            .is_u64()
    );
    assert!(
        handler
            .dispatch("getmempoolinfo", &json!([]))?
            .get("size")
            .is_u64()
    );
    assert!(
        handler
            .dispatch("getnetworkinfo", &json!([]))?
            .get("networks")
            .as_array()
            .is_some()
    );
    assert!(
        handler
            .dispatch("getblocktemplate", &json!([{}]))?
            .get("longpollid")
            .is_str()
    );
    Ok(())
}

#[test]
fn signing_methods_are_disabled() -> Result<(), Box<dyn std::error::Error>> {
    let handler = Handler::new(Arc::new(Context::new()));
    let error = handler
        .dispatch("signrawtransactionwithwallet", &json!([]))
        .err()
        .ok_or("signing method unexpectedly succeeded")?;
    assert_eq!(error.code(), RpcError::INTERNAL_ERROR);
    assert_eq!(
        error.to_string(),
        "wallet has no private keys; use external signer"
    );
    Ok(())
}

struct Fixture {
    ctx: Arc<Context>,
    tx: Transaction,
    txid: Txid,
    block_hash: Hash256,
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let ctx = Arc::new(Context::new());
        let block_hash = Hash256::from_le_bytes(&[7_u8; 32]);
        ctx.set_chain_tip(TipSnapshot {
            tip_id: NodeId::new(0),
            height: 7,
            chainwork: ChainWork::ZERO,
            hash: block_hash,
        });
        ctx.add_block(BlockRecord::synthetic(7, block_hash));
        let tx = tx(1, ScriptBuf::from_bytes(vec![0x51]));
        let txid = ctx.add_transaction(tx.clone());
        let entry = MempoolEntry::new(Arc::new(tx.clone()), 100, 1_000, 1, 7);
        ctx.mempool.write().insert_entry(entry)?;
        Ok(Self {
            ctx,
            tx,
            txid,
            block_hash,
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
