//! External template consumer: spawn the public `bitcoin-rs` binary and
//! assemble a rendered GBT from real mempool content, then submit the solved
//! block over HTTP. T36 non-relay subset: no second P2P node, no relay faking.

#![allow(missing_docs)]

use std::error::Error;

use bitcoin::absolute::LockTime;
use bitcoin::block::{Header, Version as BlockVersion};
use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin::constants::genesis_block;
use bitcoin::hashes::Hash as _;
use bitcoin::script::Builder;
use bitcoin::transaction::Version as TxVersion;
use bitcoin::{
    Amount, Block, CompactTarget, Network, OutPoint, ScriptBuf, Sequence, Target, Transaction,
    TxIn, TxMerkleNode, TxOut, WPubkeyHash, Witness,
};
use serde_json::{Value, json};

mod support;

use support::process_node::{NodeBinary, ProcessNode};

const FEE_SATS: u64 = 10_000;
const REGTEST_SUBSIDY_SATS: u64 = 5_000_000_000;
const WITNESS_RESERVED: [u8; 32] = [0_u8; 32];
const COINBASE_MATURITY: u32 = 100;

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

#[test]
fn external_miner_assembles_template_and_submits_block() -> TestResult {
    let mut node = ProcessNode::start(NodeBinary::BitcoinRs)?;

    submit_genesis(&mut node)?;

    // Mine COINBASE_MATURITY+1 empty blocks with bare OP_TRUE coinbase outputs.
    for _ in 0..=COINBASE_MATURITY {
        let result = node.rpc("generateblock", &json!(["raw(51)", []]))?;
        assert!(
            result.get("hash").is_some(),
            "generateblock must return a block hash object: {result}"
        );
    }

    let coinbase = height_1_coinbase(&mut node)?;
    let spend = spend_coinbase(&coinbase);
    let spend_hex = serialize_hex(&spend);
    let send = node.rpc("sendrawtransaction", &json!([spend_hex, 0]))?;
    assert!(
        send.as_str()
            .is_some_and(|s| s == spend.compute_txid().to_string()),
        "sendrawtransaction must return the spend txid: {send}"
    );

    let template = node.rpc("getblocktemplate", &json!([{"rules": ["segwit"]}]))?;
    assert_eq!(
        required_u64(&template, "height")?,
        u64::from(COINBASE_MATURITY) + 2,
        "template must extend the current tip"
    );
    let template_txs = template
        .get("transactions")
        .and_then(Value::as_array)
        .ok_or("template must carry a transactions array")?;
    assert_eq!(
        template_txs.len(),
        1,
        "template must select the one admitted spend"
    );
    let entry = &template_txs[0];
    assert_eq!(
        required_str(entry, "hash")?,
        spend.compute_wtxid().to_string(),
        "rendered hash must be the spend wtxid"
    );
    assert_eq!(
        required_u64(entry, "fee")?,
        FEE_SATS,
        "rendered fee must match the spend fee"
    );
    assert!(
        required_u64(entry, "weight")? > 0,
        "rendered weight must be positive"
    );
    let depends = entry
        .get("depends")
        .and_then(Value::as_array)
        .map_or(&[][..], |arr| arr.as_slice());
    assert!(depends.is_empty(), "single tx has no in-template depends");

    let block = assemble_from_template(&template)?;
    let block_hex = serialize_hex(&block);
    let submit = node.rpc("submitblock", &json!([block_hex]))?;
    assert!(
        submit.is_null(),
        "submitblock must accept the external block: {submit}"
    );

    let info = node.rpc("getblockchaininfo", &json!([]))?;
    let tip_height = required_u64(&info, "blocks")?;
    assert_eq!(
        tip_height,
        u64::from(COINBASE_MATURITY) + 2,
        "tip must advance by one"
    );

    let mempool = node.rpc("getmempoolinfo", &json!([]))?;
    assert_eq!(
        required_u64(&mempool, "size")?,
        0,
        "mempool must be empty after block inclusion"
    );

    // `node` is dropped here, killing the child and cleaning up.
    let _ = node.stop();
    Ok(())
}

fn submit_genesis(node: &mut ProcessNode) -> TestResult {
    let hex = serialize_hex(&genesis_block(Network::Regtest));
    let result = node.rpc("submitblock", &json!([hex]))?;
    // The regtest genesis may already be the starting tip; accept either.
    if !result.is_null() && result.as_str() != Some("duplicate") {
        return Err(format!("submitblock(genesis) rejected: {result}").into());
    }
    Ok(())
}

fn height_1_coinbase(node: &mut ProcessNode) -> TestResult<Transaction> {
    let hash_1 = node.rpc("getblockhash", &json!([1]))?;
    let hash = hash_1.as_str().ok_or("getblockhash must return a string")?;
    let block = node.rpc("getblock", &json!([hash, 2]))?;
    let txs = block
        .get("tx")
        .and_then(Value::as_array)
        .ok_or("getblock(2) must return a tx array")?;
    let first = txs.first().ok_or("block must have a coinbase tx")?;
    let hex = first
        .get("hex")
        .and_then(Value::as_str)
        .ok_or("coinbase tx must have a hex field")?;
    deserialize_hex(hex).map_err(|error| format!("decode coinbase: {error}").into())
}

fn spend_coinbase(coinbase: &Transaction) -> Transaction {
    let p2wpkh = ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([2; 20]));
    Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(coinbase.compute_txid(), 0),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(REGTEST_SUBSIDY_SATS - FEE_SATS),
            script_pubkey: p2wpkh,
        }],
    }
}

fn assemble_from_template(template: &Value) -> TestResult<Block> {
    let prev_hex = required_str(template, "previousblockhash")?;
    let height = u32::try_from(required_u64(template, "height")?)?;
    let coinbase_value = required_u64(template, "coinbasevalue")?;
    let bits = CompactTarget::from_unprefixed_hex(required_str(template, "bits")?)?;
    let curtime = u32::try_from(required_u64(template, "curtime")?)?;
    let version = i32::try_from(required_u64(template, "version")?)?;
    let commitment = ScriptBuf::from_hex(required_str(template, "default_witness_commitment")?)?;

    let mut txs = Vec::new();
    if let Some(entries) = template.get("transactions").and_then(Value::as_array) {
        for entry in entries {
            let data = entry
                .get("data")
                .and_then(Value::as_str)
                .ok_or("template transaction missing data hex")?;
            txs.push(deserialize_hex::<Transaction>(data)?);
        }
    }

    let coinbase = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: coinbase_script_sig(height),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[&WITNESS_RESERVED]),
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(coinbase_value),
                script_pubkey: ScriptBuf::from(vec![0x51]),
            },
            TxOut {
                value: Amount::from_sat(0),
                script_pubkey: commitment,
            },
        ],
    };

    let mut txdata = Vec::with_capacity(txs.len().saturating_add(1));
    txdata.push(coinbase);
    txdata.extend(txs);
    let mut block = Block {
        header: Header {
            version: BlockVersion::from_consensus(version),
            prev_blockhash: prev_hex.parse()?,
            merkle_root: TxMerkleNode::all_zeros(),
            time: curtime,
            bits,
            nonce: 0,
        },
        txdata,
    };
    block.header.merkle_root = block
        .compute_merkle_root()
        .ok_or("block must have a merkle root")?;
    grind_pow(&mut block.header)?;
    Ok(block)
}

fn coinbase_script_sig(height: u32) -> ScriptBuf {
    let mut builder = Builder::new().push_int(i64::from(height));
    if builder.as_bytes().len() < 2 {
        builder = builder.push_int(0);
    }
    builder.into_script()
}

fn grind_pow(header: &mut Header) -> TestResult {
    let target = Target::from(header.bits);
    loop {
        if target.is_met_by(header.block_hash()) {
            return Ok(());
        }
        header.nonce = header
            .nonce
            .checked_add(1)
            .ok_or("nonce exhausted while grinding block")?;
    }
}

fn required_str<'a>(value: &'a Value, key: &str) -> TestResult<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("template missing string {key}").into())
}

fn required_u64(value: &Value, key: &str) -> TestResult<u64> {
    value
        .get(key)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("template missing u64 {key}").into())
}
