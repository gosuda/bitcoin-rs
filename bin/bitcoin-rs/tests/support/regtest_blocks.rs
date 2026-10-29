use bitcoin::hashes::Hash;
use bitcoin::{Block, BlockHash, OutPoint, Sequence, Transaction, TxIn, TxOut, Witness};
use bitcoin_rs_e2e::ProcessNode;
use sonic_rs::{JsonValueTrait as _, json};
use std::error::Error;
use std::time::{Duration, Instant};
type Result<T = ()> = std::result::Result<T, Box<dyn Error>>;

pub(crate) fn coinbase(height: u32, outputs: Vec<TxOut>) -> Transaction {
    Transaction {
        version: bitcoin::transaction::Version::TWO,
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: bitcoin::script::Builder::new()
                .push_int(i64::from(height))
                .push_int(0)
                .into_script(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: outputs,
    }
}

pub(crate) fn block(prev: BlockHash, time: u32, txdata: Vec<Transaction>) -> Result<Block> {
    let mut block = Block {
        header: bitcoin::block::Header {
            version: bitcoin::block::Version::from_consensus(0x2000_0000),
            prev_blockhash: prev,
            merkle_root: bitcoin::TxMerkleNode::all_zeros(),
            time,
            bits: bitcoin::CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        },
        txdata,
    };
    block.header.merkle_root = block.compute_merkle_root().ok_or("empty block")?;
    while block.header.validate_pow(block.header.target()).is_err() {
        block.header.nonce = block.header.nonce.checked_add(1).ok_or("nonce")?;
    }
    Ok(block)
}

pub(crate) fn submit(node: &ProcessNode, block: &Block) -> Result {
    let result = bitcoin_rs_e2e::rpc::Connection::new(node.rpc_addr).rpc(
        &json!({"jsonrpc":"2.0","id":1,"method":"submitblock","params":[bitcoin::consensus::encode::serialize_hex(block)]}),
        ("parity", "parity"), Instant::now() + Duration::from_secs(60),
    )?;
    if result.get("error").is_some_and(|error| !error.is_null()) {
        return Err(format!("RPC: {result}").into());
    }
    let result = &result["result"];
    if !result.is_null() {
        return Err(format!("submitblock: {result}").into());
    }
    Ok(())
}
