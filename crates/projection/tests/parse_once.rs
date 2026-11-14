//! `PRJ-01` and `BLK-01`: the derived-index write path parses a block at most
//! once on the fallback body path and never on the committed-facts path.
//! The parse counter is process-global, so this binary holds one test.

use std::error::Error;
use std::sync::Arc;

use bitcoin_rs_consensus::primitives::encode::double_sha256;
use bitcoin_rs_consensus::primitives::layout::{
    parse_exact_call_count, reset_parse_exact_call_count,
};
use bitcoin_rs_projection::{IndexCapabilities, IndexWriter, SpentCoin, SpentCoins};
use bitcoin_rs_storage::{
    Bytes, CommittedBlock, CreatedOutput, RocksDbStore, SpentPrevout, TxFacts,
};

const COINBASE_VALUE: u64 = 50 * 100_000_000;
const CHILD_VALUE: u64 = COINBASE_VALUE - 1_000;
const OP_TRUE: [u8; 1] = [0x51];
const P2WPKH: [u8; 22] = [
    0x00, 0x14, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
    0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
];
const BODY_OFFSET: usize = 81;

struct NoCoins;

impl SpentCoins for NoCoins {
    fn spent_coin(&self, _txid: &[u8; 32], _vout: u32) -> Option<SpentCoin<'_>> {
        None
    }
}

struct FirstCoinbase {
    txid: [u8; 32],
}

impl SpentCoins for FirstCoinbase {
    fn spent_coin(&self, txid: &[u8; 32], vout: u32) -> Option<SpentCoin<'_>> {
        (txid == &self.txid && vout == 0).then_some(SpentCoin {
            script: &OP_TRUE,
            value: COINBASE_VALUE,
            height: 1,
            coinbase: true,
        })
    }
}

fn legacy_tx(inputs: &[([u8; 32], u32, Vec<u8>)], outputs: &[(u64, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&1_i32.to_le_bytes());
    out.push(u8::try_from(inputs.len()).unwrap_or(u8::MAX));
    for (txid, vout, script_sig) in inputs {
        out.extend_from_slice(txid);
        out.extend_from_slice(&vout.to_le_bytes());
        out.push(u8::try_from(script_sig.len()).unwrap_or(u8::MAX));
        out.extend_from_slice(script_sig);
        out.extend_from_slice(&u32::MAX.to_le_bytes());
    }
    out.push(u8::try_from(outputs.len()).unwrap_or(u8::MAX));
    for (value, script) in outputs {
        out.extend_from_slice(&value.to_le_bytes());
        out.push(u8::try_from(script.len()).unwrap_or(u8::MAX));
        out.extend_from_slice(script);
    }
    out.extend_from_slice(&0_u32.to_le_bytes());
    out
}

struct Block {
    body: Vec<u8>,
    header: [u8; 80],
    hash: [u8; 32],
}

fn block(prev: [u8; 32], height: u32, txs: &[Vec<u8>]) -> Block {
    let mut header = [0_u8; 80];
    header[..4].copy_from_slice(&1_i32.to_le_bytes());
    header[4..36].copy_from_slice(&prev);
    header[68..72].copy_from_slice(&height.to_le_bytes());
    header[72..76].copy_from_slice(&0x207f_ffff_u32.to_le_bytes());
    header[76..80].copy_from_slice(&height.to_le_bytes());
    let hash = double_sha256(&header).to_le_bytes();
    let mut body = header.to_vec();
    body.push(u8::try_from(txs.len()).unwrap_or(u8::MAX));
    for tx in txs {
        body.extend_from_slice(tx);
    }
    Block { body, header, hash }
}

fn tx_facts(
    txid: [u8; 32],
    offset: usize,
    len: usize,
    inputs: Vec<SpentPrevout>,
    outputs: Vec<CreatedOutput>,
) -> TxFacts {
    TxFacts {
        txid,
        offset: u32::try_from(offset).unwrap_or(u32::MAX),
        len: u32::try_from(len).unwrap_or(u32::MAX),
        inputs,
        outputs,
    }
}

fn created(vout: u32, value: u64, script: &[u8]) -> CreatedOutput {
    CreatedOutput {
        vout,
        value,
        script: Bytes::copy_from_slice(script),
    }
}

#[test]
fn live_facts_path_parses_nothing_and_fallback_parses_once() -> Result<(), Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let store = Arc::new(RocksDbStore::open(dir.path())?);
    let writer = IndexWriter::open(store, 1)?;
    let caps = IndexCapabilities::ALL;

    let cb1 = legacy_tx(
        &[([0; 32], u32::MAX, vec![0x01, 0x01])],
        &[(COINBASE_VALUE, OP_TRUE.to_vec())],
    );
    let first = block([0; 32], 1, std::slice::from_ref(&cb1));
    let cb1_txid = double_sha256(&cb1).to_le_bytes();

    let cb2 = legacy_tx(
        &[([0; 32], u32::MAX, vec![0x02, 0x02, 0x00])],
        &[(COINBASE_VALUE, OP_TRUE.to_vec())],
    );
    let spend = legacy_tx(
        &[(cb1_txid, 0, Vec::new())],
        &[(CHILD_VALUE, P2WPKH.to_vec())],
    );
    let second = block(first.hash, 2, &[cb2.clone(), spend.clone()]);
    let cb2_txid = double_sha256(&cb2).to_le_bytes();
    let spend_txid = double_sha256(&spend).to_le_bytes();

    let before = parse_exact_call_count();
    writer.prepare_block_with_spent_scripts(caps, 1, first.hash, &first.body, &NoCoins)?;
    let first_parses = parse_exact_call_count().saturating_sub(before);
    assert!(
        first_parses <= 1,
        "fallback parses a body at most once, got {first_parses} parses at height 1"
    );

    let before = parse_exact_call_count();
    writer.prepare_block_with_spent_scripts(
        caps,
        2,
        second.hash,
        &second.body,
        &FirstCoinbase { txid: cb1_txid },
    )?;
    let second_parses = parse_exact_call_count().saturating_sub(before);
    assert!(
        second_parses <= 1,
        "fallback parses a body at most once, got {second_parses} parses at height 2"
    );

    let facts_one = CommittedBlock {
        height: 1,
        hash: first.hash,
        parent_hash: [0; 32],
        header: first.header,
        txs: vec![tx_facts(
            cb1_txid,
            BODY_OFFSET,
            cb1.len(),
            Vec::new(),
            vec![created(0, COINBASE_VALUE, &OP_TRUE)],
        )],
    };
    let facts_two = CommittedBlock {
        height: 2,
        hash: second.hash,
        parent_hash: first.hash,
        header: second.header,
        txs: vec![
            tx_facts(
                cb2_txid,
                BODY_OFFSET,
                cb2.len(),
                Vec::new(),
                vec![created(0, COINBASE_VALUE, &OP_TRUE)],
            ),
            tx_facts(
                spend_txid,
                BODY_OFFSET + cb2.len(),
                spend.len(),
                vec![SpentPrevout {
                    txid: cb1_txid,
                    vout: 0,
                    value: COINBASE_VALUE,
                    script: Bytes::copy_from_slice(&OP_TRUE),
                    height: 1,
                    coinbase: true,
                }],
                vec![created(0, CHILD_VALUE, &P2WPKH)],
            ),
        ],
    };

    reset_parse_exact_call_count();
    writer.prepare_block_from_facts(caps, facts_one)?;
    writer.prepare_block_from_facts(caps, facts_two)?;
    let live_parses = parse_exact_call_count();
    assert_eq!(
        live_parses, 0,
        "the committed-facts path must not parse a block"
    );
    Ok(())
}
