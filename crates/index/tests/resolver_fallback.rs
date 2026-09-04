//! Exact resolution of a lossy eight-byte funding-row prefix.
#![allow(clippy::expect_used)]

mod common;

use std::sync::Arc;

use bitcoin_rs_index::types::{TxPosition, TxPositionValue};
use bitcoin_rs_index::{BlockSource, Indexer, ScriptHash, ScriptHashRow, ScriptHistoryEntry};
use bitcoin_rs_primitives::{
    Amount, Block, BlockHash, CompactTarget, Hash256, Header, LockTime, OutPoint, Script, Sequence,
    Tx, TxIn, TxOut, Txid, Witness, consensus_bytes, varint,
};
use bitcoin_rs_storage::{ColumnFamily, KvStore as _, WriteBatch as _};

use common::MemoryStore;

const HEIGHT: u32 = 100;

struct FixtureSource {
    block: Block,
}

impl BlockSource for FixtureSource {
    fn block_at_height(&self, height: u32) -> Option<Block> {
        (height == HEIGHT).then(|| self.block.clone())
    }

    fn block_bytes_at_height(&self, height: u32, offset: u32, len: u32) -> Option<Vec<u8>> {
        let block = self.block_at_height(height)?;
        let bytes = consensus_bytes(&block);
        let start = usize::try_from(offset).ok()?;
        let end = start.checked_add(usize::try_from(len).ok()?)?;
        bytes.get(start..end).map(<[u8]>::to_vec)
    }
}

fn header() -> Header {
    Header {
        version: 1,
        prev_blockhash: BlockHash::default(),
        merkle_root: Hash256::default(),
        time: 0,
        bits: CompactTarget::from_consensus(0),
        nonce: 0,
    }
}

fn tx(seed: u8, script_pubkey: Vec<u8>, value: u64) -> Tx {
    Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid(Hash256::from_le_bytes(&[seed; 32])),
                vout: u32::from(seed),
            },
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: script_pubkey.into(),
        }],
    }
}

fn script(tag: u8) -> Vec<u8> {
    vec![0x51, tag]
}

#[test]
fn eight_byte_prefix_collision_resolves_full_script_identity()
-> Result<(), Box<dyn std::error::Error>> {
    let target_script = script(0x51);
    let decoy_script = script(0x52);
    let block = Block {
        header: header(),
        txs: vec![
            tx(1, target_script.clone(), 1_000),
            tx(2, decoy_script, 2_000),
        ],
    };
    let bytes = consensus_bytes(&block);
    let first_offset = 80_usize + varint::encode(u64::try_from(block.txs.len())?).len();
    let first_len = block.txs[0].total_size();
    let target_position = TxPosition::new(u32::try_from(first_offset)?, u32::try_from(first_len)?);
    let decoy_position = TxPosition::new(
        u32::try_from(first_offset + first_len)?,
        u32::try_from(block.txs[1].total_size())?,
    );

    let target = ScriptHash::from_script_bytes(&target_script);
    let row = ScriptHashRow::row(target, HEIGHT).to_db_row();
    let store = Arc::new(MemoryStore::default());
    let mut indexer = Indexer::new(Arc::clone(&store));
    indexer.ingest_block(&bytes, HEIGHT)?;

    // A real eight-byte collision makes the writer merge both valid positions
    // under one row key. Model that persisted result directly; unlike the
    // removed fallback tests, every position is an exact range in this
    // canonical block and no row value is blank, stale, or malformed.
    let stored = store
        .get(ColumnFamily::Funding, &row)?
        .expect("target funding row");
    assert_eq!(
        TxPositionValue::decode(&stored),
        Some(core::slice::from_ref(&target_position))
    );
    let mut batch = store.new_batch();
    batch.put(
        ColumnFamily::Funding,
        &row,
        &TxPositionValue::encode(&[target_position, decoy_position]),
    );
    store.write(batch)?;

    let source = FixtureSource {
        block: block.clone(),
    };
    let entries = indexer.resolve_script_history(target, &source)?;

    assert_eq!(
        entries,
        vec![ScriptHistoryEntry::confirmed(block.txs[0].txid(), HEIGHT,)]
    );
    Ok(())
}
