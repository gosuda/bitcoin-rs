//! Exact resolution of a lossy eight-byte funding-row prefix.
#![allow(clippy::expect_used)]

#[path = "support/common.rs"]
mod common;

use std::sync::Arc;

use bitcoin_rs_index::types::TxPosition;
use bitcoin_rs_index::{BlockSource, IndexWriter, Indexer, ScriptHash, ScriptHistoryEntry};
use bitcoin_rs_primitives::{
    Amount, Block, BlockHash, CompactTarget, Hash256, Header, LockTime, OutPoint, Script, Sequence,
    Tx, TxIn, TxOut, Witness, consensus_bytes, varint,
};
use bitcoin_rs_storage::{ColumnFamily, KvStore as _};

use common::{MemoryStore, NoSpentScripts};

const HEIGHT: u32 = 0;

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

fn tx(_seed: u8, script_pubkey: Vec<u8>, value: u64) -> Tx {
    Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output: OutPoint::null(),
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
fn synthetic_history_row_filters_full_script_identity() -> Result<(), Box<dyn std::error::Error>> {
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
    let store = Arc::new(MemoryStore::default());
    IndexWriter::open(Arc::clone(&store), 1)?.commit_block(0, &bytes, &NoSpentScripts)?;
    let indexer = Indexer::new(Arc::clone(&store));

    // Inject two full-script identities into one row to isolate read-side
    // exact-hash filtering. These scripts do not share an eight-byte prefix;
    // this is not evidence of a real hash collision or writer grouping.
    // Both positions still name exact transaction ranges in the fixture body.
    let row = store
        .rows(ColumnFamily::Funding)
        .into_iter()
        .find(|(key, _)| key.starts_with(&target.prefix()))
        .expect("target funding row")
        .0;
    let mut collision_value = Vec::new();
    for (script, tx, position) in [
        (&target_script, &block.txs[0], target_position),
        (&script(0x52), &block.txs[1], decoy_position),
    ] {
        collision_value.extend_from_slice(&ScriptHash::from_script_bytes(script).to_byte_array());
        collision_value.extend_from_slice(tx.txid().as_bytes());
        collision_value.extend_from_slice(zerocopy::IntoBytes::as_bytes(&position));
        collision_value.push(1);
    }
    let mut batch = store.new_batch();
    batch.put(ColumnFamily::Funding, &row, &collision_value);
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
