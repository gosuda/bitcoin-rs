//! Little-endian key-order vs numeric-height-order contract tests.
//!
//! The 4-byte height suffix in `HashPrefixRow` is little-endian, so
//! lexicographic key-byte order does **not** match numeric height order
//! within one 8-byte prefix. Height 256 (`00 01 00 00`) sorts before
//! height 1 (`01 00 00 00`) in byte order.
//!
//! These tests pin two contracts:
//!
mod common;

use std::sync::Arc;

use bitcoin_rs_index::{BlockSource, Indexer, ScriptHash};
use bitcoin_rs_primitives::{
    Block, BlockHash, Hash256, Header, OutPoint, Tx, TxIn, TxOut, Txid, consensus_bytes,
};

use common::MemoryStore;

/// A block source backed by a simple map, serving multiple heights.
struct MultiHeightSource {
    blocks: hashbrown::HashMap<u32, Block>,
}

impl BlockSource for MultiHeightSource {
    fn block_at_height(&self, height: u32) -> Option<Block> {
        self.blocks.get(&height).cloned()
    }
}

fn header() -> Header {
    Header {
        version: 1,
        prev_blockhash: BlockHash::default(),
        merkle_root: Hash256::default(),
        time: 0,
        bits: 0,
        nonce: 0,
    }
}

fn tx_with_script(previous_output: OutPoint, script_pubkey: Vec<u8>) -> Tx {
    Tx {
        version: 2,
        lock_time: 0,
        inputs: vec![TxIn {
            previous_output,
            script_sig: Vec::new(),
            sequence: u32::MAX,
            witness: Vec::new(),
        }],
        outputs: vec![TxOut {
            value: 5_000,
            script_pubkey,
        }],
    }
}

fn spent_outpoint(label: u8, vout: u32) -> OutPoint {
    OutPoint::new(Txid(Hash256::from_le_bytes(&[label; 32])), vout)
}

/// Two funding rows with the same 8-byte prefix at heights 1 and 256 do NOT
/// iterate in numeric order under LE keys, but `resolve_script_history` DOES
/// sort by numeric height.
#[test]
fn le_key_order_differs_from_numeric_and_history_sorts_by_height() {
    let script = vec![0x51, 0x01];
    let scripthash = ScriptHash::from_script_bytes(&script);
    let mut indexer = Indexer::new(Arc::new(MemoryStore::default()));

    // Ingest a block at height 1 funding the script, then a block at height 256
    // funding the same script. Both produce a funding row with the same 8-byte
    // prefix; only the height suffix differs.
    let block_at_1 = Block {
        header: header(),
        txs: vec![tx_with_script(spent_outpoint(1, 0), script.clone())],
    };
    let block_at_256 = Block {
        header: header(),
        txs: vec![tx_with_script(spent_outpoint(2, 0), script)],
    };

    let Ok(_) = indexer.ingest_block(&consensus_bytes(&block_at_1), 1) else {
        panic!("ingest height 1");
    };
    let Ok(_) = indexer.ingest_block(&consensus_bytes(&block_at_256), 256) else {
        panic!("ingest height 256");
    };

    // --- Part A: iter_funding_rows returns LE byte order, not numeric ---

    let Ok(rows) = indexer.iter_funding_rows(scripthash) else {
        panic!("iter_funding_rows");
    };
    assert_eq!(rows.len(), 2, "two heights funded the same script");

    // Height 256 is [0x00, 0x01, 0x00, 0x00]; height 1 is [0x01, 0x00, 0x00, 0x00].
    // LE byte order puts 256 before 1.
    assert_eq!(
        rows[0].height(),
        256,
        "LE byte order puts height 256 before height 1, not numeric order"
    );
    assert_eq!(rows[1].height(), 1);

    // The corollary: numeric sort produces the opposite order.
    let mut numeric = rows.clone();
    numeric.sort_by_key(|row| row.height());
    assert_eq!(
        numeric.iter().map(|row| row.height()).collect::<Vec<_>>(),
        vec![1, 256]
    );
    assert_ne!(
        rows, numeric,
        "store iteration order must differ from numeric height order"
    );

    // --- Part B: resolve_script_history sorts by numeric height ---

    // Compute the txids before moving the blocks into the source map.
    let txid_at_1 = block_at_1.txs[0].txid();
    let txid_at_256 = block_at_256.txs[0].txid();
    let source = MultiHeightSource {
        blocks: [(1, block_at_1), (256, block_at_256)].into_iter().collect(),
    };
    let Ok(entries) = indexer.resolve_script_history(scripthash, &source) else {
        panic!("resolve_script_history");
    };

    assert_eq!(entries.len(), 2, "two confirmed entries");
    // Entries must be in numeric height order: 1 before 256, even though
    // the underlying KV iteration returns 256 before 1.
    assert_eq!(
        entries.iter().map(|e| e.height).collect::<Vec<_>>(),
        vec![1, 256],
        "resolve_script_history must sort by numeric height, not LE byte order"
    );

    // The first entry's txid must come from the height-1 block.
    assert_eq!(entries[0].txid, txid_at_1);
    assert_eq!(entries[1].txid, txid_at_256);
}

/// The scan reference resolver also sorts by numeric height, agreeing with
/// the fast resolver.
#[test]
fn history_scan_resolver_also_sorts_by_height() {
    let script = vec![0x51, 0x02];
    let scripthash = ScriptHash::from_script_bytes(&script);
    let mut indexer = Indexer::new(Arc::new(MemoryStore::default()));

    let block_at_1 = Block {
        header: header(),
        txs: vec![tx_with_script(spent_outpoint(3, 0), script.clone())],
    };
    let block_at_256 = Block {
        header: header(),
        txs: vec![tx_with_script(spent_outpoint(4, 0), script)],
    };

    let Ok(_) = indexer.ingest_block(&consensus_bytes(&block_at_1), 1) else {
        panic!("ingest height 1");
    };
    let Ok(_) = indexer.ingest_block(&consensus_bytes(&block_at_256), 256) else {
        panic!("ingest height 256");
    };

    let source = MultiHeightSource {
        blocks: [(1, block_at_1), (256, block_at_256)].into_iter().collect(),
    };

    let Ok(fast) = indexer.resolve_script_history(scripthash, &source) else {
        panic!("fast resolver");
    };
    let Ok(scan) = indexer.resolve_script_history_scan(scripthash, &source) else {
        panic!("scan resolver");
    };

    assert_eq!(fast, scan, "fast and scan resolvers must agree on order");
    assert_eq!(
        fast.iter().map(|e| e.height).collect::<Vec<_>>(),
        vec![1, 256],
        "both resolvers sort by numeric height"
    );
}

/// `resolve_unspent_outputs_with_height` also sorts by numeric height.
#[test]
fn unspent_outputs_with_height_sorts_by_numeric_height() {
    let script = vec![0x51, 0x03];
    let scripthash = ScriptHash::from_script_bytes(&script);
    let mut indexer = Indexer::new(Arc::new(MemoryStore::default()));

    let block_at_1 = Block {
        header: header(),
        txs: vec![tx_with_script(spent_outpoint(5, 0), script.clone())],
    };
    let block_at_256 = Block {
        header: header(),
        txs: vec![tx_with_script(spent_outpoint(6, 0), script)],
    };

    let Ok(_) = indexer.ingest_block(&consensus_bytes(&block_at_1), 1) else {
        panic!("ingest height 1");
    };
    let Ok(_) = indexer.ingest_block(&consensus_bytes(&block_at_256), 256) else {
        panic!("ingest height 256");
    };

    let source = MultiHeightSource {
        blocks: [(1, block_at_1), (256, block_at_256)].into_iter().collect(),
    };

    let Ok(outputs) = indexer.resolve_unspent_outputs_with_height(scripthash, &source) else {
        panic!("resolve_unspent_outputs_with_height");
    };

    assert_eq!(outputs.len(), 2);
    assert_eq!(
        outputs.iter().map(|(_, _, _, h)| *h).collect::<Vec<_>>(),
        vec![1, 256],
        "unspent outputs must be sorted by numeric height"
    );
}

/// Spending rows share the same LE height-order caveat as funding rows.
/// This test confirms the on-disk key for spending rows also uses LE height,
/// so `iter_spending_rows` returns LE byte order, not numeric.
#[test]
fn spending_rows_also_use_le_height_order() {
    let script = vec![0x51, 0x04];
    let outpoint = spent_outpoint(7, 0);

    // Block at height 1 spends the outpoint; block at height 256 also spends
    // it (different block, same prevout — unrealistic on a real chain but
    // sufficient to create two spending rows with the same prefix).
    let block_at_1 = Block {
        header: header(),
        txs: vec![tx_with_script(outpoint, script.clone())],
    };
    let block_at_256 = Block {
        header: header(),
        txs: vec![tx_with_script(outpoint, script)],
    };

    let mut indexer = Indexer::new(Arc::new(MemoryStore::default()));
    let Ok(_) = indexer.ingest_block(&consensus_bytes(&block_at_1), 1) else {
        panic!("ingest height 1");
    };
    let Ok(_) = indexer.ingest_block(&consensus_bytes(&block_at_256), 256) else {
        panic!("ingest height 256");
    };

    let Ok(rows) = indexer.iter_spending_rows(&outpoint) else {
        panic!("iter_spending_rows");
    };
    assert_eq!(rows.len(), 2, "two spending rows at two heights");

    // LE byte order: 256 before 1.
    assert_eq!(rows[0].height(), 256);
    assert_eq!(rows[1].height(), 1);
}
