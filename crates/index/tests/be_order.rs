//! Big-endian key-order vs numeric-height-order contract tests.
//!
//! The 4-byte height suffix in `HashPrefixRow` is big-endian (format 5), so
//! lexicographic key-byte order matches numeric height order within one
//! 8-byte prefix. Height 1 (`00 00 00 01`) sorts before height 256
//! (`00 00 01 00`) in byte order.
//!
//! These tests pin two contracts:
//!
mod common;

use std::sync::Arc;

use bitcoin_rs_index::types::TxPosition;
use bitcoin_rs_index::{BlockSource, IndexError, Indexer, ScriptHash, ScriptHistoryEntry};
use bitcoin_rs_primitives::{
    Amount, Block, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid, Witness,
    consensus_bytes, varint,
};
use bitcoin_rs_storage::InMemoryKvStore;

use common::{header, put_funding_row, put_funding_row_positions, put_spending_row};

/// A block source backed by a simple map, serving multiple heights.
struct MultiHeightSource {
    blocks: hashbrown::HashMap<u32, Block>,
    /// Optional override for the sliced-read channel. When a height has an
    /// entry, `block_bytes_at_height` serves these bytes instead of the
    /// `blocks` encoding — a test can then distinguish the positioned path
    /// (sliced reads) from the scan fallback (whole blocks).
    byte_blocks: hashbrown::HashMap<u32, Vec<u8>>,
}

impl BlockSource for MultiHeightSource {
    fn block_at_height(&self, height: u32) -> Option<Block> {
        self.blocks.get(&height).cloned()
    }

    fn block_bytes_at_height(&self, height: u32, offset: u32, len: u32) -> Option<Vec<u8>> {
        let start = usize::try_from(offset).ok()?;
        let end = start.checked_add(usize::try_from(len).ok()?)?;
        if let Some(bytes) = self.byte_blocks.get(&height) {
            return bytes.get(start..end).map(<[u8]>::to_vec);
        }
        let block = self.block_at_height(height)?;
        let bytes = consensus_bytes(&block);
        bytes.get(start..end).map(<[u8]>::to_vec)
    }
}

/// Independent full-scan oracle for `resolve_script_history`.
///
/// Decodes every candidate block and hashes every output script rather than
/// trusting row-carried transaction positions, so a regression in positioned
/// row encoding or range resolution cannot pass a comparison built from the
/// same `TxPosition` representation.
fn scan_script_history<B: BlockSource>(
    indexer: &Indexer<InMemoryKvStore>,
    scripthash: ScriptHash,
    source: &B,
) -> Result<Vec<ScriptHistoryEntry>, IndexError> {
    let mut entries = Vec::new();
    let mut last_height: Option<u32> = None;
    let mut cached_block: Option<Block> = None;
    for row in indexer.iter_funding_rows(scripthash)? {
        let height = row.height();
        if last_height != Some(height) {
            cached_block = source.block_at_height(height);
            last_height = Some(height);
        }
        let Some(block) = cached_block.as_ref() else {
            continue;
        };
        for tx in &block.txs {
            if tx
                .outputs
                .iter()
                .any(|output| ScriptHash::from_script_bytes(&output.script_pubkey) == scripthash)
            {
                entries.push(ScriptHistoryEntry::confirmed(tx.txid(), height));
            }
        }
    }
    entries.sort_by_key(|entry| entry.height);
    Ok(entries)
}

fn tx_with_script(previous_output: OutPoint, script_pubkey: Vec<u8>) -> Tx {
    Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: vec![TxIn {
            previous_output,
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(5_000),
            script_pubkey: script_pubkey.into(),
        }],
    }
}

fn spent_outpoint(label: u8, vout: u32) -> OutPoint {
    OutPoint::new(Txid(Hash256::from_le_bytes(&[label; 32])), vout)
}

/// Two funding rows with the same 8-byte prefix at heights 1 and 256 iterate
/// in numeric order under BE keys, and `resolve_script_history` sorts by
/// numeric height.
#[test]
fn be_key_order_matches_numeric_and_history_sorts_by_height()
-> Result<(), Box<dyn std::error::Error>> {
    let script = vec![0x51, 0x01];
    let scripthash = ScriptHash::from_script_bytes(&script);
    let store = Arc::new(InMemoryKvStore::default());
    put_funding_row(&store, scripthash, 1)?;
    put_funding_row(&store, scripthash, 256)?;
    let indexer = Indexer::new(store);

    // Direct keys at heights 1 and 256: both produce a funding row with the
    // same 8-byte prefix; only the height suffix differs. `commit_block`
    // cannot write a gapped height, so these tests own the keys themselves.
    let block_at_1 = Block {
        header: header(),
        txs: vec![tx_with_script(spent_outpoint(1, 0), script.clone())],
    };
    let block_at_256 = Block {
        header: header(),
        txs: vec![tx_with_script(spent_outpoint(2, 0), script)],
    };

    // --- Part A: iter_funding_rows returns BE byte order, hence numeric ---

    let rows = indexer.iter_funding_rows(scripthash)?;
    assert_eq!(rows.len(), 2, "two heights funded the same script");

    // Height 1 is [0x00, 0x00, 0x00, 0x01]; height 256 is
    // [0x00, 0x00, 0x01, 0x00]. BE byte order puts 1 before 256.
    assert_eq!(
        rows.iter().map(|row| row.height()).collect::<Vec<_>>(),
        vec![1, 256],
        "BE byte order matches numeric height order"
    );

    // --- Part B: resolve_script_history sorts by numeric height ---

    // Compute the txids before moving the blocks into the source map.
    let txid_at_1 = block_at_1.txs[0].txid();
    let txid_at_256 = block_at_256.txs[0].txid();
    let source = MultiHeightSource {
        blocks: [(1, block_at_1), (256, block_at_256)].into_iter().collect(),
        byte_blocks: hashbrown::HashMap::new(),
    };
    let entries = indexer.resolve_script_history(scripthash, &source)?;

    assert_eq!(entries.len(), 2, "two confirmed entries");
    // Entries must be in numeric height order: 1 before 256, matching the
    // underlying KV iteration order.
    assert_eq!(
        entries.iter().map(|e| e.height).collect::<Vec<_>>(),
        vec![1, 256],
        "resolve_script_history must sort by numeric height, matching BE iteration order"
    );

    // The first entry's txid must come from the height-1 block.
    assert_eq!(entries[0].txid, txid_at_1);
    assert_eq!(entries[1].txid, txid_at_256);
    Ok(())
}

/// `resolve_unspent_outputs_with_height` also sorts by numeric height.
#[test]
fn unspent_outputs_with_height_sorts_by_numeric_height() -> Result<(), Box<dyn std::error::Error>> {
    let script = vec![0x51, 0x03];
    let scripthash = ScriptHash::from_script_bytes(&script);
    let store = Arc::new(InMemoryKvStore::default());
    put_funding_row(&store, scripthash, 1)?;
    put_funding_row(&store, scripthash, 256)?;
    let indexer = Indexer::new(store);

    let block_at_1 = Block {
        header: header(),
        txs: vec![tx_with_script(spent_outpoint(5, 0), script.clone())],
    };
    let block_at_256 = Block {
        header: header(),
        txs: vec![tx_with_script(spent_outpoint(6, 0), script)],
    };

    let source = MultiHeightSource {
        blocks: [(1, block_at_1), (256, block_at_256)].into_iter().collect(),
        byte_blocks: hashbrown::HashMap::new(),
    };

    let outputs = indexer.resolve_unspent_outputs_with_height(scripthash, &source)?;

    assert_eq!(outputs.len(), 2);
    assert_eq!(
        outputs.iter().map(|(_, _, _, h)| *h).collect::<Vec<_>>(),
        vec![1, 256],
        "unspent outputs must be sorted by numeric height"
    );
    Ok(())
}

/// Spending rows share the same BE height order as funding rows.
/// The positioned resolver reads through `block_bytes_at_height`, which here
/// serves a different transaction per height than the whole-block channel
/// feeding the oracle and the scan fallback — so the positioned path is
/// load-bearing: a silent fallback surfaces the oracle's txids and fails.
#[test]
fn history_scan_oracle_agrees_with_positioned_resolver() -> Result<(), Box<dyn std::error::Error>> {
    let script = vec![0x51, 0x02];
    let scripthash = ScriptHash::from_script_bytes(&script);
    let store = Arc::new(InMemoryKvStore::default());

    // Whole-block channel: scanned by the oracle and by the fallback.
    let scan_block_at_1 = Block {
        header: header(),
        txs: vec![tx_with_script(spent_outpoint(3, 0), script.clone())],
    };
    let scan_block_at_256 = Block {
        header: header(),
        txs: vec![tx_with_script(spent_outpoint(4, 0), script.clone())],
    };
    // Sliced-read channel: different transactions funding the same script.
    let byte_block_at_1 = Block {
        header: header(),
        txs: vec![tx_with_script(spent_outpoint(8, 0), script.clone())],
    };
    let byte_block_at_256 = Block {
        header: header(),
        txs: vec![tx_with_script(spent_outpoint(9, 0), script)],
    };

    // Rows carry each byte block's single transaction position — offset
    // past the 80-byte header and the compact-size count — so
    // `resolve_script_history` takes its sliced-read path rather than the
    // scan fallback.
    for (height, block) in [(1_u32, &byte_block_at_1), (256, &byte_block_at_256)] {
        let offset = 80_usize + varint::encode(u64::try_from(block.txs.len())?).len();
        let position = TxPosition::new(
            u32::try_from(offset)?,
            u32::try_from(block.txs[0].total_size())?,
        );
        put_funding_row_positions(&store, scripthash, height, &[position])?;
    }
    let indexer = Indexer::new(store);

    let positioned_txid_at_1 = byte_block_at_1.txs[0].txid();
    let positioned_txid_at_256 = byte_block_at_256.txs[0].txid();
    let source = MultiHeightSource {
        blocks: [(1, scan_block_at_1), (256, scan_block_at_256)]
            .into_iter()
            .collect(),
        byte_blocks: [
            (1, consensus_bytes(&byte_block_at_1)),
            (256, consensus_bytes(&byte_block_at_256)),
        ]
        .into_iter()
        .collect(),
    };

    let fast = indexer.resolve_script_history(scripthash, &source)?;
    let scan = scan_script_history(&indexer, scripthash, &source)?;

    assert_eq!(
        fast.iter().map(|e| e.height).collect::<Vec<_>>(),
        vec![1, 256],
        "the positioned resolver sorts by numeric height"
    );
    assert_eq!(
        scan.iter().map(|e| e.height).collect::<Vec<_>>(),
        vec![1, 256],
        "the scan oracle sorts by numeric height"
    );
    // The sliced read must surface the byte-served transactions; equal
    // txids between `fast` and `scan` mean the resolver silently fell back
    // to the whole-block channel.
    assert_eq!(
        fast.iter().map(|e| e.txid).collect::<Vec<_>>(),
        vec![positioned_txid_at_1, positioned_txid_at_256],
        "the positioned resolver must return the byte-served txids"
    );
    assert_ne!(
        fast, scan,
        "channels serve different transactions, so fast == scan would mean \
         the positioned path silently fell back to a scan"
    );
    Ok(())
}

/// This test confirms the on-disk key for spending rows also uses BE height,
/// so `iter_spending_rows` returns numeric order.
#[test]
fn spending_rows_also_use_numeric_height_order() -> Result<(), Box<dyn std::error::Error>> {
    let outpoint = spent_outpoint(7, 0);
    let store = Arc::new(InMemoryKvStore::default());
    put_spending_row(&store, &outpoint, 1)?;
    put_spending_row(&store, &outpoint, 256)?;
    let indexer = Indexer::new(store);

    let rows = indexer.iter_spending_rows(&outpoint)?;
    assert_eq!(rows.len(), 2, "two spending rows at two heights");

    // BE byte order: 1 before 256.
    assert_eq!(
        rows.iter().map(|row| row.height()).collect::<Vec<_>>(),
        vec![1, 256]
    );
    Ok(())
}
