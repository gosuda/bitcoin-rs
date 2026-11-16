//! BIP30 rollback: a block whose coinbase repeats an earlier unspent coinbase
//! overwrites that coin's ScriptLive row, because both coins share one key.
//! Disconnecting the later block restores the earlier coin in the chainstate,
//! so rolling the later block back must leave exactly that coin's row, at the
//! earlier height.

use std::sync::Arc;

use bitcoin_rs_consensus::primitives::encode::double_sha256;
use bitcoin_rs_projection::types::ScriptLiveCoin;
use bitcoin_rs_projection::{
    ConsumerCursorUpdate, IndexCapabilities, IndexWatermark, IndexWriter, PreparedBatch,
    PreparedBatchLimits, SpentCoin, SpentCoins,
};
use bitcoin_rs_storage::{ColumnFamily, KvStore};

use crate::support::TestError;
use crate::support::common::MemoryStore;

const COINBASE_VALUE: u64 = 50 * 100_000_000;
const OP_TRUE: [u8; 1] = [0x51];

struct NoCoins;

impl SpentCoins for NoCoins {
    fn spent_coin(&self, _txid: &[u8; 32], _vout: u32) -> Option<SpentCoin<'_>> {
        None
    }
}

/// The chainstate view while the later block is disconnected: the coin that
/// the duplicate overwrote comes back at its original height and value.
struct RestoredCoin;

impl SpentCoins for RestoredCoin {
    fn spent_coin(&self, _txid: &[u8; 32], _vout: u32) -> Option<SpentCoin<'_>> {
        Some(SpentCoin {
            script: &OP_TRUE,
            value: COINBASE_VALUE,
            height: 1,
            coinbase: true,
        })
    }
}

fn coinbase(script_sig: Vec<u8>) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&1_i32.to_le_bytes());
    out.push(1);
    out.extend_from_slice(&[0; 32]);
    out.extend_from_slice(&u32::MAX.to_le_bytes());
    out.push(u8::try_from(script_sig.len()).unwrap_or(u8::MAX));
    out.extend_from_slice(&script_sig);
    out.extend_from_slice(&u32::MAX.to_le_bytes());
    out.push(1);
    out.extend_from_slice(&COINBASE_VALUE.to_le_bytes());
    out.push(u8::try_from(OP_TRUE.len()).unwrap_or(u8::MAX));
    out.extend_from_slice(&OP_TRUE);
    out.extend_from_slice(&0_u32.to_le_bytes());
    out
}

struct Block {
    body: Vec<u8>,
    hash: [u8; 32],
}

fn block(prev: [u8; 32], height: u32, tx: &[u8]) -> Block {
    let mut header = [0_u8; 80];
    header[..4].copy_from_slice(&1_i32.to_le_bytes());
    header[4..36].copy_from_slice(&prev);
    header[68..72].copy_from_slice(&height.to_le_bytes());
    header[72..76].copy_from_slice(&0x207f_ffff_u32.to_le_bytes());
    header[76..80].copy_from_slice(&height.to_le_bytes());
    let hash = double_sha256(&header).to_le_bytes();
    let mut body = header.to_vec();
    body.push(1);
    body.extend_from_slice(tx);
    Block { body, hash }
}

fn live_rows_for_outpoint(store: &MemoryStore, txid: &[u8; 32]) -> Result<Vec<Vec<u8>>, TestError> {
    let mut suffix = txid.to_vec();
    suffix.extend_from_slice(&[0, 0, 0]);
    let mut values = Vec::new();
    for item in store.iter_prefix(ColumnFamily::ScriptLive, &[])? {
        let (key, value) = item?;
        if key.ends_with(&suffix) {
            values.push(value);
        }
    }
    Ok(values)
}

// IDX-06
#[test]
fn rolling_back_a_bip30_duplicate_restores_the_earlier_coin_row() -> Result<(), TestError> {
    let store = Arc::new(MemoryStore::default());
    let mut writer = IndexWriter::open(Arc::clone(&store), 1)?;
    let caps = IndexCapabilities::ALL;

    let genesis_tx = coinbase(vec![0x00, 0x00]);
    let duplicated_tx = coinbase(vec![0x01, 0x01]);
    let duplicated_txid = double_sha256(&duplicated_tx).to_le_bytes();

    let b0 = block([0; 32], 0, &genesis_tx);
    let b1 = block(b0.hash, 1, &duplicated_tx);
    let b2 = block(b1.hash, 2, &duplicated_tx);

    for (height, hash, body) in [
        (0, b0.hash, &b0.body),
        (1, b1.hash, &b1.body),
        (2, b2.hash, &b2.body),
    ] {
        let prepared =
            writer.prepare_block_with_spent_scripts(caps, height, hash, body, &NoCoins)?;
        let mut batch = PreparedBatch::new(PreparedBatchLimits {
            max_rows: usize::MAX,
            max_bytes: usize::MAX,
        });
        assert!(batch.try_push(prepared).is_ok());
        writer.commit_forward(batch)?;
    }
    assert_eq!(
        live_rows_for_outpoint(&store, &duplicated_txid)?.len(),
        1,
        "the duplicate overwrites the earlier coin's row while both blocks are connected"
    );

    let fence = writer.fenced_watermarks()?.0;
    writer.commit_rollback_one_for_with_cursor_with_spent_scripts(
        fence,
        caps,
        Some(IndexWatermark {
            height: 1,
            hash: b1.hash,
        }),
        &b2.body,
        ConsumerCursorUpdate::Keep,
        &RestoredCoin,
    )?;

    let rows = live_rows_for_outpoint(&store, &duplicated_txid)?;
    assert_eq!(
        rows.len(),
        1,
        "rolling back the later duplicate leaves the earlier coin's row, as the chainstate does"
    );
    let restored = ScriptLiveCoin::decode_value(&rows[0])?;
    assert_eq!(
        restored.height, 1,
        "the restored row is the earlier coin, created at height 1"
    );
    Ok(())
}
