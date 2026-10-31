//! Tests for the persisted transaction-position row values.
#![allow(clippy::expect_used)]

use crate::support::common;

use std::sync::Arc;

use bitcoin_rs_index::types::{TX_POSITION_SIZE, TxPosition, TxPositionValue, U24_MAX};
use bitcoin_rs_index::{
    IndexCapabilities, IndexWriter, PreparedBatch, PreparedBatchLimits, ScriptHash,
    SpentCoinScripts,
};
use bitcoin_rs_primitives::{
    Amount, Block, BlockHash, CompactTarget, Hash256, Header, LockTime, OutPoint, Script, Sequence,
    Tx, TxIn, TxOut, Txid, Witness, consensus_bytes, deserialize,
};
use bitcoin_rs_storage::{ColumnFamily, KvStore};
use proptest::prelude::*;

use common::MemoryStore;

/// Answers every spent outpoint, so the v6 history rows prepare without a
/// real UTXO set.
struct FixtureScripts;

static FIXTURE_SPENT_SCRIPT: [u8; 2] = [0x51, 0x01];

impl SpentCoinScripts for FixtureScripts {
    fn script_bytes(&self, _txid: &[u8; 32], _vout: u32) -> Option<&[u8]> {
        Some(FIXTURE_SPENT_SCRIPT.as_slice())
    }
}

fn commit_block(store: &Arc<MemoryStore>, height: u32, body: &[u8]) {
    let mut writer = IndexWriter::open(Arc::clone(store), 1).expect("open");
    let header = body.get(..80).expect("header present");
    let hash = bitcoin_rs_primitives::encode::double_sha256(header).to_le_bytes();
    let prepared = writer
        .prepare_block_with_spent_scripts(
            IndexCapabilities::HISTORICAL,
            height,
            hash,
            body,
            &FixtureScripts,
        )
        .expect("prepare");
    let mut batch = PreparedBatch::new(PreparedBatchLimits {
        max_rows: usize::MAX,
        max_bytes: usize::MAX,
    });
    assert!(batch.try_push(prepared).is_ok(), "one block is admitted");
    writer.commit_forward(batch).expect("commit");
}

fn header() -> Header {
    Header {
        version: 1,
        prev_blockhash: BlockHash::default(),
        merkle_root: Hash256::default(),
        time: 7,
        bits: CompactTarget::from_consensus(0),
        nonce: 42,
    }
}

fn script(tag: u8) -> Vec<u8> {
    let mut bytes = vec![0x00, 0x14];
    bytes.extend_from_slice(&[tag; 20]);
    bytes
}

fn tx_legacy(seed: u8, outputs: Vec<TxOut>) -> Tx {
    tx_with_witness(seed, outputs, Vec::new().into())
}

fn tx_witness(seed: u8, outputs: Vec<TxOut>) -> Tx {
    tx_with_witness(seed, outputs, vec![vec![0xab; 71], vec![0xcd; 33]].into())
}

fn tx_with_witness(seed: u8, outputs: Vec<TxOut>, witness: Witness) -> Tx {
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
            witness,
        }],
        outputs,
    }
}

fn out(script_pubkey: Vec<u8>, sats: u64) -> TxOut {
    TxOut {
        value: Amount::from_sat(sats),
        script_pubkey: script_pubkey.into(),
    }
}

fn mixed_block() -> Block {
    Block {
        header: header(),
        txs: vec![
            tx_legacy(1, vec![out(script(0x11), 1_000)]),
            tx_witness(2, vec![out(script(0x22), 2_000), out(script(0x11), 3_000)]),
            tx_witness(3, vec![out(script(0x33), 4_000)]),
            tx_legacy(4, vec![out(script(0x44), 5_000), out(vec![0x6a, 0x01], 0)]),
        ],
    }
}

fn rows_with_values(store: &MemoryStore, cf: ColumnFamily) -> Vec<(Vec<u8>, Vec<u8>)> {
    store
        .iter_prefix(cf, &[])
        .expect("iterate")
        .map(|entry| entry.expect("row"))
        .collect()
}

#[test]

fn funding_positions_address_the_transactions_that_funded_the_script() {
    let block = mixed_block();
    let bytes = consensus_bytes(&block);

    let store = Arc::new(MemoryStore::default());
    commit_block(&store, 0, &bytes);

    let target = ScriptHash::from_script_bytes(&script(0x11));

    let rows = rows_with_values(&store, ColumnFamily::Funding);
    let (_key, value) = rows
        .iter()
        .find(|(key, _)| key.starts_with(&target.prefix()))
        .expect("funding row for the target script");

    let occurrences = bitcoin_rs_index::types::ScriptHistoryOccurrence::decode_all(value)
        .expect("row value decodes");
    let funded: Vec<_> = occurrences
        .iter()
        .filter(|occurrence| {
            occurrence.flags & bitcoin_rs_index::types::ScriptHistoryOccurrence::FUNDING != 0
        })
        .collect();
    assert_eq!(funded.len(), 2, "two transactions funded this script");

    for occurrence in funded {
        let position = occurrence.position;
        let start = usize::try_from(position.offset()).expect("offset fits usize");
        let end = usize::try_from(position.end().expect("end fits u32")).expect("end fits usize");
        let decoded: Tx =
            deserialize(&bytes[start..end]).expect("position slices a whole transaction");
        assert_eq!(decoded.txid().as_bytes(), &occurrence.txid);
        assert!(
            decoded
                .outputs
                .iter()
                .any(|o| ScriptHash::from_script_bytes(&o.script_pubkey) == target),
            "position must address a transaction that funded the script"
        );
    }
}

#[test]
fn txid_positions_address_their_own_transaction() {
    let block = mixed_block();
    let bytes = consensus_bytes(&block);

    let store = Arc::new(MemoryStore::default());
    commit_block(&store, 0, &bytes);

    let rows = rows_with_values(&store, ColumnFamily::TxConfirmed);
    assert_eq!(rows.len(), block.txs.len());

    for (_key, value) in &rows {
        let positions = TxPositionValue::decode(value).expect("row value decodes");
        for position in positions {
            let start = usize::try_from(position.offset()).expect("offset fits usize");
            let end =
                usize::try_from(position.end().expect("end fits u32")).expect("end fits usize");
            let decoded: Tx =
                deserialize(&bytes[start..end]).expect("position slices a whole transaction");
            assert!(
                block.txs.contains(&decoded),
                "position must address a transaction of this block"
            );
        }
    }
}

#[test]
fn a_partial_position_decodes_to_none() {
    let value = TxPositionValue::encode(&[TxPosition::new(100, 200), TxPosition::new(300, 400)]);
    for truncated in 1..value.len() {
        if truncated % TX_POSITION_SIZE == 0 {
            continue;
        }
        assert!(
            TxPositionValue::decode(&value[..truncated]).is_none(),
            "a {truncated}-byte value must not decode"
        );
    }
}

proptest! {
    #[test]
    fn position_values_round_trip(
        raw in proptest::collection::vec((0..=U24_MAX, 0..=U24_MAX), 1..32),
    ) {
        let positions = raw
            .iter()
            .map(|(offset, len)| TxPosition::new(*offset, *len))
            .collect::<Vec<_>>();
        let encoded = TxPositionValue::encode(&positions);
        let decoded = TxPositionValue::decode(&encoded).expect("decodes");
        prop_assert_eq!(decoded, positions.as_slice());
    }


}
