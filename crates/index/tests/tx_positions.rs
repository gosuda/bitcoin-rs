//! Tests for the persisted transaction-position row values.
//!
//! A position is only useful if slicing the canonical block bytes at that range
//! yields the transaction the row was written for. The row encoding is a
//! persisted-index contract; ingest implementation parity
//! is intentionally not tested here.
// A malformed fixture is a test failure; panicking reports it at the call site.
#![allow(clippy::expect_used)]

mod common;

use std::sync::Arc;

use bitcoin_rs_index::types::{TxPosition, TxPositionValue};
use bitcoin_rs_index::{Indexer, ScriptHash};
use bitcoin_rs_primitives::{
    Block, BlockHash, Hash256, Header, OutPoint, Tx, TxIn, TxOut, Txid, consensus_bytes,
    deserialize,
};
use bitcoin_rs_storage::{ColumnFamily, KvStore};
use proptest::prelude::*;

use common::MemoryStore;

const HEIGHT: u32 = 321;

fn header() -> Header {
    Header {
        version: 1,
        prev_blockhash: BlockHash::default(),
        merkle_root: Hash256::default(),
        time: 7,
        bits: 0,
        nonce: 42,
    }
}

fn script(tag: u8) -> Vec<u8> {
    let mut bytes = vec![0x00, 0x14];
    bytes.extend_from_slice(&[tag; 20]);
    bytes
}

fn tx(seed: u8, outputs: Vec<TxOut>, witness: bool) -> Tx {
    Tx {
        version: 2,
        lock_time: 0,
        inputs: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid(Hash256::from_le_bytes(&[seed; 32])),
                vout: u32::from(seed),
            },
            script_sig: Vec::new(),
            sequence: u32::MAX,
            // A segwit transaction serializes with a marker, a flag and a
            // witness. If `total_size()` and the zero-copy measurement disagree
            // anywhere, it is here.
            witness: if witness {
                vec![vec![0xab; 71], vec![0xcd; 33]]
            } else {
                Vec::new()
            },
        }],
        outputs,
    }
}

fn out(script_pubkey: Vec<u8>, sats: u64) -> TxOut {
    TxOut {
        value: sats,
        script_pubkey,
    }
}

/// A block mixing legacy and segwit transactions, several outputs each, with one
/// script funded from two different transactions.
fn mixed_block() -> Block {
    Block {
        header: header(),
        txs: vec![
            tx(1, vec![out(script(0x11), 1_000)], false),
            tx(
                2,
                vec![out(script(0x22), 2_000), out(script(0x11), 3_000)],
                true,
            ),
            tx(3, vec![out(script(0x33), 4_000)], true),
            tx(
                4,
                vec![out(script(0x44), 5_000), out(vec![0x6a, 0x01], 0)],
                false,
            ),
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
    Indexer::new(Arc::clone(&store))
        .ingest_block(&bytes, HEIGHT)
        .expect("ingest");

    // Script 0x11 is funded by transaction 0 and again by transaction 1, which
    // collapse into a single row: one key, two positions.
    let target = ScriptHash::from_script_bytes(&script(0x11));

    let rows = rows_with_values(&store, ColumnFamily::Funding);
    let (_key, value) = rows
        .iter()
        .find(|(key, _)| key.starts_with(&target.prefix()))
        .expect("funding row for the target script");

    let positions = TxPositionValue::decode(value).expect("row value decodes");
    assert_eq!(positions.len(), 2, "two transactions funded this script");

    for position in positions {
        let start = usize::try_from(position.offset()).expect("offset fits usize");
        let end = usize::try_from(position.end().expect("end fits u32")).expect("end fits usize");
        let decoded: Tx =
            deserialize(&bytes[start..end]).expect("position slices a whole transaction");
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
    Indexer::new(Arc::clone(&store))
        .ingest_block(&bytes, HEIGHT)
        .expect("ingest");

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
        if truncated % 8 == 0 {
            // Whole positions are a well-formed shorter list.
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
        raw in proptest::collection::vec((any::<u32>(), any::<u32>()), 1..32),
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
