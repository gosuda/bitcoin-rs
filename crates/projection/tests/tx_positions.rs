#![allow(clippy::expect_used)]

use crate::support::common;

use std::collections::BTreeSet;
use std::sync::Arc;

use bitcoin_rs_consensus::primitives::{
    Amount, Block, BlockHash, CompactTarget, Hash256, Header, LockTime, OutPoint, Script, Sequence,
    Tx, TxIn, TxOut, Txid, Witness, consensus_bytes, deserialize,
};
use bitcoin_rs_projection::types::{TX_POSITION_SIZE, TxPosition, TxPositionValue, U24_MAX};
use bitcoin_rs_projection::{
    IndexCapabilities, IndexReader, IndexWriter, Indexer, PreparedBatch, PreparedBatchLimits,
    ScriptHash, SpentCoin, SpentCoins,
};
use bitcoin_rs_storage::PrefixScanLimit;
use proptest::prelude::*;

use common::MemoryStore;

struct FixtureScripts;

static FIXTURE_SPENT_SCRIPT: [u8; 2] = [0x51, 0x01];

impl SpentCoins for FixtureScripts {
    fn spent_coin(&self, _txid: &[u8; 32], _vout: u32) -> Option<SpentCoin<'_>> {
        Some(SpentCoin {
            script: FIXTURE_SPENT_SCRIPT.as_slice(),
            value: 0,
            height: 0,
            coinbase: false,
        })
    }
}

fn commit_block(store: &Arc<MemoryStore>, height: u32, body: &[u8]) {
    let mut writer = IndexWriter::open(Arc::clone(store), 1).expect("open");
    let header = body.get(..80).expect("header present");
    let hash = bitcoin_rs_consensus::primitives::encode::double_sha256(header).to_le_bytes();
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

const SCAN_ALL: PrefixScanLimit = PrefixScanLimit {
    max_rows: 100_000,
    max_bytes: 64 << 20,
};

#[test]
fn funding_positions_address_the_transactions_that_funded_the_script() {
    let block = mixed_block();
    let bytes = consensus_bytes(&block);

    let store = Arc::new(MemoryStore::default());
    commit_block(&store, 0, &bytes);

    let target = ScriptHash::from_script_bytes(&script(0x11));

    let indexer = Indexer::new(Arc::clone(&store));
    let snapshot = indexer.snapshot().expect("snapshot");
    let scan = snapshot
        .funding_rows(target, SCAN_ALL)
        .expect("funding rows");
    assert!(scan.complete, "funding scan must not truncate");
    let occurrences: Vec<_> = scan
        .rows
        .iter()
        .flat_map(|row| {
            bitcoin_rs_projection::types::ScriptHistoryOccurrence::decode_all(&row.value)
                .expect("row value decodes")
        })
        .collect();
    let funded: Vec<_> = occurrences
        .iter()
        .filter(|occurrence| {
            occurrence.flags & bitcoin_rs_projection::types::ScriptHistoryOccurrence::FUNDING != 0
        })
        .collect();
    assert_eq!(funded.len(), 2, "two transactions funded this script");

    let mut seen = BTreeSet::new();
    for occurrence in funded {
        let position = occurrence.position;
        let start = usize::try_from(position.offset()).expect("offset fits usize");
        let end = usize::try_from(position.end().expect("end fits u32")).expect("end fits usize");
        let decoded: Tx =
            deserialize(&bytes[start..end]).expect("position slices a whole transaction");
        assert_eq!(decoded.txid().as_bytes(), &occurrence.txid);
        seen.insert(decoded.txid());
        assert!(
            decoded
                .outputs
                .iter()
                .any(|o| ScriptHash::from_script_bytes(&o.script_pubkey) == target),
            "position must address a transaction that funded the script"
        );
    }
    assert_eq!(
        seen,
        BTreeSet::from([block.txs[0].txid(), block.txs[1].txid()]),
        "funding positions must name exactly the two transactions that funded the script"
    );
}

#[test]
fn txid_positions_address_their_own_transaction() {
    let block = mixed_block();
    let bytes = consensus_bytes(&block);

    let store = Arc::new(MemoryStore::default());
    commit_block(&store, 0, &bytes);

    let indexer = Indexer::new(Arc::clone(&store));
    let snapshot = indexer.snapshot().expect("snapshot");
    let mut row_count = 0;
    for tx in &block.txs {
        let scan = snapshot
            .transaction_rows(&tx.txid(), SCAN_ALL)
            .expect("transaction rows");
        assert!(scan.complete, "transaction scan must not truncate");
        for row in &scan.rows {
            row_count += 1;
            let positions = TxPositionValue::decode(&row.value).expect("row value decodes");
            for position in positions {
                let start = usize::try_from(position.offset()).expect("offset fits usize");
                let end =
                    usize::try_from(position.end().expect("end fits u32")).expect("end fits usize");
                let decoded: Tx =
                    deserialize(&bytes[start..end]).expect("position slices a whole transaction");
                assert_eq!(
                    decoded.txid().as_bytes(),
                    tx.txid().as_bytes(),
                    "position must address the transaction whose txid the row is keyed by"
                );
            }
        }
    }
    assert_eq!(row_count, block.txs.len());
}

fn arb_u24() -> impl Strategy<Value = u32> {
    prop_oneof![
        Just(0),
        Just(1),
        Just(2),
        Just(U24_MAX - 1),
        Just(U24_MAX),
        0..=U24_MAX,
    ]
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: std::env::var("PROPTEST_CASES").ok().and_then(|v| v.parse().ok()).unwrap_or(1024),
        ..ProptestConfig::default()
    })]
    #[test]
    fn position_values_round_trip(
        raw in proptest::collection::vec((arb_u24(), arb_u24()), 1..=32),
        extra_len in 1_usize..TX_POSITION_SIZE,
        extra_bytes in proptest::collection::vec(any::<u8>(), TX_POSITION_SIZE..=TX_POSITION_SIZE * 2),
        flip_pos in any::<usize>(),
        flip_mask in 1_u8..=255,
    ) {
        let positions = raw
            .iter()
            .map(|(offset, len)| TxPosition::new(*offset, *len))
            .collect::<Vec<_>>();
        let encoded = TxPositionValue::encode(&positions);
        let decoded = TxPositionValue::decode(&encoded);
        prop_assert_eq!(decoded, Some(positions.as_slice()));

        prop_assert_eq!(TxPositionValue::decode(&[]), None);

        for truncated in 1..encoded.len() {
            if truncated % TX_POSITION_SIZE != 0 {
                prop_assert_eq!(
                    TxPositionValue::decode(&encoded[..truncated]),
                    None,
                    "truncated length {} must fail to decode",
                    truncated
                );
            }
        }

        let mut extended = encoded.clone();
        extended.extend_from_slice(&extra_bytes[..extra_len]);
        prop_assert_eq!(
            TxPositionValue::decode(&extended),
            None,
            "extended length {} must fail to decode",
            extended.len()
        );

        let flip_idx = flip_pos % encoded.len();
        let mut flipped = encoded.clone();
        flipped[flip_idx] ^= flip_mask;
        if flipped[flip_idx] != encoded[flip_idx] {
            let res = TxPositionValue::decode(&flipped);
            if let Some(other) = res {
                prop_assert_ne!(
                    other,
                    positions.as_slice(),
                    "mutated position bytes must not decode to identical positions"
                );
                prop_assert_eq!(other.len(), positions.len());
            }
        }
    }
}
