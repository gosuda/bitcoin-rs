//! Deterministic wire fixtures shared by borrowed-fact tests and benchmarks.
//! These are parse/identity workloads, not signed consensus-valid blocks.

use bitcoin_rs_consensus::block_view::BlockFacts;
use bitcoin_rs_primitives::{Block, BlockHash, Hash256, Header, OutPoint, Tx, TxIn, TxOut, Txid};

/// A zero witness modulus selects legacy transactions; otherwise the last
/// transaction in each modulus-sized group carries one witness stack.
pub(crate) fn fixture(
    tx_count: usize,
    input_count: usize,
    output_count: usize,
    script_len: usize,
    witness_modulus: usize,
) -> Block {
    let txs = (0..tx_count)
        .map(|index| {
            let identity = u32::try_from(index)
                .unwrap_or_else(|error| panic!("fixture transaction count: {error}"));
            let mut previous = [0_u8; 32];
            previous[..4].copy_from_slice(&identity.to_le_bytes());
            previous[4] = 1;
            let witnessed = witness_modulus != 0 && (index + 1).is_multiple_of(witness_modulus);
            let inputs = (0..input_count)
                .map(|input_index| TxIn {
                    previous_output: OutPoint::new(
                        Txid(Hash256::from_le_bytes(&previous)),
                        u32::try_from(input_index)
                            .unwrap_or_else(|error| panic!("fixture input count: {error}")),
                    ),
                    script_sig: vec![0x51; script_len],
                    sequence: 0xffff_fffe,
                    witness: if witnessed && input_index == 0 {
                        vec![vec![0x30; 72], vec![0x02; 33]]
                    } else {
                        Vec::new()
                    },
                })
                .collect();
            Tx {
                version: 2,
                inputs,
                outputs: vec![
                    TxOut {
                        value: 1,
                        script_pubkey: vec![0x51; script_len],
                    };
                    output_count
                ],
                lock_time: identity,
            }
        })
        .collect();
    Block {
        header: Header {
            version: 1,
            prev_blockhash: BlockHash::default(),
            merkle_root: Hash256::default(),
            time: 0,
            bits: 0,
            nonce: 0,
        },
        txs,
    }
}

/// Independent rust-bitcoin decoding, hashing, weight and Merkle reduction.
/// All assertions run outside benchmark timing loops.
pub(crate) fn assert_oracle(bytes: &[u8], facts: &BlockFacts) {
    let oracle: bitcoin::Block = bitcoin::consensus::deserialize(bytes)
        .unwrap_or_else(|error| panic!("oracle block decode: {error}"));
    assert_eq!(facts.tx_count(), oracle.txdata.len());
    assert_eq!(facts.weight(), oracle.weight().to_wu());
    for (actual, expected) in facts.txids().iter().zip(&oracle.txdata) {
        assert_eq!(actual.to_string(), expected.compute_txid().to_string());
    }
    let has_witness = oracle
        .txdata
        .iter()
        .any(|tx| tx.input.iter().any(|input| !input.witness.is_empty()));
    assert_eq!(facts.has_witness(), has_witness);
    match facts.wtxids() {
        Some(ids) => {
            assert_eq!(ids.len(), oracle.txdata.len());
            for (actual, expected) in ids.iter().zip(&oracle.txdata) {
                assert_eq!(actual.to_string(), expected.compute_wtxid().to_string());
            }
        }
        None => assert!(!has_witness, "witness-bearing facts must carry witness IDs"),
    }
    let root = bitcoin::merkle_tree::calculate_root(
        oracle.txdata.iter().map(bitcoin::Transaction::compute_txid),
    );
    assert_eq!(
        facts.merkle_root().map(|root| root.to_string()),
        root.map(|root| root.to_string()),
    );
    assert_eq!(facts.transaction_spans().len(), oracle.txdata.len());
    for (span, tx) in facts.transaction_spans().iter().zip(&oracle.txdata) {
        let start = usize::try_from(span.start())
            .unwrap_or_else(|error| panic!("fixture span start: {error}"));
        let end =
            usize::try_from(span.end()).unwrap_or_else(|error| panic!("fixture span end: {error}"));
        assert_eq!(&bytes[start..end], bitcoin::consensus::serialize(tx));
    }
}
