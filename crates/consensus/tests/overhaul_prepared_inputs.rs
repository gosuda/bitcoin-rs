//! Missing coins, duplicate inputs, and independently decoded transaction identities.

#![expect(clippy::expect_used, reason = "test assertions")]

use bitcoin::hashes::Hash as _;
use bitcoin_rs_consensus::{ConsensusError, UtxoView, ValidationEngine, verify_transaction};
use bitcoin_rs_primitives::{
    Amount, Block, Hash256, LockTime, Network, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Txid,
    Witness, consensus_bytes,
};
use bitcoin_rs_script::VerifyFlags;

struct Coins(hashbrown::HashMap<OutPoint, TxOut>);

impl UtxoView for Coins {
    fn lookup(&self, outpoint: &OutPoint) -> Option<TxOut> {
        self.0.get(outpoint).cloned()
    }
}

fn outpoint(byte: u8) -> OutPoint {
    OutPoint::new(Txid(Hash256::from_le_bytes(&[byte; 32])), 0)
}

fn two_input_tx() -> (Tx, Coins) {
    let tx = Tx {
        version: 2,
        lock_time: LockTime::ZERO,
        inputs: [1, 2]
            .map(|byte| TxIn {
                previous_output: outpoint(byte),
                script_sig: Script::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            })
            .to_vec(),
        outputs: vec![TxOut {
            value: Amount::from_sat(100),
            script_pubkey: Script::new(),
        }],
    };
    let coins = Coins(
        [1, 2]
            .map(|byte| {
                (
                    outpoint(byte),
                    TxOut {
                        value: Amount::from_sat(50),
                        script_pubkey: Script::new(),
                    },
                )
            })
            .into(),
    );
    (tx, coins)
}

#[test]
fn missing_or_duplicate_prevouts_fail_before_scripts() {
    for (second, expected) in [
        (
            outpoint(0xee),
            ConsensusError::MissingPrevout { input_index: 1 },
        ),
        (
            outpoint(1),
            ConsensusError::DuplicateInput { input_index: 1 },
        ),
    ] {
        let (mut tx, coins) = two_input_tx();
        tx.inputs[1].previous_output = second;
        assert_eq!(
            verify_transaction(
                &tx,
                &coins,
                0,
                0,
                VerifyFlags::MANDATORY,
                ValidationEngine::Native
            ),
            Err(expected)
        );
    }
}

#[test]
fn transaction_identities_match_reference_oracle() {
    let fixture = format!(
        "{}/../primitives/tests/testdata/481824.bin",
        env!("CARGO_MANIFEST_DIR")
    );
    let segwit = std::fs::read(&fixture).unwrap_or_else(|error| panic!("read {fixture}: {error}"));
    for bytes in [consensus_bytes(&Network::Mainnet.genesis_block()), segwit] {
        let parsed =
            bitcoin_rs_primitives::layout::ParsedBlock::parse_exact(&bytes).expect("parse");
        let oracle: bitcoin::Block =
            bitcoin::consensus::deserialize(&bytes).expect("oracle decode");
        let materialized: Block = parsed.materialize();
        assert_eq!(materialized.txs.len(), oracle.txdata.len());
        for (index, (tx, reference)) in materialized.txs.iter().zip(&oracle.txdata).enumerate() {
            assert_eq!(
                tx.txid().0,
                Hash256::from_le_bytes(reference.compute_txid().as_byte_array()),
                "txid {index} in {} byte block",
                bytes.len()
            );
            assert_eq!(
                tx.wtxid().0,
                Hash256::from_le_bytes(reference.compute_wtxid().as_byte_array()),
                "wtxid {index} in {} byte block",
                bytes.len()
            );
        }
    }
}
