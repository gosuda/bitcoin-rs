//! VAL-02: missing coins, duplicate inputs, and reference transaction identities.

#![expect(clippy::expect_used, reason = "test assertions")]

use bitcoin::hashes::Hash as _;
use bitcoin_rs_consensus::total_sigop_cost;
use bitcoin_rs_consensus::{UtxoView, ValidationEngine};
use bitcoin_rs_primitives::tx::{Tx, TxIn, TxOut};
use bitcoin_rs_primitives::{
    Amount, Block, Hash256, LockTime, Network, OutPoint, Script, Sequence, Txid, Witness,
    consensus_bytes,
};

struct Coins {
    utxos: hashbrown::HashMap<OutPoint, TxOut>,
}

impl UtxoView for Coins {
    fn lookup(&self, outpoint: &OutPoint) -> Option<TxOut> {
        self.utxos.get(outpoint).cloned()
    }
}

fn outpoint(byte: u8) -> OutPoint {
    OutPoint {
        txid: Txid(Hash256::from_le_bytes(&[byte; 32])),
        vout: 0,
    }
}

fn plain_input(byte: u8) -> TxIn {
    TxIn {
        previous_output: outpoint(byte),
        script_sig: Script::new(),
        sequence: Sequence::from_consensus(u32::MAX),
        witness: Witness::new(),
    }
}

/// Two-input transaction spending distinct coins with empty scripts.
fn two_input_tx() -> (Tx, Coins) {
    let mut utxos = hashbrown::HashMap::new();
    for byte in [1_u8, 2] {
        utxos.insert(
            outpoint(byte),
            TxOut {
                value: Amount::from_sat(50),
                script_pubkey: Script::new(),
            },
        );
    }
    let tx = Tx {
        version: 2,
        lock_time: LockTime::from_consensus(0),
        inputs: vec![plain_input(1), plain_input(2)],
        outputs: vec![TxOut {
            value: Amount::from_sat(100),
            script_pubkey: Script::new(),
        }],
    };
    (tx, Coins { utxos })
}

/// VAL-02: a missing prevout is not a script failure or an empty coin.
#[test]
fn missing_prevout_fails_closed() {
    let (mut tx, view) = two_input_tx();
    tx.inputs[1].previous_output = outpoint(0xEE);
    let flags = bitcoin_rs_script::VerifyFlags::MANDATORY;
    let verdict =
        bitcoin_rs_consensus::verify_transaction(&tx, &view, 0, 0, flags, ValidationEngine::Native);
    assert!(matches!(
        verdict,
        Err(bitcoin_rs_consensus::ConsensusError::MissingPrevout { input_index: 1 })
    ));
}

/// The sigop-cost owner counts from resolved prevouts with the P2SH and
/// witness multipliers; the standard limit boundary is enforced by the
/// mempool caller on this one owner's output.
#[test]
fn sigop_cost_owner_counts_from_resolved_prevouts() {
    let (tx, mut view) = two_input_tx();
    view.utxos.get_mut(&outpoint(1)).expect("coin").value = Amount::from_sat(60);
    let prevouts: Vec<(OutPoint, TxOut)> = tx
        .inputs
        .iter()
        .map(|input| {
            let coin = view.utxos.get(&input.previous_output).expect("resolved");
            (input.previous_output, coin.clone())
        })
        .collect();
    let flags = bitcoin_rs_script::VerifyFlags::STANDARD;
    let first = total_sigop_cost(&tx, &prevouts, flags);
    // Two empty-script inputs carry no legacy sigops: the owner's count is
    // exactly zero for this fixture, not merely "bounded".
    assert_eq!(first, 0, "empty scripts count zero sigops");

    // Out-of-order prevout slices still resolve every input.
    let mut reversed = prevouts;
    reversed.reverse();
    assert_eq!(
        total_sigop_cost(&tx, &reversed, flags),
        first,
        "out-of-order prevouts resolve identically"
    );
}

/// VAL-02: legacy and witness transaction identities match an independent decoder.
/// This is not sighash evidence; script/Core vectors own signed-spend checks.
#[test]
fn transaction_identities_match_reference_oracle() {
    // Genesis coinbase through the layout: parse, materialize, and compare
    // txid/wtxid against the oracle, proving the shared-aggregate pipeline
    // reproduces reference identity for the legacy (no-witness) family.
    let genesis = Network::Mainnet.genesis_block();
    let bytes = consensus_bytes(&genesis);
    let parsed =
        bitcoin_rs_primitives::layout::ParsedBlock::parse_exact(&bytes).expect("genesis parses");
    let materialized: Block = parsed.materialize();
    let oracle: bitcoin::Block = bitcoin::consensus::deserialize(&bytes).expect("oracle decode");

    let native_txid = materialized.txs[0].txid();
    let oracle_txid = oracle.txdata[0].compute_txid();
    assert_eq!(
        native_txid.0,
        Hash256::from_le_bytes(oracle_txid.as_byte_array()),
        "legacy txid through the shared pipeline matches the oracle"
    );

    // SegWit family: a fixture segwit block's transactions re-encode and
    // hash identically through the layout.
    let fixture = format!(
        "{}/../primitives/tests/testdata/481824.bin",
        env!("CARGO_MANIFEST_DIR")
    );
    let segwit_bytes =
        std::fs::read(&fixture).unwrap_or_else(|error| panic!("read fixture {fixture}: {error}"));
    let parsed = bitcoin_rs_primitives::layout::ParsedBlock::parse_exact(&segwit_bytes)
        .expect("segwit fixture parses");
    let oracle: bitcoin::Block =
        bitcoin::consensus::deserialize(&segwit_bytes).expect("oracle decode");
    for (index, tx) in parsed.materialize().txs.iter().enumerate() {
        assert_eq!(
            tx.txid().0,
            Hash256::from_le_bytes(oracle.txdata[index].compute_txid().as_byte_array()),
            "segwit txid {index} matches oracle"
        );
        assert_eq!(
            tx.wtxid().0,
            Hash256::from_le_bytes(oracle.txdata[index].compute_wtxid().as_byte_array()),
            "segwit wtxid {index} matches oracle"
        );
    }
}

/// VAL-02: duplicate inputs are rejected before script verification.
#[test]
fn duplicate_inputs_are_rejected() {
    let (mut tx, view) = two_input_tx();
    tx.inputs[1].previous_output = tx.inputs[0].previous_output;
    let verdict = bitcoin_rs_consensus::verify_transaction(
        &tx,
        &view,
        0,
        0,
        bitcoin_rs_script::VerifyFlags::MANDATORY,
        ValidationEngine::Native,
    );
    assert!(matches!(
        verdict,
        Err(bitcoin_rs_consensus::ConsensusError::DuplicateInput { input_index: 1 })
    ));
}
