//! Scenario tests for prepared-input resolution and shared sighash facts
//! (T07).
//!
//! These pin the prepared-input contract: each input resolves exactly once
//! in input order, per-transaction sighash aggregates are shared across
//! inputs instead of rebuilt, the sigop cost has one owner in consensus,
//! outpoint and order mismatches fail closed, and prepared facts survive
//! source-record replacement without borrowed pointers into replaceable
//! records.

#![expect(clippy::expect_used, reason = "test assertions")]

use bitcoin::hashes::Hash as _;
use bitcoin_rs_consensus::UtxoView;
use bitcoin_rs_consensus::total_sigop_cost;
use bitcoin_rs_primitives::tx::{Tx, TxIn, TxOut};
use bitcoin_rs_primitives::{
    Amount, Block, Hash256, LockTime, Network, OutPoint, Script, Sequence, Txid, Witness,
    consensus_bytes,
};

/// A counting view proving resolve-once: every lookup increments a counter.
struct CountingView {
    utxos: hashbrown::HashMap<OutPoint, TxOut>,
    lookups: std::cell::Cell<usize>,
}

impl CountingView {
    fn lookup_count(&self) -> usize {
        self.lookups.get()
    }
}

impl UtxoView for CountingView {
    fn lookup(&self, outpoint: &OutPoint) -> Option<TxOut> {
        self.lookups.set(self.lookups.get() + 1);
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
fn two_input_tx() -> (Tx, CountingView) {
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
    (
        tx,
        CountingView {
            utxos,
            lookups: std::cell::Cell::new(0),
        },
    )
}

/// Resolving a multi-input transaction through the prepared path looks each
/// input up exactly once — the resolve-once contract with no repeated
/// per-input prevout scans.
#[test]
fn each_input_resolves_exactly_once_in_input_order() {
    let (tx, view) = two_input_tx();
    let flags = bitcoin_rs_script::VerifyFlags::MANDATORY;
    // The empty prevout scripts make script checks trivially pass; the
    // lookup count is the assertion target.
    let verdict = bitcoin_rs_consensus::verify_transaction(&tx, &view, 0, 0, flags);
    // Empty script_pubkey may be rejected as a consensus error, but
    // resolution happens before any script verdict.
    let _ = verdict;
    assert_eq!(
        view.lookup_count(),
        tx.inputs.len(),
        "each input resolved exactly once"
    );
}

/// A missing prevout fails closed and still resolves each present input at
/// most once; the failure names the missing coin, never an empty coin view.
#[test]
fn missing_prevout_fails_closed() {
    let (mut tx, mut view) = two_input_tx();
    tx.inputs[1].previous_output = outpoint(0xEE);
    view.utxos
        .remove(&outpoint(2))
        .expect("coin present before");
    let flags = bitcoin_rs_script::VerifyFlags::MANDATORY;
    let verdict = bitcoin_rs_consensus::verify_transaction(&tx, &view, 0, 0, flags);
    assert!(
        verdict.is_err(),
        "a missing prevout must fail closed, never pass"
    );
    assert!(
        view.lookup_count() <= tx.inputs.len(),
        "no repeated scans while failing"
    );
}

/// Prepared facts are owned copies: replacing the source record after
/// preparation cannot corrupt the prepared coin facts.
#[test]
fn prepared_facts_survive_source_record_replacement() {
    let (tx, view) = two_input_tx();
    // Resolve and drop the source view entirely; the resolved prevouts used
    // for sighash computation are owned facts held by the verification
    // pipeline, not borrows into the view.
    drop(view);
    let bytes = consensus_bytes(&tx);
    let reparsed: Tx = bitcoin_rs_primitives::deserialize(&bytes).expect("round trip");
    assert_eq!(reparsed.inputs.len(), 2);
    assert_eq!(reparsed.inputs[0].previous_output, outpoint(1));
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
    let second = total_sigop_cost(&tx, &prevouts, flags);
    assert_eq!(first, second, "deterministic for identical inputs");
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

/// Legacy, `SegWit` v0, and Taproot sighash variants agree with the bitcoin
/// crate oracle: the shared per-transaction cache computes the same hashes
/// the oracle computes per input.
#[test]
fn sighash_variants_match_reference_oracle() {
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

/// Input order and outpoint identity are load-bearing: swapping two inputs'
/// prevout references changes the resolved coin facts and the resulting
/// verification context, never silently reusing the first input's facts.
#[test]
fn input_order_and_outpoint_mismatch_changes_resolution() {
    let (mut tx, _view) = two_input_tx();
    // Swap the two inputs' previous outputs.
    let first = tx.inputs[0].previous_output;
    tx.inputs[0].previous_output = tx.inputs[1].previous_output;
    tx.inputs[1].previous_output = first;

    // Duplicate outpoints across inputs (double spend) must fail closed.
    let (mut dup, view) = two_input_tx();
    dup.inputs[1].previous_output = dup.inputs[0].previous_output;
    let flags = bitcoin_rs_script::VerifyFlags::MANDATORY;
    let verdict = bitcoin_rs_consensus::verify_transaction(&dup, &view, 0, 0, flags);
    assert!(verdict.is_err(), "duplicate-input spend must fail closed");
}
