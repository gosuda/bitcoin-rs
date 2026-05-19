//! Replace-by-fee policy coverage.
use bdk_coin_select::FeeRate;
use bitcoin::hashes::Hash as _;
use bitcoin::{Amount, Network, OutPoint, TxOut, Txid};
use bitcoin_rs_wallet::{Descriptor, FeeBumpPlan, PrevUtxo, PsbtBuilder};

#[path = "fixtures/test_signer.rs"]
mod test_signer;

#[test]
fn bump_fee_preserves_inputs_and_satisfies_bip125_fee_rules()
-> Result<(), Box<dyn std::error::Error>> {
    let signer = test_signer::TestSigner::new()?;
    let descriptor = Descriptor::parse(&format!("wpkh({})", signer.public_key()))?;
    let outpoint = OutPoint {
        txid: Txid::from_byte_array([42_u8; 32]),
        vout: 0,
    };
    let prev_txout = TxOut {
        value: Amount::from_sat(100_000),
        script_pubkey: descriptor
            .derive_address(Network::Regtest, 0)?
            .script_pubkey(),
    };
    let mut builder = PsbtBuilder::new(core::slice::from_ref(&descriptor));
    builder.add_input(PrevUtxo::new(outpoint, prev_txout), 0)?;
    builder.add_output(
        descriptor.derive_address(Network::Regtest, 1)?,
        Amount::from_sat(90_000),
    )?;
    let base = builder.finalize()?;
    let base_txid = base.unsigned_tx.compute_txid();
    let base_fee = base.fee()?.to_sat();

    let bumped =
        FeeBumpPlan::new(base.clone()).bump_fee(base_txid, FeeRate::from_sat_per_vb(10.0))?;
    let bumped_fee = bumped.fee()?.to_sat();
    let required_delta =
        FeeRate::DEFUALT_RBF_INCREMENTAL_RELAY.implied_fee(bumped.unsigned_tx.weight().to_wu());

    assert!(base.unsigned_tx.is_explicitly_rbf());
    assert_eq!(base.unsigned_tx.input.len(), bumped.unsigned_tx.input.len());
    assert_eq!(
        base.unsigned_tx.input[0].previous_output,
        bumped.unsigned_tx.input[0].previous_output
    );
    assert!(bumped_fee > base_fee);
    assert!(bumped_fee >= base_fee + required_delta);
    assert!(
        bumped_fee
            >= FeeRate::from_sat_per_vb(10.0).implied_fee(bumped.unsigned_tx.weight().to_wu())
    );
    assert!(bumped.inputs[0].partial_sigs.is_empty());

    Ok(())
}
