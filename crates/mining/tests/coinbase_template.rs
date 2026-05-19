//! Coinbase template construction tests.

use std::error::Error;

use bitcoin::opcodes::all::{OP_PUSHBYTES_36, OP_RETURN};
use bitcoin_rs_consensus::bip34::check_bip34;
use bitcoin_rs_mining::build_coinbase_template;
use bitcoin_rs_primitives::Hash256;

#[test]
fn coinbase_template_encodes_bip34_height_and_witness_commitment() -> Result<(), Box<dyn Error>> {
    let commitment = Hash256::from_le_bytes(&[7_u8; 32]);
    let coinbase = build_coinbase_template(800_000, 12_345, &commitment, 8)?;

    let script_sig = coinbase.input[0].script_sig.as_script();
    check_bip34(800_000, script_sig)?;
    assert_eq!(&script_sig.as_bytes()[..4], &[3, 0x00, 0x35, 0x0c]);
    assert_eq!(script_sig.len(), 12);

    let witness_output = coinbase
        .output
        .iter()
        .find(|output| output.script_pubkey.is_op_return())
        .ok_or("missing witness commitment output")?;
    let script = witness_output.script_pubkey.as_bytes();

    assert_eq!(script.len(), 38);
    assert_eq!(script[0], OP_RETURN.to_u8());
    assert_eq!(script[1], OP_PUSHBYTES_36.to_u8());
    assert_eq!(&script[2..6], &[0xaa, 0x21, 0xa9, 0xed]);
    assert_eq!(&script[6..], commitment.as_byte_array());

    Ok(())
}
