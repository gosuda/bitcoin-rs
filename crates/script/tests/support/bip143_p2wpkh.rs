//! The BIP143 native-P2WPKH example shared by the ECDSA regression suites,
//! and the witness-execution helper both suites run it through.

use bitcoin_rs_primitives::{Tx, TxOut};
use bitcoin_rs_script::{Interpreter, ScriptError, VerifyFlags};

// Public test key and unsigned transaction from the BIP143 native-P2WPKH example.
pub(crate) const TX_HEX: &str = concat!(
    "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f",
    "0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57",
    "b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85",
    "c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2",
    "f0167faa815988ac11000000",
);
pub(crate) const TEST_KEY: &str =
    "619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9";
pub(crate) const PROGRAM: &str = "00141d0f172a0ecb48aee1be1f2687d2963ae33f71a1";
pub(crate) const VALUE: u64 = 600_000_000;
pub(crate) const INPUT: usize = 1;

pub(crate) fn verify_witness(
    tx: &Tx,
    prevout: &TxOut,
    witness: &[Vec<u8>],
    flags: VerifyFlags,
) -> Result<bool, ScriptError> {
    // Legacy and v0 checks read only INPUT's prevout, and BIP143 commits to
    // its spent amount; repeat it to fill the full prevout set.
    let prevouts = vec![prevout.clone(); tx.inputs.len()];
    Interpreter.execute_with_prevouts(
        &prevout.script_pubkey,
        &[],
        witness,
        flags,
        &prevouts,
        tx,
        INPUT,
    )
}
