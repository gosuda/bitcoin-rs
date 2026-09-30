//! Block fixtures shared by in-crate unit tests.

use bitcoin_rs_primitives::{
    Amount, Block, LockTime, Network, OutPoint, Script, Sequence, Tx, TxIn, TxOut, Witness,
};

/// A regtest-genesis-header block whose one transaction carries a
/// `script_len`-byte zero scriptSig.
fn padded_block(script_len: usize) -> Block {
    Block {
        header: Network::Regtest.genesis_block().header,
        txs: vec![Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::default(),
                script_sig: vec![0_u8; script_len].into(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(0),
                script_pubkey: Script::new(),
            }],
            lock_time: LockTime::ZERO,
        }],
    }
}

/// A [`padded_block`] whose serialized size is exactly `total_bytes`.
/// The script-length prefix grows by 2 bytes at 253 and again at 65536,
/// so sizes 253, 254, 65538, and 65539 above the empty-script size do
/// not exist.
pub(crate) fn padded_block_of_size(total_bytes: usize) -> Block {
    let wanted = total_bytes.saturating_sub(padded_block(0).total_size());
    let script_len = match wanted {
        0..=252 => wanted,
        255..=65_537 => wanted - 2,
        _ => wanted.saturating_sub(4),
    };
    let block = padded_block(script_len);
    assert_eq!(block.total_size(), total_bytes);
    block
}
