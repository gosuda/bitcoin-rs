use bitcoin::{consensus::Encodable, io::Write};
use sha2::{Digest, Sha256};

use crate::{Hash256, encode::Sha256Writer, varint};

/// A transaction input using the canonical `bitcoin` crate representation.
pub type TxIn = bitcoin::TxIn;

/// A transaction output using the canonical `bitcoin` crate representation.
pub type TxOut = bitcoin::TxOut;

/// A Bitcoin transaction wrapper with project-local hash computation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tx(pub bitcoin::Transaction);

impl Tx {
    /// Computes the transaction id from the non-witness serialization.
    #[must_use]
    pub fn txid(&self) -> Hash256 {
        let mut engine = Sha256::new();
        let mut writer = Sha256Writer(&mut engine);
        encode_without_witness(&self.0, &mut writer);
        finalize_double_sha256(engine)
    }

    /// Computes the witness transaction id from the witness serialization.
    #[must_use]
    pub fn wtxid(&self) -> Hash256 {
        let mut engine = Sha256::new();
        let mut writer = Sha256Writer(&mut engine);
        encode_consensus(&mut writer, &self.0);
        finalize_double_sha256(engine)
    }
}

fn encode_without_witness(tx: &bitcoin::Transaction, writer: &mut impl Write) {
    write_all(writer, &tx.version.0.to_le_bytes());
    encode_len(writer, tx.input.len());
    for input in &tx.input {
        encode_consensus(writer, &input.previous_output);
        write_script(writer, input.script_sig.as_bytes());
        write_all(writer, &input.sequence.0.to_le_bytes());
    }
    encode_len(writer, tx.output.len());
    for output in &tx.output {
        write_all(writer, &output.value.to_sat().to_le_bytes());
        write_script(writer, output.script_pubkey.as_bytes());
    }
    encode_consensus(writer, &tx.lock_time);
}

fn write_script(writer: &mut impl Write, script: &[u8]) {
    encode_len(writer, script.len());
    write_all(writer, script);
}

fn encode_len(writer: &mut impl Write, len: usize) {
    let len = u64::try_from(len).unwrap_or_else(|_| unreachable!("usize fits into u64"));
    let encoded = varint::encode(len);
    write_all(writer, encoded.as_slice());
}

fn encode_consensus<T: Encodable + ?Sized>(writer: &mut impl Write, value: &T) {
    if let Err(error) = value.consensus_encode(writer) {
        unreachable!("sha256 writer is infallible: {error}");
    }
}

fn write_all(writer: &mut impl Write, bytes: &[u8]) {
    if let Err(error) = writer.write_all(bytes) {
        unreachable!("sha256 writer is infallible: {error}");
    }
}

fn finalize_double_sha256(engine: Sha256) -> Hash256 {
    let first = engine.finalize();
    let second = Sha256::digest(first);
    let bytes = second.into();
    Hash256::from_le_bytes(&bytes)
}

#[cfg(test)]
mod tests {
    use bitcoin::hashes::Hash as _;

    use super::Tx;
    use crate::Hash256;

    #[test]
    fn txid_and_wtxid_match_bitcoin_crate_for_fixture_transactions()
    -> Result<(), Box<dyn std::error::Error>> {
        let bytes = std::fs::read("tests/testdata/363731.bin")?;
        let block: bitcoin::Block = bitcoin::consensus::deserialize(&bytes)?;

        for bitcoin_tx in block.txdata.iter().take(10) {
            let tx = Tx(bitcoin_tx.clone());
            let expected_txid = Hash256::from_le_bytes(bitcoin_tx.compute_txid().as_byte_array());
            let expected_wtxid = Hash256::from_le_bytes(bitcoin_tx.compute_wtxid().as_byte_array());

            assert_eq!(tx.txid(), expected_txid);
            assert_eq!(tx.wtxid(), expected_wtxid);
        }
        Ok(())
    }
}
