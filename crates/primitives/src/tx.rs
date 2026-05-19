use bitcoin::consensus::Encodable;

use crate::{Hash256, encode::double_sha256};

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
        let bytes = txid_bytes(&self.0);
        assert!(
            !has_witness(&self.0) || !has_segwit_marker(&bytes),
            "non-witness txid serialization unexpectedly contains a segwit marker"
        );
        double_sha256(&bytes)
    }

    /// Computes the witness transaction id from the witness serialization.
    #[must_use]
    pub fn wtxid(&self) -> Hash256 {
        let bytes = wtxid_bytes(&self.0);
        assert!(
            !has_witness(&self.0) || has_segwit_marker(&bytes),
            "witness transaction serialization omitted the segwit marker"
        );
        double_sha256(&bytes)
    }
}

fn txid_bytes(tx: &bitcoin::Transaction) -> Vec<u8> {
    let mut bytes = Vec::new();
    encode_part(&mut bytes, &tx.version);
    encode_part(&mut bytes, &tx.input);
    encode_part(&mut bytes, &tx.output);
    encode_part(&mut bytes, &tx.lock_time);
    bytes
}

fn wtxid_bytes(tx: &bitcoin::Transaction) -> Vec<u8> {
    let mut bytes = Vec::new();
    encode_part(&mut bytes, tx);
    bytes
}

fn encode_part<T: Encodable + ?Sized>(bytes: &mut Vec<u8>, value: &T) {
    if let Err(error) = value.consensus_encode(bytes) {
        panic!("consensus encoding into Vec failed: {error}");
    }
}

fn has_witness(tx: &bitcoin::Transaction) -> bool {
    tx.input.iter().any(|input| !input.witness.is_empty())
}

fn has_segwit_marker(bytes: &[u8]) -> bool {
    bytes.get(4) == Some(&0) && bytes.get(5).is_some_and(|flag| *flag != 0)
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
