//! Native transaction types and txid/wtxid computation.

use sha2::{Digest, Sha256};

use crate::{
    DecodeError, OutPoint, Txid, Wtxid,
    encode::{ConsensusEncode, Sha256Writer, deserialize, encode_tx, finalize_double_sha256},
};

/// A Bitcoin transaction input in native owned form.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TxIn {
    /// The outpoint being spent.
    pub previous_output: OutPoint,
    /// The input's scriptSig (empty for segwit spends).
    pub script_sig: Vec<u8>,
    /// The input sequence number.
    pub sequence: u32,
    /// The BIP144 witness stack; empty when the input has no witness.
    pub witness: Vec<Vec<u8>>,
}

/// A Bitcoin transaction output in native owned form.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TxOut {
    /// The output value in satoshis.
    pub value: u64,
    /// The output scriptPubKey.
    pub script_pubkey: Vec<u8>,
}

/// A Bitcoin transaction in native owned form.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Tx {
    /// Transaction version.
    pub version: i32,
    /// Inputs in consensus order.
    pub inputs: Vec<TxIn>,
    /// Outputs in consensus order.
    pub outputs: Vec<TxOut>,
    /// Lock time.
    pub lock_time: u32,
}

impl Tx {
    /// Returns true when any input carries BIP144 witness data.
    #[must_use]
    pub fn has_witness(&self) -> bool {
        self.inputs.iter().any(|input| !input.witness.is_empty())
    }

    /// Computes the transaction id: double-SHA256 of the non-witness serialization.
    #[must_use]
    pub fn txid(&self) -> Txid {
        let mut engine = Sha256::new();
        let mut writer = Sha256Writer(&mut engine);
        encode_tx(self, &mut writer, false)
            .unwrap_or_else(|error| unreachable!("sha256 writer is infallible: {error}"));
        Txid(finalize_double_sha256(engine))
    }

    /// Computes the witness transaction id: double-SHA256 of the full serialization.
    #[must_use]
    pub fn wtxid(&self) -> Wtxid {
        let mut engine = Sha256::new();
        let mut writer = Sha256Writer(&mut engine);
        ConsensusEncode::consensus_encode(self, &mut writer)
            .unwrap_or_else(|error| unreachable!("sha256 writer is infallible: {error}"));
        Wtxid(finalize_double_sha256(engine))
    }

    /// Decodes a complete transaction from its consensus serialization, rejecting any
    /// trailing bytes (the exact-consume path shared with [`crate::encode::deserialize`]).
    pub fn consensus_decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        deserialize(bytes)
    }
    /// Consensus serialization length without BIP144 witness sections (the txid layout).
    #[must_use]
    pub fn base_size(&self) -> usize {
        let mut total = 0_usize;
        let () = encode_tx(self, &mut crate::encode::CountWriter(&mut total), false)
            .unwrap_or_else(|error| unreachable!("count writer is infallible: {error}"));
        total
    }

    /// Full consensus serialization length, including BIP144 witness sections.
    #[must_use]
    pub fn total_size(&self) -> usize {
        crate::encode::consensus_len(self)
    }

    /// BIP141 transaction weight: `base_size * 3 + total_size` weight units.
    #[must_use]
    pub fn weight(&self) -> u64 {
        u64::try_from(self.base_size())
            .unwrap_or(u64::MAX)
            .saturating_mul(3)
            .saturating_add(u64::try_from(self.total_size()).unwrap_or(u64::MAX))
    }

    /// BIP141 virtual size: weight divided by four, rounded up.
    #[must_use]
    pub fn vsize(&self) -> u64 {
        self.weight().div_ceil(4)
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::expect_used, reason = "test assertions")]
    use bitcoin::hashes::Hash as _;

    use super::Tx;
    use crate::{
        DecodeError, Hash256, OutPoint, TxIn, TxOut, Txid, Wtxid, encode::consensus_bytes,
    };

    type Result<T, E = Box<dyn std::error::Error>> = std::result::Result<T, E>;

    fn native_tx() -> Tx {
        Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid(Hash256::default()), 3),
                script_sig: vec![0x51],
                sequence: 0xffff_fffe,
                witness: vec![vec![0xaa; 40]],
            }],
            outputs: vec![TxOut {
                value: 50_000,
                script_pubkey: vec![0x00, 0x14, 0xab],
            }],
            lock_time: 42,
        }
    }

    #[test]
    fn txid_and_wtxid_match_bitcoin_crate_for_fixture_transactions() -> Result<()> {
        let bytes = std::fs::read("tests/testdata/363731.bin")?;
        let block: bitcoin::Block = bitcoin::consensus::deserialize(&bytes)?;

        for bitcoin_tx in block.txdata.iter().take(10) {
            let serialized = bitcoin::consensus::serialize(bitcoin_tx);
            let tx = Tx::consensus_decode(&serialized)?;

            let expected_txid = Hash256::from_le_bytes(bitcoin_tx.compute_txid().as_byte_array());
            let expected_wtxid = Hash256::from_le_bytes(bitcoin_tx.compute_wtxid().as_byte_array());

            assert_eq!(tx.txid(), Txid(expected_txid));
            assert_eq!(tx.wtxid(), Wtxid(expected_wtxid));
            assert_eq!(consensus_bytes(&tx), serialized);
        }
        Ok(())
    }

    #[test]
    fn witness_free_tx_has_equal_txid_and_wtxid() {
        let mut tx = native_tx();
        tx.inputs[0].witness.clear();

        assert!(!tx.has_witness());
        assert_eq!(tx.txid(), Txid::from(tx.wtxid().0));
    }

    #[test]
    fn witnessed_tx_serialization_carries_marker_and_witness() {
        let tx = native_tx();

        let bytes = consensus_bytes(&tx);
        // version || marker 0x00 || flag 0x01
        assert_eq!(&bytes[4..6], &[0x00, 0x01]);

        let decoded = Tx::consensus_decode(&bytes).expect("roundtrip");
        assert_eq!(decoded, tx);
        assert_ne!(tx.txid(), Txid::from(tx.wtxid().0));
    }

    #[test]
    fn valid_tx_followed_by_garbage_is_rejected() {
        let tx = native_tx();
        let mut bytes = consensus_bytes(&tx);
        bytes.extend_from_slice(&[0xde, 0xad]);

        let error = Tx::consensus_decode(&bytes).expect_err("trailing garbage must fail");
        assert_eq!(error, DecodeError::TrailingBytes { remaining: 2 });

        // Without the garbage the same bytes decode cleanly.
        assert_eq!(Tx::consensus_decode(&consensus_bytes(&tx)), Ok(tx));
    }
}
