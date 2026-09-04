//! Native block type and block-level hashing helpers.

use crate::{
    BlockHash, Header, Tx, Txid,
    encode::{DecodeError, consensus_len, deserialize},
};

/// A Bitcoin block in native owned form.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Block {
    /// The block header.
    pub header: Header,
    /// Transactions in consensus order; the first entry is the coinbase.
    pub txs: Vec<Tx>,
}

impl Block {
    /// Computes the block hash from the block header.
    #[must_use]
    pub fn block_hash(&self) -> BlockHash {
        self.header.compute_hash()
    }

    /// Computes all transaction ids in block order.
    #[must_use]
    pub fn txids(&self) -> Vec<Txid> {
        self.txs.iter().map(Tx::txid).collect()
    }

    /// Decodes exactly one block (80-byte header, transaction count, transactions),
    /// rejecting any trailing bytes.
    pub fn consensus_decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        deserialize(bytes)
    }

    /// Full consensus serialization length, including BIP144 witness sections.
    #[must_use]
    pub fn total_size(&self) -> usize {
        consensus_len(self)
    }

    /// Consensus serialization length without BIP144 witness sections.
    ///
    /// Matches Core's `GetSerializeSize(TX_NO_WITNESS(*this))`: the header,
    /// the transaction-count compact size, and each transaction's base
    /// (txid-layout) size.
    #[must_use]
    pub fn stripped_size(&self) -> usize {
        Header::LEN
            .saturating_add(crate::varint::encoded_len(crate::encode::compact_len(
                self.txs.len(),
            )))
            .saturating_add(self.txs.iter().map(Tx::base_size).sum())
    }

    /// BIP141 block weight: `stripped_size * 3 + total_size` weight units.
    ///
    /// Matches Core's `GetBlockWeight`. Both sizes include the header and the
    /// transaction-count compact size; they are not a sum of per-transaction
    /// weights.
    #[must_use]
    pub fn weight(&self) -> u64 {
        u64::try_from(self.stripped_size())
            .unwrap_or(u64::MAX)
            .saturating_mul(3)
            .saturating_add(u64::try_from(self.total_size()).unwrap_or(u64::MAX))
    }
}

#[cfg(test)]
mod tests {
    use super::Block;
    use crate::encode::DecodeError;

    use crate::{BlockHash, Hash256, Header, OutPoint, Tx, TxIn, TxOut, Txid};

    type Result<T, E = Box<dyn std::error::Error>> = std::result::Result<T, E>;

    #[test]
    fn genesis_block_hash_matches_known_value() -> Result<()> {
        let bytes = std::fs::read("tests/testdata/0.bin")?;
        let block = Block::consensus_decode(&bytes)?;

        assert_eq!(
            block.block_hash(),
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
                .parse::<BlockHash>()?
        );
        Ok(())
    }

    #[test]
    fn fixture_block_reencodes_and_hashes_to_published_id() -> Result<()> {
        let bytes = std::fs::read("tests/testdata/363731.bin")?;
        let block = Block::consensus_decode(&bytes)?;

        assert_eq!(crate::encode::consensus_bytes(&block), bytes);
        assert_eq!(
            block.block_hash(),
            "00000000000000000c28e23330c29046f19e817fe8fe039f4044b2b2882aef53"
                .parse::<BlockHash>()?
        );
        Ok(())
    }

    #[test]
    fn size_and_weight_match_serialized_bytes_and_pinned_weights() -> Result<()> {
        let cases: &[(&str, usize, usize, u64)] = &[
            ("tests/testdata/0.bin", 285, 285, 1140),
            ("tests/testdata/363731.bin", 749_141, 749_141, 2_996_564),
        ];
        for (fixture, total, stripped, weight) in cases {
            let bytes = std::fs::read(fixture)?;
            let block = Block::consensus_decode(&bytes)?;

            assert_eq!(block.total_size(), bytes.len(), "{fixture}");
            assert_eq!(
                crate::encode::consensus_bytes(&block).len(),
                bytes.len(),
                "{fixture}"
            );
            assert_eq!(block.total_size(), *total, "{fixture}");
            assert_eq!(block.stripped_size(), *stripped, "{fixture}");
            assert_eq!(block.weight(), *weight, "{fixture}");
            assert_eq!(
                block.weight(),
                u64::try_from(block.stripped_size())?
                    .saturating_mul(3)
                    .saturating_add(u64::try_from(block.total_size())?),
                "{fixture}"
            );
        }
        Ok(())
    }

    fn witness_tx(witness: Vec<Vec<u8>>) -> Tx {
        Tx {
            version: 2,
            lock_time: 0,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid::from(Hash256::from_le_bytes(&[0_u8; 32])), 0),
                script_sig: Vec::new(),
                sequence: u32::MAX,
                witness,
            }],
            outputs: vec![TxOut {
                value: 50_000,
                script_pubkey: vec![0x51],
            }],
        }
    }

    fn block_with_tx(tx: Tx) -> Block {
        Block {
            header: Header {
                version: 1,
                prev_blockhash: BlockHash::default(),
                merkle_root: Hash256::default(),
                time: 1_700_000_000,
                bits: 0x207f_ffff,
                nonce: 0,
            },
            txs: vec![tx],
        }
    }

    #[test]
    fn stripped_size_drops_witness_and_matches_header_plus_base_transactions() {
        let block = block_with_tx(witness_tx(vec![vec![0x21_u8; 64], vec![0x03_u8; 33]]));
        let total = crate::encode::consensus_bytes(&block).len();
        let stripped = block.stripped_size();
        assert!(
            stripped < total,
            "the witness discount must be visible: {stripped} vs {total}"
        );
        let manual: usize = 80
            + 1 // compact size for one transaction
            + block.txs.iter().map(Tx::base_size).sum::<usize>();
        assert_eq!(stripped, manual);
    }

    #[test]
    fn stripped_size_equals_total_size_without_witness() {
        let block = block_with_tx(witness_tx(Vec::new()));
        assert_eq!(
            block.stripped_size(),
            crate::encode::consensus_bytes(&block).len()
        );
        assert_eq!(block.stripped_size(), block.total_size());
    }

    #[test]
    fn block_decode_rejects_trailing_bytes() -> Result<()> {
        let mut bytes = std::fs::read("tests/testdata/0.bin")?;
        assert!(Block::consensus_decode(&bytes).is_ok());
        bytes.push(0xFF);

        assert_eq!(
            Block::consensus_decode(&bytes),
            Err(DecodeError::TrailingBytes { remaining: 1 })
        );
        Ok(())
    }
}
