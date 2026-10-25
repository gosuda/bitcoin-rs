//! Native block type and block-level hashing helpers.

use crate::{BlockHash, Header, Tx, Txid, encode::ConsensusEncode};

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

    /// Full consensus serialization length, including BIP144 witness sections.
    #[must_use]
    pub fn total_size(&self) -> usize {
        self.consensus_size()
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

    /// Returns the total heap bytes allocated for this block's transaction vector,
    /// transactions, inputs, outputs, scripts, and witness stacks, including spare capacity.
    ///
    /// Excludes the inline `Block` struct itself, any separate serialized raw byte buffer,
    /// and allocator metadata or size-class rounding.
    #[must_use]
    pub fn retained_heap_bytes(&self) -> usize {
        let mut total = self
            .txs
            .capacity()
            .saturating_mul(core::mem::size_of::<Tx>());
        for tx in &self.txs {
            total = total.saturating_add(tx.retained_heap_bytes());
        }
        total
    }
}

/// Block payload facts available without materializing a full block body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BlockBodyMetadata {
    /// Serialized block byte length.
    pub body_size: usize,
    /// Number of transactions encoded in the block.
    pub tx_count: usize,
}

#[cfg(test)]
mod tests {
    use super::Block;
    use crate::deserialize;
    use crate::encode::DecodeError;

    use crate::{BlockHash, Hash256, Header, OutPoint, Tx, TxIn, TxOut, Txid};

    type Result<T, E = Box<dyn std::error::Error>> = std::result::Result<T, E>;

    #[test]
    fn genesis_block_hash_matches_known_value() -> Result<()> {
        let bytes = std::fs::read("tests/testdata/0.bin")?;
        let block = deserialize::<Block>(&bytes)?;

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
        let block = deserialize::<Block>(&bytes)?;

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
            let block = deserialize::<Block>(&bytes)?;

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

    fn witness_tx(witness: crate::Witness) -> Tx {
        Tx {
            version: 2,
            lock_time: crate::LockTime::ZERO,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid::from(Hash256::from_le_bytes(&[0_u8; 32])), 0),
                script_sig: crate::Script::new(),
                sequence: crate::Sequence::MAX,
                witness,
            }],
            outputs: vec![TxOut {
                value: crate::Amount::from_sat(50_000),
                script_pubkey: vec![0x51].into(),
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
                bits: crate::CompactTarget::from_consensus(0x207f_ffff),
                nonce: 0,
            },
            txs: vec![tx],
        }
    }

    #[test]
    fn stripped_size_drops_witness_and_matches_header_plus_base_transactions() {
        let block = block_with_tx(witness_tx(
            vec![vec![0x21_u8; 64], vec![0x03_u8; 33]].into(),
        ));
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
        let block = block_with_tx(witness_tx(crate::Witness::new()));
        assert_eq!(
            block.stripped_size(),
            crate::encode::consensus_bytes(&block).len()
        );
        assert_eq!(block.stripped_size(), block.total_size());
    }

    #[test]
    fn block_decode_rejects_trailing_bytes() -> Result<()> {
        let mut bytes = std::fs::read("tests/testdata/0.bin")?;
        assert!(deserialize::<Block>(&bytes).is_ok());
        bytes.push(0xFF);

        assert_eq!(
            deserialize::<Block>(&bytes),
            Err(DecodeError::TrailingBytes { remaining: 1 })
        );
        Ok(())
    }

    fn read_test_fixture(name: &str) -> Result<Vec<u8>> {
        let local = format!("tests/testdata/{name}");
        if let Ok(bytes) = std::fs::read(&local) {
            return Ok(bytes);
        }
        let manifest = format!("{}/tests/testdata/{name}", env!("CARGO_MANIFEST_DIR"));
        Ok(std::fs::read(manifest)?)
    }

    #[test]
    fn retained_heap_bytes_empty_and_excess_txs_capacity() {
        assert_eq!(Block::default().retained_heap_bytes(), 0);

        let mut block = Block::default();
        block.txs.reserve_exact(10);
        assert_eq!(block.retained_heap_bytes(), 10 * core::mem::size_of::<Tx>());
    }

    #[test]
    fn retained_heap_bytes_genesis_fixture_matches_independent_calculation() -> Result<()> {
        let bytes = read_test_fixture("0.bin")?;
        let block = deserialize::<Block>(&bytes)?;

        // Independently derive expected value directly from vector capacities.
        let independent = block.txs.capacity() * core::mem::size_of::<Tx>()
            + block
                .txs
                .iter()
                .map(|tx| {
                    let in_caps = tx.inputs.capacity() * core::mem::size_of::<TxIn>();
                    let out_caps = tx.outputs.capacity() * core::mem::size_of::<TxOut>();
                    let in_payloads: usize = tx
                        .inputs
                        .iter()
                        .map(|input| {
                            input.script_sig.capacity()
                                + input.witness.capacity() * core::mem::size_of::<Vec<u8>>()
                                + input.witness.iter().map(Vec::capacity).sum::<usize>()
                        })
                        .sum();
                    let out_payloads: usize = tx
                        .outputs
                        .iter()
                        .map(|output| output.script_pubkey.capacity())
                        .sum();
                    in_caps + out_caps + in_payloads + out_payloads
                })
                .sum::<usize>();

        assert_eq!(block.retained_heap_bytes(), independent);

        // Genesis fixture has 1 tx, 1 input (77-byte script_sig), 1 output (67-byte script_pubkey).
        let expected_literal = core::mem::size_of::<Tx>()
            + core::mem::size_of::<TxIn>()
            + core::mem::size_of::<TxOut>()
            + 77
            + 67;
        assert_eq!(block.retained_heap_bytes(), expected_literal);
        Ok(())
    }

    #[test]
    fn retained_heap_bytes_fixture_363731_matches_independent_calculation() -> Result<()> {
        let bytes = read_test_fixture("363731.bin")?;
        let block = deserialize::<Block>(&bytes)?;

        let independent = block.txs.capacity() * core::mem::size_of::<Tx>()
            + block
                .txs
                .iter()
                .map(|tx| {
                    let in_caps = tx.inputs.capacity() * core::mem::size_of::<TxIn>();
                    let out_caps = tx.outputs.capacity() * core::mem::size_of::<TxOut>();
                    let in_payloads: usize = tx
                        .inputs
                        .iter()
                        .map(|input| {
                            input.script_sig.capacity()
                                + input.witness.capacity() * core::mem::size_of::<Vec<u8>>()
                                + input.witness.iter().map(Vec::capacity).sum::<usize>()
                        })
                        .sum();
                    let out_payloads: usize = tx
                        .outputs
                        .iter()
                        .map(|output| output.script_pubkey.capacity())
                        .sum();
                    in_caps + out_caps + in_payloads + out_payloads
                })
                .sum::<usize>();

        assert_eq!(block.retained_heap_bytes(), independent);

        // 363731 has 1883 txs, 3748 inputs (431,845 scriptSig bytes), 4265 outputs (106,226 scriptPubKey bytes).
        // On 64-bit systems with size_of::<usize>() == 8:
        // 1883 * 56 + 3748 * 88 + 4265 * 32 + 431,845 + 106,226 = 1,109,823 bytes.
        if core::mem::size_of::<usize>() == 8 {
            assert_eq!(block.retained_heap_bytes(), 1_109_823);
        }
        Ok(())
    }

    #[test]
    fn retained_heap_bytes_synthetic_witness_heavy_capacity_variations() {
        let mut script_sig_0 = Vec::with_capacity(60);
        script_sig_0.extend_from_slice(&[0xaa; 10]);

        let mut wit_item_0 = Vec::with_capacity(128);
        wit_item_0.extend_from_slice(&[0x01; 32]);
        let mut wit_item_1 = Vec::with_capacity(256);
        wit_item_1.extend_from_slice(&[0x02; 64]);
        let mut witness_stack_0 = Vec::with_capacity(4);
        witness_stack_0.push(wit_item_0);
        witness_stack_0.push(wit_item_1);

        let mut wit_item_2 = Vec::with_capacity(80);
        wit_item_2.extend_from_slice(&[0x03; 33]);
        let mut witness_stack_1 = Vec::with_capacity(3);
        witness_stack_1.push(wit_item_2);

        let mut inputs = Vec::with_capacity(5);
        inputs.push(TxIn {
            previous_output: OutPoint::default(),
            script_sig: crate::Script::from_bytes(script_sig_0),
            sequence: crate::Sequence::MAX,
            witness: crate::Witness::from_stack(witness_stack_0),
        });
        inputs.push(TxIn {
            previous_output: OutPoint::default(),
            script_sig: crate::Script::new(),
            sequence: crate::Sequence::MAX,
            witness: crate::Witness::from_stack(witness_stack_1),
        });

        let mut spk_0 = Vec::with_capacity(75);
        spk_0.extend_from_slice(&[0x51; 34]);
        let mut spk_1 = Vec::with_capacity(110);
        spk_1.extend_from_slice(&[0x00; 22]);
        let mut outputs = Vec::with_capacity(4);
        outputs.push(TxOut {
            value: crate::Amount::from_sat(50_000),
            script_pubkey: crate::Script::from_bytes(spk_0),
        });
        outputs.push(TxOut {
            value: crate::Amount::from_sat(60_000),
            script_pubkey: crate::Script::from_bytes(spk_1),
        });

        let tx = Tx {
            version: 2,
            inputs,
            outputs,
            lock_time: crate::LockTime::ZERO,
        };

        let mut txs = Vec::with_capacity(3);
        txs.push(tx);

        let mut block = Block {
            header: Header::default(),
            txs,
        };

        let expected_txs_buf = 3 * core::mem::size_of::<Tx>();
        let expected_inputs_buf = 5 * core::mem::size_of::<TxIn>();
        let expected_outputs_buf = 4 * core::mem::size_of::<TxOut>();
        let expected_input_0_scripts = 60 + 4 * core::mem::size_of::<Vec<u8>>() + 128 + 256;
        let expected_input_1_scripts = 3 * core::mem::size_of::<Vec<u8>>() + 80;
        let expected_output_scripts = 75 + 110;

        let expected_tx = expected_inputs_buf
            + expected_outputs_buf
            + expected_input_0_scripts
            + expected_input_1_scripts
            + expected_output_scripts;
        let expected_block = expected_txs_buf + expected_tx;

        assert_eq!(block.txs[0].retained_heap_bytes(), expected_tx);
        assert_eq!(block.retained_heap_bytes(), expected_block);

        // Verifying spare capacity accounting when reserving extra capacity in txs:
        block.txs.reserve_exact(7);
        let extra_txs_cap = block.txs.capacity() - 3;
        let expected_after_reserve = expected_block + extra_txs_cap * core::mem::size_of::<Tx>();
        assert_eq!(block.retained_heap_bytes(), expected_after_reserve);
    }
}
