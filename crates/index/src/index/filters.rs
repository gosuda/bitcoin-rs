//! BIP158 basic filters and their BIP157 commitments, owned by the derived index.

use super::{IndexError, SpentCoinScripts};
use bitcoin_rs_primitives::{encode, layout::ParsedBlock};
use bitcoin_rs_storage::{ColumnFamily, KvSnapshot};

/// Additive namespace in the index metadata table; no backend table, reset scans only this prefix.
pub(super) const PREFIX: &[u8] = &[1, b'F'];

pub(super) fn key(hash: &[u8; 32]) -> [u8; 34] {
    let mut key = [0; 34];
    key[..2].copy_from_slice(PREFIX);
    key[2..].copy_from_slice(hash);
    key
}

/// One serialized basic filter and its double-SHA256 commitments (wire byte order).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BasicFilter {
    /// BIP158 `CompactSize` element count followed by Golomb-Rice coded deltas.
    pub filter: Vec<u8>,
    /// Double SHA256 of `filter`.
    pub hash: [u8; 32],
    /// Double SHA256 of `hash || previous_header`.
    pub header: [u8; 32],
}

impl BasicFilter {
    pub(super) fn decode(mut bytes: Vec<u8>) -> Result<Self, IndexError> {
        if bytes.len() < 65 {
            return Err(IndexError::InvalidCompactFilter);
        }
        let mut hash = [0; 32];
        let mut header = [0; 32];
        hash.copy_from_slice(&bytes[..32]);
        header.copy_from_slice(&bytes[32..64]);
        drop(bytes.drain(..64));
        let filter = bytes;
        if encode::double_sha256(&filter).to_le_bytes() != hash {
            return Err(IndexError::InvalidCompactFilter);
        }
        Ok(Self {
            filter,
            hash,
            header,
        })
    }

    pub(super) fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(64 + self.filter.len());
        bytes.extend_from_slice(&self.hash);
        bytes.extend_from_slice(&self.header);
        bytes.extend_from_slice(&self.filter);
        bytes
    }

    pub(super) fn chain(&mut self, previous_header: [u8; 32]) {
        let mut commitment = [0; 64];
        commitment[..32].copy_from_slice(&self.hash);
        commitment[32..].copy_from_slice(&previous_header);
        self.header = encode::double_sha256(&commitment).to_le_bytes();
    }
}

pub(super) fn read(
    snapshot: &dyn KvSnapshot,
    hash: &[u8; 32],
) -> Result<Option<BasicFilter>, IndexError> {
    snapshot
        .get(ColumnFamily::UtxoMeta, &key(hash))?
        .map(BasicFilter::decode)
        .transpose()
}

/// Resolves inputs from earlier transactions in this block before consulting the
/// authoritative undo source.
///
/// A missing external prevout fails closed. Empty and `OP_RETURN` outputs are excluded,
/// but no UTXO admission rule applies: oversized scripts and genesis stay in the
/// filter.
pub(super) fn build(
    parsed: &ParsedBlock<'_>,
    height: u32,
    hash: &[u8; 32],
    spent: &dyn SpentCoinScripts,
) -> Result<BasicFilter, IndexError> {
    let k0 = u64::from_le_bytes(
        hash[..8]
            .try_into()
            .unwrap_or_else(|_| unreachable!("SipHash keys are eight bytes")),
    );
    let k1 = u64::from_le_bytes(
        hash[8..16]
            .try_into()
            .unwrap_or_else(|_| unreachable!("SipHash keys are eight bytes")),
    );
    let mut filter = Vec::new();
    let mut writer = bitcoin::bip158::GcsFilterWriter::new(&mut filter, k0, k1, 784_931, 19);
    let mut created = hashbrown::HashMap::<([u8; 32], u32), &[u8]>::new();
    for tx in parsed.transactions() {
        for input in tx.inputs() {
            let outpoint = tx
                .span_bytes(input.outpoint())
                .unwrap_or_else(|| unreachable!("outpoint belongs to parsed image"));
            let mut txid = [0; 32];
            txid.copy_from_slice(&outpoint[..32]);
            let vout = u32::from_le_bytes(
                outpoint[32..]
                    .try_into()
                    .unwrap_or_else(|_| unreachable!("outpoint vout is four bytes")),
            );
            if txid == [0; 32] && vout == u32::MAX {
                continue;
            }
            let script = created
                .get(&(txid, vout))
                .copied()
                .or_else(|| spent.script_bytes(&txid, vout))
                .ok_or(IndexError::MissingSpentCoin { txid, vout, height })?;
            writer.add_element(script);
        }
        let txid = *tx.txid().as_bytes();
        for (vout, output) in tx.outputs().iter().enumerate() {
            let script = tx
                .span_bytes(output.script_pubkey())
                .unwrap_or_else(|| unreachable!("script belongs to parsed image"));
            let vout = u32::try_from(vout).map_err(|_| IndexError::MutationSizeOverflow)?;
            created.insert((txid, vout), script);
            if !script.is_empty() && script[0] != 0x6a {
                writer.add_element(script);
            }
        }
    }
    writer
        .finish()
        .map_err(|_| IndexError::InvalidCompactFilter)?;
    let hash = encode::double_sha256(&filter).to_le_bytes();
    Ok(BasicFilter {
        filter,
        hash,
        header: [0; 32],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{consensus::deserialize, hashes::Hash as _, hex::FromHex as _};

    struct Scripts(hashbrown::HashMap<([u8; 32], u32), Vec<u8>>);
    impl SpentCoinScripts for Scripts {
        fn script_bytes(&self, txid: &[u8; 32], vout: u32) -> Option<&[u8]> {
            self.0.get(&(*txid, vout)).map(Vec::as_slice)
        }
    }

    #[test]
    fn basic_filters_match_pinned_core_vectors() -> Result<(), Box<dyn std::error::Error>> {
        let vectors: Vec<sonic_rs::Value> =
            sonic_rs::from_str(include_str!("../../tests/data/blockfilters-core-31.1.json"))?;
        for vector in vectors.into_iter().skip(1) {
            let (height, _hash, body, prevouts, previous, expected_filter, expected_header, note):
                (u32, String, String, Vec<String>, String, String, String, String) = sonic_rs::from_value(&vector)?;
            let bytes = Vec::from_hex(&body)?;
            let block: bitcoin::Block = deserialize(&bytes)?;
            let prevouts = prevouts
                .iter()
                .map(|script| Vec::from_hex(script))
                .collect::<Result<Vec<_>, _>>()?;
            let inputs = block.txdata.iter().skip(1).flat_map(|tx| &tx.input);
            let scripts = Scripts(
                inputs
                    .zip(prevouts)
                    .map(|(input, script)| {
                        (
                            (
                                input.previous_output.txid.to_byte_array(),
                                input.previous_output.vout,
                            ),
                            script,
                        )
                    })
                    .collect(),
            );
            let hash = block.block_hash().to_byte_array();
            let mut filter = build(&ParsedBlock::parse_exact(&bytes)?, height, &hash, &scripts)?;
            assert_eq!(filter.filter, Vec::from_hex(&expected_filter)?, "{note}");
            let previous: bitcoin::bip158::FilterHeader = previous.parse()?;
            filter.chain(previous.to_byte_array());
            let expected: bitcoin::bip158::FilterHeader = expected_header.parse()?;
            assert_eq!(filter.header, expected.to_byte_array(), "{note}");
        }
        Ok(())
    }

    #[test]
    fn same_block_spends_resolve_locally_and_empty_filters_encode_zero()
    -> Result<(), Box<dyn std::error::Error>> {
        use bitcoin::{Amount, OutPoint, ScriptBuf, TxOut, consensus::serialize};

        let mut block = bitcoin::constants::genesis_block(bitcoin::Network::Regtest);
        let coinbase = &mut block.txdata[0];
        coinbase.output = vec![
            TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::new(),
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::from_bytes(vec![0x6a]),
            },
        ];
        let no_spends = Scripts(hashbrown::HashMap::new());
        let bytes = serialize(&block);
        let filter = build(
            &ParsedBlock::parse_exact(&bytes)?,
            0,
            &block.block_hash().to_byte_array(),
            &no_spends,
        )?;
        assert_eq!(filter.filter, [0]);

        block.txdata[0].output[0].script_pubkey = ScriptBuf::from_bytes(vec![0x51]);
        let parent = block.txdata[0].compute_txid();
        let mut child = block.txdata[0].clone();
        child.input[0].previous_output = OutPoint {
            txid: parent,
            vout: 0,
        };
        child.output[0].script_pubkey = ScriptBuf::from_bytes(vec![0x52]);
        block.txdata.push(child);
        let bytes = serialize(&block);
        let hash = block.block_hash().to_byte_array();
        let filter = build(&ParsedBlock::parse_exact(&bytes)?, 1, &hash, &no_spends)?;
        let expected = bitcoin::bip158::BlockFilter::new_script_filter(&block, |outpoint| {
            assert_eq!(
                *outpoint,
                OutPoint {
                    txid: parent,
                    vout: 0
                }
            );
            Ok(block.txdata[0].output[0].script_pubkey.clone())
        })?;
        assert_eq!(filter.filter, expected.content);
        assert_eq!(filter.filter[0], 2);

        block.txdata[1].input[0].previous_output.vout = 2;
        let bytes = serialize(&block);
        assert!(matches!(
            build(&ParsedBlock::parse_exact(&bytes)?, 1, &hash, &no_spends),
            Err(IndexError::MissingSpentCoin {
                height: 1,
                vout: 2,
                ..
            })
        ));
        Ok(())
    }
}
