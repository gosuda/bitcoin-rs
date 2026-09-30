//! GBT ⇄ SV2 Template Distribution translation.
//!
//! Field mappings mirror the upstream reference template provider
//! (`bitcoin-core-sv2` in stratum-mining/sv2-apps v0.8.0,
//! `unix_capnp/v31x/template_distribution_protocol/template_data.rs`):
//! hashes travel in internal (little-endian display-reversed) byte order, the
//! merkle branch is ordered leaf-first, and `SetNewPrevHash.target` is the
//! little-endian encoding of the consensus target derived from `nBits`.

use bitcoin::block::{Block, Header, Version};
use bitcoin::hashes::Hash as _;
use bitcoin::hashes::sha256d::Hash as Sha256dHash;
use bitcoin::pow::CompactTarget;
use bitcoin::{BlockHash, Sequence, TxMerkleNode};
use serde_json::Value;
use stratum_apps::stratum_core::binary_sv2::{B016MOwned, Seq064KOwned, Seq0255Owned, U256Owned};
use stratum_apps::stratum_core::bitcoin;
use stratum_apps::stratum_core::template_distribution_sv2::{
    NewTemplateOwned, SetNewPrevHashOwned, SubmitSolutionOwned,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum TemplateError {
    #[error("gbt field {field}: {why}")]
    Field { field: &'static str, why: String },
    #[error("solution does not match template: {0}")]
    Solution(String),
}

pub struct TemplateState {
    pub id: u64,
    pub version: u32,
    pub bits: u32,
    pub curtime: u32,
    /// Previous block hash in internal byte order (as it serializes).
    pub prev_hash_internal: [u8; 32],
    pub height: u64,
    /// Subsidy + fees available for downstream (pool) coinbase outputs.
    pub value_remaining: u64,
    /// Witness-commitment script the coinbase must carry verbatim, if the
    /// template has one (bitcoin-rs mining owner owns commitment rules).
    commitment_script: Option<Vec<u8>>,
    /// Merkle branch of the coinbase (leaf-first sibling hashes, internal order).
    merkle_branch: Vec<[u8; 32]>,
    /// Full template transactions (coinbase excluded), GBT order.
    pub txs: Vec<bitcoin::Transaction>,
}

impl TemplateState {
    /// Parses the required GBT fields and transactions into a template with
    /// the supplied ID, reporting missing fields or invalid field encodings.
    pub fn from_gbt(id: u64, gbt: &Value) -> Result<Self, TemplateError> {
        let field = |name: &'static str| {
            gbt.get(name).ok_or_else(|| TemplateError::Field {
                field: name,
                why: "missing".into(),
            })
        };
        let version = u32::try_from(
            field("version")?
                .as_u64()
                .ok_or_else(|| missing("version"))?,
        )
        .map_err(|_| missing("version"))?;
        let bits = u32::from_str_radix(
            field("bits")?
                .as_str()
                .ok_or_else(|| missing("bits"))?
                .trim_start_matches("0x"),
            16,
        )
        .map_err(|e| TemplateError::Field {
            field: "bits",
            why: e.to_string(),
        })?;
        let curtime = u32::try_from(
            field("curtime")?
                .as_u64()
                .ok_or_else(|| missing("curtime"))?,
        )
        .map_err(|_| missing("curtime"))?;
        let prev_hex = field("previousblockhash")?
            .as_str()
            .ok_or_else(|| missing("previousblockhash"))?;
        let prev_bytes = hex::decode(prev_hex).map_err(|e| TemplateError::Field {
            field: "previousblockhash",
            why: e.to_string(),
        })?;
        if prev_bytes.len() != 32 {
            return Err(TemplateError::Field {
                field: "previousblockhash",
                why: format!("expected 32 bytes, got {}", prev_bytes.len()),
            });
        }
        let mut prev_hash_internal = [0u8; 32];
        prev_hash_internal
            .iter_mut()
            .zip(prev_bytes.iter().rev())
            .for_each(|(o, i)| *o = *i);
        let height = field("height")?.as_u64().ok_or_else(|| missing("height"))?;
        let value_remaining = field("coinbasevalue")?
            .as_u64()
            .ok_or_else(|| missing("coinbasevalue"))?;

        let commitment_script = match field("default_witness_commitment")?.as_str() {
            Some(hex_script) => {
                Some(hex::decode(hex_script).map_err(|e| TemplateError::Field {
                    field: "default_witness_commitment",
                    why: e.to_string(),
                })?)
            }
            None => None,
        };

        let txs = field("transactions")?
            .as_array()
            .ok_or_else(|| missing("transactions"))?
            .iter()
            .map(|tx| {
                let data =
                    tx.get("data")
                        .and_then(Value::as_str)
                        .ok_or_else(|| TemplateError::Field {
                            field: "transactions[].data",
                            why: "missing".into(),
                        })?;
                let bytes = hex::decode(data).map_err(|e| TemplateError::Field {
                    field: "transactions[].data",
                    why: e.to_string(),
                })?;
                bitcoin::consensus::deserialize::<bitcoin::Transaction>(&bytes).map_err(|e| {
                    TemplateError::Field {
                        field: "transactions[].data",
                        why: e.to_string(),
                    }
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        // The coinbase occupies leaf 0 of the block's merkle tree but its
        // txid is unknown until the pool builds it. The index-0 branch only
        // carries that leaf's siblings, so a placeholder leaf yields the
        // correct path; without it the first template transaction would take
        // the coinbase slot and every root would be wrong.
        let merkle_branch = merkle_branch_coinbase(
            std::iter::once([0u8; 32])
                .chain(txs.iter().map(|tx| tx.compute_txid().to_byte_array()))
                .collect(),
        );

        Ok(Self {
            id,
            version,
            bits,
            curtime,
            prev_hash_internal,
            height,
            value_remaining,
            commitment_script,
            merkle_branch,
            txs,
        })
    }

    /// The witness-commitment output the coinbase must carry verbatim
    /// (bitcoin-rs mining owner owns coinbase/witness-commitment rules).
    /// SV2 `coinbase_tx_outputs` is a serialized-TxOut list, so the script is
    /// wrapped in a zero-value `TxOut` exactly like the upstream Core adapter
    /// (`get_serialized_required_coinbase_outputs`).
    fn required_outputs(&self) -> Option<Vec<u8>> {
        self.commitment_script.as_ref().map(|script| {
            bitcoin::consensus::serialize(&bitcoin::TxOut {
                value: bitcoin::Amount::ZERO,
                script_pubkey: bitcoin::Script::from_bytes(script).to_owned(),
            })
        })
    }

    /// Builds a future template carrying the coinbase requirements and merkle
    /// path; the paired `SetNewPrevHash` message activates it for the pool.
    pub fn new_template_msg(&self) -> NewTemplateOwned {
        NewTemplateOwned {
            template_id: self.id,
            // Always `future_template: true`: the SRI pool's bootstrap gate
            // (channel_manager) only records templates flagged as future, and
            // the paired SetNewPrevHash activates the job immediately — the
            // same idle behavior as the upstream Core template provider.
            future_template: true,
            version: self.version,
            coinbase_tx_version: 2,
            coinbase_prefix: bip34_prefix(self.height)
                .try_into()
                .expect("prefix fits B0255"),
            coinbase_tx_input_sequence: Sequence::MAX.to_consensus_u32(),
            coinbase_tx_value_remaining: self.value_remaining,
            coinbase_tx_outputs_count: usize::from(self.required_outputs().is_some()) as u32,
            coinbase_tx_outputs: self
                .required_outputs()
                .unwrap_or_default()
                .try_into()
                .expect("commitment output fits B064K"),
            coinbase_tx_locktime: 0,
            merkle_path: Seq0255Owned::new(
                self.merkle_branch
                    .iter()
                    .map(|sibling| U256Owned::from(*sibling))
                    .collect(),
            )
            .expect("merkle path fits Seq0255"),
        }
    }

    /// Builds the activation message with the previous hash in internal byte
    /// order and the target derived from `bits` in little-endian byte order.
    pub fn set_new_prev_hash_msg(&self) -> SetNewPrevHashOwned {
        let target = bitcoin::pow::Target::from(CompactTarget::from_consensus(self.bits));
        SetNewPrevHashOwned {
            template_id: self.id,
            prev_hash: U256Owned::from(self.prev_hash_internal),
            header_timestamp: self.curtime,
            n_bits: self.bits,
            target: U256Owned::from(target.to_le_bytes()),
        }
    }

    /// Serializes non-coinbase transactions in GBT order for a transaction-data
    /// response. Panics if a transaction or the list exceeds SV2 size limits.
    pub fn transaction_data(&self) -> Seq064KOwned<B016MOwned> {
        let list = self
            .txs
            .iter()
            .map(|tx| {
                B016MOwned::try_from(bitcoin::consensus::serialize(tx))
                    .expect("transaction fits B016M")
            })
            .collect();
        Seq064KOwned::new(list).expect("transaction list fits Seq064K")
    }

    /// Reassembles the block from a pool solution: solution header fields +
    /// solution coinbase (the pool may freely rewrite the scriptSig) over this
    /// template's merkle branch and transaction list.
    pub fn assemble_block(&self, solution: &SubmitSolutionOwned) -> Result<Block, TemplateError> {
        if solution.template_id != self.id {
            return Err(TemplateError::Solution(format!(
                "template id {} does not match {}",
                solution.template_id, self.id
            )));
        }
        let coinbase: bitcoin::Transaction =
            bitcoin::consensus::deserialize(solution.coinbase_tx.as_ref())
                .map_err(|e| TemplateError::Solution(format!("invalid coinbase tx: {e}")))?;

        // Merkle root: fold coinbase txid with the leaf-first branch, exactly
        // like the reference template provider's solution assembly.
        let mut current = coinbase.compute_txid().to_byte_array();
        for sibling in &self.merkle_branch {
            let mut buf = Vec::with_capacity(64);
            buf.extend_from_slice(&current);
            buf.extend_from_slice(sibling);
            current = *Sha256dHash::hash(&buf).as_byte_array();
        }

        let header = Header {
            version: Version::from_consensus(solution.version as i32),
            prev_blockhash: BlockHash::from_byte_array(self.prev_hash_internal),
            merkle_root: TxMerkleNode::from_byte_array(current),
            time: solution.header_timestamp,
            bits: CompactTarget::from_consensus(self.bits),
            nonce: solution.header_nonce,
        };
        Ok(Block {
            header,
            txdata: std::iter::once(coinbase)
                .chain(self.txs.iter().cloned())
                .collect(),
        })
    }

    /// Consensus PoW gate (reference provider validates before submitting).
    pub fn header_meets_target(header: &Header) -> bool {
        bitcoin::pow::Target::from(header.bits).is_met_by(header.block_hash())
    }
}

/// Describes a required GBT field that is absent or has an invalid type or range.
fn missing(field: &'static str) -> TemplateError {
    TemplateError::Field {
        field,
        why: "missing or wrong type".into(),
    }
}

/// Double-SHA256 over concatenated raw bytes (internal order in, internal out).
fn dsha256(a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(a.len() + b.len());
    buf.extend_from_slice(a);
    buf.extend_from_slice(b);
    *Sha256dHash::hash(&buf).as_byte_array()
}

/// Standard bitcoin merkle branch for the coinbase (index 0), leaf-first,
/// with the duplicate-last rule for odd levels.
fn merkle_branch_coinbase(mut level: Vec<[u8; 32]>) -> Vec<[u8; 32]> {
    let mut branch = Vec::new();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(*level.last().expect("len > 1"));
        }
        branch.push(level[1]);
        level = level
            .chunks(2)
            .map(|pair| dsha256(&pair[0], &pair[1]))
            .collect();
    }
    branch
}

/// BIP34 height prefix, matching bitcoin-rs `coinbase_script_sig`: minimal
/// `CScriptNum` push (`push_int`), plus `OP_0` padding when the encoding is a
/// single opcode (consensus `bad-cb-length` minimum of two bytes).
fn bip34_prefix(height: u64) -> Vec<u8> {
    let mut script = match height {
        0 => vec![0x00],
        1..=16 => vec![0x50 + height as u8],
        _ => {
            let mut num = script_num_le(height);
            if *num.last().expect("non-zero height has bytes") & 0x80 != 0 {
                num.push(0x00);
            }
            let mut push = vec![num.len() as u8];
            push.extend_from_slice(&num);
            push
        }
    };
    if script.len() < 2 {
        script.push(0x00);
    }
    script
}

/// Minimal little-endian `CScriptNum` magnitude for positive heights.
fn script_num_le(value: u64) -> Vec<u8> {
    let mut bytes = value.to_le_bytes().to_vec();
    while bytes.last().is_some_and(|b| *b == 0) {
        bytes.pop();
    }
    bytes
}

// Coinbase used by tests: mirrors bitcoin-rs build_coinbase shape.
#[cfg(test)]
pub(crate) fn test_coinbase(
    script_sig: Vec<u8>,
    commitment: Option<&[u8]>,
) -> bitcoin::Transaction {
    let mut outputs = vec![TxOut {
        value: Amount::from_sat(50_0000_0000),
        script_pubkey: Script::from_bytes(&[0x51]).to_owned(),
    }];
    let witness = if commitment.is_some() {
        Witness::from_slice(&[vec![0u8; 32].as_slice()])
    } else {
        Witness::default()
    };
    if let Some(commitment) = commitment {
        outputs.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: Script::from_bytes(commitment).to_owned(),
        });
    }
    bitcoin::Transaction {
        version: TxVersion::non_standard(2),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::new(Txid::from_byte_array([0; 32]), 0xffff_ffff),
            script_sig: Script::from_bytes(&script_sig).to_owned(),
            sequence: Sequence::MAX,
            witness,
        }],
        output: outputs,
    }
}

/// Independent full-list merkle root (test oracle for the branch).
#[cfg(test)]
fn full_merkle_root(mut level: Vec<[u8; 32]>) -> [u8; 32] {
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(*level.last().expect("len > 1"));
        }
        level = level
            .chunks(2)
            .map(|pair| dsha256(&pair[0], &pair[1]))
            .collect();
    }
    level.into_iter().next().expect("non-empty input")
}

#[cfg(test)]
fn fold_branch(coinbase_txid: [u8; 32], branch: &[[u8; 32]]) -> [u8; 32] {
    let mut current = coinbase_txid;
    for sibling in branch {
        current = dsha256(&current, sibling);
    }
    current
}

#[cfg(test)]
use bitcoin::transaction::Version as TxVersion;
#[cfg(test)]
use bitcoin::{Amount, OutPoint, Script, TxIn, TxOut, Txid, Witness};

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const COMMITMENT_HEX: &str =
        "6a24aa21a9ed5d9e8c9a8f9d7f2e1c0b0a99887766554433221100ffeeddccbbaa";

    fn gbt_fixture(txs: &[bitcoin::Transaction]) -> Value {
        let entries: Vec<Value> = txs
            .iter()
            .map(|tx| json!({ "data": hex::encode(bitcoin::consensus::serialize(tx)) }))
            .collect();
        json!({
            "version": 0x20000000u32,
            "bits": "207fffff",
            "curtime": 1_700_000_000u64,
            "previousblockhash": "0000000000000000000000000000000000000000000000000000000000000000",
            "height": 1u64,
            "coinbasevalue": 5_000_000_000u64,
            "default_witness_commitment": COMMITMENT_HEX,
            "transactions": entries,
        })
    }

    fn fake_txs(count: usize) -> Vec<bitcoin::Transaction> {
        (0..count)
            .map(|i| {
                let mut tx = test_coinbase(vec![0x51], None);
                tx.output[0].value = Amount::from_sat(i as u64 + 1_000);
                tx
            })
            .collect()
    }

    #[test]
    fn merkle_branch_matches_full_root_for_all_arities() {
        for count in 1..=6usize {
            let txids: Vec<[u8; 32]> = fake_txs(count)
                .iter()
                .map(|tx| tx.compute_txid().to_byte_array())
                .collect();
            let branch = merkle_branch_coinbase(txids.clone());
            let expected = full_merkle_root(txids.clone());
            assert_eq!(
                fold_branch(txids[0], &branch),
                expected,
                "branch must fold to the full root for {count} transactions"
            );
        }
    }

    #[test]
    fn two_tx_branch_is_second_txid() {
        let txids = fake_txs(2)
            .iter()
            .map(|tx| tx.compute_txid().to_byte_array())
            .collect::<Vec<_>>();
        let branch = merkle_branch_coinbase(txids.clone());
        assert_eq!(branch, vec![txids[1]]);
    }

    #[test]
    fn bip34_prefix_matches_bitcoin_rs_push_int() {
        assert_eq!(
            bip34_prefix(1),
            vec![0x51, 0x00],
            "height 1 is OP_1 plus OP_0 pad"
        );
        assert_eq!(
            bip34_prefix(16),
            vec![0x60, 0x00],
            "height 16 is OP_16 plus OP_0 pad"
        );
        assert_eq!(bip34_prefix(17), vec![0x01, 0x11]);
        assert_eq!(bip34_prefix(0x7f), vec![0x01, 0x7f]);
        assert_eq!(bip34_prefix(0x80), vec![0x02, 0x80, 0x00]);
        assert_eq!(bip34_prefix(255), vec![0x02, 0xff, 0x00]);
        assert_eq!(bip34_prefix(256), vec![0x02, 0x00, 0x01]);
        assert_eq!(bip34_prefix(500_000), vec![0x03, 0x20, 0xa1, 0x07]);
    }

    #[test]
    fn gbt_fields_map_into_tdp_messages() {
        let txs = fake_txs(3);
        let state = TemplateState::from_gbt(7, &gbt_fixture(&txs)).expect("fixture parses");

        let template = state.new_template_msg();
        assert_eq!(template.template_id, 7);
        assert!(
            template.future_template,
            "pool bootstrap gate requires future flag"
        );
        assert_eq!(template.version, 0x2000_0000);
        assert_eq!(template.coinbase_tx_version, 2);
        assert_eq!(template.coinbase_prefix.as_ref(), &[0x51, 0x00]);
        assert_eq!(template.coinbase_tx_input_sequence, u32::MAX);
        assert_eq!(template.coinbase_tx_value_remaining, 5_000_000_000);
        assert_eq!(template.coinbase_tx_outputs_count, 1);
        // coinbase_tx_outputs is a serialized-TxOut list: zero value,
        // compactsize length, then the commitment script.
        let mut expected_outputs = vec![0u8; 8];
        let script = hex::decode(COMMITMENT_HEX).expect("fixture hex");
        expected_outputs.push(script.len() as u8);
        expected_outputs.extend_from_slice(&script);
        assert_eq!(template.coinbase_tx_outputs.as_ref(), &expected_outputs);
        assert_eq!(template.coinbase_tx_locktime, 0);
        assert_eq!(template.merkle_path.len(), 2, "3 txs -> 2 siblings");

        let prev = state.set_new_prev_hash_msg();
        assert_eq!(prev.template_id, 7);
        assert_eq!(prev.prev_hash.as_bytes(), &[0u8; 32]);
        assert_eq!(prev.header_timestamp, 1_700_000_000);
        assert_eq!(prev.n_bits, 0x207f_ffff);
        let expected_target =
            bitcoin::pow::Target::from(CompactTarget::from_consensus(0x207f_ffff)).to_le_bytes();
        assert_eq!(prev.target.as_bytes(), &expected_target);
    }

    #[test]
    fn missing_commitment_yields_zero_outputs() {
        let mut gbt = gbt_fixture(&fake_txs(1));
        gbt["default_witness_commitment"] = Value::Null;
        let state = TemplateState::from_gbt(1, &gbt).expect("parses without commitment");
        let template = state.new_template_msg();
        assert_eq!(template.coinbase_tx_outputs_count, 0);
        assert!(template.coinbase_tx_outputs.as_ref().is_empty());
    }

    #[test]
    fn assembly_uses_solution_coinbase_and_template_branch() {
        let txs = fake_txs(3);
        let state = TemplateState::from_gbt(9, &gbt_fixture(&txs)).expect("fixture parses");

        // Pool rewrote the scriptSig: BIP34 prefix + signature + extranonce.
        let mut script_sig = bip34_prefix(1);
        script_sig.extend_from_slice(b"Stratum V2 SRI Pool");
        script_sig.extend_from_slice(&[0xaa; 8]);
        let coinbase = test_coinbase(script_sig, Some(&hex::decode(COMMITMENT_HEX).unwrap()));
        let solution = SubmitSolutionOwned {
            template_id: 9,
            version: 0x2000_0000,
            header_timestamp: 1_700_000_042,
            header_nonce: 0xdead_beef,
            coinbase_tx: bitcoin::consensus::serialize(&coinbase).try_into().unwrap(),
        };

        let block = state.assemble_block(&solution).expect("assembly succeeds");
        assert_eq!(block.txdata[0].compute_txid(), coinbase.compute_txid());
        assert_eq!(&block.txdata[1..], &state.txs[..]);

        // The assembled header must commit to the block it ships: the
        // branch folded over the solution coinbase equals the root computed
        // independently over the full transaction list.
        assert_eq!(
            block.header.merkle_root,
            block.compute_merkle_root().expect("non-empty txdata")
        );
        assert_eq!(
            block.header.prev_blockhash.to_byte_array(),
            state.prev_hash_internal
        );
        assert_eq!(block.header.time, 1_700_000_042);
        assert_eq!(block.header.nonce, 0xdead_beef);
        assert_eq!(
            block.header.bits,
            CompactTarget::from_consensus(0x207f_ffff)
        );
    }

    #[test]
    fn assembly_rejects_foreign_template_id() {
        let state = TemplateState::from_gbt(1, &gbt_fixture(&fake_txs(1))).unwrap();
        let coinbase = test_coinbase(bip34_prefix(1), None);
        let solution = SubmitSolutionOwned {
            template_id: 42,
            version: 0x2000_0000,
            header_timestamp: 0,
            header_nonce: 0,
            coinbase_tx: bitcoin::consensus::serialize(&coinbase).try_into().unwrap(),
        };
        assert!(state.assemble_block(&solution).is_err());
    }
}
