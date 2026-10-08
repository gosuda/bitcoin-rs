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

/// One issued template: the GBT fields the pool needs, the coinbase rules the
/// mining owner keeps, and the merkle branch for the coinbase slot.
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

/// Required field missing, malformed, or out of range.
fn field_err(field: &'static str, why: impl std::fmt::Display) -> String {
    format!("gbt field {field}: {why}")
}

fn field<'a>(gbt: &'a Value, name: &'static str) -> Result<&'a Value, String> {
    gbt.get(name).ok_or_else(|| field_err(name, "missing"))
}

impl TemplateState {
    /// Parses the required GBT fields and transactions into a template with
    /// the supplied id.
    pub fn from_gbt(id: u64, gbt: &Value) -> Result<Self, String> {
        let version = field(gbt, "version")?
            .as_u64()
            .and_then(|v| u32::try_from(v).ok())
            .ok_or_else(|| field_err("version", "not a u32"))?;
        let bits = u32::from_str_radix(
            field(gbt, "bits")?
                .as_str()
                .ok_or_else(|| field_err("bits", "not a string"))?
                .trim_start_matches("0x"),
            16,
        )
        .map_err(|e| field_err("bits", e))?;
        let curtime = field(gbt, "curtime")?
            .as_u64()
            .and_then(|t| u32::try_from(t).ok())
            .ok_or_else(|| field_err("curtime", "not a u32"))?;

        let prev_bytes = hex::decode(
            field(gbt, "previousblockhash")?
                .as_str()
                .ok_or_else(|| field_err("previousblockhash", "not a string"))?,
        )
        .map_err(|e| field_err("previousblockhash", e))?;
        let prev_hash_internal: [u8; 32] = prev_bytes
            .iter()
            .rev()
            .copied()
            .collect::<Vec<u8>>()
            .try_into()
            .map_err(|v: Vec<u8>| field_err("previousblockhash", format!("{} bytes", v.len())))?;

        let height = field(gbt, "height")?
            .as_u64()
            .ok_or_else(|| field_err("height", "not an integer"))?;
        let value_remaining = field(gbt, "coinbasevalue")?
            .as_u64()
            .ok_or_else(|| field_err("coinbasevalue", "not an integer"))?;

        let commitment_script = match field(gbt, "default_witness_commitment")?.as_str() {
            Some(script) => {
                Some(hex::decode(script).map_err(|e| field_err("default_witness_commitment", e))?)
            }
            None => None,
        };

        let txs = field(gbt, "transactions")?
            .as_array()
            .ok_or_else(|| field_err("transactions", "not an array"))?
            .iter()
            .map(|tx| {
                let bytes = hex::decode(
                    tx.get("data")
                        .and_then(Value::as_str)
                        .ok_or_else(|| field_err("transactions[].data", "missing"))?,
                )
                .map_err(|e| field_err("transactions[].data", e))?;
                bitcoin::consensus::deserialize::<bitcoin::Transaction>(&bytes)
                    .map_err(|e| field_err("transactions[].data", e))
            })
            .collect::<Result<Vec<_>, _>>()?;

        // The coinbase occupies leaf 0 but its txid is unknown until the pool
        // builds it. A placeholder leaf yields the correct index-0 branch;
        // without it the first template tx would take the coinbase slot and
        // every root would be wrong.
        let merkle_branch = merkle_branch(
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

    /// The witness-commitment output the coinbase must carry verbatim,
    /// wrapped as a serialized `TxOut` exactly like the upstream Core adapter
    /// (`coinbase_tx_outputs` is a serialized-TxOut list, not a bare script).
    fn required_outputs(&self) -> Option<Vec<u8>> {
        self.commitment_script.as_ref().map(|script| {
            bitcoin::consensus::serialize(&bitcoin::TxOut {
                value: bitcoin::Amount::ZERO,
                script_pubkey: bitcoin::Script::from_bytes(script).to_owned(),
            })
        })
    }

    /// Builds the `NewTemplate` carrying coinbase requirements and merkle
    /// path; the paired `SetNewPrevHash` activates it for the pool.
    pub fn new_template_msg(&self) -> NewTemplateOwned {
        let required = self.required_outputs().unwrap_or_default();
        NewTemplateOwned {
            template_id: self.id,
            // Always `future_template: true`: the SRI pool's bootstrap gate
            // only records future templates, and the paired SetNewPrevHash
            // activates the job immediately — the upstream Core TP's
            // idle behavior.
            future_template: true,
            version: self.version,
            coinbase_tx_version: 2,
            coinbase_prefix: bip34_prefix(self.height)
                .try_into()
                .expect("prefix fits B0255"),
            coinbase_tx_input_sequence: Sequence::MAX.to_consensus_u32(),
            coinbase_tx_value_remaining: self.value_remaining,
            coinbase_tx_outputs_count: (self.commitment_script.is_some()) as u32,
            coinbase_tx_outputs: required.try_into().expect("commitment output fits B064K"),
            coinbase_tx_locktime: 0,
            merkle_path: Seq0255Owned::new(
                self.merkle_branch.iter().map(U256Owned::from).collect(),
            )
            .expect("merkle path fits Seq0255"),
        }
    }

    /// Builds the activation message: previous hash in internal byte order,
    /// target derived from `bits` in little-endian byte order.
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

    /// Serializes non-coinbase transactions in GBT order for a
    /// transaction-data response.
    pub fn transaction_data(&self) -> Seq064KOwned<B016MOwned> {
        Seq064KOwned::new(
            self.txs
                .iter()
                .map(|tx| {
                    B016MOwned::try_from(bitcoin::consensus::serialize(tx))
                        .expect("transaction fits B016M")
                })
                .collect(),
        )
        .expect("transaction list fits Seq064K")
    }

    /// Reassembles the block from a pool solution: solution header fields +
    /// solution coinbase over this template's merkle branch and tx list.
    pub fn assemble_block(&self, solution: &SubmitSolutionOwned) -> Result<Block, String> {
        if solution.template_id != self.id {
            return Err(format!(
                "template id {} does not match {}",
                solution.template_id, self.id
            ));
        }
        let coinbase: bitcoin::Transaction =
            bitcoin::consensus::deserialize(solution.coinbase_tx.as_ref())
                .map_err(|e| format!("invalid coinbase tx: {e}"))?;

        // Fold the coinbase txid through the leaf-first branch, exactly like
        // the reference template provider's solution assembly.
        let mut merkle_root = coinbase.compute_txid().to_byte_array();
        for sibling in &self.merkle_branch {
            merkle_root = dsha256(&merkle_root, sibling);
        }

        Ok(Block {
            header: Header {
                version: Version::from_consensus(solution.version as i32),
                prev_blockhash: BlockHash::from_byte_array(self.prev_hash_internal),
                merkle_root: TxMerkleNode::from_byte_array(merkle_root),
                time: solution.header_timestamp,
                bits: CompactTarget::from_consensus(self.bits),
                nonce: solution.header_nonce,
            },
            txdata: std::iter::once(coinbase)
                .chain(self.txs.iter().cloned())
                .collect(),
        })
    }

    /// Consensus PoW gate before submitting (the reference TP validates too).
    pub fn header_meets_target(header: &Header) -> bool {
        bitcoin::pow::Target::from(header.bits).is_met_by(header.block_hash())
    }
}

/// Double-SHA256 over concatenated raw bytes (internal order in, out).
fn dsha256(a: &[u8], b: &[u8]) -> [u8; 32] {
    *Sha256dHash::hash(&[a, b].concat()).as_byte_array()
}

/// Standard bitcoin merkle branch for leaf index 0, leaf-first, with the
/// duplicate-last rule for odd levels.
fn merkle_branch(mut level: Vec<[u8; 32]>) -> Vec<[u8; 32]> {
    let mut branch = Vec::new();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(*level.last().expect("len > 1"));
        }
        branch.push(level[1]);
        level = level.chunks(2).map(|p| dsha256(&p[0], &p[1])).collect();
    }
    branch
}

/// BIP34 height prefix, matching bitcoin-rs `coinbase_script_sig`: minimal
/// `CScriptNum` push, plus `OP_0` padding when the encoding is a single
/// opcode (consensus `bad-cb-length` minimum of two bytes).
fn bip34_prefix(height: u64) -> Vec<u8> {
    let mut script = match height {
        0 => vec![0x00],
        1..=16 => vec![0x50 + height as u8],
        _ => {
            let mut num = height.to_le_bytes().to_vec();
            while num.last() == Some(&0) {
                num.pop();
            }
            if num.last().expect("non-zero height") & 0x80 != 0 {
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

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::{Amount, OutPoint, Script, TxIn, TxOut, Txid, Witness};
    use serde_json::json;

    const COMMITMENT_HEX: &str =
        "6a24aa21a9ed5d9e8c9a8f9d7f2e1c0b0a99887766554433221100ffeeddccbbaa";

    /// Coinbase-shaped tx for fixtures (mirrors bitcoin-rs build_coinbase).
    fn test_coinbase(script_sig: Vec<u8>, commitment: Option<&[u8]>) -> bitcoin::Transaction {
        let mut output = vec![TxOut {
            value: Amount::from_sat(50_0000_0000),
            script_pubkey: Script::from_bytes(&[0x51]).to_owned(),
        }];
        if let Some(commitment) = commitment {
            output.push(TxOut {
                value: Amount::ZERO,
                script_pubkey: Script::from_bytes(commitment).to_owned(),
            });
        }
        bitcoin::Transaction {
            version: bitcoin::transaction::Version::non_standard(2),
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([0; 32]), 0xffff_ffff),
                script_sig: Script::from_bytes(&script_sig).to_owned(),
                sequence: Sequence::MAX,
                witness: if commitment.is_some() {
                    Witness::from_slice(&[vec![0u8; 32].as_slice()])
                } else {
                    Witness::default()
                },
            }],
            output,
        }
    }

    fn gbt_fixture(txs: &[bitcoin::Transaction]) -> Value {
        json!({
            "version": 0x20000000u32,
            "bits": "207fffff",
            "curtime": 1_700_000_000u64,
            "previousblockhash": "00".repeat(32),
            "height": 1u64,
            "coinbasevalue": 5_000_000_000u64,
            "default_witness_commitment": COMMITMENT_HEX,
            "transactions": txs.iter().map(|tx|
                json!({"data": hex::encode(bitcoin::consensus::serialize(tx))})
            ).collect::<Vec<_>>(),
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

    /// Independent full-list merkle root (oracle for the branch).
    fn full_merkle_root(mut level: Vec<[u8; 32]>) -> [u8; 32] {
        while level.len() > 1 {
            if level.len() % 2 == 1 {
                level.push(*level.last().unwrap());
            }
            level = level.chunks(2).map(|p| dsha256(&p[0], &p[1])).collect();
        }
        level[0]
    }

    #[test]
    fn merkle_branch_folds_to_full_root_for_all_arities() {
        for count in 1..=6 {
            let txids: Vec<_> = fake_txs(count)
                .iter()
                .map(|tx| tx.compute_txid().to_byte_array())
                .collect();
            let branch = merkle_branch(txids.clone());
            let mut folded = txids[0];
            for sibling in &branch {
                folded = dsha256(&folded, sibling);
            }
            assert_eq!(folded, full_merkle_root(txids), "{count} txs");
        }
    }

    #[test]
    fn bip34_prefix_vectors() {
        assert_eq!(bip34_prefix(1), vec![0x51, 0x00], "OP_1 + OP_0 pad");
        assert_eq!(bip34_prefix(16), vec![0x60, 0x00], "OP_16 + OP_0 pad");
        assert_eq!(bip34_prefix(17), vec![0x01, 0x11]);
        assert_eq!(bip34_prefix(0x80), vec![0x02, 0x80, 0x00]);
        assert_eq!(bip34_prefix(256), vec![0x02, 0x00, 0x01]);
        assert_eq!(bip34_prefix(500_000), vec![0x03, 0x20, 0xa1, 0x07]);
    }

    #[test]
    fn gbt_fields_map_into_tdp_messages() {
        let state = TemplateState::from_gbt(7, &gbt_fixture(&fake_txs(3))).unwrap();

        let template = state.new_template_msg();
        assert_eq!(template.template_id, 7);
        assert!(template.future_template, "pool bootstrap gate requires it");
        assert_eq!(template.version, 0x2000_0000);
        assert_eq!(template.coinbase_tx_version, 2);
        assert_eq!(template.coinbase_prefix.as_ref(), &[0x51, 0x00]);
        assert_eq!(template.coinbase_tx_input_sequence, u32::MAX);
        assert_eq!(template.coinbase_tx_value_remaining, 5_000_000_000);
        assert_eq!(template.coinbase_tx_outputs_count, 1);
        // Serialized-TxOut list: 8 zero value bytes + compactsize + script.
        let script = hex::decode(COMMITMENT_HEX).unwrap();
        let mut expected = vec![0u8; 9];
        expected[8] = script.len() as u8;
        expected.extend_from_slice(&script);
        assert_eq!(template.coinbase_tx_outputs.as_ref(), &expected);
        assert_eq!(template.coinbase_tx_locktime, 0);
        assert_eq!(
            template.merkle_path.len(),
            2,
            "3 txs + coinbase -> 2 siblings"
        );

        let prev = state.set_new_prev_hash_msg();
        assert_eq!(prev.template_id, 7);
        assert_eq!(prev.prev_hash.as_bytes(), &[0u8; 32]);
        assert_eq!(prev.header_timestamp, 1_700_000_000);
        assert_eq!(prev.n_bits, 0x207f_ffff);
        assert_eq!(
            prev.target.as_bytes(),
            &bitcoin::pow::Target::from(CompactTarget::from_consensus(0x207f_ffff)).to_le_bytes()
        );
    }

    #[test]
    fn missing_commitment_yields_zero_outputs() {
        let mut gbt = gbt_fixture(&fake_txs(1));
        gbt["default_witness_commitment"] = Value::Null;
        let template = TemplateState::from_gbt(1, &gbt).unwrap().new_template_msg();
        assert_eq!(template.coinbase_tx_outputs_count, 0);
        assert!(template.coinbase_tx_outputs.as_ref().is_empty());
    }

    #[test]
    fn assembly_uses_solution_coinbase_and_template_branch() {
        let state = TemplateState::from_gbt(9, &gbt_fixture(&fake_txs(3))).unwrap();

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

        let block = state.assemble_block(&solution).unwrap();
        assert_eq!(block.txdata[0].compute_txid(), coinbase.compute_txid());
        assert_eq!(&block.txdata[1..], &state.txs[..]);
        // The assembled header must commit to the block it ships.
        assert_eq!(
            block.header.merkle_root,
            block.compute_merkle_root().expect("non-empty txdata")
        );
        assert_eq!(block.header.prev_blockhash.to_byte_array(), [0u8; 32]);
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
