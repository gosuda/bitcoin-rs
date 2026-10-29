//! The differential lane: one pinned reference process and one candidate.

use std::path::Path;

use bitcoin::consensus::encode::deserialize_hex;
use bitcoin::{Block, OutPoint};
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, Value, json};

use crate::error::{Error, Result};
use crate::helpers;
use crate::node::ProcessNode;

pub fn verify_reference_binary(path: &Path) -> Result<()> {
    let expected = crate::node::manifest_reference_sha256()?;
    let actual = crate::node::file_sha256(path).map_err(|error| Error::Reference {
        path: path.to_owned(),
        expected: expected.clone(),
        detail: error.to_string(),
    })?;
    if actual != expected {
        return Err(Error::Reference {
            path: path.to_owned(),
            expected,
            detail: format!("BLOCKED: actual SHA256 {actual}"),
        });
    }
    Ok(())
}

pub fn compare_reply(observation: &str, reference: &Value, candidate: &Value) -> Result<()> {
    if equivalent(reference, candidate) {
        Ok(())
    } else {
        Err(Error::Difference {
            observation: observation.to_owned(),
            reference: reference.clone(),
            candidate: candidate.clone(),
        })
    }
}

/// Compares two replies for equivalence.
///
/// Integral JSON numbers compare exactly, because `f64` cannot separate them
/// above 2^53. Floats compare within one ULP: Core prints doubles with 16
/// significant digits, so a value at the edge of that grid parses back one ULP
/// away from ours. Everything else compares strictly.
fn equivalent(reference: &Value, candidate: &Value) -> bool {
    if reference.is_number() && candidate.is_number() {
        if let (Some(left), Some(right)) = (integral(reference), integral(candidate)) {
            return left == right;
        }
        if let (Some(left), Some(right)) = (reference.as_f64(), candidate.as_f64()) {
            return within_one_ulp(left, right);
        }
    }
    if let (Some(left), Some(right)) = (reference.as_object(), candidate.as_object()) {
        return left.len() == right.len()
            && left.iter().all(|(key, value)| {
                right
                    .get(&key)
                    .is_some_and(|other| equivalent(value, other))
            });
    }
    if let (Some(left), Some(right)) = (reference.as_array(), candidate.as_array()) {
        return left.len() == right.len()
            && left
                .iter()
                .zip(right.iter())
                .all(|(value, other)| equivalent(value, other));
    }
    reference == candidate
}

/// Returns the exact integer an integral JSON number carries.
fn integral(value: &Value) -> Option<i128> {
    value
        .as_i64()
        .map(i128::from)
        .or_else(|| value.as_u64().map(i128::from))
}

fn within_one_ulp(left: f64, right: f64) -> bool {
    if left.to_bits() == right.to_bits() {
        return true;
    }
    if !left.is_finite() || !right.is_finite() {
        return false;
    }
    let ordered = |value: f64| -> i128 {
        let bits = i128::from(value.to_bits());
        if value.is_sign_negative() {
            -bits
        } else {
            bits
        }
    };
    (ordered(left) - ordered(right)).abs() <= 1
}

#[expect(
    clippy::expect_used,
    reason = "a scoped differential request thread panicking is a harness bug"
)]
pub fn compare_rpc(
    core: &mut ProcessNode,
    node: &mut ProcessNode,
    method: &str,
    params: &Value,
) -> Result<Value> {
    let (reference, candidate) = std::thread::scope(|scope| {
        let reference = scope.spawn(|| core.rpc(method, params));
        let candidate = scope.spawn(|| node.rpc(method, params));
        (
            reference.join().expect("reference request panicked"),
            candidate.join().expect("candidate request panicked"),
        )
    });
    let reference = reference?;
    let candidate = candidate?;
    compare_reply(method, &reference, &candidate)?;
    Ok(reference)
}

#[derive(Debug)]
pub struct CommonFunds {
    pub common_block_bytes: Vec<Vec<u8>>,
    pub common_outpoints: Vec<OutPoint>,
}

pub fn mine_common_chain(
    core: &mut ProcessNode,
    node: &mut ProcessNode,
    blocks: u32,
) -> Result<CommonFunds> {
    if blocks == 0 || blocks > 102 {
        return Err(Error::Protocol(
            "common funding bound is 1..=102 blocks".into(),
        ));
    }
    let address = helpers::funding_address()?;
    helpers::submit_genesis(node)?;
    let hashes = core.rpc("generatetoaddress", &json!([blocks, address.to_string()]))?;
    let hashes = hashes
        .as_array()
        .ok_or_else(|| Error::Protocol("mining result is not an array".into()))?;
    if hashes.len()
        != usize::try_from(blocks).map_err(|error| Error::Protocol(error.to_string()))?
    {
        return Err(Error::Protocol(
            "mining returned the wrong block count".into(),
        ));
    }
    let mut funds = CommonFunds {
        common_block_bytes: Vec::new(),
        common_outpoints: Vec::new(),
    };
    for hash in hashes {
        let hex = core.rpc("getblock", &json!([hash, 0]))?;
        let hex = hex
            .as_str()
            .ok_or_else(|| Error::Protocol("getblock did not return hex".into()))?;
        let block: Block =
            deserialize_hex(hex).map_err(|error| Error::Protocol(error.to_string()))?;
        if json!(block.block_hash().to_string()) != *hash {
            return Err(Error::Protocol(
                "block hash differs from mining result".into(),
            ));
        }
        let accepted = node.rpc("submitblock", &json!([hex]))?;
        if !accepted.is_null() {
            return Err(Error::Protocol(format!("submitblock rejected: {accepted}")));
        }
        let coinbase = block
            .txdata
            .first()
            .ok_or_else(|| Error::Protocol("block has no coinbase".into()))?;
        funds
            .common_outpoints
            .push(OutPoint::new(coinbase.compute_txid(), 0));
        funds
            .common_block_bytes
            .push(bitcoin::consensus::serialize(&block));
    }
    Ok(funds)
}

impl CommonFunds {
    pub fn confirmed_output(&self, index: usize) -> Result<(OutPoint, bitcoin::TxOut)> {
        let bytes = self
            .common_block_bytes
            .get(index)
            .ok_or_else(|| Error::Protocol("missing funding block".into()))?;
        let block: Block = bitcoin::consensus::deserialize(bytes)
            .map_err(|error| Error::Protocol(error.to_string()))?;
        let coinbase = block
            .txdata
            .first()
            .ok_or_else(|| Error::Protocol("missing coinbase".into()))?;
        let output = coinbase
            .output
            .first()
            .ok_or_else(|| Error::Protocol("missing coinbase output".into()))?;
        Ok((OutPoint::new(coinbase.compute_txid(), 0), output.clone()))
    }

    pub fn signed_spend(
        &self,
        fee_sats: u64,
        sequence: bitcoin::Sequence,
    ) -> Result<bitcoin::Transaction> {
        let (outpoint, output) = self.confirmed_output(0)?;
        if output.value.to_sat() < fee_sats {
            return Err(Error::Protocol("funding below fee".into()));
        }
        let mut spend =
            helpers::raw_spend_to(outpoint, &output, fee_sats, sequence, &output.script_pubkey);
        helpers::sign_p2pkh_inputs(&mut spend, std::slice::from_ref(&output))?;
        Ok(spend)
    }
}

#[cfg(test)]
#[expect(clippy::expect_used, reason = "test assertions")]
mod tests {
    use super::equivalent;
    use sonic_rs::{json, to_value};

    #[test]
    fn integers_beyond_f64_precision_compare_exactly() {
        let lower = json!(9_007_199_254_740_992_u64);
        let upper = json!(9_007_199_254_740_993_u64);
        assert_ne!(lower, upper);
        assert!(!equivalent(&lower, &upper));
        assert!(equivalent(&lower, &lower));
        assert!(!equivalent(
            &json!(-9_007_199_254_740_992_i64),
            &json!(-9_007_199_254_740_993_i64)
        ));
    }

    #[test]
    fn floats_one_ulp_apart_are_equivalent() {
        let lower = to_value(&4.656_542_373_906_924_7e-10_f64).expect("lower value");
        let upper = to_value(&4.656_542_373_906_925e-10_f64).expect("upper value");
        assert_ne!(lower, upper);
        assert!(equivalent(&lower, &upper));
        assert!(!equivalent(&json!(1.5), &json!(2.5)));
    }

    #[test]
    fn nested_values_use_the_same_rules() {
        let reference = json!({
            "height": 9_007_199_254_740_992_u64,
            "difficulty": 4.656_542_373_906_924_7e-10_f64,
            "tx": [{"weight": 3_012_u64}],
        });
        let mut candidate = reference.clone();
        candidate["difficulty"] = json!(4.656_542_373_906_925e-10_f64);
        assert!(equivalent(&reference, &candidate));
        candidate["tx"][0]["weight"] = json!(3_013_u64);
        assert!(!equivalent(&reference, &candidate));
    }
}
