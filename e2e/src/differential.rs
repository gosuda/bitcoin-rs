//! The differential lane: one pinned reference process, one candidate, and
//! the comparisons that turn two public processes into behavioral evidence.
//!
//! PRE: both processes are spawned through [`crate::node::ProcessNode`] and
//! answer only through their public RPC surface.
//! POST: every comparison here either passes with identical values or fails
//! with a typed difference that names both replies.
//! INVARIANT: no handler, type, or in-process state is ever consulted — the
//! reference is an independent binary, and a missing or substituted
//! reference binary is a typed failure that names the pinned digest.

use std::fs::File;
use std::path::Path;

use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin::hashes::{Hash as _, sha256};
use bitcoin::{Address, Block, Network, OutPoint};
use serde_json::{Value, json};

use crate::error::{Error, Result};
use crate::helpers;
use crate::node::ProcessNode;

/// Verify the reference binary at `path` matches the digest the compiled
/// `core-compat.toml` manifest pins.
///
/// PRE: `path` names a file the test claims is the pinned `bitcoind`.
/// POST: the file's SHA256 equals the manifest digest.
/// INVARIANT: a mismatch is a typed [`Error::Reference`] naming the pinned
/// digest; it is never a skipped check.
pub fn verify_reference_binary(path: &Path) -> Result<()> {
    let table: toml::Table = bitcoin_rs_rpc::manifest::MANIFEST_TOML
        .parse()
        .map_err(|error| Error::Protocol(format!("cannot parse core-compat.toml: {error}")))?;
    let expected = table
        .get("reference")
        .and_then(|reference| reference.get("release"))
        .and_then(|release| release.get("bitcoind_sha256"))
        .and_then(toml::Value::as_str)
        .ok_or_else(|| Error::Assertion("bitcoind_sha256 missing in core-compat.toml".into()))?
        .to_owned();
    let mut file = File::open(path).map_err(|error| Error::Reference {
        path: path.to_owned(),
        expected: expected.clone(),
        detail: error.to_string(),
    })?;
    let mut engine = sha256::Hash::engine();
    std::io::copy(&mut file, &mut engine)?;
    let actual = sha256::Hash::from_engine(engine);
    if actual.to_string() != expected {
        return Err(Error::Reference {
            path: path.to_owned(),
            expected,
            detail: format!("BLOCKED: actual SHA256 {actual}"),
        });
    }
    Ok(())
}

/// Exact comparison: callers choose deterministic observations; no fields vanish.
pub fn compare_reply(observation: &str, reference: &Value, candidate: &Value) -> Result<()> {
    if reference == candidate {
        Ok(())
    } else {
        Err(Error::Difference {
            observation: observation.to_owned(),
            reference: reference.clone(),
            candidate: candidate.clone(),
        })
    }
}

/// Call one method on both processes and require identical replies.
///
/// The reference and candidate calls are independent; running them
/// concurrently halves the serial request latency of every paired check.
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

/// Blocks and coinbase outpoints both processes agreed on.
#[derive(Debug)]
pub struct CommonFunds {
    /// Consensus-encoded block bytes, in height order.
    pub common_block_bytes: Vec<Vec<u8>>,
    /// The coinbase outpoint of each block, in height order.
    pub common_outpoints: Vec<OutPoint>,
}

/// Mine `blocks` blocks on Core, feed the identical bytes to the candidate,
/// and collect the shared coinbase funds.
///
/// PRE: both nodes are on regtest genesis.
/// POST: every block is accepted by the candidate and its coinbase
/// outpoint is recorded.
/// INVARIANT: block bytes come only from the independent reference process.
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
    let private = helpers::funding_key()?;
    let public = private.public_key(&bitcoin::secp256k1::Secp256k1::new());
    let address = Address::p2pkh(public, Network::Regtest);
    // Startup anchors the tip at genesis but applies the block only on the
    // first one-second sync tick (BlockSync::tick calls ensure_genesis_tip),
    // so no synchronous genesis apply exists to rely on here. A submit that
    // races the tick supplies the apply; one after it returns a duplicate
    // result string. Both orders converge on one applied genesis.
    let genesis = bitcoin::constants::genesis_block(Network::Regtest);
    node.rpc("submitblock", &json!([serialize_hex(&genesis)]))?;
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
        if Value::String(block.block_hash().to_string()) != *hash {
            return Err(Error::Protocol(
                "block hash differs from mining result".into(),
            ));
        }
        let accepted = node.rpc("submitblock", &json!([hex]))?;
        if !accepted.is_null() {
            return Err(Error::Protocol(format!(
                "submitblock rejected: {accepted}"
            )));
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
    /// Resolve only bytes returned by the independent Core process.
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

    /// A spend of the first common coinbase, signed under the deterministic
    /// funding key, paying `fee_sats` less to the same script.
    pub fn signed_spend(
        &self,
        fee_sats: u64,
        sequence: bitcoin::Sequence,
    ) -> Result<bitcoin::Transaction> {
        let (outpoint, output) = self.confirmed_output(0)?;
        let value = output
            .value
            .to_sat()
            .checked_sub(fee_sats)
            .ok_or_else(|| Error::Protocol("funding below fee".into()))?;
        let mut spend = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: outpoint,
                script_sig: bitcoin::ScriptBuf::new(),
                sequence,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(value),
                script_pubkey: output.script_pubkey.clone(),
            }],
        };
        helpers::sign_p2pkh_inputs(&mut spend, std::slice::from_ref(&output))?;
        Ok(spend)
    }
}
