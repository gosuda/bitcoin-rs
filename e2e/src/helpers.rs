//! Transaction, block, and chain helpers for scenario tests.

use std::time::Duration;

use bitcoin::absolute::LockTime;
use bitcoin::block::{Header, Version as BlockVersion};
use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin::hashes::Hash as _;
use bitcoin::script::{Builder, PushBytesBuf, Script};
use bitcoin::secp256k1::{Message, Secp256k1};
use bitcoin::sighash::{EcdsaSighashType, SighashCache};
use bitcoin::transaction::Version as TxVersion;
use bitcoin::{
    Address, Amount, Block, BlockHash, CompactTarget, Network, OutPoint, PrivateKey, ScriptBuf,
    Sequence, Target, Transaction, TxIn, TxMerkleNode, TxOut, WPubkeyHash, Witness,
};
use serde_json::{Value, json};

use crate::error::{Error, Result};
use crate::node::{Kind, ProcessNode, SpawnOptions};

/// Regtest block subsidy in satoshis (50 BTC).
pub const REGTEST_SUBSIDY_SATS: u64 = 50 * 100_000_000;
/// Blocks until a coinbase is spendable on regtest.
pub const COINBASE_MATURITY: u32 = 100;
/// Fixed regtest funding key: deterministic, unrelated to any wallet.
const FUNDING_SECRET: [u8; 32] = [1_u8; 32];

/// The deterministic funding key used across scenarios.
pub fn funding_key() -> Result<PrivateKey> {
    let secret = bitcoin::secp256k1::SecretKey::from_slice(&FUNDING_SECRET)
        .map_err(|e| Error::Assertion(e.to_string()))?;
    Ok(PrivateKey::new(secret, Network::Regtest))
}

/// P2PKH address owned by the funding key (spendable via [`signed_spend`]).
pub fn funding_address() -> Result<Address> {
    let key = funding_key()?;
    Ok(Address::p2pkh(
        key.public_key(&Secp256k1::new()),
        Network::Regtest,
    ))
}

/// A fresh bech32 address owned by nobody in particular — used as a sink.
#[must_use]
pub fn sink_script() -> ScriptBuf {
    ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([2; 20]))
}

/// The regtest genesis block.
#[must_use]
pub fn genesis_block() -> Block {
    bitcoin::constants::genesis_block(Network::Regtest)
}

/// Ensure genesis is applied: a submit that races the startup sync tick may
/// apply it, or may answer "duplicate" once the tick already has.
pub fn submit_genesis(node: &mut ProcessNode) -> Result<()> {
    let hex = serialize_hex(&genesis_block());
    let result = node.rpc("submitblock", &json!([hex]))?;
    if result.is_null() || result.as_str() == Some("duplicate") {
        Ok(())
    } else {
        Err(Error::Assertion(format!("submitblock(genesis): {result}")))
    }
}

/// Mine `count` blocks paying an `OP_TRUE` coinbase so outputs are spendable
/// without signatures.
pub fn mine_bare_blocks(node: &mut ProcessNode, count: u32) -> Result<Vec<String>> {
    mine_blocks_to(node, count, "raw(51)")
}

/// Mine `count` blocks paying `descriptor`.
///
/// A distinct coinbase script produces a distinct block hash at each
/// height, which lets reorg tests prove a regenerated branch diverged
/// rather than reproduce the old one.
pub fn mine_blocks_to(node: &mut ProcessNode, count: u32, descriptor: &str) -> Result<Vec<String>> {
    let mut hashes = Vec::new();
    for _ in 0..count {
        let result = node.rpc("generateblock", &json!([descriptor, []]))?;
        let hash = result
            .get("hash")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Assertion(format!("generateblock reply: {result}")))?;
        hashes.push(hash.to_owned());
    }
    Ok(hashes)
}

/// Fetch the coinbase transaction of the block at `height`.
pub fn coinbase_at(node: &mut ProcessNode, height: u64) -> Result<Transaction> {
    let hash = node
        .rpc("getblockhash", &json!([height]))?
        .as_str()
        .ok_or_else(|| Error::Assertion("getblockhash did not return a string".into()))?
        .to_owned();
    let block = node.rpc("getblock", &json!([hash, 2]))?;
    let txs = block
        .get("tx")
        .and_then(Value::as_array)
        .ok_or_else(|| Error::Assertion("getblock(2) lacks tx array".into()))?;
    let first = txs
        .first()
        .ok_or_else(|| Error::Assertion("block lacks coinbase".into()))?;
    let hex = first
        .get("hex")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Assertion("coinbase lacks hex".into()))?;
    deserialize_hex(hex).map_err(|e| Error::Assertion(format!("coinbase decode: {e}")))
}

/// Read output 0 of a coinbase as the funding outpoint — `(txid, 0)` plus
/// its `TxOut`. The output script is not inspected: callers must ensure the
/// coinbase pays the script they intend to spend.
pub fn funding_output(coinbase: &Transaction) -> Result<(OutPoint, TxOut)> {
    let output = coinbase
        .output
        .first()
        .ok_or_else(|| Error::Assertion("coinbase has no outputs".into()))?
        .clone();
    Ok((OutPoint::new(coinbase.compute_txid(), 0), output))
}

/// Mine `COINBASE_MATURITY + 1` blocks on a fresh genesis chain so the
/// first coinbase is spendable, then return its funding outpoint.
pub fn mature_funding(node: &mut ProcessNode) -> Result<(OutPoint, TxOut)> {
    submit_genesis(node)?;
    let _ = mine_bare_blocks(node, COINBASE_MATURITY + 1)?;
    let coinbase = coinbase_at(node, 1)?;
    funding_output(&coinbase)
}

/// An `OP_TRUE` script — spendable by anyone with an empty scriptSig.
#[must_use]
pub fn op_true_script() -> ScriptBuf {
    Builder::new().push_int(1).into_script()
}

/// Build an unsigned spend of `outpoint`/`prevout` paying `dest` minus
/// `fee_sats`. Works for both `OP_TRUE` and signed prevouts.
#[must_use]
pub fn raw_spend_to(
    outpoint: OutPoint,
    prevout: &TxOut,
    fee_sats: u64,
    sequence: Sequence,
    dest: &Script,
) -> Transaction {
    let value = prevout.value.to_sat().saturating_sub(fee_sats);
    Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: outpoint,
            script_sig: ScriptBuf::new(),
            sequence,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: dest.to_owned(),
        }],
    }
}

/// Build an unsigned spend of `outpoint`/`prevout` paying `sink_script()`
/// minus `fee_sats`. Works for both `OP_TRUE` and signed prevouts.
#[must_use]
pub fn raw_spend(
    outpoint: OutPoint,
    prevout: &TxOut,
    fee_sats: u64,
    sequence: Sequence,
) -> Transaction {
    raw_spend_to(outpoint, prevout, fee_sats, sequence, &sink_script())
}

/// An unsigned spend of an `OP_TRUE` coinbase: valid with an empty scriptSig.
#[must_use]
pub fn spend_anyone(outpoint: OutPoint, prevout: &TxOut, fee_sats: u64) -> Transaction {
    raw_spend(outpoint, prevout, fee_sats, Sequence::MAX)
}

/// A signed P2PKH spend of `outpoint`/`prevout` under the funding key.
pub fn signed_spend(
    outpoint: OutPoint,
    prevout: &TxOut,
    fee_sats: u64,
    sequence: Sequence,
) -> Result<Transaction> {
    let mut tx = raw_spend(outpoint, prevout, fee_sats, sequence);
    sign_p2pkh_inputs(&mut tx, std::slice::from_ref(prevout))?;
    Ok(tx)
}

/// Sign every input of `tx` against `prevouts` as P2PKH under the funding key.
pub fn sign_p2pkh_inputs(tx: &mut Transaction, prevouts: &[TxOut]) -> Result<()> {
    if tx.input.len() != prevouts.len() {
        return Err(Error::Assertion("input/prevout count mismatch".into()));
    }
    let key = funding_key()?;
    let secp = Secp256k1::new();
    for (index, output) in prevouts.iter().enumerate() {
        let sighash = SighashCache::new(&*tx)
            .legacy_signature_hash(index, &output.script_pubkey, EcdsaSighashType::All.to_u32())
            .map_err(|e| Error::Assertion(e.to_string()))?;
        let signature = bitcoin::ecdsa::Signature::sighash_all(
            secp.sign_ecdsa(&Message::from_digest(sighash.to_byte_array()), &key.inner),
        );
        let signature = PushBytesBuf::try_from(signature.to_vec())
            .map_err(|e| Error::Assertion(e.to_string()))?;
        tx.input[index].script_sig = Builder::new()
            .push_slice(signature)
            .push_key(&key.public_key(&secp))
            .into_script();
    }
    Ok(())
}

/// Serialize a transaction to hex for `sendrawtransaction`.
#[must_use]
pub fn tx_hex(tx: &Transaction) -> String {
    serialize_hex(tx)
}

/// Assemble a full [`Block`] from a `getblocktemplate` reply and grind its
/// `PoW`.
///
/// The coinbase pays `coinbase_script`, so the reward is spendable exactly
/// as the caller intends; the default witness commitment output is included
/// when the template provides one.
pub fn assemble_block_from_template(template: &Value, coinbase_script: &Script) -> Result<Block> {
    let prev_hex = template
        .get("previousblockhash")
        .and_then(Value::as_str)
        .ok_or_else(|| Error::Assertion("template lacks previousblockhash".into()))?;
    let height = u32::try_from(
        template
            .get("height")
            .and_then(Value::as_u64)
            .ok_or_else(|| Error::Assertion("template lacks height".into()))?,
    )
    .map_err(|e| Error::Assertion(e.to_string()))?;
    let coinbase_value = template
        .get("coinbasevalue")
        .and_then(Value::as_u64)
        .ok_or_else(|| Error::Assertion("template lacks coinbasevalue".into()))?;
    let bits = CompactTarget::from_unprefixed_hex(
        template
            .get("bits")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Assertion("template lacks bits".into()))?,
    )
    .map_err(|e| Error::Assertion(e.to_string()))?;
    let curtime = u32::try_from(
        template
            .get("curtime")
            .and_then(Value::as_u64)
            .ok_or_else(|| Error::Assertion("template lacks curtime".into()))?,
    )
    .map_err(|e| Error::Assertion(e.to_string()))?;
    let version = i32::try_from(
        template
            .get("version")
            .and_then(Value::as_u64)
            .ok_or_else(|| Error::Assertion("template lacks version".into()))?,
    )
    .map_err(|e| Error::Assertion(e.to_string()))?;

    let mut txs = Vec::new();
    if let Some(entries) = template.get("transactions").and_then(Value::as_array) {
        for entry in entries {
            let data = entry
                .get("data")
                .and_then(Value::as_str)
                .ok_or_else(|| Error::Assertion("template tx lacks data".into()))?;
            txs.push(
                deserialize_hex::<Transaction>(data)
                    .map_err(|e| Error::Assertion(format!("template tx decode: {e}")))?,
            );
        }
    }

    let mut outputs = vec![TxOut {
        value: Amount::from_sat(coinbase_value),
        script_pubkey: coinbase_script.to_owned(),
    }];
    if let Some(commitment_hex) = template
        .get("default_witness_commitment")
        .and_then(Value::as_str)
    {
        outputs.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_hex(commitment_hex)
                .map_err(|e| Error::Assertion(e.to_string()))?,
        });
    }
    let coinbase = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: coinbase_script_sig(height),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[[0u8; 32]]),
        }],
        output: outputs,
    };
    let mut txdata = Vec::with_capacity(txs.len() + 1);
    txdata.push(coinbase);
    txdata.extend(txs);
    let mut block = Block {
        header: Header {
            version: BlockVersion::from_consensus(version),
            prev_blockhash: prev_hex
                .parse::<BlockHash>()
                .map_err(|e| Error::Assertion(e.to_string()))?,
            merkle_root: TxMerkleNode::all_zeros(),
            time: curtime,
            bits,
            nonce: 0,
        },
        txdata,
    };
    block.header.merkle_root = block
        .compute_merkle_root()
        .ok_or_else(|| Error::Assertion("empty block lacks merkle root".into()))?;
    grind_pow(&mut block.header)?;
    Ok(block)
}

fn coinbase_script_sig(height: u32) -> ScriptBuf {
    let mut builder = Builder::new().push_int(i64::from(height));
    if builder.as_bytes().len() < 2 {
        builder = builder.push_int(0);
    }
    builder.into_script()
}

/// Brute-force a regtest nonce until the header meets its target.
pub fn grind_pow(header: &mut Header) -> Result<()> {
    let target = Target::from(header.bits);
    loop {
        if target.is_met_by(header.block_hash()) {
            return Ok(());
        }
        header.nonce = header
            .nonce
            .checked_add(1)
            .ok_or_else(|| Error::Assertion("nonce space exhausted".into()))?;
    }
}

/// Spin up a pinned Core peer and a bitcoin-rs node connected to it.
///
/// Returns `(core, node)`; the node is started with `--connect <core p2p>`.
pub fn spawn_synced_pair(core_blocks: u32) -> Result<(ProcessNode, ProcessNode)> {
    let mut core = ProcessNode::spawn(Kind::Core)?;
    let connect = format!("--connect=127.0.0.1:{}", core.p2p_addr.port());
    let mut node = ProcessNode::spawn_with(
        Kind::BitcoinRs,
        &SpawnOptions {
            extra_args: &[connect.as_str()],
            ..SpawnOptions::default()
        },
    )?;
    if core_blocks > 0 {
        let address = funding_address()?.to_string();
        core.rpc("generatetoaddress", &json!([core_blocks, address]))?;
        node.wait_block_count(u64::from(core_blocks), Duration::from_secs(90))?;
    }
    Ok((core, node))
}

/// Read a whole mempool's txid set.
pub fn mempool_txids(node: &mut ProcessNode) -> Result<Vec<String>> {
    node.rpc("getrawmempool", &json!([]))?
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .ok_or_else(|| Error::Assertion("getrawmempool is not an array".into()))
}

/// Poll until `txid` appears in the node's mempool.
pub fn wait_for_mempool_tx(node: &mut ProcessNode, txid: &str, timeout: Duration) -> Result<()> {
    node.wait_for("mempool tx", timeout, |node| {
        Ok(mempool_txids(node)?
            .iter()
            .any(|id| id == txid)
            .then_some(()))
    })
}
