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
/// Blocks until a coinbase is spendable.
pub use bitcoin::constants::COINBASE_MATURITY;
/// Fixed regtest funding key: deterministic, unrelated to any wallet.
const FUNDING_SECRET: [u8; 32] = [1_u8; 32];

/// The deterministic funding key used across scenarios.
fn funding_key() -> Result<PrivateKey> {
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

/// The sink every unsigned test spend pays: owned by nobody in particular.
fn sink_script() -> ScriptBuf {
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

/// An unsigned spend of an `OP_TRUE` coinbase: valid with an empty scriptSig.
#[must_use]
pub fn spend_anyone(outpoint: OutPoint, prevout: &TxOut, fee_sats: u64) -> Transaction {
    raw_spend_to(outpoint, prevout, fee_sats, Sequence::MAX, &sink_script())
}

/// A signed P2PKH spend of `outpoint`/`prevout` under the funding key.
pub fn signed_spend(
    outpoint: OutPoint,
    prevout: &TxOut,
    fee_sats: u64,
    sequence: Sequence,
) -> Result<Transaction> {
    let mut tx = raw_spend_to(outpoint, prevout, fee_sats, sequence, &sink_script());
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

/// BIP34 coinbase `script_sig` for `height`, padded to the two-byte minimum
/// the consensus coinbase-size rule requires.
#[must_use]
pub fn coinbase_script_sig(height: u32) -> ScriptBuf {
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

/// The coinbase `script_sig`: `height` in little-endian significant bytes,
/// then a single-byte `tag` push that separates competing branches.
fn bip34_script_sig(height: u32, tag: u8) -> Vec<u8> {
    let le = height.to_le_bytes();
    let used = le
        .iter()
        .rposition(|byte| *byte != 0)
        .map_or(1, |last| last + 1);
    let mut script = Vec::with_capacity(used + 3);
    script.push(u8::try_from(used).unwrap_or(1));
    script.extend_from_slice(&le[..used]);
    script.extend_from_slice(&[0x01, tag]);
    script
}

/// Builds a BIP141 segwit coinbase-only block on `parent`.
///
/// The coinbase carries the 32-byte reserved nonce in its input witness and an
/// `OP_RETURN` commitment output (`aa21a9ed`), so the body binds to the header
/// only when witness data is intact. `tag` separates competing branches so
/// coinbases (and therefore txids and headers) differ across forks at equal
/// heights.
#[must_use]
pub fn segwit_coinbase_block(parent: &Block, height: u32, tag: u8) -> Block {
    let reserved = [tag; 32];
    // Coinbase-only tree: witness leaf 0 is zeroed out, so the wtxid merkle
    // root is exactly [0;32]; commitment = sha256d(root || reserved).
    let mut buffer = [0_u8; 64];
    buffer[32..].copy_from_slice(&reserved);
    let commitment = bitcoin::hashes::sha256d::Hash::hash(&buffer).to_byte_array();
    let mut commit_script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    commit_script.extend_from_slice(&commitment);
    let coinbase = Transaction {
        version: TxVersion::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::from_bytes(bip34_script_sig(height, tag)),
            sequence: Sequence::MAX,
            witness: Witness::from_slice(&[&reserved[..]]),
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(REGTEST_SUBSIDY_SATS),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            },
            TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::from_bytes(commit_script),
            },
        ],
    };
    let mut block = Block {
        header: Header {
            version: parent.header.version,
            prev_blockhash: parent.block_hash(),
            merkle_root: parent.header.merkle_root,
            time: parent.header.time.saturating_add(1),
            bits: parent.header.bits,
            nonce: 0,
        },
        txdata: vec![coinbase],
    };
    if let Some(root) = block.compute_merkle_root() {
        block.header.merkle_root = root;
    }
    assert!(
        grind_pow(&mut block.header).is_ok(),
        "segwit coinbase nonce space exhausted"
    );
    block
}

/// Builds a chain of `count` segwit coinbase blocks extending `parent`; each
/// block carries a distinct tag so competing branches never collide.
#[must_use]
pub fn build_chain(parent: &Block, count: u32, tag: u8, start_height: u32) -> Vec<Block> {
    let mut chain = Vec::with_capacity(usize::try_from(count).unwrap_or(64));
    let mut prev = parent.clone();
    for index in 0..count {
        let tag = tag.wrapping_add(u8::try_from(index).unwrap_or(0));
        let block = segwit_coinbase_block(&prev, start_height + index, tag);
        prev = block.clone();
        chain.push(block);
    }
    chain
}

/// The node's applied height.
pub fn block_count(node: &mut ProcessNode) -> Result<u64> {
    Ok(node
        .rpc("getblockcount", &json!([]))?
        .as_u64()
        .unwrap_or(u64::MAX))
}

/// The node's applied tip hash, hex.
pub fn best_hash(node: &mut ProcessNode) -> Result<String> {
    Ok(node
        .rpc("getbestblockhash", &json!([]))?
        .as_str()
        .unwrap_or("")
        .to_owned())
}

/// The node's live peer count.
pub fn connection_count(node: &mut ProcessNode) -> Result<u64> {
    Ok(node
        .rpc("getconnectioncount", &json!([]))?
        .as_u64()
        .unwrap_or(u64::MAX))
}

/// Polls `check` every 200ms until it holds or `dur` elapses.
pub fn wait_for(dur: Duration, check: &mut dyn FnMut() -> bool) -> bool {
    let deadline = std::time::Instant::now() + dur;
    while std::time::Instant::now() < deadline {
        if check() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    false
}

/// The node's stderr evidence so far.
#[must_use]
pub fn node_stderr(node: &ProcessNode) -> String {
    std::fs::read_to_string(node.evidence.join("stderr.log")).unwrap_or_default()
}

/// Asserts the node's stderr shows no panic and no `PrevHashMismatch` —
/// `context` names where a mismatch would indicate commit churn.
pub fn assert_clean_stderr(node: &ProcessNode, context: &str) {
    let stderr = node_stderr(node);
    assert_eq!(
        stderr.matches("panic").count(),
        0,
        "node stderr contains a panic"
    );
    assert_eq!(
        stderr.matches("PrevHashMismatch").count(),
        0,
        "node stderr shows PrevHashMismatch: {context}"
    );
}
