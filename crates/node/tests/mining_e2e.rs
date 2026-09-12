//! Mining E2E: template → external-style assembly → submitblock → tip.
//!
//! The test drives the production RPC handlers (`getblocktemplate`,
//! `submitblock`) exactly like an external miner: the block is assembled from
//! rendered template JSON fields only, then enters ordinary validation.

use anyhow::{Result, bail};

use bitcoin_rs_mempool::{
    AdmissionOrigin, MempoolGateway, MempoolObserver, MutationEnvelope, MutationOutcome,
    SubmitOutcome,
};

use bitcoin_rs_mining::MiningControl;

use bitcoin_rs_node::{MiningCoordinator, Network, NodeConfig, state::NodeState};

use bitcoin_rs_primitives::{
    Amount, Block, CompactTarget, Hash256, LockTime, OutPoint, Script, Sequence, Tx, TxIn, TxOut,
    Txid, Witness, consensus_bytes, deserialize as native_deserialize, encode::double_sha256,
};

use bitcoin_rs_rpc::{
    Handler,
    context::{
        ChainAdmissionView, ChainHandles, Context, ContextHandles, IndexHandles, MempoolHandles,
        MiningHandles, NetworkHandles,
    },
};

use bitcoin_rs_utxo::UtxoSet;

use parking_lot::Mutex;

use sonic_rs::{JsonContainerTrait as _, JsonValueTrait, json};

use std::sync::Arc;

const SEED_BLOCKS: u32 = 100;
const SEED_BASE_TIME: u32 = 1_296_688_603;
const SEED_BLOCK_INTERVAL: u32 = 600;
const REGTEST_BITS: u32 = 0x207f_ffff;
const REGTEST_SUBSIDY_SATS: u64 = 50 * 100_000_000;
const MEMPOOL_TX_FEE_SATS: u64 = 10_000;
/// BIP141 witness reserved value committed by the mined coinbase.
const WITNESS_RESERVED: [u8; 32] = [0_u8; 32];

#[test]
fn template_mines_to_tip_and_drains_mempool() -> Result<()> {
    let (state, _guard) = open_regtest()?;
    apply_genesis(&state)?;
    let seed_tip_hash = seed_chain(&state, SEED_BLOCKS)?;

    // A spend of the height-1 seed coinbase matures exactly at height 101.
    let mempool_tx = seed_coinbase_spend();
    admit_to_mempool(&state, &mempool_tx)?;

    let handler = mining_handler(&state);

    // --- getblocktemplate over the real RPC handler --------------------------
    let template = handler.dispatch("getblocktemplate", &json!([{"rules": ["segwit"]}]))?;
    let prev_hex = required_str(&template, "previousblockhash")?;
    let height = required_u64(&template, "height")?;
    assert_eq!(
        height,
        u64::from(SEED_BLOCKS + 1),
        "template height must extend the applied tip"
    );
    assert_eq!(
        prev_hex,
        seed_tip_hash.to_string_be(),
        "template must build on the applied tip"
    );

    let template_txs = template
        .get("transactions")
        .and_then(|entry| entry.as_array())
        .map_or(&[][..], |entries| entries.as_slice());
    assert_eq!(template_txs.len(), 1, "the mempool tx must be selected");
    let template_txid = template_txs[0]
        .get("txid")
        .and_then(|value| value.as_str())
        .ok_or_else(|| anyhow::anyhow!("template transaction missing txid"))?;
    assert_eq!(
        template_txid,
        mempool_tx.txid().to_string(),
        "the selected template tx must be the mempool tx"
    );

    // --- rendered BIP22/BIP23 template fields -----------------------------
    assert_eq!(
        required_u64(&template, "coinbasevalue")?,
        REGTEST_SUBSIDY_SATS + MEMPOOL_TX_FEE_SATS,
        "coinbasevalue must be subsidy plus selected fees"
    );
    let entry = &template_txs[0];
    assert_eq!(
        required_u64(entry, "fee")?,
        MEMPOOL_TX_FEE_SATS,
        "rendered fee must match the mempool fee"
    );
    assert_eq!(
        required_u64(entry, "weight")?,
        mempool_tx.weight(),
        "rendered weight must match the transaction weight"
    );
    assert_eq!(
        required_u64(entry, "sigops")?,
        0,
        "p2sh-true spend has no legacy sigops"
    );
    let depends = entry
        .get("depends")
        .and_then(|value| value.as_array())
        .map_or(&[][..], |entries| entries.as_slice());
    assert!(depends.is_empty(), "single tx has no in-template dependencies");
    assert_eq!(
        required_str(entry, "hash")?,
        mempool_tx.wtxid().to_string(),
        "rendered hash is the wtxid"
    );
    assert_eq!(
        native_deserialize::<Tx>(&hex_decode(&required_str(entry, "data")?)?)?,
        mempool_tx,
        "rendered data round-trips to the mempool tx"
    );
    assert_eq!(required_u64(&template, "sigoplimit")?, 80_000);
    assert_eq!(required_u64(&template, "sizelimit")?, 4_000_000);
    assert_eq!(required_u64(&template, "weightlimit")?, 4_000_000);
    let long_poll_id = required_str(&template, "longpollid")?;
    assert!(long_poll_id.len() > 64, "longpollid carries tip hash and sequence");
    assert!(
        long_poll_id.starts_with(&seed_tip_hash.to_string_be()),
        "longpollid begins with the applied tip hash"
    );
    long_poll_id[64..]
        .parse::<u64>()
        .map_err(|_| anyhow::anyhow!("longpollid suffix must be the mempool sequence"))?;
    let mutable = template
        .get("mutable")
        .and_then(|value| value.as_array())
        .map_or(&[][..], |entries| entries.as_slice());
    let mutables: Vec<&str> = mutable
        .iter()
        .filter_map(|value| value.as_str())
        .collect();
    for expected in ["time", "transactions", "prevblock"] {
        assert!(mutables.contains(&expected), "mutable must contain {expected}");
    }
    let capabilities = template
        .get("capabilities")
        .and_then(|value| value.as_array())
        .map_or(&[][..], |entries| entries.as_slice());
    let capability_set: Vec<&str> = capabilities
        .iter()
        .filter_map(|value| value.as_str())
        .collect();
    for expected in ["proposal", "longpoll"] {
        assert!(
            capability_set.contains(&expected),
            "capabilities must contain {expected}"
        );
    }
    let rules = template
        .get("rules")
        .and_then(|value| value.as_array())
        .map_or(&[][..], |entries| entries.as_slice());
    let rule_set: Vec<&str> = rules.iter().filter_map(|value| value.as_str()).collect();
    assert!(rule_set.contains(&"!segwit"), "segwit is a mandatory rule on regtest");
    assert_eq!(required_str(&template, "noncerange")?, "00000000ffffffff");
    assert!(
        required_u64(&template, "mintime")? <= required_u64(&template, "curtime")?,
        "mintime must not exceed curtime"
    );
    let coinbase_aux = template
        .get("coinbaseaux")
        .ok_or_else(|| anyhow::anyhow!("coinbaseaux must be present"))?;
    assert!(coinbase_aux.is_object(), "coinbaseaux must be an object");
    let flags = coinbase_aux
        .get("flags")
        .and_then(|value| value.as_str())
        .ok_or_else(|| anyhow::anyhow!("coinbaseaux.flags missing"))?;
    assert!(flags.is_empty(), "coinbaseaux.flags is the empty hex string");
    let commitment = required_str(&template, "default_witness_commitment")?;
    assert!(
        commitment.starts_with(&"6a24aa21a9ed"),
        "default witness commitment carries the BIP141 commitment prefix"
    );
    let expected_root = compute_witness_merkle_root(std::slice::from_ref(&mempool_tx))
        .ok_or_else(|| anyhow::anyhow!("single-tx witness merkle root must exist"))?;
    let mut commitment_input = [0_u8; 64];
    commitment_input[..32].copy_from_slice(&expected_root.to_le_bytes());
    commitment_input[32..].copy_from_slice(&WITNESS_RESERVED);
    let expected_commitment = double_sha256(&commitment_input).to_le_bytes();
    assert_eq!(
        &commitment[12..],
        hex_encode(&expected_commitment),
        "rendered commitment must be SHA256D(witness merkle root || witness reserved value)"
    );

    // --- external-miner-style assembly from JSON fields only -----------------
    let block = assemble_from_template(&template, template_txs)?;

    // --- submitblock over the real RPC handler -------------------------------
    let hex = hex_encode(&consensus_bytes(&block));
    let verdict = handler.dispatch("submitblock", &json!([hex]))?;
    assert!(
        verdict.is_null(),
        "submitblock of the mined template must be accepted, got: {verdict}"
    );

    // --- tip advanced, mempool drained, next template rebased ----------------
    let applied = state.applied_tip();
    let loaded_tip = applied.load_full();
    let Some(tip) = loaded_tip.as_ref() else {
        bail!("applied tip must exist after an accepted submission");
    };
    assert_eq!(
        tip.height,
        SEED_BLOCKS + 1,
        "tip height must advance by one"
    );
    assert_eq!(
        tip.hash,
        Hash256::from(block.block_hash()),
        "tip hash must equal the submitted block hash"
    );
    assert_eq!(
        state.mempool().read().len(),
        0,
        "included tx must leave the mempool on block connect"
    );

    let next = handler.dispatch("getblocktemplate", &json!([{"rules": ["segwit"]}]))?;
    assert_eq!(
        required_str(&next, "previousblockhash")?,
        block.block_hash().to_string(),
        "next template must build on the submitted block"
    );
    assert_eq!(
        required_u64(&next, "height")?,
        u64::from(SEED_BLOCKS + 2),
        "next template height must extend the new tip"
    );
    Ok(())
}

#[test]
fn template_orders_parent_then_child_with_dependency() -> Result<()> {
    let (state, _guard) = open_regtest()?;
    apply_genesis(&state)?;
    let _seed_tip_hash = seed_chain(&state, SEED_BLOCKS)?;

    let parent = seed_coinbase_spend();
    let parent_txid = parent.txid();
    let child = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(parent_txid, 0),
            script_sig: p2sh_true_spend_script_sig(),
            sequence: Sequence::from_consensus(0xffff_ffff),
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(REGTEST_SUBSIDY_SATS - 2 * MEMPOOL_TX_FEE_SATS),
            script_pubkey: p2sh_true_output(),
        }],
        lock_time: LockTime::from_consensus(0),
    };
    let child_txid = child.txid();

    admit_to_mempool(&state, &parent)?;
    admit_to_mempool(&state, &child)?;

    let handler = mining_handler(&state);
    let template = handler.dispatch("getblocktemplate", &json!([{"rules": ["segwit"]}]))?;
    let template_txs = template
        .get("transactions")
        .and_then(|entry| entry.as_array())
        .map_or(&[][..], |entries| entries.as_slice());
    assert_eq!(template_txs.len(), 2, "both txs must be selected");
    assert_eq!(
        template_txs[0]
            .get("txid")
            .and_then(|value| value.as_str())
            .ok_or_else(|| anyhow::anyhow!("first template tx missing txid"))?,
        parent_txid.to_string(),
        "parent must precede child in topological template order"
    );
    assert_eq!(
        template_txs[1]
            .get("txid")
            .and_then(|value| value.as_str())
            .ok_or_else(|| anyhow::anyhow!("second template tx missing txid"))?,
        child_txid.to_string(),
        "child must follow parent in topological template order"
    );

    let parent_depends = template_txs[0]
        .get("depends")
        .and_then(|value| value.as_array())
        .map_or(&[][..], |entries| entries.as_slice());
    assert!(parent_depends.is_empty(), "parent has no in-template dependencies");

    let child_depends = template_txs[1]
        .get("depends")
        .and_then(|value| value.as_array())
        .map_or(&[][..], |entries| entries.as_slice());
    assert_eq!(child_depends.len(), 1, "child depends on the one in-template parent");
    assert_eq!(
        child_depends[0].as_i64().and_then(|n| u64::try_from(n).ok()),
        Some(1_u64),
        "child depends index must be the one-based parent position"
    );

    Ok(())
}

/// Opens an isolated regtest `NodeState`; the returned guard keeps the data
/// directory alive for the whole test body (freed when the guard drops).
fn open_regtest() -> Result<(NodeState, tempfile::TempDir)> {
    let dir = tempfile::tempdir()?;
    let mut config = NodeConfig::default_for_network(Network::Regtest);
    config.data_dir = dir.path().join("node");
    config.p2p.listen.clear();
    let state = NodeState::open(config, None)?;
    Ok((state, dir))
}

fn apply_genesis(state: &NodeState) -> Result<()> {
    let genesis = Network::Regtest.genesis_block();
    state.apply_block(&genesis)?;
    Ok(())
}

/// Mines `count` trivial-PoW regtest blocks through ordinary validation,
/// each coinbase paying an anyone-can-spend output.
fn seed_chain(state: &NodeState, count: u32) -> Result<Hash256> {
    let mut tip = current_tip(state)?;
    for height in 1..=count {
        let coinbase = Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: null_prevout(),
                // BIP34 height push plus one pad byte: consensus requires a
                // 2..=100 byte coinbase scriptSig (Core bad-cb-length).
                script_sig: Script::from_bytes(
                    [script_push_int(i64::from(height)), script_push_int(0)].concat(),
                ),
                sequence: Sequence::from_consensus(0xffff_ffff),
                witness: Witness::new(),
            }],
            outputs: vec![TxOut {
                value: Amount::from_sat(REGTEST_SUBSIDY_SATS),
                script_pubkey: Script::from_bytes(vec![0x51]),
            }],
            lock_time: LockTime::from_consensus(0),
        };
        let mut block = Block {
            header: bitcoin_rs_primitives::Header {
                version: 0x2000_0000,
                prev_blockhash: bitcoin_rs_primitives::BlockHash::from(tip.hash),
                merkle_root: Hash256::from_le_bytes(&[0_u8; 32]),
                time: SEED_BASE_TIME.saturating_add(SEED_BLOCK_INTERVAL.saturating_mul(height)),
                bits: CompactTarget::from_consensus(REGTEST_BITS),
                nonce: 0,
            },
            txs: vec![coinbase],
        };
        block.header.merkle_root = compute_merkle_root(&block.txs)
            .ok_or_else(|| anyhow::anyhow!("seed block must have a merkle root"))?;
        grind_pow(&mut block)?;
        state.apply_block(&block)?;
        tip = current_tip(state)?;
        assert_eq!(tip.height, height, "seed block must become the tip");
    }
    Ok(tip.hash)
}

fn current_tip(state: &NodeState) -> Result<bitcoin_rs_chain::TipSnapshot> {
    let applied = state.applied_tip();
    let Some(tip) = applied.load_full() else {
        bail!("applied tip must exist");
    };
    Ok((*tip).clone())
}

fn grind_pow(block: &mut Block) -> Result<()> {
    loop {
        if pow_is_met(
            block.header.bits.to_consensus(),
            &block.header.compute_hash().into(),
        ) {
            return Ok(());
        }
        let Some(next) = block.header.nonce.checked_add(1) else {
            bail!("nonce exhausted while grinding block");
        };
        block.header.nonce = next;
    }
}

/// Returns true when the header hash, read as a little-endian integer, meets
/// the compact bits target (Core `CheckProofOfWork` shape).
fn pow_is_met(bits: u32, hash: &Hash256) -> bool {
    let exponent = usize::try_from(bits >> 24).unwrap_or(usize::MAX);
    let mantissa = bits & 0x00ff_ffff;
    if mantissa == 0 || mantissa & 0x0080_0000 != 0 || exponent > 32 {
        return false;
    }
    let shift = exponent.saturating_sub(3);
    // Little-endian target bytes: mantissa placed `shift` bytes from the
    // least-significant end (mantissa is masked below 2^24, so three bytes).
    let mantissa_le = mantissa.to_le_bytes();
    let mut target = [0_u8; 32];
    for (offset, byte) in mantissa_le.iter().take(3).enumerate() {
        let position = shift + offset;
        if position < 32 {
            target[position] = *byte;
        }
    }
    // Both sides are little-endian 32-byte integers: compare from the most
    // significant byte downward (Core `CheckProofOfWork`).
    let hash_le = hash.to_le_bytes();
    for index in (0..32).rev() {
        match hash_le[index].cmp(&target[index]) {
            std::cmp::Ordering::Less => return true,
            std::cmp::Ordering::Greater => return false,
            std::cmp::Ordering::Equal => {}
        }
    }
    true
}

/// Assembles the submit-ready block from rendered template JSON fields
/// alone, the way an external miner would.
fn assemble_from_template(
    template: &sonic_rs::Value,
    template_txs: &[sonic_rs::Value],
) -> Result<Block> {
    let prev_hex = required_str(template, "previousblockhash")?;
    let height = required_u64(template, "height")?;
    let coinbase_value = required_u64(template, "coinbasevalue")?;
    let bits = u32::from_str_radix(&required_str(template, "bits")?, 16)?;
    let curtime = u32::try_from(required_u64(template, "curtime")?).unwrap_or(u32::MAX);
    let version = i32::try_from(required_u64(template, "version")?).unwrap_or(0);
    let commitment_script = hex_decode(&required_str(template, "default_witness_commitment")?)?;
    assert!(
        commitment_script.starts_with(&[0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed]),
        "default_witness_commitment must be the BIP141 commitment script"
    );

    let mut txs = Vec::with_capacity(template_txs.len());
    for entry in template_txs {
        let data = entry
            .get("data")
            .and_then(|value| value.as_str())
            .ok_or_else(|| anyhow::anyhow!("template transaction missing data hex"))?;
        txs.push(native_deserialize::<Tx>(&hex_decode(data)?)?);
    }

    assemble_block(
        prev_hex.as_str(),
        u32::try_from(height).unwrap_or(u32::MAX),
        version,
        bits,
        curtime,
        coinbase_value,
        commitment_script,
        txs,
    )
}

/// Builds the transaction spending the height-1 seed coinbase (matured at
/// height 101) with a `MEMPOOL_TX_FEE_SATS` fee; the caller inserts it into
/// the mempool.
fn seed_coinbase_spend() -> Tx {
    seed_coinbase_spend_with_fee(MEMPOOL_TX_FEE_SATS)
}

/// Builds the transaction spending the height-1 seed coinbase (matured at
/// height 101) with a caller-chosen fee; the caller inserts it into the
/// mempool.

fn seed_coinbase_spend_with_fee(fee_sats: u64) -> Tx {
    let seed_coinbase = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: null_prevout(),
            // Must mirror the height-1 seed coinbase exactly (txid anchors
            // the mempool spend).
            script_sig: Script::from_bytes([script_push_int(1), script_push_int(0)].concat()),
            sequence: Sequence::from_consensus(0xffff_ffff),
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(REGTEST_SUBSIDY_SATS),
            script_pubkey: Script::from_bytes(vec![0x51]),
        }],
        lock_time: LockTime::from_consensus(0),
    };
    Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(seed_coinbase.txid(), 0),
            script_sig: Script::new(),
            sequence: Sequence::from_consensus(0xffff_ffff),
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(REGTEST_SUBSIDY_SATS - fee_sats),
            script_pubkey: p2sh_true_output(),
        }],
        lock_time: LockTime::from_consensus(0),
    }
}

/// A P2SH output that commits to a one-byte `OP_1` redeem script.
///
/// The output is standard, the first spend uses an empty `scriptSig`, and
/// later spends push the one-byte redeem script, so the whole chain is both
/// policy-standard and consensus-valid without real signatures.
fn p2sh_true_output() -> Script {
    let redeem = bitcoin::ScriptBuf::from_bytes(vec![0x51]);
    Script::from_bytes(redeem.to_p2sh().into_bytes())
}

/// `PUSHBYTES_1 <0x51>`: the `scriptSig` that satisfies a `p2sh_true_output`.
fn p2sh_true_spend_script_sig() -> Script {
    Script::from_bytes(vec![0x01, 0x51])
}


/// Builds a regtest block without applying it, so `submitblock` can exercise
/// the external-producer path where the transactions were never in the mempool.
fn assemble_regtest_block(prev: Hash256, height: u32, txs: Vec<Tx>) -> Result<Block> {
    let coinbase = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: null_prevout(),
            script_sig: Script::from_bytes(
                [script_push_int(i64::from(height)), script_push_int(0)].concat(),
            ),
            sequence: Sequence::from_consensus(0xffff_ffff),
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(REGTEST_SUBSIDY_SATS),
            script_pubkey: Script::from_bytes(vec![0x51]),
        }],
        lock_time: LockTime::from_consensus(0),
    };
    let mut block = Block {
        header: bitcoin_rs_primitives::Header {
            version: 0x2000_0000,
            prev_blockhash: bitcoin_rs_primitives::BlockHash::from(prev),
            merkle_root: Hash256::from_le_bytes(&[0_u8; 32]),
            time: SEED_BASE_TIME.saturating_add(SEED_BLOCK_INTERVAL.saturating_mul(height)),
            bits: CompactTarget::from_consensus(REGTEST_BITS),
            nonce: 0,
        },
        txs: std::iter::once(coinbase).chain(txs).collect(),
    };
    block.header.merkle_root = compute_merkle_root(&block.txs)
        .ok_or_else(|| anyhow::anyhow!("regtest block must have a merkle root"))?;
    grind_pow(&mut block)?;
    Ok(block)
}
/// Admits `tx` through the run-composed shared gateway exactly like
/// `sendrawtransaction` does: full policy admission over the provisional
/// chain view, no direct pool write.
fn admit_to_mempool(state: &NodeState, tx: &Tx) -> Result<()> {
    let utxo = state.utxo();
    let applied_tip = state.applied_tip();
    let block_tree = state.block_tree();
    let view = ChainAdmissionView::new(&utxo, &applied_tip, &block_tree);
    let outcome = state.mempool_gateway().submit_transaction(
        Arc::new(tx.clone()),
        AdmissionOrigin::Rpc,
        None,
        unix_time_secs(),
        &view,
    );
    assert!(
        matches!(outcome, Ok(SubmitOutcome::Committed(_))),
        "gateway admission must commit the spend, got: {outcome:?}"
    );
    Ok(())
}

fn unix_time_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

/// Mines and applies the regtest block at `height` over `prev`: the seed
/// coinbase plus `txs`, through ordinary validation.
fn mine_regtest_block(
    state: &NodeState,
    prev: Hash256,
    height: u32,
    txs: Vec<Tx>,
) -> Result<Block> {
    let coinbase = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: null_prevout(),
            // BIP34 height push plus one pad byte: consensus requires a
            // 2..=100 byte coinbase scriptSig (Core bad-cb-length).
            script_sig: Script::from_bytes(
                [script_push_int(i64::from(height)), script_push_int(0)].concat(),
            ),
            sequence: Sequence::from_consensus(0xffff_ffff),
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(REGTEST_SUBSIDY_SATS),
            script_pubkey: Script::from_bytes(vec![0x51]),
        }],
        lock_time: LockTime::from_consensus(0),
    };
    let mut block = Block {
        header: bitcoin_rs_primitives::Header {
            version: 0x2000_0000,
            prev_blockhash: bitcoin_rs_primitives::BlockHash::from(prev),
            merkle_root: Hash256::from_le_bytes(&[0_u8; 32]),
            time: SEED_BASE_TIME.saturating_add(SEED_BLOCK_INTERVAL.saturating_mul(height)),
            bits: CompactTarget::from_consensus(REGTEST_BITS),
            nonce: 0,
        },
        txs: std::iter::once(coinbase).chain(txs).collect(),
    };
    block.header.merkle_root = compute_merkle_root(&block.txs)
        .ok_or_else(|| anyhow::anyhow!("mined block must have a merkle root"))?;
    grind_pow(&mut block)?;
    state.apply_block(&block)?;
    Ok(block)
}

/// Wires the production RPC context exactly like `run()` does, with the real
/// mining coordinator installed as the `MiningControl`.
fn mining_handler(state: &NodeState) -> Handler {
    let coordinator = MiningCoordinator::new(
        state.config().network,
        state.applied_tip(),
        state.block_tree(),
        state.mempool(),
        state.chainstate(),
        state.chain_followers(),
        state.config().mining.payout_script.clone(),
        state.shutdown(),
    );
    let mining_control: Arc<dyn MiningControl> = Arc::new(coordinator);
    let ctx = Context::from_handles(ContextHandles {
        chain: ChainHandles {
            chain_tip: state.chain_tip(),
            applied_tip: state.applied_tip(),
            blocks: state.blocks(),
            transactions: state.transactions(),
            utxo: Arc::new(UtxoSet::new()),
            coin_stats: state.coin_stats(),
            block_tree: state.block_tree(),
            chain_network: state.config().network,
        },
        mempool: MempoolHandles {
            mempool: MempoolGateway::shared(state.mempool()),
        },
        indexes: IndexHandles {
            derived_index: None,
            script_index: None,
        },
        network: NetworkHandles {
            network: state.network(),
            network_active: state.network_active(),
            peer_table: state.peer_table(),
            p2p_outbound_sender: Some(state.p2p_outbound_sender()),
            banned: state.banned_subnets(),
            added_nodes: Arc::new(parking_lot::RwLock::new(Vec::new())),
        },
        mining: MiningHandles {
            mining_control: Some(mining_control),
        },
        derived_index_status: None,
    });
    Handler::new(Arc::new(ctx))
}

fn assemble_block(
    prev_hex: &str,
    height: u32,
    version: i32,
    bits: u32,
    curtime: u32,
    coinbase_value: u64,
    commitment_script: Vec<u8>,
    txs: Vec<Tx>,
) -> Result<Block> {
    let coinbase = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: null_prevout(),
            // BIP34: the coinbase scriptSig begins with the serialized height.
            script_sig: Script::from_bytes(script_push_int(i64::from(height))),
            sequence: Sequence::from_consensus(0xffff_ffff),
            witness: Witness::from_stack(vec![WITNESS_RESERVED.to_vec()]),
        }],
        outputs: vec![
            TxOut {
                value: Amount::from_sat(coinbase_value),
                script_pubkey: Script::from_bytes(vec![0x51]),
            },
            TxOut {
                value: Amount::from_sat(0),
                script_pubkey: Script::from_bytes(commitment_script),
            },
        ],
        lock_time: LockTime::from_consensus(0),
    };

    let mut block_txs = Vec::with_capacity(txs.len() + 1);
    block_txs.push(coinbase);
    block_txs.extend(txs);

    let mut block = Block {
        header: bitcoin_rs_primitives::Header {
            version,
            prev_blockhash: prev_hex
                .parse::<bitcoin_rs_primitives::BlockHash>()
                .map_err(|err| anyhow::anyhow!("invalid previousblockhash: {err}"))?,
            merkle_root: Hash256::from_le_bytes(&[0_u8; 32]),
            time: curtime,
            bits: CompactTarget::from_consensus(bits),
            nonce: 0,
        },
        txs: block_txs,
    };
    block.header.merkle_root = compute_merkle_root(&block.txs)
        .ok_or_else(|| anyhow::anyhow!("block must have a merkle root"))?;
    grind_pow(&mut block)?;
    Ok(block)
}

/// The one-input null-prevout coinbase outpoint (Core `COINBASE_OUTPOINT`).
fn null_prevout() -> OutPoint {
    OutPoint::new(Txid::default(), u32::MAX)
}

/// Minimal script push of a small integer, mirroring rust-bitcoin
/// `Builder::push_int`: `OP_0` for zero, `OP_N` for 1..=16, otherwise a
/// length-prefixed little-endian payload (BIP34 heights).
fn script_push_int(value: i64) -> Vec<u8> {
    match value {
        0 => vec![0x00],
        // `value` is pinned to 1..=16 by the match arm.
        1..=16 => vec![0x50 + u8::try_from(value).unwrap_or_default()],
        _ => {
            let mut payload = Vec::new();
            let mut magnitude = value.unsigned_abs();
            while magnitude > 0 {
                // Low byte only; the shift below consumes it fully.
                payload.push(u8::try_from(magnitude & 0xff).unwrap_or_default());
                magnitude >>= 8;
            }
            let mut out = Vec::with_capacity(payload.len() + 1);
            // A small-int push never exceeds 8 payload bytes.
            out.push(u8::try_from(payload.len()).unwrap_or_default());
            out.extend(payload);
            out
        }
    }
}

/// Native BIP141-style txid merkle fold with the odd-leaf duplication rule.
fn compute_merkle_root(txs: &[Tx]) -> Option<Hash256> {
    if txs.is_empty() {
        return None;
    }
    let mut level: Vec<[u8; 32]> = txs.iter().map(|tx| *tx.txid().as_bytes()).collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pos in 0..level.len().div_ceil(2) {
            let left = level[2 * pos];
            let right = level[(2 * pos + 1).min(level.len() - 1)];
            let mut pair = [0_u8; 64];
            pair[..32].copy_from_slice(&left);
            pair[32..].copy_from_slice(&right);
            next.push(*double_sha256(&pair).as_byte_array());
        }
        level = next;
    }
    Some(Hash256::from_le_bytes(&level[0]))
}

/// Native BIP141 witness merkle fold with the odd-leaf duplication rule.
/// The coinbase wtxid is replaced by all-zeroes before folding.
fn compute_witness_merkle_root(txs: &[Tx]) -> Option<Hash256> {
    if txs.is_empty() {
        return None;
    }
    let mut level: Vec<[u8; 32]> = Vec::with_capacity(txs.len().saturating_add(1));
    level.push([0_u8; 32]);
    for tx in txs {
        level.push(*tx.wtxid().as_bytes());
    }
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for pos in 0..level.len().div_ceil(2) {
            let left = level[2 * pos];
            let right = level[(2 * pos + 1).min(level.len() - 1)];
            let mut pair = [0_u8; 64];
            pair[..32].copy_from_slice(&left);
            pair[32..].copy_from_slice(&right);
            next.push(*double_sha256(&pair).as_byte_array());
        }
        level = next;
    }
    Some(Hash256::from_le_bytes(&level[0]))
}

/// Encodes `bytes` as lowercase hexadecimal.
fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for &byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

/// Decodes a hexadecimal string into bytes.
fn hex_decode(hex: &str) -> Result<Vec<u8>> {
    let bytes = hex.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        bail!("hex string must have even length");
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.as_chunks::<2>().0 {
        let hi = hex_nibble(pair[0]).ok_or_else(|| anyhow::anyhow!("invalid hex"))?;
        let lo = hex_nibble(pair[1]).ok_or_else(|| anyhow::anyhow!("invalid hex"))?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

/// Decodes one ASCII hex nibble.
fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn required_str(value: &sonic_rs::Value, key: &str) -> Result<String> {
    let text = value
        .get(key)
        .and_then(|text| text.as_str())
        .ok_or_else(|| anyhow::anyhow!("template field {key} missing or not a string"))?;
    Ok(text.to_owned())
}

fn required_u64(value: &sonic_rs::Value, key: &str) -> Result<u64> {
    value
        .get(key)
        .and_then(sonic_rs::JsonValueTrait::as_i64)
        .and_then(|number| u64::try_from(number).ok())
        .ok_or_else(|| anyhow::anyhow!("template field {key} missing or not a number"))
}

#[test]
fn invalidateblock_readmits_parent_before_child_in_dependency_order() -> Result<()> {
    let (state, _guard) = open_regtest()?;
    apply_genesis(&state)?;
    let seed_tip_hash = seed_chain(&state, SEED_BLOCKS)?;

    // Parent spends the matured height-1 coinbase; the child spends the
    // parent. Both pay MEMPOOL_TX_FEE_SATS.
    let parent = seed_coinbase_spend();
    let parent_txid = parent.txid();
    let child = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(parent_txid, 0),
            script_sig: p2sh_true_spend_script_sig(),
            sequence: Sequence::from_consensus(0xffff_ffff),
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(REGTEST_SUBSIDY_SATS - 2 * MEMPOOL_TX_FEE_SATS),
            script_pubkey: p2sh_true_output(),
        }],
        lock_time: LockTime::from_consensus(0),
    };
    let child_txid = child.txid();

    admit_to_mempool(&state, &parent)?;
    admit_to_mempool(&state, &child)?;
    let sequence_before_reorg = state.mempool().read().sequence_number();

    let block = mine_regtest_block(&state, seed_tip_hash, SEED_BLOCKS + 1, vec![parent, child])?;
    assert_eq!(
        state.mempool().read().len(),
        0,
        "connect must drain the confirmed pair"
    );
    let mined_hash = Hash256::from(block.block_hash());

    bitcoin_rs_node::reorg::invalidate_block(
        &state.chainstate(),
        &state.chain_followers(),
        mined_hash,
    )
    .map_err(|error| anyhow::anyhow!("invalidateblock failed: {error}"))?;

    let tip = current_tip(&state)?;
    assert_eq!(tip.height, SEED_BLOCKS, "the mined block must roll back");
    {
        let mempool = state.mempool();
        let pool = mempool.read();
        assert!(pool.contains_txid(&parent_txid), "the parent returns");
        assert!(
            pool.contains_txid(&child_txid),
            "the child follows its parent"
        );
        assert_eq!(pool.len(), 2, "the coinbase must stay out");
        assert_eq!(
            pool.sequence_number(),
            sequence_before_reorg + 4,
            "connect removes two, reconsideration admits parent then child"
        );
    }
    Ok(())
}

/// Records every published change as `(sequence, txid, outcome)`.
#[derive(Default)]
struct RecordingMempoolObserver {
    changes: Mutex<Vec<(u64, Hash256, MutationOutcome)>>,
}

impl MempoolObserver for RecordingMempoolObserver {
    fn on_mutation(&self, envelope: &MutationEnvelope) {
        let result = &envelope.result;
        let mut changes = self.changes.lock();
        for (offset, change) in result.changes.iter().enumerate() {
            let sequence = result.sequence_of(offset).unwrap_or(u64::MAX);
            changes.push((sequence, change.txid, change.outcome));
        }
    }
}

/// Reorg re-admission publishes through the run-composed shared gateway:
/// two Accepted changes, parent before child, origin `Reorg`, contiguous
/// sequences. The apply path's raw sweep bypasses observers by design, so
/// these two changes are the only publications the gateway emits here.
#[test]
fn invalidateblock_readmission_publishes_a_events_through_shared_gateway() -> Result<()> {
    let (state, _guard) = open_regtest()?;
    apply_genesis(&state)?;
    let seed_tip_hash = seed_chain(&state, SEED_BLOCKS)?;

    // Interning returns the one gateway every production route reaches
    // The gateway is constructed with the observer so publication runs
    // through the same path production uses.
    let observer = Arc::new(RecordingMempoolObserver::default());
    let gateway = state.mempool_gateway();
    assert!(
        Arc::ptr_eq(&gateway, &MempoolGateway::shared(state.mempool())),
        "the node's gateway must be the one interned for its pool"
    );
    gateway
        .attach_observer_leg("test-recorder", observer.clone())
        .unwrap_or_else(|error| panic!("the node installs an observer slot to extend: {error}"));
    let parent = seed_coinbase_spend();
    let parent_txid = parent.txid();
    let child = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(parent_txid, 0),
            script_sig: p2sh_true_spend_script_sig(),
            sequence: Sequence::from_consensus(0xffff_ffff),
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(REGTEST_SUBSIDY_SATS - 2 * MEMPOOL_TX_FEE_SATS),
            script_pubkey: p2sh_true_output(),
        }],
        lock_time: LockTime::from_consensus(0),
    };
    let child_txid = child.txid();

    let block = mine_regtest_block(&state, seed_tip_hash, SEED_BLOCKS + 1, vec![parent, child])?;
    let mined_hash = Hash256::from(block.block_hash());
    bitcoin_rs_node::reorg::invalidate_block(
        &state.chainstate(),
        &state.chain_followers(),
        mined_hash,
    )
    .map_err(|error| anyhow::anyhow!("invalidateblock failed: {error}"))?;

    let tip = current_tip(&state)?;
    assert_eq!(tip.height, SEED_BLOCKS, "the mined block must roll back");
    let changes = observer.changes.lock();
    assert_eq!(
        *changes,
        vec![
            (1, Hash256::from(parent_txid), MutationOutcome::Accepted,),
            (2, Hash256::from(child_txid), MutationOutcome::Accepted,),
        ],
        "parent before child, contiguous sequences"
    );
    Ok(())
}

#[test]
fn invalidateblock_keeps_a_below_floor_parent_and_its_child_out_of_the_mempool() -> Result<()> {
    let (state, _guard) = open_regtest()?;
    apply_genesis(&state)?;
    let seed_tip_hash = seed_chain(&state, SEED_BLOCKS)?;

    // The parent spends the matured seed coinbase but offers a 1-sat fee,
    // far below the 1 000 sat/kvB relay floor. The child pays well and is
    // kept out only by its refused parent.
    let parent = seed_coinbase_spend_with_fee(1);
    let parent_txid = parent.txid();
    let child = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(parent_txid, 0),
            script_sig: p2sh_true_spend_script_sig(),
            sequence: Sequence::from_consensus(0xffff_ffff),
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(REGTEST_SUBSIDY_SATS - 1 - 5_000),
            script_pubkey: p2sh_true_output(),
        }],
        lock_time: LockTime::from_consensus(0),
    };

    let block = mine_regtest_block(&state, seed_tip_hash, SEED_BLOCKS + 1, vec![parent, child])?;
    let mined_hash = Hash256::from(block.block_hash());
    bitcoin_rs_node::reorg::invalidate_block(
        &state.chainstate(),
        &state.chain_followers(),
        mined_hash,
    )
    .map_err(|error| anyhow::anyhow!("invalidateblock failed: {error}"))?;

    let tip = current_tip(&state)?;
    assert_eq!(tip.height, SEED_BLOCKS, "the mined block must roll back");
    let mempool = state.mempool();
    let pool = mempool.read();
    assert!(
        pool.is_empty(),
        "a refused parent and its withheld child must stay out"
    );
    assert!(!pool.contains_txid(&parent_txid));
    Ok(())
}

#[test]
fn submitblock_accepts_block_without_prior_mempool_admission() -> Result<()> {
    let (state, _guard) = open_regtest()?;
    apply_genesis(&state)?;
    let seed_tip_hash = seed_chain(&state, SEED_BLOCKS)?;

    // A consensus-valid spend that never passes through the mempool gateway.
    let tx = seed_coinbase_spend();
    assert!(!state.mempool().read().contains_txid(&tx.txid()));

    let block = assemble_regtest_block(seed_tip_hash, SEED_BLOCKS + 1, vec![tx])?;
    let block_hex = hex_encode(&consensus_bytes(&block));

    let handler = mining_handler(&state);
    let verdict = handler.dispatch("submitblock", &json!([block_hex]))?;
    assert!(verdict.is_null(), "submitblock must accept a valid block, got: {verdict}");

    let tip = current_tip(&state)?;
    assert_eq!(tip.height, SEED_BLOCKS + 1, "tip must advance by one");
    assert_eq!(
        tip.hash,
        Hash256::from(block.block_hash()),
        "tip hash must equal the submitted block hash"
    );
    Ok(())
}

#[test]
fn submitblock_rejects_stale_template_with_inconclusive_prevblk() -> Result<()> {
    let (state, _guard) = open_regtest()?;
    apply_genesis(&state)?;
    let old_tip = seed_chain(&state, SEED_BLOCKS)?;

    let tx = seed_coinbase_spend();
    admit_to_mempool(&state, &tx)?;

    let handler = mining_handler(&state);
    let template = handler.dispatch("getblocktemplate", &json!([{"rules": ["segwit"]}]))?;
    let template_txs = template
        .get("transactions")
        .and_then(|value| value.as_array())
        .map_or(&[][..], |entries| entries.as_slice());
    let accepted = assemble_from_template(&template, template_txs)?;
    let accepted_hex = hex_encode(&consensus_bytes(&accepted));
    let verdict = handler.dispatch("submitblock", &json!([accepted_hex]))?;
    assert!(verdict.is_null(), "first block must be accepted, got: {verdict}");

    // A competing block built on the superseded template still points at old_tip.
    let stale_block = assemble_regtest_block(old_tip, SEED_BLOCKS + 1, Vec::new())?;
    let stale_hex = hex_encode(&consensus_bytes(&stale_block));
    let reject = handler.dispatch("submitblock", &json!([stale_hex]))?;
    let reason = reject.as_str().ok_or_else(|| anyhow::anyhow!("submitblock"))?;
    assert!(
        reason.contains("inconclusive-not-best-prevblk"),
        "stale template must be rejected with PrevHashMismatch: {reason}"
    );

    Ok(())
}
