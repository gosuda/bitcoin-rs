//! Curated acceptance comparisons against a pinned live Bitcoin Core.
//!
//! Only public RPCs and independently produced Core funding/candidate blocks
//! are used. The suite owns no consensus implementation or production hooks.

use std::fs;

use bitcoin::consensus::encode::{deserialize_hex, serialize_hex};
use bitcoin::hashes::{Hash as _, sha256};
use bitcoin::{Amount, Block, ScriptBuf, Sequence, Transaction, TxMerkleNode, Txid};
use bitcoin_rs_e2e::differential::{CommonFunds, compare_reply, mine_common_chain};
use bitcoin_rs_e2e::helpers::{
    coinbase_script_sig, funding_address, grind_pow, sign_p2pkh_inputs, signed_spend,
};
use bitcoin_rs_e2e::{Error, Kind, ProcessNode, Result, ValueExt};
use serde_json::{Value, json};

#[derive(Clone, Copy)]
enum Input<'a> {
    Block(&'a Block),
    Transaction(&'a Transaction),
}

impl Input<'_> {
    fn method(self) -> &'static str {
        match self {
            Self::Block(_) => "submitblock",
            Self::Transaction(_) => "testmempoolaccept",
        }
    }

    fn hex(self) -> String {
        match self {
            Self::Block(block) => serialize_hex(block),
            Self::Transaction(tx) => serialize_hex(tx),
        }
    }

    fn identity(self) -> String {
        match self {
            Self::Block(block) => block.block_hash().to_string(),
            Self::Transaction(tx) => tx.compute_txid().to_string(),
        }
    }

    fn verdict(self, reply: &Value) -> Result<bool> {
        match self {
            Self::Block(_) => block_verdict(reply),
            Self::Transaction(tx) => transaction_verdict(reply, tx),
        }
    }
}

fn block_verdict(reply: &Value) -> Result<bool> {
    if reply.is_null() {
        return Ok(true);
    }
    let Some(reason) = reply.as_str().filter(|reason| !reason.is_empty()) else {
        return Err(Error::Protocol(format!(
            "malformed submitblock result: {reply}"
        )));
    };
    if reason == "bad-prevblk"
        || reason == "prev-blk-not-found"
        || reason.starts_with("duplicate")
        || reason.starts_with("inconclusive")
    {
        return Err(Error::Protocol(format!(
            "block comparison lost shared state: {reason}"
        )));
    }
    Ok(false)
}

fn transaction_verdict(reply: &Value, tx: &Transaction) -> Result<bool> {
    let Some(rows) = reply.as_array().filter(|rows| rows.len() == 1) else {
        return Err(Error::Protocol(format!(
            "malformed testmempoolaccept result: {reply}"
        )));
    };
    let row = &rows[0];
    if row.str_field("txid")? != tx.compute_txid().to_string()
        || row.str_field("wtxid")? != tx.compute_wtxid().to_string()
    {
        return Err(Error::Protocol(format!(
            "transaction identity mismatch: {reply}"
        )));
    }
    let allowed = row
        .field("allowed")?
        .as_bool()
        .ok_or_else(|| Error::Protocol(format!("missing boolean admission verdict: {reply}")))?;
    if !allowed {
        let reason = row.str_field("reject-reason")?;
        if reason.is_empty() || matches!(reason, "txn-already-in-mempool" | "txn-already-known") {
            return Err(Error::Protocol(format!(
                "transaction comparison lost shared state: {reply}"
            )));
        }
    }
    Ok(allowed)
}

fn state(node: &mut ProcessNode) -> Result<Value> {
    let chain = node.rpc("getblockchaininfo", &json!([]))?;
    Ok(json!({
        "chain": chain.str_field("chain")?,
        "height": chain.u64_field("blocks")?,
        "tip": chain.str_field("bestblockhash")?,
        "mempool": node.rpc("getrawmempool", &json!([]))?,
        "connections": node.rpc("getconnectioncount", &json!([]))?,
    }))
}

fn shared_state(core: &mut ProcessNode, node: &mut ProcessNode) -> Result<Value> {
    let reference = state(core)?;
    let candidate = state(node)?;
    if reference != candidate
        || reference["chain"] != "regtest"
        || reference["mempool"] != json!([])
        || reference["connections"] != 0
    {
        return Err(Error::Assertion(format!(
            "acceptance harness requires an isolated shared regtest state: Core={reference}, bitcoin-rs={candidate}"
        )));
    }
    Ok(reference)
}

/// Save input identity before checking state or calling either node, then
/// retain both replies and the final classification alongside process logs.
fn compare_case(
    core: &mut ProcessNode,
    node: &mut ProcessNode,
    name: &str,
    input: Input<'_>,
    expected_allowed: bool,
) -> Result<()> {
    let hex = input.hex();
    let evidence_path = node.evidence.join(format!("acceptance-{name}.json"));
    let mut evidence = json!({
        "schema": "bitcoin-rs-core-acceptance-v1",
        "case": name,
        "method": input.method(),
        "input_identity": input.identity(),
        "serialized_hex": hex,
        "serialized_hex_sha256": sha256::Hash::hash(hex.as_bytes()).to_string(),
        "expected_allowed": expected_allowed,
        "reference_evidence": core.evidence,
        "candidate_evidence": node.evidence,
        "outcome": "incomplete",
    });
    fs::write(&evidence_path, serde_json::to_vec_pretty(&evidence)?)?;
    let result = (|| {
        let before = shared_state(core, node)?;
        evidence["before"] = before.clone();
        if let Input::Block(block) = input {
            if block.header.prev_blockhash.to_string() != before.str_field("tip")? {
                return Err(Error::Assertion(
                    "candidate does not extend the shared tip".into(),
                ));
            }
        }
        let params = match input {
            Input::Block(_) => json!([hex]),
            Input::Transaction(_) => json!([[hex]]),
        };
        let reference = core.rpc(input.method(), &params)?;
        evidence["reference_reply"] = reference.clone();
        // Persist the first observation even if the second process dies.
        fs::write(&evidence_path, serde_json::to_vec_pretty(&evidence)?)?;
        let candidate = node.rpc(input.method(), &params)?;
        evidence["candidate_reply"] = candidate.clone();
        let reference_allowed = input.verdict(&reference)?;
        let candidate_allowed = input.verdict(&candidate)?;
        compare_reply(name, &json!(reference_allowed), &json!(candidate_allowed))?;
        if reference_allowed != expected_allowed {
            return Err(Error::Assertion(format!(
                "curated fixture {name} expected allowed={expected_allowed}, Core returned {reference}"
            )));
        }
        let after = shared_state(core, node)?;
        evidence["after"] = after.clone();
        let mut expected_after = before;
        if let Input::Block(block) = input {
            if reference_allowed {
                expected_after["height"] = json!(expected_after.u64_field("height")? + 1);
                expected_after["tip"] = json!(block.block_hash().to_string());
            }
        }
        if after != expected_after {
            return Err(Error::Assertion(format!(
                "case {name} changed unexpected public state: expected={expected_after}, observed={after}"
            )));
        }
        Ok(())
    })();
    evidence["outcome"] = json!(match &result {
        Ok(()) => "match",
        Err(Error::Difference { .. }) => "acceptance-divergence",
        Err(_) => "harness-failure",
    });
    if let Err(error) = &result {
        evidence["error"] = json!(error.to_string());
    }
    fs::write(&evidence_path, serde_json::to_vec_pretty(&evidence)?)?;
    result
}

fn core_candidate(core: &mut ProcessNode, transactions: &[String]) -> Result<Block> {
    // submit=false returns independently assembled, solved bytes without
    // making the reference's eventual submitblock response a duplicate.
    let reply = core.rpc(
        "generateblock",
        &json!([funding_address()?.to_string(), transactions, false]),
    )?;
    let block: Block = deserialize_hex(reply.str_field("hex")?)
        .map_err(|error| Error::Protocol(error.to_string()))?;
    if block.block_hash().to_string() != reply.str_field("hash")? {
        return Err(Error::Protocol("Core candidate hash/bytes disagree".into()));
    }
    Ok(block)
}

fn update_merkle_and_pow(block: &mut Block) -> Result<()> {
    block.header.merkle_root = block
        .compute_merkle_root()
        .ok_or_else(|| Error::Assertion("fixture has no transactions".into()))?;
    grind_pow(&mut block.header)
}

fn common_active_chain(core: &mut ProcessNode, node: &mut ProcessNode) -> Result<CommonFunds> {
    // Core 31.1 activates regtest CSV/BIP34 at height 1, whereas the candidate
    // uses 432/500. Funding only to coinbase maturity does not establish the
    // same active rules. Cross both thresholds before comparing these cases.
    let mut funds = mine_common_chain(core, node, 100)?;
    for _ in 0..4 {
        let batch = mine_common_chain(core, node, 100)?;
        funds.common_block_bytes.extend(batch.common_block_bytes);
        funds.common_outpoints.extend(batch.common_outpoints);
    }
    let shared = shared_state(core, node)?;
    let deployment = core.rpc("getdeploymentinfo", &json!([]))?;
    let template = node.rpc("getblocktemplate", &json!([{"rules": ["segwit"]}]))?;
    fs::write(
        node.evidence.join("acceptance-setup.json"),
        serde_json::to_vec_pretty(&json!({
            "shared_state": shared,
            "reference_deployments": deployment,
            "candidate_template": template,
        }))?,
    )?;
    if shared.u64_field("height")? != 500
        || deployment["deployments"]["csv"]["active"] != true
        || deployment["deployments"]["bip34"]["active"] != true
        || template.u64_field("height")? != 501
        || !template["rules"]
            .as_array()
            .is_some_and(|rules| rules.contains(&json!("csv")))
    {
        return Err(Error::Assertion(
            "acceptance cases require active CSV/BIP34".into(),
        ));
    }
    Ok(funds)
}

fn transaction_cases(
    core: &mut ProcessNode,
    node: &mut ProcessNode,
    funds: &CommonFunds,
) -> Result<Transaction> {
    let valid = funds.signed_spend(1_000, Sequence::MAX)?;
    compare_case(core, node, "mature-spend", Input::Transaction(&valid), true)?;

    let (_, prevout) = funds.confirmed_output(0)?;
    let (immature_outpoint, immature_output) = funds.confirmed_output(499)?;
    let immature = signed_spend(immature_outpoint, &immature_output, 1_000, Sequence::MAX)?;
    let mut duplicate = valid.clone();
    duplicate.input.push(duplicate.input[0].clone());
    sign_p2pkh_inputs(&mut duplicate, &[prevout.clone(), prevout.clone()])?;
    let mut overspend = valid.clone();
    overspend.output[0].value = Amount::from_sat(prevout.value.to_sat() + 1);
    sign_p2pkh_inputs(&mut overspend, std::slice::from_ref(&prevout))?;
    let mut excessive_output = valid.clone();
    excessive_output.output[0].value = Amount::from_sat(2_100_000_000_000_001);
    sign_p2pkh_inputs(&mut excessive_output, std::slice::from_ref(&prevout))?;
    let mut missing = valid.clone();
    missing.input[0].previous_output.txid = Txid::from_byte_array([0x42; 32]);
    sign_p2pkh_inputs(&mut missing, std::slice::from_ref(&prevout))?;
    let sequence_locked = funds.signed_spend(1_000, Sequence::from_consensus(501))?;
    for (name, tx) in [
        ("immature-coinbase-spend", immature),
        ("duplicate-inputs", duplicate),
        ("overspend", overspend),
        ("output-above-money-range", excessive_output),
        ("missing-input", missing),
        ("relative-height-lock", sequence_locked),
    ] {
        compare_case(core, node, name, Input::Transaction(&tx), false)?;
    }

    Ok(valid)
}

#[test]
fn curated_live_acceptance() -> Result<()> {
    let mut core = ProcessNode::spawn(Kind::Core)?;
    let mut node = ProcessNode::spawn(Kind::BitcoinRs)?;
    let funds = common_active_chain(&mut core, &mut node)?;
    let valid = transaction_cases(&mut core, &mut node, &funds)?;
    let valid_block = core_candidate(&mut core, &[])?;
    compare_case(
        &mut core,
        &mut node,
        "core-coinbase-block",
        Input::Block(&valid_block),
        true,
    )?;
    let template = core_candidate(&mut core, &[])?;
    let mut bad_merkle = template.clone();
    bad_merkle.header.merkle_root = TxMerkleNode::all_zeros();
    grind_pow(&mut bad_merkle.header)?;
    let mut multiple_coinbase = template.clone();
    let mut second_coinbase = multiple_coinbase.txdata[0].clone();
    second_coinbase.input[0].script_sig = coinbase_script_sig(999);
    multiple_coinbase.txdata.push(second_coinbase);
    update_merkle_and_pow(&mut multiple_coinbase)?;
    let mut short_coinbase = template.clone();
    short_coinbase.txdata[0].input[0].script_sig = ScriptBuf::from_bytes(vec![0x51]);
    update_merkle_and_pow(&mut short_coinbase)?;
    let mut excessive_coinbase = template.clone();
    excessive_coinbase.txdata[0].output[0].value += Amount::from_sat(1);
    update_merkle_and_pow(&mut excessive_coinbase)?;
    let mut wrong_height = template.clone();
    wrong_height.txdata[0].input[0].script_sig = coinbase_script_sig(501);
    update_merkle_and_pow(&mut wrong_height)?;
    let chain = core.rpc("getblockchaininfo", &json!([]))?;
    let mut old_time = template;
    old_time.header.time = u32::try_from(chain.u64_field("mediantime")?)
        .map_err(|error| Error::Assertion(error.to_string()))?;
    grind_pow(&mut old_time.header)?;
    for (name, block) in [
        ("bad-merkle-root", bad_merkle),
        ("multiple-coinbase", multiple_coinbase),
        ("short-coinbase-script", short_coinbase),
        ("excessive-coinbase-value", excessive_coinbase),
        ("wrong-coinbase-height", wrong_height),
        ("time-at-median", old_time),
    ] {
        compare_case(&mut core, &mut node, name, Input::Block(&block), false)?;
    }
    // A positive control after all rejections also proves the shared parent
    // is still usable and the mature coin has not been consumed by previews.
    let spend_block = core_candidate(&mut core, &[serialize_hex(&valid)])?;
    compare_case(
        &mut core,
        &mut node,
        "core-spend-block",
        Input::Block(&spend_block),
        true,
    )?;
    core.stop()?;
    node.stop()
}

#[test]
fn state_and_malformed_results_are_never_consensus_rejections() {
    for reply in [
        json!("bad-prevblk"),
        json!("prev-blk-not-found"),
        json!("duplicate"),
        json!("duplicate-invalid"),
        json!("duplicate-inconclusive"),
        json!("inconclusive"),
        json!(""),
        json!(false),
        json!({"error": "offline"}),
    ] {
        assert!(block_verdict(&reply).is_err(), "{reply}");
    }
    assert!(matches!(block_verdict(&Value::Null), Ok(true)));
    assert!(matches!(block_verdict(&json!("bad-cb-amount")), Ok(false)));
}

#[test]
fn transaction_identity_and_result_shape_are_harness_invariants() {
    let tx = &bitcoin::constants::genesis_block(bitcoin::Network::Regtest).txdata[0];
    let row = json!({
        "txid": tx.compute_txid().to_string(),
        "wtxid": tx.compute_wtxid().to_string(),
        "allowed": false,
        "reject-reason": "missing-inputs",
    });
    assert!(matches!(transaction_verdict(&json!([row]), tx), Ok(false)));
    for reply in [
        json!([]),
        json!([row, row]),
        json!([{}]),
        json!([{ "txid": "wrong-transaction" }]),
    ] {
        assert!(transaction_verdict(&reply, tx).is_err(), "{reply}");
    }
    for reason in ["txn-already-in-mempool", "txn-already-known", ""] {
        let mut duplicate = row.clone();
        duplicate["reject-reason"] = json!(reason);
        assert!(transaction_verdict(&json!([duplicate]), tx).is_err());
    }
    let mut absent_verdict = row;
    absent_verdict["allowed"] = Value::Null;
    assert!(transaction_verdict(&json!([absent_verdict]), tx).is_err());
}
