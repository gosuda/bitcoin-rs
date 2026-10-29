use alloc::sync::Arc;
use core::str::FromStr as _;

use bitcoin::hex::{DisplayHex as _, FromHex as _};
use bitcoin_rs_mempool::MempoolMiningSnapshot;
use bitcoin_rs_mining::{
    AvailableMiningRule, BlockTemplate, BlockTemplateMode, BlockTemplateRequest,
    BlockTemplateResult, BlockValidationResult, GenerateRequest, GenerateSelection, GenerateTx,
    MiningCapability, MiningControlError, MiningInfo, MiningRule, TemplateMutation,
    witness_commitment_script,
};
use bitcoin_rs_primitives::{BlockPayload, Header, Network, Tx, Txid, deserialize};
use bytes::Bytes;
use compact_str::CompactString;
use sonic_rs::{JsonContainerTrait, JsonValueTrait, Value, json};

use crate::context::Context;
use crate::convert::{
    self, compact_target_hex, i64_saturated, sat_to_btc, signed_sat_to_i64, typed_to_sonic,
    typed_to_sonic_omitting_nulls,
};
use crate::error::RpcError;
use crate::handlers::util::{generateblock_payout_script, payout_script_from_address};
use crate::handlers::{
    ensure_at_most_params, ensure_no_params, optional_bool, params_array, required_str,
    required_u64,
};
use corepc_types::v31;

const NONCE_RANGE: &str = "00000000ffffffff";

const GBT_REQUIRE_SEGWIT: &str =
    r#"getblocktemplate must be called with the segwit rule set (call with {"rules": ["segwit"]})"#;
const GBT_REQUIRE_SIGNET: &str = r#"getblocktemplate must be called with the signet rule set (call with {"rules": ["segwit", "signet"]})"#;
const PRIORITISE_DUMMY_ERROR: &str =
    "Priority is no longer supported, dummy argument to prioritisetransaction must be 0.";
const PRIORITISE_DUST_ERROR: &str = "Priority is not supported for transactions with dust outputs.";
const GENERATE_INVALID_ADDRESS: &str = "Error: Invalid address";

pub(crate) fn getblocktemplate(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let control = ctx
        .mining
        .mining_control
        .as_ref()
        .ok_or_else(|| RpcError::MethodNotFound("getblocktemplate".to_owned()))?;
    let request = parse_block_template_request(params)?;
    if matches!(request.mode, BlockTemplateMode::Template) {
        ensure_template_ready(ctx)?;
        ensure_client_rules_for_template(ctx.chain.chain_network, &request.rules)?;
    }
    let client_rules = request.rules.clone();
    match control.get_block_template(request) {
        Ok(BlockTemplateResult::Template(template)) => {
            ensure_client_supports_mandatory_rules(&template, &client_rules)?;
            render_block_template(&template)
        }
        Ok(BlockTemplateResult::Proposal(result)) => Ok(render_validation_result(result)),
        Err(error) => Err(map_mining_control_error(error)),
    }
}

pub(crate) fn getmininginfo(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    let control = ctx
        .mining
        .mining_control
        .as_ref()
        .ok_or_else(|| RpcError::MethodNotFound("getmininginfo".to_owned()))?;
    let info = control.mining_info().map_err(map_mining_control_error)?;
    render_mining_info(&info)
}

pub(crate) fn submitblock(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let control = ctx
        .mining
        .mining_control
        .as_ref()
        .ok_or_else(|| RpcError::MethodNotFound("submitblock".to_owned()))?;
    ensure_at_most_params(params, 2)?;
    if let Some(dummy) = params_array(params)?.get(1) {
        if !dummy.is_null() && dummy.as_str().is_none() {
            return Err(RpcError::InvalidType("parameter must be string".to_owned()));
        }
    }
    let hex = required_str(params, 0, "block hex is required")?;
    let (payload, _) = decode_submitted_block(hex)?;
    match control.submit_block(payload) {
        Ok(result) => Ok(render_validation_result(result)),
        Err(error) => Err(map_mining_control_error(error)),
    }
}

fn decode_submitted_block(hex: &str) -> Result<(BlockPayload, usize), RpcError> {
    let raw = Vec::<u8>::from_hex(hex).map_err(|_| block_decode_failed())?;
    let (payload, consumed) =
        BlockPayload::from_prefix(Bytes::from(raw)).map_err(|_| block_decode_failed())?;
    Ok((payload, consumed))
}

fn block_decode_failed() -> RpcError {
    RpcError::Deserialization("Block decode failed".to_owned())
}

const HEADER_BYTES: usize = Header::LEN;

fn decode_block_header(hex: &str) -> Result<Header, RpcError> {
    let bytes = Vec::<u8>::from_hex(hex)
        .map_err(|_| RpcError::Deserialization("Block header decode failed".to_owned()))?;
    let Some(header_bytes) = bytes.get(..HEADER_BYTES) else {
        return Err(RpcError::Deserialization(
            "Block header decode failed".to_owned(),
        ));
    };
    deserialize::<Header>(header_bytes)
        .map_err(|_| RpcError::Deserialization("Block header decode failed".to_owned()))
}

pub(crate) fn submitheader(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let control = ctx
        .mining
        .mining_control
        .as_ref()
        .ok_or_else(|| RpcError::MethodNotFound("submitheader".to_owned()))?;
    ensure_at_most_params(params, 1)?;
    let hex = required_str(params, 0, "header hex is required")?;
    let header = decode_block_header(hex)?;
    match control.submit_header(header) {
        Ok(()) => Ok(json!(null)),
        Err(error) => Err(map_mining_control_error(error)),
    }
}
pub(crate) fn prioritisetransaction(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let (txid_str, fee_delta, dummy) = if let Some(array) = params.as_array() {
        if array.len() > 3 {
            return Err(RpcError::InvalidParams("too many parameters"));
        }
        let fee_delta = array
            .get(2)
            .and_then(JsonValueTrait::as_i64)
            .ok_or_else(|| RpcError::InvalidType("parameter must be an integer".to_owned()))?;
        (
            array.first().and_then(JsonValueTrait::as_str),
            fee_delta,
            array.get(1),
        )
    } else if params.is_object() {
        (
            params.get("txid").and_then(JsonValueTrait::as_str),
            params
                .get("fee_delta")
                .and_then(JsonValueTrait::as_i64)
                .ok_or_else(|| RpcError::InvalidType("parameter must be an integer".to_owned()))?,
            params.get("dummy"),
        )
    } else {
        return Err(RpcError::InvalidParams("params must be an array or object"));
    };
    let txid_str = txid_str.ok_or(RpcError::InvalidParams("txid is required"))?;
    let txid = super::parse_txid(txid_str, "txid")?;
    if let Some(dummy) = dummy
        && !dummy.is_null()
    {
        let nonzero = dummy
            .as_i64()
            .map(|n| n != 0)
            .or_else(|| dummy.as_u64().map(|n| n != 0))
            .or_else(|| dummy.as_f64().map(|n| n != 0.0))
            .ok_or_else(|| RpcError::InvalidType("dummy must be a number".to_owned()))?;
        if nonzero {
            return Err(RpcError::InvalidParameter(
                PRIORITISE_DUMMY_ERROR.to_owned(),
            ));
        }
    }
    let prioritised = if ctx.chain.chain_network == Network::Regtest {
        ctx.mempool
            .gateway
            .prioritise(txid, fee_delta)
            .map(|()| true)
    } else {
        let dust_relay_fee = ctx
            .mempool
            .gateway
            .read()
            .policy_snapshot()
            .standardness
            .dust_relay_fee;
        ctx.mempool
            .gateway
            .prioritise_if_not_dust(txid, fee_delta, dust_relay_fee)
    };
    if !prioritised.map_err(|_| RpcError::InvalidParams("fee delta would overflow"))? {
        return Err(RpcError::InvalidParameter(PRIORITISE_DUST_ERROR.to_owned()));
    }
    if let Some(control) = ctx.mining.mining_control.as_ref() {
        let fee_delta_sequence = {
            let pool = ctx.mempool.gateway.read();
            let fee_delta_sequence = pool.fee_delta_sequence_number();
            drop(pool);
            fee_delta_sequence
        };
        control.publish_fee_delta_generation(fee_delta_sequence);
    }
    Ok(json!(true))
}

pub(crate) fn generatetoaddress(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_at_most_params(params, 3)?;
    let control = ctx
        .mining
        .mining_control
        .as_ref()
        .ok_or_else(|| RpcError::MethodNotFound("generatetoaddress".to_owned()))?;
    let nblocks = required_u32(params, 0, "nblocks is required")?;
    let address = required_str(params, 1, "address is required")?;
    let max_tries = optional_u64(params, 2, GenerateRequest::DEFAULT_MAX_TRIES)?;
    let payout = payout_script_from_address(
        address,
        convert::bitcoin_network(ctx.chain.chain_network),
        GENERATE_INVALID_ADDRESS,
    )?;
    let generated = control
        .generate(GenerateRequest {
            payout,
            count: nblocks,
            max_tries,
            selection: GenerateSelection::Mempool,
            submit: true,
        })
        .map_err(map_mining_control_error)?;
    let hashes: Vec<String> = generated
        .iter()
        .map(|block| block.hash.to_string())
        .collect();
    Ok(json!(hashes))
}

pub(crate) fn generateblock(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_at_most_params(params, 3)?;
    let control = ctx
        .mining
        .mining_control
        .as_ref()
        .ok_or_else(|| RpcError::MethodNotFound("generateblock".to_owned()))?;
    let output = required_str(params, 0, "output is required")?;
    let payout =
        generateblock_payout_script(output, convert::bitcoin_network(ctx.chain.chain_network))?;
    let transactions = parse_generateblock_transactions(ctx, params)?;
    let submit = optional_bool(params, 2, true)?;
    let generated = control
        .generate(GenerateRequest {
            payout,
            count: 1,
            max_tries: GenerateRequest::DEFAULT_MAX_TRIES,
            selection: GenerateSelection::Ordered(transactions),
            submit,
        })
        .map_err(map_mining_control_error)?;
    let Some(block) = generated.first() else {
        return Err(RpcError::Internal(
            "generateblock produced no block hash".to_owned(),
        ));
    };
    if submit {
        Ok(json!({ "hash": block.hash.to_string() }))
    } else {
        Ok(json!({
            "hash": block.hash.to_string(),
            "hex": block.hex,
        }))
    }
}

pub(crate) fn getnetworkhashps(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let control = ctx
        .mining
        .mining_control
        .as_ref()
        .ok_or_else(|| RpcError::MethodNotFound("getnetworkhashps".to_owned()))?;
    let (lookup, height) = parse_network_hash_ps_args(params)?;
    match control.network_hash_ps(lookup, height) {
        Ok(rate) => Ok(json!(rate)),
        Err(MiningControlError::InvalidRequest(message)) => {
            Err(RpcError::InvalidParameter(message.to_string()))
        }
        Err(error) => Err(map_mining_control_error(error)),
    }
}

pub(crate) fn getprioritisedtransactions(
    ctx: &Arc<Context>,
    params: &Value,
) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    let mut object = sonic_rs::Object::new();
    for entry in ctx.mempool.gateway.prioritised_transactions() {
        let txid = entry.txid.to_string();
        let mut row = sonic_rs::Object::new();
        let _ = row.insert("fee_delta", json!(entry.fee_delta));
        let _ = row.insert("in_mempool", json!(entry.in_mempool));
        if let Some(modified_fee) = entry.modified_fee {
            let sats = signed_sat_to_i64(modified_fee);
            let _ = row.insert("modified_fee", json!(sats));
        }
        let _ = object.insert(&txid, Value::from(row));
    }
    Ok(Value::from(object))
}

/// Bitcoin Core `getnetworkhashps(nblocks=120, height=-1)`: both arguments are
/// optional, extra positionals are rejected, and omitted/`null` params use the
/// defaults.
///
/// Invalid `nblocks`/`height` values are Core `-8`, not JSON-RPC `-32602`.
fn parse_network_hash_ps_args(params: &Value) -> Result<(i64, i64), RpcError> {
    ensure_at_most_params(params, 2)?;
    let lookup = optional_i64(params, 0, 120)?;
    let height = optional_i64(params, 1, -1)?;
    if lookup < -1 || lookup == 0 {
        return Err(RpcError::InvalidParameter(
            "Invalid nblocks. Must be a positive number or -1.".to_owned(),
        ));
    }
    if height < -1 {
        return Err(RpcError::InvalidParameter(
            "Block does not exist at specified height".to_owned(),
        ));
    }
    Ok((lookup, height))
}

fn optional_i64(params: &Value, index: usize, default: i64) -> Result<i64, RpcError> {
    if params.is_null() {
        return Ok(default);
    }
    let array = params_array(params)?;
    let Some(value) = array.get(index) else {
        return Ok(default);
    };
    if value.is_null() {
        return Ok(default);
    }
    value
        .as_i64()
        .ok_or_else(|| RpcError::InvalidType("parameter must be an integer".to_owned()))
}

fn required_u32(params: &Value, index: usize, name: &'static str) -> Result<u32, RpcError> {
    let value = required_u64(params, index, name)?;
    u32::try_from(value).map_err(|_| RpcError::InvalidParams(name))
}

fn optional_u64(params: &Value, index: usize, default: u64) -> Result<u64, RpcError> {
    if params.is_null() {
        return Ok(default);
    }
    let array = params_array(params)?;
    let Some(value) = array.get(index) else {
        return Ok(default);
    };
    if value.is_null() {
        return Ok(default);
    }
    value
        .as_u64()
        .ok_or_else(|| RpcError::InvalidType("parameter must be an integer".to_owned()))
}

fn parse_generateblock_transactions(
    ctx: &Context,
    params: &Value,
) -> Result<Vec<GenerateTx>, RpcError> {
    let array = params_array(params)?;
    let Some(value) = array.get(1) else {
        return Err(RpcError::InvalidParams("transactions is required"));
    };
    if value.is_null() {
        return Err(RpcError::InvalidParams("transactions must be an array"));
    }
    let Some(entries) = value.as_array() else {
        return Err(RpcError::InvalidType(
            "transactions must be an array".to_owned(),
        ));
    };
    let mut transactions = Vec::with_capacity(entries.len());
    let mut snapshot: Option<MempoolMiningSnapshot> = None;
    for entry in entries {
        let Some(text) = entry.as_str() else {
            return Err(RpcError::InvalidType(
                "transactions must be an array of hex strings".to_owned(),
            ));
        };
        if let Ok(txid) = Txid::from_str(text) {
            let snapshot = snapshot
                .get_or_insert_with(|| ctx.mempool.gateway.read().mining_snapshot())
                .entries
                .iter()
                .find(|entry| entry.txid == txid)
                .cloned();
            let Some(entry) = snapshot else {
                return Err(RpcError::InvalidAddressOrKey(format!(
                    "Transaction {text} not in mempool."
                )));
            };
            transactions.push(GenerateTx::ResolvedMempool(entry));
            continue;
        }
        let bytes = Vec::<u8>::from_hex(text).map_err(|_| generateblock_tx_decode_failed(text))?;
        let tx: Tx = deserialize(&bytes).map_err(|_| generateblock_tx_decode_failed(text))?;
        transactions.push(GenerateTx::Raw(tx));
    }
    Ok(transactions)
}

fn generateblock_tx_decode_failed(text: &str) -> RpcError {
    RpcError::Deserialization(format!(
        "Transaction decode failed for {text}. Make sure the tx has at least one input."
    ))
}

fn parse_block_template_request(params: &Value) -> Result<BlockTemplateRequest, RpcError> {
    if params.is_null() {
        return Ok(BlockTemplateRequest {
            mode: BlockTemplateMode::Template,
            capabilities: Vec::new(),
            rules: Vec::new(),
            long_poll_id: None,
            coinbase_budget: None,
        });
    }
    let array = params_array(params)?;
    let Some(request) = array.first() else {
        return Ok(BlockTemplateRequest {
            mode: BlockTemplateMode::Template,
            capabilities: Vec::new(),
            rules: Vec::new(),
            long_poll_id: None,
            coinbase_budget: None,
        });
    };
    if request.is_null() {
        return Ok(BlockTemplateRequest {
            mode: BlockTemplateMode::Template,
            capabilities: Vec::new(),
            rules: Vec::new(),
            long_poll_id: None,
            coinbase_budget: None,
        });
    }
    if !request.is_object() {
        return Err(RpcError::InvalidType(
            "template request must be an object".to_owned(),
        ));
    }

    let mode_text = match request.get("mode") {
        None => "template",
        Some(value) if value.is_null() => "template",
        Some(value) => value
            .as_str()
            .ok_or_else(|| RpcError::InvalidParameter("Invalid mode".to_owned()))?,
    };

    if mode_text == "proposal" {
        let data = request
            .get("data")
            .and_then(JsonValueTrait::as_str)
            .ok_or_else(|| {
                RpcError::InvalidType("Missing data String key for proposal".to_owned())
            })?;
        let (payload, _) = decode_submitted_block(data)?;
        return Ok(BlockTemplateRequest {
            mode: BlockTemplateMode::Proposal(payload.into_block()),
            capabilities: Vec::new(),
            rules: Vec::new(),
            long_poll_id: None,
            coinbase_budget: None,
        });
    }
    if mode_text != "template" {
        return Err(RpcError::InvalidParameter("Invalid mode".to_owned()));
    }

    let capabilities = parse_string_list(request.get("capabilities"), "capabilities")?;
    let rules = parse_string_list(request.get("rules"), "rules")?;
    let long_poll_id = match request.get("longpollid") {
        None => None,
        Some(value) if value.is_null() => None,
        Some(value) => {
            let Some(text) = value.as_str() else {
                return Err(RpcError::InvalidType(
                    "longpollid must be a string".to_owned(),
                ));
            };
            Some(CompactString::from(text))
        }
    };

    Ok(BlockTemplateRequest {
        mode: BlockTemplateMode::Template,
        capabilities: capabilities
            .into_iter()
            .map(MiningCapability::new)
            .collect(),
        rules: rules.into_iter().map(MiningRule::new).collect(),
        long_poll_id,
        coinbase_budget: None,
    })
}

fn parse_string_list(
    value: Option<&Value>,
    field: &'static str,
) -> Result<Vec<CompactString>, RpcError> {
    match value {
        None => Ok(Vec::new()),
        Some(value) if value.is_null() => Ok(Vec::new()),
        Some(value) => {
            let Some(array) = value.as_array() else {
                return Err(RpcError::InvalidType(match field {
                    "capabilities" => "capabilities must be an array of strings".to_owned(),
                    "rules" => "rules must be an array of strings".to_owned(),
                    _ => "field must be an array of strings".to_owned(),
                }));
            };
            let mut out = Vec::with_capacity(array.len());
            for entry in array {
                let Some(text) = entry.as_str() else {
                    return Err(RpcError::InvalidType(match field {
                        "capabilities" => "capabilities must be an array of strings".to_owned(),
                        "rules" => "rules must be an array of strings".to_owned(),
                        _ => "field must be an array of strings".to_owned(),
                    }));
                };
                out.push(CompactString::from(text));
            }
            Ok(out)
        }
    }
}

fn client_supports_rule(rules: &[MiningRule], name: &str) -> bool {
    rules.iter().any(|rule| rule.as_str() == name)
}

pub(crate) fn required_gbt_rules(network: Network) -> &'static [&'static str] {
    match network {
        Network::Signet => &["segwit", "signet"],
        _ => &["segwit"],
    }
}

fn ensure_client_rules_for_template(
    network: Network,
    client_rules: &[MiningRule],
) -> Result<(), RpcError> {
    let required = required_gbt_rules(network);
    if required.contains(&"signet") && !client_supports_rule(client_rules, "signet") {
        return Err(RpcError::InvalidParameter(GBT_REQUIRE_SIGNET.to_owned()));
    }
    if required.contains(&"segwit") && !client_supports_rule(client_rules, "segwit") {
        return Err(RpcError::InvalidParameter(GBT_REQUIRE_SEGWIT.to_owned()));
    }
    Ok(())
}

fn ensure_client_supports_mandatory_rules(
    template: &BlockTemplate,
    client_rules: &[MiningRule],
) -> Result<(), RpcError> {
    for rule in &template.rules {
        if !rule_is_mandatory(rule.as_str()) {
            continue;
        }
        if !client_supports_rule(client_rules, rule.as_str()) {
            return Err(RpcError::InvalidParameter(format!(
                "Support for '{}' rule requires explicit client support",
                rule.as_str()
            )));
        }
    }
    Ok(())
}

fn rule_is_mandatory(rule: &str) -> bool {
    matches!(rule, "segwit" | "signet")
}

fn ensure_template_ready(ctx: &Context) -> Result<(), RpcError> {
    if ctx.chain.chain_network != Network::Mainnet {
        return Ok(());
    }
    if ctx.network.peer_table.is_empty() {
        return Err(RpcError::ClientNotConnected(
            "bitcoin-rs is not connected!".to_owned(),
        ));
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    if ctx
        .chain
        .progress
        .initial_block_download(now, ctx.chain.chain_network)
    {
        return Err(RpcError::ClientInInitialDownload(
            "bitcoin-rs is in initial sync and waiting for blocks...".to_owned(),
        ));
    }
    Ok(())
}

fn render_template_transactions(
    transactions: &[bitcoin_rs_mining::CandidateTransaction],
) -> Vec<v31::BlockTemplateTransaction> {
    transactions
        .iter()
        .map(|tx| v31::BlockTemplateTransaction {
            data: tx.data_hex.clone(),
            txid: tx.txid.to_string(),
            hash: tx.wtxid.to_string(),
            depends: tx.depends.iter().map(|index| i64::from(*index)).collect(),
            fee: i64_saturated(tx.fee),
            sigops: i64::from(tx.sigop_cost),
            weight: tx.weight,
        })
        .collect()
}

fn render_block_template(template: &BlockTemplate) -> Result<Value, RpcError> {
    let candidate = &template.candidate;
    let rules = template
        .rules
        .iter()
        .map(|rule| {
            if rule_is_mandatory(rule.as_str()) {
                format!("!{}", rule.as_str())
            } else {
                rule.as_str().to_owned()
            }
        })
        .collect::<Vec<_>>();
    let version_bits_available = template
        .version_bits_available
        .iter()
        .map(|AvailableMiningRule { rule, bit }| (rule.as_str().to_owned(), u32::from(*bit)))
        .collect::<std::collections::BTreeMap<_, _>>();
    let mutable = template
        .mutable
        .iter()
        .map(|mutation| match mutation {
            TemplateMutation::Time => "time",
            TemplateMutation::Transactions => "transactions",
            TemplateMutation::PreviousBlock => "prevblock",
        })
        .map(str::to_owned)
        .collect::<Vec<_>>();
    typed_to_sonic(&v31::GetBlockTemplate {
        version: candidate.version,
        rules,
        version_bits_available,
        capabilities: template
            .capabilities
            .iter()
            .map(|capability| capability.as_str().to_owned())
            .collect(),
        version_bits_required: i64::from(template.version_bits_required),
        previous_block_hash: candidate.previous_block_hash.to_string_be(),
        transactions: render_template_transactions(&candidate.transactions),
        coinbase_aux: { std::collections::BTreeMap::from([("flags".to_owned(), String::new())]) },
        coinbase_value: i64_saturated(candidate.coinbase_value),
        long_poll_id: Some(candidate.template_id.as_str().to_owned()),
        target: compact_target_hex(candidate.bits),
        min_time: candidate.min_time,
        mutable,
        nonce_range: NONCE_RANGE.to_owned(),
        sigop_limit: i64_saturated(candidate.max_sigops),
        size_limit: i64_saturated(candidate.max_size),
        weight_limit: i64_saturated(candidate.max_weight),
        current_time: u64::from(candidate.current_time),
        bits: format!("{:08x}", candidate.bits),
        height: i64::from(candidate.height),
        signet_challenge: None,
        default_witness_commitment: candidate
            .witness_commitment
            .as_ref()
            .map(|commitment| witness_commitment_script(commitment).to_lower_hex_string()),
    })
}

fn render_mining_info(info: &MiningInfo) -> Result<Value, RpcError> {
    let chain = crate::convert::chain_name(info.network);
    let next_bits = format!("{:08x}", info.next_bits);
    let next_target = compact_target_hex(info.next_bits);
    let next_height = u64::from(info.blocks) + 1;
    typed_to_sonic_omitting_nulls(&v31::GetMiningInfo {
        blocks: u64::from(info.blocks),
        current_block_weight: info.last_candidate.map(|candidate| candidate.weight),
        current_block_tx: info
            .last_candidate
            .and_then(|candidate| i64::try_from(candidate.transactions.saturating_sub(1)).ok()),
        bits: format!("{:08x}", info.bits),
        target: compact_target_hex(info.bits),
        difficulty: info.difficulty,
        network_hash_ps: info.network_hashes_per_second,
        pooled_tx: i64_saturated(info.pooled_transactions),
        block_min_tx_fee: sat_to_btc(info.minimum_fee_rate),
        chain: chain.to_owned(),
        signet_challenge: info
            .signet
            .as_ref()
            .map(|signet| signet.challenge.to_lower_hex_string()),
        next: v31::NextBlockInfo {
            height: next_height,
            bits: next_bits,
            difficulty: info.next_difficulty,
            target: next_target,
        },
        warnings: info.warnings.iter().map(ToString::to_string).collect(),
    })
}

fn render_validation_result(result: BlockValidationResult) -> Value {
    match result {
        BlockValidationResult::Accepted => Value::new_null(),
        BlockValidationResult::Duplicate => json!("duplicate"),
        BlockValidationResult::DuplicateInvalid => json!("duplicate-invalid"),
        BlockValidationResult::DuplicateInconclusive => json!("duplicate-inconclusive"),
        BlockValidationResult::Inconclusive => json!("inconclusive"),
        BlockValidationResult::Rejected(reason) => json!(reason.as_str()),
    }
}

fn map_mining_control_error(error: MiningControlError) -> RpcError {
    match error {
        MiningControlError::InvalidRequest(message)
        | MiningControlError::Unavailable(message)
        | MiningControlError::Failed(message) => RpcError::Internal(message.to_string()),
        MiningControlError::Rejected(message) => RpcError::TxVerifyError(message.to_string()),
    }
}

#[cfg(test)]
#[expect(clippy::expect_used)]
mod tests;
