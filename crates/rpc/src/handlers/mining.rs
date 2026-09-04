use alloc::sync::Arc;
use core::str::FromStr as _;

use bitcoin_rs_mining::{
    AvailableMiningRule, BlockTemplate, BlockTemplateMode, BlockTemplateRequest,
    BlockTemplateResult, BlockValidationResult, GenerateRequest, GenerateSelection, GenerateTx,
    MiningCapability, MiningControlError, MiningInfo, MiningRule, TemplateMutation,
    witness_commitment_script,
};
use bitcoin_rs_primitives::{
    Block, ConsensusDecode, Header, Network, Tx, Txid, consensus_bytes, deserialize,
};
use compact_str::CompactString;
use sonic_rs::{JsonContainerTrait, JsonValueMutTrait, JsonValueTrait, Value, json};

use crate::compat::convert::{
    self, compact_target_hex, i64_saturated, sat_to_btc, signed_sat_to_btc, typed_to_sonic,
    typed_to_sonic_omitting_nulls,
};
use crate::context::Context;
use crate::error::RpcError;
use crate::handlers::util::{generateblock_payout_script, payout_script_from_address};
use crate::handlers::{ensure_no_params, optional_bool, params_array, required_str, required_u64};
use corepc_types::v31;

const NONCE_RANGE: &str = "00000000ffffffff";

/// Core v31.0 `src/rpc/mining.cpp` template-mode client-rule errors.
const GBT_REQUIRE_SEGWIT: &str =
    r#"getblocktemplate must be called with the segwit rule set (call with {"rules": ["segwit"]})"#;
const GBT_REQUIRE_SIGNET: &str = r#"getblocktemplate must be called with the signet rule set (call with {"rules": ["segwit", "signet"]})"#;

fn from_hex(s: &str) -> Result<Vec<u8>, ()> {
    fn nibble(byte: u8) -> Result<u8, ()> {
        Ok(match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return Err(()),
        })
    }
    let bytes = s.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        return Err(());
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.chunks_exact(2) {
        out.push((nibble(chunk[0])? << 4) | nibble(chunk[1])?);
    }
    Ok(out)
}

fn to_lower_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for &byte in bytes {
        out.push(char::from(HEX[usize::from(byte >> 4)]));
        out.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    out
}

pub(crate) fn getblocktemplate(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let control = ctx
        .mining_control
        .as_ref()
        .ok_or(RpcError::MethodDisabled("mining is unavailable"))?;
    let request = parse_block_template_request(params)?;
    if matches!(request.mode, BlockTemplateMode::Template) {
        ensure_template_ready(ctx)?;
        ensure_client_rules_for_template(ctx.chain_network, &request.rules)?;
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
        .mining_control
        .as_ref()
        .ok_or(RpcError::MethodDisabled("mining is unavailable"))?;
    let info = control.mining_info().map_err(map_mining_control_error)?;
    render_mining_info(&info)
}

pub(crate) fn submitblock(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let control = ctx
        .mining_control
        .as_ref()
        .ok_or(RpcError::MethodDisabled("mining is unavailable"))?;
    ensure_at_most_params(params, 2)?;
    let hex = required_str(params, 0, "block hex is required")?;
    let block = decode_submitted_block(hex)?;
    match control.submit_block(block) {
        Ok(result) => Ok(render_validation_result(result)),
        Err(error) => Err(map_mining_control_error(error)),
    }
}

fn decode_submitted_block(hex: &str) -> Result<Block, RpcError> {
    let bytes = from_hex(hex).map_err(|()| block_decode_failed())?;
    // Core `DecodeHexBlk` unserializes a witness block and ignores leftover
    // bytes, so extra hex after a complete block is accepted.
    let mut reader: &[u8] = &bytes;
    <Block as ConsensusDecode>::consensus_decode(&mut reader).map_err(|_| block_decode_failed())
}

fn block_decode_failed() -> RpcError {
    RpcError::Deserialization("Block decode failed".to_owned())
}

const HEADER_BYTES: usize = 80;

fn decode_block_header(hex: &str) -> Result<Header, RpcError> {
    let bytes = from_hex(hex)
        .map_err(|()| RpcError::Deserialization("Block header decode failed".to_owned()))?;
    // Core's DecodeHexBlockHeader unserializes CBlockHeader and ignores leftover
    // bytes, so extra hex after 80 bytes is accepted. Fewer than 80 bytes fail.
    let Some(header_bytes) = bytes.get(..HEADER_BYTES) else {
        return Err(RpcError::Deserialization(
            "Block header decode failed".to_owned(),
        ));
    };
    Header::consensus_decode(header_bytes)
        .map_err(|_| RpcError::Deserialization("Block header decode failed".to_owned()))
}

pub(crate) fn submitheader(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let control = ctx
        .mining_control
        .as_ref()
        .ok_or(RpcError::MethodDisabled("mining is unavailable"))?;
    let hex = required_str(params, 0, "header hex is required")?;
    let header = decode_block_header(hex)?;
    match control.submit_header(header) {
        Ok(()) => Ok(json!(null)),
        Err(error) => Err(map_mining_control_error(error)),
    }
}

pub(crate) fn prioritisetransaction(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let txid_str = required_str(params, 0, "txid is required")?;
    let txid = Txid::from_str(txid_str)
        .map_err(|_| RpcError::InvalidParams("txid must be 64 hex characters"))?;
    let array = params_array(params)?;
    // params: [txid, dummy_or_fee_delta_priority_field, fee_delta]
    // Bitcoin Core's API has the deprecated `priority_delta` middle param (now
    // a dummy `0`) and a real `fee_delta` final param. Accept whichever order.
    let fee_delta = array
        .get(2)
        .and_then(JsonValueTrait::as_i64)
        .or_else(|| array.get(1).and_then(JsonValueTrait::as_i64))
        .ok_or(RpcError::InvalidParams("fee_delta is required"))?;
    ctx.mempool
        .prioritise(txid, fee_delta)
        .map_err(|_| RpcError::InvalidParams("fee delta would overflow"))?;
    if let Some(control) = ctx.mining_control.as_ref() {
        control.publish_generation();
    }
    Ok(json!(true))
}

pub(crate) fn generatetoaddress(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_at_most_params(params, 3)?;
    let control = ctx
        .mining_control
        .as_ref()
        .ok_or(RpcError::MethodDisabled("mining is unavailable"))?;
    let nblocks = required_u32(params, 0, "nblocks is required")?;
    let address = required_str(params, 1, "address is required")?;
    let max_tries = optional_u64(params, 2, GenerateRequest::DEFAULT_MAX_TRIES)?;
    let payout = payout_script_from_address(
        address,
        convert::bitcoin_network(ctx.chain_network),
        "Invalid address or key",
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
        .mining_control
        .as_ref()
        .ok_or(RpcError::MethodDisabled("mining is unavailable"))?;
    let output = required_str(params, 0, "output is required")?;
    let payout = generateblock_payout_script(output, convert::bitcoin_network(ctx.chain_network))?;
    let transactions = parse_generateblock_transactions(params)?;
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
        .mining_control
        .as_ref()
        .ok_or(RpcError::MethodDisabled("mining is unavailable"))?;
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
    for entry in ctx.mempool.prioritised_transactions() {
        let txid = entry.txid.to_string();
        let mut row = sonic_rs::Object::new();
        let _ = row.insert("fee_delta", json!(entry.fee_delta));
        let _ = row.insert("in_mempool", json!(entry.in_mempool));
        if let Some(modified_fee) = entry.modified_fee {
            let _ = row.insert("modified_fee", json!(signed_sat_to_btc(modified_fee)));
        }
        let _ = object.insert(&txid, Value::from(row));
    }
    Ok(Value::from(object))
}

/// Bitcoin Core `getnetworkhashps(nblocks=120, height=-1)`: both arguments are
/// optional, extra positionals are rejected, and omitted/`null` params use the
/// defaults. Invalid `nblocks`/`height` values are Core `-8`, not JSON-RPC `-32602`.
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

fn ensure_at_most_params(params: &Value, max: usize) -> Result<(), RpcError> {
    if params.is_null() {
        return Ok(());
    }
    let array = params_array(params)?;
    if array.len() > max {
        return Err(RpcError::InvalidParams("too many parameters"));
    }
    Ok(())
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
        .ok_or(RpcError::InvalidType("parameter must be an integer"))
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
        .ok_or(RpcError::InvalidType("parameter must be an integer"))
}

fn parse_generateblock_transactions(params: &Value) -> Result<Vec<GenerateTx>, RpcError> {
    let array = params_array(params)?;
    let Some(value) = array.get(1) else {
        return Err(RpcError::InvalidParams("transactions is required"));
    };
    if value.is_null() {
        return Err(RpcError::InvalidParams("transactions must be an array"));
    }
    let Some(entries) = value.as_array() else {
        return Err(RpcError::InvalidType("transactions must be an array"));
    };
    let mut transactions = Vec::with_capacity(entries.len());
    for entry in entries {
        let Some(text) = entry.as_str() else {
            return Err(RpcError::InvalidType(
                "transactions must be an array of hex strings",
            ));
        };
        if let Ok(txid) = Txid::from_str(text) {
            transactions.push(GenerateTx::Mempool(txid));
            continue;
        }
        let bytes = from_hex(text)
            .map_err(|()| RpcError::InvalidParams("transaction hex is not valid hexadecimal"))?;
        let tx: Tx = deserialize(&bytes)
            .map_err(|_| RpcError::InvalidParams("transaction hex could not be decoded"))?;
        transactions.push(GenerateTx::Raw(tx));
    }
    Ok(transactions)
}

fn parse_block_template_request(params: &Value) -> Result<BlockTemplateRequest, RpcError> {
    if params.is_null() {
        return Ok(BlockTemplateRequest {
            mode: BlockTemplateMode::Template,
            capabilities: Vec::new(),
            rules: Vec::new(),
            long_poll_id: None,
        });
    }
    let array = params_array(params)?;
    let Some(request) = array.first() else {
        return Ok(BlockTemplateRequest {
            mode: BlockTemplateMode::Template,
            capabilities: Vec::new(),
            rules: Vec::new(),
            long_poll_id: None,
        });
    };
    if request.is_null() {
        return Ok(BlockTemplateRequest {
            mode: BlockTemplateMode::Template,
            capabilities: Vec::new(),
            rules: Vec::new(),
            long_poll_id: None,
        });
    }
    if !request.is_object() {
        return Err(RpcError::InvalidType("template request must be an object"));
    }

    let mode_text = match request.get("mode") {
        None => "template",
        Some(value) if value.is_null() => "template",
        Some(value) => value
            .as_str()
            .ok_or_else(|| RpcError::InvalidParameter("Invalid mode".to_owned()))?,
    };

    if mode_text == "proposal" {
        // API-12: proposal request parsing.
        let data = request.get("data").and_then(JsonValueTrait::as_str).ok_or(
            RpcError::InvalidType("Missing data String key for proposal"),
        )?;
        return Ok(BlockTemplateRequest {
            mode: BlockTemplateMode::Proposal(decode_submitted_block(data)?),
            capabilities: Vec::new(),
            rules: Vec::new(),
            long_poll_id: None,
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
                return Err(RpcError::InvalidType("longpollid must be a string"));
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
                    "capabilities" => "capabilities must be an array of strings",
                    "rules" => "rules must be an array of strings",
                    _ => "field must be an array of strings",
                }));
            };
            let mut out = Vec::with_capacity(array.len());
            for entry in array {
                let Some(text) = entry.as_str() else {
                    return Err(RpcError::InvalidType(match field {
                        "capabilities" => "capabilities must be an array of strings",
                        "rules" => "rules must be an array of strings",
                        _ => "field must be an array of strings",
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

/// Core refuses template assembly until the client lists `segwit`, and
/// `signet` on signet. Proposal mode returns before these checks.
fn ensure_client_rules_for_template(
    network: Network,
    client_rules: &[MiningRule],
) -> Result<(), RpcError> {
    if network == Network::Signet && !client_supports_rule(client_rules, "signet") {
        return Err(RpcError::InvalidParameter(GBT_REQUIRE_SIGNET.to_owned()));
    }
    if !client_supports_rule(client_rules, "segwit") {
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

/// Core refuses template assembly on mainnet while disconnected or still in IBD.
/// Proposal mode skips these gates. Test chains (`Network != Mainnet`) skip them.
fn ensure_template_ready(ctx: &Context) -> Result<(), RpcError> {
    if ctx.chain_network != Network::Mainnet {
        return Ok(());
    }
    if ctx.peer_table.is_empty() {
        return Err(RpcError::ClientNotConnected(
            "bitcoin-rs is not connected!".to_owned(),
        ));
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs());
    if ctx.is_initial_block_download(now) {
        return Err(RpcError::ClientInInitialDownload(
            "bitcoin-rs is in initial sync and waiting for blocks...".to_owned(),
        ));
    }
    Ok(())
}

fn rule_is_mandatory(rule: &str) -> bool {
    matches!(rule, "segwit" | "signet")
}

fn render_template_transactions(
    transactions: &[bitcoin_rs_mining::CandidateTransaction],
) -> Vec<v31::BlockTemplateTransaction> {
    transactions
        .iter()
        .map(|tx| v31::BlockTemplateTransaction {
            data: to_lower_hex(&consensus_bytes(tx.tx.as_ref())),
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
    let mut value = typed_to_sonic_omitting_nulls(&v31::GetBlockTemplate {
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
        coinbase_aux: std::collections::BTreeMap::new(),
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
        signet_challenge: template
            .signet
            .as_ref()
            .map(|signet| to_lower_hex(&signet.challenge)),
        default_witness_commitment: candidate
            .witness_commitment
            .as_ref()
            .map(|commitment| to_lower_hex(&witness_commitment_script(commitment))),
    })?;
    if let Some(submit_old) = template.submit_old
        && let Some(object) = value.as_object_mut()
    {
        // BIP23 `submitold` is not on corepc's pinned GetBlockTemplate type.
        let _ = object.insert("submitold", json!(submit_old));
    }
    Ok(value)
}

fn render_mining_info(info: &MiningInfo) -> Result<Value, RpcError> {
    let chain = match info.network {
        bitcoin_rs_primitives::Network::Mainnet => "main",
        bitcoin_rs_primitives::Network::Testnet3 => "test",
        bitcoin_rs_primitives::Network::Testnet4 => "testnet4",
        bitcoin_rs_primitives::Network::Signet => "signet",
        bitcoin_rs_primitives::Network::Regtest => "regtest",
    };
    let next_bits = format!("{:08x}", info.next_bits);
    let next_target = compact_target_hex(info.next_bits);
    let next_height = u64::from(info.blocks) + 1;
    typed_to_sonic(&v31::GetMiningInfo {
        blocks: u64::from(info.blocks),
        current_block_weight: info.last_candidate.map(|candidate| candidate.weight),
        // Core's `currentblocktx` excludes the coinbase. `LastCandidateInfo`
        // counts it because that is the candidate's transaction total.
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
            .map(|signet| to_lower_hex(&signet.challenge)),
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
        MiningControlError::Rejected(message) => RpcError::TxVerifyError(message.to_string()),
        MiningControlError::InvalidRequest(message)
        | MiningControlError::Unavailable(message)
        | MiningControlError::Failed(message) => RpcError::Internal(message.to_string()),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::unwrap_used)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicUsize, Ordering};

    use bitcoin_rs_mining::{
        AvailableMiningRule, BlockTemplate, BlockTemplateMode, BlockTemplateRequest,
        BlockTemplateResult, BlockValidationResult, Candidate, CandidateTransaction,
        GenerateRequest, GenerateSelection, GenerateTx, GeneratedBlock, LastCandidateInfo,
        MiningControl, MiningControlError, MiningInfo, MiningRule, SignetMiningInfo, TemplateId,
        TemplateMutation,
    };
    use bitcoin_rs_primitives::{
        BlockHash, Hash256, Header, Network, OutPoint, Tx, TxIn, TxOut, Txid,
    };
    use parking_lot::Mutex;

    use crate::handlers::util::descriptor_checksum;

    struct FakeMiningControl {
        template: Mutex<Option<BlockTemplate>>,
        proposal: Mutex<BlockValidationResult>,
        submit: Mutex<BlockValidationResult>,
        info: Mutex<MiningInfo>,
        last_request: Mutex<Option<BlockTemplateRequest>>,
        last_hash_ps: Mutex<Option<(i64, i64)>>,
        last_generate: Mutex<Option<GenerateRequest>>,
        last_header: Mutex<Option<Header>>,
        template_calls: AtomicUsize,
        submit_calls: AtomicUsize,
        info_calls: AtomicUsize,
        fail: Mutex<Option<MiningControlError>>,
    }

    impl FakeMiningControl {
        fn with_template(template: BlockTemplate) -> Arc<Self> {
            Arc::new(Self {
                template: Mutex::new(Some(template)),
                proposal: Mutex::new(BlockValidationResult::Accepted),
                submit: Mutex::new(BlockValidationResult::Accepted),
                info: Mutex::new(sample_mining_info()),
                last_request: Mutex::new(None),
                last_hash_ps: Mutex::new(None),
                last_generate: Mutex::new(None),
                last_header: Mutex::new(None),
                template_calls: AtomicUsize::new(0),
                submit_calls: AtomicUsize::new(0),
                info_calls: AtomicUsize::new(0),
                fail: Mutex::new(None),
            })
        }
    }

    impl MiningControl for FakeMiningControl {
        fn get_block_template(
            &self,
            request: BlockTemplateRequest,
        ) -> Result<BlockTemplateResult, MiningControlError> {
            self.template_calls.fetch_add(1, Ordering::Relaxed);
            let fail = self.fail.lock().clone();
            if let Some(error) = fail {
                return Err(error);
            }
            *self.last_request.lock() = Some(request.clone());
            match request.mode {
                BlockTemplateMode::Proposal(_) => {
                    Ok(BlockTemplateResult::Proposal(self.proposal.lock().clone()))
                }
                BlockTemplateMode::Template => {
                    let mut template = self
                        .template
                        .lock()
                        .clone()
                        .expect("template configured for fake control");
                    if request.long_poll_id.is_some() {
                        template.submit_old = Some(true);
                    }
                    Ok(BlockTemplateResult::Template(template))
                }
            }
        }

        fn mining_info(&self) -> Result<MiningInfo, MiningControlError> {
            self.info_calls.fetch_add(1, Ordering::Relaxed);
            let fail = self.fail.lock().clone();
            if let Some(error) = fail {
                return Err(error);
            }
            Ok(self.info.lock().clone())
        }

        fn network_hash_ps(&self, lookup: i64, height: i64) -> Result<f64, MiningControlError> {
            let fail = self.fail.lock().clone();
            if let Some(error) = fail {
                return Err(error);
            }
            *self.last_hash_ps.lock() = Some((lookup, height));
            Ok(self.info.lock().network_hashes_per_second)
        }

        fn submit_block(&self, _block: Block) -> Result<BlockValidationResult, MiningControlError> {
            self.submit_calls.fetch_add(1, Ordering::Relaxed);
            let fail = self.fail.lock().clone();
            if let Some(error) = fail {
                return Err(error);
            }
            Ok(self.submit.lock().clone())
        }

        fn submit_header(&self, header: Header) -> Result<(), MiningControlError> {
            *self.last_header.lock() = Some(header);
            let fail = self.fail.lock().clone();
            if let Some(error) = fail {
                return Err(error);
            }
            Ok(())
        }

        fn publish_generation(&self) {}

        fn generate(
            &self,
            request: GenerateRequest,
        ) -> Result<Vec<GeneratedBlock>, MiningControlError> {
            *self.last_generate.lock() = Some(request.clone());
            let hash = bitcoin_rs_primitives::BlockHash::from(Hash256::from_le_bytes(&[0xab; 32]));
            Ok(vec![
                GeneratedBlock {
                    hash,
                    hex: String::from("00"),
                };
                usize::try_from(request.count).unwrap_or(0)
            ])
        }
    }

    fn sample_candidate() -> Candidate {
        let previous = Hash256::from_le_bytes(&[0x11; 32]);
        Candidate {
            template_id: TemplateId::new(&previous, 9),
            previous_block_hash: previous,
            height: 101,
            version: 0x2000_0000,
            bits: 0x207f_ffff,
            min_time: 1_700_000_001,
            current_time: 1_700_000_010,
            csv_active: true,
            segwit_active: true,
            max_weight: 4_000_000,
            max_size: 4_000_000,
            max_sigops: 80_000,
            mempool_sequence: 9,
            coinbase: Tx {
                version: 2,
                inputs: Vec::new(),
                outputs: Vec::new(),
                lock_time: 0,
            },
            coinbase_value: 5_000_000_000,
            fees: 0,
            weight: 1_000,
            size: 250,
            sigop_cost: 0,
            transactions: Vec::new(),
            witness_merkle_root: None,
            witness_reserved_value: None,
            witness_commitment: Some(Hash256::from_le_bytes(&[0xab; 32])),
        }
    }

    fn sample_template() -> BlockTemplate {
        BlockTemplate {
            candidate: Arc::new(sample_candidate()),
            rules: vec![MiningRule::new("segwit"), MiningRule::new("csv")],
            version_bits_available: Vec::new(),
            version_bits_required: 0,
            capabilities: vec![
                MiningCapability::new("proposal"),
                MiningCapability::new("longpoll"),
            ],
            mutable: vec![
                TemplateMutation::Time,
                TemplateMutation::Transactions,
                TemplateMutation::PreviousBlock,
            ],
            submit_old: None,
            signet: None,
        }
    }

    fn sample_mining_info() -> MiningInfo {
        MiningInfo {
            blocks: 12,
            last_candidate: Some(LastCandidateInfo {
                weight: 2_500,
                transactions: 3,
            }),
            bits: 0x207f_ffff,
            difficulty: 1.0,
            network_hashes_per_second: 42.5,
            pooled_transactions: 4,
            network: Network::Regtest,
            next_bits: 0x207f_ffff,
            next_difficulty: 1.0,
            minimum_fee_rate: 1_000,
            signet: None,
            warnings: Vec::new(),
        }
    }

    fn ctx_with_control(control: Arc<dyn MiningControl>) -> Arc<Context> {
        ctx_with_control_on_network(control, Network::Regtest)
    }

    fn ctx_with_control_on_network(
        control: Arc<dyn MiningControl>,
        network: Network,
    ) -> Arc<Context> {
        let mut ctx = Context::new();
        ctx.chain_network = network;
        Arc::new(ctx.with_mining_control(control))
    }

    fn sample_block() -> Block {
        let coinbase = Tx {
            version: 1,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid::default(), 0xffff_ffff),
                script_sig: vec![0x51],
                sequence: 0xffff_ffff,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 50 * 100_000_000,
                script_pubkey: Vec::new(),
            }],
            lock_time: 0,
        };
        let merkle_root = coinbase.txid().0;
        Block {
            header: Header {
                version: 1,
                prev_blockhash: BlockHash::default(),
                merkle_root,
                time: 1_296_688_602,
                bits: 0x207f_ffff,
                nonce: 2,
            },
            txs: vec![coinbase],
        }
    }

    #[test]
    fn getblocktemplate_requires_mining_control() {
        let ctx = Arc::new(Context::new());
        let error = getblocktemplate(&ctx, &json!([{"rules":["segwit"]}]))
            .expect_err("missing control must fail");
        assert!(matches!(
            error,
            RpcError::MethodDisabled("mining is unavailable")
        ));
    }

    fn register_dummy_peer(ctx: &Context) {
        let (tx, _rx) = crossbeam_channel::bounded::<bitcoin_rs_p2p::Message>(1);
        ctx.peer_table.register(
            "127.0.0.1:8333"
                .parse()
                .unwrap_or_else(|error| panic!("dummy peer addr: {error}")),
            bitcoin_rs_p2p::PeerLease::new(tx),
        );
    }

    #[test]
    fn getblocktemplate_rejects_mainnet_without_peers() {
        let control = FakeMiningControl::with_template(sample_template());
        let ctx = Arc::new(Context::new().with_mining_control(control));
        assert_eq!(ctx.chain_network, Network::Mainnet);
        let error = getblocktemplate(&ctx, &json!([{"rules":["segwit"]}]))
            .expect_err("mainnet without peers must fail");
        assert!(matches!(error, RpcError::ClientNotConnected(_)));
        assert_eq!(error.code(), RpcError::CORE_CLIENT_NOT_CONNECTED);
        assert_eq!(error.to_string(), "bitcoin-rs is not connected!");
    }

    #[test]
    fn getblocktemplate_rejects_mainnet_during_ibd() {
        let control = FakeMiningControl::with_template(sample_template());
        let ctx = Context::new().with_mining_control(control);
        register_dummy_peer(&ctx);
        let ctx = Arc::new(ctx);
        let error = getblocktemplate(&ctx, &json!([{"rules":["segwit"]}]))
            .expect_err("mainnet IBD must fail");
        assert!(matches!(error, RpcError::ClientInInitialDownload(_)));
        assert_eq!(error.code(), RpcError::CORE_CLIENT_IN_INITIAL_DOWNLOAD);
        assert_eq!(
            error.to_string(),
            "bitcoin-rs is in initial sync and waiting for blocks..."
        );
    }

    #[test]
    fn getblocktemplate_proposal_skips_mainnet_connection_gates() {
        let control = FakeMiningControl::with_template(sample_template());
        *control.proposal.lock() = BlockValidationResult::Accepted;
        let ctx = Arc::new(Context::new().with_mining_control(control));
        let genesis = sample_block();
        let hex = to_lower_hex(&consensus_bytes(&genesis));
        let result = getblocktemplate(
            &ctx,
            &json!([{
                "mode": "proposal",
                "capabilities": ["proposal"],
                "data": hex,
            }]),
        )
        .unwrap_or_else(|err| panic!("proposal on disconnected mainnet failed: {err}"));
        assert!(result.is_null());
    }

    #[test]
    fn getblocktemplate_renders_candidate_and_reuses_control_result() {
        let control = FakeMiningControl::with_template(sample_template());
        let ctx = ctx_with_control(control.clone());
        let first = getblocktemplate(&ctx, &json!([{"rules":["segwit"]}]))
            .unwrap_or_else(|err| panic!("getblocktemplate failed: {err}"));
        let second = getblocktemplate(&ctx, &json!([{"rules":["segwit"]}]))
            .unwrap_or_else(|err| panic!("getblocktemplate failed: {err}"));
        assert_eq!(control.template_calls.load(Ordering::Relaxed), 2);
        assert_eq!(
            first.get("longpollid").and_then(JsonValueTrait::as_str),
            second.get("longpollid").and_then(JsonValueTrait::as_str)
        );
        assert_eq!(
            first.get("longpollid").and_then(JsonValueTrait::as_str),
            Some(sample_candidate().template_id.as_str())
        );
        assert_eq!(
            first.get("height").and_then(JsonValueTrait::as_u64),
            Some(101)
        );
        assert_eq!(
            first.get("coinbasevalue").and_then(JsonValueTrait::as_u64),
            Some(5_000_000_000)
        );
        let rules = first
            .get("rules")
            .and_then(JsonContainerTrait::as_array)
            .expect("rules array");
        assert_eq!(rules[0].as_str(), Some("!segwit"));
        assert_eq!(rules[1].as_str(), Some("csv"));
        assert!(
            first
                .get("default_witness_commitment")
                .and_then(JsonValueTrait::as_str)
                .is_some_and(|script| script.starts_with("6a24aa21a9ed"))
        );
        assert!(
            control
                .last_request
                .lock()
                .as_ref()
                .is_some_and(|request| matches!(request.mode, BlockTemplateMode::Template))
        );
    }

    #[test]
    fn getblocktemplate_forwards_longpollid() {
        let control = FakeMiningControl::with_template(sample_template());
        let ctx = ctx_with_control(control.clone());
        let longpoll = sample_candidate().template_id.as_str().to_owned();
        let result = getblocktemplate(
            &ctx,
            &json!([{
                "rules": ["segwit"],
                "longpollid": longpoll,
            }]),
        )
        .unwrap_or_else(|err| panic!("longpoll getblocktemplate failed: {err}"));
        let request = control
            .last_request
            .lock()
            .clone()
            .expect("request recorded");
        assert_eq!(
            request.long_poll_id.as_deref(),
            Some(sample_candidate().template_id.as_str())
        );
        assert_eq!(
            result.get("submitold").and_then(JsonValueTrait::as_bool),
            Some(true)
        );
    }

    #[test]
    fn getblocktemplate_emits_submitold_and_omits_it_when_unset() {
        let mut template = sample_template();
        template.submit_old = Some(false);
        let control = FakeMiningControl::with_template(template);
        let ctx = ctx_with_control(control);
        let result = getblocktemplate(&ctx, &json!([{"rules":["segwit"]}]))
            .unwrap_or_else(|err| panic!("submitold template failed: {err}"));
        assert_eq!(
            result.get("submitold").and_then(JsonValueTrait::as_bool),
            Some(false)
        );
        assert!(result.get("signet_challenge").is_none());
        assert!(result.get("workid").is_none());
    }

    #[test]
    fn getblocktemplate_requires_signet_rule_on_signet() {
        let mut template = sample_template();
        template.rules.push(MiningRule::new("signet"));
        template.signet = Some(SignetMiningInfo {
            challenge: vec![0x51],
        });
        let control = FakeMiningControl::with_template(template);
        let ctx = ctx_with_control_on_network(control.clone(), Network::Signet);
        let missing_signet = getblocktemplate(&ctx, &json!([{"rules":["segwit"]}]))
            .expect_err("missing signet support must fail");
        assert!(matches!(missing_signet, RpcError::InvalidParameter(_)));
        assert_eq!(missing_signet.code(), RpcError::CORE_INVALID_PARAMETER);
        assert_eq!(missing_signet.to_string(), GBT_REQUIRE_SIGNET);
        let missing_both = getblocktemplate(&ctx, &json!([{}]))
            .expect_err("missing both rules on signet must quote signet first");
        assert_eq!(missing_both.to_string(), GBT_REQUIRE_SIGNET);
        assert_eq!(control.template_calls.load(Ordering::Relaxed), 0);
        let accepted = getblocktemplate(&ctx, &json!([{"rules":["segwit", "signet"]}]))
            .unwrap_or_else(|err| panic!("signet template failed: {err}"));
        let rules = accepted
            .get("rules")
            .and_then(JsonContainerTrait::as_array)
            .expect("rules array");
        assert!(rules.iter().any(|rule| rule.as_str() == Some("!signet")));
        assert_eq!(
            accepted
                .get("signet_challenge")
                .and_then(JsonValueTrait::as_str),
            Some("51")
        );
    }

    #[test]
    fn getblocktemplate_rejects_template_mandatory_rule_without_client_support() {
        let mut template = sample_template();
        template.rules.push(MiningRule::new("signet"));
        let control = FakeMiningControl::with_template(template);
        let ctx = ctx_with_control(control.clone());
        let error = getblocktemplate(&ctx, &json!([{"rules":["segwit"]}]))
            .expect_err("template-listed signet still requires client support");
        assert!(matches!(error, RpcError::InvalidParameter(_)));
        assert_eq!(error.code(), RpcError::CORE_INVALID_PARAMETER);
        assert_eq!(
            error.to_string(),
            "Support for 'signet' rule requires explicit client support"
        );
        assert_eq!(control.template_calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn getblocktemplate_proposal_accepted_returns_null() {
        let control = FakeMiningControl::with_template(sample_template());
        *control.proposal.lock() = BlockValidationResult::Accepted;
        let ctx = ctx_with_control(control.clone());
        let genesis = sample_block();
        let hex = to_lower_hex(&consensus_bytes(&genesis));
        let result = getblocktemplate(
            &ctx,
            &json!([{
                "mode": "proposal",
                "capabilities": ["proposal"],
                "data": hex,
            }]),
        )
        .unwrap_or_else(|err| panic!("proposal failed: {err}"));
        assert!(result.is_null());
        assert!(matches!(
            control
                .last_request
                .lock()
                .as_ref()
                .map(|request| &request.mode),
            Some(BlockTemplateMode::Proposal(_))
        ));
    }

    #[test]
    fn getblocktemplate_rejects_missing_segwit_rule() {
        let control = FakeMiningControl::with_template(sample_template());
        let ctx = ctx_with_control(control.clone());
        for params in [
            json!([]),
            json!([{}]),
            json!([{"rules":[]}]),
            json!([{"rules":["csv"]}]),
        ] {
            let error =
                getblocktemplate(&ctx, &params).expect_err("missing segwit support must fail");
            assert!(matches!(error, RpcError::InvalidParameter(_)));
            assert_eq!(error.code(), RpcError::CORE_INVALID_PARAMETER);
            assert_eq!(error.to_string(), GBT_REQUIRE_SEGWIT);
        }
        assert_eq!(control.template_calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn getblocktemplate_proposal_skips_client_rule_negotiation() {
        let control = FakeMiningControl::with_template(sample_template());
        *control.proposal.lock() = BlockValidationResult::Accepted;
        let ctx = ctx_with_control_on_network(control.clone(), Network::Signet);
        let genesis = sample_block();
        let hex = to_lower_hex(&consensus_bytes(&genesis));
        let result = getblocktemplate(
            &ctx,
            &json!([{
                "mode": "proposal",
                "data": hex,
            }]),
        )
        .unwrap_or_else(|err| panic!("proposal without rules failed: {err}"));
        assert!(result.is_null());
        assert_eq!(control.template_calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn getblocktemplate_rejects_invalid_mode() {
        let control = FakeMiningControl::with_template(sample_template());
        let ctx = ctx_with_control(control.clone());
        for params in [json!([{"mode": "work"}]), json!([{"mode": 1}])] {
            let error = getblocktemplate(&ctx, &params).expect_err("invalid mode must fail");
            assert!(matches!(error, RpcError::InvalidParameter(_)));
            assert_eq!(error.code(), RpcError::CORE_INVALID_PARAMETER);
            assert_eq!(error.to_string(), "Invalid mode");
        }
        assert_eq!(control.template_calls.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn getblocktemplate_proposal_decode_matches_core() {
        let control = FakeMiningControl::with_template(sample_template());
        *control.proposal.lock() = BlockValidationResult::Accepted;
        let ctx = ctx_with_control(control.clone());
        let missing = getblocktemplate(&ctx, &json!([{"mode": "proposal"}]))
            .expect_err("proposal without data must fail");
        assert!(matches!(
            missing,
            RpcError::InvalidType("Missing data String key for proposal")
        ));
        assert_eq!(missing.code(), RpcError::CORE_INVALID_TYPE);
        for hex in ["", "00", "zz", "deadbeef"] {
            let error = getblocktemplate(&ctx, &json!([{"mode": "proposal", "data": hex}]))
                .expect_err("undecodable proposal must fail");
            assert!(matches!(error, RpcError::Deserialization(_)));
            assert_eq!(error.code(), RpcError::CORE_DESERIALIZATION_ERROR);
            assert_eq!(error.to_string(), "Block decode failed");
        }
        let genesis = sample_block();
        let mut hex = to_lower_hex(&consensus_bytes(&genesis));
        hex.push_str("ffff");
        let result = getblocktemplate(
            &ctx,
            &json!([{
                "mode": "proposal",
                "data": hex,
            }]),
        )
        .unwrap_or_else(|err| panic!("proposal trailing bytes must be ignored: {err}"));
        assert!(result.is_null());
        assert_eq!(control.template_calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn getblocktemplate_rejects_malformed_rules_and_capabilities() {
        let control = FakeMiningControl::with_template(sample_template());
        let ctx = ctx_with_control(control);
        let rules_error = getblocktemplate(&ctx, &json!([{"rules":"segwit"}]))
            .expect_err("rules must be an array");
        assert!(matches!(rules_error, RpcError::InvalidType(_)));
        let capabilities_error = getblocktemplate(&ctx, &json!([{"capabilities":[1]}]))
            .expect_err("capabilities entries must be strings");
        assert!(matches!(capabilities_error, RpcError::InvalidType(_)));
    }

    #[test]
    fn submitblock_maps_accepted_rejected_and_duplicate_results() {
        let control = FakeMiningControl::with_template(sample_template());
        let ctx = ctx_with_control(control.clone());
        let genesis = sample_block();
        let hex = to_lower_hex(&consensus_bytes(&genesis));

        *control.submit.lock() = BlockValidationResult::Accepted;
        assert!(
            submitblock(&ctx, &json!([hex.as_str()]))
                .unwrap_or_else(|err| panic!("submit failed: {err}"))
                .is_null()
        );

        *control.submit.lock() = BlockValidationResult::Duplicate;
        assert_eq!(
            submitblock(&ctx, &json!([hex.as_str()]))
                .unwrap_or_else(|err| panic!("submit failed: {err}"))
                .as_str(),
            Some("duplicate")
        );

        *control.submit.lock() = BlockValidationResult::Rejected(CompactString::from("high-hash"));
        assert_eq!(
            submitblock(&ctx, &json!([hex.as_str()]))
                .unwrap_or_else(|err| panic!("submit failed: {err}"))
                .as_str(),
            Some("high-hash")
        );
        assert_eq!(control.submit_calls.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn submitblock_requires_mining_control_and_rejects_garbage_encoding() {
        let missing = Arc::new(Context::new());
        let error = submitblock(&missing, &json!(["00"]))
            .expect_err("submitblock without control must fail");
        assert!(matches!(
            error,
            RpcError::MethodDisabled("mining is unavailable")
        ));

        let control = FakeMiningControl::with_template(sample_template());
        let ctx = ctx_with_control(control);
        for hex in ["", "00", "zz", "0", "deadbeef"] {
            let error = submitblock(&ctx, &json!([hex])).expect_err("undecodable block must fail");
            assert!(matches!(error, RpcError::Deserialization(_)));
            assert_eq!(error.code(), RpcError::CORE_DESERIALIZATION_ERROR);
            assert_eq!(error.to_string(), "Block decode failed");
        }
    }

    #[test]
    fn submitblock_ignores_bip22_dummy_and_trailing_bytes() {
        let control = FakeMiningControl::with_template(sample_template());
        let ctx = ctx_with_control(control.clone());
        let genesis = sample_block();
        let mut hex = to_lower_hex(&consensus_bytes(&genesis));
        hex.push_str("ffff");
        let result = submitblock(&ctx, &json!([hex.as_str(), "ignored"]))
            .unwrap_or_else(|err| panic!("dummy and trailing bytes must be ignored: {err}"));
        assert!(result.is_null());
        assert_eq!(control.submit_calls.load(Ordering::Relaxed), 1);
        let extra = submitblock(&ctx, &json!([hex.as_str(), "ignored", "too-many"]))
            .expect_err("a third submitblock argument must fail");
        assert!(matches!(
            extra,
            RpcError::InvalidParams("too many parameters")
        ));
    }

    #[test]
    fn submitheader_requires_mining_control() {
        let ctx = Arc::new(Context::new());
        let error = submitheader(&ctx, &json!(["00"])).expect_err("missing control must fail");
        assert!(matches!(
            error,
            RpcError::MethodDisabled("mining is unavailable")
        ));
    }

    #[test]
    fn submitheader_rejects_undecodable_headers() {
        let control = FakeMiningControl::with_template(sample_template());
        let ctx = ctx_with_control(control);
        for hex in ["", "00", "zz", "0"] {
            let error =
                submitheader(&ctx, &json!([hex])).expect_err("undecodable header must fail");
            assert!(matches!(error, RpcError::Deserialization(_)));
            assert_eq!(error.code(), RpcError::CORE_DESERIALIZATION_ERROR);
            assert_eq!(error.to_string(), "Block header decode failed");
        }
    }

    #[test]
    fn submitheader_returns_null_and_forwards_decoded_header() {
        let control = FakeMiningControl::with_template(sample_template());
        let ctx = ctx_with_control(control.clone());
        let header = sample_block().header;
        let mut hex = to_lower_hex(&consensus_bytes(&header));
        hex.push_str("ffff");
        let result = submitheader(&ctx, &json!([hex]))
            .unwrap_or_else(|err| panic!("submitheader failed: {err}"));
        assert!(result.is_null());
        assert_eq!(*control.last_header.lock(), Some(header));
    }

    #[test]
    fn submitheader_maps_rejected_to_verify_error() {
        let control = FakeMiningControl::with_template(sample_template());
        *control.fail.lock() = Some(MiningControlError::Rejected(CompactString::from(
            "Must submit previous header (00) first",
        )));
        let ctx = ctx_with_control(control);
        let hex = to_lower_hex(&consensus_bytes(&sample_block().header));
        let error = submitheader(&ctx, &json!([hex])).expect_err("rejected header must fail");
        assert!(matches!(error, RpcError::TxVerifyError(_)));
        assert_eq!(error.code(), RpcError::CORE_VERIFY_ERROR);
        assert_eq!(error.to_string(), "Must submit previous header (00) first");
    }

    #[test]
    fn getmininginfo_projects_control_state() {
        let control = FakeMiningControl::with_template(sample_template());
        let ctx = ctx_with_control(control.clone());
        let result = getmininginfo(&ctx, &json!([]))
            .unwrap_or_else(|err| panic!("getmininginfo failed: {err}"));
        assert_eq!(
            result.get("blocks").and_then(JsonValueTrait::as_u64),
            Some(12)
        );
        assert_eq!(
            result
                .get("currentblockweight")
                .and_then(JsonValueTrait::as_u64),
            Some(2_500)
        );
        assert_eq!(
            result
                .get("currentblocktx")
                .and_then(JsonValueTrait::as_u64),
            Some(2)
        );
        assert_eq!(
            result.get("pooledtx").and_then(JsonValueTrait::as_u64),
            Some(4)
        );
        assert_eq!(
            result.get("chain").and_then(JsonValueTrait::as_str),
            Some("regtest")
        );
        assert_eq!(control.info_calls.load(Ordering::Relaxed), 1);
    }

    #[test]
    // Core emits the tip's nBits at top level and the next block's only under next.
    fn getmininginfo_top_level_target_is_the_tip_not_the_next_block() {
        let control = FakeMiningControl::with_template(sample_template());
        {
            let mut info = control.info.lock();
            info.bits = 0x1d00_ffff;
            info.difficulty = 1.0;
            info.next_bits = 0x1c00_ffff;
        }
        let ctx = ctx_with_control(control);
        let result = getmininginfo(&ctx, &json!([]))
            .unwrap_or_else(|err| panic!("getmininginfo failed: {err}"));
        let target = result
            .get("target")
            .and_then(JsonValueTrait::as_str)
            .expect("top-level target");
        let next = result.get("next").expect("next object");
        let next_target = next
            .get("target")
            .and_then(JsonValueTrait::as_str)
            .expect("next target");
        assert_eq!(
            result.get("bits").and_then(JsonValueTrait::as_str),
            Some("1d00ffff")
        );
        assert_eq!(target, compact_target_hex(0x1d00_ffff));
        assert_eq!(
            next.get("bits").and_then(JsonValueTrait::as_str),
            Some("1c00ffff")
        );
        assert_eq!(next_target, compact_target_hex(0x1c00_ffff));
        assert_ne!(target, next_target);
    }

    #[test]
    fn getmininginfo_requires_mining_control() {
        let ctx = Arc::new(Context::new());
        let error = getmininginfo(&ctx, &json!([])).expect_err("missing control must fail");
        assert!(matches!(
            error,
            RpcError::MethodDisabled("mining is unavailable")
        ));
    }

    #[test]
    fn prioritisetransaction_calls_mempool_prioritise_directly() {
        use bitcoin_rs_mempool::MempoolEntry;

        let ctx = Arc::new(Context::new());
        let tx = Tx {
            version: 2,
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time: 0,
        };
        let txid = tx.txid();
        {
            let mut pool = ctx.mempool.pool().write();
            pool.insert_entry(MempoolEntry::new(Arc::new(tx), 100, 1_000, 1, 7))
                .unwrap_or_else(|err| panic!("insert failed: {err}"));
        }
        let txid_hex = txid.to_string();
        let result = prioritisetransaction(&ctx, &json!([txid_hex.as_str(), 0, 500]))
            .unwrap_or_else(|err| panic!("prioritisetransaction failed: {err}"));
        assert_eq!(result.as_bool(), Some(true));
        let pool = ctx.mempool.read();
        let entry = pool
            .entry_by_txid(&txid)
            .expect("entry remains after prioritise");
        assert_eq!(entry.fee_delta, 500);
        assert_eq!(entry.fee, 1_000);
    }

    #[test]
    fn getblocktemplate_includes_selected_transactions() {
        let mut template = sample_template();
        let tx = Tx {
            version: 2,
            inputs: Vec::new(),
            outputs: vec![TxOut {
                value: 1_000,
                script_pubkey: Vec::new(),
            }],
            lock_time: 0,
        };
        let txid = tx.txid();
        let wtxid = tx.wtxid();
        let mut candidate = sample_candidate();
        candidate.transactions.push(CandidateTransaction {
            tx: Arc::new(tx.clone()),
            txid,
            wtxid,
            fee: 100,
            fee_delta: 0,
            modified_fee: 100,
            sigop_cost: 2,
            weight: 400,
            size: 100,
            depends: vec![],
        });
        template.candidate = Arc::new(candidate);
        let control = FakeMiningControl::with_template(template);
        let ctx = ctx_with_control(control);
        let result = getblocktemplate(&ctx, &json!([{"rules":["segwit"]}]))
            .unwrap_or_else(|err| panic!("template with txs failed: {err}"));
        let transactions = result
            .get("transactions")
            .and_then(JsonContainerTrait::as_array)
            .expect("transactions array");
        assert_eq!(transactions.len(), 1);
        let txid_hex = txid.to_string();
        let tx_hex = to_lower_hex(&consensus_bytes(&tx));
        assert_eq!(
            transactions[0].get("txid").and_then(JsonValueTrait::as_str),
            Some(txid_hex.as_str())
        );
        assert_eq!(
            transactions[0].get("data").and_then(JsonValueTrait::as_str),
            Some(tx_hex.as_str())
        );
    }

    #[test]
    fn getblocktemplate_renders_version_bits_and_forced_rules() {
        let mut template = sample_template();
        template.version_bits_available = vec![
            AvailableMiningRule {
                rule: MiningRule::new("taproot"),
                bit: 2,
            },
            AvailableMiningRule {
                rule: MiningRule::new("testdummy"),
                bit: 28,
            },
        ];
        template.version_bits_required = 1 << 2;
        let control = FakeMiningControl::with_template(template);
        let ctx = ctx_with_control(control);
        let result = getblocktemplate(&ctx, &json!([{"rules":["segwit"]}]))
            .unwrap_or_else(|err| panic!("version-bits template failed: {err}"));

        let vbavailable = result.get("vbavailable").expect("vbavailable object");
        assert_eq!(
            vbavailable.get("taproot").and_then(JsonValueTrait::as_u64),
            Some(2)
        );
        assert_eq!(
            vbavailable
                .get("testdummy")
                .and_then(JsonValueTrait::as_u64),
            Some(28)
        );
        assert_eq!(
            result.get("vbrequired").and_then(JsonValueTrait::as_u64),
            Some(1 << 2)
        );
        let rules = result
            .get("rules")
            .and_then(JsonContainerTrait::as_array)
            .expect("rules array");
        assert_eq!(rules[0].as_str(), Some("!segwit"));
        assert_eq!(rules[1].as_str(), Some("csv"));
    }

    #[test]
    fn getmininginfo_can_include_signet_challenge() {
        let control = FakeMiningControl::with_template(sample_template());
        {
            let mut info = control.info.lock();
            info.network = Network::Signet;
            info.signet = Some(SignetMiningInfo {
                challenge: vec![0x51],
            });
        }
        let ctx = ctx_with_control(control);
        let result = getmininginfo(&ctx, &json!([]))
            .unwrap_or_else(|err| panic!("signet mininginfo failed: {err}"));
        assert_eq!(
            result.get("chain").and_then(JsonValueTrait::as_str),
            Some("signet")
        );
        assert_eq!(
            result
                .get("signet_challenge")
                .and_then(JsonValueTrait::as_str),
            Some("51")
        );
    }

    #[test]
    fn getmininginfo_reports_testnet4_separately_from_testnet3() {
        // Core's getmininginfo reports ChainTypeToString(TESTNET4) == "testnet4",
        // matching getblockchaininfo. The old code collapsed both to "test".
        let control = FakeMiningControl::with_template(sample_template());
        {
            let mut info = control.info.lock();
            info.network = Network::Testnet4;
        }
        let ctx = ctx_with_control(control);
        let result = getmininginfo(&ctx, &json!([]))
            .unwrap_or_else(|err| panic!("testnet4 mininginfo failed: {err}"));
        assert_eq!(
            result.get("chain").and_then(JsonValueTrait::as_str),
            Some("testnet4")
        );
    }

    #[test]
    fn getnetworkhashps_requires_mining_control() {
        let ctx = Arc::new(Context::new());
        let error = getnetworkhashps(&ctx, &json!([])).expect_err("missing control must fail");
        assert!(matches!(
            error,
            RpcError::MethodDisabled("mining is unavailable")
        ));
    }

    #[test]
    fn getnetworkhashps_forwards_defaults_and_caller_window() {
        let control = FakeMiningControl::with_template(sample_template());
        let ctx = ctx_with_control(control.clone());
        let result = getnetworkhashps(&ctx, &json!([]))
            .unwrap_or_else(|err| panic!("default getnetworkhashps failed: {err}"));
        assert!((result.as_f64().unwrap_or(0.0) - 42.5).abs() < f64::EPSILON);
        assert_eq!(*control.last_hash_ps.lock(), Some((120, -1)));

        let omitted = getnetworkhashps(&ctx, &Value::new_null())
            .unwrap_or_else(|err| panic!("omitted getnetworkhashps params failed: {err}"));
        assert!((omitted.as_f64().unwrap_or(0.0) - 42.5).abs() < f64::EPSILON);
        assert_eq!(*control.last_hash_ps.lock(), Some((120, -1)));

        getnetworkhashps(&ctx, &json!([60, 10]))
            .unwrap_or_else(|err| panic!("windowed getnetworkhashps failed: {err}"));
        assert_eq!(*control.last_hash_ps.lock(), Some((60, 10)));
    }

    #[test]
    fn getnetworkhashps_rejects_arity_and_core_invalid_windows() {
        let control = FakeMiningControl::with_template(sample_template());
        let ctx = ctx_with_control(control.clone());

        let extra = getnetworkhashps(&ctx, &json!([120, -1, 1]))
            .expect_err("trailing getnetworkhashps arguments must fail");
        assert!(matches!(
            extra,
            RpcError::InvalidParams("too many parameters")
        ));
        assert!(control.last_hash_ps.lock().is_none());

        let nblocks = getnetworkhashps(&ctx, &json!([0])).expect_err("nblocks 0 must fail");
        assert!(matches!(
            nblocks,
            RpcError::InvalidParameter(message)
                if message == "Invalid nblocks. Must be a positive number or -1."
        ));

        let negative_lookup = getnetworkhashps(&ctx, &json!([-2]))
            .expect_err("nblocks other than -1 or positive must fail");
        assert!(matches!(
            negative_lookup,
            RpcError::InvalidParameter(message)
                if message == "Invalid nblocks. Must be a positive number or -1."
        ));

        let height =
            getnetworkhashps(&ctx, &json!([120, -10])).expect_err("height below -1 must fail");
        assert!(matches!(
            height,
            RpcError::InvalidParameter(message)
                if message == "Block does not exist at specified height"
        ));
        assert!(control.last_hash_ps.lock().is_none());
    }

    #[test]
    // CONTRACT: docs/contracts/external-api.md#API-06
    fn getnetworkhashps_projects_control_invalid_request_as_invalid_parameter() {
        let control = FakeMiningControl::with_template(sample_template());
        *control.fail.lock() = Some(MiningControlError::InvalidRequest(CompactString::from(
            "Block does not exist at specified height",
        )));
        let ctx = ctx_with_control(control);
        let error = getnetworkhashps(&ctx, &json!([120, 99]))
            .expect_err("out-of-range height from control must fail");
        assert!(matches!(
            error,
            RpcError::InvalidParameter(message)
                if message == "Block does not exist at specified height"
        ));
    }

    #[test]
    fn getprioritisedtransactions_projects_the_overlay() {
        use bitcoin_rs_mempool::MempoolEntry;

        let ctx = Arc::new(Context::new());
        let pooled_tx = Tx {
            version: 2,
            inputs: Vec::new(),
            outputs: Vec::new(),
            lock_time: 0,
        };
        let pooled = pooled_tx.txid();
        {
            let mut pool = ctx.mempool.pool().write();
            pool.insert_entry(MempoolEntry::new(Arc::new(pooled_tx), 100, 1_000, 1, 7))
                .unwrap_or_else(|err| panic!("insert failed: {err}"));
        }
        let absent = Txid::from(Hash256::from_le_bytes(&[0x22; 32]));
        ctx.mempool
            .prioritise(pooled, 500)
            .unwrap_or_else(|err| panic!("pooled overlay: {err}"));
        ctx.mempool
            .prioritise(absent, -25)
            .unwrap_or_else(|err| panic!("absent overlay: {err}"));
        let result = getprioritisedtransactions(&ctx, &json!([]))
            .unwrap_or_else(|err| panic!("getprioritisedtransactions failed: {err}"));
        let object = result
            .as_object()
            .unwrap_or_else(|| panic!("object result"));
        let pooled_row = object
            .get(&pooled.to_string())
            .unwrap_or_else(|| panic!("pooled overlay is listed"));
        assert_eq!(
            pooled_row.get("fee_delta").and_then(JsonValueTrait::as_i64),
            Some(500)
        );
        assert_eq!(
            pooled_row
                .get("in_mempool")
                .and_then(JsonValueTrait::as_bool),
            Some(true)
        );
        let modified = pooled_row
            .get("modified_fee")
            .and_then(JsonValueTrait::as_f64)
            .unwrap_or_else(|| panic!("pooled overlay must carry modified_fee in BTC"));
        assert!(
            (modified - signed_sat_to_btc(1_500)).abs() < f64::EPSILON,
            "modified_fee must be actual fee plus delta in BTC, got {modified}"
        );
        let absent_row = object
            .get(&absent.to_string())
            .unwrap_or_else(|| panic!("absent overlay is listed"));
        assert_eq!(
            absent_row.get("fee_delta").and_then(JsonValueTrait::as_i64),
            Some(-25)
        );
        assert_eq!(
            absent_row
                .get("in_mempool")
                .and_then(JsonValueTrait::as_bool),
            Some(false)
        );
        assert!(
            absent_row.get("modified_fee").is_none(),
            "Core omits modified_fee unless the tx is in the mempool"
        );
    }

    const REGTEST_ADDRESS: &str = "bcrt1qjqmxmkpmxt80xz4y3746zgt0q3u3ferr34acd5";

    fn sample_raw_tx() -> Tx {
        Tx {
            version: 2,
            inputs: vec![TxIn {
                previous_output: OutPoint::new(Txid::default(), 0),
                script_sig: vec![],
                sequence: u32::MAX,
                witness: vec![],
            }],
            outputs: vec![TxOut {
                value: 50_000,
                script_pubkey: vec![0x51],
            }],
            lock_time: 0,
        }
    }

    /// API-05: generatetoaddress pays a network-valid address and returns n hashes.
    #[test]
    fn generatetoaddress_projects_solved_hashes() {
        let control = FakeMiningControl::with_template(sample_template());
        let ctx = ctx_with_control(control);
        let result = generatetoaddress(&ctx, &json!([2, REGTEST_ADDRESS]))
            .unwrap_or_else(|err| panic!("generatetoaddress failed: {err}"));
        let hashes = result
            .as_array()
            .unwrap_or_else(|| panic!("generatetoaddress returns a hash array"));
        assert_eq!(hashes.len(), 2);
        assert!(hashes.iter().all(|hash| hash.as_str().is_some()));
    }

    /// API-05: generatetoaddress rejects raw script hex and descriptors.
    #[test]
    fn generatetoaddress_rejects_script_hex_and_descriptors() {
        let control = FakeMiningControl::with_template(sample_template());
        let ctx = ctx_with_control(control);
        for payout in ["51", &format!("addr({REGTEST_ADDRESS})")] {
            let error = generatetoaddress(&ctx, &json!([1, payout]))
                .err()
                .unwrap_or_else(|| panic!("`{payout}` must not be an address"));
            assert_eq!(error.code(), RpcError::CORE_NOT_FOUND, "for `{payout}`");
        }
    }

    /// API-05: generateblock output is an address or descriptor; empty txs is coinbase-only.
    #[test]
    fn generateblock_projects_hash_object() {
        let control = FakeMiningControl::with_template(sample_template());
        let ctx = ctx_with_control(control.clone());
        let result = generateblock(&ctx, &json!([REGTEST_ADDRESS, []]))
            .unwrap_or_else(|err| panic!("generateblock failed: {err}"));
        assert!(
            result
                .get("hash")
                .and_then(JsonValueTrait::as_str)
                .is_some()
        );
        assert!(result.get("hex").is_none());
        let request = control
            .last_generate
            .lock()
            .clone()
            .unwrap_or_else(|| panic!("generateblock must call generate"));
        assert_eq!(request.selection, GenerateSelection::Ordered(Vec::new()));
        assert!(request.submit);
    }

    /// API-05: generateblock accepts `addr()` without a checksum.
    #[test]
    fn generateblock_accepts_addr_descriptor() {
        let control = FakeMiningControl::with_template(sample_template());
        let ctx = ctx_with_control(control.clone());
        let result = generateblock(&ctx, &json!([format!("addr({REGTEST_ADDRESS})"), []]))
            .unwrap_or_else(|err| panic!("addr() descriptor must be accepted: {err}"));
        assert!(
            result
                .get("hash")
                .and_then(JsonValueTrait::as_str)
                .is_some()
        );
        let request = control
            .last_generate
            .lock()
            .clone()
            .unwrap_or_else(|| panic!("generateblock must call generate"));
        assert_eq!(
            request.payout,
            payout_script_from_address(
                REGTEST_ADDRESS,
                bitcoin::Network::Regtest,
                "Invalid address or key",
            )
            .unwrap_or_else(|err| panic!("fixture address must decode: {err}"))
        );
    }

    /// API-05: generateblock submit=false returns solved hex without persisting.
    #[test]
    fn generateblock_without_submit_includes_hex() {
        let control = FakeMiningControl::with_template(sample_template());
        let ctx = ctx_with_control(control.clone());
        let result = generateblock(&ctx, &json!([REGTEST_ADDRESS, [], false]))
            .unwrap_or_else(|err| panic!("generateblock failed: {err}"));
        assert!(
            result
                .get("hash")
                .and_then(JsonValueTrait::as_str)
                .is_some()
        );
        assert_eq!(
            result.get("hex").and_then(JsonValueTrait::as_str),
            Some("00")
        );
        let request = control
            .last_generate
            .lock()
            .clone()
            .unwrap_or_else(|| panic!("generateblock must call generate"));
        assert!(!request.submit);
    }

    /// API-05: generateblock requires the transactions array; null is not an empty list.
    #[test]
    fn generateblock_requires_transactions_array() {
        let control = FakeMiningControl::with_template(sample_template());
        let ctx = ctx_with_control(control);
        let missing = generateblock(&ctx, &json!([REGTEST_ADDRESS]))
            .err()
            .unwrap_or_else(|| panic!("omitted transactions must fail"));
        assert_eq!(missing.code(), RpcError::INVALID_PARAMS);
        let null = generateblock(&ctx, &json!([REGTEST_ADDRESS, Value::new_null()]))
            .err()
            .unwrap_or_else(|| panic!("null transactions must fail"));
        assert_eq!(null.code(), RpcError::INVALID_PARAMS);
        let hex = generateblock(&ctx, &json!(["51", []]))
            .err()
            .unwrap_or_else(|| panic!("bare script hex must fail"));
        assert_eq!(hex.code(), RpcError::CORE_NOT_FOUND);
    }

    /// API-05: 64-character hex is a mempool txid; longer hex is a raw transaction.
    #[test]
    fn generateblock_keeps_raw_transactions() {
        let control = FakeMiningControl::with_template(sample_template());
        let ctx = ctx_with_control(control.clone());
        let tx = sample_raw_tx();
        let raw_hex = to_lower_hex(&consensus_bytes(&tx));
        let txid = Txid::from(Hash256::from_le_bytes(&[0xcd; 32]));
        generateblock(&ctx, &json!([REGTEST_ADDRESS, [txid.to_string(), raw_hex]]))
            .unwrap_or_else(|err| panic!("generateblock failed: {err}"));
        let request = control
            .last_generate
            .lock()
            .clone()
            .unwrap_or_else(|| panic!("generateblock must call generate"));
        assert_eq!(
            request.selection,
            GenerateSelection::Ordered(vec![GenerateTx::Mempool(txid), GenerateTx::Raw(tx)])
        );
    }

    /// API-05: extra generateblock positionals are rejected, matching Core arity.
    #[test]
    fn generateblock_rejects_trailing_parameters() {
        let control = FakeMiningControl::with_template(sample_template());
        let ctx = ctx_with_control(control);
        let extra = generateblock(&ctx, &json!([REGTEST_ADDRESS, [], true, "unexpected"]))
            .err()
            .unwrap_or_else(|| panic!("trailing generateblock arguments must fail"));
        assert!(matches!(
            extra,
            RpcError::InvalidParams("too many parameters")
        ));
    }

    /// API-05: a supplied descriptor checksum is verified even when optional.
    #[test]
    fn generateblock_rejects_invalid_supplied_checksums() {
        let control = FakeMiningControl::with_template(sample_template());
        let ctx = ctx_with_control(control);
        let descriptor = format!("addr({REGTEST_ADDRESS})");
        let checksum = descriptor_checksum(&descriptor)
            .unwrap_or_else(|| panic!("fixture descriptor must have a checksum"));
        generateblock(&ctx, &json!([format!("{descriptor}#{checksum}"), []]))
            .unwrap_or_else(|err| panic!("a matching checksum must be accepted: {err}"));
        for (input, expected) in [
            (format!("{descriptor}#qqqqqqqq"), "does not match"),
            (
                format!("{descriptor}#short"),
                "Expected 8 character checksum",
            ),
            (
                format!("{descriptor}#aaaaaaaa#bbbbbbbb"),
                "Multiple '#' symbols",
            ),
        ] {
            let error = generateblock(&ctx, &json!([input.clone(), []]))
                .err()
                .unwrap_or_else(|| panic!("`{input}` must be refused"));
            assert_eq!(error.code(), RpcError::CORE_NOT_FOUND, "for `{input}`");
            assert!(
                error.to_string().contains(expected),
                "`{input}` must say why: got {error}"
            );
        }
    }
}
