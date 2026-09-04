use alloc::sync::Arc;
use core::str::FromStr as _;

use bitcoin_rs_mining::witness_commitment_script;
use bitcoin_rs_primitives::{Block, Txid, consensus_bytes, deserialize};
use compact_str::CompactString;
use sonic_rs::{JsonContainerTrait, JsonValueTrait, Value, json};

use crate::compat::convert::{compact_target_hex, i64_saturated, sat_to_btc, typed_to_sonic};
use crate::context::Context;
use crate::context::{
    AvailableMiningRule, BlockTemplate, BlockTemplateMode, BlockTemplateRequest,
    BlockTemplateResult, BlockValidationResult, MiningCapability, MiningControlError, MiningInfo,
    MiningRule, TemplateMutation,
};
use crate::error::RpcError;
use crate::handlers::{ensure_no_params, params_array, required_str};
use corepc_types::v31;

const NONCE_RANGE: &str = "00000000ffffffff";

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
    let hex = required_str(params, 0, "block hex is required")?;
    let bytes = from_hex(hex)
        .map_err(|()| RpcError::InvalidParams("block hex is not valid hexadecimal"))?;
    let block: Block = match deserialize(&bytes) {
        Ok(block) => block,
        Err(_) => return Ok(json!("bad-block-encoding")),
    };
    match control.submit_block(block) {
        Ok(result) => Ok(render_validation_result(result)),
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

    let mode_text = match request.get("mode") {
        None => "template",
        Some(value) if value.is_null() => "template",
        Some(value) => value
            .as_str()
            .ok_or(RpcError::InvalidType("mode must be a string"))?,
    };

    let mode = match mode_text {
        "template" => BlockTemplateMode::Template,
        "proposal" => {
            if !capabilities
                .iter()
                .any(|capability| capability.eq_ignore_ascii_case("proposal"))
            {
                return Err(RpcError::InvalidParams(
                    "proposal mode requires the proposal capability",
                ));
            }
            let data = request.get("data").and_then(JsonValueTrait::as_str).ok_or(
                RpcError::InvalidParams("proposal mode requires hex-encoded block data"),
            )?;
            let bytes = from_hex(data)
                .map_err(|()| RpcError::InvalidParams("block data is not valid hexadecimal"))?;
            let block: Block = deserialize(&bytes)
                .map_err(|_| RpcError::InvalidParams("block data could not be decoded"))?;
            BlockTemplateMode::Proposal(block)
        }
        _ => {
            return Err(RpcError::InvalidParams("mode must be template or proposal"));
        }
    };

    Ok(BlockTemplateRequest {
        mode,
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

fn ensure_client_supports_mandatory_rules(
    template: &BlockTemplate,
    client_rules: &[MiningRule],
) -> Result<(), RpcError> {
    for rule in &template.rules {
        if !rule_is_mandatory(rule.as_str()) {
            continue;
        }
        if !client_rules
            .iter()
            .any(|supported| supported.as_str() == rule.as_str())
        {
            return Err(RpcError::InvalidParams(
                "support for mandatory rules is required",
            ));
        }
    }
    Ok(())
}

fn rule_is_mandatory(rule: &str) -> bool {
    rule == "segwit"
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
        signet_challenge: None,
        default_witness_commitment: candidate
            .witness_commitment
            .as_ref()
            .map(|commitment| to_lower_hex(&witness_commitment_script(commitment))),
    })
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
        current_block_tx: info
            .last_candidate
            .and_then(|candidate| i64::try_from(candidate.transactions).ok()),
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

    use bitcoin_rs_mining::{Candidate, CandidateTransaction, TemplateId};
    use bitcoin_rs_primitives::{
        BlockHash, Hash256, Header, Network, OutPoint, Tx, TxIn, TxOut, Txid,
    };
    use parking_lot::Mutex;

    use crate::context::{
        AvailableMiningRule, BlockTemplate, BlockTemplateMode, BlockTemplateRequest,
        BlockTemplateResult, BlockValidationResult, LastCandidateInfo, MiningControl,
        MiningControlError, MiningInfo, MiningRule, SignetMiningInfo, TemplateMutation,
    };

    struct FakeMiningControl {
        template: Mutex<Option<BlockTemplate>>,
        proposal: Mutex<BlockValidationResult>,
        submit: Mutex<BlockValidationResult>,
        info: Mutex<MiningInfo>,
        last_request: Mutex<Option<BlockTemplateRequest>>,
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

        fn submit_block(&self, _block: Block) -> Result<BlockValidationResult, MiningControlError> {
            self.submit_calls.fetch_add(1, Ordering::Relaxed);
            let fail = self.fail.lock().clone();
            if let Some(error) = fail {
                return Err(error);
            }
            Ok(self.submit.lock().clone())
        }

        fn publish_generation(&self) {}
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
            work_id: None,
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
        Arc::new(Context::new().with_mining_control(control))
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
        getblocktemplate(
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
        // `submitold`/`workid` are BIP23 extras outside the pinned v17
        // GetBlockTemplate contract and are no longer emitted.
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
    fn getblocktemplate_rejects_missing_mandatory_rule_support() {
        let control = FakeMiningControl::with_template(sample_template());
        let ctx = ctx_with_control(control);
        let error = getblocktemplate(&ctx, &json!([{"rules":["csv"]}]))
            .expect_err("missing segwit support must fail");
        assert!(matches!(error, RpcError::InvalidParams(_)));
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
        let result = submitblock(&ctx, &json!(["deadbeef"]))
            .unwrap_or_else(|err| panic!("garbage should stay a result string: {err}"));
        assert_eq!(result.as_str(), Some("bad-block-encoding"));
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
            Some(3)
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
        template.work_id = Some(CompactString::from("work-abc"));
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
}
