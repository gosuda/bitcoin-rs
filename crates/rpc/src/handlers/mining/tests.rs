use super::*;
use alloc::sync::Arc;
use bitcoin_rs_primitives::Block;
use core::sync::atomic::Ordering;

use bitcoin_rs_mining::{
    AvailableMiningRule, BlockTemplate, BlockTemplateMode, BlockValidationResult, Candidate,
    CandidateTransaction, FakeMiningControl, GenerateSelection, GenerateTx, LastCandidateInfo,
    MiningControl, MiningControlError, MiningInfo, MiningRule, SignetMiningInfo, TemplateId,
    TemplateMutation,
};
use bitcoin_rs_primitives::{
    Amount, BlockHash, CompactTarget, Hash256, Header, LockTime, Network, OutPoint, Script,
    Sequence, Tx, TxIn, TxOut, Txid, Witness, consensus_bytes,
};

use crate::handlers::util::{
    GENERATEBLOCK_INVALID_OUTPUT, GENERATEBLOCK_MULTIPATH, GENERATEBLOCK_NEEDS_PRIVATE_KEYS,
    GENERATEBLOCK_RANGED, descriptor_checksum,
};

fn sample_candidate() -> Candidate {
    let previous = Hash256::from_le_bytes(&[0x11; 32]);
    Candidate {
        template_id: TemplateId::new(&previous, 9),
        previous_block_hash: previous,
        height: 101,
        version: 0x2000_0000,
        bits: CompactTarget::from_consensus(0x207f_ffff),
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
            lock_time: LockTime::ZERO,
        },
        coinbase_value: 5_000_000_000,
        weight: 1_000,
        transactions: Vec::new(),
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
        bits: CompactTarget::from_consensus(0x207f_ffff),
        difficulty: 1.0,
        network_hashes_per_second: 42.5,
        pooled_transactions: 4,
        network: Network::Regtest,
        next_bits: CompactTarget::from_consensus(0x207f_ffff),
        next_difficulty: 1.0,
        minimum_fee_rate: 1_000,
        signet: None,
        warnings: Vec::new(),
    }
}

fn ctx_with_control(control: Arc<dyn MiningControl>) -> Arc<Context> {
    let mut ctx = Context::new();
    ctx.chain.chain_network = Network::Regtest;
    Arc::new(ctx.with_mining_control(control))
}

fn ctx_with_control_on_network(control: Arc<dyn MiningControl>, network: Network) -> Arc<Context> {
    let mut ctx = Context::new().with_mining_control(control);
    ctx.chain.chain_network = network;
    Arc::new(ctx)
}

fn sample_block() -> Block {
    let coinbase = Tx {
        version: 1,
        inputs: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: Script::from_bytes(vec![0x51]),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(50 * 100_000_000),
            script_pubkey: Script::new(),
        }],
        lock_time: LockTime::ZERO,
    };
    let merkle_root = coinbase.txid().0;
    Block {
        header: Header {
            version: 1,
            prev_blockhash: BlockHash::default(),
            merkle_root,
            time: 1_296_688_602,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 2,
        },
        txs: vec![coinbase],
    }
}

fn register_dummy_peer(ctx: &Context) {
    let (tx, _rx) = crossbeam_channel::bounded::<bitcoin_rs_p2p::QueuedFrame>(1);
    ctx.network.peer_table.register(
        "127.0.0.1:8333"
            .parse::<bitcoin_rs_p2p::PeerRemote>()
            .unwrap_or_else(|error| panic!("dummy peer addr: {error}")),
        bitcoin_rs_p2p::PeerLease::new(tx),
    );
}

#[test]
fn getblocktemplate_rejects_mainnet_without_peers() {
    let control = FakeMiningControl::with_template(sample_template(), sample_mining_info());
    let ctx = Arc::new(Context::new().with_mining_control(control));
    assert_eq!(ctx.chain.chain_network, Network::Mainnet);
    let error = getblocktemplate(&ctx, &json!([{"rules":["segwit"]}]))
        .expect_err("mainnet without peers must fail");
    assert!(matches!(error, RpcError::ClientNotConnected(_)));
    assert_eq!(error.code(), RpcError::CORE_CLIENT_NOT_CONNECTED);
    assert_eq!(error.to_string(), "bitcoin-rs is not connected!");
}

#[test]
fn getblocktemplate_rejects_mainnet_during_ibd() {
    let control = FakeMiningControl::with_template(sample_template(), sample_mining_info());
    let ctx = Context::new().with_mining_control(control);
    register_dummy_peer(&ctx);
    let ctx = Arc::new(ctx);
    let error =
        getblocktemplate(&ctx, &json!([{"rules":["segwit"]}])).expect_err("mainnet IBD must fail");
    assert!(matches!(error, RpcError::ClientInInitialDownload(_)));
    assert_eq!(error.code(), RpcError::CORE_CLIENT_IN_INITIAL_DOWNLOAD);
    assert_eq!(
        error.to_string(),
        "bitcoin-rs is in initial sync and waiting for blocks..."
    );
}

#[test]
fn getblocktemplate_proposal_skips_mainnet_connection_gates() {
    let control = FakeMiningControl::with_template(sample_template(), sample_mining_info());
    *control.proposal.lock() = BlockValidationResult::Accepted;
    let mut ctx = Context::new();
    ctx.mining.mining_control = Some(control);
    let ctx = Arc::new(ctx);
    let genesis = sample_block();
    let hex = consensus_bytes(&genesis).to_lower_hex_string();
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
    let control = FakeMiningControl::with_template(sample_template(), sample_mining_info());
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
    assert_eq!(
        first
            .get("coinbaseaux")
            .and_then(|aux| aux.get("flags"))
            .and_then(JsonValueTrait::as_str),
        Some("")
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
    let control = FakeMiningControl::with_template(sample_template(), sample_mining_info());
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
}

#[test]
fn getblocktemplate_requires_signet_rule_on_signet() {
    let mut template = sample_template();
    template.rules.push(MiningRule::new("signet"));
    let control = FakeMiningControl::with_template(template, sample_mining_info());
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
}

#[test]
fn getblocktemplate_rejects_template_mandatory_rule_without_client_support() {
    let mut template = sample_template();
    template.rules.push(MiningRule::new("signet"));
    let control = FakeMiningControl::with_template(template, sample_mining_info());
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
fn getblocktemplate_rejects_missing_segwit_rule() {
    let control = FakeMiningControl::with_template(sample_template(), sample_mining_info());
    let ctx = ctx_with_control(control.clone());
    for params in [
        json!([]),
        json!([{}]),
        json!([{"rules":[]}]),
        json!([{"rules":["csv"]}]),
    ] {
        let error = getblocktemplate(&ctx, &params).expect_err("missing segwit support must fail");
        assert!(matches!(error, RpcError::InvalidParameter(_)));
        assert_eq!(error.code(), RpcError::CORE_INVALID_PARAMETER);
        assert_eq!(error.to_string(), GBT_REQUIRE_SEGWIT);
    }
    assert_eq!(control.template_calls.load(Ordering::Relaxed), 0);
}

#[test]
fn getblocktemplate_proposal_skips_client_rule_negotiation() {
    let control = FakeMiningControl::with_template(sample_template(), sample_mining_info());
    *control.proposal.lock() = BlockValidationResult::Accepted;
    let ctx = ctx_with_control_on_network(control.clone(), Network::Signet);
    let genesis = sample_block();
    let hex = consensus_bytes(&genesis).to_lower_hex_string();
    let result = getblocktemplate(
        &ctx,
        &json!([{
            "mode": "proposal",
            "data": hex,
        }]),
    )
    .unwrap_or_else(|err| panic!("proposal without rules failed: {err}"));
    assert!(result.is_null());
    assert!(matches!(
        control
            .last_request
            .lock()
            .as_ref()
            .map(|request| &request.mode),
        Some(BlockTemplateMode::Proposal(_))
    ));
    assert_eq!(control.template_calls.load(Ordering::Relaxed), 1);
}

#[test]
fn getblocktemplate_rejects_invalid_mode() {
    let control = FakeMiningControl::with_template(sample_template(), sample_mining_info());
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
    let control = FakeMiningControl::with_template(sample_template(), sample_mining_info());
    *control.proposal.lock() = BlockValidationResult::Accepted;
    let ctx = ctx_with_control(control.clone());
    let missing = getblocktemplate(&ctx, &json!([{"mode": "proposal"}]))
        .expect_err("proposal without data must fail");
    assert!(matches!(missing, RpcError::InvalidType(_)));
    assert_eq!(missing.code(), RpcError::CORE_INVALID_TYPE);
    assert_eq!(missing.to_string(), "Missing data String key for proposal");
    for hex in ["", "00", "zz", "deadbeef"] {
        let error = getblocktemplate(&ctx, &json!([{"mode": "proposal", "data": hex}]))
            .expect_err("undecodable proposal must fail");
        assert!(matches!(error, RpcError::Deserialization(_)));
        assert_eq!(error.code(), RpcError::CORE_DESERIALIZATION_ERROR);
        assert_eq!(error.to_string(), "Block decode failed");
    }
    let genesis = sample_block();
    let mut hex = consensus_bytes(&genesis).to_lower_hex_string();
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
    let control = FakeMiningControl::with_template(sample_template(), sample_mining_info());
    let ctx = ctx_with_control(control);
    let rules_error =
        getblocktemplate(&ctx, &json!([{"rules":"segwit"}])).expect_err("rules must be an array");
    assert!(matches!(rules_error, RpcError::InvalidType(_)));
    let capabilities_error = getblocktemplate(&ctx, &json!([{"capabilities":[1]}]))
        .expect_err("capabilities entries must be strings");
    assert!(matches!(capabilities_error, RpcError::InvalidType(_)));
}

#[test]
fn submitblock_maps_accepted_rejected_and_duplicate_results() {
    let control = FakeMiningControl::with_template(sample_template(), sample_mining_info());
    let ctx = ctx_with_control(control.clone());
    let genesis = sample_block();
    let hex = consensus_bytes(&genesis).to_lower_hex_string();

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
fn mining_methods_without_a_control_answer_method_not_found() {
    type Method = fn(&Arc<Context>, &Value) -> Result<Value, RpcError>;
    let ctx = Arc::new(Context::new());
    let cases: [(&str, Method, Value); 3] = [
        (
            "getblocktemplate",
            getblocktemplate,
            json!([{"rules":["segwit"]}]),
        ),
        ("getmininginfo", getmininginfo, json!([])),
        ("getnetworkhashps", getnetworkhashps, json!([])),
    ];

    for (name, method, params) in cases {
        let error = method(&ctx, &params)
            .err()
            .unwrap_or_else(|| panic!("{name}: missing control must fail"));
        assert!(
            matches!(&error, RpcError::MethodNotFound(method) if method == name),
            "{name}: {error}"
        );
        assert_eq!(error.code(), RpcError::METHOD_NOT_FOUND, "{name}");
    }
}

#[test]
fn submitblock_requires_mining_control_and_rejects_garbage_encoding() {
    let missing = Arc::new(Context::new());
    let error =
        submitblock(&missing, &json!(["00"])).expect_err("submitblock without control must fail");
    assert!(matches!(&error, RpcError::MethodNotFound(name) if name == "submitblock"));
    assert_eq!(error.code(), RpcError::METHOD_NOT_FOUND);

    let control = FakeMiningControl::with_template(sample_template(), sample_mining_info());
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
    let control = FakeMiningControl::with_template(sample_template(), sample_mining_info());
    let ctx = ctx_with_control(control.clone());
    let genesis = sample_block();
    let mut hex = consensus_bytes(&genesis).to_lower_hex_string();
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
fn submitblock_rejects_non_string_bip22_dummy() {
    let control = FakeMiningControl::with_template(sample_template(), sample_mining_info());
    let ctx = ctx_with_control(control.clone());
    let genesis = sample_block();
    let hex = consensus_bytes(&genesis).to_lower_hex_string();
    for dummy in [json!(123), json!(true), json!([]), json!({})] {
        let error = submitblock(&ctx, &json!([hex.as_str(), dummy]))
            .expect_err("non-string BIP22 dummy must fail");
        assert!(matches!(error, RpcError::InvalidType(_)));
        assert_eq!(error.code(), RpcError::CORE_INVALID_TYPE);
    }
    assert_eq!(control.submit_calls.load(Ordering::Relaxed), 0);

    *control.submit.lock() = BlockValidationResult::Accepted;
    let nulled = submitblock(&ctx, &json!([hex.as_str(), null]))
        .unwrap_or_else(|err| panic!("null dummy must be accepted and ignored: {err}"));
    assert!(nulled.is_null());
    let stringed = submitblock(&ctx, &json!([hex.as_str(), "ignored"]))
        .unwrap_or_else(|err| panic!("string dummy must be accepted and ignored: {err}"));
    assert!(stringed.is_null());
    assert_eq!(control.submit_calls.load(Ordering::Relaxed), 2);
}

#[test]
fn decode_tx_zero_input_zero_flag_accepted_like_core() {
    let control = FakeMiningControl::with_template(sample_template(), sample_mining_info());
    let ctx = ctx_with_control(control.clone());
    let empty = Tx {
        version: 1,
        inputs: Vec::new(),
        outputs: Vec::new(),
        lock_time: LockTime::ZERO,
    };
    let block = Block {
        header: sample_block().header,
        txs: vec![empty],
    };
    let hex = consensus_bytes(&block).to_lower_hex_string();
    let result = submitblock(&ctx, &json!([hex.as_str()]))
        .unwrap_or_else(|err| panic!("zero-input zero-flag block must decode: {err}"));
    assert!(result.is_null());
    assert_eq!(control.submit_calls.load(Ordering::Relaxed), 1);
}

#[test]
fn getmininginfo_projects_control_state() {
    let control = FakeMiningControl::with_template(sample_template(), sample_mining_info());
    let ctx = ctx_with_control(control.clone());
    let result =
        getmininginfo(&ctx, &json!([])).unwrap_or_else(|err| panic!("getmininginfo failed: {err}"));
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
fn getmininginfo_omits_unset_optional_fields() {
    let control = FakeMiningControl::with_template(sample_template(), sample_mining_info());
    {
        let mut info = control.info.lock();
        info.last_candidate = None;
    }
    let ctx = ctx_with_control(control);
    let result =
        getmininginfo(&ctx, &json!([])).unwrap_or_else(|err| panic!("getmininginfo failed: {err}"));
    assert!(result.get("currentblockweight").is_none());
    assert!(result.get("currentblocktx").is_none());
    assert!(result.get("signet_challenge").is_none());
}

#[test]
fn getmininginfo_top_level_target_is_the_tip_not_the_next_block() {
    let control = FakeMiningControl::with_template(sample_template(), sample_mining_info());
    {
        let mut info = control.info.lock();
        info.bits = CompactTarget::from_consensus(0x1d00_ffff);
        info.difficulty = 1.0;
        info.next_bits = CompactTarget::from_consensus(0x1c00_ffff);
    }
    let ctx = ctx_with_control(control);
    let result =
        getmininginfo(&ctx, &json!([])).unwrap_or_else(|err| panic!("getmininginfo failed: {err}"));
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
    assert_eq!(
        target,
        compact_target_hex(CompactTarget::from_consensus(0x1d00_ffff))
    );
    assert_eq!(
        next.get("bits").and_then(JsonValueTrait::as_str),
        Some("1c00ffff")
    );
    assert_eq!(
        next_target,
        compact_target_hex(CompactTarget::from_consensus(0x1c00_ffff))
    );
    assert_ne!(target, next_target);
}

#[test]
fn prioritisetransaction_calls_mempool_prioritise_directly() {
    use bitcoin_rs_mempool::MempoolEntry;

    let ctx = Arc::new(Context::new());
    let tx = Tx {
        version: 2,
        inputs: Vec::new(),
        outputs: Vec::new(),
        lock_time: LockTime::ZERO,
    };
    let txid = tx.txid();
    {
        let mut pool = ctx.mempool.gateway.pool().write();
        pool.insert_entry(MempoolEntry::new(Arc::new(tx), 100, 1_000, 1, 7, 0))
            .unwrap_or_else(|err| panic!("insert failed: {err}"));
    }
    let txid_hex = txid.to_string();
    let result = prioritisetransaction(&ctx, &json!([txid_hex.as_str(), 0, 500]))
        .unwrap_or_else(|err| panic!("prioritisetransaction failed: {err}"));
    assert_eq!(result.as_bool(), Some(true));
    let error = prioritisetransaction(&ctx, &json!([txid_hex.as_str(), 0, 500, "unexpected"]))
        .expect_err("extra parameters must fail");
    assert!(matches!(
        error,
        RpcError::InvalidParams("too many parameters")
    ));
    prioritisetransaction(&ctx, &json!({"txid": txid_hex, "fee_delta": 600}))
        .unwrap_or_else(|err| panic!("named fee_delta must be accepted: {err}"));
    prioritisetransaction(&ctx, &json!([txid_hex.as_str(), 0.0, 0]))
        .unwrap_or_else(|err| panic!("zero dummy float must be accepted: {err}"));
    prioritisetransaction(&ctx, &json!([txid_hex.as_str(), null, 0]))
        .unwrap_or_else(|err| panic!("null dummy must be accepted: {err}"));
    let pool = ctx.mempool.gateway.read();
    let entry = pool
        .entry_by_txid(&txid)
        .expect("entry remains after prioritise");
    assert_eq!(entry.fee_delta, 1_100);
    assert_eq!(entry.fee, 1_000);
}

#[test]
fn prioritisetransaction_rejects_nonzero_dummy_like_core() {
    let ctx = Arc::new(Context::new());
    let txid = "11".repeat(32);
    let nonzero_dummy = prioritisetransaction(&ctx, &json!([txid.as_str(), 1, 500]))
        .expect_err("nonzero dummy must fail");
    assert!(matches!(nonzero_dummy, RpcError::InvalidParameter(_)));
    assert_eq!(nonzero_dummy.code(), RpcError::CORE_INVALID_PARAMETER);
    assert_eq!(nonzero_dummy.to_string(), PRIORITISE_DUMMY_ERROR);
}

#[test]
fn prioritisetransaction_requires_fee_delta_as_third_parameter() {
    let ctx = Arc::new(Context::new());
    let txid = "11".repeat(32);
    let two_args = prioritisetransaction(&ctx, &json!([txid.as_str(), 500]))
        .expect_err("two-arg form must not treat dummy as fee_delta");
    assert!(matches!(two_args, RpcError::InvalidType(_)));
    assert_eq!(two_args.code(), RpcError::CORE_INVALID_TYPE);
}

fn dust_priority_tx() -> Tx {
    Tx {
        version: 2,
        inputs: Vec::new(),
        outputs: vec![TxOut {
            value: Amount::from_sat(1),
            script_pubkey: Script::from_bytes(vec![0x51]),
        }],
        lock_time: LockTime::ZERO,
    }
}

#[test]
fn prioritisetransaction_rejects_dust_outputs_like_core() {
    use bitcoin_rs_mempool::MempoolEntry;

    let ctx = Arc::new(Context::new());
    assert_eq!(ctx.chain.chain_network, Network::Mainnet);
    let tx = dust_priority_tx();
    let txid = tx.txid();
    {
        let mut pool = ctx.mempool.gateway.pool().write();
        pool.insert_entry(MempoolEntry::new(Arc::new(tx), 100, 1_000, 1, 7, 0))
            .unwrap_or_else(|err| panic!("insert failed: {err}"));
    }
    let txid_hex = txid.to_string();
    let error = prioritisetransaction(&ctx, &json!([txid_hex.as_str(), 0, 500]))
        .expect_err("dust mempool tx must not be prioritised");
    assert!(matches!(error, RpcError::InvalidParameter(_)));
    assert_eq!(error.code(), RpcError::CORE_INVALID_PARAMETER);
    assert_eq!(error.to_string(), PRIORITISE_DUST_ERROR);
}

#[test]
fn prioritisetransaction_allows_dust_overlay_on_regtest() {
    use bitcoin_rs_mempool::MempoolEntry;

    let mut ctx = Context::new();
    ctx.chain.chain_network = Network::Regtest;
    let ctx = Arc::new(ctx);
    let tx = dust_priority_tx();
    let txid = tx.txid();
    {
        let mut pool = ctx.mempool.gateway.pool().write();
        pool.insert_entry(MempoolEntry::new(Arc::new(tx), 100, 1_000, 1, 7, 0))
            .unwrap_or_else(|err| panic!("insert failed: {err}"));
    }
    let txid_hex = txid.to_string();
    let result = prioritisetransaction(&ctx, &json!([txid_hex.as_str(), 0, 500]))
        .unwrap_or_else(|err| panic!("regtest may prioritise dust: {err}"));
    assert_eq!(result.as_bool(), Some(true));
}

#[test]
fn prioritisetransaction_allows_absent_txid_overlay() {
    let ctx = Arc::new(Context::new());
    let txid = "11".repeat(32);
    let result = prioritisetransaction(&ctx, &json!([txid.as_str(), 0, 500]))
        .unwrap_or_else(|err| panic!("absent txid overlay must be accepted: {err}"));
    assert_eq!(result.as_bool(), Some(true));
}

#[test]
fn getblocktemplate_includes_selected_transactions() {
    let mut template = sample_template();
    let tx = Tx {
        version: 2,
        inputs: vec![TxIn {
            previous_output: OutPoint::new(Txid::default(), 0),
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::from_stack(vec![vec![0x01, 0x02, 0x03], vec![0x04]]),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: Script::from_bytes(vec![0x51]),
        }],
        lock_time: LockTime::ZERO,
    };
    let txid = tx.txid();
    let wtxid = tx.wtxid();
    let data_hex = consensus_bytes(&tx).to_lower_hex_string();
    let mut candidate = sample_candidate();
    candidate.transactions.push(CandidateTransaction {
        tx: Arc::new(tx.clone()),
        txid,
        wtxid,
        fee: 100,
        sigop_cost: 2,
        weight: 400,
        depends: vec![],
        data_hex: data_hex.clone(),
    });
    template.candidate = Arc::new(candidate);
    let control = FakeMiningControl::with_template(template, sample_mining_info());
    let ctx = ctx_with_control(control);
    let result = getblocktemplate(&ctx, &json!([{"rules":["segwit"]}]))
        .unwrap_or_else(|err| panic!("template with txs failed: {err}"));
    let transactions = result
        .get("transactions")
        .and_then(JsonContainerTrait::as_array)
        .expect("transactions array");
    assert_eq!(transactions.len(), 1);
    let txid_hex = txid.to_string();
    assert_eq!(
        transactions[0].get("txid").and_then(JsonValueTrait::as_str),
        Some(txid_hex.as_str())
    );
    let rendered = transactions[0]
        .get("data")
        .and_then(JsonValueTrait::as_str)
        .expect("template data hex");
    assert_eq!(rendered, data_hex.as_str());
    let raw = Vec::<u8>::from_hex(rendered)
        .unwrap_or_else(|err| panic!("template data must be hex: {err}"));
    let decoded: Tx =
        deserialize(&raw).unwrap_or_else(|err| panic!("template data must decode: {err}"));
    assert_eq!(decoded, tx);
    assert!(!decoded.inputs[0].witness.is_empty());
    assert_eq!(decoded.wtxid(), wtxid);
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
    let control = FakeMiningControl::with_template(template, sample_mining_info());
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
    let control = FakeMiningControl::with_template(sample_template(), sample_mining_info());
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
    let control = FakeMiningControl::with_template(sample_template(), sample_mining_info());
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
fn getnetworkhashps_forwards_defaults_and_caller_window() {
    let control = FakeMiningControl::with_template(sample_template(), sample_mining_info());
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
    let control = FakeMiningControl::with_template(sample_template(), sample_mining_info());
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

    let height = getnetworkhashps(&ctx, &json!([120, -10])).expect_err("height below -1 must fail");
    assert!(matches!(
        height,
        RpcError::InvalidParameter(message)
            if message == "Block does not exist at specified height"
    ));
    assert!(control.last_hash_ps.lock().is_none());
}

#[test]
fn getnetworkhashps_projects_control_invalid_request_as_invalid_parameter() {
    let control = FakeMiningControl::with_template(sample_template(), sample_mining_info());
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
        lock_time: LockTime::ZERO,
    };
    let pooled = pooled_tx.txid();
    {
        let mut pool = ctx.mempool.gateway.pool().write();
        pool.insert_entry(MempoolEntry::new(Arc::new(pooled_tx), 100, 1_000, 1, 7, 0))
            .unwrap_or_else(|err| panic!("insert failed: {err}"));
    }
    let absent = Txid::from(Hash256::from_le_bytes(&[0x22; 32]));
    ctx.mempool
        .gateway
        .prioritise(pooled, 500)
        .unwrap_or_else(|err| panic!("pooled overlay: {err}"));
    ctx.mempool
        .gateway
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
    assert_eq!(
        pooled_row
            .get("modified_fee")
            .and_then(JsonValueTrait::as_i64),
        Some(1_500),
        "modified_fee is actual fee plus delta in satoshis"
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
            script_sig: Script::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        outputs: vec![TxOut {
            value: Amount::from_sat(50_000),
            script_pubkey: Script::from_bytes(vec![0x51]),
        }],
        lock_time: LockTime::ZERO,
    }
}

#[test]
fn generatetoaddress_projects_solved_hashes() {
    let control = FakeMiningControl::with_template(sample_template(), sample_mining_info());
    let ctx = ctx_with_control(control);
    let result = generatetoaddress(&ctx, &json!([2, REGTEST_ADDRESS]))
        .unwrap_or_else(|err| panic!("generatetoaddress failed: {err}"));
    let hashes = result
        .as_array()
        .unwrap_or_else(|| panic!("generatetoaddress returns a hash array"));
    assert_eq!(hashes.len(), 2);
    assert!(hashes.iter().all(|hash| hash.as_str().is_some()));
}

#[test]
fn generatetoaddress_rejects_script_hex_and_descriptors() {
    let control = FakeMiningControl::with_template(sample_template(), sample_mining_info());
    let ctx = ctx_with_control(control);
    for payout in ["51", &format!("addr({REGTEST_ADDRESS})")] {
        let error = generatetoaddress(&ctx, &json!([1, payout]))
            .err()
            .unwrap_or_else(|| panic!("`{payout}` must not be an address"));
        assert_eq!(error.code(), RpcError::CORE_NOT_FOUND, "for `{payout}`");
        assert_eq!(
            error.to_string(),
            GENERATE_INVALID_ADDRESS,
            "for `{payout}`"
        );
    }
}

#[test]
fn generateblock_projects_hash_object() {
    let control = FakeMiningControl::with_template(sample_template(), sample_mining_info());
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

#[test]
fn generateblock_accepts_addr_descriptor() {
    let control = FakeMiningControl::with_template(sample_template(), sample_mining_info());
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
            GENERATE_INVALID_ADDRESS,
        )
        .unwrap_or_else(|err| panic!("fixture address must decode: {err}"))
    );
}

#[test]
fn generateblock_without_submit_includes_hex() {
    let control = FakeMiningControl::with_template(sample_template(), sample_mining_info());
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

#[test]
fn generateblock_requires_transactions_array() {
    let control = FakeMiningControl::with_template(sample_template(), sample_mining_info());
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
    assert_eq!(hex.to_string(), GENERATEBLOCK_INVALID_OUTPUT);
}

#[test]
fn generateblock_keeps_raw_transactions() {
    use bitcoin_rs_mempool::MempoolEntry;

    let control = FakeMiningControl::with_template(sample_template(), sample_mining_info());
    let ctx = ctx_with_control(control.clone());
    let pooled = sample_raw_tx();
    let txid = pooled.txid();
    {
        let mut pool = ctx.mempool.gateway.pool().write();
        pool.insert_entry(MempoolEntry::new(Arc::new(pooled), 100, 1_000, 1, 7, 0))
            .unwrap_or_else(|err| panic!("insert failed: {err}"));
    }
    let mut raw = sample_raw_tx();
    raw.lock_time = LockTime::from_consensus(1);
    let raw_hex = consensus_bytes(&raw).to_lower_hex_string();
    generateblock(&ctx, &json!([REGTEST_ADDRESS, [txid.to_string(), raw_hex]]))
        .unwrap_or_else(|err| panic!("generateblock failed: {err}"));
    let request = control
        .last_generate
        .lock()
        .clone()
        .unwrap_or_else(|| panic!("generateblock must call generate"));
    let pooled_entry = ctx
        .mempool
        .gateway
        .read()
        .mining_snapshot()
        .entries
        .into_iter()
        .find(|entry| entry.txid == txid)
        .unwrap_or_else(|| panic!("pooled txid must resolve from mining snapshot"));
    assert_eq!(
        request.selection,
        GenerateSelection::Ordered(vec![
            GenerateTx::ResolvedMempool(pooled_entry),
            GenerateTx::Raw(raw)
        ])
    );
}

#[test]
fn generateblock_rejects_unknown_mempool_txid_like_core() {
    let control = FakeMiningControl::with_template(sample_template(), sample_mining_info());
    let ctx = ctx_with_control(control);
    let missing = "CD".repeat(32);
    let error = generateblock(&ctx, &json!([REGTEST_ADDRESS, [missing.as_str()]]))
        .err()
        .unwrap_or_else(|| panic!("unknown mempool txid must fail at parse"));
    assert_eq!(error.code(), RpcError::CORE_NOT_FOUND);
    assert_eq!(
        error.to_string(),
        format!("Transaction {missing} not in mempool.")
    );
}

#[test]
fn generateblock_rejects_undecodable_raw_tx_like_core() {
    let control = FakeMiningControl::with_template(sample_template(), sample_mining_info());
    let ctx = ctx_with_control(control);
    for payload in ["00", "zz", "abcd"] {
        let error = generateblock(&ctx, &json!([REGTEST_ADDRESS, [payload]]))
            .err()
            .unwrap_or_else(|| panic!("`{payload}` must fail decode"));
        assert_eq!(
            error.code(),
            RpcError::CORE_DESERIALIZATION_ERROR,
            "for `{payload}`"
        );
        assert_eq!(
            error.to_string(),
            format!(
                "Transaction decode failed for {payload}. Make sure the tx has at least one input."
            ),
            "for `{payload}`"
        );
    }
}

#[test]
fn generateblock_rejects_trailing_parameters() {
    let control = FakeMiningControl::with_template(sample_template(), sample_mining_info());
    let ctx = ctx_with_control(control);
    let extra = generateblock(&ctx, &json!([REGTEST_ADDRESS, [], true, "unexpected"]))
        .err()
        .unwrap_or_else(|| panic!("trailing generateblock arguments must fail"));
    assert!(matches!(
        extra,
        RpcError::InvalidParams("too many parameters")
    ));
}

#[test]
fn generateblock_rejects_invalid_supplied_checksums() {
    let control = FakeMiningControl::with_template(sample_template(), sample_mining_info());
    let ctx = ctx_with_control(control);
    let descriptor = format!("addr({REGTEST_ADDRESS})");
    let checksum = descriptor_checksum(&descriptor)
        .unwrap_or_else(|| panic!("fixture descriptor must have a checksum"));
    generateblock(&ctx, &json!([format!("{descriptor}#{checksum}"), []]))
        .unwrap_or_else(|err| panic!("a matching checksum must be accepted: {err}"));
    for input in [
        format!("{descriptor}#qqqqqqqq"),
        format!("{descriptor}#short"),
        format!("{descriptor}#aaaaaaaa#bbbbbbbb"),
    ] {
        let error = generateblock(&ctx, &json!([input.clone(), []]))
            .err()
            .unwrap_or_else(|| panic!("`{input}` must be refused"));
        assert_eq!(error.code(), RpcError::CORE_NOT_FOUND, "for `{input}`");
        assert_eq!(
            error.to_string(),
            GENERATEBLOCK_INVALID_OUTPUT,
            "for `{input}`"
        );
    }
}

#[test]
fn generateblock_maps_test_block_validity_to_verify_error() {
    let control = FakeMiningControl::with_template(sample_template(), sample_mining_info());
    *control.fail.lock() = Some(MiningControlError::Rejected(CompactString::from(
        "TestBlockValidity failed: bad-txns-inputs-missingorspent",
    )));
    let ctx = ctx_with_control(control);
    let error = generateblock(&ctx, &json!([REGTEST_ADDRESS, []]))
        .expect_err("TestBlockValidity must be Core -25");
    assert_eq!(error.code(), RpcError::CORE_VERIFY_ERROR);
    assert_eq!(
        error.to_string(),
        "TestBlockValidity failed: bad-txns-inputs-missingorspent"
    );
}

#[test]
fn generateblock_rejects_garbage_output_like_core() {
    let control = FakeMiningControl::with_template(sample_template(), sample_mining_info());
    let ctx = ctx_with_control(control);
    let error = generateblock(&ctx, &json!(["not-an-address", []]))
        .err()
        .unwrap_or_else(|| panic!("garbage output must fail"));
    assert_eq!(error.code(), RpcError::CORE_NOT_FOUND);
    assert_eq!(error.to_string(), GENERATEBLOCK_INVALID_OUTPUT);
}

#[test]
fn generateblock_rejects_multipath_before_ranged_like_core() {
    let control = FakeMiningControl::with_template(sample_template(), sample_mining_info());
    let ctx = ctx_with_control(control.clone());
    let tpub = "tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B";
    let wrong_network = generateblock(
        &ctx_with_control_on_network(control, Network::Mainnet),
        &json!([format!("wpkh({tpub}/<0;1>/0)"), []]),
    )
    .err()
    .unwrap_or_else(|| panic!("wrong-network descriptor must fail"));
    assert_eq!(wrong_network.code(), RpcError::CORE_NOT_FOUND);
    assert_eq!(wrong_network.to_string(), GENERATEBLOCK_INVALID_OUTPUT);
    let multipath = generateblock(&ctx, &json!([format!("wpkh({tpub}/<0;1>/0)"), []]))
        .err()
        .unwrap_or_else(|| panic!("multipath descriptor must fail"));
    assert_eq!(multipath.code(), RpcError::CORE_INVALID_PARAMETER);
    assert_eq!(multipath.to_string(), GENERATEBLOCK_MULTIPATH);
    let both = generateblock(&ctx, &json!([format!("wpkh({tpub}/<0;1>/*)"), []]))
        .err()
        .unwrap_or_else(|| panic!("multipath+ranged descriptor must fail as multipath"));
    assert_eq!(both.code(), RpcError::CORE_INVALID_PARAMETER);
    assert_eq!(both.to_string(), GENERATEBLOCK_MULTIPATH);
    let ranged = generateblock(&ctx, &json!([format!("wpkh({tpub}/0/*)"), []]))
        .err()
        .unwrap_or_else(|| panic!("ranged descriptor must fail"));
    assert_eq!(ranged.code(), RpcError::CORE_INVALID_PARAMETER);
    assert_eq!(ranged.to_string(), GENERATEBLOCK_RANGED);
}

#[test]
fn generateblock_rejects_hardened_xpub_like_core() {
    let control = FakeMiningControl::with_template(sample_template(), sample_mining_info());
    let ctx = ctx_with_control(control);
    let tpub = "tpubD6NzVbkrYhZ4WaWSyoBvQwbpLkojyoTZPRsgXELWz3Popb3qkjcJyJUGLnL4qHHoQvao8ESaAstxYSnhyswJ76uZPStJRJCTKvosUCJZL5B";
    let error = generateblock(&ctx, &json!([format!("wpkh({tpub}/0h/0)"), []]))
        .err()
        .unwrap_or_else(|| panic!("hardened xpub must fail Expand"));
    assert_eq!(error.code(), RpcError::CORE_NOT_FOUND);
    assert_eq!(error.to_string(), GENERATEBLOCK_NEEDS_PRIVATE_KEYS);
}

#[test]
fn submitheader_maps_armed_control_failure() {
    let control = FakeMiningControl::with_template(sample_template(), sample_mining_info());
    *control.fail.lock() = Some(MiningControlError::Rejected(CompactString::from(
        "bad-prevblk",
    )));
    let ctx = ctx_with_control(control);
    let header = consensus_bytes(&sample_block().header).to_lower_hex_string();
    let error = submitheader(&ctx, &json!([header.as_str()]))
        .expect_err("armed control failure must reject the header");
    assert_eq!(error.code(), RpcError::CORE_VERIFY_ERROR);
    assert_eq!(error.to_string(), "bad-prevblk");
}
