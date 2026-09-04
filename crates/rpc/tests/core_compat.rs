//! Bitcoin Core wire-contract compatibility tests.
//!
//! Every dispatched response covered by a `corepc_types` structured type must
//! deserialize into that exact upstream type under the crate's strict
//! `serde-deny-unknown-fields` feature. Hardcoded key-set equality is gone:
//! the versioned type is the schema.
//!
//! Schema-proof surface named by `docs/policies/source-compatibility.md`
//! §5.2 (RPC methods match current Bitcoin Core schemas; clean cutover, no
//! deprecation shims).

extern crate alloc;

use alloc::sync::Arc;

use bitcoin_rs_chain::{ChainWork, NodeId, TipSnapshot};
use bitcoin_rs_mining::{Candidate, TemplateId};
use bitcoin_rs_primitives::{Block, Hash256, Network, OutPoint, Tx, TxIn, Txid, client_version};
use bitcoin_rs_rpc::Handler;
use bitcoin_rs_rpc::context::{
    BlockTemplate, BlockTemplateRequest, BlockTemplateResult, BlockValidationResult, Context,
    MiningCapability, MiningControl, MiningControlError, MiningInfo, TemplateMutation,
};
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, json};

/// Re-parses one dispatched response against the pinned upstream wire type.
fn typed<T: serde::de::DeserializeOwned>(
    value: &sonic_rs::Value,
) -> Result<T, Box<dyn std::error::Error>> {
    let text = sonic_rs::to_string(value)?;
    Ok(serde_json::from_str(&text)?)
}

fn tipped_context() -> Arc<Context> {
    let ctx = Arc::new(Context::new());
    let tip = TipSnapshot {
        tip_id: NodeId::new(0),
        height: 42,
        chainwork: ChainWork::ZERO,
        hash: Hash256::from_le_bytes(&[42_u8; 32]),
    };
    ctx.set_chain_tip(tip.clone());
    ctx.set_applied_tip(tip);
    ctx
}

#[test]
fn chain_state_responses_deserialize_into_pinned_types() -> Result<(), Box<dyn std::error::Error>> {
    let handler = Handler::new(tipped_context());

    let info: corepc_types::v31::GetBlockchainInfo =
        typed(&handler.dispatch("getblockchaininfo", &json!([]))?)?;
    assert_eq!(info.chain, "main");
    assert_eq!(info.blocks, 42);
    assert_eq!(info.headers, 42);
    assert!(!info.best_block_hash.is_empty());
    assert!(!info.bits.is_empty());
    assert!(!info.target.is_empty());
    assert!(!info.chain_work.is_empty());
    assert!(info.warnings.is_empty());

    let difficulty: corepc_types::v31::GetDifficulty =
        typed(&handler.dispatch("getdifficulty", &json!([]))?)?;
    assert!((difficulty.0 - 0.0).abs() < f64::EPSILON);

    let count: corepc_types::v31::GetBlockCount =
        typed(&handler.dispatch("getblockcount", &json!([]))?)?;
    assert_eq!(count.0, 42);

    let best: corepc_types::v31::GetBestBlockHash =
        typed(&handler.dispatch("getbestblockhash", &json!([]))?)?;
    assert_eq!(best.0, info.best_block_hash);

    let tips: corepc_types::v31::GetChainTips =
        typed(&handler.dispatch("getchaintips", &json!([]))?)?;
    assert!(
        tips.0
            .iter()
            .any(|tip| tip.status == corepc_types::v31::ChainTipsStatus::Active)
    );

    let stats: corepc_types::v31::GetChainTxStats =
        typed(&handler.dispatch("getchaintxstats", &json!([]))?)?;
    assert_eq!(stats.window_final_block_height, 42);

    let verify: corepc_types::v31::VerifyChain =
        typed(&handler.dispatch("verifychain", &json!([0, 6]))?)?;
    assert!(verify.0);

    let at_tip: corepc_types::v31::GetBlockHash =
        typed(&handler.dispatch("getblockhash", &json!([42]))?)?;
    assert_eq!(at_tip.0, best.0);
    // Pruning needs block-log rows this fixture does not provide.
    assert!(handler.dispatch("pruneblockchain", &json!([1])).is_err());

    Ok(())
}

#[test]
fn mempool_responses_deserialize_into_pinned_types() -> Result<(), Box<dyn std::error::Error>> {
    let handler = Handler::new(Arc::new(Context::new()));

    let info: corepc_types::v31::GetMempoolInfo =
        typed(&handler.dispatch("getmempoolinfo", &json!([]))?)?;
    assert!(info.loaded);
    assert_eq!(info.size, 0);
    // Policy fields project the enforced MempoolPolicySnapshot defaults:
    // bare multisig permitted, the 83-byte nulldata budget, and the enforced
    // ancestor-package bounds under the recorded cluster deviation.
    assert!(info.permit_bare_multisig);
    assert!(info.optimal);
    assert_eq!(info.max_data_carrier_size, 83);
    assert_eq!(info.limit_cluster_count, 25);
    assert_eq!(info.limit_cluster_size, 101_000);
    assert_eq!(info.max_mempool, 300_000_000);
    // fullrbf reports the real replacement policy: BIP125 rule 1 signaling
    // is enforced, so the pool is not full-rbf (the handler used to emit an
    // unconditional `true`). Core 31.1 only emits the field under
    // -deprecatedrpc=fullrbf; the always-present `false` is the recorded
    // manifest deviation.
    assert!(!info.full_rbf);

    let raw: corepc_types::v31::GetRawMempool =
        typed(&handler.dispatch("getrawmempool", &json!([]))?)?;
    assert!(raw.0.is_empty());

    let sequenced: corepc_types::v31::GetRawMempoolSequence =
        typed(&handler.dispatch("getrawmempool", &json!([false, true]))?)?;
    assert!(sequenced.txids.is_empty());
    assert_eq!(sequenced.mempool_sequence, 0);

    let verbose: corepc_types::v31::GetRawMempoolVerbose =
        typed(&handler.dispatch("getrawmempool", &json!([true]))?)?;
    assert!(verbose.0.is_empty());

    let indexes: corepc_types::v31::GetIndexInfo =
        typed(&handler.dispatch("getindexinfo", &json!([]))?)?;
    assert!(indexes.0.is_empty());

    Ok(())
}

#[test]
fn network_responses_deserialize_into_pinned_types() -> Result<(), Box<dyn std::error::Error>> {
    let handler = Handler::new(Arc::new(Context::new()));

    let network: corepc_types::v31::GetNetworkInfo =
        typed(&handler.dispatch("getnetworkinfo", &json!([]))?)?;
    assert_eq!(
        network.version,
        usize::try_from(client_version()).unwrap_or(usize::MAX)
    );
    assert_eq!(network.protocol_version, 70016);
    assert_eq!(network.connections, 0);
    assert_eq!(network.networks.len(), 3);
    assert!(network.warnings.is_empty());

    let peers: corepc_types::v31::GetPeerInfo =
        typed(&handler.dispatch("getpeerinfo", &json!([]))?)?;
    assert!(peers.0.is_empty());

    let totals: corepc_types::v31::GetNetTotals =
        typed(&handler.dispatch("getnettotals", &json!([]))?)?;
    assert_eq!(totals.total_bytes_received, 0);
    assert!(totals.upload_target.target_reached);

    let connections: corepc_types::v31::GetConnectionCount =
        typed(&handler.dispatch("getconnectioncount", &json!([]))?)?;
    assert_eq!(connections.0, 0);

    let added: corepc_types::v31::GetAddedNodeInfo =
        typed(&handler.dispatch("getaddednodeinfo", &json!([]))?)?;
    assert!(added.0.is_empty());

    let banned: corepc_types::v31::ListBanned =
        typed(&handler.dispatch("listbanned", &json!([]))?)?;
    assert!(banned.0.is_empty());

    let addresses: corepc_types::v31::GetNodeAddresses =
        typed(&handler.dispatch("getnodeaddresses", &json!([0]))?)?;
    assert!(addresses.0.is_empty());

    Ok(())
}

/// Both validateaddress failure classes answer exactly Core's sparse
/// `{"isvalid": false}` object: `isvalid` is the only key and every
/// valid-only field (`address`, `scriptPubKey`, `isscript`, `iswitness`,
/// `witness_version`, `witness_program`) is absent. The pinned corepc type
/// models those fields as required, so this branch cannot round-trip
/// through `typed()` and is pinned by key-set assertions (`local_shape`).
fn assert_sparse_invalid(value: &sonic_rs::Value) {
    let object = value
        .as_object()
        .unwrap_or_else(|| panic!("validateaddress: not an object: {value:?}"));
    assert_eq!(object.len(), 1, "expected exactly one key: {value:?}");
    assert_eq!(
        value
            .get("isvalid")
            .and_then(sonic_rs::JsonValueTrait::as_bool),
        Some(false),
        "isvalid must be false: {value:?}"
    );
    for field in [
        "address",
        "scriptPubKey",
        "isscript",
        "iswitness",
        "witness_version",
        "witness_program",
    ] {
        assert!(
            value.get(field).is_none(),
            "{field} must be absent: {value:?}"
        );
    }
}

#[test]
fn util_responses_deserialize_into_pinned_types() -> Result<(), Box<dyn std::error::Error>> {
    let handler = Handler::new(Arc::new(Context::new()));

    let estimate: corepc_types::v31::EstimateSmartFee =
        typed(&handler.dispatch("estimatesmartfee", &json!([2]))?)?;
    assert!(estimate.fee_rate.is_none());
    assert_eq!(estimate.blocks, 2);

    // The standard burn address is valid on the default mainnet selector.
    let valid: corepc_types::v31::ValidateAddress =
        typed(&handler.dispatch("validateaddress", &json!(["1111111111111111111114oLvT2"]))?)?;
    assert!(valid.is_valid);
    assert!(!valid.script_pubkey.is_empty());

    // Core answers a malformed address with the sparse `{"isvalid": false}`
    // object only, and a well-formed address from another network fails
    // identically; the corepc type cannot model that branch (local_shape).
    assert_sparse_invalid(&handler.dispatch("validateaddress", &json!(["not a real address"]))?);
    assert_sparse_invalid(&handler.dispatch(
        "validateaddress",
        &json!(["tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx"]),
    )?);
    let descriptor: corepc_types::v31::GetDescriptorInfo = typed(&handler.dispatch(
        "getdescriptorinfo",
        &json!(["addr(1111111111111111111114oLvT2)"]),
    )?)?;
    assert!(!descriptor.is_range);
    assert!(!descriptor.is_solvable);
    assert_eq!(descriptor.checksum.len(), 8);

    let memory: corepc_types::v31::GetMemoryInfoStats =
        typed(&handler.dispatch("getmemoryinfo", &json!(["stats"]))?)?;
    assert!(memory.0.contains_key("locked"));

    Ok(())
}

#[test]
fn mining_responses_error_without_a_control() {
    let handler = Handler::new(Arc::new(Context::new()));
    assert!(handler.dispatch("getblocktemplate", &json!([{}])).is_err());
    assert!(handler.dispatch("getmininginfo", &json!([])).is_err());
}

/// Mirrors the `handler_smoke` mining-control fixture so the typed mining
/// response schemas are exercised against real template facts instead of the
/// unavailable-control error path.
struct CompatMiningControl;

impl MiningControl for CompatMiningControl {
    fn get_block_template(
        &self,
        _request: BlockTemplateRequest,
    ) -> Result<BlockTemplateResult, MiningControlError> {
        let previous_block_hash = Hash256::default();
        Ok(BlockTemplateResult::Template(BlockTemplate {
            candidate: Arc::new(Candidate {
                template_id: TemplateId::new(&previous_block_hash, 0),
                previous_block_hash,
                height: 0,
                version: 0x2000_0000,
                bits: 0x1d00_ffff,
                min_time: 0,
                current_time: 0,
                csv_active: false,
                segwit_active: false,
                max_weight: 4_000_000,
                max_size: 4_000_000,
                max_sigops: 80_000,
                mempool_sequence: 0,
                coinbase: Tx {
                    version: 1,
                    lock_time: 0,
                    inputs: vec![TxIn {
                        previous_output: OutPoint::new(Txid::default(), u32::MAX),
                        script_sig: Vec::new(),
                        sequence: u32::MAX,
                        witness: Vec::new(),
                    }],
                    outputs: Vec::new(),
                },
                coinbase_value: 0,
                fees: 0,
                weight: 0,
                size: 0,
                sigop_cost: 0,
                transactions: Vec::new(),
                witness_merkle_root: None,
                witness_reserved_value: None,
                witness_commitment: None,
            }),
            rules: Vec::new(),
            version_bits_available: Vec::new(),
            version_bits_required: 0,
            capabilities: vec![MiningCapability::new("coinbasetxn")],
            mutable: vec![
                TemplateMutation::Time,
                TemplateMutation::Transactions,
                TemplateMutation::PreviousBlock,
            ],
            submit_old: None,
            work_id: None,
        }))
    }

    fn mining_info(&self) -> Result<MiningInfo, MiningControlError> {
        Ok(MiningInfo {
            blocks: 0,
            last_candidate: None,
            bits: 0x207f_ffff,
            difficulty: 1.0,
            network_hashes_per_second: 0.0,
            pooled_transactions: 0,
            network: Network::Regtest,
            next_bits: 0x207f_ffff,
            next_difficulty: 1.0,
            minimum_fee_rate: 1_000,
            signet: None,
            warnings: Vec::new(),
        })
    }

    fn submit_block(&self, _block: Block) -> Result<BlockValidationResult, MiningControlError> {
        Ok(BlockValidationResult::Accepted)
    }

    fn publish_generation(&self) {}
}

#[test]
fn mining_responses_deserialize_into_pinned_types() -> Result<(), Box<dyn std::error::Error>> {
    let handler = Handler::new(Arc::new(
        Context::new().with_mining_control(Arc::new(CompatMiningControl)),
    ));

    let template: corepc_types::v31::GetBlockTemplate =
        typed(&handler.dispatch("getblocktemplate", &json!([{}]))?)?;
    assert_eq!(template.version, 0x2000_0000);
    assert_eq!(template.height, 0);
    assert_eq!(template.bits, "1d00ffff");
    // Compact 0x1d00ffff expanded to Core's 64-char target spelling.
    assert_eq!(
        template.target,
        "00000000ffff0000000000000000000000000000000000000000000000000000"
    );
    assert_eq!(template.previous_block_hash, "0".repeat(64));
    assert_eq!(template.nonce_range, "00000000ffffffff");
    assert_eq!(template.capabilities, ["coinbasetxn"]);
    // TemplateMutation variants render as Core's `mutable` vocabulary.
    assert_eq!(template.mutable, ["time", "transactions", "prevblock"]);
    assert_eq!(template.sigop_limit, 80_000);
    assert_eq!(template.size_limit, 4_000_000);
    assert_eq!(template.weight_limit, 4_000_000);
    assert_eq!(template.coinbase_value, 0);
    assert!(template.transactions.is_empty());
    assert!(template.rules.is_empty());
    assert!(template.version_bits_available.is_empty());
    assert_eq!(template.version_bits_required, 0);
    assert_eq!(template.min_time, 0);
    assert_eq!(template.current_time, 0);
    assert!(
        template
            .long_poll_id
            .as_ref()
            .is_some_and(|id| !id.is_empty())
    );
    assert!(template.default_witness_commitment.is_none());
    assert!(template.signet_challenge.is_none());
    let mining: corepc_types::v31::GetMiningInfo =
        typed(&handler.dispatch("getmininginfo", &json!([]))?)?;
    assert!((mining.difficulty - 1.0).abs() < f64::EPSILON);
    assert!(mining.current_block_weight.is_none());
    assert!(mining.current_block_tx.is_none());
    assert_eq!(mining.bits, "207fffff");
    assert_eq!(
        mining.target,
        "7fffff0000000000000000000000000000000000000000000000000000000000"
    );
    assert!((mining.network_hash_ps - 0.0).abs() < f64::EPSILON);
    assert_eq!(mining.pooled_tx, 0);
    // 1_000 sat/kvB crosses the sat-to-BTC unit boundary Core reports.
    assert!((mining.block_min_tx_fee - 1e-5).abs() < f64::EPSILON);
    assert!((mining.next.difficulty - 1.0).abs() < f64::EPSILON);
    assert!(mining.signet_challenge.is_none());
    assert!(mining.warnings.is_empty());
    // Nested next-block facts must survive the round-trip.
    assert_eq!(mining.next.height, 1);
    assert_eq!(mining.next.bits, "207fffff");
    assert_eq!(mining.next.target, mining.target);

    Ok(())
}

#[test]
fn primitive_responses_stay_primitives() -> Result<(), Box<dyn std::error::Error>> {
    let handler = Handler::new(Arc::new(Context::new()));

    let uptime = handler.dispatch("uptime", &json!([]))?;
    assert!(uptime.as_u64().is_some());

    assert!(handler.dispatch("ping", &json!([]))?.is_null());
    assert!(
        handler
            .dispatch("addnode", &json!(["127.0.0.1:1", "onetry"]))
            .is_ok()
    );
    assert!(
        handler
            .dispatch("setban", &json!(["127.0.0.0/8", "add"]))?
            .is_null()
    );
    assert!(handler.dispatch("clearbanned", &json!([]))?.is_null());
    assert_eq!(
        handler.dispatch(
            "prioritisetransaction",
            &json!([Hash256::default().to_string(), 0, 0])
        )?,
        json!(true)
    );
    Ok(())
}
