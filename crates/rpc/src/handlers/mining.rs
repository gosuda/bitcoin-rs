use alloc::sync::Arc;
use core::time::Duration;

use bitcoin::hex::DisplayHex as _;
use bitcoin_rs_mining::{BlockTemplate, BlockTemplateParams};
use bitcoin_rs_primitives::Hash256;
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait, Value, json};

use crate::context::{CachedBlockTemplate, Context};
use crate::error::RpcError;
use crate::handlers::{ensure_no_params, params_array, required_str};

const NETWORK_HASHPS_WINDOW: u32 = 120;

/// Weight limit advertised to miners, and the ceiling selection works under.
const MAX_BLOCK_WEIGHT: u32 = 4_000_000;
/// Sigop-cost limit for a block.
const MAX_BLOCK_SIGOPS_COST: u32 = 80_000;
/// Serialized size limit advertised to miners.
const MAX_BLOCK_SERIALIZED_SIZE: u32 = 4_000_000;
/// Version bits top bits, `VERSIONBITS_TOP_BITS` in Bitcoin Core.
const VERSIONBITS_TOP_BITS: i32 = 0x2000_0000;
/// How long an assembled template stays fresh.
///
/// The cache is already invalidated by a new tip or any mempool change, so
/// this bounds only how stale `curtime` may get. Bitcoin Core re-checks on the
/// same order of interval.
const TEMPLATE_CACHE_SECONDS: u64 = 5;
/// Tip age past which the node is treated as still catching up.
///
/// Bitcoin Core's `DEFAULT_MAX_TIP_AGE`, the same 24 hours its
/// `IsInitialBlockDownload` uses.
const MAX_TIP_AGE_SECONDS: u64 = 24 * 60 * 60;

pub(crate) fn getblocktemplate(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let request = if params.is_null() {
        None
    } else {
        params_array(params)?.first()
    };

    match request
        .and_then(|request| request.get("mode"))
        .and_then(|mode| mode.as_str())
        .unwrap_or("template")
    {
        "template" => {}
        // BIP23 block proposal. Answered before the rule handshake and before
        // the connected/still-syncing preconditions, as Core does: a proposal
        // asks about one specific block, it does not ask for work.
        "proposal" => return proposal(ctx, request),
        _ => return Err(RpcError::InvalidParameter("invalid mode".to_owned())),
    }

    require_client_rules(ctx, request)?;

    let now = now_seconds();
    // Core skips both preconditions off mainnet, so a test network can build
    // templates while it is still catching up.
    if ctx.chain_network == bitcoin_rs_primitives::Network::Mainnet {
        if ctx.peers.read().is_empty() {
            return Err(RpcError::ClientNotConnected("bitcoin-rs is not connected"));
        }
        if is_in_initial_sync(ctx, now) {
            return Err(RpcError::ClientInInitialDownload(
                "bitcoin-rs is in initial sync and waiting for blocks",
            ));
        }
    }

    wait_for_long_poll(ctx, request);

    let template = template_for_tip(ctx, now)?;
    Ok(render(ctx, &template))
}

/// Answers a BIP23 block proposal: would this block connect on top of the tip?
///
/// Bitcoin Core's `getblocktemplate` proposal path. A `null` result means the
/// block is valid; every other answer is a string naming why it is not, or why
/// the question could not be answered.
fn proposal(ctx: &Context, request: Option<&Value>) -> Result<Value, RpcError> {
    use bitcoin::hashes::Hash as _;

    let data = request
        .and_then(|request| request.get("data"))
        .and_then(|data| data.as_str())
        .ok_or(RpcError::InvalidType(
            "missing data string key for proposal",
        ))?;
    let bytes = <Vec<u8> as bitcoin::hex::FromHex>::from_hex(data)
        .map_err(|_| RpcError::Deserialization("block decode failed"))?;
    let block: bitcoin::Block = bitcoin::consensus::encode::deserialize(&bytes)
        .map_err(|_| RpcError::Deserialization("block decode failed"))?;

    let hash = Hash256::from_le_bytes(block.block_hash().as_byte_array());
    if let Some(verdict) = duplicate_verdict(ctx, hash) {
        return Ok(json!(verdict));
    }
    // A proposal is weighed against the tip it names. Built on anything else it
    // is not wrong, it is unanswerable -- the UTXO set this node can offer is
    // the one at its own tip.
    if block.header.prev_blockhash.as_byte_array() != &ctx.applied_hash().to_le_bytes() {
        return Ok(json!("inconclusive-not-best-prevblk"));
    }

    let Some(control) = ctx.chain_control.as_ref() else {
        return Err(RpcError::MethodDisabled(
            "this node has no block validator installed",
        ));
    };
    match control.test_block_validity(&block) {
        Ok(()) => Ok(Value::new_null()),
        Err(reason) => Ok(json!(reason.0)),
    }
}

/// Core's three answers for a block the node has already seen.
///
/// `None` means the block is genuinely new and worth validating.
fn duplicate_verdict(ctx: &Context, hash: Hash256) -> Option<&'static str> {
    use bitcoin_rs_chain::NodeStatus;

    let tree = ctx.block_tree.read();
    let node = tree.node_by_hash(hash)?;
    Some(match node.status {
        // Connected at some point, so its transactions were validated. Core
        // asks the same question as `IsValid(BLOCK_VALID_SCRIPTS)`.
        NodeStatus::Active | NodeStatus::Stale => "duplicate",
        NodeStatus::Invalid => "duplicate-invalid",
        // The header is known but the body has never been checked, so this node
        // has no verdict to report -- not a claim that the block is fine.
        NodeStatus::HeaderValid => "duplicate-inconclusive",
    })
}

/// BIP22's rule handshake: a client must name the rules it understands.
///
/// Core makes `rules` a required argument and rejects a request that does not
/// declare `segwit`. Accepting one anyway hands a miner that predates segwit a
/// template it will turn into an invalid block, which is exactly the failure
/// the handshake exists to prevent.
fn require_client_rules(ctx: &Context, request: Option<&Value>) -> Result<(), RpcError> {
    let declared = request
        .and_then(|request| request.get("rules"))
        .and_then(|rules| rules.as_array())
        .map(|rules| {
            rules
                .iter()
                .filter_map(sonic_rs::JsonValueTrait::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    if !declared.iter().any(|rule| rule == "segwit") {
        return Err(RpcError::InvalidParameter(
            "getblocktemplate must be called with the segwit rule set \
             (call with {\"rules\": [\"segwit\"]})"
                .to_owned(),
        ));
    }
    if ctx.chain_network == bitcoin_rs_primitives::Network::Signet
        && !declared.iter().any(|rule| rule == "signet")
    {
        return Err(RpcError::InvalidParameter(
            "getblocktemplate must be called with the signet rule set \
             (call with {\"rules\": [\"signet\", \"segwit\"]})"
                .to_owned(),
        ));
    }
    Ok(())
}

/// Whether the node is still catching up, by the age of its applied tip.
///
/// Deliberately local rather than shared: `Context::is_initial_block_download`
/// is being added by the `verificationprogress` work, and the two should
/// become one helper once that lands. Duplicating a definition is the smaller
/// problem than shipping this precondition unenforced.
fn is_in_initial_sync(ctx: &Context, now: u64) -> bool {
    let Some(tip_time) = applied_tip_time(ctx) else {
        // No applied tip at all: nothing has been validated yet.
        return true;
    };
    now.saturating_sub(u64::from(tip_time)) > MAX_TIP_AGE_SECONDS
}

fn applied_tip_time(ctx: &Context) -> Option<u32> {
    let tip = ctx.applied_tip.load_full()?;
    let tree = ctx.block_tree.read();
    tree.node(tip.tip_id).ok().map(|node| node.header.time)
}

fn wait_for_long_poll(ctx: &Arc<Context>, request: Option<&Value>) {
    let Some(longpollid) = request
        .and_then(|request| request.get("longpollid"))
        .and_then(|value| value.as_str())
    else {
        return;
    };
    if longpollid == ctx.mining_template_id.load().as_str() {
        let _result = ctx
            .mining_notifications
            .recv_timeout(Duration::from_mins(1));
    }
}

/// Returns a template for the current tip, assembling one only when needed.
fn template_for_tip(ctx: &Arc<Context>, now: u64) -> Result<BlockTemplate, RpcError> {
    let tip = ctx.applied_hash();
    let sequence = ctx.mempool.read().sequence_number();

    if let Some(cached) = ctx.mining_template_cache.read().as_ref() {
        if cached.tip == tip
            && cached.mempool_sequence == sequence
            && now.saturating_sub(cached.built_at) < TEMPLATE_CACHE_SECONDS
        {
            return Ok(cached.template.clone());
        }
    }

    let template = assemble(ctx, tip, now)?;
    *ctx.mining_template_cache.write() = Some(CachedBlockTemplate {
        tip,
        mempool_sequence: sequence,
        built_at: now,
        template: template.clone(),
    });
    Ok(template)
}

fn assemble(ctx: &Arc<Context>, tip: Hash256, now: u64) -> Result<BlockTemplate, RpcError> {
    let height = ctx.applied_height().saturating_add(1);
    let min_time = median_time_past(ctx).map_or(0, |mtp| mtp.saturating_add(1));
    let current_time = u32::try_from(now).unwrap_or(u32::MAX).max(min_time);
    let bits = next_bits(ctx, current_time)?;

    let params = BlockTemplateParams {
        previous_block_hash: tip,
        height,
        version: VERSIONBITS_TOP_BITS,
        bits: format!("{:08x}", bits.to_consensus()),
        target: target_hex(bits),
        min_time,
        current_time,
        long_poll_id: ctx.mining_template_id.load().to_string(),
        max_weight: MAX_BLOCK_WEIGHT,
        max_sigops: MAX_BLOCK_SIGOPS_COST,
        max_size: MAX_BLOCK_SERIALIZED_SIZE,
    };

    let pool = ctx.mempool.read();
    BlockTemplate::from_mempool(&pool, &bitcoin_rs_mining::MiningPolicy, params)
        .map_err(|error| RpcError::Internal(format!("block template assembly failed: {error}")))
}

/// The compact target the next block must carry.
///
/// Asks the chain crate the same question a validator asks, so a template can
/// never advertise difficulty the node would then reject.
fn next_bits(ctx: &Context, candidate_time: u32) -> Result<bitcoin::CompactTarget, RpcError> {
    let Some(tip) = ctx.applied_tip.load_full() else {
        return Err(RpcError::ClientInInitialDownload(
            "bitcoin-rs has no applied tip to build on",
        ));
    };
    let tree = ctx.block_tree.read();
    bitcoin_rs_chain::expected_next_bits(ctx.chain_network, &tree, tip.tip_id, candidate_time)
        .map_err(|error| RpcError::Internal(format!("next difficulty is unknown: {error}")))
}

fn median_time_past(ctx: &Context) -> Option<u32> {
    const MEDIAN_TIME_SPAN: usize = 11;
    let tip = ctx.applied_tip.load_full()?;
    ctx.block_tree
        .read()
        .median_time_past_at(tip.tip_id, MEDIAN_TIME_SPAN)
}

/// The full target as conventional big-endian hex.
fn target_hex(bits: bitcoin::CompactTarget) -> String {
    bitcoin::Target::from_compact(bits)
        .to_be_bytes()
        .to_lower_hex_string()
}

/// Renders the template plus the fields that describe the rules it was built
/// under.
fn render(ctx: &Context, template: &BlockTemplate) -> Value {
    let transactions = template
        .transactions
        .iter()
        .map(|tx| {
            json!({
                "data": tx.data,
                "txid": tx.txid,
                "hash": tx.hash,
                "depends": tx.depends,
                "fee": tx.fee,
                "sigops": tx.sigops,
                "weight": tx.weight
            })
        })
        .collect::<Vec<_>>();

    json!({
        // `proposal` is what this node can be asked to do beyond handing out
        // work, and BIP23 says a server must name it for a miner to rely on it.
        "capabilities": vec!["proposal"],
        "version": template.version,
        "rules": active_rules(ctx, template.height),
        // No BIP9 deployment is currently signalling on any network this node
        // supports, so there is nothing for a miner to opt into. Reporting an
        // invented bit here would be worse than reporting none.
        "vbavailable": json!({}),
        "vbrequired": 0,
        "previousblockhash": template.previousblockhash,
        "transactions": transactions,
        "coinbaseaux": json!({}),
        "coinbasevalue": template.coinbasevalue,
        "longpollid": template.longpollid,
        "target": template.target,
        "mintime": template.mintime,
        "mutable": template.mutable,
        "noncerange": template.noncerange,
        "sigoplimit": template.sigoplimit,
        "sizelimit": template.sizelimit,
        "weightlimit": template.weightlimit,
        "curtime": template.curtime,
        "bits": template.bits,
        "height": template.height,
        "default_witness_commitment": template.default_witness_commitment
    })
}

/// Rule names a miner must understand to use this template.
///
/// Mirrors Core's list: `csv` always, `!segwit` and `taproot` once segwit is
/// active, and `!signet` on signet. The `!` prefix is BIP9's marker for a rule
/// that changes block structure, which a miner may not ignore.
fn active_rules(ctx: &Context, height: u32) -> Vec<&'static str> {
    let mut rules = vec!["csv"];
    if ctx.chain_network.is_segwit_active(height) {
        rules.push("!segwit");
        rules.push("taproot");
    }
    if ctx.chain_network == bitcoin_rs_primitives::Network::Signet {
        rules.push("!signet");
    }
    rules
}

fn now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
}

pub(crate) fn getmininginfo(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    ensure_no_params(params)?;
    let (current_block_weight, current_block_tx) = estimate_current_block(ctx);

    let blocks = ctx.applied_height();
    let pooledtx = ctx.mempool.read().stats().txs;
    let tip_bits = {
        let tree = ctx.block_tree.read();
        let snapshot = ctx.applied_tip.load_full();
        snapshot.and_then(|tip| tree.node(tip.tip_id).ok().map(|node| node.header.bits))
    };
    let difficulty = tip_bits.map_or(0.0, |bits| ctx.difficulty_for_bits(bits));
    let chain = match ctx.chain_network {
        bitcoin_rs_primitives::Network::Mainnet => "main",
        bitcoin_rs_primitives::Network::Testnet3 | bitcoin_rs_primitives::Network::Testnet4 => {
            "test"
        }
        bitcoin_rs_primitives::Network::Signet => "signet",
        bitcoin_rs_primitives::Network::Regtest => "regtest",
    };

    Ok(json!({
        "blocks": blocks,
        "currentblockweight": current_block_weight,
        "currentblocktx": current_block_tx,
        "difficulty": difficulty,
        "networkhashps": estimate_network_hashps(ctx),
        "pooledtx": pooledtx,
        "chain": chain,
        "warnings": ""
    }))
}

fn estimate_current_block(ctx: &Context) -> (u64, u64) {
    const MAX_BLOCK_WEIGHT: u32 = 4_000_000;
    const MAX_BLOCK_SIGOPS_COST: u32 = 80_000;

    let policy = bitcoin_rs_mining::MiningPolicy;
    let pool = ctx.mempool.read();
    let selected = policy.select_transactions(
        &pool,
        MAX_BLOCK_WEIGHT.saturating_sub(bitcoin_rs_mining::DEFAULT_BLOCK_RESERVED_WEIGHT),
        MAX_BLOCK_SIGOPS_COST,
    );
    let mut weight: u64 = 0;
    let mut count: u64 = 0;
    for entry_id in &selected {
        let Some(entry) = pool.entry(*entry_id) else {
            continue;
        };
        weight = weight.saturating_add(u64::from(entry.vsize).saturating_mul(4));
        count = count.saturating_add(1);
    }
    (weight, count)
}

fn estimate_network_hashps(ctx: &Context) -> f64 {
    let tree = ctx.block_tree.read();
    let Some(tip_snapshot) = ctx.applied_tip.load_full() else {
        return 0.0;
    };
    let tip_id = tip_snapshot.tip_id;
    let Ok(tip_node) = tree.node(tip_id) else {
        return 0.0;
    };
    let target_height = tip_node.height.saturating_sub(NETWORK_HASHPS_WINDOW);
    let Some(earliest_id) = tree.node_at_height_from(tip_id, target_height) else {
        return 0.0;
    };
    let Ok(earliest_node) = tree.node(earliest_id) else {
        return 0.0;
    };
    if earliest_node.height == tip_node.height {
        return 0.0;
    }

    let work_delta = tip_node.chainwork.saturating_sub(earliest_node.chainwork);
    let time_delta_secs =
        i64::from(tip_node.header.time).saturating_sub(i64::from(earliest_node.header.time));
    if time_delta_secs <= 0 {
        return 0.0;
    }

    chainwork_to_f64(work_delta) / f64::from(u32::try_from(time_delta_secs).unwrap_or(u32::MAX))
}

fn chainwork_to_f64(work: bitcoin_rs_chain::ChainWork) -> f64 {
    let bytes: [u8; 32] = work.to_be_bytes();
    bytes
        .iter()
        .fold(0.0_f64, |acc, &byte| acc.mul_add(256.0, f64::from(byte)))
}

pub(crate) fn submitblock(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    use bitcoin::consensus::encode::deserialize;
    use bitcoin::hex::FromHex;

    let hex = required_str(params, 0, "block hex is required")?;
    let bytes = <Vec<u8> as FromHex>::from_hex(hex)
        .map_err(|_| RpcError::InvalidParams("block hex is not valid hexadecimal"))?;
    let block: bitcoin::Block = match deserialize(&bytes) {
        Ok(b) => b,
        Err(_) => return Ok(json!("bad-block-encoding")),
    };
    let target = block.header.target();
    if block.header.validate_pow(target).is_err() {
        return Ok(json!("high-hash"));
    }
    if let Some(sender) = &ctx.inbound_blocks_sender {
        // The inbound-block channel is bounded, so a sustained peer-driven flood
        // could park this RPC worker on a blocking send. Wait briefly for a slot
        // (the drain frees one within a tick under normal load) so a locally
        // submitted block is not dropped, then report busy rather than blocking
        // the connection indefinitely.
        match sender.send_timeout(
            bitcoin_rs_p2p::InboundBlock::from_decoded(block),
            core::time::Duration::from_secs(2),
        ) {
            Ok(()) => {}
            Err(crossbeam_channel::SendTimeoutError::Timeout(_)) => {
                return Ok(json!("inbound-busy"));
            }
            Err(crossbeam_channel::SendTimeoutError::Disconnected(_)) => {
                return Ok(json!("channel-closed"));
            }
        }
    }
    // Successful enqueue (or no-sender accept path) returns null.
    Ok(Value::new_null())
}

pub(crate) fn prioritisetransaction(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    use core::str::FromStr as _;

    let txid_str = required_str(params, 0, "txid is required")?;
    let txid = bitcoin::Txid::from_str(txid_str)
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
    let bumped = ctx.mempool.write().prioritise(txid, fee_delta);
    Ok(json!(bumped))
}
#[cfg(test)]
mod submitblock_tests {
    use super::*;
    use alloc::sync::Arc;
    use bitcoin::consensus::encode::serialize;

    #[test]
    fn submitblock_accepts_regtest_genesis() {
        let ctx = Arc::new(Context::new());
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let block_hex = serialize(&genesis).to_lower_hex_string();
        let result = submitblock(&ctx, &json!([block_hex]))
            .unwrap_or_else(|err| panic!("submitblock failed: {err}"));
        assert!(
            result.is_null(),
            "expected null accept signal, got {result:?}"
        );
    }

    #[test]
    fn submitblock_pushes_to_channel_when_present() {
        let (tx, rx) = crossbeam_channel::unbounded::<bitcoin_rs_p2p::InboundBlock>();
        let mut ctx = Context::new();
        ctx.inbound_blocks_sender = Some(tx);
        let ctx = Arc::new(ctx);
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let hex = serialize(&genesis).to_lower_hex_string();
        let result = submitblock(&ctx, &json!([hex]))
            .unwrap_or_else(|err| panic!("submitblock failed: {err}"));
        assert!(result.is_null());
        let received = rx
            .try_recv()
            .unwrap_or_else(|err| panic!("channel did not receive block: {err}"));
        assert_eq!(received.block.block_hash(), genesis.block_hash());
    }

    #[test]
    fn submitblock_rejects_garbage() {
        let ctx = Arc::new(Context::new());
        let result = submitblock(&ctx, &json!(["deadbeef"]))
            .unwrap_or_else(|err| panic!("submitblock failed: {err}"));
        let Some(s) = result.as_str() else {
            panic!("expected string rejection, got {result:?}");
        };
        assert_eq!(s, "bad-block-encoding");
    }
}

#[cfg(test)]
mod getmininginfo_tests {
    use super::*;
    use alloc::sync::Arc;

    #[test]
    fn getmininginfo_returns_core_shape_on_fresh_context() {
        let ctx = Arc::new(Context::new());
        let result = getmininginfo(&ctx, &json!([]))
            .unwrap_or_else(|err| panic!("getmininginfo failed: {err}"));
        let Some(chain) = result.get("chain").and_then(JsonValueTrait::as_str) else {
            panic!("chain missing: {result:?}");
        };
        assert_eq!(chain, "main");
        let Some(blocks) = result.get("blocks").and_then(JsonValueTrait::as_u64) else {
            panic!("blocks missing: {result:?}");
        };
        assert_eq!(blocks, 0);
        let Some(pooledtx) = result.get("pooledtx").and_then(JsonValueTrait::as_u64) else {
            panic!("pooledtx missing: {result:?}");
        };
        assert_eq!(pooledtx, 0);
    }

    #[test]
    fn getmininginfo_currentblockweight_reflects_mempool_when_populated() {
        use bitcoin_rs_mempool::MempoolEntry;

        let ctx = Arc::new(Context::new());
        {
            let mut pool = ctx.mempool.write();
            let tx = bitcoin::Transaction {
                version: bitcoin::transaction::Version(2),
                lock_time: bitcoin::absolute::LockTime::ZERO,
                input: Vec::new(),
                output: Vec::new(),
            };
            let entry = MempoolEntry::new(Arc::new(tx), 250, 5_000, 1, 7);
            pool.insert_entry(entry)
                .unwrap_or_else(|err| panic!("insert_entry failed: {err}"));
        }

        let result = getmininginfo(&ctx, &json!([]))
            .unwrap_or_else(|err| panic!("getmininginfo failed: {err}"));
        let Some(weight) = result
            .get("currentblockweight")
            .and_then(JsonValueTrait::as_u64)
        else {
            panic!("currentblockweight missing: {result:?}");
        };
        let Some(tx_count) = result
            .get("currentblocktx")
            .and_then(JsonValueTrait::as_u64)
        else {
            panic!("currentblocktx missing: {result:?}");
        };

        assert_eq!(weight, 1_000);
        assert_eq!(tx_count, 1);
    }

    #[test]
    fn getmininginfo_currentblocktx_zero_when_mempool_empty() {
        let ctx = Arc::new(Context::new());
        let result = getmininginfo(&ctx, &json!([]))
            .unwrap_or_else(|err| panic!("getmininginfo failed: {err}"));
        let Some(weight) = result
            .get("currentblockweight")
            .and_then(JsonValueTrait::as_u64)
        else {
            panic!("currentblockweight missing");
        };
        let Some(count) = result
            .get("currentblocktx")
            .and_then(JsonValueTrait::as_u64)
        else {
            panic!("currentblocktx missing");
        };
        assert_eq!(weight, 0);
        assert_eq!(count, 0);
    }

    #[test]
    fn getmininginfo_networkhashps_zero_when_no_applied_tip() {
        let ctx = Arc::new(Context::new());
        let result = getmininginfo(&ctx, &json!([]))
            .unwrap_or_else(|err| panic!("getmininginfo failed: {err}"));
        let Some(rate) = result.get("networkhashps").and_then(JsonValueTrait::as_f64) else {
            panic!("networkhashps missing: {result:?}");
        };
        assert!(rate.abs() < f64::EPSILON, "expected zero, got {rate}");
    }
}

#[cfg(test)]
mod getblocktemplate_tests {
    use alloc::sync::Arc;

    use bitcoin::block::{Header, Version};
    use bitcoin::hashes::Hash as _;
    use bitcoin::{BlockHash, CompactTarget, TxMerkleNode};
    use bitcoin_rs_chain::{ChainWork, NodeStatus, TipSnapshot};
    use bitcoin_rs_primitives::{Hash256, Network};
    use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, json};

    use super::getblocktemplate;
    use crate::context::Context;
    use crate::error::RpcError;

    const REGTEST_BITS: u32 = 0x207f_ffff;

    fn header(previous: BlockHash, time: u32, nonce: u32) -> Header {
        Header {
            version: Version::ONE,
            prev_blockhash: previous,
            merkle_root: TxMerkleNode::all_zeros(),
            time,
            bits: CompactTarget::from_consensus(REGTEST_BITS),
            nonce,
        }
    }

    /// A context whose applied tip sits at the end of an eleven-block chain.
    ///
    /// Eleven so the median-time-past window is full: a shorter chain would
    /// let a `mintime` bug hide behind a degenerate median.
    fn context_with_chain(network: Network, tip_time: u32) -> Arc<Context> {
        context_with_chain_and_control(network, tip_time, None)
    }

    fn context_with_chain_and_control(
        network: Network,
        tip_time: u32,
        control: Option<Arc<dyn crate::context::ChainControl>>,
    ) -> Arc<Context> {
        let mut context = Context::new();
        context.chain_network = network;
        if let Some(control) = control {
            context = context.with_chain_control(control);
        }
        let ctx = Arc::new(context);

        let (tip_id, tip_hash, height) = {
            let mut tree = ctx.block_tree.write();
            let mut parent = None;
            let mut previous = BlockHash::all_zeros();
            let mut tip_id = bitcoin_rs_chain::NodeId::new(0);
            let mut tip_hash = Hash256::default();
            let mut height = 0_u32;
            for index in 0_u32..11 {
                // Ten-minute spacing ending at `tip_time`.
                let time = tip_time.saturating_sub((10 - index) * 600);
                let candidate = header(previous, time, index);
                previous = candidate.block_hash();
                tip_hash = Hash256::from_le_bytes(previous.as_byte_array());
                tip_id = tree
                    .insert_node(parent, candidate, NodeStatus::Active)
                    .unwrap_or_else(|err| panic!("insert_node failed: {err}"));
                parent = Some(tip_id);
                height = index;
            }
            (tip_id, tip_hash, height)
        };
        ctx.set_applied_tip(TipSnapshot {
            tip_id,
            height,
            chainwork: ChainWork::ZERO,
            hash: tip_hash,
        });
        ctx.set_chain_tip(TipSnapshot {
            tip_id,
            height,
            chainwork: ChainWork::ZERO,
            hash: tip_hash,
        });
        ctx
    }

    fn now_seconds() -> u32 {
        u32::try_from(super::now_seconds()).unwrap_or(u32::MAX)
    }

    fn template(ctx: &Arc<Context>) -> sonic_rs::Value {
        getblocktemplate(ctx, &json!([{"rules": ["segwit"]}]))
            .unwrap_or_else(|err| panic!("getblocktemplate failed: {err}"))
    }

    /// BIP22 makes the client declare what it understands, and Core enforces it.
    #[test]
    fn the_segwit_rule_must_be_declared() {
        let ctx = context_with_chain(Network::Regtest, now_seconds());

        let Err(error) = getblocktemplate(&ctx, &json!([{}])) else {
            panic!("a request that declares no rules must be refused");
        };
        assert_eq!(error.code(), RpcError::CORE_INVALID_PARAMETER);
        assert!(
            getblocktemplate(&ctx, &json!([{"rules": ["segwit"]}])).is_ok(),
            "declaring segwit must be enough"
        );
    }

    /// A miner must be told the difficulty the chain will actually require.
    ///
    /// `bits` was the string "00000000" and `target` was thirty-two zero bytes,
    /// which is a target no hash can meet. This is the field that made the old
    /// stub dangerous rather than merely incomplete.
    #[test]
    fn the_template_carries_the_difficulty_the_chain_requires() {
        let ctx = context_with_chain(Network::Regtest, now_seconds());

        let value = template(&ctx);

        let bits_field = value.get("bits");
        let Some(bits) = bits_field.as_str() else {
            panic!("bits must be a string");
        };
        let expected = {
            let tree = ctx.block_tree.read();
            let Some(tip) = ctx.applied_tip.load_full() else {
                panic!("the fixture must have an applied tip");
            };
            bitcoin_rs_chain::expected_next_bits(
                ctx.chain_network,
                &tree,
                tip.tip_id,
                now_seconds(),
            )
            .unwrap_or_else(|err| panic!("expected_next_bits failed: {err}"))
        };
        assert_eq!(
            bits,
            format!("{:08x}", expected.to_consensus()),
            "bits must be what a validator would require of the next block"
        );

        let target_field = value.get("target");
        let Some(target) = target_field.as_str() else {
            panic!("target must be a string");
        };
        assert_eq!(target.len(), 64);
        assert_ne!(
            target, "0000000000000000000000000000000000000000000000000000000000000000",
            "an all-zero target is unmeetable and was what the stub returned"
        );
    }

    /// `mintime` is the median time past plus one, as consensus requires.
    #[test]
    fn mintime_comes_from_the_median_time_past() {
        let tip_time = now_seconds();
        let ctx = context_with_chain(Network::Regtest, tip_time);

        let value = template(&ctx);

        let expected = {
            let tree = ctx.block_tree.read();
            let Some(tip) = ctx.applied_tip.load_full() else {
                panic!("the fixture must have an applied tip");
            };
            let Some(mtp) = tree.median_time_past_at(tip.tip_id, 11) else {
                panic!("the fixture chain must have a median time past");
            };
            mtp.saturating_add(1)
        };
        assert_eq!(value.get("mintime").as_u64(), Some(u64::from(expected)));
        assert!(
            expected > 0,
            "the fixture must produce a real median or this proves nothing"
        );
        assert!(
            value.get("curtime").as_u64().unwrap_or(0) >= u64::from(expected),
            "curtime must not precede mintime"
        );
    }

    /// Rule names a miner must understand to use the template.
    #[test]
    fn the_template_names_the_rules_it_was_built_under() {
        let ctx = context_with_chain(Network::Regtest, now_seconds());

        let value = template(&ctx);

        let rules_field = value.get("rules");
        let Some(rules) = rules_field.as_array() else {
            panic!("rules must be an array");
        };
        let names = rules
            .iter()
            .filter_map(sonic_rs::JsonValueTrait::as_str)
            .collect::<Vec<_>>();
        assert!(names.contains(&"csv"), "got {names:?}");
        assert!(
            names.contains(&"!segwit"),
            "segwit is active on regtest and changes block structure, so it \
             must carry the marker: {names:?}"
        );
        // Nothing is signalling, so claiming a version bit would be an invention.
        assert_eq!(value.get("vbrequired").as_u64(), Some(0));
    }

    /// The second call must not reassemble the template.
    ///
    /// Observed by planting a marker in the cache: if the handler consults it,
    /// the marker comes back. Timing cannot show this — two calls in the same
    /// second produce identical output either way.
    #[test]
    fn a_second_call_is_served_from_the_cache() {
        let ctx = context_with_chain(Network::Regtest, now_seconds());
        let _first = template(&ctx);

        {
            let mut cache = ctx.mining_template_cache.write();
            let Some(entry) = cache.as_mut() else {
                panic!("the first call must have populated the cache");
            };
            entry.template.height = 999_999;
        }

        let second = template(&ctx);
        assert_eq!(
            second.get("height").as_u64(),
            Some(999_999),
            "the handler must answer from the cache"
        );
    }

    /// A mempool change must invalidate it.
    #[test]
    fn a_mempool_change_invalidates_the_cache() {
        use alloc::sync::Arc as StdArc;
        use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, TxIn, TxOut, Witness};

        let ctx = context_with_chain(Network::Regtest, now_seconds());
        let _first = template(&ctx);
        {
            let mut cache = ctx.mining_template_cache.write();
            let Some(entry) = cache.as_mut() else {
                panic!("the first call must have populated the cache");
            };
            entry.template.height = 999_999;
        }

        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::new(bitcoin::Txid::from_byte_array([3_u8; 32]), 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let vsize = u32::try_from(tx.vsize()).unwrap_or(u32::MAX);
        let entry = bitcoin_rs_mempool::MempoolEntry::new(StdArc::new(tx), vsize, 10_000, 0, 0);
        ctx.mempool
            .write()
            .insert_entry(entry)
            .unwrap_or_else(|err| panic!("insert_entry failed: {err}"));

        let second = template(&ctx);
        assert_ne!(
            second.get("height").as_u64(),
            Some(999_999),
            "a changed mempool must force a fresh template"
        );
    }

    /// Core refuses to build a template on a chain it has not caught up with.
    #[test]
    fn a_stale_mainnet_tip_is_refused() {
        let ctx = context_with_chain(Network::Mainnet, 1_231_006_505);
        ctx.peers.write().push(peer());

        let Err(error) = getblocktemplate(&ctx, &json!([{"rules": ["segwit"]}])) else {
            panic!("a node whose tip is from 2009 must not serve a template");
        };
        assert_eq!(error.code(), RpcError::CORE_CLIENT_IN_INITIAL_DOWNLOAD);

        // The same node with a current tip answers, so the refusal above is
        // the tip age and not something else about mainnet.
        let caught_up = context_with_chain(Network::Mainnet, now_seconds());
        caught_up.peers.write().push(peer());
        assert!(getblocktemplate(&caught_up, &json!([{"rules": ["segwit"]}])).is_ok());
    }

    fn peer() -> bitcoin_rs_p2p::PeerInfo {
        bitcoin_rs_p2p::PeerInfo {
            addr: "127.0.0.1:8333".parse().unwrap_or_else(|err| {
                panic!("the fixture address must parse: {err}");
            }),
            version: 70_016,
            inbound: false,
            services: 0,
            user_agent: String::new(),
            start_height: 0,
            conn_time: 0,
        }
    }

    use bitcoin::hex::DisplayHex as _;

    /// A validator that records what it was handed and answers as configured.
    #[derive(Debug)]
    struct StubValidator {
        calls: core::sync::atomic::AtomicUsize,
        verdict: Result<(), crate::context::BlockRejectReason>,
    }

    impl StubValidator {
        fn new(verdict: Result<(), crate::context::BlockRejectReason>) -> Arc<Self> {
            Arc::new(Self {
                calls: core::sync::atomic::AtomicUsize::new(0),
                verdict,
            })
        }

        fn calls(&self) -> usize {
            self.calls.load(core::sync::atomic::Ordering::Acquire)
        }
    }

    impl crate::context::ChainControl for StubValidator {
        fn invalidate_block(
            &self,
            _hash: Hash256,
        ) -> Result<(), crate::context::ChainControlError> {
            Ok(())
        }

        fn test_block_validity(
            &self,
            _block: &bitcoin::Block,
        ) -> Result<(), crate::context::BlockRejectReason> {
            self.calls
                .fetch_add(1, core::sync::atomic::Ordering::AcqRel);
            self.verdict.clone()
        }
    }

    /// A block whose header names `previous` as its parent.
    ///
    /// Its contents do not matter to the handler: everything past the tip check
    /// is the validator's question, and these tests stub the validator so that
    /// the handler's own decisions are what fail.
    fn block_on(previous: BlockHash) -> bitcoin::Block {
        let coinbase = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: bitcoin::OutPoint::null(),
                script_sig: bitcoin::script::Builder::new()
                    .push_int(11)
                    .push_slice([0_u8; 4])
                    .into_script(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(50 * 100_000_000),
                script_pubkey: bitcoin::ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let mut block = bitcoin::Block {
            header: header(previous, 1_700_000_000, 7),
            txdata: vec![coinbase],
        };
        block.header.merkle_root = block
            .compute_merkle_root()
            .unwrap_or_else(|| panic!("a one-transaction block always has a merkle root"));
        block
    }

    fn control(validator: &Arc<StubValidator>) -> Arc<dyn crate::context::ChainControl> {
        let cloned: Arc<StubValidator> = Arc::clone(validator);
        cloned
    }

    fn proposal_params(block: &bitcoin::Block) -> sonic_rs::Value {
        let hex = bitcoin::consensus::encode::serialize(block).to_lower_hex_string();
        json!([{"mode": "proposal", "data": hex}])
    }

    fn tip_hash(ctx: &Context) -> BlockHash {
        BlockHash::from_byte_array(ctx.applied_hash().to_le_bytes())
    }

    /// A valid proposal answers `null`, which is what BIP22 calls acceptance.
    #[test]
    fn a_valid_proposal_answers_null() -> Result<(), RpcError> {
        let validator = StubValidator::new(Ok(()));
        let ctx = context_with_chain_and_control(
            Network::Regtest,
            1_700_000_000,
            Some(control(&validator)),
        );
        let block = block_on(tip_hash(&ctx));

        let answer = getblocktemplate(&ctx, &proposal_params(&block))?;

        assert!(
            answer.is_null(),
            "a valid proposal answers null: {answer:?}"
        );
        assert_eq!(
            validator.calls(),
            1,
            "the proposal must reach the validator exactly once"
        );
        Ok(())
    }

    /// A refused proposal answers with the reason, not with an RPC error.
    #[test]
    fn a_refused_proposal_answers_with_the_reject_reason() -> Result<(), RpcError> {
        let validator = StubValidator::new(Err(crate::context::BlockRejectReason(
            "bad-cb-amount".to_owned(),
        )));
        let ctx = context_with_chain_and_control(
            Network::Regtest,
            1_700_000_000,
            Some(control(&validator)),
        );
        let block = block_on(tip_hash(&ctx));

        let answer = getblocktemplate(&ctx, &proposal_params(&block))?;

        assert_eq!(answer.as_str(), Some("bad-cb-amount"));
        Ok(())
    }

    /// A block the node already holds is a duplicate, and which duplicate it is
    /// depends on how far the node got with it.
    ///
    /// The `HeaderValid` case hangs off an earlier block rather than the tip:
    /// a child of the tip carries the most work, so the tree publishes it as
    /// the active tip and the status under test would not survive insertion.
    /// `Stale` shares its answer with `Active` and is not separately reachable
    /// without driving a reorg through the fixture.
    #[test]
    fn a_proposal_the_node_already_holds_is_a_duplicate() -> Result<(), RpcError> {
        for (status, expected, on_tip) in [
            (NodeStatus::Active, "duplicate", true),
            (NodeStatus::Invalid, "duplicate-invalid", true),
            (NodeStatus::HeaderValid, "duplicate-inconclusive", false),
        ] {
            let validator = StubValidator::new(Ok(()));
            let ctx = context_with_chain_and_control(
                Network::Regtest,
                1_700_000_000,
                Some(control(&validator)),
            );
            let (parent, parent_hash) = {
                let tree = ctx.block_tree.read();
                let node = if on_tip {
                    tree.active_node_at_height(10)
                } else {
                    tree.active_node_at_height(3)
                };
                let node = node.unwrap_or_else(|| panic!("the fixture builds eleven blocks"));
                let id = tree
                    .lookup(node.hash)
                    .unwrap_or_else(|| panic!("a node the tree returned must be findable"));
                (id, BlockHash::from_byte_array(node.hash.to_le_bytes()))
            };
            let block = block_on(parent_hash);
            ctx.block_tree
                .write()
                .insert_node(Some(parent), block.header, status)
                .unwrap_or_else(|err| panic!("insert_node failed: {err}"));

            let answer = getblocktemplate(&ctx, &proposal_params(&block))?;

            assert_eq!(
                answer.as_str(),
                Some(expected),
                "a {status:?} block must answer {expected}"
            );
            assert_eq!(
                validator.calls(),
                0,
                "a block the node already holds must not be revalidated"
            );
        }
        Ok(())
    }

    /// A proposal built on anything but the tip cannot be answered.
    ///
    /// The UTXO set this node can weigh a block against is the one at its own
    /// tip, so the honest answer is that the question is inconclusive -- not
    /// that the block is invalid.
    #[test]
    fn a_proposal_that_does_not_build_on_the_tip_is_inconclusive() -> Result<(), RpcError> {
        let validator = StubValidator::new(Ok(()));
        let ctx = context_with_chain_and_control(
            Network::Regtest,
            1_700_000_000,
            Some(control(&validator)),
        );
        let block = block_on(BlockHash::from_byte_array([0x33; 32]));

        let answer = getblocktemplate(&ctx, &proposal_params(&block))?;

        assert_eq!(answer.as_str(), Some("inconclusive-not-best-prevblk"));
        assert_eq!(
            validator.calls(),
            0,
            "a proposal for another tip must not be validated against this one"
        );
        Ok(())
    }

    /// A proposal is a question about one block, so the rule handshake that
    /// guards template requests does not apply to it.
    ///
    /// Core answers proposals before it reads `rules`, and a proposal carries a
    /// finished block: there is nothing for the miner to opt into.
    #[test]
    fn a_proposal_is_answered_without_the_rules_handshake() -> Result<(), RpcError> {
        let validator = StubValidator::new(Ok(()));
        let ctx = context_with_chain_and_control(
            Network::Regtest,
            1_700_000_000,
            Some(control(&validator)),
        );
        let block = block_on(tip_hash(&ctx));

        // No `rules` key at all: a template request with this shape is refused.
        let answer = getblocktemplate(&ctx, &proposal_params(&block))?;

        assert!(answer.is_null(), "got {answer:?}");
        Ok(())
    }

    /// Missing `data` is a type error, as it is in Core.
    #[test]
    fn a_proposal_without_data_is_a_type_error() {
        let ctx = context_with_chain(Network::Regtest, 1_700_000_000);
        let error = getblocktemplate(&ctx, &json!([{"mode": "proposal"}]))
            .err()
            .unwrap_or_else(|| panic!("a proposal with no data must be refused"));
        assert_eq!(error.code(), RpcError::CORE_INVALID_TYPE);
    }

    /// Data that is not a block is a decode error, not an invalid block.
    ///
    /// Both halves of the decode are covered: `zz` is not hexadecimal at all,
    /// and `deadbeef` is perfectly good hexadecimal that is not a block. They
    /// fail on different lines and must answer the same way.
    #[test]
    fn a_proposal_whose_data_is_not_a_block_is_a_decode_error() {
        let ctx = context_with_chain(Network::Regtest, 1_700_000_000);
        for data in ["zz", "deadbeef"] {
            let error = getblocktemplate(&ctx, &json!([{"mode": "proposal", "data": data}]))
                .err()
                .unwrap_or_else(|| panic!("undecodable data must be refused: {data}"));
            assert_eq!(
                error.code(),
                RpcError::CORE_DESERIALIZATION_ERROR,
                "for {data}"
            );
        }
    }

    /// With no validator installed the node says so rather than approving.
    ///
    /// Answering `null` here would tell a miner the block is valid on the
    /// authority of nothing having been checked.
    #[test]
    fn a_proposal_is_refused_when_no_validator_is_installed() {
        let ctx = context_with_chain(Network::Regtest, 1_700_000_000);
        let block = block_on(tip_hash(&ctx));
        let error = getblocktemplate(&ctx, &proposal_params(&block))
            .err()
            .unwrap_or_else(|| panic!("a node with no validator must refuse the proposal"));
        assert!(matches!(error, RpcError::MethodDisabled(_)), "{error:?}");
    }

    /// BIP23 asks a server to name what it can be asked to do.
    #[test]
    fn the_template_advertises_the_proposal_capability() -> Result<(), RpcError> {
        let ctx = context_with_chain(Network::Regtest, 1_700_000_000);
        let template = getblocktemplate(&ctx, &json!([{"rules": ["segwit"]}]))?;
        let capabilities = template
            .get("capabilities")
            .and_then(sonic_rs::JsonContainerTrait::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(sonic_rs::JsonValueTrait::as_str)
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        assert!(
            capabilities.iter().any(|value| value == "proposal"),
            "capabilities must name proposal, got {capabilities:?}"
        );
        Ok(())
    }
}
