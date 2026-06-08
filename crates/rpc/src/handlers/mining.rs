use alloc::sync::Arc;
use core::time::Duration;

use sonic_rs::{JsonValueTrait, Value, json};

use crate::context::Context;
use crate::error::RpcError;
use crate::handlers::{ensure_no_params, params_array, required_str};

const NETWORK_HASHPS_WINDOW: u32 = 120;

pub(crate) fn getblocktemplate(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    if !params.is_null() {
        let request = params_array(params)?.first();
        if let Some(request) = request {
            if let Some(longpollid) = request.get("longpollid").and_then(|value| value.as_str()) {
                let current = ctx.mining_template_id.load();
                if longpollid == current.as_str() {
                    let _result = ctx
                        .mining_notifications
                        .recv_timeout(Duration::from_mins(1));
                }
            }
        }
    }
    let tip_hash = ctx.best_hash().to_string_be();
    let template_id = ctx.mining_template_id.load().to_string();
    Ok(json!({
        "version": 0,
        "rules": ["segwit"],
        "vbavailable": {},
        "vbrequired": 0,
        "previousblockhash": tip_hash,
        "transactions": [],
        "coinbaseaux": {},
        "coinbasevalue": 0,
        "longpollid": template_id,
        "target": "0000000000000000000000000000000000000000000000000000000000000000",
        "mintime": 0,
        "mutable": ["time", "transactions", "prevblock"],
        "noncerange": "00000000ffffffff",
        "sigoplimit": 0,
        "sizelimit": 4_000_000,
        "weightlimit": 4_000_000,
        "curtime": 0,
        "bits": "00000000",
        "height": ctx.height().saturating_add(1),
        "default_witness_commitment": ""
    }))
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

    let policy = bitcoin_rs_mining::MiningPolicy;
    let pool = ctx.mempool.read();
    let selected = policy.select_transactions(&pool, MAX_BLOCK_WEIGHT);
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
    use bitcoin::hex::DisplayHex as _;

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
