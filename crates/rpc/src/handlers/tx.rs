use alloc::sync::Arc;
use core::str::FromStr as _;

use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hex::{DisplayHex as _, FromHex as _};
use bitcoin::merkle_tree::MerkleBlock;
use bitcoin::{Amount, Transaction, Txid};
use bitcoin_rs_primitives::Hash256;
use serde_json::json as serde_json_value;
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait, Value, json};

use crate::context::Context;
use crate::error::RpcError;
use crate::handlers::{optional_bool, params_array, required_str, required_u64, serde_to_sonic};

pub(crate) fn getrawtransaction(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let txid = parse_txid(required_str(params, 0, "txid is required")?)?;
    let verbose = optional_bool(params, 1, false)?;
    {
        let transactions = ctx.transactions.read();
        if let Some(tx) = transactions.get(&txid) {
            if !verbose {
                return Ok(json!(serialize(tx).to_lower_hex_string()));
            }
            return tx_to_value(tx);
        }
    }
    {
        let pool = ctx.mempool.read();
        if let Some(id) = pool.by_txid.get(&txid) {
            if let Some(entry) = pool.entry(*id) {
                let tx = entry.tx.as_ref();
                if !verbose {
                    return Ok(json!(serialize(tx).to_lower_hex_string()));
                }
                return tx_to_value(tx);
            }
        }
    }
    Err(RpcError::NotFound("transaction not found"))
}

pub(crate) fn gettxout(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let txid = parse_txid(required_str(params, 0, "txid is required")?)?;
    let vout = required_u64(params, 1, "vout is required")?;
    let vout = usize::try_from(vout).map_err(|_| RpcError::InvalidParams("vout exceeds usize"))?;
    let transactions = ctx.transactions.read();
    let Some(tx) = transactions.get(&txid) else {
        return Ok(Value::new_null());
    };
    let Some(output) = tx.output.get(vout) else {
        return Ok(Value::new_null());
    };
    Ok(json!({
        "bestblock": ctx.best_hash().to_string_be(),
        "confirmations": 0,
        "value": btc_value(output.value.to_sat()),
        "scriptPubKey": {
            "asm": "",
            "desc": "raw()",
            "hex": output.script_pubkey.as_bytes().to_lower_hex_string(),
            "type": "nonstandard"
        },
        "coinbase": false
    }))
}

pub(crate) fn gettxoutproof(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let array = params_array(params)?;
    let txids_value = array
        .first()
        .and_then(|value| value.as_array())
        .ok_or(RpcError::InvalidParams("txids must be an array"))?;
    if txids_value.is_empty() {
        return Err(RpcError::InvalidParams("txids are required"));
    }

    let mut wanted = hashbrown::HashSet::new();
    for value in txids_value {
        let Some(txid) = value.as_str() else {
            return Err(RpcError::InvalidType("each txid must be a string"));
        };
        wanted.insert(parse_txid(txid)?);
    }

    let blocks = ctx.blocks.read();
    for record in blocks.iter() {
        let Ok(bytes) = Vec::<u8>::from_hex(&record.block_hex) else {
            continue;
        };
        let Ok(block) = deserialize::<bitcoin::Block>(&bytes) else {
            continue;
        };
        let block_txids = block
            .txdata
            .iter()
            .map(bitcoin::Transaction::compute_txid)
            .collect::<hashbrown::HashSet<Txid>>();
        if !wanted.iter().all(|txid| block_txids.contains(txid)) {
            continue;
        }

        let merkle_block =
            MerkleBlock::from_block_with_predicate(&block, |txid| wanted.contains(txid));
        return Ok(json!(serialize(&merkle_block).to_lower_hex_string()));
    }

    Err(RpcError::NotFound("no block contains all requested txids"))
}

pub(crate) fn verifytxoutproof(_ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let proof_hex = required_str(params, 0, "proof is required")?;
    let bytes = Vec::<u8>::from_hex(proof_hex)
        .map_err(|_| RpcError::InvalidParams("proof must be valid hex"))?;
    let Ok(merkle_block) = deserialize::<MerkleBlock>(&bytes) else {
        return Ok(json!([]));
    };

    let mut matched_txids = Vec::new();
    let mut indexes = Vec::new();
    if merkle_block
        .extract_matches(&mut matched_txids, &mut indexes)
        .is_err()
    {
        return Ok(json!([]));
    }

    let result = matched_txids
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    Ok(json!(result))
}

pub(crate) fn sendrawtransaction(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let raw = required_str(params, 0, "raw transaction is required")?;
    let tx = decode_tx(raw)?;
    let txid = ctx.add_transaction(tx);
    Ok(json!(txid.to_string()))
}

pub(crate) fn testmempoolaccept(_ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let raw_txs = params_array(params)?
        .first()
        .and_then(|value| value.as_array())
        .ok_or(RpcError::InvalidParams("raw transaction array is required"))?;
    let mut rows = Vec::with_capacity(raw_txs.len());
    for raw in raw_txs {
        let Some(raw) = raw.as_str() else {
            return Err(RpcError::InvalidType("raw transaction must be a string"));
        };
        let decoded = decode_tx(raw);
        let txid = decoded.as_ref().map_or_else(
            |_| Hash256::default().to_string_be(),
            |tx| tx.compute_txid().to_string(),
        );
        rows.push(json!({
            "txid": txid,
            "wtxid": txid,
            "allowed": decoded.is_ok(),
            "vsize": decoded.as_ref().map_or(0, Transaction::vsize),
            "fees": {"base": 0.0}
        }));
    }
    Ok(json!(rows))
}

pub(crate) fn decoderawtransaction(_ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let raw = required_str(params, 0, "raw transaction is required")?;
    let tx = decode_tx(raw)?;
    tx_to_value(&tx)
}

fn decode_tx(raw: &str) -> Result<Transaction, RpcError> {
    let bytes = Vec::<u8>::from_hex(raw)?;
    deserialize(&bytes).map_err(|_| RpcError::InvalidParams("transaction decode failed"))
}

fn parse_txid(value: &str) -> Result<Txid, RpcError> {
    Txid::from_str(value).map_err(|_| RpcError::InvalidParams("txid must be 64 hex characters"))
}

fn tx_to_value(tx: &Transaction) -> Result<Value, RpcError> {
    let txid = tx.compute_txid().to_string();
    let size = usize_to_u64(serialize(tx).len())?;
    let vsize = usize_to_u64(tx.vsize())?;
    let weight = tx.weight().to_wu();
    let vin = tx
        .input
        .iter()
        .map(|input| {
            serde_json_value!({
                "txid": input.previous_output.txid.to_string(),
                "vout": input.previous_output.vout,
                "scriptSig": {"asm": "", "hex": input.script_sig.as_bytes().to_lower_hex_string()},
                "sequence": input.sequence.to_consensus_u32(),
                "txinwitness": []
            })
        })
        .collect::<Vec<_>>();
    let vout = tx
        .output
        .iter()
        .enumerate()
        .map(|(index, output)| {
            serde_json_value!({
                "value": btc_value(output.value.to_sat()),
                "n": index,
                "scriptPubKey": {
                    "asm": "",
                    "desc": "raw()",
                    "hex": output.script_pubkey.as_bytes().to_lower_hex_string(),
                    "type": "nonstandard"
                }
            })
        })
        .collect::<Vec<_>>();
    let value = serde_json_value!({
        "txid": txid,
        "hash": tx.compute_wtxid().to_string(),
        "version": tx.version.0,
        "size": size,
        "vsize": vsize,
        "weight": weight,
        "locktime": tx.lock_time.to_consensus_u32(),
        "vin": vin,
        "vout": vout,
        "hex": serialize(tx).to_lower_hex_string()
    });
    serde_to_sonic(&value)
}

fn usize_to_u64(value: usize) -> Result<u64, RpcError> {
    u64::try_from(value).map_err(|_| RpcError::Internal("usize does not fit u64".to_owned()))
}

fn btc_value(sats: u64) -> f64 {
    Amount::from_sat(sats).to_btc()
}
#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use bitcoin::blockdata::constants::genesis_block;
    use bitcoin::consensus::encode::serialize;
    use bitcoin::hex::DisplayHex as _;
    use bitcoin_rs_mempool::MempoolEntry;
    use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, json};

    use super::getrawtransaction;
    use crate::Handler;
    use crate::context::{BlockRecord, Context};
    use crate::error::RpcError;

    #[test]
    fn getrawtransaction_falls_back_to_mempool_for_unconfirmed()
    -> Result<(), Box<dyn std::error::Error>> {
        let ctx = Arc::new(Context::new());
        let genesis = genesis_block(bitcoin::Network::Regtest);
        let coinbase = genesis
            .txdata
            .first()
            .ok_or_else(|| RpcError::Internal("genesis has no transactions".to_owned()))?
            .clone();
        let txid = coinbase.compute_txid();
        {
            let mut pool = ctx.mempool.write();
            let entry = MempoolEntry::new(
                Arc::new(coinbase.clone()),
                u32::try_from(coinbase.vsize())?,
                0,
                0,
                0,
            );
            pool.insert_entry(entry)?;
        }

        let result = getrawtransaction(&ctx, &json!([txid.to_string()]))?;

        let expected = serialize(&coinbase).to_lower_hex_string();
        assert_eq!(result.as_str(), Some(expected.as_str()));
        Ok(())
    }

    #[test]
    fn gettxoutproof_finds_genesis_coinbase() {
        let ctx = Arc::new(Context::new());
        let genesis = genesis_block(bitcoin::Network::Regtest);
        let Some(coinbase) = genesis.txdata.first() else {
            panic!("genesis has no transactions");
        };
        let txid = coinbase.compute_txid();
        ctx.add_block(BlockRecord::from_block(0, &genesis));
        let handler = Handler::new(Arc::clone(&ctx));
        let result = handler
            .dispatch("gettxoutproof", &json!([[txid.to_string()]]))
            .unwrap_or_else(|err| panic!("gettxoutproof failed: {err}"));
        let Some(proof_hex) = result.as_str() else {
            panic!("expected string, got {result:?}");
        };

        let extracted = handler
            .dispatch("verifytxoutproof", &json!([proof_hex]))
            .unwrap_or_else(|err| panic!("verifytxoutproof failed: {err}"));
        let Some(arr) = extracted.as_array() else {
            panic!("expected array, got {extracted:?}");
        };
        assert_eq!(arr.len(), 1);
    }
}
