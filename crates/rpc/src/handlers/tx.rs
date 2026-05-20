use alloc::sync::Arc;
use core::str::FromStr as _;

use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hashes::Hash as _;
use bitcoin::hex::{DisplayHex as _, FromHex as _};
use bitcoin::merkle_tree::MerkleBlock;
use bitcoin::{Transaction, Txid};
use bitcoin_rs_primitives::{Hash256, OutPoint};
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait, Value, json};

use crate::context::Context;
use crate::error::RpcError;
use crate::handlers::{optional_bool, params_array, required_str, required_u64};

pub(crate) fn getrawtransaction(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let txid = parse_txid(required_str(params, 0, "txid is required")?)?;
    let verbose = optional_bool(params, 1, false)?;
    let blockhash_str = params_array(params)?
        .get(2)
        .and_then(JsonValueTrait::as_str);
    if let Some(hash_str) = blockhash_str {
        let hash = Hash256::from_str(hash_str)
            .map_err(|_| RpcError::InvalidParams("blockhash must be 64 hex characters"))?;
        let Some(record) = ctx.block_by_hash(hash) else {
            return Err(RpcError::NotFound("block not found"));
        };
        if record.block_hex.is_empty() {
            return Err(RpcError::NotFound("block data pruned"));
        }
        let bytes = Vec::<u8>::from_hex(&record.block_hex)
            .map_err(|_| RpcError::Internal("stored block hex is corrupt".to_owned()))?;
        let block: bitcoin::Block = deserialize(&bytes)
            .map_err(|_| RpcError::Internal("stored block bytes failed decode".to_owned()))?;
        for tx in &block.txdata {
            if tx.compute_txid() == txid {
                if !verbose {
                    return Ok(json!(serialize(tx).to_lower_hex_string()));
                }
                return super::tx_render::tx_to_value(tx);
            }
        }
        return Err(RpcError::NotFound("transaction not in specified block"));
    }
    {
        let transactions = ctx.transactions.read();
        if let Some(tx) = transactions.get(&txid) {
            if !verbose {
                return Ok(json!(serialize(tx).to_lower_hex_string()));
            }
            return super::tx_render::tx_to_value(tx);
        }
    }
    {
        let pool = ctx.mempool.read();
        if let Some(entry) = pool.entry_by_txid(&txid) {
            let tx = entry.tx.as_ref();
            if !verbose {
                return Ok(json!(serialize(tx).to_lower_hex_string()));
            }
            return super::tx_render::tx_to_value(tx);
        }
    }
    Err(RpcError::NotFound("transaction not found"))
}

fn classify_script(script: &bitcoin::Script) -> &'static str {
    if script.is_p2tr() {
        "witness_v1_taproot"
    } else if script.is_p2wsh() {
        "witness_v0_scripthash"
    } else if script.is_p2wpkh() {
        "witness_v0_keyhash"
    } else if script.is_p2sh() {
        "scripthash"
    } else if script.is_p2pkh() {
        "pubkeyhash"
    } else if script.is_p2pk() {
        "pubkey"
    } else if script.is_op_return() {
        "nulldata"
    } else {
        "nonstandard"
    }
}

fn script_to_address(
    script: &bitcoin::Script,
    chain_network: bitcoin_rs_primitives::Network,
) -> Option<String> {
    let network = match chain_network {
        bitcoin_rs_primitives::Network::Mainnet => bitcoin::Network::Bitcoin,
        bitcoin_rs_primitives::Network::Testnet3 => bitcoin::Network::Testnet,
        bitcoin_rs_primitives::Network::Testnet4 => bitcoin::Network::Testnet4,
        bitcoin_rs_primitives::Network::Signet => bitcoin::Network::Signet,
        bitcoin_rs_primitives::Network::Regtest => bitcoin::Network::Regtest,
    };
    bitcoin::Address::from_script(script, network)
        .ok()
        .map(|address| address.to_string())
}

pub(crate) fn gettxout(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let txid = parse_txid(required_str(params, 0, "txid is required")?)?;
    let vout = required_u64(params, 1, "vout is required")?;
    let vout_u32 = u32::try_from(vout).map_err(|_| RpcError::InvalidParams("vout exceeds u32"))?;
    let outpoint = OutPoint::new(Hash256::from_le_bytes(txid.as_byte_array()), vout_u32);
    let Some(live) = ctx.utxo.get_entry(&outpoint) else {
        // Spent or never existed: Core-spec returns JSON null.
        return Ok(Value::new_null());
    };
    let applied = ctx.applied_height();
    let confirmations = applied.saturating_sub(live.height).saturating_add(1);
    let script_hex = live.txout.script_pubkey.as_bytes().to_lower_hex_string();
    let address = script_to_address(&live.txout.script_pubkey, ctx.chain_network);
    let desc = address.as_deref().map_or_else(
        || format!("raw({script_hex})"),
        |addr| format!("addr({addr})"),
    );
    let mut script_pubkey = json!({
        "asm": live.txout.script_pubkey.to_asm_string(),
        "desc": desc,
        "hex": script_hex,
        "type": classify_script(&live.txout.script_pubkey)
    });
    if let Some(addr) = address {
        let _ = script_pubkey.insert("address", json!(addr));
    }
    Ok(json!({
        "bestblock": ctx.best_hash().to_string_be(),
        "confirmations": confirmations,
        "value": super::tx_render::btc_value(live.txout.value.to_sat()),
        "scriptPubKey": script_pubkey,
        "coinbase": live.coinbase
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
    let mut saw_pruned_block = false;
    for record in blocks.iter() {
        if record.block_hex.is_empty() {
            saw_pruned_block = true;
            continue;
        }
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

    if saw_pruned_block {
        Err(RpcError::NotFound("block data pruned"))
    } else {
        Err(RpcError::NotFound("no block contains all requested txids"))
    }
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
    super::tx_render::tx_to_value(&tx)
}

fn decode_tx(raw: &str) -> Result<Transaction, RpcError> {
    let bytes = Vec::<u8>::from_hex(raw)?;
    deserialize(&bytes).map_err(|_| RpcError::InvalidParams("transaction decode failed"))
}

fn parse_txid(value: &str) -> Result<Txid, RpcError> {
    Txid::from_str(value).map_err(|_| RpcError::InvalidParams("txid must be 64 hex characters"))
}

#[cfg(test)]
mod tests {
    use alloc::sync::Arc;

    use bitcoin::blockdata::constants::genesis_block;
    use bitcoin::consensus::encode::serialize;
    use bitcoin::hashes::Hash as _;
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
            let vsize = u32::try_from(coinbase.vsize())?;
            let entry =
                MempoolEntry::new(Arc::new(coinbase.clone()), vsize, u64::from(vsize), 0, 0);
            pool.insert_entry(entry)?;
        }

        let result = getrawtransaction(&ctx, &json!([txid.to_string()]))?;

        let expected = serialize(&coinbase).to_lower_hex_string();
        assert_eq!(result.as_str(), Some(expected.as_str()));
        Ok(())
    }

    #[test]
    fn getrawtransaction_with_blockhash_finds_tx_in_specific_block() {
        let ctx = Arc::new(Context::new());
        let genesis = genesis_block(bitcoin::Network::Regtest);
        let Some(coinbase) = genesis.txdata.first() else {
            panic!("genesis has no transactions");
        };
        let txid = coinbase.compute_txid();
        let block_hash =
            bitcoin_rs_primitives::Hash256::from_le_bytes(genesis.block_hash().as_byte_array());
        ctx.add_block(BlockRecord::from_block(0, &genesis));
        let handler = Handler::new(Arc::clone(&ctx));
        let result = handler
            .dispatch(
                "getrawtransaction",
                &json!([txid.to_string(), false, block_hash.to_string_be()]),
            )
            .unwrap_or_else(|err| panic!("getrawtransaction with blockhash: {err}"));
        assert!(result.is_str(), "expected hex string, got {result:?}");
    }

    #[test]
    fn getrawtransaction_with_blockhash_reports_pruned_block_body() {
        let ctx = Arc::new(Context::new());
        let genesis = genesis_block(bitcoin::Network::Regtest);
        let Some(coinbase) = genesis.txdata.first() else {
            panic!("genesis has no transactions");
        };
        let txid = coinbase.compute_txid();
        let mut record = BlockRecord::from_block(0, &genesis);
        let block_hash = record.hash;
        record.block_hex.clear();
        ctx.add_block(record);

        let result = getrawtransaction(
            &ctx,
            &json!([txid.to_string(), false, block_hash.to_string_be()]),
        );

        assert!(matches!(
            result,
            Err(RpcError::NotFound("block data pruned"))
        ));
    }

    #[test]
    fn getrawtransaction_with_unknown_blockhash_errors() {
        let ctx = Arc::new(Context::new());
        let handler = Handler::new(Arc::clone(&ctx));
        let bogus_hash = bitcoin_rs_primitives::Hash256::from_le_bytes(&[7_u8; 32]).to_string_be();
        let result = handler.dispatch(
            "getrawtransaction",
            &json!([
                "0000000000000000000000000000000000000000000000000000000000000000",
                false,
                bogus_hash
            ]),
        );
        assert!(result.is_err());
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

    #[test]
    fn gettxoutproof_skips_pruned_blocks_before_matching_block() {
        let ctx = Arc::new(Context::new());
        let genesis = genesis_block(bitcoin::Network::Regtest);
        let Some(coinbase) = genesis.txdata.first() else {
            panic!("genesis has no transactions");
        };
        let txid = coinbase.compute_txid();
        let mut pruned_genesis = BlockRecord::from_block(0, &genesis);
        pruned_genesis.block_hex.clear();
        ctx.add_block(pruned_genesis);
        ctx.add_block(BlockRecord::from_block(0, &genesis));
        let handler = Handler::new(Arc::clone(&ctx));

        let result = handler.dispatch("gettxoutproof", &json!([[txid.to_string()]]));

        assert!(
            result.as_ref().is_ok_and(|value| value.as_str().is_some()),
            "gettxoutproof should skip pruned blocks before matching retained blocks: {result:?}"
        );
    }
}

#[cfg(test)]
mod classify_script_tests {
    use super::*;
    use bitcoin::ScriptBuf;

    #[test]
    fn classify_op_return_is_nulldata() {
        let script = ScriptBuf::new_op_return(b"hello");
        assert_eq!(classify_script(&script), "nulldata");
    }

    #[test]
    fn classify_empty_is_nonstandard() {
        let script = ScriptBuf::new();
        assert_eq!(classify_script(&script), "nonstandard");
    }

    #[test]
    fn script_to_address_returns_some_for_p2wpkh_on_mainnet() {
        use bitcoin::hex::FromHex as _;

        let script_hex = "00141111111111111111111111111111111111111111";
        let bytes = match Vec::<u8>::from_hex(script_hex) {
            Ok(bytes) => bytes,
            Err(error) => panic!("hex: {error}"),
        };
        let script = ScriptBuf::from_bytes(bytes);

        let address = script_to_address(&script, bitcoin_rs_primitives::Network::Mainnet);

        assert!(
            address.is_some(),
            "P2WPKH script must yield mainnet bech32 address"
        );
        let Some(addr) = address else {
            panic!("address");
        };
        assert!(
            addr.starts_with("bc1"),
            "mainnet P2WPKH should bech32-encode with bc1 prefix: {addr}"
        );
    }

    #[test]
    fn script_to_address_returns_none_for_nonstandard_script() {
        let script = ScriptBuf::new();

        assert!(script_to_address(&script, bitcoin_rs_primitives::Network::Mainnet).is_none());
    }
}
#[cfg(test)]
mod gettxout_via_utxo_tests {
    use super::*;

    #[test]
    fn gettxout_returns_null_for_unknown_outpoint() {
        let ctx = Arc::new(Context::new());
        let txid_hex = "a".repeat(64);
        let params = json!([txid_hex.as_str(), 0_u64]);
        let value = gettxout(&ctx, &params).unwrap_or_else(|err| panic!("gettxout failed: {err}"));
        assert!(
            value.is_null(),
            "expected null for unknown outpoint, got {value:?}"
        );
    }

    #[test]
    fn gettxout_returns_null_for_transaction_output_absent_from_utxo() {
        let ctx = Arc::new(Context::new());
        let tx = bitcoin::Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: Vec::new(),
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(50_000),
                script_pubkey: bitcoin::ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        let txid = ctx.add_transaction(tx);
        let params = json!([txid.to_string(), 0_u64]);
        let value = gettxout(&ctx, &params).unwrap_or_else(|err| panic!("gettxout failed: {err}"));
        assert!(
            value.is_null(),
            "expected null for output absent from UTXO set, got {value:?}"
        );
    }
}
