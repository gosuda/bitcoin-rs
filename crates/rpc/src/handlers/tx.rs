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
        let Some(bytes) = ctx.block_body_bytes(&record) else {
            return Err(RpcError::NotFound("block data pruned"));
        };
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
    if let Some(tx_index) = ctx.tx_index.as_ref() {
        match tx_index.transaction(&txid) {
            Ok(Some(tx)) => {
                if !verbose {
                    return Ok(json!(serialize(&tx).to_lower_hex_string()));
                }
                return super::tx_render::tx_to_value(&tx);
            }
            Ok(None) => {}
            Err(error) => return Err(error.into_rpc_error()),
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
    // Bitcoin Core's third argument, defaulting to true. It was being dropped,
    // so this RPC answered from the confirmed set only and could not see any
    // unconfirmed activity at all.
    let include_mempool = optional_bool(params, 2, true)?;

    if include_mempool {
        let mempool_outpoint = bitcoin::OutPoint {
            txid,
            vout: vout_u32,
        };
        let pool = ctx.mempool.read();
        // Core: "an unspent output that is spent in the mempool won't appear".
        // The coin is still in the confirmed set, but a mempool transaction has
        // claimed it, so reporting it spendable would hand a caller a conflict.
        if pool.is_outpoint_spent(&mempool_outpoint) {
            return Ok(Value::new_null());
        }
        if let Some(tx) = pool.transaction_by_txid(&txid)
            && let Some(txout) = usize::try_from(vout_u32)
                .ok()
                .and_then(|index| tx.output.get(index))
        {
            // Core gives a mempool coin `MEMPOOL_HEIGHT`, which renders as zero
            // confirmations. A mempool transaction is never a coinbase.
            return Ok(txout_json(ctx, txout, 0, false));
        }
    }

    let outpoint = OutPoint::new(Hash256::from_le_bytes(txid.as_byte_array()), vout_u32);
    let Some(live) = ctx.utxo.get_entry(&outpoint) else {
        // Spent or never existed: Core-spec returns JSON null.
        return Ok(Value::new_null());
    };
    let applied = ctx.applied_height();
    let confirmations = applied.saturating_sub(live.height).saturating_add(1);
    Ok(txout_json(ctx, &live.txout, confirmations, live.coinbase))
}

/// Renders one output the way `gettxout` reports it.
///
/// Shared by the confirmed and mempool answers so the two cannot drift into
/// describing the same script differently.
fn txout_json(
    ctx: &Arc<Context>,
    txout: &bitcoin::TxOut,
    confirmations: u32,
    coinbase: bool,
) -> Value {
    let script_hex = txout.script_pubkey.as_bytes().to_lower_hex_string();
    let address = script_to_address(&txout.script_pubkey, ctx.chain_network);
    let desc = address.as_deref().map_or_else(
        || format!("raw({script_hex})"),
        |addr| format!("addr({addr})"),
    );
    let mut script_pubkey = json!({
        "asm": txout.script_pubkey.to_asm_string(),
        "desc": desc,
        "hex": script_hex,
        "type": classify_script(&txout.script_pubkey)
    });
    if let Some(addr) = address {
        let _ = script_pubkey.insert("address", json!(addr));
    }
    json!({
        "bestblock": ctx.best_hash().to_string_be(),
        "confirmations": confirmations,
        "value": super::tx_render::btc_value(txout.value.to_sat()),
        "scriptPubKey": script_pubkey,
        "coinbase": coinbase
    })
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

    let blocks = match array.get(1).and_then(JsonValueTrait::as_str) {
        Some(hash_str) => {
            let hash = Hash256::from_str(hash_str)
                .map_err(|_| RpcError::InvalidParams("blockhash must be 64 hex characters"))?;
            let Some(record) = ctx.block_by_hash(hash) else {
                return Err(RpcError::NotFound("block not found"));
            };
            vec![record]
        }
        None => ctx.blocks.read().clone(),
    };
    let mut saw_pruned_block = false;
    for record in &blocks {
        let Some(bytes) = ctx.block_body_bytes(record) else {
            saw_pruned_block = true;
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

    use bitcoin::consensus::encode::serialize;
    use bitcoin::hashes::Hash as _;
    use bitcoin::hex::DisplayHex as _;
    use bitcoin::{OutPoint, Txid};
    use bitcoin_rs_mempool::MempoolEntry;
    use bitcoin_rs_primitives::Hash256;
    use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, json};

    use super::getrawtransaction;
    use crate::Handler;
    use crate::context::{BlockRecord, Context, TxIndexQuery, TxQueryError};
    use crate::error::RpcError;

    fn genesis_block(network: bitcoin::Network) -> bitcoin::Block {
        bitcoin::blockdata::constants::genesis_block(network)
    }

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
    fn getrawtransaction_checks_mempool_before_failing_txindex()
    -> Result<(), Box<dyn std::error::Error>> {
        struct FailingQuery;

        impl TxIndexQuery for FailingQuery {
            fn transaction(
                &self,
                _txid: &Txid,
            ) -> Result<Option<bitcoin::Transaction>, TxQueryError> {
                Err(TxQueryError::Storage("disk full".into()))
            }

            fn outpoint_value(&self, _outpoint: &OutPoint) -> Result<Option<u64>, TxQueryError> {
                Ok(None)
            }

            fn index_info(&self) -> Result<crate::context::TxIndexInfo, TxQueryError> {
                Ok(crate::context::TxIndexInfo {
                    synced: false,
                    best_block_height: 0,
                })
            }
        }

        let mut ctx = Context::new();
        ctx.tx_index = Some(Arc::new(FailingQuery));
        let ctx = Arc::new(ctx);
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
    fn getrawtransaction_resolves_confirmed_transaction_from_txindex_without_cache() {
        struct StaticQuery {
            tx: bitcoin::Transaction,
        }

        impl TxIndexQuery for StaticQuery {
            fn transaction(
                &self,
                txid: &Txid,
            ) -> Result<Option<bitcoin::Transaction>, TxQueryError> {
                Ok((self.tx.compute_txid() == *txid).then(|| self.tx.clone()))
            }

            fn outpoint_value(&self, _outpoint: &OutPoint) -> Result<Option<u64>, TxQueryError> {
                Ok(None)
            }

            fn index_info(&self) -> Result<crate::context::TxIndexInfo, TxQueryError> {
                Ok(crate::context::TxIndexInfo {
                    synced: true,
                    best_block_height: 1,
                })
            }
        }

        let genesis = genesis_block(bitcoin::Network::Regtest);
        let Some(coinbase) = genesis.txdata.first().cloned() else {
            panic!("genesis has no transactions");
        };
        let txid = coinbase.compute_txid();
        let mut ctx = Context::new();
        ctx.tx_index = Some(Arc::new(StaticQuery {
            tx: coinbase.clone(),
        }));
        let ctx = Arc::new(ctx);

        assert!(
            ctx.transactions.read().is_empty(),
            "confirmed transaction cache must stay empty"
        );
        let result = getrawtransaction(&ctx, &json!([txid.to_string()]))
            .unwrap_or_else(|err| panic!("txindex lookup failed: {err}"));

        let expected = serialize(&coinbase).to_lower_hex_string();
        assert_eq!(result.as_str(), Some(expected.as_str()));
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

    #[test]
    fn gettxoutproof_with_blockhash_skips_unrelated_records() {
        struct PanicBodySource;

        impl crate::BlockBodySource for PanicBodySource {
            fn block_body(&self, height: u32, hash: Hash256) -> Option<Vec<u8>> {
                panic!("specified blockhash proof should not load unrelated body {height}:{hash}");
            }
        }

        let ctx = Arc::new(Context::new().with_block_body_source(Arc::new(PanicBodySource)));
        let genesis = genesis_block(bitcoin::Network::Regtest);
        let Some(coinbase) = genesis.txdata.first() else {
            panic!("genesis has no transactions");
        };
        let txid = coinbase.compute_txid();
        let unrelated_hash = Hash256::from_le_bytes(&[7_u8; 32]);
        ctx.add_block(BlockRecord::synthetic(0, unrelated_hash));
        let record = BlockRecord::from_block(1, &genesis);
        let block_hash = record.hash;
        ctx.add_block(record);
        let handler = Handler::new(Arc::clone(&ctx));

        let result = handler.dispatch(
            "gettxoutproof",
            &json!([[txid.to_string()], block_hash.to_string_be()]),
        );

        assert!(
            result.as_ref().is_ok_and(|value| value.as_str().is_some()),
            "gettxoutproof should inspect only the specified block: {result:?}"
        );
    }

    #[test]
    fn gettxoutproof_with_blockhash_reports_pruned_block_body() {
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
        let handler = Handler::new(Arc::clone(&ctx));

        let result = handler.dispatch(
            "gettxoutproof",
            &json!([[txid.to_string()], block_hash.to_string_be()]),
        );

        assert!(matches!(
            result,
            Err(RpcError::NotFound("block data pruned"))
        ));
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

#[cfg(test)]
mod gettxout_mempool_tests {
    use alloc::sync::Arc;

    use bitcoin::hashes::Hash as _;
    use bitcoin::{Amount, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
    use bitcoin_rs_mempool::MempoolEntry;
    use sonic_rs::{JsonValueTrait, json};

    use super::*;

    fn funding_tx(tag: u8) -> Transaction {
        Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: bitcoin::OutPoint::new(
                    bitcoin::Txid::from_byte_array([tag; 32]),
                    0,
                ),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(42_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        }
    }

    fn insert(ctx: &Arc<Context>, tx: Transaction) {
        let mut pool = ctx.mempool.write();
        let Ok(_id) = pool.insert_entry(MempoolEntry::new(Arc::new(tx), 100, 10_000, 1, 7)) else {
            panic!("fixture insert failed");
        };
    }

    fn gettxout_of(
        ctx: &Arc<Context>,
        txid: bitcoin::Txid,
        vout: u64,
        params_tail: &Value,
    ) -> Value {
        let mut params = vec![json!(txid.to_string()), json!(vout)];
        if let Some(flag) = params_tail.as_bool() {
            params.push(json!(flag));
        }
        gettxout(ctx, &json!(params)).unwrap_or_else(|err| panic!("gettxout failed: {err}"))
    }

    #[test]
    fn an_unconfirmed_output_is_reported_with_zero_confirmations() {
        let ctx = Arc::new(Context::new());
        let tx = funding_tx(0x11);
        let txid = tx.compute_txid();
        insert(&ctx, tx);

        let value = gettxout_of(&ctx, txid, 0, &Value::new_null());
        assert_eq!(
            value.get("confirmations").and_then(JsonValueTrait::as_u64),
            Some(0),
            "a mempool coin is Core's MEMPOOL_HEIGHT, which renders as zero: {value:?}"
        );
        assert_eq!(
            value.get("coinbase").and_then(JsonValueTrait::as_bool),
            Some(false),
            "a mempool transaction is never a coinbase"
        );
        assert!(value.get("value").is_number(), "{value:?}");
    }

    #[test]
    fn the_mempool_is_consulted_by_default_and_skipped_when_asked() {
        let ctx = Arc::new(Context::new());
        let tx = funding_tx(0x22);
        let txid = tx.compute_txid();
        insert(&ctx, tx);

        // Default is true, so omitting the argument must find it.
        assert!(!gettxout_of(&ctx, txid, 0, &Value::new_null()).is_null());
        assert!(!gettxout_of(&ctx, txid, 0, &json!(true)).is_null());
        // Explicitly false falls back to the confirmed set, which has nothing.
        assert!(
            gettxout_of(&ctx, txid, 0, &json!(false)).is_null(),
            "include_mempool=false must not see unconfirmed outputs"
        );
    }

    #[test]
    fn an_output_a_mempool_transaction_spends_stops_being_reported() {
        let ctx = Arc::new(Context::new());
        let parent = funding_tx(0x33);
        let parent_txid = parent.compute_txid();
        insert(&ctx, parent);

        // Before the spend exists, the parent's output is there.
        assert!(!gettxout_of(&ctx, parent_txid, 0, &Value::new_null()).is_null());

        let spend = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: bitcoin::OutPoint::new(parent_txid, 0),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(41_000),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            }],
        };
        insert(&ctx, spend);

        // The case the rule exists for: the coin is CONFIRMED and unspent in the
        // UTXO set, and a mempool transaction has claimed it. Without this the
        // fixture could not tell "hidden because the mempool spent it" from
        // "absent because nothing confirmed it".
        {
            let mut changes = bitcoin_rs_utxo::BlockChanges::default();
            changes.add(bitcoin_rs_utxo::UtxoAdd::new(
                OutPoint::new(Hash256::from_le_bytes(parent_txid.as_byte_array()), 0),
                TxOut {
                    value: Amount::from_sat(42_000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
                },
                false,
                1,
            ));
            let Ok(()) = ctx
                .utxo
                .commit_block(&changes, &Hash256::from_le_bytes(&[0x99; 32]))
            else {
                panic!("seeding the confirmed output failed");
            };
        }
        assert!(
            !gettxout_of(&ctx, parent_txid, 0, &json!(false)).is_null(),
            "the output really is in the confirmed set"
        );

        // Core: "an unspent output that is spent in the mempool won't appear".
        assert!(
            gettxout_of(&ctx, parent_txid, 0, &Value::new_null()).is_null(),
            "an output claimed by a mempool transaction must not read as spendable"
        );
    }

    #[test]
    fn a_vout_the_mempool_transaction_does_not_have_is_not_invented() {
        let ctx = Arc::new(Context::new());
        let tx = funding_tx(0x44);
        let txid = tx.compute_txid();
        insert(&ctx, tx);

        assert!(
            gettxout_of(&ctx, txid, 7, &Value::new_null()).is_null(),
            "the fixture transaction has one output"
        );
    }
}
