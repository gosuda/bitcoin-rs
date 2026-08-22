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
    let txid = tx.compute_txid();
    match ctx.accept_transaction(tx, now_seconds()) {
        Ok(result) => Ok(json!(result.checks.txid.to_string())),
        // Core does not treat a resubmission as a failure: `BroadcastTransaction`
        // finds the transaction already in the mempool, rebroadcasts it, and
        // returns the txid. Callers retry on a dropped connection and expect
        // that to be idempotent.
        Err(bitcoin_rs_mempool::AcceptError::AlreadyInPool) => Ok(json!(txid.to_string())),
        Err(error) => Err(RpcError::TxRejected(error.to_string())),
    }
}

pub(crate) fn testmempoolaccept(ctx: &Arc<Context>, params: &Value) -> Result<Value, RpcError> {
    let raw_txs = params_array(params)?
        .first()
        .and_then(|value| value.as_array())
        .ok_or(RpcError::InvalidParams("raw transaction array is required"))?;
    let now = now_seconds();
    let mut rows = Vec::with_capacity(raw_txs.len());
    for raw in raw_txs {
        let Some(raw) = raw.as_str() else {
            return Err(RpcError::InvalidType("raw transaction must be a string"));
        };
        let Ok(tx) = decode_tx(raw) else {
            rows.push(json!({
                "txid": Hash256::default().to_string_be(),
                "allowed": false,
                "reject-reason": "transaction decode failed"
            }));
            continue;
        };
        let tx = Arc::new(tx);
        let txid = tx.compute_txid().to_string();
        // The old code reported the txid here too. A witness transaction's
        // wtxid differs, and package relay identifies transactions by it.
        let wtxid = tx.compute_wtxid().to_string();
        match ctx.check_transaction(&tx, now) {
            Ok(checks) => rows.push(json!({
                "txid": txid,
                "wtxid": wtxid,
                "allowed": true,
                "vsize": checks.vsize,
                "fees": {"base": bitcoin::Amount::from_sat(checks.fee).to_btc()}
            })),
            Err(error) => rows.push(json!({
                "txid": txid,
                "wtxid": wtxid,
                "allowed": false,
                "reject-reason": error.to_string()
            })),
        }
    }
    Ok(json!(rows))
}

/// Wall-clock seconds since the UNIX epoch, for mempool entry timestamps.
fn now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_secs())
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
mod acceptance_tests {
    use alloc::sync::Arc;

    use bitcoin::absolute::LockTime;
    use bitcoin::consensus::encode::serialize;
    use bitcoin::hashes::Hash as _;
    use bitcoin::hex::DisplayHex as _;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, PubkeyHash, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
    use bitcoin_rs_primitives::Hash256;
    use bitcoin_rs_utxo::{BlockChanges, UtxoAdd};
    use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, json};

    use super::{sendrawtransaction, testmempoolaccept};
    use crate::context::Context;
    use crate::error::RpcError;

    fn internal_outpoint(tag: u8) -> bitcoin_rs_primitives::OutPoint {
        bitcoin_rs_primitives::OutPoint::new(Hash256::from_le_bytes(&[tag; 32]), 0)
    }

    fn spent_outpoint(tag: u8) -> bitcoin::OutPoint {
        bitcoin::OutPoint::new(bitcoin::Txid::from_byte_array([tag; 32]), 0)
    }

    /// Seeds one confirmed, anyone-can-spend output worth `value`.
    fn seed_utxo(ctx: &Context, tag: u8, value: u64) {
        let mut changes = BlockChanges::default();
        changes.add(UtxoAdd::new(
            internal_outpoint(tag),
            TxOut {
                value: Amount::from_sat(value),
                script_pubkey: ScriptBuf::from_bytes(vec![0x51]),
            },
            false,
            7,
        ));
        ctx.utxo
            .commit_block(&changes, &Hash256::default())
            .unwrap_or_else(|err| panic!("commit_block failed: {err}"));
    }

    fn spending_tx(tag: u8, output_value: u64) -> Transaction {
        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: spent_outpoint(tag),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(output_value),
                script_pubkey: ScriptBuf::new_p2pkh(&PubkeyHash::from_byte_array([9_u8; 20])),
            }],
        }
    }

    fn hex_of(tx: &Transaction) -> String {
        serialize(tx).to_lower_hex_string()
    }

    /// The transaction must land in the mempool.
    ///
    /// It previously went into a side `HashMap` that nothing else treated as
    /// the mempool: `getmempoolinfo` reported an empty pool, mining saw no
    /// candidates, and no policy check ran at all.
    #[test]
    fn sendrawtransaction_admits_the_transaction_to_the_mempool() {
        let ctx = Arc::new(Context::new());
        seed_utxo(&ctx, 1, 100_000);
        let tx = spending_tx(1, 90_000);

        let Ok(value) = sendrawtransaction(&ctx, &json!([hex_of(&tx)])) else {
            panic!("a standard transaction spending a confirmed output must be accepted");
        };

        assert_eq!(value.as_str(), Some(tx.compute_txid().to_string().as_str()));
        assert_eq!(ctx.mempool.read().len(), 1, "the pool must hold it");
        assert!(ctx.mempool.read().contains_txid(&tx.compute_txid()));
    }

    /// A rejection must say why, under Core's `RPC_VERIFY_REJECTED` code.
    #[test]
    fn sendrawtransaction_rejects_a_transaction_whose_inputs_do_not_exist() {
        let ctx = Arc::new(Context::new());
        let tx = spending_tx(4, 90_000);

        let outcome = sendrawtransaction(&ctx, &json!([hex_of(&tx)]));

        let Err(error) = outcome else {
            panic!("a transaction with no resolvable inputs must not be accepted");
        };
        assert!(
            matches!(error, RpcError::TxRejected(_)),
            "expected a rejection, got {error:?}"
        );
        assert_eq!(error.code(), RpcError::CORE_VERIFY_REJECTED);
        assert!(ctx.mempool.read().is_empty());
    }

    /// Core rebroadcasts rather than failing, and callers retry on a dropped
    /// connection expecting that to be safe.
    #[test]
    fn sendrawtransaction_is_idempotent_for_a_transaction_already_in_the_pool() {
        let ctx = Arc::new(Context::new());
        seed_utxo(&ctx, 1, 100_000);
        let tx = spending_tx(1, 90_000);
        let params = json!([hex_of(&tx)]);
        let Ok(first) = sendrawtransaction(&ctx, &params) else {
            panic!("the first submission must succeed");
        };

        let Ok(second) = sendrawtransaction(&ctx, &params) else {
            panic!("resubmitting a transaction already in the mempool must not fail");
        };

        assert_eq!(first.as_str(), second.as_str());
        assert_eq!(ctx.mempool.read().len(), 1, "it must not be inserted twice");
    }

    /// The verdict must come from the acceptance checks.
    ///
    /// This RPC used to answer `allowed: true` for anything that merely
    /// decoded, so a transaction spending outputs that do not exist was
    /// reported as acceptable.
    #[test]
    fn testmempoolaccept_rejects_a_transaction_that_only_decodes() {
        let ctx = Arc::new(Context::new());
        let tx = spending_tx(4, 90_000);

        let Ok(value) = testmempoolaccept(&ctx, &json!([[hex_of(&tx)]])) else {
            panic!("testmempoolaccept must answer");
        };

        let Some(rows) = value.as_array() else {
            panic!("testmempoolaccept must return an array");
        };
        let Some(row) = rows.first() else {
            panic!("one transaction in, one row out");
        };
        assert_eq!(row.get("allowed").as_bool(), Some(false));
        assert!(
            row.get("reject-reason")
                .as_str()
                .is_some_and(|r| !r.is_empty()),
            "a rejection must carry a reason"
        );
    }

    #[test]
    fn testmempoolaccept_allows_a_transaction_without_admitting_it() {
        let ctx = Arc::new(Context::new());
        seed_utxo(&ctx, 1, 100_000);
        let tx = spending_tx(1, 90_000);

        let Ok(value) = testmempoolaccept(&ctx, &json!([[hex_of(&tx)]])) else {
            panic!("testmempoolaccept must answer");
        };

        let Some(row) = value.as_array().and_then(|rows| rows.first()) else {
            panic!("one transaction in, one row out");
        };
        assert_eq!(row.get("allowed").as_bool(), Some(true));
        assert_eq!(
            row.get("vsize").as_u64(),
            u64::try_from(tx.vsize()).ok(),
            "vsize must be the transaction's, not a placeholder"
        );
        assert!(
            ctx.mempool.read().is_empty(),
            "testing acceptance must not accept"
        );
    }

    /// `wtxid` was a copy of `txid`. They differ for any witness transaction,
    /// and package relay identifies transactions by the witness id.
    #[test]
    fn testmempoolaccept_reports_the_witness_txid() {
        let ctx = Arc::new(Context::new());
        let mut tx = spending_tx(4, 90_000);
        tx.input[0].witness.push([1_u8; 8]);
        assert_ne!(
            tx.compute_txid().to_string(),
            tx.compute_wtxid().to_string(),
            "the fixture must carry a witness or this proves nothing"
        );

        let Ok(value) = testmempoolaccept(&ctx, &json!([[hex_of(&tx)]])) else {
            panic!("testmempoolaccept must answer");
        };

        let Some(row) = value.as_array().and_then(|rows| rows.first()) else {
            panic!("one transaction in, one row out");
        };
        assert_eq!(
            row.get("txid").as_str(),
            Some(tx.compute_txid().to_string().as_str())
        );
        assert_eq!(
            row.get("wtxid").as_str(),
            Some(tx.compute_wtxid().to_string().as_str())
        );
    }

    /// Standardness is relay policy, and Core relaxes it only on regtest.
    ///
    /// The mempool crate tests the gate itself; this covers the wiring that
    /// decides the flag, which is the half that can silently invert.
    #[test]
    fn standardness_is_relaxed_on_regtest_only() {
        let non_standard = || {
            let mut tx = spending_tx(1, 90_000);
            // Consensus-valid, non-standard.
            tx.version = Version(4);
            tx
        };

        let mainnet = Arc::new(Context::new());
        assert_eq!(
            mainnet.chain_network,
            bitcoin_rs_primitives::Network::Mainnet,
            "the fixture assumes the default context is mainnet"
        );
        seed_utxo(&mainnet, 1, 100_000);
        assert!(
            sendrawtransaction(&mainnet, &json!([hex_of(&non_standard())])).is_err(),
            "mainnet must enforce standardness"
        );

        let mut regtest = Context::new();
        regtest.chain_network = bitcoin_rs_primitives::Network::Regtest;
        let regtest = Arc::new(regtest);
        seed_utxo(&regtest, 1, 100_000);
        assert!(
            sendrawtransaction(&regtest, &json!([hex_of(&non_standard())])).is_ok(),
            "regtest must accept the same transaction"
        );
    }
}
