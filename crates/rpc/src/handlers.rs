use alloc::sync::Arc;

use sonic_rs::{JsonContainerTrait as _, JsonValueTrait, Value, json};

use crate::context::Context;
use crate::error::RpcError;

pub(crate) mod chain;
pub(crate) mod mempool;
pub(crate) mod mining;
pub(crate) mod network;
pub(crate) mod tx;
pub(crate) mod tx_render;
pub(crate) mod util;
pub(crate) mod wallet;

const NO_PRIVATE_KEYS: &str = "wallet has no private keys; use external signer";

/// JSON-RPC method dispatcher backed by shared node context.
#[derive(Clone, Debug)]
pub struct Handler {
    ctx: Arc<Context>,
}

impl Handler {
    /// Builds a dispatcher over `ctx`.
    #[must_use]
    pub const fn new(ctx: Arc<Context>) -> Self {
        Self { ctx }
    }

    /// Dispatches one Bitcoin Core-compatible JSON-RPC method.
    pub fn dispatch(&self, method: &str, params: &Value) -> Result<Value, RpcError> {
        match method {
            "getblockchaininfo" => chain::getblockchaininfo(&self.ctx, params),
            "getchaintips" => chain::getchaintips(&self.ctx, params),
            "getchaintxstats" => chain::getchaintxstats(&self.ctx, params),
            "getblockcount" => chain::getblockcount(&self.ctx, params),
            "getblockhash" => chain::getblockhash(&self.ctx, params),
            "getbestblockhash" => chain::getbestblockhash(&self.ctx, params),
            "getblock" => chain::getblock(&self.ctx, params),
            "getblockheader" => chain::getblockheader(&self.ctx, params),
            "getblockstats" => chain::getblockstats(&self.ctx, params),
            "verifychain" => chain::verifychain(&self.ctx, params),
            "gettxoutsetinfo" => chain::gettxoutsetinfo(&self.ctx, params),
            "getblockfilter" => chain::getblockfilter(&self.ctx, params),
            "getindexinfo" => chain::getindexinfo(&self.ctx, params),
            "pruneblockchain" => chain::pruneblockchain(&self.ctx, params),
            "getrawtransaction" => tx::getrawtransaction(&self.ctx, params),
            "gettxout" => tx::gettxout(&self.ctx, params),
            "gettxoutproof" => tx::gettxoutproof(&self.ctx, params),
            "verifytxoutproof" => tx::verifytxoutproof(&self.ctx, params),
            "sendrawtransaction" => tx::sendrawtransaction(&self.ctx, params),
            "testmempoolaccept" => tx::testmempoolaccept(&self.ctx, params),
            "decoderawtransaction" => tx::decoderawtransaction(&self.ctx, params),
            "getmempoolinfo" => mempool::getmempoolinfo(&self.ctx, params),
            "getmempoolentry" => mempool::getmempoolentry(&self.ctx, params),
            "getrawmempool" => mempool::getrawmempool(&self.ctx, params),
            "clearmempool" => mempool::clearmempool(&self.ctx, params),
            "getmempoolancestors" => mempool::getmempoolancestors(&self.ctx, params),
            "getmempooldescendants" => mempool::getmempooldescendants(&self.ctx, params),
            "estimatesmartfee" => util::estimatesmartfee(&self.ctx, params),
            "uptime" => util::uptime(&self.ctx, params),
            "getrpcinfo" => util::getrpcinfo(&self.ctx, params),
            "getmemoryinfo" => util::getmemoryinfo(&self.ctx, params),
            "estimaterawfee" => util::estimaterawfee(&self.ctx, params),
            "getzmqnotifications" => util::getzmqnotifications(&self.ctx, params),
            "validateaddress" => util::validateaddress(&self.ctx, params),
            "getnetworkinfo" => network::getnetworkinfo(&self.ctx, params),
            "getpeerinfo" => network::getpeerinfo(&self.ctx, params),
            "addnode" => network::addnode(&self.ctx, params),
            "disconnectnode" => network::disconnectnode(&self.ctx, params),
            "getconnectioncount" => network::getconnectioncount(&self.ctx, params),
            "getnettotals" => network::getnettotals(&self.ctx, params),
            "getblocktemplate" => mining::getblocktemplate(&self.ctx, params),
            "getmininginfo" => mining::getmininginfo(&self.ctx, params),
            "submitblock" => mining::submitblock(&self.ctx, params),
            "prioritisetransaction" => mining::prioritisetransaction(&self.ctx, params),
            "getdescriptorinfo" => wallet::getdescriptorinfo(&self.ctx, params),
            "deriveaddresses" => wallet::deriveaddresses(&self.ctx, params),
            "scantxoutset" => wallet::scantxoutset(&self.ctx, params),
            "walletcreatefundedpsbt" => wallet::walletcreatefundedpsbt(&self.ctx, params),
            "walletprocesspsbt" => wallet::walletprocesspsbt(&self.ctx, params),
            "finalizepsbt" => wallet::finalizepsbt(&self.ctx, params),
            "combinepsbt" => wallet::combinepsbt(&self.ctx, params),
            "bumpfee" => wallet::bumpfee(&self.ctx, params),
            "signrawtransactionwithkey"
            | "signrawtransactionwithwallet"
            | "dumpprivkey"
            | "dumpwallet"
            | "importprivkey"
            | "importwallet"
            | "importmulti"
            | "importdescriptors"
            | "sethdseed"
            | "walletpassphrase"
            | "walletpassphrasechange"
            | "encryptwallet" => Err(RpcError::method_disabled(NO_PRIVATE_KEYS)),
            _ => Err(RpcError::MethodNotFound(method.to_owned())),
        }
    }
}

pub(crate) fn ensure_no_params(params: &Value) -> Result<(), RpcError> {
    if params.is_null() {
        return Ok(());
    }
    let Some(array) = params.as_array() else {
        return Err(RpcError::InvalidParams("params must be an array"));
    };
    if array.is_empty() {
        Ok(())
    } else {
        Err(RpcError::InvalidParams("method does not accept parameters"))
    }
}

pub(crate) fn params_array(params: &Value) -> Result<&sonic_rs::Array, RpcError> {
    params
        .as_array()
        .ok_or(RpcError::InvalidParams("params must be an array"))
}

pub(crate) fn optional_bool(params: &Value, index: usize, default: bool) -> Result<bool, RpcError> {
    let Some(array) = params.as_array() else {
        return Ok(default);
    };
    let Some(value) = array.get(index) else {
        return Ok(default);
    };
    if value.is_null() {
        return Ok(default);
    }
    value
        .as_bool()
        .ok_or(RpcError::InvalidType("parameter must be boolean"))
}

pub(crate) fn required_str<'a>(
    params: &'a Value,
    index: usize,
    name: &'static str,
) -> Result<&'a str, RpcError> {
    params_array(params)?
        .get(index)
        .and_then(JsonValueTrait::as_str)
        .ok_or(RpcError::InvalidParams(name))
}

pub(crate) fn required_u64(
    params: &Value,
    index: usize,
    name: &'static str,
) -> Result<u64, RpcError> {
    params_array(params)?
        .get(index)
        .and_then(JsonValueTrait::as_u64)
        .ok_or(RpcError::InvalidParams(name))
}

pub(crate) fn invalid_psbt() -> Value {
    json!({"psbt": "", "complete": false})
}

pub(crate) fn serde_to_sonic(value: &serde_json::Value) -> Result<Value, RpcError> {
    let text = serde_json::to_string(value)?;
    Ok(sonic_rs::from_str(&text)?)
}
