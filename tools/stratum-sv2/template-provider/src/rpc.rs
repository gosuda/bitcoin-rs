//! Minimal bitcoin-rs JSON-RPC client (HTTP/1.1, basic auth).
//!
//! Covers exactly what the bridge needs: `getblocktemplate` (blocking
//! long-poll), `submitblock`, and `getblockcount` (post-submit tip check).

use serde_json::{Value, json};
use std::time::Duration;

/// Bounds for non-long-poll calls: `connect_timeout` covers peer setup and
/// `REQUEST_TIMEOUT` bounds submitblock/getblockcount, so a wedged node
/// fails fast instead of freezing the pool session loop. The long-poll
/// itself stays unbounded below the request layer.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// getblocktemplate result: the raw template body plus the `longpollid` the
/// next call must pass to keep long-polling.
pub struct Gbt {
    pub raw: Value,
    pub long_poll_id: String,
}

pub struct RpcClient {
    url: String,
    user: String,
    pass: String,
    http: reqwest::Client,
}

impl RpcClient {
    pub fn new(url: &str, user: &str, pass: &str) -> Self {
        Self {
            url: url.to_owned(),
            user: user.to_owned(),
            pass: pass.to_owned(),
            // Long-poll holds requests open, so timeouts are per-request
            // (see `call`), not on the client; connect setup stays bounded.
            http: reqwest::Client::builder()
                .connect_timeout(CONNECT_TIMEOUT)
                .build()
                .expect("reqwest client"),
        }
    }

    async fn call(
        &self,
        method: &str,
        params: Value,
        timeout: Option<Duration>,
    ) -> Result<Value, String> {
        let mut request = self
            .http
            .post(&self.url)
            .basic_auth(&self.user, Some(&self.pass))
            .json(&json!({"jsonrpc": "1.0", "id": "sv2-tp", "method": method, "params": params}));
        if let Some(timeout) = timeout {
            request = request.timeout(timeout);
        }
        let response = request
            .send()
            .await
            .map_err(|e| format!("{method} http: {e}"))?;
        let payload: Value = response
            .json()
            .await
            .map_err(|e| format!("{method} decode: {e}"))?;
        if let Some(err) = payload.get("error").filter(|e| !e.is_null()) {
            return Err(format!("{method} rpc: {err}"));
        }
        payload
            .get("result")
            .cloned()
            .ok_or_else(|| format!("{method}: missing result in {payload}"))
    }

    /// `getblocktemplate {"rules": ["segwit"]}`, blocking when
    /// `long_poll_id` is passed until the tip or mempool changes.
    pub async fn get_block_template(&self, long_poll_id: Option<&str>) -> Result<Gbt, String> {
        let mut request = json!({"rules": ["segwit"]});
        if let Some(id) = long_poll_id {
            request["longpollid"] = json!(id);
        }
        let raw = self
            .call("getblocktemplate", json!([request]), None)
            .await?;
        let long_poll_id = raw
            .get("longpollid")
            .and_then(Value::as_str)
            .ok_or_else(|| "getblocktemplate: missing longpollid".to_owned())?
            .to_owned();
        Ok(Gbt { raw, long_poll_id })
    }

    /// `submitblock <hex>`: `Ok(None)` = accepted, `Ok(Some(reason))` =
    /// rejected by the mining owner.
    pub async fn submit_block(&self, block_hex: &str) -> Result<Option<String>, String> {
        match self
            .call("submitblock", json!([block_hex]), Some(REQUEST_TIMEOUT))
            .await?
        {
            Value::Null => Ok(None),
            Value::String(reason) => Ok(Some(reason)),
            other => Err(format!("submitblock: unexpected result {other}")),
        }
    }

    /// Current tip height via `getblockcount` (post-submit evidence).
    pub async fn block_count(&self) -> Result<u64, String> {
        self.call("getblockcount", json!([]), Some(REQUEST_TIMEOUT))
            .await?
            .as_u64()
            .ok_or_else(|| "getblockcount: non-integer result".to_owned())
    }
}
