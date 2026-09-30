//! Minimal bitcoin-rs JSON-RPC client (HTTP/1.1, basic auth).
//!
//! Covers exactly what the bridge needs: `getblocktemplate` (blocking
//! long-poll), `submitblock`, and `getblockchaininfo`. See
//! `docs/contracts/external-api.md` (API-11..API-20) for the wire contract.

use serde_json::{json, Value};

#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("rpc error {code}: {message}")]
    Call { code: i64, message: String },
    #[error("malformed rpc response: {0}")]
    Shape(String),
}

pub struct GbtResponse {
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
    pub fn new(url: String, user: String, pass: String) -> Self {
        Self {
            url,
            user,
            pass,
            http: reqwest::Client::builder()
                // Long-poll holds the request open; no total timeout.
                .build()
                .expect("reqwest client builds without TLS features"),
        }
    }

    async fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        let body = json!({
            "jsonrpc": "1.0",
            "id": "sv2-tp",
            "method": method,
            "params": params,
        });
        let response = self
            .http
            .post(&self.url)
            .basic_auth(&self.user, Some(&self.pass))
            .json(&body)
            .send()
            .await?;
        let payload: Value = response.json().await?;
        if let Some(err) = payload.get("error").filter(|e| !e.is_null()) {
            return Err(RpcError::Call {
                code: err.get("code").and_then(Value::as_i64).unwrap_or(-1),
                message: err
                    .get("message")
                    .and_then(Value::as_str)
                    .unwrap_or("unknown")
                    .to_string(),
            });
        }
        payload.get("result").cloned().ok_or_else(|| {
            RpcError::Shape(format!("missing result in {method} response: {payload}"))
        })
    }

    /// getblocktemplate with the required segwit rule; `long_poll_id` makes
    /// the call block until the template changes (tip or mempool).
    pub async fn get_block_template(
        &self,
        long_poll_id: Option<&str>,
    ) -> Result<GbtResponse, RpcError> {
        let mut request = json!({ "rules": ["segwit"] });
        if let Some(id) = long_poll_id {
            request["longpollid"] = json!(id);
        }
        // Ready-state failures (genesis not applied, IBD) surface as-is.
        let raw = self.call("getblocktemplate", json!([request])).await?;
        let long_poll_id = raw
            .get("longpollid")
            .and_then(Value::as_str)
            .ok_or_else(|| RpcError::Shape("getblocktemplate response missing longpollid".into()))?
            .to_string();
        Ok(GbtResponse { raw, long_poll_id })
    }

    /// submitblock: `None` result = accepted; `Some(reason)` = rejected.
    pub async fn submit_block(&self, block_hex: &str) -> Result<Option<String>, RpcError> {
        let result = self.call("submitblock", json!([block_hex])).await?;
        match result {
            Value::Null => Ok(None),
            reason @ Value::String(_) => {
                Ok(Some(reason.as_str().unwrap_or("rejected").to_string()))
            }
            other => Err(RpcError::Shape(format!(
                "unexpected submitblock result: {other}"
            ))),
        }
    }

    pub async fn block_count(&self) -> Result<u64, RpcError> {
        self.call("getblockcount", json!([]))
            .await?
            .as_u64()
            .ok_or_else(|| RpcError::Shape("getblockcount returned non-integer".into()))
    }
}
