use bitcoin_rs_index::ScriptHash;
use compact_str::CompactString;
use hashbrown::HashMap;
use sonic_rs::{Value, json};

use crate::methods::{ElectrumError, IndexHandle, MempoolHandle, scripthash_hex, status_string};

/// Per-session Electrum subscription state.
#[derive(Clone, Debug, Default)]
pub struct SessionSubscriptions {
    scripthashes: HashMap<ScriptHash, Option<CompactString>>,
    headers: Option<Value>,
}

impl SessionSubscriptions {
    /// Creates empty subscription state.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a scripthash subscription at its current status.
    pub fn subscribe_scripthash(
        &mut self,
        index: &IndexHandle,
        mempool: &MempoolHandle,
        scripthash: ScriptHash,
    ) -> Value {
        let status = status_string(index, mempool, scripthash);
        self.scripthashes.insert(scripthash, status.clone());
        status_value(status)
    }

    /// Records a header subscription result returned to the client.
    pub fn subscribe_headers(&mut self, value: Value) {
        self.headers = Some(value);
    }

    /// Polls subscribed keys and returns JSON-RPC notifications for changed statuses.
    pub fn poll(
        &mut self,
        index: &IndexHandle,
        mempool: &MempoolHandle,
    ) -> Result<Vec<Value>, ElectrumError> {
        let mut notifications = Vec::new();
        for (scripthash, old_status) in &mut self.scripthashes {
            let new_status = status_string(index, mempool, *scripthash);
            if *old_status != new_status {
                old_status.clone_from(&new_status);
                notifications.push(json!({
                    "jsonrpc": "2.0",
                    "method": "blockchain.scripthash.subscribe",
                    "params": [scripthash_hex(*scripthash), status_value(new_status)],
                }));
            }
        }
        Ok(notifications)
    }

    /// Returns the number of tracked scripthash subscriptions.
    #[must_use]
    pub fn len(&self) -> usize {
        self.scripthashes.len()
    }

    /// Returns `true` when no scripthashes are subscribed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.scripthashes.is_empty()
    }
}

/// Converts an optional Electrum status hash into its JSON value.
#[must_use]
pub fn status_value(status: Option<CompactString>) -> Value {
    match status {
        Some(status) => json!(status.as_str()),
        None => Value::new_null(),
    }
}
