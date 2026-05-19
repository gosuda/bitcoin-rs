use std::io::{BufRead as _, BufReader, Read, Write};

use bitcoin_rs_index::ScriptHash;
use compact_str::{CompactString, ToCompactString};
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait as _, Value, json};
use tracing::warn;

use crate::methods::{ElectrumError, IndexHandle, MempoolHandle, dispatch, parse_scripthash_param};
use crate::subscription::SessionSubscriptions;

/// A serialized JSON-RPC response or notification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JsonRpcResponse {
    /// Serialized line without its trailing newline.
    pub line: String,
}

/// Per-connection Electrum JSON-RPC session.
pub struct Session<S> {
    io: S,
    index: IndexHandle,
    mempool: MempoolHandle,
    subscriptions: SessionSubscriptions,
}

impl<S> Session<S>
where
    S: Read + Write,
{
    /// Creates a session over a stream-like object.
    #[must_use]
    pub fn new(io: S, index: IndexHandle, mempool: MempoolHandle) -> Self {
        Self {
            io,
            index,
            mempool,
            subscriptions: SessionSubscriptions::new(),
        }
    }

    /// Returns mutable subscription state for tests and embedders.
    pub const fn subscriptions_mut(&mut self) -> &mut SessionSubscriptions {
        &mut self.subscriptions
    }

    /// Serves line-delimited JSON-RPC until EOF or an unrecoverable I/O error.
    pub fn serve(self) -> Result<(), ElectrumError> {
        let mut reader = BufReader::new(self.io);
        let mut state = SessionState {
            index: self.index,
            mempool: self.mempool,
            subscriptions: self.subscriptions,
        };
        let mut line = String::new();
        loop {
            for notification in state.poll_serialized()? {
                reader.get_mut().write_all(notification.as_bytes())?;
                reader.get_mut().write_all(b"\n")?;
            }
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => return Ok(()),
                Ok(_) => {
                    let responses = state.handle_line(&line)?;
                    for response in responses {
                        reader.get_mut().write_all(response.line.as_bytes())?;
                        reader.get_mut().write_all(b"\n")?;
                    }
                    reader.get_mut().flush()?;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                Err(error) if error.kind() == std::io::ErrorKind::TimedOut => continue,
                Err(error) => return Err(error.into()),
            }
        }
    }

    /// Handles a single line and returns serialized responses.
    pub fn handle_line(&mut self, line: &str) -> Result<Vec<JsonRpcResponse>, ElectrumError> {
        let mut state = SessionState {
            index: self.index.clone(),
            mempool: self.mempool.clone(),
            subscriptions: core::mem::take(&mut self.subscriptions),
        };
        let result = state.handle_line(line);
        self.subscriptions = state.subscriptions;
        result
    }
}

struct SessionState {
    index: IndexHandle,
    mempool: MempoolHandle,
    subscriptions: SessionSubscriptions,
}

impl SessionState {
    fn handle_line(&mut self, line: &str) -> Result<Vec<JsonRpcResponse>, ElectrumError> {
        let Ok(value) = sonic_rs::from_str::<Value>(line.trim_end()) else {
            let id = Value::new_null();
            return serialize_single(&error_response(&id, -32700, "parse error"));
        };

        if let Some(array) = value.as_array() {
            let mut responses = Vec::with_capacity(array.len());
            for request in array {
                responses.push(self.handle_value(request)?);
            }
            return Ok(responses);
        }

        Ok(vec![self.handle_value(&value)?])
    }

    fn handle_value(&mut self, value: &Value) -> Result<JsonRpcResponse, ElectrumError> {
        let request = match RpcRequest::parse(value) {
            Ok(request) => request,
            Err(response) => return serialize_response(&response),
        };
        let result = self.call(&request);
        match result {
            Ok(value) => {
                let response = json!({"jsonrpc": "2.0", "id": request.id, "result": value});
                serialize_response(&response)
            }
            Err(error) => {
                warn!(method = %request.method, error = %error, "electrum RPC failed");
                serialize_response(&error_response(
                    &request.id,
                    error.rpc_code(),
                    &error.to_string(),
                ))
            }
        }
    }

    fn call(&mut self, request: &RpcRequest) -> Result<Value, ElectrumError> {
        let result = dispatch(&request.method, &self.index, &self.mempool, &request.params)?;
        match request.method.as_str() {
            "blockchain.scripthash.subscribe" => {
                let scripthash = parse_scripthash_param(&request.params)?;
                let value =
                    self.subscriptions
                        .subscribe_scripthash(&self.index, &self.mempool, scripthash);
                Ok(value)
            }
            "blockchain.headers.subscribe" => {
                self.subscriptions.subscribe_headers(result.clone());
                Ok(result)
            }
            _ => Ok(result),
        }
    }

    fn poll_serialized(&mut self) -> Result<Vec<String>, ElectrumError> {
        self.subscriptions
            .poll(&self.index, &self.mempool)?
            .into_iter()
            .map(|value| sonic_rs::to_string(&value).map_err(ElectrumError::from))
            .collect()
    }
}

struct RpcRequest {
    id: Value,
    method: CompactString,
    params: Value,
}

impl RpcRequest {
    fn parse(value: &Value) -> Result<Self, Value> {
        if !value.is_object() {
            let id = Value::new_null();
            return Err(error_response(&id, -32600, "invalid request"));
        }
        let id = value.get("id").cloned().unwrap_or_else(Value::new_null);
        let Some(method) = value.get("method").and_then(|method| method.as_str()) else {
            return Err(error_response(&id, -32600, "invalid request"));
        };
        let params = value.get("params").cloned().unwrap_or_else(|| json!([]));
        if !params.is_array() {
            return Err(error_response(&id, -32602, "invalid params"));
        }
        Ok(Self {
            id,
            method: method.to_compact_string(),
            params,
        })
    }
}

fn serialize_single(value: &Value) -> Result<Vec<JsonRpcResponse>, ElectrumError> {
    Ok(vec![serialize_to_line(value)?])
}

fn serialize_response(value: &Value) -> Result<JsonRpcResponse, ElectrumError> {
    serialize_to_line(value)
}

fn serialize_to_line(value: &Value) -> Result<JsonRpcResponse, ElectrumError> {
    Ok(JsonRpcResponse {
        line: sonic_rs::to_string(value)?,
    })
}

fn error_response(id: &Value, code: i64, message: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}})
}

/// Parses a scripthash from a subscription response path.
pub fn parse_subscribed_scripthash(params: &Value) -> Result<ScriptHash, ElectrumError> {
    parse_scripthash_param(params)
}
