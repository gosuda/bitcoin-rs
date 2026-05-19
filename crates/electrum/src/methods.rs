use alloc::sync::Arc;
use core::fmt;
use std::io;

use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hex::{DisplayHex as _, FromHex as _};
use bitcoin::{OutPoint, Transaction, Txid};
use bitcoin_rs_index::{HistoryEntry, HistoryHeight, ScriptHash, compute_status_hash};
use bitcoin_rs_mempool::{Mempool, MempoolEntry, MempoolLimits};
use bitcoin_rs_storage::{ColumnFamily, KvIter, KvStore, StorageError};
use compact_str::{CompactString, ToCompactString};
use hashbrown::HashMap;
use parking_lot::RwLock;
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait, Value, json};
use thiserror::Error;

const PROTOCOL_VERSION: &str = "1.4";
const SERVER_VERSION: &str = "bitcoin-rs-electrum/0.1.0";
const MAX_HEADERS: usize = 2_016;

/// Error returned by Electrum method and session handling.
#[derive(Debug, Error)]
pub enum ElectrumError {
    /// Request did not match the method parameter shape.
    #[error("invalid params: {0}")]
    InvalidParams(&'static str),
    /// Method name is not supported.
    #[error("method not found: {0}")]
    MethodNotFound(CompactString),
    /// Backend storage failed.
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
    /// Transaction payload could not be decoded.
    #[error("transaction decode error: {0}")]
    TransactionDecode(String),
    /// I/O failed while serving a session.
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    /// JSON parsing or serialization failed.
    #[error("json error: {0}")]
    Json(#[from] sonic_rs::Error),
    /// TLS failed while accepting a session.
    #[error("tls error: {0}")]
    Tls(#[from] rustls::Error),
}

impl ElectrumError {
    /// JSON-RPC error code matching Electrum/electrs conventions.
    #[must_use]
    pub const fn rpc_code(&self) -> i64 {
        match self {
            Self::InvalidParams(_) => -32602,
            Self::MethodNotFound(_) => -32601,
            Self::Storage(_)
            | Self::TransactionDecode(_)
            | Self::Io(_)
            | Self::Json(_)
            | Self::Tls(_) => 1,
        }
    }
}

#[derive(Copy, Clone, Debug)]
struct HistoryRecord {
    txid: Txid,
    height: i64,
    value: u64,
    vout: u32,
    spent: bool,
}

#[derive(Default)]
struct IndexState {
    histories: RwLock<HashMap<ScriptHash, Vec<HistoryRecord>>>,
    transactions: RwLock<HashMap<Txid, Vec<u8>>>,
    headers: RwLock<Vec<[u8; 80]>>,
    store: RwLock<Option<Arc<dyn IndexReader>>>,
}

/// Read-only Electrum index handle used by method handlers.
#[derive(Clone, Default)]
pub struct IndexHandle {
    state: Arc<IndexState>,
}

impl fmt::Debug for IndexHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IndexHandle").finish_non_exhaustive()
    }
}

impl IndexHandle {
    /// Creates an empty in-memory handle suitable for tests and embedders.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a handle backed by any workspace key-value store.
    #[must_use]
    pub fn from_store<S>(store: Arc<S>) -> Self
    where
        S: KvStore,
    {
        let handle = Self::new();
        *handle.state.store.write() = Some(Arc::new(StoreIndexReader { store }));
        handle
    }

    /// Adds a synthetic confirmed history row.
    pub fn add_history_entry(
        &self,
        scripthash: ScriptHash,
        txid: Txid,
        height: i64,
        value: u64,
        vout: u32,
        spent: bool,
    ) {
        self.state
            .histories
            .write()
            .entry(scripthash)
            .or_default()
            .push(HistoryRecord {
                txid,
                height,
                value,
                vout,
                spent,
            });
    }

    /// Stores a raw transaction for `blockchain.transaction.get`.
    pub fn add_transaction(&self, tx: &Transaction) {
        self.state
            .transactions
            .write()
            .insert(tx.compute_txid(), serialize(tx));
    }

    /// Stores a raw block header for header RPCs.
    pub fn add_header(&self, height: u32, header: [u8; 80]) {
        let Ok(index) = usize::try_from(height) else {
            return;
        };
        let mut headers = self.state.headers.write();
        if headers.len() <= index {
            headers.resize(index.saturating_add(1), [0_u8; 80]);
        }
        headers[index] = header;
    }

    fn confirmed_history(&self, scripthash: ScriptHash) -> Vec<HistoryRecord> {
        let mut records = self
            .state
            .histories
            .read()
            .get(&scripthash)
            .cloned()
            .unwrap_or_default();
        records.sort_by_key(|record| (record.height, record.txid));
        records
    }

    fn get_transaction_hex(&self, txid: &Txid) -> Option<String> {
        self.state
            .transactions
            .read()
            .get(txid)
            .map(|bytes| bytes.as_slice().to_lower_hex_string())
    }

    fn headers(&self) -> Vec<[u8; 80]> {
        let headers = self.state.headers.read().clone();
        if !headers.is_empty() {
            return headers;
        }
        let Some(reader) = self.state.store.read().clone() else {
            return Vec::new();
        };
        reader
            .iter_prefix(ColumnFamily::BlockHeaders, &[])
            .unwrap_or_default()
            .into_iter()
            .filter_map(|(key, _value)| key.try_into().ok())
            .collect()
    }
}

type IndexRows = Vec<(Vec<u8>, Vec<u8>)>;
trait IndexReader: Send + Sync {
    fn iter_prefix(&self, cf: ColumnFamily, prefix: &[u8]) -> Result<IndexRows, StorageError>;
}

struct StoreIndexReader<S: KvStore> {
    store: Arc<S>,
}

impl<S: KvStore> IndexReader for StoreIndexReader<S> {
    fn iter_prefix(&self, cf: ColumnFamily, prefix: &[u8]) -> Result<IndexRows, StorageError> {
        collect_iter(self.store.iter_prefix(cf, prefix)?)
    }
}

fn collect_iter(iter: KvIter<'_>) -> Result<IndexRows, StorageError> {
    iter.collect()
}

/// Thread-safe mempool handle used by Electrum methods.
#[derive(Clone, Debug)]
pub struct MempoolHandle {
    pool: Arc<RwLock<Mempool>>,
}

impl Default for MempoolHandle {
    fn default() -> Self {
        Self::new(Mempool::new(MempoolLimits::default()))
    }
}

impl MempoolHandle {
    /// Wraps a mempool in a shareable handle.
    #[must_use]
    pub fn new(pool: Mempool) -> Self {
        Self {
            pool: Arc::new(RwLock::new(pool)),
        }
    }

    /// Inserts a transaction with explicit policy metadata.
    pub fn insert_transaction(
        &self,
        tx: Transaction,
        fee: u64,
        time: u64,
        height: u32,
    ) -> Result<Txid, ElectrumError> {
        let txid = tx.compute_txid();
        let vsize = u32::try_from(tx.vsize())
            .map_err(|_| ElectrumError::InvalidParams("transaction vsize exceeds u32"))?;
        let entry = MempoolEntry::new(Arc::new(tx), vsize, fee, time, height);
        self.pool
            .write()
            .insert_entry(entry)
            .map_err(|error| ElectrumError::TransactionDecode(error.to_string()))?;
        Ok(txid)
    }

    fn mempool_history(&self, scripthash: ScriptHash) -> Vec<HistoryRecord> {
        let pool = self.pool.read();
        let mut records = Vec::new();
        for (_id, entry) in &pool.entries {
            let txid = entry.tx.compute_txid();
            for (vout, output) in entry.tx.output.iter().enumerate() {
                if ScriptHash::new(&output.script_pubkey) == scripthash {
                    let Ok(vout) = u32::try_from(vout) else {
                        continue;
                    };
                    records.push(HistoryRecord {
                        txid,
                        height: 0,
                        value: output.value.to_sat(),
                        vout,
                        spent: false,
                    });
                }
            }
        }
        records.sort_by_key(|record| (record.height, record.txid));
        records
    }

    fn mempool_spends(&self) -> Vec<OutPoint> {
        let pool = self.pool.read();
        pool.entries
            .iter()
            .flat_map(|(_id, entry)| entry.tx.input.iter().map(|input| input.previous_output))
            .collect()
    }

    fn get_transaction_hex(&self, txid: &Txid) -> Option<String> {
        let pool = self.pool.read();
        let id = pool.by_txid.get(txid)?;
        pool.entry(*id)
            .map(|entry| serialize(entry.tx.as_ref()).to_lower_hex_string())
    }

    fn fee_histogram(&self) -> Vec<(u64, u64)> {
        let mut buckets: HashMap<u64, u64> = HashMap::new();
        for (_id, entry) in &self.pool.read().entries {
            let rate = entry.fee_rate / 1_000;
            buckets
                .entry(rate)
                .and_modify(|vsize| *vsize = vsize.saturating_add(u64::from(entry.vsize)))
                .or_insert(u64::from(entry.vsize));
        }
        let mut rows = buckets.into_iter().collect::<Vec<_>>();
        rows.sort_by(|left, right| right.0.cmp(&left.0));
        rows
    }
}

/// Dispatches a supported Electrum method.
pub fn dispatch(
    method: &str,
    index: &IndexHandle,
    mempool: &MempoolHandle,
    params: &Value,
) -> Result<Value, ElectrumError> {
    match method {
        "server.version" => server_version(index, mempool, params),
        "server.banner" => server_banner(index, mempool, params),
        "server.donation_address" => server_donation_address(index, mempool, params),
        "server.peers.subscribe" => server_peers_subscribe(index, mempool, params),
        "server.ping" => server_ping(index, mempool, params),
        "blockchain.scripthash.get_history" => scripthash_get_history(index, mempool, params),
        "blockchain.scripthash.get_balance" => scripthash_get_balance(index, mempool, params),
        "blockchain.scripthash.subscribe" => scripthash_subscribe(index, mempool, params),
        "blockchain.scripthash.listunspent" => scripthash_listunspent(index, mempool, params),
        "blockchain.transaction.get" => transaction_get(index, mempool, params),
        "blockchain.transaction.broadcast" => transaction_broadcast(index, mempool, params),
        "blockchain.estimatefee" => estimate_fee(index, mempool, params),
        "mempool.get_fee_histogram" => mempool_get_fee_histogram(index, mempool, params),
        "blockchain.block.headers" => block_headers(index, mempool, params),
        "blockchain.headers.subscribe" => headers_subscribe(index, mempool, params),
        _ => Err(ElectrumError::MethodNotFound(method.to_compact_string())),
    }
}

pub(crate) fn server_version(
    _index: &IndexHandle,
    _mempool: &MempoolHandle,
    params: &Value,
) -> Result<Value, ElectrumError> {
    let params = params_array(params)?;
    if params.len() < 2 {
        return Err(ElectrumError::InvalidParams(
            "server.version expects client and protocol",
        ));
    }
    Ok(json!([SERVER_VERSION, PROTOCOL_VERSION]))
}

pub(crate) fn server_banner(
    _index: &IndexHandle,
    _mempool: &MempoolHandle,
    params: &Value,
) -> Result<Value, ElectrumError> {
    ensure_array_len(params, 0)?;
    Ok(json!("bitcoin-rs electrum"))
}

pub(crate) fn server_donation_address(
    _index: &IndexHandle,
    _mempool: &MempoolHandle,
    params: &Value,
) -> Result<Value, ElectrumError> {
    ensure_array_len(params, 0)?;
    Ok(Value::new_null())
}

pub(crate) fn server_peers_subscribe(
    _index: &IndexHandle,
    _mempool: &MempoolHandle,
    params: &Value,
) -> Result<Value, ElectrumError> {
    ensure_array_len(params, 0)?;
    Ok(json!([]))
}

pub(crate) fn server_ping(
    _index: &IndexHandle,
    _mempool: &MempoolHandle,
    params: &Value,
) -> Result<Value, ElectrumError> {
    ensure_array_len(params, 0)?;
    Ok(Value::new_null())
}

pub(crate) fn scripthash_get_history(
    index: &IndexHandle,
    mempool: &MempoolHandle,
    params: &Value,
) -> Result<Value, ElectrumError> {
    let scripthash = parse_scripthash_param(params)?;
    let mut rows = Vec::new();
    for record in combined_history(index, mempool, scripthash) {
        rows.push(json!({"tx_hash": record.txid.to_string(), "height": record.height}));
    }
    Ok(json!(rows))
}

pub(crate) fn scripthash_get_balance(
    index: &IndexHandle,
    mempool: &MempoolHandle,
    params: &Value,
) -> Result<Value, ElectrumError> {
    let scripthash = parse_scripthash_param(params)?;
    let spends = mempool.mempool_spends();
    let mut confirmed = 0_u64;
    for record in index.confirmed_history(scripthash) {
        let spent_by_mempool = spends.contains(&OutPoint {
            txid: record.txid,
            vout: record.vout,
        });
        if !record.spent && !spent_by_mempool {
            confirmed = confirmed.saturating_add(record.value);
        }
    }
    let mut unconfirmed = 0_u64;
    for record in mempool.mempool_history(scripthash) {
        unconfirmed = unconfirmed.saturating_add(record.value);
    }
    Ok(json!({"confirmed": confirmed, "unconfirmed": unconfirmed}))
}

pub(crate) fn scripthash_subscribe(
    index: &IndexHandle,
    mempool: &MempoolHandle,
    params: &Value,
) -> Result<Value, ElectrumError> {
    let scripthash = parse_scripthash_param(params)?;
    Ok(status_json(index, mempool, scripthash))
}

pub(crate) fn scripthash_listunspent(
    index: &IndexHandle,
    mempool: &MempoolHandle,
    params: &Value,
) -> Result<Value, ElectrumError> {
    let scripthash = parse_scripthash_param(params)?;
    let spends = mempool.mempool_spends();
    let mut rows = Vec::new();
    for record in index.confirmed_history(scripthash) {
        if record.spent
            || spends.contains(&OutPoint {
                txid: record.txid,
                vout: record.vout,
            })
        {
            continue;
        }
        rows.push(json!({
            "tx_hash": record.txid.to_string(),
            "tx_pos": record.vout,
            "height": record.height,
            "value": record.value,
        }));
    }
    for record in mempool.mempool_history(scripthash) {
        rows.push(json!({
            "tx_hash": record.txid.to_string(),
            "tx_pos": record.vout,
            "height": record.height,
            "value": record.value,
        }));
    }
    Ok(json!(rows))
}

pub(crate) fn transaction_get(
    index: &IndexHandle,
    mempool: &MempoolHandle,
    params: &Value,
) -> Result<Value, ElectrumError> {
    let params = params_array(params)?;
    let txid = parse_txid(params.first(), "blockchain.transaction.get txid")?;
    if params
        .get(1)
        .and_then(JsonValueTrait::as_bool)
        .unwrap_or(false)
    {
        return Ok(
            json!({"txid": txid.to_string(), "hex": mempool.get_transaction_hex(&txid).or_else(|| index.get_transaction_hex(&txid))}),
        );
    }
    mempool
        .get_transaction_hex(&txid)
        .or_else(|| index.get_transaction_hex(&txid))
        .map(|hex| json!(hex))
        .ok_or(ElectrumError::InvalidParams("unknown transaction"))
}

pub(crate) fn transaction_broadcast(
    _index: &IndexHandle,
    mempool: &MempoolHandle,
    params: &Value,
) -> Result<Value, ElectrumError> {
    let params = params_array(params)?;
    let tx_hex =
        params
            .first()
            .and_then(JsonValueTrait::as_str)
            .ok_or(ElectrumError::InvalidParams(
                "blockchain.transaction.broadcast hex",
            ))?;
    let bytes = Vec::from_hex(tx_hex)
        .map_err(|error| ElectrumError::TransactionDecode(error.to_string()))?;
    let tx = deserialize::<Transaction>(&bytes)
        .map_err(|error| ElectrumError::TransactionDecode(error.to_string()))?;
    let txid = mempool.insert_transaction(tx, 0, 0, 0)?;
    Ok(json!(txid.to_string()))
}

pub(crate) fn estimate_fee(
    _index: &IndexHandle,
    _mempool: &MempoolHandle,
    params: &Value,
) -> Result<Value, ElectrumError> {
    let params = params_array(params)?;
    if params.len() != 1 || params.first().and_then(JsonValueTrait::as_u64).is_none() {
        return Err(ElectrumError::InvalidParams(
            "blockchain.estimatefee blocks",
        ));
    }
    Ok(json!(-1))
}

pub(crate) fn mempool_get_fee_histogram(
    _index: &IndexHandle,
    mempool: &MempoolHandle,
    params: &Value,
) -> Result<Value, ElectrumError> {
    ensure_array_len(params, 0)?;
    let rows = mempool
        .fee_histogram()
        .into_iter()
        .map(|(rate, vsize)| json!([rate, vsize]))
        .collect::<Vec<_>>();
    Ok(json!(rows))
}

pub(crate) fn block_headers(
    index: &IndexHandle,
    _mempool: &MempoolHandle,
    params: &Value,
) -> Result<Value, ElectrumError> {
    let params = params_array(params)?;
    let start = params
        .first()
        .and_then(JsonValueTrait::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or(ElectrumError::InvalidParams(
            "blockchain.block.headers start",
        ))?;
    let count = params
        .get(1)
        .and_then(JsonValueTrait::as_u64)
        .and_then(|value| usize::try_from(value).ok())
        .ok_or(ElectrumError::InvalidParams(
            "blockchain.block.headers count",
        ))?;
    let headers = index.headers();
    let end = start
        .saturating_add(count.min(MAX_HEADERS))
        .min(headers.len());
    let selected = if start >= headers.len() {
        &[]
    } else {
        &headers[start..end]
    };
    let mut hex = String::with_capacity(selected.len().saturating_mul(160));
    for header in selected {
        hex.push_str(&header.to_lower_hex_string());
    }
    Ok(json!({"count": selected.len(), "hex": hex, "max": MAX_HEADERS}))
}

pub(crate) fn headers_subscribe(
    index: &IndexHandle,
    _mempool: &MempoolHandle,
    params: &Value,
) -> Result<Value, ElectrumError> {
    ensure_array_len(params, 0)?;
    let headers = index.headers();
    let Some((height, header)) = headers.len().checked_sub(1).and_then(|height| {
        let height_u32 = u32::try_from(height).ok()?;
        Some((height_u32, headers[height]))
    }) else {
        return Ok(json!({"height": 0, "hex": ""}));
    };
    Ok(json!({"height": height, "hex": header.to_lower_hex_string()}))
}

/// Computes the current Electrum status value for `scripthash`.
pub fn status_json(index: &IndexHandle, mempool: &MempoolHandle, scripthash: ScriptHash) -> Value {
    match status_string(index, mempool, scripthash) {
        Some(status) => json!(status.as_str()),
        None => Value::new_null(),
    }
}

/// Computes the current Electrum status hash string for `scripthash`.
pub fn status_string(
    index: &IndexHandle,
    mempool: &MempoolHandle,
    scripthash: ScriptHash,
) -> Option<CompactString> {
    let entries = combined_history(index, mempool, scripthash)
        .into_iter()
        .filter_map(|record| history_entry(record).ok())
        .collect::<Vec<_>>();
    compute_status_hash(&entries).map(|hash| hash.to_compact_string())
}

fn history_entry(record: HistoryRecord) -> Result<HistoryEntry, ElectrumError> {
    if record.height > 0 {
        let height = u32::try_from(record.height)
            .map_err(|_| ElectrumError::InvalidParams("confirmed height exceeds u32"))?;
        return Ok(HistoryEntry::confirmed(record.txid, height));
    }
    Ok(HistoryEntry {
        txid: record.txid,
        height: HistoryHeight::Unconfirmed {
            has_unconfirmed_inputs: false,
        },
    })
}

fn combined_history(
    index: &IndexHandle,
    mempool: &MempoolHandle,
    scripthash: ScriptHash,
) -> Vec<HistoryRecord> {
    let mut records = index.confirmed_history(scripthash);
    records.extend(mempool.mempool_history(scripthash));
    records.sort_by_key(|record| (record.height, record.txid));
    records
}

/// Parses the first parameter as an Electrum scripthash.
pub fn parse_scripthash_param(params: &Value) -> Result<ScriptHash, ElectrumError> {
    let params = params_array(params)?;
    let hex = params
        .first()
        .and_then(JsonValueTrait::as_str)
        .ok_or(ElectrumError::InvalidParams("scripthash hex"))?;
    parse_scripthash_hex(hex)
}

/// Parses a 32-byte scripthash hex string.
pub fn parse_scripthash_hex(hex: &str) -> Result<ScriptHash, ElectrumError> {
    let bytes = Vec::from_hex(hex).map_err(|_| ElectrumError::InvalidParams("scripthash hex"))?;
    let array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| ElectrumError::InvalidParams("scripthash length"))?;
    Ok(ScriptHash::from_byte_array(array))
}

/// Formats a scripthash for Electrum JSON parameters.
#[must_use]
pub fn scripthash_hex(scripthash: ScriptHash) -> String {
    scripthash.to_byte_array().to_lower_hex_string()
}

fn parse_txid(value: Option<&Value>, label: &'static str) -> Result<Txid, ElectrumError> {
    let hex = value
        .and_then(JsonValueTrait::as_str)
        .ok_or(ElectrumError::InvalidParams(label))?;
    hex.parse::<Txid>()
        .map_err(|_| ElectrumError::InvalidParams(label))
}

fn params_array(params: &Value) -> Result<&sonic_rs::Array, ElectrumError> {
    params
        .as_array()
        .ok_or(ElectrumError::InvalidParams("params must be an array"))
}

fn ensure_array_len(params: &Value, len: usize) -> Result<(), ElectrumError> {
    let params = params_array(params)?;
    if params.len() == len {
        Ok(())
    } else {
        Err(ElectrumError::InvalidParams("unexpected parameter count"))
    }
}
