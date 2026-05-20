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
const DEFAULT_RELAY_FEE_BTC_PER_KVB: f64 = 0.00001;

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

/// Read-side history reader for the Electrum scripthash RPCs.
///
/// Implementations resolve the lossy index prefix back to full transaction
/// identities via a [`bitcoin_rs_index::BlockSource`]. Used by
/// [`IndexHandle::confirmed_history`] to prefer real index reads over the
/// synthetic in-memory fallback.
pub trait ConfirmedHistoryReader: Send + Sync + core::fmt::Debug {
    /// Returns confirmed history records for `scripthash`, in iteration order
    /// of the index. Empty [`Vec`] on missing data.
    fn confirmed_history(&self, scripthash: ScriptHash) -> Vec<HistoryRecord>;
    /// Returns confirmed unspent-output records for `scripthash`.
    ///
    /// Resolves the lossy 8-byte prefix to full `(txid, vout, value_sats)`
    /// triples via the wrapped `BlockSource` and filters out outpoints with
    /// any matching spending row. Empty [`Vec`] on missing data.
    fn unspent_outputs(&self, _scripthash: ScriptHash) -> Vec<HistoryRecord> {
        Vec::new()
    }
    /// Returns the lowercase-hex serialized confirmed transaction for `txid`,
    /// resolved via the underlying index + `BlockSource`. `None` if not found.
    fn transaction_hex(&self, txid: bitcoin::Txid) -> Option<String> {
        let _ = txid;
        None
    }
    /// Returns the Bitcoin block at `height` (active chain), or `None` if not
    /// available via the underlying `BlockSource`.
    fn block_at_height(&self, height: u32) -> Option<bitcoin::Block> {
        let _ = height;
        None
    }
}

/// `ConfirmedHistoryReader` backed by a workspace `Indexer` and a `BlockSource`.
pub struct IndexerHistoryReader<S, B>
where
    S: bitcoin_rs_storage::KvStore + Send + Sync + 'static,
    B: bitcoin_rs_index::BlockSource + Send + Sync + 'static,
{
    indexer: Arc<bitcoin_rs_index::Indexer<S>>,
    block_source: B,
}

impl<S, B> IndexerHistoryReader<S, B>
where
    S: bitcoin_rs_storage::KvStore + Send + Sync + 'static,
    B: bitcoin_rs_index::BlockSource + Send + Sync + 'static,
{
    /// Builds a reader over `indexer` and `block_source`.
    #[must_use]
    pub const fn new(indexer: Arc<bitcoin_rs_index::Indexer<S>>, block_source: B) -> Self {
        Self {
            indexer,
            block_source,
        }
    }
}

impl<S, B> core::fmt::Debug for IndexerHistoryReader<S, B>
where
    S: bitcoin_rs_storage::KvStore + Send + Sync + 'static,
    B: bitcoin_rs_index::BlockSource + Send + Sync + 'static,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("IndexerHistoryReader")
            .finish_non_exhaustive()
    }
}

impl<S, B> ConfirmedHistoryReader for IndexerHistoryReader<S, B>
where
    S: bitcoin_rs_storage::KvStore + Send + Sync + 'static,
    B: bitcoin_rs_index::BlockSource + Send + Sync + 'static,
{
    fn confirmed_history(&self, scripthash: ScriptHash) -> Vec<HistoryRecord> {
        let Ok(entries) = self
            .indexer
            .resolve_script_history(scripthash, &self.block_source)
        else {
            return Vec::new();
        };

        entries
            .into_iter()
            .map(|entry| {
                let height = match entry.height {
                    bitcoin_rs_index::HistoryHeight::Confirmed(h) => i64::from(h),
                    bitcoin_rs_index::HistoryHeight::Unconfirmed {
                        has_unconfirmed_inputs: true,
                    } => -1,
                    bitcoin_rs_index::HistoryHeight::Unconfirmed {
                        has_unconfirmed_inputs: false,
                    } => 0,
                };
                HistoryRecord {
                    txid: entry.txid,
                    height,
                    value: 0,
                    vout: 0,
                    spent: false,
                }
            })
            .collect()
    }
    fn transaction_hex(&self, txid: bitcoin::Txid) -> Option<String> {
        let tx = self
            .indexer
            .resolve_transaction(txid, &self.block_source)
            .ok()
            .flatten()?;
        Some(serialize(&tx).to_lower_hex_string())
    }

    fn block_at_height(&self, height: u32) -> Option<bitcoin::Block> {
        self.block_source.block_at_height(height)
    }

    fn unspent_outputs(&self, scripthash: ScriptHash) -> Vec<HistoryRecord> {
        let Ok(outputs) = self
            .indexer
            .resolve_unspent_outputs_with_height(scripthash, &self.block_source)
        else {
            return Vec::new();
        };

        let mut records = Vec::with_capacity(outputs.len());
        for (txid, vout, value, height) in outputs {
            let outpoint = bitcoin::OutPoint { txid, vout };
            let spent = self
                .indexer
                .iter_spending_rows(&outpoint)
                .map(|rows| !rows.is_empty())
                .unwrap_or(false);
            if spent {
                continue;
            }
            let height_i64 = i64::from(height);
            records.push(HistoryRecord {
                txid,
                height: height_i64,
                value,
                vout,
                spent: false,
            });
        }
        records
    }
}

/// Electrum history row exposed by scripthash history RPCs.
#[derive(Copy, Clone, Debug)]
pub struct HistoryRecord {
    /// Transaction identifier.
    pub txid: Txid,
    /// Electrum history height: confirmed height, `0` for local mempool, `-1` for unconfirmed inputs.
    pub height: i64,
    /// Output value in satoshis when known.
    pub value: u64,
    /// Output index when known.
    pub vout: u32,
    /// Whether the output is spent.
    pub spent: bool,
}

struct IndexState {
    histories: RwLock<HashMap<ScriptHash, Vec<HistoryRecord>>>,
    transactions: RwLock<HashMap<Txid, Vec<u8>>>,
    headers: RwLock<Vec<[u8; 80]>>,
    store: RwLock<Option<Arc<dyn IndexReader>>>,
    reader: RwLock<Option<Arc<dyn ConfirmedHistoryReader>>>,
    network: RwLock<bitcoin::Network>,
}

impl Default for IndexState {
    fn default() -> Self {
        Self {
            histories: RwLock::new(HashMap::new()),
            transactions: RwLock::new(HashMap::new()),
            headers: RwLock::new(Vec::new()),
            store: RwLock::new(None),
            reader: RwLock::new(None),
            network: RwLock::new(bitcoin::Network::Bitcoin),
        }
    }
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

    /// Attaches a `ConfirmedHistoryReader` to this handle.
    ///
    /// When set, `confirmed_history` calls the reader instead of returning rows
    /// from the synthetic in-memory map.
    #[must_use]
    pub fn with_history_reader(self, reader: Arc<dyn ConfirmedHistoryReader>) -> Self {
        *self.state.reader.write() = Some(reader);
        self
    }

    /// Configures the chain selector used by network-aware methods like
    /// `server.features.genesis_hash`. Default is mainnet.
    #[must_use]
    pub fn with_network(self, network: bitcoin::Network) -> Self {
        *self.state.network.write() = network;
        self
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
        let reader = self.state.reader.read().clone();
        if let Some(reader) = reader {
            return reader.confirmed_history(scripthash);
        }

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

    pub(crate) fn unspent_outputs(&self, scripthash: ScriptHash) -> Vec<HistoryRecord> {
        let reader = self.state.reader.read().clone();
        if let Some(reader) = reader {
            return reader.unspent_outputs(scripthash);
        }

        Vec::new()
    }

    /// Returns the lowercase-hex serialized confirmed transaction for `txid`.
    ///
    /// Prefers a reader-backed lookup when one is attached via `with_history_reader`;
    /// otherwise falls back to the synthetic in-memory transactions map.
    #[must_use]
    pub fn transaction_hex(&self, txid: &Txid) -> Option<String> {
        if let Some(reader) = self.state.reader.read().clone()
            && let Some(hex) = reader.transaction_hex(*txid)
        {
            return Some(hex);
        }
        self.state
            .transactions
            .read()
            .get(txid)
            .map(|bytes| bytes.as_slice().to_lower_hex_string())
    }

    /// Returns the Bitcoin block at `height` via the attached `ConfirmedHistoryReader`'s
    /// `BlockSource`. Returns `None` when no reader is attached or no block at that height.
    #[must_use]
    pub fn block_at_height(&self, height: u32) -> Option<bitcoin::Block> {
        self.state.reader.read().clone()?.block_at_height(height)
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

    /// Builds a handle that shares an existing `Arc<RwLock<Mempool>>`.
    ///
    /// Use this constructor when the mempool is owned elsewhere (e.g. by
    /// `bitcoin_rs_node::NodeState`) and the Electrum server must observe
    /// the same transactions the rest of the node sees.
    #[must_use]
    pub const fn from_arc(pool: Arc<RwLock<Mempool>>) -> Self {
        Self { pool }
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
        pool.entry_by_txid(txid)
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
        "server.features" => server_features(index, mempool, params),
        "server.donation_address" => server_donation_address(index, mempool, params),
        "server.peers.subscribe" => server_peers_subscribe(index, mempool, params),
        "server.ping" => server_ping(index, mempool, params),
        "server.add_peer" => server_add_peer(index, mempool, params),
        "blockchain.scripthash.get_history" => scripthash_get_history(index, mempool, params),
        "blockchain.scripthash.get_balance" => scripthash_get_balance(index, mempool, params),
        "blockchain.scripthash.subscribe" => scripthash_subscribe(index, mempool, params),
        "blockchain.scripthash.unsubscribe" => scripthash_unsubscribe(index, mempool, params),
        "blockchain.scripthash.listunspent" => scripthash_listunspent(index, mempool, params),
        "blockchain.transaction.get" => transaction_get(index, mempool, params),
        "blockchain.transaction.get_merkle" => transaction_get_merkle(index, mempool, params),
        "blockchain.transaction.id_from_pos" => transaction_id_from_pos(index, mempool, params),
        "blockchain.transaction.broadcast" => transaction_broadcast(index, mempool, params),
        "blockchain.estimatefee" => estimate_fee(index, mempool, params),
        "blockchain.relayfee" => blockchain_relayfee(index, mempool, params),
        "mempool.get_fee_histogram" => mempool_get_fee_histogram(index, mempool, params),
        "blockchain.block.header" => block_header(index, mempool, params),
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

pub(crate) fn server_features(
    index: &IndexHandle,
    _mempool: &MempoolHandle,
    params: &Value,
) -> Result<Value, ElectrumError> {
    ensure_array_len(params, 0)?;
    let network = *index.state.network.read();
    let genesis_hash = bitcoin::blockdata::constants::genesis_block(network)
        .block_hash()
        .to_string();
    Ok(json!({
        "hosts": json!({}),
        "pruning": Value::new_null(),
        "genesis_hash": genesis_hash,
        "server_version": SERVER_VERSION,
        "protocol_min": PROTOCOL_VERSION,
        "protocol_max": PROTOCOL_VERSION,
        "hash_function": "sha256",
    }))
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
pub(crate) fn server_add_peer(
    _index: &IndexHandle,
    _mempool: &MempoolHandle,
    params: &Value,
) -> Result<Value, ElectrumError> {
    // We don't track Electrum-server peers; reject the advert per electrs's
    // behavior. The params shape is the advertised peer's features object;
    // we accept any well-formed array (even with extra args).
    if params.is_null() {
        return Err(ElectrumError::InvalidParams(
            "server.add_peer expects an array",
        ));
    }
    Ok(json!(false))
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
    let reader_records = index.unspent_outputs(scripthash);
    if reader_records.is_empty() {
        // Fallback: synthetic confirmed_history path.
        for record in index.confirmed_history(scripthash) {
            let spent_by_mempool = spends.contains(&OutPoint {
                txid: record.txid,
                vout: record.vout,
            });
            if !record.spent && !spent_by_mempool {
                confirmed = confirmed.saturating_add(record.value);
            }
        }
    } else {
        for record in reader_records {
            let spent_by_mempool = spends.contains(&OutPoint {
                txid: record.txid,
                vout: record.vout,
            });
            if !spent_by_mempool {
                confirmed = confirmed.saturating_add(record.value);
            }
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
pub(crate) fn scripthash_unsubscribe(
    _index: &IndexHandle,
    _mempool: &MempoolHandle,
    params: &Value,
) -> Result<Value, ElectrumError> {
    // Validate the scripthash format; we don't track per-session subscriptions
    // in this dispatch, so always confirm the unsubscribe. Matches electrs' v1.4
    // behavior where unsubscribe is best-effort.
    let _scripthash = parse_scripthash_param(params)?;
    Ok(json!(true))
}

pub(crate) fn scripthash_listunspent(
    index: &IndexHandle,
    mempool: &MempoolHandle,
    params: &Value,
) -> Result<Value, ElectrumError> {
    let scripthash = parse_scripthash_param(params)?;
    let spends = mempool.mempool_spends();
    let mut rows = Vec::new();
    // Prefer reader-backed (real index) data when set.
    let reader_records = index.unspent_outputs(scripthash);
    let confirmed_iter: Box<dyn Iterator<Item = HistoryRecord>> = if reader_records.is_empty() {
        Box::new(index.confirmed_history(scripthash).into_iter())
    } else {
        Box::new(reader_records.into_iter())
    };
    for record in confirmed_iter {
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
            "value": record.value,
            "height": record.height,
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
    let hex = index
        .transaction_hex(&txid)
        .or_else(|| mempool.get_transaction_hex(&txid))
        .ok_or(ElectrumError::InvalidParams("transaction not found"))?;
    if params
        .get(1)
        .and_then(JsonValueTrait::as_bool)
        .unwrap_or(false)
    {
        return Ok(json!({"txid": txid.to_string(), "hex": hex}));
    }
    Ok(json!(hex))
}

fn merkle_inclusion_proof(txdata: &[Transaction], pos: usize) -> Option<Vec<String>> {
    use bitcoin::hashes::{Hash as _, sha256d};

    if pos >= txdata.len() {
        return None;
    }

    let mut current: Vec<sha256d::Hash> = txdata
        .iter()
        .map(|tx| tx.compute_txid().to_raw_hash())
        .collect();
    let mut current_pos = pos;
    let mut path = Vec::new();
    while current.len() > 1 {
        if !current.len().is_multiple_of(2) {
            let last = current[current.len() - 1];
            current.push(last);
        }

        let sibling_idx = if current_pos.is_multiple_of(2) {
            current_pos + 1
        } else {
            current_pos - 1
        };
        if let Some(sibling) = current.get(sibling_idx).copied() {
            path.push(sibling.to_byte_array().to_lower_hex_string());
        }

        let mut next = Vec::with_capacity(current.len() / 2);
        for pair in current.chunks(2) {
            let mut combined = Vec::with_capacity(64);
            combined.extend_from_slice(pair[0].as_byte_array());
            combined.extend_from_slice(pair[1].as_byte_array());
            next.push(sha256d::Hash::hash(&combined));
        }
        current = next;
        current_pos /= 2;
    }
    Some(path)
}

pub(crate) fn transaction_get_merkle(
    index: &IndexHandle,
    _mempool: &MempoolHandle,
    params: &Value,
) -> Result<Value, ElectrumError> {
    let array = params_array(params)?;
    let txid = parse_txid(array.first(), "blockchain.transaction.get_merkle txid")?;
    let height_u64 =
        array
            .get(1)
            .and_then(JsonValueTrait::as_u64)
            .ok_or(ElectrumError::InvalidParams(
                "transaction.get_merkle height",
            ))?;
    let Ok(height) = u32::try_from(height_u64) else {
        return Err(ElectrumError::InvalidParams("height exceeds u32"));
    };
    let Some(block) = index.block_at_height(height) else {
        return Err(ElectrumError::InvalidParams(
            "block at height not available",
        ));
    };
    let Some(pos) = block.txdata.iter().position(|t| t.compute_txid() == txid) else {
        return Err(ElectrumError::InvalidParams("txid not in block"));
    };
    let merkle = merkle_inclusion_proof(&block.txdata, pos).unwrap_or_default();
    Ok(json!({
        "block_height": height,
        "merkle": merkle,
        "pos": pos,
    }))
}

pub(crate) fn transaction_id_from_pos(
    index: &IndexHandle,
    _mempool: &MempoolHandle,
    params: &Value,
) -> Result<Value, ElectrumError> {
    let array = params_array(params)?;
    let height_u64 =
        array
            .first()
            .and_then(JsonValueTrait::as_u64)
            .ok_or(ElectrumError::InvalidParams(
                "transaction.id_from_pos height",
            ))?;
    let pos_u64 =
        array
            .get(1)
            .and_then(JsonValueTrait::as_u64)
            .ok_or(ElectrumError::InvalidParams(
                "transaction.id_from_pos tx_pos",
            ))?;
    let Ok(height) = u32::try_from(height_u64) else {
        return Err(ElectrumError::InvalidParams("height exceeds u32"));
    };
    let Ok(pos) = usize::try_from(pos_u64) else {
        return Err(ElectrumError::InvalidParams("tx_pos exceeds usize"));
    };
    let Some(block) = index.block_at_height(height) else {
        return Err(ElectrumError::InvalidParams(
            "block at height not available",
        ));
    };
    let Some(tx) = block.txdata.get(pos) else {
        return Err(ElectrumError::InvalidParams("tx_pos out of range"));
    };
    let merkle_requested = array
        .get(2)
        .and_then(JsonValueTrait::as_bool)
        .unwrap_or(false);
    if merkle_requested {
        let merkle = merkle_inclusion_proof(&block.txdata, pos).unwrap_or_default();
        Ok(json!({
            "tx_hash": tx.compute_txid().to_string(),
            "merkle": merkle,
        }))
    } else {
        Ok(json!(tx.compute_txid().to_string()))
    }
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
    let placeholder_fee = u64::try_from(tx.vsize()).unwrap_or(u64::MAX);
    let txid = mempool.insert_transaction(tx, placeholder_fee, 0, 0)?;
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

pub(crate) fn blockchain_relayfee(
    _index: &IndexHandle,
    _mempool: &MempoolHandle,
    params: &Value,
) -> Result<Value, ElectrumError> {
    ensure_array_len(params, 0)?;
    Ok(json!(DEFAULT_RELAY_FEE_BTC_PER_KVB))
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

pub(crate) fn block_header(
    index: &IndexHandle,
    _mempool: &MempoolHandle,
    params: &Value,
) -> Result<Value, ElectrumError> {
    let array = params_array(params)?;
    let height =
        array
            .first()
            .and_then(JsonValueTrait::as_u64)
            .ok_or(ElectrumError::InvalidParams(
                "blockchain.block.header height",
            ))?;
    let headers = index.headers();
    let Ok(index_usize) = usize::try_from(height) else {
        return Err(ElectrumError::InvalidParams("height exceeds usize"));
    };
    let Some(header) = headers.get(index_usize) else {
        return Err(ElectrumError::InvalidParams("height out of range"));
    };
    Ok(json!(header.to_lower_hex_string()))
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

#[cfg(test)]
mod tests {
    use super::{Arc, Mempool, MempoolHandle, MempoolLimits, RwLock};

    #[test]
    fn from_arc_reuses_existing_mempool_allocation() {
        let pool = Arc::new(RwLock::new(Mempool::new(MempoolLimits::default())));

        let handle = MempoolHandle::from_arc(Arc::clone(&pool));

        assert!(Arc::ptr_eq(&pool, &handle.pool));
    }
}

#[cfg(test)]
mod server_features_tests {
    use super::*;

    #[test]
    fn server_features_returns_protocol_version_and_genesis_hash() {
        let index = IndexHandle::new();
        let mempool = MempoolHandle::default();
        let result = dispatch("server.features", &index, &mempool, &json!([]))
            .unwrap_or_else(|err| panic!("server.features failed: {err}"));
        let Some(genesis) = result.get("genesis_hash").and_then(JsonValueTrait::as_str) else {
            panic!("genesis_hash missing: {result:?}");
        };
        // Bitcoin mainnet genesis (big-endian display).
        assert_eq!(
            genesis,
            "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f"
        );
        let Some(protocol_min) = result.get("protocol_min").and_then(JsonValueTrait::as_str) else {
            panic!("protocol_min missing: {result:?}");
        };
        assert_eq!(protocol_min, "1.4");
    }

    #[test]
    fn server_features_uses_configured_network_genesis() {
        let index = IndexHandle::new().with_network(bitcoin::Network::Regtest);
        let mempool = MempoolHandle::default();
        let result = dispatch("server.features", &index, &mempool, &json!([]))
            .unwrap_or_else(|err| panic!("server.features failed: {err}"));
        let Some(genesis) = result.get("genesis_hash").and_then(JsonValueTrait::as_str) else {
            panic!("genesis_hash missing: {result:?}");
        };
        let expected = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest)
            .block_hash()
            .to_string();
        assert_eq!(genesis, expected);
    }
}

#[cfg(test)]
mod server_add_peer_tests {
    use super::*;

    #[test]
    fn server_add_peer_returns_false() {
        let index = IndexHandle::new();
        let mempool = MempoolHandle::default();
        let result = dispatch("server.add_peer", &index, &mempool, &json!([{}]))
            .unwrap_or_else(|err| panic!("server.add_peer failed: {err}"));
        assert_eq!(result.as_bool(), Some(false));
    }

    #[test]
    fn server_add_peer_rejects_null_params() {
        let index = IndexHandle::new();
        let mempool = MempoolHandle::default();
        let result = dispatch("server.add_peer", &index, &mempool, &Value::new_null());
        assert!(result.is_err());
    }
}

#[cfg(test)]
mod blockchain_relayfee_tests {
    use super::*;

    #[test]
    fn blockchain_relayfee_returns_default() {
        let index = IndexHandle::new();
        let mempool = MempoolHandle::default();
        let result = dispatch("blockchain.relayfee", &index, &mempool, &json!([]))
            .unwrap_or_else(|err| panic!("blockchain.relayfee failed: {err}"));
        let Some(rate) = result.as_f64() else {
            panic!("relayfee not numeric: {result:?}");
        };
        assert!(
            (rate - 0.00001).abs() < 1e-9,
            "expected ~0.00001, got {rate}"
        );
    }
}

#[cfg(test)]
mod history_reader_tests {
    use super::*;
    use alloc::sync::Arc;

    #[derive(Debug)]
    struct StubReader;

    impl ConfirmedHistoryReader for StubReader {
        fn confirmed_history(&self, _: ScriptHash) -> Vec<HistoryRecord> {
            use bitcoin::hashes::Hash as _;

            let mut hash = [0_u8; 32];
            hash[0] = 0xff;
            let txid = bitcoin::Txid::from_byte_array(hash);
            vec![HistoryRecord {
                txid,
                height: 7,
                value: 0,
                vout: 0,
                spent: false,
            }]
        }
    }

    #[derive(Debug)]
    struct StubReaderUnspent;

    impl ConfirmedHistoryReader for StubReaderUnspent {
        fn confirmed_history(&self, _: ScriptHash) -> Vec<HistoryRecord> {
            Vec::new()
        }

        fn unspent_outputs(&self, _: ScriptHash) -> Vec<HistoryRecord> {
            use bitcoin::hashes::Hash as _;

            let mut hash = [0_u8; 32];
            hash[0] = 0xfe;
            let txid = bitcoin::Txid::from_byte_array(hash);
            vec![HistoryRecord {
                txid,
                height: 0,
                value: 100_000,
                vout: 0,
                spent: false,
            }]
        }
    }

    #[derive(Debug)]
    struct StubReaderTxHex;

    impl ConfirmedHistoryReader for StubReaderTxHex {
        fn confirmed_history(&self, _: ScriptHash) -> Vec<HistoryRecord> {
            Vec::new()
        }

        fn transaction_hex(&self, _: bitcoin::Txid) -> Option<String> {
            Some("deadbeef".to_owned())
        }
    }

    #[test]
    fn with_history_reader_overrides_synthetic_history() {
        use bitcoin::hashes::Hash as _;

        let handle = IndexHandle::new().with_history_reader(Arc::new(StubReader));
        let mut scripthash_bytes = [0_u8; 32];
        scripthash_bytes[0] = 0xab;
        let scripthash = ScriptHash::from_byte_array(scripthash_bytes);

        let mut synthetic_txid_bytes = [0_u8; 32];
        synthetic_txid_bytes[0] = 0x11;
        handle.add_history_entry(
            scripthash,
            bitcoin::Txid::from_byte_array(synthetic_txid_bytes),
            3,
            100,
            1,
            true,
        );

        let records = handle.confirmed_history(scripthash);

        assert_eq!(records.len(), 1);
        assert!(records.iter().any(|record| record.height == 7));
    }

    #[test]
    fn transaction_hex_prefers_reader_over_synthetic() {
        use bitcoin::hashes::Hash as _;

        let handle = IndexHandle::new().with_history_reader(Arc::new(StubReaderTxHex));
        let mut hash = [0_u8; 32];
        hash[0] = 0xee;
        let txid = bitcoin::Txid::from_byte_array(hash);
        let hex = handle.transaction_hex(&txid);

        assert_eq!(hex.as_deref(), Some("deadbeef"));
    }

    #[test]
    fn unspent_outputs_reader_drives_scripthash_listunspent() {
        let handle = IndexHandle::new().with_history_reader(Arc::new(StubReaderUnspent));
        let mempool = MempoolHandle::default();
        let mut scripthash_bytes = [0_u8; 32];
        scripthash_bytes[0] = 0xcc;
        let params = json!([scripthash_bytes.to_lower_hex_string()]);

        let result = scripthash_listunspent(&handle, &mempool, &params)
            .unwrap_or_else(|err| panic!("listunspent failed: {err}"));
        let rows = result
            .as_array()
            .unwrap_or_else(|| panic!("expected array"));

        assert_eq!(rows.len(), 1, "expected one row: {result:?}");
    }
}

#[cfg(test)]
mod id_from_pos_tests {
    use super::*;
    use alloc::sync::Arc;

    #[derive(Debug)]
    struct StubReader;

    impl ConfirmedHistoryReader for StubReader {
        fn confirmed_history(&self, _: ScriptHash) -> Vec<HistoryRecord> {
            Vec::new()
        }

        fn block_at_height(&self, height: u32) -> Option<bitcoin::Block> {
            if height == 0 {
                Some(bitcoin::blockdata::constants::genesis_block(
                    bitcoin::Network::Regtest,
                ))
            } else {
                None
            }
        }
    }

    #[test]
    fn id_from_pos_returns_txid_for_genesis_coinbase() {
        let index = IndexHandle::new().with_history_reader(Arc::new(StubReader));
        let mempool = MempoolHandle::default();
        let result = dispatch(
            "blockchain.transaction.id_from_pos",
            &index,
            &mempool,
            &json!([0, 0]),
        )
        .unwrap_or_else(|err| panic!("id_from_pos failed: {err}"));
        let Some(txid_hex) = result.as_str() else {
            panic!("expected string: {result:?}");
        };
        let expected = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest)
            .txdata
            .first()
            .unwrap_or_else(|| panic!("genesis has no tx"))
            .compute_txid()
            .to_string();
        assert_eq!(txid_hex, expected);
    }

    #[test]
    fn id_from_pos_rejects_out_of_range_pos() {
        let index = IndexHandle::new().with_history_reader(Arc::new(StubReader));
        let mempool = MempoolHandle::default();
        let result = dispatch(
            "blockchain.transaction.id_from_pos",
            &index,
            &mempool,
            &json!([0, 999]),
        );
        assert!(result.is_err());
    }
}

#[cfg(test)]
mod merkle_proof_tests {
    use super::*;
    use alloc::sync::Arc;

    #[derive(Debug)]
    struct StubReaderRegtestGenesis;

    impl ConfirmedHistoryReader for StubReaderRegtestGenesis {
        fn confirmed_history(&self, _: ScriptHash) -> Vec<HistoryRecord> {
            Vec::new()
        }

        fn block_at_height(&self, height: u32) -> Option<bitcoin::Block> {
            if height == 0 {
                Some(bitcoin::blockdata::constants::genesis_block(
                    bitcoin::Network::Regtest,
                ))
            } else {
                None
            }
        }
    }

    #[test]
    fn transaction_get_merkle_returns_proof_for_genesis_coinbase() {
        let index = IndexHandle::new().with_history_reader(Arc::new(StubReaderRegtestGenesis));
        let mempool = MempoolHandle::default();
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let Some(coinbase) = genesis.txdata.first() else {
            panic!("genesis has no tx");
        };
        let txid_hex = coinbase.compute_txid().to_string();
        let result = dispatch(
            "blockchain.transaction.get_merkle",
            &index,
            &mempool,
            &json!([txid_hex, 0]),
        )
        .unwrap_or_else(|err| panic!("get_merkle failed: {err}"));
        assert!(result.get("merkle").is_some());
        assert_eq!(result.get("pos").and_then(JsonValueTrait::as_u64), Some(0));
        assert_eq!(
            result.get("block_height").and_then(JsonValueTrait::as_u64),
            Some(0)
        );
    }
}
#[cfg(test)]
mod block_header_tests {
    use super::*;

    #[test]
    fn block_header_returns_synthetic_header_hex() {
        let index = IndexHandle::new();
        index.add_header(0, [0xab_u8; 80]);
        let mempool = MempoolHandle::default();
        let result = dispatch("blockchain.block.header", &index, &mempool, &json!([0]))
            .unwrap_or_else(|err| panic!("block.header failed: {err}"));
        let Some(hex) = result.as_str() else {
            panic!("expected hex string: {result:?}");
        };
        // 80 bytes hex-encoded = 160 chars, all 'ab'.
        assert_eq!(hex.len(), 160);
        assert!(hex.starts_with("ab"));
    }

    #[test]
    fn block_header_rejects_out_of_range_height() {
        let index = IndexHandle::new();
        let mempool = MempoolHandle::default();
        let result = dispatch(
            "blockchain.block.header",
            &index,
            &mempool,
            &json!([999_999]),
        );
        assert!(result.is_err());
    }
}
#[cfg(test)]
mod scripthash_unsubscribe_tests {
    use super::*;

    #[test]
    fn scripthash_unsubscribe_returns_true() {
        let index = IndexHandle::new();
        let mempool = MempoolHandle::default();
        let scripthash_hex = [0xee_u8; 32].to_lower_hex_string();
        let result = dispatch(
            "blockchain.scripthash.unsubscribe",
            &index,
            &mempool,
            &json!([scripthash_hex]),
        )
        .unwrap_or_else(|err| panic!("unsubscribe failed: {err}"));

        assert_eq!(result.as_bool(), Some(true));
    }

    #[test]
    fn scripthash_unsubscribe_rejects_invalid_hex() {
        let index = IndexHandle::new();
        let mempool = MempoolHandle::default();
        let result = dispatch(
            "blockchain.scripthash.unsubscribe",
            &index,
            &mempool,
            &json!(["not hex"]),
        );

        assert!(result.is_err());
    }
}
