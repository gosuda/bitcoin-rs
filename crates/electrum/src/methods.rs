use alloc::sync::Arc;
use core::fmt;

use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::hex::{DisplayHex as _, FromHex as _};
use bitcoin::{OutPoint, Transaction, Txid};
use bitcoin_rs_index::{HistoryEntry, ScriptHash, compute_status_hash};
use bitcoin_rs_mempool::{Mempool, MempoolEntry, MempoolLimits};
use compact_str::{CompactString, ToCompactString};
use hashbrown::HashMap;
use parking_lot::RwLock;
use sonic_rs::{JsonContainerTrait as _, JsonValueTrait, Value, json};
use thiserror::Error;

const PROTOCOL_VERSION: &str = "1.4";
const SERVER_VERSION: &str = concat!("bitcoin-rs-electrum/", env!("CARGO_PKG_VERSION"));
const MAX_HEADERS: usize = 2_016;
const MAX_BROADCAST_INPUTS: usize = 4_096;
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
    Storage(#[from] bitcoin_rs_storage::StorageError),
    /// Transaction payload could not be decoded.
    #[error("transaction decode error: {0}")]
    TransactionDecode(String),
    /// I/O failed while serving a session.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    /// JSON parsing or serialization failed.
    #[error("json error: {0}")]
    Json(#[from] sonic_rs::Error),
    /// TLS failed while accepting a session.
    #[error("tls error: {0}")]
    Tls(#[from] rustls::Error),
    /// A transient query-unavailable condition; subscription polling should
    /// preserve prior state and emit no notification.
    #[error("unavailable: {0}")]
    Unavailable(CompactString),
    /// A requested resource was not found.
    #[error("not found: {0}")]
    NotFound(&'static str),
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
            | Self::Tls(_)
            | Self::Unavailable(_)
            | Self::NotFound(_) => 1,
        }
    }
}

/// Status reported by the node-owned transaction index.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TxIndexInfo {
    /// Whether the index has completely caught up to the authoritative chain tip.
    pub synced: bool,
    /// Height of the best block completely covered by the index.
    pub best_block_height: u32,
}

/// Complete, lockless transaction-index query adapter for Electrum scripthash/tx methods.
///
/// Implementations return explicit errors for incomplete states and never silently
/// return empty/None for data that is still catching up.
pub trait ConfirmedHistoryReader: Send + Sync + core::fmt::Debug {
    /// Returns a point-in-time snapshot of `scripthash` confirmed history and
    /// unspent outputs. Both vectors come from the same storage revision, so the
    /// unspent set is consistent with the history it corresponds to.
    fn confirmed_history_snapshot(
        &self,
        scripthash: ScriptHash,
    ) -> Result<ConfirmedHistorySnapshot, ElectrumError>;
    /// Returns confirmed unspent-output records for `scripthash`.
    fn unspent_outputs(&self, scripthash: ScriptHash) -> Result<Vec<HistoryRecord>, ElectrumError>;
    /// Returns the lowercase-hex serialized confirmed transaction for `txid`.
    fn transaction_hex(&self, txid: &Txid) -> Result<String, ElectrumError>;
    /// Returns the satoshi value of the transaction output at `op`.
    ///
    /// `Ok(None)` means the outpoint is proven absent or out of range.
    fn outpoint_value(&self, op: &bitcoin::OutPoint) -> Result<Option<u64>, ElectrumError>;
    /// Returns the durable sync status and best indexed height of the index.
    fn index_info(&self) -> Result<TxIndexInfo, ElectrumError>;
}

/// Authoritative chain adapter for Electrum header/block/merkle methods.
///
/// Implementations MUST read from the node-owned block tree, never from the
/// transaction index.
pub trait BlockTreeAdapter: Send + Sync + core::fmt::Debug {
    /// Returns the height and raw 80-byte header of the active chain tip.
    fn tip(&self) -> Result<(u32, [u8; 80]), ElectrumError>;
    /// Returns the raw 80-byte header at `height` on the active chain.
    fn header_at(&self, height: u32) -> Result<[u8; 80], ElectrumError>;
    /// Returns up to `count` raw 80-byte headers starting at `height`.
    fn headers_range(&self, start: u32, count: usize) -> Result<Vec<[u8; 80]>, ElectrumError>;
    /// Returns the full block at `height` on the active chain.
    fn block_at(&self, height: u32) -> Result<bitcoin::Block, ElectrumError>;
    /// Returns the active-chain genesis block hash.
    fn genesis_hash(&self) -> Result<bitcoin::BlockHash, ElectrumError>;
}

/// Electrum history row exposed by scripthash history RPCs.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
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
/// Point-in-time snapshot of a scripthash's confirmed history and unspent outputs.
///
/// This is the one-snapshot invariant: both `history` and `unspent` come from
/// the same storage revision, so the unspent set is consistent with the history
/// it corresponds to.
#[derive(Clone, Debug, Default)]
pub struct ConfirmedHistorySnapshot {
    /// All confirmed history records (funding and spending) sorted by
    /// `(height, txid)` and deduplicated.
    pub history: Vec<HistoryRecord>,
    /// Confirmed unspent output records from the same revision.
    pub unspent: Vec<HistoryRecord>,
}

#[derive(Debug)]
struct IndexState {
    histories: RwLock<HashMap<ScriptHash, Vec<HistoryRecord>>>,
    transactions: RwLock<HashMap<Txid, Vec<u8>>>,
    headers: RwLock<Vec<[u8; 80]>>,
    network: RwLock<bitcoin::Network>,
}

impl Default for IndexState {
    fn default() -> Self {
        Self {
            histories: RwLock::new(HashMap::new()),
            transactions: RwLock::new(HashMap::new()),
            headers: RwLock::new(Vec::new()),
            network: RwLock::new(bitcoin::Network::Bitcoin),
        }
    }
}

/// In-memory `ConfirmedHistoryReader` that reads from the shared `IndexState`.
#[derive(Clone, Debug)]
struct MemoryConfirmedHistoryReader {
    state: Arc<IndexState>,
}

impl ConfirmedHistoryReader for MemoryConfirmedHistoryReader {
    fn confirmed_history_snapshot(
        &self,
        scripthash: ScriptHash,
    ) -> Result<ConfirmedHistorySnapshot, ElectrumError> {
        let mut records = self
            .state
            .histories
            .read()
            .get(&scripthash)
            .cloned()
            .unwrap_or_default();
        let unspent = records
            .iter()
            .copied()
            .filter(|record| !record.spent)
            .collect();
        records.sort_by_key(|record| (record.height, record.txid));
        records.dedup_by(|a, b| a.txid == b.txid && a.height == b.height);
        Ok(ConfirmedHistorySnapshot {
            history: records,
            unspent,
        })
    }

    fn unspent_outputs(&self, scripthash: ScriptHash) -> Result<Vec<HistoryRecord>, ElectrumError> {
        let records = self
            .state
            .histories
            .read()
            .get(&scripthash)
            .cloned()
            .unwrap_or_default();
        Ok(records.into_iter().filter(|record| !record.spent).collect())
    }

    fn transaction_hex(&self, txid: &Txid) -> Result<String, ElectrumError> {
        self.state
            .transactions
            .read()
            .get(txid)
            .map(|bytes| bytes.as_slice().to_lower_hex_string())
            .ok_or(ElectrumError::NotFound("transaction not found"))
    }

    fn outpoint_value(&self, op: &bitcoin::OutPoint) -> Result<Option<u64>, ElectrumError> {
        let transactions = self.state.transactions.read();
        let Some(bytes) = transactions.get(&op.txid) else {
            return Ok(None);
        };
        let tx = deserialize::<Transaction>(bytes)
            .map_err(|error| ElectrumError::TransactionDecode(error.to_string()))?;
        Ok(usize::try_from(op.vout)
            .ok()
            .and_then(|vout| tx.output.get(vout))
            .map(|output| output.value.to_sat()))
    }

    fn index_info(&self) -> Result<TxIndexInfo, ElectrumError> {
        let best_block_height = self
            .state
            .headers
            .read()
            .iter()
            .rposition(|header| header.iter().any(|&byte| byte != 0))
            .map_or(Ok(0), |height| {
                u32::try_from(height)
                    .map_err(|_| ElectrumError::Unavailable("header height exceeds u32".into()))
            })?;
        Ok(TxIndexInfo {
            synced: true,
            best_block_height,
        })
    }
}

/// In-memory `BlockTreeAdapter` that reads from the shared `IndexState`.
#[derive(Clone, Debug)]
struct MemoryBlockTreeAdapter {
    state: Arc<IndexState>,
}

impl MemoryBlockTreeAdapter {
    fn tip_index(&self) -> Option<usize> {
        let headers = self.state.headers.read();
        headers
            .iter()
            .enumerate()
            .rfind(|(_, h)| !h.iter().all(|&b| b == 0))
            .map(|(i, _)| i)
    }
}

impl BlockTreeAdapter for MemoryBlockTreeAdapter {
    fn tip(&self) -> Result<(u32, [u8; 80]), ElectrumError> {
        let Some(index) = self.tip_index() else {
            return Err(ElectrumError::NotFound("no headers"));
        };
        let height = u32::try_from(index).map_err(|_| {
            ElectrumError::Unavailable("in-memory header height exceeds u32".into())
        })?;
        let headers = self.state.headers.read();
        Ok((height, headers[index]))
    }

    fn header_at(&self, height: u32) -> Result<[u8; 80], ElectrumError> {
        let index =
            usize::try_from(height).map_err(|_| ElectrumError::NotFound("height out of range"))?;
        let headers = self.state.headers.read();
        headers
            .get(index)
            .copied()
            .ok_or(ElectrumError::NotFound("height out of range"))
    }

    fn headers_range(&self, start: u32, count: usize) -> Result<Vec<[u8; 80]>, ElectrumError> {
        let start =
            usize::try_from(start).map_err(|_| ElectrumError::NotFound("height out of range"))?;
        let headers = self.state.headers.read();
        let end = start.saturating_add(count).min(headers.len());
        Ok(headers.get(start..end).unwrap_or_default().to_vec())
    }

    fn block_at(&self, _height: u32) -> Result<bitcoin::Block, ElectrumError> {
        Err(ElectrumError::NotFound(
            "block body not available in memory adapter",
        ))
    }

    fn genesis_hash(&self) -> Result<bitcoin::BlockHash, ElectrumError> {
        let network = *self.state.network.read();
        Ok(bitcoin::blockdata::constants::genesis_block(network).block_hash())
    }
}

/// Read-only Electrum index handle used by method handlers.
#[derive(Clone)]
pub struct IndexHandle {
    state: Arc<IndexState>,
    query: Arc<dyn ConfirmedHistoryReader>,
    chain: Arc<dyn BlockTreeAdapter>,
}

impl Default for IndexHandle {
    fn default() -> Self {
        Self::new()
    }
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
        let state = Arc::new(IndexState::default());
        let query = Arc::new(MemoryConfirmedHistoryReader {
            state: Arc::clone(&state),
        });
        let chain = Arc::new(MemoryBlockTreeAdapter {
            state: Arc::clone(&state),
        });
        Self {
            state,
            query,
            chain,
        }
    }

    /// Attaches a complete transaction-index query adapter.
    #[must_use]
    pub fn with_history_reader(self, reader: Arc<dyn ConfirmedHistoryReader>) -> Self {
        Self {
            query: reader,
            ..self
        }
    }

    /// Attaches an authoritative chain adapter for header/block RPCs.
    #[must_use]
    pub fn with_chain(self, chain: Arc<dyn BlockTreeAdapter>) -> Self {
        Self { chain, ..self }
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

    fn confirmed_history_snapshot(
        &self,
        scripthash: ScriptHash,
    ) -> Result<ConfirmedHistorySnapshot, ElectrumError> {
        self.query.confirmed_history_snapshot(scripthash)
    }

    pub(crate) fn unspent_outputs(
        &self,
        scripthash: ScriptHash,
    ) -> Result<Vec<HistoryRecord>, ElectrumError> {
        self.query.unspent_outputs(scripthash)
    }

    /// Returns the lowercase-hex serialized confirmed transaction for `txid`.
    pub fn transaction_hex(&self, txid: &Txid) -> Result<String, ElectrumError> {
        self.query.transaction_hex(txid)
    }

    /// Returns the Bitcoin block at `height` via the authoritative chain adapter.
    pub fn block_at_height(&self, height: u32) -> Result<bitcoin::Block, ElectrumError> {
        self.chain.block_at(height)
    }

    /// Returns the satoshi value at `op` via the transaction-index query adapter.
    pub fn outpoint_value(&self, op: &bitcoin::OutPoint) -> Result<Option<u64>, ElectrumError> {
        self.query.outpoint_value(op)
    }
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

    fn mempool_outputs(&self, scripthash: ScriptHash) -> Vec<HistoryRecord> {
        let pool = self.pool.read();
        let mut records = Vec::new();
        for (_id, entry) in &pool.entries {
            let txid = entry.txid;
            for (vout, output) in entry.tx.output.iter().enumerate() {
                if ScriptHash::new(&output.script_pubkey) != scripthash {
                    continue;
                }
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
        records.sort_by_key(|record| (record.height, record.txid, record.vout));
        records
    }

    fn mempool_activity(
        &self,
        scripthash: ScriptHash,
        confirmed_unspent: &[HistoryRecord],
    ) -> Vec<HistoryRecord> {
        let pool = self.pool.read();
        let mut watched_outpoints = HashMap::new();
        for record in confirmed_unspent {
            if !record.spent {
                watched_outpoints.insert(
                    OutPoint {
                        txid: record.txid,
                        vout: record.vout,
                    },
                    (),
                );
            }
        }

        let mut mempool_txids = HashMap::with_capacity(pool.entries.len());
        let mut funding_txids = HashMap::new();
        for (_id, entry) in &pool.entries {
            let txid = entry.txid;
            mempool_txids.insert(txid, ());
            for (vout, output) in entry.tx.output.iter().enumerate() {
                if ScriptHash::new(&output.script_pubkey) != scripthash {
                    continue;
                }
                let Ok(vout) = u32::try_from(vout) else {
                    continue;
                };
                watched_outpoints.insert(OutPoint { txid, vout }, ());
                funding_txids.insert(txid, ());
            }
        }

        let mut records = Vec::new();
        for (_id, entry) in &pool.entries {
            let txid = entry.txid;
            let spends_watched = entry
                .tx
                .input
                .iter()
                .any(|input| watched_outpoints.contains_key(&input.previous_output));
            if !funding_txids.contains_key(&txid) && !spends_watched {
                continue;
            }
            let has_unconfirmed_inputs = entry
                .tx
                .input
                .iter()
                .any(|input| mempool_txids.contains_key(&input.previous_output.txid));
            records.push(HistoryRecord {
                txid,
                height: if has_unconfirmed_inputs { -1 } else { 0 },
                value: 0,
                vout: 0,
                spent: false,
            });
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

    /// Returns the satoshi value of `outpoint` when it is funded by a
    /// transaction currently in the mempool.
    fn prevout_value(&self, outpoint: &OutPoint) -> Option<u64> {
        let pool = self.pool.read();
        let entry = pool.entry_by_txid(&outpoint.txid)?;
        let vout = usize::try_from(outpoint.vout).ok()?;
        entry
            .tx
            .output
            .get(vout)
            .map(|output| output.value.to_sat())
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
        rows.sort_by_key(|right| core::cmp::Reverse(right.0));
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
    for record in combined_history(index, mempool, scripthash)? {
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
    for record in index.unspent_outputs(scripthash)? {
        let spent_by_mempool = spends.contains(&OutPoint {
            txid: record.txid,
            vout: record.vout,
        });
        if !spent_by_mempool {
            confirmed = confirmed.saturating_add(record.value);
        }
    }
    let mut unconfirmed = 0_u64;
    for record in mempool.mempool_outputs(scripthash) {
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
    status_json(index, mempool, scripthash)
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
    for record in index.unspent_outputs(scripthash)? {
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
    for record in mempool.mempool_outputs(scripthash) {
        if spends.contains(&OutPoint {
            txid: record.txid,
            vout: record.vout,
        }) {
            continue;
        }
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
    let hex = if let Some(hex) = mempool.get_transaction_hex(&txid) {
        hex
    } else {
        index.transaction_hex(&txid)?
    };
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
            let mut combined = [0_u8; 64];
            combined[..32].copy_from_slice(pair[0].as_byte_array());
            combined[32..].copy_from_slice(pair[1].as_byte_array());
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
    let block = index.block_at_height(height)?;
    let Some(pos) = block.txdata.iter().position(|t| t.compute_txid() == txid) else {
        return Err(ElectrumError::NotFound("txid not in block"));
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
    let block = index.block_at_height(height)?;
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
    index: &IndexHandle,
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
    if tx.input.len() > MAX_BROADCAST_INPUTS {
        return Err(ElectrumError::InvalidParams(
            "transaction input count exceeds limit",
        ));
    }

    // Every prevout must resolve through the confirmed index or the mempool
    // so the fee is real (sum_in - sum_out). Reject instead of falling back
    // to a vsize placeholder that fabricates a 1 sat/vB fee.
    let mut sum_in: u64 = 0;
    for input in &tx.input {
        let value = match index.outpoint_value(&input.previous_output)? {
            Some(value) => value,
            None => mempool
                .prevout_value(&input.previous_output)
                .ok_or_else(|| {
                    ElectrumError::Unavailable("broadcast prevout not in index or mempool".into())
                })?,
        };
        sum_in = sum_in.saturating_add(value);
    }
    let sum_out: u64 = tx.output.iter().fold(0_u64, |acc, output| {
        acc.saturating_add(output.value.to_sat())
    });
    let fee = sum_in.saturating_sub(sum_out);

    let txid = mempool.insert_transaction(tx, fee, 0, 0)?;
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
    let header = index.chain.header_at(
        u32::try_from(height).map_err(|_| ElectrumError::InvalidParams("height exceeds u32"))?,
    )?;
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
        .and_then(|value| u32::try_from(value).ok())
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
    let headers = index.chain.headers_range(start, count.min(MAX_HEADERS))?;
    let mut hex = String::with_capacity(headers.len().saturating_mul(160));
    for header in &headers {
        hex.push_str(&header.to_lower_hex_string());
    }
    Ok(json!({"count": headers.len(), "hex": hex, "max": MAX_HEADERS}))
}

pub(crate) fn headers_subscribe(
    index: &IndexHandle,
    _mempool: &MempoolHandle,
    params: &Value,
) -> Result<Value, ElectrumError> {
    ensure_array_len(params, 0)?;
    let (height, header) = index.chain.tip()?;
    Ok(json!({"height": height, "hex": header.to_lower_hex_string()}))
}

/// Computes the current Electrum status value for `scripthash`.
pub fn status_json(
    index: &IndexHandle,
    mempool: &MempoolHandle,
    scripthash: ScriptHash,
) -> Result<Value, ElectrumError> {
    Ok(match status_string(index, mempool, scripthash)? {
        Some(status) => json!(status.as_str()),
        None => Value::new_null(),
    })
}

/// Computes the current Electrum status hash string for `scripthash`.
pub fn status_string(
    index: &IndexHandle,
    mempool: &MempoolHandle,
    scripthash: ScriptHash,
) -> Result<Option<CompactString>, ElectrumError> {
    let entries = combined_history(index, mempool, scripthash)?
        .into_iter()
        .filter_map(|record| history_entry(record).ok())
        .collect::<Vec<_>>();
    Ok(compute_status_hash(&entries).map(|hash| hash.to_compact_string()))
}

fn history_entry(record: HistoryRecord) -> Result<HistoryEntry, ElectrumError> {
    if record.height > 0 {
        let height = u32::try_from(record.height)
            .map_err(|_| ElectrumError::InvalidParams("confirmed height exceeds u32"))?;
        return Ok(HistoryEntry::confirmed(record.txid, height));
    }
    match record.height {
        0 => Ok(HistoryEntry::unconfirmed(record.txid, false)),
        -1 => Ok(HistoryEntry::unconfirmed(record.txid, true)),
        _ => Err(ElectrumError::InvalidParams(
            "invalid unconfirmed history height",
        )),
    }
}

fn combined_history(
    index: &IndexHandle,
    mempool: &MempoolHandle,
    scripthash: ScriptHash,
) -> Result<Vec<HistoryRecord>, ElectrumError> {
    let ConfirmedHistorySnapshot {
        mut history,
        unspent,
    } = index.confirmed_history_snapshot(scripthash)?;
    history.extend(mempool.mempool_activity(scripthash, &unspent));
    history.sort_by_key(|record| (record.height, record.txid));
    history.dedup_by(|a, b| a.txid == b.txid && a.height == b.height);
    Ok(history)
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
mod broadcast_tests {
    use super::*;
    use bitcoin::hashes::Hash as _;

    #[test]
    fn broadcast_rejects_excess_inputs_before_resolution() {
        let tx = Transaction {
            version: bitcoin::transaction::Version::ONE,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn::default(); MAX_BROADCAST_INPUTS + 1],
            output: Vec::new(),
        };
        let params = json!([serialize(&tx).to_lower_hex_string()]);

        assert!(matches!(
            transaction_broadcast(&IndexHandle::new(), &MempoolHandle::default(), &params),
            Err(ElectrumError::InvalidParams(
                "transaction input count exceeds limit"
            ))
        ));
    }

    #[test]
    fn broadcast_resolves_unconfirmed_parent_fee_from_mempool() {
        // The parent funds a 5_000 sat output inside the mempool; the child
        // spends it with a 4_500 sat output, so the real fee is 500 sat and
        // must not collapse to the old vsize placeholder.
        let mempool = MempoolHandle::default();
        let parent = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([0x21; 32]),
                    vout: 0,
                },
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(5_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };
        let Ok(parent_txid) = mempool.insert_transaction(parent, 1_000, 0, 0) else {
            panic!("parent must be accepted");
        };
        let child = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: OutPoint {
                    txid: parent_txid,
                    vout: 0,
                },
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(4_500),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };
        let params = json!([serialize(&child).to_lower_hex_string()]);

        let Ok(result) = transaction_broadcast(&IndexHandle::new(), &mempool, &params) else {
            panic!("broadcast must succeed");
        };
        let Some(child_hex) = result.as_str() else {
            panic!("broadcast must return a txid string");
        };
        let Ok(child_txid) = child_hex.parse::<Txid>() else {
            panic!("broadcast result must parse as a txid");
        };

        let pool = mempool.pool.read();
        let Some(entry) = pool.entry_by_txid(&child_txid) else {
            panic!("child must be in the mempool");
        };
        assert_eq!(entry.fee, 500, "fee must be sum_in - sum_out");
    }

    #[test]
    fn broadcast_rejects_unresolved_prevout_instead_of_placeholder_fee() {
        let mempool = MempoolHandle::default();
        let tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::absolute::LockTime::ZERO,
            input: vec![bitcoin::TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_byte_array([0x42; 32]),
                    vout: 0,
                },
                script_sig: bitcoin::ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(1_000),
                script_pubkey: bitcoin::ScriptBuf::new(),
            }],
        };
        let params = json!([serialize(&tx).to_lower_hex_string()]);

        assert!(matches!(
            transaction_broadcast(&IndexHandle::new(), &mempool, &params),
            Err(ElectrumError::Unavailable(_))
        ));
        assert!(
            mempool.pool.read().is_empty(),
            "rejected broadcast must not insert a synthetic-fee transaction"
        );
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
        fn confirmed_history_snapshot(
            &self,
            _: ScriptHash,
        ) -> Result<ConfirmedHistorySnapshot, ElectrumError> {
            use bitcoin::hashes::Hash as _;

            let mut hash = [0_u8; 32];
            hash[0] = 0xff;
            let txid = bitcoin::Txid::from_byte_array(hash);
            let record = HistoryRecord {
                txid,
                height: 7,
                value: 0,
                vout: 0,
                spent: false,
            };
            Ok(ConfirmedHistorySnapshot {
                history: vec![record],
                unspent: vec![record],
            })
        }

        fn unspent_outputs(&self, _: ScriptHash) -> Result<Vec<HistoryRecord>, ElectrumError> {
            Ok(Vec::new())
        }

        fn transaction_hex(&self, _: &Txid) -> Result<String, ElectrumError> {
            Err(ElectrumError::NotFound("transaction not found"))
        }

        fn outpoint_value(&self, _: &OutPoint) -> Result<Option<u64>, ElectrumError> {
            Ok(None)
        }

        fn index_info(&self) -> Result<TxIndexInfo, ElectrumError> {
            Ok(TxIndexInfo {
                synced: true,
                best_block_height: 0,
            })
        }
    }

    #[derive(Debug)]
    struct StubReaderUnspent;

    impl ConfirmedHistoryReader for StubReaderUnspent {
        fn confirmed_history_snapshot(
            &self,
            _: ScriptHash,
        ) -> Result<ConfirmedHistorySnapshot, ElectrumError> {
            use bitcoin::hashes::Hash as _;

            let mut hash = [0_u8; 32];
            hash[0] = 0xfe;
            let txid = bitcoin::Txid::from_byte_array(hash);
            let record = HistoryRecord {
                txid,
                height: 0,
                value: 100_000,
                vout: 0,
                spent: false,
            };
            Ok(ConfirmedHistorySnapshot {
                history: vec![record],
                unspent: vec![record],
            })
        }

        fn unspent_outputs(&self, _: ScriptHash) -> Result<Vec<HistoryRecord>, ElectrumError> {
            use bitcoin::hashes::Hash as _;

            let mut hash = [0_u8; 32];
            hash[0] = 0xfe;
            let txid = bitcoin::Txid::from_byte_array(hash);
            Ok(vec![HistoryRecord {
                txid,
                height: 0,
                value: 100_000,
                vout: 0,
                spent: false,
            }])
        }

        fn transaction_hex(&self, _: &Txid) -> Result<String, ElectrumError> {
            Err(ElectrumError::NotFound("transaction not found"))
        }

        fn outpoint_value(&self, _: &OutPoint) -> Result<Option<u64>, ElectrumError> {
            Ok(None)
        }

        fn index_info(&self) -> Result<TxIndexInfo, ElectrumError> {
            Ok(TxIndexInfo {
                synced: true,
                best_block_height: 0,
            })
        }
    }

    #[derive(Debug)]
    struct StubReaderTxHex;

    impl ConfirmedHistoryReader for StubReaderTxHex {
        fn confirmed_history_snapshot(
            &self,
            _: ScriptHash,
        ) -> Result<ConfirmedHistorySnapshot, ElectrumError> {
            Ok(ConfirmedHistorySnapshot::default())
        }

        fn unspent_outputs(&self, _: ScriptHash) -> Result<Vec<HistoryRecord>, ElectrumError> {
            Ok(Vec::new())
        }

        fn transaction_hex(&self, _: &bitcoin::Txid) -> Result<String, ElectrumError> {
            Ok("deadbeef".to_owned())
        }

        fn outpoint_value(&self, _: &OutPoint) -> Result<Option<u64>, ElectrumError> {
            Ok(None)
        }

        fn index_info(&self) -> Result<TxIndexInfo, ElectrumError> {
            Ok(TxIndexInfo {
                synced: true,
                best_block_height: 0,
            })
        }
    }

    #[test]
    fn outpoint_value_returns_none_when_no_reader_attached() {
        use bitcoin::hashes::Hash as _;

        let index = IndexHandle::new();
        let outpoint = bitcoin::OutPoint {
            txid: bitcoin::Txid::from_byte_array([0xab; 32]),
            vout: 0,
        };

        assert!(matches!(index.outpoint_value(&outpoint), Ok(None)));
    }
    #[test]
    fn with_history_reader_overrides_synthetic_history() -> Result<(), ElectrumError> {
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

        let snapshot = handle.confirmed_history_snapshot(scripthash)?;
        let records = snapshot.history;

        assert_eq!(records.len(), 1);
        assert!(records.iter().any(|record| record.height == 7));
        Ok(())
    }

    #[test]
    fn get_history_makes_one_reader_call() {
        use core::sync::atomic::{AtomicUsize, Ordering};

        #[derive(Debug)]
        struct CountingReader {
            calls: AtomicUsize,
        }

        impl ConfirmedHistoryReader for CountingReader {
            fn confirmed_history_snapshot(
                &self,
                _: ScriptHash,
            ) -> Result<ConfirmedHistorySnapshot, ElectrumError> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Ok(ConfirmedHistorySnapshot::default())
            }

            fn unspent_outputs(&self, _: ScriptHash) -> Result<Vec<HistoryRecord>, ElectrumError> {
                self.calls.fetch_add(1, Ordering::SeqCst);
                Ok(Vec::new())
            }

            fn transaction_hex(&self, _: &Txid) -> Result<String, ElectrumError> {
                Err(ElectrumError::NotFound("transaction not found"))
            }

            fn outpoint_value(&self, _: &OutPoint) -> Result<Option<u64>, ElectrumError> {
                Ok(None)
            }

            fn index_info(&self) -> Result<TxIndexInfo, ElectrumError> {
                Ok(TxIndexInfo {
                    synced: true,
                    best_block_height: 0,
                })
            }
        }

        let reader = Arc::new(CountingReader {
            calls: AtomicUsize::new(0),
        });
        let calls = Arc::clone(&reader);
        let handle = IndexHandle::new().with_history_reader(reader);
        let mempool = MempoolHandle::default();
        let params = json!([scripthash_hex(ScriptHash::from_byte_array([0xab; 32]))]);

        let result = scripthash_get_history(&handle, &mempool, &params)
            .unwrap_or_else(|err| panic!("get_history failed: {err}"));

        assert_eq!(result.as_array().map(sonic_rs::Array::len), Some(0));
        assert_eq!(calls.calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn transaction_hex_prefers_reader_over_synthetic() -> Result<(), ElectrumError> {
        use bitcoin::hashes::Hash as _;

        let handle = IndexHandle::new().with_history_reader(Arc::new(StubReaderTxHex));
        let mut hash = [0_u8; 32];
        hash[0] = 0xee;
        let txid = bitcoin::Txid::from_byte_array(hash);
        let hex = handle.transaction_hex(&txid)?;

        assert_eq!(hex.as_str(), "deadbeef");
        Ok(())
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
    struct StubChain;

    impl BlockTreeAdapter for StubChain {
        fn tip(&self) -> Result<(u32, [u8; 80]), ElectrumError> {
            Ok((
                0,
                serialize(
                    &bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest).header,
                )
                .try_into()
                .unwrap_or([0_u8; 80]),
            ))
        }

        fn header_at(&self, height: u32) -> Result<[u8; 80], ElectrumError> {
            if height == 0 {
                Ok(serialize(
                    &bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest).header,
                )
                .try_into()
                .unwrap_or([0_u8; 80]))
            } else {
                Err(ElectrumError::NotFound("height out of range"))
            }
        }

        fn headers_range(
            &self,
            _start: u32,
            _count: usize,
        ) -> Result<Vec<[u8; 80]>, ElectrumError> {
            Ok(Vec::new())
        }

        fn block_at(&self, height: u32) -> Result<bitcoin::Block, ElectrumError> {
            if height == 0 {
                Ok(bitcoin::blockdata::constants::genesis_block(
                    bitcoin::Network::Regtest,
                ))
            } else {
                Err(ElectrumError::NotFound("block not found"))
            }
        }

        fn genesis_hash(&self) -> Result<bitcoin::BlockHash, ElectrumError> {
            Ok(
                bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest)
                    .block_hash(),
            )
        }
    }

    #[test]
    fn id_from_pos_returns_txid_for_genesis_coinbase() {
        let index = IndexHandle::new().with_chain(Arc::new(StubChain));
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
        let index = IndexHandle::new().with_chain(Arc::new(StubChain));
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
    struct StubChainRegtestGenesis;

    impl BlockTreeAdapter for StubChainRegtestGenesis {
        fn tip(&self) -> Result<(u32, [u8; 80]), ElectrumError> {
            Ok((
                0,
                serialize(
                    &bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest).header,
                )
                .try_into()
                .unwrap_or([0_u8; 80]),
            ))
        }

        fn header_at(&self, height: u32) -> Result<[u8; 80], ElectrumError> {
            if height == 0 {
                Ok(serialize(
                    &bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest).header,
                )
                .try_into()
                .unwrap_or([0_u8; 80]))
            } else {
                Err(ElectrumError::NotFound("height out of range"))
            }
        }

        fn headers_range(
            &self,
            _start: u32,
            _count: usize,
        ) -> Result<Vec<[u8; 80]>, ElectrumError> {
            Ok(Vec::new())
        }

        fn block_at(&self, height: u32) -> Result<bitcoin::Block, ElectrumError> {
            if height == 0 {
                Ok(bitcoin::blockdata::constants::genesis_block(
                    bitcoin::Network::Regtest,
                ))
            } else {
                Err(ElectrumError::NotFound("block not found"))
            }
        }

        fn genesis_hash(&self) -> Result<bitcoin::BlockHash, ElectrumError> {
            Ok(
                bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest)
                    .block_hash(),
            )
        }
    }

    #[test]
    fn transaction_get_merkle_returns_proof_for_genesis_coinbase() {
        let index = IndexHandle::new().with_chain(Arc::new(StubChainRegtestGenesis));
        let mempool = MempoolHandle::default();
        let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
        let Some(coinbase) = genesis.txdata.first() else {
            panic!("genesis has no tx");
        };

        let result = dispatch(
            "blockchain.transaction.get_merkle",
            &index,
            &mempool,
            &json!([coinbase.compute_txid().to_string(), 0]),
        )
        .unwrap_or_else(|err| panic!("get_merkle failed: {err}"));
        assert_eq!(
            result.get("block_height").and_then(JsonValueTrait::as_u64),
            Some(0),
        );
        assert_eq!(result.get("pos").and_then(JsonValueTrait::as_u64), Some(0),);
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
