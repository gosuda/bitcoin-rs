#[derive(Debug, thiserror::Error)]
pub(crate) enum TestError {
    #[error(transparent)]
    Rpc(#[from] crate::error::RpcError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Sonic(#[from] sonic_rs::Error),
    #[error(transparent)]
    Chain(#[from] bitcoin_rs_chain::ChainError),
    #[error(transparent)]
    AddrParse(#[from] std::net::AddrParseError),
    #[error(transparent)]
    AddressFromScript(#[from] bitcoin::address::FromScriptError),
    #[error(transparent)]
    Utxo(#[from] bitcoin_rs_utxo::UtxoError),
    #[error(transparent)]
    UtxoScan(#[from] bitcoin_rs_utxo::scan::UtxoScanError),
    #[error(transparent)]
    Storage(#[from] bitcoin_rs_storage::StorageError),
    #[error(transparent)]
    Mempool(#[from] bitcoin_rs_mempool::MempoolError),
    #[error(transparent)]
    Submit(#[from] bitcoin_rs_mempool::SubmitError),
    #[cfg(feature = "zmq")]
    #[error(transparent)]
    ZmqBind(#[from] crate::zmq::ZmqBindError),
    #[cfg(feature = "zmq")]
    #[error(transparent)]
    Zmq(#[from] zmq::Error),
    #[cfg(feature = "pool")]
    #[error(transparent)]
    PoolLedger(#[from] bitcoin_rs_mining::pool::ledger::LedgerError),
    #[error(transparent)]
    TryFromInt(#[from] std::num::TryFromIntError),
    #[error(transparent)]
    TryFromSlice(#[from] std::array::TryFromSliceError),
    #[error("missing {0}")]
    Missing(&'static str),
    #[error("{0}")]
    Message(String),
}

impl From<&'static str> for TestError {
    fn from(s: &'static str) -> Self {
        Self::Missing(s)
    }
}

impl From<String> for TestError {
    fn from(s: String) -> Self {
        Self::Message(s)
    }
}
