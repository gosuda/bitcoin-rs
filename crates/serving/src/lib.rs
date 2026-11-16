//! Synchronous Bitcoin Core-compatible JSON-RPC surface for `bitcoin-rs`.

#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

pub mod auth;
mod base64;
pub(crate) mod compressed_tx;
pub mod context;
pub(crate) mod convert;
pub(crate) mod decimal;
mod error;
pub mod esplora;
pub mod handlers;
pub mod manifest;
pub mod mining;
pub(crate) mod registry;
mod render;
pub mod rest;
mod server;
mod tx_render;
pub mod zmq;

pub use auth::Auth;
pub use manifest::MANIFEST_TOML;

pub use error::RpcError;
pub use handlers::Handler;
pub use server::{RpcServer, RpcSurface};

#[cfg(feature = "test-seam")]
pub use server::{handle_json, read_http_request};

#[cfg(test)]
pub(crate) mod test_error {
    #[derive(Debug, thiserror::Error)]
    pub(crate) enum TestError {
        #[error(transparent)]
        Rpc(#[from] crate::error::RpcError),
        #[error(transparent)]
        Io(#[from] std::io::Error),
        #[error(transparent)]
        Sonic(#[from] sonic_rs::Error),
        #[error(transparent)]
        Chain(#[from] bitcoin_rs_execution::chain::ChainError),
        #[error(transparent)]
        AddrParse(#[from] std::net::AddrParseError),
        #[error(transparent)]
        AddressFromScript(#[from] bitcoin::address::FromScriptError),
        #[error(transparent)]
        Utxo(#[from] bitcoin_rs_storage::utxo::UtxoError),
        #[error(transparent)]
        UtxoScan(#[from] bitcoin_rs_storage::utxo::scan::UtxoScanError),
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
        PoolLedger(#[from] crate::mining::pool::ledger::LedgerError),
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
}

#[cfg(test)]
pub(crate) mod test_coins {
    use std::sync::Arc;

    use bitcoin_rs_consensus::primitives::Hash256;
    use bitcoin_rs_storage::utxo::UtxoReader;
    use bitcoin_rs_storage::{
        CoinKey, CoinStore, ColumnFamily, KvStore, MemoryKvStore, StorageError,
    };

    pub(crate) fn utxo_reader_with_undecodable_coin(
        txid: &Hash256,
    ) -> Result<UtxoReader, StorageError> {
        let store = Arc::new(MemoryKvStore::new());
        store.put(
            ColumnFamily::Coins,
            CoinKey(txid.to_le_bytes()).as_bytes(),
            &[0xff; 3],
        )?;
        Ok(UtxoReader::from_coin_store(Arc::new(CoinStore::open(
            store,
            1024 * 1024,
        ))))
    }
}
