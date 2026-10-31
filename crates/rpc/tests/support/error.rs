#[derive(Debug, thiserror::Error)]
pub(crate) enum TestError {
    #[error(transparent)]
    Load(#[from] super::fixture::LoadError),
    #[error(transparent)]
    Mismatch(#[from] super::compare::Mismatch),
    #[error(transparent)]
    Http(#[from] super::http::HttpError),
    #[error(transparent)]
    Failure(#[from] super::Failure),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Sonic(#[from] sonic_rs::Error),
    #[error(transparent)]
    Rpc(#[from] bitcoin_rs_rpc::RpcError),
    #[error(transparent)]
    Auth(#[from] bitcoin_rs_rpc::auth::AuthError),
    #[error(transparent)]
    AddrParse(#[from] std::net::AddrParseError),
    #[error(transparent)]
    FromUtf8(#[from] std::string::FromUtf8Error),
    #[error(transparent)]
    Chain(#[from] bitcoin_rs_chain::ChainError),
    #[error(transparent)]
    RegtestFixture(#[from] bitcoin_rs_chain::regtest_fixture::RegtestFixtureError),
    #[error(transparent)]
    Mempool(#[from] bitcoin_rs_mempool::MempoolError),
    #[error(transparent)]
    Rbf(#[from] bitcoin_rs_mempool::RbfError),
    #[error(transparent)]
    ChainChange(#[from] bitcoin_rs_mempool::ChainChangeError),
    #[error(transparent)]
    Utxo(#[from] bitcoin_rs_utxo::UtxoError),
    #[error(transparent)]
    UtxoScan(#[from] bitcoin_rs_utxo::scan::UtxoScanError),
    #[error(transparent)]
    NodeOpen(#[from] bitcoin_rs_node::NodeOpenError),
    #[error(transparent)]
    ConnectMutation(#[from] bitcoin_rs_node::ConnectMutationError),
    #[error(transparent)]
    ConsensusEncode(#[from] bitcoin::consensus::encode::Error),
    #[error(transparent)]
    Psbt(#[from] bitcoin::psbt::Error),
    #[error(transparent)]
    HexToBytes(#[from] bitcoin::hex::HexToBytesError),
    #[error(transparent)]
    Decode(#[from] bitcoin_rs_primitives::DecodeError),
    #[error(transparent)]
    TryFromInt(#[from] std::num::TryFromIntError),
    #[error(transparent)]
    TryFromSlice(#[from] std::array::TryFromSliceError),
    #[error(transparent)]
    ParseInt(#[from] std::num::ParseIntError),
    #[error(transparent)]
    Reference(#[from] bitcoin_rs_e2e::reference_set::ReferenceError),
    #[error(transparent)]
    E2e(#[from] bitcoin_rs_e2e::error::Error),
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
