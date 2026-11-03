pub(crate) mod regtest_blocks;
pub(crate) mod wire_peer;

#[derive(Debug, thiserror::Error)]
pub(crate) enum TestError {
    #[error(transparent)]
    E2e(#[from] bitcoin_rs_e2e::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Storage(#[from] bitcoin_rs_storage::StorageError),
    #[error(transparent)]
    HexToBytes(#[from] bitcoin::hex::HexToBytesError),
    #[error(transparent)]
    HexToArray(#[from] bitcoin::hex::HexToArrayError),
    #[error(transparent)]
    ConsensusHex(#[from] bitcoin::consensus::encode::FromHexError),
    #[error(transparent)]
    Decode(#[from] bitcoin_rs_primitives::DecodeError),
    #[error(transparent)]
    Sonic(#[from] sonic_rs::Error),
    #[error(transparent)]
    ParseInt(#[from] std::num::ParseIntError),
    #[error(transparent)]
    TryFromInt(#[from] std::num::TryFromIntError),
    #[error(transparent)]
    FromUtf8(#[from] std::string::FromUtf8Error),
    #[error(transparent)]
    ParsePublicKey(#[from] bitcoin::key::ParsePublicKeyError),
    #[error(transparent)]
    Secp256k1(#[from] bitcoin::secp256k1::Error),
    #[cfg(feature = "silent-payments")]
    #[error(transparent)]
    ScalarOutOfRange(#[from] bitcoin::secp256k1::scalar::OutOfRangeError),
    #[error(transparent)]
    FromScript(#[from] bitcoin::address::FromScriptError),
    #[error(transparent)]
    Consensus(#[from] bitcoin::consensus::encode::Error),
    #[error("missing value: {0}")]
    Missing(&'static str),
    #[cfg(windows)]
    #[error("peak RSS query failed")]
    PeakRssQueryFailed,
    #[error("fixture did not approach capacity")]
    FixtureDidNotApproachCapacity,
    #[error("HTTP {status}: {body}")]
    HttpStatus { status: u16, body: String },
    #[error("RPC error: {0}")]
    Rpc(String),
    #[error("submitblock rejected: {0}")]
    SubmitBlock(String),
    #[error("index timeout: {0}")]
    IndexTimeout(String),
    #[error("confirmation timeout: {0}")]
    ConfirmationTimeout(String),
    #[error("startup timeout: {0}")]
    StartupTimeout(String),
}
