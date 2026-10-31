#[cfg(feature = "kernel")]
use bitcoin_rs_primitives::OutPoint;

#[expect(dead_code, reason = "used when feature kernel is enabled")]
#[derive(Debug, thiserror::Error)]
pub(crate) enum TestError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] sonic_rs::Error),
    #[error("hex decode error: {0}")]
    Hex(#[from] bitcoin::hex::HexToArrayError),
    #[error("hex slice decode error: {0}")]
    HexSlice(#[from] bitcoin::hex::HexToBytesError),
    #[error("consensus decode error: {0}")]
    Decode(#[from] bitcoin_rs_primitives::DecodeError),
    #[error("consensus error: {0}")]
    Consensus(#[from] bitcoin_rs_consensus::ConsensusError),
    #[error("script flags error: {0}")]
    ScriptFlags(#[from] bitcoin_rs_script::ScriptError),
    #[cfg(feature = "kernel")]
    #[error("kernel error: {0}")]
    Kernel(#[from] bitcoinkernel::KernelError),
    #[error("try-from-int error: {0}")]
    TryFromInt(#[from] core::num::TryFromIntError),
    #[error("try-from-slice error: {0}")]
    TryFromSlice(#[from] core::array::TryFromSliceError),
    #[error("tx hex does not decode for {path}: {source}")]
    TxHex {
        path: String,
        source: bitcoin_rs_primitives::DecodeError,
    },
    #[error("txid mismatch for {path}: manifest says {expected} but hashes to {actual}")]
    TxidMismatch {
        path: String,
        expected: String,
        actual: String,
    },
    #[error("wtxid mismatch for {path}: manifest says {expected} but hashes to {actual}")]
    WtxidMismatch {
        path: String,
        expected: String,
        actual: String,
    },
    #[error("prevout mismatch for {path}: {prevouts} prevouts for {inputs} inputs")]
    PrevoutMismatch {
        path: String,
        prevouts: usize,
        inputs: usize,
    },
    #[cfg(feature = "kernel")]
    #[error("vector row {row}: {fault}")]
    Row { row: usize, fault: RowFault },
    #[cfg(feature = "kernel")]
    #[error("vector row {row}: tx does not decode: {source}")]
    RowDecode {
        row: usize,
        source: bitcoin_rs_primitives::DecodeError,
    },
    #[cfg(feature = "kernel")]
    #[error("vector row {row}: missing prevout for input {outpoint:?}")]
    RowMissingPrevout { row: usize, outpoint: OutPoint },
    #[cfg(feature = "kernel")]
    #[error("flags {names} are not a filled combination")]
    UnfilledFlags { names: RowFlagNames },
    #[cfg(feature = "kernel")]
    #[error("unknown opcode token: {token}")]
    UnknownOpcode { token: TokenText },
    #[cfg(feature = "kernel")]
    #[error("interpreter failed on input {input}: {source}")]
    Interpreter {
        input: usize,
        #[source]
        source: bitcoin_rs_script::ScriptError,
    },
    #[cfg(feature = "kernel")]
    #[error("interpreter rejected input {input}")]
    InterpreterRejected { input: usize },
    #[cfg(feature = "kernel")]
    #[error("kernel oracle failed on the {fault} fixture")]
    Oracle { fault: OracleFault },
    #[error("zero vectors loaded for {0}: gate is vacuous")]
    VacuousVectors(&'static str),
    #[error("missing expected value: {0}")]
    Missing(&'static str),
}

impl From<&'static str> for TestError {
    fn from(msg: &'static str) -> Self {
        Self::Missing(msg)
    }
}

#[cfg(feature = "kernel")]
#[derive(Debug)]
pub(crate) enum RowFault {
    NotText(&'static str),
    NotArray(&'static str),
    NotInteger(&'static str),
    OutOfRange(&'static str),
}

#[cfg(feature = "kernel")]
impl std::fmt::Display for RowFault {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotText(what) => write!(formatter, "{what} should be text"),
            Self::NotArray(what) => write!(formatter, "{what} should be an array"),
            Self::NotInteger(what) => write!(formatter, "{what} should be an integer"),
            Self::OutOfRange(what) => write!(formatter, "{what} does not fit"),
        }
    }
}

#[cfg(feature = "kernel")]
#[derive(Debug)]
pub(crate) struct RowFlagNames(pub(crate) &'static str);

#[cfg(feature = "kernel")]
impl std::fmt::Display for RowFlagNames {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.0)
    }
}

#[cfg(feature = "kernel")]
#[derive(Debug)]
pub(crate) struct TokenText(pub(crate) String);

#[cfg(feature = "kernel")]
impl std::fmt::Display for TokenText {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[cfg(feature = "kernel")]
#[derive(Debug)]
pub(crate) enum OracleFault {
    PristineKernel,
    TamperedKernel,
}

#[cfg(feature = "kernel")]
impl std::fmt::Display for OracleFault {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::PristineKernel => "pristine taproot script-path",
            Self::TamperedKernel => "tampered taproot script-path",
        })
    }
}
