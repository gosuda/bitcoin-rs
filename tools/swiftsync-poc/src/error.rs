use std::io;
use std::path::PathBuf;

use bitcoin_rs_primitives::DecodeError;
use bitcoin_rs_utxo::UtxoError;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("io {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("chain file line {line}: {reason}")]
    ChainFormat { line: usize, reason: String },
    #[error("hints file line {line}: {reason}")]
    HintsFormat { line: usize, reason: String },
    #[error("checkpoint file line {line}: {reason}")]
    CheckpointFormat { line: usize, reason: String },
    #[error("block {height} rejected by the {check} check")]
    InvalidBlock { height: u32, check: &'static str },
    #[error("transaction {txid} in block {height} pays out more value than its inputs")]
    ValueImbalance { height: u32, txid: String },
    #[error("block {height} spends {outpoint} which no earlier block created")]
    UnknownPrevout { height: u32, outpoint: String },
    #[error("block {height} has no transactions")]
    EmptyBlock { height: u32 },
    #[error("block {height} carries {carried} undo entries but {resolved} inputs resolve")]
    UndoLength {
        height: u32,
        carried: usize,
        resolved: usize,
    },
    #[error("block {height} undo entry {index} names {found} but the coin is {expected}")]
    UndoMismatch {
        height: u32,
        index: usize,
        found: String,
        expected: String,
    },
    #[error("flag {flag} value `{value}` is not usable")]
    FlagValue { flag: &'static str, value: String },
    #[error("hint file repeats outpoint {outpoint}")]
    HintDuplicate { outpoint: String },
    #[error("hints name height {hint} but the fold covers through height {folded}")]
    HintHeight { hint: u32, folded: u32 },
    #[error(
        "aggregate is not the MuHash identity: folded through height {folded} with {hints} hinted coins, leaving muhash {muhash}, {utxo_count} coins and {total_amount} satoshis"
    )]
    AggregateNotZero {
        folded: u32,
        hints: u64,
        muhash: String,
        utxo_count: u64,
        total_amount: u64,
    },
    #[error(
        "hinted set differs from the reconstructed final set: {missing} missing, {extra} extra, {mismatched} mismatched"
    )]
    HintSetMismatch {
        missing: u64,
        extra: u64,
        mismatched: u64,
    },
    #[error("checkpoint names tip {expected} but the chain holds {found} at height {height}")]
    CheckpointMismatch {
        height: u32,
        expected: String,
        found: String,
    },
    #[error("checkpoint resume point {folded} blocks is past the chain length {length}")]
    CheckpointBeyondChain { folded: u32, length: usize },
    #[error("block {height} links to {parent} while the folded tip is {tip}")]
    ReorgDetected {
        height: u32,
        parent: String,
        tip: String,
    },
    #[error("fold expects block height {expected} next, got {found}")]
    ChainGap { expected: u32, found: u32 },
    #[error("rewind target {target} is above the folded height {folded}")]
    RewindForward { target: u32, folded: u32 },
    #[error("rewind source block {height} is not the block that was folded at that height")]
    RewindSourceMismatch { height: u32 },
    #[error("block {height} decoded by bitcoin-rs differs from the wire bytes: {source}")]
    Decode {
        height: u32,
        #[source]
        source: DecodeError,
    },
    #[error(
        "bitcoin-rs decode of block {height} carries {mine} txids, the wire block carries {wire}"
    )]
    TxidCount {
        height: u32,
        mine: usize,
        wire: usize,
    },
    #[error("bitcoin-rs txid {mine} for block {height} differs from the wire txid {wire}")]
    TxidMismatch {
        height: u32,
        mine: String,
        wire: String,
    },
    #[error("coinstats listener muhash {listener} differs from the set scan muhash {scan}")]
    StatsDivergence { listener: String, scan: String },
    #[error("utxo: {0}")]
    Utxo(#[from] UtxoError),
    #[error("simulated crash after folding {folded} blocks")]
    SimulatedCrash { folded: u32 },
    #[error("unknown argument {argument}")]
    UnknownArgument { argument: String },
    #[error("missing required flag {flag}")]
    MissingFlag { flag: String },
    #[error(
        "usage: swiftsync-poc gen --out <dir> | sync --chain <file> --hints <file> [--checkpoint <file>] [--simulate-crash-after <blocks>] | verify --chain <file> --hints <file> [--snapshot <file>]"
    )]
    Usage,
}
