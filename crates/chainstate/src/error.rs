//! Typed authoritative chainstate mutation failures.

/// Errors produced when applying a block to the node state.
#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    #[error("block apply rejected because clean shutdown has begun")]
    Shutdown,
    #[error("another chain change is already active")]
    ConcurrentChainChange,
    #[error("chain-change generation exhausted")]
    ChainChangeGenerationOverflow,
    #[error("prev hash mismatch: tip {tip}, block prev {prev}")]
    PrevHashMismatch {
        tip: bitcoin_rs_primitives::Hash256,
        prev: bitcoin_rs_primitives::Hash256,
    },
    #[error("height overflow at tip {0}")]
    HeightOverflow(u32),
    #[error("output count of transaction {txid} exceeds the vout index range")]
    VoutOverflow { txid: bitcoin_rs_primitives::Txid },
    #[error("block has {transactions} transactions but {txids} txids were supplied")]
    TxidCountMismatch { transactions: usize, txids: usize },
    #[error("block value total overflows the satoshi range")]
    BlockValueOverflow,
    #[error("block creates more value than it spends")]
    BlockOutputsExceedInputs,
    #[error("proof-of-work: header hash {hash} exceeds declared target")]
    ProofOfWork {
        hash: bitcoin_rs_primitives::Hash256,
    },
    #[error("declared target exceeds network max_target")]
    TargetAboveLimit,
    #[error("consensus: {0}")]
    Consensus(#[from] bitcoin_rs_consensus::ConsensusError),
    #[error("chain: {0}")]
    Chain(#[from] bitcoin_rs_chain::ChainError),
    #[error("utxo commit: {0}")]
    UtxoCommit(#[source] bitcoin_rs_utxo::UtxoError),
    #[error("block body persistence: {0}")]
    BlockBodyPersistence(#[source] bitcoin_rs_storage::StorageError),
    #[error("undo persistence: {0}")]
    UndoPersistence(#[source] bitcoin_rs_storage::StorageError),
    #[error("chainstate journal backpressure stopped block apply: {0}")]
    JournalBackpressure(#[source] Box<bitcoin_rs_storage::chainstate_journal::JournalWriterError>),
    #[error("undo record cannot restore spent output {txid}:{vout}")]
    UndoPrevoutMissing {
        txid: bitcoin_rs_primitives::Txid,
        vout: u32,
    },
    #[error(transparent)]
    UndoLoad(#[from] bitcoin_rs_utxo::contract::UndoLoadError),
    #[error("block {hash} is not the applied tip {tip}")]
    DisconnectNotTip {
        hash: bitcoin_rs_primitives::Hash256,
        tip: bitcoin_rs_primitives::Hash256,
    },
    #[error("block {hash} body does not match its header merkle root")]
    DisconnectBodyMismatch {
        hash: bitcoin_rs_primitives::Hash256,
    },
    #[error("durable head commit: {0}")]
    DurableHeadCommit(#[source] bitcoin_rs_storage::StorageError),
    #[error("durable head names tip {head}, not this block's parent {prev}")]
    DurableHeadLineage {
        head: bitcoin_rs_primitives::Hash256,
        prev: bitcoin_rs_primitives::Hash256,
    },
    #[error("disconnect of {hash} refused: durable head {head:?} does not certify it")]
    DisconnectOffDurableHead {
        hash: bitcoin_rs_primitives::Hash256,
        head: Option<bitcoin_rs_primitives::Hash256>,
    },
    #[error(
        "durable head {head_tip} at height {head_height} cannot be reconciled with restored tip {} at height {}: {reason}",
        restored_tip.map_or_else(|| "<none>".to_owned(), |tip| tip.to_string()),
        restored_height.map_or_else(|| "<none>".to_owned(), |height| height.to_string())
    )]
    DurableHeadGapUnrecoverable {
        head_tip: bitcoin_rs_primitives::Hash256,
        head_height: u32,
        restored_tip: Option<bitcoin_rs_primitives::Hash256>,
        restored_height: Option<u32>,
        reason: &'static str,
    },
    #[error("recovery checkpoint publication failed: {0}")]
    RecoveryPublication(#[source] Box<crate::checkpoint::CheckpointError>),
    #[error("coinstats rewind: {0}")]
    CoinStatsRewind(#[source] bitcoin_rs_utxo::stats::CoinStatsRewindError),
    #[error(
        "cannot disconnect block at height {height} at or below assumeutxo base height {base_height}"
    )]
    DisconnectBelowSnapshotBase { height: u32, base_height: u32 },
    #[error(
        "cannot prune while historical validation is required through assumeutxo base height {base_height}"
    )]
    PruneDuringHistoricalValidation { base_height: u32 },
    #[error(
        "historical chainstate cannot connect block at height {height} past target height {base_height}"
    )]
    ConnectPastHistoricalTarget { height: u32, base_height: u32 },
    #[error("historical target at height {base_height} is {found}, expected {expected}")]
    HistoricalTargetHashMismatch {
        base_height: u32,
        expected: bitcoin_rs_primitives::Hash256,
        found: bitcoin_rs_primitives::Hash256,
    },
}

/// The outcome of a refused or failed block disconnect.
#[derive(Debug, thiserror::Error)]
pub enum DisconnectError {
    #[error("disconnect refused: {0}")]
    Refused(#[source] Box<ApplyError>),
    #[error(
        "disconnect of block {hash} at height {height} failed after mutation began, chain state is partial: {source}"
    )]
    Fatal {
        hash: bitcoin_rs_primitives::Hash256,
        height: u32,
        #[source]
        source: Box<ApplyError>,
    },
    #[error(
        "disconnect of block {hash} at height {height} completed but the in-flight marker remains set: {source}"
    )]
    MarkerStuck {
        hash: bitcoin_rs_primitives::Hash256,
        height: u32,
        #[source]
        source: Box<ApplyError>,
    },
}
