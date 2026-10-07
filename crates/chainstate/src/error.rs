//! Typed authoritative chainstate mutation failures.

/// Errors produced when applying a block to the node state.
#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    /// Clean shutdown has closed block-apply admission.
    #[error("block apply rejected because clean shutdown has begun")]
    Shutdown,
    /// Another node-owned chain-change reservation is already active.
    #[error("another chain change is already active")]
    ConcurrentChainChange,
    /// The node-owned cross-domain generation counter cannot reserve another
    /// transition. Restart is required before another coordinated mutation.
    #[error("chain-change generation exhausted")]
    ChainChangeGenerationOverflow,
    /// The block's previous header hash does not match the current tip's hash.
    #[error("prev hash mismatch: tip {tip}, block prev {prev}")]
    PrevHashMismatch {
        /// Current tip header hash, big-endian hex.
        tip: bitcoin_rs_primitives::Hash256,
        /// Block's previous header hash, big-endian hex.
        prev: bitcoin_rs_primitives::Hash256,
    },
    /// Height arithmetic overflowed `u32::MAX`.
    #[error("height overflow at tip {0}")]
    HeightOverflow(u32),
    /// A transaction carries more outputs than a `u32` vout can index.
    #[error("output count of transaction {txid} exceeds the vout index range")]
    VoutOverflow {
        /// Transaction id whose output count overflowed.
        txid: bitcoin_rs_primitives::Txid,
    },
    /// The prepared block's txid slice does not cover every transaction.
    #[error("block has {transactions} transactions but {txids} txids were supplied")]
    TxidCountMismatch {
        /// Transactions in the block.
        transactions: usize,
        /// Txids supplied for them.
        txids: usize,
    },
    /// Summing a block's input or output values left the satoshi range.
    #[error("block value total overflows the satoshi range")]
    BlockValueOverflow,
    /// A block's non-coinbase outputs exceed the inputs they spend.
    #[error("block creates more value than it spends")]
    BlockOutputsExceedInputs,
    /// The block header hash does not satisfy its declared proof-of-work target.
    #[error("proof-of-work: header hash {hash} exceeds declared target")]
    ProofOfWork {
        /// Block header hash, big-endian display.
        hash: bitcoin_rs_primitives::Hash256,
    },
    /// Declared target exceeds the network's proof-of-work limit.
    #[error("declared target exceeds network max_target")]
    TargetAboveLimit,
    /// Consensus validation rejected the block.
    #[error("consensus: {0}")]
    Consensus(#[from] bitcoin_rs_consensus::ConsensusError),
    /// Block-tree insertion rejected the header.
    #[error("chain: {0}")]
    Chain(#[from] bitcoin_rs_chain::ChainError),
    /// UTXO commit failed during block apply.
    #[error("utxo commit: {0}")]
    UtxoCommit(#[source] bitcoin_rs_utxo::UtxoError),
    /// Persisting the canonical prunable block body failed.
    #[error("block body persistence: {0}")]
    BlockBodyPersistence(#[source] bitcoin_rs_storage::StorageError),
    /// Persisting the UTXO undo record failed.
    #[error("undo persistence: {0}")]
    UndoPersistence(#[source] bitcoin_rs_storage::StorageError),
    /// Journal durability or retention cannot recover within configured bounds.
    #[error("chainstate journal backpressure stopped block apply: {0}")]
    JournalBackpressure(#[source] Box<bitcoin_rs_storage::chainstate_journal::JournalWriterError>),
    /// A spent output had no resolved prevout, so the undo record would be
    /// unable to restore it.
    #[error("undo record cannot restore spent output {txid}:{vout}")]
    UndoPrevoutMissing {
        /// Transaction id of the unresolvable spend.
        txid: bitcoin_rs_primitives::Txid,
        /// Output index of the unresolvable spend.
        vout: u32,
    },
    /// The undo record for a block being disconnected could not be loaded.
    #[error(transparent)]
    UndoLoad(#[from] bitcoin_rs_utxo::contract::UndoLoadError),
    /// The block asked to be disconnected is not the applied tip.
    #[error("block {hash} is not the applied tip {tip}")]
    DisconnectNotTip {
        /// Block the caller asked to disconnect.
        hash: bitcoin_rs_primitives::Hash256,
        /// Block that is actually applied.
        tip: bitcoin_rs_primitives::Hash256,
    },
    /// The supplied block body does not match its own header.
    #[error("block {hash} body does not match its header merkle root")]
    DisconnectBodyMismatch {
        /// Block whose body was rejected.
        hash: bitcoin_rs_primitives::Hash256,
    },
    /// Advancing the durable head failed.
    #[error("durable head commit: {0}")]
    DurableHeadCommit(#[source] bitcoin_rs_storage::StorageError),
    /// The stored durable head names a tip other than this block's parent.
    #[error("durable head names tip {head}, not this block's parent {prev}")]
    DurableHeadLineage {
        /// Tip the stored head certifies.
        head: bitcoin_rs_primitives::Hash256,
        /// Parent the connecting block names.
        prev: bitcoin_rs_primitives::Hash256,
    },
    /// The durable head does not certify the block being disconnected, so
    /// the disconnect cannot advance the head from a known commit point.
    #[error("disconnect of {hash} refused: durable head {head:?} does not certify it")]
    DisconnectOffDurableHead {
        /// Block the caller asked to disconnect.
        hash: bitcoin_rs_primitives::Hash256,
        /// Tip the stored head certifies, when one exists.
        head: Option<bitcoin_rs_primitives::Hash256>,
    },
    /// The committed-but-unpublished gap cannot be replayed from durable
    /// facts, so startup must fail closed.
    #[error(
        "durable head {head_tip} at height {head_height} cannot be reconciled with restored tip {} at height {}: {reason}",
        restored_tip.map_or_else(|| "<none>".to_owned(), |tip| tip.to_string()),
        restored_height.map_or_else(|| "<none>".to_owned(), |height| height.to_string())
    )]
    DurableHeadGapUnrecoverable {
        /// Tip the stored head certifies.
        head_tip: bitcoin_rs_primitives::Hash256,
        /// Height the stored head certifies.
        head_height: u32,
        /// Tip the restored chainstate sits at, when one was restored.
        restored_tip: Option<bitcoin_rs_primitives::Hash256>,
        /// Height the restored chainstate sits at, when one was restored.
        restored_height: Option<u32>,
        /// Why the gap is not a replayable publication lag.
        reason: &'static str,
    },
    /// Recovery reconstructed a coherent state but could not publish the
    /// checkpoint required by its current phase, so its marker stays armed
    /// and startup fails closed. The underlying publication failure rides as
    /// source.
    #[error("recovery checkpoint publication failed: {0}")]
    RecoveryPublication(#[source] Box<crate::checkpoint::CheckpointError>),
    /// Rewinding the block-level coinstats failed.
    #[error("coinstats rewind: {0}")]
    CoinStatsRewind(#[source] bitcoin_rs_utxo::stats::CoinStatsRewindError),
    /// Disconnecting at or below the `AssumeUTXO` snapshot base is prohibited.
    #[error(
        "cannot disconnect block at height {height} at or below assumeutxo base height {base_height}"
    )]
    DisconnectBelowSnapshotBase {
        /// Height of the block being disconnected.
        height: u32,
        /// Snapshot base height.
        base_height: u32,
    },
    /// Prefix pruning must retain the history needed to validate a snapshot.
    #[error(
        "cannot prune while historical validation is required through assumeutxo base height {base_height}"
    )]
    PruneDuringHistoricalValidation {
        /// Snapshot base whose history is still required.
        base_height: u32,
    },
    /// Historical chainstate cannot connect blocks past the `AssumeUTXO` snapshot base.
    #[error(
        "historical chainstate cannot connect block at height {height} past target height {base_height}"
    )]
    ConnectPastHistoricalTarget {
        /// Height of the block attempting connection.
        height: u32,
        /// Target base height.
        base_height: u32,
    },
    /// The historical chain reached a different block at the pinned base height.
    #[error("historical target at height {base_height} is {found}, expected {expected}")]
    HistoricalTargetHashMismatch {
        /// Snapshot base height.
        base_height: u32,
        /// Pinned base hash.
        expected: bitcoin_rs_primitives::Hash256,
        /// Reconstructed block hash.
        found: bitcoin_rs_primitives::Hash256,
    },
}

/// The outcome of a refused or failed block disconnect.
#[derive(Debug, thiserror::Error)]
pub enum DisconnectError {
    /// Refused before anything was touched. The chain is exactly as it was.
    #[error("disconnect refused: {0}")]
    Refused(#[source] Box<ApplyError>),
    /// Failed after the rollback began. Some state is rolled back and some is
    /// not, and which is which depends on where it stopped.
    #[error(
        "disconnect of block {hash} at height {height} failed after mutation began, chain state is partial: {source}"
    )]
    Fatal {
        /// Block whose disconnect wedged.
        hash: bitcoin_rs_primitives::Hash256,
        /// Height it was applied at.
        height: u32,
        /// What failed.
        #[source]
        source: Box<ApplyError>,
    },
    /// Rolled back cleanly, but the in-flight marker could not be cleared.
    #[error(
        "disconnect of block {hash} at height {height} completed but the in-flight marker remains set: {source}"
    )]
    MarkerStuck {
        /// Block that was disconnected.
        hash: bitcoin_rs_primitives::Hash256,
        /// Height it was applied at.
        height: u32,
        /// Why the marker could not be cleared.
        #[source]
        source: Box<ApplyError>,
    },
}
