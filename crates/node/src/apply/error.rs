//! Typed authoritative chainstate mutation failures.

/// Errors produced when applying a block to the node state.
#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    /// Clean shutdown has closed block-apply admission.
    #[error("block apply rejected because clean shutdown has begun")]
    Shutdown,
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
    /// Summing a block's input or output values left the satoshi range.
    #[error("block value total overflows the satoshi range")]
    BlockValueOverflow,
    /// A block's non-coinbase outputs exceed the inputs they spend.
    ///
    /// Per-transaction verification rejects this first, so reaching it means
    /// the two disagree; refuse rather than treat the block as fee-free.
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
    /// Declared `nBits` does not match the parent block's `nBits` at a non-retarget height.
    #[error(
        "nBits {actual:08x} does not match parent {expected:08x} at non-retarget height {height}"
    )]
    NbitsNonRetargetMismatch {
        /// This block's `nBits`.
        actual: u32,
        /// Parent block's `nBits`.
        expected: u32,
        /// Block height.
        height: u32,
    },
    /// Consensus validation rejected the block.
    #[error("consensus: {0}")]
    Consensus(#[from] bitcoin_rs_consensus::ConsensusError),
    /// Block-tree insertion rejected the header.
    #[error("chain: {0}")]
    Chain(#[from] bitcoin_rs_chain::ChainError),
    /// UTXO commit failed during block apply.
    #[error("utxo commit: {0}")]
    UtxoCommit(#[from] bitcoin_rs_utxo::UtxoError),
    /// Persisting the canonical prunable block body failed.
    #[error("block body persistence: {0}")]
    BlockBodyPersistence(#[from] bitcoin_rs_storage::StorageError),
    /// Persisting the UTXO undo record failed.
    ///
    /// Fatal for the block: without a recoverable undo record the node could
    /// not disconnect it, so the block must not be applied.
    #[error("undo persistence: {0}")]
    UndoPersistence(#[source] bitcoin_rs_storage::StorageError),
    /// Journal durability or retention cannot recover within configured bounds.
    ///
    /// Refused before this block mutates chainstate; retry is safe after the
    /// journal flushes or a checkpoint compacts retained segments.
    #[error("chainstate journal backpressure stopped block apply: {0}")]
    JournalBackpressure(String),
    /// A spent output had no resolved prevout, so the undo record would be
    /// unable to restore it.
    #[error("undo record cannot restore spent output {txid}:{vout}")]
    UndoPrevoutMissing {
        /// Transaction id of the unresolvable spend.
        txid: bitcoin_rs_primitives::Txid,
        /// Output index of the unresolvable spend.
        vout: u32,
    },
    /// The undo record for a block being disconnected is absent.
    ///
    /// Fatal: without it the UTXO set cannot be restored, and guessing would
    /// silently corrupt the chainstate.
    #[error("no undo record for block {hash} at height {height}")]
    UndoRecordMissing {
        /// Block whose record is absent.
        hash: bitcoin_rs_primitives::Hash256,
        /// Height the block was applied at.
        height: u32,
    },
    /// A stored undo record could not be decoded.
    #[error("undo record for block {hash} is unreadable: {reason}")]
    UndoRecordUnreadable {
        /// Block whose record is unreadable.
        hash: bitcoin_rs_primitives::Hash256,
        /// Why the codec rejected it.
        reason: String,
    },
    /// Reading a stored undo record failed.
    #[error("undo record read: {0}")]
    UndoRead(#[source] bitcoin_rs_storage::StorageError),
    /// The block asked to be disconnected is not the applied tip.
    ///
    /// Blocks must be disconnected tip-first. Taking one from the middle would
    /// restore outputs that its descendants have already spent.
    #[error("block {hash} is not the applied tip {tip}")]
    DisconnectNotTip {
        /// Block the caller asked to disconnect.
        hash: bitcoin_rs_primitives::Hash256,
        /// Block that is actually applied.
        tip: bitcoin_rs_primitives::Hash256,
    },
    /// The supplied block body does not match its own header.
    ///
    /// The header hash commits to the merkle root, not to the transactions the
    /// caller handed over. A body swapped under a matching header would roll
    /// the index back over the wrong rows.
    #[error("block {hash} body does not match its header merkle root")]
    DisconnectBodyMismatch {
        /// Block whose body was rejected.
        hash: bitcoin_rs_primitives::Hash256,
    },
    /// Advancing the durable head failed.
    ///
    /// Fatal for the attempt, like a `UtxoCommit` refusal: the atomic batch
    /// may have applied before its durability receipt failed or was lost,
    /// and [`StorageError`] does not classify that phase. The caller must
    /// reconcile through recovery instead of retrying the block.
    #[error("durable head commit: {0}")]
    DurableHeadCommit(#[source] bitcoin_rs_storage::StorageError),
    /// The stored durable head names a tip other than this block's parent.
    ///
    /// The durable chain and the in-memory chain have diverged, typically
    /// because a crash landed the head batch but not the publication and
    /// recovery has not replayed the gap yet. Refusing keeps the head's
    /// lineage intact; only recovery can close the gap.
    #[error("durable head names tip {head}, not this block's parent {prev}")]
    DurableHeadLineage {
        /// Tip the stored head certifies.
        head: bitcoin_rs_primitives::Hash256,
        /// Parent the connecting block names.
        prev: bitcoin_rs_primitives::Hash256,
    },
    /// Rewinding the block-level coinstats failed.
    ///
    /// The per-coin fields ride the UTXO change listener and are already
    /// reversed by the undo; only height and transaction count are set
    /// directly, and a refusal here means they do not describe the block being
    /// disconnected.
    #[error("coinstats rewind: {0}")]
    CoinStatsRewind(#[source] bitcoin_rs_utxo::stats::CoinStatsRewindError),
}

/// The outcome of a refused or failed block disconnect.
///
/// Two variants because the caller must act differently, and a single error
/// type let that distinction live in prose where it can be missed. Every
/// disconnect failure is one or the other; there is no third case.
#[derive(Debug, thiserror::Error)]
pub enum DisconnectError {
    /// Refused before anything was touched. The chain is exactly as it was.
    ///
    /// Safe to report and carry on: no rollback started, so no state is half
    /// applied. Every check that can produce this runs in the planning step
    /// precisely so that refusing stays free.
    #[error("disconnect refused: {0}")]
    Refused(#[source] Box<ApplyError>),
    /// Failed after the rollback began. Some state is rolled back and some is
    /// not, and which is which depends on where it stopped.
    ///
    /// Fatal. Do not retry: the UTXO commit fires the set's change listener and
    /// coinstats is registered as one, so a second pass double-counts even
    /// where the set itself converges. Stop applying blocks and report the
    /// block named here, which is why the hash and height are carried rather
    /// than left for the caller to reconstruct.
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
    ///
    /// The chain is consistent and no data is lost. What is broken is the
    /// interlock: the marker still says a disconnect was in flight, so the next
    /// start refuses until it is cleared. Reported rather than folded into
    /// success because a caller that heard "done" would restart into a refusal
    /// it had no warning of.
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
