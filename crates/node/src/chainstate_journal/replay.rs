//! Boot fast path: validates and replays the journal above a checkpoint base.
//!
//! Ownership: this module is the single owner of journal **consumption** —
//! reading records back, validating the committed range, rebuilding the
//! `BlockTree` header chain, and applying semantic mutations into the
//! `§2.2` state enumeration (`UtxoSet` + `CoinStats` + `chain_tx_count`). The
//! writer (`writer.rs`) owns production; the codec (`record.rs`) owns the
//! wire format; nothing else re-derives replay.
//!
//! Fail-closed policy (plan §2.1/rev 5): any corruption at or inside the
//! committed range — crc mismatch, malformed record, contiguity violation
//! against the base tip — invalidates the whole journal generation and
//! returns [`ReplayOutcome::Fallback`], so the node re-validates from the
//! checkpoint exactly as it would without a journal. Corruption beyond the
//! head is truncated by the writer's own recovery and never reaches here.

use bitcoin_rs_chain::{BlockTree, NodeStatus};
use bitcoin_rs_primitives::Hash256;
use bitcoin_rs_primitives::Header;
use bitcoin_rs_utxo::{BorrowedBlockChanges, BorrowedUtxoAdd, UtxoSet};

use super::record::{FRAME_HEADER_LEN, JournalRecord, MAX_PAYLOAD_LEN, Mutation, decode_record};
use super::writer::{HeadMarker, read_head_bytes};

/// Classification of a boot replay attempt.
pub(crate) enum ReplayOutcome {
    /// The journal carried the chain to `head`: the reconstructed state and
    /// tip are authoritative.
    Replayed(Box<ReplayedState>),
    /// The journal is absent or unusable; the caller must fall back to the
    /// checkpoint and full re-validation. Never partial.
    Fallback(JournalReplayError),
}

/// State reconstructed by a successful replay.
pub(crate) struct ReplayedState {
    /// Checkpoint tree extended through the journal head.
    pub tree: BlockTree,
    /// Checkpoint UTXO set with all committed-range mutations applied.
    pub utxo: UtxoSet,
    /// `CoinStats` after the same ordered mutations and block metadata.
    pub coin_stats: bitcoin_rs_utxo::stats::CoinStats,
    /// Valid applied-tip snapshot derived from the rebuilt tree node.
    pub applied_tip: bitcoin_rs_chain::TipSnapshot,
    /// Cumulative chain transaction count through the head.
    pub chain_tx_count: u64,
}

/// Why a replay did not (or could not) run.
#[derive(Debug, thiserror::Error)]
pub(crate) enum JournalReplayError {
    /// No journal directory contents (no head marker): nothing to replay.
    #[error("no journal head marker")]
    NoHead,
    /// The head marker failed its crc32c/version checks.
    #[error("journal head marker unreadable: {0}")]
    HeadUnreadable(String),
    /// The journal's base is not the restored checkpoint tip: the generation
    /// describes a different chain and must be discarded.
    #[error("journal base does not match the checkpoint tip")]
    BaseMismatch,
    /// A record inside the committed range is corrupt or non-contiguous:
    /// fail closed, never truncate the committed prefix.
    #[error("committed journal range is invalid: {0}")]
    CommittedRangeInvalid(String),
    /// Header-chain rebuild rejected a journaled header: fail closed.
    #[error("header rebuild rejected: {0}")]
    HeaderRebuildRejected(String),
}

impl JournalReplayError {
    pub(crate) const fn reason(&self) -> &'static str {
        match self {
            Self::NoHead => "no_head",
            Self::HeadUnreadable(_) => "head_unreadable",
            Self::BaseMismatch => "base_mismatch",
            Self::CommittedRangeInvalid(_) => "committed_range_invalid",
            Self::HeaderRebuildRejected(_) => "header_rebuild_rejected",
        }
    }

    pub(crate) fn is_checksum_failure(&self) -> bool {
        match self {
            Self::HeadUnreadable(_) => true,
            Self::CommittedRangeInvalid(message) => {
                message.contains("crc") || message.contains("checksum")
            }
            Self::NoHead | Self::BaseMismatch | Self::HeaderRebuildRejected(_) => false,
        }
    }
}

/// Reads and validates the committed range `(start..=head)` from the journal
/// directory: every record decodes, crc32c passes, and the contiguity
/// predicate (`record[i].height == record[i-1].height + 1` AND
/// `record[i].prev_hash == record[i-1].block_hash`) holds, with the first
/// record anchored to the checkpoint base tip.
fn stream_committed_range(
    dir: &cap_std::fs::Dir,
    head: &HeadMarker,
    base_tip_hash: [u8; 32],
    base_tip_height: u32,
    mut apply_record: impl FnMut(JournalRecord) -> Result<(), JournalReplayError>,
) -> Result<u64, JournalReplayError> {
    let mut generations = Vec::new();
    for entry in dir.entries().map_err(|error| {
        JournalReplayError::CommittedRangeInvalid(format!("segment listing failed: {error}"))
    })? {
        let entry = entry.map_err(|error| {
            JournalReplayError::CommittedRangeInvalid(format!("segment entry: {error}"))
        })?;
        if let Some(generation) =
            super::writer::parse_segment_name_pub(entry.file_name().to_string_lossy().as_ref())
            && generation >= head.start_gen
            && generation <= head.journal_gen
        {
            generations.push(generation);
        }
    }
    generations.sort_unstable();
    if generations.first() != Some(&head.start_gen) || generations.last() != Some(&head.journal_gen)
    {
        return Err(JournalReplayError::CommittedRangeInvalid(
            "retained segment window is incomplete".to_owned(),
        ));
    }

    let mut expected_height = base_tip_height.checked_add(1).ok_or_else(|| {
        JournalReplayError::CommittedRangeInvalid("base tip height overflow".to_owned())
    })?;
    let mut expected_prev = base_tip_hash;
    let mut record_count = 0_u64;
    for generation in &generations {
        let end = if *generation == head.journal_gen {
            head.offset
        } else {
            u64::MAX
        };
        record_count = record_count
            .checked_add(stream_segment(
                dir,
                *generation,
                head,
                end,
                &mut expected_height,
                &mut expected_prev,
                &mut apply_record,
            )?)
            .ok_or_else(|| {
                JournalReplayError::CommittedRangeInvalid("record count overflow".to_owned())
            })?;
    }
    Ok(record_count)
}

fn checked_frame_len(payload_len: u32) -> Result<usize, JournalReplayError> {
    let payload_len = usize::try_from(payload_len).map_err(|_| {
        JournalReplayError::CommittedRangeInvalid("payload length overflow".to_owned())
    })?;
    if payload_len > MAX_PAYLOAD_LEN {
        return Err(JournalReplayError::CommittedRangeInvalid(format!(
            "payload length exceeds codec limit: {payload_len} > {MAX_PAYLOAD_LEN}"
        )));
    }
    FRAME_HEADER_LEN
        .checked_add(payload_len)
        .and_then(|length| length.checked_add(core::mem::size_of::<u32>()))
        .ok_or_else(|| {
            JournalReplayError::CommittedRangeInvalid("frame length overflow".to_owned())
        })
}

/// Streams one segment generation record by record, enforcing contiguity.
fn stream_segment(
    dir: &cap_std::fs::Dir,
    generation: u64,
    head: &HeadMarker,
    window_end: u64,
    expected_height: &mut u32,
    expected_prev: &mut [u8; 32],
    apply_record: &mut impl FnMut(JournalRecord) -> Result<(), JournalReplayError>,
) -> Result<u64, JournalReplayError> {
    use std::io::{Read, Seek, SeekFrom};

    let frame_header_len = u64::try_from(FRAME_HEADER_LEN).map_err(|_| {
        JournalReplayError::CommittedRangeInvalid("frame header size overflow".to_owned())
    })?;

    let name = super::writer::segment_name_pub(generation);
    let file = dir.open(name.as_str()).map_err(|error| {
        JournalReplayError::CommittedRangeInvalid(format!("open segment {generation}: {error}"))
    })?;
    let length = file.metadata().map_err(|error| {
        JournalReplayError::CommittedRangeInvalid(format!("stat segment {generation}: {error}"))
    })?;
    let end = window_end.min(length.len());
    let mut offset = if generation == head.start_gen {
        head.start_offset
    } else {
        0
    };
    let mut reader = std::io::BufReader::new(file);
    reader.seek(SeekFrom::Start(offset)).map_err(|error| {
        JournalReplayError::CommittedRangeInvalid(format!(
            "seek segment {generation} to {offset}: {error}"
        ))
    })?;
    let mut record_count = 0_u64;

    while offset < end {
        if offset
            .checked_add(frame_header_len)
            .is_none_or(|header_end| header_end > end)
        {
            return Err(JournalReplayError::CommittedRangeInvalid(format!(
                "segment {generation}: truncated frame header at offset {offset}"
            )));
        }
        let mut header = [0_u8; FRAME_HEADER_LEN];
        reader.read_exact(&mut header).map_err(|error| {
            JournalReplayError::CommittedRangeInvalid(format!(
                "segment {generation}: read frame header at offset {offset}: {error}"
            ))
        })?;
        let payload_len = u32::from_le_bytes(header[5..9].try_into().map_err(|_| {
            JournalReplayError::CommittedRangeInvalid(
                "frame header length slice mismatch".to_owned(),
            )
        })?);
        let frame_size = checked_frame_len(payload_len)?;
        let frame_len = u64::try_from(frame_size).map_err(|_| {
            JournalReplayError::CommittedRangeInvalid("frame size overflow".to_owned())
        })?;
        if offset
            .checked_add(frame_len)
            .is_none_or(|frame_end| frame_end > end)
        {
            return Err(JournalReplayError::CommittedRangeInvalid(format!(
                "segment {generation}: truncated frame at offset {offset}"
            )));
        }
        let mut frame = Vec::with_capacity(frame_size);
        frame.extend_from_slice(&header);
        frame.resize(frame_size, 0);
        reader
            .read_exact(&mut frame[FRAME_HEADER_LEN..])
            .map_err(|error| {
                JournalReplayError::CommittedRangeInvalid(format!(
                    "segment {generation}: read frame at offset {offset}: {error}"
                ))
            })?;
        let record = decode_record(&frame).map_err(|error| {
            JournalReplayError::CommittedRangeInvalid(format!(
                "segment {generation} offset {offset}: {error}"
            ))
        })?;
        if record.height != *expected_height || record.prev_hash != *expected_prev {
            return Err(JournalReplayError::CommittedRangeInvalid(format!(
                "contiguity break at height {}: expected ({}, {}), found ({}, {})",
                record.height,
                *expected_height,
                hex(expected_prev),
                record.height,
                hex(&record.prev_hash)
            )));
        }
        *expected_height = record.height.checked_add(1).ok_or_else(|| {
            JournalReplayError::CommittedRangeInvalid("record height overflow".to_owned())
        })?;
        *expected_prev = record.block_hash;
        offset = offset.checked_add(frame_len).ok_or_else(|| {
            JournalReplayError::CommittedRangeInvalid("frame offset overflow".to_owned())
        })?;
        apply_record(record)?;
        record_count = record_count.checked_add(1).ok_or_else(|| {
            JournalReplayError::CommittedRangeInvalid("record count overflow".to_owned())
        })?;
    }
    Ok(record_count)
}

/// Replays a usable journal above an owned checkpoint state.
///
/// The base identity is authenticated against `head.json` before any mutation.
/// Callers reload the checkpoint on [`ReplayOutcome::Fallback`], so a semantic
/// failure can never expose a partially replayed state.
#[allow(clippy::too_many_arguments)]
pub(crate) fn replay_from_journal(
    dir: &cap_std::fs::Dir,
    base_generation: u64,
    tree: BlockTree,
    utxo: UtxoSet,
    coin_stats: bitcoin_rs_utxo::stats::CoinStats,
    base_tip: bitcoin_rs_chain::TipSnapshot,
    base_chain_tx_count: u64,
) -> ReplayOutcome {
    let head_bytes = match read_head_bytes(dir) {
        Ok(Some(bytes)) => bytes,
        Ok(None) => return ReplayOutcome::Fallback(JournalReplayError::NoHead),
        Err(error) => {
            return ReplayOutcome::Fallback(JournalReplayError::HeadUnreadable(error.to_string()));
        }
    };
    let head = match HeadMarker::deserialize(&head_bytes) {
        Ok(head) => head,
        Err(error) => {
            return ReplayOutcome::Fallback(JournalReplayError::HeadUnreadable(error.to_string()));
        }
    };
    if head.base_generation != base_generation
        || head.base_height != base_tip.height
        || head.base_hash != base_tip.hash.to_le_bytes()
        || head.base_chain_tx_count != base_chain_tx_count
        || head.height < base_tip.height
    {
        return ReplayOutcome::Fallback(JournalReplayError::BaseMismatch);
    }
    let mut replay =
        match ReplayAccumulator::new(tree, utxo, coin_stats, base_tip, base_chain_tx_count) {
            Ok(replay) => replay,
            Err(error) => return ReplayOutcome::Fallback(error),
        };
    let record_count = if head.height == replay.applied_tip.height {
        if head.block_hash != head.base_hash
            || head.chain_tx_count != base_chain_tx_count
            || head.record_count != 0
        {
            return ReplayOutcome::Fallback(JournalReplayError::BaseMismatch);
        }
        0
    } else {
        match stream_committed_range(dir, &head, head.base_hash, head.base_height, |record| {
            replay.apply(&record)
        }) {
            Ok(record_count) => record_count,
            Err(error) => return ReplayOutcome::Fallback(error),
        }
    };
    if record_count != head.record_count {
        return ReplayOutcome::Fallback(JournalReplayError::CommittedRangeInvalid(
            "record count does not match head marker".to_owned(),
        ));
    }
    let state = replay.finish();
    if let Err(error) = validate_replayed_head(&state, &head) {
        return ReplayOutcome::Fallback(error);
    }
    if state.chain_tx_count == head.chain_tx_count {
        ReplayOutcome::Replayed(Box::new(state))
    } else {
        ReplayOutcome::Fallback(JournalReplayError::CommittedRangeInvalid(
            "chain transaction count does not match head marker".to_owned(),
        ))
    }
}

fn validate_replayed_head(
    state: &ReplayedState,
    head: &HeadMarker,
) -> Result<(), JournalReplayError> {
    if state.applied_tip.height != head.height
        || state.applied_tip.hash.to_le_bytes() != head.block_hash
    {
        return Err(JournalReplayError::CommittedRangeInvalid(
            "replayed tip identity does not match head marker".to_owned(),
        ));
    }
    Ok(())
}

/// Applies ordered records above a restored checkpoint state.
///
/// Headers first regenerate valid `NodeId`s and chainwork. Mutations then pass
/// through the same `UtxoSet` commit surface as live apply, with a listener
/// seeded from the checkpoint `CoinStats`.
struct ReplayAccumulator {
    tree: BlockTree,
    utxo: UtxoSet,
    coin_stats: bitcoin_rs_utxo::stats::CoinStatsListener,
    applied_tip: bitcoin_rs_chain::TipSnapshot,
    prev_hash: [u8; 32],
    chain_tx_count: u64,
}

impl ReplayAccumulator {
    fn new(
        tree: BlockTree,
        mut utxo: UtxoSet,
        initial_coin_stats: bitcoin_rs_utxo::stats::CoinStats,
        base_tip: bitcoin_rs_chain::TipSnapshot,
        base_chain_tx_count: u64,
    ) -> Result<Self, JournalReplayError> {
        if base_chain_tx_count == 0 {
            return Err(JournalReplayError::CommittedRangeInvalid(
                "checkpoint chain_tx_count is unknown".to_owned(),
            ));
        }
        let base_node = tree.node(base_tip.tip_id).map_err(|error| {
            JournalReplayError::HeaderRebuildRejected(format!(
                "checkpoint tip node is unavailable: {error}"
            ))
        })?;
        if base_node.height != base_tip.height
            || base_node.hash != base_tip.hash
            || base_node.chainwork != base_tip.chainwork
        {
            return Err(JournalReplayError::HeaderRebuildRejected(
                "checkpoint tip snapshot does not match its tree node".to_owned(),
            ));
        }
        let coin_stats = bitcoin_rs_utxo::stats::CoinStatsListener::new(initial_coin_stats);
        utxo.set_listener(Box::new(coin_stats.clone()));
        let prev_hash = base_tip.hash.to_le_bytes();
        Ok(Self {
            tree,
            utxo,
            coin_stats,
            applied_tip: base_tip,
            prev_hash,
            chain_tx_count: base_chain_tx_count,
        })
    }

    fn apply(&mut self, record: &JournalRecord) -> Result<(), JournalReplayError> {
        self.chain_tx_count = self
            .chain_tx_count
            .checked_add(record.block_tx_count)
            .ok_or_else(|| {
                JournalReplayError::CommittedRangeInvalid(
                    "chain transaction count overflow".to_owned(),
                )
            })?;
        self.applied_tip =
            insert_replayed_header(&mut self.tree, record, self.prev_hash, self.chain_tx_count)?;
        apply_record_mutations(&self.utxo, record)?;
        advance_coin_stats(&self.coin_stats, record)?;
        self.prev_hash = record.block_hash;
        Ok(())
    }

    fn finish(self) -> ReplayedState {
        ReplayedState {
            tree: self.tree,
            utxo: self.utxo,
            coin_stats: self.coin_stats.snapshot(),
            applied_tip: self.applied_tip,
            chain_tx_count: self.chain_tx_count,
        }
    }
}

#[cfg(test)]
#[allow(clippy::needless_pass_by_value)]
fn replay_records(
    records: Vec<JournalRecord>,
    tree: BlockTree,
    utxo: UtxoSet,
    initial_coin_stats: bitcoin_rs_utxo::stats::CoinStats,
    base_tip: bitcoin_rs_chain::TipSnapshot,
    base_chain_tx_count: u64,
) -> Result<ReplayedState, JournalReplayError> {
    let mut replay = ReplayAccumulator::new(
        tree,
        utxo,
        initial_coin_stats,
        base_tip,
        base_chain_tx_count,
    )?;
    for record in &records {
        replay.apply(record)?;
    }
    Ok(replay.finish())
}

fn insert_replayed_header(
    tree: &mut BlockTree,
    record: &JournalRecord,
    expected_prev: [u8; 32],
    chain_tx_count: u64,
) -> Result<bitcoin_rs_chain::TipSnapshot, JournalReplayError> {
    let header = Header::consensus_decode(&record.raw_header[..]).map_err(|error| {
        JournalReplayError::HeaderRebuildRejected(format!("height {}: {error}", record.height))
    })?;
    if expected_prev != record.prev_hash
        || header.prev_blockhash.0.to_le_bytes() != record.prev_hash
        || header.compute_hash().0.to_le_bytes() != record.block_hash
    {
        return Err(JournalReplayError::CommittedRangeInvalid(format!(
            "record {} header identity does not match its chain fields",
            record.height
        )));
    }
    let parent = tree
        .lookup(Hash256::from_le_bytes(&expected_prev))
        .ok_or_else(|| {
            JournalReplayError::HeaderRebuildRejected(format!(
                "height {}: parent {} missing from checkpoint tree",
                record.height,
                hex(&record.prev_hash)
            ))
        })?;
    let node_id = tree
        .insert_node(Some(parent), header, NodeStatus::HeaderValid)
        .map_err(|error| {
            JournalReplayError::HeaderRebuildRejected(format!("height {}: {error}", record.height))
        })?;
    tree.restore_chain_tx_count(node_id, chain_tx_count)
        .map_err(|error| {
            JournalReplayError::HeaderRebuildRejected(format!("height {}: {error}", record.height))
        })?;
    let node = tree.node(node_id).map_err(|error| {
        JournalReplayError::HeaderRebuildRejected(format!("height {}: {error}", record.height))
    })?;
    if node.height != record.height || node.hash.to_le_bytes() != record.block_hash {
        return Err(JournalReplayError::HeaderRebuildRejected(format!(
            "height {}: rebuilt node identity mismatch",
            record.height
        )));
    }
    Ok(bitcoin_rs_chain::TipSnapshot {
        tip_id: node_id,
        height: node.height,
        chainwork: node.chainwork,
        hash: node.hash,
    })
}

fn apply_record_mutations(
    utxo: &UtxoSet,
    record: &JournalRecord,
) -> Result<(), JournalReplayError> {
    let mut changes =
        BorrowedBlockChanges::with_capacity(record.mutations.len(), record.mutations.len());
    for mutation in &record.mutations {
        match mutation {
            Mutation::Create { coin } => {
                if utxo.get_entry(&coin.outpoint).is_some() {
                    return Err(JournalReplayError::CommittedRangeInvalid(format!(
                        "create at height {} overwrites a live coin",
                        record.height
                    )));
                }
                changes.add(BorrowedUtxoAdd::new(
                    coin.outpoint,
                    &coin.txout,
                    coin.coinbase,
                    coin.height,
                ));
            }
            Mutation::Spend { coin } => {
                require_live_coin(utxo, coin, record.height, "spend")?;
                changes.remove(coin.outpoint);
            }
            Mutation::Overwrite { old_coin, new_coin } => {
                require_live_coin(utxo, old_coin, record.height, "overwrite")?;
                if old_coin.outpoint != new_coin.outpoint {
                    return Err(JournalReplayError::CommittedRangeInvalid(format!(
                        "overwrite at height {} changes its outpoint",
                        record.height
                    )));
                }
                changes.add(BorrowedUtxoAdd::new(
                    new_coin.outpoint,
                    &new_coin.txout,
                    new_coin.coinbase,
                    new_coin.height,
                ));
            }
        }
    }
    utxo.commit_borrowed_block(&changes, &block_hash_of(record))
        .map_err(|error| {
            JournalReplayError::CommittedRangeInvalid(format!(
                "height {}: utxo commit failed: {error}",
                record.height
            ))
        })
}

fn advance_coin_stats(
    coin_stats: &bitcoin_rs_utxo::stats::CoinStatsListener,
    record: &JournalRecord,
) -> Result<(), JournalReplayError> {
    let expected_height = i64::from(coin_stats.snapshot().height)
        .checked_add(record.coin_stats_height_delta)
        .and_then(|height| u32::try_from(height).ok())
        .ok_or_else(|| {
            JournalReplayError::CommittedRangeInvalid(format!(
                "height {}: invalid CoinStats height delta {}",
                record.height, record.coin_stats_height_delta
            ))
        })?;
    if expected_height != record.height {
        return Err(JournalReplayError::CommittedRangeInvalid(format!(
            "height {}: CoinStats delta reaches {expected_height}",
            record.height
        )));
    }
    coin_stats.finish_block(record.height, record.block_tx_count);
    Ok(())
}

fn require_live_coin(
    utxo: &UtxoSet,
    coin: &super::record::Coin,
    record_height: u32,
    mutation: &str,
) -> Result<(), JournalReplayError> {
    let Some(live) = utxo.get_entry(&coin.outpoint) else {
        return Err(JournalReplayError::CommittedRangeInvalid(format!(
            "{mutation} at height {record_height} references a missing coin"
        )));
    };
    if live.height != coin.height || live.coinbase != coin.coinbase || live.txout != coin.txout {
        return Err(JournalReplayError::CommittedRangeInvalid(format!(
            "{mutation} at height {record_height} does not match the live coin"
        )));
    }
    Ok(())
}

/// Lowercase hex for diagnostics.
fn hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .fold(String::with_capacity(bytes.len() * 2), |mut out, b| {
            use std::fmt::Write as _;
            let _ = write!(out, "{b:02x}");
            out
        })
}

/// The record's block hash as a [`Hash256`] (big-endian raw, matching the
/// header chain's hash semantics).
fn block_hash_of(record: &JournalRecord) -> Hash256 {
    Hash256::from_le_bytes(&record.block_hash)
}

#[cfg(test)]
mod tests {
    use bitcoin_rs_chain::{BlockTree, NodeStatus, TipSnapshot};
    use bitcoin_rs_primitives::{
        BlockHash, Hash256, Header, OutPoint, TxOut, Txid, consensus_bytes,
    };
    use bitcoin_rs_utxo::stats::{CoinStats, CoinStatsListener};
    use bitcoin_rs_utxo::{BorrowedBlockChanges, BorrowedUtxoAdd, UtxoSet};

    use super::{
        JournalRecord, JournalReplayError, Mutation, checked_frame_len, replay_records,
        validate_replayed_head,
    };
    use crate::chainstate_journal::Coin;
    use crate::chainstate_journal::record::MAX_PAYLOAD_LEN;
    use crate::chainstate_journal::writer::HeadMarker;

    type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
    type BaseState = (BlockTree, UtxoSet, CoinStats, TipSnapshot, Coin);

    fn header(prev_blockhash: BlockHash, marker: u8, time: u32) -> Header {
        let mut merkle = [0_u8; 32];
        merkle[0] = marker;
        Header {
            version: 1,
            prev_blockhash,
            merkle_root: Hash256::from_le_bytes(&merkle),
            time,
            bits: 0x207f_ffff,
            nonce: u32::from(marker),
        }
    }

    fn raw_header(header: &Header) -> [u8; 80] {
        let encoded = consensus_bytes(header);
        assert_eq!(encoded.len(), 80, "consensus header length changed");
        let mut raw = [0_u8; 80];
        raw.copy_from_slice(&encoded);
        raw
    }

    fn coin(marker: u8, height: u32, value: u64) -> Coin {
        Coin {
            outpoint: OutPoint::new(Txid(Hash256::from_le_bytes(&[marker; 32])), 0),
            txout: TxOut {
                value,
                script_pubkey: vec![0x51],
            },
            height,
            coinbase: true,
        }
    }

    fn base_state() -> TestResult<BaseState> {
        let mut tree = BlockTree::new();
        let base_header = header(BlockHash::default(), 1, 1);
        let base_id = tree.insert_node(None, base_header, NodeStatus::HeaderValid)?;
        tree.restore_chain_tx_count(base_id, 1)?;
        let base_node = tree.node(base_id)?;
        let base_tip = TipSnapshot {
            tip_id: base_id,
            height: base_node.height,
            chainwork: base_node.chainwork,
            hash: base_node.hash,
        };

        let base_coin = coin(1, 0, 50);
        let listener = CoinStatsListener::new(CoinStats::default());
        let mut utxo = UtxoSet::new();
        utxo.set_listener(Box::new(listener.clone()));
        let mut changes = BorrowedBlockChanges::with_capacity(1, 0);
        changes.add(BorrowedUtxoAdd::new(
            base_coin.outpoint,
            &base_coin.txout,
            base_coin.coinbase,
            base_coin.height,
        ));
        utxo.commit_borrowed_block(&changes, &base_tip.hash)?;
        listener.finish_block(0, 1);
        Ok((tree, utxo, listener.snapshot(), base_tip, base_coin))
    }

    #[test]
    fn oversized_frame_is_rejected_before_payload_allocation() -> TestResult {
        let oversized = u32::try_from(MAX_PAYLOAD_LEN.checked_add(1).ok_or("payload overflow")?)?;
        assert!(matches!(
            checked_frame_len(oversized),
            Err(JournalReplayError::CommittedRangeInvalid(message))
                if message.contains("payload length exceeds")
        ));
        Ok(())
    }

    #[test]
    fn replay_extends_checkpoint_state_and_returns_valid_tip() -> TestResult {
        let (tree, utxo, coin_stats, base_tip, base_coin) = base_state()?;
        let next_header = header(BlockHash(base_tip.hash), 2, 2);
        let next_hash = next_header.compute_hash();
        let new_coin = coin(2, 1, 25);
        let record = JournalRecord {
            height: 1,
            block_hash: next_hash.0.to_le_bytes(),
            prev_hash: base_tip.hash.to_le_bytes(),
            block_tx_count: 2,
            coin_stats_height_delta: 1,
            raw_header: raw_header(&next_header),
            mutations: vec![Mutation::Create {
                coin: new_coin.clone(),
            }],
        };

        let replayed = replay_records(vec![record], tree, utxo, coin_stats, base_tip, 1)?;

        assert!(replayed.utxo.get_entry(&base_coin.outpoint).is_some());
        assert!(replayed.utxo.get_entry(&new_coin.outpoint).is_some());
        assert_eq!(replayed.chain_tx_count, 3);
        assert_eq!(replayed.coin_stats.height, 1);
        assert_eq!(replayed.coin_stats.tx_count, 3);
        assert_eq!(replayed.applied_tip.height, 1);
        assert_eq!(replayed.applied_tip.hash, next_hash.0);
        let node = replayed.tree.node(replayed.applied_tip.tip_id)?;
        assert_eq!(node.hash, replayed.applied_tip.hash);
        assert_eq!(node.chainwork, replayed.applied_tip.chainwork);
        Ok(())
    }

    #[test]
    fn replayed_frontier_must_match_the_durable_head_identity() -> TestResult {
        let (tree, utxo, coin_stats, base_tip, _) = base_state()?;
        let next_header = header(BlockHash(base_tip.hash), 2, 2);
        let next_hash = next_header.compute_hash();
        let base_hash = base_tip.hash.to_le_bytes();
        let record = JournalRecord {
            height: 1,
            block_hash: next_hash.0.to_le_bytes(),
            prev_hash: base_tip.hash.to_le_bytes(),
            block_tx_count: 2,
            coin_stats_height_delta: 1,
            raw_header: raw_header(&next_header),
            mutations: Vec::new(),
        };
        let replayed = replay_records(vec![record], tree, utxo, coin_stats, base_tip, 1)?;
        let head = HeadMarker {
            base_generation: 1,
            base_height: 0,
            base_hash,
            base_chain_tx_count: 1,
            start_gen: 1,
            start_offset: 0,
            journal_gen: 1,
            offset: 1,
            height: replayed.applied_tip.height,
            block_hash: replayed.applied_tip.hash.to_le_bytes(),
            prev_hash: base_hash,
            chain_tx_count: replayed.chain_tx_count,
            record_count: 1,
        };

        validate_replayed_head(&replayed, &head)?;
        let mut wrong_height = head;
        wrong_height.height += 1;
        assert!(validate_replayed_head(&replayed, &wrong_height).is_err());
        let mut wrong_hash = head;
        wrong_hash.block_hash[0] ^= 0xff;
        assert!(validate_replayed_head(&replayed, &wrong_hash).is_err());
        Ok(())
    }
}
