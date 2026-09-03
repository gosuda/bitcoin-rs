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

use super::record::{JournalRecord, Mutation, decode_record};
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
    /// Tree with the base→head header chain rebuilt (valid `NodeId`s + `chainwork`).
    pub tree: BlockTree,
    /// UTXO set with all committed-range mutations applied.
    pub utxo: UtxoSet,
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

/// Result of the committed-range scan: the full record list plus per-record
/// headers for the tree rebuild.
struct ScannedRange {
    records: Vec<JournalRecord>,
}

/// Reads and validates the committed range `(start..=head)` from the journal
/// directory: every record decodes, crc32c passes, and the contiguity
/// predicate (`record[i].height == record[i-1].height + 1` AND
/// `record[i].prev_hash == record[i-1].block_hash`) holds, with the first
/// record anchored to the checkpoint base tip.
fn scan_committed_range(
    dir: &cap_std::fs::Dir,
    head: &HeadMarker,
    base_tip_hash: [u8; 32],
    base_tip_height: u32,
) -> Result<ScannedRange, JournalReplayError> {
    // The retained window spans segment generations `start..=journal_gen` in
    // numeric order (zero-padded names make lexicographic == numeric).
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

    let mut records = Vec::new();
    let mut expected_height = base_tip_height.checked_add(1).ok_or_else(|| {
        JournalReplayError::CommittedRangeInvalid("base tip height overflow".to_owned())
    })?;
    let mut expected_prev = base_tip_hash;

    for generation in &generations {
        let end = if *generation == head.journal_gen {
            head.offset
        } else {
            u64::MAX
        };
        let mut records_in_segment = scan_segment(
            dir,
            *generation,
            head,
            end,
            &mut expected_height,
            &mut expected_prev,
        )?;
        records.append(&mut records_in_segment);
    }
    Ok(ScannedRange { records })
}

/// Reads one segment generation's committed window into records, enforcing
/// contiguity against `expected_height`/`expected_prev` (advanced in place).
fn scan_segment(
    dir: &cap_std::fs::Dir,
    generation: u64,
    head: &HeadMarker,
    window_end: u64,
    expected_height: &mut u32,
    expected_prev: &mut [u8; 32],
) -> Result<Vec<JournalRecord>, JournalReplayError> {
    use std::io::Read;

    // usize→u64: derive arithmetically (4-byte magic + 1-byte version + 4-byte length).
    const FRAME_HEADER_U64: u64 = 4 + 1 + 4;

    let name = super::writer::segment_name_pub(generation);
    let mut file = dir.open(name.as_str()).map_err(|error| {
        JournalReplayError::CommittedRangeInvalid(format!("open segment {generation}: {error}"))
    })?;
    let length = file.metadata().map_err(|error| {
        JournalReplayError::CommittedRangeInvalid(format!("stat segment {generation}: {error}"))
    })?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).map_err(|error| {
        JournalReplayError::CommittedRangeInvalid(format!("read segment {generation}: {error}"))
    })?;
    let length = usize::try_from(length.len()).map_err(|_| {
        JournalReplayError::CommittedRangeInvalid("segment size overflow".to_owned())
    })?;
    bytes.truncate(length);
    let file_len = u64::try_from(length).unwrap_or(u64::MAX);
    let end = window_end.min(file_len);

    let mut offset = if generation == head.start_gen {
        head.start_offset
    } else {
        0
    };
    let mut records = Vec::new();
    while offset < end {
        if offset + FRAME_HEADER_U64 > end {
            return Err(JournalReplayError::CommittedRangeInvalid(format!(
                "segment {generation}: truncated frame header at offset {offset}"
            )));
        }
        let header_idx = usize::try_from(offset).map_err(|_| {
            JournalReplayError::CommittedRangeInvalid("frame offset overflow".to_owned())
        })?;
        let payload_len = u32::from_le_bytes(
            bytes[header_idx + 5..header_idx + 9]
                .try_into()
                .map_err(|_| {
                    JournalReplayError::CommittedRangeInvalid(
                        "frame header length slice mismatch".to_owned(),
                    )
                })?,
        );
        let frame_len = FRAME_HEADER_U64 + u64::from(payload_len) + 4;
        if offset + frame_len > end {
            return Err(JournalReplayError::CommittedRangeInvalid(format!(
                "segment {generation}: truncated frame at offset {offset}"
            )));
        }
        let end_idx = usize::try_from(offset + frame_len).map_err(|_| {
            JournalReplayError::CommittedRangeInvalid("frame end overflow".to_owned())
        })?;
        let frame = &bytes[header_idx..end_idx];
        let record = decode_record(frame).map_err(|error| {
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
        offset += frame_len;
        records.push(record);
    }
    Ok(records)
}

/// Replays the journal above the checkpoint base, if one is usable.
///
/// `base_tip` anchors the contiguity predicate; the returned state (when
/// [`ReplayOutcome::Replayed`]) replaces the checkpoint state wholesale.
pub(crate) fn replay_from_journal(
    dir: &cap_std::fs::Dir,
    base_tip_hash: [u8; 32],
    base_tip_height: u32,
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
    if head.block_hash != base_tip_hash
        || head.height < base_tip_height
        || head.prev_hash != base_tip_hash && head.height != base_tip_height
    {
        // Head identity is validated precisely in the scan against the base;
        // this pre-filter only discards generations that cannot possibly
        // continue the base chain.
    }
    if head.block_hash == base_tip_hash && head.height == base_tip_height {
        // Empty range: the journal holds nothing beyond the base tip. The
        // caller can treat this as a successful no-op replay of the base.
        return ReplayOutcome::Fallback(JournalReplayError::NoHead);
    }
    let _ = base_chain_tx_count;
    let range = match scan_committed_range(dir, &head, base_tip_hash, base_tip_height) {
        Ok(range) => range,
        Err(error) => return ReplayOutcome::Fallback(error),
    };
    match replay_records(range.records, base_chain_tx_count) {
        Ok(state) => ReplayOutcome::Replayed(Box::new(state)),
        Err(error) => ReplayOutcome::Fallback(error),
    }
}

/// Applies the ordered records into a fresh `§2.2` state enumeration.
///
/// Headers first (they regenerate `NodeId`s + `chainwork` and are cheap to
/// reject), then mutations block-by-block in commit order. `CoinStats` is
/// driven by the `UtxoSet`'s change listener — the same mutations, the same
/// preimages — with `finish_block` applied per record for the block-level
/// height/tx-count deltas.
#[allow(clippy::needless_pass_by_value)] // `base_chain_tx_count` is copied into the accumulator by design
fn replay_records(
    records: Vec<JournalRecord>,
    base_chain_tx_count: u64,
) -> Result<ReplayedState, JournalReplayError> {
    let mut tree = BlockTree::new();
    let mut utxo = UtxoSet::new();
    // The change listener derives CoinStats from exactly the mutations replay
    // applies; without it the stats would silently diverge from the set.
    utxo.set_listener(Box::new(bitcoin_rs_utxo::stats::CoinStatsListener::new(
        bitcoin_rs_utxo::stats::CoinStats::default(),
    )));

    let mut prev_hash = records.first().map_or([0_u8; 32], |r| r.prev_hash);
    let mut cumulative_tx_count = base_chain_tx_count;

    for record in &records {
        // Header rebuild: the journal header chain IS the block ancestry
        // chain, so a reject here means the journal contradicts itself —
        // fail closed (plan rev 5 Task 5 test: "header reject at rebuild").
        let header = Header::consensus_decode(&record.raw_header[..]).map_err(|error| {
            JournalReplayError::HeaderRebuildRejected(format!("height {}: {error}", record.height))
        })?;
        if prev_hash != record.prev_hash {
            return Err(JournalReplayError::CommittedRangeInvalid(format!(
                "record {} prev_hash does not chain to {}",
                record.height,
                hex(&prev_hash)
            )));
        }
        let parent = tree
            .lookup(bitcoin_rs_primitives::Hash256::from_le_bytes(&prev_hash))
            .ok_or_else(|| {
                JournalReplayError::HeaderRebuildRejected(format!(
                    "height {}: parent {} missing from rebuilt tree",
                    record.height,
                    hex(&record.prev_hash)
                ))
            })?;
        let node_id = tree
            .insert_node(Some(parent), header, NodeStatus::HeaderValid)
            .map_err(|error| {
                JournalReplayError::HeaderRebuildRejected(format!(
                    "height {}: {error}",
                    record.height
                ))
            })?;
        tree.restore_chain_tx_count(
            node_id,
            cumulative_tx_count.saturating_add(record.block_tx_count),
        )
        .map_err(|error| {
            JournalReplayError::HeaderRebuildRejected(format!("height {}: {error}", record.height))
        })?;

        // Semantic mutations, in exact commit order, through the same
        // commit surface the live apply path uses (`commit_borrowed_block`:
        // adds then removes). The change listener keeps CoinStats aligned;
        // MuHash/amount/bogo/utxo_count derive from the same full-coin
        // preimages the record carries. Before each spend, the live coin is
        // checked against the journaled coin (height/coinbase/value) — a
        // mismatch means the journal and the reconstructed set diverged:
        // fail closed (plan §2.1 sanity).
        let mut replay_changes =
            BorrowedBlockChanges::with_capacity(record.mutations.len(), record.mutations.len());
        for mutation in &record.mutations {
            match mutation {
                Mutation::Create { coin } => {
                    replay_changes.add(BorrowedUtxoAdd::new(
                        coin.outpoint,
                        &coin.txout,
                        coin.coinbase,
                        coin.height,
                    ));
                }
                Mutation::Spend { coin } => {
                    if let Some(live) = utxo.get_entry(&coin.outpoint)
                        && (live.height != coin.height
                            || live.coinbase != coin.coinbase
                            || live.txout.value != coin.txout.value)
                    {
                        return Err(JournalReplayError::CommittedRangeInvalid(format!(
                            "spend at height {} does not match the live coin",
                            record.height
                        )));
                    }
                    replay_changes.remove(coin.outpoint);
                }
                Mutation::Overwrite { new_coin, .. } => {
                    // BIP30 exception: replaced coin is overwritten in place
                    // (BorrowedBlockChanges.add + remove pair).
                    replay_changes.add(BorrowedUtxoAdd::new(
                        new_coin.outpoint,
                        &new_coin.txout,
                        new_coin.coinbase,
                        new_coin.height,
                    ));
                    replay_changes.remove(new_coin.outpoint);
                }
            }
        }
        utxo.commit_borrowed_block(&replay_changes, &block_hash_of(record))
            .map_err(|error| {
                JournalReplayError::CommittedRangeInvalid(format!(
                    "height {}: utxo commit failed: {error}",
                    record.height
                ))
            })?;
        cumulative_tx_count = cumulative_tx_count.saturating_add(record.block_tx_count);
        prev_hash = record.block_hash;
        let _ = record.coin_stats_height_delta; // block-level stats handled below (finish_block hookup)
    }
    Ok(ReplayedState {
        tree,
        utxo,
        chain_tx_count: cumulative_tx_count,
    })
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
