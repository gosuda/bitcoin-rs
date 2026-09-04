use std::ops::ControlFlow;

use bitcoin_rs_primitives::{Block, OutPoint, Tx, Txid, encode, varint};
use bitcoin_rs_storage::{
    ColumnFamily, KvSnapshot, KvStore, PrefixScanLimit, StorageError, WriteBatch, WriteCondition,
};
use bitcoin_slices::{Visit as _, Visitor, bsl};
use thiserror::Error;
use tracing::debug;
use zerocopy::IntoBytes;

use crate::types::{
    HashPrefixRow, HeaderRow, ScriptHash, ScriptHashRow, SpendingPrefixRow, TxidRow,
};

/// Errors returned while indexing confirmed blocks.
#[derive(Debug, Error)]
pub enum IndexError {
    /// Backend storage failed while applying index rows.
    #[error("storage error: {0}")]
    Storage(#[from] StorageError),
    /// `bitcoin_slices` rejected the serialized block.
    #[error("invalid serialized block: {0:?}")]
    BlockParse(bitcoin_slices::Error),
    /// This indexer cannot undo a block, so a reorg cannot be made consistent.
    #[error("this indexer does not support block disconnect")]
    UnsupportedRollback,
    /// A block header did not have the consensus 80-byte length.
    #[error("invalid block header length {len}")]
    InvalidHeaderLength {
        /// Actual header length observed by the visitor.
        len: usize,
    },
    /// A transaction's byte range in the block does not fit the `u32` that
    /// [`crate::types::TxPosition`] stores.
    ///
    /// Unreachable for any consensus-valid block — a block is capped far below
    /// 4 GiB — but the arithmetic is checked rather than wrapped, and the
    /// failure is an addressing limit, not a malformed header.
    #[error("transaction byte range does not fit u32 at block offset {offset}")]
    UnaddressablePosition {
        /// Block byte offset reached when the range stopped fitting.
        offset: u64,
    },
    /// Durable watermark bytes do not have the expected length.
    #[error("invalid TxIndex watermark encoding")]
    InvalidWatermark,
    /// A persisted `TxIndex` prefix row had an invalid key length.
    #[error("invalid TxIndex prefix row length {len}")]
    InvalidPrefixRowLength {
        /// Actual key length observed in storage.
        len: usize,
    },
    /// The `TxIndex` format version is not supported.
    #[error("unsupported TxIndex format version {version}")]
    UnsupportedTxIndexFormatVersion {
        /// Format version value found in the store.
        version: u32,
    },
    /// A serialized block header does not hash to the expected identity.
    #[error(
        "block body identity mismatch at height {height}: expected {expected:?}, found {actual:?}"
    )]
    BlockIdentityMismatch {
        /// Expected active-chain height.
        height: u32,
        /// Expected active-chain block hash.
        expected: [u8; 32],
        /// Hash of the serialized body's exact 80-byte header.
        actual: [u8; 32],
    },
    /// The watermark block identity row is missing during rollback.
    #[error("TxIndex watermark block identity row is missing at height {height} ({hash:?})")]
    MissingWatermarkIdentity {
        /// Watermark height.
        height: u32,
        /// Watermark hash.
        hash: [u8; 32],
    },
    /// Prepared mutation accounting exceeded the platform size type.
    #[error("prepared TxIndex mutation size overflow")]
    MutationSizeOverflow,
    /// A prepared forward transition does not extend the durable watermark.
    #[error("prepared TxIndex transition is not contiguous with {watermark:?}")]
    NonContiguousPrepared {
        /// Durable watermark observed before the write.
        watermark: Option<IndexWatermark>,
    },
    /// A prepared transition did not begin at the durable watermark it expected.
    #[error("TxIndex watermark mismatch: expected {expected:?}, found {actual:?}")]
    WatermarkMismatch {
        /// Watermark the caller prepared from.
        expected: Option<IndexWatermark>,
        /// Watermark found in the store.
        actual: Option<IndexWatermark>,
    },
    /// A prepared transition cannot mix with legacy buffered rows.
    #[error("cannot write prepared TxIndex mutations with buffered legacy rows")]
    PendingLegacyRows,
    /// `TxIndex` tables exist but the format-version key is missing.
    #[error("TxIndex tables are present without a versioned watermark")]
    LegacyCursorlessIndex,
    /// A crash-recovery marker for a capability rebuild was malformed.
    #[error("invalid TxIndex capability reset marker")]
    InvalidResetMarker,
    /// A durable capability reset rejected state derived before the reset.
    #[error("capability reset in progress; discard prepared state and re-derive")]
    ResetInProgress,
    /// The durable reset version exhausted `u64` and can no longer advance.
    #[error("capability reset version exhausted")]
    ResetVersionOverflow,
    /// Storage returned an empty but incomplete reset scan, which no
    /// conforming backend produces when row capacity is positive.
    #[error("capability reset scan returned an empty incomplete result")]
    ResetScanIncomplete,
    /// Durable ordinary-state revision bytes were not exactly one little-endian `u64`.
    #[error("invalid TxIndex ordinary-state revision encoding")]
    InvalidStateRevision,
    /// The ordinary-state revision exhausted `u64` and can no longer advance.
    #[error("TxIndex ordinary-state revision exhausted")]
    StateRevisionOverflow,
    /// Another ordinary writer committed after this state was captured.
    #[error("TxIndex state changed; discard derived state and re-derive")]
    StaleIndexState,
}

// Reserved metadata keys in `ColumnFamily::UtxoMeta`. The 0x00 prefix is reserved for
// TxIndex metadata; data row keys begin with ASCII letters only and can never collide.
const FORMAT_VERSION_KEY: &[u8] = &[0x00, b'V'];
const FORMAT_VERSION_VALUE: [u8; 4] = [0x04, 0x00, 0x00, 0x00];
/// Format 3 stores Spending keys without positions. This build still
/// understands those rows (resolvers fall back to a full block) and upgrades
/// by resetting only `ScriptHistory`, leaving `TxLookup` ready (`IDX-04`).
const FORMAT_VERSION_V3: [u8; 4] = [0x03, 0x00, 0x00, 0x00];
const TX_LOOKUP_WATERMARK_KEY: &[u8] = &[0x00, b'T'];
const SCRIPT_HISTORY_WATERMARK_KEY: &[u8] = &[0x00, b'S'];
/// Monotonic revision shared by every ordinary index mutation.
const ORDINARY_STATE_REVISION_KEY: &[u8] = &[0x00, b'O'];
/// Permanent versioned capability-reset state (`0x00, b'R'`). Absent only
/// before the first reset; afterwards the key always exists, either as
/// `Idle = [0xFF, version(u64 LE)]` (9 bytes) or as a claim
/// `[mask, process_epoch(u64 LE), base_version(u64 LE)]` (17 bytes).
/// The process epoch records provenance only; any process can complete the
/// exact claim. Interrupted 1-byte (`[mask]`) and 9-byte
/// (`[mask, process_epoch(u64 LE)]`) claims from earlier binaries are adopted
/// with a base version of zero; every other shape is a typed error. Completion
/// never deletes the key: it CASes the exact claim to
/// `Idle(base_version + 1)`, which makes stale fences un-reusable (no ABA)
/// across repeated resets.
const RESET_CAPABILITIES_KEY: &[u8] = &[0x00, b'R'];
/// Consumer cursor slot (`0x00, b'C'`). Opaque bytes owned by the node-side
/// reconciliation consumer; data row keys begin with ASCII letters only and
/// can never collide with the reserved `0x00` prefix.
const CONSUMER_CURSOR_KEY: &[u8] = &[0x00, b'C'];
const WATERMARK_LEN: usize = crate::types::HEIGHT_SIZE + 32;
const RESET_SCAN_LIMIT: PrefixScanLimit = PrefixScanLimit {
    max_rows: 1_000,
    max_bytes: 256 * 1024,
};
const RESET_IDLE_TAG: u8 = 0xFF;
const RESET_IDLE_LEN: usize = 1 + size_of::<u64>();
const RESET_CLAIM_LEN: usize = 1 + 2 * size_of::<u64>();

/// Decoded durable capability-reset state.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum ResetState {
    /// No reset is owed; `version` advances once per completed reset.
    Idle { version: u64 },
    /// A reset obligation derived on top of `base_version`. `process_epoch`
    /// records where the claim originated; it does not grant exclusive rights.
    Claim {
        mask: u8,
        process_epoch: u64,
        base_version: u64,
    },
}

/// Exact reset-state observation fencing one derived index write.
///
/// Captured before any store-dependent derivation, carried by value into the
/// matching commit, and re-checked as a conditional write on the exact bytes:
/// an ordinary commit only lands while the reset state is byte-identical to
/// the observation, so a reset that completed in between (idle version
/// advanced, or state moved Absent -> Idle) rejects the stale write instead
/// of silently re-adopting it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct IndexWriteFence {
    state: IndexWriteFenceState,
    revision: Option<u64>,
    watermarks: IndexWatermarks,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IndexWriteFenceState {
    /// No reset state existed; the commit requires the key to stay absent.
    Absent,
    /// Exact `Idle` bytes observed; the commit requires the same bytes.
    Idle([u8; RESET_IDLE_LEN]),
}

/// Atomic disposition of the reconciliation consumer cursor inside one
/// committed index transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConsumerCursorUpdate<'a> {
    /// Preserve the currently stored cursor.
    Keep,
    /// Replace the cursor with these opaque consumer bytes.
    Set(&'a [u8]),
    /// Delete the cursor atomically with the row mutation.
    Clear,
}

fn encode_idle(version: u64) -> [u8; RESET_IDLE_LEN] {
    let mut value = [0_u8; RESET_IDLE_LEN];
    value[0] = RESET_IDLE_TAG;
    value[1..].copy_from_slice(&version.to_le_bytes());
    value
}

fn encode_claim(mask: u8, process_epoch: u64, base_version: u64) -> [u8; RESET_CLAIM_LEN] {
    let mut value = [0_u8; RESET_CLAIM_LEN];
    value[0] = mask;
    value[1..9].copy_from_slice(&process_epoch.to_le_bytes());
    value[9..].copy_from_slice(&base_version.to_le_bytes());
    value
}

fn valid_reset_mask(mask: u8) -> bool {
    mask != 0 && IndexCapabilities::from_mask(mask).is_ok()
}

/// Decodes exactly `size_of::<u64>()` bytes as little-endian; any other
/// length is a malformed reset marker.
fn decode_le_u64(bytes: &[u8]) -> Result<u64, IndexError> {
    let raw: [u8; size_of::<u64>()] = bytes
        .try_into()
        .map_err(|_| IndexError::InvalidResetMarker)?;
    Ok(u64::from_le_bytes(raw))
}

fn decode_state_revision(bytes: &[u8]) -> Result<u64, IndexError> {
    let raw: [u8; size_of::<u64>()] = bytes
        .try_into()
        .map_err(|_| IndexError::InvalidStateRevision)?;
    Ok(u64::from_le_bytes(raw))
}

fn parse_reset_state(bytes: &[u8]) -> Result<ResetState, IndexError> {
    match bytes {
        [mask] if valid_reset_mask(*mask) => Ok(ResetState::Claim {
            mask: *mask,
            process_epoch: 0,
            base_version: 0,
        }),
        [RESET_IDLE_TAG, version @ ..] if version.len() == size_of::<u64>() => {
            Ok(ResetState::Idle {
                version: decode_le_u64(version)?,
            })
        }
        [mask, process_epoch_bytes @ ..]
            if process_epoch_bytes.len() == size_of::<u64>() && valid_reset_mask(*mask) =>
        {
            Ok(ResetState::Claim {
                mask: *mask,
                process_epoch: decode_le_u64(process_epoch_bytes)?,
                base_version: 0,
            })
        }
        [mask, process_epoch_and_base @ ..]
            if process_epoch_and_base.len() == 2 * size_of::<u64>() && valid_reset_mask(*mask) =>
        {
            Ok(ResetState::Claim {
                mask: *mask,
                process_epoch: decode_le_u64(&process_epoch_and_base[..8])?,
                base_version: decode_le_u64(&process_epoch_and_base[8..])?,
            })
        }
        _ => Err(IndexError::InvalidResetMarker),
    }
}

/// Captures the reset state, ordinary revision, and both watermarks from one
/// point-in-time snapshot. Pending reset claims are cooperatively completed
/// only after the snapshot has been released.
fn capture_write_fence<S: KvStore>(
    store: &S,
    generation: u64,
) -> Result<IndexWriteFence, IndexError> {
    let snapshot = store.snapshot()?;
    let observed_reset = snapshot.get(ColumnFamily::UtxoMeta, RESET_CAPABILITIES_KEY)?;
    let observed_revision = snapshot.get(ColumnFamily::UtxoMeta, ORDINARY_STATE_REVISION_KEY)?;
    let observed_tx_lookup = snapshot.get(ColumnFamily::UtxoMeta, TX_LOOKUP_WATERMARK_KEY)?;
    let observed_script_history =
        snapshot.get(ColumnFamily::UtxoMeta, SCRIPT_HISTORY_WATERMARK_KEY)?;
    drop(snapshot);

    let state = match observed_reset.as_deref() {
        None => IndexWriteFenceState::Absent,
        Some(bytes) => match parse_reset_state(bytes) {
            Ok(ResetState::Idle { .. }) => IndexWriteFenceState::Idle(
                bytes
                    .try_into()
                    .map_err(|_| IndexError::InvalidResetMarker)?,
            ),
            Ok(ResetState::Claim { process_epoch, .. }) => {
                debug!(
                    process_epoch,
                    generation, "cooperatively completing pending capability reset claim"
                );
                resume_capability_reset(store, generation, 0)?;
                return Err(IndexError::ResetInProgress);
            }
            Err(error) => {
                ensure_raw_reset_live(store, generation, Some(bytes))?;
                return Err(error);
            }
        },
    };

    let decoded: Result<(Option<u64>, IndexWatermarks), IndexError> = (|| {
        let revision = observed_revision
            .as_deref()
            .map(decode_state_revision)
            .transpose()?;
        let watermarks = IndexWatermarks {
            tx_lookup: observed_tx_lookup
                .as_deref()
                .map(IndexWatermark::from_bytes)
                .transpose()?,
            script_history: observed_script_history
                .as_deref()
                .map(IndexWatermark::from_bytes)
                .transpose()?,
        };
        Ok((revision, watermarks))
    })();
    ensure_reset_live(store, generation, &state)?;
    let (revision, watermarks) = decoded?;

    Ok(IndexWriteFence {
        state,
        revision,
        watermarks,
    })
}

fn reset_condition(state: &IndexWriteFenceState) -> WriteCondition<'_> {
    match state {
        IndexWriteFenceState::Absent => WriteCondition::Absent {
            cf: ColumnFamily::UtxoMeta,
            key: RESET_CAPABILITIES_KEY,
        },
        IndexWriteFenceState::Idle(expected) => WriteCondition::Equals {
            cf: ColumnFamily::UtxoMeta,
            key: RESET_CAPABILITIES_KEY,
            expected,
        },
    }
}

fn ensure_reset_live<S: KvStore>(
    store: &S,
    generation: u64,
    state: &IndexWriteFenceState,
) -> Result<(), IndexError> {
    let current = store.get(ColumnFamily::UtxoMeta, RESET_CAPABILITIES_KEY)?;
    let live = match (state, current.as_deref()) {
        (IndexWriteFenceState::Absent, None) => true,
        (IndexWriteFenceState::Idle(expected), Some(bytes)) => bytes == expected.as_slice(),
        _ => false,
    };
    if live {
        return Ok(());
    }
    resume_capability_reset(store, generation, 0)?;
    Err(IndexError::ResetInProgress)
}

fn ensure_raw_reset_live<S: KvStore>(
    store: &S,
    generation: u64,
    observed: Option<&[u8]>,
) -> Result<(), IndexError> {
    if store
        .get(ColumnFamily::UtxoMeta, RESET_CAPABILITIES_KEY)?
        .as_deref()
        == observed
    {
        return Ok(());
    }
    resume_capability_reset(store, generation, 0)?;
    Err(IndexError::ResetInProgress)
}

#[derive(Clone, Copy)]
struct ExactResetClaim {
    bytes: [u8; RESET_CLAIM_LEN],
    len: usize,
}

impl ExactResetClaim {
    fn from_observed(observed: &[u8]) -> Self {
        let mut bytes = [0_u8; RESET_CLAIM_LEN];
        bytes[..observed.len()].copy_from_slice(observed);
        Self {
            bytes,
            len: observed.len(),
        }
    }

    fn full(bytes: [u8; RESET_CLAIM_LEN]) -> Self {
        Self {
            bytes,
            len: RESET_CLAIM_LEN,
        }
    }

    fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    fn with_mask(mut self, mask: u8) -> Self {
        self.bytes[0] = mask;
        self
    }

    fn condition(&self) -> WriteCondition<'_> {
        WriteCondition::Equals {
            cf: ColumnFamily::UtxoMeta,
            key: RESET_CAPABILITIES_KEY,
            expected: self.as_slice(),
        }
    }
}

/// A cooperative reset obligation. The process epoch is provenance only; any
/// process can complete the exact raw claim. Same-mask adoption preserves its
/// 1/9/17-byte encoding.
struct ResetWork {
    mask: u8,
    claim: ExactResetClaim,
    revision: Option<u64>,
    next_reset: [u8; RESET_IDLE_LEN],
    next_revision: [u8; size_of::<u64>()],
}

fn prepare_reset_work(
    mask: u8,
    claim: ExactResetClaim,
    base_version: u64,
    revision: Option<u64>,
) -> Result<ResetWork, IndexError> {
    let next_reset_version = base_version
        .checked_add(1)
        .ok_or(IndexError::ResetVersionOverflow)?;
    let next_revision = revision
        .unwrap_or(0)
        .checked_add(1)
        .ok_or(IndexError::StateRevisionOverflow)?;
    Ok(ResetWork {
        mask,
        claim,
        revision,
        next_reset: encode_idle(next_reset_version),
        next_revision: next_revision.to_le_bytes(),
    })
}

fn revision_condition(
    revision: Option<u64>,
    encoded: &[u8; size_of::<u64>()],
) -> WriteCondition<'_> {
    match revision {
        Some(_) => WriteCondition::Equals {
            cf: ColumnFamily::UtxoMeta,
            key: ORDINARY_STATE_REVISION_KEY,
            expected: encoded,
        },
        None => WriteCondition::Absent {
            cf: ColumnFamily::UtxoMeta,
            key: ORDINARY_STATE_REVISION_KEY,
        },
    }
}

fn watermark_condition<'a>(
    encoded: Option<&'a [u8; WATERMARK_LEN]>,
    key: &'static [u8],
) -> WriteCondition<'a> {
    match encoded {
        Some(expected) => WriteCondition::Equals {
            cf: ColumnFamily::UtxoMeta,
            key,
            expected,
        },
        None => WriteCondition::Absent {
            cf: ColumnFamily::UtxoMeta,
            key,
        },
    }
}

/// Applies one ordinary batch under the coherent fence. Four exact conditions
/// fence the batch: reset state, ordinary revision, and both watermark rows.
/// The commit also inserts the next revision. A lost race with an unchanged
/// reset returns [`IndexError::StaleIndexState`]. A moved reset cooperatively
/// completes the pending exact claim and returns [`IndexError::ResetInProgress`].
fn commit_ordinary<S: KvStore>(
    store: &S,
    generation: u64,
    fence: &IndexWriteFence,
    mut batch: S::WriteBatch,
) -> Result<(), IndexError> {
    let next_revision = fence
        .revision
        .unwrap_or(0)
        .checked_add(1)
        .ok_or(IndexError::StateRevisionOverflow)?;
    batch.put(
        ColumnFamily::UtxoMeta,
        ORDINARY_STATE_REVISION_KEY,
        &next_revision.to_le_bytes(),
    );
    let revision_bytes = fence.revision.unwrap_or(0).to_le_bytes();
    let tx_lookup = fence
        .watermarks
        .tx_lookup
        .map(|watermark| watermark.to_bytes());
    let script_history = fence
        .watermarks
        .script_history
        .map(|watermark| watermark.to_bytes());
    let conditions = [
        reset_condition(&fence.state),
        revision_condition(fence.revision, &revision_bytes),
        watermark_condition(tx_lookup.as_ref(), TX_LOOKUP_WATERMARK_KEY),
        watermark_condition(script_history.as_ref(), SCRIPT_HISTORY_WATERMARK_KEY),
    ];
    if store.write_durable_if(&conditions, batch)? {
        return Ok(());
    }
    ensure_reset_live(store, generation, &fence.state)?;
    Err(IndexError::StaleIndexState)
}

/// Rechecks the exact reset state and ordinary revision captured by `fence`.
/// A moved reset adopts or completes the pending claim first; an unchanged
/// reset with a moved revision reports the derived state as stale.
fn ensure_fence_live<S: KvStore>(
    store: &S,
    generation: u64,
    fence: &IndexWriteFence,
) -> Result<(), IndexError> {
    let snapshot = store.snapshot()?;
    let current_reset = snapshot.get(ColumnFamily::UtxoMeta, RESET_CAPABILITIES_KEY)?;
    let current_revision = snapshot.get(ColumnFamily::UtxoMeta, ORDINARY_STATE_REVISION_KEY)?;
    drop(snapshot);

    let reset_live = match (&fence.state, current_reset.as_deref()) {
        (IndexWriteFenceState::Absent, None) => true,
        (IndexWriteFenceState::Idle(expected), Some(bytes)) => bytes == expected.as_slice(),
        _ => false,
    };
    if !reset_live {
        resume_capability_reset(store, generation, 0)?;
        return Err(IndexError::ResetInProgress);
    }
    let revision_bytes = fence.revision.unwrap_or(0).to_le_bytes();
    let expected_revision: Option<&[u8]> = fence.revision.map(|_| revision_bytes.as_slice());
    if current_revision.as_deref() == expected_revision {
        return Ok(());
    }
    Err(IndexError::StaleIndexState)
}

/// Publishes or adopts a reset claim. Same-mask adoption writes nothing; mask
/// growth changes only byte zero of the exact observed claim.
fn acquire_capability_reset<S: KvStore>(
    store: &S,
    requested_mask: u8,
    generation: u64,
) -> Result<Option<ResetWork>, IndexError> {
    loop {
        let snapshot = store.snapshot()?;
        let observed = snapshot.get(ColumnFamily::UtxoMeta, RESET_CAPABILITIES_KEY)?;
        let observed_revision =
            snapshot.get(ColumnFamily::UtxoMeta, ORDINARY_STATE_REVISION_KEY)?;
        drop(snapshot);

        let revision = match observed_revision
            .as_deref()
            .map(decode_state_revision)
            .transpose()
        {
            Ok(revision) => revision,
            Err(error) => {
                ensure_raw_reset_live(store, generation, observed.as_deref())?;
                return Err(error);
            }
        };
        let revision_bytes = revision.unwrap_or(0).to_le_bytes();

        let (current_mask, base_version, observed_claim) = match observed.as_deref() {
            Some(bytes) => match parse_reset_state(bytes) {
                Ok(ResetState::Idle { .. }) if requested_mask == 0 => return Ok(None),
                Ok(ResetState::Idle { version }) => (0, version, None),
                Ok(ResetState::Claim {
                    mask, base_version, ..
                }) => (
                    mask,
                    base_version,
                    Some(ExactResetClaim::from_observed(bytes)),
                ),
                Err(error) => {
                    ensure_raw_reset_live(store, generation, Some(bytes))?;
                    return Err(error);
                }
            },
            None if requested_mask == 0 => return Ok(None),
            None => (0, 0, None),
        };
        let mask = current_mask | requested_mask;
        if !valid_reset_mask(mask) {
            return Err(IndexError::InvalidResetMarker);
        }

        if let Some(claim) = observed_claim {
            if mask == current_mask {
                return prepare_reset_work(mask, claim, base_version, revision).map(Some);
            }
        }

        let claim = match observed_claim {
            Some(claim) => claim.with_mask(mask),
            None => ExactResetClaim::full(encode_claim(mask, generation, base_version)),
        };
        let work = prepare_reset_work(mask, claim, base_version, revision)?;
        let observed_reset_condition = match observed.as_deref() {
            Some(expected) => WriteCondition::Equals {
                cf: ColumnFamily::UtxoMeta,
                key: RESET_CAPABILITIES_KEY,
                expected,
            },
            None => WriteCondition::Absent {
                cf: ColumnFamily::UtxoMeta,
                key: RESET_CAPABILITIES_KEY,
            },
        };
        let conditions = [
            observed_reset_condition,
            revision_condition(revision, &revision_bytes),
        ];
        let mut batch = store.new_batch();
        batch.put(
            ColumnFamily::UtxoMeta,
            RESET_CAPABILITIES_KEY,
            work.claim.as_slice(),
        );
        batch.put(
            ColumnFamily::UtxoMeta,
            FORMAT_VERSION_KEY,
            &FORMAT_VERSION_VALUE,
        );
        let capabilities = IndexCapabilities::from_mask(mask)?;
        if capabilities.tx_lookup {
            batch.delete(ColumnFamily::UtxoMeta, TX_LOOKUP_WATERMARK_KEY);
        }
        if capabilities.script_history {
            batch.delete(ColumnFamily::UtxoMeta, SCRIPT_HISTORY_WATERMARK_KEY);
            // Same durable batch as FORMAT_VERSION_VALUE so a format-3
            // upgrade cannot publish version 4 while leaving the row-value
            // marker at 1.
            batch.put(
                ColumnFamily::UtxoMeta,
                INDEX_FORMAT_VERSION_KEY,
                &INDEX_FORMAT_VERSION.to_le_bytes(),
            );
        }
        batch.delete(ColumnFamily::UtxoMeta, CONSUMER_CURSOR_KEY);
        if store.write_durable_if(&conditions, batch)? {
            return Ok(Some(work));
        }
    }
}

/// Drives an exact reset claim to completion in bounded, revision-fenced
/// batches, or cooperatively adopts any pending claim when the request is empty.
fn resume_capability_reset<S: KvStore>(
    store: &S,
    generation: u64,
    requested_mask: u8,
) -> Result<(), IndexError> {
    let mut requested_mask = requested_mask;
    loop {
        let Some(work) = acquire_capability_reset(store, requested_mask, generation)? else {
            return Ok(());
        };
        requested_mask = 0;

        let capabilities = IndexCapabilities::from_mask(work.mask)?;
        let mut column_families = Vec::with_capacity(4);
        if capabilities.tx_lookup {
            column_families.push(ColumnFamily::TxConfirmed);
        }
        if capabilities.script_history {
            column_families.push(ColumnFamily::Funding);
            column_families.push(ColumnFamily::Spending);
        }
        let unselected_cursor_remains = (!capabilities.tx_lookup
            && store
                .get(ColumnFamily::UtxoMeta, TX_LOOKUP_WATERMARK_KEY)?
                .is_some())
            || (!capabilities.script_history
                && store
                    .get(ColumnFamily::UtxoMeta, SCRIPT_HISTORY_WATERMARK_KEY)?
                    .is_some());
        if !unselected_cursor_remains {
            column_families.push(ColumnFamily::BlockHeaders);
        }

        let revision_bytes = work.revision.unwrap_or(0).to_le_bytes();
        let conditions = [
            work.claim.condition(),
            revision_condition(work.revision, &revision_bytes),
        ];
        let mut claim_changed = false;
        'families: for cf in column_families {
            loop {
                let scan = store.scan_prefix_bounded(cf, &[], RESET_SCAN_LIMIT)?;
                if scan.rows.is_empty() {
                    if scan.complete {
                        break;
                    }
                    return Err(IndexError::ResetScanIncomplete);
                }
                let mut batch = store.new_batch();
                for (key, _) in scan.rows {
                    batch.delete(cf, &key);
                }
                if !store.write_durable_if(&conditions, batch)? {
                    claim_changed = true;
                    break 'families;
                }
                if scan.complete {
                    break;
                }
            }
        }
        if claim_changed {
            continue;
        }

        let mut completion = store.new_batch();
        completion.put(
            ColumnFamily::UtxoMeta,
            RESET_CAPABILITIES_KEY,
            &work.next_reset,
        );
        completion.put(
            ColumnFamily::UtxoMeta,
            ORDINARY_STATE_REVISION_KEY,
            &work.next_revision,
        );
        if capabilities.script_history {
            // Resume of a claim that predates the acquire-batch marker
            // still publishes the current row-value format.
            completion.put(
                ColumnFamily::UtxoMeta,
                INDEX_FORMAT_VERSION_KEY,
                &INDEX_FORMAT_VERSION.to_le_bytes(),
            );
        }
        if store.write_durable_if(&conditions, completion)? {
            return Ok(());
        }
    }
}

const fn watermark_key(capability: IndexCapability) -> &'static [u8] {
    match capability {
        IndexCapability::TxLookup => TX_LOOKUP_WATERMARK_KEY,
        IndexCapability::ScriptHistory => SCRIPT_HISTORY_WATERMARK_KEY,
    }
}

/// Exact durable point represented by all committed `TxIndex` rows.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct IndexWatermark {
    /// Indexed active-chain height.
    pub height: u32,
    /// Full block identity at `height`.
    pub hash: [u8; 32],
}

/// One confirmed transaction discovered by the generic script-history resolver.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ScriptHistoryEntry {
    /// Transaction identifier.
    pub txid: Txid,
    /// Confirming block height.
    pub height: u32,
}

impl ScriptHistoryEntry {
    /// Creates a confirmed script-history entry.
    pub const fn confirmed(txid: Txid, height: u32) -> Self {
        Self { txid, height }
    }
}

/// One independently tracked family of derived index rows.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum IndexCapability {
    /// Core-compatible transaction lookup rows.
    TxLookup,
    /// `ScriptIndex` scripthash funding and spending rows.
    ScriptHistory,
}

/// Capabilities included in one prepared index transition.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct IndexCapabilities {
    /// Build transaction lookup rows.
    pub tx_lookup: bool,
    /// Build `ScriptIndex` funding and spending rows.
    pub script_history: bool,
}

impl IndexCapabilities {
    /// No derived rows.
    pub const NONE: Self = Self {
        tx_lookup: false,
        script_history: false,
    };
    /// Transaction lookup only.
    pub const TX_LOOKUP: Self = Self {
        tx_lookup: true,
        script_history: false,
    };
    /// `ScriptIndex` history only.
    pub const SCRIPT_HISTORY: Self = Self {
        tx_lookup: false,
        script_history: true,
    };
    /// Both capabilities.
    pub const ALL: Self = Self {
        tx_lookup: true,
        script_history: true,
    };

    /// Returns whether `capability` is selected.
    pub const fn contains(self, capability: IndexCapability) -> bool {
        match capability {
            IndexCapability::TxLookup => self.tx_lookup,
            IndexCapability::ScriptHistory => self.script_history,
        }
    }

    /// Returns whether no capability is selected.
    pub const fn is_empty(self) -> bool {
        !self.tx_lookup && !self.script_history
    }

    fn to_mask(self) -> u8 {
        u8::from(self.tx_lookup) | (u8::from(self.script_history) << 1)
    }

    fn from_mask(mask: u8) -> Result<Self, IndexError> {
        if mask == 0 || mask & !0b11 != 0 {
            return Err(IndexError::InvalidResetMarker);
        }
        Ok(Self {
            tx_lookup: mask & 0b01 != 0,
            script_history: mask & 0b10 != 0,
        })
    }
}

/// Durable cursors for the independently ready index capabilities.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct IndexWatermarks {
    /// Transaction lookup cursor.
    pub tx_lookup: Option<IndexWatermark>,
    /// `ScriptIndex` history cursor.
    pub script_history: Option<IndexWatermark>,
}

impl IndexWatermarks {
    /// Returns one capability's durable cursor.
    pub const fn get(self, capability: IndexCapability) -> Option<IndexWatermark> {
        match capability {
            IndexCapability::TxLookup => self.tx_lookup,
            IndexCapability::ScriptHistory => self.script_history,
        }
    }
}

impl IndexWatermark {
    /// Encodes the durable representation as `height (4 LE) || hash (32)`.
    pub fn to_bytes(&self) -> [u8; WATERMARK_LEN] {
        let mut bytes = [0_u8; WATERMARK_LEN];
        bytes[..crate::types::HEIGHT_SIZE].copy_from_slice(&self.height.to_le_bytes());
        bytes[crate::types::HEIGHT_SIZE..].copy_from_slice(&self.hash);
        bytes
    }

    /// Decodes the durable representation.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, IndexError> {
        if bytes.len() != WATERMARK_LEN {
            return Err(IndexError::InvalidWatermark);
        }
        let mut height = [0_u8; crate::types::HEIGHT_SIZE];
        height.copy_from_slice(&bytes[..crate::types::HEIGHT_SIZE]);
        let mut hash = [0_u8; 32];
        hash.copy_from_slice(&bytes[crate::types::HEIGHT_SIZE..]);
        Ok(Self {
            height: u32::from_le_bytes(height),
            hash,
        })
    }

    /// Reads the durable watermark from a snapshot without requiring a writer handle.
    pub fn read_from_snapshot(
        snapshot: &dyn KvSnapshot,
        capability: IndexCapability,
    ) -> Result<Option<Self>, IndexError> {
        let key = match capability {
            IndexCapability::TxLookup => TX_LOOKUP_WATERMARK_KEY,
            IndexCapability::ScriptHistory => SCRIPT_HISTORY_WATERMARK_KEY,
        };
        snapshot
            .get(ColumnFamily::UtxoMeta, key)?
            .as_deref()
            .map(Self::from_bytes)
            .transpose()
    }
}

/// Hard limits for one prepared forward write.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PreparedBatchLimits {
    /// Maximum retained index rows in a normal batch.
    pub max_rows: usize,
    /// Maximum encoded index key/value bytes in a normal batch.
    pub max_bytes: usize,
}

/// Compact mutations for one identity-checked serialized block.
pub struct PreparedBlock {
    /// Active-chain height represented by this block.
    pub height: u32,
    /// Full block identity at `height`.
    pub hash: [u8; 32],
    /// Full parent identity read from the exact serialized header.
    pub parent_hash: [u8; 32],
    /// Number of retained, deduplicated row mutations.
    pub row_count: usize,
    /// Actual encoded key/value bytes retained by the row mutations.
    pub encoded_bytes: usize,
    capabilities: IndexCapabilities,
    /// Row mutations retained from the serialized body.
    rows: PendingRows,
}

impl PreparedBlock {
    /// Returns the watermark this block represents.
    pub const fn watermark(&self) -> IndexWatermark {
        IndexWatermark {
            height: self.height,
            hash: self.hash,
        }
    }
}

/// Prepared blocks admitted to one bounded atomic forward write.
pub struct PreparedBatch {
    limits: PreparedBatchLimits,
    blocks: Vec<PreparedBlock>,
    row_count: usize,
    encoded_bytes: usize,
    capabilities: Option<IndexCapabilities>,
}

impl PreparedBatch {
    /// Creates an empty batch with caller-selected hard limits.
    pub const fn new(limits: PreparedBatchLimits) -> Self {
        Self {
            limits,
            blocks: Vec::new(),
            row_count: 0,
            encoded_bytes: 0,
            capabilities: None,
        }
    }

    /// Admits `block`, or returns it unchanged when a non-empty batch would exceed a limit.
    ///
    /// An oversized first block is admitted so callers always make progress.
    #[expect(
        clippy::result_large_err,
        reason = "returning the prepared block avoids a hot-path allocation"
    )]
    pub fn try_push(&mut self, block: PreparedBlock) -> Result<(), PreparedBlock> {
        let capabilities = block.capabilities;
        if self
            .capabilities
            .is_some_and(|current| current != capabilities)
        {
            return Err(block);
        }
        let new_rows = self.row_count.checked_add(block.row_count);
        let new_bytes = self.encoded_bytes.checked_add(block.encoded_bytes);
        let fits = new_rows.is_some_and(|rows| rows <= self.limits.max_rows)
            && new_bytes.is_some_and(|bytes| bytes <= self.limits.max_bytes);
        if !self.blocks.is_empty() && !fits {
            return Err(block);
        }
        self.row_count = new_rows.unwrap_or(usize::MAX);
        self.encoded_bytes = new_bytes.unwrap_or(usize::MAX);
        self.blocks.push(block);
        self.capabilities.get_or_insert(capabilities);
        Ok(())
    }

    /// Returns whether no blocks have been admitted.
    pub const fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// Number of admitted blocks.
    pub const fn len(&self) -> usize {
        self.blocks.len()
    }

    /// Number of retained row mutations.
    pub const fn row_count(&self) -> usize {
        self.row_count
    }

    /// Actual encoded key/value bytes retained by row mutations.
    pub const fn encoded_bytes(&self) -> usize {
        self.encoded_bytes
    }
    /// Returns whether either normal admission limit has been reached.
    ///
    /// An oversized first block also makes the batch full.
    pub const fn is_full(&self) -> bool {
        self.row_count >= self.limits.max_rows || self.encoded_bytes >= self.limits.max_bytes
    }

    /// Returns the endpoint represented by the last admitted block.
    pub fn watermark(&self) -> Option<IndexWatermark> {
        self.blocks.last().map(PreparedBlock::watermark)
    }

    /// Consumes the batch and returns the admitted blocks.
    pub(crate) fn into_blocks(self) -> Vec<PreparedBlock> {
        self.blocks
    }

    /// Returns the row families represented by the admitted blocks.
    pub const fn capabilities(&self) -> Option<IndexCapabilities> {
        self.capabilities
    }
}

/// Counts of rows written by a confirmed block ingest.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct IndexRowCounts {
    /// Transaction-id index rows written to [`ColumnFamily::TxConfirmed`].
    pub txids: usize,
    /// Script funding rows written to [`ColumnFamily::Funding`].
    pub funding: usize,
    /// Previous-outpoint spending rows written to [`ColumnFamily::Spending`].
    pub spending: usize,
    /// Header rows written to [`ColumnFamily::BlockHeaders`].
    pub headers: usize,
}

/// Electrs-shaped block indexer backed by a workspace [`KvStore`].
pub struct Indexer<S: KvStore> {
    store: std::sync::Arc<S>,
    last_counts: IndexRowCounts,
    pending_rows: PendingRows,
    batch_depth: u32,
    /// Reset-state observation covering every buffered row, captured before
    /// the first store read that produced them and held until they flush.
    fence: Option<IndexWriteFence>,
    /// Process generation fencing this indexer's reset adoption work.
    generation: u64,
}

impl<S: KvStore> Indexer<S> {
    /// Creates an indexer over `store`.
    pub fn new(store: std::sync::Arc<S>) -> Self {
        Self {
            store,
            last_counts: IndexRowCounts::default(),
            pending_rows: PendingRows::default(),
            batch_depth: 0,
            fence: None,
            generation: 0,
        }
    }

    /// Returns the underlying key-value store.
    pub const fn store(&self) -> &std::sync::Arc<S> {
        &self.store
    }

    /// Returns the row counts from the last successful ingest.
    pub const fn last_counts(&self) -> IndexRowCounts {
        self.last_counts
    }

    /// Loads the exact durable `TxIndex` watermark, or `None` for an empty v2 index.
    pub fn watermark(&self) -> Result<Option<IndexWatermark>, IndexError> {
        self.capability_watermark(IndexCapability::TxLookup)
    }

    /// Loads one capability's exact durable watermark.
    pub fn capability_watermark(
        &self,
        capability: IndexCapability,
    ) -> Result<Option<IndexWatermark>, IndexError> {
        let key = watermark_key(capability);
        self.store
            .get(ColumnFamily::UtxoMeta, key)?
            .as_deref()
            .map(IndexWatermark::from_bytes)
            .transpose()
    }

    /// Loads both independently durable capability watermarks.
    pub fn watermarks(&self) -> Result<IndexWatermarks, IndexError> {
        Ok(IndexWatermarks {
            tx_lookup: self.capability_watermark(IndexCapability::TxLookup)?,
            script_history: self.capability_watermark(IndexCapability::ScriptHistory)?,
        })
    }

    /// Iterates confirmed funding rows for `scripthash`.
    ///
    /// Returns every `HashPrefixRow` whose 8-byte prefix matches the scripthash's
    /// scan prefix, decoded from `ColumnFamily::Funding`. Rows are returned in
    /// the iteration order of the underlying store (lexicographic by key bytes).
    ///
    /// **Height ordering caveat:** the 4-byte height suffix is little-endian,
    /// so lexicographic byte order does **not** match numeric height order
    /// within one prefix. For example, height 256 (`00 01 00 00`) sorts before
    /// height 1 (`01 00 00 00`). Callers that need chronological order must
    /// sort the returned rows by numeric height after exact-resolving them.
    ///
    /// The 8-byte prefix is lossy: callers MUST resolve heights back to full
    /// transactions via block storage to confirm scripthash identity.
    pub fn iter_funding_rows(
        &self,
        scripthash: crate::ScriptHash,
    ) -> Result<Vec<crate::HashPrefixRow>, IndexError> {
        let prefix = ScriptHashRow::scan_prefix(scripthash);
        let iter = self.store.iter_prefix(ColumnFamily::Funding, &prefix)?;
        collect_prefix_rows(iter)
    }

    /// Resolves confirmed script-history entries for `scripthash` via `source`.
    ///
    /// Walks `iter_funding_rows(scripthash)` to get every (prefix, height) pair,
    /// fetches each block via `source.block_at_height(height)`, and yields a
    /// `ScriptHistoryEntry::confirmed` for every transaction in that block that has
    /// at least one output matching `scripthash` exactly.
    ///
    /// Entries are returned sorted by numeric height (ascending). The underlying
    /// store iterates rows in lexicographic key-byte order, and because the
    /// 4-byte height suffix is little-endian, that order does **not** match
    /// numeric height order within one prefix (height 256 sorts before height
    /// 1). This method sorts the final entry list by numeric height so callers
    /// receive chronological order regardless of the on-disk key encoding.
    /// Heights not resolvable by `source` are skipped.
    ///
    /// The lossy 8-byte prefix is exact-resolved here: only transactions whose
    /// output scripthash matches the full 32-byte `scripthash` are emitted.
    pub fn resolve_script_history<B: BlockSource>(
        &self,
        scripthash: crate::ScriptHash,
        source: &B,
    ) -> Result<Vec<crate::ScriptHistoryEntry>, IndexError> {
        let rows = self.iter_funding_rows_with_values(scripthash)?;
        let mut entries = Vec::new();
        for (row, value) in &rows {
            let height = row.height();
            match positioned_history(scripthash, height, value, source) {
                Some(found) => entries.extend(found),
                None => scan_height_history(scripthash, height, source, &mut entries),
            }
        }
        entries.sort_by_key(|entry| entry.height);
        Ok(entries)
    }

    /// Naive reference implementation of [`Self::resolve_script_history`].
    ///
    /// Loads and fully decodes the block once per funding row, then hashes every
    /// output script in it. Retained as the correctness oracle for the resolver
    /// equivalence tests, as the `before` arm of the `resolve_script_history`
    /// benchmark group, and as the live fallback for rows written before row
    /// values carried transaction positions.
    ///
    /// Like [`Self::resolve_script_history`], this sorts the final entry list by
    /// numeric height so the reference and the optimized resolver agree on order.
    pub fn resolve_script_history_scan<B: BlockSource>(
        &self,
        scripthash: crate::ScriptHash,
        source: &B,
    ) -> Result<Vec<crate::ScriptHistoryEntry>, IndexError> {
        let rows = self.iter_funding_rows(scripthash)?;
        let mut entries = Vec::new();
        let mut last_height: Option<u32> = None;
        let mut cached_block: Option<Block> = None;
        for row in &rows {
            let height = row.height();
            if last_height != Some(height) {
                cached_block = source.block_at_height(height);
                last_height = Some(height);
            }
            let Some(block) = cached_block.as_ref() else {
                continue;
            };
            for tx in &block.txs {
                let mut matched = false;
                for output in &tx.outputs {
                    if crate::ScriptHash::from_script_bytes(&output.script_pubkey) == scripthash {
                        matched = true;
                        break;
                    }
                }
                if matched {
                    entries.push(crate::ScriptHistoryEntry::confirmed(tx.txid(), height));
                }
            }
        }
        entries.sort_by_key(|entry| entry.height);
        Ok(entries)
    }

    /// Iterates confirmed funding rows for `scripthash` with their row values.
    ///
    /// The value carries the transaction byte positions that let a resolver read
    /// only the matching transactions; see [`crate::types::TxPositionValue`].
    fn iter_funding_rows_with_values(
        &self,
        scripthash: crate::ScriptHash,
    ) -> Result<Vec<(crate::HashPrefixRow, Vec<u8>)>, IndexError> {
        let prefix = ScriptHashRow::scan_prefix(scripthash);
        let iter = self.store.iter_prefix(ColumnFamily::Funding, &prefix)?;
        collect_prefix_rows_with_values(iter)
    }

    /// Iterates confirmed transaction-id rows for `txid` with their row values.
    fn iter_txid_rows_with_values(
        &self,
        txid: &Txid,
    ) -> Result<Vec<(crate::HashPrefixRow, Vec<u8>)>, IndexError> {
        let prefix = TxidRow::scan_prefix(txid);
        let iter = self.store.iter_prefix(ColumnFamily::TxConfirmed, &prefix)?;
        collect_prefix_rows_with_values(iter)
    }
    /// Resolves confirmed unspent-output candidates for `scripthash` via `source`.
    ///
    /// For every funding-row (prefix, height), fetches the block and emits a
    /// triple `(txid, vout, value_sats)` for every output whose scriptPubKey
    /// hashes to `scripthash`. Spending checks are NOT performed here — callers
    /// compose with `iter_spending_rows` to filter out spent outputs.
    ///
    /// The lossy 8-byte prefix is exact-resolved here: only outputs whose script
    /// hashes match the full 32-byte `scripthash` are emitted.
    pub fn resolve_unspent_outputs<B: BlockSource>(
        &self,
        scripthash: crate::ScriptHash,
        source: &B,
    ) -> Result<Vec<(Txid, u32, u64)>, IndexError> {
        Ok(self
            .resolve_unspent_outputs_with_height(scripthash, source)?
            .into_iter()
            .map(|(txid, vout, value, _height)| (txid, vout, value))
            .collect())
    }

    /// Naive reference implementation of [`Self::resolve_unspent_outputs`].
    ///
    /// Retained as the correctness oracle for the resolver equivalence tests and
    /// as the `before` arm of the `resolve_unspent` benchmark group. Deliberately
    /// carries no optimization: an oracle that shares an optimization with the
    /// implementation it checks cannot catch a fault in that optimization.
    ///
    /// Not a fallback path — [`Self::resolve_unspent_outputs`] is always correct
    /// and always faster. Call that one.
    pub fn resolve_unspent_outputs_scan<B: BlockSource>(
        &self,
        scripthash: crate::ScriptHash,
        source: &B,
    ) -> Result<Vec<(Txid, u32, u64)>, IndexError> {
        Ok(self
            .resolve_unspent_outputs_with_height_scan(scripthash, source)?
            .into_iter()
            .map(|(txid, vout, value, _height)| (txid, vout, value))
            .collect())
    }

    /// Same as `resolve_unspent_outputs` but each tuple carries the funding height.
    ///
    /// Returns `(txid, vout, value_sats, funding_height)` quadruples sorted by
    /// funding height (ascending). Use this when callers need the confirmation
    /// height (e.g. `ScriptIndex` `listunspent` emits the height for each
    /// unspent output). The sort mirrors [`Self::resolve_script_history`]:
    /// store iteration order is LE byte order, not numeric height order.
    pub fn resolve_unspent_outputs_with_height<B: BlockSource>(
        &self,
        scripthash: crate::ScriptHash,
        source: &B,
    ) -> Result<Vec<(Txid, u32, u64, u32)>, IndexError> {
        let rows = self.iter_funding_rows_with_values(scripthash)?;
        let mut outputs = Vec::new();
        for (row, value) in &rows {
            let height = row.height();
            match positioned_unspent_outputs(scripthash, height, value, source) {
                Some(found) => outputs.extend(found),
                None => scan_height_unspent_outputs(scripthash, height, source, &mut outputs),
            }
        }
        outputs.sort_by_key(|&(_, _, _, height)| height);
        Ok(outputs)
    }

    /// Naive reference implementation of [`Self::resolve_unspent_outputs_with_height`].
    ///
    /// Computes every transaction's txid before testing any output script, which
    /// is the shape this resolver had before the lazy-txid change. Retained as
    /// the correctness oracle for the resolver equivalence tests and as the
    /// `before` arm of the `resolve_unspent` benchmark group.
    ///
    /// Not a fallback path — [`Self::resolve_unspent_outputs_with_height`] is
    /// always correct and always faster. Call that one. Like the fast path,
    /// this sorts by funding height so the reference and the optimized resolver
    /// agree on order.
    pub fn resolve_unspent_outputs_with_height_scan<B: BlockSource>(
        &self,
        scripthash: crate::ScriptHash,
        source: &B,
    ) -> Result<Vec<(Txid, u32, u64, u32)>, IndexError> {
        let rows = self.iter_funding_rows(scripthash)?;
        let mut outputs = Vec::new();
        let mut last_height: Option<u32> = None;
        let mut cached_block: Option<Block> = None;
        for row in &rows {
            let height = row.height();
            if last_height != Some(height) {
                cached_block = source.block_at_height(height);
                last_height = Some(height);
            }
            let Some(block) = cached_block.as_ref() else {
                continue;
            };
            for tx in &block.txs {
                let txid = tx.txid();
                for (vout_idx, output) in tx.outputs.iter().enumerate() {
                    if crate::ScriptHash::from_script_bytes(&output.script_pubkey) != scripthash {
                        continue;
                    }
                    let Ok(vout) = u32::try_from(vout_idx) else {
                        continue;
                    };
                    outputs.push((txid, vout, output.value, height));
                }
            }
        }
        outputs.sort_by_key(|&(_, _, _, height)| height);
        Ok(outputs)
    }

    /// Iterates confirmed spending rows that spent `outpoint`.
    ///
    /// Returns every `HashPrefixRow` whose 8-byte prefix matches the outpoint's
    /// spending scan prefix, decoded from `ColumnFamily::Spending`. The 8-byte
    /// prefix is lossy as above.
    ///
    /// **Height ordering caveat:** same as [`Self::iter_funding_rows`]: the
    /// 4-byte height suffix is little-endian, so lexicographic byte order does
    /// **not** match numeric height order within one prefix. Callers needing
    /// chronological order must sort by numeric height after exact-resolving
    /// rows.
    pub fn iter_spending_rows(
        &self,
        outpoint: &OutPoint,
    ) -> Result<Vec<crate::HashPrefixRow>, IndexError> {
        let prefix = SpendingPrefixRow::scan_prefix(outpoint);
        let iter = self.store.iter_prefix(ColumnFamily::Spending, &prefix)?;
        collect_prefix_rows(iter)
    }

    /// Iterates confirmed transaction-id rows matching `txid`.
    ///
    /// Returns every `HashPrefixRow` whose 8-byte prefix matches the txid's scan
    /// prefix, decoded from `ColumnFamily::TxConfirmed`. The 8-byte prefix is
    /// lossy; multiple txids can share a prefix.
    ///
    /// **Height ordering caveat:** same as [`Self::iter_funding_rows`]: the
    /// 4-byte height suffix is little-endian, so lexicographic byte order does
    /// **not** match numeric height order within one prefix. Callers needing
    /// chronological order must sort by numeric height after exact-resolving
    /// rows.
    pub fn iter_txid_rows(&self, txid: &Txid) -> Result<Vec<crate::HashPrefixRow>, IndexError> {
        let prefix = TxidRow::scan_prefix(txid);
        let iter = self.store.iter_prefix(ColumnFamily::TxConfirmed, &prefix)?;
        collect_prefix_rows(iter)
    }

    /// Resolves a transaction by txid via `source`.
    ///
    /// Scans `iter_txid_rows(txid)` for candidate `(prefix, height)` entries.
    /// For each height, fetches the block and looks for the transaction whose
    /// full computed txid matches `txid` exactly. Returns the first match, or
    /// `None` if no candidates resolve to the requested txid.
    ///
    /// The 8-byte prefix is lossy; this method exact-resolves it by comparing
    /// the full 32-byte txid before returning.
    pub fn resolve_transaction<B: BlockSource + ?Sized>(
        &self,
        txid: Txid,
        source: &B,
    ) -> Result<Option<Tx>, IndexError> {
        let rows = self.iter_txid_rows_with_values(&txid)?;
        for (row, value) in &rows {
            let height = row.height();
            if let Some(positions) = crate::types::TxPositionValue::decode(value) {
                let found = positions
                    .iter()
                    .filter_map(|position| transaction_at(height, *position, source))
                    .find(|tx| tx.txid() == txid);
                if let Some(tx) = found {
                    return Ok(Some(tx));
                }
            }
            // The positions did not produce the transaction, which is either an
            // 8-byte txid-prefix collision or a stale row. Both are rare, and
            // both are answered correctly by scanning; "not found" is never
            // reported on the strength of positions alone.
            if let Some(block) = source.block_at_height(height) {
                for tx in &block.txs {
                    if tx.txid() == txid {
                        return Ok(Some(tx.clone()));
                    }
                }
            }
        }
        Ok(None)
    }

    /// Naive reference implementation of [`Self::resolve_transaction`].
    ///
    /// Loads and fully decodes the block for each candidate row, then computes
    /// every transaction's txid until one matches. Retained as the correctness
    /// oracle and the `before` arm of the `resolve_transaction` benchmark group.
    pub fn resolve_transaction_scan<B: BlockSource + ?Sized>(
        &self,
        txid: Txid,
        source: &B,
    ) -> Result<Option<Tx>, IndexError> {
        let rows = self.iter_txid_rows(&txid)?;
        let mut last_height: Option<u32> = None;
        let mut cached_block: Option<Block> = None;
        for row in &rows {
            let height = row.height();
            if last_height != Some(height) {
                cached_block = source.block_at_height(height);
                last_height = Some(height);
            }
            let Some(block) = cached_block.as_ref() else {
                continue;
            };
            for tx in &block.txs {
                if tx.txid() == txid {
                    return Ok(Some(tx.clone()));
                }
            }
        }
        Ok(None)
    }

    /// Resolves the satoshi value of the transaction output at `outpoint` via
    /// `source`. Returns `Ok(None)` when the transaction is not indexed or the
    /// `vout` is out of range.
    ///
    /// Composes `resolve_transaction(outpoint.txid, source)` and reads the
    /// `output[vout].value.to_sat()`. Building block for real fee derivation
    /// in transaction-broadcast and prevout-value lookups.
    pub fn resolve_outpoint_value<B: BlockSource + ?Sized>(
        &self,
        outpoint: OutPoint,
        source: &B,
    ) -> Result<Option<u64>, IndexError> {
        let Some(tx) = self.resolve_transaction(outpoint.txid, source)? else {
            return Ok(None);
        };
        let Ok(vout_idx) = usize::try_from(outpoint.vout) else {
            return Ok(None);
        };
        Ok(tx.outputs.get(vout_idx).map(|output| output.value))
    }

    /// Resolves a transaction by txid and returns it alongside the block
    /// height where it was confirmed.
    ///
    /// Same scanning strategy as [`resolve_transaction`]: iterates the
    /// `iter_txid_rows(txid)` prefix candidates, fetches each candidate height's
    /// block via `source`, and compares full-32-byte txid for exact match.
    /// Returns the first match.
    ///
    /// Cost: O(R + B) where R = number of prefix rows for `txid` and B = block
    /// fetch cost per candidate height.
    pub fn resolve_tx_with_height<B: BlockSource + ?Sized>(
        &self,
        txid: Txid,
        source: &B,
    ) -> Result<Option<(Tx, u32)>, IndexError> {
        let rows = self.iter_txid_rows(&txid)?;
        let mut last_height: Option<u32> = None;
        let mut cached_block: Option<Block> = None;
        for row in &rows {
            let height = row.height();
            if last_height != Some(height) {
                cached_block = source.block_at_height(height);
                last_height = Some(height);
            }
            let Some(block) = cached_block.as_ref() else {
                continue;
            };
            for tx in &block.txs {
                if tx.txid() == txid {
                    return Ok(Some((tx.clone(), height)));
                }
            }
        }
        Ok(None)
    }

    /// Reports whether this index's rows carry transaction positions, adopting
    /// the current format when the index is empty.
    ///
    /// Reading is always correct either way — a row without positions takes the
    /// scan fallback — so this exists to tell an operator which path their node
    /// is on, not to gate correctness. The difference is three orders of
    /// magnitude on history resolution, which is worth a startup line.
    ///
    /// An index with rows but no version marker predates the format and is
    /// reported as [`IndexFormat::Legacy`]. The marker is written only for an
    /// empty index, because that is the only case where every row that will ever
    /// exist is going to be written with positions. Writing it for a populated
    /// legacy index would claim positions that are not there.
    pub fn ensure_format_version(&self) -> Result<IndexFormat, IndexError> {
        match self.read_format_version()? {
            Some(FormatMarker::Version(found)) => {
                return Ok(if found == INDEX_FORMAT_VERSION {
                    IndexFormat::Current
                } else {
                    IndexFormat::Legacy { found: Some(found) }
                });
            }
            Some(FormatMarker::Unreadable { len }) => {
                return Ok(IndexFormat::UnreadableMarker { len });
            }
            None => {}
        }
        if self.has_any_header()? {
            return Ok(IndexFormat::Legacy { found: None });
        }
        let mut batch = self.store.new_batch();
        batch.put(
            ColumnFamily::UtxoMeta,
            INDEX_FORMAT_VERSION_KEY,
            &INDEX_FORMAT_VERSION.to_le_bytes(),
        );
        self.store.write(batch)?;
        Ok(IndexFormat::Current)
    }

    fn read_format_version(&self) -> Result<Option<FormatMarker>, IndexError> {
        let Some(bytes) = self
            .store
            .get(ColumnFamily::UtxoMeta, INDEX_FORMAT_VERSION_KEY)?
        else {
            return Ok(None);
        };
        let Ok(encoded) = <[u8; 4]>::try_from(bytes.as_slice()) else {
            // Reported as its own outcome rather than folded into version 0: an
            // operator told "your index is at version 0" deletes and re-syncs,
            // which is the wrong response to bytes that should be a `u32` and
            // are not.
            return Ok(Some(FormatMarker::Unreadable { len: bytes.len() }));
        };
        Ok(Some(FormatMarker::Version(u32::from_le_bytes(encoded))))
    }

    /// True when the header column family holds at least one row.
    ///
    /// Deliberately not `header_count`: a legacy index takes this branch on
    /// every single start, and counting reads every row in the column family
    /// and allocates an 80-byte array per row — roughly a million of each at
    /// mainnet height — to answer a question that is only ever yes or no.
    fn has_any_header(&self) -> Result<bool, IndexError> {
        let mut rows = self.store.iter_prefix(ColumnFamily::BlockHeaders, &[])?;
        Ok(rows.next().transpose()?.is_some())
    }

    const FLUSH_THRESHOLD_ROWS: usize = 500_000;

    /// Walks one serialized block once with `bitcoin_slices` and writes electrs-shaped rows.
    pub fn ingest_block(
        &mut self,
        block: &[u8],
        height: u32,
    ) -> Result<IndexRowCounts, IndexError> {
        let (rows, _txid_count) = pending_rows_for_block(block, height, TxidSource::Compute)?;
        self.ingest_rows(rows)
    }

    /// Walks one serialized block and reuses caller-supplied transaction IDs after validation.
    ///
    /// Falls back to hashing transactions from `block` for any missing or mismatched entry,
    /// preserving `ingest_block` semantics for mismatched input.
    pub fn ingest_block_with_txids(
        &mut self,
        block: &[u8],
        height: u32,
        txids: &[Txid],
    ) -> Result<IndexRowCounts, IndexError> {
        let (rows, txid_count) =
            pending_rows_for_block(block, height, TxidSource::Validate(txids))?;
        if txids.len() != txid_count {
            return self.ingest_block(block, height);
        }
        self.ingest_rows(rows)
    }

    /// Walks one serialized block using caller-verified transaction IDs.
    ///
    /// This preserves [`Self::ingest_block_with_txids`] for untrusted callers while allowing
    /// block-apply code to avoid hashing transactions a second time after it has already built
    /// txids from the same block.
    pub fn ingest_block_with_verified_txids(
        &mut self,
        block: &[u8],
        height: u32,
        txids: &[Txid],
    ) -> Result<IndexRowCounts, IndexError> {
        let (rows, txid_count) = pending_rows_for_block(block, height, TxidSource::Trusted(txids))?;
        if txids.len() != txid_count {
            return self.ingest_block(block, height);
        }
        self.ingest_rows(rows)
    }

    /// Walks one decoded block using caller-verified transaction IDs.
    ///
    /// The serialized block is retained only as the safe fallback path when the caller-provided
    /// transaction-id count does not match the decoded block. Normal callers must pass the
    /// consensus serialization of `block` as `serialized_block`.
    pub fn ingest_decoded_block_with_verified_txids(
        &mut self,
        block: &Block,
        serialized_block: &[u8],
        height: u32,
        txids: &[Txid],
    ) -> Result<IndexRowCounts, IndexError> {
        if txids.len() != block.txs.len() {
            return self.ingest_block_with_verified_txids(serialized_block, height, txids);
        }
        let rows = pending_rows_for_decoded_block(block, height, txids)?;
        self.ingest_rows(rows)
    }

    /// Deletes every index row that ingesting `block` at `height` would have written.
    ///
    /// Derives the same txid, funding, spending, and header row keys as
    /// [`Self::ingest_decoded_block_with_verified_txids`] by reusing the shared
    /// row-construction code, then issues all deletions in a single atomic
    /// [`KvStore::write`] batch. Either the entire block's rows are removed or
    /// the method returns `Err` having deleted nothing observable.
    ///
    /// Deleting a row that is already absent is not an error: the indexer may
    /// have been enabled after `block` was applied, so its rows may never have
    /// existed. The returned [`IndexRowCounts`] reflects the rows targeted for
    /// deletion (the same counts a matching ingest would have written), which
    /// may be zero on a repeat call or when the block was never indexed.
    ///
    /// Any buffered rows are flushed first. Deletion writes straight to the
    /// store, so unflushed rows for the block being disconnected would survive
    /// in `pending_rows` and a later [`Self::end_batch`] would resurrect the
    /// very block just rolled back. Flushing first also keeps the all-or-
    /// nothing property: a failing flush returns `Err` before anything is
    /// deleted.
    pub fn rollback_block(
        &mut self,
        block: &Block,
        height: u32,
    ) -> Result<IndexRowCounts, IndexError> {
        // Buffered rows must reach the store before the deletes, or a later
        // end_batch would write back the block being disconnected.
        self.flush()?;
        let fence = capture_write_fence(self.store.as_ref(), self.generation)?;
        let txids: Vec<Txid> = block.txs.iter().map(Tx::txid).collect();
        self.rollback_block_inner(block, height, &txids, &fence)
    }

    /// Same as [`Self::rollback_block`] but reuses caller-verified transaction
    /// IDs, avoiding a second pass of `compute_txid` when the caller has
    /// already computed them for merkle verification.
    ///
    /// Falls back to [`Self::rollback_block`] when the supplied txid count
    /// does not match the block's transaction count, preserving semantics for
    /// mismatched input.
    pub fn rollback_block_with_verified_txids(
        &mut self,
        block: &Block,
        height: u32,
        txids: &[Txid],
    ) -> Result<IndexRowCounts, IndexError> {
        self.flush()?;
        if txids.len() != block.txs.len() {
            return self.rollback_block(block, height);
        }
        let fence = capture_write_fence(self.store.as_ref(), self.generation)?;
        self.rollback_block_inner(block, height, txids, &fence)
    }

    fn rollback_block_inner(
        &self,
        block: &Block,
        height: u32,
        txids: &[Txid],
        fence: &IndexWriteFence,
    ) -> Result<IndexRowCounts, IndexError> {
        let mut rows = pending_rows_for_decoded_block(block, height, txids)?;
        rows.sort();
        let counts = rows.counts();

        // Only delete if this block's header row is still there.
        //
        // Funding, spending, and txid keys are an 8-byte prefix plus the
        // height, carrying no block identity, so a replacement block at the
        // same height that shares any data — the same output script is enough —
        // derives the same keys. Rolling this block back a second time, after
        // the replacement was indexed, would delete the replacement's rows and
        // leave ScriptIndex missing active-chain history.
        //
        // The header row is the identity: its key is the 80-byte serialized
        // header, and the block hash is the double-SHA256 of exactly those
        // bytes, so no two blocks share one. Its absence means this block is
        // already rolled back and the keys now belong to whatever replaced it.
        // Rekeying the other three families would carry block identity
        // directly, but it would break the electrs-compatible layout and force
        // a reindex, which is a far larger change than the bug warrants.
        // A read failure is propagated, not treated as absence: silently
        // reporting a clean rollback because storage was unreachable would
        // leave the caller believing the block is gone.
        let identity_present = match rows.header_rows.first() {
            Some(header) => self
                .store
                .get(ColumnFamily::BlockHeaders, header)?
                .is_some(),
            None => false,
        };
        if !identity_present {
            ensure_fence_live(self.store.as_ref(), self.generation, fence)?;
        }
        if !identity_present {
            debug!(
                height,
                "rollback skipped: block header row absent, rows belong to another block"
            );
            return Ok(counts);
        }

        let mut batch = self.store.new_batch();
        // Rollback deletes by key only. Positions live in the value, so they
        // disappear with the row and need no separate handling.
        for_each_row_group(&rows.txid_rows, |row, _positions| {
            batch.delete(ColumnFamily::TxConfirmed, row.as_bytes());
        });
        for_each_row_group(&rows.funding_rows, |row, _positions| {
            batch.delete(ColumnFamily::Funding, row.as_bytes());
        });
        for_each_row_group(&rows.spending_rows, |row, _positions| {
            batch.delete(ColumnFamily::Spending, row.as_bytes());
        });
        for row in &rows.header_rows {
            batch.delete(ColumnFamily::BlockHeaders, row);
        }
        commit_ordinary(self.store.as_ref(), self.generation, fence, batch)?;
        debug!(
            txids = counts.txids,
            funding = counts.funding,
            spending = counts.spending,
            headers = counts.headers,
            "rolled back block"
        );
        Ok(counts)
    }

    fn ingest_rows(&mut self, mut rows: PendingRows) -> Result<IndexRowCounts, IndexError> {
        // Dedup before counting: a block can generate the same funding or
        // spending row twice, and only one copy is ever written. Counting the
        // raw rows would report more rows than the store receives.
        if self.fence.is_none() {
            self.fence = Some(capture_write_fence(self.store.as_ref(), self.generation)?);
        }
        rows.sort();
        let block_counts = rows.counts();
        self.pending_rows.append(rows);
        if self.batch_depth == 0 || self.pending_rows.total() >= Self::FLUSH_THRESHOLD_ROWS {
            self.flush()?;
        }
        Ok(block_counts)
    }

    fn flush(&mut self) -> Result<IndexRowCounts, IndexError> {
        self.pending_rows.sort();
        let counts = self.pending_rows.counts();
        if counts.txids + counts.funding + counts.spending + counts.headers == 0 {
            return Ok(counts);
        }
        let fence = match self.fence.take() {
            Some(fence) => fence,
            None => capture_write_fence(self.store.as_ref(), self.generation)?,
        };
        let mut batch = self.store.new_batch();
        for_each_row_group(&self.pending_rows.txid_rows, |row, positions| {
            batch.put(
                ColumnFamily::TxConfirmed,
                row.as_bytes(),
                &crate::types::TxPositionValue::encode(positions),
            );
        });
        for_each_row_group(&self.pending_rows.funding_rows, |row, positions| {
            batch.put(
                ColumnFamily::Funding,
                row.as_bytes(),
                &crate::types::TxPositionValue::encode(positions),
            );
        });
        for_each_row_group(&self.pending_rows.spending_rows, |row, positions| {
            batch.put(
                ColumnFamily::Spending,
                row.as_bytes(),
                &crate::types::TxPositionValue::encode(positions),
            );
        });
        for row in &self.pending_rows.header_rows {
            batch.put(ColumnFamily::BlockHeaders, row, &[]);
        }
        if let Err(error) = commit_ordinary(self.store.as_ref(), self.generation, &fence, batch) {
            if matches!(
                error,
                IndexError::ResetInProgress | IndexError::StaleIndexState
            ) {
                self.pending_rows = PendingRows::default();
            }
            return Err(error);
        }
        self.last_counts = counts;
        self.pending_rows = PendingRows::default();
        debug!(
            txids = counts.txids,
            funding = counts.funding,
            spending = counts.spending,
            headers = counts.headers,
            "indexed batch"
        );
        Ok(counts)
    }

    /// Disables per-block flushing so multiple ingests can be written in one batch.
    pub fn begin_batch(&mut self) {
        self.batch_depth = self.batch_depth.saturating_add(1);
    }

    /// Re-enables per-block flushing and flushes any accumulated rows.
    pub fn end_batch(&mut self) -> Result<(), IndexError> {
        self.batch_depth = self.batch_depth.saturating_sub(1);
        if self.batch_depth == 0 {
            self.flush()?;
        }
        Ok(())
    }
}

fn pending_rows_for_block_with_header(
    block: &[u8],
    height: u32,
    txids: TxidSource<'_>,
    capabilities: IndexCapabilities,
) -> Result<
    (
        PendingRows,
        usize,
        Option<[u8; crate::types::HEADER_ROW_SIZE]>,
    ),
    IndexError,
> {
    let mut rows = PendingRows::default();
    let mut header = None;
    let txid_count = {
        let mut visitor = IndexBlockVisitor {
            rows: &mut rows,
            header: &mut header,
            height_bytes: height.to_le_bytes(),
            txids,
            txid_count: 0,
            invalid_header_len: None,
            block,
            pending_funding: Vec::new(),
            pending_spending: Vec::new(),
            capabilities,
        };
        match bsl::Block::visit(block, &mut visitor) {
            Ok(_) => visitor.txid_count,
            Err(bitcoin_slices::Error::VisitBreak) => {
                if let Some(len) = visitor.invalid_header_len {
                    return Err(IndexError::InvalidHeaderLength { len });
                }
                return Err(IndexError::BlockParse(bitcoin_slices::Error::VisitBreak));
            }
            Err(error) => return Err(IndexError::BlockParse(error)),
        }
    };
    Ok((rows, txid_count, header))
}

fn pending_rows_for_block(
    block: &[u8],
    height: u32,
    txids: TxidSource<'_>,
) -> Result<(PendingRows, usize), IndexError> {
    let (rows, txid_count, _) =
        pending_rows_for_block_with_header(block, height, txids, IndexCapabilities::ALL)?;
    Ok((rows, txid_count))
}

fn pending_rows_for_decoded_block(
    block: &Block,
    height: u32,
    txids: &[Txid],
) -> Result<PendingRows, IndexError> {
    let mut rows = PendingRows::default();
    let header_bytes = encode::consensus_bytes(&block.header);
    let Some(header) = HeaderRow::from_header_bytes(&header_bytes) else {
        return Err(IndexError::InvalidHeaderLength {
            len: header_bytes.len(),
        });
    };
    rows.header_rows.push(header.to_db_row());

    // Byte offsets are derived arithmetically rather than by re-serializing: a
    // serialized block is `header || varint(tx_count) || tx...`, so the first
    // transaction starts after the header and the count, and each subsequent one
    // starts a `total_size()` further on. `both_ingest_paths_write_identical_row_values`
    // pins this against the byte offsets the zero-copy path measures directly.
    let prologue = crate::types::HEADER_ROW_SIZE
        + varint::encode(u64::try_from(block.txs.len()).unwrap_or(u64::MAX)).len();
    let mut offset = u32::try_from(prologue).map_err(|_| IndexError::UnaddressablePosition {
        offset: u64::try_from(prologue).unwrap_or(u64::MAX),
    })?;

    for (tx, txid) in block.txs.iter().zip(txids) {
        let byte_len =
            u32::try_from(tx.total_size()).map_err(|_| IndexError::UnaddressablePosition {
                offset: u64::from(offset),
            })?;
        let position = crate::types::TxPosition::new(offset, byte_len);
        offset = offset
            .checked_add(byte_len)
            .ok_or_else(|| IndexError::UnaddressablePosition {
                offset: u64::from(offset),
            })?;

        rows.txid_rows.push(PositionedRow {
            row: TxidRow::row(txid, height),
            position,
        });
        for tx_in in &tx.inputs {
            if !is_null_outpoint(&tx_in.previous_output) {
                rows.spending_rows.push(PositionedRow {
                    row: SpendingPrefixRow::row(&tx_in.previous_output, height),
                    position,
                });
            }
        }
        for tx_out in &tx.outputs {
            if !is_op_return_script(&tx_out.script_pubkey) {
                let scripthash = ScriptHash::new(&tx_out.script_pubkey);
                rows.funding_rows.push(PositionedRow {
                    row: ScriptHashRow::row(scripthash, height),
                    position,
                });
            }
        }
    }
    Ok(rows)
}

/// One index row together with the transaction byte range that produced it.
///
/// Ordered by key first so a sorted slice groups by row.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct PositionedRow {
    row: HashPrefixRow,
    position: crate::types::TxPosition,
}

#[derive(Default)]
struct PendingRows {
    txid_rows: Vec<PositionedRow>,
    funding_rows: Vec<PositionedRow>,
    spending_rows: Vec<PositionedRow>,
    header_rows: Vec<[u8; crate::types::HEADER_ROW_SIZE]>,
}

/// Counts distinct row keys in a sorted `PositionedRow` slice.
///
/// The reported count must stay "rows the store receives", not "positions
/// collected": one key can carry several positions when a block funds the same
/// script from more than one transaction, and those collapse into one row.
fn distinct_row_count(rows: &[PositionedRow]) -> usize {
    let mut count = 0;
    let mut last: Option<HashPrefixRow> = None;
    for entry in rows {
        if last != Some(entry.row) {
            count += 1;
            last = Some(entry.row);
        }
    }
    count
}

/// Calls `emit` once per row key in a sorted slice, with that key's positions.
///
/// Two blocks at one height that share a key merge their positions into one
/// value. That is safe because the reader validates every position and falls
/// back to a full scan on the first one that does not resolve, so a merged value
/// costs at most a scan — see [`crate::types::TxPositionValue`].
fn for_each_row_group<F>(rows: &[PositionedRow], mut emit: F)
where
    F: FnMut(HashPrefixRow, &[crate::types::TxPosition]),
{
    let mut positions = Vec::new();
    let mut index = 0;
    while index < rows.len() {
        let key = rows[index].row;
        positions.clear();
        while index < rows.len() && rows[index].row == key {
            positions.push(rows[index].position);
            index += 1;
        }
        emit(key, &positions);
    }
}

impl PendingRows {
    fn sort(&mut self) {
        self.txid_rows.sort_unstable();
        self.funding_rows.sort_unstable();
        self.spending_rows.sort_unstable();
        self.header_rows.sort_unstable();
        self.txid_rows.dedup();
        self.funding_rows.dedup();
        self.spending_rows.dedup();
        self.header_rows.dedup();
    }

    fn counts(&self) -> IndexRowCounts {
        IndexRowCounts {
            txids: distinct_row_count(&self.txid_rows),
            funding: distinct_row_count(&self.funding_rows),
            spending: distinct_row_count(&self.spending_rows),
            headers: self.header_rows.len(),
        }
    }
    fn append(&mut self, other: Self) {
        self.txid_rows.extend(other.txid_rows);
        self.funding_rows.extend(other.funding_rows);
        self.spending_rows.extend(other.spending_rows);
        self.header_rows.extend(other.header_rows);
    }

    fn total(&self) -> usize {
        let counts = self.counts();
        counts.txids + counts.funding + counts.spending + counts.headers
    }

    fn is_empty(&self) -> bool {
        self.total() == 0
    }

    fn encoded_bytes(&self) -> Result<usize, IndexError> {
        let txid_positions = self.txid_rows.len();
        let funding_positions = self.funding_rows.len();
        let distinct_prefix = distinct_row_count(&self.txid_rows)
            .checked_add(distinct_row_count(&self.funding_rows))
            .and_then(|s| s.checked_add(distinct_row_count(&self.spending_rows)))
            .ok_or(IndexError::MutationSizeOverflow)?;
        let prefix_bytes = distinct_prefix
            .checked_mul(crate::types::HASH_PREFIX_ROW_SIZE)
            .ok_or(IndexError::MutationSizeOverflow)?;
        let position_count = txid_positions
            .checked_add(funding_positions)
            .and_then(|s| s.checked_add(self.spending_rows.len()))
            .ok_or(IndexError::MutationSizeOverflow)?;
        let position_bytes = position_count
            .checked_mul(crate::types::TX_POSITION_SIZE)
            .ok_or(IndexError::MutationSizeOverflow)?;
        let header_bytes = self
            .header_rows
            .len()
            .checked_mul(crate::types::HEADER_ROW_SIZE)
            .ok_or(IndexError::MutationSizeOverflow)?;
        prefix_bytes
            .checked_add(position_bytes)
            .and_then(|s| s.checked_add(header_bytes))
            .ok_or(IndexError::MutationSizeOverflow)
    }
}

fn put_rows<B: WriteBatch>(batch: &mut B, rows: &PendingRows) {
    for_each_row_group(&rows.txid_rows, |row, positions| {
        batch.put(
            ColumnFamily::TxConfirmed,
            row.as_bytes(),
            &crate::types::TxPositionValue::encode(positions),
        );
    });
    for_each_row_group(&rows.funding_rows, |row, positions| {
        batch.put(
            ColumnFamily::Funding,
            row.as_bytes(),
            &crate::types::TxPositionValue::encode(positions),
        );
    });
    for_each_row_group(&rows.spending_rows, |row, positions| {
        batch.put(
            ColumnFamily::Spending,
            row.as_bytes(),
            &crate::types::TxPositionValue::encode(positions),
        );
    });
    for row in &rows.header_rows {
        batch.put(ColumnFamily::BlockHeaders, row, &[]);
    }
}

fn put_selected_watermarks<B: WriteBatch>(
    batch: &mut B,
    capabilities: IndexCapabilities,
    watermark: Option<IndexWatermark>,
) {
    for capability in [IndexCapability::TxLookup, IndexCapability::ScriptHistory] {
        if !capabilities.contains(capability) {
            continue;
        }
        let key = watermark_key(capability);
        if let Some(watermark) = watermark {
            batch.put(ColumnFamily::UtxoMeta, key, &watermark.to_bytes());
        } else {
            batch.delete(ColumnFamily::UtxoMeta, key);
        }
    }
}

fn selected_watermark(
    watermarks: IndexWatermarks,
    capabilities: IndexCapabilities,
) -> Result<Option<IndexWatermark>, IndexError> {
    match (capabilities.tx_lookup, capabilities.script_history) {
        (true, false) => Ok(watermarks.tx_lookup),
        (false, true) => Ok(watermarks.script_history),
        (true, true) if watermarks.tx_lookup == watermarks.script_history => {
            Ok(watermarks.tx_lookup)
        }
        (true, true) => Err(IndexError::WatermarkMismatch {
            expected: watermarks.tx_lookup,
            actual: watermarks.script_history,
        }),
        (false, false) => Err(IndexError::NonContiguousPrepared { watermark: None }),
    }
}

fn delete_rows<B: WriteBatch>(batch: &mut B, rows: &PendingRows, delete_shared_identity: bool) {
    for_each_row_group(&rows.txid_rows, |row, _positions| {
        batch.delete(ColumnFamily::TxConfirmed, row.as_bytes());
    });
    for_each_row_group(&rows.funding_rows, |row, _positions| {
        batch.delete(ColumnFamily::Funding, row.as_bytes());
    });
    for_each_row_group(&rows.spending_rows, |row, _positions| {
        batch.delete(ColumnFamily::Spending, row.as_bytes());
    });
    if delete_shared_identity {
        for row in &rows.header_rows {
            batch.delete(ColumnFamily::BlockHeaders, row);
        }
    }
}

struct IndexBlockVisitor<'a> {
    rows: &'a mut PendingRows,
    header: &'a mut Option<[u8; crate::types::HEADER_ROW_SIZE]>,
    height_bytes: [u8; crate::types::HEIGHT_SIZE],
    txids: TxidSource<'a>,
    txid_count: usize,
    invalid_header_len: Option<usize>,
    /// The serialized block being visited, used as the base for byte offsets.
    block: &'a [u8],
    /// Funding and spending prefixes seen for the transaction currently being parsed.
    ///
    /// `visit_tx_in` and `visit_tx_out` fire while the transaction is still
    /// being parsed, so its byte range is not known yet — `visit_transaction`
    /// runs at the end and is the first point where the position exists. Inputs
    /// and outputs are therefore buffered here and drained once, in emission
    /// order.
    pending_funding: Vec<crate::types::HashPrefix>,
    pending_spending: Vec<HashPrefixRow>,
    capabilities: IndexCapabilities,
}

impl IndexBlockVisitor<'_> {
    /// Byte range of `tx` within the block being visited.
    ///
    /// The slice `bitcoin_slices` hands back borrows from `self.block`, so the
    /// difference of their addresses is that transaction's offset. Computed from
    /// addresses only — nothing is dereferenced.
    fn push_txid_row(&mut self, txid_bytes: &[u8], position: crate::types::TxPosition) {
        self.rows.txid_rows.push(PositionedRow {
            row: TxidRow::row_bytes(txid_bytes, self.height_bytes),
            position,
        });
    }

    fn position_of(&self, tx: &bsl::Transaction<'_>) -> Option<crate::types::TxPosition> {
        let bytes: &[u8] = tx.as_ref();
        let offset = bytes
            .as_ptr()
            .addr()
            .checked_sub(self.block.as_ptr().addr())?;
        Some(crate::types::TxPosition::new(
            u32::try_from(offset).ok()?,
            u32::try_from(bytes.len()).ok()?,
        ))
    }
}

impl Visitor for IndexBlockVisitor<'_> {
    fn visit_block_header(&mut self, header: &bsl::BlockHeader<'_>) -> ControlFlow<()> {
        let Some(row) = HeaderRow::from_header_bytes(header.as_ref()) else {
            self.invalid_header_len = Some(header.as_ref().len());
            return ControlFlow::Break(());
        };
        *self.header = Some(row.to_db_row());
        self.rows.header_rows.push(row.to_db_row());
        ControlFlow::Continue(())
    }

    fn visit_transaction(&mut self, tx: &bsl::Transaction<'_>) -> ControlFlow<()> {
        let Some(position) = self.position_of(tx) else {
            // A transaction that does not lie inside the block slice, or whose
            // offset does not fit `u32`, cannot be addressed by a position.
            // Refuse the block rather than write a row that points nowhere.
            return ControlFlow::Break(());
        };
        for prefix in self.pending_funding.drain(..) {
            self.rows.funding_rows.push(PositionedRow {
                row: HashPrefixRow {
                    prefix,
                    height: self.height_bytes,
                },
                position,
            });
        }
        for row in self.pending_spending.drain(..) {
            self.rows
                .spending_rows
                .push(PositionedRow { row, position });
        }
        if !self.capabilities.tx_lookup {
            self.txid_count += 1;
            return ControlFlow::Continue(());
        }
        match self.txids {
            TxidSource::Compute => {
                let txid = tx.txid_sha2();
                self.push_txid_row(txid.as_slice(), position);
            }
            TxidSource::Validate(txids) => {
                if let Some(txid) = txids.get(self.txid_count) {
                    let computed = tx.txid_sha2();
                    let txid_bytes: &[u8] = txid.as_bytes();
                    if txid_bytes == computed.as_slice() {
                        self.push_txid_row(txid_bytes, position);
                    } else {
                        self.push_txid_row(computed.as_slice(), position);
                    }
                } else {
                    let txid = tx.txid_sha2();
                    self.push_txid_row(txid.as_slice(), position);
                }
            }
            TxidSource::Trusted(txids) => {
                if let Some(txid) = txids.get(self.txid_count) {
                    let txid_bytes: &[u8] = txid.as_bytes();
                    self.push_txid_row(txid_bytes, position);
                } else {
                    let txid = tx.txid_sha2();
                    self.push_txid_row(txid.as_slice(), position);
                }
            }
        }
        self.txid_count += 1;
        ControlFlow::Continue(())
    }

    fn visit_tx_in(&mut self, _vin: usize, tx_in: &bsl::TxIn<'_>) -> ControlFlow<()> {
        if !self.capabilities.script_history {
            return ControlFlow::Continue(());
        }
        let prevout = tx_in.prevout();
        if !is_null_prevout(prevout) {
            self.pending_spending.push(SpendingPrefixRow::row_parts(
                prevout.txid(),
                prevout.vout(),
                self.height_bytes,
            ));
        }
        ControlFlow::Continue(())
    }

    fn visit_tx_out(&mut self, _vout: usize, tx_out: &bsl::TxOut<'_>) -> ControlFlow<()> {
        if !self.capabilities.script_history {
            return ControlFlow::Continue(());
        }
        let script = tx_out.script_pubkey();
        if !is_op_return_script(script) {
            self.pending_funding
                .push(ScriptHash::from_script_bytes(script).prefix());
        }
        ControlFlow::Continue(())
    }
}

fn is_null_prevout(prevout: &bsl::OutPoint<'_>) -> bool {
    prevout.vout() == u32::MAX && prevout.txid().iter().all(|byte| *byte == 0)
}

fn is_null_outpoint(outpoint: &OutPoint) -> bool {
    outpoint.vout == u32::MAX && outpoint.txid.as_bytes().iter().all(|&byte| byte == 0)
}

#[inline]
fn is_op_return_script(script: &[u8]) -> bool {
    matches!(script.first(), Some(0x6a))
}

#[derive(Clone, Copy)]
enum TxidSource<'a> {
    Compute,
    Validate(&'a [Txid]),
    Trusted(&'a [Txid]),
}

/// Reads and decodes the single transaction a position names.
///
/// Returns `None` when the source cannot serve the range, when the range is out
/// of bounds, or when the bytes are not exactly one transaction. `deserialize`
/// rejects trailing bytes, so a range covering more than one transaction fails
/// here rather than silently decoding the first.
fn transaction_at<B: BlockSource + ?Sized>(
    height: u32,
    position: crate::types::TxPosition,
    source: &B,
) -> Option<Tx> {
    let bytes = source.block_bytes_at_height(height, position.offset(), position.byte_len())?;
    Tx::consensus_decode(&bytes).ok()
}

/// Resolves one funding row's history entries from its positions.
///
/// Returns `None` — meaning "scan this height instead" — if **any** position
/// fails to resolve to a transaction funding `scripthash`. Skipping a failed
/// position and keeping the rest is what would turn a partial result into a
/// silently complete-looking one; see [`crate::types::TxPositionValue`].
fn positioned_history<B: BlockSource + ?Sized>(
    scripthash: crate::ScriptHash,
    height: u32,
    value: &[u8],
    source: &B,
) -> Option<Vec<crate::ScriptHistoryEntry>> {
    let positions = crate::types::TxPositionValue::decode(value)?;
    let mut entries = Vec::with_capacity(positions.len());
    for position in positions {
        let tx = transaction_at(height, *position, source)?;
        if !funds_scripthash(&tx, scripthash) {
            return None;
        }
        entries.push(crate::ScriptHistoryEntry::confirmed(tx.txid(), height));
    }
    Some(entries)
}

/// Appends the history entries a full scan of `height` produces.
fn scan_height_history<B: BlockSource + ?Sized>(
    scripthash: crate::ScriptHash,
    height: u32,
    source: &B,
    entries: &mut Vec<crate::ScriptHistoryEntry>,
) {
    let Some(block) = source.block_at_height(height) else {
        return;
    };
    for tx in &block.txs {
        if funds_scripthash(tx, scripthash) {
            entries.push(crate::ScriptHistoryEntry::confirmed(tx.txid(), height));
        }
    }
}

/// Resolves one funding row's unspent-output candidates from its positions.
///
/// Same all-or-scan rule as [`positioned_history`].
fn positioned_unspent_outputs<B: BlockSource + ?Sized>(
    scripthash: crate::ScriptHash,
    height: u32,
    value: &[u8],
    source: &B,
) -> Option<Vec<(Txid, u32, u64, u32)>> {
    let positions = crate::types::TxPositionValue::decode(value)?;
    let mut outputs = Vec::new();
    for position in positions {
        let tx = transaction_at(height, *position, source)?;
        let before = outputs.len();
        append_matching_outputs(&tx, scripthash, height, &mut outputs);
        if outputs.len() == before {
            return None;
        }
    }
    Some(outputs)
}

/// Appends the unspent-output candidates a full scan of `height` produces.
fn scan_height_unspent_outputs<B: BlockSource + ?Sized>(
    scripthash: crate::ScriptHash,
    height: u32,
    source: &B,
    outputs: &mut Vec<(Txid, u32, u64, u32)>,
) {
    let Some(block) = source.block_at_height(height) else {
        return;
    };
    for tx in &block.txs {
        append_matching_outputs(tx, scripthash, height, outputs);
    }
}

/// Appends `(txid, vout, value, height)` for every output of `tx` matching
/// `scripthash`, computing the txid only once a match is found.
fn append_matching_outputs(
    tx: &Tx,
    scripthash: crate::ScriptHash,
    height: u32,
    outputs: &mut Vec<(Txid, u32, u64, u32)>,
) {
    let mut computed_txid: Option<Txid> = None;
    for (vout_idx, output) in tx.outputs.iter().enumerate() {
        if crate::ScriptHash::from_script_bytes(&output.script_pubkey) != scripthash {
            continue;
        }
        let Ok(vout) = u32::try_from(vout_idx) else {
            continue;
        };
        let txid = *computed_txid.get_or_insert_with(|| tx.txid());
        outputs.push((txid, vout, output.value, height));
    }
}

fn funds_scripthash(tx: &Tx, scripthash: crate::ScriptHash) -> bool {
    tx.outputs
        .iter()
        .any(|output| crate::ScriptHash::from_script_bytes(&output.script_pubkey) == scripthash)
}

fn collect_prefix_rows_with_values(
    iter: bitcoin_rs_storage::KvIter<'_>,
) -> Result<Vec<(crate::HashPrefixRow, Vec<u8>)>, IndexError> {
    let mut rows = Vec::new();
    for entry in iter {
        let (key, value) = entry?;
        if key.len() == crate::HASH_PREFIX_ROW_SIZE {
            rows.push((
                zerocopy::FromBytes::read_from_bytes(&key[..])
                    .map_err(|_| IndexError::InvalidHeaderLength { len: key.len() })?,
                value,
            ));
        }
    }
    Ok(rows)
}

fn collect_prefix_rows(
    iter: bitcoin_rs_storage::KvIter<'_>,
) -> Result<Vec<crate::HashPrefixRow>, IndexError> {
    let mut rows = Vec::new();
    for entry in iter {
        let (key, _value) = entry?;
        if key.len() == crate::HASH_PREFIX_ROW_SIZE {
            rows.push(
                zerocopy::FromBytes::read_from_bytes(&key[..])
                    .map_err(|_| IndexError::InvalidHeaderLength { len: key.len() })?,
            );
        }
    }
    Ok(rows)
}

/// One typed row from a `TxIndex` prefix scan, including its raw value.
#[derive(Debug)]
pub struct TxIndexScanRow {
    /// Parsed fixed-width prefix row.
    pub row: HashPrefixRow,
    /// Raw storage value associated with the row.
    pub value: Vec<u8>,
}

/// Result of one bounded typed `TxIndex` prefix scan.
#[derive(Debug)]
pub struct TxIndexScan {
    /// Parsed fixed-width prefix rows.
    pub rows: Vec<TxIndexScanRow>,
    /// Encoded key and value bytes returned by storage.
    pub encoded_bytes: usize,
    /// Whether storage returned the complete matching prefix.
    pub complete: bool,
}

/// Point-in-time, typed view of durable `TxIndex` rows.
pub trait TxIndexSnapshot: Send + Sync {
    /// Loads the transaction lookup watermark from this snapshot.
    fn watermark(&self) -> Result<Option<IndexWatermark>, IndexError>;
    /// Loads one capability's exact durable watermark from this snapshot.
    fn capability_watermark(
        &self,
        capability: IndexCapability,
    ) -> Result<Option<IndexWatermark>, IndexError> {
        let _ = capability;
        self.watermark()
    }
    /// Scans confirmed-transaction rows for `txid`.
    fn transaction_rows(
        &self,
        txid: &Txid,
        limit: PrefixScanLimit,
    ) -> Result<TxIndexScan, IndexError>;
    /// Scans funding rows for `scripthash`.
    fn funding_rows(
        &self,
        scripthash: ScriptHash,
        limit: PrefixScanLimit,
    ) -> Result<TxIndexScan, IndexError>;
    /// Scans spending rows for `outpoint`.
    fn spending_rows(
        &self,
        outpoint: &OutPoint,
        limit: PrefixScanLimit,
    ) -> Result<TxIndexScan, IndexError>;
}

struct StoreTxIndexSnapshot<'a> {
    snapshot: Box<dyn KvSnapshot + 'a>,
}

impl StoreTxIndexSnapshot<'_> {
    fn scan(
        &self,
        cf: ColumnFamily,
        prefix: &[u8],
        limit: PrefixScanLimit,
    ) -> Result<TxIndexScan, IndexError> {
        let scan = self.snapshot.scan_prefix_bounded(cf, prefix, limit)?;
        let encoded_bytes = scan.rows.iter().fold(0_usize, |total, (key, value)| {
            total.saturating_add(key.len()).saturating_add(value.len())
        });
        let mut rows = Vec::with_capacity(scan.rows.len());
        for (key, value) in scan.rows {
            if key.len() != crate::HASH_PREFIX_ROW_SIZE {
                return Err(IndexError::InvalidPrefixRowLength { len: key.len() });
            }
            let row = zerocopy::FromBytes::read_from_bytes(&key)
                .map_err(|_| IndexError::InvalidPrefixRowLength { len: key.len() })?;
            rows.push(TxIndexScanRow { row, value });
        }
        Ok(TxIndexScan {
            rows,
            encoded_bytes,
            complete: scan.complete,
        })
    }
}

impl TxIndexSnapshot for StoreTxIndexSnapshot<'_> {
    fn watermark(&self) -> Result<Option<IndexWatermark>, IndexError> {
        self.capability_watermark(IndexCapability::TxLookup)
    }

    fn capability_watermark(
        &self,
        capability: IndexCapability,
    ) -> Result<Option<IndexWatermark>, IndexError> {
        IndexWatermark::read_from_snapshot(self.snapshot.as_ref(), capability)
    }

    fn transaction_rows(
        &self,
        txid: &Txid,
        limit: PrefixScanLimit,
    ) -> Result<TxIndexScan, IndexError> {
        self.scan(
            ColumnFamily::TxConfirmed,
            &TxidRow::scan_prefix(txid),
            limit,
        )
    }

    fn funding_rows(
        &self,
        scripthash: ScriptHash,
        limit: PrefixScanLimit,
    ) -> Result<TxIndexScan, IndexError> {
        self.scan(
            ColumnFamily::Funding,
            &ScriptHashRow::scan_prefix(scripthash),
            limit,
        )
    }

    fn spending_rows(
        &self,
        outpoint: &OutPoint,
        limit: PrefixScanLimit,
    ) -> Result<TxIndexScan, IndexError> {
        self.scan(
            ColumnFamily::Spending,
            &SpendingPrefixRow::scan_prefix(outpoint),
            limit,
        )
    }
}

/// Read-only `TxIndex` interface.
pub trait IndexReader: Send + Sync {
    /// Captures a point-in-time typed `TxIndex` snapshot.
    fn snapshot(&self) -> Result<Box<dyn TxIndexSnapshot + '_>, IndexError>;
}

impl<S: KvStore> IndexReader for Indexer<S> {
    fn snapshot(&self) -> Result<Box<dyn TxIndexSnapshot + '_>, IndexError> {
        Ok(Box::new(StoreTxIndexSnapshot {
            snapshot: self.store.snapshot()?,
        }))
    }
}

/// Mutation-only handle for durable prepared `TxIndex` writes.
pub struct IndexWriter<S: KvStore> {
    indexer: Indexer<S>,
    /// Durable process epoch fencing this writer's reset work. Adoption of
    /// an interrupted reset re-fences the marker to this generation before
    /// any row deletion, and only this generation may clear the marker.
    generation: u64,
}

impl<S: KvStore> IndexWriter<S> {
    /// Opens a writer over `store`, rejecting unversioned index tables.
    ///
    /// Format 3 (Spending keys without positions) is upgraded in place by
    /// resetting `ScriptHistory` only. Any other version mismatch is
    /// [`IndexError::UnsupportedTxIndexFormatVersion`].
    pub fn open(store: std::sync::Arc<S>, generation: u64) -> Result<Self, IndexError> {
        let indexer = Indexer::new(store);
        match indexer
            .store
            .get(ColumnFamily::UtxoMeta, FORMAT_VERSION_KEY)?
        {
            Some(value) if value.as_slice() == FORMAT_VERSION_VALUE => {}
            Some(value) if value.as_slice() == FORMAT_VERSION_V3 => {
                // Only Spending's representation changed. Reset ScriptHistory
                // so new spending rows carry positions, and leave TxLookup
                // serving (`IDX-04`). Foreign versions still refuse start.
                resume_capability_reset(
                    indexer.store.as_ref(),
                    generation,
                    IndexCapabilities::SCRIPT_HISTORY.to_mask(),
                )?;
            }
            Some(value) => {
                let version = value
                    .get(..4)
                    .and_then(|bytes| <[u8; 4]>::try_from(bytes).ok())
                    .map_or(0, u32::from_le_bytes);
                return Err(IndexError::UnsupportedTxIndexFormatVersion { version });
            }
            None => {
                if has_any_index_row(&*indexer.store)? {
                    return Err(IndexError::LegacyCursorlessIndex);
                }
            }
        }
        // A plain open adopts any outstanding obligation (requested mask 0)
        // without publishing a claim of its own.
        resume_capability_reset(indexer.store.as_ref(), generation, 0)?;
        Ok(Self {
            indexer,
            generation,
        })
    }

    /// Loads the exact durable watermark.
    pub fn watermark(&self) -> Result<Option<IndexWatermark>, IndexError> {
        self.indexer.watermark()
    }

    /// Loads both independently durable capability watermarks.
    pub fn watermarks(&self) -> Result<IndexWatermarks, IndexError> {
        self.indexer.watermarks()
    }

    /// Captures one coherent fence with the exact reset state, ordinary revision,
    /// and both capability watermarks from a single snapshot. It returns the
    /// fence with the watermarks it carries. A reset that
    /// begins or completes in the read window therefore returns
    /// [`IndexError::ResetInProgress`]; callers must discard derived
    /// state and re-capture.
    pub fn fenced_watermarks(&mut self) -> Result<(IndexWriteFence, IndexWatermarks), IndexError> {
        let fence = capture_write_fence(self.indexer.store.as_ref(), self.generation)?;
        Ok((fence, fence.watermarks))
    }

    /// Resets every derived capability through the durable exact-claim fence.
    ///
    /// A pre-existing selective reset is merged into the all-capability
    /// obligation before any row is deleted.
    pub fn reset_index(store: &S, generation: u64) -> Result<(), IndexError> {
        resume_capability_reset(store, generation, IndexCapabilities::ALL.to_mask())
    }

    /// Marks selected derived rows unavailable, deletes them in bounded
    /// batches, and leaves their durable cursors empty so the worker can
    /// rebuild from genesis.
    ///
    /// The claim and cursor deletion land atomically before row deletion, and
    /// completion CASes the exact claim to the next idle version.
    /// `open` resumes an interrupted reset before exposing the writer again.
    pub fn reset_capabilities(&self, capabilities: IndexCapabilities) -> Result<(), IndexError> {
        self.ensure_prepared_ready()?;
        if capabilities.is_empty() {
            return Err(IndexError::InvalidResetMarker);
        }
        resume_capability_reset(
            self.indexer.store.as_ref(),
            self.generation,
            capabilities.to_mask(),
        )
    }

    /// Derives a `PreparedBlock` from a serialized body without allocating a decoded block.
    pub fn prepare_block(
        &self,
        height: u32,
        hash: [u8; 32],
        body: &[u8],
    ) -> Result<PreparedBlock, IndexError> {
        self.prepare_block_for(IndexCapabilities::ALL, height, hash, body)
    }

    /// Derives capability-selected row mutations from one serialized block scan.
    pub fn prepare_block_for(
        &self,
        capabilities: IndexCapabilities,
        height: u32,
        hash: [u8; 32],
        body: &[u8],
    ) -> Result<PreparedBlock, IndexError> {
        if capabilities.is_empty() {
            return Err(IndexError::NonContiguousPrepared {
                watermark: self.watermark()?,
            });
        }
        let (mut rows, _txid_count, header) =
            pending_rows_for_block_with_header(body, height, TxidSource::Compute, capabilities)?;
        let header = header.ok_or(IndexError::InvalidHeaderLength { len: 0 })?;
        let actual_hash = encode::double_sha256(header.as_slice()).to_le_bytes();
        if actual_hash != hash {
            return Err(IndexError::BlockIdentityMismatch {
                height,
                expected: hash,
                actual: actual_hash,
            });
        }
        let mut parent_hash = [0_u8; 32];
        parent_hash.copy_from_slice(&header[4..36]);
        rows.sort();
        let row_count = rows.total();
        let encoded_bytes = rows.encoded_bytes()?;
        Ok(PreparedBlock {
            height,
            hash,
            parent_hash,
            row_count,
            encoded_bytes,
            capabilities,
            rows,
        })
    }

    /// Atomically connects a bounded batch and advances the durable watermark.
    ///
    /// Captures its own fence before any store-dependent derivation and keeps
    /// the consumer cursor untouched.
    pub fn commit_forward(&mut self, batch: PreparedBatch) -> Result<IndexWatermark, IndexError> {
        let (fence, _) = self.fenced_watermarks()?;
        self.commit_forward_with_cursor(fence, batch, ConsumerCursorUpdate::Keep)
    }

    /// Atomically connects a bounded batch and applies one explicit consumer
    /// cursor disposition guarded by the captured reset-state fence.
    pub fn commit_forward_with_cursor(
        &mut self,
        fence: IndexWriteFence,
        batch: PreparedBatch,
        cursor: ConsumerCursorUpdate<'_>,
    ) -> Result<IndexWatermark, IndexError> {
        self.ensure_prepared_ready()?;
        if batch.is_empty() {
            return Err(IndexError::NonContiguousPrepared {
                watermark: fence.watermarks.tx_lookup,
            });
        }
        let capabilities = batch
            .capabilities()
            .ok_or(IndexError::NonContiguousPrepared {
                watermark: fence.watermarks.tx_lookup,
            })?;
        let current = selected_watermark(fence.watermarks, capabilities)?;
        let mut expected_height = match current {
            None => 0,
            Some(w) => w
                .height
                .checked_add(1)
                .ok_or(IndexError::NonContiguousPrepared { watermark: current })?,
        };
        let mut expected_parent = current.map(|w| w.hash);
        let mut merged = PendingRows::default();
        let mut last = None;
        let block_count = batch.len();
        for (block_index, block) in batch.into_blocks().into_iter().enumerate() {
            if block.height != expected_height {
                return Err(IndexError::NonContiguousPrepared { watermark: current });
            }
            if let Some(parent) = expected_parent {
                if block.parent_hash != parent {
                    return Err(IndexError::NonContiguousPrepared { watermark: current });
                }
            }
            merged.append(block.rows);
            if block_index + 1 < block_count {
                expected_height = expected_height
                    .checked_add(1)
                    .ok_or(IndexError::NonContiguousPrepared { watermark: current })?;
            }
            expected_parent = Some(block.hash);
            last = Some(IndexWatermark {
                height: block.height,
                hash: block.hash,
            });
        }
        merged.sort();
        let final_watermark =
            last.ok_or(IndexError::NonContiguousPrepared { watermark: current })?;
        let mut store_batch = self.indexer.store.new_batch();
        put_rows(&mut store_batch, &merged);
        store_batch.put(
            ColumnFamily::UtxoMeta,
            FORMAT_VERSION_KEY,
            &FORMAT_VERSION_VALUE,
        );
        put_selected_watermarks(&mut store_batch, capabilities, Some(final_watermark));
        match cursor {
            ConsumerCursorUpdate::Keep => {}
            ConsumerCursorUpdate::Set(bytes) => {
                store_batch.put(ColumnFamily::UtxoMeta, CONSUMER_CURSOR_KEY, bytes);
            }
            ConsumerCursorUpdate::Clear => {
                store_batch.delete(ColumnFamily::UtxoMeta, CONSUMER_CURSOR_KEY);
            }
        }
        commit_ordinary(
            self.indexer.store.as_ref(),
            self.generation,
            &fence,
            store_batch,
        )?;
        self.indexer.last_counts = merged.counts();
        Ok(final_watermark)
    }

    /// Atomically rolls back one tip block and writes the parent watermark.
    ///
    /// Captures its own fence before any store-dependent derivation and
    /// clears the consumer cursor atomically: without a valid replacement
    /// block the cursor names rows that no longer exist.
    pub fn commit_rollback_one(
        &mut self,
        prev: Option<IndexWatermark>,
        body: &[u8],
    ) -> Result<(), IndexError> {
        let (fence, _) = self.fenced_watermarks()?;
        self.commit_rollback_one_for_with_cursor(
            fence,
            IndexCapabilities::ALL,
            prev,
            body,
            ConsumerCursorUpdate::Clear,
        )
    }

    /// Atomically rolls back one block for the selected capabilities,
    /// capturing its own fence and clearing the consumer cursor.
    pub fn commit_rollback_one_for(
        &mut self,
        capabilities: IndexCapabilities,
        prev: Option<IndexWatermark>,
        body: &[u8],
    ) -> Result<(), IndexError> {
        let (fence, _) = self.fenced_watermarks()?;
        self.commit_rollback_one_for_with_cursor(
            fence,
            capabilities,
            prev,
            body,
            ConsumerCursorUpdate::Clear,
        )
    }

    /// Atomically rolls back one block and applies one explicit consumer
    /// cursor disposition guarded by the captured reset-state fence.
    pub fn commit_rollback_one_for_with_cursor(
        &mut self,
        fence: IndexWriteFence,
        capabilities: IndexCapabilities,
        prev: Option<IndexWatermark>,
        body: &[u8],
        cursor: ConsumerCursorUpdate<'_>,
    ) -> Result<(), IndexError> {
        self.ensure_prepared_ready()?;
        let current = selected_watermark(fence.watermarks, capabilities)?
            .ok_or(IndexError::NonContiguousPrepared { watermark: None })?;
        let prepared = self.prepare_block_for(capabilities, current.height, current.hash, body)?;
        if let Some(prev) = &prev {
            let expected_prev_height =
                current
                    .height
                    .checked_sub(1)
                    .ok_or(IndexError::NonContiguousPrepared {
                        watermark: Some(current),
                    })?;
            if prev.height != expected_prev_height || prev.hash != prepared.parent_hash {
                return Err(IndexError::WatermarkMismatch {
                    expected: Some(*prev),
                    actual: Some(current),
                });
            }
        } else if current.height != 0 {
            return Err(IndexError::NonContiguousPrepared {
                watermark: Some(current),
            });
        }
        let header =
            prepared
                .rows
                .header_rows
                .first()
                .ok_or(IndexError::MissingWatermarkIdentity {
                    height: current.height,
                    hash: current.hash,
                })?;
        let header_present = self
            .indexer
            .store
            .get(ColumnFamily::BlockHeaders, header)?
            .is_some();
        ensure_fence_live(self.indexer.store.as_ref(), self.generation, &fence)?;
        if !header_present {
            return Err(IndexError::MissingWatermarkIdentity {
                height: current.height,
                hash: current.hash,
            });
        }
        let mut store_batch = self.indexer.store.new_batch();
        // A disabled capability may still point above this block on the same
        // disconnected prefix. Retain every ancestor identity it may need to
        // reconcile when it is enabled again.
        let unselected_keeps_identity = (!capabilities.tx_lookup
            && fence
                .watermarks
                .tx_lookup
                .is_some_and(|watermark| watermark.height >= current.height))
            || (!capabilities.script_history
                && fence
                    .watermarks
                    .script_history
                    .is_some_and(|watermark| watermark.height >= current.height));
        delete_rows(&mut store_batch, &prepared.rows, !unselected_keeps_identity);
        store_batch.put(
            ColumnFamily::UtxoMeta,
            FORMAT_VERSION_KEY,
            &FORMAT_VERSION_VALUE,
        );
        put_selected_watermarks(&mut store_batch, capabilities, prev);
        match cursor {
            ConsumerCursorUpdate::Keep => {}
            ConsumerCursorUpdate::Set(bytes) => {
                store_batch.put(ColumnFamily::UtxoMeta, CONSUMER_CURSOR_KEY, bytes);
            }
            ConsumerCursorUpdate::Clear => {
                store_batch.delete(ColumnFamily::UtxoMeta, CONSUMER_CURSOR_KEY);
            }
        }
        commit_ordinary(
            self.indexer.store.as_ref(),
            self.generation,
            &fence,
            store_batch,
        )?;
        self.indexer.last_counts = prepared.rows.counts();
        Ok(())
    }

    /// Loads the opaque consumer cursor bytes, or `None` when none is stored.
    ///
    /// The cursor is opaque to this crate: the owning consumer defines the
    /// encoding and writes it only after its rows reached the position it
    /// names, so a present cursor always describes committed rows.
    pub fn consumer_cursor(&self) -> Result<Option<Vec<u8>>, IndexError> {
        Ok(self
            .indexer
            .store
            .get(ColumnFamily::UtxoMeta, CONSUMER_CURSOR_KEY)?)
    }

    /// Publishes the opaque consumer cursor under four exact conditions from the
    /// captured fence: reset state, ordinary revision, and both watermark rows.
    /// The commit atomically advances the ordinary revision.
    ///
    /// A lost race with an unchanged reset returns
    /// [`IndexError::StaleIndexState`]. A moved reset cooperatively completes
    /// the pending exact claim and returns [`IndexError::ResetInProgress`].
    pub fn commit_consumer_cursor(
        &mut self,
        fence: IndexWriteFence,
        cursor: &[u8],
    ) -> Result<(), IndexError> {
        self.ensure_prepared_ready()?;
        let mut store_batch = self.indexer.store.new_batch();
        store_batch.put(ColumnFamily::UtxoMeta, CONSUMER_CURSOR_KEY, cursor);
        commit_ordinary(
            self.indexer.store.as_ref(),
            self.generation,
            &fence,
            store_batch,
        )
    }

    /// Forces all completed writes to durable storage.
    pub fn flush(&self) -> Result<(), IndexError> {
        self.indexer.store.flush().map_err(IndexError::Storage)
    }

    fn ensure_prepared_ready(&self) -> Result<(), IndexError> {
        if self.indexer.batch_depth != 0 || !self.indexer.pending_rows.is_empty() {
            return Err(IndexError::PendingLegacyRows);
        }
        Ok(())
    }
}

impl<S: KvStore> IndexReader for IndexWriter<S> {
    fn snapshot(&self) -> Result<Box<dyn TxIndexSnapshot + '_>, IndexError> {
        Ok(Box::new(StoreTxIndexSnapshot {
            snapshot: self.indexer.store.snapshot()?,
        }))
    }
}

fn has_any_index_row<S: KvStore>(store: &S) -> Result<bool, IndexError> {
    for cf in [
        ColumnFamily::TxConfirmed,
        ColumnFamily::Funding,
        ColumnFamily::Spending,
        ColumnFamily::BlockHeaders,
    ] {
        let mut iter = store.iter_prefix(cf, &[])?;
        if let Some(entry) = iter.next() {
            let _ = entry?;
            return Ok(true);
        }
    }
    Ok(false)
}

/// Storage-agnostic block-ingest interface.
///
/// Use this trait when consumers must hold the indexer behind a trait
/// object (e.g. when the storage backend is selected at runtime).
pub trait IndexerLike: Send + Sync {
    /// Walks `block` once and writes index rows. See `Indexer::ingest_block`.
    fn ingest_block(&mut self, block: &[u8], height: u32) -> Result<IndexRowCounts, IndexError>;

    /// Reports the row-value format. See [`Indexer::ensure_format_version`].
    ///
    /// Defaults to [`IndexFormat::Current`] for the in-memory and stub indexers
    /// used in tests, which have no persisted rows and therefore no legacy ones.
    /// A store-backed implementation must override this.
    fn ensure_format_version(&self) -> Result<IndexFormat, IndexError> {
        Ok(IndexFormat::Current)
    }

    /// Walks `block` once and writes index rows, reusing precomputed transaction IDs when supported.
    ///
    /// The default implementation preserves existing implementations by ignoring `txids` and
    /// delegating to [`IndexerLike::ingest_block`].
    fn ingest_block_with_txids(
        &mut self,
        block: &[u8],
        height: u32,
        txids: &[Txid],
    ) -> Result<IndexRowCounts, IndexError> {
        let _ = txids;
        self.ingest_block(block, height)
    }

    /// Walks `block` once and writes index rows, trusting caller-verified transaction IDs when
    /// supported.
    ///
    /// The default implementation preserves existing implementations by validating through
    /// [`IndexerLike::ingest_block_with_txids`].
    fn ingest_block_with_verified_txids(
        &mut self,
        block: &[u8],
        height: u32,
        txids: &[Txid],
    ) -> Result<IndexRowCounts, IndexError> {
        self.ingest_block_with_txids(block, height, txids)
    }

    /// Walks a decoded block and writes rows, trusting caller-verified transaction IDs when
    /// supported.
    ///
    /// The default implementation preserves existing implementations by validating through
    /// [`IndexerLike::ingest_block_with_verified_txids`].
    fn ingest_decoded_block_with_verified_txids(
        &mut self,
        block: &Block,
        serialized_block: &[u8],
        height: u32,
        txids: &[Txid],
    ) -> Result<IndexRowCounts, IndexError> {
        let _ = block;
        self.ingest_block_with_verified_txids(serialized_block, height, txids)
    }

    /// Deletes every index row that ingesting `block` at `height` would have written.
    ///
    /// The inverse of the ingest methods above. The default returns
    /// [`IndexError::UnsupportedRollback`] rather than succeeding: an
    /// implementation that silently reports a successful rollback while
    /// deleting nothing would let the node advance its tip believing the index
    /// is consistent, and `ScriptIndex` queries would then serve transactions
    /// that are no longer in the chain. Failing loudly is the only safe
    /// default. Concrete indexers that persist rows override this.
    fn rollback_block(&mut self, block: &Block, height: u32) -> Result<IndexRowCounts, IndexError> {
        let _ = (block, height);
        Err(IndexError::UnsupportedRollback)
    }

    /// Same as [`IndexerLike::rollback_block`] but reuses caller-verified
    /// transaction IDs when supported.
    ///
    /// The default implementation preserves existing implementations by
    /// ignoring `txids` and delegating to [`IndexerLike::rollback_block`].
    fn rollback_block_with_verified_txids(
        &mut self,
        block: &Block,
        height: u32,
        txids: &[Txid],
    ) -> Result<IndexRowCounts, IndexError> {
        let _ = txids;
        self.rollback_block(block, height)
    }

    /// Begins a batch of block ingests; rows are not flushed until [`IndexerLike::end_batch`].
    fn begin_batch(&mut self) {}

    /// Ends a batch of block ingests, flushing any accumulated rows.
    fn end_batch(&mut self) -> Result<(), IndexError> {
        Ok(())
    }

    /// Resolves a confirmed transaction by txid via `source`.
    ///
    /// Default implementations may return `Ok(None)` when the concrete indexer
    /// does not support transaction lookup.
    fn resolve_transaction(
        &self,
        txid: Txid,
        source: &dyn BlockSource,
    ) -> Result<Option<Tx>, IndexError> {
        let _ = (txid, source);
        Ok(None)
    }

    /// Resolves the satoshi value of the transaction output at `outpoint` via
    /// `source`. Returns `Ok(None)` when the transaction is not indexed or the
    /// `vout` is out of range.
    ///
    /// Composes `resolve_transaction(outpoint.txid, source)` and reads the
    /// `output[vout].value.to_sat()`. Building block for real fee derivation
    /// in transaction-broadcast and prevout-value lookups.
    fn resolve_outpoint_value(
        &self,
        outpoint: OutPoint,
        source: &dyn BlockSource,
    ) -> Result<Option<u64>, IndexError>;
}

/// Metadata key marking which row-value format an index was written with.
const INDEX_FORMAT_VERSION_KEY: &[u8] = b"index:format_version";

/// Current row-value format. Version 1 added transaction byte positions to
/// funding and txid row values; version 2 added positions to spending row
/// values; version 0 (unmarked) has empty values.
pub const INDEX_FORMAT_VERSION: u32 = 2;

/// Which row-value format an opened index carries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IndexFormat {
    /// Rows carry transaction positions; resolvers take the fast path.
    Current,
    /// Rows predate transaction positions; resolvers scan whole blocks.
    ///
    /// Correct but far slower. Clearing the index directory and re-syncing
    /// rebuilds it in the current format.
    Legacy {
        /// The version marker found, or `None` when the index carries none.
        found: Option<u32>,
    },
    /// A version marker exists but is not the 4 little-endian bytes of a `u32`.
    ///
    /// Resolvers scan, exactly as for [`Self::Legacy`], but the operator
    /// response differs: this is damaged metadata, not an old index, and
    /// deleting the directory would discard the evidence of whatever wrote it.
    UnreadableMarker {
        /// Byte length of the marker value that failed to decode.
        len: usize,
    },
}

/// What the format-version marker key holds, when it is present at all.
enum FormatMarker {
    /// Four little-endian bytes that decoded to this version.
    Version(u32),
    /// Present, but not a 4-byte little-endian `u32`.
    Unreadable {
        /// Byte length of the value found.
        len: usize,
    },
}

/// Provides block lookups for resolving lossy index prefixes to full identities.
///
/// The index column families store 8-byte prefixes of txids/scripthashes/outpoints.
/// To recover the full Bitcoin identities behind a `HashPrefixRow`, callers need
/// to fetch the block at the row's height and walk its transactions. `BlockSource`
/// is the trait that hides where blocks come from (in-memory store, raw-block KV
/// database, peer fetch).
pub trait BlockSource {
    /// Returns the Bitcoin block at `height` on the active chain, if known.
    fn block_at_height(&self, height: u32) -> Option<Block>;

    /// Returns `len` serialized bytes starting `offset` bytes into the active
    /// block at `height`, without materializing or decoding the whole body.
    ///
    /// This is what lets a resolver read only the transactions a row's
    /// [`crate::types::TxPosition`]s name instead of scanning the block.
    ///
    /// Defaults to `None`, meaning "this source cannot slice". A caller must
    /// then fall back to `block_at_height` — `None` never means the bytes are
    /// absent, and an out-of-range request yields `None` rather than a short
    /// read.
    fn block_bytes_at_height(&self, _height: u32, _offset: u32, _len: u32) -> Option<Vec<u8>> {
        None
    }
}

impl<S: KvStore + Send + Sync + 'static> IndexerLike for Indexer<S> {
    fn ingest_block(&mut self, block: &[u8], height: u32) -> Result<IndexRowCounts, IndexError> {
        Self::ingest_block(self, block, height)
    }

    fn ensure_format_version(&self) -> Result<IndexFormat, IndexError> {
        Self::ensure_format_version(self)
    }

    fn ingest_block_with_txids(
        &mut self,
        block: &[u8],
        height: u32,
        txids: &[Txid],
    ) -> Result<IndexRowCounts, IndexError> {
        Self::ingest_block_with_txids(self, block, height, txids)
    }

    fn ingest_block_with_verified_txids(
        &mut self,
        block: &[u8],
        height: u32,
        txids: &[Txid],
    ) -> Result<IndexRowCounts, IndexError> {
        Self::ingest_block_with_verified_txids(self, block, height, txids)
    }

    fn ingest_decoded_block_with_verified_txids(
        &mut self,
        block: &Block,
        serialized_block: &[u8],
        height: u32,
        txids: &[Txid],
    ) -> Result<IndexRowCounts, IndexError> {
        Self::ingest_decoded_block_with_verified_txids(self, block, serialized_block, height, txids)
    }

    fn rollback_block(&mut self, block: &Block, height: u32) -> Result<IndexRowCounts, IndexError> {
        Self::rollback_block(self, block, height)
    }

    fn rollback_block_with_verified_txids(
        &mut self,
        block: &Block,
        height: u32,
        txids: &[Txid],
    ) -> Result<IndexRowCounts, IndexError> {
        Self::rollback_block_with_verified_txids(self, block, height, txids)
    }

    fn begin_batch(&mut self) {
        Self::begin_batch(self);
    }

    fn end_batch(&mut self) -> Result<(), IndexError> {
        Self::end_batch(self)
    }

    fn resolve_transaction(
        &self,
        txid: Txid,
        source: &dyn BlockSource,
    ) -> Result<Option<Tx>, IndexError> {
        Self::resolve_transaction(self, txid, source)
    }

    fn resolve_outpoint_value(
        &self,
        outpoint: OutPoint,
        source: &dyn BlockSource,
    ) -> Result<Option<u64>, IndexError> {
        Self::resolve_outpoint_value(self, outpoint, source)
    }
}

#[cfg(all(test, feature = "rocksdb"))]
mod tests {
    use std::sync::Arc;

    use bitcoin_rs_primitives::{
        Block, BlockHash, Hash256, Header, Network, OutPoint, Tx, TxIn, TxOut, Txid,
        consensus_bytes,
    };
    use bitcoin_rs_storage::{ColumnFamily, KvStore, RocksDbStore};

    use super::{BlockSource, Indexer, is_op_return_script};
    use crate::{ScriptHash, ScriptHashRow, ScriptHistoryEntry, SpendingPrefixRow, TxidRow};

    const HEIGHT: u32 = 42;
    type StoredRows = Vec<(ColumnFamily, Vec<u8>)>;

    #[test]
    fn raw_op_return_check_matches_script_prefix_semantics() {
        assert!(!is_op_return_script(&[]));
        assert!(is_op_return_script(&[0x6a]));
        assert!(is_op_return_script(&[0x6a, 0x01, 0x00]));
        assert!(!is_op_return_script(&[0x00, 0x6a]));
    }

    #[test]
    fn iter_funding_rows_returns_indexed_rows() -> Result<(), Box<dyn std::error::Error>> {
        let script = vec![0x51, 0x01];
        let tx = tx(spent_outpoint(1, 0), script.clone());
        let (_dir, mut indexer) = indexer()?;

        indexer.ingest_block(&consensus_bytes(&block(vec![tx])), HEIGHT)?;

        let scripthash = ScriptHash::from_script_bytes(&script);
        assert_eq!(
            indexer.iter_funding_rows(scripthash)?,
            vec![ScriptHashRow::row(scripthash, HEIGHT)]
        );
        Ok(())
    }

    /// Proves that lexicographic key byte order does **not** match numeric
    /// height order within one prefix, because the height suffix is
    /// little-endian. Height 256 is `[0x00, 0x01, 0x00, 0x00]`, height 1 is
    /// `[0x01, 0x00, 0x00, 0x00]`, so byte order puts 256 before 1.
    ///
    /// This pins the corrected doc contract on `iter_funding_rows`: callers
    /// needing chronological order must sort by numeric height after
    /// exact-resolving rows, never rely on store iteration order.
    #[test]
    fn iter_funding_rows_height_order_is_le_byte_order_not_numeric()
    -> Result<(), Box<dyn std::error::Error>> {
        let script = vec![0x51, 0x01];
        let scripthash = ScriptHash::from_script_bytes(&script);
        let (_dir, mut indexer) = indexer()?;

        let tx_at_1 = tx(spent_outpoint(1, 0), script.clone());
        let tx_at_256 = tx(spent_outpoint(2, 0), script);
        indexer.ingest_block(&consensus_bytes(&block(vec![tx_at_1])), 1)?;
        indexer.ingest_block(&consensus_bytes(&block(vec![tx_at_256])), 256)?;
        indexer.flush()?;

        let rows = indexer.iter_funding_rows(scripthash)?;
        assert_eq!(rows.len(), 2, "two heights funded the same script");

        // Store iteration order is LE byte order, so 256 precedes 1.
        assert_eq!(
            rows[0].height(),
            256,
            "LE byte order puts height 256 before height 1, not numeric order"
        );
        assert_eq!(rows[1].height(), 1);

        // The corollary: numeric sort produces the opposite order, so no
        // caller may treat raw iteration order as chronological.
        let mut numeric = rows.clone();
        numeric.sort_by_key(|row| row.height());
        assert_eq!(
            numeric.iter().map(|row| row.height()).collect::<Vec<_>>(),
            vec![1, 256]
        );
        assert_ne!(
            rows, numeric,
            "store iteration order must differ from numeric height order"
        );
        Ok(())
    }

    #[test]
    fn iter_spending_rows_returns_indexed_rows() -> Result<(), Box<dyn std::error::Error>> {
        let outpoint = spent_outpoint(2, 3);
        let tx = tx(outpoint, vec![0x51, 0x02]);
        let (_dir, mut indexer) = indexer()?;

        indexer.ingest_block(&consensus_bytes(&block(vec![tx])), HEIGHT)?;

        assert_eq!(
            indexer.iter_spending_rows(&outpoint)?,
            vec![SpendingPrefixRow::row(&outpoint, HEIGHT)]
        );
        Ok(())
    }

    #[test]
    fn iter_txid_rows_returns_indexed_rows() -> Result<(), Box<dyn std::error::Error>> {
        let tx = tx(spent_outpoint(4, 5), vec![0x51, 0x03]);
        let txid = tx.txid();
        let (_dir, mut indexer) = indexer()?;

        indexer.ingest_block(&consensus_bytes(&block(vec![tx])), HEIGHT)?;

        let rows = indexer.iter_txid_rows(&txid)?;
        assert!(rows.contains(&TxidRow::row(&txid, HEIGHT)));
        Ok(())
    }

    #[test]
    fn decoded_verified_txid_ingest_matches_serialized_ingest()
    -> Result<(), Box<dyn std::error::Error>> {
        let coinbase = tx(OutPoint::new(Txid::default(), u32::MAX), vec![0x51, 0x04]);
        let spender = Tx {
            version: 2,
            lock_time: 0,
            inputs: vec![TxIn {
                previous_output: spent_outpoint(9, 1),
                script_sig: Vec::new(),
                sequence: u32::MAX,
                witness: Vec::new(),
            }],
            outputs: vec![
                TxOut {
                    value: 5_000,
                    script_pubkey: vec![0x51, 0x05],
                },
                TxOut {
                    value: 0,
                    script_pubkey: vec![0x6a, 0x01, 0x00],
                },
            ],
        };
        let block = block(vec![coinbase, spender]);
        let block_bytes = consensus_bytes(&block);
        let txids = block.txs.iter().map(Tx::txid).collect::<Vec<_>>();
        let (_serialized_dir, mut serialized_indexer) = indexer()?;
        let (_decoded_dir, mut decoded_indexer) = indexer()?;

        let serialized_counts =
            serialized_indexer.ingest_block_with_verified_txids(&block_bytes, HEIGHT, &txids)?;
        let decoded_counts = decoded_indexer.ingest_decoded_block_with_verified_txids(
            &block,
            &block_bytes,
            HEIGHT,
            &txids,
        )?;

        assert_eq!(decoded_counts, serialized_counts);
        assert_eq!(
            stored_rows(&decoded_indexer)?,
            stored_rows(&serialized_indexer)?
        );
        Ok(())
    }

    #[test]
    fn decoded_verified_txid_ingest_mismatch_falls_back_to_serialized_ingest()
    -> Result<(), Box<dyn std::error::Error>> {
        let decoded_block = block(vec![tx(
            OutPoint::new(Txid::default(), u32::MAX),
            vec![0x51, 0x08],
        )]);
        let serialized_block = block(vec![
            tx(OutPoint::new(Txid::default(), u32::MAX), vec![0x51, 0x06]),
            tx(spent_outpoint(10, 0), vec![0x51, 0x07]),
        ]);
        let serialized_block_bytes = consensus_bytes(&serialized_block);
        let (_serialized_dir, mut serialized_indexer) = indexer()?;
        let (_decoded_dir, mut decoded_indexer) = indexer()?;

        let serialized_counts = serialized_indexer.ingest_block(&serialized_block_bytes, HEIGHT)?;
        let decoded_counts = decoded_indexer.ingest_decoded_block_with_verified_txids(
            &decoded_block,
            &serialized_block_bytes,
            HEIGHT,
            &[],
        )?;

        assert_eq!(decoded_counts, serialized_counts);
        assert_eq!(
            stored_rows(&decoded_indexer)?,
            stored_rows(&serialized_indexer)?
        );
        Ok(())
    }

    #[test]
    fn resolve_script_history_returns_entries_for_funded_scripthash()
    -> Result<(), Box<dyn std::error::Error>> {
        let block = Network::Regtest.genesis_block();
        let Some(tx) = block.txs.first() else {
            return Err(std::io::Error::other("genesis block has no transactions").into());
        };
        let Some(output) = tx.outputs.first() else {
            return Err(std::io::Error::other("genesis transaction has no outputs").into());
        };
        let scripthash = ScriptHash::from_script_bytes(&output.script_pubkey);
        let txid = tx.txid();
        let (_dir, mut indexer) = indexer()?;

        indexer.ingest_block(&consensus_bytes(&block), 0)?;

        let source = FakeSource {
            block,
            target_height: 0,
        };
        let entries = indexer.resolve_script_history(scripthash, &source)?;

        assert_eq!(entries, vec![ScriptHistoryEntry::confirmed(txid, 0)]);
        Ok(())
    }
    #[test]
    fn resolve_unspent_outputs_returns_txid_vout_value_for_funded_scripthash()
    -> Result<(), Box<dyn std::error::Error>> {
        let block = Network::Regtest.genesis_block();
        let Some(tx) = block.txs.first() else {
            return Err(std::io::Error::other("genesis block has no transactions").into());
        };
        let Some(output) = tx.outputs.first() else {
            return Err(std::io::Error::other("genesis transaction has no outputs").into());
        };
        let scripthash = ScriptHash::from_script_bytes(&output.script_pubkey);
        let txid = tx.txid();
        let value = output.value;
        let (_dir, mut indexer) = indexer()?;

        indexer.ingest_block(&consensus_bytes(&block), 0)?;

        let source = FakeSource {
            block,
            target_height: 0,
        };
        let outputs = indexer.resolve_unspent_outputs(scripthash, &source)?;

        assert_eq!(outputs, vec![(txid, 0, value)]);
        Ok(())
    }

    #[test]
    fn resolve_transaction_returns_coinbase_for_genesis_block_indexed_at_height_zero()
    -> Result<(), Box<dyn std::error::Error>> {
        let block = Network::Regtest.genesis_block();
        let Some(tx) = block.txs.first() else {
            return Err(std::io::Error::other("genesis block has no transactions").into());
        };
        let coinbase = tx.clone();
        let txid = tx.txid();
        let (_dir, mut indexer) = indexer()?;

        indexer.ingest_block(&consensus_bytes(&block), 0)?;

        let source = FakeSource {
            block,
            target_height: 0,
        };
        let resolved = indexer.resolve_transaction(txid, &source)?;

        assert_eq!(resolved, Some(coinbase));
        Ok(())
    }

    #[test]
    fn resolve_transaction_returns_none_when_indexed_height_is_not_visible()
    -> Result<(), Box<dyn std::error::Error>> {
        let block = Network::Regtest.genesis_block();
        let Some(tx) = block.txs.first() else {
            return Err(std::io::Error::other("genesis block has no transactions").into());
        };
        let txid = tx.txid();
        let (_dir, mut indexer) = indexer()?;

        indexer.ingest_block(&consensus_bytes(&block), 0)?;

        let source = FakeSource {
            block,
            target_height: 1,
        };
        let resolved = indexer.resolve_transaction(txid, &source)?;

        assert_eq!(resolved, None);
        Ok(())
    }

    #[test]
    fn resolve_tx_with_height_returns_genesis_coinbase_at_height_zero()
    -> Result<(), Box<dyn std::error::Error>> {
        let block = Network::Regtest.genesis_block();
        let Some(tx) = block.txs.first() else {
            return Err(std::io::Error::other("genesis block has no transactions").into());
        };
        let coinbase = tx.clone();
        let txid = tx.txid();
        let (_dir, mut indexer) = indexer()?;

        indexer.ingest_block(&consensus_bytes(&block), 0)?;

        let source = FakeSource {
            block,
            target_height: 0,
        };
        let resolved = indexer.resolve_tx_with_height(txid, &source)?;

        assert_eq!(resolved, Some((coinbase, 0)));
        Ok(())
    }

    #[test]
    fn resolve_tx_with_height_returns_none_for_unknown_txid()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_dir, indexer) = indexer()?;
        let txid = Txid(Hash256::from_le_bytes(&[0xff; 32]));
        let source = FakeSource {
            block: Network::Regtest.genesis_block(),
            target_height: 0,
        };

        assert_eq!(indexer.resolve_tx_with_height(txid, &source)?, None);
        Ok(())
    }

    #[test]
    fn resolve_outpoint_value_returns_genesis_coinbase_subsidy()
    -> Result<(), Box<dyn std::error::Error>> {
        let block = Network::Regtest.genesis_block();
        let Some(tx) = block.txs.first() else {
            return Err(std::io::Error::other("genesis block has no transactions").into());
        };
        let txid = tx.txid();
        let (_dir, mut indexer) = indexer()?;

        indexer.ingest_block(&consensus_bytes(&block), 0)?;

        let source = FakeSource {
            block,
            target_height: 0,
        };
        let outpoint = OutPoint { txid, vout: 0 };
        let value = indexer.resolve_outpoint_value(outpoint, &source)?;

        assert_eq!(value, Some(5_000_000_000));
        Ok(())
    }

    #[test]
    fn resolve_outpoint_value_via_indexerlike_dyn_source() -> Result<(), Box<dyn std::error::Error>>
    {
        let block = Network::Regtest.genesis_block();
        let Some(tx) = block.txs.first() else {
            return Err(std::io::Error::other("genesis block has no transactions").into());
        };
        let txid = tx.txid();
        let (_dir, mut indexer) = indexer()?;

        indexer.ingest_block(&consensus_bytes(&block), 0)?;

        let source = FakeSource {
            block,
            target_height: 0,
        };
        let dyn_indexer: &dyn super::IndexerLike = &indexer;
        let dyn_source: &dyn super::BlockSource = &source;
        let outpoint = OutPoint { txid, vout: 0 };
        let value = dyn_indexer.resolve_outpoint_value(outpoint, dyn_source)?;

        assert_eq!(value, Some(5_000_000_000));
        Ok(())
    }

    #[test]
    fn resolve_outpoint_value_returns_none_for_vout_out_of_range()
    -> Result<(), Box<dyn std::error::Error>> {
        let block = Network::Regtest.genesis_block();
        let Some(tx) = block.txs.first() else {
            return Err(std::io::Error::other("genesis block has no transactions").into());
        };
        let txid = tx.txid();
        let (_dir, mut indexer) = indexer()?;

        indexer.ingest_block(&consensus_bytes(&block), 0)?;

        let source = FakeSource {
            block,
            target_height: 0,
        };
        let outpoint = OutPoint { txid, vout: 99 };

        assert_eq!(indexer.resolve_outpoint_value(outpoint, &source)?, None);
        Ok(())
    }

    #[test]
    fn resolve_outpoint_value_returns_none_for_unknown_txid()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_dir, indexer) = indexer()?;
        let outpoint = OutPoint {
            txid: Txid(Hash256::from_le_bytes(&[0xff; 32])),
            vout: 0,
        };
        let source = FakeSource {
            block: Network::Regtest.genesis_block(),
            target_height: 0,
        };

        assert_eq!(indexer.resolve_outpoint_value(outpoint, &source)?, None);
        Ok(())
    }

    #[test]
    fn resolve_unspent_outputs_with_height_returns_funding_height()
    -> Result<(), Box<dyn std::error::Error>> {
        let block = Network::Regtest.genesis_block();
        let Some(tx) = block.txs.first() else {
            return Err(std::io::Error::other("genesis block has no transactions").into());
        };
        let Some(output) = tx.outputs.first() else {
            return Err(std::io::Error::other("genesis transaction has no outputs").into());
        };
        let scripthash = ScriptHash::from_script_bytes(&output.script_pubkey);
        let txid = tx.txid();
        let value = output.value;
        let (_dir, mut indexer) = indexer()?;

        indexer.ingest_block(&consensus_bytes(&block), 0)?;

        let source = FakeSource {
            block,
            target_height: 0,
        };
        let outputs = indexer.resolve_unspent_outputs_with_height(scripthash, &source)?;

        assert_eq!(outputs, vec![(txid, 0, value, 0)]);
        Ok(())
    }

    struct FakeSource {
        block: Block,
        target_height: u32,
    }

    impl BlockSource for FakeSource {
        fn block_at_height(&self, height: u32) -> Option<Block> {
            if height == self.target_height {
                return Some(self.block.clone());
            }
            None
        }
    }

    /// A block whose rows populate all four column families: a coinbase plus a
    /// spend, so funding and spending rows both exist alongside txid and header
    /// rows.
    fn rollback_fixture_block() -> Block {
        let funded = tx(OutPoint::new(Txid::default(), u32::MAX), vec![0x51]);
        let spender = tx(OutPoint::new(funded.txid(), 0), vec![0x52]);
        block(vec![funded, spender])
    }

    #[test]
    fn rollback_removes_every_row_a_matching_ingest_wrote() -> Result<(), Box<dyn std::error::Error>>
    {
        let (_dir, mut indexer) = indexer()?;
        let candidate = rollback_fixture_block();
        let before = stored_rows(&indexer)?;

        let written = indexer.ingest_block(&consensus_bytes(&candidate), HEIGHT)?;
        let after_ingest = stored_rows(&indexer)?;
        assert!(
            after_ingest.len() > before.len(),
            "fixture must write rows to be a meaningful rollback test"
        );
        // All four column families must be exercised, or the test proves little.
        for cf in [
            ColumnFamily::TxConfirmed,
            ColumnFamily::Funding,
            ColumnFamily::Spending,
            ColumnFamily::BlockHeaders,
        ] {
            assert!(
                after_ingest.iter().any(|(family, _)| *family == cf),
                "fixture wrote no rows to {cf:?}"
            );
        }

        let removed = indexer.rollback_block(&candidate, HEIGHT)?;
        assert_eq!(removed.txids, written.txids);
        assert_eq!(removed.funding, written.funding);
        assert_eq!(removed.spending, written.spending);
        assert_eq!(removed.headers, written.headers);
        assert_eq!(
            stored_rows(&indexer)?,
            before,
            "rollback must restore the pre-ingest row set exactly"
        );
        Ok(())
    }

    #[test]
    fn last_counts_remains_ingest_after_rollback() -> Result<(), Box<dyn std::error::Error>> {
        let (_dir, mut indexer) = indexer()?;
        let old = rollback_fixture_block();
        let old_written = indexer.ingest_block(&consensus_bytes(&old), HEIGHT)?;
        let _ = indexer.rollback_block(&old, HEIGHT)?;

        // A replacement at the same height with a different shape so its
        // ingest counts differ from the old block's rollback counts.
        let replacement = block(vec![
            tx(OutPoint::new(Txid::default(), u32::MAX), vec![0x51]),
            tx(OutPoint::new(Txid::default(), u32::MAX), vec![0x52]),
        ]);
        let replacement_written = indexer.ingest_block(&consensus_bytes(&replacement), HEIGHT)?;
        assert_ne!(
            replacement_written, old_written,
            "replacement counts must differ from the old block's counts"
        );

        // Re-rolling the already-gone old block returns its original counts
        // but must not overwrite the last successful ingest counts.
        let old_again = indexer.rollback_block(&old, HEIGHT)?;
        assert_eq!(old_again, old_written);
        assert_eq!(
            indexer.last_counts(),
            replacement_written,
            "last_counts must stay the last ingest counts, not the rollback counts"
        );
        Ok(())
    }

    #[test]
    fn rollback_of_a_never_indexed_block_is_not_an_error() -> Result<(), Box<dyn std::error::Error>>
    {
        let (_dir, mut indexer) = indexer()?;
        let candidate = rollback_fixture_block();

        // An indexer enabled after the block was applied never wrote its rows.
        indexer.rollback_block(&candidate, HEIGHT)?;
        assert!(stored_rows(&indexer)?.is_empty());
        Ok(())
    }

    #[test]
    fn repeated_rollback_is_not_an_error() -> Result<(), Box<dyn std::error::Error>> {
        let (_dir, mut indexer) = indexer()?;
        let candidate = rollback_fixture_block();
        indexer.ingest_block(&consensus_bytes(&candidate), HEIGHT)?;

        indexer.rollback_block(&candidate, HEIGHT)?;
        let after_first = stored_rows(&indexer)?;
        indexer.rollback_block(&candidate, HEIGHT)?;
        assert_eq!(
            stored_rows(&indexer)?,
            after_first,
            "a second rollback must be observationally inert"
        );
        Ok(())
    }

    /// Regression: rollback writes deletions straight to the store, so rows
    /// still buffered in `pending_rows` used to survive it and a later
    /// `end_batch` resurrected the disconnected block.
    #[test]
    fn rollback_inside_an_open_batch_is_not_undone_by_end_batch()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_dir, mut indexer) = indexer()?;
        let candidate = rollback_fixture_block();

        indexer.begin_batch();
        indexer.ingest_block(&consensus_bytes(&candidate), HEIGHT)?;
        indexer.rollback_block(&candidate, HEIGHT)?;
        indexer.end_batch()?;

        assert!(
            stored_rows(&indexer)?.is_empty(),
            "end_batch must not write back rows for a rolled-back block"
        );
        Ok(())
    }

    /// Delegates reads to a real store but fails every write API, so the
    /// all-or-nothing claim on `rollback_block` is exercised through its
    /// current conditional durable path.
    struct FailingWriteStore(RocksDbStore);

    impl bitcoin_rs_storage::KvStore for FailingWriteStore {
        type WriteBatch = <RocksDbStore as KvStore>::WriteBatch;

        fn get(
            &self,
            cf: ColumnFamily,
            key: &[u8],
        ) -> Result<Option<Vec<u8>>, bitcoin_rs_storage::StorageError> {
            self.0.get(cf, key)
        }

        fn iter_prefix<'a>(
            &'a self,
            cf: ColumnFamily,
            prefix: &[u8],
        ) -> Result<bitcoin_rs_storage::KvIter<'a>, bitcoin_rs_storage::StorageError> {
            self.0.iter_prefix(cf, prefix)
        }

        fn new_batch(&self) -> Self::WriteBatch {
            self.0.new_batch()
        }

        fn write(&self, _batch: Self::WriteBatch) -> Result<(), bitcoin_rs_storage::StorageError> {
            Err(bitcoin_rs_storage::StorageError::Backend(
                "injected write failure".to_owned(),
            ))
        }

        fn write_durable_if(
            &self,
            _conditions: &[bitcoin_rs_storage::WriteCondition<'_>],
            _batch: Self::WriteBatch,
        ) -> Result<bool, bitcoin_rs_storage::StorageError> {
            Err(bitcoin_rs_storage::StorageError::Backend(
                "injected write failure".to_owned(),
            ))
        }

        fn flush(&self) -> Result<(), bitcoin_rs_storage::StorageError> {
            self.0.flush()
        }

        fn snapshot(
            &self,
        ) -> Result<Box<dyn bitcoin_rs_storage::KvSnapshot + '_>, bitcoin_rs_storage::StorageError>
        {
            self.0.snapshot()
        }
    }

    #[test]
    fn rollback_deletes_nothing_when_the_write_fails() -> Result<(), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let candidate = rollback_fixture_block();

        // Populate through a normal indexer, then reopen behind the failing
        // store so the rows exist but no write can land.
        {
            let store = Arc::new(RocksDbStore::open(dir.path())?);
            let mut indexer = Indexer::new(store);
            indexer.ingest_block(&consensus_bytes(&candidate), HEIGHT)?;
        }
        let store = Arc::new(RocksDbStore::open(dir.path())?);
        let before = stored_rows(&Indexer::new(Arc::clone(&store)))?;
        assert!(!before.is_empty(), "fixture must have rows to preserve");
        drop(store);

        let failing = Arc::new(FailingWriteStore(RocksDbStore::open(dir.path())?));
        let mut indexer = Indexer::new(Arc::clone(&failing));
        let outcome = indexer.rollback_block(&candidate, HEIGHT);
        assert!(outcome.is_err(), "a failing write must surface as an error");
        drop(indexer);
        drop(failing);

        let reopened = Indexer::new(Arc::new(RocksDbStore::open(dir.path())?));
        assert_eq!(
            stored_rows(&reopened)?,
            before,
            "a failed rollback must leave every row in place"
        );
        Ok(())
    }

    /// An indexer that persists nothing and does not override the rollback
    /// default. It must refuse rather than report a successful no-op, or the
    /// node would advance its tip believing a stale index is consistent.
    struct RollbackUnawareIndexer;

    impl super::IndexerLike for RollbackUnawareIndexer {
        fn ingest_block(
            &mut self,
            _block: &[u8],
            _height: u32,
        ) -> Result<super::IndexRowCounts, super::IndexError> {
            Ok(super::IndexRowCounts::default())
        }

        fn resolve_transaction(
            &self,
            _txid: Txid,
            _source: &dyn BlockSource,
        ) -> Result<Option<Tx>, super::IndexError> {
            Ok(None)
        }

        fn resolve_outpoint_value(
            &self,
            _outpoint: OutPoint,
            _source: &dyn BlockSource,
        ) -> Result<Option<u64>, super::IndexError> {
            Ok(None)
        }
    }

    #[test]
    fn the_rollback_default_refuses_rather_than_silently_succeeding() {
        let mut indexer = RollbackUnawareIndexer;
        let candidate = rollback_fixture_block();
        assert!(matches!(
            super::IndexerLike::rollback_block(&mut indexer, &candidate, HEIGHT),
            Err(super::IndexError::UnsupportedRollback)
        ));
    }

    /// A repeated rollback must not delete a replacement block's rows.
    ///
    /// Funding, spending, and txid keys are an 8-byte prefix plus the height
    /// and carry no block identity, so a replacement at the same height that
    /// shares an output script derives the same keys. Without the header-row
    /// identity check, rolling the old block back twice deleted the
    /// replacement's history.
    #[test]
    fn a_repeated_rollback_leaves_a_replacement_blocks_rows_alone()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_dir, mut indexer) = indexer()?;
        let shared_script = vec![0x51];

        // Two different blocks at the same height that both pay the same
        // script, so their funding rows collide.
        // The shared `block` fixture pins a zero merkle root, so the nonce is
        // what distinguishes these two headers.
        let mut old_block = block(vec![tx(
            OutPoint::new(Txid(Hash256::from_le_bytes(&[0xa1; 32])), 0),
            shared_script.clone(),
        )]);
        old_block.header.nonce = 1;
        let mut replacement = block(vec![tx(
            OutPoint::new(Txid(Hash256::from_le_bytes(&[0xb2; 32])), 0),
            shared_script,
        )]);
        replacement.header.nonce = 2;
        assert_ne!(
            old_block.block_hash(),
            replacement.block_hash(),
            "the two blocks must differ, or there is nothing to confuse"
        );

        indexer.ingest_block(&consensus_bytes(&old_block), HEIGHT)?;
        indexer.rollback_block(&old_block, HEIGHT)?;
        indexer.ingest_block(&consensus_bytes(&replacement), HEIGHT)?;
        indexer.flush()?;
        let after_replacement = stored_rows(&indexer)?;
        assert!(
            !after_replacement.is_empty(),
            "the replacement must have written rows"
        );

        // Roll the OLD block back again. It is already gone; its keys now
        // belong to the replacement.
        indexer.rollback_block(&old_block, HEIGHT)?;
        indexer.flush()?;

        assert_eq!(
            stored_rows(&indexer)?,
            after_replacement,
            "a repeated rollback must not touch the replacement's rows"
        );
        Ok(())
    }

    fn indexer() -> Result<(tempfile::TempDir, Indexer<RocksDbStore>), Box<dyn std::error::Error>> {
        let dir = tempfile::tempdir()?;
        let store = Arc::new(RocksDbStore::open(dir.path())?);
        Ok((dir, Indexer::new(store)))
    }

    fn stored_rows(
        indexer: &Indexer<RocksDbStore>,
    ) -> Result<StoredRows, Box<dyn std::error::Error>> {
        let mut rows = Vec::new();
        for cf in [
            ColumnFamily::TxConfirmed,
            ColumnFamily::Funding,
            ColumnFamily::Spending,
            ColumnFamily::BlockHeaders,
        ] {
            for row in indexer.store().iter_prefix(cf, &[])? {
                let (key, _value) = row?;
                rows.push((cf, key));
            }
        }
        rows.sort_by(|left, right| {
            (left.0.as_str(), left.1.as_slice()).cmp(&(right.0.as_str(), right.1.as_slice()))
        });
        Ok(rows)
    }

    fn block(txs: Vec<Tx>) -> Block {
        Block {
            header: Header {
                version: 1,
                prev_blockhash: BlockHash::default(),
                merkle_root: Hash256::default(),
                time: 0,
                bits: 0,
                nonce: 0,
            },
            txs,
        }
    }

    fn tx(previous_output: OutPoint, script_pubkey: Vec<u8>) -> Tx {
        Tx {
            version: 2,
            lock_time: 0,
            inputs: vec![TxIn {
                previous_output,
                script_sig: Vec::new(),
                sequence: u32::MAX,
                witness: Vec::new(),
            }],
            outputs: vec![TxOut {
                value: 5_000,
                script_pubkey,
            }],
        }
    }

    fn spent_outpoint(label: u8, vout: u32) -> OutPoint {
        OutPoint::new(Txid(Hash256::from_le_bytes(&[label; 32])), vout)
    }
}
