use std::ops::ControlFlow;

use bitcoin_rs_primitives::{Block, Hash256, OutPoint, Tx, Txid, encode};
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
    /// A `ScriptLive` row had a non-empty value even though the row format is
    /// key-only.
    #[error("invalid ScriptLive row value length {len}")]
    InvalidLiveRowValue {
        /// Actual value length observed in storage.
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
    /// A capability set containing `ScriptLive` was prepared through a path
    /// that carries no spent-coin script source. Live deletes need the spent
    /// coin's exact script (#225), and a prevout-only block parse cannot
    /// produce it.
    #[error("ScriptLive preparation requires a spent-coin script source")]
    MissingSpentScripts,
    /// The spent-coin source could not resolve an external input's script.
    /// Failing closed here is deliberate: a missing anchor means the Live view
    /// would silently keep a spent output alive.
    #[error("no spent-coin script for outpoint {txid:02x?}:{vout} in block at height {height}")]
    MissingSpentCoin {
        /// Spent transaction id (little-endian bytes).
        txid: [u8; 32],
        /// Spent output index.
        vout: u32,
        /// Height of the spending block.
        height: u32,
    },
    /// `seed_script_live` was asked to seed over an existing live watermark.
    /// Seeding assumes a fresh (or reset) capability; overwriting a live view
    /// in place is how partial states become queryable.
    #[error("ScriptLive is already seeded; reset the capability first")]
    LiveAlreadySeeded,
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
const SCRIPT_LIVE_WATERMARK_KEY: &[u8] = &[0x00, b'L'];
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

/// Captures the reset state, ordinary revision, and all capability watermarks from one
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
    let observed_script_live = snapshot.get(ColumnFamily::UtxoMeta, SCRIPT_LIVE_WATERMARK_KEY)?;
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
            script_live: observed_script_live
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

/// Applies one ordinary batch under the coherent fence. Five exact conditions
/// fence the batch: reset state, ordinary revision, and all watermark rows.
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
    let script_live = fence
        .watermarks
        .script_live
        .map(|watermark| watermark.to_bytes());
    let conditions = [
        reset_condition(&fence.state),
        revision_condition(fence.revision, &revision_bytes),
        watermark_condition(tx_lookup.as_ref(), TX_LOOKUP_WATERMARK_KEY),
        watermark_condition(script_history.as_ref(), SCRIPT_HISTORY_WATERMARK_KEY),
        watermark_condition(script_live.as_ref(), SCRIPT_LIVE_WATERMARK_KEY),
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
        if capabilities.script_live {
            batch.delete(ColumnFamily::UtxoMeta, SCRIPT_LIVE_WATERMARK_KEY);
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
        if capabilities.script_live {
            column_families.push(ColumnFamily::ScriptLive);
        }
        let unselected_cursor_remains = (!capabilities.tx_lookup
            && store
                .get(ColumnFamily::UtxoMeta, TX_LOOKUP_WATERMARK_KEY)?
                .is_some())
            || (!capabilities.script_history
                && store
                    .get(ColumnFamily::UtxoMeta, SCRIPT_HISTORY_WATERMARK_KEY)?
                    .is_some())
            || (!capabilities.script_live
                && store
                    .get(ColumnFamily::UtxoMeta, SCRIPT_LIVE_WATERMARK_KEY)?
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
        IndexCapability::ScriptLive => SCRIPT_LIVE_WATERMARK_KEY,
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
    /// `ScriptIndex` live-output rows: one row per currently unspent outpoint,
    /// filed under its script (#225). Rebuildable from the authoritative UTXO
    /// set alone, unlike history.
    ScriptLive,
}

/// Capabilities included in one prepared index transition.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct IndexCapabilities {
    /// Build transaction lookup rows.
    pub tx_lookup: bool,
    /// Build `ScriptIndex` funding and spending rows.
    pub script_history: bool,
    /// Build `ScriptIndex` live-output rows.
    pub script_live: bool,
}

impl IndexCapabilities {
    /// No derived rows.
    pub const NONE: Self = Self {
        tx_lookup: false,
        script_history: false,
        script_live: false,
    };
    /// Transaction lookup only.
    pub const TX_LOOKUP: Self = Self {
        tx_lookup: true,
        script_history: false,
        script_live: false,
    };
    /// `ScriptIndex` history only.
    pub const SCRIPT_HISTORY: Self = Self {
        tx_lookup: false,
        script_history: true,
        script_live: false,
    };
    /// `ScriptIndex` live outputs only.
    pub const SCRIPT_LIVE: Self = Self {
        tx_lookup: false,
        script_history: false,
        script_live: true,
    };
    /// Every index capability, including the compact live view.
    pub const ALL: Self = Self {
        tx_lookup: true,
        script_history: true,
        script_live: true,
    };
    /// Every capability derivable from a block body alone.
    ///
    /// Anchorless paths use this, because `ScriptLive` cannot be prepared
    /// without a spent-coin script source.
    pub const HISTORICAL: Self = Self {
        tx_lookup: true,
        script_history: true,
        script_live: false,
    };

    /// Returns whether `capability` is selected.
    pub const fn contains(self, capability: IndexCapability) -> bool {
        match capability {
            IndexCapability::TxLookup => self.tx_lookup,
            IndexCapability::ScriptHistory => self.script_history,
            IndexCapability::ScriptLive => self.script_live,
        }
    }

    /// Returns whether no capability is selected.
    pub const fn is_empty(self) -> bool {
        !self.tx_lookup && !self.script_history && !self.script_live
    }

    /// Persisted cursors this selection no longer maintains.
    ///
    /// Mode demotion (`full` → `utxo`) and an explicit-`txindex` independence
    /// change leave durable rows behind. Those leftover families are reset
    /// and rebuilt or discarded; they are never served as if still configured.
    #[must_use]
    pub const fn leftover(self, watermarks: IndexWatermarks) -> Self {
        Self {
            tx_lookup: !self.tx_lookup && watermarks.tx_lookup.is_some(),
            script_history: !self.script_history && watermarks.script_history.is_some(),
            script_live: !self.script_live && watermarks.script_live.is_some(),
        }
    }

    fn to_mask(self) -> u8 {
        u8::from(self.tx_lookup)
            | (u8::from(self.script_history) << 1)
            | (u8::from(self.script_live) << 2)
    }

    fn from_mask(mask: u8) -> Result<Self, IndexError> {
        // A pre-#225 marker never carries bit 2, and reading one with the bit
        // absent is exactly right: the store had no live rows to reset.
        if mask == 0 || mask & !0b111 != 0 {
            return Err(IndexError::InvalidResetMarker);
        }
        Ok(Self {
            tx_lookup: mask & 0b001 != 0,
            script_history: mask & 0b010 != 0,
            script_live: mask & 0b100 != 0,
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
    /// `ScriptIndex` live-output cursor. Independent of history by design:
    /// a ready live view stays queryable while history backfills (#225).
    pub script_live: Option<IndexWatermark>,
}

impl IndexWatermarks {
    /// Returns one capability's durable cursor.
    pub const fn get(self, capability: IndexCapability) -> Option<IndexWatermark> {
        match capability {
            IndexCapability::TxLookup => self.tx_lookup,
            IndexCapability::ScriptHistory => self.script_history,
            IndexCapability::ScriptLive => self.script_live,
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
        let key = watermark_key(capability);
        snapshot
            .get(ColumnFamily::UtxoMeta, key)?
            .as_deref()
            .map(Self::from_bytes)
            .transpose()
    }
}

/// Source of exact scripts for coins an incoming block spends.
///
/// A block body carries only each input's previous outpoint; the spent coin's
/// `script_pubkey` lives in authoritative UTXO state, and on disconnect in the
/// block's undo record. #225 requires Live deletes to be anchored to that
/// authoritative script, so preparation of a `ScriptLive` transition takes one
/// of these instead of guessing from the parse.
pub trait SpentCoinScripts {
    /// The exact `script_pubkey` bytes of the coin `txid:vout`, if known.
    ///
    /// `txid` is in little-endian byte order, as serialized in the input.
    fn script_bytes(&self, txid: &[u8; 32], vout: u32) -> Option<&[u8]>;
}

/// The anchorless source: answers nothing.
///
/// Used by the legacy prepare path, which refuses `ScriptLive` outright rather
/// than producing a Live transition with unanchored deletes.
pub struct NoSpentScripts;

impl SpentCoinScripts for NoSpentScripts {
    fn script_bytes(&self, _txid: &[u8; 32], _vout: u32) -> Option<&[u8]> {
        None
    }
}

/// One ordered live-view mutation produced by a block.
///
/// Order is semantic, unlike every other pending row family: a later block in
/// the same committed batch may delete a key an earlier block inserted, so
/// these are applied first-to-last with the last operation per key winning.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum LiveOp {
    /// The block created this currently-unspent output.
    Insert(crate::types::ScriptLiveRow),
    /// The block spent this previously-live output.
    Delete(crate::types::ScriptLiveRow),
}

/// Upper bound on a `script_pubkey` admitted into the authoritative UTXO set.
///
/// Mirrors `bitcoin_rs_consensus::MAX_SCRIPT_SIZE` as applied by the node's
/// `build_utxo_changes`: outputs with `is_op_return()` or a script longer than
/// this never enter the UTXO set, so they must never enter the Live view
/// either -- #225 requires the spendability predicate to match authoritative
/// UTXO admission exactly. Duplicated as a literal because this crate does not
/// depend on the consensus crate; the node crate asserts the two are equal.
pub const MAX_LIVE_SCRIPT_SIZE: usize = 10_000;

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

    /// Row-family counts retained by this prepared block.
    pub fn row_counts(&self) -> IndexRowCounts {
        self.rows.counts()
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

/// Counts of rows written by a confirmed prepared commit.
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
    /// Live-output mutations applied to [`ColumnFamily::ScriptLive`].
    pub live: usize,
}

/// Electrs-shaped block indexer backed by a workspace [`KvStore`].
///
/// Reads and format/watermark queries live here. Durable row mutation is
/// owned exclusively by [`IndexWriter`].
pub struct Indexer<S: KvStore> {
    store: std::sync::Arc<S>,
    last_counts: IndexRowCounts,
}

impl<S: KvStore> Indexer<S> {
    /// Creates an indexer over `store`.
    pub fn new(store: std::sync::Arc<S>) -> Self {
        Self {
            store,
            last_counts: IndexRowCounts::default(),
        }
    }

    /// Returns the underlying key-value store.
    pub const fn store(&self) -> &std::sync::Arc<S> {
        &self.store
    }

    /// Returns the row counts from the last successful prepared commit.
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

    /// Loads all independently durable capability watermarks.
    pub fn watermarks(&self) -> Result<IndexWatermarks, IndexError> {
        Ok(IndexWatermarks {
            tx_lookup: self.capability_watermark(IndexCapability::TxLookup)?,
            script_history: self.capability_watermark(IndexCapability::ScriptHistory)?,
            script_live: self.capability_watermark(IndexCapability::ScriptLive)?,
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

    /// Iterates live-output rows for `scripthash`.
    ///
    /// Returns the outpoint locators currently filed under the scripthash's
    /// 8-byte scan prefix, decoded from [`ColumnFamily::ScriptLive`]. The
    /// prefix is lossy exactly like `Funding`'s: two scripts may share it, so
    /// callers MUST resolve each outpoint against authoritative UTXO state and
    /// exact-check the resolved coin's full `script_pubkey` before serving it
    /// (#225). This scan is read-only by contract -- live deletion is always a
    /// whole-key point delete, never a prefix-range operation.
    pub fn iter_live_outpoints(
        &self,
        scripthash: crate::ScriptHash,
    ) -> Result<Vec<OutPoint>, IndexError> {
        let snapshot = self.store.snapshot()?;
        if snapshot
            .get(ColumnFamily::UtxoMeta, SCRIPT_LIVE_WATERMARK_KEY)?
            .is_none()
        {
            return Ok(Vec::new());
        }
        let prefix = ScriptHashRow::scan_prefix(scripthash);
        let iter = snapshot.iter_prefix(ColumnFamily::ScriptLive, &prefix)?;
        let mut outpoints = Vec::new();
        for row in iter {
            let (key, value) = row?;
            if !value.is_empty() {
                return Err(IndexError::InvalidLiveRowValue { len: value.len() });
            }
            let row = crate::types::ScriptLiveRow::from_db_row(&key)
                .ok_or(IndexError::InvalidWatermark)?;
            outpoints.push(row.outpoint());
        }
        Ok(outpoints)
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
}

fn pending_rows_for_block_with_header(
    block: &[u8],
    height: u32,
    capabilities: IndexCapabilities,
    spent_scripts: &dyn SpentCoinScripts,
) -> Result<(PendingRows, Option<[u8; crate::types::HEADER_ROW_SIZE]>), IndexError> {
    let mut rows = PendingRows::default();
    let mut header = None;
    let (live_created, live_spent) = {
        let mut visitor = IndexBlockVisitor {
            rows: &mut rows,
            header: &mut header,
            height_bytes: height.to_le_bytes(),
            invalid_header_len: None,
            block,
            pending_funding: Vec::new(),
            pending_spending: Vec::new(),
            pending_live: Vec::new(),
            live_created: Vec::new(),
            live_spent: Vec::new(),
            capabilities,
        };
        match bsl::Block::visit(block, &mut visitor) {
            Ok(_) => (visitor.live_created, visitor.live_spent),
            Err(bitcoin_slices::Error::VisitBreak) => {
                if let Some(len) = visitor.invalid_header_len {
                    return Err(IndexError::InvalidHeaderLength { len });
                }
                return Err(IndexError::BlockParse(bitcoin_slices::Error::VisitBreak));
            }
            Err(error) => return Err(IndexError::BlockParse(error)),
        }
    };
    if capabilities.script_live {
        push_live_ops(&mut rows, live_created, live_spent, height, spent_scripts)?;
    }
    Ok((rows, header))
}

/// Turns a block's created and spent outputs into ordered live mutations.
///
/// Outputs created and spent within the same block cancel before the spent-coin
/// anchor is consulted: those outputs never entered the committed UTXO set.
/// Every surviving spend must resolve its exact script through the authoritative
/// anchor, otherwise preparation fails closed rather than leaving a stale live
/// row behind.
fn push_live_ops(
    rows: &mut PendingRows,
    created: Vec<([u8; 32], u32, Option<ScriptHash>)>,
    spent: Vec<([u8; 32], u32)>,
    height: u32,
    spent_scripts: &dyn SpentCoinScripts,
) -> Result<(), IndexError> {
    let created_keys: hashbrown::HashSet<([u8; 32], u32)> = created
        .iter()
        .map(|(txid, vout, _)| (*txid, *vout))
        .collect();
    let mut cancelled = hashbrown::HashSet::new();
    let mut deletes = Vec::new();
    for (txid, vout) in spent {
        if created_keys.contains(&(txid, vout)) {
            cancelled.insert((txid, vout));
            continue;
        }
        let script = spent_scripts
            .script_bytes(&txid, vout)
            .ok_or(IndexError::MissingSpentCoin { txid, vout, height })?;
        let outpoint = OutPoint::new(Txid(Hash256::from_le_bytes(&txid)), vout);
        deletes.push(LiveOp::Delete(crate::types::ScriptLiveRow::new(
            ScriptHash::from_script_bytes(script),
            &outpoint,
        )));
    }
    for (txid, vout, scripthash) in created {
        if cancelled.contains(&(txid, vout)) {
            continue;
        }
        let Some(scripthash) = scripthash else {
            continue;
        };
        let outpoint = OutPoint::new(Txid(Hash256::from_le_bytes(&txid)), vout);
        // At a BIP30 exception height the output outpoint can already be
        // live. The undo record carries that replaced coin as a restore, so
        // use the same anchor to remove its old script row before publishing
        // the new one. The inverse operation restores the old row on rollback.
        if let Some(old_script) = spent_scripts.script_bytes(&txid, vout) {
            rows.live_ops
                .push(LiveOp::Delete(crate::types::ScriptLiveRow::new(
                    ScriptHash::from_script_bytes(old_script),
                    &outpoint,
                )));
        }
        rows.live_ops
            .push(LiveOp::Insert(crate::types::ScriptLiveRow::new(
                scripthash, &outpoint,
            )));
    }
    rows.live_ops.extend(deletes);
    Ok(())
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
    /// Ordered live-view mutations. Never sorted: unlike the append-only
    /// families above, this one mixes puts and deletes, and a later block's
    /// delete of an earlier block's insert must stay later.
    live_ops: Vec<LiveOp>,
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
            live: self.live_ops.len(),
        }
    }
    fn append(&mut self, other: Self) {
        self.txid_rows.extend(other.txid_rows);
        self.funding_rows.extend(other.funding_rows);
        self.spending_rows.extend(other.spending_rows);
        self.header_rows.extend(other.header_rows);
        self.live_ops.extend(other.live_ops);
    }

    fn total(&self) -> usize {
        let counts = self.counts();
        counts.txids + counts.funding + counts.spending + counts.headers + counts.live
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
        let live_bytes = self
            .live_ops
            .len()
            .checked_mul(crate::types::SCRIPT_LIVE_ROW_SIZE)
            .ok_or(IndexError::MutationSizeOverflow)?;
        prefix_bytes
            .checked_add(position_bytes)
            .and_then(|s| s.checked_add(header_bytes))
            .and_then(|s| s.checked_add(live_bytes))
            .ok_or(IndexError::MutationSizeOverflow)
    }
}

/// Applies ordered live mutations to `batch`, last operation per key winning.
///
/// Coalescing in memory rather than relying on the backend's write-batch
/// ordering keeps the semantics backend-independent: after this, each key
/// appears in the batch at most once. `invert` swaps inserts and deletes,
/// which is exactly a block's live rollback; inverted ops are applied in
/// reverse order so the coalescing rule stays "the chronologically last
/// forward operation decides".
fn apply_live_ops<B: WriteBatch>(batch: &mut B, ops: &[LiveOp], invert: bool) {
    let mut last: hashbrown::HashMap<[u8; crate::types::SCRIPT_LIVE_ROW_SIZE], bool> =
        hashbrown::HashMap::new();
    let ordered: Box<dyn Iterator<Item = &LiveOp>> = if invert {
        Box::new(ops.iter().rev())
    } else {
        Box::new(ops.iter())
    };
    for op in ordered {
        let (row, insert) = match op {
            LiveOp::Insert(row) => (row, !invert),
            LiveOp::Delete(row) => (row, invert),
        };
        last.insert(*row.as_bytes(), insert);
    }
    for (key, insert) in last {
        if insert {
            batch.put(ColumnFamily::ScriptLive, &key, &[]);
        } else {
            batch.delete(ColumnFamily::ScriptLive, &key);
        }
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
    apply_live_ops(batch, &rows.live_ops, false);
}

fn put_selected_watermarks<B: WriteBatch>(
    batch: &mut B,
    capabilities: IndexCapabilities,
    watermark: Option<IndexWatermark>,
) {
    for capability in [
        IndexCapability::TxLookup,
        IndexCapability::ScriptHistory,
        IndexCapability::ScriptLive,
    ] {
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
    let mut selected: Option<Option<IndexWatermark>> = None;
    for capability in [
        IndexCapability::TxLookup,
        IndexCapability::ScriptHistory,
        IndexCapability::ScriptLive,
    ] {
        if !capabilities.contains(capability) {
            continue;
        }
        let cursor = watermarks.get(capability);
        match selected {
            None => selected = Some(cursor),
            Some(first) if first == cursor => {}
            Some(first) => {
                return Err(IndexError::WatermarkMismatch {
                    expected: first,
                    actual: cursor,
                });
            }
        }
    }
    selected.ok_or(IndexError::NonContiguousPrepared { watermark: None })
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
    // The live rollback is the inverse authoritative transition (#225):
    // outputs the block created leave the view, outputs it spent return.
    apply_live_ops(batch, &rows.live_ops, true);
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
    /// Outputs of the transaction currently being parsed, as `(vout,
    /// optional scripthash)`. `None` means the output is not admitted to the
    /// UTXO set (`OP_RETURN` or oversize), but it still participates in
    /// same-block cancellation. Buffered for the same reason as
    /// `pending_funding`, and additionally because the txid is unknown until
    /// `visit_transaction`.
    pending_live: Vec<(u32, Option<ScriptHash>)>,
    /// Outputs this block created, pre-cancellation. The option preserves
    /// same-block cancellation for outputs that never enter UTXO state.
    live_created: Vec<([u8; 32], u32, Option<ScriptHash>)>,
    /// Full previous outpoints this block spends, pre-cancellation.
    live_spent: Vec<([u8; 32], u32)>,
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
        let txid =
            (self.capabilities.tx_lookup || !self.pending_live.is_empty()).then(|| tx.txid_sha2());
        if let Some(hash) = txid {
            let mut txid_bytes = [0_u8; 32];
            txid_bytes.copy_from_slice(hash.as_slice());
            for (vout, scripthash) in self.pending_live.drain(..) {
                self.live_created.push((txid_bytes, vout, scripthash));
            }
            if self.capabilities.tx_lookup {
                self.push_txid_row(hash.as_slice(), position);
            }
        }
        ControlFlow::Continue(())
    }

    fn visit_tx_in(&mut self, _vin: usize, tx_in: &bsl::TxIn<'_>) -> ControlFlow<()> {
        let prevout = tx_in.prevout();
        if is_null_prevout(prevout) {
            return ControlFlow::Continue(());
        }
        if self.capabilities.script_history {
            self.pending_spending.push(SpendingPrefixRow::row_parts(
                prevout.txid(),
                prevout.vout(),
                self.height_bytes,
            ));
        }
        if self.capabilities.script_live {
            let mut txid = [0_u8; 32];
            txid.copy_from_slice(prevout.txid());
            self.live_spent.push((txid, prevout.vout()));
        }
        ControlFlow::Continue(())
    }

    fn visit_tx_out(&mut self, vout: usize, tx_out: &bsl::TxOut<'_>) -> ControlFlow<()> {
        let script = tx_out.script_pubkey();
        if self.capabilities.script_history && !is_op_return_script(script) {
            self.pending_funding
                .push(ScriptHash::from_script_bytes(script).prefix());
        }
        // The live predicate is UTXO admission, not the history predicate:
        // `build_utxo_changes` skips `is_op_return()` and oversized scripts,
        // and the genesis coinbase never enters the UTXO set at all. History
        // deliberately keeps oversized-script outputs (they are historical
        // activity); Live must not, or it would carry locators no
        // authoritative lookup can resolve.
        if self.capabilities.script_live
            && self.height_bytes != [0_u8; crate::types::HEIGHT_SIZE]
            && let Ok(vout) = u32::try_from(vout)
        {
            let scripthash = (!is_op_return_script(script) && script.len() <= MAX_LIVE_SCRIPT_SIZE)
                .then(|| ScriptHash::from_script_bytes(script));
            self.pending_live.push((vout, scripthash));
        }
        ControlFlow::Continue(())
    }
}

fn is_null_prevout(prevout: &bsl::OutPoint<'_>) -> bool {
    prevout.vout() == u32::MAX && prevout.txid().iter().all(|byte| *byte == 0)
}

#[inline]
fn is_op_return_script(script: &[u8]) -> bool {
    matches!(script.first(), Some(0x6a))
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

/// Result of one bounded `ScriptLive` prefix scan.
#[derive(Debug)]
pub struct ScriptLiveScan {
    /// Parsed live-output locator rows.
    pub rows: Vec<crate::ScriptLiveRow>,
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
    /// Scans compact live-output locator rows for `scripthash`.
    fn live_rows(
        &self,
        scripthash: ScriptHash,
        limit: PrefixScanLimit,
    ) -> Result<ScriptLiveScan, IndexError> {
        let _ = (scripthash, limit);
        Err(IndexError::UnsupportedRollback)
    }
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

    fn live_rows(
        &self,
        scripthash: ScriptHash,
        limit: PrefixScanLimit,
    ) -> Result<ScriptLiveScan, IndexError> {
        let scan = self.snapshot.scan_prefix_bounded(
            ColumnFamily::ScriptLive,
            &ScriptHashRow::scan_prefix(scripthash),
            limit,
        )?;
        let encoded_bytes = scan.rows.iter().fold(0_usize, |total, (key, value)| {
            total.saturating_add(key.len()).saturating_add(value.len())
        });
        let mut rows = Vec::with_capacity(scan.rows.len());
        for (key, value) in scan.rows {
            if !value.is_empty() {
                return Err(IndexError::InvalidLiveRowValue { len: value.len() });
            }
            rows.push(
                crate::ScriptLiveRow::from_db_row(&key)
                    .ok_or(IndexError::InvalidPrefixRowLength { len: key.len() })?,
            );
        }
        Ok(ScriptLiveScan {
            rows,
            encoded_bytes,
            complete: scan.complete,
        })
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
    /// Read access to the owned indexer, for queries beside the write path.
    pub fn indexer(&self) -> &Indexer<S> {
        &self.indexer
    }

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

    /// Returns the row counts from the last successful prepared commit.
    pub const fn last_counts(&self) -> IndexRowCounts {
        self.indexer.last_counts()
    }

    /// Loads both independently durable capability watermarks.
    pub fn watermarks(&self) -> Result<IndexWatermarks, IndexError> {
        self.indexer.watermarks()
    }

    /// Captures one coherent fence with the exact reset state, ordinary revision,
    /// and all capability watermarks from a single snapshot. It returns the
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

    /// Seeds the live view from a producer of compact locators.
    ///
    /// `produce` emits every live `(outpoint, scripthash)` at `seed_tip`.
    /// Each bounded batch, and the watermark stamp, is an ordinary fenced
    /// write: reset state, ordinary revision, and every capability watermark
    /// must still match the capture. A lost fence is [`IndexError::StaleIndexState`]
    /// or [`IndexError::ResetInProgress`]; a storage failure is
    /// [`IndexError::Storage`]. The caller resets this capability before
    /// retrying. See `IDX-07` in `docs/contracts/indexing.md`.
    ///
    /// The live watermark is written only with the last batch, so an
    /// interrupted seed stays unqueryable. Refuses to run over an existing
    /// live watermark ([`IndexError::LiveAlreadySeeded`]).
    ///
    /// A missing live watermark with leftover rows is treated as an
    /// interrupted seed: `ScriptLive` is reset before any new row is
    /// written so a later watermark cannot advertise a stale view.
    pub fn seed_script_live_stream<F>(
        &mut self,
        mut produce: F,
        seed_tip: IndexWatermark,
    ) -> Result<usize, IndexError>
    where
        F: FnMut(
            &mut dyn FnMut(OutPoint, crate::ScriptHash) -> Result<(), IndexError>,
        ) -> Result<(), IndexError>,
    {
        const SEED_BATCH_ROWS: usize = 4_096;
        let existing = capture_write_fence(self.indexer.store.as_ref(), self.generation)?;
        if existing.watermarks.script_live.is_some() {
            return Err(IndexError::LiveAlreadySeeded);
        }
        // An interrupted seed leaves rows without a ready watermark. Clear
        // them before writing so this publication cannot mix leftover
        // locators from a previous attempt. Recapture after the reset: the
        // claim advances the fence, so a pre-reset capture cannot commit.
        self.reset_capabilities(IndexCapabilities::SCRIPT_LIVE)?;
        let mut fence = capture_write_fence(self.indexer.store.as_ref(), self.generation)?;
        if fence.watermarks.script_live.is_some() {
            return Err(IndexError::LiveAlreadySeeded);
        }
        let mut written = 0;
        let mut batch = self.indexer.store.new_batch();
        batch.put(
            ColumnFamily::UtxoMeta,
            FORMAT_VERSION_KEY,
            &FORMAT_VERSION_VALUE,
        );
        let mut in_batch = 0;
        let mut add = |outpoint, scripthash| -> Result<(), IndexError> {
            let row = crate::types::ScriptLiveRow::new(scripthash, &outpoint);
            batch.put(ColumnFamily::ScriptLive, row.as_bytes(), &[]);
            written += 1;
            in_batch += 1;
            if in_batch >= SEED_BATCH_ROWS {
                let next = self.indexer.store.new_batch();
                let old = std::mem::replace(&mut batch, next);
                commit_ordinary(self.indexer.store.as_ref(), self.generation, &fence, old)?;
                fence = capture_write_fence(self.indexer.store.as_ref(), self.generation)?;
                if fence.watermarks.script_live.is_some() {
                    return Err(IndexError::LiveAlreadySeeded);
                }
                batch.put(
                    ColumnFamily::UtxoMeta,
                    FORMAT_VERSION_KEY,
                    &FORMAT_VERSION_VALUE,
                );
                in_batch = 0;
            }
            Ok(())
        };
        produce(&mut add)?;
        batch.put(
            ColumnFamily::UtxoMeta,
            FORMAT_VERSION_KEY,
            &FORMAT_VERSION_VALUE,
        );
        batch.put(
            ColumnFamily::UtxoMeta,
            SCRIPT_LIVE_WATERMARK_KEY,
            &seed_tip.to_bytes(),
        );
        commit_ordinary(self.indexer.store.as_ref(), self.generation, &fence, batch)?;
        Ok(written)
    }

    /// Seeds `ScriptLive` from an iterator of compact locators.
    ///
    /// Delegates to [`Self::seed_script_live_stream`] so fenced write
    /// failures and watermark publication have one owner.
    pub fn seed_script_live<I>(
        &mut self,
        coins: I,
        seed_tip: IndexWatermark,
    ) -> Result<usize, IndexError>
    where
        I: IntoIterator<Item = (OutPoint, crate::ScriptHash)>,
    {
        let mut coins = coins.into_iter();
        self.seed_script_live_stream(
            |emit| {
                for (outpoint, scripthash) in coins.by_ref() {
                    emit(outpoint, scripthash)?;
                }
                Ok(())
            },
            seed_tip,
        )
    }

    /// Marks selected derived rows unavailable, deletes them in bounded batches,
    /// and leaves their durable cursors empty so the worker can rebuild from genesis.
    ///
    /// The claim and cursor deletion land atomically before row deletion, and
    /// completion CASes the exact claim to the next idle version.
    /// `open` resumes an interrupted reset before exposing the writer again.
    pub fn reset_capabilities(&self, capabilities: IndexCapabilities) -> Result<(), IndexError> {
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
        self.prepare_block_for(IndexCapabilities::HISTORICAL, height, hash, body)
    }

    /// Derives capability-selected row mutations from one serialized block scan.
    pub fn prepare_block_for(
        &self,
        capabilities: IndexCapabilities,
        height: u32,
        hash: [u8; 32],
        body: &[u8],
    ) -> Result<PreparedBlock, IndexError> {
        if capabilities.script_live {
            return Err(IndexError::MissingSpentScripts);
        }
        self.prepare_block_with_spent_scripts(capabilities, height, hash, body, &NoSpentScripts)
    }

    /// [`Self::prepare_block_for`] with the spent-coin script source
    /// `ScriptLive` preparation requires (#225).
    pub fn prepare_block_with_spent_scripts(
        &self,
        capabilities: IndexCapabilities,
        height: u32,
        hash: [u8; 32],
        body: &[u8],
        spent_scripts: &dyn SpentCoinScripts,
    ) -> Result<PreparedBlock, IndexError> {
        if capabilities.is_empty() {
            return Err(IndexError::NonContiguousPrepared {
                watermark: self.watermark()?,
            });
        }
        let (mut rows, header) =
            pending_rows_for_block_with_header(body, height, capabilities, spent_scripts)?;
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

    /// Commits one serialized block through the prepared-write owner.
    ///
    /// Production catch-up uses [`Self::prepare_block_with_spent_scripts`] plus
    /// [`PreparedBatch`] to bound multi-block writes. This is the same owner
    /// for a single block: tests and benches must not grow a second ingest path.
    ///
    /// [`Self::commit_forward`] is the commit point (`IDX-06`): `Ok` means the
    /// prepared rows and capability watermark are durable together in one store
    /// batch. A crash before that write leaves the previous watermark and rows;
    /// a crash after it leaves both. Fence races
    /// ([`IndexError::StaleIndexState`], [`IndexError::ResetInProgress`]) mean
    /// discard derived state and retry from the persisted watermark.
    /// [`IndexError::Storage`] is not retried by the index worker; supervision
    /// marks it failed (`IDX-07`).
    ///
    /// This path selects [`IndexCapabilities::HISTORICAL`]: it advances
    /// `TxLookup` and `ScriptHistory` only. Callers that maintain `ScriptLive`
    /// must use [`Self::prepare_block_with_spent_scripts`] with `script_live`
    /// selected and a spent-script source, then [`Self::commit_forward`].
    pub fn commit_block(&mut self, height: u32, body: &[u8]) -> Result<IndexWatermark, IndexError> {
        let header = body.get(..crate::types::HEADER_ROW_SIZE).ok_or_else(|| {
            IndexError::InvalidHeaderLength {
                len: body.len().min(crate::types::HEADER_ROW_SIZE),
            }
        })?;
        let hash = encode::double_sha256(header).to_le_bytes();
        let prepared = self.prepare_block(height, hash, body)?;
        let mut batch = PreparedBatch::new(PreparedBatchLimits {
            max_rows: usize::MAX,
            max_bytes: usize::MAX,
        });
        if let Err(_block) = batch.try_push(prepared) {
            return Err(IndexError::NonContiguousPrepared {
                watermark: self.watermark()?,
            });
        }
        self.commit_forward(batch)
    }

    /// Atomically connects a bounded batch and advances the durable watermark.
    ///
    /// Captures its own fence before any store-dependent derivation and keeps
    /// the consumer cursor untouched. Rows and the selected watermarks land in
    /// one `write_durable_if` batch; `Ok` is the commit point (`IDX-06`). Fence
    /// races return [`IndexError::StaleIndexState`] or
    /// [`IndexError::ResetInProgress`]; the worker re-reads watermarks and
    /// re-plans. [`IndexError::Storage`] fails the worker (`IDX-07`).
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
            IndexCapabilities::HISTORICAL,
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
        if capabilities.script_live {
            return Err(IndexError::MissingSpentScripts);
        }
        let (fence, _) = self.fenced_watermarks()?;
        self.commit_rollback_one_for_with_cursor(
            fence,
            capabilities,
            prev,
            body,
            ConsumerCursorUpdate::Clear,
        )
    }

    /// Rolls back a selected transition using authoritative spent-coin
    /// scripts. `ScriptLive` uses this anchor to restore rows for outputs that
    /// the disconnected block had spent.
    pub fn commit_rollback_one_with_spent_scripts(
        &mut self,
        capabilities: IndexCapabilities,
        prev: Option<IndexWatermark>,
        body: &[u8],
        spent_scripts: &dyn SpentCoinScripts,
    ) -> Result<(), IndexError> {
        let (fence, _) = self.fenced_watermarks()?;
        self.commit_rollback_one_for_with_cursor_with_spent_scripts(
            fence,
            capabilities,
            prev,
            body,
            ConsumerCursorUpdate::Clear,
            spent_scripts,
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
        if capabilities.script_live {
            return Err(IndexError::MissingSpentScripts);
        }
        self.commit_rollback_one_for_with_cursor_with_spent_scripts(
            fence,
            capabilities,
            prev,
            body,
            cursor,
            &NoSpentScripts,
        )
    }

    /// Atomically rolls back one block with the exact scripts of its spent
    /// coins. This is the anchored variant used when `ScriptLive` is selected.
    ///
    /// The `write_durable_if` batch is the commit point (`IDX-06`), same as
    /// [`Self::commit_forward`]: `Ok` means row deletes, the selected
    /// watermark, and the cursor disposition are durable together. A crash
    /// before that write leaves the previous tip; a crash after it leaves the
    /// parent watermark. Fence races ([`IndexError::StaleIndexState`],
    /// [`IndexError::ResetInProgress`]) mean discard derived state and retry
    /// from the persisted watermark. [`IndexError::Storage`] is not retried by
    /// the index worker; supervision marks it failed (`IDX-07`).
      ///
      /// A storage error can have an indeterminate outcome at the storage
      /// boundary, so this method does not retry it. The supervising worker
      /// owns restart and reconciliation; callers must reload the persisted
      /// watermark before retrying after a crash or storage failure.
    pub fn commit_rollback_one_for_with_cursor_with_spent_scripts(
        &mut self,
        fence: IndexWriteFence,
        capabilities: IndexCapabilities,
        prev: Option<IndexWatermark>,
        body: &[u8],
        cursor: ConsumerCursorUpdate<'_>,
        spent_scripts: &dyn SpentCoinScripts,
    ) -> Result<(), IndexError> {
        let current = selected_watermark(fence.watermarks, capabilities)?
            .ok_or(IndexError::NonContiguousPrepared { watermark: None })?;
        let prepared = self.prepare_block_with_spent_scripts(
            capabilities,
            current.height,
            current.hash,
            body,
            spent_scripts,
        )?;
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
                    .is_some_and(|watermark| watermark.height >= current.height))
            || (!capabilities.script_live
                && fence
                    .watermarks
                    .script_live
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

    /// Publishes the opaque consumer cursor under five exact conditions from the
    /// captured fence: reset state, ordinary revision, and all watermark rows.
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
        ColumnFamily::ScriptLive,
    ] {
        let mut iter = store.iter_prefix(cf, &[])?;
        if let Some(entry) = iter.next() {
            let _ = entry?;
            return Ok(true);
        }
    }
    Ok(false)
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

#[cfg(all(test, feature = "rocksdb"))]
mod tests {
    use std::sync::Arc;

    use bitcoin_rs_primitives::{
        Block, BlockHash, Hash256, Header, Network, OutPoint, Tx, TxIn, TxOut, Txid,
        consensus_bytes,
    };
    use bitcoin_rs_storage::{ColumnFamily, KvStore, RocksDbStore, WriteBatch};

    use super::{BlockSource, IndexError, IndexWriter, Indexer, is_op_return_script};
    use crate::{ScriptHash, ScriptHashRow, ScriptHistoryEntry, SpendingPrefixRow, TxidRow};

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
        let (_dir, mut writer) = writer()?;

        writer.commit_block(0, &consensus_bytes(&block(vec![tx])))?;

        let scripthash = ScriptHash::from_script_bytes(&script);
        assert_eq!(
            writer.indexer().iter_funding_rows(scripthash)?,
            vec![ScriptHashRow::row(scripthash, 0)]
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
        let dir = tempfile::tempdir()?;
        let store = Arc::new(RocksDbStore::open(dir.path())?);
        put_funding_row(&store, scripthash, 1)?;
        put_funding_row(&store, scripthash, 256)?;
        let indexer = Indexer::new(store);

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
        let (_dir, mut writer) = writer()?;

        writer.commit_block(0, &consensus_bytes(&block(vec![tx])))?;

        assert_eq!(
            writer.indexer().iter_spending_rows(&outpoint)?,
            vec![SpendingPrefixRow::row(&outpoint, 0)]
        );
        Ok(())
    }

    #[test]
    fn iter_txid_rows_returns_indexed_rows() -> Result<(), Box<dyn std::error::Error>> {
        let tx = tx(spent_outpoint(4, 5), vec![0x51, 0x03]);
        let txid = tx.txid();
        let (_dir, mut writer) = writer()?;

        writer.commit_block(0, &consensus_bytes(&block(vec![tx])))?;

        let rows = writer.indexer().iter_txid_rows(&txid)?;
        assert!(rows.contains(&TxidRow::row(&txid, 0)));
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
        let (_dir, mut writer) = writer()?;

        writer.commit_block(0, &consensus_bytes(&block))?;

        let source = FakeSource {
            block,
            target_height: 0,
        };
        let entries = writer
            .indexer()
            .resolve_script_history(scripthash, &source)?;

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
        let (_dir, mut writer) = writer()?;

        writer.commit_block(0, &consensus_bytes(&block))?;

        let source = FakeSource {
            block,
            target_height: 0,
        };
        let outputs = writer
            .indexer()
            .resolve_unspent_outputs(scripthash, &source)?;

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
        let (_dir, mut writer) = writer()?;

        writer.commit_block(0, &consensus_bytes(&block))?;

        let source = FakeSource {
            block,
            target_height: 0,
        };
        let resolved = writer.indexer().resolve_transaction(txid, &source)?;

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
        let (_dir, mut writer) = writer()?;

        writer.commit_block(0, &consensus_bytes(&block))?;

        let source = FakeSource {
            block,
            target_height: 1,
        };
        let resolved = writer.indexer().resolve_transaction(txid, &source)?;

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
        let (_dir, mut writer) = writer()?;

        writer.commit_block(0, &consensus_bytes(&block))?;

        let source = FakeSource {
            block,
            target_height: 0,
        };
        let resolved = writer.indexer().resolve_tx_with_height(txid, &source)?;

        assert_eq!(resolved, Some((coinbase, 0)));
        Ok(())
    }

    #[test]
    fn resolve_tx_with_height_returns_none_for_unknown_txid()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_dir, writer) = writer()?;
        let txid = Txid(Hash256::from_le_bytes(&[0xff; 32]));
        let source = FakeSource {
            block: Network::Regtest.genesis_block(),
            target_height: 0,
        };

        assert_eq!(
            writer.indexer().resolve_tx_with_height(txid, &source)?,
            None
        );
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
        let (_dir, mut writer) = writer()?;

        writer.commit_block(0, &consensus_bytes(&block))?;

        let source = FakeSource {
            block,
            target_height: 0,
        };
        let outpoint = OutPoint { txid, vout: 0 };
        let value = writer.indexer().resolve_outpoint_value(outpoint, &source)?;

        assert_eq!(value, Some(5_000_000_000));
        Ok(())
    }

    #[test]
    fn resolve_outpoint_value_via_dyn_block_source() -> Result<(), Box<dyn std::error::Error>> {
        let block = Network::Regtest.genesis_block();
        let Some(tx) = block.txs.first() else {
            return Err(std::io::Error::other("genesis block has no transactions").into());
        };
        let txid = tx.txid();
        let (_dir, mut writer) = writer()?;

        writer.commit_block(0, &consensus_bytes(&block))?;

        let source = FakeSource {
            block,
            target_height: 0,
        };
        let dyn_source: &dyn super::BlockSource = &source;
        let outpoint = OutPoint { txid, vout: 0 };
        let value = writer
            .indexer()
            .resolve_outpoint_value(outpoint, dyn_source)?;

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
        let (_dir, mut writer) = writer()?;

        writer.commit_block(0, &consensus_bytes(&block))?;

        let source = FakeSource {
            block,
            target_height: 0,
        };
        let outpoint = OutPoint { txid, vout: 99 };

        assert_eq!(
            writer.indexer().resolve_outpoint_value(outpoint, &source)?,
            None
        );
        Ok(())
    }

    #[test]
    fn resolve_outpoint_value_returns_none_for_unknown_txid()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_dir, writer) = writer()?;
        let outpoint = OutPoint {
            txid: Txid(Hash256::from_le_bytes(&[0xff; 32])),
            vout: 0,
        };
        let source = FakeSource {
            block: Network::Regtest.genesis_block(),
            target_height: 0,
        };

        assert_eq!(
            writer.indexer().resolve_outpoint_value(outpoint, &source)?,
            None
        );
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
        let (_dir, mut writer) = writer()?;

        writer.commit_block(0, &consensus_bytes(&block))?;

        let source = FakeSource {
            block,
            target_height: 0,
        };
        let outputs = writer
            .indexer()
            .resolve_unspent_outputs_with_height(scripthash, &source)?;

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
    fn rollback_removes_every_row_a_matching_commit_wrote() -> Result<(), Box<dyn std::error::Error>>
    {
        let (_dir, mut writer) = writer()?;
        let candidate = rollback_fixture_block();
        let body = consensus_bytes(&candidate);
        let before = stored_rows(writer.indexer())?;

        writer.commit_block(0, &body)?;
        let after_commit = stored_rows(writer.indexer())?;
        assert!(
            after_commit.len() > before.len(),
            "fixture must write rows to be a meaningful rollback test"
        );
        for cf in [
            ColumnFamily::TxConfirmed,
            ColumnFamily::Funding,
            ColumnFamily::Spending,
            ColumnFamily::BlockHeaders,
        ] {
            assert!(
                after_commit.iter().any(|(family, _)| *family == cf),
                "fixture wrote no rows to {cf:?}"
            );
        }

        writer.commit_rollback_one(None, &body)?;
        assert_eq!(
            stored_rows(writer.indexer())?,
            before,
            "rollback must restore the pre-commit row set exactly"
        );
        Ok(())
    }

    #[test]
    fn rollback_without_a_watermark_is_rejected() -> Result<(), Box<dyn std::error::Error>> {
        let (_dir, mut writer) = writer()?;
        let candidate = rollback_fixture_block();
        let body = consensus_bytes(&candidate);

        assert!(matches!(
            writer.commit_rollback_one(None, &body),
            Err(IndexError::NonContiguousPrepared { watermark: None })
        ));
        assert!(stored_rows(writer.indexer())?.is_empty());
        Ok(())
    }

    #[test]
    fn a_second_rollback_is_rejected_once_the_watermark_is_gone()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_dir, mut writer) = writer()?;
        let candidate = rollback_fixture_block();
        let body = consensus_bytes(&candidate);
        writer.commit_block(0, &body)?;
        writer.commit_rollback_one(None, &body)?;
        let after_first = stored_rows(writer.indexer())?;

        assert!(matches!(
            writer.commit_rollback_one(None, &body),
            Err(IndexError::NonContiguousPrepared { watermark: None })
        ));
        assert_eq!(
            stored_rows(writer.indexer())?,
            after_first,
            "a rejected second rollback must be observationally inert"
        );
        Ok(())
    }

    /// Delegates reads to a real store but fails every write API, so the
    /// all-or-nothing claim on `commit_rollback_one` is exercised through its
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
        let body = consensus_bytes(&candidate);

        {
            let store = Arc::new(RocksDbStore::open(dir.path())?);
            let mut writer = IndexWriter::open(store, 1)?;
            writer.commit_block(0, &body)?;
        }
        let store = Arc::new(RocksDbStore::open(dir.path())?);
        let before = stored_rows(&Indexer::new(Arc::clone(&store)))?;
        assert!(!before.is_empty(), "fixture must have rows to preserve");
        drop(store);

        let failing = Arc::new(FailingWriteStore(RocksDbStore::open(dir.path())?));
        let mut writer = IndexWriter::open(Arc::clone(&failing), 1)?;
        let outcome = writer.commit_rollback_one(None, &body);
        assert!(outcome.is_err(), "a failing write must surface as an error");
        drop(writer);
        drop(failing);

        let reopened = Indexer::new(Arc::new(RocksDbStore::open(dir.path())?));
        assert_eq!(
            stored_rows(&reopened)?,
            before,
            "a failed rollback must leave every row in place"
        );
        Ok(())
    }

    /// A rollback of a replaced tip must not delete the replacement's rows.
    ///
    /// `commit_rollback_one` checks the current watermark hash against the
    /// serialized body, so a stale body's identity cannot satisfy the tip
    /// and the replacement's prefix-colliding history stays put.
    #[test]
    fn a_stale_rollback_body_leaves_a_replacement_blocks_rows_alone()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_dir, mut writer) = writer()?;
        let shared_script = vec![0x51];

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

        let old_body = consensus_bytes(&old_block);
        writer.commit_block(0, &old_body)?;
        writer.commit_rollback_one(None, &old_body)?;
        writer.commit_block(0, &consensus_bytes(&replacement))?;
        writer.flush()?;
        let after_replacement = stored_rows(writer.indexer())?;
        assert!(
            !after_replacement.is_empty(),
            "the replacement must have written rows"
        );

        assert!(
            writer.commit_rollback_one(None, &old_body).is_err(),
            "rolling back the old body against the replacement watermark must fail"
        );
        writer.flush()?;

        assert_eq!(
            stored_rows(writer.indexer())?,
            after_replacement,
            "a stale rollback body must not touch the replacement's rows"
        );
        Ok(())
    }

    fn writer() -> Result<(tempfile::TempDir, IndexWriter<RocksDbStore>), Box<dyn std::error::Error>>
    {
        let dir = tempfile::tempdir()?;
        let store = Arc::new(RocksDbStore::open(dir.path())?);
        Ok((dir, IndexWriter::open(store, 1)?))
    }

    fn put_funding_row(
        store: &RocksDbStore,
        scripthash: ScriptHash,
        height: u32,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut batch = store.new_batch();
        batch.put(
            ColumnFamily::Funding,
            &ScriptHashRow::row(scripthash, height).to_db_row(),
            &[],
        );
        store.write(batch)?;
        Ok(())
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
