//! Coherent write fences and cooperative, versioned capability-reset recovery.

use super::{
    capability::IndexCapabilities, capability::IndexWatermark, capability::IndexWatermarks,
    capability::SCRIPT_HISTORY_WATERMARK_KEY, capability::SCRIPT_LIVE_WATERMARK_KEY,
    capability::TX_LOOKUP_WATERMARK_KEY, capability::WATERMARK_LEN, error::IndexError,
    format::INDEX_FORMAT_VERSION, format::INDEX_FORMAT_VERSION_KEY,
};
use bitcoin_rs_storage::{ColumnFamily, KvStore, PrefixScanLimit, WriteBatch, WriteCondition};
use tracing::debug;

// Reserved metadata keys in `ColumnFamily::UtxoMeta`. The 0x00 prefix is reserved for
// TxIndex metadata; data row keys begin with ASCII letters only and can never collide.
pub(super) const FORMAT_VERSION_KEY: &[u8] = &[0x00, b'V'];

pub(super) const FORMAT_VERSION_VALUE: [u8; 4] = [0x04, 0x00, 0x00, 0x00];

/// Format 3 stores Spending keys without positions. This build still
/// understands those rows (resolvers fall back to a full block) and upgrades
/// by resetting only `ScriptHistory`, leaving `TxLookup` ready (`IDX-04`).
pub(super) const FORMAT_VERSION_V3: [u8; 4] = [0x03, 0x00, 0x00, 0x00];

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
pub(super) const CONSUMER_CURSOR_KEY: &[u8] = &[0x00, b'C'];

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
    pub(super) watermarks: IndexWatermarks,
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
pub(super) fn capture_write_fence<S: KvStore>(
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
pub(super) fn commit_ordinary<S: KvStore>(
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
pub(super) fn ensure_fence_live<S: KvStore>(
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
pub(super) fn resume_capability_reset<S: KvStore>(
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
